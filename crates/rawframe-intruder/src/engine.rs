//! Bounded Intruder execution.
//!
//! Every generated request is executed by the existing Repeater engine, so
//! destination resolution, address policy, scope enforcement, TLS verification,
//! timeouts, request validation, and response capture limits are *the same code*
//! the Repeater uses. This module only adds what is specific to an attack:
//! concurrency, a conservative request rate, pause/resume, cancellation, a total
//! duration ceiling, and result accounting.
//!
//! There are no retries. A request that fails is reported once, with its real
//! error, and never re-sent behind the operator's back.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rawframe_core::models::headers::Headers;
use rawframe_core::models::message::HttpRequest;
use rawframe_core::models::traffic::TrafficId;
use rawframe_core::repeater::{RepeaterResult, RepeaterTimings};
use rawframe_core::{
    AppEvent, EventSender, INTRUDER_ID_BASE, IntruderEvent, IntruderLaunch, IntruderOutcome,
    IntruderResult, IntruderStopReason, IntruderSummary, MAX_GENERATED_REQUESTS,
    RepeaterExecutionPhase, intruder_entry,
};
use rawframe_repeater::{ExecutionOutcome, RepeaterConfig, RepeaterEngine};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Intruder captures less of each response than a manual Repeater execution:
/// hundreds of full bodies would exhaust memory and the UI for no analytical
/// benefit. Bodies above this ceiling are truncated and flagged.
pub const MAX_CAPTURED_RESPONSE_BYTES: usize = 256 * 1024;
/// A generated request body is bounded independently of the proxy limit.
pub const MAX_GENERATED_REQUEST_BODY: usize = 1024 * 1024;

/// Clamps a Repeater configuration for attack traffic: same policy, lower
/// capture ceiling, and a concurrency ceiling the service never exceeds.
pub fn intruder_config(base: &RepeaterConfig) -> RepeaterConfig {
    let mut config = base.clone();
    config.max_concurrent = rawframe_core::MAX_CONCURRENCY;
    config.max_response_bytes = config.max_response_bytes.min(MAX_CAPTURED_RESPONSE_BYTES);
    config.max_request_body = config.max_request_body.min(MAX_GENERATED_REQUEST_BODY);
    config
}

/// Shared execution engine. One `RepeaterEngine` is reused for every run so the
/// cost of building the upstream trust store is paid once.
pub struct IntruderEngine {
    repeater: Arc<RepeaterEngine>,
}

impl IntruderEngine {
    pub fn new(
        config: RepeaterConfig,
        scope: Arc<std::sync::RwLock<rawframe_core::models::config::Scope>>,
    ) -> Self {
        Self {
            repeater: Arc::new(RepeaterEngine::new(config, scope)),
        }
    }

    pub fn tls_available(&self) -> bool {
        self.repeater.tls_available()
    }

    pub fn update_scope(&self, scope: rawframe_core::models::config::Scope) {
        self.repeater.update_scope(scope);
    }

    async fn execute(
        &self,
        request: &HttpRequest,
        follow_redirects: bool,
        cancel: CancellationToken,
    ) -> ExecutionOutcome {
        self.repeater
            .execute(request, follow_redirects, cancel, |_| {})
            .await
    }
}

/// Serializes request starts so an attack can never become a flood. The first
/// request is not delayed; each following start waits for the configured
/// interval. Pause, cancellation, and the run deadline are honored while
/// waiting.
pub struct RateGate {
    interval: Duration,
    next: tokio::sync::Mutex<Instant>,
}

impl RateGate {
    pub fn new(rate_per_second: u32) -> Self {
        let rate = rate_per_second.max(1) as u64;
        Self {
            interval: Duration::from_micros(1_000_000 / rate),
            next: tokio::sync::Mutex::new(Instant::now()),
        }
    }

    /// Waits for the next permitted start. Returning [`GateOutcome::Paused`]
    /// instead of blocking here lets the caller publish the pause immediately:
    /// a run that pauses mid-wait must not look like it is still dispatching.
    async fn wait(
        &self,
        cancel: &CancellationToken,
        paused: &AtomicBool,
        notify: &Notify,
        deadline: Instant,
    ) -> GateOutcome {
        loop {
            if cancel.is_cancelled() {
                return GateOutcome::Stopped;
            }
            if paused.load(Ordering::Relaxed) {
                return GateOutcome::Paused;
            }

            let slot = {
                let mut next = self.next.lock().await;
                let now = Instant::now();
                if *next <= now {
                    *next = now + self.interval;
                    return GateOutcome::Started;
                }
                *next
            };

            if slot >= deadline {
                return GateOutcome::Deadline;
            }
            tokio::select! {
                _ = cancel.cancelled() => return GateOutcome::Stopped,
                _ = tokio::time::sleep_until(slot) => {}
                _ = tokio::time::sleep_until(deadline) => return GateOutcome::Deadline,
                _ = notify.notified() => {}
                // Re-check the pause flag while waiting for the rate slot.
                _ = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateOutcome {
    Started,
    Paused,
    Stopped,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeOutcome {
    Resumed,
    Stopped,
    Deadline,
}

/// Blocks while the run is paused. Polling every 100 ms is deliberate: it makes
/// the wait immune to a missed `Notify` while still waking immediately on resume.
async fn wait_for_resume_outcome(
    cancel: &CancellationToken,
    paused: &AtomicBool,
    notify: &Notify,
    deadline: Instant,
) -> ResumeOutcome {
    loop {
        if cancel.is_cancelled() {
            return ResumeOutcome::Stopped;
        }
        if Instant::now() >= deadline {
            return ResumeOutcome::Deadline;
        }
        if !paused.load(Ordering::Relaxed) {
            return ResumeOutcome::Resumed;
        }
        tokio::select! {
            _ = cancel.cancelled() => return ResumeOutcome::Stopped,
            _ = notify.notified() => {}
            _ = tokio::time::sleep_until(deadline) => return ResumeOutcome::Deadline,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

/// Runs one attack to completion, publishing every result. Returns the exact
/// accounting the interface displays; no request is counted as sent unless it
/// was actually dispatched.
pub async fn run_attack(
    engine: Arc<IntruderEngine>,
    events: EventSender,
    run: u64,
    launch: IntruderLaunch,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
    notify: Arc<Notify>,
) -> IntruderSummary {
    let total = launch.plan.count;
    let mut summary = IntruderSummary {
        planned: total,
        ..IntruderSummary::default()
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(launch.max_duration_secs);

    let _ = events
        .send_async(AppEvent::Intruder(IntruderEvent::Started { run, total }))
        .await;

    let semaphore = Arc::new(Semaphore::new(launch.concurrency));
    let gate = Arc::new(RateGate::new(launch.rate_per_second));
    let run_cancel = cancel.child_token();
    let template_request = build_template_request(&launch);
    let mut tasks: JoinSet<IntruderResult> = JoinSet::new();
    let mut dispatched: u64 = 0;
    let mut stop: Option<IntruderStopReason> = None;
    let mut last_phase: Option<IntruderPhaseState> = None;

    while dispatched < total || !tasks.is_empty() {
        if stop.is_none() {
            if cancel.is_cancelled() {
                stop = Some(IntruderStopReason::Cancelled);
            } else if Instant::now() >= deadline {
                stop = Some(IntruderStopReason::DurationLimit);
                run_cancel.cancel();
            }
        }

        if stop.is_none() {
            while dispatched < total {
                if cancel.is_cancelled() {
                    stop = Some(IntruderStopReason::Cancelled);
                    break;
                }
                if Instant::now() >= deadline {
                    stop = Some(IntruderStopReason::DurationLimit);
                    run_cancel.cancel();
                    break;
                }
                if paused.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    break;
                };
                match gate.wait(&cancel, &paused, &notify, deadline).await {
                    GateOutcome::Started => {}
                    GateOutcome::Paused => {
                        drop(permit);
                        break;
                    }
                    GateOutcome::Stopped | GateOutcome::Deadline => {
                        drop(permit);
                        stop = Some(if cancel.is_cancelled() {
                            IntruderStopReason::Cancelled
                        } else {
                            IntruderStopReason::DurationLimit
                        });
                        break;
                    }
                }

                let index = dispatched;
                let payloads = payloads_for(&launch.plan, index as usize);
                let request = match launch.plan.slots(index as usize) {
                    Some(slots) => launch.template.expand(&launch.analysis, &slots),
                    None => Err(rawframe_core::TemplateError::InvalidHead(format!(
                        "combination {index} is out of range"
                    ))),
                };
                dispatched += 1;

                let request = match request {
                    Ok(request) => request,
                    Err(error) => {
                        let id = result_id(run, index);
                        let result = failed_result(
                            run,
                            index,
                            id,
                            payloads,
                            &launch,
                            &template_request,
                            format!("could not expand this combination: {error}"),
                        );
                        summary.record(result.outcome());
                        let entry = intruder_entry(id, &result, &template_request, launch.origin);
                        let _ = events
                            .send_async(AppEvent::Intruder(IntruderEvent::Completed {
                                run,
                                result: Box::new(result),
                                entry: Box::new(entry),
                            }))
                            .await;
                        drop(permit);
                        continue;
                    }
                };

                let engine = engine.clone();
                let task_events = events.clone();
                let task_cancel = run_cancel.clone();
                let positions = launch.plan.positions.clone();
                let follow_redirects = launch.follow_redirects;
                let origin = launch.origin;
                let template_for_entry = template_request.clone();
                let id = result_id(run, index);
                tasks.spawn(async move {
                    let _permit = permit;
                    let outcome = engine
                        .execute(&request, follow_redirects, task_cancel)
                        .await;
                    let result = IntruderResult {
                        id,
                        run,
                        index,
                        payloads,
                        positions,
                        phase: outcome.phase.clone(),
                        result: outcome.result,
                    };
                    let entry = intruder_entry(id, &result, &template_for_entry, origin);
                    let _ = task_events
                        .send_async(AppEvent::Intruder(IntruderEvent::Completed {
                            run,
                            result: Box::new(result.clone()),
                            entry: Box::new(entry),
                        }))
                        .await;
                    result
                });
            }
        }

        // Publish pause/resume transitions once, not per loop iteration.
        let phase_state = if stop.is_some() {
            IntruderPhaseState::Running
        } else if paused.load(Ordering::Relaxed) {
            IntruderPhaseState::Paused
        } else {
            IntruderPhaseState::Running
        };
        if last_phase != Some(phase_state) && stop.is_none() {
            last_phase = Some(phase_state);
            let _ = events
                .send_async(AppEvent::Intruder(IntruderEvent::Phase {
                    run,
                    phase: phase_state.as_phase(),
                }))
                .await;
        }

        if tasks.is_empty() {
            if stop.is_some() {
                break;
            }
            if paused.load(Ordering::Relaxed) {
                match wait_for_resume_outcome(&cancel, &paused, &notify, deadline).await {
                    ResumeOutcome::Resumed => continue,
                    ResumeOutcome::Stopped => {
                        stop = Some(IntruderStopReason::Cancelled);
                        continue;
                    }
                    ResumeOutcome::Deadline => {
                        stop = Some(IntruderStopReason::DurationLimit);
                        run_cancel.cancel();
                        continue;
                    }
                }
            }
            if dispatched >= total {
                break;
            }
            // A permit should always be free when nothing is in flight; this
            // guard prevents a busy spin if that invariant is ever broken.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }

        let joined = if stop.is_some() {
            tasks.join_next().await
        } else {
            tokio::select! {
                joined = tasks.join_next() => joined,
                _ = cancel.cancelled() => {
                    stop = Some(IntruderStopReason::Cancelled);
                    continue;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    stop = Some(IntruderStopReason::DurationLimit);
                    run_cancel.cancel();
                    continue;
                }
            }
        };

        match joined {
            Some(Ok(result)) => {
                if result.run == run {
                    summary.record(result.outcome());
                }
            }
            Some(Err(error)) => {
                if error.is_panic() {
                    tracing::error!(%error, "Intruder execution task panicked");
                }
                summary.record(IntruderOutcome::Failed);
            }
            None => break,
        }
    }

    summary.duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    summary.not_sent = total.saturating_sub(summary.sent);
    summary.reason = stop.or(Some(IntruderStopReason::Complete));
    if summary.not_sent > 0 && summary.reason == Some(IntruderStopReason::Complete) {
        // Defensive: if anything prevented a request from being dispatched, the
        // run did not complete the plan and must not claim that it did.
        summary.reason = Some(IntruderStopReason::Shutdown);
    }

    let _ = events
        .send_async(AppEvent::Intruder(IntruderEvent::Finished { run, summary }))
        .await;
    summary
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntruderPhaseState {
    Running,
    Paused,
}

impl IntruderPhaseState {
    fn as_phase(self) -> rawframe_core::IntruderPhase {
        match self {
            Self::Running => rawframe_core::IntruderPhase::Running,
            Self::Paused => rawframe_core::IntruderPhase::Paused,
        }
    }
}

fn result_id(run: u64, index: u64) -> TrafficId {
    TrafficId(
        INTRUDER_ID_BASE
            .saturating_add(run.saturating_mul(MAX_GENERATED_REQUESTS))
            .saturating_add(index + 1),
    )
}

fn payloads_for(plan: &rawframe_core::AttackPlan, index: usize) -> Vec<Vec<u8>> {
    let Some(slots) = plan.slots(index) else {
        return Vec::new();
    };
    plan.positions
        .iter()
        .filter_map(|position| slots.get(position).cloned())
        .collect()
}

/// The template as a real request, used only as provenance metadata for
/// persistence (never transmitted).
fn build_template_request(launch: &IntruderLaunch) -> HttpRequest {
    let mut headers = Headers::new();
    for (name, value) in &launch.template.headers {
        headers.append(name.clone(), value.clone());
    }
    HttpRequest {
        method: launch.template.method.clone(),
        scheme: launch.template.scheme,
        host: launch.template.host.clone(),
        port: launch.template.port,
        target: launch.template.target.clone(),
        version: launch.template.version.clone(),
        headers,
        body: launch.template.body.clone(),
    }
}

fn failed_result(
    run: u64,
    index: u64,
    id: TrafficId,
    payloads: Vec<Vec<u8>>,
    launch: &IntruderLaunch,
    template_request: &HttpRequest,
    error: String,
) -> IntruderResult {
    let request = template_request.clone();
    IntruderResult {
        id,
        run,
        index,
        payloads,
        positions: launch.plan.positions.clone(),
        phase: RepeaterExecutionPhase::Failed,
        result: RepeaterResult {
            request,
            response: None,
            timings: RepeaterTimings::default(),
            redirects: Vec::new(),
            truncated: false,
            response_bytes: 0,
            error: Some(error),
            warnings: Vec::new(),
            sent_at: chrono::Utc::now(),
        },
    }
}

/// Smallest useful helper for tests and callers that need to know the id of a
/// planned request before it runs.
pub fn planned_id(run: u64, index: u64) -> TrafficId {
    result_id(run, index)
}

/// Resolves a plan row to its payload map. Exposed for tests that assert the
/// engine sends exactly the combination the preview showed.
pub fn combination_slots(
    plan: &rawframe_core::AttackPlan,
    index: usize,
) -> Option<BTreeMap<rawframe_core::PositionId, Vec<u8>>> {
    plan.slots(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_across_runs_and_indices() {
        assert_eq!(planned_id(0, 0), TrafficId(INTRUDER_ID_BASE + 1));
        assert_eq!(
            planned_id(1, 0),
            TrafficId(INTRUDER_ID_BASE + MAX_GENERATED_REQUESTS + 1)
        );
        assert_ne!(planned_id(0, 5), planned_id(1, 5));
    }

    #[test]
    fn rate_gate_interval_matches_the_configured_rate() {
        let gate = RateGate::new(4);
        assert_eq!(gate.interval, Duration::from_millis(250));
        let slowest = RateGate::new(1);
        assert_eq!(slowest.interval, Duration::from_secs(1));
        // A zero rate is clamped rather than dividing by zero.
        let clamped = RateGate::new(0);
        assert_eq!(clamped.interval, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn rate_gate_serializes_starts() {
        let gate = RateGate::new(20);
        let cancel = CancellationToken::new();
        let paused = AtomicBool::new(false);
        let notify = Notify::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        let started = Instant::now();
        for _ in 0..5 {
            assert_eq!(
                gate.wait(&cancel, &paused, &notify, deadline).await,
                GateOutcome::Started,
                "gate must allow a start while not cancelled"
            );
        }
        // Four intervals of 50 ms elapse; the first start is immediate.
        assert!(started.elapsed() >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn cancel_wakes_the_gate() {
        let gate = RateGate::new(1);
        let cancel = CancellationToken::new();
        let paused = AtomicBool::new(false);
        let notify = Notify::new();
        let deadline = Instant::now() + Duration::from_secs(30);

        assert_eq!(
            gate.wait(&cancel, &paused, &notify, deadline).await,
            GateOutcome::Started
        );
        let cancelled = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancelled.cancel();
        });
        assert_eq!(
            gate.wait(&cancel, &paused, &notify, deadline).await,
            GateOutcome::Stopped,
            "cancellation must not start another request"
        );
    }

    #[tokio::test]
    async fn pause_blocks_starts_until_resumed() {
        let gate = RateGate::new(50);
        let cancel = CancellationToken::new();
        let paused = Arc::new(AtomicBool::new(true));
        let notify = Arc::new(Notify::new());
        let deadline = Instant::now() + Duration::from_secs(5);

        let flag = paused.clone();
        let wake = notify.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            flag.store(false, Ordering::Relaxed);
            wake.notify_waiters();
        });

        let started = Instant::now();
        assert_eq!(
            gate.wait(&cancel, &paused, &notify, deadline).await,
            GateOutcome::Paused,
            "a paused run must report the pause instead of dispatching"
        );
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn deadline_ends_a_paused_wait() {
        let cancel = CancellationToken::new();
        let paused = AtomicBool::new(true);
        let notify = Notify::new();
        let deadline = Instant::now() + Duration::from_millis(120);
        assert_eq!(
            wait_for_resume_outcome(&cancel, &paused, &notify, deadline).await,
            ResumeOutcome::Deadline
        );
    }
}
