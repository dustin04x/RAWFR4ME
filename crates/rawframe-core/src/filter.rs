//! Search and filter state for HTTP history.

use super::models::message::StatusClass;
use super::models::traffic::TrafficEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusFilter {
    #[default]
    All,
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
}

impl StatusFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "all status",
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirection => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::Success,
            Self::Success => Self::Redirection,
            Self::Redirection => Self::ClientError,
            Self::ClientError => Self::ServerError,
            Self::ServerError => Self::Informational,
            Self::Informational => Self::All,
        }
    }

    pub fn accepts(self, class: Option<StatusClass>) -> bool {
        match self {
            Self::All => true,
            _ => {
                let Some(class) = class else {
                    return false;
                };
                matches!(
                    (self, class),
                    (Self::Informational, StatusClass::Informational)
                        | (Self::Success, StatusClass::Success)
                        | (Self::Redirection, StatusClass::Redirection)
                        | (Self::ClientError, StatusClass::ClientError)
                        | (Self::ServerError, StatusClass::ServerError)
                )
            }
        }
    }
}

/// Filters are cumulative: every populated field must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryFilter {
    pub query: String,
    pub method: Option<String>,
    pub status: StatusFilter,
    pub host: Option<String>,
}

impl HistoryFilter {
    pub fn is_active(&self) -> bool {
        !self.query.trim().is_empty()
            || self.method.is_some()
            || self.status != StatusFilter::All
            || self.host.is_some()
    }

    pub fn active_count(&self) -> usize {
        usize::from(!self.query.trim().is_empty())
            + usize::from(self.method.is_some())
            + usize::from(self.status != StatusFilter::All)
            + usize::from(self.host.is_some())
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn matches(&self, entry: &TrafficEntry) -> bool {
        if let Some(method) = &self.method
            && !entry.request.method.eq_ignore_ascii_case(method)
        {
            return false;
        }

        if !self.status.accepts(entry.status_class()) {
            return false;
        }

        if let Some(host) = &self.host
            && !entry.request.host.eq_ignore_ascii_case(host)
        {
            return false;
        }

        let query = self.query.trim().to_ascii_lowercase();
        if query.is_empty() {
            return true;
        }

        let haystack = format!(
            "{} {} {} {} {} {}",
            entry.request.method,
            entry.request.host,
            entry.request.target,
            entry.status_label(),
            entry.state.label(),
            entry.source.label()
        )
        .to_ascii_lowercase();

        query
            .split_whitespace()
            .all(|token| haystack.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::simulated_traffic;
    use crate::models::traffic::TrafficState;

    fn entries() -> Vec<TrafficEntry> {
        simulated_traffic()
    }

    #[test]
    fn empty_filter_matches_everything_and_is_inactive() {
        let filter = HistoryFilter::default();
        assert!(!filter.is_active());
        assert_eq!(filter.active_count(), 0);
        assert!(entries().iter().all(|entry| filter.matches(entry)));
    }

    #[test]
    fn query_tokens_are_cumulative() {
        let filter = HistoryFilter {
            query: "post orders".into(),
            ..HistoryFilter::default()
        };
        let matched: Vec<_> = entries()
            .into_iter()
            .filter(|entry| filter.matches(entry))
            .collect();

        assert!(!matched.is_empty());
        for entry in matched {
            assert_eq!(entry.request.method, "POST");
            assert!(entry.request.target.contains("orders"));
        }
    }

    #[test]
    fn method_and_status_filters_apply_together() {
        let filter = HistoryFilter {
            method: Some("GET".into()),
            status: StatusFilter::ServerError,
            ..HistoryFilter::default()
        };
        let matched: Vec<_> = entries()
            .into_iter()
            .filter(|entry| filter.matches(entry))
            .collect();

        assert!(!matched.is_empty());
        for entry in matched {
            assert_eq!(entry.request.method, "GET");
            assert_eq!(entry.response.as_ref().unwrap().status, 500);
        }
    }

    #[test]
    fn status_filter_excludes_pending_requests() {
        let filter = HistoryFilter {
            status: StatusFilter::Success,
            ..HistoryFilter::default()
        };
        for entry in entries() {
            if entry.state.is_pending() {
                assert!(!filter.matches(&entry));
            }
        }
    }

    #[test]
    fn host_filter_is_case_insensitive() {
        let filter = HistoryFilter {
            host: Some("API.RAWFRAME.TEST".into()),
            ..HistoryFilter::default()
        };
        assert!(entries().iter().any(|entry| filter.matches(entry)));
    }

    #[test]
    fn filter_activity_count_and_clear() {
        let mut filter = HistoryFilter {
            query: "users".into(),
            method: Some("GET".into()),
            status: StatusFilter::Success,
            host: Some("api.rawframe.test".into()),
        };
        assert!(filter.is_active());
        assert_eq!(filter.active_count(), 4);

        filter.clear();
        assert_eq!(filter, HistoryFilter::default());
    }

    #[test]
    fn status_filter_cycles_through_all_classes() {
        let mut status = StatusFilter::All;
        for _ in 0..6 {
            status = status.next();
        }
        assert_eq!(status, StatusFilter::All);
        assert_eq!(StatusFilter::Success.label(), "2xx");
    }

    #[test]
    fn dropped_entries_can_still_be_found_by_state_query() {
        let filter = HistoryFilter {
            query: "dropped".into(),
            ..HistoryFilter::default()
        };
        let matched: Vec<_> = entries()
            .into_iter()
            .filter(|entry| filter.matches(entry))
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].state, TrafficState::Dropped);
    }
}
