//! Terminal lifecycle and the responsive event loop.
//!
//! The loop never blocks on networking or storage. Input arrives on a channel
//! from a dedicated reader thread, application events are drained from the event
//! bus, and rendering happens on the UI thread.

use std::io::{self, Stdout};
use std::panic;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyEvent, MouseEvent,
};
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::crossterm::{cursor, execute};

use crate::app::App;
use crate::interaction::RenderOutput;
use crate::ui;

const IDLE_REDRAW: Duration = Duration::from_millis(250);
const INPUT_POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
enum InputEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(String),
    Resize(u16, u16),
}

/// Owns the terminal and restores it on every exit path, including panics.
struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn start() -> io::Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste,
            cursor::Hide
        ) {
            let _ = disable_raw_mode();
            return Err(error);
        }

        let backend = CrosstermBackend::new(io::stdout());
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal();
                Err(error)
            }
        }
    }

    fn draw(&mut self, app: &mut App) -> io::Result<()> {
        let mut output = RenderOutput::default();
        self.terminal.draw(|frame| {
            output = ui::render(frame, app);
        })?;
        app.apply_render(output);
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let mut stdout = io::stdout();
    let _ = execute!(
        stdout,
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen,
        cursor::Show
    );
    let _ = disable_raw_mode();
}

fn install_panic_hook() {
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

fn spawn_input_reader() -> Receiver<InputEvent> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("rawframe-input".into())
        .spawn(move || {
            loop {
                match event::poll(INPUT_POLL) {
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key)) => {
                            if sender.send(InputEvent::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(Event::Mouse(mouse)) => {
                            if sender.send(InputEvent::Mouse(mouse)).is_err() {
                                break;
                            }
                        }
                        Ok(Event::Paste(text)) => {
                            if sender.send(InputEvent::Paste(text)).is_err() {
                                break;
                            }
                        }
                        Ok(Event::Resize(width, height)) => {
                            if sender.send(InputEvent::Resize(width, height)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        })
        .expect("spawn terminal input reader");
    receiver
}

/// Runs the interactive workbench until the operator quits.
pub fn run(mut app: App) -> io::Result<()> {
    let receiver = spawn_input_reader();
    let mut session = TerminalSession::start()?;
    session.draw(&mut app)?;
    let mut last_draw = Instant::now();

    while !app.should_quit {
        let mut redraw = false;

        while let Some(event) = app.events.poll() {
            app.handle_event(event);
            redraw = true;
        }

        match receiver.recv_timeout(INPUT_POLL) {
            Ok(input) => {
                handle_input(&mut app, input);
                redraw = true;
                while let Ok(input) = receiver.try_recv() {
                    handle_input(&mut app, input);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        app.tick();
        if app.should_quit {
            break;
        }

        let idle_due = last_draw.elapsed() >= IDLE_REDRAW;
        if redraw || idle_due {
            session.draw(&mut app)?;
            last_draw = Instant::now();
        }
    }

    Ok(())
}

fn handle_input(app: &mut App, input: InputEvent) {
    match input {
        InputEvent::Key(key) => app.handle_key(key),
        InputEvent::Mouse(mouse) => app.handle_mouse(mouse),
        InputEvent::Paste(text) => app.handle_paste(&text),
        InputEvent::Resize(width, height) => {
            app.last_area = ratatui::layout::Rect::new(0, 0, width, height);
        }
    }
}
