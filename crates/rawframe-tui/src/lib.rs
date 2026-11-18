//! RAWFRAME's terminal interface.
//!
//! The UI is an application shell around four interactive workspaces: Proxy,
//! HTTP History, Repeater, and Settings. It consumes [`AppEvent`]s and never
//! reaches into networking or storage internals. Simulated traffic is labelled
//! everywhere it appears; unimplemented modules are presented as planned rather
//! than mocked as working.

pub mod app;
pub mod commands;
pub mod components;
pub mod input;
pub mod interaction;
pub mod intruder;
pub mod layout;
pub mod screens;
pub mod state;
pub mod terminal;
pub mod testing;
pub mod text;
pub mod theme;
pub mod ui;

pub use app::App;
pub use interaction::NavSection;
pub use terminal::run;
pub use theme::Theme;

pub use rawframe_core::AppEvent;
