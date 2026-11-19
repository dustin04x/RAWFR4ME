//! RAWFRAME's terminal interface.
//!
//! The UI is an application shell around seven interactive workspaces: Proxy,
//! HTTP History, WebSocket, Repeater, Intruder, Decoder, and Settings. It
//! consumes [`AppEvent`]s and never reaches into networking or storage
//! internals. Simulated traffic is labelled everywhere it appears; an empty
//! workspace says so instead of mocking working behaviour.

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
pub mod websocket;

pub use app::App;
pub use interaction::NavSection;
pub use terminal::run;
pub use theme::Theme;

pub use rawframe_core::AppEvent;
