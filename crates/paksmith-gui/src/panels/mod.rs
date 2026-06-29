//! UI panels: reusable view components that correspond to specific application
//! states. Each panel renders a distinct "screen" or pane region and emits
//! `Message` variants for user actions.

pub mod console;
pub mod content;
pub mod detail;
pub mod key_prompt;
pub mod sidebar;
pub mod status_bar;
pub mod toolbar;
