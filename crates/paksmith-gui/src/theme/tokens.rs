//! Design tokens: one source of truth for spacing, radius, type scale, and
//! colour alpha levels.
//!
//! These constants are defined here for use by UI components in later tasks;
//! the dead-code lint is suppressed until they are consumed.
#![allow(dead_code)]

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 20.0;
pub const RADIUS: f32 = 6.0;
pub const TEXT_SM: u16 = 12;
pub const TEXT_MD: u16 = 14;
pub const TEXT_LG: u16 = 18;
/// Extra-large heading size — used for full-area panel headings (key-prompt,
/// About) so both panels share the same type scale entry.
pub const TEXT_XL: u16 = 22;
/// Per-level indent step for the file-tree widget (pixels per depth level).
pub const TREE_INDENT: f32 = 16.0;
/// Fixed width of the key column in the detail pane's key/value rows.
pub const DETAIL_LABEL_WIDTH: f32 = 120.0;
/// Grab leeway (px each side) for the pane_grid resize handle.
pub const DIVIDER_GRAB_PX: f32 = 5.0;

/// Alpha for secondary / muted body text — chosen to clear WCAG-AA (4.5:1)
/// against both the Light and Dark theme backgrounds.
///
/// Apply as `palette().text.scale_alpha(TEXT_MUTED_ALPHA)` for all placeholder
/// and secondary-body text.  Deliberately-faint non-text uses (selection
/// highlight backgrounds, chip tints) may retain their own alpha values.
pub const TEXT_MUTED_ALPHA: f32 = 0.68;
