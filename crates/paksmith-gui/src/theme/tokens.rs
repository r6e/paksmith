//! Design tokens: one source of truth for spacing, radius, and type scale.
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
/// Per-level indent step for the file-tree widget (pixels per depth level).
pub const TREE_INDENT: f32 = 16.0;
