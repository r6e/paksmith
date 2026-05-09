//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! Provides container readers (`.pak`, `IoStore`), asset deserialization,
//! format handlers, and game profile management.

pub mod container;
pub mod error;

pub use error::PaksmithError;

/// Convenience alias for `Result<T, PaksmithError>`.
pub type Result<T> = std::result::Result<T, PaksmithError>;
