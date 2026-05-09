//! Error types for paksmith operations.

use std::io;

/// Top-level error type for all paksmith-core operations.
#[derive(Debug, thiserror::Error)]
pub enum PaksmithError {
    /// Operation has not been implemented yet.
    #[error("not yet implemented")]
    NotImplemented,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}
