//! Error types for paksmith operations.

use std::io;

/// Top-level error type for all paksmith-core operations.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum PaksmithError {
    /// Decryption failure due to invalid or missing AES key.
    #[error("decryption failed for `{path}`: invalid or missing AES key")]
    Decryption { path: String },

    /// The pak file version is not recognized.
    #[error("unsupported pak version {version}")]
    UnsupportedVersion { version: u32 },

    /// Decompression failure at a specific file offset.
    #[error("decompression failed at offset {offset}")]
    Decompression { offset: u64 },

    /// Asset deserialization failure.
    #[error("asset deserialization failed for `{asset_path}`: {reason}")]
    AssetParse { reason: String, asset_path: String },

    /// The pak footer is malformed.
    #[error("invalid pak footer: {reason}")]
    InvalidFooter { reason: String },

    /// The pak index is malformed.
    #[error("invalid pak index: {reason}")]
    InvalidIndex { reason: String },

    /// A requested entry was not found in the archive.
    #[error("entry not found: `{path}`")]
    EntryNotFound { path: String },

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_decryption() {
        let err = PaksmithError::Decryption {
            path: "Game/Content.pak".into(),
        };
        assert_eq!(
            err.to_string(),
            "decryption failed for `Game/Content.pak`: invalid or missing AES key"
        );
    }

    #[test]
    fn error_display_unsupported_version() {
        let err = PaksmithError::UnsupportedVersion { version: 99 };
        assert_eq!(err.to_string(), "unsupported pak version 99");
    }

    #[test]
    fn error_display_invalid_footer() {
        let err = PaksmithError::InvalidFooter {
            reason: "magic mismatch".into(),
        };
        assert_eq!(err.to_string(), "invalid pak footer: magic mismatch");
    }

    #[test]
    fn error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: PaksmithError = io_err.into();
        assert!(matches!(err, PaksmithError::Io(_)));
    }
}
