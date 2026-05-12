//! Per-entry compression metadata: method enum + block range.
//!
//! Two domain types live here, both referenced from
//! [`super::EntryCommon`]: [`CompressionMethod`] (the algorithm) and
//! [`CompressionBlock`] (a single compressed byte range within the
//! entry payload).

use std::num::NonZeroU32;

use crate::error::{IndexParseFault, PaksmithError};

/// Compression method used for a pak entry.
///
/// On disk, the per-entry compression byte means different things by
/// version:
/// - **v3-v7**: a raw method ID (0=None, 1=Zlib, 2=Gzip, 4=Oodle).
///   Resolved via [`CompressionMethod::from_u32`].
/// - **v8+**: a 1-based index into the footer's compression-methods FName
///   table (0 = no compression, N = `compression_methods[N-1]`). The
///   table itself contains FName strings — `"Zlib"`, `"Oodle"`, etc. —
///   resolved via [`CompressionMethod::from_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression applied.
    None,
    /// Zlib (deflate) compression.
    Zlib,
    /// Gzip compression.
    Gzip,
    /// Oodle compression (Epic proprietary).
    Oodle,
    /// Zstandard compression (Epic added v8+).
    Zstd,
    /// LZ4 compression (Epic added v8+).
    Lz4,
    /// Unrecognized v3-v7 compression method ID, or v8+ table index whose
    /// slot resolved to `None`/Unknown. Held as [`NonZeroU32`] because the
    /// zero value is reserved for [`CompressionMethod::None`] (no
    /// compression) — `Unknown(0)` would be both meaningless and a footgun
    /// (operators reading "unknown method 0" would assume a real
    /// unrecognized method, not "no compression"). Preserved for
    /// diagnostics.
    Unknown(NonZeroU32),
    /// Unrecognized v8+ compression FName, preserved verbatim so error
    /// messages can name the slot's actual contents (e.g.,
    /// `"OodleNetwork"`, `"LZMA"`) rather than collapsing every unknown
    /// name to a single sentinel.
    UnknownByName(String),
}

impl CompressionMethod {
    /// Parse a raw `u32` compression method identifier (v3-v7 wire format).
    pub fn from_u32(value: u32) -> Self {
        // Zero means "no compression" — bind to None and never reach the
        // Unknown arm. The let-else makes the NonZeroU32 invariant
        // structural rather than relying on an `unwrap`/`expect` after a
        // separate match arm.
        let Some(non_zero) = NonZeroU32::new(value) else {
            return Self::None;
        };
        match non_zero.get() {
            1 => Self::Zlib,
            2 => Self::Gzip,
            4 => Self::Oodle,
            _ => Self::Unknown(non_zero),
        }
    }

    /// Parse a compression method by name (v8+ FName-table entry). Match
    /// is case-insensitive against the canonical UE names. Unrecognized
    /// names return [`CompressionMethod::UnknownByName`] preserving the
    /// raw name so the entry's downstream lookup surfaces as a typed
    /// `Decompression` error that names the actual slot contents.
    ///
    /// Callers must not pass an empty string — the slot reader handles
    /// empty slots upstream by emitting `None` directly.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "zlib" => Self::Zlib,
            "gzip" => Self::Gzip,
            "oodle" => Self::Oodle,
            "zstd" => Self::Zstd,
            "lz4" => Self::Lz4,
            _ => Self::UnknownByName(name.to_owned()),
        }
    }
}

/// Byte offset range of a single compression block within the entry payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionBlock {
    start: u64,
    end: u64,
}

impl CompressionBlock {
    /// Construct a block, rejecting `start > end` as malformed.
    pub fn new(start: u64, end: u64) -> crate::Result<Self> {
        if start > end {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::CompressionBlockInvalid { start, end },
            });
        }
        Ok(Self { start, end })
    }

    /// Start offset (inclusive) of the compressed block.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// End offset (exclusive) of the compressed block.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Length of the block in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}
