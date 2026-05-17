//! `FText` deserialization (Phase 2b Task 5 stub).
//!
//! This file is intentionally a stub during Task 4 so that
//! `primitives.rs`'s `TextProperty` arm can call into a stable
//! signature. Task 5 replaces the body with the full
//! `ETextHistoryType::None` / `Base` reader; until then, calling
//! [`read_ftext`] panics. The `TextProperty` test in `primitives.rs`
//! does not exercise this path.

use std::io::{Read, Seek};

use serde::Serialize;

use crate::asset::AssetContext;

/// Decoded `FText` value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FText {
    /// UE text flags (serialization hints; usually 0).
    pub flags: u32,
    /// The decoded history variant.
    pub history: FTextHistory,
}

/// Discriminated union over `ETextHistoryType` variants.
///
/// Phase 2b handles `None (-1)` and `Base (0)`. All other variants are
/// stored as `Unknown { history_type, skipped_bytes }`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum FTextHistory {
    /// `ETextHistoryType::None` — optionally a culture-invariant string.
    None {
        /// The culture-invariant override string, if present.
        culture_invariant: Option<String>,
    },
    /// `ETextHistoryType::Base` — the canonical localized text triple.
    Base {
        /// Namespace identifier (often empty for non-localized strings).
        namespace: String,
        /// Localization key.
        key: String,
        /// The raw source string (the English original, by convention).
        source_string: String,
    },
    /// Any `ETextHistoryType` variant Phase 2b does not decode.
    Unknown {
        /// The raw `ETextHistoryType` discriminant byte.
        history_type: i8,
        /// Number of bytes skipped past the discriminant.
        skipped_bytes: usize,
    },
}

/// Read one `FText` from `reader` (Task 5 stub).
///
/// # Panics
///
/// Panics unconditionally — the real implementation lands in Task 5.
/// The TextProperty arm in `read_primitive_value` only reaches this
/// when caller-supplied `tag.size > 0` for a `TextProperty`, which the
/// Task 4 test suite does not produce.
///
/// # Errors
///
/// Same surface as the future impl: short reads → `UnexpectedEof`,
/// malformed text-body FStrings → `FStringMalformed`.
pub fn read_ftext<R: Read + Seek>(
    _reader: &mut R,
    _ctx: &AssetContext,
    _asset_path: &str,
    _tag_size: u64,
) -> crate::Result<FText> {
    unimplemented!("read_ftext lands in Phase 2b Task 5")
}
