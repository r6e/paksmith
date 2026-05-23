//! `FText` deserialization.
//!
//! Wire layout for `ETextHistoryType::None (-1)`:
//!
//! ```text
//! Flags:                          u32
//! HistoryType:                    i8  (= -1)
//! if FEditorObjectVersion >= 33:                    // CultureInvariantTextSerializationKeyStability gate
//!   bHasCultureInvariantString:   u32
//!   if bHasCultureInvariantString:
//!     CultureInvariantString:     FString
//! ```
//!
//! Absence of an `FEditorObjectVersion` entry on the summary's
//! custom-version table is treated as "stamp implicit, ≥ 33" —
//! paksmith's UE4 floor (504 / UE 4.21) post-dates the gate, so
//! modern cooked content always has the field.
//!
//! Wire layout for `ETextHistoryType::Base (0)`:
//!
//! ```text
//! Flags:        u32
//! HistoryType:  i8  (= 0)
//! Namespace:    FString
//! Key:          FString
//! SourceString: FString
//! ```
//!
//! All other history types: `Flags` + `HistoryType` read, remaining
//! bytes skipped to `value_start + tag_size`. Stored as
//! [`FTextHistory::Unknown`].

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::custom_version::{
    EDITOR_OBJECT_VERSION_CULTURE_INVARIANT_KEY_STABILITY, EDITOR_OBJECT_VERSION_GUID,
};
use crate::asset::read_asset_fstring;
use crate::error::{AssetAllocationContext, AssetParseFault, AssetWireField, PaksmithError};

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

/// Read one `FText` from `reader`.
///
/// `tag_size` is the `FPropertyTag::Size` for the enclosing
/// `TextProperty` — used to compute how many bytes to skip for
/// unknown history types. `reader` must be positioned at the start of
/// the FText payload (immediately after the tag header).
///
/// # Errors
///
/// - [`AssetParseFault::UnexpectedEof`] / [`PaksmithError::Io`] on short reads.
/// - [`AssetParseFault::FStringMalformed`] for malformed text-body FStrings.
pub fn read_ftext<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    tag_size: u64,
) -> crate::Result<FText> {
    let eof = |field: AssetWireField| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    };

    let start_pos = reader.stream_position().map_err(PaksmithError::Io)?;

    let flags = reader
        .read_u32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::FTextHistoryType))?;
    let history_type = reader
        .read_i8()
        .map_err(|_| eof(AssetWireField::FTextHistoryType))?;

    let history = match history_type {
        -1 => {
            // `bHasCultureInvariantString` is gated behind
            // `FEditorObjectVersion::CultureInvariantTextSerializationKeyStability`
            // (= 33). Below the gate the field isn't on the wire and
            // the decoder must not consume those bytes. Absence of the
            // `FEditorObjectVersion` stamp on the summary defaults to
            // "modern cooked content" (paksmith's UE4 floor is 504 /
            // 4.21, post-gate); the field IS present. See
            // unreal_asset@f4df5d8 `str_property.rs:179-190` and
            // CUE4Parse `FTextHistory.None`.
            let needs_has_culture = ctx
                .custom_versions
                .version_for(EDITOR_OBJECT_VERSION_GUID)
                .is_none_or(|v| v >= EDITOR_OBJECT_VERSION_CULTURE_INVARIANT_KEY_STABILITY);
            let culture_invariant = if needs_has_culture {
                // Wire-encoded as a 4-byte i32 via `FArchive::ReadBoolean`.
                let has_culture = reader
                    .read_u32::<LittleEndian>()
                    .map_err(|_| eof(AssetWireField::FTextField))?;
                if has_culture != 0 {
                    Some(read_asset_fstring(reader, asset_path)?)
                } else {
                    None
                }
            } else {
                None
            };
            FTextHistory::None { culture_invariant }
        }
        0 => {
            // Modern UE writers emit all three FStrings unconditionally
            // for ETextHistoryType::Base. Empty namespace/key strings
            // are common (UE often emits namespace="" for non-localized
            // text); the asset-side fstring wrapper accepts len=0 as ""
            // — see Decision #9 and asset/fstring.rs.
            let namespace = read_asset_fstring(reader, asset_path)?;
            let key = read_asset_fstring(reader, asset_path)?;
            let source_string = read_asset_fstring(reader, asset_path)?;
            FTextHistory::Base {
                namespace,
                key,
                source_string,
            }
        }
        other => {
            let current_pos = reader.stream_position().map_err(PaksmithError::Io)?;
            let consumed = current_pos.saturating_sub(start_pos);
            let remaining_u64 = tag_size.saturating_sub(consumed);
            let remaining =
                usize::try_from(remaining_u64).map_err(|_| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::U64ExceedsPlatformUsize {
                        field: AssetWireField::FTextField,
                        value: remaining_u64,
                    },
                })?;
            // Match the property-side Unknown skip allocation policy
            // (mod.rs's read_properties): try_reserve_exact routes OOM
            // through AllocationFailed { context: UnknownFTextBytes }
            // rather than aborting. Per-call bounded by tag_size <=
            // MAX_PROPERTY_TAG_SIZE.
            let mut skip_buf = Vec::new();
            skip_buf
                .try_reserve_exact(remaining)
                .map_err(|source| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::AllocationFailed {
                        context: AssetAllocationContext::UnknownFTextBytes,
                        requested: remaining,
                        source,
                    },
                })?;
            skip_buf.resize(remaining, 0);
            reader
                .read_exact(&mut skip_buf)
                .map_err(|_| eof(AssetWireField::FTextField))?;
            FTextHistory::Unknown {
                history_type: other,
                skipped_bytes: remaining,
            }
        }
    };

    Ok(FText { flags, history })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::make_ctx;
    use std::io::Cursor;

    fn empty_ctx() -> AssetContext {
        // text.rs tests don't reference any FNames, so an empty
        // name table suffices.
        make_ctx(&[])
    }

    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len() + 1;
        buf.extend_from_slice(&i32::try_from(len).unwrap().to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.push(0u8);
    }

    fn ctx_with_editor_object_version(version: i32) -> AssetContext {
        use crate::asset::custom_version::{
            CustomVersion, CustomVersionContainer, EDITOR_OBJECT_VERSION_GUID,
        };
        use std::sync::Arc;
        let mut ctx = make_ctx(&[]);
        ctx.custom_versions = Arc::new(CustomVersionContainer {
            versions: vec![CustomVersion {
                guid: EDITOR_OBJECT_VERSION_GUID,
                version,
            }],
        });
        ctx
    }

    #[test]
    fn history_none_skips_has_culture_field_below_editor_version_33() {
        // Per `unreal_asset@f4df5d8` `str_property.rs:179-190`:
        //   `if version >= FEditorObjectVersion::CultureInvariantTextSerializationKeyStability`
        // gates the `bHasCultureInvariantString` u32 read. If the
        // editor-object-version stamp is < 33, the field is NOT on
        // the wire and the decoder must not consume those bytes.
        //
        // Wire bytes: u32 flags + i8 history_type + (NO has_culture);
        // a sentinel u8 at offset 5 detects whether the decoder
        // walked past the history_type byte unexpectedly.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.push(0x42u8); // sentinel (NOT a has_culture field)

        let ctx = ctx_with_editor_object_version(32);
        // `tag_size` is consulted only by the `Unknown` arm; for the
        // `-1` (None) branch the witness is the sentinel readback at
        // offset 5 after `read_ftext` returns.
        let tag_size = 5u64;
        let mut cur = Cursor::new(&buf[..]);
        let text = read_ftext(&mut cur, &ctx, "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            },
            "history must be None with no culture_invariant when gate is off"
        );
        let sentinel = {
            use byteorder::ReadBytesExt;
            cur.read_u8().expect("sentinel byte")
        };
        assert_eq!(
            sentinel, 0x42,
            "decoder must not consume bytes past history_type when FEditorObjectVersion < 33"
        );
    }

    #[test]
    fn history_none_reads_has_culture_field_when_no_editor_version_stamp() {
        // Absent `FEditorObjectVersion` entry defaults to "modern" —
        // paksmith's UE4 floor (504 / 4.21) post-dates the gate
        // (UE 4.15). The decoder MUST read the field.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.extend_from_slice(&0u32.to_le_bytes()); // bHasCultureInvariantString = 0
        // `empty_ctx()` has a default-empty `CustomVersionContainer`,
        // so `version_for(EDITOR_OBJECT_VERSION_GUID)` returns `None`.
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            }
        );
    }

    #[test]
    fn history_none_reads_has_culture_field_at_editor_version_33() {
        // FEditorObjectVersion = 33 (CultureInvariantTextSerializationKeyStability):
        // the field IS on the wire. Round-trips through the standard
        // happy-path layout.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.extend_from_slice(&0u32.to_le_bytes()); // bHasCultureInvariantString = 0
        let ctx = ctx_with_editor_object_version(33);
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &ctx, "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            }
        );
    }

    #[test]
    fn history_none_no_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.extend_from_slice(&0u32.to_le_bytes()); // bHasCultureInvariantString (u32) = 0
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(text.flags, 0);
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            }
        );
    }

    #[test]
    fn history_none_with_culture_invariant() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.extend_from_slice(&1u32.to_le_bytes()); // bHasCultureInvariantString (u32) = 1
        write_fstring(&mut buf, "Hello World");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: Some("Hello World".to_string())
            }
        );
    }

    #[test]
    fn history_base() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0u8);
        write_fstring(&mut buf, "MyNamespace");
        write_fstring(&mut buf, "MyKey");
        write_fstring(&mut buf, "Source string value");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Base {
                namespace: "MyNamespace".to_string(),
                key: "MyKey".to_string(),
                source_string: "Source string value".to_string(),
            }
        );
    }

    #[test]
    fn history_none_consumes_four_byte_has_culture_field() {
        // Wire format: `bHasCultureInvariantString` is a 4-byte field
        // (`FArchive::ReadBoolean` reads i32). Witnesses:
        //   - unreal_asset@f4df5d8 str_property.rs:187 (`read_i32::<LE>()`)
        //   - CUE4Parse `FTextHistory.None` (`Ar.ReadBoolean()` → 4-byte i32)
        // A sentinel placed after the FText catches the 3-byte cursor desync
        // that would result from reading only 1 byte.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1 (None)
        buf.extend_from_slice(&0u32.to_le_bytes()); // bHasCultureInvariantString = 0 (u32)
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sentinel

        let mut cur = Cursor::new(&buf[..]);
        let tag_size: u64 = 9; // flags(4) + history_type(1) + has_culture(4)
        let text = read_ftext(&mut cur, &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            }
        );
        let sentinel = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(
            sentinel, 0xDEAD_BEEF,
            "FText::None must consume all 4 bytes of bHasCultureInvariantString"
        );
    }

    #[test]
    fn unknown_history_type_skips_remaining_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(3u8);
        buf.extend_from_slice(&[0xAAu8; 20]);
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Unknown {
                history_type: 3,
                skipped_bytes: 20
            }
        );
    }
}
