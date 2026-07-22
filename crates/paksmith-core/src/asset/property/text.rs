//! `FText` deserialization.
//!
//! Wire layout for `ETextHistoryType::None (-1)`:
//!
//! ```text
//! Flags:                          u32
//! HistoryType:                    i8  (= -1)
//! if FEditorObjectVersion >= 32:                    // CultureInvariantTextSerializationKeyStability gate
//!   bHasCultureInvariantString:   u32
//!   if bHasCultureInvariantString:
//!     CultureInvariantString:     FString
//! ```
//!
//! Absence of an `FEditorObjectVersion` entry on the summary's
//! custom-version table is treated as "stamp implicit, ≥ 32" (field
//! present): CUE4Parse's `FEditorObjectVersion.Get()` returns its
//! latest version when the stamp is absent, and real cooked content in
//! range carries an explicit `FEditorObjectVersion` stamp.
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
//! Decoded history variants: `None (-1)`, `Base (0)`,
//! `NamedFormat (1)`, `OrderedFormat (2)`, and `StringTableEntry (11)`
//! (#641). All other history types: `Flags` + `HistoryType` read,
//! remaining bytes skipped to `value_start + tag_size`. Stored as
//! [`FTextHistory::Unknown`].

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};

use crate::asset::AssetContext;
use crate::asset::custom_version::{
    EDITOR_OBJECT_VERSION_CULTURE_INVARIANT_KEY_STABILITY, EDITOR_OBJECT_VERSION_GUID,
};
use crate::asset::property::MAX_COLLECTION_ELEMENTS;
use crate::asset::property::bag::MAX_PROPERTY_DEPTH;
use crate::asset::read_asset_fstring;
use crate::error::{
    AssetParseFault, AssetWireField, CollectionKind, PaksmithError, try_reserve_asset,
};
use crate::seams::AssetSeam;

/// Decoded `FText` value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FText {
    /// UE text flags (serialization hints; usually 0).
    pub flags: u32,
    /// The decoded history variant.
    pub history: FTextHistory,
}

/// Discriminated union over `ETextHistoryType` variants.
///
/// Decoded: `None (-1)`, `Base (0)`, `NamedFormat (1)`,
/// `OrderedFormat (2)`, `StringTableEntry (11)` (#641). All other
/// variants are stored as `Unknown { history_type, skipped_bytes }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// `ETextHistoryType::NamedFormat` (1) — a format pattern plus
    /// named arguments (`{Name}` placeholders). #641.
    NamedFormat {
        /// The format-pattern text (recursive `FText`).
        source_fmt: Box<FText>,
        /// The named arguments, in wire order.
        arguments: Vec<FTextNamedArg>,
    },
    /// `ETextHistoryType::OrderedFormat` (2) — a format pattern plus
    /// positional arguments (`{0}` placeholders). #641.
    OrderedFormat {
        /// The format-pattern text (recursive `FText`).
        source_fmt: Box<FText>,
        /// The positional arguments, in wire order.
        arguments: Vec<FTextFormatArg>,
    },
    /// `ETextHistoryType::StringTableEntry` (11) — a reference into a
    /// string table asset. #641.
    StringTableEntry {
        /// The string table's resolved FName (e.g.
        /// `/Game/Text/ST_UI.ST_UI`).
        table_id: String,
        /// The entry key within the table.
        key: String,
    },
    /// Any `ETextHistoryType` variant paksmith does not decode.
    Unknown {
        /// The raw `ETextHistoryType` discriminant byte.
        history_type: i8,
        /// Number of bytes skipped past the discriminant.
        skipped_bytes: usize,
    },
}

/// One named argument of an [`FTextHistory::NamedFormat`]: the
/// placeholder name plus its typed value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FTextNamedArg {
    /// The placeholder name (matches `{Name}` in the pattern).
    pub name: String,
    /// The argument value.
    pub value: FTextFormatArg,
}

/// A typed `FFormatArgumentValue` (`EFormatArgumentType` + payload).
///
/// Wire (per CUE4Parse `FText.cs` `FFormatArgumentValue`, non-
/// `isArgumentData` context — the NamedFormat/OrderedFormat path): an
/// `i8` type byte, then `Int(0)` → i64, `UInt(1)` → u64, `Float(2)` →
/// f32, `Double(3)` → f64, `Text(4)` → recursive `FText`.
/// `Gender(5)` and unknown type bytes fail closed
/// ([`AssetParseFault::TextFormatArgUnsupported`]) — neither CUE4Parse
/// nor UAssetAPI implements a Gender payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FTextFormatArg {
    /// `EFormatArgumentType::Int` — i64.
    Int(i64),
    /// `EFormatArgumentType::UInt` — u64.
    UInt(u64),
    /// `EFormatArgumentType::Float` — f32.
    Float(f32),
    /// `EFormatArgumentType::Double` — f64.
    Double(f64),
    /// `EFormatArgumentType::Text` — a nested `FText`.
    Text(Box<FText>),
}

/// Read one `FText` from `reader`.
///
/// `tag_size` is the `FPropertyTag::Size` for the enclosing
/// `TextProperty` — used to compute how many bytes to skip for
/// unknown history types. `reader` must be positioned at the start of
/// the FText payload (immediately after the tag header).
///
/// `depth` bounds the recursive nesting introduced by
/// `NamedFormat`/`OrderedFormat` (a format pattern and its `Text`-typed
/// arguments are full nested `FText`s): each nested read passes
/// `depth + 1` and the entry guard rejects `depth > MAX_PROPERTY_DEPTH`
/// — without it an adversarial asset could nest `FText`s until the
/// stack overflows (CUE4Parse has no such bound; overflow is its
/// failure mode). Every production call site threads its real
/// property-tree depth, so FText nesting COMPOSES with struct/array/map
/// nesting into the single `MAX_PROPERTY_DEPTH` budget.
///
/// # Errors
///
/// - [`AssetParseFault::PropertyDepthExceeded`] past `MAX_PROPERTY_DEPTH`.
/// - [`AssetParseFault::UnexpectedEof`] / [`PaksmithError::Io`] on short reads.
/// - [`AssetParseFault::FStringMalformed`] for malformed text-body FStrings.
/// - [`AssetParseFault::CollectionElementCountExceeded`] for a negative
///   or over-cap format-argument count.
/// - [`AssetParseFault::TextFormatArgUnsupported`] for a `Gender` or
///   unknown format-argument type byte.
/// - [`AssetParseFault::TextHistoryUnsupportedInElement`] when a NESTED
///   `FText` (format pattern / `Text` argument) carries an undecoded
///   history type — nested contexts have no size to skip with, same as
///   collection elements.
#[allow(
    clippy::too_many_lines,
    reason = "one linear match over ETextHistoryType wire variants; splitting per-variant helpers would scatter the shared start_pos/eof/depth plumbing without shortening any single arm"
)]
pub fn read_ftext<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    tag_size: u64,
    depth: usize,
) -> crate::Result<FText> {
    if depth > MAX_PROPERTY_DEPTH {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PropertyDepthExceeded {
                depth,
                limit: MAX_PROPERTY_DEPTH,
            },
        });
    }
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
            // (= 32, i.e. UE 4.23). Below the gate the field isn't on the
            // wire and the decoder must not consume those bytes. When the
            // `FEditorObjectVersion` stamp is absent, `is_none_or` treats
            // it as ≥ gate (field present), matching CUE4Parse's
            // `FEditorObjectVersion.Get()` latest-version fallback; real
            // cooked content in range carries an explicit stamp. See
            // unreal_asset `str_property.rs` and CUE4Parse `FTextHistory.None`.
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
        history_type @ (1 | 2) => {
            // NamedFormat (1) / OrderedFormat (2): recursive
            // source-pattern FText + i32 count + count × ([name FString
            // for NamedFormat] + FFormatArgumentValue). Per CUE4Parse
            // `FTextHistory.{Named,Ordered}Format` (FText.cs). #641.
            //
            // RECOVERY (direct/tagged context only, `tag_size > 0`): a
            // structurally-decodable format history can still contain an
            // UNDECODED nested piece — a pattern/argument FText with an
            // unsupported history (e.g. AsNumber) or a Gender argument.
            // Pre-#641 such content was lossy-skipped whole as `Unknown`;
            // hard-failing it now would REGRESS whole-export fidelity.
            // Catch exactly those two faults and degrade to the same
            // skip-to-tag-end `Unknown` the undecoded arm uses. EOF /
            // Io / count-cap / depth-cap faults stay fail-closed
            // (truncation or crafted input). In size-less contexts
            // (`tag_size == 0`) there is nothing to skip with, so the
            // fault propagates — the existing element/unversioned
            // recoverable-fault contract handles it there.
            match read_format_history(reader, ctx, asset_path, depth, history_type == 1) {
                Ok(history) => history,
                Err(e) if tag_size > 0 && is_recoverable_nested_text_fault(&e) => {
                    let skipped = skip_to_tag_end(reader, start_pos, tag_size, asset_path)?;
                    FTextHistory::Unknown {
                        history_type,
                        skipped_bytes: skipped,
                    }
                }
                Err(e) => return Err(e),
            }
        }
        11 => {
            // StringTableEntry: TableId FName + Key FString. No version
            // gates. Per CUE4Parse `FTextHistory.StringTableEntry`
            // (FText.cs) and UAssetAPI `TextPropertyData`. #641.
            //
            // No Unknown-recovery here (unlike arms 1|2): the faults this
            // arm can raise (`PackageIndexOob` / `FStringMalformed`) fire
            // only on corrupt or version-skewed input — a well-formed
            // asset's table_id/key always resolve — and fail-closed on
            // corruption is how NameProperty/StrProperty already behave
            // in the tagged path. Arms 1|2 recover because their faults
            // also fire on VALID content (an undecoded nested variant).
            let table_id =
                super::read_fname_pair(reader, ctx, asset_path, AssetWireField::FTextField)?;
            let key = read_asset_fstring(reader, asset_path)?;
            FTextHistory::StringTableEntry {
                table_id: table_id.to_string(),
                key,
            }
        }
        other => {
            // Skip the unrecognized FText history bytes; per-call
            // bounded by `tag_size <= MAX_PROPERTY_TAG_SIZE` (16 MiB).
            let skipped = skip_to_tag_end(reader, start_pos, tag_size, asset_path)?;
            FTextHistory::Unknown {
                history_type: other,
                skipped_bytes: skipped,
            }
        }
    };

    Ok(FText { flags, history })
}

/// Decode a `NamedFormat` (`named == true`) or `OrderedFormat` body:
/// recursive source-pattern FText + `i32` count + count × ([name
/// FString when named] + `FFormatArgumentValue`). Split from
/// `read_ftext` so the direct-context caller can catch the two
/// recoverable nested-decode faults and degrade to the `Unknown` skip.
fn read_format_history<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
    named: bool,
) -> crate::Result<FTextHistory> {
    let source_fmt = Box::new(read_nested_ftext(reader, ctx, asset_path, depth)?);
    let count = read_format_arg_count(reader, asset_path)?;
    if named {
        let mut arguments: Vec<FTextNamedArg> = Vec::new();
        try_reserve_asset(
            &mut arguments,
            count,
            asset_path,
            AssetSeam::CollectionElements,
        )?;
        for _ in 0..count {
            let name = read_asset_fstring(reader, asset_path)?;
            let value = read_format_arg(reader, ctx, asset_path, depth)?;
            arguments.push(FTextNamedArg { name, value });
        }
        Ok(FTextHistory::NamedFormat {
            source_fmt,
            arguments,
        })
    } else {
        let mut arguments: Vec<FTextFormatArg> = Vec::new();
        try_reserve_asset(
            &mut arguments,
            count,
            asset_path,
            AssetSeam::CollectionElements,
        )?;
        for _ in 0..count {
            arguments.push(read_format_arg(reader, ctx, asset_path, depth)?);
        }
        Ok(FTextHistory::OrderedFormat {
            source_fmt,
            arguments,
        })
    }
}

/// The two faults the direct-context format-history recovery may
/// absorb: an undecoded NESTED history type and an unsupported format
/// argument. Both mean "this specific FText can't be represented", not
/// truncation or crafted input — EOF / Io / count-cap / depth-cap
/// faults must NOT be absorbed (fail closed).
fn is_recoverable_nested_text_fault(e: &PaksmithError) -> bool {
    matches!(
        e,
        PaksmithError::AssetParse {
            fault: AssetParseFault::TextHistoryUnsupportedInElement { .. }
                | AssetParseFault::TextFormatArgUnsupported { .. },
            ..
        }
    )
}

/// Skip forward to `start_pos + tag_size` (the enclosing tag's end),
/// returning the number of bytes skipped. Shared by the undecoded-type
/// arm and the format-history recovery. `saturating_sub` bounds a
/// malformed `tag_size` below the bytes already consumed to a zero-skip
/// (the enclosing tag-size cursor check then fails loud).
fn skip_to_tag_end<R: Read + Seek>(
    reader: &mut R,
    start_pos: u64,
    tag_size: u64,
    asset_path: &str,
) -> crate::Result<usize> {
    let current_pos = reader.stream_position().map_err(PaksmithError::Io)?;
    let consumed = current_pos.saturating_sub(start_pos);
    let remaining_u64 = tag_size.saturating_sub(consumed);
    let remaining = usize::try_from(remaining_u64).map_err(|_| PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::U64ExceedsPlatformUsize {
            field: AssetWireField::FTextField,
            value: remaining_u64,
        },
    })?;
    crate::asset::skip_asset_bytes(
        reader,
        remaining as u64,
        asset_path,
        AssetWireField::FTextField,
    )?;
    Ok(remaining)
}

/// Read a NESTED `FText` (a format pattern or a `Text`-typed format
/// argument) at `depth + 1`. Nested contexts have no `tag_size` to skip
/// with, so an undecoded history type inside one CANNOT fall back to
/// the `Unknown` skip — the cursor would be left mid-body and every
/// subsequent read would silently desync. Fail closed with
/// [`AssetParseFault::TextHistoryUnsupportedInElement`] instead (the
/// same size-less-context contract as collection elements). #641.
fn read_nested_ftext<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<FText> {
    let text = read_ftext(reader, ctx, asset_path, 0, depth + 1)?;
    if let FTextHistory::Unknown { history_type, .. } = text.history {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type },
        });
    }
    Ok(text)
}

/// Read and validate the `i32` format-argument count for
/// `NamedFormat`/`OrderedFormat`. Negative or over-cap counts fail with
/// [`AssetParseFault::CollectionElementCountExceeded`] — CUE4Parse has
/// no cap here; each argument costs >= 5 wire bytes, so
/// `MAX_COLLECTION_ELEMENTS` comfortably covers legitimate content.
fn read_format_arg_count<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<usize> {
    let count_i32 = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof {
                field: AssetWireField::FTextField,
            },
        })?;
    usize::try_from(count_i32)
        .ok()
        .filter(|&n| n <= MAX_COLLECTION_ELEMENTS)
        .ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::CollectionElementCountExceeded {
                collection: CollectionKind::TextFormatArguments,
                count: count_i32,
                limit: MAX_COLLECTION_ELEMENTS,
            },
        })
}

/// Read one `FFormatArgumentValue`: an `i8` `EFormatArgumentType` byte
/// then the typed payload. In the NamedFormat/OrderedFormat context the
/// type byte is always present and `Int` is always i64 (the
/// `isArgumentData` gates in CUE4Parse apply only to the undecoded
/// `ArgumentFormat (3)` history). `Gender (5)` and unknown bytes fail
/// closed — no community reference implements a Gender payload. #641.
fn read_format_arg<R: Read + Seek>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    depth: usize,
) -> crate::Result<FTextFormatArg> {
    let eof = || PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof {
            field: AssetWireField::FTextField,
        },
    };
    let arg_type = reader.read_i8().map_err(|_| eof())?;
    Ok(match arg_type {
        0 => FTextFormatArg::Int(reader.read_i64::<LittleEndian>().map_err(|_| eof())?),
        1 => FTextFormatArg::UInt(reader.read_u64::<LittleEndian>().map_err(|_| eof())?),
        2 => FTextFormatArg::Float(reader.read_f32::<LittleEndian>().map_err(|_| eof())?),
        3 => FTextFormatArg::Double(reader.read_f64::<LittleEndian>().map_err(|_| eof())?),
        4 => FTextFormatArg::Text(Box::new(read_nested_ftext(reader, ctx, asset_path, depth)?)),
        other => {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::TextFormatArgUnsupported { arg_type: other },
            });
        }
    })
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
    fn history_none_reads_has_culture_field_at_editor_version_32() {
        // Regression for the off-by-one gate bug. The correct 0-based
        // ordinal of
        // `FEditorObjectVersion::CultureInvariantTextSerializationKeyStability`
        // is 32 (UE 4.23; verified against BOTH CUE4Parse@cf74fc32 and
        // unreal_asset@f4df5d8). At the boundary version 32 the
        // `bHasCultureInvariantString` field IS on the wire and must be
        // read (32 >= 32). Before the fix the const was 33, so
        // `32 >= 33` was false and the field was wrongly skipped.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1 (None)
        buf.extend_from_slice(&1u32.to_le_bytes()); // bHasCultureInvariantString = 1
        write_fstring(&mut buf, "Hello");
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sentinel

        let ctx = ctx_with_editor_object_version(32);
        let tag_size = buf.len() as u64;
        let mut cur = Cursor::new(&buf[..]);
        let text = read_ftext(&mut cur, &ctx, "x", tag_size, 0).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: Some("Hello".to_string())
            },
            "at FEditorObjectVersion == 32 the culture-invariant field must be read"
        );
        let sentinel = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(
            sentinel, 0xDEAD_BEEF,
            "decoder must consume exactly the has_culture u32 + FString at version 32"
        );
    }

    #[test]
    fn history_none_skips_has_culture_field_below_editor_version_32() {
        // Per `unreal_asset@f4df5d8` `str_property.rs:179-190`:
        //   `if version >= FEditorObjectVersion::CultureInvariantTextSerializationKeyStability`
        // gates the `bHasCultureInvariantString` u32 read. If the
        // editor-object-version stamp is < 32, the field is NOT on
        // the wire and the decoder must not consume those bytes.
        //
        // Wire bytes: u32 flags + i8 history_type + (NO has_culture);
        // a sentinel u8 at offset 5 detects whether the decoder
        // walked past the history_type byte unexpectedly.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.push(0x42u8); // sentinel (NOT a has_culture field)

        let ctx = ctx_with_editor_object_version(31);
        // `tag_size` is consulted only by the `Unknown` arm; for the
        // `-1` (None) branch the witness is the sentinel readback at
        // offset 5 after `read_ftext` returns.
        let tag_size = 5u64;
        let mut cur = Cursor::new(&buf[..]);
        let text = read_ftext(&mut cur, &ctx, "x", tag_size, 0).unwrap();
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
            "decoder must not consume bytes past history_type when FEditorObjectVersion < 32"
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
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::None {
                culture_invariant: None
            }
        );
    }

    #[test]
    fn history_none_reads_has_culture_field_above_editor_version_32() {
        // FEditorObjectVersion = 33 (one past the gate at 32): the
        // field IS still on the wire (33 >= 32). Round-trips through
        // the standard happy-path layout. Together with the v31-skips
        // and v32-reads tests this pins the boundary from both sides.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0xFFu8); // history_type = -1
        buf.extend_from_slice(&0u32.to_le_bytes()); // bHasCultureInvariantString = 0
        let ctx = ctx_with_editor_object_version(33);
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &ctx, "x", tag_size, 0).unwrap();
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
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
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
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
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
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
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
        let text = read_ftext(&mut cur, &empty_ctx(), "x", tag_size, 0).unwrap();
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
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
        assert_eq!(
            text.history,
            FTextHistory::Unknown {
                history_type: 3,
                skipped_bytes: 20
            }
        );
    }

    /// Push a `Base (0)` FText body (flags + type + 3 FStrings) — the
    /// building block for nested-pattern tests. #641.
    fn push_base_ftext(buf: &mut Vec<u8>, namespace: &str, key: &str, source: &str) {
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.push(0u8); // Base
        write_fstring(buf, namespace);
        write_fstring(buf, key);
        write_fstring(buf, source);
    }

    /// `StringTableEntry (11)`: TableId FName + Key FString. #641.
    #[test]
    fn history_string_table_entry_decodes() {
        let ctx = make_ctx(&["None", "/Game/Text/ST_UI"]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&7u32.to_le_bytes()); // flags (arbitrary)
        buf.push(11u8); // StringTableEntry
        buf.extend_from_slice(&1i32.to_le_bytes()); // FName index 1
        buf.extend_from_slice(&0i32.to_le_bytes()); // FName number
        write_fstring(&mut buf, "MSG_HELLO");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &ctx, "x", tag_size, 0).unwrap();
        assert_eq!(text.flags, 7);
        assert_eq!(
            text.history,
            FTextHistory::StringTableEntry {
                table_id: "/Game/Text/ST_UI".to_string(),
                key: "MSG_HELLO".to_string(),
            }
        );
    }

    /// `NamedFormat (1)`: nested pattern FText + i32 count + count ×
    /// (name FString + typed arg) — including a recursive `Text` arg. #641.
    #[test]
    fn history_named_format_decodes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(1u8); // NamedFormat
        push_base_ftext(&mut buf, "NS", "K", "{Count} items from {Src}");
        buf.extend_from_slice(&2i32.to_le_bytes()); // arg count
        write_fstring(&mut buf, "Count");
        buf.push(0u8); // Int
        buf.extend_from_slice(&42i64.to_le_bytes());
        write_fstring(&mut buf, "Src");
        buf.push(4u8); // Text
        push_base_ftext(&mut buf, "", "", "the source");
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
        let FTextHistory::NamedFormat {
            source_fmt,
            arguments,
        } = text.history
        else {
            panic!("expected NamedFormat, got {:?}", text.history);
        };
        assert!(matches!(
            source_fmt.history,
            FTextHistory::Base { ref source_string, .. } if source_string == "{Count} items from {Src}"
        ));
        assert_eq!(arguments.len(), 2);
        assert_eq!(arguments[0].name, "Count");
        assert_eq!(arguments[0].value, FTextFormatArg::Int(42));
        assert_eq!(arguments[1].name, "Src");
        let FTextFormatArg::Text(ref nested) = arguments[1].value else {
            panic!("expected Text arg, got {:?}", arguments[1].value);
        };
        assert!(matches!(
            nested.history,
            FTextHistory::Base { ref source_string, .. } if source_string == "the source"
        ));
    }

    /// `OrderedFormat (2)`: nested pattern + i32 count + typed args
    /// (no names). #641.
    #[test]
    fn history_ordered_format_decodes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2u8); // OrderedFormat
        push_base_ftext(&mut buf, "", "", "{0} of {1}");
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.push(3u8); // Double
        buf.extend_from_slice(&1.5f64.to_le_bytes());
        buf.push(1u8); // UInt
        buf.extend_from_slice(&7u64.to_le_bytes());
        let tag_size = buf.len() as u64;
        let text = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap();
        let FTextHistory::OrderedFormat {
            source_fmt,
            arguments,
        } = text.history
        else {
            panic!("expected OrderedFormat, got {:?}", text.history);
        };
        assert!(matches!(source_fmt.history, FTextHistory::Base { .. }));
        assert_eq!(
            arguments,
            vec![FTextFormatArg::Double(1.5), FTextFormatArg::UInt(7)]
        );
    }

    /// A `Gender (5)` argument in the DIRECT context (real `tag_size`)
    /// degrades to the skip-to-tag-end `Unknown` — the pre-#641 lossy
    /// behavior for the whole FText, preserving whole-export fidelity.
    /// The cursor must land exactly at tag end. #641.
    #[test]
    fn format_arg_gender_direct_context_degrades_to_unknown() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2u8); // OrderedFormat
        push_base_ftext(&mut buf, "", "", "{0}");
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(5u8); // Gender — unsupported
        buf.extend_from_slice(&[0xEEu8; 6]); // opaque remainder to skip
        let tag_size = buf.len() as u64;
        let mut cur = Cursor::new(&buf[..]);
        let text = read_ftext(&mut cur, &empty_ctx(), "x", tag_size, 0).unwrap();
        assert!(
            matches!(
                text.history,
                FTextHistory::Unknown {
                    history_type: 2,
                    ..
                }
            ),
            "expected Unknown(2) recovery, got {:?}",
            text.history
        );
        assert_eq!(cur.position(), tag_size, "cursor must land at tag end");
    }

    /// The same `Gender (5)` argument in a SIZE-LESS context
    /// (`tag_size == 0` — element / unversioned / nested) fails closed. #641.
    #[test]
    fn format_arg_gender_sizeless_context_fails_closed() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2u8); // OrderedFormat
        push_base_ftext(&mut buf, "", "", "{0}");
        buf.extend_from_slice(&1i32.to_le_bytes());
        buf.push(5u8); // Gender — unsupported
        let err = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", 0, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::TextFormatArgUnsupported { arg_type: 5 },
                    ..
                }
            ),
            "expected TextFormatArgUnsupported(5), got {err:?}"
        );
    }

    /// A negative format-argument count fails closed with
    /// `CollectionElementCountExceeded(TextFormatArguments)`. #641.
    #[test]
    fn format_arg_count_negative_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(2u8); // OrderedFormat
        push_base_ftext(&mut buf, "", "", "{0}");
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        let tag_size = buf.len() as u64;
        let err =
            read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", tag_size, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::CollectionElementCountExceeded {
                        collection: CollectionKind::TextFormatArguments,
                        ..
                    },
                    ..
                }
            ),
            "expected CollectionElementCountExceeded(TextFormatArguments), got {err:?}"
        );
    }

    /// A NamedFormat whose nested pattern has an undecoded history type
    /// in the DIRECT context degrades to the skip-to-tag-end `Unknown`
    /// (pre-#641 behavior for the whole FText). #641.
    #[test]
    fn nested_unknown_history_direct_context_degrades_to_unknown() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(1u8); // NamedFormat
        // Nested pattern with history_type 7 (AsDate — undecoded).
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(7u8);
        buf.extend_from_slice(&[0u8; 16]);
        let tag_size = buf.len() as u64;
        let mut cur = Cursor::new(&buf[..]);
        let text = read_ftext(&mut cur, &empty_ctx(), "x", tag_size, 0).unwrap();
        assert!(
            matches!(
                text.history,
                FTextHistory::Unknown {
                    history_type: 1,
                    ..
                }
            ),
            "expected Unknown(1) recovery, got {:?}",
            text.history
        );
        assert_eq!(cur.position(), tag_size, "cursor must land at tag end");
    }

    /// The same nested-undecoded pattern in a SIZE-LESS context fails
    /// closed — there is nothing to skip with. #641.
    #[test]
    fn nested_unknown_history_sizeless_context_fails_closed() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(1u8); // NamedFormat
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(7u8);
        buf.extend_from_slice(&[0u8; 16]);
        let err = read_ftext(&mut Cursor::new(&buf[..]), &empty_ctx(), "x", 0, 0).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::TextHistoryUnsupportedInElement { history_type: 7 },
                    ..
                }
            ),
            "expected TextHistoryUnsupportedInElement(7), got {err:?}"
        );
    }

    /// Depth boundary: exactly at `MAX_PROPERTY_DEPTH` a flat FText
    /// still decodes; one past it is rejected. Pins the entry guard's
    /// `>` against `>=` drift. #641.
    #[test]
    fn ftext_depth_boundary() {
        let mut buf = Vec::new();
        push_base_ftext(&mut buf, "", "", "s");
        let tag_size = buf.len() as u64;
        let ok = read_ftext(
            &mut Cursor::new(&buf[..]),
            &empty_ctx(),
            "x",
            tag_size,
            MAX_PROPERTY_DEPTH,
        );
        assert!(ok.is_ok(), "depth == cap must decode, got {ok:?}");
        let err = read_ftext(
            &mut Cursor::new(&buf[..]),
            &empty_ctx(),
            "x",
            tag_size,
            MAX_PROPERTY_DEPTH + 1,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::PropertyDepthExceeded { .. },
                ..
            }
        ));
    }

    /// The nested-FText read passes `depth + 1`: a NamedFormat read AT
    /// the cap trips the guard on its nested pattern read. Kills the
    /// `+ 1 -> * 1` mutant on `read_nested_ftext`'s increment. #641.
    #[test]
    fn nested_ftext_increments_depth() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(1u8); // NamedFormat
        push_base_ftext(&mut buf, "", "", "s"); // nested pattern
        buf.extend_from_slice(&0i32.to_le_bytes()); // 0 args
        let tag_size = buf.len() as u64;
        let err = read_ftext(
            &mut Cursor::new(&buf[..]),
            &empty_ctx(),
            "x",
            tag_size,
            MAX_PROPERTY_DEPTH,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::PropertyDepthExceeded { .. },
                    ..
                }
            ),
            "nested pattern at the cap must trip the depth guard, got {err:?}"
        );
    }
}
