//! `.locres` (`FTextLocalizationResource`) parser (#646).
//!
//! Wire recipe per CUE4Parse `FTextLocalizationResource.cs` /
//! `FTextKey.cs` / `FTextLocalizationResourceString.cs`; full layout
//! in `docs/formats/data/locres.md`.
//!
//! ```text
//! [magic FGuid 16B]        absent → LEGACY (v0), parse from offset 0
//! [u8 version]             0..=3; >3 rejected (mirrors the oracle)
//! [v1+] i64 StringsArrayOffset   -1 = none; else seek → i32 count +
//!                                count × { FString, [v2+] i32 RefCount }
//! [v2+] u32 EntriesCount   read-and-discarded
//! u32 NamespaceCount
//! per namespace: [v2+] u32 hash, FString
//!   u32 KeyCount
//!   per key: [v2+] u32 hash, FString
//!     u32 SourceStringHash          (ALL versions)
//!     [v1+] i32 StringIndex  |  [v0] inline FString
//! ```
//!
//! v3 (`Optimized_CityHash64_UTF16`) is wire-identical to v2 — only
//! the algorithm that PRODUCED the stored hashes differs, and the
//! oracle never computes or validates any locres hash, so paksmith
//! carries hashes opaquely and validates none of them.
//!
//! Deliberate divergences from CUE4Parse (documented in locres.md):
//! - A negative `StringIndex` fails closed
//!   ([`LocresParseFault::StringIndexOutOfRange`]) — the oracle's
//!   bounds check is upper-only and it CRASHES on negative input.
//! - Over-range indices also fail closed where the oracle warns and
//!   leaves the entry untranslated.
//! - The strings-array offset is bounds-checked in two stages: stage-1
//!   (`25 <= offset < file_len`) before seeking, stage-2 (offset must
//!   not overlap the namespace table) after parsing it. CUE4Parse
//!   seeks blindly.

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{
    LocresAllocationContext, LocresParseFault, LocresStringFault, LocresWireField, PaksmithError,
};

/// The 16-byte magic GUID opening every non-legacy `.locres` file:
/// `FGuid {0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3}`,
/// little-endian per component.
pub const LOCRES_MAGIC: [u8; 16] = [
    0x0E, 0x14, 0x74, 0x75, 0x67, 0x4A, 0x03, 0xFC, 0x4A, 0x15, 0x90, 0x9D, 0xC3, 0x37, 0x7F, 0x1B,
];

/// Cap on the strings-array / namespace / key counts. Real game
/// `.locres` files hold thousands of entries; `2^20` bounds an
/// adversarial count before any proportional allocation (see
/// `docs/formats/data/locres.md` §Caps & limits).
pub const MAX_LOCRES_COUNT: usize = 1_048_576;

/// Minimum valid `StringsArrayOffset`: the byte just past the
/// `magic(16) + version(1) + offset(8)` header prefix. An offset below
/// this points back into the header itself (stage-1 of the two-stage
/// bounds check in `docs/formats/data/locres.md`).
const MIN_STRINGS_OFFSET: usize = 25;

/// `ELocResVersion` — the version byte after the magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocresVersion {
    /// v0: no magic/header, inline strings, no hashes.
    Legacy,
    /// v1: magic + strings array; no hashes, no `EntriesCount`.
    Compact,
    /// v2: v1 + `EntriesCount` + CRC32 pre-hashes + `RefCount`.
    OptimizedCrc32,
    /// v3: wire-identical to v2; hashes are CityHash64/UTF-16.
    OptimizedCityHash64Utf16,
}

impl LocresVersion {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Legacy),
            1 => Some(Self::Compact),
            2 => Some(Self::OptimizedCrc32),
            3 => Some(Self::OptimizedCityHash64Utf16),
            _ => None,
        }
    }

    /// True for versions carrying the dedup strings array (v1+).
    fn has_strings_array(self) -> bool {
        !matches!(self, Self::Legacy)
    }

    /// True for versions carrying pre-hashes + `EntriesCount` +
    /// `RefCount` (v2+).
    fn is_optimized(self) -> bool {
        matches!(self, Self::OptimizedCrc32 | Self::OptimizedCityHash64Utf16)
    }
}

/// One `(key, translation)` entry within a namespace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LocresEntry {
    /// The localization key.
    pub key: String,
    /// The key's pre-hash (v2+; `0` below). Carried opaquely — the
    /// oracle never validates locres hashes and neither does paksmith.
    pub key_hash: u32,
    /// The source-string hash (all versions). Opaque.
    pub source_string_hash: u32,
    /// The localized string.
    pub localized: String,
}

/// One namespace and its entries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LocresNamespace {
    /// The namespace string (often empty for the game namespace).
    pub namespace: String,
    /// The namespace's pre-hash (v2+; `0` below). Opaque.
    pub namespace_hash: u32,
    /// The namespace's entries, in wire order.
    pub entries: Vec<LocresEntry>,
}

/// A parsed `.locres` file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LocresResource {
    /// The wire version.
    pub version: LocresVersion,
    /// Namespaces in wire order.
    pub namespaces: Vec<LocresNamespace>,
}

impl LocresResource {
    /// Total entry count across all namespaces.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.namespaces.iter().map(|n| n.entries.len()).sum()
    }

    /// Parse a `.locres` file from `bytes`.
    ///
    /// # Errors
    /// [`PaksmithError::LocresParse`] with a [`LocresParseFault`]
    /// naming the offending wire field; see the module doc for the
    /// deliberate fail-closed divergences from CUE4Parse.
    pub fn parse(bytes: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor { bytes, pos: 0 };

        // Magic-or-legacy discrimination (oracle: seek back to 0 and
        // assume legacy when the magic is absent).
        let version = if bytes.len() >= 17 && bytes[..16] == LOCRES_MAGIC {
            let b = bytes[16];
            // Fail-closed divergence from CUE4Parse: a version byte of
            // 0 AFTER a magic match is a contradictory state (Legacy
            // files have no magic prefix). The oracle parses it as a
            // legacy body from offset 17 — almost certainly garbage —
            // whereas paksmith rejects it. Byte > 3 is also rejected
            // (as the oracle does).
            // A version byte of 0 after the magic is the contradictory
            // case (see below) — `from_byte(0)` would yield Legacy, so
            // it is filtered out explicitly here.
            let non_legacy = LocresVersion::from_byte(b).filter(|v| *v != LocresVersion::Legacy);
            let Some(v) = non_legacy else {
                return Err(fault(LocresParseFault::UnsupportedVersion { found: b }));
            };
            cur.pos = 17;
            v
        } else {
            LocresVersion::Legacy
        };

        // v1+: the dedup strings array, read at its offset. `strings_at`
        // is the validated absolute offset (None when the array is
        // absent), kept for the stage-2 overlap check below.
        let (strings, strings_at): (Vec<String>, Option<usize>) = if version.has_strings_array() {
            read_strings_at_offset(&mut cur, bytes, version)?
        } else {
            (Vec::new(), None)
        };

        // v2+: EntriesCount, read-and-discarded (the oracle skips it).
        if version.is_optimized() {
            let _ = cur.read_u32(LocresWireField::EntriesCount)?;
        }

        let namespace_count = checked_count(
            cur.read_u32(LocresWireField::NamespaceCount)?,
            LocresWireField::NamespaceCount,
        )?;
        let mut namespaces: Vec<LocresNamespace> = Vec::new();
        try_reserve(
            &mut namespaces,
            namespace_count,
            LocresAllocationContext::Namespaces,
        )?;

        for _ in 0..namespace_count {
            let namespace_hash = if version.is_optimized() {
                cur.read_u32(LocresWireField::Namespace)?
            } else {
                0
            };
            let namespace = cur.read_fstring(LocresWireField::Namespace)?;

            let key_count = checked_count(
                cur.read_u32(LocresWireField::KeyCount)?,
                LocresWireField::KeyCount,
            )?;
            let mut entries: Vec<LocresEntry> = Vec::new();
            try_reserve(&mut entries, key_count, LocresAllocationContext::KeyEntries)?;

            for _ in 0..key_count {
                let key_hash = if version.is_optimized() {
                    cur.read_u32(LocresWireField::Key)?
                } else {
                    0
                };
                let key = cur.read_fstring(LocresWireField::Key)?;
                let source_string_hash = cur.read_u32(LocresWireField::SourceStringHash)?;

                let localized = if version.has_strings_array() {
                    let index = cur.read_i32(LocresWireField::LocalizedString)?;
                    // Fail closed on BOTH sides: the oracle's check is
                    // upper-bound-only and crashes on negative input.
                    let localized = usize::try_from(index)
                        .ok()
                        .and_then(|i| strings.get(i))
                        .ok_or_else(|| {
                            fault(LocresParseFault::StringIndexOutOfRange {
                                index,
                                count: strings.len(),
                            })
                        })?;
                    localized.clone()
                } else {
                    cur.read_fstring(LocresWireField::LocalizedString)?
                };

                entries.push(LocresEntry {
                    key,
                    key_hash,
                    source_string_hash,
                    localized,
                });
            }

            namespaces.push(LocresNamespace {
                namespace,
                namespace_hash,
                entries,
            });
        }

        // Stage-2 of the strings-offset bounds check
        // (docs/formats/data/locres.md): the strings array must sit
        // AFTER the namespace table it belongs to, never overlapping
        // the header/EntriesCount/namespace bytes. The main cursor now
        // sits at the end of the namespace table, so a well-formed
        // offset is >= that position. A smaller offset means the
        // strings were (already, harmlessly — every read is bounded and
        // capped) parsed out of namespace-table bytes; reject the whole
        // resource rather than return a double-interpreted result.
        if let Some(off) = strings_at.filter(|&o| o < cur.pos) {
            return Err(fault(LocresParseFault::StringsOffsetOutOfBounds {
                offset: i64::try_from(off).unwrap_or(i64::MAX),
                file_len: bytes.len() as u64,
            }));
        }

        Ok(Self {
            version,
            namespaces,
        })
    }
}

/// Read the v1+ strings-array offset from `cur`, bounds-check it, and
/// parse the array at that position (`-1` = `INDEX_NONE` = no array).
/// CUE4Parse seeks blindly; paksmith rejects offsets outside the file.
fn read_strings_at_offset(
    cur: &mut Cursor<'_>,
    bytes: &[u8],
    version: LocresVersion,
) -> crate::Result<(Vec<String>, Option<usize>)> {
    let offset = cur.read_i64(LocresWireField::StringsArrayOffset)?;
    if offset == -1 {
        return Ok((Vec::new(), None));
    }
    // Stage-1: non-negative, past the header prefix, inside the file.
    let in_bounds = usize::try_from(offset)
        .ok()
        .filter(|&o| o >= MIN_STRINGS_OFFSET && o < bytes.len());
    let Some(offset_usize) = in_bounds else {
        return Err(fault(LocresParseFault::StringsOffsetOutOfBounds {
            offset,
            file_len: bytes.len() as u64,
        }));
    };
    let mut sc = Cursor {
        bytes,
        pos: offset_usize,
    };
    let strings = read_strings_array(&mut sc, version)?;
    Ok((strings, Some(offset_usize)))
}

/// The strings array at its offset: `i32 count` + `count ×`
/// `{ FString, [v2+] i32 RefCount }`. `RefCount` is read and
/// discarded (mutation bookkeeping for UE's "string stealing").
fn read_strings_array(cur: &mut Cursor<'_>, version: LocresVersion) -> crate::Result<Vec<String>> {
    let raw = cur.read_i32(LocresWireField::StringsArrayCount)?;
    if raw < 0 {
        return Err(fault(LocresParseFault::NegativeValue {
            field: LocresWireField::StringsArrayCount,
            value: i64::from(raw),
        }));
    }
    #[allow(clippy::cast_sign_loss, reason = "sign-checked above")]
    let count = checked_count(raw as u32, LocresWireField::StringsArrayCount)?;
    let mut strings: Vec<String> = Vec::new();
    try_reserve(&mut strings, count, LocresAllocationContext::StringsArray)?;
    for _ in 0..count {
        let s = cur.read_fstring(LocresWireField::StringsArrayEntry)?;
        if version.is_optimized() {
            let _ref_count = cur.read_i32(LocresWireField::StringsArrayEntry)?;
        }
        strings.push(s);
    }
    Ok(strings)
}

/// u32 count → usize with the [`MAX_LOCRES_COUNT`] cap applied BEFORE
/// any proportional allocation.
fn checked_count(raw: u32, field: LocresWireField) -> crate::Result<usize> {
    let count = raw as usize;
    if count > MAX_LOCRES_COUNT {
        return Err(fault(LocresParseFault::CountExceeded {
            field,
            value: count as u64,
            limit: MAX_LOCRES_COUNT as u64,
        }));
    }
    Ok(count)
}

/// Fallible reservation surfacing allocator refusal as a structured
/// fault (the count is already capped, so the reservation is bounded).
fn try_reserve<T>(
    vec: &mut Vec<T>,
    count: usize,
    context: LocresAllocationContext,
) -> crate::Result<()> {
    vec.try_reserve_exact(count)
        .map_err(|_| fault(LocresParseFault::AllocationFailed { context }))
}

fn fault(f: LocresParseFault) -> PaksmithError {
    PaksmithError::LocresParse { fault: f }
}

/// Bounds-checked little-endian reader over the whole file slice.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize, field: LocresWireField) -> crate::Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| fault(LocresParseFault::UnexpectedEof { field }))?;
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn read_u32(&mut self, field: LocresWireField) -> crate::Result<u32> {
        Ok(LittleEndian::read_u32(self.take(4, field)?))
    }

    fn read_i32(&mut self, field: LocresWireField) -> crate::Result<i32> {
        Ok(LittleEndian::read_i32(self.take(4, field)?))
    }

    fn read_i64(&mut self, field: LocresWireField) -> crate::Result<i64> {
        Ok(LittleEndian::read_i64(self.take(8, field)?))
    }

    /// UE `FString`: `i32 len` — positive = `len` ANSI bytes,
    /// negative = `-len × 2` UTF-16-LE bytes, `0` = empty; both
    /// non-empty forms include and require a null terminator.
    fn read_fstring(&mut self, field: LocresWireField) -> crate::Result<String> {
        let len = self.read_i32(field)?;
        let string_fault = |detail| fault(LocresParseFault::MalformedString { field, detail });
        if len == 0 {
            return Ok(String::new());
        }
        if len == i32::MIN {
            return Err(string_fault(LocresStringFault::LengthOverflow));
        }
        if len < 0 {
            let chars = len.unsigned_abs() as usize;
            let byte_len = chars
                .checked_mul(2)
                .ok_or_else(|| string_fault(LocresStringFault::LengthExceedsFile))?;
            if byte_len > self.bytes.len() - self.pos {
                return Err(string_fault(LocresStringFault::LengthExceedsFile));
            }
            let raw = self.take(byte_len, field)?;
            let units: Vec<u16> = raw.chunks_exact(2).map(LittleEndian::read_u16).collect();
            if units.last() != Some(&0) {
                return Err(string_fault(LocresStringFault::MissingNullTerminator));
            }
            Ok(String::from_utf16_lossy(&units[..units.len() - 1]))
        } else {
            #[allow(clippy::cast_sign_loss, reason = "the negative arm returned above")]
            let byte_len = len as usize;
            if byte_len > self.bytes.len() - self.pos {
                return Err(string_fault(LocresStringFault::LengthExceedsFile));
            }
            let raw = self.take(byte_len, field)?;
            if raw.last() != Some(&0) {
                return Err(string_fault(LocresStringFault::MissingNullTerminator));
            }
            Ok(raw[..raw.len() - 1]
                .iter()
                .map(|&b| char::from(b))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Committed fixture: the doc's worked example (v2, one "Game"
    /// namespace, key1→Hello / key2→World).
    const SAMPLE_V2: &[u8] = include_bytes!("../../../../tests/fixtures/data/sample_v2.locres");

    fn push_ansi_fstring(b: &mut Vec<u8>, s: &str) {
        b.extend_from_slice(&i32::try_from(s.len() + 1).unwrap().to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.push(0);
    }

    /// Build a legacy (v0) file: no header, inline strings.
    fn build_v0() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // namespace count
        push_ansi_fstring(&mut b, "Game");
        b.extend_from_slice(&1u32.to_le_bytes()); // key count
        push_ansi_fstring(&mut b, "greeting");
        b.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes()); // SourceStringHash
        push_ansi_fstring(&mut b, "Hallo");
        b
    }

    /// Build a v1 (Compact) file: magic + version + strings array at a
    /// trailing offset, no hashes, no EntriesCount.
    fn build_v1() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&LOCRES_MAGIC);
        b.push(1);
        let offset_pos = b.len();
        b.extend_from_slice(&0i64.to_le_bytes()); // patched below
        b.extend_from_slice(&1u32.to_le_bytes()); // namespace count
        push_ansi_fstring(&mut b, "Game");
        b.extend_from_slice(&1u32.to_le_bytes()); // key count
        push_ansi_fstring(&mut b, "greeting");
        b.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // SourceStringHash
        b.extend_from_slice(&0i32.to_le_bytes()); // string index
        let strings_at = b.len();
        b.extend_from_slice(&1i32.to_le_bytes()); // strings count
        push_ansi_fstring(&mut b, "Bonjour"); // NO RefCount at v1
        let off = i64::try_from(strings_at).unwrap();
        b[offset_pos..offset_pos + 8].copy_from_slice(&off.to_le_bytes());
        b
    }

    #[test]
    fn parses_the_committed_v2_fixture() {
        let r = LocresResource::parse(SAMPLE_V2).expect("fixture must parse");
        assert_eq!(r.version, LocresVersion::OptimizedCrc32);
        assert_eq!(r.namespaces.len(), 1);
        let ns = &r.namespaces[0];
        assert_eq!(ns.namespace, "Game");
        assert_eq!(ns.namespace_hash, 0x5414_785E);
        assert_eq!(ns.entries.len(), 2);
        assert_eq!(ns.entries[0].key, "key1");
        assert_eq!(ns.entries[0].key_hash, 0x60F0_15C9);
        assert_eq!(ns.entries[0].localized, "Hello");
        assert_eq!(ns.entries[1].key, "key2");
        assert_eq!(ns.entries[1].localized, "World");
        assert_eq!(r.entry_count(), 2);
    }

    #[test]
    fn parses_legacy_v0_inline_strings() {
        let r = LocresResource::parse(&build_v0()).expect("v0 must parse");
        assert_eq!(r.version, LocresVersion::Legacy);
        assert_eq!(r.namespaces[0].entries[0].key, "greeting");
        assert_eq!(r.namespaces[0].entries[0].localized, "Hallo");
        assert_eq!(r.namespaces[0].entries[0].source_string_hash, 0xAABB_CCDD);
        assert_eq!(r.namespaces[0].namespace_hash, 0, "no hashes below v2");
    }

    #[test]
    fn parses_v1_compact_without_hashes_or_entries_count() {
        let r = LocresResource::parse(&build_v1()).expect("v1 must parse");
        assert_eq!(r.version, LocresVersion::Compact);
        assert_eq!(r.namespaces[0].entries[0].localized, "Bonjour");
        assert_eq!(r.namespaces[0].entries[0].key_hash, 0);
    }

    /// v3 is wire-identical to v2 — the fixture re-labelled parses the
    /// same, only the version differs.
    #[test]
    fn v3_is_wire_identical_to_v2() {
        let mut bytes = SAMPLE_V2.to_vec();
        bytes[16] = 3;
        let r = LocresResource::parse(&bytes).expect("v3 must parse");
        assert_eq!(r.version, LocresVersion::OptimizedCityHash64Utf16);
        assert_eq!(r.namespaces[0].entries[0].localized, "Hello");
    }

    /// Version bytes above 3 fail closed with the value echoed.
    #[test]
    fn version_above_latest_rejected() {
        for v in [4u8, 200] {
            let mut bytes = SAMPLE_V2.to_vec();
            bytes[16] = v;
            let err = LocresResource::parse(&bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    PaksmithError::LocresParse {
                        fault: LocresParseFault::UnsupportedVersion { found },
                    } if found == v
                ),
                "version {v} must be rejected"
            );
        }
    }

    /// Fail-closed divergence (D4): magic + version byte 0 is a
    /// contradictory state (legacy files have no magic) — paksmith
    /// rejects it where the oracle would parse a garbage legacy body
    /// from offset 17.
    #[test]
    fn magic_with_version_zero_rejected() {
        let mut b = Vec::new();
        b.extend_from_slice(&LOCRES_MAGIC);
        b.push(0);
        b.extend_from_slice(&build_v0());
        let err = LocresResource::parse(&b).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::LocresParse {
                fault: LocresParseFault::UnsupportedVersion { found: 0 },
            }
        ));
    }

    /// A genuine legacy (v0) file has NO magic — the first 16 bytes are
    /// its namespace count etc., not the GUID — so it parses fine.
    #[test]
    fn genuine_legacy_without_magic_parses() {
        let r = LocresResource::parse(&build_v0()).expect("no-magic legacy parses");
        assert_eq!(r.version, LocresVersion::Legacy);
    }

    /// Fail-closed divergence (D1): negative string indices are a
    /// structured fault (the oracle CRASHES); over-range too (the
    /// oracle warns and leaves the entry untranslated).
    #[test]
    fn string_index_out_of_range_fails_closed() {
        for (patch, label) in [((-1i32), "negative"), (2, "over-range"), (i32::MIN, "min")] {
            let mut bytes = SAMPLE_V2.to_vec();
            // key1's StringIndex per the doc's worked example layout:
            // header(17) + offset(8) + EntriesCount(4) + nsCount(4) +
            // nsHash(4) + "Game"(4+5) + keyCount(4) + key1Hash(4) +
            // "key1"(4+5) + srcHash(4) = byte 67.
            bytes[67..71].copy_from_slice(&patch.to_le_bytes());
            let err = LocresResource::parse(&bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    PaksmithError::LocresParse {
                        fault: LocresParseFault::StringIndexOutOfRange { index, count: 2 },
                    } if index == patch
                ),
                "{label} index must fail closed, got {err:?}"
            );
        }
    }

    /// The strings-array offset is bounds-checked before seeking:
    /// negative (non−1), past-EOF, and i64::MAX all fail closed.
    #[test]
    fn strings_offset_out_of_bounds_rejected() {
        for bad in [
            -2i64,
            i64::try_from(SAMPLE_V2.len()).unwrap(),
            i64::MAX,
            i64::MIN,
        ] {
            let mut bytes = SAMPLE_V2.to_vec();
            bytes[17..25].copy_from_slice(&bad.to_le_bytes());
            let err = LocresResource::parse(&bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    PaksmithError::LocresParse {
                        fault: LocresParseFault::StringsOffsetOutOfBounds { offset, .. },
                    } if offset == bad
                ),
                "offset {bad} must fail closed, got {err:?}"
            );
        }
    }

    /// Two-stage offset check with a boundary-accept case that pins
    /// stage-1's `>=` (a `>` mutant would reject the exact minimum). A
    /// v1 helper file: `magic(16) + version(1) + offset(8)` then a
    /// caller-chosen `[u8]` tail. #646.
    #[test]
    fn strings_offset_two_stage_bounds() {
        fn v1_with(offset: i64, tail: &[u8]) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&LOCRES_MAGIC);
            b.push(1); // v1
            b.extend_from_slice(&offset.to_le_bytes());
            b.extend_from_slice(tail);
            b
        }

        // Stage-1 reject: offset 10 points into the header (< 25).
        let err = LocresResource::parse(&v1_with(10, &[0u8; 4])).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::LocresParse {
                    fault: LocresParseFault::StringsOffsetOutOfBounds { offset: 10, .. },
                }
            ),
            "stage-1 (offset < 25) must reject, got {err:?}"
        );

        // Stage-1 boundary ACCEPT: offset 25 (== MIN) passes stage-1,
        // so the strings read runs and hits the -1 count there — a
        // DISTINCT fault (NegativeValue), proving 25 was accepted. A
        // `>=`→`>` mutant would instead reject 25 as
        // StringsOffsetOutOfBounds, so the two are distinguishable.
        let err = LocresResource::parse(&v1_with(25, &(-1i32).to_le_bytes())).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::LocresParse {
                    fault: LocresParseFault::NegativeValue {
                        field: LocresWireField::StringsArrayCount,
                        value: -1,
                    },
                }
            ),
            "offset == 25 must be ACCEPTED by stage-1 (then fault on the -1 count), got {err:?}"
        );

        // Stage-2 reject: offset 26 (> 25, unambiguously past stage-1)
        // reads a valid empty array at byte 26 (count 0), but overlaps
        // the namespace table — the main cursor reaches 30 after the
        // (also-zero) namespace count, so 26 < 30 → reject after the
        // loop. Tail `[00 × 5]`: bytes 25..29 = namespace count 0,
        // bytes 26..30 = strings count 0.
        let err = LocresResource::parse(&v1_with(26, &[0u8; 5])).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::LocresParse {
                    fault: LocresParseFault::StringsOffsetOutOfBounds { offset: 26, .. },
                }
            ),
            "stage-2 (offset 26 overlaps namespace table) must reject, got {err:?}"
        );
    }

    /// Offset −1 (INDEX_NONE) means "no strings array" — entries then
    /// fail on their (now-dangling) indices rather than at the offset.
    #[test]
    fn strings_offset_index_none_yields_empty_array() {
        let mut bytes = SAMPLE_V2.to_vec();
        bytes[17..25].copy_from_slice(&(-1i64).to_le_bytes());
        let err = LocresResource::parse(&bytes).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::LocresParse {
                fault: LocresParseFault::StringIndexOutOfRange { count: 0, .. },
            }
        ));
    }

    /// Counts above the cap fail before any proportional allocation.
    #[test]
    fn counts_above_cap_rejected() {
        // Namespace count lives at offset 29 (after magic+ver+offset+
        // EntriesCount) in the v2 fixture.
        let mut bytes = SAMPLE_V2.to_vec();
        let too_many = u32::try_from(MAX_LOCRES_COUNT + 1).unwrap();
        bytes[29..33].copy_from_slice(&too_many.to_le_bytes());
        let err = LocresResource::parse(&bytes).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::LocresParse {
                fault: LocresParseFault::CountExceeded {
                    field: LocresWireField::NamespaceCount,
                    ..
                },
            }
        ));
    }

    /// Truncations at every stage surface as structured EOF faults,
    /// never panics.
    #[test]
    fn truncations_fail_closed() {
        for cut in [0, 5, 16, 17, 20, 24, 30, 40, 60, 90, SAMPLE_V2.len() - 1] {
            let r = LocresResource::parse(&SAMPLE_V2[..cut]);
            assert!(r.is_err(), "truncation at {cut} must error");
        }
    }

    /// UTF-16 strings (negative FString length) round-trip; a missing
    /// null terminator faults.
    #[test]
    fn utf16_fstring_decoded() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // v0: namespace count
        // namespace = "Ü" as UTF-16: len = -(1 char + 1 term) = -2
        b.extend_from_slice(&(-2i32).to_le_bytes());
        b.extend_from_slice(&0x00DCu16.to_le_bytes()); // 'Ü'
        b.extend_from_slice(&0u16.to_le_bytes()); // terminator
        b.extend_from_slice(&0u32.to_le_bytes()); // key count 0
        let r = LocresResource::parse(&b).expect("utf16 namespace");
        assert_eq!(r.namespaces[0].namespace, "Ü");

        // Missing terminator: last UTF-16 unit non-zero.
        let mut b2 = Vec::new();
        b2.extend_from_slice(&1u32.to_le_bytes());
        b2.extend_from_slice(&(-2i32).to_le_bytes());
        b2.extend_from_slice(&0x00DCu16.to_le_bytes());
        b2.extend_from_slice(&0x00DCu16.to_le_bytes());
        b2.extend_from_slice(&0u32.to_le_bytes());
        let err = LocresResource::parse(&b2).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::LocresParse {
                fault: LocresParseFault::MalformedString {
                    detail: LocresStringFault::MissingNullTerminator,
                    ..
                },
            }
        ));
    }

    /// A 15-byte file (shorter than the magic) parses as legacy and
    /// faults on its first count read — never indexes past the end.
    #[test]
    fn short_file_is_legacy_then_eof() {
        let err = LocresResource::parse(&[0u8; 3]).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::LocresParse {
                fault: LocresParseFault::UnexpectedEof {
                    field: LocresWireField::NamespaceCount,
                },
            }
        ));
    }
}
