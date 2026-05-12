//! Pak format version definitions.

use crate::error::PaksmithError;

/// On-disk size of the v7+ footer in bytes.
///
/// encryption_guid(16) + encrypted_flag(1) + magic(4) + version(4)
///   + index_offset(8) + index_size(8) + index_hash(20) = 61
pub(super) const FOOTER_SIZE_V7_PLUS: u64 = 61;

/// On-disk size of the legacy (pre-v7) footer in bytes.
///
/// magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20) = 44
///
/// `pub` (not `pub(super)`) because the integration test
/// `tests/pak_integration.rs` reads it to locate the footer in
/// hand-rolled fixture bytes.
pub const FOOTER_SIZE_LEGACY: u64 = 44;

/// V8A footer size: v7 layout + 4 × 32-byte compression-method FName slots.
/// Used by the brief UE 4.22 V8A variant — `Version::V8A` in trumank/repak.
/// Distinguishable from V8B (221 bytes) only by total footer size.
pub(super) const FOOTER_SIZE_V8A: u64 = FOOTER_SIZE_V7_PLUS + 4 * 32;

/// Compile-time assertion that the V8A footer size constant is the sum
/// of the v7 base size and 4 × the compression-slot width. Linking these
/// at the type level prevents a future engineer changing one without
/// the other and silently flipping V8A↔V8B detection: the footer parser
/// reads `FOOTER_SIZE_V8A` bytes, counts the compression-method slots,
/// and post-corrects the wire-version-8 default (V8B) to V8A when the
/// slot count equals `COMPRESSION_SLOTS_V8A`. The entry parser then
/// dispatches on the resolved variant directly.
const _: () = assert!(
    FOOTER_SIZE_V8A
        == FOOTER_SIZE_V7_PLUS + (COMPRESSION_SLOTS_V8A as u64) * (COMPRESSION_SLOT_BYTES as u64),
    "V8A footer size must equal v7 base + 4 compression slots — keep in sync with COMPRESSION_SLOTS_V8A and COMPRESSION_SLOT_BYTES"
);
const _: () = assert!(
    FOOTER_SIZE_V8B_PLUS
        == FOOTER_SIZE_V7_PLUS
            + (COMPRESSION_SLOTS_V8B_PLUS as u64) * (COMPRESSION_SLOT_BYTES as u64),
    "V8B+ footer size must equal v7 base + 5 compression slots — keep in sync with COMPRESSION_SLOTS_V8B_PLUS and COMPRESSION_SLOT_BYTES"
);
const _: () = assert!(
    FOOTER_SIZE_V9 == FOOTER_SIZE_V8B_PLUS + 1,
    "V9 footer size must equal V8B+ base + 1 frozen-index byte"
);

/// V8B / V10 / V11 footer size: v7 layout + 5 × 32-byte compression-method
/// FName slots. UE 4.23-4.24 (V8B), 4.26 (V10), 4.27+ (V11) all share this
/// layout; the version field (8 vs 10 vs 11) disambiguates which the file is.
///
/// `pub` (not `pub(super)`) because the integration test
/// `tests/pak_integration.rs` reads it to locate the index_hash
/// field in v10/v11 fixtures for byte-patching tests.
pub const FOOTER_SIZE_V8B_PLUS: u64 = FOOTER_SIZE_V7_PLUS + 5 * 32;

/// V9 footer size: V8B layout + 1-byte frozen-index flag.
pub(super) const FOOTER_SIZE_V9: u64 = FOOTER_SIZE_V8B_PLUS + 1;

/// Number of compression-method FName slots in the V8B/V9/V10/V11 footer.
pub(super) const COMPRESSION_SLOTS_V8B_PLUS: usize = 5;

/// Number of compression-method FName slots in the V8A footer.
pub(super) const COMPRESSION_SLOTS_V8A: usize = 4;

/// Width of one compression-method FName slot: a fixed 32-byte block holding
/// a null- or whitespace-terminated UTF-8 string (`"Zlib"`, `"Oodle"`, etc.).
pub(super) const COMPRESSION_SLOT_BYTES: usize = 32;

/// Pak file format version.
///
/// Variants are ordered chronologically — `<` and `>` reflect engine
/// evolution. Internal callers should use the capability-predicate
/// method `has_path_hash_index` (crate-private) rather than comparing
/// raw discriminants where possible.
///
/// **V8A vs V8B distinction.** UE 4.22 (V8A) and UE 4.23-4.24 (V8B)
/// both record `version = 8` on the wire. They differ in the footer's
/// FName-table slot count (V8A=4, V8B=5) and the per-entry compression
/// byte width (V8A=u8, V8B=u32). [`TryFrom<u32>`] for `8` returns
/// `V8B` by default; the footer parser post-corrects to `V8A` after
/// counting slots in the FName table. This means a `PakVersion`
/// returned from a TryFrom call alone cannot distinguish the two —
/// always go through the footer parser for authoritative classification.
///
/// **Invariant:** variants MUST remain in chronological order. The derived
/// `Ord`/`PartialOrd` impl is load-bearing — the crate-private
/// `has_path_hash_index` predicate depends on it. `V8A` precedes `V8B`
/// in the chronological ordering since UE 4.22 predates UE 4.23.
/// Append new variants to the end; never reorder or insert.
///
/// **No `#[repr(u32)]`.** The wire-version-to-variant mapping is no
/// longer 1:1 (V8A and V8B both serialize to wire-version 8), so a
/// `repr(u32)` discriminant is misleading. Use [`Self::wire_version`]
/// for the wire-format value.
///
/// Marked `#[non_exhaustive]` so downstream `match` statements survive the
/// addition of future engine versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PakVersion {
    /// Initial pak format. UE 4.0. Wire version 1.
    Initial,
    /// Removed per-entry timestamps. UE 4.3. Wire version 2.
    NoTimestamps,
    /// Added compression and AES encryption support. UE 4.4. Wire version 3.
    CompressionEncryption,
    /// Added index encryption. UE 4.16. Wire version 4.
    IndexEncryption,
    /// Switched compression block offsets to be relative to the entry.
    /// UE 4.20. Wire version 5.
    RelativeChunkOffsets,
    /// Added delete records (used during patching). UE 4.21. Wire version 6.
    DeleteRecords,
    /// Added per-archive encryption key GUID to the footer. UE 4.22.
    /// Wire version 7.
    EncryptionKeyGuid,
    /// UE 4.22 V8A: FName compression table with **4** slots; per-entry
    /// compression byte is **u8**. Wire version 8 (shared with V8B).
    /// Disambiguated by footer-table slot count.
    V8A,
    /// UE 4.23-4.24 V8B: FName compression table with **5** slots;
    /// per-entry compression byte is **u32** (returned to v7 width).
    /// Wire version 8 (shared with V8A). Disambiguated by footer-table
    /// slot count.
    V8B,
    /// Added optional frozen index format. UE 4.25. Wire version 9.
    FrozenIndex,
    /// Replaced the flat index with a path-hash + encoded directory
    /// index. UE 4.26. Wire version 10.
    PathHashIndex,
    /// Fixed an FNV-64 hashing bug in the path-hash index. UE 4.27.
    /// Wire version 11.
    Fnv64BugFix,
}

impl PakVersion {
    /// Whether this version uses the path-hash + encoded-directory
    /// index layout (v10+). Used by `PakIndex::read_from` to dispatch
    /// between the flat (v3-v9) and path-hash (v10+) parsers.
    pub(crate) fn has_path_hash_index(self) -> bool {
        self >= Self::PathHashIndex
    }

    /// The wire-format version number this variant serializes to.
    /// V8A and V8B both return `8` (they share the on-disk version
    /// field; the slot count in the footer disambiguates).
    #[must_use]
    pub fn wire_version(self) -> u32 {
        match self {
            Self::Initial => 1,
            Self::NoTimestamps => 2,
            Self::CompressionEncryption => 3,
            Self::IndexEncryption => 4,
            Self::RelativeChunkOffsets => 5,
            Self::DeleteRecords => 6,
            Self::EncryptionKeyGuid => 7,
            Self::V8A | Self::V8B => 8,
            Self::FrozenIndex => 9,
            Self::PathHashIndex => 10,
            Self::Fnv64BugFix => 11,
        }
    }
}

impl TryFrom<u32> for PakVersion {
    type Error = PaksmithError;

    /// Map a wire-format version u32 to a `PakVersion` variant.
    ///
    /// **Wire version 8 is ambiguous** between V8A and V8B; this impl
    /// returns `V8B` (the more common variant — UE 4.23/4.24 vs the
    /// brief 4.22 V8A window). The footer parser post-corrects to
    /// `V8A` after counting FName-table slots; consumers calling
    /// `try_from(8)` directly should not rely on the variant beyond
    /// "some flavor of v8" without subsequent disambiguation.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initial),
            2 => Ok(Self::NoTimestamps),
            3 => Ok(Self::CompressionEncryption),
            4 => Ok(Self::IndexEncryption),
            5 => Ok(Self::RelativeChunkOffsets),
            6 => Ok(Self::DeleteRecords),
            7 => Ok(Self::EncryptionKeyGuid),
            8 => Ok(Self::V8B),
            9 => Ok(Self::FrozenIndex),
            10 => Ok(Self::PathHashIndex),
            11 => Ok(Self::Fnv64BugFix),
            other => Err(PaksmithError::UnsupportedVersion { version: other }),
        }
    }
}

/// Pak file magic number identifying valid archives.
///
/// `pub` (not `pub(super)`) because three test consumers import it:
/// `tests/pak_integration.rs`, `tests/footer_proptest.rs`, and the
/// synthetic-fixture generator at `tests/fixtures/generate.rs` (compiled
/// as a `paksmith-core` example, so it imports the public const rather
/// than redefining it).
pub const PAK_MAGIC: u32 = 0x5A6F_12E1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_try_from_valid() {
        assert_eq!(PakVersion::try_from(1u32).unwrap(), PakVersion::Initial);
        assert_eq!(
            PakVersion::try_from(7u32).unwrap(),
            PakVersion::EncryptionKeyGuid
        );
        assert_eq!(
            PakVersion::try_from(11u32).unwrap(),
            PakVersion::Fnv64BugFix
        );
    }

    /// Wire version 8 is structurally ambiguous between V8A and V8B
    /// (both write `version = 8`). `TryFrom<u32>` returns the more
    /// common V8B by default; the footer parser post-corrects to V8A
    /// after counting FName-table slots. Pin both halves of the
    /// contract so a future refactor can't silently flip the default
    /// without surfacing here.
    #[test]
    fn version_try_from_8_defaults_to_v8b() {
        assert_eq!(PakVersion::try_from(8u32).unwrap(), PakVersion::V8B);
    }

    /// `wire_version()` round-trips: every variant maps to a u32 that
    /// `TryFrom<u32>` could decode (with the V8A→V8B caveat documented
    /// in the impl). Catches a regression that adds a variant without
    /// updating the wire-version mapping.
    #[test]
    fn wire_version_round_trips() {
        for (variant, wire) in [
            (PakVersion::Initial, 1),
            (PakVersion::NoTimestamps, 2),
            (PakVersion::CompressionEncryption, 3),
            (PakVersion::IndexEncryption, 4),
            (PakVersion::RelativeChunkOffsets, 5),
            (PakVersion::DeleteRecords, 6),
            (PakVersion::EncryptionKeyGuid, 7),
            (PakVersion::V8A, 8),
            (PakVersion::V8B, 8),
            (PakVersion::FrozenIndex, 9),
            (PakVersion::PathHashIndex, 10),
            (PakVersion::Fnv64BugFix, 11),
        ] {
            assert_eq!(variant.wire_version(), wire);
        }
    }

    #[test]
    fn version_try_from_invalid() {
        for bad in [0u32, 12, 99, u32::MAX] {
            let err = PakVersion::try_from(bad).unwrap_err();
            assert!(matches!(
                err,
                PaksmithError::UnsupportedVersion { version } if version == bad
            ));
        }
    }

    #[test]
    fn version_ordering_reflects_engine_evolution() {
        assert!(PakVersion::Initial < PakVersion::EncryptionKeyGuid);
        assert!(PakVersion::Fnv64BugFix > PakVersion::PathHashIndex);
    }

    #[test]
    fn path_hash_index_threshold() {
        assert!(!PakVersion::FrozenIndex.has_path_hash_index());
        assert!(PakVersion::PathHashIndex.has_path_hash_index());
        assert!(PakVersion::Fnv64BugFix.has_path_hash_index());
    }
}
