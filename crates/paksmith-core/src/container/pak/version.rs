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
/// the other and silently flipping V8A↔V8B detection (the entry parser
/// uses `compression_methods.len() == 4` as its V8A signal, which is
/// only valid because `FOOTER_SIZE_V8A == FOOTER_SIZE_V7_PLUS +
/// COMPRESSION_SLOTS_V8A * COMPRESSION_SLOT_BYTES`).
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
/// Variants are ordered chronologically — `<` and `>` reflect engine evolution.
/// Use the capability-predicate method [`PakVersion::has_path_hash_index`]
/// rather than comparing raw discriminants where possible.
///
/// **Invariant:** variants MUST remain in chronological order. The derived
/// `Ord`/`PartialOrd` impl is load-bearing — [`PakVersion::has_path_hash_index`]
/// depends on it. Append new variants to the end; never reorder or insert.
///
/// Marked `#[non_exhaustive]` so downstream `match` statements survive the
/// addition of future engine versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum PakVersion {
    /// Initial pak format. UE 4.0.
    Initial = 1,
    /// Removed per-entry timestamps. UE 4.3.
    NoTimestamps = 2,
    /// Added compression and AES encryption support. UE 4.4.
    CompressionEncryption = 3,
    /// Added index encryption. UE 4.16.
    IndexEncryption = 4,
    /// Switched compression block offsets to be relative to the entry. UE 4.20.
    RelativeChunkOffsets = 5,
    /// Added delete records (used during patching). UE 4.21.
    DeleteRecords = 6,
    /// Added per-archive encryption key GUID to the footer. UE 4.22.
    EncryptionKeyGuid = 7,
    /// Replaced the compression-method u32 with an FName-table index. UE 4.23.
    FNameBasedCompression = 8,
    /// Added optional frozen index format. UE 4.25.
    FrozenIndex = 9,
    /// Replaced the flat index with a path-hash + encoded directory index. UE 4.26.
    PathHashIndex = 10,
    /// Fixed an FNV-64 hashing bug in the path-hash index. UE 4.27.
    Fnv64BugFix = 11,
}

impl PakVersion {
    /// Whether this version uses the path-hash + encoded-directory
    /// index layout (v10+). Used by `PakIndex::read_from` to dispatch
    /// between the flat (v3-v9) and path-hash (v10+) parsers.
    pub(crate) fn has_path_hash_index(self) -> bool {
        self >= Self::PathHashIndex
    }
}

impl TryFrom<u32> for PakVersion {
    type Error = PaksmithError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Initial),
            2 => Ok(Self::NoTimestamps),
            3 => Ok(Self::CompressionEncryption),
            4 => Ok(Self::IndexEncryption),
            5 => Ok(Self::RelativeChunkOffsets),
            6 => Ok(Self::DeleteRecords),
            7 => Ok(Self::EncryptionKeyGuid),
            8 => Ok(Self::FNameBasedCompression),
            9 => Ok(Self::FrozenIndex),
            10 => Ok(Self::PathHashIndex),
            11 => Ok(Self::Fnv64BugFix),
            other => Err(PaksmithError::UnsupportedVersion { version: other }),
        }
    }
}

/// Pak file magic number identifying valid archives.
///
/// `pub` (not `pub(super)`) because four integration tests
/// (`tests/pak_integration.rs`, `tests/footer_proptest.rs`,
/// `tests/fixture_anchor.rs`, and `tests/fixtures/generate.rs`) write
/// it into hand-rolled fixture bytes.
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
