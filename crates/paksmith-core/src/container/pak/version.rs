//! Pak format version definitions.

use crate::error::PaksmithError;

/// On-disk size of the v7+ footer in bytes.
///
/// magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20)
///   + encryption_guid(16) + encrypted_flag(1) = 61
pub const FOOTER_SIZE_V7_PLUS: u64 = 61;

/// On-disk size of the legacy (pre-v7) footer in bytes.
///
/// magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20) = 44
pub const FOOTER_SIZE_LEGACY: u64 = 44;

/// Pak file format version.
///
/// Variants are ordered chronologically — `<` and `>` reflect engine evolution.
/// Use the capability-predicate methods (e.g. [`PakVersion::has_encryption_key_guid`])
/// rather than comparing raw discriminants where possible.
///
/// **Invariant:** variants MUST remain in chronological order. The derived
/// `Ord`/`PartialOrd` impl is load-bearing — capability predicates like
/// [`PakVersion::has_encryption_key_guid`] depend on it. Append new variants
/// to the end; never reorder or insert.
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
    /// Whether this version includes an encryption key GUID in the footer (v7+).
    pub fn has_encryption_key_guid(self) -> bool {
        self >= Self::EncryptionKeyGuid
    }

    /// Whether this version uses the path-hash + encoded-directory index layout (v10+).
    pub fn has_path_hash_index(self) -> bool {
        self >= Self::PathHashIndex
    }

    /// The on-disk footer size for this version.
    pub fn footer_size(self) -> u64 {
        if self.has_encryption_key_guid() {
            FOOTER_SIZE_V7_PLUS
        } else {
            FOOTER_SIZE_LEGACY
        }
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
    fn encryption_guid_threshold() {
        assert!(!PakVersion::DeleteRecords.has_encryption_key_guid());
        assert!(PakVersion::EncryptionKeyGuid.has_encryption_key_guid());
        assert!(PakVersion::Fnv64BugFix.has_encryption_key_guid());
    }

    #[test]
    fn path_hash_index_threshold() {
        assert!(!PakVersion::FrozenIndex.has_path_hash_index());
        assert!(PakVersion::PathHashIndex.has_path_hash_index());
        assert!(PakVersion::Fnv64BugFix.has_path_hash_index());
    }

    #[test]
    fn footer_size_pre_v7() {
        assert_eq!(PakVersion::Initial.footer_size(), FOOTER_SIZE_LEGACY);
        assert_eq!(PakVersion::DeleteRecords.footer_size(), FOOTER_SIZE_LEGACY);
    }

    #[test]
    fn footer_size_v7_plus() {
        assert_eq!(
            PakVersion::EncryptionKeyGuid.footer_size(),
            FOOTER_SIZE_V7_PLUS
        );
        assert_eq!(PakVersion::Fnv64BugFix.footer_size(), FOOTER_SIZE_V7_PLUS);
    }
}
