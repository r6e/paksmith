//! Pak format version definitions.

/// Pak file format version.
///
/// Versions correspond to UE engine evolution. Each version adds fields
/// to the footer and/or index entry format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum PakVersion {
    Initial = 1,
    NoTimestamps = 2,
    CompressionEncryption = 3,
    IndexEncryption = 4,
    RelativeChunkOffsets = 5,
    DeleteRecords = 6,
    EncryptionKeyGuid = 7,
    FNameBasedCompression = 8,
    FrozenIndex = 9,
    PathHashIndex = 10,
    Fnv64BugFix = 11,
}

impl PakVersion {
    /// Parse a raw `u32` into a known version, returning `None` for unrecognized values.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Initial),
            2 => Some(Self::NoTimestamps),
            3 => Some(Self::CompressionEncryption),
            4 => Some(Self::IndexEncryption),
            5 => Some(Self::RelativeChunkOffsets),
            6 => Some(Self::DeleteRecords),
            7 => Some(Self::EncryptionKeyGuid),
            8 => Some(Self::FNameBasedCompression),
            9 => Some(Self::FrozenIndex),
            10 => Some(Self::PathHashIndex),
            11 => Some(Self::Fnv64BugFix),
            _ => None,
        }
    }

    /// Whether this version includes an encryption key GUID in the footer.
    pub fn has_encryption_key_guid(self) -> bool {
        self >= Self::EncryptionKeyGuid
    }

    /// Whether this version uses path-hash-based index encoding.
    pub fn has_path_hash_index(self) -> bool {
        self >= Self::PathHashIndex
    }

    /// The on-disk footer size for this version.
    pub fn footer_size(self) -> u64 {
        if self >= Self::EncryptionKeyGuid {
            // magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20) + encryption_guid(16) + encrypted_flag(1)
            61
        } else {
            // magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20)
            44
        }
    }
}

/// Pak file magic number identifying valid archives.
pub const PAK_MAGIC: u32 = 0x5A6F_12E1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_u32_valid() {
        assert_eq!(PakVersion::from_u32(1), Some(PakVersion::Initial));
        assert_eq!(PakVersion::from_u32(7), Some(PakVersion::EncryptionKeyGuid));
        assert_eq!(PakVersion::from_u32(11), Some(PakVersion::Fnv64BugFix));
    }

    #[test]
    fn version_from_u32_invalid() {
        assert_eq!(PakVersion::from_u32(0), None);
        assert_eq!(PakVersion::from_u32(12), None);
        assert_eq!(PakVersion::from_u32(99), None);
    }

    #[test]
    fn version_ordering() {
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
    fn footer_size_pre_v7() {
        assert_eq!(PakVersion::Initial.footer_size(), 44);
        assert_eq!(PakVersion::DeleteRecords.footer_size(), 44);
    }

    #[test]
    fn footer_size_v7_plus() {
        assert_eq!(PakVersion::EncryptionKeyGuid.footer_size(), 61);
        assert_eq!(PakVersion::Fnv64BugFix.footer_size(), 61);
    }
}
