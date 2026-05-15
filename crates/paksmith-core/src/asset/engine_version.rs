//! `FEngineVersion` — major.minor.patch + changelist + branch name.
//!
//! Wire shape (UE's `FEngineVersion::Serialize`):
//! ```text
//! u16  major
//! u16  minor
//! u16  patch
//! u32  changelist        // High bit set = licensee changelist
//! FStr branch            // e.g. "++UE5+Release-5.1"
//! ```

use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::Serialize;

use crate::container::pak::index::read_fstring;
use crate::error::{AssetParseFault, IndexParseFault, PaksmithError};

/// Decoded `FEngineVersion`. `Display` renders as the canonical UE
/// string `"major.minor.patch-changelist+branch"` (matches FModel
/// output and UE's own `FEngineVersion::ToString`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineVersion {
    /// Major version (e.g. `5`).
    pub major: u16,
    /// Minor version (e.g. `1`).
    pub minor: u16,
    /// Patch version (e.g. `1`).
    pub patch: u16,
    /// Changelist (Perforce-style). High bit set indicates a licensee
    /// changelist; preserved as-is for round-trip fidelity.
    pub changelist: u32,
    /// Branch name (e.g. `"++UE5+Release-5.1"`).
    pub branch: String,
}

impl EngineVersion {
    /// Read one `FEngineVersion` from `reader`.
    ///
    /// # Errors
    /// - [`PaksmithError::Io`] on I/O failures (including `UnexpectedEof`)
    /// - [`PaksmithError::AssetParse`] with
    ///   [`AssetParseFault::FStringMalformed`] if the branch FString is
    ///   malformed (length zero, length-overflow, encoding error,
    ///   missing null terminator).
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        let major = reader.read_u16::<LittleEndian>()?;
        let minor = reader.read_u16::<LittleEndian>()?;
        let patch = reader.read_u16::<LittleEndian>()?;
        let changelist = reader.read_u32::<LittleEndian>()?;
        let branch = read_fstring(reader).map_err(|e| match e {
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::FStringMalformed { kind },
            } => PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::FStringMalformed { kind },
            },
            other => other,
        })?;
        Ok(Self {
            major,
            minor,
            patch,
            changelist,
            branch,
        })
    }

    /// Encode to `writer`. Used by `paksmith-fixture-gen` and tests.
    ///
    /// # Errors
    /// Returns [`io::Error`] if writes fail, or if the branch length
    /// (with null terminator) exceeds `i32::MAX`. The writer trusts
    /// its caller for content validity.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_u16::<LittleEndian>(self.major)?;
        writer.write_u16::<LittleEndian>(self.minor)?;
        writer.write_u16::<LittleEndian>(self.patch)?;
        writer.write_u32::<LittleEndian>(self.changelist)?;
        // UE FString encoding: positive i32 length (UTF-8 + null) or
        // negative (UTF-16). The fixture gen always emits UTF-8.
        let bytes_with_null = self.branch.len() + 1;
        let len_i32 = i32::try_from(bytes_with_null)
            .map_err(|_| io::Error::other("branch FString length exceeds i32::MAX"))?;
        writer.write_i32::<LittleEndian>(len_i32)?;
        writer.write_all(self.branch.as_bytes())?;
        writer.write_u8(0)?;
        Ok(())
    }
}

impl std::fmt::Display for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}-{}+{}",
            self.major, self.minor, self.patch, self.changelist, self.branch
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_known_version() {
        let v = EngineVersion {
            major: 5,
            minor: 1,
            patch: 1,
            changelist: 0,
            branch: "++UE5+Release-5.1".to_string(),
        };
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(buf.as_slice());
        let parsed = EngineVersion::read_from(&mut cursor, "test.uasset").unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn display_format() {
        let v = EngineVersion {
            major: 5,
            minor: 1,
            patch: 1,
            changelist: 0,
            branch: "++UE5+Release-5.1".to_string(),
        };
        assert_eq!(format!("{v}"), "5.1.1-0+++UE5+Release-5.1");
    }

    #[test]
    fn empty_branch_round_trip() {
        // UE writers emit an empty branch as len=1, single null byte.
        // Our reader uses read_fstring which rejects len=0 — confirm
        // the write_to path emits len=1 (header + null = 5 trailer bytes).
        let v = EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: 0,
            branch: String::new(),
        };
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 10 + 4 + 1);
        let mut cursor = Cursor::new(buf.as_slice());
        let parsed = EngineVersion::read_from(&mut cursor, "test.uasset").unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn fstring_error_maps_to_asset_parse_fault() {
        // Defect 2: read_fstring's IndexParseFault::FStringMalformed must
        // map to AssetParseFault::FStringMalformed when called from
        // asset-side. Craft a malformed branch FString (length 0) and
        // confirm the error category.
        use crate::error::{AssetParseFault, FStringFault, IndexParseFault, PaksmithError};

        // Wire: 10 fixed bytes (major+minor+patch+changelist) + i32 len=0.
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes()); // len=0 — malformed

        let mut cursor = Cursor::new(buf.as_slice());
        let err = EngineVersion::read_from(&mut cursor, "Game/Foo.uasset").unwrap_err();

        // Should be AssetParse, NOT InvalidIndex.
        match err {
            PaksmithError::AssetParse {
                asset_path,
                fault:
                    AssetParseFault::FStringMalformed {
                        kind: FStringFault::LengthIsZero,
                    },
            } => {
                assert_eq!(asset_path, "Game/Foo.uasset");
            }
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::FStringMalformed { .. },
            } => {
                panic!("FString error leaked through as InvalidIndex — defect 2 not fixed");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
