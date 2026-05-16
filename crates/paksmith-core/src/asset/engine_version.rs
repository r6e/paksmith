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

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::read_asset_fstring;
#[cfg(any(test, feature = "__test_utils"))]
use crate::asset::write_asset_fstring;

/// Decoded `FEngineVersion`. `Display` renders the canonical
/// `"major.minor.patch-changelist+branch"` format (matches FModel for
/// non-empty branches). UE's own `FEngineVersion::ToString` suppresses
/// the `+branch` segment for empty branches; paksmith does not — the
/// trailing `+` is emitted unconditionally so `Display` stays in
/// lockstep with `Serialize` (which routes through `collect_str`).
/// UE writers don't emit empty branches in practice, so this
/// divergence is theoretical.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// - [`crate::error::PaksmithError::Io`] on I/O failures (including
    ///   `UnexpectedEof`)
    /// - [`crate::error::PaksmithError::AssetParse`] with
    ///   [`crate::error::AssetParseFault::FStringMalformed`] if the branch
    ///   FString is malformed (length-overflow, encoding error, missing
    ///   null terminator). Note: `len == 0` is accepted as the empty
    ///   string at the asset boundary as of commit d65909d.
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        let major = reader.read_u16::<LittleEndian>()?;
        let minor = reader.read_u16::<LittleEndian>()?;
        let patch = reader.read_u16::<LittleEndian>()?;
        let changelist = reader.read_u32::<LittleEndian>()?;
        let branch = read_asset_fstring(reader, asset_path)?;
        Ok(Self {
            major,
            minor,
            patch,
            changelist,
            branch,
        })
    }

    /// Encode to `writer`. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail, or if the branch length
    /// (with null terminator) exceeds `i32::MAX`. The writer trusts
    /// its caller for content validity.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u16::<LittleEndian>(self.major)?;
        writer.write_u16::<LittleEndian>(self.minor)?;
        writer.write_u16::<LittleEndian>(self.patch)?;
        writer.write_u32::<LittleEndian>(self.changelist)?;
        // UE FString encoding: positive i32 length (UTF-8 + null) or
        // negative (UTF-16). The fixture gen always emits UTF-8.
        write_asset_fstring(writer, &self.branch)?;
        Ok(())
    }
}

impl serde::Serialize for EngineVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // JSON matches the inspect-output contract (phase-2a-uasset-header.md
        // Task 14 deliverable: string form, not object). Mirrors PackageIndex
        // (Task 3) — see asset/package_index.rs.
        serializer.collect_str(self)
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
    fn display_format_empty_branch() {
        let v = EngineVersion {
            major: 4,
            minor: 27,
            patch: 2,
            changelist: 0,
            branch: String::new(),
        };
        assert_eq!(format!("{v}"), "4.27.2-0+");
    }

    #[test]
    fn serialize_to_display_string() {
        let v = EngineVersion {
            major: 5,
            minor: 1,
            patch: 1,
            changelist: 0,
            branch: "++UE5+Release-5.1".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#""5.1.1-0+++UE5+Release-5.1""#
        );
    }

    #[test]
    fn empty_branch_round_trip() {
        // UE writers emit an empty branch as len=1, single null byte.
        // Our write_to path mirrors that. The asset-side read_fstring
        // also accepts len=0 → "" (CUE4Parse-aligned, see fstring.rs),
        // so the empty-string round-trip is symmetric in both
        // directions but write_to specifically emits the len=1 form.
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
        // asset-side. Craft a malformed branch FString (missing null
        // terminator — len=4 followed by 4 non-null bytes) and confirm
        // the error category. `len=0` is no longer malformed asset-side
        // per the CUE4Parse-aligned relaxation (it now resolves to "")
        // so this test exercises a different malformation.
        use crate::error::{AssetParseFault, FStringFault, IndexParseFault, PaksmithError};

        // Wire: 10 fixed bytes (major+minor+patch+changelist) + i32 len=4
        // + 4 non-null bytes (no trailing 0x00).
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&4i32.to_le_bytes()); // len=4
        buf.extend_from_slice(b"abcd"); // no trailing null — malformed

        let mut cursor = Cursor::new(buf.as_slice());
        let err = EngineVersion::read_from(&mut cursor, "Game/Foo.uasset").unwrap_err();

        // Should be AssetParse, NOT InvalidIndex.
        match err {
            PaksmithError::AssetParse {
                asset_path,
                fault:
                    AssetParseFault::FStringMalformed {
                        kind: FStringFault::MissingNullTerminator { .. },
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
