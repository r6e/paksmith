//! `FCustomVersion` + container.
//!
//! Per-plugin version stamp serialized into the package summary. The
//! container is `i32 count` followed by `count` records, each `FGuid`
//! (16 bytes) + `i32 version`.
//!
//! Phase 2a accepts the modern post-UE4.13 ("Optimized") layout
//! exclusively — pre-4.13 archives used an extra FString name per
//! record (the `Guids` enum variant), but they're below our
//! `LegacyFileVersion ≥ -7` floor.

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::FGuid;
use crate::error::{
    AssetAllocationContext, AssetParseFault, AssetWireField, BoundsUnit, PaksmithError,
    try_reserve_asset,
};

/// Structural cap on the wire-claimed custom-version count. Bombed-
/// out archives won't get past this to allocate the Vec.
const MAX_CUSTOM_VERSIONS: u32 = 1024;

/// One row in the custom-version table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomVersion {
    /// Plugin GUID (16 bytes, written as 4 LE u32s by UE).
    pub guid: FGuid,
    /// Plugin's local version counter.
    pub version: i32,
}

impl CustomVersion {
    /// Read one record (20 bytes).
    ///
    /// # Errors
    /// Returns [`PaksmithError::Io`] on EOF or other I/O failures.
    pub fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let guid = FGuid::read_from(reader)?;
        let version = reader.read_i32::<LittleEndian>()?;
        Ok(Self { guid, version })
    }

    /// Write one record (20 bytes). Test- and fixture-gen-only via
    /// the `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.guid.write_to(writer)?;
        writer.write_i32::<LittleEndian>(self.version)?;
        Ok(())
    }
}

impl Serialize for CustomVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // JSON matches phase-2a deliverable (Task 14):
        // { "guid": "<canonical-form>", "version": <int> }
        // FGuid's own impl Serialize delegates to Display via collect_str.
        let mut s = serializer.serialize_struct("CustomVersion", 2)?;
        s.serialize_field("guid", &self.guid)?;
        s.serialize_field("version", &self.version)?;
        s.end()
    }
}

/// `TArray<FCustomVersion>` from the package summary.
///
/// Wraps a `Vec<CustomVersion>` rather than being a transparent alias
/// so the cap-enforced reader has a typed home. `#[serde(transparent)]`
/// makes it serialize as a bare JSON array so the parent summary's
/// `custom_versions` field shows `[ {...}, ... ]` rather than
/// `{ "versions": [ ... ] }` (matches Task 14 deliverable).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CustomVersionContainer {
    /// Parsed rows.
    pub versions: Vec<CustomVersion>,
}

impl CustomVersionContainer {
    /// Read the container (`i32 count` + `count` records).
    ///
    /// # Errors
    /// - [`AssetParseFault::NegativeValue`] if `count < 0`.
    /// - [`AssetParseFault::BoundsExceeded`] if `count > MAX_CUSTOM_VERSIONS`.
    /// - [`AssetParseFault::AllocationFailed`] if reservation fails.
    /// - [`AssetParseFault::UnexpectedEof`] (or `Io`) on EOF.
    pub fn read_from<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<Self> {
        let count = reader.read_i32::<LittleEndian>()?;
        if count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::CustomVersionCount,
                    value: i64::from(count),
                },
            });
        }
        let count_u32 = count as u32;
        if u64::from(count_u32) > u64::from(MAX_CUSTOM_VERSIONS) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    value: u64::from(count_u32),
                    limit: u64::from(MAX_CUSTOM_VERSIONS),
                    unit: BoundsUnit::Items,
                },
            });
        }
        let mut versions: Vec<CustomVersion> = Vec::new();
        try_reserve_asset(
            &mut versions,
            count_u32 as usize,
            asset_path,
            AssetAllocationContext::CustomVersionContainer,
        )?;
        for _ in 0..count_u32 {
            versions.push(CustomVersion::read_from(reader)?);
        }
        Ok(Self { versions })
    }

    /// Write the container. Test- and fixture-gen-only via the
    /// `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail or the count exceeds `i32::MAX`.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let count = i32::try_from(self.versions.len())
            .map_err(|_| std::io::Error::other("custom version count exceeds i32::MAX"))?;
        writer.write_i32::<LittleEndian>(count)?;
        for v in &self.versions {
            v.write_to(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn empty_round_trip() {
        let c = CustomVersionContainer::default();
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn one_record_round_trip() {
        let c = CustomVersionContainer {
            versions: vec![CustomVersion {
                guid: FGuid::from_bytes([
                    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B,
                ]),
                version: 42,
            }],
        };
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x").unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn multi_record_round_trip() {
        // Cover the for-loop body past N=1. Tier 3a mutation testing
        // (commit 8f25689) targets loop bounds; this test prevents
        // `0..count_u32` → `0..count_u32 - 1` mutations from passing.
        let c = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: FGuid::from_bytes([0x01; 16]),
                    version: 1,
                },
                CustomVersion {
                    guid: FGuid::from_bytes([0x02; 16]),
                    version: 2,
                },
                CustomVersion {
                    guid: FGuid::from_bytes([0x03; 16]),
                    version: 3,
                },
            ],
        };
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x").unwrap();
        assert_eq!(parsed, c);
        assert_eq!(parsed.versions.len(), 3);
    }

    #[test]
    fn rejects_count_over_cap() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_CUSTOM_VERSIONS + 1) as i32).to_le_bytes());
        let err =
            CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_negative_count() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        let err =
            CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn serialize_to_expected_shape() {
        let cv = CustomVersion {
            guid: FGuid::from_bytes([
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B,
            ]),
            version: 42,
        };
        assert_eq!(
            serde_json::to_string(&cv).unwrap(),
            r#"{"guid":"efbeadde-0302-0100-0706-05040b0a0908","version":42}"#
        );
    }

    #[test]
    fn container_serializes_as_bare_array() {
        let c = CustomVersionContainer {
            versions: vec![CustomVersion {
                guid: FGuid::from_bytes([0; 16]),
                version: 3,
            }],
        };
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"[{"guid":"00000000-0000-0000-0000-000000000000","version":3}]"#
        );
    }
}
