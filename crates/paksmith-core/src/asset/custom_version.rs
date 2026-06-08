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
use serde::{Deserialize, Serialize};

use crate::asset::FGuid;
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError, try_reserve_asset};
use crate::seams::AssetSeam;

/// Structural cap on the wire-claimed custom-version count. Bombed-
/// out archives won't get past this to allocate the Vec.
const MAX_CUSTOM_VERSIONS: u32 = 1024;

/// `FEditorObjectVersion` GUID. Cited via the community-derived
/// `unreal_asset@f4df5d8` custom-version registry
/// (`Guid::from_ints(0xE4B068ED, 0xF49442E9, 0xA231DA0B, 0x2E46BB41)`)
/// — paksmith's `FGuid` stores raw wire bytes (4 LE u32s).
pub const EDITOR_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([
    0xED, 0x68, 0xB0, 0xE4, // A = 0xE4B068ED (LE)
    0xE9, 0x42, 0x94, 0xF4, // B = 0xF49442E9 (LE)
    0x0B, 0xDA, 0x31, 0xA2, // C = 0xA231DA0B (LE)
    0x41, 0xBB, 0x46, 0x2E, // D = 0x2E46BB41 (LE)
]);

/// `FEditorObjectVersion::CultureInvariantTextSerializationKeyStability`
/// — the first editor-object-version that emits the
/// `bHasCultureInvariantString` u32 onto the wire for `FText` whose
/// `HistoryType` is `None`. Per `unreal_asset@f4df5d8`'s
/// `FEditorObjectVersion` enum, position 33.
pub const EDITOR_OBJECT_VERSION_CULTURE_INVARIANT_KEY_STABILITY: i32 = 33;

/// `FFrameworkObjectVersion` GUID. Cited via CUE4Parse
/// `FFrameworkObjectVersion.cs` (`new(0xCFFC743F, 0x43B04480, 0x939114DF,
/// 0x171D2073)`) — paksmith's `FGuid` stores raw wire bytes (4 LE u32s).
pub const FRAMEWORK_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([
    0x3F, 0x74, 0xFC, 0xCF, // A = 0xCFFC743F (LE)
    0x80, 0x44, 0xB0, 0x43, // B = 0x43B04480 (LE)
    0xDF, 0x14, 0x91, 0x93, // C = 0x939114DF (LE)
    0x73, 0x20, 0x1D, 0x17, // D = 0x171D2073 (LE)
]);

/// `FFrameworkObjectVersion::RemoveSoundWaveCompressionName` — the framework
/// object-version at/after which `USoundWave` stops serializing the dummy
/// `FName` compression-name field. Per CUE4Parse `FFrameworkObjectVersion.cs`,
/// position 12 (counting from `BeforeCustomVersionWasAdded = 0`; the immediate
/// predecessor is `PhysAssetUseSkeletalBodySetup`).
pub const FRAMEWORK_OBJECT_VERSION_REMOVE_SOUND_WAVE_COMPRESSION_NAME: i32 = 12;

/// `FCoreObjectVersion` GUID. Cited via CUE4Parse `FCoreObjectVersion.cs`
/// (`new(0x375EC13C, 0x06E448FB, 0xB50084F0, 0x262A717E)`) — paksmith's `FGuid`
/// stores raw wire bytes (4 LE u32s, same convention as
/// [`EDITOR_OBJECT_VERSION_GUID`]).
pub const CORE_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([
    0x3C, 0xC1, 0x5E, 0x37, // A = 0x375EC13C (LE)
    0xFB, 0x48, 0xE4, 0x06, // B = 0x06E448FB (LE)
    0xF0, 0x84, 0x00, 0xB5, // C = 0xB50084F0 (LE)
    0x7E, 0x71, 0x2A, 0x26, // D = 0x262A717E (LE)
]);

/// `FRenderingObjectVersion` GUID. Cited via CUE4Parse `FRenderingObjectVersion.cs`
/// (`new(0x12F88B9F, 0x88754AFC, 0xA67CD90C, 0x383ABD29)`) — paksmith's `FGuid`
/// stores raw wire bytes (4 LE u32s).
pub const RENDERING_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([
    0x9F, 0x8B, 0xF8, 0x12, // A = 0x12F88B9F (LE)
    0xFC, 0x4A, 0x75, 0x88, // B = 0x88754AFC (LE)
    0x0C, 0xD9, 0x7C, 0xA6, // C = 0xA67CD90C (LE)
    0x29, 0xBD, 0x3A, 0x38, // D = 0x383ABD29 (LE)
]);

/// `FFortniteMainBranchObjectVersion` GUID. Cited via CUE4Parse
/// `FFortniteMainBranchObjectVersion.cs`
/// (`new(0x601D1886, 0xAC644F84, 0xAA16D3DE, 0x0DEAC7D6)`) — paksmith's `FGuid`
/// stores raw wire bytes (4 LE u32s).
pub const FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID: FGuid = FGuid::from_bytes([
    0x86, 0x18, 0x1D, 0x60, // A = 0x601D1886 (LE)
    0x84, 0x4F, 0x64, 0xAC, // B = 0xAC644F84 (LE)
    0xDE, 0xD3, 0x16, 0xAA, // C = 0xAA16D3DE (LE)
    0xD6, 0xC7, 0xEA, 0x0D, // D = 0x0DEAC7D6 (LE)
]);

/// `FEditorObjectVersion::RefactorMeshEditorMaterials` — the editor-object
/// version at/after which `FSkeletalMaterial`/`FStaticMaterial` serialize a
/// `MaterialSlotName` `FName`. Per CUE4Parse `FEditorObjectVersion.cs`,
/// position 8 (anchor `CultureInvariantTextSerializationKeyStability = 32`,
/// counting back; uses [`EDITOR_OBJECT_VERSION_GUID`]).
///
/// NOTE: the `CultureInvariantTextSerializationKeyStability` anchor position
/// differs between oracles — CUE4Parse @ `cf74fc32` lists it at 32, whereas
/// `unreal_asset@f4df5d8` lists it at 33 (see
/// [`EDITOR_OBJECT_VERSION_CULTURE_INVARIANT_KEY_STABILITY`], which cites the
/// latter). This `RefactorMeshEditorMaterials` constant is anchored against the
/// CUE4Parse enum; the off-by-one anchor discrepancy is tracked separately and
/// does not affect position 8.
pub const REFACTOR_MESH_EDITOR_MATERIALS: i32 = 8;

/// `FCoreObjectVersion::SkeletalMaterialEditorDataStripping` — the core-object
/// version at/after which `FSkeletalMaterial` serializes the
/// `bSerializeImportedMaterialSlotName` bool. Per CUE4Parse
/// `FCoreObjectVersion.cs`, position 3 (anchor `EnumProperties = 2`; uses
/// [`CORE_OBJECT_VERSION_GUID`]).
pub const SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING: i32 = 3;

/// `FRenderingObjectVersion::TextureStreamingMeshUVChannelData` — the
/// rendering-object version at/after which `FSkeletalMaterial`/`FStaticMaterial`
/// serialize the `FMeshUVChannelInfo UVChannelData` struct. Per CUE4Parse
/// `FRenderingObjectVersion.cs`, position 10 (anchor
/// `MapBuildDataSeparatePackage = 9`; uses [`RENDERING_OBJECT_VERSION_GUID`]).
pub const TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA: i32 = 10;

/// `FFortniteMainBranchObjectVersion::MeshMaterialSlotOverlayMaterialAdded` —
/// the Fortnite-main-branch version at/after which `FSkeletalMaterial`/
/// `FStaticMaterial` serialize the `OverlayMaterialInterface` `FPackageIndex`
/// (UE5). Per CUE4Parse `FFortniteMainBranchObjectVersion.cs`, position 196
/// (anchor `PCGAttributeSetToPointAlwaysConverts = 195`; uses
/// [`FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID`]).
pub const MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED: i32 = 196;

/// `FSkeletalMeshCustomVersion` GUID. Cited via CUE4Parse
/// `FSkeletalMeshCustomVersion.cs` @ `cf74fc32`
/// (`new(0xD78A4A00, 0xE8584697, 0xBAA819B5, 0x487D46B4)`) — paksmith's `FGuid`
/// stores raw wire bytes (4 LE u32s, same convention as
/// [`EDITOR_OBJECT_VERSION_GUID`]).
pub const SKELETAL_MESH_CUSTOM_VERSION_GUID: FGuid = FGuid::from_bytes([
    0x00, 0x4A, 0x8A, 0xD7, // A = 0xD78A4A00 (LE)
    0x97, 0x46, 0x58, 0xE8, // B = 0xE8584697 (LE)
    0xB5, 0x19, 0xA8, 0xBA, // C = 0xBAA819B5 (LE)
    0xB4, 0x46, 0x7D, 0x48, // D = 0x487D46B4 (LE)
]);

/// `FSkeletalMeshCustomVersion::SplitModelAndRenderData` — the skeletal-mesh
/// custom version at/after which `USkeletalMesh.Deserialize` splits editor
/// `LODModels` from cooked render data, gating the editor-LODModels read on
/// `!IsEditorDataStripped()` and emitting the `bCooked` bool. Below this, the
/// legacy `FStaticLODModel` array is read inline with no `bCooked` field. Per
/// CUE4Parse `FSkeletalMeshCustomVersion.cs`, position 12 (anchor
/// `RemoveSourceData = 11`; uses [`SKELETAL_MESH_CUSTOM_VERSION_GUID`]).
pub const SPLIT_MODEL_AND_RENDER_DATA: i32 = 12;

/// One row in the custom-version table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// `TArray<FCustomVersion>` from the package summary.
///
/// Wraps a `Vec<CustomVersion>` rather than being a transparent alias
/// so the cap-enforced reader has a typed home. `#[serde(transparent)]`
/// makes it serialize as a bare JSON array so the parent summary's
/// `custom_versions` field shows `[ {...}, ... ]` rather than
/// `{ "versions": [ ... ] }` (matches Task 14 deliverable).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
        // count: i32, validated `>= 0` above; the cast is bit-preserving.
        #[allow(clippy::cast_sign_loss)]
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
            AssetSeam::CustomVersionContainer,
        )?;
        for _ in 0..count_u32 {
            versions.push(CustomVersion::read_from(reader)?);
        }
        Ok(Self { versions })
    }

    /// Look up the version number for the plugin identified by `guid`.
    ///
    /// Returns `None` if the container has no entry for that GUID —
    /// the asset summary did not declare a stamp for that plugin, so
    /// the default-version behavior applies (typically: assume the
    /// floor implied by the asset's `AssetVersion`).
    #[must_use]
    pub fn version_for(&self, guid: FGuid) -> Option<i32> {
        self.versions
            .iter()
            .find(|cv| cv.guid == guid)
            .map(|cv| cv.version)
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
        // MAX_CUSTOM_VERSIONS is a small const; +1 fits in i32.
        #[allow(clippy::cast_possible_wrap)]
        let over_cap = (MAX_CUSTOM_VERSIONS + 1) as i32;
        buf.extend_from_slice(&over_cap.to_le_bytes());
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
    fn count_equal_to_cap_is_not_rejected_as_over_cap() {
        // Pins the `count > MAX_CUSTOM_VERSIONS` boundary against `>=`: a count
        // of exactly the cap must PASS the bounds check (then fail later on EOF
        // for the absent records), not be rejected as `BoundsExceeded`.
        let mut buf = Vec::new();
        #[allow(clippy::cast_possible_wrap)]
        let at_cap = MAX_CUSTOM_VERSIONS as i32;
        buf.extend_from_slice(&at_cap.to_le_bytes());
        // No record bytes follow → the read loop hits EOF, not the cap.
        let err =
            CustomVersionContainer::read_from(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(
            !matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded { .. },
                    ..
                }
            ),
            "count == cap must not be BoundsExceeded, got {err:?}"
        );
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
    fn skeletal_material_gate_guids_and_positions() {
        // GUIDs (CUE4Parse `new FGuid(A,B,C,D)`, each u32 word little-endian).
        assert_eq!(
            CORE_OBJECT_VERSION_GUID,
            FGuid::from_bytes([
                0x3C, 0xC1, 0x5E, 0x37, 0xFB, 0x48, 0xE4, 0x06, 0xF0, 0x84, 0x00, 0xB5, 0x7E, 0x71,
                0x2A, 0x26,
            ])
        );
        assert_eq!(
            RENDERING_OBJECT_VERSION_GUID,
            FGuid::from_bytes([
                0x9F, 0x8B, 0xF8, 0x12, 0xFC, 0x4A, 0x75, 0x88, 0x0C, 0xD9, 0x7C, 0xA6, 0x29, 0xBD,
                0x3A, 0x38,
            ])
        );
        assert_eq!(
            FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
            FGuid::from_bytes([
                0x86, 0x18, 0x1D, 0x60, 0x84, 0x4F, 0x64, 0xAC, 0xDE, 0xD3, 0x16, 0xAA, 0xD6, 0xC7,
                0xEA, 0x0D,
            ])
        );
        // Enum-member positions.
        assert_eq!(REFACTOR_MESH_EDITOR_MATERIALS, 8);
        assert_eq!(SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING, 3);
        assert_eq!(TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA, 10);
        assert_eq!(MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED, 196);
    }

    #[test]
    fn skeletal_mesh_custom_version_guid_and_split_position() {
        // GUID (CUE4Parse `new FGuid(0xD78A4A00, 0xE8584697, 0xBAA819B5,
        // 0x487D46B4)` @ cf74fc32, each u32 word little-endian).
        assert_eq!(
            SKELETAL_MESH_CUSTOM_VERSION_GUID,
            FGuid::from_bytes([
                0x00, 0x4A, 0x8A, 0xD7, 0x97, 0x46, 0x58, 0xE8, 0xB5, 0x19, 0xA8, 0xBA, 0xB4, 0x46,
                0x7D, 0x48,
            ])
        );
        // Enum-member position: SplitModelAndRenderData = 12.
        assert_eq!(SPLIT_MODEL_AND_RENDER_DATA, 12);
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
