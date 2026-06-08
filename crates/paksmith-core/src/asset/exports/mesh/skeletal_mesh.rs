//! `USkeletalMesh` export parsing (Phase 3h). Wire reference:
//! `docs/formats/mesh/skeletal-mesh.md`.
//!
//! PR2 ships the segment-2 prefix reader ([`read_typed`]) — tagged properties,
//! object-GUID tail, strip flags, `ImportedBounds`, `SkeletalMaterials`, the
//! `FReferenceSkeleton`, and the `bCooked` bool (modern-cooked only) — wired
//! into the class dispatch. Legacy (pre-`SplitModelAndRenderData`) and
//! non-cooked (editor LOD data present) meshes return `UnsupportedFeature` and
//! degrade to a generic property bag. The per-LOD skin geometry beyond
//! `bCooked` lands in later PRs of the 3h series.

use std::io::{Cursor, Read};

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::custom_version::{
    ADD_CLOTH_MAPPING_LOD_BIAS, ADD_SKELETAL_MESH_SECTION_DISABLE, CORE_OBJECT_VERSION_GUID,
    EDITOR_OBJECT_VERSION_GUID, FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
    MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED, RECOMPUTE_TANGENT_CUSTOM_VERSION_GUID,
    RECOMPUTE_TANGENT_VERTEX_COLOR_MASK, REFACTOR_MESH_EDITOR_MATERIALS,
    RELEASE_OBJECT_VERSION_GUID, RENDERING_OBJECT_VERSION_GUID,
    SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED, SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING,
    SKELETAL_MESH_CUSTOM_VERSION_GUID, SPLIT_MODEL_AND_RENDER_DATA,
    TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA, UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
    UE5_RELEASE_STREAM_OBJECT_VERSION_GUID,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::{read_fname_pair, read_object_guid_tail, read_properties};
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::wire::{
    STRIP_FLAG_DUPLICATED_VERTICES, is_class_data_stripped, is_editor_data_stripped, read_bool32,
    read_strip_data_flags,
};
use crate::asset::{Asset, AssetContext, SkelMeshSection, SkeletalMeshData, read_package_index};
use crate::error::{AssetWireField, PaksmithError};

use super::read;
use super::skeleton::{MAX_BONES_PER_SKELETON, read_reference_skeleton};

/// Max `FSkeletalMaterial` slots per mesh — a generous ceiling enforced before
/// the `SkeletalMaterials` array read. Stock meshes have a handful.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention ([`super::static_mesh::MAX_SOCKETS_PER_MESH`] /
/// `MAX_BONES_PER_SKELETON`), the cap is pinned via an over-cap error-path
/// test (Phase 3h Task 7) rather than read live by an integration consumer.
pub(crate) const MAX_SKELETAL_MATERIALS: u32 = 256;

/// Max `FSkelMeshSection::BoneMap` entries — the 16-bit bone-index ceiling,
/// reusing [`MAX_BONES_PER_SKELETON`] (a `BoneMap` entry is a `u16` bone index,
/// so it can't reference more bones than a skeleton can hold).
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention ([`MAX_SKELETAL_MATERIALS`] / `MAX_BONES_PER_SKELETON`),
/// each cap is pinned via a value test (now) + an over-cap error-path test
/// (Phase 3h Task 7) rather than read live by an integration consumer.
#[allow(
    dead_code,
    reason = "enforced by read_skel_mesh_section_render in Phase 3h Task 6; pinned by skel_mesh_section_caps"
)]
pub(crate) const MAX_BONE_MAP_ENTRIES_PER_SECTION: usize = MAX_BONES_PER_SKELETON;

/// Max `FSkelMeshSection::ClothMappingDataLODs` per-LOD-bias levels — a generous
/// ceiling on the cloth LOD-bias nesting (UE ships a handful per section).
///
/// NOTE: no `__test_utils` accessor (see [`MAX_BONE_MAP_ENTRIES_PER_SECTION`]).
#[allow(
    dead_code,
    reason = "enforced by read_skel_mesh_section_render in Phase 3h Task 6; pinned by skel_mesh_section_caps"
)]
pub(crate) const MAX_CLOTH_LOD_BIAS_LEVELS: usize = 64;

/// Max cloth-mapping vertices per LOD. Kept as an independent literal (not a
/// reuse of [`super::vertex_buffers::MAX_VERTICES_PER_LOD`]) so changing the
/// render-vertex ceiling doesn't silently move the cloth ceiling — they're
/// conceptually distinct caps that coincidentally share the 4 Mi magnitude (and
/// `MAX_VERTICES_PER_LOD` is `u32`, so a direct reuse would need an `as usize`).
///
/// NOTE: no `__test_utils` accessor (see [`MAX_BONE_MAP_ENTRIES_PER_SECTION`]).
#[allow(
    dead_code,
    reason = "pinned by skel_mesh_section_caps; the _U32 companion (MAX_CLOTH_VERTS_PER_LOD_U32) is what read_skel_mesh_section_render uses"
)]
pub(crate) const MAX_CLOTH_VERTS_PER_LOD: usize = 4_194_304;

/// Max `FSkelMeshSection::DupVertData`/`DupVertIndexData` entries per section.
/// Independent literal for the same reason as [`MAX_CLOTH_VERTS_PER_LOD`].
///
/// NOTE: no `__test_utils` accessor (see [`MAX_BONE_MAP_ENTRIES_PER_SECTION`]).
#[allow(
    dead_code,
    reason = "pinned by skel_mesh_section_caps; the _U32 companion (MAX_DUP_VERTS_PER_SECTION_U32) is what read_skel_mesh_section_render uses"
)]
pub(crate) const MAX_DUP_VERTS_PER_SECTION: usize = 4_194_304;

/// Max `FSkelMeshSection::MaxBoneInfluences` — UE's `MAX_TOTAL_INFLUENCES`
/// (the per-vertex bone-weight slot count).
///
/// NOTE: no `__test_utils` accessor (see [`MAX_BONE_MAP_ENTRIES_PER_SECTION`]).
#[allow(
    dead_code,
    reason = "enforced by read_skel_mesh_section_render in Phase 3h Task 6; pinned by skel_mesh_section_caps"
)]
pub(crate) const MAX_INFLUENCES_PER_VERTEX: usize = 8;

/// `FMeshUVChannelInfo::MAX_TEXCOORDS` — the fixed `LocalUVDensities` element
/// count (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`). Read as a fixed-size
/// `float[]` with NO count prefix.
const MAX_TEXCOORDS: usize = 4;

/// Consume an `FMeshUVChannelInfo` (24 bytes), staying cursor-aligned.
///
/// Wire layout (oracle `FMeshUVChannelInfo.cs` @ `cf74fc32`, cooked):
/// `bInitialized` (4-byte strict `0/1` int-bool via `Ar.ReadBoolean`) +
/// `bOverrideDensities` (4-byte strict int-bool) + `LocalUVDensities`
/// (`MAX_TEXCOORDS` × `f32`, no count prefix) = `4 + 4 + 4·4 = 24` bytes.
///
/// The struct carries no data paksmith needs downstream — it exists only to
/// keep the surrounding `FSkeletalMaterial`/`FStaticMaterial` cursor aligned —
/// so the floats are read (validating length / EOF) and discarded.
///
/// # Errors
/// - [`crate::error::AssetParseFault::InvalidBool32`] if either bool is not 0/1.
/// - [`crate::PaksmithError::Io`] if a bool32 read hits EOF (propagated from
///   [`read_bool32`], which surfaces EOF as `Io`).
/// - [`crate::error::AssetParseFault::UnexpectedEof`] if a `LocalUVDensities`
///   float runs short.
pub(super) fn read_mesh_uv_channel_info<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
) -> crate::Result<()> {
    let _initialized = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    let _override_densities = read_bool32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    for _ in 0..MAX_TEXCOORDS {
        let _density = read::read_f32(r, asset_path, AssetWireField::MeshUvChannelInfo)?;
    }
    Ok(())
}

/// Consume one cooked `FSkeletalMaterial`, returning its `MaterialSlotName`.
///
/// Wire layout (oracle `FSkeletalMaterial.cs` @ `cf74fc32`, cooked), each
/// field gated on a per-plugin custom version:
///
/// 1. **`Material`** — `FPackageIndex` (always present). Consumed and
///    discarded; PR2 does not resolve the referenced material object.
/// 2. **`MaterialSlotName`** — `FName`, present iff
///    `FEditorObjectVersion >= RefactorMeshEditorMaterials (8)`. This is the
///    value returned.
/// 3. **`bSerializeImportedMaterialSlotName`** — `u32` bool, present iff
///    `FCoreObjectVersion >= SkeletalMaterialEditorDataStripping (3)`. When
///    present, the trailing `ImportedMaterialSlotName` `FName` is on the wire
///    iff this bool reads `true`. Per the oracle (`FSkeletalMaterial.cs` @
///    `cf74fc32`), `bSerializeImportedMaterialSlotName` defaults to
///    `!PKG_FilterEditorOnly` but is **overwritten** by `Ar.ReadBoolean()`
///    whenever this core-version gate fires — so on paksmith's path
///    (modern-cooked, where the gate is on) the `FName`'s presence is decided
///    by the wire-read bool ALONE, never by the package flags. We honor the
///    bool: consume one `FName` (8 bytes) when it is `true`, discard it.
///    Genuine UE-cooked archives write this bool as `false`
///    (`!IsFilterEditorOnly()`), so the `FName` is normally absent; honoring
///    the bool keeps the cursor aligned for non-`FilterEditorOnly` inputs
///    without any `AssetContext` package-flags plumbing.
///
///    KNOWN GAP: when the core gate is OFF (`FCoreObjectVersion <
///    SkeletalMaterialEditorDataStripping`) but `FEditorObjectVersion >=
///    RefactorMeshEditorMaterials`, the oracle reads `ImportedMaterialSlotName`
///    iff `!PKG_FilterEditorOnly` — i.e. only on editor (non-cooked) assets.
///    paksmith reads nothing there. This is reachable only on non-cooked
///    meshes, which `read_typed` already rejects via the `IsEditorDataStripped`
///    gate, so it does not affect the cooked path; out of scope for PR2.
/// 4. **`UVChannelData`** — `FMeshUVChannelInfo` (24 bytes), present iff
///    `FRenderingObjectVersion >= TextureStreamingMeshUVChannelData (10)`.
/// 5. **`OverlayMaterial`** — `FPackageIndex`, present iff
///    `FFortniteMainBranchObjectVersion >=
///    MeshMaterialSlotOverlayMaterialAdded (196)` (UE5). Consumed and
///    discarded.
///
/// # Errors
/// - [`crate::error::AssetParseFault::PackageIndexUnderflow`] if a package
///   index is unrepresentable (propagated from [`read_package_index`]).
/// - [`crate::error::AssetParseFault::InvalidBool32`] if
///   `bSerializeImportedMaterialSlotName` is not 0/1.
/// - [`crate::error::AssetParseFault::PackageIndexOob`] /
///   [`crate::error::AssetParseFault::PackageIndexUnderflow`] for an
///   out-of-range slot-name `FName` (propagated from [`read_fname_pair`]).
/// - [`crate::PaksmithError::Io`] / [`crate::error::AssetParseFault::UnexpectedEof`]
///   on a short read of any field.
pub(super) fn read_skeletal_material<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<String>> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);

    // 1. Material: FPackageIndex (always present); consumed, not resolved.
    let _material = read_package_index(r, asset_path, AssetWireField::SkeletalMaterialInterface)?;

    // 2. MaterialSlotName: FName, gated on FEditorObjectVersion.
    let slot = if version_for(EDITOR_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= REFACTOR_MESH_EDITOR_MATERIALS)
    {
        let name = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletalMaterialSlotName)?;
        Some(name.to_string())
    } else {
        None
    };

    // 3. bSerializeImportedMaterialSlotName: u32 bool, gated on
    //    FCoreObjectVersion. When the gate fires, the trailing
    //    ImportedMaterialSlotName FName is on the wire iff the bool reads true
    //    (see fn docs) — consume and discard it.
    if version_for(CORE_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING)
    {
        let serialize_imported = read_bool32(
            r,
            asset_path,
            AssetWireField::SkeletalMaterialSerializeImportedSlotName,
        )?;
        if serialize_imported {
            let _imported_slot_name = read_fname_pair(
                r,
                ctx,
                asset_path,
                AssetWireField::SkeletalMaterialImportedSlotName,
            )?;
        }
    }

    // 4. UVChannelData: FMeshUVChannelInfo, gated on FRenderingObjectVersion.
    if version_for(RENDERING_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA)
    {
        read_mesh_uv_channel_info(r, asset_path)?;
    }

    // 5. OverlayMaterial: FPackageIndex (UE5), gated on
    //    FFortniteMainBranchObjectVersion; consumed, not resolved.
    if version_for(FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED)
    {
        let _overlay = read_package_index(
            r,
            asset_path,
            AssetWireField::SkeletalMaterialOverlayInterface,
        )?;
    }

    Ok(slot)
}

/// `u32` companions of the section caps for [`read::read_capped_count`] (which
/// takes a `u32` cap). Declared as literals — not `as`-casts of the `usize`
/// caps — to stay `cast_possible_truncation`-clean; their equality with the
/// authoritative `usize` caps is pinned by `section_cap_u32_companions_match`.
const MAX_BONE_MAP_ENTRIES_PER_SECTION_U32: u32 = 65_536;
const MAX_CLOTH_LOD_BIAS_LEVELS_U32: u32 = 64;
const MAX_CLOTH_VERTS_PER_LOD_U32: u32 = 4_194_304;
const MAX_DUP_VERTS_PER_SECTION_U32: u32 = 4_194_304;
/// `i32` companion of [`MAX_INFLUENCES_PER_VERTEX`] for the signed comparison.
const MAX_INFLUENCES_PER_VERTEX_I32: i32 = 8;

/// `FMeshToMeshVertData` wire size — a constant 64 bytes in BOTH
/// `FReleaseObjectVersion` branches (only the last 8 bytes' meaning differs), so
/// cloth-mapping entries are skipped, never parsed.
const MESH_TO_MESH_VERT_DATA_BYTES: u64 = 64;

/// `FClothingSectionData` wire size — `FGuid (16)` + `i32 (4)` = 20 bytes,
/// consumed (not stored — paksmith defers cloth).
const CLOTHING_SECTION_DATA_BYTES: u64 = 20;

/// `DupVertData` element size (`u32` index → 4 bytes each).
const DUP_VERT_DATA_ELEM_BYTES: u64 = 4;

/// `DupVertIndexData` element size (`u32` start + `u32` count → 8 bytes each).
const DUP_VERT_INDEX_DATA_ELEM_BYTES: u64 = 8;

/// UE default for `RecomputeTangentsVertexMaskChannel`
/// (`ESkinVertexColorChannel::None`) when the gate is OFF.
const RECOMPUTE_TANGENTS_VERTEX_MASK_CHANNEL_NONE: u8 = 3;

/// Skip exactly `n` bytes from `r`, surfacing a short read as a typed EOF on
/// `field`. Uses a bounded `io::copy` into a sink so an attacker-supplied count
/// can't over-allocate (`Take` caps the read at `n`).
fn skip_bytes<R: Read + ?Sized>(
    r: &mut R,
    n: u64,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<()> {
    let copied = std::io::copy(&mut (&mut *r).take(n), &mut std::io::sink())
        .map_err(|_| read::eof(asset_path, field))?;
    if copied != n {
        return Err(read::eof(asset_path, field));
    }
    Ok(())
}

/// Read one cooked `FSkelMeshSection` via `SerializeRenderItem` — the
/// editor-data-stripped render path `USkeletalMesh.Deserialize`'s `bCooked`
/// branch hits (NOT the 25-field editor constructor). 18 fields in wire order;
/// cloth-mapping + dup-vert arrays are consumed-not-stored (paksmith defers
/// cloth). Each version gate is `custom_versions.version_for(GUID) >= POS`.
///
/// Counts (`BoneMap`, the nested cloth arrays, the dup-vert arrays) are capped
/// via [`read::read_capped_count`] **before** any allocation/skip: a negative
/// count surfaces as [`crate::error::AssetParseFault::NegativeValue`] and an
/// over-cap count as [`crate::error::AssetParseFault::BoundsExceeded`] carrying
/// the offending [`AssetWireField`] in its `field`. This is the permanent design
/// (consistent with PR2's `SkeletalMaterials` count) — there are no
/// section-specific `*CountExceeded` faults.
///
/// # Errors
/// [`crate::PaksmithError`] on a short / corrupt field (typed EOF), a non-strict
/// bool32 ([`crate::error::AssetParseFault::InvalidBool32`]), an over-cap /
/// negative count, or a negative `NumVertices`
/// ([`crate::error::AssetParseFault::SectionCountNegative`]) / invalid
/// `MaxBoneInfluences` ([`crate::error::AssetParseFault::SectionInfluenceCountInvalid`]).
#[allow(
    dead_code,
    reason = "wired by PR4 (FStaticLODModel.SerializeRenderItem Sections[] loop)"
)]
#[allow(
    clippy::too_many_lines,
    reason = "a flat 18-field wire sequence; splitting the in-order reads into \
              sub-fns would obscure the cursor flow the cooked layout depends on"
)]
pub(crate) fn read_skel_mesh_section_render<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<SkelMeshSection> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);

    // 1. FStripDataFlags — keep `class` for the dup-vert gate.
    let (_global, class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkelSectionStripFlags)?;

    // 2-4. MaterialIndex i16, BaseIndex i32, NumTriangles i32.
    let material_index = i32::from(read::read_i16(
        r,
        asset_path,
        AssetWireField::SkelSectionMaterialIndex,
    )?);
    let base_index = read::read_i32(r, asset_path, AssetWireField::SkelSectionBaseIndex)?;
    let num_triangles = read::read_i32(r, asset_path, AssetWireField::SkelSectionNumTriangles)?;

    // 5. bRecomputeTangent (bool32, unconditional).
    let recompute_tangent =
        read_bool32(r, asset_path, AssetWireField::SkelSectionRecomputeTangent)?;

    // 6. RecomputeTangentsVertexMaskChannel u8 — gated on FRecomputeTangentCustomVersion.
    let recompute_tangents_vertex_mask_channel =
        if version_for(RECOMPUTE_TANGENT_CUSTOM_VERSION_GUID)
            .is_some_and(|v| v >= RECOMPUTE_TANGENT_VERTEX_COLOR_MASK)
        {
            read::read_u8(
                r,
                asset_path,
                AssetWireField::SkelSectionRecomputeTangentMask,
            )?
        } else {
            RECOMPUTE_TANGENTS_VERTEX_MASK_CHANNEL_NONE
        };

    // 7. bCastShadow (bool32) — gated on FEditorObjectVersion; default true.
    let cast_shadow = if version_for(EDITOR_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= REFACTOR_MESH_EDITOR_MATERIALS)
    {
        read_bool32(r, asset_path, AssetWireField::SkelSectionCastShadow)?
    } else {
        true
    };

    // 8. bVisibleInRayTracing (bool32) — gated on FUE5MainStreamObjectVersion; default true.
    let visible_in_ray_tracing = if version_for(UE5_MAIN_STREAM_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED)
    {
        read_bool32(
            r,
            asset_path,
            AssetWireField::SkelSectionVisibleInRayTracing,
        )?
    } else {
        true
    };

    // 9. BaseVertexIndex u32 (unconditional).
    let base_vertex_index =
        read::read_u32(r, asset_path, AssetWireField::SkelSectionBaseVertexIndex)?;

    // 10. ClothMappingDataLODs — consumed, not stored. Each FMeshToMeshVertData
    //     is a constant 64 bytes (both FReleaseObjectVersion branches).
    if version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= ADD_CLOTH_MAPPING_LOD_BIAS)
    {
        // New shape: outer per-LOD-bias array of inner FMeshToMeshVertData[].
        let outer = read::read_capped_count(
            r,
            asset_path,
            AssetWireField::SkelSectionClothLodCount,
            MAX_CLOTH_LOD_BIAS_LEVELS_U32,
        )?;
        for _ in 0..outer {
            skip_capped_array(
                r,
                asset_path,
                AssetWireField::SkelSectionClothVertCount,
                MAX_CLOTH_VERTS_PER_LOD_U32,
                MESH_TO_MESH_VERT_DATA_BYTES,
            )?;
        }
    } else {
        // Legacy shape: a single FMeshToMeshVertData[] (no outer count).
        skip_capped_array(
            r,
            asset_path,
            AssetWireField::SkelSectionClothVertCount,
            MAX_CLOTH_VERTS_PER_LOD_U32,
            MESH_TO_MESH_VERT_DATA_BYTES,
        )?;
    }

    // 11. BoneMap: i32 count (capped) + N×u16.
    let bone_count = read::read_capped_count(
        r,
        asset_path,
        AssetWireField::SkelSectionBoneMapCount,
        MAX_BONE_MAP_ENTRIES_PER_SECTION_U32,
    )?;
    let mut bone_map = Vec::with_capacity(bone_count as usize);
    for _ in 0..bone_count {
        bone_map.push(read::read_u16(
            r,
            asset_path,
            AssetWireField::SkelSectionBoneMapCount,
        )?);
    }

    // 12. NumVertices i32 — sign-checked.
    let num_vertices = read::read_i32(r, asset_path, AssetWireField::SkelSectionNumVertices)?;
    if num_vertices < 0 {
        return Err(read::fault(
            asset_path,
            crate::error::AssetParseFault::SectionCountNegative {
                field: "NumVertices",
                count: num_vertices,
            },
        ));
    }

    // 13. MaxBoneInfluences i32 — sign-checked and capped.
    let max_bone_influences =
        read::read_i32(r, asset_path, AssetWireField::SkelSectionMaxBoneInfluences)?;
    if !(0..=MAX_INFLUENCES_PER_VERTEX_I32).contains(&max_bone_influences) {
        return Err(read::fault(
            asset_path,
            crate::error::AssetParseFault::SectionInfluenceCountInvalid {
                count: max_bone_influences,
                cap: MAX_INFLUENCES_PER_VERTEX,
            },
        ));
    }

    // 14. CorrespondClothAssetIndex i16.
    let correspond_cloth_asset_index =
        read::read_i16(r, asset_path, AssetWireField::SkelSectionCorrespondCloth)?;

    // 15. ClothingData = FGuid(16) + i32(4) = 20 bytes (consumed).
    skip_bytes(
        r,
        CLOTHING_SECTION_DATA_BYTES,
        asset_path,
        AssetWireField::SkelSectionClothingData,
    )?;

    // 16-17. DupVertData/DupVertIndexData — gated on
    //   `(!is_ue4_23_or_later()) || !is_class_data_stripped(class, DuplicatedVertices)`
    //   (read the dup arrays on pre-4.23 assets OR when the class did not strip
    //   duplicated-vertex data).
    if !ctx.version.is_ue4_23_or_later()
        || !is_class_data_stripped(class, STRIP_FLAG_DUPLICATED_VERTICES)
    {
        skip_capped_array(
            r,
            asset_path,
            AssetWireField::SkelSectionDupVertCount,
            MAX_DUP_VERTS_PER_SECTION_U32,
            DUP_VERT_DATA_ELEM_BYTES,
        )?;
        skip_capped_array(
            r,
            asset_path,
            AssetWireField::SkelSectionDupVertCount,
            MAX_DUP_VERTS_PER_SECTION_U32,
            DUP_VERT_INDEX_DATA_ELEM_BYTES,
        )?;
    }

    // 18. bDisabled (bool32) — gated on FReleaseObjectVersion; default false.
    let disabled = if version_for(RELEASE_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= ADD_SKELETAL_MESH_SECTION_DISABLE)
    {
        read_bool32(r, asset_path, AssetWireField::SkelSectionDisabled)?
    } else {
        false
    };

    Ok(SkelMeshSection {
        material_index,
        base_index,
        num_triangles,
        base_vertex_index,
        num_vertices,
        max_bone_influences,
        bone_map,
        recompute_tangent,
        recompute_tangents_vertex_mask_channel,
        cast_shadow,
        visible_in_ray_tracing,
        disabled,
        correspond_cloth_asset_index,
    })
}

/// Consume a capped `i32`-prefixed array of `elem_bytes`-sized elements,
/// skipping the body. The `i32` count is capped at `cap` (negative → `NegativeValue`,
/// over-cap → `BoundsExceeded { field }`) before any skip, so `count × elem_bytes`
/// cannot overflow `u64` (`count` is the capped `u32`, `elem_bytes` a small constant).
///
/// Used for both the inner cloth-mapping array (`cap = MAX_CLOTH_VERTS_PER_LOD_U32`,
/// `elem_bytes = MESH_TO_MESH_VERT_DATA_BYTES`) and the dup-vert arrays
/// (`cap = MAX_DUP_VERTS_PER_SECTION_U32`, `elem_bytes = 4` / `8`).
fn skip_capped_array<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
    field: AssetWireField,
    cap: u32,
    elem_bytes: u64,
) -> crate::Result<()> {
    let count = read::read_capped_count(r, asset_path, field, cap)?;
    let span = u64::from(count)
        .checked_mul(elem_bytes)
        .expect("count is a capped u32; count*elem_bytes fits u64");
    skip_bytes(r, span, asset_path, field)
}

/// Parse a `USkeletalMesh` export `payload` into [`Asset::SkeletalMesh`].
///
/// Segment 1 is the tagged-property stream ([`read_properties`]) plus the
/// `UObject::Serialize` object-GUID tail ([`read_object_guid_tail`]). Segment 2
/// (`USkeletalMesh.Deserialize`) then yields, in wire order:
///
/// 1. `FStripDataFlags` (`2 × u8`) — retained so the editor-data-stripped bit
///    (`GlobalStripFlags & 0x01`) can gate the `bCooked` branch below.
/// 2. `ImportedBounds` — native [`FBoxSphereBounds`] (UE4 28 bytes / UE5 LWC 56).
/// 3. `SkeletalMaterials` — `i32` count (capped at [`MAX_SKELETAL_MATERIALS`]) + N×`FSkeletalMaterial` ([`read_skeletal_material`]); each slot name is retained (an unnamed slot becomes the empty string).
/// 4. `FReferenceSkeleton` — bone hierarchy + bind pose ([`read_reference_skeleton`]).
/// 5. `bCooked` (`u32` bool) — **modern-cooked only** (see scoping below).
///
/// # Scope (PR2 of the 3h series)
///
/// Per the oracle (`USkeletalMesh.Deserialize` @ `cf74fc32`), the post-skeleton
/// layout forks on `FSkeletalMeshCustomVersion`:
///
/// - **Pre-`SplitModelAndRenderData` (legacy, `< 12`)** — the LODModels array
///   is read inline with NO `bCooked` field (a different `FStaticLODModel`
///   layout). PR2 does not support this: it returns
///   [`crate::PaksmithError::UnsupportedFeature`].
/// - **Modern (`>= SplitModelAndRenderData`)** — an optional editor `LODModels`
///   array precedes `bCooked`, gated on `!IsEditorDataStripped()`. PR2 only
///   handles the editor-data-stripped (cooked) case where that optional array
///   is absent; a non-cooked skeletal mesh (editor LOD data present) returns
///   [`crate::PaksmithError::UnsupportedFeature`]. The actual LOD parse lands
///   in a later PR of the 3h series.
///
/// Both `UnsupportedFeature` returns degrade to a generic property bag via the
/// package walker, exactly like any other typed-read failure.
///
/// The per-LOD skin geometry beyond `bCooked` is left unparsed in this PR
/// (`data.lods` stays empty). The second tuple element — the export's
/// [`FByteBulkData`] records — is always empty here (no out-of-line buffers are
/// resolved yet).
///
/// # Errors
/// [`crate::PaksmithError`] from the tagged-property parse, the object-GUID
/// tail, a short / corrupt segment-2 field, an over-cap `SkeletalMaterials`
/// count, a nested `FSkeletalMaterial` / `FReferenceSkeleton` fault, or
/// [`crate::PaksmithError::UnsupportedFeature`] for a legacy / non-cooked mesh
/// (see *Scope* above) — all of which the package walker degrades to a generic
/// property bag (see `Package::read_payloads`).
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let total_len = payload.len() as u64;
    let mut cur = Cursor::new(payload);

    // Segment 1: tagged-property stream + UObject object-GUID tail.
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;
    let _object_guid = read_object_guid_tail(&mut cur, total_len, asset_path)?;

    // Segment 2 (`USkeletalMesh.Deserialize`).
    let (strip_global, _strip_class) =
        read_strip_data_flags(&mut cur, asset_path, AssetWireField::SkeletalMeshStripFlags)?;
    let bounds_end = cur.position() + FBoxSphereBounds::wire_size(ctx);
    let bounds = FBoxSphereBounds::read_from(&mut cur, ctx, bounds_end, asset_path)?;

    let mat_count = read::read_capped_count(
        &mut cur,
        asset_path,
        AssetWireField::SkeletalMaterialCount,
        MAX_SKELETAL_MATERIALS,
    )?;
    let mut materials = Vec::with_capacity(mat_count as usize);
    for _ in 0..mat_count {
        materials.push(read_skeletal_material(&mut cur, ctx, asset_path)?.unwrap_or_default());
    }

    let skeleton = read_reference_skeleton(&mut cur, ctx, asset_path)?;

    // Post-skeleton fork on FSkeletalMeshCustomVersion (oracle
    // USkeletalMesh.Deserialize @ cf74fc32). PR2 supports modern-cooked only;
    // see the fn-level # Scope docs.
    let skel_mesh_version = ctx
        .custom_versions
        .version_for(SKELETAL_MESH_CUSTOM_VERSION_GUID)
        .unwrap_or(i32::MIN);
    if skel_mesh_version < SPLIT_MODEL_AND_RENDER_DATA {
        return Err(PaksmithError::UnsupportedFeature {
            context: "pre-SplitModelAndRenderData skeletal mesh (legacy FStaticLODModel layout) \
                      not yet supported"
                .into(),
        });
    }
    if !is_editor_data_stripped(strip_global) {
        return Err(PaksmithError::UnsupportedFeature {
            context: "non-cooked skeletal mesh with editor LOD data not supported".into(),
        });
    }
    let cooked = read_bool32(&mut cur, asset_path, AssetWireField::SkeletalMeshCooked)?;

    let mut data = SkeletalMeshData::empty();
    data.properties = PropertyBag::tree(properties);
    data.cooked = cooked;
    data.bounds = bounds;
    data.materials = materials;
    data.skeleton = skeleton;
    Ok((Asset::SkeletalMesh(data), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;

    /// Pin each `FSkelMeshSection` cap's literal value (the symbols are
    /// otherwise referenced only by the Task-6 reader, so a wrong-value mutant
    /// would survive without a value assertion).
    #[test]
    fn skel_mesh_section_caps() {
        assert_eq!(MAX_BONE_MAP_ENTRIES_PER_SECTION, 65_536); // = MAX_BONES_PER_SKELETON
        assert_eq!(MAX_BONE_MAP_ENTRIES_PER_SECTION, MAX_BONES_PER_SKELETON);
        assert_eq!(MAX_CLOTH_LOD_BIAS_LEVELS, 64);
        assert_eq!(MAX_CLOTH_VERTS_PER_LOD, 4_194_304); // 4 Mi
        assert_eq!(MAX_DUP_VERTS_PER_SECTION, 4_194_304); // 4 Mi
        assert_eq!(MAX_INFLUENCES_PER_VERTEX, 8);
        // Default RecomputeTangentsVertexMaskChannel (ESkinVertexColorChannel::None)
        // pinned as a literal so a `3 -> N` drift fails here, independent of the
        // gate-off tests (which compare against this same symbolic constant).
        assert_eq!(RECOMPUTE_TANGENTS_VERTEX_MASK_CHANNEL_NONE, 3);
    }

    /// Pin the `u32`/`i32` cap companions against the authoritative `usize`
    /// caps so a wrong-value drift in either side fails here.
    #[test]
    fn section_cap_u32_companions_match() {
        assert_eq!(
            MAX_BONE_MAP_ENTRIES_PER_SECTION_U32 as usize,
            MAX_BONE_MAP_ENTRIES_PER_SECTION
        );
        assert_eq!(
            MAX_CLOTH_LOD_BIAS_LEVELS_U32 as usize,
            MAX_CLOTH_LOD_BIAS_LEVELS
        );
        assert_eq!(
            MAX_CLOTH_VERTS_PER_LOD_U32 as usize,
            MAX_CLOTH_VERTS_PER_LOD
        );
        assert_eq!(
            MAX_DUP_VERTS_PER_SECTION_U32 as usize,
            MAX_DUP_VERTS_PER_SECTION
        );
        assert_eq!(
            MAX_INFLUENCES_PER_VERTEX_I32 as usize,
            MAX_INFLUENCES_PER_VERTEX
        );
    }

    use crate::asset::custom_version::{CustomVersion, CustomVersionContainer};
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::{FName, NameTable};
    use crate::asset::version::AssetVersion;
    use crate::error::AssetParseFault;
    use std::io::Cursor;
    use std::sync::Arc;

    /// Assemble a `CustomVersionContainer` stamping the five plugins the
    /// skeletal-mesh readers gate on, at the requested versions. Shared by
    /// [`skel_mat_ctx`] and [`skel_mat_ctx_ue5`] so the row list lives in one
    /// place. `skel_mesh` defaults callers to `SPLIT_MODEL_AND_RENDER_DATA` (the
    /// modern branch `read_typed` requires) unless they pin a legacy value.
    fn skel_custom_versions(
        editor: i32,
        core: i32,
        rendering: i32,
        fortnite: i32,
        skel_mesh: i32,
    ) -> CustomVersionContainer {
        // The four section-render gate plugins default to on-values (each at /
        // above the named position) so the material/read_typed callers — which
        // don't read them — get a fully-stamped container. The section-render
        // tests use `section_custom_versions` to pin individual positions.
        section_custom_versions(
            editor,
            core,
            rendering,
            fortnite,
            skel_mesh,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        )
    }

    /// Like [`skel_custom_versions`] but also stamps the four
    /// `FSkelMeshSection::SerializeRenderItem` gate plugins
    /// (`FRecomputeTangentCustomVersion`, `FUE5MainStreamObjectVersion`,
    /// `FUE5ReleaseStreamObjectVersion`, `FReleaseObjectVersion`) at the
    /// requested positions so the section-render gate tests can flip each on/off.
    #[allow(clippy::too_many_arguments, reason = "one arg per gated wire plugin")]
    fn section_custom_versions(
        editor: i32,
        core: i32,
        rendering: i32,
        fortnite: i32,
        skel_mesh: i32,
        recompute_tangent: i32,
        ue5_main: i32,
        ue5_release: i32,
        release: i32,
    ) -> CustomVersionContainer {
        CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: EDITOR_OBJECT_VERSION_GUID,
                    version: editor,
                },
                CustomVersion {
                    guid: CORE_OBJECT_VERSION_GUID,
                    version: core,
                },
                CustomVersion {
                    guid: RENDERING_OBJECT_VERSION_GUID,
                    version: rendering,
                },
                CustomVersion {
                    guid: FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID,
                    version: fortnite,
                },
                CustomVersion {
                    guid: SKELETAL_MESH_CUSTOM_VERSION_GUID,
                    version: skel_mesh,
                },
                CustomVersion {
                    guid: RECOMPUTE_TANGENT_CUSTOM_VERSION_GUID,
                    version: recompute_tangent,
                },
                CustomVersion {
                    guid: UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
                    version: ue5_main,
                },
                CustomVersion {
                    guid: UE5_RELEASE_STREAM_OBJECT_VERSION_GUID,
                    version: ue5_release,
                },
                CustomVersion {
                    guid: RELEASE_OBJECT_VERSION_GUID,
                    version: release,
                },
            ],
        }
    }

    /// Build an `AssetContext` for the `read_skel_mesh_section_render` tests with
    /// the four section gates at the requested positions and an explicit
    /// `(file_version_ue4, file_version_ue5)` so the dup-vert UE4.23 gate can be
    /// exercised on both sides (UE5 forces `is_ue4_23_or_later` true regardless
    /// of `file_version_ue4`, so the pre-4.23 case must pass `ue5 = None`).
    #[allow(clippy::too_many_arguments, reason = "one arg per gated wire plugin")]
    fn section_ctx(
        recompute_tangent: i32,
        editor: i32,
        ue5_main: i32,
        ue5_release: i32,
        release: i32,
        file_version_ue4: i32,
        file_version_ue5: Option<i32>,
    ) -> AssetContext {
        let custom_versions = section_custom_versions(
            editor,
            3,
            10,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            recompute_tangent,
            ue5_main,
            ue5_release,
            release,
        );
        AssetContext::new(
            Arc::new(NameTable::default()),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4,
                file_version_ue5,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Build an `AssetContext` whose `custom_versions` stamp the four
    /// `FSkeletalMaterial` gate plugins at the requested versions plus
    /// `FSkeletalMeshCustomVersion` at `SPLIT_MODEL_AND_RENDER_DATA` (the modern
    /// branch), with `names` populating the FName pool for the slot-name
    /// resolution. Per-material tests that don't touch `read_typed` ignore the
    /// skeletal-mesh stamp.
    fn skel_mat_ctx(
        names: &[&str],
        editor: i32,
        core: i32,
        rendering: i32,
        fortnite: i32,
    ) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = skel_custom_versions(
            editor,
            core,
            rendering,
            fortnite,
            SPLIT_MODEL_AND_RENDER_DATA,
        );
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Append an `FName` pair `(index, number=0)` (8 bytes).
    fn fname(buf: &mut Vec<u8>, index: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// 24-byte `FMeshUVChannelInfo`: bInitialized=0, bOverrideDensities=0,
    /// 4×f32 zero.
    fn mesh_uv_channel_info(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0i32.to_le_bytes()); // bInitialized
        buf.extend_from_slice(&0i32.to_le_bytes()); // bOverrideDensities
        buf.extend_from_slice(&[0u8; 16]); // 4 × f32
    }

    #[test]
    fn reads_skeletal_material_ue4_cooked() {
        // editor=8, core=3, rendering=10 → all three gates ON;
        // fortnite below 196 → no OverlayMaterial.
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        assert_eq!(bytes.len(), 40);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn reads_skeletal_material_ue5_with_overlay() {
        // fortnite=196 → OverlayMaterial FPackageIndex present (4 extra bytes).
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 196);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // OverlayMaterial FPackageIndex (4)
        assert_eq!(bytes.len(), 44);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn skeletal_material_gate_off_skips_uvchannel() {
        // rendering below 10 → no FMeshUVChannelInfo read. Pins the rendering
        // `>=` gate: only FPackageIndex + FName + bool32 = 16 bytes consumed.
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 9, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        assert_eq!(bytes.len(), 16);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), bytes.len() as u64);
    }

    #[test]
    fn skeletal_material_pre_refactor_returns_no_slot_name() {
        // editor<8, core<3, rendering<10, fortnite<196 → every gate OFF, so only
        // the Material FPackageIndex is on the wire. Pins the editor-`>=` and
        // core-`>=` gates (the only ones whose OFF branch the other tests don't
        // exercise) and the `None`-slot return.
        let ctx = skel_mat_ctx(&["Mat0"], 7, 2, 9, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name, None);
        assert_eq!(cur.position(), 4);
    }

    #[test]
    fn skeletal_material_fortnite_just_below_threshold_no_overlay() {
        // fortnite=195 is one below the >= 196 gate — pins `>= 196` against
        // a `> 196` mutant. No OverlayMaterial bytes on the wire; the reader
        // must consume exactly 40 bytes (same layout as the UE4-cooked test).
        let ctx = skel_mat_ctx(&["Mat0"], 8, 3, 10, 195);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0 (4)
        mesh_uv_channel_info(&mut bytes); // FMeshUVChannelInfo (24)
        assert_eq!(bytes.len(), 40);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(cur.position(), 40);
    }

    #[test]
    fn skeletal_material_serialize_imported_true_consumes_fname() {
        // bSerializeImportedMaterialSlotName = 1 → the ImportedMaterialSlotName
        // FName (8 bytes) IS on the wire and must be consumed. Pins the
        // `if serialize_imported` branch (the existing tests all use bool=0, so
        // the true arm would otherwise survive a `if true`/`if false` mutant).
        // editor=8/core=3 gates ON, rendering<10 so no UVChannelData, fortnite
        // below overlay → wire is FPackageIndex(4) + SlotName FName(8) +
        // bSerialize=1 (4) + ImportedSlotName FName(8) = 24 bytes.
        let ctx = skel_mat_ctx(&["Mat0", "Imported0"], 8, 3, 9, 100);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex (4)
        fname(&mut bytes, 0); // MaterialSlotName "Mat0" (8)
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bSerializeImported = 1 (4)
        fname(&mut bytes, 1); // ImportedMaterialSlotName "Imported0" (8)
        assert_eq!(bytes.len(), 24);

        let mut cur = Cursor::new(bytes.as_slice());
        let name = read_skeletal_material(&mut cur, &ctx, "T.uasset").expect("decode");
        assert_eq!(name.as_deref(), Some("Mat0"));
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "the ImportedMaterialSlotName FName must be consumed when the bool is true"
        );
    }

    #[test]
    fn reads_mesh_uv_channel_info_consumes_24_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInitialized = 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bOverrideDensities = 0
        bytes.extend_from_slice(&[0u8; 16]); // 4 × f32 = 0.0
        assert_eq!(bytes.len(), 24);

        let mut cur = Cursor::new(bytes.as_slice());
        read_mesh_uv_channel_info(&mut cur, "T.uasset").expect("decode");
        assert_eq!(cur.position(), 24);
    }

    #[test]
    fn rejects_non_strict_initialized_bool() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bInitialized = 2 → invalid
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::MeshUvChannelInfo,
                    observed: 2,
                },
                ..
            }
        ));
    }

    #[test]
    fn truncated_bool_region_is_io_eof() {
        // A cut inside the bool32 region propagates as PaksmithError::Io (the
        // documented read_bool32 EOF behavior), not AssetParseFault::UnexpectedEof.
        let bytes = 1i32.to_le_bytes(); // only bInitialized; bOverrideDensities truncated
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(
            matches!(err, PaksmithError::Io(_)),
            "expected Io, got {err:?}"
        );
    }

    #[test]
    fn truncated_mesh_uv_channel_info_is_eof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]); // only 2 of 4 floats

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_mesh_uv_channel_info(&mut cur, "T.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::MeshUvChannelInfo,
                },
                ..
            }
        ));
    }

    // ===== Task 7: read_typed hardening (cap / truncation / UE5 end-to-end) =====

    /// Build an `AssetContext` whose `custom_versions` stamp all four gate
    /// plugins at UE5-overlay levels (`fortnite >= 196`), with `file_version_ue5
    /// = Some(1004)` (LWC). Used by [`read_typed_ue5_overlay_end_to_end`].
    fn skel_mat_ctx_ue5(names: &[&str]) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = skel_custom_versions(8, 3, 10, 196, SPLIT_MODEL_AND_RENDER_DATA);
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -8,
                file_version_ue4: 522,
                file_version_ue5: Some(1004),
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Build the segment-1 + segment-2 prefix through `ImportedBounds` for the
    /// given `ctx`. Returns the bytes that every `read_typed` hardening test
    /// shares:
    ///
    /// ```text
    /// [segment-1]  write_object_end  (12 bytes: None-tag 8B + bSerializeGuid 4B)
    /// [seg-2]      FStripDataFlags   (2 bytes: global, class)
    /// [seg-2]      ImportedBounds    (28 bytes UE4 / 56 bytes UE5 LWC)
    /// ```
    ///
    /// The `GlobalStripFlags` byte sets bit 0 (`0x01`,
    /// [`crate::asset::wire::STRIP_FLAG_EDITOR_DATA`]) so the modern-cooked
    /// `read_typed` gate (`IsEditorDataStripped()`) takes the `bCooked` path —
    /// success-path tests reach the skeleton/`bCooked`, while the pre-gate
    /// error tests (cap / truncation) fault before the byte matters.
    ///
    /// Each test then appends its own perturbation immediately after.
    fn build_prefix_through_bounds(ctx: &AssetContext) -> Vec<u8> {
        let mut buf = Vec::new();
        // Segment 1: empty tagged-property stream + object-GUID tail.
        crate::asset::property::test_utils::write_object_end(&mut buf);
        // FStripDataFlags: global=0x01 (editor data stripped → cooked), class=0.
        buf.extend_from_slice(&[0x01u8, 0x00]);
        // ImportedBounds: all values 1.0 regardless of precision —
        // each test that parses successfully verifies these fields separately;
        // here they just need to be syntactically valid.
        let bounds_bytes = usize::try_from(FBoxSphereBounds::wire_size(ctx))
            .expect("bounds size fits usize on any supported target");
        if bounds_bytes == 28 {
            // UE4: 7 × f32.
            for _ in 0..7 {
                buf.extend_from_slice(&1.0f32.to_le_bytes());
            }
        } else {
            // UE5 LWC: 7 × f64.
            for _ in 0..7 {
                buf.extend_from_slice(&1.0f64.to_le_bytes());
            }
        }
        // write_object_end = 8 (None FName) + 4 (bSerializeGuid) = 12;
        // strip = 2; bounds = bounds_bytes.
        debug_assert_eq!(buf.len(), 12 + 2 + bounds_bytes);
        buf
    }

    /// Reject a `SkeletalMaterials` count of `MAX_SKELETAL_MATERIALS + 1`
    /// (`257`) before any allocation. Pins `BoundsExceeded { value: 257,
    /// limit: 256 }` — failing if the cap changes without updating this test.
    #[test]
    fn read_typed_materials_count_over_cap_is_rejected() {
        // UE4 ctx with no name pool needed (the cap fires before any FName read).
        let ctx = skel_mat_ctx(&[], 8, 3, 10, 100);
        let mut payload = build_prefix_through_bounds(&ctx);
        // Over-cap count — no material body bytes follow; the cap fires on the
        // i32 alone.
        let over_cap = (MAX_SKELETAL_MATERIALS + 1).cast_signed();
        payload.extend_from_slice(&over_cap.to_le_bytes());

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkeletalMaterialCount,
                        value: 257,
                        limit: 256,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(257 > 256) for SkeletalMaterialCount, got {err:?}"
        );
    }

    /// Truncated payloads surface as typed errors, never as panics.
    ///
    /// Four truncation points spanning the full segment-2 prefix:
    /// (a) inside `ImportedBounds` (first f32-vector region) — exercises the
    ///     `FBoxSphereBounds::read_from` EOF path.
    /// (b) strip flags complete, zero bounds bytes — immediate bounds EOF.
    /// (c) bounds complete, `SkeletalMaterials` count truncated — exercises the
    ///     `read_capped_count` EOF path (no mat count i32 bytes present).
    /// (d) bounds + mat_count complete, truncated mid-first-material — exercises
    ///     the `read_skeletal_material` EOF path (count says 1, zero body bytes).
    ///
    /// None must panic.
    #[test]
    fn read_typed_truncated_mid_prefix_is_typed_error() {
        let ctx = skel_mat_ctx(&[], 8, 3, 10, 100);

        // (a) segment-1 complete, strip bytes present, ImportedBounds truncated
        //     half-way through (14 of 28 bytes). The truncated f32-vector read
        //     surfaces as an AssetParse / Io error, not a panic.
        {
            let mut payload = Vec::new();
            crate::asset::property::test_utils::write_object_end(&mut payload);
            payload.extend_from_slice(&[0x00u8, 0x00]); // FStripDataFlags
            payload.extend_from_slice(&[0x00u8; 14]); // half of 28-byte UE4 bounds
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            // Any typed error is acceptable — no panic.
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-a must return typed error, got {err:?}"
            );
        }

        // (b) segment-1 complete, FStripDataFlags complete, zero bounds bytes.
        //     The very first byte of ImportedBounds is missing.
        {
            let mut payload = Vec::new();
            crate::asset::property::test_utils::write_object_end(&mut payload);
            payload.extend_from_slice(&[0x00u8, 0x00]); // FStripDataFlags only
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-b must return typed error, got {err:?}"
            );
        }

        // (c) bounds complete, SkeletalMaterials count field completely absent —
        //     exercises the read_capped_count EOF path.
        {
            let payload = build_prefix_through_bounds(&ctx);
            // payload ends right after bounds; no mat_count i32 present.
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-c must return typed error, got {err:?}"
            );
        }

        // (d) bounds + mat_count (i32=1) complete, zero material body bytes —
        //     exercises the read_skeletal_material EOF path (count says 1, but
        //     the first FPackageIndex i32 is absent).
        {
            let mut payload = build_prefix_through_bounds(&ctx);
            payload.extend_from_slice(&1i32.to_le_bytes()); // mat_count = 1
            // no FPackageIndex bytes follow
            let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-d must return typed error, got {err:?}"
            );
        }
    }

    /// Full `read_typed` end-to-end with a UE5 LWC context (`file_version_ue5 =
    /// Some(1004)`) and `FFortniteMainBranchObjectVersion >= 196` so each
    /// `FSkeletalMaterial` carries the `OverlayMaterial` `FPackageIndex`.
    ///
    /// Verifies that `read_typed` stays cursor-aligned through the LWC
    /// `FBoxSphereBounds` (56 B), the UE5 material variant (44 B per slot),
    /// the LWC `FReferenceSkeleton` (f64 `FTransform`s), and `bCooked`.
    #[test]
    fn read_typed_ue5_overlay_end_to_end() {
        // Name table: 0="None" (property-stream terminator), 1="Mat0"
        // (material slot name), 2="Root" (single bone).
        let ctx = skel_mat_ctx_ue5(&["None", "Mat0", "Root"]);

        // Segment 1 + FStripDataFlags + ImportedBounds (56B UE5 LWC) via shared helper.
        let mut payload = build_prefix_through_bounds(&ctx);

        // SkeletalMaterials: count = 1.
        payload.extend_from_slice(&1i32.to_le_bytes());
        // One FSkeletalMaterial (UE5 with OverlayMaterial, 44 bytes):
        //   Material FPackageIndex (4) + MaterialSlotName "Mat0" (8) +
        //   bSerializeImported=0 (4) + FMeshUVChannelInfo (24) +
        //   OverlayMaterial FPackageIndex (4) = 44 bytes.
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material = Null
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        mesh_uv_channel_info(&mut payload); // 24 bytes
        payload.extend_from_slice(&0i32.to_le_bytes()); // OverlayMaterial = Null

        // FReferenceSkeleton: 1 bone "Root", UE5 LWC (80-byte FTransform).
        // FinalRefBoneInfo: count 1 + (name FName, parent i32).
        payload.extend_from_slice(&1i32.to_le_bytes());
        fname(&mut payload, 2); // "Root"
        payload.extend_from_slice(&(-1i32).to_le_bytes()); // parent = root
        // FinalRefBonePose: count 1 + one 80-byte identity FTransform (f64).
        payload.extend_from_slice(&1i32.to_le_bytes());
        for v in [0.0f64, 0.0, 0.0, 1.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f64, 0.0, 0.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f64, 1.0, 1.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
        // FinalNameToIndexMap: count 1 + (key FName, value i32).
        payload.extend_from_slice(&1i32.to_le_bytes());
        fname(&mut payload, 2); // "Root"
        payload.extend_from_slice(&0i32.to_le_bytes()); // index 0

        // bCooked = true.
        payload.extend_from_slice(&1i32.to_le_bytes());

        let (asset, bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("UE5 parse");
        assert!(bulk.is_empty(), "no out-of-line bulk records");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(data.skeleton.bones.len(), 1);
        assert_eq!(data.skeleton.bones[0].name, "Root");
        assert_eq!(data.materials, vec!["Mat0".to_string()]);
        assert!(data.cooked, "bCooked must be true");
        assert!(data.lods.is_empty());
    }

    // ===== PR2 R1: bCooked gate (SplitModelAndRenderData + IsEditorDataStripped) =====

    /// Build an `AssetContext` like [`skel_mat_ctx`] but with an explicit
    /// `FSkeletalMeshCustomVersion` stamp, for the gate tests that pin the
    /// `SplitModelAndRenderData` fork. UE4 (`file_version_ue5 = None`) so the
    /// reused skeleton/material fixtures stay single-precision.
    fn skel_typed_ctx(names: &[&str], skel_mesh: i32) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = skel_custom_versions(8, 3, 10, 100, skel_mesh);
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518,
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// Build a full UE4-cooked `read_typed` payload through the
    /// `FReferenceSkeleton` (one material, two bones) with the given
    /// `GlobalStripFlags` byte. The `bCooked` byte is NOT appended — the gate
    /// tests fault before it, and the success path appends its own.
    fn build_payload_through_skeleton(strip_global: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        // Segment 1: empty tagged-property stream + object-GUID tail.
        crate::asset::property::test_utils::write_object_end(&mut payload);
        // FStripDataFlags: (global, class).
        payload.extend_from_slice(&[strip_global, 0x00]);
        // ImportedBounds (UE4 28B).
        for v in [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0] {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        // SkeletalMaterials: count 1 + one UE4-cooked FSkeletalMaterial (40B).
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        mesh_uv_channel_info(&mut payload);
        // FReferenceSkeleton (2 bones at FName 2/3).
        two_bone_reference_skeleton(&mut payload, 2, 3);
        payload
    }

    #[test]
    fn read_typed_pre_split_skeletal_mesh_is_unsupported() {
        // FSkeletalMeshCustomVersion one below SplitModelAndRenderData → the
        // legacy FStaticLODModel branch (no bCooked); PR2 returns
        // UnsupportedFeature. Strip byte sets editor-data-stripped so the ONLY
        // reason for the error is the version gate (pins the `< SPLIT` arm).
        let ctx = skel_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            SPLIT_MODEL_AND_RENDER_DATA - 1,
        );
        let payload = build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        match err {
            PaksmithError::UnsupportedFeature { context } => {
                assert!(
                    context.contains("pre-SplitModelAndRenderData"),
                    "wrong context: {context}"
                );
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn read_typed_split_boundary_is_supported() {
        // FSkeletalMeshCustomVersion EXACTLY SplitModelAndRenderData → modern
        // branch (pins `< SPLIT` against `<= SPLIT`). Editor data stripped +
        // bCooked appended → full success.
        let ctx = skel_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            SPLIT_MODEL_AND_RENDER_DATA,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("modern parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.cooked);
    }

    #[test]
    fn read_typed_editor_data_present_is_unsupported() {
        // Modern ctx (>= SplitModelAndRenderData) but GlobalStripFlags WITHOUT
        // bit 0 (editor data NOT stripped) → the editor-LODModels-before-bCooked
        // path, which PR2 does not support → UnsupportedFeature. Pins the
        // `!is_editor_data_stripped` gate (an editor-only / non-cooked mesh).
        let ctx = skel_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            SPLIT_MODEL_AND_RENDER_DATA,
        );
        // strip global = 0x00 → editor data present.
        let payload = build_payload_through_skeleton(0x00);
        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        match err {
            PaksmithError::UnsupportedFeature { context } => {
                assert!(context.contains("non-cooked"), "wrong context: {context}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    // ===== Task 5: read_typed end-to-end =====

    /// 40-byte identity `FTransform` (UE4 single-precision): Quat(0,0,0,1),
    /// Translation(0,0,0), Scale3D(1,1,1) — mirrors `skeleton.rs`'s worked
    /// example so the bind-pose decodes to the unit identity.
    fn identity_ftransform_ue4(buf: &mut Vec<u8>) {
        for v in [0.0f32, 0.0, 0.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f32, 0.0, 0.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f32, 1.0, 1.0] {
            buf.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
    }

    /// Append the PR1 2-bone `FReferenceSkeleton` worked example, with the bone
    /// names at FName indices `bone0_idx` / `bone1_idx` (shifted from the
    /// skeleton.rs example's 0/1 because the read_typed fixture forces
    /// `"None"` to index 0). 140 bytes.
    fn two_bone_reference_skeleton(buf: &mut Vec<u8>, bone0_idx: i32, bone1_idx: i32) {
        let start = buf.len();
        // FinalRefBoneInfo: count 2 + (name, parent) per bone.
        buf.extend_from_slice(&2i32.to_le_bytes());
        fname(buf, bone0_idx); // bone 0 name
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1 (root)
        fname(buf, bone1_idx); // bone 1 name
        buf.extend_from_slice(&0i32.to_le_bytes()); // parent 0
        // FinalRefBonePose: count 2 + two identity transforms (40 bytes each).
        buf.extend_from_slice(&2i32.to_le_bytes());
        identity_ftransform_ue4(buf);
        identity_ftransform_ue4(buf);
        // FinalNameToIndexMap: count 2 + (key, value) per bone.
        buf.extend_from_slice(&2i32.to_le_bytes());
        fname(buf, bone0_idx);
        buf.extend_from_slice(&0i32.to_le_bytes());
        fname(buf, bone1_idx);
        buf.extend_from_slice(&1i32.to_le_bytes());
        debug_assert_eq!(buf.len() - start, 140);
    }

    #[test]
    fn read_typed_parses_prefix_through_skeleton() {
        // Name table: 0="None" (the empty-property None terminator), 1="Mat0"
        // (material slot), 2="Root" / 3="Hip" (bones). UE4-cooked material gates
        // ON (editor=8/core=3/rendering=10), fortnite below the UE5 overlay
        // gate. ue5=None → FBoxSphereBounds=28B, FTransform=40B.
        let ctx = skel_mat_ctx(&["None", "Mat0", "Root", "Hip"], 8, 3, 10, 100);

        let mut payload = Vec::new();
        // Segment 1: empty tagged-property stream (None tag) + object-GUID tail.
        crate::asset::property::test_utils::write_object_end(&mut payload);
        // Segment 2 prefix. GlobalStripFlags=0x01 (editor data stripped →
        // modern-cooked path), class=0.
        payload.extend_from_slice(&[0x01, 0x00]); // FStripDataFlags (global, class)
        // ImportedBounds (UE4 FBoxSphereBounds, 28B): distinct non-zero
        // origin / box_extent / sphere_radius so the `data.bounds = bounds`
        // assignment is mutation-visible against the all-zero `empty()` default.
        for v in [1.0f32, 2.0, 3.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // origin x,y,z
        }
        for v in [4.0f32, 5.0, 6.0] {
            payload.extend_from_slice(&v.to_le_bytes()); // box_extent x,y,z
        }
        payload.extend_from_slice(&7.0f32.to_le_bytes()); // sphere_radius
        // SkeletalMaterials: count 1 + one UE4-cooked FSkeletalMaterial (40B):
        // Material FPackageIndex (4) + MaterialSlotName "Mat0" (8) +
        // bSerializeImported=0 (4) + FMeshUVChannelInfo (24).
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex = Null
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        mesh_uv_channel_info(&mut payload);
        // FReferenceSkeleton (2 bones at FName 2/3).
        two_bone_reference_skeleton(&mut payload, 2, 3);
        // bCooked = true.
        payload.extend_from_slice(&1i32.to_le_bytes());

        let (asset, bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("parse");
        assert!(bulk.is_empty(), "no out-of-line bulk records");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(data.skeleton.bones.len(), 2);
        assert_eq!(data.skeleton.bones[0].name, "Root");
        assert_eq!(data.skeleton.bones[1].name, "Hip");
        assert_eq!(data.materials, vec!["Mat0".to_string()]);
        // Bounds round-trip — distinct non-zero values pin the assignment
        // against an empty()-default (all-zero) mutant.
        assert!((data.bounds.origin.x - 1.0).abs() < f64::EPSILON);
        assert!((data.bounds.box_extent.z - 6.0).abs() < f64::EPSILON);
        assert!((data.bounds.sphere_radius - 7.0).abs() < f64::EPSILON);
        assert!(data.cooked);
        assert!(data.lods.is_empty());
    }

    // ===== Task 5 + 6: read_skel_mesh_section_render (cooked SerializeRenderItem) =====

    /// Append the unconditional + always-on prefix fields of a cooked
    /// `FSkelMeshSection` through `BaseVertexIndex`, given the class strip byte
    /// and whether each gated field is present. All gates are assumed ON here
    /// (the tests below either keep them on or pin one off via a tailored ctx).
    #[allow(clippy::too_many_arguments, reason = "one arg per wire field")]
    fn push_section_prefix(
        buf: &mut Vec<u8>,
        class_strip: u8,
        material_index: i16,
        base_index: i32,
        num_triangles: i32,
        recompute_tangent: bool,
        mask_channel: u8,
        cast_shadow: bool,
        visible_in_ray_tracing: bool,
        base_vertex_index: u32,
    ) {
        // 1. FStripDataFlags: global=0x00, class=class_strip.
        buf.extend_from_slice(&[0x00, class_strip]);
        // 2-4.
        buf.extend_from_slice(&material_index.to_le_bytes());
        buf.extend_from_slice(&base_index.to_le_bytes());
        buf.extend_from_slice(&num_triangles.to_le_bytes());
        // 5. bRecomputeTangent (bool32, unconditional).
        buf.extend_from_slice(&i32::from(recompute_tangent).to_le_bytes());
        // 6. RecomputeTangentsVertexMaskChannel u8 (gate ON).
        buf.push(mask_channel);
        // 7. bCastShadow (bool32, gate ON).
        buf.extend_from_slice(&i32::from(cast_shadow).to_le_bytes());
        // 8. bVisibleInRayTracing (bool32, gate ON).
        buf.extend_from_slice(&i32::from(visible_in_ray_tracing).to_le_bytes());
        // 9. BaseVertexIndex u32 (unconditional).
        buf.extend_from_slice(&base_vertex_index.to_le_bytes());
    }

    /// Append one cloth-mapping inner array: an `i32` vert count + count×64
    /// bytes of `FMeshToMeshVertData`.
    fn push_cloth_inner(buf: &mut Vec<u8>, vert_count: i32) {
        buf.extend_from_slice(&vert_count.to_le_bytes());
        for _ in 0..vert_count {
            buf.extend_from_slice(&[0u8; 64]);
        }
    }

    /// Append `BoneMap` (i32 count + count×u16) through `ClothingData` (the
    /// 18-field suffix minus the version-gated `bDisabled`). `bone_map` values
    /// are written so the round-trip is mutation-visible.
    fn push_section_suffix(
        buf: &mut Vec<u8>,
        bone_map: &[u16],
        num_vertices: i32,
        max_bone_influences: i32,
        correspond_cloth_asset_index: i16,
    ) {
        // 11. BoneMap.
        buf.extend_from_slice(&i32::try_from(bone_map.len()).unwrap().to_le_bytes());
        for &b in bone_map {
            buf.extend_from_slice(&b.to_le_bytes());
        }
        // 12. NumVertices i32. 13. MaxBoneInfluences i32.
        buf.extend_from_slice(&num_vertices.to_le_bytes());
        buf.extend_from_slice(&max_bone_influences.to_le_bytes());
        // 14. CorrespondClothAssetIndex i16.
        buf.extend_from_slice(&correspond_cloth_asset_index.to_le_bytes());
        // 15. ClothingData = FGuid(16) + i32(4) = 20 bytes.
        buf.extend_from_slice(&[0u8; 20]);
    }

    #[test]
    fn read_skel_mesh_section_render_modern_cooked() {
        // All gates ON; class strip byte sets DuplicatedVertices (0x01) and
        // file_version_ue4 >= 517 → dup-vert gate `(!is_ue4_23) || (!stripped)`
        // is `false || false` = false → dup arrays SKIPPED (absent on wire).
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        );
        let mut bytes = Vec::new();
        push_section_prefix(&mut bytes, 0x01, 7, 12, 34, true, 1, false, false, 99);
        // 10. ClothMappingDataLODs (new shape): outer m=1, inner n=1 (64 bytes).
        bytes.extend_from_slice(&1i32.to_le_bytes()); // outer count
        push_cloth_inner(&mut bytes, 1);
        push_section_suffix(&mut bytes, &[5, 6], 100, 4, -1);
        // 18. bDisabled (bool32, gate ON).
        bytes.extend_from_slice(&1i32.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").expect("decode");
        assert_eq!(s.material_index, 7);
        assert_eq!(s.base_index, 12);
        assert_eq!(s.num_triangles, 34);
        assert!(s.recompute_tangent);
        assert_eq!(s.recompute_tangents_vertex_mask_channel, 1);
        assert!(!s.cast_shadow);
        assert!(!s.visible_in_ray_tracing);
        assert_eq!(s.base_vertex_index, 99);
        assert_eq!(s.bone_map, vec![5u16, 6]);
        assert_eq!(s.num_vertices, 100);
        assert_eq!(s.max_bone_influences, 4);
        assert_eq!(s.correspond_cloth_asset_index, -1);
        assert!(s.disabled);
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "the cooked section reader must consume the full payload"
        );
    }

    #[test]
    fn read_skel_mesh_section_render_legacy_cloth_single_array() {
        // FUE5ReleaseStream < AddClothMappingLODBias(15) → cloth is ONE inner
        // array (no outer count). Class-stripped + ue4>=517 → dup arrays absent.
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1, // off → legacy single array
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        );
        let mut bytes = Vec::new();
        push_section_prefix(&mut bytes, 0x01, 0, 0, 0, false, 3, true, true, 0);
        // 10. Single inner cloth array (n=2 → 128 bytes), NO outer count.
        push_cloth_inner(&mut bytes, 2);
        push_section_suffix(&mut bytes, &[], 0, 0, 0);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bDisabled = false

        let mut cur = Cursor::new(bytes.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").expect("decode");
        assert!(s.bone_map.is_empty());
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "legacy single-array cloth path must consume exactly the inner array"
        );
    }

    #[test]
    fn read_skel_mesh_section_render_reads_dupvert_when_not_class_stripped() {
        // class byte = 0x00 (DuplicatedVertices NOT stripped) → gate
        // `(!is_ue4_23) || (!stripped)` = `false || true` = true → dup arrays
        // present and consumed.
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        );
        let mut bytes = Vec::new();
        push_section_prefix(&mut bytes, 0x00, 0, 0, 0, false, 3, true, true, 0);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // cloth outer count = 0
        push_section_suffix(&mut bytes, &[], 0, 0, 0);
        // 16. DupVertData: count=3 + 3×4 = 12 bytes.
        bytes.extend_from_slice(&3i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 12]);
        // 17. DupVertIndexData: count=2 + 2×8 = 16 bytes.
        bytes.extend_from_slice(&2i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bDisabled = false

        let mut cur = Cursor::new(bytes.as_slice());
        let _section =
            read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").expect("decode");
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "dup-vert arrays must be read+skipped when not class-stripped"
        );
    }

    #[test]
    fn read_skel_mesh_section_render_reads_dupvert_when_pre_ue423() {
        // file_version_ue4 < 517 + ue5=None → is_ue4_23_or_later() false, so even
        // with the class byte stripped (0x01) the gate `(!is_ue4_23) || ...` =
        // `true || ...` = true → dup arrays present and consumed.
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            516, // pre-UE4.23
            None,
        );
        let mut bytes = Vec::new();
        push_section_prefix(&mut bytes, 0x01, 0, 0, 0, false, 3, true, true, 0);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // cloth outer count = 0
        push_section_suffix(&mut bytes, &[], 0, 0, 0);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // DupVertData count = 0
        bytes.extend_from_slice(&0i32.to_le_bytes()); // DupVertIndexData count = 0
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bDisabled = false

        let mut cur = Cursor::new(bytes.as_slice());
        let _section =
            read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").expect("decode");
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "dup-vert arrays must be read even when class-stripped on a pre-UE4.23 asset"
        );
    }

    // ===== Task 7: gate-default + sign-check + cap + truncation hardening =====

    /// Append the cooked-section bytes through `BaseVertexIndex` (fields 1-9)
    /// with each version-gated prefix field present only when its `Some(_)` is
    /// supplied — so the OFF side of a gate omits exactly that field's bytes.
    ///
    /// `mask` (field 6, recompute gate), `cast_shadow` (field 7, editor gate),
    /// and `visible` (field 8, ue5_main gate) are independently controllable;
    /// `bRecomputeTangent` (field 5) is unconditional and always written.
    fn push_section_prefix_gated(
        buf: &mut Vec<u8>,
        class_strip: u8,
        recompute_tangent: bool,
        mask: Option<u8>,
        cast_shadow: Option<bool>,
        visible: Option<bool>,
    ) {
        // 1. FStripDataFlags: global=0x00, class=class_strip.
        buf.extend_from_slice(&[0x00, class_strip]);
        // 2-4. MaterialIndex i16, BaseIndex i32, NumTriangles i32.
        buf.extend_from_slice(&0i16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        // 5. bRecomputeTangent bool32 (unconditional, always present).
        buf.extend_from_slice(&i32::from(recompute_tangent).to_le_bytes());
        // 6. mask u8 — only when the recompute gate is ON.
        if let Some(m) = mask {
            buf.push(m);
        }
        // 7. bCastShadow bool32 — only when the editor gate is ON.
        if let Some(c) = cast_shadow {
            buf.extend_from_slice(&i32::from(c).to_le_bytes());
        }
        // 8. bVisibleInRayTracing bool32 — only when the ue5_main gate is ON.
        if let Some(v) = visible {
            buf.extend_from_slice(&i32::from(v).to_le_bytes());
        }
        // 9. BaseVertexIndex u32 (unconditional).
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    /// Section context with all class-strip + UE4-version state fixed so the
    /// cloth path is the legacy single-array (ue5_release OFF) and the dup-vert
    /// arrays are absent (class-stripped + ue4 >= 517). Only the five
    /// bool/u8 gate positions vary, via the args.
    #[allow(clippy::too_many_arguments, reason = "one arg per gated wire plugin")]
    fn gate_ctx(
        recompute: i32,
        editor: i32,
        ue5_main: i32,
        ue5_release: i32,
        release: i32,
    ) -> AssetContext {
        section_ctx(recompute, editor, ue5_main, ue5_release, release, 518, None)
    }

    /// All five bool/u8 gates OFF → every gated field is absent on the wire and
    /// the reader must fall back to its compiled defaults: mask channel 3,
    /// cast_shadow true, visible_in_ray_tracing true, disabled false. The
    /// payload omits those fields entirely, so a full-consumption assert pins
    /// that NO bytes were read for them (kills "read-then-discard" mutants) and
    /// the value asserts pin the defaults (kill `3->0`, `true->false`,
    /// `false->true` else-branch mutants).
    #[test]
    fn read_skel_mesh_section_render_all_gates_off_uses_defaults() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK - 1, // recompute OFF
            REFACTOR_MESH_EDITOR_MATERIALS - 1,      // editor OFF (cast_shadow)
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED - 1, // ue5_main OFF (visible)
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,          // ue5_release OFF (legacy cloth)
            ADD_SKELETAL_MESH_SECTION_DISABLE - 1,   // release OFF (disabled)
        );
        let mut bytes = Vec::new();
        // Fields 1-9: class byte strips DuplicatedVertices (dup absent), all
        // three gated prefix fields OMITTED.
        push_section_prefix_gated(&mut bytes, 0x01, true, None, None, None);
        // 10. Legacy single inner cloth array, empty (i32 count = 0).
        bytes.extend_from_slice(&0i32.to_le_bytes());
        // 11-15. BoneMap empty + NumVertices/MaxBoneInfluences/Correspond/Clothing.
        push_section_suffix(&mut bytes, &[], 0, 0, 0);
        // 16-17. dup-vert absent (class-stripped + ue4 >= 517).
        // 18. bDisabled OMITTED (release gate OFF).

        let mut cur = Cursor::new(bytes.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").expect("decode");
        assert_eq!(
            s.recompute_tangents_vertex_mask_channel, RECOMPUTE_TANGENTS_VERTEX_MASK_CHANNEL_NONE,
            "mask must default to 3 when the recompute gate is off"
        );
        assert!(
            s.cast_shadow,
            "cast_shadow must default to true when editor gate off"
        );
        assert!(
            s.visible_in_ray_tracing,
            "visible_in_ray_tracing must default to true when ue5_main gate off"
        );
        assert!(
            !s.disabled,
            "disabled must default to false when release gate off"
        );
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "no bytes may be consumed for the absent gated fields"
        );
    }

    /// Boundary pair for the `RecomputeTangentVertexColorMask` gate: version 1
    /// (OFF, mask absent, default 3) vs the EXACT position 2 (ON, mask u8 read).
    /// Pins `>= POS` against `> POS`: the ON case uses the boundary value, and
    /// the two payloads differ by exactly one byte (the mask u8).
    #[test]
    fn read_skel_mesh_section_render_recompute_gate_boundary() {
        // OFF: recompute = POS - 1. mask absent.
        let ctx_off = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK - 1,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut off = Vec::new();
        push_section_prefix_gated(&mut off, 0x01, false, None, Some(true), Some(true));
        off.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
        push_section_suffix(&mut off, &[], 0, 0, 0);
        off.extend_from_slice(&1i32.to_le_bytes()); // bDisabled (release ON)
        let mut cur = Cursor::new(off.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_off, "Mesh.uasset").expect("off");
        assert_eq!(
            s.recompute_tangents_vertex_mask_channel,
            RECOMPUTE_TANGENTS_VERTEX_MASK_CHANNEL_NONE
        );
        assert_eq!(cur.position(), off.len() as u64);

        // ON: recompute = EXACT POS. mask u8 present (distinct value 2).
        let ctx_on = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut on = Vec::new();
        push_section_prefix_gated(&mut on, 0x01, false, Some(2), Some(true), Some(true));
        on.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut on, &[], 0, 0, 0);
        on.extend_from_slice(&1i32.to_le_bytes());
        let mut cur = Cursor::new(on.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_on, "Mesh.uasset").expect("on");
        assert_eq!(
            s.recompute_tangents_vertex_mask_channel, 2,
            "mask must be read at POS"
        );
        assert_eq!(cur.position(), on.len() as u64);
        assert_eq!(
            on.len(),
            off.len() + 1,
            "ON consumes exactly one extra byte (mask u8)"
        );
    }

    /// Boundary pair for the `RefactorMeshEditorMaterials` gate (bCastShadow):
    /// editor 7 (OFF, default true) vs EXACT 8 (ON, bool32 read = false).
    #[test]
    fn read_skel_mesh_section_render_cast_shadow_gate_boundary() {
        let mut off = Vec::new();
        let ctx_off = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS - 1,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        push_section_prefix_gated(&mut off, 0x01, false, Some(3), None, Some(true));
        off.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut off, &[], 0, 0, 0);
        off.extend_from_slice(&1i32.to_le_bytes());
        let mut cur = Cursor::new(off.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_off, "Mesh.uasset").expect("off");
        assert!(s.cast_shadow, "default true when editor < 8");
        assert_eq!(cur.position(), off.len() as u64);

        let mut on = Vec::new();
        let ctx_on = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        push_section_prefix_gated(&mut on, 0x01, false, Some(3), Some(false), Some(true));
        on.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut on, &[], 0, 0, 0);
        on.extend_from_slice(&1i32.to_le_bytes());
        let mut cur = Cursor::new(on.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_on, "Mesh.uasset").expect("on");
        assert!(!s.cast_shadow, "bool32 read (false) at POS 8");
        assert_eq!(cur.position(), on.len() as u64);
        assert_eq!(
            on.len(),
            off.len() + 4,
            "ON consumes one extra bool32 (4 bytes)"
        );
    }

    /// Boundary pair for `SkelMeshSectionVisibleInRayTracingFlagAdded`
    /// (bVisibleInRayTracing): ue5_main 53 (OFF, below the gate, default true) vs
    /// EXACT 54 (ON, at the gate, bool32 read = false). Pins the `>= 54` position
    /// against a `>=`->`>` or wrong-position mutant.
    #[test]
    fn read_skel_mesh_section_render_visible_gate_boundary() {
        let mut off = Vec::new();
        let ctx_off = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED - 1,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        push_section_prefix_gated(&mut off, 0x01, false, Some(3), Some(true), None);
        off.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut off, &[], 0, 0, 0);
        off.extend_from_slice(&1i32.to_le_bytes());
        let mut cur = Cursor::new(off.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_off, "Mesh.uasset").expect("off");
        assert!(s.visible_in_ray_tracing, "default true when ue5_main < 54");
        assert_eq!(cur.position(), off.len() as u64);

        let mut on = Vec::new();
        let ctx_on = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        push_section_prefix_gated(&mut on, 0x01, false, Some(3), Some(true), Some(false));
        on.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut on, &[], 0, 0, 0);
        on.extend_from_slice(&1i32.to_le_bytes());
        let mut cur = Cursor::new(on.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_on, "Mesh.uasset").expect("on");
        assert!(!s.visible_in_ray_tracing, "bool32 read (false) at POS 54");
        assert_eq!(cur.position(), on.len() as u64);
        assert_eq!(
            on.len(),
            off.len() + 4,
            "ON consumes one extra bool32 (4 bytes)"
        );
    }

    /// Boundary pair for `AddSkeletalMeshSectionDisable` (bDisabled): release 11
    /// (OFF, default false, byte absent) vs EXACT 12 (ON, bool32 read = true).
    #[test]
    fn read_skel_mesh_section_render_disabled_gate_boundary() {
        let mut off = Vec::new();
        let ctx_off = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE - 1,
        );
        push_section_prefix_gated(&mut off, 0x01, false, Some(3), Some(true), Some(true));
        off.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut off, &[], 0, 0, 0);
        // bDisabled OMITTED (release gate OFF).
        let mut cur = Cursor::new(off.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_off, "Mesh.uasset").expect("off");
        assert!(!s.disabled, "default false when release < 12");
        assert_eq!(cur.position(), off.len() as u64);

        let mut on = Vec::new();
        let ctx_on = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        push_section_prefix_gated(&mut on, 0x01, false, Some(3), Some(true), Some(true));
        on.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(&mut on, &[], 0, 0, 0);
        on.extend_from_slice(&1i32.to_le_bytes()); // bDisabled = true (ON)
        let mut cur = Cursor::new(on.as_slice());
        let s = read_skel_mesh_section_render(&mut cur, &ctx_on, "Mesh.uasset").expect("on");
        assert!(s.disabled, "bool32 read (true) at POS 12");
        assert_eq!(cur.position(), on.len() as u64);
        assert_eq!(
            on.len(),
            off.len() + 4,
            "ON consumes one extra bool32 (4 bytes)"
        );
    }

    /// Boundary pair for `AddClothMappingLODBias` (cloth wire shape): ue5_release
    /// 14 (OFF → single inner array, NO outer count) vs EXACT 15 (ON →
    /// array-of-arrays with an outer count). Both encode one inner cloth array
    /// of one 64-byte element; the ON payload carries one extra i32 (the outer
    /// count), pinning `>= POS` against `> POS` and the cloth-shape fork.
    #[test]
    fn read_skel_mesh_section_render_cloth_shape_gate_boundary() {
        // OFF: legacy single inner array (count=1 → 4 + 64 bytes), no outer count.
        let ctx_off = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut off = Vec::new();
        push_section_prefix_gated(&mut off, 0x01, false, Some(3), Some(true), Some(true));
        push_cloth_inner(&mut off, 1); // single inner array, 1 element
        push_section_suffix(&mut off, &[], 0, 0, 0);
        off.extend_from_slice(&1i32.to_le_bytes()); // bDisabled
        let mut cur = Cursor::new(off.as_slice());
        let _ = read_skel_mesh_section_render(&mut cur, &ctx_off, "Mesh.uasset").expect("off");
        assert_eq!(
            cur.position(),
            off.len() as u64,
            "legacy single-array cloth consumes exactly the inner array (no outer count)"
        );

        // ON: array-of-arrays — outer count = 1, then one inner array.
        let ctx_on = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut on = Vec::new();
        push_section_prefix_gated(&mut on, 0x01, false, Some(3), Some(true), Some(true));
        on.extend_from_slice(&1i32.to_le_bytes()); // outer count = 1
        push_cloth_inner(&mut on, 1); // one inner array, 1 element
        push_section_suffix(&mut on, &[], 0, 0, 0);
        on.extend_from_slice(&1i32.to_le_bytes()); // bDisabled
        let mut cur = Cursor::new(on.as_slice());
        let _ = read_skel_mesh_section_render(&mut cur, &ctx_on, "Mesh.uasset").expect("on");
        assert_eq!(
            cur.position(),
            on.len() as u64,
            "new-shape cloth consumes the outer count + inner array"
        );
        assert_eq!(
            on.len(),
            off.len() + 4,
            "the new shape carries exactly one extra i32 (the outer LOD-bias count)"
        );
    }

    /// `NumVertices = -1` → `SectionCountNegative { field: "NumVertices", .. }`
    /// before any consumer treats it as a length.
    #[test]
    fn read_skel_mesh_section_render_negative_num_vertices_is_rejected() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut bytes = Vec::new();
        push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
        bytes.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
        // BoneMap empty + NumVertices = -1 (the perturbation) + valid tail.
        bytes.extend_from_slice(&0i32.to_le_bytes()); // BoneMap count = 0
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // NumVertices = -1
        // (reader faults here; remaining bytes never reached)

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::SectionCountNegative {
                        field: "NumVertices",
                        count: -1,
                    },
                    ..
                }
            ),
            "expected SectionCountNegative(NumVertices, -1), got {err:?}"
        );
    }

    /// `MaxBoneInfluences = -1` folds into the influence range-check
    /// (`!(0..=8).contains`), so it surfaces as `SectionInfluenceCountInvalid`,
    /// NOT `SectionCountNegative` — there is no separate negative path for it.
    #[test]
    fn read_skel_mesh_section_render_negative_max_bone_influences_is_influence_fault() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut bytes = Vec::new();
        push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
        bytes.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
        bytes.extend_from_slice(&0i32.to_le_bytes()); // BoneMap count = 0
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumVertices = 0 (valid)
        bytes.extend_from_slice(&(-1i32).to_le_bytes()); // MaxBoneInfluences = -1

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::SectionInfluenceCountInvalid { count: -1, cap: 8 },
                    ..
                }
            ),
            "expected SectionInfluenceCountInvalid(-1, 8), got {err:?}"
        );
    }

    /// `MaxBoneInfluences = 9` (> the 8-slot cap) → `SectionInfluenceCountInvalid`.
    #[test]
    fn read_skel_mesh_section_render_over_cap_max_bone_influences_is_rejected() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut bytes = Vec::new();
        push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
        bytes.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
        bytes.extend_from_slice(&0i32.to_le_bytes()); // BoneMap count = 0
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumVertices = 0
        bytes.extend_from_slice(&9i32.to_le_bytes()); // MaxBoneInfluences = 9 (> 8)

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::SectionInfluenceCountInvalid { count: 9, cap: 8 },
                    ..
                }
            ),
            "expected SectionInfluenceCountInvalid(9, 8), got {err:?}"
        );
    }

    /// An over-cap `BoneMap` count (`MAX_BONE_MAP_ENTRIES_PER_SECTION + 1`) is
    /// rejected by `read_capped_count` BEFORE any allocation, as
    /// `BoundsExceeded { field: SkelSectionBoneMapCount, .. }`.
    #[test]
    fn read_skel_mesh_section_render_over_cap_bone_map_is_rejected() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut bytes = Vec::new();
        push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
        bytes.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
        // BoneMap count = cap + 1 — the cap fires on the i32 alone (no body bytes).
        let over_cap = i32::try_from(MAX_BONE_MAP_ENTRIES_PER_SECTION + 1).unwrap();
        bytes.extend_from_slice(&over_cap.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelSectionBoneMapCount,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelSectionBoneMapCount), got {err:?}"
        );
    }

    /// An over-cap cloth INNER vertex count (`MAX_CLOTH_VERTS_PER_LOD + 1`) is
    /// rejected BEFORE the 64-byte-per-element skip, as
    /// `BoundsExceeded { field: SkelSectionClothVertCount, .. }`. Uses the
    /// legacy single-array shape so the inner count is the first cloth i32.
    #[test]
    fn read_skel_mesh_section_render_over_cap_cloth_inner_is_rejected() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1, // legacy single inner array
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let mut bytes = Vec::new();
        push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
        // Cloth inner count = cap + 1 — fires before any 64-byte element skip.
        let over_cap = i32::try_from(MAX_CLOTH_VERTS_PER_LOD + 1).unwrap();
        bytes.extend_from_slice(&over_cap.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelSectionClothVertCount,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelSectionClothVertCount), got {err:?}"
        );
    }

    /// A section payload cut mid-stream surfaces as a typed `Err`
    /// (`AssetParse`/`Io`), never a panic. Two cut points: (a) right after
    /// `BaseVertexIndex` (cloth count truncated); (b) after `BoneMap` count but
    /// before `NumVertices`.
    #[test]
    fn read_skel_mesh_section_render_truncated_is_typed_error() {
        let ctx = gate_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );

        // (a) Valid through BaseVertexIndex, then EOF (cloth count absent).
        {
            let mut bytes = Vec::new();
            push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
            let mut cur = Cursor::new(bytes.as_slice());
            let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-a must return typed error, got {err:?}"
            );
        }

        // (b) Valid through BoneMap count (=0), then EOF (NumVertices absent).
        {
            let mut bytes = Vec::new();
            push_section_prefix_gated(&mut bytes, 0x01, false, Some(3), Some(true), Some(true));
            bytes.extend_from_slice(&0i32.to_le_bytes()); // legacy cloth empty
            bytes.extend_from_slice(&0i32.to_le_bytes()); // BoneMap count = 0
            // NumVertices i32 absent → EOF.
            let mut cur = Cursor::new(bytes.as_slice());
            let err = read_skel_mesh_section_render(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-b must return typed error, got {err:?}"
            );
        }
    }
}
