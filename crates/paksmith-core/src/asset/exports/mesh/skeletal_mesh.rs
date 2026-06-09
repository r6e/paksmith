//! `USkeletalMesh` export parsing (Phase 3h). Wire reference:
//! `docs/formats/mesh/skeletal-mesh.md`.
//!
//! PR2 ships the segment-2 prefix reader ([`read_typed`]) — tagged properties,
//! object-GUID tail, strip flags, `ImportedBounds`, `SkeletalMaterials`, the
//! `FReferenceSkeleton`, and the `bCooked` bool (modern-cooked only) — wired
//! into the class dispatch. Legacy (pre-`SplitModelAndRenderData`) and
//! non-cooked (editor LOD data present) meshes return `UnsupportedFeature` and
//! degrade to a generic property bag.
//!
//! PR4 wires the cooked `FStaticLODModel` LOD header
//! ([`read_static_lod_model`]) into [`read_typed`]: gated on the UE4.24
//! new-cooked-format boundary, it reads the `LODModels` count and parses each
//! LOD's sections + required / active bones (everything before the streamed
//! blob). PR5a parses each inlined LOD's streamed blob in place; PR5b iterates
//! ALL inlined LODs (seeking `blob_start + BuffersSize` between them), consumes
//! the post-loop tail, and validates a cursor-landing sentinel.

use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::custom_version::{
    ADD_CLOTH_MAPPING_LOD_BIAS, ADD_SKELETAL_MESH_SECTION_DISABLE, ANIM_OBJECT_VERSION_GUID,
    COMPACT_CLOTH_VERTEX_BUFFER, CORE_OBJECT_VERSION_GUID, EDITOR_OBJECT_VERSION_GUID,
    FORTNITE_MAIN_BRANCH_OBJECT_VERSION_GUID, INCREASED_SKIN_WEIGHT_PRECISION,
    MATERIAL_SHADER_MAP_ID_SERIALIZATION, MESH_MATERIAL_SLOT_OVERLAY_MATERIAL_ADDED,
    RECOMPUTE_TANGENT_CUSTOM_VERSION_GUID, RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
    REFACTOR_MESH_EDITOR_MATERIALS, RELEASE_OBJECT_VERSION_GUID, REMOVING_TESSELLATION,
    RENDERING_OBJECT_VERSION_GUID, SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
    SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING, SKELETAL_MESH_CUSTOM_VERSION_GUID,
    SPLIT_MODEL_AND_RENDER_DATA, TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA,
    UE5_MAIN_STREAM_OBJECT_VERSION_GUID, UE5_RELEASE_STREAM_OBJECT_VERSION_GUID,
    UNLIMITED_BONE_INFLUENCES,
};
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::{
    Property, PropertyValue, read_fname_pair, read_object_guid_tail, read_properties,
};
use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::wire::{
    STRIP_FLAG_ADJACENCY_DATA, STRIP_FLAG_DUPLICATED_VERTICES, is_av_data_stripped,
    is_class_data_stripped, is_editor_data_stripped, read_bool32, read_strip_data_flags,
};
use crate::asset::{
    Asset, AssetContext, SkelMeshSection, SkeletalMeshData, SkeletalMeshLod, read_package_index,
};
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

use super::index_buffer;
use super::read;
use super::skeleton::{MAX_BONES_PER_SKELETON, read_reference_skeleton};
use super::skin_weights;
use super::vertex_buffers::{
    read_color_buffer, read_position_buffer, read_static_mesh_vertex_buffer,
};

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

/// Max `FStaticLODModel` records per `USkeletalMesh` (`LODModels` count). Stock
/// meshes ship a handful of LODs; this is a generous ceiling on the count prefix.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention ([`MAX_BONE_MAP_ENTRIES_PER_SECTION`]), the cap is pinned
/// via a value test (now) + an over-cap error-path test (Phase 3h Task 5).
#[allow(
    dead_code,
    reason = "enforced by read_typed's LODModels read in Phase 3h Task 4; pinned by skel_lod_caps"
)]
pub(crate) const MAX_LODS_PER_MESH: usize = 64;

/// Max `FStaticLODModel::RequiredBones` entries — a 16-bit bone-index array, so
/// it can't reference more bones than a skeleton can hold ([`MAX_BONES_PER_SKELETON`]).
///
/// NOTE: no `__test_utils` accessor (see [`MAX_LODS_PER_MESH`]).
#[allow(
    dead_code,
    reason = "enforced by read_static_lod_model in Phase 3h Task 3; pinned by skel_lod_caps"
)]
pub(crate) const MAX_REQUIRED_BONES: usize = MAX_BONES_PER_SKELETON;

/// Max `FStaticLODModel::ActiveBoneIndices` entries — same 16-bit bone-index
/// reasoning as [`MAX_REQUIRED_BONES`].
///
/// NOTE: no `__test_utils` accessor (see [`MAX_LODS_PER_MESH`]).
#[allow(
    dead_code,
    reason = "enforced by read_static_lod_model in Phase 3h Task 3; pinned by skel_lod_caps"
)]
pub(crate) const MAX_ACTIVE_BONES: usize = MAX_BONES_PER_SKELETON;

/// Max `FStaticLODModel::Sections` (`FSkelMeshSection`) per LOD — a generous
/// ceiling on the per-LOD draw-call count. Each section references a material
/// slot, so this shares the [`MAX_SKELETAL_MATERIALS`] magnitude (256); kept as
/// an independent literal so moving the material ceiling doesn't silently move
/// the section ceiling.
///
/// NOTE: no `__test_utils` accessor (see [`MAX_LODS_PER_MESH`]).
#[allow(
    dead_code,
    reason = "enforced by read_static_lod_model in Phase 3h Task 3; pinned by skel_lod_caps"
)]
pub(crate) const MAX_SECTIONS_PER_LOD: usize = 256;

/// Max `FSkinWeightProfilesData` profiles a non-inlined (bulk) LOD's
/// `SerializeAvailabilityInfo` may declare — a generous ceiling on the
/// per-LOD skin-weight-profile count (each profile is an 8-byte `FName` pair
/// skipped, never parsed). Sized as an independent literal (per the sibling
/// cap convention); pinned by value in `skel_lod_caps`.
///
/// NOTE: no `__test_utils` accessor (see [`MAX_LODS_PER_MESH`]).
#[allow(
    dead_code,
    reason = "the _U32 companion (MAX_SKIN_PROFILES_U32) is what skip_availability_info uses; pinned by skel_lod_caps"
)]
pub(crate) const MAX_SKIN_PROFILES: usize = 256;

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
/// `u32` companions of the LOD caps for [`read::read_capped_count`], consumed by
/// the LOD readers ([`MAX_LODS_PER_MESH_U32`] in [`read_typed`]; the others in
/// [`read_static_lod_model`]). Equality with the authoritative `usize` caps is
/// pinned by `skel_lod_cap_u32_companions_match`.
const MAX_LODS_PER_MESH_U32: u32 = 64;
const MAX_REQUIRED_BONES_U32: u32 = 65_536;
const MAX_ACTIVE_BONES_U32: u32 = 65_536;
const MAX_SECTIONS_PER_LOD_U32: u32 = 256;
const MAX_SKIN_PROFILES_U32: u32 = 256;
/// Max `USkeletalMesh` post-loop-tail `dummyObjs` (`FPackageIndex`) entries — a
/// generous ceiling on the cooked dummy-object array (each entry is a discarded
/// `FPackageIndex`). Sized independently of [`MAX_LODS_PER_MESH_U32`] because a
/// real cooked mesh can carry many more dummy objects than LODs; pinned by value
/// in `skel_lod_caps`. Consumed only by [`read::read_capped_count`] (a `u32`
/// cap), so kept as a lone `u32` literal with no `usize` form.
const MAX_DUMMY_OBJECTS_U32: u32 = 4_096;
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
    //     `has_cloth_data` mirrors the oracle's `FSkelMeshSection.HasClothData`
    //     (`ClothMappingDataLODs.Any(d => d.Length > 0)`), which drives the
    //     streamed-blob `ClothVertexBuffer` gate in `read_streamed_data`.
    let mut has_cloth_data = false;
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
            let inner = skip_capped_array(
                r,
                asset_path,
                AssetWireField::SkelSectionClothVertCount,
                MAX_CLOTH_VERTS_PER_LOD_U32,
                MESH_TO_MESH_VERT_DATA_BYTES,
            )?;
            has_cloth_data |= inner > 0;
        }
    } else {
        // Legacy shape: a single FMeshToMeshVertData[] (no outer count).
        let inner = skip_capped_array(
            r,
            asset_path,
            AssetWireField::SkelSectionClothVertCount,
            MAX_CLOTH_VERTS_PER_LOD_U32,
            MESH_TO_MESH_VERT_DATA_BYTES,
        )?;
        has_cloth_data |= inner > 0;
    }

    // 11. BoneMap: i32 count (capped) + N×u16.
    let bone_map = read_u16_array(
        r,
        asset_path,
        AssetWireField::SkelSectionBoneMapCount,
        MAX_BONE_MAP_ENTRIES_PER_SECTION_U32,
    )?;

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
    read::skip_bytes(
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
        // The returned element counts are unused here (dup-vert data is
        // discarded; only the cloth call sites capture the count to derive
        // `has_cloth_data`).
        let _ = skip_capped_array(
            r,
            asset_path,
            AssetWireField::SkelSectionDupVertCount,
            MAX_DUP_VERTS_PER_SECTION_U32,
            DUP_VERT_DATA_ELEM_BYTES,
        )?;
        let _ = skip_capped_array(
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
        has_cloth_data,
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
) -> crate::Result<u32> {
    let count = read::read_capped_count(r, asset_path, field, cap)?;
    let span = u64::from(count)
        .checked_mul(elem_bytes)
        .expect("count is a capped u32; count*elem_bytes fits u64");
    read::skip_bytes(r, span, asset_path, field)?;
    Ok(count)
}

/// Read a capped `i32`-prefixed `u16` LE array into a `Vec<u16>`.
///
/// `RequiredBones` / `ActiveBoneIndices` are serialized by UE as `TArray<short>`
/// (signed `i16`), but the values are unsigned bone **indices**. The 2 LE bytes
/// are identical either way, so we read them straight as `u16` — a bone index
/// `> 32767` would otherwise be misread as a negative `i16`. The count is capped
/// via [`read::read_capped_count`] **before** the `Vec` is sized, so an
/// attacker-supplied count can't over-allocate.
fn read_u16_array<R: Read + ?Sized>(
    r: &mut R,
    asset_path: &str,
    count_field: AssetWireField,
    cap: u32,
) -> crate::Result<Vec<u16>> {
    let count = read::read_capped_count(r, asset_path, count_field, cap)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        out.push(read::read_u16(r, asset_path, count_field)?);
    }
    Ok(out)
}

/// Header-region result of [`read_static_lod_model`] — the partial LOD plus the
/// signals `read_typed` needs to iterate (inline/bulk split + the inlined-blob
/// byte length for the `BuffersSize` seek).
#[derive(Debug)]
pub(crate) struct LodHeader {
    /// The partial LOD (header fields filled; geometry empty until the blob is
    /// parsed by [`read_streamed_data`]).
    pub lod: SkeletalMeshLod,
    /// `bInlined` — the streamed blob is inline (vs an external `FByteBulkData`).
    pub inlined: bool,
    /// `!IsAudioVisualDataStripped && !bIsLODCookedOut` — the section/bone block,
    /// `BuffersSize`, and the blob are on the wire.
    pub block_present: bool,
    /// `BuffersSize` — the inlined streamed-blob byte length (0 when no block).
    pub buffers_size: u32,
    /// The `FStripDataFlags` **class** byte (read at the top, regardless of
    /// `block_present`). Carries the per-LOD class strip bits — notably
    /// [`STRIP_FLAG_ADJACENCY_DATA`], which gates the adjacency-meta addend in
    /// [`skip_availability_info`]'s non-inlined (bulk) LOD path.
    pub class_strip: u8,
}

/// Read one cooked `FStaticLODModel::SerializeRenderItem` **header** — the
/// region before the streamed vertex/index/skin blob — into a [`LodHeader`].
/// The cursor stops at blob-start (right after `BuffersSize`) when the
/// section/bone block is present; otherwise at `RequiredBones`. The blob itself
/// is parsed by [`read_streamed_data`] (driven from [`read_typed`]'s LOD loop),
/// so the returned LOD's geometry vectors (positions / normals / tangents / uvs
/// / colors / indices / bone_indices / bone_weights) stay empty here.
///
/// Wire order (oracle `FStaticLODModel.SerializeRenderItem` @ `cf74fc32`,
/// cooked; `bool32` = 4-byte strict `{0,1}` via `FArchive.ReadBoolean`):
///
/// 1. `FStripDataFlags` (`2 × u8`) — the global byte's AV-data bit
///    ([`is_av_data_stripped`]) gates the section/bone block below.
/// 2. `bIsLODCookedOut` (`bool32`) — when set, the section/bone block is absent.
/// 3. `bInlined` (`bool32`) — surfaced as [`LodHeader::inlined`]. The inline
///    blob is only on the wire when `inlined && block_present` (the oracle's
///    `else if (bInlined)` branch sits inside
///    `if (!stripDataFlags.IsAudioVisualDataStripped() && !bIsLODCookedOut)`); a
///    non-inlined LOD with the block present uses an external `FByteBulkData`
///    (the bulk-streaming path — [`read_typed`] reads its header + skips the
///    `SerializeAvailabilityInfo` metadata via [`skip_availability_info`]).
///    `read_typed` combines `inlined` with `block_present` to decide whether to
///    parse the blob.
/// 4. `RequiredBones` (`i32` count + N × `u16` LE, capped at
///    [`MAX_REQUIRED_BONES_U32`]).
/// 5. **Gated** on `!is_av_data_stripped(global) && !bIsLODCookedOut`:
///    - a. `Sections` (`i32` count, capped at [`MAX_SECTIONS_PER_LOD_U32`], +
///      N × [`read_skel_mesh_section_render`]).
///    - b. `ActiveBoneIndices` (`i32` count + N × `u16` LE, capped at
///      [`MAX_ACTIVE_BONES_U32`]).
///    - c. `BuffersSize` (`u32`) — surfaced as [`LodHeader::buffers_size`]
///      (marks blob-start); **STOP**. This is the inlined streamed-blob byte
///      length `read_typed` seeks past to reach the next LOD.
///
///    When the gate is OFF (AV-stripped or cooked-out) the section/bone block is
///    absent: `sections` / `active_bone_indices` stay empty, `buffers_size` is
///    `0`, and the cursor stops right after `RequiredBones`.
///
/// The LOD-level [`SkeletalMeshLod::bone_map`] is the stable dedup-union of the
/// sections' per-section `bone_map`s (each authoritative; see the struct doc).
///
/// # Errors
/// [`crate::PaksmithError`] on a short / corrupt field (typed EOF), a non-strict
/// `bool32` ([`crate::error::AssetParseFault::InvalidBool32`]), an over-cap /
/// negative count ([`crate::error::AssetParseFault::BoundsExceeded`] /
/// [`crate::error::AssetParseFault::NegativeValue`]), or a nested
/// `FSkelMeshSection` fault (propagated from [`read_skel_mesh_section_render`]).
pub(crate) fn read_static_lod_model<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<LodHeader> {
    // 1. FStripDataFlags — keep `global` for the AV-data gate and `class_strip`
    //    (the class byte, read regardless of `block_present`) for the non-inlined
    //    LOD path's adjacency gate (`skip_availability_info`).
    let (global, class_strip) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkeletalMeshStripFlags)?;
    let av_stripped = is_av_data_stripped(global);
    // 2. bIsLODCookedOut (strict bool32).
    let is_lod_cooked_out = read_bool32(r, asset_path, AssetWireField::SkelLodCookedOut)?;
    // 3. bInlined (strict bool32) — combined with av_stripped + is_lod_cooked_out
    //    to produce `blob_present` (see fn-level doc). Stored separately so
    //    PR5b can distinguish "non-inlined" (bInlined=false, out-of-line bulk) from
    //    "inlined-but-stripped" (bInlined=true, no blob) when iterating further LODs.
    let inlined = read_bool32(r, asset_path, AssetWireField::SkelLodInlined)?;
    // 4. RequiredBones (u16 indices) — before Sections.
    let required_bones = read_u16_array(
        r,
        asset_path,
        AssetWireField::SkelLodRequiredBonesCount,
        MAX_REQUIRED_BONES_U32,
    )?;

    let mut sections = Vec::new();
    let mut active_bone_indices = Vec::new();
    let mut buffers_size = 0u32;
    // 5. Section/bone block present iff AV data is on the wire AND the LOD wasn't
    //    cooked out.
    let block_present = !av_stripped && !is_lod_cooked_out;
    if block_present {
        // 5a. Sections.
        let section_count = read::read_capped_count(
            r,
            asset_path,
            AssetWireField::SkelLodSectionCount,
            MAX_SECTIONS_PER_LOD_U32,
        )?;
        sections.reserve(section_count as usize);
        for _ in 0..section_count {
            sections.push(read_skel_mesh_section_render(r, ctx, asset_path)?);
        }
        // 5b. ActiveBoneIndices (u16 indices).
        active_bone_indices = read_u16_array(
            r,
            asset_path,
            AssetWireField::SkelLodActiveBonesCount,
            MAX_ACTIVE_BONES_U32,
        )?;
        // 5c. BuffersSize (u32) — surfaced for the read_typed seek; marks
        //     blob-start. STOP here.
        buffers_size = read::read_u32(r, asset_path, AssetWireField::SkelLodBuffersSize)?;
    }

    // bone_map = stable dedup-union of the sections' per-section bone_maps.
    let mut bone_map = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for section in &sections {
        for &bone in &section.bone_map {
            if seen.insert(bone) {
                bone_map.push(bone);
            }
        }
    }

    // `inlined` + `block_present` are surfaced separately so `read_typed` can
    // distinguish a non-inlined (out-of-line `FByteBulkData`) LOD from an
    // inlined-but-stripped one. The inline blob is on the wire iff
    // `inlined && block_present` — the oracle's `else if (bInlined)` branch sits
    // inside `if (!stripDataFlags.IsAudioVisualDataStripped() && !bIsLODCookedOut)`.
    Ok(LodHeader {
        lod: SkeletalMeshLod {
            sections,
            bone_map,
            active_bone_indices,
            required_bones,
            ..SkeletalMeshLod::default()
        },
        inlined,
        block_present,
        buffers_size,
        class_strip,
    })
}

/// `FSkinWeightVertexBuffer.MetadataSize` for a non-inlined (bulk) LOD's
/// `SerializeAvailabilityInfo` — the number of metadata bytes the cooker writes
/// for the skin-weight buffer ahead of the streamed payload.
///
/// Derived from the SAME custom-version comparisons
/// [`skin_weights::read_skin_weight_vertex_buffer`] uses (anti-drift — NOT a
/// UE-version table). `new = FAnimObjectVersion >= UnlimitedBoneInfluences`.
///
/// `!new` (legacy, UE4.24) → **12**. `new` →
/// `16 + 4 (IncreaseBoneIndexLimitPerChunk, always taken here — see body)`
/// `+ (FUE5MainStreamObjectVersion >= IncreasedSkinWeightPrecision ? 4 : 0) + 4`
/// → **24** for UE4.25-4.27 (the UE5 precision term is +0 there).
///
/// The oracle's `!UseNewCookedFormat → 8` branch is unreachable here: [`read_typed`]'s
/// UE4.24 (`MaterialShaderMapIdSerialization`) gate guarantees `UseNewCookedFormat`
/// before any LOD is read, so this helper omits it.
fn skin_weight_metadata_size(ctx: &AssetContext) -> u64 {
    let version_for = |guid| ctx.custom_versions.version_for(guid);
    let new = version_for(ANIM_OBJECT_VERSION_GUID).is_some_and(|v| v >= UNLIMITED_BONE_INFLUENCES);
    if !new {
        return 12;
    }
    // The new-format gate (ANIM >= UnlimitedBoneInfluences = 5) already implies
    // ANIM >= IncreaseBoneIndexLimitPerChunk = 4, so the bone-index-limit metadata
    // term is unconditionally +4 here (CUE4Parse keeps the `>= IncreaseBoneIndex…`
    // guard defensively; for our 4.24+ scope it is always taken). The UE5 skin-weight
    // precision term IS reachable (a UE5 asset that passes the 4.24 gate stamps
    // FUE5MainStreamObjectVersion), so it stays a live comparison — +0 for UE4.24-4.27,
    // +4 once IncreasedSkinWeightPrecision (90) is reached.
    let precision_term = if version_for(UE5_MAIN_STREAM_OBJECT_VERSION_GUID)
        .is_some_and(|v| v >= INCREASED_SKIN_WEIGHT_PRECISION)
    {
        4
    } else {
        0
    };
    16 + 4 + precision_term + 4
}

/// Skip a non-inlined (bulk) LOD's `FStaticLODModel::SerializeAvailabilityInfo`
/// block — the byte-exact metadata the cooker writes **off the main archive**
/// when `ElementCount > 0`, so the cursor lands on the next LOD. The streamed
/// geometry itself lives in the external `FByteBulkData` payload (not captured),
/// so nothing here is materialized — every region is skipped or count-driven.
///
/// Layout (oracle `FStaticLODModel.SerializeAvailabilityInfo` @ `cf74fc32`):
///
/// 1. **Constant metadata** = `5` (`FMultiSizeIndexContainer` index meta, `1+4`),
///    plus `5` adjacency meta (present iff `bAdjacencyData`), `16`
///    (`FStaticMeshVertexBuffer` meta), `8` (`FPositionVertexBuffer` meta), `8`
///    (`FColorVertexBuffer` meta), and [`skin_weight_metadata_size`]. The adjacency
///    gate is `FUE5ReleaseStreamObjectVersion < RemovingTessellation`
///    (`is_none_or`, so UE4's absent version → true) **AND**
///    `!is_class_data_stripped(lod_class, STRIP_FLAG_ADJACENCY_DATA)`.
/// 2. **Cloth** (gated `sections.iter().any(has_cloth_data)`): a capped `i32 num`,
///    then `num × 8 + 8` bytes; then, iff
///    `FUE5ReleaseStreamObjectVersion >= AddClothMappingLODBias` (UE5-only),
///    `num × 4` more.
/// 3. **`SkinWeightProfiles`** (UNCONDITIONAL): a capped `i32 count`, then
///    `count × 8` (`count` × `FName`-pair, 8 bytes each).
///
/// (No ray-tracing region — that is UE5.6-only and never fires for the UE4-cooked
/// inputs this path handles; a UE5.6 asset reaching here desyncs → the post-loop
/// sentinel → `Generic`.)
///
/// # Errors
/// [`crate::error::AssetParseFault::UnexpectedEof`] on a short metadata skip;
/// [`crate::error::AssetParseFault::NegativeValue`] /
/// [`crate::error::AssetParseFault::BoundsExceeded`] for a negative / over-cap
/// cloth or profile count (rejected by [`read::read_capped_count`] before the
/// skip).
fn skip_availability_info<R: Read + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    sections: &[SkelMeshSection],
    lod_class: u8,
) -> crate::Result<()> {
    let version_for = |guid| ctx.custom_versions.version_for(guid);

    // 1. Constant metadata region.
    let adjacency = version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
        .is_none_or(|v| v < REMOVING_TESSELLATION)
        && !is_class_data_stripped(lod_class, STRIP_FLAG_ADJACENCY_DATA);
    let constant = 5 + if adjacency { 5 } else { 0 } + 16 + 8 + 8 + skin_weight_metadata_size(ctx);
    read::skip_bytes(
        r,
        constant,
        asset_path,
        AssetWireField::SkelAvailabilityInfo,
    )?;

    // 2. Cloth (gated on any section carrying cloth data).
    if sections.iter().any(|s| s.has_cloth_data) {
        let num = read::read_capped_count(
            r,
            asset_path,
            AssetWireField::SkelLodBulkClothCount,
            MAX_CLOTH_VERTS_PER_LOD_U32,
        )?;
        read::skip_bytes(
            r,
            u64::from(num) * 8 + 8,
            asset_path,
            AssetWireField::SkelLodBulkClothCount,
        )?;
        if version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
            .is_some_and(|v| v >= ADD_CLOTH_MAPPING_LOD_BIAS)
        {
            read::skip_bytes(
                r,
                u64::from(num) * 4,
                asset_path,
                AssetWireField::SkelLodBulkClothCount,
            )?;
        }
    }

    // 3. SkinWeightProfiles (unconditional): count × FName-pair (8 bytes each).
    let count = read::read_capped_count(
        r,
        asset_path,
        AssetWireField::SkelLodSkinProfileCount,
        MAX_SKIN_PROFILES_U32,
    )?;
    read::skip_bytes(
        r,
        u64::from(count) * 8,
        asset_path,
        AssetWireField::SkelLodSkinProfileCount,
    )?;

    Ok(())
}

/// `true` iff `props` contains a [`Property`] named `name` whose value is
/// `Bool(true)`. Default `false` (absent property, non-bool value, or
/// `Bool(false)`). Used to read the `bHasVertexColors` tagged property that
/// gates the streamed blob's `ColorVertexBuffer` (a segment-1 property, NOT a
/// wire field — matching the oracle's `GetOrDefault<bool>("bHasVertexColors")`).
fn property_bool(props: &[Property], name: &str) -> bool {
    props
        .iter()
        .any(|p| p.name() == name && matches!(p.value, PropertyValue::Bool(true)))
}

/// Skip an `FSkeletalMeshVertexClothBuffer` off a generic reader (oracle
/// `FSkeletalMeshVertexClothBuffer` ctor @ `cf74fc32`):
///
/// 1. inner `FStripDataFlags` (`2 × u8`). If audio-visual data is stripped, the
///    buffer is absent — return immediately (nothing else on the wire).
/// 2. `SkipBulkArrayData` — the cloth vertex bulk array (read-and-discarded).
/// 3. **Gated** `FSkeletalMeshCustomVersion >= CompactClothVertexBuffer (10)`
///    (always on for the UE4.24+ cooked target): `ClothIndexMapping` =
///    `TArray<uint64>` (`i32` count + N × `u64`), read-and-discarded. When
///    `FUE5ReleaseStreamObjectVersion >= AddClothMappingLODBias (15)` (UE5
///    only), a trailing `count × 4` LOD-bias block follows — never on UE4, but
///    gated correctly so it stays cursor-aligned if present.
fn skip_cloth_buffer<R: Read>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<()> {
    let (global, _class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkelClothStripFlags)?;
    if is_av_data_stripped(global) {
        return Ok(());
    }
    // Cloth vertex bulk array — discarded.
    read::skip_bulk_array(r, asset_path, AssetWireField::SkelClothBulkData)?;

    if ctx
        .custom_versions
        .version_for(SKELETAL_MESH_CUSTOM_VERSION_GUID)
        .is_some_and(|v| v >= COMPACT_CLOTH_VERTEX_BUFFER)
    {
        // ClothIndexMapping = TArray<uint64>: a plain `i32` count + N × u64 (NOT
        // a bulk array — no elementSize header). Capped before the `× 8` span.
        let count = read::read_capped_count(
            r,
            asset_path,
            AssetWireField::SkelClothIndexMappingCount,
            MAX_CLOTH_VERTS_PER_LOD_U32,
        )?;
        let span = u64::from(count)
            .checked_mul(8)
            .expect("count is a capped u32; count*8 fits u64");
        read::skip_bytes(
            r,
            span,
            asset_path,
            AssetWireField::SkelClothIndexMappingCount,
        )?;

        if ctx
            .custom_versions
            .version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
            .is_some_and(|v| v >= ADD_CLOTH_MAPPING_LOD_BIAS)
        {
            // UE5 AddClothMappingLODBias trailer: `count × 4` bytes. Never fires
            // for UE4 (the version is absent); gated so a UE5 input stays aligned.
            let bias_span = u64::from(count)
                .checked_mul(4)
                .expect("count is a capped u32; count*4 fits u64");
            read::skip_bytes(
                r,
                bias_span,
                asset_path,
                AssetWireField::SkelClothIndexMappingCount,
            )?;
        }
    }
    Ok(())
}

/// Parse one inlined `FStaticLODModel::SerializeStreamedData` blob (oracle
/// @ `cf74fc32`, UE4.24–4.27 cooked), filling `lod`'s geometry in place.
///
/// Wire order (after the LOD header's `BuffersSize`, when
/// `bInlined && !av_stripped && !cooked_out`):
/// 1. inner `FStripDataFlags` (`2 × u8`) — the `class` byte gates adjacency.
/// 2. `Indices` (`FMultisizeIndexContainer`) → `lod.indices`.
/// 3. `PositionVertexBuffer` → `lod.positions`.
/// 4. `StaticMeshVertexBuffer` → `lod.normals` / `tangents` / `uvs`.
/// 5. `FSkinWeightVertexBuffer` → `lod.bone_indices` / `bone_weights`.
/// 6. `ColorVertexBuffer` — only when `b_has_vertex_colors` → `lod.colors`.
/// 7. `AdjacencyIndexBuffer` (`FMultisizeIndexContainer`) — read-and-discarded,
///    gated `FUE5ReleaseStreamObjectVersion` absent (UE4) or `< RemovingTessellation`
///    **and** `!CDSF_AdjacencyData` (class-stripped) (the tessellation indices).
/// 8. `ClothVertexBuffer` — skipped via [`skip_cloth_buffer`], gated
///    `HasClothData()` = any section's [`SkelMeshSection::has_cloth_data`].
/// 9. `FSkinWeightProfilesData` — **unconditional** `i32` map count; `0` →
///    proceed (the empty cooked norm), `> 0` → [`crate::PaksmithError::UnsupportedFeature`]
///    (the per-entry profile parse is deferred). **This is the LAST field read.**
///
/// The reader STOPS after `FSkinWeightProfilesData`; it does NOT read the
/// version-gated tail that follows on the wire (the UE4.27 ray-tracing
/// `SkipFixedArray(1)`, nor the UE5-only morph / vertex-attribute / half-edge
/// buffers). [`read_typed`]'s `blob_start + BuffersSize` seek skips that tail.
/// Stopping here avoids a 4.26-vs-4.27 desync — `file_version_ue4 = 522` is
/// shared by both, so a version gate would mis-read a 4.26 mesh's next-LOD bytes
/// as a spurious ray-tracing count. The seek re-syncs past the entire tail for
/// BOTH 4.26 (no tail) and 4.27 (tail present).
///
/// After the reads, the Structure-of-Arrays invariant (index `i` is vertex `i`)
/// is cross-checked (mirroring `lod.rs`): when `positions` is non-empty,
/// `normals.len() == positions.len()` ([`crate::error::AssetParseFault::MeshVertexBufferLengthMismatch`]);
/// non-empty `bone_indices` / `colors` must equal `positions.len()`
/// ([`read::ensure_bulk_count`]). Bone / color data legitimately come back empty
/// (AV-stripped / variable-bones / 16-bit-weight defers), so each check is guarded
/// on non-emptiness.
///
/// # Errors
/// [`crate::PaksmithError`] on any short / corrupt field (typed EOF), an over-cap
/// / negative count, a non-strict bool, a non-empty `FSkinWeightProfilesData`
/// (`UnsupportedFeature`), or an SoA-length mismatch.
fn read_streamed_data<R: Read>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    b_has_vertex_colors: bool,
    sections: &[SkelMeshSection],
    lod: &mut SkeletalMeshLod,
) -> crate::Result<()> {
    // 1. Inner FStripDataFlags — keep `class` for the adjacency gate.
    let (_global, class) =
        read_strip_data_flags(r, asset_path, AssetWireField::SkelStreamStripFlags)?;

    // 2. Indices (FMultisizeIndexContainer).
    lod.indices = index_buffer::read_multisize_index_container(
        r,
        asset_path,
        AssetWireField::SkelLodIndexCount,
    )?;

    // 3. PositionVertexBuffer.
    lod.positions = read_position_buffer(r, asset_path)?;

    // 4. StaticMeshVertexBuffer (normals / tangents / uvs).
    let v = read_static_mesh_vertex_buffer(r, ctx, asset_path)?;
    lod.normals = v.normals;
    lod.tangents = v.tangents;
    lod.uvs = v.uvs;

    // 5. FSkinWeightVertexBuffer (per-vertex bone indices / weights).
    let (bone_indices, bone_weights) =
        skin_weights::read_skin_weight_vertex_buffer(r, ctx, asset_path)?;
    lod.bone_indices = bone_indices;
    lod.bone_weights = bone_weights;

    // 6. ColorVertexBuffer — only when the bHasVertexColors tagged property is set.
    if b_has_vertex_colors {
        lod.colors = read_color_buffer(r, asset_path)?;
    }

    // 7. AdjacencyIndexBuffer (read-and-discarded). Present iff the UE5-release
    //    version is absent (UE4) or below RemovingTessellation AND the class did
    //    not strip CDSF_AdjacencyData.
    if ctx
        .custom_versions
        .version_for(UE5_RELEASE_STREAM_OBJECT_VERSION_GUID)
        .is_none_or(|v| v < REMOVING_TESSELLATION)
        && !is_class_data_stripped(class, STRIP_FLAG_ADJACENCY_DATA)
    {
        let _adjacency = index_buffer::read_multisize_index_container(
            r,
            asset_path,
            AssetWireField::SkelLodAdjacencyIndexCount,
        )?;
    }

    // 8. ClothVertexBuffer — skipped, gated on HasClothData() (any section with
    //    non-empty ClothMappingDataLODs).
    if sections.iter().any(|s| s.has_cloth_data) {
        skip_cloth_buffer(r, ctx, asset_path)?;
    }

    // 9. FSkinWeightProfilesData — UNCONDITIONAL i32 map count. The empty cooked
    //    norm is `0` (proceed); a non-empty profile map's per-entry parse is
    //    version-forked and rare on cooked assets, so it's deferred.
    let profile_count = read::read_i32(r, asset_path, AssetWireField::SkelSkinWeightProfileCount)?;
    if profile_count < 0 {
        return Err(read::fault(
            asset_path,
            crate::error::AssetParseFault::NegativeValue {
                field: AssetWireField::SkelSkinWeightProfileCount,
                value: i64::from(profile_count),
            },
        ));
    }
    if profile_count > 0 {
        return Err(PaksmithError::UnsupportedFeature {
            context: "non-empty FSkinWeightProfilesData (skin-weight profiles) not supported"
                .into(),
        });
    }

    // `read_streamed_data` STOPS here — after `FSkinWeightProfilesData`. It does
    // NOT read the version-gated tail (the UE4.27 ray-tracing `SkipFixedArray(1)`,
    // nor the UE5-only morph / vertex-attribute / half-edge buffers). The
    // `blob_start + BuffersSize` seek in `read_typed` skips whatever the tail is.
    //
    // This avoids a 4.26-vs-4.27 desync: `file_version_ue4 = 522` is shared by
    // BOTH UE4.26 and UE4.27, so an `is_ue4_27_or_later()` gate here would also
    // fire on a 4.26 cooked mesh — which did NOT serialize the ray-tracing tail —
    // and would mis-consume the next LOD's header bytes as a spurious count, then
    // overshoot the seek target → `SkeletalLodCursorDesync` → the whole asset
    // degrades to Generic. By stopping after profiles, BOTH 4.26 (no tail; the
    // seek is a no-op) and 4.27 (tail present; the seek jumps it) iterate
    // correctly — no over-read, no 4.26 desync. The seek genuinely re-syncs past
    // the entire version-gated tail.

    // SoA length invariants (index `i` is vertex `i` across the buffers),
    // mirroring `lod.rs`. Only assert when the relevant buffer is non-empty —
    // bone / color data legitimately come back empty on AV-stripped /
    // variable-bones / 16-bit-weight defers.
    if !lod.positions.is_empty() && lod.normals.len() != lod.positions.len() {
        return Err(read::fault(
            asset_path,
            // MeshVertexBufferLengthMismatch is shared with the 3g static-mesh
            // reader; here the mismatching buffer is the skeletal NORMAL buffer,
            // so its `tangents` field carries the normal count (normals + tangents
            // are interleaved in StaticMeshVertexBuffer and share a count). Reusing
            // the variant avoids a new wire-stable fault for the same SoA-length
            // invariant.
            crate::error::AssetParseFault::MeshVertexBufferLengthMismatch {
                positions: u32::try_from(lod.positions.len()).unwrap_or(u32::MAX),
                tangents: u32::try_from(lod.normals.len()).unwrap_or(u32::MAX),
            },
        ));
    }
    if !lod.bone_indices.is_empty() {
        read::ensure_bulk_count(
            asset_path,
            AssetWireField::SkinWeightVertexCount,
            u32::try_from(lod.positions.len()).unwrap_or(u32::MAX),
            u32::try_from(lod.bone_indices.len()).unwrap_or(u32::MAX),
        )?;
    }
    if let Some(colors) = &lod.colors {
        read::ensure_bulk_count(
            asset_path,
            AssetWireField::MeshColorData,
            u32::try_from(lod.positions.len()).unwrap_or(u32::MAX),
            u32::try_from(colors.len()).unwrap_or(u32::MAX),
        )?;
    }

    Ok(())
}

/// Consume the cooked `USkeletalMesh` post-LOD-loop tail and assert the
/// cursor-landing sentinel — called once, after [`read_typed`]'s LOD loop.
///
/// Tail wire order (oracle `USkeletalMesh.Deserialize` @ `cf74fc32`, cooked,
/// `UseNewCookedFormat` — the UE4.24 gate has already passed):
/// 1. `numInlinedLODs` (`u8`) + `numNonOptionalLODs` (`u8`) — read-and-discarded.
/// 2. `dummyObjs` — `i32` count (capped at [`MAX_DUMMY_OBJECTS_U32`], a generous
///    cooked ceiling) + N × `FPackageIndex`, discarded.
/// 3. UV-channel `SkipFixedArray(4)` — `i32` count + `count × 4` bytes, gated
///    `FRenderingObjectVersion` PRESENT-and-`< TextureStreamingMeshUVChannelData`.
///    `is_some_and` so an ABSENT version does NOT fire; the 4.24 gate guarantees
///    present `>= 36 > 10`, so this never fires for paksmith's range — kept for
///    cursor-math completeness only.
/// 4. `FNaniteResources` (Game `>= UE5.5`) does **not** fire for UE4.24-4.27; a
///    UE5.5+ asset desyncs into the sentinel below rather than mis-reading it.
///
/// Sentinel: segment-2 (the LODs + this tail) runs to the export payload end
/// (the `UObject` object-GUID tail was consumed early in [`read_typed`]). A
/// wrong `BuffersSize` seek or a stray tail leaves the cursor off `total_len`
/// → [`AssetParseFault::SkeletalLodCursorDesync`] → the package walker degrades
/// the asset to a generic property bag.
///
/// # Errors
/// [`crate::PaksmithError`] on a short tail field (typed EOF), an over-cap /
/// negative `dummyObjs` / UV-skip count, or a cursor-landing mismatch
/// ([`AssetParseFault::SkeletalLodCursorDesync`]).
fn read_lod_post_loop_tail(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    total_len: u64,
    asset_path: &str,
) -> crate::Result<()> {
    let _num_inlined = read::read_u8(cur, asset_path, AssetWireField::SkelLodNumInlined)?;
    let _num_non_optional = read::read_u8(cur, asset_path, AssetWireField::SkelLodNumNonOptional)?;
    let dummy_count = read::read_capped_count(
        cur,
        asset_path,
        AssetWireField::SkelDummyObjCount,
        MAX_DUMMY_OBJECTS_U32,
    )?;
    for _ in 0..dummy_count {
        let _ = read_package_index(cur, asset_path, AssetWireField::SkelDummyObjCount)?;
    }
    if ctx
        .custom_versions
        .version_for(RENDERING_OBJECT_VERSION_GUID)
        .is_some_and(|v| v < TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA)
    {
        let n = read::read_capped_count(
            cur,
            asset_path,
            AssetWireField::SkelUvChannelSkipCount,
            MAX_LODS_PER_MESH_U32,
        )?;
        read::skip_bytes(
            cur,
            u64::from(n) * 4,
            asset_path,
            AssetWireField::SkelUvChannelSkipCount,
        )?;
    }

    if cur.position() != total_len {
        return Err(read::fault(
            asset_path,
            AssetParseFault::SkeletalLodCursorDesync {
                position: cur.position(),
                expected: total_len,
            },
        ));
    }
    Ok(())
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
/// 6. `LODModels` — `i32` count (capped at [`MAX_LODS_PER_MESH`]); EVERY LOD's
///    cooked `FStaticLODModel` header is parsed via [`read_static_lod_model`]
///    and each inlined LOD's streamed blob via [`read_streamed_data`], gated on
///    the UE4.24 new-cooked-format boundary (see scoping below). The post-loop
///    tail + the cursor-landing sentinel are consumed by
///    [`read_lod_post_loop_tail`].
///
/// # Scope (PR2 + PR4 + PR5a/b of the 3h series)
///
/// Per the oracle (`USkeletalMesh.Deserialize` @ `cf74fc32`), the post-skeleton
/// layout forks on `FSkeletalMeshCustomVersion`:
///
/// - **Pre-`SplitModelAndRenderData` (legacy, `< 12`)** — the LODModels array
///   is read inline with NO `bCooked` field (a different `FStaticLODModel`
///   layout). Not supported: returns [`crate::PaksmithError::UnsupportedFeature`].
/// - **Modern (`>= SplitModelAndRenderData`)** — an optional editor `LODModels`
///   array precedes `bCooked`, gated on `!IsEditorDataStripped()`. Only the
///   editor-data-stripped (cooked) case is handled, where that optional array
///   is absent; a non-cooked skeletal mesh (editor LOD data present) returns
///   [`crate::PaksmithError::UnsupportedFeature`].
///
/// After `bCooked`, the cooked `LODModels` array is gated on the **UE4.24
/// new-cooked-format boundary** (`FRenderingObjectVersion >=
/// MaterialShaderMapIdSerialization`): a present-and-below version is the
/// distinct `SerializeRenderItem_Legacy` header (UE4.16–4.23) → returns
/// [`crate::PaksmithError::UnsupportedFeature`]; an absent version (unversioned
/// package — the shipping-game norm) proceeds, relying on the strict `bool32`
/// reads + the section reader's caps as the natural backstop against a
/// legacy-as-new mis-parse.
///
/// All `UnsupportedFeature` returns degrade to a generic property bag via the
/// package walker, exactly like any other typed-read failure.
///
/// **Multi-LOD iteration (PR4 + PR5a/b/c):** `read_typed` loops over EVERY
/// `LODModels[i]`. For each LOD it reads the header (sections + required /
/// active bones, before the streamed blob, via [`read_static_lod_model`]); for
/// an **inlined** LOD (`bInlined && block_present` — `block_present` being
/// `!av_stripped && !cooked_out`, since the oracle's `else if (bInlined)` sits
/// inside the AV+cooked-out block) it then parses the streamed blob in place via
/// [`read_streamed_data`] (indices / positions / normals / tangents / uvs /
/// colors / per-vertex bone indices+weights) and **seeks `blob_start +
/// BuffersSize`** (bounded `<= total_len`) to re-sync onto LOD[i+1]. Because
/// [`read_streamed_data`] stops after `FSkinWeightProfilesData` and does NOT
/// read the version-gated tail (UE4.27 ray-tracing / UE5 morph / vertex-attr /
/// half-edge), the seek skips that tail — for both 4.26 (no tail) and 4.27 (tail
/// present). A LOD whose block is absent
/// (AV-stripped or cooked-out) leaves geometry empty and is not seeked. A
/// **non-inlined** LOD with the block present (the external [`FByteBulkData`]
/// bulk-streaming path) reads the `FByteBulkData` header (via
/// [`FByteBulkData::read_from`], which consumes any inline payload too) and —
/// when `element_count > 0` — skips a byte-exact [`skip_availability_info`] off
/// the main archive to land on the next LOD. The bulk LOD's geometry stays
/// **empty** (the streamed payload is in the external `.ubulk` / not captured);
/// its sections/bones are populated. paksmith gates on `element_count > 0`
/// alone — the wire-deterministic subset of CUE4Parse's
/// `ElementCount > 0 && Data != null` (the `&& Data != null` is
/// file-resolvability, not wire) — guarded by the post-loop sentinel.
/// After the loop, [`read_lod_post_loop_tail`] consumes the tail and asserts the
/// cursor-landing sentinel. The second returned element — the export's
/// [`FByteBulkData`] records — is always empty here (no out-of-line buffers are
/// resolved yet).
///
/// # Errors
/// [`crate::PaksmithError`] from the tagged-property parse, the object-GUID
/// tail, a short / corrupt segment-2 field, an over-cap `SkeletalMaterials` /
/// `LODModels` count, a nested `FSkeletalMaterial` / `FReferenceSkeleton` /
/// `FStaticLODModel` fault, or [`crate::PaksmithError::UnsupportedFeature`] for
/// a legacy / non-cooked / pre-UE4.24 mesh (see *Scope* above) — all of which
/// the package walker degrades to a generic property bag (see
/// `Package::read_payloads`).
#[allow(
    clippy::too_many_lines,
    reason = "a flat in-order segment-2 wire sequence (strip flags → bounds → \
              materials → skeleton → bCooked → the LOD loop); splitting the \
              in-order reads into sub-fns would obscure the cursor flow the \
              cooked layout depends on (the post-loop tail + sentinel are \
              already extracted into read_lod_post_loop_tail)"
)]
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

    // LODModels array — gated on `bCooked` (oracle `USkeletalMesh.Deserialize`
    // reads the cooked LOD array ONLY inside `if (bCooked && LODModels == null)`;
    // on the editor-data-stripped path `read_typed` already requires, LODModels
    // is null, so the gate reduces to `cooked`). An editor-data-stripped mesh
    // with `cooked == false` is a valid strict-bool wire state that serializes
    // NOTHING after bCooked — reading a LOD count there would mis-parse the
    // following bytes.
    //
    // PR5b iterates EVERY LOD: each header + (when inlined) its streamed blob,
    // re-syncing onto the next LOD via the BuffersSize seek, then the post-loop
    // tail + the cursor-landing sentinel.
    let mut lods = Vec::new();
    if cooked {
        // UE4.24 new-cooked-format gate (oracle: SerializeRenderItem is the cooked
        // FStaticLODModel layout ONLY for Game >= UE4.24; 4.16-4.23 cooked is the
        // distinct SerializeRenderItem_Legacy header). It determines the LOD
        // FORMAT, so it only matters when LODs are actually read — kept inside the
        // `cooked` block so a non-cooked mesh isn't rejected for a pre-4.24
        // rendering version it never uses. Discriminator: FRenderingObjectVersion
        // >= MaterialShaderMapIdSerialization. Present-and-below → reject;
        // present-and-at/above → proceed; ABSENT (unversioned package, the
        // shipping-game norm) → proceed, relying on the strict bool32 reads
        // (bIsLODCookedOut / bInlined) + the section reader's caps/strict-bools as
        // the natural backstop against a legacy-as-new mis-parse.
        let rendering_ver = ctx
            .custom_versions
            .version_for(RENDERING_OBJECT_VERSION_GUID);
        if rendering_ver.is_some_and(|v| v < MATERIAL_SHADER_MAP_ID_SERIALIZATION) {
            return Err(PaksmithError::UnsupportedFeature {
                context: "pre-UE4.24 legacy cooked skeletal LOD layout \
                          (SerializeRenderItem_Legacy) not supported"
                    .into(),
            });
        }

        let lod_count = read::read_capped_count(
            &mut cur,
            asset_path,
            AssetWireField::SkelLodCount,
            MAX_LODS_PER_MESH_U32,
        )?;

        // `bHasVertexColors` is a segment-1 tagged property; hoisted above the
        // loop since every inlined LOD's ColorVertexBuffer gates on it.
        let b_has_vertex_colors = property_bool(&properties, "bHasVertexColors");

        // Iterate every LODModels[i]. For each inlined LOD: parse the header
        // (stops at blob-start), parse the streamed blob in place (read_streamed_data
        // stops after FSkinWeightProfilesData — it does NOT read the version-gated
        // tail), then SEEK to `blob_start + BuffersSize` to re-sync onto LOD[i+1].
        // The seek skips whatever the tail is — for both UE4.26 (no tail; no-op
        // seek) and UE4.27 (ray-tracing tail; the seek jumps it), which share
        // file-version 522. The seek target is bounded `<= total_len` so a hostile
        // BuffersSize faults rather than seeking past the payload. A non-inlined
        // (out-of-line FByteBulkData) LOD with the block present takes the
        // bulk-streaming path: read the FByteBulkData header + skip the byte-exact
        // SerializeAvailabilityInfo (geometry stays empty; external .ubulk).
        lods.reserve(lod_count as usize);
        for _ in 0..lod_count {
            let mut header = read_static_lod_model(&mut cur, ctx, asset_path)?;
            if header.block_present {
                if header.inlined {
                    let blob_start = cur.position();
                    let sections = header.lod.sections.clone();
                    read_streamed_data(
                        &mut cur,
                        ctx,
                        asset_path,
                        b_has_vertex_colors,
                        &sections,
                        &mut header.lod,
                    )?;
                    // The seek target is FORWARD-ONLY and bounded:
                    //   blob_end <= blob_start + BuffersSize <= total_len
                    // where `blob_end` is where `read_streamed_data` left the
                    // cursor (the minimum the blob can be — the buffers it just
                    // parsed). A too-LARGE BuffersSize would seek past the payload
                    // (caught by `<= total_len`); a too-SMALL one would seek
                    // BACKWARD into already-parsed blob bytes (caught by
                    // `>= blob_end`). Either way → desync → Generic, never a wild
                    // or backward seek that could re-read bytes as a fake LOD.
                    let blob_end = cur.position();
                    // Report the cursor position AT DETECTION (= `blob_end`, where
                    // `read_streamed_data` left the cursor — the field doc says
                    // "cursor position at detection"), not `blob_start`. The seek
                    // hasn't moved the cursor yet, so `blob_end == cur.position()`.
                    let desync = || {
                        read::fault(
                            asset_path,
                            AssetParseFault::SkeletalLodCursorDesync {
                                position: blob_end,
                                expected: total_len,
                            },
                        )
                    };
                    let target = blob_start
                        .checked_add(u64::from(header.buffers_size))
                        .filter(|t| (blob_end..=total_len).contains(t))
                        .ok_or_else(desync)?;
                    let _ = cur.seek(SeekFrom::Start(target)).map_err(|_| desync())?;
                } else {
                    // Non-inlined (bulk) LOD: FByteBulkData header (+ inline
                    // payload via read_from), then SerializeAvailabilityInfo when
                    // non-empty. Geometry is in the bulk payload (external .ubulk /
                    // not captured) → this LOD's geometry stays empty. The
                    // `element_count > 0` gate is paksmith's wire-deterministic
                    // subset of CUE4Parse's `ElementCount > 0 && Data != null`
                    // (`Data != null` is file-resolvability, not wire); the
                    // post-loop cursor-landing sentinel guards a wrong skip.
                    let bulk = FByteBulkData::read_from(&mut cur, asset_path)?;
                    if bulk.element_count > 0 {
                        skip_availability_info(
                            &mut cur,
                            ctx,
                            asset_path,
                            &header.lod.sections,
                            header.class_strip,
                        )?;
                    }
                }
            }
            lods.push(header.lod);
        }

        read_lod_post_loop_tail(&mut cur, ctx, total_len, asset_path)?;
    }

    let mut data = SkeletalMeshData::empty();
    data.properties = PropertyBag::tree(properties);
    data.cooked = cooked;
    data.bounds = bounds;
    data.materials = materials;
    data.skeleton = skeleton;
    data.lods = lods;
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

    /// Pin each `FStaticLODModel` cap's literal value — the symbols are
    /// otherwise referenced only by the Task-3/4 readers, so a wrong-value mutant
    /// would survive without a value assertion.
    #[test]
    fn skel_lod_caps() {
        assert_eq!(MAX_LODS_PER_MESH, 64);
        assert_eq!(MAX_REQUIRED_BONES, 65_536); // = MAX_BONES_PER_SKELETON
        assert_eq!(MAX_REQUIRED_BONES, MAX_BONES_PER_SKELETON);
        assert_eq!(MAX_ACTIVE_BONES, 65_536); // = MAX_BONES_PER_SKELETON
        assert_eq!(MAX_ACTIVE_BONES, MAX_BONES_PER_SKELETON);
        assert_eq!(MAX_SECTIONS_PER_LOD, 256);
        assert_eq!(MAX_SKIN_PROFILES, 256);
        // dummyObjs has only a `u32` cap (consumed solely by read_capped_count).
        assert_eq!(MAX_DUMMY_OBJECTS_U32, 4_096);
    }

    /// Pin the LOD `u32` cap companions against the authoritative `usize` caps so
    /// a wrong-value drift in either side fails here.
    #[test]
    fn skel_lod_cap_u32_companions_match() {
        assert_eq!(MAX_LODS_PER_MESH_U32 as usize, MAX_LODS_PER_MESH);
        assert_eq!(MAX_REQUIRED_BONES_U32 as usize, MAX_REQUIRED_BONES);
        assert_eq!(MAX_ACTIVE_BONES_U32 as usize, MAX_ACTIVE_BONES);
        assert_eq!(MAX_SECTIONS_PER_LOD_U32 as usize, MAX_SECTIONS_PER_LOD);
        assert_eq!(MAX_SKIN_PROFILES_U32 as usize, MAX_SKIN_PROFILES);
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
        // FRenderingObjectVersion at MaterialShaderMapIdSerialization (36) so the
        // 4.24 LOD-format gate passes (UVChannelData gate `>= 10` stays ON too).
        let custom_versions = skel_custom_versions(
            8,
            3,
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
            196,
            SPLIT_MODEL_AND_RENDER_DATA,
        );
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
        // LODModels count = 0 → no LOD parse (this test pins the prefix).
        payload.extend_from_slice(&0i32.to_le_bytes());
        push_lod_tail(&mut payload, 0); // post-loop tail (cursor-landing sentinel)

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
        // FRenderingObjectVersion at MaterialShaderMapIdSerialization (36) so the
        // 4.24 LOD-format gate passes; the pre-split / editor-data gate tests
        // sharing this ctx fault before that gate, so the bump is inert for them.
        let custom_versions =
            skel_custom_versions(8, 3, MATERIAL_SHADER_MAP_ID_SERIALIZATION, 100, skel_mesh);
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
        payload.extend_from_slice(&0i32.to_le_bytes()); // LODModels count = 0
        push_lod_tail(&mut payload, 0); // post-loop tail (cursor-landing sentinel)
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
        // ON (editor=8/core=3/rendering=36 — at MaterialShaderMapIdSerialization
        // so the 4.24 LOD-format gate passes; UVChannelData gate `>= 10` stays
        // ON), fortnite below the UE5 overlay gate. ue5=None → FBoxSphereBounds
        // =28B, FTransform=40B.
        let ctx = skel_mat_ctx(
            &["None", "Mat0", "Root", "Hip"],
            8,
            3,
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
            100,
        );

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
        // LODModels count = 0 → no LOD parse (this test pins the prefix).
        payload.extend_from_slice(&0i32.to_le_bytes());
        push_lod_tail(&mut payload, 0); // post-loop tail (cursor-landing sentinel)

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

    /// `has_cloth_data` mirrors the oracle's per-section predicate
    /// (`ClothMappingDataLODs.Any(d => d.Length > 0)`): true iff any inner cloth
    /// array is non-empty, false when every inner array is empty. Pins both
    /// arms (and the `count > 0` derivation) — it drives the streamed-blob
    /// `ClothVertexBuffer` gate, so a wrong value desyncs real cloth assets.
    #[test]
    fn read_skel_mesh_section_render_has_cloth_data_tracks_nonempty_mapping() {
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS, // new shape (outer count)
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        );

        // (a) one inner array with 1 element → has_cloth_data true.
        let mut yes = Vec::new();
        push_section_prefix(&mut yes, 0x01, 0, 0, 0, false, 3, true, true, 0);
        yes.extend_from_slice(&1i32.to_le_bytes()); // cloth outer count = 1
        push_cloth_inner(&mut yes, 1); // one inner array, 1 element
        push_section_suffix(&mut yes, &[], 0, 0, 0);
        yes.extend_from_slice(&0i32.to_le_bytes()); // bDisabled
        let s = read_skel_mesh_section_render(&mut Cursor::new(yes.as_slice()), &ctx, "M")
            .expect("decode");
        assert!(s.has_cloth_data, "non-empty cloth mapping → has_cloth_data");

        // (b) one inner array with 0 elements → has_cloth_data false.
        let mut no = Vec::new();
        push_section_prefix(&mut no, 0x01, 0, 0, 0, false, 3, true, true, 0);
        no.extend_from_slice(&1i32.to_le_bytes()); // cloth outer count = 1
        push_cloth_inner(&mut no, 0); // one inner array, 0 elements
        push_section_suffix(&mut no, &[], 0, 0, 0);
        no.extend_from_slice(&0i32.to_le_bytes()); // bDisabled
        let s = read_skel_mesh_section_render(&mut Cursor::new(no.as_slice()), &ctx, "M")
            .expect("decode");
        assert!(
            !s.has_cloth_data,
            "empty cloth mapping array → !has_cloth_data"
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

    /// `has_cloth_data` over the LEGACY single-array cloth shape
    /// (`FUE5ReleaseStream < AddClothMappingLODBias`): true iff the single inner
    /// `FMeshToMeshVertData[]` is non-empty, false when it's empty. The new-shape
    /// counterpart (line ~478) is pinned by
    /// `..._has_cloth_data_tracks_nonempty_mapping`; this pins the legacy `|=`
    /// derivation (line ~489) against the `&=` / `>`→`==`/`<`/`>=` mutants — both
    /// arms are required (`inner > 0` kills `&=`, `>`→`==`, `>`→`<`; `inner == 0`
    /// kills `>`→`>=`).
    #[test]
    fn read_skel_mesh_section_render_legacy_cloth_has_cloth_data_tracks_nonempty() {
        let ctx = section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS - 1, // off → legacy single array
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        );

        // (a) single inner array with 1 element → has_cloth_data true.
        let mut yes = Vec::new();
        push_section_prefix(&mut yes, 0x01, 0, 0, 0, false, 3, true, true, 0);
        push_cloth_inner(&mut yes, 1); // ONE inner array, 1 element (no outer count)
        push_section_suffix(&mut yes, &[], 0, 0, 0);
        yes.extend_from_slice(&0i32.to_le_bytes()); // bDisabled
        let s = read_skel_mesh_section_render(&mut Cursor::new(yes.as_slice()), &ctx, "M")
            .expect("decode");
        assert!(
            s.has_cloth_data,
            "legacy non-empty cloth mapping → has_cloth_data"
        );

        // (b) single inner array with 0 elements → has_cloth_data false.
        let mut no = Vec::new();
        push_section_prefix(&mut no, 0x01, 0, 0, 0, false, 3, true, true, 0);
        push_cloth_inner(&mut no, 0); // ONE inner array, 0 elements
        push_section_suffix(&mut no, &[], 0, 0, 0);
        no.extend_from_slice(&0i32.to_le_bytes()); // bDisabled
        let s = read_skel_mesh_section_render(&mut Cursor::new(no.as_slice()), &ctx, "M")
            .expect("decode");
        assert!(
            !s.has_cloth_data,
            "legacy empty cloth mapping array → !has_cloth_data"
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

    // ===== Task 3 + 4: read_static_lod_model / read_typed LOD-0 wiring =====

    /// Append one complete cooked `FSkelMeshSection` matching the all-gates-on
    /// `section_ctx(.., 518, None)` wire shape (class strip `0x01` → dup arrays
    /// absent; new cloth shape). The section's `bone_map` is `bone_map`.
    fn push_one_section(buf: &mut Vec<u8>, bone_map: &[u16]) {
        push_section_prefix(buf, 0x01, 7, 12, 34, true, 1, false, false, 99);
        // ClothMappingDataLODs (new shape): outer count 0 (no cloth).
        buf.extend_from_slice(&0i32.to_le_bytes());
        push_section_suffix(buf, bone_map, 100, 4, -1);
        // bDisabled (bool32, gate ON).
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// `AssetContext` for `read_static_lod_model` tests: all section gates ON,
    /// UE4 (`ue4=518`, `ue5=None`) so the section's cloth path is the new shape
    /// and dup-vert arrays are absent. Mirrors `section_ctx(.., 518, None)` with
    /// every gate at/above its enabling position.
    fn lod_ctx() -> AssetContext {
        section_ctx(
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            REFACTOR_MESH_EDITOR_MATERIALS,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
            518,
            None,
        )
    }

    /// Append a UE bulk-array header (`elementSize: i32`, `elementCount: i32`).
    fn bulk_header(buf: &mut Vec<u8>, element_size: i32, element_count: i32) {
        buf.extend_from_slice(&element_size.to_le_bytes());
        buf.extend_from_slice(&element_count.to_le_bytes());
    }

    /// Append one `u16`-array: an `i32` count + count×`u16` LE.
    fn push_u16_array(buf: &mut Vec<u8>, values: &[u16]) {
        buf.extend_from_slice(&i32::try_from(values.len()).unwrap().to_le_bytes());
        for &v in values {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    #[test]
    fn read_static_lod_model_inlined_lod() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        // 1. FStripDataFlags: global=0x00 (NOT AV-stripped), class=0x05 (a
        //    non-zero class byte, surfaced as LodHeader::class_strip).
        bytes.extend_from_slice(&[0x00u8, 0x05]);
        // 2. bIsLODCookedOut = 0 (bool32).
        bytes.extend_from_slice(&0i32.to_le_bytes());
        // 3. bInlined = 1 (bool32).
        bytes.extend_from_slice(&1i32.to_le_bytes());
        // 4. RequiredBones: count 2 + [5, 7].
        push_u16_array(&mut bytes, &[5, 7]);
        // 5a. Sections: count 1 + one section (bone_map [10, 11]).
        bytes.extend_from_slice(&1i32.to_le_bytes());
        push_one_section(&mut bytes, &[10, 11]);
        // 5b. ActiveBoneIndices: count 2 + [3, 4].
        push_u16_array(&mut bytes, &[3, 4]);
        // 5c. BuffersSize: u32 (blob-start marker).
        bytes.extend_from_slice(&99u32.to_le_bytes());
        let blob_start = bytes.len() as u64;
        // Trailing blob bytes PR4 must NOT read.
        bytes.extend_from_slice(&[0xABu8; 16]);

        let mut cur = Cursor::new(bytes.as_slice());
        let header = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").expect("decode LOD");
        let lod = &header.lod;
        // strip global=0x00 (not AV-stripped), cooked_out=false, bInlined=true →
        // inlined && block_present (all three conditions satisfied); the surfaced
        // BuffersSize is the u32 written (99).
        assert!(header.inlined, "bInlined=1 must surface inlined=true");
        assert!(
            header.block_present,
            "non-stripped non-cooked-out LOD must surface block_present=true"
        );
        assert_eq!(
            header.buffers_size, 99,
            "the BuffersSize u32 must be surfaced for the read_typed seek"
        );
        assert_eq!(
            header.class_strip, 0x05,
            "the FStripDataFlags class byte must be surfaced as class_strip"
        );
        assert_eq!(lod.sections.len(), 1);
        assert_eq!(lod.sections[0].bone_map, vec![10u16, 11]);
        assert_eq!(lod.required_bones, vec![5u16, 7]);
        assert_eq!(lod.active_bone_indices, vec![3u16, 4]);
        // bone_map = stable dedup-union of the sections' bone_maps.
        assert_eq!(lod.bone_map, vec![10u16, 11]);
        // PR5 fields stay empty.
        assert!(lod.positions.is_empty());
        assert!(lod.indices.is_empty());
        // Cursor stops at blob-start (right after BuffersSize), NOT at EOF.
        assert_eq!(
            cur.position(),
            blob_start,
            "read_static_lod_model must stop at blob-start, leaving the blob unread"
        );
    }

    // ===== Task 3: skip_availability_info (the byte-exact bulk-LOD reader) =====

    /// UE4.25+ (new skin-weight format, ANIM ≥ `UnlimitedBoneInfluences`),
    /// adjacency PRESENT (no UE5_RELEASE stamp → `is_none_or` true), class=0 (not
    /// stripped), no cloth sections, profiles count 0. The worked example:
    /// `constant = 5 + 5(adj) + 16 + 8 + 8 + 24(meta) = 66`, then `profiles
    /// count` i32 = 0 → total `66 + 4 = 70` bytes consumed.
    #[test]
    fn skip_availability_info_modern_no_cloth() {
        // ANIM ≥ 5 (new format → meta 24), UE5_RELEASE unstamped here so adjacency
        // is present; build via a ctx without the UE5_RELEASE plugin.
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: ANIM_OBJECT_VERSION_GUID,
                    version: UNLIMITED_BONE_INFLUENCES,
                },
                CustomVersion {
                    guid: UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
                    version: 0, // below INCREASED_SKIN_WEIGHT_PRECISION → +0
                },
            ],
        };
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
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
        );

        let mut bytes = vec![0xAAu8; 66]; // 5+5+16+8+8+24 constant region
        bytes.extend_from_slice(&0i32.to_le_bytes()); // profiles count = 0
        let total = bytes.len() as u64;
        assert_eq!(total, 70, "the worked example is 66 + 4 = 70 bytes");

        let mut cur = Cursor::new(bytes.as_slice());
        skip_availability_info(&mut cur, &ctx, "Mesh.uasset", &[], 0)
            .expect("modern no-cloth availability-info");
        assert_eq!(
            cur.position(),
            total,
            "must consume exactly the 66-byte constant region + the 4-byte profiles count"
        );
    }

    /// UE4.24 (legacy skin-weight format, ANIM < `UnlimitedBoneInfluences` /
    /// unstamped → metadata 12), adjacency PRESENT (UE5_RELEASE unstamped),
    /// class=0, no cloth, profiles 0:
    /// `5 + 5 + 16 + 8 + 8 + 12 = 54` constant, then `+4` profiles → `58`.
    #[test]
    fn skip_availability_info_legacy_metadata_12() {
        // No ANIM stamp → new_format false → metadata 12. No UE5_RELEASE stamp →
        // adjacency present.
        let custom_versions = CustomVersionContainer { versions: vec![] };
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
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
        );

        let mut bytes = vec![0xAAu8; 54]; // 5+5+16+8+8+12 constant region
        bytes.extend_from_slice(&0i32.to_le_bytes()); // profiles count = 0
        let total = bytes.len() as u64;
        assert_eq!(total, 58, "legacy metadata 12 → 54 + 4 = 58 bytes");

        let mut cur = Cursor::new(bytes.as_slice());
        skip_availability_info(&mut cur, &ctx, "Mesh.uasset", &[], 0)
            .expect("legacy metadata-12 availability-info");
        assert_eq!(
            cur.position(),
            total,
            "legacy metadata 12 consumes 58 bytes"
        );
    }

    /// A section with `has_cloth_data` drives the live cloth block. UE4
    /// (UE5_RELEASE below `AddClothMappingLODBias` → the `num × 4` LOD-bias tail
    /// is ABSENT). With `num = 2`: constant `5+5+16+8+8+24 = 66` (modern, adjacency
    /// present), then cloth `i32 count(=2)` + `2 × 8` + `8` = `4 + 16 + 8 = 28`,
    /// then profiles `i32 count(=0)` = `4`. Total `66 + 28 + 4 = 98`.
    #[test]
    fn skip_availability_info_with_cloth() {
        // ANIM ≥ 5 (meta 24), adjacency present (no UE5_RELEASE stamp).
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: ANIM_OBJECT_VERSION_GUID,
                    version: UNLIMITED_BONE_INFLUENCES,
                },
                CustomVersion {
                    guid: UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
                    version: 0,
                },
            ],
        };
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
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
        );

        let sections = [SkelMeshSection {
            has_cloth_data: true,
            ..SkelMeshSection::default()
        }];

        let mut bytes = vec![0xAAu8; 66]; // constant region (modern, adjacency)
        bytes.extend_from_slice(&2i32.to_le_bytes()); // cloth num = 2
        bytes.extend_from_slice(&[0xAAu8; 16 + 8]); // num*8 + 8
        bytes.extend_from_slice(&0i32.to_le_bytes()); // profiles count = 0
        let total = bytes.len() as u64;
        assert_eq!(total, 98, "modern + cloth(num=2) + profiles 0 = 98 bytes");

        let mut cur = Cursor::new(bytes.as_slice());
        skip_availability_info(&mut cur, &ctx, "Mesh.uasset", &sections, 0)
            .expect("with-cloth availability-info");
        assert_eq!(
            cur.position(),
            total,
            "the cloth block (num*8 + 8) must be consumed when a section has cloth"
        );
    }

    /// `lod_class = 0x01` (`STRIP_FLAG_ADJACENCY_DATA` set) → the 5 adjacency
    /// metadata bytes are ABSENT. Modern (meta 24), adjacency unstamped on the
    /// version side BUT class-stripped → adjacency gate false:
    /// `5 + 0 + 16 + 8 + 8 + 24 = 61` constant, `+4` profiles → `65`.
    #[test]
    fn skip_availability_info_adjacency_class_stripped() {
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: ANIM_OBJECT_VERSION_GUID,
                    version: UNLIMITED_BONE_INFLUENCES,
                },
                CustomVersion {
                    guid: UE5_MAIN_STREAM_OBJECT_VERSION_GUID,
                    version: 0,
                },
            ],
        };
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
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
        );

        let mut bytes = vec![0xAAu8; 61]; // 5 + 0(adj stripped) + 16 + 8 + 8 + 24
        bytes.extend_from_slice(&0i32.to_le_bytes()); // profiles count = 0
        let total = bytes.len() as u64;
        assert_eq!(total, 65, "class-stripped adjacency → 61 + 4 = 65 bytes");

        let mut cur = Cursor::new(bytes.as_slice());
        skip_availability_info(
            &mut cur,
            &ctx,
            "Mesh.uasset",
            &[],
            STRIP_FLAG_ADJACENCY_DATA,
        )
        .expect("class-stripped adjacency availability-info");
        assert_eq!(
            cur.position(),
            total,
            "the 5 adjacency bytes must be ABSENT when the class strips adjacency"
        );
    }

    /// `AssetContext` for `read_typed` LOD-0 tests: like [`skel_typed_ctx`] but
    /// with `FRenderingObjectVersion` at `rendering` (the 4.24 discriminator) and
    /// all the section gates stamped on (so the inlined LOD's section parses).
    fn lod_typed_ctx(names: &[&str], rendering: i32) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = section_custom_versions(
            8,
            3,
            rendering,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
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

    /// Direct unit test of [`read_lod_post_loop_tail`]'s UV-channel skip branch:
    /// `FRenderingObjectVersion` PRESENT-and-`< TextureStreamingMeshUVChannelData`
    /// (here `5 < 10`) fires the skip. `read_typed`'s own pre-4.24 gate rejects
    /// any version `< 36` before the loop, so this branch is only reachable by
    /// calling the tail reader directly — kept for cursor-math completeness.
    ///
    /// The skip is `i32 count + count × 4` bytes; with `count = 3` the body must
    /// consume `2 (u8) × 1 + 2 (u8) × 1 ... ` — concretely `numInlined` (1) +
    /// `numNonOptional` (1) + `dummyObjs` count (4, value 0) + UV count (4, value
    /// 3) + `3 × 4 = 12` skip bytes. The cursor must land exactly at `total_len`,
    /// pinning the `< 10` boundary AND the `n * 4` skip math (a `+`/`/`/`==`/`<=`
    /// mutant lands the cursor off `total_len` → the sentinel fires → Err).
    #[test]
    fn read_lod_post_loop_tail_uv_skip_fires_below_threshold() {
        // rendering = 5 < TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA (10) → skip fires.
        let ctx = lod_typed_ctx(&["None"], TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA - 5);
        let mut tail = Vec::new();
        tail.push(1u8); // numInlinedLODs
        tail.push(1u8); // numNonOptionalLODs
        tail.extend_from_slice(&0i32.to_le_bytes()); // dummyObjs count = 0
        tail.extend_from_slice(&3i32.to_le_bytes()); // UV-channel count = 3
        tail.extend_from_slice(&[0xAAu8; 12]); // 3 × 4 = 12 skip bytes
        let total_len = tail.len() as u64;

        let mut cur = Cursor::new(tail.as_slice());
        read_lod_post_loop_tail(&mut cur, &ctx, total_len, "Mesh.uasset")
            .expect("UV-skip tail must consume count + 3×4 bytes and land at total_len");
        assert_eq!(
            cur.position(),
            total_len,
            "the UV skip (3 × 4) must land the cursor exactly at total_len"
        );
    }

    /// Boundary companion: `FRenderingObjectVersion == TextureStreamingMesh`
    /// `UVChannelData` (10) does NOT fire the UV skip (`< 10` is strict). The tail
    /// ends after `dummyObjs` with NO UV array on the wire; the cursor must still
    /// land at `total_len`. Pins the `<` against `<=`/`==` (a `<=` mutant would
    /// try to read a UV count that isn't there → land off total_len → Err).
    #[test]
    fn read_lod_post_loop_tail_uv_skip_absent_at_threshold() {
        // rendering == 10 → the strict `< 10` gate does NOT fire; no UV array.
        let ctx = lod_typed_ctx(&["None"], TEXTURE_STREAMING_MESH_UV_CHANNEL_DATA);
        let mut tail = Vec::new();
        tail.push(1u8); // numInlinedLODs
        tail.push(1u8); // numNonOptionalLODs
        tail.extend_from_slice(&0i32.to_le_bytes()); // dummyObjs count = 0; tail ends here
        let total_len = tail.len() as u64;

        let mut cur = Cursor::new(tail.as_slice());
        read_lod_post_loop_tail(&mut cur, &ctx, total_len, "Mesh.uasset")
            .expect("at version == 10 the UV skip must NOT fire; tail ends after dummyObjs");
        assert_eq!(cur.position(), total_len, "no UV skip at the threshold");
    }

    /// Append a complete inlined LOD-0 streamed blob matching the `lod_typed_ctx`
    /// wire shape (UE4 `ue4=518`, `FUE5ReleaseStreamObjectVersion = 100` ≥
    /// `RemovingTessellation` → adjacency ABSENT; `FAnimObjectVersion` unstamped
    /// → legacy skin path; `bHasVertexColors` false → no color buffer): inner
    /// strip flags + 3-index `FMultisizeIndexContainer` + 2-vertex position +
    /// 2-vertex static-mesh-vertex (1 UV channel) + 2-vertex legacy skin weights +
    /// `FSkinWeightProfilesData` count 0. SoA-aligned (2 verts everywhere).
    /// (`lod_typed_ctx`'s `FUE5ReleaseStreamObjectVersion` ≥ `RemovingTessellation`,
    /// so the adjacency buffer is absent from this blob.)
    fn push_streamed_blob(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0u8, 0u8]); // inner FStripDataFlags (not AV-stripped)
        push_multisize_index_16(buf, &[0, 1, 2]); // Indices
        push_position_buffer(buf, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]); // 2 positions
        push_static_mesh_vertex_buffer(buf, 2); // normals/tangents/uvs
        push_skin_weight_legacy(buf, 2); // bone indices/weights
        // bHasVertexColors=false → no ColorVertexBuffer.
        // adjacency ABSENT (lod_typed_ctx's UE5_RELEASE ≥ RemovingTessellation).
        buf.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count = 0
        // No ray-tracing / version-gated tail is written: read_streamed_data
        // stops after profiles, and read_typed's BuffersSize seek skips any tail.
    }

    /// Append the inlined `FStaticLODModel` HEADER common to every inlined-LOD
    /// helper: strip flags (not AV-stripped), `bIsLODCookedOut=0`, `bInlined=1`,
    /// `RequiredBones`, one `Section` (with `bone_map`), then `ActiveBoneIndices`.
    /// Stops right before the `BuffersSize` u32 — the caller writes that and the
    /// streamed blob.
    fn push_inlined_lod_header(buf: &mut Vec<u8>, bone_map: &[u16]) {
        buf.extend_from_slice(&[0x00u8, 0x00]); // strip flags: not AV-stripped
        buf.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut
        buf.extend_from_slice(&1i32.to_le_bytes()); // bInlined
        push_u16_array(buf, &[5, 7]); // RequiredBones
        buf.extend_from_slice(&1i32.to_le_bytes()); // Sections count
        push_one_section(buf, bone_map);
        push_u16_array(buf, &[3, 4]); // ActiveBoneIndices
    }

    /// Append one inlined `FStaticLODModel` record (header + streamed blob) with
    /// `BuffersSize` set to the ACTUAL streamed-blob byte length — the value
    /// `read_typed` now seeks past (`blob_start + BuffersSize`). The blob is
    /// built into a temp `Vec` so its length is known before the `BuffersSize`
    /// u32 is written, keeping the multi-LOD seek cursor-aligned.
    ///
    /// When `wrong_buffers_size` is `Some(n)`, `n` is written as the `BuffersSize`
    /// instead of the real length — used by the seek-bound / sentinel desync
    /// tests to force a mis-aligned re-sync.
    fn push_inlined_lod(buf: &mut Vec<u8>, bone_map: &[u16], wrong_buffers_size: Option<u32>) {
        push_inlined_lod_header(buf, bone_map);
        let mut blob = Vec::new();
        push_streamed_blob(&mut blob);
        let buffers_size =
            wrong_buffers_size.unwrap_or_else(|| u32::try_from(blob.len()).expect("blob fits u32"));
        buf.extend_from_slice(&buffers_size.to_le_bytes()); // BuffersSize
        buf.extend_from_slice(&blob); // the inlined streamed blob
    }

    /// Append one inlined `FStaticLODModel` record whose inlined blob has
    /// `pad_len` TRAILING bytes (filled `0xFF`) AFTER everything
    /// `read_streamed_data` consumes, with `BuffersSize == consumed + pad_len` so
    /// it points at the REAL blob end (past the padding). Simulates an
    /// unparsed UE5 / ray-tracing tail that `read_streamed_data` does not read but
    /// `BuffersSize` still spans.
    ///
    /// This makes the `blob_start + BuffersSize` SEEK load-bearing: with the seek,
    /// the cursor jumps the `pad_len` padding bytes to blob-end and the next LOD
    /// parses; WITHOUT it, the next read starts mid-padding (`0xFF…`) → the
    /// strict `bIsLODCookedOut` bool32 reads `0xFFFFFFFF` → `InvalidBool32`.
    fn push_inlined_lod_with_padding(buf: &mut Vec<u8>, bone_map: &[u16], pad_len: usize) {
        push_inlined_lod_header(buf, bone_map);
        let mut blob = Vec::new();
        push_streamed_blob(&mut blob);
        let consumed = blob.len();
        blob.extend(std::iter::repeat_n(0xFFu8, pad_len)); // unparsed tail padding
        let buffers_size = u32::try_from(consumed + pad_len).expect("blob fits u32");
        buf.extend_from_slice(&buffers_size.to_le_bytes()); // BuffersSize spans the padding
        buf.extend_from_slice(&blob); // streamed blob + trailing padding
    }

    /// Append the post-LOD-loop tail (`numInlinedLODs` u8 + `numNonOptionalLODs`
    /// u8 + `dummyObjs` i32 count + `dummy_objs × FPackageIndex`). `read_typed`'s
    /// UV-channel skip never fires for the UE4.24+ test ctxs (rendering >= 36 >
    /// 10), so the tail ends after the dummyObjs array.
    fn push_lod_tail(buf: &mut Vec<u8>, dummy_objs: i32) {
        buf.push(1u8); // numInlinedLODs (discarded)
        buf.push(1u8); // numNonOptionalLODs (discarded)
        buf.extend_from_slice(&dummy_objs.to_le_bytes()); // dummyObjs count
        for _ in 0..dummy_objs {
            buf.extend_from_slice(&0i32.to_le_bytes()); // FPackageIndex (Null)
        }
    }

    /// Append a complete cooked `LODModels` array (count + N inlined LODs) **and
    /// the post-loop tail** to a payload already built through `bCooked`, so
    /// `read_typed`'s loop + tail + cursor-landing sentinel are satisfied. Each
    /// LOD's `BuffersSize` is the real blob length.
    fn push_lod_models(buf: &mut Vec<u8>, count: i32) {
        buf.extend_from_slice(&count.to_le_bytes());
        for _ in 0..count {
            push_inlined_lod(buf, &[10, 11], None);
        }
        push_lod_tail(buf, 0);
    }

    #[test]
    fn read_typed_parses_lod0() {
        // FRenderingObjectVersion >= 36 → new cooked format. count=1 + inlined LOD.
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        push_lod_models(&mut payload, 1); // count=1 inlined LOD + the post-loop tail

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("LOD-0 parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.cooked);
        assert_eq!(data.lods.len(), 1);
        assert_eq!(data.lods[0].sections.len(), 1);
        assert_eq!(data.lods[0].required_bones, vec![5u16, 7]);
        assert_eq!(data.lods[0].active_bone_indices, vec![3u16, 4]);
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        // PR5a: the inlined LOD-0 streamed blob is now parsed → geometry filled.
        assert_eq!(data.lods[0].indices, vec![0u32, 1, 2], "indices parsed");
        assert_eq!(data.lods[0].positions.len(), 2, "positions parsed");
        assert_eq!(data.lods[0].normals.len(), 2, "normals parsed");
        assert_eq!(
            data.lods[0].bone_indices,
            vec![[1, 2, 3, 4, 0, 0, 0, 0], [1, 2, 3, 4, 0, 0, 0, 0]],
            "per-vertex bone indices parsed"
        );
        assert!(
            data.lods[0].colors.is_none(),
            "bHasVertexColors property absent → no colors"
        );
    }

    #[test]
    fn read_typed_rejects_pre_424() {
        // FRenderingObjectVersion = 35 (< MaterialShaderMapIdSerialization) →
        // pre-UE4.24 legacy cooked LOD layout, UnsupportedFeature.
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION - 1,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        push_lod_models(&mut payload, 1); // unreachable — the pre-4.24 gate rejects first

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        match err {
            PaksmithError::UnsupportedFeature { context } => {
                assert!(context.contains("pre-UE4.24"), "wrong context: {context}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn read_typed_lod_count_zero() {
        // LODModels count == 0 → no LOD to read; lods empty. The post-loop tail
        // (numInlined/numNonOptional + dummyObjs) is still on the wire under
        // UseNewCookedFormat, so push_lod_models(0) appends it and the
        // cursor-landing sentinel still passes.
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        push_lod_models(&mut payload, 0); // count=0 + the post-loop tail

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("count-0 parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.cooked);
        assert!(data.lods.is_empty(), "count==0 → no LODs parsed");
    }

    #[test]
    fn read_typed_cooked_false_has_empty_lods() {
        // Editor-data-stripped mesh with bCooked == false (a valid strict-bool
        // wire state). The oracle reads the cooked LOD array ONLY inside
        // `if (bCooked && LODModels == null)`; on the stripped path LODModels is
        // null, so the gate reduces to bCooked. With cooked == false there are NO
        // LODModels bytes after bCooked — the LOD read must be skipped entirely.
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&0i32.to_le_bytes()); // bCooked = false
        // No bytes follow bCooked in this payload. paksmith's ENTIRE LOD tail
        // (LODModels + the post-loop `numInlinedLODs` / `dummyObjs` block) is under
        // `read_typed`'s `if cooked` block, so on the cooked==false path it stops
        // right after bCooked. This is acceptable: a non-cooked editor mesh degrades
        // to a property bag rather than producing a partial parse. (paksmith only
        // ever reaches `read_typed` on the editor-data-stripped cooked path, so a
        // genuine cooked==false here is an edge case; we deliberately stop early.)

        let (asset, _bulk) =
            read_typed(&payload, &ctx, "Mesh.uasset").expect("cooked==false parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(!data.cooked);
        assert!(
            data.lods.is_empty(),
            "cooked==false → LOD read skipped, lods empty"
        );
    }

    // ===== Task 5: read_static_lod_model / read_typed LOD-0 hardening =====

    /// `bone_map` is the **stable dedup-union** of the sections' per-section
    /// `bone_map`s. Two sections with OVERLAPPING maps (A=[10,11], B=[11,12])
    /// must yield `[10,11,12]` — the shared `11` appears once, in first-seen
    /// order. Pins the `if seen.insert(bone)` dedup branch (a single-section LOD
    /// never exercises the `insert == false` arm, so a skip-dedup mutant would
    /// otherwise survive).
    #[test]
    fn read_static_lod_model_bone_map_dedup_union() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags: NOT AV-stripped
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(&mut bytes, &[5, 7]); // RequiredBones
        // Sections: count 2, overlapping bone_maps [10,11] and [11,12].
        bytes.extend_from_slice(&2i32.to_le_bytes());
        push_one_section(&mut bytes, &[10, 11]);
        push_one_section(&mut bytes, &[11, 12]);
        push_u16_array(&mut bytes, &[3, 4]); // ActiveBoneIndices
        bytes.extend_from_slice(&99u32.to_le_bytes()); // BuffersSize

        let mut cur = Cursor::new(bytes.as_slice());
        let lod = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset")
            .expect("decode LOD")
            .lod;
        assert_eq!(lod.sections.len(), 2);
        // The shared bone `11` is deduped; order is stable (first-seen).
        assert_eq!(
            lod.bone_map,
            vec![10u16, 11, 12],
            "bone_map must be the stable dedup-union of the section bone_maps"
        );
    }

    /// Gate-OFF via AV-data stripping: `global` has bit 0x02 set
    /// ([`STRIP_FLAG_AV_DATA`]) → `is_av_data_stripped(global)` true → the
    /// section/bone block (Sections + ActiveBoneIndices + BuffersSize) is ABSENT.
    /// `required_bones` is still read; the cursor stops right after
    /// `RequiredBones`. Pins the `!is_av_data_stripped(global)` term of the gate
    /// against a `condition→true` mutant (cursor-position assert catches a
    /// wrongly-ON gate regardless of what the trailing sentinel bytes decode to).
    #[test]
    fn read_static_lod_model_av_stripped_skips_section_block() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        // strip flags: global = 0x02 (AV data stripped), class = 0.
        bytes.extend_from_slice(&[crate::asset::wire::STRIP_FLAG_AV_DATA, 0x00]);
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(&mut bytes, &[5, 7]); // RequiredBones
        let after_required = bytes.len() as u64;
        // Trailing sentinel bytes that, if the gate wrongly fired ON, would be
        // mis-read as a Sections count — the cursor-position assert catches that.
        bytes.extend_from_slice(&[0xABu8; 16]);

        let mut cur = Cursor::new(bytes.as_slice());
        let header = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").expect("decode LOD");
        let lod = &header.lod;
        // av_stripped=true → block_present must be false even though bInlined=1;
        // BuffersSize stays 0 (no block on the wire).
        assert!(
            header.inlined,
            "bInlined=1 must still surface inlined=true even when AV-stripped"
        );
        assert!(
            !header.block_present,
            "AV-stripped LOD must NOT have block_present even with bInlined=1"
        );
        assert_eq!(
            header.buffers_size, 0,
            "no section/bone block → BuffersSize stays 0"
        );
        assert_eq!(lod.required_bones, vec![5u16, 7]);
        assert!(
            lod.sections.is_empty(),
            "AV-stripped LOD has no section block"
        );
        assert!(
            lod.active_bone_indices.is_empty(),
            "AV-stripped LOD has no ActiveBoneIndices"
        );
        assert!(lod.bone_map.is_empty(), "no sections → empty bone_map");
        assert_eq!(
            cur.position(),
            after_required,
            "cursor must stop right after RequiredBones when AV data is stripped"
        );
    }

    /// Gate-OFF via `bIsLODCookedOut = 1` (with `global` NOT AV-stripped) → the
    /// section/bone block is ABSENT. Pins the `!is_lod_cooked_out` term of the
    /// gate against a `condition→true` mutant and the `&&` against `||` (here the
    /// first term is true, so an `&&`→`||` would wrongly take the ON branch).
    #[test]
    fn read_static_lod_model_cooked_out_skips_section_block() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        // strip flags: global = 0x00 (NOT AV-stripped) so only bIsLODCookedOut
        // gates the block off.
        bytes.extend_from_slice(&[0x00u8, 0x00]);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bIsLODCookedOut = 1
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(&mut bytes, &[5, 7]); // RequiredBones
        let after_required = bytes.len() as u64;
        bytes.extend_from_slice(&[0xABu8; 16]); // trailing sentinel

        let mut cur = Cursor::new(bytes.as_slice());
        let header = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").expect("decode LOD");
        let lod = &header.lod;
        // is_lod_cooked_out=true → block_present must be false even though
        // bInlined=1; BuffersSize stays 0 (no block on the wire).
        assert!(
            header.inlined,
            "bInlined=1 must still surface inlined=true even when cooked out"
        );
        assert!(
            !header.block_present,
            "cooked-out LOD must NOT have block_present even with bInlined=1"
        );
        assert_eq!(
            header.buffers_size, 0,
            "no section/bone block → BuffersSize stays 0"
        );
        assert_eq!(lod.required_bones, vec![5u16, 7]);
        assert!(
            lod.sections.is_empty(),
            "cooked-out LOD has no section block"
        );
        assert!(
            lod.active_bone_indices.is_empty(),
            "cooked-out LOD has no ActiveBoneIndices"
        );
        assert_eq!(
            cur.position(),
            after_required,
            "cursor must stop right after RequiredBones when the LOD is cooked out"
        );
    }

    /// Over-cap `LODModels` count (`MAX_LODS_PER_MESH + 1` = 65) is rejected by
    /// `read_capped_count` BEFORE any LOD parse, as `BoundsExceeded {
    /// SkelLodCount, value: 65, limit: 64 }`.
    #[test]
    fn read_typed_over_cap_lod_count_is_rejected() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        let over_cap = i32::try_from(MAX_LODS_PER_MESH + 1).unwrap(); // 65
        payload.extend_from_slice(&over_cap.to_le_bytes());

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelLodCount,
                        value: 65,
                        limit: 64,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelLodCount, 65 > 64), got {err:?}"
        );
    }

    /// Over-cap post-loop `dummyObjs` count (`MAX_DUMMY_OBJECTS_U32 + 1`) is
    /// rejected by `read_capped_count` BEFORE any `FPackageIndex` allocation, as
    /// `BoundsExceeded { SkelDummyObjCount, value: 4097, limit: 4096 }`. The bare
    /// over-cap count i32 is written with NO entries following — the cap fires
    /// first. Pins `dummyObjs` at the DEDICATED `MAX_DUMMY_OBJECTS_U32` cap
    /// (4096), distinct from the LOD cap (64); a count of 65 would now PASS.
    #[test]
    fn read_typed_over_cap_dummy_objects_is_rejected() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&0i32.to_le_bytes()); // LODModels count = 0
        payload.push(1u8); // numInlinedLODs
        payload.push(1u8); // numNonOptionalLODs
        let over_cap = (MAX_DUMMY_OBJECTS_U32 + 1).cast_signed(); // 4097
        payload.extend_from_slice(&over_cap.to_le_bytes()); // dummyObjs count (no entries follow)

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelDummyObjCount,
                        value: 4097,
                        limit: 4096,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelDummyObjCount, 4097 > 4096), got {err:?}"
        );
    }

    /// A `dummyObjs` count just OVER the old LOD cap (65) but UNDER the dedicated
    /// `MAX_DUMMY_OBJECTS_U32` (4096) must be ACCEPTED — proves the cap is the
    /// dedicated 4096 bound, not the reused 64 LOD cap. The 65 `FPackageIndex`
    /// entries are consumed and the cursor still lands at `total_len`.
    #[test]
    fn read_typed_dummy_objects_above_lod_cap_is_accepted() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&0i32.to_le_bytes()); // LODModels count = 0
        // 65 dummyObjs: over the 64 LOD cap, under the 4096 dummy cap → accepted.
        push_lod_tail(&mut payload, 65);

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset")
            .expect("65 dummyObjs is under the dedicated 4096 cap → accepted");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.lods.is_empty(), "count==0 → no LODs");
    }

    /// Over-cap `RequiredBones` count (`MAX_REQUIRED_BONES + 1`) → `BoundsExceeded
    /// { SkelLodRequiredBonesCount, .. }` before any bone is read.
    #[test]
    fn read_static_lod_model_over_cap_required_bones_is_rejected() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        // RequiredBones count = cap + 1 — fires on the i32 alone.
        let over_cap = i32::try_from(MAX_REQUIRED_BONES + 1).unwrap();
        bytes.extend_from_slice(&over_cap.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelLodRequiredBonesCount,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelLodRequiredBonesCount), got {err:?}"
        );
    }

    /// Over-cap `Sections` count (`MAX_SECTIONS_PER_LOD + 1` = 257) → `BoundsExceeded
    /// { SkelLodSectionCount, .. }` before any section is read.
    #[test]
    fn read_static_lod_model_over_cap_sections_is_rejected() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags: NOT AV-stripped
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0 → block present
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(&mut bytes, &[]); // RequiredBones empty
        // Sections count = cap + 1 — fires on the i32 alone.
        let over_cap = i32::try_from(MAX_SECTIONS_PER_LOD + 1).unwrap();
        bytes.extend_from_slice(&over_cap.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelLodSectionCount,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelLodSectionCount), got {err:?}"
        );
    }

    /// Over-cap `ActiveBoneIndices` count (`MAX_ACTIVE_BONES + 1`) → `BoundsExceeded
    /// { SkelLodActiveBonesCount, .. }`. Sections count = 0 first so no section
    /// body / name-table is needed to reach the ActiveBoneIndices read.
    #[test]
    fn read_static_lod_model_over_cap_active_bones_is_rejected() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags: NOT AV-stripped
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0 → block present
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(&mut bytes, &[]); // RequiredBones empty
        bytes.extend_from_slice(&0i32.to_le_bytes()); // Sections count = 0
        // ActiveBoneIndices count = cap + 1.
        let over_cap = i32::try_from(MAX_ACTIVE_BONES + 1).unwrap();
        bytes.extend_from_slice(&over_cap.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::SkelLodActiveBonesCount,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(SkelLodActiveBonesCount), got {err:?}"
        );
    }

    /// The 4.24 gate proceeds when `FRenderingObjectVersion` is ABSENT
    /// (unversioned package — the shipping-game norm). The `is_some_and` gate
    /// must NOT reject a `None` version; pins it against an `is_some_and`→
    /// `is_none_or` mutant.
    ///
    /// Because the rendering GUID is omitted, `read_skeletal_material`'s
    /// `UVChannelData` gate (`rendering >= 10`) is also OFF, so the material is
    /// the 16-byte variant (no `FMeshUVChannelInfo`). A hand-built prefix carries
    /// that 16-byte material; `LODModels count = 0` proves the gate did not reject
    /// (a valid LOD-0 body isn't needed).
    #[test]
    fn read_typed_absent_rendering_version_proceeds() {
        // ctx WITHOUT FRenderingObjectVersion: stamp only the plugins the prefix
        // needs (editor=8, core=3 for the material gates; skel_mesh = SPLIT for
        // the modern branch). UE4 single-precision.
        let table = NameTable {
            names: ["None", "Mat0", "Root", "Hip"]
                .iter()
                .map(|n| FName::new(n))
                .collect(),
        };
        let custom_versions = CustomVersionContainer {
            versions: vec![
                CustomVersion {
                    guid: EDITOR_OBJECT_VERSION_GUID,
                    version: REFACTOR_MESH_EDITOR_MATERIALS, // 8 → SlotName present
                },
                CustomVersion {
                    guid: CORE_OBJECT_VERSION_GUID,
                    version: SKELETAL_MATERIAL_EDITOR_DATA_STRIPPING, // 3 → bSerialize present
                },
                CustomVersion {
                    guid: SKELETAL_MESH_CUSTOM_VERSION_GUID,
                    version: SPLIT_MODEL_AND_RENDER_DATA,
                },
                // FRenderingObjectVersion deliberately ABSENT.
            ],
        };
        let ctx = AssetContext::new(
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
        );

        let mut payload = Vec::new();
        // Segment 1.
        crate::asset::property::test_utils::write_object_end(&mut payload);
        // FStripDataFlags: editor data stripped (cooked path), class 0.
        payload.extend_from_slice(&[crate::asset::wire::STRIP_FLAG_EDITOR_DATA, 0x00]);
        // ImportedBounds (UE4 28B).
        for v in [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0] {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        // SkeletalMaterials: count 1 + one 16-byte material (NO UVChannelData,
        // since the rendering gate is OFF): FPackageIndex(4) + SlotName(8) +
        // bSerializeImported=0(4).
        payload.extend_from_slice(&1i32.to_le_bytes());
        payload.extend_from_slice(&0i32.to_le_bytes()); // Material FPackageIndex
        fname(&mut payload, 1); // MaterialSlotName "Mat0"
        payload.extend_from_slice(&0i32.to_le_bytes()); // bSerializeImported = 0
        // FReferenceSkeleton (2 bones at FName 2/3).
        two_bone_reference_skeleton(&mut payload, 2, 3);
        // bCooked = true.
        payload.extend_from_slice(&1i32.to_le_bytes());
        // LODModels count = 0 → proves the gate did not reject (no LOD body).
        payload.extend_from_slice(&0i32.to_le_bytes());
        // Post-loop tail: absent FRenderingObjectVersion → the UV-channel skip's
        // is_some_and gate does NOT fire, so the tail ends after dummyObjs.
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) =
            read_typed(&payload, &ctx, "Mesh.uasset").expect("absent rendering version proceeds");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.cooked);
        assert!(
            data.lods.is_empty(),
            "count==0 → no LODs, but the parse must SUCCEED (gate did not reject)"
        );
    }

    /// A non-strict `bIsLODCookedOut` wire value of `2` (neither 0 nor 1) is
    /// rejected by `read_bool32` as `InvalidBool32 { SkelLodCookedOut, observed:
    /// 2 }`. Documents the legacy-as-new safety backstop for unversioned packages
    /// (a `SerializeRenderItem_Legacy` mis-parse lands on a non-bool here).
    #[test]
    fn read_static_lod_model_non_strict_cooked_out_bool_is_rejected() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bIsLODCookedOut = 2 → invalid

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidBool32 {
                        field: AssetWireField::SkelLodCookedOut,
                        observed: 2,
                    },
                    ..
                }
            ),
            "expected InvalidBool32(SkelLodCookedOut, 2), got {err:?}"
        );
    }

    /// A non-strict `bInlined` wire value of `2` is rejected as `InvalidBool32 {
    /// SkelLodInlined, observed: 2 }` — the second strict-bool backstop.
    #[test]
    fn read_static_lod_model_non_strict_inlined_bool_is_rejected() {
        let ctx = lod_ctx();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0 (valid)
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bInlined = 2 → invalid

        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidBool32 {
                        field: AssetWireField::SkelLodInlined,
                        observed: 2,
                    },
                    ..
                }
            ),
            "expected InvalidBool32(SkelLodInlined, 2), got {err:?}"
        );
    }

    /// A payload cut mid-LOD-record surfaces as a typed `Err` (`AssetParse`/`Io`),
    /// never a panic. Two cut points: (a) after `bInlined`, before `RequiredBones`
    /// (the count i32 is absent); (b) mid-section (Sections count says 1 but the
    /// section body runs short).
    #[test]
    fn read_static_lod_model_truncated_is_typed_error() {
        let ctx = lod_ctx();

        // (a) Valid through bInlined, then EOF (RequiredBones count absent).
        {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags
            bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
            bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
            // RequiredBones count absent → EOF.
            let mut cur = Cursor::new(bytes.as_slice());
            let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-a must return typed error, got {err:?}"
            );
        }

        // (b) Valid through Sections count = 1, then a truncated section body
        //     (only the 2 strip-flag bytes present; the rest of the section is
        //     absent) → the nested read_skel_mesh_section_render faults.
        {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&[0x00u8, 0x00]); // strip flags: NOT AV-stripped
            bytes.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
            bytes.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
            push_u16_array(&mut bytes, &[]); // RequiredBones empty
            bytes.extend_from_slice(&1i32.to_le_bytes()); // Sections count = 1
            bytes.extend_from_slice(&[0x00u8, 0x00]); // section strip flags only, then EOF
            let mut cur = Cursor::new(bytes.as_slice());
            let err = read_static_lod_model(&mut cur, &ctx, "Mesh.uasset").unwrap_err();
            assert!(
                matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
                "truncation-b must return typed error, got {err:?}"
            );
        }
    }

    /// `LODModels count == 2` iterates BOTH inlined LODs (`lods.len() == 2`),
    /// each with its geometry populated — the PR5b multi-LOD iteration. Each
    /// LOD's `BuffersSize` equals the real blob length, so the structural parse
    /// already lands the cursor on LOD[1] and the seek is a no-op here (a
    /// non-no-op seek that drives iteration past an over/under-read tail is
    /// exercised by the Task-6 hardening tests). Pins the loop against a `count`
    /// / LOD-0-only drift and proves both LODs decode geometry.
    #[test]
    fn read_typed_count_two_parses_both_lods() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        // count = 2: two inlined LODs (distinct bone_maps) + the post-loop tail.
        payload.extend_from_slice(&2i32.to_le_bytes());
        push_inlined_lod(&mut payload, &[10, 11], None);
        push_inlined_lod(&mut payload, &[20, 21], None);
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset").expect("count-2 parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(
            data.lods.len(),
            2,
            "count==2 must iterate BOTH inlined LODs"
        );
        // Both LODs carry their distinct bone_map + decoded geometry.
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        assert_eq!(data.lods[1].bone_map, vec![20u16, 21]);
        for (i, lod) in data.lods.iter().enumerate() {
            assert_eq!(lod.indices, vec![0u32, 1, 2], "LOD[{i}] indices parsed");
            assert_eq!(lod.positions.len(), 2, "LOD[{i}] positions parsed");
            assert_eq!(lod.normals.len(), 2, "LOD[{i}] normals parsed");
            assert_eq!(
                lod.bone_indices,
                vec![[1, 2, 3, 4, 0, 0, 0, 0], [1, 2, 3, 4, 0, 0, 0, 0]],
                "LOD[{i}] per-vertex bone indices parsed"
            );
        }
    }

    /// LOAD-BEARING: proves the `blob_start + BuffersSize` SEEK (not the
    /// structural parse) drives multi-LOD iteration. Each LOD blob carries `K=8`
    /// TRAILING padding bytes AFTER everything `read_streamed_data` consumes, and
    /// `BuffersSize` spans them. So `read_streamed_data` leaves the cursor at
    /// `blob_end - K` (mid-blob); only the SEEK to `blob_start + BuffersSize`
    /// jumps the padding to land on LOD[1].
    ///
    /// Discrimination (verified RED→GREEN by neutering `cur.seek` to a no-op):
    /// WITHOUT the seek the cursor sits in the `0xFF…` padding, so LOD[1]'s
    /// strict `bIsLODCookedOut` bool32 reads `0xFFFFFFFF` → `InvalidBool32` (Err).
    /// WITH the seek the padding is jumped → LOD[1] parses → `Ok`, both LODs'
    /// geometry populated. Mutation-pins the seek `SeekFrom::Start(target)` (a
    /// no-op / wrong-offset mutant of the seek breaks this).
    #[test]
    fn read_typed_seek_drives_iteration_over_unparsed_tail() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&2i32.to_le_bytes()); // LODModels count = 2
        // Each LOD blob has K=8 trailing 0xFF padding bytes that read_streamed_data
        // does NOT consume; only the seek jumps them to reach the next LOD.
        push_inlined_lod_with_padding(&mut payload, &[10, 11], 8);
        push_inlined_lod_with_padding(&mut payload, &[20, 21], 8);
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset")
            .expect("the seek must jump the unparsed tail padding to land on LOD[1]");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(
            data.lods.len(),
            2,
            "the seek over the padding must land on LOD[1] → both LODs parsed"
        );
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        assert_eq!(data.lods[1].bone_map, vec![20u16, 21]);
        for (i, lod) in data.lods.iter().enumerate() {
            assert_eq!(lod.indices, vec![0u32, 1, 2], "LOD[{i}] indices parsed");
            assert_eq!(lod.positions.len(), 2, "LOD[{i}] positions parsed");
            assert_eq!(
                lod.bone_indices,
                vec![[1, 2, 3, 4, 0, 0, 0, 0], [1, 2, 3, 4, 0, 0, 0, 0]],
                "LOD[{i}] per-vertex bone indices parsed"
            );
        }
    }

    /// Like [`lod_typed_ctx`] but at `file_version_ue4 = 522` (the UE4.27 object
    /// proxy → `is_ue4_27_or_later()` true). Used to prove `read_streamed_data`
    /// does NOT read the (now-removed) ray-tracing tail and the `BuffersSize` seek
    /// skips it.
    fn lod_typed_ctx_ue4_27(names: &[&str], rendering: i32) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        let custom_versions = section_custom_versions(
            8,
            3,
            rendering,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS,
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522, // UE4.27 proxy → is_ue4_27_or_later true
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    /// At `ue4=522` (the UE4.27 object proxy, which a UE4.26 cooked mesh ALSO
    /// stamps), a 4.26-shaped inlined LOD blob carries NO version-gated tail —
    /// `push_inlined_lod` ends right after `FSkinWeightProfilesData` and sets
    /// `BuffersSize` to that exact length. Both LODs must parse and the cursor must
    /// land at `total_len` (`Ok`, no degrade).
    ///
    /// Discrimination (RED pre-fix): the removed `is_ue4_27_or_later()` ray-tracing
    /// read fired at `ue4=522` and consumed the next LOD's header bytes (`[0,0]`
    /// strip + `0i32` cooked-out) as a spurious ray-tracing count+skip → the cursor
    /// overshoots `blob_start + BuffersSize` → the forward-only seek bound rejects
    /// the target → `SkeletalLodCursorDesync` → Generic. Post-fix `read_streamed_data`
    /// stops after profiles → the no-op seek lands on LOD[1] → both parse. (The
    /// 4.27 tail-present path is NOT observable through the fix — the seek lands on
    /// the same target whether the tail is read or skipped — so the only red-first
    /// witness is this 4.26-no-tail shape. Seek-skips-unconsumed-bytes is covered
    /// version-invariantly by `read_typed_seek_drives_iteration_over_unparsed_tail`.)
    #[test]
    fn read_typed_ue4_26_shape_at_522_no_spurious_tail_read() {
        let ctx = lod_typed_ctx_ue4_27(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&2i32.to_le_bytes()); // LODModels count = 2
        // 4.26-shaped blobs: no version-gated tail; BuffersSize == real blob length.
        push_inlined_lod(&mut payload, &[10, 11], None);
        push_inlined_lod(&mut payload, &[20, 21], None);
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) = read_typed(&payload, &ctx, "Mesh.uasset")
            .expect("at ue4=522 a 4.26-no-tail blob must parse both LODs (no spurious tail read)");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(
            data.lods.len(),
            2,
            "no spurious ray-tracing read at 522 → both LODs parsed"
        );
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        assert_eq!(data.lods[1].bone_map, vec![20u16, 21]);
        for (i, lod) in data.lods.iter().enumerate() {
            assert_eq!(lod.indices, vec![0u32, 1, 2], "LOD[{i}] indices parsed");
            assert_eq!(lod.positions.len(), 2, "LOD[{i}] positions parsed");
            assert_eq!(
                lod.bone_indices,
                vec![[1, 2, 3, 4, 0, 0, 0, 0], [1, 2, 3, 4, 0, 0, 0, 0]],
                "LOD[{i}] per-vertex bone indices parsed"
            );
        }
    }

    /// Append a non-inlined (bulk) `FStaticLODModel` record: the header
    /// (`bInlined=0`, block present, `BuffersSize=0`), then an `FByteBulkData`
    /// header whose flags are `BULKDATA_PayloadAtEndOfFile (0x01)` — NON-inline,
    /// so `read_from` consumes ONLY the 20-byte header (no inline payload) — with
    /// `element_count = 1 > 0` so the availability-info skip fires, then the
    /// availability-info bytes for `lod_typed_ctx` (ANIM unstamped → metadata 12;
    /// `FUE5ReleaseStreamObjectVersion = ADD_CLOTH_MAPPING_LOD_BIAS (15)
    /// ≥ RemovingTessellation (3)` → adjacency ABSENT; class=0; the section has no
    /// cloth so the cloth block — incl. the `≥ AddClothMappingLODBias` LOD-bias
    /// tail — does not fire): constant `5 + 0 + 16 + 8 + 8 + 12 = 49`, then
    /// `profiles count` i32 = 0 → `49 + 4 = 53` bytes.
    fn push_non_inlined_lod(buf: &mut Vec<u8>, bone_map: &[u16]) {
        // Header (block present, bInlined = 0).
        buf.extend_from_slice(&[0x00u8, 0x00]); // strip flags: not AV-stripped, class=0
        buf.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        buf.extend_from_slice(&0i32.to_le_bytes()); // bInlined = 0 (NOT inlined)
        push_u16_array(buf, &[5, 7]); // RequiredBones
        buf.extend_from_slice(&1i32.to_le_bytes()); // Sections count
        push_one_section(buf, bone_map);
        push_u16_array(buf, &[3, 4]); // ActiveBoneIndices
        buf.extend_from_slice(&0u32.to_le_bytes()); // BuffersSize (no inline blob)

        // FByteBulkData header (20 bytes): u32 flags + i32 count + u32 size + i64 offset.
        // flags = 0x01 (PayloadAtEndOfFile) → payload_is_inline() == false → header only.
        buf.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // BulkDataFlags
        buf.extend_from_slice(&1i32.to_le_bytes()); // ElementCount = 1 (> 0)
        buf.extend_from_slice(&0u32.to_le_bytes()); // SizeOnDisk = 0
        buf.extend_from_slice(&0i64.to_le_bytes()); // OffsetInFile = 0

        // SerializeAvailabilityInfo (53 bytes for lod_typed_ctx, see fn doc).
        buf.extend_from_slice(&[0xAAu8; 49]); // 5 + 0(adj absent) + 16 + 8 + 8 + 12
        buf.extend_from_slice(&0i32.to_le_bytes()); // SkinWeightProfiles count = 0
    }

    /// A non-inlined (bulk) LOD (`bInlined=0`) with the section/bone block PRESENT
    /// now PARSES: `read_typed` reads the `FByteBulkData` header and (since
    /// `element_count > 0`) skips the byte-exact `SerializeAvailabilityInfo`, then
    /// continues iterating. The bulk LOD's geometry stays EMPTY (the streamed data
    /// is in the external `.ubulk` / not captured), but its sections/bones are
    /// present. A mixed inline (LOD[0]) + bulk (LOD[1]) mesh parses instead of
    /// degrading to `UnsupportedFeature` (PR5b's behavior).
    #[test]
    fn read_typed_non_inlined_bulk_lod_parses() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&2i32.to_le_bytes()); // LODModels count = 2
        push_inlined_lod(&mut payload, &[10, 11], None); // LOD[0]: inlined geometry
        push_non_inlined_lod(&mut payload, &[20, 21]); // LOD[1]: bulk (empty geometry)
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) =
            read_typed(&payload, &ctx, "Mesh.uasset").expect("mixed inline + bulk LOD parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(
            data.lods.len(),
            2,
            "both the inlined and the bulk LOD must be iterated"
        );

        // LOD[0]: inlined → geometry populated.
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        assert_eq!(
            data.lods[0].indices,
            vec![0u32, 1, 2],
            "LOD[0] indices parsed"
        );
        assert_eq!(data.lods[0].positions.len(), 2, "LOD[0] positions parsed");

        // LOD[1]: bulk → geometry EMPTY, but sections/bones present.
        assert_eq!(data.lods[1].bone_map, vec![20u16, 21]);
        assert_eq!(data.lods[1].sections.len(), 1, "bulk LOD sections present");
        assert_eq!(
            data.lods[1].required_bones,
            vec![5u16, 7],
            "bulk LOD bones present"
        );
        assert!(
            data.lods[1].positions.is_empty(),
            "bulk LOD geometry stays empty (external .ubulk not captured)"
        );
        assert!(
            data.lods[1].indices.is_empty(),
            "bulk LOD indices stay empty"
        );
    }

    /// A `BuffersSize` so large that `blob_start + BuffersSize > total_len` is
    /// caught by the seek BOUND (`.filter(|t| *t <= total_len)`): the `ok_or_else`
    /// fires `SkeletalLodCursorDesync` BEFORE any `seek` — a hostile size can't
    /// seek past the payload. The whole asset degrades (`Err`, → Generic).
    #[test]
    fn read_typed_over_large_buffers_size_seek_bound_faults() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&1i32.to_le_bytes()); // LODModels count = 1
        // BuffersSize = u32::MAX → blob_start + MAX overflows / exceeds total_len.
        push_inlined_lod(&mut payload, &[10, 11], Some(u32::MAX));
        push_lod_tail(&mut payload, 0);

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::SkeletalLodCursorDesync { .. },
                    ..
                }
            ),
            "an over-large BuffersSize must fault on the seek bound, got {err:?}"
        );
    }

    /// A `BuffersSize` SMALLER than the bytes `read_streamed_data` already
    /// consumed (here `0`) would make `blob_start + BuffersSize < blob_end` — a
    /// BACKWARD seek that re-reads parsed blob bytes as the next LOD header. The
    /// forward-only `>= blob_end` lower bound faults `SkeletalLodCursorDesync`
    /// instead (no backward / wild seek). The whole asset degrades (→ Generic).
    ///
    /// Also pins the seek-bound desync's diagnostic `position`: it must report
    /// `blob_end` (the cursor AT DETECTION, where `read_streamed_data` stopped),
    /// NOT `blob_start`. `blob_end` is the payload length just before the tail.
    #[test]
    fn read_typed_too_small_buffers_size_backward_seek_faults() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&1i32.to_le_bytes()); // LODModels count = 1
        // BuffersSize = 0 → target = blob_start < blob_end (the blob is non-empty).
        push_inlined_lod(&mut payload, &[10, 11], Some(0));
        // The cursor at detection is right here — after the full LOD record, before
        // the tail — so blob_end == this length. The seek-bound desync fires before
        // the tail is read, so the tail bytes are irrelevant to `position`.
        let blob_end = payload.len() as u64;
        push_lod_tail(&mut payload, 0);

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault: AssetParseFault::SkeletalLodCursorDesync { position, expected },
                ..
            } => {
                assert_eq!(
                    position, blob_end,
                    "the seek-bound desync must report blob_end (cursor at detection), \
                     not blob_start"
                );
                assert_eq!(
                    expected,
                    payload.len() as u64,
                    "expected is the payload total_len"
                );
            }
            other => panic!("expected SkeletalLodCursorDesync, got {other:?}"),
        }
    }

    /// A correct count=1 LOD + tail, then EXTRA trailing bytes: the seek + tail
    /// both succeed but the cursor lands SHORT of `total_len`, so the
    /// cursor-landing sentinel (`cur.position() != total_len`) fires. Isolates
    /// the sentinel `!=` check (the over-large-bound test never reaches it).
    #[test]
    fn read_typed_trailing_bytes_trip_cursor_sentinel() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        push_lod_models(&mut payload, 1); // a fully-correct count=1 LOD + tail
        // Extra trailing bytes: the LODs + tail consume to here, but total_len is
        // larger → the cursor lands short → the sentinel fires.
        payload.extend_from_slice(&[0xCDu8; 8]);

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault: AssetParseFault::SkeletalLodCursorDesync { position, expected },
                ..
            } => {
                assert!(
                    position < expected,
                    "the cursor must land SHORT of total_len ({position} < {expected})"
                );
                assert_eq!(
                    expected,
                    payload.len() as u64,
                    "the sentinel's expected target is the payload total_len"
                );
            }
            other => panic!("expected SkeletalLodCursorDesync, got {other:?}"),
        }
    }

    /// Truncation MID-TAIL: a correct count=1 LOD, then only ONE tail byte
    /// (`numInlinedLODs`) — the `numNonOptionalLODs` u8 + `dummyObjs` count are
    /// missing. `read_lod_post_loop_tail` must return a typed Err (EOF), never
    /// panic. Exercises the post-loop tail's short-read path.
    #[test]
    fn read_typed_truncated_mid_tail_is_typed_error() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&1i32.to_le_bytes()); // LODModels count = 1
        push_inlined_lod(&mut payload, &[10, 11], None); // a complete LOD
        payload.push(1u8); // numInlinedLODs only — tail truncated here

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
            "a truncated post-loop tail must return a typed error, got {err:?}"
        );
    }

    /// Truncation MID-LOOP: a count=2 LODModels array but only LOD[0]'s bytes
    /// present (the loop seeks LOD[0] to its blob-end, then runs out of bytes
    /// reading LOD[1]'s header). Must return a typed Err, never panic. Exercises
    /// the loop's short-read path on the SECOND iteration.
    #[test]
    fn read_typed_truncated_mid_loop_is_typed_error() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&2i32.to_le_bytes()); // LODModels count = 2
        push_inlined_lod(&mut payload, &[10, 11], None); // LOD[0] only; LOD[1] absent

        let err = read_typed(&payload, &ctx, "Mesh.uasset").unwrap_err();
        assert!(
            matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
            "a truncated mid-loop LODModels array must return a typed error, got {err:?}"
        );
    }

    // ===== Task 6: property_bool + read_streamed_data =====

    #[test]
    fn property_bool_reads_named_bool() {
        let props = vec![
            Property {
                name: Arc::from("bHasVertexColors"),
                array_index: 0,
                guid: None,
                value: PropertyValue::Bool(true),
            },
            Property {
                name: Arc::from("bOther"),
                array_index: 0,
                guid: None,
                value: PropertyValue::Bool(false),
            },
        ];
        assert!(property_bool(&props, "bHasVertexColors"));
        // present-but-false, present-but-non-bool, and absent all default false.
        assert!(!property_bool(&props, "bOther"));
        assert!(!property_bool(&props, "bMissing"));
        let int_prop = vec![Property {
            name: Arc::from("bHasVertexColors"),
            array_index: 0,
            guid: None,
            value: PropertyValue::Int(1),
        }];
        assert!(
            !property_bool(&int_prop, "bHasVertexColors"),
            "a non-Bool value named the same must not count as true"
        );
    }

    /// Append a `DataSize=2` `FMultisizeIndexContainer` with `indices` (u16 LE).
    fn push_multisize_index_16(buf: &mut Vec<u8>, indices: &[u16]) {
        buf.push(2u8); // DataSize
        bulk_header(buf, 2, i32::try_from(indices.len()).unwrap());
        for &i in indices {
            buf.extend_from_slice(&i.to_le_bytes());
        }
    }

    /// Append an `FPositionVertexBuffer` of `verts` (each f32×3, stride 12).
    fn push_position_buffer(buf: &mut Vec<u8>, verts: &[[f32; 3]]) {
        let n = i32::try_from(verts.len()).unwrap();
        buf.extend_from_slice(&12i32.to_le_bytes()); // stride
        buf.extend_from_slice(&n.to_le_bytes()); // NumVertices
        bulk_header(buf, 12, n); // bulk header
        for v in verts {
            for c in v {
                buf.extend_from_slice(&c.to_le_bytes());
            }
        }
    }

    /// Append an `FStaticMeshVertexBuffer` for `num` verts, 1 UV channel, low
    /// precision (FPackedNormal×2 tangents + FMeshUVHalf UVs).
    fn push_static_mesh_vertex_buffer(buf: &mut Vec<u8>, num: u32) {
        let n = i32::try_from(num).unwrap();
        buf.extend_from_slice(&[0u8, 0u8]); // strip flags (not AV-stripped)
        buf.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        buf.extend_from_slice(&n.to_le_bytes()); // NumVertices
        buf.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs = false
        buf.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis = false
        bulk_header(buf, 8, n); // tangent bulk (FPackedNormal x2 = 8 B)
        for _ in 0..num {
            buf.extend_from_slice(&[0x7F, 0x00, 0x00, 0x00]); // TangentX → +X
            buf.extend_from_slice(&[0x00, 0x00, 0x7F, 0x00]); // TangentZ → +Z
        }
        bulk_header(buf, 4, n); // UV bulk (FMeshUVHalf = 4 B, 1 channel)
        for _ in 0..num {
            buf.extend_from_slice(&half::f16::from_f32(0.5).to_bits().to_le_bytes());
            buf.extend_from_slice(&half::f16::from_f32(0.25).to_bits().to_le_bytes());
        }
    }

    /// Append a legacy `FSkinWeightVertexBuffer` for `num` verts, 4 influences
    /// each (`bExtraBoneInfluences = 0`). Bone index i / weight 10*(i+1).
    fn push_skin_weight_legacy(buf: &mut Vec<u8>, num: u32) {
        let n = i32::try_from(num).unwrap();
        buf.extend_from_slice(&[0u8, 0u8]); // strip flags (not AV-stripped)
        buf.extend_from_slice(&0u32.to_le_bytes()); // bExtraBoneInfluences = 0
        buf.extend_from_slice(&0u32.to_le_bytes()); // stride (skipped)
        buf.extend_from_slice(&num.to_le_bytes()); // numVertices
        bulk_header(buf, 8, n); // FSkinWeightInfo bulk (4 idx + 4 wt = 8 B)
        for _ in 0..num {
            buf.extend_from_slice(&[1, 2, 3, 4]); // bone indices
            buf.extend_from_slice(&[10, 20, 30, 40]); // weights
        }
    }

    /// A ctx for the standalone `read_streamed_data` test: UE4 (`ue4=518`,
    /// `ue5=None`), `FSkeletalMeshCustomVersion >= SplitModelAndRenderData` (skin
    /// stride skip), `FUE5ReleaseStreamObjectVersion` BELOW `RemovingTessellation`
    /// (adjacency PRESENT), `FAnimObjectVersion` UNSTAMPED (legacy skin path).
    fn streamed_ctx() -> AssetContext {
        let custom_versions = section_custom_versions(
            8,
            3,
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            REMOVING_TESSELLATION - 1, // UE5_RELEASE below RemovingTessellation → adjacency present
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        AssetContext::new(
            Arc::new(NameTable::default()),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518, // >= 514 (no static strides); < 522 (no ray tracing)
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        )
    }

    #[test]
    fn read_streamed_data_inlined_legacy() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        // 1. inner FStripDataFlags (not AV-stripped, class=0).
        blob.extend_from_slice(&[0u8, 0u8]);
        // 2. Indices: 3 u16 [0,1,2].
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        // 3. PositionVertexBuffer: 2 verts.
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        // 4. StaticMeshVertexBuffer: 2 verts, 1 UV channel.
        push_static_mesh_vertex_buffer(&mut blob, 2);
        // 5. FSkinWeightVertexBuffer (legacy, 4 influences): 2 verts.
        push_skin_weight_legacy(&mut blob, 2);
        // 6. bHasVertexColors = false → no ColorVertexBuffer.
        // 7. AdjacencyIndexBuffer (present: UE5_RELEASE < RemovingTessellation,
        //    class not stripping CDSF_AdjacencyData) — read-and-discarded.
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        // 8. no cloth (empty sections).
        // 9. FSkinWeightProfilesData count = 0.
        blob.extend_from_slice(&0i32.to_le_bytes());
        // 10. ray-tracing absent (ue4 = 518 < 522).

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod)
            .expect("decode streamed blob");

        assert_eq!(lod.indices, vec![0u32, 1, 2], "Indices populated");
        assert_eq!(lod.positions.len(), 2, "positions populated");
        assert!((lod.positions[1].x - 1.0).abs() < f64::EPSILON);
        assert_eq!(lod.normals.len(), 2, "normals populated");
        assert_eq!(lod.tangents.len(), 2, "tangents populated");
        assert!(lod.uvs[0].is_some(), "UV channel 0 populated");
        assert_eq!(
            lod.bone_indices,
            vec![[1, 2, 3, 4, 0, 0, 0, 0], [1, 2, 3, 4, 0, 0, 0, 0]]
        );
        assert_eq!(
            lod.bone_weights,
            vec![[10, 20, 30, 40, 0, 0, 0, 0], [10, 20, 30, 40, 0, 0, 0, 0]]
        );
        assert!(lod.colors.is_none(), "bHasVertexColors=false → no colors");
        // SoA invariant.
        assert_eq!(lod.normals.len(), lod.positions.len());
        assert_eq!(lod.bone_indices.len(), lod.positions.len());
        // Full consumption (adjacency + profiles count consumed, no ray tracing).
        assert_eq!(
            cur.position(),
            blob.len() as u64,
            "the streamed-data reader must consume the full blob"
        );
    }

    /// `bHasVertexColors = true` reads a `ColorVertexBuffer` (cursor/length
    /// differs from the false case). Pins the color gate ON-branch + the SoA
    /// `ensure_bulk_count` colors check.
    #[test]
    fn read_streamed_data_reads_colors_when_flag_set() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        // ColorVertexBuffer (2 verts): strip flags + stride 4 + numVerts 2 + bulk.
        blob.extend_from_slice(&[0u8, 0u8]); // color strip flags (not stripped)
        blob.extend_from_slice(&4i32.to_le_bytes()); // stride
        blob.extend_from_slice(&2i32.to_le_bytes()); // NumVertices
        bulk_header(&mut blob, 4, 2);
        blob.extend_from_slice(&[10, 20, 30, 40]); // BGRA
        blob.extend_from_slice(&[1, 2, 3, 4]);
        // adjacency present.
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        blob.extend_from_slice(&0i32.to_le_bytes()); // profiles count 0

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", true, &[], &mut lod)
            .expect("decode streamed blob with colors");
        let colors = lod.colors.expect("colors populated when flag set");
        assert_eq!(colors.len(), 2);
        assert_eq!(cur.position(), blob.len() as u64);
    }

    /// A non-empty `FSkinWeightProfilesData` (count > 0) is rejected as
    /// `UnsupportedFeature` (the per-entry parse is deferred).
    #[test]
    fn read_streamed_data_rejects_nonempty_profiles() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]);
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        push_multisize_index_16(&mut blob, &[0, 1, 2]); // adjacency
        blob.extend_from_slice(&1i32.to_le_bytes()); // profiles count = 1 → unsupported

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        let err =
            read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod).unwrap_err();
        match err {
            PaksmithError::UnsupportedFeature { context } => {
                assert!(
                    context.contains("FSkinWeightProfilesData"),
                    "wrong context: {context}"
                );
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    /// A section with `has_cloth_data` drives the `ClothVertexBuffer` skip
    /// (`skip_cloth_buffer`): inner FStripDataFlags (not AV-stripped) +
    /// SkipBulkArrayData + ClothIndexMapping (`COMPACT_CLOTH_VERTEX_BUFFER` is on
    /// for `streamed_ctx`; `AddClothMappingLODBias` is off → no LOD-bias trailer).
    /// Pins the cloth-skip path consumes exactly the cloth buffer.
    #[test]
    fn read_streamed_data_skips_cloth_when_section_has_cloth_data() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        // adjacency present (streamed_ctx: UE5_RELEASE < RemovingTessellation).
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        // ClothVertexBuffer (skipped): strip flags (not AV-stripped) +
        // SkipBulkArrayData (elemSize=4, count=3 → 12 bytes) + ClothIndexMapping
        // (i32 count=2 + 2×u64).
        blob.extend_from_slice(&[0u8, 0u8]); // cloth FStripDataFlags
        bulk_header(&mut blob, 4, 3); // SkipBulkArrayData header
        blob.extend_from_slice(&[0u8; 12]); // SkipBulkArrayData payload
        blob.extend_from_slice(&2i32.to_le_bytes()); // ClothIndexMapping count
        blob.extend_from_slice(&[0u8; 16]); // 2 × u64
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let section = SkelMeshSection {
            has_cloth_data: true,
            ..SkelMeshSection::default()
        };
        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[section], &mut lod)
            .expect("decode blob with cloth skip");
        assert_eq!(lod.positions.len(), 2);
        assert_eq!(
            cur.position(),
            blob.len() as u64,
            "the cloth buffer must be fully skipped (header + bulk + ClothIndexMapping)"
        );
    }

    /// AV-stripped cloth buffer: inner strip flags with the AV bit set → the
    /// cloth skip returns immediately (no SkipBulkArrayData / ClothIndexMapping
    /// on the wire). Pins `skip_cloth_buffer`'s early-return arm.
    #[test]
    fn read_streamed_data_cloth_av_stripped_consumes_only_strip_flags() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        push_multisize_index_16(&mut blob, &[0, 1, 2]); // adjacency present
        // ClothVertexBuffer: AV-stripped → just the 2-byte strip flags, nothing else.
        blob.extend_from_slice(&[crate::asset::wire::STRIP_FLAG_AV_DATA, 0u8]);
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let section = SkelMeshSection {
            has_cloth_data: true,
            ..SkelMeshSection::default()
        };
        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[section], &mut lod)
            .expect("decode blob with AV-stripped cloth");
        assert_eq!(
            cur.position(),
            blob.len() as u64,
            "AV-stripped cloth consumes only the 2-byte strip flags"
        );
    }

    /// `read_streamed_data` STOPS after `FSkinWeightProfilesData` and does NOT
    /// read the version-gated tail (ray-tracing / UE5 morph/attr/half-edge), even
    /// at a UE4.27 ctx (`ue4 = 522`). The blob ends right after the profiles
    /// count; the reader must leave the cursor exactly there, consuming NO
    /// trailing bytes. (Under the BuffersSize seek in `read_typed`, the seek skips
    /// whatever the tail would have been — see `read_typed_ue4_27_tail_skipped_by_seek`.)
    /// `ue5_release` stays ≥ `RemovingTessellation` so adjacency is absent.
    #[test]
    fn read_streamed_data_stops_after_profiles_no_tail() {
        let custom_versions = section_custom_versions(
            8,
            3,
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            ADD_CLOTH_MAPPING_LOD_BIAS, // ≥ RemovingTessellation → adjacency absent
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 522, // UE4.27 proxy → is_ue4_27_or_later true
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        );
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        // adjacency ABSENT (ue5_release ≥ RemovingTessellation).
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0
        // NO tail bytes on the wire — the blob ENDS here. Pre-fix the removed
        // ray-tracing read would attempt an i32 past EOF and fault; post-fix the
        // reader stops at the profiles count.
        let profiles_end = blob.len() as u64;

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod)
            .expect("decode blob stopping after profiles, reading no tail");
        assert_eq!(
            cur.position(),
            profiles_end,
            "read_streamed_data must stop after FSkinWeightProfilesData, reading no \
             version-gated tail"
        );
    }

    /// `read_typed` with LOD[0] that has `bInlined=1` BUT whose INNER strip
    /// global has `STRIP_FLAG_AV_DATA` (bit 0x02) set: the blob is AV-stripped,
    /// so no inline blob is on the wire. The reader must skip `read_streamed_data`
    /// entirely and return `Ok` with empty geometry (`positions`/`indices` empty).
    ///
    /// With the pre-fix `if inlined`-alone gate, `read_streamed_data` fires and
    /// tries to read a blob that isn't there → immediate EOF error (RED).
    /// With the fix `if blob_present` (`bInlined && !av_stripped && !cooked_out`),
    /// the blob is skipped → Ok with empty LOD geometry (GREEN).
    ///
    /// The outer `FStripDataFlags` (`STRIP_FLAG_EDITOR_DATA` = 0x01) is the
    /// asset-level strip byte that gates `bCooked`; the INNER strip byte (0x02,
    /// inside `read_static_lod_model`) is the LOD-level byte that gates the blob.
    /// They are distinct: the outer byte is part of segment-2's leading prefix;
    /// the inner byte is the first byte of each `FStaticLODModel` wire stream.
    #[test]
    fn read_typed_av_stripped_inlined_lod_skips_blob() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        // LODModels count = 1.
        payload.extend_from_slice(&1i32.to_le_bytes());
        // LOD-0 header: inner strip global = 0x02 (AV data stripped), class = 0x00.
        payload.extend_from_slice(&[crate::asset::wire::STRIP_FLAG_AV_DATA, 0x00]);
        // bIsLODCookedOut = 0 (false).
        payload.extend_from_slice(&0i32.to_le_bytes());
        // bInlined = 1 (true) — the bug trigger: inlined=true but av-stripped=true.
        payload.extend_from_slice(&1i32.to_le_bytes());
        // RequiredBones: count 0.
        push_u16_array(&mut payload, &[]);
        // AV-stripped → section/bone block + BuffersSize are ABSENT; no seek.
        // The cursor stops right after RequiredBones, then the loop falls through
        // to the post-loop tail (the cursor-landing sentinel needs it).
        push_lod_tail(&mut payload, 0);

        let (asset, bulk) = read_typed(&payload, &ctx, "Mesh.uasset")
            .expect("AV-stripped inlined LOD must not attempt to read a missing blob");
        assert!(bulk.is_empty());
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert!(data.cooked);
        assert_eq!(data.lods.len(), 1, "LOD-0 header was consumed");
        assert!(
            data.lods[0].positions.is_empty(),
            "AV-stripped LOD: no positions (blob was skipped, not read)"
        );
        assert!(
            data.lods[0].indices.is_empty(),
            "AV-stripped LOD: no indices (blob was skipped, not read)"
        );
    }

    /// Append a bare AV-stripped `FStaticLODModel` header — strip global =
    /// `STRIP_FLAG_AV_DATA`, `bIsLODCookedOut = 0`, `bInlined = 1`, then
    /// `RequiredBones` only. The section/bone block + `BuffersSize` + the blob are
    /// ABSENT (the AV-data-stripped gate), so `read_typed` reads no blob and does
    /// NOT seek for this LOD.
    fn push_av_stripped_lod(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[crate::asset::wire::STRIP_FLAG_AV_DATA, 0x00]); // global AV-stripped
        buf.extend_from_slice(&0i32.to_le_bytes()); // bIsLODCookedOut = 0
        buf.extend_from_slice(&1i32.to_le_bytes()); // bInlined = 1
        push_u16_array(buf, &[]); // RequiredBones: count 0
    }

    /// MID-LIST AV-stripped LOD: a 3-LOD array (normal / AV-stripped / normal).
    /// The stripped middle LOD carries no blob and is NOT seeked; iteration must
    /// CONTINUE to the final normal LOD and parse its geometry. Proves the
    /// `block_present` gate skips the blob+seek for the stripped LOD without
    /// aborting the loop — the stripped LOD's geometry stays empty while the LOD
    /// AFTER it still decodes.
    #[test]
    fn read_typed_mid_list_av_stripped_lod_continues_iteration() {
        let ctx = lod_typed_ctx(
            &["None", "Mat0", "Root", "Hip"],
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
        );
        let mut payload =
            build_payload_through_skeleton(crate::asset::wire::STRIP_FLAG_EDITOR_DATA);
        payload.extend_from_slice(&1i32.to_le_bytes()); // bCooked = true
        payload.extend_from_slice(&3i32.to_le_bytes()); // LODModels count = 3
        push_inlined_lod(&mut payload, &[10, 11], None); // LOD[0]: normal
        push_av_stripped_lod(&mut payload); // LOD[1]: AV-stripped (no blob, no seek)
        push_inlined_lod(&mut payload, &[20, 21], None); // LOD[2]: normal
        push_lod_tail(&mut payload, 0);

        let (asset, _bulk) =
            read_typed(&payload, &ctx, "Mesh.uasset").expect("mid-list AV-stripped parse");
        let Asset::SkeletalMesh(data) = asset else {
            panic!("expected Asset::SkeletalMesh, got {asset:?}");
        };
        assert_eq!(data.lods.len(), 3, "all three LOD headers consumed");
        // LOD[0] (before the stripped one) decodes.
        assert_eq!(data.lods[0].bone_map, vec![10u16, 11]);
        assert_eq!(data.lods[0].positions.len(), 2, "LOD[0] geometry parsed");
        // LOD[1] is AV-stripped: header only, geometry empty, NOT seeked.
        assert!(
            data.lods[1].positions.is_empty(),
            "AV-stripped LOD[1]: no positions (blob skipped, not read)"
        );
        assert!(
            data.lods[1].indices.is_empty(),
            "AV-stripped LOD[1]: no indices"
        );
        // LOD[2] (AFTER the stripped one) still decodes — iteration continued.
        assert_eq!(data.lods[2].bone_map, vec![20u16, 21]);
        assert_eq!(
            data.lods[2].positions.len(),
            2,
            "iteration continued past the stripped LOD → LOD[2] geometry parsed"
        );
        assert_eq!(
            data.lods[2].indices,
            vec![0u32, 1, 2],
            "LOD[2] indices parsed"
        );
    }

    /// Adjacency class-stripped: the inner strip flags' `class` byte sets
    /// `CDSF_AdjacencyData` → the adjacency `FMultisizeIndexContainer` is NOT on
    /// the wire even though the version gate is open. Pins the
    /// `!is_class_data_stripped(class, ADJACENCY)` conjunct against deletion.
    #[test]
    fn read_streamed_data_adjacency_absent_when_class_stripped() {
        let ctx = streamed_ctx(); // UE5_RELEASE < RemovingTessellation (version gate open)
        let mut blob = Vec::new();
        // inner strip flags: global=0, class=CDSF_AdjacencyData (0x01).
        blob.extend_from_slice(&[0u8, STRIP_FLAG_ADJACENCY_DATA]);
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        // adjacency ABSENT (class-stripped) — no FMultisizeIndexContainer here.
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod)
            .expect("decode blob with class-stripped adjacency");
        assert_eq!(
            cur.position(),
            blob.len() as u64,
            "class-stripped adjacency: no FMultisizeIndexContainer on the wire"
        );
    }

    /// Adjacency version-gate boundary: `FUE5ReleaseStream == RemovingTessellation`
    /// (exactly the cutover). The real gate `v < RemovingTessellation` is FALSE at
    /// the boundary → adjacency ABSENT, so the wire after the skin-weight buffer is
    /// the `FSkinWeightProfilesData` count (0). Pins the `<` against the `<=`
    /// mutant: with `<=`, the gate would open at `v == RemovingTessellation`, read
    /// an `FMultisizeIndexContainer` off the `0i32` profiles bytes (`DataSize = 0`,
    /// not in {2, 4}) → typed fault. Asserting `Ok` + full consumption kills it.
    #[test]
    fn read_streamed_data_adjacency_absent_at_removing_tessellation_boundary() {
        let custom_versions = section_custom_versions(
            8,
            3,
            MATERIAL_SHADER_MAP_ID_SERIALIZATION,
            100,
            SPLIT_MODEL_AND_RENDER_DATA,
            RECOMPUTE_TANGENT_VERTEX_COLOR_MASK,
            SKEL_MESH_SECTION_VISIBLE_IN_RAY_TRACING_FLAG_ADDED,
            REMOVING_TESSELLATION, // exactly the boundary → adjacency ABSENT (v < REM is false)
            ADD_SKELETAL_MESH_SECTION_DISABLE,
        );
        let ctx = AssetContext::new(
            Arc::new(NameTable::default()),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: -7,
                file_version_ue4: 518, // < 522 → no ray-tracing tail
                file_version_ue5: None,
                file_version_licensee_ue4: 0,
            },
            Arc::new(custom_versions),
            None,
        );
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags (class not stripped)
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        // adjacency ABSENT (version gate closed at the boundary). The next bytes are
        // the FSkinWeightProfilesData count (0). With the `<=` mutant these `0`
        // bytes are misread as a FMultisizeIndexContainer DataSize → fault.
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod)
            .expect("v == RemovingTessellation: adjacency must be absent");
        assert_eq!(
            cur.position(),
            blob.len() as u64,
            "boundary adjacency absent: no FMultisizeIndexContainer on the wire"
        );
    }

    /// SoA mismatch — positions vs normals. `normals.len() != positions.len()`
    /// (positions = 2, normals = 3) with everything else aligned (bone_indices = 2,
    /// no colors) → only the `normals == positions` check fires. Pins the
    /// `!positions.is_empty()` guard against the `delete !` mutant: with the `!`
    /// deleted the guard becomes `positions.is_empty()` (false for 2 verts) → the
    /// `&&` short-circuits, the mismatch check is SKIPPED, and (since bone_indices
    /// matches and there are no colors) the reader returns `Ok`. Asserting `Err`
    /// kills the mutant.
    #[test]
    fn read_streamed_data_positions_normals_mismatch_is_typed_error() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]); // 2 positions
        push_static_mesh_vertex_buffer(&mut blob, 3); // 3 normals/tangents/uvs → mismatch
        push_skin_weight_legacy(&mut blob, 2); // 2 bone_indices (== positions → quiet)
        push_multisize_index_16(&mut blob, &[0, 1, 2]); // adjacency present
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        let err =
            read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: crate::error::AssetParseFault::MeshVertexBufferLengthMismatch { .. },
                    ..
                }
            ),
            "positions/normals mismatch must be a typed length-mismatch fault, got {err:?}"
        );
    }

    /// SoA mismatch — bone_indices vs positions. `bone_indices.len() !=
    /// positions.len()` (positions = 2, bone_indices = 3) with normals aligned
    /// (= 2, so the positions/normals check stays quiet) and no colors → only the
    /// `ensure_bulk_count(positions, bone_indices)` check fires. Pins the
    /// `!bone_indices.is_empty()` guard against the `delete !` mutant: with the `!`
    /// deleted the guard becomes `bone_indices.is_empty()` (false for 3 entries) →
    /// the check is SKIPPED → `Ok`. Asserting `Err` kills the mutant.
    #[test]
    fn read_streamed_data_bone_indices_positions_mismatch_is_typed_error() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]); // 2 positions
        push_static_mesh_vertex_buffer(&mut blob, 2); // 2 normals (== positions → quiet)
        push_skin_weight_legacy(&mut blob, 3); // 3 bone_indices → mismatch vs 2 positions
        push_multisize_index_16(&mut blob, &[0, 1, 2]); // adjacency present
        blob.extend_from_slice(&0i32.to_le_bytes()); // FSkinWeightProfilesData count 0

        let mut cur = Cursor::new(blob.as_slice());
        let mut lod = SkeletalMeshLod::default();
        let err =
            read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: crate::error::AssetParseFault::MeshBulkArrayCountMismatch {
                        field: AssetWireField::SkinWeightVertexCount,
                        ..
                    },
                    ..
                }
            ),
            "bone_indices/positions mismatch must be a typed bulk-count fault, got {err:?}"
        );
    }

    /// Truncation mid-blob → typed `Err`, never a panic. A full inlined-legacy
    /// blob cut off partway through the position buffer must propagate a typed
    /// EOF up through the orchestration (no `unwrap`/`expect` in the read path).
    /// Pins the `?`-propagation contract that cargo-mutants cannot exercise.
    #[test]
    fn read_streamed_data_truncated_mid_blob_is_typed_error() {
        let ctx = streamed_ctx();
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0u8, 0u8]); // inner strip flags
        push_multisize_index_16(&mut blob, &[0, 1, 2]);
        push_position_buffer(&mut blob, &[[0.0, 0.0, 0.0], [1.0, 2.0, 3.0]]);
        push_static_mesh_vertex_buffer(&mut blob, 2);
        push_skin_weight_legacy(&mut blob, 2);
        push_multisize_index_16(&mut blob, &[0, 1, 2]); // adjacency
        blob.extend_from_slice(&0i32.to_le_bytes()); // profiles count 0

        // Cut off partway into the position-buffer payload (after the index
        // container fully parses) so the truncation surfaces inside a sub-reader.
        let cut = 2 + (1 + 8 + 6) + 12; // strip flags + index container + half the position buffer
        let truncated = &blob[..cut];

        let mut cur = Cursor::new(truncated);
        let mut lod = SkeletalMeshLod::default();
        let err =
            read_streamed_data(&mut cur, &ctx, "Mesh.uasset", false, &[], &mut lod).unwrap_err();
        // The exact fault depends on which field the cut lands in; the contract is
        // a typed error rather than a panic.
        assert!(
            matches!(err, PaksmithError::AssetParse { .. } | PaksmithError::Io(_)),
            "mid-blob truncation must be a typed Err, got {err:?}"
        );
    }
}
