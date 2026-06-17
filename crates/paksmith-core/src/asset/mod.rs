//! UAsset deserialization.
//!
//! # Scope (Phase 2a)
//!
//! Parses the structural header of UE 4.21–UE 5.x `.uasset` files.
//! Property bodies (`FPropertyTag`-iterated payloads inside export
//! serialized regions) are carried as opaque bytes via the
//! [`PropertyBag::Opaque`] variant; tagged-property iteration and the
//! typed property surface arrive in Phase 2b.
//!
//! # Module layout
//!
//! [`Package::read_from`] / [`Package::read_from_pak`] are the entry
//! points — both return a fully parsed [`Package`] (summary + name /
//! import / export tables + opaque payload). [`Asset`] wraps the
//! `Package` as its `Generic` variant; specialized variants
//! (`Texture`, `StaticMesh`, …) land in Phase 3. [`AssetContext`]
//! bundles the `Arc`-shared tables for downstream property parsers.
//!
//! See `docs/plans/phase-2a-uasset-header.md` for the implementation
//! plan and `docs/design/SPEC.md` § "Asset Data Model" for the
//! architectural intent.

use std::sync::Arc;

use serde::Serialize;

pub mod bulk_data;
pub mod custom_version;
pub mod engine_version;
pub mod export_table;
pub(crate) mod exports;
pub(crate) mod fstring;
pub mod guid;
pub mod import_table;
pub mod mappings;
pub mod name_table;
pub mod package;
pub mod package_index;
pub mod property;
pub mod structs;
pub mod summary;
pub mod version;
pub mod wire;

pub use custom_version::{CustomVersion, CustomVersionContainer};
pub use engine_version::EngineVersion;
pub use export_table::{ExportTable, ObjectExport};
pub use exports::mesh::section::MeshSection;
pub use guid::FGuid;
pub use import_table::{ImportTable, ObjectImport};
pub use mappings::Usmap;
pub use name_table::{FName, NameTable};
pub use package::Package;
pub use package_index::{PackageIndex, PackageIndexError};
pub use property::PropertyBag;
pub use summary::PackageSummary;
pub use version::AssetVersion;

#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use fstring::write_asset_fstring;
pub(crate) use fstring::{read_asset_fstring, skip_asset_bytes, skip_asset_fstring};
pub(crate) use package_index::read_package_index;
pub(crate) use wire::read_bool32;
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) use wire::write_bool32;

/// Per-export typed payload for a deserialized UE asset.
///
/// Phase 3 ships only the [`Self::Generic`] variant carrying a
/// [`property::bag::PropertyBag`] (Tree or Opaque
/// fallback). Typed variants for known export classes —
/// `DataTable`, `Texture2D`, `SoundWave`, `StaticMesh`,
/// `SkeletalMesh` — land in Phase 3 sub-phases 3d-3h on this same
/// `#[non_exhaustive]` enum.
///
/// `#[non_exhaustive]` so downstream consumers can pattern-match with
/// `_` and survive future variant additions.
///
/// The default `#[derive(Serialize)]` form produces an externally-
/// tagged JSON object (`{"Generic": {"kind": "...", ...}}`).
/// Externally-tagged was chosen over `#[serde(untagged)]` precisely
/// because future variants need a discriminator: locking in the tag
/// shape now lets 3d-3h add `DataTable` / `Texture2D` / etc. without
/// breaking consumers who already match on the tag.
///
/// `Package::payloads: Vec<Asset>` carries one entry per export; this
/// enum is the per-export payload (NOT a per-package wrapper —
/// Phase 2 briefly used a `Generic(Package)` shape as a forward-compat
/// placeholder; Phase 3 inverted to per-export semantics).
///
/// **`PartialEq` derive — forward-compat constraint:** every variant's
/// inner type MUST implement `PartialEq` (PropertyBag already does;
/// 3d-3h's typed inner types (`DataTableData`, `Texture2DData`, etc.)
/// must follow. If a future variant carries decoder-state or other
/// non-`PartialEq` interiors, this derive will need to be removed
/// and the relevant test assertions (`assert_eq!(asset, ...)`)
/// rewritten as `matches!` checks.
// `Deserialize` is intentionally NOT derived on `Asset` because the
// inner property-bag content has a hand-rolled, view-based
// serialization that loses information (Opaque renders as a byte
// count only; FName references resolve to display strings). That
// JSON shape is designed for human consumption (`paksmith inspect`),
// not round-trip.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub enum Asset {
    /// The universal fallback: a single export's parsed property bag.
    /// Phase 2 produced this for every export; Phase 3 sub-phases
    /// (3d-3h) add typed variants for known export classes.
    Generic(property::bag::PropertyBag),
    /// A `UDataTable` export: a row-keyed table whose rows share a
    /// `RowStruct` schema. Phase 3d. The upcoming `data_table::read_from`
    /// parser fills this in; `CsvHandler` / `JsonHandler` export it.
    DataTable(DataTableData),
    /// A `UTexture2D` export. Phase 3e. Carries the segment-1 tagged
    /// properties (`SRGB`, `CompressionSettings`, …) plus the **full**
    /// `FTexturePlatformData` (dimensions, pixel format, slice/cubemap
    /// bits, `num_mips_in_tail`, `first_mip_to_serialize`, mip count) and
    /// the per-mip dimension chain ([`Texture2DData::mips`]) as of 3e-3;
    /// the virtual-texture page-table data is added to [`Texture2DData`]
    /// in its own later 3e milestone, and `PngHandler` exports it in 3e-8.
    Texture2D(Texture2DData),
    /// A `USoundWave` export. Phase 3f. It carries the `USoundBase`
    /// tagged-property segment (audio settings) plus the resolved `cooked` /
    /// `streaming` bits from the binary header; the header parse also consumes
    /// the version-conditional `DummyCompressionName`. As of 3f-4 both cooked
    /// platform-data branches parse into [`SoundWaveData`] — the non-streaming
    /// `FFormatContainer` (per-codec buffers) and the streaming
    /// `FStreamedAudioPlatformData` chunks — each with the `CompressedDataGuid`.
    /// (The oracle's UE 5.4+ cue points are unreachable — they need object
    /// version 1012, above paksmith's 1011 `FPropertyTag` ceiling.) The audio
    /// `FormatHandler`s (OGG/Opus passthrough, WAV) export it.
    SoundWave(SoundWaveData),
    /// A `UStaticMesh` export. Phase 3g. As of 3g1 it carries the segment-1
    /// tagged-property stream (`StaticMaterials`, `LODGroup`, …) plus the leading
    /// `UStaticMesh.Deserialize` fields through `BodySetup`: the `cooked` flag
    /// (gates whether the render data is eventually present) and the
    /// `body_setup` collision reference. Several more `Deserialize` fields
    /// (`NavCollision`, `LightingGuid`, `Sockets`, …) and then the per-LOD
    /// geometry (`FStaticMeshRenderData` → vertex / index buffers) sit beyond
    /// `BodySetup` and are added — with the glTF `FormatHandler` — in later 3g
    /// milestones.
    StaticMesh(StaticMeshData),
    /// A `USkeletalMesh` export. Phase 3h. Carries the segment-1 tagged
    /// properties, the `USkeletalMesh.Deserialize` prefix (`ImportedBounds`,
    /// material slot names, `bCooked`), and the reference skeleton (bone
    /// hierarchy + bind pose), plus EVERY inlined LOD's sections + bone arrays
    /// and per-vertex skin geometry (vertex/index/skin-weight buffers). A
    /// non-inlined (out-of-line `FByteBulkData`) LOD is not yet supported (the
    /// export degrades to a generic property bag). See [`SkeletalMeshData`].
    SkeletalMesh(SkeletalMeshData),
}

/// Parsed contents of a `UStaticMesh` export — Phase 3g. Carries the segment-1
/// tagged-property stream, the leading `UStaticMesh.Deserialize` fields
/// (`cooked`, `body_setup`, `nav_collision`, `lighting_guid`, `sockets`), and —
/// for cooked content — the [`StaticMeshRenderData`] geometry (per-LOD vertex /
/// index buffers + bounds).
///
/// # Scope / known limitations
///
/// The render-data parser targets the **UE 4.23–4.27 / UE 5.0–5.3 new-cooked**
/// `FStaticMeshRenderData` layout. UE5 / Nanite meshes and the pre-4.23 legacy
/// LOD format are intentionally surfaced as
/// [`crate::error::PaksmithError::UnsupportedFeature`] rather than mis-decoded
/// (no fixtures / no oracle byte-validation; deferred to a later milestone). A
/// non-inlined (`bInlined == false`) LOD's streamed geometry is resolved from its
/// companion `.ubulk` via the bulk resolver, when one is available; an
/// unresolvable record (no resolver, missing companion, or compressed bulk)
/// degrades the export to a generic property bag. A present per-LOD
/// `FDistanceFieldVolumeData` (`bValid == true`, UE4 path) is validated-skipped,
/// so a distance-field-bearing mesh still returns its geometry. The
/// `UStaticMesh.Deserialize` tail *after* the render
/// data (occluder data, SpeedTree-wind flag, `StaticMaterials`) is left
/// unconsumed, mirroring the export framework's offset-based dispatch.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct StaticMeshData {
    /// Segment-1 tagged properties (`StaticMaterials`, `LODGroup`,
    /// `LightMapResolution`, `NaniteSettings`, …).
    pub properties: property::bag::PropertyBag,
    /// `bCooked` (`UStaticMesh.Deserialize`): `true` for cooked content, where
    /// the [`StaticMeshRenderData`] payload follows the collision reference.
    pub cooked: bool,
    /// `BodySetup` — the collision `UBodySetup` reference (unresolved
    /// [`PackageIndex`]). Carried for completeness; not used by glTF export.
    pub body_setup: PackageIndex,
    /// `NavCollision` — the navigation-collision reference (unresolved
    /// [`PackageIndex`]). Always present for paksmith's supported version range
    /// (`STATIC_MESH_STORE_NAV_COLLISION` sits below the 504 floor).
    pub nav_collision: PackageIndex,
    /// `LocalLightingGuid` — the lightmap identity GUID.
    pub lighting_guid: FGuid,
    /// `Sockets` — the `UStaticMeshSocket` references (unresolved
    /// [`PackageIndex`]es).
    pub sockets: Vec<PackageIndex>,
    /// The cooked render geometry, or `None` for a non-cooked mesh (no render
    /// data follows). A cooked mesh whose render data is an unsupported variant
    /// does **not** surface here as `Some`/`None` — the typed read returns an
    /// `UnsupportedFeature` error and the package walker degrades that export to
    /// [`Asset::Generic`] instead (see the type-level "known limitations").
    pub render_data: Option<StaticMeshRenderData>,
}

impl StaticMeshData {
    /// A cheap, zero-allocation empty mesh — the discriminant sentinel the
    /// export `HandlerRegistry` registers against (matching
    /// [`SoundWaveData::empty`] etc.).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            properties: property::bag::PropertyBag::tree(Vec::new()),
            cooked: false,
            body_setup: PackageIndex::Null,
            nav_collision: PackageIndex::Null,
            lighting_guid: FGuid::default(),
            sockets: Vec::new(),
            render_data: None,
        }
    }
}

/// Cooked `FStaticMeshRenderData` — the per-LOD render geometry plus the
/// mesh-level bounds and LOD screen sizes. Phase 3g (UE 4.23–4.27 new-cooked
/// layout, full record; UE 5.0–5.3 is read geometry-only, with default `bounds`
/// and empty `screen_sizes` — see [`StaticMeshData`] and the `render_data`
/// module docs for the scope boundary).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct StaticMeshRenderData {
    /// Per-LOD render resources, highest-detail first.
    pub lods: Vec<StaticMeshLod>,
    /// Mesh-space bounding box + sphere.
    pub bounds: structs::bounds::FBoxSphereBounds,
    /// `bLODsShareStaticLighting`.
    pub lods_share_static_lighting: bool,
    /// Per-LOD screen-size thresholds (`FPerPlatformFloat::Value`, the cooked
    /// `Default`). `MAX_STATIC_LODS_UE4` (8) entries on the wire.
    pub screen_sizes: Vec<f32>,
}

/// One LOD of an `FStaticMeshLODResources`, as a Structure-of-Arrays: index `i`
/// is vertex `i` across `positions` / `normals` / `tangents` / per-channel
/// `uvs` / `colors`. Phase 3g.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct StaticMeshLod {
    /// Per-draw-call sections (material + index range + render flags).
    pub sections: Vec<exports::mesh::section::MeshSection>,
    /// Vertex positions (`FPositionVertexBuffer`).
    pub positions: Vec<structs::vector::FVector>,
    /// Per-vertex normals (`TangentZ`).
    pub normals: Vec<structs::vector::FVector>,
    /// Per-vertex tangents (`TangentX`, XYZW; `W` is the handedness sign).
    pub tangents: Vec<structs::vector::FVector4>,
    /// UV channels `0..num_tex_coords`; `None` for absent channels.
    pub uvs: [Option<Vec<structs::vector::FVector2D>>; 4],
    /// On-wire UV channel count (1–4).
    pub num_tex_coords: u32,
    /// Per-vertex colors (`FColorVertexBuffer`); `None` when stripped / empty.
    pub colors: Option<Vec<structs::color::FColor>>,
    /// Triangle-list vertex indices (16- or 32-bit on the wire, widened).
    pub indices: Vec<u32>,
}

/// Parsed `USkeletalMesh` export — Phase 3h. Carries the reference skeleton
/// (bone hierarchy + bind pose) plus the type scaffolding for the segment-2
/// prefix (`materials`, `bounds`, `cooked`) and the per-LOD skin geometry.
///
/// # Scope
///
/// PR1 populates only `skeleton` (via the standalone `read_reference_skeleton`
/// reader); the rest are declared here and populated by later 3h PRs: PR2 wires
/// dispatch + the segment-2 prefix (`cooked`, `materials`, `bounds`); PR3 adds
/// the `FSkelMeshSection` reader; PR4 fills `lods` with `LOD[0]`'s sections + bone
/// arrays; PR5 adds the per-vertex skin geometry. The `empty()` sentinel makes
/// the type constructible for the export `HandlerRegistry` discriminant.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SkeletalMeshData {
    /// Segment-1 tagged properties.
    pub properties: property::bag::PropertyBag,
    /// `bCooked` (`USkeletalMesh.Deserialize`).
    pub cooked: bool,
    /// The reference skeleton: bone hierarchy + bind pose.
    pub skeleton: ReferenceSkeleton,
    /// Material slot names (`FSkeletalMaterial`).
    pub materials: Vec<String>,
    /// `ImportedBounds` — mesh-space bounding box + sphere.
    pub bounds: structs::bounds::FBoxSphereBounds,
    /// Per-LOD records — one entry per inlined `LODModels[i]`, each with its
    /// sections + bone arrays and per-vertex skin geometry. A non-inlined
    /// (out-of-line `FByteBulkData`) LOD is not yet supported (the export
    /// degrades to a generic property bag rather than producing a partial set).
    pub lods: Vec<SkeletalMeshLod>,
}

impl SkeletalMeshData {
    /// A cheap, zero-allocation empty skeletal mesh — the discriminant sentinel
    /// the export `HandlerRegistry` registers against (matching
    /// [`StaticMeshData::empty`] etc.). `FBoxSphereBounds`/`FVector` don't
    /// implement `Default`, so the zero bounds are constructed explicitly.
    #[must_use]
    pub fn empty() -> Self {
        let zero_vector = structs::vector::FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        Self {
            properties: property::bag::PropertyBag::tree(Vec::new()),
            cooked: false,
            skeleton: ReferenceSkeleton::default(),
            materials: Vec::new(),
            bounds: structs::bounds::FBoxSphereBounds {
                origin: zero_vector,
                box_extent: zero_vector,
                sphere_radius: 0.0,
            },
            lods: Vec::new(),
        }
    }
}

/// Reference skeleton: bone hierarchy + bind pose (`FReferenceSkeleton`).
/// `bones` and `bind_pose` are parallel — index `i` is bone `i`. Phase 3h.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
pub struct ReferenceSkeleton {
    /// Per-bone metadata (`FMeshBoneInfo`, cooked subset), highest-level first.
    pub bones: Vec<BoneInfo>,
    /// Per-bone bind-pose transforms (`FinalRefBonePose`), parallel to `bones`.
    pub bind_pose: Vec<structs::transform::FTransform>,
}

/// One bone's metadata (`FMeshBoneInfo`, cooked subset — UE 4.13+ has only
/// `Name` + `ParentIndex`; `BoneColor`/`ExportName` are pre-4.12 / editor-only).
/// Phase 3h.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct BoneInfo {
    /// The bone name (resolved `FName`).
    pub name: String,
    /// Parent index into the bone array; `-1` for root.
    pub parent_index: i32,
}

/// Per-LOD skeletal geometry (Structure-of-Arrays). Fields declared here; PR3
/// populates `sections`; PR4 populates the bone arrays (`active_bone_indices`,
/// `required_bones`, `bone_map`); the vertex / index / skin-weight buffers are
/// PR5. Phase 3h.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
pub struct SkeletalMeshLod {
    /// Per-draw-call sections (`FSkelMeshSection`).
    pub sections: Vec<SkelMeshSection>,
    /// Vertex positions.
    pub positions: Vec<structs::vector::FVector>,
    /// Per-vertex normals.
    pub normals: Vec<structs::vector::FVector>,
    /// Per-vertex tangents (XYZW; `W` is the handedness sign).
    pub tangents: Vec<structs::vector::FVector4>,
    /// UV channels `0..num_tex_coords`; `None` for absent channels.
    pub uvs: [Option<Vec<structs::vector::FVector2D>>; 4],
    /// Per-vertex colors; `None` when stripped / empty.
    pub colors: Option<Vec<structs::color::FColor>>,
    /// Triangle-list vertex indices (16- or 32-bit on the wire, widened).
    pub indices: Vec<u32>,
    /// Per-vertex bone indices (up to 8 influences into `bone_map`).
    pub bone_indices: Vec<[u16; 8]>,
    /// Per-vertex bone weights (parallel to `bone_indices`). Carries its on-wire
    /// precision: `U8` (the common cooked layout) or `U16` (UE5
    /// `IncreasedSkinWeightPrecision`).
    pub bone_weights: BoneWeights,
    /// Union of the per-section `bone_map`s, populated in PR4 (the per-section
    /// [`SkelMeshSection::bone_map`] is authoritative).
    pub bone_map: Vec<u16>,
    /// Active bone indices for this LOD (`FStaticLODModel::ActiveBoneIndices`).
    pub active_bone_indices: Vec<u16>,
    /// Required bone indices for this LOD (`FStaticLODModel::RequiredBones`).
    pub required_bones: Vec<u16>,
}

/// Per-vertex bone weights with their on-wire precision (mirrors the oracle's
/// `bUse16BitBoneWeight` fork). Each inner array holds up to 8 influence weights,
/// zero-padded, parallel to [`SkeletalMeshLod::bone_indices`].
///
/// - [`Self::U8`]: 8-bit weights — the common cooked layout; a vertex's weights
///   are normalized so the influences sum to `255`.
/// - [`Self::U16`]: 16-bit weights — UE5 `FUE5MainStreamObjectVersion::
///   IncreasedSkinWeightPrecision`; influences sum to `65535`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum BoneWeights {
    /// 8-bit per-influence weights.
    U8(Vec<[u8; 8]>),
    /// 16-bit per-influence weights (UE5 increased precision).
    U16(Vec<[u16; 8]>),
}

impl Default for BoneWeights {
    /// An empty 8-bit weight list (the no-skin / not-yet-populated state).
    fn default() -> Self {
        BoneWeights::U8(Vec::new())
    }
}

impl BoneWeights {
    /// Number of vertices (per-vertex influence arrays) in this buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            BoneWeights::U8(v) => v.len(),
            BoneWeights::U16(v) => v.len(),
        }
    }

    /// `true` when no vertices carry weights (no skin data).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One `FSkelMeshSection` draw-call record. Fields populated in PR3. Phase 3h.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is a distinct FSkelMeshSection wire field, mirrored 1:1 from the oracle"
)]
#[non_exhaustive]
pub struct SkelMeshSection {
    /// Material slot index.
    pub material_index: i32,
    /// First index into the LOD index buffer.
    pub base_index: i32,
    /// Triangle count for this section.
    pub num_triangles: i32,
    /// First vertex index into the LOD vertex buffers.
    pub base_vertex_index: u32,
    /// Vertex count for this section.
    pub num_vertices: i32,
    /// Maximum bone influences per vertex in this section.
    pub max_bone_influences: i32,
    /// Per-section bone-index remap (LOD-local → skeleton). Authoritative
    /// per-section map; the LOD-level union is derivable.
    pub bone_map: Vec<u16>,
    /// Recompute-tangent-at-runtime flag.
    pub recompute_tangent: bool,
    /// Vertex-color channel driving runtime tangent recompute. UE serializes the
    /// sentinel `3` (`ESkinVertexColorChannel::None`) when no channel drives the
    /// recompute; the struct `Default` (`0`) is overwritten by the reader.
    pub recompute_tangents_vertex_mask_channel: u8,
    /// Whether this section casts dynamic shadows.
    pub cast_shadow: bool,
    /// Whether this section is visible to ray-tracing passes.
    pub visible_in_ray_tracing: bool,
    /// Whether this section is disabled (skipped at render time).
    pub disabled: bool,
    /// Cloth-asset slot. UE serializes `-1` when the section has no cloth; the
    /// struct `Default` (`0`) is overwritten by the reader.
    pub correspond_cloth_asset_index: i16,
    /// Whether this section carries cloth-mapping data at this LOD (any
    /// `ClothMappingDataLODs` inner array was non-empty). Drives the streamed-blob
    /// `ClothVertexBuffer` gate (`HasClothData()`), mirroring the oracle's
    /// per-section predicate (NOT `correspond_cloth_asset_index >= 0`, which can
    /// disagree). Set by `exports::mesh::skeletal_mesh::read_skel_mesh_section_render`.
    pub has_cloth_data: bool,
}

/// Parsed contents of a `UDataTable` export — the row-keyed table plus
/// the class-level metadata needed to round-trip it.
///
/// Phase 3d. Produced by `data_table::read_from`; consumed by the
/// DataTable `FormatHandler` impls.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DataTableData {
    /// Name of the `RowStruct` (`UScriptStruct`) every row conforms to.
    /// Empty when the table's `RowStruct` couldn't be resolved (a
    /// `tracing::warn!` is logged at parse time — see the format doc's
    /// §RowStruct resolution failure).
    pub row_struct: String,
    /// One entry per table row, in wire order.
    pub rows: Vec<DataTableRow>,
    /// Class-level tagged properties (the `RowStruct` `ObjectProperty`,
    /// the strip flags `bStripFromClientBuilds` /
    /// `bStripFromDedicatedServerBuilds`, `bIgnoreExtraFields`,
    /// `bIgnoreMissingFields`, …). `JsonHandler` round-trips these into
    /// its output so JSON consumers keep the strip-flag state that
    /// determined whether the cooker emitted zero rows; `CsvHandler`
    /// ignores them (CSV has no schema for class-level metadata).
    pub class_properties: property::bag::PropertyBag,
}

impl DataTableData {
    /// Cheap, zero-allocation empty table — used as the discriminant
    /// sentinel when registering DataTable handlers in
    /// [`crate::export::HandlerRegistry::all_default_handlers`]
    /// (`std::mem::discriminant` ignores the payload). All fields are
    /// `Vec::new()` / `String::new()`; `class_properties` is an empty
    /// `Tree`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            row_struct: String::new(),
            rows: Vec::new(),
            class_properties: property::bag::PropertyBag::tree(Vec::new()),
        }
    }
}

/// A single `UDataTable` row: a `RowName` plus the row's
/// tagged-property body (decoded against the shared `RowStruct`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DataTableRow {
    /// The row's `RowName` (resolved from the package name table).
    pub name: String,
    /// The row body's decoded tagged properties, in wire order.
    pub properties: Vec<property::primitives::Property>,
}

/// Parsed contents of a `USoundWave` export.
///
/// Phase 3f. Produced by `audio::sound_wave::read_from`; consumed (in later
/// 3f milestones) by the audio `FormatHandler`s. This carries the `USoundBase`
/// tagged-property segment (audio settings: sample rate, channel count,
/// duration, loop/attenuation metadata) plus the resolved `cooked` /
/// `streaming` bits from the USoundWave binary header. The header parse also
/// consumes the version-conditional `DummyCompressionName` (a discarded
/// `FName`). As of 3f-3 the non-streaming cooked branch (`!streaming`) parses
/// the `FFormatContainer` — its per-codec keys land in `compressed_format_keys`
/// and the encoded buffers in the `read_typed` bulk-record list — plus the
/// `CompressedDataGuid`. The UE 5.4+ cue points the oracle reads between the
/// header and platform data are absent for every asset paksmith parses (they
/// require object version 1012, above paksmith's `FIRST_UNSUPPORTED_UE5_VERSION`
/// 1011 `FPropertyTag` ceiling), so platform data follows `DummyCompressionName`
/// directly. As of 3f-4 the streaming branch (`streaming && cooked`) parses the
/// `FStreamedAudioPlatformData` — the `CompressedDataGuid`, the `AudioFormat`
/// codec, and the per-chunk metadata (into [`Self::streamed`]) with the chunk
/// buffers in the `read_typed` bulk-record list. As of 3f-5 the oracle's
/// streaming-flip retry re-parses the opposite branch when a mis-resolved
/// `streaming` guess makes the chosen branch fail. The non-streaming non-cooked
/// `RawData` path (a single uncompressed `FByteBulkData` + the
/// `CompressedDataGuid`) is now parsed too, so every `(streaming, cooked)` combo
/// is a real read and the retry is unconditional (matching the oracle). Only the
/// per-codec audio decoders (the `FormatHandler`s) remain.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct SoundWaveData {
    /// The `USoundBase` tagged-property segment (audio settings), in wire order.
    pub properties: property::bag::PropertyBag,
    /// `bCooked` — extracted from `Flags & CookedFlag` (bit 0) of the
    /// USoundWave binary header (3f-2). Cooked assets carry compressed
    /// per-codec buffers; paksmith only targets cooked content.
    pub cooked: bool,
    /// Resolved `bStreaming` (3f-2): whether the audio data is chunked for
    /// on-demand streaming vs. loaded inline. Resolved from the version-table
    /// default + the tagged `bStreaming` / `LoadingBehavior` properties (see
    /// `audio::sound_wave`). This **branches** the platform-data parse: `false`
    /// reads the non-streaming branch — `FFormatContainer` (cooked, 3f-3) or the
    /// `RawData` `FByteBulkData` (non-cooked); `true` reads the streaming
    /// `CompressedDataGuid` + (when cooked) `FStreamedAudioPlatformData` into
    /// [`Self::streamed`] (3f-4). `streaming = true` is the modern-cooked default
    /// (`is_ue4_25_or_later`). The resolved value is a heuristic that can be
    /// wrong, so 3f-5 added the oracle's streaming-flip retry: on a parse failure
    /// the reader rewinds, flips this value, and re-parses the opposite branch —
    /// so a mis-resolved asset recovers and this field reflects the branch that
    /// actually parsed. The retry is unconditional (every branch is a real read);
    /// if both branches fail the parse falls back to `Asset::Generic`.
    pub streaming: bool,
    /// Per-codec keys of the non-streaming cooked `FFormatContainer` (e.g.
    /// `"OGG"`, `"OPUS"`, `"BINKA"`), in wire order. Each
    /// `compressed_format_keys[i]` identifies the codec of the `i`-th
    /// `FByteBulkData` record this export returns from `read_typed` (positional
    /// correspondence, as with `Texture2DData::mips`). Empty on the streaming
    /// branch, the non-cooked `RawData` path, or a cooked asset with no formats.
    /// The `read_typed` bulk records are the format buffers here, the
    /// [`Self::streamed`] chunk buffers (streaming), or the single `RawData`
    /// record (non-cooked) — never a mix. Phase 3f-3.
    pub compressed_format_keys: Vec<std::sync::Arc<str>>,
    /// The `CompressedDataGuid` (`FGuid`) identifying this cook of the compressed
    /// audio. Read on every platform-data branch (after `FFormatContainer` /
    /// `RawData` on the non-streaming branch, or first on the streaming branch),
    /// so a successfully-parsed `SoundWaveData` always carries it (a parse that
    /// fails before the GUID yields `Err`, not a `SoundWaveData`). Phase 3f-3.
    pub compressed_data_guid: guid::FGuid,
    /// The streaming platform data (`FStreamedAudioPlatformData`) — `Some` only
    /// on the `streaming && cooked` branch (3f-4); `None` otherwise. Its
    /// per-chunk buffers are the `read_typed` bulk records (positional; see the
    /// XOR note on [`Self::compressed_format_keys`]). Phase 3f-4.
    pub streamed: Option<StreamedAudioData>,
}

/// The streaming platform data of a `USoundWave` (`FStreamedAudioPlatformData`):
/// the codec and the per-chunk metadata. The chunks' compressed bytes are the
/// `FByteBulkData` records [`SoundWaveData`]'s export returns from `read_typed`,
/// positionally aligned (`chunks[i]` ↔ bulk record `i`). Phase 3f-4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct StreamedAudioData {
    /// `AudioFormat` — the codec `FName` shared by every chunk (e.g. `"OGG"`),
    /// resolved against the name table.
    pub audio_format: std::sync::Arc<str>,
    /// Per-chunk metadata, in wire order.
    pub chunks: Vec<StreamedAudioChunk>,
}

/// One streamed audio chunk's metadata (`FStreamedAudioChunk`). The chunk's
/// compressed bytes live in the corresponding `FByteBulkData` record (not here).
/// Phase 3f-4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct StreamedAudioChunk {
    /// `DataSize` — the chunk's **declared** on-disk payload size in bytes,
    /// nominally including the trailing zero padding (a UE-cooker contract that
    /// `DataSize` equals the materialized `FByteBulkData` buffer length). Wire
    /// `i32`, stored as-read and **not validated** against the resolved payload
    /// length — neither the oracle nor paksmith checks the equality, and
    /// `OggHandler` ignores this field entirely, using the payload length as the
    /// authoritative bound. The real audio occupies only the first
    /// [`audio_data_size`](Self::audio_data_size) bytes.
    pub data_size: i32,
    /// `AudioDataSize` — the count of real audio bytes at the **front** of the
    /// `DataSize`-padded chunk buffer (`AudioDataSize <= DataSize`; the
    /// remainder is zero padding). Reassembling the codec stream concatenates
    /// the first `AudioDataSize` bytes of each chunk's payload — mirroring
    /// CUE4Parse `SoundDecoder` (`Sum(AudioDataSize)`-sized output,
    /// `BlockCopy(payload, 0, .., AudioDataSize)`). Wire `i32`, stored as-read;
    /// the `OggHandler` validates it against the materialized payload length
    /// before slicing.
    pub audio_data_size: i32,
    /// `SeekOffsetInAudioFrames`, present only when the chunk's
    /// `EStreamedAudioChunk::HasSeekOffset` (bit 1) flag is set.
    pub seek_offset_in_audio_frames: Option<u32>,
}

impl SoundWaveData {
    /// Cheap, zero-allocation empty sound wave — the discriminant sentinel for
    /// registering audio handlers (e.g. [`OggHandler`]) in
    /// [`crate::export::HandlerRegistry::all_default_handlers`]
    /// (`std::mem::discriminant` ignores the payload). All fields are
    /// zero / empty; `properties` is an empty `Opaque` bag and
    /// `compressed_data_guid` is the all-zero GUID. Mirrors the
    /// [`DataTableData::empty`] / [`Texture2DData::empty`] precedent.
    ///
    /// [`OggHandler`]: crate::export::OggHandler
    #[must_use]
    pub fn empty() -> Self {
        Self {
            properties: property::bag::PropertyBag::opaque(Vec::new()),
            cooked: false,
            streaming: false,
            compressed_format_keys: Vec::new(),
            compressed_data_guid: guid::FGuid::default(),
            streamed: None,
        }
    }
}

/// Parsed contents of a `UTexture2D` export.
///
/// Phase 3e. Produced by `texture::texture2d::read_from`; consumed by
/// the upcoming `PngHandler` (3e-8).
///
/// **Grows across the 3e milestones.** As of 3e-3 it carries the
/// segment-1 tagged properties, the full `FTexturePlatformData` header
/// (`size_x`, `size_y`, `pixel_format`, `num_slices`, `is_cubemap`,
/// `num_mips_in_tail`, `first_mip_to_serialize`, `mip_count`), and the
/// per-mip dimension chain ([`mips`](Self::mips)); the virtual-texture
/// page-table data lands in its own later milestone. The struct is
/// `#[non_exhaustive]` and constructed only inside this crate, so adding
/// fields is non-breaking — matching the [`DataTableData`] precedent.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Texture2DData {
    /// Segment-1 tagged properties (`SRGB`, `CompressionSettings`,
    /// `Filter`, `AddressX`/`AddressY`, `LODBias`, …), decoded by the
    /// standard `FPropertyTag` iterator. See
    /// `docs/formats/texture/texture2d.md` §"Segment 1".
    pub properties: property::bag::PropertyBag,
    /// Top-mip width in pixels (`FTexturePlatformData::SizeX`). Phase 3e-2.
    pub size_x: u32,
    /// Top-mip height in pixels (`FTexturePlatformData::SizeY`). Phase 3e-2.
    pub size_y: u32,
    /// `EPixelFormat` variant name (e.g. `"PF_DXT5"`) — drives mip-byte
    /// interpretation once the per-format decoders land. Phase 3e-2.
    pub pixel_format: String,
    /// Slice count from `PackedData` (`& 0x3FFF_FFFF`; `1` for a plain
    /// 2D texture). Follows CUE4Parse's `GetNumSlices()` convention of
    /// NOT stripping the overlapping `HasCpuCopy` bit. Phase 3e-2.
    pub num_slices: u32,
    /// Cubemap flag (`PackedData` bit 31). Phase 3e-2.
    pub is_cubemap: bool,
    /// `FOptTexturePlatformData::NumMipsInTail` — the count of trailing
    /// packed mips — when the optional-data record is present
    /// (`PackedData` bit 30), else `None`. Feeds 3e-3's mip-tail
    /// unpacking. The sibling `ExtData` is read-and-discarded (opaque
    /// platform extension data). Phase 3e-2b.
    pub num_mips_in_tail: Option<u32>,
    /// `FirstMipToSerialize` — the top-mip skip-count the cooker applied
    /// for downscaled platforms. Phase 3e-2b.
    pub first_mip_to_serialize: i32,
    /// Number of `FTexture2DMipMap` records that follow in segment 2
    /// (the mip-count prefix). Equals `mips.len()`. Phase 3e-2b.
    pub mip_count: u32,
    /// Per-mip dimensions, in wire order (mip 0 = top mip). When mip data
    /// is serialized (the common case — owner `bSerializeMipData`, true for
    /// UE4/5.0/5.1/5.2 and the default), each entry's encoded bytes are the
    /// `i`-th `FByteBulkData` record this export returns from `read_typed`,
    /// i.e. `mips[i]` ↔ the export's bulk record `i` (positional), resolved
    /// lazily through `Package::resolve_bulk_for_export`. When
    /// `bSerializeMipData` is false (a UE 5.3+ texture) the mips carry no
    /// inline bulk data and the export returns an empty record list. This
    /// struct holds only the dimensions either way. Phase 3e-3.
    pub mips: Vec<Texture2DMipMap>,
    /// The parsed `FVirtualTextureBuiltData` blob when the texture's trailing
    /// `bIsVirtual` flag (UE 4.23+, gated by
    /// [`AssetVersion::is_virtual_textures_or_later`](crate::asset::version::AssetVersion::is_virtual_textures_or_later))
    /// is set — marking a sparse/paged **virtual texture** whose pixel data
    /// lives in this blob rather than the (typically empty) standard mip chain
    /// above. `None` for the standard mip-chain textures that are the common
    /// case. A malformed blob fails the whole read (→ `Generic`), so this is
    /// `Some` iff the texture is virtual — query via [`Self::is_virtual`].
    ///
    /// Phase 3e-VT-b1 parses the **structural** fields (header, dispatch
    /// tables, layer formats); the `FVirtualTextureDataChunk[]` tile payloads
    /// are added in 3e-VT-b2 and flattened to pixels in 3e-VT-c.
    ///
    /// `Box`ed because virtual textures are rare and the blob is large
    /// (many dispatch `Vec`s): boxing keeps the common non-virtual
    /// `Texture2DData` — and the `Asset::Texture2D` enum variant — small.
    pub virtual_texture:
        Option<Box<crate::asset::exports::texture::virtual_textures::VirtualTextureData>>,
}

impl Texture2DData {
    /// Cheap, zero-allocation empty texture — the discriminant sentinel for
    /// registering the PNG handler in
    /// [`crate::export::HandlerRegistry::all_default_handlers`]
    /// (`std::mem::discriminant` ignores the payload). All fields are zero /
    /// `String::new()` / `Vec::new()`; `properties` is an empty `Tree`.
    /// Mirrors the [`DataTableData::empty`] precedent.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            properties: property::bag::PropertyBag::tree(Vec::new()),
            size_x: 0,
            size_y: 0,
            pixel_format: String::new(),
            num_slices: 0,
            is_cubemap: false,
            num_mips_in_tail: None,
            first_mip_to_serialize: 0,
            mip_count: 0,
            mips: Vec::new(),
            virtual_texture: None,
        }
    }

    /// Whether this is a virtual (sparse/paged) texture — i.e. its trailing
    /// `bIsVirtual` flag was set and the `FVirtualTextureBuiltData` blob
    /// parsed into [`Self::virtual_texture`]. Single source of truth (no
    /// separate flag field to drift out of sync).
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        self.virtual_texture.is_some()
    }
}

/// Per-mip dimensions of a `UTexture2D` mip chain
/// (`FTexture2DMipMap`'s `SizeX`/`SizeY`/`SizeZ`). The mip's encoded
/// bytes live in the export's positionally-corresponding `FByteBulkData`
/// record (resolved via `Package::resolve_bulk_for_export`), not here.
/// Phase 3e-3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Texture2DMipMap {
    /// Mip width in pixels (block units for block-compressed formats).
    pub size_x: u32,
    /// Mip height.
    pub size_y: u32,
    /// Mip depth (`1` for a plain `Texture2D`; `>1` for volume/array
    /// textures and cubemaps).
    pub size_z: u32,
}

/// Bundle threading the parsed name/import/export tables, version, and
/// optional `.usmap` schema registry through downstream property
/// parsers (Phase 2b+).
///
/// **Thread safety:** `AssetContext: Send + Sync`. All components are
/// `Arc`-shared immutable data — safe to clone and share across
/// worker threads. Pinned by the `send_sync_assertions` test in
/// `lib.rs`.
///
/// `Arc`-wrapped components so `clone()` is a handful of atomic refcount
/// bumps — important because the GUI's PropertyInspector widget holds a
/// context across many event-loop ticks and must not block on table
/// copies. (`version` is `Copy`; `mappings` is `Option<Arc<_>>`.) Built
/// from a parsed [`Package`] via [`Package::context`].
///
/// Marked `#[non_exhaustive]` because additional version-gate fields
/// land here without a major bump (`custom_versions` shipped with #355;
/// future ones may follow). Construct via [`AssetContext::new`] or
/// [`Package::context`] — struct-literal construction is blocked at
/// the public-API boundary.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AssetContext {
    /// The parsed FName pool (shared by all import/export references).
    pub names: Arc<NameTable>,
    /// The parsed import table.
    pub imports: Arc<ImportTable>,
    /// The parsed export table.
    pub exports: Arc<ExportTable>,
    /// Version constants the parsers branch on.
    pub version: AssetVersion,
    /// Per-plugin custom-version stamps from the package summary.
    /// Required by readers that gate wire-format fields on a specific
    /// plugin's local version (e.g., `FText::None` gates the
    /// `bHasCultureInvariantString` u32 on `FEditorObjectVersion`).
    /// `Arc`-wrapped to keep `clone()` refcount-cheap.
    pub custom_versions: Arc<custom_version::CustomVersionContainer>,
    /// Optional `.usmap` schema registry. Required when
    /// `summary.package_flags & PKG_UnversionedProperties != 0`; `None`
    /// for tagged-property packages (Phase 2b/2c). `Arc`-wrapped so
    /// multiple Phase 2f call paths can share one parsed `Usmap`
    /// without cloning the registry on every context clone.
    pub mappings: Option<Arc<mappings::Usmap>>,
    /// The package's bulk-data resolver, when reading from a real
    /// container (`Package::read_from*`). Threaded onto the context so
    /// typed readers can resolve a non-inlined (streamed) `FByteBulkData`
    /// payload — e.g. a static mesh's out-of-line LOD geometry — without a
    /// `TypedReaderFn` signature change. `None` for the in-memory test/
    /// header-only construction paths (a reader that needs it then degrades
    /// to [`crate::error::PaksmithError::UnsupportedFeature`]). `Arc`-shared
    /// with `Package::resolver`, so cloning a context stays refcount-cheap.
    pub(crate) bulk_resolver: Option<Arc<bulk_data::BulkDataResolver>>,
}

impl AssetContext {
    /// Construct an `AssetContext`. The public constructor; the struct
    /// is `#[non_exhaustive]` so external callers cannot use a struct
    /// literal.
    #[must_use]
    pub fn new(
        names: Arc<NameTable>,
        imports: Arc<ImportTable>,
        exports: Arc<ExportTable>,
        version: AssetVersion,
        custom_versions: Arc<custom_version::CustomVersionContainer>,
        mappings: Option<Arc<mappings::Usmap>>,
    ) -> Self {
        Self {
            names,
            imports,
            exports,
            version,
            custom_versions,
            mappings,
            bulk_resolver: None,
        }
    }
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;

    #[test]
    fn asset_generic_clone_and_debug() {
        // Phase 3 per-export shape: Asset::Generic wraps a single
        // export's PropertyBag (not the whole Package).
        let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
        let asset = Asset::Generic(bag);
        let cloned = asset.clone();
        let dbg = format!("{cloned:?}");
        assert!(dbg.starts_with("Generic("), "got: {dbg}");
    }

    #[test]
    fn asset_generic_serializes_with_externally_tagged_shape() {
        // Pin the externally-tagged JSON shape: {"Generic": <PropertyBag JSON>}.
        // The inner PropertyBag has `#[serde(tag = "kind", rename_all = "snake_case")]`
        // so an Opaque bag renders as {"kind": "opaque", "bytes": <count>}.
        // Phase 3 sub-phases (3d-3h) add typed Asset variants (DataTable,
        // Texture2D, etc.) under sibling tags ("DataTable", "Texture2D", ...).
        let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
        let asset = Asset::Generic(bag);
        let json = serde_json::to_string(&asset).unwrap();
        assert!(
            json.starts_with(r#"{"Generic":{"kind":"opaque""#),
            "expected externally-tagged Generic shape; got: {json}"
        );
        assert!(
            json.contains(r#""bytes":32"#),
            "expected PropertyBag::Opaque byte count; got: {json}"
        );
    }

    #[test]
    fn skeletal_mesh_empty_is_constructible_and_matches_variant() {
        let asset = Asset::SkeletalMesh(SkeletalMeshData::empty());
        assert!(matches!(asset, Asset::SkeletalMesh(_)));
        let Asset::SkeletalMesh(d) = asset else {
            unreachable!()
        };
        assert!(d.skeleton.bones.is_empty());
        assert!(d.lods.is_empty());
        assert!(!d.cooked);
    }

    #[test]
    fn skel_mesh_section_carries_render_fields() {
        // Construct with the PR3 render fields and read every one back. The
        // signed `-1` / `>0` literals pin against `delete -` / wrong-value
        // mutants (the struct `Default` would give `0`/`false`).
        let section = SkelMeshSection {
            material_index: 2,
            base_index: 36,
            num_triangles: 12,
            base_vertex_index: 7,
            num_vertices: 24,
            max_bone_influences: 4,
            bone_map: vec![5u16, 9, 13],
            recompute_tangent: true,
            recompute_tangents_vertex_mask_channel: 3,
            cast_shadow: true,
            visible_in_ray_tracing: true,
            disabled: false,
            correspond_cloth_asset_index: -1,
            has_cloth_data: true,
        };
        assert_eq!(section.bone_map, vec![5u16, 9, 13]);
        assert!(section.recompute_tangent);
        assert_eq!(section.recompute_tangents_vertex_mask_channel, 3);
        assert!(section.cast_shadow);
        assert!(section.visible_in_ray_tracing);
        assert!(!section.disabled);
        assert_eq!(section.correspond_cloth_asset_index, -1);
        assert!(section.has_cloth_data);
    }

    #[test]
    fn skeletal_mesh_lod_carries_bone_arrays() {
        // Construct with the PR4 bone arrays and read each back. Pins against
        // `delete` / field-swap mutants (the struct `Default` gives empty Vecs).
        let lod = SkeletalMeshLod {
            active_bone_indices: vec![1u16, 2, 3],
            required_bones: vec![0u16, 4, 7, 9],
            ..SkeletalMeshLod::default()
        };
        assert_eq!(lod.active_bone_indices, vec![1u16, 2, 3]);
        assert_eq!(lod.required_bones, vec![0u16, 4, 7, 9]);
    }

    #[test]
    fn skeletal_mesh_lod_default_bone_arrays_are_empty() {
        let lod = SkeletalMeshLod::default();
        assert!(lod.active_bone_indices.is_empty());
        assert!(lod.required_bones.is_empty());
    }

    #[test]
    fn bone_weights_len_and_is_empty_track_population() {
        // Default / no-skin is empty in both reads.
        let empty = BoneWeights::default();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        // A populated U8 buffer reports its vertex count and is NOT empty —
        // pins `is_empty -> true` and `len -> 0` mutants on both variants.
        let u8_buf = BoneWeights::U8(vec![[0u8; 8], [1u8; 8]]);
        assert_eq!(u8_buf.len(), 2);
        assert!(!u8_buf.is_empty());

        let u16_buf = BoneWeights::U16(vec![[0u16; 8]]);
        assert_eq!(u16_buf.len(), 1);
        assert!(!u16_buf.is_empty());
    }

    #[test]
    fn skel_mesh_section_default_is_zeroed() {
        let section = SkelMeshSection::default();
        assert!(section.bone_map.is_empty());
        assert!(!section.recompute_tangent);
        assert_eq!(section.recompute_tangents_vertex_mask_channel, 0);
        assert!(!section.cast_shadow);
        assert!(!section.visible_in_ray_tracing);
        assert!(!section.disabled);
        assert_eq!(section.correspond_cloth_asset_index, 0);
        assert!(!section.has_cloth_data);
    }
}
