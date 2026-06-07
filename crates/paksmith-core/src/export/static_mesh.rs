//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.
//!
//! Phase 3h (skeletal mesh) reuse: the LOD-agnostic helpers — [`GltfDoc`],
//! [`convert_position`]/[`convert_dir`]/[`convert_tangent`]/[`normalize_xyz`],
//! [`reverse_winding`], [`encode_f32_le`], [`finish_glb`], and the
//! [`MAX_GLB_BIN_BYTES`]/[`MAX_MESH_MATERIALS`] caps — are independent of
//! [`StaticMeshLod`] and reusable as-is. The remaining helpers
//! ([`push_positions`]/[`push_normals`]/[`push_tangents`]/[`push_uvs`]/[`push_colors`],
//! [`push_primitives`], [`resolve_section_indices`], [`build_materials`],
//! [`projected_bin_bytes`]) are bound to [`StaticMeshLod`]/[`StaticMeshRenderData`]
//! and would need skeletal-mesh analogues.

use std::borrow::Cow;
use std::collections::BTreeMap;

use gltf::json::Index;
use gltf::json::accessor::{ComponentType, GenericComponentType, Type};
use gltf::json::buffer::Target;
use gltf::json::mesh::{Mode, Primitive, Semantic};
use gltf::json::validation::Checked::Valid;
use gltf::json::validation::USize64;

use crate::asset::structs::vector::{FVector, FVector4};
use crate::asset::{Asset, StaticMeshLod, StaticMeshRenderData};
use crate::export::{BulkData, FormatHandler};

/// Maximum number of material slots a single static mesh may reference before
/// the glTF export is rejected. `section.material_index` is unchecked `i32` wire
/// data; without a cap a corrupt cook could request ~2 billion placeholder
/// [`Material`](gltf::json::Material) structs (memory-exhaustion DoS) and the
/// `max_ref + 1` sizing would overflow. Real meshes rarely exceed ~64 slots, so
/// 256 is generous. An over-cap mesh yields
/// [`PaksmithError::UnsupportedFeature`](crate::PaksmithError::UnsupportedFeature),
/// which the caller (the export driver) surfaces as it sees fit.
pub(crate) const MAX_MESH_MATERIALS: u32 = 256;

// NOTE: no `#[cfg(feature = "__test_utils")] max_mesh_materials()` accessor —
// per the `texture2d.rs` convention and the sibling mesh caps
// (`MAX_VERTICES_PER_LOD`, `MAX_SECTIONS_PER_LOD`, `MAX_LODS_PER_MESH`,
// `MAX_SOCKETS_PER_MESH`), a cap accessor with no integration-test consumer is
// dead code (an uncovered `fn -> CONST` passthrough mutant). The in-source tests
// pin the cap via the `UnsupportedFeature` over-cap path
// (`materials_over_cap_is_rejected` / `materials_at_cap_boundary_is_accepted`).

/// Upper bound on the aggregate glTF BIN buffer a single mesh may produce
/// (aggregate-output decompression-bomb guard). A corrupt `num_triangles` makes
/// a section's index span clamp to the FULL index buffer; with up to
/// `MAX_SECTIONS_PER_LOD` sections each duplicating that buffer across
/// `MAX_LODS_PER_MESH` LODs the accumulated `bin` could reach tens of GiB (OOM),
/// and past 4.29 GiB the GLB `u32` length field silently truncates. A real mesh
/// is far under 1 GiB, so this is generous headroom while bounding a crafted
/// mesh. Checked **pre-flight** via [`projected_bin_bytes`] BEFORE allocating —
/// follows the `pcm.rs` `MAX_AUDIO_DECODED_BYTES` convention. No
/// `#[cfg(feature = "__test_utils")]` accessor (per the sibling mesh-cap
/// pattern); the over-cap test pins it via the `UnsupportedFeature` path.
pub(crate) const MAX_GLB_BIN_BYTES: u64 = 1 << 30; // 1 GiB

/// Lowers a cooked `UStaticMesh` into a self-contained glTF 2.0 binary (`.glb`).
/// See `docs/plans/phase-3g2-gltf-export.md`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfStaticMeshHandler;

impl FormatHandler for GltfStaticMeshHandler {
    fn output_extension(&self) -> &'static str {
        "glb"
    }

    /// Accepts a `StaticMesh` carrying render data. Uncooked / Nanite / legacy /
    /// no-render-data meshes are degraded to [`Asset::Generic`] by the parser
    /// upstream, so they never reach this handler. (Were such a mesh to arrive
    /// here, `HandlerRegistry::find_handler` would simply return `None` for the
    /// unsupported `StaticMesh` — it would NOT route to the generic handler.)
    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::StaticMesh(d) if d.render_data.is_some())
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::StaticMesh(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a non-StaticMesh Asset"
                    .to_string(),
            });
        };
        let render = data
            .render_data
            .as_ref()
            .ok_or_else(|| crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a StaticMesh with no render data"
                    .to_string(),
            })?;

        // Pre-flight aggregate-output cap: reject a mesh whose lowering WOULD
        // allocate more than [`MAX_GLB_BIN_BYTES`] before allocating any of it.
        // A corrupt `num_triangles` can duplicate the full index buffer across
        // sections/LODs (memory-exhaustion DoS / `u32` GLB-length truncation).
        enforce_export_cap(render)?;

        let mut doc = GltfDoc::new();
        build_materials(&mut doc, render)?;
        let mut scene_nodes = Vec::with_capacity(render.lods.len());
        for (i, lod) in render.lods.iter().enumerate() {
            let prims = push_primitives(&mut doc, lod);
            // A LOD with no geometry (empty positions, or every section's index
            // range empty) produces zero primitives. A glTF mesh requires
            // `primitives.len() ≥ 1`, so skip the node/mesh entirely. The `LOD{i}`
            // name uses the source LOD ordinal `i`, so names still reflect the
            // original index even though emitted nodes may be non-contiguous.
            if prims.is_empty() {
                continue;
            }
            let mesh = doc.root.push(gltf::json::Mesh {
                primitives: prims,
                weights: None,
                name: Some(format!("LOD{i}")),
                extensions: None,
                extras: gltf::json::extras::Void::default(),
            });
            let node = doc.root.push(gltf::json::Node {
                mesh: Some(mesh),
                name: Some(format!("LOD{i}")),
                ..gltf::json::Node::default()
            });
            scene_nodes.push(node);
        }
        let scene = doc.root.push(gltf::json::Scene {
            nodes: scene_nodes,
            name: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
        doc.root.scene = Some(scene);

        let (root, bin) = doc.into_parts();
        finish_glb(&root, bin)
    }
}

/// Push one placeholder glTF [`Material`](gltf::json::Material) per referenced
/// slot. The slot count is `max_ref + 1`, where `max_ref` is the largest
/// non-negative `material_index` across every LOD's sections (no sections ⇒ zero
/// materials). Sizing to the maximum referenced slot guarantees every
/// primitive's `material` index is in range, so there is no out-of-range error
/// path. Placeholder names are `Material_<i>`; resolving real slot names from
/// the `StaticMaterials` tagged property is deferred to a later phase.
///
/// `material_index` is unchecked `i32` wire data. To avoid a memory-exhaustion
/// DoS (and the `max_ref + 1` overflow that would panic in debug on
/// `i32::MAX`), `max_ref` is folded as an `Option<i32>` (each term is `≥ 0` via
/// `.max(0)`) and compared against [`MAX_MESH_MATERIALS`] *as `u32`* — never
/// incrementing the `i32`. A mesh exceeding the cap yields
/// [`PaksmithError::UnsupportedFeature`](crate::PaksmithError::UnsupportedFeature);
/// this error is returned to the caller (the export driver) — NOT to the package
/// walker — so the caller decides how to surface it.
fn build_materials(doc: &mut GltfDoc, render: &StaticMeshRenderData) -> crate::Result<()> {
    let Some(max_ref) = render
        .lods
        .iter()
        .flat_map(|l| &l.sections)
        .map(|s| s.material_index.max(0))
        .max()
    else {
        return Ok(()); // no sections → zero materials
    };
    // `max_ref ≥ 0` (each term went through `.max(0)`), so `try_from` cannot
    // fail; the fallback is unreachable but avoids a bare `as` sign-loss cast.
    let max_ref = u32::try_from(max_ref).unwrap_or(u32::MAX);
    // `max_ref >= MAX_MESH_MATERIALS` ⇔ `max_ref + 1 > MAX_MESH_MATERIALS`, with
    // no `i32`/`u32` increment before the comparison.
    if max_ref >= MAX_MESH_MATERIALS {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "static mesh references material slot {max_ref} exceeding the \
                 {MAX_MESH_MATERIALS}-slot export cap"
            ),
        });
    }
    for i in 0..=max_ref {
        let _ = doc.root.push(gltf::json::Material {
            name: Some(format!("Material_{i}")),
            ..gltf::json::Material::default()
        });
    }
    Ok(())
}

/// Accumulates the single glTF BIN buffer + the `json::Root` under construction.
/// Each `push_accessor` 4-byte-aligns the buffer, emits a `buffer::View` and an
/// `accessor::Accessor`, and returns the accessor index for primitive wiring.
struct GltfDoc {
    root: gltf::json::Root,
    bin: Vec<u8>,
}

impl GltfDoc {
    fn new() -> Self {
        Self {
            root: gltf::json::Root::default(),
            bin: Vec::new(),
        }
    }

    /// Zero-pad the BIN buffer up to the next 4-byte boundary. glTF bufferViews
    /// must start 4-aligned and the final buffer length must be 4-aligned.
    fn align_to_4(&mut self) {
        while !self.bin.len().is_multiple_of(4) {
            self.bin.push(0);
        }
    }

    /// Append `data` as a new bufferView + accessor. `min`/`max` are the
    /// glTF-required position bounds (or `None`); `target` distinguishes vertex
    /// (`ArrayBuffer`) from index (`ElementArrayBuffer`) views.
    #[allow(clippy::too_many_arguments)]
    fn push_accessor(
        &mut self,
        data: &[u8],
        component_type: ComponentType,
        type_: Type,
        count: usize,
        target: Option<Target>,
        min: Option<serde_json::Value>,
        max: Option<serde_json::Value>,
        normalized: bool,
    ) -> Index<gltf::json::Accessor> {
        // 4-byte-align the start of every view (covers u8 index buffers etc.).
        self.align_to_4();
        let byte_offset = self.bin.len();
        self.bin.extend_from_slice(data);

        let view = self.root.push(gltf::json::buffer::View {
            buffer: Index::new(0),
            byte_length: USize64::from(data.len()),
            byte_offset: Some(USize64::from(byte_offset)),
            byte_stride: None,
            name: None,
            target: target.map(Valid),
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });

        self.root.push(gltf::json::Accessor {
            buffer_view: Some(view),
            byte_offset: Some(USize64(0)),
            count: USize64::from(count),
            component_type: Valid(GenericComponentType(component_type)),
            type_: Valid(type_),
            name: None,
            min,
            max,
            normalized,
            sparse: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        })
    }

    /// Finalize: register the single buffer (4-aligned) and return `(root, bin)`.
    fn into_parts(mut self) -> (gltf::json::Root, Vec<u8>) {
        self.align_to_4();
        // A self-contained GLB buffer carries no `uri`. Its index is fixed at 0
        // (no other buffer is created), so the returned `Index` is discarded.
        let _ = self.root.push(gltf::json::Buffer {
            byte_length: USize64::from(self.bin.len()),
            name: None,
            uri: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
        (self.root, self.bin)
    }
}

/// Serialize `root` + the BIN `buffer` into GLB bytes.
fn finish_glb(root: &gltf::json::Root, bin: Vec<u8>) -> crate::Result<Vec<u8>> {
    let json = serde_json::to_vec(root).map_err(|e| crate::PaksmithError::Internal {
        context: format!("glTF JSON serialization failed: {e}"),
    })?;
    // No manual 4-byte padding here: `GltfDoc::into_parts` already pads the BIN
    // buffer, and `gltf::binary::Glb::to_vec` pads both the JSON chunk (with
    // 0x20 spaces) and the BIN chunk (with 0x00) internally. A manual pad loop
    // is a no-op the test suite can't observe — an equivalent mutant.
    let bin = if bin.is_empty() {
        None
    } else {
        Some(Cow::Owned(bin))
    };
    let glb = gltf::binary::Glb {
        header: gltf::binary::Header {
            magic: *b"glTF",
            version: 2,
            length: 0,
        },
        json: Cow::Owned(json),
        bin,
    };
    glb.to_vec().map_err(|e| crate::PaksmithError::Internal {
        context: format!("GLB container assembly failed: {e}"),
    })
}

/// UE → glTF metres-per-centimetre scale.
const UE_CM_TO_M: f32 = 0.01;

/// Serialize a sequence of `[f32; N]` tuples into a little-endian byte buffer,
/// component-major (`v[0].x, v[0].y, …, v[1].x, …`). Shared by the
/// non-interleaved vertex attributes (`NORMAL`/`TANGENT`/`TEXCOORD_n`);
/// `push_positions` keeps its own loop because it also folds component-wise
/// min/max while encoding.
fn encode_f32_le<const N: usize>(items: impl ExactSizeIterator<Item = [f32; N]>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(items.len() * N * 4);
    for item in items {
        for f in item {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    bytes
}

/// Map a UE position (left-handed, Z-up, cm) to glTF (right-handed, Y-up, m).
/// Swapping Y and Z moves Z-up to Y-up AND flips handedness (basis det = −1);
/// positions also scale cm→m.
///
/// Matches CUE4Parse's glTF exporter `Gltf.cs` (`FabianFG/CUE4Parse`,
/// `CUE4Parse-Conversion/Meshes/glTF/Gltf.cs`): `SwapYZ(pos * 0.01f)` where
/// `SwapYZ(v) = new FVector(v.X, v.Z, v.Y)` — `(x, z, y)`, no negation. The
/// Blender cube oracle (Task 12) is the final visual confirmation.
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_position(v: &FVector) -> [f32; 3] {
    [
        v.x as f32 * UE_CM_TO_M,
        v.z as f32 * UE_CM_TO_M,
        v.y as f32 * UE_CM_TO_M,
    ]
}

/// Normalize an `(x, y, z)` triple to unit length, matching CUE4Parse's
/// post-`SwapYZ` `Normalize`. glTF requires unit-length `NORMAL`/`TANGENT`.
///
/// Degenerate guard: if the magnitude is zero or non-finite (NaN/∞), the input
/// is returned unchanged rather than dividing by zero and producing NaN.
fn normalize_xyz([x, y, z]: [f32; 3]) -> [f32; 3] {
    let len = (x * x + y * y + z * z).sqrt();
    if len > 0.0 && len.is_finite() {
        [x / len, y / len, z / len]
    } else {
        [x, y, z]
    }
}

/// Map a UE unit direction (normal) — same `(x, z, y)` basis as
/// [`convert_position`], no scale, then renormalize to unit length.
///
/// Matches CUE4Parse's `SwapYZAndNormalize`: the `(x, z, y)` basis swap followed
/// by a `Normalize`. glTF requires unit-length `NORMAL`; decoded values may not
/// be exactly unit after dequantization, so [`normalize_xyz`] enforces it (with
/// a zero/non-finite guard).
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_dir(v: &FVector) -> [f32; 3] {
    normalize_xyz([v.x as f32, v.z as f32, v.y as f32])
}

/// Map a UE tangent (`FVector4`): xyz like a direction (basis-swapped and
/// renormalized to unit length), `w` (handedness ±1) **negated**.
///
/// The `(x, z, y)` basis swap has determinant −1, which flips tangent-space
/// handedness. The glTF bitangent is defined as `cross(N, T.xyz) * T.w`; under
/// a det−1 basis change the cross product picks up the same sign flip, so the
/// stored `w` must be negated (`T_gltf.w = −T_ue.w`) for the reconstructed
/// bitangent to point the correct way. This is the same det−1 origin as the
/// winding reversal in [`reverse_winding`].
///
/// xyz follows CUE4Parse's `SwapYZAndNormalize(Vector4)` (`(x, z, y)` swap +
/// `Normalize`); glTF requires unit-length `TANGENT.xyz` — see [`convert_dir`]
/// for the zero/non-finite guard.
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally
// narrowed for export.
fn convert_tangent(v: &FVector4) -> [f32; 4] {
    let [x, y, z] = normalize_xyz([v.x as f32, v.z as f32, v.y as f32]);
    [x, y, z, -(v.w as f32)]
}

/// Reverse triangle winding (`[a,b,c]` → `[a,c,b]`) to restore CCW front faces
/// after the handedness-flipping basis change. Callers
/// ([`resolve_section_indices`]) floor the span to a multiple of 3 before this,
/// so `indices.len()` is always a whole number of triangles; the trailing
/// `remainder()` copy is defensive-only (a partial tail would be copied verbatim
/// rather than dropped).
///
/// DELIBERATE DIVERGENCE FROM CUE4Parse. CUE4Parse's `Gltf.cs` does NOT reverse
/// winding; it emits explicit NORMAL attributes and relies on viewers not
/// back-face-culling. paksmith reverses so the CCW front-face convention agrees
/// with the basis flip (det = −1). The orientation is verified by
/// `winding_reversal_yields_outward_ccw_faces`, which checks the recomputed
/// geometric face normal agrees with the converted vertex normal (a no-reverse
/// mutant flips the sign); the Blender cube render (Task 12) is the visual
/// confirmation.
fn reverse_winding(indices: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(indices.len());
    let mut tri = indices.chunks_exact(3);
    for c in &mut tri {
        out.extend_from_slice(&[c[0], c[2], c[1]]);
    }
    out.extend_from_slice(tri.remainder());
    out
}

/// Lower a LOD's positions into a `POSITION` accessor (VEC3 f32) with the
/// glTF-required component-wise `min`/`max`.
fn push_positions(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(lod.positions.len() * 12);
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for p in &lod.positions {
        let c = convert_position(p);
        for i in 0..3 {
            min[i] = min[i].min(c[i]);
            max[i] = max[i].max(c[i]);
        }
        for f in c {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    // Empty position list → no finite min/max; emit zeros (degenerate but valid).
    if lod.positions.is_empty() {
        min = [0.0; 3];
        max = [0.0; 3];
    }
    doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.positions.len(),
        Some(Target::ArrayBuffer),
        Some(serde_json::json!(min)),
        Some(serde_json::json!(max)),
        false,
    )
}

/// Lower normals → `NORMAL` accessor (VEC3 f32), or `None` when absent.
fn push_normals(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.normals.is_empty() {
        return None;
    }
    let bytes = encode_f32_le(lod.normals.iter().map(convert_dir));
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.normals.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower tangents → `TANGENT` accessor (VEC4 f32, w = handedness), or `None`.
fn push_tangents(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.tangents.is_empty() {
        return None;
    }
    let bytes = encode_f32_le(lod.tangents.iter().map(convert_tangent));
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec4,
        lod.tangents.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower each present UV channel → a `TEXCOORD_n` accessor (VEC2 f32), in
/// channel order. Returns the accessor indices (`accs[n]` is `TEXCOORD_n`).
/// glTF V flips relative to UE (top-left vs bottom-left origin) is NOT applied —
/// UE UVs are already top-left-origin like glTF, so they map directly.
/// UNVERIFIED: confirmed against published UE docs; visual check pending.
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UV f64 precision is intentionally narrowed.
fn push_uvs(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Index<gltf::json::Accessor>> {
    let mut out = Vec::new();
    for channel in lod.uvs.iter().flatten() {
        let bytes = encode_f32_le(channel.iter().map(|uv| [uv.x as f32, uv.y as f32]));
        out.push(doc.push_accessor(
            &bytes,
            ComponentType::F32,
            Type::Vec2,
            channel.len(),
            Some(Target::ArrayBuffer),
            None,
            None,
            false,
        ));
    }
    out
}

/// Lower per-vertex colors → a `COLOR_0` accessor (VEC4 u8, normalized), or
/// `None`. paksmith stores `FColor` as RGBA already, matching glTF's RGBA order.
fn push_colors(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    let colors = lod.colors.as_ref()?;
    let mut bytes = Vec::with_capacity(colors.len() * 4);
    for c in colors {
        bytes.extend_from_slice(&[c.r, c.g, c.b, c.a]);
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::U8,
        Type::Vec4,
        colors.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        true,
    ))
}

/// Lower a (winding-reversed) index slice → an index accessor. The component
/// width is chosen by the maximum index **value** in the slice: `UNSIGNED_SHORT`
/// when `max ≤ 65 535`, else `UNSIGNED_INT`. Choosing on the value (not the
/// vertex count) is required — a value `> 65 535` must not be silently
/// truncated to `u16`. Target is `ElementArrayBuffer`.
fn push_indices(doc: &mut GltfDoc, indices: &[u32]) -> Index<gltf::json::Accessor> {
    let max_index = indices.iter().copied().max().unwrap_or(0);
    // `u16::try_from(max_index).is_ok()` ⇔ `max_index <= u16::MAX`: every value
    // fits in `u16`, so emit UNSIGNED_SHORT.
    if u16::try_from(max_index).is_ok() {
        let mut bytes = Vec::with_capacity(indices.len() * 2);
        for &i in indices {
            // The `max_index <= u16::MAX` gate guarantees every index < 2^16.
            #[allow(clippy::cast_possible_truncation)]
            bytes.extend_from_slice(&(i as u16).to_le_bytes());
        }
        doc.push_accessor(
            &bytes,
            ComponentType::U16,
            Type::Scalar,
            indices.len(),
            Some(Target::ElementArrayBuffer),
            None,
            None,
            false,
        )
    } else {
        let mut bytes = Vec::with_capacity(indices.len() * 4);
        for &i in indices {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        doc.push_accessor(
            &bytes,
            ComponentType::U32,
            Type::Scalar,
            indices.len(),
            Some(Target::ElementArrayBuffer),
            None,
            None,
            false,
        )
    }
}

/// Resolve every section's index sub-range first (see [`resolve_section_indices`]),
/// then — only if at least one section survives — build the LOD's shared vertex
/// accessors once and emit one [`Primitive`] per surviving
/// [`MeshSection`](crate::asset::MeshSection): shared attributes (cloned) + that
/// section's winding-reversed index accessor + the section's material index. A
/// corrupt negative `material_index` maps to slot 0.
///
/// Returns no primitives — and emits **no accessors** — for a LOD with empty
/// positions OR a LOD where every section's resolved span is empty/sub-triangle:
/// a glTF `accessor.count` must be `≥ 1`, and the shared vertex accessors are
/// built only when a primitive will reference them, so a fully-skipped LOD
/// leaves no orphaned `POSITION` accessor (gltf-validator UNUSED_OBJECT). The
/// caller drops any LOD that ends up with zero primitives.
fn push_primitives(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Primitive> {
    // A LOD with no vertices has no geometry to lower. Returning early *before*
    // building any accessor avoids emitting an invalid `count = 0` POSITION
    // accessor (orphaned in `root.accessors` even when the caller skips the
    // node), which gltf-validator rejects.
    if lod.positions.is_empty() {
        return Vec::new();
    }

    // Resolve each section's winding-reversed index buffer FIRST, before pushing
    // any accessor. A section whose resolved span is empty or sub-triangle is
    // dropped here, so if every section is skipped we push no vertex accessors
    // at all — otherwise the shared POSITION/NORMAL/etc. accessors would be
    // orphaned (no primitive referencing them → gltf-validator UNUSED_OBJECT).
    let sections: Vec<(i32, Vec<u32>)> = lod
        .sections
        .iter()
        .filter_map(|s| resolve_section_indices(lod, s).map(|idx| (s.material_index, idx)))
        .collect();
    if sections.is_empty() {
        return Vec::new();
    }

    // Shared vertex accessors (built once per LOD; cloned into each primitive).
    // Every semantic key is distinct, so `insert` never displaces a prior value;
    // the discarded `Option` returns are intentional (clippy: let_underscore).
    let mut attributes = BTreeMap::new();
    let _ = attributes.insert(Valid(Semantic::Positions), push_positions(doc, lod));
    if let Some(n) = push_normals(doc, lod) {
        let _ = attributes.insert(Valid(Semantic::Normals), n);
    }
    if let Some(t) = push_tangents(doc, lod) {
        let _ = attributes.insert(Valid(Semantic::Tangents), t);
    }
    for (i, uv) in push_uvs(doc, lod).into_iter().enumerate() {
        // UV channel count is at most 4 (the fixed `[_; 4]` array), well within u32.
        #[allow(clippy::cast_possible_truncation)]
        let key = Valid(Semantic::TexCoords(i as u32));
        let _ = attributes.insert(key, uv);
    }
    if let Some(c) = push_colors(doc, lod) {
        let _ = attributes.insert(Valid(Semantic::Colors(0)), c);
    }

    let mut prims = Vec::with_capacity(sections.len());
    for (material_index, section_indices) in sections {
        let idx = push_indices(doc, &section_indices);
        // `.max(0)` guarantees the cast operand is non-negative, so the sign-loss
        // lint cannot apply; a negative slot is remapped to 0.
        #[allow(clippy::cast_sign_loss)]
        let material = Some(Index::new(material_index.max(0) as u32));
        prims.push(Primitive {
            attributes: attributes.clone(),
            indices: Some(idx),
            material,
            mode: Valid(Mode::Triangles),
            targets: None,
            extensions: None,
            extras: gltf::json::extras::Void::default(),
        });
    }
    prims
}

/// Resolve one section's index sub-range into a winding-reversed `Vec<u32>`, or
/// `None` when the section contributes no whole triangle.
///
/// The section's range is `[first_index, first_index + 3·num_triangles)`,
/// clamped to the LOD index buffer (a corrupt over-range count clamps rather
/// than panicking). The clamped span is then floored to a whole number of
/// triangles: the source index buffer's length is only validated `% index_size`
/// (NOT `% 3`) at parse time, `first_index` may not be triangle-aligned, and the
/// clamp can truncate mid-triangle — any of which can leave a leftover 1–2
/// indices. A glTF TRIANGLES primitive requires `count % 3 == 0`, so the partial
/// tail is dropped. An empty or fully-sub-triangle span yields `None` (the
/// caller emits no primitive and no `count = 0` index accessor).
fn resolve_section_indices(lod: &StaticMeshLod, s: &crate::asset::MeshSection) -> Option<Vec<u32>> {
    let first = usize::try_from(s.first_index).unwrap_or(0);
    let len = usize::try_from(s.num_triangles)
        .unwrap_or(0)
        .saturating_mul(3);
    let end = first.saturating_add(len).min(lod.indices.len());
    let avail = end.saturating_sub(first);
    // Floor to a whole number of triangles; drop the 0/1/2-index remainder.
    let tri_len = avail - (avail % 3);
    if tri_len == 0 {
        return None;
    }
    Some(reverse_winding(lod.indices.get(first..first + tri_len)?))
}

/// Sum the BIN bytes [`GltfStaticMeshHandler::export`] WOULD allocate, WITHOUT
/// allocating them — a pure pre-flight projection for the [`MAX_GLB_BIN_BYTES`]
/// aggregate-output cap. All arithmetic saturates (`u64`) because every count is
/// attacker-controlled wire data.
///
/// Per LOD: the vertex attributes (positions ×12, normals ×12, tangents ×16,
/// each present UV channel ×8, colors ×4) plus, per section, the FLOORED
/// triangle span × 4 (an `UNSIGNED_INT` upper bound — the real accessor may pick
/// `UNSIGNED_SHORT`, so this over-estimates and stays a safe upper bound). The
/// span/floor logic mirrors [`resolve_section_indices`] exactly so the estimate
/// tracks reality.
/// `true` when a [`projected_bin_bytes`] estimate exceeds the
/// [`MAX_GLB_BIN_BYTES`] aggregate-output cap. Extracted as a pure predicate so
/// the `> cap` boundary is unit-testable at the exact cap value without
/// allocating a cap-sized mesh (the `export` path can only exercise it via a
/// multi-GiB allocation).
fn exceeds_export_cap(projected: u64) -> bool {
    projected > MAX_GLB_BIN_BYTES
}

/// Reject a mesh whose projected glTF BIN buffer exceeds [`MAX_GLB_BIN_BYTES`]
/// BEFORE any lowering allocates. Pure (no allocation) so the over-cap rejection
/// is unit-testable without building a multi-GiB GLB — the slow `export` path
/// would time out the mutation runner if it had to allocate the projected bytes.
fn enforce_export_cap(render: &StaticMeshRenderData) -> crate::Result<()> {
    let projected = projected_bin_bytes(render);
    if exceeds_export_cap(projected) {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "static mesh projected glTF buffer ({projected} bytes) exceeds the \
                 {MAX_GLB_BIN_BYTES}-byte export cap"
            ),
        });
    }
    Ok(())
}

fn projected_bin_bytes(render: &StaticMeshRenderData) -> u64 {
    let mut total: u64 = 0;
    for lod in &render.lods {
        total = total.saturating_add((lod.positions.len() as u64).saturating_mul(12));
        total = total.saturating_add((lod.normals.len() as u64).saturating_mul(12));
        total = total.saturating_add((lod.tangents.len() as u64).saturating_mul(16));
        for channel in lod.uvs.iter().flatten() {
            total = total.saturating_add((channel.len() as u64).saturating_mul(8));
        }
        if let Some(colors) = lod.colors.as_ref() {
            total = total.saturating_add((colors.len() as u64).saturating_mul(4));
        }
        for s in &lod.sections {
            // Mirror `resolve_section_indices`'s clamp + triangle floor.
            let first = u64::try_from(s.first_index).unwrap_or(0);
            let len = u64::try_from(s.num_triangles)
                .unwrap_or(0)
                .saturating_mul(3);
            let end = first.saturating_add(len).min(lod.indices.len() as u64);
            let avail = end.saturating_sub(first);
            let tri_len = avail - (avail % 3);
            // Each index is at most a u32 (4 bytes) — a safe over-estimate.
            total = total.saturating_add(tri_len.saturating_mul(4));
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::asset::structs::bounds::FBoxSphereBounds;
    use crate::asset::{Asset, StaticMeshData, StaticMeshRenderData};

    fn mesh_with(render: StaticMeshRenderData) -> Asset {
        let mut data = StaticMeshData::empty();
        data.cooked = true;
        data.render_data = Some(render);
        Asset::StaticMesh(data)
    }

    fn empty_render() -> StaticMeshRenderData {
        StaticMeshRenderData {
            lods: Vec::new(),
            bounds: FBoxSphereBounds {
                origin: FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                box_extent: FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                sphere_radius: 0.0,
            },
            lods_share_static_lighting: false,
            screen_sizes: Vec::new(),
        }
    }

    #[test]
    fn extension_is_glb() {
        assert_eq!(GltfStaticMeshHandler.output_extension(), "glb");
    }

    #[test]
    fn supports_cooked_mesh_with_render_data_only() {
        assert!(GltfStaticMeshHandler.supports(&mesh_with(empty_render())));
        assert!(!GltfStaticMeshHandler.supports(&Asset::StaticMesh(StaticMeshData::empty())));
        assert!(!GltfStaticMeshHandler.supports(&Asset::Generic(
            crate::asset::PropertyBag::opaque(Vec::new())
        )));
    }

    #[test]
    fn exports_minimal_valid_glb() {
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(empty_render()), &[])
            .expect("export");
        assert_eq!(&bytes[0..4], b"glTF");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        // gltf-json 1.4.1 derives `Scene::nodes` with
        // `skip_serializing_if = "Vec::is_empty"` on serialize but NO
        // `#[serde(default)]` on deserialize, so re-deserializing into
        // `gltf::json::Root` fails on an empty scene ("missing field `nodes`").
        // Assert structurally via `serde_json::Value` instead — an absent
        // `nodes` key means zero root nodes.
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");
        let scenes = doc["scenes"].as_array().expect("scenes array");
        assert_eq!(scenes.len(), 1);
        let node_count = scenes[0]
            .get("nodes")
            .and_then(|n| n.as_array())
            .map_or(0, Vec::len);
        assert_eq!(node_count, 0);
    }

    #[test]
    fn registry_routes_cooked_static_mesh_to_glb() {
        let reg = crate::export::HandlerRegistry::all_default_handlers();
        let handler = reg
            .find_handler(&mesh_with(empty_render()))
            .expect("a handler");
        assert_eq!(handler.output_extension(), "glb");
    }

    /// Pin the `gltf` write API: an empty `json::Root` (asset only) serializes,
    /// wraps in a `binary::Glb`, and `to_vec` produces bytes starting with the
    /// `glTF` magic. Establishes the exact types the later tasks build on.
    #[test]
    fn gltf_write_api_round_trips_empty_doc() {
        let root = gltf::json::Root::default();
        let json = serde_json::to_vec(&root).expect("serialize root");
        let mut json = json;
        while !json.len().is_multiple_of(4) {
            json.push(b' ');
        }
        let glb = gltf::binary::Glb {
            header: gltf::binary::Header {
                magic: *b"glTF",
                version: 2,
                length: 0,
            },
            json: Cow::Owned(json),
            bin: None,
        };
        let bytes = glb.to_vec().expect("glb to_vec");
        assert_eq!(&bytes[0..4], b"glTF", "GLB magic");
        assert!(bytes.len() >= 12, "GLB has at least a 12-byte header");
    }

    /// `finish_glb` no longer pads the JSON/BIN buffers manually — it relies on
    /// `gltf::binary::Glb::to_vec` to 4-byte-align both chunks. Feed it a `Root`
    /// whose serialized JSON length is deliberately NOT a multiple of 4 and
    /// assert the produced GLB still parses, proving `to_vec`'s internal padding
    /// makes it valid without our removed manual loops.
    #[test]
    fn glb_with_unaligned_json_is_valid() {
        // Tune the generator string until the serialized Root is non-4-aligned.
        let mut root = gltf::json::Root::default();
        let mut generator = String::from("paksmith");
        loop {
            root.asset.generator = Some(generator.clone());
            let len = serde_json::to_vec(&root).expect("serialize root").len();
            if !len.is_multiple_of(4) {
                break;
            }
            generator.push('x');
        }
        // Precondition: the JSON length is genuinely unaligned, so this test is
        // not vacuous — without to_vec's internal padding the chunk would be
        // misaligned and rejected.
        let json_len = serde_json::to_vec(&root).expect("serialize root").len();
        assert_ne!(json_len % 4, 0, "test setup must produce unaligned JSON");

        // Non-4-aligned BIN too (3 bytes) to exercise BIN-chunk padding as well.
        let bytes = finish_glb(&root, vec![1u8, 2, 3]).expect("finish_glb");
        let glb = gltf::Glb::from_slice(&bytes).expect("unaligned GLB must parse");

        // glTF 2.0 requires JSON-chunk pad bytes be 0x20 (space). `to_vec` pads
        // with spaces; confirm the trailing pad byte is a space, not 0x00.
        assert!(glb.json.len().is_multiple_of(4), "JSON chunk is 4-aligned");
        assert_eq!(
            *glb.json.last().expect("non-empty json"),
            b' ',
            "JSON chunk padded with spaces per glTF 2.0"
        );
    }

    #[test]
    fn gltf_doc_push_accessor_aligns_and_indexes() {
        let mut doc = GltfDoc::new();
        // 3 f32 = 12 bytes, already 4-aligned.
        let a = doc.push_accessor(
            &[1.0f32, 2.0, 3.0]
                .iter()
                .flat_map(|f| f.to_le_bytes())
                .collect::<Vec<u8>>(),
            gltf::json::accessor::ComponentType::F32,
            gltf::json::accessor::Type::Scalar,
            3,
            None,
            None,
            None,
            false,
        );
        // 1 byte → padded to 4 before the next view starts.
        let b = doc.push_accessor(
            &[0xAAu8],
            gltf::json::accessor::ComponentType::U8,
            gltf::json::accessor::Type::Scalar,
            1,
            Some(gltf::json::buffer::Target::ElementArrayBuffer),
            None,
            None,
            false,
        );
        // Third push starts at bin len 13 (un-aligned) → push_accessor's own
        // alignment loop must pad 13 → 16 before this view. This is the
        // assertion that exercises the in-method loop; deleting it makes the
        // view start at 13 (a surviving mutant otherwise).
        let c = doc.push_accessor(
            &[0xBBu8, 0xCC],
            gltf::json::accessor::ComponentType::U8,
            gltf::json::accessor::Type::Scalar,
            2,
            Some(gltf::json::buffer::Target::ElementArrayBuffer),
            None,
            None,
            false,
        );
        assert_eq!(a.value(), 0);
        assert_eq!(b.value(), 1);
        assert_eq!(c.value(), 2);
        let (root, bin) = doc.into_parts();
        assert_eq!(root.accessors.len(), 3);
        assert_eq!(root.buffer_views.len(), 3);
        assert_eq!(root.buffers.len(), 1);
        // View 0 at offset 0 (len 12); view 1 starts at 12 (12 already aligned).
        // gltf-json 1.4.1 `USize64` is a `pub u64` tuple struct with no
        // `Into<u64>`; read the inner value via `.0`.
        assert_eq!(root.buffer_views[1].byte_offset.unwrap().0, 12);
        // View 2 starts at 16 — push_accessor padded 13 → 16 itself.
        assert_eq!(root.buffer_views[2].byte_offset.unwrap().0, 16);
        // BIN length is the final 4-aligned total (16 + 2 → padded to 20).
        assert_eq!(bin.len(), 20);
        assert_eq!(root.buffers[0].byte_length.0, 20);
    }

    // ---------- Coordinate-conversion tests (Task 4) ----------

    // Exact equality is correct here: the inputs and the ×0.01 products
    // (1.0/2.0/3.0/0.0/-1.0) are all exactly representable in f32, so there
    // is no rounding to tolerate.
    #[allow(clippy::float_cmp)]
    #[test]
    fn convert_position_swaps_y_z_and_scales_cm_to_m() {
        // UE (100, 200, 300) cm → glTF Y-up metres. Y/Z swap + ×0.01.
        let p = convert_position(&FVector {
            x: 100.0,
            y: 200.0,
            z: 300.0,
        });
        assert_eq!(p, [1.0f32, 3.0, 2.0]); // (x, z, y) * 0.01
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_dir_swaps_y_z_without_scale() {
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }); // UE +Z (up)
        assert_eq!(d, [0.0f32, 1.0, 0.0]); // glTF +Y (up), unit length preserved
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_tangent_swaps_xyz_and_negates_w_handedness() {
        // w = -1 → +1: the det−1 basis swap flips tangent-space handedness, so
        // glTF's `cross(N, T.xyz) * T.w` bitangent requires the stored w sign be
        // inverted (T_gltf.w = −T_ue.w).
        let t = convert_tangent(&FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: -1.0,
        });
        assert_eq!(t, [1.0f32, 0.0, 0.0, 1.0]); // xyz basis-mapped, w negated

        // The opposite sign also flips: w = +1 → -1.
        let t = convert_tangent(&FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        });
        assert_eq!(t, [1.0f32, 0.0, 0.0, -1.0]);
    }

    #[allow(clippy::float_cmp)] // exact representable values; see above
    #[test]
    fn convert_dir_normalizes_non_unit_input() {
        // Non-unit axis vector: (0,0,2) → swap (0,2,0) → normalize → (0,1,0).
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 2.0,
        });
        assert!((d[0] - 0.0).abs() < 1e-6);
        assert!((d[1] - 1.0).abs() < 1e-6);
        assert!((d[2] - 0.0).abs() < 1e-6);

        // Diagonal 3-4-5 triple: (3,0,4) → swap (3,4,0) → normalize (0.6,0.8,0).
        let d = convert_dir(&FVector {
            x: 3.0,
            y: 0.0,
            z: 4.0,
        });
        assert!((d[0] - 0.6).abs() < 1e-6);
        assert!((d[1] - 0.8).abs() < 1e-6);
        assert!((d[2] - 0.0).abs() < 1e-6);
    }

    /// Normalize an input whose three post-swap components are all distinct and
    /// nonzero so the magnitude `x*x + y*y + z*z` constrains every term.
    ///
    /// `(x=2, y=6, z=3)` → swap `(x, z, y)` = `(2, 3, 6)` → magnitude
    /// `sqrt(4 + 9 + 36) = 7` → `(2/7, 3/7, 6/7)`. With all three components
    /// distinct + nonzero, a `+`→`-`, `*`→`+`, or `/`→`%` mutant inside
    /// `normalize_xyz` changes the result and fails this assert (the existing
    /// axis-aligned tests all have a zero post-swap component, which leaves those
    /// arithmetic mutants unconstrained).
    #[test]
    fn convert_dir_normalizes_all_nonzero_components() {
        let d = convert_dir(&FVector {
            x: 2.0,
            y: 6.0,
            z: 3.0,
        });
        assert!((d[0] - 2.0 / 7.0).abs() < 1e-6);
        assert!((d[1] - 3.0 / 7.0).abs() < 1e-6);
        assert!((d[2] - 6.0 / 7.0).abs() < 1e-6);
    }

    #[allow(clippy::float_cmp)] // w is an exact representable value
    #[test]
    fn convert_tangent_normalizes_xyz_negates_w() {
        // Non-unit xyz (0,0,2) → swap (0,2,0) → normalize (0,1,0); w negated.
        let t = convert_tangent(&FVector4 {
            x: 0.0,
            y: 0.0,
            z: 2.0,
            w: -1.0,
        });
        assert!((t[0] - 0.0).abs() < 1e-6);
        assert!((t[1] - 1.0).abs() < 1e-6);
        assert!((t[2] - 0.0).abs() < 1e-6);
        assert_eq!(t[3], 1.0f32); // handedness flipped (det−1 basis): -1 → +1
    }

    /// `encode_f32_le` emits each tuple's components in order, little-endian,
    /// with no padding. Pins the byte output against `vec![]` / `vec![0]` /
    /// `vec![1]` body-replacement mutants (all wrong length/content).
    #[test]
    fn encode_f32_le_emits_exact_little_endian_bytes() {
        let bytes = encode_f32_le([[1.0f32, 2.0], [3.0, 4.0]].into_iter());
        let expected: Vec<u8> = [1.0f32, 2.0, 3.0, 4.0]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn reverse_winding_swaps_second_and_third_of_each_triangle() {
        let src = [0u32, 1, 2, 3, 4, 5];
        assert_eq!(reverse_winding(&src), vec![0u32, 2, 1, 3, 5, 4]);
    }

    /// Feed a zero vector to `convert_dir` and assert the result is exactly
    /// `[0.0, 0.0, 0.0]` with every component finite.
    ///
    /// Without the `len > 0.0` guard in `normalize_xyz`, dividing by `len=0`
    /// yields NaN; `is_finite()` and the exact-equality assert both catch the
    /// mutant.
    #[allow(clippy::float_cmp)] // zero is exactly representable; guard returns input unchanged
    #[test]
    fn convert_dir_zero_vector_does_not_nan() {
        let d = convert_dir(&FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        assert_eq!(d, [0.0f32, 0.0, 0.0]);
        assert!(d[0].is_finite());
        assert!(d[1].is_finite());
        assert!(d[2].is_finite());
    }

    /// Feed a 7-element slice (two full triangles + one trailing index) to
    /// `reverse_winding` and assert the two triangles are reversed and the
    /// trailing index is copied verbatim.
    ///
    /// Exercises the `chunks_exact(3).remainder()` path; a mutant that drops
    /// `out.extend_from_slice(tri.remainder())` would produce a 6-element
    /// result missing the trailing `9`.
    #[test]
    fn reverse_winding_copies_trailing_partial_triangle() {
        let src = [0u32, 1, 2, 3, 4, 5, 9];
        assert_eq!(reverse_winding(&src), vec![0u32, 2, 1, 3, 5, 4, 9]);
    }

    // ---------- Vertex-attribute accessor tests (Tasks 5-8) ----------

    use crate::asset::structs::color::FColor;
    use crate::asset::structs::vector::FVector2D;

    fn lod_one_triangle() -> StaticMeshLod {
        StaticMeshLod {
            sections: Vec::new(),
            positions: vec![
                FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 0.0,
                },
                FVector {
                    x: 100.0,
                    y: 0.0,
                    z: 0.0,
                },
                FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 100.0,
                },
            ],
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: vec![0, 1, 2],
        }
    }

    #[test]
    fn position_accessor_has_vec3_f32_and_minmax() {
        let mut doc = GltfDoc::new();
        let acc = push_positions(&mut doc, &lod_one_triangle());
        let (root, _bin) = doc.into_parts();
        let a = &root.accessors[acc.value()];
        assert!(matches!(a.type_, Valid(Type::Vec3)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(a.count.0, 3);
        // convert_position maps UE (x,y,z) cm → glTF (x, z, y) m. Vertices:
        //   v0 (0,0,0)     → (0,0,0)
        //   v1 (100,0,0)   → (1.0, 0.0, 0.0)
        //   v2 (0,0,100)   → (0.0, 1.0, 0.0)  [UE-Z → glTF-Y]
        // so min = (0,0,0), max = (1.0, 1.0, 0.0). max-Y = 1.0 (from v2's UE-Z),
        // max-Z = 0.0 — pins the Y/Z basis swap AND that min != max.
        assert_eq!(a.min.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
        assert_eq!(a.max.as_ref().unwrap(), &serde_json::json!([1.0, 1.0, 0.0]));
        // POSITION is plain f32, never normalized — pins normalized=false against
        // a false→true mutant.
        assert!(!a.normalized);
    }

    #[test]
    fn position_accessor_empty_emits_zero_minmax() {
        let mut lod = lod_one_triangle();
        lod.positions = Vec::new();
        let mut doc = GltfDoc::new();
        let acc = push_positions(&mut doc, &lod);
        let (root, _bin) = doc.into_parts();
        let a = &root.accessors[acc.value()];
        assert_eq!(a.count.0, 0);
        // Empty list → the INFINITY/NEG_INFINITY seeds must be replaced with
        // zeros (deleting that guard leaves non-finite ±inf in min/max).
        assert_eq!(a.min.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
        assert_eq!(a.max.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
    }

    #[test]
    fn normal_and_tangent_accessors_have_right_shapes() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0
            };
            3
        ];
        lod.tangents = vec![
            FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0
            };
            3
        ];
        let mut doc = GltfDoc::new();
        let n = push_normals(&mut doc, &lod).expect("normals present");
        let t = push_tangents(&mut doc, &lod).expect("tangents present");
        let (root, _bin) = doc.into_parts();
        let na = &root.accessors[n.value()];
        let ta = &root.accessors[t.value()];
        assert!(matches!(na.type_, Valid(Type::Vec3)));
        assert!(matches!(
            na.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(na.count.0, 3);
        assert!(matches!(ta.type_, Valid(Type::Vec4)));
        assert!(matches!(
            ta.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert_eq!(ta.count.0, 3);
        // f32 attributes are never normalized — pins normalized=false.
        assert!(!na.normalized);
        assert!(!ta.normalized);
    }

    #[test]
    fn normals_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_normals(&mut doc, &lod_one_triangle()).is_none());
    }

    #[test]
    fn tangents_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_tangents(&mut doc, &lod_one_triangle()).is_none());
    }

    #[test]
    fn uv_accessors_one_per_present_channel() {
        let mut lod = lod_one_triangle();
        lod.num_tex_coords = 2;
        lod.uvs[0] = Some(vec![FVector2D { x: 0.0, y: 0.0 }; 3]);
        lod.uvs[1] = Some(vec![FVector2D { x: 0.5, y: 0.5 }; 3]);
        let mut doc = GltfDoc::new();
        let accs = push_uvs(&mut doc, &lod);
        assert_eq!(accs.len(), 2);
        let (root, _bin) = doc.into_parts();
        for a in &accs {
            let acc = &root.accessors[a.value()];
            assert!(matches!(acc.type_, Valid(Type::Vec2)));
            assert!(matches!(
                acc.component_type,
                Valid(GenericComponentType(ComponentType::F32))
            ));
            assert_eq!(acc.count.0, 3);
            // UV f32 attributes are never normalized — pins normalized=false.
            assert!(!acc.normalized);
        }
    }

    #[test]
    fn uv_accessors_empty_when_no_channels() {
        let mut doc = GltfDoc::new();
        let accs = push_uvs(&mut doc, &lod_one_triangle());
        assert!(accs.is_empty());
    }

    #[test]
    fn color_accessor_is_u8_vec4_normalized() {
        let mut lod = lod_one_triangle();
        lod.colors = Some(vec![
            FColor {
                r: 255,
                g: 128,
                b: 0,
                a: 255
            };
            3
        ]);
        let mut doc = GltfDoc::new();
        let c = push_colors(&mut doc, &lod).expect("colors present");
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[c.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U8))
        ));
        assert!(a.normalized);
        assert_eq!(a.count.0, 3);
        // First vertex bytes are RGBA = 255,128,0,255 at the view's offset.
        // Asymmetric (r != g != b) pins RGBA order vs a BGRA/ARGB mutant.
        let off = usize::try_from(
            root.buffer_views[a.buffer_view.unwrap().value()]
                .byte_offset
                .unwrap()
                .0,
        )
        .expect("byte offset fits usize");
        assert_eq!(&bin[off..off + 4], &[255u8, 128, 0, 255]);
    }

    #[test]
    fn colors_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_colors(&mut doc, &lod_one_triangle()).is_none());
    }

    // ---------- Per-section primitive + index accessor tests (Task 9) ----------

    use crate::asset::exports::mesh::section::MeshSection;

    fn section(material_index: i32, first_index: i32, num_triangles: i32) -> MeshSection {
        MeshSection {
            material_index,
            first_index,
            num_triangles,
            min_vertex_index: 0,
            max_vertex_index: 0,
            enable_collision: false,
            cast_shadow: false,
            force_opaque: false,
            visible_in_ray_tracing: false,
            affect_distance_field_lighting: false,
        }
    }

    #[test]
    fn index_width_u16_for_small_meshes() {
        // Max index value ≤ 65535 → UNSIGNED_SHORT.
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 2]);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
    }

    #[test]
    fn index_width_u32_above_u16_range() {
        // Max index value 70_000 > 65535 → UNSIGNED_INT.
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 70_000]);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U32))
        ));
    }

    /// Pin the exact `<= u16::MAX` boundary on the index VALUE: a max index of
    /// 65 535 is still U16. A `<=`→`<` mutant would flip this case to U32.
    #[test]
    fn index_width_u16_at_exact_boundary() {
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, u32::from(u16::MAX)]); // max 65 535
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
    }

    /// Pin the first over-boundary VALUE: a max index of 65 536 → U32. Together
    /// with the 65 535 case this brackets the threshold from both sides, and a
    /// width-by-count mutant (3 indices → U16) would truncate 65 536 silently.
    #[test]
    fn index_width_u32_just_above_boundary() {
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, u32::from(u16::MAX) + 1]); // max 65 536
        let (root, bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U32))
        ));
        // And the value is NOT truncated: the third index reads back as 65 536.
        let view = root.accessors[acc.value()].buffer_view.unwrap();
        let off = usize::try_from(root.buffer_views[view.value()].byte_offset.unwrap().0)
            .expect("offset fits usize");
        let third = u32::from_le_bytes([bin[off + 8], bin[off + 9], bin[off + 10], bin[off + 11]]);
        assert_eq!(third, u32::from(u16::MAX) + 1);
    }

    #[test]
    fn primitive_per_section_reverses_winding_and_refs_material() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0
            };
            3
        ];
        lod.sections = vec![section(2, 0, 1)]; // material 2, 1 triangle from index 0
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        assert_eq!(prims[0].material.map(|m| m.value()), Some(2));
        // The shared NORMAL accessor is referenced by the primitive's attributes.
        assert!(prims[0].attributes.contains_key(&Valid(Semantic::Normals)));
        assert!(
            prims[0]
                .attributes
                .contains_key(&Valid(Semantic::Positions))
        );
        // The index accessor holds the winding-reversed triple [0,2,1].
        let idx_acc = prims[0].indices.unwrap();
        let (root, bin) = doc.into_parts();
        let view = root.accessors[idx_acc.value()].buffer_view.unwrap();
        // gltf-json 1.4.1 `USize64` exposes its inner value only via `.0`
        // (no `From<USize64> for u64`); the plan's `u64::from(..)` won't compile.
        let off = usize::try_from(root.buffer_views[view.value()].byte_offset.unwrap().0)
            .expect("offset fits usize");
        let got: Vec<u16> = bin[off..off + 6]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        assert_eq!(got, vec![0u16, 2, 1]);
    }

    /// A section whose triangle count overruns the index buffer (corrupt cook)
    /// is clamped to the available indices, not a panic.
    #[test]
    fn primitive_overrunning_section_is_clamped() {
        let mut lod = lod_one_triangle(); // 3 indices
        lod.sections = vec![section(0, 0, 100)]; // claims 300 indices
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        let idx_acc = prims[0].indices.unwrap();
        let (root, _bin) = doc.into_parts();
        // Clamped to the 3 available indices → exactly one reversed triangle.
        assert_eq!(root.accessors[idx_acc.value()].count.0, 3);
    }

    /// A section whose `first_index` lies past the end of the index buffer
    /// (corrupt cook) has an empty resolved range and is SKIPPED — emitting a
    /// `count = 0` index accessor is invalid glTF. No primitive is produced.
    #[test]
    fn primitive_first_index_past_end_is_skipped() {
        let mut lod = lod_one_triangle(); // 3 indices
        lod.sections = vec![section(0, 1000, 1)]; // first_index well past the buffer
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert!(prims.is_empty());
        // Every section is skipped, so NO accessors are emitted (not even the
        // shared POSITION accessor — vertex accessors are built only when a
        // primitive will reference them).
        let (root, _bin) = doc.into_parts();
        assert!(
            root.accessors.is_empty(),
            "no accessors when every section is skipped"
        );
    }

    /// A zero-triangle section (empty resolved range) is SKIPPED, producing no
    /// primitive and no `count = 0` index accessor.
    #[test]
    fn zero_triangle_section_is_skipped() {
        let mut lod = lod_one_triangle(); // 3 indices, one real triangle
        lod.sections = vec![section(0, 0, 1), section(0, 0, 0)]; // real + 0-tri
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1, "the 0-triangle section is dropped");
        let (root, _bin) = doc.into_parts();
        assert!(
            root.accessors.iter().all(|a| a.count.0 >= 1),
            "no zero-count accessor was emitted"
        );
    }

    /// A section index span that is not a whole number of triangles is floored
    /// to the largest triangle multiple before winding-reversal. With a 5-index
    /// buffer and a section claiming 10 triangles, the resolved span clamps to 5
    /// then floors to 3 (one triangle), so the emitted index accessor `count`
    /// is 3, not 5. A glTF TRIANGLES primitive requires `count % 3 == 0`.
    #[test]
    fn section_index_span_floored_to_triangle_multiple() {
        let mut lod = lod_one_triangle();
        // 5 indices — NOT a multiple of 3 (the parser only checks % index_size).
        lod.positions.push(FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        lod.positions.push(FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        });
        lod.indices = vec![0, 1, 2, 3, 4];
        lod.sections = vec![section(0, 0, 10)]; // claims 30 indices
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        let idx_acc = prims[0].indices.unwrap();
        let (root, _bin) = doc.into_parts();
        // Clamped to 5, then floored to a whole triangle → count 3, not 5.
        assert_eq!(root.accessors[idx_acc.value()].count.0, 3);
    }

    /// Every section's resolved span is sub-triangle (here a single 0-triangle
    /// section over a non-empty-position LOD) → the LOD emits NO node/mesh AND
    /// NO accessors at all (no orphaned POSITION accessor for gltf-validator to
    /// flag as UNUSED_OBJECT).
    #[test]
    fn all_sections_subtriangle_emits_no_node() {
        let mut lod = lod_one_triangle(); // non-empty positions
        lod.sections = vec![section(0, 0, 0)]; // single 0-triangle section
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        // The scene has zero nodes, so strict `gltf::json::Root` re-deserialize
        // fails on the absent `nodes` field (see `exports_minimal_valid_glb`).
        // Assert structurally via `serde_json::Value`: absent keys mean empty.
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let len = |k: &str| doc.get(k).and_then(|v| v.as_array()).map_or(0, Vec::len);
        assert_eq!(len("meshes"), 0, "no mesh for an all-empty LOD");
        assert_eq!(len("nodes"), 0, "no node for an all-empty LOD");
        // No vertex accessors were pushed — the shared POSITION/NORMAL/etc. are
        // built only when at least one section will emit a primitive.
        assert_eq!(
            len("accessors"),
            0,
            "no orphaned vertex accessor when every section is skipped"
        );
    }

    /// A LOD with no positions emits NO accessors at all (not even a
    /// `count = 0` POSITION accessor, which is invalid glTF).
    #[test]
    fn empty_lod_emits_no_accessors() {
        let lod = StaticMeshLod {
            sections: Vec::new(),
            positions: Vec::new(),
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: Vec::new(),
        };
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert!(prims.is_empty());
        let (root, _bin) = doc.into_parts();
        assert!(root.accessors.is_empty());
    }

    /// End-to-end: a render with one empty LOD (no geometry) followed by one
    /// real LOD emits exactly ONE node/mesh, named for the SOURCE LOD ordinal
    /// (`LOD1`), not renumbered — and no zero-count accessor survives.
    #[test]
    fn empty_lod_emits_no_node() {
        let empty = StaticMeshLod {
            sections: Vec::new(),
            positions: Vec::new(),
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: Vec::new(),
        };
        let mut real = lod_one_triangle();
        real.sections = vec![section(0, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![empty, real],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 1);
        assert_eq!(root.nodes.len(), 1);
        // Name reflects the SOURCE index (LOD1), not the emitted ordinal.
        assert_eq!(root.nodes[0].name.as_deref(), Some("LOD1"));
        // No accessor may have count 0 (gltf-validator requires count ≥ 1).
        assert!(root.accessors.iter().all(|a| a.count.0 >= 1));
    }

    /// A corrupt negative `material_index` maps to slot 0 (never panics).
    #[test]
    fn primitive_negative_material_index_maps_to_zero() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(-5, 0, 1)];
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims[0].material.map(|m| m.value()), Some(0));
    }

    // ---------- Scene wiring + materials tests (Tasks 10-11) ----------

    #[test]
    fn each_lod_becomes_a_named_node_and_mesh() {
        let mut lod0 = lod_one_triangle();
        lod0.sections = vec![section(0, 0, 1)];
        let mut lod1 = lod_one_triangle();
        lod1.sections = vec![section(0, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod0, lod1],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 2);
        assert_eq!(root.nodes.len(), 2);
        assert_eq!(root.scenes[0].nodes.len(), 2);
        assert_eq!(root.nodes[0].name.as_deref(), Some("LOD0"));
        assert_eq!(root.nodes[1].name.as_deref(), Some("LOD1"));
        // Each node must reference its own mesh, in order — pins the `mesh`
        // field against a delete-field mutant (a node without a mesh draws
        // nothing).
        assert_eq!(root.nodes[0].mesh.map(|m| m.value()), Some(0));
        assert_eq!(root.nodes[1].mesh.map(|m| m.value()), Some(1));
    }

    #[test]
    fn materials_cover_all_referenced_slots_named() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(0, 0, 1), section(3, 0, 1)]; // references slot 3
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        // max referenced index is 3 → at least 4 materials.
        assert_eq!(root.materials.len(), 4);
        assert_eq!(root.materials[0].name.as_deref(), Some("Material_0"));
        assert_eq!(root.materials[3].name.as_deref(), Some("Material_3"));
    }

    /// No sections anywhere → zero materials. Pins the empty-fold
    /// `else { return Ok(()) }` branch: emitting any material here is wrong.
    /// `build_materials` is tested directly because a section-free LOD produces
    /// no primitives (FIX 4) → an empty scene that the strict re-deserializer
    /// rejects on a missing `nodes` field.
    #[test]
    fn materials_empty_when_no_sections() {
        let render = StaticMeshRenderData {
            lods: vec![lod_one_triangle()], // a LOD with zero sections
            ..empty_render()
        };
        let mut doc = GltfDoc::new();
        build_materials(&mut doc, &render).expect("no-section mesh builds no materials");
        assert_eq!(doc.root.materials.len(), 0);
    }

    /// Every section references a negative (corrupt) slot → the table still
    /// covers slot 0 (one material). Pins the `.max(0)` clamp: dropping it makes
    /// `max_ref = -5`, `count = 0`, leaving the primitive's `Index::new(0)`
    /// material reference dangling.
    #[test]
    fn materials_all_negative_sections_cover_slot_zero() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(-5, 0, 1), section(-2, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.materials.len(), 1);
        assert_eq!(root.materials[0].name.as_deref(), Some("Material_0"));
    }

    /// A section referencing slot `MAX_MESH_MATERIALS` (one past the last
    /// allowed slot, since slots are 0-based) exceeds the export cap and is
    /// rejected with `UnsupportedFeature` — no panic, no ~256-material+ alloc.
    #[test]
    fn materials_over_cap_is_rejected() {
        let over_cap = i32::try_from(MAX_MESH_MATERIALS).expect("cap fits i32");
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(over_cap, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("over-cap mesh must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// The last in-cap slot (`MAX_MESH_MATERIALS - 1`) is still accepted — pins
    /// the `>=` boundary so a `>=`→`>` mutant (which would accept the over-cap
    /// slot) is caught alongside `materials_over_cap_is_rejected`.
    #[test]
    fn materials_at_cap_boundary_is_accepted() {
        let last_in_cap = i32::try_from(MAX_MESH_MATERIALS - 1).expect("cap fits i32");
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(last_in_cap, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("last in-cap slot must export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.materials.len(), MAX_MESH_MATERIALS as usize);
    }

    /// A material index well over the cap (but not astronomically large) must be
    /// rejected fast. `i32::MAX` caused a cargo-mutants timeout: a `>=`→`<` mutant
    /// bypasses the guard and tries to allocate ~2 billion `Material` structs,
    /// hanging the mutation runner. Using `1000` instead allocates at most ~1001
    /// materials under the mutant — still instant — so the mutant is CAUGHT without
    /// a timeout. The boundary tests (`materials_over_cap_is_rejected` at slot 256
    /// and `materials_at_cap_boundary_is_accepted` at slot 255) already pin the
    /// exact cap value; this test pins the rejection for a far-over-cap input.
    #[test]
    fn materials_far_over_cap_is_rejected() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(1000, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        let err = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect_err("far-over-cap slot must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// Winding-orientation pin: after the det−1 basis swap, `reverse_winding`
    /// must restore CCW (outward) front faces. Build a single UE triangle with a
    /// known outward normal, lower it (convert + reverse), then recompute the
    /// geometric face normal `cross(p1-p0, p2-p0)` over the CONVERTED positions
    /// in the REVERSED (glTF) order and assert it agrees with the converted
    /// vertex normal (positive dot ⇒ outward / CCW). Without the reversal the
    /// dot flips negative, so this fails for a no-reverse mutant.
    #[allow(clippy::float_cmp)]
    #[test]
    fn winding_reversal_yields_outward_ccw_faces() {
        // UE triangle in the Z=0 plane with outward normal +Z (UE up).
        let ue_positions = [
            FVector {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            FVector {
                x: 100.0,
                y: 0.0,
                z: 0.0,
            },
            FVector {
                x: 0.0,
                y: 100.0,
                z: 0.0,
            },
        ];
        let ue_normal = FVector {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        };

        // Lower exactly as the exporter does.
        let converted: Vec<[f32; 3]> = ue_positions.iter().map(convert_position).collect();
        let n = convert_dir(&ue_normal); // glTF vertex normal
        let order = reverse_winding(&[0u32, 1, 2]); // glTF index order

        let p0 = converted[order[0] as usize];
        let p1 = converted[order[1] as usize];
        let p2 = converted[order[2] as usize];

        // Geometric face normal = cross(p1 - p0, p2 - p0).
        let e1 = [p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]];
        let e2 = [p2[0] - p0[0], p2[1] - p0[1], p2[2] - p0[2]];
        let face = [
            e1[1] * e2[2] - e1[2] * e2[1],
            e1[2] * e2[0] - e1[0] * e2[2],
            e1[0] * e2[1] - e1[1] * e2[0],
        ];
        let dot = face[0] * n[0] + face[1] * n[1] + face[2] * n[2];
        // Reversed (CCW) order ⇒ geometric normal points the same way as the
        // declared vertex normal (outward). A no-reverse mutant flips this sign.
        assert!(
            dot > 0.0,
            "reversed winding must keep faces front-facing (dot = {dot})"
        );
    }

    // ---------- End-to-end cube fixture (Task 12) ----------

    /// A unit cube (8 vertices, 12 triangles, 1 section, normals + UV0).
    fn cube_lod() -> StaticMeshLod {
        // 8 corners at ±50 cm (→ ±0.5 m).
        let p = |x: f64, y: f64, z: f64| FVector { x, y, z };
        let positions = vec![
            p(-50.0, -50.0, -50.0),
            p(50.0, -50.0, -50.0),
            p(50.0, 50.0, -50.0),
            p(-50.0, 50.0, -50.0),
            p(-50.0, -50.0, 50.0),
            p(50.0, -50.0, 50.0),
            p(50.0, 50.0, 50.0),
            p(-50.0, 50.0, 50.0),
        ];
        // 12 triangles (two per face).
        let indices: Vec<u32> = vec![
            0, 1, 2, 0, 2, 3, 4, 6, 5, 4, 7, 6, 0, 4, 5, 0, 5, 1, 1, 5, 6, 1, 6, 2, 2, 6, 7, 2, 7,
            3, 3, 7, 4, 3, 4, 0,
        ];
        StaticMeshLod {
            sections: vec![section(0, 0, 12)],
            normals: positions
                .iter()
                .map(|_| FVector {
                    x: 0.0,
                    y: 0.0,
                    z: 1.0,
                })
                .collect(),
            tangents: Vec::new(),
            uvs: {
                let mut u: [Option<Vec<FVector2D>>; 4] = [None, None, None, None];
                u[0] = Some(
                    positions
                        .iter()
                        .map(|_| FVector2D { x: 0.0, y: 0.0 })
                        .collect(),
                );
                u
            },
            num_tex_coords: 1,
            colors: None,
            indices,
            positions,
        }
    }

    #[test]
    fn cube_exports_parseable_glb_with_expected_counts() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 1);
        assert_eq!(root.meshes[0].primitives.len(), 1);
        let prim = &root.meshes[0].primitives[0];
        // POSITION + NORMAL present (mode serializes ABSENT for Triangles, so we
        // do not assert `prim.mode`).
        assert!(
            prim.attributes
                .keys()
                .any(|k| matches!(k, Valid(Semantic::Positions)))
        );
        assert!(
            prim.attributes
                .keys()
                .any(|k| matches!(k, Valid(Semantic::Normals)))
        );
        // 36 indices (12 triangles), UNSIGNED_SHORT (8 verts ≤ 65535).
        // `USize64` exposes its inner value via `.0` (no `From<USize64> for u64`).
        let idx = &root.accessors[prim.indices.unwrap().value()];
        assert_eq!(idx.count.0, 36);
        assert!(matches!(
            idx.component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
        // Positions are metre-scaled: max corner is +0.5, not +50.
        let pos = &root.accessors[prim.attributes[&Valid(Semantic::Positions)].value()];
        assert_eq!(
            pos.max.as_ref().unwrap(),
            &serde_json::json!([0.5, 0.5, 0.5])
        );
    }

    // ---------- Projected-buffer-size cap tests (FIX 1) ----------

    /// `projected_bin_bytes` sums the EXACT byte strides the lowering would
    /// allocate. Pins every multiplier (positions ×12, normals ×12, tangents
    /// ×16, uv channel ×8, colors ×4, index ×4) and the triangle-span floor.
    /// A mutant changing any stride/multiplier fails this exact equality.
    #[test]
    fn projected_bin_bytes_sums_vertex_and_index_strides() {
        // 3 positions, 3 normals, 3 tangents, one 3-element uv0 channel, 3
        // colors, and one section of 1 triangle over a 3-index buffer.
        let mut lod = lod_one_triangle(); // 3 positions, indices [0,1,2]
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            };
            3
        ];
        lod.tangents = vec![
            FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            };
            3
        ];
        lod.num_tex_coords = 1;
        lod.uvs[0] = Some(vec![FVector2D { x: 0.0, y: 0.0 }; 3]);
        lod.colors = Some(vec![
            FColor {
                r: 0,
                g: 0,
                b: 0,
                a: 0,
            };
            3
        ]);
        lod.sections = vec![section(0, 0, 1)]; // 1 triangle = 3 indices
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        // positions 3*12 = 36, normals 3*12 = 36, tangents 3*16 = 48,
        // uv0 3*8 = 24, colors 3*4 = 12 → verts 156.
        // section span floored to 3 indices * 4 = 12. Total = 168.
        assert_eq!(projected_bin_bytes(&render), 168);
    }

    /// `projected_bin_bytes` floors the per-section span to a whole number of
    /// triangles (`avail - avail % 3`), mirroring `resolve_section_indices`.
    /// With a 5-index buffer and an over-claiming section, `avail = 5` floors to
    /// 3 → index bytes 3*4 = 12 (NOT 5*4 = 20, and NOT the `+`-mutant's
    /// 7*4 = 28). Positions 3*12 = 36 → total 48.
    #[test]
    fn projected_bin_bytes_floors_section_span_to_triangle_multiple() {
        let mut lod = lod_one_triangle(); // 3 positions
        lod.indices = vec![0, 1, 2, 0, 1]; // 5 indices (avail % 3 != 0)
        lod.sections = vec![section(0, 0, 10)]; // claims 30, clamps to 5, floors to 3
        let render = StaticMeshRenderData {
            lods: vec![lod],
            ..empty_render()
        };
        // verts 3*12 = 36 + floored span 3*4 = 12 → 48.
        assert_eq!(projected_bin_bytes(&render), 48);
    }

    /// `exceeds_export_cap` is `true` strictly ABOVE the cap: exactly-cap is
    /// accepted, one byte over is rejected. Pins the `> cap` boundary (a `>`→`>=`
    /// mutant would reject the exactly-cap case) without a cap-sized allocation.
    #[test]
    fn exceeds_export_cap_is_strict_above_cap() {
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES - 1));
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES));
        assert!(exceeds_export_cap(MAX_GLB_BIN_BYTES + 1));
    }

    /// A mesh that duplicates a small index buffer across MANY sections and LODs
    /// projects to >1 GiB while allocating only a few hundred KB of INPUT. The
    /// rejection is asserted at the PURE [`enforce_export_cap`] level (NOT via
    /// `export`) so the over-cap path never builds a multi-GiB GLB — a heavy
    /// `export` call here would time out the mutation runner when the guard is
    /// mutated off (it would then perform the exact lowering the guard prevents).
    #[test]
    fn oversized_mesh_via_section_duplication_is_rejected() {
        // 30_000 indices per LOD (120 KB) duplicated by 8_960 sections across
        // 5 LODs → projected 5 * 8_960 * 30_000 * 4 ≈ 50 GiB, far over the 1 GiB
        // cap, while only a few MB of INPUT (indices + section structs) is built.
        let make_lod = || {
            let mut lod = lod_one_triangle();
            lod.indices = vec![0u32; 30_000];
            lod.sections = (0..8_960).map(|_| section(0, 0, 10_000)).collect();
            lod
        };
        let render = StaticMeshRenderData {
            lods: (0..5).map(|_| make_lod()).collect(),
            ..empty_render()
        };
        assert!(
            projected_bin_bytes(&render) > MAX_GLB_BIN_BYTES,
            "test setup must project over the cap"
        );
        let err = enforce_export_cap(&render).expect_err("oversized projection must be rejected");
        assert!(matches!(
            err,
            crate::PaksmithError::UnsupportedFeature { .. }
        ));
    }

    /// `export` WIRES the cap guard in: an under-cap mesh exports successfully,
    /// confirming `enforce_export_cap(render)?` returns `Ok` on the happy path
    /// (the over-cap rejection is pinned purely by
    /// `oversized_mesh_via_section_duplication_is_rejected`; an over-cap mesh fed
    /// through the full `export` lowering would perform the multi-GiB allocation
    /// the guard exists to prevent, timing out the mutation runner).
    #[test]
    fn export_under_cap_mesh_succeeds() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        assert!(!exceeds_export_cap(projected_bin_bytes(&render)));
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("under-cap mesh must export");
        assert_eq!(&bytes[0..4], b"glTF");
    }

    /// `projected_bin_bytes` is a safe UPPER BOUND of the actual emitted BIN.
    /// The cube uses u16 indices (8 verts), so projected's ×4 index width
    /// over-estimates — confirms a drift where projected under-counts is caught.
    #[test]
    fn projected_is_upper_bound_of_actual_bin() {
        let render = StaticMeshRenderData {
            lods: vec![cube_lod()],
            ..empty_render()
        };
        let projected = projected_bin_bytes(&render);
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(render), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let actual_bin_len = glb.bin.expect("cube has a BIN buffer").len() as u64;
        assert!(
            projected >= actual_bin_len,
            "projected ({projected}) must be an upper bound of actual bin ({actual_bin_len})"
        );
    }

    /// A just-under-cap projection is ACCEPTED — brackets the `> cap` boundary
    /// from below so a `>`→`>=` mutant (which would reject the at-cap case) and a
    /// `>`→`<` mutant are caught alongside `oversized_mesh_via_section_duplication`.
    #[test]
    fn projected_at_cap_constant_is_one_gib() {
        assert_eq!(MAX_GLB_BIN_BYTES, 1_073_741_824);
    }
}
