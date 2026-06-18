//! Format-agnostic glTF 2.0 (`.glb`) building primitives shared across the
//! mesh exporters (static + skeletal).
//!
//! These helpers are independent of any specific mesh shape: the
//! [`GltfDoc`] BIN/`Root` accumulator, the coordinate-basis converters
//! ([`convert_position`]/[`convert_dir`]/[`convert_tangent`]/[`normalize_xyz`]),
//! [`reverse_winding`], [`encode_f32_le`], [`finish_glb`], and the
//! [`MAX_GLB_BIN_BYTES`] aggregate-output cap. Mesh-shape-bound lowering
//! (attribute/primitive builders, material tables, per-mesh caps) lives in the
//! per-format handler modules (`static_mesh`, `skeletal_mesh`).

use std::borrow::Cow;
use std::collections::BTreeMap;

use gltf::json::Index;
use gltf::json::accessor::{ComponentType, GenericComponentType, Type};
use gltf::json::buffer::Target;
use gltf::json::mesh::Semantic;
use gltf::json::validation::Checked;
use gltf::json::validation::Checked::Valid;
use gltf::json::validation::USize64;

use crate::asset::structs::color::FColor;
use crate::asset::structs::vector::{FVector, FVector2D, FVector4};

/// Upper bound on the aggregate glTF BIN buffer a single mesh may produce
/// (aggregate-output decompression-bomb guard). A corrupt `num_triangles` makes
/// a section's index span clamp to the FULL index buffer; with up to
/// `MAX_SECTIONS_PER_LOD` sections each duplicating that buffer across
/// `MAX_LODS_PER_MESH` LODs the accumulated `bin` could reach tens of GiB (OOM),
/// and past 4.29 GiB the GLB `u32` length field silently truncates. A real mesh
/// is far under 1 GiB, so this is generous headroom while bounding a crafted
/// mesh. Checked **pre-flight** via the per-handler projection BEFORE allocating
/// — follows the `pcm.rs` `MAX_AUDIO_DECODED_BYTES` convention. No
/// `#[cfg(feature = "__test_utils")]` accessor (per the sibling mesh-cap
/// pattern); the over-cap test pins it via the `UnsupportedFeature` path.
pub(crate) const MAX_GLB_BIN_BYTES: u64 = 1 << 30; // 1 GiB

/// Accumulates the single glTF BIN buffer + the `json::Root` under construction.
/// Each `push_accessor` 4-byte-aligns the buffer, emits a `buffer::View` and an
/// `accessor::Accessor`, and returns the accessor index for primitive wiring.
pub(crate) struct GltfDoc {
    pub(crate) root: gltf::json::Root,
    pub(crate) bin: Vec<u8>,
}

impl GltfDoc {
    pub(crate) fn new() -> Self {
        Self {
            root: gltf::json::Root::default(),
            bin: Vec::new(),
        }
    }

    /// Zero-pad the BIN buffer up to the next 4-byte boundary. glTF bufferViews
    /// must start 4-aligned and the final buffer length must be 4-aligned.
    pub(crate) fn align_to_4(&mut self) {
        while !self.bin.len().is_multiple_of(4) {
            self.bin.push(0);
        }
    }

    /// Append `data` as a new bufferView + accessor. `min`/`max` are the
    /// glTF-required position bounds (or `None`); `target` distinguishes vertex
    /// (`ArrayBuffer`) from index (`ElementArrayBuffer`) views.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push_accessor(
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
    pub(crate) fn into_parts(mut self) -> (gltf::json::Root, Vec<u8>) {
        self.align_to_4();
        // Only register a buffer when there is geometry to carry. A zero-LOD
        // (or all-empty) mesh produces no accessors/bufferViews and an empty
        // BIN; pushing a `byteLength: 0` buffer would be spec-invalid (glTF 2.0
        // §5.9 requires `byteLength > 0`, and a no-URI buffer needs a BIN chunk
        // that `finish_glb` omits when bin is empty). With bin empty there are
        // no bufferViews referencing buffer 0, so omitting it leaves nothing
        // dangling — the result is a valid asset-only GLB.
        if !self.bin.is_empty() {
            // A self-contained GLB buffer carries no `uri`. Its index is fixed
            // at 0 (no other buffer is created), so the `Index` is discarded.
            let _ = self.root.push(gltf::json::Buffer {
                byte_length: USize64::from(self.bin.len()),
                name: None,
                uri: None,
                extensions: None,
                extras: gltf::json::extras::Void::default(),
            });
        }
        (self.root, self.bin)
    }
}

/// Serialize `root` + the BIN `buffer` into GLB bytes.
pub(crate) fn finish_glb(root: &gltf::json::Root, bin: Vec<u8>) -> crate::Result<Vec<u8>> {
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
/// non-interleaved vertex attributes (`NORMAL`/`TANGENT`/`TEXCOORD_n`); a
/// position lowering keeps its own loop because it also folds component-wise
/// min/max while encoding.
pub(crate) fn encode_f32_le<const N: usize>(
    items: impl ExactSizeIterator<Item = [f32; N]>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(items.len() * N * 4);
    for item in items {
        for f in item {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    bytes
}

/// Append a `JOINTS_0` accessor (VEC4 of bone indices, one set per vertex).
///
/// glTF allows either `UNSIGNED_BYTE` or `UNSIGNED_SHORT` for joint indices;
/// `use_short` selects `U16` (little-endian) for skeletons with >255 bones,
/// otherwise each index is emitted as a single `U8`. The caller guarantees the
/// values fit in `u8` when `use_short` is false (that range check lives in the
/// handler). Joint indices are never normalized; the view targets the vertex
/// `ArrayBuffer`.
#[allow(clippy::cast_possible_truncation)]
// `v as u8` is intentional: when `use_short` is false the handler guarantees
// every index fits in a u8 (the range check lives there, not here).
pub(crate) fn push_joints(
    doc: &mut GltfDoc,
    joints: &[[u16; 4]],
    use_short: bool,
) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(joints.len() * 4 * if use_short { 2 } else { 1 });
    for set in joints {
        for &v in set {
            if use_short {
                bytes.extend_from_slice(&v.to_le_bytes());
            } else {
                bytes.push(v as u8);
            }
        }
    }
    let component_type = if use_short {
        ComponentType::U16
    } else {
        ComponentType::U8
    };
    doc.push_accessor(
        &bytes,
        component_type,
        Type::Vec4,
        joints.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    )
}

/// Append a `WEIGHTS_0` accessor (VEC4 of normalized `U8` skin weights).
///
/// Weights are stored normalized (`U8`/255 → `[0,1]`); glTF requires the four
/// per-vertex weights to sum to 1 after normalization (the handler enforces
/// that). The view targets the vertex `ArrayBuffer`.
pub(crate) fn push_weights(doc: &mut GltfDoc, weights: &[[u8; 4]]) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(weights.len() * 4);
    for set in weights {
        bytes.extend_from_slice(set);
    }
    doc.push_accessor(
        &bytes,
        ComponentType::U8,
        Type::Vec4,
        weights.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        true,
    )
}

/// Append a `WEIGHTS_0` accessor (VEC4 of normalized `U16` skin weights) for UE5
/// 16-bit (`IncreasedSkinWeightPrecision`) skin weights.
///
/// Weights are stored normalized (`U16`/65535 → `[0,1]`, little-endian); glTF
/// requires the four per-vertex weights to sum to 1 after normalization (the
/// handler enforces the sum-to-65535 invariant). The view targets the vertex
/// `ArrayBuffer`.
pub(crate) fn push_weights_u16(
    doc: &mut GltfDoc,
    weights: &[[u16; 4]],
) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(weights.len() * 4 * 2);
    for set in weights {
        for &w in set {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
    }
    doc.push_accessor(
        &bytes,
        ComponentType::U16,
        Type::Vec4,
        weights.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        true,
    )
}

/// Append an inverse-bind-matrices accessor (MAT4 of column-major `f32`).
///
/// Per the glTF 2.0 spec, the bufferView referenced by `inverseBindMatrices`
/// MUST NOT specify a `target` (it is not vertex or index data), so this passes
/// `target: None`. Each matrix is 16 little-endian `f32` in glTF column-major
/// order (the caller is responsible for the column-major layout).
pub(crate) fn push_mat4(doc: &mut GltfDoc, mats: &[[f32; 16]]) -> Index<gltf::json::Accessor> {
    let bytes = encode_f32_le(mats.iter().copied());
    doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Mat4,
        mats.len(),
        None,
        None,
        None,
        false,
    )
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
pub(crate) fn convert_position(v: &FVector) -> [f32; 3] {
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
pub(crate) fn normalize_xyz([x, y, z]: [f32; 3]) -> [f32; 3] {
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
pub(crate) fn convert_dir(v: &FVector) -> [f32; 3] {
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
pub(crate) fn convert_tangent(v: &FVector4) -> [f32; 4] {
    let [x, y, z] = normalize_xyz([v.x as f32, v.z as f32, v.y as f32]);
    [x, y, z, -(v.w as f32)]
}

/// Reverse triangle winding (`[a,b,c]` → `[a,c,b]`) to restore CCW front faces
/// after the handedness-flipping basis change. Callers floor the span to a
/// multiple of 3 before this, so `indices.len()` is always a whole number of
/// triangles; the trailing `remainder()` copy is defensive-only (a partial tail
/// would be copied verbatim rather than dropped).
///
/// DELIBERATE DIVERGENCE FROM CUE4Parse. CUE4Parse's `Gltf.cs` does NOT reverse
/// winding; it emits explicit NORMAL attributes and relies on viewers not
/// back-face-culling. paksmith reverses so the CCW front-face convention agrees
/// with the basis flip (det = −1). The orientation is verified by
/// `winding_reversal_yields_outward_ccw_faces`, which checks the recomputed
/// geometric face normal agrees with the converted vertex normal (a no-reverse
/// mutant flips the sign); the Blender cube render (Task 12) is the visual
/// confirmation.
pub(crate) fn reverse_winding(indices: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(indices.len());
    let mut tri = indices.chunks_exact(3);
    for c in &mut tri {
        out.extend_from_slice(&[c[0], c[2], c[1]]);
    }
    out.extend_from_slice(tri.remainder());
    out
}

/// True iff every CONVERTED (UE→glTF, f64→f32) geometry float for this LOD is
/// finite. Positions/normals/tangents/UVs flow into glTF accessor BIN floats;
/// a non-finite component would emit a spec-invalid `ACCESSOR_INVALID_FLOAT`
/// (or, for position min/max, JSON `null`). Colors are u8 (always finite),
/// skipped. The check is on the CONVERTED f32 (a finite f64 can overflow the
/// narrowing to `inf`).
///
/// Normals/tangents pass through [`convert_dir`]/[`convert_tangent`], whose
/// [`normalize_xyz`] returns a non-finite (NaN/∞) input unchanged rather than
/// dividing by it, so a non-finite normal/tangent xyz survives into the
/// converted output and is caught here; a non-finite tangent `w` is caught via
/// the `-(v.w as f32)` negation in [`convert_tangent`].
pub(crate) fn lod_geometry_finite(
    positions: &[FVector],
    normals: &[FVector],
    tangents: &[FVector4],
    uvs: &[Option<Vec<FVector2D>>; 4],
) -> bool {
    positions
        .iter()
        .all(|p| convert_position(p).iter().all(|c| c.is_finite()))
        && normals
            .iter()
            .all(|n| convert_dir(n).iter().all(|c| c.is_finite()))
        && tangents
            .iter()
            .all(|t| convert_tangent(t).iter().all(|c| c.is_finite()))
        && uvs.iter().flatten().flatten().all(|uv| {
            // `push_uvs` emits `uv.x as f32`, `uv.y as f32`; mirror that exact
            // narrowing for the finiteness preflight.
            #[allow(clippy::cast_possible_truncation)]
            let (x, y) = (uv.x as f32, uv.y as f32);
            x.is_finite() && y.is_finite()
        })
}

/// Lower a vertex-position slice into a `POSITION` accessor (VEC3 f32) with the
/// glTF-required component-wise `min`/`max`. Shared by both mesh exporters
/// (static + skeletal). An empty slice emits zero `min`/`max` (degenerate but
/// the `±INFINITY` seeds must not leak into the bounds).
pub(crate) fn push_positions(
    doc: &mut GltfDoc,
    positions: &[FVector],
) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(positions.len() * 12);
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for p in positions {
        let c = convert_position(p);
        for i in 0..3 {
            min[i] = min[i].min(c[i]);
            max[i] = max[i].max(c[i]);
        }
        for f in c {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    if positions.is_empty() {
        min = [0.0; 3];
        max = [0.0; 3];
    }
    doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        positions.len(),
        Some(Target::ArrayBuffer),
        Some(serde_json::json!(min)),
        Some(serde_json::json!(max)),
        false,
    )
}

/// Lower a normals slice → `NORMAL` accessor (VEC3 f32), or `None` when empty.
pub(crate) fn push_normals(
    doc: &mut GltfDoc,
    normals: &[FVector],
) -> Option<Index<gltf::json::Accessor>> {
    if normals.is_empty() {
        return None;
    }
    let bytes = encode_f32_le(normals.iter().map(convert_dir));
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        normals.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower a tangents slice → `TANGENT` accessor (VEC4 f32, w = handedness), or
/// `None` when empty.
pub(crate) fn push_tangents(
    doc: &mut GltfDoc,
    tangents: &[FVector4],
) -> Option<Index<gltf::json::Accessor>> {
    if tangents.is_empty() {
        return None;
    }
    let bytes = encode_f32_le(tangents.iter().map(convert_tangent));
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec4,
        tangents.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower each present UV channel → a `TEXCOORD_n` accessor (VEC2 f32), in channel
/// order. Returns the accessor indices (`accs[n]` is `TEXCOORD_n`). UE UVs are
/// already top-left-origin like glTF, so no V flip is applied.
#[allow(clippy::cast_possible_truncation)]
// glTF FLOAT accessors are 32-bit; UV f64 precision is intentionally narrowed.
pub(crate) fn push_uvs(
    doc: &mut GltfDoc,
    uvs: &[Option<Vec<FVector2D>>; 4],
) -> Vec<Index<gltf::json::Accessor>> {
    let mut out = Vec::new();
    for channel in uvs.iter().flatten() {
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
/// `None` when absent. `FColor` is stored RGBA already, matching glTF's order.
pub(crate) fn push_colors(
    doc: &mut GltfDoc,
    colors: Option<&[FColor]>,
) -> Option<Index<gltf::json::Accessor>> {
    let colors = colors?;
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

/// Build the shared geometry-attribute map (`POSITION`/`NORMAL`/`TANGENT`/
/// `TEXCOORD_n`/`COLOR_0`) for one LOD, pushing each present attribute as an
/// accessor and returning the `Semantic → accessor` map. Insert order matches
/// both mesh handlers' historical order: positions, then normals/tangents
/// (when present), then each present UV channel, then colors. The returned map
/// is keyed by [`Checked<Semantic>`] so the skeletal handler can layer its
/// `JOINTS`/`WEIGHTS` keys onto it. Shared by both mesh exporters; the per-LOD
/// caller is responsible for only invoking it when at least one primitive will
/// reference the accessors (so no orphaned accessor is emitted).
pub(crate) fn push_geometry_attributes(
    doc: &mut GltfDoc,
    positions: &[FVector],
    normals: &[FVector],
    tangents: &[FVector4],
    uvs: &[Option<Vec<FVector2D>>; 4],
    colors: Option<&[FColor]>,
) -> BTreeMap<Checked<Semantic>, Index<gltf::json::Accessor>> {
    // Every semantic key is distinct, so `insert` never displaces a prior value;
    // the discarded `Option` returns are intentional (clippy: let_underscore).
    let mut attributes = BTreeMap::new();
    let _ = attributes.insert(Valid(Semantic::Positions), push_positions(doc, positions));
    if let Some(n) = push_normals(doc, normals) {
        let _ = attributes.insert(Valid(Semantic::Normals), n);
    }
    if let Some(t) = push_tangents(doc, tangents) {
        let _ = attributes.insert(Valid(Semantic::Tangents), t);
    }
    for (i, uv) in push_uvs(doc, uvs).into_iter().enumerate() {
        // UV channel count is at most 4 (the fixed `[_; 4]` array), within u32.
        #[allow(clippy::cast_possible_truncation)]
        let key = Valid(Semantic::TexCoords(i as u32));
        let _ = attributes.insert(key, uv);
    }
    if let Some(c) = push_colors(doc, colors) {
        let _ = attributes.insert(Valid(Semantic::Colors(0)), c);
    }
    attributes
}

/// Lower a (winding-reversed) index slice → an index accessor. The component
/// width is chosen by the maximum index **value** in the slice: `UNSIGNED_SHORT`
/// when `max < 0xFFFF` (i.e. ≤ 65 534), else `UNSIGNED_INT`. The strict `<`
/// bound is mandatory, not a stylistic choice: glTF 2.0 forbids an index
/// accessor from containing the component-type maximum (`0xFFFF` for U16,
/// `0xFFFF_FFFF` for U32) because that value is reserved for primitive restart
/// (validator error `ACCESSOR_INDEX_PRIMITIVE_RESTART`). A mesh whose highest
/// referenced vertex is 65 535 therefore promotes to U32. Choosing on the value
/// (not the vertex count) also prevents silent `u16` truncation. The U32 ceiling
/// `0xFFFF_FFFF` is unreachable (it would need a 4-billion-vertex LOD, blocked by
/// `MAX_VERTICES_PER_LOD`). Target is `ElementArrayBuffer`. Shared by both mesh
/// exporters.
pub(crate) fn push_indices(doc: &mut GltfDoc, indices: &[u32]) -> Index<gltf::json::Accessor> {
    let max_index = indices.iter().copied().max().unwrap_or(0);
    if max_index < u32::from(u16::MAX) {
        let mut bytes = Vec::with_capacity(indices.len() * 2);
        for &i in indices {
            #[allow(clippy::cast_possible_truncation)]
            // The `max_index < 0xFFFF` gate guarantees every index ≤ 65 534.
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

/// Whether every value in `indices` references a valid vertex (`< vertex_count`).
///
/// glTF 2.0 requires index-accessor values to stay within the element count of
/// the vertex attributes the primitive references; an out-of-range index is a
/// spec error (validator `ACCESSOR_INDEX_OOB`). The `[first, num_triangles)`
/// range/triangle-floor clamp in [`section_index_span`] bounds *which slots* are
/// read, but a corrupt cook can still store an index *value* exceeding the LOD's
/// vertex count in an in-range slot. Callers screen the resolved slice with this
/// before emitting a primitive and drop the offending section. Shared by both
/// mesh exporters.
pub(crate) fn indices_within_vertex_count(indices: &[u32], vertex_count: usize) -> bool {
    // When `vertex_count` exceeds `u32::MAX` (unreachable — capped far below by
    // `MAX_VERTICES_PER_LOD`), every `u32` index is trivially in range.
    u32::try_from(vertex_count).map_or(true, |n| indices.iter().all(|&i| i < n))
}

/// Resolve a section's `[first, first + 3·num_triangles)` index range against an
/// index buffer of `indices_len`, returning `(first, tri_len)` where `tri_len` is
/// the whole-triangle-floored span actually covered.
///
/// The span is clamped to `indices_len` (a corrupt over-range count clamps rather
/// than panicking), then floored to a whole number of triangles: `first` may not
/// be triangle-aligned and the clamp can truncate mid-triangle, leaving a leftover
/// 1–2 indices that a glTF TRIANGLES primitive (`count % 3 == 0`) cannot carry.
///
/// `first` and `num_triangles` are attacker-controlled `i32`s, so `try_from` and
/// `saturating_*` defend the pre-clamp arithmetic. `first` is NOT clamped and may
/// exceed `indices_len` — but only when `tri_len == 0`, where the caller skips the
/// section before slicing with it. Shared by both mesh exporters (static uses
/// `first_index`, skeletal uses `base_index`).
pub(crate) fn section_index_span(
    first_index: i32,
    num_triangles: i32,
    indices_len: usize,
) -> (usize, usize) {
    let first = usize::try_from(first_index).unwrap_or(0);
    let len = usize::try_from(num_triangles)
        .unwrap_or(0)
        .saturating_mul(3);
    let end = first.saturating_add(len).min(indices_len);
    let avail = end.saturating_sub(first);
    let tri_len = avail - (avail % 3);
    (first, tri_len)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---------- Coordinate-conversion tests ----------

    // Exact equality is correct here: the inputs and the ×0.01 products
    // (1.0/2.0/3.0/0.0/-1.0) are all exactly representable in f32, so there
    // is no rounding to tolerate.
    #[test]
    fn indices_within_vertex_count_screens_out_of_range_values() {
        // All indices < vertex_count → in range.
        assert!(indices_within_vertex_count(&[0, 1, 2], 3));
        // The top legal value `vertex_count - 1` is in range (a `<`→`<=` /
        // `<`→`>` mutant on the bound would flip one of these two).
        assert!(indices_within_vertex_count(&[2], 3));
        // An index equal to the vertex count is OUT of range (0-based).
        assert!(!indices_within_vertex_count(&[0, 1, 3], 3));
        // A far-out-of-range value is rejected.
        assert!(!indices_within_vertex_count(&[9], 3));
        // Empty slice is vacuously in range.
        assert!(indices_within_vertex_count(&[], 0));
    }

    #[allow(clippy::float_cmp)] // exact representable values
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

    // ---------- Skin-attribute accessor helpers ----------

    #[test]
    fn push_joints_u8_is_vec4_unsigned_byte_not_normalized() {
        let mut doc = GltfDoc::new();
        let joints = [[0u16, 1, 2, 3], [4, 5, 6, 7]];
        let idx = push_joints(&mut doc, &joints, false);
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[idx.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U8))
        ));
        assert!(!a.normalized);
        assert_eq!(a.count.0, 2);
        let view = &root.buffer_views[a.buffer_view.unwrap().value()];
        assert!(matches!(view.target, Some(Valid(Target::ArrayBuffer))));
        // One byte per component, 4 components per vertex, 2 verts.
        let off = usize::try_from(view.byte_offset.unwrap().0).expect("offset fits usize");
        assert_eq!(&bin[off..off + 8], &[0u8, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn push_joints_u16_is_vec4_unsigned_short() {
        let mut doc = GltfDoc::new();
        let joints = [[0x0102u16, 0x0304, 0x0506, 0x0708]];
        let idx = push_joints(&mut doc, &joints, true);
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[idx.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
        assert!(!a.normalized);
        assert_eq!(a.count.0, 1);
        let view = &root.buffer_views[a.buffer_view.unwrap().value()];
        assert!(matches!(view.target, Some(Valid(Target::ArrayBuffer))));
        let off = usize::try_from(view.byte_offset.unwrap().0).expect("offset fits usize");
        // Little-endian u16: 0x0102 → [0x02, 0x01], etc.
        assert_eq!(
            &bin[off..off + 8],
            &[0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07]
        );
    }

    #[test]
    fn push_weights_is_vec4_unsigned_byte_normalized() {
        let mut doc = GltfDoc::new();
        let weights = [[255u8, 0, 0, 0], [64, 64, 64, 63]];
        let idx = push_weights(&mut doc, &weights);
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[idx.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U8))
        ));
        assert!(a.normalized);
        assert_eq!(a.count.0, 2);
        let view = &root.buffer_views[a.buffer_view.unwrap().value()];
        assert!(matches!(view.target, Some(Valid(Target::ArrayBuffer))));
        let off = usize::try_from(view.byte_offset.unwrap().0).expect("offset fits usize");
        assert_eq!(&bin[off..off + 8], &[255u8, 0, 0, 0, 64, 64, 64, 63]);
    }

    #[test]
    fn push_weights_u16_is_vec4_unsigned_short_normalized() {
        let mut doc = GltfDoc::new();
        let weights = [[65535u16, 0, 0, 0], [16384, 16384, 16384, 16383]];
        let idx = push_weights_u16(&mut doc, &weights);
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[idx.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
        assert!(a.normalized);
        assert_eq!(a.count.0, 2);
        let view = &root.buffer_views[a.buffer_view.unwrap().value()];
        assert!(matches!(view.target, Some(Valid(Target::ArrayBuffer))));
        let off = usize::try_from(view.byte_offset.unwrap().0).expect("offset fits usize");
        let mut expected = Vec::new();
        for w in [65535u16, 0, 0, 0, 16384, 16384, 16384, 16383] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(&bin[off..off + 16], expected.as_slice());
    }

    /// `lod_geometry_finite` is `true` for finite geometry and `false` once any
    /// single converted component (position / normal / tangent xyz / tangent w /
    /// UV) is non-finite. Pins each attribute branch of the `&&` chain.
    #[test]
    fn lod_geometry_finite_detects_each_non_finite_attribute() {
        let pos = vec![FVector {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        }];
        let nrm = vec![FVector {
            x: 0.0,
            y: 0.0,
            z: 1.0,
        }];
        let tan = vec![FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        }];
        let uvs: [Option<Vec<FVector2D>>; 4] =
            [Some(vec![FVector2D { x: 0.5, y: 0.5 }]), None, None, None];
        // Fully finite → accepted.
        assert!(lod_geometry_finite(&pos, &nrm, &tan, &uvs));

        // Non-finite position.
        let bad_pos = vec![FVector {
            x: f64::INFINITY,
            y: 0.0,
            z: 0.0,
        }];
        assert!(!lod_geometry_finite(&bad_pos, &nrm, &tan, &uvs));

        // Non-finite normal (survives `normalize_xyz`'s pass-through guard).
        let bad_nrm = vec![FVector {
            x: f64::NAN,
            y: 0.0,
            z: 0.0,
        }];
        assert!(!lod_geometry_finite(&pos, &bad_nrm, &tan, &uvs));

        // Non-finite tangent xyz.
        let bad_tan_xyz = vec![FVector4 {
            x: f64::INFINITY,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        }];
        assert!(!lod_geometry_finite(&pos, &nrm, &bad_tan_xyz, &uvs));

        // Non-finite tangent w (caught via the `-(v.w as f32)` negation).
        let bad_tan_w = vec![FVector4 {
            x: 1.0,
            y: 0.0,
            z: 0.0,
            w: f64::NAN,
        }];
        assert!(!lod_geometry_finite(&pos, &nrm, &bad_tan_w, &uvs));

        // Non-finite UV.
        let bad_uvs: [Option<Vec<FVector2D>>; 4] = [
            Some(vec![FVector2D {
                x: f64::INFINITY,
                y: 0.0,
            }]),
            None,
            None,
            None,
        ];
        assert!(!lod_geometry_finite(&pos, &nrm, &tan, &bad_uvs));
    }

    #[test]
    fn push_mat4_is_mat4_f32_no_target() {
        let mut doc = GltfDoc::new();
        let identity: [f32; 16] = [
            1.0, 0.0, 0.0, 0.0, //
            0.0, 1.0, 0.0, 0.0, //
            0.0, 0.0, 1.0, 0.0, //
            0.0, 0.0, 0.0, 1.0,
        ];
        let idx = push_mat4(&mut doc, &[identity]);
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[idx.value()];
        assert!(matches!(a.type_, Valid(Type::Mat4)));
        assert!(matches!(
            a.component_type,
            Valid(GenericComponentType(ComponentType::F32))
        ));
        assert!(!a.normalized);
        assert_eq!(a.count.0, 1);
        let view_idx = a.buffer_view.expect("inverseBindMatrices needs a view");
        // inverseBindMatrices accessors must NOT set a bufferView target.
        assert!(root.buffer_views[view_idx.value()].target.is_none());
        let off = usize::try_from(root.buffer_views[view_idx.value()].byte_offset.unwrap().0)
            .expect("offset fits usize");
        let expected: Vec<u8> = identity.iter().flat_map(|f| f.to_le_bytes()).collect();
        assert_eq!(&bin[off..off + 64], expected.as_slice());
    }
}
