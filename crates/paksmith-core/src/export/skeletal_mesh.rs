//! Skinned-mesh glTF export: the [`GltfSkeletalMeshHandler`], skeleton/skin
//! build, per-vertex skin attributes, and the UE→glTF coordinate-frame math.
//!
//! Phase 3h's skeletal exporter must place the skeleton's bone
//! transforms in the SAME coordinate frame as the geometry. The
//! geometry path ([`super::gltf_common::convert_position`]) maps a UE
//! vertex `(x, y, z)` to glTF `(0.01x, 0.01z, 0.01y)` — centimetres to
//! metres plus the Y↔Z axis swap. The bind matrices therefore have to
//! be expressed through the matching change-of-basis `B`, or the skin
//! ends up silently rotated relative to the mesh.
//!
//! This module supplies that basis (`B = 0.01·P`) and the
//! `FTransform` → column-major affine `DMat4` helper used to build
//! bone-local matrices, both on `glam`'s f64 types.

use glam::{DMat4, DQuat, DVec3, DVec4};
use gltf::json::Index;
use gltf::json::mesh::{Mode, Primitive, Semantic};
use gltf::json::validation::Checked::Valid;

use crate::PaksmithError;
use crate::asset::structs::transform::FTransform;
use crate::asset::{Asset, BoneWeights, ReferenceSkeleton, SkeletalMeshData, SkeletalMeshLod};

use super::gltf_common::{
    self, GltfDoc, MAX_GLB_BIN_BYTES, finish_glb, push_joints, push_mat4, push_weights,
    push_weights_u16, reverse_winding,
};
use super::static_mesh::MAX_MESH_MATERIALS;
use super::{BulkData, FormatHandler};

/// A skin-weight component (`u8` or `u16`) with its glTF normalization target.
/// `normalized:true` weight accessors require each vertex's weights to sum to the
/// component's max value (`255` / `65535`) so they dequantize to `1.0`. Lets the
/// skin-attribute build pass run identically for the common 8-bit layout and the
/// UE5 `IncreasedSkinWeightPrecision` 16-bit layout (emitted as `UNSIGNED_SHORT`).
trait SkinWeight: Copy + Default + PartialEq {
    /// Per-vertex normalization target: `255` for `u8`, `65535` for `u16`.
    const GLTF_SUM: u32;
    /// Widen to `u32` for sum / rescale arithmetic.
    fn to_u32(self) -> u32;
    /// `min(v, GLTF_SUM)` narrowed back to `Self` (always in range after the min).
    fn from_u32_clamped(v: u32) -> Self;
}

impl SkinWeight for u8 {
    const GLTF_SUM: u32 = 255;
    fn to_u32(self) -> u32 {
        u32::from(self)
    }
    fn from_u32_clamped(v: u32) -> Self {
        u8::try_from(v.min(Self::GLTF_SUM)).unwrap_or(u8::MAX)
    }
}

impl SkinWeight for u16 {
    const GLTF_SUM: u32 = 65535;
    fn to_u32(self) -> u32 {
        u32::from(self)
    }
    fn from_u32_clamped(v: u32) -> Self {
        u16::try_from(v.min(Self::GLTF_SUM)).unwrap_or(u16::MAX)
    }
}

/// Upper bound on bone count for a single skeleton. UE skeletons are limited to
/// `u16` bone indices on the wire; this generous cap guards against a crafted
/// asset claiming an absurd bone count before we allocate per-bone glTF nodes.
pub(crate) const MAX_BONES_PER_SKELETON: usize = 65_536;

/// The glTF nodes + skin produced from a UE [`ReferenceSkeleton`].
pub(crate) struct SkeletonOut {
    /// One node index per bone, in skeleton order (parallel to `skeleton.bones`).
    /// Part of the builder's contract (and exercised by the skeleton tests'
    /// per-joint matrix checks); the export path wires joints through `skin` +
    /// `root_nodes`, so the field is read only under `#[cfg(test)]`.
    #[allow(dead_code)]
    pub(crate) joints: Vec<gltf::json::Index<gltf::json::Node>>,
    /// The skin tying the joint list to its inverse-bind-matrices accessor.
    pub(crate) skin: gltf::json::Index<gltf::json::Skin>,
    /// Node indices of the root bones (`parent_index == -1`).
    pub(crate) root_nodes: Vec<gltf::json::Index<gltf::json::Node>>,
}

/// Build the glTF bone-node hierarchy + skin from a UE reference skeleton.
///
/// Each bone node's LOCAL matrix is `B · L_i · B⁻¹` where `L_i` is the bone's
/// (child-relative) bind transform and `B` is [`ue_to_gltf_basis`]. This
/// conjugation makes the node-hierarchy product telescope to node-global
/// `B · G_i · B⁻¹` (G_i = global bind), which the inverse-bind-matrices
/// ([`inverse_bind_matrices`]) rely on so `jointGlobal_i · IBM_i = I` in
/// bind pose.
///
/// # Errors
/// Returns [`PaksmithError::UnsupportedFeature`] for a malformed skeleton:
/// `bones`/`bind_pose` length mismatch, more than [`MAX_BONES_PER_SKELETON`]
/// bones, a `parent_index` that is neither `-1` nor an index strictly less than
/// the bone's own (forward ref / cycle / out-of-bounds), or a bind pose that
/// produces a NON-FINITE emitted node matrix or inverse-bind-matrix (degenerate
/// pose: zero/near-zero scale → singular inverse, or zero/non-finite
/// rotation/translation). `serde_json` would otherwise serialize the non-finite
/// `f32` as JSON `null`, silently invalid glTF.
pub(crate) fn build_skeleton(
    doc: &mut GltfDoc,
    skeleton: &ReferenceSkeleton,
) -> crate::Result<SkeletonOut> {
    let bone_count = skeleton.bones.len();
    if bone_count != skeleton.bind_pose.len() {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "skeletal mesh: reference-skeleton bones ({bone_count}) and bind-pose \
                 ({}) lengths differ",
                skeleton.bind_pose.len()
            ),
        });
    }
    if bone_count > MAX_BONES_PER_SKELETON {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "skeletal mesh: {bone_count} bones exceeds MAX_BONES_PER_SKELETON \
                 ({MAX_BONES_PER_SKELETON})"
            ),
        });
    }

    // Resolve each parent into `Some(parent)` (valid, strictly precedes child)
    // or `None` (root). `p < i` subsumes the forward-ref / cycle / OOB checks;
    // `usize::try_from` folds the sign check so no `as` cast (cast_sign_loss).
    let parents: Vec<Option<usize>> = skeleton
        .bones
        .iter()
        .enumerate()
        .map(|(i, bone)| match usize::try_from(bone.parent_index) {
            Ok(p) if p < i => Ok(Some(p)),
            _ if bone.parent_index == -1 => Ok(None),
            _ => Err(PaksmithError::UnsupportedFeature {
                context: format!(
                    "skeletal mesh: bone {i} ({}) has invalid parent_index {} \
                     (must be -1 or a bone index < {i})",
                    bone.name, bone.parent_index
                ),
            }),
        })
        .collect::<crate::Result<_>>()?;

    // First pass: one node per bone with the basis-conjugated local matrix.
    let b = ue_to_gltf_basis();
    let b_inv = b.inverse();
    let mut joints = Vec::with_capacity(bone_count);
    for (bone, transform) in skeleton.bones.iter().zip(&skeleton.bind_pose) {
        let local = b * ftransform_to_dmat4(transform) * b_inv;
        #[allow(clippy::cast_possible_truncation)]
        // f64 → f32 narrowing for glTF FLOAT matrix emission (glam f64 math).
        let matrix = local.to_cols_array().map(|x| x as f32);
        if !matrix_all_finite(&matrix) {
            return Err(non_finite_matrix_error());
        }
        joints.push(doc.root.push(gltf::json::Node {
            name: Some(bone.name.clone()),
            matrix: Some(matrix),
            ..Default::default()
        }));
    }

    // Second pass: collect per-parent child lists, then assign them (mutating
    // after push avoids borrowing `doc.root` while it is still being pushed to).
    let mut children: Vec<Vec<gltf::json::Index<gltf::json::Node>>> = vec![Vec::new(); bone_count];
    for (i, parent) in parents.iter().enumerate() {
        if let Some(parent) = parent {
            children[*parent].push(joints[i]);
        }
    }
    for (parent_idx, list) in children.into_iter().enumerate() {
        if !list.is_empty() {
            doc.root.nodes[joints[parent_idx].value()].children = Some(list);
        }
    }

    let root_nodes: Vec<gltf::json::Index<gltf::json::Node>> = parents
        .iter()
        .enumerate()
        .filter_map(|(i, parent)| parent.is_none().then_some(joints[i]))
        .collect();

    let ibms = inverse_bind_matrices(skeleton);
    if !ibms.iter().all(matrix_all_finite) {
        return Err(non_finite_matrix_error());
    }
    let ibm = push_mat4(doc, &ibms);

    let skin = doc.root.push(gltf::json::Skin {
        joints: joints.clone(),
        inverse_bind_matrices: Some(ibm),
        skeleton: root_nodes.first().copied(),
        name: None,
        extensions: None,
        extras: gltf::json::extras::Void::default(),
    });

    Ok(SkeletonOut {
        joints,
        skin,
        root_nodes,
    })
}

/// Per-bone glTF inverse-bind-matrices, column-major `[f32; 16]`, one per bone
/// in skeleton order. `IBM_i = (B · G_i · B⁻¹)⁻¹ = B · G_i⁻¹ · B⁻¹`, where
/// `G_i` is the global bind transform (parent-chain product). Pairs with the
/// `B · L_i · B⁻¹` node matrices from [`build_skeleton`] so that
/// `jointGlobal_i · IBM_i = I` in bind pose.
///
/// `build_skeleton` validates `parent_index < i` before calling this, but the
/// `pub(crate)` surface guards defensively: a parent that does not strictly
/// precede the bone (or is `-1`) is treated as a root.
pub(crate) fn inverse_bind_matrices(skeleton: &ReferenceSkeleton) -> Vec<[f32; 16]> {
    let b = ue_to_gltf_basis();
    let b_inv = b.inverse();
    let mut global: Vec<DMat4> = Vec::with_capacity(skeleton.bones.len());
    for (bone, transform) in skeleton.bones.iter().zip(&skeleton.bind_pose) {
        let local = ftransform_to_dmat4(transform);
        // `usize::try_from` folds the sign check (root `parent_index == -1`
        // fails the conversion); `p < global.len()` rejects forward refs.
        let g = match usize::try_from(bone.parent_index) {
            Ok(p) if p < global.len() => global[p] * local,
            _ => local,
        };
        global.push(g);
    }
    global
        .iter()
        .map(|g| {
            let cols = (b * *g * b_inv).inverse().to_cols_array();
            #[allow(clippy::cast_possible_truncation)]
            // f64 → f32 narrowing for glTF FLOAT matrix emission (glam f64 math).
            let out = cols.map(|x| x as f32);
            out
        })
        .collect()
}

/// UE→glTF change-of-basis `B = 0.01·P` (cm→m + Y↔Z axis swap), matching
/// [`super::gltf_common::convert_position`]. Column-major; pure linear (no
/// translation).
pub(crate) fn ue_to_gltf_basis() -> DMat4 {
    // B maps (x,y,z) -> (0.01x, 0.01z, 0.01y). Columns = images of e_x, e_y, e_z.
    //   e_x=(1,0,0) -> (0.01, 0,    0   )
    //   e_y=(0,1,0) -> (0,    0,    0.01)   (UE y -> glTF 3rd axis)
    //   e_z=(0,0,1) -> (0,    0.01, 0   )   (UE z -> glTF 2nd axis)
    DMat4::from_cols(
        DVec4::new(0.01, 0.0, 0.0, 0.0),
        DVec4::new(0.0, 0.0, 0.01, 0.0),
        DVec4::new(0.0, 0.01, 0.0, 0.0),
        DVec4::new(0.0, 0.0, 0.0, 1.0),
    )
}

/// `true` when every element of an emitted column-major glTF matrix is finite.
/// A bind pose with zero/near-zero scale yields a singular linear part whose
/// `.inverse()` is non-finite (this fires even for FINITE inputs — checking the
/// inputs is insufficient), and a zero quaternion normalizes to NaN; either way
/// `serde_json` would emit JSON `null` for the non-finite `f32`, so the emitted
/// matrices (not the raw inputs) are the load-bearing thing to validate.
fn matrix_all_finite(m: &[f32; 16]) -> bool {
    m.iter().all(|x| x.is_finite())
}

/// The typed error for a bind pose that produced a non-finite emitted matrix.
/// Shared by the node-matrix and inverse-bind-matrix validation sites so both
/// surface the same `UnsupportedFeature` context.
fn non_finite_matrix_error() -> PaksmithError {
    PaksmithError::UnsupportedFeature {
        context: "skeletal mesh bone transform produced a non-finite glTF matrix \
                  (degenerate bind pose: zero/near-zero scale, non-finite or zero \
                  rotation/translation)"
            .to_string(),
    }
}

/// Compose an [`FTransform`] (rotation·scale + translation) into a column-major
/// affine [`DMat4`]. The wire quaternion is normalized defensively.
pub(crate) fn ftransform_to_dmat4(t: &FTransform) -> DMat4 {
    let rot = DQuat::from_xyzw(t.rotation.x, t.rotation.y, t.rotation.z, t.rotation.w).normalize();
    DMat4::from_scale_rotation_translation(
        DVec3::new(t.scale_3d.x, t.scale_3d.y, t.scale_3d.z),
        rot,
        DVec3::new(t.translation.x, t.translation.y, t.translation.z),
    )
}

/// Per-vertex skin attributes for one LOD, split into the glTF `JOINTS_0` /
/// `WEIGHTS_0` (influences 0..4) and optional `JOINTS_1` / `WEIGHTS_1`
/// (influences 4..8) attribute sets.
///
/// `joints0`/`weights0` are parallel to the LOD's positions. `joints1`/`weights1`
/// are `Some` iff at least one vertex uses an influence slot in `4..8` (more than
/// four influences), in which case they are likewise parallel; otherwise `None`
/// so the exporter emits only the four-influence attribute set.
pub(crate) struct SkinAttrs {
    /// `JOINTS_0`: global skeleton bone indices for influences 0..4.
    pub(crate) joints0: Vec<[u16; 4]>,
    /// `JOINTS_1`: global bone indices for influences 4..8; `Some` iff used.
    pub(crate) joints1: Option<Vec<[u16; 4]>>,
    /// `WEIGHTS_0` (+ optional `WEIGHTS_1`), precision-tagged: `U8`
    /// (`UNSIGNED_BYTE`) for the common layout, `U16` (`UNSIGNED_SHORT`) for UE5
    /// `IncreasedSkinWeightPrecision`. The slot-1 weights are `Some` in lockstep
    /// with [`Self::joints1`].
    pub(crate) weights: SkinWeightAttr,
}

/// Precision-tagged `WEIGHTS_0` / `WEIGHTS_1` attribute data — `u8` (sum 255,
/// `UNSIGNED_BYTE`) or `u16` (sum 65535, `UNSIGNED_SHORT`), both `normalized`.
pub(crate) enum SkinWeightAttr {
    /// 8-bit normalized weights (the common cooked layout).
    U8 {
        /// `WEIGHTS_0` (influences 0..4).
        w0: Vec<[u8; 4]>,
        /// `WEIGHTS_1` (influences 4..8); `Some` iff used.
        w1: Option<Vec<[u8; 4]>>,
    },
    /// 16-bit normalized weights (UE5 `IncreasedSkinWeightPrecision`).
    U16 {
        /// `WEIGHTS_0` (influences 0..4).
        w0: Vec<[u16; 4]>,
        /// `WEIGHTS_1` (influences 4..8); `Some` iff used.
        w1: Option<Vec<[u16; 4]>>,
    },
}

/// Build per-vertex glTF skin attributes (`JOINTS`/`WEIGHTS`) for one LOD.
///
/// For each vertex, the owning section (the one whose
/// `[base_vertex_index, base_vertex_index + num_vertices)` range contains the
/// vertex) supplies the authoritative LOD-local → global bone-index remap via
/// [`SkelMeshSection::bone_map`](crate::asset::SkelMeshSection::bone_map). The
/// LOD-union `bone_map` is deliberately NOT used. Each vertex's eight emitted
/// weights are renormalized to sum exactly [`SkinWeight::GLTF_SUM`] (255 for u8,
/// 65535 for u16) by a proportional rescale (`new_i = round(w_i · target /
/// sum)`, with the small rounding residual folded into the largest-weight slot)
/// so the export passes `gltf-validator`'s
/// `Σ WEIGHTS ≈ 1.0` rule for ANY raw input sum — see [`renormalize_vertex`].
///
/// Degenerate vertices — whose influence weights sum to zero, or that no section
/// claims — are bound to joint `0` with weights `(255, 0, 0, 0)`. Since
/// `jointMatrix · IBM = I` in bind pose for the root, they render at rest and
/// stay glTF-valid.
///
/// On a vertex claimed by two sections, the later section in iteration order wins
/// (last-wins; documented rather than erroring, since overlapping ranges are not
/// observed in cooked assets and last-wins is harmless for a render).
///
/// # Errors
/// Returns [`PaksmithError::UnsupportedFeature`] when the skin buffers are
/// shorter than the position buffer (cannot skin), a section declares a negative
/// `num_vertices` or a vertex range that overflows / extends past the buffer, an
/// influence's local bone index is out of its section's `bone_map`, or a
/// `bone_map` entry is an out-of-bounds global skeleton index.
pub(crate) fn build_skin_attributes(
    lod: &SkeletalMeshLod,
    skeleton: &ReferenceSkeleton,
) -> crate::Result<SkinAttrs> {
    let n = lod.positions.len();
    if lod.bone_indices.len() < n || lod.bone_weights.len() < n {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "skeletal LOD skin buffers too short to skin {n} vertices: \
                 bone_indices={}, bone_weights={}",
                lod.bone_indices.len(),
                lod.bone_weights.len()
            ),
        });
    }

    let owning_section = owning_sections(lod, n)?;
    let bone_count = skeleton.bones.len();

    // The joints (bone-map remap + bounds checks) are precision-independent; only
    // the weight component type differs, so the per-vertex pass is generic over
    // the `BoneWeights` precision and the glTF accessor type follows from it.
    Ok(match &lod.bone_weights {
        BoneWeights::U8(w) => {
            let (joints0, joints1, w0, w1) = skin_weight_pass(lod, &owning_section, bone_count, w)?;
            SkinAttrs {
                joints0,
                joints1,
                weights: SkinWeightAttr::U8 { w0, w1 },
            }
        }
        BoneWeights::U16(w) => {
            let (joints0, joints1, w0, w1) = skin_weight_pass(lod, &owning_section, bone_count, w)?;
            SkinAttrs {
                joints0,
                joints1,
                weights: SkinWeightAttr::U16 { w0, w1 },
            }
        }
    })
}

/// The precision-generic per-vertex skin pass shared by both [`BoneWeights`]
/// variants. For each vertex its owning section remaps the LOD-local influence
/// bone indices to global skeleton indices (with bounds checks), the weights are
/// renormalized ([`renormalize_vertex`]), and the eight influences are split into
/// the `JOINTS_0/WEIGHTS_0` (0..4) and optional `JOINTS_1/WEIGHTS_1` (4..8) sets.
/// A vertex no section claims keeps the root-bound rest pose (joint 0, full
/// weight). Returns `(joints0, joints1, weights0, weights1)`; the slot-1 vectors
/// are `Some` iff some vertex uses an influence in `4..8`.
///
/// # Errors
/// [`PaksmithError::UnsupportedFeature`] when an influence's local bone index is
/// out of its section's `bone_map`, or a `bone_map` entry is out of the
/// skeleton's bone range.
#[allow(
    clippy::type_complexity,
    reason = "the four parallel attribute vectors are the natural return; wrapping them in a one-off struct would not aid clarity"
)]
fn skin_weight_pass<W: SkinWeight>(
    lod: &SkeletalMeshLod,
    owning_section: &[Option<usize>],
    bone_count: usize,
    bone_weights: &[[W; 8]],
) -> crate::Result<(
    Vec<[u16; 4]>,
    Option<Vec<[u16; 4]>>,
    Vec<[W; 4]>,
    Option<Vec<[W; 4]>>,
)> {
    let n = owning_section.len();
    // Default every vertex to the root bone at rest (full weight on slot 0).
    // Vertices a section claims overwrite this; uncovered vertices keep it.
    let root_rest: [W; 4] = [
        W::from_u32_clamped(W::GLTF_SUM),
        W::default(),
        W::default(),
        W::default(),
    ];
    let mut joints0 = vec![[0u16; 4]; n];
    let mut weights0 = vec![root_rest; n];
    let mut joints1 = vec![[0u16; 4]; n];
    let mut weights1 = vec![[W::default(); 4]; n];
    let mut used_slot1 = false;

    for (v, section_idx) in owning_section.iter().enumerate() {
        let Some(s) = *section_idx else { continue };
        let section_map = &lod.sections[s].bone_map;

        // Accumulate all eight influences into flat arrays, then renormalize and
        // split. Folding the renormalization residual over the full 8 slots keeps
        // the "max weight across both halves" search a single pass.
        let mut joints_all = [0u16; 8];
        let mut weights_all = [W::default(); 8];
        for i in 0..8 {
            let w = bone_weights[v][i];
            if w == W::default() {
                continue;
            }
            let local = usize::from(lod.bone_indices[v][i]);
            if local >= section_map.len() {
                return Err(PaksmithError::UnsupportedFeature {
                    context: format!(
                        "skeletal LOD vertex {v} influence {i} bone index {local} out of \
                         section bone_map ({})",
                        section_map.len()
                    ),
                });
            }
            let global = section_map[local];
            if usize::from(global) >= bone_count {
                return Err(PaksmithError::UnsupportedFeature {
                    context: format!(
                        "skeletal LOD vertex {v} influence {i} bone_map global index \
                         {global} out of skeleton bones ({bone_count})"
                    ),
                });
            }
            joints_all[i] = global;
            weights_all[i] = w;
        }

        renormalize_vertex(&mut joints_all, &mut weights_all);

        joints0[v] = [joints_all[0], joints_all[1], joints_all[2], joints_all[3]];
        weights0[v] = [
            weights_all[0],
            weights_all[1],
            weights_all[2],
            weights_all[3],
        ];
        joints1[v] = [joints_all[4], joints_all[5], joints_all[6], joints_all[7]];
        weights1[v] = [
            weights_all[4],
            weights_all[5],
            weights_all[6],
            weights_all[7],
        ];
        if weights_all[4..8].iter().any(|&w| w != W::default()) {
            used_slot1 = true;
        }
    }

    let (joints1, weights1) = if used_slot1 {
        (Some(joints1), Some(weights1))
    } else {
        (None, None)
    };
    Ok((joints0, joints1, weights0, weights1))
}

/// Map each vertex `0..n` to the index of its owning section, or `None` if no
/// section claims it. Last-wins on overlap. Validates each section's vertex range
/// (`num_vertices >= 0`, no `base + num` overflow, `end <= n`).
fn owning_sections(lod: &SkeletalMeshLod, n: usize) -> crate::Result<Vec<Option<usize>>> {
    let mut owning = vec![None; n];
    for (s, section) in lod.sections.iter().enumerate() {
        let base = usize::try_from(section.base_vertex_index).map_err(|_| {
            PaksmithError::UnsupportedFeature {
                context: format!(
                    "skeletal LOD section {s} base_vertex_index {} not representable",
                    section.base_vertex_index
                ),
            }
        })?;
        let num = usize::try_from(section.num_vertices).map_err(|_| {
            PaksmithError::UnsupportedFeature {
                context: format!(
                    "skeletal LOD section {s} has negative num_vertices {}",
                    section.num_vertices
                ),
            }
        })?;
        let end = base
            .checked_add(num)
            .ok_or_else(|| PaksmithError::UnsupportedFeature {
                context: format!("skeletal LOD section {s} vertex range {base}+{num} overflows"),
            })?;
        if end > n {
            return Err(PaksmithError::UnsupportedFeature {
                context: format!(
                    "skeletal LOD section {s} vertex range [{base}, {end}) exceeds \
                     vertex count {n}"
                ),
            });
        }
        for slot in &mut owning[base..end] {
            *slot = Some(s);
        }
    }
    Ok(owning)
}

/// Renormalize a vertex's eight weights so the emitted components sum to
/// [`SkinWeight::GLTF_SUM`] (`255` for `u8`, `65535` for `u16`), satisfying
/// glTF's `Σ WEIGHTS ≈ 1.0` rule for ANY raw input — including attacker weights
/// that sum far above the target (e.g. eight `255`s, or eight `65535`s).
///
/// Algorithm (identical for both precisions):
/// - A zero sum (degenerate / unskinned vertex) is rebound to the root bone at
///   rest, full weight on slot 0.
/// - Otherwise each slot is rescaled PROPORTIONALLY: `new_i = round(w_i · target
///   / sum)` (computed in `u64` — `65535 · 65535 + sum/2` overflows `u32` — with
///   round-to-nearest). Since `w_i ≤ sum`, every rescaled value is `≤ target`.
/// - The small rounding residual `target − Σ new_i` (bounded by ±8, one per slot)
///   is folded into the current max-weight slot with saturating arithmetic,
///   leaving `Σ == target` exactly for all realistic inputs.
///
/// The function NEVER panics: all arithmetic is `u64`/`i64`/saturating and stays
/// within the quantization tolerance even when the max slot saturates.
fn renormalize_vertex<W: SkinWeight>(joints: &mut [u16; 8], weights: &mut [W; 8]) {
    let target = W::GLTF_SUM;
    let sum: u32 = weights.iter().map(|w| w.to_u32()).sum();
    if sum == 0 {
        *joints = [0; 8];
        weights.fill(W::default());
        weights[0] = W::from_u32_clamped(target);
        return;
    }

    // Proportional rescale with round-to-nearest, in `u64` so `w · target +
    // sum/2` can't overflow at 16-bit precision (65535² + sum/2 exceeds u32::MAX).
    // `w_i ≤ sum` ⇒ `scaled ≤ target`
    // (the clamp is belt-and-suspenders against a rounding edge).
    for w in weights.iter_mut() {
        let scaled =
            (u64::from(w.to_u32()) * u64::from(target) + u64::from(sum) / 2) / u64::from(sum);
        *w = W::from_u32_clamped(u32::try_from(scaled).unwrap_or(target));
    }

    // Fold the rounding residual (|target − Σ| ≤ 8) into the max-weight slot.
    let rescaled_sum: u32 = weights.iter().map(|w| w.to_u32()).sum();
    if rescaled_sum == target {
        return;
    }
    let max_idx = weights
        .iter()
        .enumerate()
        .max_by_key(|(_, w)| w.to_u32())
        .map_or(0, |(i, _)| i);
    // `rescaled_sum ≤ 8·target` and `target` both fit `i64` infallibly, and their
    // difference (the residual) fits `i64` without overflow.
    let residual = i64::from(target) - i64::from(rescaled_sum);
    let cur = weights[max_idx].to_u32();
    weights[max_idx] = if residual >= 0 {
        W::from_u32_clamped(cur.saturating_add(u32::try_from(residual).unwrap_or(u32::MAX)))
    } else {
        W::from_u32_clamped(cur.saturating_sub(u32::try_from(-residual).unwrap_or(u32::MAX)))
    };
}

// ---------------------------------------------------------------------------
// GltfSkeletalMeshHandler — the skinned-glTF (.glb) FormatHandler
// ---------------------------------------------------------------------------

/// Maximum number of LODs a single skeletal mesh may export before the glTF
/// build is rejected. `data.lods` is parser-bounded already, but the export
/// path applies its own conservative cap (mirroring the static-mesh per-mesh
/// caps) so a crafted asset cannot inflate the node/mesh count unboundedly.
pub(crate) const MAX_SKELETAL_LODS_PER_MESH: usize = 8;

/// Lowers a cooked `USkeletalMesh` into a self-contained skinned glTF 2.0 binary
/// (`.glb`): a bone-node skeleton + skin, plus one mesh node per LOD whose
/// primitives carry the geometry attributes (POSITION/NORMAL/TANGENT/TEXCOORD_n/
/// COLOR_0) PLUS the skin attributes (JOINTS_0/WEIGHTS_0 and, when a vertex uses
/// more than four influences, JOINTS_1/WEIGHTS_1). Each LOD's mesh node is
/// identity-transformed and references the shared skin so glTF skinning folds in
/// the correct bind pose.
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfSkeletalMeshHandler;

impl FormatHandler for GltfSkeletalMeshHandler {
    fn output_extension(&self) -> &'static str {
        "glb"
    }

    /// Accepts a `SkeletalMesh` carrying at least one LOD with geometry.
    ///
    /// A `SkeletalMesh` with NO drawable LOD — e.g. one whose every LOD is
    /// non-inlined/streaming-only, which parses to `Asset::SkeletalMesh` with
    /// empty per-LOD positions — yields `supports() == false`. There is no
    /// cross-discriminant downgrade: such a mesh is NOT routed to
    /// [`GenericHandler`](crate::export::GenericHandler), and
    /// [`HandlerRegistry::find_handler`](crate::export::HandlerRegistry::find_handler)
    /// simply returns `None`. Surfacing geometry-less skeletal meshes (e.g. via
    /// the bulk LOD payload) is a future parser/walker concern.
    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::SkeletalMesh(d) if d.lods.iter().any(|l| !l.positions.is_empty()))
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::SkeletalMesh(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GltfSkeletalMeshHandler::export called on a non-SkeletalMesh Asset"
                    .to_string(),
            });
        };

        // No-drawable-geometry guard (cheap, O(LODs)). A mesh whose every LOD has
        // empty positions (e.g. all-streaming/bulk LODs) cannot emit a primitive
        // and would reach `build_skeleton`/`push_mat4(&[])`, producing spec-invalid
        // glTF (a count:0 MAT4 accessor + dangling bufferView, or a zero-joint
        // skin). Reject up front. (`supports()` already filters this, so it is not
        // attacker-reachable, but the defensive guard keeps the invariant local.)
        if !data.lods.iter().any(|l| !l.positions.is_empty()) {
            return Err(crate::PaksmithError::UnsupportedFeature {
                context: "skeletal mesh has no drawable LOD geometry".to_string(),
            });
        }

        // LOD-count cap (cheap, O(1)).
        if data.lods.len() > MAX_SKELETAL_LODS_PER_MESH {
            return Err(crate::PaksmithError::UnsupportedFeature {
                context: format!(
                    "skeletal mesh has {} LODs exceeding the {MAX_SKELETAL_LODS_PER_MESH}-LOD \
                     export cap",
                    data.lods.len()
                ),
            });
        }

        // Aggregate-output cap (O(sections), pure projection) BEFORE allocating.
        enforce_export_cap(data)?;

        // Finiteness check over CONVERTED geometry (O(verts), after the cheaper
        // cap), per LOD over ALL attributes (position/normal/tangent/UV). A
        // non-finite converted component cannot produce valid glTF: a non-finite
        // POSITION min/max serializes to JSON `null`, and a non-finite
        // normal/tangent/UV emits a spec-invalid `ACCESSOR_INVALID_FLOAT`. Reject
        // fail-fast rather than emit SILENTLY.
        // Only LODs that will actually be emitted are validated: the emit loop
        // below skips empty-position LODs (`if lod.positions.is_empty()`), so a
        // junk non-drawable LOD with a non-finite normal/UV must NOT block the
        // export of an otherwise-valid mesh. Mirror the emit-loop filter here.
        // (Residual, deliberately accepted: a LOD with non-empty positions but
        // all-degenerate sections — also dropped at emit — is still validated and
        // may over-reject. The error direction is safe, so the cheap positions-only
        // filter is kept rather than resolving sections in the preflight.)
        for lod in &data.lods {
            if lod.positions.is_empty() {
                continue;
            }
            if !gltf_common::lod_geometry_finite(
                &lod.positions,
                &lod.normals,
                &lod.tangents,
                &lod.uvs,
            ) {
                return Err(crate::PaksmithError::UnsupportedFeature {
                    context: "skeletal mesh has a non-finite vertex attribute \
                              (position/normal/tangent/UV — Inf/NaN), which cannot \
                              produce valid glTF accessors"
                        .to_string(),
                });
            }
        }

        // A skin with zero joints, referenced by JOINTS pointing at joint 0, is
        // invalid glTF. The no-drawable-geometry guard above already established
        // that at least one LOD has vertices, so an empty reference skeleton here
        // means geometry-with-no-joints — reject before building anything.
        if data.skeleton.bones.is_empty() {
            return Err(crate::PaksmithError::UnsupportedFeature {
                context: "skeletal mesh has vertex geometry but an empty reference \
                          skeleton (no joints to skin to)"
                    .to_string(),
            });
        }

        let mut doc = GltfDoc::new();
        build_materials(&mut doc, data)?;
        let skel = build_skeleton(&mut doc, &data.skeleton)?;

        let mut scene_nodes = Vec::with_capacity(data.lods.len());
        for (i, lod) in data.lods.iter().enumerate() {
            if lod.positions.is_empty() {
                continue;
            }
            let prims = push_skinned_primitives(&mut doc, lod, data)?;
            // A LOD whose every section is empty/degenerate produces no
            // primitives; a glTF mesh requires `primitives.len() ≥ 1`, so skip
            // the node/mesh entirely. `push_skinned_primitives` builds no
            // accessor when it returns empty (mirroring static_mesh), so no
            // orphaned accessor is left behind.
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
            // IDENTITY-transformed mesh node carrying the shared skin. glTF
            // skinning folds in `inverse(meshNodeGlobal)`; a non-identity mesh
            // node would break the bind pose, so no matrix/TRS is set.
            let node = doc.root.push(gltf::json::Node {
                mesh: Some(mesh),
                skin: Some(skel.skin),
                name: Some(format!("LOD{i}")),
                ..gltf::json::Node::default()
            });
            scene_nodes.push(node);
        }
        // The skeleton roots must also be reachable from the scene so the skin's
        // joint hierarchy is part of the rendered graph.
        scene_nodes.extend(skel.root_nodes.iter().copied());

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
/// slot, sized to `max(section.material_index) + 1` across every LOD (mirroring
/// the static-mesh handler). Slot names are placeholders (`Material_<i>`);
/// resolving real slot names from `data.materials` is deferred. `material_index`
/// is unchecked `i32` wire data, so the maximum is folded as a non-negative
/// `u32` and compared against [`MAX_MESH_MATERIALS`] before any allocation.
fn build_materials(doc: &mut GltfDoc, data: &SkeletalMeshData) -> crate::Result<()> {
    let Some(max_ref) = data
        .lods
        .iter()
        .flat_map(|l| &l.sections)
        .map(|s| s.material_index.max(0))
        .max()
    else {
        return Ok(()); // no sections → zero materials
    };
    // `max_ref ≥ 0` (each term went through `.max(0)`), so `try_from` cannot
    // fail; the fallback avoids a bare `as` sign-loss cast.
    let max_ref = u32::try_from(max_ref).unwrap_or(u32::MAX);
    if max_ref >= MAX_MESH_MATERIALS {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "skeletal mesh references material slot {max_ref} exceeding the \
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

/// Build one [`Primitive`] per surviving section for `lod`, sharing the LOD's
/// vertex + skin accessors. Mirrors `static_mesh::push_primitives`: resolve every
/// section's index span FIRST, and only when at least one section survives push
/// the shared geometry + skin accessors (so a fully-degenerate LOD leaves no
/// orphaned accessor for gltf-validator to flag).
///
/// The per-LOD JOINTS_0/WEIGHTS_0 (+ _1) accessors come from
/// [`build_skin_attributes`] and are shared across the LOD's primitives.
///
/// # Errors
/// Propagates [`build_skin_attributes`] errors (short/invalid skin buffers).
fn push_skinned_primitives(
    doc: &mut GltfDoc,
    lod: &SkeletalMeshLod,
    data: &SkeletalMeshData,
) -> crate::Result<Vec<Primitive>> {
    if lod.positions.is_empty() {
        return Ok(Vec::new());
    }

    // Resolve each section's winding-reversed index buffer FIRST. A section whose
    // resolved span is empty / sub-triangle is dropped here; if every section is
    // skipped, push no accessors at all.
    let sections: Vec<(i32, Vec<u32>)> = lod
        .sections
        .iter()
        .filter_map(|s| resolve_section_indices(lod, s).map(|idx| (s.material_index, idx)))
        .collect();
    if sections.is_empty() {
        return Ok(Vec::new());
    }

    // Skin attributes are computed before pushing any accessor so a skin-buffer
    // error short-circuits without leaving a half-built document.
    let skin = build_skin_attributes(lod, &data.skeleton)?;
    let use_short = data.skeleton.bones.len() > 256;

    // Shared geometry accessors (built once per LOD; cloned into each
    // primitive). The skin attributes are layered onto the returned map below.
    let mut attributes = gltf_common::push_geometry_attributes(
        doc,
        &lod.positions,
        &lod.normals,
        &lod.tangents,
        &lod.uvs,
        lod.colors.as_deref(),
    );

    // JOINTS_0/WEIGHTS_0 (always) + JOINTS_1/WEIGHTS_1 (when influences > 4). The
    // weight accessor type follows the LOD precision: UNSIGNED_BYTE (U8) or
    // UNSIGNED_SHORT (U16, UE5 IncreasedSkinWeightPrecision). `joints1` and the
    // slot-1 weights are `Some` in lockstep.
    let _ = attributes.insert(
        Valid(Semantic::Joints(0)),
        push_joints(doc, &skin.joints0, use_short),
    );
    if let Some(j1) = skin.joints1.as_ref() {
        let _ = attributes.insert(Valid(Semantic::Joints(1)), push_joints(doc, j1, use_short));
    }
    match &skin.weights {
        SkinWeightAttr::U8 { w0, w1 } => {
            let _ = attributes.insert(Valid(Semantic::Weights(0)), push_weights(doc, w0));
            if let Some(w1) = w1 {
                let _ = attributes.insert(Valid(Semantic::Weights(1)), push_weights(doc, w1));
            }
        }
        SkinWeightAttr::U16 { w0, w1 } => {
            let _ = attributes.insert(Valid(Semantic::Weights(0)), push_weights_u16(doc, w0));
            if let Some(w1) = w1 {
                let _ = attributes.insert(Valid(Semantic::Weights(1)), push_weights_u16(doc, w1));
            }
        }
    }

    let mut prims = Vec::with_capacity(sections.len());
    for (material_index, section_indices) in sections {
        let idx = gltf_common::push_indices(doc, &section_indices);
        // `.max(0)` guarantees the cast operand is non-negative (sign-loss lint
        // cannot apply); a negative slot is remapped to 0.
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
    Ok(prims)
}

/// Resolve one skeletal section's index sub-range into a winding-reversed
/// `Vec<u32>`, or `None` when the section contributes no whole triangle. The span
/// is `[base_index, base_index + 3·num_triangles)`, clamped + triangle-floored by
/// the shared [`gltf_common::section_index_span`].
fn resolve_section_indices(
    lod: &SkeletalMeshLod,
    s: &crate::asset::SkelMeshSection,
) -> Option<Vec<u32>> {
    let (first, tri_len) =
        gltf_common::section_index_span(s.base_index, s.num_triangles, lod.indices.len());
    if tri_len == 0 {
        return None;
    }
    Some(reverse_winding(lod.indices.get(first..first + tri_len)?))
}

/// `true` when a [`projected_bin_bytes`] estimate exceeds the
/// [`MAX_GLB_BIN_BYTES`] aggregate-output cap. Pure predicate so the boundary is
/// unit-testable without allocating a cap-sized mesh.
fn exceeds_export_cap(projected: u64) -> bool {
    projected > MAX_GLB_BIN_BYTES
}

/// Reject a mesh whose projected glTF BIN buffer exceeds [`MAX_GLB_BIN_BYTES`]
/// BEFORE any lowering allocates.
fn enforce_export_cap(data: &SkeletalMeshData) -> crate::Result<()> {
    let projected = projected_bin_bytes(data);
    if exceeds_export_cap(projected) {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "skeletal mesh projected glTF buffer ({projected} bytes) exceeds the \
                 {MAX_GLB_BIN_BYTES}-byte export cap"
            ),
        });
    }
    Ok(())
}

/// Sum the BIN bytes [`GltfSkeletalMeshHandler::export`] WOULD allocate, WITHOUT
/// allocating them — a pure pre-flight projection for the [`MAX_GLB_BIN_BYTES`]
/// aggregate-output cap. All arithmetic saturates (`u64`) because every count is
/// attacker-controlled wire data.
///
/// Per LOD: the geometry attributes (positions ×12, normals ×12, tangents ×16,
/// each present UV channel ×8, colors ×4) PLUS the skin attributes — conservatively
/// counting BOTH influence sets as present: `joints0`+`joints1` (each VEC4 ×2,
/// the `u16` upper bound) + `weights0`+`weights1` (each VEC4 ×2, the `u16`
/// `IncreasedSkinWeightPrecision` upper bound) per vertex — plus,
/// per section, the floored triangle span × 4 (a `UNSIGNED_INT` upper bound). The
/// projection runs before [`build_skin_attributes`], so assuming slot1 present
/// keeps the estimate a safe over-bound.
///
/// The per-skeleton inverse-bind-matrices accessor (`bone_count × 64` bytes,
/// MAT4 f32) is NOT included in this sum, but it is bounded by
/// [`MAX_BONES_PER_SKELETON`] `× 64 ≈ 4 MiB` — well within the
/// [`MAX_GLB_BIN_BYTES`] (1 GiB) cap — so omitting it does not weaken the guard.
fn projected_bin_bytes(data: &SkeletalMeshData) -> u64 {
    let mut total: u64 = 0;
    for lod in &data.lods {
        let verts = lod.positions.len() as u64;
        total = total.saturating_add(verts.saturating_mul(12)); // positions VEC3 f32
        total = total.saturating_add((lod.normals.len() as u64).saturating_mul(12));
        total = total.saturating_add((lod.tangents.len() as u64).saturating_mul(16));
        for channel in lod.uvs.iter().flatten() {
            total = total.saturating_add((channel.len() as u64).saturating_mul(8));
        }
        if let Some(colors) = lod.colors.as_ref() {
            total = total.saturating_add((colors.len() as u64).saturating_mul(4));
        }
        // Skin: JOINTS_0 + JOINTS_1 (VEC4 ×2 each, u16 upper bound) + WEIGHTS_0 +
        // WEIGHTS_1 (VEC4 ×2 each, the u16 `IncreasedSkinWeightPrecision` upper
        // bound — over-bounds the u8 layout, keeping the guard conservative).
        // 8 + 8 (joints) + 8 + 8 (weights) = 32/vert.
        total = total.saturating_add(verts.saturating_mul(32));
        for s in &lod.sections {
            let (_first, tri_len) =
                gltf_common::section_index_span(s.base_index, s.num_triangles, lod.indices.len());
            total = total.saturating_add((tri_len as u64).saturating_mul(4));
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::structs::quat::FQuat;
    use crate::asset::structs::vector::FVector;
    use crate::asset::{BoneInfo, ReferenceSkeleton, SkelMeshSection, SkeletalMeshLod};

    /// Extract the `U8` `WEIGHTS_0` / `WEIGHTS_1` from a `SkinAttrs` (the
    /// `build_skin_attributes` tests all use 8-bit weights; the 16-bit path is
    /// covered by an end-to-end glTF test).
    fn w0(attrs: &SkinAttrs) -> &Vec<[u8; 4]> {
        match &attrs.weights {
            SkinWeightAttr::U8 { w0, .. } => w0,
            SkinWeightAttr::U16 { .. } => panic!("expected U8 weights"),
        }
    }
    fn w1(attrs: &SkinAttrs) -> Option<&Vec<[u8; 4]>> {
        match &attrs.weights {
            SkinWeightAttr::U8 { w1, .. } => w1.as_ref(),
            SkinWeightAttr::U16 { .. } => panic!("expected U8 weights"),
        }
    }

    /// A non-identity bind transform parameterized by `seed` so each bone in a
    /// test skeleton is distinct.
    fn sample_transform(seed: f64) -> FTransform {
        let q = DQuat::from_axis_angle(
            DVec3::new(1.0, 2.0, 3.0).normalize(),
            (20.0 + seed * 7.0f64).to_radians(),
        );
        FTransform {
            rotation: FQuat {
                x: q.x,
                y: q.y,
                z: q.z,
                w: q.w,
            },
            translation: FVector {
                x: seed,
                y: seed * 2.0,
                z: seed * 3.0,
            },
            scale_3d: FVector {
                x: 1.0 + seed * 0.1,
                y: 1.0,
                z: 1.0,
            },
        }
    }

    fn bone(name: &str, parent: i32) -> BoneInfo {
        BoneInfo {
            name: name.to_string(),
            parent_index: parent,
        }
    }

    #[test]
    fn builds_one_node_per_bone_with_skin() {
        // root(-1) -> child(0) -> grandchild(1).
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("root", -1), bone("child", 0), bone("grandchild", 1)],
            bind_pose: vec![
                sample_transform(1.0),
                sample_transform(2.0),
                sample_transform(3.0),
            ],
        };
        let mut doc = GltfDoc::new();
        let out = build_skeleton(&mut doc, &skeleton).expect("build_skeleton");
        let (root, _bin) = doc.into_parts();

        assert!(root.nodes.len() >= 3);
        let n0 = out.joints[0].value();
        let n1 = out.joints[1].value();
        let n2 = out.joints[2].value();

        assert!(
            root.nodes[n0]
                .children
                .as_ref()
                .expect("root has children")
                .contains(&out.joints[1])
        );
        assert!(
            root.nodes[n1]
                .children
                .as_ref()
                .expect("child has children")
                .contains(&out.joints[2])
        );
        assert!(
            root.nodes[n2]
                .children
                .as_ref()
                .is_none_or(std::vec::Vec::is_empty),
            "leaf bone has no children"
        );

        assert_eq!(root.skins.len(), 1);
        let skin = &root.skins[out.skin.value()];
        assert_eq!(skin.joints.len(), 3);
        let ibm = skin
            .inverse_bind_matrices
            .expect("skin has inverse-bind-matrices");
        assert_eq!(root.accessors[ibm.value()].count.0, 3);

        assert_eq!(out.root_nodes, vec![out.joints[0]]);
    }

    /// Build an `FTransform` from explicit glam scale/rotation/translation, so
    /// the gating test can hand-pick rich (non-axis rotation + non-uniform scale
    /// + translation) bind poses.
    fn ftransform(scale: DVec3, rot: DQuat, translation: DVec3) -> FTransform {
        FTransform {
            rotation: FQuat {
                x: rot.x,
                y: rot.y,
                z: rot.z,
                w: rot.w,
            },
            translation: FVector {
                x: translation.x,
                y: translation.y,
                z: translation.z,
            },
            scale_3d: FVector {
                x: scale.x,
                y: scale.y,
                z: scale.z,
            },
        }
    }

    /// Read a node's EMITTED column-major `[f32; 16]` matrix back into a `DMat4`.
    fn emitted_node_matrix(root: &gltf::json::Root, idx: usize) -> DMat4 {
        let m = root.nodes[idx].matrix.expect("node has a matrix");
        DMat4::from_cols_array(&m.map(f64::from))
    }

    /// End-to-end numerical proof: with the REAL inverse-bind-matrices, every
    /// joint's global bind transform composed from the EMITTED node matrices
    /// cancels its IBM to identity, and a 100%-weighted vertex stays at rest.
    /// Uses rich bind poses (non-axis rotation + non-uniform scale + non-zero
    /// translation) so a transposed rotation or wrong basis column would fail.
    #[test]
    fn bind_pose_skins_to_identity() {
        // root(-1) -> child(0) -> grandchild(1), each with a distinct, rich pose.
        let root_t = ftransform(
            DVec3::new(1.3, 0.7, 1.1),
            DQuat::from_axis_angle(DVec3::new(0.0, 1.0, 0.5).normalize(), 25f64.to_radians()),
            DVec3::new(-2.0, 4.0, 1.0),
        );
        // The marquee bone: non-axis rotation AND non-uniform scale AND non-zero
        // translation, exactly per the task spec.
        let child_t = ftransform(
            DVec3::new(2.0, 0.5, 1.5),
            DQuat::from_axis_angle(DVec3::new(1.0, 1.0, 0.0).normalize(), 37f64.to_radians()),
            DVec3::new(10.0, -5.0, 3.0),
        );
        let grandchild_t = ftransform(
            DVec3::new(0.6, 1.4, 0.9),
            DQuat::from_axis_angle(DVec3::new(2.0, -1.0, 1.0).normalize(), 52f64.to_radians()),
            DVec3::new(1.5, 2.5, -3.5),
        );
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("root", -1), bone("child", 0), bone("grandchild", 1)],
            bind_pose: vec![root_t, child_t, grandchild_t],
        };

        let mut doc = GltfDoc::new();
        let out = build_skeleton(&mut doc, &skeleton).expect("build_skeleton");
        let joint_indices: Vec<usize> = out.joints.iter().map(gltf::json::Index::value).collect();
        let (root, _bin) = doc.into_parts();

        // jointGlobal[j] = product of EMITTED node-local matrices along the
        // parent chain (parent-on-left): G0 = M0, G1 = M0·M1, G2 = M0·M1·M2.
        let m: Vec<DMat4> = joint_indices
            .iter()
            .map(|&idx| emitted_node_matrix(&root, idx))
            .collect();
        let joint_global = [m[0], m[0] * m[1], m[0] * m[1] * m[2]];

        let ibms = inverse_bind_matrices(&skeleton);
        let ibm: Vec<DMat4> = ibms
            .iter()
            .map(|cols| DMat4::from_cols_array(&cols.map(f64::from)))
            .collect();

        // Assert 1: jointGlobal[j] · IBM[j] ≈ I, per element.
        let identity = DMat4::IDENTITY.to_cols_array();
        for (j, jg) in joint_global.iter().enumerate() {
            let prod = (*jg * ibm[j]).to_cols_array();
            for (k, (got, want)) in prod.iter().zip(identity.iter()).enumerate() {
                assert!(
                    (got - want).abs() < 1e-4,
                    "bone {j}: jointGlobal·IBM element {k} = {got}, expected {want}"
                );
            }
        }

        // Assert 2: a vertex weighted 100% to bone k, emitted into glTF space via
        // B, stays at rest under jointGlobal[k] · IBM[k].
        let b = ue_to_gltf_basis();
        for v_ue in [
            DVec3::new(12.0, -7.0, 4.0),
            DVec3::new(-30.0, 18.0, 22.0),
            DVec3::new(1.0, 2.0, 3.0),
        ] {
            let emitted = b.transform_point3(v_ue);
            for k in 0..3 {
                let rest = (joint_global[k] * ibm[k]).transform_point3(emitted);
                let diff = rest - emitted;
                assert!(
                    diff.length() < 1e-4,
                    "bone {k}: vertex {v_ue:?} (emitted {emitted:?}) drifted to {rest:?}"
                );
            }
        }
    }

    /// A zero quaternion `(0,0,0,0)` normalizes to NaN, producing a non-finite
    /// EMITTED node matrix. `build_skeleton` must return `Err` (NOT panic, NOT
    /// emit a `null`-laden matrix). Exercises the node-matrix finiteness site.
    #[test]
    fn zero_quaternion_bone_is_rejected() {
        let degenerate = FTransform {
            rotation: FQuat {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 0.0,
            },
            translation: FVector {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            scale_3d: FVector {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
        };
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("only", -1)],
            bind_pose: vec![degenerate],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// A zero scale `(0,0,0)` gives a singular linear part whose `.inverse()` is
    /// non-finite, so the IBM (not the node matrix) goes non-finite. Exercises
    /// the inverse-bind-matrix finiteness site (input is otherwise finite).
    #[test]
    fn zero_scale_bone_is_rejected() {
        let degenerate = FTransform {
            rotation: FQuat {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            translation: FVector {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            scale_3d: FVector {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
        };
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("only", -1)],
            bind_pose: vec![degenerate],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// A non-finite translation (`+∞`) produces a non-finite emitted matrix and
    /// is rejected with `UnsupportedFeature`.
    #[test]
    fn non_finite_translation_rejected() {
        let degenerate = FTransform {
            rotation: FQuat {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            translation: FVector {
                x: f64::INFINITY,
                y: 0.0,
                z: 0.0,
            },
            scale_3d: FVector {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
        };
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("only", -1)],
            bind_pose: vec![degenerate],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// End-to-end: a degenerate (zero-scale) bone routed through `export` returns
    /// `Err` — no GLB with a `null`-laden matrix is ever produced.
    #[test]
    fn export_rejects_degenerate_bind_pose() {
        let mut data = skinned_triangle_data();
        // Collapse bone 1's scale to zero → singular IBM.
        data.skeleton.bind_pose[1].scale_3d = FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("degenerate bind pose must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// `matrix_all_finite` is `true` for a finite matrix and `false` once any
    /// single element is non-finite. Pins the helper directly (a `→ true` mutant
    /// would let `null`-laden matrices through).
    #[test]
    fn matrix_all_finite_detects_non_finite_element() {
        let finite = [0.0f32; 16];
        assert!(matrix_all_finite(&finite));
        let mut nan = finite;
        nan[7] = f32::NAN;
        assert!(!matrix_all_finite(&nan), "NaN element rejected");
        let mut inf = finite;
        inf[15] = f32::INFINITY;
        assert!(!matrix_all_finite(&inf), "Inf element rejected");
    }

    #[test]
    fn rejects_bind_pose_length_mismatch() {
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("root", -1), bone("child", 0)],
            bind_pose: vec![sample_transform(1.0)],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn rejects_forward_parent_index() {
        // Bone 0's parent is bone 1, which has not been defined yet (forward ref).
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("a", 1), bone("b", -1)],
            bind_pose: vec![sample_transform(1.0), sample_transform(2.0)],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn node_matrix_is_basis_conjugation() {
        let t = sample_transform(5.0);
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("only", -1)],
            bind_pose: vec![t],
        };
        let mut doc = GltfDoc::new();
        let out = build_skeleton(&mut doc, &skeleton).expect("build_skeleton");
        let (root, _bin) = doc.into_parts();

        let b = ue_to_gltf_basis();
        let want = (b * ftransform_to_dmat4(&t) * b.inverse()).to_cols_array();
        let got = root.nodes[out.joints[0].value()]
            .matrix
            .expect("node has a matrix");
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert!(
                (f64::from(*g) - w).abs() < 1e-4,
                "matrix element {i}: got {g}, want {w}"
            );
        }
    }

    /// The anti-drift guard against [`super::super::gltf_common::convert_position`]:
    /// `B · (x,y,z)` must equal `(0.01x, 0.01z, 0.01y)` for arbitrary points.
    /// A wrong column would silently rotate the whole skeleton while still
    /// passing shape-only tests, so this is the load-bearing check.
    #[test]
    fn basis_matches_convert_position() {
        let b = ue_to_gltf_basis();
        for (x, y, z) in [(3.0, 5.0, 7.0), (-1.0, 2.0, -4.0), (0.0, 0.0, 0.0)] {
            let got = b.transform_point3(DVec3::new(x, y, z));
            let want = DVec3::new(x * 0.01, z * 0.01, y * 0.01);
            assert!(
                (got.x - want.x).abs() < 1e-12
                    && (got.y - want.y).abs() < 1e-12
                    && (got.z - want.z).abs() < 1e-12,
                "basis drift at ({x}, {y}, {z}): got {got:?}, want {want:?}"
            );
        }
    }

    /// `B · B⁻¹ ≈ I` — the basis is invertible (no degenerate column).
    #[test]
    fn basis_inverse_round_trips() {
        let b = ue_to_gltf_basis();
        let id = b * b.inverse();
        let id_cols = id.to_cols_array();
        let expected = DMat4::IDENTITY.to_cols_array();
        for (i, (got, want)) in id_cols.iter().zip(expected.iter()).enumerate() {
            assert!(
                (got - want).abs() < 1e-12,
                "B·B⁻¹ element {i} = {got}, expected {want}"
            );
        }
    }

    /// `ftransform_to_dmat4` composes scale→rotate→translate (glam's
    /// `from_scale_rotation_translation` order). Expected is computed
    /// independently via `rot * (scale * p) + translation` — NOT via a
    /// second `from_scale_rotation_translation`, so the test isn't circular.
    #[test]
    fn ftransform_to_dmat4_applies_srt() {
        // Non-axis-aligned rotation: 37° about normalized (1,1,0).
        let q = DQuat::from_axis_angle(DVec3::new(1.0, 1.0, 0.0).normalize(), 37f64.to_radians());
        let t = FTransform {
            rotation: FQuat {
                x: q.x,
                y: q.y,
                z: q.z,
                w: q.w,
            },
            translation: FVector {
                x: 10.0,
                y: 20.0,
                z: 30.0,
            },
            scale_3d: FVector {
                x: 2.0,
                y: 0.5,
                z: 1.5,
            },
        };
        let m = ftransform_to_dmat4(&t);

        let scale = DVec3::new(2.0, 0.5, 1.5);
        let translation = DVec3::new(10.0, 20.0, 30.0);
        for p in [
            DVec3::new(1.0, 0.0, 0.0),
            DVec3::new(0.0, 1.0, 0.0),
            DVec3::new(-3.0, 4.0, 5.0),
        ] {
            let got = m.transform_point3(p);
            // Independent SRT: scale component-wise, rotate, then translate.
            let want = q * (scale * p) + translation;
            assert!(
                (got - want).length() < 1e-9,
                "SRT mismatch at {p:?}: got {got:?}, want {want:?}"
            );
        }
    }

    // ---- build_skin_attributes ------------------------------------------

    /// A skeleton with `n` distinct root bones — enough that global indices up
    /// to `n - 1` are in-bounds (so the remap test isn't accidentally on the
    /// OOB path).
    fn skeleton_with_n_bones(n: usize) -> ReferenceSkeleton {
        ReferenceSkeleton {
            bones: (0..n).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..n)
                .map(|i| sample_transform(f64::from(u16::try_from(i).unwrap_or(0))))
                .collect(),
        }
    }

    /// `num_vertices` distinct positions (values are irrelevant to skinning).
    fn positions(num_vertices: usize) -> Vec<FVector> {
        (0..num_vertices)
            .map(|i| FVector {
                x: f64::from(u16::try_from(i).unwrap_or(0)),
                y: 0.0,
                z: 0.0,
            })
            .collect()
    }

    fn section(base: u32, num: i32, bone_map: Vec<u16>) -> SkelMeshSection {
        SkelMeshSection {
            base_vertex_index: base,
            num_vertices: num,
            bone_map,
            ..SkelMeshSection::default()
        }
    }

    #[test]
    fn remaps_via_owning_section_bone_map() {
        // section0 covers verts 0..2 (bone_map [5,6]); section1 covers 2..4
        // (bone_map [9,8]). A section1 vertex with local index 0 must map to
        // global 9, NOT section0's 5.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 2, vec![5, 6]), section(2, 2, vec![9, 8])],
            positions: positions(4),
            bone_indices: vec![[0u16; 8]; 4],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 4]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(10);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        assert_eq!(attrs.joints0[0][0], 5, "section0 vert local 0 -> global 5");
        assert_eq!(attrs.joints0[2][0], 9, "section1 vert local 0 -> global 9");
        assert_eq!(attrs.joints0[3][0], 9, "section1 vert local 0 -> global 9");
    }

    #[test]
    fn renormalizes_weights_to_255() {
        // vert0: 200 + 54 = 254 (under); vert1: 200 + 56 = 256 (over).
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 2, vec![0, 1])],
            positions: positions(2),
            bone_indices: vec![[0, 1, 0, 0, 0, 0, 0, 0]; 2],
            bone_weights: BoneWeights::U8(vec![
                [200, 54, 0, 0, 0, 0, 0, 0],
                [200, 56, 0, 0, 0, 0, 0, 0],
            ]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        let sum0: u32 = w0(&attrs)[0].iter().map(|&w| u32::from(w)).sum();
        let sum1: u32 = w0(&attrs)[1].iter().map(|&w| u32::from(w)).sum();
        assert_eq!(sum0, 255, "254 -> renormalized to 255");
        assert_eq!(sum1, 255, "256 -> renormalized to 255");
    }

    #[test]
    fn renormalize_folds_into_max_slot_not_slot0() {
        // Max weight is slot 1 (200 > 54). The +1 residual must land there,
        // pinning "fold into max slot" against a "fold into slot 0" mutant.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0, 1])],
            positions: positions(1),
            bone_indices: vec![[0, 1, 0, 0, 0, 0, 0, 0]],
            bone_weights: BoneWeights::U8(vec![[54, 200, 0, 0, 0, 0, 0, 0]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        assert_eq!(w0(&attrs)[0][0], 54, "slot 0 unchanged");
        assert_eq!(w0(&attrs)[0][1], 201, "residual folded into max slot 1");
    }

    /// UE5 16-bit weights (`BoneWeights::U16`) build the `U16` attribute,
    /// renormalized to `65535` (not `255`) — the lossless path. The same
    /// proportional rescale + residual fold runs; only the target sum and the
    /// component type differ.
    #[test]
    fn build_skin_attributes_u16_renormalizes_to_65535_and_tags_u16() {
        // Raw weights 30000 + 20000 = 50000 (under 65535) → renormalize to 65535.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0, 1])],
            positions: positions(1),
            bone_indices: vec![[0, 1, 0, 0, 0, 0, 0, 0]],
            bone_weights: BoneWeights::U16(vec![[30000, 20000, 0, 0, 0, 0, 0, 0]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        match &attrs.weights {
            SkinWeightAttr::U16 { w0, w1 } => {
                assert!(w1.is_none(), "≤4 influences → no slot1");
                let sum: u32 = w0[0].iter().map(|&w| u32::from(w)).sum();
                assert_eq!(sum, 65535, "16-bit weights renormalized to 65535");
                // Exact proportional rescale (NOT a zero-sum root rebind, which
                // would give 65535/0): 30000·65535/50000 = 39321,
                // 20000·65535/50000 = 26214 (sum 65535, no residual).
                assert_eq!(w0[0][0], 39321, "slot 0 keeps its 30000/50000 share");
                assert_eq!(w0[0][1], 26214, "slot 1 keeps its 20000/50000 share");
            }
            SkinWeightAttr::U8 { .. } => panic!("expected U16 weights for a BoneWeights::U16 LOD"),
        }
        // Joints are precision-independent: local 0 → section bone_map[0] = 0.
        assert_eq!(attrs.joints0[0][0], 0);
    }

    /// All eight slots at the max byte (raw sum 2040 ≫ 255): the old
    /// fold-into-one-slot algorithm clipped to 0 and the `debug_assert` PANICKED
    /// on this attacker input. The proportional rescale must NOT panic and the
    /// emitted weights must sum to exactly 255, each ≈ 32 (255/8).
    #[test]
    fn renormalize_all_max_weights_no_panic() {
        let mut joints = [0u16; 8];
        let mut weights = [255u8; 8];
        renormalize_vertex(&mut joints, &mut weights);
        let sum: u32 = weights.iter().map(|&w| u32::from(w)).sum();
        assert_eq!(sum, 255, "[255;8] must renormalize to a sum of 255");
        // 255/8 = 31.875 → each slot rounds to 32; the residual fold adjusts one
        // slot by at most a few. Every slot is within ±4 of 32.
        for &w in &weights {
            assert!(
                (28..=36).contains(&w),
                "each of eight equal max influences ≈ 32, got {w}"
            );
        }
    }

    /// Eight equal moderate influences summing to 320 (over 255): proportional
    /// rescale to a sum of 255 with no panic.
    #[test]
    fn renormalize_moderate_oversum() {
        let mut joints = [0u16; 8];
        let mut weights = [40u8; 8]; // sum 320
        renormalize_vertex(&mut joints, &mut weights);
        let sum: u32 = weights.iter().map(|&w| u32::from(w)).sum();
        assert_eq!(sum, 255, "[40;8] (sum 320) must renormalize to 255");
    }

    /// A raw sum BELOW 255 is scaled UP to exactly 255 (not merely topped up in
    /// one slot — the proportional rescale grows every nonzero slot).
    #[test]
    fn renormalize_undersum_still_255() {
        let mut joints = [0u16; 8];
        let mut weights = [10u8, 20, 0, 0, 0, 0, 0, 0]; // sum 30
        renormalize_vertex(&mut joints, &mut weights);
        let sum: u32 = weights.iter().map(|&w| u32::from(w)).sum();
        assert_eq!(sum, 255, "[10,20,..] (sum 30) must renormalize to 255");
        // Proportional: 10/30 → ~85, 20/30 → ~170, ratio preserved (~1:2).
        assert!(
            weights[1] > weights[0],
            "the larger raw weight stays larger"
        );
        assert_eq!(weights[2..].iter().sum::<u8>(), 0, "zero slots stay zero");
    }

    /// Pins the round-to-nearest term (`+ sum/2`) in the proportional rescale.
    /// `[1, 1, 0…]` (sum 2): each slot rescales to `(255 + 1) / 2 = 128`
    /// (rounded), summing to 256; the −1 residual folds into the LAST max slot
    /// (slot 1, `max_by_key` returns the last tie) → `[128, 127]`. WITHOUT the
    /// rounding term each slot would be `255 / 2 = 127`, summing to 254, and the
    /// +1 residual would land in slot 1 → `[127, 128]` — the mirror image. The
    /// exact `[128, 127]` assertion kills a `+ sum/2` deletion mutant.
    #[test]
    fn renormalize_rounds_to_nearest() {
        let mut joints = [0u16; 8];
        let mut weights = [1u8, 1, 0, 0, 0, 0, 0, 0]; // sum 2
        renormalize_vertex(&mut joints, &mut weights);
        assert_eq!(
            &weights[..2],
            &[128, 127],
            "round-to-nearest puts 128 in slot 0, residual into the last max (slot 1)"
        );
        assert_eq!(weights.iter().map(|&w| u32::from(w)).sum::<u32>(), 255);
    }

    /// The whole `build_skin_attributes` path with an over-sum vertex must not
    /// panic in debug and must emit a sum-255 weight set (end-to-end pin for the
    /// renorm fix through the public builder).
    #[test]
    fn build_skin_attributes_oversum_vertex_no_panic() {
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0, 1, 2, 3, 0, 1, 2, 3])],
            positions: positions(1),
            bone_indices: vec![[0, 1, 2, 3, 0, 1, 2, 3]],
            bone_weights: BoneWeights::U8(vec![[255u8; 8]]), // raw sum 2040
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");
        let total: u32 = w0(&attrs)[0]
            .iter()
            .chain(w1(&attrs).expect("slot1")[0].iter())
            .map(|&w| u32::from(w))
            .sum();
        assert_eq!(total, 255, "8×255 raw weights renormalized to 255");
    }

    #[test]
    fn weights_sum_zero_binds_root() {
        // A vertex a section claims but with all-zero weights -> root at rest.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![3])],
            positions: positions(1),
            bone_indices: vec![[0u16; 8]],
            bone_weights: BoneWeights::U8(vec![[0u8; 8]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        assert_eq!(attrs.joints0[0], [0, 0, 0, 0]);
        assert_eq!(w0(&attrs)[0], [255, 0, 0, 0]);
    }

    #[test]
    fn vertex_outside_sections_defaults_root() {
        // 3 positions, a section covering only verts 0..1 -> vert 2 is uncovered.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![1])],
            positions: positions(3),
            bone_indices: vec![[0u16; 8]; 3],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 3]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        assert_eq!(attrs.joints0[2], [0, 0, 0, 0], "uncovered vertex -> root");
        assert_eq!(w0(&attrs)[2], [255, 0, 0, 0], "uncovered vertex -> rest");
    }

    #[test]
    fn influence_index_oob_errors() {
        // local index 5 but bone_map has only 1 entry.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0])],
            positions: positions(1),
            bone_indices: vec![[5, 0, 0, 0, 0, 0, 0, 0]],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        assert!(matches!(
            build_skin_attributes(&lod, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn bone_map_global_oob_errors() {
        // bone_map entry 9, but skeleton has only 4 bones.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![9])],
            positions: positions(1),
            bone_indices: vec![[0, 0, 0, 0, 0, 0, 0, 0]],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        assert!(matches!(
            build_skin_attributes(&lod, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn eight_influence_sets_slot1() {
        // All 8 influences nonzero -> joints1/weights1 populated.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0, 1, 2, 3, 4, 5, 6, 7])],
            positions: positions(1),
            bone_indices: vec![[0, 1, 2, 3, 4, 5, 6, 7]],
            bone_weights: BoneWeights::U8(vec![[40, 40, 40, 40, 30, 30, 20, 15]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(8);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        let joints1 = attrs.joints1.as_ref().expect("joints1 Some");
        let weights1 = w1(&attrs).expect("weights1 Some");
        assert_eq!(joints1[0], [4, 5, 6, 7], "slot1 joints remapped");
        assert!(
            weights1[0].iter().any(|&w| w != 0),
            "slot1 weights populated"
        );
        let total: u32 = w0(&attrs)[0]
            .iter()
            .chain(weights1[0].iter())
            .map(|&w| u32::from(w))
            .sum();
        assert_eq!(total, 255, "8-influence weights renormalized to 255");
    }

    #[test]
    fn four_influence_no_slot1() {
        // Only slots 0..4 used -> joints1/weights1 None.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 1, vec![0, 1, 2, 3])],
            positions: positions(1),
            bone_indices: vec![[0, 1, 2, 3, 0, 0, 0, 0]],
            bone_weights: BoneWeights::U8(vec![[64, 64, 64, 63, 0, 0, 0, 0]]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        let attrs = build_skin_attributes(&lod, &skeleton).expect("build_skin_attributes");

        assert!(attrs.joints1.is_none(), "no slot1 -> joints1 None");
        assert!(w1(&attrs).is_none(), "no slot1 -> weights1 None");
    }

    #[test]
    fn short_skin_buffers_error() {
        // bone_weights shorter than positions -> cannot skin.
        let lod = SkeletalMeshLod {
            sections: vec![section(0, 2, vec![0])],
            positions: positions(2),
            bone_indices: vec![[0u16; 8]; 2],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 1]),
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        assert!(matches!(
            build_skin_attributes(&lod, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    // ---- GltfSkeletalMeshHandler -----------------------------------------

    /// A draw-call section over a triangle list: `material_index`, `base_index`,
    /// `num_triangles`, plus the vertex range + bone_map the skin path needs.
    fn draw_section(
        material_index: i32,
        base_index: i32,
        num_triangles: i32,
        base_vertex_index: u32,
        num_vertices: i32,
        bone_map: Vec<u16>,
    ) -> SkelMeshSection {
        SkelMeshSection {
            material_index,
            base_index,
            num_triangles,
            base_vertex_index,
            num_vertices,
            bone_map,
            ..SkelMeshSection::default()
        }
    }

    /// A 5-bone skeleton (root + 4 children) with one LOD: a single skinned
    /// triangle (3 verts) in one section. Every vertex is 100%-weighted to its
    /// section-local bone 0 (→ global bone 1 via the bone_map `[1, 2, 3]`).
    fn skinned_triangle_data() -> SkeletalMeshData {
        let skeleton = ReferenceSkeleton {
            bones: vec![
                bone("root", -1),
                bone("b1", 0),
                bone("b2", 0),
                bone("b3", 1),
                bone("b4", 1),
            ],
            bind_pose: (0..5).map(|i| sample_transform(f64::from(i + 1))).collect(),
        };
        let lod = SkeletalMeshLod {
            sections: vec![draw_section(0, 0, 1, 0, 3, vec![1, 2, 3])],
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
            indices: vec![0, 1, 2],
            bone_indices: vec![[0u16; 8]; 3],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 3]),
            ..SkeletalMeshLod::default()
        };
        let mut data = SkeletalMeshData::empty();
        data.cooked = true;
        data.skeleton = skeleton;
        data.lods = vec![lod];
        data
    }

    #[test]
    fn extension_is_glb() {
        assert_eq!(GltfSkeletalMeshHandler.output_extension(), "glb");
    }

    #[test]
    fn registry_selects_skeletal_handler() {
        let reg = crate::export::HandlerRegistry::all_default_handlers();
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let handler = reg.find_handler(&asset).expect("a skeletal handler");
        assert_eq!(handler.output_extension(), "glb");

        // `supports`: false for an empty (no-LOD) mesh, true with a drawable LOD.
        assert!(!GltfSkeletalMeshHandler.supports(&Asset::SkeletalMesh(SkeletalMeshData::empty())));
        assert!(GltfSkeletalMeshHandler.supports(&asset));
    }

    #[test]
    fn exports_minimal_skinned_glb() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        assert_eq!(&bytes[0..4], b"glTF");
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("parse json");

        // Exactly one skin, 5 joints, inverseBindMatrices present.
        let skins = doc["skins"].as_array().expect("skins array");
        assert_eq!(skins.len(), 1);
        let joints = skins[0]["joints"].as_array().expect("joints array");
        assert_eq!(joints.len(), 5, "skin.joints matches the 5-bone skeleton");
        assert!(
            skins[0].get("inverseBindMatrices").is_some(),
            "skin carries inverseBindMatrices"
        );

        // The LOD mesh primitive carries POSITION + JOINTS_0 + WEIGHTS_0.
        let prim = &doc["meshes"][0]["primitives"][0];
        let attrs = prim["attributes"].as_object().expect("attributes object");
        assert!(attrs.contains_key("POSITION"), "POSITION present");
        assert!(attrs.contains_key("JOINTS_0"), "JOINTS_0 present");
        assert!(attrs.contains_key("WEIGHTS_0"), "WEIGHTS_0 present");

        // A scene exists.
        assert_eq!(doc["scenes"].as_array().expect("scenes").len(), 1);

        // The node carrying `mesh` has the skin set and NO matrix (identity).
        let nodes = doc["nodes"].as_array().expect("nodes array");
        let mesh_node = nodes
            .iter()
            .find(|n| n.get("mesh").is_some())
            .expect("a node with a mesh");
        assert!(
            mesh_node.get("skin").is_some(),
            "mesh node references a skin"
        );
        assert!(
            mesh_node.get("matrix").is_none(),
            "mesh node must be identity (no matrix)"
        );
    }

    #[test]
    fn mesh_node_is_identity() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let nodes = doc["nodes"].as_array().expect("nodes array");
        let mesh_node = nodes
            .iter()
            .find(|n| n.get("mesh").is_some())
            .expect("a node with a mesh");
        // No matrix and no TRS — a glTF identity node.
        assert!(mesh_node.get("matrix").is_none(), "no matrix");
        assert!(mesh_node.get("translation").is_none(), "no translation");
        assert!(mesh_node.get("rotation").is_none(), "no rotation");
        assert!(mesh_node.get("scale").is_none(), "no scale");
    }

    #[test]
    fn joints_component_type_byte_for_small_skeleton() {
        // ≤256 bones → JOINTS_0 accessor componentType UNSIGNED_BYTE (5121).
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let joints_acc = doc["meshes"][0]["primitives"][0]["attributes"]["JOINTS_0"]
            .as_u64()
            .expect("JOINTS_0 accessor index");
        let accessors = doc["accessors"].as_array().expect("accessors array");
        let ct = accessors[usize::try_from(joints_acc).expect("index fits usize")]["componentType"]
            .as_u64()
            .expect("componentType");
        assert_eq!(ct, 5121, "UNSIGNED_BYTE for a ≤256-bone skeleton");
    }

    /// A skeleton with >256 bones forces JOINTS_0 to UNSIGNED_SHORT (5123). Pins
    /// the `use_short = bones.len() > 256` boundary against a `>`→`>=` / `256`
    /// mutant (the small-skeleton test only proves the BYTE side).
    #[test]
    fn joints_component_type_short_for_large_skeleton() {
        let mut data = skinned_triangle_data();
        // 257 root bones (all parent -1, so still a valid hierarchy). The
        // section's bone_map references low indices, all < bone_count.
        data.skeleton = ReferenceSkeleton {
            bones: (0..257).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..257)
                .map(|i| sample_transform(f64::from(u16::try_from(i).unwrap_or(0))))
                .collect(),
        };
        let asset = Asset::SkeletalMesh(data);
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let joints_acc = doc["meshes"][0]["primitives"][0]["attributes"]["JOINTS_0"]
            .as_u64()
            .expect("JOINTS_0 accessor index");
        let accessors = doc["accessors"].as_array().expect("accessors array");
        let ct = accessors[usize::try_from(joints_acc).expect("index fits usize")]["componentType"]
            .as_u64()
            .expect("componentType");
        assert_eq!(ct, 5123, "UNSIGNED_SHORT for a >256-bone skeleton");
    }

    /// The `WEIGHTS_0` accessor componentType follows the LOD weight precision:
    /// `UNSIGNED_BYTE` (5121) for the common 8-bit layout, `UNSIGNED_SHORT` (5123)
    /// for UE5 `IncreasedSkinWeightPrecision` 16-bit weights — both `normalized`.
    /// End-to-end through `export`; pins both directions of the handler's
    /// `BoneWeights` precision match.
    #[test]
    fn weights_component_type_follows_precision() {
        fn weights0_accessor(bytes: &[u8]) -> serde_json::Value {
            let glb = gltf::Glb::from_slice(bytes).expect("glb");
            let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
            let w_acc = doc["meshes"][0]["primitives"][0]["attributes"]["WEIGHTS_0"]
                .as_u64()
                .expect("WEIGHTS_0 accessor index");
            doc["accessors"][usize::try_from(w_acc).expect("index fits usize")].clone()
        }

        // 8-bit (default skinned_triangle_data) → UNSIGNED_BYTE.
        let u8_bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(skinned_triangle_data()), &[])
            .expect("export u8");
        let u8_acc = weights0_accessor(&u8_bytes);
        assert_eq!(
            u8_acc["componentType"].as_u64(),
            Some(5121),
            "u8 weights → UNSIGNED_BYTE"
        );
        assert_eq!(u8_acc["normalized"].as_bool(), Some(true));

        // 16-bit (UE5 IncreasedSkinWeightPrecision) → UNSIGNED_SHORT.
        let mut data = skinned_triangle_data();
        data.lods[0].bone_weights = BoneWeights::U16(vec![[65535, 0, 0, 0, 0, 0, 0, 0]; 3]);
        let u16_bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("export u16");
        let u16_acc = weights0_accessor(&u16_bytes);
        assert_eq!(
            u16_acc["componentType"].as_u64(),
            Some(5123),
            "u16 weights → UNSIGNED_SHORT"
        );
        assert_eq!(u16_acc["normalized"].as_bool(), Some(true));
    }

    /// A vertex using more than four influences emits JOINTS_1 + WEIGHTS_1 on the
    /// primitive (handler-level slot1 wiring, beyond `build_skin_attributes`'s
    /// own unit coverage).
    #[test]
    fn primitive_emits_slot1_for_eight_influences() {
        let mut data = skinned_triangle_data();
        // 8 bones so the section bone_map [0..8) all resolve in-bounds.
        data.skeleton = ReferenceSkeleton {
            bones: (0..8).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..8).map(|i| sample_transform(f64::from(i + 1))).collect(),
        };
        let lod = &mut data.lods[0];
        lod.sections = vec![draw_section(0, 0, 1, 0, 3, vec![0, 1, 2, 3, 4, 5, 6, 7])];
        lod.bone_indices = vec![[0, 1, 2, 3, 4, 5, 6, 7]; 3];
        lod.bone_weights = BoneWeights::U8(vec![[40, 40, 40, 40, 30, 30, 20, 15]; 3]);

        let asset = Asset::SkeletalMesh(data);
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let attrs = doc["meshes"][0]["primitives"][0]["attributes"]
            .as_object()
            .expect("attributes object");
        assert!(
            attrs.contains_key("JOINTS_1"),
            "JOINTS_1 present for >4 influences"
        );
        assert!(
            attrs.contains_key("WEIGHTS_1"),
            "WEIGHTS_1 present for >4 influences"
        );
    }

    /// A four-influence-only mesh emits NO JOINTS_1/WEIGHTS_1 (the slot1
    /// attributes are conditional on `build_skin_attributes` returning `Some`).
    #[test]
    fn primitive_omits_slot1_for_four_influences() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data()); // 1 influence/vert
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let attrs = doc["meshes"][0]["primitives"][0]["attributes"]
            .as_object()
            .expect("attributes object");
        assert!(
            !attrs.contains_key("JOINTS_1"),
            "no JOINTS_1 for ≤4 influences"
        );
        assert!(
            !attrs.contains_key("WEIGHTS_1"),
            "no WEIGHTS_1 for ≤4 influences"
        );
    }

    // ---- caps + finiteness -----------------------------------------------

    /// `exceeds_export_cap` is `true` strictly ABOVE the cap: exactly-cap is
    /// accepted, one byte over is rejected. Pins the `> cap` boundary without a
    /// cap-sized allocation.
    #[test]
    fn exceeds_export_cap_is_strict_above_cap() {
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES - 1));
        assert!(!exceeds_export_cap(MAX_GLB_BIN_BYTES));
        assert!(exceeds_export_cap(MAX_GLB_BIN_BYTES + 1));
    }

    /// `projected_bin_bytes` sums the conservative strides the lowering bounds:
    /// positions ×12, normals ×12, tangents ×16, uv ×8, colors ×4, the 32/vert
    /// skin term (JOINTS_0+JOINTS_1 ×2 each + WEIGHTS_0+WEIGHTS_1 ×2 each, the u16
    /// upper bound), and the floored index span ×4. A mutant on any multiplier
    /// fails this equality.
    #[test]
    fn projected_bin_bytes_sums_vertex_skin_and_index_strides() {
        let mut data = skinned_triangle_data(); // 3 verts, 1 tri (3 indices)
        let lod = &mut data.lods[0];
        lod.normals = vec![
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            };
            3
        ];
        lod.tangents = vec![
            crate::asset::structs::vector::FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            };
            3
        ];
        lod.uvs[0] = Some(vec![
            crate::asset::structs::vector::FVector2D {
                x: 0.0,
                y: 0.0
            };
            3
        ]);
        lod.colors = Some(vec![
            crate::asset::structs::color::FColor {
                r: 0,
                g: 0,
                b: 0,
                a: 0,
            };
            3
        ]);
        // positions 3*12=36, normals 36, tangents 3*16=48, uv 3*8=24, colors
        // 3*4=12, skin 3*32=96 → verts 252. index span 3*4=12. Total 264.
        assert_eq!(projected_bin_bytes(&data), 264);
    }

    /// A mesh duplicating a small index buffer across many sections projects over
    /// the 1 GiB cap while allocating only KB of INPUT; the rejection is asserted
    /// at the PURE `enforce_export_cap` level so no multi-GiB GLB is ever built.
    #[test]
    fn oversized_mesh_via_section_duplication_is_rejected() {
        let mut data = skinned_triangle_data();
        let lod = &mut data.lods[0];
        lod.indices = vec![0u32; 30_000];
        lod.sections = (0..8_960)
            .map(|_| draw_section(0, 0, 10_000, 0, 3, vec![1]))
            .collect();
        assert!(
            projected_bin_bytes(&data) > MAX_GLB_BIN_BYTES,
            "test setup must project over the cap"
        );
        let err = enforce_export_cap(&data).expect_err("oversized projection must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// More than `MAX_SKELETAL_LODS_PER_MESH` LODs is rejected with
    /// `UnsupportedFeature` (no node/mesh explosion).
    #[test]
    fn too_many_lods_is_rejected() {
        let base = skinned_triangle_data();
        let mut data = base.clone();
        data.lods = (0..=MAX_SKELETAL_LODS_PER_MESH)
            .map(|_| base.lods[0].clone())
            .collect();
        assert!(data.lods.len() > MAX_SKELETAL_LODS_PER_MESH);
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("over-LOD-cap mesh must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A section referencing material slot `MAX_MESH_MATERIALS` (one past the
    /// last allowed slot) exceeds the cap and is rejected — no ~256-material+
    /// allocation.
    #[test]
    fn materials_over_cap_is_rejected() {
        let over_cap = i32::try_from(MAX_MESH_MATERIALS).expect("cap fits i32");
        let mut data = skinned_triangle_data();
        data.lods[0].sections[0].material_index = over_cap;
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("over-cap material slot must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// The last in-cap slot (`MAX_MESH_MATERIALS - 1`) still exports — pins the
    /// `>=` boundary so a `>=`→`>` mutant is caught alongside the over-cap test.
    #[test]
    fn materials_at_cap_boundary_is_accepted() {
        let last = i32::try_from(MAX_MESH_MATERIALS - 1).expect("cap fits i32");
        let mut data = skinned_triangle_data();
        data.lods[0].sections[0].material_index = last;
        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("last in-cap slot must export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(
            doc["materials"].as_array().expect("materials").len(),
            MAX_MESH_MATERIALS as usize
        );
    }

    /// A mesh with drawable geometry but an EMPTY reference skeleton is rejected
    /// with `UnsupportedFeature` — a zero-joint skin with JOINTS referencing
    /// joint 0 is invalid glTF. (An all-bulk-LOD mesh parses to
    /// `Asset::SkeletalMesh` with empty geometry; this guard covers the inverse
    /// hazard where geometry is present but the skeleton is empty.)
    #[test]
    fn empty_skeleton_with_geometry_is_rejected() {
        let mut data = skinned_triangle_data();
        data.skeleton = ReferenceSkeleton {
            bones: Vec::new(),
            bind_pose: Vec::new(),
        };
        assert!(
            data.lods.iter().any(|l| !l.positions.is_empty()),
            "the test mesh must have geometry"
        );
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("geometry + empty skeleton must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A mesh whose every LOD has empty positions (no drawable geometry) is
    /// rejected up front with `UnsupportedFeature`, before
    /// `build_skeleton`/`push_mat4(&[])` can emit a spec-invalid count:0 MAT4
    /// accessor + dangling bufferView. The skeleton is deliberately kept VALID
    /// (non-empty) so the no-drawable guard A is the SOLE Err source: flipping
    /// either `!` in `!data.lods.iter().any(|l| !l.positions.is_empty())` lets the
    /// all-empty mesh through to build a valid-skeleton/empty-scene glTF → export
    /// Ok → this test fails (mutant killed). With an empty skeleton, guard B would
    /// mask guard A's mutant, so the skeleton must stay populated here.
    #[test]
    fn no_drawable_lod_is_rejected() {
        let mut data = skinned_triangle_data(); // keeps the valid 5-bone skeleton
        // Strip ALL geometry from every LOD (positions empty) but leave the
        // skeleton intact so guard A is the only thing that can reject.
        for lod in &mut data.lods {
            *lod = SkeletalMeshLod::default(); // empty positions, no sections
        }
        assert!(
            !data.skeleton.bones.is_empty(),
            "skeleton must stay populated so guard A is the sole Err source"
        );
        assert!(
            !data.lods.iter().any(|l| !l.positions.is_empty()),
            "the test mesh must have NO drawable LOD"
        );
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("no-drawable mesh must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// Pins the no-drawable guard's `!l.positions.is_empty()` term against a
    /// `delete !` mutant. The mesh has an EMPTY skeleton AND a LOD with non-empty
    /// positions but ALL-ZERO bone weights: zero-sum vertices rebind to the root
    /// in `renormalize_vertex` WITHOUT a `bone_map` lookup, so `build_skin_*`
    /// would return Ok — making the guards the ONLY Err source. Real guards fire
    /// (geometry present → empty-skeleton guard B errors). A `delete !` on the
    /// no-drawable guard A's `!l.positions.is_empty()` would make the guard see no
    /// drawable LOD, return its own (still-Err) result — but a `delete !` on the
    /// empty-skeleton guard B (`bones.is_empty()`) WOULD let this through to a
    /// zero-joint skin / empty IBM, which the all-zero-weight LOD does not
    /// independently reject → export Ok → test fails (mutant killed).
    #[test]
    fn empty_skeleton_zero_weight_geometry_is_rejected() {
        let mut data = skinned_triangle_data();
        data.skeleton = ReferenceSkeleton {
            bones: Vec::new(),
            bind_pose: Vec::new(),
        };
        // All-zero weights → degenerate vertices rebind to root, no bone_map use.
        data.lods[0].bone_weights = BoneWeights::U8(vec![[0u8; 8]; 3]);
        assert!(
            data.lods.iter().any(|l| !l.positions.is_empty()),
            "the test mesh must still have drawable geometry"
        );
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("empty skeleton + drawable zero-weight geometry must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A non-finite vertex position (Inf) is rejected with `UnsupportedFeature`
    /// — the scan runs over the CONVERTED f32, so the source `INFINITY` narrows
    /// to f32 `inf` and is caught.
    #[test]
    fn non_finite_position_is_rejected() {
        let mut data = skinned_triangle_data();
        data.lods[0].positions[0].x = f64::INFINITY;
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("inf position must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A non-finite UV (not position) is rejected — UVs flow through `push_uvs`'
    /// `uv.x as f32` into a `TEXCOORD_0` accessor, where a non-finite component
    /// emits a spec-invalid `ACCESSOR_INVALID_FLOAT`. Positions stay finite, so
    /// ONLY the UV branch fires here.
    #[test]
    fn non_finite_uv_is_rejected() {
        let mut data = skinned_triangle_data();
        data.lods[0].uvs[0] = Some(vec![
            crate::asset::structs::vector::FVector2D {
                x: f64::NAN,
                y: 0.0,
            },
            crate::asset::structs::vector::FVector2D { x: 0.0, y: 0.0 },
            crate::asset::structs::vector::FVector2D { x: 0.0, y: 0.0 },
        ]);
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("non-finite UV must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A non-finite normal (Inf) is rejected — it survives `normalize_xyz`'s
    /// pass-through guard into the converted output and trips the NORMAL branch
    /// of `lod_geometry_finite`. Positions stay finite.
    #[test]
    fn non_finite_normal_is_rejected() {
        let mut data = skinned_triangle_data();
        data.lods[0].normals = vec![
            FVector {
                x: f64::INFINITY,
                y: 0.0,
                z: 0.0,
            },
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
            FVector {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
        ];
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("non-finite normal must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A non-finite TANGENT (Inf in xyz/w) is rejected — tangents flow through
    /// `convert_tangent` into a `TANGENT` accessor where a non-finite component
    /// emits a spec-invalid `ACCESSOR_INVALID_FLOAT`. Positions/normals/UVs stay
    /// finite, so ONLY the tangent branch of `lod_geometry_finite` can fire.
    #[test]
    fn non_finite_tangent_is_rejected() {
        let mut data = skinned_triangle_data();
        data.lods[0].tangents = vec![
            crate::asset::structs::vector::FVector4 {
                x: f64::INFINITY,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            crate::asset::structs::vector::FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            crate::asset::structs::vector::FVector4 {
                x: 1.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
        ];
        let err = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect_err("non-finite tangent must be rejected");
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// A 2-LOD mesh where LOD0 is valid + drawable and LOD1 has EMPTY positions
    /// but a non-finite UV exports Ok: the junk non-drawable LOD1 is skipped (not
    /// emitted), so the finiteness preflight must skip it too rather than reject
    /// the whole export. Pins the empty-position `continue` in the preflight loop.
    #[test]
    fn empty_position_lod_with_non_finite_uv_does_not_block_export() {
        let mut data = skinned_triangle_data(); // LOD0: valid drawable triangle
        // LOD1: empty positions (non-drawable) but a non-finite UV channel.
        let junk = SkeletalMeshLod {
            uvs: [
                Some(vec![crate::asset::structs::vector::FVector2D {
                    x: f64::INFINITY,
                    y: 0.0,
                }]),
                None,
                None,
                None,
            ],
            ..SkeletalMeshLod::default()
        };
        assert!(junk.positions.is_empty(), "LOD1 must have no positions");
        data.lods.push(junk);
        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("the junk empty-position LOD must be skipped, not rejected");
        assert_eq!(&bytes[0..4], b"glTF");
    }

    /// A wholly finite mesh passes `lod_geometry_finite` (pins the check against
    /// a `true`-replacement / inverted-guard mutant).
    #[test]
    fn finite_positions_pass_the_check() {
        let data = skinned_triangle_data();
        let lod = &data.lods[0];
        assert!(gltf_common::lod_geometry_finite(
            &lod.positions,
            &lod.normals,
            &lod.tangents,
            &lod.uvs,
        ));
    }

    /// A LOD whose sole section is sub-triangle (0 triangles) produces no mesh
    /// node and NO orphaned vertex/skin accessors (gltf-validator UNUSED_OBJECT).
    #[test]
    fn degenerate_lod_emits_no_node_or_accessor() {
        let mut data = skinned_triangle_data();
        data.lods[0].sections = vec![draw_section(0, 0, 0, 0, 3, vec![1])]; // 0 triangles
        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let len = |k: &str| doc.get(k).and_then(|v| v.as_array()).map_or(0, Vec::len);
        assert_eq!(len("meshes"), 0, "no mesh for an all-degenerate LOD");
        // Only the skeleton's bone nodes remain (the 5 joints); no LOD mesh node.
        // The skeleton still pushes its inverse-bind-matrices accessor, so assert
        // NO vertex/index/skin accessor leaked: the only accessor is the IBM MAT4.
        let accessors = doc["accessors"].as_array().expect("accessors");
        assert_eq!(
            accessors.len(),
            1,
            "only the inverse-bind-matrices accessor, no orphaned geometry/skin"
        );
        assert_eq!(
            accessors[0]["type"].as_str(),
            Some("MAT4"),
            "the lone accessor is the IBM MAT4"
        );
    }

    // ---- end-to-end multi-LOD / multi-section / round-trip ----------------

    /// Slice a U8 VEC4 JOINTS accessor's bytes out of the GLB BIN, returning one
    /// `[u16; 4]` per vertex (the global skeleton indices). The accessor must be
    /// `componentType` UNSIGNED_BYTE (small skeleton) — asserted before decoding.
    fn decode_joints0_u8(
        doc: &serde_json::Value,
        bin: &[u8],
        prim: &serde_json::Value,
    ) -> Vec<[u16; 4]> {
        let acc_idx = prim["attributes"]["JOINTS_0"]
            .as_u64()
            .expect("JOINTS_0 accessor index");
        let accessors = doc["accessors"].as_array().expect("accessors array");
        let acc = &accessors[usize::try_from(acc_idx).expect("acc idx fits usize")];
        assert_eq!(
            acc["componentType"].as_u64(),
            Some(5121),
            "decode_joints0_u8 expects UNSIGNED_BYTE"
        );
        assert_eq!(acc["type"].as_str(), Some("VEC4"), "JOINTS_0 is VEC4");
        let count = usize::try_from(acc["count"].as_u64().expect("count")).expect("count usize");
        // The accessor's own byteOffset is 0; the bufferView carries the BIN offset.
        let view_idx = acc["bufferView"].as_u64().expect("bufferView index");
        let views = doc["bufferViews"].as_array().expect("bufferViews array");
        let view = &views[usize::try_from(view_idx).expect("view idx fits usize")];
        let view_off =
            usize::try_from(view["byteOffset"].as_u64().unwrap_or(0)).expect("view offset usize");
        // U8 VEC4: 4 bytes/vertex. Each component widened to u16 for the caller.
        (0..count)
            .map(|v| {
                let base = view_off + v * 4;
                [
                    u16::from(bin[base]),
                    u16::from(bin[base + 1]),
                    u16::from(bin[base + 2]),
                    u16::from(bin[base + 3]),
                ]
            })
            .collect()
    }

    /// Two non-empty LODs export to ONE shared skin, TWO meshes, and both LOD
    /// mesh nodes reference the same `skin` index with no `matrix` (identity).
    #[test]
    fn export_multi_lod_shares_one_skin() {
        let mut data = skinned_triangle_data();
        // Second LOD: clone the first (same single skinned triangle).
        let lod1 = data.lods[0].clone();
        data.lods.push(lod1);

        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");

        assert_eq!(
            doc["skins"].as_array().expect("skins").len(),
            1,
            "one shared skin"
        );
        assert_eq!(
            doc["meshes"].as_array().expect("meshes").len(),
            2,
            "two LOD meshes"
        );

        let nodes = doc["nodes"].as_array().expect("nodes array");
        let mesh_nodes: Vec<&serde_json::Value> =
            nodes.iter().filter(|n| n.get("mesh").is_some()).collect();
        assert_eq!(mesh_nodes.len(), 2, "two mesh nodes");
        let skin0 = mesh_nodes[0]["skin"].as_u64().expect("mesh node 0 skin");
        let skin1 = mesh_nodes[1]["skin"].as_u64().expect("mesh node 1 skin");
        assert_eq!(skin0, skin1, "both LOD mesh nodes share one skin index");
        assert_eq!(skin0, 0, "the shared skin is the only (index 0) skin");
        for n in &mesh_nodes {
            assert!(
                n.get("matrix").is_none(),
                "LOD mesh node is identity (no matrix)"
            );
        }
    }

    /// A single LOD whose vertices use all eight influences emits BOTH attribute
    /// sets (JOINTS_0/WEIGHTS_0 + JOINTS_1/WEIGHTS_1) through `export()`. The
    /// 4-influence negative is already pinned by
    /// `primitive_omits_slot1_for_four_influences`.
    #[test]
    fn export_eight_influence_emits_joints1_weights1() {
        let mut data = skinned_triangle_data();
        data.skeleton = ReferenceSkeleton {
            bones: (0..8).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..8).map(|i| sample_transform(f64::from(i + 1))).collect(),
        };
        let lod = &mut data.lods[0];
        lod.sections = vec![draw_section(0, 0, 1, 0, 3, vec![0, 1, 2, 3, 4, 5, 6, 7])];
        lod.bone_indices = vec![[0, 1, 2, 3, 4, 5, 6, 7]; 3];
        lod.bone_weights = BoneWeights::U8(vec![[40, 40, 40, 40, 30, 30, 20, 15]; 3]);

        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let attrs = doc["meshes"][0]["primitives"][0]["attributes"]
            .as_object()
            .expect("attributes object");
        for key in ["JOINTS_0", "WEIGHTS_0", "JOINTS_1", "WEIGHTS_1"] {
            assert!(
                attrs.contains_key(key),
                "{key} present for 8-influence export"
            );
        }
    }

    /// One LOD with two sections (distinct vertex ranges + distinct `bone_map`s)
    /// emits two primitives, and a section-1 vertex's JOINTS_0 decoded from the
    /// GLB BIN proves it was remapped through SECTION 1's bone_map (global 4),
    /// not section 0's (global 1) — the remap survives end-to-end.
    #[test]
    fn export_multi_section_one_lod_independent_remap() {
        // Two triangles (6 indices). Section 0 owns verts 0..3 (tri 0, bone_map
        // [1,2]); section 1 owns verts 3..6 (tri 1, bone_map [4,3]). Every vertex
        // is 100%-weighted to its section-local bone 0: section-0 verts -> global
        // 1, section-1 verts -> global 4. 4 != 1 discriminates the two maps.
        let skeleton = ReferenceSkeleton {
            bones: (0..6).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..6).map(|i| sample_transform(f64::from(i + 1))).collect(),
        };
        let lod = SkeletalMeshLod {
            sections: vec![
                draw_section(0, 0, 1, 0, 3, vec![1, 2]),
                draw_section(0, 3, 1, 3, 3, vec![4, 3]),
            ],
            positions: positions(6),
            indices: vec![0, 1, 2, 3, 4, 5],
            bone_indices: vec![[0u16; 8]; 6],
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 6]),
            ..SkeletalMeshLod::default()
        };
        let mut data = SkeletalMeshData::empty();
        data.cooked = true;
        data.skeleton = skeleton;
        data.lods = vec![lod];

        let bytes = GltfSkeletalMeshHandler
            .export(&Asset::SkeletalMesh(data), &[])
            .expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let bin = glb.bin.as_ref().expect("GLB BIN chunk");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");

        let prims = doc["meshes"][0]["primitives"]
            .as_array()
            .expect("primitives array");
        assert_eq!(prims.len(), 2, "two sections -> two primitives");

        // Both primitives share the LOD's single JOINTS_0 accessor, so decode it
        // once (parallel to all six positions) and read the global indices.
        let joints0 = decode_joints0_u8(&doc, bin, &prims[0]);
        assert_eq!(joints0.len(), 6, "JOINTS_0 covers all six LOD vertices");
        // Section-0 vertices (0..3): local 0 -> global 1.
        assert_eq!(
            joints0[0][0], 1,
            "section-0 vertex remaps via [1,2] -> global 1"
        );
        // Section-1 vertices (3..6): local 0 -> global 4 (NOT section-0's 1).
        assert_eq!(
            joints0[3][0], 4,
            "section-1 vertex remaps via SECTION 1's [4,3] -> global 4, not section 0's 1"
        );
        assert_eq!(
            joints0[5][0], 4,
            "section-1 vertex remaps via section 1's bone_map"
        );

        // The shared skin still covers every bone.
        let joints = doc["skins"][0]["joints"].as_array().expect("skin joints");
        assert_eq!(joints.len(), 6, "skin joints cover all six bones");
    }

    /// The emitted GLB round-trips through the `gltf` crate's DOCUMENT reader
    /// (`gltf::Gltf::from_slice`), not just `Glb` + raw serde_json: the document
    /// loads and reports one skin and one mesh. This is the structural sanity
    /// gate that proves the JSON is a well-formed glTF document, not merely valid
    /// JSON.
    #[test]
    fn export_round_trips_through_gltf_reader() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");

        // Raw container + JSON-chunk sanity (mirrors the rest of the suite).
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let _doc: serde_json::Value =
            serde_json::from_slice(&glb.json).expect("JSON chunk decodes");

        // Document-level reader: validates the whole glTF structure.
        let gltf_doc = gltf::Gltf::from_slice(&bytes).expect("gltf document loads");
        assert_eq!(gltf_doc.document.skins().count(), 1, "one skin");
        assert_eq!(gltf_doc.document.meshes().count(), 1, "one mesh");
    }

    // ---- pin tests: caps / guards / node fields --------------------------

    /// Build a flat (all-root) skeleton with exactly `n` bones, each with an
    /// identity-ish bind transform. Used to exercise the bone-count cap boundary.
    fn flat_root_skeleton(n: usize) -> ReferenceSkeleton {
        let identity = FTransform {
            rotation: FQuat {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 1.0,
            },
            translation: FVector {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            scale_3d: FVector {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
        };
        ReferenceSkeleton {
            bones: (0..n).map(|_| bone("b", -1)).collect(),
            bind_pose: vec![identity; n],
        }
    }

    /// A skeleton with EXACTLY `MAX_BONES_PER_SKELETON` bones is accepted. Pins
    /// the `bone_count > MAX_BONES_PER_SKELETON` boundary against `==` / `>=`
    /// mutants (which would reject the at-cap count).
    #[test]
    fn bone_count_at_cap_is_accepted() {
        let skeleton = flat_root_skeleton(MAX_BONES_PER_SKELETON);
        let mut doc = GltfDoc::new();
        assert!(
            build_skeleton(&mut doc, &skeleton).is_ok(),
            "exactly MAX_BONES_PER_SKELETON bones must build"
        );
    }

    /// One bone over the cap is rejected. Pins the `>` direction (a `>`→`<`
    /// mutant would accept the over-cap count).
    #[test]
    fn bone_count_over_cap_is_rejected() {
        let skeleton = flat_root_skeleton(MAX_BONES_PER_SKELETON + 1);
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// A bone whose `parent_index` equals its OWN index is rejected. Pins the
    /// `p < i` parent-ordering check against a `<`→`<=` mutant (which would
    /// accept a self-parent).
    #[test]
    fn rejects_self_parent() {
        // Bone 1's parent is bone 1 (itself): not strictly less than its index.
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("root", -1), bone("self", 1)],
            bind_pose: vec![sample_transform(1.0), sample_transform(2.0)],
        };
        let mut doc = GltfDoc::new();
        assert!(matches!(
            build_skeleton(&mut doc, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// Each emitted bone node carries its bone's name. Pins the `name` field of
    /// the per-bone `gltf::json::Node` against a field-deletion mutant (the
    /// matrix field is already pinned by `node_matrix_is_basis_conjugation`).
    #[test]
    fn bone_nodes_carry_bone_names() {
        let names = ["Root", "Spine", "Head"];
        let skeleton = ReferenceSkeleton {
            bones: vec![bone(names[0], -1), bone(names[1], 0), bone(names[2], 1)],
            bind_pose: vec![
                sample_transform(1.0),
                sample_transform(2.0),
                sample_transform(3.0),
            ],
        };
        let mut doc = GltfDoc::new();
        let out = build_skeleton(&mut doc, &skeleton).expect("build_skeleton");
        let (root, _bin) = doc.into_parts();
        for (k, want) in names.iter().enumerate() {
            assert_eq!(
                root.nodes[out.joints[k].value()].name.as_deref(),
                Some(*want),
                "bone {k} node name"
            );
        }
    }

    /// `inverse_bind_matrices`, called DIRECTLY (bypassing `build_skeleton`'s
    /// validation) on a skeleton where bone 1's `parent_index == 1` (its own
    /// index), treats the bone as a root and does NOT panic. At that point
    /// `global.len() == 1`, so `p=1` is NOT `< 1`. Pins the `p < global.len()`
    /// defensive guard against `→ true` and `<=` mutants (both would index
    /// `global[1]` out of bounds and panic).
    #[test]
    fn inverse_bind_matrices_tolerates_out_of_range_parent_directly() {
        let skeleton = ReferenceSkeleton {
            bones: vec![bone("root", -1), bone("self", 1)],
            bind_pose: vec![sample_transform(1.0), sample_transform(2.0)],
        };
        let ibms = inverse_bind_matrices(&skeleton);
        assert_eq!(ibms.len(), 2, "one IBM per bone, no panic on self-parent");
    }

    /// A LOD whose `bone_indices` buffer is STRICTLY shorter than the position
    /// count (and NO sections to trigger any other error) is rejected. The
    /// `bone_weights` buffer is full length so only the `bone_indices` operand
    /// of the `len() < n` guard can fire — pinning that operand against a
    /// `<`→`>` mutant (under which `2 > 3` is false and the export would proceed).
    #[test]
    fn short_bone_indices_buffer_is_rejected() {
        let lod = SkeletalMeshLod {
            sections: Vec::new(),
            positions: positions(3),
            bone_indices: vec![[0u16; 8]; 2], // strictly shorter than n=3
            bone_weights: BoneWeights::U8(vec![[255, 0, 0, 0, 0, 0, 0, 0]; 3]), // full length
            ..SkeletalMeshLod::default()
        };
        let skeleton = skeleton_with_n_bones(4);
        assert!(matches!(
            build_skin_attributes(&lod, &skeleton),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// A mesh with EXACTLY `MAX_SKELETAL_LODS_PER_MESH` non-empty LODs exports.
    /// Pins the `lods.len() > MAX_SKELETAL_LODS_PER_MESH` boundary against a
    /// `>`→`>=` mutant (which would reject the at-cap count). The over-cap
    /// rejection is pinned by `too_many_lods_is_rejected`.
    #[test]
    fn export_at_lod_cap_is_accepted() {
        let base = skinned_triangle_data();
        let mut data = base.clone();
        data.lods = (0..MAX_SKELETAL_LODS_PER_MESH)
            .map(|_| base.lods[0].clone())
            .collect();
        assert_eq!(data.lods.len(), MAX_SKELETAL_LODS_PER_MESH);
        assert!(
            GltfSkeletalMeshHandler
                .export(&Asset::SkeletalMesh(data), &[])
                .is_ok(),
            "exactly MAX_SKELETAL_LODS_PER_MESH LODs must export"
        );
    }

    /// The exported LOD mesh node carries `mesh`, the shared `skin` index, and
    /// the `LOD0` name. Pins all three fields of the mesh `gltf::json::Node`
    /// (line ~558) against field-deletion mutants.
    #[test]
    fn mesh_node_fields_present() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data());
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");

        // The shared skin is the sole skin (index 0).
        assert_eq!(
            doc["skins"].as_array().expect("skins array").len(),
            1,
            "one shared skin"
        );
        let nodes = doc["nodes"].as_array().expect("nodes array");
        let mesh_node = nodes
            .iter()
            .find(|n| n.get("mesh").is_some())
            .expect("a node with a mesh");
        assert!(mesh_node.get("mesh").is_some(), "mesh field present");
        assert_eq!(
            mesh_node["skin"].as_u64(),
            Some(0),
            "skin field present and points at the shared skin (index 0)"
        );
        assert_eq!(
            mesh_node["name"].as_str(),
            Some("LOD0"),
            "name field present as LOD0"
        );
    }

    /// An exported material slot carries its placeholder name. Pins the `name`
    /// field of `build_materials`' `gltf::json::Material` (line ~609) against a
    /// field-deletion mutant.
    #[test]
    fn material_node_carries_placeholder_name() {
        let asset = Asset::SkeletalMesh(skinned_triangle_data()); // section -> material 0
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(
            doc["materials"][0]["name"].as_str(),
            Some("Material_0"),
            "first material slot is named Material_0"
        );
    }

    /// A skeleton with EXACTLY 256 bones keeps JOINTS_0 at `UNSIGNED_BYTE`
    /// (5121): indices 0..255 fit u8. Pins the `bones.len() > 256` componentType
    /// boundary against a `>`→`>=` mutant (which would widen to UNSIGNED_SHORT at
    /// 256). The >256 SHORT side is pinned by
    /// `joints_component_type_short_for_large_skeleton`.
    #[test]
    fn joints_componenttype_u8_at_256_bones() {
        let mut data = skinned_triangle_data();
        // 256 root bones; the section bone_map [1,2,3] references low indices.
        data.skeleton = ReferenceSkeleton {
            bones: (0..256).map(|i| bone(&format!("b{i}"), -1)).collect(),
            bind_pose: (0..256)
                .map(|i| sample_transform(f64::from(u16::try_from(i).unwrap_or(0))))
                .collect(),
        };
        let asset = Asset::SkeletalMesh(data);
        let bytes = GltfSkeletalMeshHandler.export(&asset, &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let doc: serde_json::Value = serde_json::from_slice(&glb.json).expect("json");
        let joints_acc = doc["meshes"][0]["primitives"][0]["attributes"]["JOINTS_0"]
            .as_u64()
            .expect("JOINTS_0 accessor index");
        let accessors = doc["accessors"].as_array().expect("accessors array");
        let ct = accessors[usize::try_from(joints_acc).expect("index fits usize")]["componentType"]
            .as_u64()
            .expect("componentType");
        assert_eq!(ct, 5121, "UNSIGNED_BYTE at exactly 256 bones");
    }
}
