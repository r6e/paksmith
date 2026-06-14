//! Skinned-mesh glTF export — math foundation.
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

use crate::PaksmithError;
use crate::asset::ReferenceSkeleton;
use crate::asset::structs::transform::FTransform;

use super::gltf_common::{GltfDoc, push_mat4};

/// Upper bound on bone count for a single skeleton. UE skeletons are limited to
/// `u16` bone indices on the wire; this generous cap guards against a crafted
/// asset claiming an absurd bone count before we allocate per-bone glTF nodes.
pub(crate) const MAX_BONES_PER_SKELETON: usize = 65_536;

/// The glTF nodes + skin produced from a UE [`ReferenceSkeleton`].
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
pub(crate) struct SkeletonOut {
    /// One node index per bone, in skeleton order (parallel to `skeleton.bones`).
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
/// bones, or a `parent_index` that is neither `-1` nor an index strictly less
/// than the bone's own (forward ref / cycle / out-of-bounds).
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
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
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
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
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
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

/// Compose an [`FTransform`] (rotation·scale + translation) into a column-major
/// affine [`DMat4`]. The wire quaternion is normalized defensively.
#[allow(dead_code)] // consumed by PR6 Tasks 5–8
pub(crate) fn ftransform_to_dmat4(t: &FTransform) -> DMat4 {
    let rot = DQuat::from_xyzw(t.rotation.x, t.rotation.y, t.rotation.z, t.rotation.w).normalize();
    DMat4::from_scale_rotation_translation(
        DVec3::new(t.scale_3d.x, t.scale_3d.y, t.scale_3d.z),
        rot,
        DVec3::new(t.translation.x, t.translation.y, t.translation.z),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::structs::quat::FQuat;
    use crate::asset::structs::vector::FVector;
    use crate::asset::{BoneInfo, ReferenceSkeleton};

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
}
