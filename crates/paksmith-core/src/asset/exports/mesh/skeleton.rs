//! `FReferenceSkeleton` reader — bone hierarchy + bind pose for `USkeletalMesh`
//! (Phase 3h). Wire reference: `docs/formats/mesh/skeleton.md`. Wired into
//! `USkeletalMesh::read_typed` by PR2.
//!
//! The post-properties `FReferenceSkeleton` blob decodes in three
//! parallel-array segments (oracle `FReferenceSkeleton.cs` @ `cf74fc32`):
//!
//! 1. **`FinalRefBoneInfo`** — `i32` count + N×`FMeshBoneInfo`
//!    (cooked subset: `Name: FName` (8 bytes) + `ParentIndex: i32`).
//! 2. **`FinalRefBonePose`** — `i32` count (== bone count) + N×`FTransform`
//!    (UE4 40 bytes / UE5 LWC 80 bytes via [`FTransform::read_from`]).
//! 3. **`FinalNameToIndexMap`** — `i32` count (== bone count) + N×(`FName`
//!    key + `i32` bone-index value); consumed and validated, not retained.

use std::io::{Read, Seek};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::PaksmithError;
use crate::asset::AssetContext;
use crate::asset::property::read_fname_pair;
use crate::asset::structs::quat::FQuat;
use crate::asset::structs::stream_pos;
use crate::asset::structs::transform::FTransform;
use crate::asset::structs::vector::FVector;
use crate::error::{AssetParseFault, AssetWireField};

/// Maximum bones per skeleton. Matches the 16-bit bone-index ceiling
/// (`2^16`) used by `FStaticLODModel` / `FSkinWeightVertexBuffer`.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention (`vertex_buffers.rs` / `texture2d.rs`), the cap is pinned
/// via the in-source over-cap / at-cap error-path tests below; an
/// integration-test consumer would add the accessor when one exists.
pub(crate) const MAX_BONES_PER_SKELETON: usize = 1 << 16; // 65_536

/// Decode a `FReferenceSkeleton` (post-properties blob): `FinalRefBoneInfo`,
/// `FinalRefBonePose`, and the consume-and-validated `FinalNameToIndexMap`.
///
/// Every `i32` count prefix is attacker-controlled, so each is sign-checked
/// and the bone count is capped at [`MAX_BONES_PER_SKELETON`] *before* any
/// reservation. The pose / name-map counts must equal the bone count (the
/// arrays are parallel). Each bone's parent index must be `-1` (root) or a
/// strictly-earlier bone (no cycles / forward refs). Each name-map value
/// must be a valid bone index in `[0, bone_count)`.
///
/// `#[allow(dead_code)]`: wired into `USkeletalMesh::read_typed` by PR2;
/// the only referents until then are the unit tests below.
///
/// # Errors
/// - [`AssetParseFault::SkeletonBoneCountNegative`] / [`AssetParseFault::SkeletonBoneCountExceeded`]
///   on a negative / over-cap bone count.
/// - [`AssetParseFault::SkeletonArrayLengthMismatch`] when the pose or
///   name-map count disagrees with the bone count.
/// - [`AssetParseFault::BoneParentIndexInvalid`] on a parent index that is
///   neither `-1` nor a strictly-earlier bone.
/// - [`AssetParseFault::NameToIndexValueOob`] on a name-map value outside
///   `[0, bone_count)`.
/// - [`AssetParseFault::UnexpectedEof`] on any short count / parent / value
///   read; nested FName / FTransform faults from [`read_fname_pair`] /
///   [`FTransform::read_from`].
#[allow(dead_code)] // wired into read_typed by PR2
pub(crate) fn read_reference_skeleton<R: Read + Seek + ?Sized>(
    r: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<crate::asset::ReferenceSkeleton> {
    // --- FinalRefBoneInfo ---
    let bone_count_i32 = r
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(AssetWireField::SkeletonBoneCount, asset_path))?;
    // `try_from` rejects a negative count AND converts in one step — no
    // sign-loss `as usize` cast (mirrors `data_table::read_from`).
    let bone_count = usize::try_from(bone_count_i32).map_err(|_| {
        fault(
            AssetParseFault::SkeletonBoneCountNegative {
                count: bone_count_i32,
            },
            asset_path,
        )
    })?;
    if bone_count > MAX_BONES_PER_SKELETON {
        return Err(fault(
            AssetParseFault::SkeletonBoneCountExceeded {
                count: i64::from(bone_count_i32),
                cap: MAX_BONES_PER_SKELETON,
            },
            asset_path,
        ));
    }

    // Cap-bounded reservation (`bone_count <= MAX_BONES_PER_SKELETON`),
    // matching the mesh-module convention (`read::read_capped_count` +
    // plain `with_capacity` in `render_data.rs` / `lod.rs`): the cap above
    // bounds the worst-case reservation, so no clamp-to-remaining is needed.
    let mut bones = Vec::with_capacity(bone_count);
    for i in 0..bone_count {
        let name = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletonBoneName)?;
        let parent_index = r
            .read_i32::<LittleEndian>()
            .map_err(|_| eof(AssetWireField::SkeletonBoneParent, asset_path))?;
        // Root (-1) or a strictly-earlier bone: rejects cycles + forward refs.
        // `try_from` fails for any negative (only -1 is allowed, handled
        // first), so the closure runs only for `>= 0` candidates.
        let parent_ok = parent_index == -1 || usize::try_from(parent_index).is_ok_and(|p| p < i);
        if !parent_ok {
            return Err(fault(
                AssetParseFault::BoneParentIndexInvalid {
                    bone: i,
                    parent: parent_index,
                },
                asset_path,
            ));
        }
        bones.push(crate::asset::BoneInfo {
            name: name.to_string(),
            parent_index,
        });
    }

    // --- FinalRefBonePose (parity with bone_count) ---
    let pose_count = read_count_eq(
        r,
        bone_count,
        "FinalRefBonePose",
        AssetWireField::SkeletonBonePoseCount,
        asset_path,
    )?;
    let ft_size = FQuat::wire_size(ctx) + 2 * FVector::wire_size(ctx);
    let mut bind_pose = Vec::with_capacity(pose_count);
    for _ in 0..pose_count {
        let start = stream_pos(r, asset_path)?;
        bind_pose.push(FTransform::read_from(r, ctx, start + ft_size, asset_path)?);
    }

    // --- FinalNameToIndexMap (present for UE 4.13+; consume + validate) ---
    let map_count = read_count_eq(
        r,
        bone_count,
        "FinalNameToIndexMap",
        AssetWireField::SkeletonNameMapCount,
        asset_path,
    )?;
    for _ in 0..map_count {
        let _key = read_fname_pair(r, ctx, asset_path, AssetWireField::SkeletonNameMapKey)?;
        let value = r
            .read_i32::<LittleEndian>()
            .map_err(|_| eof(AssetWireField::SkeletonNameMapValue, asset_path))?;
        // Valid iff `0 <= value < bone_count`. `try_from` rejects negatives
        // without a sign-loss cast; the closure checks the upper bound.
        if !usize::try_from(value).is_ok_and(|v| v < bone_count) {
            return Err(fault(
                AssetParseFault::NameToIndexValueOob { value, bone_count },
                asset_path,
            ));
        }
    }

    Ok(crate::asset::ReferenceSkeleton { bones, bind_pose })
}

/// Read an `i32` count that must be non-negative AND equal `bone_count`
/// (the pose / name-map arrays are parallel to `FinalRefBoneInfo`). A
/// negative count is caught by the same `< 0` check (it can never equal a
/// `usize`), so both surface as [`AssetParseFault::SkeletonArrayLengthMismatch`]
/// with the offending wire value.
fn read_count_eq<R: Read + ?Sized>(
    r: &mut R,
    bone_count: usize,
    which: &'static str,
    field: AssetWireField,
    asset_path: &str,
) -> crate::Result<usize> {
    let got = r
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(field, asset_path))?;
    // Parallel-array invariant: count must equal `bone_count`. `try_from`
    // rejects negatives without a sign-loss cast; a negative or
    // non-matching count surfaces the mismatch with its wire value.
    if !usize::try_from(got).is_ok_and(|g| g == bone_count) {
        return Err(fault(
            AssetParseFault::SkeletonArrayLengthMismatch {
                which,
                got: i64::from(got),
                expected: bone_count,
            },
            asset_path,
        ));
    }
    Ok(bone_count)
}

/// Wrap an [`AssetParseFault`] in a [`PaksmithError::AssetParse`] tagged
/// with `asset_path` (matches the sibling readers' explicit construction —
/// there is no `From<AssetParseFault>` impl).
fn fault(fault: AssetParseFault, asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        fault,
        asset_path: asset_path.to_string(),
    }
}

/// Map a short count / scalar read to [`AssetParseFault::UnexpectedEof`]
/// tagged with the wire `field` — the skeleton-reader EOF mapper, mirroring
/// the `unexpected_eof` helper used by the property readers.
fn eof(field: AssetWireField, asset_path: &str) -> PaksmithError {
    fault(AssetParseFault::UnexpectedEof { field }, asset_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    use crate::asset::custom_version::CustomVersionContainer;
    use crate::asset::export_table::ExportTable;
    use crate::asset::import_table::ImportTable;
    use crate::asset::name_table::{FName, NameTable};
    use crate::asset::version::AssetVersion;

    /// Build an `AssetContext` with the given name table (in wire order) at
    /// the requested version. Unlike `property::test_utils::make_ctx`, this
    /// does NOT assert index 0 == "None": the skeleton reader never probes
    /// for the `(0, 0)` None-terminator (that short-circuit lives in
    /// `read_tag`), so bone index 0 may legitimately be a real bone name.
    fn skel_ctx(names: &[&str], ue4: i32, ue5: Option<i32>) -> AssetContext {
        let table = NameTable {
            names: names.iter().map(|n| FName::new(n)).collect(),
        };
        AssetContext::new(
            Arc::new(table),
            Arc::new(ImportTable::default()),
            Arc::new(ExportTable::default()),
            AssetVersion {
                legacy_file_version: if ue5.is_some() { -8 } else { -7 },
                file_version_ue4: ue4,
                file_version_ue5: ue5,
                file_version_licensee_ue4: 0,
            },
            Arc::new(CustomVersionContainer::default()),
            None,
        )
    }

    /// UE4 (non-LWC) ctx: `file_version_ue5 = None` → `FTransform` is 40 bytes.
    fn test_ctx_ue4(names: &[&str]) -> AssetContext {
        skel_ctx(names, 510, None)
    }

    /// UE5 LWC ctx: `file_version_ue5 = 1004` (== `LARGE_WORLD_COORDINATES`)
    /// → `is_lwc()` true → `FTransform` is 80 bytes (f64 components).
    fn test_ctx_ue5_lwc(names: &[&str]) -> AssetContext {
        skel_ctx(names, 510, Some(1004))
    }

    /// Append an FName pair `(index, number=0)`.
    fn fname(buf: &mut Vec<u8>, index: i32) {
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    /// 40-byte identity `FTransform` (UE4 single-precision): Quat(0,0,0,1),
    /// Translation(0,0,0), Scale3D(1,1,1). Matches skeleton.md's identity
    /// worked example.
    fn identity_ftransform_ue4() -> Vec<u8> {
        let mut b = Vec::with_capacity(40);
        for v in [0.0f32, 0.0, 0.0, 1.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f32, 0.0, 0.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f32, 1.0, 1.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
        debug_assert_eq!(b.len(), 40);
        b
    }

    /// 80-byte identity `FTransform` (UE5 LWC double-precision): 4×f64 quat
    /// + 3×f64 zero translation + 3×f64 unit scale.
    fn identity_ftransform_ue5_lwc() -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        for v in [0.0f64, 0.0, 0.0, 1.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Quat x,y,z,w
        }
        for v in [0.0f64, 0.0, 0.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Translation
        }
        for v in [1.0f64, 1.0, 1.0] {
            b.extend_from_slice(&v.to_le_bytes()); // Scale3D
        }
        debug_assert_eq!(b.len(), 80);
        b
    }

    const UNIT_SCALE: crate::asset::structs::vector::FVector =
        crate::asset::structs::vector::FVector {
            x: 1.0,
            y: 1.0,
            z: 1.0,
        };

    #[test]
    fn max_bones_cap_value() {
        assert_eq!(MAX_BONES_PER_SKELETON, 65_536);
    }

    // ===== Task 4: happy path =====

    #[test]
    fn reads_two_bone_reference_skeleton_ue4_single_precision() {
        // Name table maps index 0 -> "Root", 1 -> "Hip".
        let ctx = test_ctx_ue4(&["Root", "Hip"]);
        let mut body: Vec<u8> = Vec::new();
        // FinalRefBoneInfo count = 2
        body.extend_from_slice(&2i32.to_le_bytes());
        // bone 0: name "Root" (index 0), parent -1
        fname(&mut body, 0);
        body.extend_from_slice(&(-1i32).to_le_bytes());
        // bone 1: name "Hip" (index 1), parent 0
        fname(&mut body, 1);
        body.extend_from_slice(&0i32.to_le_bytes());
        // FinalRefBonePose count = 2 + two identity FTransforms (40 bytes each)
        body.extend_from_slice(&2i32.to_le_bytes());
        body.extend_from_slice(&identity_ftransform_ue4());
        body.extend_from_slice(&identity_ftransform_ue4());
        // FinalNameToIndexMap count = 2 + ("Root"->0, "Hip"->1)
        body.extend_from_slice(&2i32.to_le_bytes());
        fname(&mut body, 0);
        body.extend_from_slice(&0i32.to_le_bytes());
        fname(&mut body, 1);
        body.extend_from_slice(&1i32.to_le_bytes());

        // Core body (BoneInfo 28 + BonePose 84) = 112 per skeleton.md;
        // FinalNameToIndexMap adds 28 → 140 total, all consumed.
        let total = body.len() as u64;
        assert_eq!(total, 140);

        let mut cur = Cursor::new(body);
        let skel = read_reference_skeleton(&mut cur, &ctx, "Test.uasset").expect("decode");
        assert_eq!(skel.bones.len(), 2);
        assert_eq!(skel.bones[0].name, "Root");
        assert_eq!(skel.bones[0].parent_index, -1);
        assert_eq!(skel.bones[1].name, "Hip");
        assert_eq!(skel.bones[1].parent_index, 0);
        assert_eq!(skel.bind_pose.len(), 2);
        assert_eq!(skel.bind_pose[0].scale_3d, UNIT_SCALE);
        assert_eq!(skel.bind_pose[1].scale_3d, UNIT_SCALE);
        // whole body consumed — pins that the name-map is read, not skipped.
        assert_eq!(cur.position(), total);
    }

    // ===== Task 5: hardening =====

    #[test]
    fn negative_bone_count_is_rejected() {
        let ctx = test_ctx_ue4(&[]);
        let body = (-1i32).to_le_bytes().to_vec();
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::SkeletonBoneCountNegative { count },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected SkeletonBoneCountNegative, got {other:?}"),
        }
    }

    #[test]
    fn over_cap_bone_count_is_rejected_before_allocation() {
        let ctx = test_ctx_ue4(&[]);
        // MAX + 1 = 65_537, fits i32. Only the 4-byte count is present, so
        // the cap check MUST fire before any per-bone read or allocation.
        let over = i32::try_from(MAX_BONES_PER_SKELETON + 1).expect("cap+1 fits i32");
        let body = over.to_le_bytes().to_vec();
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::SkeletonBoneCountExceeded { count, cap },
                ..
            }) => {
                assert_eq!(count, 65_537i64); // MAX_BONES_PER_SKELETON + 1
                assert_eq!(cap, MAX_BONES_PER_SKELETON);
            }
            other => panic!("expected SkeletonBoneCountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn at_cap_bone_count_passes_cap_check() {
        // count == cap must NOT be rejected by the cap (`>`, not `>=`). With
        // only the 4-byte count present, it proceeds to the first bone-name
        // read and EOFs there — so the error is anything BUT
        // SkeletonBoneCountExceeded. Pins the `>` vs `>=` boundary mutant.
        let ctx = test_ctx_ue4(&[]);
        let at_cap = i32::try_from(MAX_BONES_PER_SKELETON).expect("cap fits i32");
        let body = at_cap.to_le_bytes().to_vec();
        let err = read_reference_skeleton(&mut Cursor::new(body), &ctx, "T").unwrap_err();
        assert!(
            !matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::SkeletonBoneCountExceeded { .. },
                    ..
                }
            ),
            "count == cap must pass the cap check, got {err:?}"
        );
    }

    #[test]
    fn pose_count_parity_mismatch_is_rejected() {
        // 1 valid bone, but FinalRefBonePose count = 2.
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1
        body.extend_from_slice(&2i32.to_le_bytes()); // pose count = 2 (mismatch)
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::SkeletonArrayLengthMismatch {
                        which,
                        got,
                        expected,
                    },
                ..
            }) => {
                assert_eq!(which, "FinalRefBonePose");
                assert_eq!(got, 2);
                assert_eq!(expected, 1);
            }
            other => {
                panic!("expected SkeletonArrayLengthMismatch(FinalRefBonePose), got {other:?}")
            }
        }
    }

    #[test]
    fn name_map_count_parity_mismatch_is_rejected() {
        // 1 bone, correct pose count 1, but FinalNameToIndexMap count = 0.
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1
        body.extend_from_slice(&1i32.to_le_bytes()); // pose count = 1
        body.extend_from_slice(&identity_ftransform_ue4()); // 1 transform
        body.extend_from_slice(&0i32.to_le_bytes()); // name-map count = 0 (mismatch)
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::SkeletonArrayLengthMismatch {
                        which,
                        got,
                        expected,
                    },
                ..
            }) => {
                assert_eq!(which, "FinalNameToIndexMap");
                assert_eq!(got, 0);
                assert_eq!(expected, 1);
            }
            other => {
                panic!("expected SkeletonArrayLengthMismatch(FinalNameToIndexMap), got {other:?}")
            }
        }
    }

    #[test]
    fn parent_index_equal_own_index_is_rejected() {
        // Single bone 0 with parent_index = 0 (== own index): a self/forward
        // ref. Pins the `0..i` (exclusive) range against `0..=i`.
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&0i32.to_le_bytes()); // parent 0 == own index
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::BoneParentIndexInvalid { bone, parent },
                ..
            }) => {
                assert_eq!(bone, 0);
                assert_eq!(parent, 0);
            }
            other => panic!("expected BoneParentIndexInvalid, got {other:?}"),
        }
    }

    #[test]
    fn parent_index_forward_ref_is_rejected() {
        // Bone 0 with parent_index = 5 (forward ref past the array).
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&5i32.to_le_bytes()); // parent 5 (forward ref)
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::BoneParentIndexInvalid { bone, parent },
                ..
            }) => {
                assert_eq!(bone, 0);
                assert_eq!(parent, 5);
            }
            other => panic!("expected BoneParentIndexInvalid, got {other:?}"),
        }
    }

    #[test]
    fn name_map_value_equal_bone_count_is_rejected() {
        // value == bone_count (1) is out of [0, 1). Pins the `>=` upper bound.
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1
        body.extend_from_slice(&1i32.to_le_bytes()); // pose count 1
        body.extend_from_slice(&identity_ftransform_ue4());
        body.extend_from_slice(&1i32.to_le_bytes()); // name-map count 1
        fname(&mut body, 0); // key "Root"
        body.extend_from_slice(&1i32.to_le_bytes()); // value 1 == bone_count (OOB)
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::NameToIndexValueOob { value, bone_count },
                ..
            }) => {
                assert_eq!(value, 1);
                assert_eq!(bone_count, 1);
            }
            other => panic!("expected NameToIndexValueOob, got {other:?}"),
        }
    }

    #[test]
    fn name_map_value_negative_is_rejected() {
        // value == -1 is out of [0, 1). Pins the `< 0` lower bound.
        let ctx = test_ctx_ue4(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1
        body.extend_from_slice(&1i32.to_le_bytes()); // pose count 1
        body.extend_from_slice(&identity_ftransform_ue4());
        body.extend_from_slice(&1i32.to_le_bytes()); // name-map count 1
        fname(&mut body, 0); // key "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // value -1 (OOB)
        match read_reference_skeleton(&mut Cursor::new(body), &ctx, "T") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::NameToIndexValueOob { value, bone_count },
                ..
            }) => {
                assert_eq!(value, -1);
                assert_eq!(bone_count, 1);
            }
            other => panic!("expected NameToIndexValueOob, got {other:?}"),
        }
    }

    #[test]
    fn reads_reference_skeleton_ue5_lwc_double_precision() {
        let ctx = test_ctx_ue5_lwc(&["Root"]);
        let mut body = Vec::new();
        body.extend_from_slice(&1i32.to_le_bytes()); // 1 bone
        fname(&mut body, 0); // "Root"
        body.extend_from_slice(&(-1i32).to_le_bytes()); // parent -1
        body.extend_from_slice(&1i32.to_le_bytes()); // pose count 1
        body.extend_from_slice(&identity_ftransform_ue5_lwc()); // 80 bytes (f64)
        body.extend_from_slice(&1i32.to_le_bytes()); // name-map count 1
        fname(&mut body, 0); // key "Root"
        body.extend_from_slice(&0i32.to_le_bytes()); // value 0
        let total = body.len() as u64;
        let mut cur = Cursor::new(body);
        let skel = read_reference_skeleton(&mut cur, &ctx, "T").expect("decode");
        assert_eq!(skel.bones.len(), 1);
        assert_eq!(skel.bones[0].name, "Root");
        assert_eq!(skel.bind_pose.len(), 1);
        assert_eq!(skel.bind_pose[0].scale_3d, UNIT_SCALE);
        // full LWC body consumed — confirms the 80-byte transform width.
        assert_eq!(cur.position(), total);
    }
}
