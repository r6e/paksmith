//! `FBoxSphereBounds` decoder — a bounding volume pairing an
//! axis-aligned box with a bounding sphere, composing the [`FVector`]
//! decoder + one LWC-widening scalar.
//!
//! Wire-format reference: CUE4Parse `FBoxSphereBounds.cs` at
//! `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`. The archive
//! constructor reads three components in order, with **no trailing
//! pad byte**:
//!
//! ```text
//! Origin      : FVector (x, y, z)
//! BoxExtent   : FVector (x, y, z)
//! SphereRadius: f32 / f64 (Ar.ReadFReal — LWC-widens like a vector
//!               component)
//! ```
//!
//! UE4 = 12 + 12 + 4 = 28 bytes; UE5 LWC = 24 + 24 + 8 = 56 bytes.
//! The nested [`FVector::read_from`] reads and the scalar both
//! LWC-widen on `ctx.version.is_lwc()` — the scalar via the shared
//! `read_components::<R, 1>` helper (same `ReadFReal` gate as a
//! vector component), so `FBoxSphereBounds` inherits the widening
//! for free. Same composition pattern as [`super::box_::FBox`] /
//! [`super::transform::FTransform`].
//!
//! # NOT a registry-dispatched StructProperty
//!
//! Like [`super::transform::FTransform`], `FBoxSphereBounds` is
//! **not** registered in the `lookup` dispatch table. A bare
//! `"BoxSphereBounds"` `StructProperty` is tagged-serialized (its
//! fields written as nested NTPL sub-properties), not a raw binary
//! blob — so it must fall through to Phase 2g's tagged-property
//! iteration. Verified against two independent reference parsers at
//! the pinned SHA: CUE4Parse's `FScriptStruct` dispatch has no
//! `"BoxSphereBounds"` arm (it hits the `FStructFallback` default),
//! and UAssetAPI ships binary `PropertyData` for the sibling math
//! types but none for `BoxSphereBounds`.
//!
//! The binary layout decoded here **is** real — it's how
//! `FBoxSphereBounds` appears as a *native-serialized* field
//! (`FStaticMeshRenderData` / `USkeletalMesh` `ImportedBounds`),
//! matching CUE4Parse's `new FBoxSphereBounds(Ar)` constructor.
//! Phase 3g/3h read those via [`FBoxSphereBounds::read_from`]
//! directly (and can emit the [`super::TypedStructValue::BoxSphereBounds`]
//! variant), which is why this decoder ships now as a building block
//! even though nothing registers it. See the "Adding a new struct"
//! HOWTO in [`super`] for the unregistered-building-block convention.

use std::io::{Read, Seek};

use crate::asset::AssetContext;
use crate::asset::structs::vector::FVector;
use crate::asset::structs::{read_components, stream_pos, verify_at_end};

/// Bounding volume: a center `origin`, an axis-aligned half-extent
/// `box_extent`, and a `sphere_radius` for the bounding sphere
/// (both centered on `origin`).
///
/// UE4 = 28 bytes (f32 components), UE5 LWC = 56 bytes (f64
/// components). `sphere_radius` widens f32→f64 under LWC like a
/// vector component (no `Eq`, since it carries an `f64`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FBoxSphereBounds {
    /// Center of both the box and the sphere (wire position 0).
    pub origin: FVector,
    /// Axis-aligned half-extent of the box (wire position 1).
    pub box_extent: FVector,
    /// Radius of the bounding sphere (wire position 2). Widens
    /// f32→f64 under UE5 LWC.
    pub sphere_radius: f64,
}

impl FBoxSphereBounds {
    /// Decode an `FBoxSphereBounds` from `reader`. Reads
    /// `origin: FVector`, `box_extent: FVector`, then a single
    /// LWC-widening `sphere_radius` scalar. The two nested `FVector`
    /// reads are each bounded to their own `expected_end` (the
    /// bounds' start offset plus the running per-component width), so
    /// a short nested read surfaces as the child `FVector`'s
    /// `TypedStructComponent` error; a short `sphere_radius` read is
    /// tagged `FBoxSphereBounds`.
    ///
    /// # Errors
    /// - Any error from the nested [`FVector::read_from`] reads (each
    ///   owns its own `TypedStructComponent` EOF tag).
    /// - [`crate::error::AssetParseFault::UnexpectedEof`] with
    ///   `field = TypedStructComponent { struct_name: "FBoxSphereBounds" }`
    ///   if the `sphere_radius` read hits EOF.
    /// - [`crate::error::AssetParseFault::TypedStructTrailingBytes`] /
    ///   [`crate::error::AssetParseFault::TypedStructOverrun`] if the
    ///   post-decode stream position doesn't match `expected_end`.
    pub fn read_from<R: Read + Seek + ?Sized>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let vec_size = FVector::wire_size(ctx);
        let start = stream_pos(reader, asset_path)?;
        let origin = FVector::read_from(reader, ctx, start + vec_size, asset_path)?;
        let box_extent = FVector::read_from(reader, ctx, start + 2 * vec_size, asset_path)?;
        let [sphere_radius] = read_components::<R, 1>(reader, ctx, "FBoxSphereBounds", asset_path)?;
        verify_at_end(reader, expected_end, "FBoxSphereBounds", asset_path)?;
        Ok(Self {
            origin,
            box_extent,
            sphere_radius,
        })
    }

    /// The on-wire byte size of an `FBoxSphereBounds`: two [`FVector`]s
    /// (`origin`, `box_extent`) plus one LWC-widening scalar (`sphere_radius`).
    /// UE4 = `2 × 12 + 4 = 28`; UE5 LWC = `2 × 24 + 8 = 56`. Lets composing
    /// decoders (e.g. `FStaticMeshRenderData`) bound their `expected_end`
    /// without open-coding the layout.
    #[must_use]
    pub(crate) fn wire_size(ctx: &AssetContext) -> u64 {
        2 * FVector::wire_size(ctx) + crate::asset::structs::lwc_component_width(ctx)
    }
}

// NOTE: no `read_fboxspherebounds` registry shim. A `read_f*` shim
// exists only to feed the dispatch registry, and `FBoxSphereBounds`
// is deliberately unregistered (see module docs) — a shim would be
// permanently dead code. Phase 3g/3h build the
// `TypedStructValue::BoxSphereBounds` variant by calling
// `FBoxSphereBounds::read_from` and wrapping the result inline.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PaksmithError;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::structs::test_utils::{f32_bytes, f64_bytes};
    use crate::error::{AssetParseFault, AssetWireField};
    use std::io::Cursor;

    /// Build a UE4 `FBoxSphereBounds` wire payload: origin f32×3,
    /// box_extent f32×3, sphere_radius f32.
    fn fbsb_ue4_bytes(origin: [f32; 3], extent: [f32; 3], radius: f32) -> Vec<u8> {
        let mut bytes = f32_bytes(&origin);
        bytes.extend(f32_bytes(&extent));
        bytes.extend(f32_bytes(&[radius]));
        bytes
    }

    #[test]
    fn wire_size_matches_ue4_and_lwc_layout() {
        assert_eq!(
            FBoxSphereBounds::wire_size(&make_ctx_with_version(510, None)),
            28
        );
        assert_eq!(
            FBoxSphereBounds::wire_size(&make_ctx_with_version(510, Some(1004))),
            56
        );
    }

    #[test]
    fn ue4_fboxspherebounds_decodes_28_bytes() {
        // Distinct origin / extent / radius so a field-order swap
        // surfaces as a value mismatch.
        let bytes = fbsb_ue4_bytes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 7.0);
        assert_eq!(bytes.len(), 28);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBoxSphereBounds::read_from(&mut cur, &ctx, 28, "test.uasset").expect("read");
        assert!((b.origin.x - 1.0).abs() < f64::EPSILON);
        assert!((b.origin.z - 3.0).abs() < f64::EPSILON);
        assert!((b.box_extent.x - 4.0).abs() < f64::EPSILON);
        assert!((b.box_extent.z - 6.0).abs() < f64::EPSILON);
        assert!((b.sphere_radius - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_fboxspherebounds_decodes_56_bytes() {
        // UE5 LWC gate at 1004 — both vectors AND sphere_radius widen
        // to f64. The radius `123456789.5` is exact in f64 but NOT in
        // f32 (it needs >24 mantissa bits at that magnitude), so it
        // pins that sphere_radius is read as a full f64, not an
        // f32-then-widened value (which would lose the .5 / low bits).
        const RADIUS: f64 = 123_456_789.5;
        let mut bytes = f64_bytes(&[1.0, 2.0, 3.0]);
        bytes.extend(f64_bytes(&[4.0, 5.0, 6.0]));
        bytes.extend(f64_bytes(&[RADIUS]));
        assert_eq!(bytes.len(), 56);
        let ctx = make_ctx_with_version(510, Some(1004));
        let mut cur = Cursor::new(bytes.as_slice());
        let b = FBoxSphereBounds::read_from(&mut cur, &ctx, 56, "test.uasset").expect("read");
        assert!((b.origin.y - 2.0).abs() < f64::EPSILON);
        assert!((b.box_extent.y - 5.0).abs() < f64::EPSILON);
        // Bit-exact round-trip (f64 wire → f64 store): the diff is
        // exactly 0.0. An f32-then-widened read would lose the low
        // bits and blow past EPSILON.
        assert!((b.sphere_radius - RADIUS).abs() < f64::EPSILON);
    }

    #[test]
    fn fbsb_eof_in_nested_origin_routes_to_fvector() {
        // 8 bytes — the origin FVector (needs 12) hits EOF mid-read.
        // The nested FVector::read_from owns this error → FVector tag.
        let bytes = f32_bytes(&[1.0, 2.0]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBoxSphereBounds::read_from(&mut cur, &ctx, 28, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FVector"
                        },
                    },
                    ..
                }
            ),
            "expected nested UnexpectedEof(TypedStructComponent(FVector)), got {err:?}"
        );
    }

    #[test]
    fn fbsb_eof_in_nested_box_extent_routes_to_fvector() {
        // 16 bytes — origin (12) present, box_extent FVector hits EOF
        // after 4 bytes. Still routes to the nested FVector.
        let mut bytes = f32_bytes(&[1.0, 2.0, 3.0]);
        bytes.extend(f32_bytes(&[4.0]));
        assert_eq!(bytes.len(), 16);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBoxSphereBounds::read_from(&mut cur, &ctx, 28, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FVector"
                        },
                    },
                    ..
                }
            ),
            "expected nested UnexpectedEof(TypedStructComponent(FVector)), got {err:?}"
        );
    }

    #[test]
    fn fbsb_eof_in_sphere_radius_routes_to_fboxspherebounds() {
        // 24 bytes — both FVectors (12+12) present, but the
        // sphere_radius scalar hits EOF. The scalar read is tagged
        // FBoxSphereBounds (NOT FVector), since read_from owns it.
        let mut bytes = f32_bytes(&[1.0, 2.0, 3.0]);
        bytes.extend(f32_bytes(&[4.0, 5.0, 6.0]));
        assert_eq!(bytes.len(), 24);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBoxSphereBounds::read_from(&mut cur, &ctx, 28, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TypedStructComponent {
                            struct_name: "FBoxSphereBounds"
                        },
                    },
                    ..
                }
            ),
            "expected UnexpectedEof(TypedStructComponent(FBoxSphereBounds)), got {err:?}"
        );
    }

    #[test]
    fn fbsb_trailing_bytes_rejected() {
        let mut bytes = fbsb_ue4_bytes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 7.0);
        bytes.extend_from_slice(&[0u8; 4]);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBoxSphereBounds::read_from(&mut cur, &ctx, 32, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructTrailingBytes {
                        struct_name,
                        trailing,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FBoxSphereBounds");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes(FBoxSphereBounds), got {other:?}"),
        }
    }

    #[test]
    fn fbsb_overrun_rejected() {
        // 28 wire bytes but expected_end = 24 (mid-radius). The two
        // FVectors consume 24, the radius consumes 4 → stream at 28,
        // verify_at_end sees the 4-byte overrun.
        let bytes = fbsb_ue4_bytes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 7.0);
        let ctx = make_ctx_with_version(510, None);
        let mut cur = Cursor::new(bytes.as_slice());
        let err = FBoxSphereBounds::read_from(&mut cur, &ctx, 24, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TypedStructOverrun {
                        struct_name,
                        overrun,
                    },
                ..
            } => {
                assert_eq!(struct_name, "FBoxSphereBounds");
                assert_eq!(overrun, 4u64);
            }
            other => panic!("expected TypedStructOverrun(FBoxSphereBounds), got {other:?}"),
        }
    }
}
