//! `FStaticMeshRenderData` reader (Phase 3g).
//!
//! Assembles the per-LOD [`super::lod`] resources into the mesh-level render
//! data: the LOD array, the mesh bounds, the LOD-shares-static-lighting flag,
//! and the per-LOD screen sizes. Wire-format reference:
//! `docs/formats/mesh/static-mesh.md` §`FStaticMeshRenderData`; oracle
//! `FabianFG/CUE4Parse` `FStaticMeshRenderData.cs` (`ca637ae`).
//!
//! # Scope: UE 4.23–4.27 (full tail) + UE 5.0–5.3 (geometry-only)
//!
//! For UE4.23–4.27 the full record is read: LOD array, `numInlinedLODs`, the
//! distance-field block, `Bounds`, `bLODsShareStaticLighting`, and the per-LOD
//! `ScreenSize` array.
//!
//! For UE5.0–5.3 the reader stops after `numInlinedLODs` and returns
//! **geometry-only** (default `Bounds`, empty `ScreenSize`). Per the oracle, an
//! `FNaniteResources` blob plus the inline-data-representations block follow
//! `numInlinedLODs` for UE5; neither is decoded, and the post-blob `Bounds` /
//! `ScreenSize` are therefore unreachable. The classic LOD array (read first) is
//! the renderable geometry, and the export framework dispatches the next export
//! by table offset, not cursor position (see [`super::static_mesh::read_from`]),
//! so the unconsumed UE5 tail is harmless. UE5.4+ is rejected at the package
//! level (`FIRST_UNSUPPORTED_UE5_VERSION`), so the UE5.4+ trailing
//! `FStripDataFlags` and the 5.5+/5.6+ additions are never reached.
//!
//! The pre-4.23 legacy LOD format is surfaced as
//! [`crate::error::PaksmithError::UnsupportedFeature`] (the legacy
//! `FStaticMeshLODResources` layout differs). Restricting to UE4.23+ also keeps
//! several CUE4Parse branches unreachable, so they are not decoded:
//!
//! - `minMobileLODIdx` — `StaticMesh.KeepMobileMinLODSettingOnDesktop` is `false`
//!   for stock games, so it is never serialized.
//! - the streaming-texture-factor block (UE4 path) — gated on
//!   `FRenderingObjectVersion < TextureStreamingMeshUVChannelData` (added UE4.15),
//!   always past for 4.23+. **UNVERIFIED proxy:** assumed never-present for the
//!   4.23+ range; a wrong assumption here would be a 36-byte desync, but the gate
//!   corresponds to a pre-4.15 custom-version that 4.23+ assets are well beyond.
//! - the pre-4.14 trailing bool.
//!
//! Per-LOD distance-field data (`bValid == true`, UE4 path) is also unsupported
//! (the `FDistanceFieldVolumeData` decoder is a later milestone); for cooked
//! meshes that lack mesh distance fields the per-LOD `bValid` flags are all
//! `false`. (UE5 returns before the distance-field block, so it is not consulted.)

use std::io::Cursor;

use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::structs::vector::FVector;
use crate::asset::wire::{STRIP_FLAG_AV_DATA, read_strip_data_flags};
use crate::asset::{AssetContext, StaticMeshRenderData};
use crate::error::{AssetWireField, PaksmithError};

use super::lod::read_lod;
use super::read;

/// Max LODs per static mesh (`MAX_STATIC_LODS_UE4`). Stock UE caps at 8; used
/// to bound the LOD-array count before the read loop.
pub(crate) const MAX_LODS_PER_MESH: u32 = 8;

/// Fixed on-wire `ScreenSize` array length for UE 4.9+ (`MAX_STATIC_LODS_UE4`).
const SCREEN_SIZE_COUNT: usize = 8;

// The distance-field block's class-strip flag (CUE4Parse `IsClassDataStripped(0x01)`).
const DISTANCE_FIELD_STRIP: u8 = 0x01;

/// Read an `FStaticMeshRenderData` — UE 4.23–4.27 (full record) or UE 5.0–5.3
/// (geometry-only: the classic LOD array, returning before the un-decoded Nanite
/// tail; see the module docs).
///
/// # Errors
/// - [`PaksmithError::UnsupportedFeature`] for the pre-4.23 legacy format or,
///   on the UE4 path, per-LOD distance-field data.
/// - [`crate::PaksmithError`] from a truncated / corrupt record.
pub(crate) fn read_render_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<StaticMeshRenderData> {
    if !ctx.version.is_ue4_23_or_later() {
        return Err(PaksmithError::UnsupportedFeature {
            context: "pre-UE4.23 legacy FStaticMeshRenderData LOD format — Phase 3g+".to_string(),
        });
    }

    let lod_count = read::read_capped_count(
        cur,
        asset_path,
        AssetWireField::MeshLodCount,
        MAX_LODS_PER_MESH,
    )?;
    let mut lods = Vec::with_capacity(lod_count as usize);
    for _ in 0..lod_count {
        lods.push(read_lod(cur, ctx, asset_path)?);
    }

    // numInlinedLODs (u8) — UE 4.23+, read-and-discarded.
    let _num_inlined_lods = read::read_u8(cur, asset_path, AssetWireField::MeshNumInlinedLods)?;

    // UE5 geometry-only boundary. For UE5.0–5.3 (≥5.4 is rejected at the package
    // level, `FIRST_UNSUPPORTED_UE5_VERSION`), an un-decoded `FNaniteResources`
    // blob plus the inline-data-representations block follow `numInlinedLODs`; the
    // distance-field / bounds / screen-size tail sits past them. The classic LOD
    // array above is the renderable geometry, so we stop and return geometry-only.
    // The unconsumed tail is harmless: the export framework dispatches the next
    // export by table offset, not cursor position (see `static_mesh::read_from`).
    if ctx.version.is_ue5() {
        let zero = FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        return Ok(StaticMeshRenderData {
            lods,
            bounds: FBoxSphereBounds {
                origin: zero,
                box_extent: zero,
                sphere_radius: 0.0,
            },
            lods_share_static_lighting: false,
            screen_sizes: Vec::new(),
        });
    }

    read_distance_field_block(cur, asset_path, lods.len())?;

    // Bounds — native FBoxSphereBounds (UE4: 28 bytes; the UE5 LWC 56-byte layout
    // returns early above, so this is always the f32 layout, but `wire_size` keeps
    // it version-correct).
    let bounds_end = cur.position() + FBoxSphereBounds::wire_size(ctx);
    let bounds = FBoxSphereBounds::read_from(cur, ctx, bounds_end, asset_path)?;

    let lods_share_static_lighting =
        crate::asset::wire::read_bool32(cur, asset_path, AssetWireField::MeshLodShareLighting)?;

    let mut screen_sizes = Vec::with_capacity(SCREEN_SIZE_COUNT);
    for _ in 0..SCREEN_SIZE_COUNT {
        screen_sizes.push(read_per_platform_float(cur, asset_path)?);
    }

    Ok(StaticMeshRenderData {
        lods,
        bounds,
        lods_share_static_lighting,
        screen_sizes,
    })
}

/// Consume the per-LOD distance-field block: an `FStripDataFlags` pair, then —
/// when neither audio-visual nor the distance-field class flag is stripped — a
/// per-LOD `bValid` `u32` bool. A `true` `bValid` means an `FDistanceFieldVolumeData`
/// payload follows, which this milestone does not decode → `UnsupportedFeature`.
fn read_distance_field_block(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    lod_count: usize,
) -> crate::Result<()> {
    let (global, class) =
        read_strip_data_flags(cur, asset_path, AssetWireField::MeshDistanceField)?;
    let stripped = global & STRIP_FLAG_AV_DATA != 0 || class & DISTANCE_FIELD_STRIP != 0;
    if stripped {
        return Ok(());
    }
    for _ in 0..lod_count {
        let b_valid =
            crate::asset::wire::read_bool32(cur, asset_path, AssetWireField::MeshDistanceField)?;
        if b_valid {
            return Err(PaksmithError::UnsupportedFeature {
                context: "FStaticMeshRenderData per-LOD distance-field data \
                          (FDistanceFieldVolumeData) — Phase 3g+"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// Read a cooked `FPerPlatformFloat`: `bCooked` (`u32` bool) + `Value` (`f32`).
/// The per-platform override map is editor-only (`!IsFilterEditorOnly`), so it
/// is absent for the cooked assets paksmith targets; only the `Default` value is
/// present. Returns `Value`.
fn read_per_platform_float(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<f32> {
    let _b_cooked =
        crate::asset::wire::read_bool32(cur, asset_path, AssetWireField::MeshScreenSize)?;
    read::read_f32(cur, asset_path, AssetWireField::MeshScreenSize)
}

#[cfg(test)]
mod tests {
    use super::super::lod::test_support::{inlined_lod_ue4_23, inlined_lod_ue5_0, ue5_release_ctx};
    use super::*;
    use crate::asset::custom_version::REMOVING_TESSELLATION;
    use crate::asset::property::test_utils::make_ctx_with_version;
    use crate::asset::wire::write_bool32;

    /// The render-data fields that follow the LOD array: numInlinedLODs, the
    /// distance-field strip + `lod_count` `bValid` bools (all `false`), a 28-byte
    /// UE4 Bounds, bLODsShareStaticLighting, and 8 `FPerPlatformFloat`s
    /// (`bCooked` + value `0.5`).
    fn render_data_tail(buf: &mut Vec<u8>, lod_count: usize) {
        buf.push(0x00); // numInlinedLODs
        buf.push(0x00); // distance-field GlobalStripFlags (not stripped)
        buf.push(0x00); // distance-field ClassStripFlags
        for _ in 0..lod_count {
            write_bool32(buf, false).unwrap(); // per-LOD bValid = 0
        }
        buf.extend_from_slice(&[0u8; 28]); // Bounds
        write_bool32(buf, true).unwrap(); // bLODsShareStaticLighting
        for _ in 0..8 {
            write_bool32(buf, true).unwrap();
            buf.extend_from_slice(&0.5f32.to_le_bytes());
        }
    }

    #[test]
    fn one_lod_render_data_decodes_and_consumes_exactly() {
        let ctx = make_ctx_with_version(517, None); // UE4.23
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        render_data_tail(&mut bytes, 1);
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every render-data byte"
        );
        assert_eq!(rd.lods.len(), 1);
        assert_eq!(rd.lods[0].positions.len(), 3);
        assert_eq!(rd.lods[0].indices, vec![0, 1, 2]);
        assert!(rd.lods_share_static_lighting);
        assert_eq!(rd.screen_sizes.len(), 8);
        assert!((rd.screen_sizes[0] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn zero_lod_render_data_consumes_exactly() {
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0i32.to_le_bytes()); // LOD count = 0
        render_data_tail(&mut bytes, 0);
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert!(rd.lods.is_empty());
        assert_eq!(rd.screen_sizes.len(), 8);
    }

    #[test]
    fn ue5_render_data_decodes_geometry_only() {
        // A UE5.0 cooked static mesh: the classic LOD array decodes (geometry),
        // then the FNaniteResources + inline-data-representations tail follows.
        // paksmith does not parse that tail (the export framework dispatches the
        // next export by table offset, not cursor position), so the reader returns
        // geometry-only — it must NOT attempt the distance-field / bounds /
        // screen-size reads, which sit past the un-decoded Nanite blob and would
        // desync. Trailing garbage stands in for the Nanite blob and must be left
        // untouched.
        let ctx = ue5_release_ctx(REMOVING_TESSELLATION);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue5_0());
        bytes.push(0x00); // numInlinedLODs
        bytes.extend_from_slice(&[0xAB; 32]); // FNaniteResources blob (ignored)
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(rd.lods.len(), 1);
        assert_eq!(rd.lods[0].positions.len(), 3);
        assert_eq!(rd.lods[0].indices, vec![0, 1, 2]);
    }

    #[test]
    fn pre_4_23_render_data_is_unsupported() {
        // Object version 516 (UE4.20) is below the new-cooked-format boundary.
        let ctx = make_ctx_with_version(516, None);
        let mut cur = Cursor::new([].as_slice());
        let err = read_render_data(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    #[test]
    fn lod_count_over_cap_is_rejected() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = (i32::try_from(MAX_LODS_PER_MESH).unwrap() + 1).to_le_bytes();
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_render_data(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BoundsExceeded {
                    field: AssetWireField::MeshLodCount,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_LODS_PER_MESH)
        ));
    }

    #[test]
    fn distance_field_present_is_unsupported() {
        // A 0-LOD mesh whose distance-field block is not stripped and whose
        // (single, fabricated) per-LOD bValid is true → unsupported. Build with
        // 1 LOD so there is a bValid to set.
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        bytes.push(0x00); // numInlinedLODs
        bytes.push(0x00); // distance-field GlobalStripFlags (not stripped)
        bytes.push(0x00); // distance-field ClassStripFlags
        write_bool32(&mut bytes, true).unwrap(); // per-LOD bValid = 1 → unsupported
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_render_data(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(err, PaksmithError::UnsupportedFeature { .. }));
    }

    /// Build a 1-LOD render data whose distance-field block uses the given strip
    /// bytes and emits **no** per-LOD `bValid` (i.e. the block is expected to be
    /// treated as stripped). The render data must still parse + consume exactly.
    fn render_data_distance_field_stripped(global: u8, class: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        bytes.push(0x00); // numInlinedLODs
        bytes.push(global); // distance-field GlobalStripFlags
        bytes.push(class); // distance-field ClassStripFlags
        // No per-LOD bValid — stripped.
        bytes.extend_from_slice(&[0u8; 28]); // Bounds
        write_bool32(&mut bytes, true).unwrap(); // bLODsShareStaticLighting
        for _ in 0..8 {
            write_bool32(&mut bytes, true).unwrap();
            bytes.extend_from_slice(&0.0f32.to_le_bytes());
        }
        bytes
    }

    /// Audio-visual-stripped distance-field block (`GlobalStripFlags` bit 1):
    /// no per-LOD `bValid` follows. Pins the AV-strip bit and the `||` in the
    /// stripped predicate (an `&&` mutant would read a phantom `bValid`).
    #[test]
    fn distance_field_av_stripped_skips_per_lod_flags() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = render_data_distance_field_stripped(STRIP_FLAG_AV_DATA, 0);
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert_eq!(rd.lods.len(), 1);
    }

    /// Class-stripped distance-field block (`ClassStripFlags` bit 0): likewise no
    /// per-LOD `bValid`. Pins the class-strip bit and the other `||` arm.
    #[test]
    fn distance_field_class_stripped_skips_per_lod_flags() {
        let ctx = make_ctx_with_version(517, None);
        let bytes = render_data_distance_field_stripped(0, DISTANCE_FIELD_STRIP);
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert_eq!(rd.lods.len(), 1);
    }
}
