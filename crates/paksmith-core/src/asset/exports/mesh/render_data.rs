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
//! so the unconsumed UE5 tail is harmless — for every UE5 version: the 5.4+
//! trailing `FStripDataFlags`, the 5.4 distance-field float-ization, and the
//! 5.5 ray-tracing-proxy block all sit in that never-consumed tail (#643).
//!
//! Pre-4.23 uses the legacy `SerializeBuffersLegacy` LOD layout (see
//! [`super::lod::read_lod_legacy`]). This is a **deliberately UNVERIFIED** path
//! (#561): paksmith has no real pre-4.23 cooked fixture, so it is validated only
//! against synthetic fixtures built from the CUE4Parse oracle reading. The legacy
//! branch is reachable only for object version `≤ 516` (UE4 `≤ 4.20` — object 517
//! collapses 4.21/4.22 with 4.23 and routes to the new reader); it is **tested at
//! object 516** (~UE4.20). Even at 516 the shared distance-field block applies its
//! class-strip bit unconditionally where the oracle gates it on `Game >= UE4_21`
//! (object 517+) — an un-exercised desync edge if that bit is set. The object
//! 504–515 (UE4 ≤4.19) sub-band has two further unverified edges (see
//! [`super::lod::read_lod_legacy`]
//! for the full list) and may desync. Some CUE4Parse branches stay unreachable /
//! undecoded:
//!
//! - `minMobileLODIdx` — `StaticMesh.KeepMobileMinLODSettingOnDesktop` is `false`
//!   for stock games, so it is never serialized.
//! - the streaming-texture-factor block (UE4 path) — gated on
//!   `FRenderingObjectVersion < TextureStreamingMeshUVChannelData` (added UE4.15),
//!   so it is absent at object 516 (~UE4.20) and 4.23+. A UE4.14 asset (below the
//!   gate) would carry it — an UNVERIFIED lower-edge limitation.
//! - the pre-4.14 trailing bool.
//!
//! Per-LOD distance-field data (`bValid == true`, UE4 path) is validated-skipped:
//! a present `FDistanceFieldVolumeData` is consumed off the wire (it is irrelevant
//! to glTF geometry) so the already-parsed LOD geometry is returned instead of
//! degrading to a property bag. For cooked meshes that lack mesh distance fields
//! the per-LOD `bValid` flags are all `false`. (UE5 returns before the
//! distance-field block, so it is not consulted.)

use std::io::Cursor;

use crate::asset::structs::bounds::FBoxSphereBounds;
use crate::asset::structs::vector::FVector;
use crate::asset::wire::{STRIP_FLAG_AV_DATA, read_strip_data_flags};
use crate::asset::{AssetContext, StaticMeshRenderData};
use crate::error::AssetWireField;

use super::lod::{read_lod, read_lod_legacy};
use super::read;

/// Max LODs per static mesh (`MAX_STATIC_LODS_UE4`). Stock UE caps at 8; used
/// to bound the LOD-array count before the read loop.
pub(crate) const MAX_LODS_PER_MESH: u32 = 8;

/// Fixed on-wire `ScreenSize` array length for UE 4.9+ (`MAX_STATIC_LODS_UE4`).
const SCREEN_SIZE_COUNT: usize = 8;

/// Sanity bound on a `CompressedDistanceFieldVolume` `TArray<byte>` length.
/// Distance-field volumes are small relative to mesh geometry; the validated
/// skip is allocation-free, so this mainly rejects a wild or negative count
/// before the cursor advance. 256 MiB.
const MAX_DISTANCE_FIELD_VOLUME_BYTES: u32 = 256 * 1024 * 1024;

/// Fixed middle of `FDistanceFieldVolumeData` (UE4.16+): `Size` (`FIntVector`,
/// 12B) + `LocalBoundingBox` (`FBox` = 2×`FVector` + `u8`, 25B) + `DistanceMinMax`
/// (`FVector2D`, 8B). The DF block is UE4-only, so `FVector`/`FBox` are always the
/// 4-byte-float layout (no UE5 LWC widening).
const DISTANCE_FIELD_FIXED_BYTES: u64 = 12 + 25 + 8;

// The distance-field block's class-strip flag (CUE4Parse `IsClassDataStripped(0x01)`).
const DISTANCE_FIELD_STRIP: u8 = 0x01;

/// Read an `FStaticMeshRenderData` — pre-4.23 legacy (UNVERIFIED, see
/// [`super::lod::read_lod_legacy`]), UE 4.23–4.27 (full record), or UE 5.0–5.3
/// (geometry-only: the classic LOD array, returning before the un-decoded Nanite
/// tail; see the module docs).
///
/// # Errors
/// [`crate::PaksmithError`] from a truncated / corrupt record.
pub(crate) fn read_render_data(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<StaticMeshRenderData> {
    // Pre-UE4.23 uses the legacy `SerializeBuffersLegacy` LOD layout
    // (`!StaticMesh.UseNewCookedFormat`); 4.23+ / UE5 use the new-cooked path. See
    // [`read_lod_legacy`] for the legacy path's deliberate UNVERIFIED contract (#561).
    let legacy = !ctx.version.is_ue4_23_or_later();

    let lod_count = read::read_capped_count(
        cur,
        asset_path,
        AssetWireField::MeshLodCount,
        MAX_LODS_PER_MESH,
    )?;
    let mut lods = Vec::with_capacity(lod_count as usize);
    for _ in 0..lod_count {
        lods.push(if legacy {
            read_lod_legacy(cur, ctx, asset_path)?
        } else {
            read_lod(cur, ctx, asset_path)?
        });
    }

    // numInlinedLODs (u8) — UE 4.23+ only, read-and-discarded (absent in the legacy
    // pre-4.23 render data).
    if !legacy {
        let _num_inlined_lods = read::read_u8(cur, asset_path, AssetWireField::MeshNumInlinedLods)?;
    }

    // UE5 geometry-only boundary. For every accepted UE5 version, an un-decoded
    // `FNaniteResources` blob plus the inline-data-representations block (and at
    // 5.4/5.5 further tail changes, #643) follow `numInlinedLODs`; the
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
/// payload follows, which [`read_distance_field_volume_data`] validated-skips.
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
            read_distance_field_volume_data(cur, asset_path)?;
        }
    }
    Ok(())
}

/// Validated-skip a present `FDistanceFieldVolumeData` (UE4.16+ layout — the only
/// branch reachable, since the distance-field block is UE4-only and gated `>= 4.23`).
/// The volume data is irrelevant to glTF geometry export, so it is consumed (not
/// materialised) to land the cursor on the following `Bounds`.
///
/// Wire order (oracle `DistanceFieldAtlas.cs` `FDistanceFieldVolumeData`,
/// `Ar.Game >= GAME_UE4_16`): the `CompressedDistanceFieldVolume` `TArray<byte>`
/// (`i32` count + that many bytes), then `Size` / `LocalBoundingBox` /
/// `DistanceMinMax` ([`DISTANCE_FIELD_FIXED_BYTES`]), then three `bMeshWas*`
/// `bool32`s read strictly (a desync surfaces as a non-0/1 bool rather than
/// silently mis-aligning the tail).
fn read_distance_field_volume_data(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<()> {
    let compressed_len = read::read_capped_count(
        cur,
        asset_path,
        AssetWireField::MeshDistanceFieldVolume,
        MAX_DISTANCE_FIELD_VOLUME_BYTES,
    )?;
    read::skip(
        cur,
        u64::from(compressed_len) + DISTANCE_FIELD_FIXED_BYTES,
        asset_path,
        AssetWireField::MeshDistanceFieldVolume,
    )?;
    for _ in 0..3 {
        let _ = crate::asset::wire::read_bool32(
            cur,
            asset_path,
            AssetWireField::MeshDistanceFieldVolume,
        )?;
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
    use crate::error::PaksmithError;

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

    #[cfg(feature = "__test_utils")]
    #[test]
    fn legacy_pre423_render_data_decodes_geometry() {
        use super::super::lod::test_support::legacy_lod_ue4_20;

        // Object version 516 (~UE4.20) is below the 4.23 new-cooked-format boundary,
        // so the legacy `SerializeBuffersLegacy` LOD path is taken. UNVERIFIED-by-
        // construction (no real pre-4.23 fixture exists) — see the `read_render_data`
        // / `read_lod_legacy` docs for the deliberate UNVERIFIED contract.
        let ctx = make_ctx_with_version(516, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&legacy_lod_ue4_20());
        // Legacy render-data tail: NO numInlinedLODs (that field is 4.23+). The
        // distance-field block + Bounds + bLODsShareStaticLighting + 8
        // FPerPlatformFloats are shared with the new-format UE4 path.
        bytes.push(0x00); // distance-field GlobalStripFlags (not stripped)
        bytes.push(0x00); // distance-field ClassStripFlags
        write_bool32(&mut bytes, false).unwrap(); // per-LOD bValid = 0
        bytes.extend_from_slice(&[0u8; 28]); // Bounds
        write_bool32(&mut bytes, true).unwrap(); // bLODsShareStaticLighting
        for _ in 0..8 {
            write_bool32(&mut bytes, true).unwrap();
            bytes.extend_from_slice(&0.5f32.to_le_bytes());
        }
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every legacy render-data byte"
        );
        assert_eq!(rd.lods.len(), 1);
        assert_eq!(rd.lods[0].positions.len(), 3, "legacy geometry decoded");
        assert_eq!(rd.lods[0].indices, vec![0, 1, 2]);
        assert_eq!(rd.screen_sizes.len(), 8);
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

    /// Emit a UE4.16+ `FDistanceFieldVolumeData` payload (the only branch
    /// paksmith reaches — the DF block is UE4-only and gated `>= 4.23`):
    /// `CompressedDistanceFieldVolume` (`TArray<byte>` = `i32` count + bytes),
    /// then `Size` (`FIntVector`, 12B) + `LocalBoundingBox` (`FBox`, 25B) +
    /// `DistanceMinMax` (`FVector2D`, 8B) = 45 fixed bytes, then 3 × `bool32`
    /// (`bMeshWasClosed` / `bBuiltAsIfTwoSided` / `bMeshWasPlane`).
    fn distance_field_volume_4_16(compressed: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&i32::try_from(compressed.len()).unwrap().to_le_bytes());
        b.extend_from_slice(compressed);
        b.extend_from_slice(&[0u8; 45]); // Size(12) + FBox(25) + DistanceMinMax(8)
        write_bool32(&mut b, true).unwrap(); // bMeshWasClosed
        write_bool32(&mut b, false).unwrap(); // bBuiltAsIfTwoSided
        write_bool32(&mut b, true).unwrap(); // bMeshWasPlane
        b
    }

    #[test]
    fn distance_field_present_decodes_geometry_and_consumes_exactly() {
        // A UE4.23 mesh whose distance-field block is not stripped and whose
        // single per-LOD bValid is true → the FDistanceFieldVolumeData payload
        // is validated-skipped, the cursor lands on Bounds, and the already-
        // parsed LOD geometry is returned (instead of UnsupportedFeature).
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        bytes.push(0x00); // numInlinedLODs
        bytes.push(0x00); // distance-field GlobalStripFlags (not stripped)
        bytes.push(0x00); // distance-field ClassStripFlags
        write_bool32(&mut bytes, true).unwrap(); // per-LOD bValid = 1
        bytes.extend_from_slice(&distance_field_volume_4_16(&[0xAB; 6])); // DF payload
        bytes.extend_from_slice(&[0u8; 28]); // Bounds
        write_bool32(&mut bytes, true).unwrap(); // bLODsShareStaticLighting
        for _ in 0..8 {
            write_bool32(&mut bytes, true).unwrap();
            bytes.extend_from_slice(&0.5f32.to_le_bytes());
        }
        let mut cur = Cursor::new(bytes.as_slice());
        let rd = read_render_data(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed every byte including the distance-field volume"
        );
        assert_eq!(rd.lods.len(), 1);
        assert_eq!(rd.lods[0].positions.len(), 3); // geometry survived the DF skip
        assert_eq!(rd.lods[0].indices, vec![0, 1, 2]);
        assert!(rd.lods_share_static_lighting);
        assert_eq!(rd.screen_sizes.len(), 8);
    }

    #[test]
    fn distance_field_volume_cap_is_256_mib() {
        // Pin the exact cap so an arithmetic-operator mutation in its
        // `256 * 1024 * 1024` definition is caught. The boundary test below
        // derives both its input and expected limit from the constant
        // symbolically, so it would NOT catch such a mutant — this
        // hard-coded-value assertion is what does.
        assert_eq!(MAX_DISTANCE_FIELD_VOLUME_BYTES, 268_435_456);
    }

    #[test]
    fn distance_field_volume_over_cap_is_rejected() {
        // A CompressedDistanceFieldVolume length one past the cap is rejected
        // before the cursor advance. Pins the cap as `>` (not `>=`).
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        bytes.push(0x00); // numInlinedLODs
        bytes.push(0x00); // distance-field GlobalStripFlags
        bytes.push(0x00); // distance-field ClassStripFlags
        write_bool32(&mut bytes, true).unwrap(); // per-LOD bValid = 1
        let over = i32::try_from(MAX_DISTANCE_FIELD_VOLUME_BYTES).unwrap() + 1;
        bytes.extend_from_slice(&over.to_le_bytes()); // CompressedDistanceFieldVolume len
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_render_data(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::BoundsExceeded {
                    field: AssetWireField::MeshDistanceFieldVolume,
                    limit,
                    ..
                },
                ..
            } if limit == u64::from(MAX_DISTANCE_FIELD_VOLUME_BYTES)
        ));
    }

    #[test]
    fn distance_field_volume_non_bool_is_rejected() {
        // A present DF volume whose bMeshWasClosed bool32 is neither 0 nor 1 is
        // rejected strictly — pins the trailing `read_bool32` reads against a lax
        // 12-byte skip that would silently accept the corruption.
        let ctx = make_ctx_with_version(517, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes()); // LOD count = 1
        bytes.extend_from_slice(&inlined_lod_ue4_23());
        bytes.push(0x00); // numInlinedLODs
        bytes.push(0x00); // distance-field GlobalStripFlags
        bytes.push(0x00); // distance-field ClassStripFlags
        write_bool32(&mut bytes, true).unwrap(); // per-LOD bValid = 1
        bytes.extend_from_slice(&0i32.to_le_bytes()); // CompressedDistanceFieldVolume len 0
        bytes.extend_from_slice(&[0u8; 45]); // Size + FBox + DistanceMinMax
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bMeshWasClosed = 2 → invalid bool
        let mut cur = Cursor::new(bytes.as_slice());
        let err = read_render_data(&mut cur, &ctx, "T").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::InvalidBool32 {
                    field: AssetWireField::MeshDistanceFieldVolume,
                    observed: 2,
                },
                ..
            }
        ));
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
