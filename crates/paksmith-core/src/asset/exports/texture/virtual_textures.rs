//! `FVirtualTextureBuiltData` structural parse (Phase 3e-VT-b1).
//!
//! A virtual texture replaces a `UTexture2D`'s standard mip chain with a
//! sparse/paged tile representation (see `docs/formats/texture/virtual-textures.md`).
//! When the `UTexture2D` reader sees `bIsVirtual == true` (3e-VT-a), it calls
//! [`read_from`] to decode the trailing `FVirtualTextureBuiltData` blob.
//!
//! **3e-VT-b1 scope: the structural fields only** — the fixed header, both
//! dispatch paths (the always-serialized legacy arrays + the UE5.0+ trio), the
//! [`FVirtualTextureTileOffsetData`](TileOffsetData) sub-records, the per-layer
//! `LayerTypes`, and (UE5.0+) `LayerFallbackColors`. The parse **stops before
//! the `Chunks` array** — the `FVirtualTextureDataChunk[]` records (which carry
//! the actual tile bytes via `FByteBulkData`) and their resolver routing are
//! 3e-VT-b2; the page-table flatten to pixels is 3e-VT-c. paksmith already
//! stops at the export's `serial_size` boundary, so leaving the chunk bytes
//! unconsumed is consistent with the non-virtual mip-chain path.
//!
//! **Version gating** (verified against CUE4Parse `FVirtualTextureBuiltData`
//! `@cf74fc32` + the wire-format doc): the `TileDataOffsetPerLayer` array, the
//! `ChunkIndexPerMip`/`BaseOffsetPerMip`/`TileOffsetData` trio, and
//! `LayerFallbackColors` are present only for `Ar.Game >= GAME_UE5_0`, proxied
//! by `file_version_ue5.is_some()` (paksmith rejects uncooked UE5, so any UE5
//! export is `>= 5.0` — the same proxy `skip_stripped_data_prefix` uses). The
//! legacy dispatch arrays and `LayerTypes` are always serialized.
//!
//! **Untrusted input.** Every wire count is attacker-controlled. All counted
//! arrays validate a non-negative `i32` prefix bounded by a project cap before
//! reading, and never pre-allocate to the claimed count (the `Vec` grows only
//! as elements are actually read), so a large count cannot amplify a small
//! input into a large allocation. `NumLayers` is capped at the engine's
//! `VIRTUALTEXTURE_DATA_MAXLAYERS` (8) before the fixed-length layer arrays.

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::read_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

/// Engine cap on `NumLayers` (`VIRTUALTEXTURE_DATA_MAXLAYERS`). CUE4Parse
/// asserts `<= 8`; paksmith rejects larger values to bound the fixed-length
/// `LayerTypes` / `LayerFallbackColors` arrays (`virtual-textures.md` §Caps).
const MAX_VT_LAYERS: u32 = 8;

/// Cap on any flat counted `u32[]` dispatch array (and the inner
/// `Addresses`/`Offsets` of a [`TileOffsetData`]). Real cooked VTs have
/// dispatch arrays in the thousands; a 16384² texture at a 64-px tile is
/// ~87 K tiles, so `1 << 20` (≈ 1 M entries, 4 MiB once fully read) is a
/// generous ceiling that still rejects a `u32::MAX`-count allocation bomb
/// (`virtual-textures.md` §Caps).
const MAX_VT_ARRAY_ENTRIES: i32 = 1 << 20;

/// Cap on the `TileOffsetData[]` record count. The array is per-mip-level
/// (`virtual-textures.md`), so a small bound suffices; `64` exceeds the
/// `log2(16384) ≈ 14` mips of the largest texture with margin. Bounding the
/// record count (each record itself bounded by [`MAX_VT_ARRAY_ENTRIES`])
/// keeps the nested allocation envelope finite.
const MAX_VT_TILE_OFFSET_DATA_RECORDS: i32 = 64;

/// Parsed `FVirtualTextureBuiltData` — the structural (non-chunk) fields.
///
/// `#[non_exhaustive]`: 3e-VT-b2 adds the `chunks` field (the
/// `FVirtualTextureDataChunk[]` tile payloads). `Default` yields an all-empty
/// instance (0 layers, no dispatch) — a degenerate virtual texture, handy for
/// constructing `Texture2DData` fixtures in downstream handler tests.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
pub struct VirtualTextureData {
    /// Layer count (`<= 8`). Drives the fixed-length `layer_types` /
    /// `layer_fallback_colors` arrays.
    pub num_layers: u32,
    /// Texture width in compressed-block units.
    pub width_in_blocks: u32,
    /// Texture height in compressed-block units.
    pub height_in_blocks: u32,
    /// Tile edge length in texels (typical 128 / 256).
    pub tile_size: u32,
    /// Per-edge border for sampling continuity (physical tile =
    /// `tile_size + 2 * tile_border_size`).
    pub tile_border_size: u32,
    /// Mip-level count.
    pub num_mips: u32,
    /// Full-resolution width in texels.
    pub width: u32,
    /// Full-resolution height in texels.
    pub height: u32,
    /// Per-layer byte offsets within a per-tile data block (UE5.0+; empty
    /// below UE5).
    pub tile_data_offset_per_layer: Vec<u32>,
    /// UE5.0+ dispatch: per-mip index into `chunks` (empty below UE5).
    pub chunk_index_per_mip: Vec<u32>,
    /// UE5.0+ dispatch: per-mip base byte offset into the chunk (`~0u`
    /// sentinel = no data for that mip; empty below UE5).
    pub base_offset_per_mip: Vec<u32>,
    /// UE5.0+ dispatch: per-mip tile-address tables (empty below UE5).
    pub tile_offset_data: Vec<TileOffsetData>,
    /// Legacy dispatch: per-chunk first-tile-index (always serialized).
    pub tile_index_per_chunk: Vec<u32>,
    /// Legacy dispatch: per-mip first-tile-index (always serialized).
    pub tile_index_per_mip: Vec<u32>,
    /// Legacy dispatch: per-tile byte offset within its chunk (always
    /// serialized; empty in modern UE5.0+ content, which uses
    /// `tile_offset_data`).
    pub tile_offset_in_chunk: Vec<u32>,
    /// Per-layer `EPixelFormat` names (e.g. `"PF_DXT1"`), one per layer.
    /// Stored as the raw FString (decoded to a `PixelFormat` at flatten time,
    /// 3e-VT-c, the same way [`super::pixel_format::PixelFormat::from_name`]
    /// tolerates unknown names).
    pub layer_types: Vec<String>,
    /// Per-layer fallback RGBA color, used at runtime when a tile can't be
    /// resolved (UE5.0+; empty below UE5). One `[r, g, b, a]` per layer.
    pub layer_fallback_colors: Vec<[f32; 4]>,
}

/// `FVirtualTextureTileOffsetData` (UE5.0+) — a per-mip tile-address dispatch
/// table.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct TileOffsetData {
    /// Tile-grid width at this mip level.
    pub width: u32,
    /// Tile-grid height at this mip level.
    pub height: u32,
    /// Maximum virtual address in this mip's range.
    pub max_address: u32,
    /// Block-start addresses (upper-bound search keys).
    pub addresses: Vec<u32>,
    /// Per-block byte offsets aligned with `addresses` (`~0u` = no data).
    pub offsets: Vec<u32>,
}

fn vt_fault(asset_path: &str, fault: AssetParseFault) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault,
    }
}

fn vt_eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    vt_fault(asset_path, AssetParseFault::UnexpectedEof { field })
}

fn read_u32(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<u32> {
    cur.read_u32::<LittleEndian>()
        .map_err(|_| vt_eof(asset_path, field))
}

/// Read a counted-array `i32` length prefix, mapping EOF to `field` and
/// rejecting a negative or over-`cap` count (`VirtualTextureArrayCountExceeded`)
/// before the caller reads any element — the shared allocation-bomb guard on
/// attacker-controlled wire counts.
fn read_bounded_count(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    field: AssetWireField,
    cap: i32,
) -> crate::Result<i32> {
    let count = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| vt_eof(asset_path, field))?;
    if !(0..=cap).contains(&count) {
        return Err(vt_fault(
            asset_path,
            AssetParseFault::VirtualTextureArrayCountExceeded { field, count, cap },
        ));
    }
    Ok(count)
}

/// Read a counted `u32[]`: a bounded `i32` length prefix then `count`
/// little-endian `u32`s. Does NOT pre-allocate to `count` — the `Vec` grows
/// only as elements are read, so a large count over a short input can't
/// amplify into a large allocation (it EOFs first).
fn read_counted_u32_array(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    cap: i32,
) -> crate::Result<Vec<u32>> {
    let field = AssetWireField::VirtualTextureDispatchArray;
    let count = read_bounded_count(cur, asset_path, field, cap)?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(read_u32(cur, asset_path, field)?);
    }
    Ok(values)
}

/// Read the `TileOffsetData[]` array (UE5.0+): a bounded `i32` record count,
/// then each `FVirtualTextureTileOffsetData` (3 `u32` + two counted `u32[]`).
fn read_tile_offset_data_array(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
) -> crate::Result<Vec<TileOffsetData>> {
    let field = AssetWireField::VirtualTextureTileOffsetData;
    let count = read_bounded_count(cur, asset_path, field, MAX_VT_TILE_OFFSET_DATA_RECORDS)?;
    let mut records = Vec::new();
    for _ in 0..count {
        let width = read_u32(cur, asset_path, field)?;
        let height = read_u32(cur, asset_path, field)?;
        let max_address = read_u32(cur, asset_path, field)?;
        let addresses = read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?;
        let offsets = read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?;
        records.push(TileOffsetData {
            width,
            height,
            max_address,
            addresses,
            offsets,
        });
    }
    Ok(records)
}

/// Parse the structural fields of an `FVirtualTextureBuiltData` blob, leaving
/// the cursor positioned at the `Chunks` array count (3e-VT-b2).
pub(crate) fn read_from(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<VirtualTextureData> {
    let header = AssetWireField::VirtualTextureHeader;

    // bCooked — a 4-byte UE archive bool (CUE4Parse `Ar.ReadBoolean()`,
    // strict {0,1}). Value is unused (cooked VTs are always true), but a
    // non-bool is the earliest sign the blob desynced.
    let b_cooked = read_u32(cur, asset_path, header)?;
    if b_cooked > 1 {
        return Err(vt_fault(
            asset_path,
            AssetParseFault::TextureInvalidCookedBool {
                field: header,
                value: b_cooked,
            },
        ));
    }

    let num_layers = read_u32(cur, asset_path, header)?;
    if num_layers > MAX_VT_LAYERS {
        return Err(vt_fault(
            asset_path,
            AssetParseFault::VirtualTextureLayerCountExceeded {
                count: num_layers,
                cap: MAX_VT_LAYERS,
            },
        ));
    }

    let width_in_blocks = read_u32(cur, asset_path, header)?;
    let height_in_blocks = read_u32(cur, asset_path, header)?;
    let tile_size = read_u32(cur, asset_path, header)?;
    let tile_border_size = read_u32(cur, asset_path, header)?;

    let is_ue5 = ctx.version.file_version_ue5.is_some();

    // TileDataOffsetPerLayer (UE5.0+).
    let tile_data_offset_per_layer = if is_ue5 {
        read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?
    } else {
        Vec::new()
    };

    let num_mips = read_u32(cur, asset_path, header)?;
    let width = read_u32(cur, asset_path, header)?;
    let height = read_u32(cur, asset_path, header)?;

    // UE5.0+ dispatch trio.
    let (chunk_index_per_mip, base_offset_per_mip, tile_offset_data) = if is_ue5 {
        (
            read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?,
            read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?,
            read_tile_offset_data_array(cur, asset_path)?,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    // Legacy dispatch arrays — always serialized (even in UE5.0+ content,
    // where `tile_offset_in_chunk` is empty).
    let tile_index_per_chunk = read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?;
    let tile_index_per_mip = read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?;
    let tile_offset_in_chunk = read_counted_u32_array(cur, asset_path, MAX_VT_ARRAY_ENTRIES)?;

    // LayerTypes — `num_layers` FStrings (fixed length, NO count prefix).
    // `num_layers <= 8`, so the loop and the Vec are bounded.
    let mut layer_types = Vec::new();
    for _ in 0..num_layers {
        layer_types.push(read_asset_fstring(cur, asset_path)?);
    }

    // LayerFallbackColors (UE5.0+) — `num_layers` × `FLinearColor` (4 f32).
    let layer_fallback_colors = if is_ue5 {
        let mut colors = Vec::new();
        for _ in 0..num_layers {
            let mut rgba = [0f32; 4];
            for channel in &mut rgba {
                *channel = cur.read_f32::<LittleEndian>().map_err(|_| {
                    vt_eof(asset_path, AssetWireField::VirtualTextureLayerFallbackColor)
                })?;
            }
            colors.push(rgba);
        }
        colors
    } else {
        Vec::new()
    };

    // STOP before the Chunks array (3e-VT-b2).
    Ok(VirtualTextureData {
        num_layers,
        width_in_blocks,
        height_in_blocks,
        tile_size,
        tile_border_size,
        num_mips,
        width,
        height,
        tile_data_offset_per_layer,
        chunk_index_per_mip,
        base_offset_per_mip,
        tile_offset_data,
        tile_index_per_chunk,
        tile_index_per_mip,
        tile_offset_in_chunk,
        layer_types,
        layer_fallback_colors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{make_ctx_with_version, write_fstring};

    /// Append a counted `u32[]` (`i32` count prefix + elements).
    fn push_array(buf: &mut Vec<u8>, values: &[u32]) {
        buf.extend_from_slice(&i32::try_from(values.len()).unwrap().to_le_bytes());
        for v in values {
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn parse(bytes: &[u8], ue5: Option<i32>) -> crate::Result<VirtualTextureData> {
        let ctx = make_ctx_with_version(522, ue5);
        let mut cur = Cursor::new(bytes);
        read_from(&mut cur, &ctx, "vt.uasset")
    }

    /// The 6 always-present fixed-header fields (`bCooked` through
    /// `TileBorderSize`). UE5.0+ blobs splice `TileDataOffsetPerLayer` in after
    /// this; pre-UE5 blobs continue straight to `NumMips`.
    fn fixed_header_prefix(num_layers: u32, tile_size: u32, tile_border: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // bCooked
        b.extend_from_slice(&num_layers.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // WidthInBlocks
        b.extend_from_slice(&0u32.to_le_bytes()); // HeightInBlocks
        b.extend_from_slice(&tile_size.to_le_bytes());
        b.extend_from_slice(&tile_border.to_le_bytes());
        b
    }

    /// The pre-UE5 fixed header through `Height` (no UE5.0+ fields).
    fn ue4_header(num_layers: u32, tile_size: u32, tile_border: u32) -> Vec<u8> {
        let mut b = fixed_header_prefix(num_layers, tile_size, tile_border);
        b.extend_from_slice(&0u32.to_le_bytes()); // NumMips
        b.extend_from_slice(&0u32.to_le_bytes()); // Width
        b.extend_from_slice(&0u32.to_le_bytes()); // Height
        b
    }

    #[test]
    fn ue4_degenerate_blob_parses_structural_fields() {
        // The 60-byte degenerate blob from virtual-textures.md (1 layer, 0
        // mips, empty legacy dispatch, LayerTypes=["PF_DXT1"]).
        let mut b = ue4_header(1, 128, 4);
        push_array(&mut b, &[]); // TileIndexPerChunk
        push_array(&mut b, &[]); // TileIndexPerMip
        push_array(&mut b, &[]); // TileOffsetInChunk
        write_fstring(&mut b, "PF_DXT1"); // LayerTypes[0]
        let vt = parse(&b, None).expect("parse");
        assert_eq!(vt.num_layers, 1);
        assert_eq!(vt.tile_size, 128);
        assert_eq!(vt.tile_border_size, 4);
        assert_eq!(vt.num_mips, 0);
        assert_eq!(vt.layer_types, vec!["PF_DXT1".to_string()]);
        // Pre-UE5: all UE5.0+ arrays empty.
        assert!(vt.tile_data_offset_per_layer.is_empty());
        assert!(vt.chunk_index_per_mip.is_empty());
        assert!(vt.tile_offset_data.is_empty());
        assert!(vt.layer_fallback_colors.is_empty());
    }

    #[test]
    fn ue5_blob_parses_dispatch_trio_sub_record_and_fallback_colors() {
        let mut b = fixed_header_prefix(1, 256, 2);
        push_array(&mut b, &[10, 20]); // TileDataOffsetPerLayer (UE5)
        b.extend_from_slice(&1u32.to_le_bytes()); // NumMips
        b.extend_from_slice(&256u32.to_le_bytes()); // Width
        b.extend_from_slice(&256u32.to_le_bytes()); // Height
        push_array(&mut b, &[0]); // ChunkIndexPerMip (UE5)
        push_array(&mut b, &[0xFFFF_FFFF]); // BaseOffsetPerMip (UE5, sentinel)
        // TileOffsetData (UE5): 1 record.
        b.extend_from_slice(&1i32.to_le_bytes()); // record count
        b.extend_from_slice(&4u32.to_le_bytes()); // Width
        b.extend_from_slice(&4u32.to_le_bytes()); // Height
        b.extend_from_slice(&16u32.to_le_bytes()); // MaxAddress
        push_array(&mut b, &[0, 8]); // Addresses
        push_array(&mut b, &[100, 200]); // Offsets
        push_array(&mut b, &[]); // TileIndexPerChunk
        push_array(&mut b, &[]); // TileIndexPerMip
        push_array(&mut b, &[]); // TileOffsetInChunk (empty in UE5)
        write_fstring(&mut b, "PF_BC7"); // LayerTypes[0]
        for channel in [1.0f32, 0.5, 0.25, 1.0] {
            b.extend_from_slice(&channel.to_le_bytes()); // LayerFallbackColors[0]
        }
        let vt = parse(&b, Some(1009)).expect("parse");
        assert_eq!(vt.tile_data_offset_per_layer, vec![10, 20]);
        assert_eq!(vt.chunk_index_per_mip, vec![0]);
        assert_eq!(vt.base_offset_per_mip, vec![0xFFFF_FFFF]);
        assert_eq!(vt.tile_offset_data.len(), 1);
        let tod = &vt.tile_offset_data[0];
        assert_eq!((tod.width, tod.height, tod.max_address), (4, 4, 16));
        assert_eq!(tod.addresses, vec![0, 8]);
        assert_eq!(tod.offsets, vec![100, 200]);
        assert_eq!(vt.layer_types, vec!["PF_BC7".to_string()]);
        assert_eq!(vt.layer_fallback_colors, vec![[1.0, 0.5, 0.25, 1.0]]);
    }

    #[test]
    fn num_layers_at_cap_is_accepted() {
        // 8 layers (exactly MAX_VT_LAYERS) must parse — pins the boundary as
        // `>` (not `>=`, which would reject the valid max).
        let mut b = ue4_header(MAX_VT_LAYERS, 128, 4);
        push_array(&mut b, &[]); // TileIndexPerChunk
        push_array(&mut b, &[]); // TileIndexPerMip
        push_array(&mut b, &[]); // TileOffsetInChunk
        for _ in 0..MAX_VT_LAYERS {
            write_fstring(&mut b, "PF_DXT1"); // LayerTypes[i]
        }
        let vt = parse(&b, None).expect("8 layers accepted");
        assert_eq!(vt.num_layers, MAX_VT_LAYERS);
        assert_eq!(vt.layer_types.len(), 8);
    }

    #[test]
    fn num_layers_over_cap_rejected() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // bCooked
        b.extend_from_slice(&(MAX_VT_LAYERS + 1).to_le_bytes()); // NumLayers = 9
        b.extend_from_slice(&0u32.to_le_bytes()); // WidthInBlocks (unreached)
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::VirtualTextureLayerCountExceeded { count: 9, cap: 8 },
                ..
            }) => {}
            other => panic!("expected VirtualTextureLayerCountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn negative_array_count_rejected() {
        let mut b = ue4_header(1, 128, 4);
        b.extend_from_slice(&(-1i32).to_le_bytes()); // TileIndexPerChunk count = -1
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::VirtualTextureArrayCountExceeded {
                        field: AssetWireField::VirtualTextureDispatchArray,
                        count: -1,
                        ..
                    },
                ..
            }) => {}
            other => panic!("expected VirtualTextureArrayCountExceeded(-1), got {other:?}"),
        }
    }

    #[test]
    fn array_count_over_cap_rejected() {
        let mut b = ue4_header(1, 128, 4);
        b.extend_from_slice(&(MAX_VT_ARRAY_ENTRIES + 1).to_le_bytes()); // over cap
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::VirtualTextureArrayCountExceeded {
                        field: AssetWireField::VirtualTextureDispatchArray,
                        count,
                        cap,
                    },
                ..
            }) => {
                assert_eq!(count, MAX_VT_ARRAY_ENTRIES + 1);
                assert_eq!(cap, MAX_VT_ARRAY_ENTRIES);
            }
            other => panic!("expected VirtualTextureArrayCountExceeded(over cap), got {other:?}"),
        }
    }

    #[test]
    fn tile_offset_data_record_count_over_cap_rejected() {
        // UE5 path: a TileOffsetData record count over MAX_VT_TILE_OFFSET_DATA_RECORDS.
        let mut b = fixed_header_prefix(1, 128, 4);
        push_array(&mut b, &[]); // TileDataOffsetPerLayer
        b.extend_from_slice(&0u32.to_le_bytes()); // NumMips
        b.extend_from_slice(&0u32.to_le_bytes()); // Width
        b.extend_from_slice(&0u32.to_le_bytes()); // Height
        push_array(&mut b, &[]); // ChunkIndexPerMip
        push_array(&mut b, &[]); // BaseOffsetPerMip
        b.extend_from_slice(&(MAX_VT_TILE_OFFSET_DATA_RECORDS + 1).to_le_bytes()); // over cap
        match parse(&b, Some(1009)) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::VirtualTextureArrayCountExceeded {
                        field: AssetWireField::VirtualTextureTileOffsetData,
                        count,
                        cap,
                    },
                ..
            }) => {
                assert_eq!(count, MAX_VT_TILE_OFFSET_DATA_RECORDS + 1);
                assert_eq!(cap, MAX_VT_TILE_OFFSET_DATA_RECORDS);
            }
            other => {
                panic!("expected VirtualTextureArrayCountExceeded(TileOffsetData), got {other:?}")
            }
        }
    }

    #[test]
    fn bcooked_non_bool_rejected() {
        let mut b = Vec::new();
        b.extend_from_slice(&2u32.to_le_bytes()); // bCooked = 2 (non-bool)
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TextureInvalidCookedBool {
                        field: AssetWireField::VirtualTextureHeader,
                        value: 2,
                    },
                ..
            }) => {}
            other => {
                panic!("expected TextureInvalidCookedBool(VirtualTextureHeader, 2), got {other:?}")
            }
        }
    }

    #[test]
    fn truncated_header_eofs() {
        // Only bCooked present — reading NumLayers EOFs (the reader's own
        // bounded read, mapped to a typed UnexpectedEof, never a panic).
        let b = 1u32.to_le_bytes().to_vec();
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::VirtualTextureHeader,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(VirtualTextureHeader), got {other:?}"),
        }
    }

    #[test]
    fn truncated_dispatch_array_eofs() {
        // A counted array promises 2 elements but the blob ends after the
        // count — the element read EOFs cleanly.
        let mut b = ue4_header(1, 128, 4);
        b.extend_from_slice(&2i32.to_le_bytes()); // TileIndexPerChunk count = 2, no elements
        assert!(matches!(
            parse(&b, None),
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::VirtualTextureDispatchArray,
                },
                ..
            })
        ));
    }
}
