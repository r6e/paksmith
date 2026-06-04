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

use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

use crate::asset::AssetContext;
use crate::asset::bulk_data::{FByteBulkData, MAX_BULK_DATA_RECORDS_PER_EXPORT};
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
/// `#[non_exhaustive]`. `Default` yields an all-empty instance (0 layers, no
/// dispatch, no chunks) — a degenerate virtual texture, handy for constructing
/// `Texture2DData` fixtures in downstream handler tests.
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
    /// Per-chunk tile-payload records (3e-VT-b2). Each chunk's actual tile
    /// bytes are an `FByteBulkData` appended to the **export's** bulk records
    /// (so the resolver's per-package budget covers them); the chunk stores
    /// its index into those records via
    /// [`VirtualTextureDataChunk::bulk_record_index`], NOT the payload itself.
    /// Resolve a chunk's bytes with
    /// `Package::resolve_bulk_for_export(idx)[chunk.bulk_record_index]`.
    pub chunks: Vec<VirtualTextureDataChunk>,
}

/// `FVirtualTextureDataChunk` (3e-VT-b2) — a per-chunk tile-payload record:
/// the per-layer codec dispatch + an index to the chunk's `FByteBulkData`
/// (held in the export's bulk records, not here).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct VirtualTextureDataChunk {
    /// Per-chunk content SHA-1 (UE5.0+; `None` below UE5). Stored but **not**
    /// verified by 3e-VT-b2 (matching CUE4Parse, which skips it); a future
    /// milestone MAY verify it against the resolved chunk bytes.
    pub bulk_data_hash: Option<[u8; 20]>,
    /// Total decoded byte length of all tiles in this chunk.
    pub size_in_bytes: u32,
    /// Header-extension payload size carrying per-codec metadata.
    pub codec_payload_size: u32,
    /// Per-layer codec dispatch, one entry per `num_layers`.
    pub layer_codecs: Vec<LayerCodec>,
    /// Index of this chunk's `FByteBulkData` within the export's bulk records
    /// (`Package::resolve_bulk_for_export`). Explicit so the flatten path
    /// (3e-VT-c) resolves the right record even if mip records coexist —
    /// rather than inferring a positional offset.
    pub bulk_record_index: usize,
}

/// Per-layer codec selection inside an [`VirtualTextureDataChunk`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct LayerCodec {
    /// `EVirtualTextureCodec` discriminant (`u8`): `0` Black, `1` OpaqueBlack,
    /// `2` White, `3` Flat, `4` RawGPU, `5`/`6` deprecated, `7` Max-sentinel.
    /// Stored raw; the `0..=6` validity check is deferred to the per-tile
    /// decode dispatch (3e-VT-c), since the chunk layout doesn't depend on it.
    pub codec_type: u8,
    /// Per-layer offset into the per-codec payload. `u32` for UE 4.27+/UE5,
    /// widened from the `u16` pre-4.27 wire value.
    pub codec_payload_offset: u32,
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

// Tile-address resolution (this section through `get_u32`) is landed and
// unit-tested by 3e-VT-c1; its only production consumer is the flatten in
// 3e-VT-c2, so the items are `#[allow(dead_code)]` until that lands. (`expect`
// can't replace `allow` here: each item is referenced by a sibling that is
// itself dead, so rustc still counts it "used" and the expectation goes
// unfulfilled — a false positive. `allow` is the correct staging marker.)

/// The `~0u` sentinel CUE4Parse uses for "no data" in offset arrays.
#[allow(dead_code)]
const VT_NO_DATA: u32 = u32::MAX;

/// A tile-layer's resolved data location within a chunk's bulk payload — the
/// port of CUE4Parse `FVirtualTextureBuiltData.GetTileData`'s
/// `(chunkIndex, offset, length)` tuple (3e-VT-c1). The flatten that consumes
/// it (decode + stitch) is 3e-VT-c2.
///
/// `pub(crate)`: an ephemeral lookup result, not a serialized wire struct like
/// [`VirtualTextureData`]. 3e-VT-c2 may promote it to `pub` (non-breaking) once
/// the flatten confirms a stable external shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TileData {
    /// Index into [`VirtualTextureData::chunks`] (→ the chunk's bulk record via
    /// its [`VirtualTextureDataChunk::bulk_record_index`]).
    pub chunk_index: usize,
    /// Byte offset of this tile-layer's data within the chunk's resolved
    /// payload.
    pub byte_offset: u32,
    /// The tile-layer's byte span within the per-tile block (`end - start`).
    /// paksmith's defined contract — the same meaning on both dispatch paths.
    ///
    /// On the UE5.0+ path this **deliberately differs** from CUE4Parse, whose
    /// `GetTileData` places the layer's *start* offset in this slot instead of
    /// a length. The span is the natural reading of the per-tile layout and is
    /// consistent with the (CUE4Parse-faithful, exercised) [`Self::byte_offset`]
    /// arithmetic, but it is **unverified**: nothing consumes `data_length`
    /// yet — its only would-be consumer is the deprecated `ZippedGPU` codec,
    /// never reached for the `RawGPU` codec real assets use — so the choice
    /// can't be confirmed end-to-end until the flatten lands a consumer
    /// (3e-VT-c2, which must verify it against a real asset). See
    /// [`VirtualTextureData::tile_data_ue5`].
    pub data_length: u32,
}

#[allow(dead_code)]
impl TileOffsetData {
    /// Port of CUE4Parse `FVirtualTextureTileOffsetData.GetTileOffset` — an
    /// `Algo::UpperBound(Addresses, inAddress) - 1` block lookup. Returns the
    /// tile's offset, or `None` for "no data" (the `~0u` offset sentinel, an
    /// address below the first block — where CUE4Parse would index `[-1]` — or
    /// an out-of-range block).
    fn get_tile_offset(&self, in_address: u32) -> Option<u32> {
        // UpperBound - 1: `partition_point` gives UpperBound (first index whose
        // address exceeds `in_address`); `- 1` is the last block at or below it.
        // The empty-array, below-first-address (CUE4Parse's `[-1]` throw), and
        // single-element cases all collapse to `partition_point == 0 -> None`.
        let block_index = self
            .addresses
            .partition_point(|&addr| addr <= in_address)
            .checked_sub(1)?;
        let base_offset = *self.offsets.get(block_index)?;
        if base_offset == VT_NO_DATA {
            return None;
        }
        let base_address = self.addresses[block_index];
        let local_offset = in_address.checked_sub(base_address)?;
        base_offset.checked_add(local_offset)
    }
}

#[allow(dead_code)]
impl VirtualTextureData {
    /// `Width / TileSize`, rounded up (CUE4Parse `GetWidthInTiles`). `0` when
    /// `tile_size == 0` (CUE4Parse would divide by zero).
    #[must_use]
    pub(crate) fn width_in_tiles(&self) -> u32 {
        divide_round_up(self.width, self.tile_size)
    }

    /// `Height / TileSize`, rounded up (CUE4Parse `GetHeightInTiles`).
    #[must_use]
    pub(crate) fn height_in_tiles(&self) -> u32 {
        divide_round_up(self.height, self.tile_size)
    }

    /// `TileSize + 2 * TileBorderSize` — the tile edge including its sampling
    /// border (CUE4Parse `GetPhysicalTileSize`). Saturating (the border is an
    /// untrusted `u32`).
    #[must_use]
    pub(crate) fn physical_tile_size(&self) -> u32 {
        self.tile_size
            .saturating_add(self.tile_border_size.saturating_mul(2))
    }

    /// CUE4Parse `IsLegacyData` — `TileOffsetInChunk == null || Length > 0`.
    /// paksmith always carries the (possibly-empty) vec, so "null" never
    /// applies: legacy iff `tile_offset_in_chunk` is non-empty.
    fn is_legacy_data(&self) -> bool {
        !self.tile_offset_in_chunk.is_empty()
    }

    /// CUE4Parse `GetChunkIndex(vLevel)` (UE5.0+ path) — `ChunkIndexPerMip[vLevel]`,
    /// or `None` where CUE4Parse returns `-1` (out of range).
    fn chunk_index_ue5(&self, v_level: usize) -> Option<usize> {
        let raw = *self.chunk_index_per_mip.get(v_level)?;
        usize::try_from(raw).ok()
    }

    /// CUE4Parse `GetChunkIndex_Legacy(tileIndex)` — the chunk bucket whose
    /// `[TileIndexPerChunk[i], TileIndexPerChunk[i+1])` range contains
    /// `tile_index`; defaults to the last chunk.
    fn chunk_index_legacy(&self, tile_index: u32) -> usize {
        let max = self.chunks.len().saturating_sub(1);
        if let Some(&last) = self.tile_index_per_chunk.last()
            && tile_index <= last
        {
            for i in 0..max {
                let (Some(&lo), Some(&hi)) = (
                    self.tile_index_per_chunk.get(i),
                    self.tile_index_per_chunk.get(i + 1),
                ) else {
                    break;
                };
                if tile_index >= lo && tile_index < hi {
                    return i;
                }
            }
        }
        max
    }

    /// CUE4Parse `GetTileIndex_Legacy(vLevel, vAddress)` —
    /// `TileIndexPerMip[vLevel] + vAddress * NumLayers`, or `None` (CUE4Parse
    /// `~0u`) when it reaches `TileIndexPerMip[vLevel + 1]` or any access /
    /// arithmetic is out of range.
    fn tile_index_legacy(&self, v_level: usize, v_address: u32) -> Option<u32> {
        let base = *self.tile_index_per_mip.get(v_level)?;
        let next = *self.tile_index_per_mip.get(v_level + 1)?;
        let tile_index = base.checked_add(v_address.checked_mul(self.num_layers)?)?;
        (tile_index < next).then_some(tile_index)
    }

    /// CUE4Parse `GetTileOffset_Legacy(chunkIndex, tileIndex)` —
    /// `TileOffsetInChunk[tileIndex]`, or the chunk's `SizeInBytes` when
    /// `tileIndex` is past the chunk's last tile (used to bound the final
    /// tile's length). `None` on any out-of-range access.
    fn tile_offset_legacy(&self, chunk_index: usize, tile_index: u32) -> Option<u32> {
        let next_chunk_start = *self.tile_index_per_chunk.get(chunk_index + 1)?;
        if tile_index < next_chunk_start {
            get_u32(&self.tile_offset_in_chunk, tile_index)
        } else {
            Some(self.chunks.get(chunk_index)?.size_in_bytes)
        }
    }

    /// Resolve a tile-layer's data location — the bounds-safe port of CUE4Parse
    /// `FVirtualTextureBuiltData.GetTileData(vLevel, vAddress, layerIndex)`.
    /// Returns `None` for "no data" — an empty tile, an out-of-range address,
    /// or any out-of-range array access / arithmetic overflow that would make
    /// CUE4Parse throw (paksmith never panics on untrusted input). The
    /// resolved `chunk_index` is validated against `chunks.len()`.
    ///
    /// The returned `byte_offset` / `data_length` are **not** bounded against
    /// the chunk's resolved payload size — they're plain additive `u32`s. The
    /// 3e-VT-c2 consumer MUST verify `byte_offset + data_length <= payload.len()`
    /// (checked slicing) before reading, or a crafted offset array yields an
    /// out-of-payload read.
    #[must_use]
    pub(crate) fn tile_data(&self, v_level: usize, v_address: u32, layer: u32) -> Option<TileData> {
        let tile = if self.is_legacy_data() {
            self.tile_data_legacy(v_level, v_address, layer)
        } else {
            self.tile_data_ue5(v_level, v_address, layer)
        }?;
        // Hardening (per virtual-textures.md §Caps): a tile's chunk index must
        // be in range before any tile-data read.
        (tile.chunk_index < self.chunks.len()).then_some(tile)
    }

    fn tile_data_legacy(&self, v_level: usize, v_address: u32, layer: u32) -> Option<TileData> {
        let tile_index = self.tile_index_legacy(v_level, v_address)?;
        let chunk_index = self.chunk_index_legacy(tile_index);
        let tile_offset = self.tile_offset_legacy(chunk_index, tile_index)?;
        let next_tile_offset =
            self.tile_offset_legacy(chunk_index, tile_index.checked_add(self.num_layers)?)?;
        if tile_offset == next_tile_offset {
            return None; // empty tile (zero size)
        }
        let layer_tile = tile_index.checked_add(layer)?;
        let byte_offset = self.tile_offset_legacy(chunk_index, layer_tile)?;
        let end = self.tile_offset_legacy(chunk_index, layer_tile.checked_add(1)?)?;
        let data_length = end.checked_sub(byte_offset)?;
        Some(TileData {
            chunk_index,
            byte_offset,
            data_length,
        })
    }

    fn tile_data_ue5(&self, v_level: usize, v_address: u32, layer: u32) -> Option<TileData> {
        let base_offset = *self.base_offset_per_mip.get(v_level)?;
        let tod = self.tile_offset_data.get(v_level)?;
        let chunk_index = self.chunk_index_ue5(v_level)?;
        let tile_offset = tod.get_tile_offset(v_address)?;
        if base_offset == VT_NO_DATA {
            return None;
        }
        // Per-tile block layout: layers are concatenated, with
        // `tile_data_offset_per_layer[i]` the cumulative END offset of layer `i`
        // (so `.last()` is the whole block's size, CUE4Parse's `tileDataSize`).
        // Layer `layer` spans [layer_start, layer_end) within the block.
        let tile_data_size = *self.tile_data_offset_per_layer.last()?;
        let layer_start = if layer == 0 {
            0
        } else {
            get_u32(&self.tile_data_offset_per_layer, layer.checked_sub(1)?)?
        };
        let layer_end = get_u32(&self.tile_data_offset_per_layer, layer)?;
        // `data_length` is paksmith's contract: the layer's byte span
        // (`layer_end - layer_start`). CUE4Parse puts `layer_start` in this slot
        // instead; the span is the natural reading but is UNVERIFIED (no
        // consumer until 3e-VT-c2 — see the `TileData::data_length` doc). The
        // `byte_offset` below matches CUE4Parse exactly and IS exercised.
        let data_length = layer_end.checked_sub(layer_start)?;
        let byte_offset = base_offset
            .checked_add(tile_offset.checked_mul(tile_data_size)?)?
            .checked_add(layer_start)?;
        Some(TileData {
            chunk_index,
            byte_offset,
            data_length,
        })
    }
}

/// `numerator / denominator` rounded up (CUE4Parse `DivideAndRoundUp`). `0`
/// when `denominator == 0` (CUE4Parse would divide by zero); the guard also
/// keeps [`u32::div_ceil`] from panicking.
#[allow(dead_code)]
fn divide_round_up(numerator: u32, denominator: u32) -> u32 {
    if denominator == 0 {
        return 0;
    }
    numerator.div_ceil(denominator)
}

/// Index a `u32` slice by a `u32`, returning `None` on an out-of-range index or
/// a `u32`→`usize` conversion that can't fit (16-bit targets). Both the
/// conversion and the bounds check stay load-bearing — the dispatch must never
/// panic on an untrusted index.
#[allow(dead_code)]
fn get_u32(slice: &[u32], index: u32) -> Option<u32> {
    slice.get(usize::try_from(index).ok()?).copied()
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

/// Read the `Chunks[]` array: a bounded `i32` count, then each
/// `FVirtualTextureDataChunk`. Each chunk's `FByteBulkData` payload is appended
/// to `bulk_records` (the export's bulk records, so the resolver's per-package
/// budget covers it) and the chunk stores its index into that vec.
fn read_chunks(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
    num_layers: u32,
    bulk_records: &mut Vec<FByteBulkData>,
) -> crate::Result<Vec<VirtualTextureDataChunk>> {
    let chunk = AssetWireField::VirtualTextureChunk;
    let codec = AssetWireField::VirtualTextureChunkCodec;
    // Each chunk appends one `FByteBulkData` to the export's bulk records, and
    // `Package::insert_bulk_records` rejects an export whose total record count
    // exceeds `MAX_BULK_DATA_RECORDS_PER_EXPORT` (degrading by DROPPING all of
    // them — which would leave every `bulk_record_index` dangling). So bound
    // the chunk count by the REMAINING per-export budget (after any mip records
    // already in `bulk_records`) and fail loud here, rather than silently
    // losing the chunk payloads downstream.
    let remaining = MAX_BULK_DATA_RECORDS_PER_EXPORT.saturating_sub(bulk_records.len());
    let cap = i32::try_from(remaining).unwrap_or(i32::MAX);
    let count = read_bounded_count(cur, asset_path, chunk, cap)?;
    let is_ue5 = ctx.version.file_version_ue5.is_some();
    let offset_is_u32 = ctx.version.is_ue4_27_or_later();
    let mut chunks = Vec::new();
    for _ in 0..count {
        // bulkDataHash (UE5.0+): 20-byte FSHAHash — stored, not verified.
        let bulk_data_hash = if is_ue5 {
            let mut hash = [0u8; 20];
            cur.read_exact(&mut hash)
                .map_err(|_| vt_eof(asset_path, chunk))?;
            Some(hash)
        } else {
            None
        };
        let size_in_bytes = read_u32(cur, asset_path, chunk)?;
        let codec_payload_size = read_u32(cur, asset_path, chunk)?;
        // Per-layer codec dispatch (`num_layers <= 8`, bounded). NOTE:
        // `EGame.GAME_DeltaForce` skips the per-layer offset; paksmith has no
        // game profiles, so it always reads the offset (the non-DeltaForce
        // contract). CodecPayloadOffset is `u32` for UE 4.27+/UE5, else `u16`.
        let mut layer_codecs = Vec::new();
        for _ in 0..num_layers {
            let codec_type = cur.read_u8().map_err(|_| vt_eof(asset_path, codec))?;
            let codec_payload_offset = if offset_is_u32 {
                read_u32(cur, asset_path, codec)?
            } else {
                u32::from(
                    cur.read_u16::<LittleEndian>()
                        .map_err(|_| vt_eof(asset_path, codec))?,
                )
            };
            layer_codecs.push(LayerCodec {
                codec_type,
                codec_payload_offset,
            });
        }
        // BulkData → into the export's bulk records; remember the index.
        let bulk = FByteBulkData::read_from(cur, asset_path)?;
        let bulk_record_index = bulk_records.len();
        bulk_records.push(bulk);
        chunks.push(VirtualTextureDataChunk {
            bulk_data_hash,
            size_in_bytes,
            codec_payload_size,
            layer_codecs,
            bulk_record_index,
        });
    }
    Ok(chunks)
}

/// Parse an `FVirtualTextureBuiltData` blob in full: the structural fields
/// (3e-VT-b1) then the `Chunks` array (3e-VT-b2). Each chunk's `FByteBulkData`
/// is appended to `bulk_records` (the export's bulk records) so the resolver's
/// per-package budget covers it; the returned chunks reference those records
/// by index.
pub(crate) fn read_from(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
    bulk_records: &mut Vec<FByteBulkData>,
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

    // Chunks (3e-VT-b2) — each chunk's FByteBulkData is appended to the
    // export's `bulk_records`; the chunk references it by index.
    let chunks = read_chunks(cur, ctx, asset_path, num_layers, bulk_records)?;

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
        chunks,
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

    /// Append a `Chunks` count of 0 (the empty-chunks tail every structural
    /// fixture needs now that `read_from` reads through the `Chunks` array).
    fn push_no_chunks(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    fn parse(bytes: &[u8], ue5: Option<i32>) -> crate::Result<VirtualTextureData> {
        parse_records(bytes, ue5).map(|(vt, _)| vt)
    }

    /// Parse + return the bulk records the chunks appended (chunk-routing tests).
    fn parse_records(
        bytes: &[u8],
        ue5: Option<i32>,
    ) -> crate::Result<(VirtualTextureData, Vec<FByteBulkData>)> {
        let ctx = make_ctx_with_version(522, ue5);
        let mut cur = Cursor::new(bytes);
        let mut bulk = Vec::new();
        let vt = read_from(&mut cur, &ctx, "vt.uasset", &mut bulk)?;
        Ok((vt, bulk))
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
        // The degenerate blob from virtual-textures.md (1 layer, 0 mips, empty
        // legacy dispatch, LayerTypes=["PF_DXT1"], 0 chunks).
        let mut b = ue4_struct_1layer();
        push_no_chunks(&mut b);
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
        assert!(vt.chunks.is_empty()); // Chunks count = 0
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
        push_no_chunks(&mut b);
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
        push_no_chunks(&mut b);
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

    // ===== chunks (3e-VT-b2) =====

    /// A minimal pre-UE5 structural blob (1 layer, 0 mips, empty legacy
    /// dispatch, `LayerTypes=["PF_DXT1"]`) through `LayerTypes` — ready for a
    /// `Chunks` tail.
    fn ue4_struct_1layer() -> Vec<u8> {
        let mut b = ue4_header(1, 128, 4);
        push_array(&mut b, &[]); // TileIndexPerChunk
        push_array(&mut b, &[]); // TileIndexPerMip
        push_array(&mut b, &[]); // TileOffsetInChunk
        write_fstring(&mut b, "PF_DXT1"); // LayerTypes[0]
        b
    }

    /// A minimal UE5 structural blob (1 layer) through `LayerFallbackColors`.
    fn ue5_struct_1layer() -> Vec<u8> {
        let mut b = fixed_header_prefix(1, 128, 4);
        push_array(&mut b, &[]); // TileDataOffsetPerLayer (UE5)
        b.extend_from_slice(&0u32.to_le_bytes()); // NumMips
        b.extend_from_slice(&0u32.to_le_bytes()); // Width
        b.extend_from_slice(&0u32.to_le_bytes()); // Height
        push_array(&mut b, &[]); // ChunkIndexPerMip
        push_array(&mut b, &[]); // BaseOffsetPerMip
        b.extend_from_slice(&0i32.to_le_bytes()); // TileOffsetData count = 0
        push_array(&mut b, &[]); // TileIndexPerChunk
        push_array(&mut b, &[]); // TileIndexPerMip
        push_array(&mut b, &[]); // TileOffsetInChunk
        write_fstring(&mut b, "PF_DXT1"); // LayerTypes[0]
        for channel in [0f32; 4] {
            b.extend_from_slice(&channel.to_le_bytes()); // LayerFallbackColors[0]
        }
        b
    }

    /// Append a minimal inline `FByteBulkData` (flags + 16-element / 16-byte /
    /// offset-0), the same shape the mip fixtures use.
    fn push_byte_bulk_data(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // PAYLOAD_AT_END_OF_FILE | NO_OFFSET_FIXUP
        buf.extend_from_slice(&16i32.to_le_bytes()); // ElementCount
        buf.extend_from_slice(&16u32.to_le_bytes()); // SizeOnDisk
        buf.extend_from_slice(&0i64.to_le_bytes()); // OffsetInFile
    }

    #[test]
    fn ue4_27_chunk_parses_fields_and_routes_bulk_data() {
        let mut b = ue4_struct_1layer();
        b.extend_from_slice(&1i32.to_le_bytes()); // Chunks count = 1
        b.extend_from_slice(&4096u32.to_le_bytes()); // SizeInBytes
        b.extend_from_slice(&7u32.to_le_bytes()); // CodecPayloadSize
        b.push(4); // layer 0 CodecType = RawGPU
        b.extend_from_slice(&0x55u32.to_le_bytes()); // layer 0 CodecPayloadOffset (u32, 4.27)
        push_byte_bulk_data(&mut b);
        let (vt, records) = parse_records(&b, None).expect("parse");
        assert_eq!(vt.chunks.len(), 1);
        let c = &vt.chunks[0];
        assert!(c.bulk_data_hash.is_none(), "pre-UE5 ⇒ no SHA prefix");
        assert_eq!(c.size_in_bytes, 4096);
        assert_eq!(c.codec_payload_size, 7);
        assert_eq!(c.layer_codecs.len(), 1);
        assert_eq!(c.layer_codecs[0].codec_type, 4);
        assert_eq!(c.layer_codecs[0].codec_payload_offset, 0x55);
        // The chunk's FByteBulkData was routed into the export's bulk records,
        // referenced by an explicit index (not stored inline).
        assert_eq!(c.bulk_record_index, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].size_on_disk, 16);
    }

    #[test]
    fn pre_4_27_chunk_reads_u16_codec_offset() {
        let mut b = ue4_struct_1layer();
        b.extend_from_slice(&1i32.to_le_bytes()); // Chunks count = 1
        b.extend_from_slice(&4096u32.to_le_bytes()); // SizeInBytes
        b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadSize
        b.push(4); // CodecType
        b.extend_from_slice(&0x1234u16.to_le_bytes()); // CodecPayloadOffset (u16, pre-4.27)
        push_byte_bulk_data(&mut b);
        // UE 4.23 (object 517 < 522): the offset is a u16. Reading it as u32
        // would consume 2 bytes of the bulk data and desync; asserting the
        // exact widened value pins the u16 width.
        let ctx = make_ctx_with_version(517, None);
        let mut cur = Cursor::new(b.as_slice());
        let mut bulk = Vec::new();
        let vt = read_from(&mut cur, &ctx, "vt.uasset", &mut bulk).expect("parse");
        assert_eq!(vt.chunks[0].layer_codecs[0].codec_payload_offset, 0x1234);
    }

    #[test]
    fn ue5_chunk_stores_sha_prefix() {
        let mut b = ue5_struct_1layer();
        b.extend_from_slice(&1i32.to_le_bytes()); // Chunks count = 1
        b.extend_from_slice(&[0xABu8; 20]); // bulkDataHash (UE5.0+)
        b.extend_from_slice(&4096u32.to_le_bytes()); // SizeInBytes
        b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadSize
        b.push(2); // CodecType = White
        b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadOffset (u32, UE5)
        push_byte_bulk_data(&mut b);
        let (vt, records) = parse_records(&b, Some(1009)).expect("parse");
        assert_eq!(vt.chunks.len(), 1);
        assert_eq!(vt.chunks[0].bulk_data_hash, Some([0xAB; 20]));
        assert_eq!(vt.chunks[0].layer_codecs[0].codec_type, 2);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn two_chunks_get_distinct_bulk_record_indices() {
        let mut b = ue4_struct_1layer();
        b.extend_from_slice(&2i32.to_le_bytes()); // Chunks count = 2
        for _ in 0..2 {
            b.extend_from_slice(&4096u32.to_le_bytes()); // SizeInBytes
            b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadSize
            b.push(4); // CodecType
            b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadOffset
            push_byte_bulk_data(&mut b);
        }
        let (vt, records) = parse_records(&b, None).expect("parse");
        assert_eq!(vt.chunks.len(), 2);
        assert_eq!(vt.chunks[0].bulk_record_index, 0);
        assert_eq!(vt.chunks[1].bulk_record_index, 1);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn chunk_count_over_per_export_budget_rejected() {
        // The chunk count is bounded by the per-export record budget (here the
        // full 256, since no mip records precede it). One over it fails LOUD —
        // rather than the downstream `insert_bulk_records` silently dropping all
        // records and leaving every `bulk_record_index` dangling.
        let budget = i32::try_from(MAX_BULK_DATA_RECORDS_PER_EXPORT).unwrap();
        let mut b = ue4_struct_1layer();
        b.extend_from_slice(&(budget + 1).to_le_bytes()); // Chunks count over budget
        match parse(&b, None) {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::VirtualTextureArrayCountExceeded {
                        field: AssetWireField::VirtualTextureChunk,
                        count,
                        cap,
                    },
                ..
            }) => {
                assert_eq!(count, budget + 1);
                assert_eq!(cap, budget);
            }
            other => panic!("expected VirtualTextureArrayCountExceeded(Chunk), got {other:?}"),
        }
    }

    /// A dummy parsed `FByteBulkData` (via the production reader, so no
    /// `__test_utils` gate) to pre-seed `bulk_records` like mip records would.
    fn dummy_bulk_record() -> FByteBulkData {
        let mut bytes = Vec::new();
        push_byte_bulk_data(&mut bytes);
        FByteBulkData::read_from(&mut Cursor::new(bytes.as_slice()), "seed").expect("dummy record")
    }

    #[test]
    fn bulk_record_index_accounts_for_preexisting_mip_records() {
        // The explicit index is the chunk's position in the FULL bulk_records
        // vec (`bulk_records.len()` at push time), NOT a chunk-loop counter: a
        // chunk after pre-existing mip records lands at that offset, not 0.
        let mut b = ue4_struct_1layer();
        b.extend_from_slice(&1i32.to_le_bytes()); // Chunks count = 1
        b.extend_from_slice(&0u32.to_le_bytes()); // SizeInBytes
        b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadSize
        b.push(4); // CodecType
        b.extend_from_slice(&0u32.to_le_bytes()); // CodecPayloadOffset (u32, 4.27)
        push_byte_bulk_data(&mut b);
        let ctx = make_ctx_with_version(522, None);
        let mut cur = Cursor::new(b.as_slice());
        let mut bulk = vec![dummy_bulk_record(), dummy_bulk_record()]; // 2 prior mip records
        let vt = read_from(&mut cur, &ctx, "vt.uasset", &mut bulk).expect("parse");
        assert_eq!(vt.chunks[0].bulk_record_index, 2); // after the 2 mip records
        assert_eq!(bulk.len(), 3);
    }

    // ----- 3e-VT-c1: tile-address resolution (GetTileData dispatch) -----
    //
    // No end-to-end oracle exists for the flatten, so these pin the dispatch
    // arithmetic against values hand-computed from the CUE4Parse reference. The
    // UE5 `data_length` is paksmith's own (unverified) contract rather than the
    // CUE4Parse value — see `ue5_data_length_is_the_layer_span`.

    fn vt_chunk(size_in_bytes: u32) -> VirtualTextureDataChunk {
        VirtualTextureDataChunk {
            bulk_data_hash: None,
            size_in_bytes,
            codec_payload_size: 0,
            layer_codecs: Vec::new(),
            bulk_record_index: 0,
        }
    }

    fn vt_tod(
        width: u32,
        height: u32,
        max_address: u32,
        addresses: Vec<u32>,
        offsets: Vec<u32>,
    ) -> TileOffsetData {
        TileOffsetData {
            width,
            height,
            max_address,
            addresses,
            offsets,
        }
    }

    /// A 1-mip legacy VT: `num_layers` layers, the given per-tile chunk-local
    /// byte offsets, and one chunk of `chunk_size` bytes covering all entries.
    fn legacy_vt(
        num_layers: u32,
        tile_offset_in_chunk: Vec<u32>,
        chunk_size: u32,
    ) -> VirtualTextureData {
        let entries = u32::try_from(tile_offset_in_chunk.len()).unwrap();
        VirtualTextureData {
            num_layers,
            num_mips: 1,
            tile_index_per_mip: vec![0, entries], // mip 0 spans [0, entries)
            tile_index_per_chunk: vec![0, entries], // chunk 0 spans [0, entries)
            tile_offset_in_chunk,
            chunks: vec![vt_chunk(chunk_size)],
            ..Default::default()
        }
    }

    /// A 1-mip UE5.0+ VT. `tile_offset_in_chunk` stays empty so dispatch takes
    /// the UE5 path.
    fn ue5_vt(
        num_layers: u32,
        tile_data_offset_per_layer: Vec<u32>,
        base_offset_per_mip: Vec<u32>,
        chunk_index_per_mip: Vec<u32>,
        tile_offset_data: Vec<TileOffsetData>,
        num_chunks: usize,
    ) -> VirtualTextureData {
        VirtualTextureData {
            num_layers,
            num_mips: u32::try_from(base_offset_per_mip.len()).unwrap(),
            tile_data_offset_per_layer,
            base_offset_per_mip,
            chunk_index_per_mip,
            tile_offset_data,
            chunks: (0..num_chunks).map(|_| vt_chunk(0)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn dispatch_picks_path_by_tile_offset_in_chunk_presence() {
        assert!(legacy_vt(1, vec![0, 64], 128).is_legacy_data());
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        assert!(!ue5_vt(1, vec![10], vec![0], vec![0], vec![tod], 1).is_legacy_data());
    }

    #[test]
    fn legacy_single_layer_tile_data() {
        // 4 tiles, each 64 bytes; chunk total 256.
        let vt = legacy_vt(1, vec![0, 64, 128, 192], 256);
        assert_eq!(
            vt.tile_data(0, 2, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 128,
                data_length: 64,
            }),
        );
        // Last tile: its end offset comes from the chunk's `size_in_bytes`.
        assert_eq!(
            vt.tile_data(0, 3, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 192,
                data_length: 64,
            }),
        );
        // Address past the mip's last tile → no data.
        assert_eq!(vt.tile_data(0, 4, 0), None);
    }

    #[test]
    fn legacy_address_at_mip_boundary_is_no_data() {
        // 2 mips: mip 0 = tiles [0,2), mip 1 = tiles [2,4). For mip 0, address 2
        // maps to tile_index 2 == TileIndexPerMip[1] — out of mip 0's range, so
        // None. Pins `<` vs `<=` in `tile_index_legacy`: a `<=` leak would
        // wrongly resolve mip 1's tile 2, which holds real data (asserted via
        // the mip-1 lookup below).
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 2,
            tile_index_per_mip: vec![0, 2, 4],
            tile_index_per_chunk: vec![0, 4],
            tile_offset_in_chunk: vec![0, 64, 128, 192],
            chunks: vec![vt_chunk(256)],
            ..Default::default()
        };
        assert_eq!(vt.tile_data(0, 2, 0), None);
        assert_eq!(
            vt.tile_data(1, 0, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 128,
                data_length: 64,
            }),
        );
    }

    #[test]
    fn legacy_empty_tile_is_no_data() {
        // Tile 1 and tile 2 share offset 64 → tile 1 has zero size.
        let vt = legacy_vt(1, vec![0, 64, 64, 128], 192);
        assert_eq!(vt.tile_data(0, 1, 0), None);
        assert_eq!(
            vt.tile_data(0, 0, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 0,
                data_length: 64,
            }),
        );
    }

    #[test]
    fn legacy_multi_layer_indexes_by_layer() {
        // 2 tiles × 2 layers: [t0l0=0, t0l1=32, t1l0=64, t1l1=96], total 128.
        let vt = legacy_vt(2, vec![0, 32, 64, 96], 128);
        assert_eq!(
            vt.tile_data(0, 0, 1),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 32,
                data_length: 32,
            }),
        );
        assert_eq!(
            vt.tile_data(0, 1, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 64,
                data_length: 32,
            }),
        );
    }

    #[test]
    fn legacy_multi_chunk_bucket_selection() {
        // chunk 0 = tiles [0,2), chunk 1 = tiles [2,4); offsets are chunk-local.
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_index_per_mip: vec![0, 4],
            tile_index_per_chunk: vec![0, 2, 4],
            tile_offset_in_chunk: vec![0, 50, 0, 70],
            chunks: vec![vt_chunk(100), vt_chunk(150)],
            ..Default::default()
        };
        assert_eq!(vt.tile_data(0, 0, 0).unwrap().chunk_index, 0);
        assert_eq!(vt.tile_data(0, 1, 0).unwrap().chunk_index, 0);
        assert_eq!(vt.tile_data(0, 2, 0).unwrap().chunk_index, 1);
        // Crosses into chunk 1; its end offset is chunk 1's `size_in_bytes`.
        assert_eq!(
            vt.tile_data(0, 3, 0),
            Some(TileData {
                chunk_index: 1,
                byte_offset: 70,
                data_length: 80,
            }),
        );
    }

    #[test]
    fn legacy_address_multiply_overflow_is_no_data() {
        let vt = legacy_vt(2, vec![0, 64], 128);
        // v_address * num_layers overflows u32 → None, not a panic.
        assert_eq!(vt.tile_data(0, u32::MAX, 0), None);
    }

    #[test]
    fn ue5_tile_data_address_blocks_and_layers() {
        // 2 layers, per-tile block 100 bytes (layer0=[0,40), layer1=[40,100)).
        // Address table: block 0 @ offset 0 (addr 0+), block 1 @ offset 5 (addr 2+).
        let tod = vt_tod(2, 2, 4, vec![0, 2], vec![0, 5]);
        let vt = ue5_vt(2, vec![40, 100], vec![1000], vec![0], vec![tod], 1);
        // layer 1, vAddr 1: 1000 + tileOffset(1)*100 + 40 = 1140; span 100-40 = 60.
        assert_eq!(
            vt.tile_data(0, 1, 1),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 1140,
                data_length: 60,
            }),
        );
        // layer 0, vAddr 1: 1000 + 1*100 + 0 = 1100; span 40-0 = 40.
        assert_eq!(
            vt.tile_data(0, 1, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 1100,
                data_length: 40,
            }),
        );
        // vAddr 2 hits the second address block (offset 5): 1000 + 5*100 + 0.
        assert_eq!(
            vt.tile_data(0, 2, 0),
            Some(TileData {
                chunk_index: 0,
                byte_offset: 1500,
                data_length: 40,
            }),
        );
    }

    #[test]
    fn ue5_data_length_is_the_layer_span() {
        // paksmith's contract: data_length is the layer's byte span (end-start).
        // This pins paksmith's CHOICE (unverified — see TileData::data_length),
        // not a proof about CUE4Parse: per-tile block is [layer0: 0..40,
        // layer1: 40..100], so layer 1's span is 100 - 40 = 60. The assert_ne
        // documents that we deliberately do NOT emit CUE4Parse's layer-start
        // offset (40) in this slot.
        let tod = vt_tod(2, 2, 4, vec![0], vec![0]);
        let vt = ue5_vt(2, vec![40, 100], vec![0], vec![0], vec![tod], 1);
        let resolved = vt.tile_data(0, 0, 1).expect("layer 1 tile");
        assert_eq!(resolved.data_length, 60, "layer 1 span = 100 - 40");
        assert_ne!(
            resolved.data_length, 40,
            "deliberately not CUE4Parse's layer-start offset"
        );
    }

    #[test]
    fn ue5_base_offset_sentinel_is_no_data() {
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        let vt = ue5_vt(1, vec![40], vec![VT_NO_DATA], vec![0], vec![tod], 1);
        assert_eq!(vt.tile_data(0, 0, 0), None);
    }

    #[test]
    fn ue5_chunk_index_out_of_range_is_rejected() {
        // chunk_index_per_mip points at chunk index 1 == chunks.len() (one past
        // the last valid index, the tightest out-of-range case — pins `<` vs
        // `<=` in the chunk-index validation).
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        let vt = ue5_vt(1, vec![40], vec![0], vec![1], vec![tod], 1);
        assert_eq!(vt.tile_data(0, 0, 0), None);
    }

    #[test]
    fn tile_offset_data_upper_bound_search() {
        let tod = vt_tod(0, 0, 0, vec![0, 4, 10], vec![100, 200, 300]);
        assert_eq!(tod.get_tile_offset(0), Some(100)); // block 0
        assert_eq!(tod.get_tile_offset(3), Some(103)); // block 0: 100 + 3
        assert_eq!(tod.get_tile_offset(4), Some(200)); // block 1 (exact addr)
        assert_eq!(tod.get_tile_offset(9), Some(205)); // block 1: 200 + 5
        assert_eq!(tod.get_tile_offset(10), Some(300)); // block 2 (last)
        assert_eq!(tod.get_tile_offset(50), Some(340)); // block 2: 300 + 40
    }

    #[test]
    fn tile_offset_duplicate_addresses_pick_last_block() {
        // The `partition_point(<=) - 1` equivalence to CUE4Parse's hand-rolled
        // loop hinges on duplicate addresses resolving to the SAME block.
        // CUE4Parse picks the last duplicate two ways: via the `Addresses[i] >
        // inAddress` break (interior dup) and via the `blockIndex == 0`
        // run-off-the-end special case (trailing dup). Pin both.
        //
        // Interior dup `[0,5,5,10]`@5: CUE4Parse breaks at i=3 (`10 > 5`) with
        // `blockIndex = 2`; partition_point(<=5) = 3, -1 = 2.
        let interior = vt_tod(0, 0, 0, vec![0, 5, 5, 10], vec![100, 200, 300, 400]);
        assert_eq!(interior.get_tile_offset(5), Some(300)); // block 2: 300 + 0
        assert_eq!(interior.get_tile_offset(6), Some(301)); // block 2: 300 + 1

        // Trailing dup `[0,5,5]`@5: no element is `> 5`, so CUE4Parse falls to
        // the last iteration where `i == Length-1 && blockIndex == 0` fires and
        // sets `blockIndex = 2`; partition_point(<=5) = 3, -1 = 2. This is the
        // case where the special-case AND duplicates interact.
        let trailing = vt_tod(0, 0, 0, vec![0, 5, 5], vec![100, 200, 300]);
        assert_eq!(trailing.get_tile_offset(5), Some(300)); // last dup block 2
        assert_eq!(trailing.get_tile_offset(9), Some(304)); // block 2: 300 + 4
    }

    #[test]
    fn tile_offset_below_first_address_is_no_data() {
        // The query is below every block start → CUE4Parse would index [-1].
        let tod = vt_tod(0, 0, 0, vec![5, 10], vec![100, 200]);
        assert_eq!(tod.get_tile_offset(3), None);
    }

    #[test]
    fn tile_offset_sentinel_block_is_no_data() {
        let tod = vt_tod(0, 0, 0, vec![0], vec![VT_NO_DATA]);
        assert_eq!(tod.get_tile_offset(0), None);
    }

    #[test]
    fn grid_helpers_round_up_and_border() {
        let vt = VirtualTextureData {
            width: 100,
            height: 64,
            tile_size: 32,
            tile_border_size: 4,
            ..Default::default()
        };
        assert_eq!(vt.width_in_tiles(), 4); // ceil(100 / 32)
        assert_eq!(vt.height_in_tiles(), 2); // 64 / 32
        assert_eq!(vt.physical_tile_size(), 40); // 32 + 2 * 4
    }

    #[test]
    fn grid_helpers_zero_tile_size_is_safe() {
        let vt = VirtualTextureData {
            width: 100,
            tile_size: 0,
            ..Default::default()
        };
        assert_eq!(vt.width_in_tiles(), 0); // no divide-by-zero
        assert_eq!(vt.height_in_tiles(), 0);
    }

    #[test]
    fn physical_tile_size_saturates() {
        let vt = VirtualTextureData {
            tile_size: 10,
            tile_border_size: u32::MAX,
            ..Default::default()
        };
        assert_eq!(vt.physical_tile_size(), u32::MAX); // saturating, no overflow
    }
}
