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
use crate::asset::bulk_data::{BulkData, FByteBulkData, MAX_BULK_DATA_RECORDS_PER_EXPORT};
use crate::asset::read_asset_fstring;
use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

use super::pixel_format::{DecodedTexture, PixelFormat, decode_mip, encoded_len};

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

// Tile-address resolution (3e-VT-c1) + the flatten dispatch (3e-VT-c2). The
// flatten (`flatten_virtual_texture`, consumed by the PNG handler) is the
// production consumer of this whole section, so it carries no `dead_code` allow.

/// The `~0u` sentinel CUE4Parse uses for "no data" in offset arrays.
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
    /// arithmetic, but it remains **unverified**: the 3e-VT-c2 flatten reads
    /// each tile by the trusted `packedOutputSize` (format + physical tile
    /// size), NOT `data_length`, so nothing exercises this field — its only
    /// would-be consumer is the deprecated `ZippedGPU` codec, which c2 rejects.
    /// The span semantics stay a paksmith-defined, end-to-end-unverified
    /// contract. See [`VirtualTextureData::tile_data_ue5`].
    pub data_length: u32,
}

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

    /// CUE4Parse `GetTileOffsetData(level)` reduced to the grid extents the
    /// flatten needs (`width`/`height` in tiles + `max_address`). Legacy:
    /// computed from the per-mip tile-index table; UE5.0+: read from
    /// `tile_offset_data[level]`. `None` on an out-of-range access.
    fn tile_grid_for(&self, level: usize) -> Option<TileGrid> {
        if self.is_legacy_data() {
            // CUE4Parse: MaxAddress = max(TileIndexPerMip[min(level + 1, NumMips)]
            // - TileIndexPerMip[level], 1).
            let level_start = *self.tile_index_per_mip.get(level)?;
            let next = (level + 1).min(self.num_mips as usize);
            let next_start = *self.tile_index_per_mip.get(next)?;
            Some(TileGrid {
                width: self.width_in_tiles(),
                height: self.height_in_tiles(),
                max_address: next_start.saturating_sub(level_start).max(1),
            })
        } else {
            let tod = self.tile_offset_data.get(level)?;
            Some(TileGrid {
                width: tod.width,
                height: tod.height,
                max_address: tod.max_address,
            })
        }
    }

    /// CUE4Parse `GetMinLevel` — the highest-resolution (lowest-index) mip whose
    /// decoded RGBA8 bitmap (`width·tile_size × height·tile_size × 4`) fits
    /// [`MAX_DECODED_TEXTURE_BYTES`](super::pixel_format::MAX_DECODED_TEXTURE_BYTES).
    /// `None` when no level fits — a corrupt or hostile grid — unlike CUE4Parse,
    /// which falls back to level 0 and would then allocate past the cap; the
    /// flatten turns `None` into an error rather than an OOM.
    ///
    /// The scan is bounded by the per-mip grid-data array length, NOT the raw
    /// (attacker-controlled, uncapped) `num_mips`: no level beyond the data
    /// arrays could resolve a grid anyway (`tile_grid_for` returns `None`), so a
    /// huge `num_mips` can't drive a multi-billion-iteration scan.
    ///
    /// This is the bitmap-area gate at the heart of the classify⟂decode fidelity
    /// line. [`flatten_geometry`](Self::flatten_geometry) calls it to pick the
    /// cap-fitting level, and `classify_texture` gates on `flatten_geometry().ok()`
    /// — so classify rules a VT decodable iff `min_level` succeeds *and* the
    /// remaining geometry checks pass. What classify does NOT replicate are the
    /// flatten's further *per-tile* sizing checks: the cap on total per-tile
    /// decode work (a small-bitmap / huge-border grid) and the per-tile
    /// encoded-size-overflow guard. So a pathological VT — a tile border wildly
    /// disproportionate to its tile size — can pass classify and then fail the
    /// decode cleanly (a bounded `UnsupportedFeature`, never an OOM). Mirroring
    /// those rarely-hit per-tile caps into classify would couple it to the
    /// flatten's tile math for no safety gain.
    pub(super) fn min_level(&self) -> Option<usize> {
        let data_levels = self
            .tile_offset_data
            .len()
            .max(self.tile_index_per_mip.len());
        let levels = (self.num_mips as usize).min(data_levels);
        (0..levels).find(|&level| {
            self.tile_grid_for(level)
                .and_then(|grid| grid.bitmap_bytes(self.tile_size))
                .is_some_and(|bytes| bytes <= super::pixel_format::MAX_DECODED_TEXTURE_BYTES)
        })
    }

    /// The output-bitmap geometry [`flatten_virtual_texture`] will produce: the
    /// chosen [`min_level`](Self::min_level), its tile grid, and the decoded
    /// RGBA8 bitmap's pixel dimensions and byte layout.
    ///
    /// This is the single source of truth for the dimensions the flatten
    /// returns. `flatten_virtual_texture` calls it (and then layers on the
    /// format/`packed`/decode-work checks the geometry doesn't need); the
    /// public [`classify_texture`](super::classify_texture) reads it via
    /// `.ok()`, so the dims it advertises to the GUI are *exactly* what the
    /// decode emits — by construction, not by a separately-maintained formula.
    ///
    /// Returns `Err(UnsupportedFeature)` for every cause the flatten rejects
    /// *before producing pixels*, each with its own message: legacy (UE4) data,
    /// a zero tile size, no cap-fitting `min_level`, a missing tile grid, an
    /// over-65536-tile grid axis, a zero grid dimension, or a dimension/size
    /// overflow. It does NOT apply the flatten's further *per-tile* sizing
    /// checks — the decode-work cap and the per-tile encoded-size-overflow guard
    /// (the deliberate classify⟂decode fidelity line documented on
    /// [`min_level`](Self::min_level)) — so a VT this accepts can still fail the
    /// decode cleanly on one of those, but always cleanly: never an OOM.
    pub(super) fn flatten_geometry(&self) -> crate::Result<FlattenGeometry> {
        // Legacy (UE4) VTs are not renderable; reject up front so the flatten —
        // and the `classify_texture` gate that shares this — never offers them.
        if self.is_legacy_data() {
            return Err(vt_unsupported(
                "legacy (UE4) virtual textures are not yet renderable; UE5.0+ virtual textures render",
            ));
        }
        // A zero tile size is malformed (CUE4Parse divides by it in
        // GetWidthInTiles). Reject it up front: it would otherwise zero both DoS
        // caps below (`tile_size² == 0` → `min_level`'s bitmap-bytes and the
        // decode-work product both vacuously fit), leaving the grid loop unbounded.
        if self.tile_size == 0 {
            return Err(vt_unsupported("virtual texture has a zero tile size"));
        }
        // DoS cap 1: the highest-res level whose decoded bitmap fits the cap;
        // error rather than allocate past it (CUE4Parse falls back to level 0).
        let level = self.min_level().ok_or_else(|| {
            vt_unsupported("virtual texture is too large to decode at any mip level")
        })?;
        let grid = self
            .tile_grid_for(level)
            .ok_or_else(|| vt_unsupported("virtual texture mip level has no tile grid"))?;

        // The grid is iterated by `(x, y)` and each cell's Morton address is
        // `morton_code_2(x) | (morton_code_2(y) << 1)`; `morton_code_2` keeps only
        // the low 16 bits, so a tile coordinate ≥ 65536 would alias a lower one
        // (CUE4Parse's `ReverseMortonCode2` likewise never exceeds 65535). Reject a
        // grid that large in either axis — it implies a malformed `TileOffsetData`.
        if grid.width > MAX_VT_GRID_AXIS_TILES || grid.height > MAX_VT_GRID_AXIS_TILES {
            return Err(vt_unsupported(
                "virtual texture tile grid exceeds 65536 tiles on an axis",
            ));
        }
        // A zero grid axis is malformed: a 0-tile-wide/high grid renders no
        // pixels. It also slips past `min_level` — `width·height·tile_size²·4`
        // is 0 when either axis is 0, vacuously within the cap — leaving the
        // OTHER axis's bitmap dimension unconstrained by the cap proof. Reject it
        // so `bitmap_h ≥ tile_size ≥ 1` holds below (see the `row_bytes` note) and
        // so classify never advertises a zero-area Texture view.
        if grid.width == 0 || grid.height == 0 {
            return Err(vt_unsupported(
                "virtual texture tile grid has a zero dimension",
            ));
        }

        // Bitmap dims = tile grid × tile size. CUE4Parse's legacy bitmap-shrink
        // factor fires for legacy data or a single-tile grid (maxLevel == 0); for
        // well-formed UE5.0+ content it is always 1, so paksmith omits it. (A
        // malformed UE5 VT with a 1×1 grid AND MaxAddress > 1 could trip CUE4Parse's
        // shrink; paksmith would instead emit a larger zero-padded bitmap — a safe,
        // deliberate divergence on malformed input, never an OOB.) `min_level`
        // already proved width·height·tile_size²·4 ≤ the cap, so the products fit.
        let (Some(bitmap_w), Some(bitmap_h)) = (
            grid.width.checked_mul(self.tile_size),
            grid.height.checked_mul(self.tile_size),
        ) else {
            return Err(vt_unsupported("virtual texture bitmap dimensions overflow"));
        };
        let Some(total) = (bitmap_w as usize)
            .checked_mul(bitmap_h as usize)
            .and_then(|p| p.checked_mul(4))
        else {
            return Err(vt_unsupported("virtual texture bitmap is too large"));
        };
        // `row_bytes ≤ total`: with `bitmap_h ≥ 1` (zero-axis grids rejected
        // above), `bitmap_w·4 ≤ bitmap_w·bitmap_h·4 = total`, and `total` is the
        // checked, cap-bounded allocation size — so this multiply cannot overflow
        // `usize` even on a 32-bit target.
        let row_bytes = bitmap_w as usize * 4;

        Ok(FlattenGeometry {
            level,
            grid,
            bitmap_w,
            bitmap_h,
            total,
            row_bytes,
        })
    }
}

/// The output-bitmap geometry of a flattened virtual texture, computed once by
/// [`VirtualTextureData::flatten_geometry`] and consumed by both the flatten
/// and `classify_texture`. Only `bitmap_w`/`bitmap_h` are visible outside this
/// module (the dims `classify_texture` reports); the rest are flatten-internal.
#[derive(Debug, Clone, Copy)]
pub(super) struct FlattenGeometry {
    /// The chosen `min_level` (highest-res level whose bitmap fits the cap).
    level: usize,
    /// That level's tile grid (extents + Morton upper bound).
    grid: TileGrid,
    /// Decoded bitmap width in pixels (`grid.width · tile_size`).
    pub(super) bitmap_w: u32,
    /// Decoded bitmap height in pixels (`grid.height · tile_size`).
    pub(super) bitmap_h: u32,
    /// Decoded RGBA8 byte count (`bitmap_w · bitmap_h · 4`), allocation size.
    total: usize,
    /// Decoded bitmap stride in bytes (`bitmap_w · 4`).
    row_bytes: usize,
}

/// The tile-grid extents of one VT mip level — the subset of CUE4Parse's
/// `FVirtualTextureTileOffsetData` the flatten needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TileGrid {
    /// Grid width in tiles.
    width: u32,
    /// Grid height in tiles.
    height: u32,
    /// Tile-address upper bound for this level's Morton iteration.
    max_address: u32,
}

impl TileGrid {
    /// Decoded RGBA8 byte size of this grid's full bitmap
    /// (`width·tile_size × height·tile_size × 4`), in `u64`. `None` on overflow.
    fn bitmap_bytes(self, tile_size: u32) -> Option<u64> {
        u64::from(self.width)
            .checked_mul(u64::from(self.height))?
            .checked_mul(u64::from(tile_size))?
            .checked_mul(u64::from(tile_size))?
            .checked_mul(4)
    }
}

/// CUE4Parse `MathUtils.MortonCode2` — interleave a coordinate's low 16 bits
/// into the even bit positions of a Z-order (Morton) address. The flatten maps
/// each grid cell `(x, y)` to its tile address `morton_code_2(x) |
/// (morton_code_2(y) << 1)`.
///
/// Each `x ^ (x << k)` here (and the `|` that combines the two axes) operates on
/// **disjoint** bit positions selected by the masks, so swapping `^` ↔ `|`
/// yields identical output — those cargo-mutants are equivalent, not test gaps.
fn morton_code_2(mut x: u32) -> u32 {
    x &= 0x0000_ffff;
    x = (x ^ (x << 8)) & 0x00ff_00ff;
    x = (x ^ (x << 4)) & 0x0f0f_0f0f;
    x = (x ^ (x << 2)) & 0x3333_3333;
    x = (x ^ (x << 1)) & 0x5555_5555;
    x
}

// ===== 3e-VT-c2: layer-0 flatten to RGBA8 (port of CUE4Parse TextureDecoder.DecodeVT) =====

/// `EVirtualTextureCodec` discriminants (a chunk's per-layer codec).
const VT_CODEC_BLACK: u8 = 0;
const VT_CODEC_OPAQUE_BLACK: u8 = 1;
const VT_CODEC_WHITE: u8 = 2;
const VT_CODEC_FLAT: u8 = 3;
const VT_CODEC_RAW_GPU: u8 = 4;
const VT_CODEC_ZIPPED_GPU_DEPRECATED: u8 = 5;
const VT_CODEC_CRUNCH_DEPRECATED: u8 = 6;

/// The layer the flatten renders. UE virtual textures may carry several layers
/// (e.g. base color + normal); compositing is deferred (CUE4Parse's
/// single-buffer multi-layer path overwrites earlier layers — its issue #147),
/// so paksmith renders layer 0, the base-color layer.
const FLATTEN_LAYER: u32 = 0;
/// [`FLATTEN_LAYER`] as a slice index.
const FLATTEN_LAYER_IDX: usize = FLATTEN_LAYER as usize;

/// Max tile-grid extent per axis the flatten will render. A tile coordinate is
/// Morton-encoded via [`morton_code_2`], which keeps only the low 16 bits, so
/// `x`/`y` must stay `< 65536`; the grid loop runs `0..width`, so `width` (and
/// `height`) up to `65536` keep every coordinate `≤ 65535`.
const MAX_VT_GRID_AXIS_TILES: u32 = 0x1_0000;

/// The constant RGBA8 fill for a special-fill `EVirtualTextureCodec`, or `None`
/// for a non-constant codec. `Black` is fully transparent; the rest are opaque.
/// `Flat` is the UE "flat normal" `(128, 125, 255)`.
fn vt_special_color(codec: u8) -> Option<[u8; 4]> {
    match codec {
        VT_CODEC_BLACK => Some([0, 0, 0, 0]),
        VT_CODEC_OPAQUE_BLACK => Some([0, 0, 0, 255]),
        VT_CODEC_WHITE => Some([255, 255, 255, 255]),
        VT_CODEC_FLAT => Some([128, 125, 255, 255]),
        _ => None,
    }
}

fn vt_unsupported(context: &str) -> PaksmithError {
    PaksmithError::UnsupportedFeature {
        context: context.to_string(),
    }
}

/// Flatten a UE5.0+ virtual texture's layer-0 tiles into one tightly-packed
/// RGBA8 [`DecodedTexture`] (3e-VT-c2 — port of CUE4Parse
/// `TextureDecoder.DecodeVT`).
///
/// `bulk` is the export's resolved bulk records; a chunk's tile payload is
/// `bulk[chunk.bulk_record_index]`. Tiles are decoded at the highest-resolution
/// mip level whose bitmap fits the decode cap, border-stripped, and stitched
/// into their Z-order grid positions.
///
/// **Scope.** Renders **layer 0** only (compositing deferred). **UE5.0+ only** —
/// legacy (UE4) VTs return [`PaksmithError::UnsupportedFeature`]. The deprecated
/// `ZippedGPU` / `Crunch` codecs are unsupported.
///
/// **Safety.** Every per-tile read is `packedOutputSize` bytes (trusted —
/// derived from the layer format and the fixed physical tile size) sliced with
/// `payload.get(..)`; an out-of-range tile is skipped, never panics. The output
/// allocation is bounded by `min_level`, the total decode work by a separate
/// `num_tiles · packed` cap, and the grid loop by `min_level` plus the
/// zero-tile-size and per-axis tile-count rejections.
///
/// # Errors
/// [`PaksmithError::UnsupportedFeature`] for a legacy VT, a missing/undecodable
/// layer-0 format, a VT too large to decode at any level, or a deprecated codec;
/// plus any [`decode_mip`] fault on a tile's bytes.
pub(crate) fn flatten_virtual_texture(
    vt: &VirtualTextureData,
    bulk: &[BulkData],
    is_normal_map: bool,
) -> crate::Result<DecodedTexture> {
    // Output-bitmap geometry: legacy rejection, the cap-fitting `min_level`, its
    // tile grid, and the bitmap dimensions/size — the single source of truth
    // `classify_texture` also reads, so classify⟂decode dimensions agree by
    // construction. (See `flatten_geometry` for each rejection cause.)
    let geom = vt.flatten_geometry()?;
    let grid = geom.grid;

    let format = PixelFormat::from_name(
        vt.layer_types
            .get(FLATTEN_LAYER_IDX)
            .ok_or_else(|| vt_unsupported("virtual texture has no layer-0 pixel format"))?,
    );

    let tile_size = vt.tile_size;
    let tile_pixel_size = vt.physical_tile_size(); // tile_size + 2*border
    let border = vt.tile_border_size;
    let bitmap_w = geom.bitmap_w;
    let bitmap_h = geom.bitmap_h;
    let total = geom.total;
    let row_bytes = geom.row_bytes;

    // packedOutputSize: the per-tile encoded byte count — trusted (the layer
    // format + the fixed physical tile size), NOT the tile `data_length`.
    // `encoded_len` returns `None` for two distinct causes; split them so the
    // error is accurate. (1) An undecodable format — `classify_texture`
    // pre-screens this, but a direct flatten caller may not. (2) A per-tile
    // encoded size that overflows `u64`/`usize`: an extreme `tile_border_size`
    // inflates `physical_tile_size` toward `u32::MAX`, and for a 16-byte-block
    // format that squares past the integer range. The decodable-but-overflowing
    // case must NOT report "format is not decodable" — the format IS decodable.
    if !super::pixel_format::is_decodable(&format) {
        return Err(vt_unsupported(
            "virtual-texture layer-0 pixel format is not decodable",
        ));
    }
    let packed = encoded_len(&format, tile_pixel_size, tile_pixel_size)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| {
            vt_unsupported(
                "virtual texture per-tile encoded size overflows — tile border disproportionate to tile size",
            )
        })?;

    // DoS cap 2: bound the TOTAL per-tile decode work, not just the output
    // bitmap. `min_level` caps the output (grid · tile_size² · 4), but a large
    // sampling border inflates each tile's *decoded* size to `tile_pixel_size²`
    // independently — so cap `num_tiles · packed` (the trusted per-tile encoded
    // length) against the same ceiling. Rejects a small-bitmap / huge-border VT
    // that would otherwise drive billions of tile decodes.
    let decode_work = u64::from(grid.width)
        .checked_mul(u64::from(grid.height))
        .and_then(|tiles| tiles.checked_mul(packed as u64));
    if !matches!(decode_work, Some(w) if w <= super::pixel_format::MAX_DECODED_TEXTURE_BYTES) {
        return Err(vt_unsupported(
            "virtual texture's total tile-decode work exceeds the decode budget",
        ));
    }

    let layout = FlattenLayout {
        vt,
        bulk,
        format,
        level: geom.level,
        max_address: grid.max_address,
        is_normal_map,
        tile_size,
        tile_pixel_size,
        border,
        packed,
        bitmap_w,
        bitmap_h,
        row_bytes,
    };
    let mut rgba = vec![0u8; total];

    // Iterate the tile grid directly (row-major), O(width · height) — NOT a scan
    // over the Z-order address space, which is O(Morton-extent) and explodes for
    // a degenerate aspect ratio. Each cell maps to its Morton address for the
    // tile-data lookup; the bitmap placement is `(x, y)` directly.
    for y in 0..grid.height {
        for x in 0..grid.width {
            render_tile(&layout, &mut rgba, x, y)?;
        }
    }

    Ok(DecodedTexture {
        width: bitmap_w,
        height: bitmap_h,
        rgba,
    })
}

/// The per-flatten immutable layout + inputs shared across tiles by
/// [`render_tile`].
struct FlattenLayout<'a> {
    vt: &'a VirtualTextureData,
    bulk: &'a [BulkData],
    format: PixelFormat,
    is_normal_map: bool,
    level: usize,
    /// Tile-address upper bound (CUE4Parse `MaxAddress`): grid cells whose
    /// Morton address is `>= max_address` carry no stored data.
    max_address: u32,
    tile_size: u32,
    tile_pixel_size: u32,
    border: u32,
    /// `packedOutputSize` — the trusted per-tile encoded byte length.
    packed: usize,
    bitmap_w: u32,
    bitmap_h: u32,
    row_bytes: usize,
}

/// Decode and stitch the tile at grid cell `(x, y)` into `rgba`. Cells past the
/// stored tile data, unresolved, or whose bytes fall outside the payload are
/// skipped (`Ok(())`). Returns `Err` only for a decode fault or an unsupported
/// codec.
fn render_tile(layout: &FlattenLayout, rgba: &mut [u8], x: u32, y: u32) -> crate::Result<()> {
    // Z-order (Morton) address of this cell: x in the even bits, y in the odd
    // (the inverse of CUE4Parse's `ReverseMortonCode2(addr)` placement).
    let addr = morton_code_2(x) | (morton_code_2(y) << 1);
    if addr >= layout.max_address {
        return Ok(()); // cell beyond the stored tile data
    }
    let (Some(tile_x), Some(tile_y)) = (
        x.checked_mul(layout.tile_size),
        y.checked_mul(layout.tile_size),
    ) else {
        return Ok(());
    };
    let vt = layout.vt;
    let Some(td) = vt.tile_data(layout.level, addr, FLATTEN_LAYER) else {
        return Ok(());
    };
    let Some(chunk) = vt.chunks.get(td.chunk_index) else {
        return Ok(());
    };
    let Some(codec) = chunk.layer_codecs.get(FLATTEN_LAYER_IDX) else {
        return Ok(());
    };
    match codec.codec_type {
        VT_CODEC_RAW_GPU => {
            let payload = layout
                .bulk
                .get(chunk.bulk_record_index)
                .map_or(&[][..], |b| b.bytes.as_slice());
            // Trusted-length slice, bounds-checked: skip a tile whose bytes fall
            // outside the chunk payload (never panics).
            let slice = usize::try_from(td.byte_offset)
                .ok()
                .and_then(|s| s.checked_add(layout.packed).map(|e| s..e))
                .and_then(|range| payload.get(range));
            let Some(slice) = slice else {
                return Ok(());
            };
            let tile = decode_mip(
                &layout.format,
                slice,
                layout.tile_pixel_size,
                layout.tile_pixel_size,
                layout.is_normal_map,
                "<virtual texture tile>",
            )?;
            stitch_tile(
                rgba,
                layout.row_bytes,
                layout.bitmap_h,
                &tile.rgba,
                layout.tile_pixel_size,
                layout.tile_size,
                layout.border,
                tile_x,
                tile_y,
            );
        }
        VT_CODEC_ZIPPED_GPU_DEPRECATED | VT_CODEC_CRUNCH_DEPRECATED => {
            return Err(vt_unsupported(
                "virtual-texture deprecated codec (ZippedGPU/Crunch) is not supported",
            ));
        }
        // Codecs 0..=3 paint a constant color; 5/6 are caught by the arm above;
        // anything else here (the 7 Max-sentinel or a future value) is
        // unrecognized. (A `let-else`, not an `if let` match guard — the latter
        // is still unstable at the CI MSRV.)
        other => {
            let Some(color) = vt_special_color(other) else {
                return Err(vt_unsupported(
                    "virtual-texture layer uses an unrecognized codec",
                ));
            };
            fill_tile(
                rgba,
                layout.row_bytes,
                layout.bitmap_w,
                layout.bitmap_h,
                color,
                layout.tile_size,
                tile_x,
                tile_y,
            );
        }
    }
    Ok(())
}

/// Copy a decoded `tile_pixel_size`-square RGBA8 tile's border-stripped interior
/// (the `tile_size`-square region offset by `border` on each edge) into `rgba`
/// at `(tile_x, tile_y)`. Rows/columns landing outside the bitmap or either
/// buffer are clipped — defensive; a valid address keeps the tile in bounds.
#[allow(clippy::too_many_arguments)]
fn stitch_tile(
    rgba: &mut [u8],
    row_bytes: usize,
    bitmap_h: u32,
    tile: &[u8],
    tile_pixel_size: u32,
    tile_size: u32,
    border: u32,
    tile_x: u32,
    tile_y: u32,
) {
    let tile_pitch = tile_pixel_size as usize * 4;
    let copy_bytes = tile_size as usize * 4;
    for i in 0..tile_size {
        let dst_y = tile_y + i;
        if dst_y >= bitmap_h {
            break;
        }
        let src_off = ((i + border) as usize)
            .checked_mul(tile_pitch)
            .and_then(|o| o.checked_add(border as usize * 4));
        let dst_off = (dst_y as usize)
            .checked_mul(row_bytes)
            .and_then(|o| o.checked_add(tile_x as usize * 4));
        let (Some(src_off), Some(dst_off)) = (src_off, dst_off) else {
            break;
        };
        // Clip the row to both buffers (equal-length slices for copy_from_slice).
        let src_avail = tile.len().saturating_sub(src_off);
        let dst_avail = rgba.len().saturating_sub(dst_off);
        let n = copy_bytes.min(src_avail).min(dst_avail);
        if n == 0 {
            continue;
        }
        rgba[dst_off..dst_off + n].copy_from_slice(&tile[src_off..src_off + n]);
    }
}

/// Fill a `tile_size`-square region at `(tile_x, tile_y)` with a constant RGBA8
/// `color` (special-fill codecs), clipped to the bitmap.
#[allow(clippy::too_many_arguments)]
fn fill_tile(
    rgba: &mut [u8],
    row_bytes: usize,
    bitmap_w: u32,
    bitmap_h: u32,
    color: [u8; 4],
    tile_size: u32,
    tile_x: u32,
    tile_y: u32,
) {
    let cols = tile_size.min(bitmap_w.saturating_sub(tile_x)) as usize;
    for i in 0..tile_size {
        let dst_y = tile_y + i;
        if dst_y >= bitmap_h {
            break;
        }
        let Some(row_start) = (dst_y as usize)
            .checked_mul(row_bytes)
            .and_then(|o| o.checked_add(tile_x as usize * 4))
        else {
            break;
        };
        for col in 0..cols {
            let px = row_start + col * 4;
            if px + 4 <= rgba.len() {
                rgba[px..px + 4].copy_from_slice(&color);
            }
        }
    }
}

/// `numerator / denominator` rounded up (CUE4Parse `DivideAndRoundUp`). `0`
/// when `denominator == 0` (CUE4Parse would divide by zero); the guard also
/// keeps [`u32::div_ceil`] from panicking.
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
        // contract). CodecPayloadOffset is `u32` for UE 4.27+/UE5, else `u16`,
        // gated on object version `522` (`is_ue4_27_or_later`). CUE4Parse gates
        // on the *engine* version (`Ar.Game >= GAME_UE4_27`); the widening falls
        // inside object version `522`, so genuine 4.26 VT content (also `522`)
        // is over-read as `u32` here — see `VER_UE4_GAME_UE4_27_OBJECT_PROXY`.
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
        let bulk = FByteBulkData::read_from_ctx(cur, ctx, asset_path)?;
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

    // ----- 3e-VT-c2: flatten dispatch (Morton / IsValidAddress / GetTileOffsetData
    // / GetMinLevel) -----

    #[test]
    fn morton_code_2_interleaves_into_even_bits() {
        // Interleave a coordinate's bits into the even positions.
        assert_eq!(morton_code_2(0), 0);
        assert_eq!(morton_code_2(1), 1); // bit 0 → bit 0
        assert_eq!(morton_code_2(2), 0b0100); // bit 1 → bit 2
        assert_eq!(morton_code_2(3), 0b0101); // bits 0,1 → 0,2
        assert_eq!(morton_code_2(0xFFFF), 0x5555_5555); // all 16 → even bits
        // Z-order address of a grid cell: addr = mc(x) | (mc(y) << 1). The 2×2
        // cells (0,0),(1,0),(0,1),(1,1) map to addresses 0,1,2,3.
        let addr = |x: u32, y: u32| morton_code_2(x) | (morton_code_2(y) << 1);
        assert_eq!(
            [addr(0, 0), addr(1, 0), addr(0, 1), addr(1, 1)],
            [0, 1, 2, 3]
        );
    }

    #[test]
    fn tile_grid_for_ue5_reads_tile_offset_data() {
        let tod = vt_tod(3, 5, 7, vec![0], vec![0]);
        let vt = ue5_vt(1, vec![10], vec![0], vec![0], vec![tod], 1);
        assert_eq!(
            vt.tile_grid_for(0),
            Some(TileGrid {
                width: 3,
                height: 5,
                max_address: 7,
            }),
        );
        assert_eq!(vt.tile_grid_for(1), None); // past the table
    }

    #[test]
    fn tile_grid_for_legacy_computes_max_address_span() {
        // width=64,height=64,tile_size=32 → 2×2 tiles. 2 mips: [0,4,5].
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 2,
            width: 64,
            height: 64,
            tile_size: 32,
            tile_index_per_mip: vec![0, 4, 5],
            tile_offset_in_chunk: vec![0], // non-empty → legacy
            ..Default::default()
        };
        // level 0: max_address = max(TileIndexPerMip[1] - TileIndexPerMip[0], 1) = 4.
        assert_eq!(
            vt.tile_grid_for(0),
            Some(TileGrid {
                width: 2,
                height: 2,
                max_address: 4,
            }),
        );
        // level 1: min(level+1, NumMips) = min(2,2) = 2 → TileIndexPerMip[2]=5;
        // 5 - TileIndexPerMip[1]=4 → 1.
        assert_eq!(vt.tile_grid_for(1).unwrap().max_address, 1);
    }

    #[test]
    fn min_level_picks_highest_res_level_that_fits() {
        // tile_size 128. Level 0 grid is enormous (won't fit 1 GiB); level 1 is
        // tiny. min_level skips 0 and returns 1.
        let vt = VirtualTextureData {
            num_mips: 2,
            tile_size: 128,
            tile_offset_data: vec![
                vt_tod(100_000, 100_000, 1, vec![], vec![]),
                vt_tod(2, 2, 1, vec![], vec![]),
            ],
            ..Default::default()
        };
        assert_eq!(vt.min_level(), Some(1));
    }

    #[test]
    fn min_level_returns_level_0_when_it_fits() {
        let tod = vt_tod(2, 2, 4, vec![0], vec![0]);
        let vt = ue5_vt(1, vec![10], vec![0], vec![0], vec![tod], 1);
        // ue5_vt sets num_mips = base_offset_per_mip.len() = 1.
        assert_eq!(vt.min_level(), Some(0));
    }

    #[test]
    fn min_level_is_none_when_no_level_fits() {
        // Both levels exceed the 1 GiB decoded-bitmap cap.
        let vt = VirtualTextureData {
            num_mips: 2,
            tile_size: 256,
            tile_offset_data: vec![
                vt_tod(50_000, 50_000, 1, vec![], vec![]),
                vt_tod(40_000, 40_000, 1, vec![], vec![]),
            ],
            ..Default::default()
        };
        assert_eq!(vt.min_level(), None);
    }

    #[test]
    fn min_level_scan_is_bounded_by_data_arrays_not_num_mips() {
        // `num_mips` is an uncapped wire u32; the scan must be bounded by the
        // grid-data array length (1 entry here), NOT iterate ~4.3e9 times. The
        // one level's grid is too big → None, returned promptly (this test would
        // hang without the bound).
        let vt = VirtualTextureData {
            num_mips: u32::MAX,
            tile_size: 256,
            tile_offset_data: vec![vt_tod(50_000, 50_000, 1, vec![0], vec![0])],
            ..Default::default()
        };
        assert_eq!(vt.min_level(), None);
    }

    // ----- 3e-VT-c2: flatten golden vectors -----

    /// A single-chunk VT chunk carrying `codec_type` for layer 0, payload at
    /// bulk record 0.
    fn vt_chunk_codec(codec_type: u8) -> VirtualTextureDataChunk {
        VirtualTextureDataChunk {
            bulk_data_hash: None,
            size_in_bytes: 0,
            codec_payload_size: 0,
            layer_codecs: vec![LayerCodec {
                codec_type,
                codec_payload_offset: 0,
            }],
            bulk_record_index: 0,
        }
    }

    fn raw_bulk(bytes: Vec<u8>) -> BulkData {
        BulkData {
            bytes,
            record: dummy_bulk_record(),
            tier: crate::asset::bulk_data::BulkDataTier::Inline,
        }
    }

    /// 2×2-tile UE5 VT, 1×1-pixel tiles (no border), one RawGPU `PF_B8G8R8A8`
    /// chunk whose payload holds 4 distinct tile colors. `tile_data(addr)`
    /// resolves `byte_offset = addr·4` (tile_offset·tileDataSize), so address N
    /// reads the Nth color.
    fn morton_grid_vt() -> (VirtualTextureData, Vec<BulkData>) {
        let tod = vt_tod(2, 2, 4, vec![0], vec![0]); // get_tile_offset(addr) = addr
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 1,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![4],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_RAW_GPU)],
            ..Default::default()
        };
        let payload = vec![
            0, 0, 255, 255, // addr 0 → red   (wire B,G,R,A)
            0, 255, 0, 255, // addr 1 → green
            255, 0, 0, 255, // addr 2 → blue
            255, 255, 255, 255, // addr 3 → white
        ];
        (vt, vec![raw_bulk(payload)])
    }

    #[test]
    fn flatten_rawgpu_morton_places_tiles_by_z_order() {
        let (vt, bulk) = morton_grid_vt();
        let out = flatten_virtual_texture(&vt, &bulk, false).expect("flatten");
        assert_eq!((out.width, out.height), (2, 2));
        // B8G8R8A8 → RGBA swizzle; Morton: 0→(0,0) 1→(1,0) 2→(0,1) 3→(1,1).
        assert_eq!(&out.rgba[0..4], &[255, 0, 0, 255], "(0,0) red");
        assert_eq!(&out.rgba[4..8], &[0, 255, 0, 255], "(1,0) green");
        assert_eq!(&out.rgba[8..12], &[0, 0, 255, 255], "(0,1) blue");
        assert_eq!(&out.rgba[12..16], &[255, 255, 255, 255], "(1,1) white");
    }

    #[test]
    fn flatten_geometry_matches_flatten_output_dimensions() {
        // `flatten_virtual_texture` sizes its output bitmap from
        // `flatten_geometry`, and `classify_texture` reads the same helper — so
        // the dims classify advertises are exactly the decode's. Pin that the
        // flatten doesn't override the geometry's dims (a future regression where
        // it recomputes them independently would reintroduce classify⟂decode
        // drift). grid 2×2 × tile_size 1 → 2×2 bitmap.
        let (vt, bulk) = morton_grid_vt();
        let geom = vt
            .flatten_geometry()
            .expect("a decodable VT must yield geometry");
        let out = flatten_virtual_texture(&vt, &bulk, false).expect("flatten");
        assert_eq!(
            (geom.bitmap_w, geom.bitmap_h),
            (out.width, out.height),
            "flatten output dims must equal flatten_geometry's bitmap dims",
        );
    }

    #[test]
    fn flatten_geometry_rejects_legacy_vt() {
        // Legacy (UE4) VTs are not renderable; `flatten_geometry` must refuse
        // them up front so `classify_texture` (which gates on it via `.ok()`)
        // never offers an undecodable Texture view — the unit-level companion to
        // `classify_texture_legacy_virtual_is_none`.
        let vt = legacy_vt(1, vec![0, 64], 128);
        assert!(vt.is_legacy_data(), "fixture must be legacy");
        let err = vt
            .flatten_geometry()
            .expect_err("a legacy VT must be rejected");
        assert!(
            matches!(err, PaksmithError::UnsupportedFeature { ref context } if context.contains("legacy")),
            "legacy rejection must name the cause, got {err:?}",
        );
    }

    #[test]
    fn flatten_geometry_rejects_zero_grid_dimension() {
        // A grid with a zero axis renders no pixels AND slips past `min_level`
        // (`width·height·tile_size²·4 == 0` vacuously fits the cap), which would
        // leave the OTHER axis's bitmap dimension unconstrained by the cap proof.
        // `flatten_geometry` must reject either-axis-zero so `bitmap_h ≥ 1` holds
        // for the `row_bytes` multiply and classify never advertises a zero-area
        // Texture view. Both axes are exercised to pin the full `||` guard.
        for (w, h, axis) in [(8u32, 0u32, "height"), (0u32, 8u32, "width")] {
            let vt = VirtualTextureData {
                num_layers: 1,
                num_mips: 1,
                tile_size: 4,
                tile_offset_data: vec![vt_tod(w, h, 1, vec![0], vec![0])],
                layer_types: vec!["PF_DXT1".to_string()],
                ..Default::default()
            };
            // Precondition: min_level accepts it (zero-area bitmap is 0 ≤ cap), so
            // the zero-dimension guard — not min_level — is what must reject it.
            assert_eq!(
                vt.min_level(),
                Some(0),
                "{axis}-zero grid must still pass min_level (0 bytes ≤ cap)"
            );
            let err = vt
                .flatten_geometry()
                .expect_err("a zero grid dimension must be rejected");
            assert!(
                matches!(err, PaksmithError::UnsupportedFeature { ref context }
                    if context.contains("zero dimension")),
                "the {axis} axis being zero must be rejected by name, got {err:?}",
            );
        }
    }

    #[test]
    fn flatten_rejects_overflowing_per_tile_encoded_size_with_accurate_message() {
        // A decodable 16-byte-per-block format (BC3 / PF_DXT5) with a tile border
        // so large that `physical_tile_size` saturates to ~u32::MAX makes the
        // per-tile encoded size overflow u64. `flatten_geometry` still passes —
        // the small `tile_size` keeps the OUTPUT bitmap tiny — so this is a
        // classify→decode divergence that must fail cleanly AND name the real
        // cause: the format IS decodable, so the message must not claim otherwise.
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 1,
            tile_border_size: u32::MAX / 2, // physical tile saturates to ~u32::MAX
            tile_offset_data: vec![vt_tod(1, 1, 1, vec![0], vec![0])],
            layer_types: vec!["PF_DXT5".to_string()],
            ..Default::default()
        };
        // Precondition: the output-bitmap geometry accepts it (tiny bitmap), so
        // the only thing left to reject is the per-tile encoded-size overflow —
        // not geometry. (PF_DXT5 is decodable, so the "not decodable" arm is not
        // what fires; the message assertion below would fail loudly if it were.)
        assert!(
            vt.flatten_geometry().is_ok(),
            "the tiny output bitmap must pass geometry — the overflow is per-tile, not output"
        );
        let err = flatten_virtual_texture(&vt, &[], false)
            .expect_err("an overflowing per-tile encoded size must be rejected");
        assert!(
            matches!(err, PaksmithError::UnsupportedFeature { ref context }
                if context.contains("encoded size overflows")),
            "the message must name the encoded-size overflow, not a format problem, got {err:?}",
        );
    }

    #[test]
    fn flatten_special_fill_white_tile() {
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 2,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![16],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_WHITE)],
            ..Default::default()
        };
        // Special-fill reads no payload.
        let out = flatten_virtual_texture(&vt, &[], false).expect("flatten");
        assert_eq!((out.width, out.height), (2, 2));
        assert!(
            out.rgba
                .chunks_exact(4)
                .all(|px| px == [255, 255, 255, 255]),
            "every pixel is opaque white"
        );
    }

    #[test]
    fn flatten_strips_tile_border() {
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 2,
            tile_border_size: 1, // physical tile 4×4, interior 2×2 at (1,1)
            tile_data_offset_per_layer: vec![64],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_RAW_GPU)],
            ..Default::default()
        };
        // 4×4 B8G8R8A8 tile: border = transparent black, interior 2×2 distinct.
        let mut tile = vec![0u8; 64];
        let mut put = |x: usize, y: usize, bgra: [u8; 4]| {
            let off = (y * 4 + x) * 4;
            tile[off..off + 4].copy_from_slice(&bgra);
        };
        put(1, 1, [0, 0, 255, 255]); // → output (0,0) red
        put(2, 1, [0, 255, 0, 255]); // → output (1,0) green
        put(1, 2, [255, 0, 0, 255]); // → output (0,1) blue
        put(2, 2, [255, 255, 255, 255]); // → output (1,1) white
        let out = flatten_virtual_texture(&vt, &[raw_bulk(tile)], false).expect("flatten");
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!(&out.rgba[0..4], &[255, 0, 0, 255], "(0,0) = interior (1,1)");
        assert_eq!(&out.rgba[4..8], &[0, 255, 0, 255], "(1,0) = interior (2,1)");
        assert_eq!(
            &out.rgba[8..12],
            &[0, 0, 255, 255],
            "(0,1) = interior (1,2)"
        );
        assert_eq!(
            &out.rgba[12..16],
            &[255, 255, 255, 255],
            "(1,1) = interior (2,2)"
        );
    }

    #[test]
    fn flatten_skips_tile_with_out_of_range_payload() {
        // Empty payload → every RawGPU tile's slice is out of range → skipped,
        // never panics; the bitmap stays zeroed.
        let (vt, _) = morton_grid_vt();
        let out = flatten_virtual_texture(&vt, &[raw_bulk(Vec::new())], false).expect("flatten");
        assert_eq!((out.width, out.height), (2, 2));
        assert!(out.rgba.iter().all(|&b| b == 0), "all tiles skipped");
    }

    #[test]
    fn flatten_rejects_legacy_vt() {
        let vt = legacy_vt(1, vec![0, 64], 128); // non-empty tile_offset_in_chunk → legacy
        assert!(matches!(
            flatten_virtual_texture(&vt, &[], false),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn flatten_rejects_deprecated_codec() {
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 1,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![4],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_ZIPPED_GPU_DEPRECATED)],
            ..Default::default()
        };
        // The message must name "deprecated" (distinct from the unknown-codec
        // arm), so dropping the deprecated arm — which would route 5/6 to the
        // generic `_` arm — is caught.
        match flatten_virtual_texture(&vt, &[raw_bulk(vec![0; 4])], false) {
            Err(PaksmithError::UnsupportedFeature { context }) => {
                assert!(context.contains("deprecated"), "got: {context}");
            }
            other => panic!("expected a deprecated-codec UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn flatten_rejects_oversized_vt() {
        // No mip level's bitmap fits the decode cap → min_level None → error.
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 256,
            tile_data_offset_per_layer: vec![4],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![vt_tod(50_000, 50_000, 1, vec![0], vec![0])],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_WHITE)],
            ..Default::default()
        };
        assert!(matches!(
            flatten_virtual_texture(&vt, &[], false),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn flatten_rejects_decode_amplification() {
        // A small OUTPUT bitmap (passes min_level) but a huge sampling border:
        // tile_size=1, border=8192 → physical 16385, packed ≈ 1 GiB PER TILE.
        // A 2×2 grid (4 tiles) would drive ~4 GiB of decode work → the
        // decode-work cap rejects it even though the 2×2×1 output is tiny.
        let tod = vt_tod(2, 2, 4, vec![0], vec![0]);
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 1,
            tile_border_size: 8192,
            tile_data_offset_per_layer: vec![4],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_RAW_GPU)],
            ..Default::default()
        };
        assert!(matches!(
            flatten_virtual_texture(&vt, &[raw_bulk(vec![0; 16])], false),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    /// A 1×1-tile (2×2-pixel) UE5 VT whose single chunk uses `codec`.
    fn special_fill_vt(codec: u8) -> VirtualTextureData {
        let tod = vt_tod(1, 1, 1, vec![0], vec![0]);
        VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 2,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![16],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(codec)],
            ..Default::default()
        }
    }

    #[test]
    fn flatten_special_fill_codec_colors() {
        // Each special-fill codec paints its constant RGBA8 (Black transparent).
        for (codec, color) in [
            (VT_CODEC_BLACK, [0, 0, 0, 0]),
            (VT_CODEC_OPAQUE_BLACK, [0, 0, 0, 255]),
            (VT_CODEC_WHITE, [255, 255, 255, 255]),
            (VT_CODEC_FLAT, [128, 125, 255, 255]),
        ] {
            let out = flatten_virtual_texture(&special_fill_vt(codec), &[], false)
                .unwrap_or_else(|e| panic!("codec {codec} flatten: {e:?}"));
            assert!(
                out.rgba.chunks_exact(4).all(|px| px == color),
                "codec {codec} should fill {color:?}",
            );
        }
    }

    #[test]
    fn flatten_special_fill_at_nonzero_tile_x() {
        // A 2×1-tile White grid: the second tile sits at tile_x = tile_size, so
        // `fill_tile` must place it at a nonzero column (pins the `tile_x * 4`
        // destination offset, which a 1×1 grid leaves at 0).
        let tod = vt_tod(2, 1, 2, vec![0], vec![0]);
        let vt = VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 2,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![16],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![tod],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_WHITE)],
            ..Default::default()
        };
        let out = flatten_virtual_texture(&vt, &[], false).expect("flatten");
        assert_eq!((out.width, out.height), (4, 2)); // 2 tiles × tile_size 2
        assert!(
            out.rgba
                .chunks_exact(4)
                .all(|px| px == [255, 255, 255, 255]),
            "both tiles white — the second at column 2 (tile_x = 2)",
        );
    }

    #[test]
    fn flatten_rejects_unknown_codec() {
        // Codec 7 (Max sentinel) is neither RawGPU, a special fill, nor a known
        // deprecated codec → UnsupportedFeature.
        assert!(matches!(
            flatten_virtual_texture(&special_fill_vt(7), &[], false),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn flatten_rejects_zero_tile_size() {
        // tile_size == 0 zeroes both DoS caps (bitmap-bytes and decode-work) →
        // the grid loop would be unbounded. Rejected up front.
        let mut vt = special_fill_vt(VT_CODEC_WHITE);
        vt.tile_size = 0;
        assert!(matches!(
            flatten_virtual_texture(&vt, &[], false),
            Err(PaksmithError::UnsupportedFeature { .. })
        ));
    }

    #[test]
    fn flatten_grid_axis_boundary_accepts_65536_rejects_65537() {
        // 65536 tiles on an axis is the max representable (loop x ∈ 0..width →
        // x ≤ 65535, inside morton_code_2's 16-bit domain); 65537 would alias
        // (x = 65536 → 0). The bitmap still fits the decode cap, so the per-axis
        // guard — not min_level — draws the line. Both axes, both sides of `>`.
        let make = |w: u32, h: u32| VirtualTextureData {
            num_layers: 1,
            num_mips: 1,
            tile_size: 1,
            tile_border_size: 0,
            tile_data_offset_per_layer: vec![4],
            base_offset_per_mip: vec![0],
            chunk_index_per_mip: vec![0],
            tile_offset_data: vec![vt_tod(w, h, 1, vec![0], vec![0])],
            layer_types: vec!["PF_B8G8R8A8".to_string()],
            chunks: vec![vt_chunk_codec(VT_CODEC_WHITE)],
            ..Default::default()
        };
        // Exactly 65536 on either axis is accepted (no aliasing).
        assert!(flatten_virtual_texture(&make(0x1_0000, 1), &[], false).is_ok());
        assert!(flatten_virtual_texture(&make(1, 0x1_0000), &[], false).is_ok());
        // 65537 on either axis is rejected.
        for vt in [make(0x1_0001, 1), make(1, 0x1_0001)] {
            assert!(matches!(
                flatten_virtual_texture(&vt, &[], false),
                Err(PaksmithError::UnsupportedFeature { .. })
            ));
        }
    }
}
