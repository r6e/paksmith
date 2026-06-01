//! `UTexture2D` export reader (Phase 3e).
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md` (oracle
//! `FabianFG/CUE4Parse` `UTexture2D.cs` / `FTexturePlatformData.cs` @
//! `cf74fc32`). The export payload has two back-to-back segments:
//!
//! 1. **Tagged-property stream** — the standard None-terminated
//!    `FPropertyTag` stream (`SRGB`, `CompressionSettings`, `Filter`,
//!    `LODBias`, …), decoded by the existing
//!    [`read_properties`](crate::asset::property::read_properties).
//! 2. **`FTexturePlatformData` blob** — `SizeX`/`SizeY`, the
//!    `PackedData` bit field, the `PixelFormat` name, optional
//!    `OptData`/`CPUCopy` sub-records, and the `FTexture2DMipMap[]`
//!    mip chain.
//!
//! **3e-3 scope: segment 1 + the full `FTexturePlatformData`.**
//! [`read_from`] decodes the tagged-property stream, then the whole
//! segment-2 header: the UE 5.0/5.2 stripped-data prefix, `SizeX`,
//! `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then the conditional
//! `OptData` (bit 30) / `CPUCopy` (bit 29) sub-records,
//! `FirstMipToSerialize`, and the mip-count prefix (3e-2b). It then reads
//! the `mip_count` per-mip `FTexture2DMipMap` records (3e-3): each is
//! `bCooked` (UE4 only) + an `FByteBulkData` payload record + the mip's
//! `SizeX`/`SizeY`/`SizeZ`. The per-mip dimensions land in
//! [`Texture2DData::mips`]; the `FByteBulkData` records are returned as
//! [`read_from`]'s second tuple element so the dispatch caller can store
//! them in `Package` for lazy resolution (the mip bytes live in
//! `.uasset`/`.uexp`/`.ubulk`). Wiring those records into `Package` is
//! 3e-3b's job — until then the dispatch caller collects-and-discards
//! them, which is structurally harmless: `Package::read_payloads` carves
//! each export by `serial_offset`/`serial_size` and never inspects how
//! many bytes a typed reader consumed.

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::PaksmithError;
use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::read_properties;
use crate::asset::version::VER_UE5_DATA_RESOURCES;
use crate::asset::{
    Asset, AssetContext, Texture2DData, Texture2DMipMap, read_asset_fstring, skip_asset_bytes,
};
use crate::error::{AssetParseFault, AssetWireField};

/// Maximum `SizeX` / `SizeY` accepted from `FTexturePlatformData`. The
/// GPU-sampler dimension limit on most hardware; per
/// `docs/formats/texture/texture2d.md` §Caps. A corrupt dimension field
/// claiming billions of pixels would otherwise drive a multi-GB decode
/// buffer (Phase 3e-2).
const MAX_TEXTURE_DIMENSION: i32 = 16384;

/// `FTexturePlatformData`'s UE 5.0+ stripped-data prefix
/// (`PlaceholderDerivedDataSize`) — a fixed 16-byte opaque skip in
/// cooked content. On UE 5.2+ the first of these 16 bytes is the
/// `bUsingDerivedData` flag (so 1 flag byte + 15 skipped).
const PLACEHOLDER_DERIVED_DATA_SIZE: u64 = 16;

/// `PackedData` low-30-bits `NumSlices` mask (`0x3FFF_FFFF`). Bit 29
/// (`HasCpuCopy`) overlaps the top of this mask; CUE4Parse's
/// `GetNumSlices()` does NOT strip it, and paksmith follows the same
/// convention for cross-validation parity (`texture2d.md` §Caps).
const PACKED_DATA_NUM_SLICES_MASK: u32 = 0x3FFF_FFFF;

/// `PackedData` cubemap flag (bit 31).
const PACKED_DATA_CUBEMAP_BIT: u32 = 1 << 31;

/// `PackedData` `HasOptData` flag (bit 30) — when set, an
/// `FOptTexturePlatformData` (`ExtData` + `NumMipsInTail`) follows the
/// `PixelFormat`.
const PACKED_DATA_HAS_OPT_DATA_BIT: u32 = 1 << 30;

/// `PackedData` `HasCpuCopy` flag (bit 29) — when set (UE 5.4+ writers),
/// an `FSharedImage` CPU-copy record follows the optional `OptData`.
const PACKED_DATA_HAS_CPU_COPY_BIT: u32 = 1 << 29;

/// Maximum mip count accepted from the `FTexturePlatformData` mip-count
/// prefix. A real texture has ~`log2(16384) ≈ 14` mips; `32` is
/// generous. Bounds the per-mip allocation the mip-record loop drives
/// (`texture2d.md` §Caps).
const MAX_MIP_COUNT: i32 = 32;

/// Maximum `FOptTexturePlatformData::NumMipsInTail` (matches
/// `MAX_MIP_COUNT`; `texture2d.md` §Caps).
const MAX_MIPS_IN_TAIL: u32 = 32;

/// Maximum `FSharedImage` (CPU-copy) `RawDataLen` accepted before the
/// payload-bounded skip — 8 GiB, matching the pak layer's
/// `MAX_UNCOMPRESSED_ENTRY_BYTES` (`texture2d.md` §Caps). The CPU-copy
/// payload is attacker-controllable.
const MAX_CPU_COPY_RAW_DATA_LEN: u64 = 8 * 1024 * 1024 * 1024;

/// Byte size of the `FSharedImage` fixed header preceding `RawDataLen`:
/// `SizeX` (4) + `SizeY` (4) + `SizeZ` (4) + `Format` (1) +
/// `GammaSpace` (1) = 14. paksmith skips the CPU-copy record entirely
/// (it's a redundant inline decode, not needed for PNG export).
const CPU_COPY_FIXED_HEADER_BYTES: u64 = 14;

// NOTE: a `#[cfg(feature = "__test_utils")] max_texture_dimension()`
// accessor (mirroring `max_rows_per_datatable`) is deferred until its
// first consumer — an integration boundary test in `paksmith-core-tests`.
// Adding it here with no caller would be an uncovered passthrough
// (`fn -> i32 { CONST }` survives `-> 0` / `-> 1` mutants until a test
// reads it). The in-source tests below pin the cap via the
// `TextureDimensionExceeded { cap }` field instead.

/// Parse a `UTexture2D` export payload into [`Texture2DData`].
///
/// `payload` is the export's `serial_size`-bounded byte slice. Segment 1
/// (tagged properties) plus the **full** `FTexturePlatformData` are
/// decoded: the version-gated stripped-data prefix, `SizeX`, `SizeY`,
/// `PackedData`, `PixelFormat`, the conditional `OptData` / `CPUCopy`
/// sub-records, `FirstMipToSerialize`, the mip-count prefix (3e-2), and
/// the `mip_count` per-mip `FTexture2DMipMap` records (3e-3). Returns the
/// [`Texture2DData`] (per-mip dimensions in [`Texture2DData::mips`]) plus
/// the per-mip [`FByteBulkData`] records, positionally aligned with
/// `mips`, for the dispatch caller to store in `Package` (see the module
/// docs).
///
/// # Errors
/// - Any tagged-property fault from the nested [`read_properties`] read.
/// - [`AssetParseFault::TextureDerivedDataNotAvailable`] if a UE 5.2+
///   texture sets `bUsingDerivedData`.
/// - [`AssetParseFault::TextureDimensionExceeded`] /
///   [`AssetParseFault::TextureMipCountExceeded`] /
///   [`AssetParseFault::TextureMipsInTailExceeded`] /
///   [`AssetParseFault::TextureCpuCopyDataLenExceeded`] on a negative or
///   over-cap field.
/// - [`AssetParseFault::UnexpectedEof`] / FString faults from the
///   header reads.
pub(crate) fn read_from(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Texture2DData, Vec<FByteBulkData>)> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: tagged properties (None-terminated). Stops at "None".
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;

    // Segment 2: FTexturePlatformData header (3e-2).
    let header = read_platform_data_header(&mut cur, ctx, asset_path)?;

    // Segment 2 (cont.): the per-mip FTexture2DMipMap records (3e-3).
    // `bulk_records` are returned to the dispatch caller, which stores
    // them in `Package` so the bytes resolve lazily; `mips` holds the
    // per-mip dimensions. They correspond positionally (`mips[i]` ↔
    // `bulk_records[i]`).
    let (mips, bulk_records) = read_mip_records(&mut cur, ctx, header.mip_count, asset_path)?;

    let data = Texture2DData {
        properties: PropertyBag::Tree { properties },
        size_x: header.size_x,
        size_y: header.size_y,
        pixel_format: header.pixel_format,
        num_slices: header.num_slices,
        is_cubemap: header.is_cubemap,
        num_mips_in_tail: header.num_mips_in_tail,
        // NOTE: `first_mip_to_serialize` is stored UNVALIDATED (CUE4Parse
        // reads it as a plain i32 with no bound). It's metadata for the
        // streaming system, not used as an index here. A consumer that
        // uses it to select/skip a mip (3e-8 `PngHandler`) MUST bound it
        // against `mips.len()` at that use site.
        first_mip_to_serialize: header.first_mip_to_serialize,
        mip_count: header.mip_count,
        mips,
    };
    Ok((data, bulk_records))
}

/// Read the `mip_count` per-mip `FTexture2DMipMap` records that follow
/// the platform-data header: each is `bCooked` (UE4 only) + an
/// `FByteBulkData` (the mip's payload metadata) + `SizeX`/`SizeY`/`SizeZ`.
/// Returns the per-mip dimensions and the collected `FByteBulkData`
/// records (positionally aligned). The records are handed up to the
/// dispatch caller for `Package` storage; the bytes resolve lazily.
fn read_mip_records(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    mip_count: u32,
    asset_path: &str,
) -> crate::Result<(Vec<Texture2DMipMap>, Vec<FByteBulkData>)> {
    // `mip_count` is already capped at `MAX_MIP_COUNT` (32) by
    // `read_mip_count`, so `with_capacity` is bounded.
    let count = mip_count as usize;
    let mut mips = Vec::with_capacity(count);
    let mut records = Vec::with_capacity(count);

    // `bCooked` is present only for UE4 cooked content
    // (`Ar.Ver >= TEXTURE_SOURCE_ART_REFACTOR && Ar.Game < GAME_UE5_0`).
    // `TEXTURE_SOURCE_ART_REFACTOR` (~14) is far below paksmith's UE4
    // floor (`VER_UE4_NAME_HASHES_SERIALIZED = 504`), so it's implied;
    // the live gate is just "is UE4" (`file_version_ue5.is_none()`).
    let has_bcooked = ctx.version.file_version_ue5.is_none();

    for _ in 0..count {
        if has_bcooked {
            // `i32`-encoded bool, read-and-ignored: paksmith always reads
            // the mip's bulk data regardless (cooked-only range). The
            // value is unused, so it is not validated against {0, 1}.
            let _bcooked = cur
                .read_i32::<LittleEndian>()
                .map_err(|_| eof(asset_path, AssetWireField::TextureMipCooked))?;
        }

        // The mip's payload metadata (tier + offset/size). The bytes
        // themselves live in `.uasset` / `.uexp` / `.ubulk` and resolve
        // lazily via `Package::resolve_bulk_for_export`.
        let record = FByteBulkData::read_from(cur, asset_path)?;

        // Per-mip dimensions. `SizeZ` is present for `Ar.Game >= UE4_20`,
        // always true for paksmith's >= UE4.21 range. Capped at
        // `MAX_TEXTURE_DIMENSION` (a valid mip is <= the top mip, so the
        // cap never rejects valid content).
        let size_x = read_dimension(cur, asset_path, AssetWireField::TextureMipDimension)?;
        let size_y = read_dimension(cur, asset_path, AssetWireField::TextureMipDimension)?;
        let size_z = read_dimension(cur, asset_path, AssetWireField::TextureMipDimension)?;

        mips.push(Texture2DMipMap {
            size_x,
            size_y,
            size_z,
        });
        records.push(record);
    }

    Ok((mips, records))
}

/// The `FTexturePlatformData` header fields 3e-2 decodes (3e-2a: the
/// start; 3e-2b: `num_mips_in_tail` / `first_mip_to_serialize` /
/// `mip_count`).
struct PlatformDataHeader {
    size_x: u32,
    size_y: u32,
    pixel_format: String,
    num_slices: u32,
    is_cubemap: bool,
    num_mips_in_tail: Option<u32>,
    first_mip_to_serialize: i32,
    mip_count: u32,
}

/// Decode the `FTexturePlatformData` header: the version-gated
/// stripped-data prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat`
/// (3e-2a), then the conditional `OptData` / `CPUCopy` sub-records,
/// `FirstMipToSerialize`, and the mip-count prefix (3e-2b). Stops at the
/// mip-count — the per-mip `FTexture2DMipMap` records are read in 3e-3.
fn read_platform_data_header(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<PlatformDataHeader> {
    skip_stripped_data_prefix(cur, ctx, asset_path)?;

    let size_x = read_dimension(cur, asset_path, AssetWireField::TextureSizeX)?;
    let size_y = read_dimension(cur, asset_path, AssetWireField::TextureSizeY)?;

    let packed = cur
        .read_u32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::TexturePackedData))?;
    let num_slices = packed & PACKED_DATA_NUM_SLICES_MASK;
    let is_cubemap = (packed & PACKED_DATA_CUBEMAP_BIT) != 0;

    let pixel_format = read_asset_fstring(cur, asset_path)?;

    // OptData (bit 30): `ExtData` (discarded) + `NumMipsInTail`.
    let num_mips_in_tail = if packed & PACKED_DATA_HAS_OPT_DATA_BIT != 0 {
        let _ext_data = cur
            .read_u32::<LittleEndian>()
            .map_err(|_| eof(asset_path, AssetWireField::TextureOptData))?;
        let num_mips_in_tail = cur
            .read_u32::<LittleEndian>()
            .map_err(|_| eof(asset_path, AssetWireField::TextureOptData))?;
        if num_mips_in_tail > MAX_MIPS_IN_TAIL {
            return Err(fault(
                asset_path,
                AssetParseFault::TextureMipsInTailExceeded {
                    count: num_mips_in_tail,
                    cap: MAX_MIPS_IN_TAIL,
                },
            ));
        }
        Some(num_mips_in_tail)
    } else {
        None
    };

    // CPUCopy (bit 29): an `FSharedImage` we read past but don't keep.
    if packed & PACKED_DATA_HAS_CPU_COPY_BIT != 0 {
        skip_cpu_copy(cur, asset_path)?;
    }

    let first_mip_to_serialize = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::TextureFirstMipToSerialize))?;

    let mip_count = read_mip_count(cur, asset_path)?;

    Ok(PlatformDataHeader {
        size_x,
        size_y,
        pixel_format,
        num_slices,
        is_cubemap,
        num_mips_in_tail,
        first_mip_to_serialize,
        mip_count,
    })
}

/// Read past the `FSharedImage` CPU-copy record: the 14-byte fixed
/// header, then the `i64` `RawDataLen` (range-checked), then a
/// payload-bounded skip of `RawDataLen` bytes. The record is a redundant
/// inline decode not needed for export, so nothing is retained.
fn skip_cpu_copy(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<()> {
    skip_asset_bytes(
        cur,
        CPU_COPY_FIXED_HEADER_BYTES,
        asset_path,
        AssetWireField::TextureCpuCopyHeader,
    )?;

    let raw_data_len = cur
        .read_i64::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::TextureCpuCopyRawDataLen))?;
    // Reject negative and over-cap. `unsigned_abs` is only reached for a
    // non-negative value (the `< 0` short-circuits), so it returns the
    // value losslessly. `skip_asset_bytes` then bounds the skip by the
    // actual payload (a short payload errors as `UnexpectedEof` rather
    // than over-reading).
    if raw_data_len < 0 || raw_data_len.unsigned_abs() > MAX_CPU_COPY_RAW_DATA_LEN {
        return Err(fault(
            asset_path,
            AssetParseFault::TextureCpuCopyDataLenExceeded {
                len: raw_data_len,
                cap: MAX_CPU_COPY_RAW_DATA_LEN,
            },
        ));
    }
    skip_asset_bytes(
        cur,
        raw_data_len.unsigned_abs(),
        asset_path,
        AssetWireField::TextureCpuCopyData,
    )
}

/// Read and range-check the `i32` mip-count prefix to
/// `[0, MAX_MIP_COUNT]`, returning it as `u32`.
fn read_mip_count(cur: &mut Cursor<&[u8]>, asset_path: &str) -> crate::Result<u32> {
    let count = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, AssetWireField::TextureMipCount))?;
    if !(0..=MAX_MIP_COUNT).contains(&count) {
        return Err(fault(
            asset_path,
            AssetParseFault::TextureMipCountExceeded {
                count,
                cap: MAX_MIP_COUNT,
            },
        ));
    }
    // `count` is in `[0, MAX_MIP_COUNT]`, so `unsigned_abs` is lossless.
    Ok(count.unsigned_abs())
}

/// Consume the UE 5.0+ `FTexturePlatformData` stripped-data prefix.
///
/// **Version gate (object-version proxy).** CUE4Parse gates this on
/// `Ar.Game` (the engine version): `>= GAME_UE5_2` reads a
/// `bUsingDerivedData` flag, while `>= GAME_UE5_0 && IsFilterEditorOnly`
/// applies the 16-byte skip. paksmith has no engine-version field in the
/// reader, so it gates on the object version `file_version_ue5`, which is
/// an exact proxy **for stock engine versions**: CUE4Parse's own
/// `EGame`→version table maps `GAME_UE5_2 → 1009`
/// (`VER_UE5_DATA_RESOURCES`) and `GAME_UE5_0 → 1004`, so
/// `file_version_ue5 >= 1009` ⟺ `Ar.Game >= GAME_UE5_2`, and
/// `file_version_ue5.is_some()` ⟺ `Ar.Game >= GAME_UE5_0`. (CUE4Parse's
/// per-game version *overrides* are unreachable here — paksmith branches
/// on `file_version_ue5` alone, with no game-profile field — and even a
/// misclassification between the two UE5 branches consumes the same 16
/// bytes, so `SizeX` alignment is unaffected.) The
/// `IsFilterEditorOnly` condition is implied: paksmith rejects uncooked
/// UE5 packages (`AssetParseFault::UncookedAsset`, summary.rs), so any
/// UE5 export reaching this reader is cooked. **Order matters** — the
/// `>= 1009` branch must precede the `is_some()` branch (5.2+ satisfies
/// both, but takes the flag path, not the bare 16-byte skip).
fn skip_stripped_data_prefix(
    cur: &mut Cursor<&[u8]>,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<()> {
    if ctx.version.ue5_at_least(VER_UE5_DATA_RESOURCES) {
        // UE 5.2+: a `bUsingDerivedData` flag byte. When set, the
        // platform data lives in the editor-only derived-data cache and
        // is not recoverable from the cooked asset.
        let flag = cur
            .read_u8()
            .map_err(|_| eof(asset_path, AssetWireField::TextureUsingDerivedDataFlag))?;
        if flag != 0 {
            return Err(fault(
                asset_path,
                AssetParseFault::TextureDerivedDataNotAvailable,
            ));
        }
        // The flag byte is the first of the 16-byte placeholder; skip
        // the remaining 15.
        skip_asset_bytes(
            cur,
            PLACEHOLDER_DERIVED_DATA_SIZE - 1,
            asset_path,
            AssetWireField::TextureStrippedDataPrefix,
        )?;
    } else if ctx.version.file_version_ue5.is_some() {
        // UE 5.0–5.1 cooked: the full 16-byte placeholder skip.
        skip_asset_bytes(
            cur,
            PLACEHOLDER_DERIVED_DATA_SIZE,
            asset_path,
            AssetWireField::TextureStrippedDataPrefix,
        )?;
    }
    // UE4: no prefix.
    Ok(())
}

/// Read a `SizeX` / `SizeY` `i32` and range-check it to
/// `[0, MAX_TEXTURE_DIMENSION]`, returning it as `u32`.
fn read_dimension(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<u32> {
    let value = cur
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))?;
    if !(0..=MAX_TEXTURE_DIMENSION).contains(&value) {
        return Err(fault(
            asset_path,
            AssetParseFault::TextureDimensionExceeded {
                field,
                value,
                cap: MAX_TEXTURE_DIMENSION,
            },
        ));
    }
    // `value` is in `[0, MAX_TEXTURE_DIMENSION]`, so `unsigned_abs`
    // returns it losslessly as `u32`.
    Ok(value.unsigned_abs())
}

/// Wrap an [`AssetParseFault`] in a [`PaksmithError::AssetParse`] for
/// `asset_path` — the one-line constructor every header check uses.
fn fault(asset_path: &str, fault: AssetParseFault) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault,
    }
}

/// Build an `UnexpectedEof` fault for a short read of `field`.
fn eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    fault(asset_path, AssetParseFault::UnexpectedEof { field })
}

/// Registry-compatible shim ([`crate::asset::exports::dispatch::TypedReaderFn`]).
/// Wraps [`read_from`]'s [`Texture2DData`] in the typed
/// [`Asset::Texture2D`] variant and surfaces the per-mip
/// [`FByteBulkData`] records (3e-3) as the tuple's second element — the
/// dispatch caller stores them in `Package` so the mip bytes resolve
/// lazily. The records align positionally with `data.mips`.
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let (data, bulk_records) = read_from(payload, ctx, asset_path)?;
    Ok((Asset::Texture2D(data), bulk_records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::primitives::PropertyValue;
    use crate::asset::property::test_utils::{
        make_ctx, make_ctx_with_version, write_fstring, write_int_property, write_none_tag as none,
    };

    // --- wire-byte builders. FName / IntProperty / FString go through
    // the shared `property::test_utils`; `write_platform_data` is
    // texture-specific and kept local (auditable against the format doc).

    /// A per-mip spec for the wire builder: dimensions + the
    /// `FByteBulkData` `SizeOnDisk` (a minimal inline, no-fixup record is
    /// synthesized from it). Distinct values per mip make the per-record
    /// VALUE assertions a real alignment checksum (a stride error
    /// misaligns one mip into another's value).
    #[derive(Clone, Copy)]
    #[allow(
        clippy::struct_field_names,
        reason = "`size_x`/`size_y`/`size_z` mirror `FTexture2DMipMap`'s wire \
                  fields and `size_on_disk` mirrors `FByteBulkData`'s — the \
                  shared `size` prefix is the format's, not redundant naming"
    )]
    struct Mip {
        size_x: i32,
        size_y: i32,
        size_z: i32,
        size_on_disk: u32,
    }

    /// Append a minimal inline `FByteBulkData`: `BulkDataFlags` =
    /// `PAYLOAD_AT_END_OF_FILE (0x1) | NO_OFFSET_FIXUP (0x1_0000)`, no
    /// `Size64Bit` → `i32` ElementCount + `u32` SizeOnDisk + `i64`
    /// OffsetInFile (20 bytes). ElementCount = SizeOnDisk (byte bulk).
    fn write_byte_bulk_data(buf: &mut Vec<u8>, size_on_disk: u32, offset: i64) {
        buf.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // flags
        buf.extend_from_slice(&i32::try_from(size_on_disk).unwrap().to_le_bytes()); // ElementCount
        buf.extend_from_slice(&size_on_disk.to_le_bytes()); // SizeOnDisk (u32)
        buf.extend_from_slice(&offset.to_le_bytes()); // OffsetInFile (i64)
    }

    /// Append `mips.len()` `FTexture2DMipMap` records: `bCooked` (only
    /// when `has_bcooked`, i.e. UE4) + `FByteBulkData` + `SizeX`/`SizeY`/
    /// `SizeZ`.
    fn write_mip_records(buf: &mut Vec<u8>, has_bcooked: bool, mips: &[Mip]) {
        for m in mips {
            if has_bcooked {
                buf.extend_from_slice(&1i32.to_le_bytes()); // bCooked (i32 bool)
            }
            write_byte_bulk_data(buf, m.size_on_disk, 0);
            buf.extend_from_slice(&m.size_x.to_le_bytes());
            buf.extend_from_slice(&m.size_y.to_le_bytes());
            buf.extend_from_slice(&m.size_z.to_le_bytes());
        }
    }

    /// Write a full `FTexturePlatformData` (header through the mip
    /// records), with NO stripped-data prefix — the caller prepends any
    /// version-specific prefix bytes. `PackedData` is derived: the
    /// `num_slices` low bits, bit 31 if `is_cubemap`, bit 30 if `opt` is
    /// `Some`, bit 29 if `cpu_copy` is `Some`. `mip_count` is written
    /// explicitly (so cap / truncation tests can write a count that
    /// differs from `mips.len()`). The per-mip `bCooked` field (UE4 only)
    /// is gated on `ctx` exactly as the reader gates it
    /// (`file_version_ue5.is_none()`), so the builder can never desync
    /// from the reader's version branch.
    #[allow(
        clippy::too_many_arguments,
        reason = "a faithful one-call FTexturePlatformData wire builder; \
                  splitting it would obscure the byte layout under test"
    )]
    fn write_platform_data(
        buf: &mut Vec<u8>,
        ctx: &AssetContext,
        size_x: i32,
        size_y: i32,
        num_slices: u32,
        is_cubemap: bool,
        pixel_format: &str,
        opt: Option<(u32, u32)>,
        cpu_copy: Option<&[u8]>,
        first_mip: i32,
        mip_count: i32,
        mips: &[Mip],
    ) {
        let has_bcooked = ctx.version.file_version_ue5.is_none();
        let mut packed = num_slices;
        if is_cubemap {
            packed |= PACKED_DATA_CUBEMAP_BIT;
        }
        if opt.is_some() {
            packed |= PACKED_DATA_HAS_OPT_DATA_BIT;
        }
        if cpu_copy.is_some() {
            packed |= PACKED_DATA_HAS_CPU_COPY_BIT;
        }
        buf.extend_from_slice(&size_x.to_le_bytes());
        buf.extend_from_slice(&size_y.to_le_bytes());
        buf.extend_from_slice(&packed.to_le_bytes());
        write_fstring(buf, pixel_format);
        if let Some((ext_data, num_mips_in_tail)) = opt {
            buf.extend_from_slice(&ext_data.to_le_bytes());
            buf.extend_from_slice(&num_mips_in_tail.to_le_bytes());
        }
        if let Some(raw) = cpu_copy {
            buf.extend_from_slice(&[0u8; 14]); // FSharedImage fixed header
            buf.extend_from_slice(&i64::try_from(raw.len()).unwrap().to_le_bytes());
            buf.extend_from_slice(raw);
        }
        buf.extend_from_slice(&first_mip.to_le_bytes());
        buf.extend_from_slice(&mip_count.to_le_bytes());
        write_mip_records(buf, has_bcooked, mips);
    }

    /// A plain 2D texture (1 slice, no cubemap/opt/cpu, first-mip 0)
    /// with `mip_count = mips.len()` and the given mip records.
    fn plain(
        buf: &mut Vec<u8>,
        ctx: &AssetContext,
        size_x: i32,
        size_y: i32,
        pixel_format: &str,
        mips: &[Mip],
    ) {
        write_platform_data(
            buf,
            ctx,
            size_x,
            size_y,
            1,
            false,
            pixel_format,
            None,
            None,
            0,
            i32::try_from(mips.len()).unwrap(),
            mips,
        );
    }

    /// One default mip (64×64×1, 4096 bytes on disk) — for tests that
    /// reach the mip loop but don't assert on the mip itself.
    fn one_mip() -> [Mip; 1] {
        [Mip {
            size_x: 64,
            size_y: 64,
            size_z: 1,
            size_on_disk: 4096,
        }]
    }

    fn props_of(data: &Texture2DData) -> &[crate::asset::property::primitives::Property] {
        match &data.properties {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected Tree, got {other:?}"),
        }
    }

    #[test]
    fn ue4_decodes_segment1_header_and_one_mip() {
        // UE4 (file_version_ue5 = None) → no stripped-data prefix, and
        // each mip carries a `bCooked` field (the builder derives this
        // from `ctx`, matching the reader).
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        write_int_property(&mut bytes, 1, 2, 3); // LODBias = 3
        none(&mut bytes);
        let mip = Mip {
            size_x: 64,
            size_y: 128,
            size_z: 1,
            size_on_disk: 4096,
        };
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            128,
            1,
            false,
            "PF_DXT5",
            None,
            None,
            0,
            1,
            &[mip],
        );

        let (data, records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        // Segment 1 still decodes.
        assert_eq!(props_of(&data).len(), 1);
        assert_eq!(props_of(&data)[0].value, PropertyValue::Int(3));
        // Header.
        assert_eq!(data.size_x, 64);
        assert_eq!(data.size_y, 128);
        assert_eq!(data.pixel_format, "PF_DXT5");
        assert_eq!(data.first_mip_to_serialize, 0);
        assert_eq!(data.mip_count, 1);
        // Mip dims + the positionally-aligned bulk record.
        assert_eq!(data.mips.len(), 1);
        assert_eq!(data.mips[0].size_x, 64);
        assert_eq!(data.mips[0].size_y, 128);
        assert_eq!(data.mips[0].size_z, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].size_on_disk, 4096);
        assert_eq!(records[0].element_count, 4096);
    }

    #[test]
    fn multi_mip_records_decode_with_aligned_values() {
        // The real alignment checksum (mip_count alone no longer proves
        // it — a per-record stride error reads the right COUNT of records,
        // just misaligned). Three mips with DISTINCT dims + sizes: a
        // wrong per-record byte count would misalign mip[1]/mip[2] into a
        // neighbour's value, which these per-record assertions catch.
        let ctx = make_ctx_with_version(522, None); // UE4 → bCooked present
        let mips = [
            Mip {
                size_x: 64,
                size_y: 64,
                size_z: 1,
                size_on_disk: 4096,
            },
            Mip {
                size_x: 32,
                size_y: 32,
                size_z: 1,
                size_on_disk: 1024,
            },
            Mip {
                size_x: 16,
                size_y: 16,
                size_z: 1,
                size_on_disk: 256,
            },
        ];
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 64, 64, "PF_DXT5", &mips);

        let (data, records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.mips.len(), 3);
        assert_eq!(records.len(), 3);
        for (i, m) in mips.iter().enumerate() {
            assert_eq!(
                data.mips[i].size_x,
                u32::try_from(m.size_x).unwrap(),
                "mip {i} size_x"
            );
            assert_eq!(
                data.mips[i].size_y,
                u32::try_from(m.size_y).unwrap(),
                "mip {i} size_y"
            );
            assert_eq!(
                data.mips[i].size_z,
                u32::try_from(m.size_z).unwrap(),
                "mip {i} size_z"
            );
            assert_eq!(
                records[i].size_on_disk,
                u64::from(m.size_on_disk),
                "mip {i} size_on_disk"
            );
        }
    }

    #[test]
    fn ue5_omits_the_bcooked_field() {
        // UE5 mips have NO `bCooked` field (the builder, gated on the same
        // UE5 ctx, omits it). If the reader wrongly read a 4-byte bCooked
        // here, the FByteBulkData + dims would misalign and the asserted
        // mip values would be wrong.
        let ctx = make_ctx_with_version(522, Some(1009)); // UE5.2
        let mips = [
            Mip {
                size_x: 128,
                size_y: 64,
                size_z: 1,
                size_on_disk: 8192,
            },
            Mip {
                size_x: 64,
                size_y: 32,
                size_z: 1,
                size_on_disk: 2048,
            },
        ];
        let mut bytes = Vec::new();
        none(&mut bytes);
        // UE5.2 stripped-data prefix: flag byte (0) + 15 skipped.
        bytes.push(0x00u8);
        bytes.extend_from_slice(&[0xFFu8; 15]);
        write_platform_data(
            &mut bytes, &ctx, 128, 64, 1, false, "PF_BC7", None, None, 0, 2, &mips,
        );

        let (data, records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.mips.len(), 2);
        assert_eq!(data.mips[0].size_x, 128);
        assert_eq!(data.mips[1].size_x, 64);
        assert_eq!(records[0].size_on_disk, 8192);
        assert_eq!(records[1].size_on_disk, 2048);
    }

    /// Build `none() + <prefix bytes> + a plain header with one known
    /// mip` under `make_ctx_with_version(522, ue5)`. The mip (48×24×1,
    /// 1536 bytes) is the per-record alignment checksum.
    fn parse_with_prefix(
        ue5: Option<i32>,
        prefix: &[u8],
    ) -> crate::Result<(Texture2DData, Vec<FByteBulkData>)> {
        let ctx = make_ctx_with_version(522, ue5);
        let mip = Mip {
            size_x: 48,
            size_y: 24,
            size_z: 1,
            size_on_disk: 1536,
        };
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(prefix);
        plain(&mut bytes, &ctx, 256, 256, "PF_B8G8R8A8", &[mip]);
        read_from(&bytes, &ctx, "tex.uasset")
    }

    fn assert_prefix_checksum(result: crate::Result<(Texture2DData, Vec<FByteBulkData>)>) {
        let (data, records) = result.expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8");
        // A wrong prefix/field size misaligns and corrupts these.
        assert_eq!(data.mips.len(), 1);
        assert_eq!(data.mips[0].size_x, 48);
        assert_eq!(records[0].size_on_disk, 1536);
    }

    #[test]
    fn ue4_has_no_stripped_data_prefix() {
        assert_prefix_checksum(parse_with_prefix(None, &[]));
    }

    #[test]
    fn ue5_0_skips_16_byte_prefix() {
        // UE5.0 (1004 < 1009) → the full 16-byte placeholder skip.
        assert_prefix_checksum(parse_with_prefix(Some(1004), &[0xFFu8; 16]));
    }

    #[test]
    fn ue5_1_takes_16_skip_not_the_flag_path() {
        // UE5.1 = 1008, one below VER_UE5_DATA_RESOURCES (1009). Pins the
        // exact 5.1/5.2 boundary: 5.1 takes the 16-byte skip, NOT the
        // flag path. A `>= 1008` gate would read a flag byte and misalign.
        assert_prefix_checksum(parse_with_prefix(Some(1008), &[0xFFu8; 16]));
    }

    #[test]
    fn ue5_2_flag_false_reads_flag_then_skips_15() {
        // UE5.2 = 1009: 1 `bUsingDerivedData` flag byte (0) + 15 skipped.
        let mut prefix = vec![0x00u8]; // flag = false
        prefix.extend_from_slice(&[0xFFu8; 15]);
        assert_prefix_checksum(parse_with_prefix(Some(1009), &prefix));
    }

    #[test]
    fn ue5_2_flag_true_errors_derived_data_not_available() {
        // UE5.2, `bUsingDerivedData` = 1 → typed error. Also pins the
        // branch ORDER: if the `is_some()` (16-skip) branch ran first,
        // the flag byte would be skipped and this would NOT error.
        let ctx = make_ctx_with_version(522, Some(1009));
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.push(0x01u8); // bUsingDerivedData = true
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureDerivedDataNotAvailable,
                ..
            }) => {}
            other => panic!("expected TextureDerivedDataNotAvailable, got {other:?}"),
        }
    }

    #[test]
    fn opt_data_decoded_when_bit_30_set() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // opt = (ExtData = 0xABCD, NumMipsInTail = 2).
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0xABCD, 2)),
            None,
            0,
            1,
            &one_mip(),
        );
        let (data, _records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, Some(2));
        assert_eq!(data.mips[0].size_x, 64); // checksum: opt's 8 bytes consumed
    }

    #[test]
    fn cpu_copy_record_is_skipped_when_bit_29_set() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // 4-byte CPU-copy payload → 14-byte header + i64 len(4) + 4 bytes.
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            None,
            Some(&[1, 2, 3, 4]),
            0,
            1,
            &one_mip(),
        );
        let (data, _records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, None);
        // checksum: the whole 14+8+4 CPU-copy record was skipped exactly,
        // so the trailing mip's dims land where expected.
        assert_eq!(data.mips[0].size_x, 64);
    }

    #[test]
    fn opt_and_cpu_copy_both_present() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 1)),
            Some(&[9, 9]),
            4,
            1,
            &one_mip(),
        );
        let (data, _records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, Some(1));
        assert_eq!(data.first_mip_to_serialize, 4);
        assert_eq!(data.mips[0].size_x, 64); // checksum: opt + cpu both consumed
    }

    #[test]
    fn size_x_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 16385, 64, "PF_DXT5", &[]); // 16384 + 1
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TextureDimensionExceeded {
                        field: AssetWireField::TextureSizeX,
                        value,
                        cap,
                    },
                ..
            }) => {
                assert_eq!(value, 16385);
                assert_eq!(cap, 16384);
            }
            other => panic!("expected TextureDimensionExceeded(SizeX), got {other:?}"),
        }
    }

    #[test]
    fn negative_size_y_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 64, -1, "PF_DXT5", &[]);
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TextureDimensionExceeded {
                        field: AssetWireField::TextureSizeY,
                        value,
                        ..
                    },
                ..
            }) => assert_eq!(value, -1),
            other => panic!("expected TextureDimensionExceeded(SizeY), got {other:?}"),
        }
    }

    #[test]
    fn dimension_at_cap_is_accepted() {
        // 16384 == MAX_TEXTURE_DIMENSION must pass (`>`, not `>=`).
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 16384, 16384, "PF_DXT5", &one_mip());
        let (data, _records) =
            read_from(&bytes, &ctx, "tex.uasset").expect("at-cap dimensions accepted");
        assert_eq!(data.size_x, 16384);
        assert_eq!(data.size_y, 16384);
    }

    #[test]
    fn cubemap_flag_and_slices_decoded_from_packed_data() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            6,
            true,
            "PF_DXT5",
            None,
            None,
            0,
            1,
            &one_mip(),
        );
        let (data, _records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(data.is_cubemap);
        assert_eq!(data.num_slices, 6);
    }

    #[test]
    fn num_slices_keeps_overlapping_cpu_copy_bit() {
        // HasCpuCopy (bit 29) overlaps the NumSlices mask. Pins the
        // CUE4Parse-parity convention: the 0x3FFF_FFFF mask does NOT
        // strip bit 29 — so a CPU-copy texture with 5 slices reads
        // NumSlices = 0x2000_0005. (A CPU-copy record is written + skipped.)
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            5,
            false,
            "PF_DXT5",
            None,
            Some(&[]),
            0,
            1,
            &one_mip(),
        );
        let (data, _records) = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_slices, 0x2000_0005, "bit 29 must NOT be stripped");
        assert!(!data.is_cubemap);
    }

    #[test]
    fn mip_count_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // mip_count = 33 (> MAX_MIP_COUNT); no records (cap fires first).
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            None,
            None,
            0,
            33,
            &[],
        );
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipCountExceeded { count, cap },
                ..
            }) => {
                assert_eq!(count, 33);
                assert_eq!(cap, 32);
            }
            other => panic!("expected TextureMipCountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn negative_mip_count_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            None,
            None,
            0,
            -1,
            &[],
        );
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipCountExceeded { count, .. },
                ..
            }) => assert_eq!(count, -1),
            other => panic!("expected TextureMipCountExceeded, got {other:?}"),
        }
    }

    #[test]
    fn mip_count_at_cap_is_accepted() {
        // 32 == MAX_MIP_COUNT, with 32 real records.
        let ctx = make_ctx_with_version(522, None);
        let mips: Vec<Mip> = (0..32)
            .map(|i| Mip {
                size_x: 32,
                size_y: 32,
                size_z: 1,
                size_on_disk: 64 + i,
            })
            .collect();
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 64, 64, "PF_DXT5", &mips);
        let (data, records) =
            read_from(&bytes, &ctx, "tex.uasset").expect("at-cap mip count accepted");
        assert_eq!(data.mip_count, 32);
        assert_eq!(data.mips.len(), 32);
        assert_eq!(records.len(), 32);
    }

    #[test]
    fn num_mips_in_tail_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // opt with NumMipsInTail = 33 (> MAX_MIPS_IN_TAIL); errors before mips.
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 33)),
            None,
            0,
            0,
            &[],
        );
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureMipsInTailExceeded { count, cap },
                ..
            }) => {
                assert_eq!(count, 33);
                assert_eq!(cap, 32);
            }
            other => panic!("expected TextureMipsInTailExceeded, got {other:?}"),
        }
    }

    #[test]
    fn num_mips_in_tail_at_cap_is_accepted() {
        // NumMipsInTail == MAX_MIPS_IN_TAIL must pass (`>`, not `>=`).
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 32)),
            None,
            0,
            1,
            &one_mip(),
        );
        let (data, _records) =
            read_from(&bytes, &ctx, "tex.uasset").expect("at-cap NumMipsInTail accepted");
        assert_eq!(data.num_mips_in_tail, Some(32));
    }

    #[test]
    fn per_mip_dimension_over_cap_rejected() {
        // A per-mip SizeX over MAX_TEXTURE_DIMENSION → TextureDimensionExceeded
        // tagged with the generic TextureMipDimension field.
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        let bad = Mip {
            size_x: 16385,
            size_y: 64,
            size_z: 1,
            size_on_disk: 4096,
        };
        plain(&mut bytes, &ctx, 64, 64, "PF_DXT5", &[bad]);
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::TextureDimensionExceeded {
                        field: AssetWireField::TextureMipDimension,
                        value,
                        ..
                    },
                ..
            }) => assert_eq!(value, 16385),
            other => {
                panic!("expected TextureDimensionExceeded(TextureMipDimension), got {other:?}")
            }
        }
    }

    /// Build a header whose CPU-copy `RawDataLen` field is `raw_len`,
    /// with NO trailing `RawData` (the cap check fires before the skip).
    fn header_with_cpu_copy_raw_len(raw_len: i64) -> Vec<u8> {
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(&64i32.to_le_bytes()); // SizeX
        bytes.extend_from_slice(&64i32.to_le_bytes()); // SizeY
        bytes.extend_from_slice(&(PACKED_DATA_HAS_CPU_COPY_BIT | 1).to_le_bytes());
        write_fstring(&mut bytes, "PF_DXT5");
        bytes.extend_from_slice(&[0u8; 14]); // FSharedImage fixed header
        bytes.extend_from_slice(&raw_len.to_le_bytes()); // RawDataLen
        bytes
    }

    #[test]
    fn cpu_copy_raw_data_len_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let over = i64::try_from(MAX_CPU_COPY_RAW_DATA_LEN).unwrap() + 1;
        let bytes = header_with_cpu_copy_raw_len(over);
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureCpuCopyDataLenExceeded { len, cap },
                ..
            }) => {
                assert_eq!(len, over);
                assert_eq!(cap, 8_589_934_592);
            }
            other => panic!("expected TextureCpuCopyDataLenExceeded, got {other:?}"),
        }
    }

    #[test]
    fn cpu_copy_raw_data_len_at_cap_passes_cap_check() {
        // RawDataLen == MAX must PASS the cap (`>`, not `>=`) and proceed
        // to the payload-bounded skip, which then EOFs (no RawData).
        let ctx = make_ctx_with_version(522, None);
        let at_cap = i64::try_from(MAX_CPU_COPY_RAW_DATA_LEN).unwrap();
        let bytes = header_with_cpu_copy_raw_len(at_cap);
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TextureCpuCopyData,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(TextureCpuCopyData), got {other:?}"),
        }
    }

    #[test]
    fn cpu_copy_raw_data_len_negative_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let bytes = header_with_cpu_copy_raw_len(-1);
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault: AssetParseFault::TextureCpuCopyDataLenExceeded { len, .. },
                ..
            }) => assert_eq!(len, -1),
            other => panic!("expected TextureCpuCopyDataLenExceeded, got {other:?}"),
        }
    }

    #[test]
    fn truncated_size_y_surfaces_unexpected_eof() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(&64i32.to_le_bytes()); // SizeX only
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TextureSizeY,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(TextureSizeY), got {other:?}"),
        }
    }

    #[test]
    fn truncated_mip_count_surfaces_unexpected_eof() {
        // Full header up to (but not including) the mip-count prefix.
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(&64i32.to_le_bytes()); // SizeX
        bytes.extend_from_slice(&64i32.to_le_bytes()); // SizeY
        bytes.extend_from_slice(&1u32.to_le_bytes()); // PackedData
        write_fstring(&mut bytes, "PF_DXT5");
        bytes.extend_from_slice(&0i32.to_le_bytes()); // FirstMipToSerialize; no mip count
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TextureMipCount,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(TextureMipCount), got {other:?}"),
        }
    }

    #[test]
    fn truncated_mip_record_surfaces_unexpected_eof() {
        // mip_count = 1 but no mip-record bytes follow → EOF reading the
        // UE4 bCooked field of the (missing) record.
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            &ctx,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            None,
            None,
            0,
            1,
            &[],
        );
        match read_from(&bytes, &ctx, "tex.uasset") {
            Err(PaksmithError::AssetParse {
                fault:
                    AssetParseFault::UnexpectedEof {
                        field: AssetWireField::TextureMipCooked,
                    },
                ..
            }) => {}
            other => panic!("expected UnexpectedEof(TextureMipCooked), got {other:?}"),
        }
    }

    #[test]
    fn read_typed_wraps_texture_and_surfaces_mip_records() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, &ctx, 64, 64, "PF_DXT5", &one_mip());

        let (asset, records) = read_typed(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(
            records.len(),
            1,
            "the per-mip record is surfaced for Package storage"
        );
        match asset {
            Asset::Texture2D(data) => {
                assert_eq!(data.size_x, 64);
                assert_eq!(data.pixel_format, "PF_DXT5");
                assert_eq!(data.mips.len(), 1);
            }
            other => panic!("expected Asset::Texture2D, got {other:?}"),
        }
    }
}
