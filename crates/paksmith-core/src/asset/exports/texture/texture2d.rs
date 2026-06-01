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
//! **3e-2 scope: segment 1 + the full `FTexturePlatformData` header.**
//! [`read_from`] decodes the tagged-property stream, then the whole
//! segment-2 header: the UE 5.0/5.2 stripped-data prefix, `SizeX`,
//! `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then the conditional
//! `OptData` (bit 30) / `CPUCopy` (bit 29) sub-records,
//! `FirstMipToSerialize`, and the mip-count prefix (3e-2b). It stops at
//! the mip count — the per-mip `FTexture2DMipMap` records (with their
//! `FByteBulkData`) are read in 3e-3. The dispatch caller
//! (`Package::read_payloads`) carves each export by
//! `serial_offset`/`serial_size` and never inspects how many bytes a
//! typed reader consumed, so leaving the per-mip records unread is
//! structurally harmless — the next export is still located correctly.

use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::PaksmithError;
use crate::asset::bulk_data::FByteBulkData;
use crate::asset::property::bag::PropertyBag;
use crate::asset::property::read_properties;
use crate::asset::version::VER_UE5_DATA_RESOURCES;
use crate::asset::{Asset, AssetContext, Texture2DData, read_asset_fstring, skip_asset_bytes};
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
/// generous. Bounds the per-mip allocation 3e-3 will drive
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
/// `payload` is the export's `serial_size`-bounded byte slice. As of
/// 3e-2b, segment 1 (tagged properties) plus the **full**
/// `FTexturePlatformData` header are decoded: the version-gated
/// stripped-data prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat`,
/// the conditional `OptData` / `CPUCopy` sub-records, `FirstMipToSerialize`,
/// and the mip-count prefix. The per-mip `FTexture2DMipMap` records are
/// read in 3e-3 (see the module docs).
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
) -> crate::Result<Texture2DData> {
    let mut cur = Cursor::new(payload);
    let total_len = payload.len() as u64;

    // Segment 1: tagged properties (None-terminated). Stops at "None".
    let properties = read_properties(&mut cur, ctx, 0, total_len, asset_path)?;

    // Segment 2: FTexturePlatformData header start.
    let header = read_platform_data_header(&mut cur, ctx, asset_path)?;

    Ok(Texture2DData {
        properties: PropertyBag::Tree { properties },
        size_x: header.size_x,
        size_y: header.size_y,
        pixel_format: header.pixel_format,
        num_slices: header.num_slices,
        is_cubemap: header.is_cubemap,
        num_mips_in_tail: header.num_mips_in_tail,
        first_mip_to_serialize: header.first_mip_to_serialize,
        mip_count: header.mip_count,
    })
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
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::TextureMipsInTailExceeded {
                    count: num_mips_in_tail,
                    cap: MAX_MIPS_IN_TAIL,
                },
            });
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
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TextureCpuCopyDataLenExceeded {
                len: raw_data_len,
                cap: MAX_CPU_COPY_RAW_DATA_LEN,
            },
        });
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
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TextureMipCountExceeded {
                count,
                cap: MAX_MIP_COUNT,
            },
        });
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
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::TextureDerivedDataNotAvailable,
            });
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
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TextureDimensionExceeded {
                field,
                value,
                cap: MAX_TEXTURE_DIMENSION,
            },
        });
    }
    // `value` is in `[0, MAX_TEXTURE_DIMENSION]`, so `unsigned_abs`
    // returns it losslessly as `u32`.
    Ok(value.unsigned_abs())
}

/// Build an `UnexpectedEof` fault for a short read of `field`.
fn eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    }
}

/// Registry-compatible shim ([`crate::asset::exports::dispatch::TypedReaderFn`]).
/// Wraps [`read_from`]'s [`Texture2DData`] in the typed
/// [`Asset::Texture2D`] variant. 3e-1 collects no bulk-data records
/// (the per-mip `FByteBulkData` records are parsed from segment 2 in
/// 3e-3), so the companion-records vec is empty for now.
pub(crate) fn read_typed(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
    let data = read_from(payload, ctx, asset_path)?;
    Ok((Asset::Texture2D(data), Vec::new()))
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

    /// Write a full `FTexturePlatformData` (header through the mip-count
    /// prefix), with NO stripped-data prefix — the caller prepends any
    /// version-specific prefix bytes. `PackedData` is derived: the
    /// `num_slices` low bits, bit 31 if `is_cubemap`, bit 30 if `opt` is
    /// `Some`, bit 29 if `cpu_copy` is `Some`. `opt` = `(ext_data,
    /// num_mips_in_tail)`; `cpu_copy` = the `FSharedImage` `RawData`
    /// bytes (a 14-byte zero fixed-header + the `i64` length + the bytes
    /// are written).
    #[allow(
        clippy::too_many_arguments,
        reason = "a faithful one-call FTexturePlatformData wire builder; \
                  splitting it would obscure the byte layout under test"
    )]
    fn write_platform_data(
        buf: &mut Vec<u8>,
        size_x: i32,
        size_y: i32,
        num_slices: u32,
        is_cubemap: bool,
        pixel_format: &str,
        opt: Option<(u32, u32)>,
        cpu_copy: Option<&[u8]>,
        first_mip: i32,
        mip_count: i32,
    ) {
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
    }

    /// A plain 2D texture header (1 slice, no cubemap/opt/cpu, first-mip
    /// 0) with the given dimensions / format / mip count.
    fn plain(buf: &mut Vec<u8>, size_x: i32, size_y: i32, pixel_format: &str, mip_count: i32) {
        write_platform_data(
            buf,
            size_x,
            size_y,
            1,
            false,
            pixel_format,
            None,
            None,
            0,
            mip_count,
        );
    }

    fn props_of(data: &Texture2DData) -> &[crate::asset::property::primitives::Property] {
        match &data.properties {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected Tree, got {other:?}"),
        }
    }

    #[test]
    fn ue4_decodes_segment1_then_full_platform_header() {
        // UE4 (file_version_ue5 = None) → no stripped-data prefix.
        // Combined: a segment-1 property AND the full header.
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        write_int_property(&mut bytes, 1, 2, 3); // LODBias = 3
        none(&mut bytes);
        write_platform_data(&mut bytes, 64, 128, 1, false, "PF_DXT5", None, None, 0, 5);

        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        // Segment 1 still decodes.
        assert_eq!(props_of(&data).len(), 1);
        assert_eq!(props_of(&data)[0].value, PropertyValue::Int(3));
        // Header.
        assert_eq!(data.size_x, 64);
        assert_eq!(data.size_y, 128);
        assert_eq!(data.num_slices, 1);
        assert!(!data.is_cubemap);
        assert_eq!(data.pixel_format, "PF_DXT5");
        // 3e-2b tail.
        assert_eq!(data.num_mips_in_tail, None);
        assert_eq!(data.first_mip_to_serialize, 0);
        // mip_count is the alignment checksum for the whole header walk.
        assert_eq!(data.mip_count, 5);
    }

    /// Build `none() + <prefix bytes> + plain header` and parse it under
    /// `make_ctx_with_version(522, ue5)`. The empty name table is fine:
    /// segment 1 is a bare `None`. `mip_count = 7` is the checksum.
    fn parse_with_prefix(ue5: Option<i32>, prefix: &[u8]) -> crate::Result<Texture2DData> {
        let ctx = make_ctx_with_version(522, ue5);
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(prefix);
        plain(&mut bytes, 256, 256, "PF_B8G8R8A8", 7);
        read_from(&bytes, &ctx, "tex.uasset")
    }

    #[test]
    fn ue4_has_no_stripped_data_prefix() {
        let data = parse_with_prefix(None, &[]).expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8");
        assert_eq!(data.mip_count, 7); // checksum
    }

    #[test]
    fn ue5_0_skips_16_byte_prefix() {
        // UE5.0 (1004 < 1009) → the full 16-byte placeholder skip.
        let data = parse_with_prefix(Some(1004), &[0xFFu8; 16]).expect("parse");
        assert_eq!(data.mip_count, 7); // checksum: 16-skip exact
    }

    #[test]
    fn ue5_1_takes_16_skip_not_the_flag_path() {
        // UE5.1 = 1008, one below VER_UE5_DATA_RESOURCES (1009). Pins the
        // exact 5.1/5.2 boundary: 5.1 takes the 16-byte skip, NOT the
        // flag path. A `>= 1008` gate would read a flag byte and misalign.
        let data = parse_with_prefix(Some(1008), &[0xFFu8; 16]).expect("parse");
        assert_eq!(data.mip_count, 7);
    }

    #[test]
    fn ue5_2_flag_false_reads_flag_then_skips_15() {
        // UE5.2 = 1009: 1 `bUsingDerivedData` flag byte (0) + 15 skipped.
        let mut prefix = vec![0x00u8]; // flag = false
        prefix.extend_from_slice(&[0xFFu8; 15]);
        let data = parse_with_prefix(Some(1009), &prefix).expect("parse");
        assert_eq!(data.mip_count, 7); // checksum: flag+15 exact
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
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0xABCD, 2)),
            None,
            0,
            3,
        );
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, Some(2));
        assert_eq!(data.mip_count, 3); // checksum: opt's 8 bytes consumed
    }

    #[test]
    fn cpu_copy_record_is_skipped_when_bit_29_set() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // 4-byte CPU-copy payload → 14-byte header + i64 len(4) + 4 bytes.
        write_platform_data(
            &mut bytes,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            None,
            Some(&[1, 2, 3, 4]),
            0,
            3,
        );
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, None);
        // checksum: the whole 14+8+4 CPU-copy record was skipped exactly.
        assert_eq!(data.mip_count, 3);
    }

    #[test]
    fn opt_and_cpu_copy_both_present() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(
            &mut bytes,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 1)),
            Some(&[9, 9]),
            4,
            3,
        );
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_mips_in_tail, Some(1));
        assert_eq!(data.first_mip_to_serialize, 4);
        assert_eq!(data.mip_count, 3); // checksum: opt + cpu both consumed
    }

    #[test]
    fn size_x_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, 16385, 64, "PF_DXT5", 1); // 16384 + 1
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
        plain(&mut bytes, 64, -1, "PF_DXT5", 1);
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
        plain(&mut bytes, 16384, 16384, "PF_DXT5", 1);
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("at-cap dimensions accepted");
        assert_eq!(data.size_x, 16384);
        assert_eq!(data.size_y, 16384);
    }

    #[test]
    fn cubemap_flag_and_slices_decoded_from_packed_data() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        write_platform_data(&mut bytes, 64, 64, 6, true, "PF_DXT5", None, None, 0, 1);
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
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
            64,
            64,
            5,
            false,
            "PF_DXT5",
            None,
            Some(&[]),
            0,
            1,
        );
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_slices, 0x2000_0005, "bit 29 must NOT be stripped");
        assert!(!data.is_cubemap);
    }

    #[test]
    fn mip_count_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, 64, 64, "PF_DXT5", 33); // MAX_MIP_COUNT + 1
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
        plain(&mut bytes, 64, 64, "PF_DXT5", -1);
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
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, 64, 64, "PF_DXT5", 32); // == MAX_MIP_COUNT
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("at-cap mip count accepted");
        assert_eq!(data.mip_count, 32);
    }

    #[test]
    fn num_mips_in_tail_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        // opt with NumMipsInTail = 33 (> MAX_MIPS_IN_TAIL).
        write_platform_data(
            &mut bytes,
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 33)),
            None,
            0,
            1,
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
            64,
            64,
            1,
            false,
            "PF_DXT5",
            Some((0, 32)),
            None,
            0,
            1,
        );
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("at-cap NumMipsInTail accepted");
        assert_eq!(data.num_mips_in_tail, Some(32));
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
                // Pin the exact 8 GiB cap value (8 * 1024^3) so a mutated
                // constant arithmetic surfaces here.
                assert_eq!(cap, 8_589_934_592);
            }
            other => panic!("expected TextureCpuCopyDataLenExceeded, got {other:?}"),
        }
    }

    #[test]
    fn cpu_copy_raw_data_len_at_cap_passes_cap_check() {
        // RawDataLen == MAX must PASS the cap (`>`, not `>=`) and proceed
        // to the payload-bounded skip, which then EOFs (no RawData
        // written) — so the error is `UnexpectedEof(TextureCpuCopyData)`,
        // NOT `TextureCpuCopyDataLenExceeded`.
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
    fn read_typed_wraps_header_in_texture2d_with_no_bulk_records() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        plain(&mut bytes, 64, 64, "PF_DXT5", 3);

        let (asset, records) = read_typed(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(records.is_empty(), "no per-mip records until 3e-3");
        match asset {
            Asset::Texture2D(data) => {
                assert_eq!(data.size_x, 64);
                assert_eq!(data.pixel_format, "PF_DXT5");
                assert_eq!(data.mip_count, 3);
            }
            other => panic!("expected Asset::Texture2D, got {other:?}"),
        }
    }
}
