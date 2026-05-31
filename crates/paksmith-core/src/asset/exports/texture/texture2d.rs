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
//! **3e-2a scope: segment 1 + the `FTexturePlatformData` *header start*.**
//! [`read_from`] decodes the tagged-property stream, then the segment-2
//! header up through the `PixelFormat` name: the UE 5.0/5.2 stripped-
//! data prefix, `SizeX`, `SizeY`, `PackedData`, and `PixelFormat`. The
//! remaining header fields (`OptData` / `CPUCopy` / `FirstMipToSerialize`
//! / mip-count) land in 3e-2b, and the per-mip `FTexture2DMipMap`
//! records (with their `FByteBulkData`) in 3e-3. The dispatch caller
//! (`Package::read_payloads`) carves each export by
//! `serial_offset`/`serial_size` and never inspects how many bytes a
//! typed reader consumed, so leaving the rest of segment 2 unread is
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
/// 3e-2a, segment 1 (tagged properties) plus the `FTexturePlatformData`
/// header *start* (`SizeX`, `SizeY`, `PackedData`, `PixelFormat`, after
/// the version-gated stripped-data prefix) are decoded. The rest of the
/// platform-data header is deferred to 3e-2b (see the module docs).
///
/// # Errors
/// - Any tagged-property fault from the nested [`read_properties`] read.
/// - [`AssetParseFault::TextureDerivedDataNotAvailable`] if a UE 5.2+
///   texture sets `bUsingDerivedData`.
/// - [`AssetParseFault::TextureDimensionExceeded`] if `SizeX` / `SizeY`
///   is negative or exceeds [`MAX_TEXTURE_DIMENSION`].
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
    })
}

/// The `FTexturePlatformData` header fields 3e-2a decodes.
struct PlatformDataHeader {
    size_x: u32,
    size_y: u32,
    pixel_format: String,
    num_slices: u32,
    is_cubemap: bool,
}

/// Decode the `FTexturePlatformData` header start: the version-gated
/// stripped-data prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat`.
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

    Ok(PlatformDataHeader {
        size_x,
        size_y,
        pixel_format,
        num_slices,
        is_cubemap,
    })
}

/// Consume the UE 5.0+ `FTexturePlatformData` stripped-data prefix.
///
/// **Version gate (object-version proxy).** CUE4Parse gates this on
/// `Ar.Game` (the engine version): `>= GAME_UE5_2` reads a
/// `bUsingDerivedData` flag, while `>= GAME_UE5_0 && IsFilterEditorOnly`
/// applies the 16-byte skip. paksmith has no engine-version field in the
/// reader, so it gates on the object version `file_version_ue5`, which is
/// an exact proxy: CUE4Parse's own `EGame`→version table maps
/// `GAME_UE5_2 → 1009` (`VER_UE5_DATA_RESOURCES`) and `GAME_UE5_0 → 1004`,
/// so `file_version_ue5 >= 1009` ⟺ `Ar.Game >= GAME_UE5_2`, and
/// `file_version_ue5.is_some()` ⟺ `Ar.Game >= GAME_UE5_0`. The
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
    use crate::asset::property::test_utils::{make_ctx, make_ctx_with_version, write_fname};

    // --- wire-byte builders, kept explicit so the fixture bytes stay
    // independently auditable against the format doc, not circular with
    // the parser. ---

    /// Append the `(0, 0)` "None" terminator (an empty segment 1).
    fn none(buf: &mut Vec<u8>) {
        write_fname(buf, 0, 0);
    }

    /// Append a UE4.27 `IntProperty` FPropertyTag + its i32 value.
    fn int_property(buf: &mut Vec<u8>, name_idx: i32, type_idx: i32, value: i32) {
        write_fname(buf, name_idx, 0); // Name
        write_fname(buf, type_idx, 0); // Type ("IntProperty")
        buf.extend_from_slice(&4i32.to_le_bytes()); // Size
        buf.extend_from_slice(&0i32.to_le_bytes()); // ArrayIndex
        buf.push(0u8); // HasPropertyGuid
        buf.extend_from_slice(&value.to_le_bytes()); // value
    }

    /// Append a UE `FString`: `i32` length (UTF-8 byte count incl. null)
    /// + bytes + null terminator.
    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let len = i32::try_from(s.len() + 1).expect("test string fits in i32");
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
    }

    /// Append an `FTexturePlatformData` header *start* (no stripped-data
    /// prefix — the caller prepends version-specific prefix bytes):
    /// `SizeX`, `SizeY`, `PackedData`, `PixelFormat`.
    fn platform_header(
        buf: &mut Vec<u8>,
        size_x: i32,
        size_y: i32,
        packed: u32,
        pixel_format: &str,
    ) {
        buf.extend_from_slice(&size_x.to_le_bytes());
        buf.extend_from_slice(&size_y.to_le_bytes());
        buf.extend_from_slice(&packed.to_le_bytes());
        write_fstring(buf, pixel_format);
    }

    fn props_of(data: &Texture2DData) -> &[crate::asset::property::primitives::Property] {
        match &data.properties {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected Tree, got {other:?}"),
        }
    }

    #[test]
    fn ue4_decodes_segment1_then_platform_header() {
        // UE4 (file_version_ue5 = None) → no stripped-data prefix.
        // Combined: a segment-1 property AND the header.
        let ctx = make_ctx(&["None", "LODBias", "IntProperty"]);
        let mut bytes = Vec::new();
        int_property(&mut bytes, 1, 2, 3); // LODBias = 3
        none(&mut bytes);
        platform_header(&mut bytes, 64, 128, 1, "PF_DXT5");

        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        // Segment 1 still decodes.
        assert_eq!(props_of(&data).len(), 1);
        assert_eq!(props_of(&data)[0].value, PropertyValue::Int(3));
        // Header.
        assert_eq!(data.size_x, 64);
        assert_eq!(data.size_y, 128);
        assert_eq!(data.num_slices, 1);
        assert!(!data.is_cubemap);
        // PixelFormat is the alignment checksum: a wrong prefix/field
        // size would misalign and corrupt this read.
        assert_eq!(data.pixel_format, "PF_DXT5");
    }

    /// Build `none() + <prefix bytes> + platform_header(...)` and parse
    /// it under `make_ctx_with_version(522, ue5)`. Returns the decoded
    /// data. The empty name table is fine: segment 1 is a bare `None`.
    fn parse_with_prefix(ue5: Option<i32>, prefix: &[u8]) -> crate::Result<Texture2DData> {
        let ctx = make_ctx_with_version(522, ue5);
        let mut bytes = Vec::new();
        none(&mut bytes);
        bytes.extend_from_slice(prefix);
        platform_header(&mut bytes, 256, 256, 1, "PF_B8G8R8A8");
        read_from(&bytes, &ctx, "tex.uasset")
    }

    #[test]
    fn ue4_has_no_stripped_data_prefix() {
        // No prefix bytes; pixel-format checksum confirms the header
        // starts immediately after segment 1.
        let data = parse_with_prefix(None, &[]).expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8");
        assert_eq!(data.size_x, 256);
    }

    #[test]
    fn ue5_0_skips_16_byte_prefix() {
        // UE5.0 (1004 < 1009) → the full 16-byte placeholder skip.
        let data = parse_with_prefix(Some(1004), &[0xFFu8; 16]).expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8"); // checksum: 16-skip exact
    }

    #[test]
    fn ue5_1_takes_16_skip_not_the_flag_path() {
        // UE5.1 = 1008, one below VER_UE5_DATA_RESOURCES (1009). Pins the
        // exact 5.1/5.2 boundary: 5.1 takes the 16-byte skip, NOT the
        // flag path. A `>= 1008` gate would read a flag byte and misalign.
        let data = parse_with_prefix(Some(1008), &[0xFFu8; 16]).expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8");
    }

    #[test]
    fn ue5_2_flag_false_reads_flag_then_skips_15() {
        // UE5.2 = 1009: 1 `bUsingDerivedData` flag byte (0) + 15 skipped.
        let mut prefix = vec![0x00u8]; // flag = false
        prefix.extend_from_slice(&[0xFFu8; 15]);
        let data = parse_with_prefix(Some(1009), &prefix).expect("parse");
        assert_eq!(data.pixel_format, "PF_B8G8R8A8"); // checksum: flag+15 exact
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
    fn size_x_over_cap_rejected() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        platform_header(&mut bytes, 16385, 64, 1, "PF_DXT5"); // 16384 + 1
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
        platform_header(&mut bytes, 64, -1, 1, "PF_DXT5");
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
        platform_header(&mut bytes, 16384, 16384, 1, "PF_DXT5");
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("at-cap dimensions accepted");
        assert_eq!(data.size_x, 16384);
        assert_eq!(data.size_y, 16384);
    }

    #[test]
    fn cubemap_flag_and_slices_decoded_from_packed_data() {
        // bit 31 = cubemap; low bits = NumSlices = 6.
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        platform_header(&mut bytes, 64, 64, 0x8000_0006, "PF_DXT5");
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(data.is_cubemap);
        assert_eq!(data.num_slices, 6);
    }

    #[test]
    fn num_slices_keeps_overlapping_cpu_copy_bit() {
        // PackedData with bit 29 (HasCpuCopy) + slice bits set. Pins the
        // CUE4Parse-parity convention: the 0x3FFF_FFFF mask does NOT
        // strip bit 29 from NumSlices.
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        let packed = (1u32 << 29) | 5; // HasCpuCopy + 5
        platform_header(&mut bytes, 64, 64, packed, "PF_DXT5");
        let data = read_from(&bytes, &ctx, "tex.uasset").expect("parse");
        assert_eq!(data.num_slices, 0x2000_0005, "bit 29 must NOT be stripped");
        assert!(!data.is_cubemap);
    }

    #[test]
    fn truncated_header_surfaces_unexpected_eof() {
        // Segment 1 + SizeX only; reading SizeY EOFs.
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
    fn read_typed_wraps_header_in_texture2d_with_no_bulk_records() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        none(&mut bytes);
        platform_header(&mut bytes, 64, 64, 1, "PF_DXT5");

        let (asset, records) = read_typed(&bytes, &ctx, "tex.uasset").expect("parse");
        assert!(records.is_empty(), "no per-mip records until 3e-3");
        match asset {
            Asset::Texture2D(data) => {
                assert_eq!(data.size_x, 64);
                assert_eq!(data.pixel_format, "PF_DXT5");
            }
            other => panic!("expected Asset::Texture2D, got {other:?}"),
        }
    }
}
