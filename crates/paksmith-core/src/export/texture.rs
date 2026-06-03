//! `PngHandler` — exports a parsed `UTexture2D` as an 8-bit RGBA PNG (3e-8).
//!
//! The handler decodes the texture's **first-serialized mip** (single-LOD)
//! through the pixel-format decode layer (3e-4..3e-7), then encodes the
//! resulting RGBA8 buffer to PNG with the `png` crate. It is the capstone of
//! Phase 3e: the first place the whole texture stack (parse → resolve → decode
//! → encode) runs end-to-end.
//!
//! **Mip selection.** [`FormatHandler::export`] receives a single resolved
//! [`BulkData`] (the mip the caller chose), with no mip index in the
//! signature. [`selected_mip_index`] is the **single source of truth** for
//! which mip is exported — `first_mip_to_serialize` **bounded** into
//! `[0, mips.len())`. The handler reads the decode dimensions from
//! `mips[selected_mip_index]` (NOT the top-level `size_x`/`size_y`, which are
//! the top mip and would mismatch the bytes when `first_mip_to_serialize > 0`).
//! A future export driver MUST pass `bulk[selected_mip_index(data)]` — calling
//! the same function rather than recomputing the bound keeps the bytes it
//! passes and the dimensions the handler reads in lockstep.
//!
//! **sRGB chunk.** Per the decode layer's documented consumer obligation:
//! HDR formats (`PF_BC6H` / `PF_FloatRGB` / `PF_FloatRGBA`) are already
//! sRGB-encoded at decode time → always tagged sRGB, regardless of the `SRGB`
//! property (which UE stores `false` for float formats). LDR formats are raw
//! linear → tagged sRGB iff the texture's `SRGB` tagged property is `true`
//! (UE's `UTexture` default, so an absent property means `true`).

use crate::PaksmithError;
use crate::asset::Asset;
use crate::asset::Texture2DData;
use crate::asset::exports::texture::pixel_format::{PixelFormat, decode_mip};
use crate::asset::property::primitives::{Property, PropertyValue};
use crate::export::{BulkData, FormatHandler};

/// Exports `Asset::Texture2D` to an 8-bit RGBA PNG. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct PngHandler;

impl FormatHandler for PngHandler {
    fn output_extension(&self) -> &'static str {
        "png"
    }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::Texture2D(_))
    }

    fn export(&self, asset: &Asset, bulk: Option<&BulkData>) -> crate::Result<Vec<u8>> {
        let Asset::Texture2D(data) = asset else {
            return Err(PaksmithError::Internal {
                context: "PngHandler::export called on a non-Texture2D Asset".to_string(),
            });
        };

        // Virtual (paged/tiled) textures carry their pixels in an
        // `FVirtualTextureBuiltData` blob, not the standard mip chain — which is
        // typically empty here. Surface a clear "not yet renderable" message
        // BEFORE the no-bulk / no-mips paths below (which would otherwise report
        // a misleading "no mip records"). The blob is decoded in a later 3e-VT
        // milestone.
        if data.is_virtual {
            return Err(PaksmithError::UnsupportedFeature {
                context: "virtual textures (bIsVirtual) are not yet renderable — their \
                          FVirtualTextureBuiltData tile data is decoded in a later Phase \
                          3e-VT milestone"
                    .to_string(),
            });
        }

        // The caller resolves the mip chain and passes the selected mip's
        // bytes. `None` means no serialized mip data (e.g. a UE5.3+ texture
        // with `bSerializeMipData = false`, whose pixels live in the
        // editor-only derived-data cache); a correct caller skips such
        // textures rather than calling the handler.
        let mip = bulk.ok_or_else(|| PaksmithError::Internal {
            context: "PngHandler::export requires the selected mip's resolved bulk data \
                      (none provided — the texture has no serialized mip)"
                .to_string(),
        })?;

        let (width, height) = selected_mip_dimensions(data)?;
        let format = PixelFormat::from_name(&data.pixel_format);
        let is_normal_map = has_enum(data, "CompressionSettings", "TC_Normalmap");

        let decoded = decode_mip(
            &format,
            &mip.bytes,
            width,
            height,
            is_normal_map,
            "<texture mip>",
        )?;

        encode_png(
            &decoded.rgba,
            decoded.width,
            decoded.height,
            srgb_tag(data, &format),
        )
    }
}

/// The index of the mip `PngHandler` exports — the **single source of truth**
/// for which mip both the handler (for dimensions) and a future export driver
/// (for the `BulkData` bytes it passes) must use. It is `first_mip_to_serialize`
/// bounded into `[0, mips.len())`; `None` when the texture has no mips.
///
/// A driver MUST pass `bulk[selected_mip_index(data)]` so the bytes it supplies
/// match the dimensions the handler reads — calling this rather than
/// recomputing the bound independently is what keeps the two in lockstep.
pub(crate) fn selected_mip_index(data: &Texture2DData) -> Option<usize> {
    if data.mips.is_empty() {
        return None;
    }
    // first_mip_to_serialize is stored unvalidated (i32); bound it.
    Some(
        usize::try_from(data.first_mip_to_serialize.max(0))
            .unwrap_or(0)
            .min(data.mips.len() - 1),
    )
}

/// The dimensions of the exported mip (`mips[selected_mip_index]`). Errors if
/// the texture carries no mip records.
fn selected_mip_dimensions(data: &Texture2DData) -> crate::Result<(u32, u32)> {
    let idx = selected_mip_index(data).ok_or_else(|| PaksmithError::Internal {
        context: "PngHandler: texture has no mip records to export".to_string(),
    })?;
    let mip = &data.mips[idx];
    Ok((mip.size_x, mip.size_y))
}

/// Whether the texture's PNG should be tagged sRGB. HDR formats are already
/// sRGB-encoded by the decoder → always `true`; LDR formats follow the `SRGB`
/// tagged property (UE `UTexture` default `true`, so absent ⇒ `true`).
fn srgb_tag(data: &Texture2DData, format: &PixelFormat) -> bool {
    let is_hdr = matches!(
        format,
        PixelFormat::Bc6h | PixelFormat::FloatRgb | PixelFormat::FloatRgba
    );
    is_hdr || property_bool(data, "SRGB").unwrap_or(true)
}

/// The scalar (`array_index == 0`) tagged property named `name`, if present.
fn scalar_property<'a>(data: &'a Texture2DData, name: &str) -> Option<&'a Property> {
    data.properties
        .iter_properties()
        .find(|p| p.name() == name && p.array_index == 0)
}

/// Read a scalar `BoolProperty` named `name` from the texture's tagged
/// properties, if present.
fn property_bool(data: &Texture2DData, name: &str) -> Option<bool> {
    scalar_property(data, name).and_then(|p| match p.value {
        PropertyValue::Bool(b) => Some(b),
        _ => None,
    })
}

/// Whether the scalar enum property `name` resolves to `variant`.
fn has_enum(data: &Texture2DData, name: &str, variant: &str) -> bool {
    scalar_property(data, name).is_some_and(
        |p| matches!(&p.value, PropertyValue::Enum { value, .. } if value.as_ref() == variant),
    )
}

/// Encode a tightly-packed RGBA8 buffer (`rgba.len() == width × height × 4`,
/// guaranteed by `decode_mip`) to PNG bytes, writing the `sRGB` chunk when
/// `srgb` is set.
fn encode_png(rgba: &[u8], width: u32, height: u32, srgb: bool) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    if srgb {
        encoder.set_source_srgb(png::SrgbRenderingIntent::Perceptual);
    }
    // The inputs are decoder-controlled (valid dimensions + exact-length
    // buffer), so these only fail on an allocation/encoder fault — surface it
    // rather than panic.
    let mut writer = encoder
        .write_header()
        .map_err(|e| png_error("write PNG header", &e))?;
    writer
        .write_image_data(rgba)
        .map_err(|e| png_error("write PNG image data", &e))?;
    writer.finish().map_err(|e| png_error("finish PNG", &e))?;
    Ok(out)
}

fn png_error(stage: &str, err: &png::EncodingError) -> PaksmithError {
    PaksmithError::Internal {
        context: format!("PngHandler: failed to {stage}: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::Texture2DMipMap;
    use crate::asset::property::bag::PropertyBag;
    use crate::asset::property::primitives::Property;
    use crate::export::HandlerRegistry;
    use proptest::prelude::*;

    fn mip(w: u32, h: u32) -> Texture2DMipMap {
        Texture2DMipMap {
            size_x: w,
            size_y: h,
            size_z: 1,
        }
    }

    fn texture(format: &str, props: Vec<Property>) -> Texture2DData {
        Texture2DData {
            pixel_format: format.to_string(),
            size_x: 4,
            size_y: 4,
            mip_count: 1,
            mips: vec![mip(4, 4)],
            properties: PropertyBag::tree(props),
            ..Texture2DData::empty()
        }
    }

    fn bool_prop(name: &str, value: bool) -> Property {
        Property {
            name: name.into(),
            array_index: 0,
            guid: None,
            value: PropertyValue::Bool(value),
        }
    }

    /// A 16-byte DXT5 (BC3) block decoding to solid opaque red: alpha endpoints
    /// 0xFF/0xFF (opaque), color0 = RGB565 red (0xF800), indices 0.
    const SOLID_RED_DXT5: [u8; 16] = [
        0xFF, 0xFF, 0, 0, 0, 0, 0, 0, // alpha sub-block → opaque
        0x00, 0xF8, 0x00, 0x00, 0, 0, 0, 0, // color sub-block → red
    ];

    #[test]
    fn handler_metadata_and_registration() {
        let reg = HandlerRegistry::all_default_handlers();
        let asset = Asset::Texture2D(Texture2DData::empty());
        let handler = reg
            .find_handler(&asset)
            .expect("a default handler for Asset::Texture2D");
        assert_eq!(handler.output_extension(), "png");
        assert!(PngHandler.supports(&asset));
        assert!(!PngHandler.supports(&Asset::Generic(PropertyBag::opaque(Vec::new()))));
    }

    // ===== sRGB chunk: the three documented arms =====

    #[test]
    fn srgb_tag_hdr_is_always_true() {
        // HDR is pre-sRGB-encoded by the decoder → tagged sRGB even when the
        // SRGB property is false (UE stores false for float formats).
        let t = texture("PF_BC6H", vec![bool_prop("SRGB", false)]);
        assert!(srgb_tag(&t, &PixelFormat::Bc6h));
        assert!(srgb_tag(
            &texture("PF_FloatRGBA", vec![]),
            &PixelFormat::FloatRgba
        ));
    }

    #[test]
    fn srgb_tag_ldr_follows_the_property() {
        assert!(srgb_tag(
            &texture("PF_DXT5", vec![bool_prop("SRGB", true)]),
            &PixelFormat::Bc3
        ));
        assert!(!srgb_tag(
            &texture("PF_DXT5", vec![bool_prop("SRGB", false)]),
            &PixelFormat::Bc3
        ));
        // Absent SRGB property → UE UTexture default (true).
        assert!(srgb_tag(&texture("PF_DXT5", vec![]), &PixelFormat::Bc3));
    }

    // ===== mip selection =====

    #[test]
    fn selected_mip_uses_first_serialized_mip_bounded() {
        let mut t = texture("PF_DXT5", vec![]);
        t.mips = vec![mip(64, 64), mip(32, 32), mip(16, 16)];
        t.first_mip_to_serialize = 1;
        assert_eq!(selected_mip_index(&t), Some(1)); // the shared contract
        assert_eq!(selected_mip_dimensions(&t).unwrap(), (32, 32)); // mips[1]
        t.first_mip_to_serialize = 99; // out of range → last mip
        assert_eq!(selected_mip_index(&t), Some(2));
        assert_eq!(selected_mip_dimensions(&t).unwrap(), (16, 16));
        t.first_mip_to_serialize = -5; // negative → mip 0
        assert_eq!(selected_mip_index(&t), Some(0));
        assert_eq!(selected_mip_dimensions(&t).unwrap(), (64, 64));
    }

    #[test]
    fn selected_mip_errors_without_mips() {
        let mut t = texture("PF_DXT5", vec![]);
        t.mips = vec![];
        assert_eq!(selected_mip_index(&t), None);
        assert!(matches!(
            selected_mip_dimensions(&t),
            Err(PaksmithError::Internal { .. })
        ));
    }

    #[test]
    fn first_mip_to_serialize_gt_zero_reads_dims_of_that_mip_for_the_decode() {
        // The dims/bytes-agreement contract for `first_mip_to_serialize > 0`:
        // the exported mip is index 1 (an 8×8 top mip is NOT serialized), so
        // the handler reads (4, 4) from mips[1] — and a 16-byte 4×4 BC3 block
        // (the index-1 mip's bytes a driver would pass via `bulk[1]`) decodes
        // against those dims. Reading dims from mips[0] (8×8) instead would
        // demand 64 bytes and fail. Pins that the index drives BOTH sides.
        let mut t = texture("PF_DXT5", vec![]);
        t.mips = vec![mip(8, 8), mip(4, 4)];
        t.first_mip_to_serialize = 1;
        assert_eq!(selected_mip_index(&t), Some(1));
        let (w, h) = selected_mip_dimensions(&t).unwrap();
        assert_eq!((w, h), (4, 4));
        let decoded = decode_mip(&PixelFormat::Bc3, &SOLID_RED_DXT5, w, h, false, "t")
            .expect("the index-1 mip's 16 bytes decode at its own 4×4 dims");
        let png = encode_png(&decoded.rgba, decoded.width, decoded.height, true).expect("encode");
        assert_eq!(&png[1..4], b"PNG");
    }

    // ===== PNG encode round-trip + sRGB chunk presence =====

    #[test]
    fn encode_png_round_trips_pixels_and_tags_srgb() {
        let rgba: Vec<u8> = (0u8..2 * 2 * 4).collect(); // 2×2 distinct
        let png_bytes = encode_png(&rgba, 2, 2, true).expect("encode");
        assert_eq!(&png_bytes[1..4], b"PNG"); // PNG signature
        let mut reader = png::Decoder::new(std::io::Cursor::new(png_bytes.as_slice()))
            .read_info()
            .expect("read PNG");
        assert_eq!(reader.info().width, 2);
        assert_eq!(reader.info().height, 2);
        assert!(reader.info().srgb.is_some(), "sRGB chunk should be present");
        let mut buf = vec![0u8; reader.output_buffer_size().unwrap()];
        let frame = reader.next_frame(&mut buf).expect("decode frame");
        assert_eq!(&buf[..frame.buffer_size()], rgba.as_slice());
    }

    #[test]
    fn encode_png_omits_srgb_chunk_when_untagged() {
        let png_bytes = encode_png(&[0u8; 4], 1, 1, false).expect("encode");
        let reader = png::Decoder::new(std::io::Cursor::new(png_bytes.as_slice()))
            .read_info()
            .expect("read PNG");
        assert!(reader.info().srgb.is_none(), "sRGB chunk should be absent");
    }

    // ===== decode → encode pixel pipeline =====
    // The full `export()` (parse → resolve real BulkData → export) is covered
    // end-to-end in `paksmith-core-tests`; the BulkData ctor is `__test_utils`-
    // gated, so here we exercise the decode→encode chain directly.

    #[test]
    fn dxt5_decode_then_encode_round_trips_to_red_png() {
        let decoded =
            decode_mip(&PixelFormat::Bc3, &SOLID_RED_DXT5, 4, 4, false, "t").expect("decode");
        let png_bytes =
            encode_png(&decoded.rgba, decoded.width, decoded.height, true).expect("encode");
        let mut reader = png::Decoder::new(std::io::Cursor::new(png_bytes.as_slice()))
            .read_info()
            .expect("read PNG");
        assert_eq!((reader.info().width, reader.info().height), (4, 4));
        let mut buf = vec![0u8; reader.output_buffer_size().unwrap()];
        let frame = reader.next_frame(&mut buf).expect("decode frame");
        // The whole 4×4 is opaque red.
        assert!(
            buf[..frame.buffer_size()]
                .chunks_exact(4)
                .all(|px| px == [255, 0, 0, 255])
        );
    }

    #[test]
    fn export_errors_without_bulk() {
        let t = Asset::Texture2D(texture("PF_DXT5", vec![]));
        assert!(matches!(
            PngHandler.export(&t, None),
            Err(PaksmithError::Internal { .. })
        ));
    }

    #[test]
    fn export_rejects_non_texture_asset() {
        let g = Asset::Generic(PropertyBag::opaque(Vec::new()));
        assert!(matches!(
            PngHandler.export(&g, None),
            Err(PaksmithError::Internal { .. })
        ));
    }

    #[test]
    fn export_reports_virtual_textures_as_not_yet_renderable() {
        // A virtual texture (bIsVirtual) has its pixels in a not-yet-decoded
        // blob. The is_virtual branch must fire BEFORE the no-bulk / no-mips
        // paths and carry a clear message — even when `bulk` is None (which
        // would otherwise yield the misleading "no serialized mip" error).
        let mut data = texture("PF_DXT5", vec![]);
        data.is_virtual = true;
        match PngHandler.export(&Asset::Texture2D(data), None) {
            Err(PaksmithError::UnsupportedFeature { context }) => {
                assert!(
                    context.contains("virtual") && context.contains("not yet renderable"),
                    "expected the virtual-texture message, got: {context}"
                );
            }
            other => panic!("expected UnsupportedFeature(virtual-texture), got {other:?}"),
        }
    }

    /// `export()` must read the decode dims from the SELECTED mip, NOT the
    /// top-level `size_x`/`size_y` — the central claim of the mip-selection
    /// contract, exercised through the full `export()` path (the bulk-data
    /// ctor is `__test_utils`-gated, so this test is too). `first_mip_to_serialize
    /// = 1` makes the exported mip `mips[1]` (4×4) while the top-level dims are
    /// 8×8; a 16-byte BC3 block is exactly one 4×4 block, so reading (4,4)
    /// decodes but reading (8,8) would demand 64 bytes and fail. Strict
    /// discriminant against a `selected_mip_dimensions(data)` → `(data.size_x,
    /// data.size_y)` substitution.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn export_reads_selected_mip_dims_not_top_level() {
        use crate::asset::bulk_data::{BulkData, BulkDataFlags, BulkDataTier, FByteBulkData};
        let mut data = texture("PF_DXT5", vec![]);
        data.size_x = 8;
        data.size_y = 8;
        data.mips = vec![mip(8, 8), mip(4, 4)];
        data.first_mip_to_serialize = 1;
        let bulk = BulkData {
            bytes: SOLID_RED_DXT5.to_vec(),
            record: FByteBulkData::for_test(BulkDataFlags::from(0), 16, 16, 0),
            tier: BulkDataTier::Inline,
        };
        let png = PngHandler
            .export(&Asset::Texture2D(data), Some(&bulk))
            .expect("reads mips[1]=4×4 → the 16-byte block decodes");
        // IHDR width/height: big-endian u32 at byte offsets 16 and 20.
        assert_eq!(
            &png[16..20],
            &[0, 0, 0, 4],
            "width = 4 (mips[1], not size_x=8)"
        );
        assert_eq!(&png[20..24], &[0, 0, 0, 4], "height = 4");
    }

    // ===== mutant guards: property lookups respect name + array_index =====

    fn enum_prop(name: &str, array_index: i32, variant: &str) -> Property {
        Property {
            name: name.into(),
            array_index,
            guid: None,
            value: PropertyValue::Enum {
                type_name: "TextureCompressionSettings".into(),
                value: variant.into(),
            },
        }
    }

    #[test]
    fn property_bool_respects_name_and_array_index() {
        // The real scalar SRGB is preceded by a decoy AT index 0 with a
        // DIFFERENT name, and a same-name decoy at index 1 — both carrying the
        // opposite value. Correct `name == n && array_index == 0` finds only
        // the real one. `&&`→`||` would match the index-0 decoy (→ Some(true));
        // flipping the `== 0` literal would match the index-1 decoy.
        let props = vec![
            bool_prop("OtherFlag", true), // decoy: idx 0, wrong name
            Property {
                name: "SRGB".into(),
                array_index: 1,
                guid: None,
                value: PropertyValue::Bool(true),
            }, // decoy: right name, idx 1
            bool_prop("SRGB", false),     // the real scalar SRGB
        ];
        assert_eq!(
            property_bool(&texture("PF_DXT5", props), "SRGB"),
            Some(false)
        );
    }

    #[test]
    fn property_bool_absent_is_none() {
        // Pins `property_bool`'s `None` (so `srgb_tag`'s `unwrap_or(true)`
        // default arm is meaningfully exercised, not dead).
        assert_eq!(property_bool(&texture("PF_DXT5", vec![]), "SRGB"), None);
    }

    #[test]
    fn has_enum_matches_only_the_named_scalar_variant() {
        // Real CompressionSettings = TC_Normalmap at index 0, preceded by a
        // non-enum decoy at index 0 (wrong name) and a same-name decoy at
        // index 1. The positive assertion kills `has_enum -> false` and the
        // `==`→`!=` variant compare; the decoys kill `&&`→`||` (the idx-0
        // non-enum decoy → false) and the `== 0` literal (the idx-1 decoy).
        let props = vec![
            bool_prop("OtherFlag", true), // idx 0, wrong name, non-enum
            enum_prop("CompressionSettings", 1, "TC_Default"), // right name, idx 1, OTHER variant
            enum_prop("CompressionSettings", 0, "TC_Normalmap"), // the real scalar
        ];
        let t = texture("PF_DXT5", props);
        // The idx-1 decoy's distinct variant makes `== 0`→`!= 0` observable:
        // the mutant reads the idx-1 `TC_Default` and misses the match.
        assert!(has_enum(&t, "CompressionSettings", "TC_Normalmap"));
        // A different variant must NOT match (the other side of `==`).
        assert!(!has_enum(&t, "CompressionSettings", "TC_Default"));
        // Absent property → false.
        assert!(!has_enum(
            &texture("PF_DXT5", vec![]),
            "CompressionSettings",
            "TC_Normalmap"
        ));
    }

    // ===== BC3 decode cross-validation =====
    //
    // paksmith decodes BC3 (`PF_DXT5`) through `bcdec_rs` (an iOrange/bcdec.h
    // port). Two complementary checks:
    //
    //   1. A spec-derived golden vector pinning the exact 4-entry color table,
    //      including the always-4-color rule the S3TC spec mandates for BC3.
    //   2. A restricted differential check against the independent
    //      `texture2ddecoder` (AssetStudio lineage), confirming the two impls
    //      AGREE WITHIN ROUNDING (±1) on arbitrary blocks.
    //
    // IMPORTANT — texture2ddecoder is NOT a byte-exact BC3 oracle. Its
    // `decode_bc3_block` reuses `decode_bc1_block`, which honours BC1's
    // `color0 <= color1` punchthrough (3 colors + transparent black). The
    // Khronos S3TC spec forbids that for DXT3/DXT5: the RGB block is
    // "treated as though color0 > color1, regardless of the actual values of
    // color0 and color1".
    // bcdec_rs enforces this (`only_opaque_mode = true`), so the two diverge by
    // up to 255 on `c0 <= c1` blocks. That deviation lives ONLY in this test
    // oracle — production BC1–BC7/BC6H route exclusively through bcdec_rs;
    // texture2ddecoder is wired only for ASTC/ETC (3e-6). The differential
    // check below therefore forces `c0 > c1` by construction.

    /// Decode a BC3 block tile via the independent `texture2ddecoder` path,
    /// returning RGBA8 (it emits BGRA-in-`u32`).
    fn texture2ddecoder_bc3_rgba(block: &[u8], width: u32, height: u32) -> Vec<u8> {
        let mut bgra = vec![0u32; (width as usize) * (height as usize)];
        texture2ddecoder::decode_bc3(block, width as usize, height as usize, &mut bgra)
            .expect("texture2ddecoder bc3");
        bgra.iter()
            .flat_map(|px| {
                let [b, g, r, a] = px.to_le_bytes();
                [r, g, b, a]
            })
            .collect()
    }

    #[test]
    fn bc3_color_table_matches_spec_golden_vector() {
        // Color endpoints c0 = RGB565 0x0000 (black), c1 = 0xFFFF (white), so
        // c0 <= c1 — the case texture2ddecoder mis-decodes as punchthrough.
        // Per S3TC, BC3 always uses 4-color mode:
        //   color_0 = (0,0,0)   color_1 = (255,255,255)
        //   color_2 = 2/3·c0 + 1/3·c1 = (85,85,85)
        //   color_3 = 1/3·c0 + 2/3·c1 = (170,170,170)
        // Color indices 0xE4 = 0b11_10_01_00 → pixels 0..3 select entries
        // 0,1,2,3; remaining pixels select entry 0 (black). Alpha sub-block
        // a0=255/a1=0 with all-zero indices → every texel opaque.
        let block: [u8; 16] = [
            0xFF, 0x00, 0, 0, 0, 0, 0, 0, // alpha → opaque everywhere
            0x00, 0x00, 0xFF, 0xFF, 0xE4, 0x00, 0x00, 0x00, // color c0/c1/indices
        ];
        let rgba = decode_mip(&PixelFormat::Bc3, &block, 4, 4, false, "t")
            .expect("decode")
            .rgba;
        assert_eq!(&rgba[0..4], &[0, 0, 0, 255], "index 0 → color_0");
        assert_eq!(&rgba[4..8], &[255, 255, 255, 255], "index 1 → color_1");
        assert_eq!(&rgba[8..12], &[85, 85, 85, 255], "index 2 → color_2");
        assert_eq!(&rgba[12..16], &[170, 170, 170, 255], "index 3 → color_3");
        // The discriminator vs the punchthrough deviation is RGB at index 3:
        // a BC1-punchthrough decoder yields (0,0,0) there. (Alpha can't
        // discriminate — BC3 alpha is overwritten from the alpha block.)
        assert_ne!(&rgba[12..15], &[0, 0, 0], "BC3 must not punchthrough");
    }

    #[test]
    fn bc3_solid_block_matches_oracle_exactly() {
        // SOLID_RED has c0 = 0xF800 > c1 = 0x0000 and all-zero indices (no
        // interpolation), so paksmith and the oracle agree byte-for-byte.
        let ours = decode_mip(&PixelFormat::Bc3, &SOLID_RED_DXT5, 4, 4, false, "t")
            .expect("decode")
            .rgba;
        assert_eq!(ours, texture2ddecoder_bc3_rgba(&SOLID_RED_DXT5, 4, 4));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Arbitrary BC3 blocks (forced into the `c0 > c1` 4-color region)
        /// decode within ±1 per channel through paksmith's `bcdec_rs` path and
        /// the independent `texture2ddecoder` path. ±1 is the principled bound:
        /// both libs do identical bit-replication for 565→888, so any
        /// difference is a single integer rounding of the same interpolation.
        #[test]
        fn bc3_decode_agrees_with_oracle_within_rounding(
            mut block in prop::array::uniform16(any::<u8>()),
        ) {
            // Normalise to a strict c0 > c1 so we stay in the region where BC1
            // and BC3 color decode agree (equal endpoints still disagree at
            // index 3: 4-color gives c0, punchthrough gives transparent).
            let c0 = u16::from_le_bytes([block[8], block[9]]);
            let c1 = u16::from_le_bytes([block[10], block[11]]);
            let mut hi = c0.max(c1);
            let mut lo = c0.min(c1);
            if hi == lo {
                if hi == u16::MAX {
                    lo -= 1;
                } else {
                    hi += 1;
                }
            }
            block[8..10].copy_from_slice(&hi.to_le_bytes());
            block[10..12].copy_from_slice(&lo.to_le_bytes());
            let ours = decode_mip(&PixelFormat::Bc3, &block, 4, 4, false, "t")
                .expect("decode")
                .rgba;
            let theirs = texture2ddecoder_bc3_rgba(&block, 4, 4);
            for (o, t) in ours.iter().zip(theirs.iter()) {
                prop_assert!(
                    (i32::from(*o) - i32::from(*t)).abs() <= 1,
                    "channel diff > 1: ours={o} theirs={t}"
                );
            }
        }
    }
}
