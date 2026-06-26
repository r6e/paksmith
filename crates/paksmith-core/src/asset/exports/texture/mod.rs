//! `UTexture2D` (and Phase-3e sibling) typed export readers.
//!
//! Wire-format reference: `docs/formats/texture/texture2d.md`. A
//! `UTexture2D` export body is a standard `FPropertyTag` tagged-property
//! stream, then the `UTexture` / `UTexture2D` binary entry (strip flags +
//! owner cooked/serialize flags), then the `FTexturePlatformData` blob
//! carrying the cooked mip chain.
//!
//! Phase 3e lands incrementally:
//! - **3e-1**: routes the `Texture2D` class through dispatch and
//!   decodes **segment 1** (tagged properties).
//! - **3e-2** ([`texture2d::read_from`]): the **full**
//!   `FTexturePlatformData` header — the version-gated stripped-data
//!   prefix, `SizeX`, `SizeY`, `PackedData`, `PixelFormat` (3e-2a), then
//!   the conditional `OptData` / `CPUCopy`, `FirstMipToSerialize`, and
//!   the mip-count prefix (3e-2b) — into [`crate::asset::Texture2DData`].
//! - **3e-3** ([`texture2d::read_from`], cont.): the **segment-2 entry**
//!   (`UTexture` / `UTexture2D` `FStripDataFlags` + owner `bCooked` +
//!   `bSerializeMipData`) that precedes the platform data, then the
//!   per-mip `FTexture2DMipMap` records — `bCooked` (UE4) + each mip's
//!   `FByteBulkData` payload record (iff `bSerializeMipData`) +
//!   `SizeX`/`SizeY`/`SizeZ`. Per-mip dimensions land in
//!   [`crate::asset::Texture2DData::mips`]; the bulk records are surfaced
//!   keyed by export index and stored in `Package` by `read_from_inner`
//!   (3e-3b) so the mip bytes resolve lazily via
//!   `Package::resolve_bulk_for_export`.
//! - **3e-4** ([`pixel_format`]): the `EPixelFormat` enum + uncompressed
//!   decoders (`PF_R8G8B8A8`, `PF_B8G8R8A8`, `PF_G8`, `PF_G16`) that turn a
//!   mip's encoded bytes into RGBA8, plus the `MAX_DECODED_TEXTURE_BYTES`
//!   cap.
//! - **3e-5** ([`pixel_format`]): the BC family (`PF_DXT1`/`PF_DXT3`/
//!   `PF_DXT5`/`PF_BC4`/`PF_BC5`/`PF_BC7`) via the `bcdec_rs` crate.
//! - **3e-6** ([`pixel_format`]): the mobile families via `texture2ddecoder` —
//!   ASTC (`PF_ASTC_4x4`/`6x6`/`8x8`/`10x10`/`12x12`) and ETC
//!   (`PF_ETC1`/`PF_ETC2_RGB`/`PF_ETC2_RGBA`).
//! - **3e-7** ([`pixel_format`]): the HDR family — `PF_BC6H` (via `bcdec_rs`),
//!   `PF_FloatRGB` (`R11G11B10F`), `PF_FloatRGBA` (4× `f16`) — decoded to
//!   linear float then tone-mapped (ACES + sRGB) to 8-bit. `PngHandler` (3e-8)
//!   follows.

//! - **3e-VT-a** ([`texture2d::read_from`], cont.): reads the trailing
//!   `bIsVirtual` flag (UE 4.23+) so virtual textures are identified.
//! - **3e-VT-b1** ([`virtual_textures`]): the structural parse of the
//!   `FVirtualTextureBuiltData` blob (header, dispatch tables, layer formats)
//!   when `bIsVirtual == true`, stopping before the chunk payloads (3e-VT-b2).

pub(crate) mod pixel_format;
pub(crate) mod texture2d;
pub(crate) mod virtual_textures;

use crate::PaksmithError;
use crate::asset::Asset;
use crate::asset::Texture2DData;
use crate::asset::exports::texture::pixel_format::{DecodedTexture, PixelFormat, decode_mip};
use crate::asset::exports::texture::virtual_textures::flatten_virtual_texture;
use crate::asset::package::Package;
use crate::asset::property::primitives::{Property, PropertyValue};

/// A decoded texture mip as a tightly-packed RGBA8 buffer.
///
/// Produced by [`decode_texture_mip`] and consumed by the GUI texture viewer
/// (Phase 7b). `rgba.len() == width as usize * height as usize * 4`, guaranteed
/// by the decode layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTextureRgba {
    /// Width of the decoded mip in pixels.
    pub width: u32,
    /// Height of the decoded mip in pixels.
    pub height: u32,
    /// Tightly-packed RGBA8 pixels, row-major, top-left origin.
    /// Length is always `width as usize * height as usize * 4`.
    pub rgba: Vec<u8>,
}

/// Lightweight summary of a texture export's decodable state.
///
/// Produced by [`classify_texture`] — a pure, cheap scan over `Package.payloads`
/// that collects the metadata the GUI viewer needs to populate its tab headers and
/// mip selectors without resolving bulk data. Bulk resolution and actual pixel
/// decode happen in [`decode_texture_mip`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureInfo {
    /// Index into `Package.payloads` of the `Asset::Texture2D` export.
    pub export_idx: usize,
    /// Serialized mip dimensions in wire order (index 0 = top serialized mip).
    /// For virtual textures this is `[(width, height)]` (one entry, full res).
    pub mips: Vec<(u32, u32)>,
    /// Human-readable pixel format label (`data.pixel_format` for standard
    /// textures; `vt.layer_types[0]` for virtual textures).
    pub format_label: String,
    /// Whether the texture is a tangent-space normal map
    /// (`CompressionSettings == TC_Normalmap`). Gates ASTC blue-channel
    /// reconstruction.
    pub is_normal_map: bool,
}

/// Find the first decodable `Asset::Texture2D` in `package.payloads` and return
/// a lightweight [`TextureInfo`] summary, or `None` if no decodable texture
/// export is present.
///
/// "Decodable" means the pixel format has a registered decoder (or the virtual
/// texture's layer-0 format does) **and** the export carries serialized mip
/// bytes. A standard texture with `bSerializeMipData = false` keeps its mip
/// dimensions but ships no bulk records, so it is reported as non-decodable —
/// there are no bytes to decode. This function is **pure and allocation-cheap**:
/// it checks only for the *presence* of bulk records (an O(1) map lookup) and
/// never resolves them.
///
/// The bulk-presence check relies on the typed-reader path having populated the
/// package's bulk records, which is guaranteed for any `Package` built via the
/// `read_from*` constructors. A hand-assembled `Package` with `Texture2D`
/// payloads but no `insert_bulk_records` call would classify as `None`.
///
/// # Return value
///
/// `Some(info)` where `info.export_idx` is the index of the texture in
/// `package.payloads`, `info.mips` lists each serialized mip's `(width, height)`
/// (one entry for virtual textures), and `info.format_label` is the pixel-format
/// string. Returns `None` if no matching export is found.
pub fn classify_texture(package: &Package) -> Option<TextureInfo> {
    package
        .payloads
        .iter()
        .enumerate()
        .find_map(|(export_idx, asset)| {
            let Asset::Texture2D(data) = asset else {
                return None;
            };

            let is_normal_map = has_enum(data, "CompressionSettings", "TC_Normalmap");

            if let Some(vt) = data.virtual_texture.as_deref() {
                // Virtual texture: decodable if layer-0 has a known format.
                let layer0 = vt.layer_types.first().map_or("", String::as_str);
                if !pixel_format::is_decodable(&PixelFormat::from_name(layer0)) {
                    return None;
                }
                return Some(TextureInfo {
                    export_idx,
                    mips: vec![(vt.width, vt.height)],
                    format_label: layer0.to_string(),
                    is_normal_map,
                });
            }

            // Standard mip chain: need at least one mip with a decodable format.
            if data.mips.is_empty() {
                return None;
            }
            if !pixel_format::is_decodable(&PixelFormat::from_name(&data.pixel_format)) {
                return None;
            }
            // `bSerializeMipData = false` leaves the mip dimensions populated but
            // serializes no bulk records, so the mip bytes can never be resolved.
            // Such a texture is not decodable; reject it here (cheap, no I/O)
            // rather than letting `decode_texture_mip` fail later.
            if !package.has_bulk_records(export_idx) {
                return None;
            }

            let mips = data.mips.iter().map(|m| (m.size_x, m.size_y)).collect();
            Some(TextureInfo {
                export_idx,
                mips,
                format_label: data.pixel_format.clone(),
                is_normal_map,
            })
        })
}

/// Decode a specific mip of the texture export at `export_idx` in `package`.
///
/// Resolves the export's bulk data internally via
/// `Package::resolve_bulk_for_export(export_idx)`, then decodes the mip at
/// `mip_index` to an RGBA8 [`DecodedTextureRgba`].
///
/// For virtual textures the `mip_index` argument is ignored — virtual textures
/// are always flattened at full resolution (the single entry reported by
/// [`classify_texture`]).
///
/// # Errors
///
/// - [`PaksmithError::InvalidArgument`] if `export_idx` is out of range or does
///   not point to a `Texture2DData` export, or if `mip_index` is out of range
///   for the texture's serialized mip list. These signal caller misuse.
/// - [`PaksmithError::UnsupportedFeature`] if the export carries no serialized
///   mip bytes for `mip_index` (e.g. a texture with `bSerializeMipData = false`).
///   [`classify_texture`] already screens these out, so a well-behaved GUI
///   caller never hits this path.
/// - Any decode error from the pixel-format decode layer
///   (`pixel_format::decode_mip`) or the virtual-texture flatten
///   (`flatten_virtual_texture`).
pub fn decode_texture_mip(
    package: &Package,
    export_idx: usize,
    mip_index: usize,
) -> crate::Result<DecodedTextureRgba> {
    let asset = package
        .payloads
        .get(export_idx)
        .ok_or_else(|| PaksmithError::InvalidArgument {
            arg: "export_idx",
            reason: format!(
                "out of range (payloads len {}); got {export_idx}",
                package.payloads.len()
            ),
        })?;

    let Asset::Texture2D(data) = asset else {
        return Err(PaksmithError::InvalidArgument {
            arg: "export_idx",
            reason: format!("export {export_idx} is not a Texture2D"),
        });
    };

    let is_normal_map = has_enum(data, "CompressionSettings", "TC_Normalmap");
    let bulk = package.resolve_bulk_for_export(export_idx)?;

    // Virtual texture path: flatten layer 0, ignore mip_index.
    if let Some(vt) = data.virtual_texture.as_deref() {
        let decoded = flatten_virtual_texture(vt, bulk, is_normal_map)?;
        return Ok(decoded_texture_to_rgba(decoded));
    }

    // Standard mip chain.
    let mip_record = data
        .mips
        .get(mip_index)
        .ok_or_else(|| PaksmithError::InvalidArgument {
            arg: "mip_index",
            reason: format!(
                "out of range (mips len {}); got {mip_index}",
                data.mips.len()
            ),
        })?;
    // `mip_index` is in range for the mip list but the bulk records fall short:
    // the mip bytes were not serialized (e.g. `bSerializeMipData = false`). This
    // is a capability gap on well-formed input, not caller misuse.
    let bulk_record = bulk
        .get(mip_index)
        .ok_or_else(|| PaksmithError::UnsupportedFeature {
            context: format!(
                "texture export {export_idx} has no serialized bytes for mip {mip_index} \
                 (bulk len {}; the texture may have bSerializeMipData = false)",
                bulk.len()
            ),
        })?;

    let format = PixelFormat::from_name(&data.pixel_format);
    let decoded = decode_mip(
        &format,
        &bulk_record.bytes,
        mip_record.size_x,
        mip_record.size_y,
        is_normal_map,
        "<texture mip>",
    )?;
    Ok(decoded_texture_to_rgba(decoded))
}

/// Convert the internal [`DecodedTexture`] to the public [`DecodedTextureRgba`].
fn decoded_texture_to_rgba(decoded: DecodedTexture) -> DecodedTextureRgba {
    DecodedTextureRgba {
        width: decoded.width,
        height: decoded.height,
        rgba: decoded.rgba,
    }
}

// ─── Shared property-access helpers ───────────────────────────────────────────
//
// These helpers were originally private in `crate::export::texture`. They are
// promoted here (`pub(crate)`) so both this module and `export/texture.rs` share
// a single implementation rather than parallel copies.

/// The scalar (`array_index == 0`) tagged property named `name`, if present.
pub(crate) fn scalar_property<'a>(data: &'a Texture2DData, name: &str) -> Option<&'a Property> {
    data.properties
        .iter_properties()
        .find(|p| p.name() == name && p.array_index == 0)
}

/// Read a scalar `BoolProperty` named `name` from the texture's tagged
/// properties, if present.
pub(crate) fn property_bool(data: &Texture2DData, name: &str) -> Option<bool> {
    scalar_property(data, name).and_then(|p| match p.value {
        PropertyValue::Bool(b) => Some(b),
        _ => None,
    })
}

/// Whether the scalar enum property `name` resolves to `variant`.
///
/// UE serializes tagged `EnumProperty` values as the **fully-qualified** FName
/// `EnumType::Value` for namespaced / enum-class enums, and paksmith's own
/// unversioned/`.usmap` decoder emits the same qualified form. The `EnumType::`
/// qualifier is stripped before comparison — mirroring CUE4Parse's
/// `SubstringAfter("::")` — so both `"TC_Normalmap"` and
/// `"TextureCompressionSettings::TC_Normalmap"` match `variant = "TC_Normalmap"`.
pub(crate) fn has_enum(data: &Texture2DData, name: &str, variant: &str) -> bool {
    scalar_property(data, name).is_some_and(|p| match &p.value {
        PropertyValue::Enum { value, .. } => {
            let stored = value.as_ref();
            // Strip up to and including the first `::` (the enum-type qualifier).
            let bare = stored
                .split_once("::")
                .map_or(stored, |(_, variant_name)| variant_name);
            bare == variant
        }
        _ => false,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::asset::package::Package;
    use crate::testing::uasset::{build_minimal_ue4_27, build_minimal_with_decodable_texture2d};

    fn parse_pkg(bytes: &[u8]) -> Package {
        Package::read_from(bytes, None, None, "Game/Tex.uasset").expect("parse package")
    }

    /// Build a decodable `Texture2D` package, then drop its bulk records to
    /// model a `bSerializeMipData = false` texture (mip dimensions populated, no
    /// serialized bytes). Returns the package and the texture export index.
    fn texture_pkg_with_bulk_dropped() -> (Package, usize) {
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        let export_idx = classify_texture(&pkg)
            .expect("fixture with bulk must classify before records are dropped")
            .export_idx;
        pkg.insert_bulk_records_for_test(export_idx, Vec::new())
            .expect("dropping bulk records must succeed");
        (pkg, export_idx)
    }

    // ── classify_texture ─────────────────────────────────────────────────────

    #[test]
    fn classify_texture_returns_info_for_a_decodable_texture2d() {
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let info = classify_texture(&pkg).expect("decodable texture must classify as Some");

        // The decodable fixture is 4×4 PF_DXT5 with one mip.
        assert!(!info.mips.is_empty(), "must report at least one mip");
        assert_eq!(
            info.mips[0],
            (4, 4),
            "top mip dimensions must match the 4×4 fixture"
        );
        assert_eq!(info.format_label, "PF_DXT5");
        assert!(
            !info.is_normal_map,
            "fixture has no CompressionSettings property"
        );
    }

    #[test]
    fn classify_texture_export_idx_points_to_the_texture_asset() {
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let info = classify_texture(&pkg).expect("must classify");

        assert!(
            matches!(pkg.payloads.get(info.export_idx), Some(Asset::Texture2D(_))),
            "export_idx must point at an Asset::Texture2D"
        );
    }

    #[test]
    fn classify_texture_none_for_non_texture() {
        // build_minimal_ue4_27 produces a package with a Generic export (no Texture2D).
        let fixture = build_minimal_ue4_27();
        let pkg = parse_pkg(&fixture.bytes);

        assert!(
            classify_texture(&pkg).is_none(),
            "a non-texture package must yield None"
        );
    }

    #[test]
    fn classify_texture_none_when_no_bulk_records() {
        // A decodable texture whose bulk records were dropped models
        // `bSerializeMipData = false`: the mip dimensions remain but no bytes
        // are serialized. classify must reject it so the GUI never offers a
        // Texture tab that would fail at decode time.
        let (pkg, _export_idx) = texture_pkg_with_bulk_dropped();

        assert!(
            classify_texture(&pkg).is_none(),
            "a texture with mip dims but no serialized bulk bytes must yield None"
        );
    }

    // ── classify_texture: virtual-texture branch ─────────────────────────────

    /// A minimal `VirtualTextureData` whose layer-0 format is `layer0` and whose
    /// full-resolution dimensions are 8×8.
    fn vt_with_layer0(
        layer0: &str,
    ) -> crate::asset::exports::texture::virtual_textures::VirtualTextureData {
        // Only the fields `classify_texture` reads are set explicitly (width,
        // height, layer_types); the rest default. Setting an unread field (e.g.
        // num_layers) would leave a struct-field-deletion mutant unkilled.
        crate::asset::exports::texture::virtual_textures::VirtualTextureData {
            width: 8,
            height: 8,
            layer_types: vec![layer0.to_string()],
            ..Default::default()
        }
    }

    /// Parse the decodable fixture, then promote its `Texture2D` payload to a
    /// virtual texture carrying `layer0` as its sole layer format.
    fn pkg_with_virtual_texture(layer0: &str) -> Package {
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        let tex = pkg
            .payloads
            .iter_mut()
            .find_map(|a| match a {
                Asset::Texture2D(d) => Some(d),
                _ => None,
            })
            .expect("fixture must contain a Texture2D");
        tex.virtual_texture = Some(Box::new(vt_with_layer0(layer0)));
        pkg
    }

    #[test]
    fn classify_texture_virtual_decodable_layer0_is_some() {
        let pkg = pkg_with_virtual_texture("PF_DXT1");
        let info =
            classify_texture(&pkg).expect("a VT with a decodable layer-0 must classify as Some");
        assert_eq!(
            info.mips,
            vec![(8, 8)],
            "a virtual texture reports its full-resolution dims as the single mip"
        );
        assert_eq!(info.format_label, "PF_DXT1");
    }

    #[test]
    fn classify_texture_virtual_undecodable_layer0_is_none() {
        // An unknown EPixelFormat name decodes to PixelFormat::Unknown, which is
        // not decodable. This pins the VT-branch decodability guard: it kills
        // both the `delete !` mutant on the `if !is_decodable(...)` guard and the
        // `is_decodable -> true` body mutant (either flip would wrongly classify
        // this undecodable VT as Some).
        let pkg = pkg_with_virtual_texture("PF_NotARealFormat");
        assert!(
            classify_texture(&pkg).is_none(),
            "a VT whose layer-0 format is undecodable must yield None"
        );
    }

    // ── decode_texture_mip ───────────────────────────────────────────────────

    #[test]
    fn decode_texture_mip_yields_rgba_of_expected_size() {
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let info = classify_texture(&pkg).expect("must classify");
        let out = decode_texture_mip(&pkg, info.export_idx, 0).expect("mip 0 must decode");

        assert_eq!(
            out.rgba.len() as u64,
            u64::from(out.width) * u64::from(out.height) * 4,
            "rgba len must equal width * height * 4"
        );
        assert_eq!(
            (out.width, out.height),
            info.mips[0],
            "decoded dimensions must match classify_texture mips[0]"
        );
    }

    #[test]
    fn decode_texture_mip_out_of_range_is_invalid_argument() {
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let info = classify_texture(&pkg).expect("must classify");
        let err = decode_texture_mip(&pkg, info.export_idx, info.mips.len() + 99)
            .expect_err("out-of-range mip_index must return Err");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "mip_index",
                    ..
                }
            ),
            "out-of-range mip_index is caller misuse → InvalidArgument(mip_index), got {err:?}"
        );
    }

    #[test]
    fn decode_texture_mip_bad_export_idx_is_invalid_argument() {
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let err =
            decode_texture_mip(&pkg, 9999, 0).expect_err("out-of-range export_idx must return Err");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "export_idx",
                    ..
                }
            ),
            "out-of-range export_idx is caller misuse → InvalidArgument(export_idx), got {err:?}"
        );
    }

    #[test]
    fn decode_texture_mip_non_texture_export_is_invalid_argument() {
        // The Generic export lives at index 0 in the minimal packages.
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);

        let err = decode_texture_mip(&pkg, 0, 0)
            .expect_err("calling on a non-Texture2D export must return Err");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "export_idx",
                    ..
                }
            ),
            "a non-Texture2D export is caller misuse → InvalidArgument(export_idx), got {err:?}"
        );
    }

    #[test]
    fn decode_texture_mip_no_bulk_records_is_unsupported_feature() {
        // Simulate `bSerializeMipData = false`: a decodable texture whose mip
        // dimensions are populated but whose bulk records were dropped. The empty
        // insert removes the entry, so `resolve_bulk_for_export` returns an empty
        // slice and the mip bytes can't be found.
        let (pkg, export_idx) = texture_pkg_with_bulk_dropped();

        let err = decode_texture_mip(&pkg, export_idx, 0)
            .expect_err("a texture with no serialized mip bytes must return Err");
        assert!(
            matches!(err, PaksmithError::UnsupportedFeature { .. }),
            "missing serialized mip bytes is a capability gap → UnsupportedFeature, got {err:?}"
        );
    }

    // ── property helpers: mutant guards ──────────────────────────────────────
    //
    // These mirror the guards in `export/texture.rs` but exercise the helpers
    // from their new canonical home so moves + dedup don't silently drop coverage.

    fn mip_data(w: u32, h: u32) -> crate::asset::Texture2DMipMap {
        crate::asset::Texture2DMipMap {
            size_x: w,
            size_y: h,
            size_z: 1,
        }
    }

    fn texture_data(format: &str, props: Vec<Property>) -> Texture2DData {
        Texture2DData {
            pixel_format: format.to_string(),
            size_x: 4,
            size_y: 4,
            mip_count: 1,
            mips: vec![mip_data(4, 4)],
            properties: crate::asset::property::bag::PropertyBag::tree(props),
            ..Texture2DData::empty()
        }
    }

    #[test]
    fn texture_data_helper_pins_emitted_fields() {
        // The `texture_data` / `mip_data` helpers hardcode field values that the
        // property-helper tests below never read, so the struct-field-deletion
        // mutant genus (which cargo-mutants' exclude_re cannot target — see
        // MEMORY) survives on them. This test reads every emitted field so each
        // deletion mutant is killed.
        let t = texture_data("PF_DXT5", vec![]);
        assert_eq!(t.pixel_format, "PF_DXT5");
        assert_eq!(t.size_x, 4);
        assert_eq!(t.size_y, 4);
        assert_eq!(t.mip_count, 1);
        assert_eq!(t.mips.len(), 1);
        let m = &t.mips[0];
        assert_eq!((m.size_x, m.size_y, m.size_z), (4, 4, 1));
    }

    fn bool_prop(name: &str, value: bool) -> Property {
        Property {
            name: name.into(),
            array_index: 0,
            guid: None,
            value: PropertyValue::Bool(value),
        }
    }

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
            property_bool(&texture_data("PF_DXT5", props), "SRGB"),
            Some(false)
        );
    }

    #[test]
    fn property_bool_absent_is_none() {
        assert_eq!(
            property_bool(&texture_data("PF_DXT5", vec![]), "SRGB"),
            None
        );
    }

    #[test]
    fn has_enum_matches_only_the_named_scalar_variant() {
        let props = vec![
            bool_prop("OtherFlag", true),                        // idx 0, wrong name
            enum_prop("CompressionSettings", 1, "TC_Default"),   // right name, idx 1
            enum_prop("CompressionSettings", 0, "TC_Normalmap"), // the real scalar
        ];
        let t = texture_data("PF_DXT5", props);
        assert!(has_enum(&t, "CompressionSettings", "TC_Normalmap"));
        assert!(!has_enum(&t, "CompressionSettings", "TC_Default"));
        assert!(!has_enum(
            &texture_data("PF_DXT5", vec![]),
            "CompressionSettings",
            "TC_Normalmap"
        ));
    }

    #[test]
    fn has_enum_matches_fully_qualified_value() {
        let props = vec![enum_prop(
            "CompressionSettings",
            0,
            "TextureCompressionSettings::TC_Normalmap",
        )];
        let t = texture_data("PF_DXT5", props);
        assert!(has_enum(&t, "CompressionSettings", "TC_Normalmap"));
        let other = texture_data(
            "PF_DXT5",
            vec![enum_prop(
                "CompressionSettings",
                0,
                "TextureCompressionSettings::TC_Default",
            )],
        );
        assert!(!has_enum(&other, "CompressionSettings", "TC_Normalmap"));
    }
}
