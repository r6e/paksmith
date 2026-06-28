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
/// texture's layer-0 format does), the export carries bulk records (mip bytes
/// for a standard texture, chunk payloads for a virtual texture), **and** the
/// decode fits the per-call RGBA8 cap (`MAX_DECODED_TEXTURE_BYTES`). A standard
/// texture with `bSerializeMipData = false` keeps its mip dimensions but ships no
/// bulk records, and a virtual texture with no chunks likewise has none; both are
/// reported as non-decodable — there is nothing to decode.
///
/// The cap screen keeps classify in agreement with [`decode_texture_mip`]: both
/// go through the one `pixel_format::decoded_rgba_bytes_within_cap` predicate
/// (standard) / `VirtualTextureData::min_level` gate (virtual). For standard
/// textures the screen is exact. For virtual textures it gates on the
/// bitmap-area cap that drives the decode's allocation; the flatten's further
/// per-tile sizing checks (bounding total tile-decode work, and rejecting a
/// per-tile encoded size that overflows) are not mirrored here, so a
/// pathological VT — a tile border wildly disproportionate to its tile size —
/// can still pass classify and then fail the decode, but always cleanly: a
/// bounded `UnsupportedFeature`, never an OOM. This function is **pure and does no I/O**
/// — it never resolves bulk data. It is allocation-cheap: an `O(1)` bulk-presence
/// map lookup, plus, for a virtual texture, a bounded grid scan (`min_level`)
/// over the per-mip tile-offset arrays.
///
/// The bulk-presence check relies on the typed-reader path having populated the
/// package's bulk records, which is guaranteed for any `Package` built via the
/// `read_from*` constructors. A hand-assembled `Package` with `Texture2D`
/// payloads but no `insert_bulk_records` call would classify as `None`.
///
/// # Return value
///
/// `Some(info)` where `info.export_idx` is the index of the texture in
/// `package.payloads` and `info.format_label` is the pixel-format string.
/// `info.mips` lists each decodable mip's `(width, height)`:
///
/// - Standard textures: one entry per serialized mip, in the order
///   [`decode_texture_mip`] indexes them.
/// - Virtual textures: a single entry holding the *flattened* bitmap
///   dimensions the decode produces — the highest-resolution mip level whose
///   RGBA8 image fits the decode cap (`grid_tiles × tile_size`), which can be
///   smaller than the logical `(vt.width, vt.height)`. Legacy (UE4) VTs and
///   VTs with no cap-fitting level are not decodable and yield `None`.
///
/// Returns `None` if no matching (decodable) texture export is found.
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
                // Every parsed VT chunk appends one `FByteBulkData` record
                // (`virtual_textures::read_chunks` pushes unconditionally, once
                // per chunk), so a renderable VT — including all-special-fill
                // (WHITE/BLACK/FLAT) chunks that need no payload bytes — always
                // carries ≥1 bulk record. A VT with zero records therefore has
                // no chunks at all and `flatten_virtual_texture` yields a blank
                // image, so reject it here just like the standard branch.
                if !package.has_bulk_records(export_idx) {
                    return None;
                }
                // `flatten_geometry` is the *same* helper the decode uses to size
                // its output bitmap: it rejects (via `.ok()? → None`) every VT the
                // flatten would reject before producing pixels — legacy (UE4) data
                // (which `flatten` deterministically refuses), a zero tile size, or
                // no cap-fitting `min_level` — and otherwise yields the exact
                // `(width, height)` the decode emits: the flattened bitmap of the
                // highest-resolution level whose RGBA8 image fits the decode cap
                // (`grid_tiles × tile_size`), NOT the logical `(vt.width,
                // vt.height)`. Reporting those bitmap dims keeps the GUI's
                // advertised size in lock-step with the decoded image. (Residual:
                // `flatten`'s further per-tile sizing checks — the decode-work cap
                // and the encoded-size-overflow guard, both keyed on an extreme
                // tile border — are not mirrored here, so a pathological VT can
                // still fail the decode cleanly, never an OOM. See `min_level`.)
                let geom = vt.flatten_geometry().ok()?;
                return Some(TextureInfo {
                    export_idx,
                    mips: vec![(geom.bitmap_w, geom.bitmap_h)],
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

            // Every reported mip index must decode within the cap. `decode_mip`
            // rejects an over-cap mip with `DecodedTextureBytesExceeded`, and the
            // GUI's mip picker indexes this list 1:1 into `data.mips`, so a single
            // over-cap mip cannot be silently dropped without shifting the indices
            // — reject the whole export instead, via the same
            // `decoded_rgba_bytes_within_cap` predicate `decode_mip` enforces.
            // (Reader-parsed mips are each ≤ MAX_TEXTURE_DIMENSION, so
            // width·height·4 ≤ the cap and this never fires for a parsed asset; it
            // guards hand-assembled or future uncapped inputs, keeping
            // classify⟂decode agreement explicit.)
            if !data
                .mips
                .iter()
                .all(|m| pixel_format::decoded_rgba_bytes_within_cap(m.size_x, m.size_y).is_some())
            {
                return None;
            }

            // Every reported mip is decodable: `read_mip_records` gates the
            // per-mip `FByteBulkData` push on the texture-level
            // `serialize_mip_data` flag, so the bulk-record vector is either
            // empty or exactly `data.mips.len()` (never a partial subset); the
            // `has_bulk_records` check above already ruled out the empty case;
            // and `resolve_bulk_for_export` is count-preserving (one `BulkData`
            // per record, errors propagate rather than dropping entries). So
            // `decode_texture_mip` can resolve every index in this list —
            // truncating the list to the bulk-record count would be a no-op.
            // The `bulk_data[idx].len() == data.mips.len()` invariant is pinned
            // by `decodable_texture_has_one_bulk_record_per_mip`.
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
/// Virtual textures expose a single mip (the one entry reported by
/// [`classify_texture`]) and are flattened at the highest-resolution mip level
/// whose RGBA8 bitmap fits the decode cap — which may be coarser than full
/// resolution — so `mip_index` must be `0`; any other index is rejected as
/// caller misuse rather than silently ignored, keeping the bounds contract
/// consistent with the standard-texture path. The decoded dimensions are those
/// [`classify_texture`] reported in `info.mips[0]` (the flattened bitmap size),
/// not the logical `(vt.width, vt.height)`.
///
/// # Errors
///
/// - [`PaksmithError::InvalidArgument`] if `export_idx` is out of range or does
///   not point to a `Texture2DData` export, if `mip_index` is out of range for
///   a standard texture's serialized mip list, or if `mip_index != 0` for a
///   virtual texture. These signal caller misuse and are checked before any
///   bulk I/O is attempted, so a misuse error is never masked by a
///   bulk-resolution fault.
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

    // Validate `mip_index` BEFORE resolving bulk data. `resolve_bulk_for_export`
    // can perform `.ubulk` I/O (and surface I/O faults), so caller misuse — a
    // non-zero mip for a virtual texture, or an out-of-range standard mip — is
    // rejected up front, cheaply and deterministically, never doing needless I/O
    // nor letting a bulk-resolution error mask the intended `InvalidArgument`.

    // Virtual texture path: flatten layer 0. A VT exposes a single mip (index
    // 0), so reject any other index as caller misuse rather than silently
    // ignoring it — matching the standard branch's bounds contract below.
    if let Some(vt) = data.virtual_texture.as_deref() {
        if mip_index != 0 {
            return Err(PaksmithError::InvalidArgument {
                arg: "mip_index",
                reason: format!("virtual textures expose a single mip (index 0); got {mip_index}"),
            });
        }
        let bulk = package.resolve_bulk_for_export(export_idx)?;
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
    let bulk = package.resolve_bulk_for_export(export_idx)?;
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
    // Thread the export/mip identity into the decode context so a codec error
    // (unsupported pixel format, size mismatch, over-cap dimensions) names which
    // export and mip failed instead of the opaque "<texture mip>" placeholder —
    // this is a public API, so its errors surface directly to callers.
    let decoded = decode_mip(
        &format,
        &bulk_record.bytes,
        mip_record.size_x,
        mip_record.size_y,
        is_normal_map,
        &format!("texture export {export_idx} mip {mip_index}"),
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
    use crate::asset::exports::texture::virtual_textures::{TileOffsetData, VirtualTextureData};
    use crate::asset::package::Package;
    use crate::testing::uasset::{
        build_minimal_ue4_27, build_minimal_with_decodable_texture2d, build_minimal_with_texture2d,
    };

    /// The sole `Texture2DData` payload of a fixture-built package, mutably.
    fn sole_texture2d_mut(pkg: &mut Package) -> &mut Texture2DData {
        pkg.payloads
            .iter_mut()
            .find_map(|a| match a {
                Asset::Texture2D(d) => Some(d),
                _ => None,
            })
            .expect("fixture must contain a Texture2D")
    }

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
    fn decodable_texture_has_one_bulk_record_per_mip() {
        // Invariant that `classify_texture` reports only decodable mips and that
        // `decode_texture_mip` can resolve every reported index: a decodable
        // standard texture registers exactly one bulk record per serialized mip.
        // `read_mip_records` gates the per-mip bulk push on the texture-level
        // `serialize_mip_data` flag (all-or-nothing), so the record vector is
        // never a partial subset of `mips`. If a future parser change broke that,
        // the mip picker would offer mips `decode_texture_mip` cannot decode —
        // this pin fails first.
        let fixture = build_minimal_with_decodable_texture2d();
        let pkg = parse_pkg(&fixture.bytes);
        let idx = classify_texture(&pkg).expect("must classify").export_idx;

        let Asset::Texture2D(data) = &pkg.payloads[idx] else {
            panic!("export_idx must point at a Texture2D");
        };
        let raw_record_count = pkg
            .bulk_data
            .get(&idx)
            .map_or(0, |(records, _)| records.len());

        assert_eq!(
            raw_record_count,
            data.mips.len(),
            "a decodable texture must register exactly one bulk record per mip"
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

    #[test]
    fn classify_texture_standard_over_cap_mip_is_none() {
        // A standard texture whose mip would decode past MAX_DECODED_TEXTURE_BYTES
        // must not classify as decodable: `decode_mip` rejects it with
        // DecodedTextureBytesExceeded, so offering a Texture view would strand the
        // GUI on a guaranteed decode failure. Reader-parsed mips can't reach this
        // (each dim ≤ MAX_TEXTURE_DIMENSION), so inject over-cap dims directly
        // into a parsed fixture's payload. 20000×20000×4 ≈ 1.6 GiB > 1 GiB cap.
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        sole_texture2d_mut(&mut pkg).mips = vec![mip_data(20_000, 20_000)];

        assert!(
            classify_texture(&pkg).is_none(),
            "an over-cap standard mip must yield None"
        );
    }

    #[test]
    fn classify_texture_standard_mip_exactly_at_cap_is_some() {
        // The cap is inclusive (`<=`): a mip whose decode is EXACTLY
        // MAX_DECODED_TEXTURE_BYTES (16384×16384×4 == 1 GiB) must classify as
        // decodable. This pins the boundary — a `<=` → `<` mutant in the shared
        // `decoded_rgba_bytes_within_cap` predicate would wrongly reject it. (Pure
        // classify check; nothing decodes, so no 1 GiB allocation occurs.)
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        sole_texture2d_mut(&mut pkg).mips = vec![mip_data(16_384, 16_384)];

        assert!(
            classify_texture(&pkg).is_some(),
            "a mip exactly at the cap must classify as Some"
        );
    }

    // ── classify_texture: virtual-texture branch ─────────────────────────────

    /// A minimal decodable `VirtualTextureData` whose layer-0 format is `layer0`
    /// and whose full-resolution dimensions are 8×8.
    ///
    /// Sets exactly the fields `classify_texture` reads: `width`/`height` (the
    /// reported single mip) and `layer_types` (decodability), plus a one-level
    /// tile grid (`num_mips`/`tile_size`/`tile_offset_data`) so that `min_level`
    /// finds a cap-fitting level and the VT classifies as decodable — without it,
    /// the (now `min_level`-gated) classifier would reject every fixture VT. Each
    /// emitted field is pinned by `vt_with_layer0_helper_pins_fields` so the
    /// struct-field-deletion mutant genus is killed (see MEMORY).
    fn vt_with_layer0(layer0: &str) -> VirtualTextureData {
        VirtualTextureData {
            // Logical full-res (16×16) deliberately differs from the flattened
            // min_level bitmap (grid 2×2 tiles × tile_size 4 = 8×8) so a dims test
            // that asserts the bitmap size fails against any code that reports the
            // logical `(width, height)` instead. (For a UE5.0+ VT `width`/`height`
            // drive only the legacy `width_in_tiles` path, unused here, so a value
            // independent of the grid is well-formed.)
            width: 16,
            height: 16,
            layer_types: vec![layer0.to_string()],
            num_mips: 1,
            tile_size: 4,
            tile_offset_data: vec![TileOffsetData {
                width: 2,
                height: 2,
                max_address: 1,
                addresses: vec![0],
                offsets: vec![0],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn vt_with_layer0_helper_pins_fields() {
        // Read every field the helper sets so a field-deletion mutant (value →
        // Default) fails an assert; `min_level` only observes `tile_size` and the
        // grid's `width`/`height`, so those need an explicit value check that
        // their small magnitude (any positive value fits the cap) can't provide.
        let vt = vt_with_layer0("PF_DXT1");
        assert_eq!((vt.width, vt.height), (16, 16));
        assert_eq!(vt.layer_types, vec!["PF_DXT1".to_string()]);
        assert_eq!(vt.num_mips, 1);
        assert_eq!(vt.tile_size, 4);
        assert_eq!(vt.tile_offset_data.len(), 1);
        let tod = &vt.tile_offset_data[0];
        assert_eq!((tod.width, tod.height, tod.max_address), (2, 2, 1));
        assert_eq!(
            (tod.addresses.as_slice(), tod.offsets.as_slice()),
            (&[0][..], &[0][..])
        );
        assert_eq!(
            vt.min_level(),
            Some(0),
            "the helper grid must yield a cap-fitting level so the VT classifies as decodable"
        );
    }

    /// Parse the decodable fixture, then promote its `Texture2D` payload to a
    /// virtual texture carrying `layer0` as its sole layer format.
    fn pkg_with_virtual_texture(layer0: &str) -> Package {
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        sole_texture2d_mut(&mut pkg).virtual_texture = Some(Box::new(vt_with_layer0(layer0)));
        pkg
    }

    #[test]
    fn classify_texture_virtual_decodable_layer0_is_some() {
        let pkg = pkg_with_virtual_texture("PF_DXT1");
        let info =
            classify_texture(&pkg).expect("a VT with a decodable layer-0 must classify as Some");
        // The fixture's logical dims are 16×16 but the flattened min_level bitmap
        // is grid(2×2) × tile_size(4) = 8×8; classify must report the *bitmap*
        // dims the decode produces, NOT the logical `(vt.width, vt.height)`. This
        // fails against the prior `vec![(vt.width, vt.height)]` behavior.
        assert_eq!(
            info.mips,
            vec![(8, 8)],
            "a virtual texture reports its flattened min_level bitmap dims as the single mip"
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

    #[test]
    fn classify_texture_virtual_no_bulk_records_is_none() {
        // A VT with a decodable layer-0 format but zero bulk records has no
        // chunks, so `flatten_virtual_texture` would yield a blank image. The
        // VT branch must reject it (mirroring the standard-texture branch), not
        // offer a Texture tab that decodes to nothing.
        let mut pkg = pkg_with_virtual_texture("PF_DXT1");
        let export_idx = classify_texture(&pkg)
            .expect("a VT with bulk must classify before records are dropped")
            .export_idx;
        pkg.insert_bulk_records_for_test(export_idx, Vec::new())
            .expect("dropping bulk records must succeed");

        assert!(
            classify_texture(&pkg).is_none(),
            "a chunk-less virtual texture (no bulk records) must yield None"
        );
    }

    #[test]
    fn classify_texture_virtual_no_cap_fitting_level_is_none() {
        // A VT whose every tile-grid level decodes past the cap has no fitting
        // level (`min_level` is None), so `flatten` would error rather than
        // allocate. classify must reject it via the shared `min_level` gate
        // instead of offering an undecodable Texture view — the virtual-texture
        // analogue of `classify_texture_standard_over_cap_mip_is_none`. A naive
        // `vt.width × vt.height ≤ cap` check would instead WRONGLY reject a huge
        // VT that decodes fine at a lower level, which is why the gate is
        // `min_level`, not the logical dimensions.
        let mut pkg = pkg_with_virtual_texture("PF_DXT1");
        let vt = sole_texture2d_mut(&mut pkg)
            .virtual_texture
            .as_deref_mut()
            .expect("pkg_with_virtual_texture promoted a VT");
        // tile_size 256, one 50000×50000-tile level → bitmap ≫ 1 GiB at every
        // level → `min_level` is None.
        vt.num_mips = 1;
        vt.tile_size = 256;
        vt.tile_offset_data = vec![TileOffsetData {
            width: 50_000,
            height: 50_000,
            max_address: 1,
            addresses: vec![0],
            offsets: vec![0],
        }];

        assert!(
            classify_texture(&pkg).is_none(),
            "a virtual texture with no cap-fitting level must yield None"
        );
    }

    #[test]
    fn classify_texture_legacy_virtual_is_none() {
        // `flatten_virtual_texture` deterministically rejects legacy (UE4) VTs
        // (they are not yet renderable). classify must not offer a Texture view
        // for one — otherwise the GUI promotes a tab whose decode always fails.
        // A non-empty `tile_offset_in_chunk` marks the VT as legacy
        // (`is_legacy_data`), which `flatten_geometry` refuses up front.
        let mut pkg = pkg_with_virtual_texture("PF_DXT1");
        assert!(
            classify_texture(&pkg).is_some(),
            "the UE5.0+ fixture VT must classify before being made legacy"
        );
        sole_texture2d_mut(&mut pkg)
            .virtual_texture
            .as_deref_mut()
            .expect("pkg_with_virtual_texture promoted a VT")
            .tile_offset_in_chunk = vec![0];

        assert!(
            classify_texture(&pkg).is_none(),
            "a legacy (UE4) virtual texture must yield None — its decode always fails"
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
    fn decode_texture_mip_virtual_nonzero_mip_is_invalid_argument() {
        // A virtual texture exposes a single mip (index 0). A non-zero index is
        // caller misuse and must be rejected before flatten, not silently
        // ignored — keeping the bounds contract consistent with standard
        // textures. Pins the `mip_index != 0` guard (the `!=` -> `==` mutant
        // would reject the valid index 0 and accept everything else).
        let pkg = pkg_with_virtual_texture("PF_DXT1");
        let info = classify_texture(&pkg).expect("VT must classify");
        let err = decode_texture_mip(&pkg, info.export_idx, 1)
            .expect_err("mip_index != 0 on a virtual texture must return Err");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "mip_index",
                    ..
                }
            ),
            "non-zero VT mip_index is caller misuse → InvalidArgument(mip_index), got {err:?}"
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

    /// A streaming-tier (`FLAG_PAYLOAD_IN_SEPARATE_FILE = 0x100`) bulk record
    /// whose `.ubulk` companion the stub loaders can't find, so
    /// `resolve_bulk_for_export` fails with `MissingCompanionFile`. Mirrors the
    /// seam in `package.rs::resolve_bulk_for_export_propagates_per_record_error`.
    fn failing_streaming_bulk_record() -> crate::asset::bulk_data::FByteBulkData {
        crate::asset::bulk_data::FByteBulkData {
            flags: crate::asset::bulk_data::BulkDataFlags::from(0x0000_0100u32),
            element_count: 8,
            size_on_disk: 8,
            offset_in_file: 0,
        }
    }

    /// Replace an export's bulk records with a single streaming record whose
    /// `.ubulk` companion is missing, so that bulk resolution now fails. Each
    /// caller asserts that precondition *inline* in its own body rather than via
    /// a wrapper: the only effect of this helper is the `pkg` mutation, which is
    /// invisible to a caller that just reads `decode_texture_mip`'s error — so an
    /// all-in-one inject-and-assert helper (or any second assert-only helper)
    /// could be `cargo-mutants`-replaced with `()` and survive. The inline assert
    /// observes the injection and kills that mutant (see the test-helper-mutation
    /// note in MEMORY); failures aren't cached, see the sibling
    /// `resolve_bulk_for_export_propagates_per_record_error`.
    fn inject_failing_bulk(pkg: &mut Package, export_idx: usize) {
        pkg.insert_bulk_records_for_test(export_idx, vec![failing_streaming_bulk_record()])
            .expect("injecting a streaming bulk record must succeed");
    }

    #[test]
    fn decode_texture_mip_out_of_range_validated_before_bulk_resolution() {
        // Ordering guard: `mip_index` is validated BEFORE bulk data is resolved,
        // so caller misuse is rejected deterministically even when bulk
        // resolution would fail (and do `.ubulk` I/O). Replace the texture's bulk
        // records with one whose companion file is missing, then request an
        // out-of-range mip: the result must be `InvalidArgument(mip_index)`, not
        // the `MissingCompanionFile` fault the old resolve-bulk-first order
        // surfaced.
        let fixture = build_minimal_with_decodable_texture2d();
        let mut pkg = parse_pkg(&fixture.bytes);
        let info = classify_texture(&pkg).expect("must classify");
        inject_failing_bulk(&mut pkg, info.export_idx);
        // Inline precondition (NOT in a helper — see `inject_failing_bulk`): the
        // injected record must make resolution fail, else this ordering test is
        // vacuous (the assert below would pass even under resolve-first order).
        assert!(
            pkg.resolve_bulk_for_export(info.export_idx).is_err(),
            "precondition: the injected streaming record must make bulk resolution fail"
        );

        let err = decode_texture_mip(&pkg, info.export_idx, info.mips.len() + 99)
            .expect_err("out-of-range mip_index must return Err even when bulk would fail");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "mip_index",
                    ..
                }
            ),
            "mip_index must be validated before bulk resolution → InvalidArgument(mip_index), \
             got {err:?}"
        );
    }

    #[test]
    fn decode_texture_mip_virtual_nonzero_validated_before_bulk_resolution() {
        // Same ordering guard for the virtual-texture branch: a non-zero mip
        // index is rejected before bulk resolution, so a failing `.ubulk` resolve
        // cannot mask the `InvalidArgument(mip_index)`.
        let mut pkg = pkg_with_virtual_texture("PF_DXT1");
        let info = classify_texture(&pkg).expect("VT must classify");
        inject_failing_bulk(&mut pkg, info.export_idx);
        // Inline precondition (NOT in a helper — see `inject_failing_bulk`): the
        // injected record must make resolution fail, else this ordering test is
        // vacuous (the assert below would pass even under resolve-first order).
        assert!(
            pkg.resolve_bulk_for_export(info.export_idx).is_err(),
            "precondition: the injected streaming record must make bulk resolution fail"
        );

        let err = decode_texture_mip(&pkg, info.export_idx, 1)
            .expect_err("non-zero VT mip_index must return Err even when bulk would fail");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidArgument {
                    arg: "mip_index",
                    ..
                }
            ),
            "VT mip_index must be validated before bulk resolution → InvalidArgument(mip_index), \
             got {err:?}"
        );
    }

    #[test]
    fn decode_texture_mip_decode_error_context_names_export_and_mip() {
        // `build_minimal_with_texture2d` is a 64×64 PF_DXT5 whose single inline
        // mip resolves to only 8 bytes (a deliberately fake mip, not a real
        // 4096-byte DXT5 block), so the bulk-resolve and range guards pass and
        // the failure lands in the decode layer (size mismatch). The error
        // context must name the failing export and mip (C20) instead of the
        // opaque "<texture mip>" placeholder, so a caller can tell which mip of
        // which export the public `decode_texture_mip` rejected.
        let fixture = build_minimal_with_texture2d();
        let pkg = parse_pkg(&fixture.bytes);
        let info = classify_texture(&pkg)
            .expect("a 64×64 PF_DXT5 with a bulk record present must classify");

        let err = decode_texture_mip(&pkg, info.export_idx, 0).expect_err(
            "a 64×64 texture whose mip resolves to 8 bytes must fail the decode size check",
        );
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("texture export {}", info.export_idx)),
            "decode error context must name the failing export; got: {msg}"
        );
        assert!(
            msg.contains("mip 0"),
            "decode error context must name the failing mip; got: {msg}"
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
