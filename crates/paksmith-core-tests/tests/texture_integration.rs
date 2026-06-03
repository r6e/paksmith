//! Phase 3e-8 end-to-end integration: a synthetic cooked `UTexture2D` UAsset
//! is parsed through the full `Package::read_from` → export-class dispatch
//! pipeline into an `Asset::Texture2D`, its mip is resolved through
//! `Package::resolve_bulk_for_export`, and the bytes are handed to the default
//! [`HandlerRegistry`]'s [`PngHandler`] to produce a PNG.
//!
//! This is the cross-crate capstone for the per-handler / decode unit tests in
//! `paksmith-core/src/export/texture.rs` (which pin the BC3 decode against a
//! spec golden vector + an independent oracle, the sRGB-chunk arms, and the
//! PNG round-trip in-source, where `png`/`texture2ddecoder` are available). It
//! owns the surface those can't reach from inside the crate: that
//! `Package::read_from` yields a typed `Asset::Texture2D` reachable through the
//! public API, that its mip resolves to real bytes, and that the registry's
//! default Texture2D handler turns them into a valid PNG.
//!
//! Required feature: `__test_utils` (the `testing::uasset` builders are gated
//! behind it; only this sibling crate enables it).

#![allow(missing_docs)]

use paksmith_core::Asset;
use paksmith_core::asset::Package;
use paksmith_core::export::HandlerRegistry;
use paksmith_core::testing::uasset::{
    build_minimal_with_decodable_texture2d, build_minimal_with_texture2d,
};

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Read the (width, height) from a PNG's IHDR chunk: 8-byte signature, then a
/// 4-byte length + `b"IHDR"`, then width/height as big-endian `u32`s.
fn png_dimensions(png: &[u8]) -> (u32, u32) {
    assert_eq!(&png[0..8], &PNG_SIGNATURE, "PNG signature");
    assert_eq!(&png[12..16], b"IHDR", "first chunk is IHDR");
    let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
    (width, height)
}

/// Parse a package and return its export[1] payload (the `UTexture2D`).
fn parse_texture(pkg: &paksmith_core::testing::uasset::MinimalPackage) -> (Package, Asset) {
    let parsed =
        Package::read_from(&pkg.bytes, None, None, "Game/Tex.uasset").expect("parse texture asset");
    let asset = parsed.payloads[1].clone();
    (parsed, asset)
}

#[test]
fn texture2d_dispatches_to_typed_asset_with_png_handler() {
    let (_parsed, asset) = parse_texture(&build_minimal_with_decodable_texture2d());

    // Typed dispatch: the "Texture2D"-class export routes through the typed
    // reader, not the Generic fallback.
    let Asset::Texture2D(data) = &asset else {
        panic!("expected Asset::Texture2D, got {asset:?}");
    };
    assert_eq!(data.pixel_format, "PF_DXT5");
    assert_eq!((data.size_x, data.size_y), (4, 4));

    // The registry's default handler for a Texture2D is the PNG exporter.
    let registry = HandlerRegistry::all_default_handlers();
    let handler = registry
        .find_handler(&asset)
        .expect("a default handler for Asset::Texture2D");
    assert_eq!(handler.output_extension(), "png");
    assert!(handler.supports(&asset));
}

#[test]
fn texture2d_exports_to_a_valid_png_end_to_end() {
    let (parsed, asset) = parse_texture(&build_minimal_with_decodable_texture2d());

    // Resolve the texture's mip (export index 1) to its real 16 bytes — one
    // 4×4 BC3 block. This fixture has `first_mip_to_serialize == 0`, so the
    // exported mip is `resolved[0]` (the general rule — `bulk[selected_mip_index]`
    // — and the `first_mip_to_serialize > 0` index/dims agreement are pinned
    // in-source in `export/texture.rs`, where the private index fn is visible).
    let resolved = parsed
        .resolve_bulk_for_export(1)
        .expect("the texture's mip FByteBulkData resolves");
    assert_eq!(resolved.len(), 1, "one mip record");
    assert_eq!(resolved[0].bytes.len(), 16, "4×4 BC3 block = 16 bytes");

    let registry = HandlerRegistry::all_default_handlers();
    let handler = registry.find_handler(&asset).expect("Texture2D handler");
    let png = handler
        .export(&asset, Some(&resolved[0]))
        .expect("export produces a PNG");

    // A real, dimensionally-correct PNG (the 16 resolved bytes decode to a 4×4
    // RGBA; the exact pixels are package-buffer bytes and not asserted —
    // decode correctness is pinned in-source against the spec golden vector).
    assert_eq!(png_dimensions(&png), (4, 4));
}

#[test]
fn texture2d_export_errors_cleanly_on_undersized_mip() {
    // The 64×64 fixture's mip is a deliberately fake 8 bytes (sized for the
    // resolver test). Exporting it must fail cleanly in the decoder — not
    // panic, not emit a truncated PNG — proving the handler propagates a real
    // decode error through the full pipeline.
    let (parsed, asset) = parse_texture(&build_minimal_with_texture2d());
    let resolved = parsed.resolve_bulk_for_export(1).expect("resolve mip");
    assert_eq!(resolved[0].bytes.len(), 8);

    let registry = HandlerRegistry::all_default_handlers();
    let handler = registry.find_handler(&asset).expect("Texture2D handler");
    let result = handler.export(&asset, Some(&resolved[0]));
    assert!(
        result.is_err(),
        "8 bytes can't fill a 64×64 BC3 image — expected a clean decode error"
    );
}
