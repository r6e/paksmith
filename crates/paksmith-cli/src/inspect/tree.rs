//! Human-readable tree renderer for `paksmith inspect --format table`.
//!
//! This is a presentation-only surface: it walks the already-parsed
//! [`Package`] and writes an indented summary + per-export property tree
//! to a `Write` sink. The compact formatters ([`fmt_vector`],
//! [`fmt_color`], [`fmt_linear_color`]) live HERE and HERE ONLY — the JSON
//! emit path never calls them, so the two output shapes can diverge
//! without coupling. Core is untouched (read-only).

use std::io::{self, Write};

use paksmith_core::PackageIndex;
use paksmith_core::asset::Asset;
use paksmith_core::asset::Package;
use paksmith_core::asset::property::PropertyBag;
use paksmith_core::asset::property::primitives::{MapEntry, Property, PropertyValue};
use paksmith_core::asset::structs::TypedStructValue;
use paksmith_core::asset::structs::color::{FColor, FLinearColor};
use paksmith_core::asset::structs::vector::FVector;

/// Two-space indent unit for nested property rows.
const INDENT: &str = "  ";

/// Compact one-line form of an [`FVector`]: `[x, y, z]`.
///
/// Uses `{}` (not `{:?}`) so whole floats render without a trailing
/// `.0` — `1.0` → `1`, `2.5` → `2.5`, `-3.0` → `-3`. This is a
/// human-display form, not a round-trippable one (the JSON path keeps
/// full fidelity).
pub(crate) fn fmt_vector(v: &FVector) -> String {
    format!("[{}, {}, {}]", v.x, v.y, v.z)
}

/// 8-bit `FColor` → `#RRGGBB` (or `#RRGGBBAA` when alpha != 255).
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "by-ref signature is pinned by the Task-5 brief and kept uniform with \
              fmt_vector / fmt_linear_color, whose larger structs warrant by-ref"
)]
pub(crate) fn fmt_color(c: &FColor) -> String {
    if c.a == 0xFF {
        format!("#{:02X}{:02X}{:02X}", c.r, c.g, c.b)
    } else {
        format!("#{:02X}{:02X}{:02X}{:02X}", c.r, c.g, c.b, c.a)
    }
}

/// Float `FLinearColor` → `#RRGGBB(AA)` via 0..=255 quantization.
pub(crate) fn fmt_linear_color(c: &FLinearColor) -> String {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "value is clamped to 0.0..=1.0 before scaling; result fits u8 and is non-negative. \
                  NaN is not removed by clamp (NaN propagates) but saturates to 0 via `as u8`, \
                  which is safe and non-panicking"
    )]
    let q = |f: f32| (f.clamp(0.0, 1.0) * 255.0).round() as u8;
    fmt_color(&FColor {
        r: q(c.r),
        g: q(c.g),
        b: q(c.b),
        a: q(c.a),
    })
}

use sink::TreeOut;

mod sink {
    use std::io::{self, Write};

    use crate::output::sanitize_for_display;

    /// The tree's only sink. Each line is sanitized whole, so an archive
    /// name's own `\n` becomes U+FFFD instead of forging a line; the newline
    /// is added after. It does not implement `Write` and its writer is
    /// private to this module, so the render functions, which only ever hold
    /// a `TreeOut`, cannot write past it.
    pub(super) struct TreeOut<'w>(&'w mut dyn Write);

    impl<'w> TreeOut<'w> {
        pub(super) fn new(w: &'w mut dyn Write) -> Self {
            Self(w)
        }

        pub(super) fn line(&mut self, args: std::fmt::Arguments<'_>) -> io::Result<()> {
            writeln!(self.0, "{}", sanitize_for_display(&args.to_string()))
        }
    }
}

/// Render `pkg` as a human tree to `w`.
///
/// Emits a one-line header summary (engine version, table counts, package
/// GUID) followed by per-export blocks. When `export` is `Some(idx)`, only
/// that single export's block is rendered; `None` renders every export.
///
/// Each export block is a header line (`[idx] <object_name> : <class>`), a
/// payload-shape line, and — for a decoded property tree — an indented
/// property listing applying the compact typed formatters.
pub(crate) fn render(pkg: &Package, export: Option<usize>, w: &mut dyn Write) -> io::Result<()> {
    let out = &mut TreeOut::new(w);
    let summary = &pkg.summary;
    out.line(format_args!(
        "{} | engine {} | names {} imports {} exports {} | guid {}",
        pkg.asset_path,
        summary.saved_by_engine_version,
        pkg.names.names.len(),
        pkg.imports.imports.len(),
        pkg.exports.exports.len(),
        summary.guid,
    ))?;

    let count = pkg.exports.exports.len();
    match export {
        Some(idx) => render_export(pkg, idx, out)?,
        None => {
            for idx in 0..count {
                render_export(pkg, idx, out)?;
            }
        }
    }
    Ok(())
}

/// Render a single export's block: header line, payload-shape line, and the
/// property tree (for the decoded `Tree` case).
fn render_export(pkg: &Package, idx: usize, out: &mut TreeOut<'_>) -> io::Result<()> {
    let Some(export) = pkg.exports.exports.get(idx) else {
        // Defensive: an out-of-range index is rejected upstream by
        // `select::resolve_export`, but render must never panic.
        return Ok(());
    };
    let object_name = pkg
        .names
        .resolve(export.object_name, export.object_name_number);
    let class = class_name(pkg, export.class_index);
    out.line(format_args!("[{idx}] {object_name} : {class}"))?;

    match pkg.payloads.get(idx) {
        Some(Asset::Generic(bag)) => render_bag(bag, out),
        Some(other) => {
            // Typed variants (DataTable, Texture2D, …): name the variant and
            // render its property bag when it carries one. Phase 3 ships only
            // `Generic` for the inspect fixture; the typed arms are forward
            // coverage exercised by the formatter unit tests.
            out.line(format_args!("{INDENT}{}", typed_variant_label(other)))?;
            if let Some(bag) = typed_variant_bag(other) {
                render_bag(bag, out)?;
            }
            Ok(())
        }
        None => Ok(()),
    }
}

/// Render the payload-shape line and (for `Tree`) the property listing.
fn render_bag(bag: &PropertyBag, out: &mut TreeOut<'_>) -> io::Result<()> {
    match bag {
        PropertyBag::Opaque { bytes } => {
            out.line(format_args!("{INDENT}opaque ({} bytes)", bytes.len()))
        }
        PropertyBag::Tree { properties } => {
            out.line(format_args!(
                "{INDENT}tree ({} properties)",
                properties.len()
            ))?;
            render_properties(properties, 2, out)
        }
        // `PropertyBag` is #[non_exhaustive].
        _ => out.line(format_args!("{INDENT}<unknown payload>")),
    }
}

/// Render a flat list of properties at `depth` indent levels.
fn render_properties(
    properties: &[Property],
    depth: usize,
    out: &mut TreeOut<'_>,
) -> io::Result<()> {
    for prop in properties {
        render_property(prop, depth, out)?;
    }
    Ok(())
}

/// Render one property: `<name> = <value>` (scalars inline) or a `<name>:`
/// header followed by indented children (containers / structs).
fn render_property(prop: &Property, depth: usize, out: &mut TreeOut<'_>) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    let name = prop.name();
    match &prop.value {
        PropertyValue::Struct {
            struct_name,
            properties,
        } => {
            out.line(format_args!("{pad}{name} ({struct_name}):"))?;
            render_properties(properties, depth + 1, out)
        }
        PropertyValue::Array {
            inner_type,
            elements,
        }
        | PropertyValue::Set {
            inner_type,
            elements,
        } => {
            out.line(format_args!(
                "{pad}{name} [{inner_type}] ({} items):",
                elements.len()
            ))?;
            render_values(elements, depth + 1, out)
        }
        PropertyValue::Map { entries, .. } => {
            out.line(format_args!("{pad}{name} ({} entries):", entries.len()))?;
            render_map_entries(entries, depth + 1, out)
        }
        other => out.line(format_args!("{pad}{name} = {}", scalar(other))),
    }
}

/// Render array/set elements (no per-element name).
fn render_values(values: &[PropertyValue], depth: usize, out: &mut TreeOut<'_>) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    for value in values {
        match value {
            PropertyValue::Struct {
                struct_name,
                properties,
            } => {
                out.line(format_args!("{pad}({struct_name}):"))?;
                render_properties(properties, depth + 1, out)?;
            }
            other => out.line(format_args!("{pad}- {}", scalar(other)))?,
        }
    }
    Ok(())
}

/// Render map key/value entries.
fn render_map_entries(entries: &[MapEntry], depth: usize, out: &mut TreeOut<'_>) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    for entry in entries {
        out.line(format_args!(
            "{pad}{} => {}",
            scalar(&entry.key),
            scalar(&entry.value)
        ))?;
    }
    Ok(())
}

/// One-line scalar rendering of a property value, applying the compact
/// typed formatters for vector/color typed structs and resolving enum /
/// byte / name display strings. Container variants (handled by the
/// caller) fall back to a terse placeholder if they reach here (e.g. as a
/// map key/value or array element).
fn scalar(value: &PropertyValue) -> String {
    match value {
        PropertyValue::Bool(b) => b.to_string(),
        PropertyValue::Byte(b) => b.to_string(),
        PropertyValue::Int8(n) => n.to_string(),
        PropertyValue::Int16(n) => n.to_string(),
        PropertyValue::Int(n) => n.to_string(),
        PropertyValue::Int64(n) => n.to_string(),
        PropertyValue::UInt16(n) => n.to_string(),
        PropertyValue::UInt32(n) => n.to_string(),
        PropertyValue::UInt64(n) => n.to_string(),
        PropertyValue::Float(f) => f.to_string(),
        PropertyValue::Double(f) => f.to_string(),
        PropertyValue::Str(s) => format!("{s:?}"),
        PropertyValue::Name(n) => n.to_string(),
        PropertyValue::Enum { type_name, value } => {
            if type_name.is_empty() {
                value.to_string()
            } else {
                format!("{type_name}::{value}")
            }
        }
        PropertyValue::Text(_) => "<text>".to_string(),
        PropertyValue::Unknown {
            type_name,
            skipped_bytes,
        } => format!("<{type_name}: {skipped_bytes} bytes>"),
        PropertyValue::TypedStruct(boxed) => typed_struct(boxed),
        PropertyValue::SoftObjectPath {
            asset_path,
            sub_path,
        }
        | PropertyValue::SoftClassPath {
            asset_path,
            sub_path,
        } => {
            if sub_path.is_empty() {
                asset_path.clone()
            } else {
                format!("{asset_path}:{sub_path}")
            }
        }
        PropertyValue::Object { name, .. } if name.is_empty() => "null".to_string(),
        PropertyValue::Object { name, .. } => name.to_string(),
        // Container variants are normally handled by `render_property`; if one
        // appears nested as a key/value/element, name it terselessly.
        PropertyValue::Array { inner_type, .. } | PropertyValue::Set { inner_type, .. } => {
            format!("[{inner_type} …]")
        }
        PropertyValue::Struct { struct_name, .. } => format!("({struct_name} …)"),
        PropertyValue::Map { .. } => "{…}".to_string(),
        // `PropertyValue` is #[non_exhaustive].
        _ => "<?>".to_string(),
    }
}

/// Compact display of a typed engine-struct value, applying the dedicated
/// vector / color formatters where available.
fn typed_struct(value: &TypedStructValue) -> String {
    match value {
        TypedStructValue::Vector(v) => fmt_vector(v),
        TypedStructValue::Color(c) => fmt_color(c),
        TypedStructValue::LinearColor(c) => fmt_linear_color(c),
        // Other typed structs (Rotator, Quat, Box, Transform, …) have no
        // dedicated compact form yet; name the variant.
        other => format!("<{}>", typed_struct_label(other)),
    }
}

/// Bare label for a typed-struct variant (the wire-format struct name
/// without the `F` prefix), for the fallback compact form.
fn typed_struct_label(value: &TypedStructValue) -> &'static str {
    match value {
        TypedStructValue::Vector(_) => "Vector",
        TypedStructValue::Vector2D(_) => "Vector2D",
        TypedStructValue::Vector4(_) => "Vector4",
        TypedStructValue::Rotator(_) => "Rotator",
        TypedStructValue::Quat(_) => "Quat",
        TypedStructValue::Color(_) => "Color",
        TypedStructValue::LinearColor(_) => "LinearColor",
        TypedStructValue::Box(_) => "Box",
        TypedStructValue::Box2D(_) => "Box2D",
        TypedStructValue::Transform(_) => "Transform",
        TypedStructValue::BoxSphereBounds(_) => "BoxSphereBounds",
        // `TypedStructValue` is #[non_exhaustive].
        _ => "?",
    }
}

/// Human label for a non-`Generic` [`Asset`] variant's payload-shape line.
/// The `Texture2D` variant is shared by the multidim texture classes
/// (#648), so its label consults `kind` — the engine class name, matching
/// the export's class row.
fn typed_variant_label(asset: &Asset) -> &'static str {
    use paksmith_core::asset::TextureKind;
    match asset {
        Asset::Generic(_) => "generic",
        Asset::DataTable(_) => "DataTable",
        Asset::Texture2D(t) => match t.kind {
            TextureKind::Cube => "TextureCube",
            TextureKind::Array => "Texture2DArray",
            TextureKind::Volume => "VolumeTexture",
            // TwoD, plus any future #[non_exhaustive] TextureKind variant
            // until this label learns its name.
            _ => "Texture2D",
        },
        Asset::SoundWave(_) => "SoundWave",
        Asset::StaticMesh(_) => "StaticMesh",
        Asset::SkeletalMesh(_) => "SkeletalMesh",
        // `Asset` is #[non_exhaustive].
        _ => "typed",
    }
}

/// The class-level / segment-1 property bag of a typed [`Asset`] variant,
/// when it carries one (so its tagged properties render in the tree).
fn typed_variant_bag(asset: &Asset) -> Option<&PropertyBag> {
    match asset {
        Asset::Generic(bag) => Some(bag),
        Asset::DataTable(d) => Some(&d.class_properties),
        Asset::Texture2D(t) => Some(&t.properties),
        Asset::SoundWave(s) => Some(&s.properties),
        Asset::StaticMesh(m) => Some(&m.properties),
        Asset::SkeletalMesh(m) => Some(&m.properties),
        _ => None,
    }
}

/// Resolve an export's `class_index` [`PackageIndex`] to a display class
/// name. `Null` (a script-class export) renders as `Class`; an import /
/// export reference resolves through the corresponding table; an
/// out-of-range index falls back to a terse marker rather than panicking.
fn class_name(pkg: &Package, class_index: PackageIndex) -> String {
    match class_index {
        PackageIndex::Null => "Class".to_string(),
        PackageIndex::Import(n) => pkg.imports.imports.get(n as usize).map_or_else(
            || format!("<import {n}?>"),
            |imp| pkg.names.resolve(imp.object_name, imp.object_name_number),
        ),
        PackageIndex::Export(n) => pkg.exports.exports.get(n as usize).map_or_else(
            || format!("<export {n}?>"),
            |exp| pkg.names.resolve(exp.object_name, exp.object_name_number),
        ),
        // `PackageIndex` is #[non_exhaustive].
        _ => "<class?>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::is_terminal_hazard;

    /// An object reference renders as its name, or `null` when it has none.
    #[test]
    fn scalar_renders_an_object_reference_by_name() {
        let object = |name: &str| PropertyValue::Object {
            kind: PackageIndex::Null,
            name: name.into(),
        };
        assert_eq!(scalar(&object("/Game/Mesh.Mesh")), "/Game/Mesh.Mesh");
        assert_eq!(scalar(&object("")), "null");
    }

    #[test]
    fn typed_variant_label_consults_texture_kind() {
        use paksmith_core::asset::{Texture2DData, TextureKind};
        // The shared Asset::Texture2D variant carries all four texture
        // classes (#648); the payload-shape label must show the engine
        // class, matching the export's class row.
        for (kind, label) in [
            (TextureKind::TwoD, "Texture2D"),
            (TextureKind::Cube, "TextureCube"),
            (TextureKind::Array, "Texture2DArray"),
            (TextureKind::Volume, "VolumeTexture"),
        ] {
            let mut data = Texture2DData::empty();
            data.kind = kind;
            assert_eq!(typed_variant_label(&Asset::Texture2D(data)), label);
        }
    }

    #[test]
    fn typed_variant_label_pins_every_non_texture_arm() {
        // Each remaining arm gets its own distinct label — a deleted arm
        // would fall to the non_exhaustive wildcard's "typed" and fail
        // here. (The Texture2D arm's kinds are pinned above.)
        use paksmith_core::asset::property::bag::PropertyBag;
        use paksmith_core::asset::{
            DataTableData, SkeletalMeshData, SoundWaveData, StaticMeshData,
        };
        assert_eq!(
            typed_variant_label(&Asset::Generic(PropertyBag::opaque(Vec::new()))),
            "generic"
        );
        assert_eq!(
            typed_variant_label(&Asset::DataTable(DataTableData::empty())),
            "DataTable"
        );
        assert_eq!(
            typed_variant_label(&Asset::SoundWave(SoundWaveData::empty())),
            "SoundWave"
        );
        assert_eq!(
            typed_variant_label(&Asset::StaticMesh(StaticMeshData::empty())),
            "StaticMesh"
        );
        assert_eq!(
            typed_variant_label(&Asset::SkeletalMesh(SkeletalMeshData::empty())),
            "SkeletalMesh"
        );
    }

    #[test]
    fn vector_compact() {
        assert_eq!(
            fmt_vector(&FVector {
                x: 1.0,
                y: 2.5,
                z: -3.0
            }),
            "[1, 2.5, -3]"
        );
    }

    #[test]
    fn color_opaque_is_rrggbb() {
        assert_eq!(
            fmt_color(&FColor {
                r: 0xFF,
                g: 0x88,
                b: 0x00,
                a: 0xFF
            }),
            "#FF8800"
        );
    }

    #[test]
    fn color_with_alpha_is_rrggbbaa() {
        assert_eq!(
            fmt_color(&FColor {
                r: 0x10,
                g: 0x20,
                b: 0x30,
                a: 0x40
            }),
            "#10203040"
        );
    }

    #[test]
    fn linear_color_quantizes() {
        assert_eq!(
            fmt_linear_color(&FLinearColor {
                r: 1.0,
                g: 0.0,
                b: 0.0,
                a: 1.0
            }),
            "#FF0000"
        );
    }

    /// No hazard but the line's own newlines.
    fn assert_no_hazards(out: &str) {
        assert!(
            !out.chars().any(|c| c != '\n' && is_terminal_hazard(c)),
            "{out:?}"
        );
    }

    /// A name's own newline cannot forge a tree line.
    #[test]
    fn tree_line_neutralizes_controls_and_embedded_newlines() {
        let mut buf = Vec::new();
        let hostile = "\u{1b}[2J\nX\u{202e}";
        TreeOut::new(&mut buf)
            .line(format_args!("a{hostile}b"))
            .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "a\u{FFFD}[2J\u{FFFD}X\u{FFFD}b\n"
        );
    }

    /// The property fixture with same-length byte rewrites applied; each
    /// needle must occur exactly the stated number of times.
    fn property_fixture_with(edits: &[(&[u8], &[u8], usize)]) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/minimal_uasset_v5_with_properties.uasset");
        let mut bytes = std::fs::read(path).unwrap();
        for (needle, replacement, count) in edits {
            assert_eq!(needle.len(), replacement.len());
            let at: Vec<usize> = bytes
                .windows(needle.len())
                .enumerate()
                .filter(|(_, w)| w == needle)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(at.len(), *count, "{needle:?} occurrences");
            for i in at {
                bytes[i..i + needle.len()].copy_from_slice(replacement);
            }
        }
        bytes
    }

    fn render_package(bytes: &[u8], asset_path: &str) -> String {
        let pkg = Package::read_from(bytes, None, None, asset_path).expect("fixture parses");
        let mut out = Vec::new();
        render(&pkg, None, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Archive text reaches every tree sink neutralized: the asset path and
    /// engine branch in the header, an export's object name and a property
    /// name.
    #[test]
    fn render_neutralizes_archive_text_in_a_real_package() {
        let clean = render_package(&property_fixture_with(&[]), "Game/x.uasset");
        assert_eq!(
            clean,
            "Game/x.uasset | engine 4.27.2-0+++UE4+Release-4.27 | names 10 imports 1 exports 1 \
             | guid 00000000-0000-0000-0000-000000000000\n\
             [0] Hero : Default__Object\n  tree (3 properties)\n    bEnabled = true\n    \
             MaxSpeed = 1500\n    ObjectName = \"Hero_C\"\n"
        );
        let hostile = property_fixture_with(&[
            (b"MaxSpeed", b"\x1b[2JPROP", 1),
            (b"Hero\0", b"H\x1b[O\0", 1),
            (b"++UE4+Release-4.27", b"\xc2\x9b2JBRANCHxxxxxxxx", 2),
        ]);
        let out = render_package(&hostile, "Game/\u{1b}]0;PATH\u{7}\n.uasset");

        assert_no_hazards(&out);
        for sink in [
            "\u{FFFD}[2JPROP = ",
            "] H\u{FFFD}[O : ",
            "\u{FFFD}2JBRANCH",
            "Game/\u{FFFD}]0;PATH\u{FFFD}\u{FFFD}.uasset",
        ] {
            assert!(out.contains(sink), "{sink:?} missing from {out:?}");
        }
        // The path's own newline did not forge a line.
        assert_eq!(out.lines().count(), clean.lines().count());
    }

    /// Every name-bearing property shape the fixture lacks: container and
    /// struct headers, enum, unknown, soft path, object and name values, and
    /// the placeholders for a container nested as a map key or value.
    #[test]
    fn render_property_neutralizes_every_name_bearing_arm() {
        let h = "\u{1b}[2J\u{202e}";
        let child = serde_json::json!({ "name": "c", "array_index": 0, "value": { "Name": h } });
        let nested = serde_json::json!({ "Struct": { "struct_name": h, "properties": [child] } });
        let values = [
            nested.clone(),
            serde_json::json!({ "Array": { "inner_type": h, "elements": [{ "Name": h }, nested] } }),
            serde_json::json!({ "Set": { "inner_type": h, "elements": [] } }),
            serde_json::json!({ "Map": { "key_type": "K", "value_type": "V", "entries": [
                { "key": { "Name": h }, "value": { "Enum": { "type_name": h, "value": h } } },
                {
                    "key": { "Array": { "inner_type": h, "elements": [] } },
                    "value": { "Struct": { "struct_name": h, "properties": [] } }
                }
            ] } }),
            serde_json::json!({ "Unknown": { "type_name": h, "skipped_bytes": 1 } }),
            serde_json::json!({ "SoftObjectPath": { "asset_path": h, "sub_path": h } }),
            serde_json::json!({ "Object": { "kind": "Import(0)", "name": h } }),
            serde_json::json!({ "Name": h }),
            serde_json::json!({ "Enum": { "type_name": h, "value": h } }),
        ];
        let mut buf = Vec::new();
        for value in values {
            // From text: `PackageIndex` deserializes a borrowed `&str`.
            let json = serde_json::json!({ "name": h, "array_index": 0, "value": value });
            let prop: Property = serde_json::from_str(&json.to_string()).unwrap();
            render_property(&prop, 0, &mut TreeOut::new(&mut buf)).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();

        let k = "\u{FFFD}[2J\u{FFFD}";
        let expected = [
            format!("{k} ({k}):"),
            format!("  c = {k}"),
            format!("{k} [{k}] (2 items):"),
            format!("  - {k}"),
            format!("  ({k}):"),
            format!("    c = {k}"),
            format!("{k} [{k}] (0 items):"),
            format!("{k} (2 entries):"),
            format!("  {k} => {k}::{k}"),
            format!("  [{k} …] => ({k} …)"),
            format!("{k} = <{k}: 1 bytes>"),
            format!("{k} = {k}:{k}"),
            format!("{k} = {k}"),
            format!("{k} = {k}"),
            format!("{k} = {k}::{k}"),
        ];
        assert_eq!(out, expected.join("\n") + "\n");
    }

    /// The payload-shape line for each bag kind, and a tree's children one
    /// level deeper.
    #[test]
    fn render_bag_names_the_payload_shape() {
        let bag_out = |bag: &PropertyBag| {
            let mut buf = Vec::new();
            render_bag(bag, &mut TreeOut::new(&mut buf)).unwrap();
            String::from_utf8(buf).unwrap()
        };
        assert_eq!(
            bag_out(&PropertyBag::opaque(vec![0; 3])),
            "  opaque (3 bytes)\n"
        );
        let tree: PropertyBag = serde_json::from_str(
            r#"{"kind":"tree","properties":[{"name":"p","array_index":0,"value":{"Name":"x"}}]}"#,
        )
        .unwrap();
        assert_eq!(bag_out(&tree), "  tree (1 properties)\n    p = x\n");
    }
}
