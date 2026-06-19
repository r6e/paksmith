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

/// Compact one-line form of an [`FColor`] (8-bit RGBA): `rgba(r, g, b, a)`.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "by-ref signature is pinned by the Task-5 brief and kept uniform with \
              fmt_vector / fmt_linear_color, whose larger structs warrant by-ref"
)]
pub(crate) fn fmt_color(c: &FColor) -> String {
    format!("rgba({}, {}, {}, {})", c.r, c.g, c.b, c.a)
}

/// Compact one-line form of an [`FLinearColor`] (linear f32 RGBA):
/// `linear(r, g, b, a)`.
pub(crate) fn fmt_linear_color(c: &FLinearColor) -> String {
    format!("linear({}, {}, {}, {})", c.r, c.g, c.b, c.a)
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
    let summary = &pkg.summary;
    writeln!(
        w,
        "{} | engine {} | names {} imports {} exports {} | guid {}",
        pkg.asset_path,
        summary.saved_by_engine_version,
        pkg.names.names.len(),
        pkg.imports.imports.len(),
        pkg.exports.exports.len(),
        summary.guid,
    )?;

    let count = pkg.exports.exports.len();
    match export {
        Some(idx) => render_export(pkg, idx, w)?,
        None => {
            for idx in 0..count {
                render_export(pkg, idx, w)?;
            }
        }
    }
    Ok(())
}

/// Render a single export's block: header line, payload-shape line, and the
/// property tree (for the decoded `Tree` case).
fn render_export(pkg: &Package, idx: usize, w: &mut dyn Write) -> io::Result<()> {
    let Some(export) = pkg.exports.exports.get(idx) else {
        // Defensive: an out-of-range index is rejected upstream by
        // `select::resolve_export`, but render must never panic.
        return Ok(());
    };
    let object_name = pkg
        .names
        .resolve(export.object_name, export.object_name_number);
    let class = class_name(pkg, export.class_index);
    writeln!(w, "[{idx}] {object_name} : {class}")?;

    match pkg.payloads.get(idx) {
        Some(Asset::Generic(bag)) => render_bag(bag, w),
        Some(other) => {
            // Typed variants (DataTable, Texture2D, …): name the variant and
            // render its property bag when it carries one. Phase 3 ships only
            // `Generic` for the inspect fixture; the typed arms are forward
            // coverage exercised by the formatter unit tests.
            writeln!(w, "{INDENT}{}", typed_variant_label(other))?;
            if let Some(bag) = typed_variant_bag(other) {
                render_bag(bag, w)?;
            }
            Ok(())
        }
        None => Ok(()),
    }
}

/// Render the payload-shape line and (for `Tree`) the property listing.
fn render_bag(bag: &PropertyBag, w: &mut dyn Write) -> io::Result<()> {
    match bag {
        PropertyBag::Opaque { bytes } => {
            writeln!(w, "{INDENT}opaque ({} bytes)", bytes.len())
        }
        PropertyBag::Tree { properties } => {
            writeln!(w, "{INDENT}tree ({} properties)", properties.len())?;
            render_properties(properties, 2, w)
        }
        // `PropertyBag` is #[non_exhaustive].
        _ => writeln!(w, "{INDENT}<unknown payload>"),
    }
}

/// Render a flat list of properties at `depth` indent levels.
fn render_properties(properties: &[Property], depth: usize, w: &mut dyn Write) -> io::Result<()> {
    for prop in properties {
        render_property(prop, depth, w)?;
    }
    Ok(())
}

/// Render one property: `<name> = <value>` (scalars inline) or a `<name>:`
/// header followed by indented children (containers / structs).
fn render_property(prop: &Property, depth: usize, w: &mut dyn Write) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    let name = prop.name();
    match &prop.value {
        PropertyValue::Struct {
            struct_name,
            properties,
        } => {
            writeln!(w, "{pad}{name} ({struct_name}):")?;
            render_properties(properties, depth + 1, w)
        }
        PropertyValue::Array {
            inner_type,
            elements,
        }
        | PropertyValue::Set {
            inner_type,
            elements,
        } => {
            writeln!(w, "{pad}{name} [{inner_type}] ({} items):", elements.len())?;
            render_values(elements, depth + 1, w)
        }
        PropertyValue::Map { entries, .. } => {
            writeln!(w, "{pad}{name} ({} entries):", entries.len())?;
            render_map_entries(entries, depth + 1, w)
        }
        other => writeln!(w, "{pad}{name} = {}", scalar(other)),
    }
}

/// Render array/set elements (no per-element name).
fn render_values(values: &[PropertyValue], depth: usize, w: &mut dyn Write) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    for value in values {
        match value {
            PropertyValue::Struct {
                struct_name,
                properties,
            } => {
                writeln!(w, "{pad}({struct_name}):")?;
                render_properties(properties, depth + 1, w)?;
            }
            other => writeln!(w, "{pad}- {}", scalar(other))?,
        }
    }
    Ok(())
}

/// Render map key/value entries.
fn render_map_entries(entries: &[MapEntry], depth: usize, w: &mut dyn Write) -> io::Result<()> {
    let pad = INDENT.repeat(depth);
    for entry in entries {
        writeln!(w, "{pad}{} => {}", scalar(&entry.key), scalar(&entry.value))?;
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
        PropertyValue::Object { name, .. } => name.clone(),
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
fn typed_variant_label(asset: &Asset) -> &'static str {
    match asset {
        Asset::Generic(_) => "generic",
        Asset::DataTable(_) => "DataTable",
        Asset::Texture2D(_) => "Texture2D",
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

    #[test]
    fn fmt_vector_compacts_whole_and_fractional() {
        // `{}` on f64: 1.0 -> "1", 2.5 -> "2.5", -3.0 -> "-3".
        let v = FVector {
            x: 1.0,
            y: 2.5,
            z: -3.0,
        };
        assert_eq!(fmt_vector(&v), "[1, 2.5, -3]");
    }

    #[test]
    fn fmt_color_renders_rgba_bytes() {
        let c = FColor {
            r: 255,
            g: 128,
            b: 0,
            a: 64,
        };
        assert_eq!(fmt_color(&c), "rgba(255, 128, 0, 64)");
    }

    #[test]
    fn fmt_linear_color_renders_linear_floats() {
        let c = FLinearColor {
            r: 1.0,
            g: 0.5,
            b: 0.0,
            a: 1.0,
        };
        assert_eq!(fmt_linear_color(&c), "linear(1, 0.5, 0, 1)");
    }
}
