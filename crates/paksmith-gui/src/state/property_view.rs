//! Pure property-tree row model for the PropertyInspector.
//!
//! No `iced` imports. Consumes a parsed [`Package`] and produces a flat
//! `Vec<PropRow>` for rendering in a virtualized list widget (Task 10).
//! The tree is expanded/collapsed via a `HashSet<NodeId>` — toggling an
//! id and re-calling `flatten` is the full update cycle.

use std::collections::HashSet;
use std::hash::Hash;

use paksmith_core::PackageIndex;
use paksmith_core::asset::Asset;
use paksmith_core::asset::Package;
use paksmith_core::asset::property::PropertyBag;
use paksmith_core::asset::property::primitives::{Property, PropertyValue};
use paksmith_core::asset::property::text::FTextHistory;
use paksmith_core::asset::structs::TypedStructValue;

/// Maximum tree render depth. Bounds recursion against deeply nested
/// crafted assets even though core already caps parse depth.
pub const MAX_RENDER_DEPTH: usize = 64;

/// Whether `depth` has reached the render-depth cap (defense-in-depth guard
/// against deeply-nested/adversarial property trees). Uses `>=` so the cap is
/// the maximum depth actually rendered.
fn at_depth_cap(depth: usize) -> bool {
    depth >= MAX_RENDER_DEPTH
}

/// Stable path-from-root identity for a node.
///
/// Built by hashing (parent_id, segment, array_index) with
/// `DefaultHasher` (fixed seed — same input → same output across calls).
pub type NodeId = u64;

/// Whether a row is a branch (expandable container) or a leaf (scalar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropKind {
    Branch,
    Leaf,
}

/// One rendered row in the property tree.
#[derive(Debug, Clone)]
pub struct PropRow {
    pub depth: usize,
    pub label: String,
    pub value: Option<String>,
    /// RGBA color in 0.0..=1.0 for leaf rows that carry a color value
    /// (`FColor` / `FLinearColor` typed structs). `None` for all other rows
    /// (branches and non-color leaves). The Task 10 widget renders a swatch
    /// when this is `Some`, without re-deriving color from core types.
    pub color: Option<[f32; 4]>,
    pub node_id: NodeId,
    pub is_expandable: bool,
    pub expanded: bool,
    pub kind: PropKind,
}

// ── NodeId helpers ────────────────────────────────────────────────────────────

/// Seed a root NodeId from an export index.
fn root_node_id(export_idx: usize) -> NodeId {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    export_idx.hash(&mut h);
    std::hash::Hasher::finish(&h)
}

/// Derive a child NodeId by folding (parent_id, segment, array_index).
fn child_node_id(parent: NodeId, segment: &str, array_index: i32) -> NodeId {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    parent.hash(&mut h);
    segment.hash(&mut h);
    array_index.hash(&mut h);
    std::hash::Hasher::finish(&h)
}

/// Derive a positional NodeId for anonymous array/set/map elements.
fn element_node_id(parent: NodeId, position: usize) -> NodeId {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    parent.hash(&mut h);
    // Use a sentinel segment that can't collide with a named property.
    "__elem__".hash(&mut h);
    position.hash(&mut h);
    std::hash::Hasher::finish(&h)
}

// ── payload_bag helper ────────────────────────────────────────────────────────

/// Extract the class-level property bag from any [`Asset`] variant.
///
/// Copied verbatim from the Task 5 brief (GUI module — does NOT call CLI code).
fn payload_bag(asset: &Asset) -> Option<&PropertyBag> {
    match asset {
        Asset::Generic(bag) => Some(bag),
        Asset::DataTable(d) => Some(&d.class_properties),
        Asset::Texture2D(t) => Some(&t.properties),
        Asset::SoundWave(s) => Some(&s.properties),
        Asset::StaticMesh(m) => Some(&m.properties),
        Asset::SkeletalMesh(m) => Some(&m.properties),
        // `Asset` is #[non_exhaustive].
        _ => None,
    }
}

// ── class_name helper ─────────────────────────────────────────────────────────

/// Resolve an export's `class_index` to a display class name.
///
/// Mirrors `cli/src/inspect/tree.rs::class_name` structure.
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

// ── as_color ──────────────────────────────────────────────────────────────────

/// Extract an RGBA color `[r, g, b, a]` in `0.0..=1.0` from `v` when it
/// carries a `TypedStruct` color variant; returns `None` for every other value.
///
/// - `FColor` (4 × u8): each channel is `f32::from(ch) / 255.0` (exact for 0
///   and 255; no loss for channel boundary values).
/// - `FLinearColor` (4 × f32): channels are clamped to `0.0..=1.0`.
pub fn as_color(v: &PropertyValue) -> Option<[f32; 4]> {
    let PropertyValue::TypedStruct(typed) = v else {
        return None;
    };
    match typed.as_ref() {
        TypedStructValue::Color(c) => Some([
            f32::from(c.r) / 255.0,
            f32::from(c.g) / 255.0,
            f32::from(c.b) / 255.0,
            f32::from(c.a) / 255.0,
        ]),
        TypedStructValue::LinearColor(c) => Some([
            c.r.clamp(0.0, 1.0),
            c.g.clamp(0.0, 1.0),
            c.b.clamp(0.0, 1.0),
            c.a.clamp(0.0, 1.0),
        ]),
        // All other TypedStructValue variants are not colors.
        _ => None,
    }
}

// ── display helpers ───────────────────────────────────────────────────────────

/// Extract the most-readable display string from an `FText`.
///
/// - `Base` → `source_string` (the English original by convention).
/// - `None` with a culture-invariant string → that string.
/// - `None` without → `"<text>"`.
/// - `Unknown` or future variants → `"<text>"`.
fn ftext_display(t: &paksmith_core::asset::property::text::FText) -> String {
    match &t.history {
        FTextHistory::Base { source_string, .. } => source_string.clone(),
        FTextHistory::None {
            culture_invariant: Some(s),
        } => s.clone(),
        // `None` without a culture-invariant string, `Unknown`, and future
        // variants (FTextHistory is #[non_exhaustive]) all fall through to the
        // generic placeholder.
        _ => "<text>".to_string(),
    }
}

/// Compact one-line display of a [`TypedStructValue`].
///
/// Vectors use `(x, y, z)` parenthesis form with `{}` formatting (whole
/// floats render without `.0`). Colors display as `#RRGGBB[AA]`. Other
/// variants fall back to `<VariantName>`.
fn fmt_typed_struct(value: &TypedStructValue) -> String {
    match value {
        TypedStructValue::Vector(v) => format!("({}, {}, {})", v.x, v.y, v.z),
        TypedStructValue::Vector2D(v) => format!("({}, {})", v.x, v.y),
        TypedStructValue::Vector4(v) => format!("({}, {}, {}, {})", v.x, v.y, v.z, v.w),
        TypedStructValue::Rotator(r) => format!("({}, {}, {})", r.pitch, r.yaw, r.roll),
        TypedStructValue::Quat(q) => format!("({}, {}, {}, {})", q.x, q.y, q.z, q.w),
        TypedStructValue::Color(c) => fmt_color_hex(c.r, c.g, c.b, c.a),
        TypedStructValue::LinearColor(c) => {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "value is clamped to 0.0..=1.0 before scaling; result fits u8 \
                          and is non-negative. NaN saturates to 0 via `as u8`, safe and non-panicking"
            )]
            let q = |f: f32| (f.clamp(0.0, 1.0) * 255.0).round() as u8;
            fmt_color_hex(q(c.r), q(c.g), q(c.b), q(c.a))
        }
        TypedStructValue::Box(_) => "<Box>".to_string(),
        TypedStructValue::Box2D(_) => "<Box2D>".to_string(),
        TypedStructValue::Transform(_) => "<Transform>".to_string(),
        TypedStructValue::BoxSphereBounds(_) => "<BoxSphereBounds>".to_string(),
        // `TypedStructValue` is #[non_exhaustive].
        _ => "<?>".to_string(),
    }
}

/// Render u8 RGBA as `#RRGGBB` (alpha omitted when `== 0xFF`).
fn fmt_color_hex(r: u8, g: u8, b: u8, a: u8) -> String {
    if a == 0xFF {
        format!("#{r:02X}{g:02X}{b:02X}")
    } else {
        format!("#{r:02X}{g:02X}{b:02X}{a:02X}")
    }
}

// ── scalar_display ────────────────────────────────────────────────────────────

/// One-line scalar display of a property value for leaf rows.
///
/// Always returns `Some(..)` in this task. The `Option` return type is
/// part of the public interface so Task 6 can return `None` for variants
/// it handles via richer dedicated widgets.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Option<String> is the interface contract; Task 6 will return None \
              for variants handled by dedicated widgets"
)]
pub fn scalar_display(v: &PropertyValue) -> Option<String> {
    match v {
        PropertyValue::Bool(b) => Some(b.to_string()),
        PropertyValue::Byte(b) => Some(b.to_string()),
        PropertyValue::Int8(n) => Some(n.to_string()),
        PropertyValue::Int16(n) => Some(n.to_string()),
        PropertyValue::Int(n) => Some(n.to_string()),
        PropertyValue::Int64(n) => Some(n.to_string()),
        PropertyValue::UInt16(n) => Some(n.to_string()),
        PropertyValue::UInt32(n) => Some(n.to_string()),
        PropertyValue::UInt64(n) => Some(n.to_string()),
        PropertyValue::Float(f) => Some(f.to_string()),
        PropertyValue::Double(f) => Some(f.to_string()),
        PropertyValue::Str(s) => Some(format!("\"{s}\"")),
        PropertyValue::Name(n) => Some(n.to_string()),
        PropertyValue::Enum { type_name, value } => {
            if type_name.is_empty() {
                Some(value.to_string())
            } else {
                Some(format!("{type_name}::{value}"))
            }
        }
        PropertyValue::Text(t) => Some(ftext_display(t)),
        PropertyValue::Unknown {
            type_name,
            skipped_bytes,
        } => Some(format!("<{type_name}: {skipped_bytes} bytes>")),
        PropertyValue::SoftObjectPath {
            asset_path,
            sub_path,
        }
        | PropertyValue::SoftClassPath {
            asset_path,
            sub_path,
        } => {
            if sub_path.is_empty() {
                Some(asset_path.clone())
            } else {
                Some(format!("{asset_path}:{sub_path}"))
            }
        }
        PropertyValue::Object { name, .. } => {
            if name.is_empty() {
                Some("<null>".to_string())
            } else {
                Some(name.clone())
            }
        }
        // Container variants — expandable; return count summary.
        PropertyValue::Array { elements, .. } | PropertyValue::Set { elements, .. } => {
            Some(format!("[{}]", elements.len()))
        }
        PropertyValue::Map { entries, .. } => Some(format!("[{}]", entries.len())),
        PropertyValue::Struct { properties, .. } => Some(format!("[{}]", properties.len())),
        PropertyValue::TypedStruct(b) => Some(fmt_typed_struct(b)),
        // `PropertyValue` is #[non_exhaustive] — unknown future variants.
        _ => Some("<unhandled>".to_string()),
    }
}

// ── flatten ────────────────────────────────────────────────────────────────────

/// Flatten `pkg` into a list of rows for the property inspector.
///
/// Top-level rows are one-per-export Branch rows. Expanding an export's
/// `node_id` (by inserting it into `expanded`) causes its property bag rows
/// to appear at depth 1. Containers recurse similarly.
pub fn flatten(pkg: &Package, expanded: &HashSet<NodeId>) -> Vec<PropRow> {
    let mut rows = Vec::new();
    for (idx, export) in pkg.exports.exports.iter().enumerate() {
        let object_name = pkg
            .names
            .resolve(export.object_name, export.object_name_number);
        let class = class_name(pkg, export.class_index);
        let label = format!("[{idx}] {object_name} : {class}");
        let node_id = root_node_id(idx);
        let is_exp = expanded.contains(&node_id);

        // Determine whether the export has any children to show.
        let has_payload = pkg.payloads.get(idx).is_some();

        rows.push(PropRow {
            depth: 0,
            label,
            value: None,
            color: None,
            node_id,
            is_expandable: has_payload,
            expanded: is_exp,
            kind: PropKind::Branch,
        });

        // Nested `if is_exp { if let ... }` is intentional: MSRV 1.88 does not
        // support let-chains; merging requires the unstable `if let` chain syntax.
        #[allow(clippy::collapsible_if)]
        if is_exp {
            if let Some(asset) = pkg.payloads.get(idx) {
                match payload_bag(asset) {
                    Some(PropertyBag::Tree { properties }) => {
                        for prop in properties {
                            flatten_property(prop, 1, node_id, &mut rows, expanded);
                        }
                    }
                    Some(PropertyBag::Opaque { bytes }) => {
                        rows.push(PropRow {
                            depth: 1,
                            label: format!("<opaque {} bytes>", bytes.len()),
                            value: None,
                            color: None,
                            node_id: child_node_id(node_id, "__opaque__", 0),
                            is_expandable: false,
                            expanded: false,
                            kind: PropKind::Leaf,
                        });
                    }
                    // `PropertyBag` is #[non_exhaustive].
                    Some(_) => {
                        rows.push(PropRow {
                            depth: 1,
                            label: "<unknown payload>".to_string(),
                            value: None,
                            color: None,
                            node_id: child_node_id(node_id, "__unknown_payload__", 0),
                            is_expandable: false,
                            expanded: false,
                            kind: PropKind::Leaf,
                        });
                    }
                    None => {
                        // Typed asset with no accessible property bag.
                        rows.push(PropRow {
                            depth: 1,
                            label: "<typed asset>".to_string(),
                            value: None,
                            color: None,
                            node_id: child_node_id(node_id, "__typed__", 0),
                            is_expandable: false,
                            expanded: false,
                            kind: PropKind::Leaf,
                        });
                    }
                }
            }
        }
    }
    rows
}

/// Recursively flatten one named [`Property`] into rows.
///
/// Container arms delegate to [`push_value_row`] so that recursion
/// arithmetic (depth + 1, element_node_id offsets) lives in a single
/// place. The label is computed here from `prop.name()` before the
/// delegation.
fn flatten_property(
    prop: &Property,
    depth: usize,
    parent_id: NodeId,
    rows: &mut Vec<PropRow>,
    expanded: &HashSet<NodeId>,
) {
    if at_depth_cap(depth) {
        return;
    }

    let node_id = child_node_id(parent_id, prop.name(), prop.array_index);
    let label = prop.name().to_string();
    push_value_row(&prop.value, depth, node_id, label, rows, expanded);
}

/// Flatten an anonymous positional element (array/set item) into rows.
fn flatten_value(
    value: &PropertyValue,
    depth: usize,
    parent_id: NodeId,
    position: usize,
    rows: &mut Vec<PropRow>,
    expanded: &HashSet<NodeId>,
) {
    if at_depth_cap(depth) {
        return;
    }
    let node_id = element_node_id(parent_id, position);
    let label = format!("[{position}]");
    push_value_row(value, depth, node_id, label, rows, expanded);
}

/// Push a value row (scalar leaf or expandable branch) using a pre-computed id and label.
#[allow(
    clippy::too_many_lines,
    reason = "property-type dispatch — one arm per UE container variant; \
              splitting would obscure the per-type recursion structure"
)]
fn push_value_row(
    value: &PropertyValue,
    depth: usize,
    node_id: NodeId,
    label: String,
    rows: &mut Vec<PropRow>,
    expanded: &HashSet<NodeId>,
) {
    if at_depth_cap(depth) {
        return;
    }
    let is_exp = expanded.contains(&node_id);
    // Single depth-increment binding shared by all container arms — one mutation point.
    let child_depth = depth + 1;

    match value {
        PropertyValue::Struct {
            struct_name,
            properties,
        } => {
            let branch_label = format!("{label} ({struct_name})");
            rows.push(PropRow {
                depth,
                label: branch_label,
                value: None,
                color: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for child in properties {
                    flatten_property(child, child_depth, node_id, rows, expanded);
                }
            }
        }
        PropertyValue::Array {
            inner_type,
            elements,
        }
        | PropertyValue::Set {
            inner_type,
            elements,
        } => {
            let branch_label = format!("{label} [{inner_type}]");
            rows.push(PropRow {
                depth,
                label: branch_label,
                value: None,
                color: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, elem) in elements.iter().enumerate() {
                    flatten_value(elem, child_depth, node_id, i, rows, expanded);
                }
            }
        }
        PropertyValue::Map {
            key_type,
            value_type,
            entries,
        } => {
            let branch_label = format!("{label} [{key_type} → {value_type}]");
            rows.push(PropRow {
                depth,
                label: branch_label,
                value: None,
                color: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, entry) in entries.iter().enumerate() {
                    let key_id = element_node_id(node_id, i * 2);
                    let key_label = format!("[{i}].key");
                    push_value_row(&entry.key, child_depth, key_id, key_label, rows, expanded);
                    let val_id = element_node_id(node_id, i * 2 + 1);
                    let val_label = format!("[{i}].value");
                    push_value_row(&entry.value, child_depth, val_id, val_label, rows, expanded);
                }
            }
        }
        other => {
            // Scalar leaf — populate color channel for color-typed values.
            rows.push(PropRow {
                depth,
                label,
                value: scalar_display(other),
                color: as_color(other),
                node_id,
                is_expandable: false,
                expanded: false,
                kind: PropKind::Leaf,
            });
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use paksmith_core::asset::property::primitives::PropertyValue;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn demo_package() -> paksmith_core::asset::Package {
        use paksmith_core::container::pak::PakReader;
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/real_v8b_uasset.pak");
        let reader = Arc::new(PakReader::open(p).unwrap());
        paksmith_core::asset::Package::read_from_reader(&reader, "Game/Maps/Demo.uasset", None)
            .unwrap()
    }

    #[test]
    fn scalar_display_renders_primitives() {
        assert_eq!(
            scalar_display(&PropertyValue::Bool(true)).as_deref(),
            Some("true")
        );
        assert_eq!(
            scalar_display(&PropertyValue::Int(42)).as_deref(),
            Some("42")
        );
        assert_eq!(
            scalar_display(&PropertyValue::Float(1.5)).as_deref(),
            Some("1.5")
        );
        assert_eq!(
            scalar_display(&PropertyValue::Str("hi".into())).as_deref(),
            Some("\"hi\"")
        );
    }

    #[test]
    fn flatten_collapsed_shows_only_export_rows() {
        let pkg = demo_package();
        let rows = flatten(&pkg, &HashSet::new());
        assert!(!rows.is_empty(), "at least one export row");
        assert!(
            rows.iter().all(|r| r.depth == 0),
            "collapsed = only top-level export rows"
        );
    }

    #[test]
    fn flatten_expanding_export_reveals_children() {
        let pkg = demo_package();
        let collapsed = flatten(&pkg, &HashSet::new());
        let first = collapsed[0].node_id;
        assert!(collapsed[0].is_expandable, "export row must be expandable");
        let mut exp = HashSet::new();
        #[allow(unused_results)]
        exp.insert(first);
        let expanded = flatten(&pkg, &exp);
        assert!(
            expanded.len() >= collapsed.len(),
            "expanding never removes rows"
        );
        assert!(
            expanded.iter().any(|r| r.depth == 1),
            "expanded export shows child rows"
        );
    }

    #[test]
    fn node_ids_are_stable_across_flattens() {
        let pkg = demo_package();
        let a = flatten(&pkg, &HashSet::new());
        let b = flatten(&pkg, &HashSet::new());
        let ids_a: Vec<_> = a.iter().map(|r| r.node_id).collect();
        let ids_b: Vec<_> = b.iter().map(|r| r.node_id).collect();
        assert_eq!(ids_a, ids_b, "node ids must be deterministic");
    }

    #[test]
    fn max_render_depth_is_64() {
        assert_eq!(MAX_RENDER_DEPTH, 64);
    }

    #[test]
    fn at_depth_cap_stops_at_the_cap() {
        assert!(!at_depth_cap(MAX_RENDER_DEPTH - 1), "below cap must render");
        assert!(at_depth_cap(MAX_RENDER_DEPTH), "AT the cap must stop");
        assert!(at_depth_cap(MAX_RENDER_DEPTH + 1), "past cap must stop");
    }

    #[test]
    fn child_node_ids_differ_by_array_index() {
        let parent = 0u64;
        assert_ne!(
            child_node_id(parent, "Foo", 0),
            child_node_id(parent, "Foo", 1),
            "same name, different array_index must yield distinct node ids"
        );
    }

    // ── Task 6: as_color ──────────────────────────────────────────────────────

    /// Build a `PropertyValue::TypedStruct(Box<FColor{...}>)` in the same way
    /// the core tests in `color.rs` construct values (direct struct literal).
    fn make_fcolor_value(r: u8, g: u8, b: u8, a: u8) -> PropertyValue {
        use paksmith_core::asset::structs::color::FColor;
        PropertyValue::TypedStruct(Box::new(TypedStructValue::Color(FColor { r, g, b, a })))
    }

    fn make_flinear_color_value(r: f32, g: f32, b: f32, a: f32) -> PropertyValue {
        use paksmith_core::asset::structs::color::FLinearColor;
        PropertyValue::TypedStruct(Box::new(TypedStructValue::LinearColor(FLinearColor {
            r,
            g,
            b,
            a,
        })))
    }

    #[test]
    fn as_color_fcolor_red_opaque_channel_pin() {
        // FColor (255, 0, 0, 255) → [1.0, 0.0, 0.0, 1.0].
        // 255/255.0 and 0/255.0 are IEEE-exact; epsilon comparison still
        // kills /255.0 arithmetic mutants (dropping /255 would yield 255.0 or 0.0).
        let v = make_fcolor_value(255, 0, 0, 255);
        let c = as_color(&v).expect("FColor should yield Some");
        assert!(
            (c[0] - 1.0_f32).abs() < f32::EPSILON,
            "r=255 must map to 1.0"
        );
        assert!((c[1] - 0.0_f32).abs() < f32::EPSILON, "g=0 must map to 0.0");
        assert!((c[2] - 0.0_f32).abs() < f32::EPSILON, "b=0 must map to 0.0");
        assert!(
            (c[3] - 1.0_f32).abs() < f32::EPSILON,
            "a=255 must map to 1.0"
        );
    }

    #[test]
    fn as_color_fcolor_all_channels_distinct() {
        // All four channels carry different u8 values so a mutant that drops
        // or swaps any one channel is caught here.
        // r=0x10=16, g=0x40=64, b=0x80=128, a=0xC0=192
        let v = make_fcolor_value(16, 64, 128, 192);
        let c = as_color(&v).expect("FColor should yield Some");
        let expected_r = f32::from(16_u8) / 255.0;
        let expected_g = f32::from(64_u8) / 255.0;
        let expected_b = f32::from(128_u8) / 255.0;
        let expected_a = f32::from(192_u8) / 255.0;
        assert!((c[0] - expected_r).abs() < f32::EPSILON, "r mismatch");
        assert!((c[1] - expected_g).abs() < f32::EPSILON, "g mismatch");
        assert!((c[2] - expected_b).abs() < f32::EPSILON, "b mismatch");
        assert!((c[3] - expected_a).abs() < f32::EPSILON, "a mismatch");
        // Swap-guard: the four channels must be strictly ordered as produced,
        // so a transposed r/g/b/a in as_color is caught regardless of tolerance.
        assert!(
            c[0] < c[1] && c[1] < c[2] && c[2] < c[3],
            "channels must stay in r<g<b<a order for the chosen distinct inputs"
        );
    }

    #[test]
    fn as_color_flinear_color_passthrough() {
        let v = make_flinear_color_value(0.25, 0.5, 0.75, 1.0);
        let c = as_color(&v).expect("FLinearColor should yield Some");
        assert!((c[0] - 0.25).abs() < f32::EPSILON, "r mismatch");
        assert!((c[1] - 0.50).abs() < f32::EPSILON, "g mismatch");
        assert!((c[2] - 0.75).abs() < f32::EPSILON, "b mismatch");
        assert!((c[3] - 1.00).abs() < f32::EPSILON, "a mismatch");
    }

    #[test]
    fn as_color_flinear_color_clamps_all_channels() {
        // All four channels out-of-range in the same value so that dropping
        // the clamp on ANY channel produces a wrong result.
        // r=2.0>1→1, g=-1.0<0→0, b=5.0>1→1, a=-3.0<0→0.
        let v = make_flinear_color_value(2.0, -1.0, 5.0, -3.0);
        let c = as_color(&v).expect("FLinearColor should yield Some");
        assert!(
            (c[0] - 1.0_f32).abs() < f32::EPSILON,
            "r=2.0 must clamp to 1.0, got {}",
            c[0]
        );
        assert!(
            c[1].abs() < f32::EPSILON,
            "g=-1.0 must clamp to 0.0, got {}",
            c[1]
        );
        assert!(
            (c[2] - 1.0_f32).abs() < f32::EPSILON,
            "b=5.0 must clamp to 1.0, got {}",
            c[2]
        );
        assert!(
            c[3].abs() < f32::EPSILON,
            "a=-3.0 must clamp to 0.0, got {}",
            c[3]
        );
    }

    #[test]
    fn as_color_returns_none_for_int() {
        assert!(as_color(&PropertyValue::Int(42)).is_none());
    }

    #[test]
    fn as_color_returns_none_for_str() {
        assert!(as_color(&PropertyValue::Str("red".into())).is_none());
    }

    #[test]
    fn as_color_returns_none_for_non_color_typed_struct() {
        use paksmith_core::asset::structs::vector::FVector;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Vector(FVector {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        })));
        assert!(
            as_color(&v).is_none(),
            "Vector TypedStruct must not yield a color"
        );
    }

    // ── Task 6: scalar_display enrichment ────────────────────────────────────

    #[test]
    fn scalar_display_enum_with_type_name() {
        let v = PropertyValue::Enum {
            type_name: "EMyEnum".into(),
            value: "ValueA".into(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("EMyEnum::ValueA"),
            "Enum with type_name must format as Type::Value"
        );
    }

    #[test]
    fn scalar_display_enum_empty_type_name() {
        let v = PropertyValue::Enum {
            type_name: "".into(),
            value: "SomeValue".into(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("SomeValue"),
            "Enum with empty type_name must show bare value"
        );
    }

    #[test]
    fn scalar_display_object_null() {
        let v = PropertyValue::Object {
            kind: paksmith_core::PackageIndex::Null,
            name: String::new(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("<null>"),
            "empty Object name must render as <null>"
        );
    }

    #[test]
    fn scalar_display_object_named() {
        let v = PropertyValue::Object {
            kind: paksmith_core::PackageIndex::Null,
            name: "MyMesh".into(),
        };
        assert_eq!(scalar_display(&v).as_deref(), Some("MyMesh"));
    }

    #[test]
    fn scalar_display_soft_object_path_no_sub() {
        let v = PropertyValue::SoftObjectPath {
            asset_path: "/Game/Textures/Foo".into(),
            sub_path: String::new(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("/Game/Textures/Foo"),
            "SoftObjectPath without sub_path must show only asset_path"
        );
    }

    #[test]
    fn scalar_display_soft_object_path_with_sub() {
        let v = PropertyValue::SoftObjectPath {
            asset_path: "/Game/Textures/Foo".into(),
            sub_path: "SubObject".into(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("/Game/Textures/Foo:SubObject")
        );
    }

    #[test]
    fn scalar_display_soft_class_path() {
        let v = PropertyValue::SoftClassPath {
            asset_path: "/Game/BP/Hero.Hero_C".into(),
            sub_path: String::new(),
        };
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("/Game/BP/Hero.Hero_C"),
            "SoftClassPath without sub_path must show only asset_path"
        );
    }

    #[test]
    fn scalar_display_typed_struct_vector() {
        use paksmith_core::asset::structs::vector::FVector;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Vector(FVector {
            x: 1.0,
            y: 2.5,
            z: -3.0,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("(1, 2.5, -3)"),
            "Vector must format as (x, y, z) using Display (no trailing .0)"
        );
    }

    #[test]
    fn scalar_display_typed_struct_fcolor_opaque() {
        // FColor r=0xFF g=0x88 b=0x00 a=0xFF → "#FF8800" (alpha omitted when 255)
        let v = make_fcolor_value(0xFF, 0x88, 0x00, 0xFF);
        assert_eq!(scalar_display(&v).as_deref(), Some("#FF8800"));
    }

    #[test]
    fn scalar_display_typed_struct_fcolor_with_alpha() {
        // FColor with alpha < 255 → "#RRGGBBAA"
        let v = make_fcolor_value(0x10, 0x20, 0x30, 0x40);
        assert_eq!(scalar_display(&v).as_deref(), Some("#10203040"));
    }

    #[test]
    fn scalar_display_typed_struct_flinear_color_quantizes() {
        // FLinearColor (1.0, 0.0, 0.0, 1.0) → "#FF0000"
        let v = make_flinear_color_value(1.0, 0.0, 0.0, 1.0);
        assert_eq!(scalar_display(&v).as_deref(), Some("#FF0000"));
    }

    #[test]
    fn scalar_display_text_base_shows_source_string() {
        use paksmith_core::asset::property::text::{FText, FTextHistory};
        let v = PropertyValue::Text(FText {
            flags: 0,
            history: FTextHistory::Base {
                namespace: "NS".into(),
                key: "K".into(),
                source_string: "Hello World".into(),
            },
        });
        assert_eq!(scalar_display(&v).as_deref(), Some("Hello World"));
    }

    #[test]
    fn scalar_display_text_none_with_culture_invariant() {
        use paksmith_core::asset::property::text::{FText, FTextHistory};
        let v = PropertyValue::Text(FText {
            flags: 0,
            history: FTextHistory::None {
                culture_invariant: Some("invariant".into()),
            },
        });
        assert_eq!(scalar_display(&v).as_deref(), Some("invariant"));
    }

    #[test]
    fn scalar_display_text_none_without_string() {
        use paksmith_core::asset::property::text::{FText, FTextHistory};
        let v = PropertyValue::Text(FText {
            flags: 0,
            history: FTextHistory::None {
                culture_invariant: None,
            },
        });
        assert_eq!(scalar_display(&v).as_deref(), Some("<text>"));
    }

    // ── Task 6: fmt_typed_struct per-arm coverage ────────────────────────────

    #[test]
    fn fmt_typed_struct_vector2d() {
        use paksmith_core::asset::structs::vector::FVector2D;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Vector2D(FVector2D {
            x: 3.0,
            y: -1.5,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("(3, -1.5)"),
            "Vector2D must format as (x, y)"
        );
    }

    #[test]
    fn fmt_typed_struct_vector4() {
        use paksmith_core::asset::structs::vector::FVector4;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Vector4(FVector4 {
            x: 1.0,
            y: 2.0,
            z: 3.0,
            w: 4.0,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("(1, 2, 3, 4)"),
            "Vector4 must format as (x, y, z, w)"
        );
    }

    #[test]
    fn fmt_typed_struct_rotator() {
        use paksmith_core::asset::structs::rotator::FRotator;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Rotator(FRotator {
            pitch: 10.0,
            yaw: 20.0,
            roll: 30.0,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("(10, 20, 30)"),
            "Rotator must format as (pitch, yaw, roll)"
        );
    }

    #[test]
    fn fmt_typed_struct_quat() {
        use paksmith_core::asset::structs::quat::FQuat;
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Quat(FQuat {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("(0, 0, 0, 1)"),
            "Quat must format as (x, y, z, w)"
        );
    }

    #[test]
    fn fmt_typed_struct_box_renders_placeholder() {
        use paksmith_core::asset::structs::box_::FBox;
        use paksmith_core::asset::structs::vector::FVector;
        let zero = FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Box(FBox {
            min: zero,
            max: zero,
            is_valid: false,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("<Box>"),
            "Box must render as <Box> placeholder"
        );
    }

    #[test]
    fn fmt_typed_struct_box2d_renders_placeholder() {
        use paksmith_core::asset::structs::box_::FBox2D;
        use paksmith_core::asset::structs::vector::FVector2D;
        let zero = FVector2D { x: 0.0, y: 0.0 };
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Box2D(FBox2D {
            min: zero,
            max: zero,
            is_valid: false,
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("<Box2D>"),
            "Box2D must render as <Box2D> placeholder"
        );
    }

    #[test]
    fn fmt_typed_struct_transform_renders_placeholder() {
        use paksmith_core::asset::structs::quat::FQuat;
        use paksmith_core::asset::structs::transform::FTransform;
        use paksmith_core::asset::structs::vector::FVector;
        let zero = FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        let identity_q = FQuat {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: 1.0,
        };
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::Transform(FTransform {
            rotation: identity_q,
            translation: zero,
            scale_3d: FVector {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
        })));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("<Transform>"),
            "Transform must render as <Transform> placeholder"
        );
    }

    #[test]
    fn fmt_typed_struct_boxspherebounds_renders_placeholder() {
        use paksmith_core::asset::structs::bounds::FBoxSphereBounds;
        use paksmith_core::asset::structs::vector::FVector;
        let zero = FVector {
            x: 0.0,
            y: 0.0,
            z: 0.0,
        };
        let v = PropertyValue::TypedStruct(Box::new(TypedStructValue::BoxSphereBounds(
            FBoxSphereBounds {
                origin: zero,
                box_extent: zero,
                sphere_radius: 0.0,
            },
        )));
        assert_eq!(
            scalar_display(&v).as_deref(),
            Some("<BoxSphereBounds>"),
            "BoxSphereBounds must render as <BoxSphereBounds> placeholder"
        );
    }

    // ── Task 6: PropRow.color population ─────────────────────────────────────

    #[test]
    fn prop_row_color_is_none_for_branches() {
        let pkg = demo_package();
        let rows = flatten(&pkg, &HashSet::new());
        for row in &rows {
            if row.kind == PropKind::Branch {
                assert!(
                    row.color.is_none(),
                    "branch rows must have color = None (got {:?} for '{}')",
                    row.color,
                    row.label
                );
            }
        }
    }

    #[test]
    fn push_value_row_color_leaf_wires_some_for_fcolor() {
        // Verify the `color: as_color(other)` wiring at the `push_value_row`
        // scalar-leaf path, independent of whether the real fixture happens
        // to contain a color property.
        let color_val = make_fcolor_value(255, 0, 0, 255);
        let mut rows: Vec<PropRow> = Vec::new();
        push_value_row(
            &color_val,
            0,
            0,
            "MyColor".to_string(),
            &mut rows,
            &HashSet::new(),
        );
        assert_eq!(rows.len(), 1, "exactly one leaf row");
        let c = rows[0]
            .color
            .expect("FColor leaf must populate PropRow.color");
        assert!(
            (c[0] - 1.0_f32).abs() < f32::EPSILON,
            "r channel must be 1.0, got {}",
            c[0]
        );
        assert!(
            c[1].abs() < f32::EPSILON,
            "g channel must be 0.0, got {}",
            c[1]
        );
        assert!(
            c[2].abs() < f32::EPSILON,
            "b channel must be 0.0, got {}",
            c[2]
        );
        assert!(
            (c[3] - 1.0_f32).abs() < f32::EPSILON,
            "a channel must be 1.0, got {}",
            c[3]
        );
    }

    #[test]
    fn push_value_row_non_color_leaf_has_none_color() {
        // A non-color scalar leaf must NOT populate `color`.
        // Kills a mutant that incorrectly returns `Some` for all leaves.
        let v = PropertyValue::Int(42);
        let mut rows: Vec<PropRow> = Vec::new();
        push_value_row(&v, 0, 0, "X".to_string(), &mut rows, &HashSet::new());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].color.is_none(), "Int leaf must have color = None");
    }

    // ── B1: node-id helpers ───────────────────────────────────────────────────

    #[test]
    fn root_node_ids_distinct_per_export() {
        // Kills `replace root_node_id -> NodeId with Default::default()`:
        // a const-0 collapses all exports to equal node ids.
        assert_ne!(root_node_id(0), root_node_id(1));
        assert_ne!(root_node_id(1), root_node_id(2));
    }

    #[test]
    fn element_node_ids_distinct_by_position_and_parent() {
        // Kills `replace element_node_id -> NodeId with Default::default()`:
        // a const-0 collapses all elements to equal node ids.
        assert_ne!(element_node_id(0, 0), element_node_id(0, 1));
        assert_ne!(element_node_id(0, 1), element_node_id(0, 2));
        // Parent matters: same position under different parents must differ.
        assert_ne!(element_node_id(0, 0), element_node_id(99, 0));
    }

    // ── B2: scalar_display — missing variant arms ─────────────────────────────

    #[test]
    fn scalar_display_covers_remaining_scalar_variants() {
        use paksmith_core::asset::property::primitives::MapEntry;
        use paksmith_core::asset::property::primitives::PropertyValue as V;

        // Byte
        assert_eq!(
            scalar_display(&V::Byte(7)).as_deref(),
            Some("7"),
            "Byte(7) must display as \"7\""
        );
        // Int8
        assert_eq!(
            scalar_display(&V::Int8(-3)).as_deref(),
            Some("-3"),
            "Int8(-3) must display as \"-3\""
        );
        // Int16
        assert_eq!(
            scalar_display(&V::Int16(-300)).as_deref(),
            Some("-300"),
            "Int16(-300) must display as \"-300\""
        );
        // Int64
        assert_eq!(
            scalar_display(&V::Int64(-5)).as_deref(),
            Some("-5"),
            "Int64(-5) must display as \"-5\""
        );
        // UInt16
        assert_eq!(
            scalar_display(&V::UInt16(60000)).as_deref(),
            Some("60000"),
            "UInt16(60000) must display as \"60000\""
        );
        // UInt32
        assert_eq!(
            scalar_display(&V::UInt32(4_000_000_000)).as_deref(),
            Some("4000000000"),
            "UInt32(4000000000) must display as \"4000000000\""
        );
        // UInt64
        assert_eq!(
            scalar_display(&V::UInt64(9_000_000_000)).as_deref(),
            Some("9000000000"),
            "UInt64(9000000000) must display as \"9000000000\""
        );
        // Double
        assert_eq!(
            scalar_display(&V::Double(1.5)).as_deref(),
            Some("1.5"),
            "Double(1.5) must display as \"1.5\""
        );
        // Name — Arc<str>
        assert_eq!(
            scalar_display(&V::Name("Foo".into())).as_deref(),
            Some("Foo"),
            "Name(\"Foo\") must display as \"Foo\""
        );
        // Unknown
        assert_eq!(
            scalar_display(&V::Unknown {
                type_name: "SomeType".to_string(),
                skipped_bytes: 42,
            })
            .as_deref(),
            Some("<SomeType: 42 bytes>"),
            "Unknown must display as <TypeName: N bytes>"
        );
        // Array (elements count summary)
        assert_eq!(
            scalar_display(&V::Array {
                inner_type: "IntProperty".into(),
                elements: vec![V::Int(1), V::Int(2)],
            })
            .as_deref(),
            Some("[2]"),
            "Array of 2 elements must display as \"[2]\""
        );
        // Set (elements count summary)
        assert_eq!(
            scalar_display(&V::Set {
                inner_type: "IntProperty".into(),
                elements: vec![V::Int(10), V::Int(20), V::Int(30)],
            })
            .as_deref(),
            Some("[3]"),
            "Set of 3 elements must display as \"[3]\""
        );
        // Map (entries count summary)
        assert_eq!(
            scalar_display(&V::Map {
                key_type: "IntProperty".into(),
                value_type: "StrProperty".into(),
                entries: vec![MapEntry {
                    key: V::Int(1),
                    value: V::Str("a".into()),
                }],
            })
            .as_deref(),
            Some("[1]"),
            "Map of 1 entry must display as \"[1]\""
        );
        // Struct (properties count summary)
        assert_eq!(
            scalar_display(&V::Struct {
                struct_name: "MyStruct".into(),
                properties: vec![],
            })
            .as_deref(),
            Some("[0]"),
            "Struct with 0 properties must display as \"[0]\""
        );
    }

    // ── B3: payload_bag Generic arm ───────────────────────────────────────────

    #[test]
    fn payload_bag_generic_returns_some() {
        use paksmith_core::asset::Asset;
        use paksmith_core::asset::property::PropertyBag;
        // An Asset::Generic with an empty Tree bag returns Some.
        // Kills `replace payload_bag -> Option<&PropertyBag> with None`
        // and `delete match arm Asset::Generic(bag)`.
        let bag = PropertyBag::tree(vec![]);
        let asset = Asset::Generic(bag);
        assert!(
            payload_bag(&asset).is_some(),
            "Asset::Generic must yield Some from payload_bag"
        );
    }

    // ── B4: push_value_row recursion via constructed Array/Map ───────────────

    #[test]
    fn push_value_row_array_expanded_emits_branch_and_elements() {
        use paksmith_core::asset::property::primitives::PropertyValue as V;

        let array_val = V::Array {
            inner_type: "IntProperty".into(),
            elements: vec![V::Int(10), V::Int(20)],
        };

        // Compute node_id for the array branch (same as push_value_row uses).
        let parent_id: NodeId = 42;
        let branch_id: NodeId = parent_id; // push_value_row receives node_id directly

        // Pre-build element node ids so we can add them to `expanded`.
        // push_value_row → flatten_value → element_node_id(branch_id, position)
        let elem0_id = element_node_id(branch_id, 0);
        let elem1_id = element_node_id(branch_id, 1);

        let mut expanded = HashSet::new();
        // Expand the branch so the elements are emitted.
        #[allow(unused_results)]
        expanded.insert(branch_id);

        let mut rows: Vec<PropRow> = Vec::new();
        push_value_row(
            &array_val,
            0,
            branch_id,
            "MyArray".to_string(),
            &mut rows,
            &expanded,
        );

        // 1 branch row + 2 element leaf rows
        assert_eq!(
            rows.len(),
            3,
            "expanded array must emit 1 branch + 2 leaves"
        );
        assert_eq!(rows[0].kind, PropKind::Branch, "first row must be a branch");
        assert_eq!(rows[1].kind, PropKind::Leaf, "second row must be a leaf");
        assert_eq!(rows[2].kind, PropKind::Leaf, "third row must be a leaf");

        // (b) Distinct node_ids for the two elements (kills element-position arithmetic mutants)
        assert_ne!(
            rows[1].node_id, rows[2].node_id,
            "element rows must have distinct node_ids"
        );
        // Confirm they match our expected ids.
        assert_eq!(rows[1].node_id, elem0_id);
        assert_eq!(rows[2].node_id, elem1_id);

        // (c) Element values render via scalar_display
        assert_eq!(
            rows[1].value.as_deref(),
            Some("10"),
            "first element must display as \"10\""
        );
        assert_eq!(
            rows[2].value.as_deref(),
            Some("20"),
            "second element must display as \"20\""
        );

        // (d) Element rows sit one level deeper than the branch — kills `child_depth` mutant.
        assert_eq!(rows[0].depth, 0, "branch row must be at depth 0");
        assert_eq!(
            rows[1].depth, 1,
            "array element must be at branch depth + 1"
        );
        assert_eq!(
            rows[2].depth, 1,
            "array element must be at branch depth + 1"
        );
    }

    #[test]
    fn push_value_row_map_expanded_emits_branch_key_value_rows() {
        use paksmith_core::asset::property::primitives::{MapEntry, PropertyValue as V};

        // Two-entry map: kills `i * 2` / `i * 2 + 1` arithmetic mutants by
        // making entry-1's key/value occupy positions 2/3, not 0/1.
        let map_val = V::Map {
            key_type: "IntProperty".into(),
            value_type: "StrProperty".into(),
            entries: vec![
                MapEntry {
                    key: V::Int(1),
                    value: V::Str("a".into()),
                },
                MapEntry {
                    key: V::Int(2),
                    value: V::Str("b".into()),
                },
            ],
        };

        let branch_id: NodeId = 99;
        // push_value_row uses element_node_id(node_id, i * 2) for key,
        // element_node_id(node_id, i * 2 + 1) for value.
        // entry 0: key @ position 0, value @ position 1
        // entry 1: key @ position 2, value @ position 3
        let key0_id = element_node_id(branch_id, 0); // 0 * 2
        let val0_id = element_node_id(branch_id, 1); // 0 * 2 + 1
        let key1_id = element_node_id(branch_id, 2); // 1 * 2
        let val1_id = element_node_id(branch_id, 3); // 1 * 2 + 1

        let mut expanded = HashSet::new();
        #[allow(unused_results)]
        expanded.insert(branch_id);

        let mut rows: Vec<PropRow> = Vec::new();
        push_value_row(
            &map_val,
            0,
            branch_id,
            "MyMap".to_string(),
            &mut rows,
            &expanded,
        );

        // 1 branch + 4 rows (2 entries × key + value)
        assert_eq!(
            rows.len(),
            5,
            "expanded 2-entry map must emit 1 branch + 4 leaf rows"
        );
        assert_eq!(rows[0].kind, PropKind::Branch);
        for r in &rows[1..5] {
            assert_eq!(r.kind, PropKind::Leaf);
        }

        // All four leaf node_ids are distinct — kills `i * 2` and `i * 2 + 1`
        // arithmetic mutants: e.g. `i / 2` would give entry-1.key position 0,
        // colliding with entry-0.key.
        let ids: std::collections::HashSet<NodeId> = rows[1..5].iter().map(|r| r.node_id).collect();
        assert_eq!(
            ids.len(),
            4,
            "all key/value node_ids across both entries must be distinct"
        );

        // Verify exact node_id positions match the formula.
        assert_eq!(rows[1].node_id, key0_id, "entry 0 key at position i*2=0");
        assert_eq!(
            rows[2].node_id, val0_id,
            "entry 0 value at position i*2+1=1"
        );
        assert_eq!(rows[3].node_id, key1_id, "entry 1 key at position i*2=2");
        assert_eq!(
            rows[4].node_id, val1_id,
            "entry 1 value at position i*2+1=3"
        );

        // Value rendering
        assert_eq!(
            rows[1].value.as_deref(),
            Some("1"),
            "entry 0 key must render as 1"
        );
        assert_eq!(
            rows[2].value.as_deref(),
            Some("\"a\""),
            "entry 0 value must render as \"a\""
        );
        assert_eq!(
            rows[3].value.as_deref(),
            Some("2"),
            "entry 1 key must render as 2"
        );
        assert_eq!(
            rows[4].value.as_deref(),
            Some("\"b\""),
            "entry 1 value must render as \"b\""
        );

        // key/value rows are one level deeper than the branch — kills `child_depth` mutant.
        assert_eq!(rows[0].depth, 0, "branch at depth 0");
        for r in &rows[1..5] {
            assert_eq!(r.depth, 1, "map key/value rows must be at branch depth + 1");
        }
    }

    #[test]
    fn flatten_export_row_label_contains_resolved_class_name() {
        // The Demo.uasset fixture has a single export whose class_index resolves
        // via the Import or Export table to "Default__Object". An exact-match
        // assertion on the full label kills:
        //   - `class_name -> String with "xyzzy"` (label becomes "[0] Default__Object : xyzzy")
        //   - `class_name -> String with String::new()` (label becomes "[0] Default__Object : ")
        // The PackageIndex::Null arm (which would produce ": Class") is genuinely
        // unreachable for this fixture; it is covered by an exclude_re entry.
        let pkg = demo_package();
        let rows = flatten(&pkg, &HashSet::new());
        assert!(!rows.is_empty(), "at least one export row from Demo.uasset");
        assert_eq!(
            rows[0].label, "[0] Default__Object : Default__Object",
            "export row label must include the resolved class name; got {:?}",
            rows[0].label
        );
    }

    #[test]
    fn push_value_row_collapsed_branch_emits_only_branch_row() {
        use paksmith_core::asset::property::primitives::PropertyValue as V;

        let array_val = V::Array {
            inner_type: "IntProperty".into(),
            elements: vec![V::Int(1), V::Int(2)],
        };

        let branch_id: NodeId = 7;
        // Empty expanded set → branch is collapsed.
        let mut rows: Vec<PropRow> = Vec::new();
        push_value_row(
            &array_val,
            0,
            branch_id,
            "MyArray".to_string(),
            &mut rows,
            &HashSet::new(),
        );

        // Only the branch row, no child rows.
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, PropKind::Branch);
        assert!(!rows[0].expanded);
        assert!(rows[0].is_expandable);
    }
}
