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

/// Maximum tree render depth. Bounds recursion against deeply nested
/// crafted assets even though core already caps parse depth.
pub const MAX_RENDER_DEPTH: usize = 64;

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
        PropertyValue::Text(_) => Some("<text>".to_string()),
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
                Some("null".to_string())
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
        // `PropertyValue` is #[non_exhaustive] — TypedStruct + unknown future variants.
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
#[allow(
    clippy::too_many_lines,
    reason = "property-type dispatch — one arm per UE container variant; \
              splitting would obscure the per-type recursion structure"
)]
fn flatten_property(
    prop: &Property,
    depth: usize,
    parent_id: NodeId,
    rows: &mut Vec<PropRow>,
    expanded: &HashSet<NodeId>,
) {
    if depth > MAX_RENDER_DEPTH {
        return;
    }

    let node_id = child_node_id(parent_id, prop.name(), prop.array_index);
    let is_exp = expanded.contains(&node_id);

    match &prop.value {
        PropertyValue::Struct {
            struct_name,
            properties,
        } => {
            let label = format!("{} ({})", prop.name(), struct_name);
            rows.push(PropRow {
                depth,
                label,
                value: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for child in properties {
                    flatten_property(child, depth + 1, node_id, rows, expanded);
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
            let label = format!("{} [{inner_type}] ({} items)", prop.name(), elements.len());
            rows.push(PropRow {
                depth,
                label,
                value: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, elem) in elements.iter().enumerate() {
                    flatten_value(elem, depth + 1, node_id, i, rows, expanded);
                }
            }
        }
        PropertyValue::Map {
            key_type,
            value_type,
            entries,
        } => {
            let label = format!(
                "{} [{key_type} → {value_type}] ({} entries)",
                prop.name(),
                entries.len()
            );
            rows.push(PropRow {
                depth,
                label,
                value: None,
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, entry) in entries.iter().enumerate() {
                    // Key
                    let key_id = element_node_id(node_id, i * 2);
                    let key_label = format!("[{i}].key");
                    push_value_row(&entry.key, depth + 1, key_id, key_label, rows, expanded);
                    // Value
                    let val_id = element_node_id(node_id, i * 2 + 1);
                    let val_label = format!("[{i}].value");
                    push_value_row(&entry.value, depth + 1, val_id, val_label, rows, expanded);
                }
            }
        }
        other => {
            // Scalar leaf.
            rows.push(PropRow {
                depth,
                label: prop.name().to_string(),
                value: scalar_display(other),
                node_id,
                is_expandable: false,
                expanded: false,
                kind: PropKind::Leaf,
            });
        }
    }
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
    if depth > MAX_RENDER_DEPTH {
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
    if depth > MAX_RENDER_DEPTH {
        return;
    }
    let is_exp = expanded.contains(&node_id);

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
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for child in properties {
                    flatten_property(child, depth + 1, node_id, rows, expanded);
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
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, elem) in elements.iter().enumerate() {
                    flatten_value(elem, depth + 1, node_id, i, rows, expanded);
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
                node_id,
                is_expandable: true,
                expanded: is_exp,
                kind: PropKind::Branch,
            });
            if is_exp {
                for (i, entry) in entries.iter().enumerate() {
                    let key_id = element_node_id(node_id, i * 2);
                    let key_label = format!("[{i}].key");
                    push_value_row(&entry.key, depth + 1, key_id, key_label, rows, expanded);
                    let val_id = element_node_id(node_id, i * 2 + 1);
                    let val_label = format!("[{i}].value");
                    push_value_row(&entry.value, depth + 1, val_id, val_label, rows, expanded);
                }
            }
        }
        other => {
            rows.push(PropRow {
                depth,
                label,
                value: scalar_display(other),
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
}
