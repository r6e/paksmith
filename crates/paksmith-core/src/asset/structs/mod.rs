//! Typed decoders for UE engine structs that use custom binary
//! serialization (rather than tagged-property iteration).
//!
//! Phase 3c replaces Phase 2g's empty-`PropertyBag::Struct` fallback
//! for the dominant engine structs (`FVector`, `FRotator`, `FQuat`,
//! `FColor`, `FLinearColor`, `FBox`, `FTransform`,
//! `FBoxSphereBounds` + LWC and 2D / 4D variants) with typed Rust
//! structs that decode their custom-binary wire layouts.
//!
//! See `docs/plans/phase-3c-typed-binary-structs.md`.
//!
//! # Surface
//!
//! - [`TypedStructValue`] — tagged enum carrying one of the typed
//!   decoded values. Wrapped in `Box` inside
//!   `PropertyValue::TypedStruct` (the boxing keeps the per-
//!   `PropertyValue` enum size small — see Design Decision #1 in
//!   the plan).
//! - `lookup` (crate-private) — registry-driven lookup of a decoder
//!   by struct name. Returns `None` for unknown structs; callers
//!   fall back to Phase 2g's tagged-property iteration.
//!
//! # Adding a new struct
//!
//! 1. Create `asset/structs/<name>.rs` with a `pub struct F<Name> {
//!    ... }` and `pub fn read_f<name>(reader, ctx, expected_end,
//!    asset_path) -> Result<TypedStructValue>`.
//! 2. Add a variant to [`TypedStructValue`].
//! 3. Register the decoder in the inline closure inside `registry`
//!    under the wire-format struct name (without `F` prefix — UE
//!    wire-format omits it).

// Task 1 skeleton: the registry + decoder-fn-pointer infrastructure
// is dead until Task 10 wires `lookup` into
// `containers.rs::read_struct_value`. Module-level allow collapses
// five per-item annotations; lifts cleanly when Task 10 lands.
#![allow(
    dead_code,
    reason = "Phase 3c Task 1 ships the registry skeleton; Tasks 2-9 populate it, Task 10 wires `lookup` into the property-tree dispatcher"
)]

use std::io::{Read, Seek};

// Submodules added in Tasks 2-9:
// pub mod vector;
// pub mod rotator;
// pub mod quat;
// pub mod color;
// pub mod box_;
// pub mod transform;
// pub mod bounds;

/// Tagged value carrying one of the implemented engine structs.
///
/// `#[non_exhaustive]` — Phase 3 follow-ups add variants without a
/// SemVer-major bump (one variant per added engine struct).
///
/// Serialized via `#[serde(tag = "type")]` so the discriminant lives
/// inside the typed object: `{"type": "Vector", "x": 1.0, "y": 2.0,
/// "z": 3.0}`. The outer `PropertyValue` enum is externally tagged
/// (serde default), so the full JSON path is
/// `{"TypedStruct": {"type": "Vector", "x": 1.0, ...}}` — outer
/// external tag, inner internal tag. The inner internal tag keeps
/// each variant's payload flat (no `"content": {...}` nesting layer).
///
/// **`Deserialize` is derived alongside `Serialize`.** This differs
/// from peer types like [`crate::asset::Asset`] which are
/// `Serialize`-only (their JSON shape is intentionally lossy for
/// human consumption). `TypedStructValue` round-trips cleanly
/// because each typed variant's wire shape is a fixed bag of
/// numeric fields with no resolved-FName / index-rewritten state,
/// AND because the parent [`crate::PropertyValue`] enum already
/// derives `Deserialize` (which the existing
/// `serde_json::from_str::<PropertyBag>` tests in
/// `property/bag.rs` depend on). Dropping `Deserialize` here
/// would propagate up and break those round-trip tests.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum TypedStructValue {
    // Stubs — populated in Tasks 2-9 as each decoder lands.
}

/// Trait alias for the `Read + Seek` bound the decoders share.
///
/// Decoders take `&mut dyn ReadAndSeek` so the registry can carry
/// function pointers (untyped over the concrete reader); without
/// this alias the function pointer type would have to spell
/// `&mut (dyn Read + Seek)`, which is a less-readable form.
///
/// `pub(crate)` so it matches the visibility of [`DecoderFn`] /
/// [`lookup`]; consumers outside `paksmith-core` reach decoders by
/// the concrete per-struct entry points (3g/3h pattern).
pub(crate) trait ReadAndSeek: Read + Seek {}
impl<T: Read + Seek> ReadAndSeek for T {}

/// Function-pointer signature for a typed-struct decoder. All
/// decoders share this shape so the registry can store them by
/// reference.
///
/// - `reader` — the export-payload byte stream, positioned at the
///   start of the struct's binary body.
/// - `ctx` — `AssetContext` for version gating (UE5 LWC width
///   dispatch) and name resolution.
/// - `expected_end` — the absolute byte offset the decoder MUST
///   reach. Decoders verify-at-end via this value (see Task 2's
///   `read_fvector` for the canonical pattern).
/// - `asset_path` — for error reporting only.
pub(crate) type DecoderFn = fn(
    &mut dyn ReadAndSeek,
    &crate::asset::AssetContext,
    u64,
    &str,
) -> crate::Result<TypedStructValue>;

/// Look up the typed-struct decoder for `struct_name`. Returns
/// `None` if the struct isn't in the registry (caller falls back
/// to Phase 2g's tagged-property iteration).
///
/// The lookup key is the wire-format struct name from
/// `FPropertyTag::struct_name`, which omits the leading `F` (e.g.
/// `"Vector"`, NOT `"FVector"`).
///
/// `pub(crate)` because the registry is an implementation detail
/// of the property dispatcher in `containers.rs::read_struct_value`;
/// downstream sub-phases (3g/3h) call the per-struct `read_f*`
/// decoders directly, not through the registry.
#[must_use]
pub(crate) fn lookup(struct_name: &str) -> Option<DecoderFn> {
    registry().get(struct_name).copied()
}

fn registry() -> &'static std::collections::HashMap<&'static str, DecoderFn> {
    static TABLE: std::sync::OnceLock<std::collections::HashMap<&'static str, DecoderFn>> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        // Populated by Tasks 2-9:
        // table.insert("Vector",            vector::read_fvector);
        // table.insert("Vector2D",          vector::read_fvector2d);
        // table.insert("Vector4",           vector::read_fvector4);
        // table.insert("Rotator",           rotator::read_frotator);
        // table.insert("Quat",              quat::read_fquat);
        // table.insert("Color",             color::read_fcolor);
        // table.insert("LinearColor",       color::read_flinearcolor);
        // table.insert("Box",               box_::read_fbox);
        // table.insert("Box2D",             box_::read_fbox2d);
        // table.insert("Transform",         transform::read_ftransform);
        // table.insert("BoxSphereBounds",   bounds::read_fboxspherebounds);
        std::collections::HashMap::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_unknown_returns_none() {
        // Phase 3c's registry contract: unknown struct names map to
        // `None` so the caller can fall through to Phase 2g's
        // tagged-property iteration. Pins the "unknown" path even
        // before any decoder is registered.
        assert!(lookup("UnknownStruct").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn registry_starts_empty() {
        // 3c Task 1 ships the skeleton with zero registered
        // decoders; Tasks 2-9 each add one entry. This assertion
        // will need bumping per-task as the registry grows.
        // Task 10's integration test pins the final count of 11.
        assert_eq!(registry().len(), 0);
    }
}
