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
//!    ... }`, a `pub fn read_from(...) -> Result<Self>`, and a
//!    `pub(crate) fn read_f<name>(reader, ctx, expected_end,
//!    asset_path) -> Result<TypedStructValue>` registry shim.
//! 2. Add a variant to [`TypedStructValue`].
//! 3. Register the shim in the inline closure inside `registry`
//!    under the wire-format struct name (without `F` prefix — UE
//!    wire-format omits it).
//!
//! **Exception — unregistered building blocks.** A struct whose bare
//! wire name is *tagged-serialized* (its fields written as nested
//! NTPL sub-properties, not a custom-binary blob — verify against
//! CUE4Parse / UAssetAPI) must NOT be registered: real instances fall
//! through to Phase 2g tagged iteration, and a binary decoder here
//! would misparse them. Such a struct ships only the `pub struct` +
//! `read_from` + a [`TypedStructValue`] variant (skip the `read_f*`
//! shim — it would be permanently dead code, since the shim exists
//! solely to feed the registry). `read_from` stays as a direct
//! building block for the native-serialized-array contexts (e.g.
//! mesh bone poses) that 3g/3h decode. `transform` is the canonical
//! example.

// Task 10 wired `lookup` into `containers.rs::read_struct_property`,
// so the registry + decoder-fn-pointer infrastructure is now live —
// the Task-1-era module-level `#![allow(dead_code)]` is gone. The
// `FTransform` / `FBoxSphereBounds` `read_from` building blocks stay
// reachable as public API (3g/3h call them directly); their structs
// are unregistered by design (tagged-serialized — see each module).

use std::cmp::Ordering;
use std::io::{Read, Seek};

use crate::PaksmithError;
use crate::error::{AssetParseFault, AssetWireField};

pub mod bounds;
pub mod box_;
pub mod color;
pub mod quat;
pub mod rotator;
pub mod transform;
pub mod vector;

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
    /// `FVector` — 3D float vector. UE4 = f32×3 (12 bytes), UE5
    /// LWC = f64×3 (24 bytes). Wire name: `"Vector"`. Phase 3c
    /// Task 2.
    Vector(vector::FVector),
    /// `FVector2D` — 2D float vector (UVs, screen positions).
    /// UE4 = f32×2 (8 bytes), UE5 LWC = f64×2 (16 bytes). Wire
    /// name: `"Vector2D"`. Phase 3c Task 3.
    Vector2D(vector::FVector2D),
    /// `FVector4` — 4D float vector (tangents, colors-as-vec4).
    /// UE4 = f32×4 (16 bytes), UE5 LWC = f64×4 (32 bytes). Wire
    /// name: `"Vector4"`. Phase 3c Task 3.
    Vector4(vector::FVector4),
    /// `FRotator` — Euler-angle rotation (pitch, yaw, roll in
    /// wire order). UE4 = f32×3 (12 bytes), UE5 LWC = f64×3 (24
    /// bytes). Wire name: `"Rotator"`. Phase 3c Task 4.
    Rotator(rotator::FRotator),
    /// `FQuat` — quaternion (x, y, z, w wire order; identity is
    /// `(0, 0, 0, 1)`). UE4 = f32×4 (16 bytes), UE5 LWC = f64×4
    /// (32 bytes). Wire name: `"Quat"`. Phase 3c Task 5.
    Quat(quat::FQuat),
    /// `FColor` — 32-bit sRGB color, 4 × u8. Wire order BGRA,
    /// stored RGBA (swizzled on decode). Fixed 4 bytes (NOT
    /// LWC-widened). Wire name: `"Color"`. Phase 3c Task 6.
    Color(color::FColor),
    /// `FLinearColor` — linear-space color, 4 × f32 RGBA. Fixed
    /// 16 bytes (NOT LWC-widened). Wire name: `"LinearColor"`.
    /// Phase 3c Task 6.
    LinearColor(color::FLinearColor),
    /// `FBox` — axis-aligned 3D bounding box (`min`/`max` FVector +
    /// `is_valid` u8). UE4 = 25 bytes, UE5 LWC = 49 bytes. Wire
    /// name: `"Box"`. Phase 3c Task 7.
    Box(box_::FBox),
    /// `FBox2D` — axis-aligned 2D bounding box (`min`/`max`
    /// FVector2D + `is_valid` u8). UE4 = 17 bytes, UE5 LWC = 33
    /// bytes. Wire name: `"Box2D"`. Phase 3c Task 7.
    Box2D(box_::FBox2D),
    /// `FTransform` — rotation (FQuat) + translation (FVector) +
    /// scale (FVector). UE4 = 40 bytes, UE5 LWC = 80 bytes.
    /// **Not registered in the dispatch table:** a `"Transform"`
    /// StructProperty is tagged-serialized, so it falls through to
    /// Phase 2g. This binary layout appears only in native-serialized
    /// arrays (bone poses, instanced meshes) that 3g/3h decode via
    /// [`transform::FTransform::read_from`] directly. Phase 3c Task 8.
    Transform(transform::FTransform),
    /// `FBoxSphereBounds` — origin (FVector) + box_extent (FVector) +
    /// sphere_radius (LWC scalar). UE4 = 28 bytes, UE5 LWC = 56 bytes.
    /// **Not registered in the dispatch table:** a `"BoxSphereBounds"`
    /// StructProperty is tagged-serialized, so it falls through to
    /// Phase 2g. This binary layout appears as a native-serialized
    /// field (mesh `ImportedBounds`) that 3g/3h decode via
    /// [`bounds::FBoxSphereBounds::read_from`] directly. Phase 3c Task 9.
    BoxSphereBounds(bounds::FBoxSphereBounds),
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
/// of the property dispatcher in `containers.rs::read_struct_property`;
/// downstream sub-phases (3g/3h) call the per-struct `read_f*`
/// decoders directly, not through the registry.
#[must_use]
pub(crate) fn lookup(struct_name: &str) -> Option<DecoderFn> {
    registry().get(struct_name).copied()
}

/// Verify a Phase 3c typed-struct decoder's post-read stream
/// position matches the parent property's declared `expected_end`.
/// Shared by every decoder in this module (`vector`, `rotator`,
/// `quat`, `color`, `box_`, `transform`, `bounds`).
///
/// - `Ordering::Equal` → `Ok(())`.
/// - `Ordering::Less` → [`AssetParseFault::TypedStructTrailingBytes`]
///   (soft — version mismatch where a newer UE release added
///   trailing fields).
/// - `Ordering::Greater` → [`AssetParseFault::TypedStructOverrun`]
///   (hard — decoder consumed bytes belonging to the next
///   property; property-tree bounds are corrupted).
///
/// A failure to query the stream position itself surfaces as
/// `UnexpectedEof { field: TypedStructPosition }` — practically
/// unreachable (`Cursor` / `File` `stream_position` don't fail),
/// but the typed `AssetWireField` is neutral across decoders so
/// a future Tasks 5-9 caller never sees a misrouted struct-specific
/// field.
pub(crate) fn verify_at_end<R: Seek + ?Sized>(
    reader: &mut R,
    expected_end: u64,
    struct_name: &'static str,
    asset_path: &str,
) -> crate::Result<()> {
    let pos = stream_pos(reader, asset_path)?;
    match pos.cmp(&expected_end) {
        Ordering::Equal => Ok(()),
        Ordering::Less => Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TypedStructTrailingBytes {
                struct_name,
                trailing: expected_end - pos,
            },
        }),
        Ordering::Greater => Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::TypedStructOverrun {
                struct_name,
                overrun: pos - expected_end,
            },
        }),
    }
}

fn typed_struct_position_error(asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof {
            field: AssetWireField::TypedStructPosition,
        },
    }
}

/// Per-component byte width for the LWC-dispatched vector families:
/// f64 (8 bytes) at UE5 LWC, f32 (4 bytes) for UE4 — the size
/// counterpart to `read_lwc_components`'s `is_lwc()` read branch
/// (both gate on the same `is_lwc()`; this returns the byte width
/// the other consumes by reading the float type). The vector
/// types' `wire_size` methods multiply it by their component count
/// so composing decoders (`FBox`, `FTransform`, …) can bound nested
/// reads; Task 9's `FBoxSphereBounds` also uses it directly for its
/// LWC-widened `sphere_radius` scalar.
pub(crate) fn lwc_component_width(ctx: &crate::asset::AssetContext) -> u64 {
    if ctx.version.is_lwc() { 8 } else { 4 }
}

/// Read a trailing `u8` boolean flag (e.g. `FBox` / `FBox2D`'s
/// `is_valid`), mapping EOF to the decoder's
/// `TypedStructComponent` fault. UE stores these as a raw byte and
/// treats any non-zero value as `true` (permissive — confirmed
/// against CUE4Parse `FBox.cs`, which reads `Ar.Read<byte>()` with
/// no strict 0/1 rejection); paksmith mirrors that.
pub(crate) fn read_bool_u8<R: Read + ?Sized>(
    reader: &mut R,
    struct_name: &'static str,
    asset_path: &str,
) -> crate::Result<bool> {
    use byteorder::ReadBytesExt;
    let byte = reader.read_u8().map_err(|_| {
        component_eof(
            AssetWireField::TypedStructComponent { struct_name },
            asset_path,
        )
    })?;
    Ok(byte != 0)
}

/// Query the reader's current absolute byte offset, mapping the
/// (practically-unreachable) `stream_position` failure to the
/// neutral `TypedStructPosition` EOF fault.
///
/// Used by composing decoders (`FBox`, `FBox2D`, and Task 8/9's
/// `FTransform` / `FBoxSphereBounds`) that read nested
/// vector-family structs and need the start offset to compute each
/// child's `expected_end` boundary. Also backs [`verify_at_end`].
pub(crate) fn stream_pos<R: Seek + ?Sized>(reader: &mut R, asset_path: &str) -> crate::Result<u64> {
    reader
        .stream_position()
        .map_err(|_| typed_struct_position_error(asset_path))
}

/// Read `N` little-endian components from `reader`, dispatched by
/// `ctx.version.is_lwc()`: UE5 LWC reads `f64` (8 bytes each), UE4
/// reads `f32` (4 bytes each) and widens losslessly. Shared by every
/// vector-family decoder (Tasks 2-9) — centralizes the `is_lwc`
/// branch so the mutation surface is one site, not N.
///
/// Components are returned in wire order. Caller destructures into
/// named fields (e.g. `let [x, y, z] = read_lwc_components::<R, 3>(...)?`).
pub(crate) fn read_lwc_components<R: Read + ?Sized, const N: usize>(
    reader: &mut R,
    ctx: &crate::asset::AssetContext,
    field: AssetWireField,
    asset_path: &str,
) -> crate::Result<[f64; N]> {
    use byteorder::{LittleEndian, ReadBytesExt};
    let mut out = [0.0_f64; N];
    if ctx.version.is_lwc() {
        for slot in &mut out {
            *slot = reader
                .read_f64::<LittleEndian>()
                .map_err(|_| component_eof(field, asset_path))?;
        }
    } else {
        for slot in &mut out {
            let v = reader
                .read_f32::<LittleEndian>()
                .map_err(|_| component_eof(field, asset_path))?;
            *slot = f64::from(v);
        }
    }
    Ok(out)
}

/// Build the `UnexpectedEof { field }` fault a typed-struct decoder
/// raises when a per-component read hits end-of-stream. Shared by
/// [`read_lwc_components`] and the non-LWC decoders (e.g. `FColor`'s
/// u8 reads, `FLinearColor`'s always-f32 reads) so every decoder
/// routes EOF through the same `AssetWireField::TypedStructComponent`
/// tagging.
pub(crate) fn component_eof(field: AssetWireField, asset_path: &str) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    }
}

/// Vector-family decoder convenience wrapper: builds the
/// `AssetWireField::TypedStructComponent { struct_name }` field for
/// you and dispatches to [`read_lwc_components`]. Saves ~4 lines per
/// decoder call site across the vector-family (FVector, FVector2D,
/// FVector4, FRotator, FQuat — and Tasks 6-9 siblings that take the
/// same shape).
///
/// Non-vector-family Tasks 6-9 callers that want a different EOF
/// tag (e.g. an FBox decoder calling `read_lwc_components` directly
/// with a custom field) should bypass this wrapper.
pub(crate) fn read_components<R: Read + ?Sized, const N: usize>(
    reader: &mut R,
    ctx: &crate::asset::AssetContext,
    struct_name: &'static str,
    asset_path: &str,
) -> crate::Result<[f64; N]> {
    read_lwc_components::<R, N>(
        reader,
        ctx,
        AssetWireField::TypedStructComponent { struct_name },
        asset_path,
    )
}

/// Shared test helpers for the Phase 3c decoder modules. Hoisted
/// here (instead of being duplicated in each `<struct>.rs::tests`
/// block) so Tasks 5-9's siblings can `use super::test_utils` and
/// avoid re-rolling the same wire-byte builders.
#[cfg(test)]
pub(super) mod test_utils {
    /// Build the wire-form bytes for a UE4 f32 vector of any arity.
    /// Slice-taking — scales across all vector-family decoders
    /// (FVector, FVector2D, FVector4, FRotator, FQuat, FBox, …).
    pub fn f32_bytes(components: &[f32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(components.len() * 4);
        for c in components {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    /// Build the wire-form bytes for a UE5 LWC f64 vector of any
    /// arity. Sibling of [`f32_bytes`].
    pub fn f64_bytes(components: &[f64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(components.len() * 8);
        for c in components {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }
}

fn registry() -> &'static std::collections::HashMap<&'static str, DecoderFn> {
    static TABLE: std::sync::OnceLock<std::collections::HashMap<&'static str, DecoderFn>> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: std::collections::HashMap<&'static str, DecoderFn> =
            std::collections::HashMap::new();
        // Phase 3c Task 2:
        let _ = table.insert("Vector", vector::read_fvector);
        // Phase 3c Task 3:
        let _ = table.insert("Vector2D", vector::read_fvector2d);
        let _ = table.insert("Vector4", vector::read_fvector4);
        // Phase 3c Task 4:
        let _ = table.insert("Rotator", rotator::read_frotator);
        // Phase 3c Task 5:
        let _ = table.insert("Quat", quat::read_fquat);
        // Phase 3c Task 6:
        let _ = table.insert("Color", color::read_fcolor);
        let _ = table.insert("LinearColor", color::read_flinearcolor);
        // Phase 3c Task 7:
        let _ = table.insert("Box", box_::read_fbox);
        let _ = table.insert("Box2D", box_::read_fbox2d);
        // Phase 3c Task 8: `FTransform` ships as a direct building
        // block but registers NOTHING here — `"Transform"` is
        // tagged-serialized and must fall through to Phase 2g. Full
        // rationale + reference-parser provenance lives on the
        // `transform` module docs. Task 9's `FBoxSphereBounds` is the
        // same case.
        table
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_unknown_returns_none() {
        // Phase 3c's registry contract: unknown struct names map to
        // `None` so the caller can fall through to Phase 2g's
        // tagged-property iteration.
        assert!(lookup("UnknownStruct").is_none());
        assert!(lookup("").is_none());
        // Specifically pin the F-prefix-stripped convention: the
        // wire name is `"Vector"`, not `"FVector"`. A future
        // refactor that registered under the F-prefixed name would
        // silently fail the dispatch — this assertion catches it.
        assert!(
            lookup("FVector").is_none(),
            "registry key must NOT include the F prefix"
        );
    }

    #[test]
    fn lookup_vector_returns_decoder() {
        // Positive-lookup pin — the Task 2 entry must dispatch
        // `"Vector"` to a Some(_) decoder. Replaces Task 1's
        // empty-registry mutants exclusion: the `lookup -> None`
        // whole-function mutant now fails this test.
        assert!(
            lookup("Vector").is_some(),
            "Task 2 must register a decoder under wire name `\"Vector\"`"
        );
    }

    #[test]
    fn registry_stays_nine_entries_after_task_9() {
        // Tasks 8 AND 9 each ship a decoder (`FTransform`,
        // `FBoxSphereBounds`) but register NOTHING: both serialize as
        // tagged sub-properties under their bare wire names, so they
        // must fall through to Phase 2g — registering a binary decoder
        // would silently misparse them once Task 10 wires `lookup`
        // into the dispatcher. Verified against CUE4Parse (both hit
        // the `FStructFallback` default arm) + UAssetAPI (binary
        // PropertyData for every sibling math type, neither of these).
        // The count therefore holds at the Task 7 nine — this is the
        // final Phase 3c registered count (Task 10 pins it).
        assert_eq!(registry().len(), 9);
    }

    #[test]
    fn registry_contains_exactly_the_nine_registered_names() {
        // Phase 3c Task 11 — the single authoritative "exactly these 9,
        // no more, no fewer" pin. Count + exact key set together catch
        // both an accidental drop and an accidental add (e.g. a future
        // edit that registers the tagged-serialized Transform /
        // BoxSphereBounds, or an explicit-precision `3f`/`3d` variant).
        let r = registry();
        let expected = [
            "Vector",
            "Vector2D",
            "Vector4",
            "Rotator",
            "Quat",
            "Color",
            "LinearColor",
            "Box",
            "Box2D",
        ];
        assert_eq!(r.len(), expected.len());
        for name in expected {
            assert!(r.contains_key(name), "missing registered decoder: {name}");
        }
        // The unregistered building blocks must NOT be keys.
        assert!(!r.contains_key("Transform"));
        assert!(!r.contains_key("BoxSphereBounds"));
    }

    #[test]
    fn lookup_vector2d_and_vector4_return_decoders() {
        // Pin the F-prefix-stripped wire names for the two Task 3
        // siblings. Mirrors `lookup_vector_returns_decoder`.
        assert!(lookup("Vector2D").is_some());
        assert!(lookup("Vector4").is_some());
        // Negative pin — F-prefixed names must NOT dispatch.
        assert!(lookup("FVector2D").is_none());
        assert!(lookup("FVector4").is_none());
    }

    #[test]
    fn lookup_rotator_returns_decoder() {
        // Phase 3c Task 4 — pin the FRotator dispatch.
        assert!(lookup("Rotator").is_some());
        assert!(
            lookup("FRotator").is_none(),
            "wire name strips the F prefix; FRotator must NOT dispatch"
        );
    }

    #[test]
    fn lookup_quat_returns_decoder() {
        // Phase 3c Task 5 — pin the FQuat dispatch.
        assert!(lookup("Quat").is_some());
        assert!(
            lookup("FQuat").is_none(),
            "wire name strips the F prefix; FQuat must NOT dispatch"
        );
    }

    #[test]
    fn lookup_color_and_linearcolor_return_decoders() {
        // Phase 3c Task 6 — pin the FColor / FLinearColor dispatch.
        assert!(lookup("Color").is_some());
        assert!(lookup("LinearColor").is_some());
        // Negative pins — F-prefixed names must NOT dispatch.
        assert!(lookup("FColor").is_none());
        assert!(lookup("FLinearColor").is_none());
    }

    #[test]
    fn lookup_box_and_box2d_return_decoders() {
        // Phase 3c Task 7 — pin the FBox / FBox2D dispatch.
        assert!(lookup("Box").is_some());
        assert!(lookup("Box2D").is_some());
        // Negative pins — F-prefixed names must NOT dispatch.
        assert!(lookup("FBox").is_none());
        assert!(lookup("FBox2D").is_none());
    }

    #[test]
    fn lookup_transform_is_deliberately_unregistered() {
        // Phase 3c Task 8 — `FTransform` is NOT in the dispatch
        // registry by design. A `"Transform"` StructProperty
        // serializes as tagged sub-properties (Rotation / Translation
        // / Scale3D), so it must fall through to Phase 2g's
        // tagged-property iteration; a binary decoder here would
        // silently misparse it. Verified against CUE4Parse (bare
        // `"Transform"` → `FStructFallback`) and UAssetAPI (no
        // binary Transform PropertyData). This negative pin guards
        // against a future regression that re-adds the registration.
        assert!(
            lookup("Transform").is_none(),
            "Transform is tagged-serialized; it must NOT be in the binary dispatch registry"
        );
        // The explicit-float `"Transform3f"` (raw-array binary) and
        // F-prefixed names are likewise absent.
        assert!(lookup("Transform3f").is_none());
        assert!(lookup("FTransform").is_none());
    }

    #[test]
    fn lookup_boxspherebounds_is_deliberately_unregistered() {
        // Phase 3c Task 9 — `FBoxSphereBounds` is NOT in the dispatch
        // registry by design, same as `FTransform`. A bare
        // `"BoxSphereBounds"` StructProperty is tagged-serialized, so
        // it must fall through to Phase 2g; a binary decoder here
        // would silently misparse it. Verified against CUE4Parse (no
        // `"BoxSphereBounds"` dispatch arm → `FStructFallback`) and
        // UAssetAPI (no BoxSphereBounds PropertyData). The binary
        // layout is reached only via `FBoxSphereBounds::read_from`
        // (mesh `ImportedBounds`). This negative pin guards against a
        // future regression that re-adds the registration.
        assert!(
            lookup("BoxSphereBounds").is_none(),
            "BoxSphereBounds is tagged-serialized; it must NOT be in the binary dispatch registry"
        );
        // F-prefixed name likewise absent (wire strips the F).
        assert!(lookup("FBoxSphereBounds").is_none());
    }

    #[test]
    fn typed_struct_value_vector_serde_round_trip_ue4() {
        // Pins the documented "Deserialize round-trips cleanly"
        // claim on `TypedStructValue` (see docstring on the enum):
        // `to_string` → `from_str` produces the same `Vector(v)`.
        // UE4 wire values (whole numbers — no float-precision
        // concerns in the JSON text).
        let value = TypedStructValue::Vector(vector::FVector {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        });
        let json = serde_json::to_string(&value).expect("serialize");
        // Inner internal tag → `{"type": "Vector", ...}`.
        assert!(
            json.contains(r#""type":"Vector""#),
            "expected internal-tag `\"type\":\"Vector\"`, got {json}"
        );
        let parsed: TypedStructValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, value);
    }

    #[test]
    fn typed_struct_value_vector_serde_round_trip_ue5_lwc() {
        // UE5 LWC values that wouldn't round-trip through an
        // intermediate f32 (`1e10` has no f32 representation that
        // round-trips through f64). Pins the f64 surface end-to-end.
        let value = TypedStructValue::Vector(vector::FVector {
            x: 1.0e10,
            y: -2.5e-7,
            z: 9.876_543_210_123_456,
        });
        let json = serde_json::to_string(&value).expect("serialize");
        let parsed: TypedStructValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, value);
    }
}
