# Paksmith Phase 3c: Typed engine struct decoders

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}`.

**Goal:** Replace Phase 2g's empty-`PropertyBag::Struct` fallback for the seven core UE engine structs that use **custom binary serialization** (rather than tagged-property iteration) with typed decoders. Per `phase-2g-collection-of-struct.md` §Scope vs deferred work: "Custom-binary engine struct readers (FVector, FColor, FBox, FQuat, ~100 engine types). These structs use binary serialization, not tagged-property iteration. ... Decoding custom-binary structs into typed fields belongs in Phase 3+."

This plan ships **eleven decoders** (FVector + FVector2D + FVector4 + FRotator + FQuat + FColor + FLinearColor + FBox + FBox2D + FTransform + FBoxSphereBounds), chosen because (a) they're the dominant custom-binary structs in cooked content and (b) 3g/3h require `FVector` / `FQuat` / `FBox` / `FTransform` / `FBoxSphereBounds` to lower `StaticMesh`/`SkeletalMesh` vertex/bounds data into glTF accessors. `FBoxSphereBounds` is the 11th decoder, promoted in-scope (vs. R1's deferral) so 3g/3h have a typed `bounds` field without falling through to opaque property-bag.

**Architecture:** New module `asset/structs/` (per Phase 3 master-index module layout) housing one file per struct. Each file defines a typed Rust struct + `read_from(reader, ctx, expected_end) -> Result<Self>` constructor. A central dispatcher in `containers.rs::read_struct_value` consults a `StructTypeRegistry` that maps `struct_name: &str` to the typed decoder; on hit, the decoder runs and the result wraps as `PropertyValue::TypedStruct(TypedStructValue)`; on miss, the existing Phase 2g tagged-property iteration runs (no regression for non-engine structs).

**Tech Stack:** Same as Phase 2g. No new workspace dependencies.

---

## Deliverable

Phase 2g's empty-properties fallback for engine structs:

```json
{
  "name": "Bounds",
  "value": {
    "Struct": {
      "struct_name": "Box",
      "properties": []
    }
  }
}
```

becomes a typed decoded value:

```json
{
  "name": "Bounds",
  "value": {
    "TypedStruct": {
      "Box": {
        "min": { "x": -50.0, "y": -50.0, "z": -50.0 },
        "max": { "x":  50.0, "y":  50.0, "z":  50.0 },
        "is_valid": true
      }
    }
  }
}
```

The wire-stable JSON shape matches the existing `inspect_json_snapshot` precedent — typed structs surface as `PropertyValue::TypedStruct { ... }` with the discriminant carrying the struct kind.

---

## Scope vs deferred work

**In scope (Phase 3c — seven decoders):**

| Struct | Bytes (UE4) | Bytes (UE5 LWC) | Wire shape | Used by |
|--------|-------------|-----------------|------------|---------|
| `FVector` / `FVector3f` | 12 | 24 (f64×3) | 3 × f32/f64 | Mesh vertices, transforms |
| `FVector2D` | 8 | 16 (f64×2) | 2 × f32/f64 | UVs, screen positions |
| `FVector4` | 16 | 32 (f64×4) | 4 × f32/f64 | Tangents, colors-as-vec4 |
| `FRotator` | 12 | 24 (f64×3) | 3 × f32/f64 (pitch, yaw, roll) | Transforms |
| `FQuat` | 16 | 32 (f64×4) | 4 × f32/f64 (x, y, z, w) | Bone rotations, transforms |
| `FColor` | 4 | 4 (no LWC) | 4 × u8 (BGRA) | Vertex colors |
| `FLinearColor` | 16 | 16 (no LWC) | 4 × f32 (RGBA, linear) | Materials, lighting |
| `FBox` | 25 | 49 (f64×6 + u8) | min: FVector + max: FVector + 1 × u8 (is_valid bool) | Mesh bounds |
| `FBox2D` | 17 | 33 (f64×4 + u8) | min: FVector2D + max: FVector2D + 1 × u8 | UV-space bounds |
| `FTransform` | 40 | 80 (f64×10) | rotation: FQuat (16/32) + translation: FVector (12/24) + scale_3d: FVector (12/24). No trailing pad byte despite some older references. | Mesh root transform |
| `FBoxSphereBounds` | 28 | 56 (f64×7) | origin: FVector (12/24) + box_extent: FVector (12/24) + sphere_radius: f32/f64 (4/8) | Mesh bounds (StaticMesh / SkeletalMesh) |

The table shows **11 decoders**: FVector + FVector2D + FVector4 (3) + FRotator + FQuat + FColor + FLinearColor + FBox + FBox2D + FTransform + FBoxSphereBounds. The original "seven" framing in the Goal section above is a count of distinct struct families; per-sibling-variant the implementation count is 11.

`FBoxSphereBounds` is promoted in-scope (not deferred to follow-up) because 3g (`UStaticMesh`) and 3h (`USkeletalMesh`) both consume it for their `ImportedBounds` field — without 3c shipping the typed decoder, 3g/3h would have to either embed a duplicate hand-rolled parser or fall through to opaque property-bag (per `static-mesh.md:93` and `skeletal-mesh.md:75`, FBoxSphereBounds is on the wire as a binary struct, not tagged properties).

**Width dispatch via LWC version:** UE 5.0+ widens vectors and rotators to f64 (Large World Coordinates). The decoder reads the `AssetContext.version.file_version_ue5` field; LWC starts at `VER_UE5_LARGE_WORLD_COORDINATES = 1004` (per `version.rs`). When the file version meets that gate, vector components are f64 (8 bytes each); otherwise f32 (4 bytes each). `FColor` and `FLinearColor` are NOT LWC-widened — they stay 4-byte-each.

**Outside Phase 3c (the other ~90 engine structs):**

- `FMatrix`, `FPlane`, `FRotator3f` variants, `FIntPoint`, `FIntVector`, etc. → Phase 3 follow-up when a downstream sub-phase (3e/3f/3g/3h) hits one mid-parse. Each lands as a single-file addition to `asset/structs/`; no new sub-phase needed.
- Game-specific structs from `.usmap` schemas (custom `FInventorySlot` etc.) → already covered by Phase 2f's unversioned schema path AND Phase 2g's tagged-property fallback.
- `FName` itself → already a Phase 2a primitive type; not a "struct" in the typed-struct sense.

**Explicitly deferred:**

- **Decoder for the remaining ~90 engine structs.** Phase 3c proves the pattern with the 10 most-needed; downstream sub-phases extend on-demand. No artificial scope-trim — each future decoder is a 50-line file plus a registry-table entry.
- **Custom comparison / equality semantics.** `FQuat` quaternion equality with sign-flip handling, `FColor` sRGB-aware compare, etc. — not Phase 3 concerns; format handlers convert as they need.
- **Math operations.** No `Add`/`Mul`/`Dot`/`Cross` impls. Phase 3 handlers compute via temporary `glam` or hand-rolled per-handler — adding a math API to paksmith's typed structs invites scope creep.

---

## Design decisions locked here

1. **New `PropertyValue::TypedStruct(Box<TypedStructValue>)` variant.** `TypedStructValue` is a tagged enum with one arm per implemented engine struct. The variant is `#[non_exhaustive]`. Phase 2g's `PropertyValue::Struct { struct_name, properties }` fallback REMAINS for unknown struct names — typed decoders are tried first; on registry miss, fall through.

   **The `Box<>` is load-bearing for memory efficiency.** Largest `TypedStructValue` variant is `FTransform` at 80 bytes (UE5 LWC) + discriminant + padding ≈ 96 bytes. Today's `PropertyValue` largest variant is `Struct { Arc<str>, Vec<Property> }` ≈ 32 bytes. Inlining `TypedStructValue` directly would grow EVERY `PropertyValue` (even an `Int(42)`) to ~96 bytes. A 10k-row DataTable × 30 properties = 300k `PropertyValue`s; inlining adds ~19 MB of waste. Boxing pays one allocation per typed-struct-property (uncommon — typed structs dominate vertex buffers, which 3g consumes directly from `crate::asset::structs::*` without going through `PropertyValue`) in exchange for ~3× smaller PropertyValue.

2. **`TypedStructValue` is its own type, not folded into `PropertyValue`.** Reason: keeps `PropertyValue`'s variant count finite (it would grow by 11 if folded). The discriminator in `TypedStructValue` carries the engine struct name; `PropertyValue` just carries the boxed enum wrapper. JSON output uses `#[serde(tag = "type")]` so consumers see `{"type": "Box", "min": ..., "max": ..., "is_valid": true}`.

3. **Each decoder is `pub` from `paksmith_core::asset::structs`.** Downstream sub-phases (3g, 3h) import directly without going through `PropertyValue::TypedStruct`. The dispatch through the property system is for `inspect`-time visibility; the typed-mesh-reader path in 3g uses the decoders directly to fill `MeshAsset::vertices: Vec<FVector>`.

4. **Registry uses a `&'static str → fn(...)` function pointer table.** No `dyn Trait` (each decoder has the same signature `fn(&mut R, &AssetContext, u64, &str) -> Result<TypedStructValue>` so a function-pointer table works and avoids vtable overhead). `OnceLock<HashMap<&'static str, DecoderFn>>` init pattern; populated by `register_typed_struct_decoders()` at module load.

5. **Bounds enforced via `expected_end`.** Every decoder takes `expected_end: u64` (Phase 2c's per-property bound). After parsing, the cursor must be at exactly `expected_end` (no leftover, no overrun).

   **Two distinct error variants** for the two failure modes, because they carry different threat-model semantics:
   - `TypedStructTrailingBytes { struct_name, trailing }` — cursor < `expected_end`. The decoder read fewer bytes than the property tag claimed. **Soft** error: usually a version mismatch (the wire is from a newer UE that added trailing fields the typed decoder hasn't learned yet). Recoverable by skipping to `expected_end`; logged but doesn't taint downstream parsing.
   - `TypedStructOverrun { struct_name, overrun }` — cursor > `expected_end`. The decoder consumed bytes belonging to the NEXT property — wire corruption, attack, or a struct misidentified as a typed engine struct. **Hard** error: cannot recover (the cursor is now mid-byte for the next property). Must abort the property iteration; surface as a typed fault for operator triage.

   `UnexpectedEof` covers the orthogonal case where the reader exhausts before the decoder's fixed-byte read sequence completes.

6. **LWC width detection happens once per decoder, not per-component.** The decoder reads `ctx.version.is_lwc()` (new helper) at the top, then branches the entire read sequence. Avoids 3-per-vector branch prediction misses.

7. **`FColor` byte order: BGRA on wire, ARGB in display semantics.** The struct stores `r`, `g`, `b`, `a` fields (the human-readable order); the wire layout is `b, g, r, a` per UE's `FColor` convention. The decoder swizzles at parse time so consumers don't need to remember.

8. **`FQuat` is read in `(x, y, z, w)` order** per UE's wire convention. glTF expects `(x, y, z, w)` for `Quat` accessors, so 3g/3h consume directly without reordering.

9. **`FBox.is_valid` is a 1-byte UE-encoded bool.** Per the wire-format spec: `bool` in UE binary structs is a single byte where `0 = false`, non-zero = `true`. We read as `u8` then `!= 0` cast.

10. **Decoder calls are routed through `read_struct_value`** in `containers.rs` (the function generalized in Phase 2g Task 2). Phase 2g shipped with `struct_name: Arc<str>` (the Arc-interning post-convergence shape, not the original plan's `&str`); 3c keeps that signature. The new dispatch logic:

    ```rust
    fn read_struct_value(struct_name: Arc<str>, ...) -> Result<PropertyValue> {
        if let Some(decoder) = crate::asset::structs::lookup(&struct_name) {
            let typed = decoder(reader, ctx, expected_end, asset_path)?;
            return Ok(PropertyValue::TypedStruct(Box::new(typed)));
        }
        // Phase 2g fallback: tagged-property iteration.
        let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
        Ok(PropertyValue::Struct { struct_name, properties })
    }
    ```

---

## Wire-format reference

Each struct's wire layout is documented in CUE4Parse's `CUE4Parse/UE4/Objects/Core/Math/` directory; paksmith documents the layouts here as the authoritative paksmith reference. **No engine source attribution** per `feedback_no_ue_source_attribution_in_public_docs.md`.

### `FVector` (UE4) / `FVector3f` (UE5 fallback) / `FVector` LWC (UE5+)

```
UE4 (12 bytes):
  f32 X
  f32 Y
  f32 Z

UE5 LWC (24 bytes):
  f64 X
  f64 Y
  f64 Z
```

### `FVector2D`

```
UE4 (8 bytes):
  f32 X
  f32 Y

UE5 LWC (16 bytes):
  f64 X
  f64 Y
```

### `FVector4`

```
UE4 (16 bytes):
  f32 X
  f32 Y
  f32 Z
  f32 W

UE5 LWC (32 bytes):
  f64 X, Y, Z, W
```

### `FRotator`

Wire shape identical to `FVector` — `pitch`, `yaw`, `roll` fields (in that order on wire).

### `FQuat`

```
UE4 (16 bytes):
  f32 X
  f32 Y
  f32 Z
  f32 W

UE5 LWC (32 bytes):
  f64 X, Y, Z, W
```

### `FColor` (4 bytes total, NO LWC widening)

```
  u8 B   (blue)
  u8 G   (green)
  u8 R   (red)
  u8 A   (alpha)
```

Wire is BGRA; paksmith's `FColor` struct stores `r`, `g`, `b`, `a` in human order.

### `FLinearColor` (16 bytes total, NO LWC widening)

```
  f32 R
  f32 G
  f32 B
  f32 A
```

Linear-space floating-point color.

### `FBox` (25 bytes UE4 / 49 bytes UE5 LWC)

```
  FVector min     (12 / 24 bytes)
  FVector max     (12 / 24 bytes)
  u8 is_valid     (1 byte; 0 = false, non-zero = true)
```

### `FBox2D` (17 bytes UE4 / 33 bytes UE5 LWC)

```
  FVector2D min   (8 / 16 bytes)
  FVector2D max   (8 / 16 bytes)
  u8 is_valid     (1 byte)
```

### `FTransform` (40 bytes UE4 / 80 bytes UE5 LWC)

```
  FQuat rotation      (16 / 32 bytes)
  FVector translation (12 / 24 bytes)
  FVector scale_3d    (12 / 24 bytes)

Note: serialization order is rotation → translation → scale, per
UE convention. Sum: 16+12+12 = 40 (UE4); 32+24+24 = 80 (UE5 LWC).
No trailing pad byte — earlier scope-table revisions incorrectly
listed 44/88 by assuming a 4-byte align pad that does not exist
in the wire format per CUE4Parse's `FTransform.cs`.
```

### `FBoxSphereBounds` (28 bytes UE4 / 56 bytes UE5 LWC)

```
  FVector origin      (12 / 24 bytes)
  FVector box_extent  (12 / 24 bytes)
  f32/f64 sphere_radius (4 / 8 bytes — widens to f64 under LWC,
                         like all FVector components)

Sum: 12+12+4 = 28 (UE4); 24+24+8 = 56 (UE5 LWC).
Used by FStaticMeshRenderData / USkeletalMesh ImportedBounds (per
static-mesh.md:93 + skeletal-mesh.md:75).
```

**Cross-validation oracle:** CUE4Parse's `CUE4Parse/UE4/Objects/Core/Math/` directory — `FVector.cs`, `FQuat.cs`, `FColor.cs`, `FBox.cs`, `FTransform.cs`, `FBoxSphereBounds.cs` etc. Pin SHA: same as the texture/mesh docs (`cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`).

---

## Task overview

11 tasks, one per decoder (or grouped sibling). Plus dispatcher integration + fixture-gen integration at the end.

| # | Title | Files |
|---|---|---|
| 1 | `TypedStructValue` enum + `PropertyValue::TypedStruct(Box<TypedStructValue>)` variant + registry skeleton | `asset/property/bag.rs`, `asset/structs/mod.rs` |
| 2 | `FVector` (UE4 f32 + UE5 LWC f64) + `is_lwc()` helper + shared LWC-read helper | `asset/version.rs`, `asset/structs/vector.rs`, `asset/structs/mod.rs` |
| 3 | `FVector2D` + `FVector4` (reuses shared helper) | `asset/structs/vector.rs` |
| 4 | `FRotator` | `asset/structs/rotator.rs` |
| 5 | `FQuat` | `asset/structs/quat.rs` |
| 6 | `FColor` (BGRA→RGBA swizzle) + `FLinearColor` | `asset/structs/color.rs` |
| 7 | `FBox` + `FBox2D` | `asset/structs/box_.rs` |
| 8 | `FTransform` (uses FQuat + FVector) | `asset/structs/transform.rs` |
| 9 | `FBoxSphereBounds` (uses FVector + f32/f64 sphere_radius) | `asset/structs/bounds.rs` |
| 10 | Dispatcher integration in `containers.rs::read_struct_value` | `asset/property/containers.rs` |
| 11 | Fixture-gen + integration tests + **mandatory** snapshot update | `paksmith-fixture-gen/`, `paksmith-core-tests/` |

Tasks 2-9 (the eight decoder groups) can ship in parallel via worktrees; Tasks 1, 10, 11 are sequential.

---

### Task 1: `TypedStructValue` enum + registry skeleton

**Files:**

- Create: `crates/paksmith-core/src/asset/structs/mod.rs`.
- Modify: `crates/paksmith-core/src/asset/mod.rs` (declare `pub mod structs;`).
- Modify: `crates/paksmith-core/src/asset/property/bag.rs` — add `PropertyValue::TypedStruct(TypedStructValue)` variant.

- [ ] **Step 1: Add `TypedStructValue` enum to `asset/structs/mod.rs`.**

```rust
//! Typed decoders for the dominant UE engine structs that use
//! custom binary serialization (rather than tagged-property
//! iteration). See `docs/plans/phase-3c-typed-binary-structs.md`.

use std::io::{Read, Seek};

// Submodules add themselves in their respective tasks:
// pub mod vector;
// pub mod rotator;
// ...

/// Tagged value carrying one of the ten implemented engine structs.
/// `#[non_exhaustive]` — Phase 3 follow-ups add variants without
/// SemVer-major bumps.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "type")]
pub enum TypedStructValue {
    // Stubs; populated in Tasks 2-8:
    // Vector(vector::FVector),
    // Vector2D(vector::FVector2D),
    // Vector4(vector::FVector4),
    // Rotator(rotator::FRotator),
    // Quat(quat::FQuat),
    // Color(color::FColor),
    // LinearColor(color::FLinearColor),
    // Box(box_::FBox),
    // Box2D(box_::FBox2D),
    // Transform(transform::FTransform),
}

/// Function signature for a typed-struct decoder. All decoders share
/// this shape so the registry can store function pointers.
type DecoderFn = fn(
    &mut dyn ReadAndSeek,
    &crate::asset::AssetContext,
    u64,            // expected_end
    &str,           // asset_path
) -> crate::Result<TypedStructValue>;

trait ReadAndSeek: Read + Seek {}
impl<T: Read + Seek> ReadAndSeek for T {}

/// Returns the typed-struct decoder for `struct_name`, or None if
/// the struct isn't in the registry (caller falls back to Phase 2g's
/// tagged-property iteration).
pub fn lookup(struct_name: &str) -> Option<DecoderFn> {
    registry().get(struct_name).copied()
}

fn registry() -> &'static std::collections::HashMap<&'static str, DecoderFn> {
    static TABLE: std::sync::OnceLock<std::collections::HashMap<&'static str, DecoderFn>> = std::sync::OnceLock::new();
    TABLE.get_or_init(registry_init)
}

fn registry_init() -> std::collections::HashMap<&'static str, DecoderFn> {
    let table: std::collections::HashMap<&'static str, DecoderFn> = std::collections::HashMap::new();
    // Populated by Tasks 2-8:
    // table.insert("Vector",       vector::read_fvector);
    // table.insert("Vector2D",     vector::read_fvector2d);
    // ...
    table
}
```

- [ ] **Step 2: Add `PropertyValue::TypedStruct(Box<TypedStructValue>)` variant.**

In `asset/property/bag.rs`:

```rust
// In PropertyValue enum (alongside existing variants):
TypedStruct(Box<crate::asset::structs::TypedStructValue>),
```

The Box keeps the `PropertyValue` enum size unchanged — without it, FTransform's 80-byte payload would inflate every PropertyValue 3×. See Design Decision #1.

- [ ] **Step 3: Failing TDD test — empty registry returns None.**

```rust
// asset/structs/mod.rs::tests:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("UnknownStruct").is_none());
    }

    #[test]
    fn empty_registry_returns_empty() {
        // 3c's registry starts empty (Task 1); each subsequent task
        // adds an entry. CORRECTED (Task 8): the final REGISTERED
        // count is 9 — Transform (and likely BoxSphereBounds) ship as
        // unregistered building blocks (tagged-serialized), so they
        // are NOT registry keys. See the note after this block.
        assert_eq!(registry().len(), 0);
    }
}
```

Note: the second test's assertion will need updates per-task as the registry grows. **Corrected during Task 8 execution:** the final registered count is **9**, not 10/11. `FTransform` (Task 8) ships as an *unregistered* building block because a bare `"Transform"` StructProperty is tagged-serialized (Rotation/Translation/Scale3D), not raw binary — verified against CUE4Parse (`"Transform"` → `FStructFallback` default arm) and UAssetAPI (no binary Transform PropertyData). `FBoxSphereBounds` (Task 9) is very likely the same case (the hazard note flags CUE4Parse has no `BoxSphereBounds` dispatch arm either) — Task 9 must verify its bare-name binary-vs-tagged status empirically before deciding whether to register it. Task 10's integration test pins whatever the verified final count is (9 if BoxSphereBounds is also unregistered).

- [ ] **Step 4: Run.** `cargo test -p paksmith-core asset::structs::tests 2>&1 | tail -5`.

- [ ] **Step 5: Lint + test + doc gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -15
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/structs/mod.rs crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/asset/property/bag.rs
git commit -m "$(cat <<'EOF'
feat(structs): add TypedStructValue enum + decoder registry skeleton

3c foundation. Tasks 2-8 populate the registry with FVector, FRotator,
FQuat, FColor, FLinearColor, FBox, FTransform and siblings.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `FVector` (UE4 f32 + UE5 LWC f64) + `is_lwc()` helper

**Files:**

- Modify: `crates/paksmith-core/src/asset/version.rs` — add `AssetVersion::is_lwc()`.
- Create: `crates/paksmith-core/src/asset/structs/vector.rs`.
- Modify: `asset/structs/mod.rs` — register decoder.

- [ ] **Step 1: Add `is_lwc()` helper to `AssetVersion`.**

```rust
// In version.rs:

/// UE5.0 introduces Large World Coordinates: vector components widen
/// from f32 to f64 in mesh data and transforms.
pub(crate) const VER_UE5_LARGE_WORLD_COORDINATES: i32 = 1004;

impl AssetVersion {
    /// Returns true when this asset's UE5 version meets the LWC gate
    /// (vector / rotator / transform components are f64).
    #[must_use]
    pub fn is_lwc(&self) -> bool {
        self.file_version_ue5 >= VER_UE5_LARGE_WORLD_COORDINATES
    }
}
```

- [ ] **Step 2: Write failing TDD test in `vector.rs`.**

```rust
//! `FVector` decoder. UE4 = 3 × f32 (12 bytes); UE5 LWC = 3 × f64 (24 bytes).

use std::io::{Read, Seek};
use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::asset::structs::TypedStructValue;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct FVector {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl FVector {
    /// Decode an `FVector` from `reader`. Component width is
    /// f32 (UE4) or f64 (UE5 LWC) per `ctx.version.is_lwc()`.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        ctx: &AssetContext,
        expected_end: u64,
        asset_path: &str,
    ) -> crate::Result<Self> {
        let (x, y, z) = if ctx.version.is_lwc() {
            (
                reader.read_f64::<LittleEndian>().map_err(|_| eof(asset_path))?,
                reader.read_f64::<LittleEndian>().map_err(|_| eof(asset_path))?,
                reader.read_f64::<LittleEndian>().map_err(|_| eof(asset_path))?,
            )
        } else {
            (
                f64::from(reader.read_f32::<LittleEndian>().map_err(|_| eof(asset_path))?),
                f64::from(reader.read_f32::<LittleEndian>().map_err(|_| eof(asset_path))?),
                f64::from(reader.read_f32::<LittleEndian>().map_err(|_| eof(asset_path))?),
            )
        };
        verify_at_end(reader, expected_end, "FVector", asset_path)?;
        Ok(Self { x, y, z })
    }
}

/// Registry-compatible decoder shim.
pub(crate) fn read_fvector(
    reader: &mut dyn (std::io::Read + std::io::Seek),
    ctx: &AssetContext,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<TypedStructValue> {
    let v = FVector::read_from(reader, ctx, expected_end, asset_path)?;
    Ok(TypedStructValue::Vector(v))
}

fn eof(asset_path: &str) -> crate::PaksmithError {
    crate::PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: crate::AssetParseFault::UnexpectedEof {
            field: crate::AssetWireField::FVectorComponent,
        },
    }
}

fn verify_at_end<R: Seek>(
    reader: &mut R,
    expected_end: u64,
    struct_name: &'static str,
    asset_path: &str,
) -> crate::Result<()> {
    let pos = reader.stream_position().map_err(|_| eof(asset_path))?;
    use std::cmp::Ordering;
    match pos.cmp(&expected_end) {
        Ordering::Equal => Ok(()),
        Ordering::Less => {
            // Trailing bytes (soft) — version mismatch likely.
            let trailing = expected_end - pos;
            Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::TypedStructTrailingBytes {
                    struct_name,
                    trailing,
                },
            })
        }
        Ordering::Greater => {
            // Overrun (hard) — consumed bytes from next property.
            let overrun = pos - expected_end;
            Err(crate::PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: crate::AssetParseFault::TypedStructOverrun {
                    struct_name,
                    overrun,
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::testing::context_with_version;

    #[test]
    fn ue4_vector_decodes_12_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1.5f32.to_le_bytes());
        bytes.extend_from_slice(&2.5f32.to_le_bytes());
        bytes.extend_from_slice(&3.5f32.to_le_bytes());
        let ctx = context_with_version(/* ue4 */ 510, /* ue5 */ 0);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 12, "test").expect("read");
        assert!((v.x - 1.5).abs() < f64::EPSILON);
        assert!((v.y - 2.5).abs() < f64::EPSILON);
        assert!((v.z - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn ue5_lwc_vector_decodes_24_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1.5f64.to_le_bytes());
        bytes.extend_from_slice(&2.5f64.to_le_bytes());
        bytes.extend_from_slice(&3.5f64.to_le_bytes());
        let ctx = context_with_version(/* ue4 */ 510, /* ue5 */ 1004);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        let v = FVector::read_from(&mut cur, &ctx, 24, "test").expect("read");
        assert_eq!(v.x, 1.5);
        assert_eq!(v.y, 2.5);
        assert_eq!(v.z, 3.5);
    }

    #[test]
    fn vector_trailing_bytes_rejected() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1.5f32.to_le_bytes());
        bytes.extend_from_slice(&2.5f32.to_le_bytes());
        bytes.extend_from_slice(&3.5f32.to_le_bytes());
        let ctx = context_with_version(510, 0);
        let mut cur = std::io::Cursor::new(bytes.as_slice());
        // expected_end = 16 → 4 trailing bytes after the decode → reject.
        match FVector::read_from(&mut cur, &ctx, 16, "test") {
            Err(crate::PaksmithError::AssetParse {
                fault: crate::AssetParseFault::TypedStructTrailingBytes { struct_name, trailing },
                ..
            }) => {
                assert_eq!(struct_name, "FVector");
                assert_eq!(trailing, 4u64);
            }
            other => panic!("expected TypedStructTrailingBytes, got {other:?}"),
        }
    }
}
```

> `context_with_version(ue4, ue5)` is a new test helper in `asset/testing/mod.rs`; add it as part of this task. `AssetWireField::FVectorComponent` and `AssetParseFault::TypedStructTrailingBytes { struct_name: &'static str, trailing: i64 }` are new — add to `error.rs` with hand-rolled Display arms and pin-table tests.

- [ ] **Step 3: Add `TypedStructValue::Vector(FVector)` variant.**

```rust
// In asset/structs/mod.rs:
pub mod vector;
// In TypedStructValue:
Vector(vector::FVector),
```

- [ ] **Step 4: Register the decoder.**

```rust
// In registry_init():
table.insert("Vector", vector::read_fvector);
```

- [ ] **Step 5: Run tests.**

```shell
set -o pipefail
cargo test -p paksmith-core asset::structs::vector::tests 2>&1 | tail -10
```

- [ ] **Step 6: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 7: Commit.**

```bash
git add crates/paksmith-core/src/asset/structs/vector.rs crates/paksmith-core/src/asset/structs/mod.rs crates/paksmith-core/src/asset/version.rs crates/paksmith-core/src/asset/testing/mod.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(structs): FVector decoder with UE4 f32 / UE5 LWC f64 dispatch

3c Task 2. AssetVersion::is_lwc() distinguishes the width. Tasks 3-8
follow the same pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Tasks 3-8: Remaining decoders (FVector2D/FVector4, FRotator, FQuat, FColor/FLinearColor, FBox/FBox2D, FTransform)

Each follows the **exact** Task 2 pattern:

1. Failing TDD unit test with hand-built byte fixture (one UE4 case, one UE5 LWC case where applicable).
2. Implement the struct + `read_from` constructor with LWC dispatch.
3. Implement the registry-compatible `read_*` shim returning `TypedStructValue::*(value)`.
4. Add the `TypedStructValue` variant.
5. Register in `registry_init()`.
6. Test → lint → doc gate → commit.

Per-task wire-shape specifics:

- **Task 3 (`FVector2D` + `FVector4`):** Same dispatch as `FVector`; field count differs. `FVector2D` reads 2 components; `FVector4` reads 4.

- **Task 4 (`FRotator`):** Same dispatch as `FVector`; semantic field names are `pitch`, `yaw`, `roll` (in that wire order — pitch FIRST per UE convention, NOT roll-first).

- **Task 5 (`FQuat`):** 4 components in `(x, y, z, w)` order. Same LWC dispatch as `FVector`. Verify with a known-quaternion fixture: identity quaternion `(0, 0, 0, 1)`.

- **Task 6 (`FColor` + `FLinearColor`):** `FColor` reads 4 × u8 in wire order BGRA, stores as `r, g, b, a`. NO LWC widening (it's a fixed-byte struct). `FLinearColor` reads 4 × f32 in RGBA wire order. NO LWC widening.

  Test for `FColor` BGRA swizzle:
  ```rust
  #[test]
  fn fcolor_bgra_wire_swizzles_to_rgba_struct() {
      // Wire: b=0x10, g=0x20, r=0x30, a=0xFF
      let bytes = [0x10, 0x20, 0x30, 0xFF];
      let ctx = context_with_version(510, 0);
      let mut cur = Cursor::new(&bytes);
      let c = FColor::read_from(&mut cur, &ctx, 4, "test").expect("read");
      assert_eq!(c.r, 0x30);
      assert_eq!(c.g, 0x20);
      assert_eq!(c.b, 0x10);
      assert_eq!(c.a, 0xFF);
  }
  ```

- **Task 7 (`FBox` + `FBox2D`):** `FBox` reads `min: FVector` + `max: FVector` + `is_valid: u8`. `FBox2D` same pattern with `FVector2D`. The decoder calls into the existing `FVector`/`FVector2D::read_from` (taking expected_end = current_pos + per-vector-size) for the min/max nested reads, then reads the trailing `u8`.

- **Task 8 (`FTransform`):** Reads `rotation: FQuat` + `translation: FVector` + `scale_3d: FVector` in that order. Reuses the FQuat + FVector decoders.

Each of Tasks 3-8 follows the same commit-per-task discipline. None depend on each other (except Task 7 needs Task 2's `FVector` and Task 3's `FVector2D`; Task 8 needs Task 2 + Task 5). Worktree parallelism: dispatch Tasks 2 + 4 + 5 + 6 + 7 + 8 with Task 7 / 8 starting after their deps land.

---

### Task 10: Dispatcher integration in `containers.rs::read_struct_value`

**Files:**

- Modify: `crates/paksmith-core/src/asset/property/containers.rs`.

- [ ] **Step 1: Write failing integration test that an FBox embedded as a `StructProperty` decodes typed.**

```rust
// In containers.rs::tests, after Phase 2g's collection-of-struct tests:

#[test]
fn struct_property_named_box_decodes_via_typed_decoder() {
    // Build an outer StructProperty body for a 25-byte FBox UE4-style.
    let mut body = Vec::new();
    // min FVector: (0.0, 0.0, 0.0)
    body.extend_from_slice(&0.0f32.to_le_bytes());
    body.extend_from_slice(&0.0f32.to_le_bytes());
    body.extend_from_slice(&0.0f32.to_le_bytes());
    // max FVector: (1.0, 2.0, 3.0)
    body.extend_from_slice(&1.0f32.to_le_bytes());
    body.extend_from_slice(&2.0f32.to_le_bytes());
    body.extend_from_slice(&3.0f32.to_le_bytes());
    // is_valid = 1
    body.push(1u8);

    let ctx = test_ctx_with_names(&["Box"]);
    let mut cur = Cursor::new(body.as_slice());
    let value = read_struct_value(
        Arc::from("Box"), &mut cur, &ctx, /* depth */ 0, /* expected_end */ 25, "test",
    ).expect("read_struct_value");

    match value {
        PropertyValue::TypedStruct(boxed) => {
            match *boxed {
                crate::asset::structs::TypedStructValue::Box(b) => {
                    assert_eq!(b.min.x, 0.0);
                    assert_eq!(b.max.z, 3.0);
                    assert!(b.is_valid);
                }
                other => panic!("expected TypedStructValue::Box, got {other:?}"),
            }
        }
        other => panic!("expected TypedStruct(Box(_)), got {other:?}"),
    }
}

#[test]
fn struct_property_unknown_name_still_falls_through_to_tagged() {
    // For an unknown struct name, the dispatcher MUST fall through to
    // Phase 2g's tagged-property iteration (no regression).
    let body = {
        let mut b = Vec::new();
        // None terminator only.
        b.extend_from_slice(&0i32.to_le_bytes()); // name idx
        b.extend_from_slice(&0i32.to_le_bytes()); // name num
        b
    };
    let ctx = test_ctx_with_names(&["UnknownGameStruct", "None"]);
    let mut cur = Cursor::new(body.as_slice());
    let value = read_struct_value(
        Arc::from("UnknownGameStruct"), &mut cur, &ctx, 0, 8, "test",
    ).expect("read_struct_value");
    match value {
        PropertyValue::Struct { struct_name, properties } => {
            assert_eq!(&*struct_name, "UnknownGameStruct");
            assert!(properties.is_empty()); // None-terminated immediately
        }
        other => panic!("expected fallback Struct, got {other:?}"),
    }
}
```

- [ ] **Step 2: Wire the dispatch into `read_struct_value`.**

The existing Phase 2g signature takes `struct_name: Arc<str>` (Arc-interned post-convergence — see `crates/paksmith-core/src/asset/property/containers.rs:497-510`). 3c does NOT widen this back to `&str`; the dispatch reads through the Arc.

```rust
fn read_struct_value<R: Read + Seek>(
    struct_name: Arc<str>,
    reader: &mut R,
    ctx: &AssetContext,
    depth: usize,
    expected_end: u64,
    asset_path: &str,
) -> crate::Result<PropertyValue> {
    // Phase 3c: typed-decoder lookup first; on miss, fall through.
    if let Some(decoder) = crate::asset::structs::lookup(&struct_name) {
        let typed = decoder(reader, ctx, expected_end, asset_path)?;
        return Ok(PropertyValue::TypedStruct(Box::new(typed)));
    }
    // Phase 2g fallback: tagged-property iteration. The Arc<str> is
    // moved into PropertyValue::Struct (no clone — keeps the
    // interning win Phase 2g shipped).
    let properties = super::read_properties(reader, ctx, depth + 1, expected_end, asset_path)?;
    Ok(PropertyValue::Struct {
        struct_name,
        properties,
    })
}
```

- [ ] **Step 3: Run tests.**

```shell
set -o pipefail
cargo test -p paksmith-core containers::tests::struct_property 2>&1 | tail -10
cargo test --workspace --all-features 2>&1 | tail -15
```

- [ ] **Step 4: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 5: Commit.**

```bash
git add crates/paksmith-core/src/asset/property/containers.rs
git commit -m "$(cat <<'EOF'
feat(structs): wire typed-struct dispatch into read_struct_value

Known engine struct names route through the 3c typed decoders;
unknown names fall through to Phase 2g's tagged-property iteration
unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Fixture-gen extension + integration tests + **mandatory** snapshot rewrite

**Files:**

- Modify: `crates/paksmith-fixture-gen/src/uasset.rs` — add `build_minimal_uasset_with_engine_struct(struct_name: &str)` that produces a synthetic asset carrying one StructProperty body of each type.
- Create or modify: `crates/paksmith-core-tests/tests/typed_struct_integration.rs`.
- Update: existing `inspect_json_snapshot` if it carries a typed struct.

- [ ] **Step 1: Add 11 integration tests, one per engine struct type, against synthetic fixtures.**

```rust
#[test]
fn fvector_in_real_asset_decodes_typed() {
    let pak = include_bytes!("../../tests/fixtures/typed_struct_fvector.pak");
    let pkg = Package::read_from_pak_bytes(pak, "Game/Test.uasset", None).expect("read");
    let exports = pkg.export_payloads();
    let bag = match &exports[0] {
        Asset::Generic(PropertyBag::Tree { properties }) => properties,
        other => panic!("expected Tree, got {other:?}"),
    };
    let prop = bag.iter().find(|p| p.name == "Position").expect("Position");
    match &prop.value {
        PropertyValue::TypedStruct(TypedStructValue::Vector(v)) => {
            assert!((v.x - 1.5).abs() < f64::EPSILON);
        }
        other => panic!("expected TypedStruct(Vector), got {other:?}"),
    }
}

// Mirror for FQuat, FColor, FLinearColor, FBox, FBox2D, FTransform,
// FVector2D, FVector4, FRotator, FBoxSphereBounds.
```

- [ ] **Step 2: MANDATORY: update `inspect_json_snapshot`.**

The existing snapshot at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` includes `LightingGuid: StructProperty(Guid)` and likely other engine-struct names that Phase 3c now decodes typed. ANY asset carrying a StructProperty whose `tag.struct_name` matches one of the 11 dispatched names will change its output from `PropertyValue::Struct { struct_name: "Box", properties: [] }` to `PropertyValue::TypedStruct(Box(TypedStructValue::Box(...)))` with the boxed payload's fields.

The snapshot rewrite is NOT optional — it is the canonical Phase 2 → Phase 3c wire-shape transition. `cargo insta review` + accept the new shape. This is a documented breaking change to the inspect JSON output; record in the commit message as the Phase 3c milestone shift.

The plan's library-side `lib.rs` doc-comment should also be updated with a note about the inspect-JSON shape change at Phase 3c.

- [ ] **Step 3: Pin the registry count.**

```rust
// In asset/structs/mod.rs::tests:
// CORRECTED (Task 8): "Transform" is NOT a registry key — bare
// "Transform" is tagged-serialized, so FTransform ships as an
// unregistered building block (call FTransform::read_from directly).
// "BoxSphereBounds" is pending Task 9's binary-vs-tagged verification;
// drop it from this set too if Task 9 confirms it's tagged.
#[test]
fn registry_has_all_registered_typed_structs() {
    let r = registry();
    assert_eq!(r.len(), 9);
    for name in [
        "Vector", "Vector2D", "Vector4", "Rotator", "Quat",
        "Color", "LinearColor", "Box", "Box2D",
    ] {
        assert!(r.contains_key(name), "missing: {name}");
    }
    // Unregistered building blocks (tagged-serialized under their bare
    // wire names): Transform, and likely BoxSphereBounds.
    assert!(!r.contains_key("Transform"));
}
```

- [ ] **Step 4: Bump CI's fixture-count gate.**

Per `feedback_fixture_count_gate.md`: 11 new fixtures (one per struct). Bump `.github/workflows/ci.yml` by +11.

- [ ] **Step 5: Lint + test + doc gate.** Same as Task 1 Step 5.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-fixture-gen/src/uasset.rs tests/fixtures/typed_struct_*.pak crates/paksmith-core-tests/tests/typed_struct_integration.rs crates/paksmith-core/src/asset/structs/mod.rs .github/workflows/ci.yml
git commit -m "$(cat <<'EOF'
test(structs): fixture-gen + typed-struct integration tests

Closes Phase 3c. Registry pins to exactly 9 REGISTERED entries
(FVector / FVector2D / FVector4 / FRotator / FQuat / FColor /
FLinearColor / FBox / FBox2D); FTransform — and, pending Task 9's
own verification, FBoxSphereBounds — ship as unregistered building
blocks (tagged-serialized under their bare wire names, decoded via
`read_from` directly by 3g/3h). Integration tests cover the family.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Review panel (Phase 3c specifics)

- **Wire-format pass** — MANDATORY. Every decoder consumes on-wire bytes. Cross-validate against the format-doc-referenced CUE4Parse SHA.
- **Security pass** — soft trigger. Decoders read fixed-byte structs; no allocation-driven amplification beyond the `verify_at_end` invariant. Optional but recommended for Task 1 + Task 9 (which add new error variants).
- **Deep-impact tracer** — MANDATORY for Task 1 + Task 9 (adds `PropertyValue::TypedStruct` — ripples through `PropertyBag` consumers including JSON snapshot and downstream serialization).
- **Performance** — soft trigger. The decoder dispatch is one HashMap lookup per StructProperty body; the existing tagged-property path is the slow case, not this. Optional.

Total reviewers per task: 4 (standard 3 + wire-format), 5 for Task 1 and Task 9 (+ deep-impact). Convergence loop per Phase 2g standard.

---

## After 3c lands

- Phase 2g's empty-properties fallback for the 10 engine structs is replaced by typed decoded values.
- `paksmith inspect` JSON output renders real coordinates / quaternions / colors / bounds.
- 3g (StaticMesh) can call `FVector::read_from`, `FBox::read_from`, etc. directly to fill `MeshAsset::vertices` and `MeshAsset::bounds`.
- 3h (SkeletalMesh) can use the same plus `FTransform` for bone bind poses.
- Phase 3 follow-ups extend the registry per-need: `FMatrix`, `FPlane`, `FIntPoint`, etc. land as drop-in `asset/structs/<name>.rs` files + registry entries.

---

## References

- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Phase 2g's deferral statement: [`phase-2g-collection-of-struct.md`](phase-2g-collection-of-struct.md) §Scope vs deferred work, "Custom-binary engine struct readers" bullet.
- Phase 2g's `read_struct_value` site: `crates/paksmith-core/src/asset/property/containers.rs` (the Phase 2g-generalized helper).
- Wire-format cross-validation reference: CUE4Parse `CUE4Parse/UE4/Objects/Core/Math/` at `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`.
- UE5 LWC version gate: `VER_UE5_LARGE_WORLD_COORDINATES = 1004`.
