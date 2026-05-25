# Paksmith Phase 3a: FormatHandler trait + HandlerRegistry + class-name dispatch

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Cargo exit-code caveat:** Every cargo command piped through `tail`, `head`, or `grep` in this plan returns `0` even when cargo failed — the shell drops the upstream exit code. After running any cargo gate, re-run unpiped, set `set -o pipefail`, or inspect `${PIPESTATUS[0]}` to verify the real exit code.

**Goal:** Establish two new layers that all downstream Phase 3 export work depends on:

1. **Parse-time class-name dispatch.** `Package::read_from` consults a per-class-name table when parsing each export. Unknown class names fall through to the existing generic property-bag iteration; known class names (none today; populated by 3d/3e/3f/3g) read into typed `Asset` variants.
2. **Export-time `FormatHandler` trait + `HandlerRegistry`.** Stateless handlers convert a typed `&Asset` (plus optional bulk data, populated by 3b's resolver) into target-format bytes. Registry dispatches by `Asset` variant.

3a ships both layers with **zero typed Asset variants beyond `Generic`** — the dispatch table is empty and the registry's only registered handler is the `Generic` passthrough that returns the export's raw payload bytes. This validates the wiring without committing to texture / mesh / audio / data-table shapes (those land in 3d-3g).

**Architecture:** Two new modules + one extended:

- `crates/paksmith-core/src/asset/exports/mod.rs` — NEW. Houses the parse-time dispatch table (today empty) and the `Asset` enum's class-name-to-variant mapping. Phase 3d-3g extend with submodules per export family.
- `crates/paksmith-core/src/export/mod.rs` — NEW. Houses `FormatHandler` trait, `HandlerRegistry`, `BulkData` placeholder type (real definition lands in 3b), and the `Generic` passthrough handler.
- `crates/paksmith-core/src/asset/package.rs` — extended. `read_payloads` consults the dispatch table per-export.

**Tech Stack:** Same as Phase 2g. No new workspace dependencies.

---

## Scope vs deferred work

**In scope:**

- `FormatHandler` trait definition with the exact signature locked in the master index (Design Decision #3).
- `HandlerRegistry` struct + `register`, `find_handler(&Asset)`, `find_handler_by_extension(&str, &Asset)` methods.
- `BulkData` placeholder type — concrete fields landed in 3b; 3a just defines the type with `pub(crate)` constructor so the trait signature compiles. 3a's `Generic` handler ignores it.
- `Asset` enum gains `#[non_exhaustive]` attribute. Today still single-variant `Generic(PropertyBag)`; the attribute reserves the right for 3d-3h to add variants without breaking SemVer.
- Parse-time dispatch table at `asset/exports/dispatch.rs`: `HashMap<&'static str, TypedReaderFn>` where `TypedReaderFn = fn(payload: &[u8], ctx: &AssetContext, asset_path: &str) -> crate::Result<Asset>`. Today registers nothing (the five typed families land in 3d-3h); 3d-3h each insert one entry mapping class-name → typed-reader-fn. A HashMap miss = no typed reader = `read_payloads` falls back to the existing Phase 2 generic property-bag iteration. No intermediate discriminator enum.
- `paksmith-core::export::generic::GenericHandler` — a `FormatHandler` impl that returns the export's serialized property tree bytes (via `serde_json::to_vec_pretty` of the `PropertyBag`). Output extension: `"json"`. Selected by `Asset::Generic` variant match.
- 5 unit tests: trait shape compiles, registry register-and-find round-trips, dispatch table lookup, `GenericHandler` produces non-empty JSON, `Asset` `#[non_exhaustive]` round-trips through serde.
- 1 doc test in `export/mod.rs`'s `FormatHandler` trait docstring demonstrating the public usage pattern.

**Explicitly deferred:**

- **Typed `Asset` variants.** `Asset::Texture2D`, `Asset::StaticMesh`, `Asset::SoundWave`, `Asset::DataTable` all land in their respective sub-phases. 3a's `#[non_exhaustive]` attribute reserves the variant slot without committing to shape.
- **Real `BulkData` definition.** 3a defines the type as `pub struct BulkData { #[doc(hidden)] _private: () }` so the trait signature compiles; 3b replaces with `pub struct BulkData { pub bytes: Vec<u8>, pub flags: BulkDataFlags, ... }`. Phase 3 internal API; not public yet.
- **CLI `paksmith extract` subcommand.** Phase 4 work. 3a's registry exists only as library API; no CLI surface change.
- **GUI handler-registry integration.** Phase 7 work.
- **Handler chaining / priority.** A given `Asset` variant gets at most one handler per output extension. If 3d registers both `CsvHandler` and `JsonHandler` for `Asset::DataTable`, the caller picks via `find_handler_by_extension("csv", &asset)` or `("json", &asset)`. No fallback chain, no priority field, no "best-match" heuristic.
- **Async export.** All handlers are blocking. Phase 3 has no async deps; bulk-data reads are blocking too.
- **`AssetFamily` discriminator into the serialized `Package` JSON.** Today `paksmith inspect` emits the property tree directly; family discriminator surfaces in 3d-3g when typed variants ship.

## Design decisions locked here

1. **`FormatHandler` is `dyn`-compatible (object-safe).** No generic methods, no associated types with `Self` bounds. The registry stores `Box<dyn FormatHandler>`. Stateless handlers (`GenericHandler` is a unit struct) avoid `&mut self`; the trait takes `&self` everywhere.

2. **`fn export` returns `Vec<u8>`, not a writer-generic shape.** Streaming would require `&mut dyn Write` and complicate the trait's object-safety story. Phase 3's largest realistic output is a multi-MiB glTF buffer — allocating once is acceptable. Phase 5+ can introduce a streaming variant if profiling demands it.

3. **Registry is discriminant-keyed by `Asset` variant; `supports()` survives only for sub-variant dispatch.** Discriminant-keying (`HashMap<std::mem::Discriminant<Asset>, Vec<Box<dyn FormatHandler>>>`) gives O(1) first-cut filtering by `Asset` variant. The remaining `supports(asset: &Asset) -> bool` method is consulted ONLY within the per-variant bucket — needed because some handlers serve a sub-variant of an `Asset` (e.g. the `OggPassthroughHandler` for `Asset::SoundWave` matches only when the codec_buffers Vec contains an OGG entry; `PcmWavHandler` matches only PCM). Per-variant Vecs are typically 1-3 handlers, so within-bucket linear scan is fine. Handlers register via `register(handler, discriminant)` where the discriminant comes from a sentinel value the caller provides (e.g. `mem::discriminant(&Asset::DataTable(DataTableData::default()))`); or via a `register_for<F: AssetVariantWitness>(handler)` helper. The exact API is locked in Task 2.

4. **Lying-handler footgun is defensive-only, not a silent contract.** A handler with `supports == true` then returning `MismatchedAsset` is a bug, not a recoverable state. The registry surfaces it as `PaksmithError::Internal { context }` — defensive (no panic in core per CLAUDE.md), surfaced as a hard error, not silenced. The discriminant-keyed first-cut filtering eliminates the most common shape of this bug (handler registered for wrong variant) — only sub-variant mismatches can hit it.

5. **`HandlerRegistry::register` consumes the handler `Box`.** No removal API. Handlers register once at startup; Phase 3 has no use case for dynamic registration / unregistration. Phase 5 (game profiles) may grow one, but that's out of scope here.

6. **Class-name dispatch table is `&'static str` keys mapping to `fn(...)` (NOT `ExportFamily`).** No intermediate discriminator enum. The reader-fn returns the typed `Asset` variant directly. HashMap miss = fall through to the existing Phase 2 generic property-bag iteration. Class names are interned engine identifiers (UE doesn't rename `Texture2D`); using `&'static str` avoids the `String` allocation per-export-lookup. Forward-compat for game-specific class subclasses (e.g. UE Lyra's `BPI_Texture2D`) follows the existing UE convention of inheritance — game-specific subclasses inherit the engine class's serialization, so the dispatch resolves via the property-bag fallback until a future sub-phase adds explicit subclass mappings.

7. **Dispatch table is lazy-initialized via `std::sync::OnceLock`.** No `lazy_static`. The function `class_dispatch()` returns `&'static HashMap<&'static str, TypedReaderFn>`. Phase 3a's table is empty; 3d-3h `phf!`-vs-`HashMap` choice is left to the implementing sub-phase (today `HashMap` for simplicity; PHF if profiling shows the lookup hot — unlikely with <10 known classes).

8. **Unknown-class telemetry uses `tracing::trace!` with the class name as a `&str` parameter, no allocation.** The previous `ExportFamily::Unknown(String)` design would have allocated a `String` per unknown class to carry the name into a debug log. Direct `tracing::trace!(export.class = class_name_str, ...)` at the HashMap-miss site achieves the same telemetry with zero allocations per lookup.

9. **Public API surface is `pub` from `paksmith_core::export`.** The trait, registry, and handler implementations are part of the library's stable public API. The dispatch table and `TypedReaderFn` alias are `pub(crate)` — implementation detail. `Asset` is already `pub`; the `#[non_exhaustive]` attribute extends to its variants.

10. **`GenericHandler` returns the export's parsed property tree as pretty JSON, not raw entry bytes.** Raw entry bytes are recoverable from `PakReader::read_entry` directly without going through the handler layer — a "raw bytes handler" would be redundant. `GenericHandler` exists because "I have a parsed property tree but no class-specific handler" is the common-case fallback during early Phase 3 development. Output bytes are pretty-printed; trade-off: larger output for human readability matches `paksmith inspect`'s existing precedent. The master index's milestone signal is updated to match.

11. **`BulkData` type lives in `crate::asset::bulk_data`, NOT in `export/`.** 3a's trait signature for `FormatHandler::export(&self, asset: &Asset, bulk: Option<&BulkData>)` references `BulkData` by path; the type's definition lands with 3b. To avoid the dead `#[doc(hidden)] _private: ()` placeholder shipping in a tagged 3a release, 3a Task 2 declares `pub mod bulk_data;` in `asset/mod.rs` with `pub struct BulkData;` (unit struct — no fields). 3b Task 4 then populates the fields. The trait signature compiles against the unit struct; `GenericHandler` ignores the `bulk` parameter; no field-shape API leaks in the 3a release. (M5 collapse alternative: ship 3a + 3b together so the unit-struct phase never appears in a tag. Decided to keep them separable — the unit struct is a 5-line dead-code surface for ~one sub-phase cycle, acceptable.)

12. **Single `HandlerRegistry::all_default_handlers()` constructor, NOT a `default_with_*_handlers` cascade.** Each sub-phase (3d/3e/3f/3g/3h) adds its handler(s) to this single function via additive PRs. Callers wanting a subset use `HandlerRegistry::new()` + explicit `register()` calls. Eliminates the proliferation of `default_with_data_table_handlers`, `default_with_texture_handlers`, etc.

13. **No `register_for_<variant>` helpers; inline the sentinel-discriminant construction inside `all_default_handlers()`.** The R1 design proposed per-variant `register_for_generic` / `register_for_data_table` / etc. helpers. R2 simplifier pointed out the helpers just move the cascade — N helpers, one per variant. Drop them; `all_default_handlers()` is the only registration site this crate owns, so the sentinel construction lives inline there once per variant. External callers (3rd-party plugins, future Phase 5 game-profile-driven registries) use `register(discriminant, handler)` directly.

14. **Typed-variant inner types MUST expose a cheap `empty()` or `Default` constructor** so `all_default_handlers()`'s inline sentinels don't pay heap-allocation costs. 3d's `DataTableData::empty()` returns `{ row_struct: String::new(), rows: Vec::new(), class_properties: PropertyBag::Tree { properties: Vec::new() } }` — three zero-capacity heap allocations per `Vec::new()` / `String::new()` is 0 bytes allocated (Rust's empty Vec/String don't allocate until first push). Net cost: stack-allocated sentinel + zero heap allocations. 3e/3f/3g/3h's typed inner types follow the same discipline — pin in each plan's task list.

---

## Wire-format reference

3a touches no wire formats — all changes are Rust API. The dispatch keys (class names) come from existing `package.rs` class-name resolution at lines 194-203 + 582-591; the resolution itself is Phase 2 work and unchanged here.

---

## Task overview

5 tasks, one PR each, full adversarial review panel per PR (architect + simplifier + general code reviewer minimum; security pass mandatory per `feedback_specialist_reviewers_default.md` because Task 4 changes parser dispatch).

| # | Title | Files |
|---|---|---|
| 1 | `Asset` enum: add `#[non_exhaustive]`; `Package::payloads` typed migration `Vec<PropertyBag>` → `Vec<Asset>` | `asset/mod.rs`, `asset/package.rs` |
| 2 | `export/` module: FormatHandler trait + Registry (BulkData lives in 3b, not here) | `lib.rs`, `export/mod.rs` |
| 3 | `GenericHandler` impl + registry default-population helper | `export/generic.rs`, `export/mod.rs` |
| 4 | Class-name dispatch table (`HashMap<&'static str, TypedReaderFn>`) + `read_payloads` integration | `asset/exports/mod.rs`, `asset/exports/dispatch.rs`, `asset/package.rs` |
| 5 | Public API re-exports + 1 doc test + lint/test/doc gate | `lib.rs`, `export/mod.rs` |

Tasks 1-3 can ship in parallel if dispatched as worktrees; Tasks 4 and 5 are sequential after Task 3.

---

### Task 1: Invert `Asset` enum from package-wrapper to per-export-wrapper; migrate `Package::payloads` from `Vec<PropertyBag>` to `Vec<Asset>`

**Files:**

- Modify: `crates/paksmith-core/src/asset/mod.rs` — re-shape `Asset::Generic(Package)` → `Asset::Generic(PropertyBag)` (per-export semantics).
- Modify: `crates/paksmith-core/src/asset/package.rs` — change `pub payloads: Vec<PropertyBag>` to `pub payloads: Vec<Asset>`; `read_payloads` wraps each generated `PropertyBag` in `Asset::Generic(bag)`.
- Modify: existing in-crate tests at `asset/mod.rs::tests` (`asset_generic_clone_and_debug`, `asset_generic_serializes_with_externally_tagged_shape`) — both rely on the package-level wrapper shape; both need to be updated.
- Update: `Asset` doc comment block (lines 70-96 in current source) which still says `Asset::Generic(Package)` and "inspect serializes the inner `Package` directly, not the `Asset` wrapper" — both stale post-inversion.

**Why invert?** Phase 2 `Asset::Generic(Package)` wraps the WHOLE Package — a forward-compat placeholder. Phase 3 needs typed variants PER EXPORT (one `Texture2D` export within a Package shouldn't force the whole Package to be `Asset::Texture2D`). The right granularity is per-export: each entry in `Package::payloads` is an `Asset`. Phase 2's package-level wrapper is unused in practice (`paksmith inspect` already serializes `Package` directly per the existing doc comment), so this re-shape doesn't lose external functionality — only the unused forward-compat shape changes.

- [ ] **Step 1: Re-shape the `Asset` enum.**

```rust
/// The parsed shape of a single export's payload.
///
/// `Generic` is the universal fallback — used today (Phase 2 closure)
/// for every export. Phase 3 sub-phases (3d-3h) add typed variants
/// for known export classes. The `#[non_exhaustive]` attribute
/// reserves the right to add variants without an SemVer-major bump.
///
/// `Asset` is now per-export (was per-Package in Phase 2's
/// forward-compat placeholder shape). `Package::payloads: Vec<Asset>`
/// carries one entry per export; consumers select by index.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
pub enum Asset {
    Generic(crate::asset::property::bag::PropertyBag),
    // Phase 3d adds: DataTable(DataTableData),
    // Phase 3e adds: Texture2D(Texture2DData),
    // Phase 3f adds: SoundWave(SoundWaveData),
    // Phase 3g adds: StaticMesh(StaticMeshData),
    // Phase 3h adds: SkeletalMesh(SkeletalMeshData),
}
```

The `Deserialize` is still intentionally not derived (existing comment block lines 84-96 stays valid for the same reason — `PropertyBag::Opaque`'s lossy serialization).

- [ ] **Step 1: Add `#[non_exhaustive]` to `Asset`.**

```rust
/// The parsed shape of a single export from a UE asset.
///
/// `Generic` is the universal fallback — used today (Phase 2 closure)
/// for every export. Phase 3 sub-phases (3d-3h) add typed variants
/// for known export classes. The `#[non_exhaustive]` attribute
/// reserves the right to add variants without an SemVer-major bump.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum Asset {
    Generic(crate::asset::property::bag::PropertyBag),
    // Phase 3d adds: DataTable(DataTableData),
    // Phase 3e adds: Texture2D(Texture2DData),
    // Phase 3f adds: SoundWave(SoundWaveData),
    // Phase 3g adds: StaticMesh(StaticMeshData),
    // Phase 3h adds: SkeletalMesh(SkeletalMeshData),
}
```

- [ ] **Step 2: Migrate `Package::payloads` to `Vec<Asset>`.**

Change the `Package` struct definition + `read_payloads` body + every site in `package.rs` that mutates or returns `payloads`. Every existing emit site that produced a `PropertyBag` now emits `Asset::Generic(bag)`:

```rust
pub struct Package {
    pub summary: PackageSummary,
    pub names: Arc<NameTable>,
    pub imports: Arc<ImportTable>,
    pub exports: Arc<ExportTable>,
    pub payloads: Vec<Asset>,            // CHANGED from Vec<PropertyBag>
    pub mappings: Option<Usmap>,
    pub asset_path: String,
}

// In read_payloads (around package.rs:582):
//   ... (existing iteration)
//   payloads.push(Asset::Generic(bag));
```

- [ ] **Step 3: Update the two existing in-crate Asset tests.**

Both tests at `asset/mod.rs::tests` rely on the old `Asset::Generic(Package)` shape. After Step 1's inversion:

```rust
// Old: `Asset::Generic(pkg)` where pkg is a Package.
// New: `Asset::Generic(bag)` where bag is a PropertyBag.

#[test]
fn asset_generic_clone_and_debug() {
    let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
    let asset = Asset::Generic(bag);
    let cloned = asset.clone();
    let dbg = format!("{cloned:?}");
    assert!(dbg.starts_with("Generic("), "got: {dbg}");
}

#[test]
fn asset_generic_serializes_with_externally_tagged_shape() {
    // Pin the externally-tagged JSON shape: {"Generic": <PropertyBag JSON>}.
    // The inner PropertyBag has `#[serde(tag = "kind", rename_all = "snake_case")]`
    // so an Opaque bag renders as {"kind": "opaque", "bytes": <byte count>}.
    let bag = crate::asset::property::bag::PropertyBag::opaque(vec![0u8; 32]);
    let asset = Asset::Generic(bag);
    let json = serde_json::to_string(&asset).expect("serde");
    assert!(json.starts_with(r#"{"Generic":{"kind":"opaque""#), "got: {json}");
    assert!(json.contains(r#""bytes":32"#), "got: {json}");
}
```

- [ ] **Step 4: Update CLI inspect.rs accordingly.**

`paksmith inspect` serializes `Package` (the whole package, not a single Asset). Today it renders `Package::payloads: Vec<PropertyBag>` directly inside the per-export JSON. After Step 2 it renders `Package::payloads: Vec<Asset>` — each entry is `{"Generic": {"kind": "opaque", "bytes": N}}`. Update inspect.rs's JSON-shaping logic if it wraps PropertyBag manually anywhere. Verify the change against the inspect-json snapshot in Step 5.

- [ ] **Step 5: Update `inspect_json_snapshot` via `cargo insta review`.**

The Phase 2 snapshot at `crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap` will need a regenerate. Every export's payload tree now appears under a top-level `"Generic"` tag inside the per-export JSON. This is a one-time snapshot rewrite; document in the commit message that this is the Phase 2 → Phase 3 transition shape.

- [ ] **Step 6: Update the stale `Asset` doc-comment block.**

The current `asset/mod.rs:70-96` doc comment says "Asset::Generic(Package)" and "paksmith inspect serializes the inner Package directly, not the Asset wrapper" — both stale after the inversion. Rewrite the doc comment to reflect: (a) per-export semantics, (b) `Package::payloads: Vec<Asset>` carries one entry per export, (c) `paksmith inspect` continues to serialize `Package` directly (and its inner `payloads: Vec<Asset>` field is where the per-export JSON lives).

- [ ] **Step 7: Run.**

```shell
set -o pipefail
cargo test -p paksmith-core asset::tests::asset_generic_serializes 2>&1 | tail -10
INSTA_UPDATE=always cargo test -p paksmith-cli inspect_json_snapshot 2>&1 | tail -10
cargo test --workspace --all-features 2>&1 | tail -15
```

- [ ] **Step 8: Lint + test + doc gate.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -10
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

- [ ] **Step 9: Commit (with `BREAKING:` prefix + Cargo.toml version bump).**

Per master-index §SemVer impact: 3a Task 1 ships two breaking changes (`Asset::Generic` payload inversion + `Package::payloads` field type). Commit message MUST be prefixed `BREAKING:` per Conventional Commits, and `crates/paksmith-core/Cargo.toml` MUST bump to `version = "0.2.0"` in this same commit (or in Task 5 if cleaner — see Task 5 Step 5).

```bash
git add crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/asset/package.rs crates/paksmith-cli/src/commands/inspect.rs crates/paksmith-cli/tests/snapshots/inspect_cli__inspect_json_snapshot.snap crates/paksmith-core/Cargo.toml
git commit -m "$(cat <<'EOF'
BREAKING: feat(asset): non_exhaustive Asset enum; migrate Package::payloads to Vec<Asset>

Phase 2's per-package Asset::Generic(Package) wrapper is replaced by
per-export Asset::Generic(PropertyBag); Package::payloads becomes
Vec<Asset>. Downstream Phase 3 sub-phases add typed variants
(DataTable, Texture2D, SoundWave, StaticMesh, SkeletalMesh) on the
#[non_exhaustive] enum without further breakage.

Bumps paksmith-core to 0.2.0 (breaking under pre-1.0 semver
conventions). CHANGELOG entry enumerates the two source-breaks
with migration examples.

Snapshot updated to reflect the new externally-tagged Asset JSON
shape; downstream sub-phases add typed variants without further
snapshot churn until each variant gets its first fixture.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `export/` module skeleton + `FormatHandler` trait + discriminant-keyed `HandlerRegistry`

**Files:**

- Modify: `crates/paksmith-core/src/lib.rs` (declare `pub mod export;`).
- Modify: `crates/paksmith-core/src/asset/mod.rs` (declare `pub mod bulk_data;`).
- Create: `crates/paksmith-core/src/asset/bulk_data.rs` — unit-struct stub (real fields land in 3b).
- Create: `crates/paksmith-core/src/export/mod.rs`.

- [ ] **Step 1: Declare modules.**

```rust
// In lib.rs alongside existing `pub mod asset;` etc.
pub mod export;
```

```rust
// In asset/mod.rs:
pub mod bulk_data;
```

- [ ] **Step 2: Create `asset/bulk_data.rs` as a 5-line unit-struct stub.**

```rust
//! Phase 3b lands the real `FByteBulkData` / `BulkDataResolver` /
//! `BulkData` types in this module. 3a ships a unit struct so the
//! `FormatHandler::export` signature compiles; 3b's PR converts to
//! a fields-bearing struct in a single atomic change (no
//! `#[doc(hidden)] _private` ghost field).

/// Resolved bulk-data payload. **3a unit-struct stub**; 3b adds
/// `bytes: Vec<u8>`, `record: FByteBulkData`, `tier: BulkDataTier`.
#[derive(Debug, Clone)]
pub struct BulkData;
```

> Why unit struct, not `_private: ()`? A unit struct exposes ZERO pattern-matchable surface — `let BulkData = bulk;` matches identically before and after 3b widens the type, so 3b's PR is purely additive. The hidden-field placeholder approach would have shipped a `#[doc(hidden)]` field that a paranoid downstream could destructure-match, which would break at 3b. The unit struct can't be destructured at all.

- [ ] **Step 3: Create `export/mod.rs` with trait + discriminant-keyed registry.**

```rust
//! Phase 3 export pipeline. Converts parsed UE assets into target
//! interchange formats (PNG, glTF, WAV, CSV, JSON).
//!
//! The pipeline has two layers:
//!
//! 1. **Parse-time specialization** (in `asset/exports/`) — each
//!    export's class name dispatches to a typed reader. Today (3a)
//!    every export routes through the generic property-bag iteration;
//!    3d-3h populate the dispatch table.
//! 2. **Export-time format handlers** (this module) — typed `Asset`
//!    values feed `FormatHandler` impls that produce target-format
//!    bytes. Registry is discriminant-keyed (`Discriminant<Asset>`);
//!    handlers register against the variant they serve.
//!
//! See `docs/plans/phase-3-export-pipeline.md` for the full plan.

use std::collections::HashMap;
use std::mem::Discriminant;

use crate::asset::Asset;
pub use crate::asset::bulk_data::BulkData;

/// Converts a typed `Asset` plus optional bulk data into target-format
/// bytes. Handlers are **stateless and side-effect-free**.
///
/// # Example
///
/// ```rust,no_run
/// use paksmith_core::export::{FormatHandler, HandlerRegistry};
/// use paksmith_core::asset::Asset;
///
/// fn pick_extension(reg: &HandlerRegistry, asset: &Asset) -> &'static str {
///     reg.find_handler(asset)
///         .map(|h| h.output_extension())
///         .unwrap_or("bin")
/// }
/// ```
pub trait FormatHandler: Send + Sync {
    /// File extension for the produced output (e.g. `"png"`, `"gltf"`,
    /// `"csv"`). No leading dot.
    fn output_extension(&self) -> &'static str;

    /// **Sub-variant** support check. The registry has already
    /// filtered by `Discriminant<Asset>` via the per-variant bucket
    /// keying; `supports` is consulted only within that bucket to
    /// disambiguate among handlers serving the same `Asset` variant
    /// (e.g. OGG vs OPUS vs PCM handlers for `Asset::SoundWave`,
    /// CSV vs JSON for `Asset::DataTable`).
    ///
    /// For a handler that doesn't care about sub-variants, return
    /// `true` unconditionally — the discriminant filter already
    /// ensures the variant is correct.
    fn supports(&self, asset: &Asset) -> bool;

    /// Convert `asset` (+ optional bulk data) into output bytes.
    ///
    /// # Errors
    /// Any [`crate::PaksmithError`] from the format's encode path.
    /// A handler that returned `true` from [`Self::supports`] for
    /// this asset MUST NOT return a `MismatchedAsset`-style error
    /// from `export` — that's a registry contract violation surfaced
    /// as [`crate::PaksmithError::Internal`].
    fn export(
        &self,
        asset: &Asset,
        bulk: Option<&BulkData>,
    ) -> crate::Result<Vec<u8>>;
}

/// Registry of format handlers keyed by `Asset` variant
/// discriminant. Within each variant's bucket, handlers are walked
/// in registration order; the first whose [`FormatHandler::supports`]
/// returns true wins.
pub struct HandlerRegistry {
    by_variant: HashMap<Discriminant<Asset>, Vec<Box<dyn FormatHandler>>>,
}

impl HandlerRegistry {
    /// Empty registry — register handlers explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self { by_variant: HashMap::new() }
    }

    /// Registry pre-populated with every Phase-3-defined handler
    /// across 3a-3h. Sub-phases extend this function additively;
    /// callers wanting a subset use `new()` + explicit `register()`.
    ///
    /// Phase 3a: registers `GenericHandler` only. Phase 3d-3h each
    /// add their handler(s) here. Sentinel-Asset construction is
    /// inline at each registration site (the simplifier R2 finding
    /// removed the `register_for_<variant>` helper cascade).
    #[must_use]
    pub fn all_default_handlers() -> Self {
        use crate::asset::property::bag::PropertyBag;
        let mut reg = Self::new();

        // Asset::Generic — sentinel uses the cheapest possible PropertyBag.
        let generic_sentinel = Asset::Generic(PropertyBag::opaque(Vec::new()));
        reg.register(
            std::mem::discriminant(&generic_sentinel),
            Box::new(generic::GenericHandler),
        );

        // 3d adds inline:
        //   use crate::asset::DataTableData;
        //   let dt_sentinel = Asset::DataTable(DataTableData::empty());
        //   let disc = std::mem::discriminant(&dt_sentinel);
        //   reg.register(disc, Box::new(crate::export::data_table::DataTableCsvHandler));
        //   reg.register(disc, Box::new(crate::export::data_table::DataTableJsonHandler));
        //
        // The sentinel is constructed ONCE per variant and reused across all
        // handler registrations for that variant. DataTableData (and the
        // typed-variant inner types for 3e/3f/3g/3h) MUST expose a cheap
        // `empty()` / `Default::default()` constructor to avoid the
        // allocation-cost concern raised by the architect R2 review.
        reg
    }

    /// Register a handler under a specific `Asset` variant
    /// discriminant. Callers obtain the discriminant via
    /// `std::mem::discriminant(&Asset::SomeVariant(sentinel))` or
    /// use the per-variant convenience methods below
    /// (`register_for_generic`, `register_for_data_table`, etc.).
    pub fn register(
        &mut self,
        variant: Discriminant<Asset>,
        handler: Box<dyn FormatHandler>,
    ) {
        self.by_variant.entry(variant).or_default().push(handler);
    }

    // No per-variant `register_for_<variant>` helpers. The
    // sentinel-Asset pattern is used inline in
    // `all_default_handlers()` (the single registration site
    // controlled by this crate) — see Design Decision #12. Callers
    // outside this crate use `register(discriminant, handler)`
    // directly with `std::mem::discriminant(&Asset::Variant(...))`
    // at the call site; this keeps the API surface small and
    // avoids one helper per Asset variant.

    /// Find the first registered handler for `asset`'s variant
    /// whose [`FormatHandler::supports`] returns true. O(1)
    /// variant lookup + linear scan within bucket (typical: 1-3
    /// handlers per variant).
    #[must_use]
    pub fn find_handler(&self, asset: &Asset) -> Option<&dyn FormatHandler> {
        let disc = std::mem::discriminant(asset);
        self.by_variant.get(&disc).and_then(|bucket| {
            bucket
                .iter()
                .find(|h| h.supports(asset))
                .map(std::convert::AsRef::as_ref)
        })
    }

    /// Find a handler whose `supports(asset)` is `true` AND whose
    /// `output_extension()` matches `extension`.
    #[must_use]
    pub fn find_handler_by_extension(
        &self,
        extension: &str,
        asset: &Asset,
    ) -> Option<&dyn FormatHandler> {
        let disc = std::mem::discriminant(asset);
        self.by_variant.get(&disc).and_then(|bucket| {
            bucket
                .iter()
                .find(|h| h.supports(asset) && h.output_extension() == extension)
                .map(std::convert::AsRef::as_ref)
        })
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub mod generic;

pub use generic::GenericHandler;
```

> **Why `Discriminant<Asset>` and not `TypeId`?** `Discriminant` is exactly what we want — it identifies enum variants without comparing payload contents. `TypeId` would compare `Asset` to itself, which is useless. `Discriminant` derives `Hash + Eq`; `HashMap<Discriminant<Asset>, ...>` works out of the box.

> **Why a sentinel value for `register_for_generic`?** `std::mem::discriminant` takes `&T`, so we need an actual `Asset` to call it on. The sentinel is constructed once per `register_for_*` helper call; its payload is never read (Discriminant ignores payload). Total cost: one stack-allocated PropertyBag::Opaque variant per registration call. Acceptable. Avoids exposing the discriminant API surface to callers.

- [ ] **Step 4: Write failing unit test.**

```rust
// In export/mod.rs::tests, AFTER Task 3's GenericHandler exists:

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::bag::PropertyBag;

    #[test]
    fn registry_new_finds_nothing() {
        let reg = HandlerRegistry::new();
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        assert!(reg.find_handler(&asset).is_none());
    }

    #[test]
    fn registry_all_default_handlers_matches_generic() {
        let reg = HandlerRegistry::all_default_handlers();
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        let handler = reg.find_handler(&asset).expect("all-default-handlers");
        assert_eq!(handler.output_extension(), "json");
    }

    #[test]
    fn registry_discriminant_keying_isolates_variants() {
        // Different Asset variants with discriminant-keyed buckets
        // do NOT match each other's handlers. Phase 3a only has
        // Asset::Generic; this test re-runs at 3d when DataTable
        // ships to confirm cross-variant isolation. Until 3d,
        // assert only that Generic-registered handler exists.
        let reg = HandlerRegistry::all_default_handlers();
        let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
        assert!(reg.find_handler(&asset).is_some());
    }
}
```

(The `registry_all_default_handlers_matches_generic` and `registry_discriminant_keying_isolates_variants` tests will fail until Task 3 lands `GenericHandler`. Task 3 should run them as part of its own gate.)

- [ ] **Step 5: Run.** `cargo test -p paksmith-core export::tests::registry_new_finds_nothing 2>&1 | tail -5`. Expected: passes.

- [ ] **Step 6: Lint + test + doc gate.** Same shell block as Task 1 Step 7.

- [ ] **Step 7: Commit.**

```bash
git add crates/paksmith-core/src/lib.rs crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/asset/bulk_data.rs crates/paksmith-core/src/export/mod.rs
git commit -m "$(cat <<'EOF'
feat(export): FormatHandler trait + discriminant-keyed HandlerRegistry

BulkData ships as a unit struct; 3b's PR adds fields atomically.
Registry buckets handlers by std::mem::Discriminant<Asset>, with
supports() consulted only within-bucket for sub-variant disambiguation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `GenericHandler` implementation + integration test

**Files:**

- Create: `crates/paksmith-core/src/export/generic.rs`.
- Modify: `crates/paksmith-core/src/export/mod.rs` (verify `pub mod generic;` and re-export already exist from Task 2).

- [ ] **Step 1: Write the failing test in `generic.rs`.**

```rust
use crate::asset::Asset;
use crate::asset::property::bag::PropertyBag;
use super::{BulkData, FormatHandler};

/// Passthrough handler: emits the asset's parsed property tree as
/// pretty-printed JSON. Matches every `Asset::Generic` variant; never
/// matches typed Phase 3d-3g variants (they get their own handlers).
///
/// The output is JSON because the generic case is "we parsed the
/// properties but don't know the class shape" — emitting structured
/// JSON keeps the output human-inspectable and matches the existing
/// `paksmith inspect` precedent.
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericHandler;

impl FormatHandler for GenericHandler {
    fn output_extension(&self) -> &'static str {
        "json"
    }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::Generic(_))
    }

    fn export(
        &self,
        asset: &Asset,
        _bulk: Option<&BulkData>,
    ) -> crate::Result<Vec<u8>> {
        let Asset::Generic(bag) = asset else {
            // Registry contract violation — supports() returned true
            // but the asset isn't a Generic. Fire an internal error.
            return Err(crate::PaksmithError::Internal {
                context: "GenericHandler::export called on non-Generic Asset".into(),
            });
        };
        let pretty = serde_json::to_vec_pretty(bag).map_err(|e| {
            crate::PaksmithError::Internal {
                context: format!("GenericHandler JSON serialize: {e}"),
            }
        })?;
        Ok(pretty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_handler_opaque_emits_json() {
        let asset = Asset::Generic(PropertyBag::opaque(vec![0u8; 42]));
        let handler = GenericHandler;
        assert!(handler.supports(&asset));
        let bytes = handler.export(&asset, None).expect("export");
        let json = std::str::from_utf8(&bytes).expect("utf-8 json");
        // PropertyBag's `#[serde(tag = "kind", rename_all = "snake_case")]`
        // renders Opaque as {"kind": "opaque", "bytes": <count>}.
        assert!(json.contains("\"kind\": \"opaque\""), "got: {json}");
        assert!(json.contains("\"bytes\": 42"), "got: {json}");
    }

    #[test]
    fn generic_handler_extension_is_json() {
        assert_eq!(GenericHandler.output_extension(), "json");
    }

    #[test]
    fn generic_handler_does_not_support_unknown_variant() {
        // No typed variants exist in 3a; this test asserts that the
        // ExportFamily::Unknown carrier path doesn't accidentally
        // route through Generic. When 3d adds Asset::DataTable,
        // GenericHandler.supports(Asset::DataTable(_)) MUST stay false.
        //
        // 3a-portable assertion: supports() is keyed on the variant,
        // not on a fallback. The match-arm is `Asset::Generic(_)`
        // explicitly.
        // (No assertion possible until 3d-3g typed variants exist;
        // this test exists to document the contract. The match-arm
        // discipline in supports() above is the load-bearing piece.)
    }
}
```

> **Why `PaksmithError::Internal`?** The "registry contract violation" branch is unreachable when `supports()` is consulted first by the registry. A defensive error rather than a panic keeps the library's no-panics-in-core invariant intact. If `PaksmithError::Internal` doesn't exist yet, add it as part of this task (`#[error("internal error: {context}")]` — match the existing `PaksmithError` `#[error]` annotation pattern).

- [ ] **Step 2: Run failing test, verify Task 2's `registry_all_default_handlers_matches_generic` test now passes.**

```shell
set -o pipefail
cargo test -p paksmith-core export::generic::tests 2>&1 | tail -10
cargo test -p paksmith-core export::tests::registry_all_default_handlers_matches_generic 2>&1 | tail -5
```

- [ ] **Step 3: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 4: Commit.**

```bash
git add crates/paksmith-core/src/export/generic.rs crates/paksmith-core/src/error.rs
git commit -m "$(cat <<'EOF'
feat(export): GenericHandler emits Asset property tree as JSON

Default handler for Asset::Generic — the only Asset variant in 3a.
Phase 3d-3g add typed variants; their handlers leave Generic alone.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Class-name dispatch table (`HashMap<&'static str, TypedReaderFn>`) + `read_payloads` integration

**Files:**

- Create: `crates/paksmith-core/src/asset/exports/mod.rs` + `crates/paksmith-core/src/asset/exports/dispatch.rs`.
- Modify: `crates/paksmith-core/src/asset/mod.rs` (declare `pub(crate) mod exports;`).
- Modify: `crates/paksmith-core/src/asset/package.rs` — `read_payloads` consults the dispatch table per-export.

The dispatcher maps class-name → reader-fn directly. No intermediate discriminator enum — the reader-fn returns the typed `Asset` variant for its class. HashMap miss = no typed reader exists for that class = fall through to the existing Phase 2 generic property-bag iteration (also stored as `Asset::Generic(bag)` per Task 1's migration). This eliminates the `ExportFamily` mirror enum, the unreachable Unknown(String) variant, and the per-sub-phase match-arm extension burden.

- [ ] **Step 1: Create `asset/exports/mod.rs`.**

```rust
//! Phase 3 typed export readers. Today (3a) empty; 3d-3h populate
//! with `data_table.rs`, `texture/`, `audio/`, `mesh/` submodules.
//!
//! The dispatch from class-name → typed-reader-fn lives in
//! `dispatch.rs`. Each sub-phase (3d/3e/3f/3g/3h) inserts one
//! `&'static str → fn(...)` entry; the reader-fn returns the
//! typed `Asset::*` variant for its class.

pub(crate) mod dispatch;
```

- [ ] **Step 2: Create `asset/exports/dispatch.rs` with empty initial table.**

```rust
//! Class-name → typed-reader-fn dispatch.
//!
//! Phase 3a ships an empty table — `read_payloads` falls through to
//! the existing Phase 2 generic property-bag iteration on every
//! export. Phase 3d-3h add the five known classes by extending
//! `class_dispatch_init()`.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::asset::{Asset, AssetContext};

/// Signature for a typed-export reader. Each sub-phase's reader-fn
/// takes the export's serialized payload bytes (the slice carved
/// from `bytes` by `Package::read_from`'s `carve_export_slice`
/// helper), the parsing context, and the asset path (for error
/// reporting). Returns the typed `Asset` variant for the class
/// PLUS the `FByteBulkData` records the reader collected during
/// parse.
///
/// **Why the tuple return?** Typed readers parse `FByteBulkData`
/// metadata records mid-parse (e.g. per-mip records in `Texture2D`).
/// Those records need to land in `Package::bulk_data` so 3b's lazy
/// resolver can materialize bytes on demand. The dispatch site
/// (`Package::read_from::read_payloads`) is the natural owner of
/// `&mut Package` and drives the `insert_bulk_records` insertion.
/// Routing records through the reader's return value keeps the
/// reader a pure function (bytes in, structured data out) — it
/// doesn't need `&mut Package` access at all.
///
/// Most readers collect zero records (DataTable, generic property
/// bag) and return `Vec::new()`. Texture / mesh / audio readers
/// populate the vec during parse.
pub(crate) type TypedReaderFn = fn(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<crate::asset::bulk_data::FByteBulkData>)>;

/// Returns the lazily-initialized class-name dispatch table.
///
/// Keys are interned engine class names (`"Texture2D"`,
/// `"StaticMesh"`, etc.). A class name absent from the map = no
/// typed reader registered = `read_payloads` falls through to the
/// generic property-bag path.
pub(crate) fn class_dispatch() -> &'static HashMap<&'static str, TypedReaderFn> {
    static TABLE: OnceLock<HashMap<&'static str, TypedReaderFn>> = OnceLock::new();
    TABLE.get_or_init(class_dispatch_init)
}

fn class_dispatch_init() -> HashMap<&'static str, TypedReaderFn> {
    let table: HashMap<&'static str, TypedReaderFn> = HashMap::new();

    // Phase 3a ships empty. Each later sub-phase inserts one entry:
    //
    //   3d: table.insert("DataTable", crate::asset::exports::data_table::read_typed);
    //   3d: table.insert("CompositeDataTable", crate::asset::exports::data_table::read_typed);
    //   3e: table.insert("Texture2D", crate::asset::exports::texture::texture2d::read_typed);
    //   3f: table.insert("SoundWave", crate::asset::exports::audio::sound_wave::read_typed);
    //   3g: table.insert("StaticMesh", crate::asset::exports::mesh::static_mesh::read_typed);
    //   3h: table.insert("SkeletalMesh", crate::asset::exports::mesh::skeletal_mesh::read_typed);
    //
    // Each `read_typed` function constructs the typed Asset variant
    // (e.g. `Ok(Asset::DataTable(data))`) and returns it directly.

    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dispatch_returns_empty_table() {
        assert!(class_dispatch().is_empty());
    }
}
```

- [ ] **Step 3: Wire the dispatch into `read_payloads`.**

`Package::read_from`'s payload loop already resolves `class_name` per export (`package.rs:582-591`). After resolution, look up the dispatch table. HashMap hit → typed reader produces `Asset::*`; HashMap miss → existing Phase 2 property-bag iteration produces `Asset::Generic(bag)`. There is no intermediate discriminator enum; the only branch is "did the lookup hit or miss." Both branches push exactly one `Asset` onto `payloads`.

```rust
// In read_payloads, replacing the existing PropertyBag-emit site.
// `payloads_buf` is the in-progress Vec<Asset>; `bulk_inserts` is a
// parallel Vec<(usize, Vec<FByteBulkData>)> accumulating records to
// install into Package::bulk_data AFTER read_payloads returns (since
// the Package is still being constructed at this point).

let class_name_str: &str = class_name.as_ref();
let (asset, bulk_records) = if let Some(read_typed) = crate::asset::exports::dispatch::class_dispatch().get(class_name_str) {
    // Typed reader exists for this class name.
    let payload = carve_export_slice(bytes, export, asset_path)?;
    read_typed(payload, &ctx, asset_path)?
} else {
    // No typed reader → fall through to existing Phase 2 path.
    tracing::trace!(
        export.class = class_name_str,
        "no typed reader registered; using Generic property-bag iteration"
    );
    let bag = /* existing read_payloads property-bag construction */;
    (Asset::Generic(bag), Vec::new())
};
if !bulk_records.is_empty() {
    bulk_inserts.push((export_idx, bulk_records));
}
payloads_buf.push(asset);
```

After the loop, `Package::read_from` calls `pkg.insert_bulk_records(idx, records)?` for each entry in `bulk_inserts` (Package now has `&mut self` because we're still constructing it). The defensive `MAX_BULK_DATA_RECORDS_PER_EXPORT` cap fires here at the single insertion boundary.

> The `tracing::trace!` level (NOT `debug!`) means production runs don't spam — only enabled when an operator explicitly cranks tracing for class-coverage debugging. Trace is appropriate because in the steady state, MOST class names are unknown to paksmith (UE shipping content carries thousands of distinct classes; Phase 3 covers five).

> No `unreachable!()` arm; no exhaustive `match` over typed families. The `if let Some` is exhaustive over the two real cases (typed vs generic).

> **Architectural note (R3 fix):** the typed reader returns `(Asset, Vec<FByteBulkData>)` rather than calling `insert_bulk_records` directly — the reader is a pure function (no `&mut Package` access required, no `Result` Ψ-cascade in plumbing). 3e/3f/3g/3h's reader implementations return the records they collected; the dispatch caller drives insertion at the boundary. The R2-version's "must `?`-propagate" callouts in those sub-phase plans become obsolete and are dropped.

- [ ] **Step 4: Run tests, verify nothing breaks.**

```shell
set -o pipefail
cargo test --workspace --all-features 2>&1 | tail -15
```

The existing Phase 2 test suite (~600 tests) must still pass — 3a's parse-time dispatch is a no-op routing layer.

- [ ] **Step 5: Lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/asset/exports/mod.rs crates/paksmith-core/src/asset/exports/dispatch.rs crates/paksmith-core/src/asset/mod.rs crates/paksmith-core/src/asset/package.rs
git commit -m "$(cat <<'EOF'
feat(asset): wire class-name dispatch into read_payloads (empty table)

Phase 3a: dispatch table is empty; every export still routes through
the generic property-bag iteration via the if-let fall-through.
Phase 3d-3h each insert one entry mapping class-name -> typed reader
fn that returns the typed Asset variant directly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Public re-exports + doc test + final gate

**Files:**

- Modify: `crates/paksmith-core/src/lib.rs` — re-export the public surface.

- [ ] **Step 1: Add public re-exports in `lib.rs`.**

```rust
// At the existing `pub use` block:
pub use export::{BulkData, FormatHandler, GenericHandler, HandlerRegistry};
```

- [ ] **Step 2: Add a doc test demonstrating the public API.**

In `export/mod.rs`'s module-level doc comment:

```rust
//! # Quick start
//!
//! ```rust,no_run
//! use paksmith_core::export::HandlerRegistry;
//! use paksmith_core::asset::Asset;
//! use paksmith_core::asset::property::bag::PropertyBag;
//!
//! // The default registry has every Phase-3-defined handler.
//! let reg = HandlerRegistry::all_default_handlers();
//!
//! // Phase 2 always yields Asset::Generic.
//! let asset = Asset::Generic(PropertyBag::opaque(Vec::new()));
//!
//! // Find the matching handler and run it.
//! if let Some(handler) = reg.find_handler(&asset) {
//!     let bytes = handler.export(&asset, None).expect("export");
//!     let ext = handler.output_extension(); // "json"
//!     // Caller writes `bytes` to `path.{ext}`.
//! }
//! ```
```

- [ ] **Step 3: Run doc test.**

```shell
set -o pipefail
cargo test -p paksmith-core --doc export 2>&1 | tail -10
```

- [ ] **Step 4: Final lint + test + doc gate.** Same shell block as Task 1 Step 5.

- [ ] **Step 5: Verify GHAS-equivalent gates locally.**

```shell
set -o pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features 2>&1 | tail -15
cargo clean -p paksmith-core
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features 2>&1 | tail -10
```

Per `feedback_cargo_doc_in_local_gates.md`: rustdoc lints (private_intra_doc_links, invalid_html_tags) fail CI's `Lint / Build docs` but slip past local clippy. The doc-test addition in Task 5 broadens the rustdoc surface; this gate is mandatory.

- [ ] **Step 6: Commit.**

```bash
git add crates/paksmith-core/src/lib.rs crates/paksmith-core/src/export/mod.rs
git commit -m "$(cat <<'EOF'
feat(export): re-export FormatHandler API + add doc test

Closes Phase 3a. paksmith_core::export is the public surface for
3d-3g format handlers.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Review panel (per `feedback_parallel_full_review_panel.md` + `feedback_specialist_reviewers_default.md`)

Minimum for every Task PR:

- `feature-dev:code-reviewer` — bugs, logic, security.
- `feature-dev:code-architect` — design, conventions, API impact (trait shape, `#[non_exhaustive]` semver implications).
- `code-simplifier:code-simplifier` — DRY, clarity (the new `export/` + `asset/exports/` boundary deserves scrutiny).

Mandatory specialists for 3a (per the four-trigger walk):

- **Wire-format pass** — no wire-format work in 3a; skip.
- **Security pass** — Task 4 changes the parse-time dispatch; any new attacker-controllable branch needs review. Mandatory.
- **Deep-impact tracer** — Task 1's `#[non_exhaustive]` is a SemVer-affecting change; ripples through external API consumers. Mandatory for Task 1 + Task 5 PRs.
- **Performance** — no hot-path edits in 3a; skip.

So most tasks get 4 reviewers (3 standard + security or architect-deep-impact); Task 1 + Task 5 get 5 (add deep-impact specialist).

## Convergence loop

Per `feedback_review_until_convergence.md`: after applying review-driven fixes, re-dispatch the full panel on the fix commit (R2, R3...). Stop only when every reviewer reports APPROVED. fmt/clippy/tests passing is NOT a substitute for re-review.

## After all 5 tasks land

- The class-dispatch table is empty but wired. 3d-3h extend `class_dispatch_init` + add typed reader arms in `read_payloads`.
- `paksmith inspect` produces identical output to Phase 2 closure (no behavior change — `GenericHandler` is registered but the inspect command path doesn't consult the registry).
- `paksmith-core` exposes `FormatHandler`, `HandlerRegistry`, `GenericHandler`, `BulkData` (placeholder) as `pub`.
- 3b can land in parallel with 3d (3b replaces `BulkData`'s placeholder fields; 3d adds the first typed `Asset` variant).

---

## References

- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Most-recent sub-phase plan as structural model: [`phase-2g-collection-of-struct.md`](phase-2g-collection-of-struct.md).
- Current class-name resolution site: `crates/paksmith-core/src/asset/package.rs:194-203, 582-591`.
- Trait `#[non_exhaustive]` SemVer reference: <https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute>.
