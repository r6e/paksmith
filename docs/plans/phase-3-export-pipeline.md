# Paksmith Phase 3: Export Pipeline (master index)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each sub-phase plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This document is the **index**, not the implementation plan — pick the sub-phase doc that matches the work you're starting.

**Goal:** Convert parsed UE assets into standard interchange formats (PNG, glTF, WAV/OGG, CSV/JSON). Establishes the `FormatHandler` trait + per-class typed `Asset` variants that everything downstream of Phase 2's generic `PropertyBag` consumes.

**Architecture:** Two layers, both new in Phase 3:

1. **Parse-time specialization.** Per-export dispatch in `Package::read_from` consults a per-class-name table; known classes (`Texture2D`, `StaticMesh`, `SoundWave`, `DataTable`, ...) read into typed `Asset::Texture2D { .. }` / `Asset::Mesh { .. }` / `Asset::Sound { .. }` / `Asset::DataTable { .. }` variants. Unknown classes continue to surface as `Asset::Generic(PropertyBag)`. This is independent of `FormatHandler` — it changes the shape of `Package::payloads`.
2. **Export-time format handlers.** The new `FormatHandler` trait takes a typed `&Asset` (plus optional bulk data from 3b's resolver) and produces target-format bytes. A `HandlerRegistry` dispatches by `Asset` variant (not by class name — the parse-time layer has already done the class-name lookup). 3a ships a `Generic` passthrough handler that emits raw entry bytes; 3d-3g add typed handlers per class.

The split matches Phase 2's `PropertyBag::Tree` / `PropertyBag::Opaque` pattern — typed parsing first, generic export as fallback — and lets format-handler decoders work against a structured input rather than raw FName/FPropertyTag streams.

**Tech Stack:** Same as Phase 2 (Rust 1.85+, `byteorder`, `serde`, `thiserror`, `tracing`) plus per-sub-phase additions:

- 3a: no new deps.
- 3b: no new deps (reuses existing zlib path; Oodle deferred to Phase 8's IoStore work).
- 3c: no new deps.
- 3d: `csv` workspace dep (CSV writer); `serde_json` already in dev-deps, promote to a feature-gated runtime dep for the JSON output path.
- 3e: decoder crate selection deferred to kickoff — candidates documented in `phase-3e-texture-export.md` (texture2ddecoder vs bcdec vs intel_tex_2 vs pure-Rust).
- 3f: passthrough for OGG/OPUS needs no decoder; **MVP PCM→WAV** and follow-up **ADPCM→WAV** both need a WAV writer (`hound` recommended, or ~50 lines hand-rolled RIFF — decided at 3f kickoff per `phase-3f-audio-export.md` §Crate selection); WEM→OGG header rewrite (follow-up) needs no decoder. Vorbis/Opus decode itself is **out of scope** for Phase 3 — export-to-target-format only (full decode lives in Phase 7's GUI playback path).
- 3g: glTF crate selection deferred — `gltf` (full reader+writer, heavy) vs `gltf-json` (writer-only, lighter) candidates documented in `phase-3g-staticmesh-export.md`.

---

## Sub-phase index

| #  | Title                                | Status   | Depends on       | Doc                                                                                 |
|----|--------------------------------------|----------|------------------|-------------------------------------------------------------------------------------|
| 3a | FormatHandler trait + registry       | planned  | Phase 2          | [`phase-3a-format-handler-trait.md`](phase-3a-format-handler-trait.md)              |
| 3b | FByteBulkData byte access (all tiers + .uptnl) | planned | Phase 2 | [`phase-3b-bulk-data-resolver.md`](phase-3b-bulk-data-resolver.md)                  |
| 3c | Typed engine struct decoders         | planned  | Phase 2g         | [`phase-3c-typed-binary-structs.md`](phase-3c-typed-binary-structs.md)              |
| 3d | DataTable → CSV/JSON                 | planned  | 3a               | [`phase-3d-datatable-export.md`](phase-3d-datatable-export.md)                      |
| 3e | Texture2D → PNG (incl. virtual textures) | overview | 3a, 3b      | [`phase-3e-texture-export.md`](phase-3e-texture-export.md)                          |
| 3f | SoundWave → WAV / OGG                | overview | 3a, 3b           | [`phase-3f-audio-export.md`](phase-3f-audio-export.md)                              |
| 3g | StaticMesh → glTF 2.0 (incl. Nanite) | overview | 3a, 3b, 3c       | [`phase-3g-staticmesh-export.md`](phase-3g-staticmesh-export.md)                    |
| 3h | SkeletalMesh → glTF 2.0 (bones + skinning) | overview | 3a, 3b, 3c, 3g | [`phase-3h-skeletalmesh-export.md`](phase-3h-skeletalmesh-export.md)               |

**Status legend:**

- **planned** — full Phase-2g-style TDD task list with hand-built byte fixtures, in-source unit tests, and per-task lint/test/doc/commit gates. Ready to execute.
- **overview** — architecture + scope + tech-stack candidates + milestone breakdown. Crate selection and per-task TDD steps are kickoff work. The wire-format reference lives in the `docs/formats/` family (linked from each overview); a deep TDD plan would mostly transcribe those docs and get rewritten as soon as the crate choice settles, so we don't pre-write it.

This split matches Phase 2's evolution: 2a + 2b shipped before 2c-2g's detailed plans were locked. The deep plans for 3a-3d unblock real downstream work; the overviews for 3e-3g establish the architectural commitments without freezing premature implementation detail.

---

## Dependency graph

```plaintext
Phase 2 (✓) ──┬─ 3a ──┬─ 3d
              │       ├─ 3e ── (kickoff: pick texture decoder crate)
              ├─ 3b ──┤
              │       └─ 3f ── (MVP: OGG/OPUS passthrough; follow-ups: ADPCM→WAV, WEM→OGG)
              └─ 3c ──┬─ 3g ── (may split into 3g1 parse / 3g2 glTF lower)
                      │
                      └─ 3h ── (depends on 3g for vertex-buffer reader reuse)
```

**Critical-path notes:**

- **3a is sequential before all export work.** No format handler can land without the trait. Ship 3a first.
- **3b unblocks 3e and 3g** (both need bulk data — texture mips, mesh vertex buffers). 3d and 3f's MVP do not depend on 3b: 3d's row data is fully in the export payload (`.uexp` or inline); 3f's OGG/OPUS passthrough operates on the FFormatContainer buffer which is itself a FByteBulkData record but the MVP passthrough can route directly through the inline tier without going through the resolver. 3f's ADPCM/WEM follow-ups do need 3b.
- **3c unblocks only 3g.** It does NOT block 3e — mip headers use `FByteBulkData` (u32/i64 fields), not `FVector`/`FQuat`. Tangent-basis packing in vertex-formats.md uses `FPackedNormal` / `FPackedRGBA16N` (raw bit-packing), also not engine-struct family. 3c is purely a 3g enabler.
- **3a, 3b, 3c can ship in parallel** since none depends on another. Ship 3a first because 3d is the smallest export that validates the trait shape; 3b and 3c can ship in any order before their dependents.

---

## Scope vs deferred work (Phase 3 as a whole)

**In scope (Phase 3):**

- `FormatHandler` trait + `HandlerRegistry` (3a).
- Per-class parse-time specialization for `Texture2D`, `StaticMesh`, `SkeletalMesh`, `SoundWave`, `DataTable` (3d/3e/3f/3g/3h).
- `BulkDataResolver` over **all four storage tiers**: inline, uexp-resident, `.ubulk` (streaming), `.uptnl` (optional streaming) (3b).
- Typed engine struct decoders: `FVector`, `FRotator`, `FQuat`, `FColor`, `FLinearColor`, `FBox`, `FTransform` (3c).
- Export formats: PNG (texture), glTF 2.0 (static + skeletal mesh), WAV / OGG (audio), CSV / JSON (data table).
- **Virtual textures** (`FVirtualTextureBuiltData`): documented and parsed within 3e's `Texture2D` reader. Export path may be a 3e follow-up (page-table reassembly to a flat tiled PNG is non-trivial); the parser does NOT silently ignore VT — it surfaces them either as a typed export (when 3e's MVP supports it) or via a tracked follow-up issue in 3e's plan.
- **Nanite-enabled meshes** (`FNaniteResources`): parsed within 3g's `StaticMesh` reader. The classic LOD fallback is always present in cooked content (per the wire-format doc); 3g's MVP exports the classic LOD path. Nanite-specific export (virtualized-mesh page tables) is a 3g follow-up tracked in its own plan, NOT a separate sub-phase.
- **LZO (`BULKDATA_CompressedLZO`) + BitWindow (`BULKDATA_SerializeCompressedBitWindow`) bulk compression**: rare in cooked content per the format docs; 3b ships `UnsupportedBulkCompression { method }` for both with a tracked follow-up issue. When a real-world fixture surfaces, decoders land as Phase 3 follow-up work (no new sub-phase needed — pluggable into 3b's resolver dispatch).

**Deferred to NAMED later phases (NOT artificial scope-trimming):**

- **Proprietary audio codecs.** BINKA (RAD), XMA2 (Microsoft Xbox), AT9 (Sony PlayStation), OPUSNX (Nintendo Switch). All four require licensed SDKs. → **Phase 8.** Phase 8 already ships the runtime-loaded shared-library pattern for Oodle (per ROADMAP §Phase 8 design decisions); BINKA/XMA2/AT9/OPUSNX use the same SDK-loader shape. 3f surfaces them as `UnsupportedAudioCodec` with a known-Phase-8 hook.
- **Oodle-compressed bulk data.** → **Phase 8.** Same SDK-loader pattern; piggy-backs on Phase 8's Oodle integration. 3b surfaces as `UnsupportedBulkCompression { method: "Oodle" }`.
- **Vorbis / Opus / ADPCM full-pipeline decode** (raw PCM samples, for in-app playback). → **Phase 7 (GUI Asset Viewers).** Phase 3's job is export-to-file: passthrough OGG/OPUS by rewriting the FFormatContainer buffer verbatim as `.ogg` / `.opus`, ADPCM→WAV via a small public-spec decoder. Playing audio in the GUI preview pane is a Phase 7 ASSET VIEWER concern with different latency / streaming / format-conversion requirements than file export.
- **`paksmith extract` CLI command.** → **Phase 4 (Full CLI).** Per ROADMAP §Phase 4 explicit deliverables. Phase 3 ships the library-side `FormatHandler` + registry; Phase 4 wires the CLI surface.
- **`pub` API for `BulkData` and `Package::bulk_data`.** → **Phase 4.** Phase 3 keeps these `pub(crate)` because the only consumers are 3d-3h's typed readers; Phase 4 promotes when external callers (CLI extract, GUI) consume.
- **Memory-mapped bulk-data reads** (`BULKDATA_MemoryMappedPayload`, `BULKDATA_DataIsMemoryMapped`). → **Phase 4 performance pass** alongside `paksmith extract`'s bulk-extraction flow, where memory pressure first becomes measurable.
- **Async lazy-loadable resolution** (`BULKDATA_LazyLoadable`). → **Phase 5.** Per ROADMAP §Phase 5: "Async runtime (tokio or otherwise) deferred until Phase 5 introduces network fetch." Same runtime introduction unlocks lazy bulk-data resolution.

---

## Design decisions locked here

1. **Parse-time `Asset` variants are NEW in Phase 3.** Phase 2 ships `Asset::Generic(PropertyBag)`. Phase 3 adds `Asset::Texture2D { .. }`, `Asset::StaticMesh { .. }`, `Asset::SoundWave { .. }`, `Asset::DataTable { .. }`. The fallback to `Generic` stays for unknown class names. The `Asset` enum is `#[non_exhaustive]` so adding variants in 3d/3e/3f/3g is a minor version bump, not a breaking change.

2. **Dispatch is by class name at parse time, via a direct fn-pointer table.** `Package::read_from` resolves each export's `class_index` to a class FName (already done at `package.rs:194-203` + `582-591`), then consults a `HashMap<&'static str, fn(&[u8], &AssetContext, &str) -> Result<Asset>>` table. HashMap hit → typed reader produces the typed `Asset::*` variant directly; HashMap miss → fall through to the existing generic property-bag iteration (also wrapped as `Asset::Generic(bag)` per the Task 1 `Vec<PropertyBag>` → `Vec<Asset>` migration). No intermediate `ExportFamily` discriminator enum, no `unreachable!()` arm, no `Unknown(String)` allocation. Telemetry for unknown classes uses `tracing::trace!` with a `&str` argument (zero-alloc). Each typed reader is a free function in `asset/exports/<family>/<class>.rs` exposing a `pub(crate) read_typed` shim that calls its sibling `read_from` and wraps the result in the appropriate `Asset::*` variant.

3. **`FormatHandler` is the EXPORT-time trait, decoupled from parse-time readers.** The trait shape locks in 3a:

   ```rust
   pub trait FormatHandler: Send + Sync {
       /// File extension for the produced output (e.g. "png", "gltf", "csv").
       fn output_extension(&self) -> &'static str;
       /// Sub-variant support check (consulted within the per-variant
       /// bucket; the discriminant-keyed registry has already filtered
       /// the Asset variant). Returns true unconditionally if the
       /// handler doesn't care about sub-variants.
       fn supports(&self, asset: &Asset) -> bool;
       /// Convert `asset` (+ optional bulk data) into output bytes.
       fn export(&self, asset: &Asset, bulk: Option<&BulkData>) -> crate::Result<Vec<u8>>;
   }
   ```

   `BulkData` is 3b's resolved-bytes type (per-record byte slice keyed by the source `FByteBulkData` record). `Asset` is the typed parse output. Returning `Vec<u8>` keeps handlers stateless and side-effect-free; the caller (CLI `extract`, GUI viewer, fixture-gen) decides where to write.

4. **`HandlerRegistry` is discriminant-keyed.** `HashMap<std::mem::Discriminant<Asset>, Vec<Box<dyn FormatHandler>>>` — O(1) variant lookup followed by linear scan of the per-variant bucket (typically 1-3 handlers). Handlers register via `register(discriminant, handler)` or convenience helpers like `register_for_generic`, `register_for_data_table`, etc. Multiple handlers per `Asset` variant is supported (e.g. `DataTable` → CSV or JSON depending on user choice); the caller picks via `find_handler_by_extension`. Single `HandlerRegistry::all_default_handlers()` constructor registers every Phase 3 handler; each sub-phase extends additively.

5. **No async in Phase 3.** All readers + handlers are blocking. Async deferred to Phase 5 (network registry fetch). Bulk-data reads are blocking `Read + Seek` per the existing PakReader pattern.

6. **Memory model: owned bytes, lazy resolution.** `BulkData::bytes` is owned (`Vec<u8>`), not a slice into the pak buffer. The pak buffer's lifetime is shorter than the `Asset` enum's; borrowing would force lifetime-parameter contamination across the entire export pipeline. The cost is one allocation per resolved bulk record — mitigated by (a) lazy resolution (records aren't materialized until `Package::resolve_bulk_for_export` is called) and (b) `ContainerReader::read_entry_to(&mut Write)` on streaming-tier reads to avoid a double-copy when only a sub-range of `.ubulk` / `.uptnl` is needed. See 3b Design Decisions #3 and #5.

7. **Caps are per-sub-phase.** `MAX_TEXTURE_DIMENSION` / `MAX_MIP_COUNT` / `MAX_DECODED_TEXTURE_BYTES` (3e), `MAX_VERTICES_PER_LOD` / `MAX_LODS_PER_MESH` (3g), `MAX_AUDIO_DECODED_BYTES` / `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE` (3f), `MAX_ROWS_PER_DATATABLE` (3d). Each sub-phase's plan defines its caps. The format docs already prescribe most of these — sub-phase plans pin the values and ship the `#[cfg(feature = "__test_utils")]` accessors per CLAUDE.md convention.

8. **Wire-format invariants come from `docs/formats/`, not engine source.** Every sub-phase plan cites the relevant `docs/formats/<family>/*.md` doc as its wire-format reference. Source attribution stays within the format docs (CUE4Parse / unreal_asset / FModel / UE4SS), never engine source per `feedback_no_ue_source_attribution_in_public_docs.md`.

---

## Naming convention: `asset/exports/` vs `export/`

These are TWO different concepts; the names are domain-loaded but distinct:

- **`asset/exports/`** — *parse-time* typed readers, one submodule per UE class. The directory name mirrors UE's wire-format terminology: a `UObject` instance written to disk is called an "export" (per `FObjectExport`, `ExportTable`, the cooker's "exports the cooker emits"). `asset/exports/data_table.rs` reads `UDataTable` from bytes; `asset/exports/texture/texture2d.rs` reads `UTexture2D`; etc. Returns typed `Asset::*` variants.
- **`export/`** — *export-time* output handlers, one submodule per output format. `export/data_table.rs` writes a `Asset::DataTable` to CSV or JSON bytes; `export/texture.rs` writes to PNG; etc. Implements `FormatHandler`.

The collision is unavoidable without renaming one side away from UE terminology (a real cost — every paksmith contributor familiar with UE format docs expects "exports" to mean serialized UObject records). The use-path disambiguation is clean: `paksmith_core::asset::exports::data_table` (parse) vs `paksmith_core::export::data_table` (write). A doc-comment at the top of each module's `mod.rs` reinforces the split for fresh-eyes contributors.

**Follow-up:** when Phase 3a's PR lands, propagate this naming-distinction explanation into `CONTRIBUTING.md`. Plan docs go cold post-ship; the naming wart persists in the codebase and contributors deserve a stable reference. Tracked as a Phase 3a polish item rather than a separate sub-phase.

## Module layout (post-Phase 3)

```plaintext
crates/paksmith-core/src/
├── asset/                              (Phase 2; extended in Phase 3)
│   ├── mod.rs                          # Asset enum: Generic + new typed variants
│   ├── package.rs                      # parse-time class-name dispatch (3a)
│   ├── exports/                        # NEW in Phase 3
│   │   ├── mod.rs                      # exports module barrel + dispatch table
│   │   ├── structs/                    # 3c: typed engine struct decoders
│   │   │   ├── mod.rs
│   │   │   ├── vector.rs               # FVector / FVector2D / FVector4
│   │   │   ├── rotator.rs              # FRotator
│   │   │   ├── quat.rs                 # FQuat
│   │   │   ├── color.rs                # FColor + FLinearColor
│   │   │   ├── box_.rs                 # FBox / FBox2D
│   │   │   └── transform.rs            # FTransform
│   │   ├── texture/                    # 3e: Texture2D + platform data + mips
│   │   │   ├── mod.rs
│   │   │   ├── texture2d.rs            # UTexture2D parser
│   │   │   ├── platform_data.rs        # FTexturePlatformData
│   │   │   ├── mip.rs                  # FTexture2DMipMap + FByteBulkData
│   │   │   └── pixel_format.rs         # EPixelFormat enum + per-format decoders
│   │   ├── mesh/                       # 3g + 3h: Static + Skeletal mesh
│   │   │   ├── mod.rs
│   │   │   ├── static_mesh.rs          # 3g: UStaticMesh parser
│   │   │   ├── skeletal_mesh.rs        # 3h: USkeletalMesh parser
│   │   │   ├── skeleton.rs             # 3h: bone hierarchy (FReferenceSkeleton)
│   │   │   ├── render_data.rs          # FStaticMeshRenderData
│   │   │   ├── lod.rs                  # FStaticMeshLODResources
│   │   │   ├── section.rs              # FStaticMeshSection
│   │   │   ├── vertex_buffers.rs       # FPositionVertexBuffer, etc. (shared 3g/3h)
│   │   │   ├── index_buffer.rs         # FRawStaticIndexBuffer (shared)
│   │   │   └── skin_weights.rs         # 3h: FSkinWeightVertexBuffer
│   │   ├── audio/                      # 3f: SoundWave + codec dispatch
│   │   │   ├── mod.rs
│   │   │   ├── sound_wave.rs           # USoundWave parser
│   │   │   ├── format_container.rs     # FFormatContainer + codec dispatch
│   │   │   └── streamed.rs             # FStreamedAudioPlatformData
│   │   └── data_table.rs               # 3d: UDataTable parser
│   └── bulk_data.rs                    # 3b: FByteBulkData + BulkDataResolver
├── export/                             # NEW in Phase 3
│   ├── mod.rs                          # FormatHandler trait + HandlerRegistry
│   ├── generic.rs                      # 3a: Generic passthrough handler
│   ├── data_table.rs                   # 3d: CSV + JSON handlers
│   ├── texture.rs                      # 3e: PNG handler
│   ├── audio.rs                        # 3f: WAV / OGG / OPUS handlers
│   ├── static_mesh.rs                  # 3g: glTF handler (static)
│   └── skeletal_mesh.rs                # 3h: glTF handler (skeletal, with skin)
```

---

## Milestones & deliverable signals

Each sub-phase's "done" signal is the CLI behavior:

- **3a done:** `paksmith inspect` continues to work, with one shape change: every `Package::payloads` entry now wraps as `Asset::Generic(bag)` (externally-tagged in JSON). `paksmith-core` exposes `FormatHandler` + `HandlerRegistry` + `register_for_generic` as `pub` API. A `Generic` handler that emits the parsed property tree as pretty JSON is registered by default (per 3a Design Decision #10 — NOT raw entry bytes, which are recoverable directly from `PakReader::read_entry` without going through the handler layer). Single `HandlerRegistry::all_default_handlers()` constructor, no `default_with_*_handlers` cascade.
- **3b done:** `Package::read_from_pak` no longer logs the "ubulk found but not stitched" warn. The `BulkDataResolver` is plumbed and integration-tested against synthetic fixtures across all four tiers (inline / uexp-resident / streaming / optional-streaming). **Resolution is LAZY** — `read_from_pak` constructs the resolver but doesn't materialize bulk bytes; `paksmith inspect` and GUI-tree-view workloads never trigger I/O on `.ubulk` / `.uptnl`. Sparse `Package::bulk_data: HashMap<usize, (Vec<FByteBulkData>, OnceLock<Vec<BulkData>>)>` (single map, tuple values — kept in lockstep at the `insert_bulk_records` boundary) holds parse-time records + lazy byte caches. Typed readers in 3e/3g/3h call `Package::insert_bulk_records(idx, records)` during parse + call `Package::resolve_bulk_for_export(idx)` from inside their export-time `FormatHandler::export()` paths to fill the cache on-demand. The new `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` global cap (enforced BEFORE allocation, with `AtomicU64::fetch_add(claimed_size, Relaxed)` against the wire-claimed size) defends against per-record × records-per-export × exports-count OOM; defensive `MAX_BULK_DATA_RECORDS_PER_EXPORT` enforcement at `insert_bulk_records` closes the loophole where a future export class might bypass typed-reader cap enforcement. Resolver owns `stitched: Arc<[u8]>` (NOT `&'a [u8]`) so no lifetime parameter contaminates `Package`.
- **3c done:** Phase 2g's empty-`PropertyBag::Struct` fallback for **all 11 dispatched engine structs** (FVector / FVector2D / FVector4 / FRotator / FQuat / FColor / FLinearColor / FBox / FBox2D / FTransform / FBoxSphereBounds) is replaced by typed decoded values. `paksmith inspect` JSON output renders these structs with real coordinates / quaternions / colors. **The Phase 2 inspect JSON snapshot rewrite is MANDATORY** (not "if needed") — every existing fixture asset carrying e.g. `LightingGuid: StructProperty(Guid)` now surfaces under the new `PropertyValue::TypedStruct(Box(TypedStructValue::*))` shape. This is documented as the Phase 3c wire-shape transition.
- **3d done:** A hidden `paksmith-core::export::data_table::DataTableCsvHandler` (and `DataTableJsonHandler`) converts an `Asset::DataTable` into CSV / JSON bytes. Wired into `HandlerRegistry::all_default_handlers()`; CSV uses LF (`\n`) line endings per the explicit `csv::Terminator::Any(b'\n')` writer config (NOT the crate default `\r\n`). `paksmith inspect` on a `DataTable` asset can emit the row-keyed CSV / JSON instead of the property tree. CLI extract command stays Phase 4.
- **3e done (overview milestone — detailed split set at kickoff):** Single-LOD `PF_DXT5` `Texture2D` exports to PNG matching CUE4Parse output byte-for-byte (or with quantifiable per-channel delta tolerance — exact tolerance picked at kickoff).
- **3f done (overview milestone):** Single-codec `USoundWave` (`"OGG"` key) exports its FFormatContainer buffer as a `.ogg` file that `lewton --info` reports as a valid Vorbis-I stream.
- **3g done (overview milestone — may split into 3g1+3g2):** Single-LOD `UStaticMesh` (cube) exports to glTF 2.0 that the official `gltf-validator` accepts and Blender opens without warning. Nanite-enabled meshes export via the classic LOD fallback path; Nanite-specific export tracked as a 3g follow-up.
- **3h done (overview milestone):** Single-LOD `USkeletalMesh` with a 5-bone skeleton exports to glTF 2.0 with skin matrices + skeleton node hierarchy. `gltf-validator` accepts; Blender renders the mesh in bind pose. Animation tracks (`UAnimSequence`) are explicitly out of 3h — they're a future sub-phase (or fold into Phase 9's 3D viewport when timeline scrubbing matters).

---

## SemVer impact

Phase 3a ships **three breaking changes** to the `paksmith-core` public API. Phase 2 left `paksmith-core` at version `0.1.0` per `crates/paksmith-core/Cargo.toml:3`; **Phase 3a's first PR bumps to `0.2.0`** (pre-1.0 semver-major equivalent — minor version increment signals breaking change per Cargo semver conventions). Sub-phases 3b-3h ship under 0.2.x patch/minor bumps via additive `#[non_exhaustive]` variant additions.

**Breaking change 1 — `Asset::Generic` payload type inversion.** Phase 2: `Asset::Generic(Package)` (whole-package wrapper). Phase 3a: `Asset::Generic(PropertyBag)` (per-export wrapper). External consumers that matched `Asset::Generic(pkg_ref)` need to update to `Asset::Generic(bag_ref)`. `#[non_exhaustive]` protects against new variants but NOT against payload-type changes within existing variants.

**Breaking change 2 — `Package::payloads` field type.** Phase 2: `pub payloads: Vec<PropertyBag>`. Phase 3a: `pub payloads: Vec<Asset>`. External code iterating `package.payloads` and matching each as `PropertyBag` directly must update to match each as `Asset`.

**Breaking change 3 — `HandlerRegistry::register` signature.** This is a new API in 3a (no Phase 2 surface to break), but the post-R2 shape diverges from R1 drafts. The signature locked in 3a Design Decision #3 takes `(Discriminant<Asset>, Box<dyn FormatHandler>)`. External plugin authors reading older drafts will be surprised by the discriminant-first arg; the trait/struct docstrings flag this.

**Process discipline for breaking changes:**
- 3a Task 1's commit message MUST be prefixed `BREAKING:` per Conventional Commits.
- 3a Task 5's commit MUST bump `crates/paksmith-core/Cargo.toml` to `version = "0.2.0"`.
- `CHANGELOG.md` entry for 0.2.0 enumerates the three breaks with migration examples.

**Forward-compat hygiene (additive after 3a):**
- Every new `Asset` variant landed in 3d-3h is additive on a `#[non_exhaustive]` enum — minor-bump only.
- `PropertyValue::TypedStruct(Box<TypedStructValue>)` (3c) is additive on `#[non_exhaustive]` — minor-bump only, BUT the inspect-JSON snapshot rewrite documented in 3c Task 11 IS a wire-shape change for JSON consumers. Documented as the Phase 3c transition.
- `BulkData` widening from unit struct (3a) to fields-bearing (3b) is non-breaking per advisor verification (both `let BulkData = x;` patterns compile).
- `BulkDataTier` SHOULD carry `#[non_exhaustive]` to allow Phase 8 IoStore extensions without a major bump.

## Cap → variant → check-site → test coverage table

Every new cap constant in Phase 3 must trace through four points (per the lesson learned in R1/R2 — twice now caps were defined but the check site wasn't wired). When adding a new cap in any sub-phase TDD pass, fill in this table:

| Cap constant | Fires variant | Check site (file:fn) | Test that exercises trip |
|---|---|---|---|
| `MAX_BULK_DATA_SIZE` (8 GiB) | `BulkDataSizeExceeded` | `asset/bulk_data.rs::FByteBulkData::read_from` | 3b Task 3 unit test `read_rejects_size_exceeded` |
| `MAX_UBULK_FILE_SIZE` (16 GiB) | (companion-load failure cascade) | resolver loader closure in 3b Task 6 | 3b Task 7 integration test |
| `MAX_BULK_DATA_RECORDS_PER_EXPORT` (256) | `BulkDataRecordsExceeded` | `asset/package.rs::Package::insert_bulk_records` (defensive) + 3e/3g/3h typed-reader counters (per-reader) | 3b Task 7 integration test + per-sub-phase TDD coverage |
| `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` (16 GiB) | `BulkDataPackageBudgetExceeded` | `asset/bulk_data.rs::BulkDataResolver::resolve` (atomic fetch_add) | 3b Task 5 unit test (new: multi-record budget exhaustion) |
| `MAX_ROWS_PER_DATATABLE` (2^20) | `DataTableRowCountExceeded` | `asset/exports/data_table.rs::read_from` | 3d Task 5 integration test `row_count_over_cap_errors_typed` |
| `MAX_TEXTURE_DIMENSION` (16384) | `TextureDimensionExceeded` | 3e texture2d.rs (TDD) | 3e integration test (TDD) |
| `MAX_MIP_COUNT` (32) | `MipCountExceeded` | 3e mip.rs (TDD) | 3e integration test (TDD) |
| `MAX_MIPS_IN_TAIL` (32) | `MipsInTailExceeded` | 3e platform_data.rs (TDD) | 3e integration test (TDD) |
| `MAX_CPU_COPY_RAW_DATA_LEN` (8 GiB) | `CpuCopyRawDataLenExceeded` | 3e platform_data.rs (TDD) | 3e integration test (TDD) |
| `MAX_DECODED_TEXTURE_BYTES` (16 GiB) | `DecodedTextureBytesExceeded` | 3e pixel_format.rs per-decoder (TDD) | 3e integration test (TDD, ASTC 12×12 case) |
| `MAX_AUDIO_DECODED_BYTES` (1 GiB) | `AudioDecodedBytesExceeded` | 3f sound_wave.rs (TDD) | 3f integration test (TDD) |
| `MAX_STREAMING_CHUNKS_PER_SOUNDWAVE` (4096) | `AudioStreamingChunksExceeded` | 3f streamed.rs (TDD) | 3f integration test (TDD) |
| `MAX_PLATFORM_FORMATS_PER_SOUNDWAVE` (16) | `AudioFormatsExceeded` | 3f format_container.rs (TDD) | 3f integration test (TDD) |
| `MAX_LODS_PER_MESH` (8) | `MeshLodCountExceeded` | 3g render_data.rs (TDD) | 3g integration test (TDD) |
| `MAX_SECTIONS_PER_LOD` (64) | `MeshSectionCountExceeded` | 3g lod.rs (TDD) | 3g integration test (TDD) |
| `MAX_VERTICES_PER_LOD` (4M) | `MeshVertexCountExceeded` | 3g vertex_buffers.rs (TDD) | 3g integration test (TDD) |
| `MAX_BONES_PER_SKELETON` (65535) | `SkeletonBoneCountExceeded` | 3h skeleton.rs (TDD) | 3h integration test (TDD) |
| `MAX_INFLUENCES_PER_VERTEX` (8) | `InfluenceCountInvalid` | 3h skin_weights.rs (TDD) | 3h integration test (TDD) |
| `MAX_SKELETAL_LODS_PER_MESH` (8) | `SkeletalLodCountExceeded` | 3h skeletal_mesh.rs (TDD) | 3h integration test (TDD) |
| `MAX_BONE_MAP_ENTRIES_PER_SECTION` (= MAX_BONES_PER_SKELETON) | `BoneMapCountExceeded` | 3h section.rs (TDD) — cap-check counted-prefix BEFORE `Vec::with_capacity` | 3h integration test (TDD) |
| `MAX_CLOTH_LOD_BIAS_LEVELS` (8) | `ClothLodBiasCountExceeded` | 3h section.rs (TDD) — outer counted-prefix of ClothMappingDataLODs | 3h integration test (TDD) |
| `MAX_CLOTH_VERTS_PER_LOD` (= MAX_VERTICES_PER_LOD) | `ClothVertCountExceeded` | 3h section.rs (TDD) — inner counted-prefix of each ClothMappingDataLODs element | 3h integration test (TDD) |
| `MAX_OVERLAPPING_VERTEX_MAP_ENTRIES` (= MAX_VERTICES_PER_LOD) | `OverlappingVerticesMapExceeded` | 3h section.rs (TDD) — OverlappingVertices map-count prefix | 3h integration test (TDD) |
| `MAX_OVERLAPPING_VERTICES_PER_KEY` (= MAX_VERTICES_PER_LOD) | `OverlappingVerticesKeyExceeded` | 3h section.rs (TDD) — per-key Vec<i32> count prefix | 3h integration test (TDD) |

Each sub-phase reviewer (especially the security specialist) MUST verify every cap row's check-site cell is wired in the actual code, not just declared in the constant table. The "cap defined but never enforced" failure mode is the recurring trap; this table is the close.

## Cross-cutting concerns (Phase 3 specifically)

- **Allocation caps.** Every new cap constant lands with a `#[cfg(feature = "__test_utils")]` accessor per the existing pattern (see `max_uncompressed_entry_bytes` / `max_index_bytes` / etc.). Boundary tests in `paksmith-core-tests` read the live value.
- **Wire-stable `Display` for new `AssetParseFault` variants.** Phase 3 adds at least `UnsupportedPixelFormat`, `UnsupportedAudioCodec`, `BulkDataOffsetOob`, `MipCountExceeded`, `VertexCountExceeded`. Each gets a Display pin-table test per Phase 2g Task 1's pattern. `AssetParseFault::Display` is hand-rolled per repo convention.
- **Tracing spans.** Each new typed reader (`Texture2D::read_from`, `StaticMesh::read_from`, etc.) opens a `tracing::info_span!` so a single asset's parse + export operation can be traced end-to-end. Mirrors the existing `Package::read_from` span pattern.
- **Fixture-gen extension.** `paksmith-fixture-gen` gains synthetic `.uasset` builders for each new typed export — minimal `Texture2D`, minimal `StaticMesh`, minimal `SoundWave`, minimal `DataTable`. Each cross-validated against CUE4Parse (the dominant oracle for these families per the format docs) — exact cross-validation tooling picked at kickoff (Phase 3 candidates: shelling out to a CUE4Parse CLI, or pinning a small Rust harness against pre-cooked reference outputs committed as fixtures).
- **Review panel composition.** Every sub-phase PR gets the standard 3-reviewer panel PLUS the wire-format specialist (mandatory for any FByteBulkData / EPixelFormat / FStaticMeshRenderData touchpoint) and the security pass (mandatory for any new cap constant or offset-arithmetic site). See `feedback_specialist_reviewers_default.md` — these triggers ALL fire for Phase 3 work.

---

## What this index is NOT

- **Not the implementation.** Pick the per-sub-phase doc to execute. This file is a routing index.
- **Not authoritative for wire-format details.** Those live in `docs/formats/<family>/*.md`. If this index conflicts with a format doc, the format doc wins; update the index.
- **Not a static planning artifact.** Phase 2's `phase-2{a..g}-*.md` docs are frozen historical specs once shipped. Phase 3's docs will follow the same pattern — they're the spec at kickoff, not the post-ship reference.

---

## References

- Phase 2 closure: [`ROADMAP.md`](ROADMAP.md) §Phase 2.
- Phase 2g (most-recent sub-phase plan, structural model for 3a-3d): [`phase-2g-collection-of-struct.md`](phase-2g-collection-of-struct.md).
- Format docs by family:
  - asset: [`../formats/asset/`](../formats/asset/) — uasset, uexp, ubulk, companion-resolution.
  - texture: [`../formats/texture/`](../formats/texture/) — texture2d, pixel-formats, mips-and-streaming.
  - mesh: [`../formats/mesh/`](../formats/mesh/) — static-mesh, vertex-formats, skeletal-mesh, skeleton.
  - audio: [`../formats/audio/`](../formats/audio/) — sound-wave, audio-codecs.
  - data: [`../formats/data/`](../formats/data/) — data-table, data-asset.
- Security policy: [`../security/allocation-caps.md`](../security/allocation-caps.md).
