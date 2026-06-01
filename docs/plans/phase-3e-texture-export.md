# Paksmith Phase 3e: Texture2D → PNG export (architecture overview)

> **For agentic workers:** This started as an **overview** plan. The kickoff (crate selection + scope) is now **LOCKED** — see *Kickoff decisions* below. Milestones execute one PR at a time in the Phase-2g style (failing TDD test → impl → lint/test/doc gate → full review panel with wire-format specialist MANDATORY). Later milestones (3e-2..) refine their concrete task steps from what the earlier ones discover; this doc is not pre-expanded into speculative byte-level steps.

**Goal:** Decode `UTexture2D` assets into RGBA8 pixel buffers and write as PNG. Covers the BC1/BC3/BC4/BC5/BC6H/BC7 family (desktop), ASTC 4×4 → 12×12 (mobile), ETC2 RGB/RGBA (mid-tier Android), and uncompressed formats (R8/G8/G16/R8G8B8A8/B8G8R8A8/FloatRGB/FloatRGBA).

---

## Kickoff decisions (LOCKED — 2026-05-29)

Resolved at kickoff via a dependency-research pass + a user decision round. These supersede the *Crate-selection candidates* and *Open questions* sections below.

1. **Decoder crates — two-path dispatch + png.** Three runtime deps, all `MIT`/`MIT OR Apache-2.0`, all pure-Rust (no C/FFI), all cargo-deny-allowlist-clean:
   - **`bcdec_rs`** (MIT) — the **BC1–BC7** family (desktop: DXT1/3/5, BC4/5/6H/7). Chosen over texture2ddecoder's BC path for a more battle-tested, isolated, clean-MIT BC decoder.
   - **`texture2ddecoder`** (MIT OR Apache-2.0) — **ETC2 RGB/RGBA + EAC** and **ASTC-LDR** (4×4 … 12×12). It also covers BC, but BC is routed to `bcdec_rs`; texture2ddecoder owns only the mobile formats here.
   - **`png`** (MIT OR Apache-2.0) — PNG output. Deliberately the `png` crate directly, **not** the heavier `image` crate (which pulls JPEG/GIF/WebP/TIFF transitively) — PNG-only export needs none of that.
   - **Consequence:** the pixel-format → decoder dispatch (3e-4..3e-7) has **two decoder code paths** (BC → bcdec_rs, ETC2/ASTC → texture2ddecoder), not one.
   - **Channel order:** `texture2ddecoder` emits **BGRA `&mut [u32]`** → swap to RGBA before PNG. `bcdec_rs`'s output channel order is **unverified** — confirm it empirically at 3e-4/3e-5 before assuming a swap is (or isn't) needed; do not copy texture2ddecoder's swap blindly.
   - Each crate is added in the milestone that first needs it (bcdec_rs at 3e-5, texture2ddecoder at 3e-6, png at 3e-8), with `cargo deny check` re-run on the transitive tree at add time.
2. **Virtual textures — flatten in scope.** `FVirtualTextureBuiltData` is parsed AND its page table flattened to a single PNG **within 3e** (not detect-only). This is the riskiest slice: its own dedicated milestone(s) keyed off `docs/formats/texture/virtual-textures.md`, with its own caps (page-table size, tile count, per-tile bytes). Sequenced LAST, after the flat-mip path is proven — kept well away from the early milestones.
3. **Cadence — start 3e-1 now.** 3e-1 (variant + tagged-property segment + dispatch) ships first as a no-new-dependency PR; this kickoff record + milestone revision land in that same PR.

Still deferred to their own milestones (not kickoff decisions): per-channel BC golden-test tolerance (3e-5/3e-8), HDR pixel-format → 8-bit PNG tone-mapping curve (3e-7), the UE 5.2+ `bUsingDerivedData = true` error-variant name (3e-2).

**Depends on:** 3a (FormatHandler), 3b (FByteBulkData resolver for mip data).
**Does NOT depend on:** 3c (mip headers use `FByteBulkData` u32/i64 + raw bit-packing, not engine struct family).

**Architecture:**

```plaintext
crates/paksmith-core/src/
├── asset/exports/texture/
│   ├── mod.rs              # module decl (submodule wiring only; dispatch lives in exports/dispatch.rs)
│   ├── texture2d.rs        # UTexture2D parser (tagged props [3e-1] + FTexturePlatformData [3e-2+])
│   ├── platform_data.rs    # FTexturePlatformData wire layout — NOTE: 3e-2a kept the header parser inline in texture2d.rs (small, private); extract here if 3e-2b/3e-3 grow it
│   ├── mip.rs              # FTexture2DMipMap per-mip records (3e-3)
│   └── pixel_format.rs     # EPixelFormat enum + per-format decoders (3e-4+)
└── export/
    └── texture.rs          # PngHandler impl (3e-8)
```

The new variant is `Asset::Texture2D(Texture2DData)`, where `Texture2DData`
**grows by milestone** (the `#[non_exhaustive]` struct is constructed only
in-crate, so adding fields is non-breaking — the `DataTableData` precedent).
As of 3e-1 it carries just `{ properties: PropertyBag }` (segment-1 tagged
props); later milestones add the platform-data fields (`size_x`, `size_y`,
`pixel_format`, slice/flag bits), the decoded mip chain, and the
virtual-texture data. (This supersedes any earlier draft that pre-shaped the
variant as `{ dimensions, pixel_format, mips, virtual_texture }`.)

---

## Scope (in scope for 3e proper):

> Reconciled with the *Kickoff decisions* above (the locked decisions win where this section's original draft differed — `png` not `image`; VT-flatten in scope).

- **Parser:** UTexture2D's two-segment body (tagged-property stream + `FTexturePlatformData`).
  - **UE 5.0+ stripped-data prefix (cooked content with `IsFilterEditorOnly`):** prepend a 16-byte `PlaceholderDerivedDataSize` opaque skip before `SizeX`. Cursor advances 16 bytes; data is discarded.
  - **UE 5.2+ further prefix:** read 1 `bUsingDerivedData` flag byte; if `true`, the platform-data uses the derived-data cache (not handled by paksmith or CUE4Parse) — surface `AssetParseFault::TextureDerivedDataNotAvailable`. If `false`, advance the cursor by 15 bytes (the 16-byte placeholder minus the 1 flag byte already read), then read `SizeX`.
  - Mip-count-prefixed `FTexture2DMipMap[]` reads — for each mip, `FByteBulkData::read_from` then **lazy resolution via `Package::resolve_bulk_for_export`** (per 3b's revised lazy design). The texture handler's `export()` path materializes mip bytes; the texture reader's `read_from` path only collects records.
- **EPixelFormat enum** — Rust port of the catalog at [`../formats/texture/pixel-formats.md`](../formats/texture/pixel-formats.md). `Unknown(String)` arm for forward compatibility.
- **Per-pixel-format decoders** for the dominant set:
  - BC1 (DXT1), BC3 (DXT5), BC4, BC5, BC6H, BC7 — desktop.
  - ASTC 4x4, 6x6, 8x8, 10x10, 12x12 — mobile.
  - ETC2 RGB, ETC2 RGBA — mid-tier mobile.
  - Uncompressed: R8G8B8A8, B8G8R8A8 (with swizzle), G8, G16, FloatRGB (R11G11B10F), FloatRGBA (4× f16).
- **`PngHandler`** — `FormatHandler` impl. Output extension: `"png"`. Uses the **`png` crate** directly (per locked kickoff decision #1 — NOT the heavier `image` crate, which would pull JPEG/GIF/WebP/TIFF transitively for no PNG-only benefit).
- **Caps (pinned, not speculative):**
  - `MAX_TEXTURE_DIMENSION = 16384` (matches GPU sampler limit on most hardware per `texture2d.md:202-210`).
  - `MAX_MIP_COUNT = 32` (generous against `log2(16384) ≈ 14`).
  - `MAX_MIPS_IN_TAIL = 32` (per `texture2d.md:218-219`; matches MAX_MIP_COUNT). Applied to `OptData.NumMipsInTail` when bit 30 of `PackedData` is set.
  - `MAX_CPU_COPY_RAW_DATA_LEN = 8 * 1024 * 1024 * 1024` (8 GiB; matches `MAX_UNCOMPRESSED_ENTRY_BYTES` per `texture2d.md:220-221`). Applied to `CPUCopy.RawDataLen` (UE 5.4+ only, when bit 29 of `PackedData` is set; attacker-controllable).
  - `MAX_DECODED_TEXTURE_BYTES = 16 * 1024 * 1024 * 1024` (16 GiB) — **pinned, not "likely 64 GiB"**. Computed against the ASTC 12×12 worst-case 36× expansion per `pixel-formats.md:188-190`: an ASTC 12×12 record at the per-mip cap of 8 GiB (== `MAX_UNCOMPRESSED_ENTRY_BYTES`) implies 288 GiB of decoded RGBA8 if unbounded — clearly attack territory. Realistic textures: a 16384×16384 RGBA8 = 1 GiB; 16 GiB caps at 16× that, leaving headroom for tile/array textures while rejecting decompression bombs. The decoder MUST track accumulated decoded bytes per call and abort when it would exceed this cap (NOT just check pre-allocation).
    - **Compound-cap note:** `MAX_DECODED_TEXTURE_BYTES` is INDEPENDENT of `MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE` (3b's 16 GiB resolver budget). A single Texture2D export could in principle hold up to 16 GiB of resolved mip bytes (bulk-data budget) + 16 GiB of decoded RGBA8 (decode budget) = 32 GiB peak heap. Real textures are far below either cap (a 4K RGBA8 mip is 64 MB; a 4K decompressed BC7 stays under 256 MB), so this is theoretical. But the combined budget IS the heap envelope a Texture2D export can demand; document so operators sizing process memory know the worst case.
  - `checked_mul` is REQUIRED on the `SizeX × SizeY × bytes_per_block` computation per `texture2d.md:211-213`.
  - `PackedData` `NumSlices` mask is **`0x3FFF_FFFF`** (bits 0-29 wide). Bit 29 deliberately overlaps the `HasCpuCopy` flag — CUE4Parse's `GetNumSlices()` does NOT strip bit 29 from the slice count per `texture2d.md:94-95, 173-179`. Paksmith follows the same convention to keep cross-validation parity. The engine's writer convention reserves bit 29 as the flag and uses bits 0-28 for the actual slice count on CPU-copy-bearing textures.
- **Virtual textures** (`FVirtualTextureBuiltData`) — per locked kickoff decision #2, **in scope for 3e**: the parser detects them (a one-line wire field per `texture2d.md:101`), AND the dedicated final milestone (3e-VT) parses `FVirtualTextureBuiltData` and flattens the page table to a single PNG, with its own caps. (Supersedes this section's original "detect-only, export is a follow-up" draft.)
- **Error variants:** `UnsupportedPixelFormat { name }`, `MipCountExceeded`, `TextureDimensionExceeded`, `DecodedTextureBytesExceeded`, `PixelFormatDecodeFailed { format, reason }`, `MipsInTailExceeded { count, cap }`, `CpuCopyRawDataLenExceeded { len, cap }`, `TextureDerivedDataNotAvailable` (UE 5.2+ `bUsingDerivedData = true` — derived-data cache is editor-only and not on disk in cooked content).
- **Tests:** Round-trip fixtures (synthetic + cooked) for each pixel format. Cross-validate against CUE4Parse via the `paksmith-fixture-gen` harness (same shape as 3d).

## Out of scope (named target phases):

- **Texture cube / 2D array / volume textures** (`UTextureCube`, `UTexture2DArray`, `UVolumeTexture`) — share `FTexturePlatformData` wire shape but differ in slice/face count. → **Phase 3e follow-up sub-phases** (3e-cube, 3e-array, 3e-volume) — same pattern as 3e proper; per-doc per-sibling-class. Not separate top-level Phase-3 sub-phases.
- **DDS output format** alongside PNG. → Phase 3 follow-up; `DdsHandler` is a 100-line addition to `export/texture.rs`.
- **Oodle-compressed mip bulk data** (`BULKDATA_SerializeCompressedZLIB` is handled by 3b; Oodle inherits the same dispatch but requires Phase 8's SDK loader). → **Phase 8.**
- **HDR formats requiring EXR output** (FloatRGBA → EXR rather than 8-bit PNG). → Phase 3 follow-up; `image` crate handles EXR.
- **Per-channel isolation** (export only the R channel, only A, etc.). → **Phase 7** (GUI viewer feature).

---

## Crate-selection candidates (decide at kickoff)

| Decoder family | Candidate | Notes |
|----------------|-----------|-------|
| BC1-BC7 | `texture2ddecoder` | Pure Rust; covers BC1-7 + ETC2 + ASTC; license MIT. **Recommended** for breadth. |
| BC1-BC7 alt. | `bcdec` (or `intel_tex_2` for write) | Pure Rust read-only. Smaller scope; pick if `texture2ddecoder` has license / maintenance concerns. |
| ASTC | `astc_decode` | Pure Rust; LDR only (HDR ASTC variants deferred). |
| ETC2 | `etc-decompress` or `texture2ddecoder`'s ETC2 path | Either works. |
| PNG writer | `image` (re-exported `png`) | Already de-facto Rust ecosystem standard. |
| EXR writer (optional) | `image` (with `exr` feature) | Phase 3 follow-up only. |

The choice influences task decomposition (one decoder crate covers more formats → fewer per-format tasks). Kickoff brainstorming session resolves.

---

## Milestone breakdown (post-kickoff)

1. **3e-1: Variant + tagged-property segment + dispatch wiring. ✅ DONE.** `Asset::Texture2D(Texture2DData { properties })` variant; `asset/exports/texture/texture2d.rs::read_from` decodes segment 1 (tagged properties) and stops at `"None"`; `Texture2D` class registered in `class_dispatch`. No new deps. (Honest framing: the generic path already decoded segment 1 to a `Tree` — 3e-1 promotes that to the typed variant the `PngHandler` will dispatch on; it does not "newly make textures parse.")
> **✅ RESOLVED — segment-2 entry fix (`fix/texture-owner-level-flags`).** The 3e-3a R2 wire-format panel surfaced, and a WebFetch of CUE4Parse `UTexture.Deserialize` / `UTexture2D.Deserialize` @ `cf74fc32` confirmed, that between the property `"None"` terminator and the `FTexturePlatformData` blob there is a binary entry the original `read_from` skipped. `read_segment2_entry` now decodes it (verified widths in `docs/formats/texture/texture2d.md` §"Segment-2 entry"):
> 1. **`UTexture`-base `FStripDataFlags`** (2 bytes) — editor data must be stripped (`GlobalStripFlags & 1`); else [`TextureEditorDataNotStripped`] (cooked-only domain; the unstripped branch reads an editor `FByteBulkData`/`FEditorBulkData` paksmith doesn't parse).
> 2. **`UTexture2D` `FStripDataFlags`** (2 bytes, consumed).
> 3. **Owner `bCooked`** (4-byte `u32` `ReadBoolean` ∈ {0,1}; gated `ADD_COOKED_TO_TEXTURE2D` = 227, always present). Asserted `true` ([`TextureNotCooked`] otherwise) rather than restructuring `Texture2DData` to make platform data optional — `bCooked == false` is out-of-domain.
> 4. **`bSerializeMipData`** (4-byte `u32` ∈ {0,1}) — gates the per-mip `FByteBulkData`. CUE4Parse gates it on `Ar.Game >= GAME_UE5_3` (engine version); paksmith proxies with `file_version_ue5 >= VER_UE5_SCRIPT_SERIALIZATION_OFFSET (1010)`.
>
> **Documented residual limitation (UE 5.2 vs 5.3).** CUE4Parse's `EGame` table maps **both** `GAME_UE5_2` and `GAME_UE5_3` to object version `1009` (`< GAME_UE5_4 => (522, 1009)`), so a 5.3 texture serialized at `1009` is indistinguishable from 5.2 by `file_version_ue5`. **Per user decision, paksmith optimizes for 5.2** (the established target): at `1009` it reads no `bSerializeMipData` — correct for UE4 / 5.0 / 5.1 / 5.2, but a real 5.3-at-`1009` texture's mip records mis-align. Resolved when game profiles (Phase 5) supply the engine version. `>= 1010` (5.4-preview object versions paksmith still accepts) reads the flag correctly.

2. **3e-2: `FTexturePlatformData` header parser (no mip bytes yet).** **The trickiest wire bytes — split into two reviewable PRs:**
   - **3e-2a ✅ DONE:** the version-gated stripped-data prefix + `SizeX` + `SizeY` + `PackedData` + `PixelFormat`. The prefix is gated on `file_version_ue5` as an object-version proxy for CUE4Parse's `Ar.Game` (verified against CUE4Parse's verbatim `EGame`→`FPackageFileVersion` arms @ `cf74fc32`: `< GAME_UE5_2 => (522, 1008)`, `< GAME_UE5_4 => (522, 1009)`, i.e. `GAME_UE5_0`/`5.1 → 1008` and `GAME_UE5_2`/`5.3 → 1009`, so `>= VER_UE5_DATA_RESOURCES (1009)` ⟺ `Ar.Game >= GAME_UE5_2` for the 1-byte-flag-+-15-skip path, and `file_version_ue5.is_some()` ⟺ `>= GAME_UE5_0` for the 16-byte skip; `IsFilterEditorOnly` is implied since paksmith rejects uncooked UE5). **(The earlier "`GAME_UE5_0 → 1004`" here was a WebFetch paraphrase error corrected during the segment-2-entry fix; the gate logic — boundary at 1009, floor at `is_some()` — was unaffected.)** `PlaceholderDerivedDataSize = 16` (verified). Adds `MAX_TEXTURE_DIMENSION = 16384`, `TextureDimensionExceeded`, `TextureDerivedDataNotAvailable`. `PixelFormat` is the alignment checksum across the version matrix (UE4 / UE5.0 / UE5.1 / UE5.2-flag-false / UE5.2-flag-true).
   - **3e-2b ✅ DONE:** `OptData` (bit 30: `ExtData` discarded + `NumMipsInTail`), `CPUCopy` (bit 29, `FSharedImage` — read + cap `RawDataLen` + payload-bounded skip; not stored), `FirstMipToSerialize`, mip-count prefix. Added `MAX_MIP_COUNT = 32`, `MAX_MIPS_IN_TAIL = 32`, `MAX_CPU_COPY_RAW_DATA_LEN = 8 GiB` + `TextureMipCountExceeded` / `TextureMipsInTailExceeded` / `TextureCpuCopyDataLenExceeded`. (`OptData`/`CPUCopy` are gated purely on the `PackedData` bits — no version check; the "5.4+" for CPUCopy is just when writers set bit 29.) `mip_count` is the alignment checksum (OptData/CPUCopy present-or-absent). The per-mip `FTexture2DMipMap` records are in 3e-3 (coupled with their resolution).
3. **3e-3: Per-mip `FTexture2DMipMap` records + mip resolution via 3b's BulkDataResolver.** Split into two PRs:
   - **3e-3a ✅ DONE:** `read_from` reads the `mip_count` per-mip `FTexture2DMipMap` records (`bCooked` UE4-only via `file_version_ue5.is_none()` + `FByteBulkData::read_from` + `SizeX`/`SizeY`/`SizeZ`), storing per-mip dimensions in `Texture2DData::mips` and returning the `FByteBulkData` records as `read_typed`'s tuple second element (collected-but-discarded by the dispatch caller until 3e-3b wires them). Kept inline in `texture2d.rs` (mirrors 3e-2a's inline-header decision — no `mip.rs` extraction). Adds `TextureMipCooked` / `TextureMipDimension` wire fields (per-mip dims reuse `TextureDimensionExceeded`). The multi-mip fixture's per-record VALUE assertions (distinct dims + `SizeOnDisk` per mip) are the alignment checksum — `mip_count` no longer is, since nothing trailing follows the loop.
   - **3e-3b: `Package` plumbing + end-to-end resolution.** `Package::read_payloads` surfaces the per-export records into `insert_bulk_records`; tier dispatch (inline / uexp-resident / streaming) materialized lazily via `Package::resolve_bulk_for_export` in the handler path.
4. **3e-4: EPixelFormat enum + uncompressed decoders.** R8G8B8A8, B8G8R8A8 (swizzle), G8, G16. Establishes the decoder dispatch shape + the `MAX_DECODED_TEXTURE_BYTES` accumulating cap.
5. **3e-5: BC family decoders — `bcdec_rs` (dep #1).** BC1, BC3, BC4, BC5, BC7. **Verify bcdec_rs's output channel order empirically here** (don't assume the texture2ddecoder BGRA swap applies). BC6H may slip to 3e-7 with the other HDR formats.
6. **3e-6: ASTC + ETC2 decoders — `texture2ddecoder` (dep #2).** Block-size-dispatched ASTC 4×4…12×12 + ETC2 RGB/RGBA. Apply the BGRA→RGBA swap on this crate's `&mut [u32]` output.
7. **3e-7: HDR formats — FloatRGB (R11G11B10F), FloatRGBA (4× f16), BC6H.** Tone-mapped to 8-bit PNG (curve chosen here); lossless EXR is a follow-up.
8. **3e-8: `PngHandler` + `png` dep (dep #3) + registration + integration tests.** Registers the handler in `all_default_handlers`; adds `Texture2DData::empty()` for the discriminant sentinel here (NOT earlier — it's dead code until this milestone). Single-LOD `PF_DXT5` exports cross-validated against CUE4Parse (per-channel tolerance set here). Fixture-count gate bumped if any committed `.pak` fixtures are added.
9. **3e-VT: Virtual-texture flatten (LAST).** `FVirtualTextureBuiltData` parse + page-table flatten → PNG, per `docs/formats/texture/virtual-textures.md`. Own caps (page-table size, tile count, per-tile bytes). The riskiest slice — sequenced after the flat-mip path is proven; may split into parse + flatten sub-milestones.

Each milestone gets the full Phase-2g treatment: failing TDD test with hand-built block-byte fixture, implementation, lint/test/doc gate, commit, full review panel (wire-format specialist MANDATORY for every task).

---

## Fixture-count gate

When 3e converts to a TDD plan, every committed `tests/fixtures/*.pak` test fixture forces a bump in `.github/workflows/ci.yml`'s `expected=N` count per `feedback_fixture_count_gate.md` in MEMORY. 3e is expected to add ~6-8 fixtures (one per dominant pixel format: BC1, BC3, BC5, BC7, ASTC 4×4, ETC2 RGB, R8G8B8A8, FloatRGBA). Bump the gate constant in the same PR that lands the fixtures.

## Contract callouts for TDD conversion

- **`TypedReaderFn` returns `Result<(Asset, Vec<FByteBulkData>)>`** (per 3a R3 fix). The texture reader collects per-mip `FByteBulkData` records during platform-data parsing and returns them in the second tuple element; the dispatch caller in `Package::read_from` calls `insert_bulk_records` at the boundary. The defensive `MAX_BULK_DATA_RECORDS_PER_EXPORT` cap fires there, not inside the reader. Typed texture-reader signature: `pub(crate) fn read_typed(payload: &[u8], ctx: &AssetContext, asset_path: &str) -> crate::Result<(Asset, Vec<FByteBulkData>)>`. Mip-record collection inside `Texture2D::read_from` returns the records via tuple; total records per export equals mip count, bounded by `MAX_MIP_COUNT = 32`, so the boundary cap (256) never trips in normal use.

## Open questions for kickoff

1. **Texture decoder crate finalists.** `texture2ddecoder` vs `bcdec` + `astc_decode` + `etc-decompress`. License + maintenance + format coverage trade-off.
2. **Per-channel tolerance for BC golden tests.** CUE4Parse may use a different BC implementation; byte-equal may not be achievable for BC6H/BC7. State the tolerance explicitly in 3e-8's test fixtures.
3. **Virtual texture scope.** MVP detects + carries through as opaque `VirtualTextureData::Pending`, or attempts to flatten the page table? Recommendation: detect only; flattening is a follow-up.
4. **HDR pixel format → 8-bit PNG conversion.** Tone-mapping curve choice (Reinhard vs ACES vs linear-clamp). Defer until 3e-7 fixture testing surfaces actual needs.
5. **Stripped editor-only data in UE 5.2+ assets.** The `bUsingDerivedData` flag's `true` branch routes to derived-data cache (not on disk); 3e must reject these with a typed error rather than guessing. Confirm error variant naming at kickoff.

---

## Review panel (when 3e enters TDD)

- Wire-format pass — MANDATORY (heavy: FTexturePlatformData + per-mip + per-format).
- Security pass — MANDATORY (cap-driven decoder allocation, BC block bounds, ASTC variable-size block dispatch).
- Performance — RECOMMENDED (texture decoding is hot path; profile per-format decoder allocator behavior).
- Deep-impact tracer — MANDATORY (adds `Asset::Texture2D` variant).

5-6 reviewers per task PR.

---

## References

- Wire-format references:
  - [`../formats/texture/texture2d.md`](../formats/texture/texture2d.md) — UTexture2D + FTexturePlatformData.
  - [`../formats/texture/mips-and-streaming.md`](../formats/texture/mips-and-streaming.md) — per-mip records + FByteBulkData.
  - [`../formats/texture/pixel-formats.md`](../formats/texture/pixel-formats.md) — EPixelFormat catalog.
- Master index: [`phase-3-export-pipeline.md`](phase-3-export-pipeline.md).
- Phase 3a (trait): [`phase-3a-format-handler-trait.md`](phase-3a-format-handler-trait.md).
- Phase 3b (bulk data): [`phase-3b-bulk-data-resolver.md`](phase-3b-bulk-data-resolver.md).
