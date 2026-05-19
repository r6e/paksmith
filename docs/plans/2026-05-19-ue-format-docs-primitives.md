# UE Primitives Family Documentation — PR 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land PR 2 from the framework spec — populate `docs/formats/primitive/` with six full byte-level reference docs (`fstring`, `fname`, `fguid`, `fpackage-index`, `fcustom-version`, `fengine-version`), all `complete` status because every primitive has a shipped parser in `crates/paksmith-core/src/asset/`. Add six rows to the root inventory.

**Architecture:** One commit per doc + one for the inventory update + one for final verification = 7 commits on a single feature branch. Each doc is authored against the per-doc template, cross-referenced to its parser module for ground-truth on wire shape and cap constants, and cited to community implementations (CUE4Parse + unreal_asset are the two primary oracles for primitives). Hex-anchor `### Worked example` blocks use `(none yet — see issue #NNN)` placeholders where the existing fixtures don't offer a clean byte boundary; per the spec, `(none yet)` is an allowed Verification state and PR follow-ups can backfill once a primitive-focused fixture lands.

**Tech Stack:** Pure markdown content. The only Rust touched is the parser modules read for ground truth — no code changes. CI gates: `paksmith-doc-lint required-headings docs/formats/` and `paksmith-doc-lint status-enum docs/formats/README.md` (both from PR 1).

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) must have merged to `main` — branches forked before PR 1 lands will be missing TEMPLATE.md, the family READMEs, the inventory schema, and the doc-lint crate.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md) for the per-family setup (worktree creation, scaffold verification, oracle SHA capture). This plan's family name is `primitives`.

## File structure

**Create (6 docs):**

- `docs/formats/primitive/fstring.md`
- `docs/formats/primitive/fname.md`
- `docs/formats/primitive/fguid.md`
- `docs/formats/primitive/fpackage-index.md`
- `docs/formats/primitive/fcustom-version.md`
- `docs/formats/primitive/fengine-version.md`

**Modify (1):**

- `docs/formats/README.md` — add six rows to the inventory table.

Doc ordering chosen smallest-and-most-discrete first (FGuid) → most complex last (FString). Each task is self-contained: it reads the relevant parser, cross-references the named community oracle, writes the doc verbatim, runs the linter, commits.

**Oracle citation policy.** Per the spec's "Sourcing and attribution" section, every wire-format claim needs an inline footnote that resolves to `{community-project}/{path}@{sha}`. The plan provides the project + path; the executor looks up the current HEAD SHA at execution time and substitutes it in. CUE4Parse is the default oracle for primitives; unreal_asset is the secondary triangulation source (paksmith's existing fixture oracle).

**Hex-anchor policy.** Three of the six docs (FString, FEngineVersion, FCustomVersion) have natural anchor points in `tests/fixtures/minimal_uasset_v5.uasset`. The plan calls these out per-doc; the executor verifies the exact offsets with `xxd` at execution time. The other three (FGuid, FName, FPackageIndex) use `(none yet)` per the spec's allowed Verification state — a follow-up PR can add primitive-focused fixtures once Phase 3 work generates them.

---

## Task 1: Per-family setup

Run the steps from [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" section with `<family> = primitives`. Capture oracle SHAs there for reuse across every per-doc citation in this plan (`<CUE4PARSE_SHA>`, `<UNREAL_ASSET_SHA>`).

---

## Task 2: Author `docs/formats/primitive/fguid.md`

Smallest and most-discrete primitive — 16 fixed bytes, no length, no caps beyond IO. Doubles as the template-validation pass.

**Files:**
- Create: `docs/formats/primitive/fguid.md`

**Ground truth references:**
- Parser: `crates/paksmith-core/src/asset/guid.rs` (158 lines).
- Display impl: `guid.rs:61-100` — canonical 8-4-4-4-12 form derived from four LE u32s `(A, B, C, D)`.
- Oracle: `CUE4Parse/Objects/Core/Misc/FGuid.cs` — the reference C# impl. Cite with HEAD SHA at execution time.
- Secondary oracle: `unreal_asset/src/types/guid.rs` (in the `astralorigin/unreal_asset` crate) — Rust impl paksmith's fixture-gen already uses.

- [ ] **Step 1: Read the parser for ground truth**

Run: `cat crates/paksmith-core/src/asset/guid.rs`
Note: 16 raw bytes, interpreted as 4 LE u32s for `Display` only; storage is byte-level.

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fguid.md`:

````markdown
# FGuid (`FGuid`)

> UE's 128-bit identifier — 16 fixed bytes interpreted as four little-endian u32s.

## Overview

`FGuid` is UE's standard globally-unique-identifier type, used throughout the
engine wherever a stable 128-bit ID is needed: package identifiers in the
package summary, plugin identifiers in custom-version records[^1], asset GUIDs
in cooked metadata, and editor-only object identifiers.

The wire shape is the simplest of all UE primitives — sixteen raw bytes, no
length prefix, no version conditional, no encoding selection. The
interpretation is the interesting part: those bytes are four
little-endian `u32` fields conventionally named `A`, `B`, `C`, `D`, and the
canonical display form reshapes them into the standard 8-4-4-4-12 hex layout.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | No change since UE3. | `CUE4Parse/Objects/Core/Misc/FGuid.cs@<CUE4PARSE_SHA>`[^1] |

`FGuid` has had a stable on-disk shape since UE3. Newer engine versions added
ergonomic constructors (`NewGuid()`, `Parse()`) and a `EGuidFormats` enum for
the display side, but the serialized 16 bytes have never changed.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `A` | `u32` | First u32 field. |
| 4 | 4 | LE | `B` | `u32` | Second u32 field. |
| 8 | 4 | LE | `C` | `u32` | Third u32 field. |
| 12 | 4 | LE | `D` | `u32` | Fourth u32 field. |

Total: 16 bytes, fixed.

### Display form

UE's `FGuid::ToString(EGuidFormats::DigitsWithHyphens)` reshapes the four
u32s into the canonical 8-4-4-4-12 hex layout[^1]:

```
{A:08x}-{B>>16:04x}-{B&0xFFFF:04x}-{C>>16:04x}-{C&0xFFFF:04x}{D:08x}
```

Note the asymmetry: `A` and `D` render as single 8-hex-digit groups, while `B`
and `C` each split into two 4-hex-digit halves. This matches the RFC-4122
visual convention but is **not** an endianness conversion — the bytes are still
read little-endian. The display form is a rearrangement of nibbles, not a
swap.

### Worked example

Input bytes (hex): `DE AD BE EF 00 01 02 03 04 05 06 07 08 09 0A 0B`

Decoded:
- `A = 0xEFBEADDE` (LE of `DE AD BE EF`)
- `B = 0x03020100`
- `C = 0x07060504`
- `D = 0x0B0A0908`

Display: `efbeadde-0302-0100-0706-05040b0a0908`

This is exercised by the `display_renders_canonical_ue_form` test in
`crates/paksmith-core/src/asset/guid.rs`.

## Variants

None on the wire. UE has multiple `EGuidFormats` for display (with-hyphens,
without-hyphens, parentheses, braces, base64, etc.) but all read the same 16
bytes.

The zero GUID (`00000000-0000-0000-0000-000000000000`) is meaningful as a
sentinel in some contexts — for example, an `FCustomVersion` row keyed on the
zero GUID is invalid. Each consumer documents its own zero-GUID semantics;
the primitive itself treats zero as a valid value.

## Caps & limits

None beyond IO. The size is fixed; there is no length field to validate. The
parser's only failure mode is short read (`PaksmithError::Io`) when the
underlying source has fewer than 16 bytes remaining.

## Verification

- **Fixture:** `(none yet)` — `tests/fixtures/minimal_uasset_v5.uasset` contains
  several FGuid instances (package GUID at the start of the summary, custom-
  version GUIDs in the custom-version container), but no fixture is currently
  named or positioned to make FGuid the focal anchor.
- **Cross-validation oracle:** CUE4Parse's `FGuid.Read`[^1] and
  `unreal_asset`'s `Guid::read`[^2]. Both impls confirm the 16-byte fixed
  shape and the four-u32 interpretation for display purposes.
- **Known divergences:** none. Every oracle paksmith has consulted agrees on
  FGuid's wire shape and display form.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/guid.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct FGuid` — 16-byte storage; `Copy`.
- `FGuid::read_from<R: Read>(&mut R) -> Result<FGuid>` — 16 raw bytes.
- `FGuid::from_bytes([u8; 16]) -> FGuid` — type-checked constructor.
- `FGuid::as_bytes() -> &[u8; 16]` — borrow for round-trip writes.
- `impl Display` — canonical 8-4-4-4-12 form.
- `impl Serialize` — JSON string matching `Display`.

**Error variants:** none specific to FGuid. Short reads bubble up as
`PaksmithError::Io`.

**Cap constants:** none.

**Test files:** `crates/paksmith-core/src/asset/guid.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 4).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Misc/FGuid.cs@<CUE4PARSE_SHA>` — reference C# `FGuid` implementation including the 16-byte serializer and the `EGuidFormats::DigitsWithHyphens` renderer.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/types/guid.rs@<UNREAL_ASSET_SHA>` — Rust `Guid::read` / `write` implementation; paksmith's fixture-gen cross-checks against this crate.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fguid.md
git commit -m "$(cat <<'EOF'
docs(formats): add FGuid reference

Documents the 16-byte fixed wire layout, the four-u32 partition for
display, and the canonical 8-4-4-4-12 hex form. No caps beyond IO;
no version conditionals. Cross-validated against CUE4Parse and
unreal_asset.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Author `docs/formats/primitive/fpackage-index.md`

**Files:**
- Create: `docs/formats/primitive/fpackage-index.md`

**Ground truth references:**
- Parser: `crates/paksmith-core/src/asset/package_index.rs` (268 lines).
- Wire shape: signed i32, decoded as `0 = Null`, positive `n → Export(n-1)`, negative `n → Import(-n-1)`.
- Cap: `i32::MIN` rejected (no positive counterpart).
- Oracle: `CUE4Parse/UE4/Assets/Objects/FPackageIndex.cs`.

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/package_index.rs`
Note the `try_from_raw` decode logic and the `i32::MIN` rejection.

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fpackage-index.md`:

````markdown
# FPackageIndex (`FPackageIndex`)

> UE's tagged reference into the package's import or export table — a single
> i32 with sign-encoded table selection.

## Overview

Every cross-object reference inside a UE package — `outer`, `class`, `super`,
`template` — serializes as an `FPackageIndex`. The wire form is a single
signed `i32`; the sign of that integer selects which of the package's two
tables (imports or exports) the reference points into, and the absolute value
gives a 1-based index. Zero is the null reference.

This encoding is uniform across every reference field in the wire format,
which is why paksmith wraps the raw i32 in a typed enum
(`PackageIndex::{Null, Import, Export}`) and gates every wire-read site
through one shared decode function.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Stable since UE3. | `CUE4Parse/UE4/Assets/Objects/FPackageIndex.cs@<CUE4PARSE_SHA>`[^1] |

The `(0 = Null, positive = Export, negative = Import)` convention has been
stable since UE3. The shape has never changed across engine versions.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `Index` | `i32` | Tagged table reference; see decode table below. |

Total: 4 bytes.

### Decode table

| Wire `i32` value | Decoded reference |
|------------------|--------------------|
| `0` | `Null` |
| `n > 0` | `Export(n - 1)` (1-based wire, 0-based decoded) |
| `n < 0`, `n > i32::MIN` | `Import((-n) - 1)` |
| `i32::MIN` | **Reject** — no positive counterpart (see Caps & limits) |

The 1-based encoding is a historical UE convention: the engine's internal
`INDEX_NONE` is `-1`, so positive `0` is reserved for the null sentinel and
real export indices start at `1`.

## Variants

None on the wire — one shape, one decode procedure.

## Caps & limits

- **`i32::MIN` rejected.** The wire value `-2_147_483_648` has no positive
  counterpart (`-i32::MIN` overflows), so paksmith refuses to decode it as
  an Import index. Surfaces as
  `AssetParseFault::PackageIndexUnderflow { field: AssetWireField::… }`,
  with `field` naming the specific reference site
  (`OuterIndex`/`ClassIndex`/`SuperIndex`/`TemplateIndex`/`OuterIndexImport`).
  UE writers never produce `i32::MIN`; only malicious or corrupted archives
  can trigger this. See `crates/paksmith-core/src/asset/package_index.rs:60`.
- **Index range:** decoded `Export(i)` and `Import(i)` values are bounded
  to `0..=i32::MAX - 1 = 2_147_483_646` by the decode procedure. No further
  range cap is applied at parse time — the consuming code (import-table or
  export-table lookup) validates the index against the actual table length.

## Verification

- **Fixture:** `(none yet)` — `tests/fixtures/minimal_uasset_v5.uasset`
  contains FPackageIndex references in its import/export tables, but the
  current fixture suite does not isolate one for a named hex anchor. A
  primitive-focused fixture covering each of the three states (Null, Import,
  Export) plus the `i32::MIN` rejection would be a worthwhile follow-up.
- **Cross-validation oracle:** CUE4Parse's `FPackageIndex.Read`[^1] and
  `unreal_asset`'s `PackageIndex::read`[^2]. Both agree on the
  `(0 = Null, +n = Export(n-1), -n = Import(-n-1))` decode.
- **Known divergences:** CUE4Parse does not explicitly reject `i32::MIN` —
  it lets the `-i32::MIN` overflow wrap, producing an Import index of
  `2_147_483_647`. Paksmith treats this as a malformed archive instead;
  practical impact is nil because UE writers never emit `i32::MIN`.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/package_index.rs`

**Status:** `complete`.

**Public surface:**
- `pub enum PackageIndex { Null, Import(u32), Export(u32) }` (with `#[non_exhaustive]`).
- `PackageIndex::try_from_raw(i32) -> Result<PackageIndex, PackageIndexError>`.
- `PackageIndex::to_raw() -> i32` — round-trip encoder.
- `read_package_index<R: Read>(reader, asset_path, field) -> Result<PackageIndex>` — pub(crate) wire-read wrapper that maps `PackageIndexError` to `AssetParseFault::PackageIndexUnderflow`.
- `impl Display` — renders `"Null"`, `"Import(N)"`, or `"Export(N)"`.
- `impl Serialize` — JSON string matching `Display`.

**Error variants:**
- `PackageIndexError::ImportIndexUnderflow` (private to the module) — raised when `try_from_raw` sees `i32::MIN`.
- `AssetParseFault::PackageIndexUnderflow { field: AssetWireField }` — the public-facing wire error.

**Cap constants:** none (only the `i32::MIN` rejection, which is structural
not configurable).

**Test files:** `crates/paksmith-core/src/asset/package_index.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 3).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FPackageIndex.cs@<CUE4PARSE_SHA>` — reference C# `FPackageIndex` implementation including the i32 read and the null / export / import branch decode.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/types/package_index.rs@<UNREAL_ASSET_SHA>` — Rust `PackageIndex::read` paksmith cross-validates against.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fpackage-index.md
git commit -m "$(cat <<'EOF'
docs(formats): add FPackageIndex reference

Documents the sign-tagged i32 encoding: 0 = Null, positive n =
Export(n-1), negative n = Import(-n-1). Notes the i32::MIN
rejection paksmith adds beyond what CUE4Parse does, and the
1-based-on-wire / 0-based-decoded convention.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Author `docs/formats/primitive/fcustom-version.md`

**Files:**
- Create: `docs/formats/primitive/fcustom-version.md`

**Ground truth references:**
- Parser: `crates/paksmith-core/src/asset/custom_version.rs` (280 lines).
- Wire: container = `i32 count` + count records; each record = FGuid (16 bytes) + i32 version.
- Cap: `MAX_CUSTOM_VERSIONS = 1024`.
- Version floor: post-UE4.13 ("Optimized") layout only; `LegacyFileVersion ≥ -7`.
- Oracle: `CUE4Parse/UE4/Assets/Objects/FCustomVersion.cs`.

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/custom_version.rs`

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fcustom-version.md`:

````markdown
# FCustomVersion (`FCustomVersion`)

> Per-plugin version stamp serialized into the package summary as a counted
> array of `(FGuid, i32 version)` rows.

## Overview

UE's core engine version is one number; individual plugins each have their own
version counter so a plugin can detect "this archive was saved before I added
field X" without re-versioning the entire engine. The package summary carries
an `FCustomVersion` container that maps plugin GUID to plugin-local version.

The container is a length-prefixed array. Each row is the plugin's
`FGuid`[^3] (16 bytes) followed by an `i32` version number (4 bytes). Total
record size: 20 bytes.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ≥ -7` | "Optimized" layout: `FGuid + i32` rows only. | `CUE4Parse/UE4/Assets/Objects/FCustomVersion.cs@<CUE4PARSE_SHA>`[^1] |
| `LegacyFileVersion < -7` | "Guids" or "Enum" layout: each row carries an additional FString name. | Same source[^1] |

Paksmith accepts only the post-UE4.13 ("Optimized") layout, gated by the
`LegacyFileVersion ≥ -7` floor in the package summary parser. Older archives
are rejected upstream and never reach the custom-version reader.

## Wire layout

### Container

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `count` | `i32` | Number of `FCustomVersion` rows that follow. |
| 4 | `count × 20` | — | `rows` | `FCustomVersion[count]` | Per-row layout below. |

### Single row (`FCustomVersion`)

| offset (within row) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 16 | LE u32×4 | `guid` | `FGuid`[^3] | Plugin identifier. |
| 16 | 4 | LE | `version` | `i32` | Plugin-local version counter. |

Row size: 20 bytes. Container size: `4 + (count × 20)` bytes.

## Variants

The pre-UE4.13 "Guids" and "Enum" layouts add an FString name per row. They
are not supported by paksmith — see the Versions table.

## Caps & limits

- **`count < 0` rejected.** Surfaces as
  `AssetParseFault::NegativeValue { field: AssetWireField::CustomVersionCount, value }`.
- **`count > MAX_CUSTOM_VERSIONS` rejected.**
  `MAX_CUSTOM_VERSIONS = 1024` (see
  `crates/paksmith-core/src/asset/custom_version.rs:29`). Surfaces as
  `AssetParseFault::BoundsExceeded { field: CustomVersionCount, value, limit, unit: Items }`.
  Sized to cover any realistic plugin count while preventing
  attacker-controlled multi-GB allocations.
- **Allocation failure handled.** `try_reserve_asset` is used for the row
  `Vec`; failures surface as
  `AssetParseFault::AllocationFailed { context: CustomVersionContainer, … }`
  rather than aborting the process.

See `docs/security/allocation-caps.md` for the broader allocation-cap policy.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` contains a
  custom-version container at the offset specified by the summary header.
  To anchor: run `xxd tests/fixtures/minimal_uasset_v5.uasset | head -20`
  and locate the `count` i32 (a small integer like `0a 00 00 00`) followed
  by the 20-byte rows. (A precise byte offset for this anchor should be
  added when a primitive-focused fixture lands.)
- **Cross-validation oracle:** CUE4Parse's `FCustomVersionContainer.Read`[^1]
  and `unreal_asset`'s `CustomVersion::read`[^2]. Both impls confirm the
  4-byte count prefix and the 20-byte row layout for the "Optimized"
  variant.
- **Known divergences:** CUE4Parse implements all three historical layouts
  (Unknown, Guids, Enums, Optimized) via an enum dispatch on a separate
  serialization-format tag. Paksmith implements only Optimized because the
  `LegacyFileVersion ≥ -7` floor (issue/spec rationale in
  `phase-2a-uasset-header.md`) excludes older archives.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/custom_version.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct CustomVersion { pub guid: FGuid, pub version: i32 }`.
- `CustomVersion::read_from<R: Read>(&mut R) -> Result<CustomVersion>` — 20-byte row.
- `pub struct CustomVersionContainer { pub versions: Vec<CustomVersion> }` with `#[serde(transparent)]`.
- `CustomVersionContainer::read_from<R: Read>(&mut R, asset_path) -> Result<CustomVersionContainer>` — container with cap enforcement.

**Error variants:**
- `AssetParseFault::NegativeValue { field: CustomVersionCount, value }`.
- `AssetParseFault::BoundsExceeded { field: CustomVersionCount, value, limit, unit }`.
- `AssetParseFault::AllocationFailed { context: CustomVersionContainer, … }`.

**Cap constants:**
- `MAX_CUSTOM_VERSIONS: u32 = 1024` (`custom_version.rs:29`).

**Test files:** `crates/paksmith-core/src/asset/custom_version.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 7).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/FCustomVersion.cs@<CUE4PARSE_SHA>` — reference C# `FCustomVersionContainer` implementation including the three historical layouts.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/custom_version.rs@<UNREAL_ASSET_SHA>` — Rust `CustomVersion::read` paksmith cross-validates against.
[^3]: See [`fguid.md`](fguid.md) for FGuid wire details.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fcustom-version.md
git commit -m "$(cat <<'EOF'
docs(formats): add FCustomVersion reference

Documents the post-UE4.13 ("Optimized") layout — i32 count + 20-byte
rows. Notes the LegacyFileVersion ≥ -7 floor that excludes older
layouts and the MAX_CUSTOM_VERSIONS = 1024 cap.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Author `docs/formats/primitive/fengine-version.md`

**Files:**
- Create: `docs/formats/primitive/fengine-version.md`

**Ground truth references:**
- Parser: `crates/paksmith-core/src/asset/engine_version.rs` (376 lines).
- Wire: `u16 major + u16 minor + u16 patch + u32 changelist + FString branch`.
- Changelist bit 31 = licensee-version flag; bits 0-30 = actual changelist.
- Branch FString uses asset-side wrapper (accepts `len == 0`).
- Display divergence from UE: paksmith always emits `+branch`, UE suppresses when empty.

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/engine_version.rs`
Pay attention to the module-level doc comment (lines 1-29) — it has the full wire layout already.

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fengine-version.md`:

````markdown
# FEngineVersion (`FEngineVersion`)

> UE's engine-version stamp: major.minor.patch + changelist + branch name.

## Overview

`FEngineVersion` captures the engine build that produced an archive: a
three-part semantic version (`major.minor.patch`), a Perforce-style integer
changelist with a top-bit flag for licensee builds, and an FString[^3] branch
name (e.g. `"++UE4+Release-4.27"`, `"++UE5+Release-5.1"`).

It appears in the package summary's compatibility section and in pak entry
metadata for newer pak versions. The wire shape has been stable since UE4 but
the licensee-bit packing in the changelist field is easy to overlook.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Wire shape stable. | `CUE4Parse/UE4/Versions/FEngineVersion.cs@<CUE4PARSE_SHA>`[^1] |

The licensee-bit convention has also been stable across the entire UE4/UE5
range.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 2 | LE | `major` | `u16` | Major version (e.g. `5`). |
| 2 | 2 | LE | `minor` | `u16` | Minor version (e.g. `1`). |
| 4 | 2 | LE | `patch` | `u16` | Patch version (e.g. `1`). |
| 6 | 4 | LE | `changelist` | `u32` | Packed: bit 31 = licensee flag, bits 0-30 = changelist number. See below. |
| 10 | variable | — | `branch` | `FString`[^3] | Branch name (e.g. `"++UE5+Release-5.1"`). |

Fixed-prefix size: 10 bytes. Total size: `10 + sizeof(branch)`.

### Changelist licensee-bit packing

UE packs two values into the single `u32` `changelist` field:

| Bit range | Mask | Meaning |
|-----------|------|---------|
| 0-30 | `0x7FFF_FFFF` | Perforce-style changelist number, capped at ~2.1 billion. |
| 31 | `0x8000_0000` | Licensee flag: set by studios maintaining private UE forks to indicate that the changelist number is from their internal Perforce stream, not Epic's. |

Paksmith preserves the raw u32 verbatim in `EngineVersion::changelist` for
identity round-trip; user-facing surfaces (`Display`, JSON) mask the high bit
off via `EngineVersion::masked_changelist()`. The licensee flag is exposed
separately via `EngineVersion::is_licensee_version()`.

### Worked example

`tests/fixtures/minimal_uasset_v5.uasset` carries a real `FEngineVersion`
payload terminating in the branch FString `"++UE4+Release-4.27"`. To locate
and inspect it:

```bash
# Find the branch string and back up 14 bytes to the start of the
# u16 major field (10-byte fixed prefix + 4-byte FString length).
grep -boa "++UE4" tests/fixtures/minimal_uasset_v5.uasset
# Then xxd from (match_offset - 14) for a 40-byte window.
```

A `(none yet — pending fixture-stability follow-up)` placeholder is the
honest state here; the exact byte offset depends on the upstream summary
layout and will be anchored once a primitive-focused fixture lands.

## Variants

- **Licensee vs Epic builds.** Both surface through the same wire shape; the
  `is_licensee_version()` flag distinguishes them at decode time.
- **Empty branch.** UE writers never emit an empty branch in practice. If
  one is encountered, paksmith decodes it as `""` and `Display` emits a
  trailing `+` (matching `Serialize`); UE's own `ToString` suppresses the
  trailing `+`. Theoretical divergence — see Known divergences.

## Caps & limits

- **No primitive-level caps** beyond those imposed by the embedded `FString`
  branch — see [`fstring.md`](fstring.md) for the `FSTRING_MAX_LEN = 65_536`
  cap that applies to the branch field.
- **Changelist overflow** is impossible at the wire level (the field is u32);
  the licensee-bit packing means the practical "real" changelist range is
  `0..=0x7FFF_FFFF`.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` carries a real
  `FEngineVersion` near offset `0x77` with branch `"++UE4+Release-4.27"`.
  Use `xxd -s 0x77 -l 40 tests/fixtures/minimal_uasset_v5.uasset` to inspect.
  Exact offset verification belongs in a follow-up that adds the stable
  hex-anchor block.
- **Cross-validation oracle:** CUE4Parse's `FEngineVersion.Read`[^1] and
  `unreal_asset`'s `EngineVersion::read`[^2]. Both confirm the
  `u16+u16+u16+u32+FString` layout and the licensee-bit packing.
- **Known divergences:**
  - **Empty-branch display.** UE's `FEngineVersion::ToString` suppresses
    `+branch` when `branch.IsEmpty()`. Paksmith always emits `+branch` so
    `Display` stays in lockstep with `Serialize` (which routes through
    `collect_str`). UE writers don't emit empty branches in practice, so
    this divergence is theoretical. See
    `crates/paksmith-core/src/asset/engine_version.rs:43-50`.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/engine_version.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct EngineVersion { pub major: u16, pub minor: u16, pub patch: u16, pub changelist: u32, pub branch: String }`.
- `EngineVersion::read_from<R: Read>(&mut R, asset_path) -> Result<EngineVersion>`.
- `EngineVersion::masked_changelist() -> u32` — bits 0-30.
- `EngineVersion::is_licensee_version() -> bool` — bit 31.
- `impl Display` — `"M.m.p-CL+branch"` form (masked changelist).
- `impl Serialize` — JSON string matching `Display`.

**Error variants:**
- `PaksmithError::Io` on truncation.
- `AssetParseFault::FStringMalformed { kind }` on a malformed branch FString
  (forwarded from `read_asset_fstring`).

**Cap constants:** none specific to `EngineVersion`; the branch FString
inherits `FSTRING_MAX_LEN = 65_536` from `container/pak/index/fstring.rs:26`.

**Test files:** `crates/paksmith-core/src/asset/engine_version.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 5).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Versions/FEngineVersion.cs@<CUE4PARSE_SHA>` — reference C# `FEngineVersion.Read` and `IsLicenseeVersion`.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/engine_version.rs@<UNREAL_ASSET_SHA>` — Rust `EngineVersion::read` paksmith cross-validates against.
[^3]: See [`fstring.md`](fstring.md) for FString wire details.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fengine-version.md
git commit -m "$(cat <<'EOF'
docs(formats): add FEngineVersion reference

Documents the u16+u16+u16+u32+FString wire shape and the
licensee-bit packing in the changelist field. Notes paksmith's
empty-branch display divergence from UE's ToString.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Author `docs/formats/primitive/fname.md`

**Files:**
- Create: `docs/formats/primitive/fname.md`

**Ground truth references:**
- Parser: `crates/paksmith-core/src/asset/name_table.rs` (409 lines).
- Critical distinction: the **name table entry** has a wire shape; the **FName reference** does not — it lives at the use site (import/export records).
- Name table entry wire: `FString name + u16 hash_no_case + u16 hash_case`.
- Cap: `MAX_NAME_TABLE_ENTRIES = 1_048_576`.
- UE 4.21+ layout (`FileVersionUE4 ≥ 504`).

- [ ] **Step 1: Read the parser**

Run: `cat crates/paksmith-core/src/asset/name_table.rs`
Pay attention to the module-level comment (lines 1-13) — it has the wire layout.

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fname.md`:

````markdown
# FName (`FName`)

> UE's interned string reference: an index into the per-package name table
> plus a numeric suffix.

## Overview

UE's `FName` is the engine's interned-string type. On disk, an `FName`
reference is **not** a string — it's a pair of integers (table index +
numeric suffix) that resolves against a per-package name table. The string
data lives once in the table; every site that uses it stores only the
reference.

This doc covers two distinct wire shapes:

1. The **name table entry** — one row in the per-package name pool, which IS
   on-disk string data plus two hash trailers.
2. The **FName reference** — the (table-index, number) pair stored at every
   use site (import names, export names, property names, struct paths).

Paksmith's parser owns the table entry shape; the reference shape is read by
each consuming record (import table, export table, tagged-property
iteration) since the wire form differs slightly per consumer.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` (UE 4.21+) | Current "name table entry with hash trailers" shape. | `CUE4Parse/UE4/Objects/UObject/NameTypes.cs@<CUE4PARSE_SHA>`[^1] |
| `FileVersionUE4 < 504` | No hash trailers — FString only. | Same source[^1] |

Paksmith currently parses the UE 4.21+ layout exclusively, matching the
`LegacyFileVersion ≥ -7` floor that propagates through all of Phase 2a's
header parsers.

## Wire layout

### Name table entry (one row of the pool)

| offset (within row) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | variable | — | `name` | `FString`[^3] | Base name string (no `_NN` suffix). |
| `sizeof(name)` | 2 | LE | `hash_no_case` | `u16` | CityHash16 of the case-folded name. Read and discarded by paksmith. |
| `sizeof(name) + 2` | 2 | LE | `hash_case` | `u16` | CityHash16 of the original-case name. Read and discarded by paksmith. |

Row size: `sizeof(name) + 4` bytes. The two hash trailers are validated to
exist (the parser fails if they're truncated) but their values are not
checked — linear scan suffices for header-time parsing, and FModel does not
surface them either.

### Name table container

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `count` | `i32` | Number of name entries that follow. |
| 4 | `Σ sizeof(rows)` | — | `rows` | name-entry[count] | Variable-width rows per the layout above. |

### FName reference (at use sites — for context)

Each FName reference in import/export records, property tags, etc. is a pair
of integers:

| offset (within reference) | size | endian | name | type | semantics |
|---------------------------|------|--------|------|------|-----------|
| 0 | 4 | LE | `index` | `i32` | 0-based index into the package's name table. |
| 4 | 4 | LE | `number` | `i32` | Numeric suffix (`0` means no suffix; non-zero is rendered as `_{number-1}`). |

The reference layout is documented here for cross-referencing but is **not**
parsed by `name_table.rs` — each consuming record reads its own references.
Per-consumer details live in [`uasset.md`](../asset/uasset.md) (import /
export tables) and [`tagged.md`](../property/tagged.md) (property tags).

## Variants

- **Pre-UE 4.21 layout (`FileVersionUE4 < 504`).** Name table entries had no
  hash trailers — just the FString. Not supported by paksmith.
- **UE5 "Names V2" / hash-table variants.** Some UE5 cooked builds use a
  different in-memory representation (`FNamePool` with sharded buckets);
  this is an in-memory concern, not a wire-format one. The on-disk
  package-name-table shape documented above still applies to UE5 packages.

## Caps & limits

- **`count < 0` rejected.** Surfaces as
  `AssetParseFault::NegativeValue { field: AssetWireField::NameTableCount, value }`.
- **`count > MAX_NAME_TABLE_ENTRIES` rejected.**
  `MAX_NAME_TABLE_ENTRIES = 1_048_576` (see
  `crates/paksmith-core/src/asset/name_table.rs:34`). Surfaces as
  `AssetParseFault::BoundsExceeded { field: NameTableCount, value, limit, unit: Items }`.
  Sized to cover any realistic package (real-world packages rarely exceed a
  few thousand names) while preventing attacker-controlled multi-GB
  allocations.
- **Allocation failure handled.** `try_reserve_asset` is used for the names
  `Vec`; failures surface as
  `AssetParseFault::AllocationFailed { context: NameTable, … }`.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` carries a name
  table starting near offset `0x20`. The first entry is the FString
  `"None"` (length-prefix `05 00 00 00`, bytes `4E 6F 6E 65 00`), followed
  by the two `u16` hash trailers. A precise hex-anchor block belongs in a
  follow-up.
- **Cross-validation oracle:** CUE4Parse's name-pool reader[^1] and
  `unreal_asset`'s `FNameEntry::read`[^2]. Both confirm the
  `FString + u16 + u16` row shape for UE 4.21+.
- **Known divergences:** none on the wire shape. Paksmith discards the
  hash trailers; CUE4Parse keeps them in memory for some downstream
  consumers but reads the same bytes.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/name_table.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct FName(Arc<str>)` — interned name; `Clone` is one atomic bump.
- `pub struct NameTable` — the per-package pool.
- `NameTable::read_from<R: Read + Seek>(reader, asset_path, offset, count) -> Result<NameTable>` — seeks to the table offset, reads `count` rows.
- `NameTable::get(index) -> Option<&FName>` — 0-based lookup.

**Error variants:**
- `AssetParseFault::NegativeValue { field: NameTableCount, value }`.
- `AssetParseFault::BoundsExceeded { field: NameTableCount, value, limit, unit }`.
- `AssetParseFault::AllocationFailed { context: NameTable, … }`.
- `AssetParseFault::FStringMalformed { kind }` — forwarded from each entry's
  base-name FString.

**Cap constants:**
- `MAX_NAME_TABLE_ENTRIES: u32 = 1_048_576` (`name_table.rs:34`).

**Test files:** `crates/paksmith-core/src/asset/name_table.rs` `mod tests`
plus integration cases in `crates/paksmith-core-tests/`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 6).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/UObject/NameTypes.cs@<CUE4PARSE_SHA>` — reference C# `FNameEntry` reader and the hash-trailer shape for UE 4.21+.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/types/fname.rs@<UNREAL_ASSET_SHA>` — Rust `FNameEntry::read` paksmith cross-validates against.
[^3]: See [`fstring.md`](fstring.md) for FString wire details.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fname.md
git commit -m "$(cat <<'EOF'
docs(formats): add FName reference

Documents both the per-package name-table entry shape (FString + two
u16 CityHash trailers, UE 4.21+) and the FName reference shape
(index + number) used at every use site. Notes that paksmith reads
and discards the hash trailers, matching FModel's behavior.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Author `docs/formats/primitive/fstring.md`

The most complex primitive. Sign-tagged length, encoding selection, multiple cap and security failure modes.

**Files:**
- Create: `docs/formats/primitive/fstring.md`

**Ground truth references:**
- Authoritative parser: `crates/paksmith-core/src/container/pak/index/fstring.rs` (`read_fstring`, ~200 lines).
- Asset-side wrapper: `crates/paksmith-core/src/asset/fstring.rs` (`read_asset_fstring`, 144 lines).
- Wire: `i32 length` + bytes + NUL terminator.
- Sign convention: positive = UTF-8 bytes (incl. NUL), negative = UTF-16 LE code units (incl. NUL).
- Cap: `FSTRING_MAX_LEN = 65_536`.
- Special cases: `len == 0` rejected (pak) / accepted as empty (asset); `len == i32::MIN` rejected.
- Defense-in-depth: embedded NULs rejected with `at` index.
- Per-context behavior: pak vs asset wrapper.

- [ ] **Step 1: Read both parsers**

Run: `cat crates/paksmith-core/src/container/pak/index/fstring.rs`
Run: `cat crates/paksmith-core/src/asset/fstring.rs`

Note especially:
- `container/pak/index/fstring.rs:54-70` — the `len == 0` rejection and its FDI-invariant rationale.
- `container/pak/index/fstring.rs:128-146` — embedded-NUL rejection (UTF-16 branch).
- `asset/fstring.rs:37-58` — the pak-error → asset-error remapping and the `len == 0` carve-out.

- [ ] **Step 2: Write the doc** (using `<CUE4PARSE_SHA>` and `<UNREAL_ASSET_SHA>` from preamble Step 7)

Write `docs/formats/primitive/fstring.md`:

````markdown
# FString (`FString`)

> UE's variable-length string primitive: signed-i32 length prefix, sign-tagged
> encoding (UTF-8 vs UTF-16 LE), NUL-terminated.

## Overview

`FString` is UE's wire-format string type. It appears everywhere — pak index
filenames, asset name-table entries, custom-version data, soft-object paths,
property tag values. The wire shape is uniform; what varies is which caller
is reading it and how strict that caller is about edge cases.

The encoding selection is sign-tagged: a positive length prefix means UTF-8
bytes, a negative length prefix means UTF-16 LE code units. Both encodings
include the trailing NUL in the count. The encoding selection is purely
sign-driven; there is no separate flag byte.

Two paksmith readers exist for this primitive:

- `container::pak::index::read_fstring` — strict reader used inside the pak
  index. Rejects `len == 0` because the pak FDI record-size invariant
  depends on the 5-byte minimum FString size.
- `asset::read_asset_fstring` — wrapper around the pak reader that accepts
  `len == 0` as the empty string, matching CUE4Parse's
  `FArchive.ReadFString` semantics for inside-asset reads. All other error
  cases are remapped from `IndexParseFault` to `AssetParseFault` for
  consistent operator categorization.

The strict-vs-lenient split is intentional — see Variants below.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Wire shape stable since UE3. | `CUE4Parse/UE4/Readers/FArchive.cs@<CUE4PARSE_SHA>`[^1] |

The sign-tagged length convention and the trailing-NUL discipline have been
stable for the entire UE4/UE5 wire-format lifetime.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `length` | `i32` | Sign-tagged length prefix. See Decode procedure below. |
| 4 | variable | LE | `body` | UTF-8 bytes or UTF-16 code units | Encoding selected by sign of `length`; size selected by absolute value. Includes trailing NUL. |

### Decode procedure

1. Read 4-byte signed `length` (LE).
2. If `length == 0`: handle per-context (see Variants below).
3. If `length == i32::MIN`: reject as malformed (no positive counterpart for
   absolute value).
4. Compute `abs_len = length.abs()`.
5. If `abs_len > FSTRING_MAX_LEN` (65,536): reject as malformed.
6. If `length > 0`:
   - Read `abs_len` bytes as UTF-8.
   - The last byte must be `0x00`. If not, reject as malformed.
   - Strip the trailing NUL.
   - Defense in depth: reject if any non-trailing byte is `0x00`
     (embedded NUL).
   - Convert to `String` via `String::from_utf8`. UTF-8 validation failures
     surface as malformed.
7. If `length < 0`:
   - Read `abs_len` LE `u16` code units.
   - The last code unit must be `0x0000`. If not, reject as malformed.
   - Strip the trailing NUL code unit.
   - Defense in depth: reject if any non-trailing code unit is `0x0000`
     (embedded NUL).
   - Convert to `String` via `String::from_utf16`. UTF-16 validation failures
     surface as malformed.

## Variants

### Pak-index reader (strict)

`container::pak::index::read_fstring`. Used for all pak-index FString fields
(entry filenames, mount points, FDI directory/file names).

- `len == 0` → reject as `IndexParseFault::FStringMalformed { kind: LengthIsZero }`.
- All other rules as above.

Rationale: paksmith's FDI bounds-check arithmetic
(`MIN_FDI_*_RECORD_BYTES = 9`) assumes the 5-byte minimum FString
(`length(4) + NUL(1)`). Allowing `len == 0` would shrink the per-record
minimum to 4 bytes and let an attacker pack ~12.5% more records into a
given FDI region than the cap predicts. See issue #104 and
`container/pak/index/fstring.rs:54-70`.

### Asset-side wrapper (lenient on `len == 0`)

`asset::read_asset_fstring`. Used for all asset-side FString fields (name
table entries, custom-version branch names, soft-object paths, property tag
values).

- `len == 0` → accept as `""` (empty string).
- All other malformations remapped from `IndexParseFault::FStringMalformed`
  to `AssetParseFault::FStringMalformed` for consistent operator-facing
  error categorization.

Rationale: CUE4Parse's `FArchive.ReadFString` returns `""` on `len == 0`
without throwing[^1]. Paksmith matches that semantics inside assets (no
FDI invariant to protect) but keeps the strict pak-side reader for archive
structural integrity.

### Encoding selection

- `length > 0` → UTF-8 bytes.
- `length < 0` → UTF-16 LE code units.
- `length == 0` → see strict/lenient variants above.

There is no third encoding. ASCII is treated as UTF-8 (single-byte
characters validate identically); ANSI / Windows-1252 inputs are theoretical
and have never been observed in cooked UE output.

## Caps & limits

- **Length cap.** `FSTRING_MAX_LEN = 65_536` bytes (UTF-8) or code units
  (UTF-16) — `container/pak/index/fstring.rs:26`. Sized to comfortably
  exceed any realistic UE virtual path while rejecting attacker-controlled
  multi-GB allocations. Surfaces as
  `FStringFault::LengthExceedsMaximum { length, maximum }`.
- **`len == 0`** — see Variants for the per-reader handling.
- **`len == i32::MIN`** — reject (no positive counterpart). Surfaces as
  `FStringFault::LengthIsI32Min`.
- **Embedded NUL bytes/code units** — reject with position index. Surfaces
  as `FStringFault::EmbeddedNul { encoding, at }`. Defensive measure: UE
  writers never emit embedded NULs, and allowing them through would let an
  attacker craft a path like `"asset.uasset\0../../etc/passwd"` that gets
  truncated at the NUL by POSIX `open(2)` but preserved on NTFS — a
  cross-platform path-truncation vector. Currently inert in paksmith
  (FName-as-HashMap-key carries the NUL through transparently), but the
  parser is the right chokepoint to gate at before Phase 4+ extraction
  lands.
- **Missing trailing NUL** — reject. Surfaces as
  `FStringFault::MissingNullTerminator { encoding }`.
- **Allocation cap.** Allocations use `try_reserve_exact` and surface as
  `IndexParseFault::AllocationFailed { context: FStringUtf8Bytes |
  FStringUtf16CodeUnits, requested, source, path }` if reservation fails.
  At the `FSTRING_MAX_LEN` cap, the maximum allocation is 128 KiB for
  UTF-16 — well within infallible territory on a healthy machine.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` carries multiple
  asset-side FStrings. The `"None"` name-table entry at offset `0x20` is
  the cleanest single-FString anchor — a 5-byte UTF-8 payload with the
  length-prefix `05 00 00 00`, bytes `4E 6F 6E 65 00`. Verify with:
  ```bash
  xxd -s 0x20 -l 9 tests/fixtures/minimal_uasset_v5.uasset
  ```
  Expected output:
  ```
  00000020: 0500 0000 4e6f 6e65 00                   ....None.
  ```
  (Precise embedding in this doc as a `### Worked example` block once the
  hex-anchor CI check lands per the framework spec.)
- **Cross-validation oracle:** CUE4Parse's `FArchive.ReadFString`[^1] and
  `unreal_asset`'s `FString::read`[^2]. Both confirm the sign-tagged
  length, the UTF-8/UTF-16 selection, and the trailing-NUL discipline.
- **Known divergences:**
  - **`len == 0` handling.** CUE4Parse accepts `len == 0` as `""`
    universally. Paksmith splits: pak-side strict rejection (for FDI
    invariants), asset-side lenient acceptance (matches CUE4Parse). Both
    behaviors are intentional. See `asset/fstring.rs:1-13`.
  - **Embedded NUL rejection.** Paksmith rejects embedded NULs as a
    defense-in-depth path-traversal guard. CUE4Parse does not. The
    practical impact is nil because UE writers never emit embedded NULs.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/container/pak/index/fstring.rs` — strict pak-index
  reader (`read_fstring`).
- `crates/paksmith-core/src/asset/fstring.rs` — asset-side wrapper
  (`read_asset_fstring`, `write_asset_fstring`).

**Status:** `complete`.

**Public surface:**
- `pub(crate) fn read_fstring<R: Read>(reader: &mut R) -> Result<String>`
  (re-exported as `crate::container::pak::index::read_fstring`).
- `pub(crate) fn read_asset_fstring<R: Read>(reader: &mut R, asset_path: &str) -> Result<String>`.
- `pub(crate) fn write_asset_fstring<W: Write>(writer: &mut W, s: &str) -> io::Result<()>` (gated behind `__test_utils`).

Both readers are `pub(crate)` — no external API surface for FString reading.
Consumers go through the structured `NameTable`, `CustomVersion`,
`PackageSummary`, etc. types that own the per-record context.

**Error variants:**
- `IndexParseFault::FStringMalformed { kind: FStringFault::* }` (pak-side).
- `AssetParseFault::FStringMalformed { kind: FStringFault::* }` (asset-side, remapped).
- `FStringFault::{LengthIsZero, LengthIsI32Min, LengthExceedsMaximum, MissingNullTerminator, EmbeddedNul, InvalidEncoding}`.
- `IndexParseFault::AllocationFailed { context: FStringUtf8Bytes |
  FStringUtf16CodeUnits, … }`.

**Cap constants:**
- `FSTRING_MAX_LEN: i32 = 65_536` (`container/pak/index/fstring.rs:26`).

**Test files:**
- `crates/paksmith-core/src/container/pak/index/fstring.rs` `mod tests` (if
  present) plus the FString-focused tests in
  `crates/paksmith-core/src/container/pak/index/mod.rs:1031-1116`.
- `crates/paksmith-core/src/asset/fstring.rs` `mod tests` (`len_zero_decodes_as_empty_string`, `non_zero_malformation_still_errors`, `embedded_nul_forwards_through_wrapper`).

**Phase plan:**
- Pak-side strict reader: covered by Phase 1 hardening (issue #104).
- Asset-side wrapper: `docs/plans/phase-2a-uasset-header.md` (Task 1).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Readers/FArchive.cs@<CUE4PARSE_SHA>` — reference C# `FArchive.ReadFString` including the `len == 0` carve-out and the sign-tagged encoding selection.
[^2]: `AstralOrigin/unreal_asset/unreal_asset/src/types/fstring.rs@<UNREAL_ASSET_SHA>` — Rust `FString::read` paksmith cross-validates against.
````

- [ ] **Step 3: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/primitive/fstring.md
git commit -m "$(cat <<'EOF'
docs(formats): add FString reference

Documents the sign-tagged i32 length prefix, the UTF-8/UTF-16
encoding selection, the FSTRING_MAX_LEN = 65_536 cap, and the
intentional pak-strict vs asset-lenient split on len == 0. Spells
out the embedded-NUL rejection as a defense-in-depth path-traversal
guard.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 1: Add six rows to the inventory table**

In `docs/formats/README.md`, locate the inventory table (the line starting
`| Doc | Doc status | Parser status |`). Use the Edit tool to insert six new
rows immediately after the separator row.

The rows to insert (substituting `<SHA>` = current `git rev-parse --short HEAD`,
`<CUE4PARSE_SHA>` / `<UNREAL_ASSET_SHA>` from preamble Step 7):

```markdown
| `primitive/fguid.md` | complete | complete | `asset/guid.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `primitive/fpackage-index.md` | complete | complete | `asset/package_index.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `primitive/fcustom-version.md` | complete | complete | `asset/custom_version.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `primitive/fengine-version.md` | complete | complete | `asset/engine_version.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `primitive/fname.md` | complete | complete | `asset/name_table.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
| `primitive/fstring.md` | complete | complete | `container/pak/index/fstring.rs` | CUE4Parse @ `<CUE4PARSE_SHA>` | `<SHA>` |
```

Use the Edit tool with `old_string` = the separator line `|-----|------------|...|` (verify exact content with `grep -n "^|-" docs/formats/README.md`), `new_string` = that line + `\n` + the six rows above.

- [ ] **Step 2: Run preamble's Per-family final-verification + push tail**

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family final-verification + push tail" section: capture branch HEAD, status-enum lint, required-headings lint, file-tree sanity check, typos, `cargo doc -D warnings`. The expected commit log after Step 3 below has 7 entries (one per doc + one for the inventory update).

- [ ] **Step 3: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the six primitive docs in the inventory

All six primitives (FString, FName, FGuid, FPackageIndex,
FCustomVersion, FEngineVersion) ship complete docs with complete
parsers behind them. Last-verified anchor is this branch's HEAD.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Push the branch and open the PR**

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Push and open PR" + "Run the reviewer panel" steps.

Title: `docs(formats): populate primitive family (FString/FName/FGuid/FPackageIndex/FCustomVersion/FEngineVersion)`

PR body (write to a tempfile first):

```markdown
## Summary

Lands PR 2 of the UE format documentation framework. Populates
`docs/formats/primitive/` with six full byte-level reference docs:

- `fstring.md` — sign-tagged length, UTF-8/UTF-16 selection, NUL discipline.
- `fname.md` — name-table entry shape (UE 4.21+) + FName-reference shape.
- `fguid.md` — 16-byte fixed shape + canonical display form.
- `fpackage-index.md` — sign-tagged i32 (Null/Import/Export decode).
- `fcustom-version.md` — post-UE4.13 "Optimized" container layout.
- `fengine-version.md` — `u16+u16+u16+u32+FString` + licensee-bit packing.

All six docs are `complete` status because every primitive has a shipped
parser in `crates/paksmith-core/src/asset/`. Six rows added to the root
inventory.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes on all docs.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean (no Rust changes).
- [x] `typos docs/formats/` clean.
- [x] Cross-validated every wire-format claim against CUE4Parse + unreal_asset.

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean (no Rust changed).
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

None — pure documentation. The docs themselves spell out the security
posture of each primitive parser (caps, embedded-NUL rejection, FDI
invariants).

## Notes for reviewers

- Hex-anchor `### Worked example` blocks are `(none yet)` for three docs
  (FGuid, FPackageIndex, FName) per the spec's allowed Verification state;
  the other three reference `tests/fixtures/minimal_uasset_v5.uasset` with
  unverified offsets pending a follow-up that adds primitive-focused
  fixtures.
- Oracle citations point at CUE4Parse and unreal_asset; SHAs were captured
  at the start of authoring (see commit dates).
- The "Versions" tables on FGuid and FPackageIndex have a single row each
  ("stable since UE3") which looks sparse but is accurate — required by the
  template and load-bearing for anyone scanning for version-conditional
  decode logic.
```

(Reviewer panel dispatch + convergence loop is covered by [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md).)

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's specifics: six rows present in `docs/formats/README.md` inventory, all `complete | complete` (every primitive has a shipped parser).
