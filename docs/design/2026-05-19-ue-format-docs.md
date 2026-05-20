# UE format documentation framework

> **Status:** approved design, ready for implementation planning.
> **Owner:** paksmith maintainers.
> **Companion:** the implementation plan generated from this spec.

## Goal

Stand up `docs/formats/` as the canonical, audience-layered, byte-level reference
for every Unreal-Engine-specific binary format paksmith intends to support — and
keep it accurate as the parser, the fixtures, and the UE ecosystem evolve.

Each format gets one document. Each document serves two readers from the same
content:

- An **external UE-format researcher** building a parser in any language, who reads
  the wire-layout sections and ignores the implementation sidebar.
- A **paksmith contributor** who reads the wire-layout sections for orientation
  and the implementation sidebar to find the parser module, the cap constants,
  the fixtures, and the known divergences.

Wire-format content is load-bearing and audience-agnostic. Paksmith specifics live
in a single appendix-style section per doc so the wire content stays portable.

## Non-goals

- **Not a Rust API reference.** That lives in `cargo doc`. The format docs are
  about the bytes on disk, not the types in the codebase.
- **Not a porting guide.** Step-by-step "build a parser from scratch" content
  belongs in tutorials, not reference docs.
- **Not a roadmap.** The phase plans under `docs/plans/` own scheduling; the
  format docs are reference artifacts that outlive any given phase.
- **Not an FModel comparison.** Where paksmith diverges from FModel intentionally,
  that goes in a project-level design note, not in a format reference.

## Architecture

### Directory layout

```
docs/formats/
├── README.md                       — front door + format inventory table
├── TEMPLATE.md                     — canonical skeleton authors copy
├── CONVENTIONS.md                  — hex-anchor format, citation style, version-marker syntax
├── container/
│   ├── README.md
│   ├── pak.md                      — covers v1–v11 in one doc (variants table)
│   ├── iostore-utoc.md
│   ├── iostore-ucas.md
│   └── iostore-uptnl.md
├── asset/
│   ├── README.md
│   ├── uasset.md                   — header + name/import/export tables
│   ├── uexp.md
│   ├── ubulk.md
│   └── companion-resolution.md
├── property/
│   ├── README.md
│   ├── tagged.md                   — FPropertyTag wire layout
│   ├── unversioned.md              — UE5 schema-driven serialization
│   ├── primitives.md
│   ├── containers.md
│   ├── struct.md
│   └── text.md
├── primitive/
│   ├── README.md
│   ├── fstring.md
│   ├── fname.md
│   ├── fguid.md
│   ├── fpackage-index.md
│   ├── fcustom-version.md
│   └── fengine-version.md
├── texture/
│   ├── README.md
│   ├── texture2d.md
│   ├── pixel-formats.md
│   └── mips-and-streaming.md
├── mesh/
│   ├── README.md
│   ├── static-mesh.md
│   ├── skeletal-mesh.md
│   ├── skeleton.md
│   └── vertex-formats.md
├── audio/
│   ├── README.md
│   ├── sound-wave.md
│   └── audio-codecs.md
├── animation/
│   ├── README.md
│   └── anim-sequence.md
├── material/
│   ├── README.md
│   ├── material.md
│   └── material-instance.md
├── data/
│   ├── README.md
│   ├── data-asset.md
│   ├── data-table.md
│   └── locres.md
├── compression/
│   ├── README.md
│   ├── pak-block-framing.md
│   ├── zlib.md
│   └── oodle.md
└── crypto/
    ├── README.md
    └── aes-pak.md
```

~40 format docs across 12 family directories (container, asset, property,
primitive, texture, mesh, audio, animation, material, data, compression,
crypto). Family `README.md` files carry narrative-only overviews ("when to
read which doc in this family") — no status tables, no inventory rows.
Inventory lives only in the root README.

### Per-doc template

Every format doc has the following H2 sections in this exact order. Section
bodies adapt per format; the headings are fixed and CI fails the build if one
is missing.

```markdown
# <Format name> (`.ext` / FStructName)

> One-line summary: what this is and where it appears in a UE pak.

## Overview
What this format encodes, where it sits in the bigger picture, what other docs
to read first.

## Versions
Table: UE version range → wire-format changes. Each row cites the version
constant (e.g. `FileVersionUE4 ≥ 507`) and the community impl + commit SHA
where the change was first documented. Anchor for every conditional in later
sections.

## Wire layout
The byte-by-byte reference. One subsection per top-level record. Each field
listed as:
| offset | size | endian | name | type | semantics |
Optionally a `### Worked example` subsection with an annotated hex block from
a named fixture. Hex blocks follow CONVENTIONS.md (16 bytes/row, ASCII gutter,
field-boundary markers).

## Variants
Per-version, per-platform, per-game variants. Each variant gets a named
subsection that references back to the Versions table.

## Caps & limits
What paksmith refuses to parse and why. Cross-link to
docs/security/allocation-caps.md. Required even if the answer is "none" —
the section header must be present so a reader can trust "if it's not listed
here, paksmith doesn't cap it."

## Verification
How a reader can verify the spec is correct against a real file:
- Fixture path in tests/fixtures/ (or "(none yet)" with a tracking issue link)
- Hex anchor commands (e.g. `xxd -s 0x40 -l 32 …`)
- Cross-validation oracle (community impl name + version)
- Known divergences between oracle and engine output

## Paksmith implementation
Audience-switch sidebar. Names the parser module, the error variants, the cap
constants, the test files. Status badge: `not impl` / `partial` /
`complete`. Links to the phase plan that owns the work.

## References
Numbered citation list. Each entry: community project + file path + commit SHA
+ a short description of what's cited. EpicGames/UnrealEngine URLs are
forbidden — enforced by PR review and CONTRIBUTING.md, not by automation.
```

**Rationale notes.**

- **Versions sits early** because almost every later field has a version
  conditional; anchoring them up front avoids inline "in UE 4.27+" sprawl
  through the Wire layout.
- **Caps & limits is mandatory-even-when-empty** so readers can rely on the
  presence of the section as evidence the question was considered.
- **Paksmith implementation is the last content section** (References sits
  after for citation hygiene) so external readers can stop reading at
  Verification without missing reference material.

### Format inventory

The root `docs/formats/README.md` carries one table — the single source of
truth for what exists, what's planned, and where the gaps are. Every row maps
to one doc file. No family-level duplicate tables.

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|-----------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `<sha>` | `<commit>` |
| `container/iostore-utoc.md` | partial | not impl | — | CUE4Parse @ `<sha>` | n/a |
| `asset/uasset.md` | partial | partial | `asset/` | unreal_asset @ `<sha>` | `<commit>` |
| `property/tagged.md` | complete | complete | `asset/property/` | unreal_asset @ `<sha>` | `<commit>` |
| `texture/texture2d.md` | partial | not impl | — | CUE4Parse @ `<sha>` | n/a |
| … | | | | | |

**Status enums (fixed; CI checks values):**

- **Doc status:** `stub` (1–2 paragraphs + references — the pre-authoring
  placeholder state, not used by any authored doc), `partial` (some sections
  complete, others marked `TODO` — the steady-state for unshipped formats
  and detection-only-but-not-decoded surfaces), `complete` (every section
  filled, every claim verified). In practice every authored doc is at
  least `partial`; `stub` exists for the empty-row pre-author state only.
- **Parser status:** `not impl`, `partial`, `complete`. This column is the
  source of truth for each doc's `## Paksmith implementation` sidebar — they
  must agree.
- **Last verified:** the commit SHA where the doc was last cross-checked
  against the oracle plus fixtures. Bumped only when verification was
  actually re-run, not on every edit.

The phase plans under `docs/plans/` are scheduling artifacts. They are
deliberately not represented in this table — the inventory is a reference
artifact that outlives any given phase's planning state.

## Sourcing and attribution

### Citation format

Every wire-format claim in `## Wire layout`, `## Versions`, or `## Variants`
needs an inline footnote reference. Footnotes resolve in the `## References`
section, where each entry is a `{community-project}/{path}@{sha}` URL plus a
one-line description. SHAs (not branches) so links don't rot as upstream moves.

**Required oracle priority order**, when multiple sources cover a claim:

1. **CUE4Parse** — broadest coverage; default citation for asset internals.
2. **repak** — pak-specific; default for container claims.
3. **FModel** — UI/struct insights; cite when CUE4Parse references a struct
   FModel documents more cleanly.
4. **UE4SS** — live runtime RE; cite for behavior not visible in cooked output.
5. **unreal_asset** — Rust API; already paksmith's fixture oracle, cite when
   triangulating a Rust-perspective view.

### Hex-anchor convention

Each `### Worked example` block names a fixture under `tests/fixtures/` and a
reproducible shell command. The doc shows the expected output verbatim. CI
runs every command and diffs against the embedded expected output. A fixture
changing under a doc's feet fails the build with a pointer to the affected
doc.

Allowed commands are read-only inspection tools that ship with the CI runners
or are explicitly installed by the workflow — at minimum `xxd`, `hexdump`,
`od`, `wc`, `sha1sum`. Each command must be deterministic and side-effect
free. CONVENTIONS.md is the authoritative list and grows by PR when a new
inspection tool is needed.

### Attribution rules

Restating from CLAUDE.md memory because this rule is load-bearing for the whole
corpus:

- **Scope:** these rules apply to files under `docs/formats/`. Other docs
  under `docs/` predate this framework and are not subject to it.
- **Zero links to `github.com/EpicGames/UnrealEngine`** paths or line numbers,
  ever, in any `docs/formats/` file.
- **Plain-prose engine facts are fine** — describing what the engine does is
  not the same as citing engine source.
- **Citations go to community projects only** — see priority list above.
- **Forward cross-references (`[…](../family/doc.md)`) are allowed even when
  the target doc hasn't landed yet.** The 12-PR rollout sequences families
  for content dependency reasons; intra-corpus links resolve as each
  family's PR merges. Authors are expected to use forward links freely;
  reviewers should not block on broken-link evidence until both PRs have
  merged. The hex-anchor CI check is per-changed-file and the
  reference-link nightly check both tolerate this; missed targets get
  surfaced naturally as later PRs land.

Enforcement is human (PR review + a line in `CONTRIBUTING.md`), not automated.
An automated grep for `EpicGames/UnrealEngine` is itself a public artifact in
`.github/workflows/` that signals the project looks at engine source closely
enough to need an automated guard. The rule stands; the enforcement stays
quiet.

## CI enforcement

Four mechanical checks. The set is deliberately scoped so the framework PR can
land checks 1–2 immediately and defer 3–4 until enough content exists to make
them useful.

1. **Required-headings linter.** Every `docs/formats/**/*.md` (excluding
   `README.md`, `TEMPLATE.md`, `CONVENTIONS.md`) must contain the eight H2
   sections from the template, in the specified order. Lands with PR 1.
2. **Status-enum + doc/parser consistency linter.** The root README table only
   contains the fixed status values. Doc/parser status pairs are checked for
   smells (a `complete` doc whose parser is `not impl` warns; the inverse
   warns too). Lands with PR 1.
3. **Hex-anchor checker.** Parses `### Worked example` blocks, runs each
   command, diffs against the embedded expected output. Runs only on changed
   files in PR builds; full sweep nightly. Deferred to a follow-up PR after
   at least one family ships docs with worked examples.
4. **Reference-link checker.** Every footnote in `## References` resolves to a
   `{project}@{sha}` URL that returns 200. Network-flaky — runs nightly only,
   not per-PR. Deferred to a follow-up PR after enough citations exist to
   amortize the network cost.

The attribution rule from the previous section is NOT enforced by CI. It is
enforced by PR review and `CONTRIBUTING.md` only.

## Maintenance triggers

Five triggers, each pinned to a mechanical signal so currency doesn't depend
on memory:

1. **Parser change in a documented module.** The PR that touches
   `crates/paksmith-core/src/<module>` must include a corresponding edit to
   the matching format doc — at minimum bumping `Last verified`, more if
   behavior changed. PR template gains a checkbox: *"Touched a parser?
   Updated its format doc?"*
2. **Fixture change.** A change to `tests/fixtures/` referenced by a
   `### Worked example` block fails the hex-anchor check. Doc and fixture
   move together or one of them is wrong.
3. **New UE version observed in the wild.** Bumping `FileVersionUE4`
   constants or adding a new pak version variant means a new row in that
   doc's `## Versions` table. Doc status downgrades to `partial` until the
   row lands.
4. **Oracle bug found.** When triangulation discovers a community impl
   disagrees with engine-cooked output (Phase 2a found 8 such cases), the
   doc records the divergence in `## Verification → Known divergences` with
   the cooked-output evidence. Doc stays `complete`; the divergence is the
   new ground truth.
5. **Quarterly verification sweep.** Every doc whose `Last verified` is
   older than 90 days gets re-checked against its current oracle SHA and
   fixtures, with the result bumping `Last verified` or downgrading status.
   The only time-based trigger; everything else is event-driven.

Triggers 3 and 4 are the load-bearing ones — they're how the corpus stays
accurate as the UE ecosystem evolves. Triggers 1 and 2 turn drift into
mechanical CI/PR-template failures rather than judgment calls.

## Rollout

Twelve PRs, each independently mergeable and reviewable. Framework usable
after PR 1.

**Implementation-plan scope.** The plan generated from this spec covers
**PR 1 (framework scaffold) only**. Per-family PRs each get their own
implementation plan when their phase opens — the per-format research,
fixture work, and oracle triangulation is meaningful effort that shouldn't
be collapsed into a single mega-plan. PR 1 produces the scaffold, the
linters, and the empty inventory; subsequent PRs are planned individually.

**PR 1 — Framework scaffold (no content).**
`docs/formats/README.md` (inventory table with every planned doc as a `stub`
row, no rows filled), `TEMPLATE.md`, `CONVENTIONS.md`, all family `README.md`
files (narrative only). Adds the required-headings and status-enum linters
to CI. Establishes the rules; populates nothing.

**PR 2 — Primitives family** (FString, FName, FGuid, FPackageIndex,
FCustomVersion, FEngineVersion).
Authored first because every other doc cites these. Small in pages but
unblocks all downstream work. Validates the template against six small docs
at once.

**PRs 3–12 — One PR per family**, in dependency order:

3. Container (pak, iostore-utoc, iostore-ucas, iostore-uptnl)
4. Asset (uasset, uexp, ubulk, companion-resolution)
5. Property (tagged, unversioned, primitives, containers, struct, text)
6. Compression (pak-block-framing, zlib, oodle)
7. Crypto (aes-pak)
8. Texture (texture2d, pixel-formats, mips-and-streaming)
9. Mesh (static-mesh, skeletal-mesh, skeleton, vertex-formats)
10. Audio (sound-wave, audio-codecs)
11. Animation + Material (anim-sequence, material, material-instance)
12. Data (data-asset, data-table, locres)

Stubs allowed for formats whose parser hasn't shipped; `complete` required
for any format already in the codebase.

**Two follow-up infra PRs**, ordered after content has started landing:

- Hex-anchor CI check — after at least one family PR ships docs with
  `### Worked example` blocks.
- Reference-link nightly check — after enough citations exist to amortize the
  network cost.

**Cadence after backfill.** Once the framework exists, every new parser PR
(Phase 2f, Phase 3, Phase 8) is expected to ship its format doc in the same
PR. The 12-PR rollout is one-time backfill; subsequent format docs come for
free with their phase work.

**Pacing reality.** This is a multi-month effort no matter how it's sliced.
The framework lands quickly (PR 1 is small), but completing the corpus is
paced by the broader roadmap. Unfinished family rows are not a regression —
they're the normal state until the corresponding phase work runs.

## Open questions

None at design time. If questions arise during implementation, surface them
in the writing-plans output, not by amending this spec.

## References

This spec cites no community implementations directly; it defines a framework
those citations will live inside. Per-family docs produced under this
framework will cite CUE4Parse, repak, FModel, UE4SS, and unreal_asset per the
priority order above.
