# Paksmith format reference

This directory documents every Unreal-Engine-specific binary format paksmith
parses (or intends to parse). Each format gets one document, layered for two
readers from the same content:

- **External UE-format researchers** building a parser in any language. Read
  the `Versions`, `Wire layout`, `Variants`, and `Caps & limits` sections.
- **Paksmith contributors**. Read the same wire content for orientation, then
  the `Paksmith implementation` sidebar for parser module, fixtures, and
  caps.

See `docs/design/2026-05-19-ue-format-docs.md` for the design that produced
this directory. See `TEMPLATE.md` for the per-doc skeleton and `CONVENTIONS.md`
for hex-anchor + citation conventions.

## Families

- [`container/`](container/README.md) — archive formats (`.pak`, IoStore)
- [`asset/`](asset/README.md) — package format (`.uasset`, `.uexp`, `.ubulk`)
- [`property/`](property/README.md) — tagged and unversioned property
  serialization
- [`primitive/`](primitive/README.md) — `FString`, `FName`, `FGuid`,
  `FPackageIndex`, custom-version / engine-version records
- [`texture/`](texture/README.md) — `Texture2D`, pixel formats, mips
- [`mesh/`](mesh/README.md) — static / skeletal mesh, skeleton, vertex
  formats
- [`audio/`](audio/README.md) — `SoundWave`, audio codec framing
- [`animation/`](animation/README.md) — `AnimSequence`
- [`material/`](material/README.md) — `Material`, `MaterialInstance`
- [`data/`](data/README.md) — `DataAsset`, `DataTable`, `Locres`
- [`compression/`](compression/README.md) — pak block framing, zlib, Oodle
- [`crypto/`](crypto/README.md) — AES-256 pak encryption

## Inventory

The table below is the single source of truth for which formats have docs,
which docs are complete, and which parsers are wired up. Rows ship as
`stub | not impl` placeholders for the full planned corpus; per-family PRs
UPDATE existing rows rather than appending new ones. See the design spec
section "Format inventory" for column semantics.

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `355b5f62f51959c7cc6dd5a51708646ef483065d` | `8f56038` |
| `container/iostore-utoc.md` | complete | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `container/iostore-ucas.md` | complete | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `container/iostore-uptnl.md` | complete | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `container/iostore-directory-index.md` | complete | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `asset/uasset.md` | complete | complete | `asset/` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `asset/uexp.md` | complete | complete | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `asset/ubulk.md` | complete | partial | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `asset/companion-resolution.md` | complete | complete | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `asset/bulk-data.md` | complete | partial | `asset/package.rs` | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `property/tagged.md` | complete | complete | `asset/property/tag.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `property/unversioned.md` | complete | partial | `asset/property/unversioned.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `property/primitives.md` | complete | complete | `asset/property/primitives.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `property/containers.md` | complete | complete | `asset/property/containers.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `property/struct.md` | complete | partial | `asset/property/containers.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `property/text.md` | complete | partial | `asset/property/text.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `primitive/fstring.md` | complete | complete | `container/pak/index/fstring.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `primitive/fname.md` | complete | complete | `asset/name_table.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `primitive/fguid.md` | complete | complete | `asset/guid.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `primitive/fpackage-index.md` | complete | complete | `asset/package_index.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `primitive/fcustom-version.md` | complete | complete | `asset/custom_version.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `primitive/fengine-version.md` | complete | complete | `asset/engine_version.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `8f56038` |
| `texture/texture2d.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `texture/pixel-formats.md` | complete | partial | `asset/exports/texture/pixel_format.rs` | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `texture/mips-and-streaming.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `texture/virtual-textures.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `mesh/static-mesh.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `mesh/skeletal-mesh.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `mesh/skeleton.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `mesh/vertex-formats.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `mesh/nanite-resources.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `audio/sound-wave.md` | complete | partial | `asset/exports/audio/` | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `audio/audio-codecs.md` | complete | partial | `export/audio.rs` | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `animation/anim-sequence.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `material/material.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `material/material-instance.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `material/static-parameter-set.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `material/parameter-values.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `data/data-asset.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `data/data-table.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `data/locres.md` | complete | not impl | — | CUE4Parse @ `cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` | `8f56038` |
| `compression/pak-block-framing.md` | complete | complete | `container/pak/index/compression.rs` | repak @ `355b5f62f51959c7cc6dd5a51708646ef483065d` | `8f56038` |
| `compression/zlib.md` | complete | complete | `container/pak/mod.rs` | repak @ `355b5f62f51959c7cc6dd5a51708646ef483065d` | `8f56038` |
| `compression/oodle.md` | complete | partial | `container/pak/index/compression.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `8f56038` |
| `crypto/aes-pak.md` | complete | partial | `container/pak/footer.rs` | repak @ `355b5f62f51959c7cc6dd5a51708646ef483065d` | `8f56038` |

Status enums (the `paksmith-doc-lint status-enum` check enforces these):

- **Doc status:** `stub` · `partial` · `complete`
- **Parser status:** `not impl` · `partial` · `complete`
- **Last verified:** commit SHA where the doc's wire claims were last
  cross-checked against the `Reference oracle` SHA. Bumped on
  substantive content edits AND on explicit audit-passes that
  re-verify the wire claims against the oracle. Use `n/a` if the
  doc has never been cross-checked. **Do NOT bump for purely
  formatting / whitespace edits** — the column tracks verification
  activity, not commit-touch.
