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
| `container/pak.md` | complete | complete | `container/pak/` | repak @ `355b5f62f51959c7cc6dd5a51708646ef483065d` | `778d82d` |
| `container/iostore-utoc.md` | partial | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | n/a |
| `container/iostore-ucas.md` | partial | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | n/a |
| `container/iostore-uptnl.md` | partial | not impl | — | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | n/a |
| `asset/uasset.md` | complete | complete | `asset/` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `a915f3c` |
| `asset/uexp.md` | complete | complete | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `a915f3c` |
| `asset/ubulk.md` | partial | partial | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `a915f3c` |
| `asset/companion-resolution.md` | complete | complete | `asset/package.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `a915f3c` |
| `property/tagged.md` | complete | complete | `asset/property/tag.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `property/unversioned.md` | partial | partial | `asset/property/unversioned.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `property/primitives.md` | complete | complete | `asset/property/primitives.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `property/containers.md` | complete | complete | `asset/property/containers.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `property/struct.md` | partial | partial | `asset/property/containers.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `property/text.md` | partial | partial | `asset/property/text.rs` | CUE4Parse @ `ecc4878950336126f125af0747190edf474b2a21` | `0e7d733` |
| `primitive/fstring.md` | complete | complete | `container/pak/index/fstring.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `primitive/fname.md` | partial | complete | `asset/name_table.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `primitive/fguid.md` | partial | complete | `asset/guid.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `primitive/fpackage-index.md` | partial | complete | `asset/package_index.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `primitive/fcustom-version.md` | partial | complete | `asset/custom_version.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `primitive/fengine-version.md` | partial | complete | `asset/engine_version.rs` | CUE4Parse @ `380d005380d166a3fc19a8bb6940a61af8261e8a` | `0af1609` |
| `texture/texture2d.md` | stub | not impl | — | — | n/a |
| `texture/pixel-formats.md` | stub | not impl | — | — | n/a |
| `texture/mips-and-streaming.md` | stub | not impl | — | — | n/a |
| `mesh/static-mesh.md` | stub | not impl | — | — | n/a |
| `mesh/skeletal-mesh.md` | stub | not impl | — | — | n/a |
| `mesh/skeleton.md` | stub | not impl | — | — | n/a |
| `mesh/vertex-formats.md` | stub | not impl | — | — | n/a |
| `audio/sound-wave.md` | stub | not impl | — | — | n/a |
| `audio/audio-codecs.md` | stub | not impl | — | — | n/a |
| `animation/anim-sequence.md` | stub | not impl | — | — | n/a |
| `material/material.md` | stub | not impl | — | — | n/a |
| `material/material-instance.md` | stub | not impl | — | — | n/a |
| `data/data-asset.md` | stub | not impl | — | — | n/a |
| `data/data-table.md` | stub | not impl | — | — | n/a |
| `data/locres.md` | stub | not impl | — | — | n/a |
| `compression/pak-block-framing.md` | stub | not impl | — | — | n/a |
| `compression/zlib.md` | stub | not impl | — | — | n/a |
| `compression/oodle.md` | stub | not impl | — | — | n/a |
| `crypto/aes-pak.md` | stub | not impl | — | — | n/a |

Status enums (the `paksmith-doc-lint status-enum` check enforces these):

- **Doc status:** `stub` · `partial` · `complete`
- **Parser status:** `not impl` · `partial` · `complete`
- **Last verified:** commit SHA where the doc was last cross-checked against
  oracle + fixtures, or `n/a` if not yet verified.
