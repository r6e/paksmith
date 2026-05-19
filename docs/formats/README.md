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
which docs are complete, and which parsers are wired up. There are no rows
yet — they accrete as per-family PRs land. See the design spec section
"Format inventory" for column semantics.

| Doc | Doc status | Parser status | Parser module | Reference oracle | Last verified |
|-----|------------|---------------|----------------|-------------------|---------------|

Status enums (the `paksmith-doc-lint status-enum` check enforces these):

- **Doc status:** `stub` · `partial` · `complete`
- **Parser status:** `not impl` · `partial` · `complete`
- **Last verified:** commit SHA where the doc was last cross-checked against
  oracle + fixtures, or `n/a` if not yet verified.
