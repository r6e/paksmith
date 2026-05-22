# IoStore `.utoc` (Table of Contents)

> Index file for an IoStore container — the metadata sidecar that maps
> chunk IDs to byte offsets in the `.ucas` data file.

## Overview

IoStore is Unreal Engine's replacement for `.pak`, introduced in UE 4.27
and the dominant shipped-game container format from UE 5.x onward. A single
IoStore container comprises two coupled files (always at the same path
prefix):

- **`.utoc`** — Table of Contents. Holds the chunk-ID index, container
  metadata, encryption parameters, and compression-block descriptors.
- **`.ucas`** — Container As-Stream. The bulk data file; chunk payloads
  concatenated.

A third sidecar, `.uptnl` (Optional Container Data), is also part of the
IoStore trio for patch / optional content distribution. See
[`iostore-ucas.md`](iostore-ucas.md) and [`iostore-uptnl.md`](iostore-uptnl.md).

**Status: not yet implemented in paksmith.** This doc reserves a slot in
the inventory for the Phase 8 work; full byte-level content will be
authored when the parser lands.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | Initial IoStore format (TOC v1+). Multiple TOC versions exist within UE 5's lifetime. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

To be filled in when the parser is built; UE has released several `EIoStoreTocVersion` revisions across the UE5 line.

## Wire layout

To be authored alongside the Phase 8 parser. The high-level shape per
CUE4Parse:

- Fixed `FIoStoreTocHeader` (signature `"-==--==--==--==-"`, ~144 bytes).
- Chunk-ID table (`FIoChunkId[]`).
- Per-chunk offset+length table.
- Compression-block table.
- Compression-method name table (FName-style 32-byte slots, like pak V8+).
- Optional AES-256 ECB encryption-key signature blocks.
- Optional directory-index (UE 5.x).

## Variants

To be enumerated by `EIoStoreTocVersion` once parsing lands. Known variants
include `Initial`, `DirectoryIndex`, `PartitionSize`, `PerfectHash`,
`PerfectHashWithOverflow`, `OnDemandMetaData` (most recent).

## Caps & limits

Paksmith does not yet parse `.utoc`; no caps are defined. When the parser
lands it will enforce structural caps mirroring the pak side (entry counts,
allocation sizes, compression-block table sizes). See
`docs/security/allocation-caps.md` for the project-wide cap policy.

## Verification

- **Fixture:** `(none yet — Phase 8 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 8 deliverable)`.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1]. Phase 8 will
  add a Rust IoStore oracle (`trumank/repak` has no IoStore coverage at
  time of writing).
- **Known divergences:** none yet — no implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for IoStore TOC format. Cite specific subfiles (`FIoStoreTocHeader`, `FIoChunkId`, etc.) when the per-record sections of this doc fill in.
