# IoStore `.uptnl` (Optional Container Data)

> Optional-payload sidecar for an IoStore container — chunk data that
> ships separately from the primary `.ucas`, typically for patches,
> language packs, or DLC.

## Overview

`.uptnl` is the third file in the IoStore trio (`.utoc` + `.ucas` +
optional `.uptnl`). It holds chunk payloads that the shipping container
references but doesn't ship inline — used for content the engine treats as
loadable-on-demand: optional language assets, day-one patches, DLC
overlays.

Structurally `.uptnl` is identical to `.ucas`: an unstructured byte stream
of chunk payloads. The matching `.utoc` is the only file that distinguishes
which chunks live in `.ucas` vs `.uptnl`, via a per-chunk
`EIoContainerFlags::Optional` flag (or a similar bit on the chunk record,
depending on TOC version).

**Document status: complete.** The `.uptnl` file is structurally
identical to `.ucas` ([`iostore-ucas.md`](iostore-ucas.md)): a flat
byte stream of chunk payloads with no internal structure. This doc
documents the structural identity, the per-chunk `ChunkType`
discriminant that selects `.uptnl` over `.ucas`, and the optional
nature of the file itself.

**Paksmith parser status: `not impl`.** Phase 8 deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field; the `.utoc` determines whether a `.uptnl` is expected and where each optional chunk lives within it. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

## Wire layout

Identical to `.ucas` (see [`iostore-ucas.md`](iostore-ucas.md)
§*Wire layout* for the full byte-stream description, partitioned
layout, and per-chunk decode chain) — `.uptnl` is an unstructured
byte stream of chunk payloads with bounds and per-block
compression/encryption parameters all published by the matching
`.utoc`.

### Chunk-type dispatch (`.ucas` vs `.uptnl`)

The semantic difference between `.ucas` and `.uptnl` chunks is
encoded in the matching `.utoc`'s `FIoChunkId.ChunkType` field (see
[`iostore-utoc.md`](iostore-utoc.md) §*Chunk-ID array*). A reader
selects between the two source files by inspecting the chunk's
type:

| UE major version | `ChunkType` value | Enum name | Source file |
|------------------|-------------------|-----------|-------------|
| UE4 | `3` | `BulkData` | `.ucas` |
| UE4 | `4` | `OptionalBulkData` | **`.uptnl`** |
| UE5 | `2` | `BulkData` | `.ucas` |
| UE5 | `3` | `OptionalBulkData` | **`.uptnl`** |

All other chunk types (`ExportBundleData`, `ContainerHeader`,
`MemoryMappedBulkData`, etc.) source from `.ucas`. The `.uptnl`
file is therefore optional on disk — an IoStore container with no
`OptionalBulkData` chunks ships only `.utoc` + `.ucas`.

The `OptionalBulkData` chunks themselves use the same
`FIoStoreTocCompressedBlockEntry` records (with `block.Offset`
interpreted as an offset into `.uptnl` instead of `.ucas`); a
reader only needs the type-dispatch step at the top of the read
path.

### Worked example

See [`iostore-ucas.md`](iostore-ucas.md) §*Worked example* —
substitute `.uptnl` for `.ucas` and use a `ChunkType` value of
`4` (UE4) or `3` (UE5) on the matching `FIoChunkId`. The
byte-level decode path is identical.

## Variants

None on the wire. The `.uptnl` file is structurally indistinguishable
from `.ucas`; the only variant is "this file exists" (when at least
one `OptionalBulkData` chunk is present) vs "this file is absent"
(when no optional chunks are declared in the `.utoc`).

## Caps & limits

### Format-defined limits (wire-imposed)

- **Identical to `.ucas`** — see
  [`iostore-ucas.md`](iostore-ucas.md) §*Caps & limits* /
  *Format-defined limits*. No file-level caps; per-block / per-chunk
  bounds come from the matching `.utoc`.

### Implementation hardening (recommended for any parser)

- **Identical to `.ucas`** — see
  [`iostore-ucas.md`](iostore-ucas.md) §*Implementation hardening*.
  All caps and arithmetic-safety requirements apply unchanged.
- **Dispatch validation**: a reader MUST route only
  `OptionalBulkData`-typed chunks to `.uptnl`; routing any other
  `ChunkType` to `.uptnl` indicates a malformed `.utoc` and SHOULD
  be rejected.
- **Missing-file handling**: a `.utoc` that declares
  `OptionalBulkData` chunks without a corresponding `.uptnl` file
  on disk is malformed; the reader SHOULD surface a typed error
  (`MissingCompanionFile { kind: Uptnl }` or similar) rather than
  silently treating those chunks as zero-length.

## Verification

- **Fixture:** No standalone fixture — the format is identical to
  `.ucas` (see that doc's Worked example). A real-cooked
  `.uptnl` + `.utoc` pair for end-to-end cross-validation is a
  Phase 8 deliverable.
- **Hex anchor commands:** None needed — same hex anchors as
  `.ucas` apply (substitute `.uptnl` as the source file).
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1].
  The `.uptnl` path is opened alongside `.utoc` + `.ucas` in
  `IoStoreReader.Initialize`; the file is treated as a sibling
  byte source with no separate parser.
- **Known divergences:** none — no paksmith implementation to
  diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `.uptnl` path is opened alongside `.utoc` + `.ucas` in `IoStoreReader.Initialize`.
