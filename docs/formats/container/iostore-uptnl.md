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

**Status: not yet implemented in paksmith.** Phase 8 deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field; the `.utoc` determines whether a `.uptnl` is expected and where each optional chunk lives within it. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

## Wire layout

Identical to `.ucas` (see [`iostore-ucas.md`](iostore-ucas.md)) — an
unstructured byte stream of chunk payloads with bounds and per-chunk
compression/encryption parameters all published by the matching `.utoc`.

The semantic difference (optional vs primary) is encoded entirely in the
`.utoc`, not in the `.uptnl` byte stream.

## Variants

None on the wire.

## Caps & limits

Paksmith does not yet parse `.uptnl`; caps will be defined alongside the
Phase 8 parser. Same considerations as `.ucas`.

## Verification

- **Fixture:** `(none yet — Phase 8 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 8 deliverable)`.
- **Cross-validation oracle:** CUE4Parse's `IoStoreReader`[^1].
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under `crates/paksmith-core/src/container/iostore/`)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore Support).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `.uptnl` path is opened alongside `.utoc` + `.ucas` in `IoStoreReader.Initialize`.
