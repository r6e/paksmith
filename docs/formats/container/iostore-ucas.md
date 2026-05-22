# IoStore `.ucas` (Container As-Stream)

> Bulk-data file for an IoStore container — chunk payloads concatenated,
> referenced by offset+length pairs in the matching `.utoc`.

## Overview

`.ucas` ("Container As-Stream") holds the actual data payloads of an
IoStore container. It is purely a byte stream — no header, no per-chunk
metadata. All structure lives in the paired `.utoc` file
([`iostore-utoc.md`](iostore-utoc.md)), which publishes `(chunk_id → offset, length, compression-block-list)`
mappings into this file.

Compression and AES-256 ECB encryption are applied at the
compression-block granularity, the same way `.pak` does it, with parameters
(block size, method, key) all carried in the `.utoc`.

**Status: not yet implemented in paksmith.** Phase 8 deliverable.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.27+ | No on-stream version field — `.ucas` is unstructured bytes. All version-conditional shape lives in `.utoc`. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | filesize | — | `chunks` | byte stream | Concatenation of chunk payloads. Each chunk's bounds are published by the matching `.utoc`. |

A chunk payload is one or more compression blocks (per the `.utoc`'s
block table). When the chunk is uncompressed, the payload is the raw
chunk bytes; when compressed, it is the concatenated compressed blocks,
each readable as a single decompress call against the method named in the
`.utoc`'s compression-method table.

When encryption is enabled (per the `.utoc`'s `bIsEncrypted` flag), the
encryption is applied at the compression-block granularity in AES-256 ECB
mode — same as pak's per-entry encryption.

## Variants

None on the wire. All variance lives in `.utoc`.

## Caps & limits

Paksmith does not yet parse `.ucas`; caps will be defined alongside the
Phase 8 parser. The pak-side `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB` cap is
the obvious analog for per-chunk decompression bounds.

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

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. The `.ucas` reading happens inline with `.utoc` chunk lookup in this file's `ReadAsync`.
