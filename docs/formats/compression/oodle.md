# Oodle decompression

> RAD Game Tools' Oodle Data compression suite — Epic's recommended
> backend for shipped UE titles. Paksmith detects Oodle-compressed
> entries but rejects them at decompression time; the codec is
> proprietary and non-redistributable.

## Overview

Oodle Data is a commercial compression suite licensed by RAD Game
Tools (now part of Epic Games Tools) covering several encoders:

- **Kraken** — high-ratio, mid-speed; the default for UE5 shipping.
- **Mermaid** — faster decode, lower ratio than Kraken.
- **Selkie** — faster decode than Mermaid, lower ratio.
- **Leviathan** — highest ratio, slowest decode; used for cold-load assets.
- **LZNA** — older, replaced by Kraken in newer SDKs.
- **BitKnit** — short-block variant.

On disk in a UE pak, Oodle compression is signaled by `CompressionMethod::Oodle`
(method ID `4` in v3-v7 archives; FName `"Oodle"` in the v8+
compression-method table). The per-entry compression-blocks framing
(see [`pak-block-framing.md`](pak-block-framing.md)) is identical to
zlib-compressed entries — what differs is the per-block compressed
bytes are an Oodle stream rather than a zlib stream.

**Paksmith status: `partial`.** Paksmith detects Oodle archives at
parse time (the entry's `CompressionMethod` resolves to
`CompressionMethod::Oodle`) but rejects decompression with
`PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { method: CompressionMethod::Oodle } }`.
The codec is **not bundled** with paksmith because Oodle requires a
RAD/Epic license. A future runtime-loaded shared-library integration
will let consumers who have a licensed Oodle SDK installed enable
decompression at runtime; the integration shape is sketched below
under Variants.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 4+ (UE 4.16+, sporadically; UE 4.21+ commonly; UE 5.x universally) | Oodle introduced as `CompressionMethod::Oodle` (raw method ID 4 in v3-v7; FName `"Oodle"` in v8+). | `CUE4Parse/Compression/OodleHelper.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| Oodle SDK 2.6 → 2.9 | Stream-format-compatible across SDK versions; a decoder built against SDK 2.6 reads streams compressed with SDK 2.9 and vice versa within the published-compatibility matrix. Encoder choices (Kraken vs Mermaid vs Selkie) are encoded in the stream header byte. | RAD Game Tools / Epic Games Tools "Oodle Data" documentation (no public URL — distributed with the licensed SDK). |

Within paksmith's accepted UE range, Oodle stream format itself does
not change across UE versions — UE bundles a specific Oodle SDK per
engine release, but the on-disk stream is compatible across them.

## Wire layout

Per RAD's Oodle SDK documentation; reproduced here at a high level
because the byte-level format is proprietary and Epic does not
publish it.

| offset (within block) | size | name | semantics |
|----------------------|------|------|-----------|
| 0 | 2 | `header` | Stream header. High nibble = encoder family (Kraken, Mermaid, Selkie, Leviathan). Low nibble + flags = SDK-version-dependent metadata. |
| 2 | variable | `payload` | Encoder-specific payload. Each encoder has its own internal block / chunk structure. |

The full byte layout is documented only in the licensed Oodle SDK
(specifically the `OodleNetwork2.pdf` and `OodleCore_Compression.h`
headers shipped with each SDK release). Paksmith does not reproduce
it here because:

1. Reverse-engineered byte-level documentation would distribute
   information Epic / RAD treats as proprietary.
2. paksmith does not need it — the future integration calls into
   the licensed shared library, which accepts a compressed buffer
   and writes the decompressed output; no parsing of the
   Oodle-internal layout happens on the paksmith side.

If a future paksmith needs Oodle byte-level documentation (e.g. for
a fixture-gen oracle), the right move is to cite CUE4Parse's
`Compression/OodleHelper.cs` for its loader-integration code and rely on
RAD's documentation for the format details, with no reverse-engineered
content shipped in this repo.

### Worked example

*(none yet — see Verification for the no-fixture rationale.)*

## Variants

### Encoder selection

The high nibble of the stream's first header byte selects the
encoder (Kraken, Mermaid, Selkie, Leviathan, etc.). Different UE
projects use different encoders depending on their decompression
performance budget; cooked content within one game typically picks
one encoder for all assets. The decoder dispatches on the header
byte; consumers don't need to know the encoder in advance.

### Future runtime-loaded SDK integration

When implemented, the shape paksmith expects to use:

1. **No build-time dependency.** Paksmith builds and tests run
   without the Oodle SDK; the codec is opt-in at runtime.
2. **Runtime `dlopen`/`LoadLibrary` of `liboo2corelinux64.so` /
   `oo2core_win64.dll` / `liboo2coremac64.dylib`.** The library
   path is configurable via an environment variable or a future
   `[oodle]` section in a profile config.
3. **`OodleLZ_Decompress` is the only entry point called.** Its C
   signature is `intptr_t OodleLZ_Decompress(const u8* in, intptr_t in_size, u8* out, intptr_t out_size, int fuzz_safe, int check_crc, int verbosity, void* dec_buf, intptr_t dec_buf_size, void* fp_callback, void* user_data, void* scratch, intptr_t scratch_size, int thread_phase)`.
   `fuzz_safe = 1` is required (it's the option that makes Oodle
   reject malformed streams instead of crashing).
4. **Decompression cap layering matches zlib.** The Oodle output
   buffer is bounded by the same per-block budget the zlib path
   uses; Oodle's own bounds-checking serves as a second layer.

This integration is **deferred work** — not yet in any phase plan.
A natural insertion point is a Phase 3+ task that adds support for
Oodle-compressed asset bulk-data (which is the most common
shipping-cooked-game blocker on paksmith adoption today).

## Caps & limits

No Oodle-specific caps yet. When the SDK integration lands, it will
inherit:

- The pak entry-level cap (`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`).
- The per-block budget layering described in
  [`zlib.md`](zlib.md).
- An additional `OodleLZ_Decompress` `out_size` bound that the
  Oodle library itself enforces (defense in depth).

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — Oodle non-redistributable)`. The
  detection path can be exercised with a synthetic fixture that
  declares `CompressionMethod::Oodle` and whose entry's compressed
  bytes are unreachable; the parser stops at the unsupported-
  decompression error before reading. Such a synthetic fixture is
  not currently in the test suite — adding one would surface the
  detection coverage in CI without requiring a licensed Oodle SDK.
- **Hex anchor commands:** (none yet — Oodle decompression is
  unimplemented; no fixture).
- **Cross-validation oracle:** CUE4Parse[^1] for the loader-
  integration code. The licensed Oodle SDK is the authoritative
  reference for the stream format itself.
- **Known divergences:**
  - **Decompression unimplemented.** CUE4Parse offers a `dlopen`-style
    runtime SDK load; paksmith currently rejects. Both projects
    agree on the *detection* — the FName slot reads as `"Oodle"`,
    the method byte reads as `4` — only the post-detection action
    differs.

## Paksmith implementation

**Parser module:**
`crates/paksmith-core/src/container/pak/index/compression.rs`
(`CompressionMethod::Oodle` variant) plus the rejection sites in
`crates/paksmith-core/src/container/pak/mod.rs`.

There are two rejection layers:

- **`:1006` (`stream_entry_to` early-reject)** and **`:811` (`verify_entry`)**
  — the user-facing paths. Both return
  `PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { method: CompressionMethod::Oodle } }`.
- **`:1069` (`stream_entry_to` match exhaustiveness arm)** — a dead-code
  guard that only fires if the early-reject at `:1006` is bypassed by
  a future refactor. Returns
  `PaksmithError::InvalidIndex { fault: IndexParseFault::StreamEntryToDispatchedUnsupportedCompression { method } }`.
  Operators seeing this variant should treat it as a bug, not an
  expected Oodle rejection.

**Status:** `partial`. Detection ships; decompression rejects with
`PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { method: CompressionMethod::Oodle } }`.

**Public surface:**
- `CompressionMethod::Oodle` — detection variant.
- `PakReader::read_entry(path)` returns
  `PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { .. } }` for any
  Oodle-compressed entry.

**Error variants:**
- `PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { method: CompressionMethod::Oodle } }` — current rejection.
- Future: `DecompressionFault::OodleLibraryNotFound`,
  `OodleStreamError { … }`, etc. when the SDK integration lands.

**Cap constants:** none yet.

**Phase plan:** not yet in a phase plan. A Phase 3+ insertion is the
likely path — texture / audio / mesh bulk-data work is the dominant
use case for Oodle-compressed entries.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/Compression/OodleHelper.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the loader-integration shape. Covers the `dlopen`-equivalent runtime load and the `OodleLZ_Decompress` call signature.
