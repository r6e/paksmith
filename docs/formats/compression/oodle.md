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

On disk in a UE pak, Oodle compression is signaled by the FName
`"Oodle"` in the v8+ compression-method table, or in v3-v7 archives
by a value whose codec depends on the game, such as the legacy
`COMPRESS_Custom` flag `4` (see Wire layout). The per-entry
compression-blocks framing (see
[`pak-block-framing.md`](pak-block-framing.md)) is identical to
zlib-compressed entries — what differs is the per-block compressed
bytes are an Oodle stream rather than a zlib stream.

**Document status: complete (publicly-documented surface).** Wire
format documented in full for the on-pak detection layer (the
`u32` compression flags in V3-V7 archives, the `"Oodle"` FName slot in V8+
compression-method tables) and the public-knowledge stream-header
encoder-family dispatch byte. The Oodle *internal* stream layout
beyond the first header byte is RAD/Epic-proprietary and is
intentionally NOT documented here (see Wire layout §*Per-block
stream layout* for the rationale). A parser implementer can
detect Oodle-compressed V8+ entries from this doc; V3-V7 entries also
take per-game knowledge (see Wire layout §*Detection layer*).
Actually decoding the per-block payload requires the licensed Oodle
SDK.

**Paksmith parser status: `partial`.** Paksmith detects Oodle
archives at parse time (the entry's `CompressionMethod` resolves to
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
| Wire version 1-7 | An entry names Oodle only through a value whose codec depends on the game, such as the `COMPRESS_Custom` flag `4`. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/Objects/FPakEntry.cs@ecc4878950336126f125af0747190edf474b2a21`[^2] |
| Wire version 8+ | An entry names Oodle through a compression index that resolves to a footer slot named `"Oodle"`. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/Objects/FPakEntry.cs@ecc4878950336126f125af0747190edf474b2a21`[^2] (the entry's index); `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/Objects/FPakInfo.cs@ecc4878950336126f125af0747190edf474b2a21`[^4] (the slots it selects from) |
| Oodle SDK 2.6 → 2.9 | Stream-format-compatible across SDK versions; a decoder built against SDK 2.6 reads streams compressed with SDK 2.9 and vice versa within the published-compatibility matrix. Encoder choices (Kraken vs Mermaid vs Selkie) are encoded in the stream header byte. | RAD Game Tools / Epic Games Tools "Oodle Data" documentation (no public URL — distributed with the licensed SDK). |

Within paksmith's accepted UE range, Oodle stream format itself does
not change across UE versions — UE bundles a specific Oodle SDK per
engine release, but the on-disk stream is compatible across them.

## Wire layout

This section documents the bytes a paksmith-equivalent parser
*observes on disk* in a `.pak` entry header and at the start of an
Oodle stream. Two distinct wire layers:

### Detection layer — pak entry dispatch

In V3-V7 archives, each entry header holds a `u32` of UE's legacy
compression flags[^2]. `0` (`COMPRESS_None`) means no compression.
The codec flags are `1` (`COMPRESS_ZLIB`), `2` (`COMPRESS_GZIP`) and
`4` (`COMPRESS_Custom`, compression through callbacks the game
supplies). The enum's bits from `0x10` up are option and purpose
flags, such as `COMPRESS_BiasSpeed` (`0x20`) and
`COMPRESS_ForPackaging` (`0x100`), and name no codec. Oodle has no
flag of its own, so naming the codec behind `4`, or behind the other
values some games write, takes per-game knowledge. Readers map these
values differently (see Known divergences).

In V8+ archives, each entry carries an index into a table of fixed
32-byte FName-as-padded-string slots in the pak footer.
[`pak.md`](../container/pak.md) gives the slot count, index width and
index resolution per version (§*V8+ footer additions*, §*Entry header
(inline form)*, §*Entry header (encoded form, v10+)*). A slot
named `"Oodle"` (5 bytes, null-padded to 32) identifies the Oodle
codec.

| Archive era | Field | Oodle marker |
|-------------|-------|--------------|
| V3-V7 | entry header `compression_method: u32` LE | none of its own; for example `4` (`04 00 00 00`, `COMPRESS_Custom`) in a game whose custom codec is Oodle |
| V8+ | entry header compression index | an index that resolves to the footer's `"Oodle"` slot |
| V8+ | footer `compression_methods`, 32-byte slots | slot bytes `4F 6F 64 6C 65 00...00` (`"Oodle"` + 27 zero-pad) |

### Per-block stream layout (proprietary internals)

Inside each Oodle-compressed block, the on-wire stream opens with a
2-byte header whose high nibble selects the encoder family. The
remaining low-nibble bits and the rest of the per-block payload are
encoder-specific and documented only in the licensed Oodle SDK
(`oodle2.h` / `OodleLZ.h` headers shipped with each Oodle Data SDK
release).

| offset (within block) | size | name | semantics |
|----------------------|------|------|-----------|
| 0 | 2 | `header` | Stream header. High nibble = encoder family (Kraken, Mermaid, Selkie, Leviathan). Low nibble + flags = SDK-version-dependent metadata. |
| 2 | variable | `payload` | Encoder-specific payload. Each encoder has its own internal block / chunk structure (proprietary). |

Paksmith does not reproduce the per-encoder byte layout because:

1. Reverse-engineered byte-level documentation would distribute
   information Epic / RAD treats as proprietary.
2. paksmith does not need it — the future integration calls into
   the licensed shared library, which accepts a compressed buffer
   and writes the decompressed output; no parsing of the
   Oodle-internal layout happens on the paksmith side.

A future paksmith Oodle implementation depending on byte-level
documentation should cite CUE4Parse's `Compression/OodleHelper.cs`
for its loader-integration code and rely on RAD's documentation for
the format details, with no reverse-engineered content shipped in
this repo.

### Worked example — V3-V7 entry dispatch (4 bytes)

The `compression_method: u32` LE field in a V3-V7 entry header of a
game whose custom codec is Oodle, set to dispatch to it:

```
Offset (within entry header)  Bytes (LE)        Field
----------------------------  ---------------   --------------------
+<header offset>              04 00 00 00       compression_method = 4 (COMPRESS_Custom)
```

For such a game, a parser fed these 4 bytes at the matching
entry-header offset MUST identify the entry as Oodle-compressed and
dispatch to the Oodle decoder (or, if Oodle is unsupported, surface
a typed "Oodle unsupported" error before any decompression attempt).

### Worked example — V8+ compression-method-table slot (32 bytes)

The footer slot holding `"Oodle"` looks like:

```
Offset (within slot)  Bytes (LE)                                       Field
--------------------  -----------------------------------------------  -----------------
+0                    4F 6F 64 6C 65                                   "Oodle" (5 bytes UTF-8)
+5                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  zero-pad (27 bytes)
+21                   00 00 00 00 00 00 00 00 00 00 00
+32                                                                     (end of slot)
```

A parser fed an entry whose compression index resolves to this slot
MUST identify it as Oodle-compressed and dispatch it to the Oodle
decoder (or, if Oodle is unsupported, surface a typed "Oodle
unsupported" error before any decompression attempt). An unused slot
is 32 zero bytes.

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

### Format-defined limits (wire-imposed)

- **V3-V7 `compression_method`:** `u32` field; the full `0..=u32::MAX`
  range is wire-valid. Its values are UE's legacy compression flags
  (see Wire layout §*Detection layer*).
- **V8+ compression-method table:** fixed 32-byte slots, as many as
  [`pak.md`](../container/pak.md) gives per version.
- **Per-block Oodle stream header:** 2 bytes; high nibble selects
  the encoder family per the proprietary spec.

The wire format does NOT cap the per-block Oodle stream payload
length beyond what the pak-block-framing layer publishes (see
[`pak-block-framing.md`](pak-block-framing.md)).

### Implementation hardening (recommended for any parser)

When SDK integration lands, an Oodle decompressor MUST:

- **Inherit the pak entry-level cap** (`MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`)
  on the final decompressed output.
- **Inherit per-block budgets** from the pak-block framing layer
  (see [`pak-block-framing.md`](pak-block-framing.md)).
- **Pass `fuzz_safe = 1` to `OodleLZ_Decompress`** so the Oodle
  library itself rejects malformed streams rather than crashing.
- **Pass an explicit `out_size` bound** to `OodleLZ_Decompress`;
  the library enforces this as a defense-in-depth layer on top of
  the pak-block cap.

Independent of the SDK, a pak parser MUST NOT read a V8+ entry as Oodle
unless its compression index resolves to a slot named `"Oodle"`. It
MUST report a nonzero V8+ index that reaches no codec as an error, not
as uncompressed bytes, and the same for a nonzero V3-V7 value it cannot
map to a codec. When it maps a nonzero V3-V7 value to a codec without
knowing which codec the game uses for that value, it MUST report the
entry as an error, not as uncompressed bytes, if it does not support
that codec or the codec fails to decode the entry.
[`pak.md`](../container/pak.md) §*V8+ footer additions* covers how an
index resolves.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The two Worked examples above (V3-V7 `04 00 00 00`
  `COMPRESS_Custom` dispatch + V8+ 32-byte `"Oodle"` table slot) are
  byte-exact, and both can be synthesized end-to-end without a
  licensed Oodle SDK; the V3-V7 one identifies Oodle only with
  per-game knowledge. A
  decompression-end fixture would require either a licensed Oodle
  SDK in the test environment or a Kraken/Mermaid/etc. encoder; both
  are deferred until the runtime-loaded SDK integration lands.
- **Hex anchor commands:**
  ```
  # Synthesize the V3-V7 entry-header compression_method = 4 (COMPRESS_Custom) field:
  printf '\x04\x00\x00\x00' | xxd
  # Synthesize the V8+ 32-byte compression-method-table slot holding "Oodle":
  printf 'Oodle\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | xxd
  ```
  A conformant pak parser fed these bytes at the matching offsets
  MUST dispatch them as the Worked examples above require.
- **Cross-validation oracle:** CUE4Parse[^1] for the loader-
  integration code; CUE4Parse[^2] and repak[^3] for the V3-V7 values;
  CUE4Parse[^4] and [`pak.md`](../container/pak.md) for the V8+
  compression-method table. The licensed Oodle SDK is the
  authoritative reference for the per-block stream layout itself.
- **Known divergences:**
  - **Decompression unimplemented.** CUE4Parse offers a `dlopen`-style
    runtime SDK load; paksmith currently rejects.
  - **V3-V7 compression values.** All three read `0` as no
    compression. Paksmith matches any other value exactly: `1` is
    zlib, `2` gzip, `4` Oodle, and anything else an unknown method.
    repak[^3] maps a nonzero `N` to `[Zlib, Gzip, Oodle][N - 1]`,
    unchecked. CUE4Parse[^2] has special cases for some values and
    games (in Sea of Thieves, for one, `4` is LZ4); otherwise it tests
    the zlib, gzip and custom bits in that order, maps custom to Oodle,
    and reads a nonzero value with none of them as an unknown method.
    So, in a game CUE4Parse has no special case for, `4` is Oodle to
    paksmith and CUE4Parse, while repak panics when it extracts the
    entry's data; `3` is an unknown method to paksmith, zlib to
    CUE4Parse and Oodle to repak.

## Paksmith implementation

**Parser module:**
`crates/paksmith-core/src/container/pak/index/compression.rs`
(`CompressionMethod::Oodle` variant) plus the rejection sites in
`crates/paksmith-core/src/container/pak/mod.rs`.

There are two rejection layers:

- **`:1020` (`stream_entry_to` early-reject)** and **`:824` (`verify_entry`)**
  — the user-facing paths. Both return
  `PaksmithError::Decompression { path, offset, fault: DecompressionFault::UnsupportedMethod { method: CompressionMethod::Oodle } }`.
- **`:1074` (`stream_entry_to` match exhaustiveness arm)** — a dead-code
  guard that only fires if the early-reject at `:1020` is bypassed by
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
[^2]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/Objects/FPakEntry.cs@ecc4878950336126f125af0747190edf474b2a21` — the pre-V8 switch from a compression value to an index, and the V8+ reads of an entry's index (a `u8` in V8A, an `int` from V8B, 6 bits in an encoded entry), into the method list `CUE4Parse/UE4/Pak/Objects/FPakInfo.cs` builds. `CUE4Parse/UE4/Objects/Core/Misc/ECompressionFlags.cs` at the same revision gives the flag values.
[^3]: `trumank/repak/repak/src/footer.rs@355b5f62f51959c7cc6dd5a51708646ef483065d` — `Footer::read` builds the pre-V8 `[Zlib, Gzip, Oodle]` list. At the same revision, `repak/src/entry.rs` decodes `N` as `N - 1` in `Entry::read` and indexes the list in `Entry::read_file`.
[^4]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Pak/Objects/FPakInfo.cs@ecc4878950336126f125af0747190edf474b2a21` — builds the compression-method list: a fixed one before V8; from V8, no-method followed by the footer's named slots.
