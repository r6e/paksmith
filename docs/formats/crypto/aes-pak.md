# AES-256 pak encryption

> Unreal Engine's pak encryption scheme — AES-256 in ECB mode applied
> at two granularities (whole index region; per-entry payload).
> Paksmith detects encryption metadata at every layer but does not
> decrypt: encrypted archives are rejected at open time, encrypted
> entries skip integrity verification.

## Overview

UE optionally encrypts pak archive content with AES-256 in **ECB mode**
(no IV, no chaining). Encryption can be applied at two granularities:

- **Index encryption** (V4+, gated by the footer's `encrypted` byte
  (present V4+; paksmith reads it only in V7+ archives because the
  V1–V6 legacy footer probe is 44 bytes)): the whole index region
  (the bytes between
  `index_offset` and `index_offset + index_size`) is ciphertext. The
  reader must decrypt before parsing entry records.
- **Per-entry encryption** (V3+, gated by each entry's `encrypted`
  byte in its header): an individual entry's payload is ciphertext.
  The reader decrypts the full compressed payload (16-byte-aligned)
  then decompresses by block — decryption precedes decompression.
  See [`../compression/pak-block-framing.md`](../compression/pak-block-framing.md)
  for the block-framing layout.

Both surfaces share the same key. Key distribution is out-of-band:
UE writes the key into a `Crypto.json` file (UE 4.20+) or supplies it
via UnrealPak command-line; consumers must somehow obtain it.

**Document status: complete.** Wire format documented in full for
the encryption metadata surface — footer encryption byte, V7+ key
GUID, per-entry encryption flag (both V3-V9 flat form and V10+
bit-22 encoded form), `Crypto.json` key-file shape (both hex and
base64 conventions), and AES-256 ECB block-cipher parameters. The
encrypted payload bytes themselves are ciphertext until decrypted;
ciphertext content is not a format property and is therefore
outside this doc's scope.

**Paksmith parser status: `partial`.** Detection of every
encryption metadata surface is complete; decryption is unimplemented.
paksmith rejects whole-archive-encrypted archives at `from_reader`
time with `PaksmithError::Decryption`, and skips per-entry-encrypted
entries during verification (`VerifyOutcome::SkippedEncrypted`). Key
management is gated by the Phase 5 profile-system work.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3 (UE 4.4) | Per-entry encryption introduced. Encryption signaled by the entry header's `encrypted` byte; no index encryption yet. | `trumank/repak/repak/src/entry.rs@355b5f62f51959c7cc6dd5a51708646ef483065d`[^1] |
| Wire version 4 (UE 4.16, `IndexEncryption`) | Index encryption introduced. The whole index region is AES-encrypted when the writer enables it; reader must decrypt before parsing entries. The footer gains a 1-byte `encrypted` field. (paksmith does not currently read this byte for V4-V6 archives — see Wire layout §Footer fields for the gap.) | Same[^1] |
| Wire version 7 (UE 4.22, `EncryptionKeyGuid`) | 16-byte `encryption_key_guid` field added to the footer. Identifies which key the archive uses when a project ships multiple. Zero GUID = no specific key assigned. | Same[^1] |

The AES-256 ECB primitive itself has been stable across the whole
wire-version range; the variance is in *what* is encrypted (per-entry
only → index → keyed) and *how* the consumer locates the key.

## Wire layout

This doc covers the encryption *metadata* on the wire. The encrypted
content itself is opaque to paksmith.

### Footer fields (V7+ layout)

Offsets below are for the V7+ footer shape. V4-V6 have a different
layout — the encrypted byte sits at the very start of the footer with
no preceding `encryption_key_guid` (see *V4-V6 gap* paragraph below).

| offset (in footer) | size | endian | name | type | semantics |
|--------------------|------|--------|------|------|-----------|
| 0 | 16 | — | `encryption_key_guid` | `[u8; 16]` | (V7+ only.) Identifies the key used to encrypt this archive's index / entries. Zero-filled when no specific key is assigned. The 4-u32 partition matches `FGuid`'s convention (see [`../primitive/fguid.md`](../primitive/fguid.md)). |
| 16 | 1 | — | `encrypted` | `u8` | (V7+; V4-V6 also have this byte but at footer offset 0.) `1` = the index region is AES-encrypted; `0` = the index is plaintext. |

Wire versions 4–6 also include a 1-byte `encrypted` field in the
footer (introduced with `IndexEncryption` in V4) but paksmith's
legacy footer parser (`read_legacy`) covers V1–V6 and always sets
`encrypted = false`. The root cause is architectural: paksmith's
legacy probe window is `FOOTER_SIZE_LEGACY = 44` bytes, beginning at
`EOF - 44`. On V4–V6 archives, the wire layout is
`encrypted(1) + magic(4) + version(4) + index_offset(8) + index_size(8) + hash(20) = 45 bytes`;
the encrypted byte sits at `EOF - 45`, one byte before the probe
window begins. The probe lands on the magic byte and never reads the
preceding encrypted flag — `read_legacy` therefore hardcodes
`encrypted = false`. Any V4–V6 archive with index encryption is
therefore treated as plaintext by paksmith (no decryption, potentially
corrupt index parse). This is a known gap; V4–V6 encrypted archives
are rare in practice. V7+ footers carry both the 16-byte GUID and the
encrypted byte, and paksmith reads both correctly.

### Per-entry encryption flag

For each pak entry (in both V3–V9 flat-form headers and V10+
encoded-form headers — see [`../container/pak.md`](../container/pak.md)):

| field | encoding | semantics |
|-------|----------|-----------|
| `encrypted` (V3–V9 flat form) | `u8` after the compression-blocks array | `1` = entry payload is AES-encrypted. |
| `encrypted` (V10+ encoded form) | bit 22 of the encoding's packed `bits` u32 (per `entry_header.rs:367`) | Same semantics; bit-packed. |

### `Crypto.json` (UE 4.20+ key-file format)

UE's UnrealPak commandlet writes a `Crypto.json` sidecar describing
the keys used to encrypt a cooked build. Out of scope for paksmith
today, but the shape per community loaders (CUE4Parse[^2]):

```json
{
  "EncryptionKey": {
    "Name": "Embedded",
    "Guid": "00000000000000000000000000000000",
    "Key": "0x1122334455667788990011223344556677889900112233445566778899001122"
  },
  "SecondaryEncryptionKeys": [
    {
      "Name": "DLC-Pack-A",
      "Guid": "1234567890ABCDEF1234567890ABCDEF",
      "Key": "0x1122334455667788990011223344556677889900112233445566778899001122"
    }
  ]
}
```

The encoding of the `Key` field is writer-dependent:

- **CUE4Parse / UnrealPak convention (hex):** `"Key": "0x<64-hex-digits>"` —
  66 characters total; the `0x` prefix is required by `FAesKey`'s parser.
  Example: `"0x1122334455667788990011223344556677889900112233445566778899001122"`.
- **repak / community convention (base64):** `"Key": "<44-base64-chars>"` —
  no `0x` prefix; 44 characters ending in `=`.
  Example: `"ESIzRFVmd4iZABEiM0RVZneImQARIjNEVWZ3iJkAESI="`.

Both encode the same 32-byte (256-bit) AES key; the prefix (or its absence)
tells the consumer which encoding to use. The `Guid` field matches the pak
footer's `encryption_key_guid`: when paksmith adds key support, the lookup
flow will be "footer GUID → `Crypto.json` entry → 32-byte key".

### Block-cipher details

| field | value | source |
|-------|-------|--------|
| Algorithm | AES | NIST FIPS 197 |
| Key size | 256 bits (32 bytes) | UE-fixed |
| Mode | ECB (Electronic Codebook) | UE-fixed |
| Block size | 128 bits (16 bytes) | AES-fixed |
| Padding | None — UE aligns encrypted regions to 16-byte boundaries at write time | UE-fixed |

The choice of ECB is **cryptographically questionable** for any
real-world content — it leaks block-equality patterns and provides
no diffusion across blocks. Epic's choice prioritizes simple
indexable random-access decryption (no IV state to track per block)
over modern AEAD practice. paksmith does not opine; the docs
describe what UE does, not what UE *should* do.

CUE4Parse's `Aes.cs`[^2] confirms: `Mode = CipherMode.ECB`,
`Padding = PaddingMode.None`, IV = `null`.

### Worked example — V7+ footer encryption fragment (17 bytes)

The V7+ footer's encryption metadata is fully contained in the
17-byte run `encryption_key_guid (16) + encrypted (1)`. A footer
with a zero-GUID (no specific key) and the index-encryption flag
set:

```
Offset (within footer)  Bytes (LE)                                       Field
----------------------  -----------------------------------------------  -------------------------
+0                      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  encryption_key_guid = zero (16 bytes; "no specific key")
+16                     01                                                encrypted = 1 (index region AES-encrypted)
+17                                                                       (continues into the rest of the V7+ footer — magic, version, etc.)
```

A footer with a non-zero key GUID (the "this archive uses key
GUID `12345678-90AB-CDEF-1234-567890ABCDEF`" case) carries the GUID
in the four-`u32`-LE convention used by [`../primitive/fguid.md`](../primitive/fguid.md).
Per that doc's `Display` formula `{A:08x}-{B>>16:04x}-{B&0xFFFF:04x}-{C>>16:04x}-{C&0xFFFF:04x}{D:08x}`,
the four `u32` LE-wire components are
`A = 0x12345678`, `B = 0x90ABCDEF`, `C = 0x12345678`, `D = 0x90ABCDEF`:

```
Offset (within footer)  Bytes (LE)                                       Field
----------------------  -----------------------------------------------  -------------------------
+0                      78 56 34 12 EF CD AB 90 78 56 34 12 EF CD AB 90  encryption_key_guid = {12345678-90AB-CDEF-1234-567890ABCDEF}
                        ↑─── A LE ──↑↑─── B LE ──↑↑─── C LE ──↑↑─── D LE ──↑
+16                     01                                                encrypted = 1
```

### Worked example — V3-V9 per-entry encrypted flag

For a V3-V9 flat-form entry, the `encrypted` field is a single `u8`
that appears at a fixed position in the entry header per
[`../container/pak.md`](../container/pak.md) §*Flat-form entry header*.
A value of `01` marks the payload encrypted; per the same pak.md
section, the next field on the wire is `compression_block_size: u32`
(4 bytes LE), NOT the compression-method field (which lives much
earlier in the header, before the SHA1 hash). A 6-byte fragment
showing the encrypted-byte position and its trailing
`compression_block_size`:

```
... compression-blocks array ...
01                    encrypted = 1 (payload is AES-encrypted)
00 00 01 00           compression_block_size = 0x00010000 = 65536 (u32 LE)
```

For a V10+ encoded-form entry, the same encrypted flag is bit 22 of
the packed `bits: u32`. With `bits = 0x00400000` (just the
encrypted bit), the LE wire bytes are `00 00 40 00`. With
`bits = 0x01C00000` (encrypted bit 22 + compression method index 3
in bits 23-28 per `entry_header.rs` `(bits >> 23) & 0x3f`), the LE
wire bytes are `00 00 C0 01`.

### Generating a fixture

Generating a runnable encrypted fixture would require either:

1. **Synthetic encrypted fixture with a published test-only key**, which
   the test suite would carry in source. This is the natural shape for
   adding end-to-end decryption coverage when paksmith implements AES.
2. **A real cooked encrypted pak**, which would expose a production
   AES key in the repo. Out of bounds.

The detection codepath can be exercised today with a synthetic fixture
that sets the footer's `encrypted` byte to `1` and leaves the index
plaintext — paksmith stops at `PaksmithError::Decryption` before
trying to read the index, so the fixture doesn't actually have to be
encrypted to test the detection.

## Variants

### Index-encrypted vs entry-encrypted vs both

Four wire-possible combinations (per the Wire layout footer and
per-entry flag tables above):

- **Plaintext** — `footer.encrypted == 0` and no entry has `encrypted == 1`.
- **Per-entry-only** — `footer.encrypted == 0`; one or more entries have `encrypted == 1`. Index is plaintext; individual payloads are ciphertext.
- **Index-only** — `footer.encrypted == 1`; no entry has `encrypted == 1`. Wire-possible but operationally moot for paksmith: the archive is rejected at `from_reader` before any entry is inspected.
- **Whole-archive** — `footer.encrypted == 1` and entries have `encrypted == 1`. Both index and payloads are ciphertext.

See Paksmith implementation for the precise rejection points per combination.

### Encryption-key-GUID dispatch (V7+)

Cooked games sometimes ship multiple keys (DLC pack X uses key 1,
DLC pack Y uses key 2). The footer's GUID identifies which key was
used. With key support, the reader flow becomes:

1. Read footer → get GUID.
2. Look up GUID in the key registry (loaded from `Crypto.json` or
   equivalent).
3. Use the matched 32-byte key to decrypt.

paksmith stores the GUID via `PakFooter::encryption_key_guid()` but
doesn't yet act on it.

## Caps & limits

### Format-defined limits (wire-imposed)

- **Footer `encrypted` byte:** `u8`. Values `0` and `1` are the only
  semantically meaningful values; other values are wire-valid but
  undefined. The byte itself has no overflow surface.
- **Footer `encryption_key_guid`:** fixed `[u8; 16]` — no length to
  bound.
- **Per-entry `encrypted` flag (V3-V9 flat form):** `u8`.
- **Per-entry `encrypted` flag (V10+ encoded form):** 1 bit (bit 22
  of the `bits: u32` field per
  [`../container/pak.md`](../container/pak.md)).
- **AES-256 block size:** 16 bytes (128 bits, AES-fixed per NIST FIPS 197).
- **AES-256 key length:** 32 bytes (256 bits, UE-fixed).
- **Encrypted region alignment:** UE writers pad encrypted regions
  to the 16-byte AES block boundary at write time; the wire format
  is therefore always block-aligned at AES boundaries (no
  reader-side padding logic needed).

### Implementation hardening (recommended for any parser)

A reader that performs AES decryption (paksmith does not yet) MUST:

- **Cap the index-region size** before allocation. paksmith already
  enforces this via `max_index_bytes()` for the plaintext path; the
  decryption step inherits the same cap, ensuring an attacker-
  influenced footer cannot drive a giant pre-decrypt allocation.
- **Cap the per-entry payload size** by `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`
  and per-block budgets (per
  [`../compression/pak-block-framing.md`](../compression/pak-block-framing.md)).
- **Reject mis-aligned encrypted regions** (sizes not divisible by
  16). A 16-byte misalignment indicates either corruption or a
  malformed writer; a reader that pads-on-read silently masks the
  defect.
- **Validate AES key length** at parse time, not at decrypt time.
  A `Crypto.json` key of any length other than 32 bytes (after
  hex / base64 decode) is invalid; reject with a typed error before
  attempting decryption.
- **Cap the key registry** when key support lands (number of loaded
  keys, total bytes per `Crypto.json`) to bound memory from a
  malicious key file.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** `(none yet — see issue #347)` — paksmith does not ship
  encrypted pak fixtures. See the Wire layout's worked-example section
  for why.
- **Cross-validation oracle:** repak[^1] (paksmith's primary pak
  oracle; covers the per-entry-flag and footer-flag detection
  identically) and CUE4Parse[^2] (for the block-cipher specifics
  and the `Crypto.json` key-file format).
- **Known divergences:**
  - **Decryption unimplemented.** repak and CUE4Parse both decrypt
    given a key; paksmith rejects. Both projects agree on what bytes
    constitute the *metadata* on disk.
  - **No key management.** paksmith has no Crypto.json loader, no
    config surface for paste-a-hex-key, no profile-system integration.
    Key support is gated by the Phase 5 profile-system work.
  - **V4–V6 index encryption gap.** Paksmith treats any V4–V6 archive as plaintext — see Wire layout §*Footer fields* for the root cause (`FOOTER_SIZE_LEGACY = 44` probe window excludes the `encrypted` byte). repak reads it; we don't.

## Paksmith implementation

Paksmith rejects whole-archive-encrypted archives at `from_reader` time
(footer.is_encrypted() guard at `mod.rs:247`); per-entry-only archives
open successfully and rejection occurs at extraction time via
`stream_entry_to` at `mod.rs:1003`. `verify_entry` skips encrypted
entries silently (`Ok(VerifyOutcome::SkippedEncrypted)` at
`mod.rs:685`).

**Parser modules:**
- `crates/paksmith-core/src/container/pak/footer.rs` — `PakFooter::encryption_key_guid`,
  `PakFooter::is_encrypted`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` —
  per-entry `is_encrypted` field, in both flat-form (V3–V9) and
  encoded-form (V10+, bit 22) readers.
- `crates/paksmith-core/src/container/pak/mod.rs:247` —
  `PakReader::from_reader` rejection point.
- `crates/paksmith-core/src/container/pak/mod.rs:685` —
  `verify_entry` skip-encrypted path; emits `VerifyOutcome::SkippedEncrypted`.

**Status:** `partial`. Detection of every encryption metadata surface
is complete; decryption is unimplemented. Encrypted archives raise
`PaksmithError::Decryption`; encrypted entries skip verification
(`VerifyOutcome::SkippedEncrypted`).

**Public surface:**
- `PakFooter::encryption_key_guid() -> Option<&[u8; 16]>` — Some for
  V7+ archives, None for legacy.
- `PakFooter::is_encrypted() -> bool` — index-encryption flag. Returns true only for V7+ archives where the writer set the bit; always returns false for V1-V3 (no field on wire) and V4-V6 (parser gap; see Wire layout §Footer fields).
- `PakEntryHeader::is_encrypted() -> bool` — per-entry flag.
- `PakReader::open()` / `from_reader()` returns
  `PaksmithError::Decryption { path: Option<String> }` for any
  `footer.is_encrypted() == true` archive.
- `PakReader::verify_entry(path)` skips encrypted entries with
  `VerifyOutcome::SkippedEncrypted` (countered separately in
  `IntegrityStats::entries_skipped_encrypted()`).
- `PakReader::stream_entry_to(entry: &PakIndexEntry, writer: &mut dyn Write)` returns
  `PaksmithError::Decryption { path }` at `mod.rs:1003` when the
  requested entry's `is_encrypted()` flag is set. This is the runtime
  extraction path: `from_reader` rejects whole-archive-encrypted at
  open time; `stream_entry_to` rejects per-entry-encrypted at
  extraction time.

**Error variants:**
- `PaksmithError::Decryption { path: Option<String> }` — the only
  decryption-related variant today. Path is `Some` when opening by
  path; `None` from `from_reader`.
- Future: `DecryptionFault::InvalidKey { … }`,
  `DecryptionFault::KeyNotFound { guid }`,
  `DecryptionFault::BadKeyLength { … }` etc. when AES decryption
  lands.

**Cap constants:** none specific to encryption.

**Phase plan:**
- Detection (current): `docs/plans/phase-1-foundation.md` (shipped as part of pak footer + entry-header parsing).
- AES decryption + key management: not yet in a phase plan. Phase 5 (game profiles) is the natural insertion point — the profile system will own the key registry.

## References

[^1]: `trumank/repak/repak/src/entry.rs@355b5f62f51959c7cc6dd5a51708646ef483065d` plus `repak/src/lib.rs` — primary oracle for the on-wire encryption metadata. paksmith's detection paths mirror repak's exactly.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/Encryption/Aes/Aes.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — secondary oracle for the AES-256 ECB block-cipher specifics (confirms ECB mode, no padding, no IV, 16-byte block size). `FabianFG/CUE4Parse/CUE4Parse/Encryption/Aes/FAesKey.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — key-wrapping type; implements the `0x`-prefixed hex-string parser and 32-byte validation cited in the `Crypto.json` §Key field encoding. NIST FIPS 197 is the upstream reference for AES itself; not cited inline as it is external to UE.
