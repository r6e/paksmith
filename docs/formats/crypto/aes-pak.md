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
paksmith does not yet model key handling — it detects the encrypted
state, rejects with a typed error, and leaves the key-management
question to a future profile-system phase (likely Phase 5).

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3 (UE 4.4) | Per-entry encryption introduced. Encryption signaled by the entry header's `encrypted` byte; no index encryption yet. | `trumank/repak/repak/src/entry.rs@355b5f62f51959c7cc6dd5a51708646ef483065d`[^1] |
| Wire version 4 (UE 4.16, `IndexEncryption`) | Index encryption introduced. The whole index region is AES-encrypted when the writer enables it; reader must decrypt before parsing entries. The footer gains a 1-byte `encrypted` field. | Same[^1] |
| Wire version 7 (UE 4.22, `EncryptionKeyGuid`) | 16-byte `encryption_key_guid` field added to the footer. Identifies which key the archive uses when a project ships multiple. Zero GUID = no specific key assigned. | Same[^1] |

The AES-256 ECB primitive itself has been stable across the whole
wire-version range; the variance is in *what* is encrypted (per-entry
only → index → keyed) and *how* the consumer locates the key.

## Wire layout

This doc covers the encryption *metadata* on the wire. The encrypted
content itself is opaque to paksmith.

### Footer fields (V7+)

| offset (in footer) | size | endian | name | type | semantics |
|--------------------|------|--------|------|------|-----------|
| 0 | 16 | — | `encryption_key_guid` | `[u8; 16]` | Identifies the key used to encrypt this archive's index / entries. Zero-filled when no specific key is assigned. The 4-u32 partition matches `FGuid`'s convention (see [`../primitive/fguid.md`](../primitive/fguid.md)). |
| 16 | 1 | — | `encrypted` | `u8` | `1` = the index region is AES-encrypted; `0` = the index is plaintext. |

Wire versions 4–6 also include a 1-byte `encrypted` field in the
footer (introduced with `IndexEncryption` in V4) but paksmith's
legacy footer parser (`read_legacy`) covers V1–V6 and always sets
`encrypted = false`. The root cause is architectural: paksmith's
legacy probe window is `FOOTER_SIZE_LEGACY = 44` bytes, which ends
exactly before the wire offset where the V4–V6 `encrypted` byte sits,
so the parser never reads it. Any V4–V6 archive with index encryption
is therefore treated as plaintext by paksmith (no decryption,
potentially corrupt index parse). This is a known gap; V4–V6 encrypted
archives are rare in practice. V7+ footers carry both the 16-byte GUID
and the encrypted byte, and paksmith reads both correctly.

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

### Worked example

`(none yet — no encrypted fixture)`. Generating an encrypted fixture
would require either:

1. **Synthetic encrypted fixture with a published test-only key**, which
   the test suite would carry in source. This is the natural shape for
   adding hex-anchor coverage to this doc, deferred until a real
   need.
2. **A real cooked encrypted pak**, which would expose a production
   AES key in the repo. Out of bounds.

The detection codepath can be exercised with a synthetic fixture
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

No paksmith-side caps on encryption metadata — the footer's
`encrypted` byte is a u8 (no overflow surface); the encryption GUID
is a fixed 16 bytes (no length to bound); per-entry flags are u8 / 1
bit.

When AES decryption lands, the caps that already cover decompression
will protect the decryption stage analogously:

- Index region's size is capped by `max_index_bytes()` before any
  read. The decryption step inherits that cap.
- Per-entry payload's size is capped by `MAX_UNCOMPRESSED_ENTRY_BYTES = 8 GiB`
  and per-block budgets.

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
(footer.is_encrypted() guard at `mod.rs:242`); per-entry-only archives
open successfully and rejection occurs at extraction time via
`stream_entry_to` at `mod.rs:998-1001`. `verify_entry` skips encrypted
entries silently (`Ok(VerifyOutcome::SkippedEncrypted)` at
`mod.rs:680-683`).

**Parser modules:**
- `crates/paksmith-core/src/container/pak/footer.rs` — `PakFooter::encryption_key_guid`,
  `PakFooter::is_encrypted`.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs` —
  per-entry `is_encrypted` field, in both flat-form (V3–V9) and
  encoded-form (V10+, bit 22) readers.
- `crates/paksmith-core/src/container/pak/mod.rs:242` —
  `PakReader::from_reader` rejection point.
- `crates/paksmith-core/src/container/pak/mod.rs:680` —
  `verify_entry` skip-encrypted path; emits `VerifyOutcome::SkippedEncrypted`.

**Status:** `partial`. Detection of every encryption metadata surface
is complete; decryption is unimplemented. Encrypted archives raise
`PaksmithError::Decryption`; encrypted entries skip verification
(`VerifyOutcome::SkippedEncrypted`).

**Public surface:**
- `PakFooter::encryption_key_guid() -> Option<&[u8; 16]>` — Some for
  V7+ archives, None for legacy.
- `PakFooter::is_encrypted() -> bool` — V7+ index-encryption flag.
- `PakEntryHeader::is_encrypted() -> bool` — per-entry flag.
- `PakReader::open()` / `from_reader()` returns
  `PaksmithError::Decryption { path: Option<String> }` for any
  `footer.is_encrypted() == true` archive.
- `PakReader::verify_entry(path)` skips encrypted entries with
  `VerifyOutcome::SkippedEncrypted` (countered separately in
  `IntegrityStats::entries_skipped_encrypted()`).
- `PakReader::stream_entry_to(path, writer)` returns
  `PaksmithError::Decryption { path }` at `mod.rs:998-1001` when the
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
[^2]: `FabianFG/CUE4Parse/CUE4Parse/Encryption/Aes/Aes.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — secondary oracle for the AES-256 ECB block-cipher specifics (confirms ECB mode, no padding, no IV, 16-byte block size). Also `FAesKey.cs` in the same directory for the key-wrapping type. NIST FIPS 197 is the upstream reference for AES itself; not cited inline as it is external to UE.
