# UE Crypto Family Documentation — PR 7 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `docs/formats/crypto/` with one document: `aes-pak.md` (`partial | partial`, AES-256 ECB pak encryption — paksmith detects encryption metadata at every layer but rejects decryption pending a key-management design). Add one row to the root inventory.

**Architecture:** Single-doc family. The doc documents the full wire surface paksmith parses (encryption key GUID in the footer, per-entry encryption flag, V7+ encryption-key-GUID field) and the rejection behavior in `PakReader::from_reader`. The `Crypto.json` key-file format UE 4.20+ uses is referenced but explicitly out of scope for paksmith until a key-management profile lands (likely Phase 5).

**Tech Stack:** Pure markdown. PR 1 linters. Primary oracle is `trumank/repak` for the pak-side detection, secondary is CUE4Parse's `Encryption/Aes.cs` for the AES-256 ECB block-cipher specifics + the `Crypto.json` format reference.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite:** PR 1 (framework scaffold) has merged to `main`.

---

## Prerequisites

Follow [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md). Family name `crypto`; capture `<REPAK_SHA>` and `<CUE4PARSE_SHA>` at preamble Step 7.

## File structure

**Create (1 doc):**

- `docs/formats/crypto/aes-pak.md` — AES-256 ECB pak encryption (partial).

**Modify (1):**

- `docs/formats/README.md` — add one row to the inventory.

**Oracle citation policy.** Primary: `trumank/repak` (where the pak-side AES detection sites are most legible). Secondary: `CUE4Parse/Compression/Encryption/Aes.cs` for the block-cipher + `Crypto.json` schema specifics.

**Hex-anchor policy.** `(none yet)` — paksmith does not ship encrypted pak fixtures. Generating one synthetically would require a key-management workflow paksmith does not have, and shipping a real encrypted fixture would expose the AES key in the test suite. A follow-up could add a synthetic fixture with a published test-only key, but it's scope creep for this PR.

---

## Task 1: Per-family setup

Run [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s "Per-family setup" with `<family> = crypto`. Capture oracle SHAs at preamble Step 7 for use across this plan's doc citations.

---

## Task 2: Author `docs/formats/crypto/aes-pak.md`

The pak-side AES-256 ECB encryption scheme. Two encryption surfaces:
**index encryption** (V4+, toggleable via the footer's `encrypted` byte
on V7+ archives) and **per-entry encryption** (V3+ via the per-entry
`encrypted` byte). Both use the same algorithm and the same key.

**Files:**
- Create: `docs/formats/crypto/aes-pak.md`

**Ground truth references:**
- `crates/paksmith-core/src/container/pak/version.rs:9` — `FOOTER_SIZE_V7_PLUS = 61` includes the 16-byte `encryption_key_guid` + 1-byte `encrypted` flag.
- `crates/paksmith-core/src/container/pak/footer.rs:25` — `PakFooter::encryption_key_guid` field (V7+).
- `crates/paksmith-core/src/container/pak/footer.rs:64` — `is_encrypted()` accessor.
- `crates/paksmith-core/src/container/pak/mod.rs:242` — `from_reader` rejection point.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs:112` — per-entry `is_encrypted` field.
- `crates/paksmith-core/src/container/pak/index/entry_header.rs:367` — V10+ encoded-form encryption bit (bit 22).
- `crates/paksmith-core/src/error.rs:67` — `Decryption` error variant.

- [ ] **Step 1: Read the parsers**

Run: `grep -n "is_encrypted\|encryption_key_guid\|Decryption" crates/paksmith-core/src/container/pak/mod.rs crates/paksmith-core/src/container/pak/footer.rs crates/paksmith-core/src/container/pak/index/entry_header.rs crates/paksmith-core/src/error.rs | head -40`

Note the rejection point at `from_reader`, the per-entry detection at `verify_entry`, the V10+ encoded-form bit-22 path.

- [ ] **Step 3: Write the doc**

Write `docs/formats/crypto/aes-pak.md`:

````markdown
# AES-256 pak encryption

> Unreal Engine's pak encryption scheme — AES-256 in ECB mode applied
> at two granularities (whole index region; per-entry payload).
> Paksmith detects encryption metadata at every layer but does not
> decrypt: encrypted archives are rejected at open time, encrypted
> entries skip integrity verification.

## Overview

UE optionally encrypts pak archive content with AES-256 in **ECB mode**
(no IV, no chaining). Encryption can be applied at two granularities:

- **Index encryption** (V4+, gated by the footer's `encrypted` byte on
  V7+ archives): the whole index region (the bytes between
  `index_offset` and `index_offset + index_size`) is ciphertext. The
  reader must decrypt before parsing entry records.
- **Per-entry encryption** (V3+, gated by each entry's `encrypted`
  byte in its header): an individual entry's payload is ciphertext.
  The reader decrypts each block before decompressing (decryption
  happens at the compression-block granularity — see
  [`../compression/pak-block-framing.md`](../compression/pak-block-framing.md)).

Both surfaces share the same key. Key distribution is out-of-band:
UE writes the key into a `Crypto.json` file (UE 4.20+) or supplies it
via UnrealPak command-line; consumers must somehow obtain it.
paksmith does not yet model key handling — it detects the encrypted
state, rejects with a typed error, and leaves the key-management
question to a future profile-system phase (likely Phase 5).

ECB mode means each 16-byte block is encrypted independently with no
chaining. Encrypted block boundaries must align to 16-byte (AES
block-size) boundaries; UE's writer pads / aligns appropriately at
the index and entry level.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| Wire version 3 (UE 4.4) | Per-entry encryption introduced. Encryption signaled by the entry header's `encrypted` byte; no index encryption yet. | `trumank/repak/repak/src/entry.rs@<REPAK_SHA>`[^1] |
| Wire version 4 (UE 4.16, `IndexEncryption`) | Index encryption introduced. The whole index region is AES-encrypted when the writer enables it; reader must decrypt before parsing entries. | Same[^1] |
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

Legacy V3–V6 footers do not have either field. Per-entry encryption
is still available on those versions but no archive-level key
identifier or index-encryption toggle exists; encrypted entries must
be enumerated by reading the index plaintext and checking each
entry's per-entry flag.

### Per-entry encryption flag

For each pak entry (in both V3–V9 flat-form headers and V10+
encoded-form headers — see [`../container/pak.md`](../container/pak.md)):

| field | encoding | semantics |
|-------|----------|-----------|
| `encrypted` (V3–V9 flat form) | `u8` after the compression-blocks array | `1` = entry payload is AES-encrypted at compression-block granularity. |
| `encrypted` (V10+ encoded form) | bit 22 of the entry's high u32 word | Same semantics; bit-packed. |

### `Crypto.json` (UE 4.20+ key-file format)

UE's UnrealPak commandlet writes a `Crypto.json` sidecar describing
the keys used to encrypt a cooked build. Out of scope for paksmith
today, but the shape per CUE4Parse[^2]:

```json
{
  "EncryptionKey": {
    "Name": "Embedded",
    "Guid": "00000000000000000000000000000000",
    "Key": "0xBASE64-ENCODED-32-BYTES"
  },
  "SecondaryEncryptionKeys": [
    {
      "Name": "DLC-Pack-A",
      "Guid": "1234567890ABCDEF...",
      "Key": "0xBASE64-ENCODED-32-BYTES"
    }
  ]
}
```

The 32-byte (256-bit) key is base64- or hex-encoded depending on
the writer. The `Guid` field matches the pak footer's
`encryption_key_guid`: when paksmith adds key support, the lookup
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

Three meaningful combinations:

- **Plaintext archive** (`footer.encrypted == 0`, every entry's
  `encrypted == 0`): the common case for development cooked content.
- **Per-entry-only** (`footer.encrypted == 0`, some entries
  `encrypted == 1`): a subset of entries are encrypted; the index is
  readable. UE supports this for selective DRM.
- **Whole archive** (`footer.encrypted == 1`, every entry
  `encrypted == 1`): both index and entries are encrypted. The
  reader can't even enumerate entries without the key.

paksmith's detection currently rejects at the first encrypted
surface it encounters — opening an `footer.encrypted == 1` archive
raises `PaksmithError::Decryption` before any per-entry inspection.

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

- **Fixture:** `(none yet)` — paksmith does not ship encrypted pak
  fixtures. See the Wire layout's worked-example section for why.
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

## Paksmith implementation

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
- `PakFooter::is_encrypted() -> bool` — V4+ index-encryption flag.
- `PakEntryHeader::is_encrypted() -> bool` — per-entry flag.
- `PakReader::open()` / `from_reader()` returns
  `PaksmithError::Decryption { path: Option<String> }` for any
  `footer.is_encrypted() == true` archive.
- `PakReader::verify_entry(path)` skips encrypted entries with
  `VerifyOutcome::SkippedEncrypted` (countered separately in
  `IntegrityStats::entries_skipped_encrypted()`).

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

[^1]: `trumank/repak/repak/src/entry.rs@<REPAK_SHA>` plus `repak/src/lib.rs` — primary oracle for the on-wire encryption metadata. paksmith's detection paths mirror repak's exactly.
[^2]: `FabianFG/CUE4Parse/CUE4Parse/Compression/Encryption/Aes.cs@<CUE4PARSE_SHA>` and `CUE4Parse/UE4/Assets/CryptoSettings.cs` — secondary oracle for the AES-256 ECB block-cipher specifics and the `Crypto.json` schema. NIST FIPS 197 is the upstream reference for AES itself; not cited inline as it's external to UE.
````

- [ ] **Step 4: Commit** (preamble convention — required-headings linter must pass before commit)

```bash
git add docs/formats/crypto/aes-pak.md
git commit -m "$(cat <<'EOF'
docs(formats): add AES-256 pak encryption partial reference

Documents UE's pak encryption surface: AES-256 ECB at index and
per-entry granularities, the V4 / V7 wire-version evolution
(per-entry → index → keyed-by-GUID), the V10+ encoded-form
bit-22 encryption flag, and the Crypto.json key-file format
paksmith does not yet consume. Spells out paksmith's detection-
but-reject behavior (Decryption error at open; SkippedEncrypted
at verify) and the Phase 5 key-management insertion point.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Update root inventory + final verification + push

**Files:**
- Modify: `docs/formats/README.md`

- [ ] **Step 2: Add one row to the inventory**

Verify the existing inventory layout with `grep -n "^|" docs/formats/README.md`, then use Edit to insert one new row.

Row to insert:

```markdown
| `crypto/aes-pak.md` | partial | partial | `container/pak/footer.rs` | repak @ `<REPAK_SHA>` | `<SHA>` |
```

The `Last verified` is this branch's HEAD — paksmith's detection
behavior IS verified against the real codepath at the current
commit; what's `partial` is the decryption, which the doc documents
accurately as unimplemented.

- [ ] **Step 8: Commit the inventory update**

```bash
git add docs/formats/README.md
git commit -m "$(cat <<'EOF'
docs(formats): register the AES-pak doc in the inventory

Single partial-partial row: detection of every encryption metadata
surface is verified against the real codepath; decryption is
unimplemented pending Phase 5 key management. Last-verified anchor
is this branch's HEAD.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

```
<sha> docs(formats): register the AES-pak doc in the inventory
<sha> docs(formats): add AES-256 pak encryption partial reference
```

- [ ] **Step 11: Open the PR**

Title: `docs(formats): populate crypto family (aes-pak)`

Body — write to a tempfile first, then `gh pr create --body-file <tempfile>`:

```markdown
## Summary

Lands PR 7 of the UE format documentation framework. Populates
`docs/formats/crypto/` with one document:

- **`aes-pak.md`** *(partial)* — UE's AES-256 ECB pak encryption.
  Documents the two encryption surfaces (index region V4+, per-entry
  V3+), the V7+ encryption-key-GUID footer field, the V10+ encoded-
  form bit-22 encryption flag, the `Crypto.json` UE-4.20+ key-file
  format, the ECB block-cipher specifics, and paksmith's detection-
  but-reject behavior (`PaksmithError::Decryption` at open;
  `VerifyOutcome::SkippedEncrypted` at verify).

One row added to the root inventory: `partial | partial`.

## Linked issue

(none — design spec drives this work)

## Test plan

- [x] `paksmith-doc-lint required-headings` passes.
- [x] `paksmith-doc-lint status-enum` passes on the updated inventory.
- [x] `typos docs/formats/crypto/` clean.
- [x] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` clean.
- [x] Cross-validated every wire-format claim against trumank/repak
      (primary) + CUE4Parse (secondary).

## Pre-flight checklist

- [x] PR title is a Conventional Commit.
- [x] Branch name follows `<type>/<kebab-case>`.
- [x] `cargo fmt --all` clean (no Rust changed).
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [x] Documentation updated (this PR IS documentation).
- [x] No `unsafe` introduced.
- [x] Touched a parser? No — pure docs PR.

## Security considerations

The doc documents UE's choice of AES-256 ECB and flags it as
cryptographically questionable (ECB leaks block-equality patterns,
no diffusion across blocks) while making clear paksmith documents
what UE does rather than opining on what UE should do. The doc
also notes that the three-layer decompression-bomb defense
documented in `compression/zlib.md` carries over to decryption when
AES support lands (the index cap and per-block budgets apply to
the decryption stage analogously).

## Notes for reviewers

- The `aes-pak.md` Wire layout's "Worked example" is `(none yet)`.
  paksmith does not ship encrypted pak fixtures, and the reasoning
  is documented in the section: synthetic fixtures with published
  keys would be the natural addition but were judged out of scope
  for this PR. Detection can be tested via a footer with the
  encrypted byte set to 1 (the parser rejects before reading the
  ciphertext index, so the fixture doesn't have to be actually
  encrypted).
- The doc explicitly notes ECB is "cryptographically questionable"
  but doesn't editorialize beyond that — the no-engine-source rule
  isn't about hiding criticism; it's about not linking engine
  source. Documenting choices Epic made is in scope.
- The Crypto.json schema in the doc is sourced from CUE4Parse's
  `CryptoSettings.cs`. When Phase 5 implements the key registry,
  the schema should be re-checked against the loader's actual
  parsing.
```

---

## Done criteria

Per [PREAMBLE.md](2026-05-19-ue-format-docs-PREAMBLE.md)'s tail (linters green, typos clean, rustdoc clean, PR open, reviewer panel converged), plus this plan's inventory specifics enumerated above.
