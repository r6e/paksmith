# Phase 5a — Core AES Pak Decryption Design

**Status:** approved (brainstorming), pre-implementation
**Date:** 2026-06-19
**Roadmap:** Phase 5 (Game Profiles) — sub-phase 5a (the enabling prerequisite)

## Context

Phase 5 (Game Profiles) decomposes into **5a AES decryption → 5b profiles +
key management → 5c registry (async/network) → 5d auto-detection**, each its
own spec → plan → cycle. This document specifies **5a only**.

paksmith currently **cannot open AES-encrypted paks**: `PakReader::from_reader`
detects `footer.is_encrypted()` and immediately returns
`PaksmithError::Decryption { path: None }`. There is no `aes` crate, no
key-passing API, and no decryption — encrypted paks are refused. The index
parser already handles the encrypted-entry *layout* (16-byte AES alignment in
the compression-block math, per-entry `is_encrypted` flags, and
`VerifyOutcome::SkippedEncrypted` to skip hash verification of encrypted
regions), but never decrypts.

5a builds the missing capability: decrypt an encrypted pak's index and entries
given a 32-byte AES-256 key, exposed via a new core API and a global
`--aes-key` CLI flag. This is the prerequisite for 5b's key management — "AES
key management" is meaningless until a key can actually be *used*.

## Crypto facts (community-reference verified — repak/CUE4Parse; no engine source)

- UE pak encryption is **AES-256 in ECB mode**: each 16-byte block is
  encrypted/decrypted independently with the same 256-bit key. Confirmed
  against `trumank/repak` (`key.decrypt_block` / `key.encrypt_block` per
  `aes::Block`, 16-byte alignment).
- Encrypted regions are **padded to 16-byte alignment**; the real
  (unpadded) size is known from the index, so decrypt-then-trim recovers the
  plaintext.
- Two encryption scopes, both with the same key:
  - **Index encryption** (`footer.is_encrypted()`, UE "IndexEncryption" v4+):
    the entire serialized index region is AES-encrypted.
  - **Per-entry encryption** (`entry.is_encrypted`): an individual entry's
    stored bytes are AES-encrypted (independent of index encryption).

## Goals / non-goals

- **Goal:** open + read AES-encrypted paks given one supplied key, via core API
  + a global `--aes-key` CLI flag across all four container commands.
- **Non-goal:** key *storage*, a guid→key *map* (multiple games), key-testing
  UX, profiles, network — all 5b+. IoStore/Oodle (Phase 8). Writing/encrypting
  paks (read-only tool; repak does the encryption for fixtures).

## Dependencies

- `paksmith-core`: add **`aes`** (RustCrypto, pure-Rust, MIT/Apache — the same
  crate repak uses) and **`zeroize`** (MIT/Apache, zero key material on drop).
  ECB is done by manual 16-byte block iteration over `aes::Aes256` — **no
  `ecb`/`cbc` dependency**.
- `paksmith-fixture-gen`: enable repak's **`encryption`** feature (adds
  repak's `aes`) to write encrypted fixtures.
- CLI hex-key decoding is an **internal helper** (no `hex` crate) — ~one small
  unit-tested function.
- `cargo deny` must stay green (all permissive licenses; confirm at impl).

## Architecture

```
crates/paksmith-core/Cargo.toml                       # MODIFY: add aes, zeroize
crates/paksmith-core/src/container/pak/crypto.rs       # CREATE: AesKey + aes256_ecb_decrypt
crates/paksmith-core/src/container/pak/mod.rs          # MODIFY: open_with_key/from_reader_with_key + index/entry decrypt
crates/paksmith-cli/src/main.rs                        # MODIFY: global --aes-key flag + hex decode
crates/paksmith-cli/src/commands/{list,inspect,extract,search}.rs  # MODIFY: open via key when present
crates/paksmith-fixture-gen/Cargo.toml                 # MODIFY: repak "encryption" feature
crates/paksmith-fixture-gen/src/...                    # MODIFY: emit encrypted fixtures + cross-validate
tests/fixtures/*.pak                                   # CREATE: encrypted fixtures (bump CI count gate)
```

### Component 1 — `crypto.rs` (pure, unit-testable)

```rust
/// 32-byte AES-256 key. Zeroized on drop (crypto-material hygiene).
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct AesKey([u8; 32]);

impl AesKey {
    pub fn new(bytes: [u8; 32]) -> Self;          // from raw bytes
    // (no Debug that prints the key; Debug is redacted)
}

/// Decrypt `data` in place as AES-256-ECB (16-byte blocks). `data.len()` must
/// be a multiple of 16 (encrypted regions are 16-aligned). Returns an error
/// (not a panic) on unaligned length.
pub(crate) fn aes256_ecb_decrypt(key: &AesKey, data: &mut [u8]) -> crate::Result<()>;
```

`aes256_ecb_decrypt` builds `aes::Aes256::new(key)` once and calls
`decrypt_block` over each 16-byte chunk. Pure; no I/O. `AesKey` has a redacted
`Debug` (never prints bytes) and no `Display`.

### Component 2 — `PakReader` key-aware open + decrypt

- `pub fn open_with_key<P: AsRef<Path>>(path: P, key: AesKey) -> Result<Self>`
  and `pub fn from_reader_with_key<R>(reader: R, key: AesKey) -> Result<Self>`.
  Both store the key on the `PakReader` (zeroized when the reader drops).
- `open(path)` / `from_reader(reader)` are unchanged (no key); on an encrypted
  pak they still return `Decryption`, with the message updated to suggest
  `--aes-key`.
- **Index decrypt:** when `footer.is_encrypted()`, read the index region bytes,
  `aes256_ecb_decrypt` them with the key, then feed the plaintext to the
  existing index parser. A wrong key yields garbage that fails the index
  parser's magic/bounds checks → mapped to
  `PaksmithError::Decryption { path, reason }` (a "wrong AES key?" hint), not an
  opaque parse error. (The index parser's existing bounds/validation is the
  wrong-key detector; no separate "known plaintext marker" is required.)
- **Entry decrypt:** in `stream_entry_to`, when `entry.is_encrypted`, read the
  16-aligned encrypted bytes, decrypt with the stored key, trim to the entry's
  real size, then continue the existing decompress/hash path. If the reader has
  no key but an entry is encrypted → `Decryption`.

### Component 3 — CLI global `--aes-key <HEX>`

- A `#[arg(long, global = true)]` `aes_key: Option<String>` on the top-level
  `Cli` (sibling of `--format`/`--verbose`).
- Decoded once in `main` via an internal `parse_aes_key(&str) -> Result<AesKey>`:
  accepts 64 hex chars, optional `0x`/`0X` prefix, case-insensitive; rejects
  wrong length / non-hex with `InvalidArgument` (exit 2). The decoded `AesKey`
  is threaded to each command's `run`.
- Each command's `PakReader::open(path)` site becomes: `match &key { Some(k) =>
  PakReader::open_with_key(path, k.clone()), None => PakReader::open(path) }`.
  (`Package::read_from_pak` / `read_from_reader` in `inspect`/`extract` need a
  key-aware variant or an already-open `Arc<PakReader>` path — see Build notes.)
- Key supplied for an unencrypted pak → ignored (harmless). Encrypted pak +
  no key → the `Decryption` error with the `--aes-key` hint.

### Component 4 — fixture-gen encrypted fixtures

Enable repak's `encryption` feature; add a generator path that builds encrypted
paks via `repak::PakBuilder::new().key(aes256).writer(...)` (index-encrypted
and/or per-entry-encrypted variants), with a known test key. Cross-validate:
paksmith's `open_with_key` + read of each entry must equal the plaintext repak
wrote. Emit a small number of encrypted `.pak` fixtures into `tests/fixtures/`
and **bump the CI fixture-count gate** in `.github/workflows/ci.yml`.

## Error handling / exit codes

- Core: `PaksmithError::Decryption { path, reason }` for wrong/missing key
  (reason carries the hint). `aes256_ecb_decrypt` returns `Result` (no panic)
  on unaligned input. No key material in any error/log message.
- CLI: bad `--aes-key` hex → `InvalidArgument` (exit 2). Existing exit-code
  discipline (0/1/2, BrokenPipe) unchanged.

## Security (mandatory security-reviewer surface)

- Untrusted encrypted bytes: decryption is fixed-size 16-byte block ops over
  **index-bounded** lengths (the index caps already enforce sane sizes before
  any decrypt), so no allocation blow-up. Decrypt happens after the existing
  bounds checks where possible.
- `zeroize` the key on drop; redacted `Debug`; never log the key.
- **Not constant-time** is acceptable: this is a local extractor, not a
  network timing-oracle context. Documented, not a finding.
- Wrong-key handling must fail closed (error), never silently return garbage
  bytes as if valid.

## Testing

- **Unit (`crypto.rs`):** `aes256_ecb_decrypt` against known AES-256-ECB test
  vectors (NIST FIPS-197 / standard vectors); encrypt→decrypt round-trip;
  unaligned-length → error; `AesKey` Debug is redacted; `parse_aes_key` (valid
  64-hex, `0x` prefix, wrong length, non-hex).
- **Integration:** `open_with_key` on the encrypted fixture — every entry's
  decrypted+decompressed bytes equal the plaintext; **wrong key → `Decryption`
  error**; unencrypted pak + key → opens normally; encrypted pak + no key →
  `Decryption` with hint. Cross-validation vs repak in fixture-gen.
- **CLI:** `--aes-key <hex>` end-to-end (`list` over the encrypted fixture
  lists entries; one assertion per command that the key path opens it);
  bad-hex → exit 2.
- New `.pak` fixtures → bump the fixture-count gate.

## Build notes / open implementation points

- `inspect`/`extract` open paks through `Package::read_from_pak(path, ...)` /
  `read_from_reader(Arc<PakReader>, ...)` (the 4a addition). Threading the key
  needs either a `read_from_pak_with_key` variant, or constructing the
  `Arc<PakReader>` via `open_with_key` and using `read_from_reader`. Prefer the
  latter where a reader is already built; add a thin `_with_key` constructor
  where `read_from_pak` is called directly. Resolve at the task against the
  live signatures.
- Confirm whether the index region is read as a contiguous buffer before
  parsing (needed for decrypt-before-parse); if the parser streams from the
  file, 5a reads the (bounded) index region into a buffer, decrypts, and parses
  from the buffer.

## Scope boundary

5a ships single-key AES decryption end-to-end. The guid→key map, key storage,
key-testing UX, profiles, registry, and detection are 5b+ and out of scope.

5a decrypts **flat-index (v3–v9) encrypted paks** and per-entry-encrypted data
of any version. v10+ (path-hash) **encrypted-index** decryption is explicitly
deferred: the PHI and FDI sub-regions use absolute file-position seeks that are
incompatible with the Cursor-based decryption approach; paksmith returns an
honest `UnsupportedFeature` error (not `Decryption`) so the user knows the key
is correct but this index layout is not yet supported.
