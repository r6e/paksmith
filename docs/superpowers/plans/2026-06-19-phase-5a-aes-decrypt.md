# Phase 5a — Core AES Pak Decryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let paksmith open AES-256-ECB-encrypted paks given a 32-byte key — core `open_with_key` decrypting the index + per-entry data, a global `--aes-key` CLI flag across all four commands, and repak-cross-validated encrypted fixtures.

**Architecture:** A pure `crypto.rs` (`AesKey` + `aes256_ecb_decrypt`) underpins a key-aware `PakReader` (`open_with_key`); the encrypted index is read into a buffer, decrypted, and parsed via a `read_positioned` helper extracted from `PakIndex::read_from`; encrypted entries decrypt in `stream_entry_to` before decompress. The CLI threads a global `--aes-key` (hex) to every command's open site. fixture-gen emits encrypted paks via repak for round-trip cross-validation.

**Tech Stack:** Rust, RustCrypto `aes` + `zeroize` (core), `regex`/`clap` (existing), repak `encryption` feature (fixture-gen); tests via `assert_cmd`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-06-19-phase-5a-aes-decrypt-design.md`

## Global Constraints

- **MSRV:** workspace `rust-version` (1.88). No newer/unstable syntax — `let-else`, not `if let` match guards.
- **No panics in `paksmith-core`** — all fallible ops return `Result<T, PaksmithError>`. `aes256_ecb_decrypt` returns `Result` on unaligned input (no panic).
- **Crypto:** AES-**256**-**ECB**, 16-byte blocks, encrypted regions 16-byte-aligned. ECB by manual block iteration over `aes::Aes256` — **no `ecb`/`cbc` dep**. Only `aes` + `zeroize` added to core.
- **Key handling:** `AesKey` zeroized on drop, redacted `Debug` (never prints bytes), no `Display`, never logged.
- **Wrong key fails closed** — returns `PaksmithError::Decryption { path: Some(..) }` (existing variant; its message already reads "invalid or missing AES key"), never silently returns garbage. Keep the `Decryption { path }` shape (do NOT add fields).
- **CLI:** global `--aes-key <HEX>` (64 hex chars, optional `0x`/`0X`, case-insensitive) → exit `2` (`InvalidArgument`) on bad hex. Key on an unencrypted pak is ignored.
- **No engine-source references** in any committed doc/comment — cite repak/CUE4Parse or plain facts.
- **New `.pak` fixtures bump the CI fixture-count gate** in `.github/workflows/ci.yml`.
- **Conventional commits**; pre-push gates: `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`, `typos .`, and `cargo deny check` (new deps).
- **Review:** adversarial panel to convergence with a **mandatory security specialist** (untrusted-input crypto + parser).

---

## File Structure

```
crates/paksmith-core/Cargo.toml                          # MODIFY: add aes, zeroize
crates/paksmith-core/src/container/pak/crypto.rs          # CREATE: AesKey + aes256_ecb_decrypt
crates/paksmith-core/src/container/pak/mod.rs             # MODIFY: key field, open_with_key, index+entry decrypt
crates/paksmith-core/src/container/pak/index/mod.rs       # MODIFY: extract read_positioned from read_from
crates/paksmith-cli/src/main.rs                          # MODIFY: global --aes-key + parse_aes_key + thread key
crates/paksmith-cli/src/commands/mod.rs                  # MODIFY: Command::run takes the key
crates/paksmith-cli/src/commands/{list,search,extract,inspect}.rs  # MODIFY: open via key
crates/paksmith-fixture-gen/Cargo.toml                   # MODIFY: repak "encryption" feature
crates/paksmith-fixture-gen/src/main.rs (+ uasset/helpers) # MODIFY: emit encrypted paks + cross-validate
tests/fixtures/real_v*_encrypted*.pak                    # CREATE: encrypted fixtures
```

---

## Task 1: `crypto.rs` — `AesKey` + `aes256_ecb_decrypt`

**Files:**
- Modify: `crates/paksmith-core/Cargo.toml`
- Create: `crates/paksmith-core/src/container/pak/crypto.rs`
- Modify: `crates/paksmith-core/src/container/pak/mod.rs` (add `pub(crate) mod crypto;` + `pub use crypto::AesKey;` re-export at the container level)

**Interfaces:**
- Produces: `pub struct AesKey([u8; 32])` with `pub fn new(bytes: [u8; 32]) -> Self`, `ZeroizeOnDrop`, redacted `Debug`, `Clone`.
- Produces: `pub(crate) fn aes256_ecb_decrypt(key: &AesKey, data: &mut [u8]) -> crate::Result<()>`.

- [ ] **Step 1: Add deps**

In `crates/paksmith-core/Cargo.toml` `[dependencies]` (mirror the commented style of existing deps), add:
```toml
# Phase 5a: AES-256-ECB decryption of encrypted UE paks (the same RustCrypto
# crate repak uses). ECB is done by manual 16-byte block iteration — no ecb/cbc dep.
aes = "0.8"
# Phase 5a: zero AES key material on drop (crypto-material hygiene).
zeroize = { version = "1", features = ["zeroize_derive"] }
```

- [ ] **Step 2: Write the failing unit tests**

Create `crates/paksmith-core/src/container/pak/crypto.rs`:
```rust
//! AES-256-ECB decryption for encrypted UE paks. UE encrypts pak data with
//! AES-256 in ECB mode (each 16-byte block independent); encrypted regions are
//! padded to 16-byte alignment. Verified against trumank/repak.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use zeroize::ZeroizeOnDrop;

/// A 32-byte AES-256 key. Zeroized on drop; `Debug` is redacted so the key
/// never lands in logs.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesKey([u8; 32]);

impl AesKey {
    /// Construct from raw key bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesKey(<redacted>)")
    }
}

/// Decrypt `data` in place as AES-256-ECB. `data.len()` MUST be a multiple of
/// 16 (encrypted pak regions are 16-byte aligned). Returns
/// [`crate::PaksmithError::Decryption`] on unaligned input rather than panicking.
pub(crate) fn aes256_ecb_decrypt(key: &AesKey, data: &mut [u8]) -> crate::Result<()> {
    if data.len() % 16 != 0 {
        return Err(crate::PaksmithError::Decryption { path: None });
    }
    let cipher = Aes256::new(aes::cipher::generic_array::GenericArray::from_slice(&key.0));
    for block in data.chunks_exact_mut(16) {
        cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(block));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 AES-256 known-answer (ECB single block):
    // key   = 000102...1f (32 bytes), plaintext = 00112233...ffee... (16 bytes),
    // ciphertext = 8ea2b7ca516745bfeafc49904b496089.
    const KEY: [u8; 32] = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    ];
    const PLAIN: [u8; 16] = [
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    ];
    const CIPHER: [u8; 16] = [
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89,
    ];

    #[test]
    fn decrypts_fips197_known_vector() {
        let key = AesKey::new(KEY);
        let mut data = CIPHER;
        aes256_ecb_decrypt(&key, &mut data).unwrap();
        assert_eq!(data, PLAIN);
    }

    #[test]
    fn multi_block_is_per_block_ecb() {
        // Two identical ciphertext blocks decrypt to two identical plaintext blocks.
        let key = AesKey::new(KEY);
        let mut data = [CIPHER, CIPHER].concat();
        aes256_ecb_decrypt(&key, &mut data).unwrap();
        assert_eq!(&data[..16], &PLAIN);
        assert_eq!(&data[16..], &PLAIN);
    }

    #[test]
    fn unaligned_length_errors_not_panics() {
        let key = AesKey::new(KEY);
        let mut data = [0u8; 17];
        assert!(matches!(
            aes256_ecb_decrypt(&key, &mut data),
            Err(crate::PaksmithError::Decryption { .. })
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let key = AesKey::new(KEY);
        assert_eq!(format!("{key:?}"), "AesKey(<redacted>)");
        assert!(!format!("{key:?}").contains("00"));
    }
}
```

- [ ] **Step 3: Wire the module + run**

Add to `crates/paksmith-core/src/container/pak/mod.rs` (near the other `mod`/`use`):
```rust
pub(crate) mod crypto;
pub use crypto::AesKey;
```
(Confirm `AesKey` reaches `paksmith_core::container::pak::AesKey`, or re-export further up to `paksmith_core::container::AesKey` if that matches the existing public surface — check how `PakReader`/`EntryMetadata` are re-exported and mirror it.)

Run: `cargo test -p paksmith-core --all-features crypto`
Expected: 4 tests PASS (after deps resolve).

- [ ] **Step 4: deny + clippy**

Run `cargo deny check 2>&1 | tail -20` (aes/zeroize are MIT/Apache — expect clean; surface any flag). `cargo fmt --all`; `cargo clippy -p paksmith-core --all-targets --all-features -- -D warnings`. (If clippy flags `generic_array` import verbosity, alias it; if `aes` 0.8's API differs slightly — e.g. `KeyInit`/`BlockDecrypt` trait paths — adjust the imports to the resolved `aes 0.8` API, keeping the per-16-byte `decrypt_block` loop.)

- [ ] **Step 5: Commit**
```bash
git add crates/paksmith-core/Cargo.toml crates/paksmith-core/src/container/pak/crypto.rs \
        crates/paksmith-core/src/container/pak/mod.rs
git commit -m "feat(core): add AesKey + AES-256-ECB decryption primitive"
```

---

## Task 2: fixture-gen — emit encrypted pak fixtures

**Files:**
- Modify: `crates/paksmith-fixture-gen/Cargo.toml` (repak `encryption` feature)
- Modify: `crates/paksmith-fixture-gen/src/main.rs` (+ its helpers)
- Create: `tests/fixtures/*encrypted*.pak`
- Modify: `.github/workflows/ci.yml` (fixture-count gate)

**Interfaces:**
- Produces: at least one encrypted `.pak` fixture in `tests/fixtures/` with a KNOWN 32-byte key (document the key as a constant in the test that consumes it), containing ≥1 entry. Prefer two: an **index-encrypted** pak and an **entry-encrypted** pak (or one pak exercising both, if repak does both together).

- [ ] **Step 1: Enable repak encryption**

In `crates/paksmith-fixture-gen/Cargo.toml`, change the repak dep features to include `encryption`:
```toml
repak = { version = "0.2", git = "https://github.com/trumank/repak", rev = "e215472c51db69328b1ce77be2db24d24c1d646b", default-features = false, features = ["compression", "encryption"] }
```

- [ ] **Step 2: Add an encrypted-pak generator**

In `paksmith-fixture-gen` (follow the existing per-fixture generator pattern in `src/main.rs`/`uasset.rs`), add a generator that builds an encrypted pak via repak's `PakBuilder::new().key(aes256).writer(...)`. Determine the exact repak write API from the cached source: `~/.cargo/git/checkouts/repak-*/e215472/repak/src/pak.rs` (`PakBuilder { key }`, `.key(aes::Aes256)`, `.writer(...)`/`.reader(...)`; `aes::Aes256::new` from a `[u8;32]`). Use a fixed test key (e.g. all-`0x42` bytes, or a documented constant). Write a small known entry set (mirror an existing minimal fixture's paths/bytes). Emit to `tests/fixtures/` with a name like `real_v11_encrypted.pak` (pick the pak version repak's encryption path supports — confirm against repak; v7+ has `EncryptionKeyGuid`, v4+ has index encryption).

(If repak writes index-encryption and entry-encryption via distinct flags, emit one fixture per scope so Tasks 3 and 4 can target them independently. Record each fixture's plaintext entries — paths + bytes — as constants/JSON for cross-validation.)

- [ ] **Step 3: Regenerate fixtures + bump the gate**

Run `cargo run -p paksmith-fixture-gen` (per the project's fixture regeneration flow). Confirm the new `.pak`(s) appear in `tests/fixtures/`. In `.github/workflows/ci.yml`, find the hardcoded fixture-count (`expected=N`) and bump it by the number of new `.pak` files.

- [ ] **Step 4: Commit**
```bash
git add crates/paksmith-fixture-gen/Cargo.toml crates/paksmith-fixture-gen/src/ \
        tests/fixtures/ .github/workflows/ci.yml
git commit -m "test(fixture-gen): emit AES-encrypted pak fixtures via repak"
```

---

## Task 3: `PakReader` key field + index decryption

**Files:**
- Modify: `crates/paksmith-core/src/container/pak/index/mod.rs` (extract `read_positioned`)
- Modify: `crates/paksmith-core/src/container/pak/mod.rs` (key field, `open_with_key`/`from_reader_with_key`, index decrypt)
- Test: `crates/paksmith-core` integration (or in-source) against the Task 2 fixture

**Interfaces:**
- Consumes: `AesKey`, `aes256_ecb_decrypt` (Task 1); the encrypted fixture (Task 2).
- Produces:
  - `PakIndex::read_positioned<R: Read + Seek>(reader, version, index_size, file_size, methods) -> Result<Self>` (the post-seek body of `read_from`).
  - `PakReader::open_with_key<P>(path, key: AesKey) -> Result<Self>`, `from_reader_with_key<R>(reader, key) -> Result<Self>`.
  - `PakReader` gains `key: Option<AesKey>`.

- [ ] **Step 1: Extract `read_positioned` (pure refactor)**

In `index/mod.rs`, split `read_from` so the version-branch (post-seek) is reusable:
```rust
pub fn read_from<R: Read + Seek>(
    reader: &mut R, version: PakVersion, index_offset: u64, index_size: u64,
    file_size: u64, compression_methods: &[Option<CompressionMethod>],
) -> crate::Result<Self> {
    let _ = reader.seek(SeekFrom::Start(index_offset))?;
    Self::read_positioned(reader, version, index_size, file_size, compression_methods)
}

/// Parse the index from a reader already positioned at the index start.
/// (The decrypted-index path constructs a `Cursor` over the plaintext region
/// and calls this directly — there are NO further seeks beyond `read_from`'s.)
pub fn read_positioned<R: Read + Seek>(
    reader: &mut R, version: PakVersion, index_size: u64,
    file_size: u64, compression_methods: &[Option<CompressionMethod>],
) -> crate::Result<Self> {
    if version.has_path_hash_index() {
        Self::read_v10_plus_from(reader, index_size, file_size, compression_methods)
    } else {
        Self::read_flat_from(reader, version, index_size, compression_methods)
    }
}
```
Run `cargo test -p paksmith-core --all-features pak::index` — all existing index tests still PASS (pure refactor, behavior identical).

- [ ] **Step 2: Write the failing integration test**

In a `paksmith-core` integration/in-source test (mirror where existing `from_reader`/`open` tests live), using the Task 2 encrypted fixture + its known key:
```rust
#[test]
fn open_with_key_decrypts_index_and_lists_entries() {
    let key = AesKey::new(TEST_KEY); // the documented fixture key
    let reader = PakReader::open_with_key(encrypted_fixture_path(), key).unwrap();
    let paths: Vec<_> = reader.entries().map(|e| e.path().to_string()).collect();
    assert!(!paths.is_empty()); // index decrypted + parsed
    // paths match the known plaintext set the fixture-gen recorded
}

#[test]
fn open_with_wrong_key_is_decryption_error() {
    let wrong = AesKey::new([0u8; 32]);
    assert!(matches!(
        PakReader::open_with_key(encrypted_fixture_path(), wrong),
        Err(PaksmithError::Decryption { .. })
    ));
}

#[test]
fn open_without_key_on_encrypted_is_decryption_error() {
    assert!(matches!(
        PakReader::open(encrypted_fixture_path()),
        Err(PaksmithError::Decryption { .. })
    ));
}
```

- [ ] **Step 3: Run — verify it fails**
Run: `cargo test -p paksmith-core --all-features open_with_key`
Expected: FAIL — `open_with_key` not defined.

- [ ] **Step 4: Implement the key field + index decrypt**

Add `key: Option<AesKey>` to `PakReader`. Add `open_with_key`/`from_reader_with_key` mirroring `open`/`from_reader` but storing the key. In `from_reader_with_key`, replace the `if footer.is_encrypted() { return Err(Decryption) }` early-return with:
```rust
let index = if footer.is_encrypted() {
    let Some(key) = key.as_ref() else {
        return Err(PaksmithError::Decryption { path: None });
    };
    // Read the encrypted index region, decrypt, parse from the plaintext buffer.
    // Encrypted regions are 16-aligned: read up to the aligned end of index_size.
    let aligned = footer.index_size().div_ceil(16) * 16;
    let mut buf = vec![0u8; usize::try_from(aligned).map_err(/* U64ExceedsPlatformUsize */ ...)?];
    // (bounds: the existing index-size cap already gates index_size before this)
    {
        let mut file = locked_or_buffered_reader; // seek to index_offset, read_exact(buf)
        let _ = file.seek(SeekFrom::Start(footer.index_offset()))?;
        file.read_exact(&mut buf)?;
    }
    crypto::aes256_ecb_decrypt(key, &mut buf)?;
    let mut cur = std::io::Cursor::new(&buf[..]);
    PakIndex::read_positioned(&mut cur, version, footer.index_size(), file_size, &methods)
        // wrong key → garbage → this parse fails; map parse errors here to Decryption
        .map_err(|_| PaksmithError::Decryption { path: None })?
} else {
    PakIndex::read_from(&mut buffered, version, footer.index_offset(), footer.index_size(), file_size, &methods)?
};
```
(Resolve against the actual `from_reader` locals: `version`, `methods`/`compression_methods`, the reader handle, and the existing index-size cap. The `.map_err(|_| Decryption)` ONLY wraps the post-decrypt index parse so a wrong key surfaces as `Decryption` rather than an opaque parse fault — do NOT swallow I/O errors from the read itself. Keep the unencrypted branch byte-identical to today. `open_with_key` upgrades `Decryption { path: None }` → `Some(path)` like `open` does today.)

- [ ] **Step 5: Run — verify pass + no regression**
Run: `cargo test -p paksmith-core --all-features open_with_key` (PASS) and `cargo test -p paksmith-core --all-features` (all prior PASS — `open`/`from_reader` unchanged).

- [ ] **Step 6: fmt + clippy + commit**
```bash
git add crates/paksmith-core/src/container/pak/index/mod.rs crates/paksmith-core/src/container/pak/mod.rs
git commit -m "feat(core): open_with_key — decrypt and parse encrypted pak index"
```

---

## Task 4: per-entry decryption in `stream_entry_to`

**Files:**
- Modify: `crates/paksmith-core/src/container/pak/mod.rs` (`stream_entry_to` / the entry read path)

**Interfaces:**
- Consumes: the `key` field + `aes256_ecb_decrypt`; the entry-encrypted fixture (Task 2).
- Produces: encrypted entries decrypt on read; reads through `read_entry`/`read_entry_to`/`stream_entry_to` return plaintext.

- [ ] **Step 1: Write the failing test**
```rust
#[test]
fn reads_encrypted_entry_as_plaintext() {
    let key = AesKey::new(TEST_KEY);
    let reader = PakReader::open_with_key(entry_encrypted_fixture_path(), key).unwrap();
    let bytes = reader.read_entry(KNOWN_ENCRYPTED_ENTRY_PATH).unwrap();
    assert_eq!(bytes, KNOWN_PLAINTEXT_BYTES); // matches what fixture-gen/repak wrote
}

#[test]
fn encrypted_entry_without_key_errors() {
    let reader = PakReader::open(/* a pak whose index is NOT encrypted but has an */
                                 /* encrypted entry, if repak can produce one */).ok();
    // If such a fixture exists: read_entry on the encrypted entry → Decryption.
    // (If repak only encrypts index+entries together, this case is covered by Task 3's
    //  no-key test; document that and skip.)
}
```
(Use whichever fixture shape Task 2 produced. If repak couples index+entry encryption, the "encrypted entry" is reached only after a successful key-bearing open — so this test reads an entry and asserts plaintext; the no-key case is Task 3's.)

- [ ] **Step 2: Run — verify it fails**
Run: `cargo test -p paksmith-core --all-features encrypted_entry`
Expected: FAIL — entry bytes are still ciphertext (garbage ≠ plaintext).

- [ ] **Step 3: Implement entry decrypt**

In the entry read path (`stream_entry_to` or where the stored bytes are read before decompress), when `entry.header().is_encrypted()`:
- read the stored bytes rounded UP to 16-byte alignment (the encrypted on-disk size is 16-aligned; the existing alignment math already reflects this — read `align_up(stored_size, 16)`),
- `crypto::aes256_ecb_decrypt(key, &mut buf)?` (Decryption if no key),
- trim to the real stored size, then continue the existing decompress/copy path.
Keep unencrypted entries on the existing zero-copy/stream path. Resolve the exact buffer boundary against the live `stream_entry_to` + the entry header's stored/compressed-size accessors and the fixture.

- [ ] **Step 4: Run — verify pass + commit**
Run: `cargo test -p paksmith-core --all-features` (entry test PASS, all prior PASS).
```bash
git add crates/paksmith-core/src/container/pak/mod.rs
git commit -m "feat(core): decrypt encrypted pak entries on read"
```

---

## Task 5: CLI global `--aes-key` across all commands

**Files:**
- Modify: `crates/paksmith-cli/src/main.rs` (flag + `parse_aes_key` + thread key)
- Modify: `crates/paksmith-cli/src/commands/mod.rs` (`Command::run` signature)
- Modify: `crates/paksmith-cli/src/commands/{list,search,extract,inspect}.rs`
- Test: `crates/paksmith-cli/tests/*` (integration)

**Interfaces:**
- Produces: `fn parse_aes_key(s: &str) -> paksmith_core::Result<paksmith_core::container::pak::AesKey>` (in main.rs); `Command::run(&self, format: OutputFormat, key: Option<&AesKey>) -> Result<u8>`.

- [ ] **Step 1: Write the failing tests**

Unit (`main.rs` `#[cfg(test)]`):
```rust
#[test]
fn parse_aes_key_accepts_64_hex_with_optional_prefix() {
    let k = parse_aes_key("0x".to_string() + &"ab".repeat(32)).unwrap();
    let _ = k; // 32 bytes of 0xAB
    assert!(parse_aes_key(&"ab".repeat(32)).is_ok()); // no prefix
    assert!(parse_aes_key(&"AB".repeat(32)).is_ok()); // case-insensitive
}
#[test]
fn parse_aes_key_rejects_bad() {
    assert!(parse_aes_key("ab").is_err());            // too short
    assert!(parse_aes_key(&"zz".repeat(32)).is_err()); // non-hex
}
```
Integration (in the relevant `tests/*_cli.rs`, using the Task 2 encrypted fixture + its hex key):
```rust
#[test]
fn list_with_aes_key_opens_encrypted_pak() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["--aes-key", FIXTURE_KEY_HEX, "list"]).arg(encrypted_fixture())
        .assert().success();
}
#[test]
fn aes_key_bad_hex_exits_2() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["--aes-key", "nothex", "list"]).arg(encrypted_fixture())
        .assert().code(2);
}
#[test]
fn encrypted_pak_without_key_fails() {
    Command::cargo_bin("paksmith").unwrap()
        .args(["list"]).arg(encrypted_fixture())
        .assert().failure(); // Decryption → exit 2
}
```

- [ ] **Step 2: Run — verify fail**
Run: `cargo test -p paksmith-cli aes_key` and `--test <list_cli>` → FAIL (no flag / no parse fn).

- [ ] **Step 3: Add the flag + parser + thread the key**

In `main.rs` `Cli`, add (sibling of `format`):
```rust
    /// 32-byte AES-256 key as 64 hex chars (optional `0x` prefix) to open an
    /// encrypted pak.
    #[arg(long, global = true, value_name = "HEX")]
    aes_key: Option<String>,
```
Add `parse_aes_key` (internal hex decode: strip optional `0x`/`0X`; require exactly 64 chars; decode each hex pair → `[u8;32]`; bad → `PaksmithError::InvalidArgument { arg: "--aes-key", reason: ... }`). In `main`, `let key = cli.aes_key.as_deref().map(parse_aes_key).transpose()?;` then pass `key.as_ref()` into `cli.command.run(cli.format, key.as_ref())`.

Change `Command::run(&self, format: OutputFormat, key: Option<&AesKey>) -> Result<u8>` and thread `key` to each command's `run(args, format, key)`:
- `list`/`search`: `match key { Some(k) => PakReader::open_with_key(path, k.clone()), None => PakReader::open(path) }`.
- `extract`: same, wrapped in `Arc::new(...)` (the existing `read_from_reader(&Arc)` path then decrypts uasset/uexp/ubulk via the key-bearing reader).
- `inspect`: replace `Package::read_from_pak(&args.pak, &args.asset, usmap)` with `let reader = Arc::new(match key { Some(k) => PakReader::open_with_key(&args.pak, k.clone())?, None => PakReader::open(&args.pak)? }); Package::read_from_reader(&reader, &args.asset, usmap.as_ref())` (the 4a reader path; the key-bearing reader decrypts the asset + companions).

- [ ] **Step 4: Run — verify pass**
Run: `cargo test -p paksmith-cli` (parse unit + integration + all prior commands unaffected — `key=None` path is byte-identical to before).

- [ ] **Step 5: Commit**
```bash
git add crates/paksmith-cli/src/main.rs crates/paksmith-cli/src/commands/
git commit -m "feat(cli): add global --aes-key to open encrypted paks"
```

---

## Task 6: fixture-gen cross-validation, ROADMAP, gates

**Files:**
- Modify: `crates/paksmith-fixture-gen` (or `paksmith-core-tests`) cross-validation
- Modify: `docs/plans/ROADMAP.md`

- [ ] **Step 1: Cross-validate paksmith vs repak/plaintext**

Now that `open_with_key` works, add a cross-validation test (in `paksmith-core-tests` or the fixture-gen oracle harness, matching how existing fixtures cross-validate): paksmith's `open_with_key` + `read_entry` for every entry equals the plaintext repak wrote. This closes the loop on the encrypted fixtures (no documented coverage gap — unlike 4a/4b, 5a has a real end-to-end encrypted fixture).

- [ ] **Step 2: ROADMAP**
In `docs/plans/ROADMAP.md` Phase 5 section, note 5a shipped (core AES-256-ECB decryption + global `--aes-key`), and that it's the enabler for 5b key management. Factual, brief, no engine-source references.

- [ ] **Step 3: Full gate chain (each UNPIPED; fix any failure)**
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
```
Plus, since this PR adds let-chains-free crypto + a dep, run `cargo +1.88 check -p paksmith-core -p paksmith-cli` if 1.88 is installed (MSRV floor sanity).

- [ ] **Step 4: Commit**
```bash
git add crates/ docs/plans/ROADMAP.md
git commit -m "test(core): cross-validate AES-decrypted reads vs repak; mark 5a shipped"
```

---

## Review & Push

- [ ] Adversarial panel with a **mandatory security specialist** (untrusted-input crypto + parser): key handling/zeroize, wrong-key-fails-closed, no key in logs, decrypt-bounds (no alloc blow-up — index-size cap gates the buffer), the index decrypt-injection correctness, and the entry-decrypt boundary. Plus code-reviewer + architect + a wire-format reviewer (the index/entry decrypt vs the UE/repak layout).
- [ ] Cycle to convergence; re-dispatch the full panel after each fix commit.
- [ ] Touch the convergence marker (separate Bash call), push, open PR (`gh --body-file`), Monitor CI to green (watch the **Minimal versions** + **MSRV 1.88** + **cargo-deny** jobs given the new deps). Do NOT merge — user merges.

---

## Self-Review (plan vs spec)

**Spec coverage:**
- AES-256-ECB primitive + AesKey (zeroize/redacted) → Task 1. ✓
- `open_with_key` + index decrypt (fail-closed) → Task 3. ✓
- per-entry decrypt → Task 4. ✓
- global `--aes-key` across all 4 commands + hex parse + exit 2 → Task 5. ✓
- fixture-gen encrypted fixtures (repak) + cross-validation → Task 2 + Task 6. ✓
- no `ecb`/`cbc` dep (manual block loop) → Task 1. ✓
- `Decryption { path }` kept (no new field) → Tasks 3/4. ✓ (deviation from spec's `reason` field — the existing message already reads "invalid or missing AES key"; documented here.)
- security framing (mandatory specialist) → Review section. ✓
- fixture-count gate bump → Task 2. ✓

**Type consistency:** `AesKey::new([u8;32])`, `aes256_ecb_decrypt(&AesKey, &mut [u8]) -> Result<()>`, `PakIndex::read_positioned(...)`, `PakReader::open_with_key/from_reader_with_key`, `Command::run(&self, OutputFormat, Option<&AesKey>)`, `parse_aes_key(&str) -> Result<AesKey>` are referenced identically across tasks.

**Open implementation points (resolve at the task against live code/fixture, not placeholders — each has a crisp deliverable + test):**
- The exact `aes 0.8` trait/import paths (`KeyInit`/`BlockDecrypt`/`GenericArray`) — adjust to the resolved API; the per-16-byte `decrypt_block` loop is the invariant (Task 1).
- repak's exact `PakBuilder` write-encryption API + which pak version + whether index/entry encryption are separate flags — read `~/.cargo/git/checkouts/repak-*/e215472/repak/src/pak.rs` (Task 2).
- The `from_reader` locals (version, compression_methods, reader handle, index-size cap) for the decrypt-injection; the entry stored/compressed-size accessors + the `stream_entry_to` boundary (Tasks 3/4).
- `AesKey` public re-export path to mirror `PakReader`'s (Task 1).
