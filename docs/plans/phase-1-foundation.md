# Paksmith Phase 1: Foundation & Pak Reading

> **Status: frozen historical spec.** Phase 1 is delivered; this document is preserved as the original design intent and is no longer load-bearing. The implementation diverged in several places — read the code, not this plan, for the current shape:
>
> - **Error model:** issues #28-32 retired the placeholder `InvalidIndex { reason: String }`, the `omits_sha1: bool` flag, the `FNameBasedCompression = 8` enum variant, and the `CompressionMethod::Unknown(u32)` shape. Current source of truth: `crates/paksmith-core/src/error.rs` and `crates/paksmith-core/src/container/pak/index/`.
> - **Public API:** `PakVersion::footer_size()` and `has_encryption_key_guid()` (referenced below) were never implemented as standalone methods; their concerns are folded into the footer parser.
> - **Dependencies:** `tokio` and `indicatif` (mentioned in the tech-stack section) were not used in Phase 1 and are not in `Cargo.toml`.
>
> Do not write new code against the snippets in this document — they reflect pre-refactor types. Use the current modules under `crates/paksmith-core/src/{error,container/pak/version,container/pak/index,container/pak/footer}.rs`.
>
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working `paksmith list` CLI command that reads .pak files and outputs their contents as JSON or a formatted table.

**Architecture:** Cargo workspace with `paksmith-core` (container parsing, error types) and `paksmith-cli` (clap-based command dispatch, output formatting). `paksmith-gui` is scaffolded as a placeholder. TDD throughout — synthetic test fixtures validate the binary parser.

**Tech Stack:** Rust 1.83+, `thiserror`, `byteorder`, `clap` (derive), `serde`/`serde_json`, `comfy-table`, `tracing`, `tokio`, `insta`, `assert_cmd`

---

## File Structure

```plaintext
paksmith/
├── Cargo.toml                              # Workspace root
├── crates/
│   ├── paksmith-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                      # Public API re-exports
│   │       ├── error.rs                    # PaksmithError enum
│   │       └── container/
│   │           ├── mod.rs                  # ContainerReader trait, types
│   │           └── pak/
│   │               ├── mod.rs              # PakReader public API
│   │               ├── footer.rs           # Pak footer parsing
│   │               ├── index.rs            # Pak index/entry parsing
│   │               └── version.rs          # Pak version enum + constants
│   ├── paksmith-cli/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                     # Entry point, CLI dispatch
│   │       ├── commands/
│   │       │   ├── mod.rs                  # Command module
│   │       │   └── list.rs                 # `list` command
│   │       └── output.rs                   # JSON/table formatting
│   └── paksmith-gui/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                     # Placeholder
├── tests/
│   └── fixtures/
│       ├── generate.rs                     # Fixture generator binary
│       └── minimal_v11.pak                 # Generated test pak
├── .github/
│   └── workflows/
│       └── ci.yml                          # Cross-platform CI
├── .gitignore
├── CLAUDE.md
└── README.md
```

---

### Task 1: Workspace Scaffolding

**Files:**

- Create: `paksmith/Cargo.toml`
- Create: `paksmith/crates/paksmith-core/Cargo.toml`
- Create: `paksmith/crates/paksmith-core/src/lib.rs`
- Create: `paksmith/crates/paksmith-cli/Cargo.toml`
- Create: `paksmith/crates/paksmith-cli/src/main.rs`
- Create: `paksmith/crates/paksmith-gui/Cargo.toml`
- Create: `paksmith/crates/paksmith-gui/src/main.rs`
- Create: `paksmith/.gitignore`
- Create: `paksmith/CLAUDE.md`
- Create: `paksmith/README.md`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.85"

[workspace.dependencies]
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
byteorder = "1"
tracing = "0.1"
tokio = { version = "1", features = ["full"] }
```

- [ ] **Step 2: Create paksmith-core crate**

`crates/paksmith-core/Cargo.toml`:

```toml
[package]
name = "paksmith-core"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
byteorder.workspace = true
tracing.workspace = true

[dev-dependencies]
proptest = "1"
```

`crates/paksmith-core/src/lib.rs`:

```rust
pub mod container;
pub mod error;

pub use error::PaksmithError;
pub type Result<T> = std::result::Result<T, PaksmithError>;
```

- [ ] **Step 3: Create paksmith-cli crate**

`crates/paksmith-cli/Cargo.toml`:

```toml
[package]
name = "paksmith-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "paksmith"
path = "src/main.rs"

[dependencies]
paksmith-core = { path = "../paksmith-core" }
clap = { version = "4", features = ["derive"] }
serde_json.workspace = true
comfy-table = "7"
tracing.workspace = true
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tokio.workspace = true
indicatif = "0.17"
```

`crates/paksmith-cli/src/main.rs`:

```rust
fn main() {
    println!("paksmith");
}
```

- [ ] **Step 4: Create paksmith-gui placeholder crate**

`crates/paksmith-gui/Cargo.toml`:

```toml
[package]
name = "paksmith-gui"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
paksmith-core = { path = "../paksmith-core" }
iced = "0.13"
```

`crates/paksmith-gui/src/main.rs`:

```rust
fn main() {
    println!("paksmith-gui: not yet implemented");
}
```

- [ ] **Step 5: Create .gitignore**

```gitignore
/target
*.swp
*.swo
.DS_Store
```

- [ ] **Step 6: Create CLAUDE.md**

```markdown
# Paksmith

Cross-platform Rust rewrite of FModel for exploring and extracting Unreal Engine game assets.

## Build

- `cargo build` — build all crates
- `cargo test` — run all tests
- `cargo run -p paksmith-cli -- <args>` — run the CLI
- `cargo clippy --workspace -- -D warnings` — lint

## Architecture

Cargo workspace with three crates:

- `paksmith-core` — library: format parsing, container I/O, traits
- `paksmith-cli` — binary: command-line interface
- `paksmith-gui` — binary: Iced GUI (in progress)

Core is the load-bearing crate. CLI and GUI are thin frontends.

## Conventions

- TDD: write failing test first, then implement
- `thiserror` for error types, `tracing` for logging
- No panics in core — all fallible ops return `Result`
- `byteorder` for binary parsing (little-endian unless noted)
- Commits: conventional commits (feat:, fix:, chore:)
```

- [ ] **Step 7: Create README.md**

````markdown
# Paksmith

A cross-platform tool for exploring and extracting Unreal Engine game assets. Written in Rust.

## Status

Early development. Currently supports listing .pak archive contents.

## Installation

```sh
cargo install --path crates/paksmith-cli
```

## Usage

```sh
paksmith list path/to/game.pak
paksmith list path/to/game.pak --format json
```

## License

MIT

````

- [ ] **Step 8: Initialize git and verify workspace compiles**

```bash
cd /Users/rob/Projects/Code/paksmith
git init
cargo check --workspace
````

Expected: compiles with no errors (lib.rs references modules that don't exist yet — fix in next step).

- [ ] **Step 9: Create placeholder modules so the workspace compiles**

`crates/paksmith-core/src/error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum PaksmithError {
    #[error("not yet implemented")]
    NotImplemented,
}
```

`crates/paksmith-core/src/container/mod.rs`:

```rust
pub mod pak;
```

`crates/paksmith-core/src/container/pak/mod.rs`:

```rust
pub mod footer;
pub mod index;
pub mod version;
```

`crates/paksmith-core/src/container/pak/footer.rs`:

```rust

```

`crates/paksmith-core/src/container/pak/index.rs`:

```rust

```

`crates/paksmith-core/src/container/pak/version.rs`:

```rust

```

- [ ] **Step 10: Verify full workspace compiles and commit**

```bash
cargo check --workspace
git add -A
git commit -m "chore: scaffold workspace with core, cli, and gui crates"
```

Expected: clean compile, no warnings.

---

### Task 2: Core Error Types

**Files:**

- Modify: `crates/paksmith-core/src/error.rs`
- Test: inline `#[cfg(test)]` module

- [ ] **Step 1: Write tests for error display formatting**

`crates/paksmith-core/src/error.rs`:

```rust
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum PaksmithError {
    #[error("decryption failed for `{path}`: invalid or missing AES key")]
    Decryption { path: String },

    #[error("unsupported pak version {version}")]
    UnsupportedVersion { version: u32 },

    #[error("decompression failed at offset {offset}")]
    Decompression { offset: u64 },

    #[error("asset deserialization failed for `{asset_path}`: {reason}")]
    AssetParse { reason: String, asset_path: String },

    #[error("invalid pak footer: {reason}")]
    InvalidFooter { reason: String },

    #[error("invalid pak index: {reason}")]
    InvalidIndex { reason: String },

    #[error("entry not found: `{path}`")]
    EntryNotFound { path: String },

    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_decryption() {
        let err = PaksmithError::Decryption {
            path: "Game/Content.pak".into(),
        };
        assert_eq!(
            err.to_string(),
            "decryption failed for `Game/Content.pak`: invalid or missing AES key"
        );
    }

    #[test]
    fn error_display_unsupported_version() {
        let err = PaksmithError::UnsupportedVersion { version: 99 };
        assert_eq!(err.to_string(), "unsupported pak version 99");
    }

    #[test]
    fn error_display_invalid_footer() {
        let err = PaksmithError::InvalidFooter {
            reason: "magic mismatch".into(),
        };
        assert_eq!(err.to_string(), "invalid pak footer: magic mismatch");
    }

    #[test]
    fn error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let err: PaksmithError = io_err.into();
        assert!(matches!(err, PaksmithError::Io(_)));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p paksmith-core
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-core/src/error.rs
git commit -m "feat(core): add PaksmithError with contextual error variants"
```

---

### Task 3: Pak Version Definitions

**Files:**

- Modify: `crates/paksmith-core/src/container/pak/version.rs`

- [ ] **Step 1: Write tests for version properties**

`crates/paksmith-core/src/container/pak/version.rs`:

```rust
/// Pak file format version.
///
/// Versions correspond to UE engine evolution. Each version adds fields
/// to the footer and/or index entry format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum PakVersion {
    Initial = 1,
    NoTimestamps = 2,
    CompressionEncryption = 3,
    IndexEncryption = 4,
    RelativeChunkOffsets = 5,
    DeleteRecords = 6,
    EncryptionKeyGuid = 7,
    FNameBasedCompression = 8,
    FrozenIndex = 9,
    PathHashIndex = 10,
    Fnv64BugFix = 11,
}

impl PakVersion {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Initial),
            2 => Some(Self::NoTimestamps),
            3 => Some(Self::CompressionEncryption),
            4 => Some(Self::IndexEncryption),
            5 => Some(Self::RelativeChunkOffsets),
            6 => Some(Self::DeleteRecords),
            7 => Some(Self::EncryptionKeyGuid),
            8 => Some(Self::FNameBasedCompression),
            9 => Some(Self::FrozenIndex),
            10 => Some(Self::PathHashIndex),
            11 => Some(Self::Fnv64BugFix),
            _ => None,
        }
    }

    pub fn has_encryption_key_guid(self) -> bool {
        self >= Self::EncryptionKeyGuid
    }

    pub fn has_path_hash_index(self) -> bool {
        self >= Self::PathHashIndex
    }

    pub fn footer_size(self) -> u64 {
        if self >= Self::EncryptionKeyGuid {
            // magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20) + encryption_guid(16) + encrypted_flag(1)
            61
        } else {
            // magic(4) + version(4) + index_offset(8) + index_size(8) + index_hash(20)
            44
        }
    }
}

pub const PAK_MAGIC: u32 = 0x5A6F12E1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_u32_valid() {
        assert_eq!(PakVersion::from_u32(1), Some(PakVersion::Initial));
        assert_eq!(PakVersion::from_u32(7), Some(PakVersion::EncryptionKeyGuid));
        assert_eq!(PakVersion::from_u32(11), Some(PakVersion::Fnv64BugFix));
    }

    #[test]
    fn version_from_u32_invalid() {
        assert_eq!(PakVersion::from_u32(0), None);
        assert_eq!(PakVersion::from_u32(12), None);
        assert_eq!(PakVersion::from_u32(99), None);
    }

    #[test]
    fn version_ordering() {
        assert!(PakVersion::Initial < PakVersion::EncryptionKeyGuid);
        assert!(PakVersion::Fnv64BugFix > PakVersion::PathHashIndex);
    }

    #[test]
    fn encryption_guid_threshold() {
        assert!(!PakVersion::DeleteRecords.has_encryption_key_guid());
        assert!(PakVersion::EncryptionKeyGuid.has_encryption_key_guid());
        assert!(PakVersion::Fnv64BugFix.has_encryption_key_guid());
    }

    #[test]
    fn footer_size_pre_v7() {
        assert_eq!(PakVersion::Initial.footer_size(), 44);
        assert_eq!(PakVersion::DeleteRecords.footer_size(), 44);
    }

    #[test]
    fn footer_size_v7_plus() {
        assert_eq!(PakVersion::EncryptionKeyGuid.footer_size(), 61);
        assert_eq!(PakVersion::Fnv64BugFix.footer_size(), 61);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p paksmith-core -- pak::version
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-core/src/container/pak/version.rs
git commit -m "feat(core): add PakVersion enum with format metadata"
```

---

### Task 4: Pak Footer Parsing

**Files:**

- Modify: `crates/paksmith-core/src/container/pak/footer.rs`

- [ ] **Step 1: Write tests for footer parsing**

`crates/paksmith-core/src/container/pak/footer.rs`:

```rust
use std::io::{self, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::PaksmithError;
use crate::container::pak::version::{PakVersion, PAK_MAGIC};

#[derive(Debug, Clone)]
pub struct PakFooter {
    pub version: PakVersion,
    pub index_offset: u64,
    pub index_size: u64,
    pub index_hash: [u8; 20],
    pub encrypted: bool,
    pub encryption_key_guid: Option<[u8; 16]>,
}

impl PakFooter {
    pub fn read_from<R: Read + Seek>(reader: &mut R) -> crate::Result<Self> {
        // Try v7+ footer first (larger), fall back to legacy
        let file_size = reader.seek(SeekFrom::End(0))?;

        // Try v7+ size first
        let v7_footer_size = PakVersion::EncryptionKeyGuid.footer_size();
        if file_size >= v7_footer_size {
            reader.seek(SeekFrom::End(-(v7_footer_size as i64)))?;
            if let Ok(footer) = Self::try_read_v7_plus(reader) {
                return Ok(footer);
            }
        }

        // Fall back to legacy footer
        let legacy_footer_size = PakVersion::Initial.footer_size();
        if file_size < legacy_footer_size {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("file too small ({file_size} bytes) for pak footer"),
            });
        }

        reader.seek(SeekFrom::End(-(legacy_footer_size as i64)))?;
        Self::try_read_legacy(reader)
    }

    fn try_read_v7_plus<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"),
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version = PakVersion::from_u32(version_raw).ok_or(PaksmithError::UnsupportedVersion {
            version: version_raw,
        })?;

        if !version.has_encryption_key_guid() {
            return Err(PaksmithError::InvalidFooter {
                reason: "not a v7+ footer".into(),
            });
        }

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        let mut encryption_key_guid = [0u8; 16];
        reader.read_exact(&mut encryption_key_guid)?;

        let encrypted = reader.read_u8()? != 0;

        Ok(Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted,
            encryption_key_guid: Some(encryption_key_guid),
        })
    }

    fn try_read_legacy<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"),
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version = PakVersion::from_u32(version_raw).ok_or(PaksmithError::UnsupportedVersion {
            version: version_raw,
        })?;

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        Ok(Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted: false,
            encryption_key_guid: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use byteorder::WriteBytesExt;

    fn build_v11_footer(index_offset: u64, index_size: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        // Prepend some fake data so the file is bigger than the footer
        buf.extend_from_slice(&[0xAA; 100]);

        // Footer starts here
        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(11).unwrap(); // version
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index hash
        buf.extend_from_slice(&[0u8; 16]); // encryption GUID
        buf.push(0); // not encrypted
        buf
    }

    fn build_legacy_footer(version: u32, index_offset: u64, index_size: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAA; 100]);

        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(version).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index hash
        buf
    }

    #[test]
    fn parse_v11_footer() {
        let data = build_v11_footer(1024, 256);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version, PakVersion::Fnv64BugFix);
        assert_eq!(footer.index_offset, 1024);
        assert_eq!(footer.index_size, 256);
        assert!(!footer.encrypted);
        assert!(footer.encryption_key_guid.is_some());
    }

    #[test]
    fn parse_legacy_v3_footer() {
        let data = build_legacy_footer(3, 512, 128);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version, PakVersion::CompressionEncryption);
        assert_eq!(footer.index_offset, 512);
        assert_eq!(footer.index_size, 128);
        assert!(!footer.encrypted);
        assert!(footer.encryption_key_guid.is_none());
    }

    #[test]
    fn reject_bad_magic() {
        let mut data = build_v11_footer(0, 0);
        // Corrupt the magic at the footer position (100 bytes of padding + first 4 bytes)
        let footer_start = data.len() - 61;
        data[footer_start] = 0xFF;

        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_unsupported_version() {
        let mut data = build_legacy_footer(99, 0, 0);
        // Replace version with 99 in legacy footer
        let footer_start = data.len() - 44;
        data[footer_start + 4] = 99; // version byte (LE)
        // Also corrupt the v7 read attempt by not having a valid v7 footer
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(
            matches!(err, PaksmithError::UnsupportedVersion { version: 99 })
                || matches!(err, PaksmithError::InvalidFooter { .. })
        );
    }

    #[test]
    fn reject_file_too_small() {
        let data = vec![0u8; 10]; // Way too small for any footer
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p paksmith-core -- pak::footer
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-core/src/container/pak/footer.rs
git commit -m "feat(core): implement pak footer parsing (v1-v11)"
```

---

### Task 5: Pak Index Parsing

**Files:**

- Modify: `crates/paksmith-core/src/container/pak/index.rs`

- [ ] **Step 1: Write tests and implementation for index entry parsing**

`crates/paksmith-core/src/container/pak/index.rs`:

```rust
use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::PaksmithError;
use crate::container::pak::version::PakVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    None,
    Zlib,
    Gzip,
    Oodle,
    Unknown(u32),
}

impl CompressionMethod {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Zlib,
            2 => Self::Gzip,
            4 => Self::Oodle,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PakIndexEntry {
    pub filename: String,
    pub offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct PakIndex {
    pub mount_point: String,
    pub entries: Vec<PakIndexEntry>,
}

impl PakIndex {
    pub fn read_from<R: Read>(reader: &mut R, _version: PakVersion) -> crate::Result<Self> {
        let mount_point = read_fstring(reader)?;
        let entry_count = reader.read_u32::<LittleEndian>()?;

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(PakIndexEntry::read_from(reader)?);
        }

        Ok(Self {
            mount_point,
            entries,
        })
    }
}

impl PakIndexEntry {
    fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let filename = read_fstring(reader)?;
        let offset = reader.read_u64::<LittleEndian>()?;
        let compressed_size = reader.read_u64::<LittleEndian>()?;
        let uncompressed_size = reader.read_u64::<LittleEndian>()?;
        let compression_raw = reader.read_u32::<LittleEndian>()?;
        let compression_method = CompressionMethod::from_u32(compression_raw);

        // 20-byte SHA1 hash
        let mut _hash = [0u8; 20];
        reader.read_exact(&mut _hash)?;

        // Compression blocks (if compressed)
        let has_blocks = compression_method != CompressionMethod::None;
        if has_blocks {
            let block_count = reader.read_u32::<LittleEndian>()?;
            for _ in 0..block_count {
                let _block_start = reader.read_u64::<LittleEndian>()?;
                let _block_end = reader.read_u64::<LittleEndian>()?;
            }
        }

        let is_encrypted = reader.read_u8()? != 0;

        // Compression block size (present when blocks exist)
        if has_blocks {
            let _block_size = reader.read_u32::<LittleEndian>()?;
        }

        Ok(Self {
            filename,
            offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            is_encrypted,
        })
    }
}

fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    if len == 0 {
        return Ok(String::new());
    }

    // Negative length means UTF-16 encoded
    if len < 0 {
        let char_count = (-len) as usize;
        let mut buf = vec![0u16; char_count];
        for item in &mut buf {
            *item = reader.read_u16::<LittleEndian>()?;
        }
        // Strip null terminator
        if buf.last() == Some(&0) {
            buf.pop();
        }
        return String::from_utf16(&buf).map_err(|_| PaksmithError::InvalidIndex {
            reason: "invalid UTF-16 string in index".into(),
        });
    }

    // Positive length: UTF-8 (with null terminator included in length)
    let len = len as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    // Strip null terminator
    if buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| PaksmithError::InvalidIndex {
        reason: "invalid UTF-8 string in index".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use byteorder::WriteBytesExt;

    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        // Length includes null terminator
        buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32).unwrap();
        buf.extend_from_slice(bytes);
        buf.push(0); // null terminator
    }

    fn write_uncompressed_entry(buf: &mut Vec<u8>, filename: &str, offset: u64, size: u64) {
        write_fstring(buf, filename);
        buf.write_u64::<LittleEndian>(offset).unwrap();
        buf.write_u64::<LittleEndian>(size).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // no compression
        buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
        buf.push(0); // not encrypted
    }

    #[test]
    fn parse_index_single_entry() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(1).unwrap(); // 1 entry
        write_uncompressed_entry(&mut data, "Content/Textures/hero.uasset", 0, 1024);

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.mount_point, "../../../");
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].filename, "Content/Textures/hero.uasset");
        assert_eq!(index.entries[0].uncompressed_size, 1024);
        assert_eq!(index.entries[0].compression_method, CompressionMethod::None);
        assert!(!index.entries[0].is_encrypted);
    }

    #[test]
    fn parse_index_multiple_entries() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(3).unwrap();
        write_uncompressed_entry(&mut data, "Content/a.uasset", 0, 100);
        write_uncompressed_entry(&mut data, "Content/b.uasset", 100, 200);
        write_uncompressed_entry(&mut data, "Content/c.uasset", 300, 50);

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.entries.len(), 3);
        assert_eq!(index.entries[0].filename, "Content/a.uasset");
        assert_eq!(index.entries[1].filename, "Content/b.uasset");
        assert_eq!(index.entries[2].filename, "Content/c.uasset");
        assert_eq!(index.entries[2].uncompressed_size, 50);
    }

    #[test]
    fn parse_empty_index() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(0).unwrap(); // 0 entries

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.entries.len(), 0);
        assert_eq!(index.mount_point, "../../../");
    }

    #[test]
    fn compression_method_from_u32() {
        assert_eq!(CompressionMethod::from_u32(0), CompressionMethod::None);
        assert_eq!(CompressionMethod::from_u32(1), CompressionMethod::Zlib);
        assert_eq!(CompressionMethod::from_u32(4), CompressionMethod::Oodle);
        assert_eq!(CompressionMethod::from_u32(99), CompressionMethod::Unknown(99));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p paksmith-core -- pak::index
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-core/src/container/pak/index.rs
git commit -m "feat(core): implement pak index parsing with FString support"
```

---

### Task 6: Container Trait & PakReader

**Files:**

- Modify: `crates/paksmith-core/src/container/mod.rs`
- Modify: `crates/paksmith-core/src/container/pak/mod.rs`

- [ ] **Step 1: Define ContainerReader trait and types**

`crates/paksmith-core/src/container/mod.rs`:

```rust
pub mod pak;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ContainerFormat {
    Pak,
    IoStore,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryMetadata {
    pub path: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_compressed: bool,
    pub is_encrypted: bool,
}

pub trait ContainerReader: Send + Sync {
    fn list_entries(&self) -> &[EntryMetadata];
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>>;
    fn format(&self) -> ContainerFormat;
    fn mount_point(&self) -> &str;
}
```

- [ ] **Step 2: Implement PakReader**

`crates/paksmith-core/src/container/pak/mod.rs`:

```rust
pub mod footer;
pub mod index;
pub mod version;

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::PaksmithError;
use crate::container::{ContainerFormat, ContainerReader, EntryMetadata};

use self::footer::PakFooter;
use self::index::{CompressionMethod, PakIndex};
use self::version::PakVersion;

pub struct PakReader {
    path: std::path::PathBuf,
    footer: PakFooter,
    index: PakIndex,
    entries: Vec<EntryMetadata>,
}

impl PakReader {
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = BufReader::new(File::open(&path)?);

        let footer = PakFooter::read_from(&mut file)?;

        if footer.encrypted {
            return Err(PaksmithError::Decryption {
                path: path.display().to_string(),
            });
        }

        file.seek(SeekFrom::Start(footer.index_offset))?;
        let index = PakIndex::read_from(&mut file, footer.version)?;

        let entries = index
            .entries
            .iter()
            .map(|e| EntryMetadata {
                path: e.filename.clone(),
                compressed_size: e.compressed_size,
                uncompressed_size: e.uncompressed_size,
                is_compressed: e.compression_method != CompressionMethod::None,
                is_encrypted: e.is_encrypted,
            })
            .collect();

        Ok(Self {
            path,
            footer,
            index,
            entries,
        })
    }

    pub fn version(&self) -> PakVersion {
        self.footer.version
    }
}

impl ContainerReader for PakReader {
    fn list_entries(&self) -> &[EntryMetadata] {
        &self.entries
    }

    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let entry = self
            .index
            .entries
            .iter()
            .find(|e| e.filename == path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        if entry.compression_method != CompressionMethod::None {
            return Err(PaksmithError::Decompression {
                offset: entry.offset,
            });
        }

        if entry.is_encrypted {
            return Err(PaksmithError::Decryption {
                path: path.to_string(),
            });
        }

        let mut file = BufReader::new(File::open(&self.path)?);
        file.seek(SeekFrom::Start(entry.offset))?;

        // Entry data is preceded by a serialized record header in the file;
        // for uncompressed entries we can read directly from the offset.
        // NOTE: The actual on-disk format includes an entry header before raw data.
        // For now, read uncompressed_size bytes at the offset. This will be refined
        // when we add full entry header parsing for on-disk layout.
        let mut buf = vec![0u8; entry.uncompressed_size as usize];
        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        &self.index.mount_point
    }
}
```

- [ ] **Step 3: Run all core tests to verify nothing is broken**

```bash
cargo test -p paksmith-core
```

Expected: all prior tests still pass. (PakReader itself will be integration-tested with a fixture in Task 7.)

- [ ] **Step 4: Commit**

```bash
git add crates/paksmith-core/src/container/mod.rs crates/paksmith-core/src/container/pak/mod.rs
git commit -m "feat(core): add ContainerReader trait and PakReader implementation"
```

---

### Task 7: Test Fixture Generator & Integration Test

**Files:**

- Create: `tests/fixtures/generate.rs` (standalone binary for generating fixtures)
- Create: `tests/fixtures/README.md`
- Create: `crates/paksmith-core/tests/pak_integration.rs`

- [ ] **Step 1: Create fixture generator**

`tests/fixtures/generate.rs`:

```rust
//! Run with: cargo run --example generate_fixtures
//! Generates synthetic .pak files for testing.

use std::fs::File;
use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

const PAK_MAGIC: u32 = 0x5A6F12E1;

fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32).unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

fn write_entry_record(buf: &mut Vec<u8>, filename: &str, offset: u64, size: u64) {
    write_fstring(buf, filename);
    buf.write_u64::<LittleEndian>(offset).unwrap(); // offset
    buf.write_u64::<LittleEndian>(size).unwrap(); // compressed size
    buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed size
    buf.write_u32::<LittleEndian>(0).unwrap(); // compression: none
    buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
    buf.push(0); // not encrypted
}

fn write_v11_footer(buf: &mut Vec<u8>, index_offset: u64, index_size: u64) {
    buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    buf.write_u32::<LittleEndian>(11).unwrap();
    buf.write_u64::<LittleEndian>(index_offset).unwrap();
    buf.write_u64::<LittleEndian>(index_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // index hash
    buf.extend_from_slice(&[0u8; 16]); // encryption GUID
    buf.push(0); // not encrypted
}

fn main() {
    let entries = vec![
        ("Content/Textures/hero.uasset", b"HERO_TEXTURE_DATA_HERE" as &[u8]),
        ("Content/Maps/level01.umap", b"LEVEL01_MAP_DATA"),
        ("Content/Sounds/bgm.uasset", b"BGM_SOUND_DATA_PLACEHOLDER"),
    ];

    // Build data section
    let mut data_section = Vec::new();
    let mut offsets: Vec<(String, u64, u64)> = Vec::new();

    for (name, content) in &entries {
        let offset = data_section.len() as u64;
        data_section.extend_from_slice(content);
        offsets.push((name.to_string(), offset, content.len() as u64));
    }

    // Build index
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(entries.len() as u32).unwrap();
    for (name, offset, size) in &offsets {
        write_entry_record(&mut index_section, name, *offset, *size);
    }

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    // Assemble final file: data + index + footer
    let mut pak_file = Vec::new();
    pak_file.extend_from_slice(&data_section);
    pak_file.extend_from_slice(&index_section);
    write_v11_footer(&mut pak_file, index_offset, index_size);

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/minimal_v11.pak");
    std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
    let mut f = File::create(&fixture_path).unwrap();
    f.write_all(&pak_file).unwrap();

    println!("Generated: {}", fixture_path.display());
    println!("  Data section: {} bytes", data_section.len());
    println!("  Index: {} bytes at offset {}", index_size, index_offset);
    println!("  Total: {} bytes", pak_file.len());
    println!("  Entries: {}", entries.len());
}
```

- [ ] **Step 2: Add as an example in paksmith-core's Cargo.toml and generate the fixture**

Add to `crates/paksmith-core/Cargo.toml`:

```toml
[[example]]
name = "generate_fixtures"
path = "../../tests/fixtures/generate.rs"
```

```bash
cargo run -p paksmith-core --example generate_fixtures
```

Expected: prints generation summary, creates `tests/fixtures/minimal_v11.pak`.

- [ ] **Step 3: Write integration test**

`crates/paksmith-core/tests/pak_integration.rs`:

```rust
use paksmith_core::container::{ContainerFormat, ContainerReader};
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PakVersion;

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

#[test]
fn open_minimal_v11_pak() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    assert_eq!(reader.version(), PakVersion::Fnv64BugFix);
    assert_eq!(reader.format(), ContainerFormat::Pak);
    assert_eq!(reader.mount_point(), "../../../");
}

#[test]
fn list_entries_minimal_v11() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let entries = reader.list_entries();

    assert_eq!(entries.len(), 3);

    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
}

#[test]
fn entry_metadata_correct() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let entries = reader.list_entries();

    let hero = entries.iter().find(|e| e.path.contains("hero")).unwrap();
    assert_eq!(hero.uncompressed_size, 22); // b"HERO_TEXTURE_DATA_HERE".len()
    assert!(!hero.is_compressed);
    assert!(!hero.is_encrypted);
}

#[test]
fn read_entry_data() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let data = reader.read_entry("Content/Textures/hero.uasset").unwrap();
    assert_eq!(data, b"HERO_TEXTURE_DATA_HERE");
}

#[test]
fn read_entry_not_found() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let err = reader.read_entry("Content/DoesNotExist.uasset").unwrap_err();
    assert!(matches!(err, paksmith_core::PaksmithError::EntryNotFound { .. }));
}

#[test]
fn open_nonexistent_file() {
    let err = PakReader::open("/tmp/this_does_not_exist.pak").unwrap_err();
    assert!(matches!(err, paksmith_core::PaksmithError::Io(_)));
}
```

- [ ] **Step 4: Run integration tests**

```bash
cargo test -p paksmith-core --test pak_integration
```

Expected: 6 tests pass.

- [ ] **Step 5: Create fixtures README**

`tests/fixtures/README.md`:

````markdown
# Test Fixtures

Synthetic .pak files for testing paksmith's container parsers.

## Regenerating

```sh
cargo run -p paksmith-core --example generate_fixtures
```

## Files

- `minimal_v11.pak` — v11 pak with 3 uncompressed, unencrypted entries

````

- [ ] **Step 6: Commit**

```bash
git add tests/ crates/paksmith-core/Cargo.toml crates/paksmith-core/tests/
git commit -m "feat(core): add pak integration tests with synthetic fixture"
````

---

### Task 8: CLI Scaffolding with `list` Command

**Files:**

- Modify: `crates/paksmith-cli/src/main.rs`
- Create: `crates/paksmith-cli/src/commands/mod.rs`
- Create: `crates/paksmith-cli/src/commands/list.rs`
- Create: `crates/paksmith-cli/src/output.rs`

- [ ] **Step 1: Define CLI structure with clap**

`crates/paksmith-cli/src/main.rs`:

```rust
mod commands;
mod output;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "paksmith", version, about = "Explore and extract Unreal Engine game assets")]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,

    /// Output format
    #[arg(long, global = true, default_value = "auto")]
    format: output::OutputFormat,

    /// Verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match cli.command.run(cli.format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
```

- [ ] **Step 2: Define command dispatch**

`crates/paksmith-cli/src/commands/mod.rs`:

```rust
pub mod list;

use clap::Subcommand;

use crate::output::OutputFormat;

#[derive(Subcommand)]
pub enum Command {
    /// List archive contents
    List(list::ListArgs),
}

impl Command {
    pub fn run(&self, format: OutputFormat) -> paksmith_core::Result<()> {
        match self {
            Self::List(args) => list::run(args, format),
        }
    }
}
```

- [ ] **Step 3: Implement list command**

`crates/paksmith-cli/src/commands/list.rs`:

```rust
use std::path::PathBuf;

use clap::Args;

use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

use crate::output::OutputFormat;

#[derive(Args)]
pub struct ListArgs {
    /// Path to .pak file
    pub path: PathBuf,

    /// Filter entries by glob pattern
    #[arg(long)]
    pub filter: Option<String>,
}

pub fn run(args: &ListArgs, format: OutputFormat) -> paksmith_core::Result<()> {
    let reader = PakReader::open(&args.path)?;
    let entries = reader.list_entries();

    let filtered: Vec<_> = match &args.filter {
        Some(pattern) => {
            let pat = glob::Pattern::new(pattern).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
            entries.iter().filter(|e| pat.matches(&e.path)).collect()
        }
        None => entries.iter().collect(),
    };

    let format = format.resolve();
    crate::output::print_entries(&filtered, format);
    Ok(())
}
```

- [ ] **Step 4: Implement output formatting**

`crates/paksmith-cli/src/output.rs`:

```rust
use std::io::IsTerminal;

use comfy_table::{Table, presets::UTF8_FULL_CONDENSED};
use serde::Serialize;

use paksmith_core::container::EntryMetadata;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Auto,
    Json,
    Table,
}

impl OutputFormat {
    pub fn resolve(self) -> ResolvedFormat {
        match self {
            Self::Json => ResolvedFormat::Json,
            Self::Table => ResolvedFormat::Table,
            Self::Auto => {
                if std::io::stdout().is_terminal() {
                    ResolvedFormat::Table
                } else {
                    ResolvedFormat::Json
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResolvedFormat {
    Json,
    Table,
}

#[derive(Serialize)]
struct EntryRow<'a> {
    path: &'a str,
    size: u64,
    compressed_size: u64,
    compressed: bool,
    encrypted: bool,
}

pub fn print_entries(entries: &[&EntryMetadata], format: ResolvedFormat) {
    match format {
        ResolvedFormat::Json => {
            let rows: Vec<EntryRow> = entries
                .iter()
                .map(|e| EntryRow {
                    path: &e.path,
                    size: e.uncompressed_size,
                    compressed_size: e.compressed_size,
                    compressed: e.is_compressed,
                    encrypted: e.is_encrypted,
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        }
        ResolvedFormat::Table => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL_CONDENSED);
            table.set_header(vec!["Path", "Size", "Compressed", "Encrypted"]);

            for entry in entries {
                table.add_row(vec![
                    entry.path.clone(),
                    format_size(entry.uncompressed_size),
                    if entry.is_compressed { "yes".into() } else { "no".into() },
                    if entry.is_encrypted { "yes".into() } else { "no".into() },
                ]);
            }

            println!("{table}");
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
```

- [ ] **Step 5: Add `glob` dependency to CLI Cargo.toml**

Add to `[dependencies]` in `crates/paksmith-cli/Cargo.toml`:

```toml
glob = "0.3"
```

- [ ] **Step 6: Verify it compiles and runs**

```bash
cargo build -p paksmith-cli
cargo run -p paksmith-cli -- list tests/fixtures/minimal_v11.pak
cargo run -p paksmith-cli -- list tests/fixtures/minimal_v11.pak --format json
```

Expected: table output shows 3 entries in the first run, JSON array in the second.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-cli/
git commit -m "feat(cli): implement 'list' command with JSON and table output"
```

---

### Task 9: CLI Integration Tests

**Files:**

- Create: `crates/paksmith-cli/tests/cli_integration.rs`

- [ ] **Step 1: Write CLI integration tests using assert_cmd and insta**

Add to `crates/paksmith-cli/Cargo.toml`:

```toml
[dev-dependencies]
assert_cmd = "2"
predicates = "3"
insta = { version = "1", features = ["json"] }
```

`crates/paksmith-cli/tests/cli_integration.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(name: &str) -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

#[test]
fn list_json_output() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v11.pak"), "--format", "json"]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 3);

    let paths: Vec<&str> = arr
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
}

#[test]
fn list_table_output() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", &fixture_path("minimal_v11.pak"), "--format", "table"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("hero.uasset"))
        .stdout(predicate::str::contains("level01.umap"))
        .stdout(predicate::str::contains("bgm.uasset"));
}

#[test]
fn list_with_filter() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args([
        "list",
        &fixture_path("minimal_v11.pak"),
        "--format", "json",
        "--filter", "*.uasset",
    ]);

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 2); // hero.uasset and bgm.uasset, not level01.umap
}

#[test]
fn list_nonexistent_file() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.args(["list", "/tmp/nonexistent_file.pak"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn no_args_shows_help() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn version_flag() {
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("paksmith"));
}
```

- [ ] **Step 2: Run CLI integration tests**

```bash
cargo test -p paksmith-cli --test cli_integration
```

Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/paksmith-cli/Cargo.toml crates/paksmith-cli/tests/
git commit -m "test(cli): add integration tests for list command"
```

---

### Task 10: CI Workflow

**Files:**

- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create GitHub Actions CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    name: Check (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --workspace

  test:
    name: Test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo run -p paksmith-core --example generate_fixtures
      - run: cargo test --workspace

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace -- -D warnings
```

- [ ] **Step 2: Verify workflow file is valid YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" 2>/dev/null && echo "valid" || echo "invalid"
```

Expected: "valid"

- [ ] **Step 3: Commit**

```bash
git add .github/
git commit -m "chore: add cross-platform CI workflow (check, test, lint)"
```

---

### Task 11: Final Verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test --workspace
```

Expected: all tests pass (unit + integration for core, integration for CLI).

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: no warnings or errors.

- [ ] **Step 3: Run formatter check**

```bash
cargo fmt --all -- --check
```

Expected: no formatting issues (or run `cargo fmt --all` to fix).

- [ ] **Step 4: Verify the binary works end-to-end**

```bash
cargo run -p paksmith-cli -- list tests/fixtures/minimal_v11.pak
cargo run -p paksmith-cli -- list tests/fixtures/minimal_v11.pak --format json | python3 -m json.tool
cargo run -p paksmith-cli -- list tests/fixtures/minimal_v11.pak --filter "*.umap" --format json
```

Expected: table with 3 entries, valid JSON array with 3 entries, JSON array with 1 entry (level01.umap).

- [ ] **Step 5: Final commit if any formatting fixes were needed**

```bash
git status
# If changes: git add -A && git commit -m "chore: apply rustfmt"
```
