//! Unreal Engine `.pak` archive reader.
//!
//! # Supported scope
//!
//! This reader implements:
//! - Footer parsing for v1–v11 paks.
//! - Flat-entry index layout for v3–v9.
//! - **Path-hash + encoded-directory index** for v10/v11 (the bit-packed
//!   FPakEntry format, full-directory-index walk, and FNV-1a path
//!   hashing for cross-archive lookup; see
//!   [`crate::container::pak::index::PakIndex::read_from`] for dispatch).
//! - V8+ FName-based compression-method indirection (the per-entry
//!   compression byte is a 1-based index into a 4- or 5-slot FName table
//!   stored in the footer; resolution happens in
//!   [`crate::container::pak::index::PakEntryHeader::read_from`]).
//! - V8A's narrower u8 compression byte (V8B and later use u32).
//! - V9's optional `frozen_index` flag (parsed for round-trip; v9
//!   archives with frozen=true are rejected at open since the index
//!   region would be in UE's compiled-frozen layout).
//! - The duplicate FPakEntry record header that real archives write before
//!   each payload at [`crate::container::pak::index::PakEntryHeader::offset`],
//!   with cross-validation against the index entry.
//! - Zlib decompression for v5+ archives (block offsets are relative to the
//!   entry record start), and LZ4 decompression for v8+ archives (the
//!   only versions where the `"LZ4"` FName slot is resolvable).
//! - SHA1 verification of the index and per-entry stored bytes via opt-in
//!   [`PakReader::verify_index`], [`PakReader::verify_entry`], and
//!   [`PakReader::verify`]. **v10+ encoded entries omit SHA1**, so
//!   `verify_entry` surfaces them as `SkippedNoHash`. Verification is
//!   opt-in to keep list-only workloads from paying the cost.
//!
//! It does NOT yet handle:
//! - AES decryption of v10+ (path-hash) encrypted indexes — the PHI/FDI
//!   sub-regions require absolute file-position seeks incompatible with
//!   Cursor-based decryption; paksmith returns [`crate::PaksmithError::UnsupportedFeature`]
//!   rather than silently returning garbage or misattributing a key error.
//! - AES decryption of entries that are *both* encrypted and compressed —
//!   UE encrypts the compressed payload, so correct support requires
//!   decrypting the 16-aligned region before per-block inflation; with no
//!   oracle fixture for that path yet, paksmith returns
//!   [`crate::PaksmithError::UnsupportedFeature`] rather than feed ciphertext
//!   to the inflater. Encrypted *uncompressed* entries decrypt normally.
//! - Gzip / Oodle / Zstd compression — resolved from the FName table
//!   but not wired up downstream (only Zlib and LZ4 decompress).
//! - Pre-v5 absolute-offset compression blocks (rare in real archives).
//! - V9 frozen-index format (rejected at open).
//!
//! # File-immutability assumption
//!
//! [`PakReader`] holds a single [`std::fs::File`] handle inside a
//! [`std::sync::Mutex`], opened at [`PakReader::open`] time and reused for
//! every entry read. The reader caches `file_size` at open time and assumes
//! the file is immutable for its lifetime — a file that shrinks between
//! `open` and a later read will surface as a typed `InvalidIndex` (the
//! per-entry payload-end-vs-file-size check fires before the read), and a
//! file that grows or is replaced will silently read different bytes than
//! the cached index describes. Truncation racing the read mid-stream
//! still surfaces as [`PaksmithError::Io`] (`UnexpectedEof`).

pub(crate) mod crypto;
pub mod footer;
pub mod index;
pub mod version;
pub use crypto::{AesKey, AesKeyHexError};

use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

use crate::container::{ContainerFormat, ContainerReader, EntryFlags, EntryMetadata};
use crate::digest::Sha1Digest;
use crate::error::{
    AllocationContext, BlockBoundsKind, BoundsUnit, DecompressionFault, HashTarget,
    IndexParseFault, IndexRegionKind, OffsetPastFileSizeKind, OverflowSite, PaksmithError,
    WireField, check_region_bounds,
};
use crate::seams::PakSeam;

use self::footer::PakFooter;
use self::index::{
    CompressionBlock, CompressionMethod, MAX_INDEX_BYTES, PakEntryHeader, PakIndex, PakIndexEntry,
    RegionDescriptor,
};
use self::version::PakVersion;

/// Hard ceiling on the uncompressed size of a single entry, applied before
/// any allocation. Sized to comfortably exceed any realistic UE asset (the
/// largest cooked textures peak in the low hundreds of MiB) while preventing
/// a malicious index that claims a multi-terabyte entry from triggering an
/// allocator abort. Tunable upwards if a legitimate archive ever trips it.
///
/// Exposed to integration tests via [`max_uncompressed_entry_bytes`] so that
/// boundary tests don't hard-code the literal and stay correct if the cap
/// ever changes.
pub(in crate::container::pak) const MAX_UNCOMPRESSED_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Test-only accessor for `MAX_UNCOMPRESSED_ENTRY_BYTES`. The cap is
/// an implementation detail of the parser — tests that care about the
/// boundary read it from here rather than duplicating the literal,
/// which would silently drift if the cap ever changes.
///
/// Gated behind the `__test_utils` feature so it's not part of the
/// stable public API. Integration tests in this crate enable it via
/// `dev-dependencies`-style activation; downstream consumers cannot
/// pin against this value.
#[cfg(feature = "__test_utils")]
pub fn max_uncompressed_entry_bytes() -> u64 {
    MAX_UNCOMPRESSED_ENTRY_BYTES
}

/// Trait alias for the bounds [`PakReader`] needs on its underlying
/// byte source: `Read + Seek` for the actual entry-read mechanics,
/// `Send` so the wrapping `Mutex` upholds the
/// [`crate::container::ContainerReader`] trait's `: Send + Sync`
/// contract.
///
/// Blanket impl over every concrete type satisfying the three bounds —
/// `std::fs::File`, `std::io::Cursor<Vec<u8>>`, and any future custom
/// reader (`memmap2::Mmap`, a network-backed reader, etc.) all match
/// automatically.
pub trait PakReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send + ?Sized> PakReadSeek for T {}

/// Reader for `.pak` archive files.
///
/// **Thread safety:** `PakReader: Send + Sync`. Multiple threads can
/// call [`Self::read_entry`] concurrently; reads are serialized via
/// the internal `Mutex` on the file handle. Pinned by the
/// `send_sync_assertions` test in `lib.rs`.
///
/// Holds a single `Mutex<Box<dyn PakReadSeek>>` constructed at open
/// time and reused for every entry read, replacing the previous
/// "reopen the file on every `read_entry`" pattern. The mutex
/// serializes concurrent reads (which is required anyway because each
/// read seeks the shared cursor); for paksmith's single-threaded
/// CLI/GUI usage there's no contention.
///
/// The boxed-trait-object indirection (issue #161) lets the same
/// `PakReader` value back a file, an in-memory `Cursor<Vec<u8>>`, or
/// any future custom reader — without a generic `<R>` parameter
/// rippling through every consumer. Per-read dynamic dispatch cost
/// is negligible against the I/O it gates.
///
/// `EntryMetadata` is constructed on demand by the
/// [`ContainerReader::entries`] iterator — there is no
/// `Vec<EntryMetadata>` cache alongside the parsed index. The
/// underlying index DOES materialize a `Vec<PakIndexEntry>` at
/// open time; the laziness is only in projecting each
/// `PakIndexEntry` to an owned `EntryMetadata` per `next()` call.
pub struct PakReader {
    file_size: u64,
    footer: PakFooter,
    index: PakIndex,
    reader: Mutex<Box<dyn PakReadSeek>>,
    /// AES-256 key supplied via [`Self::open_with_key`] /
    /// [`Self::from_reader_with_key`], used to decrypt the index at open
    /// time and (Phase 5a task 4+) per-entry payloads at read time.
    /// `None` for the `open` / `from_reader` entry points, which preserve
    /// the pre-key behavior (encrypted archives are rejected with
    /// [`PaksmithError::Decryption`]).
    key: Option<AesKey>,
}

impl std::fmt::Debug for PakReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Box<dyn PakReadSeek>` is not `Debug`. Hand-roll a useful
        // shape that doesn't try to format the reader.
        f.debug_struct("PakReader")
            .field("file_size", &self.file_size)
            .field("footer", &self.footer)
            .field("index", &self.index)
            .field("reader", &"<boxed reader>")
            // `AesKey`'s own Debug is redacted, so this never leaks key
            // bytes; it only reveals presence/absence of a key.
            .field("key", &self.key)
            .finish()
    }
}

impl PakReader {
    /// Open and parse a `.pak` file at the given path. Filesystem
    /// entry point; the symlink-warn defense-in-depth gate runs here.
    ///
    /// For in-memory bytes (tests, fuzz harnesses, network sources),
    /// prefer [`Self::from_bytes`] or [`Self::from_reader`] — both
    /// skip the disk roundtrip without sacrificing any parser
    /// guarantees.
    ///
    /// Rejects pre-v3 archives, v9 frozen-index archives, and archives
    /// with an AES-encrypted index. Per-entry AES and pre-v5
    /// absolute-offset compression blocks are deferred to read time.
    /// See the module-level docs for the full supported/unsupported
    /// matrix.
    pub fn open<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        Self::open_inner(path.as_ref(), None)
    }

    /// Open and parse a `.pak` whose index (and/or per-entry data) is
    /// AES-256 encrypted, supplying the decryption `key`.
    ///
    /// Behaves exactly like [`Self::open`] for unencrypted archives (the
    /// key is simply retained for any later encrypted entry reads). For
    /// an archive with an AES-encrypted index, the index region is
    /// decrypted and parsed at open time. A wrong key surfaces as
    /// [`PaksmithError::Decryption`] (the garbage plaintext fails the
    /// index parser's magic/bounds checks, which is mapped to a
    /// fail-closed decryption error rather than an opaque parse fault).
    pub fn open_with_key<P: AsRef<Path>>(path: P, key: AesKey) -> crate::Result<Self> {
        Self::open_inner(path.as_ref(), Some(key))
    }

    /// Read ONLY the pak footer and return its encryption-key GUID, if any.
    ///
    /// The footer (including the GUID field) is **not** encrypted, so this
    /// works on an encrypted pak without a key — it is how `--game`
    /// resolution learns which key a pak needs before opening it.
    ///
    /// Returns `None` for pre-v7 paks that have no GUID field.
    ///
    /// # Implementation note
    ///
    /// The footer is located and parsed by [`PakFooter::read_from`], which
    /// performs its own seek internally — the same call used by
    /// [`Self::open`] and [`Self::from_reader`]. No index parsing or
    /// decryption is performed — the returned GUID comes from the
    /// unencrypted footer only.
    pub fn read_footer_guid<P: AsRef<Path>>(path: P) -> crate::Result<Option<[u8; 16]>> {
        // Open the file and delegate entirely to PakFooter::read_from —
        // the same call used by from_reader_inner, so footer-seek logic
        // cannot drift between this helper and the open path.
        let mut file = File::open(path.as_ref())?;
        let footer = PakFooter::read_from(&mut file)?;
        Ok(footer.encryption_key_guid().copied())
    }

    /// Shared filesystem entry point for [`Self::open`] /
    /// [`Self::open_with_key`]: the symlink-warn defense-in-depth gate,
    /// the `File::open`, and the `Decryption { path: None }` →
    /// `Some(path)` diagnostic upgrade. The only difference between the
    /// two public callers is whether a key is threaded through.
    fn open_inner(path: &Path, key: Option<AesKey>) -> crate::Result<Self> {
        // F4 (security hardening, defense-in-depth): warn when the path
        // resolves through a symbolic link. The current threat model is
        // a user-local CLI — paksmith only reads what the invoking user
        // could already read directly, so a hard rejection would break
        // legitimate workflows (game-asset symlink trees are common).
        // The warn establishes operator visibility without breaking
        // anything; when Phase 4+ batch/daemon extraction lands, this
        // should escalate to opt-in (e.g. `--allow-symlinks`) rejection.
        //
        // `symlink_metadata` returns the link's own metadata (does not
        // traverse), so a broken symlink still gets the warn before
        // `File::open` surfaces the eventual NotFound via `#[from]
        // io::Error`. There is a TOCTOU race window between the
        // `symlink_metadata` check and `File::open`, but it is only
        // exploitable by an attacker with write access to the parent
        // directory — which is outside the threat model for this gate.
        if let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            tracing::warn!(
                path = %path.display(),
                "opening pak via symbolic link; defense-in-depth: future daemon mode will require explicit opt-in"
            );
        }
        let file = File::open(path)?;
        // `from_reader_inner` emits `Decryption { path: None }` since it
        // has no filesystem path to attach. Upgrade `None` → the real
        // path so operators get a useful diagnostic on this code path.
        Self::from_reader_inner(file, key).map_err(|e| match e {
            PaksmithError::Decryption { path: None } => PaksmithError::Decryption {
                path: Some(path.display().to_string()),
            },
            other => other,
        })
    }

    /// Parse a `.pak` archive from an owned byte buffer. Convenience
    /// wrapper around [`Self::from_reader`] that boxes the bytes in a
    /// `Cursor`.
    ///
    /// Right entry point for tests that assemble hand-crafted pak bytes
    /// in a `Vec<u8>` and fuzz harnesses that route mutator output
    /// without a disk roundtrip. For filesystem files, prefer
    /// [`Self::open`]; for custom readers (mmap, network streams),
    /// prefer [`Self::from_reader`].
    pub fn from_bytes(bytes: Vec<u8>) -> crate::Result<Self> {
        Self::from_reader(std::io::Cursor::new(bytes))
    }

    /// Parse a `.pak` archive from any `Read + Seek + Send + 'static`
    /// source. The most general entry point; [`Self::open`] and
    /// [`Self::from_bytes`] both delegate to it.
    ///
    /// Use this directly when the byte source is neither a filesystem
    /// path nor an in-memory `Vec<u8>` — e.g. `memmap2::Mmap`, a
    /// streamed network response materialized into a `Cursor`, or a
    /// custom adapter over a non-`File` OS handle.
    ///
    /// The reader is boxed into the `PakReader` and held for the
    /// lifetime of the value; subsequent entry reads route through it.
    /// `'static` lets the box live as long as `PakReader` does, which
    /// matches how every plausible reader source works (owned `File`,
    /// owned `Cursor<Vec<u8>>`, owned `Mmap`).
    pub fn from_reader<R: PakReadSeek + 'static>(reader: R) -> crate::Result<Self> {
        Self::from_reader_inner(reader, None)
    }

    /// Parse a `.pak` archive from any `Read + Seek + Send + 'static`
    /// source, supplying an AES-256 decryption `key`. The key-aware
    /// counterpart to [`Self::from_reader`]; [`Self::open_with_key`]
    /// delegates to it.
    ///
    /// Use this for an encrypted-index archive whose byte source is
    /// neither a filesystem path nor an in-memory `Vec<u8>`. For an
    /// archive with an AES-encrypted index, the index region is
    /// decrypted and parsed at open time; a wrong key surfaces as
    /// [`PaksmithError::Decryption`].
    pub fn from_reader_with_key<R: PakReadSeek + 'static>(
        reader: R,
        key: AesKey,
    ) -> crate::Result<Self> {
        Self::from_reader_inner(reader, Some(key))
    }

    /// Shared body of [`Self::from_reader`] / [`Self::from_reader_with_key`].
    ///
    /// The two public entry points differ only in whether a key is
    /// threaded through; every other step (footer parse, frozen/version
    /// rejection, the post-index payload-bounds sweep) is identical, so
    /// it lives here once. The single key-dependent branch is index
    /// acquisition:
    /// - encrypted index + key present → decrypt the on-disk index
    ///   region into a plaintext buffer and parse it from a `Cursor`
    ///   (see [`PakIndex::read_positioned`]); a wrong key fails closed as
    ///   [`PaksmithError::Decryption`].
    /// - encrypted index + no key → `Decryption { path: None }` (the
    ///   pre-key behavior; `open` upgrades the path).
    /// - unencrypted → the original `read_from` path, byte-identical to
    ///   pre-key behavior.
    fn from_reader_inner<R: PakReadSeek + 'static>(
        reader: R,
        key: Option<AesKey>,
    ) -> crate::Result<Self> {
        let mut reader: Box<dyn PakReadSeek> = Box::new(reader);
        let mut buffered = BufReader::new(&mut *reader);
        let file_size = buffered.seek(SeekFrom::End(0))?;

        let footer = PakFooter::read_from(&mut buffered)?;

        // Encrypted index with no key — reject HERE (before the frozen /
        // version gates), preserving the exact pre-key ordering: an
        // encrypted archive without a key always surfaced as
        // `Decryption`, never `UnsupportedVersion`. `from_reader` (no
        // key) and `open` (which upgrades `None` → the real path) both
        // rely on this. The with-key decrypt happens later at index
        // acquisition; the `let Some(key) = ... else` there stays as
        // fail-closed defense in depth.
        if footer.is_encrypted() && key.is_none() {
            // No path available from a `Read + Seek` source. The
            // path-based `open()` catches this `None` and upgrades it to
            // `Some(path)` so operators get a useful diagnostic.
            return Err(PaksmithError::Decryption { path: None });
        }

        // V9's `frozen_index = true` writer flag means the index region
        // is in UE's compiled-frozen layout — completely different bytes
        // than the flat-entry parser expects. Silently parsing as if not
        // frozen would produce garbage entries (paths read as gibberish,
        // offsets pointing nowhere). Repak's writer doesn't currently
        // emit frozen=true so the cross-parser tests can't catch this;
        // reject explicitly at open time. See #7 follow-up for proper
        // frozen-index parsing.
        if footer.frozen_index() {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version().wire_version(),
            });
        }

        // v1/v2 entry records have a different shape (timestamp field
        // pre-v2, no trailing flags+block_size). PakEntryHeader::read_from
        // assumes the v3+ layout. We have no fixtures for v1/v2 and
        // they're rare in the wild, so reject explicitly rather than
        // silently misparse.
        if footer.version() < PakVersion::CompressionEncryption {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version().wire_version(),
            });
        }

        let index = if footer.is_encrypted() {
            // The encrypted+no-key case was already rejected above; this
            // `else` is fail-closed defense in depth (a future refactor
            // that drops the early gate still can't reach a decrypt with
            // no key). NOT an unwrap/expect — that would reintroduce a
            // panic path.
            let Some(key) = key.as_ref() else {
                return Err(PaksmithError::Decryption { path: None });
            };
            read_encrypted_index(&mut buffered, &footer, file_size, key)?
        } else {
            // PakIndex::read_from seeks to index_offset itself (v10+
            // needs to seek elsewhere for the full directory index, so
            // it owns the seek dance). Byte-identical to pre-key behavior.
            PakIndex::read_from(
                &mut buffered,
                footer.version(),
                footer.index_offset(),
                footer.index_size(),
                file_size,
                footer.compression_methods(),
            )?
        };
        // Drop the BufReader's borrow so we can move `reader` into
        // the Mutex. The BufReader is throwaway — entry reads will
        // create fresh BufReaders against the locked reader.
        drop(buffered);

        // Issue #58: the per-entry payload-end-vs-file-size check
        // already exists at verify_entry / stream_*_to time, but
        // never fires for `paksmith list`-style consumers that
        // surface `compressed_size()` without extracting. Walk the
        // index once at open and reject any entry whose claim
        // implies on-disk bytes past EOF, so consumers reading the
        // header can't be lied to. Covers single-block,
        // multi-block, and zero-block entries uniformly through
        // the same single iteration.
        //
        // For encrypted multi-block entries, `compressed_size` is
        // the unaligned sum; the actual on-disk extent is up to
        // `16 * block_count` bytes larger due to AES padding. We
        // accept that ~1 MiB worst-case under-check at open since
        // the read-time per-block bound at `stream_zlib_to` still
        // catches anything beyond the wire claim that would
        // actually walk past EOF.
        for entry in index.entries() {
            let header = entry.header();
            let offset = header.offset();
            let compressed = header.compressed_size();
            let uncompressed = header.uncompressed_size();
            // The on-disk extent of an entry is
            // `offset + in_data_header_size + compressed`, NOT just
            // `offset + compressed`: every entry has an in-data
            // FPakEntry record sitting between `offset` and the
            // payload bytes. Pre-#85 this check used `offset +
            // compressed`, leaving a window where marginal-lying
            // entries (off by ≤ in_data_header_size, ~50-70 bytes)
            // bypassed the typed `OffsetPastFileSize` and surfaced
            // as bare `Io::UnexpectedEof` at read time. `wire_size`
            // works for both Inline (v3-v9) and Encoded (v10+)
            // variants — Encoded reuses the V8B+ in-data shape.
            //
            // The footer's index-bounds check already pinned
            // `index_offset + index_size <= file_size`, so a
            // malformed footer's `file_size` is sanitized by the
            // time we reach this loop. The remaining attack vector
            // is per-entry header lies, which this loop closes.
            let in_data_size = header.wire_size();
            let payload_end = offset
                .checked_add(in_data_size)
                .and_then(|p| p.checked_add(compressed))
                .ok_or_else(|| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        path: Some(entry.filename().to_string()),
                        operation: OverflowSite::PayloadEnd,
                    },
                })?;
            if payload_end > file_size {
                warn!(
                    path = entry.filename(),
                    offset,
                    in_data_size,
                    compressed,
                    file_size,
                    "entry payload extends past file_size at open time"
                );
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        path: entry.filename().to_string(),
                        kind: OffsetPastFileSizeKind::PayloadEndBounds {
                            payload_end,
                            file_size_max: file_size,
                        },
                    },
                });
            }
            // Open-time `uncompressed_size` backstop. The parse-time
            // `block_count * compression_block_size` cap in
            // `read_encoded` is structurally tight for compressed
            // multi-block AND single-block paths (issue #58 sibling),
            // but it doesn't bound the `compression_block_size` field
            // itself — an attacker who sets that to `u32::MAX` lifts
            // the cap to ~256 TiB. The inline v3-v9 path doesn't
            // apply ANY parse-time cap. This open-time check covers
            // both gaps uniformly: any consumer reading
            // `uncompressed_size()` (CLI list, JSON output, alloc
            // estimators) is bounded by `MAX_UNCOMPRESSED_ENTRY_BYTES`
            // (8 GiB), the same backstop `verify_entry`/`read_entry`
            // already rely on at extract time.
            if uncompressed > MAX_UNCOMPRESSED_ENTRY_BYTES {
                warn!(
                    path = entry.filename(),
                    uncompressed,
                    limit = MAX_UNCOMPRESSED_ENTRY_BYTES,
                    "entry uncompressed_size exceeds backstop at open time"
                );
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: WireField::UncompressedSize,
                        value: uncompressed,
                        limit: MAX_UNCOMPRESSED_ENTRY_BYTES,
                        unit: BoundsUnit::Bytes,
                        path: Some(entry.filename().to_string()),
                    },
                });
            }
        }

        Ok(Self {
            file_size,
            footer,
            index,
            reader: Mutex::new(reader),
            key,
        })
    }

    /// The pak format version of this archive.
    pub fn version(&self) -> PakVersion {
        self.footer.version()
    }

    /// Look up the parsed index entry for `path`, exposing the wire-level
    /// fields (entry offset, on-disk sizes, compression blocks, stored
    /// SHA1) that the lighter [`EntryMetadata`] hides.
    ///
    /// Use this when a caller needs to compute a derived offset (e.g., to
    /// poke at a specific payload byte for a corruption test) and would
    /// otherwise have to hardcode arithmetic that drifts when the on-disk
    /// header layout changes. Returns `None` if no entry has that path.
    #[must_use]
    pub fn index_entry(&self, path: &str) -> Option<&PakIndexEntry> {
        self.index.find(path)
    }

    /// Whether the archive's index hash slot is non-zero — i.e., the
    /// writer recorded an integrity claim. When `true`, any zero entry
    /// hash slot is treated as a tampering signal (an attacker stripping
    /// the integrity tag) rather than "no claim recorded." See
    /// [`PakReader::verify_entry`] for the details.
    fn archive_claims_integrity(&self) -> bool {
        !self.footer.index_hash().is_zero()
    }

    /// Acquire the shared reader handle, recovering from poison.
    ///
    /// **Safety contract.** A previous panic-while-locked left the
    /// reader cursor at an unknown position, so the recovered guard
    /// cannot be trusted to be at any particular offset. **Every caller
    /// MUST seek before its first read** (typically via `BufReader::seek`
    /// or by going through [`Self::open_entry_into`], which seeks
    /// unconditionally). Reading from the guard's initial position after
    /// a poisoned lock would silently return bytes from wherever the
    /// panicked thread left off. This invariant is upheld today by every
    /// lock site in this file; future additions must preserve it.
    fn locked(&self) -> std::sync::MutexGuard<'_, Box<dyn PakReadSeek>> {
        self.reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Verify the SHA1 hash recorded in the footer against the actual bytes
    /// of the index.
    ///
    /// Returns:
    /// - `Ok(VerifyOutcome::Verified)` when the stored hash matches.
    /// - `Ok(VerifyOutcome::SkippedNoHash)` when the footer's stored hash
    ///   is all zeros — UE writers leave the field zero-filled when
    ///   integrity hashing was not enabled at archive-creation time, so a
    ///   zeroed slot means "no integrity claim to verify against," not
    ///   "tampered."
    /// - `Err(HashMismatch { target: Index, .. })` when a non-zero stored
    ///   hash disagrees with the recomputed digest — the only signal of
    ///   actual tampering or transit corruption.
    ///
    /// # Security note
    ///
    /// An attacker who can rewrite the archive can zero the index hash
    /// slot to force `Ok(SkippedNoHash)` — a downgrade attack. Callers in
    /// security-sensitive contexts should treat any `SkippedNoHash`
    /// outcome as suspicious unless they have out-of-band evidence the
    /// archive was never hashed (e.g., known-pre-hashing UE version).
    /// [`VerifyStats::is_fully_verified`] provides a one-call check for
    /// "every byte that could have been hashed was hashed."
    ///
    /// Opt-in: not called by [`PakReader::open`] because hashing the index
    /// is an extra full-index read that list-only callers don't need to
    /// pay for.
    ///
    /// # Encrypted paks
    ///
    /// For paks where the index is AES-encrypted (`footer.is_encrypted()`),
    /// UE computes `index_hash` over the **plaintext** before encryption, so
    /// verification must decrypt the index and then hash the decrypted bytes.
    /// Opening an encrypted pak without a key (`open` rather than
    /// `open_with_key`) fails at construction (`Decryption` error), so calling
    /// `verify_index()` on an encrypted pak always has a key available.
    pub fn verify_index(&self) -> crate::Result<VerifyOutcome> {
        let main = self.verify_main_index_region()?;
        // V10+ also has FDI/PHI regions at arbitrary file offsets that
        // the main-index byte range doesn't cover. Verify them here so
        // a caller using `verify_index()` directly (rather than the
        // higher-level `verify()`) gets full tamper coverage. Issue #86.
        let fdi = self.verify_fdi_region()?;
        let phi = self.verify_phi_region()?;
        Ok(combine_index_outcomes(main, fdi, phi))
    }

    /// Hash and verify the main-index byte range (the `index_offset` ..
    /// `index_offset + index_size` window referenced by the footer).
    /// Always present regardless of pak version.
    ///
    /// For encrypted paks, UE hashes the **plaintext** before encrypting, so
    /// verification must decrypt first and then hash the decrypted bytes.
    /// Encrypted paks opened without a key fail at construction (`Decryption`
    /// error), so `self.key` is always `Some` when `is_encrypted()` is true
    /// in practice. A defensive `Err(Decryption)` branch covers future constructors.
    fn verify_main_index_region(&self) -> crate::Result<VerifyOutcome> {
        if self.footer.index_hash().is_zero() {
            debug!("index has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        // For encrypted paks, UE stores SHA1 of plaintext (hash-before-encrypt).
        // Decrypt into a temporary buffer, then hash the plaintext (up to
        // `index_size` bytes; the AES alignment padding is excluded).
        if self.footer.is_encrypted() {
            // `self.key.is_none()` is structurally unreachable today —
            // `from_reader_inner` rejects encrypted paks opened without a key
            // before constructing `PakReader`. The `Err(Decryption)` branch is a
            // defensive invariant for future constructors; it must NOT return
            // `Ok(SkippedNoHash)` since the hash slot is non-zero at this point
            // (the `index_hash().is_zero()` guard above already handled zero slots).
            let Some(ref key) = self.key else {
                return Err(PaksmithError::Decryption { path: None });
            };
            // `index_size` is bounded by the open-time MAX_INDEX_BYTES cap —
            // every `PakReader` with an encrypted footer was built through
            // `read_encrypted_index → decrypt_index_region`, which enforces the
            // cap before the 16-alignment multiply. The overflow-safety comment
            // in `decrypt_index_region` applies.
            let buf = {
                let mut guard = self.locked();
                decrypt_index_region(&mut *guard, &self.footer, key)?
            };
            let index_size = self.footer.index_size();
            let index_size_usize =
                usize::try_from(index_size).map_err(|_| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ExceedsPlatformUsize {
                        field: WireField::IndexSize,
                        value: index_size,
                        path: None,
                    },
                })?;
            let mut hasher = Sha1::new();
            hasher.update(&buf[..index_size_usize]);
            let actual = Sha1Digest::from(<[u8; 20]>::from(hasher.finalize()));
            if actual != self.footer.index_hash() {
                let expected = self.footer.index_hash().to_string();
                let actual_hex = actual.to_string();
                error!(
                    expected = %expected,
                    actual = %actual_hex,
                    "encrypted index hash mismatch — archive may be tampered"
                );
                return Err(PaksmithError::HashMismatch {
                    target: HashTarget::Index,
                    expected,
                    actual: actual_hex,
                });
            }
            return Ok(VerifyOutcome::Verified);
        }
        let mut guard = self.locked();
        let mut file = BufReader::new(&mut *guard);
        let _ = file.seek(SeekFrom::Start(self.footer.index_offset()))?;
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let actual = sha1_of_reader(&mut file, self.footer.index_size(), &mut buf)?;
        if actual != self.footer.index_hash() {
            let expected = self.footer.index_hash().to_string();
            let actual_hex = actual.to_string();
            error!(
                expected = %expected,
                actual = %actual_hex,
                "index hash mismatch — archive may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target: HashTarget::Index,
                expected,
                actual: actual_hex,
            });
        }
        Ok(VerifyOutcome::Verified)
    }

    /// Hash and verify the v10+ full-directory-index region.
    /// `Ok(None)` for pre-v10 (flat) archives where no FDI exists.
    /// `Ok(Some(SkippedNoHash))` when the FDI hash slot is zero
    /// ("no integrity claim recorded at write time").
    fn verify_fdi_region(&self) -> crate::Result<Option<VerifyOutcome>> {
        let Some(regions) = self.index.encoded_regions() else {
            return Ok(None);
        };
        Ok(Some(
            self.verify_region(regions.fdi(), IndexRegionKind::Fdi)?,
        ))
    }

    /// Hash and verify the v10+ path-hash-index region.
    /// `Ok(None)` for pre-v10 archives or v10+ archives that recorded
    /// `has_path_hash_index = false` (the PHI is optional even in v10+).
    fn verify_phi_region(&self) -> crate::Result<Option<VerifyOutcome>> {
        let Some(regions) = self.index.encoded_regions() else {
            return Ok(None);
        };
        let Some(phi) = regions.phi() else {
            return Ok(None);
        };
        Ok(Some(self.verify_region(phi, IndexRegionKind::Phi)?))
    }

    /// Shared region-hashing helper used by `verify_fdi_region` and
    /// `verify_phi_region`. Both regions have identical wire shape:
    /// an `(offset, size, SHA1)` triple in the main-index header
    /// pointing into the parent file.
    ///
    /// When the stored hash slot is zero, applies the same
    /// strip-detection policy as `verify_entry`: if the archive
    /// claims integrity (footer index_hash non-zero), surface as
    /// [`PaksmithError::IntegrityStripped`] — an attacker who can
    /// recompute the footer hash can zero a region hash slot to
    /// downgrade the region to `SkippedNoHash`, evading callers that
    /// match on `verify_index() == Verified` rather than going
    /// through `is_fully_verified()`. The PHI case is the more
    /// dangerous of the two because paksmith never inspects PHI
    /// bytes during parse, so the slot is the ONLY tamper signal.
    fn verify_region(
        &self,
        region: RegionDescriptor,
        region_kind: IndexRegionKind,
    ) -> crate::Result<VerifyOutcome> {
        let target = HashTarget::from(region_kind);
        // Issue #127: pre-validate the region's wire-declared
        // `(offset, size)` against `file_size` BEFORE the zero-hash
        // short-circuit. Order matters: a zero-hash PHI with
        // `phi_offset = u64::MAX` would otherwise return
        // `SkippedNoHash` and leave the malformed header
        // unflagged — moving the bounds check first surfaces the
        // typed fault even when the archive declined to record an
        // integrity hash. For FDI this also runs at open time
        // (parse-time check in `read_v10_plus_from`); for PHI this
        // is the primary defense since the parser doesn't seek to
        // PHI at open. Shared comparator via `check_region_bounds`.
        check_region_bounds(region_kind, region.offset(), region.size(), self.file_size)
            .map_err(|fault| PaksmithError::InvalidIndex { fault })?;
        if region.hash().is_zero() {
            if self.archive_claims_integrity() {
                error!(
                    region = %target,
                    expected = "non-zero (archive-wide integrity claimed)",
                    actual = "0000000000000000000000000000000000000000",
                    "region has zero SHA1 but archive index does — \
                     possible integrity-strip attack"
                );
                return Err(PaksmithError::IntegrityStripped { target });
            }
            debug!(
                region = %target,
                "region has no recorded SHA1; skipping verification"
            );
            return Ok(VerifyOutcome::SkippedNoHash);
        }
        let mut guard = self.locked();
        let mut file = BufReader::new(&mut *guard);
        let _ = file.seek(SeekFrom::Start(region.offset()))?;
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let actual = sha1_of_reader(&mut file, region.size(), &mut buf)?;
        if actual != region.hash() {
            let expected = region.hash().to_string();
            let actual_hex = actual.to_string();
            error!(
                region = %target,
                expected = %expected,
                actual = %actual_hex,
                "region hash mismatch — archive may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target,
                expected,
                actual: actual_hex,
            });
        }
        Ok(VerifyOutcome::Verified)
    }

    /// Verify the SHA1 hash of a single entry's on-disk stored bytes. For
    /// uncompressed entries this is the payload itself; for compressed
    /// entries it is the concatenation of the per-block compressed bytes
    /// (UE hashes the on-disk representation, not the decompressed content).
    ///
    /// **Scope:** the entry's stored SHA1 covers payload bytes only, NOT
    /// the in-data FPakEntry record header. Tampering inside the in-data
    /// header is caught earlier by `PakEntryHeader::matches_payload` and
    /// surfaces as `InvalidIndex`, not `HashMismatch`.
    ///
    /// # Archive-wide integrity policy
    ///
    /// UE's stock writer is all-or-nothing for entries that CARRY a
    /// SHA1 field on the wire: it either records integrity hashes for
    /// the entire archive or for none of it. The reader treats "mixed
    /// state" (index hash non-zero, one entry hash zero) as the
    /// attacker signature of a stripped integrity tag, surfacing as
    /// [`PaksmithError::IntegrityStripped`]. When the index hash is
    /// also zero (the archive claims no integrity), a zero entry hash
    /// is accepted as `Ok(SkippedNoHash)`. This closes the bypass path
    /// where an attacker would zero a single entry's hash slot to
    /// force a silent skip.
    ///
    /// **V10+ encoded entries are exempt** from the strip-detection
    /// gate because their wire format omits the SHA1 field entirely
    /// (only the in-data record carries it). Such entries are the
    /// [`crate::container::pak::index::PakEntryHeader::Encoded`]
    /// variant — `sha1()` returns `None` rather than a placeholder
    /// zero — and always surface as `Ok(SkippedNoHash)` regardless of
    /// the archive's index hash. There's no "stripped" state to
    /// detect when no slot exists in the first place.
    ///
    /// **Compatibility caveat:** third-party packers that don't follow
    /// UE's stock all-or-nothing pattern (custom packers, partial
    /// regeneration, mod tools) may legitimately produce mixed-state
    /// archives. Such files will surface as `IntegrityStripped` here even
    /// though they aren't tampered. If you need to accept third-party
    /// packers, treat `IntegrityStripped` as a distinguishable warning
    /// rather than a hard rejection at the call site.
    ///
    /// Returns:
    /// - `Ok(VerifyOutcome::Verified)` on a hash match.
    /// - `Ok(VerifyOutcome::SkippedNoHash)` when the entry's stored SHA1
    ///   is all zeros (no integrity claim recorded at write time).
    /// - `Ok(VerifyOutcome::SkippedEncrypted)` for AES-encrypted entries —
    ///   verifying ciphertext without the key is not supported.
    /// - `Err(EntryNotFound)` for unknown paths.
    /// - `Err(Decompression)` for unsupported compression methods (Gzip,
    ///   Oodle, Zstd, UnknownByName, Unknown). Zlib and LZ4 verify
    ///   normally (the entry SHA1 covers the on-disk compressed bytes,
    ///   so no decompression happens on the verify path). We refuse to
    ///   hash arbitrary bytes we can't interpret; doing otherwise risks
    ///   reporting a misleading `HashMismatch` for a well-formed archive
    ///   in a method we don't support yet.
    /// - `Err(InvalidIndex)` for offset/bounds problems uncovered while
    ///   reading.
    /// - `Err(HashMismatch { target: Entry { path }, .. })` when the
    ///   stored hash disagrees with the recomputed digest.
    #[allow(clippy::too_many_lines)] // bounded by the per-block error branches
    pub fn verify_entry(&self, path: &str) -> crate::Result<VerifyOutcome> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        // Encryption check first: if the bytes at entry.header().offset() are
        // ciphertext, hashing them is meaningless. This priority is
        // intentional — an encrypted-AND-zero-hash entry reports as
        // SkippedEncrypted, not SkippedNoHash, because encryption is the
        // stronger reason we can't verify.
        //
        // TODO(Task-4): when per-entry decryption is added, verify whether
        // UE stores the entry SHA1 over plaintext or ciphertext (the index
        // path confirmed hash-before-encrypt for the index — but that wire
        // fact must be verified separately for individual entries before
        // being assumed here). See verify_main_index_region's encrypted branch.
        if entry.header().is_encrypted() {
            debug!(path, "entry is encrypted; skipping SHA1 verification");
            return Ok(VerifyOutcome::SkippedEncrypted);
        }

        // V10+ encoded entries have NO sha1 field on the wire (the
        // bit-packed `FPakEntry::EncodeTo` format omits it; only the
        // in-data record carries one). The Encoded variant returns
        // `None` from `sha1()`, which is the unambiguous "no integrity
        // claim was made" signal — distinct from a real-but-zero digest
        // on an Inline entry, which is the v3-v9 tampering signal we
        // want to surface.
        let Some(expected_sha1) = entry.header().sha1() else {
            debug!(
                path,
                "entry has no recorded SHA1 (encoded entry); skipping verification"
            );
            return Ok(VerifyOutcome::SkippedNoHash);
        };

        if expected_sha1.is_zero() {
            // Inline entry with an all-zero SHA1. If the archive opts
            // into integrity (non-zero index_hash), this is a tampering
            // signal we want to surface; otherwise it's a legitimate
            // "no integrity recorded" case.
            if self.archive_claims_integrity() {
                error!(
                    path,
                    expected = "non-zero (archive-wide integrity claimed)",
                    actual = "0000000000000000000000000000000000000000",
                    "entry has zero SHA1 but archive index does — \
                     possible integrity-strip attack"
                );
                return Err(PaksmithError::IntegrityStripped {
                    target: HashTarget::Entry {
                        path: path.to_string(),
                    },
                });
            }
            debug!(path, "entry has no recorded SHA1; skipping verification");
            return Ok(VerifyOutcome::SkippedNoHash);
        }

        let mut guard = self.locked();
        let mut file = BufReader::new(&mut *guard);
        let in_data = self.open_entry_into(&mut file, entry)?;

        // Single buffer reused across all per-block reads so multi-block
        // entries don't pay N heap allocations.
        let mut buf = [0u8; HASH_BUFFER_BYTES];

        let actual = match entry.header().compression_method() {
            CompressionMethod::None => {
                // Mirror the payload-end bounds check from
                // `stream_uncompressed_to` so a truncated archive
                // surfaces as the structured `OffsetPastFileSize`
                // variant rather than a bare `Io::UnexpectedEof` from
                // `read_exact` partway through hashing. Uniform
                // diagnostic across the verify and read paths is the
                // whole point of the typed variant (issue #48).
                //
                // Pre-#85 this used `offset + uncompressed_size`,
                // missing the in-data header bytes between them. Use
                // the file cursor (which `open_entry_into` already
                // advanced past the in-data header) as the payload
                // start, matching `stream_uncompressed_to`'s
                // `payload_end = file.stream_position()? + size`
                // pattern exactly — this is now defense-in-depth
                // since #85's open-time check rejects the same shape
                // upstream, but keeping the verify path correct
                // preserves the documented diagnostic contract for
                // any future caller that bypasses `PakReader::open`.
                let payload_end = file
                    .stream_position()?
                    .checked_add(entry.header().uncompressed_size())
                    .ok_or_else(|| PaksmithError::InvalidIndex {
                        fault: IndexParseFault::U64ArithmeticOverflow {
                            path: Some(path.to_string()),
                            operation: OverflowSite::PayloadEnd,
                        },
                    })?;
                if payload_end > self.file_size {
                    return Err(PaksmithError::InvalidIndex {
                        fault: IndexParseFault::OffsetPastFileSize {
                            path: path.to_string(),
                            kind: OffsetPastFileSizeKind::PayloadEndBounds {
                                payload_end,
                                file_size_max: self.file_size,
                            },
                        },
                    });
                }
                sha1_of_reader(&mut file, entry.header().uncompressed_size(), &mut buf)?
            }
            CompressionMethod::Zlib | CompressionMethod::Lz4 => {
                // Hash the on-disk compressed bytes block-by-block —
                // method-agnostic: the index hash covers the on-disk
                // payload, so no decompression happens here and zlib
                // and LZ4 entries walk the identical path.
                // All per-block validation (start-overlap, end-past-file,
                // out-of-order) routes through `validate_block_bounds`
                // shared with the stream_*_to readers — keeps the verify
                // and read paths from diverging on the same archive.
                let payload_start = entry
                    .header()
                    .offset()
                    .checked_add(in_data.wire_size())
                    .ok_or_else(|| PaksmithError::InvalidIndex {
                        fault: IndexParseFault::U64ArithmeticOverflow {
                            path: Some(path.to_string()),
                            operation: OverflowSite::OffsetPlusHeader,
                        },
                    })?;
                let mut hasher = Sha1::new();
                let mut prev_abs_end: Option<u64> = None;
                for (i, block) in entry.header().compression_blocks().iter().enumerate() {
                    let (abs_start, _abs_end) = validate_block_bounds(
                        block,
                        i,
                        entry.header().offset(),
                        payload_start,
                        self.file_size,
                        &mut prev_abs_end,
                        path,
                    )?;
                    let _ = file.seek(SeekFrom::Start(abs_start))?;
                    feed_hasher(&mut hasher, &mut file, block.len(), &mut buf)?;
                }
                Sha1Digest::from(<[u8; 20]>::from(hasher.finalize()))
            }
            // Already rejected at the top of read_entry for known unsupported
            // methods; here we extend the same policy to verify_entry rather
            // than silently succeed by hashing whatever bytes are at offset.
            method @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_)) => {
                return Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.header().offset(),
                    fault: DecompressionFault::UnsupportedMethod {
                        method: method.clone(),
                    },
                });
            }
        };

        if actual != expected_sha1 {
            let expected = expected_sha1.to_string();
            let actual_hex = actual.to_string();
            error!(
                path,
                expected = %expected,
                actual = %actual_hex,
                "entry hash mismatch — payload may be tampered or corrupted"
            );
            return Err(PaksmithError::HashMismatch {
                target: HashTarget::Entry {
                    path: path.to_string(),
                },
                expected,
                actual: actual_hex,
            });
        }

        Ok(VerifyOutcome::Verified)
    }

    /// Verify the index hash AND every entry's hash, returning structured
    /// counts of what was actually checked vs skipped. Stops on the first
    /// `HashMismatch` and returns the error.
    ///
    /// **Skips are reported, not silenced.** Entries that have no recorded
    /// hash (UE didn't enable integrity at write time) and entries that are
    /// AES-encrypted (we have no key) are counted in the returned
    /// [`VerifyStats`]. Callers can inspect the report to decide whether
    /// `Ok` means "all bytes intact" or "some bytes weren't verifiable" —
    /// avoiding the silent partial-success failure mode that returning bare
    /// `Result<()>` would create.
    pub fn verify(&self) -> crate::Result<VerifyStats> {
        let mut stats = VerifyStats::default();
        // Drive each region with its own helper rather than calling
        // `verify_index` once and mapping a single outcome — the per-
        // region calls let us populate `VerifyStats.fdi`/`phi` with
        // fine-grained state instead of bucketing the worst-case
        // outcome across all three regions.
        match self.verify_main_index_region()? {
            VerifyOutcome::Verified => stats.index_verified = true,
            VerifyOutcome::SkippedNoHash => stats.index_skipped_no_hash = true,
            // `verify_main_index_region` returns Verified, SkippedNoHash,
            // or Err — never SkippedEncrypted (the encrypted branch returns
            // either Verified or HashMismatch). Surface as a typed error per
            // the no-panics-in-core rule rather than `unreachable!`.
            VerifyOutcome::SkippedEncrypted => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::UnexpectedSkippedEncrypted {
                        region: IndexRegionKind::Main,
                    },
                });
            }
        }
        stats.fdi = match self.verify_fdi_region()? {
            None => RegionVerifyState::NotPresent,
            Some(VerifyOutcome::Verified) => RegionVerifyState::Verified,
            Some(VerifyOutcome::SkippedNoHash) => RegionVerifyState::SkippedNoHash,
            Some(VerifyOutcome::SkippedEncrypted) => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::UnexpectedSkippedEncrypted {
                        region: IndexRegionKind::Fdi,
                    },
                });
            }
        };
        stats.phi = match self.verify_phi_region()? {
            None => RegionVerifyState::NotPresent,
            Some(VerifyOutcome::Verified) => RegionVerifyState::Verified,
            Some(VerifyOutcome::SkippedNoHash) => RegionVerifyState::SkippedNoHash,
            Some(VerifyOutcome::SkippedEncrypted) => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::UnexpectedSkippedEncrypted {
                        region: IndexRegionKind::Phi,
                    },
                });
            }
        };
        for entry in self.index.entries() {
            match self.verify_entry(entry.filename())? {
                VerifyOutcome::Verified => stats.entries_verified += 1,
                VerifyOutcome::SkippedNoHash => stats.entries_skipped_no_hash += 1,
                VerifyOutcome::SkippedEncrypted => stats.entries_skipped_encrypted += 1,
            }
        }
        let fdi_skipped = matches!(stats.fdi, RegionVerifyState::SkippedNoHash);
        let phi_skipped = matches!(stats.phi, RegionVerifyState::SkippedNoHash);
        if stats.index_skipped_no_hash
            || fdi_skipped
            || phi_skipped
            || stats.entries_skipped_encrypted > 0
            || stats.entries_skipped_no_hash > 0
        {
            warn!(
                index_skipped = stats.index_skipped_no_hash,
                fdi_skipped,
                phi_skipped,
                encrypted = stats.entries_skipped_encrypted,
                no_hash = stats.entries_skipped_no_hash,
                verified = stats.entries_verified,
                "verify(): some bytes were not hashed; inspect VerifyStats"
            );
        }
        Ok(stats)
    }

    /// Position `reader` at `entry.header().offset()`, parse the in-data FPakEntry
    /// header, and validate it against the index entry. Returns the parsed
    /// in-data header; the caller continues reading the payload from
    /// `reader` (now positioned just past the header).
    ///
    /// Takes a reader by reference rather than opening one internally so
    /// callers can share the `PakReader`'s single `Mutex<File>` handle.
    /// Bounds-checks the entry offset against [`Self::file_size`] before
    /// seeking, so a malformed pak can't read past EOF undetected.
    fn open_entry_into<R: Read + Seek>(
        &self,
        reader: &mut R,
        entry: &PakIndexEntry,
    ) -> crate::Result<PakEntryHeader> {
        let path = entry.filename();

        // SAFETY: structurally unreachable from a successfully-opened
        // reader. The open-time per-entry payload-end check in
        // `PakReader::open` (issues #58 + #85) computes
        // `payload_end = offset + wire_size() + compressed` and rejects
        // `payload_end > file_size`.
        // `wire_size()` is strictly positive for every entry shape
        // (50 bytes for V8A, 53 for V8B+/v3-v7, more when compression
        // blocks are present), so `offset >= file_size` implies
        // `payload_end > file_size` upstream and surfaces as
        // `OffsetPastFileSizeKind::PayloadEndBounds`, not
        // `EntryHeaderOffset`. The branch is kept as a typed-error
        // safety net so a future refactor that breaks the open-time
        // invariant surfaces here as `EntryHeaderOffset` rather than
        // as `Io::UnexpectedEof` from the seek below. Issue #92.
        if entry.header().offset() >= self.file_size {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    path: path.to_string(),
                    kind: OffsetPastFileSizeKind::EntryHeaderOffset {
                        entry_offset: entry.header().offset(),
                        file_size_max: self.file_size,
                    },
                },
            });
        }

        let _ = reader.seek(SeekFrom::Start(entry.header().offset()))?;
        let in_data = PakEntryHeader::read_from(
            reader,
            self.footer.version(),
            self.footer.compression_methods(),
        )?;

        entry.header().matches_payload(&in_data, path)?;
        Ok(in_data)
    }

    /// Inner streaming primitive shared by `read_entry_to` (trait method,
    /// looks up the entry by path) and `read_entry` (override, looks up
    /// the entry by path AND wraps with try_reserve_exact). Takes a
    /// pre-resolved `&PakIndexEntry` so callers don't pay two HashMap
    /// lookups for the same path.
    fn stream_entry_to(&self, entry: &PakIndexEntry, writer: &mut dyn Write) -> crate::Result<u64> {
        let path = entry.filename();

        // Fail-closed: encrypted entry without a key → Decryption immediately.
        // When a key is present, the in-data FPakEntry header is plaintext (UE
        // encrypts only the payload, not the in-data record), so we defer the
        // key to the payload reader below rather than short-circuiting.
        if entry.header().is_encrypted() && self.key.is_none() {
            return Err(PaksmithError::Decryption {
                path: Some(path.to_string()),
            });
        }
        // Encrypted + compressed entries are not yet supported. UE encrypts the
        // compressed payload, so correct support requires decrypting the 16-aligned
        // region BEFORE per-block inflation — and no oracle fixture exercises that
        // path yet. Rather than feed ciphertext into the inflater (which rejects it
        // with a misleading Decompression error), reject explicitly. The key may be
        // correct; this is a deferred layout, not a wrong-key situation. Mirrors the
        // v10+ encrypted-index UnsupportedFeature deferral.
        if is_encrypted_compressed(
            entry.header().is_encrypted(),
            entry.header().compression_method(),
        ) {
            return Err(PaksmithError::UnsupportedFeature {
                context: format!(
                    "encrypted + compressed entry '{path}' is not yet supported: paksmith \
                     currently decrypts only uncompressed encrypted entries; your key may be correct"
                ),
            });
        }
        match entry.header().compression_method() {
            CompressionMethod::None | CompressionMethod::Zlib | CompressionMethod::Lz4 => {}
            method @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_)) => {
                warn!(path, ?method, "rejected unsupported compression method");
                return Err(PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: entry.header().offset(),
                    fault: DecompressionFault::UnsupportedMethod {
                        method: method.clone(),
                    },
                });
            }
        }

        // No `uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES` re-check
        // here: issue #58's open-time iteration in `PakReader::open`
        // already enforces the cap for every index entry, and the index
        // is immutable post-open. The deleted re-check was dead code
        // post-#58. Open-time enforcement is pinned by the
        // `open_rejects_oversized_uncompressed_size` integration test.
        // Issue #92.
        let mut guard = self.locked();
        let mut file = BufReader::new(&mut *guard);
        let in_data = self.open_entry_into(&mut file, entry)?;
        // After open_entry_into, `file` is positioned just past the in-data
        // FPakEntry record. Use the parsed in-data header's wire_size as
        // the single source of truth for the payload start, so any future
        // change to the wire format only needs updating in
        // PakEntryHeader::read_from (which `wire_size` mirrors by
        // construction).
        let payload_start = entry
            .header()
            .offset()
            .checked_add(in_data.wire_size())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::OffsetPlusHeader,
                },
            })?;

        match entry.header().compression_method() {
            CompressionMethod::None => {
                // Decrypt key (None for unencrypted entries; Some for encrypted).
                // `is_encrypted && key.is_none()` was already rejected above.
                let key = if entry.header().is_encrypted() {
                    self.key.as_ref()
                } else {
                    None
                };
                stream_uncompressed_to(&mut file, entry, self.file_size, key, writer)
            }
            CompressionMethod::Zlib => stream_zlib_to(
                &mut file,
                entry,
                self.file_size,
                payload_start,
                self.version(),
                writer,
            ),
            CompressionMethod::Lz4 => {
                stream_lz4_to(&mut file, entry, self.file_size, payload_start, writer)
            }
            // Already rejected at the top of `stream_entry_to`; this
            // arm exists to keep the match exhaustive (per CLAUDE.md
            // "no panics in core") without an opaque `_` catch-all.
            // If we ever reach here, the early-reject path was bypassed
            // by a refactor — surface the offending method via the
            // typed `StreamEntryToDispatchedUnsupportedCompression`
            // variant so operators see exactly which arm tripped.
            m @ (CompressionMethod::Gzip
            | CompressionMethod::Oodle
            | CompressionMethod::Zstd
            | CompressionMethod::Unknown(_)
            | CompressionMethod::UnknownByName(_)) => Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::StreamEntryToDispatchedUnsupportedCompression {
                    method: m.clone(),
                },
            }),
        }
    }
}

/// Returns `true` when an entry is BOTH encrypted AND compressed.
///
/// Encrypted + compressed entries require decrypting the 16-byte-aligned
/// payload region BEFORE per-block inflation — a layout that paksmith does
/// not yet support. Pulled out as a pure predicate so the fail-closed
/// decision in [`PakReader::stream_entry_to`] is unit-testable without an
/// (intentionally absent) encrypted+compressed fixture.
fn is_encrypted_compressed(is_encrypted: bool, method: &CompressionMethod) -> bool {
    is_encrypted && *method != CompressionMethod::None
}

impl ContainerReader for PakReader {
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + Send + '_> {
        Box::new(self.index.entries().iter().map(|e| {
            EntryMetadata::new(
                e.filename().to_owned(),
                e.header().compressed_size(),
                e.header().uncompressed_size(),
                EntryFlags {
                    compressed: *e.header().compression_method() != CompressionMethod::None,
                    encrypted: e.header().is_encrypted(),
                },
            )
        }))
    }

    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> crate::Result<u64> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;
        self.stream_entry_to(entry, writer)
    }

    /// Implements the trait's required `read_entry` (no default — see
    /// the trait docstring for why). Reserves the full uncompressed
    /// size via `Vec::try_reserve_exact` upfront, surfacing OOM as a
    /// typed `InvalidIndex` before any I/O begins.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>> {
        let entry = self
            .index
            .find(path)
            .ok_or_else(|| PaksmithError::EntryNotFound {
                path: path.to_string(),
            })?;

        let uncompressed_size = entry.header().uncompressed_size();
        // No `uncompressed_size > MAX_UNCOMPRESSED_ENTRY_BYTES` re-check
        // here: issue #58's open-time iteration enforces the cap for
        // every index entry, and the index is immutable post-open.
        // The deleted re-check was dead code post-#58. Open-time
        // enforcement is pinned by `open_rejects_oversized_uncompressed_size`.
        // Issue #92.
        let size_usize =
            usize::try_from(uncompressed_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::UncompressedSize,
                    value: uncompressed_size,
                    path: Some(path.to_string()),
                },
            })?;

        // Allocate fallibly upfront so a legitimate-but-large entry on a
        // memory-constrained host surfaces as a typed error rather than an
        // allocator abort during the streaming write.
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(size_usize).map_err(|source| {
            warn!(path, size = size_usize, error = %source, "output reservation failed");
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::EntryPayloadBytes,
                    requested: size_usize,
                    source,
                    path: Some(path.to_string()),
                },
            }
        })?;
        // Call the inner streamer directly with the entry we already
        // resolved, avoiding a second HashMap find through `read_entry_to`.
        let _ = self.stream_entry_to(entry, &mut buf)?;
        Ok(buf)
    }

    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    fn mount_point(&self) -> &str {
        self.index.mount_point()
    }
}

/// Read and AES-256-ECB-decrypt a pak index region into a `Zeroizing` buffer.
///
/// Returns the decrypted bytes of length `align_up(footer.index_size(), 16)`.
/// The real index occupies `footer.index_size()` bytes at the start; the
/// trailing AES-alignment pad bytes are not part of the index content.
///
/// Rejects `index_size > MAX_INDEX_BYTES` (1 GiB) before allocating, so
/// the overflow-safe `div_ceil(16) * 16` multiply and the `usize` conversion
/// are guaranteed to succeed on any supported platform. Returns
/// `BoundsExceeded` to distinguish a gigantic-index footer from a wrong-key
/// situation.
///
/// I/O errors from the seek/read stay as native [`PaksmithError::Io`].
/// Decryption alignment errors surface as [`PaksmithError::Decryption`].
fn decrypt_index_region<R: Read + Seek>(
    reader: &mut R,
    footer: &PakFooter,
    key: &AesKey,
) -> crate::Result<Zeroizing<Vec<u8>>> {
    let index_size = footer.index_size();

    // Cap before the 16-alignment multiply to avoid u64 overflow near
    // u64::MAX. Strict `>` so a size sitting exactly at the cap is accepted
    // (mirrors read_v10_plus_from). The flat reader bounds entry_count against
    // the byte budget but never rejects an oversized index_size outright —
    // this is the only enforcement point for the encrypted path.
    if index_size > MAX_INDEX_BYTES {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: WireField::IndexSize,
                value: index_size,
                limit: MAX_INDEX_BYTES,
                unit: BoundsUnit::Bytes,
                path: None,
            },
        });
    }

    // Encrypted regions are 16-aligned on disk. Overflow-safe because
    // index_size <= MAX_INDEX_BYTES (1 GiB) above, so index_size + 15 < u64::MAX.
    let aligned = index_size.div_ceil(16) * 16;
    let aligned_usize = usize::try_from(aligned).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::U64ExceedsPlatformUsize {
            field: WireField::IndexSize,
            value: aligned,
            path: None,
        },
    })?;

    // `Zeroizing` scrubs the plaintext index bytes on drop, consistent with
    // the key zeroization policy (`AesKey: ZeroizeOnDrop`).
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    buf.try_reserve_exact(aligned_usize)
        .map_err(|source| PaksmithError::InvalidIndex {
            fault: IndexParseFault::AllocationFailed {
                context: AllocationContext::EncryptedIndexBytes,
                requested: aligned_usize,
                source,
                path: None,
            },
        })?;
    buf.resize(aligned_usize, 0);

    // I/O errors stay as native `Io` — only the post-decrypt parse step is
    // mapped to `Decryption` by the callers.
    let _ = reader.seek(SeekFrom::Start(footer.index_offset()))?;
    reader.read_exact(&mut buf)?;
    crypto::aes256_ecb_decrypt(key, &mut buf)?;

    Ok(buf)
}

/// Read, AES-256-ECB-decrypt, and parse an encrypted pak index.
///
/// UE encrypts the index region in place and pads it to 16-byte
/// alignment, so the on-disk encrypted extent is
/// `align_up(index_size, 16)` bytes starting at `index_offset`. We slurp
/// that region, decrypt it, and hand the plaintext to
/// [`PakIndex::read_positioned`] via a `Cursor` (the seek-to-offset that
/// `read_from` performs is meaningless against an in-memory plaintext
/// buffer). Only the **flat (v3–v9)** index layout is supported here:
/// the path-hash (v10+) index uses PHI and FDI sub-regions with absolute
/// file-position seeks that are incompatible with a `Cursor`-based
/// decryption approach. v10+ encrypted-index paks are rejected with
/// [`PaksmithError::UnsupportedFeature`] before reaching the decrypt step.
///
/// **Fail-closed.** A wrong key produces garbage plaintext that the
/// index parser's magic/bounds checks reject; that parse error is mapped
/// to [`PaksmithError::Decryption`] so the caller can't tell a wrong key
/// from a corrupt index (and neither leaks an opaque parse fault). Only
/// the post-decrypt parse is wrapped — the seek/`read_exact` I/O stays as
/// its native [`PaksmithError::Io`].
///
/// **No unbounded allocation.** `decrypt_index_region` caps `index_size` at
/// [`MAX_INDEX_BYTES`] (1 GiB) before the 16-alignment multiply (which
/// would otherwise overflow near `u64::MAX`), the `usize` conversion, and a
/// fallible `try_reserve_exact` — every step surfaces a typed error rather
/// than aborting the process.
fn read_encrypted_index<R: Read + Seek>(
    reader: &mut R,
    footer: &PakFooter,
    file_size: u64,
    key: &AesKey,
) -> crate::Result<PakIndex> {
    // v10+ (path-hash index) uses PHI and FDI sub-regions with absolute
    // file-position seeks — incompatible with the Cursor-based decryption
    // below. Reject early with a clear non-Decryption error so the user
    // doesn't think their key is wrong (deferred, not a wrong-key situation).
    if footer.version().has_path_hash_index() {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "encrypted v{} (path-hash index layout) is not yet supported: \
                 the path-hash and full-directory-index regions use absolute file \
                 positions incompatible with in-memory decryption; your key may be \
                 correct",
                footer.version().wire_version()
            ),
        });
    }

    let index_size = footer.index_size();
    let buf = decrypt_index_region(reader, footer, key)?;

    // Parse the decrypted plaintext. A wrong key → garbage → the parser's
    // magic/bounds checks fail (including `Io(UnexpectedEof)` from
    // `read_fstring` when garbage lengths exhaust the `Take` boundary).
    // Map all of these to a fail-closed `Decryption`.
    // `index_size` (not the 16-aligned length) is the real index byte
    // budget; the trailing AES pad bytes are not part of the index.
    //
    // Pass-through only resource/platform faults (AllocationFailed,
    // U64ExceedsPlatformUsize) that are independent of key correctness.
    // All other errors — including Io from the in-memory Cursor reader —
    // map to Decryption: they arise from garbage plaintext, not I/O
    // failures on the underlying file (those propagated before map_err).
    PakIndex::read_positioned(
        &mut Cursor::new(&buf[..]),
        footer.version(),
        index_size,
        file_size,
        footer.compression_methods(),
    )
    .map_err(|e| {
        let is_resource_fault = matches!(
            e,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed { .. }
                    | IndexParseFault::U64ExceedsPlatformUsize { .. },
            }
        );
        if is_resource_fault {
            e
        } else {
            debug!(?e, "encrypted index parse failed — likely wrong key");
            PaksmithError::Decryption { path: None }
        }
    })
}

/// Stream the uncompressed payload of `entry` from `file` to `writer`.
/// Returns the number of bytes written (equals `uncompressed_size`).
///
/// When `key` is `Some`, the entry is AES-256-ECB encrypted: the on-disk
/// payload is 16-byte aligned (padded with trailing zeros by UE's pak writer).
/// The full aligned block is read into a `Zeroizing` buffer, decrypted in
/// place, trimmed to the real `uncompressed_size`, and then written. This
/// sacrifices the streaming property for encrypted entries — peak allocation
/// is `align_up(uncompressed_size, 16)` bytes — but remains bounded by
/// `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB), which is enforced at open time.
///
/// When `key` is `None`, the path is the original zero-copy stream via
/// `io::copy`'s 8 KiB internal buffer.
fn stream_uncompressed_to<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    key: Option<&AesKey>,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    let path = entry.filename();
    let size = entry.header().uncompressed_size();

    if let Some(key) = key {
        // Encrypted uncompressed entry: on-disk bytes are 16-aligned.
        // `size <= MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) is enforced at open
        // time, so `size + 15` cannot overflow u64.
        let aligned = size.div_ceil(16) * 16;
        let aligned_usize = usize::try_from(aligned).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ExceedsPlatformUsize {
                field: WireField::UncompressedSize,
                value: aligned,
                path: Some(path.to_string()),
            },
        })?;

        // Bounds-check the aligned read against EOF.
        let payload_start = file.stream_position()?;
        let payload_end =
            payload_start
                .checked_add(aligned)
                .ok_or_else(|| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        path: Some(path.to_string()),
                        operation: OverflowSite::PayloadEnd,
                    },
                })?;
        if payload_end > file_size {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    path: path.to_string(),
                    kind: OffsetPastFileSizeKind::PayloadEndBounds {
                        payload_end,
                        file_size_max: file_size,
                    },
                },
            });
        }

        // Read the aligned ciphertext into a zeroize-on-drop buffer, decrypt,
        // then write only the `size` real bytes to the caller's writer.
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        buf.try_reserve_exact(aligned_usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::EntryPayloadBytes,
                    requested: aligned_usize,
                    source,
                    path: Some(path.to_string()),
                },
            })?;
        buf.resize(aligned_usize, 0);
        file.read_exact(&mut buf)?;
        crypto::aes256_ecb_decrypt(key, &mut buf)?;

        let size_usize = usize::try_from(size).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ExceedsPlatformUsize {
                field: WireField::UncompressedSize,
                value: size,
                path: Some(path.to_string()),
            },
        })?;
        writer.write_all(&buf[..size_usize])?;
        return Ok(size);
    }

    // For uncompressed entries the payload immediately follows the in-data
    // header, so the reader is already positioned correctly. Bounds-check
    // the payload against EOF before reading.
    let payload_end =
        file.stream_position()?
            .checked_add(size)
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::PayloadEnd,
                },
            })?;
    if payload_end > file_size {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::OffsetPastFileSize {
                path: path.to_string(),
                kind: OffsetPastFileSizeKind::PayloadEndBounds {
                    payload_end,
                    file_size_max: file_size,
                },
            },
        });
    }

    let mut limited = file.by_ref().take(size);
    let written = io::copy(&mut limited, writer)?;
    if written != size {
        // Should be unreachable given the bounds check above, but the
        // file-grew-since-open invariant could be violated by an external
        // truncation. Surface it as a typed error instead of silent
        // short-write.
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::ShortEntryRead {
                path: path.to_string(),
                written,
                expected: size,
            },
        });
    }
    Ok(written)
}

/// Validate one compression block's `(start, end)` pair against
/// the entry's payload region, the file size, and the previously
/// validated block's end (for monotonic file-order). Returns the
/// computed absolute `(abs_start, abs_end)` and updates
/// `prev_abs_end` so the next call sees this block's end.
///
/// Colocated with both call sites (`stream_zlib_to` for the
/// extract path and `verify_entry`'s Zlib arm for the hash path)
/// so the three checks (`StartOverlapsHeader`, `EndPastFileSize`,
/// `OutOfOrder`) live in one place. Without the shared helper a
/// regression that hardens one path silently leaves the other
/// vulnerable — verify and read would diverge on the same
/// pathological archive. Issue #129.
fn validate_block_bounds(
    block: &CompressionBlock,
    block_index: usize,
    entry_offset: u64,
    payload_start: u64,
    file_size: u64,
    prev_abs_end: &mut Option<u64>,
    path: &str,
) -> crate::Result<(u64, u64)> {
    let abs_start =
        entry_offset
            .checked_add(block.start())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::BlockStart,
                },
            })?;
    let abs_end =
        entry_offset
            .checked_add(block.end())
            .ok_or_else(|| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ArithmeticOverflow {
                    path: Some(path.to_string()),
                    operation: OverflowSite::BlockEnd,
                },
            })?;
    if abs_start < payload_start {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BlockBoundsViolation {
                path: path.to_string(),
                block_index,
                kind: BlockBoundsKind::StartOverlapsHeader {
                    block_start: abs_start,
                    payload_start_min: payload_start,
                },
            },
        });
    }
    if abs_end > file_size {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BlockBoundsViolation {
                path: path.to_string(),
                block_index,
                kind: BlockBoundsKind::EndPastFileSize {
                    block_end: abs_end,
                    file_size_max: file_size,
                },
            },
        });
    }
    // Strict `<` — touching blocks (`abs_start == prev_abs_end`)
    // are the standard layout, only true overlap or backward-
    // ordering is the wire-attacker pathology.
    if let Some(prev) = *prev_abs_end
        && abs_start < prev
    {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BlockBoundsViolation {
                path: path.to_string(),
                block_index,
                kind: BlockBoundsKind::OutOfOrder {
                    block_start: abs_start,
                    prev_block_end_min: prev,
                },
            },
        });
    }
    *prev_abs_end = Some(abs_end);
    Ok((abs_start, abs_end))
}

/// Read one compressed block from `file` into `buf`.
///
/// Shared input-side scaffold of [`stream_zlib_to`] and
/// [`stream_lz4_to`]: narrow the block length to `usize`, seek to the
/// block's absolute start, fallibly reserve through the
/// [`PakSeam::CompressedReserve`] OOM seam, and read exactly the
/// on-disk compressed bytes. `buf` is `clear()`ed, not dropped, so
/// hoisted capacity survives across blocks (#373). `codec` labels the
/// reservation-failure `warn!` ("zlib" / "lz4") so the per-codec
/// operator log strings stay byte-identical to their pre-extraction
/// forms.
fn read_compressed_block<R: Read + Seek>(
    file: &mut R,
    buf: &mut Vec<u8>,
    block_len: u64,
    abs_start: u64,
    block_index: usize,
    codec: &'static str,
    path: &str,
) -> crate::Result<()> {
    let block_len_usize = usize::try_from(block_len).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::U64ExceedsPlatformUsize {
            field: WireField::BlockLength,
            value: block_len,
            path: Some(path.to_string()),
        },
    })?;

    let _ = file.seek(SeekFrom::Start(abs_start))?;
    // Bounded by file_size (via `validate_block_bounds`'s abs_end
    // check). Allocate fallibly so OOM is typed; `clear()` preserves
    // the hoisted capacity from prior blocks and `try_reserve_exact`
    // re-allocates only if this block needs more room than any
    // predecessor.
    buf.clear();
    let reserve_res = buf.try_reserve_exact(block_len_usize);
    crate::seams::seam_check!(
        reserve_res,
        crate::testing::oom::SeamSite::Pak(PakSeam::CompressedReserve)
    );
    reserve_res.map_err(|e| {
        warn!(path, block = block_index, block_len, error = %e, "{codec} block reservation failed");
        PaksmithError::Decompression {
            path: path.to_string(),
            offset: abs_start,
            fault: DecompressionFault::CompressedBlockReserveFailed {
                block_index,
                requested: block_len_usize,
                source: e,
            },
        }
    })?;
    buf.resize(block_len_usize, 0);
    file.read_exact(buf)?;
    Ok(())
}

/// Enforce the end-of-entry size invariant shared by
/// [`stream_zlib_to`] and [`stream_lz4_to`]: the cumulative
/// decompressed byte count must equal the index-declared
/// `uncompressed_size`, else the entry is truncated or corrupt
/// ([`DecompressionFault::SizeUnderrun`]).
fn check_cumulative_size(
    bytes_written: u64,
    uncompressed_size: u64,
    entry_offset: u64,
    path: &str,
) -> crate::Result<()> {
    if bytes_written == uncompressed_size {
        return Ok(());
    }
    warn!(
        path,
        actual = bytes_written,
        uncompressed_size,
        "cumulative decompressed size mismatch"
    );
    Err(PaksmithError::Decompression {
        path: path.to_string(),
        offset: entry_offset,
        fault: DecompressionFault::SizeUnderrun {
            actual: bytes_written,
            expected: uncompressed_size,
        },
    })
}

/// Stream the zlib-decompressed payload of `entry` from `file` to
/// `writer`. Returns the number of decompressed bytes written.
///
/// Peak heap allocation is one compression block at a time: a
/// compressed-input buffer sized to the largest block seen so far,
/// plus a decompressed-output buffer sized to that block's output.
/// Both buffers are hoisted outside the per-block loop and reuse
/// capacity across blocks (#373); the full `uncompressed_size`
/// never lives in memory at once. A K-block entry pays 2
/// allocations on the first block, then runs allocator-free for
/// every subsequent block whose `len()` is `<=` the running peak.
#[allow(clippy::too_many_lines)] // bounded by per-block error-reporting + zlib-stream branches
fn stream_zlib_to<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    version: PakVersion,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    let path = entry.filename();

    if version < PakVersion::RelativeChunkOffsets {
        // Pre-v5 paks store absolute file offsets in compression_blocks rather
        // than offsets relative to the entry record. Real-world v3/v4 paks are
        // rare; reject explicitly rather than silently producing garbage.
        return Err(PaksmithError::UnsupportedVersion {
            version: version.wire_version(),
        });
    }

    let uncompressed_size = entry.header().uncompressed_size();
    let mut bytes_written: u64 = 0;

    // Per-call scratch buffer reused across all compression blocks.
    // Hoisted out of the per-block loop so a multi-block entry pays
    // one allocation, not N — at 32 KiB heap-alloc per block, a
    // 100-block entry × 10k entries during bulk extract was tens of
    // thousands of redundant allocs. 32 KiB matches zlib's typical
    // inflate window. Heap-allocated (not `[0u8; 32 * 1024]`) to
    // satisfy clippy's `large_stack_arrays` lint and stay portable
    // to small-stack platforms.
    let mut scratch = vec![0u8; 32 * 1024];

    // Per-block compressed-input and decompressed-output buffers,
    // also hoisted (#373). `Vec::clear()` keeps the heap allocation,
    // so subsequent blocks reuse the same buffer if the prior block
    // was at least as large. The `try_reserve_*` inside the loop is
    // a no-op on capacity hits and re-allocates only on growth.
    // Net for a K-block entry: 2 allocations instead of 2K. The OOM
    // seams (`CompressedReserve`, `ScratchReserve`) still fire via
    // `seam_check!` on every `try_reserve_*` call because the
    // macro runs `Ok.and_then(|()| maybe_fail_at(site))` regardless
    // of whether the allocator was actually consulted.
    let mut compressed: Vec<u8> = Vec::new();
    let mut block_out: Vec<u8> = Vec::new();

    // Track the previous block's end so `validate_block_bounds` can
    // enforce monotonic file-order (issue #129) across loop iters.
    let mut prev_abs_end: Option<u64> = None;

    for (i, block) in entry.header().compression_blocks().iter().enumerate() {
        let (abs_start, _abs_end) = validate_block_bounds(
            block,
            i,
            entry.header().offset(),
            payload_start,
            file_size,
            &mut prev_abs_end,
            path,
        )?;

        read_compressed_block(
            file,
            &mut compressed,
            block.len(),
            abs_start,
            i,
            "zlib",
            path,
        )?;

        // Bound the decoder to the remaining output budget plus one byte.
        // The +1 lets us detect "decompressed more than we expected" without
        // allowing unbounded growth: a zlib bomb that wants to expand past
        // `uncompressed_size` will be cut off at uncompressed_size + 1, then
        // the post-loop length check rejects.
        let remaining = uncompressed_size.saturating_sub(bytes_written);
        let budget = remaining.saturating_add(1);
        let mut limited = ZlibDecoder::new(&compressed[..]).take(budget);
        // Per-block decompressed buffer. We can't `write_all` directly
        // into the output writer because we need the full block's
        // decompressed length for the bomb check and the per-block
        // sanity assertion before committing.
        //
        // The previous implementation used `read_to_end`, which grows
        // the Vec infallibly via `Vec::reserve`. Combined with the
        // 8 GiB `MAX_UNCOMPRESSED_ENTRY_BYTES` ceiling on `budget`,
        // that path could OOM-abort on a malicious entry. Instead, we
        // read in fixed-size scratch chunks and `try_reserve` per
        // chunk so the allocation grows fallibly and surfaces as a
        // typed `Decompression` error rather than an
        // `alloc::handle_alloc_error` abort.
        //
        // `clear()` keeps the heap allocation across blocks (#373);
        // first block grows fresh, subsequent blocks reuse capacity.
        block_out.clear();
        let written = loop {
            let n = limited.read(&mut scratch).map_err(|e| {
                warn!(path, block = i, abs_start, error = %e, "zlib decompress failed");
                PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    fault: DecompressionFault::ZlibStreamError {
                        block_index: i,
                        kind: e.kind(),
                        message: e.to_string(),
                    },
                }
            })?;
            if n == 0 {
                break block_out.len();
            }
            let scratch_res = block_out.try_reserve(n);
            crate::seams::seam_check!(
                scratch_res,
                crate::testing::oom::SeamSite::Pak(PakSeam::ScratchReserve)
            );
            scratch_res.map_err(|e| {
                // Mirror the warn! at the sibling CompressedBlockReserveFailed
                // site so operators triaging an OOM via the tracing stream
                // see both reserve-failed paths. `already_committed` is the
                // triage signal that distinguishes small-allocator-pressure
                // (failure on the first chunk) from genuine large-entry OOM
                // (failure after gigabytes accumulated).
                warn!(
                    path,
                    block = i,
                    requested = n,
                    already_committed = block_out.len(),
                    error = %e,
                    "zlib scratch reservation failed mid-decode"
                );
                PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    fault: DecompressionFault::ZlibScratchReserveFailed {
                        block_index: i,
                        requested: n,
                        already_committed: block_out.len(),
                        source: e,
                    },
                }
            })?;
            block_out.extend_from_slice(&scratch[..n]);
        };

        let new_total = bytes_written.saturating_add(written as u64);
        if new_total > uncompressed_size {
            warn!(
                path,
                block = i,
                actual = new_total,
                uncompressed_size,
                "decompression bomb: block exceeded uncompressed_size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::DecompressionBomb {
                    block_index: i,
                    actual: new_total,
                    claimed_uncompressed: uncompressed_size,
                },
            });
        }

        // Sanity: every block except possibly the last should produce exactly
        // compression_block_size bytes when decompressed.
        if i + 1 < entry.header().compression_blocks().len()
            && written as u64 != u64::from(entry.header().compression_block_size())
        {
            let expected = entry.header().compression_block_size();
            warn!(
                path,
                block = i,
                written,
                expected,
                "non-final block decompressed to wrong size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::NonFinalBlockSizeMismatch {
                    block_index: i,
                    expected,
                    actual: written as u64,
                },
            });
        }

        // Block validated — commit to the output writer.
        writer.write_all(&block_out)?;
        bytes_written = new_total;
    }

    check_cumulative_size(
        bytes_written,
        uncompressed_size,
        entry.header().offset(),
        path,
    )?;

    Ok(bytes_written)
}

/// Maximum factor by which one raw LZ4 block can inflate: a block of
/// N compressed bytes decodes to at most `N × 255` output bytes.
/// Literals copy 1:1; the only amplifying construct is a match-length
/// extension byte, and each 0xFF extension byte contributes at most
/// 255 output bytes (LZ4 Block Format). The true supremum is strictly
/// below 255 (offset/token overhead is never zero), so `N × 255` is a
/// safe over-estimate that never under-sizes a valid decode.
const MAX_LZ4_BLOCK_EXPANSION_RATIO: u64 = 255;

/// Bound the pre-decode output reservation for one LZ4 block.
///
/// `expected_out` is the pak-derived output size for this block
/// (`min(compression_block_size, remaining)`) — but
/// `compression_block_size` is attacker-controlled and NOT capped on
/// the inline v3-v9 read path, so pre-allocating it verbatim lets a
/// tiny crafted block force a multi-gigabyte eager allocation
/// (memory-amplification DoS, #636). Intersecting with
/// `compressed_len × `[`MAX_LZ4_BLOCK_EXPANSION_RATIO`] keeps the
/// reservation input-proportional: a valid block's real output is
/// always `≤ compressed_len × 255`, so the cap is transparent for
/// well-formed entries and only bites the crafted case. The resulting
/// buffer is still the decompression-bomb cap — `decompress_into`
/// errors if the block tries to inflate past it.
fn lz4_block_output_cap(expected_out: u64, compressed_len: u64) -> u64 {
    expected_out.min(compressed_len.saturating_mul(MAX_LZ4_BLOCK_EXPANSION_RATIO))
}

/// Stream the LZ4-decompressed payload of `entry` from `file` to
/// `writer`. Returns the number of decompressed bytes written.
///
/// UE pak LZ4 payloads are independent RAW LZ4 blocks (no LZ4-frame
/// header, no size prefix) — the block form repak writes via
/// `lz4_flex::block::compress` and the CUE4Parse reference decodes
/// (`K4os LZ4Codec.Decode` into a caller-sized buffer). The reader
/// derives each block's decompressed size: every block except the
/// last inflates to exactly `compression_block_size`; the last takes
/// the remainder of `uncompressed_size`. See
/// `docs/formats/compression/lz4.md`. Issue #636.
///
/// Buffer discipline mirrors [`stream_zlib_to`] (#373): one
/// compressed-input buffer and one decompressed-output buffer,
/// hoisted and capacity-reused across blocks; the full
/// `uncompressed_size` never lives in memory at once. Unlike zlib
/// there is no mid-decode growth loop — the output buffer is
/// pre-sized to the block's expected output, which doubles as the
/// decompression-bomb cap: `lz4_flex::block::decompress_into` errors
/// on a block that would expand past it (surfaced as
/// [`DecompressionFault::Lz4DecodeError`]), so over-expansion can
/// never allocate beyond the per-block expected size.
#[allow(clippy::too_many_lines)] // bounded by per-block error-reporting, mirroring stream_zlib_to
fn stream_lz4_to<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    // NOTE: unlike `stream_zlib_to`, this takes no `version` and has no
    // pre-v5 relative-offset guard. `CompressionMethod::Lz4` is
    // obtainable ONLY through the v8+ FName compression-slot table
    // (`CompressionMethod::from_name`); the v3-v7 numeric method IDs
    // (`from_u32`) never yield `Lz4`. So any entry reaching here parsed
    // as v8 or newer, where compression-block offsets are already
    // relative — the guard `stream_zlib_to` needs (zlib IS reachable
    // pre-v5 via numeric method 1) would be structurally unreachable
    // dead code here. Defense in depth: even a hypothetical
    // absolute-offset entry reaching this loop fails closed at
    // `validate_block_bounds` (abs_end > file_size), never decoding
    // out-of-bounds bytes.
    let path = entry.filename();

    let uncompressed_size = entry.header().uncompressed_size();
    let block_size = u64::from(entry.header().compression_block_size());
    let mut bytes_written: u64 = 0;

    // Hoisted per-block buffers (#373): `clear()` keeps capacity, so
    // a K-block entry pays 2 allocations, not 2K.
    let mut compressed: Vec<u8> = Vec::new();
    let mut block_out: Vec<u8> = Vec::new();

    let mut prev_abs_end: Option<u64> = None;

    for (i, block) in entry.header().compression_blocks().iter().enumerate() {
        let (abs_start, _abs_end) = validate_block_bounds(
            block,
            i,
            entry.header().offset(),
            payload_start,
            file_size,
            &mut prev_abs_end,
            path,
        )?;

        let block_len = block.len();
        read_compressed_block(file, &mut compressed, block_len, abs_start, i, "lz4", path)?;

        // Expected decompressed size for THIS block: the fixed
        // compression_block_size for every block except the last,
        // which takes the remainder. `min` covers both (the remainder
        // is < block_size only on the final block of a well-formed
        // entry). A crafted entry with excess blocks yields expected 0
        // for the extras: non-final extras die at the block-size check
        // below (a 0-byte decode != block_size), and while a single
        // TRAILING zero-output block (e.g. the 1-byte `0x00` "empty
        // last sequence" block) does decode Ok into an empty buffer,
        // it produces no bytes — output stays exactly the declared
        // `uncompressed_size` via `check_cumulative_size`. The repak
        // oracle is more lenient still (it silently ignores ALL excess
        // blocks), so this is matching-or-stricter behavior.
        let remaining = uncompressed_size.saturating_sub(bytes_written);
        let expected_out = remaining.min(block_size);

        // SECURITY (#636): cap the reservation input-proportionally —
        // see `lz4_block_output_cap` for the derivation and threat
        // model. The capped buffer remains the decompression-bomb cap.
        let alloc_bound = lz4_block_output_cap(expected_out, block_len);
        let alloc_usize =
            usize::try_from(alloc_bound).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::CompressionBlockSize,
                    value: alloc_bound,
                    path: Some(path.to_string()),
                },
            })?;

        // Fallible output reservation so OOM surfaces typed, with its
        // own seam site (#636).
        block_out.clear();
        let out_reserve_res = block_out.try_reserve_exact(alloc_usize);
        crate::seams::seam_check!(
            out_reserve_res,
            crate::testing::oom::SeamSite::Pak(PakSeam::Lz4OutputReserve)
        );
        out_reserve_res.map_err(|e| {
            warn!(
                path,
                block = i,
                requested = alloc_usize,
                error = %e,
                "lz4 output reservation failed"
            );
            PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::Lz4OutputReserveFailed {
                    block_index: i,
                    requested: alloc_usize,
                    source: e,
                },
            }
        })?;
        block_out.resize(alloc_usize, 0);

        // Raw-block decode into the pre-sized buffer. The buffer IS
        // the bomb cap: over-expansion errors inside the decoder.
        let produced =
            lz4_flex::block::decompress_into(&compressed, &mut block_out).map_err(|e| {
                warn!(path, block = i, abs_start, error = %e, "lz4 decompress failed");
                PaksmithError::Decompression {
                    path: path.to_string(),
                    offset: abs_start,
                    fault: DecompressionFault::Lz4DecodeError {
                        block_index: i,
                        message: e.to_string(),
                    },
                }
            })?;

        // Sanity: every block except possibly the last must produce
        // exactly compression_block_size bytes — same invariant and
        // fault as the zlib path.
        if i + 1 < entry.header().compression_blocks().len() && produced as u64 != block_size {
            let expected = entry.header().compression_block_size();
            warn!(
                path,
                block = i,
                produced,
                expected,
                "non-final lz4 block decompressed to wrong size"
            );
            return Err(PaksmithError::Decompression {
                path: path.to_string(),
                offset: abs_start,
                fault: DecompressionFault::NonFinalBlockSizeMismatch {
                    block_index: i,
                    expected,
                    actual: produced as u64,
                },
            });
        }

        // Block validated — commit exactly the produced bytes.
        writer.write_all(&block_out[..produced])?;
        bytes_written = bytes_written.saturating_add(produced as u64);
    }

    check_cumulative_size(
        bytes_written,
        uncompressed_size,
        entry.header().offset(),
        path,
    )?;

    Ok(bytes_written)
}

/// Default scratch-buffer size for streaming SHA1 computation. Sized to
/// match `BufReader`'s default capacity so we don't fragment reads against
/// the underlying buffered reader. Stack-allocated by callers as
/// `[0u8; HASH_BUFFER_BYTES]` (8 KiB is well within any reasonable stack
/// limit; neither `verify_index` nor `verify_entry` recurses).
const HASH_BUFFER_BYTES: usize = 8 * 1024;

/// Outcome of a single SHA1 verification call.
///
/// Marked `#[must_use]` because the variants distinguish "verified" from
/// "skipped because we couldn't check" — silently dropping the value with
/// `let _ = reader.verify_entry(p);` defeats the purpose of opt-in
/// verification. Marked `#[non_exhaustive]` because future variants
/// (e.g., `SkippedUnsupportedCompression`) are plausible follow-up work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "VerifyOutcome distinguishes Verified from Skipped — \
              check the variant or use VerifyStats::is_fully_verified"]
#[non_exhaustive]
pub enum VerifyOutcome {
    /// Hash was computed and matched the stored value.
    Verified,
    /// The stored hash slot is all zeros — UE's "no integrity claim
    /// recorded" sentinel. Nothing was hashed.
    SkippedNoHash,
    /// The entry is AES-encrypted; verifying ciphertext without the key is
    /// not supported. Only ever returned by [`PakReader::verify_entry`],
    /// never by [`PakReader::verify_index`].
    SkippedEncrypted,
}

/// Per-region verification state for the v10+ encoded-index regions
/// (full directory index and optional path hash index).
///
/// Distinct from [`VerifyOutcome`] because regions can be `NotPresent`
/// (pre-v10 archives have no FDI/PHI; PHI is also optional in v10+),
/// whereas `VerifyOutcome` always describes a region that exists.
/// `#[non_exhaustive]` for forward-compat with future region kinds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegionVerifyState {
    /// Region not present in this archive. Pre-v10 archives have no
    /// FDI or PHI; v10+ archives may omit the PHI. The default for
    /// `VerifyStats` so legacy callers see the natural value before
    /// [`PakReader::verify`] populates per-region state.
    #[default]
    NotPresent,
    /// Region's hash slot is the all-zero sentinel ("no integrity
    /// claim was recorded at write time"). Region bytes were not
    /// hashed. Counts against [`VerifyStats::is_fully_verified`].
    SkippedNoHash,
    /// Region bytes were hashed and matched the stored SHA1.
    Verified,
}

/// Structured report from [`PakReader::verify`]: counts of what was
/// actually hashed vs skipped, so callers can distinguish "fully verified"
/// from "verification ran but skipped some entries we couldn't check."
///
/// Marked `#[non_exhaustive]` to allow future fields (e.g., a count of
/// entries with detected I/O errors during partial-archive recovery)
/// without breaking downstream pattern-matchers. Fields are `pub(crate)`
/// — external callers read counts via the named accessors below
/// ([`Self::index_verified`], [`Self::entries_verified`], etc.) and
/// the high-level helper [`Self::is_fully_verified`]. This keeps the
/// struct's internal representation free to change (e.g., split a
/// counter into per-reason buckets) without breaking downstream
/// consumers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyStats {
    pub(crate) index_verified: bool,
    pub(crate) index_skipped_no_hash: bool,
    /// V10+ full-directory-index region state. `NotPresent` for v3-v9
    /// archives. Issue #86.
    pub(crate) fdi: RegionVerifyState,
    /// V10+ path-hash-index region state. `NotPresent` for v3-v9 and
    /// for v10+ archives without a PHI. Issue #86.
    pub(crate) phi: RegionVerifyState,
    pub(crate) entries_verified: usize,
    pub(crate) entries_skipped_no_hash: usize,
    pub(crate) entries_skipped_encrypted: usize,
}

impl VerifyStats {
    /// True iff the index hash was computed and matched.
    pub fn index_verified(&self) -> bool {
        self.index_verified
    }

    /// True iff the index had no recorded hash (zeroed slot, accepted
    /// as a no-integrity-claim signal rather than a tampering one).
    pub fn index_skipped_no_hash(&self) -> bool {
        self.index_skipped_no_hash
    }

    /// V10+ full-directory-index region verification state. Returns
    /// [`RegionVerifyState::NotPresent`] for pre-v10 archives. Issue
    /// #86: the FDI region's bytes live at an arbitrary file offset
    /// outside the main-index byte range, with an independent SHA1
    /// slot in the main-index header. Pre-fix, the slot was discarded.
    pub fn fdi(&self) -> RegionVerifyState {
        self.fdi
    }

    /// V10+ path-hash-index region verification state. Returns
    /// [`RegionVerifyState::NotPresent`] for pre-v10 archives and for
    /// v10+ archives whose main-index header recorded
    /// `has_path_hash_index = false`.
    pub fn phi(&self) -> RegionVerifyState {
        self.phi
    }

    /// Number of entries whose hash was computed and matched.
    pub fn entries_verified(&self) -> usize {
        self.entries_verified
    }

    /// Number of entries skipped because the stored SHA1 was the all-zero
    /// sentinel (no integrity claim recorded at write time) or the entry
    /// was a v10+ encoded record (which omits SHA1 from the wire format).
    pub fn entries_skipped_no_hash(&self) -> usize {
        self.entries_skipped_no_hash
    }

    /// Number of entries skipped because they are AES-encrypted (hashing
    /// ciphertext is meaningless without the key).
    pub fn entries_skipped_encrypted(&self) -> usize {
        self.entries_skipped_encrypted
    }

    /// Number of entries skipped for any reason (no-hash + encrypted).
    /// Sum of [`Self::entries_skipped_no_hash`] and
    /// [`Self::entries_skipped_encrypted`]. Convenience for callers
    /// that only care about the total skip count rather than the
    /// reason — e.g., the post-verify warn log in [`PakReader::verify`]
    /// and downstream "did anything get skipped?" predicates.
    pub fn total_skipped_entries(&self) -> usize {
        self.entries_skipped_no_hash + self.entries_skipped_encrypted
    }

    /// True iff every byte the verifier could see was hashed and matched.
    /// Use this in security-sensitive contexts where any `SkippedNoHash`
    /// outcome should be treated as a potential downgrade attack on the
    /// stored hash slot — UE's writer either records integrity for the
    /// whole archive or for none of it, so a partial-skip in a context
    /// you control end-to-end is a tampering signal.
    ///
    /// Equivalent to manually checking that the index was verified, no
    /// entries were skipped for either reason, and at least one entry was
    /// actually hashed. The "at least one entry" requirement defends
    /// against the empty-but-hashed-shell substitution attack: an
    /// attacker who replaces a populated archive with a zero-entry
    /// archive whose index correctly hashes still fails this check.
    ///
    /// **PHI ↔ FDI consistency (issue #131):** for v10+ archives
    /// with a PHI region, `is_fully_verified() == true` now also
    /// implies that the PHI's `(fnv64(path) → encoded_offset)`
    /// mappings agree with the FDI's `(path → encoded_offset)`
    /// walk for every file. The cross-check fires at
    /// `PakReader::open` time — any disagreement surfaces as
    /// `IndexParseFault::PhiFdiInconsistency` before this accessor
    /// is reachable. Pre-#131 the gap was a documented caveat: an
    /// attacker who rewrote the PHI's stored SHA-1 could redirect
    /// a known hash to a different offset without triggering any
    /// signal. That cross-check is now load-bearing at open time.
    pub fn is_fully_verified(&self) -> bool {
        // Region state passes if Verified or NotPresent — the latter
        // is the legitimate "no FDI/PHI in this archive" case for
        // pre-v10 archives and for v10+ archives without a PHI.
        // SkippedNoHash counts against full verification, same as
        // the main index's `index_skipped_no_hash`.
        let fdi_ok = matches!(
            self.fdi,
            RegionVerifyState::Verified | RegionVerifyState::NotPresent
        );
        let phi_ok = matches!(
            self.phi,
            RegionVerifyState::Verified | RegionVerifyState::NotPresent
        );
        self.index_verified
            && !self.index_skipped_no_hash
            && fdi_ok
            && phi_ok
            && self.entries_skipped_no_hash == 0
            && self.entries_skipped_encrypted == 0
            && self.entries_verified > 0
    }
}

/// Reduce per-region verify outcomes to a single conservative
/// `VerifyOutcome` for the back-compat return value of
/// [`PakReader::verify_index`]. The pre-#86 method returned only the
/// main-index outcome; post-fix, `verify_index` covers all three
/// regions and the conservative outcome is the "worst" state
/// observed across them — anything less than `Verified` from any
/// region wins, because any non-Verified state means full coverage
/// wasn't achieved.
///
/// `HashMismatch` / `IntegrityStripped` don't appear here: those
/// short-circuit as `Err` before this function is reached, so the
/// inputs are always `Ok` variants.
///
/// The per-region match is exhaustive (no `_` arm) so that any
/// future variant added to `VerifyOutcome` (it's `#[non_exhaustive]`
/// — e.g. the documented `SkippedUnsupportedCompression` candidate)
/// fails the build here rather than silently laundering into
/// `Verified`. That's the exact silent-tamper-gap shape #86 fixed
/// for the regions themselves; the same discipline must apply to
/// the outcome reducer.
fn combine_index_outcomes(
    main: VerifyOutcome,
    fdi: Option<VerifyOutcome>,
    phi: Option<VerifyOutcome>,
) -> VerifyOutcome {
    let reduce = |o: VerifyOutcome| match o {
        VerifyOutcome::Verified => VerifyOutcome::Verified,
        VerifyOutcome::SkippedNoHash => VerifyOutcome::SkippedNoHash,
        VerifyOutcome::SkippedEncrypted => VerifyOutcome::SkippedEncrypted,
    };
    let prefer_worse = |a: VerifyOutcome, b: VerifyOutcome| match (a, b) {
        (VerifyOutcome::Verified, other) | (other, VerifyOutcome::Verified) => other,
        // Any non-Verified beats Verified; among non-Verified states
        // the choice is arbitrary (callers should consult VerifyStats
        // for per-region detail). Pick `a` for determinism.
        (a, _) => a,
    };
    let mut worst = reduce(main);
    if let Some(o) = fdi {
        worst = prefer_worse(worst, reduce(o));
    }
    if let Some(o) = phi {
        worst = prefer_worse(worst, reduce(o));
    }
    worst
}

/// Read exactly `len` bytes from `reader` and return the SHA1 digest.
/// `buf` is the caller-owned scratch buffer — fixed-size at
/// [`HASH_BUFFER_BYTES`] so an empty buffer is structurally
/// unrepresentable (issue #45). Reusing one buffer across calls
/// avoids reallocating per invocation in the multi-block hashing path.
fn sha1_of_reader<R: Read>(
    reader: &mut R,
    len: u64,
    buf: &mut [u8; HASH_BUFFER_BYTES],
) -> crate::Result<Sha1Digest> {
    let mut hasher = Sha1::new();
    feed_hasher(&mut hasher, reader, len, buf)?;
    Ok(Sha1Digest::from(<[u8; 20]>::from(hasher.finalize())))
}

/// Append exactly `len` bytes from `reader` into the running `hasher`,
/// using `buf` as the per-iteration scratch buffer. Caller owns `buf`
/// so multi-call sequences (e.g., per-block hashing in
/// [`PakReader::verify_entry`]) can amortise its allocation.
///
/// The buffer type is a fixed-size `&mut [u8; HASH_BUFFER_BYTES]`
/// rather than a slice so the empty-buffer case (which would loop
/// forever consuming zero bytes per iteration) is unrepresentable.
/// Pre-PR-#45 this was guarded by a `debug_assert!` that was stripped
/// in release builds — a latent infinite-loop footgun.
fn feed_hasher<R: Read>(
    hasher: &mut Sha1,
    reader: &mut R,
    len: u64,
    buf: &mut [u8; HASH_BUFFER_BYTES],
) -> crate::Result<()> {
    // `buf.len()` rather than the const so the chunk size derives from
    // the buffer's actual capacity. Today they're identical (the type
    // guarantees `buf.len() == HASH_BUFFER_BYTES`), but if the signature
    // is ever generalised to a const-generic `<const N: usize>` the
    // const reference would silently cap at 8 KiB regardless of the
    // passed buffer.
    let mut remaining = len;
    while remaining > 0 {
        // `remaining.min(buf.len() as u64)` is bounded by `buf.len()`
        // (HASH_BUFFER_BYTES = 8192) — safely fits in usize on every
        // supported target. `buf.len() as u64` is a lossless widening
        // (usize ≤ 64 bits) that clippy can't prove without
        // target-cfg analysis.
        #[allow(clippy::cast_possible_truncation)]
        let want = remaining.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..want])?;
        hasher.update(&buf[..want]);
        remaining -= want as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A well-formed LZ4 block: a 64 KiB output derived from ~300
    /// compressed bytes. `compressed_len × 255` (76_500) exceeds the
    /// pak-derived `expected_out`, so the cap is transparent — it
    /// returns `expected_out` unchanged and never under-sizes a valid
    /// decode.
    #[test]
    fn lz4_block_output_cap_passes_through_valid_block() {
        assert_eq!(lz4_block_output_cap(65_536, 300), 65_536);
    }

    /// The security property (#636): a 400-byte compressed block that
    /// claims a 4 GiB `compression_block_size` must NOT force a 4 GiB
    /// eager allocation. The cap clamps the reservation to
    /// input-proportional size (`400 × 255`), so the crafted claim
    /// cannot amplify.
    #[test]
    fn lz4_block_output_cap_bounds_crafted_oversized_claim() {
        assert_eq!(
            lz4_block_output_cap(4 * 1024 * 1024 * 1024, 400),
            400 * MAX_LZ4_BLOCK_EXPANSION_RATIO
        );
    }

    /// `compressed_len × 255` must saturate (not overflow/panic) for a
    /// pathological length, in which case `expected_out` wins the
    /// `min`. Pins the `saturating_mul` against a `checked`/wrapping
    /// mutant.
    #[test]
    fn lz4_block_output_cap_saturates_without_overflow() {
        assert_eq!(lz4_block_output_cap(1_000, u64::MAX), 1_000);
    }

    /// The `locked()` helper recovers from a poisoned mutex
    /// via `PoisonError::into_inner`. The safety contract is "every
    /// caller MUST seek before its first read" — encoded in production
    /// by every existing call site. Pin that poisoning the mutex (by
    /// panicking while holding the guard) doesn't break subsequent
    /// reads: the high-level `read_entry` path seeks unconditionally
    /// via `open_entry_into`, so it must return correct bytes against
    /// the pre-poison baseline.
    ///
    /// This test lives in `pak/mod.rs` (not `tests/pak_integration.rs`)
    /// because `locked()` is private to the module; integration tests
    /// can't reach it. Poisoning via a real public API would require
    /// triggering a panic inside a `locked()`-guarded read path, which
    /// is brittle to wire up — direct access is the cleaner route.
    #[test]
    fn locked_recovers_from_poisoned_mutex() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_minimal.pak");
        let reader = Arc::new(PakReader::open(&fixture).unwrap());
        let path = reader.entries().next().unwrap().path.clone();
        let expected = reader.read_entry(&path).unwrap();

        // Poison the mutex: spawn a thread that acquires the guard
        // then panics. After joining, the mutex is in PoisonError
        // state; `Mutex::lock()` would return `Err(PoisonError)`
        // forever after, but `locked()` recovers via `into_inner`.
        let r2 = Arc::clone(&reader);
        let handle = std::thread::spawn(move || {
            let _guard = r2.locked();
            panic!("deliberately poison the mutex for test");
        });
        let join_result = handle.join();
        assert!(
            join_result.is_err(),
            "poisoning thread must panic to set the mutex's poison flag"
        );

        // Verify the mutex is actually poisoned now — guards against
        // a future change where Mutex stops being poisonable (e.g.,
        // if we ever switched to parking_lot's non-poisoning Mutex).
        assert!(
            reader.reader.is_poisoned(),
            "mutex should be poisoned after the thread panic"
        );

        // The post-poison read must succeed and return bytes-identical
        // output to the pre-poison baseline. If `locked()` propagated
        // the poison via `unwrap()` instead of `unwrap_or_else(into_inner)`,
        // this would panic. If the safety contract were violated (some
        // caller skipped the pre-read seek), the cursor would be at
        // wherever the panicked thread left off and the read would
        // return wrong bytes.
        let actual = reader.read_entry(&path).unwrap();
        assert_eq!(
            actual, expected,
            "read_entry after poison must return bytes-identical output to pre-poison baseline"
        );
    }

    /// Issue #278 (deferred from #235): direct coverage of the
    /// `OffsetPastFileSizeKind::EntryHeaderOffset` safety-net branch
    /// at `mod.rs::open_entry_into` (the `entry.header().offset() >=
    /// self.file_size` check).
    ///
    /// That branch is structurally unreachable from
    /// `PakReader::open` — the open-time `payload_end > file_size`
    /// check fires first for any entry with `wire_size > 0`
    /// (universally true; minimum 50 bytes for V8A). The indirect
    /// proxy test `open_rejects_index_offset_past_eof` in
    /// `pak_integration.rs` confirms the `offset == file_size` case
    /// surfaces as `PayloadEndBounds`, NOT `EntryHeaderOffset`.
    ///
    /// Shrinks `file_size` to the first entry's offset to trip the
    /// `>=` check. Without the safety-net branch, the same
    /// post-mutation read would surface as a bare `Io::UnexpectedEof`
    /// from the seek, indistinguishable from a truncated file.
    #[test]
    fn entry_header_offset_branch_fires_when_file_size_shrunk_post_open() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_minimal.pak");
        let mut reader = PakReader::open(&fixture).unwrap();

        // Snapshot the first entry's path + offset BEFORE the
        // mutation, releasing the borrow on `reader.index` so the
        // subsequent `&mut reader.file_size` write is allowed.
        let (path, offset) = {
            let entry = reader
                .index
                .entries()
                .iter()
                .next()
                .expect("real_v11_minimal.pak must have ≥ 1 entry");
            (entry.filename().to_owned(), entry.header().offset())
        };

        // Hit the `>=` inclusive-comparator boundary exactly:
        // setting `file_size = offset` makes `offset >= file_size`
        // true via equality, the boundary the safety-net branch is
        // designed to catch.
        reader.file_size = offset;

        let err = reader
            .read_entry(&path)
            .expect_err("safety-net branch must reject the post-mutation read");
        // Pin both struct fields explicitly (not via `..`) so a
        // future field-swap at the construction site
        // (mod.rs:966-968) is caught here. Both fields should equal
        // the snapshot `offset` because the mutation made them so.
        match &err {
            PaksmithError::InvalidIndex {
                fault:
                    IndexParseFault::OffsetPastFileSize {
                        kind:
                            OffsetPastFileSizeKind::EntryHeaderOffset {
                                entry_offset,
                                file_size_max,
                            },
                        ..
                    },
            } => {
                assert_eq!(
                    *entry_offset, offset,
                    "entry_offset field must echo the snapshot"
                );
                assert_eq!(
                    *file_size_max, offset,
                    "file_size_max field must echo the post-mutation file_size"
                );
            }
            other => panic!(
                "expected typed OffsetPastFileSize::EntryHeaderOffset (NOT Io::UnexpectedEof, \
                 NOT PayloadEndBounds); got: {other:?}"
            ),
        }
    }

    /// Issue #45 contract pin: `feed_hasher` and `sha1_of_reader` take
    /// `&mut [u8; HASH_BUFFER_BYTES]` — a fixed-size array reference —
    /// so the empty-buffer case is structurally unrepresentable.
    /// Pre-fix the buffer was `&mut [u8]` and an empty buffer would
    /// loop forever consuming zero bytes per iteration; the only
    /// guard was a `debug_assert!` stripped in release builds.
    ///
    /// This test passes by *compiling*: the buffer must be exactly
    /// `[u8; HASH_BUFFER_BYTES]` to be accepted. The body pins the
    /// canonical SHA1 of the lowercase pangram (no trailing period)
    /// so a future regression in `feed_hasher` — e.g., an off-by-one
    /// in the read loop, or a wrong slice bound — fails here rather
    /// than silently producing the wrong digest.
    ///
    /// The expected digest is hardcoded rather than computed via
    /// `Sha1::digest(payload)` deliberately. If the `sha1` crate
    /// shipped a regression, both `feed_hasher` and `Sha1::digest`
    /// would call the same broken update/finalize path and produce
    /// matching wrong digests — the pin against the well-known
    /// public test vector catches that class of dependency
    /// regression.
    #[test]
    fn feed_hasher_pins_canonical_sha1_for_pangram() {
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut reader: &[u8] = payload;
        feed_hasher(&mut hasher, &mut reader, payload.len() as u64, &mut buf).unwrap();
        let actual: [u8; 20] = hasher.finalize().into();
        assert_eq!(
            Sha1Digest::from(actual).to_string(),
            "16312751ef9307c3fd1afbcb993cdc80464ba0f1",
            "feed_hasher must produce the canonical SHA1 digest"
        );
    }

    /// `feed_hasher` with `len: 0` must not invoke `read` on the
    /// reader at all. Pre-PR-#45 the implementation looped while
    /// `remaining > 0` — correct shape — but the test only verified
    /// the resulting digest matched the empty-input SHA1. That same
    /// digest would also be produced if the loop entered once,
    /// called `read_exact(&mut buf[..0])` (which is a no-op
    /// `Ok(())`), and then exited; the test wouldn't catch a
    /// regression that did exactly that.
    ///
    /// `PoisonReader` panics on any `read` call, so this test fails
    /// loudly on any future code that touches the reader when
    /// `len == 0`.
    #[test]
    fn feed_hasher_zero_length_does_not_call_read() {
        struct PoisonReader;
        impl Read for PoisonReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("feed_hasher must not call read() when len == 0");
            }
        }
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        feed_hasher(&mut hasher, &mut PoisonReader, 0, &mut buf).unwrap();
        // SHA1 of the empty input — canonical reference value.
        let actual: [u8; 20] = hasher.finalize().into();
        assert_eq!(
            Sha1Digest::from(actual).to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    /// `feed_hasher` must correctly handle payloads larger than
    /// `HASH_BUFFER_BYTES` — i.e., the multi-iteration loop branch.
    /// Pre-fix coverage: the existing pangram test (43 bytes) and the
    /// integration tests against real fixtures (variable-size) both
    /// fit in a single iteration, leaving the
    /// `remaining > buf.len()` boundary untested directly. A future
    /// off-by-one in `remaining -= want as u64` (e.g., an accidental
    /// `+=`, or `remaining -= want as u64 - 1`) would slip past the
    /// short-payload tests but corrupt multi-block hashes.
    ///
    /// Uses `Sha1::digest(payload)` as the oracle — independent
    /// computation against the same input is the right shape for
    /// catching feed_hasher-specific bugs (off-by-one, wrong slice
    /// bound). The dependency-regression class is covered by the
    /// hardcoded-digest pin in
    /// `feed_hasher_pins_canonical_sha1_for_pangram`.
    #[test]
    fn feed_hasher_handles_multi_iteration_payloads() {
        // 3 full iterations + 17-byte remainder — exercises both the
        // full-buffer chunk branch and the partial-final-chunk branch.
        let payload_len = HASH_BUFFER_BYTES * 3 + 17;
        // `i % 251` is in `0..251` — fits in u8 by construction.
        #[allow(clippy::cast_possible_truncation)]
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let mut buf = [0u8; HASH_BUFFER_BYTES];
        let mut hasher = Sha1::new();
        let mut reader: &[u8] = &payload;
        feed_hasher(&mut hasher, &mut reader, payload.len() as u64, &mut buf).unwrap();
        let actual: [u8; 20] = hasher.finalize().into();
        let expected: [u8; 20] = Sha1::digest(&payload).into();
        assert_eq!(
            actual, expected,
            "multi-iteration feed_hasher digest must match independent Sha1::digest oracle"
        );
    }

    /// F4 (security hardening): `PakReader::open` emits a
    /// `tracing::warn!` when the pak path resolves through a symbolic
    /// link, but still opens the file successfully. The warn is the
    /// defense-in-depth surface that lets operators detect symlink-
    /// based redirection; the non-rejection keeps current user-local
    /// CLI workflows working (Phase 4+ daemon mode is expected to
    /// escalate to opt-in rejection).
    ///
    /// Unix-only: Windows symlinks require Developer Mode or admin
    /// privileges to create, so the test would flake in CI.
    #[cfg(unix)]
    #[test]
    #[tracing_test::traced_test]
    fn open_warns_on_symlink_then_succeeds() {
        let real = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_minimal.pak");
        let tmp = tempfile::tempdir().expect("create tempdir");
        let link = tmp.path().join("link.pak");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");

        let reader = PakReader::open(&link).expect("open via symlink should succeed");
        // Sanity-check the open actually returned a working reader.
        assert!(
            reader.entries().count() > 0,
            "symlink-opened reader should have entries"
        );

        assert!(
            logs_contain("opening pak via symbolic link"),
            "expected symlink warn token in captured logs"
        );
    }

    /// F4 (security hardening): the warn must NOT fire on a plain
    /// (non-symlink) path — that would spam operator logs for every
    /// list call.
    #[test]
    #[tracing_test::traced_test]
    fn open_does_not_warn_on_regular_file() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_minimal.pak");
        let _reader = PakReader::open(&fixture).expect("open should succeed");
        assert!(
            !logs_contain("opening pak via symbolic link"),
            "regular-file open should not emit the symlink warn"
        );
    }

    /// `stream_zlib_to`'s returned `u64` must equal the decompressed
    /// byte count (== `entry.uncompressed_size()`). Pinned at the
    /// `paksmith-core` unit-test boundary (not just via the
    /// `read_entry_to_returns_exact_bytes_written` integration test
    /// in `paksmith-core-tests`) so the invariant is exercised by the
    /// default `cargo test` runner that excludes `paksmith-core-tests`
    /// from `default-members`. Catches mutants that short-circuit
    /// the function body to a constant return value (`Ok(0)`,
    /// `Ok(1)`, etc.) — those produce the wrong count even though
    /// the writer ends up empty, which an integration test in a
    /// non-default-members crate wouldn't see under `cargo-mutants`'
    /// default test invocation.
    #[test]
    fn stream_zlib_to_returns_exact_uncompressed_size() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_compressed.pak");
        let reader = PakReader::open(&fixture).expect("open compressed fixture");
        let path = "Content/Compressed.uasset";
        let entry = reader.index_entry(path).expect("compressed entry present");
        let uncompressed_size = entry.header().uncompressed_size();
        assert!(
            uncompressed_size > 0,
            "fixture invariant: compressed entry is non-empty"
        );
        let mut buf: Vec<u8> = Vec::new();
        let written = reader
            .read_entry_to(path, &mut buf)
            .expect("read_entry_to(compressed) must succeed");
        assert_eq!(
            written, uncompressed_size,
            "returned u64 must equal entry.uncompressed_size()"
        );
        assert_eq!(
            usize::try_from(written).expect("test fixture fits in usize"),
            buf.len(),
            "returned u64 must equal bytes actually written to the writer"
        );
    }

    // ---- LZ4 pak-entry decompression (#636) ----
    //
    // Fixtures are repak-written (`lz4_flex::block::compress` — raw
    // LZ4 blocks, no size prefix), the same block form the CUE4Parse
    // reference decodes (`K4os LZ4Codec.Decode` into a caller-sized
    // buffer). Each block decompresses to exactly
    // `compression_block_size` bytes; the last takes the remainder
    // of `uncompressed_size`.

    /// The compressible payload fixture-gen writes into every
    /// `*_compressed.pak` / `*_lz4.pak` entry: 256 `'A'` bytes.
    /// Content equality against this constant makes the round-trip
    /// byte-exact against the repak oracle, not just size-exact.
    const LZ4_FIXTURE_PAYLOAD_LEN: usize = 256;

    fn lz4_fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../tests/fixtures/{name}"))
    }

    #[test]
    fn read_lz4_entry_round_trips_v11() {
        let reader = PakReader::open(lz4_fixture("real_v11_lz4.pak")).expect("open lz4 fixture");
        let path = "Content/Compressed.uasset";
        let entry = reader.index_entry(path).expect("lz4 entry present");
        assert!(
            matches!(entry.header().compression_method(), CompressionMethod::Lz4),
            "fixture invariant: entry is LZ4-compressed, got {:?}",
            entry.header().compression_method()
        );
        let mut buf: Vec<u8> = Vec::new();
        let written = reader
            .read_entry_to(path, &mut buf)
            .expect("read_entry_to(lz4) must succeed");
        assert_eq!(written, entry.header().uncompressed_size());
        assert_eq!(
            buf,
            vec![b'A'; LZ4_FIXTURE_PAYLOAD_LEN],
            "decompressed content must be byte-exact against the repak-written payload"
        );
    }

    #[test]
    fn read_lz4_entry_round_trips_v8b() {
        // v8b = earliest 5-slot/u32-index FName-table layout (v8a's
        // 4-slot/u8-index variant is exercised by the zlib corpus's
        // real_v8a_compressed.pak; slot resolution is method-agnostic
        // upstream of the decoder).
        let reader = PakReader::open(lz4_fixture("real_v8b_lz4.pak")).expect("open lz4 fixture");
        let path = "Content/Compressed.uasset";
        let mut buf: Vec<u8> = Vec::new();
        let written = reader
            .read_entry_to(path, &mut buf)
            .expect("read_entry_to(lz4, v8b) must succeed");
        assert_eq!(written, buf.len() as u64);
        assert_eq!(buf, vec![b'A'; LZ4_FIXTURE_PAYLOAD_LEN]);
    }

    #[test]
    fn verify_lz4_entry_no_longer_errors_unsupported() {
        // The v11 fixture uses the v10+ ENCODED directory index, whose
        // compact per-entry encoding carries NO SHA1 field (repak does
        // write a real hash into the legacy in-data record, but the
        // parsed index entry — the one `verify_entry` sees — has none).
        // So verify short-circuits to SkippedNoHash before the method
        // match and cannot reach the hash arm. What it DOES pin: verify
        // on an LZ4 entry returns Ok (the pre-#636 code errored with
        // UnsupportedMethod for LZ4). The hash-arm ROUTING (Lz4 shares
        // the block-walk arm with Zlib) is pinned against a REAL hash by
        // `verify_lz4_entry_v8b_legacy_index_verifies` below (v8b's
        // legacy index does carry the SHA1) and by the synthetic
        // `verify_entry_lz4_succeeds` in paksmith-core-tests.
        let reader = PakReader::open(lz4_fixture("real_v11_lz4.pak")).expect("open lz4 fixture");
        let outcome = reader
            .verify_entry("Content/Compressed.uasset")
            .expect("verify_entry(lz4) must succeed");
        assert!(
            matches!(outcome, VerifyOutcome::SkippedNoHash),
            "v10+ encoded index carries no per-entry hash; expected SkippedNoHash, got {outcome:?}"
        );
    }

    #[test]
    fn verify_lz4_entry_v8b_legacy_index_verifies() {
        // The v8b fixture uses the LEGACY directory index, which stores
        // the full FPakEntry — including its real SHA1 — per entry. So
        // verify reaches the hash arm and recomputes the digest over the
        // on-disk compressed LZ4 block bytes. This is an end-to-end
        // cross-check that paksmith's entry hashing matches repak's over
        // real repak-written blocks: the outcome is Verified, NOT
        // SkippedNoHash, proving the LZ4 method routes through the
        // block-walk hash arm on a REAL (non-zero) stored hash.
        let reader = PakReader::open(lz4_fixture("real_v8b_lz4.pak")).expect("open lz4 fixture");
        let outcome = reader
            .verify_entry("Content/Compressed.uasset")
            .expect("verify_entry(lz4, v8b) must succeed");
        assert!(
            matches!(outcome, VerifyOutcome::Verified),
            "v8b legacy index carries a real SHA1; expected Verified, got {outcome:?}"
        );
    }

    #[test]
    fn read_lz4_entry_rejects_corrupt_block() {
        // Overwrite the FIRST byte of the compressed block (the LZ4
        // token) — structural corruption the decoder must reject
        // with a typed Decompression fault, never a panic. NOTE: raw
        // LZ4 blocks carry NO checksum, so a flip in literal DATA can
        // decode "successfully" to wrong bytes — content integrity is
        // the entry SHA1's job (see docs/formats/compression/lz4.md).
        // The block's absolute start is derived from the parsed index
        // rather than hardcoded, so fixture regeneration can't
        // silently move the target into the in-data header (which
        // would trip the index-mismatch guard instead).
        let pristine =
            PakReader::open(lz4_fixture("real_v11_lz4.pak")).expect("open pristine fixture");
        let entry = pristine
            .index_entry("Content/Compressed.uasset")
            .expect("entry present");
        let block0 = &entry.header().compression_blocks()[0];
        let target = usize::try_from(entry.header().offset() + block0.start())
            .expect("fixture offsets fit usize");
        drop(pristine);
        let original = std::fs::read(lz4_fixture("real_v11_lz4.pak")).expect("read fixture");
        let mut corrupted = original.clone();
        corrupted[target] = 0xFF; // token demanding more input than the block holds
        let dir = tempfile::tempdir().expect("create tempdir");
        let corrupt_path = dir.path().join("corrupt_v11_lz4.pak");
        std::fs::write(&corrupt_path, &corrupted).expect("write corrupt copy");
        let reader =
            PakReader::open(&corrupt_path).expect("index parses (corruption is in payload)");
        let mut buf: Vec<u8> = Vec::new();
        let result = reader.read_entry_to("Content/Compressed.uasset", &mut buf);
        match result {
            // Must be a DECODE-level fault from inside the LZ4 path —
            // an UnsupportedMethod here would mean the dispatch never
            // reached the decoder at all.
            Err(PaksmithError::Decompression { fault, .. })
                if !matches!(fault, DecompressionFault::UnsupportedMethod { .. }) => {}
            other => panic!(
                "expected a decode-level Decompression fault on a corrupt LZ4 block, got {other:?}"
            ),
        }
        // `dir` (and the corrupt copy inside it) is removed on drop.
    }

    // The next two tests exercise `stream_lz4_to`'s non-final-block
    // size guard with SYNTHETIC multi-block v8b paks. They live
    // in-package (not only in `paksmith-core-tests`) because
    // cargo-mutants scopes each mutant's test run to the mutated
    // package: the cross-crate integration copies do NOT credit
    // mutants in `mod.rs`, so the `i + 1 < len` and `produced !=
    // block_size` operators in that guard survive without these.
    // Gated on `__test_utils` because the shared builder lives in
    // `crate::testing::wire`.

    /// A valid multi-block LZ4 entry (two full non-final blocks that
    /// each inflate to EXACTLY `compression_block_size`, plus a short
    /// final block) must round-trip byte-exact. Pins the non-final
    /// guard's `produced != block_size` comparison: a `== block_size`
    /// inversion would reject each valid non-final block and break this
    /// decode.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_multi_block_round_trips() {
        let block_size = 128u32;
        let payload: Vec<u8> = (0..296u32).map(|i| (i % 251) as u8).collect();
        let streams: Vec<Vec<u8>> = payload
            .chunks(block_size as usize)
            .map(lz4_flex::block::compress)
            .collect();
        assert_eq!(streams.len(), 3, "fixture invariant: 2 full + 1 remainder");
        let pak =
            crate::testing::wire::build_v8b_lz4_pak(&streams, payload.len() as u64, block_size);
        let reader = PakReader::from_bytes(pak).expect("synthetic multi-block v8b pak parses");
        let mut out = Vec::new();
        let written = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect("multi-block lz4 round-trip must succeed");
        assert_eq!(written, payload.len() as u64);
        assert_eq!(out, payload, "multi-block decode must be byte-exact");
    }

    /// A non-final block that inflates to FEWER than
    /// `compression_block_size` bytes must surface
    /// `NonFinalBlockSizeMismatch` at that exact block. Pins the
    /// guard's `i + 1 < len` predicate: inverting `<` to `>` makes the
    /// guard never fire, so the shortfall would instead surface as a
    /// cumulative `SizeUnderrun` — asserting the EXACT fault (and block
    /// index) distinguishes the two and kills that mutant.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_short_non_final_block_surfaces_non_final_mismatch() {
        let block_size = 128u32;
        // block0 inflates to 64 (< 128) yet is non-final; block1
        // supplies the remaining 64 of a 192-byte uncompressed size.
        let short = lz4_flex::block::compress(&[b'A'; 64]);
        let tail = lz4_flex::block::compress(&[b'B'; 64]);
        let pak = crate::testing::wire::build_v8b_lz4_pak(&[short, tail], 192, block_size);
        let reader = PakReader::from_bytes(pak).expect("synthetic pak parses");
        let mut out = Vec::new();
        let err = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect_err("short non-final block must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::Decompression {
                    fault: DecompressionFault::NonFinalBlockSizeMismatch { block_index: 0, .. },
                    ..
                }
            ),
            "expected NonFinalBlockSizeMismatch at block 0, got {err:?}"
        );
    }

    /// The documented AES-256 key for the vendored encrypted fixtures
    /// (`crates/paksmith-fixture-gen/src/encryption.rs::FIXTURE_AES_KEY`).
    /// Hardcoded here because `paksmith-core` must NOT depend on
    /// `paksmith-fixture-gen`; mirrored from the fixture-gen constant +
    /// `tests/fixtures/PROVENANCE-encrypted.md`
    /// (hex `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`).
    const FIXTURE_AES_KEY: [u8; 32] = [
        0x94, 0xd2, 0x5b, 0xc3, 0xae, 0xb4, 0x20, 0xe0, 0xbe, 0x91, 0x4e, 0xdc, 0x9d, 0x54, 0x35,
        0xa1, 0xea, 0xab, 0x5f, 0x28, 0x64, 0xe0, 0x9e, 0x94, 0x01, 0x9a, 0xc2, 0x05, 0xb7, 0x27,
        0xa7, 0xde,
    ];

    /// Path to the encrypted-INDEX fixture (index encrypted, entry data
    /// plaintext — isolates the index-decrypt path).
    fn encrypted_index_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_encrypted_index.pak")
    }

    /// Happy path: with the correct key, the encrypted index decrypts and
    /// parses, exposing the four known plaintext entries. This is the
    /// oracle for the index-decrypt being byte-correct — a wrong decrypt
    /// would yield garbage that fails the flat-index parser's
    /// magic/bounds checks.
    #[test]
    fn open_with_key_decrypts_index_and_lists_entries() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_index_fixture(), key)
            .expect("decrypt + parse index");
        let mut paths: Vec<String> = reader.entries().map(|e| e.path().to_string()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "directory/nested.txt".to_string(),
                "test.png".to_string(),
                "test.txt".to_string(),
                "zeros.bin".to_string(),
            ],
            "decrypted index must expose the four known fixture entries"
        );
    }

    /// `from_reader_with_key` (the reader-based key entry point, no
    /// filesystem path) decrypts and parses the same fixture from an
    /// in-memory `Cursor`. Exercises the path `open_with_key` doesn't —
    /// the reader entry point directly — and confirms a key threaded
    /// through `from_reader_inner` (not `open_inner`) reaches the decrypt.
    #[test]
    fn from_reader_with_key_decrypts_index() {
        let bytes = std::fs::read(encrypted_index_fixture()).expect("read fixture bytes");
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(bytes), key)
            .expect("decrypt + parse index from reader");
        assert_eq!(
            reader.entries().count(),
            4,
            "from_reader_with_key must expose the four fixture entries"
        );
    }

    /// Wrong key → decrypted bytes are garbage → the flat-index parser's
    /// magic/bounds checks fail → that parse error is mapped to
    /// `Decryption` (fail-closed), NOT surfaced as an opaque parse fault.
    #[test]
    fn open_with_wrong_key_is_decryption_error() {
        // Two structurally different wrong keys: an all-zero key and a
        // mixed-byte key that differs from the real `FIXTURE_AES_KEY` in
        // every byte. The wrong-key detector is the index parser rejecting
        // garbage plaintext (the spec's documented parse-as-oracle), so the
        // fail-closed guarantee is probabilistic; pinning it at a single key
        // (paksmith's recurring pinned-answer hazard) would let a detector
        // that only rejects the all-zero case slip through. Both must map to
        // `Decryption`, never an empty `Ok` index or an opaque parse error.
        for wrong in [AesKey::new([0u8; 32]), AesKey::new([0xA5u8; 32])] {
            let err = PakReader::open_with_key(encrypted_index_fixture(), wrong)
                .expect_err("wrong key must fail");
            assert!(
                matches!(err, PaksmithError::Decryption { .. }),
                "wrong key must fail closed as Decryption, got: {err:?}"
            );
        }
    }

    /// Encrypted index but no key supplied (`open`, which sets
    /// `key: None`) → `Decryption` (unchanged from today's behavior).
    #[test]
    fn open_without_key_on_encrypted_is_decryption_error() {
        let err = PakReader::open(encrypted_index_fixture())
            .expect_err("encrypted index without key must fail");
        assert!(
            matches!(err, PaksmithError::Decryption { .. }),
            "no key on encrypted index must be Decryption, got: {err:?}"
        );
    }

    /// `open_with_key` on a plain (unencrypted) pak must succeed and expose
    /// entries normally — a supplied key that isn't needed must be ignored.
    #[test]
    fn open_with_key_on_unencrypted_pak_succeeds() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_compressed.pak");
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(fixture, key)
            .expect("key-supplied open on unencrypted pak must succeed");
        assert!(
            reader.entries().count() > 0,
            "unencrypted pak opened with key must expose its entries"
        );
    }

    /// `verify_index()` on an encrypted pak must succeed — UE stores
    /// `index_hash` as SHA1 of the **plaintext** (computed before encryption),
    /// so `verify_main_index_region` must decrypt before hashing. This test
    /// empirically confirms the decryption-before-hash path is correct.
    #[test]
    fn verify_index_on_encrypted_pak_returns_verified() {
        // The fixture was produced by UnrealPak and has a non-zero index_hash
        // computed over the plaintext index (UE hashes before encrypting).
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_index_fixture(), key)
            .expect("open encrypted fixture for verify_index test");
        let outcome = reader
            .verify_index()
            .expect("verify_index must not error on a valid encrypted fixture with a key");
        assert!(
            matches!(outcome, VerifyOutcome::Verified),
            "verify_index on the UnrealPak encrypted fixture must be Verified \
             (SHA1 of plaintext matches), got: {outcome:?}"
        );
    }

    /// `verify_index()` on an encrypted pak whose footer `index_hash` has been
    /// tampered must return `HashMismatch`, not `Verified`. Pins the negative
    /// branch of `verify_main_index_region`'s decrypt-then-hash comparison.
    #[test]
    fn verify_index_on_tampered_encrypted_pak_returns_hash_mismatch() {
        // Byte-patch the stored `index_hash` in a copy of the fixture.
        // V8B+ footer layout: magic(4) + version(4) + index_offset(8) +
        // index_size(8) + index_hash(20) = field starts at footer_start + 24.
        let fixture_bytes =
            std::fs::read(encrypted_index_fixture()).expect("read encrypted fixture");
        let magic = b"\xe1\x12\x6f\x5a";
        let footer_start = fixture_bytes
            .windows(4)
            .rposition(|w| w == magic)
            .expect("footer magic must be present in fixture");
        let hash_start = footer_start + 24;
        let hash_end = hash_start + 20;
        assert!(
            hash_end <= fixture_bytes.len(),
            "index_hash field must fit within fixture"
        );
        let mut tampered = fixture_bytes;
        tampered[hash_start] ^= 0xFF; // flip the first hash byte

        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(tmp.path(), &tampered).expect("write tampered fixture");

        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(tmp.path(), key)
            .expect("open must succeed — only the hash slot, not the ciphertext, is patched");
        let err = reader
            .verify_index()
            .expect_err("verify_index must error on hash mismatch");
        assert!(
            matches!(
                err,
                PaksmithError::HashMismatch {
                    target: HashTarget::Index,
                    ..
                }
            ),
            "tampered index_hash must surface as HashMismatch(Index), got: {err:?}"
        );
    }

    /// v10+ (path-hash index) encrypted paks must produce an honest
    /// `UnsupportedFeature` error — NOT `Decryption` — so the user knows
    /// the key is fine but this version is deferred, not that the key is wrong.
    #[test]
    fn open_v11_encrypted_index_is_unsupported_feature_not_decryption() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_encrypted_index.pak");
        let key = AesKey::new(FIXTURE_AES_KEY);
        let err =
            PakReader::open_with_key(fixture, key).expect_err("v11 encrypted index must fail");
        assert!(
            matches!(err, PaksmithError::UnsupportedFeature { .. }),
            "v11 encrypted index must fail as UnsupportedFeature (not Decryption), got: {err:?}"
        );
        // Also confirm the error message is informative (not a wrong-key message).
        let msg = err.to_string();
        assert!(
            msg.contains("path-hash") || msg.contains("not yet supported"),
            "UnsupportedFeature message should mention path-hash or deferred, got: {msg}"
        );
    }

    /// `index_size > MAX_INDEX_BYTES` on the encrypted path must be rejected
    /// before any allocation attempt. Verified via a crafted fake reader that
    /// reports a >2 GiB file_size and a flat (v8b) footer with an oversized
    /// `index_size` field — both well above the 1 GiB cap. The guard fires
    /// before `try_reserve_exact`, so the fake reader never serves index bytes.
    #[test]
    fn encrypted_index_oversized_index_size_is_rejected_before_alloc() {
        use std::io::{self, Cursor, Read, Seek, SeekFrom};

        use byteorder::{LittleEndian, WriteBytesExt};

        // A `Read + Seek` that reports a large file_size via `seek(End(0))`
        // but backs the footer with real bytes. Index bytes are never served
        // (the cap check fires first).
        struct FakeReader {
            inner: Cursor<Vec<u8>>,
            reported_file_size: u64,
        }

        impl Read for FakeReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.inner.read(buf)
            }
        }

        impl Seek for FakeReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    // Only `SeekFrom::End(0)` (→ file_size) and
                    // `SeekFrom::End(-footer_len)` (→ footer start) are
                    // exercised by this test — the cap check fires before
                    // any index bytes are read, so no `SeekFrom::Start`
                    // or positive-offset `End` seeks ever arrive. The
                    // implementation handles the general case defensively.
                    SeekFrom::End(offset) => {
                        // Compute virtual absolute position: file_size + offset.
                        // offset is negative for backward seeks; unsigned_abs()
                        // avoids a sign-loss cast regardless of sign.
                        let mag = offset.unsigned_abs();
                        let abs_virtual = if offset >= 0 {
                            self.reported_file_size.checked_add(mag)
                        } else {
                            self.reported_file_size.checked_sub(mag)
                        }
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "seek overflow or underflow in FakeReader",
                            )
                        })?;
                        // Map virtual position to cursor position. The cursor holds
                        // the last `cursor_len` bytes of the virtual file.
                        let cursor_len =
                            u64::try_from(self.inner.get_ref().len()).unwrap_or(u64::MAX);
                        let cursor_start = self.reported_file_size.saturating_sub(cursor_len);
                        let cursor_pos = abs_virtual.saturating_sub(cursor_start);
                        let _ = self.inner.seek(SeekFrom::Start(cursor_pos))?;
                        // Return the virtual absolute position.
                        Ok(abs_virtual)
                    }
                    other => self.inner.seek(other),
                }
            }
        }

        // Build a v8b footer: encrypted=1, index_size=MAX+1.
        // The footer itself must be self-consistent (index_offset + index_size
        // ≤ file_size) so footer validation passes and the decrypt guard runs.
        const OVERSIZED: u64 = index::MAX_INDEX_BYTES + 1;
        // Use a reported file_size large enough to pass the footer boundary check.
        const REPORTED_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

        // V8B+ footer size (61 base + 5×32 compression slots = 221 bytes).
        let footer_size = version::FOOTER_SIZE_V8B_PLUS;
        let index_offset = REPORTED_FILE_SIZE - footer_size - OVERSIZED;

        let mut footer_bytes: Vec<u8> = Vec::new();
        footer_bytes.extend_from_slice(&[0u8; 16]); // encryption_key_guid
        footer_bytes.push(1u8); // encrypted = true
        footer_bytes
            .write_u32::<LittleEndian>(crate::container::pak::version::PAK_MAGIC)
            .unwrap();
        footer_bytes.write_u32::<LittleEndian>(8).unwrap(); // version = v8b
        footer_bytes
            .write_u64::<LittleEndian>(index_offset)
            .unwrap();
        footer_bytes.write_u64::<LittleEndian>(OVERSIZED).unwrap();
        footer_bytes.extend_from_slice(&[0u8; 20]); // index_hash
        footer_bytes.extend_from_slice(&[0u8; 5 * 32]); // 5 compression slots
        assert_eq!(footer_bytes.len() as u64, version::FOOTER_SIZE_V8B_PLUS);

        // The FakeReader's cursor holds only the footer; its Start offset
        // must line up so `seek(End(0)) - footer_len` finds the footer start.
        // from_reader_inner does: `seek(End(0))` → file_size, then
        // `seek(End(-footer_len))` → footer start position.
        // We set the cursor to hold exactly the footer bytes at position 0.
        // For seek(End(-221)): real cursor is len=221, so End(-221) → 0. ✓
        let cursor = Cursor::new(footer_bytes);
        let fake = FakeReader {
            inner: cursor,
            reported_file_size: REPORTED_FILE_SIZE,
        };

        let key = AesKey::new(FIXTURE_AES_KEY);
        let err = PakReader::from_reader_with_key(fake, key)
            .expect_err("oversized index_size must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: crate::error::IndexParseFault::BoundsExceeded { .. }
                }
            ),
            "oversized encrypted index_size must be BoundsExceeded, got: {err:?}"
        );
    }

    // ---- Task 4: per-entry decryption tests --------------------------------

    /// Path to the per-entry-encrypted fixture (index plaintext, entry data
    /// AES-256-ECB encrypted). Opens without a key; `read_entry` on an
    /// encrypted entry requires the key.
    fn encrypted_entries_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_encrypted_entries.pak")
    }

    /// Plaintext of `test.txt` inside the encrypted-entries fixture.
    /// Copied from `paksmith-fixture-gen/src/encryption.rs::FIXTURE_PLAINTEXT_TEST_TXT`.
    /// Core must NOT depend on fixture-gen, so the constant is hardcoded here.
    const FIXTURE_PLAINTEXT_TEST_TXT: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n";

    /// Plaintext of `directory/nested.txt` inside the encrypted-entries fixture.
    const FIXTURE_PLAINTEXT_NESTED_TXT: &[u8] = b"Proin urna leo, placerat non tristique sed, commodo sit amet enim. Nam aliquet metus et turpis semper tempus. Aliquam vitae dolor aliquam, elementum augue non, molestie nisi. Maecenas aliquet sagittis elit, id elementum magna dictum sed. Vivamus nulla nulla, aliquet et magna ut, tempus ultrices diam. Donec posuere fringilla feugiat. Etiam imperdiet neque nec mollis ornare. Fusce mollis neque risus, ac molestie ligula sagittis vel. Nam tempus et ante eget egestas. Curabitur porta placerat nisi ut vehicula. Nunc suscipit lacinia leo nec tincidunt. Phasellus blandit arcu non pulvinar mollis.\n";

    /// Length (bytes) of `zeros.bin` inside the encrypted-entries fixture: 2048 zero bytes.
    const FIXTURE_ZEROS_BIN_LEN: usize = 2048;

    /// Byte length of `test.png` inside the encrypted-entries fixture.
    const FIXTURE_TEST_PNG_LEN: usize = 10257;

    /// Happy-path: open the per-entry-encrypted fixture with the correct key and
    /// read `test.txt` — result must equal the known plaintext. This is the
    /// RED→GREEN oracle for entry decryption.
    #[test]
    fn reads_encrypted_entry_as_plaintext_test_txt() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_entries_fixture(), key)
            .expect("open per-entry-encrypted fixture");
        let bytes = reader
            .read_entry("test.txt")
            .expect("read_entry must succeed on encrypted fixture with key");
        assert_eq!(
            bytes.as_slice(),
            FIXTURE_PLAINTEXT_TEST_TXT,
            "decrypted test.txt must equal the known Lorem-ipsum plaintext"
        );
    }

    /// `directory/nested.txt` — exercises a different plaintext length, confirms
    /// decrypt is not just the first entry.
    #[test]
    fn reads_encrypted_entry_as_plaintext_nested_txt() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_entries_fixture(), key)
            .expect("open per-entry-encrypted fixture");
        let bytes = reader
            .read_entry("directory/nested.txt")
            .expect("read_entry must succeed on nested.txt");
        assert_eq!(
            bytes.as_slice(),
            FIXTURE_PLAINTEXT_NESTED_TXT,
            "decrypted directory/nested.txt must equal the known plaintext"
        );
    }

    /// `zeros.bin` — all-zero plaintext exercises the case where the decrypted
    /// output happens to be all zeros (not confused with a zeroed/failed decrypt).
    #[test]
    fn reads_encrypted_entry_zeros_bin() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_entries_fixture(), key)
            .expect("open per-entry-encrypted fixture");
        let bytes = reader
            .read_entry("zeros.bin")
            .expect("read_entry must succeed on zeros.bin");
        assert_eq!(
            bytes.len(),
            FIXTURE_ZEROS_BIN_LEN,
            "decrypted zeros.bin must be exactly {FIXTURE_ZEROS_BIN_LEN} bytes"
        );
        assert!(
            bytes.iter().all(|&b| b == 0),
            "decrypted zeros.bin must be all-zero bytes"
        );
    }

    /// `test.png` — larger binary entry, exercises multi-AES-block reads.
    /// Asserts both byte length and the PNG magic signature to prove that
    /// real decryption occurred (ciphertext would not start with the PNG header).
    #[test]
    fn reads_encrypted_entry_test_png() {
        const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_entries_fixture(), key)
            .expect("open per-entry-encrypted fixture");
        let bytes = reader
            .read_entry("test.png")
            .expect("read_entry must succeed on test.png");
        assert_eq!(
            bytes.len(),
            FIXTURE_TEST_PNG_LEN,
            "decrypted test.png must be exactly {FIXTURE_TEST_PNG_LEN} bytes"
        );
        assert_eq!(
            &bytes[..8],
            &PNG_MAGIC,
            "decrypted test.png must start with PNG magic signature"
        );
    }

    /// Fail-closed: the encrypted-entries fixture has a PLAINTEXT index, so
    /// `PakReader::open()` (no key) succeeds. Reading an encrypted entry without
    /// a key must return `Decryption`, not silently return ciphertext.
    #[test]
    fn encrypted_entry_without_key_returns_decryption_error() {
        // index is plaintext → open succeeds even without a key
        let reader = PakReader::open(encrypted_entries_fixture())
            .expect("open with plaintext index and no key must succeed");
        let err = reader
            .read_entry("test.txt")
            .expect_err("reading an encrypted entry without a key must fail");
        assert!(
            matches!(err, PaksmithError::Decryption { .. }),
            "encrypted entry without key must fail closed as Decryption, got: {err:?}"
        );
    }

    // ── is_encrypted_compressed predicate truth table ──────────────────────
    // These four cases must all be covered to resist `&&`→`||`, `!=`→`==`,
    // and `-> true` mutants (see project accessor-negative-coverage convention).

    #[test]
    fn is_encrypted_compressed_enc_zlib_true() {
        // Encrypted + compressed → must be detected (the deferred layout).
        assert!(
            is_encrypted_compressed(true, &CompressionMethod::Zlib),
            "encrypted Zlib entry must be flagged as encrypted+compressed"
        );
    }

    #[test]
    fn is_encrypted_compressed_enc_none_false() {
        // Encrypted but uncompressed → currently supported, must NOT be flagged.
        assert!(
            !is_encrypted_compressed(true, &CompressionMethod::None),
            "encrypted uncompressed entry must NOT be flagged as encrypted+compressed"
        );
    }

    #[test]
    fn is_encrypted_compressed_plain_zlib_false() {
        // Plaintext compressed → currently supported, must NOT be flagged.
        assert!(
            !is_encrypted_compressed(false, &CompressionMethod::Zlib),
            "plaintext Zlib entry must NOT be flagged as encrypted+compressed"
        );
    }

    #[test]
    fn is_encrypted_compressed_plain_none_false() {
        // Plaintext uncompressed → trivially supported, must NOT be flagged.
        assert!(
            !is_encrypted_compressed(false, &CompressionMethod::None),
            "plaintext uncompressed entry must NOT be flagged as encrypted+compressed"
        );
    }

    // ---- Surviving-mutant kill tests (Phase 5a decrypt paths) --------------

    /// Pin the literal value of `MAX_INDEX_BYTES` (1 GiB). The const's
    /// initializer is `1024 * 1024 * 1024`; asserting the resolved literal
    /// kills the `*`→`+` (=3072) and `*`→`/` (=0) initializer mutants. The
    /// RHS is the spelled-out literal, NOT `1024 * 1024 * 1024`, so the
    /// assertion can't be satisfied by a mutated initializer.
    #[test]
    fn max_index_bytes_is_one_gib() {
        assert_eq!(
            MAX_INDEX_BYTES, 1_073_741_824,
            "MAX_INDEX_BYTES must be exactly 1 GiB (1024^3 bytes)"
        );
    }

    /// Pin every field emitted by the `PakEntryHeader::inline_for_test`
    /// builder so a mutant that rewrites any field assignment is caught.
    /// `stream_uncompressed_to` only reads `uncompressed_size`, so without
    /// this the other field assignments are unobserved and survive.
    #[test]
    fn inline_for_test_emits_expected_fields() {
        let h = PakEntryHeader::inline_for_test(4096, true);
        assert_eq!(
            h.uncompressed_size(),
            4096,
            "uncompressed_size must round-trip"
        );
        assert_eq!(
            h.compressed_size(),
            4096,
            "compressed_size mirrors uncompressed_size in the builder"
        );
        assert_eq!(h.offset(), 0, "offset must be 0");
        assert!(
            h.is_encrypted(),
            "is_encrypted must round-trip the `true` arg"
        );
        assert_eq!(
            h.compression_method(),
            &CompressionMethod::None,
            "builder emits no compression"
        );
        assert!(
            h.compression_blocks().is_empty(),
            "builder emits no compression blocks"
        );
        assert_eq!(
            h.compression_block_size(),
            0,
            "builder emits a zero compression_block_size"
        );
        assert_eq!(
            h.sha1(),
            Some(Sha1Digest::ZERO),
            "builder emits a ZERO sha1"
        );

        // The `is_encrypted` arg must actually flow through, not be hardcoded.
        let plain = PakEntryHeader::inline_for_test(16, false);
        assert!(
            !plain.is_encrypted(),
            "is_encrypted must round-trip the `false` arg"
        );
    }

    /// Pin that `PakIndexEntry::for_test` pairs the filename and header it is
    /// handed (guards the trivial constructor against an accidental swap).
    #[test]
    fn pak_index_entry_for_test_pairs_filename_and_header() {
        let header = PakEntryHeader::inline_for_test(32, true);
        let entry = PakIndexEntry::for_test("dir/file.bin".to_string(), header);
        assert_eq!(entry.filename(), "dir/file.bin");
        assert_eq!(entry.header().uncompressed_size(), 32);
        assert!(entry.header().is_encrypted());
    }

    /// Boundary: an encrypted-index footer declaring `index_size` EXACTLY at
    /// `MAX_INDEX_BYTES` must be ACCEPTED by the cap check (strict `>`). The
    /// read then fails later for a different reason (the fake reader can't
    /// serve a 1 GiB index → EOF/Io), so the discriminator is that the error
    /// is NOT `BoundsExceeded`.
    ///
    /// Kills the `>`→`>=` mutant on the `index_size > MAX_INDEX_BYTES` cap:
    /// under `>=`, a size == cap IS rejected as `BoundsExceeded`, which this
    /// assertion forbids.
    #[test]
    fn encrypted_index_size_exactly_at_cap_is_not_bounds_exceeded() {
        use std::io::{self, Cursor, Read, Seek, SeekFrom};

        use byteorder::{LittleEndian, WriteBytesExt};

        // Same FakeReader shape as the oversized test: reports a large
        // file_size so the footer self-consistency check passes and the cap
        // check is the real discriminator, but only backs the footer bytes.
        struct FakeReader {
            inner: Cursor<Vec<u8>>,
            reported_file_size: u64,
        }

        impl Read for FakeReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.inner.read(buf)
            }
        }

        impl Seek for FakeReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                match pos {
                    SeekFrom::End(offset) => {
                        let mag = offset.unsigned_abs();
                        let abs_virtual = if offset >= 0 {
                            self.reported_file_size.checked_add(mag)
                        } else {
                            self.reported_file_size.checked_sub(mag)
                        }
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "seek overflow or underflow in FakeReader",
                            )
                        })?;
                        let cursor_len =
                            u64::try_from(self.inner.get_ref().len()).unwrap_or(u64::MAX);
                        let cursor_start = self.reported_file_size.saturating_sub(cursor_len);
                        let cursor_pos = abs_virtual.saturating_sub(cursor_start);
                        let _ = self.inner.seek(SeekFrom::Start(cursor_pos))?;
                        Ok(abs_virtual)
                    }
                    other => self.inner.seek(other),
                }
            }
        }

        // index_size sits EXACTLY at the cap.
        const AT_CAP: u64 = index::MAX_INDEX_BYTES;
        const REPORTED_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

        let footer_size = version::FOOTER_SIZE_V8B_PLUS;
        let index_offset = REPORTED_FILE_SIZE - footer_size - AT_CAP;

        let mut footer_bytes: Vec<u8> = Vec::new();
        footer_bytes.extend_from_slice(&[0u8; 16]); // encryption_key_guid
        footer_bytes.push(1u8); // encrypted = true
        footer_bytes
            .write_u32::<LittleEndian>(crate::container::pak::version::PAK_MAGIC)
            .unwrap();
        footer_bytes.write_u32::<LittleEndian>(8).unwrap(); // version = v8b
        footer_bytes
            .write_u64::<LittleEndian>(index_offset)
            .unwrap();
        footer_bytes.write_u64::<LittleEndian>(AT_CAP).unwrap();
        footer_bytes.extend_from_slice(&[0u8; 20]); // index_hash
        footer_bytes.extend_from_slice(&[0u8; 5 * 32]); // 5 compression slots
        assert_eq!(footer_bytes.len() as u64, version::FOOTER_SIZE_V8B_PLUS);

        let cursor = Cursor::new(footer_bytes);
        let fake = FakeReader {
            inner: cursor,
            reported_file_size: REPORTED_FILE_SIZE,
        };

        let key = AesKey::new(FIXTURE_AES_KEY);
        let err = PakReader::from_reader_with_key(fake, key).expect_err(
            "a 1 GiB index that can't be served must still fail (just not as BoundsExceeded)",
        );
        assert!(
            !matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: crate::error::IndexParseFault::BoundsExceeded { .. }
                }
            ),
            "index_size == MAX_INDEX_BYTES must NOT be rejected as BoundsExceeded (strict `>`); got: {err:?}"
        );
    }

    /// `stream_uncompressed_to`, encrypted branch: a payload ending EXACTLY at
    /// `file_size` is valid (strict `>`), so the call returns `Ok` and writes
    /// the decrypted plaintext.
    ///
    /// Kills the `payload_end > file_size` `>`→`>=` mutant: under `>=`, a
    /// payload ending at EOF would be rejected (Err), so the `expect("Ok")`
    /// would fail.
    #[test]
    fn stream_uncompressed_encrypted_payload_ending_at_eof_is_ok() {
        use std::io::Cursor;

        // 16 bytes of ciphertext at offset 0; file_size == payload_end == 16.
        let ciphertext = vec![0u8; 16];
        let mut cursor = Cursor::new(ciphertext);

        let header = PakEntryHeader::inline_for_test(16, true);
        let entry = PakIndexEntry::for_test("at_eof.bin".to_string(), header);
        let key = AesKey::new(FIXTURE_AES_KEY);

        let mut out: Vec<u8> = Vec::new();
        let written = stream_uncompressed_to(&mut cursor, &entry, 16, Some(&key), &mut out)
            .expect("payload ending exactly at file_size must be accepted");
        assert_eq!(written, 16, "must report the full uncompressed size");
        assert_eq!(out.len(), 16, "must write the full uncompressed size");
    }

    /// `stream_uncompressed_to`, encrypted branch: a payload extending PAST
    /// `file_size` must be rejected as `PayloadEndBounds` before reading.
    ///
    /// Kills the `payload_end > file_size` `>`→`==` mutant: under `==`,
    /// `16 == 15` is false, so the guard wouldn't fire and the call would
    /// proceed to read+decrypt and return `Ok`, failing this `expect_err`.
    #[test]
    fn stream_uncompressed_encrypted_payload_past_eof_is_rejected() {
        use std::io::Cursor;

        // 16 bytes available, but file_size claims only 15 → payload_end (16)
        // > file_size (15).
        let ciphertext = vec![0u8; 16];
        let mut cursor = Cursor::new(ciphertext);

        let header = PakEntryHeader::inline_for_test(16, true);
        let entry = PakIndexEntry::for_test("past_eof.bin".to_string(), header);
        let key = AesKey::new(FIXTURE_AES_KEY);

        let mut out: Vec<u8> = Vec::new();
        let err = stream_uncompressed_to(&mut cursor, &entry, 15, Some(&key), &mut out)
            .expect_err("payload extending past file_size must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                        ..
                    }
                }
            ),
            "must reject as PayloadEndBounds; got: {err:?}"
        );
    }

    /// `PakReader`'s `Debug` impl must render the struct name and the `key`
    /// field, and the key must appear redacted (never as raw bytes).
    ///
    /// Kills the `<impl Debug>::fmt -> Ok(())` mutant: under that mutant
    /// `format!` yields an empty string, so every `contains` assertion fails.
    #[test]
    fn pak_reader_debug_renders_redacted_key() {
        use std::fmt::Write as _;

        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_index_fixture(), key)
            .expect("open encrypted-index fixture for Debug test");
        let s = format!("{reader:?}");
        assert!(s.contains("PakReader"), "Debug must name the struct: {s}");
        assert!(s.contains("key"), "Debug must render the `key` field: {s}");
        assert!(
            s.contains("<redacted>"),
            "the key must render via AesKey's redacted Debug: {s}"
        );
        // Defense-in-depth: the real key bytes must never leak. Build the
        // lowercase hex of the full key and assert it's absent from the
        // Debug output.
        let mut key_hex = String::with_capacity(FIXTURE_AES_KEY.len() * 2);
        for b in FIXTURE_AES_KEY {
            write!(key_hex, "{b:02x}").unwrap();
        }
        assert!(
            !s.contains(&key_hex),
            "Debug output must not contain the raw key hex"
        );
    }

    /// `PakReader::verify()` must return non-default `VerifyStats` for a valid
    /// encrypted-index fixture opened with its key: the main index is hashed
    /// and verified, so `index_verified` is `true`.
    ///
    /// Kills the `verify -> Ok(Default::default())` mutant: a default
    /// `VerifyStats` has `index_verified == false`, so this assertion fails
    /// under the mutant. Distinct from the `verify_index()` tests — this
    /// exercises the stats-returning entry point.
    #[test]
    fn verify_returns_index_verified_for_encrypted_fixture() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_index_fixture(), key)
            .expect("open encrypted-index fixture for verify() test");
        let stats = reader
            .verify()
            .expect("verify() must not error on a valid encrypted fixture with a key");
        assert!(
            stats.index_verified(),
            "verify() must report the main index as verified (non-default stats)"
        );
    }
}
