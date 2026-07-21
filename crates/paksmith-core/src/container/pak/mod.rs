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
//! - AES-256 decryption (with a key via [`PakReader::open_with_key`]) of
//!   the index and of encrypted ENTRIES. The v3-v9 flat index and the
//!   v10/v11 path-hash index (all three regions — primary, path-hash, and
//!   full-directory) are each read as a 16-aligned on-disk region and
//!   decrypted, with the AES padding excluded from the logical size (the
//!   v10+ regions truncate to it; the flat index applies it downstream as
//!   the parse/hash budget). Encrypted entries come
//!   both uncompressed and compressed; encrypted compressed entries decrypt
//!   the 16-aligned payload region as one contiguous block before per-block
//!   inflation. **The hash conventions are opposite:** encrypted entries
//!   verify keylessly (the stored SHA1 covers the on-disk ciphertext),
//!   whereas encrypted index regions store the SHA1 of their PLAINTEXT — so
//!   index verification requires the key (#635).
//!
//! It does NOT yet handle:
//! - Gzip / Oodle / Zstd compression — resolvable (Gzip and Oodle
//!   also via the v3-v7 numeric IDs, Zstd via the v8+ FName table)
//!   but not wired up downstream (only Zlib and LZ4 decompress).
//! - Three legacy shapes are deliberately fail-closed and left unsupported —
//!   see issue #637 for the recorded decision. Two of the three are an
//!   effort/value deferral, NOT a capability gap: repak (our writer oracle)
//!   CAN produce them, but paksmith doesn't parse them yet and they are
//!   museum-grade rarities:
//!   - **v1/v2 archives** — the pre-v3 entry record has a different shape
//!     (pre-v2 per-entry timestamp, no trailing flags + block_size) that the
//!     parser doesn't implement. repak writes v2 (its README marks v2 write
//!     supported; v1 write is untested). paksmith rejects at open rather
//!     than silently misparse.
//!   - **Pre-v5 absolute-offset compression blocks** — pre-v5 stores
//!     compression-block offsets as absolute file offsets (v5+ made them
//!     entry-relative), and the read path doesn't implement that. repak CAN
//!     emit a compressed v4 archive (verified by probe; v3 shares the same
//!     pre-v8 compression path), so an oracle exists; paksmith rejects at
//!     read time (pinned by `read_zlib_rejects_pre_v5_compressed_entry`).
//!   - **V9 frozen-index format** — the index is UE's compiled-frozen
//!     in-memory layout (a different serialization). This one genuinely has
//!     no oracle: repak never emits `frozen = true`. Rejected at open.
//!
//!   (The reader DOES cover v3-v9 flat and v10/v11 path-hash indexes; v4
//!   and v5 are fixture-anchored per #637.)
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
// Unused in the no-`__test_utils` lib-test compile (seam machinery
// no-ops there); exercised by CI's package-scoped compile guard.
#[cfg_attr(not(feature = "__test_utils"), allow(unused_imports))]
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
        // offsets pointing nowhere). Repak's writer never emits
        // frozen=true, so there is no oracle to build/verify a parser
        // against; reject explicitly at open time. Deliberate wontfix —
        // see #637 for the recorded decision and rationale.
        if footer.frozen_index() {
            return Err(PaksmithError::UnsupportedVersion {
                version: footer.version().wire_version(),
            });
        }

        // v1/v2 entry records have a different shape (timestamp field
        // pre-v2, no trailing flags+block_size) that PakEntryHeader::read_from
        // doesn't implement. repak writes v2 (README-supported), so an oracle
        // exists — this is a low-value deferral for museum-grade versions, not
        // a capability gap. Reject explicitly rather than silently misparse;
        // deliberate wontfix — see #637.
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
        // For encrypted COMPRESSED entries `compressed_size` is the sum
        // of the AES-ALIGNED per-block footprints (#634) — i.e. the
        // actual on-disk extent — so this bound is exact for that class.
        // For encrypted UNCOMPRESSED entries `compressed_size` mirrors
        // the unaligned `uncompressed_size` (`real_v8b_encrypted_entries`
        // `test.txt`: 446, not the 448-aligned footprint), so this
        // open-time bound UNDER-counts the real on-disk extent by up to
        // 15 bytes. That gap is caught fail-closed at read AND verify
        // time — the `checked_payload_end` on the AES-aligned length
        // inside `stream_uncompressed_to` /
        // `read_decrypted_compressed_payload`, and
        // `checked_encrypted_verify_extents` in `verify_entry`'s
        // encrypted arm (#689), reject a truncated tail with
        // `OffsetPastFileSize` rather than reading past EOF or reporting
        // `Verified` for an unreadable entry; nothing here relies on this
        // bound being exact for the uncompressed class.
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
                decrypt_index_region(&mut *guard, &self.footer, self.file_size, key)?
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
            let actual = sha1_of_bytes(&buf[..index_size_usize]);
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
        // Encrypted v10+ indexes (#635): each region (FDI/PHI) is
        // AES-encrypted in place, and UE records the SHA-1 over the
        // PLAINTEXT — so decrypt before hashing, exactly as
        // `verify_main_index_region` does. Hashing the on-disk ciphertext
        // would false-`HashMismatch` a pristine encrypted archive.
        let actual = if self.footer.is_encrypted() {
            // Structurally `Some` — an encrypted pak can't be opened
            // without a key (see `verify_main_index_region`); the branch
            // stays defensive rather than returning a wrong outcome.
            let Some(ref key) = self.key else {
                return Err(PaksmithError::Decryption { path: None });
            };
            let plain = self.decrypt_region_plaintext(region, region_kind, key)?;
            sha1_of_bytes(&plain)
        } else {
            let mut guard = self.locked();
            let mut file = BufReader::new(&mut *guard);
            let _ = file.seek(SeekFrom::Start(region.offset()))?;
            let mut buf = [0u8; HASH_BUFFER_BYTES];
            sha1_of_reader(&mut file, region.size(), &mut buf)?
        };
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

    /// Read and AES-256-ECB-decrypt an encrypted v10+ index region
    /// (FDI/PHI) into a `Zeroizing` plaintext buffer of `region.size()`
    /// bytes, for verify-time plaintext hashing (#635).
    ///
    /// `region.size()` is already bounded: `verify_region` ran
    /// `check_region_bounds` (`offset + size <= file_size`) before calling
    /// this, and the region was parsed under the `MAX_FDI_BYTES` cap at
    /// open. The 16-aligned on-disk extent is computed overflow-safely by
    /// [`checked_aligned_payload_len`] (`checked_mul`), which also bounds it
    /// against `file_size`. Mirrors `decrypt_index_region`'s hygiene.
    fn decrypt_region_plaintext(
        &self,
        region: RegionDescriptor,
        region_kind: IndexRegionKind,
        key: &AesKey,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        // `verify_region` only ever passes `Fdi`/`Phi` here — the main
        // index is verified via `verify_main_index_region` +
        // `decrypt_index_region`, so `Main` never reaches this function; it
        // shares the `Fdi` arm as a harmless exhaustiveness default (the
        // grouped value is never rendered). Map the region to its byte-size
        // wire field for typed faults; the human-readable `path` label comes
        // from the shared `IndexRegionKind::human_label` (one home, #635).
        let field = match region_kind {
            IndexRegionKind::Phi => WireField::PhiSize,
            IndexRegionKind::Fdi | IndexRegionKind::Main => WireField::FdiSize,
        };
        let size = region.size();
        // Bounds-check the 16-aligned on-disk extent against EOF and get
        // the aligned length through the shared align-then-check helper
        // (one home with the open-path region reads, #635) — so verify
        // reads exactly the same extent open does.
        let aligned = checked_aligned_payload_len(
            region.offset(),
            size,
            self.file_size,
            region_kind.human_label(),
        )?;
        let aligned_usize = usize::try_from(aligned).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ExceedsPlatformUsize {
                field,
                value: aligned,
                path: None,
            },
        })?;
        // `size <= aligned <= usize::MAX` is proven above (the `aligned`
        // conversion succeeded), so this cannot fail — but keep it fallible
        // to match `read_region_maybe_decrypt` and the no-panics-in-core
        // policy rather than `.expect()`.
        let size_usize = usize::try_from(size).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ExceedsPlatformUsize {
                field,
                value: size,
                path: None,
            },
        })?;
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
        {
            let mut guard = self.locked();
            let _ = guard.seek(SeekFrom::Start(region.offset()))?;
            guard.read_exact(&mut buf)?;
        }
        crypto::aes256_ecb_decrypt(key, &mut buf)?;
        buf.truncate(size_usize);
        Ok(buf)
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
    /// AES-encrypted entries verify KEYLESSLY and METHOD-AGNOSTICALLY
    /// (#634): UE stores the entry SHA1 over the on-disk CIPHERTEXT, and
    /// verification never decompresses, so an encrypted entry is hashed
    /// over its contiguous ciphertext regardless of compression method —
    /// an encrypted Oodle/Zstd entry verifies exactly like an encrypted
    /// Zlib one. (Encrypted INDEX regions differ — their SHA1 covers the
    /// PLAINTEXT, so `verify_index` decrypts before hashing; #635.
    /// Whole-archive-encrypted paks are rejected at open.)
    ///
    /// Returns:
    /// - `Ok(VerifyOutcome::Verified)` on a hash match.
    /// - `Ok(VerifyOutcome::SkippedNoHash)` when the entry's stored SHA1
    ///   is all zeros (no integrity claim recorded at write time), or the
    ///   entry is a v10+ encoded record (which omits SHA1 from the wire).
    /// - `Err(EntryNotFound)` for unknown paths.
    /// - `Err(Decompression)` for a PLAINTEXT entry in an unsupported
    ///   compression method (Gzip, Oodle, Zstd, UnknownByName, Unknown).
    ///   Plaintext Zlib and LZ4 verify normally (the entry SHA1 covers
    ///   the on-disk compressed bytes, so no decompression happens on the
    ///   verify path); for unsupported methods we refuse to hash raw
    ///   compressed bytes we can't interpret. This method gate applies
    ///   ONLY to plaintext entries — encrypted entries hash opaque
    ///   ciphertext (see above), so the method never matters for them.
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

        // Task-4 RESOLVED (#634): UE stores the entry SHA1 over the on-disk
        // CIPHERTEXT truncated to `compressed_size` — verified empirically
        // against the UnrealPak-produced vendored fixtures for BOTH entry
        // classes (uncompressed `test.txt`: the 446-byte `compressed_size`
        // range matches the stored hash, the 448-byte aligned region does
        // not; every compressed entry matches its ciphertext range too).
        // Encrypted entries therefore verify KEYLESSLY through the same
        // hash arms as plaintext entries: the bytes on disk are exactly
        // what the hash covers. No `is_encrypted` branch is needed here.

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

        let actual = if entry.header().is_encrypted() {
            // Encrypted entries verify KEYLESSLY and METHOD-AGNOSTICALLY
            // (#634): UE stores the entry SHA1 over the on-disk CIPHERTEXT
            // `[payload_start, payload_start + compressed_size)` — including
            // any intra-block AES padding (v8b `test.png` hashes 7760, not
            // the 7746 unaligned block sum). `verify` never decompresses, so
            // the compression method is IRRELEVANT here: an encrypted
            // Oodle/Zstd entry hashes its ciphertext exactly like an encrypted
            // Zlib one. Handling every encrypted entry with one contiguous
            // hash — ahead of the plaintext method match — keeps `verify()`
            // gracefully degrading over modern encrypted archives instead of
            // fail-fasting on the first unsupported-method entry.
            let payload_start =
                checked_payload_start(entry.header().offset(), in_data.wire_size(), path)?;
            let compressed = entry.header().compressed_size();
            // Bounds-check the hashed range AND the method-dependent
            // 16-ALIGNED extent the read path must consume, so `Verified`
            // implies the read path's payload bounds hold — a crafted pak
            // missing only its trailing AES padding (or splitting the
            // inline compressed/uncompressed fields for a `None`-method
            // entry) must fail verify, not report Verified and then fail
            // to read (#689 review). The hash below still covers only
            // `compressed` bytes, per the wire SHA-1 convention.
            checked_encrypted_verify_extents(
                payload_start,
                compressed,
                entry.header().uncompressed_size(),
                matches!(entry.header().compression_method(), CompressionMethod::None),
                self.file_size,
                path,
            )?;
            let _ = file.seek(SeekFrom::Start(payload_start))?;
            sha1_of_reader(&mut file, compressed, &mut buf)?
        } else {
            match entry.header().compression_method() {
                CompressionMethod::None => {
                    // Plaintext uncompressed entry. Bounds-check the payload
                    // end so a truncated archive surfaces as the structured
                    // `OffsetPastFileSize` rather than a bare
                    // `Io::UnexpectedEof` partway through hashing (issue #48).
                    let _ = checked_payload_end(
                        file.stream_position()?,
                        entry.header().uncompressed_size(),
                        self.file_size,
                        path,
                    )?;
                    sha1_of_reader(&mut file, entry.header().uncompressed_size(), &mut buf)?
                }
                CompressionMethod::Zlib | CompressionMethod::Lz4 => {
                    // Plaintext compressed entry: hash the on-disk compressed
                    // bytes block-by-block (encrypted entries are hashed
                    // contiguously above). Blocks are contiguous so this
                    // equals the `compressed_size` range, but the walk routes
                    // every block through `validate_block_bounds`
                    // (start-overlap, end-past-file, out-of-order) — shared
                    // with the stream_*_to readers so verify and read can't
                    // diverge on the same archive.
                    let payload_start =
                        checked_payload_start(entry.header().offset(), in_data.wire_size(), path)?;
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
                // Plaintext entry in a method we don't decode. Unlike the
                // encrypted branch above (which hashes opaque ciphertext),
                // we refuse to hash raw compressed bytes of a method we
                // can't interpret rather than risk a misleading result.
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
    /// hash (UE didn't enable integrity at write time, or a v10+ encoded
    /// record with no SHA1 on the wire) are counted in the returned
    /// [`VerifyStats`]. (Encrypted entries are NOT skipped as of #634 —
    /// they verify keylessly against the on-disk ciphertext hash.) Callers
    /// can inspect the report to decide whether `Ok` means "all bytes
    /// intact" or "some bytes weren't verifiable" — avoiding the silent
    /// partial-success failure mode that returning bare
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
        let payload_start =
            checked_payload_start(entry.header().offset(), in_data.wire_size(), path)?;

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
            method @ (CompressionMethod::Zlib | CompressionMethod::Lz4) => {
                // Encrypted + compressed (#634): UE encrypts the 16-aligned
                // compressed payload as one contiguous AES-256-ECB region, so
                // it must be decrypted BEFORE per-block inflation. Decrypt
                // into memory and run the unchanged codec streamers over a
                // rebased view of the plaintext-compressed bytes; the
                // `is_encrypted && key.is_none()` case was already rejected
                // above, so a missing key here is unreachable.
                if entry.header().is_encrypted() {
                    let Some(key) = self.key.as_ref() else {
                        return Err(PaksmithError::Decryption {
                            path: Some(path.to_string()),
                        });
                    };
                    let decrypted = read_decrypted_compressed_payload(
                        &mut file,
                        entry,
                        self.file_size,
                        payload_start,
                        key,
                    )?;
                    let mut rebased = RebasedReader::new(&decrypted, payload_start);
                    // The block streamers validate `abs_end` against the
                    // ceiling passed here. The backing store is the
                    // decrypted buffer (`decrypted.len()` bytes at
                    // `payload_start`), NOT the whole file — so pass the
                    // buffer's extent as the ceiling. A malformed v3-v9
                    // inline block pointing past the payload (no
                    // block-sum cross-check exists for that index form)
                    // then surfaces as a typed `BlockBoundsViolation`
                    // (`EndPastFileSize`) from `validate_block_bounds`
                    // rather than a bare `Io(UnexpectedEof)` from the
                    // rebased cursor. `payload_start + decrypted.len()` was
                    // already EOF-checked inside
                    // `read_decrypted_compressed_payload`, so it cannot
                    // actually overflow — but use `checked_add` for a typed
                    // fault anyway, matching this file's defense-in-depth
                    // arithmetic convention. The `buffer_end` vs
                    // `self.file_size` ceiling choice is pinned by the
                    // in-source test
                    // `read_encrypted_compressed_block_end_between_buffer_and_file_uses_buffer_ceiling`
                    // (in-source, not the integration crate, so cargo-mutants —
                    // which runs only default-members — actually credits the
                    // kill): a forged single-block `end` between the two values
                    // must reject as `EndPastFileSize`, which the wider
                    // `self.file_size` ceiling would let through.
                    let buffer_end = payload_start
                        .checked_add(decrypted.len() as u64)
                        .ok_or_else(|| PaksmithError::InvalidIndex {
                            fault: IndexParseFault::U64ArithmeticOverflow {
                                path: Some(path.to_string()),
                                operation: OverflowSite::PayloadEnd,
                            },
                        })?;
                    dispatch_compressed(
                        &mut rebased,
                        method,
                        entry,
                        buffer_end,
                        payload_start,
                        self.version(),
                        writer,
                    )
                } else {
                    dispatch_compressed(
                        &mut file,
                        method,
                        entry,
                        self.file_size,
                        payload_start,
                        self.version(),
                        writer,
                    )
                }
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

/// Route a `Zlib | Lz4` entry to its per-block streamer over `reader`.
///
/// `reader` is either the pak file (plaintext entries) or a
/// [`RebasedReader`] over the decrypted payload (encrypted entries,
/// #634) — the streamers are generic over `R: Read + Seek`, so the same
/// dispatch serves both. `method` MUST be `Zlib` or `Lz4` (the caller's
/// match guarantees it); the `else` branch is `Lz4`.
fn dispatch_compressed<R: Read + Seek>(
    reader: &mut R,
    method: &CompressionMethod,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    version: PakVersion,
    writer: &mut dyn Write,
) -> crate::Result<u64> {
    if *method == CompressionMethod::Zlib {
        stream_zlib_to(reader, entry, file_size, payload_start, version, writer)
    } else {
        stream_lz4_to(reader, entry, file_size, payload_start, writer)
    }
}

/// Cap a claimed `compressed_size` at `MAX_UNCOMPRESSED_ENTRY_BYTES`
/// (8 GiB) — the per-entry allocation ceiling (#634).
///
/// The same ceiling the open-time sweep enforces on `uncompressed_size`,
/// the v10+ encoded parser enforces on `compressed_size`
/// (`entry_header.rs`), and the crypto hardening policy
/// (`docs/formats/crypto/aes-pak.md`) requires of any AES reader. The
/// v3-v9 INLINE index applies no parse-time cap on `compressed_size`, so
/// without this an inline encrypted+compressed entry could drive a
/// single-shot decrypt buffer bounded only by the file size, not by the
/// codebase's stated per-entry ceiling.
///
/// Extracted from `read_decrypted_compressed_payload` so the boundary is
/// unit-testable WITHOUT driving the multi-GiB allocation the full read
/// path would attempt at `comp == MAX` — a `checked_payload_end` mutant
/// that bypasses the later EOF guard would otherwise let an at-cap test
/// allocate 8 GiB and time the whole test binary out.
fn ensure_compressed_size_within_cap(comp: u64, path: &str) -> crate::Result<()> {
    if comp > MAX_UNCOMPRESSED_ENTRY_BYTES {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: WireField::CompressedSize,
                value: comp,
                limit: MAX_UNCOMPRESSED_ENTRY_BYTES,
                unit: BoundsUnit::Bytes,
                path: Some(path.to_string()),
            },
        });
    }
    Ok(())
}

/// Read and decrypt an encrypted entry's compressed payload (#634).
///
/// UE encrypts the compressed payload as ONE contiguous AES-256-ECB
/// region padded to 16-byte alignment (per the repak/UnrealPak wire
/// reference), so the whole aligned region is read and decrypted up
/// front, then truncated to `compressed_size` — the per-block
/// decompressors then walk the plaintext-compressed bytes through a
/// [`RebasedReader`]. Mirrors `stream_uncompressed_to`'s encrypted arm:
/// same `Zeroizing` hygiene, same `AllocationFailed` fault, same
/// EOF bounds discipline.
fn read_decrypted_compressed_payload<R: Read + Seek>(
    file: &mut R,
    entry: &PakIndexEntry,
    file_size: u64,
    payload_start: u64,
    key: &AesKey,
) -> crate::Result<Zeroizing<Vec<u8>>> {
    let path = entry.filename();
    let comp = entry.header().compressed_size();

    // Cap the per-entry allocation at `MAX_UNCOMPRESSED_ENTRY_BYTES`
    // (8 GiB) BEFORE reading (see the helper's docs for why the inline
    // index needs this and why it lives in a testable free function).
    ensure_compressed_size_within_cap(comp, path)?;

    // Reject a `compressed_size` claim past EOF before the alignment
    // arithmetic: a fail-fast on the unaligned claim that keeps the
    // allocation file-proportional. (Overflow-freedom of the `div_ceil`/
    // `* 16` below does NOT rest on this check — the 8 GiB cap above
    // already bounds `comp < 2^63`, and the `checked_mul` guards the
    // multiply regardless; this is the stricter aligned check's weaker
    // sibling, kept for the tighter unaligned error attribution.)
    let _ = checked_payload_end(payload_start, comp, file_size, path)?;
    // Align-up + aligned-extent EOF check via the shared helper (also used
    // by `verify_entry`'s encrypted arm — one home for this arithmetic so
    // verify and read cannot drift; #689 review). `comp <= min(file_size,
    // 8 GiB) < 2^63`, so the align-up cannot actually overflow; the
    // helper's `checked_mul` guards it with a typed fault regardless.
    // INVARIANT: the cap (`ensure_compressed_size_within_cap`) is on `comp`,
    // but the allocation below is on `aligned`; that stays `<= MAX` only
    // because `MAX_UNCOMPRESSED_ENTRY_BYTES` is itself 16-aligned (2^33), so
    // `comp <= MAX` implies `aligned <= MAX`. Keep that constant a multiple
    // of 16 if it ever changes.
    let aligned = checked_aligned_payload_len(payload_start, comp, file_size, path)?;
    let aligned_usize = usize::try_from(aligned).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::U64ExceedsPlatformUsize {
            field: WireField::CompressedSize,
            value: aligned,
            path: Some(path.to_string()),
        },
    })?;
    let comp_usize = usize::try_from(comp).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::U64ExceedsPlatformUsize {
            field: WireField::CompressedSize,
            value: comp,
            path: Some(path.to_string()),
        },
    })?;

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
    let _ = file.seek(SeekFrom::Start(payload_start))?;
    file.read_exact(&mut buf)?;
    crypto::aes256_ecb_decrypt(key, &mut buf)?;
    buf.truncate(comp_usize);
    Ok(buf)
}

/// `Read + Seek` view over a decrypted in-memory payload that answers
/// ABSOLUTE file offsets (#634): `Seek(Start(abs))` maps to
/// `abs - base` within the buffer, so the per-block decompressors —
/// whose block tables carry real file offsets — run unchanged over the
/// plaintext-compressed bytes. Seeks or reads outside the payload
/// region surface as `io::Error` (fail-closed; a block table pointing
/// outside its own entry's payload is malformed for encrypted entries).
struct RebasedReader<'a> {
    inner: io::Cursor<&'a [u8]>,
    base: u64,
}

impl<'a> RebasedReader<'a> {
    fn new(payload: &'a [u8], base: u64) -> Self {
        Self {
            inner: io::Cursor::new(payload),
            base,
        }
    }
}

impl Read for RebasedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for RebasedReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Only `Start(abs)` is meaningful for a rebasing view: the block
        // streamers seek exclusively by absolute file offset. `Current`
        // and `End` would silently diverge from the pak-file reader this
        // substitutes (`End(0)` = payload end, not file end), so reject
        // them fail-closed rather than answer a subtly wrong position.
        let abs = match pos {
            SeekFrom::Start(abs) => abs,
            SeekFrom::Current(_) | SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RebasedReader supports only SeekFrom::Start",
                ));
            }
        };
        let rel = abs.checked_sub(self.base).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before encrypted payload base",
            )
        })?;
        let rel_pos = self.inner.seek(SeekFrom::Start(rel))?;
        rel_pos
            .checked_add(self.base)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rebased position overflow"))
    }
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
    file_size: u64,
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

    // Encrypted regions are 16-aligned on disk. `checked_aligned_payload_len`
    // computes that extent overflow-safely (`checked_mul`, and `index_size <=
    // MAX_INDEX_BYTES` above keeps it far from the ceiling) AND bounds it
    // against `file_size` — so a crafted `index_size` whose 16-padding
    // overshoots EOF surfaces as a typed `OffsetPastFileSize`, not a bare
    // `Io(UnexpectedEof)` from `read_exact` (matches the v10+ region reads,
    // #635).
    let aligned = checked_aligned_payload_len(
        footer.index_offset(),
        index_size,
        file_size,
        IndexRegionKind::Main.human_label(),
    )?;
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

/// Read, AES-256-ECB-decrypt, and parse an encrypted pak index — both the
/// flat (v3-v9) and path-hash (v10+) layouts (#635).
///
/// UE encrypts each index region in place and pads it to 16-byte
/// alignment. Two shapes:
/// - **Flat (v3-v9):** one contiguous region at `index_offset`. We slurp
///   `align_up(index_size, 16)` bytes, decrypt, and parse the plaintext
///   through a `Cursor` (the parser's seek-to-offset is meaningless
///   against an in-memory buffer).
/// - **Path-hash (v10+):** three regions (primary/PHI/FDI) at separate
///   absolute file offsets. Decryption happens PER region inside
///   [`PakIndex::read_v10_plus_from`] — each is read from the real file
///   reader (so the absolute FDI/PHI seeks work) and decrypted in place —
///   so we seek to the primary index and thread the key through
///   [`PakIndex::read_positioned_maybe_encrypted`].
///
/// **Fail-closed.** A wrong key produces garbage plaintext that the
/// index parser's magic/bounds checks reject; that error is mapped to
/// [`PaksmithError::Decryption`] so the caller can't tell a wrong key
/// from a corrupt index (and neither leaks an opaque parse fault). See
/// the `wrong_key_map` comment for the version-dependent `Io` handling.
///
/// **No unbounded allocation.** Every region caps its size at
/// [`MAX_INDEX_BYTES`] / [`MAX_FDI_BYTES`] before the 16-alignment
/// multiply (which would otherwise overflow near `u64::MAX`), the `usize`
/// conversion, and a fallible `try_reserve_exact`.
fn read_encrypted_index<R: Read + Seek>(
    reader: &mut R,
    footer: &PakFooter,
    file_size: u64,
    key: &AesKey,
) -> crate::Result<PakIndex> {
    let index_size = footer.index_size();

    // A parse failure on a decrypted region means garbage plaintext — a
    // wrong key — so map it to a fail-closed `Decryption` that a caller
    // can't distinguish from a corrupt index. Pass through only
    // resource/platform faults that are independent of key correctness.
    //
    // On `Io`: wrong-key never produces a non-EOF reader `Io`. For the FLAT
    // (v3-v9) path all file I/O happens up front in `decrypt_index_region`
    // (outside this map) and `read_positioned` parses an in-memory `Cursor`,
    // so the only `Io` this map sees is a Cursor `UnexpectedEof` from garbage
    // plaintext (wrong key). For the V10+ path the region reads DO go through
    // the real reader inside this map, but their extents are bounds-pre-checked
    // — a wrong key corrupts only the decrypted CONTENT, surfacing as a typed
    // `InvalidIndex` or an in-memory Cursor `UnexpectedEof` (garbage
    // mount-string length / over-read). So a non-EOF reader `Io` (disk / media
    // / seek failure) is always a genuine, key-independent error and is
    // PRESERVED as `Io` (see `wrong_key_map`), giving the operator the real
    // cause instead of a misleading "wrong key". `UnexpectedEof` stays mapped
    // to `Decryption` (ambiguous: wrong-key Cursor over-read vs. file-shrink
    // race) — fail-closed, and wrong-key detection is unaffected.
    //
    // Accepted trade-off: for the v10+ path this collapse also swallows
    // faults that are NOT wrong-key garbage. Two classes:
    //   (1) post-parse cross-check faults — a correctly-keyed index that
    //       decrypts to structurally valid plaintext but fails the issue
    //       #131 `PhiFdiInconsistency` check, or a non-ASCII path hitting
    //       the `fnv64_path` ASCII-only limitation;
    //   (2) pre-decrypt structural bounds faults, such as
    //       `OffsetPastFileSize` (aligned extent past EOF),
    //       `RegionPastFileSize` (unaligned offset+size past EOF), or
    //       `BoundsExceeded` (declared size over its cap).
    // Both collapse into `Decryption`; the unencrypted path would surface
    // the specific fault, the encrypted path reports "looks like a wrong
    // key." This is deliberate and uniform. The FDI/PHI region offsets and
    // sizes come from the DECRYPTED primary index, so a wrong key's garbage
    // could itself trip class (2) — surfacing the typed fault there would be
    // a wrong-key oracle, and passing class (1) through would leak that the
    // key decrypted to a valid-looking index. The PRIMARY region's bounds
    // fault is key-independent (footer fields), but it is collapsed too so
    // the v10+ open presents one conservative failure mode. (The flat v3-v9
    // path keeps its typed bounds faults because they are checked on
    // plaintext footer fields OUTSIDE this closure — see
    // `decrypt_index_region` and the `flat_encrypted_index_aligned_overshoot`
    // test.) A wrong key reaching a structurally-valid parse is
    // cryptographically negligible, so the collapse loses nothing
    // security-relevant. The cost is diagnostic precision on encrypted v10+
    // opens only.
    let wrong_key_map = |e: PaksmithError| {
        let is_resource_fault = matches!(
            &e,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed { .. }
                    | IndexParseFault::U64ExceedsPlatformUsize { .. },
            }
        );
        // Preserve a genuine non-EOF reader `Io` (see the "On `Io`" rationale
        // in this function's doc): it is always a key-independent media/seek
        // failure, never a wrong-key signal. `UnexpectedEof` still collapses to
        // `Decryption` (ambiguous — wrong-key Cursor over-read vs. file-shrink
        // race — so fail-closed wins).
        let is_genuine_io = matches!(
            &e,
            PaksmithError::Io(io) if io.kind() != std::io::ErrorKind::UnexpectedEof
        );
        if is_resource_fault || is_genuine_io {
            e
        } else {
            debug!(?e, "encrypted index parse failed — likely wrong key");
            PaksmithError::Decryption { path: None }
        }
    };

    if footer.version().has_path_hash_index() {
        // v10+ (path-hash index): the primary/PHI/FDI regions live at
        // separate absolute file offsets, so decryption happens per
        // region inside `read_v10_plus_from` (each region is read via
        // the real file reader and decrypted in place). Position the
        // reader at the primary index and thread the key through (#635).
        let _ = reader.seek(SeekFrom::Start(footer.index_offset()))?;
        return PakIndex::read_positioned_maybe_encrypted(
            reader,
            footer.version(),
            index_size,
            file_size,
            footer.compression_methods(),
            Some(key),
        )
        .map_err(wrong_key_map);
    }

    // Flat (v3-v9): one contiguous encrypted region — decrypt it up front
    // and parse the plaintext through a `Cursor` (the parser's
    // seek-to-`index_offset` is meaningless against an in-memory buffer).
    // `index_size` (not the 16-aligned length) is the real index byte
    // budget; the trailing AES pad bytes are not part of the index.
    let buf = decrypt_index_region(reader, footer, file_size, key)?;
    PakIndex::read_positioned(
        &mut Cursor::new(&buf[..]),
        footer.version(),
        index_size,
        file_size,
        footer.compression_methods(),
    )
    .map_err(wrong_key_map)
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
        // Align-up + aligned-extent EOF check via the shared helper (one
        // home with `read_decrypted_compressed_payload` and
        // `verify_entry`'s encrypted arm, so the three sites cannot
        // drift; #689 review). `size <= MAX_UNCOMPRESSED_ENTRY_BYTES`
        // (8 GiB) is enforced at open time, so the align-up cannot
        // actually overflow; the helper's `checked_mul` guards it with a
        // typed fault regardless.
        let payload_start = file.stream_position()?;
        let aligned = checked_aligned_payload_len(payload_start, size, file_size, path)?;
        let aligned_usize = usize::try_from(aligned).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ExceedsPlatformUsize {
                field: WireField::UncompressedSize,
                value: aligned,
                path: Some(path.to_string()),
            },
        })?;

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
    let _ = checked_payload_end(file.stream_position()?, size, file_size, path)?;

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

/// Compute an entry's payload start (`offset + in-data record size`),
/// mapping an overflow to the typed `OffsetPlusHeader` fault. The
/// `checked_payload_end` sibling for the leading-add half of the same
/// payload-bounds pattern.
fn checked_payload_start(offset: u64, wire_size: u64, path: &str) -> crate::Result<u64> {
    offset
        .checked_add(wire_size)
        .ok_or_else(|| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ArithmeticOverflow {
                path: Some(path.to_string()),
                operation: OverflowSite::OffsetPlusHeader,
            },
        })
}

/// Compute a payload's end offset (`start + size`) and reject it if it
/// runs past `file_size`, returning typed faults. Shared by every
/// fixed-length payload read/verify path so a truncated archive surfaces
/// as `OffsetPastFileSize` (or `U64ArithmeticOverflow` on the add)
/// instead of a bare `Io(UnexpectedEof)` partway through the read — the
/// non-block-table sibling of [`validate_block_bounds`], which
/// consolidates the same check for the block-table case.
fn checked_payload_end(start: u64, size: u64, file_size: u64, path: &str) -> crate::Result<u64> {
    let end = start
        .checked_add(size)
        .ok_or_else(|| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ArithmeticOverflow {
                path: Some(path.to_string()),
                operation: OverflowSite::PayloadEnd,
            },
        })?;
    if end > file_size {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::OffsetPastFileSize {
                path: path.to_string(),
                kind: OffsetPastFileSizeKind::PayloadEndBounds {
                    payload_end: end,
                    file_size_max: file_size,
                },
            },
        });
    }
    Ok(end)
}

/// Align `size` up to the 16-byte AES block size (typed overflow fault)
/// and bounds-check the ALIGNED extent against `file_size` — the region
/// an encrypted-payload reader must actually consume.
///
/// Returns the aligned LENGTH, NOT an end offset — unlike its sibling
/// [`checked_payload_end`], which returns `start + size`. Callers size
/// buffers from the returned value; do not add `start` to it again or
/// compare it against absolute offsets (#689 Copilot review — the
/// `_len` suffix is load-bearing).
///
/// One home for the align-then-check arithmetic so the callers cannot
/// drift (#689 review): `read_decrypted_compressed_payload` and
/// `stream_uncompressed_to`'s encrypted arm (each sizing its decrypt
/// buffer), `checked_encrypted_verify_extents` (which picks the
/// read-required size field per compression method — see its docs for
/// why the field differs), and the encrypted v10+ index-region reads
/// (`read_region_maybe_decrypt` / `decrypt_region_plaintext`, #635).
/// Real archives always carry the AES padding (the index/footer follow
/// it), so an aligned-extent rejection only ever fires on crafted input.
pub(in crate::container::pak) fn checked_aligned_payload_len(
    start: u64,
    size: u64,
    file_size: u64,
    path: &str,
) -> crate::Result<u64> {
    let aligned = size
        .div_ceil(16)
        .checked_mul(16)
        .ok_or_else(|| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ArithmeticOverflow {
                path: Some(path.to_string()),
                operation: OverflowSite::PayloadEnd,
            },
        })?;
    let _ = checked_payload_end(start, aligned, file_size, path)?;
    Ok(aligned)
}

/// Bounds-check everything `verify_entry`'s encrypted arm relies on: the
/// hashed range plus the READ-REQUIRED on-disk extent, so `Verified`
/// implies the read path's payload bounds hold (#689 review, both
/// findings).
///
/// The read-required extent is METHOD-DEPENDENT, because the two read
/// paths align different fields:
/// - `None` (uncompressed): `stream_uncompressed_to`'s encrypted arm
///   reads `align16(uncompressed_size)` — and on inline v3-v9 entries
///   `compressed_size`/`uncompressed_size` are independent wire fields
///   (only the v10+ encoded parser aliases them), so checking the
///   compressed extent alone leaves a split-fields crafted entry that
///   verifies but cannot be read.
/// - `Zlib`/`Lz4`/anything else: `read_decrypted_compressed_payload`
///   reads `align16(compressed_size)` (unsupported methods decline
///   before reading, so the compressed extent is the conservative
///   claim there).
///
/// The unaligned `compressed_size` check runs first for tighter error
/// attribution, mirroring `read_decrypted_compressed_payload`. The
/// SHA-1 itself still covers only `compressed_size` bytes. A crafted
/// reverse split (`compressed > uncompressed`) can make verify reject
/// an entry the read path would accept — fail-closed over-tightening on
/// forged input; the invariant is one-directional (Verified ⟹ readable
/// bounds), and no real writer emits unequal fields for `None`.
fn checked_encrypted_verify_extents(
    payload_start: u64,
    compressed: u64,
    uncompressed: u64,
    is_uncompressed_method: bool,
    file_size: u64,
    path: &str,
) -> crate::Result<()> {
    let _ = checked_payload_end(payload_start, compressed, file_size, path)?;
    let _ = checked_aligned_payload_len(payload_start, compressed, file_size, path)?;
    if is_uncompressed_method {
        let _ = checked_aligned_payload_len(payload_start, uncompressed, file_size, path)?;
    }
    Ok(())
}

/// Validate one compression block's `(start, end)` pair against
/// the entry's payload region, the file size, and the previously
/// validated block's end (for monotonic file-order). Returns the
/// computed absolute `(abs_start, abs_end)` and updates
/// `prev_abs_end` so the next call sees this block's end.
///
/// Colocated with all three call sites (`stream_zlib_to` and
/// `stream_lz4_to` for the extract paths, `verify_entry`'s shared
/// `Zlib | Lz4` arm for the hash path)
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
        // Pre-v5 paks store compression-block offsets as absolute file offsets
        // rather than entry-relative (v5+); this read path doesn't implement
        // the absolute-offset case. repak CAN emit a compressed v4 archive
        // (verified by probe; v3 shares the same pre-v8 path), so an oracle
        // exists — this is a low-value deferral, not a capability gap. Reject
        // explicitly rather than silently produce garbage; wontfix — see #637.
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

/// Per-block decode budget for one LZ4 block: the size the output
/// buffer is pre-sized to (before the [`lz4_block_output_cap`]
/// intersection).
///
/// Non-final blocks are budgeted at `min(remaining, block_size)` —
/// the post-decode guard requires them to produce EXACTLY
/// `compression_block_size`, so a larger buffer could only be dead
/// weight (an eager `remaining`-sized reservation here was R8's
/// memory-discipline finding: block 0 of a multi-block entry would
/// reserve and zero-fill up to the whole entry). The FINAL block is
/// budgeted at `remaining` — NOT `min(remaining, block_size)` — the
/// exact mirror of `stream_zlib_to`'s `take(remaining + 1)`: a
/// single-block entry can legitimately declare a
/// `compression_block_size` smaller than `uncompressed_size` (repak
/// decodes that shape everywhere and CUE4Parse on its encoded/v10+
/// path, both via single-block normalization; CUE4Parse's legacy
/// v3-v9 reader has no normalization and rejects it — issue #685),
/// and the v3-v9 inline index applies no parse-time
/// `block_count × block_size` bound that would reject it first.
fn lz4_block_budget(remaining: u64, block_size: u64, is_final: bool) -> u64 {
    if is_final {
        remaining
    } else {
        remaining.min(block_size)
    }
}

/// Bound the pre-decode output reservation for one LZ4 block.
///
/// `expected_out` is the block's decode budget from
/// [`lz4_block_budget`] — for the final block that is the entry's
/// full remaining output (bounded upstream by the 8 GiB
/// `MAX_UNCOMPRESSED_ENTRY_BYTES` open-time cap), which is
/// entry-scale, not block-scale: pre-allocating it verbatim would
/// let a tiny crafted final block inside a large-claim entry force a
/// multi-gigabyte eager allocation (memory-amplification DoS, #636).
/// Intersecting with `compressed_len` ×
/// [`MAX_LZ4_BLOCK_EXPANSION_RATIO`] keeps the reservation
/// input-proportional: a valid block's real output is always
/// `≤ compressed_len × 255`, so the cap is transparent for
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
/// pre-sized to the block's decode budget (`lz4_block_budget`:
/// `min(remaining, compression_block_size)` for non-final blocks,
/// the remaining output for the final block), capped
/// input-proportionally by `lz4_block_output_cap` at
/// `compressed_len × 255`. The capped buffer doubles as the
/// decompression-bomb cap: `lz4_flex::block::decompress_into` errors
/// on a block that would expand past it (surfaced as
/// [`DecompressionFault::Lz4DecodeError`]), so over-expansion can
/// never allocate beyond the per-block capped budget.
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

        // Decode budget for THIS block — see `lz4_block_budget` for
        // the non-final/final split and its rationale. A crafted
        // entry with excess blocks yields budget 0 for the extras
        // (remaining is exhausted): a content-carrying extra dies
        // INSIDE the decoder (`OutputTooSmall` against the 0-byte
        // buffer → `Lz4DecodeError`), a zero-output non-final extra
        // dies at the block-size check below (0 != block_size), and
        // while a single TRAILING zero-output block (e.g. the 1-byte
        // `0x00` "empty last sequence" block) does decode Ok into an
        // empty buffer, it produces no bytes — output stays exactly
        // the declared `uncompressed_size` via
        // `check_cumulative_size`. The repak oracle is more lenient
        // still (it silently ignores ALL excess blocks), so this is
        // matching-or-stricter behavior.
        let remaining = uncompressed_size.saturating_sub(bytes_written);
        let is_final = i + 1 == entry.header().compression_blocks().len();
        let expected_out = lz4_block_budget(remaining, block_size, is_final);

        // SECURITY (#636): cap the reservation input-proportionally —
        // see `lz4_block_output_cap` for the derivation and threat
        // model. The capped buffer remains the decompression-bomb cap.
        let alloc_bound = lz4_block_output_cap(expected_out, block_len);
        // 32-bit-only: `value` is the DERIVED allocation bound
        // (`min(budget, block_len × 255)`), not a raw wire field.
        // The narrow can only fail for the FINAL block: a non-final
        // budget is capped by `compression_block_size`, a u32 that
        // always fits a 32-bit usize, so a failing bound always
        // derives from the `uncompressed_size` claim — `field` names
        // that. Unreachable on 64-bit (budget ≤ the 8 GiB entry cap).
        let alloc_usize =
            usize::try_from(alloc_bound).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::UncompressedSize,
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
        if !is_final && produced as u64 != block_size {
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
    /// RETIRED (#634): has NO producer as of encrypted-entry keyless
    /// verification — the stored SHA1 covers the on-disk ciphertext, so
    /// encrypted entries verify by hashing that ciphertext directly
    /// (method-agnostically, since verify never decompresses) rather than
    /// skipping. Retained (the enum is `#[non_exhaustive]`, and
    /// [`VerifyStats::entries_skipped_encrypted`] still reports its count,
    /// pinned at 0) for API stability. Never produced by
    /// [`PakReader::verify_index`] either.
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

    /// RETIRED counter (#634): always 0 now that encrypted entries verify
    /// keylessly (the stored SHA1 covers the on-disk ciphertext). Retained
    /// for API stability; see [`VerifyOutcome::SkippedEncrypted`].
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
    /// Since #634, per-entry-encrypted entries verify keylessly (they no
    /// longer count as skips), so a fully-encrypted archive whose stored
    /// hashes all match now reports `true` here — where it previously
    /// reported `false` on the retired `SkippedEncrypted` skip.
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

/// SHA1 digest of a contiguous in-memory byte slice. The single-slice
/// counterpart to [`sha1_of_reader`] (which streams `len` bytes through a
/// scratch buffer) — used where the bytes are already resident, e.g. a
/// decrypted index region in [`PakReader::verify_region`] /
/// [`PakReader::verify_main_index_region`].
fn sha1_of_bytes(bytes: &[u8]) -> Sha1Digest {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    Sha1Digest::from(<[u8; 20]>::from(hasher.finalize()))
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

    /// Non-final blocks are budgeted at `min(remaining, block_size)`
    /// — the memory-discipline half of `lz4_block_budget` (#636 R8):
    /// block 0 of a large entry must NOT be budgeted at the whole
    /// remaining output.
    #[test]
    fn lz4_block_budget_bounds_non_final_by_block_size() {
        assert_eq!(lz4_block_budget(8_000_000, 65_536, false), 65_536);
    }

    /// A non-final block past the declared total (excess-block shape)
    /// is budgeted at the exhausted remainder, not `block_size`.
    #[test]
    fn lz4_block_budget_non_final_exhausted_remainder_wins() {
        assert_eq!(lz4_block_budget(100, 65_536, false), 100);
    }

    /// The FINAL block is budgeted at `remaining` even when the
    /// declared `compression_block_size` is smaller — the
    /// reference-compatible single-block shape (#685). A
    /// `min(remaining, block_size)` regression here reintroduces the
    /// R7 rejection bug.
    #[test]
    fn lz4_block_budget_final_block_takes_full_remaining() {
        assert_eq!(lz4_block_budget(300, 128, true), 300);
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

    /// `stream_zlib_to` rejects pre-v5 (absolute-offset) versions at its
    /// version guard, and lets v5+ (entry-relative) through. In-source so
    /// cargo-mutants covers it — the integration-crate
    /// `read_zlib_rejects_pre_v5_compressed_entry` isn't run under the
    /// default-members mutant invocation, which let the `<
    /// RelativeChunkOffsets` boundary drift to `==`/`<=` unnoticed (#637
    /// review). `stream_zlib_to` takes `version` as a plain arg, so we drive
    /// the boundary directly against a real (v8b, entry-relative) compressed
    /// entry by overriding the version.
    #[test]
    fn stream_zlib_to_version_boundary_rejects_pre_v5_only() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_compressed.pak");
        let reader = PakReader::open(&fixture).expect("open compressed fixture");
        let path = "Content/Compressed.uasset";
        let entry = reader.index_entry(path).expect("compressed entry present");
        let payload_start = entry.header().offset() + entry.header().wire_size();
        let file_size = std::fs::metadata(&fixture).expect("stat fixture").len();

        // Pre-v5 (v3, v4): absolute-offset blocks are unimplemented — reject
        // with `UnsupportedVersion` before touching the blocks. Kills the
        // `<`→`==` mutant (which would let v3/v4 fall through).
        for v in [
            PakVersion::CompressionEncryption,
            PakVersion::IndexEncryption,
        ] {
            let mut file = std::fs::File::open(&fixture).expect("reopen fixture");
            let mut sink: Vec<u8> = Vec::new();
            let err = stream_zlib_to(&mut file, entry, file_size, payload_start, v, &mut sink)
                .expect_err("pre-v5 zlib must be rejected");
            assert!(
                matches!(err, PaksmithError::UnsupportedVersion { version } if version == v.wire_version()),
                "pre-v5 ({v:?}) must reject as UnsupportedVersion, got {err:?}"
            );
        }

        // v5 (RelativeChunkOffsets): the v8b entry's blocks ARE entry-relative,
        // so v5 dispatch passes the guard and decompresses to the full
        // uncompressed size. Asserting success (not merely "not rejected")
        // proves the v5 path actually works, and still kills the `<`→`<=`
        // mutant — which would reject v5 with `UnsupportedVersion` instead.
        let mut file = std::fs::File::open(&fixture).expect("reopen fixture");
        let mut sink: Vec<u8> = Vec::new();
        let written = stream_zlib_to(
            &mut file,
            entry,
            file_size,
            payload_start,
            PakVersion::RelativeChunkOffsets,
            &mut sink,
        )
        .expect("v5 (entry-relative) must pass the guard and decompress");
        assert_eq!(
            written,
            entry.header().uncompressed_size(),
            "v5 must decompress the v8b entry to its full uncompressed size"
        );
        assert_eq!(
            u64::try_from(sink.len()).expect("fits u64"),
            written,
            "bytes written to the sink must equal the returned count"
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

    // The following synthetic-pak tests exercise `stream_lz4_to`'s
    // budget and non-final-block size guards with SYNTHETIC v8b paks.
    // They live in-package (not only in `paksmith-core-tests`) because
    // cargo-mutants scopes each mutant's test run to the mutated
    // package: the cross-crate integration copies do NOT credit
    // mutants in `mod.rs`, so the `is_final` derivation
    // (`i + 1 == len`) and the guard's `produced != block_size`
    // operator survive without these.
    // EVERY test that touches the shared builder MUST be gated on
    // `__test_utils` because `crate::testing::wire` is — an ungated
    // test breaks every PACKAGE-SCOPED build of paksmith-core
    // (cargo-mutants baseline, `cargo test -p paksmith-core`,
    // publish). Wider invocations mask it: feature unification turns
    // `__test_utils` on whenever paksmith-core-tests or
    // paksmith-gui's dev-dep is in the resolved graph, which
    // includes the bare default-members `cargo test`. CI's guard is
    // therefore `-p paksmith-core`-scoped (#636 R8/R9).

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

    /// A single-block entry whose stored `compression_block_size` is
    /// SMALLER than `uncompressed_size`. The v3-v9 inline index has no
    /// parse-time `block_count × block_size` bound, so the shape
    /// reaches the decoder; repak decodes it (`ranges.len() == 1`
    /// normalization — CUE4Parse normalizes only on its encoded/v10+
    /// path and rejects this shape on v3-v9) and the zlib path
    /// decodes it too (its per-block budget is remaining-based, not
    /// `block_size`-bounded). The final block's budget must therefore
    /// be `remaining`, not `min(remaining, block_size)` — issue #685
    /// context, R7 review finding.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_single_block_smaller_declared_block_size_round_trips() {
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let stream = lz4_flex::block::compress(&payload);
        // block_size (128) < uncompressed_size (300), one block.
        let pak = crate::testing::wire::build_v8b_lz4_pak(
            std::slice::from_ref(&stream),
            payload.len() as u64,
            128,
        );
        let reader = PakReader::from_bytes(pak).expect("synthetic v8b pak parses");
        let mut out = Vec::new();
        let written = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect("single-block entry with an under-declared block_size must decode");
        assert_eq!(written, payload.len() as u64);
        assert_eq!(out, payload, "decode must be byte-exact");
    }

    /// A multi-block entry whose FINAL block carries the excess
    /// (`uncompressed_size > block_count × compression_block_size`,
    /// non-final blocks exact) decodes successfully: the final block's
    /// budget is `remaining`, so the 172-byte overflow fits. This is a
    /// DOCUMENTED divergence from the references (repak/CUE4Parse
    /// bound the final chunk by `compression_block_size` and would
    /// reject this shape) — paksmith is deliberately consistent with
    /// its own zlib path (`take(remaining + 1)`) instead, which
    /// accepts the identical framing. See lz4.md's derivation
    /// section; adversarial-only shape, no real writer emits it.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_multi_block_final_overflow_decodes() {
        let block_size = 128u32;
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        // Block 0 inflates to exactly block_size (128); the final
        // block carries the remaining 172 (> block_size).
        let streams: Vec<Vec<u8>> = vec![
            lz4_flex::block::compress(&payload[..128]),
            lz4_flex::block::compress(&payload[128..]),
        ];
        let pak =
            crate::testing::wire::build_v8b_lz4_pak(&streams, payload.len() as u64, block_size);
        let reader = PakReader::from_bytes(pak).expect("synthetic v8b pak parses");
        let mut out = Vec::new();
        let written = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect("final-block overflow shape must decode (documented lenient divergence)");
        assert_eq!(written, payload.len() as u64);
        assert_eq!(out, payload, "decode must be byte-exact");
    }

    /// A non-final block that inflates to FEWER than
    /// `compression_block_size` bytes must surface
    /// `NonFinalBlockSizeMismatch` at that exact block. Pins the
    /// guard's `!is_final` predicate (derived from `i + 1 == len`): a
    /// mutant that makes the guard never fire would instead surface
    /// the shortfall as a cumulative `SizeUnderrun` — asserting the
    /// EXACT fault (and block index) distinguishes the two and kills
    /// that mutant.
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

    /// A single-block entry whose stream inflates to FEWER bytes than
    /// the declared `uncompressed_size` must surface `SizeUnderrun`
    /// from the shared `check_cumulative_size` — the final block has
    /// no exact-size guard, so the post-loop cumulative check is the
    /// only thing standing. Lives in-package (not just the
    /// integration copy) so cargo-mutants credits the
    /// `check_cumulative_size -> Ok(())` gut mutant, which the CI
    /// shard run proved survives on integration coverage alone.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_short_final_block_surfaces_size_underrun() {
        // Stream decodes to 200 bytes; the entry claims 300.
        let stream = lz4_flex::block::compress(&[b'A'; 200]);
        let pak = crate::testing::wire::build_v8b_lz4_pak(std::slice::from_ref(&stream), 300, 300);
        let reader = PakReader::from_bytes(pak).expect("synthetic pak parses");
        let mut out = Vec::new();
        let err = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect_err("short final block must be rejected");
        match &err {
            PaksmithError::Decompression {
                fault: DecompressionFault::SizeUnderrun { actual, expected },
                ..
            } => {
                assert_eq!(*actual, 200, "actual must be the produced byte count");
                assert_eq!(*expected, 300, "expected must be the declared size");
            }
            other => {
                panic!("expected SizeUnderrun {{ actual: 200, expected: 300 }}; got {other:?}")
            }
        }
    }

    /// The mirror direction: a non-final block that inflates PAST
    /// `compression_block_size` dies INSIDE the decoder
    /// (`OutputTooSmall` against the `min(remaining, block_size)`
    /// buffer → `Lz4DecodeError`) — a different fault than the
    /// under-produce direction's post-decode `NonFinalBlockSizeMismatch`
    /// above. Pins the budget's non-final `min` arm (a
    /// `remaining`-sized mutant buffer would decode this block
    /// successfully) and the doc's fault-taxonomy claim (R10 review).
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_lz4_entry_over_producing_non_final_block_rejected() {
        let block_size = 64u32;
        // block0 inflates to 128 (> 64) and is non-final; block1
        // supplies a valid 64-byte tail of a 192-byte total.
        let over = lz4_flex::block::compress(&[b'A'; 128]);
        let tail = lz4_flex::block::compress(&[b'B'; 64]);
        let pak = crate::testing::wire::build_v8b_lz4_pak(&[over, tail], 192, block_size);
        let reader = PakReader::from_bytes(pak).expect("synthetic pak parses");
        let mut out = Vec::new();
        let err = reader
            .read_entry_to(crate::testing::wire::LZ4_SYNTH_PATH, &mut out)
            .expect_err("over-producing non-final block must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::Decompression {
                    fault: DecompressionFault::Lz4DecodeError { block_index: 0, .. },
                    ..
                }
            ),
            "expected Lz4DecodeError at block 0 (decoder-level OutputTooSmall), got {err:?}"
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

    /// Absolute offset of the footer's 4-byte magic within `bytes` — the
    /// anchor for magic-relative footer field offsets (version at `+4`,
    /// index_offset at `+8`, index_size at `+16`, index_hash at `+24`).
    /// Sourced from [`version::PAK_MAGIC`] rather than a hand-typed literal,
    /// and shared by the tests that patch/inspect the footer. The footer
    /// sits at the physical tail, so the LAST magic occurrence is its.
    fn footer_magic_pos(bytes: &[u8]) -> usize {
        let magic = crate::container::pak::version::PAK_MAGIC.to_le_bytes();
        bytes
            .windows(4)
            .rposition(|w| w == magic.as_slice())
            .expect("footer magic must be present in fixture")
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

    /// A flat (v3-v9) encrypted index whose LOGICAL `index_size` passes the
    /// footer bound (`index_offset + index_size <= file_size`) but whose
    /// 16-aligned on-disk extent overshoots EOF must surface a typed
    /// `OffsetPastFileSize` (via the shared `checked_aligned_payload_len`),
    /// not a bare `Io(UnexpectedEof)` from `read_exact`. The v10+ region
    /// reads run the same `checked_aligned_payload_len` internally, but
    /// `read_encrypted_index` collapses their faults into `Decryption` at
    /// the open boundary (see `wrong_key_map`); the flat path surfaces the
    /// typed fault directly because its check runs on the plaintext footer
    /// fields, outside that collapse.
    #[test]
    fn flat_encrypted_index_aligned_overshoot_is_offset_past_file_size() {
        let mut bytes = std::fs::read(encrypted_index_fixture()).expect("read fixture bytes");
        let footer_start = footer_magic_pos(&bytes);
        let idx_off_pos = footer_start + 8;
        let idx_size_pos = footer_start + 16;
        let index_offset =
            u64::from_le_bytes(bytes[idx_off_pos..idx_off_pos + 8].try_into().unwrap());
        let file_size = bytes.len() as u64;
        // Claim the entire region-through-EOF as the index: index_offset +
        // index_size == file_size (passes the footer bound), but the encrypted
        // region is 16-aligned on disk and the v8b+ footer is 221 bytes
        // (≡ 13 mod 16), so file_size - index_offset ≡ 13 mod 16 → align16
        // overshoots EOF by 3.
        let patched = file_size - index_offset;
        assert_ne!(patched % 16, 0, "test requires a non-16-aligned overshoot");
        bytes[idx_size_pos..idx_size_pos + 8].copy_from_slice(&patched.to_le_bytes());

        let key = AesKey::new(FIXTURE_AES_KEY);
        let err = PakReader::from_reader_with_key(std::io::Cursor::new(bytes), key)
            .expect_err("aligned index extent overshoots EOF");
        match err {
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize { path, .. },
            } => assert_eq!(
                path, "index",
                "the aligned-overshoot fault must carry a diagnostic region label"
            ),
            other => {
                panic!("aligned-overshoot must surface as typed OffsetPastFileSize, got {other:?}")
            }
        }
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
        let footer_start = footer_magic_pos(&fixture_bytes);
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

    /// Path of the v11 (path-hash index) encrypted-index fixture.
    fn encrypted_v11_index_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_encrypted_index.pak")
    }

    /// #635 RED→GREEN oracle: an encrypted v11 (path-hash + full-directory
    /// index) pak must open with the correct key and expose the four known
    /// corpus entries. All THREE index regions (primary, PHI, FDI) are
    /// AES-256-ECB encrypted on the wire (probed empirically: ciphertext is
    /// garbage, plaintext parses — PHI opens with count 4, FDI with 2
    /// directories), so this exercises decrypt-then-parse for each region.
    /// Replaces the retired `UnsupportedFeature` deferral pin.
    #[test]
    fn open_with_key_decrypts_v11_path_hash_index_and_lists_entries() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_v11_index_fixture(), key)
            .expect("v11 encrypted path-hash index must decrypt + parse");
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
            "decrypted v11 index must expose the four known fixture entries"
        );
    }

    /// #635: end-to-end read through the decrypted v11 index — the entry
    /// payloads in this fixture are PLAINTEXT (only the index is
    /// encrypted), so a correct index decrypt yields the known corpus
    /// bytes.
    #[test]
    fn reads_entry_through_encrypted_v11_path_hash_index() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_v11_index_fixture(), key)
            .expect("v11 encrypted path-hash index must decrypt + parse");
        let bytes = reader
            .read_entry("test.txt")
            .expect("read through the decrypted v11 index");
        assert_eq!(bytes, FIXTURE_PLAINTEXT_TEST_TXT);
    }

    /// #635: `verify_index()` on the encrypted v11 pak must report
    /// `Verified` for ALL THREE regions. UE records each region's SHA-1
    /// over the PLAINTEXT (probed: the footer index hash and the PHI/FDI
    /// hashes all match `sha1(plaintext[..size])`, not the ciphertext) —
    /// so verification must DECRYPT each region before hashing. A verify
    /// path that hashed the on-disk ciphertext for FDI/PHI would false-
    /// mismatch (this is the encrypted-region analogue of the #634 R1
    /// bug). Keyed open is required (a keyless open can't decrypt).
    #[test]
    fn verify_index_on_encrypted_v11_index_is_verified() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_v11_index_fixture(), key)
            .expect("v11 encrypted path-hash index must decrypt + parse");
        assert_eq!(
            reader
                .verify_index()
                .expect("verify_index must run on the decrypted v11 index"),
            VerifyOutcome::Verified,
            "all three encrypted index regions hash their plaintext; verify must decrypt first"
        );
    }

    /// #635 v10 half of the acceptance criteria. No first-party v10
    /// encrypted-index fixture is vendored, but V10 (`PathHashIndex`) and
    /// V11 (`Fnv64BugFix`) share the SAME footer and index layout — the
    /// only wire difference is the FNV path-hash seed handling, and
    /// paksmith's `fnv64_path` is VERSION-AGNOSTIC (it consumes only the
    /// stored seed, accepting both UE variants — see index/mod.rs). So
    /// patching the real v11 fixture's footer version u32 from 11 to 10
    /// yields a wire-valid v10 encrypted-index pak over otherwise-real
    /// UnrealPak bytes: it exercises the v10 version-DISPATCH end-to-end
    /// (open + decrypt all three regions + FDI path recovery + read),
    /// with the real v11 fixture as the wire-conformance anchor. The
    /// version u32 sits in the footer after guid(16)+enc(1)+magic(4);
    /// changing it invalidates no region hash (hashes cover the index
    /// regions, not the footer).
    #[test]
    fn open_with_key_decrypts_v10_path_hash_index_and_reads() {
        let mut bytes = std::fs::read(encrypted_v11_index_fixture()).expect("read v11 fixture");
        // Locate the footer via its magic bytes (as the other tests in this
        // module do) rather than hardcoding the footer size; the version u32
        // sits immediately after the 4-byte magic. The "reads 11" sanity
        // assert below still guards the offset math either way.
        let ver_off = footer_magic_pos(&bytes) + 4;
        assert_eq!(
            u32::from_le_bytes(bytes[ver_off..ver_off + 4].try_into().unwrap()),
            11,
            "sanity: patch target must be the version field currently reading 11"
        );
        bytes[ver_off..ver_off + 4].copy_from_slice(&10u32.to_le_bytes());

        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(bytes), key)
            .expect("v10 (path-hash index) encrypted pak must decrypt + parse");
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
        );
        let plaintext = reader
            .read_entry("test.txt")
            .expect("read through v10 index");
        assert_eq!(plaintext, FIXTURE_PLAINTEXT_TEST_TXT);
        assert_eq!(
            reader.verify_index().expect("verify v10 index"),
            VerifyOutcome::Verified,
        );
    }

    /// A `Read + Seek` over in-memory bytes that injects a chosen
    /// [`std::io::Error`] the moment a read STARTS at absolute offset
    /// `fail_at`. Used to fire a fault during the encrypted index-region
    /// read — which happens AFTER the footer parse, so it routes through
    /// `read_encrypted_index`'s `wrong_key_map`.
    struct FaultAtOffset {
        inner: std::io::Cursor<Vec<u8>>,
        fail_at: u64,
        kind: std::io::ErrorKind,
    }

    impl std::io::Read for FaultAtOffset {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.inner.position() == self.fail_at {
                return Err(std::io::Error::new(self.kind, "injected fault"));
            }
            self.inner.read(buf)
        }
    }

    impl std::io::Seek for FaultAtOffset {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// The v11 fixture's primary-index absolute offset, parsed from the
    /// footer (`…magic(4) + version(4) + index_offset(8)…`).
    fn v11_primary_index_offset(bytes: &[u8]) -> u64 {
        let magic_pos = footer_magic_pos(bytes);
        u64::from_le_bytes(bytes[magic_pos + 8..magic_pos + 16].try_into().unwrap())
    }

    /// #635 diagnostics: a genuine (non-EOF) reader I/O error during the
    /// encrypted v10+ index-region read must surface as `Io`, NOT collapse
    /// to `Decryption`. Wrong-key never produces a non-EOF reader Io (the
    /// ciphertext reads are bounds-pre-checked; a wrong key corrupts only
    /// the decrypted content), so a media/seek failure is key-independent
    /// and its real cause must reach the operator — matching the flat path.
    #[test]
    fn v10_plus_encrypted_open_preserves_genuine_disk_io() {
        let bytes = std::fs::read(encrypted_v11_index_fixture()).expect("read v11 fixture");
        let fail_at = v11_primary_index_offset(&bytes);
        let reader = FaultAtOffset {
            inner: std::io::Cursor::new(bytes),
            fail_at,
            kind: std::io::ErrorKind::Other,
        };
        let key = AesKey::new(FIXTURE_AES_KEY);
        let err = PakReader::from_reader_with_key(reader, key)
            .expect_err("injected disk Io must fail the open");
        assert!(
            matches!(&err, PaksmithError::Io(io) if io.kind() == std::io::ErrorKind::Other),
            "a genuine non-EOF disk Io during the encrypted index read must surface as Io, not Decryption; got {err:?}"
        );
    }

    /// #635 fail-closed: an `UnexpectedEof` during the same read stays
    /// mapped to `Decryption` — it is ambiguous between a wrong-key Cursor
    /// over-read and a file-shrink race, so fail-closed wins. Pins the
    /// `!= UnexpectedEof` half of `wrong_key_map`'s Io discrimination.
    #[test]
    fn v10_plus_encrypted_open_maps_eof_to_decryption() {
        let bytes = std::fs::read(encrypted_v11_index_fixture()).expect("read v11 fixture");
        let fail_at = v11_primary_index_offset(&bytes);
        let reader = FaultAtOffset {
            inner: std::io::Cursor::new(bytes),
            fail_at,
            kind: std::io::ErrorKind::UnexpectedEof,
        };
        let key = AesKey::new(FIXTURE_AES_KEY);
        let err = PakReader::from_reader_with_key(reader, key)
            .expect_err("EOF during index read must fail the open");
        assert!(
            matches!(err, PaksmithError::Decryption { .. }),
            "UnexpectedEof during the encrypted index read must map to Decryption (fail-closed); got {err:?}"
        );
    }

    /// #635 fail-closed: a WRONG key on the v11 encrypted index must
    /// surface as `Decryption` (garbage plaintext fails the primary-index
    /// parse), never as `UnsupportedFeature`, a panic, or garbage entries.
    #[test]
    fn open_encrypted_v11_index_with_wrong_key_is_decryption() {
        let mut wrong_bytes = FIXTURE_AES_KEY;
        wrong_bytes[0] ^= 0xFF;
        let wrong = AesKey::new(wrong_bytes);
        let err = PakReader::open_with_key(encrypted_v11_index_fixture(), wrong)
            .expect_err("wrong key must fail");
        assert!(
            matches!(err, PaksmithError::Decryption { .. }),
            "wrong key on a v11 encrypted index must fail closed as Decryption, got: {err:?}"
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

    // ── encrypted + COMPRESSED entries (issue #634) ────────────────────────

    /// UnrealPak-produced fixture whose entries are both zlib-compressed
    /// AND AES-256-ECB encrypted (plaintext index; same four-entry corpus
    /// and key as the encrypted-entries fixture). Vendored from repak's
    /// test suite — see tests/fixtures/PROVENANCE-encrypted.md.
    fn encrypted_compressed_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v8b_encrypted_compressed.pak")
    }

    /// v11 (encoded-index) sibling of [`encrypted_compressed_fixture`].
    fn encrypted_compressed_v11_fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/real_v11_encrypted_compressed.pak")
    }

    /// RED→GREEN oracle for decrypt-then-decompress (#634): `test.txt` in
    /// the encrypted+compressed fixture must round-trip to the same known
    /// plaintext as the uncompressed encrypted fixture (same source corpus,
    /// now behind AES over the zlib-compressed payload).
    #[test]
    fn reads_encrypted_compressed_entry_as_plaintext_test_txt() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_compressed_fixture(), key)
            .expect("open encrypted+compressed fixture");
        let bytes = reader
            .read_entry("test.txt")
            .expect("read_entry must decrypt-then-decompress test.txt");
        assert_eq!(
            bytes, FIXTURE_PLAINTEXT_TEST_TXT,
            "decrypt-then-decompress must recover the known plaintext"
        );
    }

    /// Second text entry, distinct plaintext — guards against a decode that
    /// happens to work for only one block shape.
    #[test]
    fn reads_encrypted_compressed_entry_nested_txt() {
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_compressed_fixture(), key)
            .expect("open encrypted+compressed fixture");
        let bytes = reader
            .read_entry("directory/nested.txt")
            .expect("read_entry must decrypt-then-decompress nested.txt");
        assert_eq!(bytes, FIXTURE_PLAINTEXT_NESTED_TXT);
    }

    /// Binary entries: zeros.bin must be exactly 2048 zero bytes; test.png
    /// must have its full length and the PNG magic.
    #[test]
    fn reads_encrypted_compressed_entry_binaries() {
        const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_compressed_fixture(), key)
            .expect("open encrypted+compressed fixture");

        let zeros = reader.read_entry("zeros.bin").expect("read zeros.bin");
        assert_eq!(zeros.len(), FIXTURE_ZEROS_BIN_LEN);
        assert!(zeros.iter().all(|&b| b == 0), "zeros.bin must be all zero");

        let png = reader.read_entry("test.png").expect("read test.png");
        assert_eq!(png.len(), FIXTURE_TEST_PNG_LEN);
        assert_eq!(&png[..8], &PNG_MAGIC);
    }

    /// The v11 sibling exercises the encoded-index generation end-to-end
    /// (bit-packed entries, no per-entry SHA1 in the index). `test.png`
    /// (not `test.txt`) is the target: in the v11 fixture only `test.png`
    /// and `zeros.bin` are genuinely encrypted+COMPRESSED — `test.txt`
    /// and `nested.txt` are stored encrypted-uncompressed, so they'd
    /// exercise the pre-existing uncompressed arm, not the new path.
    #[test]
    fn reads_encrypted_compressed_entry_v11() {
        const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::open_with_key(encrypted_compressed_v11_fixture(), key)
            .expect("open v11 encrypted+compressed fixture");
        let bytes = reader
            .read_entry("test.png")
            .expect("read_entry must decrypt-then-decompress on the encoded index");
        assert_eq!(bytes.len(), FIXTURE_TEST_PNG_LEN);
        assert_eq!(&bytes[..8], &PNG_MAGIC);
    }

    /// Pin the encrypted v10+ ENCODED verify outcome (R3 architect
    /// finding): removing the entry-level `SkippedEncrypted` short-circuit
    /// means the "no SHA1 on the wire" gate now runs first for encrypted
    /// encoded entries too, so a v11 encrypted entry reports
    /// `SkippedNoHash` (its true reason — encoded records omit the SHA1
    /// field regardless of encryption) rather than the retired
    /// `SkippedEncrypted`. Keyless open (plaintext index) suffices.
    #[test]
    fn verify_encrypted_v11_encoded_entry_is_skipped_no_hash() {
        let reader = PakReader::open(encrypted_compressed_v11_fixture())
            .expect("keyless open (plaintext index)");
        assert_eq!(
            reader.verify_entry("test.png").expect("verify must run"),
            VerifyOutcome::SkippedNoHash,
        );
    }

    /// Fail-closed: plaintext index → keyless open succeeds; reading an
    /// encrypted+compressed entry without a key must be `Decryption`, not
    /// `UnsupportedFeature` (the layout is supported now) and not garbage.
    #[test]
    fn encrypted_compressed_entry_without_key_returns_decryption_error() {
        let reader = PakReader::open(encrypted_compressed_fixture())
            .expect("open with plaintext index and no key must succeed");
        let err = reader
            .read_entry("test.txt")
            .expect_err("reading an encrypted+compressed entry without a key must fail");
        assert!(
            matches!(err, PaksmithError::Decryption { .. }),
            "must fail closed as Decryption, got: {err:?}"
        );
    }

    /// v8b flat-index pak with a SINGLE encrypted entry (#634), for
    /// in-source coverage of the decrypt-then-decompress read path.
    ///
    /// Duplicated (minimally) from `paksmith-core-tests`'s
    /// `build_single_entry_pak_with_flags` / `build_v8b_lz4_pak` ON PURPOSE:
    /// in-source tests can't reach the integration crate, and cargo-mutants
    /// runs only default-members (paksmith-core, `cargo test`), so a mutant on
    /// the encrypted read path (e.g. the `buffer_end` block-bounds ceiling in
    /// `stream_entry_to`) is killable ONLY by an in-source test. The footer
    /// carries one compression-name slot (`method_name`, resolved via the
    /// per-entry 1-based `method_index`; pass 0 for `None`-method entries,
    /// whose records omit the block table) and a PLAINTEXT index (footer
    /// encrypted byte = 0); the per-entry `is_encrypted` flag is set, so
    /// `from_reader_with_key` reads the index keylessly and `read_entry`
    /// decrypts the payload with the key. `payload` is the exact on-disk
    /// (already AES-encrypted, 16-aligned) entry bytes; `compressed_size` /
    /// `uncompressed_size` / `blocks` / `block_size` are written verbatim so
    /// a test can forge them (real encrypted `None` entries store the
    /// UNALIGNED size in both fields while the on-disk payload is padded).
    /// The per-entry SHA-1 is computed over `payload[..compressed_size]` —
    /// the wire convention — so keyless `verify_entry` works on the result.
    #[cfg(feature = "__test_utils")]
    #[allow(clippy::too_many_arguments)]
    fn build_v8b_encrypted_single_entry(
        method_index: u32,
        method_name: &str,
        payload: &[u8],
        compressed_size: u64,
        uncompressed_size: u64,
        blocks: &[(u64, u64)],
        block_size: u32,
    ) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        use sha1::{Digest, Sha1};

        use crate::testing::wire::{write_fstring, write_pak_entry};

        let hashed = usize::try_from(compressed_size)
            .ok()
            .filter(|&n| n <= payload.len())
            .expect("test builder: compressed_size must be <= payload.len()");
        let sha1: [u8; 20] = Sha1::digest(&payload[..hashed]).into();
        let write_entry = |buf: &mut Vec<u8>| {
            write_pak_entry(
                buf,
                0,
                compressed_size,
                uncompressed_size,
                method_index, // 1-based index → footer slot 0 = method_name; 0 = None
                &sha1,
                blocks,
                block_size,
                true, // per-entry encrypted
            );
        };

        let mut data = Vec::new();
        write_entry(&mut data);
        data.extend_from_slice(payload);

        let mut index = Vec::new();
        write_fstring(&mut index, "../../../");
        index.write_u32::<LittleEndian>(1).unwrap();
        write_fstring(&mut index, "Content/x.uasset");
        write_entry(&mut index);

        let index_offset = data.len() as u64;
        let index_size = index.len() as u64;
        let mut pak = data;
        pak.extend_from_slice(&index);

        pak.extend_from_slice(&[0u8; 16]); // encryption GUID
        pak.push(0); // index NOT encrypted (per-entry flag drives entry decryption)
        pak.write_u32::<LittleEndian>(crate::container::pak::version::PAK_MAGIC)
            .unwrap();
        pak.write_u32::<LittleEndian>(8).unwrap(); // v8b
        pak.write_u64::<LittleEndian>(index_offset).unwrap();
        pak.write_u64::<LittleEndian>(index_size).unwrap();
        pak.extend_from_slice(&[0u8; 20]); // index hash (zero = skip)
        let mut slot0 = [0u8; 32];
        let nb = method_name.as_bytes();
        slot0[..nb.len()].copy_from_slice(nb);
        pak.extend_from_slice(&slot0);
        pak.extend_from_slice(&[0u8; 32 * 4]); // slots 1..=4
        pak
    }

    /// #634 (R6/R7 architect): the encrypted+compressed read path passes
    /// `buffer_end = payload_start + decrypted.len()` (the decrypted-buffer
    /// extent) — NOT `self.file_size` — as the block-bounds ceiling into
    /// `validate_block_bounds`. A forged single-block `end` landing strictly
    /// BETWEEN `buffer_end` and the real `file_size` must reject as
    /// `BlockBoundsViolation { EndPastFileSize }`.
    ///
    /// IN-SOURCE (not `paksmith-core-tests`) on purpose: cargo-mutants runs
    /// only default-members, so the `buffer_end -> self.file_size` mutant on
    /// `stream_entry_to` is killable only here. Verified to kill it — under the
    /// wider `self.file_size` ceiling the forged block is accepted and the read
    /// surfaces `Io(UnexpectedEof)` over the short `RebasedReader` instead of
    /// the typed fault. A single-block entry suffices: the bounds check fires
    /// before any decrypt output is inflated, so no valid ciphertext is needed
    /// (16 arbitrary bytes decrypt to unused garbage).
    #[cfg(feature = "__test_utils")]
    #[test]
    fn read_encrypted_compressed_block_end_between_buffer_and_file_uses_buffer_ceiling() {
        // 16-byte (AES-aligned) payload; content irrelevant (never inflated).
        let payload = [0u8; 16];
        let payload_start = crate::testing::wire::pak_entry_wire_size(1); // one block
        let buffer_end = payload_start + payload.len() as u64;
        // Forge the block end 4 bytes past buffer_end — into the index region
        // that follows the payload, so it stays strictly < file_size.
        let forged_end = buffer_end + 4;
        let blocks = [(payload_start, forged_end)];

        let pak = build_v8b_encrypted_single_entry(1, "Zlib", &payload, 16, 16, &blocks, 16);
        let file_size = pak.len() as u64;
        assert!(
            buffer_end < forged_end && forged_end < file_size,
            "forged end {forged_end} must sit strictly in (buffer_end {buffer_end}, \
             file_size {file_size}) to discriminate the ceiling mutant"
        );

        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(pak), key)
            .expect("open v8b (plaintext index) with key");
        let err = reader
            .read_entry("Content/x.uasset")
            .expect_err("forged block end past the decrypted buffer must be rejected");
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BlockBoundsViolation {
                        kind: BlockBoundsKind::EndPastFileSize { .. },
                        ..
                    }
                }
            ),
            "must be EndPastFileSize (proves the buffer_end ceiling, not file_size); got: {err:?}"
        );
    }

    /// #634 (R7 architect finding 2): a single-block encrypted + LZ4 entry
    /// round-trips through the full decrypt-then-decompress read path. This is
    /// the only end-to-end coverage of encrypted+LZ4 (every vendored fixture is
    /// zlib), and LZ4 is in the #634 acceptance criteria. IN-SOURCE because
    /// `paksmith-core-tests` has no `aes` dev-dep to synthesize the ciphertext.
    /// No multi-block / #688 wire-convention dependency: a single block's
    /// `(start, end)` are read verbatim off the wire.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn reads_encrypted_lz4_entry_round_trips() {
        let plaintext: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let lz4 = lz4_flex::block::compress(&plaintext);
        let lz4_len = lz4.len() as u64;

        // On-disk payload = AES-encrypt(lz4 bytes, zero-padded to 16). For an
        // encrypted entry `compressed_size` is the 16-aligned footprint, while
        // the block spans the UNALIGNED lz4 bytes (repak/CUE4Parse: block end =
        // start + unaligned length; the cursor advances by the aligned length).
        let mut payload = lz4.clone();
        payload.resize(lz4.len().next_multiple_of(16), 0);
        let key = AesKey::new(FIXTURE_AES_KEY);
        crypto::aes256_ecb_encrypt(&key, &mut payload).expect("encrypt 16-aligned payload");

        let payload_start = crate::testing::wire::pak_entry_wire_size(1);
        let blocks = [(payload_start, payload_start + lz4_len)];
        let uncompressed_size = plaintext.len() as u64;
        let block_size = u32::try_from(plaintext.len()).expect("300 fits u32");
        let pak = build_v8b_encrypted_single_entry(
            1,
            "LZ4",
            &payload,
            payload.len() as u64,
            uncompressed_size,
            &blocks,
            block_size,
        );

        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(pak), key)
            .expect("open v8b (plaintext index) with key");
        let mut out = Vec::new();
        let written = reader
            .read_entry_to("Content/x.uasset", &mut out)
            .expect("encrypted+LZ4 entry must decrypt-then-decompress");
        assert_eq!(written, plaintext.len() as u64);
        assert_eq!(out, plaintext, "encrypted+LZ4 decode must be byte-exact");
    }

    /// #634 (R8 architect): a MULTI-BLOCK encrypted+compressed entry
    /// round-trips through decrypt → `RebasedReader` → per-block inflate. The
    /// single-block LZ4/zlib tests + fixtures never exercise the block loop
    /// walking 2+ blocks across the AES-aligned inter-block gaps inside the
    /// decrypted buffer — this pins that self-consistency (SEPARATE from the
    /// #688 question of whether the aligned-footprint convention matches a
    /// real UnrealPak multi-block archive, which stays deferred).
    ///
    /// Each non-final block decompresses to exactly `compression_block_size`;
    /// on disk each block's lz4 bytes occupy an AES-aligned footprint, so the
    /// block table's `(start, end)` spans the UNALIGNED lz4 length while the
    /// next block starts at the previous block's 16-aligned end.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn reads_encrypted_lz4_multi_block_round_trips() {
        let block_size = 128u32;
        // 2 full blocks + a 40-byte remainder → 3 blocks.
        let plaintext: Vec<u8> = (0..296u32).map(|i| (i % 251) as u8).collect();
        let chunks: Vec<Vec<u8>> = plaintext
            .chunks(block_size as usize)
            .map(lz4_flex::block::compress)
            .collect();
        assert_eq!(chunks.len(), 3, "fixture invariant: 2 full + 1 remainder");
        // Self-assert the discriminating property: at least one block's lz4
        // length is NOT 16-aligned, so its AES footprint carries real padding
        // that the next block's aligned start must skip over. Without this, an
        // all-16-aligned coincidence would make the block table's aligned
        // advances degenerate to the unaligned ones — masking the inter-block
        // gap walk (the R1 "16-aligned coincidence" mask class).
        assert!(
            chunks.iter().any(|c| c.len() % 16 != 0),
            "at least one block must be non-16-aligned to exercise the AES padding gap; got {:?}",
            chunks.iter().map(Vec::len).collect::<Vec<_>>()
        );

        // Lay each block's lz4 bytes at its AES-aligned footprint offset and
        // ECB-encrypt the whole contiguous region.
        let payload_start = crate::testing::wire::pak_entry_wire_size(chunks.len() as u64);
        let mut payload = Vec::new();
        let mut blocks: Vec<(u64, u64)> = Vec::new();
        let mut cursor = payload_start;
        for c in &chunks {
            blocks.push((cursor, cursor + c.len() as u64)); // end = UNALIGNED lz4 length
            payload.extend_from_slice(c);
            let footprint = c.len().next_multiple_of(16);
            payload.resize(payload.len() + (footprint - c.len()), 0); // pad to 16
            cursor += footprint as u64;
        }
        let key = AesKey::new(FIXTURE_AES_KEY);
        crypto::aes256_ecb_encrypt(&key, &mut payload)
            .expect("encrypt aligned multi-block payload");

        let pak = build_v8b_encrypted_single_entry(
            1,
            "LZ4",
            &payload,
            payload.len() as u64,
            plaintext.len() as u64,
            &blocks,
            block_size,
        );
        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(pak), key)
            .expect("open v8b (plaintext index) with key");
        let mut out = Vec::new();
        let written = reader
            .read_entry_to("Content/x.uasset", &mut out)
            .expect("multi-block encrypted+LZ4 must decrypt-then-decompress every block");
        assert_eq!(written, plaintext.len() as u64);
        assert_eq!(
            out, plaintext,
            "multi-block encrypted decode must be byte-exact across all 3 blocks"
        );
    }

    /// #689 R11 (found independently by three reviewers): END-TO-END pin of
    /// the split-size-fields gap for `None`-method encrypted entries. The
    /// READ path (`stream_uncompressed_to`) aligns `uncompressed_size`,
    /// while verify hashes/bounds `compressed_size` — and on inline v3-v9
    /// entries the two fields are independent wire values. A crafted entry
    /// whose compressed extents fit but whose `align16(uncompressed_size)`
    /// overshoots `file_size` (while passing the open-time 8 GiB cap, which
    /// is decoupled from `file_size`) must FAIL verify — not report
    /// `Verified` for an entry `read_entry` then rejects. Also the only
    /// end-to-end coverage of `verify_entry`'s aligned-extent wiring:
    /// deleting the `checked_encrypted_verify_extents` call makes the split
    /// pak verify as `Verified` and this test fail.
    #[cfg(feature = "__test_utils")]
    #[test]
    fn verify_encrypted_none_entry_rejects_split_size_fields() {
        // On-disk payload: 448 bytes (16-aligned); the true unaligned size
        // is 446 — the shape of every real encrypted uncompressed entry
        // (`real_v8b_encrypted_entries` test.txt: 446 stored, 448 on disk).
        let payload: Vec<u8> = (0..448u32).map(|i| (i % 251) as u8).collect();

        // Positive control: equal fields (what every real writer emits)
        // must verify keylessly — so the rejection below is attributable
        // to the field split alone, not some other defect in the pak.
        let pak = build_v8b_encrypted_single_entry(0, "", &payload, 446, 446, &[], 0);
        let reader = PakReader::from_bytes(pak).expect("keyless open (plaintext index)");
        assert_eq!(
            reader
                .verify_entry("Content/x.uasset")
                .expect("well-formed encrypted None entry verifies keylessly"),
            VerifyOutcome::Verified,
        );

        // Split fields: compressed extents fit (446 hashed / 448 on disk)
        // but align16(1_000_000) is far past file_size while still under
        // the open-time 8 GiB uncompressed cap.
        let pak = build_v8b_encrypted_single_entry(0, "", &payload, 446, 1_000_000, &[], 0);
        let reader = PakReader::from_bytes(pak).expect("keyless open (plaintext index)");
        let err = reader
            .verify_entry("Content/x.uasset")
            .expect_err("split size fields must fail verify, not report Verified");
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                        ..
                    }
                }
            ),
            "must reject on the aligned UNCOMPRESSED extent; got: {err:?}"
        );

        // The read path rejects the same pak the same way — the invariant
        // verify now guarantees (Verified ⟹ readable payload bounds),
        // shown from the other side.
        let pak = build_v8b_encrypted_single_entry(0, "", &payload, 446, 1_000_000, &[], 0);
        let key = AesKey::new(FIXTURE_AES_KEY);
        let reader = PakReader::from_reader_with_key(std::io::Cursor::new(pak), key)
            .expect("open v8b (plaintext index) with key");
        let read_err = reader
            .read_entry("Content/x.uasset")
            .expect_err("read must reject the oversized uncompressed extent");
        assert!(
            matches!(
                &read_err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize { .. }
                }
            ),
            "read rejects the same bounds; got: {read_err:?}"
        );
    }

    /// TODO(Task-4) resolution pin (#634): the stored entry SHA-1 covers the
    /// on-disk CIPHERTEXT `[payload_start, payload_start + compressed_size)`,
    /// including the intra-block AES padding. Every entry in the compressed
    /// fixture must verify keylessly — CRUCIALLY including `test.png`
    /// (compressed_size 7760 = aligned footprint), `nested.txt` (352), and
    /// `zeros.bin` (32), whose block sums are SHORTER than `compressed_size`.
    /// The per-block-walk hash (unaligned block ranges) would mis-hash these
    /// and only pass `test.txt`, whose 272-byte size is coincidentally
    /// 16-aligned — the R1 false-`HashMismatch` regression. Iterating all
    /// four entries makes that degenerate mask impossible.
    #[test]
    fn verify_encrypted_compressed_entries_hash_ciphertext_keylessly() {
        let reader = PakReader::open(encrypted_compressed_fixture())
            .expect("keyless open (plaintext index)");
        for path in ["test.txt", "directory/nested.txt", "zeros.bin", "test.png"] {
            let outcome = reader
                .verify_entry(path)
                .unwrap_or_else(|e| panic!("verify_entry({path}) must run keylessly: {e:?}"));
            assert_eq!(
                outcome,
                VerifyOutcome::Verified,
                "stored SHA1 covers the contiguous ciphertext, so keyless verify of \
                 {path} must pass (a block-walk hash would false-mismatch the \
                 non-16-aligned entries)"
            );
        }
    }

    /// #634 (R8 architect): end-to-end pin of the documented semantic change —
    /// `verify()` reports a fully-per-entry-encrypted archive as FULLY
    /// verified. Pre-#634 the entry-level encrypted skip forced
    /// `is_fully_verified()` to `false`; now the stored per-entry SHA-1 covers
    /// the on-disk ciphertext, so keyless verification of every (encrypted)
    /// entry plus the matching plaintext index hash suffices. The fixture's
    /// footer carries a real (non-zero) index hash, so this exercises the
    /// full `verify()` → `is_fully_verified()` composition, not just the
    /// per-entry arm.
    #[test]
    fn verify_encrypted_compressed_archive_is_fully_verified() {
        let reader = PakReader::open(encrypted_compressed_fixture())
            .expect("keyless open (plaintext index)");
        let stats = reader.verify().expect("verify must run keylessly");
        assert!(
            stats.is_fully_verified(),
            "a pristine fully-encrypted archive with a matching index hash and \
             all entries hashing keylessly must be fully verified: {stats:?}"
        );
    }

    /// Same pin for the UNCOMPRESSED encrypted class, where
    /// `compressed_size` (446) is not 16-aligned — passing requires hashing
    /// the TRUNCATED ciphertext, not the aligned read region.
    #[test]
    fn verify_encrypted_uncompressed_entry_hashes_truncated_ciphertext() {
        let reader =
            PakReader::open(encrypted_entries_fixture()).expect("keyless open (plaintext index)");
        let outcome = reader
            .verify_entry("test.txt")
            .expect("verify_entry must run keylessly on an encrypted entry");
        assert_eq!(outcome, VerifyOutcome::Verified);
    }

    /// `RebasedReader` (#634) maps absolute file offsets into the decrypted
    /// buffer and is the sole seek surface the block streamers drive over an
    /// encrypted entry. Directly pins its Start-only contract (R2 finding):
    /// `Start(abs)` rebases to `abs - base`, offsets below base and the
    /// `Current`/`End` variants fail closed, and an over-read EOFs — so a
    /// malformed block table never reads outside the payload.
    #[test]
    fn rebased_reader_maps_offsets_and_fails_closed() {
        use std::io::{Read, Seek, SeekFrom};
        let payload = b"0123456789ABCDEF"; // 16 bytes
        let base = 1000u64;
        let mut r = RebasedReader::new(payload, base);

        // Start(base) → buffer offset 0; the returned position is absolute.
        assert_eq!(r.seek(SeekFrom::Start(base)).unwrap(), base);
        let mut four = [0u8; 4];
        r.read_exact(&mut four).unwrap();
        assert_eq!(&four, b"0123");

        // Start(base + k) → buffer offset k.
        assert_eq!(r.seek(SeekFrom::Start(base + 10)).unwrap(), base + 10);
        let mut two = [0u8; 2];
        r.read_exact(&mut two).unwrap();
        assert_eq!(&two, b"AB");

        // Below base, and the non-Start variants, all fail closed.
        for pos in [
            SeekFrom::Start(base - 1),
            SeekFrom::Current(0),
            SeekFrom::End(0),
        ] {
            assert_eq!(
                r.seek(pos).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput,
                "{pos:?} must be rejected"
            );
        }

        // A read past the payload end EOFs rather than reading OOB.
        let _ = r.seek(SeekFrom::Start(base + 14)).unwrap();
        let mut over = [0u8; 4];
        assert_eq!(
            r.read_exact(&mut over).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
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

    /// `read_decrypted_compressed_payload`'s compressed-size cap (#634): an
    /// inline encrypted+compressed entry whose `compressed_size` exceeds
    /// `MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) must be rejected as
    /// `BoundsExceeded` on `CompressedSize` BEFORE any I/O. The v3-v9 inline
    /// index applies no parse-time cap on `compressed_size` (unlike the v10+
    /// encoded parser at `entry_header.rs`), so this free-function check is
    /// the only enforcement point for inline entries. The cap runs first in
    /// the body, ahead of every seek/read/decrypt, so an empty in-memory
    /// `Cursor` suffices — no multi-GiB file is required.
    ///
    /// Kills the delete-cap-body mutant: with the check gone, `comp = MAX+1`
    /// would flow to `checked_payload_end` and surface as `OffsetPastFileSize`
    /// (the tiny `file_size`), not `BoundsExceeded`, failing this assertion.
    #[test]
    fn read_decrypted_compressed_payload_over_cap_is_bounds_exceeded() {
        use std::io::Cursor;

        // `inline_for_test` sets `compressed_size == uncompressed_size`, so
        // `MAX + 1` yields a `compressed_size` exactly one byte over the cap.
        let header = PakEntryHeader::inline_for_test(MAX_UNCOMPRESSED_ENTRY_BYTES + 1, true);
        let entry = PakIndexEntry::for_test("over_cap.bin".to_string(), header);
        let key = AesKey::new(FIXTURE_AES_KEY);

        let mut file = Cursor::new(Vec::<u8>::new());
        let err = read_decrypted_compressed_payload(&mut file, &entry, 100, 0, &key)
            .expect_err("compressed_size past the 8 GiB cap must be rejected before any read");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: WireField::CompressedSize,
                        ..
                    }
                }
            ),
            "must reject as BoundsExceeded on CompressedSize; got: {err:?}"
        );
    }

    /// Boundary sibling of the over-cap test: a `compressed_size` EXACTLY at
    /// `MAX_UNCOMPRESSED_ENTRY_BYTES` must PASS the cap (strict `>`).
    ///
    /// Tests `ensure_compressed_size_within_cap` DIRECTLY — not through
    /// `read_decrypted_compressed_payload` — precisely so a
    /// `checked_payload_end` mutant that bypasses the downstream EOF guard
    /// can't make this at-cap case allocate the full 8 GiB and time the whole
    /// mutation run out. The over-cap sibling still exercises the in-path call
    /// (comp = MAX+1 is rejected before any allocation), so the call site stays
    /// covered.
    ///
    /// Kills the `>`→`>=` mutant on `comp > MAX_UNCOMPRESSED_ENTRY_BYTES`:
    /// under `>=`, `comp == cap` returns `BoundsExceeded`, which `Ok(())`
    /// forbids.
    #[test]
    fn ensure_compressed_size_at_cap_is_accepted() {
        ensure_compressed_size_within_cap(MAX_UNCOMPRESSED_ENTRY_BYTES, "at_cap.bin")
            .expect("comp == MAX_UNCOMPRESSED_ENTRY_BYTES must pass the cap (strict `>`)");
    }

    /// `checked_aligned_payload_len` (#689 Copilot finding): an encrypted
    /// payload whose UNALIGNED `size` fits within `file_size` but whose
    /// 16-aligned extent overshoots must be rejected — this is the exact
    /// gap where `verify_entry` used to report `Verified` for a crafted
    /// pak that `read_entry` then fails to read. Numbers mirror the real
    /// v8b `test.txt` (446 stored / 448 aligned): with `file_size == 446`
    /// the truncated hash range fits but the padding is missing.
    #[test]
    fn aligned_payload_len_rejects_missing_padding() {
        let err = checked_aligned_payload_len(0, 446, 446, "test.txt")
            .expect_err("aligned extent (448) past file_size (446) must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        kind: OffsetPastFileSizeKind::PayloadEndBounds {
                            payload_end: 448,
                            file_size_max: 446,
                        },
                        ..
                    }
                }
            ),
            "must reject as PayloadEndBounds on the ALIGNED end; got: {err:?}"
        );
    }

    /// Boundary sibling: with the padding present (`file_size == 448`) the
    /// same payload passes, and the returned length is the aligned 448 —
    /// pinning the `div_ceil(16) * 16` math. A mutant degenerating
    /// `aligned` to `size` would wrongly ACCEPT the truncated input,
    /// failing the rejection test above (which catches it); one inflating
    /// `aligned` would wrongly reject the padded input, failing this test.
    #[test]
    fn aligned_payload_len_with_padding_present_is_ok() {
        let aligned = checked_aligned_payload_len(0, 446, 448, "test.txt")
            .expect("exact aligned fit must be accepted");
        assert_eq!(aligned, 448, "must return the 16-aligned extent");
        // Already-aligned size: aligned == size, no padding required.
        let exact = checked_aligned_payload_len(0, 32, 32, "zeros.bin")
            .expect("16-aligned size needs no padding slack");
        assert_eq!(exact, 32);
    }

    /// #689 R11 security finding: for a `None`-method (uncompressed)
    /// encrypted entry the READ path aligns `uncompressed_size`, and on
    /// inline v3-v9 entries the two size fields are independent wire
    /// values — so verify must bounds-check `align16(uncompressed_size)`
    /// too, or a split-fields crafted entry (compressed extent fits,
    /// uncompressed extent overshoots) verifies but cannot be read.
    /// Numbers mirror the reviewer's exploit: comp = 432 (16-aligned,
    /// fits in the 448-byte budget), uncomp = 460 (aligns to 464 > 448).
    #[test]
    fn encrypted_verify_extents_reject_split_fields_for_uncompressed_method() {
        let err = checked_encrypted_verify_extents(0, 432, 460, true, 448, "split.bin")
            .expect_err("uncompressed read extent (464) past file_size (448) must be rejected");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::OffsetPastFileSize {
                        kind: OffsetPastFileSizeKind::PayloadEndBounds {
                            payload_end: 464,
                            file_size_max: 448,
                        },
                        ..
                    }
                }
            ),
            "must reject on the aligned UNCOMPRESSED extent; got: {err:?}"
        );
    }

    /// Guard-inversion sibling: for COMPRESSED methods the read path
    /// consumes `align16(compressed_size)` and never touches
    /// `uncompressed_size` as an on-disk extent — the same split fields
    /// must PASS when the method is not `None`. Kills the
    /// `is_uncompressed_method` guard->true mutant (which would wrongly
    /// apply the uncompressed check to compressed entries), while the
    /// rejection test above kills guard->false.
    #[test]
    fn encrypted_verify_extents_ignore_uncompressed_field_for_compressed_methods() {
        checked_encrypted_verify_extents(0, 432, 460, false, 448, "split.bin")
            .expect("compressed-method extents must ignore the uncompressed field");
    }

    /// Real-archive shape: equal fields (every genuine `None`-method
    /// encrypted entry) pass under both method classes with the padding
    /// present.
    #[test]
    fn encrypted_verify_extents_equal_fields_are_ok() {
        checked_encrypted_verify_extents(0, 446, 446, true, 448, "test.txt")
            .expect("equal fields with padding present must verify (uncompressed)");
        checked_encrypted_verify_extents(0, 446, 446, false, 448, "test.txt")
            .expect("equal fields with padding present must verify (compressed)");
    }

    /// Overflow guard: a `size` near `u64::MAX` overflows the align-up
    /// multiply and must surface as the typed `U64ArithmeticOverflow`,
    /// not a panic or wraparound.
    #[test]
    fn aligned_payload_len_overflow_is_typed() {
        let err = checked_aligned_payload_len(0, u64::MAX, u64::MAX, "huge.bin")
            .expect_err("align-up of u64::MAX must overflow");
        assert!(
            matches!(
                err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        operation: OverflowSite::PayloadEnd,
                        ..
                    }
                }
            ),
            "must be a typed overflow fault; got: {err:?}"
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
