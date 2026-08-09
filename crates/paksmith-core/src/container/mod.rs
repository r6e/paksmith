//! Archive container readers.
//!
//! The `.pak` reader (see [`pak`]) implements [`ContainerReader`]. The
//! [`ContainerFormat::IoStore`] variant reserves the API surface for the
//! Phase 8 IoStore reader; no [`ContainerReader`] implementor exists for
//! it yet. [`open`] is the container-agnostic entry point — it returns
//! `Arc<dyn ContainerReader>` so callers never name a concrete reader
//! type.

pub mod pak;

use std::io::Write;

use serde::Serialize;

/// Supported archive container formats.
///
/// Marked `#[non_exhaustive]` for forward-compat — the Phase 8 IoStore
/// implementation will turn `IoStore` from a name-only variant into a
/// fully-supported reader, and future container kinds (e.g. raw uasset
/// directories) can be added without breaking external `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum ContainerFormat {
    /// Unreal Engine `.pak` archive.
    Pak,
    /// Unreal Engine I/O Store (`.utoc`/`.ucas`).
    IoStore,
}

/// Boolean flags for an [`EntryMetadata`]. Grouped into a struct so
/// `EntryMetadata::new`'s call sites can't accidentally swap the
/// `compressed`/`encrypted` arguments — both are bool, both adjacent,
/// the swap would compile silently. Named-field construction at the
/// call site spells out which flag is which.
///
/// Marked `#[non_exhaustive]` so future flags (e.g., a `delete_record`
/// boolean for v6+ archives, or `aes256` once UE adopts it) can be
/// added without breaking external `ContainerReader` implementors.
///
/// **No `new(compressed, encrypted)` constructor on purpose**: a
/// positional two-bool constructor would re-introduce the very
/// swap risk this type exists to prevent. In-crate callers
/// construct via named-field struct literals (allowed because
/// `#[non_exhaustive]` only blocks struct literals from *outside*
/// the crate). External `ContainerReader` implementors should use
/// [`Self::NONE`] + the [`Self::compressed`] / [`Self::encrypted`]
/// builder methods so each flag is labeled at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryFlags {
    /// True iff the entry's payload is compressed on disk.
    /// Implementors derive this from their format's compression method
    /// (e.g. pak: `method != CompressionMethod::None`) — it's a
    /// computed property of the wire shape, not a header flag.
    pub compressed: bool,
    /// True iff the entry is AES-encrypted on disk.
    pub encrypted: bool,
}

impl EntryFlags {
    /// All flags false — the builder-pattern base for external
    /// `ContainerReader` implementors who can't use struct literals
    /// (`#[non_exhaustive]` blocks them from outside the crate).
    /// Chain [`Self::compressed`] / [`Self::encrypted`] to label each
    /// flag at the call site.
    pub const NONE: Self = Self {
        compressed: false,
        encrypted: false,
    };

    /// Mark `compressed = true`, returning `self` for chaining. The
    /// zero-arg form defeats the positional-bool swap (`with(true,
    /// false)` vs `with(false, true)`) that motivated `EntryFlags`
    /// itself. For conditional setting, use `if cond {
    /// flags.compressed() } else { flags }`.
    #[must_use]
    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Mark `encrypted = true`. See [`Self::compressed`] for the
    /// rationale.
    #[must_use]
    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }
}

/// What an entry's stored SHA-1 field claims (#662) — the classification
/// of `EntryMetadata`'s stored SHA-1 field once the archive-level
/// [`ContainerReader::claims_integrity`] bit disambiguates a zeroed
/// field. Produced by [`ContainerReader::entry_integrity`]; mirrors the states
/// `PakReader::verify_entry` distinguishes before it hashes anything.
///
/// Carries the digest itself, not formatted text: consumers that display
/// it format on demand (`Display for Sha1Digest` is lowercase hex), so
/// holding one of these per entry costs no heap.
///
/// Deliberately NOT `#[non_exhaustive]`, unlike its module siblings: the
/// four states enumerate what the wire can say (no field / zeroed /
/// real) once the archive-level bit is applied — the bit only splits
/// the zeroed case, since an absent field and a real digest mean the
/// same thing either way. That is a closed set, not an open one. Exhaustive
/// matching is the safety property — a fifth state must break every
/// consumer at compile time rather than fall into a catch-all that
/// shows the wrong prose about an integrity claim. Consumers MAY fold
/// states deliberately (`verify_region` gives `NoClaim` and
/// `NotInIndex` one arm, since a fixed-width region slot cannot be
/// absent); what the missing attribute buys is that folding must be
/// written down, not inherited from a wildcard.
///
/// SCOPE: `Claim` carries a [`Sha1Digest`](crate::digest::Sha1Digest)
/// because that is the digest the metadata surface exposes
/// (`EntryMetadata`'s stored SHA-1 field) and the one pak records.
/// Whether a second container fits depends on the container: per
/// `docs/formats/container/iostore-utoc.md`, IoStore's
/// `FIoStoreTocEntryMeta.ChunkHash` is an `FSHAHash` (20 bytes, SHA-1)
/// from TOC v8 — which WOULD fit — but an `FIoChunkHash` (32 bytes)
/// below it, which would not. A reader needing the wider form forces a
/// breaking change to this enum; that is accepted deliberately while
/// the crate is pre-1.0, unpublished, and pak is the only implemented
/// reader. Generalizing to an algorithm-agnostic digest before a second
/// reader exists would be designing against a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryIntegrity {
    /// The reader reported no stored hash for this entry —
    /// [`EntryMetadata`]'s SHA-1 field is unset. (In pak that is the
    /// v10+ bit-packed index record, which carries no hash field at
    /// all; the entry's in-data record still stores one. Other
    /// containers may have their own hash-less record forms.)
    ///
    /// This states what the READER declared, not what the wire holds:
    /// an unset field is indistinguishable from a hash-less encoding,
    /// so a reader whose format DOES record a per-entry hash must call
    /// [`EntryMetadata::with_sha1`]. Omitting it makes every one of
    /// that reader's entries read as hash-less, here and in any UI
    /// downstream.
    NotInIndex,
    /// The field is all zeros AND the archive-level bit says no claim
    /// either — nothing to check (verify: `SkippedNoHash`). Scoped to
    /// those two facts: it does not certify that the archive was written
    /// without integrity, only that neither field carries a claim now.
    NoClaim,
    /// The field is all zeros in an archive that DOES claim integrity
    /// (verify: `IntegrityStripped`). This is what an integrity STRIP
    /// looks like — someone zeroed a hash and recomputed the archive's
    /// own — but the state is the OBSERVATION, not the verdict, and
    /// nothing here establishes that a strip is the only way to reach
    /// it. Display surfaces must report the two fields and let the
    /// reader judge; only a consumer that knows the archive's
    /// provenance can call it tampering.
    Stripped,
    /// A real stored claim. UNVERIFIED: this is what the archive says,
    /// not a checked result — verifying means reading and hashing the
    /// entry (`PakReader::verify_entry`).
    ///
    /// The digest covers the entry's ON-DISK bytes (ciphertext when
    /// encrypted, compressed blocks when compressed), so it equals the
    /// EXTRACTED file's digest only for plain stored entries — display
    /// surfaces must say so rather than invite a `sha1sum` comparison.
    ///
    /// Those bytes are the PAYLOAD, which for pak begins after the
    /// duplicated header the entry's offset points at — the hashed
    /// range and [`EntryMetadata::offset`] do not share a start. A
    /// surface showing both should not imply the digest covers bytes
    /// from that offset onward.
    Claim(crate::digest::Sha1Digest),
}

/// Classify a stored SHA-1 field against the archive-level integrity
/// bit — the ONE implementation of the policy (#662).
///
/// Consumed by the display path ([`ContainerReader::entry_integrity`],
/// whose default body is a direct call) and by BOTH per-slot verify
/// paths in the pak reader — `verify_entry` and `verify_region`
/// (FDI/PHI) — each mapping the states onto `SkippedNoHash` /
/// `IntegrityStripped` / hash-and-compare. Keeping one function means
/// the Info pane can never label an entry benign while `verify` calls
/// the same bytes a strip, or vice versa.
///
/// The footer's own `index_hash` is the one zero-check that does NOT
/// route through here (`verify_main_index_region`): it is the INPUT
/// that defines `archive_claims_integrity`, so classifying it against
/// itself would be circular — a zero footer hash means the archive
/// makes no claim, which is the `SkippedNoHash` that site already
/// returns, and `Stripped` is unreachable for it by construction.
pub(crate) fn classify_sha1_claim(
    sha1: Option<crate::digest::Sha1Digest>,
    archive_claims_integrity: bool,
) -> EntryIntegrity {
    match sha1 {
        None => EntryIntegrity::NotInIndex,
        Some(d) if d == crate::digest::Sha1Digest::ZERO => {
            if archive_claims_integrity {
                EntryIntegrity::Stripped
            } else {
                EntryIntegrity::NoClaim
            }
        }
        Some(d) => EntryIntegrity::Claim(d),
    }
}

/// Metadata for a single entry within a container archive.
///
/// Constructed by [`ContainerReader`] implementors (typically inside
/// `entries()`) via [`Self::new`]. External readers access fields via
/// the named accessors below, not by struct-literal destructuring —
/// the struct is `#[non_exhaustive]` so future container formats
/// (iostore, future pak versions) can add fields (e.g.
/// `format_hint: Option<AssetKind>`, `mount_relative_path: String`)
/// without breaking downstream consumers.
///
/// Fields are `pub(crate)` to reserve the right to change internal
/// representation (e.g., interning paths, packing booleans into a
/// bitset) without an API break. The accessors are the stable surface,
/// with one deliberate exception: the stored SHA-1 has a `pub` builder
/// but a `pub(crate)` reader, because the classified form
/// ([`ContainerReader::entry_integrity`]) is the one external consumers
/// should see. An implementor sets it; only this crate reads it raw.
///
/// **Implementor-facing trade-off**: the `#[non_exhaustive]` marker
/// pushes the breaking-change surface from struct-literal construction
/// into [`Self::new`]'s arity. Adding a parameter to `new` is itself
/// a breaking change for every external `ContainerReader` impl — if
/// this seam grows past ~6 args, prefer migrating to a builder
/// (preserves arg-name stability across additions).
///
/// **Implementors must do two things**: call [`Self::new`] with the
/// four values every container has, then chain a `with_*` builder for
/// each OPTIONAL detail the format can supply — [`Self::with_offset`],
/// [`Self::with_compression_method`], [`Self::with_sha1`]. Details the
/// format genuinely lacks are correctly left unset.
///
/// Omission is not uniformly harmless, and the stakes differ by field.
/// Skipping `with_offset` or `with_compression_method` costs a display
/// surface some information — a dash where a value would be. Skipping
/// `with_sha1` makes a CLAIM: absent means
/// [`EntryIntegrity::NotInIndex`], which consumers state as fact ("the
/// index record carries no hash field"). Leave that one out only when
/// it is TRUE of the format, not because the value was inconvenient to
/// plumb.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EntryMetadata {
    pub(crate) path: String,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) is_compressed: bool,
    pub(crate) is_encrypted: bool,
    pub(crate) offset: Option<u64>,
    pub(crate) compression_method: Option<std::sync::Arc<str>>,
    pub(crate) sha1: Option<crate::digest::Sha1Digest>,
}

impl EntryMetadata {
    /// Construct an `EntryMetadata`. Used by [`ContainerReader`]
    /// implementors yielding entries from their `entries()` iterator.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from
    /// outside this crate, so external trait implementors MUST go
    /// through this constructor.
    ///
    /// Flags are grouped into [`EntryFlags`] (named-field struct)
    /// rather than two adjacent positional bools — the call site
    /// then reads `EntryFlags { compressed: ..., encrypted: ... }`,
    /// making argument-order swaps a compile error rather than a
    /// silent semantic bug.
    ///
    /// Takes only the values EVERY container has. The optional details
    /// — offset, compression-method name, stored SHA-1 — default to
    /// `None` here and are supplied by chaining [`Self::with_offset`],
    /// [`Self::with_compression_method`] and [`Self::with_sha1`]. An
    /// implementor that stops at `new` leaves all three unset — which
    /// for the SHA-1 in particular publishes "this format's index has no
    /// such field", a claim display surfaces state as fact; see the
    /// struct doc.
    pub fn new(
        path: String,
        compressed_size: u64,
        uncompressed_size: u64,
        flags: EntryFlags,
    ) -> Self {
        Self {
            path,
            compressed_size,
            uncompressed_size,
            is_compressed: flags.compressed,
            is_encrypted: flags.encrypted,
            offset: None,
            compression_method: None,
            sha1: None,
        }
    }

    /// Record the file offset of the entry's on-disk RECORD within the
    /// container (#662).
    ///
    /// The rule for an implementor: this is the offset the container's
    /// own index publishes for the entry — the address a reader seeks to
    /// in order to reach it — NOT a derived payload start. Where a
    /// format prefixes an entry's payload with a per-entry header (pak
    /// duplicates the entry header there), this points at that header
    /// and the first payload byte is further in. (Whether a format's
    /// deletion records — pak has them from v6 — carry a payload or a
    /// header copy is format-specific and, for pak, unestablished; see
    /// issue #742.) If a format's index
    /// addresses payload bytes directly, the two coincide; report what
    /// the index says either way, so a consumer comparing this against a
    /// hex dump of the archive finds the record where it was told. Builder-style so [`Self::new`]'s arity stays
    /// put — each detail is optional and self-naming. The struct doc's
    /// note prescribed migrating `new` ITSELF to a builder once its
    /// arity grew; keeping the four universal values positional and
    /// taking only the optional details this way holds `new` below that
    /// threshold instead of crossing it, which is the same arg-name
    /// stability the note was protecting.
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Record the compression method's display name (#662). Call only for
    /// compressed entries — the name is container-specific prose, not an
    /// enum, so the generic surface stays free of pak-only types.
    ///
    /// "Display name" does NOT promise a short identifier. It is usually
    /// one (`"Zlib"`, `"Oodle"`), but a container that cannot name the
    /// method may render a whole phrase — pak yields
    /// `unknown (id/slot 7)` for an unrecognized id and the
    /// Debug-escaped `unknown ("LZMA")` for an unrecognized FName, the
    /// escaping being a security control (see `CompressionMethod::
    /// display_name`). Consumers that compose it into a larger string
    /// must expect embedded parentheses and quotes.
    ///
    /// Takes a shared `Arc<str>` so a reader can INTERN the names it can
    /// bound and hand every entry a pointer to the same bytes, and a
    /// consumer retaining the value per entry inherits that sharing
    /// instead of duplicating a hostile name a million times.
    ///
    /// The bound is the READER's to establish and it is not automatic:
    /// pak interns the names its footer table can enumerate, but NOT
    /// its `Unknown(id)` rendering, whose number comes from each
    /// entry's own field — interning an unbounded namespace would grow
    /// a pool with the archive rather than shrink it.
    #[must_use]
    pub fn with_compression_method(mut self, method: impl Into<std::sync::Arc<str>>) -> Self {
        self.compression_method = Some(method.into());
        self
    }

    /// Record the entry's stored SHA-1 field VERBATIM (#662) — exactly
    /// what the reader's index carries, all-zero values included. On pak,
    /// what a zeroed slot MEANS depends on the archive-level bit
    /// ([`ContainerReader::claims_integrity`]): the strip-shaped state
    /// (see [`EntryIntegrity::Stripped`] for what else wears it) in an
    /// integrity-claiming archive, an ordinary "no claim" otherwise — so
    /// readers must NOT filter it away here. Skip the call only when the
    /// reader's index record carries no hash field at all (pak v10+
    /// bit-packed index records; the entry's in-data record still stores
    /// one, but this surface reports what the index declares).
    #[must_use]
    pub fn with_sha1(mut self, sha1: crate::digest::Sha1Digest) -> Self {
        self.sha1 = Some(sha1);
        self
    }

    /// Take the entry's path, consuming the metadata.
    ///
    /// For consumers that RETAIN the path and discard the rest — the
    /// CLI narrows each entry to the fields it prints (#662) — this
    /// moves the `String` the reader already allocated instead of
    /// paying a second allocation and copy per entry. Use [`Self::path`]
    /// when the value is still needed afterwards.
    #[must_use]
    pub fn into_path(self) -> String {
        self.path
    }

    /// Virtual path of the entry within the archive.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Compressed size in bytes (equals [`Self::uncompressed_size`] when
    /// the entry is stored uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Uncompressed size in bytes — the size the entry occupies when
    /// extracted.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// True iff the entry is stored compressed (any non-None
    /// compression method).
    pub fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    /// File offset of the entry's on-disk RECORD within the container,
    /// when the reader recorded one (#662). For a pak entry with a
    /// payload this is where the duplicated entry header starts — the
    /// payload follows that header copy, so this is NOT the first
    /// payload byte. (Whether a v6+ delete record has either is
    /// unestablished, and `entries()` does not filter such records out;
    /// see issue #742 and [`Self::with_offset`].)
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Display name of the compression method, when the entry is
    /// compressed and the reader recorded one (#662).
    ///
    /// The `_shared` suffix names what the caller gets: a handle to the
    /// bytes the reader already holds, not a copy. Retaining one per
    /// entry (the GUI's entry map) costs a refcount bump where
    /// `map(String::from)` would copy; reading one in passing is
    /// `.as_deref()`.
    ///
    /// Sharing is NOT guaranteed: it is exactly as good as the
    /// implementor's interning, and pak deliberately excludes its
    /// `Unknown(id)` rendering (the id is the entry's own wire field,
    /// so pooling it would be unbounded). A consumer sizing a memory
    /// budget from this method must budget one allocation per entry for
    /// that class — an archive whose entries all name one unrecognized
    /// method id pays per entry, not once. See
    /// [`Self::with_compression_method`].
    #[must_use]
    pub fn compression_method_shared(&self) -> Option<std::sync::Arc<str>> {
        self.compression_method.clone()
    }

    /// The entry's stored SHA-1 field VERBATIM, when the reader's index
    /// carries one (#662).
    ///
    /// `pub(crate)`: on THIS generic surface the public route is
    /// [`ContainerReader::entry_integrity`], which returns the same
    /// digest inside [`EntryIntegrity::Claim`] once the archive-level
    /// bit has ruled out the zeroed states. A public raw accessor here
    /// would invite the flattening this design exists to discourage — a
    /// caller emitting forty zeros as a fact for an entry whose hash was
    /// stripped.
    ///
    /// It does NOT seal that off: `PakReader::index_entry` ->
    /// `PakIndexEntry::header` -> `PakEntryHeader::sha1` is an unchanged
    /// public pak-specific route to the same raw `Option<Sha1Digest>`.
    /// What `pub(crate)` buys is that the CONTAINER-GENERIC
    /// surface — the one a second reader and its consumers are built
    /// against — offers the classified form first. Widening this later
    /// is not a breaking change; narrowing it after publish would be. `None` means the INDEX record has no hash
    /// field (pak v10+ bit-packed index; the entry's in-data record still
    /// stores one — this surface reports what the index declares). An
    /// all-zero value is passed through, not filtered: what it means
    /// depends on [`ContainerReader::claims_integrity`], so prefer
    /// [`ContainerReader::entry_integrity`] over reading this raw field
    /// when the question is "what does this entry claim?".
    pub(crate) fn sha1(&self) -> Option<crate::digest::Sha1Digest> {
        self.sha1
    }

    /// True iff the entry is AES-encrypted on disk.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }
}

/// Trait for reading archive containers regardless of format.
///
/// Designed for object safety (`dyn ContainerReader` works) so that
/// future format dispatch (Pak vs IoStore) can be done dynamically.
/// That's why [`Self::entries`] returns a boxed iterator rather than
/// `impl Iterator` — `impl Trait` in trait return position would
/// disqualify the trait from being `dyn`-compatible.
pub trait ContainerReader: Send + Sync {
    /// Iterator over the archive's entries.
    ///
    /// **NOT lazy in the wire-parsing sense.** The full entries vector
    /// has already been parsed into the in-memory index by the time
    /// the implementor returns — what's lazy here is the construction
    /// of the per-call [`EntryMetadata`] (each `next()` allocates a
    /// fresh `String` for the `path` field). For an N-entry archive,
    /// iterating yields N owned [`EntryMetadata`] values and pays N
    /// heap allocations for the paths. The `compression_method` name
    /// adds allocations only as the implementor's interning allows: an
    /// implementor that interns (pak does) pays one per DISTINCT name it
    /// can bound — a handful — and one per entry only for names it
    /// cannot bound, such as pak's per-entry unrecognized method ids.
    /// Any such pool is scoped to ONE CALL of this method: two
    /// iterations of the same reader may hand out equal-but-distinct
    /// `Arc`s, so callers must compare names by value, never by pointer
    /// identity. See [`EntryMetadata::with_compression_method`].
    ///
    /// Each value is ~100 bytes plus its path. Callers that RETAIN one
    /// per entry for a multi-million-entry archive should consume this
    /// iterator streaming-fashion (build the derived structure as
    /// entries arrive) rather than collecting it first.
    ///
    /// For a workload that scans for one entry by path, prefer the
    /// implementor's `find` shortcut (e.g.
    /// [`crate::container::pak::PakReader::index_entry`]) over
    /// filtering this iterator — direct lookup is O(1) and
    /// allocation-free.
    ///
    /// The boxed iterator is the cost of keeping the trait
    /// object-safe; callers that need a borrowed-`&str` iterator must
    /// reach through the concrete reader type.
    ///
    /// The `+ Send` bound matches the trait-level `: Send + Sync`
    /// promise. Without it, the iterator escape hatch would silently
    /// break the trait's thread-safety guarantee: callers couldn't
    /// move it across thread boundaries even though the parent
    /// reader they got it from is `Send`.
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + Send + '_>;

    /// Stream a single entry's decompressed bytes to `writer`. Returns the
    /// number of bytes written.
    ///
    /// This is the streaming primitive — it never materializes the full
    /// payload in memory, so multi-GiB cooked content is handled in
    /// bounded scratch buffers. See [`Self::read_entry`] for the
    /// convenience wrapper that collects to a `Vec<u8>`.
    ///
    /// The `EntryNotFound` error-identity contract documented on
    /// [`Self::read_entry`] applies here identically.
    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> crate::Result<u64>;

    /// Read raw bytes for a specific entry by path into an owned `Vec<u8>`.
    ///
    /// **Required, not defaulted, for safety.** A naïve default that just
    /// did `let mut v = Vec::new(); self.read_entry_to(path, &mut v)?;
    /// Ok(v)` would let `Vec` grow unboundedly during the streaming write
    /// — a malformed archive claiming a multi-GiB `uncompressed_size` on
    /// a memory-constrained host could trip the allocator's abort path
    /// before any typed error surfaces. Each implementor must provide
    /// its own collector that fallibly reserves the entry size upfront
    /// (typically via `Vec::try_reserve_exact`) so OOM becomes a
    /// recoverable typed error rather than a process kill.
    ///
    /// See `paksmith_core::container::pak::PakReader::read_entry` for
    /// the canonical implementation.
    ///
    /// # Error identity contract
    ///
    /// A `path` not present in the archive MUST surface as
    /// [`crate::PaksmithError::EntryNotFound`] — never a generic `Io`
    /// error. Generic consumers distinguish "no such entry" from "read
    /// failed" solely on this identity: `Package::read_from_reader`
    /// treats `EntryNotFound` on the `.uexp` companion as "monolithic
    /// asset, keep going" and maps it on `.ubulk`/`.uptnl` to the typed
    /// `MissingCompanionFile` fault, while any other error aborts the
    /// parse outright. An implementor that leaks `Io(NotFound)` instead
    /// would turn every monolithic asset into a hard parse failure.
    fn read_entry(&self, path: &str) -> crate::Result<Vec<u8>>;

    /// The container format this reader handles.
    fn format(&self) -> ContainerFormat;

    /// The virtual mount point for paths in this archive.
    fn mount_point(&self) -> &str;

    /// Whether the archive records an ARCHIVE-LEVEL integrity claim
    /// (#662) — one bit, not a survey: pak answers it from the footer's
    /// `index_hash` alone and does not consult the v10+ FDI/PHI region
    /// hashes, which `verify_region` checks separately. It is the bit
    /// that disambiguates a zeroed per-entry hash from
    /// `EntryMetadata`'s stored SHA-1 field: in an integrity-claiming archive a zero
    /// slot is the strip-shaped state (the verify path's
    /// `IntegrityStripped`; [`EntryIntegrity::Stripped`] scopes it),
    /// while in an archive that records none it is the ordinary "no claim"
    /// case (`SkippedNoHash`). Defaulted to `false` so a container that
    /// doesn't override it can never trigger a false tampering
    /// accusation — but note the trade: consumers render that default as
    /// a positive "no integrity claims recorded", so an implementor whose
    /// format DOES carry an archive-level claim must override this or its
    /// entries' zeroed hashes will read as benign.
    fn claims_integrity(&self) -> bool {
        false
    }

    /// Classify one of THIS reader's entries (#662) — the route CALLERS
    /// should take. The policy itself takes the archive-level bit as a
    /// parameter, which a caller could get wrong, and whose zero-effort
    /// wrong answer (`false`) is the one that hides a tampering signal;
    /// so the bit-taking form stays crate-internal and this method
    /// supplies `self`'s bit. Implementors get that for free by
    /// overriding [`Self::claims_integrity`] and leaving this alone.
    ///
    /// That is a default worth inheriting, NOT a guarantee: this is an
    /// overridable trait method and [`EntryIntegrity`] is a plain
    /// enum, so an implementor that overrides this can return any
    /// variant — including one that reports a stripped hash as
    /// [`EntryIntegrity::NoClaim`]. Keeping the classifier crate-internal
    /// makes the safe path the easy one; it does not seal the unsafe one.
    ///
    /// SCOPE: the zero-digest policy itself is pak's, and is not
    /// pluggable — `classify_sha1_claim` and the raw field are both
    /// crate-internal, so an external implementor whose format assigns
    /// a zeroed digest some OTHER meaning cannot express that here. It
    /// would have to override this method and carry its own state.
    /// Accepted while pak is the only reader; generalising before a
    /// second one exists would be designing against a guess.
    ///
    /// `meta` must come from this reader's own [`Self::entries`];
    /// classifying another archive's metadata against this archive's bit
    /// is a caller error the type system cannot catch.
    fn entry_integrity(&self, meta: &EntryMetadata) -> EntryIntegrity {
        classify_sha1_claim(meta.sha1(), self.claims_integrity())
    }
}

/// Compile-time assertion that [`ContainerReader`] is dyn-compatible.
/// The trait's docstring promises object-safety; this `const _` makes
/// that promise a build-failure if a future trait method takes `Self` by
/// value, returns `impl Trait`, or otherwise breaks dyn-compatibility.
#[allow(dead_code)]
const _: fn() = || {
    fn assert_dyn_compatible(_: &dyn ContainerReader) {}
};

/// Open a container archive as a type-erased [`ContainerReader`].
///
/// This is the container-agnostic seam every frontend uses instead of
/// naming a concrete reader type (issue #654; ROADMAP: "command
/// implementations never reference a specific container type").
///
/// Today this always constructs a [`pak::PakReader`]; Phase 8 adds
/// format dispatch here (sniff `.pak` vs `.utoc`/IoStore) as a branch
/// inside this ONE function, leaving every consumer untouched.
///
/// Delegates to [`pak::PakReader::open`] / [`pak::PakReader::open_with_key`],
/// so their documented behaviors — the symlink defense-in-depth warning
/// and the `Decryption { path }` diagnostic upgrade — are preserved by
/// construction, and every [`crate::PaksmithError`] passes through
/// unchanged (the GUI's Decryption→Locked key-prompt policy depends on
/// the error identity surviving this seam).
///
/// Known residual pak-specific surfaces (Phase 8 must dispatch these
/// too, not just this factory): the pre-open key-GUID probe
/// [`pak::PakReader::read_footer_guid`] — consumed by both
/// `profile::resolve::resolve_pak_context` and the CLI `profile test`
/// command — and the key-verification path `profile::key_test::test_key`
/// (`PakReader::open_with_key` + `verify_index`). IoStore stores the same
/// key GUID in the `.utoc` header, so Phase 8 wants format-dispatching
/// siblings for both probe shapes next to this factory.
///
/// # Errors
///
/// Exactly the constructor errors of the underlying reader — see
/// [`pak::PakReader::open`].
pub fn open(
    path: &std::path::Path,
    key: Option<&crate::AesKey>,
) -> crate::Result<std::sync::Arc<dyn ContainerReader>> {
    let reader = match key {
        Some(k) => pak::PakReader::open_with_key(path, k.clone())?,
        None => pak::PakReader::open(path)?,
    };
    Ok(std::sync::Arc::new(reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_integrity_defaults_to_no_claim() {
        // Pins the trait default's `false` body: a reader that does
        // not override the method must report "no integrity claim known" —
        // a `true` default would let zeroed hashes classify as tampering
        // signals on containers that never made a claim.
        struct NoOverride;
        impl ContainerReader for NoOverride {
            fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + Send + '_> {
                Box::new(std::iter::empty())
            }
            fn read_entry_to(&self, _: &str, _: &mut dyn Write) -> crate::Result<u64> {
                unreachable!("not exercised by this test")
            }
            fn read_entry(&self, _: &str) -> crate::Result<Vec<u8>> {
                unreachable!("not exercised by this test")
            }
            fn format(&self) -> ContainerFormat {
                ContainerFormat::Pak
            }
            // The trait fixes the `&self`-bound lifetime; `&'static str`
            // would not match the required signature.
            #[allow(clippy::unnecessary_literal_bound)]
            fn mount_point(&self) -> &str {
                ""
            }
        }
        assert!(
            !NoOverride.claims_integrity(),
            "the un-overridden default must be false (no claim known)"
        );
    }

    #[test]
    fn classify_sha1_claim_covers_all_four_states() {
        use crate::digest::Sha1Digest;
        // Inputs supplied directly: the function takes an Option and a
        // bool, so routing them through an EntryMetadata would couple
        // this test to a constructor it has no stake in. That the
        // builder stores the field verbatim is pinned separately by
        // `entry_metadata_builders_set_each_detail`.
        //
        // No index field: the archive bit is irrelevant.
        assert_eq!(classify_sha1_claim(None, false), EntryIntegrity::NotInIndex);
        assert_eq!(classify_sha1_claim(None, true), EntryIntegrity::NotInIndex);
        // A zeroed field is AMBIGUOUS alone — the archive bit decides,
        // mirroring verify_entry's SkippedNoHash / IntegrityStripped
        // split. Neither may become a Claim of twenty zero bytes.
        assert_eq!(
            classify_sha1_claim(Some(Sha1Digest::ZERO), false),
            EntryIntegrity::NoClaim
        );
        assert_eq!(
            classify_sha1_claim(Some(Sha1Digest::ZERO), true),
            EntryIntegrity::Stripped
        );
        // A real claim propagates regardless of the archive bit.
        let real = Sha1Digest::from([0xABu8; 20]);
        assert_eq!(
            classify_sha1_claim(Some(real), false),
            EntryIntegrity::Claim(real)
        );
        assert_eq!(
            classify_sha1_claim(Some(real), true),
            EntryIntegrity::Claim(real)
        );
    }

    /// `into_path` has no in-core caller — both consumers are in the
    /// CLI and GUI — so without this it is uncovered under
    /// `cargo test -p paksmith-core` and under cargo-mutants' baseline,
    /// which are package-scoped and never credit another crate's tests.
    /// A `-> String::new()` stub would otherwise survive.
    #[test]
    fn into_path_yields_the_constructed_path() {
        let m = EntryMetadata::new("Game/Maps/Demo.uasset".into(), 1, 2, EntryFlags::NONE);
        assert_eq!(m.path(), "Game/Maps/Demo.uasset");
        assert_eq!(m.into_path(), "Game/Maps/Demo.uasset");
    }

    #[test]
    fn entry_metadata_details_default_to_none() {
        let m = EntryMetadata::new(
            "a/b.uasset".into(),
            10,
            20,
            EntryFlags {
                compressed: false,
                encrypted: false,
            },
        );
        assert_eq!(m.offset(), None);
        assert_eq!(m.compression_method_shared(), None);
        assert_eq!(m.sha1(), None);
    }

    #[test]
    fn entry_metadata_builders_set_each_detail() {
        let digest = crate::digest::Sha1Digest::from([0xAB; 20]);
        let m = EntryMetadata::new(
            "a/b.uasset".into(),
            10,
            20,
            EntryFlags {
                compressed: true,
                encrypted: false,
            },
        )
        .with_offset(0x1234)
        .with_compression_method("Zlib".to_string())
        .with_sha1(digest);
        assert_eq!(m.offset(), Some(0x1234));
        assert_eq!(m.compression_method_shared().as_deref(), Some("Zlib"));
        assert_eq!(m.sha1(), Some(digest));
    }
}
