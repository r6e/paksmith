//! Property-based tests for v10+ index parsing.
//!
//! Two properties:
//!
//! 1. **No-panic on garbage**: random bytes fed into
//!    `PakIndex::read_from` (with a v10+ version, so the v10+ code
//!    path is exercised) never panic — they either return `Ok(...)`
//!    (vanishingly rare given the structured wire format) or
//!    `Err(...)` (typical). Validates the "no panics in core" rule
//!    from CLAUDE.md against the most complex parser in the
//!    codebase.
//!
//! 2. **Structured-input-with-randomized-fields never panics**: a
//!    minimal-valid v10+ main-index frame (mount FString + the
//!    structural prefix that gets the parser past its first reject
//!    points) is planted, and the bounds-relevant numeric fields
//!    (`file_count`, `encoded_entries_size`, `fdi_offset`, etc.) are
//!    randomized. This exercises the parser's bounds-check arms
//!    under near-valid input — paths the unbiased fuzz at (1)
//!    rarely reaches because most random byte sequences fail the
//!    initial FString length check.
//!
//! Issue #51.

#![allow(missing_docs)]

use std::io::Cursor;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::index::PakIndex;
use paksmith_core::container::pak::version::PakVersion;
use proptest::prelude::*;

/// Write an FString (length-prefixed, null-terminated ASCII).
/// Length sign convention: positive = ASCII, length includes null.
fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let len = (s.len() + 1) as i32;
    buf.write_i32::<LittleEndian>(len).unwrap();
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Plant a minimal valid v10+ main-index prefix that passes the
/// FString + path_hash_seed + has_path_hash_index reads. The caller
/// chooses bounds-relevant field values (`file_count`, encoded blob
/// size, FDI header values) to drive the parser's bounds-check arms.
///
/// Layout per `PakIndex::read_v10_plus_from`:
/// - mount FString (`/` for minimal)
/// - `file_count: u32`
/// - `path_hash_seed: u64`
/// - `has_path_hash_index: u32` (0 = absent)
/// - `has_full_directory_index: u32` (1 = present — required, else
///   the parser rejects with `MissingFullDirectoryIndex`)
/// - if FDI present: `fdi_offset: u64 + fdi_size: u64 + fdi_hash:
///   [u8; 20]`
/// - `encoded_entries_size: u32`
/// - encoded_entries_size bytes of encoded blob
/// - `non_encoded_count: u32`
/// - non-encoded records
fn plant_v10_main_index(
    file_count: u32,
    fdi_offset: u64,
    fdi_size: u64,
    encoded_entries_size: u32,
    non_encoded_count: u32,
    tail: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_fstring(&mut buf, "/");
    buf.write_u32::<LittleEndian>(file_count).unwrap();
    buf.write_u64::<LittleEndian>(0).unwrap(); // path_hash_seed
    buf.write_u32::<LittleEndian>(0).unwrap(); // has_path_hash_index = false
    buf.write_u32::<LittleEndian>(1).unwrap(); // has_full_directory_index = true
    buf.write_u64::<LittleEndian>(fdi_offset).unwrap();
    buf.write_u64::<LittleEndian>(fdi_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // fdi_hash
    buf.write_u32::<LittleEndian>(encoded_entries_size).unwrap();
    buf.extend_from_slice(tail);
    buf.write_u32::<LittleEndian>(non_encoded_count).unwrap();
    buf
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Garbage bytes fed into the v10+ parser never panic. Uses
    /// `PakVersion::PathHashIndex` so `read_from` dispatches to
    /// `read_v10_plus_from` (rather than the flat v3-v9 path).
    #[test]
    fn read_v10_plus_garbage_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        index_size_override in 0u64..4096,
    ) {
        // index_size is an upper bound the parser uses to bound
        // FString reads + entry reservations; randomize it
        // independently of the byte length so the parser exercises
        // both "header claims more bytes than available" and "header
        // claims fewer bytes than available" branches.
        let mut cursor = Cursor::new(bytes);
        // Result intentionally discarded — we only care that parsing
        // returns (Ok or Err) instead of panicking or aborting.
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            index_size_override,
            &[],
        );
    }

    /// Structured property: plant a minimal-valid v10+ main-index
    /// frame, randomize the bounds-relevant numeric fields, randomize
    /// the inner blob bytes, and assert no panic. This exercises the
    /// bounds-check arms (`BoundsExceeded` for `file_count`,
    /// `BoundsExceeded` for `encoded_entries_size`,
    /// `OffsetPastFileSize` / `BoundsExceeded` for `fdi_size`, etc.)
    /// under near-valid input.
    ///
    /// The planted prefix passes the initial FString and
    /// has_path_hash_index reads, so the parser walks deeper than
    /// the unbiased fuzz at `read_v10_plus_garbage_bytes_never_panic`
    /// can reach with random bytes (most random byte sequences fail
    /// the FString length-prefix check on the first 4 bytes).
    #[test]
    fn read_v10_plus_planted_frame_random_fields_never_panic(
        file_count in 0u32..u32::MAX,
        fdi_offset in 0u64..u64::MAX,
        fdi_size in 0u64..u64::MAX,
        encoded_entries_size in 0u32..1024,
        non_encoded_count in 0u32..u32::MAX,
        tail in proptest::collection::vec(any::<u8>(), 0..1024),
        index_size_override in 0u64..8192,
    ) {
        let buf = plant_v10_main_index(
            file_count,
            fdi_offset,
            fdi_size,
            encoded_entries_size,
            non_encoded_count,
            &tail,
        );
        let mut cursor = Cursor::new(buf);
        // Result discarded — parser must return, not panic, regardless
        // of how the bounds checks fire (or don't) against the
        // randomized fields.
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            index_size_override,
            &[],
        );
    }

    /// Random bytes into the FNV64BugFix path-hash variant (v11) —
    /// covers the same parser but via the second has_path_hash_index
    /// version variant. Catches version-specific dispatch bugs the
    /// PathHashIndex test would miss.
    #[test]
    fn read_v11_garbage_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        index_size_override in 0u64..4096,
    ) {
        let mut cursor = Cursor::new(bytes);
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::Fnv64BugFix,
            0,
            index_size_override,
            &[],
        );
    }
}
