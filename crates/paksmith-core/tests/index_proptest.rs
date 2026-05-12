//! Property-based tests for v10+ index parsing.
//!
//! Two properties:
//!
//! 1. **Garbage bytes never panic**: random bytes fed into
//!    `PakIndex::read_from` (with a v10+ version) never panic — they
//!    either return `Ok(...)` (vanishingly rare given the structured
//!    wire format) or `Err(...)` (typical). Validates the "no panics
//!    in core" rule from CLAUDE.md against the most complex parser
//!    in the codebase.
//!
//! 2. **Deep-structured-input never panics**: plants a minimal-valid
//!    v10+ main-index prefix that gets the parser past the FString
//!    and structural-flag reads, then randomizes the bounds-relevant
//!    numeric fields AND biases `fdi_offset` to land inside the
//!    buffer so the FDI walk actually runs (the deepest, most fragile
//!    parser code: `dir_count`, `dir_name` FString reads, per-file
//!    FString reads, file_count cross-check). Optionally plants a
//!    path-hash-index header so the PHI-present arm is reachable.
//!
//! Issue #51.
//!
//! ## Out of scope (filed as follow-ups)
//!
//! - **Structural round-trip oracle**: building a well-formed v10+
//!   archive and asserting the parser recovers the planted fields
//!   would need access to the production `build_v10_buffer` helper
//!   (currently `#[cfg(test)]`-private inside `pak/index.rs`).
//!   Promoting the helper to a `pub(crate)` testing utility is a
//!   separate refactor — filed as a follow-up issue.

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
/// chooses bounds-relevant field values to drive the parser's
/// bounds-check arms.
///
/// Layout per `PakIndex::read_v10_plus_from`:
/// - mount FString (`/`)
/// - `file_count: u32`
/// - `path_hash_seed: u64`
/// - `has_path_hash_index: u32` (0 = absent, 1 = present)
/// - if PHI present: `phi_offset: u64 + phi_size: u64 + phi_hash: [u8; 20]`
/// - `has_full_directory_index: u32` (must be 1, else parser rejects
///   with `MissingFullDirectoryIndex`)
/// - `fdi_offset: u64 + fdi_size: u64 + fdi_hash: [u8; 20]`
/// - `encoded_entries_size: u32`
/// - `encoded_entries_size` bytes of encoded blob
/// - `non_encoded_count: u32`
/// - non-encoded records (caller-supplied tail bytes)
#[allow(clippy::too_many_arguments)]
fn plant_v10_main_index(
    file_count: u32,
    has_phi: bool,
    fdi_offset: u64,
    fdi_size: u64,
    encoded_entries_size: u32,
    encoded_blob: &[u8],
    non_encoded_count: u32,
    non_encoded_tail: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_fstring(&mut buf, "/");
    buf.write_u32::<LittleEndian>(file_count).unwrap();
    buf.write_u64::<LittleEndian>(0).unwrap(); // path_hash_seed
    buf.write_u32::<LittleEndian>(u32::from(has_phi)).unwrap();
    if has_phi {
        buf.write_u64::<LittleEndian>(0).unwrap(); // phi_offset
        buf.write_u64::<LittleEndian>(0).unwrap(); // phi_size (zero so the
        // parser doesn't try to read PHI bytes outside the buffer)
        buf.extend_from_slice(&[0u8; 20]); // phi_hash
    }
    buf.write_u32::<LittleEndian>(1).unwrap(); // has_full_directory_index = true
    buf.write_u64::<LittleEndian>(fdi_offset).unwrap();
    buf.write_u64::<LittleEndian>(fdi_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // fdi_hash
    buf.write_u32::<LittleEndian>(encoded_entries_size).unwrap();
    buf.extend_from_slice(encoded_blob);
    buf.write_u32::<LittleEndian>(non_encoded_count).unwrap();
    buf.extend_from_slice(non_encoded_tail);
    buf
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Garbage bytes fed into the v10+ parser never panic. Uses
    /// `PakVersion::PathHashIndex` so `read_from` dispatches to
    /// `read_v10_plus_from` rather than the flat v3-v9 path.
    /// Most random byte sequences fail the initial FString
    /// length-prefix check; this property guards the early-reject
    /// paths.
    #[test]
    fn read_v10_plus_garbage_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        index_size_kind in 0u8..3,
        index_size_random in 0u64..u64::MAX,
    ) {
        // Stratify `index_size` across three buckets so the shrinker
        // collapses to discrete cases rather than fighting two
        // independently-shrinking integers: zero, exactly-buffer-length
        // (the "honest" header), and unbounded random (mostly larger
        // than buffer, triggers the truncated-read path). Without this,
        // a discovered regression shrinks to an arbitrary middle value.
        let index_size = match index_size_kind {
            0 => 0,
            1 => bytes.len() as u64,
            _ => index_size_random,
        };
        let mut cursor = Cursor::new(bytes);
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            index_size,
            &[],
        );
    }

    /// Deep-structured property: plant a v10+ main-index prefix that
    /// gets the parser past the FString and structural-flag reads,
    /// then drive the FDI walk by biasing `fdi_offset` to land inside
    /// the buffer most of the time. The FDI walk itself
    /// (`dir_count`, per-dir `dir_name` FString + per-file FString +
    /// `i32 encoded_offset`, plus the file_count cross-check at
    /// `read_v10_plus_from`'s end) is the deepest parser code in the
    /// codebase; random bytes from the property above almost never
    /// reach it because of the early FString-length reject.
    ///
    /// `has_path_hash_index` is randomized: when true, the PHI header
    /// (offset/size/hash) is planted with zero size so the parser
    /// doesn't try to read PHI bytes outside the buffer — but the
    /// "PHI is present" branch is still exercised, which the
    /// previous version of this property never reached.
    #[test]
    fn read_v10_plus_planted_frame_with_in_bounds_fdi_never_panics(
        file_count in 0u32..1024,
        has_phi in any::<bool>(),
        fdi_offset_kind in 0u8..3,
        fdi_offset_random in 0u64..u64::MAX,
        fdi_size_kind in 0u8..3,
        fdi_size_random in 0u64..u64::MAX,
        encoded_blob in proptest::collection::vec(any::<u8>(), 0..512),
        encoded_size_lies in any::<bool>(),
        non_encoded_count in 0u32..1024,
        non_encoded_tail in proptest::collection::vec(any::<u8>(), 0..512),
        fdi_tail in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let encoded_size = if encoded_size_lies {
            // Lie about the encoded blob size — exercises the bounds
            // check at index.rs:1107.
            (encoded_blob.len() as u32).saturating_add(1024)
        } else {
            encoded_blob.len() as u32
        };
        let main_prefix = plant_v10_main_index(
            file_count,
            has_phi,
            0, // fdi_offset placeholder — patched below
            0, // fdi_size placeholder — patched below
            encoded_size,
            &encoded_blob,
            non_encoded_count,
            &non_encoded_tail,
        );
        let main_len = main_prefix.len() as u64;

        // Bias fdi_offset to land in-bounds (kind 0 + 1 = inside the
        // buffer, kind 2 = fully random — overwhelmingly out of bounds).
        // Out-of-bounds is fine to test, but without the in-bounds
        // bias the FDI parser is unreachable for ~99.99% of cases.
        let fdi_offset = match fdi_offset_kind {
            0 => main_len, // FDI directly follows main index — the canonical layout.
            1 => fdi_offset_random.checked_rem(main_len.saturating_mul(2).max(1)).unwrap_or(0),
            _ => fdi_offset_random,
        };
        let fdi_size = match fdi_size_kind {
            0 => fdi_tail.len() as u64,
            1 => 0,
            _ => fdi_size_random,
        };

        // Concatenate main + fdi_tail; patch the fdi_offset/fdi_size
        // fields in the prefix. The PHI header occupies 36 bytes
        // (8 offset + 8 size + 20 hash) when has_phi is true.
        let phi_bytes: u64 = if has_phi { 36 } else { 0 };
        // Locate the FDI header in the prefix: mount FString
        // (4 length + 2 bytes "/\0") + file_count(4) + path_hash_seed(8)
        // + has_path_hash_index(4) + [phi_bytes if PHI] +
        // has_full_directory_index(4) = 26 + phi_bytes.
        let fdi_header_pos = (4 + 2 + 4 + 8 + 4 + phi_bytes + 4) as usize;
        let mut buf = main_prefix;
        if buf.len() >= fdi_header_pos + 16 {
            buf[fdi_header_pos..fdi_header_pos + 8]
                .copy_from_slice(&fdi_offset.to_le_bytes());
            buf[fdi_header_pos + 8..fdi_header_pos + 16]
                .copy_from_slice(&fdi_size.to_le_bytes());
        }
        // Pad to fdi_offset so the FDI seek lands inside the buffer
        // for kind-0 / kind-1 cases.
        if (fdi_offset as usize) > buf.len() && (fdi_offset as usize) < 8 * 1024 {
            buf.resize(fdi_offset as usize, 0);
        }
        buf.extend_from_slice(&fdi_tail);

        let total_len = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            // `index_size` is the main-index length, not the whole
            // buffer — the parser uses it to bound the main-index
            // reads before seeking to the FDI.
            main_len.min(total_len),
            &[],
        );
    }
}
