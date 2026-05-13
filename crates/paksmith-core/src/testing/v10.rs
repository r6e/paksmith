//! V10+ pak index wire-format synthesis for tests.
//!
//! Issue #68 promoted these helpers out of `pak/index/mod.rs`'s
//! in-source `#[cfg(test)] mod tests` block so that integration
//! tests under `tests/` can use the same fixture builder rather
//! than maintaining a parallel ~30-line copy that silently rots
//! the moment the wire format gains a field.
//!
//! **Stability:** gated behind the `__test_utils` feature; do not
//! depend on this from downstream crates.
//!
//! `Vec` writes are infallible (the only `unwrap()` panics in
//! these helpers come from `byteorder::WriteBytesExt` against a
//! `Vec<u8>` sink, which never fails). Suppressing the
//! `missing_panics_doc` lint at the module level rather than
//! sprinkling `# Panics` sections that would all say the same
//! thing — these are test-only synthesizers, never production
//! code paths.
#![allow(clippy::missing_panics_doc)]

use byteorder::{LittleEndian, WriteBytesExt};

/// Write an FString (length-prefixed ASCII, null-terminated) to
/// `buf`. Length sign convention: positive = UTF-8 bytes, negative
/// = UTF-16 code units (this helper only writes UTF-8). The length
/// includes the trailing null byte.
pub fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

/// Append an FDI ("full directory index") body to `buf` from a
/// flat `(dir_name, [(file_name, encoded_offset_i32)])` spec. The
/// wire shape is `dir_count u32` followed by per-dir
/// `FString name + file_count u32 + per-file FString filename + i32 encoded_offset`.
pub fn write_fdi_body(buf: &mut Vec<u8>, dirs: &[(&str, &[(&str, i32)])]) {
    buf.write_u32::<LittleEndian>(dirs.len() as u32).unwrap();
    for (dir_name, files) in dirs {
        write_fstring(buf, dir_name);
        buf.write_u32::<LittleEndian>(files.len() as u32).unwrap();
        for (file_name, encoded_offset) in *files {
            write_fstring(buf, file_name);
            buf.write_i32::<LittleEndian>(*encoded_offset).unwrap();
        }
    }
}

/// Write a v10+ non-encoded (FPakEntry-shape) record to `buf`. The
/// record is uncompressed and unencrypted, totalling 53 bytes — it
/// must round-trip through
/// `PakEntryHeader::read_from(reader, PathHashIndex, &[])`.
pub fn write_v10_non_encoded_uncompressed(buf: &mut Vec<u8>, offset: u64, size: u64) {
    buf.write_u64::<LittleEndian>(offset).unwrap();
    buf.write_u64::<LittleEndian>(size).unwrap(); // compressed
    buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed
    buf.write_u32::<LittleEndian>(0).unwrap(); // compression_method = None
    buf.extend_from_slice(&[0u8; 20]); // SHA1
    buf.push(0); // not encrypted
    buf.write_u32::<LittleEndian>(0).unwrap(); // block_size
}

/// Spec for assembling a v10+ test fixture. Each `*_override`
/// field substitutes a forged value in place of the natural one —
/// the natural value is computed from the structural fields (e.g.,
/// `encoded_entries.len()`). This is what lets a single helper
/// drive both happy-path and "header lies about size" negative
/// tests.
pub struct V10Fixture<'a> {
    /// Mount point FString written at the start of the main index.
    pub mount: &'a str,
    /// `file_count` field written into the main-index header.
    /// Doesn't have to match the actual number of FDI entries (the
    /// parser cross-checks them).
    pub file_count: u32,
    /// When false, omits the FDI region entirely AND writes
    /// `has_full_directory_index = 0`. The parser will reject this
    /// shape with `MissingFullDirectoryIndex` — useful for negative
    /// tests.
    pub has_full_directory_index: bool,
    /// Pre-serialized encoded entries blob bytes.
    pub encoded_entries: Vec<u8>,
    /// When set, overrides the wire `encoded_entries_size` field
    /// with the supplied value (instead of using
    /// `encoded_entries.len()`). Used to drive bounds-check
    /// negative tests.
    pub encoded_entries_size_override: Option<u32>,
    /// Pre-serialized non-encoded (`PakEntryHeader`-shape) record
    /// bytes.
    pub non_encoded_records: Vec<u8>,
    /// When set, overrides the wire `non_encoded_count` field.
    pub non_encoded_count_override: Option<u32>,
    /// Number of non-encoded records the wire header should claim.
    pub non_encoded_count: u32,
    /// FDI body spec: list of `(dir_name, [(file_name,
    /// encoded_offset)])`.
    pub fdi: Vec<(&'a str, &'a [(&'a str, i32)])>,
    /// When set, overrides the wire `fdi_size` field. Used to
    /// drive `fdi_size > MAX_FDI_BYTES`-style negative tests.
    pub fdi_size_override: Option<u64>,
}

impl Default for V10Fixture<'_> {
    fn default() -> Self {
        Self {
            mount: "../../../",
            file_count: 0,
            has_full_directory_index: true,
            encoded_entries: Vec::new(),
            encoded_entries_size_override: None,
            non_encoded_records: Vec::new(),
            non_encoded_count_override: None,
            non_encoded_count: 0,
            fdi: Vec::new(),
            fdi_size_override: None,
        }
    }
}

/// Assemble a v10+ buffer with `[main_index][fdi]` layout starting
/// at offset 0. Returns `(buffer, main_index_size)` so the test
/// can pass `main_index_size` as `index_size` to
/// `PakIndex::read_from`. `spec` is consumed by destructure-move
/// so its `Vec` fields don't have to be cloned.
pub fn build_v10_buffer(spec: V10Fixture<'_>) -> (Vec<u8>, u64) {
    let V10Fixture {
        mount,
        file_count,
        has_full_directory_index,
        encoded_entries,
        encoded_entries_size_override,
        non_encoded_records,
        non_encoded_count_override,
        non_encoded_count,
        fdi,
        fdi_size_override,
    } = spec;

    let mut main = Vec::new();
    write_fstring(&mut main, mount);
    main.write_u32::<LittleEndian>(file_count).unwrap();
    main.write_u64::<LittleEndian>(0).unwrap(); // path_hash_seed
    main.write_u32::<LittleEndian>(0).unwrap(); // has_path_hash_index = false

    main.write_u32::<LittleEndian>(u32::from(has_full_directory_index))
        .unwrap();
    let fdi_header_pos = if has_full_directory_index {
        let p = main.len();
        main.write_u64::<LittleEndian>(0).unwrap(); // fdi_offset placeholder
        main.write_u64::<LittleEndian>(0).unwrap(); // fdi_size placeholder
        main.extend_from_slice(&[0u8; 20]); // fdi_hash
        Some(p)
    } else {
        None
    };

    let natural_encoded_size = u32::try_from(encoded_entries.len()).unwrap();
    let encoded_size = encoded_entries_size_override.unwrap_or(natural_encoded_size);
    main.write_u32::<LittleEndian>(encoded_size).unwrap();
    main.extend_from_slice(&encoded_entries);

    let non_enc_count = non_encoded_count_override.unwrap_or(non_encoded_count);
    main.write_u32::<LittleEndian>(non_enc_count).unwrap();
    main.extend_from_slice(&non_encoded_records);

    let main_size = main.len() as u64;
    let fdi_offset = main_size;

    let mut fdi_bytes = Vec::new();
    write_fdi_body(&mut fdi_bytes, &fdi);
    let natural_fdi_size = fdi_bytes.len() as u64;
    let fdi_size = fdi_size_override.unwrap_or(natural_fdi_size);

    if let Some(p) = fdi_header_pos {
        main[p..p + 8].copy_from_slice(&fdi_offset.to_le_bytes());
        main[p + 8..p + 16].copy_from_slice(&fdi_size.to_le_bytes());
    }

    let mut buf = main;
    buf.extend_from_slice(&fdi_bytes);
    (buf, main_size)
}

// --- Bit-packed encoded-entry synthesis (issue #79) -----------------

/// Args for [`encode_entry_bytes`]. Consolidated into a struct so a
/// new field doesn't require touching every call site, and to keep
/// the function under clippy's argument-count limit. `Copy` so the
/// helper takes by value without a needless-pass-by-value lint.
#[derive(Copy, Clone)]
pub struct EncodeArgs<'a> {
    /// Entry's `offset` field. Determines whether the on-wire varint
    /// uses u32 (fits) or u64 (otherwise) — the bit-31 flag is set
    /// when `offset <= u32::MAX`.
    pub offset: u64,
    /// Entry's `uncompressed_size`. Same u32-fits-via-bit-30 dispatch.
    pub uncompressed: u64,
    /// Entry's `compressed_size`. Same u32-fits-via-bit-29 dispatch.
    /// Only emitted on the wire when `compression_slot_1based != 0`.
    pub compressed: u64,
    /// 1-based index into the footer's compression-method FName
    /// table. `0` = no compression (the field is absent on the wire).
    /// Masked to 6 bits by the parser, so values >63 are silently
    /// truncated; tests should stay in `0..64`.
    pub compression_slot_1based: u32,
    /// Entry encryption flag. The encrypted-and-block_count==1 case
    /// enters the multi-block path (per-block sizes required) rather
    /// than the trivial single-block branch.
    pub encrypted: bool,
    /// Number of compression blocks. Masked to 16 bits by the parser
    /// (`(bits >> 6) & 0xffff`); tests should stay in `0..=u16::MAX`.
    /// `0` means no blocks (only valid when `compression_slot_1based
    /// == 0` after issue #59).
    pub block_count: u32,
    /// Compression block size. Either fits the 5-bit field (a
    /// multiple of 0x800 in `0..0x3f * 0x800`) OR uses the sentinel
    /// `0x3f` and is written as a separate u32 immediately after
    /// the bit-packed header.
    pub block_size: u32,
    /// Per-block compressed sizes. Required when `block_count > 0`
    /// AND (`block_count != 1` OR `encrypted`); the trivial
    /// single-block-uncompressed-and-not-encrypted layout omits
    /// them. Caller must supply `block_count` entries. Sum must
    /// equal `compressed` to satisfy the issue #58 cross-check.
    pub per_block_sizes: &'a [u32],
}

/// Append `value` to `buf` as a u32-LE if it fits, else u64-LE.
/// Mirrors the wire-format var-int encoding used by encoded entries
/// for `offset` / `uncompressed` / `compressed`.
fn push_var_int(buf: &mut Vec<u8>, value: u64) {
    match u32::try_from(value) {
        Ok(v) => buf.extend_from_slice(&v.to_le_bytes()),
        Err(_) => buf.extend_from_slice(&value.to_le_bytes()),
    }
}

/// Build a v10+ bit-packed encoded-entry buffer from the parameters
/// the parser's bit-shift logic should round-trip. Mirrors UE's
/// `FPakEntry::EncodeTo` (and repak's `Entry::write_encoded`) so a
/// future change to either encoder/decoder side surfaces here.
///
/// Issue #79: promoted from `pak/index/mod.rs::tests` to this
/// shared `__test_utils` surface so the integration proptest under
/// `tests/index_proptest.rs` can drive the positive-`encoded_offset`
/// arm of `path_hash.rs`'s FDI walk (the one that decodes via
/// `PakEntryHeader::read_encoded`) — the existing round-trip
/// proptest only exercises the non-encoded fallback.
pub fn encode_entry_bytes(args: EncodeArgs<'_>) -> Vec<u8> {
    // Encode block_size: stored as 5 bits left-shifted by 11, with
    // sentinel 0x3f meaning "doesn't fit; read u32 verbatim."
    let (block_size_bits, write_block_size_extra) = {
        let candidate = args.block_size >> 11;
        if (candidate << 11) == args.block_size && candidate < 0x3f {
            (candidate, false)
        } else {
            (0x3f, true)
        }
    };
    let offset_fits_u32 = u32::try_from(args.offset).is_ok();
    let uncompressed_fits_u32 = u32::try_from(args.uncompressed).is_ok();
    let compressed_fits_u32 = u32::try_from(args.compressed).is_ok();

    let mut bits: u32 = block_size_bits;
    bits |= (args.block_count & 0xffff) << 6;
    bits |= u32::from(args.encrypted) << 22;
    bits |= (args.compression_slot_1based & 0x3f) << 23;
    // u32-fits flags: set if value fits in u32.
    bits |= u32::from(compressed_fits_u32) << 29;
    bits |= u32::from(uncompressed_fits_u32) << 30;
    bits |= u32::from(offset_fits_u32) << 31;

    let mut buf = Vec::new();
    buf.extend_from_slice(&bits.to_le_bytes());
    if write_block_size_extra {
        buf.extend_from_slice(&args.block_size.to_le_bytes());
    }
    // var_int(31) — offset; var_int(30) — uncompressed.
    push_var_int(&mut buf, args.offset);
    push_var_int(&mut buf, args.uncompressed);
    // var_int(29) — compressed, only present when compression slot != 0.
    if args.compression_slot_1based != 0 {
        push_var_int(&mut buf, args.compressed);
    }
    // Per-block sizes for the non-trivial layouts (multi-block, or
    // single-block-but-encrypted). The single-uncompressed-block case
    // is reconstructed by the decoder from the in-data record size,
    // so no per-block sizes appear in the wire stream.
    let needs_per_block_sizes = args.block_count > 0 && (args.block_count != 1 || args.encrypted);
    if needs_per_block_sizes {
        assert_eq!(
            args.per_block_sizes.len(),
            args.block_count as usize,
            "test must supply N block sizes for non-trivial block layout"
        );
        for &s in args.per_block_sizes {
            buf.extend_from_slice(&s.to_le_bytes());
        }
    }
    buf
}
