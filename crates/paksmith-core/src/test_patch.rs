//! Byte-patching helpers for tamper-scenario tests (#662).
//!
//! `#[cfg(test)]`-only: every caller is an in-source test in this
//! crate, so this is NOT part of the `__test_utils` surface and is not
//! reachable from `paksmith-core-tests`. That suite does patch fixture
//! bytes, but derives the footer offsets from its own
//! `INDEX_HASH_OFFSET_IN_FOOTER` rather than calling in here. If it
//! ever wants these, move the module back under `testing/` and gate it
//! on the feature.

/// Zero every occurrence of a 20-byte needle in `bytes`, returning the
/// occurrence count.
///
/// Search-based rather than offset-based so a patch survives fixture
/// regeneration; callers must assert on the returned count so a needle
/// that stops matching fails loudly instead of silently testing nothing.
///
/// One caller today — core's `zeroed_entry_hash_and_archive_bit_
/// classify_end_to_end`. It sits here rather than inline so that the
/// scheme has one home if it ever needs hardening (say a regenerated
/// fixture contains the needle in payload bytes).
#[must_use]
pub(crate) fn zero_needle(bytes: &mut [u8], needle: &[u8; 20]) -> usize {
    let mut hits = 0;
    let mut i = 0;
    while i + 20 <= bytes.len() {
        if &bytes[i..i + 20] == needle {
            bytes[i..i + 20].fill(0);
            hits += 1;
            i += 20;
        } else {
            i += 1;
        }
    }
    hits
}

/// Byte offset of the pak footer's MAGIC within `bytes`.
///
/// Found by scanning BACKWARD (`rposition`), so a fixture whose payload
/// happens to contain the magic bytes still anchors on the real footer.
///
/// # Panics
///
/// Panics if `bytes` contains no footer magic at all — a test fixture
/// that is not a pak is a broken test, not a runtime condition.
#[must_use]
pub(crate) fn footer_magic_pos(bytes: &[u8]) -> usize {
    let magic = crate::container::pak::version::PAK_MAGIC.to_le_bytes();
    bytes
        .windows(4)
        .rposition(|w| w == magic.as_slice())
        .expect("footer magic must be present in fixture")
}

/// Byte range of the footer's stored `index_hash`, for tests that patch
/// or inspect it.
///
/// Anchored on the MAGIC, not the footer start — for V7+ the footer
/// opens with the encryption GUID and flag, so the two differ by 17
/// bytes. From the magic the layout is magic(4) + version(4) +
/// index_offset(8) + index_size(8), putting the 20-byte hash at
/// `magic + 24` for every footer variant.
///
/// Other test files derive the same byte from the footer START instead
/// (`footer_start + 41`, since 41 = 17 + 24 for a V7+ footer); both
/// forms are correct, and a footer that grew a field before the hash
/// would have to be fixed wherever it is spelled.
///
/// # Panics
///
/// Panics if the magic is absent, or if the 20-byte hash field would
/// run past the end of `bytes`.
#[must_use]
pub(crate) fn footer_index_hash_range(bytes: &[u8]) -> std::ops::Range<usize> {
    let start = footer_magic_pos(bytes) + 24;
    let range = start..start + 20;
    assert!(
        range.end <= bytes.len(),
        "index_hash field must fit within the fixture"
    );
    range
}
