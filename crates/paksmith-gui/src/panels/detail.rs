//! Detail-pane helpers.
//!
//! [`entry_rows`] is the load-bearing one: it decides which ENTRY-level
//! Info-pane rows exist, in what order, and which label carries which
//! value, so that those choices sit somewhere a test can see them
//! rather than inside `panels::content`'s `#[mutants::skip]` view. The
//! entry row labels are constants here for the same reason. The pane's
//! PACKAGE-level rows (Exports/Names/Engine) are still assembled inline
//! in that view and are not covered by this seam. The value formatters
//! (`human_size`, `compression_ratio`, `record_offset_label`,
//! `compressed_label`, `sha1_label`) back it, and `kv_row` builds the
//! widget. `panels::content` reaches only two items here: `entry_rows`
//! (path-qualified) and `kv_row` (its one `use`); the rest are this
//! module's own internals.
//!
//! The original `view`/`empty_detail`/`entry_detail` functions that composed
//! the Phase 6 detail pane were retired in Phase 7a when the tabbed content
//! host (`panels::content`) took over.

use iced::widget::{row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::state::archive::EntryMeta;
use crate::theme::tokens::{DETAIL_LABEL_WIDTH, SPACE_XS, TEXT_MUTED_ALPHA, TEXT_SM};

// ── pure helpers ──────────────────────────────────────────────────────────────

/// Format a byte count as a human-readable decimal string.
///
/// Uses SI (decimal) prefixes (1 KB = 1000 B) to match the test cases in the
/// task brief (`2_400_000 → "2.4 MB"`).
///
/// Boundaries:
/// - < 1 000 B → "N B"
/// - < 1 000 000 B → "N.N KB"
/// - < 1 000 000 000 B → "N.N MB"
/// - ≥ 1 000 000 000 B → "N.N GB"
pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        let whole = bytes / KB;
        let frac = (bytes % KB) / 100; // one decimal digit
        if frac == 0 {
            format!("{whole} KB")
        } else {
            format!("{whole}.{frac} KB")
        }
    } else if bytes < GB {
        let whole = bytes / MB;
        let frac = (bytes % MB) / 100_000; // one decimal digit
        if frac == 0 {
            format!("{whole} MB")
        } else {
            format!("{whole}.{frac} MB")
        }
    } else {
        let whole = bytes / GB;
        let frac = (bytes % GB) / 100_000_000; // one decimal digit
        if frac == 0 {
            format!("{whole} GB")
        } else {
            format!("{whole}.{frac} GB")
        }
    }
}

/// The Info pane's Offset row LABEL. `(record)` is load-bearing, not
/// decoration: the value points at the entry's on-disk record — the
/// duplicated header — not the first payload byte, and this label is
/// the only place a user learns which. Lives here, beside the
/// value helper, so the qualifier is covered by a test rather than
/// sitting as a literal inside the `#[mutants::skip]` view.
pub const OFFSET_ROW_LABEL: &str = "Offset (record)";

/// The Info pane's SHA-1 row LABEL. `(stored)` is load-bearing: the
/// pane reports what the archive RECORDS, never a verification result,
/// and dropping the qualifier would let a stored claim read as a
/// checked one. The matching "unverified" qualifier lives in
/// the VALUE — see [`sha1_label`] — because labels sit in a fixed
/// [`DETAIL_LABEL_WIDTH`] column that a longer string would wrap.
pub const SHA1_ROW_LABEL: &str = "SHA-1 (stored)";

/// The Info pane's remaining row labels. Plain descriptions with no
/// load-bearing qualifier, but they live here with the other two so
/// [`entry_rows`] defines no bare literal and every label is pinned.
pub const PATH_ROW_LABEL: &str = "Path";
/// See [`PATH_ROW_LABEL`].
pub const SIZE_ROW_LABEL: &str = "Size";
/// See [`PATH_ROW_LABEL`].
pub const COMPRESSED_ROW_LABEL: &str = "Compressed";
/// See [`PATH_ROW_LABEL`].
pub const ENCRYPTED_ROW_LABEL: &str = "Encrypted";

/// The Info pane's Offset row value: hex (the customary base for file
/// offsets), an em-dash when the container recorded none (#662).
#[must_use]
pub fn record_offset_label(offset: Option<u64>) -> String {
    offset.map_or_else(|| "\u{2014}".to_string(), |o| format!("0x{o:X}"))
}

/// The Info pane's Compressed row value (#662): "No", or "Yes" carrying
/// the method name (when the container recorded one), the compressed
/// size, and the ratio — e.g. `Yes (Zlib, 1.2 MB, 55%)`.
#[must_use]
pub fn compressed_label(
    is_compressed: bool,
    method: Option<&str>,
    compressed_size: &str,
    ratio: &str,
) -> String {
    if !is_compressed {
        return "No".to_string();
    }
    match method {
        Some(m) => format!("Yes ({m}, {compressed_size}, {ratio})"),
        None => format!("Yes ({compressed_size}, {ratio})"),
    }
}

/// The Info pane's stored-SHA-1 row value (#662). The Phase 6 GUI-shell
/// design doc's `detail.rs` bullet (§View panels) asks for "SHA1
/// verification status"; this row reports the
/// STORED-CLAIM status — actually verifying would mean reading and
/// hashing the entry on every selection, which belongs to the verify
/// path, not an info pane. The row's label says "stored" and the claim
/// carries "(unverified)" so hex can't read as a checked result.
///
/// Each state gets distinct prose, and each states only what is
/// observed — never a reading of it. The prose avoids naming any one
/// container's wire structures: the enum is generic, `container::open`
/// gains a second reader in Phase 8, and a row that named pak's shapes
/// would assert them of an archive built differently.
#[must_use]
pub fn sha1_label(status: &paksmith_core::container::EntryIntegrity) -> String {
    use paksmith_core::container::EntryIntegrity;
    match status {
        // Names what is absent, not the structure it would have sat in
        // (pak reaches this via a v10+ bit-packed record; another
        // container will have its own hash-less form).
        EntryIntegrity::NotInIndex => "not recorded in the entry listing".to_string(),
        // ONE observation: this entry's field is zeroed. The row
        // deliberately says nothing about the archive. Reaching this
        // arm does depend on `claims_integrity() == false`, but that is
        // a single bit (pak: the footer hash) which surveys neither the
        // other entries nor the v10+ region hashes — every wording that
        // tried to describe it ended up asserting more than it checked.
        // What distinguishes this from `Stripped` is stated there, on
        // the arm that has evidence for it. It does
        // NOT name what the reader consulted to answer that — pak reads
        // one footer hash, a container with no archive-level claim at
        // all just inherits the trait default, and both are honestly
        // described as "claims no integrity" (earlier
        // wordings variously named pak's footer, surveyed structures
        // the row never inspected, and presupposed such a structure
        // exists).
        EntryIntegrity::NoClaim => "no claim (the entry's hash is zeroed)".to_string(),
        // Reports the two observed fields and stops there.
        // A strip is the alarming reading of this shape, and the pane
        // cannot establish that it is the only one — it sees two zeroed
        // fields, not the archive's provenance. Naming a strip would
        // turn an observation into an accusation the row cannot back.
        EntryIntegrity::Stripped => "zeroed, though the archive claims integrity".to_string(),
        // "covers on-disk bytes": the digest is over the stored form
        // (ciphertext when encrypted, compressed blocks when
        // compressed), so it will NOT match `sha1sum` of an extracted
        // file except for plain stored entries.
        EntryIntegrity::Claim(digest) => {
            format!("{digest} (unverified; covers on-disk bytes)")
        }
    }
}

/// The Info pane's entry rows as `(label, value)` pairs, in display
/// order (#662).
///
/// A PURE SEAM, for the reason `viewer_scroll` exists in `content.rs`:
/// `info_view` is `#[mutants::skip]` and returns an opaque `Element`,
/// so a swap of two `kv_row` arguments there is invisible to the whole
/// suite — that exact mutation survived a review probe in #660. Row
/// PRESENCE, ORDER and label-to-value PAIRING are the deliverable of
/// this change, so they are decided here where a test can see them, and
/// `info_view` only wraps each pair in a widget.
///
/// Row order follows the Phase 6 GUI-shell design doc's `detail.rs`
/// bullet (§View panels): path, sizes, compression (method folded in),
/// offset, SHA-1 status, and the encryption flag LAST.
#[must_use]
pub fn entry_rows(path: &str, meta: Option<&EntryMeta>) -> Vec<(&'static str, String)> {
    let Some(m) = meta else {
        // No EntryMeta — still show the path.
        return vec![(PATH_ROW_LABEL, path.to_owned())];
    };
    let ratio = compression_ratio(m.uncompressed_size, m.compressed_size)
        .unwrap_or_else(|| "\u{2014}".to_string());
    vec![
        (PATH_ROW_LABEL, path.to_owned()),
        (SIZE_ROW_LABEL, human_size(m.uncompressed_size)),
        (
            COMPRESSED_ROW_LABEL,
            compressed_label(
                m.is_compressed,
                m.compression_method.as_deref(),
                &human_size(m.compressed_size),
                &ratio,
            ),
        ),
        (OFFSET_ROW_LABEL, record_offset_label(m.offset)),
        (SHA1_ROW_LABEL, sha1_label(&m.integrity)),
        (
            ENCRYPTED_ROW_LABEL,
            if m.is_encrypted { "Yes" } else { "No" }.to_owned(),
        ),
    ]
}

/// Format the compression ratio as "N%" (rounded to nearest integer).
///
/// Returns `None` when `uncompressed == 0` to avoid division by zero.
pub fn compression_ratio(uncompressed: u64, compressed: u64) -> Option<String> {
    if uncompressed == 0 {
        return None;
    }
    // Ratio = compressed/uncompressed * 100, clamped to [0, 100].
    // u64 → f64 may lose precision for large sizes (> 2^53 bytes), but
    // ratios at that scale are still meaningfully accurate.
    // `round()` + `clamp(0.0, 100.0)` guarantees the value fits in [0, 100]
    // before the cast, so cast_possible_truncation and cast_sign_loss are safe.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let pct = (compressed as f64 / uncompressed as f64 * 100.0)
        .round()
        .clamp(0.0, 100.0) as u64;
    Some(format!("{pct}%"))
}

/// Build one key/value row in the metadata panel.
///
/// Both key and value are taken as owned `String` so the returned element
/// is `'static` — the caller doesn't need to keep them alive beyond the call.
pub(crate) fn kv_row(
    key: impl Into<String>,
    value: impl Into<String>,
) -> Element<'static, Message> {
    row![
        text(key.into())
            .size(f32::from(TEXT_SM))
            .width(Length::Fixed(DETAIL_LABEL_WIDTH))
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
            }),
        // `.width(Fill)` lets long paths wrap instead of overflowing the pane.
        text(value.into())
            .size(f32::from(TEXT_SM))
            .width(Length::Fill)
            .style(|theme: &iced::Theme| iced::widget::text::Style {
                color: Some(theme.palette().text),
            }),
    ]
    .spacing(SPACE_XS)
    .align_y(iced::Alignment::Start)
    .into()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── brief-specified tests (verbatim) ──────────────────────────────────────

    #[test]
    fn formats_size_human_readable() {
        assert_eq!(human_size(2_400_000), "2.4 MB");
        assert_eq!(human_size(512), "512 B");
    }

    // ── #662 detail rows ─────────────────────────────────────────────────────

    /// A fully-populated entry: compressed with a method name, a real
    /// offset, and every field distinct so a mis-paired row shows up.
    fn meta_fixture() -> EntryMeta {
        EntryMeta {
            uncompressed_size: 2_400_000,
            compressed_size: 1_200_000,
            is_compressed: true,
            is_encrypted: true,
            offset: Some(0x1A2B),
            compression_method: Some(std::sync::Arc::from("Zlib")),
            integrity: paksmith_core::container::EntryIntegrity::NotInIndex,
        }
    }

    /// The rows the Info pane actually renders: which ones, in what
    /// order, and — the part no other test can see — which label is
    /// paired with which VALUE. `info_view` is `#[mutants::skip]` and
    /// returns an opaque `Element`, so a swapped `kv_row` argument pair
    /// there is invisible; the identical mutation survived a review
    /// probe in #660. Every value here is distinctive, so a swap or a
    /// dropped row fails.
    ///
    /// Compares against the label CONSTANTS, not their text, on purpose:
    /// renaming a label should not fail an ordering test. The text is
    /// owned by `row_labels_keep_their_meaning_changing_qualifiers` —
    /// one property per test, not a redundant pair.
    #[test]
    fn entry_rows_pair_each_label_with_its_own_value_in_order() {
        let m = meta_fixture();
        let rows = entry_rows("Game/a.uasset", Some(&m));
        assert_eq!(
            rows,
            vec![
                (PATH_ROW_LABEL, "Game/a.uasset".to_string()),
                (SIZE_ROW_LABEL, "2.4 MB".to_string()),
                (COMPRESSED_ROW_LABEL, "Yes (Zlib, 1.2 MB, 50%)".to_string()),
                (OFFSET_ROW_LABEL, "0x1A2B".to_string()),
                (
                    SHA1_ROW_LABEL,
                    "not recorded in the entry listing".to_string()
                ),
                (ENCRYPTED_ROW_LABEL, "Yes".to_string()),
            ],
            "row set, order and label-to-value pairing are the deliverable"
        );
    }

    /// The Encrypted row's values are meaning-bearing in the same way
    /// the SHA-1 label's qualifier is: inverting them would report every
    /// encrypted entry as plaintext. This pins the FALSE half; the
    /// sibling ordering test covers the true half via `meta_fixture`,
    /// so an inverted ternary fails both.
    #[test]
    fn encrypted_row_says_yes_only_when_the_entry_is_encrypted() {
        let mut m = meta_fixture();
        m.is_encrypted = false;
        let rows = entry_rows("a", Some(&m));
        let (label, value) = rows.last().expect("rows are never empty");
        assert_eq!(*label, ENCRYPTED_ROW_LABEL);
        assert_eq!(value, "No");
    }

    // No GUI-side escaping or unknown-method-phrase test on purpose:
    // core owns the escaping (`display_escapes_hostile_unknown_names`,
    // four injection classes), and `compressed_label`'s `Some` arm
    // interpolates without inspecting the string — so a parenthesised
    // or quoted name composes through the identical path as "Zlib" and
    // could not fail independently of the assertion above.

    /// Without metadata the pane still names the entry — one row, the
    /// path, and no fabricated detail rows.
    #[test]
    fn entry_rows_without_metadata_show_only_the_path() {
        assert_eq!(
            entry_rows("Game/a.uasset", None),
            vec![(PATH_ROW_LABEL, "Game/a.uasset".to_string())]
        );
    }

    /// Both row labels carry a qualifier that changes what the row
    /// MEANS, so each is pinned verbatim: `(record)` distinguishes the
    /// record offset from the payload offset, and `(stored)` keeps a
    /// recorded claim from reading as a verification result. A tidying
    /// edit that shortens either — the plausible one, since both read
    /// as verbose — has to fail here. This is the ONLY test that reads
    /// the label text; the ordering test above deliberately compares
    /// against these constants instead.
    #[test]
    fn row_labels_keep_their_meaning_changing_qualifiers() {
        assert_eq!(OFFSET_ROW_LABEL, "Offset (record)");
        assert_eq!(SHA1_ROW_LABEL, "SHA-1 (stored)");
        // The plain four, pinned as TEXT: `entry_rows`'s own assertion
        // compares against these constants, so it would accept any
        // rename. These are what a user reads.
        assert_eq!(PATH_ROW_LABEL, "Path");
        assert_eq!(SIZE_ROW_LABEL, "Size");
        assert_eq!(COMPRESSED_ROW_LABEL, "Compressed");
        assert_eq!(ENCRYPTED_ROW_LABEL, "Encrypted");
    }

    #[test]
    fn record_offset_label_is_hex_or_em_dash() {
        // Uppercase hex with the 0x prefix — divergent from decimal at any
        // value with a letter digit, so a base swap cannot survive.
        assert_eq!(record_offset_label(Some(0x1A2B)), "0x1A2B");
        assert_eq!(record_offset_label(Some(0)), "0x0");
        assert_eq!(record_offset_label(None), "\u{2014}");
    }

    #[test]
    fn sha1_label_names_each_state() {
        use paksmith_core::container::EntryIntegrity;
        assert_eq!(
            sha1_label(&EntryIntegrity::NotInIndex),
            "not recorded in the entry listing"
        );
        assert_eq!(
            sha1_label(&EntryIntegrity::NoClaim),
            "no claim (the entry's hash is zeroed)"
        );
        assert_eq!(
            sha1_label(&EntryIntegrity::Stripped),
            "zeroed, though the archive claims integrity"
        );
        // No arm may name a container's wire shape: the enum is
        // generic and Phase 8 adds a second reader.
        for state in [
            EntryIntegrity::NotInIndex,
            EntryIntegrity::NoClaim,
            EntryIntegrity::Stripped,
        ] {
            let s = sha1_label(&state);
            // Bans one container's vocabulary, NOT generic structural
            // nouns: "entry listing" and "index" describe something every
            // container has, and forbidding them once forced the
            // NotInIndex arm into a claim that was false for pak v10+
            // (the in-data record still carries a hash). "footer" and
            // "index hash" are pak's own; "strip" is a verdict.
            for word in ["pak", "footer", "index hash", "strip"] {
                assert!(
                    !s.to_lowercase().contains(word),
                    "{state:?} names a format-specific fact or a verdict: {s}"
                );
            }
        }
        assert_eq!(
            sha1_label(&EntryIntegrity::Claim(paksmith_core::Sha1Digest::from(
                [0xABu8; 20]
            ))),
            // Lowercase hex plus the unverified qualifier: a stored claim
            // must never read as a checked verification result.
            format!("{} (unverified; covers on-disk bytes)", "ab".repeat(20))
        );
    }

    #[test]
    fn compressed_label_carries_method_size_and_ratio() {
        assert_eq!(compressed_label(false, None, "1 KB", "50%"), "No");
        // An uncompressed entry shows "No" even if a method string were
        // passed — the flag is the authority.
        assert_eq!(compressed_label(false, Some("Zlib"), "1 KB", "50%"), "No");
        assert_eq!(
            compressed_label(true, Some("Zlib"), "1.2 MB", "55%"),
            "Yes (Zlib, 1.2 MB, 55%)"
        );
        // Containers that record no method name still show the figures.
        assert_eq!(
            compressed_label(true, None, "1.2 MB", "55%"),
            "Yes (1.2 MB, 55%)"
        );
    }

    // ── additional coverage ───────────────────────────────────────────────────

    #[test]
    fn human_size_zero() {
        assert_eq!(human_size(0), "0 B");
    }

    #[test]
    fn human_size_exact_kb() {
        // 1000 B → "1 KB" (no decimal when frac is 0)
        assert_eq!(human_size(1_000), "1 KB");
    }

    #[test]
    fn human_size_kb_with_decimal() {
        // 1500 B → "1.5 KB"
        assert_eq!(human_size(1_500), "1.5 KB");
    }

    #[test]
    fn human_size_exact_mb() {
        assert_eq!(human_size(1_000_000), "1 MB");
    }

    #[test]
    fn human_size_gb() {
        assert_eq!(human_size(2_500_000_000), "2.5 GB");
    }

    #[test]
    fn human_size_just_below_kb() {
        assert_eq!(human_size(999), "999 B");
    }

    // ── compression ratio tests ───────────────────────────────────────────────

    #[test]
    fn ratio_zero_uncompressed_returns_none() {
        assert_eq!(compression_ratio(0, 0), None);
    }

    #[test]
    fn ratio_half() {
        assert_eq!(compression_ratio(1000, 500), Some("50%".to_string()));
    }

    #[test]
    fn ratio_capped_at_100() {
        // compressed > uncompressed (e.g. incompressible data) → clamped to 100%
        assert_eq!(compression_ratio(100, 150), Some("100%".to_string()));
    }

    #[test]
    fn ratio_identical_is_100() {
        assert_eq!(compression_ratio(1000, 1000), Some("100%".to_string()));
    }

    // ── human_size boundary mutant killers ────────────────────────────────────
    //
    // The surviving mutant replaces `< KB` with `<= KB` (and analogously for MB
    // and GB). At the exact boundary (e.g., 1_000) the correct behaviour is to
    // format as "1 KB"; the `<=` mutant would format 1_000 as "1000 B" (stays
    // in the bytes branch). Asserting both `value - 1` and `value` at each
    // threshold distinguishes `<` from `<=`.

    #[test]
    fn human_size_kb_boundary() {
        // 999 → bytes (< 1000); 1000 → KB (NOT bytes).
        assert_eq!(human_size(999), "999 B", "999 must stay in bytes");
        assert_eq!(human_size(1_000), "1 KB", "1000 must flip to KB");
    }

    #[test]
    fn human_size_mb_boundary() {
        // 999_999 → KB; 1_000_000 → MB.
        assert_eq!(human_size(999_999), "999.9 KB", "999_999 must still be KB");
        assert_eq!(human_size(1_000_000), "1 MB", "1_000_000 must flip to MB");
    }

    #[test]
    fn human_size_gb_boundary() {
        // 999_999_999 → MB; 1_000_000_000 → GB.
        assert_eq!(
            human_size(999_999_999),
            "999.9 MB",
            "999_999_999 must still be MB"
        );
        assert_eq!(
            human_size(1_000_000_000),
            "1 GB",
            "1_000_000_000 must flip to GB"
        );
    }
}
