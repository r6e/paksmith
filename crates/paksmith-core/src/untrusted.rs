//! Bounds for untrusted text — registry- and store-derived strings —
//! before it reaches a log field or an error message.

use std::borrow::Cow;

/// Characters of untrusted text [`clamp`] keeps before eliding the rest.
pub(crate) const MAX_UNTRUSTED_CHARS: usize = 64;

/// `s` cut to its first [`MAX_UNTRUSTED_CHARS`] chars plus `…`, or `s`
/// unchanged when it is no longer than that. Bounds length only; control
/// characters pass through.
#[must_use]
pub(crate) fn clamp(s: &str) -> Cow<'_, str> {
    match s.char_indices().nth(MAX_UNTRUSTED_CHARS) {
        Some((cut, _)) => Cow::Owned(format!("{}…", &s[..cut])),
        None => Cow::Borrowed(s),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{MAX_UNTRUSTED_CHARS, clamp};

    #[test]
    fn clamp_bounds_untrusted_values() {
        let long = "a".repeat(500);
        let out = clamp(&long);
        assert_eq!(out.chars().count(), 65, "64 chars plus the ellipsis");
        assert!(out.ends_with('…'));
        // Multi-byte input must not split a char.
        let wide = "é".repeat(500);
        let out = clamp(&wide);
        assert!(out.starts_with('é') && out.ends_with('…'));
        assert_eq!(out.chars().count(), 65);
    }

    #[test]
    fn clamp_keeps_exactly_the_bound() {
        assert!(matches!(clamp("dead"), Cow::Borrowed("dead")));

        let at_bound = "a".repeat(MAX_UNTRUSTED_CHARS);
        assert!(matches!(clamp(&at_bound), Cow::Borrowed(s) if s == at_bound));

        let over = "a".repeat(MAX_UNTRUSTED_CHARS + 1);
        assert_eq!(clamp(&over), format!("{at_bound}…"));
    }
}
