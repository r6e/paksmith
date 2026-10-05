//! Bounds for untrusted text — archive-, mappings-, registry- and
//! store-derived strings — before it reaches a log field or an error
//! message.

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

/// Fixtures for tests that check a name reaches output bounded.
#[cfg(test)]
pub(crate) mod test_support {
    use super::MAX_UNTRUSTED_CHARS;

    /// A name that runs past the bound: `{tag}KEPT` and an ESC sequence
    /// fill the first [`MAX_UNTRUSTED_CHARS`] chars, then `{tag}CUT`
    /// starts exactly at the bound. `tag` is at most 8 chars.
    pub(crate) fn hostile_name(tag: &str) -> String {
        let mut name = format!("{tag}KEPT\u{1b}[2J");
        name.push_str(&"x".repeat(MAX_UNTRUSTED_CHARS - name.chars().count()));
        name.push_str(tag);
        name.push_str("CUT");
        name
    }

    /// A `logs_assert` check: at least one line carries `message`, and
    /// each such line holds the [`hostile_name`] for `tag` clamped —
    /// `{tag}KEPT` present, `{tag}CUT` absent.
    #[cfg(feature = "__test_utils")]
    pub(crate) fn lines_clamped<'a>(
        message: &'a str,
        tag: &'a str,
    ) -> impl Fn(&[&str]) -> Result<(), String> + 'a {
        move |lines: &[&str]| {
            let (kept, cut) = (format!("{tag}KEPT"), format!("{tag}CUT"));
            let mut matched = lines.iter().filter(|l| l.contains(message)).peekable();
            if matched.peek().is_none() {
                return Err(format!("no `{message}` line was logged"));
            }
            match matched.find(|l| !l.contains(&kept) || l.contains(&cut)) {
                Some(line) => Err(format!("`{tag}` not clamped in {line:?}")),
                None => Ok(()),
            }
        }
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
    fn hostile_name_cuts_exactly_at_the_bound() {
        use super::test_support::hostile_name;

        let name = hostile_name("TAG");
        let (cut, _) = name.char_indices().nth(MAX_UNTRUSTED_CHARS).unwrap();
        assert!(name[..cut].starts_with("TAGKEPT\u{1b}[2J"), "{name:?}");
        assert_eq!(&name[cut..], "TAGCUT");
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
