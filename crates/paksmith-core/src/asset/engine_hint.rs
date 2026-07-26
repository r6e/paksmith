//! Typed engine-version hint — an OUT-OF-BAND signal (a game
//! profile's stored `engine_version`) that refines wire-version gates
//! the package bytes cannot disambiguate (issue #656).
//!
//! Lives asset-side, not profile-side, because the parser is the
//! consumer: `profile` parses strings into this type, `asset` gates on
//! it. The reverse dependency would invert the crate's layering.
//!
//! The WIRE type stays `Option<String>`: a strict serde type would turn
//! one hand-edited value into `CorruptStore` for the whole document
//! (store parse failure is all-or-nothing), the TOML round-trip pins
//! `engine_version = "5.3"` byte-exactly, and the ed25519-signed
//! registry schema can never change. Parsing happens leniently at
//! RESOLUTION time instead — an unparsable string degrades to `None`
//! with a warning, never an error, because registry-authored strings
//! are untrusted input.
//!
//! Distinct from [`crate::asset::EngineVersion`], the wire
//! `FEngineVersion` (5 fields incl. changelist + branch) read from a
//! package summary; this type is the 2-3 component human form users
//! store in profiles.

/// A parsed `major.minor[.patch]` engine version from a profile.
///
/// Ordered comparisons use [`UeVersion::at_least`]; `patch` is carried
/// for display fidelity but deliberately ignored by gates (no known
/// wire difference is patch-scoped).
///
/// Note the derived equality is EXACT, so `"5.3"` and `"5.3.0"` are
/// different values even though every gate treats them identically —
/// compare through [`UeVersion::at_least`], not `==`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UeVersion {
    /// Engine major version (4 or 5 for every supported asset).
    pub major: u32,
    /// Engine minor version.
    pub minor: u32,
    /// Optional patch component (`"5.3.2"`), display-only.
    pub patch: Option<u32>,
}

impl UeVersion {
    /// Parse a stored profile string leniently: optional
    /// case-insensitive `UE` prefix, then `major.minor` or
    /// `major.minor.patch`, surrounding whitespace ignored. `None` for
    /// anything else — the caller warns and proceeds unhinted.
    pub fn parse_lenient(s: &str) -> Option<Self> {
        let s = s.trim();
        // One case-insensitive two-char prefix. `str::get` yields
        // None when byte 2 is past the end or falls INSIDE a char (a
        // leading 3- or 4-byte one), so both cases fall through to the
        // no-prefix path instead of panicking. A 2-byte leading char
        // ends exactly at byte 2, so it yields `Some` and simply fails
        // the ASCII compare. The `&s[2..]` index inside the arm is
        // reachable only after `get` proved byte 2 is a boundary.
        let s = match s.get(..2) {
            Some(p) if p.eq_ignore_ascii_case("UE") => &s[2..],
            _ => s,
        }
        .trim_start();
        let mut parts = s.split('.');
        let major: u32 = parts.next()?.parse().ok()?;
        let minor: u32 = parts.next()?.parse().ok()?;
        let patch: Option<u32> = match parts.next() {
            Some(p) => Some(p.parse().ok()?),
            None => None,
        };
        if parts.next().is_some() {
            return None; // four components is not a UE version
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// True iff this version is `major.minor` or later (patch ignored:
    /// no supported wire difference is patch-scoped).
    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }
}

impl std::fmt::Display for UeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.patch {
            Some(p) => write!(f, "{}.{}.{}", self.major, self.minor, p),
            None => write!(f, "{}.{}", self.major, self.minor),
        }
    }
}

/// What a package's own object versions say about an engine-version
/// gate — a THREE-state answer, because "the proxy is false" and "the
/// wire cannot tell" are different facts with different consequences.
///
/// Collapsing them into one boolean is the bug this enum exists to
/// prevent: a profile declaring 5.3 must refine the genuinely
/// ambiguous case, and must NOT disturb a package whose wire version
/// says plainly that the field is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireVerdict {
    /// The object versions unambiguously place the package at or above
    /// the gate: the field IS on the wire. A hint cannot override this
    /// — the bytes outrank a fallible human annotation.
    Asserts,
    /// The object versions unambiguously place the package below the
    /// gate: the field is NOT on the wire. A hint cannot override this
    /// either, so declaring a newer engine can never desync an older
    /// package (e.g. reusing a UE5.3 profile for its AES key over UE4
    /// content).
    Denies,
    /// The object versions cannot distinguish — two engine versions
    /// serialize the same value and only one writes the field. This is
    /// the ONLY state a hint decides.
    Ambiguous,
}

/// Resolve an ENGINE-version gate against the wire's verdict and the
/// profile's declaration.
///
/// [`WireVerdict::Ambiguous`] is the only state the hint decides; with
/// no hint it resolves `false`, which is paksmith's established
/// default, so every unhinted parse is byte-for-byte what it was
/// before hints existed.
///
/// # Scope: this resolves FALSE-NEGATIVE residuals only
///
/// It answers "the wire cannot tell, does this engine write the
/// field?". Several catalogued residuals are the opposite shape — the
/// object-version proxy OVER-fires (e.g. UE 4.19 sharing object
/// version 516 with 4.20, or 517 standing in for the 4.23
/// VirtualTextures boundary), so resolving them means SUPPRESSING a
/// gate the wire asserts. That inverts the safety argument above and
/// needs its own resolver with its own justification; do not reach for
/// this one.
///
/// # Scope: version-only, no per-game overrides
///
/// CUE4Parse gates can name specific titles (`bSerializeMipData` is
/// `Ar.Game >= GAME_UE5_3 || Ar.Game == GAME_TheFirstDescendant`). A
/// declared `major.minor` cannot express that clause, so a title that
/// opts in below its nominal engine version still needs a per-game
/// override this type does not model.
#[must_use]
pub fn resolve_engine_gate(
    wire: WireVerdict,
    hint: Option<UeVersion>,
    major: u32,
    minor: u32,
) -> bool {
    match wire {
        WireVerdict::Asserts => true,
        WireVerdict::Denies => false,
        WireVerdict::Ambiguous => hint.is_some_and(|h| h.at_least(major, minor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_stored_forms_in_the_wild() {
        // "5.3" and "4.27" are the two forms existing stores carry.
        assert_eq!(
            UeVersion::parse_lenient("5.3"),
            Some(UeVersion {
                major: 5,
                minor: 3,
                patch: None
            })
        );
        assert_eq!(
            UeVersion::parse_lenient("4.27"),
            Some(UeVersion {
                major: 4,
                minor: 27,
                patch: None
            })
        );
    }

    #[test]
    fn parses_patch_and_prefix_and_whitespace() {
        assert_eq!(
            UeVersion::parse_lenient(" UE 5.3.2 "),
            Some(UeVersion {
                major: 5,
                minor: 3,
                patch: Some(2)
            })
        );
        // All four case spellings of the prefix, so a dropped arm is
        // observable (each `strip_prefix` is otherwise unpinned).
        for spelling in ["UE4.27", "ue4.27", "Ue4.27", "uE4.27"] {
            assert_eq!(
                UeVersion::parse_lenient(spelling),
                Some(UeVersion {
                    major: 4,
                    minor: 27,
                    patch: None
                }),
                "prefix spelling {spelling:?}"
            );
        }
    }

    #[test]
    fn multibyte_leading_chars_fall_through_without_panicking() {
        // The prefix probe indexes byte 2. Pin both shapes the comment
        // describes: a 3-byte leading char (byte 2 falls INSIDE it, so
        // `get` yields None) and a 2-byte one (byte 2 is a boundary, so
        // `get` yields Some and the ASCII compare simply fails). Either
        // way the value is rejected rather than panicking.
        for bad in ["\u{20ac}5.3", "\u{e9}5.3", "\u{1f600}5.3"] {
            assert_eq!(UeVersion::parse_lenient(bad), None, "input: {bad:?}");
        }
        // And a multi-byte char AFTER a real prefix stays harmless.
        assert_eq!(UeVersion::parse_lenient("UE\u{20ac}"), None);
    }

    #[test]
    fn rejects_non_versions() {
        for bad in ["", "5", "abc", "5.x", "5.3.2.1", "5..3", "-5.3", "5.-3"] {
            assert_eq!(UeVersion::parse_lenient(bad), None, "input: {bad:?}");
        }
    }

    #[test]
    fn at_least_orders_by_major_then_minor_ignoring_patch() {
        let v52 = UeVersion::parse_lenient("5.2").unwrap();
        let v53 = UeVersion::parse_lenient("5.3").unwrap();
        let patched = UeVersion::parse_lenient("5.3.2").unwrap();
        let v427 = UeVersion::parse_lenient("4.27").unwrap();
        assert!(!v52.at_least(5, 3));
        assert!(v53.at_least(5, 3));
        assert!(patched.at_least(5, 3), "patch ignored");
        assert!(v53.at_least(5, 2), "later minor satisfies earlier gate");
        assert!(!v427.at_least(5, 0), "major dominates minor 27");
        assert!(v427.at_least(4, 20));
    }

    #[test]
    fn only_the_ambiguous_verdict_consults_the_hint() {
        let v52 = UeVersion::parse_lenient("5.2");
        let v53 = UeVersion::parse_lenient("5.3");
        // Asserts: the wire wins, whatever the profile claims.
        for hint in [None, v52, v53] {
            assert!(resolve_engine_gate(WireVerdict::Asserts, hint, 5, 3));
        }
        // Denies: the wire wins here too — a newer profile must NOT
        // make an older package read a field it never wrote.
        for hint in [None, v52, v53] {
            assert!(!resolve_engine_gate(WireVerdict::Denies, hint, 5, 3));
        }
        // Ambiguous: the hint decides, defaulting false without one.
        assert!(!resolve_engine_gate(WireVerdict::Ambiguous, None, 5, 3));
        assert!(!resolve_engine_gate(WireVerdict::Ambiguous, v52, 5, 3));
        assert!(resolve_engine_gate(WireVerdict::Ambiguous, v53, 5, 3));
    }

    #[test]
    fn display_round_trips_both_arities() {
        for s in ["5.3", "4.27", "5.3.2"] {
            assert_eq!(UeVersion::parse_lenient(s).unwrap().to_string(), s);
        }
    }
}
