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

use serde::{Deserialize, Serialize};

/// A parsed `major.minor[.patch]` engine version from a profile.
///
/// Ordered comparisons use [`UeVersion::at_least`]; `patch` is carried
/// for display fidelity but deliberately ignored by gates (no known
/// wire difference is patch-scoped).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        let s = s
            .strip_prefix("UE")
            .or_else(|| s.strip_prefix("ue"))
            .or_else(|| s.strip_prefix("Ue"))
            .or_else(|| s.strip_prefix("uE"))
            .unwrap_or(s)
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

/// Resolve an ENGINE-version gate that the package's own object
/// versions only approximate.
///
/// `wire` is the established object-version proxy; `hint` is the
/// profile's declaration. The result is `wire || hint >= major.minor`
/// — deliberately monotone: a hint can only ADD a gate the wire
/// missed, never remove one the wire asserts.
///
/// That asymmetry is the safety property. The bytes are ground truth
/// for what they contain; a profile is a fallible human annotation, so
/// a profile contradicting an unambiguous wire signal loses. Where the
/// wire is genuinely ambiguous (the whole point of a hint) the proxy
/// reads `false` and the hint decides. With no hint the expression
/// collapses to `wire`, so every unhinted parse is byte-for-byte what
/// it was before hints existed.
#[must_use]
pub fn resolve_engine_gate(wire: bool, hint: Option<UeVersion>, major: u32, minor: u32) -> bool {
    wire || hint.is_some_and(|h| h.at_least(major, minor))
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
        assert_eq!(
            UeVersion::parse_lenient("ue4.27"),
            Some(UeVersion {
                major: 4,
                minor: 27,
                patch: None
            })
        );
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
    fn engine_gate_is_monotone_over_the_wire_proxy() {
        let v52 = UeVersion::parse_lenient("5.2");
        let v53 = UeVersion::parse_lenient("5.3");
        // No hint: collapses to the wire, both polarities.
        assert!(resolve_engine_gate(true, None, 5, 3));
        assert!(!resolve_engine_gate(false, None, 5, 3));
        // Hint ADDS a gate the ambiguous wire missed.
        assert!(resolve_engine_gate(false, v53, 5, 3));
        assert!(!resolve_engine_gate(false, v52, 5, 3));
        // Hint NEVER removes one the wire asserts (contradiction loses).
        assert!(resolve_engine_gate(true, v52, 5, 3));
    }

    #[test]
    fn display_round_trips_both_arities() {
        for s in ["5.3", "4.27", "5.3.2"] {
            assert_eq!(UeVersion::parse_lenient(s).unwrap().to_string(), s);
        }
    }
}
