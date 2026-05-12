//! SHA1 digest newtype for paksmith's domain-level integrity hashes.
//!
//! [`Sha1Digest`] wraps a raw `[u8; 20]` to:
//!
//! - Document the "all-zero sentinel = no integrity claim" semantic at
//!   the type level (via [`Sha1Digest::is_zero`] and
//!   [`Sha1Digest::ZERO`]).
//! - Provide a canonical hex [`std::fmt::Display`] for operator-facing
//!   logs, replacing scattered `hex(&[u8; 20])` helpers.
//! - Distinguish a domain SHA1 from any arbitrary 20-byte buffer in
//!   accessor and constructor signatures.
//!
//! Wire-format byte slices (e.g., raw FString bytes, GUIDs, on-disk
//! fixture bytes in tests) stay as `[u8; 20]` / `&[u8]` — they're not
//! cryptographic digests, just 20-byte regions that happen to be the
//! same width.

use std::fmt;

/// SHA1 digest (20 bytes).
///
/// UE writers leave per-entry and per-index SHA1 slots zero-filled when
/// integrity hashing was not enabled at archive-creation time. This is
/// the "no integrity claim was recorded" signal, distinct from "this
/// is a real digest that happens to be all zeros" (which is
/// cryptographically negligible — a uniformly random SHA1 collides
/// with `[0; 20]` once per `2^160` digests). The
/// [`PakReader::verify_index`](crate::container::pak::PakReader::verify_index)
/// and [`verify_entry`](crate::container::pak::PakReader::verify_entry)
/// paths gate on [`Self::is_zero`] for that reason.
///
/// Construct via `From<[u8; 20]>` or [`Self::ZERO`]. Read the
/// underlying bytes via [`Self::as_bytes`]. `Display` renders as
/// lowercase 40-char hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha1Digest([u8; 20]);

impl Sha1Digest {
    /// The all-zero digest sentinel ("no integrity claim recorded").
    pub const ZERO: Self = Self([0u8; 20]);

    /// True iff this digest is the all-zero sentinel. Consumers MUST
    /// gate on this rather than comparing against a hardcoded
    /// `[0; 20]` — the comparison is what `verify_entry` / `verify_index`
    /// use to distinguish "no integrity claim" from "tampered slot."
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Borrow the underlying 20 bytes. Use sparingly — most call sites
    /// should compare two `Sha1Digest`s directly (via `PartialEq`) or
    /// emit via `Display`.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl From<[u8; 20]> for Sha1Digest {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Sha1Digest {
    /// Lowercase hex encoding (40 ASCII chars). Stable across refactors:
    /// any tooling that greps for SHA1 hex strings in logs keeps working.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert!(Sha1Digest::ZERO.is_zero());
        assert!(Sha1Digest::from([0u8; 20]).is_zero());
    }

    #[test]
    fn non_zero_is_not_zero() {
        // Even a single non-zero bit should disqualify.
        let mut bytes = [0u8; 20];
        bytes[19] = 1;
        assert!(!Sha1Digest::from(bytes).is_zero());

        bytes = [0u8; 20];
        bytes[0] = 1;
        assert!(!Sha1Digest::from(bytes).is_zero());
    }

    #[test]
    fn display_is_lowercase_hex() {
        let bytes: [u8; 20] = [
            0x16, 0x31, 0x27, 0x51, 0xef, 0x93, 0x07, 0xc3, 0xfd, 0x1a, 0xfb, 0xcb, 0x99, 0x3c,
            0xdc, 0x80, 0x46, 0x4b, 0xa0, 0xf1,
        ];
        let digest = Sha1Digest::from(bytes);
        assert_eq!(
            digest.to_string(),
            "16312751ef9307c3fd1afbcb993cdc80464ba0f1"
        );
    }

    #[test]
    fn display_zero() {
        assert_eq!(
            Sha1Digest::ZERO.to_string(),
            "0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn equality_via_bytes() {
        let a = Sha1Digest::from([0xAA; 20]);
        let b = Sha1Digest::from([0xAA; 20]);
        let c = Sha1Digest::from([0xBB; 20]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn as_bytes_round_trips() {
        let bytes = [0x11u8; 20];
        let digest = Sha1Digest::from(bytes);
        assert_eq!(*digest.as_bytes(), bytes);
    }
}
