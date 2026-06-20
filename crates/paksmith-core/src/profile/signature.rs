//! Ed25519 detached-signature verification for the registry payload.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::PaksmithError;
use crate::error::ProfileFault;

/// Compiled-in trusted ed25519 public key (32-byte, 64 lowercase hex chars).
///
/// This is a documented placeholder until a live paksmith registry exists.
/// The value is the verifying key of a throwaway keypair derived from seed
/// `[1u8; 32]` via `ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])`.
/// Production deployments override this via `[registry] public_key` in config.
pub(crate) const TRUSTED_REGISTRY_PUBKEY_HEX: &str =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

// Task 3 (registry fetch) will be the first call site; allow until then.
#[allow(dead_code)]
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if !chunk[0].is_ascii_hexdigit() || !chunk[1].is_ascii_hexdigit() {
            return None;
        }
        out[i] = u8::from_str_radix(
            // SAFETY: we just verified both bytes are ASCII hex digits
            std::str::from_utf8(chunk).ok()?,
            16,
        )
        .ok()?;
    }
    Some(out)
}

/// Verify a detached ed25519 signature over `payload` against `pubkey_hex`.
///
/// Returns `Ok(())` on success. Any failure — malformed hex, wrong key length,
/// wrong signature length, or signature mismatch — returns
/// [`ProfileFault::SignatureInvalid`]. Never panics on malformed input. Never
/// includes payload or key material in the error.
// Task 3 (registry fetch) will be the first call site; allow until then.
#[allow(dead_code)]
pub(crate) fn verify_detached(
    payload: &[u8],
    sig: &[u8],
    pubkey_hex: &str,
) -> Result<(), PaksmithError> {
    let fail = || PaksmithError::Profile {
        fault: ProfileFault::SignatureInvalid,
    };
    let key_bytes = decode_hex_32(pubkey_hex).ok_or_else(fail)?;
    let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|_| fail())?;
    let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| fail())?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(payload, &signature).map_err(|_| fail())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn test_keypair() -> (SigningKey, String) {
        // Deterministic 32-byte seed → reproducible test keypair (no rng dep).
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey_hex = hex_lower(sk.verifying_key().as_bytes());
        (sk, pubkey_hex)
    }

    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, pk) = test_keypair();
        let payload = b"registry-bytes";
        let sig = sk.sign(payload).to_bytes();
        assert!(verify_detached(payload, &sig, &pk).is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let (sk, pk) = test_keypair();
        let sig = sk.sign(b"registry-bytes").to_bytes();
        let err = verify_detached(b"registry-BYTES", &sig, &pk).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::SignatureInvalid
            }
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _) = test_keypair();
        let other = hex_lower(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let sig = sk.sign(b"x").to_bytes();
        assert!(matches!(
            verify_detached(b"x", &sig, &other).unwrap_err(),
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::SignatureInvalid
            }
        ));
    }

    #[test]
    fn malformed_sizes_error_not_panic() {
        let (_, pk) = test_keypair();
        assert!(verify_detached(b"x", &[0u8; 10], &pk).is_err()); // bad sig len (short)
        assert!(verify_detached(b"x", &[0u8; 65], &pk).is_err()); // bad sig len (long)
        assert!(verify_detached(b"x", &[], &pk).is_err()); // empty sig
        assert!(verify_detached(b"x", &[0u8; 64], "abcd").is_err()); // bad key hex len
        // 64 hex chars but one non-hex char ('g') — exercises the is_ascii_hexdigit guard.
        let non_hex = format!("g{}", &pk[1..]);
        assert!(verify_detached(b"x", &[0u8; 64], &non_hex).is_err());
    }

    /// Verify that `TRUSTED_REGISTRY_PUBKEY_HEX` is a canonical ed25519 key
    /// (not a random 32-byte value that `VerifyingKey::from_bytes` rejects).
    /// We prove this by signing with the matching signing key (seed `[1u8;32]`)
    /// and asserting the round-trip returns `Ok`.
    #[test]
    fn trusted_pubkey_const_is_valid() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let expected_hex = hex_lower(sk.verifying_key().as_bytes());
        assert_eq!(
            TRUSTED_REGISTRY_PUBKEY_HEX, expected_hex,
            "TRUSTED_REGISTRY_PUBKEY_HEX must match the verifying key of seed [1u8;32]"
        );
        // Round-trip: sign with the matching key, verify against the const.
        let sig = sk.sign(b"paksmith-registry").to_bytes();
        assert!(
            verify_detached(b"paksmith-registry", &sig, TRUSTED_REGISTRY_PUBKEY_HEX).is_ok(),
            "const must parse and verify correctly"
        );
    }
}
