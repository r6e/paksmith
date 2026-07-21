//! Test a candidate AES key against a pak: open + verify the index hash.

use std::path::Path;

use crate::container::pak::{PakReader, VerifyOutcome};
use crate::{AesKey, PaksmithError};

/// Result of testing a candidate AES key against a pak archive.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyTestOutcome {
    /// Opened and the index SHA-1 matched the decrypted plaintext.
    Verified,
    /// Opened, but the pak stores no index hash to verify against.
    ///
    /// A zeroed hash slot can be forced by a downgrade attack, so this
    /// outcome is intentionally weaker than [`Self::Verified`] — the key
    /// decrypted the index but we cannot confirm integrity.
    Decrypted,
    /// The key did not decrypt the index (wrong key).
    WrongKey,
    /// The pak uses a layout this build cannot decrypt (e.g. v10+
    /// encrypted index) — the key may be correct but cannot be tested.
    Unsupported,
}

/// Open `pak` with `key` and verify its index hash. See [`KeyTestOutcome`].
///
/// Maps outcomes as follows:
/// - Index hash matches → [`KeyTestOutcome::Verified`]
/// - Index opened but no hash to check → [`KeyTestOutcome::Decrypted`]
///   (intentionally NOT `Verified` — a zeroed hash slot cannot confirm integrity)
/// - [`PaksmithError::Decryption`] from open → [`KeyTestOutcome::WrongKey`]
/// - [`PaksmithError::UnsupportedFeature`] from open → [`KeyTestOutcome::Unsupported`]
/// - Any other error → [`KeyTestOutcome::Unsupported`] (the key is not the problem)
pub fn test_key<P: AsRef<Path>>(pak: P, key: &AesKey) -> KeyTestOutcome {
    let reader = match PakReader::open_with_key(pak, key.clone()) {
        Ok(r) => r,
        Err(PaksmithError::Decryption { .. }) => return KeyTestOutcome::WrongKey,
        // UnsupportedFeature (e.g. a V9 frozen index) and any other open
        // error both map to Unsupported — the key is not the problem.
        Err(_) => return KeyTestOutcome::Unsupported,
    };
    match reader.verify_index() {
        Ok(VerifyOutcome::Verified) => KeyTestOutcome::Verified,
        // SkippedNoHash and any future VerifyOutcome variant both map to
        // Decrypted (weaker than Verified — no hash to check against).
        Ok(_) => KeyTestOutcome::Decrypted,
        Err(PaksmithError::Decryption { .. }) => KeyTestOutcome::WrongKey,
        Err(_) => KeyTestOutcome::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AesKey;
    use crate::container::pak::PakReader;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }
    const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

    #[test]
    fn test_key_verified_with_correct_key() {
        let key = AesKey::from_hex(KEY).unwrap();
        let out = test_key(fixture("real_v8b_encrypted_index.pak"), &key);
        assert_eq!(
            out,
            KeyTestOutcome::Verified,
            "correct key on UnrealPak fixture must Verify"
        );
    }

    #[test]
    fn test_key_wrong_key_is_wrongkey() {
        let key = AesKey::from_hex(&"00".repeat(32)).unwrap();
        let out = test_key(fixture("real_v8b_encrypted_index.pak"), &key);
        assert_eq!(out, KeyTestOutcome::WrongKey);
    }

    #[test]
    fn read_footer_guid_returns_some_for_v8b() {
        // v8b is >= v7 so a GUID field is present (all-zero for this fixture).
        let guid = PakReader::read_footer_guid(fixture("real_v8b_encrypted_index.pak")).unwrap();
        assert_eq!(
            guid,
            Some([0u8; 16]),
            "fixture uses the default (all-zero) GUID"
        );
    }

    /// Zeroing the footer `index_hash` field (without touching ciphertext) causes
    /// `verify_index` to see a zero hash and return `SkippedNoHash`, which
    /// `test_key` maps to `Decrypted` (not `Verified` — integrity cannot be confirmed).
    ///
    /// V8B+ footer layout: magic(4) + version(4) + index_offset(8) +
    /// index_size(8) + index_hash(20) → hash field starts at footer_start + 24.
    #[test]
    fn read_footer_guid_returns_none_for_pre_v7() {
        // The encryption-key GUID field was added in pak v7. A v3 footer has
        // no GUID, so read_footer_guid must return None. Pins the function
        // against the `Ok(Some([0;16]))` mutant (which the v8b all-zero test
        // cannot, since Some([0;16]) is its own expected value).
        let guid = PakReader::read_footer_guid(fixture("real_v3_minimal.pak")).unwrap();
        assert_eq!(guid, None, "pre-v7 paks have no encryption-key GUID field");
    }

    #[test]
    fn test_key_zeroed_index_hash_returns_decrypted() {
        let fixture_bytes =
            std::fs::read(fixture("real_v8b_encrypted_index.pak")).expect("read encrypted fixture");
        let magic = b"\xe1\x12\x6f\x5a";
        let footer_start = fixture_bytes
            .windows(4)
            .rposition(|w| w == magic)
            .expect("footer magic must be present in fixture");
        let hash_start = footer_start + 24;
        let hash_end = hash_start + 20;
        assert!(
            hash_end <= fixture_bytes.len(),
            "index_hash field must fit within fixture"
        );

        let mut patched = fixture_bytes;
        patched[hash_start..hash_end].fill(0x00);

        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(tmp.path(), &patched).expect("write patched fixture");

        let key = AesKey::from_hex(KEY).unwrap();
        let out = test_key(tmp.path(), &key);
        assert_eq!(
            out,
            KeyTestOutcome::Decrypted,
            "zeroed index_hash: index decrypts fine but hash cannot be verified → must be Decrypted"
        );
    }

    /// A v11 (path-hash index) encrypted pak now decrypts with the correct
    /// key (#635) and its index hash matches → `Verified`. Previously this
    /// surfaced as `Unsupported` (the v10+ encrypted-index deferral, now
    /// retired).
    #[test]
    fn test_key_v11_encrypted_index_with_correct_key_is_verified() {
        let key = AesKey::from_hex(KEY).unwrap();
        let out = test_key(fixture("real_v11_encrypted_index.pak"), &key);
        assert_eq!(
            out,
            KeyTestOutcome::Verified,
            "v11 encrypted-index pak with the correct key decrypts and its index hash verifies"
        );
    }

    /// A WRONG key on a v11 encrypted index fails the decrypt (garbage
    /// plaintext fails the primary-index parse) → `WrongKey`.
    #[test]
    fn test_key_v11_encrypted_index_with_wrong_key_is_wrongkey() {
        let wrong = AesKey::from_hex(&"00".repeat(32)).unwrap();
        let out = test_key(fixture("real_v11_encrypted_index.pak"), &wrong);
        assert_eq!(
            out,
            KeyTestOutcome::WrongKey,
            "wrong key on a v11 encrypted index must map to WrongKey (Decryption)"
        );
    }
}
