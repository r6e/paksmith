//! AES-256-ECB decryption for encrypted UE paks. UE encrypts pak data with
//! AES-256 in ECB mode (each 16-byte block independent); encrypted regions are
//! padded to 16-byte alignment. Verified against trumank/repak.

use aes::Aes256;
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use zeroize::ZeroizeOnDrop;

/// A 32-byte AES-256 key. Zeroized on drop; `Debug` is redacted so the key
/// never lands in logs.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesKey([u8; 32]);

/// Failure decoding a hex AES-256 key. Carries no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AesKeyHexError {
    /// The hex string (after stripping an optional `0x`/`0X`) was not 64 chars.
    WrongLength {
        /// Number of hex chars seen (excluding the prefix).
        got: usize,
    },
    /// A non-hex character was present.
    NonHex,
}

impl std::fmt::Display for AesKeyHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLength { got } => {
                write!(f, "expected 64 hex chars (32 bytes), got {got}")
            }
            Self::NonHex => f.write_str("key contains non-hex characters"),
        }
    }
}

impl std::error::Error for AesKeyHexError {}

impl AesKey {
    /// Construct from raw key bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Decode a 64-hex-char AES-256 key (optional `0x`/`0X` prefix,
    /// case-insensitive). Never includes key material in the error.
    ///
    /// # Panics
    ///
    /// Does not panic in practice. The two `.expect()` calls inside are
    /// unreachable: `from_utf8` is called on a 2-byte slice that has already
    /// been validated to be ASCII hex digits, and `from_str_radix` is called
    /// on that same ASCII-validated hex pair.
    pub fn from_hex(s: &str) -> Result<Self, AesKeyHexError> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if hex.len() != 64 {
            return Err(AesKeyHexError::WrongLength { got: hex.len() });
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            if !chunk[0].is_ascii_hexdigit() || !chunk[1].is_ascii_hexdigit() {
                return Err(AesKeyHexError::NonHex);
            }
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).expect("ascii-validated above"),
                16,
            )
            .expect("ascii-hex pair always parses");
        }
        Ok(Self::new(bytes))
    }

    /// Lowercase 64-char hex of the key. Crate-internal: used ONLY by the
    /// profile serializer to write the profile store. Not public — keeps the
    /// no-public-byte-accessor invariant.
    pub(crate) fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in self.0 {
            write!(s, "{b:02x}").expect("write to String is infallible");
        }
        s
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesKey(<redacted>)")
    }
}

/// Decrypt `data` in place as AES-256-ECB. `data.len()` MUST be a multiple of
/// 16 (encrypted pak regions are 16-byte aligned). Returns
/// [`crate::PaksmithError::Decryption`] on unaligned input rather than panicking.
pub(crate) fn aes256_ecb_decrypt(key: &AesKey, data: &mut [u8]) -> crate::Result<()> {
    if !data.len().is_multiple_of(16) {
        return Err(crate::PaksmithError::Decryption { path: None });
    }
    // `key.0.into()` copies the 32 key bytes into a `GenericArray` stack
    // temporary. The temporary is not explicitly zeroized after `Aes256::new`
    // absorbs it — this is a bounded-duration stack residue. The round-key
    // schedule inside `cipher` IS zeroized on drop (via the `aes/zeroize`
    // feature), as is the `AesKey` field on `PakReader`. For paksmith's
    // local-extractor threat model, this is an accepted trade-off.
    let cipher = Aes256::new(&key.0.into());
    for block in data.chunks_exact_mut(16) {
        let block_arr = <&mut aes::Block>::try_from(block)
            .expect("chunks_exact_mut(16) guarantees 16-byte slices");
        cipher.decrypt_block(block_arr);
    }
    Ok(())
}

/// AES-256-ECB ENCRYPT — the inverse of [`aes256_ecb_decrypt`], for
/// synthesizing encrypted entry payloads in tests (there is no
/// production encrypt path; paksmith is read-only). `data.len()` MUST be
/// a multiple of 16, matching the decrypt contract; returns
/// [`crate::PaksmithError::Decryption`] on unaligned input rather than
/// panicking. Gated on `all(test, __test_utils)` — it has only in-source
/// test users, so it never ships in the library and never appears as a
/// compiled-but-unused item in a non-test `--all-features` build.
#[cfg(all(test, feature = "__test_utils"))]
pub(crate) fn aes256_ecb_encrypt(key: &AesKey, data: &mut [u8]) -> crate::Result<()> {
    use aes::cipher::BlockCipherEncrypt;

    if !data.len().is_multiple_of(16) {
        return Err(crate::PaksmithError::Decryption { path: None });
    }
    let cipher = Aes256::new(&key.0.into());
    for block in data.chunks_exact_mut(16) {
        let block_arr = <&mut aes::Block>::try_from(block)
            .expect("chunks_exact_mut(16) guarantees 16-byte slices");
        cipher.encrypt_block(block_arr);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS-197 AES-256 known-answer (ECB single block):
    // key   = 000102...1f (32 bytes), plaintext = 00112233...eeff (16 bytes),
    // ciphertext = 8ea2b7ca516745bfeafc49904b496089.
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const PLAIN: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const CIPHER: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    #[test]
    fn decrypts_fips197_known_vector() {
        let key = AesKey::new(KEY);
        let mut data = CIPHER;
        aes256_ecb_decrypt(&key, &mut data).unwrap();
        assert_eq!(data, PLAIN);
    }

    /// The test-only encrypt helper must be the exact inverse of decrypt:
    /// it turns the FIPS-197 plaintext into the known ciphertext, and
    /// `decrypt(encrypt(x)) == x` round-trips. Pins that the helper
    /// actually enciphers (a no-op body would leave `PLAIN != CIPHER`).
    #[cfg(feature = "__test_utils")]
    #[test]
    fn encrypt_is_inverse_of_decrypt() {
        let key = AesKey::new(KEY);
        let mut data = PLAIN;
        aes256_ecb_encrypt(&key, &mut data).unwrap();
        assert_eq!(data, CIPHER, "encrypt must produce the FIPS-197 ciphertext");
        aes256_ecb_decrypt(&key, &mut data).unwrap();
        assert_eq!(data, PLAIN, "decrypt(encrypt(x)) must round-trip");
    }

    /// Encrypt rejects unaligned input with a typed error, not a panic —
    /// same contract as decrypt (pins the length guard).
    #[cfg(feature = "__test_utils")]
    #[test]
    fn encrypt_unaligned_length_errors_not_panics() {
        let key = AesKey::new(KEY);
        let mut data = [0u8; 17];
        assert!(matches!(
            aes256_ecb_encrypt(&key, &mut data),
            Err(crate::PaksmithError::Decryption { .. })
        ));
    }

    #[test]
    fn multi_block_is_per_block_ecb() {
        // Two identical ciphertext blocks decrypt to two identical plaintext blocks.
        let key = AesKey::new(KEY);
        let mut data = [CIPHER, CIPHER].concat();
        aes256_ecb_decrypt(&key, &mut data).unwrap();
        assert_eq!(&data[..16], &PLAIN);
        assert_eq!(&data[16..], &PLAIN);
    }

    #[test]
    fn unaligned_length_errors_not_panics() {
        let key = AesKey::new(KEY);
        let mut data = [0u8; 17];
        assert!(matches!(
            aes256_ecb_decrypt(&key, &mut data),
            Err(crate::PaksmithError::Decryption { .. })
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let key = AesKey::new(KEY);
        assert_eq!(format!("{key:?}"), "AesKey(<redacted>)");
    }

    #[test]
    fn from_hex_roundtrips_with_to_hex() {
        let hex = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
        let key = AesKey::from_hex(hex).expect("valid 64-hex key");
        assert_eq!(
            key.to_hex(),
            hex,
            "to_hex must round-trip from_hex (lowercase)"
        );
    }

    #[test]
    fn from_hex_accepts_0x_prefix_and_uppercase() {
        let lower = AesKey::from_hex("ab".repeat(32).as_str()).unwrap();
        let prefixed = AesKey::from_hex(&format!("0X{}", "AB".repeat(32))).unwrap();
        assert_eq!(
            lower.to_hex(),
            prefixed.to_hex(),
            "0x prefix + uppercase decode identically"
        );
    }

    #[test]
    fn from_hex_rejects_wrong_length_and_non_hex() {
        assert!(matches!(
            AesKey::from_hex(&"ab".repeat(31)),
            Err(AesKeyHexError::WrongLength { got: 62 })
        ));
        assert!(matches!(
            AesKey::from_hex(&format!("0x{}", "ab".repeat(31))),
            Err(AesKeyHexError::WrongLength { got: 62 })
        ));
        assert!(matches!(
            AesKey::from_hex(&format!("g{}", "a".repeat(63))),
            Err(AesKeyHexError::NonHex)
        ));
    }

    #[test]
    fn aes_key_hex_error_display_has_no_key_material() {
        let e = AesKeyHexError::WrongLength { got: 10 };
        assert!(
            e.to_string().contains("64"),
            "message names the expected length: {e}"
        );
    }
}
