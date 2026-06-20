//! AES-256-ECB decryption for encrypted UE paks. UE encrypts pak data with
//! AES-256 in ECB mode (each 16-byte block independent); encrypted regions are
//! padded to 16-byte alignment. Verified against trumank/repak.

use aes::Aes256;
use aes::cipher::{BlockDecrypt, KeyInit};
use zeroize::ZeroizeOnDrop;

/// A 32-byte AES-256 key. Zeroized on drop; `Debug` is redacted so the key
/// never lands in logs.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesKey([u8; 32]);

impl AesKey {
    /// Construct from raw key bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
    let cipher = Aes256::new(&key.0.into());
    for block in data.chunks_exact_mut(16) {
        let block_arr = aes::Block::from_mut_slice(block);
        cipher.decrypt_block(block_arr);
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
}
