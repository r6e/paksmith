//! Hex digit decoding: two ASCII digits of either case to one byte. Callers
//! keep their own prefix, length and error rules.

/// Two hex digits → one byte, high nibble first; `None` if either is not a
/// hex digit. Two nibbles are at most 0xFF, so this cannot overflow.
pub(crate) fn decode_pair([hi, lo]: [u8; 2]) -> Option<u8> {
    Some(nibble(hi)? * 16 + nibble(lo)?)
}

/// One hex digit → its nibble value. `None` for anything else, which is the
/// ONLY non-hex rejection — an `is_ascii_hexdigit` pre-check in a caller
/// would be redundant, and so an untestable branch.
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_pair_reads_the_high_nibble_first() {
        assert_eq!(decode_pair(*b"f0"), Some(0xF0));
        assert_eq!(decode_pair(*b"0F"), Some(0x0F));
        assert_eq!(decode_pair(*b"g0"), None);
        assert_eq!(decode_pair(*b"0g"), None);
    }

    /// `nibble` agrees with `char::to_digit(16)` on every byte, which accepts
    /// exactly the `u8::is_ascii_hexdigit` bytes.
    #[test]
    fn nibble_is_ascii_hexdigit_at_its_value() {
        for b in 0..=u8::MAX {
            assert_eq!(nibble(b).map(u32::from), char::from(b).to_digit(16));
        }
    }
}
