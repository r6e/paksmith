//! Hex text and bytes: ASCII digits of either case, two per byte, high nibble
//! first, lengths in BYTES. Each caller picks its prefix rule, length and error type.

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

/// Why [`parse_hex_bytes`] rejected its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HexError {
    /// The input was not `2 * N` bytes long; `got` is its byte length.
    WrongLength { got: usize },
    /// A byte outside `0-9`, `a-f` and `A-F`.
    NonHex,
}

/// `s` without one leading `0x`, or failing that one leading `0X`.
pub(crate) fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").or(s.strip_prefix("0X")).unwrap_or(s)
}

/// Exactly `2 * N` bytes of hex, no prefix or trimming; length checked first.
pub(crate) fn parse_hex_bytes<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    if s.len() != 2 * N {
        return Err(HexError::WrongLength { got: s.len() });
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().as_chunks::<2>().0) {
        *byte = decode_pair(*pair).ok_or(HexError::NonHex)?;
    }
    Ok(out)
}

/// Lowercase hex in one exact allocation: no outgrown buffer of key text is freed.
pub(crate) fn to_hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        #[expect(clippy::expect_used, reason = "fmt::Write to String is infallible")]
        write!(s, "{b:02x}").expect("write to String is infallible");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_lower_is_one_exact_allocation() {
        let s = to_hex_lower(&[0x01, 0xAB, 0xFF]);
        assert_eq!((s.as_str(), s.capacity()), ("01abff", 6));
    }

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
