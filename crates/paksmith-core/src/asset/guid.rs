//! `FGuid` — UE's 128-bit identifier as four LE u32s.
//!
//! Wire shape: 16 bytes interpreted as four little-endian u32s
//! `(A, B, C, D)`. `Display` renders the canonical 8-4-4-4-12 form
//! `{A:08x}-{B>>16:04x}-{B&0xFFFF:04x}-{C>>16:04x}-{C&0xFFFF:04x}{D:08x}`,
//! matching UE's `FGuid::ToString(EGuidFormats::DigitsWithHyphens)`
//! and CUE4Parse's `FGuid` renderer. `Serialize` delegates to
//! `Display` via `collect_str` so the JSON output matches.

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

/// UE's 128-bit identifier. Equality and hashing are byte-level.
///
/// Stored as raw bytes for round-trip fidelity; `Display`/`Serialize`
/// interpret the bytes as four LE u32s (`A`, `B`, `C`, `D`) per UE's
/// `FGuid::ToString(DigitsWithHyphens)` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FGuid {
    /// Raw 16 bytes in disk/wire order.
    bytes: [u8; 16],
}

impl FGuid {
    /// Construct from raw 16 bytes (in disk/wire order — first 4 bytes
    /// are the LE-encoded `A` u32, etc.).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Read 16 raw bytes from `reader`.
    ///
    /// # Errors
    /// Returns [`crate::error::PaksmithError::Io`] on EOF or other I/O
    /// failures.
    pub fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)?;
        Ok(Self { bytes })
    }

    /// Write 16 raw bytes to `writer`. Test- and fixture-gen-only via
    /// the `__test_utils` feature; release builds drop this method.
    ///
    /// # Errors
    /// Returns [`std::io::Error`] if writes fail.
    #[cfg(any(test, feature = "__test_utils"))]
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.bytes)
    }
}

impl std::fmt::Display for FGuid {
    // Names a/b/c/d mirror UE's FGuid::ToString reference implementation
    // and the canonical 8-4-4-4-12 layout's four-u32 partition.
    #[allow(clippy::many_single_char_names)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Array destructuring instead of `try_into().expect(...)` so the
        // 4-byte partition is enforced at the type level — zero panic
        // surface, complying with CLAUDE.md's "no panics in core" rule.
        let [
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            b2,
            b3,
            c0,
            c1,
            c2,
            c3,
            d0,
            d1,
            d2,
            d3,
        ] = self.bytes;
        let a = u32::from_le_bytes([a0, a1, a2, a3]);
        let b = u32::from_le_bytes([b0, b1, b2, b3]);
        let c = u32::from_le_bytes([c0, c1, c2, c3]);
        let d = u32::from_le_bytes([d0, d1, d2, d3]);
        write!(
            f,
            "{a:08x}-{:04x}-{:04x}-{:04x}-{:04x}{d:08x}",
            b >> 16,
            b & 0xffff,
            c >> 16,
            c & 0xffff,
        )
    }
}

impl serde::Serialize for FGuid {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // JSON shape matches UE's FGuid::ToString canonical form.
        // Mirrors PackageIndex (Task 3) and EngineVersion (Task 4).
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn display_renders_canonical_ue_form() {
        // Bytes [DE AD BE EF 00 01 02 03 04 05 06 07 08 09 0A 0B] read
        // as four LE u32s: A=0xEFBEADDE, B=0x03020100, C=0x07060504,
        // D=0x0B0A0908. UE format reshapes the middle u32s into 4+4
        // hex halves: "efbeadde-0302-0100-0706-05040b0a0908".
        let g = FGuid::from_bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B,
        ]);
        assert_eq!(format!("{g}"), "efbeadde-0302-0100-0706-05040b0a0908");
    }

    #[test]
    fn display_zero_guid() {
        let g = FGuid::from_bytes([0; 16]);
        assert_eq!(format!("{g}"), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn serialize_renders_string_via_display() {
        let g = FGuid::from_bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B,
        ]);
        assert_eq!(
            serde_json::to_string(&g).unwrap(),
            r#""efbeadde-0302-0100-0706-05040b0a0908""#
        );
    }

    #[test]
    fn round_trip_bytes() {
        let g = FGuid::from_bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B,
        ]);
        let mut buf = Vec::new();
        g.write_to(&mut buf).unwrap();
        let parsed = FGuid::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed, g);
        assert_eq!(parsed.as_bytes(), g.as_bytes());
    }
}
