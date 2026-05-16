//! Asset-side FString reader: thin wrapper around
//! [`crate::container::pak::index::read_fstring`] that re-categorizes
//! pak-side `IndexParseFault::FStringMalformed` errors as asset-side
//! `AssetParseFault::FStringMalformed`, and relaxes the `len == 0` →
//! malformed rejection to match CUE4Parse's UAsset FString reader.
//!
//! Without this wrapper, a malformed FString inside a uasset surfaces
//! as `PaksmithError::InvalidIndex { fault: IndexParseFault::* }` —
//! wrong category, confusing operator logs. The wrapper also accepts
//! `len == 0` and returns the empty string, matching CUE4Parse's
//! `FArchive.ReadFString` behavior. The pak-side reader keeps its
//! strict rejection (issue #104) because pak-index FDI records have a
//! minimum-size invariant that depends on it.

use std::io::Read;

use crate::container::pak::index::read_fstring;
use crate::error::{AssetParseFault, FStringFault, IndexParseFault, PaksmithError};

/// Read an FString from `reader`, mapping pak-side FString errors to
/// asset-side ones with `asset_path` context. The `len == 0` case is
/// re-categorized as a valid empty string per CUE4Parse semantics —
/// see the module-level comment.
///
/// All non-FString errors propagate unchanged (`PaksmithError::Io` for
/// truncation, any other variant from `read_fstring` as-is).
///
/// # Errors
/// - [`PaksmithError::Io`] on I/O failures.
/// - [`PaksmithError::AssetParse`] with
///   [`AssetParseFault::FStringMalformed`] when the FString is malformed
///   (other than the `len == 0` case, which is accepted as `""`).
pub(crate) fn read_asset_fstring<R: Read>(
    reader: &mut R,
    asset_path: &str,
) -> crate::Result<String> {
    read_fstring(reader).or_else(|e| match e {
        // Asset-side FString reads accept `len == 0` as the empty
        // string. CUE4Parse's FArchive.ReadFString returns "" in this
        // case rather than throwing — see
        // CUE4Parse/UE4/Readers/FArchive.cs. The pak-side reader stays
        // strict (issue #104) because FDI record-size invariants
        // depend on the 5-byte minimum.
        PaksmithError::InvalidIndex {
            fault:
                IndexParseFault::FStringMalformed {
                    kind: FStringFault::LengthIsZero,
                },
        } => Ok(String::new()),
        PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed { kind },
        } => Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::FStringMalformed { kind },
        }),
        other => Err(other),
    })
}

/// Write a UTF-8 FString using UE's wire convention: i32 length
/// (bytes including null terminator) + the bytes + a null byte.
/// Test- and fixture-gen-only via the `__test_utils` feature.
///
/// # Errors
/// Returns [`std::io::Error`] if writes fail or if the string's
/// `len + 1` exceeds `i32::MAX`.
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) fn write_asset_fstring<W: std::io::Write>(
    writer: &mut W,
    s: &str,
) -> std::io::Result<()> {
    use byteorder::{LittleEndian, WriteBytesExt};
    let bytes_with_null = s.len() + 1;
    let len_i32 = i32::try_from(bytes_with_null)
        .map_err(|_| std::io::Error::other("FString length exceeds i32::MAX"))?;
    writer.write_i32::<LittleEndian>(len_i32)?;
    writer.write_all(s.as_bytes())?;
    writer.write_u8(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// CUE4Parse's `FArchive.ReadFString` accepts `len == 0` and
    /// returns "" — paksmith's asset-side reader honors that. The
    /// pak-side reader stays strict (issue #104).
    #[test]
    fn len_zero_decodes_as_empty_string() {
        let bytes = 0i32.to_le_bytes();
        let parsed = read_asset_fstring(&mut Cursor::new(&bytes[..]), "x.uasset").unwrap();
        assert_eq!(parsed, String::new());
    }

    /// Non-`len == 0` malformations still map to AssetParseFault::FStringMalformed
    /// — the relaxation is a single-case carve-out, not blanket lenience.
    #[test]
    fn non_zero_malformation_still_errors() {
        // Missing null terminator: declare len=4 (UTF-8) but supply
        // 4 non-null bytes. Reader expects last byte = 0.
        let mut buf = Vec::new();
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(b"abcd"); // no trailing null
        let err = read_asset_fstring(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::FStringMalformed {
                    kind: FStringFault::MissingNullTerminator { .. },
                },
                ..
            }
        ));
    }
}
