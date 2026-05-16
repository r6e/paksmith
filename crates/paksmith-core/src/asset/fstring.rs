//! Asset-side FString reader: thin wrapper around
//! [`crate::container::pak::index::read_fstring`] that re-categorizes
//! pak-side `IndexParseFault::FStringMalformed` errors as asset-side
//! `AssetParseFault::FStringMalformed`.
//!
//! Without this wrapper, a malformed FString inside a uasset surfaces
//! as `PaksmithError::InvalidIndex { fault: IndexParseFault::* }` —
//! wrong category, confusing operator logs.

use std::io::Read;

use crate::container::pak::index::read_fstring;
use crate::error::{AssetParseFault, IndexParseFault, PaksmithError};

/// Read an FString from `reader`, mapping pak-side FString errors to
/// asset-side ones with `asset_path` context.
///
/// All non-FString errors propagate unchanged (`PaksmithError::Io` for
/// truncation, any other variant from `read_fstring` as-is).
///
/// # Errors
/// - [`PaksmithError::Io`] on I/O failures.
/// - [`PaksmithError::AssetParse`] with
///   [`AssetParseFault::FStringMalformed`] when the FString is malformed.
pub(crate) fn read_asset_fstring<R: Read>(
    reader: &mut R,
    asset_path: &str,
) -> crate::Result<String> {
    read_fstring(reader).map_err(|e| match e {
        PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed { kind },
        } => PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::FStringMalformed { kind },
        },
        other => other,
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
