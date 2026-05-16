//! Shared wire-format helpers for asset-side readers.
//!
//! UE serializes booleans as 4-byte `i32` values (bool32), not single
//! bytes. These helpers centralize the read/write convention so every
//! call site agrees on the encoding. The pattern appears 7+ times per
//! export record (forced_export, not_for_client, etc.) and 1+ per
//! import record (`import_optional`); Phase 2b's `FPropertyTag` will
//! add more.

use std::io::Read;
#[cfg(any(test, feature = "__test_utils"))]
use std::io::Write;

#[cfg(any(test, feature = "__test_utils"))]
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{AssetParseFault, AssetWireField, PaksmithError};

/// Read a UE bool32 — 4 LE bytes treated as `i32`, returns `bool`.
/// CUE4Parse's `FArchive.ReadBoolean` rejects any value other than 0
/// or 1; paksmith matches that contract. The `field` and `asset_path`
/// arguments surface in [`AssetParseFault::InvalidBool32`] so log
/// triage points at the specific record slot.
///
/// # Errors
/// - [`PaksmithError::AssetParse`] with
///   [`AssetParseFault::InvalidBool32`] if the wire value is neither 0
///   nor 1.
/// - [`PaksmithError::Io`] on EOF or other I/O failures.
pub(crate) fn read_bool32<R: Read>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<bool> {
    let raw = reader.read_i32::<LittleEndian>()?;
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        observed => Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::InvalidBool32 { field, observed },
        }),
    }
}

/// Write a UE bool32 — `true` as `1i32`, `false` as `0i32`, 4 LE bytes.
/// Test- and fixture-gen-only via the `__test_utils` feature; release
/// builds drop this method.
///
/// # Errors
/// Returns [`std::io::Error`] if the write fails.
#[cfg(any(test, feature = "__test_utils"))]
pub(crate) fn write_bool32<W: Write>(writer: &mut W, value: bool) -> std::io::Result<()> {
    writer.write_i32::<LittleEndian>(i32::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// CUE4Parse-faithful contract: `read_bool32` returns `Ok(false)`
    /// for 0 and `Ok(true)` for 1. Pin both arms.
    #[test]
    fn accepts_canonical_zero_and_one() {
        let z = 0i32.to_le_bytes();
        let o = 1i32.to_le_bytes();
        assert!(
            !read_bool32(
                &mut Cursor::new(&z[..]),
                "x.uasset",
                AssetWireField::ExportIsAsset,
            )
            .unwrap()
        );
        assert!(
            read_bool32(
                &mut Cursor::new(&o[..]),
                "x.uasset",
                AssetWireField::ExportIsAsset,
            )
            .unwrap()
        );
    }

    /// Strict-reject: any i32 other than 0 or 1 surfaces as
    /// `AssetParseFault::InvalidBool32 { observed }`. Test 2, -1, and
    /// i32::MAX to cover the three "out of band" zones.
    #[test]
    fn rejects_values_other_than_zero_or_one() {
        for raw in [2i32, -1, i32::MAX] {
            let bytes = raw.to_le_bytes();
            let err = read_bool32(
                &mut Cursor::new(&bytes[..]),
                "x.uasset",
                AssetWireField::ExportForcedExport,
            )
            .unwrap_err();
            match err {
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidBool32 { observed, field },
                    ..
                } => {
                    assert_eq!(observed, raw);
                    assert_eq!(field, AssetWireField::ExportForcedExport);
                }
                other => panic!("expected InvalidBool32, got {other:?}"),
            }
        }
    }
}
