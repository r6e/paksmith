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

/// Read a UE bool32 — 4 LE bytes treated as `i32`, returns `bool`
/// where any non-zero value is `true`. Matches UE's convention.
///
/// # Errors
/// Returns [`std::io::Error`] on EOF or other I/O failures.
pub(crate) fn read_bool32<R: Read>(reader: &mut R) -> std::io::Result<bool> {
    Ok(reader.read_i32::<LittleEndian>()? != 0)
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
