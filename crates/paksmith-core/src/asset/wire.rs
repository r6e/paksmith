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
pub(crate) fn read_bool32<R: Read + ?Sized>(
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

/// `FStripDataFlags::GlobalStripFlags` bit 0 (`0x01`) — editor-only data
/// stripped (CUE4Parse `IsEditorDataStripped`, set by the cooker). Written as a
/// plain literal (not `1 << 0`) so there's no shift operator to mutate into an
/// equivalent (`1 >> 0 == 1`); the value is pinned by `strip_flag_bit_values`.
pub(crate) const STRIP_FLAG_EDITOR_DATA: u8 = 0x01;
/// `FStripDataFlags::GlobalStripFlags` bit 1 (`0x02`) — audio-visual (runtime
/// render) data stripped (CUE4Parse `IsAudioVisualDataStripped`).
pub(crate) const STRIP_FLAG_AV_DATA: u8 = 0x02;

/// Read an `FStripDataFlags` pair (`GlobalStripFlags` + `ClassStripFlags`,
/// `u8` each). CUE4Parse's single-arg `FStripDataFlags(Ar)` chains to
/// `OLDEST_LOADABLE_PACKAGE`, far below paksmith's 504 floor, so both bytes
/// are unconditionally present for paksmith's range. `field` surfaces in the
/// [`AssetParseFault::UnexpectedEof`] so triage points at the right record
/// (e.g. `TextureStripFlags` vs `StaticMeshStripFlags`).
///
/// # Errors
/// [`PaksmithError::AssetParse`] with [`AssetParseFault::UnexpectedEof`] on EOF.
pub(crate) fn read_strip_data_flags<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<(u8, u8)> {
    let eof = || PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault: AssetParseFault::UnexpectedEof { field },
    };
    let global = reader.read_u8().map_err(|_| eof())?;
    let class = reader.read_u8().map_err(|_| eof())?;
    Ok((global, class))
}

/// `FStripDataFlags::IsEditorDataStripped()` — true iff the editor-only-data
/// bit ([`STRIP_FLAG_EDITOR_DATA`], `0x01`) is set in `GlobalStripFlags`.
///
/// `global` is the first element of the [`read_strip_data_flags`] tuple. The
/// cooker sets this bit for shipped (cooked) content; editor packages leave it
/// clear. CUE4Parse computes the predicate identically
/// (`(GlobalStripFlags & 1) != 0`).
#[must_use]
pub(crate) fn is_editor_data_stripped(global: u8) -> bool {
    global & STRIP_FLAG_EDITOR_DATA != 0
}

/// `FStripDataFlags::IsClassDataStripped(flag)` — true when `flag`'s bit is set
/// in the CLASS strip-flags byte (the 2nd element of [`read_strip_data_flags`]).
///
/// CUE4Parse computes the predicate identically (`(ClassStripFlags & flag) !=
/// 0`). Unlike [`is_editor_data_stripped`] the bit under test is caller-supplied
/// because class-strip bits are class-specific (e.g.
/// [`STRIP_FLAG_DUPLICATED_VERTICES`] for `FSkelMeshSection`).
#[must_use]
#[allow(
    dead_code,
    reason = "consumed by read_skel_mesh_section_render in Phase 3h Task 6; pinned by is_class_data_stripped_checks_the_given_bit"
)]
pub(crate) fn is_class_data_stripped(class: u8, flag: u8) -> bool {
    class & flag != 0
}

/// The `DuplicatedVertices` class-strip flag (gates the cooked
/// `FSkelMeshSection`'s `DupVertData`/`DupVertIndexData` arrays). Written as a
/// plain literal (no shift) so there's no operator to mutate; pinned by
/// `is_class_data_stripped_checks_the_given_bit`.
#[allow(
    dead_code,
    reason = "consumed by read_skel_mesh_section_render in Phase 3h Task 6; pinned by is_class_data_stripped_checks_the_given_bit"
)]
pub(crate) const STRIP_FLAG_DUPLICATED_VERTICES: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Pin the `FStripDataFlags` `GlobalStripFlags` bit values literally — the
    /// `1 << n` shifts are otherwise mutation-invisible to the consumers that
    /// reference the symbols in both the fixture and the check.
    #[test]
    fn strip_flag_bit_values() {
        assert_eq!(STRIP_FLAG_EDITOR_DATA, 1); // bit 0
        assert_eq!(STRIP_FLAG_AV_DATA, 2); // bit 1
    }

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

    #[test]
    fn is_class_data_stripped_checks_the_given_bit() {
        assert!(is_class_data_stripped(0x01, 0x01)); // DuplicatedVertices set
        assert!(!is_class_data_stripped(0x00, 0x01)); // unset
        assert!(!is_class_data_stripped(0x02, 0x01)); // a different bit set → still unset for 0x01
        assert!(is_class_data_stripped(0x03, 0x01)); // bits 0+1
        assert_eq!(STRIP_FLAG_DUPLICATED_VERTICES, 0x01); // pin the flag's bit value
    }

    #[test]
    fn is_editor_data_stripped_reads_global_bit_zero() {
        // Bit 0 set → stripped; bit 0 clear → not stripped. The `0x02`
        // (AV-data) and `0x04` cases pin that ONLY bit 0 is consulted (kills a
        // `& -> |` mutant and a wrong-mask mutant).
        assert!(is_editor_data_stripped(STRIP_FLAG_EDITOR_DATA)); // 0x01
        assert!(is_editor_data_stripped(0x03)); // bits 0+1 set
        assert!(!is_editor_data_stripped(0x00)); // nothing set
        assert!(!is_editor_data_stripped(STRIP_FLAG_AV_DATA)); // 0x02 — bit 0 clear
        assert!(!is_editor_data_stripped(0x04)); // bit 2 only — bit 0 clear
    }

    #[test]
    fn strip_data_flags_reads_global_then_class_in_order() {
        // Two bytes → (global, class) in that order (pins the read order + that
        // both bytes are returned, not one duplicated or swapped).
        let (global, class) = read_strip_data_flags(
            &mut Cursor::new(&[0x07u8, 0x03][..]),
            "x",
            AssetWireField::TextureStripFlags,
        )
        .unwrap();
        assert_eq!(global, 0x07);
        assert_eq!(class, 0x03);
    }

    #[test]
    fn strip_data_flags_eof_on_second_byte_maps_to_field() {
        // Only one of the two bytes present → EOF carrying the caller's field.
        let err = read_strip_data_flags(
            &mut Cursor::new(&[0x07u8][..]),
            "x",
            AssetWireField::TextureStripFlags,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof {
                    field: AssetWireField::TextureStripFlags
                },
                ..
            }
        ));
    }
}
