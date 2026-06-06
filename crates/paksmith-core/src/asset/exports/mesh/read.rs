//! Shared little-endian wire-read helpers for the Phase 3g mesh render-data
//! readers (`vertex_buffers`, `index_buffer`, `section`, `lod`, `render_data`).
//!
//! Mirrors the per-reader `eof` / `negative` / `bounds` pattern the other typed
//! readers use (e.g. `audio::sound_wave`), plus the count-cap / bulk-array-header
//! reads the vertex/index buffers need. Counts are validated (non-negative + capped)
//! **before** any allocation, and the readers consume their bulk arrays
//! incrementally — so a count that lies larger than the data hits EOF rather
//! than over-allocating.

use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

/// Wrap a parse `fault` with the asset path.
pub(super) fn fault(asset_path: &str, fault: AssetParseFault) -> PaksmithError {
    PaksmithError::AssetParse {
        asset_path: asset_path.to_string(),
        fault,
    }
}

/// `UnexpectedEof` tagged with the wire `field` that ran short.
pub(super) fn eof(asset_path: &str, field: AssetWireField) -> PaksmithError {
    fault(asset_path, AssetParseFault::UnexpectedEof { field })
}

pub(super) fn read_i32<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<i32> {
    reader
        .read_i32::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))
}

pub(super) fn read_u8<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<u8> {
    reader.read_u8().map_err(|_| eof(asset_path, field))
}

pub(super) fn read_u16<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<u16> {
    reader
        .read_u16::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))
}

pub(super) fn read_u32<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<u32> {
    reader
        .read_u32::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))
}

pub(super) fn read_f32<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<f32> {
    reader
        .read_f32::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))
}

pub(super) fn read_f64<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<f64> {
    reader
        .read_f64::<LittleEndian>()
        .map_err(|_| eof(asset_path, field))
}
// The mesh bool32 fields (`bUseFullPrecisionUVs`, `bUseHighPrecisionTangentBasis`,
// `is32bit`, `bShouldExpandTo32Bit`, `bIsLODCookedOut`, `bInlined`, the section
// flags, `bValid`, `FPerPlatformFloat::bCooked`) are all read via the oracle's
// strict `FArchive.ReadBoolean` (rejects non-0/1), so they go through
// [`crate::asset::wire::read_bool32`] directly — no separate lax helper.

/// Read an `i32` array-count prefix, rejecting a negative value
/// ([`AssetParseFault::NegativeValue`]) and a value exceeding `max`
/// ([`AssetParseFault::BoundsExceeded`], `Items`). Returns the validated `u32`.
/// The cap is enforced **before** the caller allocates / iterates.
pub(super) fn read_capped_count<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
    max: u32,
) -> crate::Result<u32> {
    let raw = read_i32(reader, asset_path, field)?;
    let count = u32::try_from(raw).map_err(|_| {
        fault(
            asset_path,
            AssetParseFault::NegativeValue {
                field,
                value: i64::from(raw),
            },
        )
    })?;
    if count > max {
        return Err(fault(
            asset_path,
            AssetParseFault::BoundsExceeded {
                field,
                value: u64::from(count),
                limit: u64::from(max),
                unit: BoundsUnit::Items,
            },
        ));
    }
    Ok(count)
}

/// Read a UE bulk-array header (`elementSize: i32`, then `elementCount: i32`) as
/// written by CUE4Parse's `FArchive.ReadBulkArray<T>` / `BulkSerialize`. The
/// `elementCount` is validated non-negative and `<= max` ([`read_capped_count`]);
/// `elementSize` is returned raw for the caller to cross-check against the
/// expected per-element width (CUE4Parse asserts the same). Returns
/// `(elementSize, elementCount)`.
pub(super) fn read_bulk_array_header<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
    max: u32,
) -> crate::Result<(i32, u32)> {
    let element_size = read_i32(reader, asset_path, field)?;
    let element_count = read_capped_count(reader, asset_path, field, max)?;
    Ok((element_size, element_count))
}

/// Assert a mesh bulk array's `elementCount` matches the `expected` count the
/// surrounding metadata implies, erroring with
/// [`AssetParseFault::MeshBulkArrayCountMismatch`] otherwise (mirroring the
/// oracle's `throw` on the same disagreement). Shared by the tangent / UV /
/// color cross-checks.
pub(super) fn ensure_bulk_count(
    asset_path: &str,
    field: AssetWireField,
    expected: u32,
    observed: u32,
) -> crate::Result<()> {
    if expected != observed {
        return Err(fault(
            asset_path,
            AssetParseFault::MeshBulkArrayCountMismatch {
                field,
                expected,
                observed,
            },
        ));
    }
    Ok(())
}

/// Advance the cursor by `n` bytes (a bounds-checked `Ar.Position += n`),
/// erroring with [`AssetParseFault::UnexpectedEof`] tagged `field` if the skip
/// would pass the end of the underlying buffer. Used to consume the
/// read-and-discard render-data fields (the `FStaticMeshBuffersSize` trailer,
/// the bulk-array payloads) without materializing them.
pub(super) fn skip(
    cur: &mut Cursor<&[u8]>,
    n: u64,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<()> {
    let len = cur.get_ref().len() as u64;
    let end = cur
        .position()
        .checked_add(n)
        .filter(|&e| e <= len)
        .ok_or_else(|| eof(asset_path, field))?;
    cur.set_position(end);
    Ok(())
}

/// `FArchive.SkipBulkArrayData`: read `elementSize` (`i32`) + `elementCount`
/// (`i32`), both non-negative, then skip `elementSize * elementCount` bytes.
/// Used to discard the per-LOD ray-tracing geometry bulk array (UE 4.25+).
pub(super) fn skip_bulk_array(
    cur: &mut Cursor<&[u8]>,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<()> {
    let element_size = read_i32(cur, asset_path, field)?;
    let element_count = read_i32(cur, asset_path, field)?;
    let size = u64::try_from(element_size).map_err(|_| {
        fault(
            asset_path,
            AssetParseFault::NegativeValue {
                field,
                value: i64::from(element_size),
            },
        )
    })?;
    let count = u64::try_from(element_count).map_err(|_| {
        fault(
            asset_path,
            AssetParseFault::NegativeValue {
                field,
                value: i64::from(element_count),
            },
        )
    })?;
    // Each factor is a non-negative `i32` (≤ ~2³¹), so the product fits in u64.
    skip(cur, size * count, asset_path, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: AssetWireField = AssetWireField::MeshLodMaxDeviation;

    /// A count exactly at the cap is accepted; one over is rejected. Pins the
    /// boundary as `>` (not `>=`).
    #[test]
    fn read_capped_count_accepts_at_cap_rejects_over() {
        let at = read_capped_count(&mut Cursor::new(3i32.to_le_bytes().as_slice()), "T", F, 3);
        assert_eq!(at.unwrap(), 3);
        let over = read_capped_count(&mut Cursor::new(4i32.to_le_bytes().as_slice()), "T", F, 3)
            .unwrap_err();
        assert!(matches!(
            over,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    limit: 3,
                    value: 4,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn skip_advances_position() {
        let buf = [0u8; 16];
        let mut cur = Cursor::new(buf.as_slice());
        skip(&mut cur, 12, "T", F).unwrap();
        assert_eq!(cur.position(), 12);
    }

    #[test]
    fn skip_to_exact_end_is_ok() {
        let buf = [0u8; 8];
        let mut cur = Cursor::new(buf.as_slice());
        skip(&mut cur, 8, "T", F).unwrap();
        assert_eq!(cur.position(), 8);
    }

    #[test]
    fn skip_past_end_is_eof() {
        let buf = [0u8; 8];
        let mut cur = Cursor::new(buf.as_slice());
        let err = skip(&mut cur, 9, "T", F).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { field: F },
                ..
            }
        ));
        // A rejected skip must not advance the cursor.
        assert_eq!(cur.position(), 0);
    }

    /// `skip_bulk_array` consumes the 8-byte header + `size * count` payload.
    #[test]
    fn skip_bulk_array_consumes_header_plus_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_le_bytes()); // elementSize
        buf.extend_from_slice(&4i32.to_le_bytes()); // elementCount
        buf.extend_from_slice(&[0u8; 12]); // 3 * 4 payload
        let mut cur = Cursor::new(buf.as_slice());
        skip_bulk_array(&mut cur, "T", F).unwrap();
        assert_eq!(cur.position(), 8 + 12);
    }

    /// An empty bulk array (count 0) consumes only the 8-byte header.
    #[test]
    fn skip_bulk_array_empty_consumes_only_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        let mut cur = Cursor::new(buf.as_slice());
        skip_bulk_array(&mut cur, "T", F).unwrap();
        assert_eq!(cur.position(), 8);
    }

    /// A negative `elementCount` is rejected before any skip.
    #[test]
    fn skip_bulk_array_rejects_negative_count() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        let mut cur = Cursor::new(buf.as_slice());
        let err = skip_bulk_array(&mut cur, "T", F).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue { .. },
                ..
            }
        ));
    }

    /// A bulk array whose payload runs past EOF surfaces as EOF, not overflow.
    #[test]
    fn skip_bulk_array_payload_overrun_is_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&100i32.to_le_bytes()); // claims 400 bytes
        buf.extend_from_slice(&[0u8; 8]); // supplies 8
        let mut cur = Cursor::new(buf.as_slice());
        let err = skip_bulk_array(&mut cur, "T", F).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::UnexpectedEof { .. },
                ..
            }
        ));
    }
}
