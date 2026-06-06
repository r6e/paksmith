//! Shared little-endian wire-read helpers for the Phase 3g mesh render-data
//! readers (`vertex_buffers`, `index_buffer`, `section`, `lod`, `render_data`).
//!
//! Mirrors the per-reader `eof` / `negative` / `bounds` pattern the other typed
//! readers use (e.g. `audio::sound_wave`), plus the count-cap + lax-bool32 reads
//! the vertex/index buffers need. Counts are validated (non-negative + capped)
//! **before** any allocation, and the readers consume their bulk arrays
//! incrementally — so a count that lies larger than the data hits EOF rather
//! than over-allocating.

use std::io::Read;

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

/// Read a **lax** UE bool32 — `Ar.Read<int>() != 0`. Unlike the strict
/// [`crate::asset::wire::read_bool32`] (which rejects non-0/1), several mesh
/// flags (`bUseFullPrecisionUVs`, `bUseHighPrecisionTangentBasis`, `is32bit`,
/// `bShouldExpandTo32Bit`) are read this way by the oracle.
pub(super) fn read_lax_bool32<R: Read + ?Sized>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<bool> {
    Ok(read_i32(reader, asset_path, field)? != 0)
}

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
