//! `UStaticMesh` vertex-buffer readers + the packed tangent-basis decoders
//! (Phase 3g render data).
//!
//! Wire-format reference: `docs/formats/mesh/vertex-formats.md` (oracle
//! `FabianFG/CUE4Parse`). This module is built bottom-up; the leaf pieces here
//! — the [`decode_packed_normal`] / [`decode_packed_rgba16n`] tangent decoders —
//! are pure functions with exact worked-example vectors in the format doc, so
//! they land first. The buffer readers (`FPositionVertexBuffer`,
//! `FStaticMeshVertexBuffer`, `FColorVertexBuffer`) build on them.

use std::io::Read;

use half::f16;

use crate::asset::AssetContext;
use crate::asset::structs::color::FColor;
use crate::asset::structs::vector::{FVector, FVector2D, FVector4};
use crate::asset::wire::{STRIP_FLAG_AV_DATA, read_strip_data_flags};
use crate::error::{AssetParseFault, AssetWireField};

use super::read;

/// Conservative per-LOD vertex cap (`vertex-formats.md` §Caps). 4 Mi vertices —
/// enforced before any bulk read so a hostile `NumVertices` can't drive a large
/// allocation; the bulk arrays are also consumed incrementally (EOF-bounded).
pub(crate) const MAX_VERTICES_PER_LOD: u32 = 4 * 1024 * 1024;

// NOTE: no `#[cfg(feature = "__test_utils")] max_vertices_per_lod()` accessor —
// per the `texture2d.rs` convention, a cap accessor with no integration-test
// consumer is dead code (and an uncovered `fn -> CONST` passthrough mutant). The
// in-source tests pin the cap via the `BoundsExceeded { limit }` error field.

/// Read an `FPositionVertexBuffer`: `Stride` (`i32`, `{12, 24}`) + `NumVertices`
/// (`i32`) + the bulk position array (`ReadBulkArray<FVector>`: an
/// `elementSize` + `elementCount` header, then the vertices). Component width is
/// dispatched on `Stride` — `12` = f32×3 (UE4), `24` = f64×3 (UE5 LWC) — which is
/// authoritative, so this reader needs no version context
/// (`vertex-formats.md` §`FPositionVertexBuffer`). Components are always stored
/// as `f64` (UE4 widened on decode), mirroring [`FVector`]. The bulk array's
/// `elementCount` (not the leading `NumVertices`) governs the vertex count, as in
/// the oracle; both are capped before any read.
pub(crate) fn read_position_buffer<R: Read>(
    reader: &mut R,
    asset_path: &str,
) -> crate::Result<Vec<FVector>> {
    let stride = read::read_i32(reader, asset_path, AssetWireField::MeshPositionStride)?;
    let lwc = match stride {
        12 => false,
        24 => true,
        _ => {
            return Err(read::fault(
                asset_path,
                AssetParseFault::VertexBufferStrideInvalid {
                    field: AssetWireField::MeshPositionStride,
                    observed: stride,
                    allowed: "12 or 24",
                },
            ));
        }
    };
    // `NumVertices` (SerializeMetaData) — informational; the bulk header below
    // carries the authoritative element count. Consumed + capped regardless.
    let _num_vertices = read::read_capped_count(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    // `ReadBulkArray<FVector>`: `elementSize` + `elementCount`. The element size
    // (== stride for valid data) is consumed but not relied on — paksmith reads
    // `count` × `stride` bytes and is EOF-bounded against a lying header.
    let (_element_size, count) = read::read_bulk_array_header(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    let mut positions = Vec::new();
    for _ in 0..count {
        positions.push(read_vec3(reader, asset_path, lwc)?);
    }
    Ok(positions)
}

/// Read a single position `FVector` — three f64 (LWC) or three f32-widened
/// components, tagged [`AssetWireField::MeshVertexCount`] on EOF.
fn read_vec3<R: Read>(reader: &mut R, asset_path: &str, lwc: bool) -> crate::Result<FVector> {
    let mut component = || -> crate::Result<f64> {
        if lwc {
            read::read_f64(reader, asset_path, AssetWireField::MeshVertexCount)
        } else {
            read::read_f32(reader, asset_path, AssetWireField::MeshVertexCount).map(f64::from)
        }
    };
    Ok(FVector {
        x: component()?,
        y: component()?,
        z: component()?,
    })
}

/// Read an `FColorVertexBuffer`: `FStripDataFlags` + `Stride` (`i32`, always
/// `4`) + `NumVertices` (`i32`). When audio-visual data is **not** stripped
/// (`GlobalStripFlags` bit 1) **and** `NumVertices > 0`, a bulk `FColor` array
/// (`ReadBulkArray<FColor>`: an `elementSize` + `elementCount` header, then the
/// colors) follows; otherwise no array is serialized and this returns `None`.
/// Wire byte order is `B, G, R, A`, stored as `r, g, b, a` (`vertex-formats.md`
/// §`FColorVertexBuffer`). The gate matches the oracle (`!AVStripped &
/// NumVertices > 0`); the bulk header's `elementCount` governs the read.
pub(crate) fn read_color_buffer<R: Read>(
    reader: &mut R,
    asset_path: &str,
) -> crate::Result<Option<Vec<FColor>>> {
    let (global, _class) =
        read_strip_data_flags(reader, asset_path, AssetWireField::MeshColorStripFlags)?;
    let stride = read::read_i32(reader, asset_path, AssetWireField::MeshColorStride)?;
    if stride != 4 {
        return Err(read::fault(
            asset_path,
            AssetParseFault::VertexBufferStrideInvalid {
                field: AssetWireField::MeshColorStride,
                observed: stride,
                allowed: "4",
            },
        ));
    }
    let num_vertices = read::read_capped_count(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    // The bulk array is serialized only when not AV-stripped and non-empty; when
    // skipped, NO `elementSize`/`elementCount` header is on the wire either.
    if global & STRIP_FLAG_AV_DATA != 0 || num_vertices == 0 {
        return Ok(None);
    }
    let (_element_size, count) = read::read_bulk_array_header(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    let mut colors = Vec::new();
    for _ in 0..count {
        let b = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let g = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let r = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let a = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        colors.push(FColor { r, g, b, a });
    }
    Ok(Some(colors))
}

/// `FStaticMeshVertexBuffer` strides-removed engine-version anchor (UE 4.19).
///
/// **UNVERIFIED object-version boundary.** The strides field is gated on the
/// *engine* version (`Game < UE4_19`) in CUE4Parse, but paksmith tracks *object*
/// versions and the CUE4Parse `EGame`→object-version map / object-version enum
/// file was not reachable to pin the exact constant. Anchored two steps below
/// paksmith's UE4.20 proxy (516). No pre-4.19 static-mesh fixtures exist to
/// validate against; the common 4.19+ path (strides absent) is unaffected.
/// Pre-4.19's *interleaved* tangent/UV layout is also not decoded — this reader
/// targets the 4.19+ separate-bulk-array format (the standard cooked layout).
const VER_UE4_STATIC_MESH_STRIDES_REMOVED: i32 = 514;

/// Decoded `FStaticMeshVertexBuffer` — per-vertex tangent basis + UV channels
/// (Structure-of-Arrays; index `i` is vertex `i` across all fields).
#[derive(Debug, Clone)]
pub(crate) struct StaticMeshVertexData {
    /// Decoded `TangentZ` (vertex normal), XYZ.
    pub normals: Vec<FVector>,
    /// Decoded `TangentX` (vertex tangent), XYZW — `W` is the handedness sign.
    pub tangents: Vec<FVector4>,
    /// UV channels `0..num_tex_coords`; `None` for absent channels.
    pub uvs: [Option<Vec<FVector2D>>; 4],
    /// On-wire UV channel count (1–4).
    pub num_tex_coords: u32,
}

/// Read an `FStaticMeshVertexBuffer` (the per-vertex tangent-basis + UV buffer).
///
/// Wire (4.19+ separate-bulk-array layout): `FStripDataFlags`, `NumTexCoords`
/// (`i32`, 1–4), `NumVertices` (`i32`, capped), `bUseFullPrecisionUVs` +
/// `bUseHighPrecisionTangentBasis` (lax `int != 0` bools). Then — only when
/// audio-visual data is **not** stripped — two `BulkSerialize` arrays, each
/// prefixed by an `itemSize` + `itemCount` header: the tangent array
/// (`NumVertices` entries, 2 packed values each — `FPackedNormal` ×2 = 8 B, or
/// `FPackedRGBA16N` ×2 = 16 B under high precision) followed by the UV array
/// (`NumTexCoords` UVs/vertex — `FMeshUVHalf` f16×2 or `FMeshUVFloat` f32×2). The
/// UV array's vertex count derives from its `itemCount` (with the engine's
/// odd-`NumTexCoords` padding); the extra padding vertex's UVs are consumed but
/// not stored. `vertex-formats.md` §`FStaticMeshVertexBuffer`; oracle
/// `FStaticMeshVertexBuffer.cs`.
pub(crate) fn read_static_mesh_vertex_buffer<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<StaticMeshVertexData> {
    let (strip_global, _strip_class) =
        read_strip_data_flags(reader, asset_path, AssetWireField::MeshVertexStripFlags)?;

    let num_tex_coords_raw = read::read_i32(reader, asset_path, AssetWireField::MeshNumTexCoords)?;
    if !(1..=4).contains(&num_tex_coords_raw) {
        return Err(read::fault(
            asset_path,
            AssetParseFault::MeshNumTexCoordsOob {
                observed: num_tex_coords_raw,
            },
        ));
    }
    // Validated `1..=4` directly above, so the sign-loss cast is exact.
    #[allow(clippy::cast_sign_loss)]
    let num_tex_coords = num_tex_coords_raw as u32;

    // `Strides` (legacy, pre-UE4.19 only): read and discard.
    if !ctx
        .version
        .ue4_at_least(VER_UE4_STATIC_MESH_STRIDES_REMOVED)
    {
        let _legacy_strides =
            read::read_i32(reader, asset_path, AssetWireField::MeshVertexStrides)?;
    }

    let num = read::read_capped_count(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    // Lax `int != 0` bools (oracle `Ar.ReadBoolean()`).
    let full_precision_uvs =
        read::read_lax_bool32(reader, asset_path, AssetWireField::MeshVertexStripFlags)?;
    let high_precision_tangents =
        read::read_lax_bool32(reader, asset_path, AssetWireField::MeshVertexStripFlags)?;
    let xor = ctx.version.is_ue4_20_or_later();

    let mut normals = Vec::new();
    let mut tangents = Vec::new();
    let mut uvs: [Option<Vec<FVector2D>>; 4] = [None, None, None, None];

    // Audio-visual-stripped buffers carry no tangent/UV arrays (oracle gates the
    // whole block on `!IsAudioVisualDataStripped()`).
    if strip_global & STRIP_FLAG_AV_DATA == 0 {
        // Tangent `BulkSerialize` header (itemSize + itemCount == NumVertices),
        // then `NumVertices` tangent pairs.
        let (_tangent_item_size, _tangent_item_count) = read::read_bulk_array_header(
            reader,
            asset_path,
            AssetWireField::MeshVertexTangents,
            MAX_VERTICES_PER_LOD,
        )?;
        for _ in 0..num {
            let (tangent_x, tangent_z) =
                read_tangent_pair(reader, asset_path, high_precision_tangents, xor)?;
            tangents.push(FVector4 {
                x: tangent_x[0],
                y: tangent_x[1],
                z: tangent_x[2],
                w: tangent_x[3],
            });
            normals.push(FVector {
                x: tangent_z[0],
                y: tangent_z[1],
                z: tangent_z[2],
            });
        }

        // UV `BulkSerialize` header. `itemCount` is the total UV count; the engine
        // pads the vertex count to even when `NumTexCoords` is odd, so derive the
        // vertex count from `itemCount` and consume the (unstored) padding row.
        let (_uv_item_size, uv_item_count) = read::read_bulk_array_header(
            reader,
            asset_path,
            AssetWireField::MeshVertexTexCoords,
            // UVs per LOD ≤ vertices × channels; the index ceiling bounds it.
            super::index_buffer::MAX_INDICES_PER_LOD,
        )?;
        let tex_coord_num_verts = tex_coord_num_verts(uv_item_count, num, num_tex_coords);

        for channel in uvs.iter_mut().take(num_tex_coords as usize) {
            *channel = Some(Vec::new());
        }
        for vertex in 0..tex_coord_num_verts {
            for channel in uvs.iter_mut().take(num_tex_coords as usize) {
                let uv = read_uv(reader, asset_path, full_precision_uvs)?;
                // Store only the real vertices; the padding row is consumed but dropped.
                if vertex < num {
                    channel
                        .as_mut()
                        .expect("channel initialized above")
                        .push(uv);
                }
            }
        }
    }

    Ok(StaticMeshVertexData {
        normals,
        tangents,
        uvs,
        num_tex_coords,
    })
}

/// The UV-array vertex count for an `FStaticMeshVertexBuffer`, mirroring
/// CUE4Parse's `GetTexCoordNumVerts`: normally `num_vertices`, but the cooker
/// pads to an even vertex count when `num_tex_coords` is odd (so the half-float
/// UV stream stays 4-byte aligned), in which case `item_count` exceeds
/// `num_vertices * num_tex_coords` and the count is `num_vertices + 1`.
fn tex_coord_num_verts(item_count: u32, num_vertices: u32, num_tex_coords: u32) -> u32 {
    if item_count == num_vertices.saturating_mul(num_tex_coords) {
        return num_vertices;
    }
    let padding = if num_vertices > 0 {
        num_tex_coords % 2
    } else {
        0
    };
    num_vertices + padding
}

/// Read one vertex's `(TangentX, TangentZ)` packed pair → two decoded `[f64; 4]`.
fn read_tangent_pair<R: Read>(
    reader: &mut R,
    asset_path: &str,
    high_precision: bool,
    xor: bool,
) -> crate::Result<([f64; 4], [f64; 4])> {
    if high_precision {
        Ok((
            read_rgba16n(reader, asset_path, xor)?,
            read_rgba16n(reader, asset_path, xor)?,
        ))
    } else {
        let tx = read::read_u32(reader, asset_path, AssetWireField::MeshVertexTangents)?;
        let tz = read::read_u32(reader, asset_path, AssetWireField::MeshVertexTangents)?;
        Ok((decode_packed_normal(tx, xor), decode_packed_normal(tz, xor)))
    }
}

/// Read four `u16` and decode as an `FPackedRGBA16N`.
fn read_rgba16n<R: Read>(reader: &mut R, asset_path: &str, xor: bool) -> crate::Result<[f64; 4]> {
    let mut raw = [0u16; 4];
    for slot in &mut raw {
        *slot = read::read_u16(reader, asset_path, AssetWireField::MeshVertexTangents)?;
    }
    Ok(decode_packed_rgba16n(raw, xor))
}

/// Read one UV — `FMeshUVFloat` (f32×2) or `FMeshUVHalf` (f16×2, widened).
fn read_uv<R: Read>(
    reader: &mut R,
    asset_path: &str,
    full_precision: bool,
) -> crate::Result<FVector2D> {
    let field = AssetWireField::MeshVertexTexCoords;
    let (u, v) = if full_precision {
        (
            f64::from(read::read_f32(reader, asset_path, field)?),
            f64::from(read::read_f32(reader, asset_path, field)?),
        )
    } else {
        (
            f64::from(f16::from_bits(read::read_u16(reader, asset_path, field)?).to_f32()),
            f64::from(f16::from_bits(read::read_u16(reader, asset_path, field)?).to_f32()),
        )
    };
    Ok(FVector2D { x: u, y: v })
}

/// Decode an `FPackedNormal` (4 × `u8`, one `u32` on the wire) into four `f64`
/// components in `[-1, 1]`. For UE 4.20+ (`FRenderingObjectVersion`
/// `IncreaseNormalPrecision`) the raw `u32` is XORed with `0x8080_8080` before
/// the per-byte `b / 127.5 - 1` decode (`vertex-formats.md` §`FPackedNormal`).
/// Components are `[X, Y, Z, W]`; `W` carries the tangent handedness sign.
pub(crate) fn decode_packed_normal(raw: u32, is_ue4_20_or_later: bool) -> [f64; 4] {
    let data = if is_ue4_20_or_later {
        raw ^ 0x8080_8080
    } else {
        raw
    };
    data.to_le_bytes().map(|b| f64::from(b) / 127.5 - 1.0)
}

/// Decode an `FPackedRGBA16N` (4 × `u16`) into four `f64` components in
/// `[-1, 1]`. For UE 4.20+ each raw `u16` is XORed with `0x8000` before the
/// `(v - 32767.5) / 32767.5` decode (`vertex-formats.md` §`FPackedRGBA16N`).
/// The high-precision tangent-basis path; components are `[X, Y, Z, W]`.
pub(crate) fn decode_packed_rgba16n(raw: [u16; 4], is_ue4_20_or_later: bool) -> [f64; 4] {
    raw.map(|s| {
        let v = if is_ue4_20_or_later { s ^ 0x8000 } else { s };
        (f64::from(v) - 32767.5) / 32767.5
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `vertex-formats.md` worked example: a +Z normal `(0, 0, 1, 0)` at UE 4.20+
    /// is on-wire bytes `00 00 7F 00` (raw `u32` `0x007F0000`); after the
    /// `0x80808080` XOR the decoded components are ≈`(0, 0, 1, 0)`.
    #[test]
    fn packed_normal_z_up_ue4_20_matches_worked_example() {
        let raw = u32::from_le_bytes([0x00, 0x00, 0x7F, 0x00]);
        let [x, y, z, w] = decode_packed_normal(raw, true);
        assert!((z - 1.0).abs() < 1e-9, "Z should decode to 1.0, got {z}");
        // The other components are ~0 (one LSB off zero under the byte decode).
        for c in [x, y, w] {
            assert!(c.abs() < 0.01, "off-axis component {c} should be ~0");
        }
    }

    /// Pre-UE-4.20 (no XOR): the same `(0, 0, 1, 0)` normal needs the post-XOR
    /// byte positions on the wire (`80 80 FF 80`).
    #[test]
    fn packed_normal_z_up_pre_4_20_no_xor() {
        let raw = u32::from_le_bytes([0x80, 0x80, 0xFF, 0x80]);
        let [_, _, z, _] = decode_packed_normal(raw, false);
        assert!((z - 1.0).abs() < 1e-9, "Z should decode to 1.0, got {z}");
    }

    /// The XOR gate actually changes the result: the same raw bytes decode
    /// differently with vs without the UE-4.20 XOR (kills a "drop the gate" mutant).
    #[test]
    fn packed_normal_xor_gate_changes_output() {
        let raw = u32::from_le_bytes([0x00, 0x00, 0x7F, 0x00]);
        let on = decode_packed_normal(raw, true);
        let off = decode_packed_normal(raw, false);
        // The Z component differs sharply (1.0 vs ≈0) — pins the gate.
        assert!(
            (on[2] - off[2]).abs() > 0.5,
            "XOR gate must change the decode"
        );
    }

    /// `FPackedRGBA16N` decode formula: `v = 65535` → `1.0`, `v = 0` → ≈`-1.0`,
    /// `v = 32768` → ≈`0`. Tested on the no-XOR (pre-4.20) path with direct values.
    #[test]
    fn packed_rgba16n_decode_formula_endpoints() {
        let [x, y, z, w] = decode_packed_rgba16n([0, 32768, 65535, 32768], false);
        assert!((x + 1.0).abs() < 1e-4, "0 → -1.0, got {x}");
        assert!(y.abs() < 1e-4, "32768 → ~0, got {y}");
        assert!((z - 1.0).abs() < 1e-4, "65535 → 1.0, got {z}");
        assert!(w.abs() < 1e-4, "32768 → ~0, got {w}");
    }

    /// The gate is XOR, **not** OR: with a high-bit-SET input the two diverge
    /// (`0xFF ^ 0x80 = 0x7F ≈ 0`, but `0xFF | 0x80 = 0xFF = 1.0`). Pins the
    /// operator (kills the `^ → |` mutant, which is invisible on high-bit-clear
    /// inputs like the worked example).
    #[test]
    fn packed_normal_gate_is_xor_not_or() {
        let raw = u32::from_le_bytes([0xFF, 0x00, 0x00, 0x00]);
        let [x, _, _, _] = decode_packed_normal(raw, true);
        assert!(x.abs() < 0.01, "XOR clears the high bit → X ≈ 0, got {x}");
    }

    /// `FPackedRGBA16N`: same XOR-not-OR pin — `0xFFFF ^ 0x8000 = 0x7FFF ≈ 0`,
    /// but `0xFFFF | 0x8000 = 0xFFFF = 1.0`.
    #[test]
    fn packed_rgba16n_gate_is_xor_not_or() {
        let [x, _, _, _] = decode_packed_rgba16n([0xFFFF, 0, 0, 0], true);
        assert!(x.abs() < 0.01, "XOR clears the high bit → X ≈ 0, got {x}");
    }

    /// The UE-4.20 XOR (`0x8000`) flips the high bit: with the gate on, a wire
    /// `0x7FFF` decodes to the same value `0xFFFF` does with the gate off.
    #[test]
    fn packed_rgba16n_xor_gate() {
        let on = decode_packed_rgba16n([0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF], true);
        let off = decode_packed_rgba16n([0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF], false);
        // `0x7FFF ^ 0x8000 == 0xFFFF`, so the two decode identically (bit-exact).
        for (a, b) in on.iter().zip(off.iter()) {
            assert!((a - b).abs() < 1e-12, "XOR(0x7FFF) must equal raw 0xFFFF");
        }
        // And the gate matters: same raw, different output.
        let gate_on = decode_packed_rgba16n([0x7FFF; 4], true);
        let gate_off = decode_packed_rgba16n([0x7FFF; 4], false);
        assert!(
            (gate_on[0] - gate_off[0]).abs() > 0.5,
            "XOR gate must change the decode"
        );
    }

    use std::io::Cursor;

    fn approx(v: &FVector, x: f64, y: f64, z: f64) -> bool {
        (v.x - x).abs() < 1e-6 && (v.y - y).abs() < 1e-6 && (v.z - z).abs() < 1e-6
    }

    /// `vertex-formats.md` worked example — a 3-vertex UE4 (f32, stride 12)
    /// position buffer: `(0,0,0)`, `(1,0,0)`, `(0,1,0)`. Wire is `Stride +
    /// NumVertices + ReadBulkArray` (`elementSize` + `elementCount` + verts).
    #[test]
    fn position_buffer_3_vertex_worked_example() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12i32.to_le_bytes()); // stride
        bytes.extend_from_slice(&3i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&12i32.to_le_bytes()); // bulk elementSize
        bytes.extend_from_slice(&3i32.to_le_bytes()); // bulk elementCount
        for v in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
            for c in v {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        assert_eq!(bytes.len(), 16 + 36);
        let mut cur = Cursor::new(bytes.as_slice());
        let v = read_position_buffer(&mut cur, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed the bulk header"
        );
        assert_eq!(v.len(), 3);
        assert!(approx(&v[0], 0.0, 0.0, 0.0));
        assert!(approx(&v[1], 1.0, 0.0, 0.0));
        assert!(approx(&v[2], 0.0, 1.0, 0.0));
    }

    /// UE5 LWC stride (24) reads f64 components.
    #[test]
    fn position_buffer_lwc_stride_24() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&24i32.to_le_bytes()); // stride
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&24i32.to_le_bytes()); // bulk elementSize
        bytes.extend_from_slice(&1i32.to_le_bytes()); // bulk elementCount
        for c in [1.5f64, -2.0, 3.25] {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let v = read_position_buffer(&mut Cursor::new(bytes), "T").unwrap();
        assert_eq!(v.len(), 1);
        assert!(approx(&v[0], 1.5, -2.0, 3.25));
    }

    /// A stride outside `{12, 24}` is rejected before any vertex read.
    #[test]
    fn position_buffer_rejects_bad_stride() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        let err = read_position_buffer(&mut Cursor::new(bytes), "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::VertexBufferStrideInvalid { observed: 8, .. },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// A negative `NumVertices` is rejected (no allocation attempt).
    #[test]
    fn position_buffer_rejects_negative_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12i32.to_le_bytes());
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        let err = read_position_buffer(&mut Cursor::new(bytes), "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::NegativeValue { .. },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// A bulk `elementCount` larger than the available data hits EOF (no
    /// over-allocation).
    #[test]
    fn position_buffer_count_overrun_is_eof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12i32.to_le_bytes()); // stride
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&12i32.to_le_bytes()); // bulk elementSize
        bytes.extend_from_slice(&100i32.to_le_bytes()); // bulk elementCount: claims 100
        bytes.extend_from_slice(&[0u8; 12]); // supplies 1
        let err = read_position_buffer(&mut Cursor::new(bytes), "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::UnexpectedEof { .. },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// `FColorVertexBuffer`: BGRA wire order swizzled to stored RGBA.
    #[test]
    fn color_buffer_reads_bgra_swizzle() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]); // strip flags: not stripped
        bytes.extend_from_slice(&4i32.to_le_bytes()); // stride
        bytes.extend_from_slice(&2i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&4i32.to_le_bytes()); // bulk elementSize
        bytes.extend_from_slice(&2i32.to_le_bytes()); // bulk elementCount
        bytes.extend_from_slice(&[10, 20, 30, 40]); // B,G,R,A → r30 g20 b10 a40
        bytes.extend_from_slice(&[1, 2, 3, 4]); // B,G,R,A → r3 g2 b1 a4
        let mut cur = Cursor::new(bytes.as_slice());
        let colors = read_color_buffer(&mut cur, "T").unwrap().unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed the bulk header"
        );
        assert_eq!(colors.len(), 2);
        assert_eq!(
            colors[0],
            FColor {
                r: 30,
                g: 20,
                b: 10,
                a: 40
            }
        );
        assert_eq!(
            colors[1],
            FColor {
                r: 3,
                g: 2,
                b: 1,
                a: 4
            }
        );
    }

    /// Audio-visual data stripped (GlobalStripFlags bit 1) → no color payload.
    #[test]
    fn color_buffer_av_stripped_is_none() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[STRIP_FLAG_AV_DATA, 0u8]); // AV stripped
        bytes.extend_from_slice(&4i32.to_le_bytes());
        bytes.extend_from_slice(&5i32.to_le_bytes()); // num=5 but no payload follows
        assert!(
            read_color_buffer(&mut Cursor::new(bytes), "T")
                .unwrap()
                .is_none()
        );
    }

    /// Zero vertices → `None` even when not stripped.
    #[test]
    fn color_buffer_zero_vertices_is_none() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&4i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        assert!(
            read_color_buffer(&mut Cursor::new(bytes), "T")
                .unwrap()
                .is_none()
        );
    }

    /// A stride other than 4 is rejected.
    #[test]
    fn color_buffer_rejects_bad_stride() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&8i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
        let err = read_color_buffer(&mut Cursor::new(bytes), "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::VertexBufferStrideInvalid { observed: 8, .. },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    use crate::asset::property::test_utils::make_ctx_with_version;

    /// `FStaticMeshVertexBuffer` low-precision path: `FPackedNormal` tangents
    /// (8 B/vertex) + `FMeshUVHalf` (f16) UVs. UE4.27 (XOR on, strides absent).
    #[test]
    fn static_mesh_vertex_low_precision_f16_uvs() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]); // strip flags
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs = false
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis = false
        bytes.extend_from_slice(&8i32.to_le_bytes()); // tangent bulk itemSize (FPackedNormal x2)
        bytes.extend_from_slice(&1i32.to_le_bytes()); // tangent bulk itemCount
        bytes.extend_from_slice(&[0x7F, 0x00, 0x00, 0x00]); // TangentX → +X
        bytes.extend_from_slice(&[0x00, 0x00, 0x7F, 0x00]); // TangentZ → +Z
        bytes.extend_from_slice(&4i32.to_le_bytes()); // UV bulk itemSize (FMeshUVHalf)
        bytes.extend_from_slice(&1i32.to_le_bytes()); // UV bulk itemCount (1 vert × 1 channel)
        bytes.extend_from_slice(&f16::from_f32(0.5).to_bits().to_le_bytes());
        bytes.extend_from_slice(&f16::from_f32(0.25).to_bits().to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let data = read_static_mesh_vertex_buffer(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed both bulk headers"
        );
        assert_eq!(data.num_tex_coords, 1);
        assert_eq!(data.normals.len(), 1);
        assert_eq!(data.tangents.len(), 1);
        assert!((data.normals[0].z - 1.0).abs() < 0.01, "TangentZ → +Z");
        assert!((data.tangents[0].x - 1.0).abs() < 0.01, "TangentX → +X");
        let uv0 = data.uvs[0].as_ref().unwrap();
        assert_eq!(uv0.len(), 1);
        assert!((uv0[0].x - 0.5).abs() < 0.01, "u ≈ 0.5, got {}", uv0[0].x);
        assert!((uv0[0].y - 0.25).abs() < 0.01, "v ≈ 0.25, got {}", uv0[0].y);
        assert!(data.uvs[1].is_none());
    }

    /// High-precision path: `FPackedRGBA16N` tangents (16 B/vertex) + f32 UVs.
    #[test]
    fn static_mesh_vertex_high_precision_f32_uvs() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumVertices
        bytes.extend_from_slice(&1i32.to_le_bytes()); // full-precision UVs
        bytes.extend_from_slice(&1i32.to_le_bytes()); // high-precision tangents
        bytes.extend_from_slice(&16i32.to_le_bytes()); // tangent bulk itemSize (FPackedRGBA16N x2)
        bytes.extend_from_slice(&1i32.to_le_bytes()); // tangent bulk itemCount
        // TangentX (+X): X=0x7FFF→1.0 after XOR, others 0→≈0.
        for s in [0x7FFFu16, 0, 0, 0] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        // TangentZ (+Z): Z=0x7FFF.
        for s in [0u16, 0, 0x7FFF, 0] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        bytes.extend_from_slice(&8i32.to_le_bytes()); // UV bulk itemSize (FMeshUVFloat)
        bytes.extend_from_slice(&1i32.to_le_bytes()); // UV bulk itemCount
        bytes.extend_from_slice(&0.5f32.to_le_bytes());
        bytes.extend_from_slice(&0.25f32.to_le_bytes());

        let mut cur = Cursor::new(bytes.as_slice());
        let data = read_static_mesh_vertex_buffer(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed both bulk headers"
        );
        assert!((data.tangents[0].x - 1.0).abs() < 0.01, "TangentX → +X");
        assert!((data.normals[0].z - 1.0).abs() < 0.01, "TangentZ → +Z");
        let uv0 = data.uvs[0].as_ref().unwrap();
        assert!((uv0[0].x - 0.5).abs() < 1e-6);
        assert!((uv0[0].y - 0.25).abs() < 1e-6);
    }

    /// `NumTexCoords` outside `1..=4` is rejected.
    #[test]
    fn static_mesh_vertex_rejects_num_tex_coords_oob() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&5i32.to_le_bytes()); // 5 > 4
        let err = read_static_mesh_vertex_buffer(&mut Cursor::new(bytes), &ctx, "T").unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::PaksmithError::AssetParse {
                    fault: AssetParseFault::MeshNumTexCoordsOob { observed: 5 },
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// Pre-4.19 reads (and discards) the legacy `Strides` field — exercises the
    /// version gate (a UE4.18 ctx, object version 510, below the 514 anchor).
    #[test]
    fn static_mesh_vertex_pre_4_19_consumes_strides() {
        let ctx = make_ctx_with_version(510, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]);
        bytes.extend_from_slice(&1i32.to_le_bytes()); // NumTexCoords
        bytes.extend_from_slice(&999i32.to_le_bytes()); // legacy Strides (discarded)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumVertices = 0
        bytes.extend_from_slice(&0i32.to_le_bytes()); // full-precision UVs
        bytes.extend_from_slice(&0i32.to_le_bytes()); // high-precision tangents
        // 0 vertices → empty bulk arrays, but both headers are still on the wire.
        bytes.extend_from_slice(&8i32.to_le_bytes()); // tangent bulk itemSize
        bytes.extend_from_slice(&0i32.to_le_bytes()); // tangent bulk itemCount = 0
        bytes.extend_from_slice(&4i32.to_le_bytes()); // UV bulk itemSize
        bytes.extend_from_slice(&0i32.to_le_bytes()); // UV bulk itemCount = 0
        let mut cur = Cursor::new(bytes.as_slice());
        let data = read_static_mesh_vertex_buffer(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64);
        assert_eq!(data.normals.len(), 0);
        assert_eq!(data.num_tex_coords, 1);
    }

    /// An audio-visual-stripped vertex buffer carries no tangent / UV bulk
    /// arrays (not even their headers) — the reader stops after the bools.
    #[test]
    fn static_mesh_vertex_av_stripped_has_no_tangents_or_uvs() {
        let ctx = make_ctx_with_version(522, None);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[STRIP_FLAG_AV_DATA, 0u8]); // AV stripped
        bytes.extend_from_slice(&2i32.to_le_bytes()); // NumTexCoords
        bytes.extend_from_slice(&5i32.to_le_bytes()); // NumVertices (no payload follows)
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bUseFullPrecisionUVs
        bytes.extend_from_slice(&0i32.to_le_bytes()); // bUseHighPrecisionTangentBasis
        let mut cur = Cursor::new(bytes.as_slice());
        let data = read_static_mesh_vertex_buffer(&mut cur, &ctx, "T").unwrap();
        assert_eq!(cur.position(), bytes.len() as u64, "no bulk arrays read");
        assert!(data.normals.is_empty() && data.tangents.is_empty());
        assert!(data.uvs.iter().all(Option::is_none));
        assert_eq!(data.num_tex_coords, 2);
    }

    /// Odd `NumTexCoords` (3) pads the UV vertex count to even: `itemCount`
    /// (`(NumVertices+1) * NumTexCoords`) exceeds `NumVertices * NumTexCoords`,
    /// so the extra padding row is consumed but not stored.
    #[test]
    fn static_mesh_vertex_uv_padding_for_odd_tex_coords() {
        let ctx = make_ctx_with_version(522, None);
        let num_vertices = 1i32;
        let num_tex_coords = 3i32;
        let tex_coord_verts = num_vertices + 1; // padded (3 is odd)
        let uv_item_count = tex_coord_verts * num_tex_coords; // 6
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8, 0u8]); // not stripped
        bytes.extend_from_slice(&num_tex_coords.to_le_bytes());
        bytes.extend_from_slice(&num_vertices.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes()); // half UVs
        bytes.extend_from_slice(&0i32.to_le_bytes()); // low-precision tangents
        bytes.extend_from_slice(&8i32.to_le_bytes()); // tangent itemSize
        bytes.extend_from_slice(&num_vertices.to_le_bytes()); // tangent itemCount
        bytes.extend_from_slice(&[0u8; 8]); // 1 vertex's tangent pair
        bytes.extend_from_slice(&4i32.to_le_bytes()); // UV itemSize
        bytes.extend_from_slice(&uv_item_count.to_le_bytes()); // padded itemCount
        for _ in 0..uv_item_count {
            bytes.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
            bytes.extend_from_slice(&f16::from_f32(0.0).to_bits().to_le_bytes());
        }
        let mut cur = Cursor::new(bytes.as_slice());
        let data = read_static_mesh_vertex_buffer(&mut cur, &ctx, "T").unwrap();
        assert_eq!(
            cur.position(),
            bytes.len() as u64,
            "consumed the padding row"
        );
        // Only the real vertex is stored, across all 3 channels.
        let want = usize::try_from(num_vertices).unwrap();
        for ch in 0..3 {
            assert_eq!(data.uvs[ch].as_ref().unwrap().len(), want);
        }
    }

    /// Pin the derived cap's literal value so the `4 * 1024 * 1024` arithmetic
    /// can't be mutated (a symbolic `== MAX_VERTICES_PER_LOD` test would track
    /// the mutant on both sides).
    #[test]
    fn max_vertices_per_lod_value() {
        assert_eq!(MAX_VERTICES_PER_LOD, 4_194_304); // 4 Mi
    }

    /// `tex_coord_num_verts` (the `GetTexCoordNumVerts` port) — directly pin the
    /// no-padding case, the odd-`NumTexCoords` padding (`% 2`), and the
    /// `num_vertices > 0` guard.
    #[test]
    fn tex_coord_num_verts_cases() {
        // itemCount == num × ntc → no padding.
        assert_eq!(tex_coord_num_verts(3, 3, 1), 3);
        // itemCount mismatches, ntc=1 (odd), num>0 → +1 (pins `% 2`, not `/ 2`).
        assert_eq!(tex_coord_num_verts(2, 1, 1), 2);
        // num_vertices == 0 → no padding even on mismatch (pins `> 0`, not `>= 0`).
        assert_eq!(tex_coord_num_verts(5, 0, 3), 0);
    }
}
