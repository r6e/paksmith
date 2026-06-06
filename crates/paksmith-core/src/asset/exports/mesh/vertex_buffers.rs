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

use crate::asset::structs::color::FColor;
use crate::asset::structs::vector::FVector;
use crate::asset::wire::read_strip_data_flags;
use crate::error::{AssetParseFault, AssetWireField};

use super::read;

/// `FStripDataFlags` `GlobalStripFlags` bit 1 — audio-visual data stripped
/// (CUE4Parse `IsAudioVisualDataStripped()`). Gates the `FColorVertexBuffer`
/// payload.
const STRIP_FLAG_AV_DATA: u8 = 1 << 1;

/// Conservative per-LOD vertex cap (`vertex-formats.md` §Caps). 4 Mi vertices —
/// enforced before any bulk read so a hostile `NumVertices` can't drive a large
/// allocation; the bulk arrays are also consumed incrementally (EOF-bounded).
pub(crate) const MAX_VERTICES_PER_LOD: u32 = 4 * 1024 * 1024;

#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_vertices_per_lod() -> u32 {
    MAX_VERTICES_PER_LOD
}

/// Read an `FPositionVertexBuffer`: `Stride` (`i32`, `{12, 24}`) + `NumVertices`
/// (`i32`, capped) + the bulk position array. Component width is dispatched on
/// `Stride` — `12` = f32×3 (UE4), `24` = f64×3 (UE5 LWC) — which is
/// authoritative, so this reader needs no version context
/// (`vertex-formats.md` §`FPositionVertexBuffer`). Components are always stored
/// as `f64` (UE4 widened on decode), mirroring [`FVector`].
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
    let num = read::read_capped_count(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    let mut positions = Vec::new();
    for _ in 0..num {
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
/// `4`) + `NumVertices` (`i32`, capped) + the bulk `FColor` array. Returns
/// `None` when audio-visual data is stripped (`GlobalStripFlags` bit 1) or
/// `NumVertices == 0` — the LOD carries no per-vertex colors. Wire byte order
/// is `B, G, R, A`, stored as `r, g, b, a` (`vertex-formats.md`
/// §`FColorVertexBuffer`).
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
    let num = read::read_capped_count(
        reader,
        asset_path,
        AssetWireField::MeshVertexCount,
        MAX_VERTICES_PER_LOD,
    )?;
    if global & STRIP_FLAG_AV_DATA != 0 || num == 0 {
        return Ok(None);
    }
    let mut colors = Vec::new();
    for _ in 0..num {
        let b = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let g = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let r = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        let a = read::read_u8(reader, asset_path, AssetWireField::MeshColorData)?;
        colors.push(FColor { r, g, b, a });
    }
    Ok(Some(colors))
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

    /// `vertex-formats.md` worked example — a 44-byte 3-vertex UE4 (f32, stride
    /// 12) position buffer: `(0,0,0)`, `(1,0,0)`, `(0,1,0)`.
    #[test]
    fn position_buffer_3_vertex_worked_example() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12i32.to_le_bytes()); // stride
        bytes.extend_from_slice(&3i32.to_le_bytes()); // num
        for v in [[0.0f32, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
            for c in v {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        assert_eq!(bytes.len(), 44);
        let v = read_position_buffer(&mut Cursor::new(bytes), "T").unwrap();
        assert_eq!(v.len(), 3);
        assert!(approx(&v[0], 0.0, 0.0, 0.0));
        assert!(approx(&v[1], 1.0, 0.0, 0.0));
        assert!(approx(&v[2], 0.0, 1.0, 0.0));
    }

    /// UE5 LWC stride (24) reads f64 components.
    #[test]
    fn position_buffer_lwc_stride_24() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&24i32.to_le_bytes());
        bytes.extend_from_slice(&1i32.to_le_bytes());
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

    /// A count larger than the available data hits EOF (no over-allocation).
    #[test]
    fn position_buffer_count_overrun_is_eof() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12i32.to_le_bytes());
        bytes.extend_from_slice(&100i32.to_le_bytes()); // claims 100, supplies 1
        bytes.extend_from_slice(&[0u8; 12]);
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
        bytes.extend_from_slice(&2i32.to_le_bytes()); // num
        bytes.extend_from_slice(&[10, 20, 30, 40]); // B,G,R,A → r30 g20 b10 a40
        bytes.extend_from_slice(&[1, 2, 3, 4]); // B,G,R,A → r3 g2 b1 a4
        let colors = read_color_buffer(&mut Cursor::new(bytes), "T")
            .unwrap()
            .unwrap();
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
}
