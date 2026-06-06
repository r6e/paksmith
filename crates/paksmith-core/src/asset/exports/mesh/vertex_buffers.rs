//! `UStaticMesh` vertex-buffer readers + the packed tangent-basis decoders
//! (Phase 3g render data).
//!
//! Wire-format reference: `docs/formats/mesh/vertex-formats.md` (oracle
//! `FabianFG/CUE4Parse`). This module is built bottom-up; the leaf pieces here
//! — the [`decode_packed_normal`] / [`decode_packed_rgba16n`] tangent decoders —
//! are pure functions with exact worked-example vectors in the format doc, so
//! they land first. The buffer readers (`FPositionVertexBuffer`,
//! `FStaticMeshVertexBuffer`, `FColorVertexBuffer`) build on them.

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
}
