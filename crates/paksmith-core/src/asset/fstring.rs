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

use std::io;
use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::container::pak::index::read_fstring;
use crate::error::{AssetParseFault, AssetWireField, FStringFault, IndexParseFault, PaksmithError};

/// Hard cap on FString length, matching the pak-side reader's
/// `FSTRING_MAX_LEN`. Wire i32 length envelope after `checked_abs`.
const FSTRING_MAX_LEN: i32 = 65_536;

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

/// Read-and-discard an FString from `reader`, consuming the same
/// bytes [`read_asset_fstring`] would consume but without allocating
/// a `String`.
///
/// Used by [`PackageSummary`](crate::asset::PackageSummary) for
/// wire-format fields like `additional_packages_to_cook` that UE
/// writers emit but paksmith doesn't surface — the count cap on
/// those fields permits up to thousands of FStrings per asset, each
/// of which would otherwise allocate and immediately drop a
/// `String` of up to 65,536 bytes. Issue #372.
///
/// **Validation posture:** matches [`read_asset_fstring`]'s length-
/// envelope checks (`i32::MIN`, `> FSTRING_MAX_LEN`) so an
/// adversarial header is rejected at the same boundary. NUL-byte
/// validation and UTF-8 decoding are dropped — the bytes are
/// discarded by `io::sink`, so embedded NULs / invalid UTF-8 have
/// no security impact (no string is surfaced anywhere). Matches the
/// `len == 0` → empty-string carve-out (skip is a no-op).
///
/// # Errors
/// - [`PaksmithError::Io`] on a short read of either the length
///   prefix or the payload bytes.
/// - [`PaksmithError::AssetParse`] with
///   [`AssetParseFault::FStringMalformed`] for the length-envelope
///   rejections ([`FStringFault::LengthIsI32Min`],
///   [`FStringFault::LengthExceedsMaximum`]).
#[allow(
    clippy::cast_sign_loss,
    reason = "abs_len comes from checked_abs on i32 — bounded to [0, i32::MAX], sign-loss casts to u32/u64 are bit-preserving"
)]
pub(crate) fn skip_asset_fstring<R: Read>(
    reader: &mut R,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<()> {
    let len = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof { field },
        })?;

    // `len == 0` is the CUE4Parse-aligned empty-FString case (see
    // `read_asset_fstring` above) — skip is a no-op.
    if len == 0 {
        return Ok(());
    }

    let Some(abs_len) = len.checked_abs() else {
        // `i32::MIN` has no positive counterpart; reject.
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::FStringMalformed {
                kind: FStringFault::LengthIsI32Min,
            },
        });
    };
    if abs_len > FSTRING_MAX_LEN {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::FStringMalformed {
                kind: FStringFault::LengthExceedsMaximum {
                    length: abs_len as u32,
                    maximum: FSTRING_MAX_LEN as u32,
                },
            },
        });
    }

    // UTF-8: `abs_len` bytes total (includes trailing null).
    // UTF-16: `abs_len` u16 code units = `abs_len * 2` bytes.
    // Multiplication can't overflow u64: abs_len ≤ 65_536, ×2 ≤ 131_072.
    let byte_count = if len < 0 {
        u64::from(abs_len as u32) * 2
    } else {
        u64::from(abs_len as u32)
    };

    // `io::copy` into `io::sink` uses a 4 KiB stack buffer — no heap
    // (#372). `take(byte_count)` bounds the read; a short underlying
    // stream surfaces as `copied < byte_count` and we re-emit it as
    // the same `UnexpectedEof` the prior allocating path produced.
    let copied =
        io::copy(&mut reader.by_ref().take(byte_count), &mut io::sink()).map_err(|_| {
            PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::UnexpectedEof { field },
            }
        })?;
    if copied != byte_count {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::UnexpectedEof { field },
        });
    }
    Ok(())
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

    /// F1 (security hardening): embedded NULs in asset-side FStrings
    /// must surface through the wrapper as
    /// `AssetParseFault::FStringMalformed { kind: EmbeddedNul, .. }`.
    /// Pin the wrapper's catch-all forwarding — narrowing the match
    /// arm in `read_asset_fstring` would silently drop this without
    /// the test.
    #[test]
    fn embedded_nul_forwards_through_wrapper() {
        let mut buf = Vec::new();
        // Length 8: "foo\0bar" plus trailing NUL.
        buf.extend_from_slice(&8i32.to_le_bytes());
        buf.extend_from_slice(b"foo\0bar\0");
        let err = read_asset_fstring(&mut Cursor::new(&buf), "x.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::FStringMalformed {
                        kind: FStringFault::EmbeddedNul { at: 3, .. },
                    },
                    ..
                }
            ),
            "expected AssetParse{{EmbeddedNul, at=3}}, got: {err:?}"
        );
    }

    /// Skip helper consumes exactly the bytes a UTF-8 FString
    /// occupies on the wire — i32 length + N payload bytes — and
    /// leaves the cursor positioned at the byte immediately after.
    /// Verified by reading a u32 sentinel placed right after the
    /// FString. Issue #372.
    #[test]
    fn skip_consumes_utf8_fstring_bytes_and_advances_cursor() {
        let mut buf = Vec::new();
        // FString "abcd\0" — len = 5 (UTF-8, includes trailing NUL).
        buf.extend_from_slice(&5i32.to_le_bytes());
        buf.extend_from_slice(b"abcd\0");
        // Sentinel u32 immediately after the FString.
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut cur = Cursor::new(buf);
        skip_asset_fstring(
            &mut cur,
            "x.uasset",
            AssetWireField::AdditionalPackagesToCookEntry,
        )
        .unwrap();
        let sentinel = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(
            sentinel, 0xDEAD_BEEF,
            "cursor must land at the byte after the FString payload"
        );
    }

    /// `len == 0` is the CUE4Parse-aligned empty-FString case —
    /// skip is a no-op, only the 4 length bytes are consumed.
    #[test]
    fn skip_len_zero_consumes_only_the_length_prefix() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut cur = Cursor::new(buf);
        skip_asset_fstring(
            &mut cur,
            "x.uasset",
            AssetWireField::AdditionalPackagesToCookEntry,
        )
        .unwrap();
        let sentinel = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(sentinel, 0xDEAD_BEEF);
    }

    /// UTF-16 FString: negative length encodes a UTF-16 string of
    /// `abs(len)` u16 code units = `abs(len) * 2` bytes. Skip
    /// consumes the doubled byte count.
    #[test]
    fn skip_consumes_utf16_fstring_doubled_byte_count() {
        let mut buf = Vec::new();
        // len = -3 → 3 u16 code units = 6 bytes (UE writes the
        // trailing NUL as the final u16).
        buf.extend_from_slice(&(-3i32).to_le_bytes());
        buf.extend_from_slice(&[b'A', 0, b'B', 0, 0, 0]); // "AB\0" UTF-16LE
        buf.extend_from_slice(&0xCAFEu32.to_le_bytes());
        let mut cur = Cursor::new(buf);
        skip_asset_fstring(
            &mut cur,
            "x.uasset",
            AssetWireField::AdditionalPackagesToCookEntry,
        )
        .unwrap();
        let sentinel = cur.read_u32::<LittleEndian>().unwrap();
        assert_eq!(sentinel, 0xCAFE);
    }

    /// Length-envelope rejections mirror `read_asset_fstring`'s.
    /// Pin both rejection arms so the validation posture stays in
    /// sync with the allocating variant.
    #[test]
    fn skip_rejects_length_envelope_violations() {
        // i32::MIN — `checked_abs` returns None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&i32::MIN.to_le_bytes());
        let err = skip_asset_fstring(
            &mut Cursor::new(buf),
            "x.uasset",
            AssetWireField::AdditionalPackagesToCookEntry,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::FStringMalformed {
                    kind: FStringFault::LengthIsI32Min,
                },
                ..
            }
        ));

        // Length over the FSTRING_MAX_LEN cap.
        let mut buf = Vec::new();
        buf.extend_from_slice(&(FSTRING_MAX_LEN + 1).to_le_bytes());
        let err = skip_asset_fstring(
            &mut Cursor::new(buf),
            "x.uasset",
            AssetWireField::AdditionalPackagesToCookEntry,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::FStringMalformed {
                    kind: FStringFault::LengthExceedsMaximum { .. },
                },
                ..
            }
        ));
    }
}
