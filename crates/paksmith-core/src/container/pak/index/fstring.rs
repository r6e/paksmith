//! UE FString reader for the pak index.
//!
//! UE's FString wire format is a length-prefixed null-terminated string
//! with sign-encoded encoding selection: positive length = UTF-8 byte
//! count, negative = UTF-16 LE code-unit count, both including the
//! trailing null. A length of `0` is rejected as malformed — UE's
//! writer represents the empty FString as `len=1, byte=0x00`
//! (one-byte null terminator only); `len=0` is never produced by a
//! UE writer. See [`crate::error::FStringFault::LengthIsZero`].
//!
//! This module is the single source of truth for parsing FStrings out
//! of the pak index — all entry filenames, mount points, and FDI
//! directory/file names go through [`read_fstring`].

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{
    AllocationContext, BoundsUnit, FStringEncoding, FStringFault, IndexParseFault, PaksmithError,
};

/// Maximum length (in bytes for UTF-8, code units for UTF-16) accepted
/// for an FString. Sized to comfortably exceed any realistic UE virtual
/// path while rejecting attacker-controlled multi-GB allocations.
const FSTRING_MAX_LEN: i32 = 65_536;

/// Read a length-prefixed FString from `reader`.
///
/// Length encoding: a signed `i32` where the sign selects encoding —
/// positive = UTF-8 byte count (including null terminator),
/// negative = UTF-16 code-unit count (including null terminator),
/// absolute value. A value of `0` is rejected as malformed (issue
/// #104 — UE's writer represents the empty FString as
/// `len=1, byte=0x00` (one-byte null terminator only); `len=0` is
/// never produced by a UE writer).
///
/// Errors out (rather than silently truncating) when the trailing null
/// terminator is missing, when the length exceeds [`FSTRING_MAX_LEN`],
/// or when `len == 0` / `len == i32::MIN`.
pub(crate) fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    // Issue #104: reject `len == 0` as malformed. UE's writer
    // convention represents an empty FString as `len=1, byte=0x00`
    // (one-byte null terminator only); `len=0` is never produced by
    // a UE writer. The pre-fix short-circuit returned an empty
    // String after consuming only 4 bytes, which made
    // `MIN_FDI_*_RECORD_BYTES = 9` (which assumes the 5-byte
    // minimum FString) loose by ~12.5% against an adversarial FDI
    // packing `len=0` records — `fdi_size / 8` accepted slips past
    // the `fdi_size / 9` cap. Rejecting here closes the gap AND
    // keeps the existing 9-byte constants correct.
    if len == 0 {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::LengthIsZero,
            },
        });
    }

    let Some(abs_len) = len.checked_abs() else {
        // i32::MIN has no positive counterpart; reject.
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::LengthIsI32Min,
            },
        });
    };
    if abs_len > FSTRING_MAX_LEN {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::LengthExceedsMaximum {
                    length: abs_len as u32,
                    maximum: FSTRING_MAX_LEN as u32,
                },
            },
        });
    }
    let abs_len = abs_len as usize;

    if len < 0 {
        // Issue #132 item 3: fallible allocation, consistent with
        // the `try_reserve_exact` discipline used elsewhere in the
        // crate. `abs_len` is capped by `FSTRING_MAX_LEN = 65_536`
        // u16 code units (= 128 KiB), well within infallible-alloc
        // territory on a healthy machine — but if the cap ever
        // loosens, this would become an OOM-abort site.
        let mut buf: Vec<u16> = Vec::new();
        buf.try_reserve_exact(abs_len)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FStringUtf16CodeUnits,
                    requested: abs_len,
                    unit: BoundsUnit::Items,
                    source,
                    path: None,
                },
            })?;
        buf.resize(abs_len, 0);
        for item in &mut buf {
            *item = reader.read_u16::<LittleEndian>()?;
        }
        match buf.last() {
            Some(&0) => {
                let _ = buf.pop();
            }
            _ => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::FStringMalformed {
                        kind: FStringFault::MissingNullTerminator {
                            encoding: FStringEncoding::Utf16,
                        },
                    },
                });
            }
        }
        return String::from_utf16(&buf).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::InvalidEncoding {
                    encoding: FStringEncoding::Utf16,
                },
            },
        });
    }

    // Issue #132 item 3: fallible allocation — see UTF-16 branch above.
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(abs_len)
        .map_err(|source| PaksmithError::InvalidIndex {
            fault: IndexParseFault::AllocationFailed {
                context: AllocationContext::FStringUtf8Bytes,
                requested: abs_len,
                unit: BoundsUnit::Bytes,
                source,
                path: None,
            },
        })?;
    buf.resize(abs_len, 0);
    reader.read_exact(&mut buf)?;
    match buf.last() {
        Some(&0) => {
            let _ = buf.pop();
        }
        _ => {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::FStringMalformed {
                    kind: FStringFault::MissingNullTerminator {
                        encoding: FStringEncoding::Utf8,
                    },
                },
            });
        }
    }
    String::from_utf8(buf).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::FStringMalformed {
            kind: FStringFault::InvalidEncoding {
                encoding: FStringEncoding::Utf8,
            },
        },
    })
}
