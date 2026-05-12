//! UE FString reader for the pak index.
//!
//! UE's FString wire format is a length-prefixed null-terminated string
//! with sign-encoded encoding selection: positive length = UTF-8 byte
//! count, negative = UTF-16 LE code-unit count, both including the
//! trailing null. A length of `0` denotes the empty string.
//!
//! This module is the single source of truth for parsing FStrings out
//! of the pak index — all entry filenames, mount points, and FDI
//! directory/file names go through [`read_fstring`].

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{FStringEncoding, FStringFault, IndexParseFault, PaksmithError};

/// Maximum length (in bytes for UTF-8, code units for UTF-16) accepted
/// for an FString. Sized to comfortably exceed any realistic UE virtual
/// path while rejecting attacker-controlled multi-GB allocations.
pub(super) const FSTRING_MAX_LEN: i32 = 65_536;

/// Read a length-prefixed FString from `reader`.
///
/// Length encoding: a signed `i32` where the sign selects encoding —
/// positive = UTF-8 byte count (including null terminator),
/// negative = UTF-16 code-unit count (including null terminator),
/// absolute value. A value of `0` denotes the empty string.
///
/// Errors out (rather than silently truncating) when the trailing null
/// terminator is missing or when the length exceeds [`FSTRING_MAX_LEN`].
pub(super) fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    if len == 0 {
        return Ok(String::new());
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
        let mut buf = vec![0u16; abs_len];
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

    let mut buf = vec![0u8; abs_len];
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
