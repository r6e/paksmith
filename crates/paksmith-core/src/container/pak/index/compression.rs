//! Per-entry compression metadata: method enum + block range.
//!
//! Two domain types live here, both referenced from
//! [`super::EntryCommon`]: [`CompressionMethod`] (the algorithm) and
//! [`CompressionBlock`] (a single compressed byte range within the
//! entry payload).

use std::num::NonZeroU32;

use crate::error::{IndexParseFault, PaksmithError};

/// Compression method used for a pak entry.
///
/// On disk, the per-entry compression byte means different things by
/// version:
/// - **v3-v7**: a raw method ID (0=None, 1=Zlib, 2=Gzip, 4=Oodle).
///   Resolved via [`CompressionMethod::from_u32`].
/// - **v8+**: a 1-based index into the footer's compression-methods FName
///   table (0 = no compression, N = `compression_methods[N-1]`). The
///   table itself contains FName strings — `"Zlib"`, `"Oodle"`, etc. —
///   resolved via [`CompressionMethod::from_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionMethod {
    /// No compression applied.
    None,
    /// Zlib (deflate) compression.
    Zlib,
    /// Gzip compression.
    Gzip,
    /// Oodle compression (Epic proprietary).
    Oodle,
    /// Zstandard compression (Epic added v8+).
    Zstd,
    /// LZ4 compression (Epic added v8+).
    Lz4,
    /// Unrecognized v3-v7 compression method ID, or v8+ table index whose
    /// slot resolved to `None`/Unknown. Held as [`NonZeroU32`] because the
    /// zero value is reserved for [`CompressionMethod::None`] (no
    /// compression) — `Unknown(0)` would be both meaningless and a footgun
    /// (operators reading "unknown method 0" would assume a real
    /// unrecognized method, not "no compression"). Preserved for
    /// diagnostics.
    Unknown(NonZeroU32),
    /// Unrecognized v8+ compression FName, preserved verbatim so error
    /// messages can name the slot's actual contents (e.g.,
    /// `"OodleNetwork"`, `"LZMA"`) rather than collapsing every unknown
    /// name to a single sentinel.
    UnknownByName(String),
}

impl CompressionMethod {
    /// Parse a raw `u32` compression method identifier (v3-v7 wire format).
    pub fn from_u32(value: u32) -> Self {
        // Zero means "no compression" — bind to None and never reach the
        // Unknown arm. The let-else makes the NonZeroU32 invariant
        // structural rather than relying on an `unwrap`/`expect` after a
        // separate match arm.
        let Some(non_zero) = NonZeroU32::new(value) else {
            return Self::None;
        };
        match non_zero.get() {
            1 => Self::Zlib,
            2 => Self::Gzip,
            4 => Self::Oodle,
            _ => Self::Unknown(non_zero),
        }
    }

    /// Parse a compression method by name (v8+ FName-table entry). Match
    /// is case-insensitive against the canonical UE names. Unrecognized
    /// names return [`CompressionMethod::UnknownByName`] preserving the
    /// raw name so the entry's downstream lookup surfaces as a typed
    /// `Decompression` error that names the actual slot contents.
    ///
    /// Callers must not pass an empty string — the slot reader handles
    /// empty slots upstream by emitting `None` directly.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "zlib" => Self::Zlib,
            "gzip" => Self::Gzip,
            "oodle" => Self::Oodle,
            "zstd" => Self::Zstd,
            "lz4" => Self::Lz4,
            _ => Self::UnknownByName(name.to_owned()),
        }
    }

    /// The display name as a [`Cow`](std::borrow::Cow), borrowing for the six known codecs
    /// and allocating only for the two unknown variants whose payload
    /// must be interpolated.
    ///
    /// The only PROSE rendering of this type — the one built for a
    /// human reading a metadata row. (`DecompressionFault::
    /// UnsupportedMethod` renders the same value a second way, with
    /// `{self:?}`, for operator logs; the two are deliberately distinct,
    /// see below.) `Display` is deliberately NOT implemented: `DecompressionFault::UnsupportedMethod` renders the
    /// method with `{self:?}` in a wire-stable error string, and while a
    /// `Display` existed a `{method:?}` -> `{method}` slip there would
    /// have compiled and silently rewritten operator-visible text. With
    /// no `Display`, that slip is a compile error.
    ///
    /// [`CompressionMethod::Unknown`]'s number is rendered "id/slot"
    /// because the variant does not record which namespace it came from:
    /// it is a raw method ID for v3-v7 archives and a 1-based index into
    /// the footer's method table for v8+. Naming only one would be wrong
    /// for every archive of the other vintage.
    ///
    /// Cost, per variant: the six
    /// known codecs borrow and allocate nothing here, so a caller that
    /// converts to `Arc<str>` (as `PakReader::entries` does) pays one
    /// allocation instead of the two a `to_string()` would cost; the two
    /// unknown variants allocate a `String` here regardless, so that
    /// caller pays two either way. Neither figure is per-entry — the
    /// reader interns, so it calls this once per DISTINCT method it can
    /// bound, and `Unknown(_)` is the unbounded case it deliberately
    /// cannot (see `PakReader::entries`).
    ///
    /// SECURITY CONTROL — the `{name:?}` in the
    /// [`CompressionMethod::UnknownByName`] arm below is load-bearing,
    /// not cosmetic quoting. That name is attacker-controlled text from
    /// the archive's footer table, and this string is carried on
    /// [`crate::container::EntryMetadata::compression_method_shared`]
    /// into the GUI's Info pane today and into any future text sink (a
    /// CLI column, a log field); `Debug`-formatting escapes ANSI control
    /// bytes, bidi overrides, and newlines that would otherwise inject.
    /// Do NOT "simplify" it to `\"{name}\"` — pinned by
    /// `display_escapes_hostile_unknown_names`.
    #[must_use]
    pub fn display_name(&self) -> std::borrow::Cow<'static, str> {
        use std::borrow::Cow;
        match self {
            Self::None => Cow::Borrowed("none"),
            Self::Zlib => Cow::Borrowed("Zlib"),
            Self::Gzip => Cow::Borrowed("Gzip"),
            Self::Oodle => Cow::Borrowed("Oodle"),
            Self::Zstd => Cow::Borrowed("Zstd"),
            Self::Lz4 => Cow::Borrowed("LZ4"),
            Self::Unknown(n) => Cow::Owned(format!("unknown (id/slot {n})")),
            Self::UnknownByName(name) => Cow::Owned(format!("unknown ({name:?})")),
        }
    }
}

/// Byte offset range of a single compression block within the entry payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionBlock {
    start: u64,
    end: u64,
}

impl CompressionBlock {
    /// Construct a block, rejecting `start > end` as malformed.
    pub fn new(start: u64, end: u64) -> crate::Result<Self> {
        if start > end {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::CompressionBlockInvalid { start, end },
            });
        }
        Ok(Self { start, end })
    }

    /// Start offset (inclusive) of the compressed block.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// End offset (exclusive) of the compressed block.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Length of the block in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_every_method_for_the_metadata_surface() {
        // Pins every rendering this method can produce. Note the `None`
        // arm is NOT one the metadata surface can carry: `entries()`
        // gates `with_compression_method` behind
        // `*method != CompressionMethod::None`, so "none" is unreachable
        // there and is pinned only as a total-function property. The
        // rest are the strings `EntryMetadata::compression_method_shared`
        // carries to the UIs (#662) — known codecs by canonical name,
        // unknown variants with their diagnostic payload preserved.
        assert_eq!(CompressionMethod::None.display_name(), "none");
        assert_eq!(CompressionMethod::Zlib.display_name(), "Zlib");
        assert_eq!(CompressionMethod::Gzip.display_name(), "Gzip");
        assert_eq!(CompressionMethod::Oodle.display_name(), "Oodle");
        assert_eq!(CompressionMethod::Zstd.display_name(), "Zstd");
        assert_eq!(CompressionMethod::Lz4.display_name(), "LZ4");
        // "id/slot", not "id": the variant carries a v3-v7 method ID or a
        // v8+ table index and cannot tell which.
        assert_eq!(
            CompressionMethod::Unknown(NonZeroU32::new(7).unwrap()).display_name(),
            "unknown (id/slot 7)"
        );
        assert_eq!(
            CompressionMethod::UnknownByName("LZMA".to_string()).display_name(),
            "unknown (\"LZMA\")"
        );
    }

    #[test]
    fn display_escapes_hostile_unknown_names() {
        // The FName is attacker text from the footer table and this
        // string reaches terminals and UI rows, so the Debug-escaping in
        // the UnknownByName arm is a security control. "LZMA"
        // cannot detect its removal — every character is inert — so
        // exercise the classes that actually inject.
        for (raw, needle) in [
            ("\u{1b}[31mred", "\\u{1b}"),     // ANSI escape
            ("a\nb", "\\n"),                  // newline / log forging
            ("\u{202e}gnp.exe", "\\u{202e}"), // RTL override
            ("a\rb", "\\r"),                  // carriage return
        ] {
            let rendered = CompressionMethod::UnknownByName(raw.to_string()).display_name();
            assert!(
                rendered.contains(needle),
                "hostile name {raw:?} must render escaped as {needle}, got: {rendered}"
            );
            assert!(
                !rendered.contains('\u{1b}')
                    && !rendered.contains('\n')
                    && !rendered.contains('\r')
                    && !rendered.contains('\u{202e}'),
                "no raw control/bidi byte may survive into the rendered string: {rendered}"
            );
        }
    }
}
