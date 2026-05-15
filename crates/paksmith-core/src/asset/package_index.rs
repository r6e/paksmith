//! Typed wrapper around UE's i32 import/export reference encoding.
//!
//! UE encodes object references as a single `i32` where `0 = Null`,
//! positive values are 1-based indices into the export table
//! (`1 → exports[0]`), and negative values are 1-based mirrors of the
//! import table (`-1 → imports[0]`). The encoding is uniform across
//! every `OuterIndex`, `ClassIndex`, `SuperIndex`, `TemplateIndex`
//! field in the wire format.
//!
//! Wrapping the raw i32 in this typed enum keeps the "+1 / -1 / 0
//! sentinel" arithmetic in one place — every dereference site reads
//! the typed variant rather than re-deriving the indexing.

use std::fmt;

/// Typed reference to an entry in the import table, the export table,
/// or `Null`.
///
/// Decoded from the on-wire `i32`:
/// - `0` → [`Self::Null`]
/// - positive `n` → [`Self::Export(n as u32 - 1)`]
/// - negative `n` → [`Self::Import((-n) as u32 - 1)`]
///
/// `Copy` because the payload is one u32 — cheaper to pass by value
/// than by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIndex {
    /// The reference is null (UE's `INDEX_NONE`-via-PackageIndex).
    Null,
    /// 0-based index into the import table.
    Import(u32),
    /// 0-based index into the export table.
    Export(u32),
}

impl PackageIndex {
    /// Decode from the raw wire i32, surfacing `i32::MIN` as a typed
    /// error rather than panicking. Used at every wire-read site.
    ///
    /// # Errors
    /// Returns [`PackageIndexError::ImportIndexUnderflow`] when
    /// `raw == i32::MIN`.
    pub fn try_from_raw(raw: i32) -> Result<Self, PackageIndexError> {
        match raw {
            0 => Ok(Self::Null),
            1.. => Ok(Self::Export((raw - 1) as u32)),
            i32::MIN => Err(PackageIndexError::ImportIndexUnderflow),
            _ => Ok(Self::Import((-raw - 1) as u32)),
        }
    }

    /// Re-encode to the on-wire i32.
    ///
    /// # Panics (debug builds)
    /// Panics in debug builds if a synthetic `PackageIndex::Export(i)` or
    /// `PackageIndex::Import(i)` carries `i > i32::MAX as u32 - 1`. The
    /// wire-read path via [`Self::try_from_raw`] never produces such a
    /// value (its output is bounded to `0..=i32::MAX - 1`), so only direct
    /// construction (fixture-gen, test builders) can trip this. Release
    /// builds wrap silently — callers building synthetic values must
    /// validate the input before constructing the variant.
    #[must_use]
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Null => 0,
            Self::Export(i) => {
                debug_assert!(
                    i < i32::MAX as u32,
                    "PackageIndex::Export({i}) exceeds i32::MAX - 1; constructable only via try_from_raw or validated synthetic source"
                );
                (i as i32) + 1
            }
            Self::Import(i) => {
                debug_assert!(
                    i < i32::MAX as u32,
                    "PackageIndex::Import({i}) exceeds i32::MAX - 1; constructable only via try_from_raw or validated synthetic source"
                );
                -((i as i32) + 1)
            }
        }
    }
}

impl serde::Serialize for PackageIndex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Render via Display so JSON shows "Null" / "Import(N)" / "Export(N)"
        // — matches the inspect-output contract (phase-2a-uasset-header.md
        // Task 14 deliverable). Derives like `#[serde(tag = ...)]` would
        // emit a tagged object, diverging from the documented shape.
        serializer.collect_str(self)
    }
}

impl fmt::Display for PackageIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Import(i) => write!(f, "Import({i})"),
            Self::Export(i) => write!(f, "Export({i})"),
        }
    }
}

/// Errors from [`PackageIndex::try_from_raw`]. Bubbled up as
/// [`AssetParseFault`](crate::error::AssetParseFault) variants by
/// callers — this enum stays in `asset::` so the test module can pin
/// without importing the top-level error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIndexError {
    /// The wire value was `i32::MIN` — has no representable positive
    /// counterpart. Practically only emitted by malicious / corrupted
    /// archives (UE writers never produce it).
    ImportIndexUnderflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_round_trip() {
        let pi = PackageIndex::try_from_raw(0).unwrap();
        assert_eq!(pi, PackageIndex::Null);
        assert_eq!(pi.to_raw(), 0);
    }

    #[test]
    fn import_round_trip() {
        let pi = PackageIndex::try_from_raw(-3).unwrap();
        assert_eq!(pi, PackageIndex::Import(2));
        assert_eq!(pi.to_raw(), -3);
    }

    #[test]
    fn export_round_trip() {
        let pi = PackageIndex::try_from_raw(5).unwrap();
        assert_eq!(pi, PackageIndex::Export(4));
        assert_eq!(pi.to_raw(), 5);
    }

    #[test]
    fn import_min_avoids_overflow() {
        assert_eq!(
            PackageIndex::try_from_raw(i32::MIN),
            Err(PackageIndexError::ImportIndexUnderflow),
        );
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", PackageIndex::Null), "Null");
        assert_eq!(format!("{}", PackageIndex::Import(2)), "Import(2)");
        assert_eq!(format!("{}", PackageIndex::Export(4)), "Export(4)");
    }

    #[test]
    fn serialize_to_display_string() {
        assert_eq!(
            serde_json::to_string(&PackageIndex::Null).unwrap(),
            r#""Null""#
        );
        assert_eq!(
            serde_json::to_string(&PackageIndex::Import(2)).unwrap(),
            r#""Import(2)""#
        );
        assert_eq!(
            serde_json::to_string(&PackageIndex::Export(4)).unwrap(),
            r#""Export(4)""#
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "PackageIndex::Export")]
    fn to_raw_panics_on_export_overflow_in_debug() {
        let _ = PackageIndex::Export(u32::MAX).to_raw();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "PackageIndex::Import")]
    fn to_raw_panics_on_import_overflow_in_debug() {
        let _ = PackageIndex::Import(u32::MAX).to_raw();
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn raw_to_typed_to_raw_is_identity(raw in (i32::MIN + 1)..=i32::MAX) {
            let pi = PackageIndex::try_from_raw(raw).unwrap();
            prop_assert_eq!(pi.to_raw(), raw);
        }

        #[test]
        fn typed_to_raw_to_typed_is_identity_for_export(idx in 0u32..(i32::MAX as u32 - 1)) {
            let pi = PackageIndex::Export(idx);
            let round = PackageIndex::try_from_raw(pi.to_raw()).unwrap();
            prop_assert_eq!(round, pi);
        }

        #[test]
        fn typed_to_raw_to_typed_is_identity_for_import(idx in 0u32..(i32::MAX as u32 - 1)) {
            let pi = PackageIndex::Import(idx);
            let round = PackageIndex::try_from_raw(pi.to_raw()).unwrap();
            prop_assert_eq!(round, pi);
        }
    }
}
