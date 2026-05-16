//! Decoded property body for one export.
//!
//! Phase 2a ships only the [`PropertyBag::Opaque`] variant — the
//! export's serialized bytes are carried verbatim. Phase 2b lands the
//! tagged-property iterator that produces typed `Tree` payloads
//! (added as a new variant under `#[non_exhaustive]`); Phase 2c lands
//! the container properties whose recursive parsing is bounded by
//! `MAX_PROPERTY_DEPTH`.

use std::fmt;

use serde::Serialize;

/// Hard cap on nested struct/array/map depth in the property tree.
/// Defined here in Phase 2a even though only Phase 2c references it,
/// to lock the contract before downstream parsers are written. Value
/// chosen to match FModel's nesting bound; UE assets in practice
/// never nest beyond ~12.
///
/// Visibility is `pub(crate)` because every other Phase 2a structural
/// cap (`MAX_NAME_TABLE_ENTRIES`, `MAX_IMPORT_TABLE_ENTRIES`, etc.) is
/// private — this is a defensive bound for in-crate parsers, not a
/// semantic compatibility boundary like `FIRST_UNSUPPORTED_UE5_VERSION`.
/// `dead_code` is allowed until Phase 2c's recursive container
/// readers consume it; `max_depth_constant_is_locked` pins the value
/// contract regardless of consumer status.
#[allow(
    dead_code,
    reason = "consumer lands in Phase 2c container property readers"
)]
pub(crate) const MAX_PROPERTY_DEPTH: usize = 128;

/// Decoded body for one export.
///
/// `#[non_exhaustive]` so Phase 2b can add a `Tree` variant without
/// source-breaking downstream `match` arms.
///
/// `Debug` is hand-rolled to elide the `Opaque` byte content (mirrors
/// the `Serialize` impl). The derived `Debug` would emit the entire
/// `Vec<u8>` inline; for an export with megabyte-class payload, that
/// blows up any `dbg!`/`tracing::debug!`/panic dump.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropertyBag {
    /// Phase 2a: raw bytes carved out of the asset's payload region.
    Opaque {
        /// The export's serialized bytes (length matches
        /// `ObjectExport::serial_size`).
        #[serde(serialize_with = "serialize_byte_count")]
        bytes: Vec<u8>,
    },
}

impl fmt::Debug for PropertyBag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opaque { bytes } => f
                .debug_struct("Opaque")
                .field("bytes", &format_args!("<{} bytes>", bytes.len()))
                .finish(),
        }
    }
}

impl PropertyBag {
    /// Convenience constructor for the Phase-2a opaque variant.
    #[must_use]
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self::Opaque { bytes }
    }

    /// Number of bytes in the bag (raw payload bytes for Opaque).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Opaque { bytes } => bytes.len(),
        }
    }
}

/// Serialize `bytes` as just its length, not its content. Asset
/// payloads can be megabytes; serializing them inline would blow up
/// `inspect` JSON output. Phase 2b's `Tree` variant will serialize
/// the decoded property structure instead.
#[allow(
    clippy::ptr_arg,
    reason = "serde's #[serialize_with] requires &Vec<u8> exactly — it doesn't auto-deref to &[u8]"
)]
fn serialize_byte_count<S: serde::Serializer>(
    bytes: &Vec<u8>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(bytes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_byte_len() {
        let bag = PropertyBag::opaque(vec![0u8; 84]);
        assert_eq!(bag.byte_len(), 84);
    }

    #[test]
    fn serialize_renders_byte_count_not_payload() {
        let bag = PropertyBag::opaque(vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&bag).unwrap();
        assert_eq!(json, r#"{"kind":"opaque","bytes":5}"#);
    }

    #[test]
    fn max_depth_constant_is_locked() {
        assert_eq!(MAX_PROPERTY_DEPTH, 128);
    }

    #[test]
    fn debug_elides_byte_content() {
        // Custom Debug impl mirrors Serialize: emits the byte count,
        // not the bytes themselves. Prevents a megabyte-class payload
        // from blowing up dbg!/tracing::debug!/panic dumps.
        let bag = PropertyBag::opaque(vec![0u8; 1_048_576]);
        let debug_output = format!("{bag:?}");
        assert!(
            !debug_output.contains("0, 0, 0"),
            "Debug should not emit byte content; got: {debug_output}"
        );
        assert!(
            debug_output.contains("1048576 bytes"),
            "Debug should emit byte count; got: {debug_output}"
        );
    }
}
