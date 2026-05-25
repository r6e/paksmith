//! Phase 3b lands the real `FByteBulkData` / `BulkDataResolver` /
//! `BulkData` types in this module. 3a ships a unit struct so the
//! `FormatHandler::export` signature in `crate::export` compiles
//! against the type identity; 3b's PR widens to fields-bearing in a
//! single atomic change.
//!
//! Why unit struct, not `_private: ()` hidden field? A unit struct
//! exposes no destructurable FIELD surface — so 3b's widening to
//! `BulkData { bytes: ..., record: ..., tier: ... }` doesn't break
//! any field-destructure pattern (none exists today). The
//! hidden-field placeholder approach would ship a `#[doc(hidden)]`
//! field that a paranoid downstream could destructure-match
//! (`BulkData { _private }`), which would break at 3b.

/// Resolved bulk-data payload. **3a unit-struct stub.**
///
/// # Breaking change at 3b
///
/// 3b's PR widens this to a fields-bearing struct carrying
/// `bytes: Vec<u8>`, `record: FByteBulkData`, and
/// `tier: BulkDataTier`. The widening doesn't break field-pattern
/// match arms (none can exist on a unit struct today), but it
/// DOES break direct unit-literal construction:
///
/// ```rust,ignore
/// // Works in 3a, breaks at 3b:
/// let bulk = paksmith_core::export::BulkData;
/// ```
///
/// Phase 3 internal callers should treat `BulkData` as
/// constructor-opaque; 3b adds the necessary constructors via
/// `BulkDataResolver`. External consumers don't need to construct
/// `BulkData` in 3a (handlers receive `Option<&BulkData>` and
/// today's `GenericHandler` ignores the argument).
#[derive(Debug, Clone)]
pub struct BulkData;
