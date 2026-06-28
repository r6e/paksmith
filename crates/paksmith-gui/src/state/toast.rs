//! Pure toast-notification state: a list of transient notifications with
//! per-severity auto-dismiss durations. iced-free; unit + mutation tested.

use std::time::Duration;

/// Auto-dismiss delay for a success toast.
const SUCCESS_TTL: Duration = Duration::from_secs(4);
/// Auto-dismiss delay for an error toast — longer, so failures can be read.
const ERROR_TTL: Duration = Duration::from_secs(8);

/// Toast severity — drives tint and auto-dismiss duration. No `Info`: no
/// agreed trigger produces one (see the Phase 7c design spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Success,
    Error,
}

impl Severity {
    /// How long a toast of this severity stays up before auto-expiring.
    #[must_use]
    pub fn ttl(self) -> Duration {
        match self {
            Severity::Success => SUCCESS_TTL,
            Severity::Error => ERROR_TTL,
        }
    }
}

/// A single transient notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Stable id used to schedule auto-expiry and to target manual dismissal.
    pub id: u64,
    pub severity: Severity,
    pub message: String,
}

/// The app's live toast list plus its monotonic id source.
#[derive(Debug, Default)]
pub struct Toasts {
    items: Vec<Toast>,
    next_id: u64,
}

impl Toasts {
    /// Push a new toast; returns its id so the caller can schedule auto-expiry.
    pub fn push(&mut self, severity: Severity, message: String) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.items.push(Toast {
            id,
            severity,
            message,
        });
        id
    }

    /// Remove the toast with `id` if present (no-op otherwise). Used by both
    /// manual dismiss and auto-expiry, so it is idempotent — a late expiry after
    /// a manual dismiss does nothing.
    pub fn remove(&mut self, id: u64) {
        self.items.retain(|t| t.id != id);
    }

    /// The current toasts, oldest first.
    #[must_use]
    pub fn items(&self) -> &[Toast] {
        &self.items
    }

    /// Whether there are any toasts (so `view` can skip the overlay layer).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn push_assigns_increasing_distinct_ids() {
        let mut toasts = Toasts::default();
        let a = toasts.push(Severity::Success, "one".to_string());
        let b = toasts.push(Severity::Error, "two".to_string());
        assert_ne!(a, b, "each toast gets a distinct id");
        assert!(b > a, "ids increase monotonically");
    }

    #[test]
    fn push_appends_in_order_and_preserves_fields() {
        let mut toasts = Toasts::default();
        let _ = toasts.push(Severity::Success, "first".to_string());
        let _ = toasts.push(Severity::Error, "second".to_string());
        let items = toasts.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].message, "first");
        assert_eq!(items[0].severity, Severity::Success);
        assert_eq!(items[1].message, "second");
        assert_eq!(items[1].severity, Severity::Error);
    }

    #[test]
    fn remove_removes_only_the_matching_id() {
        let mut toasts = Toasts::default();
        let keep = toasts.push(Severity::Success, "keep".to_string());
        let drop = toasts.push(Severity::Error, "drop".to_string());
        toasts.remove(drop);
        let items = toasts.items();
        assert_eq!(items.len(), 1, "exactly one toast removed");
        assert_eq!(items[0].id, keep, "the non-matching toast survives");
        assert_eq!(items[0].message, "keep");
    }

    #[test]
    fn remove_absent_id_is_a_noop() {
        let mut toasts = Toasts::default();
        let only = toasts.push(Severity::Success, "only".to_string());
        toasts.remove(only.wrapping_add(999)); // never issued
        assert_eq!(
            toasts.items().len(),
            1,
            "removing an absent id changes nothing"
        );
    }

    #[test]
    fn is_empty_reflects_contents() {
        let mut toasts = Toasts::default();
        assert!(toasts.is_empty(), "a fresh list is empty");
        let id = toasts.push(Severity::Error, "x".to_string());
        assert!(!toasts.is_empty(), "non-empty after a push");
        toasts.remove(id);
        assert!(
            toasts.is_empty(),
            "empty again after removing the last toast"
        );
    }

    #[test]
    fn ttl_is_severity_specific_and_error_outlasts_success() {
        // Pins the exact constants AND that the match maps each arm correctly —
        // a swapped/duplicated arm would make these equal or wrong.
        assert_eq!(Severity::Success.ttl(), Duration::from_secs(4));
        assert_eq!(Severity::Error.ttl(), Duration::from_secs(8));
        assert!(
            Severity::Error.ttl() > Severity::Success.ttl(),
            "errors stay up longer than successes"
        );
    }
}
