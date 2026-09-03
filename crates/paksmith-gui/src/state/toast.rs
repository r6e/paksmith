//! Pure toast-notification state: a list of notifications, each either
//! auto-dismissing after its severity's duration or staying until dismissed.
//! iced-free; unit + mutation tested.

use std::path::{Path, PathBuf};
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

/// How long a toast stays up.
///
/// Deliberately a per-toast property rather than a function of [`Severity`].
/// Several sites push `Severity::Error` and only one — an archive-level open
/// failure — warrants persisting, so deriving persistence from severity would
/// silently make the others permanent. Their tests assert only the severity,
/// so they would stay green while their behaviour changed; the control lives in
/// `export_completed_failed_pushes_error_toast`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifetime {
    /// Auto-expires after the severity's [`Severity::ttl`].
    Transient,
    /// Stays until the user dismisses it, or until a newer persistent toast
    /// replaces it. At most one is live at a time — see
    /// [`Toasts::push_with`].
    UntilDismissed {
        /// The file the notice is about. A persistent card outlives the action
        /// that raised it, so it needs an identity: it is what the message
        /// names, and what [`Toasts::dismiss_persistent_for`] matches so a
        /// later completed attempt on THIS file supersedes it while an
        /// unrelated one leaves it standing.
        subject: PathBuf,
    },
}

impl Lifetime {
    /// How long a toast of this lifetime stays up, or `None` if it stays until
    /// dismissed.
    ///
    /// This is the whole persistence mechanism, extracted so it can be pinned:
    /// a toast is transient only because its pusher schedules an expiry, and
    /// `None` here is what withholds that. The label alone does not pin it — a
    /// caller can hold the label and schedule an expiry regardless; how the
    /// pusher's side is asserted is that layer's concern (see
    /// `push_toast_with` in `app.rs`).
    #[must_use]
    pub fn expiry(&self, severity: Severity) -> Option<Duration> {
        match self {
            Lifetime::Transient => Some(severity.ttl()),
            Lifetime::UntilDismissed { .. } => None,
        }
    }

    /// The file this toast reports on, or `None` for a transient one.
    #[must_use]
    pub fn subject(&self) -> Option<&Path> {
        match self {
            Lifetime::Transient => None,
            Lifetime::UntilDismissed { subject } => Some(subject),
        }
    }
}

/// A single notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Stable id used to schedule auto-expiry and to target manual dismissal.
    pub id: u64,
    pub severity: Severity,
    pub message: String,
    pub lifetime: Lifetime,
}

/// The app's live toast list plus its monotonic id source.
#[derive(Debug, Default)]
pub struct Toasts {
    items: Vec<Toast>,
    next_id: u64,
}

impl Toasts {
    /// Push a toast with an explicit lifetime; returns its id.
    ///
    /// An `UntilDismissed` push first retires any existing persistent toast.
    /// That replacement is what bounds the list: nothing auto-expires these and
    /// there is no cap or dedup, so a user retrying a bad path would otherwise
    /// stack cards until they permanently occlude the overlay corner. Transient
    /// toasts are untouched — replacement is scoped to the persistent slot, so
    /// an in-flight success toast is not collateral damage.
    ///
    /// Taking the lifetime as a parameter (rather than exposing one pusher per
    /// variant) lets the caller drive BOTH the stored label and its expiry
    /// decision from a single value — see `push_toast_with` in `app.rs`. Two
    /// independent statements of the same fact can silently disagree.
    pub fn push_with(&mut self, severity: Severity, message: String, lifetime: Lifetime) -> u64 {
        if lifetime.subject().is_some() {
            self.dismiss_persistent();
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.items.push(Toast {
            id,
            severity,
            message,
            lifetime,
        });
        id
    }

    /// Remove the persistent toast, if one is live. No-op otherwise.
    ///
    /// The UNCONDITIONAL form, for the two gestures aimed at the card itself
    /// rather than at its subject: [`Self::push_with`] replacing it, and the
    /// spare-Escape handler. Nothing retires one on a timer — "until
    /// dismissed" means the user dismisses it or acts past it.
    ///
    /// For the subject-scoped form, see [`Self::dismiss_persistent_for`].
    pub fn dismiss_persistent(&mut self) {
        self.items.retain(|t| t.lifetime.subject().is_none());
    }

    /// Whether a persistent toast is live.
    ///
    /// Drives the tree-key listener's gate: the spare-Escape exit must exist
    /// even when no archive is loaded, because the mismatched-failure branch
    /// can raise a card in that state — see `tree_key_listener_active` in
    /// `app.rs`.
    #[must_use]
    pub fn has_persistent(&self) -> bool {
        self.items.iter().any(|t| t.lifetime.subject().is_some())
    }

    /// Remove the persistent toast if it reports on `path`. No-op otherwise.
    ///
    /// Called from the completed-attempt arms that own their outcome's
    /// surface: `Ok`, and `Locked` (reaching the key prompt supersedes a
    /// failure report about the same file). The prompt's own wrong-key branch
    /// completes an attempt too and deliberately does NOT call this: it is
    /// gated on the failure matching the prompt's file, and a card about that
    /// file cannot exist — the `Locked` arm that raised the prompt retired
    /// it. A card about a different file is deliberately left standing
    /// everywhere: the user has one notice per failed file and a success
    /// elsewhere is not evidence about it. Matching on the path rather than
    /// clearing on any success is also what keeps a slow earlier open,
    /// landing after a later one already failed, from retiring the newer
    /// file's card unreplaced.
    pub fn dismiss_persistent_for(&mut self, path: &Path) {
        self.items
            .retain(|t| t.lifetime.subject().is_none_or(|s| s != path));
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
        let a = toasts.push_with(Severity::Success, "one".to_string(), Lifetime::Transient);
        let b = toasts.push_with(Severity::Error, "two".to_string(), Lifetime::Transient);
        assert_ne!(a, b, "each toast gets a distinct id");
        assert!(b > a, "ids increase monotonically");
    }

    #[test]
    fn push_appends_in_order_and_preserves_fields() {
        let mut toasts = Toasts::default();
        let _ = toasts.push_with(Severity::Success, "first".to_string(), Lifetime::Transient);
        let _ = toasts.push_with(Severity::Error, "second".to_string(), Lifetime::Transient);
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
        let keep = toasts.push_with(Severity::Success, "keep".to_string(), Lifetime::Transient);
        let drop = toasts.push_with(Severity::Error, "drop".to_string(), Lifetime::Transient);
        toasts.remove(drop);
        let items = toasts.items();
        assert_eq!(items.len(), 1, "exactly one toast removed");
        assert_eq!(items[0].id, keep, "the non-matching toast survives");
        assert_eq!(items[0].message, "keep");
    }

    #[test]
    fn remove_absent_id_is_a_noop() {
        let mut toasts = Toasts::default();
        let only = toasts.push_with(Severity::Success, "only".to_string(), Lifetime::Transient);
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
        let id = toasts.push_with(Severity::Error, "x".to_string(), Lifetime::Transient);
        assert!(!toasts.is_empty(), "non-empty after a push");
        toasts.remove(id);
        assert!(
            toasts.is_empty(),
            "empty again after removing the last toast"
        );
    }

    /// An `UntilDismissed` lifetime for the default test subject.
    fn persistent() -> Lifetime {
        persistent_for("a.pak")
    }

    fn persistent_for(path: &str) -> Lifetime {
        Lifetime::UntilDismissed {
            subject: PathBuf::from(path),
        }
    }

    #[test]
    fn push_with_until_dismissed_marks_the_toast() {
        let mut toasts = Toasts::default();
        let _ = toasts.push_with(Severity::Error, "stays".to_string(), persistent());
        assert_eq!(toasts.items()[0].lifetime, persistent());
        assert_eq!(toasts.items()[0].severity, Severity::Error);
        assert_eq!(toasts.items()[0].message, "stays");
    }

    #[test]
    fn until_dismissed_push_replaces_the_previous_one() {
        // Why replacement is required: see `Toasts::push_with`.
        // Two DIFFERENT subjects: the bound is on the slot, not on the file,
        // so a second failed file replaces the first rather than adding to it.
        let mut toasts = Toasts::default();
        let first = toasts.push_with(
            Severity::Error,
            "first".to_string(),
            persistent_for("first.pak"),
        );
        let second = toasts.push_with(
            Severity::Error,
            "second".to_string(),
            persistent_for("second.pak"),
        );
        assert_ne!(first, second, "the replacement gets a fresh id");
        let sticky: Vec<_> = toasts
            .items()
            .iter()
            .filter(|t| t.lifetime.subject().is_some())
            .collect();
        assert_eq!(sticky.len(), 1, "only one persistent toast survives");
        assert_eq!(sticky[0].message, "second", "the newest one wins");
    }

    #[test]
    fn until_dismissed_push_leaves_transient_toasts_alone() {
        // Replacement is scoped to the persistent slot: an in-flight success
        // toast must not be collateral damage.
        let mut toasts = Toasts::default();
        let keep = toasts.push_with(Severity::Success, "copied".to_string(), Lifetime::Transient);
        let _ = toasts.push_with(Severity::Error, "one".to_string(), persistent());
        let _ = toasts.push_with(Severity::Error, "two".to_string(), persistent());
        assert!(
            toasts.items().iter().any(|t| t.id == keep),
            "the transient toast survives a persistent replacement"
        );
        assert_eq!(toasts.items().len(), 2, "transient + one persistent");
    }

    #[test]
    fn dismiss_persistent_for_spares_transients_and_other_subjects() {
        // The retain keeps a toast when it has NO subject (transient) or a
        // DIFFERENT subject; flipping `is_none_or` to `is_some_and` inverts
        // the first half and every completed open would silently destroy every
        // live transient toast. Neither of the app-level path-scoping tests
        // can see that — they never hold a transient during the open.
        let mut toasts = Toasts::default();
        let transient =
            toasts.push_with(Severity::Success, "copied".to_string(), Lifetime::Transient);
        let _ = toasts.push_with(
            Severity::Error,
            "stays".to_string(),
            persistent_for("other.pak"),
        );
        toasts.dismiss_persistent_for(Path::new("match-nothing.pak"));
        assert_eq!(toasts.items().len(), 2, "no subject matched: full no-op");

        toasts.dismiss_persistent_for(Path::new("other.pak"));
        assert_eq!(toasts.items().len(), 1, "the matching card goes");
        assert_eq!(
            toasts.items()[0].id,
            transient,
            "the transient survives a matching retirement"
        );
    }

    #[test]
    fn expiry_is_none_only_for_until_dismissed() {
        // The layer-local pin on the `Lifetime::expiry` mapping. NOT sole
        // custody: `persistent_push_schedules_no_expiry_task` (app.rs) reads
        // the scheduling decision off the pusher's returned task and covers
        // both this arm and the pusher's own guard — it is the test whose
        // deletion would silently restore the 8-second card. This one exists
        // so the pure function is pinned where it lives.
        assert_eq!(
            persistent().expiry(Severity::Error),
            None,
            "a persistent toast schedules no expiry"
        );
        assert_eq!(
            persistent().expiry(Severity::Success),
            None,
            "and severity cannot reintroduce one"
        );
        assert_eq!(
            Lifetime::Transient.expiry(Severity::Error),
            Some(Duration::from_secs(8))
        );
        assert_eq!(
            Lifetime::Transient.expiry(Severity::Success),
            Some(Duration::from_secs(4))
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
