//! Bounded in-memory ring buffer of `tracing` events for the debug console.
//!
//! A [`RingBufferLayer`] (installed once in `main`) writes every event into a
//! shared [`LogBuffer`]; the GUI reads a [`LogBuffer::snapshot`] each frame.
//! Pure ring logic is unit + mutation tested; the `Layer`/`Visit` glue is
//! integration-tested via a scoped subscriber.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Maximum number of records retained. Oldest are evicted first.
const CONSOLE_RING_CAPACITY: usize = 2000;

/// One captured log event.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Monotonic sequence number assigned at capture (stable ordering key).
    pub seq: u64,
    /// Severity level.
    pub level: Level,
    /// Event target (module path or an explicit `target:`).
    pub target: String,
    /// Rendered message: the `message` field plus any `key=value` fields.
    pub message: String,
}

#[derive(Default)]
struct RingState {
    records: VecDeque<LogRecord>,
    next_seq: u64,
}

/// A cloneable handle to the shared, bounded log ring.
///
/// Cloning shares the same underlying buffer (`Arc`). The tracing `Layer`
/// holds one clone (writer); the GUI `App` holds another (reader).
#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<RingState>>,
}

/// True when a ring holding `len` records is at capacity and must evict before
/// the next push. Extracted as a pure predicate so the boundary is
/// mutation-tested on both sides, independent of the push path's invariant.
fn ring_is_full(len: usize) -> bool {
    len >= CONSOLE_RING_CAPACITY
}

impl LogBuffer {
    /// Append a record, evicting the oldest if at capacity, and assign the next
    /// sequence number. The lock is held only for the push — never across an
    /// `.await`.
    pub fn push(&self, level: Level, target: String, message: String) {
        // A poisoned lock means a prior holder panicked mid-mutation; recover
        // the guard and continue. We only append, so losing atomicity is
        // harmless, and a debug console must never panic the app.
        let mut state = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let seq = state.next_seq;
        state.next_seq += 1;
        if ring_is_full(state.records.len()) {
            drop(state.records.pop_front());
        }
        state.records.push_back(LogRecord {
            seq,
            level,
            target,
            message,
        });
    }

    /// Remove all records. Sequence numbering continues (monotonic across
    /// clears) so a later record never reuses an earlier seq.
    pub fn clear(&self) {
        let mut state = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        state.records.clear();
    }

    /// Snapshot the current records (oldest first) for rendering. Clones the
    /// retained records (≤ capacity); called only while the console is visible.
    pub fn snapshot(&self) -> Vec<LogRecord> {
        let state = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        state.records.iter().cloned().collect()
    }
}

/// A `tracing` layer that records every event into a [`LogBuffer`].
pub struct RingBufferLayer {
    buffer: LogBuffer,
}

impl RingBufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for RingBufferLayer {
    // Event-wiring glue: needs a live tracing dispatcher to exercise, covered
    // by `ring_layer_captures_*` via `with_default`, not mutation-tested.
    #[mutants::skip]
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.buffer.push(
            *meta.level(),
            meta.target().to_string(),
            visitor.into_message(),
        );
    }
}

/// Collects the `message` field and appends any other fields as ` key=value`.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn into_message(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.fields.trim_start().to_string()
        } else {
            format!("{}{}", self.message, self.fields)
        }
    }
}

impl Visit for MessageVisitor {
    // All typed `record_*` default to `record_debug`, so overriding this one
    // captures every field. Trait glue — integration-tested, not mutated.
    #[mutants::skip]
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
}

/// Install a global tracing subscriber that records events into `buffer`.
///
/// Capture floor defaults to `warn` for dependencies plus `debug` for the
/// paksmith crates, overridable via `RUST_LOG`. The `warn` floor keeps
/// wgpu/naga/iced INFO chatter out of the bounded ring so the console reads as
/// paksmith-focused. A no-op if a subscriber is already installed (e.g. in
/// tests) — never panics.
#[mutants::skip] // global one-shot subscriber install; not unit-testable
pub fn init_console_tracing(buffer: LogBuffer) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,paksmith_core=debug,paksmith_gui=debug"));
    let _ = tracing_subscriber::registry()
        .with(RingBufferLayer::new(buffer))
        .with(filter)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn push_assigns_monotonic_seq_from_zero() {
        let b = LogBuffer::default();
        b.push(Level::INFO, "t".into(), "a".into());
        b.push(Level::WARN, "t".into(), "b".into());
        b.push(Level::ERROR, "t".into(), "c".into());
        let seqs: Vec<u64> = b.snapshot().iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
    }

    #[test]
    fn ring_is_full_predicate_is_exact_at_capacity_boundary() {
        assert!(!ring_is_full(CONSOLE_RING_CAPACITY - 1));
        assert!(ring_is_full(CONSOLE_RING_CAPACITY));
        assert!(ring_is_full(CONSOLE_RING_CAPACITY + 1));
    }

    #[test]
    fn ring_evicts_oldest_beyond_capacity() {
        let b = LogBuffer::default();
        for i in 0..(CONSOLE_RING_CAPACITY + 5) {
            b.push(Level::INFO, "t".into(), format!("m{i}"));
        }
        let r = b.snapshot();
        assert_eq!(r.len(), CONSOLE_RING_CAPACITY);
        // First 5 evicted: oldest retained is m5 at seq 5; newest is the last push.
        assert_eq!(r.first().unwrap().message, "m5");
        assert_eq!(r.first().unwrap().seq, 5);
        assert_eq!(
            r.last().unwrap().message,
            format!("m{}", CONSOLE_RING_CAPACITY + 4)
        );
    }

    #[test]
    fn clear_empties_but_seq_stays_monotonic() {
        let b = LogBuffer::default();
        b.push(Level::INFO, "t".into(), "a".into());
        b.clear();
        assert!(b.snapshot().is_empty());
        b.push(Level::INFO, "t".into(), "b".into());
        let r = b.snapshot();
        assert_eq!(r.len(), 1);
        // Continues from before the clear (1), never reused back to 0.
        assert_eq!(r[0].seq, 1);
    }

    #[test]
    fn ring_layer_captures_level_target_and_message() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::registry().with(RingBufferLayer::new(buffer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "paksmith_test", "hello {}", "world");
        });
        let r = buffer.snapshot();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level, Level::INFO);
        assert_eq!(r[0].target, "paksmith_test");
        assert_eq!(r[0].message, "hello world");
    }

    // `into_message` has three branches (fields-only, message-only, combined).
    // Construct `MessageVisitor` directly so each branch is pinned with exact,
    // deterministic input — no dependence on tracing's field-recording order.

    #[test]
    fn into_message_returns_message_when_no_extra_fields() {
        let v = MessageVisitor {
            message: "hello world".into(),
            fields: String::new(),
        };
        assert_eq!(v.into_message(), "hello world");
    }

    #[test]
    fn into_message_trims_leading_space_when_fields_only() {
        let v = MessageVisitor {
            message: String::new(),
            fields: " count=7".into(),
        };
        assert_eq!(v.into_message(), "count=7");
    }

    #[test]
    fn into_message_concatenates_message_then_fields() {
        let v = MessageVisitor {
            message: "load failed".into(),
            fields: " count=5".into(),
        };
        assert_eq!(v.into_message(), "load failed count=5");
    }
}
