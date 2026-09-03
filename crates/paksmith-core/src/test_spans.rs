//! Test-only span capture for the #665 tracing-span boundaries.
//!
//! A minimal [`tracing::Subscriber`] that records every span's name and
//! fields, so tests can assert an operation emitted its documented span
//! without any new dependency: `tracing-test` (the event-capture dev-dep)
//! exposes formatted LOG lines, not span creation, so it cannot see a span
//! that contains no events. Install via [`SpanRecorder::capture_until`] —
//! thread-local, so it works across `.await` points on tokio's
//! current-thread test runtime and cannot leak into other tests.
//!
//! Parallel-test hazard, and why the capture helpers retry: a
//! `#[instrument]` callsite registers itself lazily on its FIRST-EVER
//! hit, and that registration rebuilds its interest via tracing-core's
//! `Rebuilder::JustOne` fast path (0.1.36, `callsite.rs:319` +
//! `callsite.rs:545`), which evaluates against the REGISTERING thread's
//! current default — not the registered dispatcher set. A sibling test
//! running with no subscriber can therefore be the first to hit the
//! function under test and cache `Interest::never` while this recorder's
//! guard is live on another thread, silently skipping the span
//! (observed: ~1-in-4 full-suite runs at 16 threads flaked exactly this
//! way). [`SpanRecorder::capture_until`]'s retry is deterministic, not a
//! sleep: the SECOND attempt's [`SpanRecorder::install`] constructs a new
//! `Dispatch`, whose registration (`Dispatch::new` →
//! `callsite::register_dispatch`) rebuilds every callsite's interest from
//! the live registered-dispatcher snapshot — which includes the fresh
//! recorder — so the poisoned callsite, permanently registered by the
//! first miss, is re-armed before the second attempt runs — in practice a
//! second miss means the attribute is genuinely absent. (Not a proof:
//! `register` pushes a callsite to the global list BEFORE computing its
//! interest (`callsite.rs:318` then `:319`), so a concurrent
//! `register_dispatch` rebuild could store `always` only for the
//! registering thread's `JustOne` store of `never` to overwrite it. That
//! window has never been observed across repeated 16-thread stress
//! batteries here; if a span test ever flakes twice running, suspect it
//! before suspecting the attribute.) (Calling
//! `rebuild_interest_cache()` between attempts would be WORSE than
//! useless: it would run after the first guard dropped, where the thread
//! default is `NoSubscriber`, and the same `JustOne` fast path would
//! re-cache `Interest::never` — poisoning concurrent span tests.)

use std::fmt;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata};

/// One captured span: its static name plus every field rendered to a string.
#[derive(Debug, Clone)]
pub(crate) struct RecordedSpan {
    pub name: &'static str,
    pub fields: Vec<(String, String)>,
}

/// Records `new_span` calls; everything else is a no-op.
#[derive(Clone, Default)]
pub(crate) struct SpanRecorder {
    spans: Arc<Mutex<Vec<RecordedSpan>>>,
}

impl SpanRecorder {
    /// Build a recorder and install it as this thread's default subscriber.
    ///
    /// Hold the guard for the duration of the operation under test; spans
    /// created on this thread (including across `.await` on a current-thread
    /// runtime) are recorded until it drops. Prefer [`Self::capture_until`]
    /// / [`Self::capture_until_async`], which also close the
    /// lazy-registration race described in the module doc.
    pub fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let rec = Self::default();
        let guard = tracing::subscriber::set_default(rec.clone());
        (rec, guard)
    }

    /// Run `op` with a fresh recorder installed; if `ok(&recorder)` does not
    /// hold, run it once more with another fresh recorder — whose
    /// installation re-arms the callsite (see the module doc) — and return
    /// that attempt's recorder.
    ///
    /// `ok` is the RETRY condition, not the assertion: pass the minimal
    /// span-presence/count predicate the test's assertions depend on, and
    /// keep the real assertions (with their messages) after the call. Each
    /// attempt uses a fresh recorder, so per-attempt counts stay exact. A
    /// span that never appears exhausts the attempts and the caller's
    /// assertions fail loudly — a stripped `#[instrument]` is still caught.
    pub fn capture_until(mut op: impl FnMut(), ok: impl Fn(&Self) -> bool) -> Self {
        let (rec, guard) = Self::install();
        op();
        drop(guard);
        if ok(&rec) {
            return rec;
        }
        // Second attempt: this install()'s Dispatch registration re-arms the
        // poisoned callsite (see the module doc) — decisive by construction.
        let (rec, guard) = Self::install();
        op();
        drop(guard);
        rec
    }

    /// [`Self::capture_until`] for async operations, driven on the caller's
    /// runtime.
    pub async fn capture_until_async<F, Fut>(mut op: F, ok: impl Fn(&Self) -> bool) -> Self
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let (rec, guard) = Self::install();
        op().await;
        drop(guard);
        if ok(&rec) {
            return rec;
        }
        let (rec, guard) = Self::install();
        op().await;
        drop(guard);
        rec
    }

    /// Count of recorded spans named `span`.
    pub fn count(&self, span: &str) -> usize {
        self.names().iter().filter(|n| **n == span).count()
    }

    /// Names of every span recorded so far, in creation order.
    pub fn names(&self) -> Vec<&'static str> {
        self.spans
            .lock()
            .expect("span list lock")
            .iter()
            .map(|s| s.name)
            .collect()
    }

    /// Every recorded span, in creation order.
    ///
    /// Gated like its only caller (`export/mod.rs`'s `facade_tests`): the
    /// package-scoped no-feature build compiles this module without that
    /// test module, and `-D warnings` turns the resulting dead code into a
    /// compile error.
    #[cfg(feature = "__test_utils")]
    pub fn spans(&self) -> Vec<RecordedSpan> {
        self.spans.lock().expect("span list lock").clone()
    }

    /// The rendered value of `field` on the FIRST span named `span`.
    pub fn field(&self, span: &str, field: &str) -> Option<String> {
        self.spans
            .lock()
            .expect("span list lock")
            .iter()
            .find(|s| s.name == span)?
            .fields
            .iter()
            .find(|(k, _)| k == field)
            .map(|(_, v)| v.clone())
    }
}

/// Renders every field type to a plain string (`record_debug` catches the
/// `%`-display wrappers, whose `Debug` forwards to `Display`, so display
/// fields come out quote-free).
struct FieldCollector(Vec<(String, String)>);

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .push((field.name().to_string(), format!("{value:?}")));
    }

    // Only `record_str` needs an override beyond `record_debug`: it strips
    // the quotes `Debug` adds around strings. Integers and bools render
    // identically under Debug and Display, so the trait defaults (which
    // forward to `record_debug`) already produce the expected text.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl tracing::Subscriber for SpanRecorder {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut collector = FieldCollector(Vec::new());
        attrs.record(&mut collector);
        let mut spans = self.spans.lock().expect("span list lock");
        spans.push(RecordedSpan {
            name: attrs.metadata().name(),
            fields: collector.0,
        });
        // Ids must be non-zero; the post-push length is, and is unique here.
        Id::from_u64(spans.len() as u64)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}
