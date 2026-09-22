//! Theme: follows the OS light/dark preference, reads the system accent once
//! at startup where a backend exists (macOS only — see [`accent`]), and maps
//! both onto an Iced theme + the design tokens.

pub mod accent;
pub mod tokens;

/// Light or dark appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
}

/// One OS appearance reading, preserving the tri-state the OS reports.
///
/// Kept tri-state on purpose (#662): collapsing to binary [`Mode`] before
/// the theme-follow edge detector destroyed real edges — GNOME's default
/// Light style reports the portal's `NoPreference`, so a Dark→Light switch
/// there never produced a transition once both ends folded to `Dark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsReading {
    Light,
    Dark,
    /// The OS reported no explicit preference — and equally what a FAILED
    /// read reads as, which mundy does not distinguish (#780), so this
    /// value is never evidence on its own. Only the portal reports it as a
    /// genuine preference at all; see [`INDEFINITE_IS_A_READING`].
    NoPreference,
}

/// Map a reported colour scheme onto a reading. The tri-state is preserved:
/// an absent preference is a reading, not a failed read.
#[must_use]
fn reading_from_scheme(scheme: mundy::ColorScheme) -> OsReading {
    match scheme {
        mundy::ColorScheme::Light => OsReading::Light,
        mundy::ColorScheme::Dark => OsReading::Dark,
        mundy::ColorScheme::NoPreference => OsReading::NoPreference,
    }
}

/// One item from the appearance stream, tagged with what it is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appearance {
    /// A fresh read of the current setting: what it IS, not that it
    /// changed. A source's opening item, where [`tag`] keeps one at all.
    Read(OsReading),
    /// A change the OS signalled.
    Changed(OsReading),
}

impl Appearance {
    /// The reading carried, whatever it is evidence of.
    #[must_use]
    pub const fn reading(self) -> OsReading {
        match self {
            Self::Read(reading) | Self::Changed(reading) => reading,
        }
    }
}

/// Whether an indefinite reading can mean anything but a failed read.
///
/// GNOME's default Light style reports the portal's `NoPreference`, which is
/// the transition [`adopted_mode`] exists to answer. The macOS and Windows
/// backends report a binary value on success — mundy derives the Windows one
/// from a `UIColorType` and folds every failure to `NoPreference` — so there
/// the value carries no preference, only the news that a read did not land.
#[cfg(target_os = "linux")]
const INDEFINITE_IS_A_READING: bool = true;
#[cfg(not(target_os = "linux"))]
const INDEFINITE_IS_A_READING: bool = false;

/// Budget for the startup read.
///
/// Honoured by the portal backend, which races the read against a timer. The
/// macOS backend resolves synchronously and ignores it; the Windows one also
/// ignores it and joins a COM thread with no bound of its own, so the budget
/// is not a cap there and a stalled activation stalls startup (#792). On
/// Linux iced runs a second 200ms read of its own before the first frame
/// besides (#789). The window is not shown until the read returns.
///
/// Also bounds each retry rung, which is a re-read of the same thing.
const STARTUP_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

/// The preference read, shared by both samplers so they cannot drift.
///
/// Every wrong value produces `ColorScheme::NoPreference` rather than an
/// error — mundy leaves an unasked-for preference at its default — which is
/// the value this design already treats as a failed read, so nothing would
/// notice. That it is the ONLY preference read is enforced by the manifest,
/// not here: mundy's other `Interest` constants are feature-gated, so with
/// `color-scheme` alone they do not exist and `Interest::All` is this value.
/// Widening the feature list widens what a portal read costs, since the
/// freedesktop backend issues one sequential `Read` per interested
/// preference inside `STARTUP_BUDGET`.
const INTEREST: mundy::Interest = mundy::Interest::ColorScheme;

/// The appearance to open in, read synchronously.
///
/// The window is created, themed and made visible from the mode the app
/// holds at that moment, so a reading that only arrives by message would
/// paint the first frames on the default and then flip.
///
/// MUST be called from the main thread: mundy's macOS backend asserts it.
// `#[mutants::skip]`: a live OS read; the mapping is the tested
// `reading_from_scheme`.
#[mutants::skip]
#[must_use]
pub fn startup_reading() -> Option<OsReading> {
    mundy::Preferences::once_blocking(INTEREST, STARTUP_BUDGET)
        .map(|preferences| reading_from_scheme(preferences.color_scheme))
}

/// The OS appearance, as a stream that opens with the current value and
/// then yields each change.
///
/// Taken from mundy directly rather than through `iced::system`, although
/// iced links mundy on Linux: iced overwrites its reading at window
/// creation with the window's own theme — which X11 never reports and
/// Wayland reports only for a client-side-decoration override — and off
/// Linux it never links mundy at all — and what iced would fall back to
/// does not serve: on macOS winit stops reporting theme changes once iced
/// sets the window's appearance.
pub fn appearance_stream() -> impl iced::futures::Stream<Item = Appearance> {
    // Eager, not deferred: see [`readings`] for the thread that requires it.
    composed(readings, readings)
}

/// Wire the resilience mechanisms together: replace a source that finishes,
/// and race the result against the post-boot re-reads.
///
/// Separated from [`appearance_stream`] only so the wiring can be driven by
/// stand-ins — the same split, for the same reason, as `base_app` under
/// `boot_app`. A real reading source serves in neither role: constructing it
/// panics off the main thread on macOS, and on Linux it pends rather than
/// ending wherever its change subscription IS established, so a test driving
/// it would hang.
///
/// `readings` is called HERE — see its own doc for the thread that requires
/// it — and this is the function the shipping path traverses, which is why
/// the eagerness can be pinned at all. `retry_readings` is NOT called here:
/// `startup_retries` calls it per rung, on whichever worker polls.
fn composed<P, R>(
    readings: fn() -> P,
    retry_readings: fn() -> R,
) -> impl iced::futures::Stream<Item = Appearance>
where
    P: iced::futures::Stream<Item = OsReading>,
    R: iced::futures::Stream<Item = OsReading>,
{
    use iced::futures::StreamExt as _;

    retried(
        appearances(readings()).chain(rebuilds(readings)),
        retry_readings,
    )
}

/// The raw readings behind a source, untagged, and the only place a mundy
/// backend is constructed for the stream.
///
/// The FIRST construction must happen on the thread iced builds
/// subscriptions on, because mundy's macOS backend asserts the main thread
/// there; [`appearance_stream`] does that eagerly. The rebuild and retry
/// paths construct more, and only on Linux, where building a backend off
/// the main thread is allowed.
fn readings() -> impl iced::futures::Stream<Item = OsReading> {
    use iced::futures::StreamExt as _;

    mundy::Preferences::stream(INTEREST)
        .map(|preferences| reading_from_scheme(preferences.color_scheme))
}

/// Tag a reading stream: the opening item is a re-read of the current
/// setting, anything emitted after it is a change the OS signalled.
///
/// What survives at each position is [`tag`]'s rule — an indefinite reading
/// is dropped at the opening position everywhere, and at every position off
/// the portal. Each [`rebuilds`] cycle builds a fresh source, so ITS re-read
/// is an opening read too and falls under the same rule.
///
/// The cost is a real flip INTO `NoPreference` going unseen: while the
/// stream is down; once more after an opening read that failed, because
/// mundy dedups each change against the last value it EMITTED, which
/// includes the failure value we dropped (#790); and when one lands at a
/// rebuild boundary (#798). A later definite reading restores the watermark
/// and clears mundy's dedup either way, and moves the displayed mode too.
/// Paid because the alternative fabricates flips from failed reads — and a
/// rebuild is when a read is MOST likely to have failed, so adopting one
/// there would repaint a dark desktop Light exactly when the bus is sick.
fn appearances<S>(readings: S) -> impl iced::futures::Stream<Item = Appearance>
where
    S: iced::futures::Stream<Item = OsReading>,
{
    use iced::futures::StreamExt as _;

    // `filter_map` AFTER `enumerate`, so a dropped opening read does not
    // renumber the first real change into one.
    readings
        .enumerate()
        .filter_map(|(index, reading)| std::future::ready(tag(index, reading)))
}

/// Classify one item of a source by its position, dropping what is not
/// evidence.
fn tag(index: usize, reading: OsReading) -> Option<Appearance> {
    if matches!(reading, OsReading::NoPreference) && (index == 0 || !INDEFINITE_IS_A_READING) {
        return None;
    }
    Some(if index == 0 {
        Appearance::Read(reading)
    } else {
        Appearance::Changed(reading)
    })
}

/// Re-reads the appearance for a bounded window after boot.
///
/// A boot read can fail while the session bus is up but the portal is not
/// yet activated — a login race. Nothing else recovers from that: the app
/// opens on the dark default, the source's own opening read carries the
/// same indefinite value and is dropped by [`tag`], and the source does not
/// END either (zbus establishes the change subscription even when nothing
/// owns the portal name), so [`rebuilds`] never fires. These spaced
/// re-reads are the only second chance.
///
/// The window is bounded, and what falls outside it is not recovered (#791),
/// in two ways: a portal that first answers AFTER the last rung leaves the
/// app on the startup default though nothing ever changed, and a setting
/// that changes while the portal is down emits no signal when the portal
/// returns. Either way nothing re-reads, so the app stays stale until the OS
/// signals a change of its own.
#[cfg(target_os = "linux")]
fn startup_retries<S>(readings: fn() -> S) -> impl iced::futures::Stream<Item = Appearance>
where
    S: iced::futures::Stream<Item = OsReading>,
{
    use iced::futures::StreamExt as _;

    iced::futures::stream::iter(0..STARTUP_RETRIES)
        .then(|_| tokio::time::sleep(STARTUP_RETRY_DELAY))
        // `flat_map` holds the next rung until this one ENDS, so each is
        // bounded twice: `take` confines it to the raw opening read, which
        // is what keeps a rung a re-read and never a `Changed` that could
        // discharge a standing choice; the budget ends a read that never
        // lands at all, as the boot read it retries is also bounded.
        .flat_map(move |()| {
            appearances(readings().take(1)).take_until(tokio::time::sleep(STARTUP_BUDGET))
        })
}

/// How many spaced re-reads follow boot before the appearance is left to
/// the change subscription.
#[cfg(target_os = "linux")]
const STARTUP_RETRIES: u32 = 6;

/// How long to wait between those re-reads. Their product is the window a
/// late-activating portal has to be picked up in.
#[cfg(target_os = "linux")]
const STARTUP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Race the primary stream against the startup re-reads, where those exist.
///
/// `select`, not `chain`: the primary does not finish on a session where the
/// portal is merely unowned — the common login race — so chained re-reads
/// would never be polled at all. It CAN finish where the change subscription
/// fails or the bus goes away, which is what [`rebuilds`] covers.
#[cfg(target_os = "linux")]
fn retried<P, S>(
    primary: P,
    retry_readings: fn() -> S,
) -> impl iced::futures::Stream<Item = Appearance>
where
    P: iced::futures::Stream<Item = Appearance>,
    S: iced::futures::Stream<Item = OsReading>,
{
    use iced::futures::StreamExt as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    // The rungs cover a boot read that produced nothing, so a primary that
    // has EMITTED anything has discharged them — and running on past that
    // risks the opposite fault. Each rung samples the setting over a
    // connection it opens itself, so one in flight when a change is
    // signalled arrives after it carrying the older value, and the
    // watermark that stale read advances would swallow the next real edge.
    //
    // Emitted, not read: where every reading is indefinite — GNOME on its
    // default style — `tag` drops the primary's opening read AND every
    // rung's, so neither side emits, the gate never arms, and the ladder
    // runs its full length beside a healthy primary. That costs a session
    // connection per rung and no more: a rung can only move the watermark by
    // emitting, so a ladder that emits nothing cannot race anything.
    let spoke = std::sync::Arc::new(AtomicBool::new(false));
    let spoken = std::sync::Arc::clone(&spoke);

    iced::futures::stream::select(
        primary.inspect(move |_| spoke.store(true, Ordering::Relaxed)),
        startup_retries(retry_readings)
            .take_while(move |_| std::future::ready(!spoken.load(Ordering::Relaxed))),
    )
}

#[cfg(not(target_os = "linux"))]
fn retried<P, S>(
    primary: P,
    _retry_readings: fn() -> S,
) -> impl iced::futures::Stream<Item = Appearance>
where
    P: iced::futures::Stream<Item = Appearance>,
    S: iced::futures::Stream<Item = OsReading>,
{
    primary
}

/// Replacements for a source that finished, where one can.
///
/// The freedesktop source ends rather than erroring when there is no
/// session bus, when its change subscription cannot be established, or when
/// the bus goes away mid-session — and iced never rebuilds a subscription
/// whose stream finished, so without this the first such failure would end
/// theme following for the rest of the session. The macOS source cannot end
/// — it holds the sender in the KVO observer it owns — and the Windows one
/// does not in practice, its sender living on a spawned COM thread with no
/// reachable panic path. So there is nothing to replace off Linux, and macOS
/// may not be rebuilt off the main thread anyway.
///
/// Two Windows failures instead go quiet WITHOUT ending, which no rebuild
/// could detect either, and which #787 covers together: a source whose hook
/// registration fails, so nothing ever sends it a change, and one whose
/// `UISettings` never activated, whose every read is the same failure value
/// and is suppressed as a repeat. Everywhere else, including the BSDs, mundy
/// falls back to a source that yields one constant reading and ends, so those
/// targets have no appearance detection at all (#788) and rebuilding would
/// re-emit the same value forever.
#[cfg(target_os = "linux")]
fn rebuilds<P>(readings: fn() -> P) -> impl iced::futures::Stream<Item = Appearance>
where
    P: iced::futures::Stream<Item = OsReading>,
{
    use iced::futures::StreamExt as _;

    iced::futures::stream::repeat(())
        .then(|()| tokio::time::sleep(RESTART_DELAY))
        .flat_map(move |()| appearances(readings()))
}

#[cfg(not(target_os = "linux"))]
fn rebuilds<P>(_readings: fn() -> P) -> impl iced::futures::Stream<Item = Appearance>
where
    P: iced::futures::Stream<Item = OsReading>,
{
    iced::futures::stream::empty()
}

/// How long to wait before rebuilding a finished appearance stream.
///
/// Spaces the rebuild loop: long enough that a session with no bus at all
/// costs one attempt per interval rather than a spin, short enough that a bus
/// arriving after startup is picked up promptly. It does NOT govern a late
/// PORTAL: the source does not end in that case, so [`rebuilds`] never runs
/// and `STARTUP_RETRIES` x `STARTUP_RETRY_DELAY` is the only knob.
#[cfg(target_os = "linux")]
const RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// The appearance the app STARTS in for a given startup reading.
///
/// The pre-#662 contract verbatim: OS-Light → `Light`; Dark, NoPreference,
/// or a failed read → `Dark`. With no transition evidence yet, unknown
/// leans on the app's dark default.
#[must_use]
pub fn startup_mode(reading: Option<OsReading>) -> Mode {
    match reading {
        Some(OsReading::Light) => Mode::Light,
        Some(OsReading::Dark | OsReading::NoPreference) | None => Mode::Dark,
    }
}

/// The appearance a LIVE transition into `reading` adopts.
///
/// Differs from [`startup_mode`] on `NoPreference`, deliberately: on GNOME
/// — the common emitter — `NoPreference` is what the default Light style
/// reports, so a transition INTO it is the user switching to Light. This is
/// a trade-off, not a universal: other desktops can emit `NoPreference` for
/// schemes that are actually dark (reported for KDE Plasma 5's third-party
/// color schemes), where Light is a mis-adoption — accepted because the
/// alternative left every GNOME light-switch unanswered. At startup the
/// same value carries no transition evidence and keeps the conservative
/// dark default.
#[must_use]
fn adopted_mode(reading: OsReading) -> Mode {
    match reading {
        OsReading::Light | OsReading::NoPreference => Mode::Light,
        OsReading::Dark => Mode::Dark,
    }
}

/// The Iced base theme for a given appearance mode.
pub fn iced_theme(mode: Mode) -> iced::Theme {
    match mode {
        Mode::Light => iced::Theme::Light,
        Mode::Dark => iced::Theme::Dark,
    }
}

/// What an appearance item does to the displayed mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A real OS change: take it, and treat any standing manual choice as
    /// discharged — the user overrode the OLD reading, not this one. That
    /// discharge is what separates this from [`Decision::Resync`], which is
    /// only ever returned when no choice stands, so the two write the same
    /// state today and differ in what they mean.
    Adopt(Mode),
    /// No transition evidence: re-sync to the [`startup_mode`] reading of
    /// what the OS reports. The two mappings differ on `NoPreference`, and
    /// [`tag`] is what keeps that off this path — index 0 is the only
    /// position that can produce a `Read`, and an indefinite reading is
    /// dropped there. `startup_mode` is chosen so that one arriving anyway
    /// lands on the conservative default rather than mis-adopting Light.
    Resync(Mode),
    /// Nothing to do.
    Hold,
}

/// Weigh one appearance item against the watermark and any standing choice.
///
/// The TAG decides how far an item is believed: only one the OS pushed is
/// [`Appearance::Changed`], and that is adopted whether or not a prior
/// reading was seen. A [`Appearance::Read`] is adopted only when it and the
/// watermark are both definite and differ — see the arm for why that is a
/// change and not a restatement. The watermark serves to spot a change that
/// merely RESTATES the last reading, and the comparison runs on the tri-state
/// [`OsReading`], never the collapsed [`Mode`], so GNOME's Dark↔NoPreference
/// flips stay real edges. `user_chose` is an explicit flag, NOT a mode
/// comparison — an even toggle count lands back on the default yet is still
/// a choice.
#[must_use]
pub fn appearance_decision(last: Option<OsReading>, now: Appearance, user_chose: bool) -> Decision {
    // `last` is the last reading ANY sampler observed — the boot read, the
    // primary, a rung, a rebuild — while the restatement arm below reads it
    // as the primary's edge reference. Those disagree when a sampler writes
    // a value the primary is about to signal (#794).
    match (now, last) {
        (Appearance::Changed(reading), Some(prev)) if prev == reading => Decision::Hold,
        (Appearance::Changed(reading), _) => Decision::Adopt(adopted_mode(reading)),
        // A DEFINITE re-read against a DEFINITE watermark they differ from
        // is a real change, not a restatement: mundy cannot report Light or
        // Dark as a failed read, so two definite readings that disagree
        // disagree for a reason. Without this, a change observed only by
        // re-read — a rebuild's opening item, or a rung — is absorbed into
        // the watermark while a choice stands, leaving the mode behind for
        // good. `is_definite(reading)` is belt-and-braces on a `pub` fn:
        // [`tag`] cannot emit an indefinite `Read` in the first place.
        (Appearance::Read(reading), Some(prev))
            if is_definite(reading) && is_definite(prev) && prev != reading =>
        {
            Decision::Adopt(adopted_mode(reading))
        }
        (Appearance::Read(reading), _) if !user_chose => {
            Decision::Resync(startup_mode(Some(reading)))
        }
        (Appearance::Read(_), _) => Decision::Hold,
    }
}

/// Whether a reading says anything beyond "the read did not land".
const fn is_definite(reading: OsReading) -> bool {
    !matches!(reading, OsReading::NoPreference)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One-item reading constructors. Sources are Dark and rungs are Light,
    /// so a leaked rung is visible by value.
    fn one_dark_reading() -> impl iced::futures::Stream<Item = OsReading> {
        iced::futures::stream::once(std::future::ready(OsReading::Dark))
    }

    fn one_light_reading() -> impl iced::futures::Stream<Item = OsReading> {
        iced::futures::stream::once(std::future::ready(OsReading::Light))
    }

    /// A rung is a re-read and nothing else. `take` confines it to the raw
    /// opening read, so the tagging can only ever label it `Read`; bounding
    /// the TAGGED stream instead would let a rung's second reading through
    /// as a `Changed`, which adopts over a standing manual choice.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn a_rung_can_only_ever_offer_a_re_read() {
        use iced::futures::StreamExt as _;

        fn changes_after_an_indefinite_read() -> impl iced::futures::Stream<Item = OsReading> {
            iced::futures::stream::iter([OsReading::NoPreference, OsReading::Light])
        }
        let offered: Vec<_> = startup_retries(changes_after_an_indefinite_read)
            .collect()
            .await;
        assert!(
            offered.is_empty(),
            "a rung must stop at its opening read, dropped or not"
        );
    }

    /// The startup re-reads must be bounded AND spaced: they exist to cover
    /// a login race, not to re-read a settled desktop forever, and not to
    /// spend the whole window before a portal could possibly arrive.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn startup_retries_are_bounded_and_spaced() {
        use iced::futures::StreamExt as _;

        let start = tokio::time::Instant::now();
        let count = startup_retries(one_light_reading).count().await;
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(30),
            "deleting the spacing runs the whole ladder before a portal \
             could possibly arrive"
        );
        // Literal, not STARTUP_RETRIES: an expectation computed from the
        // value under test passes at zero, which would delete the
        // login-race recovery entirely and leave the suite green.
        assert_eq!(count, 6, "one reading per scheduled re-read, then done");
    }

    /// Only the OPENING item of a source is a re-read; what follows it is
    /// signalled, and the two reach different arms of the decision.
    #[tokio::test]
    async fn a_source_opens_with_a_re_read_and_then_reports_changes() {
        use iced::futures::StreamExt as _;

        // Definite throughout, so the platform rule for an indefinite
        // reading does not enter into it.
        let tagged: Vec<_> = appearances(iced::futures::stream::iter([
            OsReading::Dark,
            OsReading::Light,
            OsReading::Dark,
        ]))
        .collect()
        .await;
        assert_eq!(
            tagged,
            vec![
                Appearance::Read(OsReading::Dark),
                Appearance::Changed(OsReading::Light),
                Appearance::Changed(OsReading::Dark),
            ]
        );
    }

    /// A failed read is reported as NoPreference, so an opening read of it
    /// is indistinguishable from a real one and must be dropped — without
    /// renumbering what follows, which a `filter` placed BEFORE the
    /// `enumerate` would do, promoting the first real change into a re-read
    /// that never reaches the edge arm.
    #[tokio::test]
    async fn an_indefinite_opening_read_is_dropped_without_promoting_the_next() {
        use iced::futures::StreamExt as _;

        let tagged: Vec<_> = appearances(iced::futures::stream::iter([
            OsReading::NoPreference,
            OsReading::Dark,
        ]))
        .collect()
        .await;
        assert_eq!(
            tagged,
            vec![Appearance::Changed(OsReading::Dark)],
            "the item after a dropped opening read is still a change"
        );
    }

    /// The ladder must survive a re-read that yields nothing.
    ///
    /// A read that never LANDS must still release its rung, or the rest of
    /// the ladder never runs: `flat_map` holds the next rung until this one
    /// ends, and `take` cannot end a stream that yields no item at all. Only
    /// the budget does.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn an_unlanded_read_does_not_stall_the_ladder() {
        use iced::futures::StreamExt as _;

        fn never_reads() -> impl iced::futures::Stream<Item = OsReading> {
            iced::futures::stream::pending()
        }
        // Virtual time, so the budget is deterministic rather than a race:
        // a stalled ladder fails here instead of hanging the suite.
        let start = tokio::time::Instant::now();
        let unread = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            startup_retries(never_reads).collect::<Vec<_>>(),
        )
        .await
        .expect("a rung whose read never lands must still end, budgeted");
        assert!(unread.is_empty(), "an unlanded read offers nothing");
        // Which duration the site uses, not just the constant's own value:
        // every rung costs its spacing plus its budget, so swapping in the
        // spacing again doubles this and a materially shorter bound undershoots.
        let ladder = start.elapsed();
        assert!(
            (std::time::Duration::from_secs(31)..=std::time::Duration::from_secs(40))
                .contains(&ladder),
            "each rung must cost its spacing plus the startup budget"
        );
    }

    /// The wiring, not the mechanisms: a source that finishes must be
    /// replaced, and the rungs must stay out of it once the source speaks.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn the_composition_replaces_a_finished_source_without_rungs() {
        use iced::futures::StreamExt as _;

        // Bounded for the same reason as its sibling: a starving mutation
        // would otherwise spin the paused clock rather than fail.
        let wired: Vec<_> = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            composed(one_dark_reading, one_light_reading)
                .take(3)
                .collect::<Vec<_>>(),
        )
        .await
        .expect("the composition must keep producing, not starve the stream");
        assert_eq!(
            wired,
            vec![Appearance::Read(OsReading::Dark); 3],
            "dropping the rebuild starves this; letting a rung through \
             colours it Light"
        );
    }

    /// A rung must reach the composed output while the source stays silent
    /// after an opening read the tagging drops — every other ladder test
    /// drives `retried` directly, so only this one sees it wired in.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn the_composition_runs_the_ladder_while_the_source_is_silent() {
        use iced::futures::StreamExt as _;

        // Opens with a reading the tagging DROPS and then pends — the login
        // race itself, and the shape mundy's source has on a live bus whose
        // portal name is unowned. Silent after that opening read, so the
        // assertion is by VALUE: a `chain` in place of the race, or a ladder
        // unwired from the composition, yields nothing instead of a rung's
        // Light. A gate fed from the RAW readings would count that dropped
        // read as the primary speaking and cancel the ladder outright.
        fn opens_indefinite_then_pends() -> impl iced::futures::Stream<Item = OsReading> {
            iced::futures::stream::once(std::future::ready(OsReading::NoPreference))
                .chain(iced::futures::stream::pending())
        }
        let mut wired = std::pin::pin!(composed(opens_indefinite_then_pends, one_light_reading));
        let first = tokio::time::timeout(std::time::Duration::from_secs(600), wired.next())
            .await
            .expect("a rung must reach the composed stream, not be gated off by a dropped read");
        assert_eq!(
            first,
            Some(Appearance::Read(OsReading::Light)),
            "a rung must reach the composed stream while the source is silent"
        );
    }

    /// Off the portal the composition is two passthroughs: `retried` yields
    /// the primary and `rebuilds` contributes nothing. Collecting the WHOLE
    /// stream pins both — anything appended would repeat, and a `retried`
    /// that dropped the primary would empty it.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test(start_paused = true)]
    async fn the_composition_is_the_bare_source_off_the_portal() {
        use iced::futures::StreamExt as _;

        // `take` bounds an appending mutation, which stays READY forever and
        // so never lets the paused clock advance; the timeout bounds a
        // pending one, which does. Either fails here rather than hanging the
        // suite out to the job timeout.
        let wired = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            composed(one_dark_reading, one_light_reading)
                .take(2)
                .collect::<Vec<_>>(),
        )
        .await
        .expect("the source must not be left pending off the portal");
        assert_eq!(
            wired,
            vec![Appearance::Read(OsReading::Dark)],
            "the source's Dark passes through; anything appended would \
             repeat it, and a dropped primary would empty it"
        );
    }

    /// The readings must be built by whoever CALLS [`composed`], because
    /// that is the thread mundy's macOS backend asserts. Deferring it into a
    /// combinator moves construction to whichever worker polls first, which
    /// no assertion on the item sequence can see. [`appearance_stream`] calls
    /// `composed` directly, so this covers the shipping path.
    #[test]
    fn the_composition_builds_its_readings_before_the_first_poll() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static BUILDS: AtomicUsize = AtomicUsize::new(0);
        fn counts_construction() -> impl iced::futures::Stream<Item = OsReading> {
            let _ = BUILDS.fetch_add(1, Ordering::Relaxed);
            one_dark_reading()
        }
        // Never polled: construction is the whole assertion.
        let _stream = composed(counts_construction, one_light_reading);
        assert_eq!(
            BUILDS.load(Ordering::Relaxed),
            1,
            "the readings must be constructed eagerly, by the caller"
        );
    }

    /// An indefinite OPENING read is dropped on every platform: it is
    /// indistinguishable from a failed read, and each [`rebuilds`] cycle
    /// re-reads at index 0, so this is what costs a genuine no-preference
    /// flip landing at a rebuild boundary (#798).
    #[test]
    fn an_indefinite_opening_read_is_never_a_reading() {
        assert_eq!(tag(0, OsReading::NoPreference), None);
    }

    /// Only the portal reports an indefinite reading as a preference, so
    /// only there can one past the opening read be a transition.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_indefinite_reading_after_the_opening_one_is_a_transition() {
        assert_eq!(
            tag(1, OsReading::NoPreference),
            Some(Appearance::Changed(OsReading::NoPreference)),
            "GNOME's switch to its default Light style is a real edge"
        );
    }

    /// Off the portal a reading is binary on success, so an indefinite one
    /// reports only that the read failed — at ANY position. Adopting it
    /// would repaint the window Light on a dark desktop, and mundy re-reads
    /// on every unrelated Windows setting broadcast.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn an_indefinite_reading_is_never_a_transition() {
        assert_eq!(tag(1, OsReading::NoPreference), None);
        // Definite readings are unaffected.
        assert_eq!(
            tag(1, OsReading::Light),
            Some(Appearance::Changed(OsReading::Light))
        );
    }

    /// A source that ends must be replaced, not left finished.
    ///
    /// Driven with a stand-in rather than the real source: mundy's stream
    /// ends when no session bus resolves or its change subscription cannot
    /// be established, and otherwise blocks indefinitely, so a test on the
    /// real source would hang on most desktops.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn a_finished_source_is_replaced() {
        use iced::futures::StreamExt as _;

        let start = tokio::time::Instant::now();
        // Bounded on virtual time: a mutation that starves the stream leaves
        // `take` unfilled while the rebuild loop keeps sleeping, so without
        // this the clock advances forever and the test hangs.
        let replacements: Vec<_> = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            rebuilds(one_dark_reading).take(2).collect::<Vec<_>>(),
        )
        .await
        .expect("a finished source must be replaced, not starve the stream");
        assert_eq!(
            replacements,
            vec![
                Appearance::Read(OsReading::Dark),
                Appearance::Read(OsReading::Dark)
            ],
            "a source that ends must be rebuilt, not left finished"
        );
        // A literal, not a product of the constant under test: one derived
        // from RESTART_DELAY passes when the delay is zero.
        assert!(
            start.elapsed() >= std::time::Duration::from_secs(2),
            "the rebuilds must be spaced by the gap, not spun"
        );
    }

    #[test]
    fn the_startup_budget_bounds_the_first_frame() {
        // On the portal, which is the only backend that honours it: too low
        // and the blocking read never lands, so a Light desktop always opens
        // Dark; too high and the first frame waits out a hung portal.
        assert!(
            (100..=1000).contains(&STARTUP_BUDGET.as_millis()),
            "the startup read must be able to land without stalling the \
             first frame"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_restart_delay_is_bounded_both_ways() {
        // Too low and a session with no bus spins on the rebuild; too high
        // and a bus arriving after startup is not picked up promptly. NOT a
        // late portal — that never ends the source, so `rebuilds` never runs.
        assert!(
            (std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(15))
                .contains(&RESTART_DELAY),
            "the rebuild interval must not spin, nor stall a late bus"
        );
    }

    #[test]
    fn the_interest_asks_for_the_colour_scheme() {
        assert!(
            INTEREST.is(mundy::Interest::ColorScheme),
            "both samplers read the colour scheme"
        );
    }

    #[test]
    fn colour_schemes_map_to_the_tristate() {
        assert_eq!(
            reading_from_scheme(mundy::ColorScheme::Light),
            OsReading::Light
        );
        assert_eq!(
            reading_from_scheme(mundy::ColorScheme::Dark),
            OsReading::Dark
        );
        assert_eq!(
            reading_from_scheme(mundy::ColorScheme::NoPreference),
            OsReading::NoPreference,
            "an absent preference is a reading, not a failure"
        );
    }

    #[test]
    fn dark_mode_maps_to_iced_dark() {
        assert!(matches!(iced_theme(Mode::Dark), iced::Theme::Dark));
        assert!(matches!(iced_theme(Mode::Light), iced::Theme::Light));
    }

    #[test]
    fn tokens_are_a_consistent_scale() {
        use crate::theme::tokens::*;
        const { assert!(SPACE_XS < SPACE_SM && SPACE_SM < SPACE_MD && SPACE_MD < SPACE_LG) }
    }

    #[test]
    fn startup_mode_is_light_only_for_a_definite_light_reading() {
        // The pre-#662 contract verbatim: everything but OS-Light starts Dark.
        assert_eq!(startup_mode(Some(OsReading::Light)), Mode::Light);
        assert_eq!(startup_mode(Some(OsReading::Dark)), Mode::Dark);
        assert_eq!(startup_mode(Some(OsReading::NoPreference)), Mode::Dark);
        assert_eq!(startup_mode(None), Mode::Dark);
    }

    #[test]
    fn adopted_mode_treats_no_preference_as_light() {
        // The GNOME mapping: a LIVE transition into NoPreference is the user
        // switching to the default Light style.
        assert_eq!(adopted_mode(OsReading::Light), Mode::Light);
        assert_eq!(adopted_mode(OsReading::NoPreference), Mode::Light);
        assert_eq!(adopted_mode(OsReading::Dark), Mode::Dark);
    }

    #[test]
    fn os_change_is_adopted_in_both_directions() {
        // The edge branch ignores `user_chose` — an OS change wins over any
        // standing mode, override included.
        assert_eq!(
            appearance_decision(
                Some(OsReading::Dark),
                Appearance::Changed(OsReading::Light),
                false
            ),
            Decision::Adopt(Mode::Light)
        );
        assert_eq!(
            appearance_decision(
                Some(OsReading::Light),
                Appearance::Changed(OsReading::Dark),
                true
            ),
            Decision::Adopt(Mode::Dark)
        );
        // The GNOME edge that a binary-Mode comparison destroyed (#662):
        // PreferDark → NoPreference is a real transition and lands Light.
        assert_eq!(
            appearance_decision(
                Some(OsReading::Dark),
                Appearance::Changed(OsReading::NoPreference),
                false
            ),
            Decision::Adopt(Mode::Light)
        );
    }

    #[test]
    fn a_signalled_change_is_adopted_without_a_watermark_too() {
        // Only an item the OS PUSHED is tagged Changed, so it is a real
        // transition whether or not we saw the prior state — a watermark is
        // needed to spot a change that restates it, not to establish that
        // one happened. Without this a startup read that timed out on a
        // desktop reporting no preference (so every opening read is dropped)
        // leaves the watermark None, and one manual toggle would then make
        // every later OS change unfollowable.
        assert_eq!(
            appearance_decision(None, Appearance::Changed(OsReading::Light), true),
            Decision::Adopt(Mode::Light)
        );
        assert_eq!(
            appearance_decision(None, Appearance::Changed(OsReading::NoPreference), true),
            Decision::Adopt(Mode::Light),
            "the GNOME default style is a switch to Light, not to the dark default"
        );
    }

    #[test]
    fn a_change_matching_the_watermark_adopts_nothing() {
        for reading in [OsReading::Light, OsReading::Dark, OsReading::NoPreference] {
            assert_eq!(
                appearance_decision(Some(reading), Appearance::Changed(reading), false),
                Decision::Hold
            );
            assert_eq!(
                appearance_decision(Some(reading), Appearance::Changed(reading), true),
                Decision::Hold
            );
        }
    }

    #[test]
    fn a_definite_re_read_differing_from_a_definite_watermark_is_a_change() {
        // mundy cannot report Light or Dark as a failed read, so a definite
        // reading against a definite watermark they differ from IS a change,
        // however it was observed. Held instead, it would be absorbed into
        // the watermark with the mode left behind for good.
        assert_eq!(
            appearance_decision(
                Some(OsReading::Dark),
                Appearance::Read(OsReading::Light),
                true
            ),
            Decision::Adopt(Mode::Light)
        );
        // Equal definite readings are a restatement, not a change — and
        // level-triggered while no choice stands, since the displayed mode
        // can have drifted from the watermark.
        assert_eq!(
            appearance_decision(
                Some(OsReading::Dark),
                Appearance::Read(OsReading::Dark),
                true
            ),
            Decision::Hold
        );
        assert_eq!(
            appearance_decision(
                Some(OsReading::Light),
                Appearance::Read(OsReading::Light),
                false
            ),
            Decision::Resync(Mode::Light)
        );
        // An INDEFINITE re-read is a failed read, whatever the watermark
        // says, so it keeps the conservative treatment. These are the only
        // rows that feed an indefinite reading against a DEFINITE watermark,
        // which is what reaching the edge arm needs, so they are what pins
        // `is_definite(reading)`: the first fixes the mapping it falls back
        // to, the second that a standing choice still blocks it.
        assert_eq!(
            appearance_decision(
                Some(OsReading::Light),
                Appearance::Read(OsReading::NoPreference),
                false
            ),
            Decision::Resync(Mode::Dark)
        );
        assert_eq!(
            appearance_decision(
                Some(OsReading::Light),
                Appearance::Read(OsReading::NoPreference),
                true
            ),
            Decision::Hold
        );
    }

    #[test]
    fn a_re_read_against_an_indefinite_watermark_carries_no_edge() {
        // Against an INDEFINITE watermark a re-read carries no edge to
        // adopt, so it must not reach the adopting arm. A late-activating
        // portal answering a re-read with the truth would otherwise revert a
        // theme the user picked seconds earlier — the watermark it would be
        // adopting against is a failed boot read, not a reading.
        assert_eq!(
            appearance_decision(
                Some(OsReading::NoPreference),
                Appearance::Read(OsReading::Dark),
                true
            ),
            Decision::Hold
        );
        // The same re-read while no choice stands re-syncs to the OS, which
        // is the whole point of re-reading after a failed boot read.
        assert_eq!(
            appearance_decision(
                Some(OsReading::NoPreference),
                Appearance::Read(OsReading::Dark),
                false
            ),
            Decision::Resync(Mode::Dark)
        );
    }

    #[test]
    fn read_recovery_adopts_the_startup_mapping_unless_the_user_chose() {
        // A None watermark means the reads so far FAILED. Recovery is not an
        // OS edge — but while the user has not chosen, adopt what a
        // SUCCESSFUL startup read would have produced, or a Light desktop
        // whose startup read timed out once would stay Dark forever.
        // Deterministic: NoPreference recovers to Dark, exactly like the
        // startup-success path — never decided by timing.
        for (reading, mode) in [
            (OsReading::Light, Mode::Light),
            (OsReading::Dark, Mode::Dark),
            (OsReading::NoPreference, Mode::Dark),
        ] {
            assert_eq!(
                appearance_decision(None, Appearance::Read(reading), false),
                Decision::Resync(mode)
            );
            // ANY manual toggle before recovery — even a count that lands
            // back on the default mode — means the user already chose:
            // recovery must not revert it, whatever the reading says.
            assert_eq!(
                appearance_decision(None, Appearance::Read(reading), true),
                Decision::Hold
            );
        }
    }
}
