//! Tab-collection model for the content host. No direct `iced` imports, though
//! a `Tab` transitively holds an iced render handle via the cached
//! [`render`](crate::state::texture_view::TextureState::render) field on
//! [`TextureState`](crate::state::texture_view::TextureState).

use std::collections::HashSet;

use std::sync::Arc;

use crate::state::audio_view;
use crate::state::hex_view;
use crate::state::property_view::NodeId;
use crate::state::texture_view;
use paksmith_core::asset::Package;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Properties,
    Hex,
    Info,
    Texture,
    Audio,
}

#[derive(Debug, Clone)]
pub enum TabContent {
    Loading,
    Ready {
        /// Capped raw prefix, ≤ [`crate::task::asset::HEX_BYTES_CAP`] bytes.
        bytes: Vec<u8>,
        /// Whether the entry is larger than the cap (entry was truncated at read time).
        truncated: bool,
        parsed: Result<Arc<Package>, String>,
    },
}

#[derive(Debug, Clone)]
pub struct Tab {
    pub path: String,
    pub view: ViewMode,
    pub content: TabContent,
    pub hex: hex_view::HexState,
    pub texture: texture_view::TextureState,
    pub audio: audio_view::AudioState,
    pub expanded: HashSet<NodeId>,
}

/// Returns `true` iff `tab` holds a decodable texture export.
///
/// This reads only the per-tab decodable-mip cache (`tab.texture.mips`), so it
/// is O(1) and safe to call on every per-frame view render (see
/// `panels/content.rs`) — it never re-classifies the `Package`. The cache is the
/// single source of truth, kept correct at two mutation sites so `mips` is
/// non-empty iff the tab's current content is a decodable texture:
///
/// - `Tabs::set_content` resets `tab.texture` on every content swap, so the
///   cache can never read stale-true after the content changes.
/// - The `AssetLoaded` handler repopulates `mips` from `classify_texture`
///   immediately after `set_content`, before any reader (`pick_view_after_load`
///   or a view render) observes it.
///
/// (Archive swaps clear all tabs and `open_or_activate` re-activates an open
/// path without reloading — neither populates `mips`, so neither can leave a
/// stale cache behind.)
#[must_use]
pub fn texture_available(tab: &Tab) -> bool {
    !tab.texture.mips.is_empty()
}

/// Returns `true` iff `tab` holds a classified sound-wave export.
///
/// Reads only the per-tab [`audio_view::AudioState::info`] cache — O(1), safe
/// to call on every per-frame render. The `AssetLoaded` handler populates it
/// via `classify_audio` immediately after `set_content`. Note: unlike the
/// texture cache, `set_content` does not yet reset `tab.audio`; the handler
/// that calls `set_content` is responsible for clearing it before a content
/// swap (Phase 7d follow-up).
#[must_use]
pub fn audio_available(tab: &Tab) -> bool {
    tab.audio.info.is_some()
}

#[derive(Debug, Clone, Default)]
pub struct Tabs {
    pub open: Vec<Tab>,
    pub active: Option<usize>,
}

impl Tabs {
    /// Open `path` in a new Loading tab and activate it, or just activate the
    /// existing tab if `path` is already open. Returns the active index.
    pub fn open_or_activate(&mut self, path: &str) -> usize {
        if let Some(i) = self.open.iter().position(|t| t.path == path) {
            self.active = Some(i);
            return i;
        }
        self.open.push(Tab {
            path: path.to_string(),
            view: ViewMode::Properties,
            content: TabContent::Loading,
            hex: hex_view::HexState::default(),
            texture: texture_view::TextureState::default(),
            audio: audio_view::AudioState::default(),
            expanded: HashSet::new(),
        });
        let i = self.open.len() - 1;
        self.active = Some(i);
        i
    }

    /// Close the tab at `idx` (no-op if out of bounds), re-picking `active`.
    pub fn close(&mut self, idx: usize) {
        if idx >= self.open.len() {
            return;
        }
        let _ = self.open.remove(idx);
        if self.open.is_empty() {
            self.active = None;
            return;
        }
        self.active = Some(match self.active {
            Some(a) if a > idx => a - 1,       // active shifted left
            Some(a) if a < idx => a,           // active unaffected
            _ => idx.min(self.open.len() - 1), // closed the active tab → clamp
        });
    }

    /// Activate the tab at `idx` (no-op if out of bounds).
    pub fn activate(&mut self, idx: usize) {
        if idx < self.open.len() {
            self.active = Some(idx);
        }
    }

    /// Set the view mode of the tab at `idx` (no-op if out of bounds).
    pub fn set_view(&mut self, idx: usize, view: ViewMode) {
        if let Some(t) = self.open.get_mut(idx) {
            t.view = view;
        }
    }

    /// Replace the content of the tab identified by `path` (no-op if closed).
    pub fn set_content(&mut self, path: &str, content: TabContent) {
        if let Some(t) = self.open.iter_mut().find(|t| t.path == path) {
            t.content = content;
            // Invalidate the per-content texture cache at the mutation site so
            // `texture_available` (which reads `t.texture.mips` as a "decodable
            // texture loaded" signal) can never observe state left over from the
            // tab's previous content. The `AssetLoaded` handler
            // repopulates it immediately after for a decodable texture, so this
            // costs nothing in the normal flow while keeping the no-stale-true
            // invariant self-enforcing for any future in-place reload (Phase 7c).
            t.texture = texture_view::TextureState::default();
        }
    }

    /// After a load completes, promote or demote the default view.
    ///
    /// - If the asset has a decodable texture, promote to `ViewMode::Texture`.
    /// - If the asset failed to parse, demote to `ViewMode::Info`.
    ///
    /// Only acts when the tab is still on the default `Properties` view
    /// (respects a user-initiated view switch).
    ///
    /// # Preconditions
    ///
    /// The Texture promotion reads [`texture_available`], i.e. the tab's
    /// decodable-mip cache (`tab.texture.mips`). Callers must populate that
    /// cache from `classify_texture` (and reset it via [`set_content`] for the
    /// new content) **before** calling this — the `AssetLoaded` handler does
    /// exactly that. A caller that runs this before populating the cache
    /// silently leaves a decodable texture on `Properties` instead of promoting
    /// it (relevant to any future in-place reload — Phase 7c).
    ///
    /// [`set_content`]: Self::set_content
    pub fn pick_view_after_load(&mut self, path: &str) {
        let Some(tab) = self.open.iter_mut().find(|t| t.path == path) else {
            return;
        };
        if tab.view != ViewMode::Properties {
            return; // user already switched; respect their choice
        }
        if texture_available(tab) {
            tab.view = ViewMode::Texture;
        } else if audio_available(tab) {
            tab.view = ViewMode::Audio;
        } else if matches!(&tab.content, TabContent::Ready { parsed: Err(_), .. }) {
            tab.view = ViewMode::Info;
        }
    }

    /// Whether a tab for `path` is already open.
    #[must_use]
    pub fn is_open(&self, path: &str) -> bool {
        self.open.iter().any(|t| t.path == path)
    }

    /// Drop all tabs (called when the archive changes).
    pub fn clear(&mut self) {
        self.open.clear();
        self.active = None;
    }

    /// The currently active tab, if any.
    pub fn active_tab(&self) -> Option<&Tab> {
        self.active.and_then(|i| self.open.get(i))
    }

    /// Mutable reference to the currently active tab, if any.
    pub fn active_tab_mut(&mut self) -> Option<&mut Tab> {
        self.active.and_then(|i| self.open.get_mut(i))
    }

    /// The parsed `Package` for the open tab at `path`, if that tab exists and
    /// parsed successfully. Lets Export As… enumerate formats synchronously
    /// when the asset is already open (the common case), avoiding a re-parse.
    #[must_use]
    pub fn parsed_package(&self, path: &str) -> Option<&Arc<Package>> {
        self.open
            .iter()
            .find(|t| t.path == path)
            .and_then(|t| match &t.content {
                TabContent::Ready {
                    parsed: Ok(arc), ..
                } => Some(arc),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loading_tabs(paths: &[&str]) -> Tabs {
        let mut t = Tabs::default();
        for p in paths {
            let _ = t.open_or_activate(p);
        }
        t
    }

    #[test]
    fn open_new_path_appends_and_activates() {
        let mut t = Tabs::default();
        let i = t.open_or_activate("A.uasset");
        assert_eq!(i, 0);
        assert_eq!(t.open.len(), 1);
        assert_eq!(t.active, Some(0));
        assert!(matches!(t.open[0].content, TabContent::Loading));
        assert_eq!(t.open[0].view, ViewMode::Properties); // default view
    }

    #[test]
    fn open_existing_path_activates_without_duplicating() {
        let mut t = loading_tabs(&["A", "B"]);
        let i = t.open_or_activate("A"); // already open at 0
        assert_eq!(i, 0);
        assert_eq!(t.open.len(), 2, "must not duplicate");
        assert_eq!(t.active, Some(0));
    }

    #[test]
    fn close_active_repicks_previous() {
        let mut t = loading_tabs(&["A", "B", "C"]); // active = 2
        t.close(2);
        assert_eq!(t.open.len(), 2);
        assert_eq!(
            t.active,
            Some(1),
            "closing active tail re-picks the new last"
        );
    }

    #[test]
    fn close_before_active_shifts_active_index_down() {
        let mut t = loading_tabs(&["A", "B", "C"]);
        t.activate(2);
        t.close(0); // removed before active → active shifts 2→1
        assert_eq!(t.active, Some(1));
        assert_eq!(t.open[t.active.unwrap()].path, "C");
    }

    #[test]
    fn close_last_remaining_clears_active() {
        let mut t = loading_tabs(&["A"]);
        t.close(0);
        assert!(t.open.is_empty());
        assert_eq!(t.active, None);
    }

    #[test]
    fn close_out_of_bounds_is_noop() {
        let mut t = loading_tabs(&["A"]);
        t.close(99);
        assert_eq!(t.open.len(), 1);
        assert_eq!(t.active, Some(0), "no-op close must not change active");
    }

    #[test]
    fn close_after_active_leaves_active_index_unchanged() {
        let mut t = loading_tabs(&["A", "B", "C"]);
        t.activate(0);
        t.close(2); // removed index is after active → active stays 0
        assert_eq!(t.active, Some(0));
        assert_eq!(t.open[0].path, "A");
        assert_eq!(t.open.len(), 2);
    }

    #[test]
    fn set_view_changes_only_target_tab() {
        let mut t = loading_tabs(&["A", "B"]);
        t.set_view(0, ViewMode::Hex);
        assert_eq!(t.open[0].view, ViewMode::Hex);
        assert_eq!(t.open[1].view, ViewMode::Properties);
    }

    #[test]
    fn set_content_targets_by_path_not_index() {
        let mut t = loading_tabs(&["A", "B"]);
        t.set_content(
            "A",
            TabContent::Ready {
                bytes: vec![1, 2],
                truncated: false,
                parsed: Err("x".into()),
            },
        );
        assert!(matches!(t.open[0].content, TabContent::Ready { .. }));
        assert!(matches!(t.open[1].content, TabContent::Loading));
    }

    #[test]
    fn set_content_for_closed_path_is_noop() {
        // A late async result for an already-closed tab must not panic or reopen.
        let mut t = loading_tabs(&["A"]);
        t.close(0);
        t.set_content(
            "A",
            TabContent::Ready {
                bytes: vec![],
                truncated: false,
                parsed: Err("x".into()),
            },
        );
        assert!(t.open.is_empty());
    }

    // ── pick_view_after_load ──────────────────────────────────────────────────

    fn ready_err_tab(path: &str) -> Tabs {
        let mut t = Tabs::default();
        let _ = t.open_or_activate(path);
        t.set_content(
            path,
            TabContent::Ready {
                bytes: vec![],
                truncated: false,
                parsed: Err("not a uasset".into()),
            },
        );
        t
    }

    fn ready_ok_tab(path: &str) -> Tabs {
        // Parse a known-good minimal .uasset fixture synchronously.
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/minimal_uasset_v5.uasset");
        let bytes = std::fs::read(&fixture_path).expect("read minimal_uasset_v5.uasset");
        let pkg = paksmith_core::asset::Package::read_from(&bytes, None, None, "test.uasset")
            .expect("parse minimal_uasset_v5.uasset");
        let mut t = Tabs::default();
        let _ = t.open_or_activate(path);
        t.set_content(
            path,
            TabContent::Ready {
                bytes,
                truncated: false,
                parsed: Ok(Arc::new(pkg)),
            },
        );
        t
    }

    #[test]
    fn pick_view_after_load_err_on_properties_demotes_to_info() {
        let mut t = ready_err_tab("a.uasset");
        assert_eq!(t.open[0].view, ViewMode::Properties);
        t.pick_view_after_load("a.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Info,
            "Err tab on Properties must switch to Info"
        );
    }

    #[test]
    fn pick_view_after_load_ok_leaves_view_as_properties() {
        let mut t = ready_ok_tab("a.uasset");
        assert_eq!(t.open[0].view, ViewMode::Properties);
        t.pick_view_after_load("a.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Properties,
            "Ok tab must stay on Properties"
        );
    }

    #[test]
    fn pick_view_after_load_err_already_on_hex_stays_hex() {
        let mut t = ready_err_tab("a.uasset");
        t.set_view(0, ViewMode::Hex);
        t.pick_view_after_load("a.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Hex,
            "Err tab not on Properties must not be touched"
        );
    }

    #[test]
    fn clear_empties_all() {
        let mut t = loading_tabs(&["A", "B"]);
        t.clear();
        assert!(t.open.is_empty());
        assert_eq!(t.active, None);
    }

    #[test]
    fn is_open_reports_membership() {
        let mut t = Tabs::default();
        assert!(!t.is_open("A"));
        let _ = t.open_or_activate("A");
        assert!(t.is_open("A"));
        assert!(!t.is_open("B"));
    }

    #[test]
    fn activate_out_of_bounds_is_noop() {
        let mut t = loading_tabs(&["A"]);
        t.activate(5);
        assert_eq!(t.active, Some(0));
    }

    // ── B5: close / activate boundary ────────────────────────────────────────

    #[test]
    fn close_active_middle_repicks_via_min_not_decrement() {
        // Tabs: A(0) B(1) C(2) D(3); active = 1.
        // Close idx=1 (the active tab). a==idx falls through to the `_` arm:
        //   idx.min(len - 1) = 1.min(2) = 1 → points at C.
        // The `> with >=` mutant would trigger the `a >= idx` arm for `a == idx`,
        // returning `a - 1 = 0` instead of 1 (wrong: A, not C).
        let mut t = loading_tabs(&["A", "B", "C", "D"]);
        t.activate(1);
        t.close(1);
        assert_eq!(
            t.active,
            Some(1),
            "closing active middle tab must pick the new tab at that index"
        );
        assert_eq!(t.open[1].path, "C", "index 1 must now point at C");
    }

    #[test]
    fn activate_exactly_at_len_is_rejected() {
        // Tabs: ["A"]; len=1. activate(1) is one-past-the-end.
        // `< with <=` mutant: would accept idx=1 → sets active=Some(1) (OOB).
        let mut t = loading_tabs(&["A"]);
        let original_active = t.active;
        t.activate(1); // idx == len(1): `<` rejects, `<=` would accept (OOB)
        assert_eq!(
            t.active, original_active,
            "activate at exactly len must be rejected (out of bounds)"
        );
    }

    // ── ViewMode::Texture + texture_available (Phase 7b Task 3) ──────────────

    /// Build a `TabContent::Ready` wrapping a non-texture `Package`
    /// (Generic export; classify_texture → None).
    fn ready_non_texture_content() -> TabContent {
        use std::sync::Arc;
        let mp = paksmith_core::testing::uasset::build_minimal_ue4_27();
        let pkg =
            paksmith_core::asset::Package::read_from(&mp.bytes, None, None, "Game/Foo.uasset")
                .expect("build_minimal_ue4_27 must parse");
        TabContent::Ready {
            bytes: mp.bytes.clone(),
            truncated: false,
            parsed: Ok(Arc::new(pkg)),
        }
    }

    #[test]
    fn pick_view_promotes_when_mip_cache_is_populated() {
        // Unit test of `pick_view_after_load` in isolation: it promotes off the
        // decodable-mip cache (`texture_available`), NOT by re-classifying the
        // `Package`. We seed `mips` directly to stand in for the handler's
        // classify step. The classify→populate→promote pipeline (and a classify
        // regression that would empty the cache) is covered end-to-end by
        // `app::tests::asset_loaded_decodable_texture_populates_path_keyed_tab`.
        let mut t = Tabs::default();
        let _ = t.open_or_activate("Game/T_Rock.uasset");
        // Content kind is deliberately non-texture: a `Texture` promotion here
        // proves the decision comes from the seeded `mips` cache, never from
        // re-classifying the `Package`.
        t.set_content("Game/T_Rock.uasset", ready_non_texture_content());
        t.open[0].texture.mips = vec![(4, 4)];
        t.pick_view_after_load("Game/T_Rock.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Texture,
            "a tab with a populated decodable-mip cache must promote to Texture view"
        );
    }

    // `pick_view_after_load`'s Ok-stays-Properties and Err-demotes-to-Info paths
    // are covered by `pick_view_after_load_ok_leaves_view_as_properties` and
    // `pick_view_after_load_err_on_properties_demotes_to_info` above; since
    // `pick_view` no longer classifies (it reads the mip cache), a non-texture Ok
    // tab is indistinguishable from any other empty-cache Ok tab, so no separate
    // non-texture variant is needed here.

    #[test]
    fn texture_available_reads_the_decodable_mip_cache() {
        // `texture_available` is a pure reader of the per-tab decodable-mip
        // cache (`tab.texture.mips`): empty → false, non-empty → true. It never
        // re-classifies the `Package`, so the tab's content kind is irrelevant —
        // only the cache the `AssetLoaded` handler populates matters.
        let mut t = Tabs::default();
        let _ = t.open_or_activate("tex.uasset");

        // Empty cache (the default after `open_or_activate`) → false.
        assert!(
            !texture_available(&t.open[0]),
            "an empty decodable-mip cache must read false"
        );

        // A populated cache → true, even on a tab whose content would itself
        // classify as non-texture (proving the read never re-classifies).
        t.set_content("tex.uasset", ready_non_texture_content());
        t.open[0].texture.mips = vec![(64, 64)];
        assert!(
            texture_available(&t.open[0]),
            "a non-empty decodable-mip cache must read true"
        );
    }

    #[test]
    fn parsed_package_some_for_ready_ok_none_otherwise() {
        let mut t = ready_ok_tab("a.uasset");
        assert!(t.parsed_package("a.uasset").is_some(), "Ready+Ok → Some");
        assert!(
            t.parsed_package("missing.uasset").is_none(),
            "absent → None"
        );

        let e = ready_err_tab("b.uasset");
        assert!(e.parsed_package("b.uasset").is_none(), "Ready+Err → None");

        let _ = t.open_or_activate("loading.uasset"); // Loading content
        assert!(
            t.parsed_package("loading.uasset").is_none(),
            "Loading → None"
        );
    }

    #[test]
    fn set_content_resets_stale_texture_cache() {
        // `set_content` invalidates the per-content texture cache so
        // `texture_available` cannot read stale-true after a content swap (the
        // Phase 7c in-place-reload hazard). Populate the cache, swap to
        // non-texture content, and assert it is cleared and the tab no longer
        // offers a Texture view.
        let mut t = Tabs::default();
        let _ = t.open_or_activate("a.uasset");
        t.open[0].texture.mips = vec![(64, 64)];
        t.open[0].texture.selected_mip = 3;
        t.set_content("a.uasset", ready_non_texture_content());
        assert!(
            t.open[0].texture.mips.is_empty(),
            "set_content must reset the texture cache on content swap"
        );
        assert_eq!(
            t.open[0].texture.selected_mip, 0,
            "set_content must reset the full texture state, not just mips"
        );
        assert!(
            !texture_available(&t.open[0]),
            "after a swap to non-texture content the Texture tab must not be offered"
        );
    }

    // ── ViewMode::Audio + audio_available (Phase 7d Task 4) ──────────────────

    /// Build an `AudioInfo` for use in tests (Vorbis/stereo/12.5 s/playable).
    fn sample_audio_info() -> paksmith_core::asset::AudioInfo {
        paksmith_core::asset::AudioInfo {
            export_idx: 0,
            codec_label: "Vorbis (Ogg)".to_string(),
            channels: Some(2),
            duration_secs: Some(12.5),
            playable: true,
        }
    }

    #[test]
    fn audio_available_is_true_only_once_classified() {
        // `audio_available` is the audio peer of `texture_available`: it reads
        // the per-tab AudioInfo cache (tab.audio.info) rather than re-classifying
        // the Package. None → false; Some → true.
        let mut t = Tabs::default();
        let _ = t.open_or_activate("audio.uasset");
        assert!(
            !audio_available(&t.open[0]),
            "no AudioInfo yet → must be false"
        );
        t.open[0].audio.info = Some(sample_audio_info());
        assert!(audio_available(&t.open[0]), "AudioInfo set → must be true");
    }

    #[test]
    fn pick_view_promotes_to_audio_when_audio_available_and_no_texture() {
        // A tab whose texture-mip cache is empty (texture_available = false) but
        // whose audio.info is Some (audio_available = true) must be promoted from
        // Properties to Audio. Uses ready_non_texture_content so the tab's
        // Package is a realistic non-texture parse result, making the test an
        // honest simulation of a sound-wave asset load.
        let mut t = Tabs::default();
        let _ = t.open_or_activate("audio.uasset");
        t.set_content("audio.uasset", ready_non_texture_content());
        // texture_available is false (set_content resets mips to empty).
        assert!(t.open[0].texture.mips.is_empty());
        // Populate audio.info to make audio_available true.
        t.open[0].audio.info = Some(sample_audio_info());
        t.pick_view_after_load("audio.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Audio,
            "a tab with audio but no texture, on Properties, must promote to Audio"
        );
    }

    #[test]
    fn pick_view_audio_respects_user_set_hex() {
        // pick_view_after_load must not override a user-initiated view switch.
        // Even with audio_available = true, a tab already on Hex must stay on Hex.
        let mut t = loading_tabs(&["audio.uasset"]);
        t.open[0].audio.info = Some(sample_audio_info());
        t.set_view(0, ViewMode::Hex);
        t.pick_view_after_load("audio.uasset");
        assert_eq!(
            t.open[0].view,
            ViewMode::Hex,
            "user-set Hex must be respected even when audio_available is true"
        );
    }
}
