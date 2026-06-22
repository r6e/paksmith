//! Pure tab-collection model for the content host. No `iced` imports.

use std::collections::HashSet;

use crate::state::hex_view;
use crate::state::property_view::NodeId;
use paksmith_core::asset::Package;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Properties,
    Hex,
    Info,
}

#[derive(Debug, Clone)]
pub enum TabContent {
    Loading,
    Ready {
        bytes: Vec<u8>,
        parsed: Result<Box<Package>, String>,
    },
}

#[derive(Debug, Clone)]
pub struct Tab {
    pub path: String,
    pub view: ViewMode,
    pub content: TabContent,
    pub hex: hex_view::HexState,
    pub expanded: HashSet<NodeId>,
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
        }
    }

    /// After a load completes, demote the default view to Info for an unparsable
    /// asset (so the user lands on useful metadata, not the Properties error).
    /// Only acts when the tab is still on the default `Properties` view.
    pub fn pick_view_after_load(&mut self, path: &str) {
        if let Some(tab) = self.open.iter_mut().find(|t| t.path == path) {
            #[allow(clippy::collapsible_if)]
            if matches!(&tab.content, TabContent::Ready { parsed: Err(_), .. }) {
                if tab.view == ViewMode::Properties {
                    tab.view = ViewMode::Info;
                }
            }
        }
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
                parsed: Ok(Box::new(pkg)),
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
}
