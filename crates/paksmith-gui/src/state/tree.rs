/// Pure, virtualized file-tree model for the explorer panel.
///
/// No `iced` imports. All mutations invalidate the cached `visible_rows` slice,
/// which is rebuilt on the next call or eagerly on mutation (dirty-flag approach).
///
/// # Arena layout
///
/// Nodes are stored in a `Vec<Node>` (the arena).  Index 0 is a synthetic
/// virtual root that is never emitted as a visible row; its children are the
/// top-level entries.  Every non-root node holds its parent index, its
/// children (as arena indices), its label (path segment), and—for files—its
/// full path.
///
/// # Child ordering
///
/// Children are sorted at build time: **directories first, then files, each
/// group alphabetical**.  The DFS walk emits them in this order for free.
///
/// # Filter semantics
///
/// When a non-empty filter is active, the walk emits only nodes that are
/// *ancestors* of at least one matching file (including the file itself).
/// All such ancestor dirs are treated as expanded regardless of `expanded`
/// state.  Clearing the filter restores the normal collapsed/expanded view.
use std::collections::HashSet;

// ── public types ─────────────────────────────────────────────────────────────

/// A single row in the visible tree.
#[derive(Debug, Clone)]
pub struct VisibleRow {
    pub depth: usize,
    pub label: String,
    pub is_dir: bool,
    pub expanded: bool,
    /// `Some(path)` for files, `None` for dirs.
    pub full_path: Option<String>,
}

// ── internal arena node ───────────────────────────────────────────────────────

#[derive(Debug)]
struct Node {
    /// Display label (single path segment).
    label: String,
    /// `None` for the virtual root and for directories.
    full_path: Option<String>,
    is_dir: bool,
    /// Arena index of parent.  The virtual root (index 0) points to itself.
    parent: usize,
    /// Arena indices of direct children, in sorted order (dirs first, then
    /// files, each group alphabetical).
    children: Vec<usize>,
}

// ── Tree ─────────────────────────────────────────────────────────────────────

/// Pure file-tree model.  No Iced imports; safe to test without a display.
pub struct Tree {
    /// Arena of all nodes.  Index 0 is the virtual root.
    nodes: Vec<Node>,
    /// Nodes whose directories are currently expanded.
    expanded: HashSet<usize>,
    /// Selected FILE node index.
    selected: Option<usize>,
    /// Active case-insensitive filter query (empty = no filter).
    filter: String,
    /// Cached visible rows (rebuilt on every mutation).
    rows: Vec<VisibleRow>,
    /// Parallel vec: for `rows[i]`, `row_nodes[i]` is the arena index.
    row_nodes: Vec<usize>,
    /// Total file count (computed once at build time).
    file_count: usize,
}

impl Tree {
    // ── construction ─────────────────────────────────────────────────────────

    /// Build a tree from an iterator of slash-separated paths.
    ///
    /// Intermediate segments become directories; the final segment becomes a
    /// file.  Duplicate paths collapse into a single node.
    pub fn from_paths(paths: impl IntoIterator<Item = String>) -> Tree {
        // Virtual root at index 0.
        let root = Node {
            label: String::new(),
            full_path: None,
            is_dir: true,
            parent: 0,
            children: Vec::new(),
        };
        let mut nodes: Vec<Node> = vec![root];
        let mut file_count = 0usize;

        for path in paths {
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segments.is_empty() {
                continue;
            }
            let mut current = 0usize; // start at virtual root
            let last = segments.len() - 1;
            for (depth_idx, &seg) in segments.iter().enumerate() {
                let is_last = depth_idx == last;
                // Look up an existing child with this label.
                let existing = nodes[current]
                    .children
                    .iter()
                    .copied()
                    .find(|&c| nodes[c].label == seg);
                if let Some(child_idx) = existing {
                    // Reuse the existing node if this is an intermediate segment.
                    // If it's the last segment and already exists, skip (duplicate path).
                    current = child_idx;
                } else {
                    // Insert new node.
                    let new_idx = nodes.len();
                    let full_path = if is_last { Some(path.clone()) } else { None };
                    let is_dir = !is_last;
                    nodes.push(Node {
                        label: seg.to_owned(),
                        full_path,
                        is_dir,
                        parent: current,
                        children: Vec::new(),
                    });
                    if !is_dir {
                        file_count += 1;
                    }
                    nodes[current].children.push(new_idx);
                    current = new_idx;
                }
            }
        }

        // Sort children at every node: dirs first, then files, each group alpha.
        sort_children_recursive(&mut nodes, 0);

        let mut tree = Tree {
            nodes,
            expanded: HashSet::new(),
            selected: None,
            filter: String::new(),
            rows: Vec::new(),
            row_nodes: Vec::new(),
            file_count,
        };
        tree.rebuild_rows();
        tree
    }

    // ── public API ────────────────────────────────────────────────────────────

    /// Returns the currently visible rows (cached; rebuilds on any mutation).
    pub fn visible_rows(&self) -> &[VisibleRow] {
        &self.rows
    }

    /// Expand or collapse the directory at visible-row index `row`.
    /// Out-of-range indices and file rows are silent no-ops.
    pub fn toggle(&mut self, row: usize) {
        let Some(&node_idx) = self.row_nodes.get(row) else {
            return;
        };
        if !self.nodes[node_idx].is_dir {
            return;
        }
        if self.expanded.contains(&node_idx) {
            let _ = self.expanded.remove(&node_idx);
        } else {
            let _ = self.expanded.insert(node_idx);
        }
        self.rebuild_rows();
    }

    /// Select the file at visible-row index `row`.
    /// Out-of-range and dir rows are silent no-ops (selection unchanged).
    pub fn select(&mut self, row: usize) {
        let Some(&node_idx) = self.row_nodes.get(row) else {
            return;
        };
        if self.nodes[node_idx].is_dir {
            return;
        }
        self.selected = Some(node_idx);
        // No row rebuild needed — VisibleRow carries no selection highlight.
    }

    /// Returns the full path of the selected file, or `None`.
    pub fn selected(&self) -> Option<&str> {
        self.selected
            .and_then(|i| self.nodes[i].full_path.as_deref())
    }

    /// Set a case-insensitive filter.  Empty string clears the filter.
    pub fn set_filter(&mut self, query: &str) {
        query.clone_into(&mut self.filter);
        self.rebuild_rows();
    }

    /// Total number of files (not dirs) in the tree.
    pub fn len(&self) -> usize {
        self.file_count
    }

    /// Returns `true` if the tree contains no files.
    pub fn is_empty(&self) -> bool {
        self.file_count == 0
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Rebuild `self.rows` and `self.row_nodes` from current state.
    fn rebuild_rows(&mut self) {
        self.rows.clear();
        self.row_nodes.clear();

        if self.filter.is_empty() {
            // Normal DFS walk.
            let root_children: Vec<usize> = self.nodes[0].children.clone();
            for child in root_children {
                self.dfs_normal(child, 0);
            }
        } else {
            // Filter walk: compute the match set first.
            let q = self.filter.to_lowercase();
            let match_set = compute_match_set(&self.nodes, &q);
            let root_children: Vec<usize> = self.nodes[0].children.clone();
            for child in root_children {
                self.dfs_filtered(child, 0, &match_set);
            }
        }
    }

    /// DFS walk for the unfiltered case.
    fn dfs_normal(&mut self, node_idx: usize, depth: usize) {
        let node = &self.nodes[node_idx];
        let is_dir = node.is_dir;
        let is_expanded = self.expanded.contains(&node_idx);
        let row = VisibleRow {
            depth,
            label: node.label.clone(),
            is_dir,
            expanded: is_expanded,
            full_path: node.full_path.clone(),
        };
        self.rows.push(row);
        self.row_nodes.push(node_idx);

        if is_dir && is_expanded {
            let children: Vec<usize> = self.nodes[node_idx].children.clone();
            for child in children {
                self.dfs_normal(child, depth + 1);
            }
        }
    }

    /// DFS walk for the filtered case.  Only emits nodes in `match_set`.
    /// All dir nodes in the set are treated as expanded.
    fn dfs_filtered(&mut self, node_idx: usize, depth: usize, match_set: &HashSet<usize>) {
        if !match_set.contains(&node_idx) {
            return;
        }
        let node = &self.nodes[node_idx];
        let is_dir = node.is_dir;
        // Under a filter, dirs are shown as expanded if they're in the match set.
        let is_expanded = is_dir;
        let row = VisibleRow {
            depth,
            label: node.label.clone(),
            is_dir,
            expanded: is_expanded,
            full_path: node.full_path.clone(),
        };
        self.rows.push(row);
        self.row_nodes.push(node_idx);

        if is_dir {
            let children: Vec<usize> = self.nodes[node_idx].children.clone();
            for child in children {
                self.dfs_filtered(child, depth + 1, match_set);
            }
        }
    }
}

// ── free functions ────────────────────────────────────────────────────────────

/// Recursively sort children of every node (dirs first, then files, alpha).
fn sort_children_recursive(nodes: &mut Vec<Node>, idx: usize) {
    // Collect and sort child indices by (is_file, label).
    let mut children = nodes[idx].children.clone();
    children.sort_by(|&a, &b| {
        let a_is_file = !nodes[a].is_dir;
        let b_is_file = !nodes[b].is_dir;
        a_is_file
            .cmp(&b_is_file)
            .then_with(|| nodes[a].label.cmp(&nodes[b].label))
    });
    nodes[idx].children.clone_from(&children);
    for child in children {
        sort_children_recursive(nodes, child);
    }
}

/// Compute the set of all node indices that should be visible under `query`.
/// A node is in the set if:
/// - It's a file whose full_path (lowercased) contains `query`, OR
/// - It's a dir that is an ancestor of at least one such file.
fn compute_match_set(nodes: &[Node], query: &str) -> HashSet<usize> {
    let mut set = HashSet::new();
    // Walk all nodes looking for matching files, then mark ancestors.
    for (idx, node) in nodes.iter().enumerate() {
        if node.is_dir {
            continue;
        }
        if let Some(fp) = &node.full_path
            && fp.to_lowercase().contains(query)
        {
            // Mark this file and walk up to root.
            let mut cur = idx;
            loop {
                if !set.insert(cur) {
                    // Already inserted — ancestors already marked.
                    break;
                }
                if cur == 0 {
                    break;
                }
                cur = nodes[cur].parent;
            }
        }
    }
    set
}

// ── tests (verbatim from task brief + extra edge-case coverage) ───────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> Tree {
        Tree::from_paths([
            "Content/Char/Hero.uasset".to_string(),
            "Content/Char/Hero.uexp".to_string(),
            "Content/Maps/A.umap".to_string(),
            "README.txt".to_string(),
        ])
    }

    // ── brief tests (verbatim) ────────────────────────────────────────────────

    #[test]
    fn collapsed_root_shows_only_top_level() {
        let t = demo();
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]); // dirs before files, sorted
    }

    #[test]
    fn expanding_reveals_children_lazily() {
        let mut t = demo();
        t.toggle(0); // expand Content
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "Char", "Maps", "README.txt"]);
        // grandchildren NOT shown until their dir expands
        assert!(!labels.contains(&"Hero.uasset"));
    }

    #[test]
    fn deep_expand_then_collapse_restores() {
        let mut t = demo();
        t.toggle(0); // Content
        t.toggle(1); // Char
        assert!(t.visible_rows().iter().any(|r| r.label == "Hero.uasset"));
        t.toggle(0); // collapse Content — grandchildren vanish too
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]);
    }

    #[test]
    fn select_a_file_exposes_its_full_path() {
        let mut t = demo();
        t.toggle(0);
        t.toggle(1);
        let hero = t
            .visible_rows()
            .iter()
            .position(|r| r.label == "Hero.uasset")
            .unwrap();
        t.select(hero);
        assert_eq!(t.selected(), Some("Content/Char/Hero.uasset"));
    }

    #[test]
    fn filter_keeps_only_matching_paths_and_their_ancestors() {
        let mut t = demo();
        t.set_filter("umap");
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"A.umap"));
        assert!(!labels.contains(&"Hero.uasset"));
        assert!(labels.contains(&"Content") && labels.contains(&"Maps")); // ancestors kept
    }

    #[test]
    fn len_counts_files_not_dirs() {
        assert_eq!(demo().len(), 4);
    }

    // ── extra edge-case tests ─────────────────────────────────────────────────

    #[test]
    fn out_of_range_toggle_is_noop() {
        let mut t = demo();
        t.toggle(9999); // must not panic
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]);
    }

    #[test]
    fn out_of_range_select_is_noop() {
        let mut t = demo();
        t.select(9999); // must not panic
        assert_eq!(t.selected(), None);
    }

    #[test]
    fn empty_tree_is_empty_and_len_zero() {
        let t = Tree::from_paths(std::iter::empty::<String>());
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.visible_rows().is_empty());
    }

    #[test]
    fn duplicate_paths_collapse() {
        let t = Tree::from_paths(["Foo/bar.txt".to_string(), "Foo/bar.txt".to_string()]);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn clear_filter_restores_collapsed_view() {
        let mut t = demo();
        t.set_filter("umap");
        t.set_filter("");
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        // Back to collapsed: only top-level entries.
        assert_eq!(labels, vec!["Content", "README.txt"]);
    }

    #[test]
    fn filter_is_case_insensitive() {
        let mut t = demo();
        t.set_filter("UMAP");
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"A.umap"));
    }

    #[test]
    fn select_dir_row_does_not_change_selection() {
        let mut t = demo();
        t.toggle(0); // expand Content, row 0 = Content (dir)
        t.select(0); // selecting a dir should be a no-op
        assert_eq!(t.selected(), None);
    }

    #[test]
    fn toggle_file_row_is_noop() {
        let mut t = demo();
        // row 1 = README.txt (file)
        t.toggle(1);
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["Content", "README.txt"]);
    }
}
