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

#[derive(Debug, Clone)]
struct Node {
    /// Display label (single path segment).
    label: String,
    /// `None` for the virtual root and for directories.
    full_path: Option<String>,
    /// Lowercased `full_path` for file nodes; empty string for dirs/root.
    /// Cached once at build time so `compute_match_set` avoids per-keystroke
    /// heap allocations when a live filter is active.
    lower_path: String,
    is_dir: bool,
    /// Arena index of parent.  The virtual root (index 0) points to itself.
    parent: usize,
    /// Arena indices of direct children, in sorted order (dirs first, then
    /// files, each group alphabetical).
    children: Vec<usize>,
}

// ── Tree ─────────────────────────────────────────────────────────────────────

/// Pure file-tree model.  No Iced imports; safe to test without a display.
#[derive(Debug, Clone)]
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
            lower_path: String::new(),
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
                    let lower_path = if is_last {
                        path.to_lowercase()
                    } else {
                        String::new()
                    };
                    let is_dir = !is_last;
                    nodes.push(Node {
                        label: seg.to_owned(),
                        full_path,
                        lower_path,
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
        if node.lower_path.contains(query) {
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

    #[test]
    fn lower_path_cache_matches_full_path_lowercased() {
        // Verify the build-time cache is correct for every file node.
        let t = demo();
        for node in &t.nodes {
            if !node.is_dir {
                let expected = node.full_path.as_deref().unwrap_or("").to_lowercase();
                assert_eq!(node.lower_path, expected);
            }
        }
    }

    // ── depth-arithmetic mutant killers ───────────────────────────────────────
    //
    // These tests pin the NUMERIC `depth` values emitted by `dfs_normal` and
    // `dfs_filtered`.  The survivors replace `depth + 1` with `depth * 1` in
    // the child recursive call.  When `depth` starts at 0 (root children),
    // `0 + 1 == 1` but `0 * 1 == 0`; then `1 + 1 == 2` but `1 * 1 == 1`.
    // Asserting depth == 2 for grandchildren kills both mutants.

    #[test]
    fn depth_values_normal_walk() {
        // After expanding Content (row 0) and then Char (now row 1), the rows are:
        //   row 0: Content        depth 0  (dir)
        //   row 1: Char           depth 1  (dir)
        //   row 2: Hero.uasset   depth 2  (file)
        //   row 3: Hero.uexp     depth 2  (file)
        //   row 4: Maps           depth 1  (dir)
        //   row 5: README.txt    depth 0  (file)
        let mut t = demo();
        t.toggle(0); // expand Content
        t.toggle(1); // expand Char
        let rows = t.visible_rows();
        assert_eq!(rows[0].label, "Content");
        assert_eq!(rows[0].depth, 0, "top-level dir must be depth 0");
        assert_eq!(rows[1].label, "Char");
        assert_eq!(rows[1].depth, 1, "first-level subdir must be depth 1");
        // Grandchildren (files inside Char) must be depth 2.
        // `depth + 1` gives 2; `depth * 1` would give 1 — the assert distinguishes them.
        let hero_row = rows
            .iter()
            .find(|r| r.label == "Hero.uasset")
            .expect("Hero.uasset must be visible after expanding Char");
        assert_eq!(
            hero_row.depth, 2,
            "grandchild file must be depth 2, not 1 or 0"
        );
        // Top-level file must still be depth 0.
        let readme = rows
            .iter()
            .find(|r| r.label == "README.txt")
            .expect("README.txt must be visible");
        assert_eq!(readme.depth, 0, "top-level file must be depth 0");
    }

    #[test]
    fn depth_values_filtered_walk() {
        // Under a filter, dfs_filtered also uses `depth + 1` for children.
        // Querying "uasset" shows: Content(0) → Char(1) → Hero.uasset(2).
        // The `depth * 1` mutant would collapse all to depth 0.
        let mut t = demo();
        t.set_filter("uasset");
        let rows = t.visible_rows();
        let content = rows
            .iter()
            .find(|r| r.label == "Content")
            .expect("Content must appear as ancestor");
        assert_eq!(content.depth, 0);
        let char_dir = rows
            .iter()
            .find(|r| r.label == "Char")
            .expect("Char must appear as ancestor");
        assert_eq!(char_dir.depth, 1);
        let hero = rows
            .iter()
            .find(|r| r.label == "Hero.uasset")
            .expect("Hero.uasset must match the filter");
        assert_eq!(hero.depth, 2, "filtered grandchild must be depth 2");
    }

    // ── sort_children_recursive mutant killers ────────────────────────────────
    //
    // Survivor 1: "replace sort_children_recursive with ()" — a no-op body.
    //   Kill: if insertion order != sorted order, visible_rows come out wrong.
    //   We insert paths in non-alphabetical order and assert sorted output.
    //
    // Survivor 2: "delete !" in `!nodes[a].is_dir` / `!nodes[b].is_dir`
    //   which would invert the sort key — files would sort before dirs.
    //   Kill: assert that dirs precede files at each level.

    #[test]
    fn sort_children_uses_dirs_first_alpha_not_insertion_order() {
        // Insert paths in reverse-alpha order so the no-op mutant fails.
        // Also mix dirs and files to kill the "delete !" (file-first) mutant.
        //
        // Insertion order (deliberately anti-sorted):
        //   "Zebra/z.txt"   — dir Zebra, file z.txt
        //   "Apple/b.txt"   — dir Apple, file b.txt
        //   "m_file.txt"    — top-level file
        //   "Beta/c.txt"    — dir Beta, file c.txt
        //
        // Expected top-level visible rows (collapsed): Apple, Beta, Zebra, m_file.txt
        // If sort is a no-op: Zebra, Apple, m_file.txt, Beta.
        let t = Tree::from_paths([
            "Zebra/z.txt".to_string(),
            "Apple/b.txt".to_string(),
            "m_file.txt".to_string(),
            "Beta/c.txt".to_string(),
        ]);
        let labels: Vec<_> = t.visible_rows().iter().map(|r| r.label.as_str()).collect();
        // Dirs must come before files.
        assert_eq!(
            labels,
            vec!["Apple", "Beta", "Zebra", "m_file.txt"],
            "top-level rows must be dirs-first alphabetical, not insertion order"
        );
    }

    #[test]
    fn sort_children_dirs_before_files_within_same_dir() {
        // Build a dir where files would sort alpha-before the subdir.
        // "a_file.txt" < "z_dir" alphabetically; correct sort puts z_dir first.
        // The "delete !" mutant inverts is_dir → files would come first.
        let t = Tree::from_paths([
            "Parent/a_file.txt".to_string(),
            "Parent/z_dir/nested.txt".to_string(),
        ]);
        let mut t = t;
        t.toggle(0); // expand Parent
        let rows = t.visible_rows();
        // Expected: Parent(0), z_dir(1), a_file.txt(2)
        assert_eq!(
            rows[1].label, "z_dir",
            "dir should come before file even if alpha-after"
        );
        assert_eq!(rows[2].label, "a_file.txt", "file should follow dir");
        assert!(rows[1].is_dir);
        assert!(!rows[2].is_dir);
    }

    #[test]
    fn sort_children_recursive_sorts_within_subdir() {
        // sort_children_recursive recurses into every subdir. Without recursion,
        // only the root level is sorted. This test pins subdir child order.
        //
        // In Zebra we insert z.txt before a.txt — correct sort yields a.txt, z.txt.
        let t = Tree::from_paths(["Zebra/z.txt".to_string(), "Zebra/a.txt".to_string()]);
        let mut t = t;
        t.toggle(0); // expand Zebra
        let rows = t.visible_rows();
        // row 0 = Zebra (dir), row 1 = a.txt, row 2 = z.txt
        assert_eq!(
            rows[1].label, "a.txt",
            "children must be sorted alpha within dir"
        );
        assert_eq!(rows[2].label, "z.txt");
    }
}
