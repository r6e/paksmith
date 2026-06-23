#!/usr/bin/env bash
#
# Flags **orphan unfinished-work markers in Rust doc comments** (`///` / `//!`):
# a bare `TODO` / `FIXME` with no tracking reference. A public-API doc comment
# carrying a bare TODO is the mechanically-detectable slice of the doc-rot class
# PR #594 hit (e.g. R7's "the visible-row cap is a TODO" left in a doc comment
# after the cap was implemented). It also enforces CLAUDE.md's "no orphan TODOs".
#
# Deliberately NARROW to stay zero-noise on a mature tree:
#   * only DOC-comment lines (`///`, `//!`) — ordinary `// TODO` in code is fine
#   * only the conventional markers `TODO` / `FIXME`, matched as whole words
#   * a tracked `TODO(scope)` / `FIXME(#123)` (anything with a following `(`) is
#     allowed — that is a referenced, owned item, not an orphan
#
# Known limitation: detection is line-based, so a line carrying BOTH a bare and a
# tracked marker (`/// TODO fix the TODO(x)`) is allowed — erring toward a false
# negative on a pathological line rather than noise, consistent with the design.
#
# NOT detected on purpose: prose like "placeholder" / "stub" / "not yet
# implemented". Those are legitimate technical vocabulary (a tree scan found 45
# correct uses), so a grep cannot tell a stale lie from a real domain term —
# that judgment belongs to the "verify the doc claim end-to-end" review step
# (see memory feedback_trace_data_path_and_verify_claims), not to a lint.
#
# Escape hatch: put `lint-allow-todo` on the same line for an intentional case.
#
# Usage:
#   scripts/lint-orphan-doc-todos.sh [FILE ...]   # scan the given files (worktree)
#   scripts/lint-orphan-doc-todos.sh              # default: STAGED .rs, read from index
#   scripts/lint-orphan-doc-todos.sh --all        # all tracked .rs (worktree)
#
# Exit 0 = clean, 1 = orphan marker(s) found.
set -euo pipefail

# Doc-comment line prefix (leading whitespace + `///` or `//!`).
doc_prefix='^[[:space:]]*(///|//!)'
# Word-boundary matching is done with POSIX `grep -w`, NOT `\b`: `\b` is a GNU
# extension; under POSIX ERE (BSD/macOS `grep -E`) it is a backspace escape, which
# would silently make this lint a no-op. The detection is therefore two passes:
#   1. `grep -wE marker_word`   — the marker as a whole word (so MYTODO/TODOLIST
#                                  do not match), covering both bare and tracked.
#   2. `grep -vE tracked_marker` — drop the tracked form `TODO(`/`FIXME(`, leaving
#                                  only orphan markers.
marker_word='(TODO|FIXME)'
tracked_marker='(TODO|FIXME)\('

# Default mode (no args) is the pre-commit case: scan STAGED `.rs` and read each
# file's content FROM THE INDEX, so an unstaged working-tree edit neither masks a
# staged orphan nor trips a failure on a marker that was never staged. `--all`
# and explicit file args operate on the working tree instead.
scan_from_index=0
[ "$#" -eq 0 ] && scan_from_index=1

select_files() {
  if [ "$#" -gt 0 ] && [ "$1" = "--all" ]; then
    git ls-files -- '*.rs'
  elif [ "$#" -gt 0 ]; then
    printf '%s\n' "$@"
  else
    git diff --cached --name-only --diff-filter=ACM -- '*.rs'
  fi
}

# Emit the content to scan for one path: the staged blob in index mode, else the
# working-tree file (skipped if it has vanished, e.g. staged-then-deleted).
file_content() {
  if [ "$scan_from_index" -eq 1 ]; then
    git show ":$1" 2>/dev/null || true
  elif [ -f "$1" ]; then
    cat -- "$1"
  fi
}

hits=0
while IFS= read -r f; do
  # `grep -n` numbers the content stream from 1 (matches the file's line numbers);
  # the allow-escape and marker filters run on the `lineno:content` stream so the
  # number survives to the report.
  while IFS= read -r match; do
    echo "  $f:$match"
    hits=1
  done < <(
    file_content "$f" \
      | grep -nE "$doc_prefix" \
      | grep -ivE 'lint-allow-todo' \
      | grep -wE "$marker_word" \
      | grep -vE "$tracked_marker" || true
  )
done < <(select_files "$@")

if [ "$hits" -ne 0 ]; then
  echo "error: orphan TODO/FIXME in doc comment(s) (see above)." >&2
  echo "  Resolve it, give it a tracking ref (TODO(scope) / FIXME(#123))," >&2
  echo "  or add 'lint-allow-todo' on the line if it is intentional." >&2
  exit 1
fi
exit 0
