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
#   * only the conventional markers `TODO` / `FIXME`
#   * a tracked `TODO(scope)` / `FIXME(#123)` (anything with a following `(`) is
#     allowed — that is a referenced, owned item, not an orphan
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
#   scripts/lint-orphan-doc-todos.sh [FILE ...]   # scan the given files
#   scripts/lint-orphan-doc-todos.sh              # default: staged .rs files
#   scripts/lint-orphan-doc-todos.sh --all        # scan all tracked .rs files
#
# Exit 0 = clean, 1 = orphan marker(s) found.
set -euo pipefail

# Doc-comment line prefix (leading whitespace + `///` or `//!`).
doc_prefix='^[[:space:]]*(///|//!)'
# A bare TODO/FIXME: the marker NOT immediately followed by `(` (which would make
# it a tracked `TODO(scope)`). `[^(]` or end-of-line after the marker word.
orphan_marker='\b(TODO|FIXME)\b([^(]|$)'

select_files() {
  if [ "$#" -gt 0 ] && [ "$1" = "--all" ]; then
    git ls-files -- '*.rs'
  elif [ "$#" -gt 0 ]; then
    printf '%s\n' "$@"
  else
    git diff --cached --name-only --diff-filter=ACM -- '*.rs'
  fi
}

hits=0
while IFS= read -r f; do
  # `[ -f ]` also covers blank/empty input (no producer emits blank lines, but
  # a staged-then-deleted path can vanish before the scan).
  [ -f "$f" ] || continue
  # `grep -n` keeps the original line number; the allow-escape and marker filters
  # run on the `lineno:content` stream so the number survives to the report.
  while IFS= read -r match; do
    echo "  $f:$match"
    hits=1
  done < <(
    grep -nE "$doc_prefix" "$f" \
      | grep -ivE 'lint-allow-todo' \
      | grep -E "$orphan_marker" || true
  )
done < <(select_files "$@")

if [ "$hits" -ne 0 ]; then
  echo "error: orphan TODO/FIXME in doc comment(s) (see above)." >&2
  echo "  Resolve it, give it a tracking ref (TODO(scope) / FIXME(#123))," >&2
  echo "  or add 'lint-allow-todo' on the line if it is intentional." >&2
  exit 1
fi
exit 0
