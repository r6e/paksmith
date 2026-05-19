# UE Format Documentation Plans — Shared Preamble

> **Read this before any of the per-family plans** (`2026-05-19-ue-format-docs-{primitives,containers,asset,property,compression,crypto,texture,mesh,audio,animation-material,data}.md`). This preamble captures the setup steps and conventions every family plan would otherwise repeat verbatim.
>
> The framework plan (`2026-05-19-ue-format-docs-framework.md`, for PR 1) does NOT use this preamble — it ships actual code rather than family content and has its own setup flow.

**Spec reference:** `docs/design/2026-05-19-ue-format-docs.md` (commit `72b364e`). **Prerequisite for every family plan:** PR 1 (framework scaffold) has merged to `main`.

---

## Per-family setup (do once at the start of each family plan)

Every family plan begins with these steps. The family plan's first task can be one sentence: *"Run the per-family setup in PREAMBLE.md, then proceed to Task 2."*

- [ ] **Step 1: Confirm PR 1 has merged**

Run: `git fetch origin && git log origin/main --oneline | grep -c "format documentation framework"`
Expected: ≥ 1. If `0`, PR 1 hasn't merged — stop and finish PR 1 first.

- [ ] **Step 2: Create the worktree from `origin/main`**

From the primary checkout root:

Run: `git worktree add .claude/worktrees/docs+ue-format-docs-<family> -b docs/ue-format-docs-<family> origin/main`

Substitute `<family>` for the per-plan family name (e.g. `primitives`, `containers`, `asset`).

- [ ] **Step 3: Switch session cwd into the worktree**

Run: `cd .claude/worktrees/docs+ue-format-docs-<family> && pwd && git branch --show-current`
Expected: prints the worktree path and the matching branch name.

All subsequent commands run with the worktree as cwd. Do NOT use `git -C` or reach into other worktrees.

- [ ] **Step 4: Verify the framework scaffold is present**

Run: `ls docs/formats/<dir>/README.md docs/formats/TEMPLATE.md docs/formats/CONVENTIONS.md docs/formats/README.md`
Expected: all four files listed.

Note: `<dir>` is the `docs/formats/` subdirectory name, which usually matches `<family>` but differs for three plans:
- `primitives` plan → `<dir>` = `primitive`
- `containers` plan → `<dir>` = `container`
- `animation-material` plan → `<dir>` ∈ `{animation, material}` (two subdirs; verify both: `ls docs/formats/animation/README.md docs/formats/material/README.md`)

Each family plan's Task 1 specifies both `<family>` (branch/worktree slug) and `<dir>` explicitly.

- [ ] **Step 5: Build the linter binary**

Run: `cargo build -p paksmith-doc-lint --release`
Expected: clean.

- [ ] **Step 6: Linter smoke-test**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Step 7: Capture oracle SHAs for this plan run**

Look up HEADs at plan-execution time and note them for use across every per-doc citation in this plan:

Run: `git ls-remote https://github.com/FabianFG/CUE4Parse HEAD | cut -f1` — note as `<CUE4PARSE_SHA>`.
Run: `git ls-remote https://github.com/trumank/repak HEAD | cut -f1` — note as `<REPAK_SHA>` (used by container / compression / crypto family plans; skip for others).
Run: `git ls-remote https://github.com/AstralOrigin/unreal_asset HEAD | cut -f1` — note as `<UNREAL_ASSET_SHA>`.

If any repo URL has moved, find the current canonical home via web search. Recent paksmith commits citing these crates are the most reliable backup signal — `git log --all --oneline | xargs -I{} git show {} | grep -E "github.com/(FabianFG|AstralOrigin|trumank)" | head -5`.

These SHAs apply to every footnote citation in this plan's doc bodies — capture once here, reuse everywhere. Oracle HEADs don't meaningfully drift across a single authoring session.

Setup complete. No commit — this is environment-only. Family plans pick up at Task 2.

---

## Per-doc-authoring-task convention

Every doc-authoring task in a family plan follows the same shape. The family plan spells out the per-doc particulars (parser file references, oracle paths, doc body verbatim, commit message); the mechanical tail steps below are implicit and don't need to be repeated:

After writing each doc (the family-plan task's `Write` step), every task ends with:

1. **Lint check** — `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`. Expected: exits 0. If it fails, the section heading order or membership is wrong; re-check against `TEMPLATE.md`.
2. **Commit** — `git add docs/formats/<family>/<doc>.md && git commit -m "<task-specific message>"` per the commit messages spelled out per-task in the family plan.

Family plans omit these two mechanical steps from per-task bodies. If a task deviates (e.g. a verification step needs to run before commit), the deviation is called out inline.

---

## Per-family final-verification + push tail

Every family plan's last task before PR-creation does the same finalization work. The family plan adds the specific inventory rows and the specific push command; everything else is shared:

- [ ] **Capture branch HEAD**

Run: `git rev-parse --short HEAD` — note as `<SHA>` for the `Last verified` column of the inventory rows added in this PR.

- [ ] **Status-enum lint after inventory edit**

Run: `cargo run -p paksmith-doc-lint --release -- status-enum docs/formats/README.md`
Expected: exits 0.

- [ ] **Required-headings lint across all docs**

Run: `cargo run -p paksmith-doc-lint --release -- required-headings docs/formats/`
Expected: exits 0.

- [ ] **File tree sanity check**

Run: `ls docs/formats/<family>/*.md | sort` and confirm the listed files match the inventory rows.

- [ ] **Typos check**

Run: `typos docs/formats/<family>/`
Expected: clean. Domain terms likely to flag — extend `_typos.toml` only when reword isn't natural.

- [ ] **rustdoc lints**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
Expected: clean (no Rust changed in a family PR).

- [ ] **Push and open PR**

Run: `git push -u origin docs/ue-format-docs-<family>`

Open the PR per project convention: title is lowercase verb-first, body via `--body-file <tempfile>` (never inline `--body "$(cat <<EOF ...)"` — backticks get eaten; see project memory `feedback_pr_body_no_backtick_escaping.md`). The family plan provides the specific title + body content.

- [ ] **Run the reviewer panel**

Dispatch in a SINGLE message with multiple Agent tool calls (per project memory `feedback_parallel_full_review_panel.md` + `feedback_always_run_review_panel.md`):

- `feature-dev:code-reviewer` (general quality + spec adherence + factual accuracy against parser source)
- `feature-dev:code-architect` (status-pair coherence, oracle citations sound, cross-references valid)
- `code-simplifier:code-simplifier` (any sections over-explained; redundancy hunt)

Address issues, re-run the panel on the fix commit, repeat until every reviewer says APPROVED (per `feedback_review_until_convergence.md`).
