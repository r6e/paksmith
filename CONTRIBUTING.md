# Contributing

Contributions are welcome. This document covers the workflow and expectations.

## Getting Started

```sh
git clone https://github.com/<owner>/paksmith.git
cd paksmith
git config core.hooksPath .githooks
cargo build --workspace
cargo test --workspace
```

The `core.hooksPath` config enables the pre-commit hook that runs `cargo fmt` and `cargo clippy` before each commit.

## Development Workflow

1. Create a feature branch from `main`.
2. Write a failing test.
3. Implement the minimal code to pass it.
4. Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.
5. Commit with a conventional commit message.
6. Open a PR against `main`.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```plaintext
feat(core): add IoStore container reader
fix(cli): handle empty pak files without panic
chore: update dependencies
test(core): add property-based tests for AES decryption
docs: update ARCHITECTURE.md with export pipeline
```

## Code Style

- Run `cargo fmt --all` before committing. The pre-commit hook enforces this.
- Clippy pedantic lints are enabled workspace-wide. Fix warnings, don't suppress them without justification.
- Every public symbol needs a doc comment.
- No `unsafe` code in the workspace.

## Testing

- TDD: write the test first, watch it fail, then implement.
- Unit tests live alongside the code in `#[cfg(test)]` modules.
- Integration tests live in each crate's `tests/` directory.
- Test fixtures go in `tests/fixtures/`. Never commit real game assets.
- Target 80%+ coverage on `paksmith-core`.

### Always use `--workspace` for tests

The cross-parser validation tests (which check `paksmith-core`'s pak parser against an independent implementation, [trumank/repak](https://github.com/trumank/repak)) live in the dev-only `paksmith-fixture-gen` crate. That crate is **excluded from the workspace's `default-members`** so plain `cargo build` and `cargo test` from the repo root never have to resolve the `repak` git dependency — which keeps routine local development fast and not coupled to github.com reachability.

The trade-off: bare `cargo test` skips the cross-parser test suite in `paksmith-fixture-gen/tests/cross_validation.rs` (~45 tests as of Phase 1: ~29 `cross_parser_agreement_*` byte-for-byte agreement tests + ~15 `paksmith_reads_repak_*` smoke tests + a few targeted regression pins). **Always run `cargo test --workspace`** before pushing. CI uses `--workspace` for every job, so a missed local run would surface the failure on PR — but it'll cost you a round-trip you didn't need.

The SHA1 byte anchor on `real_v3_minimal.pak` (`crates/paksmith-core/tests/fixture_anchor.rs`) DOES run on default `cargo test`, so accidental fixture corruption is caught even without `--workspace`. But cross-parser disagreements (paksmith vs. repak) only surface with `--workspace`.

## Pull Requests

- Keep PRs focused — one logical change, under 200 lines when possible.
- PRs must pass CI (check, test, lint on all three platforms).
- Squash merge to `main`.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for module boundaries and design decisions. Follow existing patterns when adding new code. If you need to deviate, explain why in the PR description.

## Reporting Issues

Open a GitHub issue with:

- What you expected to happen.
- What actually happened.
- Steps to reproduce.
- Pak/archive format details if relevant (game, engine version).
