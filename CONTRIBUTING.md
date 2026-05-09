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

```
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
