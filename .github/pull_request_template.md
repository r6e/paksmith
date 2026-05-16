## Summary

<!-- 1-3 sentences on what changed and why. -->

## Linked issue

Closes #

## Test plan

<!--
Per CONTRIBUTING.md, paksmith follows TDD — list the tests added or modified.
For parser changes, call out any cross-parser agreement tests in
`crates/paksmith-fixture-gen/tests/`.
-->

- [ ] New tests added (unit / integration / property)
- [ ] `cargo test --workspace` passes locally (covers cross-parser tests)

## Pre-flight checklist

- [ ] PR title is a Conventional Commit (e.g. `feat(core): ...`, `fix(cli): ...`) — validated by CI
- [ ] Branch name follows `<type>/<kebab-case>` (e.g. `feat/iostore-reader`)
- [ ] `cargo fmt --all` is clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean (mirrors CI)
- [ ] Documentation updated if behavior or public API changed
- [ ] No `unsafe` introduced (workspace lint denies it; if needed, justify here)

## Security considerations

<!-- Required for changes touching: parser code paths, AES key handling, decompression,
     path resolution, or anything reading untrusted bytes.
     Note new attack surface, allocation caps, integer-overflow checks, input validation. -->

## Notes for reviewers

<!-- Optional. Trade-offs, design decisions worth flagging, follow-ups deferred. -->
