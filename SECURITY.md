# Security Policy

## Scope

Paksmith reads and parses binary archive files from potentially untrusted sources. Security-relevant areas include:

- Binary format parsing (buffer overflows, integer overflows, excessive allocations)
- AES decryption key handling
- Network requests to community registries
- File system writes during extraction

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately:

1. **Do not** open a public GitHub issue.
2. Email the maintainers directly (or use GitHub's private vulnerability reporting if enabled on the repository).
3. Include a description of the vulnerability, steps to reproduce, and potential impact.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

Only the latest release on `main` is actively supported with security fixes.

## Security Practices

- `unsafe` code is denied workspace-wide via lint configuration.
- The root workspace's dependencies are subject to `cargo audit`, which the `Security Audit` workflow (`.github/workflows/audit.yml`) runs daily and on every push that changes a `Cargo.toml` or `Cargo.lock`. The `fuzz/` workspace's advisories are checked by `cargo deny` in `.github/workflows/deny.yml`.
- Fuzzing targets for binary parsers will be added as the format handling matures.
- AES keys are never logged. Tracing spans for decryption operations omit key material.
- Network requests use HTTPS exclusively. Registry endpoints validate TLS certificates.
- File extraction respects path boundaries — no path traversal via crafted archive entries. An entry that adds a path component under `--output` naming a Windows reserved device (`NUL`, `CON`, `COM1`, `CONIN$`, …, in any case, with any extension, `:` suffix or trailing spaces) is refused on every platform, in `--dry-run` too, and so is one that holds a control or Unicode Bidi_Control character, or one of U+F001–U+F01F, which Cygwin, MSYS2 and Linux CIFS mounts list as C0 controls. Under `--flat` only the file name is added, so only it is checked.
- **An entry whose parent resolves outside `extract --output` through a symlink is refused, not warned** (issue #723): per entry, unconditionally, with no opt-out. A symlink, FIFO, socket or device node at the destination itself is never written through — refused, or replaced under `--overwrite`. `--output` itself is followed as the caller's spelling, so in a directory others can write to, create it yourself first. Changing the output tree, or anything a link in it resolves through, *during* extraction is out of scope.

## Threat Model

Paksmith is a **user-local CLI**: it parses archive files on behalf of the invoking user and only reads files the user could already read directly. The current threat model does **not** include:

- A daemon or service account ingesting untrusted archives autonomously.
- A multi-tenant environment where one user's archive is parsed in another user's filesystem context.
- An untrusted operator with shell access on the same machine.

The parser is hardened defensively against malformed/adversarial archive *content* (rejecting integer overflows, oversized allocations, unbounded loops, etc.) regardless of source. The threat model expands when Phase 4+ batch/daemon extraction lands; the hardening notes below flag the gates that need to escalate at that point.

## Hardening Notes

Defense-in-depth measures applied at the parser layer that are inert under the current threat model but will become load-bearing at Phase 4+:

- **Embedded NULs rejected in pak FStrings.** UE writers never emit a NUL byte (UTF-8) or `0x0000` code unit (UTF-16) inside an FString/FName payload — they're a path-truncation vector at filesystem boundaries (POSIX `open(2)` truncates at NUL, NTFS preserves; the same crafted name could write to two different files on the two platforms). Currently inert because pak entry filenames are only used as `HashMap` keys, but the wire reader is the right chokepoint to gate before extraction lands. Surfaces as `FStringFault::EmbeddedNul`.
- **Symlinks warned, not rejected, on `PakReader::open`.** A `tracing::warn!` fires when the pak path resolves through a symbolic link, but the open still succeeds. The warn gives operators visibility into symlink-based redirection; the non-rejection keeps legitimate symlink-organized game-asset trees working. When Phase 4+ batch/daemon extraction lands, this should escalate to opt-in (e.g. `--allow-symlinks`) rejection. There is a small TOCTOU window between the `symlink_metadata` check and `File::open`; closing it on Unix would need `O_NOFOLLOW` via `OpenOptionsExt`, accepted as out-of-scope for the current threat model.

## GitHub Apps

paksmith uses installation-scoped GitHub Apps for workflows that need permissions `GITHUB_TOKEN` doesn't grant. The list and rotation procedures below are authoritative; SECURITY.md must be updated in the same PR that changes any App's scope.

### r6e-release-please

A GitHub App installed only on `r6e/paksmith`. `.github/workflows/release.yml` uses [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token) to mint a 1-hour installation token that authenticates the `googleapis/release-please-action` step. The release tag that step creates starts `.github/workflows/release-assets.yml`, which builds the tagged commit and publishes the release. This pattern is in place because the default `GITHUB_TOKEN` cannot create pull requests here (the repository's "Allow GitHub Actions to create and approve pull requests" setting is intentionally off), and an App token is more durable than a PAT and is GitHub's endorsed pattern for 2024+. Background: PR #173.

**Repository permissions**: Contents read+write (release-branch commits, the release tag, the draft release), Pull requests read+write (release PRs), Metadata read (default). The App must not hold the Workflows permission, which would let its token change workflow files.

**Configuration**: `vars.APP_CLIENT_ID` (App Client ID; a non-secret repository variable) and `secrets.RELEASE_APP_PRIVATE_KEY` (App private key, PEM-encoded; a secret of the `release` environment).

- The `release` environment must have **Deployment branches and tags** set to selected branches, with `main` as the only entry. A job reads the key only by naming that environment in a workflow run on `main`. Any workflow on `main` can do that, so the key is guarded as well as `main` is. The environment needs no reviewers or wait timer.
- If the `release` environment is deleted, the next run of `release.yml` recreates it with no branch policy; set the policy again before adding the key.
- The key must not be stored as a repository secret under any name: a workflow run on any ref could read it there. `gh api repos/r6e/paksmith/actions/secrets` lists the repository secrets by name; none may hold the key.
- The App (integration 3727550) must be a bypass actor on the "Release tags" ruleset, which lets it create `v*` tags, and on no other ruleset. `gh api repos/r6e/paksmith/rulesets` lists the rulesets and `gh api repos/r6e/paksmith/rulesets/<id>` shows one's rules and bypass actors. The blast radius below assumes this state; update it whenever a ruleset changes.

**Blast radius if compromised**: an attacker with the App's private key can mint tokens scoped to **Contents + Pull Requests + Metadata on `r6e/paksmith` only**: no other repository, and no direct Issues, Actions, Secrets or Packages access. The worst cases:

- **Unreviewed code on `main`.** The token cannot push to, rewrite or delete `main`, but the "Default Branch" ruleset requires no approving review, so the token can open a pull request and merge it once the required checks pass. Without the Workflows permission it cannot change a workflow file, but it can change the scripts, actions and build code the checks run. Code on `main` ships in the nightlies and the next release and runs with the permissions of `main`'s workflows. It reads this key only through a workflow file that names the `release` environment; whether the token can merge a pull request that changes one is untested.
- **Any other branch.** The token can create, force-push and delete every branch but `main`, including the head branch of an open pull request.
- **A forged or destroyed release.** The token can create a `v*` tag, and the tagged commit's own copy of `release-assets.yml` then builds and publishes it. Its archives can carry valid build-provenance attestations: an attestation records which workflow built an archive, not that the tag was authorized. The token can also publish a release itself, on a `v*` tag or any other new tag, with any files attached. Such a release has no build-provenance attestation, so the README's `gh attestation verify` command rejects its files, but GitHub attests every immutable release, so `gh release verify` accepts it. The token can delete a release, and delete or publish a draft early. The "All Tags" ruleset keeps it from moving or deleting any existing tag. Releases are immutable, so a forged or deleted release uses up its version number for good.

The repository's Activity view and its pull request and release pages show these actions; a personal account has no organization audit log.

#### Rotation procedure

1. Go to **GitHub Settings → Developer settings → GitHub Apps → `r6e-release-please` → General → Private keys**.
2. Click **Generate a private key** — downloads a new `.pem` file.
3. Update the `release` environment's secret `RELEASE_APP_PRIVATE_KEY` (**Repo Settings → Environments → release → Environment secrets → RELEASE_APP_PRIVATE_KEY → Update**) with the full contents of the new `.pem` (including the `-----BEGIN/END RSA PRIVATE KEY-----` lines).
4. Trigger a release-workflow run (merge a release-please PR, or `gh workflow run release.yml`) and verify the `Mint installation token (r6e-release-please App)` step succeeds with the new key. Then confirm no repository secret holds the key (see **Configuration**).
5. Return to the App's **Private keys** page and **Delete** the old key entry.

For a **suspected-leak** rotation, change the order:

1. Generate the new key (step 2) and delete the leaked one at once. GitHub will not delete an App's only key.
2. Suspend the App's installation (**Repo owner Settings → Applications → Installed GitHub Apps → Configure → Suspend**). Deleting a key does not revoke installation tokens already minted with it, which last up to an hour, and a suspension holds only once the leaked key is gone. Keep it suspended for at least an hour: whether an older token works again after an unsuspend is untested.
3. Review what the old key could have done: pull requests and merges to `main`, branches, tags, and releases, drafts included.
4. Store the new key (step 3), unsuspend the installation, and verify (step 4). The release workflow fails while the installation is suspended.

#### When to rotate

- **Immediately** if the private key is suspected leaked (committed to a repo, pasted in a chat, exfiltrated from a backup, etc.).
- **Defensively** if a contributor with access to the App settings or the repository's settings (which include the `release` environment and the rulesets) leaves the project.
- **Annually** as a baseline cadence. Aligns with NIST SP 800-57's 1–2-year ceiling for long-lived asymmetric service-account keys; set a calendar reminder. Rotation takes ~5 minutes following the procedure above.
