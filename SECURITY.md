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
- Fuzz targets for the parsers and decoders (`fuzz/fuzz_targets/`) run nightly in `.github/workflows/fuzz.yml`.
- AES keys are never logged. Tracing spans for decryption operations omit key material.
- Network requests use HTTPS exclusively. Registry endpoints validate TLS certificates.
- File extraction respects path boundaries — no path traversal via crafted archive entries. An entry that adds a path component under `--output` naming a Windows reserved device (`NUL`, `CON`, `COM1`, `CONIN$`, …, in any case, with any extension, `:` suffix or trailing spaces) is refused on every platform, in `--dry-run` too, and so is one that holds a control or Unicode Bidi_Control character, or one of U+F001–U+F01F, which Cygwin, MSYS2 and Linux CIFS mounts list as C0 controls. Under `--flat` only the file name is added, so only it is checked.
- **An entry whose parent resolves outside `extract --output` through a symlink is refused, not warned** (issue #723): per entry, unconditionally, with no opt-out. A symlink, FIFO, socket or device node at the destination itself is never written through — refused, or replaced under `--overwrite`. `--output` itself is followed as the caller's spelling, so in a directory others can write to, create it yourself first. Changing the output tree, or anything a link in it resolves through, *during* extraction is out of scope.
- **`extract` reads each archive under a read budget** (issue #848). A pak index can give many names to one payload, so extracting every name could read one region once per name. Each entry's first read is charged the part of the archive it can touch, and a read whose charge would take the total past the archive's size, or a read of an entry after its second, is refused: the entry being extracted, or the asset whose companion's read was refused, is reported `FAILED` with a `payload_extent_total` or `entry_reads` error, the rest of the batch continues, and the run exits 1. The other commands and the GUI open archives without the budget.

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
- **A forged or destroyed release.** The token can create a `vX.Y.Z` tag on a commit in `main`'s history and a draft release for it, and the tagged commit's own copy of `release-assets.yml` then builds and attests the archives and publishes the draft. Without the draft the run still builds and attests the archives, and fails only at publishing. Either way the archives carry valid build-provenance attestations: an attestation records which workflow built an archive, not that the tag was authorized. The exception is the workflow's copies before `659ed4b`, the first at `4c617d0`: they neither check that the tagged commit is on `main` nor attest, so a tag on a commit that carries one, or on a branch cut from it, would be built and published unattested (untested). A tag on anything older starts no run. The token can also publish a release itself, on a `v*` tag or any other new tag, with any files attached. The README's `gh attestation verify` command rejects a file of such a release unless it is a byte-for-byte copy of an archive the workflows built and attested. GitHub attests every immutable release, so `gh release verify` accepts the release either way. The token can delete a release, and delete or publish a draft early. The "All Tags" ruleset keeps it from moving or deleting any existing tag. Releases are immutable, so a forged or deleted release uses up its version number for good. Immutability covers a release's tag and files, not its title, its notes or its latest and pre-release marks: the token can change those on any published release, an old one included, for example to add a download link.
- **The App's installation.** The key itself can suspend or uninstall the App's installation through the API, which stops the release workflow.

There is no complete record of these actions: a personal account has no organization audit log. The repository's Activity view shows branch changes, and the pull request, tag and release pages show what still exists, but a deleted release or draft leaves no page behind.

#### Rotation procedure

1. Go to **GitHub Settings → Developer settings → GitHub Apps → `r6e-release-please` → General → Private keys**.
2. Click **Generate a private key** — downloads a new `.pem` file.
3. Update the `release` environment's secret `RELEASE_APP_PRIVATE_KEY` (**Repo Settings → Environments → release → Environment secrets → RELEASE_APP_PRIVATE_KEY → Update**) with the full contents of the new `.pem` (including the `-----BEGIN/END RSA PRIVATE KEY-----` lines).
4. Trigger a release-workflow run (merge a release-please PR, or `gh workflow run release.yml`) and verify the `Mint installation token (r6e-release-please App)` step succeeds with the new key. Then confirm no repository secret holds the key (see **Configuration**).
5. Return to the App's **Private keys** page and **Delete** the old key entry.

For a **suspected-leak** rotation, follow these steps instead. First run `export GH_REPO=r6e/paksmith` in the shell you will use, so that no `gh` command below acts on the repository of whatever directory you are in; run `unset GH_REPO` once you finish:

1. Suspend the App's installation (**Repo owner Settings → Applications → Installed GitHub Apps → Configure → Suspend**). This cuts off installation tokens already minted with the leaked key, which otherwise last up to an hour and survive the key's deletion. The App's own credentials cannot lift a suspension made from this page. The page can show two other states:
   - The installation is already suspended and the page offers no way to change that. The key suspended it through the API and can lift it again, so do steps 2 and 3 now, then return to this page, suspend the installation here if it is active again, and go on to step 4.
   - The App is not listed. The key uninstalled it, which ends its tokens; go on to step 2.
2. Stop the workflows. Suspending the App does not touch a run's `GITHUB_TOKEN`, which GitHub Actions issues itself, so a run can still attest and publish what the attacker put on a tag or on `main`. Disable `release.yml`, `release-assets.yml` and `nightly.yml`, which tag, attest or publish, and `fuzz.yml` (`gh workflow disable <file>`). On `main`, the only workflow token that can enable or dispatch a workflow belongs to `fuzz.yml`'s `housekeeping` job, which runs no repository code, but an older copy of `fuzz.yml` gave such a token to its fuzz job, which runs repository code. The key cannot start a run of an older copy, but a run of one already in progress can: it can dispatch an older copy on another branch, or re-run a run from before the `housekeeping` job existed. GitHub refuses to re-run a disabled workflow's runs, and should refuse to dispatch one too (inferred from its documentation). Then cancel every run that has not completed, repeating until none is listed: `for s in requested queued pending waiting in_progress; do gh run list --status "$s" --limit 1000 --json databaseId --jq '.[].databaseId'; done` and `gh run cancel <id>`. Without `--limit` the listing shows only 20 runs. Last, confirm the four workflows are still disabled (`gh workflow list --all`). If runs keep appearing, or one of the four is enabled again, a run is undoing your work: turn Actions off for the repository (**Repo Settings → Actions → General → Actions permissions**), cancel what is left, disable the four again, then turn Actions back on (untested).
3. Generate the new key (step 2 of the rotation procedure) and delete the leaked one. GitHub will not delete an App's only key. Close off the place the key leaked from as well, or the new key leaks the same way.
4. Review what the leaked key could have done: go through each **Blast radius** bullet, and through what the runs since the leak attested, published or reported. Finish before storing the new key. Reverting a commit is not enough on its own:
   - `release-assets.yml` builds any `vX.Y.Z` tag on `main`'s history, which still holds a reverted commit. Delete every release (drafts included) and `v*` tag that does not belong to a release PR you merged. Delete a published release first and then its tag: GitHub refuses to delete a published release's tag while the release exists. The "All Tags" ruleset lets a repository admin delete a tag (`gh api -X DELETE repos/r6e/paksmith/git/refs/tags/<tag>`).
   - A release PR you merged does not prove its release is yours: the token could have tagged another commit for that version, published the release itself, or pushed to the release PR's branch before you merged it. For each release you keep, check that:
     - the tag (`gh api repos/r6e/paksmith/commits/refs/tags/<tag> --jq .sha`) points at the release PR's merge commit (`gh pr view <number> --json mergeCommit --jq .mergeCommit.oid`), and, for a release PR merged since the leak, that the pull request's diff (`gh pr diff <number>`) changes only the changelogs, `.release-please-manifest.json` and, in `Cargo.toml` and `Cargo.lock`, the workspace crates' own versions and their version requirements on each other;
     - no commit of the attacker's between the previous release's tag and this one is still in effect at the tag (in a clone of `r6e/paksmith`, `git fetch --tags`, then `git log <previous tag>..<tag>`, or `git log <tag>` for the first release): a release cut before the revert still carries it. Such a commit came in through a pull request you did not merge yourself, or was pushed to the head branch of one you did, so read what each merged pull request changed and not only who merged it;
     - the release's files are the three archives and their three `SHA256SUMS-<target>.txt` files, and nothing else;
     - every archive passes the README's `gh attestation verify` command, with `--source-ref refs/heads/main` only for a release whose build you started again from `main` yourself, and each checksum file, which has no attestation of its own, matches its archive (`shasum -a 256 -c`);
     - the title and notes hold nothing the changelogs at the tag do not, such as an added link, the release carries the latest mark only if it is the newest release, and it is marked a pre-release only if it is one.
   - A nightly built from the attacker's code stays downloadable for 30 days, and the README sends readers to the newest successful run. Keep what the investigation needs, then delete the nightly runs that built the attacker's code (`gh run delete <id>`), which removes their archives.
   - Deleting a run or a release leaves its archives' attestations (inferred from GitHub's documentation, untested), so a copy downloaded earlier still passes the README's check. Delete the attestations of those nightly archives, and of archives built for a tag you deleted, under **Actions → Attestations**.
   - release-please treats a merged pull request labelled `autorelease: pending` as a release to tag. List them with `gh pr list --state merged --label "autorelease: pending" --limit 1000 --json number,title,mergedBy` and remove the label from any you did not merge yourself, that is not a release PR, or whose diff fails the release PR check above.
   - Check the head branch of every open pull request, the release PR's included, for commits that are not yours.
   - If any run since the leak ran the attacker's code or a step they changed, whether or not it built anything, delete the Actions caches (`gh cache delete --all`): a later run would restore them. Do this after the attacker's code is off `main`, or the next run saves poisoned caches again.
5. Store the new key (step 3 of the rotation procedure).
6. Unsuspend the installation once it has stayed suspended for an hour after the leaked key's deletion (whether an older token works again after an unsuspend is untested). Lift a suspension you made from the settings page on that page. A suspension the key made can be lifted only from the App's side: sign a JWT with the new key and the App's client ID ([GitHub's guide](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)), read the installation id from `GET /app/installations` with that JWT, and send `DELETE /app/installations/<installation id>/suspended`. If the key uninstalled the App instead (step 1), skip the unsuspend: install the App again on `r6e/paksmith` only and check its ruleset bypass (see **Configuration**).
7. Enable the four workflows again (`gh workflow enable <file>`), and any other that `gh workflow list --all` shows disabled and you did not disable: a run of an older copy of `fuzz.yml` could have disabled one. Verify with `gh workflow run release.yml` (step 4 of the rotation procedure), not by merging a release PR.

#### When to rotate

- **Immediately** if the private key is suspected leaked (committed to a repo, pasted in a chat, exfiltrated from a backup, etc.).
- **Defensively** if a contributor with access to the App settings or the repository's settings (which include the `release` environment and the rulesets) leaves the project.
- **Annually** as a baseline cadence. Aligns with NIST SP 800-57's 1–2-year ceiling for long-lived asymmetric service-account keys; set a calendar reminder. A routine rotation takes ~5 minutes following the procedure above.
