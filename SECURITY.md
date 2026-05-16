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
- All dependencies are subject to `cargo audit`, run automatically on every push/PR via the `Security Audit` job in `.github/workflows/ci.yml`.
- Fuzzing targets for binary parsers will be added as the format handling matures.
- AES keys are never logged. Tracing spans for decryption operations omit key material.
- Network requests use HTTPS exclusively. Registry endpoints validate TLS certificates.
- File extraction respects path boundaries — no path traversal via crafted archive entries.

## GitHub Apps

paksmith uses installation-scoped GitHub Apps for workflows that need permissions `GITHUB_TOKEN` doesn't grant. The list and rotation procedures below are authoritative; SECURITY.md must be updated in the same PR that changes any App's scope.

### paksmith-release-please

A GitHub App installed only on `r6e/paksmith`. `.github/workflows/release.yml` uses [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token) to mint a 1-hour installation token that authenticates the `googleapis/release-please-action` step. This pattern is in place because the default `GITHUB_TOKEN` cannot create pull requests here (the org-wide "Allow GitHub Actions to create and approve pull requests" setting is intentionally off), and an App token is more durable than a PAT and is GitHub's endorsed pattern for 2024+. Background: PR #173.

**Repository permissions**: Contents read+write (release-branch commits), Pull requests read+write (release PRs), Metadata read (default).

**Repo configuration**: `vars.APP_CLIENT_ID` (App Client ID, non-secret), `secrets.APP_PRIVATE_KEY` (App private key, PEM-encoded).

**Blast radius if compromised**: an attacker with `APP_PRIVATE_KEY` can mint tokens scoped to **Contents + Pull Requests + Metadata on `r6e/paksmith` only** — no other repos, no org-wide resources, no Issues/Actions/Secrets/Packages access. Realistic worst case: forged commits to release branches and forged release PRs, both visible in the audit log.

#### Rotation procedure

1. Go to **GitHub Settings → Developer settings → GitHub Apps → `paksmith-release-please` → General → Private keys**.
2. Click **Generate a private key** — downloads a new `.pem` file.
3. Update the repo secret `APP_PRIVATE_KEY` (**Repo Settings → Secrets and variables → Actions → APP_PRIVATE_KEY → Update**) with the full contents of the new `.pem` (including the `-----BEGIN/END RSA PRIVATE KEY-----` lines).
4. Trigger a release-workflow run (merge a release-please PR, or `gh workflow run release.yml`) and verify the `Mint installation token (paksmith-release-please App)` step succeeds with the new key.
5. Return to the App's **Private keys** page and **Delete** the old key entry.

For a **suspected-leak** rotation, swap the order: delete the old key BEFORE installing the new one. This accepts a brief release-workflow outage but closes the attacker's window during the install-verify cycle.

#### When to rotate

- **Immediately** if the private key is suspected leaked (committed to a repo, pasted in a chat, exfiltrated from a backup, etc.).
- **Defensively** if a contributor with access to either the App settings or the repo secrets leaves the project.
- **Annually** as a baseline cadence. Aligns with NIST SP 800-57's 1–2-year ceiling for long-lived asymmetric service-account keys; set a calendar reminder. Rotation takes ~5 minutes following the procedure above.
