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

## Release-please GitHub App

### What

`paksmith-release-please` is a GitHub App installed only on `r6e/paksmith`. Used by `.github/workflows/release.yml` to mint a 1-hour installation token via [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token), which authenticates the `googleapis/release-please-action` step.

**Repository permissions**:
- Contents: read+write (commits to release branches)
- Pull requests: read+write (opens release PRs)
- Metadata: read (default)

**Repo configuration**:
- `vars.APP_CLIENT_ID` — App Client ID (non-secret)
- `secrets.APP_PRIVATE_KEY` — App private key, PEM-encoded

### Why

The default `GITHUB_TOKEN` cannot create pull requests in this repo (the org-wide "Allow GitHub Actions to create and approve pull requests" setting is intentionally off). A GitHub App token has installation-scoped permissions, is more durable than a personal access token, and is GitHub's endorsed pattern for 2024+. Background: PR #173.

### Blast radius if compromised

An attacker with `APP_PRIVATE_KEY` can mint installation tokens with the App's permission scope above — **Contents + Pull Requests + Metadata on `r6e/paksmith` only**. They cannot:

- Access any other repository (App is installed on this repo only)
- Reach organization-wide resources
- Read/write Issues, Actions, Secrets, Packages, or any other resource not in the scope list

The realistic worst case is forged commits to release branches and forged release PRs, both visible in the audit log.

### Rotation procedure

1. Go to **GitHub Settings → Developer settings → GitHub Apps → `paksmith-release-please` → General → Private keys**.
2. Click **Generate a private key** — downloads a new `.pem` file.
3. Update the repo secret `APP_PRIVATE_KEY` (**Repo Settings → Secrets and variables → Actions → APP_PRIVATE_KEY → Update**) with the full contents of the new `.pem` (including the `-----BEGIN/END RSA PRIVATE KEY-----` lines).
4. Trigger a release-workflow run (merge a release-please PR, or `gh workflow run release.yml`) and verify the `Mints a 1h installation token` step succeeds with the new key.
5. Return to the App's **Private keys** page and **Delete** the old key entry.

### When to rotate

- **Immediately** if the private key is suspected leaked (committed to a repo, pasted in a chat, exfiltrated from a backup, etc.).
- **Defensively** if a contributor with access to either the App settings or the repo secrets leaves the project.
- **Annually** as a baseline cadence. Set a calendar reminder; rotation takes ~5 minutes following the procedure above.
