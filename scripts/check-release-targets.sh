#!/usr/bin/env bash
#
# Fails when the three statements of the release build targets disagree:
# the build matrix of release-assets.yml, the build matrix of nightly.yml,
# and the file list in release-assets.yml's publish job.
#
# The lists stay in the workflow files, where only an actor allowed to
# change workflows can edit them and where a dispatch from main can repair
# one for a tag that already exists. This check is what keeps them in step.
#
# Usage, from the repository root (needs yq and jq):
#   scripts/check-release-targets.sh [RELEASE_ASSETS_YML NIGHTLY_YML]
set -euo pipefail

release="${1:-.github/workflows/release-assets.yml}"
nightly="${2:-.github/workflows/nightly.yml}"

# To stderr, so a failure inside a command substitution is still shown.
fail() {
  echo "::error::$1" >&2
  exit 1
}

for tool in yq jq; do
  command -v "${tool}" > /dev/null || fail "this check needs ${tool}"
done

# The `os` and `target` of each build leg, in a canonical order.
matrix() {
  yq -o=json '.jobs.build.strategy.matrix.include' "$1" |
    jq -ceS 'select(type == "array" and length > 0) | map({os, target}) | sort_by(.target)' ||
    fail "$1 has no build matrix to read"
}

release_matrix="$(matrix "${release}")"
nightly_matrix="$(matrix "${nightly}")"
[[ "${release_matrix}" == "${nightly_matrix}" ]] ||
  fail "the build matrices differ: ${release} has ${release_matrix}, ${nightly} has ${nightly_matrix}"

built="$(jq -r '.[].target' <<< "${release_matrix}")"
# The publish job lists its files as `<target>:<archive extension>` words.
published="$(yq '.jobs.publish.steps[].run // ""' "${release}" |
  grep -oE '^ *[a-z0-9_-]+:(tar\.gz|zip)\b' | sed -E 's/^ *//; s/:.*//' | LC_ALL=C sort || true)"
[[ -n "${published}" ]] || fail "${release}'s publish job lists no targets"
[[ "${published}" == "${built}" ]] ||
  fail "${release}'s publish job lists ${published//$'\n'/ }, but its build matrix has ${built//$'\n'/ }"

echo "The release and nightly workflows agree on: ${built//$'\n'/ }"
