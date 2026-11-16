#!/usr/bin/env bash
#
# Fails when the three workflow statements of the release build legs
# disagree: the build matrix of release-assets.yml (runner and target), the
# build matrix of nightly.yml (runner and target), and the targets in the
# file list of release-assets.yml's publish job.
#
# Not checked: the targets the README names, that each archive extension in
# the publish list is the one .github/actions/package gives that runner, and
# anything else that decides what runs (other jobs, `if:` conditions, the
# publish loop's body).
#
# Usage, from the repository root (needs mikefarah's yq v4, and jq):
#   scripts/check-release-targets.sh [RELEASE_ASSETS_YML NIGHTLY_YML]
# The paths are for trying the check against an edited copy.
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

# The runner and target of each build leg, in a canonical order. A matrix
# with any key besides `include` could run legs this does not see.
matrix() {
  yq -o=json '.jobs.build.strategy.matrix' "$1" |
    jq -ce 'select(type == "object" and keys == ["include"]) | .include
      | select(type == "array" and length > 0) | map({os, target})
      | select(all(.[]; (.os | type == "string") and (.target | type == "string" and test("^[a-z0-9_-]+$"))))
      | sort_by(.target)' ||
    fail "$1 could not be read, or its build matrix is not a lone \`include\` list of legs with an \`os\` and a \`target\`"
}

release_matrix="$(matrix "${release}")"
nightly_matrix="$(matrix "${nightly}")"
[[ "${release_matrix}" == "${nightly_matrix}" ]] ||
  fail "the build matrices differ: ${release} has ${release_matrix}, ${nightly} has ${nightly_matrix}"

built="$(jq -r '.[].target' <<< "${release_matrix}")"
# The publish job's one loop: a line starting `for entry in`, through a line
# ending `; do`, whose words are all a bare `<target>:<archive extension>`.
scripts="$(yq '.jobs.publish.steps[].run' "${release}")"
[[ "$(grep -c 'for entry in' <<< "${scripts}")" == 1 ]] ||
  fail "${release}'s publish job needs exactly one \`for entry in\` loop"
loop="$(awk '/^ *for entry in / { on = 1 } on { print } /; do$/ { on = 0 }' <<< "${scripts}")"
entries="$(sed -E 's/^ *for entry in//; s/; do$//; s/ \\$//' <<< "${loop}" | tr -s ' \n' '\n' | sed '/^$/d')"
unread="$(grep -vE '^[a-z0-9_-]+:(tar\.gz|zip)$' <<< "${entries}" || true)"
[[ -z "${unread}" ]] ||
  fail "${release}'s publish loop must start a line with \`for entry in\`, end a line with \`; do\`, and hold only bare \`<target>:<tar.gz|zip>\` words; it has: ${unread//$'\n'/ }"
published="$(cut -d: -f1 <<< "${entries}" | LC_ALL=C sort)"
[[ "${published}" == "${built}" ]] ||
  fail "${release}'s publish loop lists '${published//$'\n'/ }', but its build matrix has '${built//$'\n'/ }'"

echo "The release and nightly workflows agree on: ${built//$'\n'/ }"
