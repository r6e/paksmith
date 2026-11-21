#!/usr/bin/env bash
#
# Fails when the statements of what a release holds disagree:
# - the build legs: the build matrix of release-assets.yml (runner and
#   target), the build matrix of nightly.yml (runner and target), and the
#   file list of release-assets.yml's publish job (target and archive
#   extension, the extension being the one .github/actions/package gives
#   the leg's runner);
# - the README: every archive it names as `paksmith-v<version>-<name>`
#   (the version being digits or `X.Y.Z`) and every `SHA256SUMS-<name>`,
#   which must be the release's files, each named at least once; and every
#   `target=` line that gives a bare target.
#
# Not checked: anything else that decides what runs (other jobs, `if:`
# conditions, the publish loop's body, the rest of the package action),
# where in the README a name stands, or a target or archive the README
# writes in another form.
#
# Usage, from the repository root (needs mikefarah's yq v4, and jq):
#   scripts/check-release-targets.sh [RELEASE_ASSETS_YML NIGHTLY_YML README PACKAGE_ACTION_YML]
# The paths are for trying the check against an edited copy.
set -euo pipefail
# One order for every `sort`, and ASCII ranges in every pattern.
export LC_ALL=C

release="${1:-.github/workflows/release-assets.yml}"
nightly="${2:-.github/workflows/nightly.yml}"
readme="${3:-README.md}"
package="${4:-.github/actions/package/action.yml}"

# To stderr, so a failure inside a command substitution is still shown.
fail() {
  echo "::error::${1//[[:cntrl:]]/ }" >&2
  exit 1
}

for tool in yq jq; do
  command -v "${tool}" > /dev/null || fail "this check needs ${tool}"
done

# The runner and target of each build leg, in a canonical order. Anything
# else in the job could build a leg, a runner or a file name this does not
# see: a second YAML document, a matrix key besides `include`, a `runs-on`
# or a package `target` that is not the matrix's, or an `os` whose
# operating system the label does not give.
matrix() {
  [[ "$(yq ea '[.] | length' "$1")" == 1 ]] || fail "$1 could not be read as one YAML document"
  yq -o=json '.jobs.build' "$1" |
    jq -ce 'select(.["runs-on"] == "${{ matrix.os }}")
      | select([.steps[] | select(.uses == "./.github/actions/package") | .with.target] == ["${{ matrix.target }}"])
      | .strategy.matrix
      | select(type == "object" and keys == ["include"]) | .include
      | select(type == "array" and length > 0) | map({os, target})
      | select(all(.[]; (.os | type == "string" and test("\\A(ubuntu|macos|windows)-[a-z0-9.-]+\\z"))
          and (.target | type == "string" and test("\\A[a-z0-9_-]+\\z"))))
      | select((map(.target) | unique | length) == length)
      | sort_by(.target)' ||
    fail "$1's build job is not one this check can read: it must run on \`\${{ matrix.os }}\`, pass \`\${{ matrix.target }}\` to ./.github/actions/package once, and have a matrix that is a lone \`include\` list of legs, each with its own \`target\` and an \`os\` label starting ubuntu-, macos- or windows-"
}

release_matrix="$(matrix "${release}")"
nightly_matrix="$(matrix "${nightly}")"
[[ "${release_matrix}" == "${nightly_matrix}" ]] ||
  fail "the build matrices differ: ${release} has ${release_matrix}, ${nightly} has ${nightly_matrix}"

built="$(jq -r '.[].target' <<< "${release_matrix}")"

# What each leg uploads, as `<target>:<archive extension>`. The extension
# rule and the file names are the package action's, restated: its own
# lines are pinned so that they change together.
ext_rule="\${{ runner.os == 'Windows' && 'zip' || 'tar.gz' }}"
[[ "$(yq '[.runs.steps[] | select(.id == "names")] | length' "${package}")" == 1 ]] ||
  fail "${package} could not be read, or has no one step with \`id: names\`, which this check reads the EXT rule and the file names from"
ext="$(yq '.runs.steps[] | select(.id == "names") | .env.EXT' "${package}")"
[[ "${ext}" == "${ext_rule}" ]] ||
  fail "${package} sets EXT to '${ext}'; this check assumes '${ext_rule}', so change ${0##*/} with it wherever it names an extension"
naming="$(yq '.runs.steps[] | select(.id == "names") | .run' "${package}" | sed -E 's/^ +//')"
# shellcheck disable=SC2016 # the action's own text, not this script's variables
for line in 'staging="paksmith-${LABEL}-${TARGET}"' 'echo "archive=${staging}.${EXT}"' 'echo "checksums=SHA256SUMS-${TARGET}.txt"'; do
  grep -qxF -- "${line}" <<< "${naming}" ||
    fail "${package}'s \`names\` step has no line '${line}'; this check, the publish job and the README assume it, so change them with it"
done
expected="$(jq -r '.[] | "\(.target):\(if .os | startswith("windows") then "zip" else "tar.gz" end)"' <<< "${release_matrix}" | sort)"

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
listed="$(sort <<< "${entries}")"
[[ "${listed}" == "${expected}" ]] ||
  fail "${release}'s publish loop lists '${listed//$'\n'/ }', but its build matrix's runners produce '${expected//$'\n'/ }'"

# The README's names for the release files, each compared as a set: a name
# counts wherever it stands, and a full stop ending a sentence is dropped.
# A bare target after the version is the directory an archive unpacks to.
# The README's `target=` lines need only name built targets; a value that
# is not a bare target, quoted or not, is another form.
[[ -r "${readme}" ]] || fail "${readme} could not be read"
readme_names() {
  grep -aoE "$1[A-Za-z0-9_.-]+" "${readme}" | sed -E "s/^$1//; s/\.+\$//" | sort -u || true
}
archives="$(readme_names 'paksmith-v([0-9]+\.[0-9]+\.[0-9]+|X\.Y\.Z)-' | grep -vxF -- "${built}" || true)"
release_archives="$(sed -E 's/:/./' <<< "${expected}" | sort)"
[[ "${archives}" == "${release_archives}" ]] ||
  fail "${readme} names, after \`paksmith-vX.Y.Z-\` or a numeric version, the archives '${archives//$'\n'/ }', but a release holds '${release_archives//$'\n'/ }'"
summed="$(readme_names 'SHA256SUMS-')"
release_sums="$(sed -E 's/$/.txt/' <<< "${built}" | sort)"
[[ "${summed}" == "${release_sums}" ]] ||
  fail "${readme} names, after \`SHA256SUMS-\`, the files '${summed//$'\n'/ }', but a release holds '${release_sums//$'\n'/ }'"
unbuilt="$(grep -aE '^[[:space:]]*(export[[:space:]]+)?target=' "${readme}" | tr -d '\r' |
  sed -E 's/^[^=]*=//; s/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/' |
  grep -E '^[a-z0-9_]+(-[a-z0-9_]+)+$' | grep -vxF -- "${built}" || true)"
[[ -z "${unbuilt}" ]] ||
  fail "${readme} has a \`target=\` line for '${unbuilt//$'\n'/ }', but the workflows build '${built//$'\n'/ }'"

echo "The workflows and ${readme} agree on the release files (${expected//$'\n'/ })"
