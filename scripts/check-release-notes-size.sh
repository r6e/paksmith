#!/usr/bin/env bash
#
# Fails when the newest section of the changelog is too long to be a
# GitHub release body.
#
# release-please creates the tag and then the draft release, with that
# version's notes as its body, and GitHub refuses a body over 125,000
# characters, so a release PR merged with longer notes leaves a tag
# without a draft. This check is red on such a PR, before the merge.
# The header of .github/workflows/release.yml says how to shorten them.
#
# The notes release-please sends are the ones it wrote into the
# changelog, heading included, so the section stands in for them. It
# keeps its own copy with the release PR and sends that one: editing
# the changelog on the release PR's branch turns this check green and
# shortens nothing. Bytes are counted, which can only overcount
# characters.
#
# Usage, from the repository root:
#   scripts/check-release-notes-size.sh [CHANGELOG]
# No changelog, or one without a version section, passes: there is no
# release to refuse. The path is for trying the check against a copy.
set -euo pipefail
export LC_ALL=C

changelog="${1:-CHANGELOG.md}"
# Keep in step with the notes step of release-assets.yml.
limit=120000

fail() {
  echo "::error::$1" >&2
  exit 1
}

if [[ ! -e "${changelog}" && ! -L "${changelog}" ]]; then
  echo "${changelog} does not exist; nothing to check."
  exit 0
fi
[[ -f "${changelog}" ]] || fail "${changelog} is not a regular file"

# From the first version heading up to the next. The pattern is the one
# the notes step of release-assets.yml ends a section at; keep them in
# step.
size="$(awk '/^## \[?v?[0-9]+\.[0-9]+([^0-9A-Za-z]|$)/ { n++ } n == 1' "${changelog}" | wc -c)"
size="$((size))"
if ((size == 0)); then
  echo "${changelog} has no version section; nothing to check."
  exit 0
fi

((size <= limit)) ||
  fail "the newest section of ${changelog} is ${size} bytes, over the ${limit} a release body can hold: do not merge a release PR in this state, and see the header of .github/workflows/release.yml"
echo "The newest section of ${changelog} is ${size} bytes (limit ${limit})."
