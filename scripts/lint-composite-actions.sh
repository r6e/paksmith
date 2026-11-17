#!/usr/bin/env bash
#
# Lints the `run` scripts of the composite actions under .github/actions,
# which actionlint does not read:
# - every script fails on a `${{ }}` expression, which GitHub pastes into the
#   script text before the shell runs it; pass the value through `env`
# - every bash script goes through shellcheck
#
# A `pwsh` script gets the expression rule but no linter. Any other shell
# fails the check. Nothing outside `run` is read (`with`, `env`, `if`).
# A symbolic link under .github/actions fails the check, and so does a
# tracked action file anywhere else, where this check would not read it.
#
# Usage, from the repository root (needs git, mikefarah's yq v4, and shellcheck):
#   scripts/lint-composite-actions.sh [ACTION_YML...]
# Paths replace the search, for trying the check against an edited copy.
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 1
}

for tool in yq shellcheck; do
  command -v "${tool}" > /dev/null || fail "this check needs ${tool}"
done
# The Python wrapper around jq is also called yq, and has no `tag`.
[[ "$(yq --null-input '"a" | tag' 2> /dev/null)" == '!!str' ]] ||
  fail "this check needs mikefarah's yq v4, and the yq on PATH is something else"

if (($# > 0)); then
  actions=("$@")
else
  # find does not follow a link, and following one could lead outside the
  # repository, so a link here fails the check rather than hide an action.
  links="$(find .github/actions -type l | LC_ALL=C sort | paste -sd ' ' -)" ||
    fail "could not search .github/actions; run this from the repository root"
  [[ -z "${links}" ]] || fail "symbolic links under .github/actions are not linted; use real files: ${links}"
  # `uses: ./any/path` loads an action from anywhere in the repository.
  stray="$(git ls-files -z -- ':(glob,icase)**/action.yml' ':(glob,icase)**/action.yaml' ':(exclude,glob).github/actions/**' |
    tr '\0' '\n' | paste -sd ' ' -)" || fail "could not list the repository's files"
  [[ -z "${stray}" ]] || fail "action files outside .github/actions are not linted; move them there: ${stray}"
  actions=()
  while IFS= read -r action; do
    actions+=("${action}")
  # `-iname`: the macOS and Windows runners find Action.yml as well.
  done < <(find .github/actions \( -iname action.yml -o -iname action.yaml \) | LC_ALL=C sort)
fi
((${#actions[@]} > 0)) || fail "no action file was found under .github/actions"

failed=0
# Records a failure and carries on, so one run lists every bad step.
report() {
  echo "::error file=$1::$2" >&2
  failed=1
}

checked=0
for action in "${actions[@]}"; do
  # `explode` resolves anchors and merge keys, so no step hides behind one.
  steps="$(yq 'explode(.) | select(.runs.using == "composite") | .runs.steps | select(tag == "!!seq") | length' "${action}" || true)"
  [[ "${steps}" =~ ^[0-9]+$ ]] || {
    report "${action}" "not a composite action with a list of steps, or could not be read"
    continue
  }
  for ((i = 0; i < steps; i++)); do
    step="explode(.) | .runs.steps[${i}]"
    # Anything but one true or false means a step yq does not tag as a
    # map, or a file with several documents; neither may pass unlinted.
    case "$(yq "${step} | select(tag == \"!!map\") | has(\"run\")" "${action}" 2> /dev/null || true)" in
      true) ;;
      false) continue ;;
      *)
        report "${action}" "step ${i} could not be read as a single step"
        continue
        ;;
    esac
    name="$(yq "${step} | .name // \"step ${i}\"" "${action}")"
    shell="$(yq "${step} | .shell // \"\"" "${action}")"
    script="$(yq "${step} | .run" "${action}")"
    # shellcheck disable=SC2016
    if [[ "${script}" == *'${{'* ]]; then
      report "${action}" "'${name}' has a \${{ }} expression in its script; pass the value through env"
    fi
    case "${shell}" in
      bash)
        # `--norc`, as actionlint does: a .shellcheckrc must not relax this.
        # The exclusions are ones actionlint also makes, for what a script
        # alone does not show: a variable the step's `env` sets (SC2153,
        # SC2154) and a file the runner provides for `source` (SC1091). The
        # cost is that a misspelled variable name passes.
        shellcheck --norc --shell=bash --exclude=SC1091,SC2153,SC2154 - <<< "${script}" ||
          report "${action}" "shellcheck findings in '${name}', listed above with line numbers relative to its script"
        checked=$((checked + 1))
        ;;
      pwsh) ;;
      "") report "${action}" "'${name}' has no \`shell\`" ;;
      *) report "${action}" "'${name}' uses shell '${shell}'; this check lints \`bash\` and allows \`pwsh\`" ;;
    esac
  done
done

((failed == 0)) || exit 1
((checked > 0)) || fail "no bash step was found to lint"
echo "shellcheck passed on ${checked} bash steps of ${#actions[@]} composite actions"
