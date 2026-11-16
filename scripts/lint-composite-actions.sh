#!/usr/bin/env bash
#
# Runs shellcheck over the bash `run` scripts of the composite actions in
# .github/actions, which actionlint does not read, and fails on a `run`
# script that holds a `${{ }}` expression: a composite action passes values
# to its scripts through `env`.
#
# Not checked: `pwsh` steps.
#
# Usage, from the repository root (needs mikefarah's yq v4, and shellcheck):
#   scripts/lint-composite-actions.sh [ACTION_YML...]
set -euo pipefail

for tool in yq shellcheck; do
  command -v "${tool}" > /dev/null || {
    echo "::error::this check needs ${tool}" >&2
    exit 1
  }
done

if (($# > 0)); then
  actions=("$@")
else
  actions=(.github/actions/*/action.yml)
fi

failed=0
report() {
  echo "::error file=$1::$2" >&2
  failed=1
}

checked=0
for action in "${actions[@]}"; do
  [[ "$(yq '.runs.using' "${action}")" == composite ]] || {
    report "${action}" "not a composite action, or could not be read"
    continue
  }
  steps="$(yq '.runs.steps | length' "${action}")"
  for ((i = 0; i < steps; i++)); do
    [[ "$(yq ".runs.steps[${i}] | has(\"run\")" "${action}")" == true ]] || continue
    name="$(yq ".runs.steps[${i}].name // \"step ${i}\"" "${action}")"
    shell="$(yq ".runs.steps[${i}].shell" "${action}")"
    script="$(yq ".runs.steps[${i}].run" "${action}")"
    # shellcheck disable=SC2016
    if [[ "${script}" == *'${{'* ]]; then
      report "${action}" "'${name}' has a \${{ }} expression in its script; pass the value through env"
    fi
    case "${shell}" in
      bash)
        # GitHub runs a composite action's bash steps with `-e -o pipefail`.
        shellcheck --shell=bash - <<< "${script}" ||
          report "${action}" "shellcheck findings in '${name}', listed above"
        checked=$((checked + 1))
        ;;
      pwsh) ;;
      *) report "${action}" "'${name}' uses shell '${shell}', which this check cannot lint" ;;
    esac
  done
done

((failed == 0)) || exit 1
((checked > 0)) || {
  echo "::error::no bash step was found to lint" >&2
  exit 1
}
echo "shellcheck passed on ${checked} bash steps of ${#actions[@]} composite actions"
