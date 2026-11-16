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
#
# Usage, from the repository root (needs mikefarah's yq v4, and shellcheck):
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

if (($# > 0)); then
  actions=("$@")
else
  actions=()
  while IFS= read -r action; do
    actions+=("${action}")
  done < <(find .github/actions \( -name action.yml -o -name action.yaml \) | LC_ALL=C sort)
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
    [[ "$(yq "${step} | has(\"run\")" "${action}")" == true ]] || continue
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
        shellcheck --norc --shell=bash - <<< "${script}" ||
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
