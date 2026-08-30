#!/usr/bin/env bash
set -euo pipefail

# Keep package scheduling deterministic on shared CI runners. Tests within each
# package retain their normal concurrency; -p=1 only prevents independent test
# binaries from competing for the runner's limited CPU and I/O at once.
log_directory="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
log_file="$(mktemp "${log_directory%/}/hsg-go-test.XXXXXX")"
trap 'rm -f -- "$log_file"' EXIT

if go test -count=1 -p=1 ./... 2>&1 | tee "$log_file"; then
  exit 0
fi

# GitHub's anonymous API exposes check annotations but not job logs. Preserve a
# bounded diagnostic there so a public CI failure remains actionable.
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  diagnostic="$(tail -n 120 "$log_file" | tail -c 16000)"
  diagnostic="${diagnostic//'%'/'%25'}"
  diagnostic="${diagnostic//$'\r'/'%0D'}"
  diagnostic="${diagnostic//$'\n'/'%0A'}"
  printf '::error title=go test failed::%s\n' "$diagnostic"
fi

exit 1
