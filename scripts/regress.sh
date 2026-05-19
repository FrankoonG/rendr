#!/usr/bin/env bash
# rendr regression suite entry point.
#
# Usage:
#   ./scripts/regress.sh                  # phase 1 (T1+T2) then phase 2 / T3
#   ./scripts/regress.sh --phase=1        # only phase 1
#   ./scripts/regress.sh --phase=2        # only phase 2 (requires fresh phase-1 state)
#   ./scripts/regress.sh --tier=3         # only T3 (phase-2 gate auto-applied)
#   ./scripts/regress.sh --tier=4         # T4 long-run (release-tag use)
#   ./scripts/regress.sh --tier=5         # T5 TCP fallback (M3-prod/M4 required)
#   ./scripts/regress.sh --full           # phase 1 + phase 2 (all tiers)
#   ./scripts/regress.sh --force-phase2   # local debug only; CI MUST NOT pass this
#
# See docs/regression-suite.md for the design + tier breakdown.
#
# This wrapper just shells out to the regress driver inside the
# submodule. xray-core's heavy dependency tree lives in
# regress/go.mod so the root rendr module stays xray-agnostic.
set -e

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Reports land at <root>/reports/ unless --report-dir is overridden
# by the caller. The driver creates it on demand.
exec_args=(--report-dir="$ROOT/reports")
for arg in "$@"; do
  case "$arg" in
    --report-dir=*) exec_args=("${exec_args[@]/--report-dir=*/$arg}") ;;
    *)              exec_args+=("$arg") ;;
  esac
done

cd "$ROOT/regress"
exec go run ./cmd/regress "${exec_args[@]}"
