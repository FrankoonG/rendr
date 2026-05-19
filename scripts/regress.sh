#!/usr/bin/env bash
# rendr regression suite entry point.
#
# Default behavior: build the regress docker image (if absent) and
# run the suite inside it. Per docs/regression-suite.md §3 the
# canonical runtime is a Linux container; the suite uses iptables,
# tc, and the rendr engine's Linux-only -race / bench targets.
#
# Usage:
#   ./scripts/regress.sh                  # docker run, default = phase 1 + phase 2 / T3
#   ./scripts/regress.sh --phase=1        # only phase 1
#   ./scripts/regress.sh --phase=2        # only phase 2 (T3 default)
#   ./scripts/regress.sh --tier=3         # only T3
#   ./scripts/regress.sh --tier=4         # T4 long-run (release-tag use)
#   ./scripts/regress.sh --full           # phase 1 + all of phase 2
#   ./scripts/regress.sh --local          # bypass docker; run go directly (dev only)
#   ./scripts/regress.sh --rebuild-image  # docker build --no-cache before run
#
# The image lands as rendr-regress:latest; rebuild when source or
# docker/regress.Dockerfile changes.
set -e

# ---- find repo root ----
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# ---- parse our wrapper-level flags + pass-through ----
LOCAL_MODE=0
REBUILD_IMAGE=0
passthrough=()
for arg in "$@"; do
  case "$arg" in
    --local)         LOCAL_MODE=1 ;;
    --rebuild-image) REBUILD_IMAGE=1 ;;
    *)               passthrough+=("$arg") ;;
  esac
done

mkdir -p "$ROOT/reports"

# ---- --local: bypass docker, run go directly ----
if [ "$LOCAL_MODE" = "1" ]; then
  cd "$ROOT/regress"
  exec go run ./cmd/regress --report-dir="$ROOT/reports" "${passthrough[@]}"
fi

# ---- containerized run (default) ----
if ! command -v docker >/dev/null 2>&1; then
  echo "scripts/regress.sh: docker not found." >&2
  echo "Either install docker, or pass --local to run the suite directly" >&2
  echo "via 'go run' (dev only; some tier1/tier2 cases need Linux)." >&2
  exit 50
fi

IMAGE_TAG="${REGRESS_IMAGE:-rendr-regress:latest}"

needs_build=0
if [ "$REBUILD_IMAGE" = "1" ]; then
  needs_build=1
elif ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  needs_build=1
fi

if [ "$needs_build" = "1" ]; then
  echo "==> docker build $IMAGE_TAG"
  build_args=(build -f docker/regress.Dockerfile -t "$IMAGE_TAG")
  if [ "$REBUILD_IMAGE" = "1" ]; then
    build_args+=(--no-cache)
  fi
  build_args+=(.)
  docker "${build_args[@]}"
fi

echo "==> docker run $IMAGE_TAG ${passthrough[*]}"
exec docker run --rm \
    --cap-add=NET_ADMIN \
    --sysctl net.core.rmem_max=8388608 \
    --sysctl net.core.wmem_max=8388608 \
    -v "$ROOT/reports":/out \
    "$IMAGE_TAG" \
    "${passthrough[@]}"
