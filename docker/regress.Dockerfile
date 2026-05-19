# rendr regression suite container.
#
# Build:
#   docker build -f docker/regress.Dockerfile -t rendr-regress:latest .
#
# Run (the host-side scripts/regress.sh wraps this):
#   docker run --rm \
#     --cap-add=NET_ADMIN \
#     --sysctl net.core.rmem_max=8388608 \
#     --sysctl net.core.wmem_max=8388608 \
#     -v "$(pwd)/reports":/out \
#     rendr-regress:latest [--phase=N] [--tier=N] [--full]
#
# Per docs/regression-suite.md §3.1-§3.2 the runtime image needs:
#   - iproute2 + iptables: tc / netns / iptables-j-DROP (G4 + chaos)
#   - procps + coreutils + ca-certificates: shell helpers + TLS
#   - the compiled regress binary
#   - sysctl net.core.rmem_max=8MiB applied at docker run time (the
#     namespace inherits host sysctls, so the host must allow it;
#     scripts/regress.sh checks and warns)

# ---- build stage ----
FROM golang:1.26.3-bookworm AS build

WORKDIR /src

# Copy go.mod / go.sum first so layer cache survives source changes
# that don't touch dependencies. xray-core is in regress/go.mod;
# root rendr deps are in go.mod.
COPY go.mod go.sum ./
COPY regress/go.mod regress/go.sum ./regress/

# Source: root + regress submodule.
COPY . .

# Build the regress driver against the regress submodule's go.mod
# (which has the xray-core dependency). The binary lands at
# /usr/local/bin/regress in the runtime stage.
WORKDIR /src/regress
RUN CGO_ENABLED=0 go build -o /out/regress ./cmd/regress

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        procps \
        coreutils \
        ca-certificates \
        gcc \
        libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the regress binary AND the rendr source tree the binary
# shells out to (T1 invokes `go test ./...` which compiles the
# source at run time). The build-stage golang toolchain is also
# carried over so the runtime can compile.
COPY --from=build /out/regress /usr/local/bin/regress
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /src /workspace
ENV PATH=/usr/local/go/bin:${PATH}
ENV GOPATH=/root/go
ENV GOCACHE=/tmp/go-build

WORKDIR /workspace

# Default args: full default invocation = phase 1 + phase 2 T3.
# Caller overrides with -- --phase=1 etc.
ENTRYPOINT ["/usr/local/bin/regress", "--rendr-root=/workspace", "--report-dir=/out"]
CMD []
