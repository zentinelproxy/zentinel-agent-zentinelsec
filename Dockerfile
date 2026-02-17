# syntax=docker/dockerfile:1.4

# Zentinel ZentinelSec Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-zentinelsec-agent /zentinel-zentinelsec-agent

LABEL org.opencontainers.image.title="Zentinel ZentinelSec Agent" \
      org.opencontainers.image.description="Zentinel ZentinelSec Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-zentinelsec"

ENV RUST_LOG=info,zentinel_zentinelsec_agent=debug \
    SOCKET_PATH=/var/run/zentinel/zentinelsec.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-zentinelsec-agent"]
