# syntax=docker/dockerfile:1.4

# Sentinel SentinelSec Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-sentinelsec-agent /sentinel-sentinelsec-agent

LABEL org.opencontainers.image.title="Sentinel SentinelSec Agent" \
      org.opencontainers.image.description="Sentinel SentinelSec Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-sentinelsec"

ENV RUST_LOG=info,sentinel_sentinelsec_agent=debug \
    SOCKET_PATH=/var/run/sentinel/sentinelsec.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-sentinelsec-agent"]
