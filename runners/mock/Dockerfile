FROM docker.io/library/golang:1.26.10-bookworm@sha256:5b1f78db1f54cc8cb46e652c51d3f854441c4310a449161b6fe9fb553edab505 AS builder

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

COPY go.mod ./
COPY internal/strictjson/decode.go ./internal/strictjson/decode.go
COPY internal/runnerwire/codec.go internal/runnerwire/sequence.go internal/runnerwire/stream.go internal/runnerwire/types.go ./internal/runnerwire/
COPY cmd/mock-runner/main.go ./cmd/mock-runner/main.go

RUN go build -mod=readonly -buildvcs=false -trimpath -ldflags="-s -w" -o /out/mock-runner ./cmd/mock-runner

FROM builder AS new-only-builder

RUN go build -mod=readonly -buildvcs=false -trimpath -ldflags="-s -w -X main.fixedSessionPolicy=new_only" -o /out/mock-runner ./cmd/mock-runner

FROM scratch AS runtime-base

LABEL org.opencontainers.image.title="Harness Security Gateway HRP mock runner" \
      org.opencontainers.image.description="Deterministic HRP/1 boundary conformance fixture" \
      org.opencontainers.image.version="0.1.0" \
      io.harness-gateway.hrp.protocol="hrp/1" \
      io.harness-gateway.hrp.adapter.family="mock" \
      io.harness-gateway.hrp.adapter.version="0.1.0"

USER 65532:65532
ENTRYPOINT ["/mock-runner"]

FROM runtime-base AS new-only

LABEL io.harness-gateway.mock.session-policy="new_only"
COPY --from=new-only-builder --chown=65532:65532 /out/mock-runner /mock-runner

# Keep the default final stage backward-compatible with the resumable mock.
FROM runtime-base AS opaque-resume

COPY --from=builder --chown=65532:65532 /out/mock-runner /mock-runner
