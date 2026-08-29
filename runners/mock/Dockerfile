FROM docker.io/library/golang:1.26.7-bookworm@sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514 AS builder

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

COPY go.mod ./
COPY internal/strictjson/decode.go ./internal/strictjson/decode.go
COPY internal/runnerwire/codec.go internal/runnerwire/sequence.go internal/runnerwire/stream.go internal/runnerwire/types.go ./internal/runnerwire/
COPY cmd/mock-runner/main.go ./cmd/mock-runner/main.go

RUN go build -mod=readonly -buildvcs=false -trimpath -ldflags="-s -w" -o /out/mock-runner ./cmd/mock-runner

FROM scratch

LABEL org.opencontainers.image.title="Harness Security Gateway HRP mock runner" \
      org.opencontainers.image.description="Deterministic HRP/1 boundary conformance fixture" \
      org.opencontainers.image.version="0.1.0" \
      io.harness-gateway.hrp.protocol="hrp/1" \
      io.harness-gateway.hrp.adapter.family="mock" \
      io.harness-gateway.hrp.adapter.version="0.1.0"

COPY --from=builder --chown=65532:65532 /out/mock-runner /mock-runner

USER 65532:65532
ENTRYPOINT ["/mock-runner"]
