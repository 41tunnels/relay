# syntax=docker/dockerfile:1

# Cross-compiles on the native builder arch: Go needs no QEMU, so a
# two-platform build (linux/amd64 + linux/arm64) costs no more than one.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/relay ./cmd/relay

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/41tunnels/relay"
COPY --from=build /out/relay /relay
EXPOSE 8080 9091
USER nonroot:nonroot
# distroless has no shell and no curl: the binary healthchecks itself
# (see cmd/relay/main.go's -healthcheck flag).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/relay", "-healthcheck"]
ENTRYPOINT ["/relay"]
