# APB — two static binaries on a distroless base. No shell, no package
# manager, no interpreter: the image contains the service and nothing else.

# ---------------------------------------------------------------- build ----
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change reuses this layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=2.1.3
ARG COMMIT=""
ARG DATE=""

# CGO stays off: modernc.org/sqlite is pure Go, which is what lets the final
# image be distroless and the binary be trivially cross-compiled.
ENV CGO_ENABLED=0
RUN LDFLAGS="-s -w \
      -X github.com/alexwoo-awso/apb/internal/version.Version=${VERSION} \
      -X github.com/alexwoo-awso/apb/internal/version.Commit=${COMMIT} \
      -X github.com/alexwoo-awso/apb/internal/version.Date=${DATE}" \
 && go build -trimpath -ldflags="$LDFLAGS" -o /out/apbd  ./cmd/apbd \
 && go build -trimpath -ldflags="$LDFLAGS" -o /out/apbctl ./cmd/apbctl

# The data directory is created here with the right ownership so that a fresh
# named volume inherits it and the service can write as a non-root user.
RUN mkdir -p /out/data /out/data/geo && chown -R 65532:65532 /out/data

# --------------------------------------------------------------- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="APB" \
      org.opencontainers.image.description="Shared abuse blocklist for MikroTik RouterOS" \
      org.opencontainers.image.source="https://github.com/alexwoo-awso/apb" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/apbd  /apbd
COPY --from=build /out/apbctl /apbctl
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532
WORKDIR /
VOLUME ["/data"]
EXPOSE 8080

ENV APB_ADDR=:8080 \
    APB_DATA_DIR=/data \
    APB_LOG_FORMAT=json

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/apbd", "-healthcheck"]

ENTRYPOINT ["/apbd"]
