# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/wg-gateway .

# Static binary, no TLS or shell needed: an empty image is enough.
FROM scratch

COPY --from=build /out/wg-gateway /wg-gateway

# Runs unprivileged: userspace WireGuard needs no TUN device, no
# capabilities and no port below 1024.
USER 65532:65532

EXPOSE 51820/udp

ENTRYPOINT ["/wg-gateway"]
