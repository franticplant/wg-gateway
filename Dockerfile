# syntax=docker/dockerfile:1
#
# Targets (build with `--target <name>`; the default, the last stage, is
# "scratch"):
#   scratch      empty image, just the binary           (default)
#   alpine       Alpine with a shell and apk, for debugging
#   ubi          Red Hat UBI 10 rootfs, no shell and no package manager
#   ubi-minimal  Red Hat UBI 10 minimal (shell + microdnf)

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

# All variants run unprivileged: userspace WireGuard needs no TUN device,
# no capabilities and no port below 1024.

FROM alpine:3.24 AS alpine
COPY --from=build /out/wg-gateway /usr/local/bin/wg-gateway
COPY LICENSE THIRD_PARTY_NOTICES.txt /licenses/
USER 65532:65532
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/wg-gateway"]

# Bare UBI: a root filesystem assembled from UBI RPMs (so scanners see the
# RPM database), but with no shell and no package manager inside.
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2 AS ubi-rootfs
RUN microdnf install -y --installroot /rootfs --releasever 10 \
        --config /etc/dnf/dnf.conf --noplugins \
        --setopt=cachedir=/var/cache/dnf --setopt=reposdir=/etc/yum.repos.d \
        --setopt=varsdir=/etc/dnf/vars --setopt=install_weak_deps=0 \
        --nodocs filesystem setup \
    && rm -rf /rootfs/var/cache /rootfs/var/log/* /rootfs/tmp/*

FROM scratch AS ubi
COPY --from=ubi-rootfs /rootfs/ /
COPY --from=build /out/wg-gateway /usr/local/bin/wg-gateway
COPY LICENSE THIRD_PARTY_NOTICES.txt /licenses/
USER 65532:65532
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/wg-gateway"]

FROM registry.access.redhat.com/ubi10/ubi-minimal:10.2 AS ubi-minimal
COPY --from=build /out/wg-gateway /usr/local/bin/wg-gateway
COPY LICENSE THIRD_PARTY_NOTICES.txt /licenses/
USER 65532:65532
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/wg-gateway"]

# Static binary, no TLS or shell needed: an empty image is enough.
FROM scratch AS scratch
COPY --from=build /out/wg-gateway /wg-gateway
COPY LICENSE THIRD_PARTY_NOTICES.txt /licenses/
USER 65532:65532
EXPOSE 51820/udp
ENTRYPOINT ["/wg-gateway"]
