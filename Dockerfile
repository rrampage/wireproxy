# Build on the native builder platform and cross-compile for the target, so
# multi-platform builds don't need QEMU emulation. The Makefile sets
# CGO_ENABLED=0, which the static distroless base image below requires.
FROM --platform=$BUILDPLATFORM docker.io/golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src/wireproxy
COPY . .

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /usr/src/wireproxy/wireproxy /usr/bin/wireproxy

VOLUME [ "/etc/wireproxy"]
ENTRYPOINT [ "/usr/bin/wireproxy" ]
CMD [ "--config", "/etc/wireproxy/config" ]

LABEL org.opencontainers.image.title="wireproxy"
LABEL org.opencontainers.image.description="Wireguard client that exposes itself as a socks5 proxy"
LABEL org.opencontainers.image.licenses="ISC"
