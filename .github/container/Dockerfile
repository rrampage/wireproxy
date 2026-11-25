# CI image: packages wireproxy binaries that the container workflow has
# already built with Go (CGO_ENABLED=0), one per target architecture. Nothing
# runs inside the image during the build, so multi-platform builds need no
# emulation. The build context is the workflow's dist/ directory.
#
# The base is pinned to the multi-arch index digest of
# gcr.io/distroless/static-debian13:nonroot.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG TARGETARCH

COPY linux_${TARGETARCH}/wireproxy /usr/bin/wireproxy

VOLUME [ "/etc/wireproxy"]
ENTRYPOINT [ "/usr/bin/wireproxy" ]
CMD [ "--config", "/etc/wireproxy/config" ]

LABEL org.opencontainers.image.title="wireproxy"
LABEL org.opencontainers.image.description="Wireguard client that exposes itself as a socks5 proxy"
LABEL org.opencontainers.image.licenses="ISC"
