# The integration host: Docker's own dind image plus the userland custodexa.sh expects on a Linux
# host (bash, GNU coreutils and tar, jq, ss). BusyBox applets are kept out of the way on purpose:
# GNU coreutils and util-linux shadow them in /usr/bin, ahead of /bin on PATH.
# Pinned 2026-10-05: docker:29-dind (engine 29.8.1, Alpine 3.24) resolved to this index digest.
FROM docker:29-dind@sha256:3f3c01aaaebf7cce837356b688b7c059a4749f10bd7660dec7c58fc454a283f0
RUN apk add --no-cache bash coreutils util-linux findutils grep sed gawk tar gzip jq procps \
      iproute2-ss curl diffutils ca-certificates openssl \
 && bash --version | head -n1 && tar --version | head -n1 && jq --version
