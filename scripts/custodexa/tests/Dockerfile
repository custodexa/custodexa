# Test runner for custodexa.sh: bats, shellcheck and jq on a full Debian userland (GNU coreutils,
# util-linux), the same kind of tools the script meets on a Linux host. BusyBox is not used on
# purpose: its applets differ (mv -T, flock options) and a check could pass there for the wrong reason.
# Pinned 2026-09-29: debian:stable-slim resolved to this index digest.
FROM debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce
RUN apt-get update \
 && apt-get install -y --no-install-recommends bats shellcheck jq util-linux coreutils procps openssl ca-certificates git acl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
