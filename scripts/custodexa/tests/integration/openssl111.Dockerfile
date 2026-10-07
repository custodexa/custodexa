# OpenSSL 1.1.1: the oldest line the decryption commands in the operations guide claim to support.
# Alpine 3.15 is the last Alpine release whose openssl package is 1.1.1; its repository stays online.
# Pinned 2026-10-05: alpine:3.15.11 resolved to this index digest.
FROM alpine:3.15.11@sha256:19b4bcc4f60e99dd5ebdca0cbce22c503bbcff197549d7e19dab4f22254dc864
RUN apk add --no-cache openssl \
 && openssl version | grep -q '^OpenSSL 1\.1\.1'
ENTRYPOINT ["openssl"]
