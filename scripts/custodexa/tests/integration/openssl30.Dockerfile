# OpenSSL 3.0 for the -saltlen version probe of the encrypt scenario (Alpine 3.17 ships 3.0.x).
# Pinned 2026-10-05: alpine:3.17.10 resolved to this index digest.
FROM alpine:3.17.10@sha256:8fc3dacfb6d69da8d44e42390de777e48577085db99aa4e4af35f483eb08b989
RUN apk add --no-cache openssl \
 && openssl version | grep -q '^OpenSSL 3\.0\.'
ENTRYPOINT ["openssl"]
