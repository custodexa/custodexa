#!/usr/bin/env bats
# The release build reads its offline image bundle back with check_bundle before publishing it. A
# check that passes a bundle missing an image, holding other content under a pinned tag, or built
# for the other architecture ships an offline install that fails on site. Two names of the MANIFEST
# share one image (the PostgreSQL client of the bundled database's major is that database image),
# so the bundle holds fewer images than the MANIFEST has names.
# Each case builds a bundle in the layout `docker save` writes (manifest.json, config blobs named
# by the sha256 of their bytes), changes one thing, and expects a failure naming the image.

load helper

setup() {
  BUILD=$(cd "$SRC/../release" && pwd)/build-package.sh
  B=$BATS_TEST_TMPDIR/bundle
  mkdir -p "$B/blobs/sha256"
  INDEX='[]'
  IMAGES='{}'
}

# blob <arch> <seed>: a config naming <arch>; prints its digest (sha256:<hex>).
blob() {
  local f=$BATS_TEST_TMPDIR/cfg hex
  printf '{"architecture":"%s","os":"linux","config":{"Labels":{"seed":"%s"}}}' "$1" "$2" >"$f"
  hex=$(sha256sum "$f" | cut -d' ' -f1)
  mv "$f" "$B/blobs/sha256/$hex"
  printf 'sha256:%s' "$hex"
}

# saved <familiar ref:tag> <config digest>: an image entry of the bundle's manifest.json.
saved() {
  INDEX=$(jq -c --arg t "$1" --arg c "blobs/sha256/${2#sha256:}" '. + [{Config: $c, RepoTags: [$t], Layers: []}]' <<<"$INDEX")
}

# listed <name> <ref> <tag> <amd64 config digest>: an image of the MANIFEST.
listed() {
  IMAGES=$(jq -c --arg n "$1" --arg r "$2" --arg t "$3" --arg d "$4" \
    '.[$n] = {ref: $r, tag: $t, index_digest: "sha256:\("0" * 64)", upstream: true, platforms: {amd64: {config_digest: $d}}}' <<<"$IMAGES")
}

# release: the nine names of a release; pgclient16 and postgres are one image.
release() {
  local d n
  for n in backend frontend; do
    d=$(blob amd64 "$n")
    saved "ghcr.io/custodexa/$n:1.16.0" "$d"
    listed "$n" "ghcr.io/custodexa/$n" 1.16.0 "$d"
  done
  d=$(blob amd64 guacd)
  saved guacamole/guacd:1.6.0 "$d"
  listed guacd docker.io/guacamole/guacd 1.6.0 "$d"
  d=$(blob amd64 nginx)
  saved nginx:1.30.5-alpine3.24 "$d"
  listed nginx docker.io/library/nginx 1.30.5-alpine3.24 "$d"
  d=$(blob amd64 openssl)
  saved alpine/openssl:3.5.4 "$d"
  listed openssl docker.io/alpine/openssl 3.5.4 "$d"
  d=$(blob amd64 pg16)
  saved postgres:16.15-alpine3.24 "$d"
  listed postgres docker.io/library/postgres 16.15-alpine3.24 "$d"
  listed pgclient16 docker.io/library/postgres 16.15-alpine3.24 "$d"
  PG17=$(blob amd64 pg17)
  saved postgres:17.11-alpine3.24 "$PG17"
  listed pgclient17 docker.io/library/postgres 17.11-alpine3.24 "$PG17"
  d=$(blob amd64 pg18)
  saved postgres:18.6-alpine3.24 "$d"
  listed pgclient18 docker.io/library/postgres 18.6-alpine3.24 "$d"
}

# check [arch]: write the bundle and the MANIFEST, run check_bundle on them.
check() {
  printf '%s' "$INDEX" >"$B/manifest.json"
  jq -n --argjson i "$IMAGES" '{format: 1, version: "1.16.0", images: $i}' >"$BATS_TEST_TMPDIR/MANIFEST.json"
  tar -cf "$BATS_TEST_TMPDIR/bundle.tar" -C "$B" manifest.json blobs
  run bash -c '. "$1"; check_bundle "$2" "$3" "$4"' _ "$BUILD" \
    "$BATS_TEST_TMPDIR/bundle.tar" "$BATS_TEST_TMPDIR/MANIFEST.json" "${1:-amd64}"
}

# check_fails <image name> <what the message says>
check_fails() {
  check
  [ "$status" -ne 0 ] || { echo "accepted a bad bundle"; echo "$output"; return 1; }
  [[ $output == *"$1"*"$2"* ]] || { echo "failure does not name '$1' with '$2':"; echo "$output"; return 1; }
}

@test "a bundle of the release's images passes: nine names, eight images" {
  release
  check
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq length "$B/manifest.json")" -eq 8 ]
  local n
  for n in backend frontend guacd nginx openssl postgres pgclient16 pgclient17 pgclient18; do
    [[ $output == *"  $n "* ]] || { echo "no line for $n:"; echo "$output"; return 1; }
  done
}

@test "a bundle without the PostgreSQL 17 client fails and names it" {
  release
  INDEX=$(jq -c 'map(select(.RepoTags != ["postgres:17.11-alpine3.24"]))' <<<"$INDEX")
  check_fails pgclient17 "no single image tagged postgres:17.11-alpine3.24"
}

@test "an image whose config digest is not the MANIFEST's fails and names it" {
  release
  IMAGES=$(jq -c --arg d "sha256:$(printf '%064d' 7)" '.pgclient18.platforms.amd64.config_digest = $d' <<<"$IMAGES")
  check_fails pgclient18 "config digest"
}

@test "an image built for another architecture fails and names it" {
  release
  local d
  d=$(blob arm64 pg17)
  INDEX=$(jq -c --arg c "blobs/sha256/${d#sha256:}" 'map(if .RepoTags == ["postgres:17.11-alpine3.24"] then .Config = $c else . end)' <<<"$INDEX")
  IMAGES=$(jq -c --arg d "$d" '.pgclient17.platforms.amd64.config_digest = $d' <<<"$IMAGES")
  check_fails pgclient17 "is not amd64"
}

@test "two names on one tag with different content fail and name the one the bundle does not hold" {
  release
  # The client of 16 claims the 17 content under the 16 tag: the bundle holds one image for the tag.
  IMAGES=$(jq -c --arg d "$PG17" '.pgclient16.platforms.amd64.config_digest = $d' <<<"$IMAGES")
  check_fails pgclient16 "config digest"
}

@test "an image the MANIFEST does not list fails" {
  release
  saved postgres:15.14-alpine3.24 "$(blob amd64 pg15)"
  check
  [ "$status" -ne 0 ] || { echo "accepted a bad bundle"; echo "$output"; return 1; }
  [[ $output == *"holds 9 images, the MANIFEST lists 8"* ]] || { echo "$output"; return 1; }
}
