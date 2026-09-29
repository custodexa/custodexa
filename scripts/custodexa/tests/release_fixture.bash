# A release of six images for the tests that obtain, load and start them: references, tags and
# index digests as the release manifest lists them, one small config and layer per image, what a
# registry pull can fetch (for tests/fakes/daemon-sim), the release manifest itself, and offline
# bundles laid out the way `docker save` writes them on each image store.
# Needs ROOT and BATS_TEST_TMPDIR; call fixture_release in setup, after make_root.

NAMES="backend frontend postgres guacd openssl nginx"
declare -gA REF=([backend]=ghcr.io/custodexa/backend [frontend]=ghcr.io/custodexa/frontend
  [postgres]=docker.io/library/postgres [guacd]=docker.io/guacamole/guacd
  [openssl]=docker.io/alpine/openssl [nginx]=docker.io/library/nginx)
declare -gA TAG=([backend]=1.13.0 [frontend]=1.13.0 [postgres]=16.15-alpine3.24 [guacd]=1.6.0
  [openssl]=3.5.4 [nginx]=1.30.5-alpine3.24)
# Index digests: backend, frontend and guacd are the ones the reviewed screens show.
declare -gA IDX=(
  [backend]=sha256:3f9a00000000000000000000000000000000000000000000000000000000c21e
  [frontend]=sha256:5b0700000000000000000000000000000000000000000000000000000000e911
  [postgres]=sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
  [guacd]=sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f
  [openssl]=sha256:42c7389ef077aed0eb4e96d0abbd094083d701bbaff1313073b061c0c9cd8278
  [nginx]=sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94)
declare -gA CFG=()

# fixture_release: configs and layers under $FIX, the registry contents in $SIM/registry (GHCR and
# the Docker Hub mirror of the own images, the upstream registries), and the release manifest.
fixture_release() {
  FIX=$BATS_TEST_TMPDIR/fix
  mkdir -p "$FIX/blobs" "$ROOT/current/source/backend" "$SIM"
  echo 'package main' >"$ROOT/current/source/backend/main.go"
  local n c
  for n in $NAMES; do
    printf 'layer of %s\n' "$n" >"$FIX/layer-$n"
    c=$(printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
      "$(sha256sum "$FIX/layer-$n" | cut -d' ' -f1)")
    printf '%s' "$c" >"$FIX/config-$n"
    CFG[$n]=sha256:$(sha256sum "$FIX/config-$n" | cut -d' ' -f1)
    printf '%s@%s %s\n' "${REF[$n]}" "${IDX[$n]}" "${CFG[$n]}" >>"$SIM/registry"
  done
  printf '%s@%s %s\n' docker.io/custodexa/backend "${IDX[backend]}" "${CFG[backend]}" \
    docker.io/custodexa/frontend "${IDX[frontend]}" "${CFG[frontend]}" >>"$SIM/registry"
  release_manifest >"$ROOT/current/MANIFEST.json"
}

release_manifest() {
  local n img='{}' e src
  declare -F cx_tree_sha256 >/dev/null || . "$SRC/lib/verify.sh"
  src=$(cx_tree_sha256 "$ROOT/current/source")
  for n in $NAMES; do
    e=$(jq -n --arg r "${REF[$n]}" --arg t "${TAG[$n]}" --arg d "${IDX[$n]}" --arg c "${CFG[$n]}" \
      '{ref: $r, tag: $t, index_digest: $d, platforms: {amd64: {config_digest: $c, size: 1000}}}')
    case $n in
      backend | frontend) e=$(jq --arg m "docker.io/custodexa/$n" '. + {mirror: $m}' <<<"$e") ;;
      *) e=$(jq '. + {upstream: true}' <<<"$e") ;;
    esac
    img=$(jq --arg n "$n" --argjson e "$e" '.[$n] = $e' <<<"$img")
  done
  jq -n --argjson i "$img" --arg s "$src" \
    '{format: 1, version: "1.13.0", images: $i, rollback_compatible: [], source: {path: "source/", sha256: $s}}'
}

# make_bundle <tar> <classic|containerd> [names...]: an offline bundle laid out like `docker save`
# on that store (index.json, manifest.json, blobs/sha256/), with SHA256SUMS next to it.
make_bundle() {
  local tar=$1 style=$2 n d m md lh
  shift 2
  d=$BATS_TEST_TMPDIR/bundle-$style
  rm -rf "$d"
  mkdir -p "$d/blobs/sha256"
  local idx='[]' man='[]'
  local -a list=("$@")
  [ ${#list[@]} -gt 0 ] || read -ra list <<<"$NAMES"
  for n in "${list[@]}"; do
    lh=$(sha256sum "$FIX/layer-$n" | cut -d' ' -f1)
    cp "$FIX/layer-$n" "$d/blobs/sha256/$lh"
    cp "$FIX/config-$n" "$d/blobs/sha256/${CFG[$n]#sha256:}"
    if [ "$style" = containerd ]; then
      m=$(jq -n --arg c "${CFG[$n]}" --arg l "sha256:$lh" \
        '{schemaVersion: 2, mediaType: "application/vnd.docker.distribution.manifest.v2+json",
          config: {mediaType: "application/vnd.docker.container.image.v1+json", digest: $c, size: 100},
          layers: [{mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", digest: $l, size: 10}]}')
    else
      m=$(jq -cn --arg c "${CFG[$n]}" --arg l "sha256:$lh" \
        '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
          config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: $c, size: 100},
          layers: [{mediaType: "application/vnd.oci.image.layer.v1.tar", digest: $l, size: 10}]}')
    fi
    printf '%s' "$m" >"$d/m"
    md=$(sha256sum "$d/m" | cut -d' ' -f1)
    mv "$d/m" "$d/blobs/sha256/$md"
    idx=$(jq -c --arg d "sha256:$md" --arg name "${REF[$n]}:${TAG[$n]}" --arg t "${TAG[$n]}" \
      '. + [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: 500,
             annotations: {"io.containerd.image.name": $name, "org.opencontainers.image.ref.name": $t}}]' <<<"$idx")
    local fam=${REF[$n]#docker.io/}
    fam=${fam#library/}
    man=$(jq -c --arg c "blobs/sha256/${CFG[$n]#sha256:}" --arg t "$fam:${TAG[$n]}" --arg l "blobs/sha256/$lh" \
      '. + [{Config: $c, RepoTags: [$t], Layers: [$l]}]' <<<"$man")
  done
  jq -c '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: .}' <<<"$idx" >"$d/index.json"
  printf '%s' "$man" >"$d/manifest.json"
  echo '{"imageLayoutVersion": "1.0.0"}' >"$d/oci-layout"
  (cd "$d" && tar -cf "$tar" index.json manifest.json oci-layout blobs)
  (cd "$(dirname "$tar")" && sha256sum "$(basename "$tar")" >SHA256SUMS)
}

store() { echo "$1" >"$SIM/store"; }
have() { printf '%s %s\n' "$1" "$2" >>"$SIM/images"; } # <full reference> <id>
down() { printf 'Error response from daemon: Get "https://%s/v2/": dial tcp 10.9.9.9:443: i/o timeout\n' "$1" >"$SIM/down.$1"; }
