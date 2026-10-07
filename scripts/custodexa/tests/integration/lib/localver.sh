# shellcheck shell=bash
# Builder side of "needs: package local-versions": three releases that no registry holds, made
# from the working tree, so a scenario can go between versions this script supports going back
# between. Versions that a published release never takes:
#   1.16.90  the working tree
#   1.16.91  the same source, only the version differs (the same migrations)
#   1.16.92  the working tree with fixtures/rollback-probe-migration.patch: one more migration
#            (it_rollback_probe, which changes nothing), so going to it is an upgrade that changed
#            the database. The patch fails to apply once migrations.go moves on: the build stops
#            and names it.
# For each: the backend and frontend images built from docker/<component>/Dockerfile (target
# production, the backend with the build argument VERSION, so it reports that version), the install
# package by build-package.sh and the offline bundle by build-package.sh offline, both unchanged.
# The images are only on this host: build-package.sh reads registry indexes and manifests, which
# are written here for them (an index naming the image built here for both architectures; only
# this architecture is ever installed), and the offline mode's pull, tag and image rm of them are
# answered here. Everything else goes to the registry-cache shim and on to the real docker.
#
# Results: /it-run/pkg-<version>/ (package, MANIFEST.json, SHA256SUMS), /it-run/bundle-dir-<version>
# (the bundle's folder in the cache), /it-run/local-versions (the versions, one line). The images
# are kept in /cache/local-versions/ under a hash of what goes into them, so a later run with the
# same backend, frontend and Dockerfiles loads them instead of building again.

readonly IT_LV_VERSIONS="1.16.90 1.16.91 1.16.92"
readonly IT_LV_PROBE=1.16.92
readonly IT_LV_REPO=ghcr.io/custodexa-it
readonly IT_LV_PATCH=/src/scripts/custodexa/tests/integration/fixtures/rollback-probe-migration.patch
readonly IT_LV_RELEASED_AT=2026-10-01T00:00:00+00:00
# What the images are built from (paths in the source tree); a change in any of them builds again.
readonly IT_LV_INPUTS="backend frontend docker/backend docker/frontend VERSION LICENSE NOTICE THIRD-PARTY-LICENSES.md licenses .dockerignore"

it_local_versions() {
  local arch=$1 v src
  it_lv_shim
  for v in $IT_LV_VERSIONS; do
    src=$IT_WORK/source
    if [ "$v" = "$IT_LV_PROBE" ]; then
      src=$IT_WORK/source-probe
      rm -rf "$src"
      cp -a "$IT_WORK/source" "$src"
      (cd "$src" && git apply -p1 "$IT_LV_PATCH") || it_die "${IT_LV_PATCH##*/} does not apply to backend/internal/database/migrations.go any more"
    fi
    it_lv_images "$v" "$src" "$arch"
    it_lv_registry "$v"
    it_lv_package "$v" "$src"
    it_bundle "$v" "$arch" "pkg-$v" "bundle-dir-$v" "$IT_WORK/lvbin"
  done
  printf '%s\n' "$IT_LV_VERSIONS" >/it-run/local-versions
}

# it_lv_key <source> <version>: what the images of this version are made of.
it_lv_key() {
  local src=$1 v=$2 p
  local -a in=()
  for p in $IT_LV_INPUTS; do [ ! -e "$src/$p" ] || in+=("$p"); done
  {
    printf 'recipe 1 %s\n' "$v"
    tar -C "$src" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - "${in[@]}" | sha256sum
  } | sha256sum | cut -c1-16
}

# it_lv_images <version> <source> <arch>: the two images, tagged <repo>/<component>:<version>.
it_lv_images() {
  local v=$1 src=$2 arch=$3 key tar c log
  key=$(it_lv_key "$src" "$v")
  tar=/cache/local-versions/$v-$arch-$key.tar
  if [ -f "$tar" ]; then
    docker load -q -i "$tar" >/dev/null || it_die "cannot load $tar"
    it_step "images of $v: loaded from the cache ($key)"
    return 0
  fi
  for c in backend frontend; do
    log=$IT_WORK/build-$c-$v.log
    it_step "build $c $v from the working tree"
    if ! docker build --target production -f "$src/docker/$c/Dockerfile" --build-arg "VERSION=$v" \
      --label "org.custodexa.integration.version=$v" -t "$IT_LV_REPO/$c:$v" "$src" >"$log" 2>&1; then
      tail -n 40 "$log" >&2
      it_die "building $c $v failed"
    fi
  done
  mkdir -p /cache/local-versions
  docker save -o "$tar.tmp-$$" "$IT_LV_REPO/backend:$v" "$IT_LV_REPO/frontend:$v"
  mv -f "$tar.tmp-$$" "$tar"
  it_step "images of $v: built, kept as ${tar##*/}"
}

# it_lv_registry <version>: the index and manifest build-package.sh reads for each image, in
# $IT_WORK/lvreg/<digest>.json. The manifest names the image's config (on the classic store of this
# host the image ID is the config digest) and its size; the index lists that manifest for both
# architectures. Writes $IT_WORK/lv-digests-<version>.json for --digests.
it_lv_registry() {
  local v=$1 c id size m mdig idx idig out='{}'
  mkdir -p "$IT_WORK/lvreg"
  for c in backend frontend; do
    id=$(docker image inspect --format '{{.Id}}' "$IT_LV_REPO/$c:$v")
    size=$(docker image inspect --format '{{.Size}}' "$IT_LV_REPO/$c:$v")
    m=$(jq -cn --arg id "$id" --argjson s "$size" \
      '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
        config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: $id, size: 0},
        layers: [{mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", size: $s}]}')
    mdig=sha256:$(printf '%s' "$m" | sha256sum | cut -d' ' -f1)
    printf '%s' "$m" >"$IT_WORK/lvreg/${mdig#sha256:}.json"
    idx=$(jq -cn --arg m "$mdig" --argjson n "${#m}" \
      '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $m, size: $n,
                     platform: {os: "linux", architecture: "amd64"}},
                    {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $m, size: $n,
                     platform: {os: "linux", architecture: "arm64"}}]}')
    idig=sha256:$(printf '%s' "$idx" | sha256sum | cut -d' ' -f1)
    printf '%s' "$idx" >"$IT_WORK/lvreg/${idig#sha256:}.json"
    out=$(jq --arg c "$c" --arg d "$idig" --arg r "$IT_LV_REPO/$c" '.[$c] = {digest: $d, ghcr: "\($r)@\($d)"}' <<<"$out")
  done
  jq -n --arg v "$v" --argjson i "$out" '{version: $v, images: $i}' >"$IT_WORK/lv-digests-$v.json"
}

# it_lv_shim: $IT_WORK/lvbin/docker, first on PATH for build-package.sh. The registry reads of
# the images built here come from $IT_WORK/lvreg; their pull and tag are no-ops (they are here and
# tagged already); image rm keeps everything (this host saves one architecture, its own); a pull
# of an image this host has by that digest is not repeated. The rest goes to the registry-cache
# shim of build.sh, which hands it on to the real docker.
it_lv_shim() {
  it_docker_shim
  mkdir -p "$IT_WORK/lvbin"
  cat >"$IT_WORK/lvbin/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
next=$IT_WORK/bin/docker
real=$IT_REAL_DOCKER
mine() { [[ \$1 == $IT_LV_REPO/* ]]; }
if [ "\${1:-} \${2:-} \${3:-} \${4:-}" = "buildx imagetools inspect --raw" ] && mine "\${5:-}"; then
  exec cat "$IT_WORK/lvreg/\${5##*@sha256:}.json"
fi
case \${1:-} in
  image) [ "\${2:-}" != rm ] || exit 0 ;;
  pull)
    ref=\${!#}
    if mine "\$ref" || "\$real" image inspect "\$ref" >/dev/null 2>&1; then exit 0; fi
    ;;
  tag) ! mine "\${2:-}" || exit 0 ;;
esac
exec "\$next" "\$@"
EOF
  chmod +x "$IT_WORK/lvbin/docker"
}

# it_lv_package <version> <source>: build-package.sh with the digests of the images built here.
it_lv_package() {
  local v=$1 src=$2 out=/it-run/pkg-$1
  rm -rf "$IT_WORK/out-$v"
  PATH=$IT_WORK/lvbin:$PATH bash /src/scripts/release/build-package.sh --digests "$IT_WORK/lv-digests-$v.json" \
    --source "$src" --out "$IT_WORK/out-$v" --released-at "$IT_LV_RELEASED_AT"
  rm -rf "$out"
  mkdir -p "$out"
  cp "$IT_WORK/out-$v/custodexa-$v.tar.gz" "$IT_WORK/out-$v/MANIFEST.json" "$out/"
  (cd "$out" && sha256sum "custodexa-$v.tar.gz" MANIFEST.json >SHA256SUMS)
  it_step "package $v: $(jq -r '.migrations | length' "$out/MANIFEST.json") migrations, $(cd "$out" && sha256sum "custodexa-$v.tar.gz")"
}
