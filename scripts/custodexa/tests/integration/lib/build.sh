# shellcheck shell=bash
# The builder host (has network access): image tars the cache lacks, then, when a scenario needs
# it, the install package built from the working tree by scripts/release/build-package.sh and the
# offline bundle for this architecture. Writes only under /cache (kept across runs) and /it-run.
#
# The package carries the working tree's scripts, compose files and source; its images are those
# of the published release IT_VERSION (GitHub Release MANIFEST.json, checked against SHA256SUMS),
# so the backend reports that version and install's health check accepts it.

readonly IT_RELEASES=https://github.com/custodexa/custodexa/releases/download
readonly IT_REAL_DOCKER=/usr/local/bin/docker

it_arch() {
  case $(uname -m) in
    x86_64) printf amd64 ;;
    aarch64) printf arm64 ;;
    *) it_die "unsupported architecture $(uname -m)" ;;
  esac
}

it_build() {
  local arch
  arch=$(it_arch)
  [ ! -s /it-run/fetch ] || it_fetch_images "$arch"
  [ -z "${IT_PUBLISHED_VERSION:-}" ] || it_published "$IT_PUBLISHED_VERSION" "$arch"
  [ "${IT_PACKAGE:-0}" = 1 ] || return 0
  it_release_meta "$IT_VERSION"
  it_source_tree
  it_package "$IT_VERSION" pkg
  it_bundle "$IT_VERSION" "$arch" pkg bundle-dir
  # A scenario that goes between versions built here (lib/localver.sh).
  if [ "${IT_LOCAL_VERSIONS:-0}" = 1 ]; then
    # shellcheck source=scripts/custodexa/tests/integration/lib/localver.sh
    . "$IT_DIR/lib/localver.sh"
    it_local_versions "$arch"
  fi
  # A scenario that upgrades also gets a package of an older release, from the same working tree.
  [ -n "${IT_FROM_VERSION:-}" ] || return 0
  it_release_meta "$IT_FROM_VERSION"
  it_package "$IT_FROM_VERSION" pkg-from
  it_bundle "$IT_FROM_VERSION" "$arch" pkg-from bundle-dir-from
  # A scenario that upgrades twice also gets the release before that one.
  [ -n "${IT_FROM2_VERSION:-}" ] || return 0
  it_release_meta "$IT_FROM2_VERSION"
  it_package "$IT_FROM2_VERSION" pkg-from2
  it_bundle "$IT_FROM2_VERSION" "$arch" pkg-from2 bundle-dir-from2
}

# it_fetch_images <arch>: each line of /it-run/fetch is "<ref:tag@digest> <tar>"; pulled by digest
# for this architecture, tagged, saved into the cache.
it_fetch_images() {
  local arch=$1 src tar name tag tmp
  while read -r src tar; do
    name=${src%@*}
    tag=$name
    name=${name%:*}
    it_step "fetch $src"
    docker pull -q --platform "linux/$arch" "$name@${src#*@}" >/dev/null
    docker tag "$name@${src#*@}" "$tag"
    tmp=/cache/images/$tar.tmp-$$
    docker save --platform "linux/$arch" -o "$tmp" "$tag"
    mv -f "$tmp" "/cache/images/$tar"
  done </it-run/fetch
}

# it_release_meta <version>: the release's MANIFEST.json, checked against its SHA256SUMS.
it_release_meta() {
  local v=$1 d=/cache/release/$1 f
  [ -f "$d/MANIFEST.json" ] && return 0
  mkdir -p "$d.tmp-$$"
  for f in MANIFEST.json SHA256SUMS; do
    curl -fsSL --retry 3 -o "$d.tmp-$$/$f" "$IT_RELEASES/v$v/$f" || it_die "cannot download $f of v$v"
  done
  (cd "$d.tmp-$$" && grep ' MANIFEST.json$' SHA256SUMS | sha256sum -c --quiet) || it_die "MANIFEST.json of v$v does not match its SHA256SUMS"
  rm -rf "$d"
  mv "$d.tmp-$$" "$d"
}

# it_published <version> <arch>: the release's own install package and offline bundle as published
# (not built here), each checked against the release's SHA256SUMS; kept in
# /cache/published/<version>-<arch>/ with a SHA256SUMS of the two, for "needs: published".
it_published() {
  local v=$1 arch=$2 d=/cache/published/$1-$2 f
  local -a files=("custodexa-$v.tar.gz" "custodexa-images-$v-$arch.tar")
  if [ -f "$d/SHA256SUMS" ] && (cd "$d" && sha256sum -c --quiet SHA256SUMS); then
    it_step "published release $v ($arch): from the cache"
    return 0
  fi
  rm -rf "$d.tmp-$$"
  mkdir -p "$d.tmp-$$"
  curl -fsSL --retry 3 -o "$d.tmp-$$/SHA256SUMS.release" "$IT_RELEASES/v$v/SHA256SUMS" || it_die "cannot download SHA256SUMS of v$v"
  for f in "${files[@]}"; do
    it_step "download $f of v$v"
    curl -fsSL --retry 3 -o "$d.tmp-$$/$f" "$IT_RELEASES/v$v/$f" || it_die "cannot download $f of v$v"
    grep -E "^[0-9a-f]{64}  $f\$" "$d.tmp-$$/SHA256SUMS.release" >>"$d.tmp-$$/SHA256SUMS" || it_die "SHA256SUMS of v$v does not list $f"
  done
  rm -f "$d.tmp-$$/SHA256SUMS.release"
  (cd "$d.tmp-$$" && sha256sum -c --quiet SHA256SUMS) || it_die "the published files of v$v do not match its SHA256SUMS"
  rm -rf "$d"
  mv "$d.tmp-$$" "$d"
  it_step "published release $v ($arch): $(cd "$d" && sha256sum "custodexa-$v.tar.gz")"
}

# it_source_tree: /it/source, the files git lists for the working tree (tracked and untracked, not
# ignored; run.sh wrote the list), less what the public tree leaves out (scripts/release/
# exclude-list.txt) and less the release tooling build-package.sh refuses to find in a source.
it_source_tree() {
  local p n=0
  # shellcheck source=/dev/null # the release tooling is checked by its own suite
  . /src/scripts/release/lib.sh
  release_load_excludes /src/scripts/release/exclude-list.txt
  rm -rf "$IT_WORK/source"
  mkdir -p "$IT_WORK/source"
  : >"$IT_WORK/source.list"
  while IFS= read -r -d '' p; do
    [ -e "/src/$p" ] || continue
    case $p in
      .env) continue ;;
      scripts/release/build-package.sh | scripts/release/migrations-json.sh) ;;
      scripts/release/*) continue ;;
    esac
    release_is_excluded "$p" && continue
    printf '%s\0' "$p" >>"$IT_WORK/source.list"
    n=$((n + 1))
  done </it-run/source-files
  tar -C /src --null -T "$IT_WORK/source.list" -cf - | tar -C "$IT_WORK/source" -xf -
  it_step "source tree: $n files from the working tree"
}

# The `docker buildx imagetools inspect --raw <ref>@sha256:<d>` calls of build-package.sh are
# answered from /cache/registry when the cached bytes hash to <d> (content addressed, so a stale
# entry cannot exist); anything else goes to the real docker.
it_docker_shim() {
  mkdir -p "$IT_WORK/bin" /cache/registry
  cat >"$IT_WORK/bin/docker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
real=$IT_REAL_DOCKER
if [ "\${1:-} \${2:-} \${3:-} \${4:-}" = "buildx imagetools inspect --raw" ] && [[ \${5:-} == *@sha256:* ]]; then
  want=\${5##*@sha256:}
  f=/cache/registry/\$(printf '%s' "\$5" | tr '/:@' '___').json
  if [ ! -f "\$f" ] || [ "\$(sha256sum <"\$f" | cut -d' ' -f1)" != "\$want" ]; then
    "\$real" "\$@" >"\$f.tmp-\$\$"
    if [ "\$(sha256sum <"\$f.tmp-\$\$" | cut -d' ' -f1)" = "\$want" ]; then
      mv -f "\$f.tmp-\$\$" "\$f"
    else
      cat "\$f.tmp-\$\$"
      rm -f "\$f.tmp-\$\$"
      exit 0
    fi
  fi
  cat "\$f"
  exit 0
fi
exec "\$real" "\$@"
EOF
  chmod +x "$IT_WORK/bin/docker"
}

# it_package <version> <folder>: build-package.sh from the working tree; result in /it-run/<folder>
# with a SHA256SUMS like the release's. The package's image list must equal the release's (the
# PostgreSQL client tool images aside).
it_package() {
  local v=$1 out=/it-run/$2 mf=/cache/release/$1/MANIFEST.json mirror min at
  local -a args=()
  jq '{version, images: (.images | with_entries(select(.key == "backend" or .key == "frontend"))
        | map_values({digest: .index_digest, ghcr: "\(.ref)@\(.index_digest)"}))}' "$mf" >"$IT_WORK/image-digests.json"
  mirror=$(jq -r '.images.backend.mirror // empty' "$mf")
  if [ -n "$mirror" ]; then
    mirror=${mirror#docker.io/}
    args+=(--mirror-namespace "${mirror%/backend}")
  fi
  min=$(jq -er '.min_source_version' "$mf")
  at=$(jq -er '.released_at' "$mf")
  it_docker_shim
  rm -rf "$IT_WORK/out"
  PATH=$IT_WORK/bin:$PATH bash /src/scripts/release/build-package.sh --digests "$IT_WORK/image-digests.json" \
    --source "$IT_WORK/source" --out "$IT_WORK/out" --min-source "$min" --released-at "$at" ${args[@]+"${args[@]}"}
  # The PostgreSQL clients are tool images a release before them does not list; the rest must match.
  [ "$(jq -cS '.images | with_entries(select(.key | test("^pgclient[0-9]+$") | not))' "$IT_WORK/out/MANIFEST.json")" \
    = "$(jq -cS '.images | with_entries(select(.key | test("^pgclient[0-9]+$") | not))' "$mf")" ] ||
    it_die "the package's image list differs from the v$v release's"
  rm -rf "$out"
  mkdir -p "$out"
  cp "$IT_WORK/out/custodexa-$v.tar.gz" "$IT_WORK/out/MANIFEST.json" "$out/"
  (cd "$out" && sha256sum "custodexa-$v.tar.gz" MANIFEST.json >SHA256SUMS)
  it_step "package: $(cd "$out" && sha256sum "custodexa-$v.tar.gz")"
}

# it_bundle <version> <arch> <package folder> <note> [docker folder]: the offline bundle, kept in the
# cache under the hash of the image list (it holds images only, so the working tree does not change
# it). /it-run/<note> names it. With a docker folder, its docker comes first on PATH (localver.sh).
it_bundle() {
  local v=$1 arch=$2 mf=/it-run/$3/MANIFEST.json note=/it-run/$4 bin=${5:-} key dir file tmp
  key=$(jq -cS .images "$mf" | sha256sum | cut -c1-16)
  dir=$v-$arch-$key
  file=custodexa-images-$v-$arch.tar
  if [ "${IT_REBUILD_BUNDLE:-0}" = 1 ] || [ ! -f "/cache/bundles/$dir/$file" ]; then
    tmp=/cache/bundles/.tmp-$dir-$$
    mkdir -p /cache/bundles
    rm -rf "$tmp"
    PATH=${bin:+$bin:}$PATH bash /src/scripts/release/build-package.sh offline --manifest "$mf" --arch "$arch" --out "$tmp"
    (cd "$tmp" && sha256sum "$file" >SHA256SUMS)
    rm -rf "/cache/bundles/$dir"
    mv "$tmp" "/cache/bundles/$dir"
  fi
  printf '%s\n' "$dir" >"$note"
  it_step "offline bundle: $dir/$file"
}
