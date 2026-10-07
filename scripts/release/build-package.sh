#!/usr/bin/env bash
# build-package.sh: assemble the install package and its MANIFEST.json for one release.
#
#   build-package.sh --digests image-digests.json --source <public tree> --out <dir>
#                    [--min-source 1.12.4] [--released-at <ISO time>] [--mirror-namespace <ns>]
#                    [--notes <json file>]
#                    [--rollback-compatible <version>[,<version>...] --rehearsals-dir <dir>]
#   build-package.sh offline --manifest MANIFEST.json --arch <amd64|arm64> --out <dir>
#
# Output in <dir>: custodexa-<version>.tar.gz and MANIFEST.json (the same bytes as the copy
# inside the package). The package unpacks to custodexa/, which is a deployment root:
#
#   custodexa/custodexa.sh -> current/custodexa.sh
#   custodexa/current      -> releases/<version>
#   custodexa/releases/<version>/  custodexa.sh lib/ lang/ VERSION MANIFEST.json compose*.yml
#                                  .env.example reverse-proxy/ source/
#
# image-digests.json comes from the publish job of the release workflow. Platform config digests
# and sizes are read with `docker buildx imagetools inspect --raw`, so the host needs registry
# access. --source must be the public tree of the same commit; a tree holding private working
# files is refused. Needs GNU tar, gzip, jq, sha256sum.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=scripts/custodexa/lib/verify.sh
. "$repo/scripts/custodexa/lib/verify.sh"

die() { echo "build-package: $*" >&2; exit 1; }

# ---- offline mode ----
#   build-package.sh offline --manifest MANIFEST.json --arch <amd64|arm64> --out <dir>
# Writes <dir>/custodexa-images-<version>-<arch>.tar: every image of the MANIFEST, pulled by its
# index digest for linux/<arch>, tagged <ref>:<tag> and saved with `docker save --platform`.
# The file is then read back and must hold exactly those tags, each with the config digest the
# MANIFEST lists for <arch> and a config that names <arch>. Needs docker (save --platform) and jq.
# Local copies of these images are removed before each pull: run it on a build host, not a deployment.

# familiar <ref>: the name docker writes into a saved bundle (docker.io/library/x -> x).
familiar() {
  local r=${1#docker.io/}
  printf '%s' "${r#library/}"
}

# check_bundle <tar> <MANIFEST.json> <arch>: the bundle holds the MANIFEST's images and nothing else.
# Two names of the MANIFEST may share one image (a PostgreSQL client is the database image of its
# version): the bundle holds it once, and both names must find the same config in it.
check_bundle() {
  local tar=$1 manifest=$2 arch=$3 index name ref tag cfg entry got want distinct
  index=$(tar -xOf "$tar" manifest.json) || die "$tar has no manifest.json"
  for name in $(jq -r '.images | keys[]' "$manifest"); do
    ref=$(jq -r --arg n "$name" '.images[$n].ref' "$manifest")
    tag=$(jq -r --arg n "$name" '.images[$n].tag' "$manifest")
    want=$(jq -r --arg n "$name" --arg a "$arch" '.images[$n].platforms[$a].config_digest' "$manifest")
    entry=$(jq -c --arg t "$(familiar "$ref"):$tag" '[.[] | select(.RepoTags | index($t))] | if length == 1 then .[0] else empty end' <<<"$index")
    [ -n "$entry" ] || die "$tar: $name: no single image tagged $(familiar "$ref"):$tag"
    cfg=$(jq -r '.Config' <<<"$entry")
    got=${cfg##*/}
    got=sha256:${got%.json}
    [ "$got" = "$want" ] || die "$tar: $name config digest $got, MANIFEST $arch lists $want"
    [ "$(tar -xOf "$tar" "$cfg" | jq -r '.architecture')" = "$arch" ] || die "$tar: $name is not $arch"
    printf '  %-10s %s:%s %s\n' "$name" "$(familiar "$ref")" "$tag" "$got"
  done
  distinct=$(jq '[.images[] | "\(.ref):\(.tag)"] | unique | length' "$manifest")
  [ "$(jq 'length' <<<"$index")" -eq "$distinct" ] \
    || die "$tar holds $(jq 'length' <<<"$index") images, the MANIFEST lists $distinct"
}

offline() {
  local manifest="" arch="" out="" version name ref tag digest final
  local -a tags=()
  while [ $# -gt 0 ]; do
    case $1 in
      --manifest) manifest=${2:-} ;;
      --arch) arch=${2:-} ;;
      --out) out=${2:-} ;;
      *) die "offline: unknown argument: $1" ;;
    esac
    shift 2
  done
  [ -f "$manifest" ] || die "offline: --manifest <MANIFEST.json> is required"
  case $arch in amd64 | arm64) ;; *) die "offline: --arch must be amd64 or arm64" ;; esac
  [ -n "$out" ] || die "offline: --out <dir> is required"
  version=$(jq -er '.version' "$manifest") || die "offline: MANIFEST has no version"
  final=$out/custodexa-images-$version-$arch.tar
  [ -e "$final" ] && die "offline: $final exists"
  mkdir -p "$out"
  for name in $(jq -r '.images | keys[]' "$manifest"); do
    ref=$(jq -er --arg n "$name" '.images[$n].ref' "$manifest")
    tag=$(jq -er --arg n "$name" '.images[$n].tag' "$manifest")
    digest=$(jq -er --arg n "$name" '.images[$n].index_digest' "$manifest")
    # A name sharing its image with one pulled already (a PostgreSQL client): saved once.
    [[ " ${tags[*]+"${tags[*]}"} " != *" $ref:$tag "* ]] || continue
    # A classic image store keeps one platform per repository digest and refuses to pull a second
    # one over it ("cannot overwrite digest"), so a copy left by the other architecture goes first.
    docker image rm "$ref:$tag" "$ref@$digest" >/dev/null 2>&1 || true
    docker pull -q --platform "linux/$arch" "$ref@$digest" >/dev/null || die "offline: cannot pull $ref@$digest for $arch"
    docker tag "$ref@$digest" "$ref:$tag"
    tags+=("$ref:$tag")
  done
  offline_tmp=$final.tmp-$$
  trap 'rm -f "$offline_tmp"' EXIT
  docker save --platform "linux/$arch" -o "$offline_tmp" "${tags[@]}" || die "offline: docker save failed"
  echo "build-package: offline bundle $arch, read back:"
  check_bundle "$offline_tmp" "$manifest" "$arch"
  mv -f "$offline_tmp" "$final"
  echo "build-package: $final"
}
# Sourced (the tests call check_bundle directly): the functions only.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
if [ "${1:-}" = offline ]; then
  shift
  offline "$@"
  exit 0
fi

digests="" source="" out="" min_source=1.12.4 released_at="" mirror_ns="" notes="" rollback_compat="" rehearsals_dir=""
while [ $# -gt 0 ]; do
  case $1 in
    --digests) digests=${2:-} ;;
    --source) source=${2:-} ;;
    --out) out=${2:-} ;;
    --min-source) min_source=${2:-} ;;
    --released-at) released_at=${2:-} ;;
    --mirror-namespace) mirror_ns=${2:-} ;;
    --notes) notes=${2:-} ;;
    --rollback-compatible) rollback_compat=${2:-} ;;
    --rehearsals-dir) rehearsals_dir=${2:-} ;;
    -h | --help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift 2
done
[ -f "$digests" ] || die "--digests <image-digests.json> is required"
[ -d "$source" ] || die "--source <public tree> is required"
[ -n "$out" ] || die "--out <dir> is required"
[ -e "$out" ] && die "output folder exists, refusing to mix with old files: $out"

semver='^[0-9]+\.[0-9]+\.[0-9]+$'
version=$(jq -er '.version' "$digests") || die "image-digests.json has no version"
[[ $version =~ $semver ]] || die "not a release version: $version"
[[ $min_source =~ $semver ]] || die "not a version: $min_source"
[ -n "$released_at" ] || released_at=$(date '+%Y-%m-%dT%H:%M:%S%:z')
if [ -n "$notes" ]; then
  jq -e 'type == "object" and all(.[]; type == "array")' "$notes" >/dev/null || die "--notes must map language -> list"
fi

# The package ships the public tree only. In the public tree this folder holds only this script
# and the migration reader it sources; a tree with more there, or with a live .env, is a working
# tree and is refused.
[ -e "$source/.env" ] && die "--source holds .env: that is not the public tree"
for f in "$source"/scripts/release/* "$source"/scripts/release/.[!.]*; do
  [ -e "$f" ] || continue
  case ${f##*/} in
    build-package.sh | migrations-json.sh) ;;
    *) die "--source is not the public tree (it holds scripts/release/${f##*/})" ;;
  esac
done

sha_re='^sha256:[0-9a-f]{64}$'
own_digest() { # <component>
  local d
  d=$(jq -er --arg c "$1" '.images[$c].digest' "$digests") || die "image-digests.json lacks images.$1.digest"
  [[ $d =~ $sha_re ]] || die "bad digest for $1: $d"
  printf '%s' "$d"
}
own_repo() { # <component>: the GHCR repository the workflow published to (namespace may vary)
  local r
  r=$(jq -er --arg c "$1" '.images[$c].ghcr' "$digests") || die "image-digests.json lacks images.$1.ghcr"
  r=${r%@*}
  [[ $r =~ ^ghcr\.io/[a-z0-9._/-]+/$1$ ]] || die "unexpected GHCR reference for $1: $r"
  printf '%s' "$r"
}
# One assignment per line: in `a=$(x) b=$(y)` a failing x does not stop the script.
backend_digest=$(own_digest backend)
frontend_digest=$(own_digest frontend)
backend_repo=$(own_repo backend)
frontend_repo=$(own_repo frontend)

# ---- rollback_compatible: earlier versions this release may go straight back to ----
# Each one needs the record of a rehearsal of exactly these images (<this>-from-<earlier>.txt in the
# folder --rehearsals-dir names; without that folder no version is listed): the first line PASS, then one "key: value" per line, each key
# once and none empty. A listed version lets a deployment whose database this release changed go
# back without a restore, so a record that is incomplete or tested other images stops the build.
rehearsal_keys="date operator from to to_backend_digest to_frontend_digest step1_upgrade step2_write step3_rollback step4_old_readwrite"
version_lt() { # <a> <b>: a is older than b
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]
}
check_rehearsal() { # <earlier version>
  local from=$1 file key line val n=0
  local -A seen=()
  file=$rehearsals_dir/$version-from-$from.txt
  [ -f "$file" ] || die "--rollback-compatible $from: no rehearsal record $file"
  [ "$(head -n 1 "$file")" = PASS ] || die "$file: the first line is not PASS"
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ "$n" -gt 1 ] && [ -n "$line" ] || continue
    [[ $line =~ ^([a-z0-9_]+):\ ?(.*)$ ]] || die "$file: line $n is not \"key: value\""
    key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
    [[ " $rehearsal_keys " == *" $key "* ]] || die "$file: unknown field $key"
    [ -z "${seen[$key]+x}" ] || die "$file: field $key appears twice"
    seen[$key]=$val
  done <"$file"
  for key in $rehearsal_keys; do
    [ -n "${seen[$key]:-}" ] || die "$file: field $key is missing or empty"
  done
  [[ ${seen[date]} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "$file: field date is not YYYY-MM-DD"
  [ "${seen[from]}" = "$from" ] || die "$file: field from is ${seen[from]}, the build lists $from"
  [ "${seen[to]}" = "$version" ] || die "$file: field to is ${seen[to]}, this build is $version"
  for key in step1_upgrade step2_write step3_rollback step4_old_readwrite; do
    [[ ${seen[$key]} == "PASS "* ]] || die "$file: field $key does not start with PASS"
  done
  [ "${seen[to_backend_digest]}" = "$backend_digest" ] \
    || die "$file: field to_backend_digest is not the backend image of this build ($backend_digest)"
  [ "${seen[to_frontend_digest]}" = "$frontend_digest" ] \
    || die "$file: field to_frontend_digest is not the frontend image of this build ($frontend_digest)"
}
compat_json='[]'
if [ -n "$rollback_compat" ]; then
  [ -n "$rehearsals_dir" ] || die "--rollback-compatible needs --rehearsals-dir <folder of the rehearsal records>"
  [ -d "$rehearsals_dir" ] || die "--rehearsals-dir: no such folder: $rehearsals_dir"
  IFS=, read -r -a compat_list <<<"$rollback_compat"
  for v in "${compat_list[@]}"; do
    [[ $v =~ $semver ]] || die "--rollback-compatible: not a version: $v"
    version_lt "$v" "$version" || die "--rollback-compatible: $v is not older than $version"
    check_rehearsal "$v"
    compat_json=$(jq -c --arg v "$v" '. + [$v] | unique' <<<"$compat_json")
  done
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root=$stage/custodexa
rel=$root/releases/$version
mkdir -p "$rel"

# ---- compose files: fill in version, digests and (for rehearsal namespaces) the repository ----
fill() { # <template> <destination>
  sed -e "s|@@VERSION@@|$version|g" \
      -e "s|@@BACKEND_DIGEST@@|${backend_digest#sha256:}|g" \
      -e "s|@@FRONTEND_DIGEST@@|${frontend_digest#sha256:}|g" \
      -e "s|ghcr.io/custodexa/backend:|$backend_repo:|g" \
      -e "s|ghcr.io/custodexa/frontend:|$frontend_repo:|g" "$1" >"$2"
  if grep -nE '@@[A-Z_]+@@' "$2"; then die "unfilled placeholder in $2"; fi
}
for f in compose.yml compose.external-ingress.yml compose.external-database.yml; do
  fill "$repo/packaging/$f" "$rel/$f"
done

# ---- script, product files, source ----
cp -R "$repo/scripts/custodexa/custodexa.sh" "$repo/scripts/custodexa/lib" "$repo/scripts/custodexa/lang" "$rel/"
printf '%s\n' "$version" >"$rel/VERSION"
cp "$source/.env.example" "$rel/.env.example"
mkdir -p "$rel/reverse-proxy"
cp "$source/docker/reverse-proxy/tls-init.sh" "$source/docker/reverse-proxy/nginx-tls.conf.template" "$rel/reverse-proxy/"
mkdir -p "$rel/source"
(cd "$source" && tar --exclude=./.git -cf - .) | (cd "$rel/source" && tar -xf -)
ln -s "releases/$version" "$root/current"
ln -s current/custodexa.sh "$root/custodexa.sh"

# ---- MANIFEST.json ----
# Migration ids in the order they run, from the migrations slice in the Go source.
# shellcheck source=scripts/release/migrations-json.sh
. "$here/migrations-json.sh"

# >>> runtime markers (the test suite reads this block by its markers)
# Rows the backend writes into schema_migrations that are not migrations, with the first release
# a database could hold each one in. A restore uses the version to tell a marker of newer data
# from one its release knows. Every id of runtimeMarkerVersions in the Go source has exactly one
# row here and every row is in the Go source; a row is never removed and its version never
# changed, since older databases keep the marker.
runtime_marker_first_versions='20260804_ldap_env_seeded 1.0.0
20260825_offsite_env_seeded 1.1.0
20260906_credential_secrets_converted 1.6.0'

runtime_markers_json() { # <source tree>
  local go=$1/backend/internal/database names name val ids="" id ver row out
  names=$(awk '
    /^var runtimeMarkerVersions = \[\]string\{$/ { slice = 1; found = 1; next }
    slice && /^}$/ { ended = 1; exit }
    slice {
      line = $0
      sub(/\/\/.*/, "", line)
      gsub(/[[:space:]]/, "", line)
      if (line == "") next
      if (line !~ /^[A-Za-z_][A-Za-z0-9_]*,$/) { print "unrecognized runtime marker entry: " line > "/dev/stderr"; exit 1 }
      sub(/,$/, "", line)
      print line
    }
    END { if (!found || !ended) { print "runtimeMarkerVersions not found or unfinished" > "/dev/stderr"; exit 1 } }
  ' "$go/migrations.go") || die "cannot read runtimeMarkerVersions from $go/migrations.go"
  [ -n "$names" ] || die "no runtime markers found in $go/migrations.go"
  for name in $names; do
    val=$(sed -n "s/^const $name = \"\([^\"]*\)\"$/\1/p" "$go"/*.go)
    [ -n "$val" ] && [ "$(printf '%s\n' "$val" | wc -l)" -eq 1 ] || die "runtime marker $name is not one string constant"
    ids+="$val"$'\n'
  done
  out=""
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    row=$(awk -v id="$id" '$1 == id' <<<"$runtime_marker_first_versions")
    [ "$(printf '%s\n' "$row" | grep -c .)" -eq 1 ] || die "runtime marker $id needs one row in runtime_marker_first_versions"
    ver=${row#* }
    [[ $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "runtime marker $id has no version"
    out+="$id $ver"$'\n'
  done <<<"$ids"
  while read -r id ver; do
    grep -qxF -- "$id" <<<"$ids" || die "runtime marker $id is listed but not in the Go source"
  done <<<"$runtime_marker_first_versions"
  printf '%s' "$out" | jq -R 'split(" ") | {id: .[0], first_version: .[1]}' | jq -s .
}
# <<< runtime markers

raw() { docker buildx imagetools inspect --raw "$1"; }

# platforms <repository> <index digest>: config digest and compressed size per architecture.
platforms() {
  local ref=$1 idx=$2 index arch m manifest out='{}'
  index=$(raw "$ref@$idx") || die "cannot read index $ref@$idx"
  for arch in amd64 arm64; do
    m=$(jq -r --arg a "$arch" '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $a)][0].digest // empty' <<<"$index")
    [ -n "$m" ] || die "$ref@$idx has no linux/$arch image"
    manifest=$(raw "$ref@$m") || die "cannot read manifest $ref@$m"
    out=$(jq --arg a "$arch" --argjson man "$manifest" \
      '.[$a] = {config_digest: $man.config.digest, size: (([$man.layers[].size] | add) + $man.config.size)}' <<<"$out")
    jq -e --arg a "$arch" '.[$a].config_digest | test("^sha256:[0-9a-f]{64}$")' <<<"$out" >/dev/null \
      || die "$ref@$m has no config digest"
  done
  printf '%s' "$out"
}

# docker.io short names as the registry knows them: postgres -> docker.io/library/postgres.
normalize() {
  local r=$1
  case $r in
    */*.*/* | *.*/*) ;;
    */*) r=docker.io/$r ;;
    *) r=docker.io/library/$r ;;
  esac
  printf '%s' "$r"
}

images='{}'
for c in backend frontend; do
  digest=$(own_digest "$c")
  repo_c=$(own_repo "$c")
  plat=$(platforms "$repo_c" "$digest")
  entry=$(jq -n --arg ref "$repo_c" --arg tag "$version" --arg d "$digest" \
    --argjson p "$plat" '{ref: $ref, tag: $tag, index_digest: $d, platforms: $p}')
  if [ -n "$mirror_ns" ]; then
    entry=$(jq --arg m "docker.io/$mirror_ns/$c" '. + {mirror: $m}' <<<"$entry")
  fi
  images=$(jq --arg c "$c" --argjson e "$entry" '.[$c] = $e' <<<"$images")
done
# Upstream images: exactly the pinned defaults of compose.yml, so the MANIFEST and the compose
# file cannot name different images.
while IFS= read -r line; do
  [[ $line =~ image:\ \$\{CUSTODEXA_IMAGE_([A-Z0-9_]+):-([^}]+)\}$ ]] || continue
  name=${BASH_REMATCH[1],,} ref=${BASH_REMATCH[2]}
  case $name in backend | frontend) continue ;; esac
  [[ $ref =~ ^([^@]+):([^:@/]+)@(sha256:[0-9a-f]{64})$ ]] || die "upstream image $name is not pinned by digest: $ref"
  tag=${BASH_REMATCH[2]}
  digest=${BASH_REMATCH[3]}
  repo_u=$(normalize "${BASH_REMATCH[1]}")
  plat=$(platforms "$repo_u" "$digest")
  entry=$(jq -n --arg ref "$repo_u" --arg tag "$tag" --arg d "$digest" \
    --argjson p "$plat" '{ref: $ref, tag: $tag, index_digest: $d, upstream: true, platforms: $p}')
  images=$(jq --arg c "$name" --argjson e "$entry" '.[$c] = $e' <<<"$images")
done <"$rel/compose.yml"
# The PostgreSQL clients the backup of an external database runs: tool images, never services, one
# per server major version the backup supports, pinned by index digest. The one of the bundled
# database's major is the bundled database image itself (the same pin as compose.yml).
tool_pins="
pgclient16 postgres:16.15-alpine3.24@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
pgclient17 postgres:17.11-alpine3.24@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
pgclient18 postgres:18.6-alpine3.24@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873
"
while read -r name ref; do
  [ -n "$name" ] || continue
  [[ $ref =~ ^([^@]+):([^:@/]+)@(sha256:[0-9a-f]{64})$ ]] || die "tool image $name is not pinned by digest: $ref"
  tag=${BASH_REMATCH[2]}
  digest=${BASH_REMATCH[3]}
  repo_u=$(normalize "${BASH_REMATCH[1]}")
  plat=$(platforms "$repo_u" "$digest")
  entry=$(jq -n --arg ref "$repo_u" --arg tag "$tag" --arg d "$digest" \
    --argjson p "$plat" '{ref: $ref, tag: $tag, index_digest: $d, upstream: true, platforms: $p}')
  images=$(jq --arg c "$name" --argjson e "$entry" '.[$c] = $e' <<<"$images")
done <<<"$tool_pins"
[ "$(jq 'length' <<<"$images")" -eq 9 ] || die "expected 9 images, found: $(jq -c 'keys' <<<"$images")"
# One reference, one content: names that share an image must pin the same digest.
shared=$(jq -r 'to_entries | group_by("\(.value.ref):\(.value.tag)")[] | select(map(.value.index_digest) | unique | length > 1)
  | map(.key) | join(" ")' <<<"$images")
[ -z "$shared" ] || die "these images name one tag with different digests: $shared"

notes_json='{"zh-TW": [], "en": [], "ja": []}'
[ -n "$notes" ] && notes_json=$(cat "$notes")
mig=$(migrations_json "$source")
markers=$(runtime_markers_json "$source")
src_sha=$(cx_tree_sha256 "$rel/source")
jq -n --arg v "$version" --arg min "$min_source" --arg at "$released_at" \
  --argjson mig "$mig" --argjson markers "$markers" --argjson img "$images" \
  --arg src "$src_sha" --argjson notes "$notes_json" --argjson compat "$compat_json" \
  '{format: 1, version: $v, min_source_version: $min, released_at: $at, migrations: $mig,
    runtime_markers: $markers, images: $img, rollback_compatible: $compat, source: {path: "source/", sha256: $src}, notes: $notes}' \
  >"$rel/MANIFEST.json"

# ---- tarball: fixed order, owner and times, so the same inputs give the same bytes ----
mkdir -p "$out"
epoch=$(git -C "$source" log -1 --format=%ct 2>/dev/null || true)
[[ $epoch =~ ^[0-9]+$ ]] || epoch=$(date -d "$released_at" +%s)
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  -C "$stage" -cf - custodexa | gzip -n >"$out/custodexa-$version.tar.gz"
cp "$rel/MANIFEST.json" "$out/MANIFEST.json"
echo "build-package: $out/custodexa-$version.tar.gz"
echo "build-package: $out/MANIFEST.json"
