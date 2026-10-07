#!/usr/bin/env bash
# Controlled integration runs of custodexa.sh against real Docker, PostgreSQL and openssl.
# Each scenario runs on its own throw-away docker:29-dind host (privileged, no network unless its
# header says "network: bridge"); a builder host with network access makes the install package and
# fills the cache first. A scenario whose header says "hosts: a b" gets two such hosts, no network
# between them, sharing only a volume at /transfer.
#   bash scripts/custodexa/tests/integration/run.sh <scenario|group>...
#   bash scripts/custodexa/tests/integration/run.sh list
#   bash scripts/custodexa/tests/integration/run.sh clean [--cache]
# Environment:
#   CX_IT_VERSION=1.15.2      the published release whose images back the package
#   CX_IT_FROM_VERSION=1.15.1 the older release a scenario that upgrades installs first
#   CX_IT_FROM2_VERSION=1.15.0 the release before it, for a scenario that upgrades twice
#   CX_IT_PUBLISHED_VERSION=1.15.2  the release whose own published package and offline bundle a
#                             scenario with "needs: published" installs (not built from here)
#   CX_IT_CACHE=<dir>         downloads, image tars, offline bundles, run logs
#                             (default ${XDG_CACHE_HOME:-~/.cache}/custodexa-it)
#   CX_IT_STORE=classic|containerd   image store of the scenario hosts (default: the engine's)
#   CX_IT_REBUILD_BUNDLE=1    rebuild the offline bundle even when the cache holds one
#   CX_IT_KEEP=1              leave a failed scenario's host running; `run.sh clean` removes it
# Everything this creates on the local Docker carries the label below and the name prefix
# custodexa-it-; `run.sh clean` removes all of it. Written for bash 3.2 too (macOS).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
readonly PREFIX=custodexa-it
readonly LABEL=org.custodexa.integration=1
readonly HOST_IMAGE=custodexa-it-host:1
readonly READY_TRIES=60
cache=${CX_IT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/custodexa-it}
version=${CX_IT_VERSION:-1.15.2}
from_version=${CX_IT_FROM_VERSION:-1.15.1}
from2_version=${CX_IT_FROM2_VERSION:-1.15.0}
published_version=${CX_IT_PUBLISHED_VERSION:-1.15.2}
started=""

say() { printf '%s\n' "$*"; }
die() {
  printf 'integration: %s\n' "$*" >&2
  exit 1
}

# ---- resources on the local Docker ----

clean() {
  local ids vols
  ids=$( (docker ps -aq --filter "label=$LABEL"; docker ps -aq --filter "name=^$PREFIX-") | sort -u)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  vols=$( (docker volume ls -q --filter "label=$LABEL"; docker volume ls -q --filter "name=^$PREFIX-") | sort -u)
  # shellcheck disable=SC2086
  [ -z "$vols" ] || docker volume rm $vols >/dev/null
  say "integration: removed $(printf '%s' "$ids" | grep -c . || true) container(s), $(printf '%s' "$vols" | grep -c . || true) volume(s)"
  if [ "${1:-}" = --cache ]; then
    rm -rf "$cache"
    docker image rm "$HOST_IMAGE" custodexa-it-openssl111:1 custodexa-it-openssl30:1 custodexa-it-openssl32:1 \
      custodexa-it-testimage:1 >/dev/null 2>&1 || true
    say "integration: removed $cache and the images built for it"
  fi
}

host_stop() {
  docker rm -fv "$1" >/dev/null 2>&1 || true
  docker volume rm "$1-docker" >/dev/null 2>&1 || true
}

# The transfer volumes of two-host scenarios; removed after their hosts.
transfers=""

on_exit() {
  local n
  for n in $started; do host_stop "$n"; done
  for n in $transfers; do docker volume rm "$n" >/dev/null 2>&1 || true; done
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# host_start <name> <bridge|none> <default|classic|containerd> <hostname> [docker run arguments]:
# an integration host whose engine listens on its unix socket only (no TCP port, nothing published).
host_start() {
  local name=$1 net=$2 hostname=$4 i
  local -a store=()
  case $3 in
    default) ;;
    classic) store=(--feature containerd-snapshotter=false) ;;
    containerd) store=(--feature containerd-snapshotter=true) ;;
    *) die "image store must be classic or containerd, not $3" ;;
  esac
  shift 4
  docker volume create --label "$LABEL" "$name-docker" >/dev/null
  started="$started $name"
  docker run -d --privileged --name "$name" --hostname "$hostname" --label "$LABEL" \
    --network "$net" -e DOCKER_TLS_CERTDIR= -v "$name-docker:/var/lib/docker" -v "$repo:/src:ro" "$@" \
    "$HOST_IMAGE" dockerd --host=unix:///var/run/docker.sock ${store[@]+"${store[@]}"} >/dev/null
  for ((i = 0; i < READY_TRIES; i++)); do
    docker exec "$name" docker info >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$name" 2>&1 | tail -n 20 >&2
  die "$name: the engine did not come up"
}

# ---- scenarios ----

scenario_file() { printf '%s/scenarios/%s.sh' "$here" "$1"; }
meta() { sed -n "s/^# $2: //p" "$(scenario_file "$1")" | head -n1; }
needs() { [[ " $(meta "$1" needs) " == *" $2 "* ]]; } # <scenario> <package|upgrade|twice|local-versions|published>

expand() {
  local a line
  for a in "$@"; do
    line=$(sed -n "s/^$a: //p" "$here/scenarios/groups.txt")
    if [ -n "$line" ]; then
      printf '%s\n' "$line" | tr ' ' '\n'
    elif [ -f "$(scenario_file "$a")" ]; then
      printf '%s\n' "$a"
    else
      die "no scenario or group named $a (run.sh list)"
    fi
  done
}

list() {
  local f n
  say "groups:"
  sed -n 's/^\([a-z0-9-]*\): /  \1: /p' "$here/scenarios/groups.txt"
  say "scenarios:"
  for f in "$here"/scenarios/*.sh; do
    n=${f##*/}
    n=${n%.sh}
    printf '  %-18s %s\n' "$n" "$(sed -n 's/^# about: //p' "$f" | head -n1)"
  done
}

# ---- images ----

catalogue() { grep -v '^#' "$here/images.txt" | awk -v k="$1" '$1 == k'; }
img_tar() { # <key>: the cached tar's file name for this architecture
  local kind src id
  read -r _ kind src _ <<<"$(catalogue "$1")" || true
  [ -n "$kind" ] || die "images.txt has no image $1"
  if [ "$kind" = registry ]; then
    id=${src##*@sha256:}
  else
    id=$(docker image inspect --format '{{.Id}}' "$src")
    id=${id#sha256:}
  fi
  printf '%s-%s-%s.tar' "$1" "$arch" "${id:0:16}"
}

# The images the packaging pins and the catalogue must not drift apart: the compose file's, and the
# PostgreSQL clients of the release build.
check_pins() {
  local k ref
  for k in pg16 openssl-3.5.4; do
    ref=$(catalogue "$k" | awk '{print $3}')
    grep -qF ":-$ref}" "$repo/packaging/compose.yml" || die "images.txt $k ($ref) is not the pin in packaging/compose.yml"
  done
  for k in 16 17 18; do
    ref=$(catalogue "pg$k" | awk '{print $3}')
    grep -qxF "pgclient$k $ref" "$repo/scripts/release/build-package.sh" ||
      die "images.txt pg$k ($ref) is not the pgclient$k pin in scripts/release/build-package.sh"
  done
}

build_local_images() {
  local k kind tag file
  docker build -q -t "$HOST_IMAGE" -f "$here/host.Dockerfile" "$here" >/dev/null
  while read -r k kind tag file; do
    [ "$kind" = build ] || continue
    docker build -q -t "$tag" -f "$here/$file" "$(dirname "$here/$file")" >/dev/null
  done < <(grep -v '^#' "$here/images.txt")
}

# prepare_images <keys>: each key's tar name is fixed once per run in $run/images (an image built
# here could be rebuilt while the run goes on); host-built images are saved into the cache here,
# registry images that the cache lacks are listed in $run/fetch for the builder.
prepare_images() {
  local k t kind src
  mkdir -p "$cache/images"
  : >"$run/fetch"
  : >"$run/images"
  for k in "$@"; do
    grep -q "^$k " "$run/images" && continue
    t=$(img_tar "$k")
    printf '%s %s\n' "$k" "$t" >>"$run/images"
    [ -f "$cache/images/$t" ] && continue
    read -r _ kind src _ <<<"$(catalogue "$k")" || true
    if [ "$kind" = build ]; then
      docker save -o "$cache/images/$t.tmp" "$src"
      mv -f "$cache/images/$t.tmp" "$cache/images/$t"
    else
      printf '%s %s\n' "$src" "$t" >>"$run/fetch"
    fi
  done
}

# ---- phases ----

build_phase() { # <needs package: 0|1> <needs the older package: 0|1> <and the one before: 0|1>
  # <versions built from the working tree: 0|1> <the published release's own package: 0|1>
  local name=$PREFIX-$runid-build from="" from2="" published=""
  [ "$2" = 0 ] || from=$from_version
  [ "${3:-0}" = 0 ] || from2=$from2_version
  [ "${5:-0}" = 0 ] || published=$published_version
  say "== builder ($name): package=$1 from=${from:-none} from2=${from2:-none} fetch=$(grep -c . "$run/fetch" || true)"
  if [ "$1" = 1 ]; then
    git -C "$repo" ls-files -co --exclude-standard -z >"$run/source-files"
  fi
  # Classic store, like the release builder: build-package.sh offline is written against it.
  host_start "$name" bridge classic it-host -v "$cache:/cache" -v "$run:/it-run"
  local rc
  set +e
  docker exec -e IT_VERSION="$version" -e IT_FROM_VERSION="$from" -e IT_FROM2_VERSION="$from2" -e IT_PACKAGE="$1" \
    -e IT_REBUILD_BUNDLE="${CX_IT_REBUILD_BUNDLE:-0}" -e IT_LOCAL_VERSIONS="${4:-0}" -e IT_PUBLISHED_VERSION="$published" \
    "$name" bash /src/scripts/custodexa/tests/integration/inside.sh build 2>&1 | tee "$run/build.log"
  rc=${PIPESTATUS[0]}
  set -e
  host_stop "$name"
  [ "$rc" -eq 0 ] || die "builder failed (exit $rc), log: $run/build.log"
}

scenario_phase() { # <scenario>: prints the scenario's own PASS/FAIL line, returns its exit code
  local s=$1 name=$PREFIX-$runid-$1 k images="" rc net
  local -a mounts=(-v "$run:/it-run:ro" -v "$cache/images:/cache/images:ro")
  for k in $(meta "$s" images); do images="$images $k=$(awk -v k="$k" '$1 == k {print $2}' "$run/images")"; done
  if needs "$s" package; then
    mounts+=(-v "$cache/bundles/$(cat "$run/bundle-dir"):/bundle:ro")
  fi
  if needs "$s" upgrade; then
    mounts+=(-v "$cache/bundles/$(cat "$run/bundle-dir-from"):/bundle-from:ro")
  fi
  if needs "$s" twice; then
    mounts+=(-v "$cache/bundles/$(cat "$run/bundle-dir-from2"):/bundle-from2:ro")
  fi
  if needs "$s" published; then
    mounts+=(-v "$cache/published/$published_version-$arch:/published:ro")
  fi
  if needs "$s" local-versions; then
    for k in $(cat "$run/local-versions"); do
      mounts+=(-v "$cache/bundles/$(cat "$run/bundle-dir-$k"):/bundle-$k:ro")
    done
  fi
  net=$(meta "$s" network)
  case ${net:-none} in none | bridge) ;; *) die "$s: network must be none or bridge, not $net" ;; esac
  if [ -n "$(meta "$s" hosts)" ]; then
    [ "${net:-none}" = none ] || die "$s: a scenario with two hosts has no network (drop its network: line)"
    hosts_phase "$s" "${mounts[@]}"
    return
  fi
  say "== $s ($name, network ${net:-none})"
  host_start "$name" "${net:-none}" "${CX_IT_STORE:-default}" it-host "${mounts[@]}"
  set +e
  docker exec -e IT_IMAGES="$images" "$name" bash /src/scripts/custodexa/tests/integration/inside.sh scenario "$s" 2>&1 |
    tee "$run/$s.log"
  rc=${PIPESTATUS[0]}
  set -e
  if [ "$rc" -ne 0 ] && [ "${CX_IT_KEEP:-0}" = 1 ]; then
    started=${started/ $name/}
    say "   kept for inspection: docker exec -it $name bash   (remove: run.sh clean)"
  else
    host_stop "$name"
  fi
  return "$rc"
}

# hosts_phase <scenario> <mounts...>: a scenario whose header says "hosts: a b" gets one host per
# name, all started before the first part runs, none with a network, sharing only the volume
# mounted at /transfer. Each host in header order runs the scenario's scenario_<name>() (the last
# prints PASS); the first that fails ends the scenario. Uses $images of scenario_phase.
hosts_phase() {
  local s=$1 h names="" n=0 i=0 rc=0 last transfer=$PREFIX-$runid-$1-transfer
  shift
  for h in $(meta "$s" hosts); do
    [[ $h =~ ^[a-z][a-z0-9]*$ ]] || die "$s: host name $h must be lowercase letters and digits"
    [[ " $names " != *" $h "* ]] || die "$s: host $h is named twice"
    names="$names $h"
    n=$((n + 1))
  done
  [ "$n" -ge 2 ] || die "$s: hosts: names two hosts or more, not $n"
  say "== $s (hosts:$names, no network between them, shared: $transfer)"
  docker volume create --label "$LABEL" "$transfer" >/dev/null
  transfers="$transfers $transfer"
  for h in $names; do
    host_start "$PREFIX-$runid-$s-$h" none "${CX_IT_STORE:-default}" "it-host-$h" "$@" -v "$transfer:/transfer"
  done
  : >"$run/$s.log"
  for h in $names; do
    i=$((i + 1))
    last=0
    [ "$i" -lt "$n" ] || last=1
    say "-- host $h ($PREFIX-$runid-$s-$h, hostname it-host-$h)" | tee -a "$run/$s.log"
    set +e
    docker exec -e IT_IMAGES="$images" -e IT_HOST="$h" -e IT_HOST_LAST="$last" "$PREFIX-$runid-$s-$h" \
      bash /src/scripts/custodexa/tests/integration/inside.sh scenario "$s" 2>&1 | tee -a "$run/$s.log"
    rc=${PIPESTATUS[0]}
    set -e
    [ "$rc" -eq 0 ] || break
  done
  if [ "$rc" -ne 0 ] && [ "${CX_IT_KEEP:-0}" = 1 ]; then
    for h in $names; do
      started=${started/ $PREFIX-$runid-$s-$h/}
      say "   kept for inspection: docker exec -it $PREFIX-$runid-$s-$h bash"
    done
    transfers=${transfers/ $transfer/}
    say "   and the volume $transfer   (remove all: run.sh clean)"
  else
    for h in $names; do host_stop "$PREFIX-$runid-$s-$h"; done
    docker volume rm "$transfer" >/dev/null 2>&1 || true
    transfers=${transfers/ $transfer/}
  fi
  return "$rc"
}

main() {
  local s k t0 rc=0 package=0 upgrade=0 twice=0 lv=0 published=0 failed=""
  local -a scenarios=() keys=()
  case ${1:-} in
    "" | -h | --help) sed -n '2,23p' "$0"; exit 0 ;;
    list) list; exit 0 ;;
    clean) shift; clean "$@"; exit 0 ;;
  esac
  # A command substitution, not a process substitution: an unknown name must stop the run here.
  s=$(expand "$@")
  while IFS= read -r k; do scenarios+=("$k"); done <<<"$s"
  t0=$(date +%s)
  runid=$(date +%Y%m%d-%H%M%S)-$$
  run=$cache/runs/$runid
  mkdir -p "$run"
  check_pins
  build_local_images
  arch=$(docker run --rm --entrypoint uname "$HOST_IMAGE" -m)
  case $arch in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) die "unsupported architecture $arch" ;; esac
  for s in "${scenarios[@]}"; do
    needs "$s" package && package=1
    needs "$s" upgrade && package=1 upgrade=1
    needs "$s" twice && package=1 upgrade=1 twice=1
    needs "$s" local-versions && package=1 lv=1
    needs "$s" published && published=1
    for k in $(meta "$s" images); do keys+=("$k"); done
  done
  prepare_images ${keys[@]+"${keys[@]}"}
  say "== run $runid: ${scenarios[*]} (release images $version, $arch, log $run)"
  # Versions built from the working tree must leave it as it was: its status before and after.
  [ "$lv" = 0 ] || git -C "$repo" status --porcelain >"$run/worktree-status.before"
  if [ "$package" = 1 ] || [ "$published" = 1 ] || [ -s "$run/fetch" ]; then
    build_phase "$package" "$upgrade" "$twice" "$lv" "$published"
  fi
  [ "$lv" = 0 ] || git -C "$repo" status --porcelain >"$run/worktree-status.after"
  for s in "${scenarios[@]}"; do
    scenario_phase "$s" || { rc=1; failed="$failed $s"; }
  done
  say "== done in $(($(date +%s) - t0)) s; failed:${failed:- none}"
  return "$rc"
}

main "$@"
