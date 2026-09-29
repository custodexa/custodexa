#!/usr/bin/env bash
# test_mirror_image.sh - exercise mirror-image.sh against two throwaway local registries.
#
# Guards against: a mirror whose digest differs from the primary registry (one provenance
# attestation could then no longer verify both copies); "latest" reaching the mirror; a
# released version being overwritten with different content.
#
# Usage: bash .github/scripts/test_mirror_image.sh
#   CRANE=<path> selects the crane binary (default: crane on PATH).
#   REGISTRY_IMAGE overrides the registry image (default pinned below).
#   MIRROR_IMAGE_SCRIPT=<path> overrides the script under test (used for mutation checks).
# Needs a docker daemon; starts two registry containers bound to 127.0.0.1 on random ports and
# removes them afterwards. No external registry is contacted apart from pulling REGISTRY_IMAGE.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
mirror="${MIRROR_IMAGE_SCRIPT:-$here/mirror-image.sh}"
CRANE="${CRANE:-crane}"
export CRANE
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e}"

command -v "$CRANE" >/dev/null 2>&1 || { echo "FAIL: crane not found (set CRANE)" >&2; exit 1; }

work="$(mktemp -d)"
containers=()
cleanup() {
  local c
  for c in "${containers[@]+"${containers[@]}"}"; do
    docker rm -f "$c" >/dev/null 2>&1
  done
  rm -rf "$work"
}
trap cleanup EXIT

start_registry() {
  local cid port
  cid="$(docker run -d -p 127.0.0.1::5000 "$REGISTRY_IMAGE")" || return 1
  containers+=("$cid")
  port="$(docker port "$cid" 5000/tcp | head -n1 | sed 's/.*://')"
  local _
  for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:${port}/v2/" >/dev/null 2>&1; then
      REG="localhost:${port}"
      return 0
    fi
    sleep 0.2
  done
  echo "registry on port ${port} did not become ready" >&2
  return 1
}

start_registry || { echo "FAIL: cannot start source registry" >&2; exit 1; }
SRC_REG="$REG"
start_registry || { echo "FAIL: cannot start target registry" >&2; exit 1; }
DST_REG="$REG"
src="${SRC_REG}/custodexa/backend"
dst="${DST_REG}/custodexa/backend"

# seed_index NAME: push a two-manifest index with unique content to the source registry and
# print its digest.
seed_index() {
  local name="$1" part
  for part in a b; do
    mkdir -p "$work/$name-$part"
    printf '%s-%s-%s\n' "$name" "$part" "$RANDOM" > "$work/$name-$part/content.txt"
    tar -C "$work/$name-$part" -cf "$work/$name-$part.tar" content.txt
    "$CRANE" append --oci-empty-base -f "$work/$name-$part.tar" -t "${src}:seed-${name}-${part}" >/dev/null 2>&1 || return 1
  done
  "$CRANE" index append -m "${src}:seed-${name}-a" -m "${src}:seed-${name}-b" -t "${src}:seed-${name}" >/dev/null 2>&1 || return 1
  "$CRANE" digest "${src}:seed-${name}"
}

d1="$(seed_index one)" || { echo "FAIL: cannot seed index one" >&2; exit 1; }
d2="$(seed_index two)" || { echo "FAIL: cannot seed index two" >&2; exit 1; }
echo "source ${src}: one=${d1} two=${d2}"

pass=0
fail=0
cases=0
check() {
  local name="$1"
  shift
  cases=$((cases + 1))
  if "$@"; then
    echo "PASS [$name]"
    pass=$((pass + 1))
  else
    echo "FAIL [$name]"
    fail=$((fail + 1))
  fi
}
run_mirror() {
  bash "$mirror" "$@" > "$work/last.out" 2>&1
  local rc=$?
  sed 's/^/    /' "$work/last.out"
  return "$rc"
}
digest_of() { "$CRANE" digest "$1" 2>/dev/null; }
tag_absent() { ! "$CRANE" digest "$1" >/dev/null 2>&1; }
last_output_has() { grep -q "$1" "$work/last.out"; }
# refused ARGS...: true when mirror-image.sh exits non-zero; output kept in last.out.
refused() { ! run_mirror "$@"; }

echo "== 1. normal copy keeps the digest =="
check "copy-exit-0" run_mirror "$src" "$dst" "$d1" 1.13.0 1.13
check "copy-full-tag-digest" test "$(digest_of "${dst}:1.13.0")" = "$d1"
check "copy-line-tag-digest" test "$(digest_of "${dst}:1.13")" = "$d1"
check "copy-matches-source" test "$(digest_of "${dst}:1.13.0")" = "$(digest_of "${src}@${d1}")"

echo "== 2. latest is refused =="
check "latest-refused" refused "$src" "$dst" "$d1" 1.13.0 latest
check "latest-message" last_output_has "refusing to publish 'latest'"
check "latest-not-created" tag_absent "${dst}:latest"
check "latest-alone-refused" refused "$src" "$dst" "$d1" latest
check "latest-not-created-2" tag_absent "${dst}:latest"

echo "== 3. an existing version with different content is not overwritten =="
"$CRANE" copy "${src}@${d2}" "${dst}:1.14.0" >/dev/null 2>&1
check "overwrite-refused" refused "$src" "$dst" "$d1" 1.14.0 1.14
check "overwrite-message" last_output_has "never overwritten"
check "overwrite-target-unchanged" test "$(digest_of "${dst}:1.14.0")" = "$d2"
check "overwrite-no-partial-write" tag_absent "${dst}:1.14"

echo "== 4. re-running with the same content succeeds =="
check "rerun-exit-0" run_mirror "$src" "$dst" "$d1" 1.13.0 1.13
check "rerun-reports-existing" last_output_has "already at ${d1}"
check "rerun-digest-unchanged" test "$(digest_of "${dst}:1.13.0")" = "$d1"

echo "== 5. X.Y moves, X.Y.Z stays =="
check "line-move-exit-0" run_mirror "$src" "$dst" "$d2" 1.13.1 1.13
check "line-moved" test "$(digest_of "${dst}:1.13")" = "$d2"
check "old-version-kept" test "$(digest_of "${dst}:1.13.0")" = "$d1"

echo "== 6. unexpected input is refused =="
check "v-prefixed-tag-refused" refused "$src" "$dst" "$d1" v1.13.0
check "major-only-tag-refused" refused "$src" "$dst" "$d1" 1
check "bad-digest-refused" refused "$src" "$dst" sha256:1234 1.13.0
missing="sha256:$(printf '0%.0s' $(seq 1 64))"
check "missing-source-refused" refused "$src" "$dst" "$missing" 1.15.0
check "missing-source-no-write" tag_absent "${dst}:1.15.0"

echo "test_mirror_image: ${pass}/${cases} passed"
[ "$fail" -eq 0 ] && [ "$pass" -eq "$cases" ]
