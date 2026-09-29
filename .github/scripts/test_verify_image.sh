#!/usr/bin/env bash
# test_verify_image.sh - prove that verify-image.sh accepts a correct image and rejects
# deliberately broken ones.
#
# Guards against: the release contract check passing images it should stop (a shell left in
# the backend, missing or outdated license files, a binary for the wrong architecture, a wrong
# license label or version). If any broken image passes, the pre-publish check is ineffective.
#
# Usage:
#   BACKEND_IMAGE=<ref> FRONTEND_IMAGE=<ref> bash .github/scripts/test_verify_image.sh
#
#   Both references must be local multi-platform images (linux/amd64 and linux/arm64) built
#   from this source tree with the production targets, for example:
#     docker buildx build --platform linux/amd64,linux/arm64 -f docker/backend/Dockerfile \
#       --target production -t local/backend:test --load .
#   EXPECT_VERSION defaults to the VERSION file. Needs a docker daemon whose image store can
#   hold multi-platform images (containerd image store). Broken images are built on top of the
#   given ones, tagged verify-image-test/*, and removed afterwards.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
verify="$here/verify-image.sh"
backend="${BACKEND_IMAGE:?set BACKEND_IMAGE to a local multi-platform backend image}"
frontend="${FRONTEND_IMAGE:?set FRONTEND_IMAGE to a local multi-platform frontend image}"
version="${EXPECT_VERSION:-$(tr -d ' \t\r\n' < "$root/VERSION")}"

work="$(mktemp -d)"
built=()
img=""
cleanup() {
  local img
  for img in "${built[@]+"${built[@]}"}"; do
    docker image rm -f "$img" >/dev/null 2>&1
  done
  rm -rf "$work"
}
trap cleanup EXIT

pass=0
fail=0
cases=0

# expect NAME WANT(pass|fail) NEEDLE -- verify-image arguments...
expect() {
  local name="$1" want="$2" needle="$3"
  shift 4
  local out rc
  cases=$((cases + 1))
  out="$(bash "$verify" "$@" 2>&1)"
  rc=$?
  printf '%s\n' "$out" | sed "s/^/    [$name] /"
  if [ "$want" = pass ]; then
    if [ "$rc" -eq 0 ]; then
      echo "PASS [$name] accepted"
      pass=$((pass + 1))
    else
      echo "FAIL [$name] expected exit 0, got $rc"
      fail=$((fail + 1))
    fi
    return
  fi
  if [ "$rc" -eq 0 ]; then
    echo "FAIL [$name] broken image was accepted"
    fail=$((fail + 1))
  elif ! printf '%s\n' "$out" | grep -q "^FAIL: .*${needle}"; then
    echo "FAIL [$name] exit $rc but no failure line naming '${needle}'"
    fail=$((fail + 1))
  else
    echo "PASS [$name] rejected (exit $rc) naming '${needle}'"
    pass=$((pass + 1))
  fi
}

# build_bad NAME PLATFORM BASE <<Dockerfile   (sets $img on success)
build_bad() {
  local name="$1" platform="$2" base="$3"
  local dir="$work/$name" tag="verify-image-test/${name}:test"
  mkdir -p "$dir"
  cat > "$dir/Dockerfile"
  printf 'tampered third-party notice\n' > "$dir/tampered.md"
  if ! docker buildx build --quiet --platform "$platform" --build-arg "BASE=$base" \
      -t "$tag" --load "$dir" >"$dir/build.log" 2>&1; then
    echo "FAIL [$name] could not build the broken image:"
    sed 's/^/    /' "$dir/build.log"
    fail=$((fail + 1))
    cases=$((cases + 1))
    return 1
  fi
  built+=("$tag")
  img="$tag"
}

echo "== correct images =="
for p in linux/amd64 linux/arm64; do
  expect "good-backend-${p#linux/}" pass "" -- --component backend --platform "$p" --version "$version" "$backend"
  expect "good-frontend-${p#linux/}" pass "" -- --component frontend --platform "$p" --version "$version" "$frontend"
done

echo "== broken images =="

if build_bad with-shell linux/arm64 "$backend" <<'EOF'
ARG BASE
FROM ${BASE} AS base
FROM base
COPY --from=base /bin/busybox /bin/sh
EOF
then
  expect with-shell fail "/bin/sh exists" -- --component backend --platform linux/arm64 --version "$version" "$img"
fi

if build_bad missing-notice linux/amd64 "$frontend" <<'EOF'
ARG BASE
FROM ${BASE}
RUN rm /usr/share/doc/custodexa/NOTICE
EOF
then
  expect missing-notice fail "NOTICE is missing" -- --component frontend --platform linux/amd64 --version "$version" "$img"
fi

if build_bad stale-third-party linux/amd64 "$backend" <<'EOF'
ARG BASE
FROM ${BASE}
COPY tampered.md /usr/share/doc/custodexa/THIRD-PARTY-LICENSES.md
EOF
then
  expect stale-third-party fail "THIRD-PARTY-LICENSES.md differs" -- --component backend --platform linux/amd64 --version "$version" "$img"
fi

if build_bad arm64-with-amd64-binary linux/arm64 "$backend" <<'EOF'
ARG BASE
FROM --platform=linux/amd64 ${BASE} AS foreign
FROM ${BASE}
COPY --from=foreign /root/custodexa /root/custodexa
EOF
then
  expect arm64-with-amd64-binary fail "custodexa built for linux/amd64, expected linux/arm64" -- --component backend --platform linux/arm64 --version "$version" "$img"
fi

if build_bad deprecated-license-label linux/amd64 "$frontend" <<'EOF'
ARG BASE
FROM ${BASE}
LABEL org.opencontainers.image.licenses="AGPL-3.0"
EOF
then
  expect deprecated-license-label fail "org.opencontainers.image.licenses is 'AGPL-3.0'" -- --component frontend --platform linux/amd64 --version "$version" "$img"
fi

expect wrong-version fail "custodexa reports version" -- --component backend --platform linux/amd64 --version "0.0.0-not-this" "$backend"
expect wrong-revision-label fail "org.opencontainers.image.revision" -- --component frontend --platform linux/amd64 --version "$version" \
  --revision 0000000000000000000000000000000000000000 --source https://example.invalid/repo "$frontend"

echo "test_verify_image: ${pass}/${cases} passed"
[ "$fail" -eq 0 ] && [ "$pass" -eq "$cases" ]
