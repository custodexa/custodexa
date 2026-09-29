#!/usr/bin/env bash
# test_image_tags.sh - table-driven tests for image-tags.sh.
#
# Guards against: Docker Hub receiving "latest" (older compose files that name
# custodexa/<component>:latest would pull an image not built from their source); an image
# published under a version that differs from the VERSION file; a pre-release or an old-line
# patch release taking over "latest" or X.Y.
#
# Usage: bash .github/scripts/test_image_tags.sh
#   IMAGE_TAGS_SCRIPT=<path> overrides the script under test (used for mutation checks).
# Pure bash; needs no network and no container runtime. Exit status 0 when every case passes.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${IMAGE_TAGS_SCRIPT:-$here/image-tags.sh}"
[ -f "$script" ] || { echo "FAIL: script under test not found: $script" >&2; exit 1; }

pass=0
fail=0
cases=0

report_fail() {
  echo "FAIL [$1]: $2" >&2
  fail=$((fail + 1))
}

# expect_ok NAME TAG VERSION EXISTING STABLE GHCR DOCKERHUB
expect_ok() {
  local name="$1" tag="$2" ver="$3" existing="$4"
  local want_stable="$5" want_ghcr="$6" want_hub="$7"
  local out rc got_stable got_ghcr got_hub got_version
  cases=$((cases + 1))
  out="$(bash "$script" "$tag" "$ver" "$existing" 2>&1)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    report_fail "$name" "expected success, got exit $rc: $out"
    return
  fi
  got_stable="$(printf '%s\n' "$out" | sed -n 's/^stable=//p')"
  got_version="$(printf '%s\n' "$out" | sed -n 's/^version=//p')"
  got_ghcr="$(printf '%s\n' "$out" | sed -n 's/^ghcr_tags=//p')"
  got_hub="$(printf '%s\n' "$out" | sed -n 's/^dockerhub_tags=//p')"
  local ok=1
  [ "$got_stable" = "$want_stable" ] || { report_fail "$name" "stable='$got_stable' want '$want_stable'"; ok=0; }
  [ "$got_version" = "${tag#v}" ] || { report_fail "$name" "version='$got_version' want '${tag#v}'"; ok=0; }
  [ "$got_ghcr" = "$want_ghcr" ] || { report_fail "$name" "ghcr_tags='$got_ghcr' want '$want_ghcr'"; ok=0; }
  [ "$got_hub" = "$want_hub" ] || { report_fail "$name" "dockerhub_tags='$got_hub' want '$want_hub'"; ok=0; }
  # Invariant checked on every successful case, independent of the expected table.
  case " $got_hub " in
    *" latest "*) report_fail "$name" "Docker Hub tag list contains latest: '$got_hub'"; ok=0 ;;
  esac
  if [ "$want_stable" = true ]; then
    local want_arg=""
  else
    local want_arg="${tag#v}"
  fi
  local got_arg
  got_arg="$(printf '%s\n' "$out" | sed -n 's/^version_build_arg=//p')"
  [ "$got_arg" = "$want_arg" ] || { report_fail "$name" "version_build_arg='$got_arg' want '$want_arg'"; ok=0; }
  [ "$ok" -eq 1 ] && pass=$((pass + 1))
}

# expect_fail NAME TAG VERSION EXISTING MESSAGE-SUBSTRING
expect_fail() {
  local name="$1" tag="$2" ver="$3" existing="$4" needle="$5"
  local out rc
  cases=$((cases + 1))
  out="$(bash "$script" "$tag" "$ver" "$existing" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    report_fail "$name" "expected failure, got success: $out"
    return
  fi
  case "$out" in
    *"$needle"*) pass=$((pass + 1)) ;;
    *) report_fail "$name" "failure message lacks '$needle': $out" ;;
  esac
}

history="v1.0.0 v1.0.1 v1.11.0 v1.12.0 v1.12.3 v1.12.4 v1.13.0-rc.1"

# 1. Final release, highest overall.
expect_ok "release-highest" v1.13.0 "1.13.0" "$history" \
  true "1.13.0 1.13 latest" "1.13.0 1.13"
expect_ok "release-highest-first-ever" v1.0.0 "1.0.0" "" \
  true "1.0.0 1.0 latest" "1.0.0 1.0"
expect_ok "release-rerun-self-listed" v1.13.0 "1.13.0" "$history v1.13.0" \
  true "1.13.0 1.13 latest" "1.13.0 1.13"
expect_ok "release-version-file-trailing-newline" v1.13.0 $'1.13.0\n' "$history" \
  true "1.13.0 1.13 latest" "1.13.0 1.13"
expect_ok "release-numeric-not-lexical" v1.10.0 "1.10.0" "v1.9.9 v1.2.0" \
  true "1.10.0 1.10 latest" "1.10.0 1.10"

# 2. Old-line patch release.
expect_ok "old-line-patch-highest-in-line" v1.12.5 "1.12.5" "$history v1.13.0" \
  true "1.12.5 1.12" "1.12.5 1.12"
expect_ok "old-line-patch-not-highest-in-line" v1.12.2 "1.12.2" "$history v1.13.0" \
  true "1.12.2" "1.12.2"
expect_ok "older-patch-with-newer-major" v1.13.1 "1.13.1" "v1.13.0 v2.0.0" \
  true "1.13.1 1.13" "1.13.1 1.13"
expect_ok "prerelease-in-history-does-not-block-latest" v1.13.0 "1.13.0" "v1.13.0-rc.1 v1.14.0-rc.1" \
  true "1.13.0 1.13 latest" "1.13.0 1.13"
expect_ok "junk-tags-ignored" v1.13.0 "1.13.0" "v9.9 release-2 v1.13.0.1 vv2.0.0" \
  true "1.13.0 1.13 latest" "1.13.0 1.13"

# 3. Pre-release.
expect_ok "prerelease-rc" v1.13.0-rc.1 "1.13.0" "$history" \
  false "1.13.0-rc.1" ""
expect_ok "prerelease-drill" v1.12.4-drill.1 "1.12.4" "$history" \
  false "1.12.4-drill.1" ""
expect_ok "prerelease-above-all-releases" v2.0.0-beta.3 "2.0.0" "$history" \
  false "2.0.0-beta.3" ""

# 4. Tag does not match VERSION.
expect_fail "tag-version-mismatch" v1.13.1 "1.13.0" "$history" "does not match VERSION"
expect_fail "prerelease-version-mismatch" v1.13.0-rc.1 "1.12.4" "$history" "does not match VERSION"
expect_fail "empty-version-file" v1.13.0 "" "$history" "VERSION file content is empty"

# 5. Malformed tag.
for bad in v1.13 v1.13.0.1 v01.13.0 v1.13.0- "v1.13.0-rc..1" v1.13.0+build.1 "v1.13.0-rc_1" v1 ""; do
  expect_fail "malformed-${bad:-empty}" "$bad" "1.13.0" "$history" "is not vX.Y.Z"
done

# 6. Missing "v" prefix.
expect_fail "missing-v-prefix" 1.13.0 "1.13.0" "$history" "is not vX.Y.Z"
expect_fail "missing-v-prefix-pre" 1.13.0-rc.1 "1.13.0" "$history" "is not vX.Y.Z"

# Argument count.
cases=$((cases + 1))
if bash "$script" v1.13.0 >/dev/null 2>&1; then
  report_fail "arg-count" "one argument must be rejected"
else
  pass=$((pass + 1))
fi

echo "test_image_tags: ${pass}/${cases} passed"
[ "$fail" -eq 0 ] && [ "$pass" -eq "$cases" ]
