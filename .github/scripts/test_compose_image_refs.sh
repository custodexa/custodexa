#!/usr/bin/env bash
# test_compose_image_refs.sh - static checks on image references in the source-build compose
# files.
#
# Guards against: a locally built image carrying a published registry name (it could not be
# told apart from the signed release image by name); a self-built service losing
# `pull_policy: never` and pulling a same-named image from a registry instead; the upstream
# guacd image referenced by tag only (a rebuilt upstream tag would reach deployments
# unverified) or rebuilt locally again.
#
# Usage: bash .github/scripts/test_compose_image_refs.sh [compose-file...]
#   Default files: docker-compose.yml and docker-compose.dev.yml at the repository root.
#   Needs yq (mikefarah, v4). Reads the files only; no container runtime needed.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
if [ "$#" -gt 0 ]; then
  files=("$@")
else
  files=("$root/docker-compose.yml" "$root/docker-compose.dev.yml")
fi
command -v yq >/dev/null 2>&1 || { echo "FAIL: yq not found" >&2; exit 1; }

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
ok() {
  echo "  ok: $*"
}

guacd_re='^guacamole/guacd:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$'

for file in "${files[@]}"; do
  [ -f "$file" ] || { fail "compose file not found: $file"; continue; }
  name="$(basename "$file")"
  yq -e '.services' "$file" >/dev/null 2>&1 || { fail "${name}: no services"; continue; }
  built=0
  for svc in $(yq '.services | keys | .[]' "$file"); do
    has_build="$(yq ".services.\"${svc}\" | has(\"build\")" "$file")"
    image="$(yq ".services.\"${svc}\".image // \"\"" "$file")"
    policy="$(yq ".services.\"${svc}\".pull_policy // \"\"" "$file")"
    if [ "$has_build" = "true" ]; then
      built=$((built + 1))
      svc_ok=1
      if [ "$policy" != "never" ]; then
        fail "${name}: service '${svc}' builds locally but pull_policy is '${policy:-unset}' (must be never)"
        svc_ok=0
      fi
      case "$image" in
        ghcr.io/*|docker.io/*|*/*/*)
          fail "${name}: service '${svc}' builds locally but its image '${image}' carries a registry name"
          svc_ok=0 ;;
      esac
      [ "$svc_ok" -eq 1 ] && ok "${name}: ${svc} builds locally as '${image}' with pull_policy: never"
    fi
    if [ "$svc" = "guacd" ]; then
      if [ "$has_build" = "true" ]; then
        fail "${name}: guacd must reference the upstream image, not build it"
      fi
      if [[ "$image" =~ $guacd_re ]]; then
        ok "${name}: guacd references ${image}"
      else
        fail "${name}: guacd image '${image}' must be guacamole/guacd:<version>@sha256:<64 hex>"
      fi
    fi
  done
  [ "$built" -gt 0 ] || fail "${name}: no locally built service found (wrong file?)"
  if [ "$(yq '.services | has("guacd")' "$file")" != "true" ]; then
    fail "${name}: no guacd service"
  fi
done

if [ "$failures" -gt 0 ]; then
  echo "test_compose_image_refs: ${failures} check(s) failed"
  exit 1
fi
echo "test_compose_image_refs: all checks passed"
