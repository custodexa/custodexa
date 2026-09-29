#!/usr/bin/env bash
# verify-image.sh - check the release contract of one platform of a built image.
#
# Usage:
#   verify-image.sh --component backend|frontend --platform linux/<arch> --version <version>
#                   [--revision <git-sha> --source <repository-url>] [--source-root <dir>]
#                   [--pull] <image-reference>
#
# Checks (all of them run; every failure is reported before the script exits non-zero):
#   - the image config for the requested platform reports that OS and architecture
#   - /usr/share/doc/custodexa/ holds LICENSE, NOTICE, THIRD-PARTY-LICENSES.md and licenses/,
#     byte-identical (sha256) to the same files under --source-root (default: repository root)
#   - label org.opencontainers.image.licenses is AGPL-3.0-only
#   - with --revision/--source: labels org.opencontainers.image.revision, .source and
#     .version equal the given revision, source URL and --version
#   - backend: no shell interpreter exists at /bin/sh, /bin/ash, /bin/bash, /usr/bin/sh;
#     /root/custodexa and /usr/local/bin/sqlcmd are linux binaries for the requested
#     architecture, and /root/custodexa carries -X main.Version=<version>
#   - frontend: /usr/share/nginx/html/index.html exists
#
# Files are copied out of a created (never started) container, so the checks do not depend on
# a shell inside the image. Go build metadata is read with `go version -m` inside a pinned Go
# toolchain image ($GO_IMAGE), which runs on the host architecture.
#
# Exit status: 0 when every check passes, 1 when any check fails, 2 on usage errors.
set -uo pipefail

# Pinned by index digest as well as tag: this toolchain reads the GOARCH and version guards, so a
# rebuilt tag must not change what they see. Digest checked 2026-09-29 with
# `docker buildx imagetools inspect golang:1.26.6-alpine`.
GO_IMAGE="${GO_IMAGE:-golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83}"
LICENSE_LABEL="AGPL-3.0-only"
DOC_DIR="/usr/share/doc/custodexa"

usage() {
  sed -n '2,8p' "$0" >&2
  exit 2
}

component=""
platform=""
version=""
revision=""
source_url=""
source_root="$(cd "$(dirname "$0")/../.." && pwd)"
pull=0
image=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --component) component="${2:-}"; shift ;;
    --platform) platform="${2:-}"; shift ;;
    --version) version="${2:-}"; shift ;;
    --revision) revision="${2:-}"; shift ;;
    --source) source_url="${2:-}"; shift ;;
    --source-root) source_root="${2:-}"; shift ;;
    --pull) pull=1 ;;
    -h|--help) usage ;;
    -*) echo "verify-image: unknown option $1" >&2; usage ;;
    *) [ -z "$image" ] || usage; image="$1" ;;
  esac
  shift
done

case "$component" in backend|frontend) ;; *) echo "verify-image: --component must be backend or frontend" >&2; usage ;; esac
case "$platform" in linux/amd64|linux/arm64) ;; *) echo "verify-image: --platform must be linux/amd64 or linux/arm64" >&2; usage ;; esac
[ -n "$version" ] || { echo "verify-image: --version is required" >&2; usage; }
[ -n "$image" ] || { echo "verify-image: image reference is required" >&2; usage; }
if [ -n "$revision" ] || [ -n "$source_url" ]; then
  [ -n "$revision" ] && [ -n "$source_url" ] || { echo "verify-image: --revision and --source go together" >&2; usage; }
fi
[ -d "$source_root" ] || { echo "verify-image: source root not found: $source_root" >&2; exit 2; }
arch="${platform#linux/}"

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
ok() {
  echo "  ok: $*"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

work="$(mktemp -d)"
cid=""
go_cid=""
cleanup() {
  [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
  [ -n "$go_cid" ] && docker rm -f "$go_cid" >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

echo "== verify ${component} ${platform} ${image} (expected version ${version}) =="

if [ "$pull" -eq 1 ]; then
  docker pull --quiet --platform "$platform" "$image" >/dev/null || { fail "cannot pull ${image} for ${platform}"; exit 1; }
fi

# `docker image inspect --platform` needs a recent CLI. Without it, inspect reads the only
# platform present, which is the case after `docker pull --platform` into a classic image
# store; the platform check below then still catches a mismatch.
inspect_args=()
if docker image inspect --help 2>/dev/null | grep -q -- '--platform'; then
  inspect_args=(--platform "$platform")
fi

# 1. Platform recorded in the image config.
got_platform="$(docker image inspect ${inspect_args[@]+"${inspect_args[@]}"} --format '{{.Os}}/{{.Architecture}}' "$image" 2>&1)" || {
  fail "cannot inspect ${image} for ${platform}: ${got_platform}"
  exit 1
}
if [ "$got_platform" = "$platform" ]; then
  ok "image config platform ${got_platform}"
else
  fail "image config platform is ${got_platform}, expected ${platform}"
fi

# 2. Labels.
label() {
  docker image inspect ${inspect_args[@]+"${inspect_args[@]}"} \
    --format "{{ index .Config.Labels \"$1\" }}" "$image" 2>/dev/null
}
got_license="$(label org.opencontainers.image.licenses)"
if [ "$got_license" = "$LICENSE_LABEL" ]; then
  ok "label org.opencontainers.image.licenses=${got_license}"
else
  fail "label org.opencontainers.image.licenses is '${got_license}', expected '${LICENSE_LABEL}'"
fi
if [ -n "$revision" ]; then
  for pair in "revision=${revision}" "source=${source_url}" "version=${version}"; do
    key="${pair%%=*}"
    want="${pair#*=}"
    got="$(label "org.opencontainers.image.${key}")"
    if [ "$got" = "$want" ]; then
      ok "label org.opencontainers.image.${key}=${got}"
    else
      fail "label org.opencontainers.image.${key} is '${got}', expected '${want}'"
    fi
  done
fi

# 3. Files, copied out of a created container.
# stderr is kept apart from the container ID: on a host without the image cached, docker prints
# its pull progress to stderr, which must not end up in the ID.
cid="$(docker create --platform "$platform" "$image" 2>"$work/create.err")" || {
  fail "cannot create a container from ${image}: $(cat "$work/create.err")"
  cid=""
  exit 1
}

mkdir -p "$work/doc"
if docker cp "${cid}:${DOC_DIR}/." "$work/doc/" >/dev/null 2>&1; then
  for f in LICENSE NOTICE THIRD-PARTY-LICENSES.md; do
    if [ ! -f "$work/doc/$f" ]; then
      fail "${DOC_DIR}/${f} is missing"
    elif [ "$(sha256_of "$work/doc/$f")" != "$(sha256_of "$source_root/$f")" ]; then
      fail "${DOC_DIR}/${f} differs from ${f} in the source tree (sha256 mismatch)"
    else
      ok "${DOC_DIR}/${f} matches the source tree"
    fi
  done
  if [ ! -d "$work/doc/licenses" ]; then
    fail "${DOC_DIR}/licenses/ is missing"
  else
    want_list="$(cd "$source_root/licenses" && find . -type f | LC_ALL=C sort)"
    got_list="$(cd "$work/doc/licenses" && find . -type f | LC_ALL=C sort)"
    if [ "$want_list" != "$got_list" ]; then
      fail "${DOC_DIR}/licenses/ file list differs from licenses/ in the source tree"
      diff <(printf '%s\n' "$want_list") <(printf '%s\n' "$got_list") | sed 's/^/    /'
    fi
    lic_bad=0
    while IFS= read -r rel; do
      [ -n "$rel" ] || continue
      [ -f "$work/doc/licenses/$rel" ] || continue
      if [ "$(sha256_of "$work/doc/licenses/$rel")" != "$(sha256_of "$source_root/licenses/$rel")" ]; then
        fail "${DOC_DIR}/licenses/${rel#./} differs from the source tree (sha256 mismatch)"
        lic_bad=1
      fi
    done <<<"$want_list"
    [ "$lic_bad" -eq 0 ] && [ "$want_list" = "$got_list" ] && ok "${DOC_DIR}/licenses/ matches the source tree ($(printf '%s\n' "$want_list" | grep -c .) files)"
  fi
else
  fail "${DOC_DIR}/ is missing"
fi

if [ "$component" = "frontend" ]; then
  if docker cp "${cid}:/usr/share/nginx/html/index.html" "$work/index.html" >/dev/null 2>&1; then
    ok "/usr/share/nginx/html/index.html present"
  else
    fail "/usr/share/nginx/html/index.html is missing"
  fi
fi

if [ "$component" = "backend" ]; then
  # 4. No shell interpreter (existence, not only executability).
  for sh_path in /bin/sh /bin/ash /bin/bash /usr/bin/sh; do
    if docker cp "${cid}:${sh_path}" - >/dev/null 2>&1; then
      fail "${sh_path} exists in the backend image"
    else
      ok "${sh_path} absent"
    fi
  done

  # 5. Target architecture and version of the binaries built by this project.
  mkdir -p "$work/bin"
  bins_ok=1
  docker cp "${cid}:/root/custodexa" "$work/bin/custodexa" >/dev/null 2>&1 || { fail "/root/custodexa is missing"; bins_ok=0; }
  docker cp "${cid}:/usr/local/bin/sqlcmd" "$work/bin/sqlcmd" >/dev/null 2>&1 || { fail "/usr/local/bin/sqlcmd is missing"; bins_ok=0; }
  if [ "$bins_ok" -eq 1 ]; then
    go_cid="$(docker create "$GO_IMAGE" go version -m /x/custodexa /x/sqlcmd 2>"$work/go-create.err")" || {
      fail "cannot create ${GO_IMAGE} container: $(cat "$work/go-create.err")"
      go_cid=""
    }
    if [ -n "$go_cid" ]; then
      docker cp "$work/bin/." "${go_cid}:/x/" >/dev/null
      meta="$(docker start -a "$go_cid" 2>&1)"
      printf '%s\n' "$meta" > "$work/go-version-m.txt"
      for bin in custodexa sqlcmd; do
        section="$(printf '%s\n' "$meta" | awk -v f="/x/${bin}:" '$1 == f {on=1; next} /^\/x\// {on=0} on')"
        if [ -z "$section" ]; then
          fail "no Go build information in ${bin}"
          continue
        fi
        got_arch="$(printf '%s\n' "$section" | awk '$1 == "build" && $2 ~ /^GOARCH=/ {sub(/^GOARCH=/, "", $2); print $2}')"
        got_os="$(printf '%s\n' "$section" | awk '$1 == "build" && $2 ~ /^GOOS=/ {sub(/^GOOS=/, "", $2); print $2}')"
        if [ "$got_arch" = "$arch" ] && [ "$got_os" = "linux" ]; then
          ok "${bin} built for ${got_os}/${got_arch}"
        else
          fail "${bin} built for ${got_os:-?}/${got_arch:-?}, expected linux/${arch}"
        fi
        if [ "$bin" = "custodexa" ]; then
          got_version="$(printf '%s\n' "$section" | sed -n 's/.*-X main\.Version=\([^ "]*\).*/\1/p' | head -n1)"
          if [ "$got_version" = "$version" ]; then
            ok "custodexa reports version ${got_version}"
          else
            fail "custodexa reports version '${got_version}', expected '${version}'"
          fi
        fi
      done
    fi
  fi
fi

if [ "$failures" -gt 0 ]; then
  echo "== ${failures} check(s) failed for ${component} ${platform} =="
  exit 1
fi
echo "== all checks passed for ${component} ${platform} =="
