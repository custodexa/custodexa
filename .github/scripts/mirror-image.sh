#!/usr/bin/env bash
# mirror-image.sh - copy one image index to a repository under the given tags, keeping its
# digest, and refuse anything that would overwrite a released version or publish "latest".
#
# Usage:
#   mirror-image.sh <source-repository> <target-repository> <index-digest> <tag>...
#
#   <source-repository>  e.g. ghcr.io/custodexa/backend (no tag, no digest)
#   <target-repository>  e.g. docker.io/custodexa/backend; may equal the source repository,
#                        which tags the digest in place
#   <index-digest>       sha256:<64 hex>, the index to copy
#   <tag>...             X.Y.Z, X.Y.Z-<pre-release> or X.Y
#
# Rules:
#   - "latest" is refused before anything is read or written. The Docker Hub mirror never
#     carries "latest" (unprefixed image names resolve to Docker Hub, and older compose files
#     reference custodexa/<component>:latest for locally built images).
#   - A full version tag (X.Y.Z or X.Y.Z-<pre-release>) that already exists in the target with a
#     different digest stops the run before any write. The same digest counts as a re-run.
#   - X.Y is a moving tag and is updated.
#   - After copying, every tag in the target must resolve to <index-digest>.
#
# Needs crane (go-containerregistry); set CRANE to use another binary path. Registry
# credentials come from the usual docker config (docker login).
# Exit status: 0 on success, 1 on refusal or failure, 2 on usage errors.
set -euo pipefail

CRANE="${CRANE:-crane}"

die() {
  echo "mirror-image: $*" >&2
  exit 1
}

[ "$#" -ge 4 ] || { sed -n '2,12p' "$0" >&2; exit 2; }

src="$1"
dst="$2"
digest="$3"
shift 3
tags=("$@")

repo_re='^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$'
for repo in "$src" "$dst"; do
  [[ "$repo" =~ $repo_re ]] || die "'${repo}' is not a repository name without tag or digest"
done
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "'${digest}' is not a sha256 digest"

num='(0|[1-9][0-9]*)'
full_re="^${num}\.${num}\.${num}(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
line_re="^${num}\.${num}$"

# Refuse "latest" and anything unexpected before touching any registry.
for tag in "${tags[@]}"; do
  [ "$tag" != "latest" ] || die "refusing to publish 'latest' to ${dst}"
  if [[ ! "$tag" =~ $full_re ]] && [[ ! "$tag" =~ $line_re ]]; then
    die "refusing unexpected tag '${tag}' (allowed: X.Y.Z, X.Y.Z-<pre-release>, X.Y)"
  fi
done

# current_digest REF: prints the digest REF resolves to, or nothing when the tag does not exist.
# Any other registry error is fatal.
current_digest() {
  local out
  if out="$("$CRANE" digest "$1" 2>&1)"; then
    printf '%s\n' "$out"
    return 0
  fi
  case "$out" in
    *MANIFEST_UNKNOWN*|*NAME_UNKNOWN*|*"404 Not Found"*|*"status code 404"*) return 0 ;;
  esac
  echo "mirror-image: cannot read ${1}: ${out}" >&2
  return 1
}

got="$(current_digest "${src}@${digest}")" || exit 1
[ "$got" = "$digest" ] || die "source ${src}@${digest} not found"

# Pre-check every full version tag before any write.
for tag in "${tags[@]}"; do
  [[ "$tag" =~ $full_re ]] || continue
  existing="$(current_digest "${dst}:${tag}")" || exit 1
  if [ -n "$existing" ] && [ "$existing" != "$digest" ]; then
    die "${dst}:${tag} already exists with digest ${existing}; released versions are never overwritten (wanted ${digest})"
  fi
done

for tag in "${tags[@]}"; do
  existing="$(current_digest "${dst}:${tag}")" || exit 1
  if [ "$existing" = "$digest" ]; then
    echo "  ok: ${dst}:${tag} already at ${digest}"
    continue
  fi
  "$CRANE" copy "${src}@${digest}" "${dst}:${tag}"
  after="$(current_digest "${dst}:${tag}")" || exit 1
  [ "$after" = "$digest" ] || die "${dst}:${tag} resolves to '${after}' after copy, expected ${digest}"
  echo "  ok: ${dst}:${tag} -> ${digest}"
done
