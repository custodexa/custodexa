#!/usr/bin/env bash
# image-tags.sh - derive the image tags to publish for one release tag.
#
# Usage:
#   image-tags.sh <git-tag> <VERSION-file-content> [existing-release-tags]
#
#   <git-tag>                the tag that triggered the release, e.g. v1.13.0 or v1.13.0-rc.1
#   <VERSION-file-content>   content of the VERSION file at that commit (whitespace ignored)
#   [existing-release-tags]  whitespace- or newline-separated list of git tags already in the
#                            repository (e.g. the output of `git tag -l 'v*'`). Only final
#                            releases (vX.Y.Z) are considered; pre-releases and anything
#                            that does not parse are ignored. The triggering tag itself may
#                            be included; it never counts as "higher than itself".
#
# Output (key=value lines, suitable for $GITHUB_OUTPUT):
#   stable=true|false        true for a final release vX.Y.Z, false for a pre-release
#   version=<version>        the version without the leading "v" (X.Y.Z or X.Y.Z-<pre>)
#   version_build_arg=<v>    empty for a final release (the image reads the VERSION file);
#                            the full pre-release version otherwise
#   ghcr_tags=<tags>         space-separated tags for the primary registry
#   dockerhub_tags=<tags>    space-separated tags for the Docker Hub mirror; empty for
#                            pre-releases. Never contains "latest".
#
# Rules:
#   - A final release always gets X.Y.Z. It gets X.Y only when no existing final release in
#     the same X.Y line is higher, and "latest" (primary registry only) only when no existing
#     final release at all is higher. No major-only tag is ever produced.
#   - A pre-release gets only its full version on the primary registry and is not mirrored.
#   - Docker Hub never receives "latest": unprefixed image names resolve to Docker Hub, and
#     older compose files reference custodexa/<component>:latest for locally built images.
#   - The X.Y.Z part of the tag must equal the VERSION file; otherwise the script fails before
#     anything is built or pushed.
#
# Exit status: 0 on success, 1 on invalid input or a tag/VERSION mismatch.
set -euo pipefail

die() {
  echo "image-tags: $*" >&2
  exit 1
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || die "usage: image-tags.sh <git-tag> <VERSION-file-content> [existing-release-tags]"

git_tag="$1"
version_file="$(printf '%s' "$2" | tr -d ' \t\r\n')"
existing="${3:-}"

num='(0|[1-9][0-9]*)'
pre_ident='[0-9A-Za-z-]+'
release_re="^v${num}\.${num}\.${num}$"
prerelease_re="^v${num}\.${num}\.${num}-${pre_ident}(\.${pre_ident})*$"

if [[ "$git_tag" =~ $release_re ]]; then
  stable=true
elif [[ "$git_tag" =~ $prerelease_re ]]; then
  stable=false
else
  die "tag '${git_tag}' is not vX.Y.Z or vX.Y.Z-<pre-release>"
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
version="${git_tag#v}"
base="${major}.${minor}.${patch}"

[ -n "$version_file" ] || die "VERSION file content is empty"
if [ "$base" != "$version_file" ]; then
  die "tag ${git_tag} (version ${base}) does not match VERSION file (${version_file})"
fi

# Docker tags allow at most 128 characters from [A-Za-z0-9_.-].
[ "${#version}" -le 128 ] || die "version '${version}' is longer than 128 characters"

# is_higher A B: true when final release A (major minor patch) is strictly higher than B.
is_higher() {
  local a1="$1" a2="$2" a3="$3" b1="$4" b2="$5" b3="$6"
  [ "$a1" -gt "$b1" ] && return 0
  [ "$a1" -lt "$b1" ] && return 1
  [ "$a2" -gt "$b2" ] && return 0
  [ "$a2" -lt "$b2" ] && return 1
  [ "$a3" -gt "$b3" ]
}

if [ "$stable" = false ]; then
  echo "stable=false"
  echo "version=${version}"
  echo "version_build_arg=${version}"
  echo "ghcr_tags=${version}"
  echo "dockerhub_tags="
  exit 0
fi

highest_overall=true
highest_in_line=true
for tag in $existing; do
  [[ "$tag" =~ $release_re ]] || continue
  e1="${BASH_REMATCH[1]}"
  e2="${BASH_REMATCH[2]}"
  e3="${BASH_REMATCH[3]}"
  if is_higher "$e1" "$e2" "$e3" "$major" "$minor" "$patch"; then
    highest_overall=false
    if [ "$e1" = "$major" ] && [ "$e2" = "$minor" ]; then
      highest_in_line=false
    fi
  fi
done

ghcr="${base}"
dockerhub="${base}"
if [ "$highest_in_line" = true ]; then
  ghcr="${ghcr} ${major}.${minor}"
  dockerhub="${dockerhub} ${major}.${minor}"
fi
if [ "$highest_overall" = true ]; then
  ghcr="${ghcr} latest"
fi

echo "stable=true"
echo "version=${version}"
echo "version_build_arg="
echo "ghcr_tags=${ghcr}"
echo "dockerhub_tags=${dockerhub}"
