# shellcheck shell=bash
# Integrity checks shared by the deployment script and the release pipeline.
# The release job verifies its own draft with this file, so what CI accepts is exactly what a
# deployment host accepts.

# cx_tree_sha256 <dir>: one checksum for a folder of files: sha256 over the sorted list of
# "<sha256>  <path>" lines for regular files and "<target>  <path> -> " lines for symlinks.
# Ownership, modes and times are left out so that unpacking on another host gives the same value.
cx_tree_sha256() {
  (
    cd "$1" || exit 1
    export LC_ALL=C
    {
      find . -type f -print0 | sort -z | xargs -0 -r sha256sum
      find . -type l -print0 | sort -z | while IFS= read -r -d '' l; do
        printf '%s  %s -> \n' "$(readlink "$l")" "$l"
      done
    } | sha256sum | cut -d' ' -f1
  )
}

# ---------- release assets ----------
# One release is one set of files, checked as a whole before it is published and again by whoever
# downloads it:
#   custodexa-<ver>.tar.gz  custodexa-images-<ver>-amd64.tar  custodexa-images-<ver>-arm64.tar
#   MANIFEST.json  get-custodexa.sh  SHA256SUMS  SHA256SUMS.sigstore.json
readonly CX_SIGSTORE_ISSUER=https://token.actions.githubusercontent.com

# cx_verify_release_assets <dir> <signer identity> [<image-digests.json>]
# Checks, reporting every failure by name: the signature bundle verifies SHA256SUMS for exactly that
# workflow identity; SHA256SUMS lists every file of the set once, nothing else, and every checksum
# matches; the standalone MANIFEST.json is byte for byte the one inside the package; with
# image-digests.json (needs jq), the MANIFEST's version and own image digests are the published ones.
cx_verify_release_assets() {
  (
    dir=$1 identity=$2 digests=${3:-}
    failed=0
    bad() { printf 'verify: FAIL %s\n' "$*" >&2; failed=1; }
    cd "$dir" || { bad "no folder $dir"; exit 1; }
    pkgs=(custodexa-*.tar.gz)
    if [ "${#pkgs[@]}" -ne 1 ] || [ ! -f "${pkgs[0]}" ]; then
      bad "expected exactly one custodexa-<version>.tar.gz, found: ${pkgs[*]}"
      exit 1
    fi
    ver=${pkgs[0]#custodexa-}
    ver=${ver%.tar.gz}
    expected="SHA256SUMS SHA256SUMS.sigstore.json MANIFEST.json get-custodexa.sh custodexa-$ver.tar.gz custodexa-images-$ver-amd64.tar custodexa-images-$ver-arm64.tar"
    for f in $expected; do
      [ -f "$f" ] || bad "missing: $f"
    done
    for f in * .[!.]*; do
      [ -e "$f" ] || continue
      case " $expected " in *" $f "*) ;; *) bad "not part of a release: $f" ;; esac
    done
    if [ ! -f SHA256SUMS ] || [ ! -f SHA256SUMS.sigstore.json ]; then
      exit 1
    fi

    if ! cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$identity" \
      --certificate-oidc-issuer "$CX_SIGSTORE_ISSUER" SHA256SUMS >/dev/null 2>&1; then
      bad "SHA256SUMS signature does not verify for $identity"
    fi

    declare -A listed=()
    n=0
    # shellcheck disable=SC2094 # the loop only reads SHA256SUMS; bad() writes to stderr
    while IFS= read -r line || [ -n "$line" ]; do
      n=$((n + 1))
      if [[ ! $line =~ ^[0-9a-f]{64}\ [\ *]([A-Za-z0-9._-]+)$ ]]; then
        bad "SHA256SUMS line $n is not '<sha256>  <file name>'"
        continue
      fi
      f=${BASH_REMATCH[1]}
      [ -z "${listed[$f]+x}" ] || bad "SHA256SUMS lists $f twice"
      listed[$f]=1
      case $f in
        SHA256SUMS | SHA256SUMS.sigstore.json) bad "SHA256SUMS lists itself or its signature: $f" ;;
        *) case " $expected " in *" $f "*) ;; *) bad "SHA256SUMS lists a file that is not part of the release: $f" ;; esac ;;
      esac
    done <SHA256SUMS
    for f in $expected; do
      case $f in SHA256SUMS | SHA256SUMS.sigstore.json) continue ;; esac
      [ -n "${listed[$f]+x}" ] || bad "SHA256SUMS does not list $f"
    done
    if ! sha256sum --check --strict --quiet SHA256SUMS >/dev/null 2>&1; then
      bad "checksum mismatch: $(sha256sum --check --strict SHA256SUMS 2>/dev/null | grep -v ': OK$' | tr '\n' ' ')"
    fi

    if ! tar -xzOf "custodexa-$ver.tar.gz" "custodexa/releases/$ver/MANIFEST.json" 2>/dev/null | cmp -s - MANIFEST.json; then
      bad "MANIFEST.json differs from custodexa/releases/$ver/MANIFEST.json inside custodexa-$ver.tar.gz"
    fi

    if [ -n "$digests" ]; then
      [ "$(jq -r .version MANIFEST.json)" = "$ver" ] || bad "MANIFEST.json version is not $ver"
      [ "$(jq -r .version "$digests")" = "$ver" ] || bad "image-digests.json version is not $ver"
      for c in backend frontend; do
        [ "$(jq -r --arg c "$c" '.images[$c].index_digest' MANIFEST.json)" = "$(jq -r --arg c "$c" '.images[$c].digest' "$digests")" ] \
          || bad "MANIFEST.json $c digest is not the published one"
      done
    fi
    [ "$failed" -eq 0 ] && printf 'verify: release %s: signature, checksums, file list and MANIFEST all consistent\n' "$ver"
    exit "$failed"
  )
}
