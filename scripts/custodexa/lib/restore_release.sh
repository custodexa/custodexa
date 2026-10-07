# shellcheck shell=bash
# Obtain the data release without applying the upgrade's version-direction rules. Preparation
# writes only to the incoming folder; placement and image resolution are called after confirmation.
# The caller loads restore_read.sh first (CX_RS_DIR, CX_RS_TS, CX_RS_VERSION and package helpers).
# shellcheck disable=SC2034,SC2153

CX_RS_RELEASE="" CX_RS_INCOMING="" CX_RS_PACKAGE_NAME="" CX_RS_PACKAGE_CHECK="local"
CX_RS_SIGNATURE="local" CX_RS_DOWNLOAD_CODE=""

cx_rs_release_cleanup() {
  [ -z "$CX_RS_INCOMING" ] || rm -rf -- "$CX_RS_INCOMING"
  CX_RS_INCOMING=""
}
cx_rs_release_bad() {
  local key=$1
  shift
  cx_line FAIL "$(cx_msg "$key" "$@")"
  [ "$key" != rs_release_manifest ] || cx_rs_par "$(cx_msg rs_release_manifest_guide)"
  cx_rs_unchanged
  cx_rs_release_cleanup
  return 1
}

# Like the upgrade download, with the HTTP status retained to distinguish absent release files
# from an unreachable server. A missing optional signature still belongs to signature policy.
cx_rs_download() {
  local ver=$1 dir=$2 name code rc
  for name in "custodexa-$ver.tar.gz" SHA256SUMS SHA256SUMS.sigstore.json; do
    cx_line RUN "$(cx_msg up_wait_download "$name")"
    rc=0
    code=$(curl -sSL --proto '=https' --proto-redir '=https' --retry 2 -w '%{http_code}' \
      -o "$dir/$name" "$CX_UP_DOWNLOAD/download/v$ver/$name" 2>/dev/null) || rc=$?
    if [ "$rc" != 0 ] || [ "$code" != 200 ]; then
      rm -f -- "$dir/$name"
      [ "$name" != SHA256SUMS.sigstore.json ] || return 0
      if [ "$code" = 404 ]; then
        cx_line FAIL "$(cx_msg rs_release_absent "$ver")"
        cx_rs_par "$(cx_msg rs_release_absent_guide "$ver" "$ver")"
        cx_cmd "sudo $(printf '%q' "$CX_SELF") restore $(printf '%q' "$CX_RS_FILE") --package <path>/custodexa-$ver.tar.gz"
        cx_rs_par "$(cx_msg rs_release_other)"
      else
        cx_line FAIL "$(cx_msg rs_release_download "$ver")"
        cx_rs_par "$(cx_msg rs_release_offline "$ver" "$ver")"
      fi
      return 1
    fi
    cx_line OK "$(cx_msg up_download_ok "$name")"
  done
}

# cx_rs_release <version>: verify an existing release, or prepare a checked incoming release.
cx_rs_release() {
  local ver=$1 pkg dir
  CX_RS_RELEASE=$CX_ROOT/releases/$ver
  CX_RS_PACKAGE_NAME="" CX_RS_PACKAGE_CHECK=local CX_RS_SIGNATURE=local
  if [ -d "$CX_RS_RELEASE" ]; then
    if [ "$(cat "$CX_RS_RELEASE/VERSION" 2>/dev/null)" != "$ver" ]; then
      cx_rs_release_bad up_pkg_layout "$CX_RS_RELEASE" "$ver"; return 1
    fi
    if ! cmp -s "$CX_RS_RELEASE/MANIFEST.json" "$CX_RS_DIR/pass2/release-MANIFEST.json"; then
      cx_rs_release_bad rs_release_manifest "$ver"; return 1
    fi
    return 0
  fi
  CX_RS_INCOMING=$(mktemp -d "$CX_ROOT/releases/.incoming-$CX_RS_TS-XXXXXX") || return 1
  if [ -n "${CX_RS_PACKAGE:-}" ]; then
    pkg=$(readlink -f -- "$CX_RS_PACKAGE") || pkg=$CX_RS_PACKAGE
    dir=${pkg%/*}
  else
    cx_rs_download "$ver" "$CX_RS_INCOMING" || {
      cx_rs_unchanged; cx_rs_release_cleanup; return 1;
    }
    pkg=$CX_RS_INCOMING/custodexa-$ver.tar.gz dir=$CX_RS_INCOMING
  fi
  cx_up_verify_package "$pkg" "$dir" "$ver" || {
    cx_rs_unchanged; cx_rs_release_cleanup; return 1;
  }
  CX_RS_PACKAGE_NAME=${pkg##*/} CX_RS_PACKAGE_CHECK=ok
  CX_RS_SIGNATURE=${CX_UP_PACKAGE_VERIFICATION##*signature=}
  CX_RS_RELEASE=$CX_RS_INCOMING/custodexa/releases/$ver
  if ! tar -xzf "$pkg" -C "$CX_RS_INCOMING" "custodexa/releases/$ver" 2>/dev/null ||
    [ "$(cat "$CX_RS_RELEASE/VERSION" 2>/dev/null)" != "$ver" ]; then
    cx_rs_release_bad up_pkg_layout "$pkg" "$ver"; return 1
  fi
  if ! cmp -s "$CX_RS_RELEASE/MANIFEST.json" "$CX_RS_DIR/pass2/release-MANIFEST.json"; then
    cx_rs_release_bad rs_release_manifest "$ver"; return 1
  fi
}

# These two functions are deliberately separate from preparation: the stage engine calls them
# only after the preview has been confirmed, and current is not switched here.
cx_rs_release_place() {
  [ -n "$CX_RS_INCOMING" ] || return 0
  cx_up_place_release "$CX_RS_INCOMING" "$CX_RS_VERSION" || return 1
  CX_RS_INCOMING=""
  CX_RS_RELEASE=$CX_UP_PKG_DIR
}
cx_rs_images() {
  local CX_DIR=$1
  cx_manifest_load "$CX_DIR/MANIFEST.json" || return 1
  cx_images_resolve "$(cx_rs_get deploy.overlays)" || return 1
  cx_images_write_env "$CX_DIR/images.env" && cx_images_write_ids "$CX_DIR/image-ids.env"
}

# The snapshot must contain every data-release migration. Extra entries must be runtime markers
# the engine knows were introduced no later than the data version.
cx_rs_migrations() {
  local i id first bad="" missing=0
  local -A known=() seen=()
  cx_manifest_load "$(cx_rs_metadata)/release-MANIFEST.json" || return 1
  i=0
  while [ -n "$(cx_mf "migrations.$i")" ]; do
    known[$(cx_mf "migrations.$i")]=migration
    i=$((i + 1))
  done
  cx_manifest_load "$CX_DIR/MANIFEST.json" || return 1
  i=0
  while [ -n "$(cx_mf "runtime_markers.$i.id")" ]; do
    id=$(cx_mf "runtime_markers.$i.id") first=$(cx_mf "runtime_markers.$i.first_version")
    if cx_vr_valid "$first" && [ "$(cx_vr_cmp "$first" "$CX_RS_VERSION")" != 1 ]; then
      [ -n "${known[$id]:-}" ] || known[$id]=marker
    fi
    i=$((i + 1))
  done
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    seen[$id]=1
    [ -n "${known[$id]:-}" ] || { bad=$id; break; }
  done < <(sed -n 's/^migration=//p' "$(cx_rs_metadata)/snapshot.txt")
  if [ -z "$bad" ]; then
    for id in "${!known[@]}"; do
      if [ "${known[$id]}" = migration ] && [ -z "${seen[$id]:-}" ]; then bad=$id; missing=1; break; fi
    done
  fi
  if [ -n "$bad" ]; then
    cx_line FAIL "$(cx_msg rs_migration_bad "$CX_RS_VERSION" "$CX_RS_VERSION")"
    if [ "$missing" = 1 ]; then cx_rs_par "$(cx_msg rs_migration_missing "$bad" "$CX_RS_VERSION")"
    else cx_rs_par "$(cx_msg rs_migration_unknown "$bad" "$CX_RS_VERSION")"; fi
    if [ "$missing" = 1 ]; then cx_rs_par "$(cx_msg rs_migration_missing_guide)"
    else cx_rs_par "$(cx_msg rs_migration_guide)"; fi
    cx_rs_unchanged
    return 1
  fi
}
