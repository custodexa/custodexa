# shellcheck shell=bash
# CX_UP_* are read by the upgrade libraries sourced below and by the tests.
# shellcheck disable=SC2034
# custodexa.sh upgrade: the three ways to call it, and the hand-over to the target version's script.
#
#   upgrade                    check for a newer version, change nothing
#   upgrade <version>          download, verify, hand over
#   upgrade <package .tar.gz>  verify, hand over
#
# The upgrade itself always runs in the target version's script: an older script only obtains and
# verifies the new package. A script that sits in releases/<v>/ while current points elsewhere takes
# <v> as its target (it was handed over to).
# Nothing is written in the deployment folder before the preview is answered, except the verified
# package being unpacked under releases/.
# shellcheck source=lib/version_rules.sh
. "${BASH_SOURCE[0]%/*}/version_rules.sh"
# shellcheck source=lib/upgrade_query.sh
. "${BASH_SOURCE[0]%/*}/upgrade_query.sh"
# shellcheck source=lib/upgrade_preflight.sh
. "${BASH_SOURCE[0]%/*}/upgrade_preflight.sh"
# shellcheck source=lib/upgrade_output.sh
. "${BASH_SOURCE[0]%/*}/upgrade_output.sh"
# shellcheck source=lib/drain_gate.sh
. "${BASH_SOURCE[0]%/*}/drain_gate.sh"
# shellcheck source=lib/stop_check.sh
. "${BASH_SOURCE[0]%/*}/stop_check.sh"
# shellcheck source=lib/health.sh
. "${BASH_SOURCE[0]%/*}/health.sh"
# shellcheck source=lib/upgrade_steps.sh
. "${BASH_SOURCE[0]%/*}/upgrade_steps.sh"

# CX_UP_DOWNLOAD (the releases address) is set by lib/upgrade_query.sh.
CX_UP_KIND=package
CX_UP_CURRENT="" # the version running now
CX_UP_TARGET=""
CX_UP_PKG_DIR="" # the unpacked release (releases/<v>/ inside the package) after cx_up_fetch

# cx_up_handed_over: print <v> when this script is <root>/releases/<v>/ and current is another one.
cx_up_handed_over() {
  local cur
  [ "${CX_DIR%/*}" = "$CX_ROOT/releases" ] || return 1
  cur=$(readlink -f -- "$CX_ROOT/current" 2>/dev/null) || cur=""
  [ "$cur" != "$CX_DIR" ] || return 1
  printf '%s' "${CX_DIR##*/}"
}

# cx_up_current_version: the version running now.
cx_up_current_version() { cx_state_get current.version; }

# cx_up_is_package <arg>: the argument names a package file.
cx_up_is_package() { [[ ${1##*/} =~ ^custodexa-[0-9A-Za-z.-]+\.tar\.gz$ ]]; }

# cx_up_no_deployment: this folder holds an unpacked package but no deployment. Point at the running
# one when the backend container says where compose started it.
cx_up_no_deployment() {
  local dir
  cx_line FAIL "$(cx_msg up_no_deployment "$CX_ROOT")"
  dir=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' \
    custodexa-backend 2>/dev/null) || dir=""
  if [ -n "$dir" ] && cx_check_root_path "$dir"; then
    printf '%s\n' "$(cx_msg up_no_deployment_running "$dir")"
    cx_cmd "CUSTODEXA_HOME=$dir sudo -E $CX_SELF upgrade"
  fi
  exit "$CX_EXIT_REFUSED"
}

# cx_up_handoff_args: the options to pass to the target script (language and the run's answers).
cx_up_handoff_args() {
  CX_UP_ARGS=()
  [ -z "${CX_LANG_FLAG:-}" ] || CX_UP_ARGS+=(--lang "$CX_LANG_FLAG")
  [ "${CX_YES:-0}" != 1 ] || CX_UP_ARGS+=(--yes)
  [ "${CX_NO_COLOR:-0}" != 1 ] || CX_UP_ARGS+=(--no-color)
  [ -z "${CX_IMAGES:-}" ] || CX_UP_ARGS+=(--images "$CX_IMAGES")
  [ "${CX_IMAGES_FROM_GIVEN:-0}" != 1 ] || CX_UP_ARGS+=(--images-from "$CX_IMAGES_FROM")
  [ -z "${CX_BACKUP_REF:-}" ] || CX_UP_ARGS+=(--backup-ref "$CX_BACKUP_REF")
  [ -z "${CX_BACKUP_TIME:-}" ] || CX_UP_ARGS+=(--backup-time "$CX_BACKUP_TIME")
  [ -z "${CX_BACKUP_RESTORE:-}" ] || CX_UP_ARGS+=(--backup-restore "$CX_BACKUP_RESTORE")
}

# cx_up_handoff: run the target version's script on this deployment; it does the upgrade. The
# version is passed on, so the target script never takes a bare call for a check or a refusal.
cx_up_handoff() {
  local -a CX_UP_ARGS
  cx_up_handoff_args
  cx_log HANDOFF "to=${CX_UP_PKG_DIR#"$CX_ROOT"/} version=$CX_UP_TARGET"
  CUSTODEXA_HOME=$CX_ROOT exec bash "$CX_UP_PKG_DIR/custodexa.sh" upgrade "$CX_UP_TARGET" "${CX_UP_ARGS[@]}"
}

cmd_upgrade() {
  local arg=${1:-} self rel
  [ $# -le 1 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$2"
  self=$(cx_script_version)
  [ -f "$CX_ROOT/state.json" ] || cx_up_no_deployment
  cx_state_load "$CX_ROOT/state.json"
  if rel=$(cx_up_handed_over); then
    self=$rel
    [ -n "$arg" ] || arg=$rel
  fi
  if [ -z "$arg" ]; then
    cx_up_query
    return
  fi
  CX_UP_CURRENT=$(cx_up_current_version)
  if [ "$arg" = "$self" ]; then
    CX_UP_TARGET=$self
    cx_up_run
    return
  fi
  cx_up_fetch "$arg" || exit "$?"
  cx_up_handoff
}

# ---------- obtaining and verifying a package ----------

# cx_up_fetch <version | package path>: CX_UP_TARGET and CX_UP_PKG_DIR, verified and unpacked.
cx_up_fetch() {
  local arg=$1 ts inc pkg dir ver rc
  ts=$(date '+%Y%m%d-%H%M%S')
  if cx_vr_valid "$arg"; then
    ver=$arg
  elif cx_up_is_package "$arg" && [ -f "$arg" ]; then
    ver=${arg##*/custodexa-}
    ver=${ver%.tar.gz}
    cx_vr_valid "$ver" || { cx_line FAIL "$(cx_msg up_not_target "$arg")"; return "$CX_EXIT_USAGE"; }
  else
    cx_line FAIL "$(cx_msg up_not_target "$arg")"
    return "$CX_EXIT_USAGE"
  fi
  # An older or the same version is refused before anything is downloaded or unpacked.
  cx_vr_check "$CX_UP_CURRENT" "$ver" || return "$?"
  inc=$CX_ROOT/releases/.incoming-$ts
  (umask 022 && mkdir -p "$inc") || { cx_line FAIL "$(cx_msg up_incoming_failed "$inc")"; return "$CX_EXIT_FAILED"; }
  if [ "$arg" = "$ver" ]; then
    cx_up_download "$ver" "$inc" || { rm -rf "$inc"; return "$CX_EXIT_FAILED"; }
    pkg=$inc/custodexa-$ver.tar.gz dir=$inc
  else
    pkg=$(readlink -f -- "$arg") dir=${pkg%/*}
  fi
  cx_up_verify_package "$pkg" "$dir" "$ver" || { rm -rf "$inc"; return "$CX_EXIT_FAILED"; }
  if ! tar -xzf "$pkg" -C "$inc" "custodexa/releases/$ver" 2>/dev/null \
    || [ "$(tr -d '[:space:]' <"$inc/custodexa/releases/$ver/VERSION" 2>/dev/null)" != "$ver" ]; then
    cx_line FAIL "$(cx_msg up_pkg_layout "$pkg" "$ver")"
    rm -rf "$inc"
    return "$CX_EXIT_FAILED"
  fi
  # The target's minimum source version, from its own MANIFEST, before the release is put in place.
  if ! cx_manifest_load "$inc/custodexa/releases/$ver/MANIFEST.json"; then
    rm -rf "$inc"
    return "$CX_EXIT_FAILED"
  fi
  cx_vr_check "$CX_UP_CURRENT" "$ver" "$(cx_mf min_source_version)" || { rc=$?; rm -rf "$inc"; return "$rc"; }
  CX_UP_TARGET=$ver
  CX_UP_PKG_DIR=$inc/custodexa/releases/$ver
  cx_up_place_release "$inc" "$ver"
}

# cx_up_place_release <incoming dir> <version>: move the unpacked release to releases/<v>/. One that
# is there already (an earlier attempt) is used only when it holds exactly the same files.
cx_up_place_release() {
  local inc=$1 ver=$2 dst=$CX_ROOT/releases/$2
  if [ -e "$dst" ]; then
    if [ "$(cx_tree_sha256 "$dst")" != "$(cx_tree_sha256 "$inc/custodexa/releases/$ver")" ]; then
      cx_line FAIL "$(cx_msg up_release_differs "$dst")"
      rm -rf "$inc"
      return "$CX_EXIT_FAILED"
    fi
  else
    mv -- "$inc/custodexa/releases/$ver" "$dst" || { rm -rf "$inc"; return "$CX_EXIT_FAILED"; }
  fi
  rm -rf "$inc"
  CX_UP_PKG_DIR=$dst
}

# cx_up_download <version> <dir>: the package, SHA256SUMS and optional signature bundle.
cx_up_download() {
  local ver=$1 dir=$2 f
  for f in "custodexa-$ver.tar.gz" SHA256SUMS; do
    cx_line RUN "$(cx_msg up_wait_download "$f")"
    if ! curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 -o "$dir/$f" "$CX_UP_DOWNLOAD/download/v$ver/$f" 2>/dev/null; then
      cx_line FAIL "$(cx_msg up_download_failed "$ver")"
      cx_cmd "sudo $CX_SELF upgrade /path/custodexa-$ver.tar.gz"
      return 1
    fi
    cx_line OK "$(cx_msg up_download_ok "$f")"
  done
  cx_line RUN "$(cx_msg up_wait_download SHA256SUMS.sigstore.json)"
  curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 -o "$dir/SHA256SUMS.sigstore.json" "$CX_UP_DOWNLOAD/download/v$ver/SHA256SUMS.sigstore.json" 2>/dev/null || rm -f "$dir/SHA256SUMS.sigstore.json"
}

# cx_up_verify_package <package> <dir with SHA256SUMS> <version>: layer 1 (the checksum, always) and
# layer 2 (the publisher signature over SHA256SUMS, when cosign is on this host).
cx_up_verify_package() {
  local pkg=$1 dir=$2 ver=$3 name want got identity
  name=${pkg##*/}
  cx_line RUN "$(cx_msg up_wait_checksum "$name")"
  if [ ! -f "$dir/SHA256SUMS" ]; then
    cx_line FAIL "$(cx_msg up_pkg_no_sums "$dir/SHA256SUMS")"
    return 1
  fi
  want=$(awk -v f="$name" '$2 == f || $2 == "*"f { print $1; exit }' "$dir/SHA256SUMS")
  got=$(sha256sum -- "$pkg" | cut -d' ' -f1)
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    cx_line FAIL "$(cx_msg up_pkg_sum_bad "$name")"
    return 1
  fi
  cx_line OK "$(cx_msg up_checksum_ok "$name")"
  if ! command -v cosign >/dev/null 2>&1; then
    export CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=skip-no-cosign'
    cx_line WARN "$(cx_msg up_pkg_sig_skip "$name")"
    cx_log VERIFY "package $name checksum OK | signature WARN reason=no-cosign"
    return 0
  fi
  if [ ! -f "$dir/SHA256SUMS.sigstore.json" ]; then
    export CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=skip-no-sig'
    cx_line WARN "$(cx_msg up_pkg_sig_missing "$name")"
    cx_log VERIFY "package $name checksum OK | signature WARN reason=no-sig"
    return 0
  fi
  identity="https://github.com/$CX_SIGNER_REPO/$CX_SIGNER_WORKFLOW@refs/tags/v$ver"
  cx_line RUN "$(cx_msg up_wait_signature)"
  if ! cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" --certificate-identity "$identity" \
    --certificate-oidc-issuer "$CX_SIGSTORE_ISSUER" "$dir/SHA256SUMS" >/dev/null 2>&1; then
    export CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=mismatch'
    cx_line WARN "$(cx_msg up_pkg_sig_bad "$name")"
    cx_log VERIFY "package $name checksum OK | signature MISMATCH"
    return 0
  fi
  export CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=ok'
  cx_line OK "$(cx_msg up_pkg_ok "$name")"
}

# ---------- the upgrade in this script ----------

# cx_up_preview_head: the top of the preview.
cx_up_preview_head() {
  printf '%s\n\n' "$(cx_msg up_title)"
  printf '%s\n' "$(cx_msg up_row_installed "$CX_UP_CURRENT")" "$(cx_msg up_row_target "$CX_UP_TARGET")" \
    "$(cx_msg up_row_root "$CX_ROOT")"
}

# cx_up_run: the upgrade to CX_UP_TARGET by this script. Steps 1 (checks) and 2 (images) run
# before the preview (step 3); the rest after it is answered (lib/upgrade_steps.sh).
cx_up_run() {
  local rc=0 t0
  # An unfinished or failed earlier run first: after a switch, current.version already names the
  # target, and its recovery commands matter more than the version rules.
  cx_up_pre_unfinished || exit "$?"
  # Older and same version need no MANIFEST to be refused.
  cx_vr_check "$CX_UP_CURRENT" "$CX_UP_TARGET" || exit "$?"
  cx_manifest_load "$CX_DIR/MANIFEST.json" || exit "$CX_EXIT_FAILED"
  cx_vr_check "$CX_UP_CURRENT" "$CX_UP_TARGET" "$(cx_mf min_source_version)" || rc=$?
  [ "$rc" -eq 0 ] || exit "$rc"
  t0=$(cx_now)
  cx_up_preflight || exit "$?"
  CX_UP_D1=$(cx_duration $(($(cx_now) - t0)))
  cx_up_images || exit "$?"
  cx_up_preview_head
  cx_up_preview_body
  printf '\n'
  if ! cx_confirm up_confirm; then
    printf '%s\n' "$(cx_msg pre_nothing_changed)"
    exit "$CX_EXIT_REFUSED"
  fi
  # --yes answered the question: show it answered, as on the terminal.
  [ "${CX_YES:-0}" != 1 ] || printf '%s y\n' "$(cx_msg up_confirm)"
  printf '\n'
  cx_up_main
}
