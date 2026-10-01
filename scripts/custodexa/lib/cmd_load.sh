# shellcheck shell=bash
# CX_IMG_ARCH and CX_IMG_SRC are read by lib/images.sh and lib/trust.sh.
# shellcheck disable=SC2034
# custodexa.sh load <bundle>: check an offline image bundle and load it into Docker. Nothing is
# started and the current release is left as it is; install and upgrade then find the images on
# this host. In order, each on its own line:
#   1 the bundle's line in SHA256SUMS next to it
#   2 its architecture (from the file name) is this host's; the release manifest names the config
#     of that architecture, so step 3 also proves the content is built for it
#   3 before loading: every manifest and config in the bundle matches the release manifest
#   4 docker load
#   5 every loaded image carries the ID computed in 3
#   6 who published the images, when the tools and the signing services can be reached
# The IDs are recorded as load.version and load.image_ids in state.json: on the containerd image
# store a loaded tag can only be recognised later by that ID (lib/images.sh, cx_img_try_local).
#
# The signature checks of step 6 are made on the registry's index digests that the release manifest
# names; the loaded content is tied to them only through that manifest. So the publisher is shown
# as verified only when the manifest itself is the publisher's: the one of the unpacked package
# (verified before unpacking), or the one next to the bundle when SHA256SUMS, which lists it, passes
# cosign verify-blob for the release workflow of that version. Unavailable or mismatched signatures
# are warned about and recorded; checksum and content mismatches still stop the load.

CX_LOAD_MF=""       # the release manifest used
CX_LOAD_MF_TRUST="" # package | signed | no-cosign | no-sig | offline | sig-bad

# A package manifest inherits the package signature result recorded for this version's upgrade.
cmd_load_package_trust() { # <version>: called after cx_begin loads the state under the lock
  local record
  [ "$CX_LOAD_MF_TRUST" = package ] || return 0
  [ "$(cx_state_get last_upgrade.to)" = "$1" ] || return 0
  record=$(cx_state_get last_upgrade.package_verification)
  case $record in
    *"signature=mismatch"*) CX_LOAD_MF_TRUST=sig-bad ;;
    *"signature=skip-no-cosign"*) CX_LOAD_MF_TRUST=package-no-cosign ;;
    *"signature=skip-no-sig"*) CX_LOAD_MF_TRUST=package-no-sig ;;
  esac
}

# cmd_load_manifest <version> <bundle folder>: the release manifest of that version, from the
# unpacked package, else the one published next to the bundle (checked against SHA256SUMS there,
# and SHA256SUMS against its signature when cosign is on this host). Returns 1 when there is none.
cmd_load_manifest() {
  local ver=$1 dir=$2 err rc
  if [ -f "$CX_ROOT/releases/$ver/MANIFEST.json" ]; then
    CX_LOAD_MF=$CX_ROOT/releases/$ver/MANIFEST.json CX_LOAD_MF_TRUST=package
    return 0
  fi
  [ -f "$dir/MANIFEST.json" ] || return 1
  cx_bundle_sha_ok "$dir/MANIFEST.json" && rc=0 || rc=$?
  [ "$rc" -eq 0 ] || { [ "$rc" -ne 3 ] && return 1; return 2; }
  CX_LOAD_MF=$dir/MANIFEST.json
  if ! command -v cosign >/dev/null 2>&1; then
    CX_LOAD_MF_TRUST=no-cosign
  elif [ ! -f "$dir/SHA256SUMS.sigstore.json" ]; then
    CX_LOAD_MF_TRUST=no-sig
  elif err=$(cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" \
    --certificate-identity "https://github.com/$CX_SIGNER_REPO/$CX_SIGNER_WORKFLOW@refs/tags/v$ver" \
    --certificate-oidc-issuer "$CX_SIGSTORE_ISSUER" "$dir/SHA256SUMS" 2>&1 >/dev/null); then
    CX_LOAD_MF_TRUST=signed
  elif cx_trust_offline "$err"; then
    CX_LOAD_MF_TRUST=offline
  else
    CX_LOAD_MF_TRUST=sig-bad
  fi
}

cmd_load_fail() { # <message id> [args...]: one FAIL line; the run is recorded as failed and stops
  cx_line FAIL "$(cx_msg "$@")"
  cx_finish failed
  exit "$CX_EXIT_FAILED"
}

cmd_load() {
  local b=${1:-} base ver arch host mf rc t0 n count=0 ids="" size
  [ -n "$b" ] || cx_die "$CX_EXIT_USAGE" load_usage
  if [ ! -f "$b" ]; then
    cx_die "$CX_EXIT_FAILED" load_missing "$b"
  fi
  b=$(readlink -f -- "$b")
  base=${b##*/}
  if [[ ! $base =~ ^custodexa-images-(.+)-(amd64|arm64)\.tar$ ]]; then
    cx_die "$CX_EXIT_USAGE" load_bad_name "$base"
  fi
  ver=${BASH_REMATCH[1]} arch=${BASH_REMATCH[2]}
  cmd_load_manifest "$ver" "${b%/*}" && rc=0 || rc=$?
  case $rc in
    0) ;;
    2) cx_die "$CX_EXIT_FAILED" load_manifest_sum_bad ;;
    *) cx_die "$CX_EXIT_FAILED" load_no_manifest "$ver" "${b%/*}" ;;
  esac
  mf=$CX_LOAD_MF
  cx_manifest_load "$mf" || exit "$CX_EXIT_FAILED"

  cx_begin load
  cmd_load_package_trust "$ver"
  # For the recovery command after an interruption; a path the state file cannot hold is left out.
  cx_state_set load.bundle "$b" 2>/dev/null || true
  cx_log VERIFY "manifest $mf $CX_LOAD_MF_TRUST"
  [ "$CX_LOAD_MF_TRUST" != sig-bad ] || cx_log VERIFY "manifest signature MISMATCH source unverified"
  size=$(stat -c %s -- "$b")
  printf '%s\n%s\n\n' "$(cx_msg load_title)" "$(cx_msg load_file "$b" "$(cx_size_human "$size")")"

  cx_step 1
  cx_bundle_sha_ok "$b" && rc=0 || rc=$?
  case $rc in
    0) cx_line OK "$(cx_msg load_sum_ok)" ;;
    1) cmd_load_fail load_sum_none "${b%/*}" ;;
    2) cmd_load_fail load_sum_unlisted "${b%/*}" ;;
    *) cmd_load_fail load_sum_bad ;;
  esac

  cx_step 2
  host=$(cx_arch) || host=$(uname -m)
  [ "$arch" = "$host" ] || cmd_load_fail load_arch_bad "$arch" "$host" "custodexa-images-$ver-$host.tar"
  cx_line OK "$(cx_msg load_arch_ok "$arch")"

  cx_step 3
  CX_IMG_ARCH=$arch
  cx_img_needed ""
  cx_bundle_check "$b" || cmd_load_fail load_check_bad "$CX_BUNDLE_ERR"
  for n in "${CX_IMG_NAMES[@]}"; do
    [ -n "${CX_IMG_BUNDLE_ID[$n]+x}" ] && count=$((count + 1))
  done
  [ "$count" -gt 0 ] || cmd_load_fail load_empty "$ver"

  cx_step 4
  t0=$(cx_now)
  cx_log_run docker load -q -i "$b" >/dev/null || cmd_load_fail load_failed
  cx_line_timed OK "$(cx_msg load_loaded "$count")" "$(cx_duration $(($(cx_now) - t0)))"

  cx_step 5
  cx_bundle_verify_loaded || cmd_load_fail load_id_bad "$CX_BUNDLE_BAD"
  cx_line OK "$(cx_msg load_digests_ok)"
  local -a loaded=()
  for n in "${CX_IMG_NAMES[@]}"; do
    [ -n "${CX_IMG_BUNDLE_ID[$n]+x}" ] || continue
    loaded+=("$n")
    CX_IMG_SRC["$n"]=offline
    ids+="${ids:+ }$n=${CX_IMG_BUNDLE_ID[$n]}"
  done
  CX_IMG_NAMES=("${loaded[@]}")

  cx_step 6
  cx_trust_check
  # A manifest that is not the publisher's cannot tie the checks above to what was loaded.
  case $CX_LOAD_MF_TRUST in
    package | signed) ;;
    sig-bad)
      CX_TRUST_SIG=mismatch
      [ "$CX_TRUST_PROV" = mismatch ] || CX_TRUST_PROV=skip:mf-sig-bad
      cx_log VERIFY "manifest signature MISMATCH | image_sig $(cx_trust_logword "$CX_TRUST_SIG") | provenance $(cx_trust_logword "$CX_TRUST_PROV")"
      ;;
    package-*)
      [ "$CX_TRUST_SIG" = mismatch ] || CX_TRUST_SIG=skip:$CX_LOAD_MF_TRUST
      [ "$CX_TRUST_PROV" = mismatch ] || CX_TRUST_PROV=skip:$CX_LOAD_MF_TRUST
      cx_log VERIFY "package signature not verified ($CX_LOAD_MF_TRUST): publisher checks not tied to the loaded images"
      ;;
    *)
      [ "$CX_TRUST_SIG" = mismatch ] || CX_TRUST_SIG=skip:mf-$CX_LOAD_MF_TRUST
      [ "$CX_TRUST_PROV" = mismatch ] || CX_TRUST_PROV=skip:mf-$CX_LOAD_MF_TRUST
      cx_log VERIFY "manifest not verified ($CX_LOAD_MF_TRUST): publisher checks not tied to the loaded images"
      ;;
  esac
  cx_state_set load.version "$ver"
  cx_state_set load.image_ids "$ids"
  cx_state_set load.verification "$(cx_trust_state)"
  cx_finish succeeded

  local pkg=${b%/*}/custodexa-$ver.tar.gz
  if [ "$CX_TRUST_SIG" = ok ] && [ "$CX_TRUST_PROV" = ok ]; then
    cx_line OK "$(cx_msg load_trust_ok)"
  else
    if [ "$CX_TRUST_SIG" != ok ]; then
      cx_line WARN "$(cx_wrap "$CX_WRAP" "$(cx_msg load_trust_skip "$(cx_msg trust_name_sig)" "$(cx_trust_reason "$CX_TRUST_SIG")")")"
    else
      cx_line WARN "$(cx_wrap "$CX_WRAP" "$(cx_msg load_trust_skip "$(cx_msg trust_name_prov)" "$(cx_trust_reason "$CX_TRUST_PROV")")")"
    fi
    printf '\n%s\n' "$(cx_msg text_load_unverified)"
  fi
  printf '\n%s\n' "$(cx_msg load_next)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh install"
  printf '%s\n' "$(cx_msg load_next_upgrade)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $pkg"
}
