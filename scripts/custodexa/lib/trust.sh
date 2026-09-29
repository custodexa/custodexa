# shellcheck shell=bash
# The CX_TRUST_* results are read by the install command.
# shellcheck disable=SC2034
# Who published the images. Checksums and content digests are always checked (lib/images.sh); on top
# of that, when the tools are on this host and the signing services can be reached:
#   signature    cosign verify <ghcr ref>@<index digest>, signer = the release workflow of this tag
#   provenance   gh attestation verify oci://<ghcr ref>@<index digest> --repo custodexa/custodexa
# A layer that cannot run is skipped and said so, with the commands to run elsewhere; a layer that
# runs and fails stops the install. Only the project's own images carry these; upstream images are
# pinned by digest.

readonly CX_SIGNER_REPO=custodexa/custodexa
readonly CX_SIGNER_WORKFLOW=.github/workflows/release-images.yml
CX_TRUST_SIG=""   # ok | skip:<reason> | fail
CX_TRUST_PROV=""
declare -ga CX_TRUST_IMAGES=() # own images obtained from a publisher source (not built here)

cx_trust_identity() { printf 'https://github.com/%s/%s@refs/tags/v%s' "$CX_SIGNER_REPO" "$CX_SIGNER_WORKFLOW" "$(cx_mf version)"; }

# cx_trust_offline <error text>: the service could not be reached (as opposed to a failed check).
cx_trust_offline() {
  case $1 in
    *"no such host"* | *"i/o timeout"* | *"connection refused"* | *"network is unreachable"* | *"Timeout exceeded"* | *"TLS handshake timeout"*) return 0 ;;
  esac
  return 1
}

# cx_trust_run <layer: sig|prov>: sets CX_TRUST_SIG or CX_TRUST_PROV.
cx_trust_run() {
  local layer=$1 tool n ref d err result=ok
  case $layer in sig) tool=cosign ;; prov) tool=gh ;; esac
  if [ "${#CX_TRUST_IMAGES[@]}" -eq 0 ]; then
    result=skip:local-build
  elif ! command -v "$tool" >/dev/null 2>&1; then
    result=skip:no-$tool
  else
    for n in "${CX_TRUST_IMAGES[@]}"; do
      ref=$(cx_mf "images.$n.ref") d=$(cx_mf "images.$n.index_digest")
      if [ "$layer" = sig ]; then
        err=$(cosign verify "$ref@$d" --certificate-identity "$(cx_trust_identity)" \
          --certificate-oidc-issuer "$CX_SIGSTORE_ISSUER" 2>&1 >/dev/null) && continue
      else
        err=$(gh attestation verify "oci://$ref@$d" --repo "$CX_SIGNER_REPO" 2>&1 >/dev/null) && continue
      fi
      cx_log VERIFY "$layer $n FAIL $(printf '%s' "$err" | tail -n1)"
      if cx_trust_offline "$err"; then
        result=skip:offline
      elif [ "$layer" = prov ] && [[ $err == *"gh auth login"* || $err == *"GH_TOKEN"* ]]; then
        result=skip:gh-login
      else
        result=fail
        break
      fi
    done
  fi
  if [ "$layer" = sig ]; then CX_TRUST_SIG=$result; else CX_TRUST_PROV=$result; fi
}

# cx_trust_check: run both layers for the own images that were not built here.
cx_trust_check() {
  local n
  CX_TRUST_IMAGES=()
  for n in "${CX_IMG_NAMES[@]}"; do
    cx_img_upstream "$n" && continue
    [ "${CX_IMG_SRC[$n]:-}" = build ] && continue
    CX_TRUST_IMAGES+=("$n")
  done
  cx_trust_run sig
  cx_trust_run prov
  cx_log VERIFY "checksum OK | image_sig $(cx_trust_logword "$CX_TRUST_SIG") | provenance $(cx_trust_logword "$CX_TRUST_PROV")"
}
cx_trust_logword() {
  case $1 in
    ok) printf 'OK' ;;
    fail) printf 'FAIL' ;;
    skip:*) printf 'SKIP reason=%s' "${1#skip:}" ;;
  esac
}

# cx_trust_state: the value of current.verification in state.json.
cx_trust_state() { printf 'checksum=ok signature=%s provenance=%s' "${CX_TRUST_SIG//:/-}" "${CX_TRUST_PROV//:/-}"; }

# cx_trust_summary: the words in the closing line of step 3.
cx_trust_summary() {
  if [ "$CX_TRUST_SIG" = ok ] && [ "$CX_TRUST_PROV" = ok ]; then
    cx_msg ver_all
  elif [ "$CX_TRUST_SIG" = ok ]; then
    cx_msg ver_sig_only
  else
    cx_msg ver_checksum_only
  fi
}

cx_trust_reason() { # <skip:reason>
  case ${1#skip:} in
    no-cosign) cx_msg trust_no_cosign ;;
    no-gh) cx_msg trust_no_gh ;;
    offline) cx_msg trust_offline ;;
    gh-login) cx_msg trust_gh_login ;;
    local-build) cx_msg trust_local_build ;;
    mf-*) cx_msg trust_mf_unverified "$(cx_trust_mf_why "${1#skip:mf-}")" ;;
  esac
}
cx_trust_mf_why() { # why the release manifest next to an offline bundle is not verified (load)
  case $1 in
    no-cosign) cx_msg trust_no_cosign ;;
    offline) cx_msg trust_offline ;;
    *) cx_msg trust_mf_no_sig ;;
  esac
}

# cx_trust_failed: a layer ran and did not verify: print why and return 0.
cx_trust_failed() {
  [ "$CX_TRUST_SIG" = fail ] || [ "$CX_TRUST_PROV" = fail ] || return 1
  if [ "$CX_TRUST_SIG" = fail ]; then
    cx_sub FAIL "$(cx_msg trust_sig_bad "$(cx_trust_identity)")"
  else
    cx_sub FAIL "$(cx_msg trust_prov_bad "$CX_SIGNER_REPO")"
  fi
  return 0
}

# cx_trust_screen: when a layer was skipped, say what was and was not checked, list the commands
# to run elsewhere with full digests, and ask whether to go on. Returns 0 to go on.
cx_trust_screen() {
  local n ref d
  case "$CX_TRUST_SIG $CX_TRUST_PROV" in "ok ok") return 0 ;; esac
  printf '\n%s %s\n\n' "$(cx_mark ASK)" "$(cx_msg trust_title)"
  printf '  %s %s\n' "$(cx_mark OK)" "$(cx_msg trust_row_checksum)"
  cx_trust_row sig "$CX_TRUST_SIG"
  cx_trust_row prov "$CX_TRUST_PROV"
  printf '\n%s\n' "$(cx_msg text_trust_explain)"
  for n in "${CX_TRUST_IMAGES[@]}"; do
    ref=$(cx_mf "images.$n.ref") d=$(cx_mf "images.$n.index_digest")
    if [ "$CX_TRUST_SIG" != ok ]; then
      printf '\n    cosign verify %s@%s \\\n' "$ref" "$d"
      printf '      --certificate-identity "%s" \\\n' "$(cx_trust_identity)"
      printf '      --certificate-oidc-issuer "%s"\n' "$CX_SIGSTORE_ISSUER"
    fi
    if [ "$CX_TRUST_PROV" != ok ]; then
      printf '\n    gh attestation verify oci://%s@%s \\\n' "$ref" "$d"
      printf '      --repo %s\n' "$CX_SIGNER_REPO"
    fi
  done
  printf '\n%s\n\n' "$(cx_msg trust_recorded)"
  cx_confirm trust_continue
}
cx_trust_row() { # <sig|prov> <result>
  local label
  label=$(cx_msg "trust_label_$1")
  if [ "$2" = ok ]; then
    printf '  %s %s%s\n' "$(cx_mark OK)" "$label" "$(cx_msg trust_verified)"
  else
    printf '  %s %s%s\n' "$(cx_mark SKIP)" "$label" "$(cx_trust_reason "$2")"
  fi
}
