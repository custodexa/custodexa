# shellcheck shell=bash
# CX_OVERLAYS is read by lib/compose.sh.
# shellcheck disable=SC2034
# `custodexa.sh upgrade` without an argument on a package deployment: what the newest release is and
# whether this deployment can go to it directly. Changes nothing.
# The release's MANIFEST.json, SHA256SUMS and optional signature bundle are downloaded to a temporary
# folder. The MANIFEST's checksum must match SHA256SUMS, or no answer about upgrading is given at all;
# signature checks that cannot run or do not match warn while the query still answers. The number
# of structure changes is the MANIFEST's migrations that this
# database has not applied yet.
# shellcheck source=lib/backup.sh
. "${BASH_SOURCE[0]%/*}/backup.sh"

[ -n "${CX_UP_DOWNLOAD+x}" ] || readonly CX_UP_DOWNLOAD=https://github.com/custodexa/custodexa/releases
CX_Q_VR=0 # 0 checksum and signature verified, 1 checksum only
CX_Q_REASON=""

# cx_q_ind <mark> <text>: a status line 2 columns in, later lines under the text.
cx_q_ind() { printf '  %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'         }"; }

# cx_q_pending: the number of MANIFEST migrations the database does not have; fails when the
# database cannot be read.
cx_q_pending() {
  local applied i=0 n=0 m
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  applied=$(cx_snap_sql "SELECT version FROM schema_migrations" 2>/dev/null) || return 1
  while m=$(cx_mf "migrations.$i") && [ -n "$m" ]; do
    grep -qxF -- "$m" <<<"$applied" || n=$((n + 1))
    i=$((i + 1))
  done
  printf '%s' "$n"
}

# cx_q_verify <dir>: 0 checksum and signature, 1 checksum only, 2 checksum mismatch,
# 3 signature mismatch.
cx_q_verify() {
  local dir=$1 want got ver
  want=$(awk '$2 == "MANIFEST.json" || $2 == "*MANIFEST.json" { print $1; exit }' "$dir/SHA256SUMS")
  got=$(sha256sum -- "$dir/MANIFEST.json" | cut -d' ' -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || return 2
  if ! command -v cosign >/dev/null 2>&1; then
    CX_Q_REASON=no-cosign
    return 1
  fi
  if [ ! -f "$dir/SHA256SUMS.sigstore.json" ]; then
    CX_Q_REASON=no-sig
    return 1
  fi
  ver=$(sed -n 's/^  "version": "\([^"]*\)",\{0,1\}$/\1/p' "$dir/MANIFEST.json" | head -n 1)
  cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" \
    --certificate-identity "https://github.com/$CX_SIGNER_REPO/$CX_SIGNER_WORKFLOW@refs/tags/v$ver" \
    --certificate-oidc-issuer "$CX_SIGSTORE_ISSUER" "$dir/SHA256SUMS" >/dev/null 2>&1 || return 3
}

# cx_q_fetch: the newest release's MANIFEST.json, checked (CX_Q_VR) and loaded. Returns 1 offline,
# 2 checksum mismatch, 4 the manifest does not load (it says why).
cx_q_fetch() {
  local tmp f rc=0
  CX_Q_VR=0
  CX_Q_REASON=""
  tmp=$(mktemp -d)
  for f in MANIFEST.json SHA256SUMS; do
    curl -fsSL --retry 2 -o "$tmp/$f" "$CX_UP_DOWNLOAD/latest/download/$f" 2>/dev/null || { rm -rf "$tmp"; return 1; }
  done
  curl -fsSL --retry 2 -o "$tmp/SHA256SUMS.sigstore.json" "$CX_UP_DOWNLOAD/latest/download/SHA256SUMS.sigstore.json" 2>/dev/null || rm -f "$tmp/SHA256SUMS.sigstore.json"
  cx_q_verify "$tmp" || CX_Q_VR=$?
  if [ "$CX_Q_VR" -eq 2 ]; then
    rm -rf "$tmp"
    return "$CX_Q_VR"
  fi
  cx_manifest_load "$tmp/MANIFEST.json" || rc=4
  rm -rf "$tmp"
  return "$rc"
}

# cx_q_target <installed version>: the version to upgrade to next, from the loaded MANIFEST: the
# newest, or first its minimum source version when the installed one is below it. Nothing and
# non-zero when the installed version is up to date.
cx_q_target() {
  local cur=$1 latest min r
  latest=$(cx_mf version) min=$(cx_mf min_source_version)
  r=$(cx_vr_cmp "$latest" "$cur") || return 1
  [ "$r" = 1 ] || return 1
  if [ -n "$min" ] && [ "$(cx_vr_cmp "$cur" "$min")" = -1 ]; then
    printf '%s' "$min"
  else
    printf '%s' "$latest"
  fi
}

# cx_q_latest: the version the check suggests, printed alone, for the main menu. Nothing and
# non-zero when there is none: up to date, offline, or the release manifest checksum mismatches.
cx_q_latest() {
  cx_q_fetch >/dev/null 2>&1 || return 1
  cx_q_target "$(cx_state_get current.version)"
}

cx_up_query() {
  local rc=0 vr latest cur min pending r target
  cur=$(cx_state_get current.version)
  cx_q_fetch || rc=$?
  case $rc in
    0) ;;
    1)
      cx_line FAIL "$(cx_msg q_offline)"
      cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade /path/custodexa-<version>.tar.gz"
      printf '\n%s\n' "$(cx_msg q_only)"
      exit "$CX_EXIT_FAILED"
      ;;
    2)
      printf '%s\n\n' "$(cx_msg q_installed "$cur" "$CX_ROOT")"
      cx_q_ind FAIL "$(cx_msg "q_verify_fail_$rc")"
      printf '\n%s\n' "$(cx_msg q_only)"
      exit "$CX_EXIT_FAILED"
      ;;
    *) exit "$CX_EXIT_FAILED" ;;
  esac
  vr=$CX_Q_VR
  latest=$(cx_mf version) min=$(cx_mf min_source_version)
  printf '%s\n' "$(cx_msg q_installed "$cur" "$CX_ROOT")" \
    "$(cx_msg q_latest "$latest" "$(cx_mf released_at | cut -c1-10)")"
  printf '\n'
  r=$(cx_vr_cmp "$latest" "$cur") || r=bad
  if [ "$r" != 1 ]; then
    cx_q_ind OK "$(cx_msg q_up_to_date)"
  elif [ -n "$min" ] && [ "$(cx_vr_cmp "$cur" "$min")" = -1 ]; then
    cx_q_ind FAIL "$(cx_msg vr_skip "$latest" "$cur" "$min")"
  else
    cx_q_ind OK "$(cx_msg q_direct "$latest" "${min:-$cur}")"
    if ! pending=$(cx_q_pending); then
      cx_q_ind WARN "$(cx_msg q_migrations_unknown)"
    elif [ "$pending" -eq 0 ]; then
      cx_q_ind OK "$(cx_msg q_migrations_none)"
    elif [ "$pending" -eq 1 ]; then
      cx_q_ind WARN "$(cx_msg q_migrations_one)"
    else
      cx_q_ind WARN "$(cx_msg q_migrations_many "$pending")"
    fi
  fi
  printf '\n'
  if [ "$vr" -eq 0 ]; then
    cx_q_ind OK "$(cx_msg q_verified)"
  elif [ "$vr" -eq 3 ]; then
    cx_q_ind WARN "$(cx_msg q_verify_fail_3)"
  elif [ "$CX_Q_REASON" = no-sig ]; then
    cx_q_ind WARN "$(cx_msg q_no_sig)"
  else
    cx_q_ind WARN "$(cx_msg q_unverified)"
  fi
  printf '%s\n' "$(cx_msg q_notes "https://github.com/custodexa/custodexa/releases/tag/v$latest")"
  if target=$(cx_q_target "$cur"); then
    printf '\n%s\n' "$(cx_msg q_run)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $target"
  fi
  printf '\n%s\n' "$(cx_msg q_only)"
}
