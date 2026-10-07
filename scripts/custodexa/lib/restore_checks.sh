# shellcheck shell=bash
# Additional checks over the verified metadata. No database is started and no release is fetched.
# shellcheck disable=SC2034
CX_RS_KEY_FP=""
cx_rs_refuse() { local k=$1; shift; cx_line FAIL "$(cx_msg "$k" "$@")"; cx_rs_unchanged; return 1; }

# The backend accepts 32 raw bytes first, then trimmed raw, hex and strict base64 (standard or
# URL alphabet, with or without padding). Binary material stays in the private working folder.
cx_rs_key_fingerprint() {
  local material=$1 value escaped="" i h canonical
  local LC_ALL=C
  CX_RS_KEY_FP=""
  value=$material
  if [ "${#value}" != 32 ]; then
    value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
  fi
  case ${#value} in
    32) printf '%s' "$value" >"$CX_RS_DIR/key.raw" ;;
    64)
      [[ $value != *[!0-9a-fA-F]* ]] || return 1
      for ((i=0; i<64; i+=2)); do escaped+="\\x${value:i:2}"; done
      printf '%b' "$escaped" >"$CX_RS_DIR/key.raw" ;;
    43|44)
      [[ $value =~ ^[A-Za-z0-9+/_-]{43}=?$ ]] || return 1
      [[ $value != *'+'* && $value != *'/'* ]] || [[ $value != *'-'* && $value != *'_'* ]] || return 1
      value=${value//-/+} value=${value//_/\/}
      value=${value%=}=
      printf '%s' "$value" | base64 -d >"$CX_RS_DIR/key.raw" 2>/dev/null || return 1
      canonical=$(base64 -w0 <"$CX_RS_DIR/key.raw")
      [ "$canonical" = "$value" ] || return 1 ;;
    *) return 1 ;;
  esac
  [ "$(wc -c <"$CX_RS_DIR/key.raw")" -eq 32 ] || return 1
  h=$(sha256sum "$CX_RS_DIR/key.raw") || return 1
  CX_RS_KEY_FP=${h:0:16}
  rm -f "$CX_RS_DIR/key.raw"
}
cx_rs_checks() {
  local provider env fp key value
  env=$(cx_rs_metadata)/env.bak
  cx_vr_valid "$CX_RS_VERSION" || { cx_rs_bad manifest product.version; return 1; }
  # Keep this before all other additional checks, including missing fingerprints and downloads.
  if [ "$(cx_vr_cmp "$CX_RS_VERSION" 1.16.0)" = -1 ]; then
    cx_line FAIL "$(cx_msg rs_data_old "$CX_RS_VERSION")"
    cx_rs_par "$CX_RS_FILE"
    cx_rs_par "$(cx_msg rs_data_old_guide "$CX_RS_VERSION")"
    cx_rs_unchanged
    return 1
  fi
  if [ "$(cx_vr_cmp "$CX_RS_ENGINE" "$CX_RS_VERSION")" = -1 ]; then
    cx_line FAIL "$(cx_msg rs_engine_old "$CX_RS_ENGINE" "$CX_RS_VERSION")"
    cx_rs_par "$(cx_msg rs_engine_old_guide "$CX_RS_VERSION" "$CX_RS_VERSION")"
    cx_rs_unchanged
    return 1
  fi
  if [ "$(cx_rs_get kek.fingerprint_status)" != ok ]; then
    cx_line FAIL "$(cx_msg rs_fp_missing)"
    cx_rs_par "$(cx_msg rs_fp_manual)"
    cx_rs_unchanged
    return 1
  fi
  provider=$(cx_rs_get kek.provider)
  [ "$provider" != hsm ] || { cx_rs_refuse rs_hsm; return 1; }
  if [ "$provider" = env ]; then
    if ! cx_rs_key_fingerprint "$(cx_env_get "$env" ENCRYPTION_KEY)"; then cx_rs_bad secret ENCRYPTION_KEY; return 1; fi
    if [ "$CX_RS_KEY_FP" != "$(cx_rs_get kek.fingerprint)" ]; then
      cx_line FAIL "$(cx_msg rs_key_mismatch)"
      cx_rs_par "$(cx_msg rs_key_fingerprints "$CX_RS_KEY_FP" "$(cx_rs_get kek.fingerprint)")"
      cx_rs_par "$(cx_msg rs_key_wrong)"
      cx_rs_unchanged
      return 1
    fi
    cx_line OK "$(cx_msg rs_key_ok "$CX_RS_KEY_FP")"
  fi
  fp=$(cx_snap_get "$(cx_rs_metadata)/snapshot.txt" fp.jwt)
  if [ -n "$fp" ]; then
    [ "$fp" = "$(cx_snap_fp "$(cx_env_get "$env" JWT_SECRET)")" ] || { cx_rs_bad jwt; return 1; }
    cx_line OK "$(cx_msg rs_jwt_ok)"
  else
    cx_line ' -- ' "$(cx_msg rs_jwt_unknown)"
  fi
  for key in JWT_SECRET DB_PASSWORD $([ "$provider" != env ] || echo ENCRYPTION_KEY); do
    value=$(cx_env_get "$env" "$key")
    case $value in ''|change-me*|changeme|CHANGE_ME|your-*|custodexa_password) cx_rs_bad secret "$key"; return 1 ;; esac
  done
  # The roles an external database's grants name are checked on its server (lib/restore_external.sh).
  [ "$(cx_rs_get db.location)" = external ] || cx_rs_grants || return 1
  CX_PB_PASS=""
  [ "$CX_RS_VERIFY_ONLY" != 1 ] || return 0
  cx_rs_read_timed extracted "$(cx_msg rs_extracted "$CX_RS_DIR/")" "$(cx_duration "$CX_RS_EXTRACT_TIME")"
}
