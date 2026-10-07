# shellcheck shell=bash
# Preview uses the reader, release preparation, merged host values and space estimates.
# shellcheck disable=SC2034,SC2153
CX_RS_PAD="" CX_RS_OTHER_HOST=0 CX_RS_COUNTS_KNOWN=0 CX_RS_AUDIT="" CX_RS_SESSIONS=""
CX_RS_CERT_WARNING=""
cx_rs_row() {
  local label=$1 value=$2 prefix=$CX_RS_PAD
  [ "$label" = - ] || prefix=$(cx_msg "rs_label_$label")
  printf '%s%s\n' "$prefix" "${value//$'\n'/$'\n'$CX_RS_PAD}"
}
cx_rs_size() { cx_size_human "$1" | sed 's/\.0 / /'; }
cx_rs_number() {
  local n=$1 out=""
  while [ "${#n}" -gt 3 ]; do out=,${n: -3}$out; n=${n:0:${#n}-3}; done
  printf '%s%s' "$n" "$out"
}
cx_rs_preview_counts() {
  CX_RS_OTHER_HOST=0 CX_RS_COUNTS_KNOWN=0
  [ "$(cx_rs_get source.hostname)" = "$(cx_env_host_fqdn)" ] || CX_RS_OTHER_HOST=1
  [ "$CX_RS_FLOW" = same ] || return 0
  cx_bk_vars
  CX_RS_AUDIT=$(cx_snap_sql 'SELECT count(*) FROM audit_logs' 2>/dev/null) || return 0
  CX_RS_SESSIONS=$(cx_snap_sql 'SELECT count(*) FROM sessions' 2>/dev/null) || return 0
  [[ $CX_RS_AUDIT =~ ^[0-9]+$ && $CX_RS_SESSIONS =~ ^[0-9]+$ ]] || return 0
  CX_RS_COUNTS_KNOWN=1
}

# Provided certificates stay untouched. Only their public leaf is read, using the engine's
# pinned tool. An unreadable certificate is described as unchecked, not as an address match.
cx_rs_cert_check() {
  local value option
  CX_RS_CERT_WARNING=""
  if [ "$(cx_rs_get deploy.tls_mode)" != provided ] || [ "$(cx_rs_get contents.tls)" != true ]; then return 0; fi
  if ! cx_rs_openssl_image >/dev/null ||
    ! tar -xOzf "$CX_RS_DIR/pass2/tls.tar.gz" tls/fullchain.pem >"$CX_RS_DIR/cert.pem" 2>/dev/null; then
    CX_RS_CERT_WARNING=unknown; return 0
  fi
  if ! cx_rs_cert_tool -ext subjectAltName >"$CX_RS_DIR/cert-san.txt" 2>/dev/null; then
    CX_RS_CERT_WARNING=unknown; return 0
  fi
  if [ -n "${CX_RS_HOST_VALUES[TLS_DOMAIN]}" ]; then
    if ! grep -q 'DNS:' "$CX_RS_DIR/cert-san.txt" ||
      ! cx_rs_cert_matches -checkhost "${CX_RS_HOST_VALUES[TLS_DOMAIN]}"; then CX_RS_CERT_WARNING=mismatch; fi
  fi
  option=-checkip
  local -a ips=()
  IFS=, read -r -a ips <<<"${CX_RS_HOST_VALUES[TLS_IP_SAN]}"
  for value in "${ips[@]}"; do
    [ -z "$value" ] || cx_rs_cert_matches "$option" "$value" || CX_RS_CERT_WARNING=mismatch
  done
}
cx_rs_cert_matches() {
  local result
  result=$(cx_rs_cert_tool "$@" 2>/dev/null) || return 1
  # x509 can exit successfully after reporting a name mismatch; require its positive result.
  [[ $result == *" does match certificate" ]]
}
cx_rs_cert_tool() {
  docker run --rm --pull never --network none --log-driver none \
    --name "custodexa-restore-tool-$CX_RS_TS-cert" -v "$CX_RS_DIR:/work:ro" \
    --entrypoint openssl "$CX_RS_OPENSSL" x509 -in /work/cert.pem -noout "$@"
}
cx_rs_preview_package() {
  if [ "$CX_RS_PACKAGE_CHECK" = ok ]; then cx_rs_row - "$(cx_msg rs_package_checked "$CX_RS_PACKAGE_NAME")"
  else cx_rs_row - "$(cx_msg rs_package_local)"; fi
  case $CX_RS_SIGNATURE in
    ok) cx_rs_row - "$(cx_msg rs_signature_ok)" ;;
    skip-no-cosign) cx_rs_row - "$(cx_msg rs_signature_no_cosign)" ;;
    skip-no-sig) cx_rs_row - "$(cx_msg rs_signature_no_bundle)" ;;
    mismatch) cx_rs_row - "$(cx_msg rs_signature_bad)"; cx_rs_row - "$(cx_msg up_pkg_sig_bad "$CX_RS_PACKAGE_NAME")" ;;
    *) cx_rs_row - "$(cx_msg rs_signature_local)" ;;
  esac
  cx_rs_row - "$(cx_msg rs_manifest_identical)"
  if [ -n "${CX_IMAGES:-}" ]; then
    cx_rs_row - "$(cx_msg rs_preview_images_offline "${#CX_IMG_NAMES[@]}" "${CX_IMAGES##*/}")"
  elif [ "${CX_IMAGES_FROM:-auto}" = source ]; then
    cx_rs_row - "$(cx_msg rs_preview_images_source "${#CX_IMG_NAMES[@]}")"
  elif [ "${CX_RS_IMAGES_MISSING:-1}" = 0 ]; then
    cx_rs_row - "$(cx_msg rs_preview_images_local "${#CX_IMG_NAMES[@]}")"
  else
    cx_rs_row - "$(cx_msg rs_preview_images_auto "${#CX_IMG_NAMES[@]}")"
  fi
}
cx_rs_preview_hosts() {
  local key first=host changed=0
  for key in DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL; do
    case $key in TLS_DOMAIN|TLS_IP_SAN) [ -n "$(cx_rs_get deploy.tls_mode)" ] || continue ;; esac
    if [ "$CX_RS_FLOW" = new ]; then
      cx_rs_row "$first" "$(printf '%-16s %s' "$key" "${CX_RS_HOST_VALUES[$key]}")"
      first=-
    elif [ "${CX_RS_HOST_VALUES[$key]}" != "${CX_RS_HOST_SOURCE[$key]}" ]; then
      [ "$changed" = 1 ] || cx_rs_row - "$(cx_msg rs_host_differences)"
      cx_rs_row - "$(cx_msg rs_host_difference "$key" "${CX_RS_HOST_SOURCE[$key]}" "${CX_RS_HOST_VALUES[$key]}")"
      changed=1
    fi
  done
  [ "$CX_RS_REISSUE" != 1 ] || cx_rs_row - "$(cx_msg rs_reissue)"
  case $CX_RS_CERT_WARNING in
    mismatch) cx_rs_row - "$(cx_msg rs_cert_mismatch)" ;;
    unknown) cx_rs_row - "$(cx_msg rs_cert_unknown)" ;;
  esac
}
cx_rs_preview_template() {
  [ -n "$CX_RS_TEMPLATE" ] || return 0
  cx_rs_row - "$(cx_msg rs_preview_template "$CX_RS_TEMPLATE")"
  [ "$CX_RS_TEMPLATE_CHANGED" != 1 ] || cx_rs_row - "$(cx_msg rs_template_repointed)"
  [ -z "$CX_RS_TEMPLATE_KEEP" ] || cx_rs_row - "$(cx_msg rs_template_keep "$CX_RS_TEMPLATE_KEEP")"
}
cx_rs_preview() {
  local created host provider tls restores n label current encrypted="" kept="" counts
  CX_RS_PAD='                 '
  [ "$CX_LANG" != zh-TW ] || CX_RS_PAD='             '
  created=$(cx_rs_get created_at); created=${created:0:16}; created=${created/T/ }
  host=$(cx_rs_get source.hostname) provider=$(cx_rs_get kek.provider) tls=$(cx_rs_get deploy.tls_mode)
  current=$(cx_state_get current.version)
  cx_rs_preview_counts
  cx_rs_cert_check
  printf '\n'
  if [ "$CX_RS_FLOW" = new ]; then printf '%s\n' "$(cx_msg rs_preview_new)"
  else cx_line WARN "$(cx_msg rs_preview_same)"; fi
  printf '\n'
  cx_rs_row backup "$CX_RS_FILE"
  if [ "$CX_RS_ENC" = 1 ]; then encrypted=$(cx_msg rs_preview_encrypted); else encrypted=$(cx_msg rs_preview_plain); fi
  if [ "$CX_RS_FLOW" = same ] && [ "$CX_RS_OTHER_HOST" = 0 ]; then
    cx_rs_row - "$(cx_msg rs_backup_here "$created" "$host")"
    [ "$CX_RS_ENC" != 1 ] || cx_rs_row - "$encrypted"
  else cx_rs_row - "$(cx_msg rs_backup_source "$created" "$host" "$encrypted")"; fi
  cx_rs_row - "$(cx_msg rs_backup_integrity)"
  if [ "$CX_RS_FLOW" = new ]; then
    cx_rs_row data_version "$(cx_msg rs_data_engine "$CX_RS_VERSION" "$CX_RS_ENGINE")"
    cx_rs_row install "$CX_RS_VERSION"
  else
    if [ "$current" = "$CX_RS_VERSION" ]; then cx_rs_row version "$(cx_msg rs_versions "$current" "$CX_RS_VERSION")"
    else cx_rs_row version "$(cx_msg rs_versions_changed "$current" "$CX_RS_VERSION")"; fi
    if [ "$CX_RS_OTHER_HOST" = 1 ]; then
      cx_rs_par "$(cx_msg rs_other_host "$host")"
    fi
  fi
  cx_rs_preview_package
  if cx_rs_ext; then label=rs_deployment_external; else label=rs_deployment; fi
  cx_rs_row deployment "$(cx_msg "$label" "$(cx_msg "rs_tls_${tls:-external}")" "$(cx_msg "rs_provider_$provider")")"
  if [ "$CX_RS_FLOW" = new ]; then
    restores=$(cx_msg rs_restores_new "$(cx_rs_size "$(cx_rs_get size.db_bytes)")" "$(cx_rs_size "$(cx_rs_get size.audit_bytes)")")
  else restores=$(cx_msg rs_restores_same); fi
  [ "$(cx_rs_get contents.tls)" != true ] || restores+="$(cx_msg rs_restores_tls)"
  cx_rs_row restores "$restores"
  if [ "$CX_RS_FLOW" = same ]; then
    if [ -n "$tls" ]; then cx_rs_row - "$(cx_msg rs_settings_same)"
    else cx_rs_row - "$(cx_msg rs_settings_same_external)"; fi
  fi
  cx_rs_preview_template
  [ "$CX_RS_FLOW" != same ] || cx_rs_preview_hosts
  if [ "$(cx_rs_get contents.recordings)" = true ]; then cx_rs_row recordings "$(cx_msg rs_recordings_restore)"
  elif [ "$CX_RS_FLOW" = same ]; then cx_rs_row recordings "$(cx_msg rs_recordings_kept)"
  else cx_rs_row recordings "$(cx_msg rs_recordings_missing "$(cx_rs_size "$(cx_rs_get size.recordings_bytes)")")"; fi
  [ "$CX_RS_FLOW" != new ] || cx_rs_preview_hosts
  if [ "$CX_RS_FLOW" = same ]; then
    cx_rs_row replaced "$(cx_msg rs_replaced)"
    if [ "$CX_RS_COUNTS_KNOWN" = 0 ]; then cx_rs_row - "$(cx_msg rs_counts_unknown)"
    else
      counts=$(cx_msg rs_counts_current "$(cx_rs_number "$CX_RS_AUDIT")" "$(cx_rs_number "$CX_RS_SESSIONS")")
      if [ "$CX_RS_OTHER_HOST" = 0 ]; then
        counts+="$(cx_msg rs_counts_backup "$(cx_rs_number "$(cx_snap_get "$CX_RS_DIR/pass2/snapshot.txt" count.audit_logs)")" \
          "$(cx_rs_number "$(cx_snap_get "$CX_RS_DIR/pass2/snapshot.txt" count.sessions)")")"
      fi
      cx_rs_row - "$counts"
      [ "$CX_RS_OTHER_HOST" != 0 ] || cx_rs_row - "$(cx_msg rs_counts_caution)"
    fi
    ! cx_rs_ext || cx_rs_ext_preview_db
    if [ -n "${CX_BACKUP_REF:-}" ]; then cx_rs_row safety "$(cx_msg rs_safety_own "$CX_BACKUP_REF" "$CX_BACKUP_TIME")"
    else cx_rs_row safety "$(cx_msg rs_safety_script "backups/custodexa-backup-$current-$CX_RS_TS.tar")"; fi
    if cx_rs_ext; then cx_rs_ext_kept
    else
      if [ "$(cx_rs_get contents.tls)" = true ]; then kept=$(cx_msg rs_kept)
      else kept=$(cx_msg rs_kept_no_tls); fi
      kept+=$'\n'"$CX_RS_DATA/postgres.before-restore-$CX_RS_TS"$'\n'"$CX_RS_DATA/audit.before-restore-$CX_RS_TS"
      [ "$(cx_rs_get contents.tls)" != true ] || kept+=$'\n'"$CX_ROOT/tls.before-restore-$CX_RS_TS"
      cx_rs_row kept "$kept"
    fi
    cx_rs_row downtime "$(cx_msg rs_downtime "$((CX_RS_SAFETY_MIN + CX_RS_IMPORT_MIN + 5))" "$CX_RS_SAFETY_MIN" "$CX_RS_IMPORT_MIN")"
  elif cx_rs_ext; then
    cx_rs_ext_preview_db
    cx_rs_ext_preview_safety
    cx_rs_ext_preview_space
  else cx_rs_row safety "$(cx_msg rs_safety_none)"; fi
  ! cx_rs_ext || cx_rs_ext_preview_skip
  label=space
  for n in "${CX_RS_SPACE_MOUNTS[@]}"; do
    if [ "$CX_RS_FLOW/$CX_LANG" = new/en ]; then
      cx_rs_row "$label" "$(cx_msg rs_preview_space_new "$(cx_gb_up "${CX_RS_SPACE_NEED[$n]}")" "$(cx_gb_down "${CX_RS_SPACE_FREE[$n]}")" "$n")"
    elif [ "$CX_RS_FLOW/$CX_LANG" = same/zh-TW ]; then
      cx_rs_row "$label" "$(cx_msg rs_preview_space_same "$n" "$(cx_gb_up "${CX_RS_SPACE_NEED[$n]}")" "$(cx_gb_down "${CX_RS_SPACE_FREE[$n]}")")"
    else
      cx_rs_row "$label" "$(cx_msg "rs_preview_space_$CX_RS_FLOW" "$(cx_gb_up "${CX_RS_SPACE_NEED[$n]}")" "$n" "$(cx_gb_down "${CX_RS_SPACE_FREE[$n]}")")"
    fi
    label=-
  done
  [ "$CX_RS_FLOW" != same ] || ! cx_rs_ext || cx_rs_ext_preview_space
  case $provider in
    env) cx_rs_par "$(cx_msg rs_preview_env "$(cx_rs_get kek.fingerprint)")" ;;
    ui) cx_rs_par "$(cx_msg "rs_preview_ui_$CX_RS_FLOW" "$(cx_rs_get kek.fingerprint)")" ;;
    kms) cx_rs_par "$(cx_msg rs_preview_kms)" ;;
  esac
  if [ "$CX_RS_FLOW" = new ] && [ "$(cx_rs_get trigger)" != upgrade ]; then
    if [ ! -t 0 ]; then cx_rs_par "$(cx_msg rs_after_noninteractive)"
    elif [ "$CX_RS_ENGINE" = "$CX_RS_VERSION" ]; then cx_rs_par "$(cx_msg rs_after_same_version)"
    else cx_rs_par "$(cx_msg rs_after_newer_engine "$CX_RS_ENGINE")"; fi
  fi
  printf '\n'
}
cx_rs_confirm() {
  local answer rc=0
  # A non-empty external database is confirmed by its name.
  cx_rs_ext_confirm || rc=$?
  [ "$rc" = 2 ] || return "$rc"
  if [ "$CX_RS_FLOW" = same ]; then
    if [ "${CX_YES:-0}" = 1 ] || [ ! -t 0 ]; then
      [ "${CX_YES:-0}" = 1 ] && [ "${CX_RS_CONFIRM_LOSS:-0}" = 1 ] && return 0
      cx_rs_refuse rs_confirm_flags
      return 1
    fi
    printf '%s\n> ' "$(cx_msg rs_confirm_version "$CX_RS_VERSION")"
    IFS= read -r answer || answer=""
    if [ "$answer" != "$CX_RS_VERSION" ]; then
      printf '%s\n' "$(cx_msg rs_confirm_cancel "$CX_RS_VERSION")"
      return 1
    fi
  else
    [ "${CX_YES:-0}" != 1 ] || return 0
    if [ ! -t 0 ]; then cx_rs_refuse rs_confirm_new_flags; return 1; fi
    printf '%s' "$(cx_msg rs_confirm_new)"
    IFS= read -r answer || answer=""
    case $answer in y|Y) ;; *) cx_rs_unchanged; return 1 ;; esac
  fi
}
