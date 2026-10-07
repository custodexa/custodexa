# shellcheck shell=bash
# Rebuild the execution context from durable input. Settings already placed on the deployment
# are never silently replaced during recovery (in particular after a master-key mismatch).
# shellcheck disable=SC2034,SC2004 # host value maps are associative arrays from restore_env.sh
cx_rs_context_save() {
  local key value
  (
    umask 077
    printf '{\n'
    for key in package images images_from cert_warning; do
      case $key in package) value=${CX_RS_PACKAGE:-} ;; images) value=${CX_IMAGES:-} ;; images_from) value=${CX_IMAGES_FROM:-auto} ;; cert_warning) value=${CX_RS_CERT_WARNING:-} ;; esac
      cx_state_valid_value "$value" || exit 1
      printf '  "%s": "%s",\n' "$key" "$value"
    done
    printf '  "env_sha256": "%s"\n}\n' "$(cx_pb_sha "$CX_RS_DIR/env.merged")"
  ) >"$CX_RS_DIR/context.tmp" && sync -f "$CX_RS_DIR/context.tmp" &&
    mv -- "$CX_RS_DIR/context.tmp" "$CX_RS_DIR/context.json" && sync -f "$CX_RS_DIR"
}
cx_rs_env_context() {
  local key path
  CX_RS_ENV=$CX_RS_DIR/env.merged
  CX_RS_DATA=$(cx_env_get "$CX_RS_ENV" DATA_PATH)
  [[ $CX_RS_DATA == /* ]] || CX_RS_DATA=$CX_ROOT/${CX_RS_DATA#./}
  CX_RS_TEMPLATE="" CX_RS_REISSUE=0
  if [ "$(cx_rs_get contents.nginx_template)" = true ]; then
    path=$(cx_env_get "$CX_RS_ENV" TLS_NGINX_TEMPLATE)
    CX_RS_TEMPLATE=$(cx_rs_template_path "$path") || return 1
  fi
  for key in DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL; do
    CX_RS_HOST_SOURCE[$key]=$(cx_env_get "$CX_RS_DIR/pass2/env.bak" "$key")
    CX_RS_HOST_VALUES[$key]=$(cx_env_get "$CX_RS_ENV" "$key")
  done
  if [ "$(cx_rs_get deploy.tls_mode)" = selfsigned ] &&
    { [ "${CX_RS_HOST_SOURCE[TLS_DOMAIN]}" != "${CX_RS_HOST_VALUES[TLS_DOMAIN]}" ] ||
      [ "${CX_RS_HOST_SOURCE[TLS_IP_SAN]}" != "${CX_RS_HOST_VALUES[TLS_IP_SAN]}" ]; }; then CX_RS_REISSUE=1; fi
}
cx_rs_resume_input() {
  local expected retained=0
  expected=$(cx_state_get last_restore.file_sha256)
  if [ ! -d "$CX_RS_DIR/pass2" ]; then
    if [ "$(cx_state_get last_restore.covering)" = 1 ]; then
      cx_line FAIL "$(cx_msg rs_journal_missing)"
      cx_rs_control_hints
      return 1
    fi
    if [ "$(cx_pb_sha "$CX_RS_FILE" 2>/dev/null)" != "$expected" ]; then
      cx_line FAIL "$(cx_msg rs_resume_original "$CX_RS_FILE")"; return 1
    fi
    (umask 077; mkdir -p "$CX_RS_DIR") && chmod 0700 "$CX_RS_DIR" || return 1
    [ "$CX_RS_CHECKSUM" != absent ] || CX_RS_NO_CHECKSUM=1
    if [ -f "$CX_RS_DIR/context.json" ]; then
      cx_rs_context_load || return 1
      retained=1
    fi
    cx_rs_open "$CX_RS_FILE" && cx_rs_checks && cx_rs_migrations || return 1
    if [ "$retained" = 0 ]; then cx_rs_env_merge && cx_rs_context_save || return 1; fi
  fi
  cx_rs_input_verify || return 1
  [ "$(cx_rs_get product.version)" = "$CX_RS_VERSION" ] || return 1
  CX_RS_VERIFY_ONLY=0
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  cx_secrets_from_env "$CX_RS_DIR/pass2/env.bak"
  cx_rs_env_context && cx_rs_recovery_route resume
}

# Validate the retained payload and host settings before either forward or safety recovery.
cx_rs_input_verify() {
  if ! cmp -s "$CX_RS_DIR/pass1/SHA256SUMS" "$CX_RS_DIR/pass2/SHA256SUMS" ||
    ! (cd "$CX_RS_DIR/pass2" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
    cx_line FAIL "$(cx_msg rs_resume_changed "$CX_RS_DIR/pass2/")"; return 1
  fi
  cx_rs_context_load && cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS
}
cx_rs_context_load() {
  local -A context=()
  local -a keys=()
  cx_flat_parse "$CX_RS_DIR/context.json" context keys || return 1
  if [ "$(cx_pb_sha "$CX_RS_DIR/env.merged")" != "${context[env_sha256]:-}" ]; then
    cx_line FAIL "$(cx_msg rs_resume_changed "$CX_RS_DIR/env.merged")"; return 1
  fi
  CX_RS_PACKAGE=${context[package]:-} CX_IMAGES=${context[images]:-} CX_IMAGES_FROM=${context[images_from]:-auto}
  CX_RS_CERT_WARNING=${context[cert_warning]:-}
}
