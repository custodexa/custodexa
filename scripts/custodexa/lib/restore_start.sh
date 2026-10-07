# shellcheck shell=bash
# Service startup is separate from health and from the runtime master-key evidence.
# shellcheck disable=SC2034
CX_RS_WAS_AWAITING=0
cx_rs_images_load() {
  local name id rest release=$CX_ROOT/releases/$CX_RS_VERSION
  cx_manifest_load "$release/MANIFEST.json" || return 1
  cx_img_needed "$(cx_rs_get deploy.overlays)"
  CX_IMG_ID=()
  while IFS='=' read -r name id rest; do
    [[ $name =~ ^[a-z0-9_]+$ && $id =~ ^sha256:[a-f0-9]{64}$ && -z $rest ]] || return 1
    # shellcheck disable=SC2004 # associative array declared by images.sh
    CX_IMG_ID[$name]=$id
  done <"$release/image-ids.env"
  for name in "${CX_IMG_NAMES[@]}"; do [ -n "${CX_IMG_ID[$name]:-}" ] || return 1; done
  # Tool images are in no ids file (openssl behind an external ingress, the external database's
  # clients): each as install and load accept it on this host, the clients as the checks found
  # them, so that the deployment records every one of them again once the files are placed.
  for name in "${CX_TOOL_NAMES[@]+"${CX_TOOL_NAMES[@]}"}"; do
    [ -n "${CX_IMG_ARCH:-}" ] || CX_IMG_ARCH=$(cx_arch) || return 1
    if [[ $name =~ ^pgclient([0-9]+)$ ]]; then id=$(cx_rs_ext_client_id "${BASH_REMATCH[1]}") || id=""
    else id=$(cx_img_held_id "$name") || id=""; fi
    # shellcheck disable=SC2004 # associative array declared by images.sh
    [ -z "$id" ] || CX_IMG_ID[$name]=$id
  done
}
cx_rs_all_running() {
  local active name service
  active=$(cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" ps --status running --services) || return 1
  for name in "${CX_IMG_NAMES[@]}"; do
    case $name in openssl) continue ;; nginx) service=tls-proxy ;; *) service=$name ;; esac
    grep -qxF "$service" <<<"$active" || return 1
  done
}
cx_rs_stop_all() {
  cx_rs_services all-stopped &&
    cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" stop >/dev/null 2>&1 || return 1
  [ "$(cx_rs_actual_services)" = stopped ]
}
cx_rs_health() {
  local tries=0 max health
  max=$(cx_ready_tries)
  until health=$(cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" exec -T backend wget -qO- http://localhost:8080/health 2>/dev/null); do
    tries=$((tries + 1))
    [ "$tries" -lt "$max" ] || return 1
    sleep "$CX_UP_READY_WAIT"
  done
  CX_UP_HEALTH_VER=""
  [[ $health =~ \"version\":[[:space:]]*\"([^\"]*)\" ]] && CX_UP_HEALTH_VER=${BASH_REMATCH[1]}
  [ "$CX_UP_HEALTH_VER" = "$CX_RS_VERSION" ]
}
cx_rs_unseal_screen() {
  cx_line WARN "$(cx_msg rs_unseal_wait "$CX_RS_VERSION")"
  cx_rs_par "$(cx_msg "rs_unseal_$(cx_rs_get kek.provider)")"
  cx_cmd "$(cx_env_get "$CX_ROOT/.env" PUBLIC_BASE_URL)/unseal"
  cx_rs_par "$(cx_msg rs_unseal_fingerprint "$(cx_rs_get kek.fingerprint)")"
  cx_rs_par "$(cx_msg rs_unseal_finish)"
  cx_cmd "$(cx_rs_control_command resume)"
  cx_rs_par "$(cx_msg rs_failure_log "$CX_LOG_FILE")"
}
cx_rs_seal_unreadable() {
  cx_line FAIL "$(cx_msg rs_unseal_unreadable)"
  cx_cmd "$(cx_rs_status_command)"
  cx_rs_control_hints
  return 1
}
cx_rs_kek_verify() {
  local body id="" expected provider state
  provider=$(cx_rs_get kek.provider) expected=$(cx_rs_get kek.fingerprint)
  # The endpoint reports the top-level "state" (sealed, unsealing, unsealed, sealed-faulted) and,
  # only when unsealed, "kek_id"; status reads it the same way.
  body=$(cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" exec -T backend wget -qO- http://localhost:8080/api/v1/seal/status 2>/dev/null) || {
    cx_rs_seal_unreadable; return 1;
  }
  # The backend answers its seal state as "state": sealed, unsealing, sealed-faulted or unsealed.
  state=$(cx_seal_state "$body") || { cx_rs_seal_unreadable; return 1; }
  if [[ $state == sealed || $state == unsealing || $state == sealed-faulted ]]; then
    case $provider in ui|kms) ;; *) cx_rs_seal_unreadable; return 1 ;; esac
    cx_rs_progress_end key WARN
    if [ "$(cx_rs_phase_value)" = awaiting_unseal ]; then
      cx_line WARN "$(cx_msg rs_unseal_still)"
      cx_rs_par "$(cx_msg rs_unseal_again "$(cx_env_get "$CX_ROOT/.env" PUBLIC_BASE_URL)/unseal")"
      cx_cmd "$(cx_rs_control_command resume)"
    else
      cx_rs_phase awaiting_unseal || return 1
      cx_rs_unseal_screen
    fi
    return 4
  fi
  if [ "$state" = unsealed ] && [[ $body =~ \"kek_id\":[[:space:]]*\"([^\"]+)\" ]]; then
    id=${BASH_REMATCH[1]}
  fi
  if [ -z "$id" ] || ! cx_state_valid_value "$id"; then cx_rs_seal_unreadable; return 1; fi
  if [ "$id" != "$expected" ]; then
    cx_state_set last_restore.kek_mismatch "$id" && cx_rs_save || return 1
    cx_rs_stop_all || { cx_rs_failure; return 1; }
    cx_rs_phase placed || return 1
    cx_line FAIL "$(cx_msg rs_runtime_mismatch "$id" "$expected")"
    cx_rs_par "$(cx_msg rs_runtime_stopped)"
    cx_rs_par "$(cx_msg rs_runtime_guide)"
    if [ "$provider" = env ]; then cx_rs_par "$(cx_msg rs_runtime_resume_env)"
    else cx_rs_par "$(cx_msg rs_runtime_resume)"; fi
    cx_cmd "$(cx_rs_control_command resume)"
    cx_rs_exit_hint
    return 1
  fi
  cx_state_set last_restore.kek_evidence runtime-id && cx_rs_phase "done" || return 1
  if [ "${CX_RS_PROGRESS_ID:-}" = key ]; then cx_rs_progress_end key
  else cx_line OK "$(cx_msg rs_runtime_match "$id")"; fi
  [ "$CX_RS_WAS_AWAITING" != 1 ] || cx_line OK "$(cx_msg rs_restore_done "$CX_RS_VERSION")"
}
cx_rs_start() {
  local phase provider step=9 total=10
  phase=$(cx_rs_phase_value) provider=$(cx_rs_get kek.provider)
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  CX_RS_WAS_AWAITING=0
  if [ "$phase" = awaiting_unseal ]; then CX_RS_WAS_AWAITING=1; cx_rs_kek_verify; return "$?"; fi
  case $phase in placed|started) ;; *) return 1 ;; esac
  cx_rs_progress_begin start
  if [ "$phase" = placed ] && [ "$provider" = env ]; then
    if ! cx_rs_key_fingerprint "$(cx_env_get "$CX_ROOT/.env" ENCRYPTION_KEY)" ||
      [ "$CX_RS_KEY_FP" != "$(cx_rs_get kek.fingerprint)" ]; then
      cx_line FAIL "$(cx_msg rs_key_mismatch)"
      cx_rs_par "$(cx_msg rs_key_fingerprints "${CX_RS_KEY_FP:-?}" "$(cx_rs_get kek.fingerprint)")"
      cx_rs_par "$(cx_msg rs_key_wrong)"
      cx_rs_control_hints
      return 1
    fi
  fi
  cx_rs_images_load || return 1
  if [ "$phase" = placed ] || ! cx_rs_all_running; then
    cx_rs_services starting || return 1
    cx_rs_job cx_rs_compose_quiet "$CX_ROOT/releases/$CX_RS_VERSION" up -d || return 1
  fi
  cx_images_verify_running && cx_rs_services up && cx_rs_phase started || return 1
  if [ "$CX_RS_FLOW" = new ]; then
    cx_rs_progress_end start
    cx_rs_progress_begin ready
  fi
  if ! cx_rs_health; then
    [ "$CX_RS_FLOW" != new ] || { step=$((7 + $(cx_rs_ext_shift))); total=$(cx_rs_steps_total); }
    cx_line WARN " $step/$total  $(cx_msg rs_ready_timeout "$(cx_ready_seconds)")"
    printf '\n%s\n' "$(cx_msg rs_ready_body)"
    cx_rs_par "$(cx_msg rs_ready_status)"; cx_cmd "$(cx_rs_status_command)"
    cx_rs_par "$(cx_msg rs_ready_resume)"; cx_cmd "$(cx_rs_control_command resume)"
    cx_rs_exit_hint
    return 1
  fi
  if [ "$CX_RS_FLOW" = new ]; then cx_rs_progress_end ready
  else cx_rs_progress_end start; fi
  cx_rs_progress_begin key
  cx_rs_kek_verify
}
