# shellcheck shell=bash
# Safety backups are verified as restore inputs, without replacing the source restore context.
# These functions are called by the execution stages, never by preview alone.
# Every operand in a guard must pass. Reader context changes are intentionally isolated.
# shellcheck disable=SC2034,SC2015,SC2030,SC2031
CX_RS_SAFETY_OK=0 CX_RS_SAFETY_REASON="" CX_RS_SAFETY_FP="" CX_RS_SAFETY_CHOICE=script

cx_rs_safety_reason() {
  CX_RS_SAFETY_REASON=$(cx_msg "rs_safety_reason_$1" "${@:2}")
  CX_RS_SAFETY_BRIEF=$CX_RS_SAFETY_REASON
  [ "$1" != fingerprint ] || CX_RS_SAFETY_BRIEF=$(cx_msg rs_safety_reason_fingerprint_short)
  CX_RS_SAFETY_BRIEF=${CX_RS_SAFETY_BRIEF%.}
  CX_RS_SAFETY_BRIEF=${CX_RS_SAFETY_BRIEF%。}
  return 1
}
cx_rs_safety_preflight() {
  local out count key value ver ids kv
  CX_RS_SAFETY_OK=0 CX_RS_SAFETY_REASON="" CX_RS_SAFETY_FP=""
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  out=$(cx_snap_sql "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1" 2>/dev/null) || out=""
  count=$(printf '%s\n' "$out" | grep -c .) || true
  [ "$count" = 1 ] || { cx_rs_safety_reason fingerprint "$count"; return 1; }
  CX_RS_SAFETY_FP=$out
  cx_pb_kek_mode
  [ "$CX_PB_KEK" != hsm ] || { cx_rs_safety_reason hsm; return 1; }
  [ -n "$CX_PB_KEK" ] || { cx_rs_safety_reason secret KEK_PROVIDER; return 1; }
  for key in JWT_SECRET DB_PASSWORD $([ "$CX_PB_KEK" != env ] || echo ENCRYPTION_KEY); do
    value=$(cx_bk_env "$key")
    case $value in ''|change-me*|changeme|CHANGE_ME|your-*|custodexa_password)
      cx_rs_safety_reason secret "$key"; return 1 ;;
    esac
  done
  if [ "$CX_PB_KEK" = env ]; then
    cx_rs_key_fingerprint "$(cx_bk_env ENCRYPTION_KEY)" && [ "$CX_RS_KEY_FP" = "$out" ] || {
      cx_rs_safety_reason key; return 1;
    }
  fi
  ver=$(cx_state_get current.version)
  if ! cx_vr_valid "$ver" || [ "$(cx_vr_cmp "$ver" 1.16.0)" = -1 ]; then
    cx_rs_safety_reason old "$ver"; return 1
  fi
  [ "$(cx_vr_cmp "$CX_RS_ENGINE" "$ver")" != -1 ] || {
    cx_rs_safety_reason engine "$CX_ROOT/releases/$ver/custodexa.sh"; return 1;
  }
  cmp -s "$CX_ROOT/releases/$ver/MANIFEST.json" "$CX_ROOT/current/MANIFEST.json" && cx_pb_versions >/dev/null || {
    cx_rs_safety_reason manifest "$CX_ROOT/releases/$ver/MANIFEST.json"; return 1;
  }
  ids=$(cx_state_get current.image_ids)
  [ -n "$ids" ] || { cx_rs_safety_reason images "$ver"; return 1; }
  for kv in $ids; do
    [ "$(cx_img_id "${kv#*=}")" = "${kv#*=}" ] || {
      cx_rs_safety_reason images "${kv%%=*}"; return 1;
    }
  done
  printf '%s\n' "$CX_RS_SAFETY_FP" >"$CX_RS_DIR/safety-fingerprint" || return 1
  CX_RS_SAFETY_OK=1
}

# The choice is asked before confirmation and before any service stops. On a failed attempt,
# use the recorded stop time and ask again; a rejected script backup leaves only the own option.
cx_rs_safety_choose() {
  local answer title=rs_safety_choose_title opt=rs_safety_choose_script
  if [ "${CX_RS_ACTION:-}" = resume ]; then title=rs_safety_choose_again; opt=rs_safety_choose_retry; fi
  if [ "$CX_RS_SAFETY_OK" != 1 ]; then
    if [ -t 0 ]; then
      cx_line WARN "$(cx_msg rs_safety_preflight_warn)"
      cx_rs_par "$CX_RS_SAFETY_REASON"
      if [ -z "$(cx_state_get last_restore.stopped_at)" ]; then cx_rs_par "$(cx_msg rs_safety_preflight_own)"
      else cx_rs_par "$(cx_msg rs_safety_resume_own)"; fi
    elif ! cx_br_flags_given; then
      local text
      text=$(cx_msg rs_safety_preflight_fail "$CX_RS_SAFETY_BRIEF")
      [ "$CX_LANG" != en ] || text=$(cx_wrap 67 "$text")
      cx_line FAIL "$text"
      cx_rs_unchanged
      return 3
    fi
  fi
  if cx_br_flags_given; then
    [ -n "${CX_BACKUP_REF:-}" ] && [ -n "${CX_BACKUP_TIME:-}" ] && [ -n "${CX_BACKUP_RESTORE:-}" ] || {
      cx_line FAIL "$(cx_msg br_flags_incomplete)"; return 2;
    }
    CX_RS_SAFETY_CHOICE=own
    return 0
  fi
  CX_RS_SAFETY_CHOICE=script
  if [ ! -t 0 ] || [ "${CX_YES:-0}" = 1 ]; then
    [ "$CX_RS_SAFETY_OK" = 1 ] || return 3
    return 0
  fi
  cx_line ASK "$(cx_msg "$title")"
  printf '\n'
  if [ "$CX_RS_SAFETY_OK" = 1 ]; then cx_rs_par "$(cx_msg "$opt" "${CX_RS_SAFETY_MIN:-1}")"; fi
  cx_rs_par "$(cx_msg rs_safety_choose_own)"
  printf '\n'
  while :; do
    if [ "$CX_RS_SAFETY_OK" = 1 ]; then printf '%s' "$(cx_msg rs_safety_choose_prompt)"
    else printf '%s' "$(cx_msg rs_safety_choose_only)"; fi
    IFS= read -r answer || return 3
    case $answer in
      2) CX_RS_SAFETY_CHOICE=own; return 0 ;;
      ''|1) [ "$CX_RS_SAFETY_OK" != 1 ] || return 0 ;;
    esac
  done
}

# Check every application container, including one restarted and stopped again by an operator.
# Compare timestamps with fractional seconds, so a restart in the stop's second is not missed.
cx_rs_safety_still_stopped() {
  local stopped=$1 svc row running started finished extra stop_ns start_ns logs
  stop_ns=$(date -d "$stopped" +%s%N 2>/dev/null) || return 1
  for svc in $CX_BK_SERVICES; do
    row=$(docker container inspect --format '{{.State.Running}} {{.State.StartedAt}} {{.State.FinishedAt}}' "custodexa-$svc" 2>/dev/null) || return 1
    read -r running started finished extra <<<"$row"
    [ "$running" = false ] && [ -z "$extra" ] && [ -n "$finished" ] || return 1
    start_ns=$(date -d "$started" +%s%N 2>/dev/null) || return 1
    [ "$start_ns" -le "$stop_ns" ] || return 1
  done
  logs=$(docker logs custodexa-backend 2>&1) || return 1
  ! grep -qF "$CX_UP_DRAIN_TIMEOUT_MARK" <<<"$logs"
}
cx_rs_safety_stop() {
  cx_rs_services app-stopped || return 1
  cx_pb_stop || return 1
  cx_rs_safety_still_stopped "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
  cx_rs_apps_stopped
}
# The producer callback must stop the pipeline if the durable stop record cannot be written.
cx_rs_safety_step() {
  [ "$1" != FAIL ] || return 1
  if [ "$4" = stop ]; then
    cx_rs_safety_still_stopped "$(date '+%Y-%m-%dT%H:%M:%S%z')" && cx_rs_apps_stopped || return 1
    # The external database: once this host's services stopped, no other connection may remain.
    if cx_rs_ext; then cx_rs_ext_quiet 2 "$(cx_rs_steps_total)" rs_ext_step_stop || return 1; fi
    cx_rs_progress_end stop
    cx_rs_progress_begin safety
  fi
}

cx_rs_safety_command() {
  local cmd
  cmd=$(cx_rs_control_command resume)
  printf '%s --backup-ref <%s> --backup-time <%s> --backup-restore <%s>' "$cmd" \
    "$(cx_msg rs_safety_id)" "$(cx_msg rs_safety_time)" "$(cx_msg rs_safety_procedure)"
}
cx_rs_safety_failed() {
  local why=$1 text stopped column=61
  case $why:$CX_LANG in write:en|write:zh-TW) column=72 ;; esac
  cx_rs_timed_line FAIL " $(cx_msg rs_safety_failed_title)" "$(cx_duration "$(($(cx_now) - ${CX_RS_SAFETY_STARTED:-$(cx_now)}))")" "$column"
  text=$(cx_msg "rs_safety_failed_$why" "${CX_RS_SAFETY_REASON:-}")
  [ "$CX_LANG" != en ] || text=$(cx_wrap 67 "$text")
  printf '       %s\n' "${text//$'\n'/$'\n'       }"
  printf '\n%s\n' "$(cx_msg rs_safety_failed_body)"
  if [ "$why" = unusable ]; then
    cx_rs_par "$(cx_msg rs_safety_resume_own)"
    cx_cmd "$(cx_rs_safety_command)"
  else
    cx_rs_par "$(cx_msg rs_safety_resume)"
    cx_cmd "$(cx_rs_control_command resume)"
  fi
  cx_rs_par "$(cx_msg rs_safety_revert)"
  cx_cmd "$(cx_rs_control_command revert)"
  if [ "$why" != unusable ]; then
    cx_rs_par "$(cx_msg rs_safety_use_own)"
    cx_cmd "$(cx_rs_safety_command)"
  fi
  stopped=$(date -d "$(cx_state_get last_restore.stopped_at)" '+%Y-%m-%d %H:%M') || return 1
  cx_rs_par "$(cx_msg rs_safety_stop_time "$stopped")"
  return 1
}

# A separate subshell and private directory keep all reader maps, release metadata and secrets
# of the safety file from changing the original restore input. No payload is retained.
cx_rs_safety_verify() (
  CX_RS_DIR=$(mktemp -d "$CX_RS_DIR/safety-check-XXXXXX") || exit 1
  trap 'rm -rf -- "$CX_RS_DIR"' EXIT
  CX_RS_NO_CHECKSUM=0 CX_PASSPHRASE_FILE="" CX_PB_PASS=""
  cx_rs_open --verify-only "$1" || exit 1
  cx_rs_checks && cx_rs_migrations || exit 2
  [ "$(cx_rs_get kek.fingerprint)" = "$2" ] || { cx_rs_bad fingerprint; exit 2; }
)
cx_rs_safety_take() {
  local rc=0 fp
  CX_RS_SAFETY_STARTED=$(cx_now)
  cx_pb_versions && cx_pb_kek_mode && cx_pb_parts || return 1
  fp=$(cat "$CX_RS_DIR/safety-fingerprint") || return 1
  cx_pb_open restore-safety || { cx_line FAIL "$(cx_msg rs_safety_setup_failed)"; return 1; }
  cx_rs_services app-stopped || return 1
  cx_rs_progress_begin stop
  if ! cx_bk_take restore-safety cx_rs_safety_step; then
    [ -z "${CX_RS_EXT_HELD:-}" ] || return 1
    if [ -z "$(cx_state_get last_restore.stopped_at)" ]; then
      cx_line FAIL "$(cx_msg rs_safety_restarted)"
      cx_cmd "$(cx_rs_control_command resume)"
      cx_cmd "$(cx_rs_control_command revert)"
    elif grep -qF 'No space left on device' "$CX_LOG_FILE"; then cx_rs_safety_failed write
    elif [ "$CX_BK_FAILED_STEP" = pack ]; then cx_rs_safety_failed read
    else cx_rs_safety_failed operation; fi
    return 1
  fi
  cx_rs_progress_end safety
  cx_rs_progress_begin verify
  cx_rs_safety_verify "$CX_PB_FINAL" "$fp" >"$CX_RS_DIR/safety-check.log" 2>&1 || rc=$?
  if [ "$rc" != 0 ]; then
    CX_RS_SAFETY_REASON=$(sed -n 's/^\[FAIL\] *//p' "$CX_RS_DIR/safety-check.log" | head -n 1)
    if [ "$rc" = 2 ]; then cx_rs_safety_failed unusable
    else cx_rs_safety_failed read; fi
    return 1
  fi
  cx_state_set last_restore.safety script && cx_state_set last_restore.safety_file "$CX_PB_FINAL" && cx_rs_save || return 1
  cx_rs_progress_end verify
  cx_pb_cleanup || return 1
  cx_rs_phase safety
}

cx_rs_safety_own() {
  umask 077
  local stop t k v ptr
  cx_rs_progress_begin stop
  stop=$(cx_state_get last_restore.stopped_at)
  if [ -z "$stop" ]; then
    if cx_br_flags_given; then
      # Noninteractive callers must stop the services before starting the command.
      stop=$(cx_br_backend)
      [[ $stop == stopped\ * ]] || { cx_line FAIL "$(cx_msg br_ref_running)"; return 3; }
      stop=${stop#stopped }
      cx_rs_safety_still_stopped "$stop" || { cx_line FAIL "$(cx_msg rs_safety_restarted)"; return 1; }
      cx_state_set last_restore.stopped_at "$stop" && cx_rs_services app-stopped || return 1
    else
      cx_rs_safety_stop || return 1
      stop=$(cx_state_get last_restore.stopped_at)
    fi
  fi
  cx_rs_safety_still_stopped "$stop" || { cx_line FAIL "$(cx_msg rs_safety_restarted)"; cx_cmd "$(cx_rs_control_command revert)"; return 1; }
  cx_rs_progress_end stop
  cx_rs_progress_begin own
  cx_br_set_stop "$stop" || return 1
  if cx_br_flags_given; then
    t=$(cx_br_parse_time "$CX_BACKUP_TIME") || { cx_line FAIL "$(cx_msg br_time_format)"; return 2; }
    if ! cx_br_after_stop "$t"; then
      cx_line FAIL "$(cx_msg br_time_early "${CX_BACKUP_TIME#* }" "$CX_BR_STOP_SHOWN")"
      cx_cmd "$(cx_rs_control_command revert)"
      return 1
    fi
    CX_BR_REF=$CX_BACKUP_REF CX_BR_TIME=$CX_BACKUP_TIME CX_BR_RESTORE=$CX_BACKUP_RESTORE
  else
    # Reuse the upgrade questions and validation; only the recovery hint belongs to restore.
    (
      MSG_br_enter=$(cx_msg rs_safety_enter)
      # Invoked by cx_br_interactive on refusal, inside this subshell only.
      # shellcheck disable=SC2317
      cx_br_resume() { cx_cmd "$(cx_rs_control_command revert)"; }
      cx_br_interactive "$CX_BR_STOP_SHOWN" 0 || exit 1
      printf '%s\n%s\n%s\n' "$CX_BR_REF" "$CX_BR_TIME" "$CX_BR_RESTORE" >"$CX_RS_DIR/safety-own.answers"
    ) || return 1
    { IFS= read -r CX_BR_REF; IFS= read -r CX_BR_TIME; IFS= read -r CX_BR_RESTORE; } <"$CX_RS_DIR/safety-own.answers"
  fi
  cx_rs_safety_still_stopped "$stop" || { cx_line FAIL "$(cx_msg rs_safety_restarted)"; return 1; }
  printf 'ref=%s\ntime=%s\nrestore=%s\nstopped_at=%s\n' "$CX_BR_REF" "$CX_BR_TIME" "$CX_BR_RESTORE" "$stop" >"$CX_RS_DIR/safety-own.txt" || return 1
  ptr="see ${CX_RS_DIR#"$CX_ROOT"/}/safety-own.txt"
  for k in ref time restore; do
    case $k in ref) v=$CX_BR_REF ;; time) v=$CX_BR_TIME ;; restore) v=$CX_BR_RESTORE ;; esac
    cx_state_valid_value "$v" || v=$ptr
    cx_state_set "last_restore.safety_$k" "$v" || return 1
  done
  cx_state_set last_restore.safety own && cx_state_set last_restore.safety_file '' && cx_rs_save && cx_rs_phase safety || return 1
  cx_rs_progress_end own
}

# Called after preparing the release, and on --resume at precisely that phase.
cx_rs_safety() {
  if cx_br_flags_given && { [ "$(cx_state_get last_restore.phase)" != prepared ] || [ "$(cx_state_get last_restore.covering)" = 1 ]; }; then
    cx_line FAIL "$(cx_msg rs_safety_flags_phase)"; return 2
  fi
  [ "$(cx_state_get last_restore.phase)" = prepared ] || return 1
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  if [ "${CX_RS_ACTION:-}" = resume ]; then
    # A new preflight is needed for a retry; own backups do not need a readable old database.
    cx_rs_safety_preflight || true
    cx_rs_safety_choose || return "$?"
  fi
  if [ "$CX_RS_SAFETY_CHOICE" = own ]; then cx_rs_safety_own
  else cx_rs_safety_take; fi
}
