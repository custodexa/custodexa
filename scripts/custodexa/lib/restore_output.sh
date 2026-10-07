# shellcheck shell=bash
# Restore screens retain their own duration columns and continuation indents.
# These are presentation settings only; shared backup/upgrade formatting is unchanged.
CX_RS_PROGRESS_ID="" CX_RS_PROGRESS_STARTED=0
cx_rs_timed_line() {
  local mark=$1 text=$2 duration=$3 column=$4 minimum=${5:-2} width pad
  width=$(cx_width "${text##*$'\n'}")
  [[ $text == *$'\n'* ]] || width=$((width + 7))
  pad=$((column - 1 - width))
  [ "$pad" -ge "$minimum" ] || pad=$minimum
  printf '%s %s%*s%s\n' "$(cx_mark "$mark")" "$text" "$pad" '' "$duration"
}
cx_rs_read_timed() {
  local kind=$1 text=$2 duration=$3 column=61 minimum=2
  case $kind:$CX_LANG in
    parts:en) column=65 ;; parts:zh-TW) column=63 ;;
    extracted:en|extracted:zh-TW) minimum=3 ;;
  esac
  cx_rs_timed_line OK "${text//$'\n'/$'\n'       }" "$duration" "$column" "$minimum"
}
# Starting a step records its display clock. Only its end prints a completed line.
cx_rs_progress_begin() { CX_RS_PROGRESS_ID=$1 CX_RS_PROGRESS_STARTED=$(cx_now); }
cx_rs_progress_end() {
  local id=$1 mark=${2:-OK} key=rs_progress_$1 step total=10 column=72 minimum=2
  local text duration="" indent=14 file
  [ "${CX_RS_PROGRESS_ID:-}" = "$id" ] || return 0
  case $id in
    release) step=1; key+=_$CX_RS_FLOW ;;
    stop) step=2 ;;
    safety|own) step=3 ;;
    verify) step=4 ;;
    swap) step=5; [ "$CX_RS_FLOW" != new ] || { step=2; key=rs_progress_settings; } ;;
    import) step=6 ;;
    check) step=7 ;;
    files) step=8; key+=_$CX_RS_FLOW
      [ "$CX_RS_FLOW:${CX_RS_REISSUE:-0}" != new:1 ] || key+=_reissue ;;
    start) step=9; key+=_$CX_RS_FLOW ;;
    ready) step=7 ;;
    key) step=10; key=rs_progress_key_wait; [ "$mark" != OK ] || key=rs_runtime_match ;;
  esac
  # The same host's external database: its own labels for the stop, the last look and the import.
  if text=$(cx_rs_ext_step_key "$id"); then key=$text; fi
  if [ "$CX_RS_FLOW" = new ]; then
    total=8 indent=13 column=73
    case $id in import) step=3 ;; check) step=4 ;; files) step=5 ;; start) step=6 ;; key) step=8 ;; esac
    # A new host's external database export (step 3) moves the steps after it on by one.
    if cx_rs_ext_export_step; then
      total=9
      case $id in export) step=3 key=rs_ext_step_export ;; import|check|files|start|ready|key) step=$((step + 1)) ;; esac
    fi
  fi
  case $id in
    release|start|ready) text=$(cx_msg "$key" "$CX_RS_VERSION") ;;
    safety) file=${CX_PB_FINAL:-$(cx_state_get last_restore.safety_file)}
      text=$(cx_msg "$key" "${file#"$CX_ROOT"/}"); minimum=3 ;;
    own) text=$(cx_msg "$key" "$(cx_state_get last_restore.safety_ref)" "$(cx_state_get last_restore.safety_time)") ;;
    check) text=$(cx_msg "$key" "$(cx_rs_get db.migrations_count)") ;;
    key) text=$(cx_msg "$key" "$(cx_rs_get kek.fingerprint)") ;;
    *) text=$(cx_msg "$key") ;;
  esac
  # The approved layouts have a few language-specific last-line positions.
  case $CX_RS_FLOW:$id:$CX_LANG in
    same:release:en|same:release:ja) column=71 ;;
    same:swap:ja) column=73 ;;
    same:check:zh-TW) minimum=3 ;;
    new:release:zh-TW|new:release:ja|new:import:ja) column=72 ;;
    new:import:zh-TW) [ "$mark" = FAIL ] || column=72 ;;
    new:check:zh-TW) minimum=5 ;;
  esac
  printf -v file '%*s' "$indent" ''
  text=${text//$'\n'/$'\n'"$file"}
  printf -v text '%2s/%s  %s' "$step" "$total" "$text"
  case $CX_RS_FLOW:$id in
    *:key|*:own|new:swap|same:files) printf '%s %s\n' "$(cx_mark "$mark")" "$text" ;;
    *) duration=$(cx_duration "$(($(cx_now) - CX_RS_PROGRESS_STARTED))")
      cx_rs_timed_line "$mark" "$text" "$duration" "$column" "$minimum" ;;
  esac
  CX_RS_PROGRESS_ID=""
}

# Recovery instructions always name the engine that owns this restore.
cx_rs_status_command() { printf 'sudo %s status%s' "$(cx_rs_engine_path)" "$(cx_status_lang_arg)"; }
cx_rs_exit_hint() {
  local action
  action=$(cx_rs_return_action)
  if [ "$(cx_state_get last_restore.safety)" = own ] && [ "$(cx_state_get last_restore.covering)" = 1 ]; then
    cx_rs_par "$(cx_msg rs_failure_own "$(cx_state_get last_restore.safety_restore)" "$(cx_state_get last_restore.safety_ref)" "$(cx_state_get last_restore.safety_time)")"
  else
    if cx_rs_ext_way_back "$action"; then :
    elif [ "$action" = abandon ]; then cx_rs_par "$(cx_msg rs_failure_abandon)"
    elif [ "$(cx_state_get last_restore.covering)" != 1 ]; then cx_rs_par "$(cx_msg rs_safety_revert)"
    else cx_rs_par "$(cx_msg rs_failure_revert)"; fi
    cx_cmd "$(cx_rs_control_command "$action")"
  fi
}
cx_rs_failure_details() {
  local step=${CX_RUN_STEP:-0} path count=0 first=""
  if [ -n "$(cx_rs_exit_action)" ]; then cx_rs_control_hints; return 0; fi
  if [ "$CX_RS_FLOW" = new ]; then
    cx_rs_ext_failure_state || cx_rs_par "$(cx_msg rs_failure_no_safety)"
  elif [ "$(cx_state_get last_restore.covering)" != 1 ]; then
    cx_rs_par "$(cx_msg rs_failure_uncovered)"
  elif [ "$(cx_state_get last_restore.safety)" = script ]; then
    while IFS= read -r path; do count=$((count + 1)); [ -n "$first" ] || first=$path; done < <(cx_rs_kept_paths)
    [ "$count" = 0 ] || cx_rs_par "$(cx_msg rs_failure_kept "$first" "$(cx_rs_kept_number "$count")" "$(cx_state_get last_restore.safety_file)")"
  fi
  [ "$CX_RS_FLOW" != same ] || cx_rs_ext_failure_state || true
  cx_rs_par "$(cx_msg rs_failure_resume "$step")"
  cx_cmd "$(cx_rs_control_command resume)"
  cx_rs_exit_hint
  [ "$CX_RS_FLOW" != same ] || cx_rs_par "$(cx_msg rs_failure_plaintext "$CX_RS_DIR/")"
  cx_rs_par "$(cx_msg rs_failure_log "$CX_LOG_FILE")"
}
# Read the actual containers, including postgres; a phase never proves that all are stopped.
cx_rs_actual_services() {
  local active
  if ! active=$(cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" ps --status running --services 2>/dev/null); then
    printf unknown
  elif [ -n "$active" ]; then printf running
  else printf stopped; fi
}
cx_rs_failure() {
  local actual
  actual=$(cx_rs_actual_services)
  [ "$CX_RS_FLOW:$actual" != new:stopped ] || actual=new_stopped
  printf '\n%s\n' "$(cx_msg "rs_failure_$actual" "${CX_RUN_STEP:-0}")"
  [[ $actual == stopped || $actual == new_stopped ]] || cx_cmd "$(cx_rs_status_command)"
  cx_rs_failure_details
  return 1
}
