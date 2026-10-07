# shellcheck shell=bash
# Restore interlocks use only the loaded state, so every command and older deployment's
# current entry can explain which engine owns the unfinished work.
cx_rs_engine_path() { printf '%s' "${CX_STATE[last_restore.engine]:-$CX_ROOT/custodexa.sh}"; }
cx_rs_control_command() {
  local action=$1 leaving
  leaving=$(cx_rs_exit_action)
  [ "$action" != resume ] || [ -z "$leaving" ] || action=$leaving
  printf 'sudo %s restore --%s%s' "$(cx_rs_engine_path)" "$action" "$(cx_status_lang_arg)"
}
cx_rs_exit_action() {
  case ${CX_STATE[last_restore.exit]:-} in reverting) printf revert ;; abandoning) printf abandon ;; esac
}
cx_rs_return_action() {
  if [ "${CX_STATE[last_restore.flow]:-}" = new-host ] && [ "${CX_STATE[last_restore.safety]:-}" != db-dump ]; then printf abandon
  else printf revert; fi
}
cx_rs_control_hints() {
  local action
  action=$(cx_rs_exit_action)
  if [ -n "$action" ]; then
    printf '    %s\n' "$(cx_rs_control_command "$action")"
    return 0
  fi
  printf '    %s\n' "$(cx_rs_control_command resume)"
  if [ "${CX_STATE[last_restore.safety]:-}" = own ] && [ "${CX_STATE[last_restore.covering]:-}" = 1 ]; then
    printf '  %s\n    %s\n' "$(cx_msg rs_control_own "${CX_STATE[last_restore.safety_ref]:-}")" "${CX_STATE[last_restore.safety_restore]:-}"
  else
    printf '    %s\n' "$(cx_rs_control_command "$(cx_rs_return_action)")"
  fi
}
cx_rs_phase_text() {
  local phase=${CX_STATE[last_restore.phase]:-checked}
  case $phase in
    checked|prepared|safety|stopped|swapped|imported|db_checked|placed|started|awaiting_unseal|done) cx_msg "rs_phase_$phase" ;;
    *) printf '%s' "$phase" ;;
  esac
}
cx_rs_started_minute() {
  local at=${CX_STATE[last_restore.started_at]:-}
  printf '%s %s' "${at:0:10}" "${at:11:5}"
}
# Only the restore has checked startup images and the key at these late phases. covering
# overrides an early phase after an interrupted move, but not an already completed placement.
cx_rs_start_allowed() {
  case ${CX_STATE[last_restore.phase]:-} in started|awaiting_unseal) return 0 ;; *) return 1 ;; esac
}
cx_run_restore_guard() {
  local cmd=$1 action=${2:-} phase=${CX_STATE[last_restore.phase]:-} leaving engine at
  [ "${CX_STATE[last_restore.result]:-}" = in_progress ] || return 0
  [ -n "$cmd" ] || return 0
  case $cmd in status|load|stop) return 0 ;; esac
  leaving=$(cx_rs_exit_action)
  if [ -n "$leaving" ]; then
    if [ "$cmd" != restore ] || [ "$action" != "$leaving" ]; then
      cx_line FAIL "$(cx_msg "rs_control_$leaving")"
      cx_rs_control_hints
      return 1
    fi
  fi
  if [ "$cmd" = restore ] && [[ $action == resume || $action == revert || $action == abandon ]]; then
    engine=$(cx_rs_engine_path)
    if [ -n "${CX_SELF:-}" ] && [ "$(readlink -f -- "$engine")" != "$(readlink -f -- "$CX_SELF")" ]; then
      cx_line FAIL "$(cx_msg rs_control_engine)"
      printf '    %s\n' "$(cx_rs_control_command "$action")"
      return 1
    fi
    return 0
  fi
  if [ "$cmd" = start ]; then
    cx_rs_start_allowed && return 0
    if [ "$phase" = placed ]; then
      cx_line FAIL "$(cx_msg rs_control_placed)"
      printf '    %s\n' "$(cx_rs_control_command resume)"
      return 1
    fi
    if [ "${CX_STATE[last_restore.covering]:-}" != 1 ] && [[ $phase == checked || $phase == prepared || $phase == safety || $phase == stopped ]]; then
      if [ "${CX_STATE[last_restore.flow]:-}" = new-host ]; then
        cx_line FAIL "$(cx_msg rs_control_previous)"
        cx_rs_control_hints
      else
        cx_line FAIL "$(cx_msg rs_control_before)"
        printf '    %s\n' "$(cx_rs_control_command revert)"
      fi
    else
      cx_line FAIL "$(cx_msg rs_control_unchecked "${CX_STATE[last_restore.step]:-?}")"
      if [ "${CX_STATE[last_restore.flow]:-}" = new-host ] && [ "${CX_STATE[last_restore.safety]:-}" != db-dump ]; then
        printf '  %s\n' "$(cx_msg rs_control_choices_new)"
      else printf '  %s\n' "$(cx_msg rs_control_choices)"; fi
      cx_rs_control_hints
    fi
    return 1
  fi
  case $cmd in
    upgrade|backup|rollback)
      at=$(cx_rs_started_minute)
      cx_line FAIL "$(cx_msg "rs_control_$cmd" "$(cx_rs_phase_text)" "$at")"
      if [ "$phase" = awaiting_unseal ]; then
        printf '  %s\n    %s\n' "$(cx_msg rs_control_after_unseal)" "$(cx_rs_control_command resume)"
      else cx_rs_control_hints; fi ;;
    *) cx_line FAIL "$(cx_msg rs_control_previous)"; cx_rs_control_hints ;;
  esac
  return 1
}
