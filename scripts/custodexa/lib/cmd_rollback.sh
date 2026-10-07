# shellcheck shell=bash
# Shared run globals are consumed by run.sh.
# shellcheck disable=SC2034
# The new entry holds the same deployment lock as other changes, but confirms before
# creating its record. Recovery loads that record without resetting its identity or step.
# shellcheck source=lib/backup.sh
. "${BASH_SOURCE[0]%/*}/backup.sh"
# shellcheck source=lib/service_controls.sh
. "${BASH_SOURCE[0]%/*}/service_controls.sh"
# shellcheck source=lib/rollback_check.sh
. "${BASH_SOURCE[0]%/*}/rollback_check.sh"
# shellcheck source=lib/rollback_output.sh
. "${BASH_SOURCE[0]%/*}/rollback_output.sh"
# shellcheck source=lib/rollback_steps.sh
. "${BASH_SOURCE[0]%/*}/rollback_steps.sh"

cx_rb_pending() {
  local key prefix step
  for key in "${CX_STATE_KEYS[@]}"; do
    [[ $key == *.result ]] || continue
    [ "${CX_STATE[$key]}" = in_progress ] || continue
    prefix=${key%.result} step=${CX_STATE[${key%.result}.step]:-?}
    if [ "$CX_RB_FRESH" = 0 ] && [ "$prefix" = last_rollback ]; then continue; fi
    if [ "$prefix" = last_upgrade ] && [[ $step =~ ^[0-9]+$ ]] && [ "$step" -ge 9 ]; then continue; fi
    cx_line WARN "$(cx_msg run_interrupted "$(cx_run_command_of "$prefix")" "$step")"
    if [ "$prefix" = load ]; then cx_up_par "$(cx_msg run_load_rerun)"; continue; fi
    cx_recovery_hint "$(cx_run_command_of "$prefix")"
    return 1
  done
}

cx_rb_open() {
  local old k base n=0
  CX_RUN_CMD=rollback CX_RUN_STEP=$(cx_state_get last_rollback.step)
  exec {CX_SIGNAL_FD}>&2
  trap 'cx_rb_signal' INT TERM HUP
  old=$(cx_state_get last_rollback.log)
  cx_secrets_from_env "$CX_ROOT/.env"
  cx_log_open rollback || return 1
  # Distinct attempts even when two invocations start within the same second.
  if [ -s "$CX_LOG_FILE" ] || [ "$CX_ROOT/$old" = "$CX_LOG_FILE" ]; then
    base=${CX_LOG_FILE%.log}
    while [ -e "$base-$n.log" ]; do n=$((n + 1)); done
    CX_LOG_FILE=$base-$n.log
    (umask 077 && : >"$CX_LOG_FILE") || return 1
  fi
  cx_log BEGIN "rollback lang=$CX_LANG flags=${CX_FLAGS_TEXT:-}"
  if [ "$CX_RB_FRESH" = 1 ]; then
    for k in "${CX_STATE_KEYS[@]}"; do [[ $k != last_rollback.* ]] || cx_state_unset "$k"; done
    cx_rb_endpoints || return 1
    cx_state_set last_rollback.direction rollback
    cx_state_set last_rollback.target "$CX_RB_TARGET"
    cx_state_set last_rollback.basis "$CX_RB_BASIS"
    cx_state_set last_rollback.started_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    cx_state_set last_rollback.log "${CX_LOG_FILE#"$CX_ROOT"/}"
    cx_state_set last_rollback.step 0
    cx_state_set last_rollback.result in_progress
  else
    cx_state_set last_rollback.attempt_log "${CX_LOG_FILE#"$CX_ROOT"/}"
    if [ -n "$old" ] && [ -f "$CX_ROOT/$old" ]; then
      printf '%s RESUME %s\n' "$(cx_log_now)" "${CX_LOG_FILE#"$CX_ROOT"/}" >>"$CX_ROOT/$old"
    fi
    if [ "${CX_REVERT:-0}" = 1 ]; then
      cx_state_set last_rollback.direction revert
      cx_state_set last_rollback.target "$(cx_state_get last_rollback.from)"
    fi
  fi
  cx_rb_save || return 1
  CX_RUN_CMD=rollback CX_RUN_STEP=$(cx_state_get last_rollback.step)
  CX_RB_DIRECTION=$(cx_state_get last_rollback.direction) CX_RB_TARGET=$(cx_state_get last_rollback.target)
  exec {CX_SIGNAL_FD}>&2
  trap 'cx_rb_signal' INT TERM HUP
}

# Recovery commands must reflect the last durable direction, even if a signal arrives
# while saving the requested reversal.
cx_rb_signal() {
  cx_state_load "$CX_ROOT/state.json"
  CX_RUN_STEP=$(cx_state_get last_rollback.step)
  cx_on_signal
}

cmd_rollback() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_unknown_option "$*"
  [ -f "$CX_ROOT/state.json" ] || cx_die "$CX_EXIT_REFUSED" svc_not_installed
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  [ "$(cx_state_get current.kind)" = package ] || cx_die "$CX_EXIT_REFUSED" svc_not_installed
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_compose_files >/dev/null || return "$CX_EXIT_REFUSED"
  cx_bk_vars
  CX_RB_FRESH=1
  if [ "${CX_RESUME:-0}" = 1 ] || [ "${CX_REVERT:-0}" = 1 ]; then
    CX_RB_FRESH=0
    [ "$(cx_state_get last_rollback.result)" = in_progress ] || {
      cx_line FAIL "$(cx_msg rb_no_pending)"; cx_rb_status_hint; return "$CX_EXIT_REFUSED";
    }
    cx_rb_pending || return "$CX_EXIT_REFUSED"
    CX_RB_TARGET=$(cx_state_get last_rollback.target)
    CX_RB_DIRECTION=$(cx_state_get last_rollback.direction)
    if [ "${CX_REVERT:-0}" = 1 ]; then
      CX_RB_TARGET=$(cx_state_get last_rollback.from)
      CX_RB_DIRECTION=revert
      cx_up_par "$(cx_msg rb_revert_title "$CX_RB_TARGET")"
      cx_confirm rb_confirm || return "$CX_EXIT_REFUSED"
    fi
  else
    if [ "$(cx_state_get last_rollback.result)" = in_progress ]; then
      cx_rb_pending || return "$CX_EXIT_REFUSED"
      return "$CX_EXIT_REFUSED"
    fi
    # Classification precedes mutual exclusion so a pre-switch or already rolled-back
    # upgrade gets its own explanation, rather than a misleading record mismatch.
    if ! cx_rb_premise; then cx_rb_premise_screen; return "$CX_EXIT_REFUSED"; fi
    cx_rb_pending || return "$CX_EXIT_REFUSED"
    if ! cx_rb_judge; then cx_rb_refused 0; return "$CX_EXIT_REFUSED"; fi
    if ! cx_rb_images; then cx_rb_images_screen; return "$CX_EXIT_REFUSED"; fi
    cx_rb_preview
    cx_confirm rb_confirm || { printf '%s\n' "$(cx_msg pre_nothing_changed)"; return "$CX_EXIT_REFUSED"; }
  fi
  cx_rb_open || return "$CX_EXIT_FAILED"
  cx_rb_main
}
