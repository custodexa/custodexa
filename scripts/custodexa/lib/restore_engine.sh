# shellcheck shell=bash
# The stage runner stops at the first incomplete stage. Final result recording belongs to the
# completion handler after this runner has obtained runtime master-key evidence.
# shellcheck disable=SC2034
cx_rs_run() {
  local phase rc step release=$CX_ROOT/releases/$CX_RS_VERSION
  while :; do
    phase=$(cx_rs_phase_value)
    rc=0
    case $phase in
      checked)
        cx_rs_step 1 || return 1
        cx_rs_progress_begin release
        if [ -z "$CX_RS_RELEASE" ] || [ ! -d "$CX_RS_RELEASE" ]; then cx_rs_release "$CX_RS_VERSION" || return 1; fi
        cx_rs_release_place && cx_rs_images "$release" && cx_rs_phase prepared || rc=$?
        [ "$rc" != 0 ] || cx_rs_progress_end release ;;
      prepared)
        if [ "$CX_RS_FLOW" = same ]; then
          cx_rs_step 3 && cx_rs_safety || rc=$?
        elif cx_rs_ext_export_step; then
          # A new host's external database that holds anything: exported once the settings are
          # written (step 3, at phase swapped).
          cx_rs_phase safety || rc=$?
        else
          cx_state_set last_restore.safety none && cx_rs_phase safety || rc=$?
        fi ;;
      safety)
        step=5; [ "$CX_RS_FLOW" != new ] || step=2
        cx_rs_step "$step" || return 1
        cx_rs_progress_begin swap
        if cx_rs_ext; then
          # The external database: no other connection now, before anything here is renamed.
          cx_rs_ext_quiet "$step" "$(cx_rs_steps_total)" rs_ext_step_quiet || return 1
        elif [ "$CX_RS_FLOW" = same ]; then
          local CX_DB_RELEASE=$release
          cx_bk_vars
          [ "$(cx_db sql 'SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = current_user AND pid <> pg_backend_pid()')" = 0 ] || return 1
        fi
        cx_rs_stop_all && cx_rs_phase stopped || rc=$? ;;
      stopped)
        [ "${CX_RS_PROGRESS_ID:-}" = swap ] || cx_rs_progress_begin swap
        if [ ! -d "$CX_RS_DATA" ]; then cx_rs_journal data-folder mkdir "$CX_RS_DATA" 0700 || return 1; fi
        cx_rs_swapped || rc=$?
        [ "$rc" != 0 ] || cx_rs_progress_end swap ;;
      swapped)
        if cx_rs_ext_export_step && [ -z "$(cx_state_get last_restore.safety)" ]; then
          cx_rs_progress_begin export
          cx_rs_step 3 && cx_rs_ext_safety || return 1
          cx_rs_progress_end export
        fi
        step=6; [ "$CX_RS_FLOW" != new ] || step=$((3 + $(cx_rs_ext_shift)))
        cx_rs_progress_begin import
        cx_rs_step "$step" && cx_rs_job cx_rs_db_import || rc=$?
        [ "$rc" != 0 ] || cx_rs_progress_end import ;;
      imported)
        step=7; [ "$CX_RS_FLOW" != new ] || step=$((4 + $(cx_rs_ext_shift)))
        cx_rs_progress_begin check
        cx_rs_step "$step" && cx_rs_db_check || rc=$?
        [ "$rc" != 0 ] || cx_rs_progress_end check ;;
      db_checked)
        step=8; [ "$CX_RS_FLOW" != new ] || step=$((5 + $(cx_rs_ext_shift)))
        cx_rs_progress_begin files
        cx_rs_step "$step" && cx_rs_images_load && cx_rs_files_place || rc=$?
        [ "$rc" != 0 ] || cx_rs_progress_end files ;;
      placed|started|awaiting_unseal)
        step=9; [ "$CX_RS_FLOW" != new ] || step=$((6 + $(cx_rs_ext_shift)))
        if [ "$phase" = awaiting_unseal ]; then cx_rs_start || rc=$?
        else cx_rs_step "$step" && cx_rs_start || rc=$?; fi ;;
      done) return 0 ;;
      *) return 1 ;;
    esac
    [ "$rc" = 0 ] || return "$rc"
  done
}

# The preflight and execution entries share the same lock and log. Resuming keeps the original
# log and checked host choices; only the first unfinished stage is run again.
cx_rs_execute() {
  local rc=0
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  CX_COMPOSE_ENV=$CX_ROOT/.env
  [ -f "$CX_COMPOSE_ENV" ] || CX_COMPOSE_ENV=$CX_RS_DIR/env.merged
  cx_rs_run || rc=$?
  if [ "$rc" = 0 ]; then cx_rs_finish || rc=$?; fi
  # A held external database printed its own stop screen.
  [ "$rc" != 1 ] || [ -n "${CX_RS_EXT_HELD:-}" ] || cx_rs_failure
  return "$rc"
}
cx_rs_continue() {
  local rc=0
  cx_lock
  [ "$(cx_state_get last_restore.result)" = in_progress ] || { cx_rs_no_pending; return "$?"; }
  cx_rs_recover_context || return 1
  CX_LOG_FILE=$(cx_state_get last_restore.log)
  [[ $CX_LOG_FILE == /* ]] || CX_LOG_FILE=$CX_ROOT/$CX_LOG_FILE
  trap cx_rs_cleanup EXIT
  trap cx_rs_signal INT TERM HUP
  case $CX_RS_ACTION in
    resume)
      if cx_br_flags_given && { [ "$(cx_state_get last_restore.phase)" != prepared ] || [ "$(cx_state_get last_restore.covering)" = 1 ]; }; then
        cx_line FAIL "$(cx_msg rs_safety_flags_phase)"; return 2
      fi
      cx_rs_resume_input && cx_rs_execute ;;
    revert) cx_rs_revert || rc=$?; [ "$rc" != 1 ] || cx_rs_failure; return "$rc" ;;
    abandon) cx_rs_abandon || rc=$?; [ "$rc" != 1 ] || cx_rs_failure; return "$rc" ;;
  esac
}
cx_rs_new() {
  cx_rs_flow
  cx_rs_read_setup && cx_rs_open "$1" && cx_rs_checks && cx_rs_release "$CX_RS_VERSION" &&
    cx_rs_migrations && cx_rs_env_merge && cx_rs_external && cx_rs_space || return 3
  if [ "$CX_RS_FLOW" = same ]; then
    cx_rs_safety_preflight || true
    cx_rs_safety_choose || return "$?"
  fi
  cx_rs_preview
  cx_rs_confirm || return 3
  # The external database's CA file and client certificate and key, where the settings name them.
  ! cx_rs_ext || cx_rs_ext_begin || return 1
  cx_rs_begin_execution
}
cx_rs_begin_execution() {
  cx_rs_context_save && cx_rs_record || return 1
  cx_rs_execute
}
