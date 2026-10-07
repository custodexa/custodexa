# Screen functions from the pre-rollback baseline, for the legacy-version comparison.

cx_up_fail_switched() {
  local id=$1 st=up_state_switched
  shift
  [ "$id" != up_fail_ready ] || st=up_state_not_ready
  printf '\n'
  cx_line FAIL "$(cx_msg "$id" "$@")"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_state_title)")"
  cx_up_bullet "$(cx_msg "$st" "$CX_UP_TARGET")"
  cx_up_bullet_backup
  cx_up_bullet "$(cx_msg up_state_no_auto)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_logs_first)")"
  cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
  cx_up_par "$(cx_msg up_logs_more)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_restore_guide "$CX_UP_CURRENT")")"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
}

cx_up_recovery_hint() {
  local step=$2
  if [ "$1" != last_upgrade ] || ! [[ $step =~ ^[0-9]+$ ]]; then
    [ "$1" != last_upgrade ] || printf '%s\n' "$(cx_msg run_recover_first)"
    cx_recovery_hint "$(cx_run_command_of "$1")"
    return 0
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  if [ "$step" -le 8 ]; then
    cx_up_par "$(cx_msg up_hint_stopped)"
    cx_up_resume_cmd
    cx_up_par "$(cx_msg up_hint_again)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
  else
    cx_up_par "$(cx_msg up_hint_switched)"
    cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
    if [ -n "$(cx_state_get last_backup.file)" ]; then
      cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_backup.file)")"
    elif [ -n "$(cx_state_get last_backup.dir)" ]; then
      cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_backup.dir)/")"
    fi
    cx_up_par "$(cx_msg up_restore_guide "$(cx_state_get previous.version)")"
  fi
}

cx_pc_empty_screen() {
  local now_path before=$CX_BK_DATA sessions_now sessions_before
  now_path=$(cx_bk_env DATA_PATH)
  case $now_path in "" | /*) ;; *) now_path=$CX_ROOT/${now_path#./} ;; esac
  now_path=${now_path:-$CX_ROOT/data}
  sessions_now=$( [ -z "$CX_PC_AFTER" ] || cx_pc_snap "$CX_PC_AFTER" count.sessions)
  sessions_before=$( [ -z "$CX_UP_SNAP" ] || cx_pc_snap "$CX_UP_SNAP" count.sessions)
  printf '\n'
  cx_line FAIL "$(cx_msg pc_empty_title)"
  printf '\n'
  if [ "$now_path" != "$before" ]; then
    cx_up_par "$(cx_msg pc_empty_moved "$1" "${sessions_now:-?}" "$(cx_up_num "$2")" \
      "$(cx_up_num "${sessions_before:-0}")" "$before" "$now_path" "$before")"
    printf '\n'
    cx_up_par "$(cx_msg pc_empty_moved_do "$now_path" "$1" "${sessions_now:-?}" "$before" "$before" "$now_path")"
  else
    cx_up_par "$(cx_msg pc_empty_same "$1" "${sessions_now:-?}" "$(cx_up_num "$2")" \
      "$(cx_up_num "${sessions_before:-0}")" "$before")"
    printf '\n'
    cx_up_par "$(cx_msg pc_empty_same_do)"
  fi
  printf '\n'
  cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}

cx_up_done() {
  local sealed=1 n=0 url
  case $CX_BK_KEK in env | "") sealed=0 ;; esac
  printf '\n'
  if [ "$sealed" = 1 ]; then
    cx_line OK "$(cx_msg up_done_sealed "$CX_UP_TARGET")"
  else
    cx_line OK "$(cx_msg up_done "$CX_UP_TARGET")"
  fi
  printf '\n'
  cx_pc_print
  printf '\n%s\n' "$(cx_msg up_todo)"
  url=$(cx_bk_env PUBLIC_BASE_URL)
  case $CX_BK_KEK in
    ui) n=1; cx_up_point 1 "$(cx_msg up_todo_unseal_ui "${url%/}/unseal")" ;;
    kms | hsm) n=1; cx_up_point 1 "$(cx_msg up_todo_unseal_kms "${url%/}/unseal")" ;;
  esac
  if [ "$n" = 1 ]; then
    cx_up_point 2 "$(cx_msg up_todo_manual_after)"
  else
    cx_up_point 1 "$(cx_msg up_todo_manual)"
  fi
  printf '\n'
  cx_up_par "$(cx_msg up_done_rollback)"
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_up_par "$(cx_msg up_done_backup "$CX_UP_BACKUP_DIR/external.txt")"
  else
    cx_up_par "$(cx_msg up_done_backup "$CX_ROOT/$CX_UP_BACKUP")"
  fi
  cx_up_par "$(cx_msg up_done_log "$CX_LOG_FILE")"
}
