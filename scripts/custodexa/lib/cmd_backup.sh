# shellcheck shell=bash
# CX_OVERLAYS is read by lib/compose.sh.
# shellcheck disable=SC2034
# custodexa.sh backup: a stopped backup of this deployment into backups/<timestamp>/ (lib/backup.sh).
#   preview (pause, sealing, size and free space) -> confirm -> 6 steps -> where it is, how to keep it
# Not enough space stops the run before any service is stopped. A deployment on an external database
# is not backed up here: its database is backed up with the operator's own procedure.
# shellcheck source=lib/backup.sh
. "${BASH_SOURCE[0]%/*}/backup.sh"

# cmd_backup_ind <mark> <text>: a status line 2 columns in, later lines under the text.
cmd_backup_ind() { printf '  %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'         }"; }
# cmd_backup_par <text>: a paragraph 2 columns in.
cmd_backup_par() { printf '%s\n' "$1" | sed 's/^/  /'; }

# cmd_backup_step <OK|FAIL> <n> <total> <step id> <start>: the step line; a few steps show no time.
cmd_backup_step() {
  local dur=""
  if [ "$1" = OK ] && [ "$4" != conf ]; then
    dur=$(cx_duration $(($(cx_now) - $5)))
  fi
  cx_step_line "$1" "$2/$3" "$(cx_msg "bk_step_$4")" "$dur"
  cx_step "$2" "$3" "$4"
}

# cmd_backup_contents: "Contains: database, ..., certificates tls/", wrapped like the screen.
cmd_backup_contents() {
  local sep items env=bk_item_env
  sep=$(cx_msg bk_item_sep)
  [ "$CX_BK_KEK" = env ] && env=bk_item_env_kek
  items="$(cx_msg bk_item_db)$sep$(cx_msg bk_item_rec)$sep$(cx_msg bk_item_audit)$sep$(cx_msg "$env")$sep$(cx_msg bk_item_tls)"
  cmd_backup_par "$(cx_wrap 70 "$(cx_msg bk_contents "$items")")"
}

cmd_backup_unseal_url() {
  local url
  url=$(cx_bk_env PUBLIC_BASE_URL)
  printf '%s/unseal' "${url%/}"
}

cmd_backup() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_state_load "$CX_ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  case " $CX_OVERLAYS " in
    *" external-database "*) cx_die "$CX_EXIT_REFUSED" bk_external_db ;;
  esac
  cx_bk_vars
  cx_begin backup

  if ! cx_bk_estimate; then
    cx_line FAIL "$(cx_msg bk_db_unreachable)"
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  printf '%s\n\n' "$(cx_msg bk_title)"
  cmd_backup_par "$(cx_msg bk_pause "$(cx_bk_minutes)")"
  [ "$CX_BK_KEK" != ui ] || cmd_backup_ind WARN "$(cx_msg bk_warn_seal)"
  cmd_backup_par "$(cx_msg bk_size "$(cx_bk_gb "$CX_BK_NEED")" "$(cx_bk_gb "$CX_BK_FREE")")"
  printf '\n'
  cx_log PREVIEW "need=$CX_BK_NEED free=$CX_BK_FREE kek_provider=$CX_BK_KEK"
  if [ "$CX_BK_NEED" -gt "$CX_BK_FREE" ]; then
    cx_line FAIL "$(cx_msg bk_no_space "$(cx_bk_gb "$CX_BK_NEED")" "$CX_ROOT/backups" "$(cx_bk_gb "$CX_BK_FREE")")"
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  if ! cx_confirm bk_confirm; then
    printf '%s\n' "$(cx_msg pre_nothing_changed)"
    cx_finish cancelled
    exit "$CX_EXIT_REFUSED"
  fi
  # --yes answered the question: show it answered, as on the terminal.
  [ "${CX_YES:-0}" != 1 ] || printf '%s y\n' "$(cx_msg bk_confirm)"
  printf '\n'

  if ! cx_bk_open; then
    cx_line FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  if ! cx_bk_take standalone cmd_backup_step; then
    printf '\n'
    cx_line FAIL "$(cx_msg bk_failed "$CX_BK_DIR/")"
    # Stopped at step 1 to 5 of 6: the services may still be stopped.
    if [ "$CX_BK_FAILED_STEP" != verify ]; then
      printf '%s\n' "$(cx_msg bk_start_again)"
      cx_cmd "cd $CX_ROOT && sudo docker compose start $CX_BK_SERVICES"
    fi
    printf '%s\n' "$(cx_msg bk_log "$CX_LOG_FILE")"
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  cx_finish succeeded

  printf '\n'
  cx_line OK "$(cx_msg bk_done "$CX_BK_DIR/" "$(cx_bk_gb "$(cx_bk_du "$CX_BK_DIR")")")"
  cmd_backup_contents
  [ "$CX_SNAP_USABLE" = true ] || cmd_backup_ind WARN "$(cx_msg bk_warn_snapshot)"
  cmd_backup_ind WARN "$(cx_msg bk_warn_keep)"
  [ "$CX_BK_KEK" != ui ] || cmd_backup_ind WARN "$(cx_msg bk_warn_sealed "$(cmd_backup_unseal_url)")"
  cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}
