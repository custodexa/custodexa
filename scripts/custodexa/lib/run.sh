# shellcheck shell=bash
# One run of a command that changes state: lock, interrupted-run detection, steps,
# signal handling and confirmation. Nothing here undoes work: an interruption only records where
# it stopped and prints how to recover; there is no automatic rollback.

# shellcheck source=lib/restore_control.sh
. "${BASH_SOURCE[0]%/*}/restore_control.sh"

CX_RUN_CMD=""
CX_RUN_STEP=0

# State key prefix per command.
cx_run_prefix() {
  case $1 in
    install) printf 'install' ;;
    upgrade) printf 'last_upgrade' ;;
    rollback) printf 'last_rollback' ;;
    backup) printf 'last_backup' ;;
    restore) printf 'last_restore' ;;
    *) printf '%s' "$1" ;;
  esac
}

# cx_lock: one state-changing command at a time per deployment (flock on <root>/.custodexa.lock).
cx_lock() {
  local lock="$CX_ROOT/.custodexa.lock" holder
  exec 9>>"$lock"
  if ! flock -n 9; then
    holder=$(tr -dc '0-9' <"$lock" 2>/dev/null)
    cx_line FAIL "$(cx_msg lock_busy "${holder:-?}")" >&2
    exit "$CX_EXIT_REFUSED"
  fi
  : >"$lock"
  printf '%s\n' "$$" >>"$lock"
  cx_state_load "$CX_ROOT/state.json"
  cx_run_restore_guard "${CX_COMMAND:-${CX_SVC_COMMAND:-$CX_RUN_CMD}}" "${CX_RS_ACTION:-}" || exit "$CX_EXIT_REFUSED"
}

# The command whose state keys start with this prefix.
cx_run_command_of() {
  case $1 in
    last_upgrade) printf 'upgrade' ;;
    last_rollback) printf 'rollback' ;;
    last_backup) printf 'backup' ;;
    last_restore) printf 'restore' ;;
    *) printf '%s' "$1" ;;
  esac
}

# cx_recovery_hint <interrupted command>: the command that finishes the interrupted run. install
# and load are safe to repeat; upgrade and rollback add their own per-step table; until then the
# hint is status plus the log.
cx_recovery_hint() {
  local bundle
  case $1 in
    install) cx_cmd "sudo $CX_ROOT/custodexa.sh install" ;;
    rollback)
      if [ "$(cx_state_get last_rollback.direction)" = revert ]; then
        printf '  %s\n' "$(cx_msg rb_resume_revert "$(cx_state_get last_rollback.from)")"
      else
        printf '  %s\n' "$(cx_msg rb_resume)"
      fi
      cx_cmd "sudo $CX_ROOT/custodexa.sh rollback --resume$(cx_status_lang_arg)"
      if [ "$(cx_state_get last_rollback.direction)" != revert ] &&
        [[ $(cx_state_get last_rollback.step) =~ ^[2-4]$ ]]; then
        printf '  %s\n' "$(cx_msg rb_revert "$(cx_state_get last_rollback.from)")"
        cx_cmd "sudo $CX_ROOT/custodexa.sh rollback --revert$(cx_status_lang_arg)"
      fi
      ;;
    restore) cx_rs_control_hints ;;
    load)
      bundle=$(cx_state_get load.bundle)
      if [ -n "$bundle" ]; then
        cx_cmd "sudo $CX_ROOT/custodexa.sh load $bundle"
      else
        cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
      fi
      ;;
    *) cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)" ;;
  esac
}

# cx_new_started_mark: called by every entry that starts the services, right before it does. When
# current points at the version the last upgrade went to, last_upgrade.new_started_at records that
# the new version may have run (and so may have changed the database) and is written to state.json
# first; a write that fails returns 1 and the caller starts nothing. The record is never taken back:
# only the next upgrade clears it (cx_up_begin). Needs the deployment lock and state.json loaded.
cx_new_started_mark() {
  local to dirty=0
  # Any intervening start invalidates a saved check across the database-stop boundary,
  # even if the operator stops the services again before resuming the rollback.
  if [ "$(cx_state_get last_rollback.result)" = in_progress ] &&
    [ -n "$(cx_state_get last_rollback.switch_checked)" ]; then
    cx_state_unset last_rollback.switch_checked
    dirty=1
  fi
  to=$(cx_state_get last_upgrade.to)
  if [ -n "$to" ] && [ "$(readlink -- "$CX_ROOT/current" 2>/dev/null)" = "releases/$to" ] &&
    [ -z "$(cx_state_get last_upgrade.new_started_at)" ]; then
    cx_state_set last_upgrade.new_started_at "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
    dirty=1
  fi
  [ "$dirty" = 1 ] || return 0
  if ! cx_state_save "$CX_ROOT/state.json"; then
    cx_log FAIL "state.json not written: startup records; nothing started"
    return 1
  fi
  cx_log STATE "last_upgrade.new_started_at=$(cx_state_get last_upgrade.new_started_at)"
}

# ---------- a backup that never finished ----------
# An interrupted backup may leave the services stopped and its parts in a temporary folder. It does
# not hold up start, stop or another backup (each says so first); an upgrade waits until a backup
# finishes. The next backup records the interrupted one (last_backup.unfinished_*); only a
# finished backup clears that (lib/portable.sh cx_pb_record).
CX_RUN_BK_AT="" CX_RUN_BK_PARTIAL=""

# cx_run_backup_unfinished: true when the last backup is still in progress (it was interrupted:
# the lock keeps runs apart) or an interrupted one has not been followed by a finished backup.
# Sets CX_RUN_BK_AT (YYYY-MM-DD HH:MM, when it started) and CX_RUN_BK_PARTIAL (its temporary
# folder, "" when it made none).
cx_run_backup_unfinished() {
  local at partial
  if [ "$(cx_state_get last_backup.result)" = in_progress ]; then
    at=$(cx_state_get last_backup.started_at) partial=$(cx_state_get last_backup.partial)
  elif [ -n "$(cx_state_get last_backup.unfinished_at)" ]; then
    at=$(cx_state_get last_backup.unfinished_at) partial=$(cx_state_get last_backup.unfinished_partial)
  else
    return 1
  fi
  CX_RUN_BK_PARTIAL=""
  [ -z "$partial" ] || CX_RUN_BK_PARTIAL=$CX_ROOT/$partial/
  # The folder is named after the time the run took; else the time it started.
  if [[ ${partial##*.partial-} =~ ^([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})[0-9]{2}$ ]]; then
    CX_RUN_BK_AT="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}"
  elif [ -n "$at" ]; then
    CX_RUN_BK_AT="${at:0:10} ${at:11:5}"
  else
    CX_RUN_BK_AT="?"
  fi
}

# cx_run_backup_warn: the WARN that start, stop and backup print first after an unfinished backup.
cx_run_backup_warn() {
  cx_run_backup_unfinished || return 0
  if [ -n "$CX_RUN_BK_PARTIAL" ]; then
    cx_line WARN "$(cx_msg run_backup_unfinished "$CX_RUN_BK_AT" "$CX_RUN_BK_PARTIAL")"
  else
    cx_line WARN "$(cx_msg run_backup_unfinished_nodir "$CX_RUN_BK_AT")"
  fi
}

# cx_run_backup_refuse: an upgrade after an unfinished backup: refused until a backup finishes,
# with the commands to start the services and to back up again. Returns 1 when nothing is
# unfinished.
cx_run_backup_refuse() {
  cx_run_backup_unfinished || return 1
  cx_line FAIL "$(cx_msg run_backup_upgrade "$CX_RUN_BK_AT")"
  printf '  sudo %s/custodexa.sh start%s\n' "$CX_ROOT" "$(cx_status_lang_arg)"
  printf '  sudo %s/custodexa.sh backup%s\n' "$CX_ROOT" "$(cx_status_lang_arg)"
}

# cx_run_backup_rerun: a backup starting after an unfinished one: say so, and record the one that
# was interrupted (in state.json until a backup finishes, and at the end of its own log).
cx_run_backup_rerun() {
  local old step
  cx_run_backup_unfinished || return 0
  cx_run_backup_warn
  [ "$(cx_state_get last_backup.result)" = in_progress ] || return 0
  old=$(cx_state_get last_backup.log) step=$(cx_state_get last_backup.step)
  cx_state_set last_backup.unfinished_at "$(cx_state_get last_backup.started_at)"
  cx_state_set last_backup.unfinished_partial "$(cx_state_get last_backup.partial)"
  cx_state_unset last_backup.partial
  if [ -n "$old" ] && [ -f "$CX_ROOT/$old" ]; then
    printf '%s %-5s result=interrupted step=%s recorded_by=%s\n' "$(cx_log_now)" END "${step:-?}" \
      "${CX_LOG_FILE#"$CX_ROOT"/}" >>"$CX_ROOT/$old" 2>/dev/null || true
  fi
  cx_log PREVIOUS "backup result=interrupted step=${step:-?} log=${old:-none}"
}

# cx_run_switched_only <command>: the only unfinished run is an upgrade that already switched to the
# new version (step 9 or later), and the command is one its screens send people to: rollback, or the
# restore and load that a refused rollback prints. Anything else unfinished keeps them out as before.
cx_run_switched_only() {
  local key step=${CX_STATE[last_upgrade.step]:-}
  case $1 in rollback | restore | load) ;; *) return 1 ;; esac
  [ "${CX_STATE[last_upgrade.result]:-}" = in_progress ] || return 1
  [[ $step =~ ^[0-9]+$ ]] && [ "$step" -ge 9 ] || return 1
  for key in "${CX_STATE_KEYS[@]}"; do
    [[ $key == *.result ]] || continue
    [ "$key" = last_upgrade.result ] || [ "${CX_STATE[$key]}" != in_progress ] || return 1
  done
}

# cx_run_upgrade_handed: a restore takes over an upgrade interrupted after the switch. The upgrade
# is settled as failed (what a failure after the switch records) with the hand-over noted; every
# other key of it stays, and its own log gets the line that says who closed it.
cx_run_upgrade_handed() {
  local old step=${CX_STATE[last_upgrade.step]:-?}
  old=$(cx_state_get last_upgrade.log)
  cx_state_set last_upgrade.result failed
  cx_state_set last_upgrade.handed_to restore
  cx_state_set last_upgrade.handed_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  if [ -n "$old" ] && [ -f "$CX_ROOT/$old" ]; then
    printf '%s %-5s result=interrupted step=%s handed_to=restore\n' "$(cx_log_now)" END "$step" \
      >>"$CX_ROOT/$old" 2>/dev/null || true
  fi
}

# cx_run_upgrade_restored: a restore that finished settles an upgrade that failed after the backup
# or was handed over to it: the deployment is now what the backup holds. The upgrade preflight no
# longer refuses for that upgrade, and rollback has nothing to go back from. Every other key of it
# stays; the caller saves the state together with the restore's own result.
cx_run_upgrade_restored() {
  [ "$(cx_state_get last_upgrade.result)" = failed ] || return 0
  cx_state_set last_upgrade.settled_by restore || return 1
  cx_state_set last_upgrade.settled_at "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
  cx_log STATE "last_upgrade.settled_by=restore step=$(cx_state_get last_upgrade.step)"
}

# cx_begin <command>: lock, stop on an unfinished earlier run, then mark this run in progress.
cx_begin() {
  local cmd=$1 key prefix step handed=0
  CX_RUN_CMD=$cmd
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  for key in "${CX_STATE_KEYS[@]+"${CX_STATE_KEYS[@]}"}"; do
    [[ $key == *.result ]] || continue
    [ "${CX_STATE[$key]}" = in_progress ] || continue
    prefix=${key%.result}
    # The restore-specific gate has already checked this command under the lock.
    [ "$prefix" != last_restore ] || continue
    step=${CX_STATE[$prefix.step]:-?}
    if [ "$prefix" = last_upgrade ] && cx_run_switched_only "$cmd"; then
      [ "$cmd" = rollback ] || cx_line WARN "$(cx_msg run_interrupted upgrade "$step")"
      [ "$cmd" != restore ] || handed=1
      continue
    fi
    if [ "$prefix" = last_backup ]; then
      # Another backup goes on and records it (below); an upgrade waits for a finished backup.
      [ "$cmd" != backup ] || continue
      if [ "$cmd" = upgrade ]; then
        cx_run_backup_refuse
        exit "$CX_EXIT_REFUSED"
      fi
    fi
    cx_line WARN "$(cx_msg run_interrupted "$prefix" "$step")"
    if [ "$prefix" = install ] && [ "$cmd" = install ]; then
      printf '%s\n' "$(cx_msg run_install_rerun)"
      continue
    fi
    # load only loads and checks images; nothing else depends on an unfinished load.
    if [ "$prefix" = load ]; then
      printf '%s\n' "$(cx_msg run_load_rerun)"
      continue
    fi
    if [ "$prefix" = install ]; then
      printf '%s\n' "$(cx_msg run_recover_install)"
    else
      printf '%s\n' "$(cx_msg run_recover_first)"
    fi
    cx_recovery_hint "$(cx_run_command_of "$prefix")"
    exit "$CX_EXIT_REFUSED"
  done
  prefix=$(cx_run_prefix "$cmd")
  cx_secrets_from_env "$CX_ROOT/.env"
  cx_log_open "$cmd"
  local self=${CX_SELF:-} flags=${CX_FLAGS_TEXT:-}
  cx_log BEGIN "$cmd lang=${CX_LANG:-en} script=${self#"$CX_ROOT"/} flags=\"${flags# }\""
  [ "$cmd" != backup ] || cx_run_backup_rerun
  if [ "$handed" = 1 ]; then
    cx_run_upgrade_handed
    cx_log PREVIOUS "upgrade result=interrupted step=$(cx_state_get last_upgrade.step) handed_to=restore"
  fi
  cx_state_set "$prefix.log" "${CX_LOG_FILE#"$CX_ROOT"/}"
  cx_state_set "$prefix.result" in_progress
  cx_state_set "$prefix.step" 0
  cx_state_set "$prefix.started_at" "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_save "$CX_ROOT/state.json"
  # The terminal as it is now: a step may run its command with output sent to /dev/null, and the
  # signal handler runs inside that redirection.
  exec {CX_SIGNAL_FD}>&2
  trap 'cx_on_signal' INT TERM HUP
}

cx_step() { # <n> [total] [name]
  CX_RUN_STEP=$1
  cx_log STEP "$1${2:+/$2}${3:+ $3}"
  cx_state_set "$(cx_run_prefix "$CX_RUN_CMD").step" "$1"
  cx_state_save "$CX_ROOT/state.json"
}

cx_finish() { # <succeeded|failed>
  local prefix
  prefix=$(cx_run_prefix "$CX_RUN_CMD")
  cx_log END "result=$1 step=$CX_RUN_STEP"
  cx_state_set "$prefix.result" "$1"
  cx_state_set "$prefix.finished_at" "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_save "$CX_ROOT/state.json"
  trap - INT TERM HUP
}

# Signal: say where it stopped and how to go on; the state stays in_progress on purpose.
cx_on_signal() {
  trap - INT TERM HUP
  # A database client call of an external database may have its pgpass file on disk right now.
  ! declare -F cx_db_pgpass_rm >/dev/null || cx_db_pgpass_rm
  cx_log END "result=interrupted step=$CX_RUN_STEP"
  {
    printf '\n'
    cx_line FAIL "$(cx_msg run_signal "$CX_RUN_STEP")"
    cx_recovery_hint "$CX_RUN_CMD"
  } >&"${CX_SIGNAL_FD:-2}"
  exit "$CX_EXIT_FAILED"
}

# cx_confirm <message id> [args...]: y/N question (the message ends with its own [y/N]). --yes answers yes; without a terminal and
# without --yes the run stops (exit 3) instead of waiting for input that never comes.
cx_confirm() {
  local answer
  if [ "${CX_YES:-0}" = 1 ]; then
    return 0
  fi
  if [ ! -t 0 ]; then
    cx_line FAIL "$(cx_msg confirm_needs_yes)" >&2
    # A run that stops here did nothing unfinished: record it as cancelled, not in progress.
    [ -z "$CX_RUN_CMD" ] || cx_finish cancelled
    [ -z "${CX_SVC_COMMAND:-}" ] || cx_svc_finish cancelled
    exit "$CX_EXIT_REFUSED"
  fi
  printf '%s ' "$(cx_msg "$@")"
  read -r answer || answer=""
  case $answer in
    y | Y | yes | YES) return 0 ;;
    *) return 1 ;;
  esac
}

# cx_up_link <link> <target>: point a symlink at target in one rename.
cx_up_link() {
  [ "$(readlink -- "$1" 2>/dev/null)" != "$2" ] || return 0
  ln -sfn -- "$2" "$1.new" && mv -Tf -- "$1.new" "$1"
}
