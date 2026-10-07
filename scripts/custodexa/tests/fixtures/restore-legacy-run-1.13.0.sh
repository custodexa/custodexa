# Source: Custodexa 1.13.0 lib/run.sh, retained verbatim below for compatibility testing.
# shellcheck shell=bash
# One run of a command that changes state: lock, interrupted-run detection, steps,
# signal handling and confirmation. Nothing here undoes work: an interruption only records where
# it stopped and prints how to recover; there is no automatic rollback.

CX_RUN_CMD=""
CX_RUN_STEP=0

# State key prefix per command.
cx_run_prefix() {
  case $1 in
    install) printf 'install' ;;
    upgrade) printf 'last_upgrade' ;;
    rollback) printf 'last_rollback' ;;
    backup) printf 'last_backup' ;;
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
}

# The command whose state keys start with this prefix.
cx_run_command_of() {
  case $1 in
    last_upgrade) printf 'upgrade' ;;
    last_rollback) printf 'rollback' ;;
    last_backup) printf 'backup' ;;
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
    load)
      bundle=$(cx_state_get load.bundle)
      if [ -n "$bundle" ]; then
        cx_cmd "sudo $CX_ROOT/custodexa.sh load $bundle"
      else
        cx_cmd "sudo $CX_ROOT/custodexa.sh status"
      fi
      ;;
    *) cx_cmd "sudo $CX_ROOT/custodexa.sh status" ;;
  esac
}

# cx_begin <command>: lock, stop on an unfinished earlier run, then mark this run in progress.
cx_begin() {
  local cmd=$1 key prefix step
  CX_RUN_CMD=$cmd
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  for key in "${CX_STATE_KEYS[@]+"${CX_STATE_KEYS[@]}"}"; do
    [[ $key == *.result ]] || continue
    [ "${CX_STATE[$key]}" = in_progress ] || continue
    prefix=${key%.result}
    step=${CX_STATE[$prefix.step]:-?}
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
    exit "$CX_EXIT_REFUSED"
  fi
  printf '%s ' "$(cx_msg "$@")"
  read -r answer || answer=""
  case $answer in
    y | Y | yes | YES) return 0 ;;
    *) return 1 ;;
  esac
}
