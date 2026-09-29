# shellcheck shell=bash
# The CX_BR_* results are read by the upgrade command.
# shellcheck disable=SC2034
# A backup of the operator's own (a virtual machine or storage snapshot) in place of the script's.
# It is only worth something when it starts after the audit queue drained and the services stopped:
# a snapshot taken earlier misses the last writes. So the script asks for it after the stop, shows
# both times, and refuses a snapshot whose start time is before the stop time (compared to the
# second; "the same day" or "about then" is not accepted).
#   interactive:      the choice [1/2], then the questions (name, start time, restore procedure, yes)
#   non-interactive:  --backup-ref with --backup-time and --backup-restore, only when the services
#                     were already stopped before the script started
# Nothing here restores anything: a rollback that needs this snapshot stops before the restore.

CX_BR_CHOICE="" CX_BR_REF="" CX_BR_TIME="" CX_BR_RESTORE="" CX_BR_EPOCH=""
CX_BR_STOP_EPOCH="" CX_BR_STOP_SHOWN="" CX_BR_STOP_ISO=""

cx_br_par() { printf '%s\n' "$1" | sed 's/^/  /'; }
cx_br_ind() { printf '  %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'         }"; }

# cx_br_backend: "running", "stopped <FinishedAt>", or "absent" for the backend container.
cx_br_backend() {
  local out
  out=$(docker container inspect --format '{{.State.Running}} {{.State.FinishedAt}}' custodexa-backend 2>/dev/null) \
    || { printf 'absent'; return 0; }
  case $out in
    true\ *) printf 'running' ;;
    *) printf 'stopped %s' "${out#* }" ;;
  esac
}

# cx_br_set_stop <time docker reports>: the stop time as seconds, as HH:MM:SS local and as ISO.
cx_br_set_stop() {
  CX_BR_STOP_EPOCH=$(date -d "$1" +%s 2>/dev/null) || return 1
  CX_BR_STOP_SHOWN=$(date -d "@$CX_BR_STOP_EPOCH" +%H:%M:%S)
  CX_BR_STOP_ISO=$(date -d "@$CX_BR_STOP_EPOCH" '+%Y-%m-%dT%H:%M:%S%z')
}

# cx_br_parse_time <YYYY-MM-DD HH:MM>: seconds since the epoch (local time); fails on anything else.
cx_br_parse_time() {
  [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] || return 1
  date -d "$1" +%s 2>/dev/null
}

# cx_br_after_stop <seconds>: the snapshot started at or after the stop, to the second.
cx_br_after_stop() { [ "$1" -ge "$CX_BR_STOP_EPOCH" ]; }

# cx_br_resume: how to cancel: bring every service back and check. A package deployment starts
# current/ with the image references of that release (images.env, as the script loads it before
# every compose call); a git clone deployment before its conversion has no current/ yet: its own
# project and root compose files, and the status of this script pointed at it.
cx_br_resume() {
  local ov f files=""
  printf '\n%s\n' "$(cx_br_par "$(cx_msg br_cancel_hint)")"
  if [ "${CX_UP_KIND:-}" = convert ]; then
    for f in $CX_UP_OLD_FILES; do files+="${files:+ }-f $f"; done
    cx_cmd "sudo docker compose -p $CX_UP_OLD_PROJECT --project-directory $CX_ROOT \\"
    cx_cmd "  $files up -d"
    cx_cmd "sudo env CUSTODEXA_HOME=$CX_ROOT $CX_DIR/custodexa.sh status$(cx_status_lang_arg)"
    return 0
  fi
  files="-f $CX_ROOT/current/compose.yml"
  for ov in ${CX_OVERLAYS:-}; do files+=" -f $CX_ROOT/current/compose.$ov.yml"; done
  cx_cmd "sudo sh -c 'set -a; . $CX_ROOT/current/images.env; exec \\"
  cx_cmd "  docker compose -p $CX_PROJECT --project-directory $CX_ROOT \\"
  cx_cmd "  $files up -d'"
  cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
}

cx_br_refused() {
  printf '\n'
  cx_line FAIL "$(cx_msg br_not_confirmed)"
  cx_br_resume
  return 1
}

# cx_br_time_early <entered HH:MM>: the refusal for a snapshot older than the stop.
cx_br_time_early() {
  cx_line FAIL "$(cx_msg br_time_early "$1" "$CX_BR_STOP_SHOWN")"
  cx_br_par "$(cx_msg br_time_early_detail)"
  cx_br_resume
}

# cx_br_ask <message id>: print the question (2 columns in), read one line into CX_BR_ANSWER.
# End of input is an empty answer.
CX_BR_ANSWER=""
cx_br_ask() {
  local q
  q=$(cx_msg "$1")
  q=${q//$'\n'/$'\n'  }
  printf '  %s' "$q"
  IFS= read -r CX_BR_ANSWER || CX_BR_ANSWER=""
}

# cx_br_choose <size text> <minutes> <external database 0|1>: CX_BR_CHOICE = 1 or 2. An external
# database leaves no choice: only the operator can back it up. Fails when no answer comes.
cx_br_choose() {
  local a
  if [ "$3" = 1 ]; then
    CX_BR_CHOICE=2
    return 0
  fi
  cx_line ASK "$(cx_msg br_title)"
  printf '\n'
  cx_br_par "$(cx_msg br_opt1)"
  cx_br_par "$(cx_msg br_opt1_detail "$1" "$2")" | sed 's/^/    /'
  cx_br_par "$(cx_msg br_opt2)"
  cx_br_par "$(cx_msg br_opt2_detail)" | sed 's/^/    /'
  printf '\n'
  while :; do
    printf '%s' "$(cx_msg br_choose)"
    IFS= read -r a || { cx_br_refused; return 1; }
    case $a in
      1 | 2) CX_BR_CHOICE=$a; return 0 ;;
    esac
  done
}

# cx_br_interactive <drained HH:MM:SS> <external database 0|1>: after the stop, the questions of
# the own-backup path. 0 = accepted (CX_BR_* set); 1 = refused, the services stay stopped and how
# to bring them back is printed.
cx_br_interactive() {
  local drained=$1 ext=$2 t
  printf '\n'
  cx_line WARN "$(cx_msg br_chosen)"
  printf '\n'
  cx_br_par "$(cx_msg br_times "$drained" "$CX_BR_STOP_SHOWN")"
  printf '\n'
  cx_br_par "$(cx_msg br_must)"
  {
    cx_msg br_item_data "$(cx_br_data_path)"
    printf '\n'
    cx_msg br_item_env "$CX_ROOT/.env"
    printf '\n'
    cx_msg br_item_tls "$CX_ROOT/tls/"
    if [ "$ext" = 1 ]; then
      printf '\n'
      cx_msg br_item_db "$CX_BR_STOP_SHOWN"
    fi
    printf '\n'
  } | sed 's/^/    /'
  printf '\n'
  cx_br_par "$(cx_msg br_cannot_check)"
  printf '\n'
  cx_br_par "$(cx_msg br_enter)"
  cx_br_ask br_ask_ref
  CX_BR_REF=$CX_BR_ANSWER
  [ -n "$CX_BR_REF" ] || { cx_br_refused; return 1; }
  while :; do
    cx_br_ask br_ask_time
    [ -n "$CX_BR_ANSWER" ] || { cx_br_refused; return 1; }
    if t=$(cx_br_parse_time "$CX_BR_ANSWER"); then
      break
    fi
    cx_br_ind WARN "$(cx_msg br_time_format)"
  done
  if ! cx_br_after_stop "$t"; then
    printf '\n'
    cx_br_time_early "${CX_BR_ANSWER#* }"
    return 1
  fi
  CX_BR_TIME=$CX_BR_ANSWER CX_BR_EPOCH=$t
  cx_br_ind OK "$(cx_msg br_time_ok "${CX_BR_TIME#* }" "$CX_BR_STOP_SHOWN")"
  cx_br_ask br_ask_restore
  CX_BR_RESTORE=$CX_BR_ANSWER
  [ -n "$CX_BR_RESTORE" ] || { cx_br_refused; return 1; }
  cx_br_ask br_ask_yes
  if [ "$CX_BR_ANSWER" != yes ]; then
    cx_br_refused
    return 1
  fi
}

cx_br_data_path() {
  local d
  d=$(sed -n 's/^[[:space:]]*DATA_PATH=//p' "$CX_ROOT/.env" 2>/dev/null | tail -n 1)
  d=${d:-./data}
  case $d in
    /*) printf '%s' "$d" ;;
    *) printf '%s/%s' "$CX_ROOT" "${d#./}" ;;
  esac
}

# cx_br_flags_given: any of the three own-backup options was given.
cx_br_flags_given() { [ -n "${CX_BACKUP_REF:-}${CX_BACKUP_TIME:-}${CX_BACKUP_RESTORE:-}" ]; }

# cx_br_noninteractive: --backup-ref with its two companions. Returns 0 (accepted, CX_BR_* set),
# 2 (options incomplete), 3 (services still running: refused, nothing changed) or 1 (the snapshot
# is older than the stop, the stop time is unknown, or the stop did not drain the audit queue).
cx_br_noninteractive() {
  local st t
  if [ -z "${CX_BACKUP_REF:-}" ] || [ -z "${CX_BACKUP_TIME:-}" ] || [ -z "${CX_BACKUP_RESTORE:-}" ]; then
    cx_line FAIL "$(cx_msg br_flags_incomplete)"
    return 2
  fi
  if ! t=$(cx_br_parse_time "$CX_BACKUP_TIME"); then
    cx_line FAIL "$(cx_msg br_time_format)"
    return 2
  fi
  st=$(cx_br_backend)
  case $st in
    running)
      cx_line FAIL "$(cx_msg br_ref_running)"
      return 3
      ;;
    stopped\ *) cx_br_set_stop "${st#stopped }" || { cx_line FAIL "$(cx_msg br_stop_unknown)"; return 1; } ;;
    *)
      cx_line FAIL "$(cx_msg br_stop_unknown)"
      return 1
      ;;
  esac
  # The same check as after the upgrade's own stop: a stop that timed out draining lost records.
  if docker logs custodexa-backend 2>&1 | grep -q '稽核佇列排空逾時'; then
    cx_line FAIL "$(cx_msg br_drain_timeout)"
    return 1
  fi
  if ! cx_br_after_stop "$t"; then
    cx_br_time_early "${CX_BACKUP_TIME#* }"
    return 1
  fi
  CX_BR_REF=$CX_BACKUP_REF CX_BR_TIME=$CX_BACKUP_TIME CX_BR_RESTORE=$CX_BACKUP_RESTORE CX_BR_EPOCH=$t
  cx_line WARN "$(cx_msg br_ref_used "$CX_BR_REF" "${CX_BR_TIME#* }" "$CX_BR_STOP_SHOWN")"
}

# cx_br_record <id> [nostate]: the accepted own backup: backups/<id>/external.txt (the answers as
# given, any language) and last_backup.* in state.json. A value state.json cannot hold (not
# printable ASCII) is kept in the file only and state.json points there. With nostate (a git clone
# deployment before its conversion, which has no state.json yet) only the file and the log.
cx_br_record() {
  local id=$1 dir=$CX_ROOT/backups/$1 k v ptr
  (umask 077 && mkdir -p "$CX_ROOT/backups" "$dir") || return 1
  chmod 0700 "$CX_ROOT/backups" "$dir"
  (
    umask 077
    printf 'ref=%s\ntime=%s\nrestore=%s\nstopped_at=%s\n' \
      "$CX_BR_REF" "$CX_BR_TIME" "$CX_BR_RESTORE" "$CX_BR_STOP_ISO" >"$dir/external.txt"
  ) || return 1
  if [ "${2:-}" = nostate ]; then
    cx_log BACKUP "kind=external id=$id time=\"$CX_BR_TIME\" stopped_at=$CX_BR_STOP_ISO"
    return 0
  fi
  ptr="see backups/$id/external.txt"
  cx_state_set last_backup.id "$id"
  cx_state_set last_backup.kind external
  cx_state_set last_backup.dir "backups/$id"
  cx_state_set last_backup.taken_at "$(date -d "@$CX_BR_EPOCH" '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set last_backup.external_time "$(date -d "@$CX_BR_EPOCH" '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set last_backup.stopped_at "$CX_BR_STOP_ISO"
  for k in ref restore; do
    v=$CX_BR_REF
    [ "$k" = restore ] && v=$CX_BR_RESTORE
    cx_state_valid_value "$v" || v=$ptr
    cx_state_set "last_backup.external_$k" "$v"
  done
  # Values of an earlier script backup do not describe this one.
  cx_state_set last_backup.size_bytes ""
  cx_state_set last_backup.snapshot_usable ""
  cx_state_save "$CX_ROOT/state.json"
  cx_log BACKUP "kind=external id=$id time=\"$CX_BR_TIME\" stopped_at=$CX_BR_STOP_ISO"
  cx_log BACKUP "external_ref=\"$CX_BR_REF\" external_restore=\"$CX_BR_RESTORE\""
}
