# shellcheck shell=bash
# CX_PC_* are read by the closing screen of upgrade.
# shellcheck disable=SC2034
# Step 12 of upgrade: is the new version running on the same data? Compared with the snapshot taken
# while the old version was stopped (lib/snapshot.sh):
#   services       backend, guacd, frontend running; postgres running and healthy        FAIL
#   version        /health reports the target version                                     FAIL
#   images         every container runs the image ID checked in step 2                    FAIL
#   empty database the backend log shows the baseline migration run, or users dropped to  stop all
#                  1 or fewer from more than 1: the new version made a fresh database      services,
#                  somewhere else. The services are stopped at once (nothing is changed    FAIL
#                  or deleted) so nobody signs in or sets up a master key on it.
#   structure      every migration from before is still there; the new ones are listed    FAIL
#   counts         users and sessions equal, audit_logs not fewer                         FAIL
#   keys           the four fingerprints equal; a snapshot that is not usable: WARN       FAIL
#   instance lock  "held" in the log; held by another database session                    FAIL
#   entry          the HTTPS (or, behind an external ingress, HTTP) port answers          WARN
# What cannot be read is a warning, not a stop, except where the list above says FAIL: a value that
# is missing proves nothing either way, and the manual checks on the closing screen remain.

readonly CX_PC_BASELINE='執行 migration: 20260816_schema_baseline'
readonly CX_PC_LOCK_HELD='[InstanceGuard] 單實例鎖狀態=held'
readonly CX_PC_LOCK_OTHER='由另一個資料庫工作階段持有'

declare -ga CX_PC_ROWS=() # mark, text, mark, text, ...
CX_PC_FAIL=0 CX_PC_LOG="" CX_PC_AFTER=""

cx_pc_row() { # <mark> <message id> [args...]
  local m=$1 id=$2
  shift 2
  CX_PC_ROWS+=("$m" "$(cx_msg "$id" "$@")")
  cx_log CHECK "$m $id $*"
  [ "$m" != FAIL ] || CX_PC_FAIL=1
}

# cx_pc_print: the rows under their heading, 2 columns in; later lines of a row carry their indent.
cx_pc_print() {
  local i
  printf '%s\n' "$(cx_msg pc_title)"
  for ((i = 0; i < ${#CX_PC_ROWS[@]}; i += 2)); do
    printf '  %s %s\n' "$(cx_mark "${CX_PC_ROWS[i]}")" "${CX_PC_ROWS[i + 1]//$'\n'/$'\n'         }"
  done
}

cx_pc_snap() { cx_snap_get "$1" "$2"; }

# cx_pc_services: the long-running services are up; postgres also healthy.
cx_pc_services() {
  local out s want="backend guacd frontend" line bad=""
  [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ] || want+=" postgres"
  out=$(cx_compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null) || out=""
  for s in $want; do
    line=$(printf '%s\n' "$out" | awk -v s="$s" '$1 == s { print; exit }')
    case $s:$line in
      postgres:"postgres running healthy") ;;
      postgres:*) bad+="${bad:+ }$s" ;;
      *:"$s running"*) ;;
      *) bad+="${bad:+ }$s" ;;
    esac
  done
  [ -z "$bad" ] || cx_pc_row FAIL pc_services_bad "$bad"
}

# cx_pc_empty: the new version runs on a fresh database. 0 = it does.
cx_pc_empty() {
  local before=$1 after=$2
  if printf '%s\n' "$CX_PC_LOG" | grep -qF "$CX_PC_BASELINE"; then
    return 0
  fi
  [[ $before =~ ^[0-9]+$ ]] && [[ $after =~ ^[0-9]+$ ]] && [ "$before" -gt 1 ] && [ "$after" -le 1 ]
}

# cx_pc_data: structure, counts and keys against the snapshot. Unreadable values warn.
cx_pc_data() {
  local b=$CX_UP_SNAP a=$CX_PC_AFTER missing added k
  if [ -z "$b" ] || [ -z "$a" ]; then
    cx_pc_row WARN pc_data_unknown
    return 0
  fi
  local bu bs ba au as aa
  bu=$(cx_pc_snap "$b" count.users) bs=$(cx_pc_snap "$b" count.sessions) ba=$(cx_pc_snap "$b" count.audit_logs)
  au=$(cx_pc_snap "$a" count.users) as=$(cx_pc_snap "$a" count.sessions) aa=$(cx_pc_snap "$a" count.audit_logs)
  if ! [[ "$bu$bs$ba$au$as$aa" =~ ^[0-9]+$ ]] || [ -z "$bu" ] || [ -z "$au" ]; then
    cx_pc_row WARN pc_data_unknown
  elif [ "$au" = "$bu" ] && [ "$as" = "$bs" ] && [ "$aa" -ge "$ba" ]; then
    cx_pc_row OK pc_same_data "$(cx_up_num "$au")" "$(cx_up_num "$as")" "$(cx_up_num "$aa")" \
      "$(cx_up_num "$ba")" "$(cx_up_num $((aa - ba)))"
  else
    cx_pc_row FAIL pc_counts_bad "$(cx_up_num "$au")" "$(cx_up_num "$bu")" "$(cx_up_num "$as")" \
      "$(cx_up_num "$bs")" "$(cx_up_num "$aa")" "$(cx_up_num "$ba")"
  fi
  missing=$(comm -23 <(cx_snap_migrations "$b" | sort) <(cx_snap_migrations "$a" | sort))
  added=$(comm -13 <(cx_snap_migrations "$b" | sort) <(cx_snap_migrations "$a" | sort))
  if [ -n "$missing" ]; then
    cx_pc_row FAIL pc_mig_missing "$(printf '%s\n' "$missing" | paste -sd' ')"
  elif [ -z "$added" ]; then
    cx_pc_row OK pc_mig_none
  elif [ "$(printf '%s\n' "$added" | grep -c .)" -eq 1 ]; then
    cx_pc_row OK pc_mig_one "$added"
  else
    cx_pc_row OK pc_mig_many "$(printf '%s\n' "$added" | grep -c .)" "$(printf '%s\n' "$added" | paste -sd' ')"
  fi
  if [ "$(cx_pc_snap "$b" usable)" != true ] || [ "$(cx_pc_snap "$a" usable)" != true ]; then
    cx_pc_row WARN pc_keys_manual
    return 0
  fi
  for k in fp.jwt fp.kek fp.export_signing fp.checkpoint_signing; do
    if [ "$(cx_pc_snap "$b" "$k")" != "$(cx_pc_snap "$a" "$k")" ]; then
      cx_pc_row FAIL pc_keys_changed
      return 0
    fi
  done
  cx_pc_row OK pc_keys_same
}

# cx_pc_lock: the single-instance lock, from the log of this start.
cx_pc_lock() {
  if printf '%s\n' "$CX_PC_LOG" | grep -qF "$CX_PC_LOCK_OTHER"; then
    cx_pc_row FAIL pc_lock_other
  elif printf '%s\n' "$CX_PC_LOG" | grep -qF "$CX_PC_LOCK_HELD"; then
    cx_pc_row OK pc_lock_held
  else
    cx_pc_row WARN pc_lock_unknown
  fi
}

# cx_pc_entry: the way users come in answers (any 2xx or 3xx).
cx_pc_entry() {
  local url code
  if [[ " $CX_OVERLAYS " == *" external-ingress "* ]]; then
    url="http://127.0.0.1:$(cx_bk_env HTTP_PORT)"
    [ "$url" != "http://127.0.0.1:" ] || url=http://127.0.0.1:80
  else
    url="https://127.0.0.1:$(cx_bk_env TLS_HTTPS_PORT)"
    [ "$url" != "https://127.0.0.1:" ] || url=https://127.0.0.1:443
  fi
  code=$(curl -skI -o /dev/null -w '%{http_code}' --max-time 10 "$url/" 2>/dev/null) || code=""
  [[ $code =~ ^[23][0-9][0-9]$ ]] || cx_pc_row WARN pc_entry_bad "$url/"
}

# cx_pc_stop_all: the empty-database stop: every service, the database too.
cx_pc_stop_all() { cx_log_run cx_compose stop >/dev/null 2>&1; }

# cx_up_post_checks <n>: step 12. 0 = every check passed or only warned.
cx_up_post_checks() {
  local n=$1 started bu au tmp
  CX_PC_ROWS=() CX_PC_FAIL=0 CX_PC_AFTER=""
  started=$(docker container inspect --format '{{.State.StartedAt}}' custodexa-backend 2>/dev/null) || started=""
  CX_PC_LOG=$(docker logs ${started:+--since "$started"} custodexa-backend 2>&1) || CX_PC_LOG=""
  # Taken through the database client: the bundled service, or the external database's client once
  # one was chosen (lib/dbext.sh); without one there is no snapshot after.
  if cx_db_ready; then
    tmp=$(mktemp)
    if cx_snap_take "$tmp" "$(cx_bk_env JWT_SECRET)"; then
      # Kept next to the log, beside the snapshot from before (<log>.before.txt).
      CX_PC_AFTER=${CX_LOG_FILE%.log}.after.txt
      mv -f "$tmp" "$CX_PC_AFTER" 2>/dev/null || CX_PC_AFTER=$tmp
    else
      rm -f "$tmp"
    fi
  fi
  [ -z "$CX_UP_SNAP" ] || bu=$(cx_pc_snap "$CX_UP_SNAP" count.users)
  [ -z "$CX_PC_AFTER" ] || au=$(cx_pc_snap "$CX_PC_AFTER" count.users)
  if cx_pc_empty "${bu:-}" "${au:-}"; then
    cx_log FAIL "empty database: baseline or users ${bu:-?} -> ${au:-?}; stopping every service"
    cx_pc_stop_all
    cx_up_step_line FAIL "$n" "$(cx_msg up_step_check)"
    cx_pc_empty_screen "${au:-?}" "${bu:-?}"
    return 1
  fi
  cx_pc_services
  if [ "$CX_UP_HEALTH_VER" = "$CX_UP_TARGET" ]; then
    cx_pc_row OK pc_version "$CX_UP_HEALTH_VER"
  else
    cx_pc_row FAIL pc_version_bad "${CX_UP_HEALTH_VER:-?}" "$CX_UP_TARGET"
  fi
  tmp=$(mktemp)
  if ! cx_images_verify_running >"$tmp" 2>&1; then
    cx_pc_row FAIL pc_images_bad
  fi
  rm -f "$tmp"
  cx_pc_data
  cx_pc_lock
  cx_pc_entry
  if [ "$CX_PC_FAIL" = 1 ]; then
    cx_up_step_line FAIL "$n" "$(cx_msg up_step_check)"
    printf '\n'
    cx_pc_print
    cx_up_fail_switched up_fail_checks
    return 1
  fi
  cx_up_step_line OK "$n" "$(cx_msg up_step_check)"
}

# cx_pc_empty_screen <users now> <users before>: the new version found an empty database.
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
  if cx_rb_hint_ok; then
    printf '\n'
    cx_up_bullet_backup
    cx_rb_hint
  fi
  printf '\n'
  cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}

# ---------- the closing screen ----------

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
  if cx_rb_hint_ok; then
    cx_up_par "$(cx_msg rb_upgrade_done "$(cx_state_get last_upgrade.from)" "$CX_ROOT" "$(cx_status_lang_arg)")"
  else
    cx_up_par "$(cx_msg up_done_rollback)"
  fi
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_up_par "$(cx_msg up_done_backup "$CX_UP_BACKUP_DIR/external.txt")"
  else
    cx_up_par "$(cx_msg up_done_backup "$CX_ROOT/$CX_UP_BACKUP")"
  fi
  cx_up_par "$(cx_msg up_done_log "$CX_LOG_FILE")"
}

# cx_up_point <n> <text>: "  1. text", later lines under the text.
cx_up_point() { printf '  %s. %s\n' "$1" "${2//$'\n'/$'\n'     }"; }
