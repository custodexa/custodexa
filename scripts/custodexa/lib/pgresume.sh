# shellcheck shell=bash
# An upgrade interrupted in step 8 (the database conversion), and what the next upgrade does with it.
# The old data folder is never touched here. Step 5 records when the application services stopped and
# the ID of each application container (last_upgrade.app_stop.*); the next upgrade judges, in this
# order, after any unfinished folder rename was settled (lib/dirop.sh):
#   recovery=restart_old is on record   the failure wrap-up was cut short: finish it (the temporary
#                                       container and the export scratch space go, the new folder is
#                                       kept as failed-convert, the old services start when they are
#                                       not running), then a new upgrade from the start; the backup
#                                       and the snapshot of that run are not used again
#   the application services run        they were started by hand: a new upgrade from the start
#   the services are stopped            the backup stays valid only when the stop is proven to be
#                                       unbroken: every application container exists, has the ID
#                                       recorded at the stop, is not running, and was started before
#                                       the recorded stop. Equal row counts prove nothing (an update of
#                                       an existing row changes none), so they are only an extra check.
#                                       Proven: the half-converted folder is kept as partial-convert and
#                                       step 8 runs again on the backup of the run that was cut short.
#                                       Anything else, or nothing recorded: a new upgrade from the start.
# CX_UP_RESUME is none | fresh | resume for the run that follows. Needs lib/pgconvert.sh, lib/dirop.sh
# and lib/backup.sh loaded (cx_bk_vars has run).
# shellcheck disable=SC2034
CX_UP_RESUME=none CX_PGR_WHY="" CX_PGR_STATE=""

# cx_pgr_record_stop: step 5, once the services are stopped: the time and the container IDs. Anything
# that cannot be read leaves no record at all (a later judgment then finds nothing to prove with).
cx_pgr_record_stop() {
  local svc id ids=""
  for svc in $(cx_up_services); do
    id=$(cx_compose ps -aq "$svc" 2>/dev/null | head -n 1)
    [[ $id =~ ^[0-9a-f]{12,64}$ ]] || { ids=""; break; }
    ids+="${ids:+ }$svc=$id"
  done
  if [ -z "$ids" ]; then
    cx_state_unset last_upgrade.app_stop.at
    cx_state_unset last_upgrade.app_stop.ids
    cx_log WARN "stop: application container IDs not readable, no stop record"
  else
    cx_state_set last_upgrade.app_stop.at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    cx_state_set last_upgrade.app_stop.ids "$ids"
  fi
  cx_state_save "$CX_ROOT/state.json" || cx_log WARN "stop: state.json not written after the stop"
}

# cx_pgr_proof: 0 when nothing started an application container since the stop of step 5 (CX_PGR_WHY
# otherwise: no_record, time, gone, running, started).
cx_pgr_proof() {
  local at ids pair id info cur_id started running stop_epoch start_epoch
  at=$(cx_state_get last_upgrade.app_stop.at) ids=$(cx_state_get last_upgrade.app_stop.ids)
  if [ -z "$at" ] || [ -z "$ids" ]; then CX_PGR_WHY=no_record; return 1; fi
  stop_epoch=$(date -d "$at" +%s 2>/dev/null) || { CX_PGR_WHY="time"; return 1; }
  for pair in $ids; do
    id=${pair#*=}
    info=$(docker inspect --format '{{.Id}}|{{.State.StartedAt}}|{{.State.Running}}' "$id" 2>/dev/null) \
      || { CX_PGR_WHY=gone; return 1; }
    IFS='|' read -r cur_id started running <<<"$info"
    case $cur_id in "$id"*) ;; *) CX_PGR_WHY=gone; return 1 ;; esac
    [ "$running" = false ] || { CX_PGR_WHY=running; return 1; }
    start_epoch=$(date -d "$started" +%s 2>/dev/null) || { CX_PGR_WHY="time"; return 1; }
    [ "$start_epoch" -lt "$stop_epoch" ] || { CX_PGR_WHY=started; return 1; }
  done
}

# cx_pgr_consistent: the extra check, never the proof: no connection of the application account, and
# the counts and migrations the snapshot of that run recorded are what the database holds now.
cx_pgr_consistent() {
  local snap t n want conn migs
  snap=$(cx_state_get last_upgrade.snapshot)
  [ -n "$snap" ] && [ -f "$CX_ROOT/$snap" ] || return 0
  cx_db_ready || return 0
  conn=$(cx_snap_sql "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = current_user AND pid <> pg_backend_pid()" 2>/dev/null) || return 1
  [ "$conn" = 0 ] || return 1
  for t in users sessions audit_logs; do
    n=$(cx_snap_sql "SELECT count(*) FROM $t" 2>/dev/null) || return 1
    want=$(cx_snap_get "$CX_ROOT/$snap" "count.$t")
    [ "$n" = "$want" ] || return 1
  done
  migs=$(cx_snap_sql "SELECT version FROM schema_migrations ORDER BY version" 2>/dev/null) || return 1
  [ "$migs" = "$(cx_snap_migrations "$CX_ROOT/$snap")" ] || return 1
}

# cx_pgr_restart_old: the old application services start and the backend becomes healthy. 1 both, 2
# started but not healthy, 0 not started.
cx_pgr_restart_old() {
  # shellcheck disable=SC2046
  cx_log_run cx_compose start $(cx_up_services) >/dev/null 2>&1 || return 0
  cx_wait_backend_health >/dev/null 2>&1 || return 2
  return 1
}

# cx_pgr_aside <new folder> <rename id> <target>: the half-converted new folder goes aside through
# the rename log (never deleted); CX_PGR_ASIDE is where it went.
cx_pgr_aside() {
  local new=$1 id=$2 to=$3
  [ -d "$new" ] && [ -n "$(ls -A "$new" 2>/dev/null)" ] || return 0
  cx_dirop_rename "$id" "$new" "$to" || return 1
  CX_PGR_ASIDE=$to
}

# cx_pgr_judge: the interrupted step 8. Returns 0 (CX_UP_RESUME and the screen set) or the refusal's
# exit code, with the screen, when a folder rename cannot be told apart.
CX_PGR_ASIDE="" CX_PGR_BACKUP=""
cx_pgr_judge() {
  local rec ph new old st rc=0 ts running=0 started=0
  CX_UP_RESUME=fresh CX_PGR_ASIDE="" CX_PGR_STATE="" CX_PGR_BACKUP=""
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  cx_dirop_recover || rc=$?
  if [ "$rc" = 3 ]; then
    cx_dirop_ambiguous_screen
    return "$CX_EXIT_REFUSED"
  elif [ "$rc" != 0 ]; then
    cx_line FAIL "$(cx_msg dirop_intent_failed "$(cx_state_get dir_op.from)" "$(cx_state_get dir_op.to)")"
    return "$CX_EXIT_REFUSED"
  fi
  rec=$(cx_state_get last_upgrade.db_convert.recovery)
  ph=$(cx_state_get last_upgrade.db_convert.phase)
  new=$(cx_state_get last_upgrade.db_convert.new_path)
  old=$(cx_state_get last_upgrade.db_convert.old_path)
  CX_PGR_BACKUP=$(cx_state_get last_upgrade.backup)
  ts=$(date '+%Y%m%d-%H%M%S')
  st=$(cx_br_backend)
  [ "$st" != running ] || running=1
  # What every branch finishes: the temporary container and the export scratch space.
  docker rm -f "$CX_PGC_CONTAINER" >/dev/null 2>&1 || true
  [ -z "$CX_BK_DATA" ] || rm -rf -- "$CX_BK_DATA/.pg-convert"
  if [ "$rec" = restart_old ]; then
    cx_pgr_aside "$new" failed-convert "$new.failed-convert-$ts" || true
    CX_PGR_STATE=failed
    if [ "$running" = 0 ]; then
      cx_pgr_restart_old || started=$?
      [ "${started:-0}" != 1 ] || running=1
    fi
  else
    case $ph in init | restore | verify | analyze | done) cx_pgr_aside "$new" partial-convert "$new.partial-convert-$ts" || true ;; esac
    if [ "$running" = 1 ]; then
      CX_PGR_STATE=running
    elif cx_pgr_proof && cx_pgr_consistent; then
      CX_UP_RESUME=resume
      CX_PGR_STATE=proven
    else
      CX_PGR_STATE=unproven
      cx_log CHECK "interrupted conversion: the stop cannot be proven unbroken (${CX_PGR_WHY:-state differs})"
    fi
  fi
  cx_log CHECK "interrupted conversion: phase=${ph:-none} recovery=${rec:-none} judgment=$CX_PGR_STATE resume=$CX_UP_RESUME"
  cx_pgr_screen "$running" "$old"
}

# cx_pgr_backup_name: the file of the backup of the run that was cut short.
cx_pgr_backup_name() {
  local b=${CX_PGR_BACKUP:-}
  printf '%s' "${b##*/}"
}

# cx_pgr_screen <running 0|1> <old data folder>: P06, A or B.
cx_pgr_screen() {
  local running=$1 old=$2 state
  [ -n "$old" ] || old=$CX_BK_DATA/postgres
  cx_line WARN "$(cx_msg pgr_head)"
  if [ "$running" = 1 ]; then
    state=pgr_state_running
  else
    state=pgr_state_stopped
  fi
  cx_up_par "$(cx_msg "$state" "$CX_UP_CURRENT" "$old")"
  case $CX_PGR_STATE in
    proven)
      cx_up_par "$(cx_msg pgr_a_proof)"
      cx_up_bullet "$(cx_msg pgr_a_reuse "$(cx_pgr_backup_name)")"
      ;;
    failed)
      cx_up_par "$(cx_msg pgr_b_failed "$(cx_pgr_backup_name)")"
      cx_up_par "$(cx_msg pgr_b_again)"
      ;;
    *)
      cx_up_par "$(cx_msg pgr_b_unknown "$(cx_pgr_backup_name)")"
      cx_up_par "$(cx_msg pgr_b_again)"
      ;;
  esac
  [ -z "$CX_PGR_ASIDE" ] || cx_up_bullet "$(cx_msg pgr_aside "$CX_PGR_ASIDE")"
  printf '\n'
}

# cx_pgr_resume_load: a run that continues at step 8: the backup, its kind and the snapshot of the run
# that was cut short, as they are on record.
cx_pgr_resume_load() {
  local snap
  CX_UP_BACKUP=$(cx_state_get last_upgrade.backup)
  CX_UP_BACKUP_KIND=$(cx_state_get last_upgrade.backup_kind)
  CX_UP_BACKUP_DIR=""
  [ "$CX_UP_BACKUP_KIND" != external ] || CX_UP_BACKUP_DIR=$CX_ROOT/$CX_UP_BACKUP
  snap=$(cx_state_get last_upgrade.snapshot)
  CX_UP_SNAP=""
  [ -z "$snap" ] || CX_UP_SNAP=$CX_ROOT/$snap
  [ -n "$CX_UP_BACKUP" ]
}

# cx_pgr_forget: a run that starts from the beginning: nothing of the earlier run's stop or conversion
# is carried over. The backup pointers stay until step 7 of the new run replaces them (status shows
# the last finished upgrade's backup until then); the backup file itself stays on disk.
cx_pgr_forget() {
  local k
  for k in app_stop.at app_stop.ids db_convert.phase db_convert.result db_convert.recovery \
    db_convert.reuse db_convert.params db_convert.checksums db_convert.bytes db_convert.old_path \
    db_convert.new_path; do
    cx_state_unset "last_upgrade.$k"
  done
}
