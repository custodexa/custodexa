# shellcheck shell=bash
# CX_RS_EXT_* come from the checks before the preview (lib/restore_external.sh); CX_RS_DIR,
# CX_RS_ENV and the backup's map from the reader.
# shellcheck disable=SC2034,SC2153
# What a restore of an external database shows besides a bundled one's screens: the database
# section of the preview and its confirmation, the steps that differ, what became of the external
# database when the import failed, and what giving up leaves in it.

# cx_rs_ext_where: host:port of the external database, as the merged settings name it.
cx_rs_ext_where() {
  local env=${CX_RS_ENV:-}
  [ -n "$env" ] && [ -f "$env" ] || env=$CX_RS_DIR/env.merged
  [ -f "$env" ] || env=$CX_ROOT/.env
  printf '%s:%s' "$(cx_env_get "$env" EXTERNAL_DB_HOST)" "$(cx_rs_get db.external_port)"
}

# cx_rs_ext_export_file: where a new host's safety export of a database that is not empty goes.
cx_rs_ext_export_file() { printf '%s/safety-db.dump' "$CX_RS_DIR"; }

# cx_rs_ext_preview_db: the database section of the preview.
cx_rs_ext_preview_db() {
  local mode h c phrase="" objects user sep
  user=$(cx_rs_get db.user)
  cx_rs_row database "$(cx_msg rs_ext_preview_server "$(cx_rs_ext_where)" "$(cx_rs_get db.name)" "$CX_RS_EXT_SERVER")"
  cx_rs_row - "$(cx_msg rs_ext_preview_tool "$CX_RS_EXT_MAJOR" "$CX_RS_ENGINE")"
  mode=$CX_DB_SSLMODE
  [ "${CX_DB_SSLMODE_BY_SYSTEM:-0}" != 1 ] || mode=$(cx_msg pb_ext_mode_system)
  cx_rs_row - "$(cx_msg "rs_ext_conn_${CX_DB_TLS_VERIFY}_$CX_DB_TLS_TRUST" "$mode")"
  if [ "$CX_RS_FLOW" = same ] && [ "$CX_RS_EXT_CONNS" -gt 0 ]; then
    cx_rs_row - "$(cx_msg rs_ext_preview_rights_listed "$user" "$CX_RS_EXT_CONNS" "$CX_RS_EXT_FROM" "$CX_RS_EXT_APPS")"
  else
    cx_rs_row - "$(cx_msg rs_ext_preview_rights "$user")"
  fi
  if [ "$CX_RS_EXT_EMPTY" = 1 ]; then
    cx_rs_row - "$(cx_msg rs_ext_preview_empty)"
    return 0
  fi
  sep=$(cx_msg bk_item_sep)
  while IFS='|' read -r h c; do
    [ -n "$h" ] || continue
    # The phrase names the count and the schema in each language's own order.
    if [ "$CX_LANG" = en ]; then objects=$(cx_msg rs_ext_objects "$c" "$(cx_dbx_show_name "$h")")
    else objects=$(cx_msg rs_ext_objects "$(cx_dbx_show_name "$h")" "$c"); fi
    phrase+="${phrase:+$sep}$objects"
  done <<<"$CX_RS_EXT_OBJECTS"
  cx_rs_row - "$(cx_msg rs_ext_preview_emptied "$phrase")"
}

# cx_rs_ext_preview_safety: a new host's safety row: the export of a database that is not empty.
cx_rs_ext_preview_safety() {
  if [ "$CX_RS_EXT_EMPTY" = 1 ]; then cx_rs_row safety "$(cx_msg rs_safety_none)"
  else cx_rs_row safety "$(cx_msg rs_ext_preview_export "$(cx_rs_ext_export_file)")"; fi
}

# cx_rs_ext_preview_space: until the transaction ends, the server holds the old and the new data;
# the script cannot see that disk.
cx_rs_ext_preview_space() {
  local bytes
  [ "$CX_RS_EXT_EMPTY" = 0 ] || return 0
  bytes=$(cx_rs_get size.db_bytes)
  [[ $bytes =~ ^[0-9]+$ ]] || bytes=0
  cx_rs_par "$(cx_line WARN "$(cx_msg rs_ext_preview_space "$(cx_gb_up $((bytes * 2)))")")"
}

# cx_rs_ext_kept: the same host's kept row: the external database has no folder here.
cx_rs_ext_kept() {
  local kept
  if [ "$(cx_rs_get contents.tls)" = true ]; then kept=$(cx_msg rs_kept_external)
  else kept=$(cx_msg rs_kept_external_no_tls); fi
  kept+=$'\n'"$CX_RS_DATA/audit.before-restore-$CX_RS_TS"
  [ "$(cx_rs_get contents.tls)" != true ] || kept+=$'\n'"$CX_ROOT/tls.before-restore-$CX_RS_TS"
  cx_rs_row kept "$kept"
}

# cx_rs_ext_confirm: a database that is not empty is confirmed by typing its name; without a
# terminal --yes and --confirm-data-loss. Returns 1 to cancel, 2 when the confirmation is not
# this one's (the bundled confirmation applies).
cx_rs_ext_confirm() {
  local answer db
  cx_rs_ext && [ "$CX_RS_EXT_EMPTY" = 0 ] || return 2
  if [ "${CX_YES:-0}" = 1 ] || [ ! -t 0 ]; then
    if [ "${CX_YES:-0}" != 1 ] && [ "$CX_RS_FLOW" = new ]; then cx_rs_refuse rs_confirm_new_flags; return 1; fi
    [ "${CX_RS_CONFIRM_LOSS:-0}" = 1 ] && return 0
    cx_rs_refuse rs_confirm_flags
    return 1
  fi
  db=$(cx_rs_get db.name)
  printf '%s\n> ' "$(cx_msg rs_confirm_db "$db")"
  IFS= read -r answer || answer=""
  [ "$answer" = "$db" ] && return 0
  printf '%s\n' "$(cx_msg rs_confirm_cancel "$db")"
  return 1
}

# cx_rs_ext_step_key <progress id>: the same host's step label when the database is external.
cx_rs_ext_step_key() {
  cx_rs_ext && [ "$CX_RS_FLOW" = same ] || return 1
  case $1 in
    stop) printf rs_ext_step_stop ;;
    swap) printf rs_ext_step_quiet ;;
    import) printf rs_ext_step_import ;;
    *) return 1 ;;
  esac
}

# cx_rs_ext_import_failed <outcome>: the import step's failure line and psql's reason; what became
# of the external database is said by the failure screen (cx_rs_ext_failure_state).
cx_rs_ext_import_failed() {
  local line detail=""
  if [ "${CX_RS_PROGRESS_ID:-}" = import ]; then cx_rs_progress_end import FAIL
  else cx_line FAIL " ${CX_RUN_STEP:-0}/$(cx_rs_steps_total)  $(cx_msg rs_ext_step_import)"; fi
  [ "$1" = rolled-back ] || return 0
  # psql's own error, after the transaction was sent.
  if [ -f "${CX_LOG_FILE:-}" ]; then
    while IFS= read -r line; do
      [ -n "$detail" ] || [[ $line != *ERROR:* ]] || detail=$(cx_mask "ERROR:${line#*ERROR:}")
    done < <(sed -n '/external import: db_covering=1/,$p' "$CX_LOG_FILE")
  fi
  if [ -n "$detail" ]; then printf '       %s\n       %s\n' "$(cx_msg rs_ext_import_error_detail)" "$detail"
  else printf '       %s\n' "$(cx_msg rs_ext_import_error)"; fi
}

# cx_rs_ext_outcome: what the last import transaction did, from its record: rolled-back, unknown
# (sent, result not known), or nothing when no transaction of this restore is open.
cx_rs_ext_outcome() {
  local h before state
  cx_rs_ext && [ "$(cx_state_get last_restore.db_covering)" = 1 ] || return 0
  [ "$(cx_state_get last_restore.phase)" = swapped ] || return 0
  [ -f "$CX_RS_DIR/external-import" ] || return 0
  read -r h before state _ <"$CX_RS_DIR/external-import" || return 0
  case $state in rolled-back) printf rolled-back ;; begun) printf unknown ;; esac
}

# cx_rs_ext_committed_here: the import of this restore was committed.
cx_rs_ext_committed_here() {
  [ "$(cx_state_get last_restore.db_covering)" = 1 ] || return 1
  case $(cx_state_get last_restore.phase) in checked|prepared|safety|stopped|swapped) return 1 ;; esac
}

# cx_rs_ext_db_dump: a new host whose non-empty external database was exported first.
cx_rs_ext_db_dump() { [ "$CX_RS_FLOW" = new ] && [ "$(cx_state_get last_restore.safety)" = db-dump ]; }

# cx_rs_ext_failure_state: the failure screen's sentence on the external database. Fails when
# the screen says nothing of its own (the bundled sentences apply).
cx_rs_ext_failure_state() {
  local outcome file
  cx_rs_ext || return 1
  outcome=$(cx_rs_ext_outcome)
  if cx_rs_ext_db_dump; then
    file=$(cx_state_get last_restore.safety_file)
    # The rollback is claimed only when the record says so; no transaction sent says unchanged.
    if [ "$outcome" = unknown ]; then cx_rs_par "$(cx_msg rs_ext_failure_unknown_export "${file#"$CX_ROOT"/}")"
    elif cx_rs_ext_committed_here; then cx_rs_par "$(cx_msg rs_ext_failure_committed_export "${file#"$CX_ROOT"/}")"
    elif [ "$outcome" = rolled-back ]; then cx_rs_par "$(cx_msg rs_ext_failure_rolled_back_export "${file#"$CX_ROOT"/}")"
    else cx_rs_par "$(cx_msg rs_ext_failure_unsent_export "${file#"$CX_ROOT"/}")"; fi
    return 0
  fi
  [ "$CX_RS_FLOW" != new ] || cx_rs_par "$(cx_msg rs_failure_no_safety)"
  case $outcome in
    rolled-back) cx_rs_par "$(cx_msg rs_ext_failure_rolled_back)" ;;
    unknown) cx_rs_par "$(cx_msg rs_ext_import_unknown)" ;;
    *) [ "$CX_RS_FLOW" = new ] || return 1 ;;
  esac
}

# cx_rs_ext_way_back <action>: the description of the second command when the external database
# changes it: the safety export put back, or giving up that leaves the imported data in place.
cx_rs_ext_way_back() {
  cx_rs_ext && [ "$CX_RS_FLOW" = new ] || return 1
  if [ "$1" = revert ] && cx_rs_ext_db_dump; then cx_rs_par "$(cx_msg rs_ext_failure_revert)"
  elif [ "$1" = abandon ] && cx_rs_ext_committed_here; then cx_rs_par "$(cx_msg rs_ext_failure_abandon)"
  else return 1; fi
}

# cx_rs_ext_abandon_refused: once a non-empty database is being emptied and imported, only the
# safety export takes it back. Fails when giving up is allowed.
cx_rs_ext_abandon_refused() {
  cx_rs_ext_db_dump && [ "$(cx_state_get last_restore.db_covering)" = 1 ] || return 1
  cx_log FAIL "abandon refused: the external database is being emptied and imported"
  cx_line FAIL "$(cx_msg rs_ext_abandon_refused)"
  cx_cmd "$(cx_rs_control_command revert)"
  cx_rs_unchanged
}

# cx_rs_ext_abandon_screen: what giving up leaves in the external database, and the safety export.
cx_rs_ext_abandon_screen() {
  local file
  cx_rs_ext || return 0
  if cx_rs_ext_db_dump; then
    file=$(cx_state_get last_restore.safety_file)
    [ ! -f "$file" ] || cx_rs_par "$(cx_msg rs_ext_abandon_export "$file")"
  elif cx_rs_ext_committed_here; then
    cx_rs_par "$(cx_msg rs_ext_abandon_kept "$(cx_rs_ext_where)" "$(cx_rs_get db.name)")"
  elif [ "$(cx_rs_ext_outcome)" = unknown ]; then
    cx_rs_par "$(cx_msg rs_ext_abandon_maybe "$(cx_rs_ext_where)" "$(cx_rs_get db.name)")"
  fi
}

# cx_rs_ext_finish_skipped: the grants left out, and where their list is.
cx_rs_ext_finish_skipped() {
  local n
  [ -s "$CX_RS_DIR/skipped-grants.txt" ] || return 0
  n=$(grep -c '[^[:space:]]' "$CX_RS_DIR/skipped-grants.txt") || true
  cx_rs_par "$(cx_msg rs_ext_finish_skipped "$n" "$CX_RS_DIR/skipped-grants.txt")"
}

# cx_rs_ext_finish_export: a new host's safety export stays after the restore; where it is.
cx_rs_ext_finish_export() {
  local file
  cx_rs_ext_db_dump || return 0
  file=$(cx_state_get last_restore.safety_file)
  [ ! -f "$file" ] || cx_rs_par "$(cx_msg rs_ext_finish_export "$file")"
}
