# shellcheck shell=bash
# CX_RS_EXT_* and CX_DB_* are shared with lib/restore_external.sh and the database client.
# shellcheck disable=SC2034,SC2153
# A new host has no deployment to back up, but an external database that already holds data has
# the only copy of it. Before it is emptied it is exported, with the client of the server's major,
# to restore/<ts>/safety-db.dump, and the file is read back completely with the same client: its
# table of contents lists, and the whole content is written out and hashed with exit 0 (a listing
# alone does not read the data). The target digest is measured before and after the export; a
# difference means somebody wrote meanwhile and the export is not used. Recorded:
# last_restore.safety=db-dump, the file, its SHA-256 and that digest.
#
# --revert puts the file back with the commit protocol of the import (one transaction), and is done
# only once the target digest equals the one recorded at the export; then the restore is given up
# as --abandon does it. Until then the file is never deleted, and --revert can be run again.

# cx_rs_ext_objects: the number of objects in the non-system schemas (0: the database is empty).
cx_rs_ext_objects() {
  cx_dbx_rows "SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE $CX_DBX_SYS_SCHEMAS)
  + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE $CX_DBX_SYS_SCHEMAS)
  + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE $CX_DBX_SYS_SCHEMAS
      AND t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)) AS obj_total"
}

# cx_rs_ext_export <file>: pg_dump -Fc of the database into the file, then the file read back in
# full: pg_restore --list, and pg_restore -f - into a hash, every exit code collected.
cx_rs_ext_export() {
  local file=$1 rc=0
  local -a st=()
  rm -f -- "$file" && (umask 077 && : >"$file") || return 1
  CX_DB_ACTION=dump cx_db_ext_run 1 pg_dump -Fc -d "$(cx_db_conninfo)" >"$file" 2>>"$CX_LOG_FILE" ||
    { cx_log FAIL "safety export: pg_dump failed"; return 1; }
  [ -s "$file" ] || return 1
  CX_DB_ACTION=restore-list cx_db_ext_run 0 pg_restore --list <"$file" >/dev/null 2>>"$CX_LOG_FILE" ||
    { cx_log FAIL "safety export: the export's table of contents cannot be read"; return 1; }
  CX_DB_ACTION=restore-file cx_db_ext_run 0 pg_restore -f - <"$file" 2>>"$CX_LOG_FILE" | sha256sum >/dev/null
  st=("${PIPESTATUS[@]}")
  for rc in "${st[@]}"; do
    [ "$rc" = 0 ] || { cx_log FAIL "safety export: reading the export in full ended with ${st[*]}"; return 1; }
  done
}

# cx_rs_ext_safety_take: the export of a non-empty database, between two equal digests;
# CX_RS_EXT_SAFETY is "none" or "db-dump <sha256> <digest>". Run inside cx_rs_ext_with.
CX_RS_EXT_SAFETY=""
cx_rs_ext_safety_take() {
  local file=$CX_RS_DIR/safety-db.dump n before after sum
  CX_RS_EXT_SAFETY=""
  cx_rs_ext_ready || return 1
  n=$(cx_rs_ext_objects) || return 1
  if [ "$n" = 0 ]; then
    cx_log CHECK "safety export: the external database is empty; nothing to export"
    CX_RS_EXT_SAFETY=none
    return 0
  fi
  before=$(cx_rs_ext_digest) || return 1
  cx_rs_ext_export "$file" || return 1
  after=$(cx_rs_ext_digest) || return 1
  if [ "$before" != "$after" ]; then
    cx_log FAIL "safety export: the database changed during the export (digest $before, then $after)"
    return 1
  fi
  sum=$(cx_pb_sha "$file") || return 1
  cx_log CHECK "safety export: $file objects=$n sha256=$sum digest=$before"
  CX_RS_EXT_SAFETY="db-dump $sum $before"
}

# cx_rs_ext_begin: after the confirmation, the connection's files in place; a new host whose
# external database held anything at the checks marks its export as a step of its own.
cx_rs_ext_begin() {
  cx_rs_ext_place || return 1
  [ "$CX_RS_FLOW" = new ] && [ "$CX_RS_EXT_EMPTY" = 0 ] || return 0
  (umask 077 && : >"$CX_RS_DIR/external-export")
}

# cx_rs_ext_export_step: the export is step 3, once the settings are written; the steps after it
# move on by one (cx_rs_ext_shift prints 1, else 0).
cx_rs_ext_export_step() { [ "$CX_RS_FLOW" = new ] && [ -f "$CX_RS_DIR/external-export" ]; }
cx_rs_ext_shift() { if cx_rs_ext_export_step; then printf 1; else printf 0; fi; }

# cx_rs_ext_safety: on a new host, at phase swapped (step 3) before the import: no other
# connection, then the export when the database holds anything; the result recorded. Nothing in
# the external database has been changed yet; the export is taken again only while none is recorded.
cx_rs_ext_safety() {
  local kind sum digest
  cx_rs_ext_quiet "$CX_RUN_STEP" "$(cx_rs_steps_total)" rs_ext_step_export || return 1
  if ! cx_rs_ext_with cx_rs_ext_safety_take; then
    cx_rs_ext_failed rs_ext_export_failed "$CX_LOG_FILE"
    return 1
  fi
  read -r kind sum digest <<<"$CX_RS_EXT_SAFETY"
  if [ "$kind" = db-dump ]; then
    cx_state_set last_restore.safety_file "$CX_RS_DIR/safety-db.dump" &&
      cx_state_set last_restore.safety_sha256 "$sum" &&
      cx_state_set last_restore.safety_digest "$digest" || return 1
  fi
  cx_state_set last_restore.safety "$kind" && cx_rs_save
}

# cx_rs_ext_put_back: the export into the external database with the commit protocol (its grants
# as they were: nothing skipped); done when the target digest equals the export's.
cx_rs_ext_put_back() {
  local CX_RS_EXT_SQL=$CX_RS_DIR/sql CX_RS_EXT_DUMP CX_RS_EXT_MISSING_FILE="" want now rc=0
  CX_RS_EXT_DUMP=$(cx_state_get last_restore.safety_file) want=$(cx_state_get last_restore.safety_digest)
  if [ ! -f "$CX_RS_EXT_DUMP" ] || [ "$(cx_pb_sha "$CX_RS_EXT_DUMP")" != "$(cx_state_get last_restore.safety_sha256)" ]; then
    cx_log FAIL "revert: $CX_RS_EXT_DUMP is missing or changed"; return 1
  fi
  cx_rs_ext_with cx_rs_ext_ready || return 1
  now=$(cx_rs_ext_with cx_rs_ext_digest) || return 1
  cx_log CHECK "revert: digest at the export=$want now=$now"
  [ "$now" != "$want" ] || return 0
  cx_rs_ext_with cx_rs_ext_make || return 1
  cx_rs_ext_quiet "${CX_RUN_STEP:-0}" "$(cx_rs_steps_total)" rs_ext_step_import || return 1
  cx_rs_ext_with cx_rs_ext_commit || rc=$?
  now=$(cx_rs_ext_with cx_rs_ext_digest) || return 1
  cx_log CHECK "revert: psql ended with $rc; digest now=$now"
  [ "$now" = "$want" ] || return 1
  rm -rf -- "$CX_RS_EXT_SQL"
}

# cx_rs_ext_revert: --revert of a new host whose external database was exported first.
cx_rs_ext_revert() {
  local file CX_RS_ENV
  file=$(cx_state_get last_restore.safety_file)
  cx_rs_exit_context || return 1
  CX_RS_ENV=$CX_COMPOSE_ENV
  if [ "$(cx_state_get last_restore.exit)" != reverting ] && [ "${CX_YES:-0}" != 1 ]; then
    [ -t 0 ] || { cx_line FAIL "$(cx_msg rs_exit_yes)"; return 3; }
    local answer
    printf '%s' "$(cx_msg rs_ext_revert_confirm "$file")"
    answer=""
    IFS= read -r answer || true
    if [[ $answer != y && $answer != Y ]]; then cx_line WARN "$(cx_msg rs_exit_cancelled)"; return 3; fi
  fi
  cx_rs_exit_begin reverting || return 1
  if ! cx_rs_stop_all; then
    cx_line FAIL "$(cx_msg rs_abandon_stop_failed)"
    cx_rs_control_hints
    return 1
  fi
  # Only the transaction can have touched the database; without it the export is still what is there.
  if [ "$(cx_state_get last_restore.db_covering)" = 1 ] && ! cx_rs_ext_put_back; then
    [ -n "${CX_RS_EXT_HELD:-}" ] && return 1
    cx_line FAIL "$(cx_msg rs_ext_revert_failed "$file")"
    cx_cmd "$(cx_rs_control_command revert)"
    return 1
  fi
  cx_rs_abandon_rest || return 1
  rm -f -- "$file"
  cx_rs_plaintext_clear "$CX_RS_DIR" && cx_rs_settle reverted || return 1
  cx_line OK "$(cx_msg rs_ext_revert_done)"
}
