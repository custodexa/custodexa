#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
setup() {
  rs_import_host
  printf 'count.users=5\ncount.sessions=42\ncount.audit_logs=1234\n' >"$RS_I_STAGE/pass2/snapshot.txt"
  sed 's/^/migration=/' "$DB/migrations" >>"$RS_I_STAGE/pass2/snapshot.txt"
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.1 CX_RS_ENGINE=1.16.1
  CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched CX_RS_DATA=$CX_ROOT/data
  CX_RS_MAP=([db.migrations_count]=2 [kek.fingerprint]=5a5a5a5a5a5a5a5a)
  CX_RS_MAP[db.migrations_sha256]=$(cx_snap_migrations "$CX_RS_DIR/pass2/snapshot.txt" | LC_ALL=C sort | sha256sum | cut -c1-64)
  cx_rs_record && cx_rs_phase imported && cx_rs_step 7 || return 1
  cx_state_set last_restore.covering 1
  cx_state_set last_restore.safety script
  cx_state_set last_restore.safety_file backups/safety.tar
  cx_rs_db_check
}
HARNESS
  printf 'running\n' >"$DB/ctr/postgres"
}
check_refused() {
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = imported ] || return 1
  [ "$(cat "$DB/ctr/backend")" = stopped ] || return 1
  ! grep -Eq '^(start|up)( |$)' "$DB/events" || return 1
  [[ $output == *'7/10  Check the database:'* && $output == *'restore --resume'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
}
@test "restore database check: a changed migration set refuses before the backend starts" {
  printf '20261103_session_tags\n' >>"$DB/migrations"
  rs_import_run
  check_refused || return 1
  [[ $output == *'migrations after the import differ'* && $output == *'1 extra: 20261103_session_tags'* ]]
}
# - **WHEN** 匯入後資料庫的 `audit_logs` 筆數與快照不同
# - **THEN** 腳本在啟動後端前停下，畫面印出接續與回去兩條指令
@test "restore acceptance: 匯入後與備份不同" {
  printf '1235\n' >"$DB/count.audit_logs"
  rs_import_run
  check_refused || return 1
  [[ $output == *'audit_logs row count differs (imported 1235, backup 1234)'* ]]
}
@test "restore database check: a different active key refuses before the backend starts" {
  printf '0c0c0c0c0c0c0c0c\n' >"$DB/kek"
  rs_import_run
  check_refused || return 1
  [[ $output == *'active master key IDs differ'* ]]
}
@test "restore database check: matching migrations counts and active key advance the checkpoint" {
  rs_import_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = db_checked ]
}
