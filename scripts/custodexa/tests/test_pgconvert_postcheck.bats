#!/usr/bin/env bats
# lib/pgconvert_post.sh (task 3.7): step 12's check of the database major, the database part of the
# closing screen, and the way back printed when a step after the switch fails (the three screens
# of a converted upgrade). The unit tests run the functions on backup_host's deployment.

load helper
load install_host
load backup_host
load upgrade_host
load pgconvert_host

setup() {
  backup_host ui
  load_lib
  for f in upgrade_query upgrade_preflight upgrade_output drain_gate stop_check health upgrade_steps rollback_check rollback_output; do
    # shellcheck source=/dev/null
    . "$SRC/lib/$f.sh"
  done
  CX_ROOT=$ROOT
  CX_LANG=en
  CX_LOG_FILE=$BATS_TEST_TMPDIR/log
  : >"$CX_LOG_FILE"
  cx_state_load "$ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  CX_UP_TARGET=1.23.0 CX_UP_CURRENT=1.13.0
  CX_UP_BACKUP=backups/custodexa-backup-1.13.0-20261120-021502.tar CX_UP_BACKUP_KIND=script CX_UP_BACKUP_DIR=$ROOT/backups
  mkdir -p "$ROOT/releases/1.23.0" "$ROOT/backups"
  : >"$ROOT/$CX_UP_BACKUP"
  jq '.version = "1.23.0" | .images.postgres.tag = "18.6-alpine3.24"
    | .bundled_db = {major: 18, data_dir: "postgresql", pgdata: "18/docker"}' \
    "$ROOT/releases/1.13.0/MANIFEST.json" >"$ROOT/releases/1.23.0/MANIFEST.json"
  CX_DIR=$ROOT/releases/1.23.0
  CX_UP_PRE_EXTERNAL_DB=0
  CX_PC_ROWS=() CX_PC_FAIL=0
  cx_manifest_load "$CX_DIR/MANIFEST.json"
}

# converted: the run converted the database from 16 to 18 (the in-process plan and the record).
converted() {
  declare -gA CX_IMG_REF=([postgres]=docker.io/library/postgres@sha256:aaaa)
  cx_pgc_plan
  cx_state_set last_upgrade.db_convert.result "done"
  cx_state_set last_upgrade.from 1.13.0
}

@test "[pg18] 升級後資料庫大版本不符" {
  converted
  pgc_version 16 postgresql 18/docker
  mkdir -p "$ROOT/data/postgresql/18/docker"
  printf '16\n' >"$ROOT/data/postgresql/18/docker/PG_VERSION"
  printf '180006\n' >"$DB/server_version_num"
  cx_pc_dbmajor
  [ "$CX_PC_FAIL" = 1 ] || return 1
  [[ ${CX_PC_ROWS[1]} == *"expected PostgreSQL 18"* && ${CX_PC_ROWS[1]} == *"holds 16"* ]] || { echo "${CX_PC_ROWS[1]}"; return 1; }
  # the running server of another major is a failure too
  CX_PC_ROWS=() CX_PC_FAIL=0
  printf '18\n' >"$ROOT/data/postgresql/18/docker/PG_VERSION"
  printf '160015\n' >"$DB/server_version_num"
  cx_pc_dbmajor
  [ "$CX_PC_FAIL" = 1 ] || return 1
  # everything agrees: one OK row says so
  CX_PC_ROWS=() CX_PC_FAIL=0
  printf '180006\n' >"$DB/server_version_num"
  cx_pc_dbmajor
  [ "$CX_PC_FAIL" = 0 ] && [ "${CX_PC_ROWS[0]}" = OK ] || return 1
  [[ ${CX_PC_ROWS[1]} == *"PostgreSQL 18, the data is in $ROOT/data/postgresql"* ]] || { echo "${CX_PC_ROWS[1]}"; return 1; }
}

@test "[pg18] 步驟 12 沒有轉換時只在不符才出現資料庫列" {
  # an upgrade that keeps the major shows no row when everything agrees
  pgc_manifest "$ROOT/releases/1.23.0" without 16
  cx_manifest_load "$ROOT/releases/1.23.0/MANIFEST.json"
  CX_PGC_ACTIVE=0
  printf '160015\n' >"$DB/server_version_num"
  cx_pc_dbmajor
  [ "${#CX_PC_ROWS[@]}" -eq 0 ] || return 1
  printf '180006\n' >"$DB/server_version_num"
  cx_pc_dbmajor
  [ "$CX_PC_FAIL" = 1 ] || return 1
  # a value the server does not give is not compared
  CX_PC_ROWS=() CX_PC_FAIL=0
  echo 1 >"$DB/server_version_num.rc"
  cx_pc_dbmajor
  [ "$CX_PC_FAIL" = 0 ] || return 1
}

@test "[pg18] 資料庫轉換後新版啟動但未就緒" {
  converted
  # A: the new version started, the old data is there
  cx_state_set last_upgrade.new_started_at 2026-11-20T02:40:00+0800
  run cx_up_fail_switched up_fail_ready 180
  [[ $output == *"did not report ready"* || $output == *"ready"* ]] || return 1
  [[ $output == *"The database was converted to PostgreSQL 18; the old PostgreSQL 16"* ]] || { echo "$output"; return 1; }
  [[ $output == *"$ROOT/data/postgres"* ]] || return 1
  [[ $output == *"two ways, both to the data of the upgrade"* ]] || return 1
  [[ $output == *"1. Go back to the previous version with the kept PostgreSQL 16 data"* ]] || return 1
  [[ $output == *"custodexa.sh rollback"* ]] || return 1
  [[ $output == *"Data written after the new version started is not in the database"* ]] || return 1
  [[ $output == *"2. Restore the backup taken before the upgrade:"* ]] || return 1
  [[ $output == *"custodexa.sh restore $ROOT/$CX_UP_BACKUP"* ]] || return 1
  # a failure of step 9, the new version never started: the sentence is not there
  cx_state_unset last_upgrade.new_started_at
  run cx_up_fail_switched up_fail_switch
  [[ $output == *"1. Go back to the previous version"* && $output == *"2. Restore the backup"* ]] || return 1
  [[ $output != *"Data written after the new version started"* ]] || return 1
  # B: the old data folder is gone: restore is all there is
  rm -rf "$ROOT/data/postgres"
  run cx_up_fail_switched up_fail_ready 180
  [[ $output == *"restore the backup taken before the upgrade"* && $output == *"is no longer there"* ]] || { echo "$output"; return 1; }
  [[ $output == *"custodexa.sh restore $ROOT/$CX_UP_BACKUP"* ]] || return 1
  [[ $output != *"custodexa.sh rollback"* && $output != *"1. Go back"* ]] || return 1
}

@test "[pg18] 外接資料庫部署升級後核對失敗" {
  CX_OVERLAYS="external-database"
  CX_UP_PRE_EXTERNAL_DB=1
  cx_pgc_plan
  [ "$CX_PGC_ACTIVE" = 0 ] || return 1
  # no database row, even with a data folder of another major on this host
  cx_pc_dbmajor
  [ "${#CX_PC_ROWS[@]}" -eq 0 ] || return 1
  rm -rf "$ROOT/data/postgres"
  run cx_up_fail_switched up_fail_checks
  [[ $output != *"was converted"* && $output != *"Data written after"* && $output != *"is no longer there"* ]] || return 1
  [[ $output != *"two ways"* ]] || return 1
  # the rule of a same-major upgrade is the one that prints (rollback, or the restore guide)
  [[ $output == *"rollback"* || $output == *"restore"* ]] || return 1
}

@test "[pg18] 完成畫面的資料庫段" {
  converted
  mkdir -p "$ROOT/data/postgres"
  head -c 2048 /dev/zero >"$ROOT/data/postgres/blob"
  run cx_pgc_done_section
  [[ $output == *"Database"* ]] || return 1
  [[ $output == *"old PostgreSQL 16 data is still kept in $ROOT/data/postgres"* ]] || { echo "$output"; return 1; }
  [[ $output == *'"Database upgrade"'* ]] || return 1
  flat=$(printf '%s' "$output" | tr '\n' ' ' | tr -s ' ')
  [[ $flat == *"going back to 1.13.0"* && $flat == *"does not bring back the data written afterwards"* ]] || return 1
  [[ $output == *"Once the old data is removed, rollback is no longer possible"* ]] || return 1
  # an upgrade that did not convert has no such section
  CX_PGC_ACTIVE=0
  [ -z "$(cx_pgc_done_section)" ] || return 1
}

@test "[pg18] 跨大版本只有一個定義" {
  converted
  cx_pgc_crossed || return 1
  # external, or a SKIP: not crossed
  cx_state_set last_upgrade.db_convert.result skipped
  ! cx_pgc_crossed || return 1
  cx_state_set last_upgrade.db_convert.result "done"
  CX_PGC_ACTIVE=0
  # from another command: the MANIFESTs state.json names
  cx_state_set previous.release_dir releases/1.13.0
  cx_state_set current.release_dir releases/1.23.0
  cx_pgc_crossed || return 1
  cx_state_set current.release_dir releases/1.13.0
  ! cx_pgc_crossed || return 1
  cx_state_set current.release_dir releases/1.23.0
  cx_state_set current.overlays external-database
  ! cx_pgc_crossed || return 1
}
