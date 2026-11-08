#!/usr/bin/env bats
# Restore of a bundled database across PostgreSQL majors: the list of the backup is checked against
# the major its release bundles, the data folder follows that release, both folders of a deployment
# on another major are renamed and kept, and the cluster is created under the start check.
# The first group drives the real restore through the journal harness (a host whose data is on 18,
# restoring the backup of an older release on 16); the second group calls the checks directly.

load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host
load restore_journal_host
load pgconvert_host

setup_file() {
  export RS_FIX=$BATS_FILE_TMPDIR/safety
  rs_make "$RS_FIX" ui : || return 1
  rs_host_once journal rs_journal_host
}

# A host on 18 (the deployment being replaced) restoring the release that bundles 16.
pgr_host_18_to_16() {
  rs_host_restore journal
  pgc_manifest "$ROOT/releases/1.16.0" with 18
  pgc_manifest "$ROOT/releases/1.16.1" without 16
  mkdir -p "$ROOT/data/postgresql/18/docker"
  printf '18\n' >"$ROOT/data/postgresql/18/docker/PG_VERSION"
  printf '16\n' >"$ROOT/data/postgres/PG_VERSION"
}

@test "[pg18] 在 1.23 主機還原 1.22 的備份" {
  pgr_host_18_to_16
  cp -a "$ROOT/data/postgresql" "$BATS_TEST_TMPDIR/before-18"
  cp -a "$ROOT/data/postgres" "$BATS_TEST_TMPDIR/before-16"
  run bash "$RS_J_ENGINE" restore "$RS_J_HOST/restore-input.tar" --same-host --yes --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  # Both folders are renamed and kept as they were, nothing of them is deleted.
  diff -r "$BATS_TEST_TMPDIR/before-18" "$ROOT/data/postgresql.before-restore-journal-test" || return 1
  diff -r "$BATS_TEST_TMPDIR/before-16" "$ROOT/data/postgres.before-restore-journal-test" || return 1
  # The release restored keeps its own folder, newly made and empty; the 18 folder is gone.
  [ -d "$ROOT/data/postgres" ] && [ -z "$(ls -A "$ROOT/data/postgres")" ] || return 1
  [ ! -e "$ROOT/data/postgresql" ] || return 1
  [ "$(stat -c %a "$ROOT/data/postgres")" = 700 ] || return 1
}

@test "[pg18] 還原的預覽寫明備份的資料庫版本與保留的目錄" {
  pgr_host_18_to_16
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/cmd_restore.sh"
  CX_LANG=en CX_ROOT=$ROOT CX_RS_DATA=$ROOT/data CX_RS_TS=20261125-093015 CX_RS_FLOW=same
  CX_RS_VERSION=1.16.1 CX_RS_DIR=$BATS_TEST_TMPDIR/stage CX_RS_PAD='                 '
  CX_RS_MAP=([db.location]=bundled [db.server_major]=16)
  cx_state_load "$ROOT/state.json"
  run cx_rs_preview_db
  [ "$status" = 0 ] || return 1
  [[ $output == *'PostgreSQL 16 (a backup of 1.16.1)'* && $output == *'current PostgreSQL 18'* ]] || { echo "$output"; return 1; }
  [[ $output == *"$ROOT/data/postgresql.before-restore-20261125-093015"* ]] || { echo "$output"; return 1; }
  [[ $output == *"$ROOT/data/postgres.before-restore-20261125-093015"* ]] || { echo "$output"; return 1; }
  [[ $output == *'run upgrade as usual'* ]] || { echo "$output"; return 1; }
}

@test "[pg18] 清單的資料庫大版本與版本不符" {
  rs_host_restore journal
  pgc_manifest "$ROOT/releases/1.16.1" with 18
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/cmd_restore.sh"
  CX_LANG=en CX_ROOT=$ROOT CX_RS_VERSION=1.16.1 CX_RS_DIR=$BATS_TEST_TMPDIR/stage
  # The list says 16, the release bundles 18: refused with nothing started or moved.
  CX_RS_MAP=([db.location]=bundled [db.server_major]=16)
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  run cx_rs_db_major_check
  [ "$status" = 1 ] || return 1
  [[ $output == *'names PostgreSQL 16'* && $output == *'bundles PostgreSQL 18'* ]] || { echo "$output"; return 1; }
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/after"
  cmp "$BATS_TEST_TMPDIR/before" "$BATS_TEST_TMPDIR/after" || return 1
  # Agreeing lists pass, and the external form is left to its own server checks.
  CX_RS_MAP=([db.location]=bundled [db.server_major]=18)
  cx_rs_db_major_check || return 1
  CX_RS_MAP=([db.location]=external [db.server_major]=16)
  cx_rs_db_major_check
}

@test "[pg18] 還原建立叢集只在該階段且目標為空時放行" {
  rs_host_restore journal
  pgc_manifest "$ROOT/releases/1.16.1" with 18
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/cmd_restore.sh"
  CX_LANG=en CX_ROOT=$ROOT CX_RS_VERSION=1.16.1 CX_RS_DATA=$ROOT/data CX_RS_DIR=$BATS_TEST_TMPDIR/stage
  CX_RS_MAP=([db.location]=bundled)
  mkdir -p "$CX_RS_DATA/postgresql"
  cx_state_load "$ROOT/state.json"
  # At the stage that creates the cluster, with an empty folder: let through.
  cx_state_set last_restore.phase swapped
  cx_rs_dirop_init_guard || return 1
  # The same folder at another stage of the record: refused.
  cx_state_set last_restore.phase placed
  run cx_rs_dirop_init_guard
  [ "$status" = 1 ] && [[ $output == *'"placed"'* ]] || { echo "$output"; return 1; }
  # At the stage but the folder holds something: refused.
  cx_state_set last_restore.phase swapped
  mkdir -p "$CX_RS_DATA/postgresql/18/docker"
  printf '18\n' >"$CX_RS_DATA/postgresql/18/docker/PG_VERSION"
  run cx_rs_dirop_init_guard
  [ "$status" = 1 ] || return 1
  # At the stage, empty folder, but a rename that is not settled: refused.
  rm -rf "$CX_RS_DATA/postgresql"
  mkdir -p "$CX_RS_DATA/postgresql"
  cx_state_set dir_op.id before-restore
  cx_state_set dir_op.from "$CX_RS_DATA/a"
  cx_state_set dir_op.to "$CX_RS_DATA/b"
  cx_state_set dir_op.phase intent
  run cx_rs_dirop_init_guard
  [ "$status" = 1 ] || return 1
}

@test "[pg18] 匯入後的啟動步沒有版本檔就拒絕" {
  rs_host_restore journal
  pgc_manifest "$ROOT/releases/1.16.1" with 18
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/cmd_restore.sh"
  CX_LANG=en CX_ROOT=$ROOT CX_RS_VERSION=1.16.1 CX_RS_DATA=$ROOT/data CX_RS_DIR=$BATS_TEST_TMPDIR/stage
  CX_RS_MAP=([db.location]=bundled)
  rm -rf "$CX_RS_DATA/postgresql"
  mkdir -p "$CX_RS_DATA/postgresql"
  cx_state_load "$ROOT/state.json"
  run cx_rs_dirop_start_guard
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  mkdir -p "$CX_RS_DATA/postgresql/18/docker"
  printf '16\n' >"$CX_RS_DATA/postgresql/18/docker/PG_VERSION"
  run cx_rs_dirop_start_guard
  [ "$status" = 1 ] || return 1
  printf '18\n' >"$CX_RS_DATA/postgresql/18/docker/PG_VERSION"
  cx_rs_dirop_start_guard || return 1
}
