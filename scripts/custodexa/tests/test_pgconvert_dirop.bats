#!/usr/bin/env bats
# lib/dirop.sh: the rename log of the database data folders and the check before a
# database starts. Each test works on a throw-away deployment folder; state.json is the real file
# written by lib/state.sh. A power cut between two steps is the state.json a test writes: the
# intent on disk with the folder moved or not.

load helper
load pgconvert_host

setup() {
  load_lib
  CX_ROOT=$BATS_TEST_TMPDIR/root
  D=$CX_ROOT/data
  mkdir -p "$D"
  CX_LOG_FILE=$BATS_TEST_TMPDIR/log
  : >"$CX_LOG_FILE"
  CX_LANG=en
  EVENTS=$BATS_TEST_TMPDIR/events
  : >"$EVENTS"
  cx_state_reset
  cx_state_set format 2
  cx_state_set current.version 1.23.0
  cx_state_save "$CX_ROOT/state.json"
  # The mv of a data folder is recorded, so a test can say there was none.
  cx_dirop_mv() { printf 'mv %s %s\n' "$1" "$2" >>"$EVENTS"; mv -- "$1" "$2"; }
}

# mkdata <dir> <major> [pgdata]: a data folder with its PG_VERSION.
mkdata() {
  mkdir -p "$D/$1${3:+/$3}"
  printf '%s\n' "$2" >"$D/$1${3:+/$3}/PG_VERSION"
}


st() { jq -r --arg k "$1" '.[$k] // ""' "$CX_ROOT/state.json"; }

# intent_on_disk <id> <from> <to>: what an interrupted run left in state.json.
intent_on_disk() {
  cx_state_set dir_op.id "$1"
  cx_state_set dir_op.from "$2"
  cx_state_set dir_op.to "$3"
  cx_state_set dir_op.phase intent
  cx_state_save "$CX_ROOT/state.json"
}

@test "the intent is saved before the mv and the completion after it" {
  mkdata postgresql 18 18/docker
  cx_dirop_rename rolled-back "$D/postgresql" "$D/postgresql.rolled-back-1" || return 1
  [ -d "$D/postgresql.rolled-back-1" ] && [ ! -e "$D/postgresql" ] || return 1
  [ "$(st dir_op.phase)" = done ] || return 1
  [ "$(st dir_op.from)" = "$D/postgresql" ] && [ "$(st dir_op.to)" = "$D/postgresql.rolled-back-1" ] || return 1
  grep -q 'DIROP intent' "$CX_LOG_FILE" && grep -q 'DIROP done' "$CX_LOG_FILE" || return 1
}

@test "when the intent cannot be saved there is no mv" {
  mkdata postgres 16
  cx_state_save() { return 1; }
  run cx_dirop_rename before-convert "$D/postgres" "$D/postgres.x"
  [ "$status" -eq 1 ] || return 1
  [ ! -s "$EVENTS" ] || return 1
  [ -d "$D/postgres" ] || return 1
}

@test "[pg18] 記下意圖後、改名前斷電" {
  mkdata postgresql 18 18/docker
  intent_on_disk rolled-back "$D/postgresql" "$D/postgresql.rolled-back-9"
  cx_state_reset
  cx_state_load "$CX_ROOT/state.json"
  cx_dirop_pending || return 1
  cx_dirop_recover || return 1
  [ -d "$D/postgresql.rolled-back-9" ] && [ ! -e "$D/postgresql" ] || return 1
  [ "$(st dir_op.phase)" = done ] || return 1
  [ "$(grep -c '^mv ' "$EVENTS")" = 1 ] || return 1
}

@test "[pg18] 改名完成後、記下完成前斷電" {
  mkdata postgresql.rolled-back-9 18 18/docker
  intent_on_disk rolled-back "$D/postgresql" "$D/postgresql.rolled-back-9"
  cx_dirop_recover || return 1
  [ "$(st dir_op.phase)" = done ] || return 1
  [ ! -s "$EVENTS" ] || return 1
}

@test "[pg18] 改名兩端都存在" {
  mkdata postgresql 18 18/docker
  mkdata postgresql.rolled-back-9 16
  intent_on_disk rolled-back "$D/postgresql" "$D/postgresql.rolled-back-9"
  use_fake_docker
  rc=0
  cx_dirop_recover || rc=$?
  [ "$rc" = 3 ] || return 1
  run cx_dirop_ambiguous_screen
  [[ $output == *"$D/postgresql"* && $output == *"$D/postgresql.rolled-back-9"* ]] || return 1
  [[ $output == *"version: 18"* && $output == *"version: 16"* ]] || return 1
  [ ! -s "$EVENTS" ] || return 1
  [ "$(st dir_op.phase)" = intent ] || return 1
  run cx_dirop_guard "$D" postgresql 18/docker 18
  [ "$status" -eq 1 ] || return 1
  [ ! -s "$FAKE_DOCKER_LOG" ] || return 1
}

@test "both ends missing: ambiguous too, the guard refuses and no docker call is made" {
  intent_on_disk rolled-back "$D/postgresql" "$D/postgresql.rolled-back-9"
  use_fake_docker
  run cx_dirop_guard "$D" postgresql 18/docker 18
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"$D/postgresql.rolled-back-9"* && $output == *"not there"* ]] || return 1
  [ ! -s "$FAKE_DOCKER_LOG" ] || return 1
}

@test "[pg18] 撤回時反向改名中斷" {
  mkdata postgresql.rolled-back-9 18 18/docker
  intent_on_disk revert "$D/postgresql.rolled-back-9" "$D/postgresql"
  cx_dirop_recover || return 1
  [ -e "$D/postgresql/18/docker/PG_VERSION" ] || return 1
  [ ! -e "$D/postgresql.rolled-back-9" ] || return 1
  [ "$(st dir_op.id)" = revert ] && [ "$(st dir_op.phase)" = done ] || return 1
  # the way there goes through the same log
  cx_dirop_rename rolled-back "$D/postgresql" "$D/postgresql.rolled-back-10" || return 1
  [ "$(st dir_op.id)" = rolled-back ] || return 1
}

@test "[pg18] 資料目錄缺版本檔時不啟動" {
  mkdir -p "$D/postgresql/18/docker"
  use_fake_docker
  run cx_dirop_guard "$D" postgresql 18/docker 18
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"no PG_VERSION"* ]] || return 1
  [ ! -s "$FAKE_DOCKER_LOG" ] || return 1
}

@test "a data folder of another major is not started" {
  mkdata postgresql 16 18/docker
  run cx_dirop_guard "$D" postgresql 18/docker 18
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"PostgreSQL 16"* ]] || return 1
}

@test "[pg18] 一般啟動不適用初始化例外" {
  # after the init the next start is checked against PG_VERSION like any other
  mkdir -p "$D/postgresql/18/docker"
  cx_dirop_start_check "$D" postgresql 18/docker 18 init || return 1
  rc=0
  cx_dirop_start_check "$D" postgresql 18/docker 18 || rc=$?
  [ "$rc" = 4 ] && [ "$CX_DIROP_WHY" = missing ] || return 1
  # a pending rename ends the exception too
  intent_on_disk x "$D/a" "$D/b"
  rc=0
  cx_dirop_start_check "$D" postgresql 18/docker 18 init || rc=$?
  [ "$rc" = 4 ] || return 1
  printf '18\n' >"$D/postgresql/18/docker/PG_VERSION"
  cx_state_set dir_op.phase done
  cx_dirop_start_check "$D" postgresql 18/docker 18 || return 1
}

@test "[pg18] 受控轉換在空目錄初始化新叢集" {
  cx_dirop_start_check "$D" postgresql 18/docker 18 init || return 1
  mkdir -p "$D/postgresql/18/docker"
  cx_dirop_start_check "$D" postgresql 18/docker 18 init || return 1
  mkdata postgresql 18 18/docker
  rc=0
  cx_dirop_start_check "$D" postgresql 18/docker 18 init || rc=$?
  [ "$rc" = 4 ] && [ "$CX_DIROP_WHY" = notempty ] || return 1
}

@test "a good folder starts, and a new install (no version, no folder) is not held" {
  mkdata postgresql 18 18/docker
  cx_dirop_guard "$D" postgresql 18/docker 18 || return 1
  rm -rf "$D/postgresql"
  cx_state_unset current.version
  cx_dirop_guard "$D" postgresql 18/docker 18 || return 1
}

@test "the start command refuses a data folder without PG_VERSION before any compose call" {
  grep -q 'cx_dirop_start_guard' "$SRC/lib/cmd_start.sh" || return 1
  grep -q 'cx_dirop_start_guard' "$SRC/lib/upgrade_steps.sh" || return 1
}

@test "the entry guard reads the release: 18 layout is checked, external database and old 16 layout as they are" {
  rel=$BATS_TEST_TMPDIR/rel
  mkdir -p "$rel"
  jq -n '{format: 1, version: "1.23.0", images: {postgres: {tag: "18.6-alpine3.24"}},
    bundled_db: {major: 18, data_dir: "postgresql", pgdata: "18/docker"}}' >"$rel/MANIFEST.json"
  CX_BK_DATA=$D
  CX_OVERLAYS=""
  mkdir -p "$D/postgresql/18/docker"
  run cx_dirop_start_guard "$rel"
  [ "$status" -eq 1 ] || return 1
  CX_OVERLAYS="external-database"
  cx_dirop_start_guard "$rel" || return 1
  CX_OVERLAYS=""
  jq -n '{format: 1, version: "1.22.0", images: {postgres: {tag: "16.15-alpine3.24"}}}' >"$rel/MANIFEST.json"
  mkdata postgres 16
  cx_dirop_start_guard "$rel" || return 1
}

@test "the start after a backup only starts the application services, never the database" {
  # postgres keeps running through a backup, so this entry cannot start a database of another major
  sed -n '/^cx_bk_services()/p;/^cx_bk_start()/p' "$SRC/lib/backup.sh" >"$BATS_TEST_TMPDIR/svc"
  grep -q 'cx_form_app_services' "$BATS_TEST_TMPDIR/svc" || return 1
  grep -q 'compose start \$(cx_bk_services)' "$BATS_TEST_TMPDIR/svc" || return 1
}
