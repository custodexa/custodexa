#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { export RS_FIX=$BATS_FILE_TMPDIR/fixtures; rs_make "$RS_FIX/plain" ui :; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_host ui
  backup_strict
  rs_unpack "$(rs_fix plain)" "$BATS_TEST_TMPDIR/input"
}
check_migrations() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"
    . "$1/lib/cmd_restore.sh"
    CX_DIR=$2 CX_RS_DIR=$3 CX_RS_VERSION=1.16.0
    cx_rs_migrations || exit 3' _ "$SRC" "$ROOT/releases/1.16.0" "$BATS_TEST_TMPDIR/checked"
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events" || return 1
}
ready() {
  mkdir -p "$BATS_TEST_TMPDIR/checked"
  mv "$BATS_TEST_TMPDIR/input" "$BATS_TEST_TMPDIR/checked/pass2"
}

@test "restore migrations: all release migrations and known runtime markers pass" {
  jq '.runtime_markers=[{id:"runtime_old",first_version:"1.15.0"}]' "$ROOT/releases/1.16.0/MANIFEST.json" >"$ROOT/releases/1.16.0/mf.new"
  mv "$ROOT/releases/1.16.0/mf.new" "$ROOT/releases/1.16.0/MANIFEST.json"
  printf 'migration=runtime_old\n' >>"$BATS_TEST_TMPDIR/input/snapshot.txt"
  ready
  check_migrations
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

# - **WHEN** 備份快照含一項不在資料版本發行清單、也不是該版執行期標記的 migration
# - **THEN** 腳本在停機前拒絕並列出該項，部署沒有任何變更
@test "restore migrations: an unknown snapshot migration refuses before stopping" {
  printf 'migration=20990101_unknown\n' >>"$BATS_TEST_TMPDIR/input/snapshot.txt"
  ready
  check_migrations
  [ "$status" -eq 3 ] && [[ $output == *'20990101_unknown'* && $output == *'not in the 1.16.0 release manifest'* ]] || { echo "$output"; return 1; }
}

@test "restore migrations: a missing release migration refuses before stopping" {
  sed -i '/^migration=20260901_add_x$/d' "$BATS_TEST_TMPDIR/input/snapshot.txt"
  ready
  check_migrations
  [ "$status" -eq 3 ] && [[ $output == *'20260901_add_x'* && $output == *'absent from the backup snapshot'* ]] || { echo "$output"; return 1; }
}

@test "restore migrations: a runtime marker first introduced after the data version refuses" {
  jq '.runtime_markers=[{id:"runtime_new",first_version:"1.16.1"}]' "$ROOT/releases/1.16.0/MANIFEST.json" >"$ROOT/releases/1.16.0/mf.new"
  mv "$ROOT/releases/1.16.0/mf.new" "$ROOT/releases/1.16.0/MANIFEST.json"
  printf 'migration=runtime_new\n' >>"$BATS_TEST_TMPDIR/input/snapshot.txt"
  ready
  check_migrations
  [ "$status" -eq 3 ] && [[ $output == *'runtime_new'* && $output == *'not in the 1.16.0 release manifest'* ]] || { echo "$output"; return 1; }
}
