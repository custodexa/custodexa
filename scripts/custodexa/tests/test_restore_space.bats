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
  W=$BATS_TEST_TMPDIR/space
  rs_unpack "$(rs_fix plain)" "$W/pass2"
  DATA=$BATS_TEST_TMPDIR/data
  mkdir -p "$DATA"
  SPACE=$BATS_TEST_TMPDIR/space.sh
  cat >"$SPACE" <<'SH'
#!/bin/bash
. "$1/lib/common.sh"
CX_LANG_FLAG=en
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_DATA=$4 CX_RS_FLOW=same CX_RS_BYTES=1000000
cx_state_load "$CX_ROOT/state.json"
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
cx_rs_space || exit 3
printf 'filesystems=%s\n' "${#CX_RS_SPACE_MOUNTS[@]}"
cx_rs_space_lines
SH
}
space() {
  before=$(sha256sum "$ROOT/state.json" "$ROOT/.env")
  run bash "$SPACE" "$SRC" "$ROOT" "$W" "$DATA"
  [ "$before" = "$(sha256sum "$ROOT/state.json" "$ROOT/.env")" ] || return 1
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events"
}

# - **WHEN** 部署根所在的檔案系統容不下暫存目錄與安全備份
# - **THEN** 腳本拒絕並列出需要與可用量，部署沒有任何變更
@test "restore space: insufficient deployment filesystem names its need and free space before refusing" {
  host_free "$ROOT" 1024
  host_free "$DATA" 900000000
  space
  [ "$status" -eq 3 ] && [[ $output == *'Not enough space'* && $output == *"$ROOT ("* && $output == *'has 0 GB'* ]] || { echo "$output"; return 1; }
}

@test "restore space: insufficient data filesystem is reported even when the working filesystem fits" {
  host_free "$ROOT" 900000000
  host_free "$DATA" 1024
  space
  [ "$status" -eq 3 ] && [[ $output == *'Not enough space'* && $output == *"$DATA (data folder)"* && $output == *'has 0 GB'* ]] || { echo "$output"; return 1; }
}

@test "restore space: one filesystem is calculated as the sum rather than separate sufficient amounts" {
  # The data database plus its safety copy and the largest safety member together exceed 40 GB.
  printf '17179869184\n' >"$DB/size"
  (cd "$W/pass2" && rs_mf_set size.db_bytes 17179869184)
  host_free / 41943040
  space
  [ "$status" -eq 3 ] && [[ $output == *'Not enough space'* ]] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | grep -c '^  / (')" -eq 1 ]
}

@test "restore space: enough space passes and shared filesystems have one combined estimate" {
  host_free / 900000000
  space
  [ "$status" -eq 0 ] && [[ $output == *'filesystems=1'* ]] || { echo "$output"; return 1; }
}
