#!/usr/bin/env bats
load helper

@test "cx_size_human displays bytes and upgrade backup sizes" {
  run bash -c '. "$1/lib/common.sh"; for n in 0 314573 19756849562 107374182400; do cx_size_human "$n"; printf "\n"; done' _ "$SRC"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = '0.0 KB' ]
  [ "${lines[1]}" = '0.3 MB' ]
  [ "${lines[2]}" = '18.4 GB' ]
  [ "${lines[3]}" = '100 GB' ]
  run bash -c '. "$1/lib/common.sh"; cx_size_human 1024' _ "$SRC"
  [ "$output" = '1.0 KB' ]
  run bash -c '. "$1/lib/common.sh"; cx_size_human 3145730' _ "$SRC"
  [ "$output" = '3.0 MB' ]
  run bash -c '. "$1/lib/common.sh"; cx_size_human 102400' _ "$SRC"
  [ "$output" = '100 KB' ]
  run bash -c '
    CX_LANG_FLAG=zh-TW
    . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/upgrade_output.sh"; . "$1/lib/upgrade_steps.sh"
    CX_BK_TS=20261001-101502 CX_BK_DIR=/unused
    CX_PB_NAME=custodexa-backup-1.16.0-20261001-101502.tar CX_PB_SIZE=19756849562
    cx_bk_du() { printf 314573; }
    cx_up_bk_cb OK 1 5 db 0
    cx_up_bk_cb OK 5 5 pack 0' _ "$SRC"
  # Step 7 makes one portable file: the database part is a size line without a file name, and the
  # file is named once, on the last line, with its own size.
  [ "$status" -eq 0 ] && [ "${#lines[@]}" -eq 2 ] || { echo "$output"; return 1; }
  [ "${lines[0]}" = '        [ OK ] 資料庫        0.3 MB' ] || { echo "$output"; return 1; }
  [ "${lines[1]}" = '        [ OK ] 備份檔  custodexa-backup-1.16.0-20261001-101502.tar  18.4 GB' ] || { echo "$output"; return 1; }
}
