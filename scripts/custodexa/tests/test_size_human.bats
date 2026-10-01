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
    cx_bk_du() { printf 314573; }
    cx_up_bk_cb OK 1 6 db 0' _ "$SRC"
  [ "$status" -eq 0 ] && [[ $output == *'custodexa-db-20261001-101502.dump  0.3 MB'* ]] || { echo "$output"; return 1; }
}
