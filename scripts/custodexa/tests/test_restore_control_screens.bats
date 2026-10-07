#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_state_host

setup() {
  rs_state_host
  SCREEN=$BATS_TEST_TMPDIR/screen.sh
  cat >"$SCREEN" <<'SH'
. "$1/lib/common.sh"
CX_LANG_FLAG=$3
cx_load_libs "$1"
CX_LANG_FLAG=""
CX_ROOT=$2 CX_DIR=$2/current CX_SELF=$2/current/custodexa.sh
cx_script_version() { cat "$CX_DIR/VERSION"; }
cx_state_load "$CX_ROOT/state.json"
case $4 in
  guard) cx_run_restore_guard upgrade; exit 0 ;;
  status) . "$1/lib/cmd_status.sh"; cmd_status_restore ;;
  menu)
    . "$1/lib/menu.sh"
    CX_MENU_KIND=restore CX_MENU_VERSION=1.16.0
    cx_menu_show
    printf '%s\n' "$(cx_msg menu_choose "${#CX_MENU_ACTIONS[@]}")" ;;
esac
SH
  bk_state_set last_restore.engine "$ROOT/releases/1.16.2/custodexa.sh"
  printf '1.16.2\n' >"$ROOT/current/VERSION"
}
snapshot() {
  local name=$1 kind=$2 l expected errs=0
  for l in en zh-TW ja; do
    run bash "$SCREEN" "$SRC" "$ROOT" "$l" "$kind"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    output=${output//"$ROOT"/\/opt\/custodexa}
    expected=$TESTS_DIR/snapshots/restore-$name.$l.txt
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
      errs=1
    else diff <(printf '%s\n' "$output") "$expected" || errs=1; fi
  done
  [ "$errs" = 0 ]
}

@test "restore screens: pending unseal refuses upgrade in all three languages" { snapshot interlock-unseal guard; }
# - **WHEN** 還原停在待解封核對時執行 `status`
# - **THEN** 輸出含還原段，寫明待解封核對、開始時間、資料版本與接續指令
@test "restore screens: pending unseal status in all three languages" {
  snapshot status-unseal status || return 1
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [ "$status" -eq 4 ] && [[ $output == *'Restore'*'waiting for unseal to check'* && $output == *'2026-10-12 09:30'* && $output == *'data version 1.16.0'* && $output == *"$ROOT/releases/1.16.2/custodexa.sh restore --resume"* ]] || { echo "$output"; return 1; }
}
@test "restore screens: completed status in all three languages" {
  bk_state_set last_restore.result succeeded
  bk_state_set last_restore.finished_at 2026-10-12T09:58:00+0800
  mkdir -p "$ROOT/data/postgres.before-restore-20261012-093015" "$ROOT/data/audit.before-restore-20261012-093015" "$ROOT/tls.before-restore-20261012-093015"
  snapshot status-done status
}
@test "restore screens: unfinished exits and settled exits are described with the matching action" {
  local action l
  for action in reverting abandoning; do
    bk_state_set last_restore.exit "$action"
    for l in en zh-TW ja; do
      run bash "$SCREEN" "$SRC" "$ROOT" "$l" status
      [ "$status" -eq 0 ] || { echo "$output"; return 1; }
      if [ "$action" = reverting ]; then [[ $output == *'restore --revert'* && $output != *'restore --resume'* ]]
      else [[ $output == *'restore --abandon'* && $output != *'restore --resume'* ]]; fi || { echo "$output"; return 1; }
    done
  done
  for action in reverted abandoned; do
    bk_state_set last_restore.result "$action"
    bk_state_set last_restore.finished_at 2026-10-12T10:20:00+0800
    run bash "$SCREEN" "$SRC" "$ROOT" en status
    [ "$status" -eq 0 ] && [[ $output == *'Last restore:'*'2026-10-12 10:20'* && $output == *'0 folders are kept'* ]] || { echo "$output"; return 1; }
    if [ "$action" = reverted ]; then [[ $output == *'went back'* ]]; else [[ $output == *'back to not installed'* ]]; fi
  done
}

# The same host goes back with its safety backup where a new host gives up (the fifth item).
@test "restore screens: unfinished same-host menu offers going back as the fifth item" {
  local l want
  for l in en zh-TW ja; do
    run bash "$SCREEN" "$SRC" "$ROOT" "$l" menu
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    want=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg menu_rs_revert' _ "$SRC")
    [[ $output == *$'\n'"  [5] $want"$'\n'"  [6] "* ]] || { echo "$output"; return 1; }
    want=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg menu_rs_abandon' _ "$SRC")
    [[ $output != *"$want"* ]] || { echo "$output"; return 1; }
    # The reviewed wording, in the two languages the reviewed screens are written in.
    case $l in
      en) [[ $output == *"  [5] Go back with the safety backup"* ]] ;;
      zh-TW) [[ $output == *"  [5] 用安全備份還原回去"* ]] ;;
    esac || { echo "$output"; return 1; }
  done
}

@test "restore screens: unfinished new-host menu in all three languages" {
  bk_state_set last_restore.flow new-host
  snapshot menu-unseal menu
}
# - **WHEN** 還原停在待解封核對時，維運在終端機不帶子命令執行腳本
# - **THEN** 主選單顯示還原未完成的狀態與接續還原項，不列升級與備份
@test "restore menu: terminal entry offers only allowed work and calls the owning engine" {
  bk_state_set last_restore.flow new-host
  mkdir -p "$ROOT/releases/1.16.2"
  cat >"$ROOT/releases/1.16.2/custodexa.sh" <<'SH'
printf '%s\n' "$*" >>"$DB/engine-called"
SH
  run bash -c 'printf "1\n0\n" | script -qec "$1" /dev/null' _ "bash '$ROOT/custodexa.sh' --lang en --no-color"
  [ "$status" -eq 0 ] && [[ $output == *'Status: a restore has not finished'* && $output == *'Carry on with the restore'* && $output != *'[4] Upgrade'* && $output != *'[5] Back up'* ]] || { echo "$output"; return 1; }
  [ "$(cat "$DB/engine-called")" = 'restore --resume --lang en --no-color' ]
  local variant
  for variant in placed reverting abandoning; do
    if [ "$variant" = placed ]; then bk_state_set last_restore.phase placed
    else bk_state_set last_restore.exit "$variant"; fi
    run bash "$SCREEN" "$SRC" "$ROOT" en menu
    [ "$status" -eq 0 ] && [[ $output != *'Start services'* ]] || { echo "$output"; return 1; }
    case $variant in
      placed) [[ $output == *'Carry on with the restore'* ]] ;;
      reverting) [[ $output == *'Finish going back'* && $output != *'Give up on this restore and'* ]] ;;
      abandoning) [[ $output == *'Finish giving up on the restore'* && $output != *'Go back with the safety backup'* ]] ;;
    esac || { echo "$output"; return 1; }
  done
}
