#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_safety_host

setup() {
  rs_safety_host
  SCREEN=$BATS_TEST_TMPDIR/screen.sh
  cat >"$SCREEN" <<'SH'
stty -echo 2>/dev/null || true
. "$1/lib/common.sh"
CX_LANG_FLAG=$3 CX_NO_COLOR=1
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_LANG_FLAG="" CX_ROOT=$2 CX_DIR=$2/current CX_RS_SAFETY_MIN=12 CX_YES=0
cx_state_load "$CX_ROOT/state.json"
cx_state_set last_restore.engine /opt/custodexa/custodexa.sh
CX_RS_SAFETY_OK=1
case $4 in
  choose) cx_rs_safety_choose; printf '\n' ;;
  again) CX_RS_ACTION=resume; cx_rs_safety_choose; printf '\n' ;;
  preflight|refused)
    cx_rs_safety_reason fingerprint 2 || true
    CX_RS_SAFETY_OK=0
    cx_rs_safety_choose; printf '\n' ;;
  *)
    cx_state_set last_restore.stopped_at 2026-10-12T09:31:00+0000
    CX_RS_SAFETY_STARTED=0
    cx_now() { echo 125; }
    CX_RS_SAFETY_REASON=$(cx_msg rs_safety_reason_fingerprint_short)
    cx_rs_safety_failed "$4" || true ;;
esac
SH
}
safety_snapshot() {
  local kind=$1 lang expected errs=0
  for lang in en zh-TW ja; do
    case $kind in
      choose|again|preflight)
        run bash -c 'printf "2\n" | script -qec "$1" /dev/null' _ "bash '$SCREEN' '$SRC' '$ROOT' '$lang' '$kind'"
        output=${output//$'\r'/}
        # script echoes input before the child disables echo.
        output=${output#2$'\n'} ;;
      *) run bash "$SCREEN" "$SRC" "$ROOT" "$lang" "$kind" </dev/null ;;
    esac
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    expected=$TESTS_DIR/snapshots/restore-safety-$kind.$lang.txt
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
      errs=1
    else diff <(printf '%s\n' "$output") "$expected" || errs=1; fi
  done
  [ "$errs" = 0 ]
}
@test "restore safety screens: initial and resumed choices in three languages" {
  local rc=0
  safety_snapshot choose || rc=1
  safety_snapshot again || rc=1
  return "$rc"
}
@test "restore safety screens: preflight refusal and own-only choice in three languages" {
  local rc=0
  safety_snapshot preflight || rc=1
  safety_snapshot refused || rc=1
  return "$rc"
}
@test "restore safety screens: write, readback and unusable failures in three languages" {
  local kind rc=0
  for kind in write read unusable; do safety_snapshot "$kind" || rc=1; done
  return "$rc"
}
