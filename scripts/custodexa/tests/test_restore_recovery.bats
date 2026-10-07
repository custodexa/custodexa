#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
load restore_start_host
setup() {
  rs_start_host
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  if [ -z "$CX_RS_ACTION" ]; then
    CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.0 CX_RS_ENGINE=1.16.1
    CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched
    cx_rs_record && cx_rs_phase prepared || return 1
  else cx_rs_recover_context || return 1; fi
  cx_rs_restart_original
}
HARNESS
}
@test "restore recovery: before covering only the original services are started and settled after readiness" {
  rs_start_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$DB/events")" = $'up\nhealth' ] || return 1
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = reverted ]
}
@test "restore recovery: original service timeout keeps reverting in progress until another revert is ready" {
  echo 1 >"$DB/health.rc"
  rs_start_run
  [ "$status" = 1 ] && [[ $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = in_progress ] || return 1
  [ "$(jq -r '."last_restore.exit"' "$ROOT/state.json")" = reverting ] || return 1
  rm "$DB/health.rc"
  run bash "$RS_I_ENGINE" restore --revert --yes --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = reverted ]
}
