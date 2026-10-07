#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
setup() {
  rs_host env
  backup_strict
  touch "$ROOT/current/compose.yml"
  bk_env_set PUBLIC_BASE_URL https://10.0.0.31
  mkdir -p "$ROOT/logs" "$ROOT/data/postgres" "$ROOT/restore/20261012-093015"
  SCRIPT=$BATS_TEST_TMPDIR/screens.sh
  cat >"$SCRIPT" <<'SH'
. "$1/lib/common.sh"
CX_LANG_FLAG=$3
export NO_COLOR=1
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_ROOT=$2 CX_DIR=$2/current CX_RS_DATA=$2/data CX_RS_DIR=$2/restore/20261012-093015
CX_RS_TS=20261012-093015 CX_RS_VERSION=1.16.0 CX_RS_ENGINE=1.16.2 CX_RS_FLOW=new
CX_RS_FILE=/srv/custodexa-backup-1.16.0-20261005-101502.tar.enc
CX_LOG_FILE=$2/logs/restore-20261012-093015.log
CX_RS_MAP=([trigger]=upgrade [created_at]=2026-10-05T10:15:02Z [kek.provider]=env
  [kek.fingerprint]=5a5a5a5a5a5a5a5a [contents.recordings]=false [contents.tls]=true
  [source.data_path]=/data/custodexa)
CX_RS_HOST_SOURCE[PUBLIC_BASE_URL]=https://10.0.0.11
CX_RS_REC_MISSING=1204 CX_RS_REC_FILE=$CX_RS_DIR/missing-recordings.txt
if [ "$4" = finish ]; then
  cx_rs_finish_screen
  cx_rs_upgrade_offer
else
  cx_state_set last_restore.covering 1
  cx_rs_abandon_screen || exit 1
  printf '%s\n' "$(cx_msg rs_exit_confirm_abandon)"
fi
SH
}
snapshot() {
  local l expected errors=0
  for l in en zh-TW ja; do
    run bash "$SCRIPT" "$SRC" "$ROOT" "$l" "$1"
    [ "$status" = 0 ] || { echo "$output"; return 1; }
    output=${output//"$ROOT"/\/opt\/custodexa}
    expected=$TESTS_DIR/snapshots/restore-$1-reviewed.$l.txt
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
      errors=1; continue
    fi
    diff <(printf '%s\n' "$output") "$expected" || errors=1
  done
  [ "$errors" = 0 ]
}
@test "restore screens: completed pre-upgrade restore in all three languages" { snapshot finish; }
@test "restore screens: giving up the running new-host restore in all three languages" { snapshot abandon; }
