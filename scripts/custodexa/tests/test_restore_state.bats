#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup() { rs_host ui; backup_strict; }

@test "restore state: format 2 records retain their identity, phases, service intent and exit across recovery" {
  cat >"$BATS_TEST_TMPDIR/state.sh" <<'SH'
. "$1/lib/common.sh"
CX_LANG_FLAG=en
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_ROOT=$2 CX_DIR=$2/current CX_SELF=$2/current/custodexa.sh
cx_lock
cx_log_open restore
CX_RS_FILE=$3 CX_RS_FLOW=same CX_RS_ENGINE=1.16.0 CX_RS_VERSION=1.16.0 CX_RS_TS=20261012-093015
CX_RS_DIR=$2/restore/$CX_RS_TS CX_RS_CHECKSUM=ok
if [ "${4:-}" = different ]; then
  CX_RS_ENGINE=1.16.2 CX_RS_VERSION=1.16.2 CX_DIR=$2/releases/1.16.2 CX_SELF=$2/releases/1.16.2/custodexa.sh
fi
CX_RS_MAP=([kek.provider]=ui [kek.fingerprint]=5a5a5a5a5a5a5a5a)
cx_rs_record || exit 1
cx_rs_phase prepared && cx_rs_step 3 && cx_rs_apps_stopped || exit 1
cx_state_set last_restore.covering 1
cx_state_set last_restore.kek_mismatch aaaaaaaaaaaaaaaa
cx_state_set last_restore.kek_evidence runtime-id
cx_rs_leaving reverting || exit 1
cx_state_load "$CX_ROOT/state.json"
CX_RS_FILE=ignored CX_RS_DIR=ignored CX_RS_PHASE=ignored CX_RUN_STEP=0
CX_RS_ACTION=revert
cx_rs_recover_context || exit 1
printf 'context=%s|%s|%s|%s|%s\n' "$CX_RS_PHASE" "$CX_RUN_STEP" "$CX_RS_FILE" "$CX_RS_DIR" "$CX_RS_FLOW"
SH
  printf 'backup placeholder\n' >"$BATS_TEST_TMPDIR/input.tar"
  run bash "$BATS_TEST_TMPDIR/state.sh" "$SRC" "$ROOT" "$BATS_TEST_TMPDIR/input.tar"
  [ "$status" -eq 0 ] && [[ $output == *"context=prepared|3|$BATS_TEST_TMPDIR/input.tar|$ROOT/restore/20261012-093015|same"* ]] || { echo "$output"; return 1; }
  jq -e '.format=="2" and ."last_restore.result"=="in_progress" and ."last_restore.flow"=="same-host" and
    ."last_restore.purpose"=="restore" and ."last_restore.services"=="app-stopped" and (."last_restore.stopped_at"|length)>0 and
    ."last_restore.covering"=="1" and ."last_restore.exit"=="reverting" and ."last_restore.kek_mismatch"=="aaaaaaaaaaaaaaaa" and
    ."last_restore.kek_evidence"=="runtime-id" and ."last_restore.engine"==($root+"/custodexa.sh")' \
    --arg root "$ROOT" "$ROOT/state.json" || return 1
  # Until placement, current can still be the old deployment even if engine and data agree.
  bk_state_set last_restore.result succeeded
  mkdir -p "$ROOT/releases/1.16.2"
  cp "$ROOT/current/custodexa.sh" "$ROOT/releases/1.16.2/custodexa.sh"
  printf '1.16.2\n' >"$ROOT/releases/1.16.2/VERSION"
  run bash "$BATS_TEST_TMPDIR/state.sh" "$SRC" "$ROOT" "$BATS_TEST_TMPDIR/input.tar" different
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.engine"' "$ROOT/state.json")" = "$ROOT/releases/1.16.2/custodexa.sh" ]
}
