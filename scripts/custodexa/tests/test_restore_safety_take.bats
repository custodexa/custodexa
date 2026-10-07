#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup() {
  rs_host ui
  backup_strict
  fake sleep ':'
  clock
  bk_state_set last_backup.file backups/earlier.tar
  bk_state_set last_backup.result in_progress
  bk_state_set last_backup.partial backups/.partial-earlier
  bk_state_set last_backup.unfinished_at 20260929-100000
  jq -S 'with_entries(select(.key|startswith("last_backup.")))' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/before.json"
  cat >"$BATS_TEST_TMPDIR/safety.sh" <<'SH'
. "$1/lib/common.sh"
CX_LANG_FLAG=en
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_ROOT=$2 CX_DIR=$2/current CX_SELF=$2/current/custodexa.sh CX_COMMAND=restore
cx_rs_read_setup || exit 1
CX_OVERLAYS=$(cx_state_get current.overlays)
cx_bk_vars
cx_pb_versions && cx_pb_kek_mode && cx_pb_parts || exit 1
# The safety mode fixes these, even if another backup mode set them earlier in this shell.
CX_PB_WITH_REC=1 CX_PB_ENC=1 CX_PB_PASS=unused CX_PB_TRIGGER=upgrade CX_PB_STATE=1
cx_pb_open restore-safety || exit 1
jq -S 'with_entries(select(.key|startswith("last_backup.")))' "$CX_ROOT/state.json" >"$3/open.json"
step() { printf '%s %s/%s %s\n' "$1" "$2" "$3" "$4" >>"$DB/steps"; }
cx_bk_take restore-safety step || exit 1
cx_pb_cleanup || exit 1
cx_rs_open "$CX_PB_FINAL" || exit 1
printf '%s\n' "$(cx_rs_get trigger)|$(cx_rs_get contents.recordings)|$(cx_rs_get encryption.enabled)"
SH
}

# - **WHEN** 同機還原產生安全備份
# - **THEN** 安全備份之後到覆蓋之前沒有任何服務被啟動，`status` 顯示的最近一次備份仍是還原前那一份，安全備份檔可通過還原的讀檔驗證
@test "restore acceptance: 安全備份不重啟服務也不改最近備份紀錄" {
  bk_status >"$BATS_TEST_TMPDIR/status-before"
  run bash "$BATS_TEST_TMPDIR/safety.sh" "$SRC" "$ROOT" "$BATS_TEST_TMPDIR"
  [ "$status" -eq 0 ] && [[ $output == *'manual|false|false'* ]] || { echo "$output"; return 1; }
  diff "$DB/steps" - <<'STEPS' || return 1
OK 1/6 stop
OK 2/6 db
OK 3/6 files
OK 4/6 conf
OK 5/6 verify
OK 6/6 pack
STEPS
  grep -qx 'stop backend guacd frontend' "$DB/events" || { cat "$DB/events"; return 1; }
  ! grep -Eq '^(start|up)( |$)' "$DB/events" || return 1
  cmp "$BATS_TEST_TMPDIR/before.json" "$BATS_TEST_TMPDIR/open.json" || return 1
  jq -S 'with_entries(select(.key|startswith("last_backup.")))' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/after.json"
  cmp "$BATS_TEST_TMPDIR/before.json" "$BATS_TEST_TMPDIR/after.json" || return 1
  bk_status >"$BATS_TEST_TMPDIR/status-after"
  cmp "$BATS_TEST_TMPDIR/status-before" "$BATS_TEST_TMPDIR/status-after"
}

@test "restore safety backup: SIGTERM in pack removes its tools, processes and pipes without changing the backup record" {
  : >"$DB/tar.readback.sleep"
  printf '%s\n' custodexa-backup-tool-20260930-101502-reader >"$DB/tools"
  # Keep a container registry, so cleanup is observed as removal, not just a docker invocation.
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/safety-hook"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
if [ "$1" = rm ]; then
  for n in "${@:2}"; do
    [ "$n" = -f ] && continue
    awk -v n="$n" '$0 != n' "$DB/tools" >"$DB/tools.new"
    mv "$DB/tools.new" "$DB/tools"
  done
fi
exec "$FAKE_DOCKER_REPLAY/safety-hook" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  bash "$BATS_TEST_TMPDIR/safety.sh" "$SRC" "$ROOT" "$BATS_TEST_TMPDIR" >"$BATS_TEST_TMPDIR/out" 2>&1 &
  local pid=$! rc=0 p
  wait_for "$DB/paused.tar" || { kill -9 "$pid"; cat "$BATS_TEST_TMPDIR/out"; return 1; }
  kill -TERM "$pid"
  wait "$pid" || rc=$?
  [ "$rc" -eq 1 ] || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
  [ ! -s "$DB/tools" ] || { cat "$DB/tools"; return 1; }
  for p in "$(cat "$DB/tar.pid")" "$(cat "$DB/tar.sleep.pid")"; do
    local st
    st=$(ps -o stat= -p "$p" 2>/dev/null) || continue
    [[ $st == Z* ]] || { echo "process $p still running: $st"; return 1; }
  done
  [ -z "$(find "$ROOT/backups" -type p)" ] || return 1
  ! grep -Eq '^(start|up)( |$)' "$DB/events" || return 1
  jq -S 'with_entries(select(.key|startswith("last_backup.")))' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/after.json"
  cmp "$BATS_TEST_TMPDIR/before.json" "$BATS_TEST_TMPDIR/after.json"
}
