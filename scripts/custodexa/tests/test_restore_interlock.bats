#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_state_host

setup() { rs_state_host; }

@test "restore interlock: early, status" { rs_gate_case early status 0; }
@test "restore interlock: early, load" { rs_gate_case early load 0; }
@test "restore interlock: early, start" { rs_gate_case early start 3; }
@test "restore interlock: early, stop" { rs_gate_case early stop 0; }
@test "restore interlock: early, backup" { rs_gate_case early backup 3; }
@test "restore interlock: early, upgrade" { rs_gate_case early upgrade 3; }
@test "restore interlock: early, rollback" { rs_gate_case early rollback 3; }
@test "restore interlock: early, install" { rs_gate_case early install 3; }
@test "restore interlock: early, restore" { rs_gate_case early restore 3; }
@test "restore interlock: early, restore-resume" { rs_gate_case early restore-resume 0; }
@test "restore interlock: early, restore-revert" { rs_gate_case early restore-revert 0; }
@test "restore interlock: early, restore-abandon" { rs_gate_case early restore-abandon 0; }
@test "restore interlock: unchecked, status" { rs_gate_case unchecked status 0; }
@test "restore interlock: unchecked, load" { rs_gate_case unchecked load 0; }
@test "restore interlock: unchecked, start" { rs_gate_case unchecked start 3; }
@test "restore interlock: unchecked, stop" { rs_gate_case unchecked stop 0; }
@test "restore interlock: unchecked, backup" { rs_gate_case unchecked backup 3; }
@test "restore interlock: unchecked, upgrade" { rs_gate_case unchecked upgrade 3; }
@test "restore interlock: unchecked, rollback" { rs_gate_case unchecked rollback 3; }
@test "restore interlock: unchecked, install" { rs_gate_case unchecked install 3; }
@test "restore interlock: unchecked, restore" { rs_gate_case unchecked restore 3; }
@test "restore interlock: unchecked, restore-resume" { rs_gate_case unchecked restore-resume 0; }
@test "restore interlock: unchecked, restore-revert" { rs_gate_case unchecked restore-revert 0; }
@test "restore interlock: unchecked, restore-abandon" { rs_gate_case unchecked restore-abandon 0; }
@test "restore interlock: placed, status" { rs_gate_case placed status 0; }
@test "restore interlock: placed, load" { rs_gate_case placed load 0; }
@test "restore interlock: placed, start" { rs_gate_case placed start 3; }
@test "restore interlock: placed, stop" { rs_gate_case placed stop 0; }
@test "restore interlock: placed, backup" { rs_gate_case placed backup 3; }
@test "restore interlock: placed, upgrade" { rs_gate_case placed upgrade 3; }
@test "restore interlock: placed, rollback" { rs_gate_case placed rollback 3; }
@test "restore interlock: placed, install" { rs_gate_case placed install 3; }
@test "restore interlock: placed, restore" { rs_gate_case placed restore 3; }
@test "restore interlock: placed, restore-resume" { rs_gate_case placed restore-resume 0; }
@test "restore interlock: placed, restore-revert" { rs_gate_case placed restore-revert 0; }
@test "restore interlock: placed, restore-abandon" { rs_gate_case placed restore-abandon 0; }
@test "restore interlock: started, status" { rs_gate_case started status 0; }
@test "restore interlock: started, load" { rs_gate_case started load 0; }
@test "restore interlock: started, start" { rs_gate_case started start 0; }
@test "restore interlock: started, stop" { rs_gate_case started stop 0; }
@test "restore interlock: started, backup" { rs_gate_case started backup 3; }
@test "restore interlock: started, upgrade" { rs_gate_case started upgrade 3; }
@test "restore interlock: started, rollback" { rs_gate_case started rollback 3; }
@test "restore interlock: started, install" { rs_gate_case started install 3; }
@test "restore interlock: started, restore" { rs_gate_case started restore 3; }
@test "restore interlock: started, restore-resume" { rs_gate_case started restore-resume 0; }
@test "restore interlock: started, restore-revert" { rs_gate_case started restore-revert 0; }
@test "restore interlock: started, restore-abandon" { rs_gate_case started restore-abandon 0; }
@test "restore interlock: reverting, status" { rs_gate_case reverting status 0; }
@test "restore interlock: reverting, load" { rs_gate_case reverting load 0; }
@test "restore interlock: reverting, start" { rs_gate_case reverting start 3; }
@test "restore interlock: reverting, stop" { rs_gate_case reverting stop 0; }
@test "restore interlock: reverting, backup" { rs_gate_case reverting backup 3; }
@test "restore interlock: reverting, upgrade" { rs_gate_case reverting upgrade 3; }
@test "restore interlock: reverting, rollback" { rs_gate_case reverting rollback 3; }
@test "restore interlock: reverting, install" { rs_gate_case reverting install 3; }
@test "restore interlock: reverting, restore" { rs_gate_case reverting restore 3; }
@test "restore interlock: reverting, restore-resume" { rs_gate_case reverting restore-resume 3; }
@test "restore interlock: reverting, restore-revert" { rs_gate_case reverting restore-revert 0; }
@test "restore interlock: reverting, restore-abandon" { rs_gate_case reverting restore-abandon 3; }
@test "restore interlock: abandoning, status" { rs_gate_case abandoning status 0; }
@test "restore interlock: abandoning, load" { rs_gate_case abandoning load 0; }
@test "restore interlock: abandoning, start" { rs_gate_case abandoning start 3; }
@test "restore interlock: abandoning, stop" { rs_gate_case abandoning stop 0; }
@test "restore interlock: abandoning, backup" { rs_gate_case abandoning backup 3; }
@test "restore interlock: abandoning, upgrade" { rs_gate_case abandoning upgrade 3; }
@test "restore interlock: abandoning, rollback" { rs_gate_case abandoning rollback 3; }
@test "restore interlock: abandoning, install" { rs_gate_case abandoning install 3; }
@test "restore interlock: abandoning, restore" { rs_gate_case abandoning restore 3; }
@test "restore interlock: abandoning, restore-resume" { rs_gate_case abandoning restore-resume 3; }
@test "restore interlock: abandoning, restore-revert" { rs_gate_case abandoning restore-revert 3; }
@test "restore interlock: abandoning, restore-abandon" { rs_gate_case abandoning restore-abandon 0; }

@test "restore interlock: covering before phase advances uses the unchecked-data refusal" {
  bk_state_set last_restore.phase stopped
  bk_state_set last_restore.step 5
  bk_state_set last_restore.covering 1
  run bash "$GATE" "$SRC" "$ROOT" start
  [ "$status" -eq 3 ] && [[ $output == *'data has not been checked'* && $output == *'restore --resume'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
}

# - **WHEN** 還原停在待解封核對時執行 `upgrade`
# - **THEN** 腳本在任何變更前拒絕，說明還原尚未完成，印出 `restore --resume` 的完整指令
@test "restore interlock: the CLI refuses new work and a different engine with the owning engine's path" {
  mkdir -p "$ROOT/releases/1.16.2"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$ROOT/releases/1.16.2/"
  bk_state_set last_restore.engine "$ROOT/releases/1.16.2/custodexa.sh"
  local cmd
  for cmd in upgrade backup rollback install restore; do
    run bash "$ROOT/custodexa.sh" "$cmd" --lang en </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'restore'* && $output == *"sudo $ROOT/releases/1.16.2/custodexa.sh restore --resume"* ]] || { echo "$cmd: $output"; return 1; }
  done
  run bash "$ROOT/custodexa.sh" restore --resume --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'management script that started this restore'* && $output == *"$ROOT/releases/1.16.2/custodexa.sh restore --resume"* ]] || { echo "$output"; return 1; }
  [ ! -s "$DB/events" ]
}

# - **WHEN** 同機還原在匯入資料庫時失敗，維運接著執行 `start`
# - **THEN** 腳本拒絕並印出接續與用安全備份還原回去兩條指令，服務維持停止
# - **WHEN** 還原停在資料已放回、服務尚未啟動的階段時執行 `start`
# - **THEN** 腳本拒絕並印出 `restore --resume`，服務沒有被啟動
@test "restore interlock: failed import and placed data both refuse CLI start" {
  local p
  for p in imported placed; do
    bk_state_set last_restore.phase "$p"
    bk_state_set last_restore.covering 1
    printf 'stopped\n' | tee "$DB/ctr/backend" "$DB/ctr/guacd" "$DB/ctr/frontend" "$DB/ctr/postgres" >/dev/null
    run bash "$ROOT/custodexa.sh" start --lang en </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'restore --resume'* ]] || { echo "$output"; return 1; }
    if [ "$p" = imported ]; then [[ $output == *'data has not been checked'* && $output == *'restore --revert'* ]]
    else [[ $output == *'restored data is in place'* ]]; fi || { echo "$output"; return 1; }
    ! grep -qxv stopped "$DB"/ctr/* || return 1
  done
  [ ! -s "$DB/events" ]
}

@test "restore interlock: load passes the generic begin loop without changing the restore record" {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=$2; CX_SELF=$2/current/custodexa.sh; CX_DIR=$2/current
    cx_begin load; cx_finish succeeded' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = in_progress ]
}

@test "restore interlock: the old runner refuses upgrade using the same format 2 record" {
  # Keep compatibility testing independent of repository history and worktree metadata.
  cp "$SRC/tests/fixtures/restore-legacy-run-1.13.0.sh" "$BATS_TEST_TMPDIR/old-run.sh"
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$3"
    CX_ROOT=$2; CX_SELF=$2/current/custodexa.sh; cx_begin upgrade' _ "$SRC" "$ROOT" "$BATS_TEST_TMPDIR/old-run.sh"
  [ "$status" -eq 3 ] && [[ $output == *'last_restore'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r .format "$ROOT/state.json")" = 2 ]
}

# - **WHEN** 還原停在待解封核對時執行 `stop` 再執行 `start`
# - **THEN** 兩者照常完成，還原狀態仍是待解封核對
@test "restore interlock: stop and start finish while the unseal check remains pending" {
  run bash "$ROOT/custodexa.sh" stop --yes --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  ! grep -qxv stopped "$DB"/ctr/* || return 1
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  ! grep -qxv running "$DB"/ctr/* || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = awaiting_unseal ]
}
