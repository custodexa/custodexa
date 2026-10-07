#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_journal_host
setup_file() {
  export RS_FIX=$BATS_FILE_TMPDIR/safety
  rs_make "$RS_FIX" ui :
}
setup() { rs_journal_host; }

@test "restore journal: database rename survives every interrupt with either exit" { rs_journal_matrix postgres-before; }
@test "restore journal: audit rename survives every interrupt with either exit" { rs_journal_matrix audit-before; }
@test "restore journal: certificate rename survives every interrupt with either exit" { rs_journal_matrix tls-before; }
@test "restore journal: empty database creation survives every interrupt with either exit" { rs_journal_matrix postgres-empty; }
@test "restore journal: settings replacement survives every interrupt with either exit" { rs_journal_matrix env-merged; }
@test "restore journal: template rename survives every interrupt with either exit" { rs_journal_matrix template-before; }
@test "restore journal: template placement survives every interrupt with either exit" { rs_journal_matrix template-place; }
@test "restore journal: leaf folder creation survives every interrupt with either exit" { rs_journal_matrix leaf-folder; }
@test "restore journal: certificate move survives every interrupt with either exit" { rs_journal_matrix leaf-fullchain.pem; }
@test "restore journal: private key move survives every interrupt with either exit" { rs_journal_matrix leaf-privkey.pem; }
@test "restore journal: current link survives every interrupt with either exit" { rs_journal_matrix current-link; }
@test "restore journal: current version survives every interrupt with either exit" { rs_journal_matrix current-version; }
@test "restore journal: current images survive every interrupt with either exit" { rs_journal_matrix current-image_ids; }

# - **WHEN** 同機還原在舊資料庫目錄已改名、稽核目錄尚未改名時被 SIGKILL，接著執行 `restore --revert`
# - **THEN** 腳本判定已開始覆蓋，以安全備份還原，不會以「尚未覆蓋」直接啟動原服務
@test "restore acceptance: 改名做到一半時中斷再回去" {
  rs_journal_reset
  rs_journal_start after-action:postgres-before || return 1
  run bash "$RS_J_ENGINE" restore --revert --yes --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  grep -q '^restore-safety ' "$DB/events" && ! grep -q '^original-services$' "$DB/events"
}

@test "restore journal: covering is persisted before the first intent and controls both exits" {
  local point action
  for point in before-state after-state; do
    for action in resume revert; do
      rs_journal_reset
      rs_journal_start "$point:covering" || return 1
      run bash "$RS_J_ENGINE" restore "--$action" --yes --lang en
        [ "$status" = 0 ] || { echo "$output"; return 1; }
        if [ "$action" = resume ]; then rs_journal_resumed || return 1
        elif [ "$point" = before-state ]; then grep -q '^original-services$' "$DB/events" || return 1
        else grep -q '^restore-safety ' "$DB/events" || return 1; fi
    done
  done
}
@test "restore journal: ambiguous paths refuse both exits before any rename" {
  rs_journal_reset
  rs_journal_start after-intent:postgres-before || return 1
  cp -a "$ROOT/data/postgres" "$ROOT/data/postgres.before-restore-journal-test"
  tree_of "$ROOT/data" >"$BATS_TEST_TMPDIR/ambiguous-before"
  local action
  for action in resume revert; do
    run bash "$RS_J_ENGINE" restore "--$action" --yes --lang en
    [ "$status" = 1 ] && [[ $output == *'Cannot determine'* && $output == *"$ROOT/data/postgres"* && $output == *"$ROOT/data/postgres.before-restore-journal-test"* ]] || { echo "$output"; return 1; }
    tree_of "$ROOT/data" >"$BATS_TEST_TMPDIR/ambiguous-after"
    cmp "$BATS_TEST_TMPDIR/ambiguous-before" "$BATS_TEST_TMPDIR/ambiguous-after" || return 1
  done
}
@test "restore journal: losing the journal refuses resume but retains the safety exit" {
  rs_journal_reset
  rs_journal_start after-action:postgres-before || return 1
  rm "$RS_J_STAGE/journal"
  run bash "$RS_J_ENGINE" restore --resume --lang en
  [ "$status" = 1 ] && [[ $output == *'journal'*'missing'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
  run bash "$RS_J_ENGINE" restore --revert --yes --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  grep -q '^restore-safety ' "$DB/events" && ! grep -q '^original-services$' "$DB/events"
}

phase_boundary() {
  local phase=$1 point action
  for point in before-state after-state; do
    for action in resume revert; do
      rs_journal_reset
      rs_journal_start "$point:phase-$phase" || return 1
      run bash "$RS_J_ENGINE" restore "--$action" --yes --lang en
      [ "$status" = 0 ] || { echo "$output"; return 1; }
      if [ "$action" = resume ]; then rs_journal_resumed || return 1
      else grep -q '^restore-safety ' "$DB/events" && ! grep -q '^original-services$' "$DB/events" || return 1; fi
    done
  done
}
@test "restore journal: swapped phase persists across both exit boundaries" { phase_boundary swapped; }
@test "restore journal: placed phase persists across both exit boundaries" { phase_boundary placed; }
