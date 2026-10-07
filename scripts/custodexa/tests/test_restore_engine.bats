#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host
setup() { rs_engine_host; }
@test "restore engine: env input completes every stage" {
  rs_engine_run
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$status $output"; return 1; }
}
@test "restore engine: prepared failure carries on to completion" { rs_engine_matrix prepared 0; }
@test "restore engine: prepared SIGTERM carries on to completion" { rs_engine_matrix prepared 1; }
@test "restore engine: safety failure carries on to completion" { rs_engine_matrix safety 0; }
@test "restore engine: safety SIGTERM carries on to completion" { rs_engine_matrix safety 1; }
@test "restore engine: stopped failure carries on to completion" { rs_engine_matrix stopped 0; }
@test "restore engine: stopped SIGTERM carries on to completion" { rs_engine_matrix stopped 1; }
@test "restore engine: swapped failure carries on to completion" { rs_engine_matrix swapped 0; }
@test "restore engine: swapped SIGTERM carries on to completion" { rs_engine_matrix swapped 1; }
@test "restore engine: imported failure carries on to completion" { rs_engine_matrix imported 0; }
@test "restore engine: imported SIGTERM carries on to completion" { rs_engine_matrix imported 1; }
@test "restore engine: db_checked failure carries on to completion" { rs_engine_matrix db_checked 0; }
@test "restore engine: db_checked SIGTERM carries on to completion" { rs_engine_matrix db_checked 1; }
@test "restore engine: placed failure carries on to completion" { rs_engine_matrix placed 0; }
@test "restore engine: placed SIGTERM carries on to completion" { rs_engine_matrix placed 1; }
@test "restore engine: started failure carries on to completion" { rs_engine_matrix started 0; }
@test "restore engine: started SIGTERM carries on to completion" { rs_engine_matrix started 1; }
@test "restore engine: awaiting_unseal failure carries on to completion" { rs_engine_matrix awaiting_unseal 0; }
@test "restore engine: awaiting_unseal SIGTERM carries on to completion" { rs_engine_matrix awaiting_unseal 1; }
@test "restore engine: interruption after up and before readiness reports the running containers" {
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'SH'
eval "$(declare -f cx_compose_release | sed '1s/cx_compose_release/rs_e_compose/')"
cx_compose_release() {
  rs_e_compose "$@" || return 1
  if [ "$2 ${3:-}" = 'up -d' ] && [ "$#" = 3 ] && [ ! -e "$DB/cut-hit" ]; then
    touch "$DB/cut-hit"
    kill -TERM "$$"
  fi
}
SH
  rs_engine_run
  [ "$status" = 1 ] && [[ $output == *'Some or all services may be running'* && $output == *' status'* && $output == *'restore --resume'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = placed ] || return 1
  local f
  for f in "$DB"/ctr/*; do [ "$(cat "$f")" = running ] || return 1; done
  rs_engine_resume
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$output"; return 1; }
}
@test "restore engine: failed import is retained and resumed without another safety backup" {
  echo 1 >"$DB/import.rc"
  rs_engine_run
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  [[ $output == *'[FAIL]  6/10  Import the database'* && $output == *'pg_restore reported an error'* && $output != *'[ OK ]  6/10'* && $output != *'[ OK ]  7/10'* ]] || { echo "$output"; return 1; }
  local dumps
  dumps=$(grep -cx pg_dump "$DB/events")
  rm "$DB/import.rc"
  rs_engine_resume
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$output"; return 1; }
  [ "$(grep -cx pg_dump "$DB/events")" = "$dumps" ] || return 1
  [ -n "$(find "$ROOT/data" -maxdepth 1 -name 'postgres.partial-restore-*')" ]
}
@test "restore engine: after covering revert imports the safety backup without taking another backup" {
  export RS_E_CUT=imported
  rs_engine_run
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  unset RS_E_CUT
  local dumps safety before=$BATS_TEST_TMPDIR/safety-input
  dumps=$(grep -cx pg_dump "$DB/events")
  safety=$(jq -r '."last_restore.safety_file"' "$ROOT/state.json")
  tar -xOf "$safety" db.dump >"$before"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = reverted ] || { echo "$status $output"; return 1; }
  [ "$(grep -cx pg_dump "$DB/events")" = "$dumps" ] || return 1
  cmp "$before" "$ROOT/data/postgres/import-data" || return 1
  [ -n "$(find "$ROOT/data" -maxdepth 1 -name 'postgres.partial-restore-*')" ]
}
@test "restore engine: revert interrupted during a rename carries on with its own journal" {
  export RS_E_CUT=db_checked
  rs_engine_run
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  unset RS_E_CUT
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'SH'
eval "$(declare -f cx_rs_journal_apply | sed '1s/cx_rs_journal_apply/rs_e_apply/')"
cx_rs_journal_apply() {
  rs_e_apply || return 1
  if [ "$CX_RS_ACTION" = revert ] && [ "$CX_RS_J_KIND" = move ] && [ ! -e "$DB/revert-cut" ]; then
    touch "$DB/revert-cut"
    kill -TERM "$$"
    return 1
  fi
}
SH
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en
  [ "$status" = 1 ] && [ -e "$DB/revert-cut" ] || { echo "$status $output"; return 1; }
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = reverted ] || { echo "$status $output"; return 1; }
}
@test "restore engine: a completed restore refuses revert and names a new restore from its safety file" {
  rs_engine_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/settled"
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en
  [ "$status" = 3 ] && [[ $output == *'last restore finished'* && $output == *'That is a new restore'* && $output == *"restore $(jq -r '."last_restore.safety_file"' "$ROOT/state.json")"* ]] || { echo "$output"; return 1; }
  cmp "$ROOT/state.json" "$BATS_TEST_TMPDIR/settled" && [ ! -s "$DB/events" ]
}
