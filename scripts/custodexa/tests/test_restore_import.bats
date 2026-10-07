#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
setup() { rs_import_host; }

# - **WHEN** 內建資料庫部署進行還原的匯入步驟
# - **THEN** 此時只有資料庫容器在執行，後端容器沒有啟動過
@test "restore acceptance: 匯入前不啟動後端" {
  rs_import_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  rs_import_only_postgres || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = imported ]
}
@test "restore import: differing database encoding refuses before importing" {
  printf 'LATIN1|en_US.utf8|en_US.utf8\n' >"$DB/encoding"
  rs_import_run
  [ "$status" = 1 ] && [[ $output == *'encoding, collation or character classification differs'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = swapped ] || return 1
  ! grep -q '^pg_restore import$' "$DB/events"
}
@test "restore import: resume retains the partial cluster and imports into a new empty cluster" {
  printf '1\n' >"$DB/import.rc"
  rs_import_run
  [ "$status" = 1 ] && [[ $output == *'[FAIL]  6/10  Import the database'* && $output == *'pg_restore reported an error'* ]] || { echo "$output"; return 1; }
  rm "$DB/import.rc"
  run bash "$RS_I_ENGINE" restore --resume --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$ROOT/data/postgres.partial-restore-import-test-1/import-data")" = unfinished ] || return 1
  [ "$(cat "$ROOT/data/postgres/import-data")" = complete ] || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = imported ] || return 1
  rs_import_only_postgres
}

@test "restore import: failed client diagnostics follow the timed header and all lines reach the log" {
  printf '1\n' >"$DB/import.rc"
  printf '%s\n' 'pg_restore: error: could not execute query: ERROR:  No space left on device' \
    'Command was: COPY audit_logs FROM stdin;' >"$DB/import.stderr"
  rs_import_run
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  [[ $output == *'[FAIL]  6/10  Import the database'*$'\n       pg_restore reported an error (the full message is in the log):\n       ERROR:  No space left on device' ]] || { echo "$output"; return 1; }
  [[ $output != *'Command was:'* ]] || return 1
  grep -qF 'pg_restore: error: could not execute query: ERROR:  No space left on device' "$ROOT"/logs/restore-*.log || return 1
  grep -qF 'Command was: COPY audit_logs FROM stdin;' "$ROOT"/logs/restore-*.log || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = swapped ] || return 1
  rm "$DB/import.rc"
  printf 'pg_restore: warning: example warning\n' >"$DB/import.stderr"
  run bash "$RS_I_ENGINE" restore --resume --lang en
  [ "$status" = 0 ] && [[ $output == *'pg_restore: warning: example warning'* && $output != *'No space left on device'* ]] || { echo "$output"; return 1; }
  grep -qF 'pg_restore: warning: example warning' "$ROOT"/logs/restore-*.log
}
