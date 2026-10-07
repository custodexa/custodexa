#!/usr/bin/env bats
# The external database after the confirmation: the SQL is made into files and checked first, and
# only then one transaction empties and fills the database. A maker that fails or is cut short, or
# a file that is not complete pg_restore output, opens no transaction. An error inside it rolls all
# of it back; when its result cannot be known, carrying on measures the target and imports again
# (unchanged), goes on (committed) or stops with both digests (neither).
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_ext_fixtures; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_ext_host
  backup_strict
  printf '%s\n' 'public|214' 'reports|3' >"$DB/objects"
  W=$BATS_TEST_TMPDIR/w
  rs_unpack "$(rs_fix "${RS_FIXTURE:-external}")" "$W/pass2" || return 1
  bk_state_set last_restore.phase swapped
  bk_state_set last_restore.db_covering ''
  H=$BATS_TEST_TMPDIR/import.sh
  cat >"$H" <<'SH'
#!/bin/bash
. "$1/lib/common.sh"
CX_LANG_FLAG=$4
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_FLOW=same CX_RS_TS=20261012-093015 CX_SELF=$2/custodexa.sh
CX_LOG_FILE=$3/restore.log CX_RUN_STEP=6
cx_state_load "$CX_ROOT/state.json"
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
CX_RS_ENV=$CX_RS_DIR/pass2/env.bak CX_RS_DATA=$CX_ROOT/data
rc=0
cx_rs_ext_import || rc=$?
# What the failure screen then says of the external database.
[ "$rc" = 0 ] || cx_rs_ext_failure_state || true
echo "rc=$rc phase=$(cx_state_get last_restore.phase) db_covering=$(cx_state_get last_restore.db_covering)"
SH
}
# import [language]: the import step on its own, as the stage runner calls it at phase swapped.
import() { run bash "$H" "$SRC" "$ROOT" "$W" "${1:-en}"; }
no_import() { ! grep -qx 'psql import' "$DB/events" || { cat "$DB/events"; return 1; }; }
imports() { grep -cx 'psql import' "$DB/events" || true; }
untouched() {
  [[ $output == *"rc=1 phase=swapped db_covering="$'\n'* || $output == *"rc=1 phase=swapped db_covering=" ]] || { echo "$output"; return 1; }
  no_import
}

@test "restore external import: the files are made and checked, then one transaction empties and fills the database" {
  printf '%s\n' auditor_ro >"$DB/grants.restore"
  import
  [[ $output == "rc=0 phase=imported db_covering=1" ]] || { echo "$output"; return 1; }
  [ "$(imports)" = 1 ] || return 1
  # The order: the files made (no connection), the last look for connections, the digest, the
  # transaction; nothing written to the database before it.
  [ "$(grep -E '^(pg_restore file|psql (activity|digest|import))$' "$DB/events" | uniq | paste -sd ' ')" = \
    'pg_restore file psql activity psql digest psql import' ] || { cat "$DB/events"; return 1; }
  grep -- '--entrypoint psql' "$FAKE_DOCKER_LOG" | tr '\t' ' ' | grep -- '--single-transaction' |
    grep -qE -- '-v ON_ERROR_STOP=1 --single-transaction .* -f /w/clear.sql -f /w/body.sql -f /w/grants.sql( |$)' || { grep single "$FAKE_DOCKER_LOG"; return 1; }
  # The makers ran without a network; the transaction's files were mounted read-only.
  [ "$(grep -- '--entrypoint pg_restore' "$FAKE_DOCKER_LOG" | grep -c -- ' -L ')" = 2 ] || return 1
  ! grep -- '--entrypoint pg_restore' "$FAKE_DOCKER_LOG" | grep -v -- '--network none' | grep -q . || return 1
  grep -- '--single-transaction' "$FAKE_DOCKER_LOG" | grep -q -- '/sql:/w:ro ' || return 1
  [ "$(cat "$DB/sent/clear.sql")" = 'DROP SCHEMA public CASCADE;
DROP SCHEMA reports CASCADE;
CREATE SCHEMA public;
ALTER SCHEMA public OWNER TO pg_database_owner;
GRANT USAGE ON SCHEMA public TO PUBLIC;' ] || { cat "$DB/sent/clear.sql"; return 1; }
  grep -qx '\\restrict 0f1e2d3c4b5a' "$DB/sent/body.sql" && grep -qx '\\unrestrict 0f1e2d3c4b5a' "$DB/sent/body.sql" || return 1
  [ ! -e "$W/sql" ] || return 1
  grep -q 'external import: db_covering=1 database=custodexa digest before=' "$W/restore.log" &&
    grep -q ' begun$' "$W/external-import"
}

# The fake does not run SQL: the query itself is read. An object without an ACL counts as its
# owner's default ACL, so a restore that leaves out a grant (target NULL, source written out) still
# measures the same grants; each kind of object that has an ACL gets its own default.
@test "restore external import: the target digest counts an object without an ACL as its owner's default" {
  local sql
  sql=$(. "$SRC/lib/dbext.sh"; . "$SRC/lib/restore_external_import.sh"; printf '%s' "$CX_RS_EXT_DIGEST_SQL")
  [[ $sql == *"aclexplode(o.acl)"* ]] || return 1
  [[ $sql == *"coalesce(relacl, CASE"*"WHEN relkind = 'S' THEN acldefault('s', relowner)"* ]] || return 1
  [[ $sql == *"WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN acldefault('r', relowner) END"* ]] || return 1
  [[ $sql == *"coalesce(proacl, acldefault('f', proowner))"* ]] || return 1
  [[ $sql == *"coalesce(typacl, acldefault('T', typowner))"* ]] || return 1
  [[ $sql == *"coalesce(nspacl, acldefault('n', nspowner))"* ]] || return 1
  # The digest sent to the server is that query (the log keeps its lines as they are).
  import
  grep -qx 'psql digest' "$DB/events" || { cat "$DB/events"; return 1; }
  grep -qF -- "coalesce(proacl, acldefault('f', proowner))" "$FAKE_DOCKER_LOG" || return 1
}

@test "restore external import: a maker that ends badly after a valid start, or is killed, opens no transaction" {
  local cut
  for cut in '120 1' '120 KILL' '120 TERM'; do
    printf '%s\n' "$cut" >"$DB/pg_restore.cut"
    : >"$DB/events"
    import
    untouched || { echo "cut $cut"; return 1; }
    [[ $output == *'[FAIL]  6/10  The SQL for the import could not be made or checked; no transaction'* ]] || { echo "$output"; return 1; }
  done
  rm "$DB/pg_restore.cut"
  # The grants made badly: the same.
  printf '%s\n' auditor_ro >"$DB/grants.restore"
  printf '%s\n' '60 3' >"$DB/pg_restore.cut.grants"
  : >"$DB/events"
  import
  untouched || return 1
  grep -q 'making the grants failed' "$W/restore.log"
}

@test "restore external import: output that is not complete or carries other psql commands opens no transaction" {
  local body ok='\restrict k1' end=$'--\n-- PostgreSQL database dump complete\n--\n\n\\unrestrict k1'
  for body in \
    "$ok"$'\nCREATE TABLE t (id int);\n'"${end%k1}k2" \
    "$ok"$'\nCREATE TABLE t (id int);\n'"${end%$'\n\n'*}" \
    $'CREATE TABLE t (id int);\n'"$end" \
    "$ok"$'\n\\! touch /tmp/x\n'"$end" \
    "$ok"$'\nCOMMIT;\nBEGIN;\n'"$end" \
    "$ok"$'\nSET SESSION AUTHORIZATION postgres;\n'"$end" \
    "$ok"$'\nCREATE TABLE t (id int);\n'"$end"$'\nDROP TABLE t;' \
    "$ok"$'\nCREATE TABLE t (id int);\n' \
    "$ok"$'\n'"$ok"$'\n'"$end"; do
    printf '%s\n' "$body" >"$DB/pg_restore.out"
    : >"$DB/events"
    import
    untouched || { echo "body: $body"; return 1; }
  done
  # COPY data and a dollar-quoted body may hold what elsewhere would be refused.
  printf '%s\n' "$ok" 'COPY public.t (a) FROM stdin;' '\N' 'BEGIN' '\.' \
    'CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $_$' 'BEGIN' '  NULL;' 'END' '$_$;' "$end" >"$DB/pg_restore.out"
  import
  [ "$output" = "rc=0 phase=imported db_covering=1" ] || { echo "$output"; cat "$W/restore.log"; return 1; }
}

@test "restore external import: an error in the transaction rolls all of it back; carrying on imports again" {
  echo 3 >"$DB/import.rc"
  import zh-TW
  [[ $output == *'[FAIL]  6/10  清空並匯入資料庫（同一個交易）'*'psql 回報錯誤'*'  這次的清空與匯入已整筆撤回，外接資料庫保持原狀。'* ]] || { echo "$output"; return 1; }
  [[ $output == *'rc=1 phase=swapped db_covering=1'* ]] || { echo "$output"; return 1; }
  grep -q ' rolled-back$' "$W/external-import" || return 1
  rm "$DB/import.rc"
  import
  [ "$output" = "rc=0 phase=imported db_covering=1" ] && [ "$(imports)" = 2 ] || { echo "$output"; return 1; }
}

@test "restore external import: a result not known is told by the target: unchanged imports again, committed goes on, neither stops" {
  # psql killed, nothing committed: the same digest as before, imported again.
  echo 137 >"$DB/import.rc"
  import
  [[ $output == *'Whether the import was committed cannot be told. Carrying on checks'* && $output == *'rc=1 phase=swapped db_covering=1'* ]] || { echo "$output"; return 1; }
  rm "$DB/import.rc"
  import
  [ "$output" = "rc=0 phase=imported db_covering=1" ] && [ "$(imports)" = 2 ] || { echo "$output"; return 1; }
  # The connection lost after the server committed: the second checkpoint passes, no import again.
  bk_state_set last_restore.phase swapped
  rm -f "$DB/ext.digest"
  echo 2 >"$DB/import.rc"; echo 1 >"$DB/import.commit"
  import
  [[ $output == *'rc=1 phase=swapped'* ]] || { echo "$output"; return 1; }
  rm "$DB/import.rc"
  import
  [ "$output" = "rc=0 phase=imported db_covering=1" ] && [ "$(imports)" = 3 ] || { echo "$output"; return 1; }
  grep -q 'the earlier transaction was committed' "$W/restore.log" || return 1
  # Neither: the digest moved and the checkpoint does not pass. Both digests shown, no import.
  bk_state_set last_restore.phase swapped
  rm -f "$DB/ext.digest"
  echo 2 >"$DB/import.rc"
  import
  echo changed >"$DB/ext.digest"
  echo 999 >"$DB/count.users"
  rm "$DB/import.rc"
  import
  [[ $output == *'whether the last import was'*'Before the import: '*'Now:               '*'rc=1 phase=swapped'* ]] || { echo "$output"; return 1; }
  [ "$(imports)" = 4 ]
}

@test "restore external import: grants to roles the user chose to skip are left out and listed" {
  printf '%s\n' '"report reader"' auditor_ro >"$DB/grants.restore"
  printf '%s\n' 'report reader' >"$W/missing-roles"
  import
  [ "$output" = "rc=0 phase=imported db_covering=1" ] || { echo "$output"; return 1; }
  grep -qx 'GRANT SELECT ON TABLE public.t4001 TO auditor_ro;' "$DB/sent/grants.sql" || return 1
  ! grep -q 'report reader' "$DB/sent/grants.sql" || return 1
  [ "$(cat "$W/skipped-grants.txt")" = 'GRANT SELECT ON TABLE public.t4000 TO "report reader";' ]
}
