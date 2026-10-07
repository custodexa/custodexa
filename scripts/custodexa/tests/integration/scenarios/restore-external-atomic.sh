# shellcheck shell=bash
# about: the import of an external database is one transaction, against a real PostgreSQL 17 holding data: a new host's restore stopped after its database check has the target digest of the source at the backup (the script's own query), its safety export reads back in full and --revert puts the target back to the digest of the export; body.sql cut after a valid prefix, its maker sent SIGTERM and SIGKILL, the grants maker failing, a grant the filter cannot split, and an error in the middle of the import each leave the target digest unchanged (no transaction opened, or the one opened rolled back); the import's psql killed, and its session ended by the server, while it copies: --resume finds the digest of before, imports again and finishes with the backup's snapshot
# needs: package local-versions
# images: pg17

readonly XA_PORT=15447
XA_A=/opt/custodexa XA_B=/opt/b/custodexa XA_B_DATA=/opt/b/data XA_FILE="" XA_LOG_AT=0
XR_SERVER=xa17

# xa_log: the log of the restore on record on host B.
xa_log() {
  local log
  log=$(ex_st "$XA_B" last_restore.log)
  [[ $log == /* ]] || log=$XA_B/$log
  printf '%s' "$log"
}

# xa_run <label> <arguments...>: custodexa.sh on host B; XA_LOG_AT, the log's lines before it.
xa_run() {
  local label=$1
  shift
  XA_LOG_AT=0
  [ ! -f "$XA_B/state.json" ] || [ "$(ex_st "$XA_B" last_restore.result)" != in_progress ] || XA_LOG_AT=$(wc -l <"$(xa_log)")
  xr_cx "$label" "$XA_B" "$@"
}
xa_new() { # <label> [options]
  local label=$1
  shift
  xa_run "$label" restore "$XA_FILE" --new-host --yes --confirm-data-loss --data-path "$XA_B_DATA" "$@"
}
xa_since() { tail -n +"$((XA_LOG_AT + 1))" "$(xa_log)"; }
xa_logged() { xa_since | grep -qF -- "$1"; }

# xa_failed <label> <log line> <digest before> [opened]: the run failed in the import step, with that
# line in its log; without "opened" no import transaction was started; the target is unchanged.
xa_failed() {
  local label=$1 line=$2 before=$3 opened=${4:-}
  it_same "$label: exit 1" 1 "$XR_RC"
  it_check "$label: the injection happened" test -s "$IT_WORK/xr-injected"
  it_same "$label: still in progress at the import" "in_progress swapped" \
    "$(ex_st "$XA_B" last_restore.result) $(ex_st "$XA_B" last_restore.phase)"
  it_check "$label: the log says: $line" xa_logged "$line"
  if [ -z "$opened" ]; then
    it_same "$label: no import container was started (no transaction opened)" "" "$(grep -- '-import ' "$IT_WORK/xr-docker.log" || true)"
    # shellcheck disable=SC2016 # expanded by the inner shell
    it_check "$label: no psql import ran" bash -c '! grep -qF "external import: psql ended with" <<<"$1"' _ "$(xa_since)"
  fi
  xr_quiet "$XR_SERVER"
  it_same "$label: the target digest is the one before (objects, whole-table hashes, sequences, grants)" "$before" "$(xr_digest "$XR_SERVER")"
  it_same "$label: no client container is left" "" "$(docker ps -aq --filter name=custodexa-restore-tool)"
}

# xa_seen: the import wrapper saw the session copying before it acted.
xa_seen() { test -s "$IT_WORK/xr-injected" && ! grep -q never-seen "$IT_WORK/xr-injected"; }

# xa_record: the import's record on host B, "<database> <digest before> <state>".
xa_record() { cat "$(xr_rs_dir "$XA_B")/external-import" 2>/dev/null || true; }

# xa_decodes <file>: the export lists and reads back in full with pg_restore of PostgreSQL 17.
xa_decodes() {
  docker run --rm --network none -v "$1:/d.dump:ro" --entrypoint pg_restore "$(it_image pg17)" -l /d.dump >/dev/null &&
    docker run --rm --network none -v "$1:/d.dump:ro" --entrypoint pg_restore "$(it_image pg17)" -f - /d.dump | sha256sum >/dev/null &&
    [ "${PIPESTATUS[0]}" = 0 ]
}

scenario() {
  local src t0 t1 before safety rec f
  it_step "server xa17 (PostgreSQL 17) on $(ex_addr):$XA_PORT, role \"report reader\""
  ex_pg_start xa17 17 "$XA_PORT"
  ex_db_create xa17
  it_pg_sql xa17 postgres 'CREATE ROLE "report reader"'

  it_step "host A: install $XR_V on xa17; a table of DB_USER with two million rows, granted to \"report reader\""
  xr_install "$XA_A" "$XA_PORT"
  ex_db_sql xa17 "$EX_DB" "CREATE TABLE public.it_bulk (id bigint PRIMARY KEY, v text);
    INSERT INTO public.it_bulk SELECT g, md5(g::text) FROM generate_series(1, 2000000) g;
    GRANT SELECT ON public.it_bulk TO \"report reader\""

  it_step "host A stopped: the source digest by the script's own query, then the backup"
  xr_cx stop "$XA_A" stop --yes
  it_same "host A stops" 0 "$XR_RC"
  xr_lines xa17 >"$IT_WORK/source.lines"
  src=$(xr_digest xa17)
  it_same "the digest is the hash of its lines (the lines below are what it measures)" "$src" \
    "$(printf '%s' "$(cat "$IT_WORK/source.lines")" | sha256sum | cut -c1-64)"
  it_check "the source lines hold the large table and its grant" grep -q '^a|c|public|it_bulk|custodexa|report reader|SELECT|' "$IT_WORK/source.lines"
  ex_backup "$XA_A"
  mkdir -p "$IT_WORK/f"
  cp -p "$EX_FILE" "$EX_FILE.sha256" "$IT_WORK/f/"
  XA_FILE=$IT_WORK/f/${EX_FILE##*/}
  cp "$EX_X/snapshot.txt" "$IT_WORK/backup.snapshot"
  cp "$EX_MF" "$IT_WORK/backup.manifest"
  it_same "the backup is of $XR_V on PostgreSQL 17" "$XR_V 17" "$(ex_mf product.version) $(ex_mf db.server_major)"

  it_step "host A is gone; the database moves on after the backup"
  xr_gone xa17
  ex_db_sql xa17 "$EX_DB" "INSERT INTO public.it_bulk VALUES (0, 'after the backup'); CREATE TABLE public.it_after (x int)"

  it_step "host B: $XR_V unpacked, its offline bundle loaded"
  xr_new_host "$XA_B"

  it_step "normal case: host B's restore, held after the database check (the file placement fails)"
  t0=$(xr_digest xa17)
  it_check "the target holds other data than the source" test "$t0" != "$src"
  XR_INJECT=place-fail xa_new normal
  it_same "normal: exit 1 at the file placement" 1 "$XR_RC"
  it_check "normal: the injection happened" test -s "$IT_WORK/xr-injected"
  it_same "normal: in progress, database checked" "in_progress db_checked" "$(ex_st "$XA_B" last_restore.result) $(ex_st "$XA_B" last_restore.phase)"
  it_same "normal: the target digest equals the source's at the backup" "$src" "$(xr_digest xa17)"
  it_same "normal: and so every line of it" "$(cat "$IT_WORK/source.lines")" "$(xr_lines xa17)"
  it_same "normal: the safety export was made (the target was not empty)" db-dump "$(ex_st "$XA_B" last_restore.safety)"
  it_same "normal: recorded with the digest of the target before" "$t0" "$(ex_st "$XA_B" last_restore.safety_digest)"
  safety=$(ex_st "$XA_B" last_restore.safety_file)
  it_same "normal: safety-db.dump has its recorded SHA-256" "$(ex_st "$XA_B" last_restore.safety_sha256)" "$(sha256sum "$safety" | cut -c1-64)"
  it_check "normal: safety-db.dump lists and reads back in full (pg_restore 17)" xa_decodes "$safety"
  xa_run revert restore --revert --yes
  it_same "revert: exit 0" 0 "$XR_RC"
  it_same "revert: recorded reverted" reverted "$(ex_st "$XA_B" last_restore.result)"
  it_same "revert: the target digest is the one at the export" "$t0" "$(xr_digest xa17)"
  it_check "revert: safety-db.dump is removed once the digest matched" test ! -e "$safety"
  it_same "revert: host B is not installed" "" "$(ex_st "$XA_B" current.version)"

  it_step "role \"report reader\" dropped: the backup's grant to it is skipped (--accept-grant-loss)"
  it_pg_sql xa17 "$EX_DB" 'DROP OWNED BY "report reader"'
  it_pg_sql xa17 postgres 'DROP ROLE "report reader"'
  t1=$(xr_digest xa17)

  it_step "body.sql cut after a valid prefix, its maker ending with 1"
  XR_INJECT=body-prefix xa_new body-prefix --accept-grant-loss
  xa_failed body-prefix "external import: making body.sql failed" "$t1"
  it_step "body.sql's maker sent SIGTERM part way"
  XR_INJECT=body-term xa_run body-term restore --resume
  xa_failed body-term "external import: making body.sql failed" "$t1"
  it_check "body-term: killed part way (exit 143, no completion line)" grep -q 'maker exit 143; completion lines 0$' "$IT_WORK/xr-injected"
  it_step "body.sql's maker sent SIGKILL part way"
  XR_INJECT=body-kill xa_run body-kill restore --resume
  xa_failed body-kill "external import: making body.sql failed" "$t1"
  it_check "body-kill: killed part way (exit 137, no completion line)" grep -q 'maker exit 137; completion lines 0$' "$IT_WORK/xr-injected"
  it_step "the grants maker fails"
  XR_INJECT=grants-fail xa_run grants-fail restore --resume
  xa_failed grants-fail "external import: making the grants failed" "$t1"
  it_step "a grant to a missing and an existing role at once (the filter cannot split it)"
  XR_INJECT=grants-filter xa_run grants-filter restore --resume
  xa_failed grants-filter "external import: the grants to the missing roles cannot be told apart" "$t1"
  it_step "an error in the middle of the import (after the first COPY data)"
  XR_INJECT=body-error xa_run body-error restore --resume
  xa_failed body-error "external import: psql ended with 3" "$t1" opened
  it_same "body-error: the import's record says rolled back" "rolled-back" "$(xa_record | cut -d' ' -f3)"

  it_step "the import's psql killed (SIGKILL) while it copies the large table"
  XR_INJECT=import-kill xa_run import-kill restore --resume
  it_check "import-kill: the session was seen in its transaction" xa_seen
  xa_failed import-kill "external import: psql ended with 137" "$t1" opened
  rec=$(xa_record)
  it_same "import-kill: the record says begun, with the digest before" "$t1 begun" "$(cut -d' ' -f2,3 <<<"$rec")"
  it_step "--resume: the digest of before tells nothing was committed; imported again (held after the database check)"
  XR_INJECT=place-fail xa_run import-kill-resume restore --resume
  it_same "import-kill-resume: exit 1 at the file placement" 1 "$XR_RC"
  it_check "import-kill-resume: the log compares the digests" xa_logged "external import: digest before=$t1 now=$t1"
  it_check "import-kill-resume: not committed, imported again" xa_logged "external import: the earlier transaction was not committed; importing again"
  it_same "import-kill-resume: database checked" "in_progress db_checked" "$(ex_st "$XA_B" last_restore.result) $(ex_st "$XA_B" last_restore.phase)"
  it_same "the target lines are the source's but the skipped grant" "$(grep -vF '|report reader|' "$IT_WORK/source.lines")" "$(xr_lines xa17)"
  f=$(find "$(xr_rs_dir "$XA_B")" -name skipped-grants.txt | head -n1)
  it_check "skipped-grants.txt lists the grant to \"report reader\"" grep -qF '"report reader"' "$f"
  xr_mark xa17
  xa_run finish restore --resume
  it_same "finish: exit 0" 0 "$XR_RC"
  it_same "finish: recorded succeeded" succeeded "$(ex_st "$XA_B" last_restore.result)"
  lv_wait_version "$XR_V"
  xr_snap_same "finish: the snapshot (rows, migrations, keys) equals the backup's" xa17 "$XA_B" "$IT_WORK/backup.snapshot"
  it_same "finish: the active master key is the backup's" "$(jq -r '."kek.fingerprint"' "$IT_WORK/backup.manifest")" "$(ri_kek_id)"
  it_same "finish: the rows written after the backup are gone" "0 0" \
    "$(ex_db_sql xa17 "$EX_DB" "SELECT count(*) FROM public.it_bulk WHERE id = 0") $(ex_db_sql xa17 "$EX_DB" "SELECT count(*) FROM pg_tables WHERE tablename = 'it_after'")"

  it_step "host B restores the same file on its own host; the server ends the import's session while it copies"
  XR_INJECT=import-terminate xa_run terminate restore "$XA_FILE" --same-host --yes --confirm-data-loss --accept-grant-loss
  it_same "terminate: exit 1" 1 "$XR_RC"
  it_check "terminate: the session was seen in its transaction" xa_seen
  it_same "terminate: still in progress at the import" "in_progress swapped" "$(ex_st "$XA_B" last_restore.result) $(ex_st "$XA_B" last_restore.phase)"
  rec=$(xa_record)
  it_same "terminate: the result is not known, the record says begun" begun "$(cut -d' ' -f3 <<<"$rec")"
  before=$(cut -d' ' -f2 <<<"$rec")
  xr_quiet xa17
  it_same "terminate: the target digest is the one before the transaction" "$before" "$(xr_digest xa17)"
  xr_mark xa17
  xa_run terminate-resume restore --resume
  it_same "terminate-resume: exit 0" 0 "$XR_RC"
  it_check "terminate-resume: the log compares the digests" xa_logged "external import: digest before=$before now=$before"
  it_check "terminate-resume: not committed, imported again" xa_logged "external import: the earlier transaction was not committed; importing again"
  it_same "terminate-resume: recorded succeeded" succeeded "$(ex_st "$XA_B" last_restore.result)"
  lv_wait_version "$XR_V"
  xr_snap_same "terminate-resume: the snapshot equals the backup's" xa17 "$XA_B" "$IT_WORK/backup.snapshot"

  it_same "no client container is left" "" "$(docker ps -aq --filter name=custodexa-restore-tool)"
  it_same "no pgpass file is left" "" "$(find "$XA_A" "$XA_B" -name '.pgpass' 2>/dev/null | head -n1)"
  ex_teardown "$XA_B"
  rm -rf /opt/b "$XA_A"
  it_pg_stop xa17
}
