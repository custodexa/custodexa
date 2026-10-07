# shellcheck shell=bash
# CX_RS_EXT_* and CX_DB_* are shared with lib/restore_external.sh and the database client.
# shellcheck disable=SC2034,SC2153
# The external database after the confirmation: emptied and filled in one transaction.
#
# The SQL is made first, into files, and checked; only then is one transaction opened:
#   1. Made, with the client of the server's major and no connection to the database: clear.sql
#      (drop every non-system schema, then public again as PostgreSQL makes it), body.sql (the dump
#      without its grants) and grants.sql (only its grants; without the statements for roles the
#      server lacks when the user chose to skip them). Every maker has to end with 0.
#   2. Checked: each file ends with pg_restore's completion line, wrapped once in a matching
#      \restrict / \unrestrict pair; besides the COPY data there is no other psql meta-command and
#      no statement that ends, opens or splits a transaction or switches the session's user.
#   3. Committed: one psql, ON_ERROR_STOP, --single-transaction, the three files in order.
# Before the transaction the target's digest is measured and recorded with db_covering; when the
# result of the transaction cannot be known (psql killed, the connection lost), carrying on
# measures again: the same digest means nothing was committed (import again); the second
# checkpoint passing means it was (go on); anything else stops with both digests shown.

# The target digest: objects of the non-system schemas with their owners, each table's row count
# and the hash of its rows in primary key order (row text order without one), each sequence's state
# and every grant, sorted and hashed. One consistent read-only snapshot (the session options).
# An object without an explicit ACL (NULL) counts as its owner's default ACL (acldefault): the two
# grant the same privileges, and a restore that leaves out a grant keeps NULL where the source had
# the default written out.
CX_RS_EXT_DIGEST_SQL="WITH s AS (SELECT n.oid, n.nspname FROM pg_namespace n WHERE $CX_DBX_SYS_SCHEMAS),
rows AS (
  SELECT 'n|' || s.nspname || '|' || pg_get_userbyid(n.nspowner) AS l FROM s JOIN pg_namespace n ON n.oid = s.oid
  UNION ALL SELECT 'c|' || s.nspname || '|' || c.relname || '|' || c.relkind::text || '|' || pg_get_userbyid(c.relowner)
    FROM pg_class c JOIN s ON s.oid = c.relnamespace
  UNION ALL SELECT 'p|' || s.nspname || '|' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')|'
    || p.prokind::text || '|' || pg_get_userbyid(p.proowner) FROM pg_proc p JOIN s ON s.oid = p.pronamespace
  UNION ALL SELECT 't|' || s.nspname || '|' || t.typname || '|' || t.typtype::text || '|' || pg_get_userbyid(t.typowner)
    FROM pg_type t JOIN s ON s.oid = t.typnamespace
    WHERE t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)
  UNION ALL SELECT 'd|' || s.nspname || '|' || c.relname || '|' || (xpath('/row/h/text()', query_to_xml(format(
      'SELECT count(*) || '':'' || coalesce(md5(string_agg(md5(t::text), '''' ORDER BY %s)), '''') AS h FROM %I.%I t',
      coalesce(k.ord, 't::text'), s.nspname, c.relname), false, true, '')))[1]::text
    FROM pg_class c JOIN s ON s.oid = c.relnamespace
    LEFT JOIN LATERAL (SELECT string_agg(format('t.%I', a.attname), ', ' ORDER BY x.n) AS ord
      FROM pg_index i CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY x(attnum, n)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = x.attnum
      WHERE i.indrelid = c.oid AND i.indisprimary) k ON true
    WHERE c.relkind = 'r'
  UNION ALL SELECT 'q|' || s.nspname || '|' || c.relname || '|' || (xpath('/row/v/text()', query_to_xml(format(
      'SELECT last_value || '':'' || is_called AS v FROM %I.%I', s.nspname, c.relname), false, true, '')))[1]::text
    FROM pg_class c JOIN s ON s.oid = c.relnamespace WHERE c.relkind = 'S'
  UNION ALL SELECT 'a|' || o.kind || '|' || s.nspname || '|' || o.name || '|' || pg_get_userbyid(a.grantor) || '|'
      || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END || '|' || a.privilege_type || '|' || a.is_grantable
    FROM (SELECT 'c' AS kind, relnamespace AS ns, relname::text AS name, coalesce(relacl, CASE
          WHEN relkind = 'S' THEN acldefault('s', relowner)
          WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN acldefault('r', relowner) END) AS acl FROM pg_class
      UNION ALL SELECT 'p', pronamespace, proname || '(' || pg_get_function_identity_arguments(oid) || ')',
        coalesce(proacl, acldefault('f', proowner)) FROM pg_proc
      UNION ALL SELECT 't', typnamespace, typname::text, coalesce(typacl, acldefault('T', typowner)) FROM pg_type
      UNION ALL SELECT 'n', oid, nspname::text, coalesce(nspacl, acldefault('n', nspowner)) FROM pg_namespace) o
    JOIN s ON s.oid = o.ns CROSS JOIN LATERAL aclexplode(o.acl) a WHERE o.acl IS NOT NULL)
SELECT encode(sha256(convert_to(coalesce(string_agg(l, E'\n' ORDER BY l), ''), 'UTF8')), 'hex') AS target_digest FROM rows"

# cx_rs_ext_ready: the connection and the client of the server's major, as the checks chose them
# (the backup's settings, this host's data folder). Run inside cx_rs_ext_with.
cx_rs_ext_ready() {
  CX_RS_EXT_ITEMS=()
  cx_rs_ext_tls >/dev/null </dev/null || return 1
  cx_rs_ext_server >/dev/null </dev/null || return 1
  [ "${#CX_RS_EXT_ITEMS[@]}" -eq 0 ]
}

# cx_rs_ext_digest: the target digest, in one serializable read-only transaction.
cx_rs_ext_digest() {
  local out
  out=$(CX_DB_ACTION=sql cx_db_ext_run 1 psql -AtX -v ON_ERROR_STOP=1 \
    -d "$(cx_db_conninfo) options='-c default_transaction_read_only=on -c default_transaction_isolation=serializable'" \
    -c "$CX_RS_EXT_DIGEST_SQL" 2>>"$CX_LOG_FILE") || return 1
  [[ $out =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$out"
}

# cx_rs_ext_tool <pg_restore arguments...>: pg_restore of the
# backup's dump (mounted read-only as /in/db.dump) in the client, without a network; the SQL
# folder is /w. Its own exit code, nothing piped.
cx_rs_ext_tool() {
  local CX_DB_EXT_MOUNTS="$CX_RS_EXT_SQL:/w $CX_RS_EXT_DUMP:/in/db.dump:ro"
  local CX_DB_EXT_NAME=custodexa-restore-tool-$CX_RS_TS-sql
  CX_DB_ACTION=restore-file cx_db_ext_run 0 pg_restore "$@" </dev/null
}

# cx_rs_ext_sql_check <file>: the file is complete pg_restore output and nothing else: the
# completion line, after it only blank lines, "--" and the \unrestrict of the one \restrict that opens the
# file (the first line that is neither blank nor a comment), the same key; outside COPY data no
# other line starting with a backslash, and no statement that begins, ends or splits a transaction,
# switches the session user or connects elsewhere. Dollar-quoted bodies are not read as statements.
cx_rs_ext_sql_check() {
  LC_ALL=C awk '
  function bad(why) { printf "%s: line %d: %s\n", FILENAME, FNR, why > "/dev/stderr"; failed = 1; exit 1 }
  BEGIN { copy = 0; dq = ""; first = 1 }
  copy { if ($0 == "\\.") copy = 0; next }
  dq != "" { if (index($0, dq)) { rest = substr($0, index($0, dq) + length(dq)); dq = ""; if (rest !~ /\$[A-Za-z_]*\$/) next } else next }
  {
    if (done) {
      if ($0 ~ /^[ \t]*$/ || $0 == "--") next
      if ($0 ~ /^\\unrestrict [A-Za-z0-9]+$/ && !unr) { if (substr($0, 13) != key) bad("restrict key differs"); unr = 1; next }
      bad("text after the completion line")
    }
    if ($0 == "-- PostgreSQL database dump complete") { done = 1; next }
    if ($0 ~ /^[ \t]*$/ || $0 ~ /^--/) next
    if (first) {
      first = 0
      if ($0 !~ /^\\restrict [A-Za-z0-9]+$/) bad("does not open with \\restrict")
      key = substr($0, 11); next
    }
    if ($0 ~ /^\\/) bad("psql meta-command")
    u = toupper($0)
    if (u ~ /^[ \t]*(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|START[ \t]+TRANSACTION|END|ABORT|PREPARE[ \t]+TRANSACTION)([ \t;]|$)/) bad("transaction control")
    if (u ~ /SET[ \t]+SESSION[ \t]+AUTHORIZATION/ || u ~ /^[ \t]*(RESET|SET)[ \t]+ROLE/) bad("session user")
    if ($0 ~ /^COPY .* FROM stdin;$/) { copy = 1; next }
    # an opening dollar quote without its closing one on the same line
    line = $0
    while (match(line, /\$[A-Za-z_]*\$/)) {
      tag = substr(line, RSTART, RLENGTH); line = substr(line, RSTART + RLENGTH)
      p = index(line, tag)
      if (!p) { dq = tag; break }
      line = substr(line, p + length(tag))
    }
  }
  END {
    if (failed) exit 1
    if (!done) { printf "%s: no completion line\n", FILENAME > "/dev/stderr"; exit 1 }
    if (key == "" || !unr) { printf "%s: \\restrict without its \\unrestrict\n", FILENAME > "/dev/stderr"; exit 1 }
  }' "$1"
}

# cx_rs_ext_clear_sql: clear.sql from the non-system schemas the server has now.
cx_rs_ext_clear_sql() {
  local rows h
  rows=$(cx_dbx_rows "SELECT encode(convert_to(quote_ident(n.nspname), 'UTF8'), 'hex') AS ext_schemas
FROM pg_namespace n WHERE $CX_DBX_SYS_SCHEMAS ORDER BY 1") || return 1
  {
    while IFS= read -r h; do
      [ -n "$h" ] || continue
      [[ $h =~ ^([0-9a-f]{2})+$ ]] || return 1
      printf 'DROP SCHEMA %s CASCADE;\n' "$(cx_dbx_unhex "$h")"
    done <<<"$rows"
    printf '%s\n' 'CREATE SCHEMA public;' 'ALTER SCHEMA public OWNER TO pg_database_owner;' \
      'GRANT USAGE ON SCHEMA public TO PUBLIC;'
  } >"$CX_RS_EXT_SQL/clear.sql"
}

# cx_rs_ext_make: step 1 and 2 of the commit protocol. Returns 1 with the reason in the log; the
# database has not been touched.
cx_rs_ext_make() {
  local n f
  rm -rf -- "$CX_RS_EXT_SQL" && (umask 077 && mkdir -p "$CX_RS_EXT_SQL") || return 1
  cx_rs_ext_tool -l /in/db.dump >"$CX_RS_EXT_SQL/toc" 2>>"$CX_LOG_FILE" || { cx_log FAIL "external import: listing the dump failed"; return 1; }
  grep -v ' ACL ' "$CX_RS_EXT_SQL/toc" >"$CX_RS_EXT_SQL/body.list" || true
  grep ' ACL ' "$CX_RS_EXT_SQL/toc" >"$CX_RS_EXT_SQL/grants.list" || true
  cx_rs_ext_clear_sql || { cx_log FAIL "external import: the schema list could not be read"; return 1; }
  cx_rs_ext_tool -L /w/body.list -f /w/body.sql /in/db.dump 2>>"$CX_LOG_FILE" ||
    { cx_log FAIL "external import: making body.sql failed"; return 1; }
  : >"$CX_RS_EXT_SQL/grants.sql"
  n=$(grep -c . "$CX_RS_EXT_SQL/grants.list") || true
  if [ "$n" -gt 0 ]; then
    cx_rs_ext_tool -L /w/grants.list -f /w/grants.all.sql /in/db.dump 2>>"$CX_LOG_FILE" ||
      { cx_log FAIL "external import: making the grants failed"; return 1; }
  fi
  for f in body.sql grants.all.sql; do
    [ "$f" = body.sql ] || [ "$n" -gt 0 ] || continue
    if [ ! -s "$CX_RS_EXT_SQL/$f" ] || ! cx_rs_ext_sql_check "$CX_RS_EXT_SQL/$f" 2>>"$CX_LOG_FILE"; then
      cx_log FAIL "external import: $f is not complete pg_restore output"
      return 1
    fi
  done
  if [ "$n" -gt 0 ]; then
    # A put-back of the safety export grants as it was: CX_RS_EXT_MISSING_FILE empty.
    if [ -s "${CX_RS_EXT_MISSING_FILE-$CX_RS_DIR/missing-roles}" ]; then
      cx_rs_ext_grants_filter "$CX_RS_EXT_SQL/grants.all.sql" "$CX_RS_DIR/missing-roles" \
        "$CX_RS_EXT_SQL/grants.sql" "$CX_RS_DIR/skipped-grants.txt" >/dev/null 2>>"$CX_LOG_FILE" ||
        { cx_log FAIL "external import: the grants to the missing roles cannot be told apart"; return 1; }
      cx_rs_ext_sql_check "$CX_RS_EXT_SQL/grants.sql" 2>>"$CX_LOG_FILE" ||
        { cx_log FAIL "external import: the filtered grants are not complete"; return 1; }
    else mv -- "$CX_RS_EXT_SQL/grants.all.sql" "$CX_RS_EXT_SQL/grants.sql" || return 1; fi
  fi
  [ -s "$CX_RS_EXT_SQL/clear.sql" ] || return 1
  cx_log CHECK "external import: clear.sql, body.sql and grants.sql made and checked (grant entries=$n)"
}

# cx_rs_ext_commit: step 3. Returns 0 committed, 3 rolled back for certain (psql reported the
# error and ended the transaction), anything else when the result cannot be known.
cx_rs_ext_commit() {
  local rc=0
  local CX_DB_EXT_MOUNTS="$CX_RS_EXT_SQL:/w:ro" CX_DB_EXT_NAME=custodexa-restore-tool-$CX_RS_TS-import
  CX_DB_ACTION=import cx_db_ext_run 1 psql -X -q -v ON_ERROR_STOP=1 --single-transaction -d "$(cx_db_conninfo)" \
    -f /w/clear.sql -f /w/body.sql -f /w/grants.sql </dev/null >>"$CX_LOG_FILE" 2>&1 || rc=$?
  cx_log CHECK "external import: psql ended with $rc"
  return "$rc"
}

# cx_rs_ext_committed: the second checkpoint, without a word on screen: migrations, the three
# tables' counts and the active master key ID as in the backup.
cx_rs_ext_committed() {
  local rows digest table got
  rows=$(cx_db sql 'SELECT version FROM schema_migrations ORDER BY version' 2>>"$CX_LOG_FILE") || return 1
  rows=$(printf '%s\n' "$rows" | LC_ALL=C sort)
  digest=$(printf '%s\n' "$rows" | sha256sum)
  [ "$(printf '%s\n' "$rows" | grep -c .)" = "$(cx_rs_get db.migrations_count)" ] &&
    [ "${digest%% *}" = "$(cx_rs_get db.migrations_sha256)" ] || return 1
  for table in users sessions audit_logs; do
    got=$(cx_db sql "SELECT count(*) FROM $table" 2>>"$CX_LOG_FILE") || return 1
    [ "$got" = "$(cx_snap_get "$CX_RS_DIR/pass2/snapshot.txt" "count.$table")" ] || return 1
  done
  got=$(cx_db sql "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1" 2>>"$CX_LOG_FILE") || return 1
  [ -n "$got" ] && [ "$got" = "$(cx_rs_get kek.fingerprint)" ]
}

# cx_rs_ext_record [<state>]: the import's record, "<database> <digest before> <state>": begun
# (sent, result not known), rolled-back.
cx_rs_ext_record() {
  (umask 077; printf '%s %s %s\n' "$(cx_dbx_hex "$(cx_rs_get db.name)")" "$CX_RS_EXT_BEFORE" "$1" >"$CX_RS_DIR/external-import.tmp") &&
    sync -f "$CX_RS_DIR/external-import.tmp" && mv -- "$CX_RS_DIR/external-import.tmp" "$CX_RS_DIR/external-import" &&
    sync -f "$CX_RS_DIR"
}

# cx_rs_ext_failed <message key> [arguments]: the import step's failure line and the sentence on
# what became of the external database.
cx_rs_ext_failed() {
  cx_line FAIL " ${CX_RUN_STEP:-0}/$(cx_rs_steps_total)  $(cx_msg "$@")"
}

# cx_rs_steps_total: the number of steps the screens count to.
cx_rs_steps_total() { if [ "$CX_RS_FLOW" = new ]; then printf %s $((8 + $(cx_rs_ext_shift))); else printf 10; fi; }

# cx_rs_ext_import: the import of the external database (phase swapped -> imported).
cx_rs_ext_import() {
  local CX_RS_EXT_SQL=$CX_RS_DIR/sql CX_RS_EXT_DUMP=$CX_RS_DIR/pass2/db.dump CX_RS_EXT_BEFORE="" now rc=0
  local db h before state extra
  cx_rs_ext_with cx_rs_ext_ready || { cx_rs_ext_failed rs_ext_import_unreachable "$CX_LOG_FILE"; return 1; }
  if [ -f "$CX_RS_DIR/external-import" ]; then
    read -r h before state extra <"$CX_RS_DIR/external-import" || return 1
    [ -z "$extra" ] && [[ $before =~ ^[0-9a-f]{64}$ ]] || return 1
    if [ "$state" = begun ]; then
      # The last transaction's result was not known: the target tells.
      now=$(cx_rs_ext_with cx_rs_ext_digest) || { cx_rs_ext_failed rs_ext_import_unreachable "$CX_LOG_FILE"; return 1; }
      cx_log CHECK "external import: digest before=$before now=$now"
      if [ "$now" != "$before" ]; then
        if cx_rs_ext_with cx_rs_ext_committed; then
          cx_log CHECK "external import: the earlier transaction was committed"
          rm -rf -- "$CX_RS_EXT_SQL"
          cx_rs_phase imported
          return
        fi
        cx_rs_ext_failed rs_ext_import_unknown_stop "$before" "$now"
        return 1
      fi
      cx_log CHECK "external import: the earlier transaction was not committed; importing again"
    fi
  fi
  cx_rs_ext_with cx_rs_ext_make || { cx_rs_ext_failed rs_ext_import_make "$CX_LOG_FILE"; return 1; }
  # The last look for other connections, then nothing waits for anyone until the transaction.
  cx_rs_ext_quiet "${CX_RUN_STEP:-0}" "$(cx_rs_steps_total)" rs_ext_step_import || return 1
  CX_RS_EXT_BEFORE=$(cx_rs_ext_with cx_rs_ext_digest) || { cx_rs_ext_failed rs_ext_import_unreachable "$CX_LOG_FILE"; return 1; }
  cx_rs_ext_record begun || return 1
  if [ -z "${CX_RS_PHASE_FILE:-}" ]; then
    cx_state_set last_restore.db_covering 1 && cx_rs_save || return 1
  fi
  cx_log CHECK "external import: db_covering=1 database=$(cx_rs_get db.name) digest before=$CX_RS_EXT_BEFORE"
  cx_rs_ext_with cx_rs_ext_commit || rc=$?
  case $rc in
    0)
      rm -rf -- "$CX_RS_EXT_SQL"
      cx_rs_phase imported ;;
    3)
      cx_rs_ext_record rolled-back || return 1
      cx_rs_ext_import_failed rolled-back
      return 1 ;;
    *)
      cx_rs_ext_import_failed unknown
      return 1 ;;
  esac
}
