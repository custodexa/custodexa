# shellcheck shell=bash
# about: a published release (run once with CX_IT_PUBLISHED_VERSION=1.17.9 and once with 1.22.0) installed from its own package and offline bundle in the built-in form (host builtin) with a user, an asset, a session, audit rows and a table of many rows, upgraded to the working tree (PostgreSQL 18): at the end of step 8, before step 10, every table (count and md5 of all rows), every sequence and schema_migrations are equal on the old and the new database; after the upgrade schema_migrations is a superset, users, sessions and audit rows are not fewer, the four key fingerprints are the ones before, and a new backup has authz.refs=ok and usable=true; the same source in the external database form (host external) skips step 8 and creates no local data folder, an injected failure at step 11 prints rollback with no note about data that does not come back, rollback --yes returns to the published release, and rollback --revert after an unfinished way back returns to the working tree's version, the local data folder names unchanged all the way
# hosts: builtin external
# free-hosts: yes
# needs: package local-versions published
# images: pg17
#
# Run twice, once per source (two runs, each prints PASS):
#   CX_IT_LOCAL_VERSIONS=1.23.90 CX_IT_PUBLISHED_VERSION=1.17.9 CX_IT_PG_BULK_ROWS=20000 run.sh pg18-upgrade-from-published
#   CX_IT_LOCAL_VERSIONS=1.23.90 CX_IT_PUBLISHED_VERSION=1.22.0 CX_IT_PG_BULK_ROWS=20000 run.sh pg18-upgrade-from-published
# CX_IT_PG_BULK_ROWS sets the rows of the extra table (1 KiB each; default 20000, about 20 MB).

readonly PU_NEW=${CX_IT_LOCAL_VERSIONS:-1.23.90}
readonly PU_BULK_ROWS=${CX_IT_PG_BULK_ROWS:-20000}

pu_flat() { tr '\n' ' ' <<<"$LV_OUT" | tr -s ' '; }

# pu_hash <sql runner...>: one line per public table "<table> <count> <md5 of all rows>", then every
# sequence's last value. The runner takes the SQL as its last argument.
pu_hash() {
  local t
  while read -r t; do
    [ -n "$t" ] || continue
    printf '%s %s\n' "$t" "$("$@" "SELECT count(*) || ' ' || coalesce(md5(string_agg(x::text, '' ORDER BY x::text)), '-') FROM \"$t\" x" </dev/null)"
  done < <("$@" "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")
  "$@" "SELECT string_agg(sequencename || '=' || coalesce(last_value::text, 'null'), ',' ORDER BY sequencename) FROM pg_sequences"
}

pu_old_sql() { lv_sql "$1"; }

# The new cluster read by a server of the target's own image on that folder, no network, while the
# upgrade waits before step 10.
pu_new_start() {
  local ref
  ref=$(jq -r '"\(.images.postgres.ref):\(.images.postgres.tag)"' "/it-run/pkg-$PU_NEW/MANIFEST.json")
  docker run -d --name it-pgconvert-read --network none -v "$LV_ROOT/data/postgresql:/var/lib/postgresql" "$ref" >/dev/null
  lv_until "the new cluster answers" docker exec it-pgconvert-read pg_isready -q
}
pu_new_sql() {
  docker exec -i it-pgconvert-read psql -X -v ON_ERROR_STOP=1 -At -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "$1"
}
pu_new_stop() { docker rm -f it-pgconvert-read >/dev/null; }

# pu_counts: users, sessions, audit rows, one line.
pu_counts() { lv_sql "SELECT (SELECT count(*) FROM users)||' '||(SELECT count(*) FROM sessions)||' '||(SELECT count(*) FROM audit_logs)"; }
pu_migrations() { lv_sql 'SELECT version FROM schema_migrations ORDER BY version' | LC_ALL=C sort -u; }

pu_seed() {
  it_step "builtin: users, an asset, a session, audit rows (the API writes them) and a table of $PU_BULK_ROWS rows"
  lv_api POST /users "$(jq -cn '{username: "it-before-pu", password: "It-user-pass-0001", email: "it-before-pu@example.test", full_name: "Upgrade test user"}')" >/dev/null
  lv_api POST /assets "$(jq -cn '{name: "it-before-pu", protocol: "ssh", host: "192.0.2.20", port: 22, description: "upgrade test asset", tags: "it,upgrade"}')" >/dev/null
  lv_sql "INSERT INTO sessions (session_id, status, protocol, user_id, client_ip, start_time, created_at, updated_at)
    SELECT 'it-pu-session-1', 'closed', 'ssh', id, '192.0.2.9', now(), now(), now() FROM users ORDER BY id LIMIT 1" >/dev/null
  lv_sql "CREATE TABLE it_bulk AS SELECT g AS id, repeat(md5(g::text), 32) AS pad FROM generate_series(1, $PU_BULK_ROWS) g" >/dev/null
  lv_sql "ALTER TABLE it_bulk ADD PRIMARY KEY (id)" >/dev/null
  lv_sql "CREATE SEQUENCE it_seq" >/dev/null
  lv_sql "SELECT setval('it_seq', 4242)" >/dev/null
}

# pu_fp <snapshot file>: the four key fingerprints of a snapshot.txt.
pu_fp() { grep -E '^fp\.' "$1" | LC_ALL=C sort; }

scenario_builtin() {
  local r0 r0pre r8 m0 c0 hold_out log x pu_changed
  fu_install builtin
  it_same "the data folder is PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  it_say "   source release: $FU_OLD"
  pu_seed
  r0=$(pu_hash pu_old_sql)
  m0=$(pu_migrations)
  c0=$(pu_counts)
  it_say "R0 ($FU_OLD, PostgreSQL 16): counts users/sessions/audit_logs = $c0, $(grep -c . <<<"$m0") migrations"
  it_say "R0 table hashes:"
  printf '%s\n' "$r0" | sed 's/^/   R0  /'
  it_check "every table has rows to compare" test "$(grep -c . <<<"$r0")" -gt 5

  it_step "builtin: upgrade $FU_OLD -> $PU_NEW held before step 10"
  : >"$IT_WORK/docker-calls.log"
  touch "$IT_WORK/lv-hold" "$IT_WORK/mark"
  LV_INJECT=hold-up lv_bg up1 upgrade "$(it_package_file "$PU_NEW")" --images "$(it_bundle_file "$PU_NEW")" --yes
  lv_until "the upgrade reaches step 10" test -e "$IT_WORK/lv-up-reached"
  it_same "step 8 recorded as done" done "$(lv_st last_upgrade.db_convert.result)"
  # R0 is the old database as it is when the conversion has read it: the services are stopped, the
  # old server still runs. What the services wrote while they were being stopped (audit rows, the
  # chain's state) is the only difference from the hash taken before the upgrade started.
  r0pre=$r0
  r0=$(pu_hash pu_old_sql)
  m0=$(pu_migrations)
  c0=$(pu_counts)
  it_say "R0 at the end of step 8 ($FU_OLD, services stopped): counts users/sessions/audit_logs = $c0"
  pu_changed=$(diff <(printf '%s\n' "$r0pre") <(printf '%s\n' "$r0") | sed -n 's/^> \([a-z_]*\) .*/\1/p' | sort -u | paste -sd' ' - || true)
  it_say "   tables that changed between the hash before the upgrade and the old database at step 8: ${pu_changed:-none}"
  it_check "only the audit tables changed in between" \
    test -z "$(tr ' ' '\n' <<<"$pu_changed" | grep -vxE -e '' -e audit_logs -e audit_chain_verify_states || true)"
  pu_new_start
  r8=$(pu_hash pu_new_sql)
  it_say "R8 (new database, end of step 8, PostgreSQL 18) table hashes:"
  printf '%s\n' "$r8" | sed 's/^/   R8  /'
  it_same "R8 equals R0: every table (count and md5 of all rows), every sequence" "$r0" "$r8"
  it_same "R8: schema_migrations equals R0" "$m0" "$(pu_new_sql 'SELECT version FROM schema_migrations ORDER BY version' | LC_ALL=C sort -u)"
  it_same "R8: data_checksums on" on "$(pu_new_sql 'SHOW data_checksums')"
  pu_new_stop
  rm -f "$IT_WORK/lv-hold"
  LV_RC=0
  wait "$LV_PID" || LV_RC=$?
  hold_out=$(cat "$IT_WORK/up1.out")
  printf '%s\n' "$hold_out" | sed 's/^/   up1> /'
  it_same "the upgrade exits 0" 0 "$LV_RC"
  lv_wait_version "$PU_NEW"
  # shellcheck disable=SC2034 # read by lv_api: sign in again on the version now running
  LV_TOKEN=""
  it_same "the old data folder is still PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"

  it_step "builtin: R1, after the upgrade"
  it_same "R1: the server is PostgreSQL 18 with checksums on" "18 on" "$(lv_sql "SELECT substr(current_setting('server_version_num'), 1, 2)")"' '"$(lv_sql 'SHOW data_checksums')"
  it_say "R1 ($PU_NEW): counts = $(pu_counts), $(pu_migrations | grep -c .) migrations; added: $(LC_ALL=C comm -13 <(printf '%s\n' "$m0") <(pu_migrations) | paste -sd' ' -)"
  it_check "R1: schema_migrations is a superset of R0" test -z "$(LC_ALL=C comm -23 <(printf '%s\n' "$m0") <(pu_migrations))"
  it_check "R1: users, sessions and audit rows are not fewer than R0 ($c0 -> $(pu_counts))" \
    bash -c 'read -r u0 s0 a0 <<<"$1"; read -r u1 s1 a1 <<<"$2"; [ "$u1" -ge "$u0" ] && [ "$s1" -ge "$s0" ] && [ "$a1" -ge "$a0" ]' _ "$c0" "$(pu_counts)"
  it_same "R1: the extra table is still whole" "$PU_BULK_ROWS" "$(lv_sql 'SELECT count(*) FROM it_bulk')"
  log=$(find "$LV_ROOT/logs" -name 'upgrade-*.log' -newer "$IT_WORK/mark" | sort | tail -n 1)
  it_check "the upgrade's own check passed the keys (the four fingerprints equal)" bash -c '! grep -E "FAIL" <<<"$1"' _ "$hold_out"
  it_step "builtin: a backup after the upgrade"
  touch "$IT_WORK/mark2"
  sleep 1
  lv_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  x=$IT_WORK/after-backup.x
  rm -rf "$x"
  mkdir -p "$x"
  tar -xf "$(find "$LV_ROOT/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark2" | head -n1)" -C "$x"
  it_same "the backup is data of $PU_NEW" "$PU_NEW" "$(jq -r '."product.version"' "$x/backup-manifest.json")"
  it_same "its snapshot: authz.refs" ok "$(sed -n 's/^authz\.refs=//p' "$x/snapshot.txt")"
  it_same "its snapshot: usable" true "$(sed -n 's/^usable=//p' "$x/snapshot.txt")"
  it_same "the four fingerprints are those taken before the upgrade" "$(pu_fp "${log%.log}.before.txt")" "$(pu_fp "$x/snapshot.txt")"
  lv_cx status status
  it_same "status reports no failure" 0 "$(grep -c '\[FAIL\]' <<<"$LV_OUT" || true)"
}

# ---- the external database form ----

pu_data_names() { (cd "$LV_ROOT" && ls -1A data 2>/dev/null | paste -sd' ' -); }

scenario_external() {
  local names0 data0 ident
  fu_install extdb
  it_say "   source release: $FU_OLD"
  fu_sentinel 1
  data0=$(pu_data_names)
  ident=$(fu_identity)
  it_step "external: upgrade $FU_OLD -> $PU_NEW (step 8 is a SKIP)"
  lv_upgrade "$PU_NEW"
  it_check "step 8 is shown as SKIP" grep -Eq '\[SKIP\] +8/13' <<<"$LV_OUT"
  lv_wait_version "$PU_NEW"
  LV_TOKEN=""
  it_same "the server's identity is the same" "$ident" "$(fu_identity)"
  it_same "the local data folder names are unchanged" "$data0" "$(pu_data_names)"
  it_check "no built-in database folder was made" bash -c '[ ! -e "$1/data/postgres" ] && [ ! -e "$1/data/postgresql" ]' _ "$LV_ROOT"
  it_same "the sentinel is readable" "1 it-sentinel-1" "$(fu_sentinels)"

  # A release before 1.22 has fewer migrations than the working tree: step 10 of any upgrade from it
  # applies them, so there is no way straight back to it (rollback says so and gives the restore).
  if [ "$(printf '%s\n%s\n' 1.22.0 "$FU_OLD" | sort -V | head -n1)" != 1.22.0 ]; then
    it_say "   the way-back rounds are for a source of 1.22.0 or later; $FU_OLD has fewer migrations, so rollback is refused after the upgrade (restore is the way back)"
    it_step "external: rollback is refused, with the restore of the upgrade's backup"
    lv_cx rollback rollback --yes
    it_same "rollback exits 3" 3 "$LV_RC"
    it_check "the screen gives the restore command of the upgrade's backup" grep -q 'custodexa.sh restore .*custodexa-backup-' <<<"$LV_OUT"
    return 0
  fi
  it_step "external: way back to $FU_OLD"
  lv_cx rollback rollback --yes
  it_same "rollback exits 0" 0 "$LV_RC"
  lv_wait_version "$FU_OLD"
  LV_TOKEN=""
  it_same "the local data folder names are unchanged" "$data0" "$(pu_data_names)"

  it_step "external: upgrade again, failing at step 11 (injected)"
  LV_INJECT=health-fail LV_READY_TRIES=2 lv_upgrade "$PU_NEW" 1
  it_check "the failure is at step 11" grep -q 'step 11/13' <<<"$LV_OUT"
  it_check "the screen offers rollback" grep -q 'custodexa.sh rollback' <<<"$LV_OUT"
  it_check "the screen has no note about data that does not come back" \
    bash -c '! grep -qiE "not in the database|after going back" <<<"$1"' _ "$LV_OUT"
  it_same "the local data folder names are unchanged" "$data0" "$(pu_data_names)"
  lv_cx rollback rollback --yes
  it_same "rollback --yes exits 0" 0 "$LV_RC"
  lv_wait_version "$FU_OLD"
  LV_TOKEN=""
  it_same "the sentinel is readable on $FU_OLD" "1 it-sentinel-1" "$(fu_sentinels)"

  it_step "external: an unfinished way back, then --revert"
  lv_upgrade "$PU_NEW"
  lv_wait_version "$PU_NEW"
  LV_TOKEN=""
  LV_INJECT=health-fail LV_READY_TRIES=2 lv_cx rollback rollback --yes
  it_check "the injected rollback did not succeed (exit $LV_RC)" test "$LV_RC" != 0
  it_same "the record is a rollback that is not finished" "in_progress rollback" \
    "$(lv_st last_rollback.result) $(lv_st last_rollback.direction)"
  LV_SCRIPT="$LV_ROOT/releases/$PU_NEW/custodexa.sh" lv_cx revert rollback --revert --yes
  it_same "rollback --revert exits 0" 0 "$LV_RC"
  lv_wait_version "$PU_NEW"
  LV_TOKEN=""
  it_same "the sentinel is readable on $PU_NEW" "1 it-sentinel-1" "$(fu_sentinels)"
  it_same "the local data folder names are unchanged all the way" "$data0" "$(pu_data_names)"
  it_same "the server's identity is the same" "$ident" "$(fu_identity)"
}
