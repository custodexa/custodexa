#!/usr/bin/env bats
# A backup of an external database deployment, checked before anything stops: the client of the
# server's major, the connection rebuilt from the backup (never another server), ownership,
# extensions, encoding, other connections (refused on a new host, listed on this one), the roles
# the backup grants rights to, the CA file and the client certificate. Each refusal changes
# nothing: no service stopped, no file placed, no database query that writes.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_ext_fixtures; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_ext_host
  rs_preflight_only
  backup_strict
  NEWDATA=$BATS_TEST_TMPDIR/newdata
}
same() { run bash "$ROOT/custodexa.sh" restore "$(rs_fix "$1")" --same-host --yes --confirm-data-loss --lang "${2:-en}" </dev/null; }
new() {
  local f=$1
  shift
  rs_new_host
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix "$f")" --new-host --yes --data-path "$NEWDATA" --lang en "$@" </dev/null
}
no_stop() { ! grep -Eq '^(stop|start|up|create|curl)( |$)' "$DB/events"; }
# unconfirmed <fixture> [options]: on a new host without --yes the checks pass and the restore ends
# at the confirmation, before anything is placed.
unconfirmed() {
  local f=$1
  shift
  rs_new_host
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix "$f")" --new-host --data-path "$NEWDATA" --lang en "$@" </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'Without a terminal, use --yes to confirm the restore.'* ]] &&
    [[ $output != *"cannot be restored yet"* && $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  no_stop
}
reached_end() { [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }; no_stop; }
refused() { [ "$status" -eq 3 ] && [[ $output == *"[FAIL] The external database cannot be restored yet, because:"* ]] &&
  [[ $output == *"Nothing has been changed."* ]] || { echo "$output"; return 1; }; no_stop; }
# Only SELECT and SHOW reach the external database before anything stops.
read_only() { ! grep -E -- '-c ' "$DB/run.argv" | grep -viE -- "-c '?(SELECT|SHOW|WITH)" | grep -q .; }

@test "restore external: on this host the checks pass with its own backend connected; the client of the server's major asks" {
  printf '%s\n' '10.0.0.12 custodexa-backend' >"$DB/activity"
  same external
  reached_end || return 1
  [[ $output != *"cannot be restored yet"* ]] || return 1
  grep -q "psql activity" "$DB/events" || return 1
  grep -q "${BK_PGC_ID[17]} psql activity" "$DB/db-runs" || return 1
  grep -q 'external database other connections=1' "$ROOT"/logs/restore-*.log || return 1
  # The safety backup's estimate asks the external database too, never a bundled one.
  ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG" || { grep 'exec -T postgres' "$FAKE_DOCKER_LOG"; return 1; }
  grep -q 'pg_database_size' "$DB/run.argv" || return 1
  read_only
}

@test "restore external: on a new host another connection refuses before anything stops, naming its sources and applications" {
  printf '%s\n' '10.0.0.12 custodexa-backend' '10.0.0.12 custodexa-backend' '10.0.0.13 psql' >"$DB/activity"
  new external
  refused || return 1
  [[ $output == *"  - 3 other connections are using custodexa (from 10.0.0.12, 10.0.0.13, application"$'\n'"    custodexa-backend, psql). Stop the services on the original host first,"$'\n'"    and make sure no standby host has taken this database over."* ]] || { echo "$output"; return 1; }
  [ ! -e "$NEWDATA" ] || [ -z "$(ls -A "$NEWDATA")" ] || return 1
  [ "$(jq -r '."current.version" // ""' "$ROOT/state.json")" = "" ] || return 1
  printf '%s\n' '- psql' >"$DB/activity"
  new external
  refused || return 1
  [[ $output == *"1 other connection is using custodexa (from a local socket, application"$'\n'"    psql)."* ]] || { echo "$output"; return 1; }
  rm "$DB/activity"
  new external
  reached_end
}

@test "restore external: a server with no client of this release (15, 19) refuses, naming the clients there are" {
  local v
  for v in 15.8 19.1; do
    bk_server "$v"
    same external
    refused || return 1
    [[ $output == *"The server runs PostgreSQL $v, which has no client here; this"$'\n'"    release carries clients for PostgreSQL 16, 17 and 18."* ]] || { echo "$output"; return 1; }
  done
}

@test "restore external: a server older than the backup's refuses; a newer one is asked with its own client" {
  bk_server 16.4
  same external
  refused || return 1
  [[ $output == *"The server runs PostgreSQL 16.4, older than the PostgreSQL 17 the"* ]] || return 1
  bk_server 18.2
  : >"$DB/db-runs"
  same ext16
  reached_end || return 1
  grep -q "${BK_PGC_ID[18]} psql activity" "$DB/db-runs"
}

@test "restore external: owner, objects of another role, extensions and encoding are all named in one refusal" {
  printf 'f\n' >"$DB/datdba"
  printf 'public|report_cache|analyst\nreports||analyst\n' >"$DB/foreign"
  printf '%s\n' 'postgis 3.4.2' 'pg_trgm 1.6' >"$DB/extensions"
  printf '%s\n' 'SQL_ASCII|C|C' >"$DB/encoding"
  same external
  refused || return 1
  [[ $output == *"  - custodexa_app does not own the database custodexa; rebuilding schema public needs"* ]] || return 1
  [[ $output == *"  - The object public.report_cache is owned by analyst, not custodexa_app;"$'\n'"    the script can only empty objects that custodexa_app owns."* ]] || return 1
  [[ $output == *"  - The object reports is owned by analyst, not custodexa_app;"* ]] || return 1
  [[ $output == *"(postgis 3.4.2, pg_trgm 1.6)"* ]] || return 1
  [[ $output == *"ENCODING 'UTF8' LC_COLLATE 'en_US.utf8' LC_CTYPE 'en_US.utf8'"* ]] || return 1
  [ "$(printf '%s\n' "$output" | grep -c '^  - ')" = 5 ] || { echo "$output"; return 1; }
  read_only
}

@test "restore external: the refusal reads the same in zh-TW and ja" {
  printf 'public|report_cache|analyst\n' >"$DB/foreign"
  printf '%s\n' '10.0.0.12 custodexa-backend' '10.0.0.12 custodexa-backend' >"$DB/activity"
  rs_new_host
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix external)" --new-host --yes --data-path "$NEWDATA" --lang zh-TW </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 外接資料庫還不能還原，原因："$'\n'"  - 有 2 個其他連線正在使用 custodexa（來自 10.0.0.12，應用程式 custodexa-backend）。"$'\n'"    請先停止原主機的服務，並確認沒有備援主機接手這個資料庫。"$'\n'"  - 物件 public.report_cache 的擁有者是 analyst，不是 custodexa_app；"$'\n'"    腳本只能清空 custodexa_app 擁有的物件。"$'\n'"沒有變更任何資料。"* ]] || { echo "$output"; return 1; }
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix external)" --new-host --yes --data-path "$NEWDATA" --lang ja </dev/null
  [ "$status" -eq 3 ] && [[ $output == *"外部データベースはまだ復元できません。理由："* && $output == *"オブジェクト public.report_cache の所有者は analyst"* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore external: the TLS settings of the backup are rebuilt; a weaker server check than recorded refuses" {
  rs_derive external extweak 'sed -i "s/^DB_SSLMODE=.*/DB_SSLMODE=require/" env.bak' || return 1
  same extweak
  refused || return 1
  [[ $output == *"The server certificate would be checked less than when the backup"$'\n'"    was taken (now none/none, at the backup full/system)."* ]] || { echo "$output"; return 1; }
  ! grep -q 'psql' "$DB/events"
}

@test "restore external: the backup's CA file is what the client checks the server with; a different file at its place refuses" {
  local dest=$NEWDATA/exports/db/ca.pem u=$BATS_TEST_TMPDIR/u
  rs_unpack "$(rs_fix extca)" "$u" || return 1
  # The checks only mount it: without the confirmation nothing is placed.
  unconfirmed extca
  grep -Eq "/restore/[^ ]*/pass2/db-ca.pem:/cx/tls/root.crt:ro" "$DB/run.mounts" || { cat "$DB/run.mounts"; return 1; }
  [ ! -e "$dest" ] || return 1
  # Once confirmed, the backup's file is where the settings name it.
  new extca
  reached_end || return 1
  cmp "$u/db-ca.pem" "$dest" || return 1
  printf 'another CA\n' >"$dest"
  : >"$DB/events"
  new extca
  refused || return 1
  [[ $output == *"The CA file goes to $dest, where a file with other"* ]] || { echo "$output"; return 1; }
  ! grep -q psql "$DB/events" || return 1
  [ "$(cat "$dest")" = 'another CA' ] || return 1
  cp "$u/db-ca.pem" "$dest"
  new extca
  reached_end
}

@test "restore external: a client certificate is needed: without the files refused; given, they are mounted, the key copied nowhere" {
  local c=$BATS_TEST_TMPDIR/given/client.crt k=$BATS_TEST_TMPDIR/given/client.key
  new extcert
  refused || return 1
  [[ $output == *"--db-client-cert and"$'\n'"    --db-client-key."* ]] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | grep -c '^  - ')" = 1 ] || return 1
  new extcert --db-client-cert "$BATS_TEST_TMPDIR/nothing.crt" --db-client-key "$k"
  refused || return 1
  [[ $output == *"$BATS_TEST_TMPDIR/nothing.crt cannot be read."* ]] || return 1
  mkdir -p "${c%/*}"
  printf 'client certificate\n' >"$c"
  printf 'rs-test-client-key-0006\n' >"$k"
  chmod 600 "$k"
  # The checks mount the given files and copy the key nowhere.
  unconfirmed extcert --db-client-cert "$c" --db-client-key "$k"
  grep -qx "$c:/cx/tls/client.crt:ro" "$DB/run.mounts" && grep -qx "$k:/cx/tls/client.key:ro" "$DB/run.mounts" || { cat "$DB/run.mounts"; return 1; }
  ! grep -rqa 'rs-test-client-key-0006' "$ROOT" "$NEWDATA" 2>/dev/null || { echo "the key was copied"; return 1; }
  # Once confirmed, the key is only where the settings name it (0600), never in the work folder
  # or the log.
  new extcert --db-client-cert "$c" --db-client-key "$k"
  reached_end || return 1
  [ "$(grep -rlaF 'rs-test-client-key-0006' "$ROOT" "$NEWDATA" 2>/dev/null)" = "$NEWDATA/exports/db/client.key" ] ||
    { grep -rlaF 'rs-test-client-key-0006' "$ROOT" "$NEWDATA"; return 1; }
  [ "$(stat -c %a "$NEWDATA/exports/db/client.key")" = 600 ] && cmp "$c" "$NEWDATA/exports/db/client.crt"
}

@test "restore external: on this host the certificate and key already in place are used without asking" {
  mkdir -p "$ROOT/data/exports/db"
  printf 'client certificate\n' >"$ROOT/data/exports/db/client.crt"
  printf 'rs-test-client-key-0007\n' >"$ROOT/data/exports/db/client.key"
  chmod 600 "$ROOT/data/exports/db/client.key"
  same extcert
  reached_end || return 1
  grep -qx "$ROOT/data/exports/db/client.key:/cx/tls/client.key:ro" "$DB/run.mounts"
}

@test "restore external: roles the backup grants rights to and the server lacks refuse, from the backup's list and the dump" {
  printf '%s\n' auditor_ro >"$DB/roles"
  same extgrants
  [ "$status" -eq 3 ] && no_stop || { echo "$output"; return 1; }
  [[ $output == *'[FAIL] The target database server lacks 1 role the backup grants rights'$'\n''       to: "report reader".'* ]] || { echo "$output"; return 1; }
  printf '%s\n' '"report reader"' 'x_dump_role' >"$DB/grants.restore"
  printf '%s\n' auditor_ro 'report reader' >"$DB/roles"
  same extgrants
  [ "$status" -eq 3 ] && [[ $output == *'lacks 1 role the'*'to: x_dump_role.'* ]] || { echo "$output"; return 1; }
  printf '%s\n' auditor_ro 'report reader' x_dump_role >"$DB/roles"
  same extgrants
  reached_end
}

@test "restore external: the grants of a dump name their roles exactly, quoted or not" {
  local g=$BATS_TEST_TMPDIR/grants
  cat >"$g" <<'SQL'
GRANT SELECT ON TABLE public."a TO b" TO "report reader";
GRANT ALL ON SCHEMA public TO custodexa_app, "x, ""y""" WITH GRANT OPTION GRANTED BY "grantor one";
REVOKE ALL ON TABLE public.t FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE custodexa_app IN SCHEMA public GRANT SELECT ON TABLES TO auditor_ro;
SET search_path = public;
SQL
  run bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/cmd_restore.sh"; cx_rs_ext_grantees "$2"' _ "$SRC" "$g"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$output" = 'report reader
grantor one
custodexa_app
x, "y"
PUBLIC
custodexa_app
auditor_ro' ] || { echo "$output"; return 1; }
}

@test "restore external: the connection is the backup's: a leftover .env of this host names no other server" {
  printf '%s\n' 'EXTERNAL_DB_HOST=db.other.internal' 'DB_NAME=other' >"$ROOT/.env"
  new external
  reached_end || return 1
  grep -q "host='db.example.internal' port='5432' dbname='custodexa' user='custodexa_app' sslmode='verify-full'" "$DB/run.argv" || { cat "$DB/run.argv"; return 1; }
  ! grep -q 'db.other.internal' "$DB/run.argv"
}

@test "restore external: an unreachable server refuses with the log named; nothing stops" {
  printf '2\n' >"$DB/connect.rc"
  same external
  refused || return 1
  [[ $output == *"Cannot reach the external database db.example.internal:5432, or the login failed;"* ]] || { echo "$output"; return 1; }
  grep -q 'connection to server' "$ROOT"/logs/restore-*.log
}

@test "restore external: without the client images on this host the restore refuses and names the release" {
  grep -v ":${BK_PGC_TAG[18]} " "$DB/images.ref" >"$DB/images.new"
  mv "$DB/images.new" "$DB/images.ref"
  same external
  refused || return 1
  [[ $output == *"This host does not have the PostgreSQL 18 client image (shipped"$'\n'"    with 1.16.0)"* ]] || { echo "$output"; return 1; }
}

@test "restore external: a client is the release's by its pull digest or by the ID load or install recorded; a tag alone is not" {
  # A new host that loaded the offline bundle: the IDs load recorded (rs_ext_host).
  new external
  reached_end || return 1
  grep -q "${BK_PGC_ID[17]} psql activity" "$DB/db-runs" || return 1
  # The same tags without what load recorded: content nobody checked.
  rs_ext_host
  rs_preflight_only
  jq 'del(."load.version", ."load.image_ids")' "$ROOT/state.json" >"$ROOT/state.json.new"
  mv "$ROOT/state.json.new" "$ROOT/state.json"
  new external
  refused || return 1
  [[ $output == *"This host does not have the PostgreSQL 18 client image"* ]] || { echo "$output"; return 1; }
  # Load recorded another content for the tag than the one there now.
  rs_ext_host
  rs_preflight_only
  bk_state_set load.image_ids "pgclient16=${BK_PGC_ID[16]} pgclient17=${BK_PGC_ID[18]} pgclient18=${BK_PGC_ID[17]}"
  new external
  refused || return 1
  # This host's own install recorded them (no load): the same host goes on.
  rs_ext_host
  rs_preflight_only
  jq 'del(."load.version", ."load.image_ids")' "$ROOT/state.json" >"$ROOT/state.json.new"
  mv "$ROOT/state.json.new" "$ROOT/state.json"
  : >"$DB/db-runs"
  same external
  reached_end || return 1
  grep -q "${BK_PGC_ID[17]} psql activity" "$DB/db-runs" || return 1
  # Pulled by the release's index digest: that digest is the ID, nothing recorded needed.
  rs_ext_host
  rs_preflight_only
  rs_ext_pulled
  : >"$DB/db-runs"
  new external
  reached_end || return 1
  grep -q "${BK_PGC_DIGEST[17]} psql activity" "$DB/db-runs"
}

@test "restore external: after the stop another connection stops the restore at its step, with carry on and give up" {
  local w=$BATS_TEST_TMPDIR/w h=$BATS_TEST_TMPDIR/quiet.sh
  rs_unpack "$(rs_fix external)" "$w/pass2" || return 1
  cat >"$h" <<'SH'
#!/bin/bash
. "$1/lib/common.sh"
CX_LANG_FLAG=$4
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_FLOW=same CX_RS_TS=20261012-093015 CX_SELF=$2/custodexa.sh
cx_state_load "$CX_ROOT/state.json"
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
CX_RS_ENV=$CX_RS_DIR/pass2/env.bak CX_RS_DATA=$CX_ROOT/data
rc=0
cx_rs_ext_quiet 2 10 rs_ext_step_stop || rc=$?
echo "rc=$rc"
SH
  printf '%s\n' '10.0.0.45 psql' >"$DB/activity"
  run bash "$h" "$SRC" "$ROOT" "$w" zh-TW
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == "[FAIL]  2/10  停止服務（外接資料庫不受影響）：停止之後，仍有 1 個其他連線"$'\n'"              在使用 custodexa（來自 10.0.0.45，應用程式 psql）。"$'\n'"還原停在第 2 步。還沒有覆蓋任何資料；服務維持停止。"$'\n'"  請找出並結束這個連線（確認不是備援主機接手），再重跑接續："$'\n'"    sudo "*"custodexa.sh restore --resume"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  或放棄還原、啟動原本的服務："$'\n'"    sudo "*"custodexa.sh restore --revert"* && $output == *"rc=1" ]] || { echo "$output"; return 1; }
  run bash "$h" "$SRC" "$ROOT" "$w" en
  [[ $output == "[FAIL]  2/10  Stop the services (the external database is not affected):"$'\n'"              once they stopped, 1 other connection is still using"$'\n'"              custodexa (from 10.0.0.45, application psql)."$'\n'"The restore stopped at step 2. Nothing has been overwritten; the"* ]] || { echo "$output"; return 1; }
  rm "$DB/activity"
  run bash "$h" "$SRC" "$ROOT" "$w" en
  [ "$status" -eq 0 ] && [ "$output" = "rc=0" ] || { echo "$output"; return 1; }
  no_stop
}
