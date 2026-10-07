#!/usr/bin/env bats
# Threat (A): a backup test passing because the fake host answered something the script never asked
# for, or because a failure switch did not fire. The fake database must refuse queries and docker
# calls it does not describe (99), and every failure switch the backup tests rely on must make its
# call fail, or the failure paths they claim to cover were never taken.

load helper
load install_host
load backup_host
load upgrade_host

setup() {
  backup_host ui
  backup_strict
}

# dk <args...>: the fake docker as the script calls it.
dk() { run docker "$@"; }

@test "fixture: each master key mode gets a .env the backend would accept; the contradiction is kept apart" {
  val() { sed -n "s/^$1=//p" "$ROOT/.env"; }
  for m in ui kms hsm; do
    bk_dotenv "$m"
    [ "$(val KEK_PROVIDER)" = "$m" ] || return 1
    ! grep -q '^ENCRYPTION_KEY=' "$ROOT/.env" || { echo "$m has a key"; return 1; }
    [ "$m" != kms ] || [ "$(val KEK_KMS_PROVIDER)" = aws ] || return 1
  done
  bk_dotenv env
  [ "$(val KEK_PROVIDER)" = env ] && [ "$(val ENCRYPTION_KEY)" = "$BK_KEK" ] || return 1
  bk_dotenv implicit
  ! grep -q '^KEK_PROVIDER' "$ROOT/.env" && [ "$(val ENCRYPTION_KEY)" = "$BK_KEK" ] || return 1
  bk_dotenv_raw KEK_PROVIDER=ui "ENCRYPTION_KEY=$BK_KEK"
  [ "$(val KEK_PROVIDER)" = ui ] && [ "$(val ENCRYPTION_KEY)" = "$BK_KEK" ] || return 1
  [ "$(stat -c %a "$ROOT/.env")" = 600 ]
}

@test "fixture: a query or a docker call the fake does not describe exits 99" {
  dk compose -p custodexa exec -T postgres psql -U postgres -d custodexa -AtX -v ON_ERROR_STOP=1 -c 'SELECT 1'
  [ "$status" -eq 99 ] || { echo "$status $output"; return 1; }
  [[ $output == *"unknown query"* ]] || return 1
  for c in "network ls" "volume rm x" "compose -p custodexa exec -T postgres vacuumdb" "compose -p custodexa down"; do
    # shellcheck disable=SC2086
    dk $c
    [ "$status" -eq 99 ] || { echo "$c: $status"; return 1; }
  done
}

@test "fixture: the queries the backup manifest needs are answered, and each can be made to fail" {
  for f in server_version server_version_num encoding size; do
    : >"$DB/events"
    case $f in
      server_version) q='SHOW server_version' want=16.15 ;;
      server_version_num) q='SHOW server_version_num' want=160015 ;;
      encoding) q="SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = current_database()" want='UTF8|en_US.utf8|en_US.utf8' ;;
      size) q='SELECT pg_database_size(current_database())' want=1073741824 ;;
    esac
    dk compose exec -T postgres psql -AtX -c "$q"
    [ "$status" -eq 0 ] && [ "$output" = "$want" ] || { echo "$f: $status $output"; return 1; }
    printf '1\n' >"$DB/$f.rc"
    dk compose exec -T postgres psql -AtX -c "$q"
    [ "$status" -eq 1 ] || { echo "$f did not fail"; return 1; }
  done
}

@test "fixture: pg_dump --version, /health and the tool container answer, and each switch makes it fail" {
  dk compose exec -T postgres pg_dump --version
  [ "$status" -eq 0 ] && [ "$output" = 'pg_dump (PostgreSQL) 16.15' ] || return 1
  printf '1\n' >"$DB/pg_dump_version.rc"
  dk compose exec -T postgres pg_dump --version
  [ "$status" -eq 1 ] || return 1
  dk compose exec -T backend wget -qO- http://localhost:8080/health
  [ "$status" -eq 0 ] && [[ $output == *'"status":"ok"'* ]] || return 1
  printf '1\n' >"$DB/health.rc"
  dk compose exec -T backend wget -qO- http://localhost:8080/health
  [ "$status" -eq 1 ] || return 1
  # The tool container: argv, -e, mounts and the name are kept; the command runs on the mapped path.
  mkdir -p "$BATS_TEST_TMPDIR/w"
  printf 'hello\n' >"$BATS_TEST_TMPDIR/w/in"
  dk run --rm -i --pull never --network none --name custodexa-backup-tool-20260930-101502-enc \
    -e TOOL_MODE=test -v "$BATS_TEST_TMPDIR/w:/work:ro" sha256:abc cat /work/in
  [ "$status" -eq 0 ] && [ "$output" = hello ] || { echo "$output"; return 1; }
  grep -qx 'custodexa-backup-tool-20260930-101502-enc' "$DB/run.names" || return 1
  grep -qx 'TOOL_MODE=test' "$DB/run.env" || return 1
  grep -qx "$BATS_TEST_TMPDIR/w:/work:ro" "$DB/run.mounts" || return 1
  grep -q -- '--name custodexa-backup-tool-20260930-101502-enc' "$DB/run.argv" || return 1
  grep -qx 'run custodexa-backup-tool-20260930-101502-enc' "$DB/events" || return 1
  printf '1\n' >"$DB/run.rc"
  dk run --rm --name x sha256:abc cat /dev/null
  [ "$status" -eq 1 ] || return 1
  dk rm -f custodexa-backup-tool-20260930-101502-enc
  [ "$status" -eq 0 ] && grep -qx 'rm rm -f custodexa-backup-tool-20260930-101502-enc' "$DB/events"
}

@test "fixture: each tar switch makes its call fail; the pack mutations break the file" {
  local w=$BATS_TEST_TMPDIR/w
  mkdir -p "$w/part" "$DB/dup"
  printf 'a\n' >"$w/part/snapshot.txt"
  printf 'b\n' >"$w/part/db.dump"
  printf 'dup\n' >"$DB/dup/snapshot.txt"
  for m in audit recordings tls; do
    printf '2\n' >"$DB/tar.$m.rc"
    run tar -czf "$w/$m.tar.gz" -C "$ROOT/data" audit
    [ "$status" -eq 2 ] || { echo "$m: $status"; return 1; }
  done
  printf '2\n' >"$DB/tar.pack.rc"
  run tar --format=gnu -cf "$w/x.tar" -C "$w/part" snapshot.txt db.dump
  [ "$status" -eq 2 ] && [ ! -e "$w/x.tar" ] || return 1
  rm "$DB/tar.pack.rc"
  : >"$DB/tar.pack.dup"
  run tar --format=gnu -cf "$w/x.tar" -C "$w/part" snapshot.txt db.dump
  [ "$status" -eq 0 ] || return 1
  [ "$(/usr/bin/tar -tf "$w/x.tar" | grep -c '^snapshot.txt$')" -eq 2 ] || return 1
  rm "$DB/tar.pack.dup" "$w/x.tar"
  : >"$DB/tar.pack.link"
  run tar --format=gnu -cf "$w/x.tar" -C "$w/part" snapshot.txt db.dump
  [ "$status" -eq 0 ] && /usr/bin/tar -tvf "$w/x.tar" | grep -q '^l.* link -> /etc/hostname$' || return 1
  rm "$DB/tar.pack.link" "$w/x.tar"
  dd if=/dev/zero of="$w/part/db.dump" bs=1k count=40 status=none
  : >"$DB/tar.pack.cut"
  run tar --format=gnu -cf "$w/x.tar" -C "$w/part" snapshot.txt db.dump
  [ "$status" -eq 0 ] && [ "$(stat -c %s "$w/x.tar")" -eq 10240 ] || return 1
  run /usr/bin/tar -tf "$w/x.tar"
  [ "$status" -ne 0 ] || return 1
  printf '2\n' >"$DB/tar.readback.rc"
  run tar -x --to-command=cat -f "$w/x.tar"
  [ "$status" -eq 2 ] && grep -qx 'tar readback' "$DB/events"
}

@test "fixture: the hash, link, state write and cleanup switches fire only where the backup needs them" {
  local p=$ROOT/backups/.partial-20260930-101502
  mkdir -p "$p"
  printf '1\n' >"$DB/sha256.rc"
  run sha256sum /dev/null
  [ "$status" -eq 0 ] || { echo "sha256sum failed before the backup file exists"; return 1; }
  : >"$p/custodexa-backup-1.13.0-20260930-101502.tar"
  run sha256sum /dev/null
  [ "$status" -eq 1 ] || return 1
  rm "$DB/sha256.rc"
  : >"$p/x.tar.sha256"
  printf '1\n' >"$DB/ln.sidecar.rc"
  run ln "$p/x.tar.sha256" "$ROOT/backups/x.tar.sha256"
  [ "$status" -eq 1 ] && [ ! -e "$ROOT/backups/x.tar.sha256" ] || return 1
  printf '1\n' >"$DB/ln.file.rc"
  run ln "$p/custodexa-backup-1.13.0-20260930-101502.tar" "$ROOT/backups/x.tar"
  [ "$status" -eq 1 ] && [ ! -e "$ROOT/backups/x.tar" ] || return 1
  # state.json: only a write that moves last_backup.file fails.
  printf '1\n' >"$DB/mv.state.rc"
  printf '{\n  "format": "2"\n}\n' >"$BATS_TEST_TMPDIR/s1"
  run mv -f "$BATS_TEST_TMPDIR/s1" "$ROOT/state.json"
  [ "$status" -eq 0 ] || return 1
  printf '{\n  "format": "2",\n  "last_backup.file": "backups/x.tar"\n}\n' >"$BATS_TEST_TMPDIR/s2"
  run mv -f "$BATS_TEST_TMPDIR/s2" "$ROOT/state.json"
  [ "$status" -eq 1 ] && ! grep -q last_backup "$ROOT/state.json" || return 1
  printf '1\n' >"$DB/rmdir.rc"
  rm -f "$p"/*
  run rmdir "$p"
  [ "$status" -eq 1 ] && [ -d "$p" ]
}

@test "fixture: a pause holds the call until the test lets it go" {
  : >"$DB/pause.start"
  docker compose start backend guacd frontend & local pid=$!
  wait_for "$DB/paused.start" || return 1
  ! grep -q '^start' "$DB/events" || { echo "went on before the go"; return 1; }
  : >"$DB/go.start"
  wait "$pid"
  grep -qx 'start backend guacd frontend' "$DB/events"
}

# ---------- an external database ----------

# dbrun <entrypoint> <args...>: a client container as the script starts one, with a pgpass file.
dbrun() {
  local e=$1
  shift
  mkdir -p "$BATS_TEST_TMPDIR/pp"
  (umask 077 && printf '*:*:*:*:%s\n' 'p\:w' >"$BATS_TEST_TMPDIR/pp/.pgpass")
  CX_DB_ACTION=${ACTION:-sql} run docker run --rm --pull never --log-driver none --entrypoint "$e" \
    -e HOME=/cx/home --tmpfs /cx/home --network host -e PGPASSFILE=/cx/pgpass \
    -v "$BATS_TEST_TMPDIR/pp/.pgpass:/cx/pgpass:ro" "${BK_PGC_ID[18]}" "$@"
}

@test "fixture: an external database deployment: overlay, recorded clients, their images on the host, the .env lines" {
  bk_external 16.4
  [ "$(jq -r '."current.overlays"' "$ROOT/state.json")" = external-database ] || return 1
  [ "$(jq -r '."current.tool_image_ids"' "$ROOT/state.json")" = "pgclient16=${BK_PGC_ID[16]} pgclient17=${BK_PGC_ID[17]} pgclient18=${BK_PGC_ID[18]}" ] || return 1
  for m in 16 17 18; do
    dk image inspect --format '{{.Id}}' "${BK_PGC_ID[$m]}"
    [ "$status" -eq 0 ] && [ "$output" = "${BK_PGC_ID[$m]}" ] || return 1
    [ "$(jq -r --arg n "pgclient$m" '.images[$n].index_digest' "$ROOT/current/MANIFEST.json")" = "${BK_PGC_DIGEST[$m]}" ] || return 1
  done
  grep -qx 'EXTERNAL_DB_HOST=db.example.internal' "$ROOT/.env" && grep -qx 'DB_SSLMODE=verify-full' "$ROOT/.env" || return 1
  [ "$(stat -c %a "$ROOT/.env")" = 600 ] || return 1
  bk_env_set DB_SSLMODE -
  ! grep -q '^DB_SSLMODE=' "$ROOT/.env" || return 1
  dbrun psql -AtX -d 'host=x' -c 'SHOW server_version_num'
  [ "$status" -eq 0 ] && [ "$output" = 160004 ] || { echo "$status $output"; return 1; }
}

@test "fixture: a client container answers from the fake database, records its image, its pgpass file; an unknown query exits 99" {
  bk_external
  dbrun psql -AtX -d 'host=x' -c 'SELECT 1'
  [ "$status" -eq 99 ] && [[ $output == *"unknown query"* ]] || { echo "$status $output"; return 1; }
  : >"$DB/db-runs"
  dbrun psql -AtX -d 'host=x' -c 'SHOW server_version'
  [ "$status" -eq 0 ] && [ "$output" = 17.6 ] || { echo "$status $output"; return 1; }
  grep -qx "sql ${BK_PGC_ID[18]} psql server_version" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  grep -qx "600 $BATS_TEST_TMPDIR/pp/.pgpass" "$DB/pgpass.seen" || { cat "$DB/pgpass.seen"; return 1; }
  grep -qxF '*:*:*:*:p\:w' "$DB/pgpass.content" || return 1
  grep -qx /cx/home "$DB/run.tmpfs" || return 1
  ACTION=dump dbrun pg_dump -Fc -d 'host=x'
  [ "$status" -eq 0 ] && [[ $output == PGDMP* ]] || return 1
  ACTION=dump-version dbrun pg_dump --version
  [ "$status" -eq 0 ] && [ "$output" = 'pg_dump (PostgreSQL) 16.15' ] || return 1
  CX_DB_ACTION=restore-list run docker run --rm -i --pull never --log-driver none --entrypoint pg_restore --network none \
    "${BK_PGC_ID[17]}" --list </dev/null
  [ "$status" -eq 0 ] && grep -qx "restore-list ${BK_PGC_ID[17]} pg_restore" "$DB/db-runs" || return 1
  # No "run" event for a client: the event order shows the database actions only.
  ! grep -q '^run ' "$DB/events" || { cat "$DB/events"; return 1; }
}

@test "fixture: each external database switch makes its call fail: unreachable, a dependency query, no system CA file" {
  bk_external
  printf '2\n' >"$DB/connect.rc"
  dbrun psql -AtX -d 'host=x' -c 'SHOW server_version_num'
  [ "$status" -eq 2 ] && [[ $output == *"Connection refused"* ]] || { echo "$status $output"; return 1; }
  dbrun pg_dump -Fc -d 'host=x'
  [ "$status" -eq 2 ] || return 1
  # Without a connection: the listing and the version still answer.
  dbrun pg_dump --version
  [ "$status" -eq 0 ] || return 1
  rm "$DB/connect.rc"
  for f in tablespaces owners extensions grants datdba; do
    case $f in
      tablespaces) q="SELECT 1 FROM pg_tablespace t" ;;
      owners) q="SELECT c.relowner FROM pg_class c" ;;
      extensions) q="SELECT extname FROM pg_extension" ;;
      grants) q="SELECT 1 FROM aclexplode(NULL)" ;;
      datdba) q="SELECT datdba FROM pg_database" ;;
    esac
    printf '%s|3\n' "$(bk_hex report_owner)" >"$DB/$f"
    dbrun psql -AtX -d 'host=x' -c "$q"
    [ "$status" -eq 0 ] && [ "$output" = "$(bk_hex report_owner)|3" ] || { echo "$f: $status $output"; return 1; }
    printf '1\n' >"$DB/$f.rc"
    dbrun psql -AtX -d 'host=x' -c "$q"
    [ "$status" -eq 1 ] || { echo "$f did not fail"; return 1; }
  done
  [ "$(bk_hex 'report reader')" = 7265706f727420726561646572 ] || return 1
  run docker run --rm --pull never --network none --log-driver none --entrypoint test "${BK_PGC_ID[17]}" -f /etc/ssl/certs/ca-certificates.crt
  [ "$status" -eq 0 ] || return 1
  printf '%s\n' "${BK_PGC_ID[17]}" >"$DB/sysca.absent"
  run docker run --rm --pull never --network none --log-driver none --entrypoint test "${BK_PGC_ID[17]}" -f /etc/ssl/certs/ca-certificates.crt
  [ "$status" -eq 1 ] || return 1
  run docker run --rm --pull never --network none --log-driver none --entrypoint test "${BK_PGC_ID[18]}" -f /etc/ssl/certs/ca-certificates.crt
  [ "$status" -eq 0 ]
}

@test "fixture: a pause holds a client container until the test lets it go" {
  bk_external
  : >"$DB/pause.db.pg_dump"
  docker run --rm --entrypoint pg_dump "${BK_PGC_ID[17]}" -Fc -d 'host=x' >/dev/null & local pid=$!
  wait_for "$DB/paused.db.pg_dump" || return 1
  ! grep -q '^pg_dump$' "$DB/events" || { echo "went on before the go"; return 1; }
  : >"$DB/go.db.pg_dump"
  wait "$pid"
  grep -qx pg_dump "$DB/events"
}

@test "fixture: the upgrade of an external database deployment from a release without clients: no PostgreSQL image here" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_external_host || return 1
  [ "$(jq -r '."current.overlays"' "$ROOT/state.json")" = external-database ] || return 1
  [ "$(jq -r 'has("current.tool_image_ids")' "$ROOT/state.json")" = false ] || return 1
  # The target release names the clients; the host has none of them and not the bundled database.
  for n in postgres pgclient16 pgclient17 pgclient18; do
    [ "$(jq -r --arg n "$n" '.images[$n].ref' "$ROOT/releases/1.13.2/MANIFEST.json")" != null ] || return 1
    for r in "${UP_IMG_REF[$n]}@$(up_digest "idx-$n")" "${UP_IMG_REF[$n]}:1.13.2" "${UP_IMG_REF[$n]}:1.13.0"; do
      dk image inspect --format '{{.Id}}' "$r"
      [ "$status" -ne 0 ] && [ -z "$output" ] || { echo "$r is on the host: $output"; return 1; }
    done
  done
  dk image inspect --format '{{.Id}}' "${UP_IMG_REF[backend]}@$(up_digest idx-backend)"
  [ "$output" = "$(up_digest cfg-backend)" ]
}

@test "fixture: two upgrades in a row: 1.13.0 to 1.13.2 done, 1.16.0 fetched" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_twice_host || return 1
  [ "$(jq -r '."current.version"' "$ROOT/state.json")" = 1.13.2 ] || return 1
  [ "$(jq -r '."previous.version"' "$ROOT/state.json")" = 1.13.0 ] || return 1
  [ "$(cat "$ROOT/releases/1.16.0/VERSION")" = 1.16.0 ]
}
