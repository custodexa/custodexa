# A package deployment for the backup, upgrade and rollback tests, with a fake database behind
# `docker compose exec -T postgres ...`. Needs helper.bash and install_host.bash loaded.
#   $DB/<name>      what psql prints for a query (size, count.users, count.sessions, count.active,
#                   count.audit_logs, migrations, kek, export, checkpoint); <name>.rc makes it fail
#   $DB/pg_dump.rc, $DB/pg_restore.rc, $DB/stop.rc, $DB/start.rc   make that call fail
#   $DB/du.<path with / as ->   bytes du reports for that path (else the real du)
#   $DB/events      the order of what happened: stop, start, pg_dump, pg_restore, tar -czf <file>...

# backup_host [KEK_PROVIDER]: $ROOT laid out as an installed 1.13.0 package deployment.
backup_host() {
  local kek=${1:-ui}
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  printf '1.13.0\n' >"$ROOT/releases/1.13.0/VERSION"
  use_fake_docker
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  export PATH="$FAKES:$PATH"
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
  export DB=$BATS_TEST_TMPDIR/db
  mkdir -p "$DB"
  : >"$DB/events"
  printf '{\n  "format": "2",\n  "compose_project": "custodexa",\n  "current.version": "1.13.0",\n  "current.overlays": "",\n  "install.result": "succeeded"\n}\n' >"$ROOT/state.json"
  # Test values only; they stand for secrets so the tests can look for them in logs and files.
  BK_JWT=jwt-test-value-for-masking-0001
  BK_KEK=kek-test-value-for-masking-0002
  BK_DBPW=dbpw-test-value-for-masking-03
  (
    umask 077
    printf '%s\n' "DATA_PATH=./data" "DB_USER=postgres" "DB_PASSWORD=$BK_DBPW" "DB_NAME=custodexa" \
      "JWT_SECRET=$BK_JWT" "KEK_PROVIDER=$kek" "ENCRYPTION_KEY=$BK_KEK" \
      "PUBLIC_BASE_URL=https://10.0.0.12" >"$ROOT/.env"
  )
  mkdir -p "$ROOT/data/recordings/2026" "$ROOT/data/audit" "$ROOT/data/exports" "$ROOT/tls"
  printf 'rec\n' >"$ROOT/data/recordings/2026/a.cast"
  printf 'audit\n' >"$ROOT/data/audit/fallback.log"
  printf 'plaintext evidence\n' >"$ROOT/data/exports/evidence.zip"
  printf 'cert\n' >"$ROOT/tls/server.crt"
  db_default
  write_db_hook
  fake tar 'case "$1" in -czf|-tzf) printf "tar %s %s\n" "$1" "${2##*/}" >>'"$DB"'/events ;; esac; exec /usr/bin/tar "$@"'
  fake du 'p=${@: -1}; k=$(printf "%s" "$p" | tr / -); if [ -e '"$DB"'/du.$k ]; then printf "%s\t%s\n" "$(cat '"$DB"'/du.$k)" "$p"; else exec /usr/bin/du "$@"; fi'
  host_free / 221249536 # 211 GB in KiB
}

# db_default: a database with users, sessions, audit rows, two migrations and one key of each kind.
db_default() {
  printf '%s\n' 5 >"$DB/count.users"
  printf '%s\n' 42 >"$DB/count.sessions"
  printf '%s\n' 2 >"$DB/count.active"
  printf '%s\n' 1234 >"$DB/count.audit_logs"
  printf '%s\n' 20260816_schema_baseline 20260901_add_x >"$DB/migrations"
  printf '%s\n' 5a5a5a5a5a5a5a5a >"$DB/kek"
  # 32 bytes of "A" and of "B", base64 (Ed25519 public keys are 32 bytes).
  printf '%s\n' QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE= >"$DB/export"
  printf '%s\n' QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI= >"$DB/checkpoint"
  printf '%s\n' 1073741824 >"$DB/size"
}

write_db_hook() {
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
# The postgres container and the stop/start of the services, for the backup tests.
[ "$1" = compose ] || exit 99
all=" $* "
ev() { printf '%s\n' "$1" >>"$DB/events"; }
rc() { [ -e "$DB/$1.rc" ] && exit "$(cat "$DB/$1.rc")"; return 0; }
case $all in
  *" exec -T postgres psql "*)
    sql=${*: -1}
    case $sql in
      *pg_database_size*) f=size ;;
      *"FROM users"*) f=count.users ;;
      *"FROM sessions WHERE status = 'active'"*) f=count.active ;;
      *"FROM sessions"*) f=count.sessions ;;
      *"FROM audit_logs"*) f=count.audit_logs ;;
      *schema_migrations*) f=migrations ;;
      *data_keys*) f=kek ;;
      *export_signing_keys*) f=export ;;
      *checkpoint_signing_keys*) f=checkpoint ;;
      *) echo "fake psql: unknown query: $sql" >&2; exit 1 ;;
    esac
    ev "psql $f"
    rc "$f"
    # The one piece of SQL the fake honours: LIMIT 1 keeps the first row.
    case $sql in
      *"LIMIT 1"*) [ -e "$DB/$f" ] && head -n 1 "$DB/$f" ;;
      *) [ -e "$DB/$f" ] && cat "$DB/$f" ;;
    esac
    exit 0 ;;
  *" exec -T postgres pg_dump "*) ev pg_dump; rc pg_dump; printf 'PGDMP fake custom-format dump\n'; exit 0 ;;
  *" exec -T postgres pg_restore --list "*)
    ev pg_restore; cat >/dev/null; rc pg_restore; printf ';\n; Archive created at 2026-09-30\n'; exit 0 ;;
  *" stop "*) ev "stop ${*: -3}"; rc stop; exit 0 ;;
  *" start "*) ev "start ${*: -3}"; rc start; exit 0 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# backup_run <lang> [options...]: the real script without a terminal.
backup_run() {
  local l=$1
  shift
  run bash "$ROOT/custodexa.sh" backup --lang "$l" "$@" </dev/null
}

# screen <file>: the output with the deployment folder shown as /opt/custodexa.
screen_of() { printf '%s\n' "$1" | sed "s#$ROOT#/opt/custodexa#g"; }
