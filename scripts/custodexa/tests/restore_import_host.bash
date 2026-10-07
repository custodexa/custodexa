# A database-only fake execution adapter, after the journal has swapped the old folders.
rs_import_host() {
  rs_host ui
  backup_strict
  fake sleep ':'
  export CX_READY_TRIES=2
  export RS_I_STAGE=$ROOT/restore/import-test
  mkdir -p "$ROOT/data/postgres" "$RS_I_STAGE/pass2"
  cp "$ROOT/.env" "$RS_I_STAGE/env.merged"
  printf 'PGDMP source archive\n' >"$RS_I_STAGE/pass2/db.dump"
  printf 'original cluster\n' >"$ROOT/data/postgres/PG_VERSION"
  cp -a "$ROOT/releases/1.16.0" "$ROOT/releases/1.16.1"
  printf '1.16.1\n' >"$ROOT/releases/1.16.1/VERSION"
  touch "$ROOT/releases/1.16.1/compose.yml"
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  cx_state_load "$CX_ROOT/state.json"
  if [ -z "$CX_RS_ACTION" ]; then
    CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.1 CX_RS_ENGINE=1.16.1
    CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched
    cx_rs_record && cx_rs_phase stopped && cx_rs_services all-stopped || return 1
  else cx_rs_recover_context || return 1; fi
  CX_RS_DATA=$CX_ROOT/data
  CX_RS_MAP=([contents.tls]=true [db.encoding]=UTF8 [db.collate]=en_US.utf8 [db.ctype]=en_US.utf8)
  if [ "$(cx_state_get last_restore.phase)" = stopped ]; then cx_rs_swapped || return 1; fi
  cx_rs_progress_begin import
  cx_rs_db_import
}
HARNESS
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/import-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' up -d postgres '*)
    n=$(cat "$DB/import-attempts" 2>/dev/null || echo 0); n=$((n + 1))
    printf '%s\n' "$n" >"$DB/import-attempts"
    printf 'cluster %s\n' "$n" >"$ROOT/data/postgres/PG_VERSION"
    printf 'up postgres\n' >>"$DB/events"
    printf 'running\n' >"$DB/ctr/postgres"
    exit 0 ;;
  *' pg_isready '*) printf 'tcp-ready\n' >>"$DB/events"; exit 0 ;;
  *' psql '*"SELECT 1"*) printf 'target-ready\n' >>"$DB/events"; echo 1; exit 0 ;;
  *' pg_restore --single-transaction --exit-on-error '*)
    printf 'pg_restore import\n' >>"$DB/events"
    [ ! -f "$DB/import.stderr" ] || cat "$DB/import.stderr" >&2
    cat >"$DB/imported.dump"
    if [ -f "$DB/import.rc" ]; then
      printf 'unfinished\n' >"$ROOT/data/postgres/import-data"
      exit "$(cat "$DB/import.rc")"
    fi
    printf 'complete\n' >"$ROOT/data/postgres/import-data"
    exit 0 ;;
  *' ps --status running --services '*)
    for f in "$DB"/ctr/*; do [ "$(cat "$f")" != running ] || printf '%s\n' "${f##*/}"; done
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/import-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  local f
  for f in "$DB"/ctr/*; do printf 'stopped\n' >"$f"; done
  export RS_I_ENGINE=$ROOT/releases/1.16.1/custodexa.sh
  : >"$DB/events"
}
rs_import_run() { run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en; }
rs_import_only_postgres() {
  local svc
  for svc in guacd backend frontend; do [ "$(cat "$DB/ctr/$svc")" = stopped ] || return 1; done
  [ "$(cat "$DB/ctr/postgres")" = running ] || return 1
  [ "$(grep -E '^(start|up)( |$)' "$DB/events" | sort -u)" = 'up postgres' ]
}
