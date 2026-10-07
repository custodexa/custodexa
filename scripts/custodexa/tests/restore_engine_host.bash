# A whole-stage fake host: the parser, reader, safety producer, journal, import, runtime check
# and recovery are real. Only Docker/host responses and explicit interruption points are faked.
rs_engine_host() {
  rs_host env
  backup_strict
  fake sleep ':'
  export CX_READY_TRIES=2
  BK_KEK=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
  bk_dotenv env
  bk_env_set COMPOSE_PROJECT_NAME custodexa
  bk_env_set COMPOSE_FILE current/compose.yml:current/compose.external-ingress.yml
  bk_state_set current.overlays external-ingress
  awk '$1 == "fill5a" {print $3}' /src/backend/pkg/crypto/testdata/kek-fingerprint-vectors.txt >"$DB/kek"
  jq '.images |= with_entries(.value.platforms = {amd64: {config_digest: .value.index_digest}, arm64: {config_digest: .value.index_digest}}) | .images.guacd = .images.postgres | .images.backend = .images.postgres | .images.frontend = .images.postgres' \
    "$ROOT/current/MANIFEST.json" >"$BATS_TEST_TMPDIR/full-mf"
  cp "$BATS_TEST_TMPDIR/full-mf" "$ROOT/current/MANIFEST.json"
  touch "$ROOT/current/compose.yml" "$ROOT/current/compose.external-ingress.yml"
  bk_state_set current.image_ids "postgres=$BK_PG_DIGEST guacd=$BK_PG_DIGEST backend=$BK_PG_DIGEST frontend=$BK_PG_DIGEST"
  mkdir -p "$ROOT/data/postgres"
  printf 'original cluster\n' >"$ROOT/data/postgres/PG_VERSION"
  # The fake database has a real import marker; retaining it proves which data was imported.
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/engine-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' logs '*) exit 0 ;;
  *'{{.State.Running}} {{.State.StartedAt}} {{.State.FinishedAt}}'*)
    svc=${*: -1}; svc=${svc#custodexa-}; running=false
    [ "$(cat "$DB/ctr/$svc")" != running ] || running=true
    printf '%s %s %s\n' "$running" 2026-01-01T00:00:00Z 2026-09-01T00:00:00Z
    exit 0 ;;
  *' stop '*)
    echo stop >>"$DB/events"
    [ ! -f "$DB/stop.rc" ] || exit "$(cat "$DB/stop.rc")"
    while [ "$1" != stop ]; do shift; done; shift
    [ "$#" -gt 0 ] || set -- postgres guacd backend frontend
    for c in "$@"; do echo stopped >"$DB/ctr/$c"; done
    exit 0 ;;
  *' image inspect --format {{.Id}} '*@sha256:*) printf '%s\n' "${*: -1}" | sed 's/.*@//'; exit 0 ;;
  *' inspect --format {{.Image}} '*)
    printf 'verify %s\n' "${*: -1}" >>"$DB/events"
    printf '%s\n' "$BK_PG_DIGEST"; exit 0 ;;
  *' up -d postgres '*)
    echo 'up postgres' >>"$DB/events"
    echo running >"$DB/ctr/postgres"
    echo cluster >"$ROOT/data/postgres/PG_VERSION"; exit 0 ;;
  *' up -d '*)
    echo up >>"$DB/events"
    for c in postgres guacd backend frontend; do echo running >"$DB/ctr/$c"; done
    exit 0 ;;
  *' pg_isready '*) exit 0 ;;
  *' psql '*'SELECT 1 '*) echo 1; exit 0 ;;
  *' pg_restore --single-transaction --exit-on-error '*)
    echo import >>"$DB/events"
    cat >"$ROOT/data/postgres/import-data"
    [ ! -f "$DB/import.rc" ] || exit "$(cat "$DB/import.rc")"
    exit 0 ;;
  *' ps --status running --services '*)
    for f in "$DB"/ctr/*; do [ ! -f "$f" ] || [ "$(cat "$f")" != running ] || printf '%s\n' "${f##*/}"; done
    exit 0 ;;
  *' exec -T backend wget '*'/health '*)
    echo health >>"$DB/events"
    [ ! -f "$DB/health.rc" ] || exit "$(cat "$DB/health.rc")"
    cat "$DB/health"; exit 0 ;;
  *' rm -f '*)
    [ ! -f "$DB/tools" ] || { for n in "$@"; do sed -i "\\|^$n\$|d" "$DB/tools"; done; }
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/engine-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  export BK_PG_DIGEST
  echo unsealed >"$DB/seal"
  bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/producer.log" 2>&1 || {
    cat "$BATS_TEST_TMPDIR/producer.log"; return 1;
  }
  export RS_E_FILE
  RS_E_FILE=$(find "$ROOT/backups" -name '*.tar')
  mkdir "$BATS_TEST_TMPDIR/source"
  cp "$RS_E_FILE" "$RS_E_FILE.sha256" "$BATS_TEST_TMPDIR/source/"
  RS_E_FILE=$BATS_TEST_TMPDIR/source/${RS_E_FILE##*/}
  rm -f "$ROOT"/backups/*
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'HARNESS'
# Inject once at a real phase boundary, recording the actual containers at the interruption.
eval "$(declare -f cx_rs_phase | sed '1s/cx_rs_phase/rs_e_phase/')"
cx_rs_phase() {
  rs_e_phase "$@" || return 1
  [ "${RS_E_CUT:-}" = "$1" ] || return 0
  [ ! -e "$DB/cut-hit" ] || return 0
  echo "$1" >"$DB/cut-hit"
  cp -a "$DB/ctr" "$DB/at-cut"
  if [ "${RS_E_SIGNAL:-0}" = 1 ]; then
    echo "custodexa-restore-tool-$CX_RS_TS-cut" >>"$DB/tools"
    kill -TERM "$$"
  fi
  return 1
}
HARNESS
  : >"$DB/events"
  : >"$FAKE_DOCKER_LOG"
}
rs_engine_run() {
  run bash "$ROOT/custodexa.sh" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en "$@" </dev/null
}
rs_engine_resume() { run bash "$ROOT/custodexa.sh" restore --resume --lang en </dev/null; }
rs_engine_result() { jq -r '."last_restore.result"' "$ROOT/state.json"; }
rs_engine_matrix() {
  local phase=$1 sig=${2:-0} f running=0
  export RS_E_CUT=$phase RS_E_SIGNAL=$sig
  if [ "$phase" = awaiting_unseal ]; then
    # env backups cannot await unseal; the reader and runtime check use the ui fixture here.
    bk_env_set KEK_PROVIDER ui
    bk_env_set ENCRYPTION_KEY ""
    bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/ui.log" 2>&1 || { cat "$BATS_TEST_TMPDIR/ui.log"; return 1; }
    RS_E_FILE=$(find "$ROOT/backups" -name '*.tar' | head -n 1)
    mkdir -p "$BATS_TEST_TMPDIR/ui"
    cp "$RS_E_FILE" "$RS_E_FILE.sha256" "$BATS_TEST_TMPDIR/ui/"
    RS_E_FILE=$BATS_TEST_TMPDIR/ui/${RS_E_FILE##*/}
    rm -f "$ROOT"/backups/*
    echo sealed >"$DB/seal"
    : >"$DB/events"
  fi
  rs_engine_run
  [ "$status" = 1 ] && [ "$(cat "$DB/cut-hit")" = "$phase" ] || { echo "$phase $sig: $status $output"; return 1; }
  [[ $output == *'restore --resume'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
  for f in "$DB"/ctr/*; do [ "$(cat "$f")" != running ] || running=1; done
  if [ "$sig" = 1 ]; then
    if [ "$running" = 1 ]; then [[ $output == *'Some or all services may be running'* ]]
    else [[ $output == *'The services stay stopped'* ]]; fi || { echo "$output"; return 1; }
    ! grep -q 'custodexa-restore-tool-' "$DB/tools" || return 1
  fi
  echo unsealed >"$DB/seal"
  unset RS_E_CUT RS_E_SIGNAL
  local before
  before=$(grep -cx pg_dump "$DB/events" || true)
  rs_engine_resume
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$phase resume: $status $output"; return 1; }
  if [ "$phase" != prepared ]; then [ "$(grep -cx pg_dump "$DB/events" || true)" = "$before" ] || return 1; fi
}
