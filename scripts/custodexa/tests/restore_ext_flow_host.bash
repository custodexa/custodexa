# A whole-stage fake host on an external database: rs_ext_host's deployment with the engine's
# Docker answers (stop, up, ps, health, the release images by digest), so that a restore runs from
# the file to the end. The parser, reader, checks, safety producer, journal, import protocol,
# runtime check and recovery are real; only Docker/host responses are faked.
rs_ext_flow_host() {
  rs_ext_host "${1:-17.6}"
  backup_strict
  fake sleep ':'
  export CX_READY_TRIES=2
  bk_env_set COMPOSE_PROJECT_NAME custodexa
  awk '$1 == "fill5a" {print $3}' /src/backend/pkg/crypto/testdata/kek-fingerprint-vectors.txt >"$DB/kek"
  # The services' images: a repository and digest of their own (the release's postgres tag is
  # also the 16 client's, which this host knows by tag only).
  RS_X_SVC=$BK_PG_DIGEST_OTHER
  jq --arg d "$RS_X_SVC" '.images.guacd = {ref: "ghcr.io/custodexa/service", tag: "1.16.0", index_digest: $d}
    | .images.backend = .images.guacd | .images.frontend = .images.guacd
    | .images |= with_entries(.value.platforms = {amd64: {config_digest: .value.index_digest}, arm64: {config_digest: .value.index_digest}})' \
    "$ROOT/current/MANIFEST.json" >"$BATS_TEST_TMPDIR/full-mf"
  cp "$BATS_TEST_TMPDIR/full-mf" "$ROOT/current/MANIFEST.json"
  bk_state_set current.image_ids "guacd=$RS_X_SVC backend=$RS_X_SVC frontend=$RS_X_SVC openssl=$BK_OPENSSL_ID"
  printf '%s\n' "$RS_X_SVC" >>"$DB/images"
  touch "$ROOT/current/compose.yml" "$ROOT/current/compose.external-database.yml"
  rm -f "$DB/ctr/postgres"
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/ext-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' logs '*) exit 0 ;;
  *'{{.State.Running}} {{.State.StartedAt}} {{.State.FinishedAt}}'*)
    svc=${*: -1}; svc=${svc#custodexa-}; running=false
    [ "$(cat "$DB/ctr/$svc" 2>/dev/null)" != running ] || running=true
    printf '%s %s %s\n' "$running" 2026-01-01T00:00:00Z 2026-09-01T00:00:00Z
    exit 0 ;;
  *' stop '*)
    echo stop >>"$DB/events"
    [ ! -f "$DB/stop.rc" ] || exit "$(cat "$DB/stop.rc")"
    while [ "$1" != stop ]; do shift; done; shift
    [ "$#" -gt 0 ] || set -- guacd backend frontend
    for c in "$@"; do echo stopped >"$DB/ctr/$c"; done
    # Once the services stop, the deployment's own connections end ($DB/activity.after-stop).
    [ ! -e "$DB/activity.after-stop" ] || cp "$DB/activity.after-stop" "$DB/activity"
    exit 0 ;;
  *' image inspect --format {{.Id}} '*@sha256:*)
    # The release's service images by their digest; the clients stay rs_ext_host's (by tag).
    d=${*: -1}; d=${d#*@}
    [[ " $RS_X_CLIENTS " == *" $d "* ]] || { printf '%s\n' "$d"; exit 0; } ;;
  *' inspect --format {{.Image}} '*)
    printf 'verify %s\n' "${*: -1}" >>"$DB/events"
    case ${*: -1} in *tls-init*) printf '%s\n' "$BK_OPENSSL_ID" ;; *) printf '%s\n' "$RS_X_SVC" ;; esac
    exit 0 ;;
  *' run --rm --no-deps --name custodexa-restore-tool-'*' tls-init '*)
    # A new host's server certificate.
    printf 'new leaf\n' >"$ROOT/tls/fullchain.pem"
    printf 'new leaf key\n' >"$ROOT/tls/privkey.pem"
    echo 'issue leaf' >>"$DB/events"
    exit 0 ;;
  *' up -d '*)
    echo up >>"$DB/events"
    for c in guacd backend frontend; do echo running >"$DB/ctr/$c"; done
    # $DB/kek.after-up: the master key ID the started backend reports (unsealed with another key).
    [ ! -e "$DB/kek.after-up" ] || cp "$DB/kek.after-up" "$DB/kek"
    exit 0 ;;
  *' ps --status running --services '*)
    for f in "$DB"/ctr/*; do [ ! -f "$f" ] || [ "$(cat "$f")" != running ] || printf '%s\n' "${f##*/}"; done
    exit 0 ;;
  *' --entrypoint psql '*offsite_profiles*)
    echo 'psql offsite' >>"$DB/events"
    if [ -e "$DB/offsite" ]; then cat "$DB/offsite"; else echo 0; fi
    exit 0 ;;
  *' exec -T backend wget '*'/health '*)
    echo health >>"$DB/events"
    [ ! -f "$DB/health.rc" ] || exit "$(cat "$DB/health.rc")"
    cat "$DB/health"; exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/ext-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  export BK_OPENSSL_ID RS_X_SVC RS_X_CLIENTS="${BK_PGC_DIGEST[16]} ${BK_PGC_DIGEST[17]} ${BK_PGC_DIGEST[18]}"
  echo unsealed >"$DB/seal"
  # RS_X_BEFORE: a function of the test that sets the source deployment up before its backup.
  [ -z "${RS_X_BEFORE:-}" ] || "$RS_X_BEFORE"
  bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/producer.log" 2>&1 || {
    cat "$BATS_TEST_TMPDIR/producer.log"; return 1;
  }
  export RS_X_FILE
  RS_X_FILE=$(find "$ROOT/backups" -name '*.tar')
  mkdir "$BATS_TEST_TMPDIR/source"
  cp "$RS_X_FILE" "$RS_X_FILE.sha256" "$BATS_TEST_TMPDIR/source/"
  RS_X_FILE=$BATS_TEST_TMPDIR/source/${RS_X_FILE##*/}
  rm -f "$ROOT"/backups/*
  : >"$DB/events"
  : >"$FAKE_DOCKER_LOG"
}
rs_ext_flow_run() {
  run bash "$ROOT/custodexa.sh" restore "$RS_X_FILE" --same-host --yes --confirm-data-loss --lang en "$@" </dev/null
}
rs_ext_flow_resume() { run bash "$ROOT/custodexa.sh" restore --resume --lang en </dev/null; }
rs_ext_flow_result() { jq -r '."last_restore.result"' "$ROOT/state.json"; }
