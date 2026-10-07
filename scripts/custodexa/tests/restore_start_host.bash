# Startup adapter keeps the real parser, state, image check, health wait and seal-state reader.
rs_start_host() {
  rs_import_host
  touch "$ROOT/releases/1.16.0/compose.yml"
  local svc
  for svc in postgres guacd backend frontend; do
    printf '%s=%s\n' "$svc" "$BK_PG_DIGEST"
  done >"$ROOT/releases/1.16.0/image-ids.env"
  jq '.images.guacd = .images.postgres | .images.backend = .images.postgres | .images.frontend = .images.postgres' \
    "$ROOT/releases/1.16.0/MANIFEST.json" >"$BATS_TEST_TMPDIR/full-manifest"
  cp "$BATS_TEST_TMPDIR/full-manifest" "$ROOT/releases/1.16.0/MANIFEST.json"
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  if [ -z "$CX_RS_ACTION" ]; then
    CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.0 CX_RS_ENGINE=1.16.1
    CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched
    cx_rs_record && cx_rs_phase placed || return 1
  else cx_rs_recover_context || return 1; fi
  CX_RS_DATA=$CX_ROOT/data
  CX_RS_MAP=([deploy.overlays]=external-ingress [kek.provider]="${RS_START_PROVIDER:-ui}" [kek.fingerprint]="${RS_START_FP:-5a5a5a5a5a5a5a5a}")
  cx_rs_start
}
HARNESS
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/start-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' inspect --format {{.Image}} '*)
    name=${*: -1}; name=${name#custodexa-}
    printf 'verify %s\n' "$name" >>"$DB/events"
    sed -n "s/^$name=//p" "$ROOT/releases/1.16.0/image-ids.env"
    exit 0 ;;
  *' exec -T backend wget '*'/health '*)
    echo health >>"$DB/events"
    [ ! -e "$DB/health.rc" ] || exit "$(cat "$DB/health.rc")"
    cat "$DB/health"; exit 0 ;;
  *' up -d '*)
    echo up >>"$DB/events"
    for f in "$DB"/ctr/*; do echo running >"$f"; done
    # A backend restarted after a mismatched key returns sealed.
    [ ! -e "$DB/reseal-on-up" ] || echo sealed >"$DB/seal"
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/start-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  printf sealed >"$DB/seal"
}
rs_start_run() { run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en; }
rs_start_resume() { run bash "$RS_I_ENGINE" restore --resume --lang en; }
rs_start_phase() { jq -r '."last_restore.phase"' "$ROOT/state.json"; }
