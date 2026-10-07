# Placement adapter: validated payloads, imported and checked database, no backend started.
rs_files_host() {
  export BATS_TEST_TMPDIR=$BATS_TEST_TMPDIR/files-host
  mkdir -p "$BATS_TEST_TMPDIR"
  rs_import_host
  mkdir -p "$RS_I_STAGE/payload/audit" "$RS_I_STAGE/payload/tls" "$RS_I_STAGE/payload/recordings"
  printf 'restored audit\n' >"$RS_I_STAGE/payload/audit/segment"
  printf 'restored CA\n' >"$RS_I_STAGE/payload/tls/ca.crt"
  printf 'old leaf\n' >"$RS_I_STAGE/payload/tls/fullchain.pem"
  printf 'old leaf key\n' >"$RS_I_STAGE/payload/tls/privkey.pem"
  printf 'recorded data\n' >"$RS_I_STAGE/payload/recordings/session.cast"
  printf 'missing data\n' >"$RS_I_STAGE/payload/recordings/other.cast"
  local name
  for name in audit tls recordings; do
    tar -czf "$RS_I_STAGE/pass2/$name.tar.gz" -C "$RS_I_STAGE/payload" "$name"
  done
  mkdir -p "$ROOT/conf"
  printf 'server { backup; }\n' >"$RS_I_STAGE/pass2/nginx-tls.conf.template"
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  CX_RS_FILE=$1 CX_RS_FLOW=${RS_FILES_FLOW:-same} CX_RS_VERSION=1.16.1 CX_RS_ENGINE=1.16.1
  CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched CX_RS_DATA=$CX_ROOT/data
  CX_RS_MAP=([contents.tls]="${RS_FILES_TLS:-true}" [contents.recordings]="${RS_FILES_REC:-false}")
  CX_RS_TEMPLATE=${RS_FILES_TEMPLATE:-} CX_RS_REISSUE=${RS_FILES_REISSUE:-0}
  cx_rs_record && cx_rs_phase stopped && cx_rs_services all-stopped && cx_rs_swapped && cx_rs_phase db_checked || return 1
  cx_rs_files_place
}
HARNESS
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/files-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' run --rm --no-deps --name custodexa-restore-tool-'*' tls-init '*)
    printf 'new leaf\n' >"$ROOT/tls/fullchain.pem"
    printf 'new leaf key\n' >"$ROOT/tls/privkey.pem"
    printf 'issue leaf\n' >>"$DB/events"
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/files-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}
rs_files_run() { run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en; }
