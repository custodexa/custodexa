# A real argument parser with only the unfinished execution entry replaced in the fake release.
# All safety functions, producer steps, readers and state writers are the production functions.
rs_safety_host() {
  rs_host ui
  backup_strict
  fake sleep ':'
  clock
  bk_state_set current.kind package
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/safety-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
if [ "$1" = logs ]; then
  [ ! -f "$DB/backend.log" ] || cat "$DB/backend.log"
  exit 0
fi
if [[ $* == *'{{.State.Running}} {{.State.StartedAt}} {{.State.FinishedAt}}'* ]]; then
  svc=${*: -1}; svc=${svc#custodexa-}
  started=2026-01-01T00:00:00Z
  [ ! -f "$DB/started.$svc" ] || started=$(cat "$DB/started.$svc")
  running=false
  [ "$(cat "$DB/ctr/$svc")" != running ] || running=true
  printf '%s %s %s\n' "$running" "$started" 2026-09-01T00:00:00Z
  exit 0
fi
exec "$FAKE_DOCKER_REPLAY/safety-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  if [ "$CX_RS_ACTION" = resume ]; then
    cx_lock
    cx_rs_recover_context || return 3
    cx_log_open restore || return 1
    cx_rs_safety
    return "$?"
  fi
  cx_rs_read_setup || return 1
  CX_RS_FLOW=same CX_RS_VERSION=1.16.0 CX_RS_FILE=$1 CX_RS_CHECKSUM=matched
  cx_rs_safety_preflight || true
  cx_rs_safety_choose || return "$?"
  [ ! -e "$DB/only-preflight" ] || return 0
  cx_rs_record && cx_rs_phase prepared || return 1
  if [ -e "$DB/race" ]; then printf '%s\n' 5a5a5a5a5a5a5a5a 6b6b6b6b6b6b6b6b >"$DB/kek"; fi
  cx_rs_safety
}
HARNESS
  printf 'source restore input\n' >"$BATS_TEST_TMPDIR/source.tar"
  cp "$ROOT/.env" "$BATS_TEST_TMPDIR/env-before"
  tree_of "$ROOT/data" >"$BATS_TEST_TMPDIR/data-before"
  : >"$DB/events"
}
rs_safety_run() { run bash "$ROOT/custodexa.sh" restore "$BATS_TEST_TMPDIR/source.tar" --same-host --yes --lang en </dev/null; }
rs_safety_no_cover() {
  cmp "$ROOT/.env" "$BATS_TEST_TMPDIR/env-before" || return 1
  tree_of "$ROOT/data" >"$BATS_TEST_TMPDIR/data-after"
  cmp "$BATS_TEST_TMPDIR/data-before" "$BATS_TEST_TMPDIR/data-after" || return 1
  [ -z "$(find "$ROOT" -name '*.before-restore-*')" ] || return 1
  ! grep -Eq '^(start|up)( |$)' "$DB/events"
}
rs_safety_failed() {
  [ "$status" -eq 1 ] && [[ $output == *'restore --resume'* && $output == *'restore --revert'* && $output == *'start the original services'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = prepared ] || return 1
  rs_safety_no_cover
}
