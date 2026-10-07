# Unfinished restore records and a read-only interlock harness.
rs_state_host() {
  rs_host ui
  backup_strict
  bk_state_set current.kind package
  bk_state_set last_restore.result in_progress
  bk_state_set last_restore.flow same-host
  bk_state_set last_restore.phase awaiting_unseal
  bk_state_set last_restore.step 10
  bk_state_set last_restore.started_at 2026-10-12T09:30:15+0800
  bk_state_set last_restore.product_version 1.16.0
  bk_state_set last_restore.file /srv/transfer/custodexa-backup-1.16.0-20261005-101502.tar.enc
  bk_state_set last_restore.engine "$ROOT/custodexa.sh"
  bk_state_set last_restore.safety script
  bk_state_set last_restore.stamp 20261012-093015
  bk_state_set last_restore.services up
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/restore-hook"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' ps --status running --services '*)
    for f in "$DB"/ctr/*; do [ "$(cat "$f")" != running ] || printf '%s\n' "${f##*/}"; done
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/restore-hook" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  GATE=$BATS_TEST_TMPDIR/gate.sh
  cat >"$GATE" <<'GATE'
. "$1/lib/common.sh"
CX_LANG_FLAG=en
cx_load_libs "$1"
CX_ROOT=$2 CX_SELF=$2/current/custodexa.sh CX_DIR=$2/current
cx_state_load "$CX_ROOT/state.json"
cx_run_restore_guard "$3" "${4:-}" || exit 3
printf 'allowed\n'
GATE
}
rs_gate_case() {
  local group=$1 cmd=$2 expected=$3 action=""
  case $group in
    early) bk_state_set last_restore.phase prepared ;;
    unchecked) bk_state_set last_restore.phase imported; bk_state_set last_restore.step 6; bk_state_set last_restore.covering 1 ;;
    placed) bk_state_set last_restore.phase placed; bk_state_set last_restore.covering 1 ;;
    started) bk_state_set last_restore.phase awaiting_unseal; bk_state_set last_restore.covering 1 ;;
    reverting) bk_state_set last_restore.exit reverting ;;
    abandoning) bk_state_set last_restore.exit abandoning; bk_state_set last_restore.flow new-host ;;
  esac
  case $cmd in restore-*) action=${cmd#restore-}; cmd=restore ;; esac
  run bash "$GATE" "$SRC" "$ROOT" "$cmd" "$action"
  [ "$status" -eq "$expected" ] || { echo "$output"; return 1; }
  if [ "$expected" = 0 ]; then [ "$output" = allowed ]; return; fi
  [[ $output == *'[FAIL]'* && $output != *'allowed'* ]] || { echo "$output"; return 1; }
  local want=resume
  case $group in
    reverting) want=revert; [[ $output == *'Going back is under way'* ]] || return 1 ;;
    abandoning) want=abandon; [[ $output == *'Giving up on this restore is under way'* ]] || return 1 ;;
    early) if [ "$cmd" = start ]; then want=revert; [[ $output == *'not overwritten data yet'* ]] || return 1; fi ;;
    unchecked) if [ "$cmd" = start ]; then [[ $output == *'data has not been checked'* && $output == *'restore --revert'* ]] || return 1; fi ;;
    placed) if [ "$cmd" = start ]; then [[ $output == *'restored data is in place'* ]] || return 1; fi ;;
  esac
  [[ $output == *"sudo $ROOT/custodexa.sh restore --$want"* ]] || { echo "$output"; return 1; }
}
