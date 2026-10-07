# A fake execution adapter keeps the real CLI parser, lock, state and journal. Stages not yet
# connected to the public entry are driven directly. Exit tests exercise the journal's routing;
# completing a safety restore and checking service readiness belong to the exit-stage tests.
rs_journal_host() {
  rs_host ui
  backup_strict
  fake sleep ':'
  mkdir -p "$ROOT/data/postgres"
  printf 'original database\n' >"$ROOT/data/postgres/PG_VERSION"
  printf 'original leaf\n' >"$ROOT/tls/fullchain.pem"
  printf 'original key\n' >"$ROOT/tls/privkey.pem"
  export RS_J_STAGE=$ROOT/restore/journal-test
  mkdir -p "$RS_J_STAGE/pass2"
  cp "$ROOT/.env" "$RS_J_STAGE/env.merged"
  printf '\n# restored settings\n' >>"$RS_J_STAGE/env.merged"
  printf 'restored template\n' >"$RS_J_STAGE/pass2/nginx-tls.conf.template"
  printf 'original template\n' >"$ROOT/nginx.conf"
  printf 'source archive\n' >"$BATS_TEST_TMPDIR/restore-input.tar"
  export RS_J_SAFETY
  RS_J_SAFETY=$(find "$RS_FIX" -maxdepth 1 -name '*.tar')
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'HARNESS'
# Interrupt at the boundary of a real function, without modifying the production function.
rs_j_cut() {
  if [ "${RS_J_CUT:-}" = "$1:$2" ]; then
    printf '%s\n' "$RS_J_CUT" >"$DB/cut-hit"
    kill -KILL "$$"
  fi
}
eval "$(declare -f cx_rs_journal_append | sed '1s/cx_rs_journal_append/rs_j_append/')"
cx_rs_journal_append() {
  local seq mark rest
  read -r seq mark rest <<<"$*"
  rs_j_cut "before-$mark" "$CX_RS_J_ID"
  rs_j_append "$@" || return 1
  rs_j_cut "after-$mark" "$CX_RS_J_ID"
}
eval "$(declare -f cx_rs_journal_apply | sed '1s/cx_rs_journal_apply/rs_j_apply/')"
cx_rs_journal_apply() {
  rs_j_cut before-action "$CX_RS_J_ID"
  rs_j_apply || return 1
  rs_j_cut after-action "$CX_RS_J_ID"
}
eval "$(declare -f cx_rs_save | sed '1s/cx_rs_save/rs_j_save/')"
cx_rs_save() {
  local id=${CX_RS_J_ID:-setup}
  [ "${RS_J_COVERING:-0}" != 1 ] || id=covering
  rs_j_cut before-state "$id"
  rs_j_save || return 1
  rs_j_cut after-state "$id"
}
eval "$(declare -f cx_rs_phase | sed '1s/cx_rs_phase/rs_j_phase/')"
cx_rs_phase() { local CX_RS_J_ID=phase-$1; rs_j_phase "$1"; }
eval "$(declare -f cx_rs_covering | sed '1s/cx_rs_covering/rs_j_covering/')"
cx_rs_covering() { local RS_J_COVERING=1; rs_j_covering; }
rs_j_forward() {
  cx_rs_swapped || return 1
  # The payload-file stage is a fixture here; journal primitives are the production ones.
  [ -d "$CX_ROOT/tls" ] || cp -a "$CX_ROOT/tls.before-restore-$CX_RS_TS" "$CX_ROOT/tls"
  cx_rs_template_place && cx_rs_leaf_keep && cx_rs_switch_release 1.16.1 || return 1
  cx_rs_current_set version 1.16.1 && cx_rs_current_set image_ids 'backend=sha256:restored' || return 1
  cx_rs_phase placed
}
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  cx_state_load "$CX_ROOT/state.json"
  if [ -z "$CX_RS_ACTION" ]; then
    CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.1 CX_RS_ENGINE=1.16.1
    CX_RS_DIR=$RS_J_STAGE CX_RS_TS=journal-test CX_RS_CHECKSUM=matched
    cx_rs_record && cx_rs_phase stopped && cx_rs_services all-stopped || return 1
    cx_state_set last_restore.safety script && cx_state_set last_restore.safety_file "$RS_J_SAFETY" && cx_rs_save || return 1
  else cx_rs_recover_context || return 1; fi
  CX_RS_DATA=$CX_ROOT/data CX_RS_TEMPLATE=$CX_ROOT/nginx.conf
  CX_RS_MAP=([contents.tls]=true)
  CX_RS_J_ID=""
  cx_rs_recovery_route "${CX_RS_ACTION:-resume}" || return 1
  case $CX_RS_RECOVERY in
    resume) rs_j_forward ;;
    original)
      printf 'original-services\n' >>"$DB/events"
      cx_compose_release "$CX_ROOT/releases/1.16.0" start ;;
    safety)
      # Verify the selected input with the real reader. No stage chooses the old postgres
      # directory just because the overall phase still says stopped.
      cx_rs_safety_verify "$(cx_state_get last_restore.safety_file)" 5a5a5a5a5a5a5a5a || return 1
      printf 'restore-safety %s\n' "$(cx_state_get last_restore.safety_file)" >>"$DB/events" ;;
    *) return 1 ;;
  esac
}
HARNESS
  cp -a "$ROOT/releases/1.16.0" "$ROOT/releases/1.16.1"
  printf '1.16.1\n' >"$ROOT/releases/1.16.1/VERSION"
  touch "$ROOT/releases/1.16.0/compose.yml" "$ROOT/releases/1.16.1/compose.yml"
  cp -a "$ROOT" "$BATS_TEST_TMPDIR/journal-original"
  export RS_J_ENGINE=$ROOT/releases/1.16.1/custodexa.sh
}
rs_journal_reset() {
  rm -rf "$ROOT"
  cp -a "$BATS_TEST_TMPDIR/journal-original" "$ROOT"
  : >"$DB/events"
  rm -f "$DB/cut-hit"
  local f
  for f in "$DB"/ctr/*; do printf 'stopped\n' >"$f"; done
}
rs_journal_start() {
  run env RS_J_CUT="$1" bash "$RS_J_ENGINE" restore "$BATS_TEST_TMPDIR/restore-input.tar" --same-host --yes --lang en
  [ "$status" = 137 ] && [ "$(cat "$DB/cut-hit")" = "$1" ] || { echo "cut=$1 status=$status $output"; return 1; }
}
rs_journal_resumed() {
  local name before=$BATS_TEST_TMPDIR/journal-original
  for name in postgres audit; do
    [ "$(find "$ROOT/data" -maxdepth 1 -name "$name.before-restore-*" | wc -l)" = 1 ] || return 1
    diff -r "$before/data/$name" "$ROOT/data/$name.before-restore-journal-test" || return 1
  done
  [ "$(find "$ROOT" -maxdepth 1 -name 'tls.before-restore-*' | wc -l)" = 1 ] || return 1
  diff -r "$before/tls" "$ROOT/tls.before-restore-journal-test" || return 1
  cmp "$ROOT/.env" "$RS_J_STAGE/env.merged" && [ "$(stat -c %a "$ROOT/.env")" = 600 ] || return 1
  cmp "$before/.env" "$RS_J_STAGE/env-before-restore" && cmp "$before/state.json" "$RS_J_STAGE/state-before.json" || return 1
  [ "$(stat -c %a "$RS_J_STAGE/journal")" = 600 ] || return 1
  cmp "$before/nginx.conf" "$ROOT/nginx.conf.before-restore-journal-test" || return 1
  cmp "$RS_J_STAGE/pass2/nginx-tls.conf.template" "$ROOT/nginx.conf" || return 1
  cmp "$before/tls/fullchain.pem" "$ROOT/tls/leaf.before-restore-journal-test/fullchain.pem" || return 1
  cmp "$before/tls/privkey.pem" "$ROOT/tls/leaf.before-restore-journal-test/privkey.pem" || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.16.1 ] || return 1
  [ "$(jq -r '."current.version"' "$ROOT/state.json")" = 1.16.1 ]
}
rs_journal_matrix() {
  local op=$1 point exit_action covering
  for point in before-intent after-intent before-action after-action before-done after-done before-state after-state; do
    for exit_action in resume revert; do
      rs_journal_reset
      rs_journal_start "$point:$op" || return 1
      covering=$(jq -r '."last_restore.covering"' "$ROOT/state.json")
      run bash "$RS_J_ENGINE" restore "--$exit_action" --yes --lang en
      [ "$status" = 0 ] || { echo "$point:$op --$exit_action $output"; return 1; }
      if [ "$exit_action" = resume ]; then rs_journal_resumed || return 1
      elif [ "$covering" = 1 ]; then
        grep -q '^restore-safety ' "$DB/events" && ! grep -q '^original-services$' "$DB/events" || return 1
        [[ $output != *'Nothing has been overwritten'* ]] || return 1
      else grep -q '^original-services$' "$DB/events" && ! grep -q '^restore-safety ' "$DB/events" || return 1; fi
    done
  done
}
