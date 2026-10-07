# shellcheck shell=bash
# about: rollback from 1.16.91 to 1.16.90 against the real PostgreSQL of a built-in deployment when the database changes after the preview: a migration row committed while the preview waits is caught by the second check after the services stop (refused, the old version never starts, nothing switched); one written in a transaction that is not committed does not count (the rollback finishes); a committed row before the run is refused before the preview, the uncommitted one is not listed; after an upgrade that failed at the switch step, a new version that was started (by a revert of the rollback, or by start) and wrote a row is never let back on the never-started basis
# needs: package local-versions
# images:

readonly RR_OLD=1.16.90 RR_NEW=1.16.91

rr_mark() { lv_sql "INSERT INTO schema_migrations (version, applied_at) VALUES ('$1', now())" >/dev/null; }
rr_unmark() { lv_sql "DELETE FROM schema_migrations WHERE version LIKE 'it_rollback_race%'" >/dev/null; }
rr_marks() { lv_sql "SELECT version FROM schema_migrations WHERE version LIKE 'it_rollback_race%' ORDER BY version" | tr '\n' ' ' | sed 's/ $//'; }

# rr_tx_open <version>: a psql session that has inserted the row in an open transaction.
rr_tx_open() {
  rm -f "$IT_WORK/tx.in" "$IT_WORK/tx.out"
  mkfifo "$IT_WORK/tx.in"
  exec 8<>"$IT_WORK/tx.in"
  docker exec -i custodexa-postgres psql -X -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" \
    <"$IT_WORK/tx.in" >"$IT_WORK/tx.out" 2>&1 &
  RR_TX=$!
  printf "BEGIN;\nINSERT INTO schema_migrations (version, applied_at) VALUES ('%s', now());\nSELECT 'tx-open';\n" "$1" >&8
  lv_until "the transaction is open" grep -q tx-open "$IT_WORK/tx.out"
}
rr_tx_close() {
  printf 'ROLLBACK;\n\\q\n' >&8 2>/dev/null || true
  exec 8>&-
  wait "$RR_TX" 2>/dev/null || true
}

# rr_interactive <label> <action>: rollback on a terminal (script(1) gives it one); when the preview
# asks [y/N], run the action, then answer y. LV_RC, LV_OUT.
rr_interactive() {
  local label=$1 action=$2 pid
  rm -f "$IT_WORK/$label.in"
  mkfifo "$IT_WORK/$label.in"
  exec 7<>"$IT_WORK/$label.in"
  script -qfec "$LV_ROOT/custodexa.sh rollback --lang en" /dev/null <"$IT_WORK/$label.in" >"$IT_WORK/$label.out" 2>&1 &
  pid=$!
  lv_until "$label: the preview asks" grep -q 'Start? \[y/N\]' "$IT_WORK/$label.out"
  it_say "   $label: the preview asks; now: $action"
  "$action"
  printf 'y\n' >&7
  LV_RC=0
  wait "$pid" || LV_RC=$?
  exec 7>&-
  LV_OUT=$(tr -d '\r' <"$IT_WORK/$label.out")
  printf '%s\n' "$LV_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$LV_RC"
}

rr_commit_race() { rr_mark it_rollback_race; }
rr_open_race() { rr_tx_open it_rollback_race; }

# rr_refused_changed <label>: the rollback was refused before anything stopped because the database
# holds the committed row: the list comes from the query, so the never-started basis (which reads
# nothing and lets the rollback go on) was not taken.
rr_refused_changed() {
  it_same "$1: exit 3" 3 "$LV_RC"
  it_check "$1: the screen refuses and lists it_rollback_race as the database change after the upgrade" \
    bash -c 'grep -q "Cannot go straight back to $2" <<<"$1" && grep -q "the database structure changed after the upgrade" <<<"$1" && grep -q "(it_rollback_race)" <<<"$1"' _ "$LV_OUT" "$RR_OLD"
  it_same "$1: current.version, the current link are unchanged" "$RR_NEW releases/$RR_NEW" \
    "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
}

scenario() {
  local t0 t1 newid ps0 pg0
  lv_install "$RR_OLD"
  lv_upgrade "$RR_NEW"
  newid=$(docker inspect --format '{{.Image}}' custodexa-backend)

  it_step "a migration row is committed while the preview waits: the second check refuses"
  t0=$(date +%s)
  rr_interactive race-commit rr_commit_race
  t1=$(date +%s)
  it_same "exit 1" 1 "$LV_RC"
  it_same "last_rollback.result" refused "$(lv_st last_rollback.result)"
  it_check "the screen is the second check's refusal and lists it_rollback_race" \
    bash -c 'grep -q "a second check after the services" <<<"$1" && grep -q it_rollback_race <<<"$1"' _ "$LV_OUT"
  it_same "the backend container's image is still that of $RR_NEW" "$newid" "$(docker inspect --format '{{.Image}}' custodexa-backend)"
  it_same "no container of $RR_OLD started" "" \
    "$(docker events --since "$t0" --until "$t1" --filter type=container --filter event=start --format '{{.Actor.Attributes.name}} {{.Actor.Attributes.image}}' | grep -F ":$RR_OLD" || true)"
  it_same "current.version, the current link are unchanged" "$RR_NEW releases/$RR_NEW" \
    "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "the database is still running" true "$(docker inspect --format '{{.State.Running}}' custodexa-postgres)"
  rr_unmark
  lv_cx start start
  lv_wait_version "$RR_NEW"

  it_step "a migration row written in a transaction that is not committed: the rollback finishes"
  rr_tx_open it_rollback_race
  pg0=$(docker inspect --format '{{.State.StartedAt}}' custodexa-postgres)
  rr_interactive race-open true
  it_same "exit 0" 0 "$LV_RC"
  it_same "last_rollback.result, basis" "succeeded same_migrations" "$(lv_st last_rollback.result) $(lv_st last_rollback.basis)"
  lv_wait_version "$RR_OLD"
  # After its second check the rollback stops the database too (step 2) and starts it with the old
  # version: the session holding the uncommitted row ends there, and its row with it.
  it_check "the database was stopped and started again during the rollback" \
    test "$(docker inspect --format '{{.State.StartedAt}}' custodexa-postgres)" != "$pg0"
  it_same "the transaction's session ended: no session is left idle in that transaction" 0 \
    "$(lv_sql "SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' AND query LIKE '%tx-open%'")"
  rr_tx_close
  it_same "the uncommitted row is not in the database" "" "$(rr_marks)"

  it_step "one of two rows committed before the run: refused before the preview, the committed one listed"
  lv_upgrade "$RR_NEW"
  rr_mark it_rollback_race_a
  rr_tx_open it_rollback_race_b
  ps0=$(lv_ps)
  lv_cx partial rollback --yes
  it_same "exit 3" 3 "$LV_RC"
  it_check "before the preview" bash -c '! grep -q "preview" <<<"$1"' _ "$LV_OUT"
  it_check "it_rollback_race_a is listed" grep -q it_rollback_race_a <<<"$LV_OUT"
  it_check "it_rollback_race_b is not" bash -c '! grep -q it_rollback_race_b <<<"$1"' _ "$LV_OUT"
  it_same "the services still run, the same containers" "$ps0" "$(lv_ps)"
  rr_tx_close
  rr_unmark

  it_step "an upgrade failing at the switch step (9); rollback interrupted after the switch; --revert starts $RR_NEW, which writes a row"
  lv_cx back rollback --yes
  it_same "rollback to $RR_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$RR_OLD"
  LV_INJECT=recordings-fail lv_upgrade "$RR_NEW" 1
  it_same "last_upgrade.result, step; new_started_at" "failed 9 " \
    "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step) $(lv_st last_upgrade.new_started_at)"
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-up lv_bg after-switch rollback --yes
  lv_signal_at_up after-switch
  it_same "the first rollback went on the never-started basis" not_started "$(lv_st last_rollback.basis)"
  it_same "it stopped after the switch: last_rollback.result, step" "in_progress 3" \
    "$(lv_st last_rollback.result) $(lv_st last_rollback.step)"
  lv_cx revert rollback --revert --yes
  it_same "--revert exits 0" 0 "$LV_RC"
  lv_wait_version "$RR_NEW"
  it_check "starting $RR_NEW recorded new_started_at" test -n "$(lv_st last_upgrade.new_started_at)"
  rr_mark it_rollback_race
  lv_cx after-revert rollback --yes
  rr_refused_changed after-revert

  it_step "the same, but $RR_NEW is started with start after the failed upgrade"
  rr_unmark
  lv_cx back-2 rollback --yes
  it_same "rollback to $RR_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$RR_OLD"
  LV_INJECT=recordings-fail lv_upgrade "$RR_NEW" 1
  it_same "last_upgrade.result, step; new_started_at" "failed 9 " \
    "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step) $(lv_st last_upgrade.new_started_at)"
  lv_cx start-new start
  lv_wait_version "$RR_NEW"
  it_check "start recorded new_started_at" test -n "$(lv_st last_upgrade.new_started_at)"
  rr_mark it_rollback_race
  lv_cx after-start rollback --yes
  rr_refused_changed after-start
}
