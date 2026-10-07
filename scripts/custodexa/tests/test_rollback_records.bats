#!/usr/bin/env bats
# What going back after an upgrade relies on, written by the upgrade and the commands around it:
#   - from step 7 on, where the backup is, what kind it is, and the snapshot taken while the old
#     version was stopped (a failure of steps 9 to 12 needs them, and they used to be written only
#     at the end);
#   - a record, written before any start of the new version (upgrade, start, the backup's restart),
#     that the new version may have run: without it an upgrade that failed at the switch looks
#     untouched although `start` ran the new version on the database since;
#   - an upgrade interrupted after the switch keeps out the rollback, and the restore and load a
#     refused rollback prints, only when it is the one thing unfinished.
# A missing record, a record written after the start, or a hand-over that loosens the other locks
# shows here as a failed assertion.

load helper
load install_host
load backup_host
load upgrade_host

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

fresh() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host "${1:-ui}" || return 1
  clock 0 3 0 41 0 4 0 11
  : >"$DB/events"
}

# switch_fails: step 9 fails (preparing the recordings folder), after current moved.
switch_fails() { hook_before 'case " $* " in *" run "*" --entrypoint /bin/sh "*) exit 1 ;; esac'; }

# mark_seen_at_up: each `up` notes whether state.json already held the record when it ran.
mark_seen_at_up() {
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'case " $* " in *" compose "*" up -d "*)
  if grep -q "\"last_upgrade.new_started_at\": \"[^\"]" "$ROOT/state.json"; then echo "up marked" >>"$DB/events"
  else echo "up unmarked" >>"$DB/events"; fi ;;
esac'
}

# begin <command>: cx_begin of that command on $ROOT, as the command runs it; prints the state after.
begin() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=$2
    cx_begin "$3" >/dev/null 2>&1 || exit $?
    cx_finish succeeded' _ "$SRC" "$ROOT" "$1"
}

# upgrade_at <step> <result>: the record of the failed upgrade, set to stop at that step.
upgrade_at() {
  bk_state_set last_upgrade.step "$1"
  bk_state_set last_upgrade.result "$2"
}

@test "rollback records: step 7 writes the backup, its kind and the snapshot; a failure at the switch keeps them" {
  fresh ui
  switch_fails
  full_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ "$(st last_upgrade.step)" = 9 ] && [ "$(st last_upgrade.result)" = failed ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(st last_upgrade.backup)" = backups/custodexa-backup-1.13.0-20260930-101502.tar ] || return 1
  [ -f "$ROOT/$(st last_upgrade.backup)" ] || return 1
  [ "$(st last_upgrade.backup_kind)" = script ] || return 1
  [ "$(st last_upgrade.snapshot)" = logs/upgrade-20260930-101502.before.txt ] && [ -s "$ROOT/$(st last_upgrade.snapshot)" ] \
    || { cat "$ROOT/state.json"; return 1; }
  # The new version never started.
  [ -z "$(st last_upgrade.new_started_at)" ] && ! grep -qx up "$DB/events"
}

@test "rollback records: step 10 and start write the record before up; a new upgrade clears it" {
  fresh ui
  mark_seen_at_up
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -n "$(st last_upgrade.new_started_at)" ] && grep -qx 'up marked' "$DB/events" && ! grep -qx 'up unmarked' "$DB/events" \
    || { cat "$DB/events"; return 1; }
  # Failed at the switch, then started by hand with `start`: recorded before the start.
  fresh ui
  switch_fails
  full_run en
  [ "$status" -eq 1 ] && [ -z "$(st last_upgrade.new_started_at)" ] || { echo "$output"; return 1; }
  mark_seen_at_up
  # The backend does not answer, so start runs up.
  touch "$UP/health.rc"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  grep -qx 'up marked' "$DB/events" && ! grep -qx 'up unmarked' "$DB/events" || { echo "$output"; cat "$DB/events"; return 1; }
  [ -n "$(st last_upgrade.new_started_at)" ] || return 1
  # A start while current still points at the old version records nothing.
  fresh ui
  bk_state_set current.kind package
  bk_state_set last_upgrade.to 1.13.2
  mark_seen_at_up
  touch "$UP/health.rc"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  grep -qx 'up unmarked' "$DB/events" && [ -z "$(st last_upgrade.new_started_at)" ] || { echo "$output"; cat "$DB/events"; return 1; }
  # The next upgrade starts without it: one that fails at the switch has none.
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_twice_host ui || return 1
  [ -n "$(st last_upgrade.new_started_at)" ] || { cat "$ROOT/state.json"; return 1; }
  switch_fails
  clock 0 3 0 41 0 4 0 11
  printf '{"status":"ok","version":"1.16.0"}\n' >"$UP/health"
  run bash "$ROOT/releases/1.16.0/custodexa.sh" upgrade --lang en --yes </dev/null
  [ "$status" -eq 1 ] && [ "$(st last_upgrade.step)" = 9 ] && [ "$(st last_upgrade.to)" = 1.16.0 ] || { echo "$output"; return 1; }
  [ -z "$(st last_upgrade.new_started_at)" ] || { cat "$ROOT/state.json"; return 1; }
}

@test "rollback records: an upgrade interrupted after the switch lets rollback, load and restore in, and only them" {
  fresh ui
  switch_fails
  full_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  upgrade_at 11 in_progress
  jq -S 'with_entries(select(.key | startswith("last_upgrade.")))' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/up-before"
  local old_log
  old_log=$ROOT/$(st last_upgrade.log)
  cp "$old_log" "$BATS_TEST_TMPDIR/log-before"
  # load: let in, the upgrade's record unchanged.
  begin load
  [ "$status" -eq 0 ] || { echo "load: $output"; return 1; }
  diff <(jq -S 'with_entries(select(.key | startswith("last_upgrade.")))' "$ROOT/state.json") "$BATS_TEST_TMPDIR/up-before" || return 1
  # rollback: let in.
  begin rollback
  [ "$status" -eq 0 ] || { echo "rollback: $output"; return 1; }
  bk_state_set last_rollback.result succeeded
  # upgrade and backup: still kept out.
  begin backup
  [ "$status" -eq 3 ] || { echo "backup: $status"; return 1; }
  # restore: let in; the upgrade settled as failed and handed over, everything else kept.
  begin restore
  [ "$status" -eq 0 ] || { echo "restore: $output"; return 1; }
  [ "$(st last_upgrade.result)" = failed ] && [ "$(st last_upgrade.handed_to)" = restore ] && [ -n "$(st last_upgrade.handed_at)" ] \
    || { cat "$ROOT/state.json"; return 1; }
  diff <(jq -S 'with_entries(select(.key | startswith("last_upgrade.")) | select(.key != "last_upgrade.result"
      and .key != "last_upgrade.handed_to" and .key != "last_upgrade.handed_at"))' "$ROOT/state.json") \
    <(jq -S 'with_entries(select(.key != "last_upgrade.result"))' "$BATS_TEST_TMPDIR/up-before") || return 1
  diff "$BATS_TEST_TMPDIR/log-before" "$old_log" | grep -q '^> .*END   result=interrupted step=11 handed_to=restore$' \
    || { diff "$BATS_TEST_TMPDIR/log-before" "$old_log"; return 1; }
}

@test "rollback records: before the switch, or with another run unfinished, load and restore stay kept out" {
  fresh ui
  switch_fails
  full_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  local c
  upgrade_at 7 in_progress
  for c in load restore rollback; do
    begin "$c"
    [ "$status" -eq 3 ] || { echo "$c at step 7: $status"; return 1; }
  done
  upgrade_at 11 in_progress
  bk_state_set last_rollback.result in_progress
  bk_state_set last_rollback.step 2
  for c in load restore; do
    begin "$c"
    [ "$status" -eq 3 ] || { echo "$c with a rollback unfinished: $status"; return 1; }
  done
  [ "$(st last_upgrade.result)" = in_progress ] && [ -z "$(st last_upgrade.handed_to)" ]
}
