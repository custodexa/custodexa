#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

setup() { rollback_host ready; }

unchanged_before() {
  cp "$ROOT/state.json" "$DB/state.before"
  readlink "$ROOT/current" >"$DB/link.before"
}
unchanged_after() {
  cmp "$ROOT/state.json" "$DB/state.before" || return 1
  [ "$(readlink "$ROOT/current")" = "$(cat "$DB/link.before")" ] || return 1
  ! grep -Eq '^(stop|up|start)' "$DB/events"
}

@test "rollback entry: equal migrations switch back without touching data, configuration, certificates or backups" {
  local protected
  protected=$(tree_of "$ROOT/data"; tree_of "$ROOT/tls"; sha256sum "$ROOT/.env"; tree_of "$ROOT/backups")
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; cat "$DB/events"; return 1; }
  [ "$(rb_state current.version)" = 1.16.1 ]
  [ "$(rb_state previous.version)" = 1.16.2 ]
  [ "$(rb_state last_rollback.basis)" = same_migrations ]
  [ "$(rb_state last_rollback.result)" = succeeded ]
  [ "$(rb_state last_upgrade.result)" = rolled_back ]
  [ "$(readlink "$ROOT/current")" = releases/1.16.1 ]
  [ "$(readlink "$ROOT/custodexa.sh")" = current/custodexa.sh ]
  [ "$protected" = "$(tree_of "$ROOT/data"; tree_of "$ROOT/tls"; sha256sum "$ROOT/.env"; tree_of "$ROOT/backups")" ]
  grep -q 'psql migrations' "$DB/events"
  [ "$(grep -c '^stop' "$DB/events")" -eq 2 ]
  local ordered
  ordered=$(sed -n '/^drain/,$p' "$DB/events" | sed 's/ marked=.*//')
  [ "$ordered" = $'drain\nstop guacd backend frontend\npsql migrations\nstop postgres\nswitch releases/1.16.1\nup releases/1.16.1\nhealth\nid custodexa-backend\nid custodexa-frontend\nid custodexa-postgres\nid custodexa-guacd' ] || { cat "$DB/events"; return 1; }
  unchanged_before
  : >"$DB/events"
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *'one version only'* ]] || { echo "$output"; return 1; }
  unchanged_after
  run bash "$ROOT/custodexa.sh" upgrade 1.16.2 --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'Run again with --yes.'* ]] || { echo "$output"; return 1; }
}

@test "rollback entry: preview needs confirmation and neither refusal nor cancellation changes the deployment" {
  unchanged_before
  rb_run en
  [ "$status" -eq 3 ] && [[ $output == *'Run again with --yes.'* ]] || { echo "$output"; return 1; }
  unchanged_after
  [ -z "$(rb_state last_rollback.result)" ]
}

@test "rollback entry: changed and unreadable databases refuse with the actual backup file or the manual guide" {
  local condition backup
  backup=$(rb_state last_upgrade.backup)
  for condition in changed unreadable snapshot; do
    case $condition in
      changed) echo new_structure >>"$DB/migrations" ;;
      unreadable) sed -i '/new_structure/d' "$DB/migrations"; echo 1 >"$DB/migrations.rc" ;;
      snapshot) rm "$DB/migrations.rc"; rm "$ROOT/$(rb_state last_upgrade.snapshot)" ;;
    esac
    unchanged_before
    rb_run en --yes
    [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    [[ $output == *"restore $ROOT/$backup"* ]] && [ -f "$ROOT/$backup" ] || { echo "$output"; return 1; }
    if [ "$condition" = changed ]; then [[ $output == *new_structure* ]]; else [[ $output == *'could not be read'* ]]; fi
    unchanged_after
  done
  for condition in folder external absent; do
    mkdir -p "$ROOT/backups/own"
    bk_state_set last_upgrade.backup backups/own
    case $condition in
      external) bk_state_set last_upgrade.backup_kind external ;;
      absent) bk_state_set last_upgrade.backup_kind script; bk_state_set last_upgrade.backup backups/missing.tar ;;
    esac
    unchanged_before
    rb_run en --yes
    [ "$status" -eq 3 ] && [[ $output != *'custodexa.sh restore '* ]] || { echo "$output"; return 1; }
    [[ $output == *'restore the backup above by hand'* ]] || { echo "$output"; return 1; }
    unchanged_after
  done
}

@test "rollback entry: the last check rejects a new migration after stopping only application services" {
  echo late_structure >"$DB/rb.race"
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ "$(rb_state last_rollback.result)" = refused ]
  [ "$(rb_state current.version)" = 1.16.2 ]
  [ "$(readlink "$ROOT/current")" = releases/1.16.2 ]
  [ "$(cat "$DB/running")" = postgres ]
  ! grep -Eq '^up|^stop postgres' "$DB/events" || return 1
  [[ $output == *'application services are stopped'* && $output == *'custodexa.sh start'* ]]
}

@test "rollback entry: the three switch boundaries recover, and only a never-started version skips the query" {
  local outcome
  for outcome in before-switch switch-recorded switch-linked; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    rollback_host "$outcome"
    rb_run en --yes
    [ "$status" -eq 0 ] || { echo "$outcome: $output"; return 1; }
    [ "$(rb_state current.version)" = 1.16.1 ]
    [ "$(readlink "$ROOT/current")" = releases/1.16.1 ]
    [ "$(readlink "$ROOT/custodexa.sh")" = current/custodexa.sh ]
    [ "$(rb_state last_rollback.basis)" = not_started ]
    ! grep -q '^psql' "$DB/events" || return 1
  done
}

@test "rollback entry: an interrupted upgrade permits rollback but still blocks backup and upgrade" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host interrupted-start
  [ "$(rb_state last_upgrade.step)" = 10 ]
  run bash "$ROOT/custodexa.sh" backup --yes --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  publish 1.16.3 1.12.4 20260816_schema_baseline 20260901_add_x
  run bash "$ROOT/custodexa.sh" upgrade 1.16.3 --yes --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "rollback entry: versions before the supported minimum refuse without querying the database" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host ready ui 1.15.2
  unchanged_before
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *'1.16.0 or later'* ]] || { echo "$output"; return 1; }
  unchanged_after
  [ ! -s "$DB/db-calls" ]
}

@test "rollback entry: an upgrade stopped after backup explains the recovery before checking version relationships" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host backup
  unchanged_before
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *'stopped at step 7'* && $output == *'custodexa.sh upgrade 1.16.2'* ]] || { echo "$output"; return 1; }
  [ "$(rb_state last_upgrade.backup_kind)" = script ]
  unchanged_after
}

@test "rollback entry: an upgrade with an own backup keeps its actual reference in the manual restore guide" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host external
  [ "$(rb_state last_upgrade.backup_kind)" = external ]
  [ -f "$ROOT/$(rb_state last_upgrade.backup)/external.txt" ]
  printf 'new_structure\n' >>"$DB/migrations"
  unchanged_before
  rb_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"$ROOT/$(rb_state last_upgrade.backup)/external.txt"* && $output != *'custodexa.sh restore '* ]]
  unchanged_after
}

@test "rollback entry: start cannot start the new version if its durable marker cannot be saved" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host switch-linked
  touch "$DB/rb.health"
  printf '\ncx_state_save() { return 1; }\n' >>"$ROOT/current/lib/cmd_start.sh"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ -z "$(rb_state last_upgrade.new_started_at)" ]
  ! grep -q '^up' "$DB/events" || return 1
}

# restore_finished: what a restore of the pre-upgrade backup that finished leaves (lib/restore_finish.sh):
# the version before is current again and the swapped-out one previous, the restore succeeded, and the
# upgrade's record goes through the real settlement of lib/run.sh.
restore_finished() {
  local k cur
  for k in version release_dir images_env image_ids; do
    cur=$(rb_state "current.$k")
    bk_state_set "current.$k" "$(rb_state "previous.$k")"
    bk_state_set "previous.$k" "$cur"
  done
  ln -sfn "releases/$(rb_state current.version)" "$ROOT/current"
  bk_state_set last_restore.result succeeded
  bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=$2
    cx_state_load "$2/state.json"; cx_run_upgrade_restored && cx_state_save "$2/state.json"' _ "$SRC" "$ROOT"
}

# upgrade_status: the status section of the last upgrade in English, then whether it warned (the
# exit code 4 of status).
upgrade_status() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/cmd_status.sh"
    CX_ROOT=$2; cx_state_load "$2/state.json"; cmd_status_upgrade; printf "warned=%s\n" "$CX_STATUS_WARNED"' _ "$SRC" "$ROOT"
}

@test "rollback entry: a failed upgrade keeps upgrade out until a restore finishes; then upgrade runs and rollback has nothing to go back to" {
  local outcome before
  for outcome in ready-failed interrupted; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    rollback_host "$outcome"
    publish 1.16.3 1.12.4 20260816_schema_baseline 20260901_add_x
    if [ "$outcome" = interrupted ]; then
      # The restore hand-over settles the interrupted upgrade as failed first (lib/run.sh).
      bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=$2; cx_begin restore' _ "$SRC" "$ROOT" \
        >/dev/null 2>&1 || return 1
      [ "$(rb_state last_upgrade.handed_to)" = restore ] || return 1
      # That restore was then given up: a restore that did not finish settles nothing.
      bk_state_set last_restore.result abandoned
    fi
    [ "$(rb_state last_upgrade.result)" = failed ] && [ "$(rb_state last_upgrade.step)" -ge 9 ] || { cat "$ROOT/state.json"; return 1; }
    # Not handled yet: the upgrade stays refused with its recovery commands, as before.
    run bash "$ROOT/custodexa.sh" upgrade 1.16.3 --lang en </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'The last upgrade stopped at step'* && $output != *'Run again with --yes.'* ]] \
      || { echo "$outcome before restore: $output"; return 1; }
    [ -z "$(rb_state last_upgrade.settled_by)" ] || return 1
    # status: the failure is a fault until then, with no word of a restore that dealt with it.
    upgrade_status
    [ "$status" -eq 0 ] && [[ ${lines[1]} == '  [FAIL] 1.16.1 -> 1.16.2 failed at step '* ]] &&
      [ "${lines[-1]}" = warned=1 ] && [[ $output != *'dealt with this failure'* ]] \
      || { echo "$outcome status before restore: $output"; return 1; }
    before=$(jq -S 'with_entries(select(.key | startswith("last_upgrade.")))' "$ROOT/state.json")
    restore_finished || return 1
    [ "$(rb_state last_upgrade.settled_by)" = restore ] && [ -n "$(rb_state last_upgrade.settled_at)" ] || return 1
    diff <(jq -S 'with_entries(select(.key | startswith("last_upgrade.")) | select(.key != "last_upgrade.settled_by" and
      .key != "last_upgrade.settled_at"))' "$ROOT/state.json") <(printf '%s\n' "$before") || return 1
    # status: the same failure, no longer a fault, and the restore that settled it under the log path.
    upgrade_status
    [ "$status" -eq 0 ] && [[ ${lines[1]} == '  [ OK ] 1.16.1 -> 1.16.2 failed at step '* ]] &&
      [ "${lines[-3]}" = "         The restore on $(rb_state last_upgrade.settled_at | sed -E 's/^(.{10})T(.{5}).*/\1 \2/') dealt with this failure;" ] &&
      [ "${lines[-2]}" = '         you can upgrade again' ] && [ "${lines[-1]}" = warned=0 ] && [[ $output != *'[FAIL]'* ]] \
      || { echo "$outcome status after restore: $output"; return 1; }
    # Settled: the upgrade preflight lets the next upgrade through to its confirmation.
    run bash "$ROOT/custodexa.sh" upgrade 1.16.3 --lang en </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'Run again with --yes.'* && $output != *'The last upgrade stopped at step'* ]] \
      || { echo "$outcome after restore: $output"; return 1; }
    # rollback: nothing to go back to, the version record changed since the upgrade; nothing changed.
    : >"$DB/events"
    unchanged_before
    rb_run en --yes
    [ "$status" -eq 3 ] && [[ $output == *'There is no previous version to go back to.'* &&
      $output == *'The version record has changed since the last upgrade.'* ]] || { echo "$outcome rollback: $output"; return 1; }
    unchanged_after || return 1
  done
}
