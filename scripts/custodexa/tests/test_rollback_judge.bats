#!/usr/bin/env bats
# What `rollback` decides before anything stops: whether the deployment is where an upgrade by this
# script left it, and whether the new version has left the database as it was. The cost is not
# symmetric: going back on a database the new version changed starts the old version on data it
# does not know, and it starts without complaint. So every case where the database cannot be read,
# or the record is not what an upgrade wrote, has to come out as "do not go back"; a case that
# comes out the other way fails here.

load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

# img <ref> <id>: the image ID this host reports for a reference ("" = not on this host).
img() {
  local key
  key=image_inspect_--format_{{.Id}}_$(printf '%s' "$1" | tr '/ :@' '----')
  rm -f "$FAKE_DOCKER_REPLAY/$key.out" "$FAKE_DOCKER_REPLAY/$key.rc"
  if [ -n "$2" ]; then printf '%s\n' "$2" >"$FAKE_DOCKER_REPLAY/$key.out"; else printf '1\n' >"$FAKE_DOCKER_REPLAY/$key.rc"; fi
}

# These are captured from a real upgrade, including its image records and snapshot.
switched() {
  local outcome=ready
  case $4 in 7) outcome=backup ;; 9) outcome=switch-linked ;; 10) outcome=start ;; esac
  rb_judge_host "$outcome" "$1" "$2"
}
rb_judge_host() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host "$1" ui "${2:-1.16.1}" "${3:-1.16.2}"
  OLD_B=$(up_digest old-backend) OLD_F=$(up_digest old-frontend)
  NEW_B=$(up_digest cfg-backend) NEW_F=$(up_digest cfg-frontend)
}

# db_down: no service runs, the database included.
db_down() {
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/hook.db"
  # shellcheck disable=SC2016 # expanded by the hook
  printf '#!/bin/bash\ncase " $* " in *" ps --status running --services "*) exit 0 ;; esac\nexec "$FAKE_DOCKER_REPLAY/hook.db" "$@"\n' \
    >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# decide <function...>: run the decision functions on $ROOT; prints the variables they set.
decide() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/backup.sh"
    . "$1/lib/rollback_check.sh"; CX_ROOT=$2; cx_bk_vars; cx_state_load "$2/state.json"; shift 2
    rc=0; for f in "$@"; do "$f" || { rc=$?; break; }; done
    printf "why=%s target=%s pre=%s basis=%s reason=%s added=%s bad=%s\n" "$CX_RB_WHY" "$CX_RB_TARGET" \
      "$CX_RB_PRESWITCH" "$CX_RB_BASIS" "$CX_RB_REASON" "${CX_RB_ADDED[*]+"${CX_RB_ADDED[*]}"}" \
      "${CX_RB_IMG_BAD[*]+"${CX_RB_IMG_BAD[*]}"}"
    exit "$rc"' _ "$SRC" "$ROOT" "$@"
}

setup() {
  backup_host ui
  : >"$DB/events"
  : >"$DB/db-calls"
}

@test "rollback premise: each way the record can differ from an upgrade after the switch is refused, in order" {
  # Never upgraded by the script.
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=none "* ]] || { echo "$output"; return 1; }
  switched 1.16.1 1.16.2 succeeded 13
  decide cx_rb_premise
  [ "$status" -eq 0 ] && [[ $output == *"why= target=1.16.1 pre=0 "* ]] || { echo "$output"; return 1; }
  # Gone back already: said before anything else, even with the record changed since.
  bk_state_set last_upgrade.result rolled_back
  bk_state_set current.version 1.16.1
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=already "* ]] || { echo "$output"; return 1; }
  # Stopped before the switch: said before the version relation (which is not there yet).
  switched 1.16.1 1.16.2 failed 7
  bk_state_set current.version 1.16.1
  bk_state_set previous.version 1.15.2
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=before_switch "* ]] || { echo "$output"; return 1; }
  # The version record changed since the upgrade (a restore, say).
  switched 1.16.1 1.16.2 succeeded 13
  bk_state_set current.version 1.16.3
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=changed "* ]] || { echo "$output"; return 1; }
  # current points elsewhere than the record says.
  switched 1.16.1 1.16.2 succeeded 13
  ln -sfn releases/1.16.1 "$ROOT/current"
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=link "* ]] || { echo "$output"; return 1; }
  # The version before is older than 1.16.0.
  switched 1.15.2 1.16.0 succeeded 13
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=too_old "* ]] || { echo "$output"; return 1; }
  # No database call for any of this.
  [ ! -s "$DB/db-calls" ]
}

@test "rollback premise: the three points inside the switch step are each recoverable" {
  # Step 9 on record, the switch not saved: still 1.16.1 everywhere; going back has nothing to swap.
  rb_judge_host before-switch
  decide cx_rb_premise cx_rb_images
  [ "$status" -eq 0 ] && [[ $output == *"why= target=1.16.1 pre=1 "* ]] || { echo "$output"; return 1; }
  # Saved, current not moved yet.
  rb_judge_host switch-recorded
  decide cx_rb_premise
  [ "$status" -eq 0 ] && [[ $output == *"pre=0 "* ]] || { echo "$output"; return 1; }
  # current moved (the root script link is the next thing).
  switched 1.16.1 1.16.2 failed 9
  decide cx_rb_premise
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # The same link mismatch after step 9 is not one of them.
  switched 1.16.1 1.16.2 failed 10
  ln -sfn releases/1.16.1 "$ROOT/current"
  decide cx_rb_premise
  [ "$status" -eq 1 ] && [[ $output == *"why=link "* ]] || { echo "$output"; return 1; }
}

@test "rollback judge: never started, same migrations, listed as compatible; anything unknown is changed" {
  # Failed at the switch, the new version never started: no database call at all.
  switched 1.16.1 1.16.2 failed 9
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=not_started "* ]] && [ ! -s "$DB/db-calls" ] || { echo "$output"; return 1; }
  # The same, after `start` ran the new version: the database is read.
  touch "$DB/rb.health"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  rm "$DB/rb.health"
  [ -n "$(st last_upgrade.new_started_at)" ]
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=same_migrations "* ]] && grep -q 'psql migrations' "$DB/db-calls" \
    || { echo "$output"; cat "$DB/db-calls"; return 1; }
  # One migration more: changed, and named.
  switched 1.16.1 1.16.2 succeeded 13
  printf '%s\n' 20261101_session_tag_index >>"$DB/migrations"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=changed added=20261101_session_tag_index "* ]] || { echo "$output"; return 1; }
  # ... unless this release lists the version before.
  jq '.rollback_compatible = ["1.16.1"]' "$ROOT/releases/1.16.2/MANIFEST.json" >"$BATS_TEST_TMPDIR/m"
  cp "$BATS_TEST_TMPDIR/m" "$ROOT/releases/1.16.2/MANIFEST.json"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=compatible "* ]] || { echo "$output"; return 1; }
  # The query fails; the snapshot is gone; the database is not running: each is unreadable.
  switched 1.16.1 1.16.2 succeeded 13
  printf '1\n' >"$DB/migrations.rc"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=unreadable "* ]] || { echo "$output"; return 1; }
  rm -f "$DB/migrations.rc" "$ROOT/$(st last_upgrade.snapshot)"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=unreadable "* ]] || { echo "$output"; return 1; }
  switched 1.16.1 1.16.2 succeeded 13
  db_down
  : >"$DB/events"
  : >"$DB/db-calls"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=unreadable "* ]] && [ ! -s "$DB/db-calls" ] || { echo "$output"; return 1; }
  # Deciding started nothing.
  ! grep -Eq '^(up|start)' "$DB/events"
}

@test "rollback images: each image of the version before must be here with the ID recorded then" {
  switched 1.16.1 1.16.2 succeeded 13
  decide cx_rb_premise cx_rb_images
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  img ghcr.io/custodexa/backend:1.16.1 ""
  img ghcr.io/custodexa/frontend:1.16.1 "$NEW_F"
  decide cx_rb_premise cx_rb_images
  [ "$status" -eq 1 ] && [[ $output == *"bad=backend missing frontend differs $OLD_F $NEW_F"* ]] || { echo "$output"; return 1; }
  rm "$ROOT/releases/1.16.1/images.env"
  decide cx_rb_premise cx_rb_images
  [ "$status" -eq 1 ] && [[ $output == *"bad=release missing"* ]] || { echo "$output"; return 1; }
}

@test "rollback start: the record that the new version may run is written first; when it cannot be, nothing starts" {
  switched 1.16.1 1.16.2 failed 9
  # Going back to the version after the upgrade: current points at it.
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/rollback_check.sh"
    CX_ROOT=$2; cx_state_load "$2/state.json"; cx_state_save() { return 1; }
    cx_rb_start' _ "$SRC" "$ROOT"
  [ "$status" -ne 0 ] && ! grep -q '^up ' "$DB/events" && [ -z "$(st last_upgrade.new_started_at)" ] || { echo "$output"; cat "$DB/events"; return 1; }
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/rollback_check.sh"
    CX_ROOT=$2; cx_state_load "$2/state.json"; cx_rb_start' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] && grep -q '^up ' "$DB/events" && [ -n "$(st last_upgrade.new_started_at)" ] || { echo "$output"; return 1; }
  # Going back to the version before: nothing to record, and it starts.
  bk_state_set last_upgrade.new_started_at ""
  ln -sfn releases/1.16.1 "$ROOT/current"
  : >"$DB/events"
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/rollback_check.sh"
    CX_ROOT=$2; cx_state_load "$2/state.json"; cx_rb_start' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] && grep -q '^up ' "$DB/events" && [ -z "$(st last_upgrade.new_started_at)" ]
}
