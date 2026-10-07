#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

fresh() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host "${1:-ready}" "${2:-ui}" "${3:-1.16.1}"
}
normalized() {
  printf '%s\n' "$output" | sed -E "s#$ROOT#/opt/custodexa#g; s/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9:]+/2026-11-05T09:30:12+0800/g; s/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/2026-11-05 09:30/g"
}
screen() {
  local name=rollback-$1.$RB_LANG.txt path
  path=$TESTS_DIR/snapshots/$name
  if [ ! -f "$path" ]; then
    printf '# SNAPSHOT %s %s\n' "$name" "$(normalized | base64 -w0)" >&3
    return 1
  fi
  diff <(normalized) "$path"
}
status_screen() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=$3; cx_load_libs "$1"
    . "$1/lib/cmd_status.sh"; CX_ROOT=$2; cx_state_load "$2/state.json"; cmd_status_upgrade' _ "$SRC" "$ROOT" "$RB_LANG"
}
restore_ready() {
  rm -rf "$ROOT"
  cp -a "$DB/ready" "$ROOT"
  printf '%s\n' postgres guacd backend frontend >"$DB/running"
  printf 'true 0001-01-01T00:00:00Z\n' >"$UP/running"
  rm -f "$DB"/rb.* "$DB/migrations.rc"
  db_default
  : >"$DB/events"
}

@test "rollback screens: refusal premises, database reasons, backup forms and missing images in three languages" {
  local name errs=0 dir key
  for RB_LANG in en zh-TW ja; do
    fresh
    cp -a "$ROOT" "$DB/ready"
    for name in none not-installed pending-backup pending-rollback changed-record link already old changed unreadable missing-snapshot folder external missing-backup missing-images; do
      restore_ready
      case $name in
        none) bk_state_set last_upgrade.result '' ;;
        not-installed) bk_state_set current.kind '' ;;
        pending-backup) bk_state_set last_backup.result in_progress; bk_state_set last_backup.step 2 ;;
        pending-rollback)
          touch "$DB/rb.health"
          rb_run "$RB_LANG" --yes
          [ "$status" -eq 1 ] || { echo "$output"; return 1; }
          rm "$DB/rb.health" ;;
        changed-record) bk_state_set current.version 1.16.3 ;;
        link) ln -sfn releases/1.16.1 "$ROOT/current" ;;
        already) rb_run "$RB_LANG" --yes; [ "$status" -eq 0 ] || { echo "$output"; return 1; } ;;
        old) bk_state_set previous.version 1.15.2; bk_state_set last_upgrade.from 1.15.2 ;;
        changed) echo new_structure >>"$DB/migrations" ;;
        unreadable) echo 1 >"$DB/migrations.rc" ;;
        missing-snapshot) rm "$ROOT/$(rb_state last_upgrade.snapshot)" ;;
        folder|external|missing-backup)
          echo new_structure >>"$DB/migrations"
          bk_state_set last_upgrade.backup backups/own
          mkdir "$ROOT/backups/own"
          case $name in external) bk_state_set last_upgrade.backup_kind external ;; missing-backup) rmdir "$ROOT/backups/own" ;; esac ;;
        missing-images)
          key=image_inspect_--format_{{.Id}}_ghcr.io-custodexa-backend-1.16.1
          echo 1 >"$FAKE_DOCKER_REPLAY/$key.rc"
          docker_says image_inspect_--format_{{.Id}}_ghcr.io-custodexa-frontend-1.16.1 "$(up_digest wrong)" ;;
      esac
      cp "$ROOT/state.json" "$DB/before"
      local link=$(readlink "$ROOT/current")
      : >"$DB/events"
      rb_run "$RB_LANG" --yes
      [ "$status" -eq 3 ] || { echo "$name: $output"; return 1; }
      cmp "$ROOT/state.json" "$DB/before" || return 1
      [ "$(readlink "$ROOT/current")" = "$link" ] || return 1
      ! grep -Eq '^(stop|up|start)' "$DB/events" || return 1
      screen "refused-$name" || errs=1
    done
    fresh backup
    rb_run "$RB_LANG" --yes
    [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    screen refused-before-switch || errs=1
  done
  [ "$errs" = 0 ]
}

@test "rollback screens: three bases, revert completion and failure at each step in three languages" {
  local name errs=0 dir
  for RB_LANG in en zh-TW ja; do
    fresh
    cp -a "$ROOT" "$DB/ready"
    for name in same compatible stop-failed switch-failed start-failed health-failed image-failed drain-cancelled; do
      restore_ready
      case $name in
        compatible)
          echo new_structure >>"$DB/migrations"
          jq '.rollback_compatible=["1.16.1"]' "$ROOT/releases/1.16.2/MANIFEST.json" >"$DB/m"
          cp "$DB/m" "$ROOT/releases/1.16.2/MANIFEST.json" ;;
        stop-failed) touch "$DB/rb.stop" ;;
        switch-failed)
          for dir in "$ROOT"/releases/*; do printf '\ncx_rb_link() { return 1; }\n' >>"$dir/lib/cmd_rollback.sh"; done ;;
        start-failed) touch "$DB/rb.up" ;;
        health-failed) touch "$DB/rb.health" ;;
        image-failed) up_digest wrong >"$UP/image.backend" ;;
        drain-cancelled) touch "$DB/rb.metrics" ;;
      esac
      rb_run "$RB_LANG" --yes
      case $name in same|compatible) [ "$status" -eq 0 ] ;; drain-cancelled) [ "$status" -eq 3 ] ;; *) [ "$status" -eq 1 ] ;; esac || { echo "$name: $output"; return 1; }
      screen "$name" || errs=1
      rm -f "$UP/image.backend"
    done
    fresh switch-linked
    rb_run "$RB_LANG" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen not-started || errs=1
    fresh
    touch "$DB/rb.health"
    rb_run "$RB_LANG" --yes
    rm "$DB/rb.health"
    rb_run "$RB_LANG" --revert --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen reverted || errs=1
  done
  [ "$errs" = 0 ]
}

@test "rollback screens: final gate, recovery drain, reverse direction and status results in three languages" {
  local name errs=0
  for RB_LANG in en zh-TW ja; do
    for name in refused refused-interrupted resume-drain revert-drain revert-failed; do
      if [ "$name" = refused-interrupted ]; then fresh interrupted; else fresh; fi
      case $name in
        refused*) echo late_structure >"$DB/rb.race"; rb_run "$RB_LANG" --yes ;;
        *)
          touch "$DB/rb.health"
          rb_run "$RB_LANG" --yes
          rm "$DB/rb.health"
          case $name in
            resume-drain) touch "$DB/rb.metrics"; rb_run "$RB_LANG" --resume ;;
            revert-drain) touch "$DB/rb.metrics"; rb_run "$RB_LANG" --revert --yes ;;
            revert-failed) touch "$DB/rb.up"; rb_run "$RB_LANG" --revert --yes ;;
          esac ;;
      esac
      [ "$status" -eq 1 ] || { echo "$name: $output"; return 1; }
      screen "$name" || errs=1
      status_screen
      screen "status-$name" || errs=1
    done
    fresh
    rb_run "$RB_LANG" --yes
    status_screen
    screen status-complete || errs=1
    fresh
    touch "$DB/rb.health"
    rb_run "$RB_LANG" --yes
    rm "$DB/rb.health"
    rb_run "$RB_LANG" --revert --yes
    status_screen
    screen status-reverted || errs=1
    fresh interrupted
    run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=$3; cx_load_libs "$1"; CX_ROOT=$2; cx_begin restore' _ "$SRC" "$ROOT" "$RB_LANG"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    status_screen
    screen status-handed || errs=1
    # That restore finished: the upgrade it took over is settled (lib/run.sh).
    bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=$2
      cx_state_load "$2/state.json"; cx_run_upgrade_restored && cx_state_save "$2/state.json"' _ "$SRC" "$ROOT" || return 1
    status_screen
    screen status-settled || errs=1
  done
  [ "$errs" = 0 ]
}

@test "rollback screens: supported upgrades offer rollback on completion, failure and interrupted recovery" {
  local name errs=0
  for RB_LANG in en zh-TW ja; do
    for name in ready ready-failed checks; do
      fresh "$name"
      output=$RB_UP_OUTPUT
      [[ $output == *'custodexa.sh rollback'* ]] || { echo "$output"; return 1; }
      screen "upgrade-$name" || errs=1
    done
    fresh interrupted
    publish 1.16.3 1.12.4 20260816_schema_baseline 20260901_add_x
    run bash "$ROOT/custodexa.sh" upgrade 1.16.3 --yes --lang "$RB_LANG" </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'custodexa.sh rollback'* ]] || { echo "$output"; return 1; }
    screen upgrade-interrupted || errs=1
  done
  [ "$errs" = 0 ]
}

@test "rollback screens: upgrades from an older version retain the exact pre-rollback screens" {
  local name baseline expected
  for RB_LANG in en zh-TW ja; do
    for name in ready ready-failed checks interrupted; do
      for baseline in yes no; do
        rm -rf "${BATS_TEST_TMPDIR:?}"/*
        RB_BASELINE=""
        [ "$baseline" != yes ] || RB_BASELINE=$TESTS_DIR/rollback_legacy_screens.bash
        rollback_host "$name" ui 1.15.2 1.16.0
        output=$RB_UP_OUTPUT
        if [ "$name" = interrupted ]; then
          # Use the original upgrade script, whose displayed recovery is being compared.
          [ "$baseline" != yes ] || cat "$RB_BASELINE" >>"$ROOT/releases/1.16.0/lib/upgrade_steps.sh"
          run bash "$ROOT/releases/1.16.0/custodexa.sh" upgrade 1.16.0 --lang "$RB_LANG" --yes </dev/null
          [ "$status" -eq 3 ] || { echo "$output"; return 1; }
        fi
        if [ "$baseline" = yes ]; then
          expected=$(normalized)
        else
          diff <(printf '%s\n' "$expected") <(normalized) || return 1
        fi
      done
    done
  done
}
