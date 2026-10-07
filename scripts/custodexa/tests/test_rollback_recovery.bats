#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

fresh() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  rollback_host "${1:-ready}"
}
settled() {
  [ "$(rb_state current.version)" = "$1" ] && [ "$(readlink "$ROOT/current")" = "releases/$1" ] || return 1
  [ "$(readlink "$ROOT/custodexa.sh")" = current/custodexa.sh ] || return 1
  [ "$(rb_state last_rollback.result)" = "$2" ] || return 1
}

@test "rollback recovery: before and after every step, resume preserves identity and finishes the old version" {
  local fn when identity
  for fn in cx_rb_stop_apps cx_rb_switch cx_rb_start cx_rb_check; do
    for when in before after; do
      fresh
      rb_interrupt "$fn" "$when"
      rb_run en --yes
      [ "$status" -eq 1 ] || { echo "$fn $when: $output"; return 1; }
      [ "$(rb_state last_rollback.result)" = in_progress ]
      identity=$(rb_identity)
      rb_run en --resume
      [ "$status" -eq 0 ] || { echo "$fn $when: $output"; return 1; }
      settled 1.16.1 succeeded
      [ "$(rb_state previous.version)" = 1.16.2 ]
      [ "$identity" = "$(rb_identity)" ]
      [ "$(rb_state last_rollback.log)" != "$(rb_state last_rollback.attempt_log)" ]
      grep -q ' RESUME logs/rollback-' "$ROOT/$(rb_state last_rollback.log)"
    done
  done
}

@test "rollback recovery: before and after every step, revert returns to the upgraded version" {
  local fn when identity
  for fn in cx_rb_stop_apps cx_rb_switch cx_rb_start cx_rb_check; do
    for when in before after; do
      fresh
      rb_interrupt "$fn" "$when"
      rb_run en --yes
      [ "$status" -eq 1 ] || { echo "$fn $when: $output"; return 1; }
      identity=$(rb_identity)
      rb_run en --revert --yes
      [ "$status" -eq 0 ] || { echo "$fn $when: $output"; return 1; }
      settled 1.16.2 reverted
      [ "$(rb_state last_rollback.direction)" = revert ]
      [ "$(rb_state last_upgrade.result)" = succeeded ]
      [ "$identity" = "$(rb_identity)" ]
    done
  done
}

@test "rollback recovery: resume after every interrupted revert keeps the recorded direction and endpoints" {
  local fn when identity
  for fn in cx_rb_stop_apps cx_rb_switch cx_rb_start cx_rb_check; do
    for when in before after; do
      fresh
      touch "$DB/rb.health"
      rb_run en --yes
      [ "$status" -eq 1 ] || { echo "$output"; return 1; }
      rm "$DB/rb.health"
      identity=$(rb_identity)
      rb_interrupt "$fn" "$when"
      rb_run en --revert --yes
      [ "$status" -eq 1 ] || { echo "$fn $when: $output"; return 1; }
      [[ $output == *'rollback --resume'* && $output != *'rollback --revert'* ]]
      [ "$(rb_state last_rollback.direction)" = revert ]
      [ "$(rb_state last_rollback.target)" = 1.16.2 ]
      rb_run en --resume
      [ "$status" -eq 0 ] || { echo "$fn $when: $output"; return 1; }
      settled 1.16.2 reverted
      [ "$identity" = "$(rb_identity)" ]
    done
  done
}

@test "rollback recovery: a fresh drain refusal cancels, but a resumed or reverted drain refusal stays unfinished" {
  local mode before
  fresh
  touch "$DB/rb.metrics"
  rb_run en --yes
  [ "$status" -eq 3 ] && [ "$(rb_state last_rollback.result)" = cancelled ] || { echo "$output"; return 1; }
  ! grep -q '^stop' "$DB/events" || return 1
  [[ $output != *'rollback --resume'* && $output != *'rollback --revert'* ]]
  for mode in resume revert; do
    fresh
    touch "$DB/rb.health"
    rb_run en --yes
    [ "$status" -eq 1 ]
    rm "$DB/rb.health"
    touch "$DB/rb.metrics"
    : >"$DB/events"
    before=$(rb_state last_rollback.step)
    rb_run en "--$mode" --yes
    [ "$status" -eq 1 ] && [ "$(rb_state last_rollback.result)" = in_progress ] || { echo "$output"; return 1; }
    [ "$(rb_state last_rollback.step)" = "$before" ]
    ! grep -q '^stop' "$DB/events" || return 1
    [[ $output != *'Nothing was changed'* && $output == *'rollback --resume'* ]]
    rm "$DB/rb.metrics"
    rb_run en --resume
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    if [ "$mode" = revert ]; then settled 1.16.2 reverted; else settled 1.16.1 succeeded; fi
  done
}

@test "rollback recovery: a resumed attempt stops applications again and checks a migration committed after a manual start" {
  fresh
  rb_interrupt cx_rb_stop_apps after
  rb_run en --yes
  [ "$status" -eq 1 ]
  # The real start command may need up; the stopped backend is not healthy yet.
  touch "$DB/rb.health"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  rm "$DB/rb.health"
  printf 'after_manual_start\n' >>"$DB/migrations"
  : >"$DB/events"
  rb_run en --resume
  [ "$status" -eq 1 ] && [ "$(rb_state last_rollback.result)" = refused ] || { echo "$output"; return 1; }
  grep -q '^stop guacd backend frontend' "$DB/events"
  grep -q '^psql migrations' "$DB/events"
  ! grep -Eq '^up|^stop postgres' "$DB/events" || return 1
  # The same safety rule across an interrupted switch: a real start must invalidate
  # its saved check, even if the database is stopped again before the retry.
  fresh
  rb_interrupt cx_rb_link before
  rb_run en --yes
  [ "$status" -eq 1 ]
  [ -n "$(rb_state last_rollback.switch_checked)" ]
  touch "$DB/rb.health"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  rm "$DB/rb.health"
  [ -z "$(rb_state last_rollback.switch_checked)" ]
  printf 'after_manual_start\n' >>"$DB/migrations"
  : >"$DB/running"
  printf 'false 2026-09-30T02:16:13Z\n' >"$UP/running"
  : >"$DB/events"
  rb_run en --resume
  [ "$status" -eq 1 ] && [ "$(rb_state last_rollback.result)" = refused ] || { echo "$output"; return 1; }
  ! grep -q '^up' "$DB/events" || return 1
}

@test "rollback recovery: pending rollback rejects a new one, backup and upgrade, while start and status remain usable" {
  fresh
  touch "$DB/rb.health"
  rb_run en --yes
  [ "$status" -eq 1 ] && [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  local identity=$output
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  run bash "$ROOT/custodexa.sh" backup --yes --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  run bash "$ROOT/custodexa.sh" upgrade 1.16.2 --yes --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  rm "$DB/rb.health"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [ "$status" -ne 3 ] && [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  # Execute the printed logs command from / (without sudo inside the test container).
  local command
  command=$(printf '%s\n' "$identity" | sed -n 's/^    sudo \(docker compose .* logs --tail 50 backend\)$/\1/p')
  [ -n "$command" ]
  run bash -c 'cd / && eval "$1"' _ "$command"
  grep -q -- "-f $ROOT/current/compose.yml logs --tail 50 backend" "$FAKE_DOCKER_LOG"
}

@test "rollback recovery: reverting a never-started upgrade records the new start before up and never clears it" {
  fresh switch-linked
  rb_interrupt cx_rb_switch after
  rb_run en --yes
  [ "$status" -eq 1 ] && [ -z "$(rb_state last_upgrade.new_started_at)" ] || { echo "$output"; return 1; }
  rb_run en --revert --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -Eq '^up releases/1.16.2 marked=.' "$DB/events"
  [ -n "$(rb_state last_upgrade.new_started_at)" ]
  printf 'after_revert\n' >>"$DB/migrations"
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *after_revert* ]] || { echo "$output"; return 1; }
}

@test "rollback recovery: interruption before writing the reversal keeps the old direction and both commands" {
  fresh
  touch "$DB/rb.health"
  rb_run en --yes
  [ "$status" -eq 1 ]
  rm "$DB/rb.health"
  rb_interrupt cx_rb_save before
  rb_run en --revert --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ "$(rb_state last_rollback.direction)" = rollback ]
  [ "$(rb_state last_rollback.target)" = 1.16.1 ]
  [[ $output == *'rollback --resume'* && $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
  rb_run en --resume
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "rollback recovery: a crash after the database stops or state saves repairs each link once" {
  local point dir
  for point in database current script; do
    fresh
    if [ "$point" = database ]; then
      hook_before 'case " $* " in *" compose "*" stop postgres "*)
        if [ ! -e "$DB/crashed" ]; then
          touch "$DB/crashed"; : >"$DB/running"
          kill -TERM "$PPID"; exit 1
        fi ;; esac'
    else
      for dir in "$ROOT"/releases/*; do
        cat >>"$dir/lib/cmd_rollback.sh" <<HOOK
cx_rb_link() {
  if [[ \$1 == */$(if [ "$point" = current ]; then echo current; else echo custodexa.sh; fi) ]] && [ ! -e "\$DB/crashed" ]; then
    touch "\$DB/crashed"; kill -TERM \$\$
  fi
  cx_up_link "\$@"
}
HOOK
      done
    fi
    rb_run en --yes
    [ "$status" -eq 1 ] || { echo "$point: $output"; return 1; }
    rb_run en --resume
    [ "$status" -eq 0 ] || { echo "$point: $output"; cat "$DB/events"; return 1; }
    settled 1.16.1 succeeded
    [ "$(rb_state previous.version)" = 1.16.2 ]
  done
}
