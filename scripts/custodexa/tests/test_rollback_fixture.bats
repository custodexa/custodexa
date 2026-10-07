#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

@test "rollback host: real upgrade writes a finished record and the backup snapshot" {
  rollback_host ready
  [ "$(rb_state last_upgrade.result)" = succeeded ]
  [ "$(rb_state last_upgrade.from)" = 1.16.1 ]
  [ "$(rb_state last_upgrade.to)" = 1.16.2 ]
  [ "$(rb_state previous.version)" = 1.16.1 ]
  [ -s "$ROOT/$(rb_state last_upgrade.snapshot)" ]
  [ -f "$ROOT/$(rb_state last_upgrade.backup)" ]
  [ -n "$(rb_state last_upgrade.new_started_at)" ]
}

@test "rollback host: failures at backup, start, readiness, checks and an interruption use real steps" {
  local outcome step result
  for outcome in backup start ready-failed checks interrupted; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    rollback_host "$outcome"
    case $outcome in backup) step=7 ;; start) step=10 ;; ready-failed|interrupted) step=11 ;; checks) step=12 ;; esac
    result=failed; [ "$outcome" != interrupted ] || result=in_progress
    [ "$(rb_state last_upgrade.step)" = "$step" ]
    [ "$(rb_state last_upgrade.result)" = "$result" ]
    [ -s "$ROOT/$(rb_state last_upgrade.snapshot)" ]
    [ -f "$ROOT/$(rb_state last_upgrade.backup)" ]
  done
}

@test "rollback host: switch step before state, after state and after current link are distinct" {
  local outcome
  for outcome in before-switch switch-recorded switch-linked; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    rollback_host "$outcome"
    [ "$(rb_state last_upgrade.step)" = 9 ]
    [ -z "$(rb_state last_upgrade.new_started_at)" ]
    if [ "$outcome" = before-switch ]; then
      [ "$(rb_state current.version)" = 1.16.1 ]
    else
      [ "$(rb_state current.version)" = 1.16.2 ]
      [ "$(rb_state previous.version)" = 1.16.1 ]
    fi
    if [ "$outcome" = switch-linked ]; then
      [ "$(readlink "$ROOT/current")" = releases/1.16.2 ]
    else
      [ "$(readlink "$ROOT/current")" = releases/1.16.1 ]
    fi
  done
}
