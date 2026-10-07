# shellcheck shell=bash
# about: after an upgrade from 1.16.90 to 1.16.92 (one more migration) rollback is refused before anything stops and prints the restore command of the backup the upgrade took, from three starting points: the upgrade succeeded, failed at its readiness step, or was interrupted (SIGTERM) there; with the upgrade unfinished, the old offline bundle loads and rollback still gets to its decision; the restore command, run as printed, brings back the version and the database of before the upgrade
# needs: package local-versions
# images:

readonly RF_OLD=1.16.90 RF_NEW=1.16.92

# rf_refused <label>: rollback refuses, exit 3, nothing stopped, the restore command names the backup
# file the upgrade recorded.
rf_refused() {
  local label=$1 ps0 file
  ps0=$(lv_ps)
  lv_cx "$label" rollback --yes
  it_same "$label: rollback exits 3" 3 "$LV_RC"
  it_check "$label: the screen says the database was changed by $RF_NEW and names it_rollback_probe" \
    bash -c 'grep -q "Cannot go straight back to $2" <<<"$1" && grep -q it_rollback_probe <<<"$1"' _ "$LV_OUT" "$RF_OLD"
  it_same "$label: the services still run, the same containers" "$ps0" "$(lv_ps)"
  file=$(grep -oE 'custodexa\.sh restore [^ ]+' <<<"$LV_OUT" | tail -n 1 | awk '{print $3}')
  it_check "$label: the screen gives the restore command" test -n "$file"
  it_same "$label: it names the backup of the upgrade (last_upgrade.backup)" "$LV_ROOT/$(lv_st last_upgrade.backup)" "$file"
  it_check "$label: that file exists" test -f "$file"
  it_same "$label: current.version, the current link are unchanged" "$RF_NEW releases/$RF_NEW" \
    "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  RF_RESTORE=$(grep -E 'custodexa\.sh restore ' <<<"$LV_OUT" | tail -n 1 |
    sed -E 's/^ *(sudo +)?//; s/ --lang [a-zA-Z-]+//; s#^[^ ]*/custodexa\.sh +##')
}

# rf_restore <label>: the restore command as printed, with what a run without a terminal has to
# add: the kind of restore (this host is installed) and the two answers to its question (--yes,
# --confirm-data-loss). It has to finish: the version, the current link and the database go back
# to those of $RF_OLD before the upgrade (no it_rollback_probe), an unfinished upgrade is taken
# over (failed, handed_to restore), not held against the restore.
rf_restore() {
  local label=$1 upgrade_before
  upgrade_before=$(lv_st last_upgrade.result)
  # shellcheck disable=SC2086 # the command as the screen gives it
  lv_cx "$label-restore" $RF_RESTORE --same-host --yes --confirm-data-loss
  it_same "$label: restore exits 0" 0 "$LV_RC"
  it_same "$label: last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$RF_OLD"
  it_same "$label: back on $RF_OLD" "$RF_OLD releases/$RF_OLD" "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "$label: the backend reports $RF_OLD" "$RF_OLD" "$(lv_version)"
  it_same "$label: the database no longer has it_rollback_probe" 0 \
    "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = 'it_rollback_probe'")"
  if [ "$upgrade_before" = in_progress ]; then
    it_same "$label: the unfinished upgrade is settled by the restore" "failed restore" \
      "$(lv_st last_upgrade.result) $(lv_st last_upgrade.handed_to)"
  else
    it_same "$label: last_upgrade.result is kept" "$upgrade_before" "$(lv_st last_upgrade.result)"
  fi
}

rf_fresh() {
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK/lv-admin-password"
  lv_install "$RF_OLD"
}

scenario() {
  local ps0
  it_step "starting point: the upgrade to $RF_NEW succeeded"
  lv_install "$RF_OLD"
  lv_upgrade "$RF_NEW"
  it_same "last_upgrade.result" succeeded "$(lv_st last_upgrade.result)"
  rf_refused succeeded
  rf_restore succeeded

  it_step "starting point: the upgrade to $RF_NEW failed at its readiness step (step 11)"
  rf_fresh
  LV_INJECT=health-fail LV_READY_TRIES=2 lv_upgrade "$RF_NEW" 1
  it_same "last_upgrade.result, step" "failed 11" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step)"
  lv_wait_version "$RF_NEW"
  rf_refused failed
  rf_restore failed

  it_step "starting point: the upgrade to $RF_NEW was interrupted (SIGTERM) at its readiness step (step 11)"
  rf_fresh
  LV_INJECT=health-fail lv_bg upgrade-sigterm upgrade "$(it_package_file "$RF_NEW")" --images "$(it_bundle_file "$RF_NEW")" --yes
  lv_until "the upgrade reaches step 11" bash -c '[ "$(jq -r ".\"last_upgrade.step\" // empty" "$1")" = 11 ]' _ "$LV_ROOT/state.json"
  sleep 2
  kill -TERM "$LV_PID"
  LV_RC=0
  wait "$LV_PID" || LV_RC=$?
  sed 's/^/   upgrade-sigterm> /' "$IT_WORK/upgrade-sigterm.out"
  it_check "the upgrade ended with an error" test "$LV_RC" -ne 0
  it_same "last_upgrade.result, step" "in_progress 11" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step)"
  it_same "no tool container is left" "" "$(lv_tools_left)"
  lv_wait_version "$RF_NEW"
  rf_refused in-progress

  it_step "unfinished upgrade: the old backend image is removed, the old offline bundle loads, rollback gets to its decision"
  docker rmi "ghcr.io/custodexa-it/backend:$RF_OLD" >/dev/null
  ps0=$(lv_ps)
  lv_cx images rollback --yes
  it_same "rollback exits 3" 3 "$LV_RC"
  it_check "the database decision comes first: the screen is the one of a changed database" \
    grep -q "Cannot go straight back to $RF_OLD" <<<"$LV_OUT"
  it_same "the services still run, the same containers" "$ps0" "$(lv_ps)"
  lv_cx load load "$(it_bundle_file "$RF_OLD")"
  it_same "load of the $RF_OLD bundle is not held back by the unfinished upgrade: exit 0" 0 "$LV_RC"
  it_check "the $RF_OLD backend image is here again" docker image inspect "ghcr.io/custodexa-it/backend:$RF_OLD"
  it_same "last_upgrade.result, step are unchanged by load" "in_progress 11" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step)"
  rf_refused in-progress-after-load
  rf_restore in-progress
}
