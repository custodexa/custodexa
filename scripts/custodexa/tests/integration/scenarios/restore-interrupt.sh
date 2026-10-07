# shellcheck shell=bash
# about: restores of a built-in deployment interrupted for real: SIGTERM while pg_restore loads the database (no tool container or process left, --resume finishes with the backup's rows); SIGKILL between the two renames of the data folders, finished once with --resume (the backup's rows) and once with --revert (the rows from before), never starting an empty database as the old one; SIGTERM after the services were started but before they are ready (the screen says they may be running, as docker ps shows); a failed database check gone back with --revert (version, rows, data, sequences and grants from before); on a new host waiting for the unseal, --abandon stops every container and leaves it not installed
# needs: package local-versions
# images:

readonly RT_V=1.16.90

# rt_bg <label> <inject> [restore arguments]: the restore of RI_FILE on this host in the background.
rt_bg() {
  local label=$1
  rm -f "$IT_WORK/lv-injected" "$IT_WORK/lv-import-reached" "$IT_WORK/lv-swap-reached" "$IT_WORK/lv-up-reached"
  LV_INJECT=$2 lv_bg "$label" restore "$RI_FILE" --same-host --yes --confirm-data-loss
}

# rt_end <label>: wait for the background run; LV_RC, LV_OUT.
rt_end() {
  LV_RC=0
  wait "$LV_PID" || LV_RC=$?
  LV_OUT=$(cat "$IT_WORK/$1.out")
  printf '%s\n' "$LV_OUT" | sed "s/^/   $1> /"
  printf '   %s> (exit %s)\n' "$1" "$LV_RC"
}

# rt_left <label>: no tool container, no process of the run (the script, its docker clients, the
# shim) on this host, and no pg_restore in the database container when it runs.
rt_left() {
  it_same "$1: no tool container is left" "" "$(lv_tools_left)"
  it_same "$1: no process of the run is left" "" \
    "$(pgrep -af 'custodexa\.sh|lvshim|pg_restore' || true)"
  if [ "$(docker inspect --format '{{.State.Running}}' custodexa-postgres 2>/dev/null)" = true ]; then
    it_same "$1: no pg_restore runs in the database container" "" \
      "$(docker top custodexa-postgres -eo pid,args 2>/dev/null | grep pg_restore || true)"
  fi
}

rt_resume() { # <label>: restore --resume finishes; the database is the backup's
  ri_doc "$1" restore --resume
  it_same "$1: restore --resume exits 0" 0 "$LV_RC"
  it_same "$1: last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$RT_V"
  ri_snap_same "$1: the database equals the backup's snapshot.txt" backup
  ri_running_same "$1"
}

rt_revert() { # <label> <facts before>: restore --revert brings back what was there before
  ri_doc "$1" restore --revert --yes
  it_same "$1: restore --revert exits 0" 0 "$LV_RC"
  it_same "$1: last_restore.result" reverted "$(lv_st last_restore.result)"
  lv_wait_version "$RT_V"
  ri_same_facts "$1: version, rows, data, sequences and grants are those before the restore" "$2"
  ri_running_same "$1"
}

# rt_swap_kill <label>: SIGKILL to the script between the two renames of the data folders.
rt_swap_kill() {
  local label=$1 ts
  touch "$IT_WORK/lv-hold"
  rt_bg "$label" hold-swap
  lv_until "$label: the run renamed the database folder, not yet the audit folder" test -e "$IT_WORK/lv-swap-reached"
  it_say "   $label: phase $(lv_st last_restore.phase); SIGKILL to the script"
  kill -KILL "$LV_PID"
  rm -f "$IT_WORK/lv-hold"
  rt_end "$label"
  it_same "$label: the run was killed" 137 "$LV_RC"
  # The held sync (a child, with the lock's descriptor) ends once released.
  lv_until "$label: nothing holds the deployment's lock" flock -n "$LV_ROOT/.custodexa.lock" true
  ts=$(lv_st last_restore.stamp)
  it_check "$label: the database folder was moved aside, the audit folder not" \
    test ! -e "$LV_ROOT/data/postgres" -a -d "$LV_ROOT/data/postgres.before-restore-$ts" -a -d "$LV_ROOT/data/audit"
  it_same "$label: no database container runs" "" "$(docker ps -q --filter name=custodexa-postgres)"
}

scenario() {
  local ps
  lv_install "$RT_V"
  ri_data in-backup
  ri_backup backup

  it_step "SIGTERM while pg_restore loads the database, then --resume"
  ri_data r1; ri_mark
  rt_bg import-term hold-import
  lv_until "import-term: pg_restore started" test -e "$IT_WORK/lv-import-reached"
  sleep 2
  it_say "   import-term: phase $(lv_st last_restore.phase); SIGTERM to the script"
  kill -TERM "$LV_PID"
  rt_end import-term
  it_check "import-term: the run ended with an error" test "$LV_RC" -ne 0
  it_same "import-term: last_restore.result, phase" "in_progress swapped" "$(lv_st last_restore.result) $(lv_st last_restore.phase)"
  rt_left import-term
  it_check "import-term: the screen gives --resume" grep -q 'custodexa.sh restore --resume' <<<"$LV_OUT"
  rt_resume import-resume
  it_same "import-resume: the user written after the backup is not there" 0 "$(ri_has r1)"

  it_step "SIGKILL between the two renames, then --resume"
  ri_data r2; ri_mark
  rt_swap_kill swap-kill-1
  rt_resume swap-resume
  it_same "swap-resume: the user written after the backup is not there" 0 "$(ri_has r2)"

  it_step "SIGKILL between the two renames, then --revert"
  ri_data r3; ri_mark
  ri_facts "$IT_WORK/facts.r3"
  rt_swap_kill swap-kill-2
  rt_revert swap-revert "$IT_WORK/facts.r3"
  it_same "swap-revert: the user written before this restore is there" 1 "$(ri_has r3)"

  it_step "SIGTERM after the services were started, before they are ready"
  touch "$IT_WORK/lv-hold"
  ri_mark; rt_bg up-term hold-after-up
  lv_signal_at_up up-term
  it_check "up-term: the run ended with an error" test "$LV_RC" -ne 0
  ps=$(docker ps --format '{{.Names}}' --filter name=custodexa- | LC_ALL=C sort | paste -sd ' ' -)
  it_say "   up-term: running now: $ps"
  it_check "up-term: the screen says the services may be running" grep -q 'Some or all services may be running' <<<"$LV_OUT"
  it_check "up-term: and they are (docker ps)" grep -q custodexa-backend <<<"$ps"
  it_check "up-term: the screen gives the status command" grep -q 'custodexa.sh status' <<<"$LV_OUT"
  rt_left up-term
  rt_resume up-resume

  it_step "the database check fails, then --revert"
  ri_data r4; ri_mark
  ri_facts "$IT_WORK/facts.r4"
  rt_bg check-fail restore-check-fail
  rt_end check-fail
  it_same "check-fail: the restore fails: exit 1" 1 "$LV_RC"
  it_check "check-fail: the failure was the injected one" test -e "$IT_WORK/lv-injected"
  it_same "check-fail: last_restore.phase" imported "$(lv_st last_restore.phase)"
  rt_revert check-revert "$IT_WORK/facts.r4"
  it_same "check-revert: the user written before this restore is there" 1 "$(ri_has r4)"

  it_step "a new host waiting for the unseal gives up with --abandon"
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK/lv-admin-password"
  ri_ui_install "$RT_V"
  head -c 24 /dev/urandom | base64 | tr '+/' 'xy' >"$IT_WORK/ui-material"
  ri_unseal "$(cat "$IT_WORK/ui-material")" init
  it_same "the first unseal is accepted" 200 "$RI_HTTP"
  lv_until "the backend is unsealed" ri_is_unsealed || true
  ri_data ui
  ri_backup ui-backup
  mkdir -p "$IT_WORK/carried"
  cp "$RI_FILE" "$RI_FILE.sha256" "$IT_WORK/carried/"
  RI_FILE=$IT_WORK/carried/${RI_FILE##*/}
  ex_teardown "$LV_ROOT"
  it_unpack /opt "$RT_V"
  lv_cx load load "$(it_bundle_file "$RT_V")"
  it_same "load of the offline bundle exits 0" 0 "$LV_RC"
  ri_doc new-host restore "$RI_FILE" --new-host --yes --package "$(it_package_file "$RT_V")" --images "$(it_bundle_file "$RT_V")"
  it_same "new-host: restore exits 4 (waiting for the unseal)" 4 "$LV_RC"
  it_same "new-host: last_restore.phase" awaiting_unseal "$(lv_st last_restore.phase)"
  it_check "new-host: the services run" test -n "$(docker ps -q --filter name=custodexa-backend)"
  ri_doc abandon restore --abandon --yes
  it_same "abandon: restore --abandon exits 0" 0 "$LV_RC"
  it_same "abandon: no container runs" "" "$(docker ps -q --filter name=custodexa-)"
  it_same "abandon: last_restore.result" abandoned "$(lv_st last_restore.result)"
  lv_cx status status
  it_check "abandon: status says not installed" grep -q 'Not installed yet' <<<"$LV_OUT"
}
