# shellcheck shell=bash
# shellcheck disable=SC2034
# Steps 5 and 6 of upgrade: stop the old version, then prove it is gone.
#   5  stop backend, guacd and frontend (SIGTERM: the graceful shutdown drains the audit queue;
#      postgres keeps running for the backup). Then the backend's log of the run that just ended:
#      "稽核佇列排空逾時" means some audit rows were not confirmed written; the upgrade stops there
#      with the counts from that line and where the fallback file is.
#   6  the application account has no connection left on the database (the query of the upgrade
#      guide, excluding its own). Anything else, a query that fails included, stops the upgrade.
#      An external database is asked through the client the checks chose (lib/dbext.sh); without
#      one (the operator's own backup this time) nothing can ask it: the stopped services are taken
#      as the answer, with a warning to make sure no other host is connected to that database.
# The services stay stopped after a failure here; the command that starts the old version again is
# printed in full (project, folder, files), never relying on the current directory.

readonly CX_UP_DRAIN_TIMEOUT_MARK='稽核佇列排空逾時'

# cx_up_compose <compose arguments...>: compose on the version that runs now.
cx_up_compose() { cx_compose "$@"; }

# cx_up_resume_cmd: how to start the old version's services again.
cx_up_resume_cmd() {
  local files=""
  printf '%s\n' "$(cx_up_par "$(cx_msg st_resume)")"
  files="-f $CX_ROOT/current/compose.yml"
  local ov
  for ov in ${CX_OVERLAYS:-}; do files+=" -f $CX_ROOT/current/compose.$ov.yml"; done
  cx_cmd "sudo docker compose -p $CX_PROJECT --project-directory $CX_ROOT $files \\"
  cx_cmd "  start $CX_BK_SERVICES"
  cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
}

# cx_up_stop <step>: step 5. 0 = stopped and drained; 1 = failed (the screen says why).
cx_up_stop() {
  local n=$1 t0 started line
  t0=$(cx_now)
  # shellcheck disable=SC2086
  if ! cx_up_compose stop $CX_BK_SERVICES >/dev/null 2>&1; then
    cx_up_step_line FAIL "$n" "$(cx_msg st_stop_failed)"
    cx_up_resume_cmd
    return 1
  fi
  if ! started=$(docker container inspect --format '{{.State.StartedAt}}' custodexa-backend 2>/dev/null) \
    || [ -z "$started" ]; then
    cx_up_step_line FAIL "$n" "$(cx_msg st_log_unreadable)"
    cx_up_resume_cmd
    return 1
  fi
  line=$(docker logs --since "$started" custodexa-backend 2>&1 | grep -F "$CX_UP_DRAIN_TIMEOUT_MARK" | tail -n 1) || true
  if [ -n "$line" ]; then
    cx_log FAIL "stop: $line"
    cx_up_step_line FAIL "$n" "$(cx_msg st_drain_timeout)"
    if [[ $line =~ ([0-9]+)\ 列未確認落地（已降級寫檔\ ([0-9]+)\ 列、worker\ 持有中未回報\ ([0-9]+)\ 列、確定遺失\ ([0-9]+)\ 列） ]]; then
      printf '%s\n' "$(cx_up_par "$(cx_msg st_drain_counts "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
        "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}")")"
    fi
    printf '%s\n' "$(cx_up_par "$(cx_msg st_drain_detail "$CX_BK_DATA/audit/")")"
    cx_up_resume_cmd
    return 1
  fi
  cx_up_step_line OK "$n" "$(cx_msg bk_step_stop)" "$(cx_duration $(($(cx_now) - t0)))"
}

# cx_up_gone <step>: step 6. 0 = no connection of the application account is left (or, for an
# external database without a client, the services are stopped and the screen warns).
cx_up_gone() {
  local n=$1 count
  if ! cx_db_ready; then
    cx_log CHECK "old instance connections=unchecked (external database, no client chosen)"
    cx_up_step_line WARN "$n" "$(cx_msg st_gone_unchecked)"
    return 0
  fi
  count=$(cx_snap_sql "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = current_user AND pid <> pg_backend_pid()" 2>/dev/null) || count=""
  cx_log CHECK "old instance connections=${count:-unknown}"
  if [ "$count" = 0 ]; then
    cx_up_step_line OK "$n" "$(cx_msg st_gone)"
    return 0
  fi
  if [[ $count =~ ^[0-9]+$ ]]; then
    cx_up_step_line FAIL "$n" "$(cx_msg st_conn_left "$count")"
  else
    cx_up_step_line FAIL "$n" "$(cx_msg st_conn_unknown)"
  fi
  printf '%s\n' "$(cx_up_par "$(cx_msg st_conn_detail)")"
  if cx_db_external; then
    local port
    port=$(cx_bk_env EXTERNAL_DB_PORT)
    cx_cmd "psql -h $(cx_bk_env EXTERNAL_DB_HOST) -p ${port:-5432} -U $CX_BK_DBUSER -d $CX_BK_DBNAME \\"
    cx_cmd "  -tAc \"SELECT count(*) FROM pg_stat_activity"
  else
    cx_cmd "sudo docker compose $(cx_up_compose_hint) exec -T postgres \\"
    cx_cmd "  psql -U $CX_BK_DBUSER -d $CX_BK_DBNAME -tAc \"SELECT count(*) FROM pg_stat_activity"
  fi
  cx_cmd "  WHERE datname = current_database() AND usename = current_user"
  cx_cmd "  AND pid <> pg_backend_pid()\""
  cx_up_resume_cmd
  return 1
}
