# shellcheck shell=bash
# CX_UP_OLD_* and CX_BK_COMPOSE are read by the backup library and the rest of the upgrade.
# shellcheck disable=SC2034
# Steps 5 and 6 of upgrade: stop the old version, then prove it is gone.
#   5  stop backend, guacd and frontend (SIGTERM: the graceful shutdown drains the audit queue;
#      postgres keeps running for the backup). Then the backend's log of the run that just ended:
#      "稽核佇列排空逾時" means some audit rows were not confirmed written; the upgrade stops there
#      with the counts from that line and where the fallback file is.
#   6  the application account has no connection left on the database (the query of the upgrade
#      guide, excluding its own). Anything else, a query that fails included, stops the upgrade.
# The services stay stopped after a failure here; the command that starts the old version again is
# printed in full (project, folder, files), never relying on the current directory.
# A git clone deployment that is not converted yet runs under its own project name and its own
# compose files at the root; every compose call then goes through the exception entry
# (lib/compose.sh cx_compose_explicit) with those, including the backup's (CX_BK_COMPOSE).

readonly CX_UP_DRAIN_TIMEOUT_MARK='稽核佇列排空逾時'

CX_UP_OLD_PROJECT="" CX_UP_OLD_FILES="" CX_UP_OLD_HINT=""

# cx_up_legacy_compose: the project and compose files the git clone deployment runs under. The
# project is the one compose put on the running backend container; the files are COMPOSE_FILE in
# .env (colon-separated, relative to the root) or docker-compose.yml. Fails when the project name
# is not one compose accepts.
cx_up_legacy_compose() {
  local cf f
  local -a list=()
  CX_UP_OLD_PROJECT=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' \
    custodexa-backend 2>/dev/null) || CX_UP_OLD_PROJECT=""
  # No backend container to ask: the name compose itself gives the project (COMPOSE_PROJECT_NAME
  # in .env, else the folder name in lower case).
  if [ -z "$CX_UP_OLD_PROJECT" ]; then
    CX_UP_OLD_PROJECT=$(cx_env_get "$CX_ROOT/.env" COMPOSE_PROJECT_NAME)
    [ -n "$CX_UP_OLD_PROJECT" ] || CX_UP_OLD_PROJECT=$(basename -- "$CX_ROOT" | tr '[:upper:]' '[:lower:]')
  fi
  [[ $CX_UP_OLD_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { CX_UP_OLD_PROJECT=""; return 1; }
  cf=$(cx_env_get "$CX_ROOT/.env" COMPOSE_FILE)
  IFS=: read -ra list <<<"${cf:-docker-compose.yml}"
  CX_UP_OLD_FILES=""
  for f in "${list[@]}"; do
    [ -n "$f" ] || continue
    case $f in /*) ;; *) f=$CX_ROOT/${f#./} ;; esac
    cx_check_root_path "$f" || return 1
    CX_UP_OLD_FILES+="${CX_UP_OLD_FILES:+ }$f"
  done
  [ -n "$CX_UP_OLD_FILES" ] || return 1
  CX_UP_OLD_HINT="-p $CX_UP_OLD_PROJECT --project-directory $CX_ROOT"
  for f in $CX_UP_OLD_FILES; do CX_UP_OLD_HINT+=" -f $f"; done
  CX_BK_COMPOSE=cx_up_compose
}

# cx_up_compose <compose arguments...>: compose on the version that runs now.
cx_up_compose() {
  if [ "$CX_UP_KIND" = convert ]; then
    # shellcheck disable=SC2086 # the file list holds checked paths without spaces
    cx_compose_explicit "$CX_UP_OLD_PROJECT" "$CX_ROOT" $CX_UP_OLD_FILES -- "$@"
  else
    cx_compose "$@"
  fi
}

# cx_up_resume_cmd: how to start the old version's services again.
cx_up_resume_cmd() {
  local files=""
  printf '%s\n' "$(cx_up_par "$(cx_msg st_resume)")"
  if [ "$CX_UP_KIND" = convert ]; then
    cx_cmd "sudo docker compose $CX_UP_OLD_HINT \\"
  else
    files="-f $CX_ROOT/current/compose.yml"
    local ov
    for ov in ${CX_OVERLAYS:-}; do files+=" -f $CX_ROOT/current/compose.$ov.yml"; done
    cx_cmd "sudo docker compose -p $CX_PROJECT --project-directory $CX_ROOT $files \\"
  fi
  cx_cmd "  start $CX_BK_SERVICES"
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

# cx_up_gone <step>: step 6. 0 = no connection of the application account is left.
cx_up_gone() {
  local n=$1 count
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
  cx_cmd "sudo docker compose $(cx_up_compose_hint) exec -T postgres \\"
  cx_cmd "  psql -U $CX_BK_DBUSER -d $CX_BK_DBNAME -tAc \"SELECT count(*) FROM pg_stat_activity"
  cx_cmd "  WHERE datname = current_database() AND usename = current_user"
  cx_cmd "  AND pid <> pg_backend_pid()\""
  cx_up_resume_cmd
  return 1
}
