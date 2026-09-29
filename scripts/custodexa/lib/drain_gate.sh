# shellcheck shell=bash
# Step 4 of upgrade: wait until the audit queue is empty before anything is stopped. Records still
# in the backend's memory when it stops are lost to the audit trail, so this gate only lets the run
# go on when it knows there is nothing left:
#   the queue metric reads 0                            go on
#   the queue metric reads more than 0                  read again every 2 seconds, show the number;
#                                                       still more than 0 after 120 seconds: stop
#   the metric cannot be read                           ask the seal state:
#     HTTP 200, sealed / sealed-faulted / unsealing,    go on: the audit writer only starts when the
#     and the backend never unsealed since it started   system is unsealed, so there is no queue
#     anything else (403 from the source address       the state is unknown: stop
#     limit, no answer, another status, unreadable,
#     unsealed, unsealed earlier and sealed again)
#   the backend container is stopped                    nothing in memory to wait for
#   no backend container at all                         the same, with a warning
# Only a running backend whose queue cannot be read stops the run. Every stop leaves the services running and nothing changed. --yes does not skip the gate.
# Both requests run inside the backend container, which already holds METRICS_TOKEN from .env:
# the token never appears on the host's command line, on the screen or in the log. The production
# image has no shell (removed on purpose), so the token is expanded by busybox's own sh applet.

readonly CX_DG_LIMIT=120 CX_DG_EVERY=2
# The backend logs this once stage 2 (the audit writer among it) is assembled after an unseal.
readonly CX_DG_UNSEALED_MARK='[Seal] 已解封並換上完整路由'

CX_DG_BODY="" CX_DG_CODE=""

# cx_dg_get <path>: GET inside the backend container. CX_DG_BODY = the body, CX_DG_CODE = the HTTP
# status the server answered ("" when none: no answer, timeout, no container).
cx_dg_get() {
  local err
  err=$(mktemp)
  # shellcheck disable=SC2016 # expanded inside the container
  CX_DG_BODY=$(docker exec custodexa-backend /bin/busybox sh -c \
    'wget -S -q -T 5 -O - ${METRICS_TOKEN:+--header="Authorization: Bearer $METRICS_TOKEN"} "http://localhost:8080$1"' \
    _ "$1" 2>"$err") || true
  CX_DG_CODE=$(grep -o 'HTTP/[0-9.]* [0-9][0-9][0-9]' "$err" | tail -n 1 | awk '{ print $2 }') || true
  rm -f "$err"
}

# cx_dg_depth: print the queue depth; fails when the metric cannot be read.
cx_dg_depth() {
  local v
  cx_dg_get /metrics
  [ "$CX_DG_CODE" = 200 ] || return 1
  v=$(printf '%s\n' "$CX_DG_BODY" | awk '$1 ~ /^custodexa_audit_queue_depth({.*})?$/ { print $2; exit }')
  # Prometheus writes a gauge as a float; a queue depth is a whole number.
  v=${v%.0}
  [[ $v =~ ^[0-9]+$ ]] || return 1
  printf '%s' "$v"
}

# cx_dg_sealed_empty: the seal state was read (HTTP 200) as sealed, sealed-faulted or unsealing,
# and the backend has not logged an unseal since the container started.
cx_dg_sealed_empty() {
  local state started
  cx_dg_get /api/v1/seal/status
  [ "$CX_DG_CODE" = 200 ] || { cx_log DRAIN "seal status http=${CX_DG_CODE:-none}"; return 1; }
  state=$(cx_seal_state "$CX_DG_BODY") || { cx_log DRAIN "seal status unreadable"; return 1; }
  cx_log DRAIN "seal state=$state"
  case $state in
    sealed | sealed-faulted | unsealing) ;;
    *) return 1 ;;
  esac
  started=$(docker container inspect --format '{{.State.StartedAt}}' custodexa-backend 2>/dev/null) || return 1
  [ -n "$started" ] || return 1
  if docker logs --since "$started" custodexa-backend 2>&1 | grep -qF "$CX_DG_UNSEALED_MARK"; then
    cx_log DRAIN "unsealed earlier since $started"
    return 1
  fi
}

# cx_dg_manual: the command to read the number by hand (the token itself is never printed).
cx_dg_manual() {
  local hdr=""
  [ -z "$(cx_env_get "$CX_ROOT/.env" METRICS_TOKEN)" ] || hdr='--header="Authorization: Bearer <token>" '
  cx_cmd "sudo docker compose $(cx_up_compose_hint) exec -T backend \\"
  cx_cmd "  wget -qO- ${hdr}http://localhost:8080/metrics | grep custodexa_audit_queue_depth"
}

# cx_dg_wait <step number>: the gate. 0 = go on; 1 = stopped here (the screen says why).
cx_dg_wait() {
  local n=$1 t0 depth last="" shown=0
  t0=$(cx_now)
  case $(cx_br_backend) in
    stopped\ *)
      cx_log DRAIN "backend stopped: no queue"
      cx_up_step_line SKIP "$n" "$(cx_msg dg_stopped)"
      return 0
      ;;
    absent)
      cx_log DRAIN "backend container not found: no queue"
      cx_up_step_line WARN "$n" "$(cx_msg dg_stopped)"
      return 0
      ;;
  esac
  while :; do
    if ! depth=$(cx_dg_depth); then
      cx_log DRAIN "metrics http=${CX_DG_CODE:-none} unreadable"
      [ "$shown" = 0 ] || printf '\n'
      if cx_dg_sealed_empty; then
        cx_up_step_line OK "$n" "$(cx_msg dg_sealed)"
        return 0
      fi
      cx_up_step_line FAIL "$n" "$(cx_msg dg_unknown)"
      printf '%s\n\n' "$(cx_msg dg_unknown_detail)"
      cx_up_par "$(cx_msg dg_unknown_what "$CX_ROOT/custodexa.sh" "$(cx_status_lang_arg)")"
      return 1
    fi
    cx_log DRAIN "queue depth=$depth"
    if [ "$depth" = 0 ]; then
      [ "$shown" = 0 ] || printf '%s\n' "$(cx_msg dg_left_next 0)"
      cx_up_step_line OK "$n" "$(cx_msg dg_done)" "$(cx_duration $(($(cx_now) - t0)))"
      return 0
    fi
    if [ "$shown" = 0 ]; then
      cx_up_step_line RUN "$n" "$(cx_msg dg_step)"
      printf '        %s' "$(cx_msg dg_left_first "$(cx_up_num "$depth")")"
      shown=1
    elif [ "$depth" != "$last" ]; then
      printf '%s' "$(cx_msg dg_left_next "$(cx_up_num "$depth")")"
    fi
    last=$depth
    if [ $(($(cx_now) - t0)) -ge "$CX_DG_LIMIT" ]; then
      printf '\n'
      cx_log DRAIN "timeout depth=$depth"
      cx_up_step_line FAIL "$n" "$(cx_msg dg_timeout "$(cx_up_num "$depth")")"
      printf '\n'
      cx_up_par "$(cx_msg dg_timeout_what)"
      cx_dg_manual
      return 1
    fi
    sleep "$CX_DG_EVERY"
  done
}
