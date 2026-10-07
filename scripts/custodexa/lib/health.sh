# shellcheck shell=bash
# Shared backend readiness poll. The upgrade caller records the returned version.
readonly CX_UP_READY_TRIES=60 CX_UP_READY_WAIT=3
CX_UP_HEALTH_VER=""
cx_backend_healthy_once() {
  cx_compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1
}
# cx_ready_tries: how many times the poll asks. CX_READY_TRIES (a whole number from 1 to 9999) in
# the environment replaces the default; the tests use it to reach the limit quickly.
cx_ready_tries() {
  if [[ ${CX_READY_TRIES:-} =~ ^[1-9][0-9]{0,3}$ ]]; then
    printf '%s' "$CX_READY_TRIES"
  else
    printf '%s' "$CX_UP_READY_TRIES"
  fi
}
# cx_ready_seconds: the longest the poll waits, as the screens say it.
cx_ready_seconds() { printf '%s' $(($(cx_ready_tries) * CX_UP_READY_WAIT)); }
cx_wait_backend_health() {
  local tries=0 health max
  max=$(cx_ready_tries)
  until health=$(cx_compose exec -T backend wget -qO- http://localhost:8080/health 2>/dev/null); do
    tries=$((tries + 1))
    [ "$tries" -lt "$max" ] || return 1
    sleep "$CX_UP_READY_WAIT"
  done
  CX_UP_HEALTH_VER=""
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && CX_UP_HEALTH_VER=${BASH_REMATCH[1]}
  cx_log CHECK "health version=${CX_UP_HEALTH_VER:-none}"
}
