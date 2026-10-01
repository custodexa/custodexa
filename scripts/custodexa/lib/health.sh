# shellcheck shell=bash
# Shared backend readiness poll. The upgrade caller records the returned version.
readonly CX_UP_READY_TRIES=60 CX_UP_READY_WAIT=3
CX_UP_HEALTH_VER=""
cx_backend_healthy_once() {
  cx_compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1
}
cx_wait_backend_health() {
  local tries=0 health
  until health=$(cx_compose exec -T backend wget -qO- http://localhost:8080/health 2>/dev/null); do
    tries=$((tries + 1))
    [ "$tries" -lt "$CX_UP_READY_TRIES" ] || return 1
    sleep "$CX_UP_READY_WAIT"
  done
  CX_UP_HEALTH_VER=""
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && CX_UP_HEALTH_VER=${BASH_REMATCH[1]}
  cx_log CHECK "health version=${CX_UP_HEALTH_VER:-none}"
}
