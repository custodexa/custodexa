# shellcheck shell=bash
# shellcheck source=lib/service_controls.sh
. "${BASH_SOURCE[0]%/*}/service_controls.sh"
cmd_stop() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_svc_prepare stop || exit "$?"
  if cx_svc_stopped; then
    cx_line OK "$(cx_msg svc_stop_already)"
    cx_svc_finish succeeded
    return 0
  fi
  printf '%s\n' "$(cx_msg svc_stop_title)"
  cx_line WARN "$(cx_msg svc_stop_warn)"
  if ! cx_confirm svc_stop_confirm; then
    printf '%s\n' "$(cx_msg svc_cancelled)"
    cx_svc_finish cancelled
    return "$CX_EXIT_REFUSED"
  fi
  [ "$CX_YES" != 1 ] || printf '%s y\n' "$(cx_msg svc_stop_confirm)"
  cx_line RUN "$(cx_msg svc_drain_run)"
  if ! cx_dg_wait 0 service; then
    cx_svc_finish failed
    return "$CX_EXIT_FAILED"
  fi
  cx_line RUN "$(cx_msg svc_stop_run)"
  if ! cx_compose stop >/dev/null 2>&1 || ! cx_svc_stopped; then
    cx_line FAIL "$(cx_msg svc_stop_failed)"
    cx_svc_resume
    cx_svc_finish failed
    return "$CX_EXIT_FAILED"
  fi
  cx_line OK "$(cx_msg svc_stop_done)"
  cx_svc_hint
  cx_svc_finish succeeded
}
