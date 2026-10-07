# shellcheck shell=bash
# shellcheck source=lib/service_controls.sh
. "${BASH_SOURCE[0]%/*}/service_controls.sh"
cmd_start() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  [ "$CX_YES" = 0 ] || cx_die "$CX_EXIT_USAGE" usage_unknown_option --yes
  cx_svc_prepare start || exit "$?"
  if cx_svc_all_running && cx_backend_healthy_once; then
    cx_line OK "$(cx_msg svc_start_already)"
    cx_svc_finish succeeded
    return 0
  fi
  printf '%s\n' "$(cx_msg svc_start_title)"
  cx_line RUN "$(cx_msg svc_start_run)"
  if ! cx_new_started_mark || ! cx_compose up -d --remove-orphans >/dev/null 2>&1; then
    cx_line FAIL "$(cx_msg svc_start_failed)"
    cx_svc_resume
    cx_svc_log_hint
    cx_svc_finish failed
    return "$CX_EXIT_FAILED"
  fi
  cx_line OK "$(cx_msg svc_containers_up)"
  cx_line RUN "$(cx_msg svc_ready_run)"
  if ! cx_wait_backend_health; then
    cx_line FAIL "$(cx_msg svc_ready_failed)"
    cx_svc_resume
    cx_svc_log_hint
    cx_svc_finish failed
    return "$CX_EXIT_FAILED"
  fi
  cx_line OK "$(cx_msg svc_ready_done)"
  cx_line OK "$(cx_msg svc_start_done)"
  printf '  sudo %s/custodexa.sh status%s\n' "$CX_ROOT" "$(cx_status_lang_arg)"
  cx_svc_finish succeeded
}
