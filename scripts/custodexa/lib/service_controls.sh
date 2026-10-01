# shellcheck shell=bash
# Shared setup and recovery for whole-deployment start/stop.
# shellcheck source=lib/backup_ref.sh
. "${BASH_SOURCE[0]%/*}/backup_ref.sh"
# shellcheck source=lib/upgrade_output.sh
. "${BASH_SOURCE[0]%/*}/upgrade_output.sh"
# shellcheck source=lib/drain_gate.sh
. "${BASH_SOURCE[0]%/*}/drain_gate.sh"
# shellcheck source=lib/health.sh
. "${BASH_SOURCE[0]%/*}/health.sh"

cx_svc_hint() {
  printf '%s\n' "$(cx_msg svc_status_hint)"
  printf '  sudo %s/custodexa.sh status%s\n' "$CX_ROOT" "$(cx_status_lang_arg)"
}
cx_svc_resume() {
  printf '%s\n' "$(cx_msg svc_resume_hint)"
  cx_svc_hint
  printf '  sudo %s/custodexa.sh start%s\n' "$CX_ROOT" "$(cx_status_lang_arg)"
}
cx_svc_log_hint() {
  cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
}
cx_svc_signal() {
  trap - INT TERM HUP
  cx_log END "result=interrupted command=$CX_SVC_COMMAND"
  printf '\n' >&2
  cx_svc_resume >&2
  exit "$CX_EXIT_FAILED"
}
cx_svc_finish() {
  cx_log END "result=$1 command=$CX_SVC_COMMAND"
  trap - INT TERM HUP
}
cx_svc_pending() {
  local key cmd
  for key in install.result last_upgrade.result last_backup.result; do
    [ "$(cx_state_get "$key")" = in_progress ] || continue
    cmd=$(cx_run_command_of "${key%.result}")
    cx_line FAIL "$(cx_msg svc_pending_run "$cmd")"
    cx_recovery_hint "$cmd"
    return 1
  done
  return 0
}
cx_svc_prepare() {
  CX_SVC_COMMAND=$1
  [ -f "$CX_ROOT/state.json" ] || cx_die "$CX_EXIT_REFUSED" svc_not_installed
  cx_state_load "$CX_ROOT/state.json"
  if [ "$(cx_state_get current.kind)" != package ] || [ -z "$(cx_state_get current.version)" ]; then
    cx_die "$CX_EXIT_REFUSED" svc_not_installed
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_compose_files >/dev/null || return "$CX_EXIT_REFUSED"
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  if [ "$(cx_state_get current.kind)" != package ] || [ -z "$(cx_state_get current.version)" ]; then
    cx_die "$CX_EXIT_REFUSED" svc_not_installed
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_compose_files >/dev/null || return "$CX_EXIT_REFUSED"
  cx_svc_pending || return "$CX_EXIT_REFUSED"
  cx_secrets_from_env "$CX_ROOT/.env"
  cx_log_open "$1" || return "$CX_EXIT_FAILED"
  cx_log BEGIN "$1 lang=${CX_LANG:-en} script=${CX_SELF#"$CX_ROOT"/} flags=\"${CX_FLAGS_TEXT# }\""
  trap 'cx_svc_signal' INT TERM HUP
}
# Compose lists the services of the current deployment, including stopped containers. The
# one-shot certificate initializer is intentionally excluded from the running set.
cx_svc_services() { cx_compose ps --all --services 2>/dev/null | sed '/^tls-init$/d'; }
cx_svc_running() { cx_compose ps --status running --services 2>/dev/null | sed '/^tls-init$/d'; }
cx_svc_stopped() {
  local running
  running=$(cx_svc_running) || return 1
  [ -z "$running" ]
}
cx_svc_all_running() {
  local all running
  all=$(cx_svc_services) || return 1
  [ -n "$all" ] || return 1
  running=$(cx_svc_running) || return 1
  [ "$(printf '%s\n' "$all" | sort)" = "$(printf '%s\n' "$running" | sort)" ]
}
