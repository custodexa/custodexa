# shellcheck shell=bash
# Recovery primitives. The exit dispatcher must reconcile before calling a route; restarting
# original services is valid only while the durable covering flag is absent.
# shellcheck disable=SC2034
cx_rs_tools_rm() {
  local name prefix=custodexa-restore-tool-$CX_RS_TS-
  local -a names=()
  while IFS= read -r name; do
    [[ $name != "$prefix"* ]] || names+=("$name")
  done < <(docker ps -a --filter "name=$prefix" --format '{{.Names}}' 2>/dev/null || true)
  [ "${#names[@]}" = 0 ] || docker rm -f "${names[@]}" >/dev/null 2>&1 || true
}
# Keep command redirections in a waited child, so the parent's signal screen stays visible.
cx_rs_compose_quiet() { cx_compose_release "$@" >/dev/null 2>&1; }
# Long imports run as a waited job so signals can stop the client and its children promptly.
# Its durable phase is read back by the parent; it does not transfer uncommitted shell state.
cx_rs_job() {
  local rc=0
  "$@" <&0 &
  CX_PB_JOB=$!
  wait "$CX_PB_JOB" || rc=$?
  CX_PB_JOB=""
  cx_state_load "$CX_ROOT/state.json"
  return "$rc"
}
cx_rs_interrupted() {
  local actual
  cx_pb_stop_jobs
  [ "${CX_PB_MODE:-}" != restore-safety ] || cx_pb_interrupt_cleanup
  cx_rs_tools_rm
  cx_db_pgpass_rm
  [ ! -d "$CX_RS_DIR" ] || find "$CX_RS_DIR" -type p -delete
  cx_state_load "$CX_ROOT/state.json"
  CX_RUN_STEP=$(cx_state_get last_restore.step)
  actual=$(cx_rs_actual_services)
  cx_line FAIL "$(cx_msg "rs_interrupted_$actual" "$CX_RUN_STEP")"
  [ "$actual" = stopped ] || cx_cmd "$(cx_rs_status_command)"
  cx_rs_failure_details
  cx_log END "result=interrupted phase=$(cx_state_get last_restore.phase) services=$actual"
}
cx_rs_plaintext_clear() {
  local dir=$1
  [ -d "$dir" ] || return 0
  find "$dir" -type f \( -name db.dump -o -name env.bak -o -name '*.tar.gz' -o -name env.merged -o -name key.raw -o -name '*.sql' \) -delete || return 1
  rm -rf -- "$dir/files-audit" "$dir/files-tls" "$dir/files-recordings"
}
# A timeout leaves exit=reverting and in_progress, so another --revert can finish the startup.
cx_rs_restart_original() {
  local CX_RS_VERSION CX_OVERLAYS
  local -A CX_RS_MAP=()
  [ "$(cx_state_get last_restore.covering)" != 1 ] || return 1
  CX_RS_VERSION=$(cx_state_get last_restore.prev_version)
  CX_OVERLAYS=$(cx_state_get current.overlays)
  CX_RS_MAP[deploy.overlays]=$CX_OVERLAYS
  cx_rs_leaving reverting && cx_rs_services starting || return 1
  if ! cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" up -d || ! cx_rs_health; then
    cx_line FAIL "$(cx_msg rs_revert_start_failed)"
    cx_cmd "$(cx_rs_control_command revert)"
    return 1
  fi
  cx_rs_services up && cx_rs_plaintext_clear "$CX_RS_DIR" && cx_rs_settle reverted || return 1
  cx_line OK "$(cx_msg rs_revert_original_done "$CX_RS_VERSION")"
}
