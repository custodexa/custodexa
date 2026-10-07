# shellcheck shell=bash
# Giving up never deletes recordings. Stop and observe all containers before replaying any
# interrupted rename, then retain this restore's files and return to the engine release.
# shellcheck disable=SC2034,SC2030,SC2031
cx_rs_abandon_paths() {
  local path
  [ "$(cx_state_get last_restore.covering)" = 1 ] || return 0
  for path in "$CX_RS_DATA/postgres" "$CX_RS_DATA/audit"; do
    # An external database keeps no folder on this host.
    [ "$path" != "$CX_RS_DATA/postgres" ] || ! cx_db_external || continue
    [ ! -d "$path" ] || printf '%s\n' "$path"
  done
  if [ "$(cx_rs_get contents.tls)" = true ] || [ -d "$CX_ROOT/tls.before-restore-$CX_RS_TS" ]; then
    [ ! -d "$CX_ROOT/tls" ] || printf '%s\n' "$CX_ROOT/tls"
  fi
  [ ! -f "$CX_ROOT/.env" ] || printf '%s\n' "$CX_ROOT/.env"
}
cx_rs_abandon_screen() {
  local active count path line
  active=$(cx_compose_release "$CX_ROOT/releases/$CX_RS_VERSION" ps --status running --services) || return 1
  count=$(printf '%s\n' "$active" | grep -c .) || true
  printf '%s\n\n' "$(cx_msg rs_abandon_title)"
  if [ "$count" = 0 ]; then cx_rs_par "$(cx_msg rs_abandon_stopped)"
  else cx_rs_par "$(cx_msg rs_abandon_services "$count")"; fi
  cx_rs_par "$(cx_msg rs_abandon_kept)"
  while IFS= read -r path; do cx_rs_par "$(cx_msg rs_abandon_path "$path.abandoned-$CX_RS_TS")"; done < <(cx_rs_abandon_paths)
  if [ -f "$CX_RS_DIR/env-before-restore" ]; then cx_rs_par "$(cx_msg rs_abandon_old_env)"; fi
  (
    local CX_RS_JOURNAL=$CX_RS_DIR/journal
    cx_rs_journal_load || exit 1
    for line in "${CX_RS_J_LINES[@]}"; do
      cx_rs_journal_parse "$line" || exit 1
      [ "${CX_RS_J_DONE[$CX_RS_J_SEQ]:-}" = 1 ] || continue
      case $CX_RS_J_ID in
        template-place) cx_rs_par "$(cx_msg rs_abandon_path "${CX_RS_J_ARGS[1]}.abandoned-$CX_RS_TS")" ;;
        template-before) cx_rs_par "$(cx_msg rs_abandon_old_template "${CX_RS_J_ARGS[0]}")" ;;
      esac
    done
  ) || return 1
  cx_rs_ext_abandon_screen
  cx_rs_par "$(cx_msg rs_abandon_tail "$CX_RS_DATA/recordings" "$CX_RS_ENGINE" "$CX_RS_VERSION")"
  printf '\n'
}
cx_rs_abandon() {
  local path key
  [ "$CX_RS_FLOW" = new ] || { cx_line FAIL "$(cx_msg rs_exit_wrong abandon)"; return 3; }
  cx_rs_exit_context || return 1
  # A non-empty external database being emptied and imported goes back only with its export.
  ! cx_rs_ext_abandon_refused || return 3
  if [ "$(cx_state_get last_restore.exit)" != abandoning ]; then
    cx_rs_abandon_screen && cx_rs_exit_confirm abandon || return "$?"
  fi
  cx_rs_exit_begin abandoning || return 1
  if ! cx_rs_stop_all; then
    cx_line FAIL "$(cx_msg rs_abandon_stop_failed)"
    cx_rs_control_hints
    return 1
  fi
  cx_rs_abandon_rest || return 1
  cx_rs_plaintext_clear "$CX_RS_DIR" && cx_rs_settle abandoned || return 1
  cx_line OK "$(cx_msg rs_abandon_done)"
}
# The files of this restore put aside, the settings and the release as before (also the end of a
# new host's --revert to its external database's export). The services are stopped.
cx_rs_abandon_rest() {
  local path key
  # Stop before replay: an earlier attempt might have died with an uncompleted move intent.
  cx_rs_reconcile resume || return 1
  while IFS= read -r path; do
    key=$(printf '%s' "$path" | sha256sum); key=${key%% *}
    cx_rs_journal_move "abandon-$key" "$path" "$path.abandoned-$CX_RS_TS" || return 1
  done < <(cx_rs_abandon_paths)
  cx_rs_exit_template abandoned || return 1
  if [ -f "$CX_RS_DIR/env-before-restore" ]; then
    cx_rs_journal_put abandon-env-original "$CX_RS_DIR/env-before-restore" "$CX_ROOT/.env" 0600 || return 1
  fi
  cx_rs_journal abandon-current link "$CX_ROOT/current" "$(readlink "$CX_ROOT/current")" "releases/$CX_RS_ENGINE" || return 1
  for key in "${CX_STATE_KEYS[@]}"; do
    [[ $key == current.* ]] || continue
    cx_rs_journal "abandon-$key" state "$key" "$(cx_state_get "$key")" '' || return 1
  done
}
