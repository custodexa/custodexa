# shellcheck shell=bash
# Exit operations have their own journal. Reconciliation of the forward journal classifies
# unfinished intents without replaying them; later exit retries replay only the exit journal.
# shellcheck disable=SC2034,SC2030,SC2031 # safety recovery intentionally isolates reader context
cx_rs_exit_begin() {
  local action=$1
  if [ ! -f "$CX_RS_DIR/exit-journal" ]; then
    cx_rs_reconcile exit || return 1
    (umask 077; touch "$CX_RS_DIR/exit-journal") && sync -f "$CX_RS_DIR/exit-journal" || return 1
  fi
  cx_rs_leaving "$action" || return 1
  CX_RS_JOURNAL=$CX_RS_DIR/exit-journal
}
cx_rs_exit_template() {
  local kind=$1 line path="" kept="" placed=0
  local CX_RS_JOURNAL=$CX_RS_DIR/journal
  cx_rs_journal_load || return 1
  for line in "${CX_RS_J_LINES[@]}"; do
    cx_rs_journal_parse "$line" || return 1
    [ "${CX_RS_J_DONE[$CX_RS_J_SEQ]:-}" = 1 ] || continue
    case $CX_RS_J_ID in
      template-place) path=${CX_RS_J_ARGS[1]}; placed=1 ;;
      template-before) path=${CX_RS_J_ARGS[0]}; kept=${CX_RS_J_ARGS[1]} ;;
    esac
  done
  CX_RS_JOURNAL=$CX_RS_DIR/exit-journal
  if [ "$placed" = 1 ]; then
    cx_rs_journal_move exit-template "$path" "$path.$kind-$CX_RS_TS" || return 1
  fi
  [ -z "$kept" ] || cx_rs_journal_move exit-template-original "$kept" "$path"
}
cx_rs_exit_confirm() {
  local kind=$1 answer
  [ "${CX_YES:-0}" != 1 ] || return 0
  [ -t 0 ] || { cx_line FAIL "$(cx_msg rs_exit_yes)"; return 3; }
  if [ "$kind" = safety ]; then
    printf '%s\n> ' "$(cx_msg rs_revert_confirm_version "$(cx_state_get last_restore.prev_version)")"
    IFS= read -r answer && [ "$answer" = "$(cx_state_get last_restore.prev_version)" ] && return 0
  else
    if [ "$kind" = original ]; then printf '%s' "$(cx_msg rs_exit_confirm_original "$(cx_state_get last_restore.prev_version)")"
    else printf '%s' "$(cx_msg rs_exit_confirm_abandon)"; fi
    IFS= read -r answer && [[ $answer == y || $answer == Y ]] && return 0
  fi
  cx_line WARN "$(cx_msg rs_exit_cancelled)"
  return 3
}
cx_rs_revert_screen() {
  local file at count=0 path first="" minutes bytes
  file=$(cx_state_get last_restore.safety_file)
  at=$(date -d "$(cx_state_get last_restore.stopped_at)" '+%Y-%m-%d %H:%M' 2>/dev/null) || at='?'
  for path in "$CX_RS_DATA/postgres" "$CX_RS_DATA/audit" "$CX_ROOT/tls"; do
    [ -d "$path" ] || continue
    # An external database keeps no folder on this host.
    [ "$path" != "$CX_RS_DATA/postgres" ] || ! cx_db_external || continue
    count=$((count + 1)); [ -n "$first" ] || first=$path.partial-restore-$CX_RS_TS
  done
  printf '%s\n\n' "$(cx_msg rs_revert_title)"
  cx_rs_par "$(cx_msg rs_revert_details "${file#"$CX_ROOT"/}" "$at" "$(cx_state_get last_restore.prev_version)")"
  [ "$count" = 0 ] || cx_rs_par "$(cx_msg rs_revert_partial "$first" "$(cx_rs_kept_number "$count")")"
  bytes=$(stat -c %s "$file") || return 1
  minutes=$(((bytes + CX_BK_RATE * 60 - 1) / (CX_BK_RATE * 60) + 5))
  cx_rs_par "$(cx_msg rs_revert_downtime "$minutes")"
  printf '\n'
}
# Recover enough host context for exits even if the input staging has been lost. Exits do not
# trust a damaged input payload: going back reads the independent safety backup from scratch.
cx_rs_exit_context() {
  local env=$CX_ROOT/.env
  [ -f "$env" ] || env=$CX_RS_DIR/env.merged
  CX_RS_DATA=$(cx_env_get "$env" DATA_PATH)
  [ -n "$CX_RS_DATA" ] || CX_RS_DATA=$CX_ROOT/data
  [[ $CX_RS_DATA == /* ]] || CX_RS_DATA=$CX_ROOT/${CX_RS_DATA#./}
  CX_OVERLAYS=$(cx_state_get current.overlays)
  if [ -f "$CX_RS_DIR/pass2/backup-manifest.json" ]; then
    cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || return 1
    [ -n "$CX_OVERLAYS" ] || CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  fi
  (umask 077; mkdir -p "$CX_RS_DIR") || return 1
  CX_COMPOSE_ENV=$env
}
# The safety restore uses the same stages and checks, a separate working folder/journal and a
# durable phase file. The parent restore remains in_progress/reverting until runtime checks pass.
cx_rs_revert_safety() {
  local parent=$CX_RS_DIR rc=0 original_version=$CX_RS_VERSION
  local safety
  safety=$(cx_state_get last_restore.safety_file)
  cx_rs_exit_begin reverting || return 1
  cx_rs_job cx_rs_revert_work "$parent" "$original_version" "$safety" || rc=$?
  cx_state_load "$CX_ROOT/state.json"
  [ "$rc" = 0 ] || { cx_rs_control_hints; return "$rc"; }
  cx_rs_plaintext_clear "$parent" && cx_rs_settle reverted
}
cx_rs_revert() {
  # A new host goes back only to its external database's export.
  if [ "$CX_RS_FLOW" = new ] && [ "$(cx_state_get last_restore.safety)" = db-dump ]; then cx_rs_ext_revert; return; fi
  [ "$CX_RS_FLOW" = same ] || { cx_line FAIL "$(cx_msg rs_exit_wrong revert)"; return 3; }
  cx_rs_exit_context || return 1
  if [ "$(cx_state_get last_restore.covering)" != 1 ]; then
    cx_rs_exit_confirm original || return "$?"
    cx_rs_restart_original
  elif [ "$(cx_state_get last_restore.safety)" = script ]; then
    if [ "$(cx_state_get last_restore.exit)" != reverting ]; then
      cx_rs_revert_screen
      cx_rs_exit_confirm safety || return "$?"
    fi
    cx_rs_revert_safety
  else
    cx_rs_par "$(cx_msg rs_failure_own "$(cx_state_get last_restore.safety_restore)" "$(cx_state_get last_restore.safety_ref)" "$(cx_state_get last_restore.safety_time)")"
    return 3
  fi
}
cx_rs_no_pending() {
  local at file
  if [ "$CX_RS_ACTION" = revert ] && [ "$(cx_state_get last_restore.result)" = succeeded ]; then
    at=$(cx_state_get last_restore.finished_at); at="${at:0:10} ${at:11:5}"
    cx_line FAIL "$(cx_msg rs_revert_finished "$at")"
    if [ "$(cx_state_get last_restore.safety)" = own ]; then
      cx_rs_par "$(cx_msg rs_failure_own "$(cx_state_get last_restore.safety_restore)" "$(cx_state_get last_restore.safety_ref)" "$(cx_state_get last_restore.safety_time)")"
    else
      cx_rs_par "$(cx_msg rs_revert_fresh)"
      file=$(cx_state_get last_restore.safety_file)
      cx_cmd "sudo $CX_ROOT/custodexa.sh restore $file"
    fi
    cx_rs_unchanged
  else cx_line FAIL "$(cx_msg rs_no_pending)"; fi
  return 3
}

cx_rs_revert_work() {
  local parent=$1 original_version=$2 safety=$3
  CX_RS_DIR=$parent/revert CX_RS_JOURNAL="" CX_RS_PHASE_FILE=$parent/revert/phase
  CX_RS_KEEP_KIND=partial-restore CX_RS_FLOW=same CX_RS_ACTION=revert
  CX_RS_NO_CHECKSUM=0 CX_PASSPHRASE_FILE="" CX_PB_PASS=""
  mkdir -p "$CX_RS_DIR" && chmod 0700 "$CX_RS_DIR" || exit 1
  if [ ! -f "$CX_RS_PHASE_FILE" ]; then
    cx_rs_open "$safety" && cx_rs_checks && cx_rs_release "$CX_RS_VERSION" && cx_rs_migrations &&
      cx_rs_env_merge && cx_rs_context_save || exit 1
    # Stop with the release whose services the failed restore might have started.
    CX_RS_VERSION=$original_version
    cx_rs_stop_all || exit 1
    CX_RS_VERSION=$(cx_rs_get product.version)
    (CX_RS_DIR=$parent; CX_RS_JOURNAL=$parent/exit-journal
      cx_rs_reconcile resume && cx_rs_exit_template partial-restore) || exit 1
    cx_rs_phase stopped || exit 1
  else
    [ "$(cx_rs_phase_value)" != "done" ] || return 0
    cx_rs_input_verify || exit 1
    CX_RS_VERSION=$(cx_rs_get product.version)
    cx_rs_env_context || exit 1
  fi
  CX_COMPOSE_ENV=$CX_ROOT/.env
  cx_rs_run || exit "$?"
  cx_rs_recordings_missing "$CX_RS_DIR" || exit 1
  cx_rs_finish_screen rs_revert_done
  cx_rs_plaintext_clear "$CX_RS_DIR"
}
