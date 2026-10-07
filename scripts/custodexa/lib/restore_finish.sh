# shellcheck shell=bash
# Completion is recorded only after runtime evidence. Retained lists and before-state snapshots
# survive plaintext cleanup; any upgrade starts a normal, separately locked command.
# shellcheck disable=SC2034
# shellcheck source=lib/restore_recordings.sh
. "${BASH_SOURCE[0]%/*}/restore_recordings.sh"

cx_rs_previous() {
  local key
  local -A before=()
  local -a keys=()
  [ "$CX_RS_FLOW" = same ] || return 0
  cx_flat_parse "$CX_RS_DIR/state-before.json" before keys || return 1
  for key in "${CX_STATE_KEYS[@]}"; do [[ $key != previous.* ]] || cx_state_unset "$key"; done
  for key in "${keys[@]}"; do
    [[ $key != current.* ]] || cx_state_set "previous.${key#current.}" "${before[$key]}" || return 1
  done
}
cx_rs_kept_number() {
  if [ "$CX_LANG" = zh-TW ]; then printf '%s' "$1"
  else printf '%s' "$(($1 - 1))"; fi
}
cx_rs_kept_paths() {
  local path
  for path in "$CX_RS_DATA/postgres.before-restore-$CX_RS_TS" "$CX_RS_DATA/audit.before-restore-$CX_RS_TS" "$CX_ROOT/tls.before-restore-$CX_RS_TS"; do
    [ ! -d "$path" ] || printf '%s\n' "$path"
  done
}
cx_rs_finish_screen() {
  local at url provider file path count=0 first=""
  at=$(cx_rs_get created_at); at="${at:0:10} ${at:11:5}"
  file=${CX_RS_FILE##*/} url=$(cx_env_get "$CX_ROOT/.env" PUBLIC_BASE_URL) provider=$(cx_rs_get kek.provider)
  [ "$CX_RS_WAS_AWAITING" = 1 ] || cx_line OK "$(cx_msg "${1:-rs_finish_title}" "$CX_RS_VERSION")"
  cx_rs_par "$(cx_msg rs_finish_from "$file" "$at")"
  if [ "$CX_RS_FLOW" = same ]; then
    while IFS= read -r path; do count=$((count + 1)); [ -n "$first" ] || first=$path; done < <(cx_rs_kept_paths)
    if [ "$count" -gt 0 ]; then
      if [ "$(cx_state_get last_restore.safety)" = script ]; then
        file=$(cx_state_get last_restore.safety_file)
        cx_rs_par "$(cx_msg rs_finish_kept "$first" "$(cx_rs_kept_number "$count")" "${file#"$CX_ROOT"/}")"
      else
        cx_rs_par "$(cx_msg rs_finish_kept_own "$first" "$(cx_rs_kept_number "$count")" "$(cx_state_get last_restore.safety_ref)")"
      fi
    fi
  fi
  cx_rs_par "$(cx_msg rs_finish_address "$url")"
  cx_rs_par "$(cx_msg "rs_finish_key_$provider" "$(cx_rs_get kek.fingerprint)")"
  cx_rs_rec_section "$CX_RS_FLOW" "$(cx_rs_get contents.recordings)" "$(cx_rs_get source.data_path)" "$CX_RS_REC_PUT"
  if [ "$url" != "${CX_RS_HOST_SOURCE[PUBLIC_BASE_URL]}" ]; then cx_rs_rec_line WARN "$(cx_msg rs_finish_oidc "$url")"; fi
  [ -z "$CX_RS_CERT_WARNING" ] || cx_rs_par "$(cx_msg "rs_cert_$CX_RS_CERT_WARNING")"
  ! cx_rs_ext || { cx_rs_ext_finish_skipped && cx_rs_ext_finish_export; }
  cx_rs_par "$(cx_msg rs_finish_checklist)"
  cx_rs_par "$(cx_msg rs_failure_log "$CX_LOG_FILE")"
}
cx_rs_upgrade_existing() {
  [ "$(cx_vr_cmp "$CX_RS_ENGINE" "$CX_RS_VERSION")" = 1 ] || return 0
  cx_rs_par "$(cx_msg rs_upgrade_existing "$CX_RS_ENGINE")"
  cx_cmd "sudo $CX_DIR/custodexa.sh upgrade $CX_RS_ENGINE"
}
cx_rs_upgrade_handoff() {
  local target=$1
  cx_log END "result=succeeded upgrade=$target"
  trap - EXIT INT TERM HUP
  cx_rs_cleanup
  exec 9>&-
  exec bash "$CX_DIR/custodexa.sh" upgrade "$target" --lang "$CX_LANG"
}
cx_rs_upgrade_offer() {
  local answer rc=0
  printf '\n'
  if [ "$(cx_rs_get trigger)" = upgrade ]; then
    cx_rs_par "$(cx_msg rs_upgrade_before "$CX_RS_VERSION")"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade"
    return 0
  fi
  if [ ! -t 0 ]; then
    cx_rs_upgrade_existing
    cx_rs_par "$(cx_msg rs_upgrade_later)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade"
    return 0
  fi
  printf '%s\n' "$(cx_msg rs_upgrade_lookup)"
  cx_up_query_core menu || rc=$?
  if [ "$rc" != 0 ]; then
    cx_line WARN "$(cx_msg rs_upgrade_unknown)"
    cx_rs_upgrade_existing
    cx_rs_par "$(cx_msg rs_upgrade_lookup_later)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade"
  elif [ -n "$CX_Q_TARGET" ]; then
    cx_line ASK "$(cx_msg rs_upgrade_ask "$CX_Q_TARGET")"
    IFS= read -r answer || answer=""
    if [[ $answer == y || $answer == Y ]]; then cx_rs_upgrade_handoff "$CX_Q_TARGET"; return "$?"; fi
    cx_rs_par "$(cx_msg rs_upgrade_declined)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_Q_TARGET"
  elif [ "$(cx_vr_cmp "$(cx_mf version)" "$CX_RS_VERSION")" = 1 ]; then
    cx_rs_par "$(cx_msg rs_upgrade_lookup_later)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade"
  else cx_line OK "$(cx_msg rs_upgrade_current "$CX_RS_VERSION")"; fi
}
cx_rs_finish() {
  local CX_DB_RELEASE=$CX_ROOT/releases/$CX_RS_VERSION line
  CX_RS_REC_PUT=0
  cx_rs_journal_load || return 1
  for line in "${CX_RS_J_LINES[@]}"; do
    cx_rs_journal_parse "$line" || return 1
    if [[ $CX_RS_J_ID == recordings-* && $CX_RS_J_KIND == put ]] && [ "${CX_RS_J_DONE[$CX_RS_J_SEQ]:-}" = 1 ]; then
      CX_RS_REC_PUT=$((CX_RS_REC_PUT + 1))
    fi
  done
  [ "$(cx_rs_phase_value)" = "done" ] && [ "$(cx_state_get last_restore.kek_evidence)" = runtime-id ] || return 1
  # An external database: a run that carries on after the database check chose no client yet.
  if cx_rs_ext && [ -z "${CX_DB_EXT_ID:-}" ] && ! cx_rs_ext_with cx_rs_ext_ready; then return 1; fi
  cx_rs_recordings_missing "$CX_RS_DIR" && cx_rs_previous && cx_rs_plaintext_clear "$CX_RS_DIR" &&
    cx_run_upgrade_restored && cx_rs_settle succeeded || return 1
  cx_rs_finish_screen rs_finish_title
  cx_log END 'result=succeeded'
  cx_rs_upgrade_offer
}
