# shellcheck shell=bash
# CX_STATUS_WARNED is consumed by cmd_status after all sections.
# shellcheck disable=SC2034
# The restore section uses the durable record, including exits that have not settled yet.
cx_rs_kept_count() {
  local data stamp count=0 path
  data=$(cmd_status_data_path) stamp=$(cx_state_get last_restore.stamp)
  [ -n "$stamp" ] || { printf 0; return; }
  for path in "$data/postgres.before-restore-$stamp" "$data/audit.before-restore-$stamp" "$CX_ROOT/tls.before-restore-$stamp" \
    "$data/postgres.abandoned-$stamp" "$data/audit.abandoned-$stamp" "$CX_ROOT/tls.abandoned-$stamp"; do
    [ ! -d "$path" ] || count=$((count + 1))
  done
  printf '%s' "$count"
}
cx_rs_status_line() {
  case $1 in OK) ;; *) CX_STATUS_WARNED=1 ;; esac
  cx_line "$1" "$2" | sed 's/^/  /'
}
cmd_status_restore() {
  local result phase leaving file at hint
  result=$(cx_state_get last_restore.result)
  [ -n "$result" ] || return 0
  printf '%s\n' "$(cx_msg rs_status_title)"
  phase=$(cx_state_get last_restore.phase) leaving=$(cx_rs_exit_action)
  file=$(cx_state_get last_restore.file); file=${file##*/}
  at=$(cmd_status_minute "$(cx_state_get last_restore.finished_at)")
  case $result in
    in_progress)
      if [ -n "$leaving" ]; then
        cx_rs_status_line WARN "$(cx_msg "rs_status_$leaving")"
        cmd_status_under "$(cx_rs_control_command "$leaving")"
      elif [ "$phase" = awaiting_unseal ] || [ "$phase" = started ]; then
        cx_rs_status_line WARN "$(cx_msg rs_status_pending "$(cx_rs_phase_text)" "$(cx_rs_started_minute)" "$(cx_state_get last_restore.product_version)")"
        cmd_status_under "$(cx_msg rs_status_from "$file")"
        cmd_status_under "$(cx_msg rs_status_resume "$(cx_rs_control_command resume)")"
      else
        cx_rs_status_line WARN "$(cx_msg rs_status_failed "$(cx_state_get last_restore.step)")"
        while IFS= read -r hint; do cmd_status_under "${hint#    }"; done < <(cx_rs_control_hints)
      fi ;;
    succeeded)
      cx_rs_status_line OK "$(cx_msg rs_status_done "$at" "$file")"
      hint=$(cx_msg rs_status_kept "$(cx_rs_kept_count)")
      while IFS= read -r hint; do cmd_status_under "$hint"; done <<<"$hint" ;;
    reverted|abandoned)
      cx_rs_status_line OK "$(cx_msg "rs_status_$result" "$at")"
      cmd_status_under "$(cx_msg rs_status_retained "$(cx_rs_kept_count)")" ;;
  esac
  printf '\n'
}
