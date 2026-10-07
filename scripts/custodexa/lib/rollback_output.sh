# shellcheck shell=bash
# CX_RB_TARGET is supplied by rollback_check.sh and cmd_rollback.sh.
# shellcheck disable=SC2153
# Rollback screens and recovery commands. All state descriptions are read when printed.
cx_rb_status_hint() {
  cx_up_par "$(cx_msg rb_status_hint)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
}
# cx_rb_bullet <text>: one item of the "current state" list, later lines under its text.
cx_rb_bullet() { printf '%s\n' "$1" | sed '1s/^/    - /; 2,$s/^/      /'; }
# cx_rb_minute <recorded time>: 2026-11-05T09:30:12+0800 shown as 2026-11-05 09:30.
cx_rb_minute() { printf '%s %s' "${1:0:10}" "${1:11:5}"; }
cx_rb_hint() {
  cx_up_par "$(cx_msg rb_upgrade_hint "$(cx_state_get last_upgrade.from)" "$(cx_state_get last_upgrade.from)")"
  cx_cmd "sudo $CX_ROOT/custodexa.sh rollback$(cx_status_lang_arg)"
}
cx_rb_restore_hint() {
  local backup kind target
  backup=$(cx_state_get last_upgrade.backup) kind=$(cx_state_get last_upgrade.backup_kind)
  target=$(cx_state_get last_upgrade.from)
  if ! cx_rb_older "$target" "$CX_RB_MIN" && [ "$kind" = script ] && [ -f "$CX_ROOT/$backup" ]; then
    cx_up_par "$(cx_msg rb_restore "$target")"
    cx_cmd "sudo $CX_ROOT/custodexa.sh restore $CX_ROOT/$backup$(cx_status_lang_arg)"
  else
    cx_up_par "$(cx_msg up_restore_guide "$target")"
    if [ -n "$backup" ]; then
      [ "$kind" != external ] || backup+=/external.txt
      cx_up_par "$(cx_msg up_done_backup "$CX_ROOT/$backup")"
    fi
  fi
}
cx_rb_premise_screen() {
  if [ "$CX_RB_WHY" = too_old ]; then
    cx_line FAIL "$(cx_msg rb_too_old "$CX_RB_TARGET")"
    cx_rb_restore_hint
    return
  fi
  cx_line FAIL "$(cx_msg rb_no_previous)"
  case $CX_RB_WHY in
    already)
      cx_up_par "$(cx_msg rb_already "$(cx_rb_minute "$(cx_state_get last_upgrade.rolled_back_at)")" \
        "$(cx_state_get last_upgrade.to)" "$CX_RB_TARGET" "$(cx_state_get last_upgrade.to)")" ;;
    before_switch)
      cx_up_par "$(cx_msg rb_before_switch "$(cx_state_get last_upgrade.step)")"
      # The upgrade preflight needs the portable/backup helpers; load only for this recovery.
      # shellcheck source=lib/upgrade_preflight.sh
      . "${BASH_SOURCE[0]%/*}/upgrade_preflight.sh"
      # shellcheck source=lib/stop_check.sh
      . "${BASH_SOURCE[0]%/*}/stop_check.sh"
      CX_UP_TARGET=$(cx_state_get last_upgrade.to)
      cx_up_recovery_hint last_upgrade "$(cx_state_get last_upgrade.step)"
      return ;;
    *) cx_up_par "$(cx_msg "rb_premise_$CX_RB_WHY")" ;;
  esac
  cx_rb_status_hint
}
cx_rb_refused() {
  local after=$1 new desc items="" item count=${#CX_RB_ADDED[@]} shown=0 key=rb_refused
  [ "$CX_RB_REASON" != unreadable ] || key=rb_refused_unreadable
  new=$(cx_state_get last_upgrade.to)
  if [ "$after" = 1 ]; then
    cx_line FAIL "$(cx_msg "${key}_after" "$CX_RB_TARGET" "$new")"
  else
    desc=$(cx_msg rb_services_running)
    if cx_rb_apps_stopped; then desc=$(cx_msg rb_services_stopped); fi
    cx_line FAIL "$(cx_msg "$key" "$CX_RB_TARGET" "$new" "$desc")"
  fi
  if [ "$CX_RB_REASON" = changed ]; then
    for item in "${CX_RB_ADDED[@]}"; do
      [ "$shown" -lt 3 ] || break
      items+="${items:+, }$item"; shown=$((shown + 1))
    done
    [ "$count" -le 3 ] || items+="$(cx_msg rb_more "$((count - 3))")"
    cx_up_par "$(cx_msg rb_reason_changed "$count" "$items" "$CX_RB_TARGET")"
  else
    cx_up_par "$(cx_msg rb_reason_unreadable)"
  fi
  cx_rb_restore_hint
  if [ "$after" = 1 ] && [ "$(cx_state_get last_upgrade.result)" != in_progress ]; then
    cx_up_par "$(cx_msg rb_keep_new "$new")"
    cx_cmd "sudo $CX_ROOT/custodexa.sh start$(cx_status_lang_arg)"
  fi
}
cx_rb_images_screen() {
  local row name kind want now arch unknown=0
  for row in "${CX_RB_IMG_BAD[@]}"; do
    [[ $row != 'release missing' && $row != *' unrecorded' ]] || unknown=1
  done
  if [ "$unknown" = 1 ]; then
    cx_line FAIL "$(cx_msg rb_images_unverified "$CX_RB_TARGET")"
  else
    cx_line FAIL "$(cx_msg rb_images_bad "$CX_RB_TARGET" "${#CX_RB_IMG_BAD[@]}")"
  fi
  for row in "${CX_RB_IMG_BAD[@]}"; do
    read -r name kind want now <<<"$row"
    if [ "$name" = release ]; then
      cx_up_par "$(cx_msg rb_release_unverified)"
    elif [ "$kind" = differs ]; then
      cx_up_par "$(cx_msg rb_image_diff "$(printf '%-9s' "$name")" "$want" "$now")"
    elif [ "$kind" = unrecorded ]; then
      cx_up_par "$(cx_msg rb_image_unrecorded "$(printf '%-9s' "$name")")"
    else
      cx_up_par "$(cx_msg rb_image_missing "$(printf '%-9s' "$name")")"
    fi
  done
  case $(uname -m) in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
  cx_up_par "$(cx_msg rb_load "$CX_RB_TARGET")"
  cx_cmd "sudo $CX_ROOT/custodexa.sh load <custodexa-images-$CX_RB_TARGET-$arch.tar>$(cx_status_lang_arg)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh rollback$(cx_status_lang_arg)"
}
cx_rb_preview() {
  local count=0 pair text key=rb_basis_compatible
  for pair in $(cx_rb_target_ids); do count=$((count + 1)); done
  [ "${#CX_RB_ADDED[@]}" != 1 ] || key=rb_basis_compatible_one
  printf '%s\n\n' "$(cx_msg rb_preview)"
  cx_up_par "$(cx_msg rb_versions "$(cx_state_get last_upgrade.to)" "$CX_RB_TARGET")"
  case $CX_RB_BASIS in
    same_migrations) text=$(cx_msg rb_basis_same) ;;
    not_started) text=$(cx_msg rb_basis_not_started) ;;
    compatible)
      if [ "$CX_RB_READ" = 1 ]; then
        text=$(cx_msg "$key" "${#CX_RB_ADDED[@]}" "$(cx_state_get last_upgrade.to)" "$CX_RB_TARGET")
      else
        text=$(cx_msg rb_basis_compatible_unreadable "$(cx_state_get last_upgrade.to)" "$CX_RB_TARGET")
      fi ;;

  esac
  cx_up_par "$text"
  cx_up_par "$(cx_msg rb_keep_data)"
  cx_up_par "$(cx_msg rb_images "$count")"
  printf '\n'
  cx_up_par "$(cx_msg rb_steps "$CX_RB_TARGET")"
  cx_up_par "$(cx_msg rb_keep_records)"
  printf '\n'
}
cx_rb_failed() {
  local version link running step
  step=$(cx_state_get last_rollback.step)
  version=$(cx_state_get current.version) link=$(readlink "$CX_ROOT/current" 2>/dev/null) || link=""
  cx_log END "result=in_progress step=$(cx_state_get last_rollback.step)"
  printf '\n'
  cx_up_par "$(cx_msg rb_state_title)"
  if [ "$link" = "releases/$version" ]; then
    if [ "$step" = 4 ] && [ "${CX_RB_CHECK_ERROR:-}" = health ]; then
      cx_rb_bullet "$(cx_msg rb_state_not_ready "$version")"
    elif [ "$step" = 1 ] && [ "$version" = "$(cx_state_get last_rollback.from)" ]; then
      cx_rb_bullet "$(cx_msg rb_state_before "$version")"
    elif [ "$step" = 3 ]; then
      cx_rb_bullet "$(cx_msg rb_state_start_failed "$version")"
    else
      cx_rb_bullet "$(cx_msg rb_state_version "$version")"
    fi
  else
    cx_rb_bullet "$(cx_msg rb_state_links "$version" "$link")"
  fi
  running=$(cx_svc_running) || running="?"
  [ -n "$running" ] || running=$(cx_msg rb_no_services)
  cx_rb_bullet "$(cx_msg rb_state_services "${running//$'\n'/ }")"
  cx_rb_bullet "$(cx_msg rb_unchanged_data)"
  cx_up_par "$(cx_msg up_logs_first)"
  cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
  cx_recovery_hint rollback
  cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")"
  trap - INT TERM HUP
}
cx_rb_done() {
  local text url
  printf '\n'
  if [ "$CX_RB_DIRECTION" = revert ]; then
    text=$(cx_msg rb_reverted "$CX_RB_TARGET")
  else
    text=$(cx_msg rb_done "$CX_RB_TARGET")
  fi
  case $CX_BK_KEK in
    ui | kms | hsm)
      url=$(cx_bk_env PUBLIC_BASE_URL)
      # Sentences in Chinese and Japanese follow each other without a space.
      case $CX_LANG in zh-TW | ja) ;; *) text+=" " ;; esac
      text+=$(cx_msg rb_unseal "${url%/}/unseal") ;;
  esac
  cx_line OK "$text"
  [ "$CX_RB_DIRECTION" != rollback ] || cx_up_par "$(cx_msg rb_upgrade_later)"
  cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}
