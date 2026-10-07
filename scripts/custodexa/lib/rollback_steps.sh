# shellcheck shell=bash
# Four resumable steps. The immutable version records let a retry repair either side of a
# interrupted state/link update without swapping the versions a second time.
# shellcheck disable=SC2034
readonly CX_RB_FIELDS='version kind overlays release_dir images_env image_ids image_source verification since tool_image_ids compose_project'
CX_RB_FRESH=0 CX_RB_DIRECTION=rollback CX_RB_CHECK_ERROR="" CX_RB_STOPPED=0

cx_rb_save() { cx_state_save "$CX_ROOT/state.json"; }
cx_rb_at() { cx_step "$1" 4 "$2"; }
cx_rb_link() { cx_up_link "$@"; }
cx_rb_apps_stopped() {
  local running
  running=$(cx_svc_running) || return 1
  [ -z "$(printf '%s\n' "$running" | sed '/^postgres$/d; /^$/d')" ]
}

# Save both endpoints once. An upgrade may have recorded step 9 before writing current.*;
# in that case its prepared target release supplies the new version's image record.
cx_rb_endpoints() {
  local side prefix k v from to ids
  from=$(cx_state_get last_upgrade.to) to=$(cx_state_get last_upgrade.from)
  cx_state_set last_rollback.from "$from"
  cx_state_set last_rollback.to "$to"
  for side in from to; do
    v=$from; [ "$side" != to ] || v=$to
    prefix=previous
    [ "$(cx_state_get current.version)" != "$v" ] || prefix=current
    for k in $CX_RB_FIELDS; do
      cx_state_set "last_rollback.$side.$k" "$(cx_state_get "$prefix.$k")" || return 1
    done
    if [ "$(cx_state_get "$prefix.version")" != "$v" ]; then
      ids=$(tr '\n' ' ' <"$CX_ROOT/releases/$v/image-ids.env") || return 1
      cx_state_set "last_rollback.$side.version" "$v"
      cx_state_set "last_rollback.$side.kind" package
      cx_state_set "last_rollback.$side.overlays" "$(cx_state_get current.overlays)"
      cx_state_set "last_rollback.$side.release_dir" "releases/$v"
      cx_state_set "last_rollback.$side.images_env" "releases/$v/images.env"
      cx_state_set "last_rollback.$side.image_ids" "${ids% }"
      cx_state_set "last_rollback.$side.compose_project" "$CX_PROJECT"
    fi
  done
  cx_state_set last_rollback.preswitch "$CX_RB_PRESWITCH"
}

cx_rb_stop_apps() {
  local all svc
  local -a apps=()
  CX_RB_STOPPED=0
  if cx_rb_apps_stopped; then CX_RB_STOPPED=1; return 0; fi
  all=$(cx_svc_services) || return 1
  for svc in $all; do [ "$svc" = postgres ] || apps+=("$svc"); done
  [ ${#apps[@]} -gt 0 ] || return 1
  cx_log_run cx_compose stop "${apps[@]}" >/dev/null 2>&1 || return 1
  cx_rb_apps_stopped
}

cx_rb_switch() {
  local target side other k running checked=0
  target=$(cx_state_get last_rollback.target)
  cx_state_load "$CX_ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_rb_apps_stopped || return 1
  if [ "$(cx_state_get current.version)" = "$target" ] &&
    [ "$(readlink "$CX_ROOT/current")" = "releases/$target" ]; then
    cx_rb_link "$CX_ROOT/custodexa.sh" current/custodexa.sh
    return
  fi
  if [ "$CX_RB_DIRECTION" = rollback ]; then
    CX_RB_TARGET=$target
    # After a crash between the last check and the switch, a stopped database cannot be
    # queried. Reuse the durable check only while ALL services stayed stopped. If anything
    # was started in between, the database must pass the live check again.
    running=$(cx_svc_running) || return 1
    if [ -z "$running" ] && [ "$(cx_state_get last_rollback.switch_checked)" = "$target" ]; then
      checked=1
    fi
    if [ "$checked" = 0 ]; then
      if ! cx_rb_judge; then
        cx_state_set last_rollback.result refused
        cx_state_set last_rollback.refusal_reason "$CX_RB_REASON"
        cx_state_set last_rollback.refused_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
        cx_rb_save || return 1
        cx_log END 'result=refused step=2'
        cx_rb_refused 1
        return 2
      fi
      cx_state_set last_rollback.basis "$CX_RB_BASIS"
    fi
  fi
  cx_state_set last_rollback.switch_checked "$target"
  cx_rb_save || return 1
  if ! cx_db_external; then
    cx_log_run cx_compose stop postgres >/dev/null 2>&1 || return 1
    running=$(cx_svc_running) || return 1
    [ -z "$running" ] || return 1
  fi
  # Writing both records is one state save. The saved endpoints make retrying either
  # link operation independent of which rename succeeded before an interruption.
  side=to other=from
  [ "$CX_RB_DIRECTION" != revert ] || { side=from; other=to; }
  for k in $CX_RB_FIELDS; do
    cx_state_set "current.$k" "$(cx_state_get "last_rollback.$side.$k")" || return 1
    cx_state_set "previous.$k" "$(cx_state_get "last_rollback.$other.$k")" || return 1
  done
  cx_state_set current.since "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_rb_save || return 1
  cx_rb_link "$CX_ROOT/current" "releases/$target" || return 1
  cx_rb_link "$CX_ROOT/custodexa.sh" current/custodexa.sh || return 1
  CX_OVERLAYS=$(cx_state_get current.overlays)
}

cx_rb_check() {
  local pair name want got
  CX_RB_CHECK_ERROR=""
  if ! cx_wait_backend_health; then CX_RB_CHECK_ERROR=health; return 1; fi
  if [ "$CX_UP_HEALTH_VER" != "$CX_RB_TARGET" ]; then CX_RB_CHECK_ERROR=version; return 1; fi
  for pair in $(cx_state_get current.image_ids); do
    name=${pair%%=*} want=${pair#*=}
    got=$(docker inspect --format '{{.Image}}' "$(cx_img_container "$name")" 2>/dev/null) || got=""
    [ "$got" = "$want" ] || CX_RB_CHECK_ERROR+="${CX_RB_CHECK_ERROR:+ }$name"
  done
  [ -z "$CX_RB_CHECK_ERROR" ]
}

cx_rb_main() {
  local drain rc=0 text result
  # Do not change the recorded step before the drain passes: a resumed attempt can have
  # switched already, and an unconfirmed drain must keep that recovery information.
  if ! drain=$(cx_dg_wait 0 service); then
    printf '%s\n' "$drain"
    if [ "$CX_RB_FRESH" = 1 ]; then
      cx_finish cancelled
      printf '%s\n' "$(cx_msg pre_nothing_changed)"
      return "$CX_EXIT_REFUSED"
    fi
    cx_rb_failed
    return "$CX_EXIT_FAILED"
  fi
  cx_rb_at 1 stop || return 1
  if ! cx_rb_stop_apps; then cx_step_line FAIL 1/4 "$(cx_msg rb_step_stop)"; cx_rb_failed; return 1; fi
  text=$(cx_msg rb_step_stop)
  [ "$CX_RB_STOPPED" = 0 ] || text=$(cx_msg rb_step_stopped)
  cx_step_line OK 1/4 "$text"
  cx_rb_at 2 switch || return 1
  cx_rb_switch || rc=$?
  [ "$rc" != 2 ] || { trap - INT TERM HUP; return 1; }
  text=$(cx_msg rb_step_switch "$CX_RB_TARGET")
  [ "$CX_RB_DIRECTION" != revert ] || text=$(cx_msg rb_step_revert "$CX_RB_TARGET")
  if [ "$rc" != 0 ]; then cx_step_line FAIL 2/4 "$text"; cx_rb_failed; return 1; fi
  cx_step_line OK 2/4 "$text"
  cx_rb_at 3 start || return 1
  if ! cx_rb_start; then cx_step_line FAIL 3/4 "$(cx_msg rb_step_start)"; cx_rb_failed; return 1; fi
  cx_step_line OK 3/4 "$(cx_msg rb_step_start)"
  cx_rb_at 4 check || return 1
  if ! cx_rb_check; then
    case $CX_RB_CHECK_ERROR in
      health) text=$(cx_msg rb_check_health "$(cx_ready_seconds)") ;;
      *) text=$(cx_msg rb_check_diff "$CX_RB_CHECK_ERROR") ;;
    esac
    cx_step_line FAIL 4/4 "$text"
    cx_rb_failed
    return 1
  fi
  text=$(cx_msg rb_step_check "$CX_RB_TARGET")
  [ "$CX_RB_DIRECTION" != revert ] || text=$(cx_msg rb_step_check_revert "$CX_RB_TARGET")
  cx_step_line OK 4/4 "$text"
  result=succeeded
  if [ "$CX_RB_DIRECTION" = revert ]; then
    result=reverted
  else
    cx_state_set last_upgrade.result rolled_back
    cx_state_set last_upgrade.rolled_back_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  fi
  cx_finish "$result"
  cx_rb_done
}
