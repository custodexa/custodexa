# shellcheck shell=bash
# CX_UP_* are read by the upgrade command and the checks after the start.
# shellcheck disable=SC2034
# The 13 steps of upgrade. Steps 1 to 3 come before anything stops (lib/cmd_upgrade.sh runs the
# checks and the preview); from the confirmation on, this file:
#   3  begin: lock, log, last_upgrade in progress; the checked image references go next to the
#      target release (images.env, image-ids.env)
#   4  the drain gate (lib/drain_gate.sh)        5, 6  stop and prove gone (lib/stop_check.sh)
#   7  the snapshot, then the script's backup or the operator's own (lib/backup.sh, backup_ref.sh);
#      the backup folder also gets state.json as it was when the upgrade began, which is what
#      going back by hand puts in place again
#   8  the first conversion of a git clone deployment (lib/convert.sh); nothing on a package one
#   9  state.json: previous.* <- current.*, current.* <- the target; then current -> the target
#      release and the recordings folder prepared
#   10 start   11 ready within 180 seconds   12 the checks (lib/post_checks.sh)   13 the record
# A git clone deployment has no state.json before its conversion writes one: until step 8 its run
# only locks and logs; from there on it runs as a package deployment. A failure stops where it is and prints what the upgrade guide says for that
# step; nothing is rolled back on its own. A failure from step 8 on is recorded with its step, and
# the next upgrade refuses with the same commands (lib/upgrade_preflight.sh).
# shellcheck source=lib/post_checks.sh
. "${BASH_SOURCE[0]%/*}/post_checks.sh"
# shellcheck source=lib/convert.sh
. "${BASH_SOURCE[0]%/*}/convert.sh"

readonly CX_UP_READY_TRIES=60 CX_UP_READY_WAIT=3 # up to 180 seconds
CX_UP_D1="" CX_UP_D2="" CX_UP_DRAINED="" CX_UP_SNAP="" CX_UP_BACKUP_DIR="" CX_UP_BACKUP_KIND=""
CX_UP_HEALTH_VER="" CX_UP_STARTED=""
CX_UP_STATE0="" # state.json as the upgrade found it, byte for byte (a trailing x keeps the last newline)

# cx_up_at <n> <name>: the step now running (state.json once there is one, the log always).
cx_up_at() {
  if [ "$CX_UP_KIND" = package ]; then
    cx_step "$1" "$CX_UP_STEPS" "$2"
  else
    CX_RUN_STEP=$1
    cx_log STEP "$1/$CX_UP_STEPS $2"
  fi
}

# cx_up_end <succeeded|failed>: the end of the run, in state.json when there is one.
cx_up_end() {
  if [ "$CX_UP_KIND" = package ]; then
    cx_finish "$1"
  else
    cx_log END "result=$1 step=$CX_RUN_STEP"
    trap - INT TERM HUP
  fi
}

cx_up_fail_exit() { cx_up_end failed; exit "$CX_EXIT_FAILED"; }

# cx_up_again: a failure before anything stopped: how to run it again.
cx_up_again() {
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
  printf '%s\n' "$(cx_msg up_hint_again)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
}

# cx_up_images: step 2, before the preview. The images of the target release, then who published
# them; a layer that could not run asks first (the same screen as install). Nothing is written in
# the deployment folder here.
cx_up_images() {
  local t0 out
  t0=$(cx_now)
  out=$(mktemp)
  if ! cx_images_resolve "$CX_OVERLAYS" >"$out" 2>&1; then
    cx_up_step_line FAIL 2 "$(cx_msg up_step_images)"
    cat "$out"
    rm -f "$out"
    cx_up_again
    return "$CX_EXIT_FAILED"
  fi
  cx_trust_check
  rm -f "$out"
  CX_UP_D2=$(cx_duration $(($(cx_now) - t0)))
  cx_trust_screen
}

# cx_up_begin: step 3, once the preview is answered.
cx_up_begin() {
  if [ "$CX_UP_KIND" = package ]; then
    CX_UP_STATE0=$(cat -- "$CX_ROOT/state.json" && printf x) || CX_UP_STATE0=""
    # An earlier run that may start over (lib/upgrade_preflight.sh) is closed first.
    if [ "$CX_UP_RERUN" = 1 ]; then
      cx_state_set last_upgrade.result interrupted
      cx_state_save "$CX_ROOT/state.json"
    fi
    cx_begin upgrade
    cx_state_set last_upgrade.from "$CX_UP_CURRENT"
    cx_state_set last_upgrade.to "$CX_UP_TARGET"
    if [ -n "${CX_UP_PACKAGE_VERIFICATION:-}" ]; then
      cx_state_set last_upgrade.package_verification "$CX_UP_PACKAGE_VERIFICATION"
    fi
  else
    CX_RUN_CMD=upgrade
    cx_lock
    cx_secrets_from_env "$CX_ROOT/.env"
    cx_log_open upgrade
    cx_log BEGIN "upgrade (git clone deployment) lang=${CX_LANG:-en} script=$CX_SELF"
    # Read back when a conversion stopped before state.json was written (lib/convert.sh).
    cx_log CONVERT "project=$CX_UP_OLD_PROJECT files=$CX_UP_OLD_FILES"
    CX_UP_STARTED=$(date '+%Y-%m-%dT%H:%M:%S%z')
    exec {CX_SIGNAL_FD}>&2
    trap 'cx_on_signal' INT TERM HUP
  fi
  [ -z "${CX_UP_PACKAGE_VERIFICATION:-}" ] || cx_log VERIFY "package $CX_UP_PACKAGE_VERIFICATION"
  cx_log UPGRADE "from=$CX_UP_CURRENT to=$CX_UP_TARGET kind=$CX_UP_KIND"
  cx_log VERIFY "images $(cx_trust_state)"
  cx_up_at 3 confirmed
  if ! cx_images_write_env "$CX_DIR/images.env" || ! cx_images_write_ids "$CX_DIR/image-ids.env"; then
    cx_up_step_line FAIL 3 "$(cx_msg up_step_confirmed)"
    cx_up_again
    cx_up_fail_exit
  fi
}

# ---------- step 7 ----------

# cx_up_keep_state <backup folder>: state.json as the upgrade found it, into the backup (0600).
cx_up_keep_state() {
  [ -n "$CX_UP_STATE0" ] || return 0
  (umask 077 && printf '%s' "${CX_UP_STATE0%x}" >"$1/state.json") && chmod 0600 "$1/state.json"
}

# cx_up_sub <mark> <text>: a line under step 7, 8 columns in.
cx_up_sub() { printf '        %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'               }"; }

# cx_up_bk_cb: the callback of cx_bk_take: one line per part of the backup.
cx_up_bk_cb() { # <OK|FAIL> <n> <total> <step id> <start>
  local f text
  text=$(cx_msg "bk_step_$4")
  if [ "$1" = OK ]; then
    case $4 in
      db) f=custodexa-db-$CX_BK_TS.dump ;;
      files) f=custodexa-files-$CX_BK_TS.tar.gz ;;
      *) f="" ;;
    esac
    [ -z "$f" ] || text=$(cx_msg "up_bk_$4" "$f" "$(cx_bk_gb "$(cx_bk_du "$CX_BK_DIR/$f")")")
  fi
  cx_up_sub "$1" "$text"
}

# cx_up_own_backup: the operator's own backup (choice [2], --backup-ref, or an external database).
cx_up_own_backup() {
  local st rc=0 id
  if cx_br_flags_given; then
    # --backup-ref and its companions were checked before the preview (CX_BR_* are set).
    :
  else
    st=$(cx_br_backend)
    if [[ $st != stopped\ * ]] || ! cx_br_set_stop "${st#stopped }"; then
      cx_line FAIL "$(cx_msg br_stop_unknown)"
      return 1
    fi
    cx_br_interactive "$CX_UP_DRAINED" "$CX_UP_PRE_EXTERNAL_DB" || return 1
  fi
  id=$(date '+%Y%m%d-%H%M%S')
  if [ "$CX_UP_KIND" = package ]; then cx_br_record "$id" || rc=1; else cx_br_record "$id" nostate || rc=1; fi
  [ "$rc" = 0 ] || { cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"; return 1; }
  CX_UP_BACKUP_DIR=$CX_ROOT/backups/$id CX_UP_BACKUP_KIND=external
  cx_up_keep_state "$CX_UP_BACKUP_DIR" || { cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"; return 1; }
  # The database of an external-database deployment is not reachable from here: no snapshot.
  [ "$CX_UP_PRE_EXTERNAL_DB" = 0 ] || return 0
  cx_up_snapshot "$CX_UP_BACKUP_DIR/snapshot.txt"
}

# cx_up_snapshot <file>: what the checks after the start compare with.
cx_up_snapshot() {
  if ! cx_snap_take "$1" "$(cx_bk_env JWT_SECRET)"; then
    cx_up_sub FAIL "$(cx_msg up_bk_snap)"
    return 1
  fi
  CX_UP_SNAP=$1
  cx_log SNAPSHOT "usable=$CX_SNAP_USABLE${CX_SNAP_REASONS:+ reasons=\"$CX_SNAP_REASONS\"}"
  cx_up_sub OK "$(cx_msg up_bk_snap)"
}

# cx_up_backup <n>: step 7. The services are stopped (step 5).
cx_up_backup() {
  local n=$1 own=0
  cx_up_step_line RUN "$n" "$(cx_msg up_step_backup)"
  if [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ] || cx_br_flags_given; then
    own=1
  elif [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then
    cx_br_choose "$(cx_bk_gb "$CX_BK_NEED")" "$(cx_bk_minutes)" 0 || return 1
    [ "$CX_BR_CHOICE" = 1 ] || own=1
  fi
  if [ "$own" = 1 ]; then
    cx_up_own_backup
    return
  fi
  if ! cx_bk_open; then
    cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"
    return 1
  fi
  CX_UP_BACKUP_DIR=$CX_BK_DIR CX_UP_BACKUP_KIND=script
  cx_up_keep_state "$CX_BK_DIR" || { cx_up_bk_failed; return 1; }
  cx_up_snapshot "$CX_BK_DIR/snapshot.txt" || { cx_up_bk_failed; return 1; }
  cx_bk_take upgrade cx_up_bk_cb || { cx_up_bk_failed; return 1; }
  # A git clone deployment has no state.json yet: the conversion records the backup (step 8).
  [ "$CX_UP_KIND" != package ] || cx_bk_record
}

# cx_up_bk_failed: the backup did not finish: what is there, how to start the old version again.
cx_up_bk_failed() {
  printf '\n'
  cx_line FAIL "$(cx_msg bk_failed "$CX_BK_DIR/")"
  cx_up_resume_cmd
  [ "$CX_BK_KEK" != ui ] || cx_up_par "$(cx_msg up_unseal_after)"
}

# ---------- steps 8 to 11 ----------

# cx_up_convert <n>: step 8. A package deployment has nothing to reorganize.
cx_up_convert() {
  if [ "$CX_UP_KIND" = package ]; then
    cx_up_step_line SKIP "$1" "$(cx_msg up_step_convert_skip)"
    return 0
  fi
  cx_cv_run "$1"
}

# cx_up_record_switch: state.json before current moves: what runs now becomes previous.*, the
# target becomes current.* (a rollback reads previous.*). The clone a conversion came from ran under
# its own project and files.
cx_up_record_switch() {
  local k n src="" proj=$CX_PROJECT
  for k in version kind overlays release_dir images_env image_ids image_source verification since; do
    cx_state_set "previous.$k" "$(cx_state_get "current.$k")"
  done
  cx_state_set previous.image_ids "$CX_UP_PRE_OLD_IDS"
  if [ "$(cx_state_get current.kind)" = legacy-git-clone ]; then
    proj=$(cx_state_get conversion.old_project)
    cx_state_set previous.compose_files "$(cx_state_get conversion.old_files)"
  fi
  cx_state_set previous.compose_project "$proj"
  cx_state_set current.kind package
  cx_state_set current.overlays "$CX_OVERLAYS"
  for n in "${CX_IMG_NAMES[@]}"; do src+="${src:+ }$n=${CX_IMG_SRC[$n]:-?}"; done
  cx_state_set current.version "$CX_UP_TARGET"
  cx_state_set current.since "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set current.release_dir "releases/$CX_UP_TARGET"
  cx_state_set current.images_env "releases/$CX_UP_TARGET/images.env"
  cx_state_set current.image_ids "$(cx_images_ids_text)"
  cx_state_set current.image_source "$src"
  cx_state_set current.verification "$(cx_trust_state)"
  cx_state_save "$CX_ROOT/state.json"
}

# cx_up_link <link> <target>: point a symlink at target in one rename.
cx_up_link() {
  [ "$(readlink -- "$1" 2>/dev/null)" != "$2" ] || return 0
  ln -sfn -- "$2" "$1.new" && mv -Tf -- "$1.new" "$1"
}

# cx_up_recordings: the recordings folder as install prepares it (owner 1000, group 0, 2770).
cx_up_recordings() {
  local dir=$CX_BK_DATA/recordings img out
  img=${CX_IMG_REF[openssl]:-${CX_IMG_REF[guacd]:-}}
  mkdir -p "$dir" || return 1
  # shellcheck disable=SC2016 # the script runs inside the container
  out=$(cx_log_run docker run --rm --pull never --network none --user 0:0 -v "$dir:/r" \
    --entrypoint /bin/sh "$img" -c \
    'chown 1000:0 /r && chmod 2770 /r && find /r -mindepth 1 -maxdepth 1 -type f -group 1000 -exec chgrp 0 {} + && stat -c "%u:%g %a" /r') \
    || return 1
  [ "$(printf '%s\n' "$out" | tail -n1)" = "$CX_RECORDINGS_MODE" ]
}

# cx_up_switch <n>: step 9.
cx_up_switch() {
  cx_up_record_switch
  if ! cx_up_link "$CX_ROOT/current" "releases/$CX_UP_TARGET" \
    || ! cx_up_link "$CX_ROOT/custodexa.sh" current/custodexa.sh; then
    cx_up_step_line FAIL "$1" "$(cx_msg up_step_switch "$CX_UP_TARGET")"
    return 1
  fi
  if ! cx_up_recordings; then
    cx_up_step_line FAIL "$1" "$(cx_msg up_step_switch "$CX_UP_TARGET")"
    cx_up_par "$(cx_msg install_recordings_failed "$CX_BK_DATA/recordings")"
    return 1
  fi
  cx_up_step_line OK "$1" "$(cx_msg up_step_switch "$CX_UP_TARGET")"
}

# cx_up_start <n>: step 10.
cx_up_start() {
  local t0
  t0=$(cx_now)
  if ! cx_log_run cx_compose up -d --remove-orphans >/dev/null 2>&1; then
    cx_up_step_line FAIL "$1" "$(cx_msg up_step_start)"
    return 1
  fi
  cx_up_step_line OK "$1" "$(cx_msg up_step_start)" "$(cx_duration $(($(cx_now) - t0)))"
}

# cx_up_ready <n>: step 11. /health answers within 180 seconds (its version is checked in step 12).
cx_up_ready() {
  local t0 tries=0 health
  t0=$(cx_now)
  until health=$(cx_compose exec -T backend wget -qO- http://localhost:8080/health 2>/dev/null); do
    tries=$((tries + 1))
    if [ "$tries" -ge "$CX_UP_READY_TRIES" ]; then
      cx_up_step_line FAIL "$1" "$(cx_msg up_step_ready)"
      return 1
    fi
    sleep "$CX_UP_READY_WAIT"
  done
  CX_UP_HEALTH_VER=""
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && CX_UP_HEALTH_VER=${BASH_REMATCH[1]}
  cx_log CHECK "health version=${CX_UP_HEALTH_VER:-none}"
  cx_up_step_line OK "$1" "$(cx_msg up_step_ready)" "$(cx_duration $(($(cx_now) - t0)))"
}

# ---------- a failure after the switch ----------

# cx_up_fail_switched <headline message id> [args...]: steps 9 to 12. The new version is in place;
# the script does not roll back on its own.
cx_up_fail_switched() {
  local id=$1 st=up_state_switched
  shift
  [ "$id" != up_fail_ready ] || st=up_state_not_ready
  printf '\n'
  cx_line FAIL "$(cx_msg "$id" "$@")"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_state_title)")"
  cx_up_bullet "$(cx_msg "$st" "$CX_UP_TARGET")"
  cx_up_bullet_backup
  cx_up_bullet "$(cx_msg up_state_no_auto)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_logs_first)")"
  cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
  cx_up_par "$(cx_msg up_logs_more)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_restore_guide "$CX_UP_CURRENT")")"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
}

# cx_up_bullet <text>: "    - text", later lines under the text.
cx_up_bullet() { printf '    - %s\n' "${1//$'\n'/$'\n'      }"; }

cx_up_bullet_backup() {
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_up_bullet "$(cx_msg up_state_backup_own "$CX_UP_BACKUP_DIR/external.txt")"
  else
    cx_up_bullet "$(cx_msg up_state_backup "$CX_UP_BACKUP_DIR/")"
  fi
}

# ---------- the run ----------

# cx_up_main: steps 3 to 13, after the preview was answered yes.
cx_up_main() {
  cx_up_begin
  printf '%s\n%s\n\n' "$(cx_msg up_run_title "$CX_UP_CURRENT" "$CX_UP_TARGET")" "$(cx_msg bk_log "$CX_LOG_FILE")"
  cx_up_step_line OK 1 "$(cx_msg up_step_env)" "$CX_UP_D1"
  cx_up_step_line OK 2 "$(cx_msg up_step_images)" "$CX_UP_D2"
  cx_up_step_line OK 3 "$(cx_msg up_step_confirmed)"
  cx_up_at 4 drain
  cx_dg_wait 4 || cx_up_fail_exit
  CX_UP_DRAINED=$(date +%H:%M:%S)
  cx_up_at 5 stop
  cx_up_stop 5 || cx_up_fail_exit
  cx_up_at 6 gone
  cx_up_gone 6 || cx_up_fail_exit
  cx_up_at 7 backup
  cx_up_backup 7 || cx_up_fail_exit
  cx_up_at 8 convert
  cx_up_convert 8 || cx_up_fail_exit
  cx_up_at 9 switch
  cx_up_switch 9 || { cx_up_fail_switched up_fail_switch; cx_up_fail_exit; }
  cx_up_at 10 start
  cx_up_start 10 || { cx_up_fail_switched up_fail_start; cx_up_fail_exit; }
  cx_up_at 11 ready
  cx_up_ready 11 || { cx_up_fail_switched up_fail_ready $((CX_UP_READY_TRIES * CX_UP_READY_WAIT)); cx_up_fail_exit; }
  cx_up_at 12 check
  cx_up_post_checks 12 || cx_up_fail_exit
  cx_up_at 13 record
  cx_state_set last_upgrade.backup "${CX_UP_BACKUP_DIR#"$CX_ROOT"/}"
  cx_up_end succeeded
  cx_up_step_line OK 13 "$(cx_msg up_step_record)"
  cx_up_done
}
