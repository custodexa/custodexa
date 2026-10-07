# shellcheck shell=bash
# CX_UP_* are read by the upgrade command and the checks after the start.
# shellcheck disable=SC2034
# The 13 steps of upgrade. Steps 1 to 3 come before anything stops (lib/cmd_upgrade.sh runs the
# checks and the preview); from the confirmation on, this file:
#   3  begin: lock, log, last_upgrade in progress; the checked image references go next to the
#      target release (images.env, image-ids.env)
#   4  the drain gate (lib/drain_gate.sh)        5, 6  stop and prove gone (lib/stop_check.sh)
#   7  the snapshot, then the script's backup or the operator's own (lib/portable.sh,
#      backup_ref.sh). The script's backup is one portable file (trigger=upgrade, recordings in,
#      not encrypted) holding state.json as it was when the upgrade began, which is what going back
#      by hand puts in place again; the snapshot the checks of step 12 compare with is kept beside
#      the log (<log>.before.txt) as well, since packing the file removes its members
#   8  reserved to retain the recorded step numbers of older upgrades
#   9  state.json: previous.* <- current.*, current.* <- the target; then current -> the target
#      release and the recordings folder prepared
#   10 start   11 ready within 180 seconds   12 the checks (lib/post_checks.sh)   13 the record
# A failure stops where it is and prints what the upgrade guide says for that
# step; nothing is rolled back on its own. A failure from step 8 on is recorded with its step, and
# the next upgrade refuses with the same commands (lib/upgrade_preflight.sh).
# shellcheck source=lib/post_checks.sh
. "${BASH_SOURCE[0]%/*}/post_checks.sh"

CX_UP_D1="" CX_UP_D2="" CX_UP_DRAINED="" CX_UP_SNAP="" CX_UP_BACKUP_DIR="" CX_UP_BACKUP_KIND=""
CX_UP_BACKUP="" # the backup of this upgrade as recorded: backups/<file>, or backups/<id> for an own one
CX_UP_HEALTH_VER="" CX_UP_STARTED=""
CX_UP_STATE0="" # state.json as the upgrade found it, byte for byte (a trailing x keeps the last newline)

# cx_up_at <n> <name>: the step now running (state.json once there is one, the log always).
cx_up_at() {
  cx_step "$1" "$CX_UP_STEPS" "$2"
}

# cx_up_end <succeeded|failed>: the end of the run, in state.json when there is one.
cx_up_end() {
  cx_finish "$1"
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
  local t0
  t0=$(cx_now)
  if ! cx_images_resolve "$CX_OVERLAYS"; then
    cx_up_step_line FAIL 2 "$(cx_msg up_step_images)"
    cx_up_again
    return "$CX_EXIT_FAILED"
  fi
  cx_trust_check
  CX_UP_D2=$(cx_duration $(($(cx_now) - t0)))
  cx_trust_screen
}

# cx_up_begin: step 3, once the preview is answered.
cx_up_begin() {
  CX_UP_STATE0=$(cat -- "$CX_ROOT/state.json" && printf x) || CX_UP_STATE0=""
  # An earlier run that may start over (lib/upgrade_preflight.sh) is closed first.
  if [ "$CX_UP_RERUN" = 1 ]; then
    cx_state_set last_upgrade.result interrupted
    cx_state_save "$CX_ROOT/state.json"
  fi
  cx_begin upgrade
  cx_state_set last_upgrade.from "$CX_UP_CURRENT"
  cx_state_set last_upgrade.to "$CX_UP_TARGET"
  # The keys an earlier upgrade left that describe that run only.
  local k
  for k in new_started_at backup_kind snapshot rolled_back_at handed_to handed_at settled_by settled_at; do
    cx_state_unset "last_upgrade.$k"
  done
  if [ -n "${CX_UP_PACKAGE_VERIFICATION:-}" ]; then
    cx_state_set last_upgrade.package_verification "$CX_UP_PACKAGE_VERIFICATION"
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

# cx_up_bk_cb: the callback of cx_bk_take: one line per part of the backup file.
cx_up_bk_cb() { # <OK|FAIL> <n> <total> <step id> <start>
  local text
  case $4 in
    db) text=$(cx_msg bk_step_db) ;;
    files) text=$(cx_msg bk_step_files) ;;
    conf) text=$(cx_msg bk_step_conf) ;;
    verify) text=$(cx_msg pb_step_verify) ;;
    *) text=$(cx_msg pb_step_pack) ;;
  esac
  if [ "$1" = OK ]; then
    case $4 in
      db) text=$(cx_msg up_bk_db "$(cx_size_human "$(cx_bk_du "$CX_BK_DIR/db.dump")")") ;;
      files)
        text=$(cx_msg up_bk_files "$(cx_size_human $(($(cx_bk_du "$CX_BK_DIR/audit.tar.gz") \
          + $(cx_bk_du "$CX_BK_DIR/recordings.tar.gz"))))")
        ;;
      pack) text=$(cx_msg up_bk_file "$CX_PB_NAME" "$(cx_size_human "$CX_PB_SIZE")") ;;
    esac
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
  cx_br_record "$id" || rc=1
  [ "$rc" = 0 ] || { cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"; return 1; }
  CX_UP_BACKUP_DIR=$CX_ROOT/backups/$id CX_UP_BACKUP_KIND=external CX_UP_BACKUP=backups/$id
  cx_up_keep_state "$CX_UP_BACKUP_DIR" || { cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"; return 1; }
  # An external database is reachable only through the client the checks chose: without one, no
  # snapshot (the checks after the start then say the data cannot be compared).
  cx_db_ready || return 0
  cx_up_snapshot "$CX_UP_BACKUP_DIR/snapshot.txt"
}

# cx_up_snapshot <file>: what the checks after the start compare with.
cx_up_snapshot() {
  if ! cx_snap_take "$1" "$(cx_bk_env JWT_SECRET)"; then
    cx_up_sub FAIL "$(cx_msg up_bk_snap)"
    return 1
  fi
  CX_UP_SNAP=$1
  cx_log SNAPSHOT "file=${1#"$CX_ROOT"/} usable=$CX_SNAP_USABLE${CX_SNAP_REASONS:+ reasons=\"$CX_SNAP_REASONS\"}"
  cx_up_sub OK "$(cx_msg up_bk_snap)"
}

# cx_up_backup <n>: step 7. The services are stopped (step 5). The operator's own backup when it
# was given on the command line, chosen at [2], or the only one possible (an external database the
# script cannot back up this time, lib/upgrade_preflight.sh); otherwise the script's file.
cx_up_backup() {
  local n=$1 own=0
  cx_up_step_line RUN "$n" "$(cx_msg up_step_backup)"
  if [ "$CX_UP_OWN_ONLY" = 1 ] || cx_br_flags_given; then
    own=1
  elif [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then
    cx_br_choose "$(cx_size_human "$CX_BK_NEED")" "$(cx_bk_minutes)" 0 || return 1
    [ "$CX_BR_CHOICE" = 1 ] || own=1
  fi
  if [ "$own" = 1 ]; then
    cx_up_own_backup
    return
  fi
  cx_up_script_backup
}

# cx_up_script_backup: the portable file (lib/portable.sh): the snapshot first, beside the log and
# in the temporary folder, then state.json as the upgrade found it, then the steps up to the commit;
# state.json then points at the file (last_backup.*).
cx_up_script_backup() {
  local rc=0
  CX_PB_TRIGGER=upgrade CX_PB_STATE=1 CX_PB_WITH_REC=1 CX_PB_ENC=0
  cx_pb_open upgrade || rc=$?
  if [ "$rc" != 0 ]; then
    if [ "$rc" = 2 ]; then
      cx_up_sub FAIL "$(cx_msg pb_ts_taken "$CX_ROOT/backups" "$CX_BK_TS")"
    else
      cx_up_sub FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"
    fi
    cx_up_resume_cmd
    return 1
  fi
  CX_UP_BACKUP_DIR=$CX_BK_DIR CX_UP_BACKUP_KIND=script
  CX_PB_CREATED_AT=$(date '+%Y-%m-%dT%H:%M:%S%z')
  cx_up_keep_state "$CX_BK_DIR" || { cx_up_bk_failed; return 1; }
  cx_up_snapshot "${CX_LOG_FILE%.log}.before.txt" || { cx_up_bk_failed; return 1; }
  if ! (umask 077 && cp -- "$CX_UP_SNAP" "$CX_BK_DIR/snapshot.txt") || ! chmod 0600 "$CX_BK_DIR/snapshot.txt"; then
    cx_up_bk_failed
    return 1
  fi
  cx_bk_take upgrade cx_up_bk_cb || { cx_up_bk_failed; return 1; }
  CX_UP_BACKUP=backups/$CX_PB_NAME
  cx_pb_record_file
  if ! cx_state_save "$CX_ROOT/state.json"; then
    cx_log FAIL "state.json not written after the commit"
    printf '\n'
    cx_line FAIL "$(cx_msg up_bk_unrecorded "$CX_PB_FINAL")"
    cx_up_resume_cmd
    return 1
  fi
  cx_pb_cleanup || cx_log WARN "temporary folder ${CX_BK_DIR#"$CX_ROOT"/} not removed"
}

# cx_up_bk_failed: the backup did not finish: what is there, how to start the old version again.
cx_up_bk_failed() {
  printf '\n'
  cx_line FAIL "$(cx_msg bk_failed "$CX_BK_DIR/")"
  cx_up_resume_cmd
  [ "$CX_BK_KEK" != ui ] || cx_up_par "$(cx_msg up_unseal_after)"
}

# ---------- steps 8 to 11 ----------

# cx_up_record_switch: state.json before current moves: what runs now becomes previous.*, the
# target becomes current.* (a rollback reads previous.*).
cx_up_record_switch() {
  local k n src="" proj=$CX_PROJECT
  for k in version kind overlays release_dir images_env image_ids image_source verification since; do
    cx_state_set "previous.$k" "$(cx_state_get "current.$k")"
  done
  cx_state_set previous.image_ids "$CX_UP_PRE_OLD_IDS"
  if [ -n "$(cx_state_get current.tool_image_ids)" ]; then
    cx_state_set previous.tool_image_ids "$(cx_state_get current.tool_image_ids)"
  else
    cx_state_unset previous.tool_image_ids
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
  cx_tools_record current
  cx_state_set current.image_source "$src"
  cx_state_set current.verification "$(cx_trust_state)"
  cx_state_save "$CX_ROOT/state.json"
}

# cx_up_recordings: the recordings folder as install prepares it (owner 1000, group 0, 2770).
cx_up_recordings() {
  local dir=$CX_BK_DATA/recordings img out
  img=${CX_IMG_REF[guacd]:-}
  cx_img_is_tool openssl || img=${CX_IMG_REF[openssl]:-$img}
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
  cx_up_record_switch || return 1
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
  if ! cx_new_started_mark || ! cx_log_run cx_compose up -d --remove-orphans >/dev/null 2>&1; then
    cx_up_step_line FAIL "$1" "$(cx_msg up_step_start)"
    return 1
  fi
  cx_up_step_line OK "$1" "$(cx_msg up_step_start)" "$(cx_duration $(($(cx_now) - t0)))"
}

# cx_up_ready <n>: step 11. /health answers within 180 seconds (its version is checked in step 12).
cx_up_ready() {
  local t0
  t0=$(cx_now)
  if ! cx_wait_backend_health; then
    cx_up_step_line FAIL "$1" "$(cx_msg up_step_ready)"
    return 1
  fi
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
  printf '\n'
  if cx_rb_hint_ok; then
    cx_rb_hint
  else
    cx_up_par "$(cx_msg up_restore_guide "$CX_UP_CURRENT")"
  fi
  printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
}

# cx_up_bullet <text>: "    - text", later lines under the text.
cx_up_bullet() { printf '    - %s\n' "${1//$'\n'/$'\n'      }"; }

cx_up_bullet_backup() {
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_up_bullet "$(cx_msg up_state_backup_own "$CX_UP_BACKUP_DIR/external.txt")"
  else
    cx_up_bullet "$(cx_msg up_state_backup "$CX_ROOT/$CX_UP_BACKUP")"
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
  # On record from here: a failure of steps 9 to 12 points at this backup as the way back, and a
  # rollback compares the database with the snapshot taken while the old version was stopped.
  cx_state_set last_upgrade.backup "$CX_UP_BACKUP"
  cx_state_set last_upgrade.backup_kind "$CX_UP_BACKUP_KIND"
  if [ -n "$CX_UP_SNAP" ]; then
    cx_state_set last_upgrade.snapshot "${CX_UP_SNAP#"$CX_ROOT"/}"
  else
    cx_state_unset last_upgrade.snapshot
  fi
  cx_up_at 8 reserved
  cx_up_step_line SKIP 8 "$(cx_msg up_step_reserved)"
  cx_up_at 9 switch
  cx_up_switch 9 || { cx_up_fail_switched up_fail_switch; cx_up_fail_exit; }
  cx_up_at 10 start
  cx_up_start 10 || { cx_up_fail_switched up_fail_start; cx_up_fail_exit; }
  cx_up_at 11 ready
  cx_up_ready 11 || { cx_up_fail_switched up_fail_ready $((CX_UP_READY_TRIES * CX_UP_READY_WAIT)); cx_up_fail_exit; }
  cx_up_at 12 check
  cx_up_post_checks 12 || cx_up_fail_exit
  cx_up_at 13 record
  cx_up_end succeeded
  cx_up_step_line OK 13 "$(cx_msg up_step_record)"
  cx_up_done
}
