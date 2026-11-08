# shellcheck shell=bash
# Going back across a change of the bundled database's major version (PostgreSQL 16 -> 18 and back).
# "Across" has one definition: cx_pgc_crossed (lib/pgconvert_post.sh). The judgment, the last check,
# the preview, the warnings and the folder renames of rollback and `rollback --revert` all ask it;
# an external database, or an upgrade whose database step was skipped, never takes this path.
#
# What differs from going back inside one major:
#   - the data the version before needs is the folder the upgrade kept (the old release's data
#     folder, with its PG_VERSION): the migrations of the new database are not read, and the list of
#     versions a release can go straight back to is not consulted
#   - after the database stops, the folder of the new major is renamed and kept (lib/dirop.sh), so
#     the old version finds only its own data; `--revert` renames it back before anything starts
#   - what the new version wrote after it started is not in the old folder: a warning and a y/N
#     (or --yes) come before anything changes
# Needs lib/rollback_check.sh, lib/rollback_output.sh, lib/dirop.sh, lib/pgmajor.sh and lib/backup.sh.
# shellcheck disable=SC2034
# shellcheck source=lib/pgconvert_post.sh
declare -F cx_pgc_crossed >/dev/null || . "${BASH_SOURCE[0]%/*}/pgconvert_post.sh"

CX_RB_CROSSED=0    # 1: this rollback crosses the database major
CX_RB_OLD_MAJOR="" CX_RB_NEW_MAJOR="" CX_RB_OLD_PATH="" CX_RB_NEW_PATH="" CX_RB_ASIDE=""
CX_RB_OLD_DIR="" CX_RB_OLD_PGDATA="" CX_RB_OLD_FOUND="" # the major the kept folder says it holds, or "missing"

# cx_rb_pg_paths: the majors and folders of the two releases; sets the CX_RB_*_MAJOR/_PATH variables
# (CX_RB_ASIDE is fixed once, on the first call). Fails when a release does not say.
cx_rb_pg_paths() {
  local old new om od op nm nd np
  old=$(cx_pgc_release_db "$CX_ROOT/releases/$CX_RB_TARGET") || return 1
  new=$(cx_pgc_release_db "$CX_ROOT/releases/$(cx_state_get last_upgrade.to)") || return 1
  IFS='|' read -r om od op <<<"$old"
  IFS='|' read -r nm nd np <<<"$new"
  [ -n "${CX_BK_DATA:-}" ] || cx_bk_vars
  CX_RB_OLD_MAJOR=$om CX_RB_NEW_MAJOR=$nm
  CX_RB_OLD_DIR=$od CX_RB_OLD_PGDATA=$op
  CX_RB_OLD_PATH=$CX_BK_DATA/$od${op:+/$op}
  CX_RB_NEW_PATH=$CX_BK_DATA/$nd
  [ "$od" != "$nd" ] || return 1
  [ -n "$CX_RB_ASIDE" ] || CX_RB_ASIDE=$CX_RB_NEW_PATH.rolled-back-$(date '+%Y%m%d-%H%M%S')
}

# cx_rb_pg_judge: the judgment of a rollback across the major. 0: may go back (CX_RB_BASIS is
# not_started when the new version never started, old_data otherwise); 1: refused, CX_RB_REASON is
# old_gone (no folder or no PG_VERSION) or old_wrong (CX_RB_OLD_FOUND is its major). Starts nothing.
cx_rb_pg_judge() {
  CX_RB_CROSSED=1 CX_RB_BASIS="" CX_RB_REASON="" CX_RB_ADDED=() CX_RB_READ=0 CX_RB_OLD_FOUND=""
  if ! cx_rb_pg_paths; then
    CX_RB_REASON=old_gone
    cx_log CHECK "rollback across the database major refused reason=$CX_RB_REASON"
    return 1
  fi
  CX_RB_OLD_FOUND=$(cx_pgm_dir_major "$CX_BK_DATA" "$CX_RB_OLD_DIR" "$CX_RB_OLD_PGDATA") || CX_RB_OLD_FOUND=missing
  if [ "$CX_RB_OLD_FOUND" = missing ]; then
    CX_RB_REASON=old_gone
  elif [ "$CX_RB_OLD_FOUND" != "$CX_RB_OLD_MAJOR" ]; then
    CX_RB_REASON=old_wrong
  fi
  if [ -n "$CX_RB_REASON" ]; then
    cx_log CHECK "rollback across the database major refused reason=$CX_RB_REASON found=$CX_RB_OLD_FOUND"
    return 1
  fi
  CX_RB_BASIS=old_data
  [ -n "$(cx_state_get last_upgrade.new_started_at)" ] || CX_RB_BASIS=not_started
  cx_log CHECK "rollback across the database major basis=$CX_RB_BASIS"
}

# cx_rb_pg_backup_file: the backup file of the upgrade when the script took it (a backup of the
# operator's own has no file to restore from).
cx_rb_pg_backup_file() {
  local backup kind
  backup=$(cx_state_get last_upgrade.backup) kind=$(cx_state_get last_upgrade.backup_kind)
  [ "$kind" = script ] && [ -n "$backup" ] && [ -f "$CX_ROOT/$backup" ] || return 1
  printf '%s' "$CX_ROOT/$backup"
}

# cx_rb_pg_restore_alt: "the other way": a restore of the backup of the upgrade.
cx_rb_pg_restore_alt() {
  local file backup kind
  if file=$(cx_rb_pg_backup_file); then
    cx_up_par "$(cx_msg pgrb_warn_restore)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh restore $file$(cx_status_lang_arg)"
    return
  fi
  backup=$(cx_state_get last_upgrade.backup) kind=$(cx_state_get last_upgrade.backup_kind)
  [ -n "$backup" ] || return 0
  [ "$kind" != external ] || backup+=/external.txt
  cx_up_par "$(cx_msg pgrb_warn_restore_own "$CX_ROOT/$backup")"
}

# cx_rb_pg_minute <recorded time>: the minute in the form of the screens, or empty.
cx_rb_pg_minute() {
  if [ -n "$1" ]; then cx_rb_minute "$1"; fi
}

# cx_rb_pg_preview: the preview of a rollback across the major (the two screens: new version never
# started, and started).
cx_rb_pg_preview() {
  local count=0 pair at
  for pair in $(cx_rb_target_ids); do count=$((count + 1)); done
  at=$(cx_rb_pg_minute "$(cx_state_get last_upgrade.app_stop.at)")
  printf '%s\n\n' "$(cx_msg rb_preview)"
  cx_up_par "$(cx_msg pgrb_versions "$(cx_state_get last_upgrade.to)" "$CX_RB_NEW_MAJOR" "$CX_RB_TARGET" "$CX_RB_OLD_MAJOR")"
  if [ "$CX_RB_BASIS" = not_started ]; then
    cx_up_par "$(cx_msg pgrb_db_untouched "$CX_RB_OLD_MAJOR" "$CX_RB_OLD_PATH" "$CX_RB_NEW_MAJOR" "$CX_RB_ASIDE")"
    cx_up_par "$(cx_msg pgrb_no_loss)"
    cx_up_par "$(cx_msg rb_images "$count")"
    cx_rb_pg_env_line
    printf '\n'
    cx_up_par "$(cx_msg pgrb_steps "$CX_RB_OLD_MAJOR" "$CX_RB_NEW_MAJOR" "$CX_RB_TARGET")"
    printf '\n'
    return
  fi
  if [ -n "$at" ]; then
    cx_up_par "$(cx_msg pgrb_db_started "$CX_RB_OLD_MAJOR" "$CX_RB_OLD_PATH" "$at")"
  else
    cx_up_par "$(cx_msg pgrb_db_started_nostamp "$CX_RB_OLD_MAJOR" "$CX_RB_OLD_PATH")"
  fi
  cx_up_par "$(cx_msg rb_images "$count")"
  printf '\n'
  cx_line WARN "$(cx_msg pgrb_warn "$(cx_state_get last_upgrade.to)" \
    "$(cx_rb_pg_minute "$(cx_state_get last_upgrade.new_started_at)")" "$CX_RB_TARGET" "$CX_RB_TARGET")"
  cx_up_par "$(cx_msg pgrb_warn_kept "$CX_RB_NEW_MAJOR" "$CX_RB_ASIDE" "$(cx_state_get last_upgrade.to)" \
    "$CX_RB_OLD_MAJOR" "$CX_RB_NEW_MAJOR")"
  printf '\n'
  cx_rb_pg_restore_alt
  printf '\n'
  cx_up_par "$(cx_msg pgrb_steps "$CX_RB_OLD_MAJOR" "$CX_RB_NEW_MAJOR" "$CX_RB_TARGET")"
  cx_rb_pg_env_line
  printf '\n'
}

# cx_rb_pg_env_line: the .env line of the two previews, one line without the lines of the block;
# nothing when the block does not change.
cx_rb_pg_env_line() {
  local text
  cx_rb_env_plan "$CX_RB_TARGET" || return 0
  if [ "$CX_RB_ENV_LAYOUT" = overlays ] && [ "$(cx_form_layout "$CX_ROOT/current")" = profiles ]; then
    text=$(cx_msg rb_env_back "$CX_RB_TARGET")
  else
    text=$(cx_msg rb_env_fwd "$CX_RB_TARGET")
  fi
  text=${text%:}
  cx_up_par "${text%：}"
}

# cx_rb_pg_warn_confirm <ask text> <need-yes text> <command printed when --yes is missing>: the y/N
# of a warning that gives data up. --yes passes; without a terminal and without --yes the text and the
# command are printed and it fails (nothing was changed); interactively only y/yes pass, Enter is no.
cx_rb_pg_warn_confirm() {
  local answer
  [ "${CX_YES:-0}" = 1 ] && return 0
  if [ ! -t 0 ]; then
    cx_line FAIL "$2" >&2
    cx_cmd "$3" >&2
    return 1
  fi
  printf '%s ' "$1"
  read -r answer || answer=""
  case $answer in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

# cx_rb_pg_after_answer: a blank line between a typed "y" and the steps that follow.
cx_rb_pg_after_answer() {
  if [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then printf '\n'; fi
}

# cx_rb_pg_confirm: the confirmation of a rollback across the major: the warning's y/N when the new
# version started, the ordinary question when it never did. 0 go on; 1 no (refusal code by the caller).
cx_rb_pg_confirm() {
  if [ "$CX_RB_BASIS" = not_started ]; then
    cx_confirm rb_confirm || { printf '%s\n' "$(cx_msg pre_nothing_changed)"; return 1; }
    cx_rb_pg_after_answer
    return 0
  fi
  if cx_rb_pg_warn_confirm "$(cx_msg pgrb_ask "$CX_RB_TARGET")" "$(cx_msg pgrb_need_yes "$CX_RB_TARGET")" \
    "sudo $CX_ROOT/custodexa.sh rollback --yes$(cx_status_lang_arg)"; then
    cx_rb_pg_after_answer
    return 0
  fi
  [ -t 0 ] && [ "${CX_YES:-0}" != 1 ] && printf '%s\n' "$(cx_msg pre_nothing_changed)"
  return 1
}

# cx_rb_pg_refused <after>: the refusal when the kept folder is gone or is of another major;
# after=1 is the last check, with the application services already stopped.
cx_rb_pg_refused() {
  local after=$1 desc file at
  desc=$(cx_msg rb_services_running)
  if [ "$after" = 1 ]; then desc=$(cx_msg rb_services_stopped); elif cx_rb_apps_stopped; then desc=$(cx_msg rb_services_stopped); fi
  if [ "$CX_RB_REASON" = old_wrong ]; then
    cx_line FAIL "$(cx_msg pgrb_wrong "$CX_RB_TARGET" "$CX_RB_OLD_PATH" "$CX_RB_OLD_MAJOR" "$desc")"
    cx_up_par "$(cx_msg pgrb_wrong_why "$CX_RB_OLD_FOUND" "$CX_RB_TARGET")"
  else
    cx_line FAIL "$(cx_msg pgrb_gone "$CX_RB_TARGET" "$CX_RB_OLD_MAJOR" "$desc")"
    # The time the menu's clean-up recorded; a folder removed by hand has none.
    at=$(cx_state_get db_remove.at)
    if [ -n "$at" ] && [ -n "${CX_RB_OLD_PATH:-}" ] && [[ " $(cx_state_get db_remove.dirs) " == *" ${CX_RB_OLD_PATH##*/} "* ]]; then
      cx_up_par "$(cx_msg pgrb_gone_why_at "$CX_RB_TARGET" "$CX_RB_OLD_MAJOR" "${CX_RB_OLD_PATH}" "${at:0:10} ${at:11:5}")"
    else
      cx_up_par "$(cx_msg pgrb_gone_why "$CX_RB_TARGET" "$CX_RB_OLD_MAJOR" "${CX_RB_OLD_PATH:-?}")"
    fi
  fi
  if file=$(cx_rb_pg_backup_file); then
    at=$(cx_rb_pg_backup_time "$file")
    if [ "$CX_RB_REASON" = old_wrong ]; then
      cx_up_par "$(cx_msg pgrb_restore_same "$CX_RB_TARGET")"
    else
      cx_up_par "$(cx_msg pgrb_restore "$CX_RB_TARGET" "$at")"
    fi
    cx_cmd "sudo $CX_ROOT/custodexa.sh restore $file$(cx_status_lang_arg)"
  else
    cx_rb_restore_hint
  fi
  if [ "$after" = 1 ] && [ "$(cx_state_get last_upgrade.result)" != in_progress ]; then
    cx_up_par "$(cx_msg rb_keep_new "$(cx_state_get last_upgrade.to)")"
    cx_cmd "sudo $CX_ROOT/custodexa.sh start$(cx_status_lang_arg)"
  fi
}

# cx_rb_pg_backup_time <backup file>: "2026-11-20 02:15" from the stamp in its name
# (custodexa-backup-1.22.0-20261120-021502.tar); a name without one gives the plain words.
cx_rb_pg_backup_time() {
  if [[ $1 =~ ([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})[0-9]{2}\.tar$ ]]; then
    printf '%s-%s-%s %s:%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" \
      "${BASH_REMATCH[4]}" "${BASH_REMATCH[5]}"
  else
    cx_msg pgrb_when_backup
  fi
}

# ---------- the way back to the new version (rollback --revert) ----------

# cx_rb_pg_saved: the rollback's own record: crossed or not (decided once, when it began).
cx_rb_pg_saved() { [ "$(cx_state_get last_rollback.db_crossed)" = 1 ]; }

# cx_rb_pg_started: the old version may already have written to its database: the record's step got
# to the start of the old version (3) or past it, in the direction of going back.
cx_rb_pg_started() {
  [ "$(cx_state_get last_rollback.direction)" = rollback ] || return 1
  [[ $(cx_state_get last_rollback.step) =~ ^[34]$ ]]
}

# cx_rb_pg_revert_preview: P22. Prints the preview; the caller confirms with cx_rb_pg_revert_confirm.
cx_rb_pg_revert_preview() {
  local to old nmajor omajor aside newp oldp
  to=$(cx_state_get last_rollback.from)
  nmajor=$(cx_state_get last_rollback.db_new_major) omajor=$(cx_state_get last_rollback.db_old_major)
  aside=$(cx_state_get last_rollback.db_aside) newp=$(cx_state_get last_rollback.db_new_path)
  oldp=$(cx_state_get last_rollback.db_old_path)
  old=$(cx_state_get last_rollback.to)
  printf '%s\n\n' "$(cx_msg pgrv_preview)"
  if cx_rb_pg_started; then
    cx_up_par "$(cx_msg pgrv_state_started "$omajor" "$old")"
  else
    cx_up_par "$(cx_msg pgrv_state_early "$old")"
  fi
  cx_up_par "$(cx_msg pgrv_to "$to" "$nmajor")"
  cx_up_par "$(cx_msg pgrv_db "$nmajor" "$aside" "$newp" "$nmajor")"
  if cx_rb_pg_started; then
    printf '\n'
    cx_line WARN "$(cx_msg pgrv_warn "$old" "$omajor" "$omajor" "$to")"
    cx_up_par "$(cx_msg pgrv_warn_kept "$oldp")"
  else
    cx_up_par "$(cx_msg pgrv_early_none "$old" "$omajor" "$omajor")"
  fi
  printf '\n'
}

# cx_rb_pg_revert_confirm: 0 go on; 1 no or refused (nothing was changed, the record is as it was).
cx_rb_pg_revert_confirm() {
  if ! cx_rb_pg_started; then
    cx_confirm rb_confirm && cx_rb_pg_after_answer
    return
  fi
  local to omajor
  to=$(cx_state_get last_rollback.from) omajor=$(cx_state_get last_rollback.db_old_major)
  if cx_rb_pg_warn_confirm "$(cx_msg pgrv_ask "$to" "$omajor")" "$(cx_msg pgrv_need_yes "$omajor")" \
    "sudo $CX_ROOT/releases/$to/custodexa.sh rollback --revert --yes$(cx_status_lang_arg)"; then
    cx_rb_pg_after_answer
    return 0
  fi
  [ -t 0 ] && [ "${CX_YES:-0}" != 1 ] && printf '%s\n' "$(cx_msg pre_nothing_changed)"
  return 1
}

# ---------- the rename, between stopping the database and starting a version ----------

# cx_rb_pg_rename: after the database is stopped, before the links and records change. Rolling back:
# the folder of the new major is renamed to the place fixed at the start and kept; reverting: it is
# renamed back. Both go through the rename log (lib/dirop.sh). 0 done (or already done); 1 failed,
# the screen was printed.
cx_rb_pg_rename() {
  local id from to rc=0
  if [ "$CX_RB_DIRECTION" = revert ]; then
    id=revert from=$(cx_state_get last_rollback.db_aside) to=$(cx_state_get last_rollback.db_new_path)
  else
    id=rolled-back from=$(cx_state_get last_rollback.db_new_path) to=$(cx_state_get last_rollback.db_aside)
  fi
  [ -n "$from" ] && [ -n "$to" ] || return 1
  cx_dirop_recover || rc=$?
  if [ "$rc" = 3 ]; then cx_dirop_ambiguous_screen; return 1; fi
  if [ "$rc" != 0 ]; then
    cx_line FAIL "$(cx_msg dirop_intent_failed "$(cx_state_get dir_op.from)" "$(cx_state_get dir_op.to)")"
    return 1
  fi
  if [ "$(cx_state_get dir_op.id)" = "$id" ] && [ "$(cx_state_get dir_op.to)" = "$to" ] &&
    [ "$(cx_state_get dir_op.phase)" = "done" ]; then
    return 0
  fi
  # A folder already there would take the moved one inside it instead of being replaced.
  if [ ! -e "$from" ] || [ -e "$to" ]; then
    cx_log WARN "rename refused: $from -> $to"
    cx_line FAIL "$(cx_msg pgrb_rename_blocked "$from" "$to")"
    return 1
  fi
  cx_dirop_rename "$id" "$from" "$to" && return 0
  rc=$?
  [ "$rc" != 3 ] || return 0
  cx_line FAIL "$(cx_msg dirop_intent_failed "$from" "$to")"
  return 1
}

# cx_rb_pg_check: step 4's addition: the running server is the major of the version now running.
# What the server does not say proves nothing either way. Sets CX_RB_CHECK_ERROR.
cx_rb_pg_check() {
  local want num srv
  want=$(cx_state_get last_rollback.db_old_major)
  [ "$CX_RB_DIRECTION" != revert ] || want=$(cx_state_get last_rollback.db_new_major)
  num=$(cx_db sql "SHOW server_version_num" 2>/dev/null) || return 0
  srv=$(cx_pgm_server_major "$num") || return 0
  [ "$srv" = "$want" ] || CX_RB_CHECK_ERROR+="${CX_RB_CHECK_ERROR:+ }database"
  [ -z "$CX_RB_CHECK_ERROR" ]
}
