# shellcheck shell=bash
# custodexa.sh db-upgrade: the bundled database's major version, and the removal of the old data
# folders it leaves behind.
#   db-upgrade                        what the data is, what this release supports, the old folders kept
#   db-upgrade --remove-old [path..]  remove them (all that may go, or the ones named), after a
#                                     confirmation (the version typed, or --yes)
# The data's major is the PG_VERSION of the data folder; while the database runs the server must agree.
# Equal to what the release bundles: nothing to upgrade. Lower: the conversion module of upgrade step 8
# runs (the way in for a later major; the upgrade to this release already converted). Higher: refused.
# An external database is left alone. Needs the libraries of the upgrade and backup commands.
# shellcheck disable=SC2034
# shellcheck source=lib/db_old.sh
. "${BASH_SOURCE[0]%/*}/db_old.sh"
# shellcheck source=lib/backup.sh
. "${BASH_SOURCE[0]%/*}/backup.sh"
# shellcheck source=lib/snapshot.sh
. "${BASH_SOURCE[0]%/*}/snapshot.sh"
# shellcheck source=lib/health.sh
. "${BASH_SOURCE[0]%/*}/health.sh"
# shellcheck source=lib/upgrade_output.sh
. "${BASH_SOURCE[0]%/*}/upgrade_output.sh"

CX_DBU_DATA="" CX_DBU_DISK="" CX_DBU_SERVER="" CX_DBU_UP_OK=1 CX_DBU_NEW_OK=1 CX_DBU_IDLE_OK=1 CX_DBU_DB_OK=1
CX_DBU_REMOVED=0

# cx_dbu_external_screen: P12.
cx_dbu_external_screen() {
  local host port
  host=$(cx_state_get current.external_db_host)
  port=$(cx_state_get current.external_db_port)
  [ -n "$host" ] || host=$(cx_form_db_host "$CX_ROOT/.env")
  [ -n "$port" ] || port=5432
  printf '%s\n\n' "$(cx_msg dbu_title)"
  cx_up_par "$(cx_msg dbu_external "$host" "$port")"
  printf '\n%s\n' "$(cx_msg dbu_nothing)"
}

# cx_dbu_read: CX_DBU_DATA, CX_DBU_DISK (the data folder's major, "" when unreadable) and CX_DBU_SERVER
# (the running server's major, "" when it does not answer).
cx_dbu_read() {
  local num
  cx_bk_vars
  CX_DBU_DATA=$CX_BK_DATA
  CX_DBU_DISK=$(cx_pgm_dir_major "$CX_DBU_DATA" "$CX_DBO_DIR" "$CX_DBO_PGDATA") || CX_DBU_DISK=""
  CX_DBU_SERVER=""
  num=$(cx_snap_sql "SHOW server_version_num" 2>/dev/null) || num=""
  CX_DBU_SERVER=$(cx_pgm_server_major "$num") || CX_DBU_SERVER=""
}

# cx_dbu_head: the first rows of the database upgrade screen.
cx_dbu_head() {
  printf '%s\n\n' "$(cx_msg dbu_title)"
  printf '%s\n' "$(cx_msg dbu_row_current "$CX_DBU_DISK" "$CX_DBU_DATA/$CX_DBO_DIR")"
  printf '%s\n' "$(cx_msg dbu_row_supported "$CX_DBO_MAJOR")"
}

# cx_dbu_old_block: the heading and the rows of the kept old folders (nothing printed when none).
cx_dbu_old_block() {
  [ "${#CX_DBO_ROWS[@]}" -gt 0 ] || return 0
  printf '\n%s\n' "$(cx_msg dbu_old_head)"
  cx_dbo_rows_text "  " "      "
}

# cx_dbu_backup_info: the upgrade's backup file as CX_DBU_BK (path), CX_DBU_BK_TIME and CX_DBU_BK_SIZE;
# 1 when the state records none, 2 when it is recorded and the file is gone.
cx_dbu_backup_info() {
  local f
  CX_DBU_BK="" CX_DBU_BK_TIME="" CX_DBU_BK_SIZE=""
  f=$(cx_state_get last_upgrade.backup)
  [ -n "$f" ] && [ "$(cx_state_get last_upgrade.backup_kind)" != external ] || return 1
  case $f in /*) ;; *) f=$CX_ROOT/$f ;; esac
  CX_DBU_BK=$f
  [ -f "$f" ] || return 2
  CX_DBU_BK_TIME=$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null)
  CX_DBU_BK_SIZE=$(cx_size_human "$(stat -c %s -- "$f" 2>/dev/null || echo 0)")
}

# cx_dbu_checks: the four conditions of a removal, CX_DBU_*_OK (1 holds).
cx_dbu_checks() {
  local r new settled
  CX_DBU_DB_OK=1 CX_DBU_UP_OK=1 CX_DBU_NEW_OK=1 CX_DBU_IDLE_OK=1
  [ -n "$CX_DBU_DISK" ] && [ "$CX_DBU_DISK" = "$CX_DBO_MAJOR" ] && [ "$CX_DBU_SERVER" = "$CX_DBO_MAJOR" ] \
    && cx_backend_healthy_once || CX_DBU_DB_OK=0
  r=$(cx_state_get last_upgrade.result)
  new=$(cx_state_get last_upgrade.new_started_at)
  settled=$(cx_state_get last_upgrade.settled_at)
  if [ -z "$settled" ]; then
    case $r in '' | succeeded | cancelled) ;; *) CX_DBU_UP_OK=0 ;; esac
    case $r in '' | cancelled) ;; *) [ -n "$new" ] || CX_DBU_NEW_OK=0 ;; esac
  fi
  [ "$(cx_state_get install.result)" != in_progress ] || CX_DBU_IDLE_OK=0
  [ "$(cx_state_get last_rollback.result)" != in_progress ] || CX_DBU_IDLE_OK=0
  [ "$(cx_state_get last_restore.result)" != in_progress ] || CX_DBU_IDLE_OK=0
  if cx_dirop_pending && [ "$(cx_state_get dir_op.id)" != removing ]; then CX_DBU_IDLE_OK=0; fi
}

# cx_dbu_art_ok: the second kind (what a failed conversion left) may go when the run on record is
# not unfinished beyond a conversion failure that was recorded as failed.
cx_dbu_art_ok() {
  local r
  r=$(cx_state_get last_upgrade.result)
  [ "$r" != in_progress ] || return 1
  [ "$r" != failed ] || [ "$(cx_state_get last_upgrade.db_convert.result)" = failed ]
}

# cx_dbu_may_remove <row>: 0 when that folder may be removed now; otherwise 1 with CX_DBU_WHY set to
# keep, artifact, mounted.
cx_dbu_may_remove() {
  local kind p class
  IFS='|' read -r kind p _ _ <<<"$1"
  class=$(cx_dbo_class "$kind")
  CX_DBU_WHY=$class
  if [ "$class" = finish ]; then
    ! cx_dbo_mounted "$p" || { CX_DBU_WHY=mounted; return 1; }
    return 0
  fi
  ! cx_dbo_mounted "$p" || { CX_DBU_WHY=mounted; return 1; }
  if [ "$class" = keep ]; then
    [ "$CX_DBU_DB_OK$CX_DBU_UP_OK$CX_DBU_NEW_OK$CX_DBU_IDLE_OK" = 1111 ]
  else
    [ "$CX_DBU_DB_OK$CX_DBU_IDLE_OK" = 11 ] && cx_dbu_art_ok
  fi
}

# cx_dbu_check_lines: P14: each condition as a line.
cx_dbu_check_lines() {
  local step
  step=$(cx_state_get last_upgrade.step)
  if [ "$CX_DBU_DB_OK" = 1 ]; then cx_line OK "$(cx_msg dbu_chk_db_ok "$CX_DBO_MAJOR")"
  else cx_line FAIL "$(cx_msg dbu_chk_db_bad "$CX_DBO_MAJOR")"; fi
  if [ "$CX_DBU_UP_OK$CX_DBU_NEW_OK" = 11 ]; then cx_line OK "$(cx_msg dbu_chk_up_started)"
  elif [ "$CX_DBU_UP_OK" = 1 ]; then cx_line OK "$(cx_msg dbu_chk_up_ok)"
  else cx_line FAIL "$(cx_msg dbu_chk_up_bad "${step:-?}")"; fi
  [ "$CX_DBU_NEW_OK" = 1 ] || cx_line FAIL "$(cx_msg dbu_chk_new_bad)"
  # An unfinished upgrade is already said above, so the line about what is in progress leaves it out.
  if [ "$CX_DBU_IDLE_OK" != 1 ]; then cx_line FAIL "$(cx_msg dbu_chk_idle_bad)"
  elif [ "$CX_DBU_UP_OK" = 1 ]; then cx_line OK "$(cx_msg dbu_chk_idle_ok)"
  else cx_line OK "$(cx_msg dbu_chk_idle_short)"; fi
}

# cx_dbu_refuse <rows that cannot go>: P14 for what is asked and cannot be removed.
cx_dbu_refuse() {
  local e kind p
  cx_line FAIL "$(cx_msg dbu_ref_head)"
  cx_dbu_check_lines | sed 's/^/  /'
  for e in "$@"; do
    IFS='|' read -r kind p _ _ <<<"$e"
    # The kept folder is the only way back while the upgrade has not settled.
    [ "$(cx_dbo_class "$kind")" != keep ] || [ "$CX_DBU_UP_OK$CX_DBU_NEW_OK" = 11 ] \
      || cx_up_par "$(cx_msg dbu_ref_keep "$p" "$(cx_state_get previous.version)")"
    ! cx_dbo_mounted "$p" || cx_line FAIL "$(cx_msg dbu_chk_mount_bad "$p")" | sed 's/^/  /'
  done
  if [ "$CX_DBU_DB_OK" = 0 ]; then
    cx_up_par "$(cx_msg dbu_ref_start)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh start$(cx_status_lang_arg)"
  else
    cx_up_par "$(cx_msg dbu_ref_later)"
  fi
  cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
}

# cx_dbu_clear <path>: through the rename log, then delete. A folder already named .removing- is
# deleted as it is. 0 removed.
cx_dbu_clear() {
  local p=$1 to=$1
  case $p in *.removing-*) ;; *)
    to=$p.removing-$(date '+%Y%m%d-%H%M%S')
    cx_dirop_rename removing "$p" "$to" || return 1 ;;
  esac
  rm -rf -- "$to"
}

# cx_dbu_confirm_screen <rows>: P13 up to the question.
cx_dbu_confirm_screen() {
  local e kind p major bytes has_prev=0 rc=0 cur
  printf '%s\n\n  %s\n' "$(cx_msg dbu_rm_head)" "$(cx_msg dbu_rm_what)"
  for e in "$@"; do
    IFS='|' read -r kind p major bytes <<<"$e"
    printf '    %s\n        PostgreSQL %s    %s\n' "$p" "$(cx_dbo_major_text "$major")" "$(cx_size_human "$bytes")"
    [ "$kind" != previous ] || has_prev=1
  done
  cur=$(cx_state_get previous.version)
  printf '  %s\n    %s\n' "$(cx_msg dbu_rm_after)" "$(cx_msg dbu_rm_b_lost)"
  if [ "$has_prev" = 1 ]; then
    printf '    %s\n' "$(cx_msg dbu_rm_b_rollback "$cur" "$cur" | sed '2,$s/^/    /')"
    cx_dbu_backup_info || rc=$?
    if [ "$rc" = 0 ]; then
      printf '    %s\n' "$(cx_msg dbu_rm_b_backup "$CX_DBU_BK" "$CX_DBU_BK_TIME" "$CX_DBU_BK_SIZE" | sed '2,$s/^/    /')"
    elif [ "$rc" = 2 ]; then
      cx_line WARN "$(cx_msg dbu_rm_nobackup "$CX_DBU_BK" "$cur")" | sed 's/^/  /'
    fi
  fi
  printf '  %s\n' "$(cx_msg dbu_rm_unaffected "$CX_DBO_MAJOR" "$CX_DBU_DATA/$CX_DBO_DIR" | sed '2,$s/^/  /')"
}

# cx_dbu_prepare: the lock, the log and the state, for the commands that change something.
cx_dbu_prepare() {
  CX_SVC_COMMAND="db-upgrade"
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  cx_secrets_from_env "$CX_ROOT/.env"
  cx_log_open db-upgrade || return "$CX_EXIT_FAILED"
  cx_log BEGIN "db-upgrade lang=${CX_LANG:-en} script=${CX_SELF#"$CX_ROOT"/} flags=\"${CX_FLAGS_TEXT# }\""
}

# cx_dbu_remove [path...]: --remove-old. 0 removed or nothing to do; refusals and failures return their code.
cx_dbu_remove() {
  local e kind p ans word rc=0 want n gone="" freed=0
  local -a sel=() blocked=() done_names=()
  cx_dbu_prepare || return "$?"
  if cx_dirop_pending; then
    cx_dirop_recover || rc=$?
    if [ "$rc" = 3 ]; then cx_dirop_ambiguous_screen; cx_log END "result=failed command=db-upgrade"; return "$CX_EXIT_FAILED"; fi
    [ "$rc" = 0 ] || { cx_line FAIL "$(cx_msg dirop_intent_failed "$(cx_state_get dir_op.from)" "$(cx_state_get dir_op.to)")"; return "$CX_EXIT_FAILED"; }
  fi
  cx_dbo_list "$CX_DBU_DATA"
  cx_dbu_checks
  if [ "${#CX_DBO_ROWS[@]}" -eq 0 ]; then
    printf '%s\n' "$(cx_msg dbu_rm_none)"
    cx_log END "result=succeeded command=db-upgrade"
    return 0
  fi
  for e in "${CX_DBO_ROWS[@]}"; do
    IFS='|' read -r kind p _ _ <<<"$e"
    if [ "${#CX_ARGS[@]}" -gt 0 ]; then
      want=0
      for n in "${CX_ARGS[@]}"; do [ "${n%/}" != "$p" ] || want=1; done
      [ "$want" = 1 ] || continue
    fi
    if cx_dbu_may_remove "$e"; then sel+=("$e"); else blocked+=("$e"); fi
  done
  for n in "${CX_ARGS[@]+"${CX_ARGS[@]}"}"; do
    want=0
    for e in "${CX_DBO_ROWS[@]}"; do IFS='|' read -r _ p _ _ <<<"$e"; [ "${n%/}" != "$p" ] || want=1; done
    [ "$want" = 1 ] || { cx_line FAIL "$(cx_msg dbu_rm_not_listed "$n")"; cx_log END "result=failed command=db-upgrade"; return "$CX_EXIT_REFUSED"; }
  done
  if [ "${#sel[@]}" -eq 0 ]; then
    cx_dbu_refuse "${blocked[@]}"
    cx_log END "result=refused command=db-upgrade"
    return "$CX_EXIT_REFUSED"
  fi
  if [ "${#blocked[@]}" -gt 0 ]; then
    cx_line WARN "$(cx_msg dbu_blocked_head)"
    cx_dbu_check_lines | sed 's/^/  /'
    for e in "${blocked[@]}"; do IFS='|' read -r _ p _ _ <<<"$e"; printf '         %s\n' "$p"; done
    printf '\n'
  fi
  if [ "${CX_YES:-0}" != 1 ] && [ ! -t 0 ]; then
    cx_line FAIL "$(cx_msg dbu_rm_needs_yes)" >&2
    printf '    sudo %s/custodexa.sh db-upgrade --remove-old --yes\n' "$CX_ROOT"
    cx_log END "result=cancelled command=db-upgrade"
    return "$CX_EXIT_REFUSED"
  fi
  cx_dbu_confirm_screen "${sel[@]}"
  if [ "${#sel[@]}" -eq 1 ]; then
    IFS='|' read -r _ _ word _ <<<"${sel[0]}"
    [ "$word" != missing ] || word=remove
    ans_msg=dbu_rm_ask_one
  else
    word=all ans_msg=dbu_rm_ask_all
  fi
  printf '\n%s\n> ' "$(cx_msg "$ans_msg" "$word")"
  if [ "${CX_YES:-0}" = 1 ]; then
    printf '%s\n\n' "$word"
  else
    read -r ans || ans=""
    if [ "$ans" != "$word" ]; then
      [ -t 0 ] || printf '\n'
      printf '%s\n' "$(cx_msg dbu_rm_cancel)"
      cx_log END "result=cancelled command=db-upgrade"
      return "$CX_EXIT_REFUSED"
    fi
    printf '\n'
  fi
  for e in "${sel[@]}"; do
    IFS='|' read -r _ p _ n <<<"$e"
    if cx_dbu_clear "$p"; then
      cx_line OK "$(cx_msg dbu_rm_done "$p" "$(cx_size_human "$n")")"
      done_names+=("${p##*/}")
      freed=$((freed + n))
    else
      cx_line FAIL "$(cx_msg dbu_rm_failed "$p")"
      rc=$CX_EXIT_FAILED
    fi
  done
  if [ "${#done_names[@]}" -gt 0 ]; then
    cx_state_set db_remove.at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    cx_state_set db_remove.dirs "${done_names[*]}"
    cx_state_save "$CX_ROOT/state.json" || true
    cx_log STATE "db_remove.dirs=${done_names[*]}"
  fi
  cx_log END "result=$([ "$rc" = 0 ] && echo succeeded || echo failed) command=db-upgrade"
  return "$rc"
}

# cx_dbu_convert: the data is older than what this release bundles: the conversion of upgrade step 8
# runs for the current release. The upgrade to 1.23.0 already converts, so this is the way in for a
# later major; cx_up_run does the checks, the preview, the drain, the stop, the backup, the conversion
# and the start. CX_DBU_SAME lets it accept the release that is already running and CX_PGC_DISK_FROM
# tells the plan which major the folder holds.
cx_dbu_convert() {
  # shellcheck source=lib/cmd_upgrade.sh
  . "${BASH_SOURCE[0]%/*}/cmd_upgrade.sh"
  printf '%s\n' "$(cx_msg dbu_convert_note "$CX_DBU_DISK" "$CX_DBO_MAJOR")"
  CX_UP_CURRENT=$(cx_state_get current.version)
  CX_UP_TARGET=$CX_UP_CURRENT
  CX_DBU_SAME=1 CX_PGC_DISK_FROM=$CX_DBU_DISK
  cx_up_run
}

cmd_db_upgrade() {
  [ -f "$CX_ROOT/state.json" ] || cx_die "$CX_EXIT_REFUSED" svc_not_installed
  cx_state_load "$CX_ROOT/state.json"
  if [ "$(cx_state_get current.kind)" != package ] || [ -z "$(cx_state_get current.version)" ]; then
    cx_die "$CX_EXIT_REFUSED" svc_not_installed
  fi
  if [ "${CX_REMOVE_OLD:-0}" != 1 ]; then
    [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
    [ "${CX_YES:-0}" = 0 ] || cx_die "$CX_EXIT_USAGE" usage_unknown_option --yes
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  if cx_db_external; then
    cx_dbu_external_screen
    return 0
  fi
  cx_compose_files >/dev/null || return "$CX_EXIT_REFUSED"
  cx_dbo_current || cx_die "$CX_EXIT_FAILED" dbu_release_unreadable
  cx_dbu_read
  if [ -z "$CX_DBU_DISK" ]; then
    cx_line FAIL "$(cx_msg dbu_unreadable "$CX_DBU_DATA/$CX_DBO_DIR${CX_DBO_PGDATA:+/$CX_DBO_PGDATA}")"
    return "$CX_EXIT_FAILED"
  fi
  if [ -n "$CX_DBU_SERVER" ] && [ "$CX_DBU_SERVER" != "$CX_DBU_DISK" ]; then
    cx_line FAIL "$(cx_msg dbu_mismatch "$CX_DBU_DISK" "$CX_DBU_SERVER")"
    return "$CX_EXIT_FAILED"
  fi
  if [ "$CX_DBU_DISK" -gt "$CX_DBO_MAJOR" ]; then
    cx_dbu_head
    cx_line FAIL "$(cx_msg dbu_newer "$CX_DBU_DISK" "$CX_DBO_MAJOR")"
    return "$CX_EXIT_REFUSED"
  fi
  if [ "$CX_DBU_DISK" -lt "$CX_DBO_MAJOR" ]; then
    [ "${CX_REMOVE_OLD:-0}" != 1 ] || cx_die "$CX_EXIT_REFUSED" dbu_remove_before_convert
    cx_dbu_convert
    return
  fi
  if [ "${CX_REMOVE_OLD:-0}" = 1 ]; then
    cx_dbu_remove
    return
  fi
  cx_dbo_list "$CX_DBU_DATA"
  cx_dbu_head
  cx_line OK "$(cx_msg dbu_latest)" | sed 's/^/  /'
  if [ "${#CX_DBO_ROWS[@]}" -gt 0 ]; then
    cx_dbu_old_block
    printf '  %s\n    sudo %s/custodexa.sh db-upgrade --remove-old%s\n\n' "$(cx_msg dbu_old_remove)" "$CX_ROOT" "$(cx_status_lang_arg)"
    printf '%s\n' "$(cx_msg dbu_query_only)"
  else
    printf '\n%s\n' "$(cx_msg dbu_nothing)"
  fi
}
