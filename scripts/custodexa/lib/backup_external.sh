# shellcheck shell=bash
# The screens of a backup of an external database (lib/cmd_backup.sh sources this file after
# lib/portable.sh): the refusals before anything is stopped, the lines the preview adds, and the
# warning of the closing screen. What is checked is in lib/dbext.sh.

# cmd_backup_ext_where: <host>:<port> of the external database.
cmd_backup_ext_where() {
  local port
  port=$(cx_bk_env EXTERNAL_DB_PORT)
  printf '%s:%s' "$(cx_bk_env EXTERNAL_DB_HOST)" "${port:-5432}"
}

# cmd_backup_summary: the version, the database and the master key mode.
cmd_backup_summary() {
  if cx_db_external; then
    cmd_backup_par "$(cx_msg pb_summary_ext "$CX_PB_VERSION" "$(cmd_backup_ext_where)" "$CX_DBX_SERVER" "$(cmd_backup_mode)")"
  else
    cmd_backup_par "$(cx_msg pb_summary "$CX_PB_VERSION" "$(cx_msg pb_db_bundled)" "$(cmd_backup_mode)")"
  fi
}

# cmd_backup_ext_majors: the client majors of this release, as a list in words (16, 17 and 18).
cmd_backup_ext_majors() {
  local -a m=()
  mapfile -t m < <(cx_dbx_majors)
  [ "${#m[@]}" -gt 0 ] || { printf '?'; return 0; }
  if [ "${#m[@]}" -eq 1 ]; then
    printf '%s' "${m[0]}"
  else
    printf '%s%s%s' "$(cx_join "$(cx_msg bk_item_sep)" "${m[@]:0:${#m[@]}-1}")" "$(cx_msg pb_ext_and)" "${m[-1]}"
  fi
}

# cmd_backup_ext_items: the lines of an unsupported setting, each "  - <text>", later lines of an
# item under its text.
cmd_backup_ext_items() {
  local item key text
  local -a args=()
  for item in "${CX_DBX_ITEMS[@]}"; do
    key=${item%% *}
    args=()
    [ "$key" = "$item" ] || IFS=$'\t' read -r -a args <<<"${item#* }"
    text=$(cx_msg "$key" "${args[@]+"${args[@]}"}")
    printf '  - %s\n' "${text//$'\n'/$'\n'    }"
  done
}

# cmd_backup_ext_refuse: the database cannot be backed up by the script; nothing was stopped.
cmd_backup_ext_refuse() {
  local items
  case $CX_DBX_FAIL in
    image)
      cx_line FAIL "$(cx_msg pb_ext_no_image "$CX_PB_SCRIPT_VERSION")"
      cmd_backup_cmd "$(printf 'sudo %s/custodexa.sh load custodexa-images-%s-%s.tar' "$CX_ROOT" \
        "$CX_PB_SCRIPT_VERSION" "$(cx_arch 2>/dev/null || uname -m)")"
      ;;
    connect)
      cx_line FAIL "$(cx_msg pb_ext_unreachable "$(cmd_backup_ext_where)")"
      cmd_backup_par "$(cx_msg pb_ext_unreachable_hint "$(cmd_backup_cmd_of status)")"
      cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
      ;;
    version) cx_line FAIL "$(cx_msg pb_ext_no_tool "$CX_DBX_SERVER" "$(cmd_backup_ext_majors)")" ;;
    *)
      items=$(cmd_backup_ext_items)
      cx_line FAIL "$(cx_msg pb_ext_unsupported "$items")"
      ;;
  esac
  cx_log FAIL "external database: $CX_DBX_FAIL${CX_DBX_MISSING_MAJOR:+ missing=pgclient$CX_DBX_MISSING_MAJOR}"
  cx_finish failed
  exit "$CX_EXIT_REFUSED"
}

# cmd_backup_external: an external database is checked before the preview (lib/dbext.sh).
cmd_backup_external() {
  cx_db_external || return 0
  cx_dbx_prepare
  [ -z "$CX_DBX_FAIL" ] || cmd_backup_ext_refuse
}

# cmd_backup_ext_conn: "Connection: <sslmode>, <how the server is checked>".
cmd_backup_ext_conn() {
  local mode=$CX_DB_SSLMODE
  [ "$CX_DB_SSLMODE_BY_SYSTEM" != 1 ] || mode=$(cx_msg pb_ext_mode_system)
  cx_msg pb_ext_conn "$mode" "$(cx_msg "pb_ext_verify_${CX_DB_TLS_VERIFY}_$CX_DB_TLS_TRUST")"
}

# cmd_backup_ext_preview: the export tool and the connection, after the summary line.
cmd_backup_ext_preview() {
  cx_db_external || return 0
  local conn
  cmd_backup_par "$(cx_msg pb_ext_tool "$CX_DB_EXT_MAJOR")"
  conn=$(cmd_backup_ext_conn)
  # A full-width aside that does not fit goes to the next line whole: wide text has no space to
  # break at but the one inside the aside.
  if [ "$(cx_width "$conn")" -gt 70 ] && [[ $conn == *"）" && $conn == *"（"* ]]; then
    cmd_backup_par "${conn%（*}"$'\n'"（${conn##*（}"
  else
    cmd_backup_par "$(cx_wrap 70 "$conn")"
  fi
}

# cmd_backup_ext_standby: the warning about a standby host, after the sizes.
cmd_backup_ext_standby() {
  cx_db_external || return 0
  cmd_backup_ind WARN "$(cx_msg pb_ext_standby)"
}

# cmd_backup_ext_roles: the warning of the closing screen when other roles hold privileges.
cmd_backup_ext_roles() {
  cx_db_external && [ -n "$CX_DBX_ROLES" ] || return 0
  cmd_backup_ind WARN "$(cx_msg pb_ext_roles "$(cx_dbx_roles_shown)")"
}
