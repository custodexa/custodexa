# shellcheck shell=bash
# The database in steps 9 to 13 of an upgrade that changed the bundled database's major: the check of
# step 12 (the data folder, the running server and the data location agree with the release), the
# database part of the closing screen, and the way back printed when a step after the switch fails.
# Needs lib/pgconvert.sh, lib/pgmajor.sh, lib/post_checks.sh and lib/backup.sh loaded.
# shellcheck disable=SC2034

# cx_pgc_release_db <release dir>: "major|data dir|pgdata" of a release folder's MANIFEST.
cx_pgc_release_db() {
  (cx_manifest_load "$1/MANIFEST.json" >/dev/null 2>&1 && cx_pgm_release_db \
    && printf '%s|%s|%s' "$CX_PGM_MAJOR" "$CX_PGM_DATA_DIR" "$CX_PGM_PGDATA")
}

# cx_pgc_crossed: the one definition of "this upgrade changed the bundled database's major version":
# the form is the bundled database, the two releases name different majors, and the conversion is on
# record as done. An external database, or an upgrade whose step 8 was a SKIP, is never crossed.
# Inside the run of the upgrade itself the plan it made is the answer; any other command reads the
# MANIFESTs of the two releases state.json names.
cx_pgc_crossed() {
  local p c from to
  if [ "${CX_PGC_ACTIVE:-0}" = 1 ]; then
    [ "$(cx_state_get last_upgrade.db_convert.result)" = "done" ]
    return
  fi
  [[ " $(cx_state_get current.overlays) " != *" external-database "* ]] || return 1
  [ "$(cx_state_get last_upgrade.db_convert.result)" = "done" ] || return 1
  # The two releases the upgrade named, so the answer does not change when a rollback swaps
  # current and previous; a record without them falls back to current and previous.
  from=$(cx_state_get last_upgrade.from) to=$(cx_state_get last_upgrade.to)
  if [ -n "$from" ] && [ -n "$to" ] && [ -f "$CX_ROOT/releases/$from/MANIFEST.json" ] \
    && [ -f "$CX_ROOT/releases/$to/MANIFEST.json" ]; then
    p=$(cx_pgc_release_db "$CX_ROOT/releases/$from") || return 1
    c=$(cx_pgc_release_db "$CX_ROOT/releases/$to") || return 1
  else
    p=$(cx_pgc_release_db "$CX_ROOT/$(cx_state_get previous.release_dir)") || return 1
    c=$(cx_pgc_release_db "$CX_ROOT/$(cx_state_get current.release_dir)") || return 1
  fi
  [ "${p%%|*}" != "${c%%|*}" ]
}

# cx_pc_dbmajor: step 12: the data folder's PG_VERSION, the running server and the data location are
# what the target release says. The row is shown when the database was converted; a mismatch is a
# failure whenever it is found.
cx_pc_dbmajor() {
  local info major dir pgdata found num srv loc want
  [ "$CX_UP_PRE_EXTERNAL_DB" != 1 ] || return 0
  info=$(cx_pgc_release_db "$CX_DIR") || return 0
  IFS='|' read -r major dir pgdata <<<"$info"
  found=$(cx_pgm_dir_major "$CX_BK_DATA" "$dir" "$pgdata") || found=missing
  # What the server does not say proves nothing either way: it is not compared.
  num=$(cx_snap_sql "SHOW server_version_num" 2>/dev/null) || num=""
  srv=$(cx_pgm_server_major "$num") || srv=$major
  want=${pgdata:+/var/lib/postgresql/$pgdata}
  loc=$want
  [ -z "$want" ] || loc=$(cx_snap_sql "SHOW data_directory" 2>/dev/null) || loc=$want
  [ -n "$loc" ] || loc=$want
  if [ "$found" != "$major" ] || [ "$srv" != "$major" ] || [ "$loc" != "$want" ]; then
    cx_pc_row FAIL pc_db_bad "$major" "$found" "$srv" "${loc:-$CX_BK_DATA/$dir}"
  elif [ "${CX_PGC_ACTIVE:-0}" = 1 ]; then
    cx_pc_row OK pc_db_ok "$major" "$CX_BK_DATA/$dir"
  fi
}

# cx_pgc_done_section: the database part of the closing screen (after a conversion).
cx_pgc_done_section() {
  local old
  [ "${CX_PGC_ACTIVE:-0}" = 1 ] || return 0
  old=$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}
  printf '\n%s\n' "$(cx_msg pgc_done_head)"
  cx_up_par "$(cx_msg pgc_done_old "$CX_PGC_FROM" "$old" "$(cx_size_human "$(cx_bk_du "$old")")")"
  cx_up_par "$(cx_msg pgc_done_back "$CX_UP_CURRENT")"
  cx_up_par "$(cx_msg pgc_done_gone)"
}

# cx_pgc_restore_line: the restore of the backup taken before the upgrade, as a command; the
# operator's own backup has no file to give, so the guide stands in.
cx_pgc_restore_line() {
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_up_par "$(cx_msg up_restore_guide "$CX_UP_CURRENT")"
    cx_up_par "$(cx_msg up_done_backup "$CX_UP_BACKUP_DIR/external.txt")"
  else
    cx_cmd "sudo $CX_ROOT/custodexa.sh restore $CX_ROOT/$CX_UP_BACKUP$(cx_status_lang_arg)"
  fi
}

# cx_pgc_old_present: the old data folder is still there with the old major's PG_VERSION.
cx_pgc_old_present() {
  [ "$(cx_pgm_dir_major "$CX_BK_DATA" "$CX_PGC_OLD_DIR" "$CX_PGC_OLD_PGDATA" 2>/dev/null)" = "$CX_PGC_FROM" ]
}

# cx_pgc_fail_state: a bullet under "current state" of a failure after the switch: the database was
# converted and where the old data is.
cx_pgc_fail_state() {
  cx_pgc_crossed || return 0
  cx_pgc_old_present || return 0
  cx_up_bullet "$(cx_msg pgc_p18_converted "$CX_PGC_TO" "$CX_PGC_FROM" \
    "$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}")"
}

# cx_pgc_fail_next: what to do next after a failure of steps 9 to 12 when the major changed (the
# two ways back, the one the old data's absence leaves, or nothing when the upgrade did not cross).
# 0 when it printed; 1 for the caller's own text.
cx_pgc_fail_next() {
  local old
  cx_pgc_crossed || return 1
  old=$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}
  if ! cx_pgc_old_present; then
    cx_up_par "$(cx_msg pgc_p18_gone "$CX_UP_CURRENT" "$CX_PGC_FROM" "$old")"
    cx_pgc_restore_line
    return 0
  fi
  cx_up_par "$(cx_msg pgc_p18_both "$CX_UP_CURRENT")"
  cx_up_par "$(cx_msg pgc_p18_roll "$CX_PGC_FROM")"
  cx_cmd "sudo $CX_ROOT/custodexa.sh rollback$(cx_status_lang_arg)" | sed 's/^/   /'
  # Written after the new version started has data the old one will not have; before it started the
  # new database holds nothing the old one lacks.
  [ -z "$(cx_state_get last_upgrade.new_started_at)" ] || cx_up_par "$(cx_msg pgc_p18_roll_note)"
  cx_up_par "$(cx_msg pgc_p18_restore)"
  cx_pgc_restore_line | sed 's/^/   /'
}
