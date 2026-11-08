# shellcheck shell=bash
# The bundled database of a restore: which PostgreSQL major and which data folder the data release
# uses, the check of the backup list against it, and the controlled start of the new cluster.
# The data release's MANIFEST (the installed one, else the one inside the backup) decides; the
# deployment being replaced is read from its own current release. A release without bundled_db is
# the 16 layout (data/postgres).
# Needs lib/pgmajor.sh, lib/dirop.sh and the reader (cx_rs_get, cx_rs_metadata).
# shellcheck disable=SC2034
CX_RS_DB_MAJOR="" CX_RS_DB_DIR="" CX_RS_DB_PGDATA="" CX_RS_DB_CUR_MAJOR="" CX_RS_DB_CUR_DIR=""

# cx_rs_db_info <MANIFEST file>: prints "<major>|<data dir>|<pgdata>"; 1 when it cannot be read.
cx_rs_db_info() {
  [ -f "$1" ] || return 1
  (cx_manifest_load "$1" >/dev/null 2>&1 && cx_pgm_release_db &&
    printf '%s|%s|%s' "$CX_PGM_MAJOR" "$CX_PGM_DATA_DIR" "$CX_PGM_PGDATA")
}

# cx_rs_db_target: the data release's layout in CX_RS_DB_MAJOR/DIR/PGDATA; 1 when unreadable.
cx_rs_db_target() {
  local f info
  CX_RS_DB_MAJOR="" CX_RS_DB_DIR="" CX_RS_DB_PGDATA=""
  f=$CX_ROOT/releases/${CX_RS_VERSION:-}/MANIFEST.json
  [ -f "$f" ] || f=$(cx_rs_metadata)/release-MANIFEST.json
  [ -f "$f" ] || f=$CX_RS_DIR/pass2/release-MANIFEST.json
  info=$(cx_rs_db_info "$f") || return 1
  IFS='|' read -r CX_RS_DB_MAJOR CX_RS_DB_DIR CX_RS_DB_PGDATA <<<"$info"
}

# cx_rs_db_current: the layout of the deployment being replaced in CX_RS_DB_CUR_MAJOR/DIR; empty
# when there is none (a new host).
cx_rs_db_current() {
  local v info
  CX_RS_DB_CUR_MAJOR="" CX_RS_DB_CUR_DIR=""
  v=$(cx_state_get current.version)
  [ -n "$v" ] || return 0
  info=$(cx_rs_db_info "$CX_ROOT/releases/$v/MANIFEST.json") || return 0
  IFS='|' read -r CX_RS_DB_CUR_MAJOR CX_RS_DB_CUR_DIR _ <<<"$info"
}

# cx_rs_db_dir: prints the data folder name of the data release (the 16 layout when unreadable).
cx_rs_db_dir() {
  cx_rs_db_target || CX_RS_DB_DIR=postgres
  printf '%s' "${CX_RS_DB_DIR:-postgres}"
}

# cx_rs_db_dir_mode: prints the mode of the empty data folder a restore makes. In the 16 layout the
# folder is PGDATA itself: the image's entrypoint takes it over, and 0700 is what PostgreSQL wants.
# In the 18 layout the folder is only the volume above PGDATA (<major>/docker): the image creates
# that subfolder as its own user, so the volume must be traversable, as the one Docker makes for a
# fresh install or a conversion is (0755). The data itself stays 0700 inside <major>/docker.
cx_rs_db_dir_mode() {
  cx_rs_db_target || CX_RS_DB_PGDATA=""
  if [ -n "${CX_RS_DB_PGDATA:-}" ]; then printf '0755'; else printf '0700'; fi
}

# cx_rs_db_other_dir: prints the folder of the deployment being replaced when it is another one
# than the data release's; nothing otherwise.
cx_rs_db_other_dir() {
  local tgt
  tgt=$(cx_rs_db_dir)
  cx_rs_db_current
  [ -z "$CX_RS_DB_CUR_DIR" ] || [ "$CX_RS_DB_CUR_DIR" = "$tgt" ] || printf '%s' "$CX_RS_DB_CUR_DIR"
}

# cx_rs_db_major_check: the backup list of a bundled database names the major its release bundles.
# Before anything is stopped. The external form has its own server checks.
cx_rs_db_major_check() {
  local listed
  [ "$(cx_rs_get db.location)" != external ] || return 0
  listed=$(cx_rs_get db.server_major)
  # A release list that cannot be read is refused by the migration and release checks that follow.
  if ! cx_rs_db_target || [ -z "$CX_RS_DB_MAJOR" ]; then return 0; fi
  [ "$listed" != "$CX_RS_DB_MAJOR" ] || return 0
  cx_line FAIL "$(cx_msg rs_db_major_mismatch "${listed:-?}" "$CX_RS_VERSION" "$CX_RS_DB_MAJOR")"
  cx_rs_par "$(cx_msg rs_db_major_guide)"
  cx_rs_unchanged
  return 1
}

# cx_rs_dirop_init_guard: the start check of the restore's cluster creation. The one controlled
# exception to "a version file must exist": it holds only while the restore record is at the stage
# that creates the cluster (swapped), nothing is pending in the rename log, and the target folder is
# absent or empty. Anything else is refused (CX_EXIT_FAILED) with the screen of the check.
cx_rs_dirop_init_guard() {
  if [ "$(cx_rs_phase_value)" != swapped ]; then
    cx_line FAIL "$(cx_msg rs_db_init_stage "$(cx_rs_phase_value)")"
    return "$CX_EXIT_FAILED"
  fi
  cx_rs_db_target || { cx_line FAIL "$(cx_msg rs_db_init_unknown)"; return "$CX_EXIT_FAILED"; }
  cx_dirop_guard "$CX_RS_DATA" "$CX_RS_DB_DIR" "$CX_RS_DB_PGDATA" "$CX_RS_DB_MAJOR" init
}

# cx_rs_dirop_start_guard: the start check of every start after the import. The version file of the
# restored cluster must be there and be the release's major. The external form has no folder here.
cx_rs_dirop_start_guard() {
  ! cx_rs_ext || return 0
  cx_rs_db_target || { cx_line FAIL "$(cx_msg rs_db_init_unknown)"; return "$CX_EXIT_FAILED"; }
  cx_dirop_guard "$CX_RS_DATA" "$CX_RS_DB_DIR" "$CX_RS_DB_PGDATA" "$CX_RS_DB_MAJOR"
}

# cx_rs_preview_db: the database row of the preview (same-host restore of a bundled database): the
# backup's major, the one it is restored with and, when the deployment's own differs, what is kept.
# Shown for a release that records bundled_db or when the majors differ, so a restore inside the
# 16 layout reads as before.
cx_rs_preview_db() {
  local rows tgt other keep_cur keep_old="" cur_major
  ! cx_rs_ext || return 0
  [ "$CX_RS_FLOW" = same ] || return 0
  cx_rs_db_target || return 0
  [ -n "$CX_RS_DB_MAJOR" ] || return 0
  cx_rs_db_current
  cur_major=$CX_RS_DB_CUR_MAJOR
  if [ -z "$cur_major" ] || [ "$cur_major" = "$CX_RS_DB_MAJOR" ]; then
    [ -n "$(cx_rs_db_has_bundled)" ] || return 0
    cx_rs_row database "$(cx_msg rs_db_same "$CX_RS_DB_MAJOR" "$CX_RS_DB_MAJOR")"
    return 0
  fi
  tgt=$CX_RS_DB_DIR other=$CX_RS_DB_CUR_DIR
  rows=$(cx_msg rs_db_other "$CX_RS_DB_MAJOR" "$CX_RS_VERSION" "$CX_RS_DB_MAJOR")
  rows+=$'\n'$(cx_msg rs_db_differs "$cur_major")
  rows+=$'\n'$(cx_msg rs_db_back "$CX_RS_VERSION" "$CX_RS_DB_MAJOR")
  keep_cur=$CX_RS_DATA/$other.before-restore-$CX_RS_TS
  rows+=$'\n'$(cx_msg rs_db_kept_cur "$cur_major" "$keep_cur")
  if [ "$tgt" != "$other" ] && [ -d "$CX_RS_DATA/$tgt" ]; then
    keep_old=$CX_RS_DATA/$tgt.before-restore-$CX_RS_TS
    rows+=$'\n'$(cx_msg rs_db_kept_old "$CX_RS_DB_MAJOR" "$keep_old")
  fi
  if [ "$CX_RS_DB_MAJOR" -lt "$cur_major" ]; then
    rows+=$'\n'$(cx_msg rs_db_again "$(cx_state_get current.version)" "$cur_major")
  fi
  cx_rs_row database "$rows"
}

# cx_rs_db_has_bundled: prints 1 when the data release records bundled_db.
cx_rs_db_has_bundled() {
  local f
  f=$CX_ROOT/releases/${CX_RS_VERSION:-}/MANIFEST.json
  [ -f "$f" ] || f=$(cx_rs_metadata)/release-MANIFEST.json
  [ -f "$f" ] || return 0
  (cx_manifest_load "$f" >/dev/null 2>&1 && [ -n "$(cx_mf bundled_db.major)" ] && printf 1) || true
}

# cx_rs_db_kept_paths: the database folders a same-host restore renames and keeps, one per line:
# the deployment's own, and the data release's folder when that is another one and exists.
cx_rs_db_kept_paths() {
  local tgt cur
  tgt=$(cx_rs_db_dir)
  cx_rs_db_current
  cur=${CX_RS_DB_CUR_DIR:-$tgt}
  printf '%s' "$CX_RS_DATA/$cur.before-restore-$CX_RS_TS"
  if [ "$tgt" != "$cur" ] && [ -d "$CX_RS_DATA/$tgt" ]; then
    printf '\n%s' "$CX_RS_DATA/$tgt.before-restore-$CX_RS_TS"
  fi
}
