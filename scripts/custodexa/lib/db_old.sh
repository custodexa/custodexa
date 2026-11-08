# shellcheck shell=bash
# The old database folders a deployment keeps next to the current one: what the folders are, how big
# they are and which PostgreSQL major they hold. Used by status (the database section), the main
# menu and the db-upgrade command; nothing here changes a folder.
# The rows of CX_DBO_ROWS are "kind|path|major|bytes":
#   previous         the data folder of an earlier release (postgres/ when the current one is postgresql/)
#   before-convert   what an upgrade's conversion moved aside
#   rolled-back      the newer version's data, kept when rollback went back across the major
#   before-restore   what a restore moved aside
#   failed-convert   the half-made new folder of a failed conversion
#   partial-convert  the half-made new folder of an interrupted conversion
#   removing         a folder whose removal was started and not finished
# Needs lib/manifest.sh, lib/pgmajor.sh, lib/dirop.sh and lib/state.sh.
# shellcheck disable=SC2034
CX_DBO_MAJOR="" CX_DBO_DIR="" CX_DBO_PGDATA=""
declare -ga CX_DBO_ROWS=()

# cx_dbo_release <release folder>: "major|data dir|pgdata" read from its MANIFEST.json.
cx_dbo_release() {
  [ -f "$1/MANIFEST.json" ] || return 1
  (cx_manifest_load "$1/MANIFEST.json" >/dev/null 2>&1 && cx_pgm_release_db \
    && printf '%s|%s|%s' "$CX_PGM_MAJOR" "$CX_PGM_DATA_DIR" "$CX_PGM_PGDATA")
}

# cx_dbo_current: CX_DBO_MAJOR, CX_DBO_DIR and CX_DBO_PGDATA of the release the deployment runs.
# 1 when it cannot be read.
cx_dbo_current() {
  local info rel=$CX_ROOT/current
  [ -f "$rel/MANIFEST.json" ] || rel=${CX_DIR:-$CX_ROOT/current}
  info=$(cx_dbo_release "$rel") || return 1
  IFS='|' read -r CX_DBO_MAJOR CX_DBO_DIR CX_DBO_PGDATA <<<"$info"
}

# cx_dbo_data_path: where the data folders are (DATA_PATH of .env, made absolute).
cx_dbo_data_path() {
  local d=""
  [ -r "$CX_ROOT/.env" ] && d=$(cx_env_get "$CX_ROOT/.env" DATA_PATH)
  case $d in
    "") d=$CX_ROOT/data ;;
    /*) ;;
    *) d=$CX_ROOT/${d#./} ;;
  esac
  printf '%s' "${d%/}"
}

# cx_dbo_du <folder>: bytes used (0 when absent or unreadable).
cx_dbo_du() {
  local out
  [ -d "$1" ] || { printf 0; return 0; }
  out=$(du -sb -- "$1" 2>/dev/null) || true
  out=${out%%[[:space:]]*}
  printf '%s' "${out:-0}"
}

# cx_dbo_class <kind>: keep (may hold data the application wrote), artifact (only a conversion
# container wrote it) or finish (a removal that was started).
cx_dbo_class() {
  case $1 in
    previous | before-convert | rolled-back | before-restore) printf keep ;;
    failed-convert | partial-convert) printf artifact ;;
    *) printf finish ;;
  esac
}

# cx_dbo_list <data path>: CX_DBO_ROWS in the order of the kinds above. Needs cx_dbo_current first;
# without it the folder of the current release is not known and nothing is listed.
cx_dbo_list() {
  local data=$1 kind p major prev=""
  CX_DBO_ROWS=()
  [ -n "$CX_DBO_DIR" ] || return 0
  if [ "$CX_DBO_DIR" != postgres ] && [ -d "$data/postgres" ]; then prev=postgres; fi
  [ -z "$prev" ] || CX_DBO_ROWS+=("previous|$data/$prev|$(cx_dirop_version_of "$data/$prev")|$(cx_dbo_du "$data/$prev")")
  for kind in before-convert rolled-back before-restore failed-convert partial-convert removing; do
    for p in "$data"/postgres*."$kind"-*; do
      [ -d "$p" ] || continue
      major=$(cx_dirop_version_of "$p")
      CX_DBO_ROWS+=("$kind|$p|$major|$(cx_dbo_du "$p")")
    done
  done
}

# cx_dbo_mounted <path>: a running container has the folder (or something under it) mounted, or
# Docker cannot say. Such a folder is in use.
cx_dbo_mounted() {
  local ids src s
  ids=$(docker ps -q 2>/dev/null) || return 0
  [ -n "$ids" ] || return 1
  # shellcheck disable=SC2086
  src=$(docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' $ids 2>/dev/null) || return 0
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    case $s in "$1" | "$1"/*) return 0 ;; esac
  done <<<"$src"
  return 1
}

# cx_dbo_major_text <major>: the major as shown ("?" when the folder has no readable version file).
cx_dbo_major_text() { if [ "$1" = missing ]; then printf '?'; else printf '%s' "$1"; fi; }

# cx_dbo_kind_text <kind> [with version]: what a kind of folder is, in a few words. With the
# version, a kept earlier folder says which upgrade kept it (db-upgrade and the menu); the
# database section of status does not.
cx_dbo_kind_text() {
  if [ "$1" = previous ] && [ "${2:-0}" = 1 ]; then
    cx_msg dbo_kind_previous_up "$(cx_state_get last_upgrade.to)"
  else
    cx_msg "dbo_kind_${1//-/_}"
  fi
}

# cx_dbo_size_text <bytes> <width>: the size as shown, right-aligned so that the sizes of the rows
# line up (the width is that of the longest, see cx_dbo_size_width).
cx_dbo_size_text() { printf '%*s' "$2" "$(cx_size_human "$1")"; }

# cx_dbo_size_width: the width of the longest size among CX_DBO_ROWS (those of a removal in
# progress are not listed with the others by status, but a longer one only adds a space).
cx_dbo_size_width() {
  local e w=0 t
  for e in "${CX_DBO_ROWS[@]}"; do
    t=$(cx_size_human "${e##*|}")
    [ "${#t}" -le "$w" ] || w=${#t}
  done
  printf '%s' "$w"
}

# cx_dbo_rows_text <indent> <detail indent>: the rows as path line and detail line.
cx_dbo_rows_text() {
  local e kind p major bytes w
  w=$(cx_dbo_size_width)
  for e in "${CX_DBO_ROWS[@]}"; do
    IFS='|' read -r kind p major bytes <<<"$e"
    printf '%s%s\n%sPostgreSQL %s    %s    %s\n' "$1" "$p" "$2" "$(cx_dbo_major_text "$major")" \
      "$(cx_dbo_size_text "$bytes" "$w")" "$(cx_dbo_kind_text "$kind" 1)"
  done
}
