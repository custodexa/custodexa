# shellcheck shell=bash
# Which PostgreSQL major the bundled database of a release is, where its data lives, and what the
# data folder on disk holds. The library prints nothing for people and never guesses: the callers
# (the upgrade's database conversion, rollback, restore, status, the menu) decide what to say.
#   cx_pgm_release_db       from the loaded MANIFEST (cx_manifest_load): CX_PGM_MAJOR, CX_PGM_DATA_DIR,
#                           CX_PGM_PGDATA. A release with bundled_db says so; an older one has none and
#                           is the 16 layout (data/postgres, no PGDATA) read from its postgres image tag.
#   cx_pgm_dir_major        the major in <data path>/<data dir>/<pgdata>/PG_VERSION
#   cx_pgm_server_major     the major of a server_version_num
#   cx_pgm_check            the folder against the running server; stops on any disagreement
# shellcheck disable=SC2034
CX_PGM_MAJOR="" CX_PGM_DATA_DIR="" CX_PGM_PGDATA="" CX_PGM_FOUND=""

# cx_pgm_release_db: 0 and the three variables set; 1 when the MANIFEST names neither bundled_db nor
# a postgres image whose tag starts with a major.
cx_pgm_release_db() {
  local major tag
  CX_PGM_MAJOR="" CX_PGM_DATA_DIR="" CX_PGM_PGDATA=""
  major=$(cx_mf bundled_db.major)
  if [ -n "$major" ]; then
    [[ $major =~ ^[0-9]+$ ]] || return 1
    [ -n "$(cx_mf bundled_db.data_dir)" ] || return 1
    CX_PGM_MAJOR=$major
    CX_PGM_DATA_DIR=$(cx_mf bundled_db.data_dir)
    CX_PGM_PGDATA=$(cx_mf bundled_db.pgdata)
    return 0
  fi
  tag=$(cx_mf images.postgres.tag)
  [[ $tag =~ ^([0-9]+)[.-] ]] || return 1
  CX_PGM_MAJOR=${BASH_REMATCH[1]}
  CX_PGM_DATA_DIR=postgres
  CX_PGM_PGDATA=""
}

# cx_pgm_dir_major <data path> <data dir> <pgdata>: prints the major; 2 when PG_VERSION is missing,
# unreadable or not a number (nothing printed).
cx_pgm_dir_major() {
  local f=$1/$2${3:+/$3}/PG_VERSION v
  [ -r "$f" ] || return 2
  v=$(head -n 1 "$f" 2>/dev/null) || return 2
  [[ $v =~ ^[0-9]+$ ]] || return 2
  printf '%s' "$v"
}

# cx_pgm_server_major <server_version_num>: 160015 -> 16 (the number is major * 10000 + minor).
cx_pgm_server_major() {
  [[ ${1:-} =~ ^[0-9]{5,6}$ ]] || return 1
  printf '%s' $((10#$1 / 10000))
}

# cx_pgm_check <data path> <data dir> <pgdata> [server_version_num]: 0 when the folder has a
# PG_VERSION (CX_PGM_FOUND is its major) and, when a server number is given, the server agrees;
# 2 when there is no usable PG_VERSION; 3 when the server runs another major.
cx_pgm_check() {
  local found srv rc=0
  CX_PGM_FOUND=""
  found=$(cx_pgm_dir_major "$1" "$2" "$3") || return 2
  CX_PGM_FOUND=$found
  [ -n "${4:-}" ] || return 0
  srv=$(cx_pgm_server_major "$4") || rc=3
  [ "$rc" -ne 0 ] || [ "$srv" = "$found" ] || rc=3
  return "$rc"
}
