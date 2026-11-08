# shellcheck shell=bash
# The conversion of the bundled database to the major of the release being upgraded to: the checks
# before the preview (what cannot be converted, the space, what an earlier failure left behind), the
# preview section, and step 8 of upgrade. The old data folder is never written, renamed or deleted by
# anything here: the old server keeps running, its data is dumped with the new major's pg_dump,
# and a new cluster is created in a new folder from that dump.
# Phases, each recorded in state.json (last_upgrade.db_convert.phase) before it starts:
#   prepare  read the old database's encoding and collation; an earlier <data>/postgresql goes aside
#   dump     pg_dump -Fc into <data>/.pg-convert/<ts>/db.dump, then pg_restore -l reads it
#   init     a temporary container (network none) with the new image makes the new cluster
#   restore  pg_restore --single-transaction --exit-on-error
#   verify   per-table counts, schema_migrations, sequences, encoding and collation are equal on both
#            sides, and SHOW data_checksums is on
#   analyze  vacuumdb --all --analyze-in-stages
#   done     the temporary container stops, the dump goes
# A failed phase is wrapped up by cx_pgc_fail (the old services come back, the new folder is kept as
# postgresql.failed-convert-<ts>). Needs lib/dirop.sh, lib/pgmajor.sh, the target MANIFEST loaded
# (cx_mf), lib/backup.sh (cx_bk_vars) and lib/dbclient.sh.
# shellcheck disable=SC2034
readonly CX_PGC_CONTAINER=custodexa-pgconvert
readonly CX_PGC_PHASES="prepare dump init restore verify analyze done"
# The speed and fixed time of the estimate (minutes = ceil(size / rate) + overhead), set
# from measured conversions.
CX_PGC_RATE_BYTES=${CX_PGC_RATE_BYTES:-1073741824} CX_PGC_OVERHEAD_MIN=${CX_PGC_OVERHEAD_MIN:-1}
# While a long phase (export, import) runs, a line says how long step 8 has taken and how much is
# left, every CX_PGC_TICK seconds. Lines are appended; nothing is redrawn.
CX_PGC_TICK=${CX_PGC_TICK:-60} CX_PGC_T0=0
# What the new cluster takes beyond the database's own size: the WAL the import writes (up to about
# 1.1 GiB at 1.3 GB of data, measured: the margin of 1 GiB was exceeded by 4%) and
# temporary files. Only ever raised.
CX_PGC_NEW_MARGIN=${CX_PGC_NEW_MARGIN:-2147483648}
CX_PGC_ACTIVE=0 CX_PGC_FROM="" CX_PGC_TO="" CX_PGC_OLD_DIR="" CX_PGC_OLD_PGDATA=""
CX_PGC_NEW_DIR="" CX_PGC_NEW_PGDATA="" CX_PGC_DBSIZE=0 CX_PGC_MINUTES=0
CX_PGC_WORK="" CX_PGC_ENC="" CX_PGC_COLLATE="" CX_PGC_CTYPE="" CX_PGC_WHY=""
declare -ga CX_PGC_ART=()

# cx_pgc_plan: whether this upgrade converts the bundled database (CX_PGC_ACTIVE), and from which
# major to which. The target MANIFEST is the one loaded; the running release is read in a subshell.
cx_pgc_plan() {
  local cur
  CX_PGC_ACTIVE=0
  [[ " ${CX_OVERLAYS:-} " != *" external-database "* ]] || return 0
  cx_pgm_release_db || return 0
  CX_PGC_TO=$CX_PGM_MAJOR CX_PGC_NEW_DIR=$CX_PGM_DATA_DIR CX_PGC_NEW_PGDATA=$CX_PGM_PGDATA
  cur=$(cx_manifest_load "$CX_ROOT/current/MANIFEST.json" >/dev/null 2>&1 && cx_pgm_release_db \
    && printf '%s|%s|%s' "$CX_PGM_MAJOR" "$CX_PGM_DATA_DIR" "$CX_PGM_PGDATA") || return 0
  IFS='|' read -r CX_PGC_FROM CX_PGC_OLD_DIR CX_PGC_OLD_PGDATA <<<"$cur"
  # db-upgrade on a folder older than the release it runs: the folder, not the MANIFEST, says the
  # major the data is in (the old folder is the one the new cluster replaces).
  if [ -n "${CX_PGC_DISK_FROM:-}" ]; then
    CX_PGC_FROM=$CX_PGC_DISK_FROM CX_PGC_OLD_DIR=$CX_PGC_NEW_DIR
    CX_PGC_OLD_PGDATA=""
    [ "$CX_PGC_FROM" -lt 18 ] || CX_PGC_OLD_PGDATA=$CX_PGC_FROM/docker
  fi
  [ "$CX_PGC_FROM" != "$CX_PGC_TO" ] || return 0
  CX_PGC_ACTIVE=1
}

# cx_pgc_scan_sql: one query, rows "kind|name": the settings the conversion does not carry (an
# extension other than plpgsql, a tablespace other than the two built in, a role other than the
# application's own, PUBLIC and the built-in pg_ roles that holds a privilege). The privileges are
# the ones pg_restore -l lists as ACL entries and the restore judges the same way: on the objects of
# the application's schemas (tables and sequences, columns, schemas, functions, types, large
# objects, foreign servers), the default privileges (pg_default_acl) and the database itself. Asked
# of the running server because step 1 has no dump to read; the catalogs of the system schemas are
# left out, as a dump leaves them out.
cx_pgc_scan_sql() {
  cat <<EOF
/* pgc-scan */
WITH us AS (SELECT oid FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg\_toast%')
SELECT 'ext|' || extname FROM pg_extension WHERE extname <> 'plpgsql'
UNION ALL SELECT 'ts|' || spcname FROM pg_tablespace WHERE spcname NOT IN ('pg_default', 'pg_global')
UNION ALL SELECT DISTINCT 'role|' || r.rolname FROM (
  SELECT (aclexplode(relacl)).grantee g FROM pg_class WHERE relacl IS NOT NULL AND relnamespace IN (SELECT oid FROM us)
  UNION SELECT (aclexplode(a.attacl)).grantee FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
    WHERE a.attacl IS NOT NULL AND c.relnamespace IN (SELECT oid FROM us)
  UNION SELECT (aclexplode(nspacl)).grantee FROM pg_namespace WHERE nspacl IS NOT NULL AND oid IN (SELECT oid FROM us)
  UNION SELECT (aclexplode(proacl)).grantee FROM pg_proc WHERE proacl IS NOT NULL AND pronamespace IN (SELECT oid FROM us)
  UNION SELECT (aclexplode(typacl)).grantee FROM pg_type WHERE typacl IS NOT NULL AND typnamespace IN (SELECT oid FROM us)
  UNION SELECT (aclexplode(defaclacl)).grantee FROM pg_default_acl WHERE defaclacl IS NOT NULL
  UNION SELECT (aclexplode(lomacl)).grantee FROM pg_largeobject_metadata WHERE lomacl IS NOT NULL
  UNION SELECT (aclexplode(srvacl)).grantee FROM pg_foreign_server WHERE srvacl IS NOT NULL
  UNION SELECT (aclexplode(datacl)).grantee FROM pg_database WHERE datacl IS NOT NULL AND datname = current_database()) x
  JOIN pg_roles r ON r.oid = x.g WHERE x.g <> 0 AND r.rolname NOT LIKE 'pg\_%' AND r.rolname <> '${CX_BK_DBUSER:-custodexa}'
ORDER BY 1
EOF
}

# cx_pgc_precheck: 0 nothing in the way; CX_EXIT_REFUSED with the screen (P03) when something is. A
# database the script cannot ask is not a refusal here (the checks that come after say so).
cx_pgc_precheck() {
  local rows ext="" ts="" role="" line
  [ "$CX_PGC_ACTIVE" = 1 ] || return 0
  cx_db_ready || return 0
  rows=$(cx_db sql "$(cx_pgc_scan_sql)" 2>/dev/null) || return 0
  while IFS= read -r line; do
    case $line in
      ext\|*) ext+="${ext:+, }${line#ext|}" ;;
      ts\|*) ts+="${ts:+, }${line#ts|}" ;;
      role\|*) role+="${role:+, }${line#role|}" ;;
    esac
  done <<<"$rows"
  [ -n "$ext$ts$role" ] || return 0
  cx_log CHECK "conversion refused: extensions=[$ext] tablespaces=[$ts] roles=[$role]"
  cx_line FAIL "$(cx_msg pgc_unsupported_head)"
  [ -z "$ext" ] || cx_up_par "$(cx_msg pgc_unsupported_ext "$ext")"
  [ -z "$ts" ] || cx_up_par "$(cx_msg pgc_unsupported_ts "$ts")"
  [ -z "$role" ] || cx_up_par "$(cx_msg pgc_unsupported_role "$role")"
  cx_up_par "$(cx_msg pgc_unsupported_foot "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET")"
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
  return "$CX_EXIT_REFUSED"
}

# ---------- space ----------

declare -ga CX_PGC_MOUNTS=()
declare -gA CX_PGC_NEED=() CX_PGC_FREE=() CX_PGC_ITEMS=()

# cx_pgc_space_add <path> <bytes> <kind> <message id of the place>: the path's file system and what
# is free on it; one that cannot be found stops the check (CX_PGC_WHY names the place). What each
# file system is asked for is kept as lines "kind|path|bytes" (kind: backup images newdb dump margin).
cx_pgc_space_add() {
  local path=$1 bytes=$2 kind=$3 mount free
  mount=$(cx_mount_of "$path") free=$(cx_free_bytes "$path")
  if [ -z "$mount" ] || ! [[ $free =~ ^[0-9]+$ ]]; then
    CX_PGC_WHY=$4
    return 1
  fi
  if [ -z "${CX_PGC_NEED[$mount]+x}" ]; then
    CX_PGC_MOUNTS+=("$mount")
    CX_PGC_NEED[$mount]=0 CX_PGC_FREE[$mount]=$free CX_PGC_ITEMS[$mount]=""
  fi
  CX_PGC_NEED[$mount]=$((${CX_PGC_NEED[$mount]} + bytes))
  CX_PGC_ITEMS[$mount]+="$kind|$path|$bytes"$'\n'
}

# cx_pgc_kinds <mount>: the kinds of what is written there, as a word list ("backup newdb dump").
cx_pgc_kinds() {
  local line kinds=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case " $kinds " in *" ${line%%|*} "*) ;; *) kinds+="${kinds:+ }${line%%|*}" ;; esac
  done <<<"${CX_PGC_ITEMS[$1]}"
  printf '%s' "$kinds"
}

# cx_pgc_item_path <mount> <kind>: the path of the first item of the kind.
cx_pgc_item_path() {
  local line rest
  while IFS= read -r line; do
    [ "${line%%|*}" = "$2" ] || continue
    rest=${line#*|}
    printf '%s' "${rest%%|*}"
    return 0
  done <<<"${CX_PGC_ITEMS[$1]}"
}

# cx_pgc_wrap <indent> <token>...: the tokens joined and broken into lines of at most 73 columns
# (wide characters count two); a token carries its own trailing separator, dropped at a line end.
cx_pgc_wrap() {
  local pad=$1 line="" tok cand w lead=${CX_WRAP_FIRST:-$1}
  shift
  for tok in "$@"; do
    cand=$line$tok
    w=$(cx_width "$lead$cand")
    if [ -n "$line" ] && [ "$w" -gt 73 ]; then
      printf '%s%s\n' "$lead" "${line% }"
      lead=$pad
      line=${tok# }
    else
      line=$cand
    fi
  done
  [ -z "$line" ] || printf '%s%s\n' "$lead" "${line% }"
}

# cx_pgc_head <mount>: what is written on the file system, in words.
cx_pgc_head() {
  case $(cx_pgc_kinds "$1") in
    backup) cx_msg pgc_mh_backup "$(cx_pgc_item_path "$1" backup)" ;;
    images) cx_msg pgc_mh_images "$(cx_pgc_item_path "$1" images)" ;;
    newdb | "newdb margin") cx_msg pgc_mh_newdb "$(cx_pgc_item_path "$1" newdb)" ;;
    dump) cx_msg pgc_mh_dump "$(cx_pgc_item_path "$1" dump)" ;;
    "newdb margin dump" | "newdb dump margin" | "newdb dump")
      cx_msg pgc_mh_newdb_dump "$(cx_pgc_item_path "$1" newdb)" "$(cx_pgc_item_path "$1" dump)" ;;
    *images*) cx_msg pgc_mh_mixed "$(cx_pgc_item_path "$1" images)" ;;
    *) cx_msg pgc_mh_shared ;;
  esac
}

# cx_pgc_amount <mount> <indent> <form>: the amounts of one file system, wrapped.
#   ok1    the preview: needed and free on a line, the parts in brackets under it
#   ok     needed (parts), then free, or only what is free and what is short when it is short
#   plain  as ok without the parts
cx_pgc_amount() {
  local m=$1 pad=$2 form=$3 line kind rest bytes margin=0 n sep isep one="" pre=pgc_cl need free short=0
  local -a parts=() tok=()
  need=${CX_PGC_NEED[$m]} free=${CX_PGC_FREE[$m]}
  [ "$need" -le "$free" ] || short=1
  [ "$form" != ok1 ] || pre=pgc_c
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    kind=${line%%|*} rest=${line#*|} bytes=${rest##*|}
    if [ "$kind" = margin ]; then margin=$((margin + bytes)); continue; fi
    parts+=("$(cx_msg "${pre}_$kind" "$(cx_size_human "$bytes")")")
  done <<<"${CX_PGC_ITEMS[$m]}"
  # The margin is whole gigabytes, written as such.
  [ "$margin" -eq 0 ] || parts+=("$(cx_msg "${pre}_margin" "$(((margin + CX_GIB - 1) / CX_GIB)) GB")")
  isep=$(cx_msg pgc_sp_item_sep) sep=$(cx_msg pgc_sp_sep)
  [ "${#parts[@]}" -ne 1 ] || [ "$(cx_pgc_kinds "$m")" != images ] || one=$(cx_msg pgc_sp_one_images)
  if [ "$form" = ok ] && [ "${#parts[@]}" -gt 1 ]; then
    tok=("$(cx_msg pgc_sp_need "$(cx_size_human "$need")")$(cx_msg pgc_sp_open)${parts[0]}$isep")
    for ((n = 1; n < ${#parts[@]} - 1; n++)); do tok+=("${parts[n]}$isep"); done
    tok+=("${parts[-1]}$(cx_msg pgc_sp_close)$sep")
  else
    tok=("$(cx_msg pgc_sp_need "$(cx_size_human "$need")")$one$sep")
  fi
  if [ "$short" = 1 ]; then
    tok+=("$(cx_msg pgc_sp_only "$(cx_size_human "$free")")$sep" "$(cx_msg pgc_sp_short "$(cx_size_human $((need - free)))")")
  else
    tok+=("$(cx_msg pgc_sp_free "$(cx_size_human "$free")")")
  fi
  cx_pgc_wrap "$pad" "${tok[@]}"
  if [ "$form" = ok1 ] && [ "${#parts[@]}" -gt 1 ]; then
    tok=("$(cx_msg pgc_sp_open)${parts[0]}$isep")
    for ((n = 1; n < ${#parts[@]} - 1; n++)); do tok+=("${parts[n]}$isep"); done
    tok+=("${parts[-1]}$(cx_msg pgc_sp_close)")
    cx_pgc_wrap "$pad" "${tok[@]}"
  fi
}

# cx_pgc_block <mount> <lead> <mount column width> <form>: one file system's block. The lead stands
# in front of the mount on the first line; the amounts sit under what the mount heads.
cx_pgc_block() {
  local m=$1 lead=$2 w=$3 form=$4 col pad
  [ "${#m}" -lt "$w" ] || w=$((${#m} + 1))
  col=$(cx_width "$lead")
  pad=$(printf '%*s' "$((col + w))" '')
  printf '%s%-*s%s\n' "$lead" "$w" "$m" "$(cx_pgc_head "$m")"
  cx_pgc_amount "$m" "$pad" "$form"
}

# cx_pgc_dbsize: the old database's size in CX_PGC_DBSIZE (and the minutes of the estimate).
cx_pgc_dbsize() {
  local n
  CX_PGC_DBSIZE=0
  cx_db_ready || return 0
  n=$(cx_snap_sql "SELECT pg_database_size(current_database())" 2>/dev/null) || return 0
  [[ $n =~ ^[0-9]+$ ]] || return 0
  CX_PGC_DBSIZE=$n
  CX_PGC_MINUTES=$(((n + CX_PGC_RATE_BYTES - 1) / CX_PGC_RATE_BYTES + CX_PGC_OVERHEAD_MIN))
}

# cx_pgc_mounted <path>: a running container has the folder (or something under it) mounted, or
# Docker cannot say. Such a folder is in use and is never offered for removal.
cx_pgc_mounted() {
  local ids src
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

# cx_pgc_artifacts: the folders an earlier failed conversion left (CX_PGC_ART, "path|bytes"), the ones
# in use by a running container left out.
cx_pgc_artifacts() {
  local d bytes
  CX_PGC_ART=()
  for d in "$CX_BK_DATA"/postgresql.failed-convert-* "$CX_BK_DATA"/postgresql.partial-convert-*; do
    [ -d "$d" ] || continue
    ! cx_pgc_mounted "$d" || continue
    bytes=$(cx_bk_du "$d")
    CX_PGC_ART+=("$d|$bytes")
  done
}

# cx_pgc_artifact_lines: the list of CX_PGC_ART, a folder per line, the sizes right-aligned.
cx_pgc_artifact_lines() {
  local e w=0 p
  for e in "${CX_PGC_ART[@]}"; do p=${e%%|*}; [ "${#p}" -le "$w" ] || w=${#p}; done
  for e in "${CX_PGC_ART[@]}"; do
    printf '    %-*s  %7s\n' "$w" "${e%%|*}" "$(cx_size_human "${e##*|}")"
  done
}

# cx_pgc_art_version <folder>: the PostgreSQL major in the folder's PG_VERSION (at the top or one
# or two levels down, as the layouts differ), empty when there is none.
cx_pgc_art_version() {
  local f v
  f=$(find "$1" -maxdepth 3 -name PG_VERSION -type f 2>/dev/null | head -n 1)
  [ -n "$f" ] || return 0
  v=$(head -n 1 "$f" 2>/dev/null)
  [[ $v =~ ^[0-9]+$ ]] && printf '%s' "$v"
  return 0
}

# cx_pgc_art_detail_lines: the list of the question (P21): a folder per line, under it the version
# and the size, right-aligned.
cx_pgc_art_detail_lines() {
  local e v
  for e in "${CX_PGC_ART[@]}"; do
    v=$(cx_pgc_art_version "${e%%|*}")
    if [ -n "$v" ]; then v=$(cx_msg pgc_art_ver "$v"); else v=$(cx_msg pgc_art_ver_unknown); fi
    printf '    %s\n' "${e%%|*}"
    printf '        %s  %9s\n' "$v" "$(cx_size_human "${e##*|}")"
  done
}

# cx_pgc_art_ok: an earlier failure's leftovers may be offered for removal: the run on record is not
# unfinished beyond a conversion failure that was recorded as failed (and cx_pgc_artifacts leaves out
# a folder a running container mounts).
cx_pgc_art_ok() {
  local r
  r=$(cx_state_get last_upgrade.result)
  case $r in in_progress) return 1 ;; esac
  [ "$r" != failed ] || [ "$(cx_state_get last_upgrade.db_convert.result)" = failed ]
}

# cx_pgc_art_clear <path>: remove one of them, through the rename log, then delete the renamed folder.
cx_pgc_art_clear() {
  local p=$1 to
  case $p in "$CX_BK_DATA"/postgresql.failed-convert-* | "$CX_BK_DATA"/postgresql.partial-convert-*) ;; *) return 1 ;; esac
  ! cx_pgc_mounted "$p" || return 1
  to=$p.removing-$(date '+%Y%m%d-%H%M%S')
  cx_dirop_rename removing "$p" "$to" || return 1
  rm -rf -- "$to"
}

# cx_pgc_art_offer: P21. Interactive: list them and ask (default no); yes removes each. Not
# interactive: nothing is removed. 0 when something was removed (the space is to be counted again).
cx_pgc_art_offer() {
  local e removed=1 p b
  [ "${#CX_PGC_ART[@]}" -gt 0 ] || return 1
  cx_pgc_art_ok || return 1
  printf '\n%s\n' "$(cx_msg pgc_art_head)"
  printf '%s\n' "$(cx_msg pgc_art_desc)"
  cx_pgc_art_detail_lines
  if ! cx_up_interactive; then
    printf '%s\n' "$(cx_msg pgc_art_ni)"
    return 1
  fi
  printf '%s\n' "$(cx_msg pgc_art_after_head)"
  cx_up_bullet "$(cx_msg pgc_art_after_1)"
  cx_up_bullet "$(cx_msg pgc_art_after_2 "$CX_UP_CURRENT" "$CX_BK_DATA/$CX_PGC_OLD_DIR")"
  cx_up_bullet "$(cx_msg pgc_art_after_3)"
  printf '\n'
  if cx_ask_yn pgc_art_ask "${#CX_PGC_ART[@]}"; then
    # The answer ends its line on a terminal; this is the blank line after it.
    printf '\n'
    for e in "${CX_PGC_ART[@]}"; do
      p=${e%%|*} b=${e##*|}
      if cx_pgc_art_clear "$p"; then
        cx_line OK "$(cx_msg pgc_art_cleared "$p" "$(cx_size_human "$b")")"
        removed=0
      fi
    done
  else
    printf '%s\n' "$(cx_msg pgc_art_kept "${#CX_PGC_ART[@]}")"
  fi
  return "$removed"
}

# cx_ask_yn <message id> [args]: y or yes on a terminal; Enter is no.
cx_ask_yn() {
  local answer
  printf '%s ' "$(cx_msg "$@")"
  read -r answer || answer=""
  case ${answer,,} in y | yes) return 0 ;; esac
  return 1
}

# cx_pgc_docker_root: the Docker image store's folder, empty when Docker does not say.
cx_pgc_docker_root() { docker info --format '{{.DockerRootDir}}' 2>/dev/null | head -n 1; }

# cx_pgc_space: every write the upgrade makes, grouped by file system (a refusal before anything
# stops). Returns 0, CX_EXIT_FAILED with the screen (P02) when short or when a place cannot be
# found. With --backup-ref the backup is the operator's and is not counted; the conversion is.
cx_pgc_space() {
  local m free need images droot short=0 new dump keep=1 pass
  local -a was_short=()
  [ "$CX_PGC_ACTIVE" = 1 ] || return 0
  cx_pgc_dbsize
  for pass in 1 2; do
    CX_PGC_MOUNTS=() CX_PGC_NEED=() CX_PGC_FREE=() CX_PGC_ITEMS=() CX_PGC_WHY="" short=0
    droot=$(cx_pgc_docker_root)
    new=$CX_BK_DATA/$CX_PGC_NEW_DIR
    dump=$CX_BK_DATA/.pg-convert
    if ! cx_br_flags_given && [ "${CX_BK_NEED:-0}" -gt 0 ]; then
      cx_pgc_space_add "$CX_ROOT/backups" "$CX_BK_NEED" backup pgc_where_backups || true
    fi
    images=$(cx_mf_needed_bytes "$(cx_arch 2>/dev/null || printf amd64)")
    if [ -z "$CX_PGC_WHY" ] && [ -z "$droot" ]; then CX_PGC_WHY=pgc_where_images; fi
    [ -n "$CX_PGC_WHY" ] || cx_pgc_space_add "$droot" "$images" images pgc_where_images || true
    [ -n "$CX_PGC_WHY" ] || cx_pgc_space_add "$new" "$CX_PGC_DBSIZE" newdb pgc_where_newdb || true
    [ -n "$CX_PGC_WHY" ] || cx_pgc_space_add "$new" "$CX_PGC_NEW_MARGIN" margin pgc_where_newdb || true
    [ -n "$CX_PGC_WHY" ] || cx_pgc_space_add "$dump" "$CX_PGC_DBSIZE" dump pgc_where_dump || true
    if [ -n "$CX_PGC_WHY" ]; then
      cx_log CHECK "space: cannot place $CX_PGC_WHY"
      cx_line FAIL "$(cx_msg pgc_space_unknown_head)"
      cx_up_par "$(cx_msg pgc_space_unknown "$(cx_msg "$CX_PGC_WHY")" "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET")"
      return "$CX_EXIT_FAILED"
    fi
    for m in "${CX_PGC_MOUNTS[@]}"; do
      [ "${CX_PGC_NEED[$m]}" -le "${CX_PGC_FREE[$m]}" ] || short=1
      cx_log CHECK "space $m need=${CX_PGC_NEED[$m]} free=${CX_PGC_FREE[$m]}"
    done
    if [ "$short" != 1 ]; then
      # Leftovers were removed and it is enough now: say what was counted again.
      for m in "${was_short[@]}"; do
        cx_line OK "$(cx_msg pgc_art_recount "$m" "$(cx_size_human "${CX_PGC_NEED[$m]}")" "$(cx_size_human "${CX_PGC_FREE[$m]}")")"
      done
      [ "${#was_short[@]}" -eq 0 ] || printf '       %s\n' "$(cx_msg pgc_art_untouched "$CX_BK_DATA/$CX_PGC_OLD_DIR")"
      return 0
    fi
    [ "$pass" != 1 ] || for m in "${CX_PGC_MOUNTS[@]}"; do
      [ "${CX_PGC_NEED[$m]}" -le "${CX_PGC_FREE[$m]}" ] || was_short+=("$m")
    done
    # A second pass only after leftovers were removed.
    if [ "$pass" = 1 ] && [ "$keep" = 1 ]; then
      cx_pgc_artifacts
      if cx_pgc_art_offer; then keep=0; continue; fi
    fi
    break
  done
  cx_line FAIL "$(cx_msg pgc_space_head)"
  cx_pgc_space_screen
  return "$CX_EXIT_FAILED"
}

# cx_pgc_space_screen: the file systems that are short, the leftovers of an earlier failure that
# take space, and what to do (P02).
cx_pgc_space_screen() {
  local m need free k art=0 only_images=1 backup_short="" shorts="" sep ok_b="" ok_n=""
  local -a short=()
  cx_pgc_artifacts
  if [ "${#CX_PGC_ART[@]}" -gt 0 ] && cx_pgc_art_ok; then art=1; fi
  for m in "${CX_PGC_MOUNTS[@]}"; do
    need=${CX_PGC_NEED[$m]} free=${CX_PGC_FREE[$m]}
    [ "$need" -gt "$free" ] || continue
    short+=("$m")
    k=$(cx_pgc_kinds "$m")
    [ "$k" = images ] || only_images=0
    case " $k " in *" backup "*) [ -n "$backup_short" ] || backup_short=$m ;; esac
  done
  sep=$(cx_msg pgc_sp_list_sep)
  for m in "${short[@]}"; do shorts+="${shorts:+$sep}$m"; done
  if [ "$art" = 1 ]; then
    for m in "${short[@]}"; do cx_pgc_block "$m" '  ' 8 plain; done
  elif [ "$only_images" = 1 ]; then
    for m in "${short[@]}"; do cx_pgc_block "$m" '  ' 8 ok; done
    for m in "${CX_PGC_MOUNTS[@]}"; do
      case " $(cx_pgc_kinds "$m") " in *" backup "*) ok_b=$m ;; esac
      case " $(cx_pgc_kinds "$m") " in *" newdb "*) ok_n=$m ;; esac
    done
    if [ -n "$ok_b" ]; then
      cx_up_par "$(cx_msg pgc_ok_both "$ok_b" "$ok_n")"
    else
      cx_up_par "$(cx_msg pgc_ok_new "$ok_n")"
    fi
  else
    for m in "${CX_PGC_MOUNTS[@]}"; do cx_pgc_block "$m" '  ' 8 ok; done
  fi
  if [ "$art" = 1 ]; then
    printf '\n%s\n' "$(cx_up_par "$(cx_msg pgc_space_art)")"
    cx_pgc_artifact_lines
    cx_up_par "$(cx_msg pgc_space_art_hint "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET" "$shorts")"
  elif [ -n "$backup_short" ]; then
    cx_up_par "$(cx_msg pgc_space_foot_backup "$backup_short" "$(cx_pgc_item_path "$backup_short" backup)" "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET")"
  else
    cx_up_par "$(cx_msg pgc_space_foot "$shorts" "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET")"
  fi
}

# cx_pgc_preview: the "database conversion" section of the preview (P01).
cx_pgc_preview() {
  local m old new lead
  [ "$CX_PGC_ACTIVE" = 1 ] || return 0
  old=$CX_BK_DATA/$CX_PGC_OLD_DIR
  new=$CX_BK_DATA/$CX_PGC_NEW_DIR
  printf '\n%s\n' "$(cx_msg pgc_prev_head "$CX_PGC_FROM" "$CX_PGC_TO")"
  if [ "$CX_PGC_FROM" -ge 13 ] 2>/dev/null; then
    # The community supports a major for five years: the final release is in November of major + 2012.
    printf '%s\n' "$(cx_msg pgc_prev_why "$CX_UP_TARGET" "$CX_PGC_TO" "$((CX_PGC_TO + 2012))" "$CX_PGC_FROM" "$((CX_PGC_FROM + 2012))")"
  else
    printf '%s\n' "$(cx_msg pgc_prev_why_plain "$CX_UP_TARGET" "$CX_PGC_TO")"
  fi
  printf '%s\n' "$(cx_msg pgc_prev_how "$CX_PGC_TO")"
  printf '%s\n' "$(cx_msg pgc_prev_old "$old")"
  printf '%s\n' "$(cx_msg pgc_prev_new "$new")"
  lead=$(cx_msg pgc_prev_space_lead)
  for m in "${CX_PGC_MOUNTS[@]}"; do
    cx_pgc_block "$m" "$lead" 7 ok1
    lead=$(printf '%*s' "$(cx_width "$lead")" '')
  done
  if [ "$CX_PGC_DBSIZE" -gt 0 ]; then
    printf '%s\n' "$(cx_msg pgc_prev_time "$CX_PGC_MINUTES" "$((CX_PGC_MINUTES * 2))")"
  fi
  printf '%s\n' "$(cx_msg pgc_prev_fail "$CX_UP_CURRENT")"
  printf '%s\n' "$(cx_msg pgc_prev_back "$CX_UP_CURRENT")"
}

# ---------- step 8 ----------

# cx_pgc_phase <name>: recorded before the phase runs.
cx_pgc_phase() {
  cx_state_set last_upgrade.db_convert.phase "$1"
  cx_state_save "$CX_ROOT/state.json"
}

# cx_pgc_image: the new database image as the target's images name it.
cx_pgc_image() { printf '%s' "${CX_IMG_REF[postgres]:-}"; }

# cx_pgc_psql <sql>: SQL on the new cluster, in the temporary container.
cx_pgc_psql() {
  docker exec "$CX_PGC_CONTAINER" psql -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -AtX -v ON_ERROR_STOP=1 -c "$1"
}

# cx_pgc_env_pw: the database password for a docker run, handed over by name so it is never part of a
# logged command line.
cx_pgc_env_pw() { cx_bk_env DB_PASSWORD; }

# cx_pgc_network: the network the old database container is on.
cx_pgc_network() {
  local id
  id=$(cx_compose ps -q postgres 2>/dev/null | head -n 1)
  [ -n "$id" ] || return 1
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$id" 2>/dev/null | head -n 1
}

cx_pgc_prepare() {
  local row
  row=$(cx_db sql 'SELECT pg_encoding_to_char(encoding) || chr(124) || datcollate || chr(124) || datctype FROM pg_database WHERE datname = current_database()') || return 1
  IFS='|' read -r CX_PGC_ENC CX_PGC_COLLATE CX_PGC_CTYPE <<<"$row"
  [ -n "$CX_PGC_ENC" ] && [ -n "$CX_PGC_COLLATE" ] && [ -n "$CX_PGC_CTYPE" ] || return 1
  cx_state_set last_upgrade.db_convert.params "$CX_PGC_ENC|$CX_PGC_COLLATE|$CX_PGC_CTYPE"
  # An earlier <data>/postgresql with something in it goes aside, not deleted.
  local new=$CX_BK_DATA/$CX_PGC_NEW_DIR
  if [ -d "$new" ] && [ -n "$(ls -A "$new" 2>/dev/null)" ]; then
    cx_dirop_rename before-convert "$new" "$new.before-convert-$CX_PGC_TS" || return 1
  fi
}

cx_pgc_dump() {
  local net img
  net=$(cx_pgc_network) || return 1
  img=$(cx_pgc_image)
  (umask 077 && mkdir -p "$CX_PGC_WORK") || return 1
  PGPASSWORD=$(cx_pgc_env_pw) cx_log_run docker run --rm --pull never --network "$net" -e PGPASSWORD \
    -v "$CX_PGC_WORK:/dump" --entrypoint pg_dump "$img" -h postgres -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" \
    -Fc -f /dump/db.dump >/dev/null 2>&1 || return 1
  cx_log_run docker run --rm --pull never --network none -v "$CX_PGC_WORK:/dump:ro" \
    --entrypoint pg_restore "$img" -l /dump/db.dump >/dev/null 2>&1
}

cx_pgc_init() {
  local img tries=0 max
  img=$(cx_pgc_image)
  cx_dirop_start_check "$CX_BK_DATA" "$CX_PGC_NEW_DIR" "$CX_PGC_NEW_PGDATA" "$CX_PGC_TO" init || return 1
  POSTGRES_PASSWORD=$(cx_pgc_env_pw) cx_log_run docker run -d --name "$CX_PGC_CONTAINER" --network none --pull never \
    -e POSTGRES_USER="$CX_BK_DBUSER" -e POSTGRES_DB="$CX_BK_DBNAME" -e POSTGRES_PASSWORD \
    -e "POSTGRES_INITDB_ARGS=--encoding=$CX_PGC_ENC --lc-collate=$CX_PGC_COLLATE --lc-ctype=$CX_PGC_CTYPE" \
    -v "$CX_BK_DATA/$CX_PGC_NEW_DIR:/var/lib/postgresql" -v "$CX_PGC_WORK:/dump:ro" "$img" >/dev/null 2>&1 || return 1
  max=$(cx_ready_tries)
  until docker exec "$CX_PGC_CONTAINER" pg_isready -h 127.0.0.1 -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt "$max" ] || return 1
    sleep "$CX_UP_READY_WAIT"
  done
}

cx_pgc_restore() {
  local out
  out=$(cx_log_run docker exec "$CX_PGC_CONTAINER" pg_restore --single-transaction --exit-on-error \
    -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" /dump/db.dump 2>&1) || {
    CX_PGC_WHY=$(printf '%s\n' "$out" | head -n 1)
    return 1
  }
}

# cx_pgc_facts_sql: what must be equal on both sides: every table's row count, the migrations, the
# sequences, the encoding and the collation.
cx_pgc_facts_sql() {
  cat <<'EOF'
/* pgc-facts */
SELECT 'count|' || format('%I.%I', schemaname, relname) || '=' ||
  (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, relname), false, true, '')))[1]::text
  FROM pg_stat_user_tables
UNION ALL SELECT 'migrations|' || coalesce(string_agg(version::text, ',' ORDER BY version), '') FROM schema_migrations
UNION ALL SELECT 'sequence|' || schemaname || '.' || sequencename || '=' || coalesce(last_value::text, 'null') FROM pg_sequences
UNION ALL SELECT 'database|' || pg_encoding_to_char(encoding) || ',' || datcollate || ',' || datctype FROM pg_database WHERE datname = current_database()
ORDER BY 1
EOF
}

cx_pgc_verify() {
  local old new sums
  old=$(cx_db sql "$(cx_pgc_facts_sql)") || { CX_PGC_WHY=old_read; return 1; }
  new=$(cx_pgc_psql "$(cx_pgc_facts_sql)") || { CX_PGC_WHY=new_read; return 1; }
  if [ "$old" != "$new" ]; then
    CX_PGC_WHY="differs: $(diff <(printf '%s\n' "$old") <(printf '%s\n' "$new") | sed -n 's/^[<>] //p' | head -n 1)"
    return 1
  fi
  CX_PGC_TABLES=$(printf '%s\n' "$old" | grep -c '^count|' || true)
  sums=$(cx_pgc_psql 'SHOW data_checksums') || { CX_PGC_WHY=checksums_read; return 1; }
  if [ "$sums" != on ]; then
    CX_PGC_WHY="data_checksums is $sums"
    return 1
  fi
}

cx_pgc_analyze() {
  cx_log_run docker exec "$CX_PGC_CONTAINER" vacuumdb --all --analyze-in-stages -U "$CX_BK_DBUSER" >/dev/null 2>&1
}

cx_pgc_done() {
  local sz
  cx_log_run docker stop -t 120 "$CX_PGC_CONTAINER" >/dev/null 2>&1 || return 1
  cx_log_run docker rm "$CX_PGC_CONTAINER" >/dev/null 2>&1 || return 1
  rm -rf -- "$CX_PGC_WORK"
  sz=$(cx_bk_du "$CX_BK_DATA/$CX_PGC_NEW_DIR")
  cx_state_set last_upgrade.db_convert.checksums on
  cx_state_set last_upgrade.db_convert.bytes "$sz"
  cx_state_set last_upgrade.db_convert.result "done"
  cx_pgc_phase "done"
}

# cx_pgc_tick_line: the progress line. The remaining time is the preview's range (minutes and twice
# the minutes) less what has passed; past the end of the range it says so instead.
cx_pgc_tick_line() {
  local el=$(($(cx_now) - CX_PGC_T0)) lo hi dur
  dur=$(cx_duration "$el")
  if [ "$CX_PGC_DBSIZE" -le 0 ] || [ "$CX_PGC_MINUTES" -le 0 ]; then
    printf '        %s\n' "$(cx_msg pgc_tick_bare "$dur")"
    return 0
  fi
  lo=$(((CX_PGC_MINUTES * 60 - el + 59) / 60))
  hi=$(((CX_PGC_MINUTES * 120 - el + 59) / 60))
  [ "$lo" -ge 1 ] || lo=1
  if [ "$hi" -le 1 ]; then
    printf '        %s\n' "$(cx_msg pgc_tick_over "$dur")"
  else
    printf '        %s\n' "$(cx_msg pgc_tick "$dur" "$lo" "$hi")"
  fi
}

# cx_pgc_timed <function>: runs it with the progress line going in the background. The ticker looks
# every second (so nothing sleeps on after it is stopped) and ends when the script does.
cx_pgc_timed() {
  local rc=0 pid
  (
    last=$(cx_now)
    while kill -0 "$$" 2>/dev/null; do
      sleep 1
      if [ $(($(cx_now) - last)) -ge "$CX_PGC_TICK" ]; then
        cx_pgc_tick_line
        last=$(cx_now)
      fi
    done
  ) &
  pid=$!
  "$@" || rc=$?
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return "$rc"
}

# cx_pgc_sub <mark> <n> <text> [duration]: a line under step 8, "n/5 text", with the duration where
# the steps put theirs.
cx_pgc_sub() {
  local text=${3//$'\n'/$'\n'                    }
  [ -z "${4:-}" ] || text=$(cx_with_duration "$text" 20 "$4")
  printf '        %s %s  %s\n' "$(cx_mark "$1")" "$2/5" "$text"
}

# cx_pgc_sub_no <phase>: the number of the phase among the five lines under step 8 (none for the
# preparation and the clean-up).
cx_pgc_sub_no() {
  case $1 in dump) printf 1 ;; init) printf 2 ;; restore) printf 3 ;; verify) printf 4 ;; analyze) printf 5 ;; *) return 1 ;; esac
}

# cx_pgc_why_text <phase>: the cause of a failed phase in a sentence; the database's own words
# follow when there are some (a line that is not a bare keyword).
cx_pgc_why_text() {
  case ${CX_PGC_WHY:-} in
    *" "*) if [ "$1" = restore ] || [ "$1" = verify ]; then cx_msg "pgc_why_${1}_d" "$CX_PGC_WHY"; return; fi ;;
  esac
  cx_msg "pgc_why_$1"
}

# cx_pgc_fail <phase>: the wrap-up of a failed phase, in the order of the design: the temporary
# container goes, the new folder is kept as failed-convert, the dump goes, the way back is on record
# BEFORE the old services start, the old services start, the upgrade is recorded as failed. Returns
# CX_EXIT_FAILED always; the caller exits.
cx_pgc_fail() {
  local phase=$1 new kept="" started=0 d pname n
  new=$CX_BK_DATA/$CX_PGC_NEW_DIR
  cx_log FAIL "db_convert phase=$phase reason=${CX_PGC_WHY:-unknown}"
  pname=$(cx_msg "pgc_ph_$phase")
  docker rm -f "$CX_PGC_CONTAINER" >/dev/null 2>&1 || true
  if [ -d "$new" ] && [ -n "$(ls -A "$new" 2>/dev/null)" ]; then
    kept=$new.failed-convert-$CX_PGC_TS
    cx_dirop_rename failed-convert "$new" "$kept" || kept=""
  fi
  [ -z "$CX_PGC_WORK" ] || rm -rf -- "$CX_PGC_WORK"
  cx_state_set last_upgrade.db_convert.result failed
  cx_state_set last_upgrade.db_convert.recovery restart_old
  cx_state_set last_upgrade.db_convert.reuse invalid
  if cx_state_save "$CX_ROOT/state.json"; then
    cx_pgr_restart_old || started=$?
  else
    cx_log FAIL "db_convert: the way back could not be recorded, the old services are not started"
  fi
  if n=$(cx_pgc_sub_no "$phase"); then
    if [ "$phase" = verify ]; then cx_pgc_sub FAIL "$n" "$(cx_msg pgc_subf_verify)"
    else cx_pgc_sub FAIL "$n" "$(cx_msg "pgc_sub_$phase" "$CX_PGC_TO")"; fi
  fi
  printf '\n'
  if [ "$started" = 1 ]; then
    cx_line FAIL "$(cx_msg pgc_fail_head "$pname")"
  else
    cx_line FAIL "$(cx_msg pgc_fail_head_stopped "$pname")"
  fi
  local -a words=()
  read -r -a words <<<"$(cx_pgc_why_text "$phase")"
  words=("${words[@]/%/ }")
  words[-1]=${words[-1]% }
  CX_WRAP_FIRST=$(cx_msg pgc_fail_reason_lab) cx_pgc_wrap '             ' "${words[@]}" "$(cx_msg pgc_fail_summary)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg pgc_fail_state_title)")"
  if [ "$started" = 1 ]; then
    cx_up_bullet "$(cx_msg pgc_fail_running "$CX_UP_CURRENT")"
  else
    cx_up_bullet "$(cx_msg pgc_fail_stopped "$CX_UP_CURRENT")"
  fi
  d=$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}
  cx_up_bullet "$(cx_msg pgc_fail_old_kept "$d")"
  [ -z "$kept" ] || cx_up_bullet "$(cx_msg pgc_fail_kept "$kept")"
  cx_up_bullet_backup
  [ "$started" = 1 ] || cx_up_bullet "$(cx_msg pgc_fail_no_auto)"
  if [ "$started" = 1 ]; then
    [ "$CX_BK_KEK" != ui ] || cx_up_par "$(cx_msg up_unseal_after)"
    printf '\n'
    cx_up_par "$(cx_msg pgc_fail_again)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
  else
    cx_up_par "$(cx_msg pgc_fail_restart)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh start"
    cx_up_par "$(cx_msg pgc_fail_again_b)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
  fi
  printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
  return "$CX_EXIT_FAILED"
}

# cx_pgc_run <n>: step 8. 0 converted (or nothing to convert, shown as SKIP); otherwise the failure
# wrap-up has run and the caller exits.
cx_pgc_run() {
  local n=$1 t0 p t1 line
  local sn
  CX_PGC_TABLES=0
  if [ "$CX_PGC_ACTIVE" != 1 ]; then
    # An external database is the operator's own; the bundled one may already be on the newest major.
    case " ${CX_OVERLAYS:-} " in
      *" external-database "*) cx_up_step_line SKIP "$n" "$(cx_msg up_step_pgconvert_external)" ;;
      *) cx_up_step_line SKIP "$n" "$(cx_msg up_step_reserved)" ;;
    esac
    return 0
  fi
  CX_PGC_TS=$(date '+%Y%m%d-%H%M%S')
  CX_PGC_WORK=$CX_BK_DATA/.pg-convert/$CX_PGC_TS
  cx_state_unset last_upgrade.db_convert.result
  cx_state_unset last_upgrade.db_convert.recovery
  cx_state_unset last_upgrade.db_convert.reuse
  cx_state_unset last_upgrade.db_convert.phase
  # Where the two folders are, for the screens of a later command that has not read the MANIFEST.
  cx_state_set last_upgrade.db_convert.old_path "$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}"
  cx_state_set last_upgrade.db_convert.new_path "$CX_BK_DATA/$CX_PGC_NEW_DIR"
  cx_up_step_line RUN "$n" "$(cx_msg up_step_pgconvert "$CX_PGC_FROM" "$CX_PGC_TO" "$(cx_size_human "$CX_PGC_DBSIZE")")"
  printf '        %s\n' "$(cx_msg pgc_run_note)"
  t0=$(cx_now)
  CX_PGC_T0=$t0
  for p in $CX_PGC_PHASES; do
    CX_PGC_WHY=""
    t1=$(cx_now)
    cx_pgc_phase "$p"
    case $p in
      prepare) cx_pgc_prepare ;;
      dump) cx_pgc_timed cx_pgc_dump ;;
      init) cx_pgc_init ;;
      restore) cx_pgc_timed cx_pgc_restore ;;
      verify) cx_pgc_verify ;;
      analyze) cx_pgc_analyze ;;
      'done') cx_pgc_done ;;
    esac || { cx_pgc_fail "$p"; return "$CX_EXIT_FAILED"; }
    if sn=$(cx_pgc_sub_no "$p"); then
      line=$(cx_msg "pgc_sub_$p" "$([ "$p" = verify ] && printf '%s' "$CX_PGC_TABLES" || printf '%s' "$CX_PGC_TO")")
      if [ "$p" = verify ]; then cx_pgc_sub OK "$sn" "$line"
      else cx_pgc_sub OK "$sn" "$line" "$(cx_duration $(($(cx_now) - t1)))"; fi
    fi
  done
  cx_up_step_line OK "$n" "$(cx_msg up_step_pgconvert_done "$CX_PGC_FROM" "$CX_PGC_TO")" \
    "$(cx_duration $(($(cx_now) - t0)))"
  printf '        %s\n' "$(cx_msg pgc_old_kept "$CX_BK_DATA/$CX_PGC_OLD_DIR${CX_PGC_OLD_PGDATA:+/$CX_PGC_OLD_PGDATA}")"
}
