# shellcheck shell=bash
# CX_DBX_* are read by lib/cmd_backup.sh and lib/backup_manifest.sh.
# shellcheck disable=SC2034
# An external database, before anything is stopped: is the client there, can it reach the server,
# which client matches the server, and does the database depend on anything a dump of it leaves
# out (pg_dump writes neither roles nor tablespaces).
#   1 the TLS settings the client can follow (lib/dbclient.sh cx_db_tls_read)
#   2 the client of the highest major version is on this host; it asks the server for its version
#   3 the client of the server's own major version is chosen (no other: an older pg_dump is not
#     used even where it would work)
#   4 the dependencies: tablespaces, owners, extensions refuse; privileges granted to other roles
#     are recorded and warned about, not refused
# Results: CX_DBX_FAIL "" (ready), image, connect, version or unsupported; CX_DBX_ITEMS the lines
# of an unsupported one, "<message key> [arguments...]" with arguments separated by a tab.
# Role and tablespace names come back hex-encoded (the bytes of the UTF-8 name), so no name can
# break a line of psql's output; they are decoded only to be shown (cx_dbx_show_name).

CX_DBX_FAIL="" CX_DBX_SERVER="" CX_DBX_SERVER_MAJOR="" CX_DBX_ROLES="" CX_DBX_PROBE_MAJOR=""
CX_DBX_MISSING_MAJOR=""
declare -ga CX_DBX_ITEMS=()
declare -gA CX_DBX_IDS=() # major -> image ID recorded for the client of that major

readonly CX_DBX_SYS_SCHEMAS="n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_)'"

# cx_dbx_ids: CX_DBX_IDS from the tool images recorded at install or upgrade (pgclientNN=<ID>).
cx_dbx_ids() {
  local kv n
  CX_DBX_IDS=()
  for kv in $(cx_state_get current.tool_image_ids); do
    n=${kv%%=*}
    [[ $n =~ ^pgclient([0-9]+)$ ]] || continue
    n=${BASH_REMATCH[1]}
    [[ ${kv#*=} =~ ^sha256:[0-9a-f]{64}$ ]] || continue
    CX_DBX_IDS[$n]=${kv#*=}
  done
}

# cx_dbx_ids_resolved: CX_DBX_IDS from the clients obtained in this run (CX_IMG_ID), for an
# upgrade that checks the external database before anything is recorded.
cx_dbx_ids_resolved() {
  local n m
  CX_DBX_IDS=()
  for n in "${!CX_IMG_ID[@]}"; do
    [[ $n =~ ^pgclient([0-9]+)$ ]] || continue
    # The major first: the next =~ replaces BASH_REMATCH.
    m=${BASH_REMATCH[1]}
    [[ ${CX_IMG_ID[$n]} =~ ^sha256:[0-9a-f]{64}$ ]] && CX_DBX_IDS[$m]=${CX_IMG_ID[$n]}
  done
  return 0
}

# cx_dbx_majors: the recorded client majors, ascending.
cx_dbx_majors() { printf '%s\n' "${!CX_DBX_IDS[@]}" | sort -n; }

# cx_dbx_present <major>: that client is recorded and this host holds exactly that image.
cx_dbx_present() {
  local id=${CX_DBX_IDS[$1]:-}
  [ -n "$id" ] && [ "$(docker image inspect --format '{{.Id}}' "$id" 2>/dev/null)" = "$id" ]
}

# cx_dbx_use <major>: the database client from now on.
cx_dbx_use() {
  CX_DB_EXT_ID=${CX_DBX_IDS[$1]} CX_DB_EXT_MAJOR=$1
  cx_log CHECK "database client pgclient$1 id=$CX_DB_EXT_ID"
}

# cx_dbx_system_ca: verify-ca without a CA file of its own checks the server with the system CA
# file of the client image; the chosen image must have one.
cx_dbx_system_ca() {
  [ "$CX_DB_ROOTCERT" = "$CX_DB_SYSTEM_CA" ] || return 0
  docker run --rm --pull never --network none --log-driver none --entrypoint test "$CX_DB_EXT_ID" \
    -f "$CX_DB_SYSTEM_CA" >/dev/null 2>&1 && return 0
  cx_log CHECK "client pgclient$CX_DB_EXT_MAJOR has no $CX_DB_SYSTEM_CA"
  CX_DBX_ITEMS+=("pb_ext_dep_sysca")
  return 1
}

# cx_dbx_unhex <hex>: the bytes.
cx_dbx_unhex() {
  local h=$1 out="" i
  for ((i = 0; i < ${#h}; i += 2)); do out+="\\x${h:i:2}"; done
  printf '%b' "$out"
}

# cx_dbx_hex <name>: the bytes of the name in lower-case hex, two characters each.
cx_dbx_hex() {
  local LC_ALL=C s=$1 i out=""
  for ((i = 0; i < ${#s}; i++)); do printf -v out '%s%02x' "$out" "'${s:i:1}"; done
  printf '%s' "$out"
}

# cx_dbx_hex_list <hex...>: the manifest value: unique, in byte order, one space between.
cx_dbx_hex_list() {
  [ $# -gt 0 ] || return 0
  printf '%s\n' "$@" | LC_ALL=C sort -u | paste -sd ' ' -
}

# cx_dbx_show_name <hex>: a name as SQL would need it written: as is when it is lower-case letters,
# digits and underscores not starting with a digit, otherwise in double quotes with an inner quote
# doubled; a control character shows as \xNN.
cx_dbx_show_name() {
  local LC_ALL=C h=$1 name out="" i c b
  name=$(cx_dbx_unhex "$h")
  if [[ $name =~ ^[a-z_][a-z0-9_]*$ ]]; then
    printf '%s' "$name"
    return 0
  fi
  for ((i = 0; i < ${#h}; i += 2)); do
    b=${h:i:2}
    if [ $((16#$b)) -lt 32 ] || [ "$b" = 7f ]; then
      out+="\\\\x$b"
    elif [ "$b" = 22 ]; then
      out+='\x22\x22'
    else
      out+="\\x$b"
    fi
  done
  c=$(printf '%b' "$out")
  printf '"%s"' "$c"
}

# cx_dbx_rows <sql>: the query's rows through the database client; what the client says on stderr
# (why it could not connect) goes to the log. Fails when the query fails.
cx_dbx_rows() {
  local err out rc=0 line
  err=$(mktemp) || return 1
  out=$(cx_db sql "$1" 2>"$err") || rc=$?
  while IFS= read -r line || [ -n "$line" ]; do cx_log OUT "$line"; done <"$err"
  rm -f "$err"
  [ "$rc" = 0 ] || return "$rc"
  printf '%s' "$out"
}

# cx_dbx_version: the server's version through the probe client. Fails when the server cannot be
# reached or answers with something else.
cx_dbx_version() {
  local n v
  n=$(cx_dbx_rows 'SHOW server_version_num') || return 1
  v=$(cx_dbx_rows 'SHOW server_version') || return 1
  [[ $n =~ ^[0-9]+$ ]] || return 1
  CX_DBX_SERVER=${v%%[[:space:]]*}
  CX_DBX_SERVER_MAJOR=$((n / 10000))
  cx_log CHECK "external database server=$CX_DBX_SERVER major=$CX_DBX_SERVER_MAJOR"
}

# cx_dbx_deps: the dependencies a dump leaves out (CX_DBX_ITEMS) and the other roles granted
# privileges (CX_DBX_ROLES). Fails when a query fails.
cx_dbx_deps() {
  local rows line a b
  local -a roles=()
  rows=$(cx_dbx_rows "WITH d AS (SELECT dattablespace AS ts FROM pg_database WHERE datname = current_database()),
o AS (SELECT CASE WHEN c.reltablespace = 0 THEN d.ts ELSE c.reltablespace END AS ts
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN d WHERE $CX_DBX_SYS_SCHEMAS)
SELECT encode(convert_to(t.spcname, 'UTF8'), 'hex'), (SELECT count(*) FROM o WHERE o.ts = t.oid)
FROM pg_tablespace t WHERE t.spcname NOT IN ('pg_default', 'pg_global')
  AND (t.oid IN (SELECT ts FROM o) OR t.oid = (SELECT ts FROM d)) ORDER BY 1") || return 1
  while IFS='|' read -r a b; do
    [ -n "$a" ] && CX_DBX_ITEMS+=("pb_ext_dep_ts $(cx_dbx_show_name "$a")"$'\t'"$b")
  done <<<"$rows"
  rows=$(cx_dbx_rows "WITH o AS (
  SELECT n.nspowner AS own FROM pg_namespace n WHERE $CX_DBX_SYS_SCHEMAS
    AND NOT (n.nspname = 'public' AND n.nspowner = 'pg_database_owner'::regrole)
  UNION ALL SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE $CX_DBX_SYS_SCHEMAS
  UNION ALL SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE $CX_DBX_SYS_SCHEMAS
  UNION ALL SELECT t.typowner FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE $CX_DBX_SYS_SCHEMAS
    AND t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid))
SELECT encode(convert_to(pg_get_userbyid(own), 'UTF8'), 'hex'), count(*) FROM o
WHERE own <> (SELECT oid FROM pg_roles WHERE rolname = current_user) GROUP BY 1 ORDER BY 1") || return 1
  while IFS='|' read -r a b; do
    [ -n "$a" ] && CX_DBX_ITEMS+=("pb_ext_dep_owner $CX_BK_DBUSER"$'\t'"$(cx_dbx_show_name "$a")"$'\t'"$b")
  done <<<"$rows"
  rows=$(cx_dbx_rows "SELECT extname || ' ' || extversion FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1") || return 1
  while IFS= read -r line; do
    [ -n "$line" ] && CX_DBX_ITEMS+=("pb_ext_dep_ext $line")
  done <<<"$rows"
  rows=$(cx_dbx_rows "WITH s AS (SELECT n.oid FROM pg_namespace n WHERE $CX_DBX_SYS_SCHEMAS),
a AS (SELECT n.nspacl AS acl FROM pg_namespace n WHERE n.oid IN (SELECT oid FROM s)
  UNION ALL SELECT relacl FROM pg_class WHERE relnamespace IN (SELECT oid FROM s)
  UNION ALL SELECT attacl FROM pg_attribute JOIN pg_class c ON c.oid = attrelid WHERE c.relnamespace IN (SELECT oid FROM s)
  UNION ALL SELECT proacl FROM pg_proc WHERE pronamespace IN (SELECT oid FROM s)
  UNION ALL SELECT typacl FROM pg_type WHERE typnamespace IN (SELECT oid FROM s)
  UNION ALL SELECT defaclacl FROM pg_default_acl
  UNION ALL SELECT lomacl FROM pg_largeobject_metadata),
r AS (SELECT x.grantee AS id FROM a CROSS JOIN LATERAL aclexplode(a.acl) x WHERE a.acl IS NOT NULL
  UNION SELECT x.grantor FROM a CROSS JOIN LATERAL aclexplode(a.acl) x WHERE a.acl IS NOT NULL
  UNION SELECT defaclrole FROM pg_default_acl)
SELECT encode(convert_to(rolname, 'UTF8'), 'hex') FROM pg_roles
WHERE oid IN (SELECT id FROM r) AND rolname <> current_user AND rolname !~ '^pg_' ORDER BY 1") || return 1
  # A name starting with pg_ is a built-in role (PostgreSQL reserves the prefix): never listed,
  # whatever the server answered.
  while IFS= read -r line; do
    [[ $line =~ ^([0-9a-f]{2})+$ && $line != 70675f* ]] && roles+=("$line")
  done <<<"$rows"
  CX_DBX_ROLES=$(cx_dbx_hex_list ${roles[@]+"${roles[@]}"})
  rows=$(cx_dbx_rows "SELECT pg_get_userbyid(datdba) = current_user FROM pg_database WHERE datname = current_database()") || return 1
  [ "$rows" = t ] || cx_log CHECK "the database is owned by another role than DB_USER (pg_dump leaves the owner of the database out)"
  cx_log CHECK "external database dependencies=${#CX_DBX_ITEMS[@]} other_roles=${CX_DBX_ROLES:-none}"
}

# cx_dbx_prepare [resolved]: steps 1 to 4 above. Sets CX_DBX_FAIL ("" when the backup can go on).
# "resolved": the clients are the ones obtained in this run, not the ones state.json records.
cx_dbx_prepare() {
  local top
  CX_DBX_FAIL="" CX_DBX_ITEMS=() CX_DBX_ROLES="" CX_DBX_SERVER="" CX_DBX_SERVER_MAJOR=""
  CX_DBX_MISSING_MAJOR="" CX_DB_EXT_ID="" CX_DB_EXT_MAJOR=""
  cx_db_tls_read
  if [ "${#CX_DB_TLS_ITEMS[@]}" -gt 0 ]; then
    CX_DBX_ITEMS=("${CX_DB_TLS_ITEMS[@]}")
    CX_DBX_FAIL=unsupported
    return 0
  fi
  if [ "${1:-}" = resolved ]; then cx_dbx_ids_resolved; else cx_dbx_ids; fi
  top=$(cx_dbx_majors | tail -n 1)
  CX_DBX_PROBE_MAJOR=$top
  if [ -z "$top" ] || ! cx_dbx_present "$top"; then
    CX_DBX_MISSING_MAJOR=${top:-none}
    CX_DBX_FAIL=image
    return 0
  fi
  cx_dbx_use "$top"
  if ! cx_dbx_system_ca; then
    CX_DBX_FAIL=unsupported
    return 0
  fi
  if ! cx_dbx_version; then
    CX_DBX_FAIL=connect
    return 0
  fi
  if [ -z "${CX_DBX_IDS[$CX_DBX_SERVER_MAJOR]:-}" ]; then
    CX_DBX_FAIL=version
    return 0
  fi
  if ! cx_dbx_present "$CX_DBX_SERVER_MAJOR"; then
    CX_DBX_MISSING_MAJOR=$CX_DBX_SERVER_MAJOR
    CX_DBX_FAIL=image
    return 0
  fi
  if ! cx_dbx_deps; then
    CX_DBX_FAIL=connect
    return 0
  fi
  cx_dbx_use "$CX_DBX_SERVER_MAJOR"
  cx_dbx_system_ca || true
  [ "${#CX_DBX_ITEMS[@]}" -eq 0 ] || CX_DBX_FAIL=unsupported
}

# cx_dbx_roles_shown: the other roles as the screen shows them, separated by the language's
# separator, in the order of the manifest.
cx_dbx_roles_shown() {
  local h out="" sep
  sep=$(cx_msg bk_item_sep)
  for h in $CX_DBX_ROLES; do out+="${out:+$sep}$(cx_dbx_show_name "$h")"; done
  printf '%s' "$out"
}
