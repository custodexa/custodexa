# shellcheck shell=bash
# CX_RS_EXT_* are read by the preview and by the steps after the confirmation; CX_RS_DIR,
# CX_RS_ENV and CX_RS_DATA come from the reader and the host-value merge.
# shellcheck disable=SC2034,SC2153
# A backup of a deployment on an external database, before anything is stopped. The connection is
# the backup's own (host, port, database, user and TLS settings of the merged .env, which keeps
# them as the backup has them; a restore never connects to another server or database). The
# client is the PostgreSQL client of this release for the server's own major version. Checked:
#   - the TLS settings give the same server check as the backup recorded (never a weaker one);
#     the backup's CA file and the client certificate and key the user names are only mounted
#     into the client containers here, never placed (cx_rs_ext_place does that after confirmation)
#   - the server's major version has a client in this release, on this host; the server is not
#     older than the backup's and the client not older than the tool that made the dump
#   - the client connects and logs in
#   - DB_USER owns the database, and every object in the non-system schemas (public may keep its
#     default owner pg_database_owner)
#   - no extension but plpgsql; encoding and collation as in the backup
#   - other connections to the database: on another host there must be none; on this host they are
#     listed only (its own backend is still connected) and checked again, strictly, once the
#     services stopped and before anything is overwritten (cx_rs_ext_quiet)
#   - the roles the backup grants rights to exist on the server
#   - whether the database is empty (non-system schemas without any object)
# Any failure is shown with all the reasons found, and nothing has been changed.

CX_RS_EXT_MAJOR="" CX_RS_EXT_SERVER="" CX_RS_EXT_MAJORS=""
CX_RS_EXT_CA_DEST="" CX_RS_EXT_CERT_SRC="" CX_RS_EXT_CERT_DEST="" CX_RS_EXT_KEY_SRC="" CX_RS_EXT_KEY_DEST=""
CX_RS_EXT_EMPTY="" CX_RS_EXT_OBJECTS="" CX_RS_EXT_MISSING=""
CX_RS_EXT_CONNS=0 CX_RS_EXT_FROM="" CX_RS_EXT_APPS=""
CX_RS_DB_CLIENT_CERT=${CX_RS_DB_CLIENT_CERT:-} CX_RS_DB_CLIENT_KEY=${CX_RS_DB_CLIENT_KEY:-}
declare -ga CX_RS_EXT_ITEMS=() # the reasons found: "<message key> [arguments separated by a tab]"

# cx_rs_ext: the backup is of a deployment on an external database.
cx_rs_ext() { [ "$(cx_rs_get db.location)" = external ]; }

# cx_rs_ext_item <message key> [arguments...]: one more reason.
cx_rs_ext_item() {
  local key=$1 args=""
  shift
  [ $# -eq 0 ] || args=" $(cx_join $'\t' "$@")"
  CX_RS_EXT_ITEMS+=("$key$args")
}

# cx_rs_ext_with <command...>: the command with the database client pointed at the backup's
# database: the merged settings instead of this deployment's .env, this host's data folder for the
# certificate paths, and the pgpass file in the private work folder.
cx_rs_ext_with() {
  local CX_BK_ENV_FILE=$CX_RS_ENV CX_BK_DATA=$CX_RS_DATA CX_BK_DIR=$CX_RS_DIR/.partial-db CX_BK_TS=""
  local CX_OVERLAYS CX_BK_DBUSER CX_BK_DBNAME
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  CX_BK_DBUSER=$(cx_rs_get db.user) CX_BK_DBNAME=$(cx_rs_get db.name)
  (umask 077 && mkdir -p "$CX_BK_DIR") || return 1
  "$@"
}

# cx_rs_ext_client_id <major>: the image ID of the release's client of that major on this host,
# accepted as install accepts an image already here (cx_img_try_local), without a word on screen:
# pulled by the release's index digest; or its tag, carrying the content the release names (the
# config digest), or on the containerd image store the ID recorded when it was checked and loaded
# (load) or installed (this host's own release). A tag alone proves nothing: an image loaded from
# an offline bundle on containerd answers to its tag only, under an ID of its own.
cx_rs_ext_client_id() {
  local n=pgclient$1 ref idx tag cfg id kv
  ref=$(cx_mf "images.$n.ref") idx=$(cx_mf "images.$n.index_digest") tag=$(cx_mf "images.$n.tag")
  cfg=$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")
  [[ -n $ref && $idx =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  id=$(cx_img_id "$ref@$idx") || id=""
  if [ -n "$id" ] && { [ "$id" = "$idx" ] || [ "$id" = "$cfg" ]; }; then
    printf '%s' "$id"
    return 0
  fi
  [ -n "$tag" ] || return 1
  id=$(cx_img_id "$ref:$tag") || return 1
  [[ $id =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  if [ "$id" = "$cfg" ]; then
    printf '%s' "$id"
    return 0
  fi
  [ "$(cx_img_store)" = containerd ] || return 1
  if [ "$id" = "$(cx_img_loaded_id "$n")" ]; then
    printf '%s' "$id"
    return 0
  fi
  [ "$(cx_state_get current.version)" = "$(cx_mf version)" ] || return 1
  for kv in $(cx_state_get current.tool_image_ids); do
    if [ "$kv" = "$n=$id" ]; then
      printf '%s' "$id"
      return 0
    fi
  done
  return 1
}

# cx_rs_ext_clients: CX_RS_EXT_MAJORS, the client majors this release (the engine) names, and
# CX_DBX_IDS for those this host holds, by the release's own pins.
cx_rs_ext_clients() {
  local k m id
  local -a majors=()
  CX_DBX_IDS=() CX_RS_EXT_MAJORS=""
  CX_IMG_ARCH=$(cx_arch) || return 1
  cx_manifest_load "$CX_DIR/MANIFEST.json" >/dev/null || return 1
  for k in "${!CX_MF[@]}"; do
    [[ $k =~ ^images\.pgclient([0-9]+)\.index_digest$ ]] || continue
    m=${BASH_REMATCH[1]}
    majors+=("$m")
    if id=$(cx_rs_ext_client_id "$m"); then CX_DBX_IDS["$m"]=$id; fi
  done
  cx_log CHECK "external database clients here:$(for m in "${!CX_DBX_IDS[@]}"; do printf ' pgclient%s=%s' "$m" "${CX_DBX_IDS[$m]}"; done)"
  [ "${#majors[@]}" -eq 0 ] || CX_RS_EXT_MAJORS=$(printf '%s\n' "${majors[@]}" | sort -n | paste -sd ' ' -)
}

# cx_rs_ext_majors_shown: the client majors as a list in words.
cx_rs_ext_majors_shown() {
  local -a m=()
  read -ra m <<<"$CX_RS_EXT_MAJORS"
  case ${#m[@]} in
    0) printf '?' ;;
    1) printf '%s' "${m[0]}" ;;
    *) printf '%s%s%s' "$(cx_join "$(cx_msg bk_item_sep)" "${m[@]:0:${#m[@]}-1}")" "$(cx_msg pb_ext_and)" "${m[-1]}" ;;
  esac
}

# cx_rs_ext_file <option value> <destination> <prompt key>: CX_RS_EXT_FILE, the file to use for a
# client certificate or key: the one named by the option, else the one already at its place on this
# host, else (at a terminal) the one the user types. Fails with a reason recorded.
CX_RS_EXT_FILE=""
cx_rs_ext_file() {
  local given=$1 dest=$2 prompt=$3
  CX_RS_EXT_FILE=""
  if [ -z "$given" ] && [ -n "$dest" ] && [ -f "$dest" ] && [ -r "$dest" ]; then
    CX_RS_EXT_FILE=$dest
    return 0
  fi
  if [ -z "$given" ] && [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then
    printf '%s' "$(cx_msg "$prompt")"
    IFS= read -r given || given=""
  fi
  if [ -z "$given" ]; then
    cx_rs_ext_item rs_ext_client_missing
    return 1
  fi
  [[ $given == /* ]] || given=$PWD/$given
  if ! [ -f "$given" ] || ! [ -r "$given" ]; then
    cx_rs_ext_item rs_ext_client_unreadable "$given"
    return 1
  fi
  if [ -n "$dest" ] && [ -e "$dest" ] && ! cmp -s "$given" "$dest"; then
    cx_rs_ext_item rs_ext_client_conflict "$dest"
    return 1
  fi
  CX_RS_EXT_FILE=$given
}

# cx_rs_ext_tls: the TLS settings of the merged .env rebuilt as the backup recorded them; the files
# they name come from the backup (CA file) and from the user (client certificate and key). Fails
# with the reasons recorded.
cx_rs_ext_tls() {
  local item ok=0 cert key key_kept=1
  cx_db_tls_read
  # A file the deployment's folders do not hold yet is supplied here, not refused; a key the backup
  # would have packed is refused as the backup refused it.
  for item in ${CX_DB_TLS_ITEMS[@]+"${CX_DB_TLS_ITEMS[@]}"}; do
    case ${item%% *} in
      pb_ext_dep_ca | pb_ext_dep_cert | pb_ext_dep_keypath) ;;
      *) CX_RS_EXT_ITEMS+=("$item"); ok=1 ;;
    esac
    case ${item%% *} in pb_ext_dep_key | pb_ext_dep_key_rec) key_kept=0 ;; esac
  done
  if [ "$CX_DB_TLS_TRUST" != "$(cx_rs_get db.tls_trust)" ] || [ "$CX_DB_TLS_VERIFY" != "$(cx_rs_get db.tls_verify)" ] ||
    [ "$CX_DB_CLIENT_CERT" != "$(cx_rs_get db.tls_client_cert)" ]; then
    cx_rs_ext_item rs_ext_tls_lower "$CX_DB_TLS_VERIFY/$CX_DB_TLS_TRUST" "$(cx_rs_get db.tls_verify)/$(cx_rs_get db.tls_trust)"
    ok=1
  fi
  CX_RS_EXT_CA_DEST=""
  if [ "$CX_DB_TLS_TRUST" = file ]; then
    if ! CX_RS_EXT_CA_DEST=$(cx_db_host_path "$CX_DB_CA_ENV"); then
      CX_RS_EXT_CA_DEST=""
      cx_rs_ext_item pb_ext_dep_ca "$CX_DB_CA_ENV"
      ok=1
    elif [ -e "$CX_RS_EXT_CA_DEST" ] && ! cmp -s "$CX_RS_DIR/pass2/db-ca.pem" "$CX_RS_EXT_CA_DEST"; then
      cx_rs_ext_item rs_ext_ca_conflict "$CX_RS_EXT_CA_DEST"
      ok=1
    else
      CX_DB_CA_HOST=$CX_RS_DIR/pass2/db-ca.pem
    fi
  fi
  CX_RS_EXT_CERT_SRC="" CX_RS_EXT_CERT_DEST="" CX_RS_EXT_KEY_SRC="" CX_RS_EXT_KEY_DEST=""
  [ "$CX_DB_CLIENT_CERT" = true ] || return "$ok"
  cert=$(cx_bk_env PGSSLCERT) key=$(cx_bk_env PGSSLKEY)
  if [ -n "$cert" ]; then
    CX_RS_EXT_CERT_DEST=$(cx_db_host_path "$cert") || CX_RS_EXT_CERT_DEST=""
    if cx_rs_ext_file "$CX_RS_DB_CLIENT_CERT" "$CX_RS_EXT_CERT_DEST" rs_ext_ask_cert; then
      CX_RS_EXT_CERT_SRC=$CX_RS_EXT_FILE CX_DB_CERT_HOST=$CX_RS_EXT_FILE
    else
      # One reason for both files: the key is not asked for when the certificate is missing.
      return 1
    fi
  fi
  if [ -n "$key" ] && [ "$key_kept" = 1 ]; then
    CX_RS_EXT_KEY_DEST=$(cx_db_host_path "$key") || CX_RS_EXT_KEY_DEST=""
    if cx_rs_ext_file "$CX_RS_DB_CLIENT_KEY" "$CX_RS_EXT_KEY_DEST" rs_ext_ask_key; then
      CX_RS_EXT_KEY_SRC=$CX_RS_EXT_FILE CX_DB_KEY_HOST=$CX_RS_EXT_FILE
    else
      ok=1
    fi
  fi
  return "$ok"
}

# cx_rs_ext_activity: CX_RS_EXT_CONNS, the other connections to the database now (client
# backends, this query's own excluded), with their sources and application names. Fails when the
# query fails.
cx_rs_ext_activity() {
  local rows addr app n=0 sep
  local -A from=() apps=()
  local -a fl=() al=()
  rows=$(cx_dbx_rows "SELECT coalesce(host(client_addr), ''), encode(convert_to(application_name, 'UTF8'), 'hex')
FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
  AND backend_type = 'client backend' ORDER BY 1, 2") || return 1
  while IFS='|' read -r addr app; do
    [ -n "$addr$app" ] || continue
    n=$((n + 1))
    [ -n "$addr" ] || addr=$(cx_msg rs_ext_from_local)
    [ -n "${from[$addr]+x}" ] || { from[$addr]=1; fl+=("$addr"); }
    if [[ $app =~ ^([0-9a-f]{2})*$ ]]; then app=$(cx_dbx_unhex "$app" | tr -d '\000-\037\177'); else app=""; fi
    [ -n "$app" ] || app='""'
    [ -n "${apps[$app]+x}" ] || { apps[$app]=1; al+=("$app"); }
  done <<<"$rows"
  sep=$(cx_msg bk_item_sep)
  CX_RS_EXT_CONNS=$n CX_RS_EXT_FROM="" CX_RS_EXT_APPS=""
  if [ "$n" -gt 0 ]; then
    CX_RS_EXT_FROM=$(cx_join "$sep" "${fl[@]}")
    CX_RS_EXT_APPS=$(cx_join "$sep" "${al[@]}")
  fi
  cx_log CHECK "external database other connections=$n"
}

# cx_rs_ext_conns_item: the reason for the other connections found by cx_rs_ext_activity.
cx_rs_ext_conns_item() {
  if [ "$CX_RS_EXT_CONNS" -eq 1 ]; then
    cx_rs_ext_item rs_ext_conns_one "$(cx_rs_get db.name)" "$CX_RS_EXT_FROM" "$CX_RS_EXT_APPS"
  else
    cx_rs_ext_item rs_ext_conns "$CX_RS_EXT_CONNS" "$(cx_rs_get db.name)" "$CX_RS_EXT_FROM" "$CX_RS_EXT_APPS"
  fi
}

# cx_rs_ext_grantees <file>: the role names a dump's grant statements name (grantees, grantors,
# the role of default privileges), one per line, unquoted. A statement this does not read leaves
# its roles to the backup's own list of roles.
cx_rs_ext_grantees() {
  awk '
  function emit(r) {
    gsub(/^ +| +$/, "", r)
    if (r ~ /^GROUP /) r = substr(r, 7)
    if (r ~ /^".*"$/) { r = substr(r, 2, length(r) - 2); gsub(/""/, "\"", r) }
    if (r != "") print r
  }
  # the position after the last keyword kw outside double quotes in s (0 when none)
  function after(s, kw,   i, q, n, k, at) {
    n = length(s); k = length(kw); q = 0; at = 0
    for (i = 1; i <= n; i++) {
      if (substr(s, i, 1) == "\"") { q = !q; continue }
      if (!q && substr(s, i, k) == kw) at = i + k
    }
    return at
  }
  # the position of the first keyword kw outside double quotes in s (0 when none)
  function first(s, kw,   i, q, n, k) {
    n = length(s); k = length(kw); q = 0
    for (i = 1; i <= n; i++) {
      if (substr(s, i, 1) == "\"") { q = !q; continue }
      if (!q && substr(s, i, k) == kw) return i
    }
    return 0
  }
  function list(s,   i, q, n, c, cur) {
    n = length(s); q = 0; cur = ""
    for (i = 1; i <= n; i++) {
      c = substr(s, i, 1)
      if (c == "\"") q = !q
      if (c == "," && !q) { emit(cur); cur = ""; continue }
      cur = cur c
    }
    emit(cur)
  }
  /^(GRANT|REVOKE|ALTER DEFAULT PRIVILEGES) / {
    s = $0
    sub(/;[ \t]*$/, "", s)
    if (s ~ /^ALTER DEFAULT PRIVILEGES FOR ROLE /) {
      r = substr(s, 35); p = first(r, " ")
      emit(p ? substr(r, 1, p - 1) : r)
    }
    p = after(s, " TO "); f = after(s, " FROM ")
    if (f > p) p = f
    if (!p) next
    t = substr(s, p)
    g = first(t, " GRANTED BY ")
    if (g) { emit(substr(t, g + 12)); t = substr(t, 1, g - 1) }
    w = first(t, " WITH GRANT OPTION"); if (w) t = substr(t, 1, w - 1)
    w = first(t, " CASCADE"); if (w) t = substr(t, 1, w - 1)
    w = first(t, " RESTRICT"); if (w) t = substr(t, 1, w - 1)
    list(t)
  }' "$1"
}

# cx_rs_ext_roles: CX_RS_EXT_MISSING, the roles (hex) the backup grants rights to that the server
# lacks: the backup's recorded roles and those its dump names, less DB_USER, PUBLIC and pg_*.
# Returns 1 when the server cannot be asked, 3 when the dump cannot be read.
cx_rs_ext_roles() {
  local h r rows in="" user
  local -A want=()
  user=$(cx_dbx_hex "$(cx_rs_get db.user)")
  for h in $(cx_rs_get db.extra_grant_roles_hex); do want[$h]=1; done
  (set -o pipefail; cx_rs_member_stream db.dump | cx_rs_grant_tool "$CX_DB_EXT_ID" -l) \
    >"$CX_RS_DIR/toc" 2>"$CX_RS_DIR/pg.err" || return 3
  sed -n '/ ACL /p' "$CX_RS_DIR/toc" >"$CX_RS_DIR/acl"
  if [ -s "$CX_RS_DIR/acl" ]; then
    (set -o pipefail; cx_rs_member_stream db.dump | cx_rs_grant_tool "$CX_DB_EXT_ID" -L /w/acl -f -) \
      >"$CX_RS_DIR/grants" 2>"$CX_RS_DIR/pg.err" || return 3
    while IFS= read -r r; do
      case $r in PUBLIC | pg_*) continue ;; esac
      want[$(cx_dbx_hex "$r")]=1
    done < <(cx_rs_ext_grantees "$CX_RS_DIR/grants")
  fi
  unset 'want[$user]'
  for h in "${!want[@]}"; do
    [[ $h =~ ^([0-9a-f]{2})+$ && $h != 70675f* ]] || { unset 'want[$h]'; continue; }
    in+="${in:+, }'$h'"
  done
  CX_RS_EXT_MISSING=""
  [ -n "$in" ] || return 0
  rows=$(cx_dbx_rows "SELECT encode(convert_to(rolname, 'UTF8'), 'hex') FROM pg_roles
WHERE encode(convert_to(rolname, 'UTF8'), 'hex') IN ($in) ORDER BY 1") || return 1
  while IFS= read -r h; do [ -z "$h" ] || unset 'want[$h]'; done <<<"$rows"
  [ "${#want[@]}" -eq 0 ] || CX_RS_EXT_MISSING=$(cx_dbx_hex_list "${!want[@]}")
  cx_log CHECK "external database missing roles=${CX_RS_EXT_MISSING:-none}"
}

# cx_rs_ext_database: ownership, extensions, encoding, other connections and emptiness of the
# database, through the client of the server's major. Returns 2 when a query fails.
cx_rs_ext_database() {
  local rows a b c n=0 user enc
  local -a ext=()
  user=$(cx_rs_get db.user)
  cx_rs_ext_activity || return 2
  # This host's own backend is still connected: listed for the preview, checked once it stopped.
  [ "$CX_RS_FLOW" = same ] || [ "$CX_RS_EXT_CONNS" -eq 0 ] || cx_rs_ext_conns_item
  rows=$(cx_dbx_rows "SELECT pg_get_userbyid(datdba) = current_user FROM pg_database WHERE datname = current_database()") || return 2
  [ "$rows" = t ] || cx_rs_ext_item rs_ext_not_owner "$user" "$(cx_rs_get db.name)"
  # The objects an extension made are named once, as that extension (below), not one by one.
  rows=$(cx_dbx_rows "WITH x AS (SELECT classid, objid FROM pg_depend WHERE deptype = 'e'), o AS (
  SELECT n.nspname AS s, '' AS name, n.nspowner AS own FROM pg_namespace n WHERE $CX_DBX_SYS_SCHEMAS
    AND NOT (n.nspname = 'public' AND n.nspowner = 'pg_database_owner'::regrole)
  UNION ALL SELECT n.nspname, c.relname, c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE $CX_DBX_SYS_SCHEMAS
    AND ('pg_class'::regclass::oid, c.oid) NOT IN (SELECT classid, objid FROM x)
  UNION ALL SELECT n.nspname, p.proname, p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE $CX_DBX_SYS_SCHEMAS
    AND ('pg_proc'::regclass::oid, p.oid) NOT IN (SELECT classid, objid FROM x)
  UNION ALL SELECT n.nspname, t.typname, t.typowner FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE $CX_DBX_SYS_SCHEMAS
    AND ('pg_type'::regclass::oid, t.oid) NOT IN (SELECT classid, objid FROM x)
    AND t.typrelid = 0 AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid))
SELECT encode(convert_to(s, 'UTF8'), 'hex'), encode(convert_to(name, 'UTF8'), 'hex'),
  encode(convert_to(pg_get_userbyid(own), 'UTF8'), 'hex') AS obj_owner
FROM o WHERE own <> (SELECT oid FROM pg_roles WHERE rolname = current_user) ORDER BY 1, 2 LIMIT 11") || return 2
  while IFS='|' read -r a b c; do
    [ -n "$a" ] || continue
    n=$((n + 1))
    if [ "$n" -gt 10 ]; then cx_rs_ext_item rs_ext_owner_more "$user"; break; fi
    a=$(cx_dbx_show_name "$a")
    [ -z "$b" ] || a+=.$(cx_dbx_show_name "$b")
    cx_rs_ext_item rs_ext_owner "$a" "$(cx_dbx_show_name "$c")" "$user" "$user"
  done <<<"$rows"
  rows=$(cx_dbx_rows "SELECT extname || ' ' || extversion FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1") || return 2
  if [ -n "$rows" ]; then
    mapfile -t ext <<<"$rows"
    cx_rs_ext_item rs_ext_extension "$(cx_join "$(cx_msg bk_item_sep)" "${ext[@]}")"
  fi
  rows=$(cx_dbx_rows "SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = current_database()") || return 2
  enc="$(cx_rs_get db.encoding)|$(cx_rs_get db.collate)|$(cx_rs_get db.ctype)"
  [ "$rows" = "$enc" ] || cx_rs_ext_item rs_ext_encoding "$(cx_rs_get db.encoding)" "$(cx_rs_get db.collate)" "$(cx_rs_get db.ctype)"
  rows=$(cx_dbx_rows "WITH o AS (SELECT c.relnamespace AS ns FROM pg_class c
  UNION ALL SELECT p.pronamespace FROM pg_proc p
  UNION ALL SELECT t.typnamespace FROM pg_type t WHERE t.typrelid = 0
    AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid))
SELECT encode(convert_to(n.nspname, 'UTF8'), 'hex'), count(*) AS obj_count FROM o JOIN pg_namespace n ON n.oid = o.ns
WHERE $CX_DBX_SYS_SCHEMAS GROUP BY 1 ORDER BY 1") || return 2
  CX_RS_EXT_OBJECTS=$rows
  CX_RS_EXT_EMPTY=1
  [ -z "$rows" ] || CX_RS_EXT_EMPTY=0
}

# cx_rs_ext_server: the client, the connection and the server's version. Returns 1 with the reason
# recorded when no further check can be made.
cx_rs_ext_server() {
  local top dump
  cx_rs_ext_clients || return 1
  top=${CX_RS_EXT_MAJORS##* }
  if [ -z "$top" ] || ! cx_dbx_present "$top"; then
    cx_rs_ext_item rs_ext_no_image "${top:-?}" "$CX_RS_ENGINE"
    return 1
  fi
  cx_dbx_use "$top"
  if ! cx_dbx_system_ca; then
    CX_RS_EXT_ITEMS+=("${CX_DBX_ITEMS[@]}")
    return 1
  fi
  if ! cx_dbx_version; then
    cx_rs_ext_item rs_ext_unreachable "$(cx_bk_env EXTERNAL_DB_HOST):$(cx_rs_get db.external_port)" "$CX_LOG_FILE"
    return 1
  fi
  CX_RS_EXT_SERVER=$CX_DBX_SERVER CX_RS_EXT_MAJOR=$CX_DBX_SERVER_MAJOR
  if [[ " $CX_RS_EXT_MAJORS " != *" $CX_RS_EXT_MAJOR "* ]]; then
    cx_rs_ext_item rs_ext_no_client "$CX_RS_EXT_SERVER" "$(cx_rs_ext_majors_shown)"
    return 1
  fi
  if ! cx_dbx_present "$CX_RS_EXT_MAJOR"; then
    cx_rs_ext_item rs_ext_no_image "$CX_RS_EXT_MAJOR" "$CX_RS_ENGINE"
    return 1
  fi
  if [ "$CX_RS_EXT_MAJOR" -lt "$(cx_rs_get db.server_major)" ]; then
    cx_rs_ext_item rs_ext_server_old "$CX_RS_EXT_SERVER" "$(cx_rs_get db.server_major)"
    return 1
  fi
  dump=$(cx_rs_get db.dump_tool_version | grep -oE '[0-9]+' | head -n 1) || dump=""
  if [[ $dump =~ ^[0-9]+$ ]] && [ "$CX_RS_EXT_MAJOR" -lt "$dump" ]; then
    cx_rs_ext_item rs_ext_client_old "$CX_RS_EXT_MAJOR" "$(cx_rs_get db.dump_tool_version)"
    return 1
  fi
  cx_dbx_use "$CX_RS_EXT_MAJOR"
  if ! cx_dbx_system_ca; then
    CX_RS_EXT_ITEMS+=("${CX_DBX_ITEMS[@]}")
    return 1
  fi
}

# cx_rs_ext_reasons: the reasons found, each "  - <text>", later lines of one under its text.
cx_rs_ext_reasons() {
  local item key text
  local -a args=()
  for item in "${CX_RS_EXT_ITEMS[@]}"; do
    key=${item%% *}
    args=()
    [ "$key" = "$item" ] || IFS=$'\t' read -r -a args <<<"${item#* }"
    text=$(cx_msg "$key" "${args[@]+"${args[@]}"}")
    printf '  - %s\n' "${text//$'\n'/$'\n'    }"
  done
}

# cx_rs_ext_roles_refuse: the roles the server lacks; the restore cannot go on without them.
cx_rs_ext_roles_refuse() {
  local h shown="" sep n=0
  sep=$(cx_msg bk_item_sep)
  for h in $CX_RS_EXT_MISSING; do
    shown+="${shown:+$sep}$(cx_dbx_show_name "$h")"
    n=$((n + 1))
  done
  if [ "$n" = 1 ]; then cx_line FAIL "$(cx_msg rs_ext_roles_missing_one "$shown")"
  else cx_line FAIL "$(cx_msg rs_ext_roles_missing "$n" "$shown")"; fi
  cx_rs_unchanged
}

# cx_rs_ext_grants_filter <grants SQL> <missing roles> <kept SQL> <skipped>: the grant SQL a dump
# prints (pg_restore -L <grant entries> -f), without the statements that grant or revoke rights to
# a role the server lacks (one name per line in <missing roles>); those go to <skipped>. Read
# strictly, one statement per line: comments, blank lines, the \restrict and \unrestrict lines that
# wrap pg_restore's output (kept as they are), its SET and set_config lines, and GRANT, REVOKE and
# ALTER DEFAULT PRIVILEGES statements whose grantee list reads fully. A statement naming a missing
# role and another one, or a line read any other way, means the statements to skip cannot be told
# apart for certain: exit 3, with the line number on standard error. Prints the number skipped.
cx_rs_ext_grants_filter() {
  LC_ALL=C awk -v missing="$2" -v kept="$3" -v skipped="$4" '
  BEGIN {
    while ((getline r < missing) > 0) if (r != "") gone[r] = 1
    printf "" > kept; printf "" > skipped
  }
  function fail() { printf "grant statement %d cannot be read for certain\n", NR > "/dev/stderr"; bad = 1; exit 3 }
  # a role name as written: PUBLIC, a plain lower-case name, or a double-quoted one ("" inside)
  function role(t,   r) {
    if (t == "PUBLIC") return "\001PUBLIC"
    if (t ~ /^[a-z_][a-z0-9_$]*$/) return t
    if (t ~ /^"([^"]|"")+"$/) { r = substr(t, 2, length(t) - 2); gsub(/""/, "\"", r); return r }
    fail()
  }
  # the position after the last keyword kw outside double quotes in s (0 when none)
  function after(s, kw,   i, q, n, k, at) {
    n = length(s); k = length(kw); q = 0; at = 0
    for (i = 1; i <= n; i++) {
      if (substr(s, i, 1) == "\"") { q = !q; continue }
      if (!q && substr(s, i, k) == kw) at = i + k
    }
    return at
  }
  # the grantees of list s into g[1..n], n returned; a list not read fully fails
  function grantees(s, g,   i, n, c, q, cur) {
    n = 0; q = 0; cur = ""
    for (i = 1; i <= length(s); i++) {
      c = substr(s, i, 1)
      if (c == "\"") q = !q
      if (c == "," && !q) {
        g[++n] = role(cur)
        if (substr(s, i + 1, 1) != " ") fail()
        i++; cur = ""; continue
      }
      cur = cur c
    }
    g[++n] = role(cur)
    return n
  }
  /^$/ || /^--/ || /^\\(un)?restrict [A-Za-z0-9]+$/ { print > kept; next }
  /^SET [a-z_]+ = [^;]*;$/ || /^SELECT pg_catalog\.set_config\(.search_path., .., false\);$/ { print > kept; next }
  {
    s = $0
    if (s !~ /;$/ || gsub(/"/, "\"", s) % 2) fail()
    s = substr(s, 1, length(s) - 1)
    owner = ""
    if (s ~ /^ALTER DEFAULT PRIVILEGES FOR ROLE /) {
      t = substr(s, 35)
      if (t ~ /^"/) { p = index(substr(t, 2), "\" "); if (!p) fail(); owner = role(substr(t, 1, p + 1)); t = substr(t, p + 3) }
      else { p = index(t, " "); if (!p) fail(); owner = role(substr(t, 1, p - 1)); t = substr(t, p + 1) }
      if (t ~ /^IN SCHEMA /) { t = substr(t, 11); if (t ~ /^"/) { p = index(substr(t, 2), "\" "); if (!p) fail(); t = substr(t, p + 3) } else { p = index(t, " "); if (!p) fail(); t = substr(t, p + 1) } }
      s = t
    }
    if (s ~ /^GRANT /) { p = after(s, " TO "); w = " WITH GRANT OPTION" }
    else if (s ~ /^REVOKE /) { p = after(s, " FROM "); w = "" }
    else fail()
    if (!p) fail()
    t = substr(s, p)
    if (w != "" && substr(t, length(t) - length(w) + 1) == w) t = substr(t, 1, length(t) - length(w))
    n = grantees(t, g); m = 0; o = 0
    for (i = 1; i <= n; i++) if (g[i] in gone) m++; else o++
    fo = (owner != "" && owner in gone)
    if (!m && !fo) { print > kept; next }
    if (m && !o) { print > skipped; count++; next }
    fail()
  }
  END { if (!bad) print count + 0 }' "$1"
}

# cx_rs_ext_roles_choose: roles the server lacks (CX_RS_EXT_MISSING). Without a terminal (or with
# --yes) they refuse unless --accept-grant-loss; at a terminal the user chooses to create them first
# (the default: the restore ends, nothing changed) or to skip their grants. Skipping needs the grant
# statements told apart for certain (cx_rs_ext_grants_filter); otherwise the roles must be created.
# Sets CX_RS_EXT_SKIPPED, the number of grant statements left out, or "" when nothing is skipped.
CX_RS_EXT_SKIPPED="" CX_RS_ACCEPT_GRANT_LOSS=${CX_RS_ACCEPT_GRANT_LOSS:-0}
cx_rs_ext_roles_choose() {
  local h shown="" n=0 answer count
  CX_RS_EXT_SKIPPED=""
  [ -n "$CX_RS_EXT_MISSING" ] || return 0
  if [ "$CX_RS_ACCEPT_GRANT_LOSS" != 1 ]; then
    if [ "${CX_YES:-0}" = 1 ] || [ ! -t 0 ]; then
      cx_rs_ext_roles_refuse
      return 1
    fi
    for h in $CX_RS_EXT_MISSING; do
      shown+="${shown:+$'\n'}  $(cx_dbx_show_name "$h")"
      n=$((n + 1))
    done
    if [ "$n" = 1 ]; then
      cx_line ASK "$(cx_msg rs_ext_roles_ask_one "$shown")"
      printf '\n'
      cx_rs_par "$(cx_msg rs_ext_roles_create_one)"
      cx_rs_par "$(cx_msg rs_ext_roles_skip_one)"
    else
      cx_line ASK "$(cx_msg rs_ext_roles_ask "$n" "$shown")"
      printf '\n'
      cx_rs_par "$(cx_msg rs_ext_roles_create)"
      cx_rs_par "$(cx_msg rs_ext_roles_skip)"
    fi
    printf '\n'
    while :; do
      printf '%s' "$(cx_msg pb_choose)"
      IFS= read -r answer || answer=1
      case $answer in
        '' | 1) cx_log CHECK "external database missing roles: create them first"; cx_rs_unchanged; return 1 ;;
        2) break ;;
      esac
    done
  fi
  for h in $CX_RS_EXT_MISSING; do cx_dbx_unhex "$h"; printf '\n'; done >"$CX_RS_DIR/missing-roles"
  [ -e "$CX_RS_DIR/grants" ] || : >"$CX_RS_DIR/grants"
  if ! count=$(cx_rs_ext_grants_filter "$CX_RS_DIR/grants" "$CX_RS_DIR/missing-roles" \
    "$CX_RS_DIR/grants.kept" "$CX_RS_DIR/skipped-grants.txt" 2>>"$CX_LOG_FILE"); then
    cx_log FAIL "external database: grants to the missing roles cannot be told apart"
    cx_line FAIL "$(cx_msg rs_ext_grants_unsure)"
    cx_rs_unchanged
    return 1
  fi
  CX_RS_EXT_SKIPPED=$count
  cx_log CHECK "external database grants to missing roles skipped=$count"
}

# cx_rs_ext_preview_skip: the preview's line for the grants left out.
cx_rs_ext_preview_skip() {
  local n
  [ -n "$CX_RS_EXT_SKIPPED" ] || return 0
  n=$(wc -w <<<"$CX_RS_EXT_MISSING" | tr -d ' ')
  if [ "$n" = 1 ]; then cx_rs_row skipped "$(cx_msg rs_ext_skipped_row_one)"
  else cx_rs_row skipped "$(cx_msg rs_ext_skipped_row "$n")"; fi
}

cx_rs_ext_checks() {
  local rc=0 key
  CX_RS_EXT_ITEMS=() CX_DBX_ITEMS=() CX_RS_EXT_MISSING="" CX_RS_EXT_EMPTY="" CX_RS_EXT_OBJECTS=""
  CX_RS_EXT_CONNS=0 CX_RS_EXT_FROM="" CX_RS_EXT_APPS="" CX_RS_EXT_MAJOR="" CX_RS_EXT_SERVER=""
  cx_rs_ext_tls || true
  if [ "${#CX_RS_EXT_ITEMS[@]}" -eq 0 ] && cx_rs_ext_server; then
    cx_rs_ext_database || rc=$?
    if [ "$rc" = 0 ] && [ "${#CX_RS_EXT_ITEMS[@]}" -eq 0 ]; then cx_rs_ext_roles || rc=$?; fi
    if [ "$rc" = 3 ]; then
      cx_rs_bad grants_read
      return 1
    fi
    if [ "$rc" != 0 ]; then
      CX_RS_EXT_ITEMS=()
      cx_rs_ext_item rs_ext_unreachable "$(cx_bk_env EXTERNAL_DB_HOST):$(cx_rs_get db.external_port)" "$CX_LOG_FILE"
    fi
  fi
  if [ "${#CX_RS_EXT_ITEMS[@]}" -gt 0 ]; then
    for key in "${CX_RS_EXT_ITEMS[@]}"; do cx_log FAIL "external database: ${key%% *}"; done
    cx_line FAIL "$(cx_msg rs_ext_refused)"
    cx_rs_ext_reasons
    cx_rs_unchanged
    return 1
  fi
  cx_rs_ext_roles_choose || return 1
  cx_log CHECK "external database checked: server=$CX_RS_EXT_SERVER client=pgclient$CX_RS_EXT_MAJOR empty=$CX_RS_EXT_EMPTY other_connections=$CX_RS_EXT_CONNS"
}

# cx_rs_external: the checks of an external database, before the preview. Nothing to do for a
# bundled one.
cx_rs_external() {
  cx_rs_ext || return 0
  cx_rs_ext_with cx_rs_ext_checks
}

# cx_rs_ext_quiet <step> <steps> <label key>: no other connection to the external database now
# (after the services of this host stopped, and again before anything is overwritten). When there
# is one: the step's failure, where the restore stopped, and the two ways on; returns 1. Returns 2
# when the database cannot be asked.
cx_rs_ext_quiet() {
  local step=$1 steps=$2 label=$3 reason pos text pad
  cx_rs_ext_with cx_rs_ext_quiet_ask || return 2
  [ "$CX_RS_EXT_CONNS" -gt 0 ] || return 0
  if [ "$CX_RS_EXT_CONNS" -eq 1 ]; then
    reason=$(cx_msg rs_ext_still_one "$(cx_rs_get db.name)" "$CX_RS_EXT_FROM" "$CX_RS_EXT_APPS")
  else
    reason=$(cx_msg rs_ext_still "$CX_RS_EXT_CONNS" "$(cx_rs_get db.name)" "$CX_RS_EXT_FROM" "$CX_RS_EXT_APPS")
  fi
  # The step number right-aligned to the steps' width; later lines of the text under its start.
  pos=$(printf '%*s/%s' "${#steps}" "$step" "$steps")
  pad=$(printf '%*s' $((7 + ${#pos} + 2)) '')
  text="$(cx_msg "$label")$reason"
  printf '%s %s  %s\n' "$(cx_mark FAIL)" "$pos" "${text//$'\n'/$'\n'$pad}"
  printf '%s\n' "$(cx_msg rs_ext_stopped_at "$step")"
  cx_rs_par "$(cx_msg rs_ext_end_conn)"
  cx_cmd "$(cx_rs_control_command resume)"
  cx_rs_par "$(cx_msg rs_safety_revert)"
  cx_cmd "$(cx_rs_control_command revert)"
  CX_RS_EXT_HELD=1
  return 1
}
cx_rs_ext_quiet_ask() {
  CX_RS_EXT_ITEMS=()
  cx_rs_ext_tls >/dev/null </dev/null || return 1
  cx_rs_ext_clients || return 1
  [ -n "$CX_RS_EXT_MAJOR" ] || CX_RS_EXT_MAJOR=$(cx_rs_get db.server_major)
  cx_dbx_present "$CX_RS_EXT_MAJOR" || return 1
  cx_dbx_use "$CX_RS_EXT_MAJOR"
  cx_rs_ext_activity
}

# cx_rs_ext_place: after the confirmation, the files the connection needs where the deployment's
# settings name them: the backup's CA file, and the client certificate and key the user named
# (0600). The key never passes through the work folder or the log.
cx_rs_ext_place() {
  local i
  local -a src=("$CX_RS_DIR/pass2/db-ca.pem" "$CX_RS_EXT_CERT_SRC" "$CX_RS_EXT_KEY_SRC")
  local -a dest=("$CX_RS_EXT_CA_DEST" "$CX_RS_EXT_CERT_DEST" "$CX_RS_EXT_KEY_DEST")
  for i in 0 1 2; do
    if [ -z "${dest[i]}" ] || [ -z "${src[i]}" ] || [ "${src[i]}" = "${dest[i]}" ] || [ ! -f "${src[i]}" ]; then continue; fi
    (umask 077 && mkdir -p "${dest[i]%/*}") || return 1
    install -m 0600 -- "${src[i]}" "${dest[i]}" || return 1
    cx_log CHECK "placed ${dest[i]}"
  done
}
