# shellcheck shell=bash
# CX_DB_* are read by lib/dbext.sh, lib/portable.sh and lib/backup_manifest.sh.
# shellcheck disable=SC2034
# The one way into the database: every query, the dump, its listing and the dump tool's version.
# A bundled database is reached in its compose service (docker compose exec postgres). An external
# database is reached by a PostgreSQL client container of the release (a tool image, chosen by
# lib/dbext.sh into CX_DB_EXT_ID); until one is chosen a call stops with an error instead of
# reaching for the bundled service.
# CX_DB_ACTION names the action in the docker client's environment, so a trace of the docker calls
# (and the tests) can tell which action each one belongs to.
#
# The client container of an external database:
#   - the password reaches it in a pgpass file (0600, in a private folder, removed after the call
#     and on an interruption), never as an argument or an environment variable;
#   - its environment holds only PGPASSFILE and HOME, which points at an empty tmpfs, so libpq
#     loads no root certificate the connection settings do not name;
#   - the connection settings are one conninfo argument: host, port, database, user, sslmode and
#     the certificate paths inside the container (cx_db_tls_read);
#   - host network: the address is reached the way this host reaches it; no log of its output.

# cx_db_external: the deployment's overlays (CX_OVERLAYS) include the external database.
cx_db_external() { [[ " ${CX_OVERLAYS:-} " == *" external-database "* ]]; }

# The client image (an image ID) and its major version; set by lib/dbext.sh.
CX_DB_EXT_ID="" CX_DB_EXT_MAJOR=""
# The TLS settings as the backend reads them, for the client (cx_db_tls_read).
CX_DB_SSLMODE_RAW="" CX_DB_SSLMODE="" CX_DB_SSLMODE_BY_SYSTEM=0 CX_DB_TLS_TRUST="" CX_DB_TLS_VERIFY=""
CX_DB_ROOTCERT="" CX_DB_CA_ENV="" CX_DB_CA_HOST="" CX_DB_CERT_HOST="" CX_DB_KEY_HOST=""
CX_DB_CLIENT_CERT=false
declare -ga CX_DB_TLS_ITEMS=() # unsupported TLS settings: "<message key> [argument]" per item
CX_DB_PGPASS="" # the pgpass file while a call runs

readonly CX_DB_SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
readonly CX_DB_CTR_PGPASS=/cx/pgpass CX_DB_CTR_HOME=/cx/home CX_DB_CTR_TLS=/cx/tls
readonly CX_DB_CONNECT_TIMEOUT=10

# cx_db_ready: a database call can be made now (bundled, or an external client was chosen).
cx_db_ready() { ! cx_db_external || [ -n "$CX_DB_EXT_ID" ]; }

# cx_db_host_path <path in the backend container>: the path on this host, for a path under one of
# the backend's mounts (audit, recordings, exports under DATA_PATH). Fails for any other path, a
# relative one, or one with a .. part.
cx_db_host_path() {
  local p=$1 m
  [[ $p == /* && /$p/ != */../* ]] || return 1
  for m in /var/log/custodexa/audit:audit /var/lib/custodexa/recordings:recordings \
    /var/lib/custodexa/exports:exports; do
    case $p in
      "${m%%:*}"/*) printf '%s/%s%s' "$CX_BK_DATA" "${m#*:}" "${p#"${m%%:*}"}"; return 0 ;;
    esac
  done
  return 1
}

# cx_db_host_file <.env key>: CX_DB_HOST_FILE, the file on this host the key names; fails when it
# is not under a backend mount or not a readable regular file.
CX_DB_HOST_FILE=""
cx_db_host_file() {
  CX_DB_HOST_FILE=$(cx_db_host_path "$(cx_bk_env "$1")") || return 1
  [ -f "$CX_DB_HOST_FILE" ] && [ -r "$CX_DB_HOST_FILE" ]
}

# cx_db_tls_read: the TLS settings of .env as the backend applies them (DB_SSLMODE, empty or
# unset is disable; PGSSLROOTCERT=system makes it verify-full), mapped to what the client is given
# so it checks the server exactly as much as the backend does:
#   CX_DB_TLS_TRUST   none | system | file      where the trust anchor comes from
#   CX_DB_TLS_VERIFY  none | ca | full          how much of the server certificate is checked
#   CX_DB_ROOTCERT    the client's sslrootcert ("" when it must load no root certificate)
# A setting the client cannot follow is listed in CX_DB_TLS_ITEMS (refused before any stop).
cx_db_tls_read() {
  local root
  CX_DB_TLS_ITEMS=() CX_DB_CA_HOST="" CX_DB_CERT_HOST="" CX_DB_KEY_HOST="" CX_DB_ROOTCERT=""
  CX_DB_SSLMODE_BY_SYSTEM=0 CX_DB_CLIENT_CERT=false
  CX_DB_SSLMODE_RAW=$(cx_bk_env DB_SSLMODE)
  CX_DB_SSLMODE=${CX_DB_SSLMODE_RAW:-disable}
  root=$(cx_bk_env PGSSLROOTCERT)
  CX_DB_CA_ENV=$root
  CX_DB_TLS_TRUST=none CX_DB_TLS_VERIFY=none
  if [ "$root" = system ]; then
    [ "$CX_DB_SSLMODE" = verify-full ] || CX_DB_SSLMODE_BY_SYSTEM=1
    CX_DB_SSLMODE=verify-full CX_DB_TLS_TRUST=system CX_DB_TLS_VERIFY=full CX_DB_ROOTCERT=system
  elif [ -z "$root" ]; then
    case $CX_DB_SSLMODE in
      verify-full) CX_DB_TLS_TRUST=system CX_DB_TLS_VERIFY=full CX_DB_ROOTCERT=system ;;
      verify-ca) CX_DB_TLS_TRUST=system CX_DB_TLS_VERIFY=ca CX_DB_ROOTCERT=$CX_DB_SYSTEM_CA ;;
    esac
  else
    CX_DB_TLS_TRUST='file'
    if cx_db_host_file PGSSLROOTCERT; then
      CX_DB_CA_HOST=$CX_DB_HOST_FILE
    else
      CX_DB_TLS_ITEMS+=("pb_ext_dep_ca $root")
    fi
    case $CX_DB_SSLMODE in
      require | verify-ca) CX_DB_TLS_VERIFY=ca CX_DB_ROOTCERT=$CX_DB_CTR_TLS/root.crt ;;
      verify-full) CX_DB_TLS_VERIFY=full CX_DB_ROOTCERT=$CX_DB_CTR_TLS/root.crt ;;
    esac
  fi
  cx_db_tls_client
  cx_log CHECK "database tls sslmode=${CX_DB_SSLMODE_RAW:-unset} effective=$CX_DB_SSLMODE trust=$CX_DB_TLS_TRUST verify=$CX_DB_TLS_VERIFY client_cert=$CX_DB_CLIENT_CERT"
}

# cx_db_tls_client: the client certificate and key (PGSSLCERT, PGSSLKEY), mounted for the client.
# The key never goes into the backup file, so a key in a folder the backup packs is refused.
cx_db_tls_client() {
  local cert key
  cert=$(cx_bk_env PGSSLCERT) key=$(cx_bk_env PGSSLKEY)
  [ -n "$cert$key" ] || return 0
  CX_DB_CLIENT_CERT=true
  if [ -n "$cert" ]; then
    if cx_db_host_file PGSSLCERT; then CX_DB_CERT_HOST=$CX_DB_HOST_FILE; else CX_DB_TLS_ITEMS+=("pb_ext_dep_cert $cert"); fi
  fi
  [ -n "$key" ] || return 0
  case $key in
    /var/log/custodexa/audit/*) CX_DB_TLS_ITEMS+=("pb_ext_dep_key") ;;
    /var/lib/custodexa/recordings/*) CX_DB_TLS_ITEMS+=("pb_ext_dep_key_rec") ;;
    *)
      if cx_db_host_file PGSSLKEY; then CX_DB_KEY_HOST=$CX_DB_HOST_FILE; else CX_DB_TLS_ITEMS+=("pb_ext_dep_keypath $key"); fi
      ;;
  esac
}

# cx_db_conn_value <text>: a conninfo value, single-quoted with \ and ' escaped.
cx_db_conn_value() {
  local v=${1//\\/\\\\}
  printf "'%s'" "${v//\'/\\\'}"
}

# cx_db_conninfo: the connection settings for the client, without the password.
cx_db_conninfo() {
  local port
  port=$(cx_bk_env EXTERNAL_DB_PORT)
  printf 'host=%s port=%s dbname=%s user=%s sslmode=%s connect_timeout=%s' \
    "$(cx_db_conn_value "$(cx_bk_env EXTERNAL_DB_HOST)")" "$(cx_db_conn_value "${port:-5432}")" \
    "$(cx_db_conn_value "$CX_BK_DBNAME")" "$(cx_db_conn_value "$CX_BK_DBUSER")" \
    "$(cx_db_conn_value "$CX_DB_SSLMODE")" "$CX_DB_CONNECT_TIMEOUT"
  [ -z "$CX_DB_ROOTCERT" ] || printf ' sslrootcert=%s' "$(cx_db_conn_value "$CX_DB_ROOTCERT")"
  [ -z "$CX_DB_CERT_HOST" ] || printf ' sslcert=%s' "$CX_DB_CTR_TLS/client.crt"
  [ -z "$CX_DB_KEY_HOST" ] || printf ' sslkey=%s' "$CX_DB_CTR_TLS/client.key"
}

# cx_db_pgpass_dir: where the pgpass file goes: the backup's temporary folder once it exists,
# before that a private folder next to it.
cx_db_pgpass_dir() {
  if [ -n "${CX_BK_DIR:-}" ] && [[ $CX_BK_DIR == */.partial-* ]] && [ -d "$CX_BK_DIR" ]; then
    printf '%s' "$CX_BK_DIR"
  else
    printf '%s/backups/.db-client-%s' "$CX_ROOT" "$$"
  fi
}

# cx_db_pgpass_write: CX_DB_PGPASS, a pgpass file (0600, in a 0700 folder) for DB_PASSWORD, with
# ":" and "\" escaped as the pgpass format wants. printf is a builtin: the password is in no
# process's arguments.
cx_db_pgpass_write() {
  local d pw
  d=$(cx_db_pgpass_dir)
  (umask 077 && mkdir -p "$CX_ROOT/backups" && mkdir -p "$d") || return 1
  chmod 0700 "$d" || return 1
  pw=$(cx_bk_env DB_PASSWORD)
  pw=${pw//\\/\\\\}
  pw=${pw//:/\\:}
  CX_DB_PGPASS=$d/.pgpass
  (umask 077 && printf '*:*:*:*:%s\n' "$pw" >"$CX_DB_PGPASS") || return 1
  chmod 0600 "$CX_DB_PGPASS"
}

# cx_db_pgpass_rm: remove the pgpass file, and its private folder when it had one. Safe to call
# at any time (an interruption calls it).
cx_db_pgpass_rm() {
  # Both places it can be: a call run in a subshell (a step's job) set CX_DB_PGPASS there only.
  [ -z "${CX_BK_DIR:-}" ] || rm -f -- "$CX_BK_DIR/.pgpass" 2>/dev/null || true
  if [ -n "${CX_ROOT:-}" ] && [ -d "$CX_ROOT/backups/.db-client-$$" ]; then
    rm -f -- "$CX_ROOT/backups/.db-client-$$/.pgpass" 2>/dev/null || true
    rmdir -- "$CX_ROOT/backups/.db-client-$$" 2>/dev/null || true
  fi
  [ -z "$CX_DB_PGPASS" ] || rm -f -- "$CX_DB_PGPASS" 2>/dev/null || true
  CX_DB_PGPASS=""
  return 0
}

# cx_db_ext_run <connect: 0|1> <tool> <arguments...>: the tool in the chosen client container.
# With connect=1 it gets the pgpass file, the certificate files and the host network; otherwise no
# network at all. stdin is passed on only to pg_restore.
cx_db_ext_run() {
  local connect=$1 tool=$2 rc=0
  shift 2
  local -a opts=(--rm --pull never --log-driver none --entrypoint "$tool" -e "HOME=$CX_DB_CTR_HOME"
    --tmpfs "$CX_DB_CTR_HOME")
  [ -z "${CX_BK_TS:-}" ] || opts+=(--name "custodexa-backup-tool-$CX_BK_TS-db")
  # A restore names its own container and mounts its work files ("<host>:<container>[:ro]" each).
  [ -z "${CX_DB_EXT_NAME:-}" ] || opts+=(--name "$CX_DB_EXT_NAME")
  local m
  for m in ${CX_DB_EXT_MOUNTS:-}; do opts+=(-v "$m"); done
  [ "$tool" != pg_restore ] || opts+=(-i)
  if [ "$connect" = 1 ]; then
    cx_db_pgpass_write || { cx_db_pgpass_rm; return 1; }
    opts+=(--network host -e "PGPASSFILE=$CX_DB_CTR_PGPASS" -v "$CX_DB_PGPASS:$CX_DB_CTR_PGPASS:ro")
    [ "$CX_DB_ROOTCERT" != "$CX_DB_CTR_TLS/root.crt" ] || opts+=(-v "$CX_DB_CA_HOST:$CX_DB_CTR_TLS/root.crt:ro")
    [ -z "$CX_DB_CERT_HOST" ] || opts+=(-v "$CX_DB_CERT_HOST:$CX_DB_CTR_TLS/client.crt:ro")
    [ -z "$CX_DB_KEY_HOST" ] || opts+=(-v "$CX_DB_KEY_HOST:$CX_DB_CTR_TLS/client.key:ro")
  else
    opts+=(--network none)
  fi
  cx_log CMD "docker run ${opts[*]} $CX_DB_EXT_ID $*"
  docker run "${opts[@]}" "$CX_DB_EXT_ID" "$@" || rc=$?
  [ "$connect" != 1 ] || cx_db_pgpass_rm
  return "$rc"
}

# cx_db_ext <action> [sql]: the action in the chosen client container.
cx_db_ext() {
  local action=$1
  if [ -z "$CX_DB_EXT_ID" ]; then
    printf 'custodexa.sh: no database client for an external database chosen (%s)\n' "$action" >&2
    return 70
  fi
  case $action in
    sql) CX_DB_ACTION=sql cx_db_ext_run 1 psql -AtX -v ON_ERROR_STOP=1 -d "$(cx_db_conninfo)" -c "$2" ;;
    dump) CX_DB_ACTION=dump cx_db_ext_run 1 pg_dump -Fc -d "$(cx_db_conninfo)" ;;
    restore-list) CX_DB_ACTION=restore-list cx_db_ext_run 0 pg_restore --list ;;
    dump-version) CX_DB_ACTION=dump-version cx_db_ext_run 0 pg_dump --version ;;
    *)
      printf 'custodexa.sh: internal error: unknown database action %q\n' "$action" >&2
      return 2
      ;;
  esac
}

# An import uses its data release before current changes. The caller scopes this variable;
# ordinary database callers keep using current.
cx_db_compose() {
  if [ -n "${CX_DB_RELEASE:-}" ]; then cx_compose_release "$CX_DB_RELEASE" "$@"
  else cx_compose "$@"; fi
}

# cx_db <action> [sql]: sql <query> | dump | restore-list | dump-version | ready | restore.
# stdout is the client's
# output; restore-list reads the dump on stdin. Uses CX_BK_DBUSER and CX_BK_DBNAME (cx_bk_vars).
cx_db() {
  local action=$1
  if cx_db_external; then
    cx_db_ext "$@"
    return
  fi
  case $action in
    sql)
      CX_DB_ACTION=sql cx_db_compose exec -T postgres \
        psql -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -AtX -v ON_ERROR_STOP=1 -c "$2"
      ;;
    dump) CX_DB_ACTION=dump cx_db_compose exec -T postgres pg_dump -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -Fc ;;
    restore-list) CX_DB_ACTION=restore-list cx_db_compose exec -T postgres pg_restore --list ;;
    dump-version) CX_DB_ACTION=dump-version cx_db_compose exec -T postgres pg_dump --version ;;
    ready)
      CX_DB_ACTION=ready cx_db_compose exec -T postgres pg_isready -h 127.0.0.1 -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" &&
        CX_DB_ACTION=ready cx_db_compose exec -T postgres psql -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -AtX -v ON_ERROR_STOP=1 -c 'SELECT 1'
      ;;
    restore)
      CX_DB_ACTION=restore cx_db_compose exec -T postgres pg_restore --single-transaction --exit-on-error \
        -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME"
      ;;
    *)
      printf 'custodexa.sh: internal error: unknown database action %q\n' "$action" >&2
      return 2
      ;;
  esac
}
