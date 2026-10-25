# shellcheck shell=bash
# snapshot.txt: what the database held when the services were stopped, so the checks after an
# upgrade or a rollback have something to compare with. One key=value per line:
#   format=1
#   count.users=12   count.sessions=340   count.audit_logs=98211
#   migration=<version>          one line per applied schema_migrations row, sorted
#   fp.jwt / fp.kek / fp.export_signing / fp.checkpoint_signing=<16 hex>   (empty when not known)
#   usable=true|false            false when any fingerprint is missing or its source is not unique
#   unusable=<reasons>           e.g. "kek:not-unique export:none"
# The fingerprints use the algorithm of the key inventory page: the first 8 bytes of SHA-256 of the
# raw bytes, lower-case hex. The KEK is shown there as the key ID of the active data keys, so that is
# read as it is. Nothing here needs the system to be unsealed or anyone to sign in.
# A snapshot that is not usable is never taken for a match: the key checks become manual.
#
# The permission model (the role bindings, their scopes and sources, the external-group mappings,
# the group members) adds one summary, taken by the backend itself in a one-shot command
# (docker compose run, no HTTP, nothing started): the keys authz.model / authz.snapshot /
# authz.catalog / authz.digest / authz.version / authz.refs and one authz.count.<set> per set.
# A data set without the permission-model migration is written as authz.model=legacy and its
# tables are never asked for. A set with the migration needs every key; one missing is no backup.

# shellcheck source=lib/dbclient.sh
. "${BASH_SOURCE[0]%/*}/dbclient.sh"

CX_SNAP_USABLE=false
CX_SNAP_REASONS=""

# The migration that introduces the permission model's tables (its presence in schema_migrations
# says which data model a database holds; no version string is compared).
readonly CX_SNAP_AUTHZ_MIGRATION=20261017_permission_state_attestation
# The versions of the summary these scripts read. Three axes are told apart: the backup format
# (format=1 of the archive), the data model (the migration above) and the summary itself (model and
# snapshot version, and the catalog the backend pins by its digest). A version not listed here is not
# read as an older one and is never defaulted: the restore stops and says which release made it.
readonly CX_SNAP_AUTHZ_KNOWN_MODEL=1 CX_SNAP_AUTHZ_KNOWN_SNAPSHOT=1
# Every key a permission-model snapshot must carry.
readonly CX_SNAP_AUTHZ_KEYS="authz.model authz.snapshot authz.catalog authz.digest authz.version authz.refs
 authz.count.roles authz.count.user_roles authz.count.group_roles authz.count.binding_nodes authz.count.nodes
 authz.count.role_maps authz.count.group_maps authz.count.members authz.count.groups authz.count.principals"

# cx_snap_sql <sql>: run one query through the database client, unaligned, tuples only.
cx_snap_sql() { cx_db sql "$1"; }

# cx_snap_fp <text>: the fingerprint of the bytes of text.
cx_snap_fp() {
  local sum
  sum=$(printf '%s' "$1" | sha256sum)
  printf '%s' "${sum:0:16}"
}

# cx_snap_fp_b64 <base64> [length]: the fingerprint of the decoded bytes; fails when the text does
# not decode or, with a length, when the decoded key is not that many bytes.
cx_snap_fp_b64() {
  local n sum
  n=$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c) || return 1
  printf '%s' "$1" | base64 -d >/dev/null 2>&1 || return 1
  [ -z "${2:-}" ] || [ "$n" -eq "$2" ] || return 1
  sum=$(printf '%s' "$1" | base64 -d | sha256sum)
  printf '%s' "${sum:0:16}"
}

cx_snap_unusable() { CX_SNAP_REASONS="${CX_SNAP_REASONS:+$CX_SNAP_REASONS }$1"; }

# cx_snap_backend <subcommand...>: a one-shot command of the backend image in the release the
# database client uses (CX_DB_RELEASE, else current). It only connects to the database: no
# migration, no listener, no unseal. Nothing but its stdout is kept.
cx_snap_backend() { CX_DB_ACTION=authz cx_db_compose run --rm --no-deps -T backend ./custodexa "$@" 2>/dev/null; }

# cx_snap_authz_valid <text>: the summary has every key, once, with a value that has the right shape.
cx_snap_authz_valid() {
  local key n line
  for key in $CX_SNAP_AUTHZ_KEYS; do
    n=$(printf '%s\n' "$1" | grep -c "^${key//./\\.}=") || true
    [ "$n" = 1 ] || return 1
  done
  while IFS= read -r line; do
    [[ $line =~ ^authz\.(model|snapshot|version|count\.[a-z_]+)=[0-9]+$ ||
      $line =~ ^authz\.(catalog|digest)=[0-9a-f]{16,128}$ ||
      $line =~ ^authz\.refs=(ok|findings:[0-9]+)$ ]] || return 1
  done <<<"$1"
}

# cx_snap_authz_known <text>: the model and snapshot versions of a valid summary are the ones read here.
cx_snap_authz_known() {
  printf '%s\n' "$1" | grep -qx "authz\.model=$CX_SNAP_AUTHZ_KNOWN_MODEL" &&
    printf '%s\n' "$1" | grep -qx "authz\.snapshot=$CX_SNAP_AUTHZ_KNOWN_SNAPSHOT"
}

# cx_snap_authz <migration list>: the authz.* lines on stdout; fails (nothing printed) when the data
# holds the permission model and the backend cannot give a complete, well-formed summary.
cx_snap_authz() {
  local out
  if ! printf '%s\n' "$1" | grep -qxF "$CX_SNAP_AUTHZ_MIGRATION"; then
    printf 'authz.model=legacy\n'
    return 0
  fi
  out=$(cx_snap_backend permission-meta) || return 1
  out=$(printf '%s\n' "$out" | grep '^authz\.') || return 1
  cx_snap_authz_valid "$out" || return 1
  printf '%s\n' "$out"
}

# cx_snap_one_row <reason prefix> <sql>: CX_SNAP_ROW = the only row the query returns. Records the
# reason and fails when the query fails, returns nothing, or returns more than one row. Called
# directly (not in $(...)), so the reason it records is kept.
CX_SNAP_ROW=""
cx_snap_one_row() {
  local out n
  CX_SNAP_ROW=""
  if ! out=$(cx_snap_sql "$2"); then
    cx_snap_unusable "$1:query"
    return 1
  fi
  n=$(printf '%s' "$out" | grep -c .) || true
  if [ "$n" -eq 0 ]; then
    cx_snap_unusable "$1:none"
    return 1
  fi
  if [ "$n" -gt 1 ]; then
    cx_snap_unusable "$1:not-unique"
    return 1
  fi
  CX_SNAP_ROW=$out
}

# cx_snap_take <file> <JWT_SECRET value>: write the snapshot. Fails (and writes nothing) only when the
# counts or the migration list cannot be read; a fingerprint that cannot be read makes the snapshot
# not usable instead. Sets CX_SNAP_USABLE.
cx_snap_take() {
  local file=$1 jwt=$2 t n migs authz fp_jwt="" fp_kek="" fp_exp="" fp_chk=""
  local -a counts=()
  CX_SNAP_REASONS=""
  for t in users sessions audit_logs; do
    n=$(cx_snap_sql "SELECT count(*) FROM $t") || return 1
    [[ $n =~ ^[0-9]+$ ]] || return 1
    counts+=("count.$t=$n")
  done
  migs=$(cx_snap_sql "SELECT version FROM schema_migrations ORDER BY version") || return 1
  [ -n "$migs" ] || return 1
  authz=$(cx_snap_authz "$migs") || return 1

  if [ -n "$jwt" ]; then
    fp_jwt=$(cx_snap_fp "$jwt")
  else
    cx_snap_unusable jwt:none
  fi
  # The data keys of every purpose are wrapped by the one current KEK: one distinct key ID.
  cx_snap_one_row kek "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1" && fp_kek=$CX_SNAP_ROW
  # The newest export signing key is the one in use (the table has no status column).
  if cx_snap_one_row export "SELECT public_key FROM export_signing_keys ORDER BY id DESC LIMIT 1"; then
    fp_exp=$(cx_snap_fp_b64 "$CX_SNAP_ROW" 32) || cx_snap_unusable export:decode
  fi
  if cx_snap_one_row checkpoint "SELECT public_key FROM checkpoint_signing_keys WHERE active"; then
    fp_chk=$(cx_snap_fp_b64 "$CX_SNAP_ROW" 32) || cx_snap_unusable checkpoint:decode
  fi
  # References that do not hold: the backup is kept as a diagnosis, it is not fit to restore from.
  case $authz in *$'\n'authz.refs=findings:* | authz.refs=findings:*) cx_snap_unusable authz:refs ;; esac
  CX_SNAP_USABLE=true
  [ -z "$CX_SNAP_REASONS" ] || CX_SNAP_USABLE=false

  (
    umask 077
    {
      printf 'format=1\n'
      printf '%s\n' "${counts[@]}"
      printf '%s\n' "$migs" | sed 's/^/migration=/'
      printf '%s\n' "$authz"
      printf 'fp.jwt=%s\nfp.kek=%s\nfp.export_signing=%s\nfp.checkpoint_signing=%s\n' \
        "$fp_jwt" "$fp_kek" "$fp_exp" "$fp_chk"
      printf 'usable=%s\n' "$CX_SNAP_USABLE"
      printf 'unusable=%s\n' "$CX_SNAP_REASONS"
    } >"$file"
  )
}

# cx_snap_get <file> <key>: one value (the first line for the key).
cx_snap_get() { sed -n "s/^$2=//p" "$1" | head -n 1; }

# cx_snap_migrations <file>: the migration versions, one per line.
cx_snap_migrations() { sed -n 's/^migration=//p' "$1"; }
