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

CX_SNAP_USABLE=false
CX_SNAP_REASONS=""

# cx_snap_sql <sql>: run one query in the postgres container, unaligned, tuples only.
cx_snap_sql() {
  cx_compose exec -T postgres psql -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -AtX -v ON_ERROR_STOP=1 -c "$1"
}

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
  local file=$1 jwt=$2 t n migs fp_jwt="" fp_kek="" fp_exp="" fp_chk=""
  local -a counts=()
  CX_SNAP_REASONS=""
  for t in users sessions audit_logs; do
    n=$(cx_snap_sql "SELECT count(*) FROM $t") || return 1
    [[ $n =~ ^[0-9]+$ ]] || return 1
    counts+=("count.$t=$n")
  done
  migs=$(cx_snap_sql "SELECT version FROM schema_migrations ORDER BY version") || return 1
  [ -n "$migs" ] || return 1

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
  CX_SNAP_USABLE=true
  [ -z "$CX_SNAP_REASONS" ] || CX_SNAP_USABLE=false

  (
    umask 077
    {
      printf 'format=1\n'
      printf '%s\n' "${counts[@]}"
      printf '%s\n' "$migs" | sed 's/^/migration=/'
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
