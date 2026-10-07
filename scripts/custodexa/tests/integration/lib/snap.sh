# shellcheck shell=bash
# The snapshot of a restored database, taken by the management script's own code (lib/snapshot.sh
# of the working tree), so that it compares line for line with the snapshot.txt a backup carries:
# row counts, schema_migrations, the four key fingerprints, usable.
#   it_snap_take <file> <JWT_SECRET value> <command...>
#       <command...> plus one SQL statement as its last argument prints the rows unaligned, tuples
#       only; e.g. docker exec -i <container> psql -U <user> -d <db> -AtX -v ON_ERROR_STOP=1 -c
#   it_snap_same <what> <snapshot.txt of the backup> <snapshot of the restore>

it_snap_take() {
  local file=$1 jwt=$2
  shift 2
  (
    # shellcheck source=scripts/custodexa/lib/snapshot.sh
    . /src/scripts/custodexa/lib/snapshot.sh
    IT_SNAP_CMD=("$@")
    # The script reaches the database through its client (cx_db); here the command given does.
    # shellcheck disable=SC2317,SC2329 # called by cx_snap_take
    cx_snap_sql() { "${IT_SNAP_CMD[@]}" "$1"; }
    cx_snap_take "$file" "$jwt"
  )
}

it_snap_same() {
  local out
  if out=$(diff -u "$2" "$3" 2>&1); then
    printf 'ok - %s\n' "$1"
    return 0
  fi
  printf 'not ok - %s\n' "$1"
  printf '%s\n' "$out" | tail -n 30 | sed 's/^/   | /'
  return 1
}
