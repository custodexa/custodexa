# shellcheck shell=bash
# CX_BK_KEK and CX_BK_FAILED_STEP are read by the commands that source this file.
# shellcheck disable=SC2034
# The stopped backup, shared by `backup` and by the backup step of `upgrade`. It follows the
# stopped-backup procedure of the backup and restore guide step by step, into backups/<ts>/:
#   custodexa-db-<ts>.dump        pg_dump -Fc of the database (postgres keeps running)
#   custodexa-files-<ts>.tar.gz   recordings and audit under DATA_PATH (not exports: evidence
#                                 package artifacts hold decrypted plaintext and are not backed up)
#   custodexa-env-<ts>.bak        .env (secrets included; the folder is private)
#   custodexa-tls-<ts>.tar.gz     tls/
#   snapshot.txt                  counts, schema_migrations, key fingerprints (lib/snapshot.sh)
#   SHA256SUMS                    the files above
#   INCOMPLETE                    written first, removed last: present only when the run failed
# Within an upgrade the services are not started again (the next step changes the version).
# shellcheck source=lib/snapshot.sh
. "${BASH_SOURCE[0]%/*}/snapshot.sh"

readonly CX_BK_SERVICES="backend guacd frontend"
# Bytes per second assumed for the time shown in the preview: slow disks, compressed on one core.
readonly CX_BK_RATE=$((25 * 1048576))
readonly CX_BK_SLACK=1073741824 # 1 GB on top of the estimate; the compression rate is not counted

CX_BK_TS="" CX_BK_DIR="" CX_BK_DATA="" CX_BK_DBUSER="" CX_BK_DBNAME="" CX_BK_KEK=""
CX_BK_NEED=0 CX_BK_FREE=0 CX_BK_FAILED_STEP=""

# cx_bk_env <key>: the value in this deployment's .env as compose reads it (lib/env.sh cx_env_get).
cx_bk_env() { cx_env_get "$CX_ROOT/.env" "$1"; }

cx_bk_du() { # <path>: bytes used, 0 when absent
  local out
  [ -e "$1" ] || { printf '0'; return 0; }
  out=$(du -sb -- "$1" 2>/dev/null) || true
  out=${out%%[[:space:]]*}
  printf '%s' "${out:-0}"
}

# cx_bk_vars: the deployment values the backup needs, with the defaults of the shipped compose file
# (the same values compose itself would use when .env leaves a key out).
cx_bk_vars() {
  CX_BK_DATA=$(cx_bk_env DATA_PATH)
  CX_BK_DATA=${CX_BK_DATA:-./data}
  case $CX_BK_DATA in
    /*) ;;
    *) CX_BK_DATA=$CX_ROOT/${CX_BK_DATA#./} ;;
  esac
  CX_BK_DBUSER=$(cx_bk_env DB_USER)
  CX_BK_DBUSER=${CX_BK_DBUSER:-postgres}
  CX_BK_DBNAME=$(cx_bk_env DB_NAME)
  CX_BK_DBNAME=${CX_BK_DBNAME:-custodexa}
  CX_BK_KEK=$(cx_bk_env KEK_PROVIDER)
}

# cx_bk_estimate: CX_BK_NEED (database size + recordings + audit + tls/ + 1 GB) and CX_BK_FREE
# (free space where backups/ lives). Fails when the database size cannot be read.
cx_bk_estimate() {
  local db
  db=$(cx_snap_sql "SELECT pg_database_size(current_database())" 2>/dev/null) || return 1
  [[ $db =~ ^[0-9]+$ ]] || return 1
  CX_BK_NEED=$((db + $(cx_bk_du "$CX_BK_DATA/recordings") + $(cx_bk_du "$CX_BK_DATA/audit") \
    + $(cx_bk_du "$CX_ROOT/tls") + CX_BK_SLACK))
  CX_BK_FREE=$(cx_free_bytes "$CX_ROOT/backups")
  CX_BK_FREE=${CX_BK_FREE:-0}
}

# cx_bk_minutes: the pause shown in the preview, whole minutes, at least 1.
cx_bk_minutes() {
  local m=$(((CX_BK_NEED - CX_BK_SLACK + CX_BK_RATE * 60 - 1) / (CX_BK_RATE * 60)))
  [ "$m" -ge 1 ] || m=1
  printf '%s' "$m"
}

# cx_bk_quiet <output file> <command...>: run with stdout into the file; stderr goes to the log.
cx_bk_quiet() {
  local out=$1 err rc=0 line
  shift
  err=$(mktemp)
  "$@" >"$out" 2>"$err" || rc=$?
  while IFS= read -r line || [ -n "$line" ]; do cx_log OUT "$line"; done <"$err"
  rm -f "$err"
  return "$rc"
}

# cx_bk_open: create backups/ (0700) and backups/<ts>/ with its INCOMPLETE marker.
cx_bk_open() {
  CX_BK_TS=$(date '+%Y%m%d-%H%M%S')
  CX_BK_DIR=$CX_ROOT/backups/$CX_BK_TS
  (umask 077 && mkdir -p "$CX_ROOT/backups" && mkdir "$CX_BK_DIR") || return 1
  chmod 0700 "$CX_ROOT/backups" "$CX_BK_DIR"
  (umask 077 && printf 'started %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" >"$CX_BK_DIR/INCOMPLETE")
  cx_log BACKUP "dir=${CX_BK_DIR#"$CX_ROOT"/}"
}

# The steps. Each returns non-zero on failure and leaves the files it wrote.
# shellcheck disable=SC2086
cx_bk_stop() { cx_compose stop $CX_BK_SERVICES >/dev/null 2>&1; }
# shellcheck disable=SC2086
cx_bk_start() { cx_compose start $CX_BK_SERVICES >/dev/null 2>&1; }

cx_bk_db() {
  (umask 077 && cx_bk_quiet "$CX_BK_DIR/custodexa-db-$CX_BK_TS.dump" \
    cx_compose exec -T postgres pg_dump -U "$CX_BK_DBUSER" -d "$CX_BK_DBNAME" -Fc) || return 1
  [ -s "$CX_BK_DIR/custodexa-db-$CX_BK_TS.dump" ] || return 1
  cx_snap_take "$CX_BK_DIR/snapshot.txt" "$(cx_bk_env JWT_SECRET)" || return 1
  cx_log SNAPSHOT "usable=$CX_SNAP_USABLE${CX_SNAP_REASONS:+ reasons=\"$CX_SNAP_REASONS\"}"
}

cx_bk_files() {
  (umask 077 && cx_bk_quiet /dev/null tar -czf "$CX_BK_DIR/custodexa-files-$CX_BK_TS.tar.gz" \
    -C "$CX_BK_DATA" recordings audit)
}

cx_bk_conf() {
  (umask 077 && cp -- "$CX_ROOT/.env" "$CX_BK_DIR/custodexa-env-$CX_BK_TS.bak") || return 1
  chmod 0600 "$CX_BK_DIR/custodexa-env-$CX_BK_TS.bak"
  (umask 077 && cx_bk_quiet /dev/null tar -czf "$CX_BK_DIR/custodexa-tls-$CX_BK_TS.tar.gz" \
    -C "$CX_ROOT" tls)
}

# cx_bk_verify: the dump lists in pg_restore and both archives list in tar; then SHA256SUMS, and
# the INCOMPLETE marker goes last.
cx_bk_verify() {
  local listing f sums
  listing=$(mktemp)
  cx_bk_quiet "$listing" cx_compose exec -T postgres pg_restore --list \
    <"$CX_BK_DIR/custodexa-db-$CX_BK_TS.dump" || { rm -f "$listing"; return 1; }
  grep -q . "$listing" || { rm -f "$listing"; return 1; }
  rm -f "$listing"
  for f in files tls; do
    cx_bk_quiet /dev/null tar -tzf "$CX_BK_DIR/custodexa-$f-$CX_BK_TS.tar.gz" || return 1
  done
  sums=$(mktemp)
  (
    cd "$CX_BK_DIR" || exit 1
    find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name INCOMPLETE -printf '%P\n' | sort \
      | xargs -d '\n' sha256sum >"$sums"
  ) || { rm -f "$sums"; return 1; }
  chmod 0600 "$sums"
  mv -f "$sums" "$CX_BK_DIR/SHA256SUMS" || return 1
  rm -f "$CX_BK_DIR/INCOMPLETE"
}

# cx_bk_record: the backup as the last one in state.json (status reads these keys).
cx_bk_record() {
  cx_state_set last_backup.id "$CX_BK_TS"
  cx_state_set last_backup.kind script
  cx_state_set last_backup.taken_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set last_backup.dir "backups/$CX_BK_TS"
  cx_state_set last_backup.size_bytes "$(cx_bk_du "$CX_BK_DIR")"
  cx_state_set last_backup.snapshot_usable "$CX_SNAP_USABLE"
  cx_state_save "$CX_ROOT/state.json"
}

# cx_bk_take <standalone|upgrade> <step callback>: stop, back up, start, verify, record. The callback
# is called as <callback> <OK|FAIL> <n> <total> <step id> <start seconds> after each step, so the
# caller prints the step lines. Within an upgrade the services are already stopped (its step 5) and
# stay stopped, and the upgrade records the backup itself: 4 steps, db files conf verify.
# Needs cx_bk_open first. Returns non-zero at the first failed step; CX_BK_FAILED_STEP names it.
cx_bk_take() {
  local mode=$1 cb=$2 total=6 n=0 id t0
  local -a steps=(stop db files conf start verify)
  [ -n "$CX_BK_DIR" ] && [ -d "$CX_BK_DIR" ] || return 1 # cx_bk_open first
  if [ "$mode" = upgrade ]; then
    steps=(db files conf verify)
    total=4
  fi
  for id in "${steps[@]}"; do
    n=$((n + 1))
    t0=$(cx_now)
    cx_log STEP "backup $n/$total $id"
    if ! "cx_bk_$id"; then
      CX_BK_FAILED_STEP=$id
      cx_log FAIL "backup step $id"
      "$cb" FAIL "$n" "$total" "$id" "$t0"
      return 1
    fi
    "$cb" OK "$n" "$total" "$id" "$t0"
  done
  [ "$mode" = upgrade ] || cx_bk_record
}
