# shellcheck shell=bash
# CX_BK_KEK and CX_BK_FAILED_STEP are read by the commands that source this file.
# shellcheck disable=SC2034
# What the backup command and step 7 of upgrade share (both make one portable file, lib/portable.sh):
# the deployment values, the size estimate and the free space, and the steps in order (cx_bk_take).
# Within an upgrade the services are not started again (the next step changes the version).
# shellcheck source=lib/snapshot.sh
. "${BASH_SOURCE[0]%/*}/snapshot.sh"

readonly CX_BK_SERVICES="backend guacd frontend"
# Bytes per second assumed for the time shown in the preview: slow disks, compressed on one core.
readonly CX_BK_RATE=$((25 * 1048576))
readonly CX_BK_SLACK=1073741824 # 1 GB on top of the estimate; the compression rate is not counted

CX_BK_TS="" CX_BK_DIR="" CX_BK_DATA="" CX_BK_DBUSER="" CX_BK_DBNAME="" CX_BK_KEK=""
CX_BK_NEED=0 CX_BK_FREE=0 CX_BK_FAILED_STEP="" CX_BK_STEP_MARK=OK CX_BK_STEP_NOW=0
CX_BK_SIZE_DB=0 CX_BK_SIZE_REC=0 CX_BK_SIZE_AUDIT=0 CX_BK_SIZE_TLS=0

# cx_bk_env <key>: the value in this deployment's .env as compose reads it (lib/env.sh cx_env_get).
# A restore points CX_BK_ENV_FILE at the settings it is about to put in place, for the database
# client to reach the backup's external database.
cx_bk_env() { cx_env_get "${CX_BK_ENV_FILE:-$CX_ROOT/.env}" "$1"; }

# cx_bk_has_tls: the deployment has a tls/ (anything by that name, as tar would take it). A
# deployment behind its own ingress has none: there is nothing to pack, which is no loss.
cx_bk_has_tls() { [ -e "$CX_ROOT/tls" ] || [ -L "$CX_ROOT/tls" ]; }

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
# (free space where backups/ lives); the parts in CX_BK_SIZE_*. Fails when the database size cannot
# be read.
cx_bk_estimate() {
  local db
  db=$(cx_snap_sql "SELECT pg_database_size(current_database())" 2>/dev/null) || return 1
  [[ $db =~ ^[0-9]+$ ]] || return 1
  CX_BK_SIZE_DB=$db
  CX_BK_SIZE_REC=$(cx_bk_du "$CX_BK_DATA/recordings")
  CX_BK_SIZE_AUDIT=$(cx_bk_du "$CX_BK_DATA/audit")
  CX_BK_SIZE_TLS=$(cx_bk_du "$CX_ROOT/tls")
  CX_BK_NEED=$((db + CX_BK_SIZE_REC + CX_BK_SIZE_AUDIT + CX_BK_SIZE_TLS + CX_BK_SLACK))
  CX_BK_FREE=$(cx_free_bytes "$CX_ROOT/backups")
  CX_BK_FREE=${CX_BK_FREE:-0}
}

# cx_bk_minutes: what step 7 of upgrade adds to the downtime, whole minutes: the data of the file
# at the assumed rate (cx_pb_minutes; cx_pb_space set the file with the recordings), then as much
# again to pack the file and read it back while the services stay stopped.
cx_bk_minutes() { printf '%s' $((2 * $(cx_pb_minutes))); }

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

# The steps. Each returns non-zero on failure and leaves the files it wrote.
# shellcheck disable=SC2086
cx_bk_stop() { cx_compose stop $CX_BK_SERVICES >/dev/null 2>&1; }
# shellcheck disable=SC2086
cx_bk_start() { cx_compose start $CX_BK_SERVICES >/dev/null 2>&1; }

# cx_bk_take <upgrade|portable|restore-safety> <step callback>: run the steps (lib/portable.sh,
# cx_pb_open first, with restore-safety for a safety backup).
# The callback is called as <callback> <OK|WARN|FAIL> <n> <total> <step id> <start seconds> after
# each step, so the caller prints the step lines; a step that went on despite a problem sets
# CX_BK_STEP_MARK=WARN.
#   upgrade   the services are already stopped (its step 5) and stay stopped; the snapshot and
#             state.json are in the temporary folder already: db files conf verify pack
#   portable  stop db files conf start verify pack
#   restore-safety  stop db files conf verify pack; the caller holds the restore lock and records
#                   the file in last_restore only. No recordings, encryption or backup record.
# Returns non-zero at the first failed step; CX_BK_FAILED_STEP names it. CX_BK_STEP_NOW is the
# number of the step running (for the screen of an interruption).
cx_bk_take() {
  local mode=$1 cb=$2 n=0 id t0
  local -a steps=(db files conf verify pack)
  [ -n "$CX_BK_DIR" ] && [ -d "$CX_BK_DIR" ] || return 1 # cx_pb_open first
  case $mode in
    portable) steps=(stop db files conf start verify pack) ;;
    restore-safety)
      [ "$CX_PB_MODE" = restore-safety ] || return 1
      steps=(stop db files conf verify pack)
      cx_pb_safety_options ;;
    upgrade) ;;
    *) return 1 ;;
  esac
  for id in "${steps[@]}"; do
    n=$((n + 1))
    CX_BK_STEP_NOW=$n
    t0=$(cx_now)
    CX_BK_STEP_MARK=OK
    cx_log STEP "backup $n/${#steps[@]} $id"
    if ! "cx_pb_$id"; then
      CX_BK_FAILED_STEP=$id
      cx_log FAIL "backup step $id"
      "$cb" FAIL "$n" "${#steps[@]}" "$id" "$t0"
      return 1
    fi
    "$cb" "$CX_BK_STEP_MARK" "$n" "${#steps[@]}" "$id" "$t0" || return 1
  done
}
