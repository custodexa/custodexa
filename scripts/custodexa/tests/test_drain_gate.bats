#!/usr/bin/env bats
# Threat (B): the drain gate passes without knowing the audit queue is empty. Records still in the
# backend's memory when it stops never reach the audit trail. The gate may only let the upgrade go
# on when the queue metric reads 0, or when the seal state is read (HTTP 200) as sealed and the
# backend has not unsealed since it started (no audit writer yet), or when no backend runs at all
# (nothing holds a queue). For a running backend, a queue that does not drain in
# time, a 403 from the source address limit, no answer, another status, an unreadable answer, an
# unseal earlier in this container's life, or an unsealed backend without the metric all stop the
# run with the services running and no stop issued. --yes changes none of this.
# After the stop, the same threat from the other side: a shutdown that ran out of time draining
# (the backend logs it), or an application connection still open on the database (an old backend
# elsewhere), stops the upgrade with the services left stopped and the command to start them again.

load helper
load install_host
load backup_host

setup() {
  backup_host ui
  export DG=$BATS_TEST_TMPDIR/dg
  mkdir -p "$DG"
  : >"$DG/events"
  printf 'true 0001-01-01T00:00:00Z\n' >"$DG/running"
  printf '2026-09-30T01:00:00.000000000Z\n' >"$DG/started"
  : >"$DG/logs.since"
  : >"$DG/logs.all"
  printf '0\n' >"$DG/conns"
  fake sleep ':'
  write_gate_hook
}

# The backend container, as the gate sees it:
#   $DG/metrics  one answer per read, "<http code|none> <depth|->"; the last one repeats
#   $DG/seal     "<http code|none> <state|->"
#   $DG/running  what inspect says of State.Running and State.FinishedAt ("" = no such container)
#   $DG/logs.since, $DG/logs.all   the log since StartedAt, and the whole log of the container
write_gate_hook() {
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
answer() { # <"code value"> <body when 200>
  local code=${1%% *}
  [ "$code" = none ] && exit 1
  printf '  HTTP/1.1 %s X\n' "$code" >&2
  [ "$code" = 200 ] || { echo "wget: server returned error: HTTP/1.1 $code X" >&2; exit 1; }
  printf '%s\n' "$2"
}
case $1 in
  exec)
    [ "$2" = custodexa-backend ] || exit 99
    # The production backend image has no shell (removed on purpose); only /bin/busybox is left.
    if [ "$3" = sh ] || [ "$3" = /bin/sh ]; then
      echo 'OCI runtime exec failed: exec failed: unable to start container process: exec: "'"$3"'": executable file not found in $PATH' >&2
      exit 127
    fi
    case ${*: -1} in
      /metrics)
        printf 'read\n' >>"$DG/reads"
        line=$(head -n 1 "$DG/metrics")
        [ "$(wc -l <"$DG/metrics")" -le 1 ] || sed -i 1d "$DG/metrics"
        v=${line#* }
        body='# TYPE custodexa_audit_queue_depth gauge'
        [ "$v" = - ] || body+=$'\n'"custodexa_audit_queue_depth $v"
        answer "$line" "$body" ;;
      /api/v1/seal/status)
        line=$(cat "$DG/seal")
        s=${line#* }
        # As the backend answers: keys in alphabetical order, the instance_guard object (with a
        # "state" of its own) before the seal state.
        body="{\"initialization_required\":false,\"instance_guard\":{\"state\":\"held\",\"peers\":0},\"state\":\"$s\"}"
        [ "$s" = - ] && body='<html>not json</html>'
        answer "$line" "$body" ;;
      *) exit 1 ;;
    esac
    exit 0 ;;
  container)
    [ -s "$DG/running" ] || exit 1
    case $* in
      *StartedAt*) cat "$DG/started" ;;
      *) cat "$DG/running" ;;
    esac
    exit 0 ;;
  logs)
    case " $* " in
      *" --since $(cat "$DG/started") "*) cat "$DG/logs.since" ;;
      *) cat "$DG/logs.all" ;;
    esac
    exit 0 ;;
  compose)
    printf 'compose %s\n' "$*" >>"$DG/events"
    case " $* " in
      *" psql "*pg_stat_activity*) [ -e "$DG/conns.rc" ] && exit 1; cat "$DG/conns" ;;
      *" stop "*) [ -e "$DG/stop.rc" ] && exit 1 ;;
    esac
    exit 0 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# gate <lang>: the gate as step 4 of 13, with --yes given.
gate() {
  run bash -c 'CX_LANG_FLAG=$1; . "$2/lib/common.sh"; cx_load_libs "$2"; . "$2/lib/backup_ref.sh"
    . "$2/lib/upgrade_output.sh"; . "$2/lib/drain_gate.sh"; CX_ROOT=$3 CX_YES=1; cx_dg_wait 4' _ "$1" "$SRC" "$ROOT"
}

no_stop() { ! grep -q ' stop \| down ' "$FAKE_DOCKER_LOG"; }

@test "the queue drains: the numbers as they fall, then OK with the time (two languages)" {
  for l in zh-TW en; do
    printf '%s\n' '200 214' '200 87' '200 87' '200 12' '200 0' >"$DG/metrics"
    clock 0 2 2 2 3
    gate "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s13-drained.$l.txt" || return 1
  done
  # Empty at once: only the OK line.
  printf '200 0\n' >"$DG/metrics"
  clock 0 4
  gate zh-TW
  [ "$status" -eq 0 ] && [ "${#lines[@]}" -eq 1 ] || { echo "$output"; return 1; }
  [ "$output" = '[ OK ]  4/13  等稽核紀錄寫完（待寫入 0 筆）                 4 秒' ] || { echo "$output"; return 1; }
  no_stop
}

@test "the queue does not drain in 120 seconds: FAIL, the manual command, no stop" {
  for l in zh-TW en; do
    printf '200 1530\n' >"$DG/metrics"
    rm -f "$DG/reads"
    clock 0 60 61 999
    gate "$l"
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    # Read at 0 and at 60 seconds; at 121 it gives up instead of reading again.
    [ "$(wc -l <"$DG/reads")" -eq 2 ] || { cat "$DG/reads"; return 1; }
    diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') "$TESTS_DIR/snapshots/s13-timeout.$l.txt" \
      || { echo "$output"; return 1; }
  done
  # Just under the limit it keeps reading.
  printf '%s\n' '200 1530' '200 1530' '200 0' >"$DG/metrics"
  clock 0 60 59 1
  gate en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  no_stop
}

@test "no metric, sealed and never unsealed since start: OK, nothing to wait for" {
  printf 'none -\n' >"$DG/metrics"
  for l in zh-TW en; do
    for s in sealed sealed-faulted unsealing; do
      printf '200 %s\n' "$s" >"$DG/seal"
      gate "$l"
      [ "$status" -eq 0 ] || { echo "$s: $output"; return 1; }
      diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s13-sealed.$l.txt" || return 1
    done
  done
  # An unseal logged by an earlier life of the container does not count.
  printf '%s\n' '[Seal] 已解封並換上完整路由（generation=1）' >"$DG/logs.all"
  printf '200 sealed\n' >"$DG/seal"
  gate en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  no_stop
}

@test "every unknown state stops the run with nothing changed and no stop, --yes or not" {
  unknown() { # <label>
    gate "$1"
    [ "$status" -eq 1 ] || { echo "$2 passed the gate: $output"; return 1; }
    diff <(screen_of "$output") "$TESTS_DIR/snapshots/s13-unknown.$1.txt" || { echo "$2"; return 1; }
    no_stop || { echo "$2 stopped something"; return 1; }
  }
  printf 'none -\n' >"$DG/metrics"
  printf '403 -\n' >"$DG/seal"
  unknown zh-TW "403 from the source address limit" || return 1
  unknown en "403 from the source address limit" || return 1
  printf 'none -\n' >"$DG/seal"
  unknown en "no answer" || return 1
  printf '500 sealed\n' >"$DG/seal"
  unknown en "HTTP 500" || return 1
  printf '200 -\n' >"$DG/seal"
  unknown en "an answer that does not parse" || return 1
  printf '200 unsealed\n' >"$DG/seal"
  unknown en "unsealed without the metric" || return 1
  printf '200 sealed\n' >"$DG/seal"
  printf '%s\n' '[Seal] 已解封並換上完整路由（generation=1）' >"$DG/logs.since"
  unknown en "unsealed earlier and sealed again" || return 1
  : >"$DG/logs.since"
  printf '403 -\n' >"$DG/metrics"
  printf '200 -\n' >"$DG/seal"
  unknown en "the metric refused, sealed state unreadable" || return 1
  printf '200 junk\n' >"$DG/metrics"
  printf '403 -\n' >"$DG/seal"
  unknown en "a metric value that is not a number" || return 1
  [ ! -s "$DG/events" ]
}

@test "the metric turns unreadable while draining: stopped, not passed" {
  printf '%s\n' '200 40' '403 -' >"$DG/metrics"
  printf '200 unsealed\n' >"$DG/seal"
  clock 0 2 2
  gate en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL]  4/13  Wait for audit records to be written: cannot confirm"* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "backend stopped (SKIP) or not there (WARN): nothing in memory, go on; the token never shown or logged" {
  printf 'false 2026-09-30T02:00:00Z\n' >"$DG/running"
  gate en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == "[SKIP]  4/13  Wait for audit records to be written: the backend is not"* ]] || { echo "$output"; return 1; }
  # No backend container at all: no backend holds a queue either; a warning, and the run goes on.
  : >"$DG/running"
  gate en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == "[WARN]  4/13  Wait for audit records to be written: the backend is not"* ]] || { echo "$output"; return 1; }
  no_stop || return 1
  # With METRICS_TOKEN set, the manual command carries a placeholder, never the value.
  printf '%s\n' 'METRICS_TOKEN=metrics-token-test-value-0004' >>"$ROOT/.env"
  printf 'true 0001-01-01T00:00:00Z\n' >"$DG/running"
  printf '200 9\n' >"$DG/metrics"
  clock 0 130 999
  gate en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *'wget -qO- --header="Authorization: Bearer <token>" http://localhost:8080/metrics'* ]] || { echo "$output"; return 1; }
  [[ $output != *metrics-token-test-value-0004* ]] || return 1
  ! grep -q metrics-token-test-value-0004 "$FAKE_DOCKER_LOG"
}

# ---------- after the gate: the stop, and the old version gone ----------

# stop_steps <lang>: steps 5 and 6 of this deployment.
stop_steps() {
  run bash -c 'CX_LANG_FLAG=$1; . "$2/lib/common.sh"; cx_load_libs "$2"; . "$2/lib/backup.sh"
    . "$2/lib/backup_ref.sh"; . "$2/lib/upgrade_output.sh"; . "$2/lib/stop_check.sh"
    CX_ROOT=$3 CX_UP_KIND=package CX_OVERLAYS=""
    cx_bk_vars
    cx_up_stop 5 && cx_up_gone 6' _ "$1" "$SRC" "$ROOT"
}

DRAIN_LINE='2026/09/30 02:15:30 稽核佇列排空逾時：37 列未確認落地（已降級寫檔 30 列、worker 持有中未回報 5 列、確定遺失 2 列）'

@test "stop and check: both OK; the stop is backend, guacd and frontend only, postgres stays" {
  clock 0 11
  stop_steps zh-TW
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output") - <<'SCREEN' || return 1
[ OK ]  5/13  停止服務（資料庫保持運作）                    11 秒
[ OK ]  6/13  確認舊版已完全停止（資料庫連線 0）
SCREEN
  grep -q "compose -p custodexa --project-directory $ROOT -f $ROOT/current/compose.yml stop backend guacd frontend" \
    "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  ! grep -q ' stop .*postgres\| down ' "$FAKE_DOCKER_LOG"
}

@test "the shutdown ran out of time draining: FAIL with the counts and the fallback folder, how to start again" {
  printf '%s\n' "$DRAIN_LINE" >"$DG/logs.since"
  clock 0 11
  stop_steps en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output") - <<'SCREEN' || return 1
[FAIL]  5/13  Stop the services: not all audit records were written to the
              database within the shutdown limit
  37 not confirmed written (30 moved to the fallback file, 5 still
  being handled, 2 lost)
  The fallback file is in /opt/custodexa/data/audit/. The upgrade
  stopped here; the services stay stopped and nothing else was
  changed. Check these records before starting the old version again.
  To start the old version again:
    sudo docker compose -p custodexa --project-directory /opt/custodexa -f /opt/custodexa/current/compose.yml \
      start backend guacd frontend
    sudo /opt/custodexa/custodexa.sh status --lang en
SCREEN
  # Only the log of the run that just ended counts: an older line is not this stop's.
  : >"$DG/logs.since"
  printf '%s\n' "$DRAIN_LINE" >"$DG/logs.all"
  stop_steps en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "an application connection left, or the count unreadable: FAIL, services left stopped" {
  printf '1\n' >"$DG/conns"
  stop_steps zh-TW
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL]  6/13  舊版停止後，應用帳號在資料庫仍有 1 條連線"* ]] || { echo "$output"; return 1; }
  [[ $output == *"AND pid <> pg_backend_pid()"* && $output == *"  start backend guacd frontend"* ]] || { echo "$output"; return 1; }
  touch "$DG/conns.rc"
  stop_steps en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL]  6/13  The connections of the application account could not be read"* ]] \
    || { echo "$output"; return 1; }
  ! grep -q ' start \| up ' "$FAKE_DOCKER_LOG"
}
