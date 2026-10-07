#!/usr/bin/env bats
# Threat (A): an interrupted backup that leaves things running or leaves the operator stuck. A
# signal must stop the command the step was running and everything it started, remove this run's
# tool containers and named pipes, keep the temporary folder private, and print how to start the
# services and back up again. Afterwards start, stop and another backup go on (each says first that
# the last backup did not finish); an upgrade waits until a backup finishes, and start alone does
# not lift that.

load helper
load install_host
load backup_host
load upgrade_host

TS=20260930-101502

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  clock
  printf '%s\n' 18683107737 >"$DB/size"
  kind_package
  OUT=$BATS_TEST_TMPDIR/out
}

# kind_package: state.json says this is a package deployment (start and stop need it).
kind_package() {
  jq '."current.kind" = "package"' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
}

# tree <pid>: the process and every process under it.
tree() {
  local c
  printf '%s\n' "$1"
  for c in $(pgrep -P "$1" || true); do tree "$c"; done
}

# gone <pid>: no such process (or only its exit status left to collect).
gone() {
  local st
  st=$(ps -o stat= -p "$1" 2>/dev/null) || return 0
  [[ $st == Z* ]]
}

# interrupt <lang> <script>: a backup in the background, held in a long-running tar; SIGTERM. RC is
# its exit code, output its screen, HELD every process of the run at the time of the signal.
interrupt() {
  bash "$2" backup --lang "$1" --yes </dev/null >"$OUT" 2>&1 &
  BK_PID=$!
  wait_for "$DB/paused.tar" || { kill -9 "$BK_PID"; cat "$OUT"; return 1; }
  mapfile -t HELD < <(tree "$BK_PID")
  kill -TERM "$BK_PID"
  RC=0
  wait "$BK_PID" || RC=$?
  output=$(cat "$OUT")
  rm -f "$DB/paused.tar"
}

# all_gone: every process of the run held at the signal has ended.
all_gone() {
  local p
  [ "${#HELD[@]}" -ge 3 ] || { echo "only ${#HELD[@]} processes held: ${HELD[*]}"; return 1; }
  for p in "${HELD[@]}" "$(cat "$DB/tar.pid")" "$(cat "$DB/tar.sleep.pid")"; do
    gone "$p" || { echo "process $p is still there"; ps -ef; return 1; }
  done
}

interrupted_screen_en() {
  printf '%s\n' "[FAIL] The backup was interrupted at step $1 and no backup file was made." \
    '       The tool processes it started have been stopped. What was taken so' \
    "       far is in /opt/custodexa/backups/.partial-$TS/; it cannot" \
    '       be restored from and holds sensitive plaintext. Delete it.'
  if [ "$2" = stopped ]; then
    printf '%s\n' 'The services may still be stopped. To start them again:' \
      '  sudo /opt/custodexa/custodexa.sh start --lang en'
  fi
  printf '%s\n' 'To back up again, run it again:' '  sudo /opt/custodexa/custodexa.sh backup --lang en'
}

interrupted_part() { screen_of "$output" | sed -n '/^\[FAIL\] \(The backup was interrupted\|備份在第\)/,$p'; }

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

@test "interrupted at step 3: tool processes and containers gone, pipe removed, no file, start and backup commands" {
  : >"$DB/tar.audit.sleep"
  printf '%s\n' "custodexa-backup-tool-$TS-enc" custodexa-backup-tool-20260930-091500-enc >"$DB/tools"
  interrupt en "$ROOT/custodexa.sh" || return 1
  [ "$RC" -eq 1 ] || { echo "exit $RC"; echo "$output"; return 1; }
  diff <(interrupted_part) <(interrupted_screen_en 3 stopped) || { echo "$output"; return 1; }
  all_gone || return 1
  # This run's tool containers, looked up by its fixed name prefix, are removed; another run's not.
  grep -qx "ps custodexa-backup-tool-$TS-" "$DB/events" || { cat "$DB/events"; return 1; }
  grep -qx "rm rm -f custodexa-backup-tool-$TS-enc" "$DB/events" || { cat "$DB/events"; return 1; }
  ! grep -q 'rm .*091500' "$DB/events" || return 1
  # The temporary folder stays, private, with what was taken; no named pipe; no file.
  local p=$ROOT/backups/.partial-$TS
  [ -d "$p" ] && [ "$(stat -c %a "$p")" = 700 ] && [ -s "$p/db.dump" ] || { ls -lA "$p"; return 1; }
  [ -z "$(find "$p" -type p)" ] || return 1
  ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || return 1
  # Never started again; the run stays unfinished, with where its parts are.
  ! grep -q '^start' "$DB/events" || return 1
  [ "$(st last_backup.result)" = in_progress ] && [ "$(st last_backup.partial)" = "backups/.partial-$TS" ] \
    || { cat "$ROOT/state.json"; return 1; }
  grep -q "END   result=interrupted step=3 commit=pre-commit" "$ROOT/logs/backup-$TS.log" || return 1
  [ "$(st last_backup.step)" = 3 ]
}

@test "interrupted: the zh-TW screen as reviewed" {
  : >"$DB/tar.audit.sleep"
  interrupt zh-TW "$ROOT/custodexa.sh" || return 1
  [ "$RC" -eq 1 ] || { echo "$output"; return 1; }
  diff <(interrupted_part) - <<EOF || { echo "$output"; return 1; }
[FAIL] 備份在第 3 步被中斷，沒有產生備份檔。已停止這次啟動的工具程序。
       已取得的部分在 /opt/custodexa/backups/.partial-$TS/，
       不能用來還原，而且含機敏明文；請刪除。
服務可能仍在停止中。恢復服務：
  sudo /opt/custodexa/custodexa.sh start --lang zh-TW
要重新備份，直接再執行一次：
  sudo /opt/custodexa/custodexa.sh backup --lang zh-TW
EOF
}

@test "interrupted at step 7 while reading back: the named pipe and the hash beside tar are gone; ready, so no start command" {
  : >"$DB/tar.readback.sleep"
  bash "$ROOT/custodexa.sh" backup --lang en --yes </dev/null >"$OUT" 2>&1 &
  BK_PID=$!
  wait_for "$DB/paused.tar" || { kill -9 "$BK_PID"; cat "$OUT"; return 1; }
  local p=$ROOT/backups/.partial-$TS
  [ -n "$(find "$p" -type p)" ] || { echo "no pipe while reading back"; ls -lA "$p"; kill -9 "$BK_PID"; return 1; }
  mapfile -t HELD < <(tree "$BK_PID")
  kill -TERM "$BK_PID"
  RC=0
  wait "$BK_PID" || RC=$?
  output=$(cat "$OUT")
  [ "$RC" -eq 1 ] || { echo "$output"; return 1; }
  diff <(interrupted_part) <(interrupted_screen_en 7 ready) || { echo "$output"; return 1; }
  all_gone || return 1
  [ -z "$(find "$p" -type p)" ] || { ls -lA "$p"; return 1; }
  [ -d "$p" ] && ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null
}

@test "interrupted before anything was stopped: nothing changed, nothing left unfinished" {
  # Held in the database size query of the preview: no temporary folder yet.
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/db-hook"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *pg_database_size*) : >"$DB/paused.tar"; /usr/bin/sleep 2 ;;
esac
exec "$FAKE_DOCKER_REPLAY/db-hook" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  bash "$ROOT/custodexa.sh" backup --lang en --yes </dev/null >"$OUT" 2>&1 &
  BK_PID=$!
  wait_for "$DB/paused.tar" || { kill -9 "$BK_PID"; cat "$OUT"; return 1; }
  kill -TERM "$BK_PID"
  RC=0
  wait "$BK_PID" || RC=$?
  output=$(cat "$OUT")
  [ "$RC" -eq 1 ] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | tail -n 1)" = "Nothing was changed." ] || { echo "$output"; return 1; }
  [ "$(st last_backup.result)" = cancelled ] || { cat "$ROOT/state.json"; return 1; }
  ! grep -q '^stop' "$DB/events" && [ ! -e "$ROOT/backups" ]
}

@test "an interrupted stop does not block start, which brings the services back under the lock" {
  svc_host
  : >"$SVC_SIM/pause.stop"
  bash "$ROOT/custodexa.sh" stop --yes --lang en </dev/null >"$OUT" 2>&1 &
  local pid=$!
  wait_for "$SVC_SIM/paused.stop" || { kill -9 "$pid"; cat "$OUT"; return 1; }
  kill -TERM "$pid"
  : >"$SVC_SIM/go.stop"
  local rc=0
  wait "$pid" || rc=$?
  [ "$rc" -eq 1 ] && [ "$(cat "$SVC_SIM/state")" = partial ] || { echo "$rc"; cat "$OUT"; return 1; }
  grep -qF "sudo $ROOT/custodexa.sh start --lang en" "$OUT" || { cat "$OUT"; return 1; }
  # Another holder of the lock: start is refused and changes nothing.
  (
    flock -x 9
    : >"$SVC_SIM/locked"
    exec /usr/bin/sleep 30
  ) 9>>"$ROOT/.custodexa.lock" &
  local holder=$!
  wait_for "$SVC_SIM/locked" || return 1
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  kill "$holder" 2>/dev/null || true
  wait "$holder" 2>/dev/null || true
  [ "$status" -eq 3 ] && [[ $output == *"Another custodexa.sh is running on this deployment"* ]] || { echo "$output"; return 1; }
  [ "$(cat "$SVC_SIM/state")" = partial ] || return 1
  # Then start brings every service back.
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$SVC_SIM/state")" = running ] && [[ $output != *"did not finish"* ]]
}

# svc_host: a deployment whose services stop and start (the stop can be held), for start and stop.
svc_host() {
  printf '{\n  "format": "2",\n  "current.version": "1.13.0",\n  "current.kind": "package",\n  "current.overlays": ""\n}\n' >"$ROOT/state.json"
  export SVC_SIM=$BATS_TEST_TMPDIR/service
  mkdir -p "$SVC_SIM"
  printf 'running\n' >"$SVC_SIM/state"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
args=" $* "
case $args in
  *' ps --all --services '*) printf 'postgres\nguacd\nbackend\nfrontend\ntls-proxy\n'; exit 0 ;;
  *' ps --status running --services '*)
    case $(cat "$SVC_SIM/state") in
      running) printf 'postgres\nguacd\nbackend\nfrontend\ntls-proxy\n' ;;
      partial) printf 'postgres\nfrontend\ntls-proxy\n' ;;
    esac
    exit 0 ;;
  *' stop '*)
    printf 'partial\n' >"$SVC_SIM/state"
    if [ -e "$SVC_SIM/pause.stop" ]; then
      rm -f "$SVC_SIM/pause.stop"; : >"$SVC_SIM/paused.stop"
      until [ -e "$SVC_SIM/go.stop" ]; do /usr/bin/sleep 0.05; done
    fi
    exit 0 ;;
  *' up -d --remove-orphans '*) printf 'running\n' >"$SVC_SIM/state"; exit 0 ;;
  *' exec -T backend wget -qO- http://localhost:8080/health '*)
    [ "$(cat "$SVC_SIM/state")" = running ] || exit 1
    printf '{"version":"1.13.0"}\n'; exit 0 ;;
  *' container inspect --format {{.State.Running}} {{.State.FinishedAt}} custodexa-backend '*)
    printf 'true 0001-01-01T00:00:00Z\n'; exit 0 ;;
  *' exec custodexa-backend /bin/busybox sh -c '*'/metrics '* )
    printf 'HTTP/1.1 200 OK\n' >&2
    printf 'custodexa_audit_queue_depth 0\n'; exit 0 ;;
  *' exec custodexa-backend /bin/busybox sh -c '*'/api/v1/seal/status '* ) exit 1 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

@test "interrupted backup: start warns and starts; the next backup records the earlier one interrupted" {
  : >"$DB/tar.audit.sleep"
  interrupt en "$ROOT/custodexa.sh" || return 1
  [ "$RC" -eq 1 ] || { echo "$output"; return 1; }
  rm -f "$DB/tar.audit.sleep"
  local warn
  warn=$(printf '%s\n' '[WARN] The last backup (2026-09-30 10:15) did not finish; the temporary' \
    "       folder /opt/custodexa/backups/.partial-$TS/ can be deleted.")
  # start: the warning first, then the services back and ready.
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(screen_of "$output" | head -n 2)" = "$warn" ] || { echo "$output"; return 1; }
  grep -qx up "$DB/events" && grep -qx health "$DB/events" || { cat "$DB/events"; return 1; }
  # start leaves the record of the backup as it was.
  [ "$(st last_backup.result)" = in_progress ] || return 1
  # stop goes on too, with the same warning.
  run bash "$ROOT/custodexa.sh" stop --lang en </dev/null
  [ "$status" -eq 3 ] && [ "$(screen_of "$output" | head -n 2)" = "$warn" ] || { echo "$output"; return 1; }
  # backup: the warning, a new backup (the next second: this one's folder is still there), and the
  # interrupted one recorded at the end of its own log.
  local old=$ROOT/$(st last_backup.log)
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(screen_of "$output" | head -n 2)" = "$warn" ] || { echo "$output"; return 1; }
  [ "$(bk_pointer)" = backups/custodexa-backup-1.13.0-20260930-101503.tar ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(st last_backup.result)" = succeeded ] || return 1
  # (The fixed clock gives both runs the same log file name.)
  grep -q " END   result=interrupted step=3 recorded_by=logs/backup-$TS.log$" "$old" || { cat "$old"; return 1; }
  grep -q 'PREVIOUS backup result=interrupted step=3' "$ROOT/logs/backup-$TS.log" || return 1
  for k in last_backup.partial last_backup.unfinished_at last_backup.unfinished_partial; do
    [ -z "$(st "$k")" ] || { echo "$k kept"; return 1; }
  done
  # Nothing unfinished any more: start says nothing about it.
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] && [[ $output != *"did not finish"* ]] || { echo "$output"; return 1; }
}

@test "interrupted backup: start does not lift the upgrade refusal; a finished backup does" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host ui || return 1
  kind_package
  clock 0 3 0 41 0 4 0 11
  : >"$DB/tar.audit.sleep"
  interrupt en "$ROOT/custodexa.sh" || return 1
  [ "$RC" -eq 1 ] || { echo "$output"; return 1; }
  rm -f "$DB/tar.audit.sleep"
  run bash "$ROOT/custodexa.sh" start --lang en </dev/null
  [ "$status" -eq 0 ] && [[ $output == "[WARN] The last backup (2026-09-30 10:15) did not finish"* ]] || { echo "$output"; return 1; }
  # The upgrade is refused before anything changes, with the commands to start and to back up.
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  : >"$DB/events"
  full_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output") - <<'EOF' || return 1
[FAIL] The last backup (2026-09-30 10:15) did not finish, and an upgrade
       needs a finished one first. If the services are still stopped, start
       them; then back up again, and upgrade once that backup is done:
  sudo /opt/custodexa/custodexa.sh start --lang en
  sudo /opt/custodexa/custodexa.sh backup --lang en
EOF
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT") || return 1
  ! grep -q '^stop\|^pg_dump\|^up' "$DB/events" || { cat "$DB/events"; return 1; }
  # zh-TW, as reviewed.
  full_run zh-TW
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output") - <<'EOF' || return 1
[FAIL] 上次的備份（2026-09-30 10:15）沒有完成，升級前要先有一份完成的備份。
       服務若仍停著，先啟動；接著重新備份，備份完成後再升級：
  sudo /opt/custodexa/custodexa.sh start --lang zh-TW
  sudo /opt/custodexa/custodexa.sh backup --lang zh-TW
EOF
  # A backup run that is refused before it starts does not lift it either.
  host_free / 1048576
  backup_run en --yes
  [ "$status" -eq 1 ] && [[ $output == *"Not enough space"* ]] || { echo "$output"; return 1; }
  full_run en
  [ "$status" -eq 3 ] && [[ $output == "[FAIL] The last backup (2026-09-30 10:15) did not finish"* ]] || { echo "$output"; return 1; }
  # A finished backup does: the upgrade goes through.
  host_free / 221249536
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(st current.version)" = 1.13.2 ] && [ "$(st last_upgrade.result)" = succeeded ]
}
