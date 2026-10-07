# shellcheck shell=bash
# about: a real backup sent SIGTERM while it packs the audit files (services stopped) and again while the encryption container runs: the script ends, no process it started and no tool container is left, no backup file is made, start brings the services back, and the next backup finishes and records the interrupted one
# needs: package
# images:

readonly IR_PASS='it-test-only passphrase 0007'
readonly IR_FILLER_MB=2048 # incompressible audit data, so that packing it takes long enough to signal
readonly IR_WAIT=600       # tenths of a second to wait for the moment to signal, and for the end

# ir_tree <pid>: "<pid> <args>" of that process and every process under it.
ir_tree() {
  ps -eo pid=,ppid=,args= | awk -v root="$1" '
    { p = $1; par[p] = $2; $1 = ""; $2 = ""; sub(/^ +/, ""); args[p] = $0 }
    END {
      keep[root] = 1
      do { more = 0; for (p in par) if (!(p in keep) && (par[p] in keep)) { keep[p] = 1; more = 1 } } while (more)
      for (p in keep) if (p in args) print p, args[p]
    }'
}

# ir_alive <file of ir_tree lines>: the lines whose process still runs with the same arguments.
ir_alive() {
  local p a now
  while read -r p a; do
    now=$(tr '\0' ' ' 2>/dev/null <"/proc/$p/cmdline" | sed 's/ $//') || continue
    [ "$now" != "$a" ] || printf '%s %s\n' "$p" "$a"
  done <"$1"
}

# ir_until <what> <command...>: poll every tenth of a second, at most IR_WAIT times.
ir_until() {
  local what=$1 i
  shift
  for ((i = 0; i < IR_WAIT; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  printf 'not ok - %s never happened\n' "$what"
  return 1
}

ir_packing_audit() { pgrep -f 'tar -czf .*/backups/\.partial-[0-9-]*/audit\.tar\.gz' >/dev/null; }
ir_encrypting() { [ -n "$(docker ps -q --filter name=custodexa-backup-tool-)" ]; }

# ir_signal <label> <tree file>: SIGTERM to the backup's own process only, as `kill <pid>` sends,
# then wait for it to end. IR_RC is its exit code.
ir_signal() {
  local i
  ir_tree "$IR_PID" >"$2"
  it_say "   $1: $(grep -c . "$2") processes under the backup when signalled:"
  sed 's/^/     /' "$2"
  kill -TERM "$IR_PID"
  for ((i = 0; i < IR_WAIT; i++)); do
    kill -0 "$IR_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$IR_PID" 2>/dev/null; then
    printf 'not ok - %s: the backup still runs %s s after SIGTERM\n' "$1" $((IR_WAIT / 10))
    return 1
  fi
  IR_RC=0
  wait "$IR_PID" || IR_RC=$?
  it_say "   $1: the backup ended with exit $IR_RC; its screen:"
  sed 's/^/     | /' "$IT_WORK/$1.out"
}

# ir_left <label> <tree file>: nothing it started is left.
ir_left() {
  local root=/opt/custodexa
  it_same "$1: no process that ran under the backup is left" "" "$(ir_alive "$2")"
  it_same "$1: no openssl, tar or gzip process is left" "" "$(pgrep -af 'openssl enc|tar -[cx]|gzip' || true)"
  it_same "$1: no tool container is left" "" "$(docker ps -aq --filter name=custodexa-backup-tool-)"
  sleep 3
  it_same "$1: and none 3 s later" "" "$(docker ps -aq --filter name=custodexa-backup-tool-)"
  it_same "$1: no backup file" "" "$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*' -newer "$IT_WORK/mark")"
  it_same "$1: no named pipe" "" "$(find "$root/backups" -type p)"
  it_check "$1: the temporary folder stays, 0700" \
    test "$(stat -c %a "$(find "$root/backups" -maxdepth 1 -name '.partial-*' -newer "$IT_WORK/mark" | head -n1)")" = 700
  it_same "$1: no pg_dump left in the database container" "" "$(docker exec custodexa-postgres pgrep pg_dump || true)"
}

ir_status() { # <label>: what status says after the interruption (recorded; the spec asks status to
  # list an interrupted load, not an interrupted backup)
  local out rc
  out=$(it_cx /opt/custodexa status --lang en) && rc=0 || rc=$?
  it_say "   status after $1 (exit $rc), its WARN and FAIL lines (the services may be stopped):"
  grep -E '\[(WARN|FAIL)\]' <<<"$out" | sed 's/^/     | /' || true
}

scenario() {
  local root=/opt/custodexa t out rc
  it_step "built-in form: install --images $(it_bundle_file)"
  it_unpack /opt
  it_cx "$root" install --images "$(it_bundle_file)"
  head -c "$((IR_FILLER_MB * 1048576))" /dev/urandom >"$root/data/audit/it-filler.bin"
  install -m 600 -o root /dev/null "$IT_WORK/cx-pass"
  printf '%s\n' "$IR_PASS" >"$IT_WORK/cx-pass"

  it_step "SIGTERM while step 3 packs the audit files (the services are stopped)"
  touch "$IT_WORK/mark"
  sleep 1
  t=$(date +%s)
  "$root/custodexa.sh" backup --lang en --yes >"$IT_WORK/at-step-3.out" 2>&1 &
  IR_PID=$!
  ir_until "packing the audit files" ir_packing_audit
  it_say "   packing began $(($(date +%s) - t)) s after the start"
  ir_signal at-step-3 "$IT_WORK/tree-3"
  it_check "at-step-3: exit is not 0" test "$IR_RC" -ne 0
  ir_left at-step-3 "$IT_WORK/tree-3"
  it_check "at-step-3: the screen names the step and the start command" \
    bash -c 'grep -q "interrupted at step 3" "$1" && grep -q "custodexa.sh start" "$1"' _ "$IT_WORK/at-step-3.out"
  ir_status at-step-3

  it_step "start after the interruption"
  out=$(it_cx "$root" start --lang en) && rc=0 || rc=$?
  printf '%s\n' "$out" | sed 's/^/     | /'
  it_check "start exits 0 or 4 (warnings only), got $rc" test "$rc" = 0 -o "$rc" = 4
  it_check "start warns about the interrupted backup" grep -qE 'WARN.*(did not finish|interrupted)' <<<"$out"
  out=$(it_cx "$root" status --lang en) || true
  it_check "the six services run again" grep -q '\[ OK \] 6 service processes started' <<<"$out"

  it_step "SIGTERM while the encryption container runs (step 7)"
  touch "$IT_WORK/mark"
  sleep 1
  "$root/custodexa.sh" backup --lang en --yes --passphrase-file "$IT_WORK/cx-pass" >"$IT_WORK/at-step-7.out" 2>&1 &
  IR_PID=$!
  ir_until "the encryption container" ir_encrypting
  ir_signal at-step-7 "$IT_WORK/tree-7"
  it_check "at-step-7: exit is not 0" test "$IR_RC" -ne 0
  ir_left at-step-7 "$IT_WORK/tree-7"
  it_check "at-step-7: the screen says the backup was interrupted at step 7" grep -q "interrupted at step 7" "$IT_WORK/at-step-7.out"
  ir_status at-step-7

  it_step "the next backup finishes and records the interrupted one"
  rm -f "$root/data/audit/it-filler.bin"
  it_cx "$root" backup --lang en --yes >"$IT_WORK/after.out" 2>&1
  it_check "a backup file is made" test -n "$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark")"
  it_check "its log records the interrupted backup" \
    grep -rq 'PREVIOUS backup result=interrupted' "$(ls -t "$root"/logs/*backup*.log | head -n1)"
  out=$(it_cx "$root" status --lang en) || true
  it_check "status shows the new backup file" \
    grep -qF "$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark" -printf '%f')" <<<"$out"
}
