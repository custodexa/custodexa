#!/usr/bin/env bats
# Threat (A): an upgrade whose backup cannot bring the deployment back. Step 7 makes the same
# portable backup file as the backup command (the recordings, state.json as the upgrade found it,
# not encrypted), the checks after the start compare with a snapshot kept outside that file, an
# external database is exported by a client of its own major version (obtained and checked before
# the server is probed), and whatever the script cannot back up is refused before any service
# stops. A backup file that is missing a part, a check that compares with nothing, a client used
# before it was checked, or a stop before a refusal would each show here as a failed assertion.

load helper
load install_host
load backup_host
load upgrade_host
load pty_host

LOG_TS=20260930-101502
UP_FILE=backups/custodexa-backup-1.13.0-20260930-101502.tar

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }
from_line() { screen_of "$output" | sed -n "/^$(printf '%s' "$1" | sed 's/[][\/.*]/\\&/g')/,\$p"; }
stopped_all_after_up() { grep -A99 -x up "$DB/events" | grep -qx stop-all; }

# at <regex>: the line of the first event matching it (0 when none); last_at: of the last one.
at() {
  local n
  n=$(grep -n -m1 -E "$1" "$DB/events" | cut -d: -f1)
  printf '%s' "${n:-0}"
}
last_at() {
  local n
  n=$(grep -n -E "$1" "$DB/events" | tail -n1 | cut -d: -f1)
  printf '%s' "${n:-0}"
}

# no_stop: no service was stopped and no backup file was made.
no_stop() {
  ! grep -q '^stop\|^up$\|^stop-all$' "$DB/events" || { cat "$DB/events"; return 1; }
  ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || { ls -lA "$ROOT/backups"; return 1; }
}

# fresh: the bundled deployment of upgraded_host, the clock at the start, no event yet.
fresh() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host "${1:-ui}" || return 1
  clock 0 3 0 41 0 4 0 11
  : >"$DB/events"
  : >"$FAKE_DOCKER_LOG"
}

# The answers of an own backup taken after the stop (02:16:13 UTC).
OWN_ANSWERS=("> " vm-snap-0218 "> " "2026-09-30 02:18" "> " /doc "> " yes)

the_log() { printf '%s' "$ROOT/logs/upgrade-$LOG_TS.log"; }

# first_call <text>: the line of the first docker call containing it (0 when none). Step 2 starts
# with the backend image by its digest (STEP2_MARK); the checks before it ask for the installed
# version's images by their tags.
first_call() {
  local n
  n=$(grep -n -m1 -F -- "$1" "$FAKE_DOCKER_LOG" | cut -d: -f1)
  printf '%s' "${n:-0}"
}
STEP2_MARK='image inspect --format {{.Id}} ghcr.io/custodexa/backend@'


# snapshot_beside_log: the log names the snapshot beside it, and it is there.
snapshot_beside_log() {
  grep -q "SNAPSHOT file=logs/upgrade-$LOG_TS.before.txt usable=" "$(the_log)" || { grep SNAPSHOT "$(the_log)"; return 1; }
  [ -s "$ROOT/logs/upgrade-$LOG_TS.before.txt" ] || { ls -lA "$ROOT/logs"; return 1; }
}

# ---------- step 7: one portable backup file ----------

@test "upgrade backup: a portable backup file with recordings and state.json, not encrypted; the checks after compare with the snapshot kept outside it" {
  fresh ui
  cp -p "$ROOT/state.json" "$BATS_TEST_TMPDIR/state-before"
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  [ "$(st last_upgrade.backup)" = "$UP_FILE" ] && [ -f "$BK_FILE" ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(stat -c %a "$BK_FILE")" = 600 ] || return 1
  [ "$(bk_mf trigger)" = upgrade ] && [ "$(bk_mf encryption.enabled)" = false ] || return 1
  [ "$(bk_mf contents.recordings)" = true ] && [ "$(bk_mf contents.state)" = true ] || return 1
  bk_member recordings.tar.gz | /usr/bin/tar -tzf - | grep -q 'a.cast$' || return 1
  # state.json as the upgrade found it, byte for byte.
  cmp "$BATS_TEST_TMPDIR/state-before" <(bk_member state.json) || return 1
  # The snapshot the checks compared with is beside the log, the same as the one in the file.
  snapshot_beside_log || return 1
  cmp "$ROOT/logs/upgrade-$LOG_TS.before.txt" <(bk_member snapshot.txt) || return 1
  [[ $output == *"[ OK ] Same data       42 users and 18,305 connection records, as"* ]] || { echo "$output"; return 1; }
  # The services stay stopped while the file is made: no start between the stop and the new version.
  sed -n "$(at '^stop backend'),$(at '^up$')p" "$DB/events" | { ! grep -q '^start'; } || { cat "$DB/events"; return 1; }
  [ "$(at "^tar pack ${UP_FILE#backups/}")" -lt "$(at '^up$')" ] || { cat "$DB/events"; return 1; }
  ! compgen -G "$ROOT/backups/.partial-*" >/dev/null
}

@test "upgrade backup: the checks after the start read the snapshot beside the log: the same data, an emptied database, a missing migration, another KEK" {
  fresh ui
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] Keys            all four key fingerprints are unchanged"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] Same data       42 users and 18,305 connection records, as"* ]] || { echo "$output"; return 1; }
  snapshot_beside_log || return 1
  # Users down from 42 to 1 and no baseline line in the log: an empty database, everything stopped.
  fresh ui
  printf '1\n' >"$UP/after.count.users"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The new version found an empty database. All services were"* ]] \
    || { echo "$output"; return 1; }
  stopped_all_after_up || { cat "$DB/events"; return 1; }
  snapshot_beside_log || return 1
  # One migration of before missing afterwards.
  fresh ui
  printf '%s\n' 20260816_schema_baseline 20261010_report_schedule >"$UP/after.migrations"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] Database        structure versions from before are missing:"* ]] \
    || { echo "$output"; return 1; }
  snapshot_beside_log || return 1
  # The KEK fingerprint changed.
  fresh ui
  printf '%s\n' 'sha256:1111' >"$UP/after.kek"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] Keys            a key fingerprint differs from before the upgrade"* ]] \
    || { echo "$output"; return 1; }
  snapshot_beside_log
}

@test "upgrade backup: the second upgrade in a row keeps state.json of the version it came from (current 1.13.2, previous 1.13.0)" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_twice_host ui || return 1
  [ "$(st current.version)" = 1.13.2 ] && [ "$(st previous.version)" = 1.13.0 ] || { cat "$ROOT/state.json"; return 1; }
  cp -p "$ROOT/state.json" "$BATS_TEST_TMPDIR/state-before"
  printf '{"status":"ok","version":"1.16.0"}\n' >"$UP/health"
  clock 0 3 0 41 0 4 0 11
  run bash "$ROOT/releases/1.16.0/custodexa.sh" upgrade --lang en --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  [ -f "$BK_FILE" ] && [[ $BK_FILE == */custodexa-backup-1.13.2-* ]] || { cat "$ROOT/state.json"; return 1; }
  cmp "$BATS_TEST_TMPDIR/state-before" <(bk_member state.json) || return 1
  [ "$(bk_member state.json | jq -r '."current.version"')" = "$(bk_mf product.version)" ] || return 1
  [ "$(bk_mf product.version)" = 1.13.2 ] || return 1
  [ "$(bk_member state.json | jq -r '."previous.version"')" = 1.13.0 ] || return 1
  [ "$(st current.version)" = 1.16.0 ] && [ "$(st previous.version)" = 1.13.2 ]
}

@test "upgrade backup (bundled): the dump tool is the old release's postgres, its digest from release-MANIFEST.json, not tool-MANIFEST.json" {
  fresh ui
  # The old release's postgres runs the export (its reference among the images the services run).
  printf 'CUSTODEXA_IMAGE_POSTGRES=docker.io/library/postgres@%s\n' "$BK_PG_DIGEST" >>"$ROOT/current/images.env"
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'case " $* " in
  *" exec -T postgres pg_dump --version "*) ;;
  *" exec -T postgres pg_dump "*) printf "%s\n" "${CUSTODEXA_IMAGE_POSTGRES:-}" >>"$DB/dump-image" ;;
esac'
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  local d
  d=$(bk_mf tool.dump_image_digest)
  [ "$(bk_mf tool.dump_manifest)" = release ] && [ "$(bk_mf tool.dump_image)" = postgres ] || return 1
  [ "$d" = "$(bk_member release-MANIFEST.json | jq -r .images.postgres.index_digest)" ] && [ "$d" = "$BK_PG_DIGEST" ] || return 1
  [ "$d" != "$(bk_member tool-MANIFEST.json | jq -r .images.postgres.index_digest)" ] || return 1
  cmp <(bk_member tool-MANIFEST.json) "$ROOT/releases/1.13.2/MANIFEST.json" || return 1
  # The container that ran the export is that image.
  [ "$(sort -u "$DB/dump-image")" = "docker.io/library/postgres@$d" ] || { cat "$DB/dump-image"; return 1; }
}

# The commit point of step 7: the file is put in place whole and recorded before the switch, or the
# upgrade stops there with the old version's start command.
@test "upgrade backup: packing or reading the file back fails: no backup file, nothing recorded, never switched" {
  local sw
  for sw in tar.pack.rc tar.readback.rc; do
    fresh ui
    printf '1\n' >"$DB/$sw"
    full_run en
    [ "$status" -eq 1 ] || { echo "$sw: $output"; return 1; }
    printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
    ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || { ls -lA "$ROOT/backups"; return 1; }
    [ -z "$(st last_backup.file)" ] && [ -z "$(st last_upgrade.backup)" ] || { cat "$ROOT/state.json"; return 1; }
    [ "$(st last_upgrade.step)" = 7 ] && [ "$(readlink "$ROOT/current")" = releases/1.13.0 ] || return 1
    ! grep -qx up "$DB/events" || { cat "$DB/events"; return 1; }
  done
}

# ---------- an external database ----------

@test "upgrade (external, first to this release): the clients are obtained and checked before the probe, the probe before the space estimate; [1]/[2] at step 7" {
  local how out
  for how in online offline; do
    fresh_ext "$how"
    out=$BATS_TEST_TMPDIR/screen-$how
    pty_up "$out" -- "[y/N] " y "Choose [1/2]: " 1 || { echo "$how"; pty_screen "$out"; return 1; }
    pty_screen "$out" | grep -qF '[1] Let the script make a full backup (recommended)' || { pty_screen "$out"; return 1; }
    pty_screen "$out" | grep -qF '[2] Use my own backup' || return 1
    case $how in
      online)
        [ "$(at '^pull pgclient')" -gt 0 ] || { cat "$DB/events"; return 1; }
        ! grep -q '^load$' "$DB/events" || return 1
        [ "$(last_at '^pull pgclient')" -lt "$(at '^psql ')" ] || { cat "$DB/events"; return 1; }
        ;;
      offline)
        [ "$(at '^load$')" -gt 0 ] || { cat "$DB/events"; return 1; }
        ! grep -q '^pull ' "$DB/events" || { cat "$DB/events"; return 1; }
        ! grep -q 'pull .*postgres-client' "$FAKE_DOCKER_LOG" || return 1
        [ "$(at '^load$')" -lt "$(at '^psql ')" ] || { cat "$DB/events"; return 1; }
        ;;
    esac
    # The first database call is the probe (the server's version), the space estimate after it.
    [ "$(at '^psql ')" = "$(at '^psql server_version_num$')" ] || { cat "$DB/events"; return 1; }
    [ "$(at '^psql server_version_num$')" -lt "$(at '^psql size$')" ] || { cat "$DB/events"; return 1; }
    [ "$(at '^psql size$')" -lt "$(at '^stop backend')" ] || { cat "$DB/events"; return 1; }
    # The probe ran on the client checked a moment before (the highest major), by its ID.
    grep -q " $(pgc_id 18) psql server_version_num$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
    [ "$(st last_upgrade.result)" = succeeded ] || { pty_screen "$out"; return 1; }
  done
}

@test "upgrade backup (external): choice [1] exports the external database with the pinned client of its major into a portable file" {
  fresh_ext online 17.6
  pty_up "$BATS_TEST_TMPDIR/screen" -- "[y/N] " y "Choose [1/2]: " 1 || { pty_screen "$BATS_TEST_TMPDIR/screen"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  [ "$(st last_upgrade.backup)" = "$UP_FILE" ] && [ -f "$BK_FILE" ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(bk_mf trigger)" = upgrade ] && [ "$(bk_mf db.location)" = external ] || return 1
  [ "$(bk_mf tool.dump_image)" = pgclient17 ] && [ "$(bk_mf tool.dump_manifest)" = tool ] || return 1
  [ "$(bk_mf tool.dump_image_digest)" = "$(jq -r .images.pgclient17.index_digest "$ROOT/releases/1.13.2/MANIFEST.json")" ] || return 1
  [ "$(bk_mf db.server_major)" = 17 ] && [ "$(bk_mf db.external_host)" = db.example.internal ] || return 1
  # The export ran in the client of the server's major, checked at the start; none in a service.
  grep -q " $(pgc_id 17) pg_dump$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  ! grep -q " $(pgc_id 16) pg_dump$\| $(pgc_id 18) pg_dump$" "$DB/db-runs" || return 1
  ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG" || return 1
  # The client images are recorded as the tools of the new version.
  [[ " $(st current.tool_image_ids) " == *" pgclient17=$(pgc_id 17) "* ]] || { cat "$ROOT/state.json"; return 1; }
  [ "$(st current.version)" = 1.13.2 ]
}

@test "upgrade (external, client available): step 7 offers [1] and [2]; [2] lists a full backup of the external database" {
  fresh_ext online
  pty_up "$BATS_TEST_TMPDIR/screen" -- "[y/N] " y "Choose [1/2]: " 2 "${OWN_ANSWERS[@]}" \
    || { pty_screen "$BATS_TEST_TMPDIR/screen"; return 1; }
  local s
  s=$(pty_screen "$BATS_TEST_TMPDIR/screen")
  [[ $s == *"[1] Let the script make a full backup (recommended)"* && $s == *"[2] Use my own backup"* ]] || { echo "$s"; return 1; }
  [[ $s == *"    Database         a full backup of the external database taken
                     after 02:16:13"* ]] || { echo "$s"; return 1; }
  [ "$(st last_backup.kind)" = external ] && [ "$(st last_upgrade.result)" = succeeded ] || { cat "$ROOT/state.json"; return 1; }
  ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || return 1
  # The snapshot for the checks was taken through the client all the same.
  [ -s "$ROOT/$(st last_upgrade.backup)/snapshot.txt" ] || { ls -lAR "$ROOT/backups"; return 1; }
  [[ $s == *"[ OK ] Same data       42 users and 18,305 connection records, as"* ]] || { echo "$s"; return 1; }
}

@test "upgrade (external, PostgreSQL 15, on a terminal): the preview says why, step 7 takes the operator's own backup only" {
  fresh_ext online 15.8
  pty_up "$BATS_TEST_TMPDIR/screen" -- "[y/N] " y "${OWN_ANSWERS[@]}" || { pty_screen "$BATS_TEST_TMPDIR/screen"; return 1; }
  local s
  s=$(pty_screen "$BATS_TEST_TMPDIR/screen")
  [[ $s == *"
  [WARN] The script cannot back up the external database this time: it runs
         PostgreSQL 15.8, and this release has no export tool of that major
         version. Step 7 can only take your own backup.

Start the upgrade? [y/N] y"* ]] || { echo "$s"; return 1; }
  [[ $s == *"  2. The script cannot back up the external database this time (see
     below); after the stop you confirm a backup of your own taken
     after the stop"* ]] || { echo "$s"; return 1; }
  [[ $s != *"Choose [1/2]"* ]] || { echo "$s"; return 1; }
  [[ $s == *"a full backup of the external database"* ]] || { echo "$s"; return 1; }
  [ "$(st last_backup.kind)" = external ] && [ "$(st last_upgrade.result)" = succeeded ] || { cat "$ROOT/state.json"; return 1; }
  # Neither an export nor a step-6 query: no client was chosen.
  ! grep -q ' pg_dump$\| psql connections$' "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  [[ $s == *"[WARN]  6/13"* ]] || { echo "$s"; return 1; }
}

@test "upgrade (external) --yes without --backup-ref on PostgreSQL 15: refused before any stop, the four steps in order" {
  fresh_ext online 15.8
  full_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(from_line '[FAIL] The script cannot back up the external database') "$TESTS_DIR/snapshots/upgrade-external-refused.en.txt" \
    || { echo "$output"; return 1; }
  no_stop || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.13.0 ] && [ -z "$(st last_upgrade.result)" ] || { cat "$ROOT/state.json"; return 1; }
  # On a terminal, --yes asks nothing either: the same refusal.
  fresh_ext online 15.8
  local rc=0
  pty_up "$BATS_TEST_TMPDIR/screen" --yes || rc=$?
  [ "$rc" -eq 3 ] || { pty_screen "$BATS_TEST_TMPDIR/screen"; return 1; }
  diff <(pty_screen "$BATS_TEST_TMPDIR/screen" | sed -n '/^\[FAIL\] The script cannot back up the external database/,$p') \
    "$TESTS_DIR/snapshots/upgrade-external-refused.en.txt" || return 1
  no_stop
}

# log_path_of <text>: the log file the screen names (its "Log file" line).
log_path_of() { printf '%s\n' "$1" | sed -n 's/^  Log file \(.*\.log\)$/\1/p'; }

@test "upgrade (external, server unreachable, on a terminal): the reason the preview points to the log for is in the upgrade's log" {
  fresh_ext online 17.6
  printf '2\n' >"$DB/connect.rc"
  pty_up "$BATS_TEST_TMPDIR/screen" -- "[y/N] " y "${OWN_ANSWERS[@]}" || { pty_screen "$BATS_TEST_TMPDIR/screen"; return 1; }
  local s
  s=$(pty_screen "$BATS_TEST_TMPDIR/screen")
  [[ $s == *"[WARN] The script cannot back up the external database this time: it"*"the reason is in the log file."* ]] \
    || { echo "$s"; return 1; }
  [ "$(st last_upgrade.result)" = succeeded ] && [ "$(st last_upgrade.log)" = "logs/upgrade-$LOG_TS.log" ] \
    || { cat "$ROOT/state.json"; return 1; }
  # The checks before the preview wrote the reason; it is in the run's log, ahead of its BEGIN line.
  local check fail begin
  check=$(grep -n -m1 'CHECK external database: the script cannot back it up this time: connect' "$(the_log)" | cut -d: -f1)
  fail=$(grep -n -m1 -F 'OUT   psql: error: connection to server at "db.example.internal" (10.0.0.5), port 5432 failed' "$(the_log)" | cut -d: -f1)
  begin=$(grep -n -m1 ' BEGIN upgrade ' "$(the_log)" | cut -d: -f1)
  [ -n "$check" ] && [ -n "$fail" ] && [ -n "$begin" ] && [ "$fail" -lt "$check" ] && [ "$check" -lt "$begin" ] \
    || { cat "$(the_log)"; return 1; }
}

@test "upgrade (external) --yes, server unreachable: the refusal names a log of its own that holds the reason; state.json untouched" {
  fresh_ext online 17.6
  printf '2\n' >"$DB/connect.rc"
  local before log
  before=$(cat "$ROOT/state.json")
  full_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The script cannot back up the external database (it cannot be"*"the reason is in the log file"* ]] \
    || { echo "$output"; return 1; }
  log=$(log_path_of "$output")
  [ "$log" = "$ROOT/logs/upgrade-$LOG_TS.log" ] && [ -f "$log" ] || { echo "$output"; ls -lA "$ROOT/logs"; return 1; }
  grep -q 'CHECK external database: the script cannot back it up this time: connect' "$log" || { cat "$log"; return 1; }
  grep -qF 'OUT   psql: error: connection to server at "db.example.internal" (10.0.0.5), port 5432 failed' "$log" \
    || { cat "$log"; return 1; }
  grep -q ' END   result=refused step=1$' "$log" || { cat "$log"; return 1; }
  [ "$(stat -c %a "$log")" = 600 ] || { stat -c %a "$log"; return 1; }
  [ "$(cat "$ROOT/state.json")" = "$before" ] || { diff <(printf '%s\n' "$before") "$ROOT/state.json"; return 1; }
  no_stop
}

@test "upgrade (external): following the four steps of the refusal, the run with --backup-ref is accepted; a backup older than the stop is not" {
  local t
  for t in '2026-09-30 02:17' '2026-09-30 02:15'; do
    fresh_ext online 15.8
    full_run en
    [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    # 1 and 2: the operator drained and stopped the services, and status shows them stopped.
    printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
    echo stopped >"$DB/svc"
    # 3: the own backup started at $t. 4: the command of step 4, with the three options.
    printf '%s\n' "$output" | grep -qxF "       sudo $ROOT/custodexa.sh upgrade 1.13.2 --yes \\" || { echo "$output"; return 1; }
    : >"$DB/events"
    : >"$DB/db-runs"
    clock 0 3 0 41 0 4 0 11
    run bash "$ROOT/custodexa.sh" upgrade 1.13.2 --lang en --yes --backup-ref vm-snap-0217 --backup-time "$t" \
      --backup-restore /doc </dev/null
    if [ "$t" = '2026-09-30 02:17' ]; then
      [ "$status" -eq 0 ] || { echo "$output"; return 1; }
      [[ $output == *"[SKIP]  8/13"* && $output == *"[ OK ] 13/13"* ]] || { echo "$output"; return 1; }
      [ "$(st last_backup.kind)" = external ] && [ "$(st last_backup.external_ref)" = vm-snap-0217 ] || { cat "$ROOT/state.json"; return 1; }
    else
      [ "$status" -ne 0 ] && [[ $output == *"[FAIL] The snapshot time 02:15 is before the stop time 02:16:13"* ]] \
        || { echo "$output"; return 1; }
      no_stop || return 1
      [ "$(st current.version)" = 1.13.0 ] || return 1
    fi
  done
}

@test "upgrade (external) --backup-ref: no early client and no probe; the clients are obtained once, with the other images" {
  fresh_ext online 17.6
  printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
  full_run en --backup-ref vm-snap-0217 --backup-time '2026-09-30 02:17' --backup-restore /doc
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ ! -s "$DB/db-runs" ] || { cat "$DB/db-runs"; return 1; }
  ! grep -q '^psql ' "$DB/events" || { cat "$DB/events"; return 1; }
  [[ $output == *"  2. Use the backup of your own given with --backup-ref; the script
     makes none this time"* ]] || { echo "$output"; return 1; }
  # The clients are first asked for in step 2, after the first of the other images.
  [ "$(first_call 'image inspect --format {{.Id}} docker.io/library/postgres-client-')" -gt "$(first_call "$STEP2_MARK")" ] \
    || { grep -n 'postgres-client\|custodexa/backend@' "$FAKE_DOCKER_LOG"; return 1; }
  # Without --backup-ref they are obtained before the probe, ahead of the other images.
  fresh_ext online 17.6
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(first_call 'image inspect --format {{.Id}} docker.io/library/postgres-client-')" -lt "$(first_call "$STEP2_MARK")" ] \
    || { grep -n 'postgres-client\|custodexa/backend@' "$FAKE_DOCKER_LOG"; return 1; }
}

# ---------- the backup's path on the closing and failure screens ----------

@test "upgrade backup: the closing screen and a failure after the switch name the backup file; last_upgrade.backup and last_backup.file point at it" {
  local l
  for l in zh-TW en; do
    fresh ui
    full_run "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(from_line "$(sed -n 1p "$TESTS_DIR/snapshots/s11.$l.txt")") "$TESTS_DIR/snapshots/s11.$l.txt" || { echo "$output"; return 1; }
    [ "$(st last_upgrade.backup)" = "$UP_FILE" ] && [ "$(st last_backup.file)" = "$UP_FILE" ] && [ -f "$ROOT/$UP_FILE" ] \
      || { cat "$ROOT/state.json"; return 1; }
  done
  # Steps 9 to 12 each fail after the backup: the same file on record and on the screen.
  local sw
  for sw in switch start ready check; do
    fresh ui
    case $sw in
      switch) hook_before 'case " $* " in *" run "*" --entrypoint /bin/sh "*) exit 1 ;; esac' ;;
      start) touch "$UP/up.rc" ;;
      ready) touch "$UP/health.rc" ;;
      check) printf '%s\n' 20260816_schema_baseline 20261010_report_schedule >"$UP/after.migrations" ;;
    esac
    full_run en
    [ "$status" -eq 1 ] || { echo "$sw: $output"; return 1; }
    [ "$(st last_upgrade.backup)" = "$UP_FILE" ] && [ "$(st last_backup.file)" = "$UP_FILE" ] && [ -f "$ROOT/$UP_FILE" ] \
      || { echo "$sw"; cat "$ROOT/state.json"; return 1; }
    [[ $output == *"$ROOT/$UP_FILE"* ]] || { echo "$sw: $output"; return 1; }
    if [ "$sw" = ready ]; then
      diff <(from_line '[FAIL] The upgrade stopped at step 11/13') "$TESTS_DIR/snapshots/s12c.en.txt" || { echo "$output"; return 1; }
    fi
  done
}

# ---------- the checks before the preview ----------

# du_is <path> <bytes>: what du reports for that folder of the deployment.
du_is() { printf '%s\n' "$2" >"$DB/du.$(printf '%s' "$ROOT/$1" | tr / -)"; }

@test "upgrade (external): the space for the backup file is checked; one byte short is refused before any stop" {
  fresh_ext online 17.6
  # The need: the file (database 18,683,107,737 bytes, recordings, audit and tls/ 1,000 bytes each),
  # its largest member (the database) again and 1 GB, plus the images (seven of 1,000 bytes, three
  # times over): 38,439,981,298 bytes. 37,539,045 KiB are free: 782 bytes more than that.
  du_is data/recordings 1000
  du_is tls 1000
  host_free / 37539045
  du_is data/audit 1782
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  [[ $output == *"Custodexa upgrade preview"* ]] || { echo "$output"; return 1; }
  # One byte more than the free space: refused before the preview.
  du_is data/audit 1783
  : >"$DB/events"
  : >"$DB/db-runs"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en --yes </dev/null
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] Not enough space for the backup:"* ]] || { echo "$output"; return 1; }
  [[ $output != *"Custodexa upgrade preview"* ]] || return 1
  # The estimate asked the external database (through the client) for its size.
  grep -q " $(pgc_id 17) psql size$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  no_stop
}

@test "upgrade (external): the preview's downtime counts packing and reading the file back (27 to 54 minutes, 15 to 30 before)" {
  fresh_ext online 17.6
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  # 18,683,107,737 bytes of database at 25 MiB/s: 12 minutes to take the data, as many again to
  # pack and read back the file, then 3 to switch and start; up to twice that.
  [[ $output == *"  - Expect 27 to 54 minutes of downtime. Nobody can connect meanwhile,
    and open connections will be cut (2 are open now)"* ]] || { echo "$output"; return 1; }
  [[ $output == *"certificates. About 35.8 GB; 211 GB free where backups go"* ]] || { echo "$output"; return 1; }
  # The query for the connections in progress went through the client.
  grep -q " $(pgc_id 17) psql count.active$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
}

# tpl_env <value>: TLS_NGINX_TEMPLATE in .env.
tpl_env() { printf 'TLS_NGINX_TEMPLATE=%s\n' "$1" >>"$ROOT/.env"; }

@test "upgrade backup: TLS_NGINX_TEMPLATE goes into the upgrade's backup file; a missing template is refused before any stop" {
  fresh ui
  mkdir -p "$ROOT/custom"
  printf 'server { listen 443 ssl; } # custom\n' >"$ROOT/custom/proxy.conf.template"
  tpl_env ./custom/proxy.conf.template
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  cmp "$ROOT/custom/proxy.conf.template" <(bk_member nginx-tls.conf.template) || return 1
  [ "$(bk_mf contents.nginx_template)" = true ] && [ "$(bk_mf source.tls_nginx_template)" = ./custom/proxy.conf.template ] || return 1
  # Not set: no member, false and empty.
  fresh ui
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  ! /usr/bin/tar -tf "$BK_FILE" | grep -qx nginx-tls.conf.template || return 1
  [ "$(bk_mf contents.nginx_template)" = false ] && [ "$(bk_mf source.tls_nginx_template)" = "" ] || return 1
  # Missing, and a path the manifest cannot hold: refused before the preview with the exit code of
  # the other refusals there (3), nothing stopped; with --backup-ref no file is made and the
  # template is not checked.
  local c
  for c in missing backslash; do
    fresh ui
    mkdir -p "$ROOT/custom"
    case $c in
      missing) tpl_env ./custom/gone.template ;;
      backslash)
        printf 'x\n' >"$ROOT/custom/a\\b.template"
        tpl_env './custom/a\b.template'
        ;;
    esac
    full_run en
    [ "$status" -eq 3 ] || { echo "$c: $output"; return 1; }
    case $c in
      missing) [[ $output == *"[FAIL] TLS_NGINX_TEMPLATE in .env names $ROOT/custom/gone.template,"* ]] ;;
      backslash) [[ $output == *"[FAIL] TLS_NGINX_TEMPLATE in .env is ./custom/a\\b.template,"* ]] ;;
    esac || { echo "$output"; return 1; }
    [[ $output != *"Custodexa upgrade preview"* ]] || return 1
    no_stop || return 1
    ! grep -q ' stop ' "$FAKE_DOCKER_LOG" || return 1
    printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
    clock 0 3 0 41 0 4 0 11
    TZ=UTC full_run en --backup-ref vm-snap-0217 --backup-time '2026-09-30 02:17' --backup-restore /doc
    [ "$status" -eq 0 ] || { echo "$c, --backup-ref: $output"; return 1; }
  done
}

# As the backup command checks them: the backup file records the data's version and the master key mode, so they are checked before the
# stop too, not when the file is written at step 7.
@test "upgrade backup: the data's version and a master key setting the backup refuses are refused before any stop" {
  fresh ui
  sed -i 's/"version": "1.13.0"/"version": "1.13.1"/' "$ROOT/releases/1.13.0/MANIFEST.json"
  full_run en
  [ "$status" -eq 3 ] && [[ $output == *"[FAIL] state.json says 1.13.0 is installed, but current/MANIFEST.json is"* ]] \
    || { echo "$output"; return 1; }
  [[ $output != *"Custodexa upgrade preview"* ]] || return 1
  no_stop || return 1
  fresh ui
  bk_dotenv_raw KEK_PROVIDER=ui "ENCRYPTION_KEY=$BK_KEK"
  full_run en
  [ "$status" -eq 3 ] && [[ $output == *"[FAIL] "* && $output != *"Custodexa upgrade preview"* ]] || { echo "$output"; return 1; }
  no_stop
}

# ---------- step 6 on an external database ----------

@test "upgrade step 6 (external, a client chosen): asked through the client; connections left FAIL as before" {
  fresh_ext online 17.6
  printf '3\n' >"$DB/connections"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL]  6/13"* ]] || { echo "$output"; return 1; }
  [[ $output == *"After the stop, the application account still has 3"* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qF "psql -h db.example.internal -p 5432 -U custodexa_app -d custodexa \\" || { echo "$output"; return 1; }
  [[ $output != *"exec -T postgres"* ]] || { echo "$output"; return 1; }
  grep -q " $(pgc_id 17) psql connections$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG" || return 1
  [ "$(st last_upgrade.step)" = 6 ] && ! grep -qx up "$DB/events" || return 1
  printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
  # No connection left: OK, through the client too.
  fresh_ext online 17.6
  full_run en
  [ "$status" -eq 0 ] && [[ $output == *"[ OK ]  6/13"* ]] || { echo "$output"; return 1; }
  grep -q " $(pgc_id 17) psql connections$" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
}

@test "upgrade step 6 (external, no client: own backup): WARN and go on, never exec postgres" {
  fresh_ext online 17.6
  printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
  full_run en --backup-ref vm-snap-0217 --backup-time '2026-09-30 02:17' --backup-restore /doc
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN]  6/13  Old version stopped (its services are stopped; the
              script cannot count connections on the external"* ]] || { echo "$output"; return 1; }
  grep -q 'CHECK old instance connections=unchecked' "$(the_log)" || return 1
  ! grep -q 'exec -T postgres\|--entrypoint psql' "$FAKE_DOCKER_LOG" || { grep 'exec -T postgres\|--entrypoint psql' "$FAKE_DOCKER_LOG"; return 1; }
  [ ! -s "$DB/db-runs" ] || { cat "$DB/db-runs"; return 1; }
  [ "$(st last_upgrade.result)" = succeeded ]
}

# The query and the screen of a connection left are those of the releases before this change.
@test "upgrade step 6 (bundled): the same query through the postgres service, after the stop and before the backup; connections left FAIL as before" {
  fresh ui
  full_run en
  [ "$status" -eq 0 ] && [[ $output == *"[ OK ]  6/13  Confirm the old version has fully stopped"* ]] || { echo "$output"; return 1; }
  local q='exec -T postgres psql -U postgres -d custodexa -AtX -v ON_ERROR_STOP=1 -c SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND usename = current_user AND pid <> pg_backend_pid()'
  local stop query dump
  stop=$(grep -n -m1 'compose .* stop backend guacd frontend' "$FAKE_DOCKER_LOG" | cut -d: -f1)
  query=$(grep -n -m1 -F "$q" "$FAKE_DOCKER_LOG" | cut -d: -f1)
  dump=$(grep -n -m1 'exec -T postgres pg_dump ' "$FAKE_DOCKER_LOG" | cut -d: -f1)
  [ -n "$stop" ] && [ -n "$query" ] && [ -n "$dump" ] && [ "$stop" -lt "$query" ] && [ "$query" -lt "$dump" ] \
    || { grep -n 'pg_stat_activity\|stop backend\|pg_dump' "$FAKE_DOCKER_LOG"; return 1; }
  grep -q 'CHECK old instance connections=0' "$(the_log)" || return 1
  fresh ui
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'case " $* " in *" psql "*pg_stat_activity*) echo 2; exit 0 ;; esac'
  full_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(from_line '[FAIL]  6/13' | sed -n '1,/AND pid <> pg_backend_pid()"$/p') - <<'EOF' || { echo "$output"; return 1; }
[FAIL]  6/13  After the stop, the application account still has 2
              connections to the database
  An old backend may still run on another host or under another
  compose project, or its connection is not reclaimed yet. The
  upgrade stopped here; the services stay stopped. Find it and stop
  it until the query below reads 0:
    sudo docker compose -p custodexa -f /opt/custodexa/current/compose.yml exec -T postgres \
      psql -U postgres -d custodexa -tAc "SELECT count(*) FROM pg_stat_activity
      WHERE datname = current_database() AND usename = current_user
      AND pid <> pg_backend_pid()"
EOF
}
