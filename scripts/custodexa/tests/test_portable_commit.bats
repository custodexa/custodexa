#!/usr/bin/env bats
# Threat (A): a backup file under its final name that is not whole, or a record that points at the
# wrong backup. The file gets its final name only after it was read back whole; that link is the
# commit point. A failure before it leaves no file under a final name and the previous record as
# it was; a failure after it says the file is valid and what was left undone. An interruption is
# told the same way, from what is on disk. Every kind of record (a portable file, a backup folder,
# the operator's own backup) replaces the others' pointers, so status never pairs one backup's
# time with another's path.

load helper
load install_host
load backup_host

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  clock
  FIRST=backups/custodexa-backup-1.13.0-20260930-101502.tar
  NEXT=backups/custodexa-backup-1.13.0-20260930-101503.tar
  OUT=$BATS_TEST_TMPDIR/out
}

# first_backup: one backup made and recorded, the one a failed second run must leave in place.
first_backup() {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(bk_pointer)" = "$FIRST" ] || { echo "first not recorded"; return 1; }
  : >"$DB/events"
}

# made <yes|no>: the second backup file and its checksum file are in backups/, or neither is.
made() {
  if [ "$1" = yes ]; then
    [ -f "$ROOT/$NEXT" ] && [ -f "$ROOT/$NEXT.sha256" ] || { ls -lA "$ROOT/backups"; return 1; }
    (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "${NEXT#backups/}.sha256") || return 1
  else
    [ ! -e "$ROOT/$NEXT" ] && [ ! -e "$ROOT/$NEXT.sha256" ] || { ls -lA "$ROOT/backups"; return 1; }
  fi
}

# before_commit: the screen of a failure at step 7, the services started, no backup file made.
before_commit() {
  [ "$status" -eq 1 ] || { echo "$status: $output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\] 7\/7/,$p') - <<'EOF'
[FAIL] 7/7  Build the single file and read it back

[FAIL] The backup did not finish and no backup file was made. What was
       taken so far is in /opt/custodexa/backups/.partial-20260930-101503/;
       it cannot be restored from and holds sensitive plaintext. Delete it
       once you know the cause.
  [WARN] The services are started and waiting to be unsealed: enter the
         master key at https://10.0.0.12/unseal
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
}

# after_commit <text after "[FAIL] ">: the screen of a committed file whose follow-up failed.
after_commit() {
  [ "$status" -eq 1 ] || { echo "$status: $output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[WARN\] The backup file is valid:/,$p') - <<EOF
[WARN] The backup file is valid:
  /opt/custodexa/$NEXT
  Checksum file ${NEXT#backups/}.sha256 (same folder)
[FAIL] $1
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
}

@test "commit: a failure building the file, hashing it, or putting either file in place leaves no file and the record as it was" {
  local sw
  for sw in tar.pack.rc sha256.rc ln.sidecar.rc ln.file.rc; do
    rm -rf "$ROOT/backups" "$ROOT/state.json.prev" "$DB"/*.rc
    first_backup || return 1
    printf '2\n' >"$DB/$sw"
    backup_run en --yes
    before_commit || { echo "[$sw]"; return 1; }
    made no || { echo "[$sw]"; return 1; }
    [ "$(bk_pointer)" = "$FIRST" ] || { echo "[$sw] the record moved"; return 1; }
    [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = failed ] || return 1
    [[ "$(bk_status)" == *"/opt/custodexa/$FIRST "* ]] || { bk_status; return 1; }
    [ -d "$ROOT/backups/.partial-20260930-101503" ] || return 1
  done
}

@test "commit: state.json cannot be written after the file is in place: the file is valid, the record as it was, exit 1" {
  first_backup || return 1
  printf '1\n' >"$DB/mv.state.rc"
  backup_run en --yes
  after_commit "But the work after it did not finish: state.json was not updated
       (status still shows the previous backup).
       Check the disk space and permissions; the next backup updates
       state.json." || return 1
  made yes || return 1
  [ "$(bk_pointer)" = "$FIRST" ] || return 1
  [[ "$(bk_status)" == *"/opt/custodexa/$FIRST "* ]] || { bk_status; return 1; }
  # Only what failed is listed: the temporary folder was removed.
  [ ! -e "$ROOT/backups/.partial-20260930-101503" ]
}

@test "commit: the temporary folder cannot be removed after state.json points at the new file: kept, FAIL, exit 1" {
  first_backup || return 1
  printf '1\n' >"$DB/rmdir.rc"
  backup_run en --yes
  after_commit "But the work after it did not finish: the temporary folder
       /opt/custodexa/backups/.partial-20260930-101503/ was not removed.
       Check the disk space and permissions, then delete the temporary
       folder by hand." || return 1
  made yes || return 1
  [ "$(bk_pointer)" = "$NEXT" ] || return 1
  [[ "$(bk_status)" == *"/opt/custodexa/$NEXT "* ]] || { bk_status; return 1; }
  # Left empty: tar took each member out as it stored it, the links went after the commit.
  [ -d "$ROOT/backups/.partial-20260930-101503" ] && [ -z "$(ls -A "$ROOT/backups/.partial-20260930-101503")" ]
}

@test "commit: a member twice, a link among the members or a cut file fails the read-back: no file, the record as it was" {
  mkdir -p "$DB/dup"
  printf 'format=1\nnot the snapshot\n' >"$DB/dup/snapshot.txt"
  for sw in tar.pack.dup tar.pack.link tar.pack.cut; do
    rm -rf "$ROOT/backups" "$DB/tar.pack.dup" "$DB/tar.pack.link" "$DB/tar.pack.cut"
    first_backup || return 1
    : >"$DB/$sw"
    backup_run en --yes
    before_commit || { echo "[$sw]"; return 1; }
    made no || return 1
    [ "$(bk_pointer)" = "$FIRST" ] || return 1
    grep -qx 'tar readback' "$DB/events" || return 1
  done
}

# signal_at <committed|recorded>: backup in the background, held at that point, sent SIGTERM, let
# go. RC is its exit code; $BATS_TEST_TMPDIR/state.at-signal is state.json when the signal came.
signal_at() {
  : >"$DB/pause.$1"
  backup_bg "$OUT"
  wait_for "$DB/paused.$1" || { kill -9 "$BK_PID"; cat "$OUT"; return 1; }
  cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.at-signal"
  kill -TERM "$BK_PID"
  : >"$DB/go.$1"
  RC=0
  wait "$BK_PID" || RC=$?
  output=$(cat "$OUT")
}

# interrupted_part: the output from the line that says the run was interrupted.
interrupted_part() { screen_of "$output" | sed -n '/^\[WARN\] The backup was interrupted/,$p'; }

# interrupted_screen <committed|recorded> <timeout|ready>: the screen after the signal.
interrupted_screen() {
  local p=/opt/custodexa/backups/.partial-20260930-101502/
  printf '%s\n' '[WARN] The backup was interrupted while finishing, but the backup file is' \
    '       complete and valid:' "  /opt/custodexa/$FIRST" "  Checksum file ${FIRST#backups/}.sha256 (same folder)"
  if [ "$1" = committed ]; then
    printf '%s\n' '[FAIL] state.json was not updated (status still shows the previous backup),' \
      "       and the temporary folder $p" '       was not removed; delete it by hand.'
  else
    printf '%s\n' "[FAIL] The temporary folder $p" '       was not removed; delete it by hand.'
  fi
  if [ "$2" = timeout ]; then
    printf '%s\n' '  [WARN] The backend was not ready within 180 seconds, so users may not be' \
      '         able to connect yet. Check the status, and start again if needed:' \
      '    sudo /opt/custodexa/custodexa.sh status --lang en' '    sudo /opt/custodexa/custodexa.sh start --lang en'
  fi
  printf '%s\n' '  Log file /opt/custodexa/logs/backup-20260930-101502.log'
}

@test "interrupted after the file is in place, before state.json: the file is valid, state.json as it was" {
  signal_at committed || return 1
  [ "$RC" -eq 1 ] || { echo "$RC: $output"; return 1; }
  diff <(interrupted_part) <(interrupted_screen committed ready) || return 1
  [[ $output != *"no backup file was made"* ]] || return 1
  cmp "$BATS_TEST_TMPDIR/state.at-signal" "$ROOT/state.json" || return 1
  [ -f "$ROOT/$FIRST" ] && [ -f "$ROOT/$FIRST.sha256" ] && [ -z "$(bk_pointer)" ] || return 1
  (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "${FIRST#backups/}.sha256")
}

@test "interrupted after state.json points at the new file: the file is valid, the record kept, the folder left" {
  signal_at recorded || return 1
  [ "$RC" -eq 1 ] || { echo "$RC: $output"; return 1; }
  diff <(interrupted_part) <(interrupted_screen recorded ready) || return 1
  [ "$(bk_pointer)" = "$FIRST" ] && cmp "$BATS_TEST_TMPDIR/state.at-signal" "$ROOT/state.json" || return 1
  [ -d "$ROOT/backups/.partial-20260930-101502" ] && [ -f "$ROOT/$FIRST" ]
}

@test "interrupted after the commit while the backend was not ready: status and start are given; when ready they are not" {
  printf '1\n' >"$DB/health.rc"
  for at in committed recorded; do
    rm -rf "$ROOT/backups" "$DB"/paused.* "$DB"/go.*
    bk_state_fresh
    signal_at "$at" || return 1
    [ "$RC" -eq 1 ] || { echo "$RC: $output"; return 1; }
    diff <(interrupted_part) <(interrupted_screen "$at" timeout) \
      || { echo "[$at]"; return 1; }
  done
  rm -f "$DB/health.rc"
  for at in committed recorded; do
    rm -rf "$ROOT/backups" "$DB"/paused.* "$DB"/go.*
    bk_state_fresh
    signal_at "$at" || return 1
    [ "$RC" -eq 1 ] && [[ $output == *"The backup was interrupted while finishing"* ]] || { echo "$output"; return 1; }
    [[ $output != *"was not ready"* && $output != *"custodexa.sh status"* && $output != *"custodexa.sh start"* ]] \
      || { echo "[$at ready] $output"; return 1; }
  done
}

# ---------- one pointer per record ----------

# The upgrade records its backup (step 7) with cx_pb_record_file, which took over from the
# folder record of earlier releases: the record it replaces is dropped key by key, so status never
# shows the upgrade's file with the encrypted mark, the folder or the own-backup reference left over.
@test "pointers: the upgrade's file recorded after an encrypted portable file drops encrypted, folder and own-backup keys; status shows the file" {
  jq '. + {"last_backup.id": "20260930-101502", "last_backup.kind": "script", "last_backup.taken_at": "2026-09-30T10:15:02+0000",
      "last_backup.file": "backups/'"${FIRST#backups/}"'.enc", "last_backup.encrypted": "true", "last_backup.size_bytes": "100",
      "last_backup.dir": "backups/20260929-020000", "last_backup.external_ref": "old-snap"}' \
    "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  bk_libs || return 1
  cx_state_load "$ROOT/state.json"
  local up=custodexa-backup-1.13.0-20261001-020000.tar
  CX_BK_TS=20261001-020000 CX_PB_NAME=$up CX_PB_ENC=0 CX_PB_SIZE=300000 CX_SNAP_USABLE=true
  CX_PB_CREATED_AT=$(date '+%Y-%m-%dT%H:%M:%S%z')
  cx_pb_record_file
  cx_state_save "$ROOT/state.json" || return 1
  for k in last_backup.dir last_backup.external_ref; do
    ! grep -q "\"$k\"" "$ROOT/state.json" || { echo "$k kept"; return 1; }
  done
  [ "$(bk_pointer)" = "backups/$up" ] || return 1
  [ "$(jq -r '."last_backup.encrypted"' "$ROOT/state.json")" = false ] || { echo "encrypted kept"; return 1; }
  run bk_status
  [[ $output == *"         /opt/custodexa/backups/$up "* ]] || { echo "$output"; return 1; }
  [[ $output != *".tar.enc"* && $output != *"encrypted"* && $output != *"20260929-020000"* ]] || { echo "$output"; return 1; }
  [[ $output == *"Latest $(date -d "$(jq -r '."last_backup.taken_at"' "$ROOT/state.json")" '+%Y-%m-%d %H:%M')"* ]] || { echo "$output"; return 1; }
}

@test "pointers: a portable file recorded after a backup folder drops the folder; the operator's own backup drops the file" {
  jq '. + {"last_backup.id": "20260929-020000", "last_backup.kind": "script", "last_backup.dir": "backups/20260929-020000",
      "last_backup.taken_at": "2026-09-29T02:00:00+0000", "last_backup.external_ref": "old-snap"}' \
    "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(bk_pointer)" = "$FIRST" ] || return 1
  [ "$(jq -r '."last_backup.dir" // "none"' "$ROOT/state.json")" = none ] || return 1
  [ "$(jq -r '."last_backup.external_ref" // "none"' "$ROOT/state.json")" = none ] || return 1
  [[ "$(bk_status)" == *"/opt/custodexa/$FIRST "* ]] || { bk_status; return 1; }
  # Then the operator's own backup, as the upgrade records it.
  jq '."last_backup.encrypted" = "true"' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  bk_libs || return 1
  # shellcheck disable=SC1091
  . "$SRC/lib/backup_ref.sh"
  cx_state_load "$ROOT/state.json"
  CX_BR_REF=vm-snap-1 CX_BR_TIME='2026-09-30 02:18' CX_BR_RESTORE=/doc CX_BR_STOP_ISO=2026-09-30T02:16:13+0000
  CX_BR_EPOCH=$(date -d '2026-09-30 02:18' +%s)
  cx_br_record 20260930-021613
  for k in last_backup.file last_backup.encrypted; do
    ! grep -q "\"$k\"" "$ROOT/state.json" || { echo "$k kept"; return 1; }
  done
  run bk_status
  [[ $output == *"your own backup"* && $output == *"         vm-snap-1"* ]] || { echo "$output"; return 1; }
  [[ $output != *".tar"* ]]
}
