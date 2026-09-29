#!/usr/bin/env bats
# Threat (A): the checks after an upgrade or a rollback passing for the wrong reason. They compare
# with snapshot.txt, taken when the services were stopped: counts, applied migrations and the four
# key fingerprints. A fingerprint computed differently from the key inventory page, or a snapshot
# whose key source was not unique being taken as usable, would make "keys unchanged" meaningless.
# After the start (step 12 of upgrade): a new version on an empty database (the baseline migration
# ran, or users fell to 1) must stop every service at once, before anyone signs in or sets up a
# master key on it; fewer rows, a missing migration, another image ID or the lock held by another
# session must each fail; a snapshot that is not usable makes the key check a warning, never OK.

load helper
load install_host
load backup_host
load upgrade_host

setup() {
  backup_host ui
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/backup.sh"
  export CX_ROOT=$ROOT
  cx_bk_vars
  SNAP=$BATS_TEST_TMPDIR/snapshot.txt
}

# The key inventory page computes fingerprints with backend/pkg/crypto Fingerprint; these vectors
# are the ones its Go test pins (TestFingerprintVector): SHA-256, first 8 bytes, lower-case hex.
@test "fingerprint: the Go vectors, and base64 input fingerprints the decoded bytes" {
  [ "$(cx_snap_fp '')" = e3b0c44298fc1c14 ] || return 1
  [ "$(cx_snap_fp abc)" = ba7816bf8f01cfea ] || return 1
  [ "$(cx_snap_fp_b64 YWJj)" = ba7816bf8f01cfea ] || return 1
  # An Ed25519 public key must decode to 32 bytes.
  run cx_snap_fp_b64 YWJj 32
  [ "$status" -ne 0 ] || return 1
  run cx_snap_fp_b64 'not base64!' 32
  [ "$status" -ne 0 ]
}

@test "snapshot: counts, migrations and four fingerprints; usable" {
  cx_snap_take "$SNAP" abc
  [ "$CX_SNAP_USABLE" = true ] || return 1
  exp_export=$(printf 'A%.0s' $(seq 32) | openssl dgst -sha256 -r | cut -c1-16)
  exp_chk=$(printf 'B%.0s' $(seq 32) | openssl dgst -sha256 -r | cut -c1-16)
  diff "$SNAP" - <<EOF
format=1
count.users=5
count.sessions=42
count.audit_logs=1234
migration=20260816_schema_baseline
migration=20260901_add_x
fp.jwt=ba7816bf8f01cfea
fp.kek=5a5a5a5a5a5a5a5a
fp.export_signing=$exp_export
fp.checkpoint_signing=$exp_chk
usable=true
unusable=
EOF
  [ "$(stat -c %a "$SNAP")" = 600 ] || return 1
  [ "$(cx_snap_get "$SNAP" count.users)" = 5 ] || return 1
  [ "$(cx_snap_migrations "$SNAP" | wc -l)" -eq 2 ]
}

# not_usable <reason> : the snapshot is written, marked not usable, with the reason.
not_usable() {
  cx_snap_take "$SNAP" abc || { echo "snapshot not written"; return 1; }
  [ "$CX_SNAP_USABLE" = false ] || { echo "usable despite $1"; return 1; }
  [ "$(cx_snap_get "$SNAP" usable)" = false ] || return 1
  [[ " $(cx_snap_get "$SNAP" unusable) " == *" $1 "* ]] || { echo "reason: $(cx_snap_get "$SNAP" unusable)"; return 1; }
}

@test "snapshot: two active data keys under different KEKs make the snapshot not usable" {
  printf '%s\n' 5a5a5a5a5a5a5a5a 6b6b6b6b6b6b6b6b >"$DB/kek"
  not_usable kek:not-unique
}

@test "snapshot: every other missing or unclear key source makes it not usable" {
  : >"$DB/kek"
  not_usable kek:none || return 1
  db_default
  printf '%s\n' QkJC QkJD >"$DB/checkpoint"
  not_usable checkpoint:not-unique || return 1
  db_default
  : >"$DB/checkpoint"
  not_usable checkpoint:none || return 1
  db_default
  printf '%s\n' YWJj >"$DB/export"
  not_usable export:decode || return 1
  db_default
  printf '1\n' >"$DB/export.rc"
  not_usable export:query || return 1
  rm -f "$DB/export.rc"
  cx_snap_take "$SNAP" ""
  [ "$CX_SNAP_USABLE" = false ] || return 1
  [ "$(cx_snap_get "$SNAP" unusable)" = jwt:none ]
}

@test "snapshot: counts or migrations that cannot be read fail the snapshot (no file)" {
  printf '1\n' >"$DB/count.sessions.rc"
  run cx_snap_take "$SNAP" abc
  [ "$status" -ne 0 ] || return 1
  [ ! -e "$SNAP" ] || return 1
  rm -f "$DB/count.sessions.rc"
  : >"$DB/migrations"
  run cx_snap_take "$SNAP" abc
  [ "$status" -ne 0 ]
}

# ---- step 12 of upgrade, on the whole run ----

fresh() { # [kek]
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host "${1:-ui}" || return 1
  clock 0 3 0 41 0 4 0 11
}
up_run() { run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang "$1" --yes </dev/null; }
from_line() { screen_of "$output" | sed -n "/^$(printf '%s' "$1" | sed 's/[][\/.*]/\\&/g')/,\$p"; }
stopped_all_after_up() { grep -A99 -x up "$DB/events" | grep -qx stop-all; }

@test "empty database (baseline migration in the log): every service stopped at once, the screen word for word" {
  for l in zh-TW en; do
    fresh ui
    printf '%s\n' "$ROOT-new/data" >"$UP/data_path"
    printf '%s\n' '2026/09/30 02:20:03 執行 migration: 20260816_schema_baseline' >>"$UP/logs"
    printf '1\n' >"$UP/after.count.users"
    printf '0\n' >"$UP/after.count.sessions"
    tree_of "$ROOT/data" >"$BATS_TEST_TMPDIR/data-before"
    up_run "$l"
    [ "$status" -eq 1 ] || { echo "$l: $status"; echo "$output"; return 1; }
    diff <(from_line "$(sed -n 1p "$TESTS_DIR/snapshots/s12b.$l.txt")") "$TESTS_DIR/snapshots/s12b.$l.txt" \
      || { echo "$output"; return 1; }
    stopped_all_after_up || { cat "$DB/events"; return 1; }
    diff "$BATS_TEST_TMPDIR/data-before" <(tree_of "$ROOT/data") || return 1
  done
  [ "$(jq -r '."last_upgrade.step"' "$ROOT/state.json")" = 12 ]
}

@test "empty database (users fell to 1 with no baseline line, or the baseline line alone): stopped all the same" {
  fresh ui
  printf '1\n' >"$UP/after.count.users"
  up_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The new version found an empty database. All services were"* ]] \
    || { echo "$output"; return 1; }
  [[ $output == *"The data path $ROOT/data"* ]] || { echo "$output"; return 1; }
  stopped_all_after_up || { cat "$DB/events"; return 1; }
  # The baseline migration in the log alone is enough, whatever the counts say.
  fresh ui
  printf '%s\n' '2026/09/30 02:20:03 執行 migration: 20260816_schema_baseline' >>"$UP/logs"
  up_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The new version found an empty database."* ]] || { echo "$output"; return 1; }
  stopped_all_after_up || { cat "$DB/events"; return 1; }
}

@test "fewer rows, a missing migration, another image ID, the lock held elsewhere: each FAIL, services left running" {
  check_fails() { # <expected row text>
    up_run en
    [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The upgrade stopped at step 12/13: the checks did not pass"* ]] \
      || { echo "$output"; return 1; }
    [[ $output == *"$1"* ]] || { echo "$output"; return 1; }
    printf '%s\n' "$output" | grep -qxF '  in "Backup and Restore", section 5 "Restore procedure".' || { echo "$output"; return 1; }
    [[ $output != *"custodexa.sh rollback"* ]] || { echo "$output"; return 1; }
    ! stopped_all_after_up || { echo "stopped every service"; return 1; }
  }
  fresh ui
  printf '18304\n' >"$UP/after.count.sessions"
  check_fails "[FAIL] Same data       42 users (42 before), 18,304 connection records" || return 1
  fresh ui
  printf '1204539\n' >"$UP/after.count.audit_logs"
  check_fails "1,204,539 audit records (1,204,540 before)" || return 1
  fresh ui
  printf '%s\n' 20260816_schema_baseline 20261010_report_schedule >"$UP/after.migrations"
  check_fails "[FAIL] Database        structure versions from before are missing:" || return 1
  fresh ui
  printf '%s\n' sha256:9999999999999999999999999999999999999999999999999999999999999999 >"$UP/image.backend"
  check_fails "[FAIL] Images          a running image differs from the one obtained" || return 1
  fresh ui
  printf '%s\n' '2026/09/30 02:20:05 [InstanceGuard] 單實例鎖由另一個資料庫工作階段持有' >"$UP/logs"
  check_fails "[FAIL] Single instance the database lock is held by another database" || return 1
  fresh ui
  printf '%s\n' 'sha256:1111' >"$UP/after.kek"
  check_fails "[FAIL] Keys            a key fingerprint differs from before the upgrade"
}

@test "a snapshot that is not usable: keys WARN, never OK; what cannot be read warns and the upgrade completes" {
  fresh ui
  printf '%s\n' kek-a kek-b >"$DB/kek" # two active KEKs: not unique
  printf '%s\n' '2026/09/30 02:20:05 nothing about the lock' >"$UP/logs"
  touch "$REL/entry.rc"
  up_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Keys            the fingerprints before or after are incomplete"* ]] || { echo "$output"; return 1; }
  [[ $output != *"[ OK ] Keys"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Single instance the backend log does not show the database lock"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Entry           https://127.0.0.1:443/ does not answer"* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_upgrade.result"' "$ROOT/state.json")" = succeeded ]
}
