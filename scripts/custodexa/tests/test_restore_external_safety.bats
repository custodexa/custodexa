#!/usr/bin/env bats
# A new host's restore of an external database deployment: a database that already holds data is
# exported before anything is emptied, read back in full, between two equal target digests;
# --revert puts the export back with the one-transaction import and is done only when the target
# digest equals the export's; until then the export is never deleted.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_ext_flow_host
setup() {
  rs_ext_flow_host
  rs_new_host
  NEWDATA=$BATS_TEST_TMPDIR/newdata
  printf '%s\n' 'public|12' >"$DB/objects"
}
new_run() { run bash "$ROOT/custodexa.sh" restore "$RS_X_FILE" --new-host --yes --confirm-data-loss --data-path "$NEWDATA" --lang en "$@" </dev/null; }
st() { jq -r --arg k "last_restore.$1" '.[$k] // ""' "$ROOT/state.json"; }
digest_now() { cat "$DB/ext.digest" 2>/dev/null || echo before; }
sha_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

@test "restore external safety: a new host's non-empty database is exported and read back before the transaction" {
  new_run
  [ "$status" = 0 ] && [ "$(st result)" = succeeded ] || { echo "$status $output"; return 1; }
  # No other connection, the digest, the export, the listing and the full read, the digest again;
  # only then the import.
  [ "$(grep -E '^(pg_dump|pg_restore( full)?|psql (activity|digest|total|import))$' "$DB/events" | sed '/^psql import$/q' | paste -sd ' ')" = \
    'psql activity psql activity psql activity psql total psql digest pg_dump pg_restore pg_restore full psql digest psql activity psql digest psql import' ] ||
    { grep -E '^(pg_dump|pg_restore|psql )' "$DB/events" | paste -sd ' '; return 1; }
  # The export is a step of its own once the settings are written: nine steps.
  [[ $output == *'  2/9  Write the settings file'*$'\n''[ OK ]  3/9  Export the current external database as the safety backup'*$'\n''[ OK ]  4/9  Import the database'*' 9/9  Master key'* ]] ||
    { echo "$output"; return 1; }
  [ "$(grep -c '/8  ' <<<"$output")" = 0 ] || { echo "$output"; return 1; }
  grep -q -- '--entrypoint pg_restore .*--list' "$FAKE_DOCKER_LOG" && grep -q -- '--entrypoint pg_restore .* -f -' "$FAKE_DOCKER_LOG" ||
    { grep pg_restore "$FAKE_DOCKER_LOG"; return 1; }
  local file
  file=$(st safety_file)
  [ "$(st safety)" = db-dump ] && [ -f "$file" ] && [[ $file == */restore/*/safety-db.dump ]] || { jq . "$ROOT/state.json"; return 1; }
  [ "$(st safety_sha256)" = "$(sha256sum "$file" | cut -d' ' -f1)" ] || return 1
  [ "$(st safety_digest)" = "$(sha_of before)" ] || return 1
  [ "$(stat -c %a "$file")" = 600 ] || return 1
  # The export stays after the restore; the completion screen gives its path.
  [[ $output == *$'\n''  Export       the safety export (the external database from before'$'\n''               the restore, in plaintext) is kept in'$'\n''               '"$file"$';\n''               delete it yourself once section 6 checks out.'$'\n'* ]] || { echo "$output"; return 1; }
}

@test "restore external safety: an empty database is not exported" {
  rm -f "$DB/objects"
  new_run
  [ "$status" = 0 ] || { echo "$status $output"; return 1; }
  [ "$(st safety)" = none ] || return 1
  ! grep -qx pg_dump "$DB/events" || return 1
  ! compgen -G "$ROOT/restore/*/safety-db.dump" >/dev/null || return 1
  # Finished, and the completion screen names no export.
  [ "$(st result)" = succeeded ] && [[ $output == *'section 6 of "Backup and Restore"'* ]] || { echo "$output"; return 1; }
  [[ $output != *'Export       '* && $output != *'safety-db.dump'* ]] || { echo "$output"; return 1; }
}

@test "restore external safety: an export that cannot be read back in full stops before anything is emptied" {
  echo 1 >"$DB/pg_restore_full.rc"
  new_run
  [ "$status" = 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *'[FAIL]  3/9  The external database could not be exported and read back in full;'*'it has not been changed.'* ]] || { echo "$output"; return 1; }
  ! grep -qx 'psql import' "$DB/events" || return 1
  [ "$(digest_now)" = before ] && [ -z "$(st db_covering)" ] && [ -z "$(st safety)" ] && [ "$(st phase)" = swapped ] || { jq . "$ROOT/state.json"; return 1; }
  # Carrying on exports again (none is recorded) and finishes.
  rm -f "$DB/pg_restore_full.rc"
  run bash "$ROOT/custodexa.sh" restore --resume --lang en </dev/null
  [ "$status" = 0 ] && [ "$(st result)" = succeeded ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; return 1; }
  [[ $output == *' 3/9  Export the current external database'* ]] || { echo "$output"; return 1; }
}

@test "restore external safety: --revert puts the export back, checks the digest, then gives up; the export is deleted only then" {
  # The transaction's result is not known and the target holds part of the import.
  echo 1 >"$DB/import.rc"; echo 1 >"$DB/import.commit"; echo partial >"$DB/import.digest"
  new_run
  [ "$status" = 1 ] && [ "$(st db_covering)" = 1 ] || { echo "$status $output"; return 1; }
  local file
  file=$(st safety_file)
  rm -f "$DB/import.rc" "$DB/import.commit"
  # A put-back that leaves anything else than the export: stopped, the export kept, run again.
  echo other >"$DB/import.digest"
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" = 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *'could not be put back as it was exported;'* ]] || { echo "$output"; return 1; }
  [ -f "$file" ] && [ "$(st result)" = in_progress ] && [ "$(st exit)" = reverting ] || { jq . "$ROOT/state.json"; return 1; }
  grep -qx 'psql import' "$DB/events" || return 1
  echo before >"$DB/import.digest"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" = 0 ] || { echo "$status $output"; return 1; }
  [[ $output == *'The external database is back as it was exported before the'* ]] || { echo "$output"; return 1; }
  [ "$(digest_now)" = before ] && [ "$(st result)" = reverted ] || { jq . "$ROOT/state.json"; return 1; }
  [ ! -e "$file" ] || return 1
  # Given up as --abandon does: this host is back to not installed.
  [ -z "$(jq -r '."current.version" // ""' "$ROOT/state.json")" ] || return 1
  # The put-back imported the export itself, its grants unfiltered.
  grep -q -- "-v $file:/in/db.dump:ro" "$FAKE_DOCKER_LOG" || { grep db.dump "$FAKE_DOCKER_LOG"; return 1; }
}

@test "restore external safety: --revert before the transaction was sent does not touch the database" {
  printf '%s\n' '10.0.0.45 psql' >"$DB/activity.4"
  new_run
  [ "$status" = 1 ] && [ -z "$(st db_covering)" ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" = 0 ] && [ "$(st result)" = reverted ] || { echo "$status $output"; return 1; }
  ! grep -qE '^psql (import|digest)$' "$DB/events" || { cat "$DB/events"; return 1; }
}

@test "restore external safety: carrying on after an import of unknown result never exports the imported data" {
  # The server committed, then the client was killed: the result is not known here.
  echo 137 >"$DB/import.rc"
  echo 1 >"$DB/import.commit"
  new_run
  [ "$status" = 1 ] && [ "$(st safety)" = db-dump ] && [ "$(digest_now)" = imported ] || { echo "$status $output"; return 1; }
  local sum
  sum=$(st safety_sha256)
  rm -f "$DB/import.rc" "$DB/import.commit"
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --resume --lang en </dev/null
  [ "$status" = 0 ] && [ "$(st result)" = succeeded ] || { echo "$status $output"; return 1; }
  # The export of before stays the safety backup: no second export, no step 3 again.
  ! grep -qx pg_dump "$DB/events" && [ "$(st safety_sha256)" = "$sum" ] || { cat "$DB/events"; return 1; }
  [[ $output != *'Export the current external database'* ]] || { echo "$output"; return 1; }
}
