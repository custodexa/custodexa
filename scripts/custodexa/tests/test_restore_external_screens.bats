#!/usr/bin/env bats
# The screens of an external database's restore, produced by the whole flow on the fake host and
# compared word for word with the reviewed text: the preview's database section, the refusals
# before and after the stop, the confirmation by the database's name, the steps that differ, what
# a failed import says of the database, the way back, and what giving up leaves in it.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_ext_flow_host

# The source as the reviewed screens show it: DB_USER custodexa, a CA trusted by the system, and a
# database of 17.4 GB.
source_setup() {
  bk_env_set DB_USER custodexa
  bk_env_set PGSSLROOTCERT system
  printf '%s\n' 18683107738 >"$DB/size"
  # The tests of a restore waiting for unseal: the master key is entered in the web page. Only the
  # master key lines change; the rest of .env (the external database's host) stays.
  [[ $BATS_TEST_DESCRIPTION != *'waiting for unseal'* ]] || {
    bk_env_set ENCRYPTION_KEY -
    bk_env_set KEK_PROVIDER ui
  }
}
setup() {
  RS_X_BEFORE=source_setup rs_ext_flow_host
  NEWDATA=$BATS_TEST_TMPDIR/newdata
  printf '%s\n' 'public|214' >"$DB/objects"
}
new_host() { rs_new_host; }
new_run() { run bash "$ROOT/custodexa.sh" restore "$RS_X_FILE" --new-host --data-path "$NEWDATA" --lang "${LANG_RUN:-en}" "$@" </dev/null; }
same_run() { run bash "$ROOT/custodexa.sh" restore "$RS_X_FILE" --same-host --yes --confirm-data-loss --lang "${LANG_RUN:-en}" "$@" </dev/null; }
st() { jq -r --arg k "last_restore.$1" '.[$k] // ""' "$ROOT/state.json"; }
no_stop() { ! grep -Eq '^(stop|up)$' "$DB/events"; }
digest_now() { cat "$DB/ext.digest" 2>/dev/null || echo before; }
# shown: the output as on a production host: the deployment, the restore's time stamp (its
# working folder without the random suffix) and the management script's release as the reviewed
# screens show them, and the commands without the --lang the test chose.
shown() {
  sed -e "s#$ROOT#/opt/custodexa#g" -e 's#[0-9]\{8\}-[0-9]\{6\}#20261012-093015#g' \
    -e "s#$(cat "$ROOT/current/VERSION")#1.16.2#g" -e 's#\(20261012-093015\)-[A-Za-z0-9]\{6\}#\1#g' \
    -e 's# --lang \(en\|zh-TW\|ja\)$##' <<<"$output"
}
# snapshot <name> <language> <text>: the text equals tests/snapshots/restore-ext-<name>.<language>.txt.
snapshot() {
  local want=$TESTS_DIR/snapshots/restore-ext-$1.$2.txt
  if [ ! -f "$want" ] || ! diff <(printf '%s\n' "$3") "$want"; then
    printf '# SNAPSHOT %s %s\n' "${want##*/}" "$(printf '%s\n' "$3" | base64 -w0)" >&3
    return 1
  fi
}

@test "restore external screens: a new host's preview shows the database section as reviewed" {
  new_host
  local l errs=0 part
  for l in en zh-TW ja; do
    : >"$DB/events"
    LANG_RUN=$l new_run
    # Without --yes there is no confirmation without a terminal: nothing is changed.
    [ "$status" -eq 3 ] && no_stop || { echo "$status $output"; return 1; }
    # From the database's label to the end of the space warning.
    part=$(shown | awk '/^  (Database|資料庫|データベース) /{p=1} p&&w&&!/^         /{exit} p{print} p&&/^  \[WARN\] /{w=1}')
    snapshot preview-db "$l" "$part" || errs=1
  done
  [ "$errs" = 0 ]
  # The deployment is described as external; nothing of a bundled database's.
  LANG_RUN=en new_run
  [[ $output == *'  Deployment     external database; '* && $output != *'bundled database'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: an empty database needs neither emptying, export nor the space warning" {
  new_host
  rm -f "$DB/objects"
  new_run --yes
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [[ $output == *'                 The target database is empty; nothing needs emptying'$'\n''  Safety backup  not needed: this host has no data yet'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output != *'GB free; the script cannot'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: a new host's non-empty database needs --confirm-data-loss with --yes" {
  new_host
  new_run --yes
  [ "$status" -eq 3 ] && no_stop || { echo "$status $output"; return 1; }
  [[ $output == *'--confirm-data-loss'* ]] || { echo "$output"; return 1; }
  [ "$(digest_now)" = before ] || return 1
}

@test "restore external screens: at a terminal the database's name confirms; a wrong one cancels, exit 3, no stop" {
  # Enter at the safety backup's question (its default), then the name.
  run bash -c 'printf "%b" "$2" | script -qec "$1" /dev/null' _ \
    "bash '$ROOT/custodexa.sh' restore '$RS_X_FILE' --same-host --no-color --lang en" '\ncustodexa_x\n'
  output=${output//$'\r'/}
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  [[ $output == *'To confirm, type the name of the database to empty, custodexa:'$'\n''> '* ]] || { echo "$output"; return 1; }
  [[ $output == *'The entry was not custodexa; the restore was cancelled.'* ]] || { echo "$output"; return 1; }
  [[ $output != *'To confirm, type the version after the restore'* ]] || { echo "$output"; return 1; }
  no_stop && [ "$(digest_now)" = before ] || { cat "$DB/events"; return 1; }
}

@test "restore external screens: the same host's preview keeps no database folder, and its steps read as reviewed" {
  printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
  : >"$DB/activity.after-stop"
  same_run
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [[ $output != *'postgres.before-restore'* && $output == *'  Kept           the current audit and certificate folders are'* ]] || { echo "$output"; return 1; }
  # This host's own backend, listed and not refused before the stop.
  [[ $output == *'it; 1 other connections now (from 172.18.0.5, application'* ]] || { echo "$output"; return 1; }
  [[ $output == *'[ OK ]  2/10  Stop the services (the external database is not affected)'* ]] || { echo "$output"; return 1; }
  [[ $output == *'[ OK ]  5/10  Make sure no other connection is open'* ]] || { echo "$output"; return 1; }
  [[ $output == *'[ OK ]  6/10  Empty and import the database (one transaction)'* ]] || { echo "$output"; return 1; }
  [[ $output != *'database keeps running'* && $output != *'Import the database '* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: a failed import says the transaction was rolled back, or that its result is not known" {
  echo 3 >"$DB/import.rc"
  LANG_RUN=zh-TW same_run
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *'[FAIL]  6/10  清空並匯入資料庫（同一個交易）'*$'\n''       psql 回報錯誤（完整訊息在紀錄檔）。'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output == *$'\n''  這次的清空與匯入已整筆撤回，外接資料庫保持原狀。'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output == *'restore --resume'*'restore --revert'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: an import whose result is not known claims nothing about the database" {
  # Killed during the transaction.
  echo 137 >"$DB/import.rc"
  same_run
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *$'\n''  Whether the import was committed cannot be told. Carrying on checks'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output != *'rolled back as a whole'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: a new host's failure with a safety export names it and the way back is --revert" {
  new_host
  echo 3 >"$DB/import.rc"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *'  This emptying and import were rolled back as a whole; the external'$'\n''  database is as it was. The safety export is in restore/'*'/safety-db.dump.'* ]] || { echo "$output"; return 1; }
  [[ $output == *'  Or put the safety export back into the external database and give up'$'\n''  on this restore:'$'\n''    sudo '*'restore --revert'* ]] || { echo "$output"; return 1; }
  [[ $output != *'restore --abandon'* && $output != *'no safety backup'* ]] || { echo "$output"; return 1; }
  # Not committed: nothing says the database holds the backup.
  [[ $output != *'The import was committed'* ]] || { echo "$output"; return 1; }
}

# The same rolled-back import in Chinese: the reviewed sentence, not the one of a committed import.
@test "restore external screens: a rolled-back import on a new host with a safety export keeps the rolled-back sentence (zh-TW)" {
  new_host
  echo 3 >"$DB/import.rc"
  LANG_RUN=zh-TW new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *$'\n''  這次的清空與匯入已整筆撤回，外接資料庫保持原狀；安全匯出在 restore/'*'/safety-db.dump'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output != *'匯入已提交'* ]] || { echo "$output"; return 1; }
}

# A failure after the import was committed (here the services not ready in time): the external
# database holds the backup now; the screen must not say the import was rolled back.
@test "restore external screens: a failure after the import was committed on a new host with a safety export says the database holds the backup" {
  new_host
  echo 1 >"$DB/health.rc"
  LANG_RUN=zh-TW new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; return 1; }
  [[ $output == *$'\n''  匯入已提交，外接資料庫現在是備份的內容；安全匯出在 restore/'*'/safety-db.dump'$'\n'* ]] || { echo "$output"; return 1; }
  # From the sentence on, each way on is given once, as the command that follows it.
  local rest=${output#*'匯入已提交'}
  [ "$(grep -c -- '--resume' <<<"$rest")" = 1 ] && [ "$(grep -c -- '--revert' <<<"$rest")" = 1 ] || { echo "$output"; return 1; }
  # From the steps on (the preview describes a failed transaction before anything starts).
  local steps=${output#*' 1/9  '}
  [ "$steps" != "$output" ] || { echo "$output"; return 1; }
  [[ $steps != *'撤回'* && $steps != *'保持原狀'* && $steps != *'維持原樣'* ]] || { echo "$output"; return 1; }
  [[ $output == *'restore --resume'*'restore --revert'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: once the transaction was sent, --abandon of a non-empty database is refused for --revert" {
  new_host
  echo 3 >"$DB/import.rc"
  new_run --yes --confirm-data-loss
  [ "$(st db_covering)" = 1 ] && [ "$(st safety)" = db-dump ] || { jq . "$ROOT/state.json"; return 1; }
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --abandon --yes --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  [ "$(shown)" = "[FAIL] Emptying and importing the external database has started, so the
       restore cannot simply be given up. Put the safety export back
       (this host then goes back to not installed as well):
    sudo /opt/custodexa/custodexa.sh restore --revert
Nothing has been changed." ] || { shown; return 1; }
  ! grep -Eq '^(stop|psql import)$' "$DB/events" && [ -z "$(st exit)" ] || { cat "$DB/events"; return 1; }
  [ -f "$(st safety_file)" ] || return 1
}

# unsent_failure: the maker of the SQL ends badly after a valid start, so the transaction never
# opens; a new host whose database held data.
unsent_failure() {
  new_host
  printf '%s\n' '120 1' >"$DB/pg_restore.cut"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] && [ -z "$(st db_covering)" ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; return 1; }
  ! grep -qx 'psql import' "$DB/events" && [ "$(digest_now)" = before ] || { cat "$DB/events"; return 1; }
}

@test "restore external screens: a failure before the transaction was sent says the database was not changed, nothing of a rollback" {
  unsent_failure || return 1
  [[ $output == *$'\n''  The external database was not changed. The safety export is in restore/'*'/safety-db.dump.'$'\n'* ]] || { echo "$output"; return 1; }
  local steps=${output#*' 1/9  '}
  [ "$steps" != "$output" ] || { echo "$output"; return 1; }
  [[ $steps != *'rolled back'* && $steps != *'The import was committed'* ]] || { echo "$output"; return 1; }
  [[ $output == *'restore --resume'*$'\n''  Or put the safety export back into the external database and give up'$'\n''  on this restore:'$'\n''    sudo '*'restore --revert'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: a failure before the transaction was sent claims no rollback (zh-TW)" {
  LANG_RUN=zh-TW unsent_failure || return 1
  [[ $output == *$'\n''  外接資料庫沒有被改動；安全匯出在 restore/'*'/safety-db.dump'$'\n'* ]] || { echo "$output"; return 1; }
  # From the steps on (the preview describes a failed transaction before anything starts).
  local steps=${output#*' 1/9  '}
  [ "$steps" != "$output" ] || { echo "$output"; return 1; }
  [[ $steps != *'撤回'* && $steps != *'匯入已提交'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: --abandon before the transaction leaves the database untouched and the export kept" {
  new_host
  # The transaction never opens: the maker of the SQL ends badly after a valid start.
  printf '%s\n' '120 1' >"$DB/pg_restore.cut"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] && [ -z "$(st db_covering)" ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  local file
  file=$(st safety_file)
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --abandon --yes --lang en </dev/null
  [ "$status" -eq 0 ] && [ "$(st result)" = abandoned ] || { echo "$status $output"; return 1; }
  [[ $output == *'  Safety export  '"$file"$'\n''                 is kept, not deleted; delete it yourself once it is not'* ]] || { echo "$output"; return 1; }
  # No SQL of the external database is sent; the services were stopped first.
  ! grep -Eq '^psql (import|digest)$' "$DB/events" || { cat "$DB/events"; return 1; }
  [ "$(head -n1 "$DB/events")" = stop ] || { cat "$DB/events"; return 1; }
  [ -f "$file" ] && [ "$(digest_now)" = before ] || return 1
}

@test "restore external screens: giving up after an empty database was imported leaves the data and says so" {
  new_host
  rm -f "$DB/objects"
  # Imported and checked, then the startup is not ready: the restore stops at a late phase.
  echo 1 >"$DB/health.rc"
  new_run --yes
  [ "$status" -eq 1 ] && [ "$(st db_covering)" = 1 ] && [ "$(st safety)" = none ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  [[ $output == *'the data this restore imported'$'\n''  into the external database is not removed):'$'\n''    sudo '*'restore --abandon'* ]] || { echo "$output"; return 1; }
  : >"$DB/events"
  LANG_RUN=zh-TW
  run bash "$ROOT/custodexa.sh" restore --abandon --yes --lang zh-TW </dev/null
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [[ $(shown) == *$'\n''  外接資料庫   db.example.internal:5432／custodexa 裡這次匯入的資料不會被清掉；'$'\n''             需要清空時請由資料庫管理者處理，'$'\n''             下次還原會把它當成非空的目標先做安全匯出'$'\n'* ]] || { shown; return 1; }
  # Stopped first; nothing emptied.
  [ "$(head -n1 "$DB/events")" = stop ] || { cat "$DB/events"; return 1; }
  ! grep -Eq '^psql (import|clear)$' "$DB/events" && ! grep -q 'DROP SCHEMA' "$FAKE_DOCKER_LOG" || { cat "$DB/events"; return 1; }
  [ "$(digest_now)" = imported ] || return 1
}

@test "restore external screens: the refusal before anything stops reads as reviewed" {
  new_host
  printf '%s\n' '10.0.0.12 custodexa-backend' '10.0.0.12 custodexa-backend' >"$DB/activity"
  printf '%s\n' 'public|report_cache|analyst' >"$DB/foreign"
  local l errs=0
  for l in en zh-TW ja; do
    LANG_RUN=$l new_run --yes --confirm-data-loss
    [ "$status" -eq 3 ] && no_stop || { echo "$status $output"; return 1; }
    snapshot refused "$l" "$(shown | sed -n '/^\[FAIL\] /,$p')" || errs=1
  done
  [ "$errs" = 0 ]
}

@test "restore external screens: a connection left once the services stopped holds the restore as reviewed" {
  printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
  printf '%s\n' '10.0.0.45 psql' >"$DB/activity.after-stop"
  local l errs=0
  for l in en zh-TW ja; do
    LANG_RUN=$l same_run
    [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
    snapshot held "$l" "$(shown | sed -n '/^\[FAIL\]  2\/10 /,$p')" || errs=1
    run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
    [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
    printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
  done
  [ "$errs" = 0 ]
}

@test "restore external screens: the menu offers the export's way back, not giving up" {
  new_host
  echo 3 >"$DB/import.rc"
  new_run --yes --confirm-data-loss
  run bash -c 'printf "0\n" | script -qec "$1" /dev/null' _ "bash '$ROOT/custodexa.sh' --no-color --lang en"
  output=${output//$'\r'/}
  [[ $output == *'] Put the safety export back into the external database and give up'$'\n''      on this restore'$'\n'* ]] || { echo "$output"; return 1; }
  [[ $output != *'Give up on this restore and return to not installed'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: the grants left out are counted at the end, and their list stays" {
  # The dump grants to a role the server lacks; the restore goes on without those grants.
  printf '%s\n' '"report reader"' >"$DB/grants.restore"
  : >"$DB/roles"
  same_run --accept-grant-loss
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  local list
  list=$(find "$ROOT/restore" -name skipped-grants.txt)
  [ -s "$list" ] || { find "$ROOT/restore"; return 1; }
  [[ $output == *$'\n''  Skipped      '[1-9]*' grant statements for roles the server lacks were not'$'\n''               restored; the list is in '"$list"$'\n'* ]] || { echo "$output"; return 1; }
}

# Not ready in time, or a master key that does not match, on a new host whose database held data:
# the second way on is the safety export's.
ext_way_back() {
  [[ $output == *'restore --resume'*$'\n''  Or put the safety export back into the external database and give up'$'\n''  on this restore:'$'\n''    sudo '*'restore --revert'* ]] || { echo "$output"; return 1; }
  [[ $output != *'Or go back with the safety backup'* && $output != *'restore --abandon'* ]] || { echo "$output"; return 1; }
}
# ext_committed: a failure after the import was committed says the database holds the backup and
# nothing of a rollback.
ext_committed() {
  [[ $output == *$'\n''  The import was committed: the external database now holds the'$'\n''  contents of the backup. The safety export is in restore/'*'/safety-db.dump.'$'\n'* ]] || { echo "$output"; return 1; }
  # From the sentence on, each way on is given once, as the command that follows it.
  local rest=${output#*'The import was committed'}
  [ "$(grep -c -- '--resume' <<<"$rest")" = 1 ] && [ "$(grep -c -- '--revert' <<<"$rest")" = 1 ] || { echo "$output"; return 1; }
  # From the steps on (the preview describes a failed transaction before anything starts).
  local steps=${output#*' 1/9  '}
  [ "$steps" != "$output" ] || { echo "$output"; return 1; }
  [[ $steps != *'rolled back'* && $steps != *'as it was'* ]] || { echo "$output"; return 1; }
}

@test "restore external screens: not ready in time on a new host with a safety export offers --revert" {
  new_host
  echo 1 >"$DB/health.rc"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; return 1; }
  [[ $output == *'[WARN]  8/9  Start the services and wait until ready: not ready within'* ]] || { echo "$output"; return 1; }
  ext_way_back
  ext_committed
}

@test "restore external screens: a master key that does not match on a new host with a safety export offers --revert" {
  new_host
  printf '0c0c0c0c0c0c0c0c\n' >"$DB/kek.after-up"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 1 ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; return 1; }
  [[ $output == *'[FAIL] The master key does not match: the ID read after unseal is'* ]] || { echo "$output"; return 1; }
  ext_way_back
  ext_committed
}

# Leaving a restore that is waiting for unseal stops the services first (as at started).
@test "restore external screens: --abandon while waiting for unseal stops the services first and empties nothing" {
  new_host
  rm -f "$DB/objects"
  echo sealed >"$DB/seal"
  new_run --yes
  [ "$status" -eq 4 ] && [ "$(st phase)" = awaiting_unseal ] && [ "$(st db_covering)" = 1 ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  [ "$(cat "$DB/ctr/backend")" = running ] || return 1
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --abandon --yes --lang en </dev/null
  [ "$status" -eq 0 ] && [ "$(st result)" = abandoned ] || { echo "$status $output"; return 1; }
  [ "$(head -n1 "$DB/events")" = stop ] && [ "$(cat "$DB/ctr/backend")" = stopped ] || { cat "$DB/events"; return 1; }
  ! grep -Eq '^psql (import|clear)$' "$DB/events" && ! grep -q 'DROP SCHEMA' "$FAKE_DOCKER_LOG" || { cat "$DB/events"; return 1; }
  [ "$(digest_now)" = imported ] || return 1
}

@test "restore external screens: --revert while waiting for unseal stops the services before the export goes back" {
  new_host
  echo sealed >"$DB/seal"
  new_run --yes --confirm-data-loss
  [ "$status" -eq 4 ] && [ "$(st phase)" = awaiting_unseal ] && [ "$(st safety)" = db-dump ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  # The put-back leaves the export's content.
  echo before >"$DB/import.digest"
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" -eq 0 ] && [ "$(st result)" = reverted ] || { echo "$status $output"; return 1; }
  # The stop comes before any SQL that writes the database.
  [ "$(grep -Ex 'stop|psql import' "$DB/events" | head -n1)" = stop ] && grep -qx 'psql import' "$DB/events" || { cat "$DB/events"; return 1; }
  [ "$(cat "$DB/ctr/backend")" = stopped ] && [ "$(digest_now)" = before ] || { cat "$DB/events"; return 1; }
}
