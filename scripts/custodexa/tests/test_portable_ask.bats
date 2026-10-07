#!/usr/bin/env bats
# Threat (A): a backup that asks where nobody can answer, or decides what nobody chose. The
# recordings and the encryption are asked only on a terminal without --yes; the two options decide
# without asking; automation without --yes stops at the confirmation instead of waiting; what goes
# into the file and whether it is encrypted follow exactly from that. A question asked to a script,
# a recording left out that was asked for, an encryption nobody chose, or a run that stops the
# services after the input ended would each show here as a failed assertion.

load helper
load install_host
load backup_host
load pty_host

BK_PASS='test-passphrase-only-0001'

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  clock
  printf '%s\n' 18683107737 >"$DB/size"
  bk_openssl
  PASSFILE=$BATS_TEST_TMPDIR/cx-pass
  bk_passfile "$PASSFILE" "$BK_PASS"
}

# fresh: the deployment as before any backup (the files of earlier runs gone).
fresh() {
  rm -rf "$ROOT/backups" "$ROOT/logs" "$ROOT/.custodexa.lock"
  : >"$DB/events"
  bk_state_fresh
  bk_openssl
}

# no_stop: no service was stopped and nothing was made under backups/.
no_stop() {
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ ! -e "$ROOT/backups" ] || [ -z "$(ls -A "$ROOT/backups")" ] || { ls -lA "$ROOT/backups"; return 1; }
}

OUT_FILE=""
# on_terminal <answers for the recordings and encryption questions> <options...>: the backup on a
# terminal, English, no color; each question present gets its answer, the confirmation gets y.
# RUN_RC and RUN_OUT (the screen) are set.
on_terminal() {
  local rec_answer=$1 enc_answer=$2
  shift 2
  local -a talk=()
  [ "$rec_answer" = - ] || talk+=("for the default: " "$rec_answer")
  [ "$enc_answer" = - ] || talk+=("for the default: " "$enc_answer")
  talk+=("Start the backup? [y/N] " y)
  OUT_FILE=$BATS_TEST_TMPDIR/screen.$RANDOM
  RUN_RC=0
  pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color $*" "${talk[@]}" || RUN_RC=$?
  RUN_OUT=$(pty_screen "$OUT_FILE")
}

# members_of <backup file>: the member names, decrypted first when the file is encrypted.
members_of() {
  local f=$1
  if [[ $f == *.enc ]]; then
    bk_decrypt "$f" "$BK_PASS" "$BATS_TEST_TMPDIR/plain.tar" || return 1
    f=$BATS_TEST_TMPDIR/plain.tar
  fi
  /usr/bin/tar -tf "$f"
}

@test "ask matrix: terminal, --yes, --with-recordings, --passphrase-file: the questions, the file and the exit code (16 runs)" {
  local tty yes rec pf opts want_rq want_eq want_rc got_rq got_eq label f
  for tty in 0 1; do for yes in 0 1; do for rec in 0 1; do for pf in 0 1; do
    fresh
    label="terminal=$tty --yes=$yes --with-recordings=$rec --passphrase-file=$pf"
    opts=""
    [ "$yes" = 0 ] || opts+=" --yes"
    [ "$rec" = 0 ] || opts+=" --with-recordings"
    [ "$pf" = 0 ] || opts+=" --passphrase-file $PASSFILE"
    # A question only on a terminal without --yes, and only for what no option decided.
    want_rq=0 want_eq=0 want_rc=0
    if [ "$tty" = 1 ] && [ "$yes" = 0 ]; then
      [ "$rec" = 1 ] || want_rq=1
      [ "$pf" = 1 ] || want_eq=1
    fi
    [ "$tty" = 1 ] || [ "$yes" = 1 ] || want_rc=3
    if [ "$tty" = 1 ]; then
      local ra=- ea=-
      [ "$want_rq" = 0 ] || ra=""
      [ "$want_eq" = 0 ] || ea=""
      # shellcheck disable=SC2086 # the options, one per word
      on_terminal "$ra" "$ea" $opts
    else
      # shellcheck disable=SC2086
      run bash "$ROOT/custodexa.sh" backup --lang en $opts </dev/null
      RUN_RC=$status RUN_OUT=$output
    fi
    got_rq=$(grep -c 'Put the recordings in the backup file?' <<<"$RUN_OUT" || true)
    got_eq=$(grep -c 'Encrypt the backup file with a passphrase?' <<<"$RUN_OUT" || true)
    [ "$got_rq/$got_eq" = "$want_rq/$want_eq" ] || { echo "$label: questions $got_rq/$got_eq, want $want_rq/$want_eq"; echo "$RUN_OUT"; return 1; }
    [ "$RUN_RC" = "$want_rc" ] || { echo "$label: exit $RUN_RC, want $want_rc"; echo "$RUN_OUT"; return 1; }
    if [ "$want_rc" = 3 ]; then
      no_stop || { echo "$label"; return 1; }
      [[ $RUN_OUT == *"there is no terminal to ask on"* ]] || { echo "$label: $RUN_OUT"; return 1; }
      continue
    fi
    f=$(compgen -G "$ROOT/backups/custodexa-backup-*.tar*" | grep -v '\.sha256$') || { echo "$label: no file"; return 1; }
    [ "$(wc -l <<<"$f")" -eq 1 ] || { echo "$label: $f"; return 1; }
    if [ "$pf" = 1 ]; then
      [[ $f == *.tar.enc ]] || { echo "$label: not encrypted: $f"; return 1; }
      [[ $RUN_OUT == *"Encryption: with the passphrase in $PASSFILE"* ]] || { echo "$label: $RUN_OUT"; return 1; }
    else
      [[ $f == *.tar ]] || { echo "$label: encrypted: $f"; return 1; }
    fi
    members_of "$f" >"$BATS_TEST_TMPDIR/members" || { echo "$label: cannot list $f"; return 1; }
    if [ "$rec" = 1 ]; then
      grep -qx recordings.tar.gz "$BATS_TEST_TMPDIR/members" || { echo "$label: no recordings"; return 1; }
      [[ $RUN_OUT == *"Recordings: included"* ]] || { echo "$label: $RUN_OUT"; return 1; }
    else
      if grep -qx recordings.tar.gz "$BATS_TEST_TMPDIR/members"; then echo "$label: recordings put in"; return 1; fi
    fi
  done; done; done; done
}

@test "recordings: Enter on the terminal leaves them out, the manifest says so, the screen warns with the folder" {
  on_terminal "" ""
  [ "$RUN_RC" = 0 ] || { echo "$RUN_OUT"; return 1; }
  bk_one || return 1
  if bk_member recordings.tar.gz >/dev/null 2>&1; then echo "recordings put in"; return 1; fi
  [ "$(bk_mf contents.recordings)" = false ] && [ "$(bk_mf encryption.enabled)" = false ] || return 1
  [[ $RUN_OUT == *"  Recordings: not included
  Encryption: none
"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  [WARN] The recordings are not in the backup file. They are in
         /opt/custodexa/data/recordings/; keep them some other way, or"* ]] || { echo "$RUN_OUT"; return 1; }
  # The answer 2 puts them in.
  fresh
  on_terminal 2 ""
  [ "$RUN_RC" = 0 ] || { echo "$RUN_OUT"; return 1; }
  bk_one && bk_member recordings.tar.gz >/dev/null && [ "$(bk_mf contents.recordings)" = true ] || return 1
  [[ $RUN_OUT == *"  Recordings: included"* && $RUN_OUT == *"[ OK ] 3/7  Recordings and audit files"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"The recordings are not in the backup file"* ]] || { echo "$RUN_OUT"; return 1; }
}

@test "recordings: --yes --with-recordings asks nothing and puts recordings.tar.gz in" {
  backup_run en --yes --with-recordings
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output != *"[ ?? ]"* && $output == *"  Recordings: included"* ]] || { echo "$output"; return 1; }
  bk_one || return 1
  bk_member recordings.tar.gz | /usr/bin/tar -tzf - | grep -qx 'recordings/2026/a.cast' || return 1
  [ "$(bk_mf contents.recordings)" = true ]
  # Without the option, --yes leaves them out and says how to put them in.
  fresh
  backup_run en --yes
  [ "$status" -eq 0 ] && [[ $output == *"  Recordings: not included (add --with-recordings to include them)
  Encryption: none (add --passphrase-file <file> to encrypt)"* ]] || { echo "$output"; return 1; }
}

@test "ask: an answer other than 1, 2 or Enter is asked again" {
  OUT_FILE=$BATS_TEST_TMPDIR/screen
  pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color" \
    "for the default: " 3 "for the default: " yes "for the default: " 1 \
    "for the default: " 0 "for the default: " "" "Start the backup? [y/N] " n && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$OUT_FILE")
  [ "$rc" = 3 ] && [ "$PTY_FED" = 6 ] || { echo "exit $rc, typed $PTY_FED"; echo "$RUN_OUT"; return 1; }
  [ "$(grep -c '\[WARN\] No such choice; type one of the numbers in brackets.' <<<"$RUN_OUT")" -eq 3 ] || { echo "$RUN_OUT"; return 1; }
  [ "$(grep -c '\[ ?? \] Put the recordings' <<<"$RUN_OUT")" -eq 1 ] || { echo "$RUN_OUT"; return 1; }
  [ "$(grep -c '\[ ?? \] Encrypt the backup file' <<<"$RUN_OUT")" -eq 1 ] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"Start the backup? [y/N] n
Nothing was changed."* ]] || { echo "$RUN_OUT"; return 1; }
  no_stop || return 1
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = cancelled ]
}

@test "ask: the input ending at a question cancels with exit 3; nothing stopped, nothing left unfinished" {
  # At the recordings question.
  OUT_FILE=$BATS_TEST_TMPDIR/screen
  pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color" && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$OUT_FILE")
  [ "$rc" = 3 ] || { echo "exit $rc"; echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"Choose [1-2], or press Enter for the default: "*"Nothing was changed."* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"Encrypt the backup file"* ]] || { echo "$RUN_OUT"; return 1; }
  no_stop || return 1
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = cancelled ] || return 1
  # At the encryption question, and at the passphrase.
  for at in enc pass; do
    fresh
    if [ "$at" = enc ]; then
      pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color" "for the default: " "" && rc=0 || rc=$?
    else
      pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color" "for the default: " "" \
        "for the default: " 2 && rc=0 || rc=$?
    fi
    RUN_OUT=$(pty_screen "$OUT_FILE")
    [ "$rc" = 3 ] && [[ $RUN_OUT == *"Nothing was changed."* ]] || { echo "$at: exit $rc"; echo "$RUN_OUT"; return 1; }
    no_stop || return 1
    [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = cancelled ] || return 1
  done
  [[ $RUN_OUT == *"Passphrase        > "* ]] || { echo "$RUN_OUT"; return 1; }
}

@test "ask: a recordings choice that does not fit is refused before any stop, with the space it needs" {
  # 17.4 GB database, 212 GB recordings, 211 GB free: without them it fits, with them it does not.
  printf '%s\n' 227633266688 >"$DB/du.$(printf '%s' "$ROOT/data/recordings" | tr / -)"
  OUT_FILE=$BATS_TEST_TMPDIR/screen
  pty_talk "$OUT_FILE" "bash $ROOT/custodexa.sh backup --lang en --no-color" "for the default: " 2 && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$OUT_FILE")
  [ "$rc" = 1 ] || { echo "exit $rc"; echo "$RUN_OUT"; return 1; }
  # The choice says so before it is made, and only under the choice that does not fit.
  [[ $RUN_OUT == *"  [1] No (default): a file of about 17.4 GB, services paused about 12 minutes
  [2] Yes: a file of about 229 GB, services paused about 2 hours 37 minutes
      Needs 442 GB, more than is free; this choice will be refused
      Without them, keep the recordings folder some other way."* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"[FAIL] Not enough space for the backup: 442 GB needed (including room to"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"Encrypt the backup file"* ]] || { echo "$RUN_OUT"; return 1; }
  no_stop
}
