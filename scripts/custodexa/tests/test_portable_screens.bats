#!/usr/bin/env bats
# Threat (A): screens that drift from the reviewed text. Each screen of the backup this release
# reviewed is run here as an operator meets it and compared word for word with its snapshot,
# tests/snapshots/backup-<screen>.<lang>.txt: the zh-TW and en of every screen `backup` prints, and the ja
# of five. A snapshot holds one or more runs, each between a "==== <what was run> ====" line and an
# "==== exit <code> ====" line; trailing blanks are dropped (a prompt ends in one). The menu, help
# and status screens are compared by test_messages.bats and test_portable_backup.bats.
# CX_SNAPSHOT_WRITE=<folder> writes the screens there instead of comparing (to review a change);
# a change of a snapshot names the screens it changed in its commit message.

load helper
load install_host
load backup_host
load pty_host

TS=20260930-101502
FILE=custodexa-backup-1.13.0-$TS.tar
BK_PASS='test-passphrase-only-0004'
GIB=1073741824

# The snapshots that must exist for the backup screens: one per screen and language, written out
# so that a snapshot added or lost shows as a difference.
SNAPSHOTS="backup-ask-recordings.zh-TW backup-ask-recordings.en backup-confirm.zh-TW backup-confirm.en backup-progress.zh-TW backup-progress.en backup-done-ui.zh-TW backup-done-ui.en backup-done-ui.ja
backup-done-key.zh-TW backup-done-key.en backup-no-space.zh-TW backup-no-space.en backup-failed-early.zh-TW backup-failed-early.en backup-failed-early.ja backup-failed-late.zh-TW backup-failed-late.en backup-no-questions.zh-TW
backup-no-questions.en backup-version-mismatch.zh-TW backup-version-mismatch.en backup-ask-encrypt.zh-TW backup-ask-encrypt.en backup-ask-passphrase.zh-TW backup-ask-passphrase.en backup-retype-passphrase.zh-TW backup-retype-passphrase.en backup-passphrase-gave-up.zh-TW
backup-passphrase-gave-up.en backup-passfile-problem.zh-TW backup-passfile-problem.en backup-encrypt-line.zh-TW backup-encrypt-line.en backup-confirm-encrypted.zh-TW backup-confirm-encrypted.en backup-done-encrypted.zh-TW backup-done-encrypted.en backup-done-encrypted.ja
backup-no-crypt-image.zh-TW backup-no-crypt-image.en backup-key-mismatch.zh-TW backup-key-mismatch.en backup-key-mismatch.ja backup-restart-outcomes.zh-TW backup-restart-outcomes.en backup-restart-outcomes.ja backup-committed-unrecorded.zh-TW backup-committed-unrecorded.en
backup-interrupted.zh-TW backup-interrupted.en backup-previous-unfinished.zh-TW backup-previous-unfinished.en backup-interrupted-committed.zh-TW backup-interrupted-committed.en"

setup() {
  PASSFILE=$BATS_TEST_TMPDIR/cx-pass
}

# du_is <path> <bytes>: what du reports for the path.
du_is() { printf '%s\n' "$2" >"$DB/du.$(printf '%s' "$1" | tr / -)"; }

# case_host <master key mode> [recordings bytes]: a fresh deployment with the sizes of the reviewed
# text (database 17.4 GB, audit files 12 MB, recordings 212 GB, 211 GB free, a file of 17.4 GB),
# the encryption image, a passphrase file, and the step times of the reviewed progress screen.
case_host() {
  rm -rf "$BATS_TEST_TMPDIR/opt" "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/host" "$BATS_TEST_TMPDIR/replay"
  backup_host "$1"
  backup_strict
  fake sleep ':'
  printf '%s\n' 18683107737 >"$DB/size"
  du_is "$ROOT/data/audit" 12582912
  du_is "$ROOT/data/recordings" "${2:-227633266688}"
  du_is "$ROOT/backups/$FILE" 18690000000
  du_is "$ROOT/backups/$FILE.enc" 18690000000
  bk_openssl
  bk_passfile "$PASSFILE" "$BK_PASS"
  host_arch x86_64
  # stop 11s, database 1m 40s, audit 2s, settings, start 41s, check 38s, the file 3m 12s
  clock 0 11 0 100 0 2 0 0 41 0 38 0 192
}

# clock_enc: the same times, the encrypted file 3m 40s.
clock_enc() { clock 0 11 0 100 0 2 0 0 41 0 38 0 220; }

# norm: a screen as the snapshots hold it.
norm() {
  tr -d '\r' | sed -e "s#$ROOT#/opt/custodexa#g" -e "s#$PASSFILE#/root/cx-pass#g" -e 's/[[:space:]]*$//'
}

# block <what> <exit code> <screen file>: one run in a snapshot.
block() {
  printf '==== %s ====\n' "$1"
  norm <"$3"
  printf '==== exit %s ====\n' "$2"
}

# plain <what> <lang> [options...]: `backup` without a terminal, as automation runs it.
plain() {
  local what=$1 l=$2 rc=0
  shift 2
  bash "$ROOT/custodexa.sh" backup --lang "$l" "$@" </dev/null >"$BATS_TEST_TMPDIR/screen" 2>&1 || rc=$?
  block "$what" "$rc" "$BATS_TEST_TMPDIR/screen"
}

# Prompts in each language: a choice, the confirmation, the passphrase entries.
prompt_choose() {
  case $1 in en) printf 'for the default: ' ;; zh-TW) printf '直接按 Enter 使用預設：' ;; ja) printf 'Enter で既定を使います：' ;; esac
}

# talk <what> <lang> <answers...> [-- options...]: `backup` on a terminal. An answer is c:<text>
# (a choice), p:<text> (a passphrase entry) or y:<text> (the confirmation).
talk() {
  local what=$1 l=$2 a rc=0
  local -a t=() opts=()
  shift 2
  while [ $# -gt 0 ] && [ "$1" != -- ]; do
    a=$1
    case $a in
      c:*) t+=("$(prompt_choose "$l")" "${a#c:}") ;;
      p:*) t+=("secret:> " "${a#p:}") ;;
      y:*) t+=("[y/N] " "${a#y:}") ;;
    esac
    shift
  done
  [ $# -eq 0 ] || { shift; opts=("$@"); }
  pty_talk "$BATS_TEST_TMPDIR/screen" "bash $ROOT/custodexa.sh backup --lang $l --no-color ${opts[*]}" "${t[@]}" || rc=$?
  block "$what" "$rc" "$BATS_TEST_TMPDIR/screen"
}

# background <what> <lang> <point>: `backup --yes` held at a point of the fake (paused.<point>),
# sent SIGTERM there, then let go.
background() {
  local what=$1 l=$2 point=$3 rc=0 pid
  bash "$ROOT/custodexa.sh" backup --lang "$l" --yes </dev/null >"$BATS_TEST_TMPDIR/screen" 2>&1 &
  pid=$!
  wait_for "$DB/paused.$point" >&2 || { kill -9 "$pid"; return 1; }
  kill -TERM "$pid"
  : >"$DB/go.$point"
  wait "$pid" || rc=$?
  block "$what" "$rc" "$BATS_TEST_TMPDIR/screen"
}

# ---------- the screens ----------

screen_backup_ask_recordings() {
  case_host ui
  talk "on a terminal, ui, recordings too big for the free space: Enter, Enter, n" "$1" c: c: y:n
}
screen_backup_confirm() {
  case_host kms $((2 * GIB))
  talk "on a terminal, kms: recordings 2, Enter, n" "$1" c:2 c: y:n
}
screen_backup_progress() {
  case_host env $((2 * GIB))
  talk "on a terminal, env: recordings 2, Enter, y" "$1" c:2 c: y:y
}
screen_backup_done_ui() {
  case_host ui
  talk "on a terminal, ui: Enter, Enter, y" "$1" c: c: y:y
}
screen_backup_done_key() {
  case_host env
  plain "--yes, env" "$1" --yes
  case_host kms
  printf '%s\n' 'arn:aws:kms:ap-northeast-1:111122223333:key/0b1c2d3e-0000-4000-8000-000000000000' >"$DB/kek"
  plain "--yes, kms with a key ID" "$1" --yes
  case_host ui
  rm -f "$DB/kek"
  plain "--yes, ui, no master key fingerprint" "$1" --yes
  case_host ui
  printf '1\n' >"$DB/checkpoint.rc"
  plain "--yes, ui, the master key fingerprint read, another one not" "$1" --yes
}
screen_backup_no_space() {
  case_host ui
  host_free / 21076378 # 20.1 GB
  plain "--yes, ui, 20.1 GB free" "$1" --yes
}
screen_backup_failed_early() {
  case_host ui
  printf '1\n' >"$DB/pg_dump.rc"
  plain "--yes, ui, the database dump fails" "$1" --yes
}
screen_backup_failed_late() {
  case_host ui
  printf '2\n' >"$DB/tar.pack.rc"
  plain "--yes, ui, building the file fails" "$1" --yes
}
screen_backup_no_questions() {
  case_host ui
  plain "no terminal, no --yes" "$1"
}
screen_backup_version_mismatch() {
  case_host ui
  sed -i 's/"version": "1.13.0"/"version": "1.13.1"/' "$ROOT/releases/1.13.0/MANIFEST.json"
  plain "--yes, current/MANIFEST.json is 1.13.1" "$1" --yes
}
screen_backup_ask_encrypt() {
  case_host env
  talk "on a terminal, env: Enter, Enter, n" "$1" c: c: y:n
}
screen_backup_ask_passphrase() {
  case_host ui
  talk "on a terminal, ui: Enter, encrypt, the passphrase twice, n" "$1" c: c:2 "p:$BK_PASS" "p:$BK_PASS" y:n
}
screen_backup_retype_passphrase() {
  case_host ui
  talk "on a terminal: two entries that differ, then 11 characters, then the passphrase twice, n" "$1" \
    c: c:2 p:test-passphrase-a1 p:test-passphrase-b2 p:test-pass11 "p:$BK_PASS" "p:$BK_PASS" y:n
}
screen_backup_passphrase_gave_up() {
  case_host ui
  talk "on a terminal: a character outside ASCII, 257 characters, two entries that differ" "$1" \
    c: c:2 'p:test-密碼-passphrase' "p:$(printf 'k%.0s' $(seq 1 257))" p:test-passphrase-a1 p:test-passphrase-b2
}
screen_backup_passfile_problem() {
  case_host ui
  rm -f "$PASSFILE"
  plain "--yes --passphrase-file, no such file" "$1" --yes --passphrase-file "$PASSFILE"
  bk_passfile "$PASSFILE" "$BK_PASS"
  chmod 644 "$PASSFILE"
  plain "--yes --passphrase-file, mode 0644" "$1" --yes --passphrase-file "$PASSFILE"
  chmod 600 "$PASSFILE"
  setfacl -m u:nobody:r "$PASSFILE" && chmod 600 "$PASSFILE"
  plain "--yes --passphrase-file, mode 0600 with an extended ACL" "$1" --yes --passphrase-file "$PASSFILE"
  setfacl -b "$PASSFILE"
  printf 'test-pass11\n' >"$PASSFILE"
  plain "--yes --passphrase-file, a first line of 11 characters" "$1" --yes --passphrase-file "$PASSFILE"
}
screen_backup_encrypt_line() {
  case_host ui
  clock_enc
  talk "on a terminal with --passphrase-file, ui: Enter, y" "$1" c: y:y -- --passphrase-file "$PASSFILE"
}
screen_backup_confirm_encrypted() {
  case_host ui
  clock_enc
  talk "on a terminal, ui: Enter, encrypt, the passphrase twice, y" "$1" c: c:2 "p:$BK_PASS" "p:$BK_PASS" y:y
}
screen_backup_done_encrypted() {
  case_host ui
  clock_enc
  plain "--yes --passphrase-file, ui" "$1" --yes --passphrase-file "$PASSFILE"
  case_host env
  clock_enc
  plain "--yes --passphrase-file, env" "$1" --yes --passphrase-file "$PASSFILE"
}
screen_backup_no_crypt_image() {
  case_host ui
  bk_state_fresh
  plain "--yes --passphrase-file, no openssl image recorded" "$1" --yes --passphrase-file "$PASSFILE"
}
screen_backup_key_mismatch() {
  case_host ui
  bk_dotenv_raw KEK_PROVIDER=ui "ENCRYPTION_KEY=$BK_KEK"
  plain "--yes, KEK_PROVIDER=ui with an ENCRYPTION_KEY" "$1" --yes
  bk_dotenv_raw
  plain "--yes, neither KEK_PROVIDER nor ENCRYPTION_KEY" "$1" --yes
  bk_dotenv_raw KEK_PROVIDER=env
  plain "--yes, KEK_PROVIDER=env without ENCRYPTION_KEY" "$1" --yes
  bk_dotenv_raw KEK_PROVIDER=UI
  plain "--yes, KEK_PROVIDER=UI" "$1" --yes
}
screen_backup_restart_outcomes() {
  case_host env
  plain "--yes, env, ready at once" "$1" --yes
  case_host kms
  plain "--yes, kms, ready at once" "$1" --yes
  case_host ui
  printf '1\n' >"$DB/health.rc"
  clock 0 11 0 100 0 2 0 0 180 0 38 0 192
  plain "--yes, ui, never ready (60 tries)" "$1" --yes
}
screen_backup_committed_unrecorded() {
  case_host ui
  printf '1\n' >"$DB/mv.state.rc"
  plain "--yes, ui, state.json cannot be written after the commit" "$1" --yes
  case_host ui
  printf '1\n' >"$DB/rmdir.rc"
  plain "--yes, ui, the temporary folder cannot be removed" "$1" --yes
}
screen_backup_interrupted() {
  case_host ui
  : >"$DB/tar.audit.sleep"
  background "--yes, ui, SIGTERM at step 3" "$1" tar
}
screen_backup_previous_unfinished() {
  screen_backup_interrupted "$1" >/dev/null
  rm -f "$DB/tar.audit.sleep" "$DB/paused.tar"
  clock 0 11 0 100 0 2 0 0 41 0 38 0 192
  plain "--yes, ui, the next backup after one interrupted at step 3" "$1" --yes
}
screen_backup_interrupted_committed() {
  case_host ui
  : >"$DB/pause.committed"
  background "--yes, ui, SIGTERM once the file is in place" "$1" committed
  case_host ui
  : >"$DB/pause.recorded"
  background "--yes, ui, SIGTERM once state.json points at the file" "$1" recorded
}

# ---------- the tests ----------

@test "screens: the snapshot files of the backup screens are exactly the list (one per screen and language)" {
  local f got=""
  for f in "$TESTS_DIR"/snapshots/backup-*.txt; do
    [ -e "$f" ] || continue
    f=${f##*/}
    # The screens of an external database have their own exact list (test_external_screens.bats).
    [[ $f != backup-external-* ]] || continue
    got+="${f%.txt}"$'\n'
  done
  diff <(printf '%s' "$got" | sort) <(printf '%s\n' $SNAPSHOTS | sort)
}

@test "screens: every backup screen in each language matches its snapshot" {
  local s pb l want got bad=""
  for s in $SNAPSHOTS; do
    pb=${s%%.*} l=${s#*.}
    got=$BATS_TEST_TMPDIR/$s.txt
    "screen_${pb//-/_}" "$l" >"$got" || { echo "$s: the run did not get through"; cat "$got"; return 1; }
    if [ -n "${CX_SNAPSHOT_WRITE:-}" ]; then
      cp "$got" "$CX_SNAPSHOT_WRITE/$s.txt"
      continue
    fi
    want=$TESTS_DIR/snapshots/$s.txt
    diff "$want" "$got" >"$BATS_TEST_TMPDIR/$s.diff" 2>&1 || bad+=" $s"
  done
  [ -z "$bad" ] && return 0
  for s in $bad; do echo "== $s"; head -n 40 "$BATS_TEST_TMPDIR/$s.diff"; done
  return 1
}
