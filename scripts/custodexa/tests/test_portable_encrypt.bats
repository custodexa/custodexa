#!/usr/bin/env bats
# Threat (A): an encrypted backup that cannot be opened, or a passphrase that leaks. The file must
# open with the fixed scheme and the passphrase as typed (spaces and backslashes kept), with the
# command a restore uses; a passphrase that breaks the rules, two entries that differ, or a
# passphrase file other accounts can read must stop the run before any service is stopped; and the
# passphrase must not reach the screen, the log, state.json, the manifest, any process's arguments
# or environment, or any file. The known answer vector keeps the scheme itself from drifting.

load helper
load install_host
load backup_host
load pty_host

BK_PASS='test-passphrase-only-0002'
VEC_DIR=$TESTS_DIR/fixtures

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

fresh() {
  rm -rf "$ROOT/backups" "$ROOT/logs" "$ROOT/.custodexa.lock"
  : >"$DB/events"
  bk_state_fresh
  bk_openssl
}

no_stop() {
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ ! -e "$ROOT/backups" ] || [ -z "$(ls -A "$ROOT/backups")" ] || { ls -lA "$ROOT/backups"; return 1; }
}

# interactive <out file> <answers...>: the backup on a terminal (English, no color) with the
# questions answered in turn: recordings, encryption, then the passphrase twice and the confirmation.
interactive() {
  local out=$1
  shift
  pty_talk "$out" "bash $ROOT/custodexa.sh backup --lang en --no-color" "$@"
}

# typed_twice <passphrase>: the answers that choose encryption, type it twice and start.
typed_twice() {
  TALK=("for the default: " "" "for the default: " 2 "secret:Passphrase        > " "$1"
    "secret:Type it again     > " "$1" "Start the backup? [y/N] " y)
}

# no_secret_in <passphrase> <path...>: no file under the paths holds the passphrase.
no_secret_in() {
  local p=$1
  shift
  if grep -rlF -- "$p" "$@" 2>/dev/null; then echo "the passphrase is in the files above"; return 1; fi
  return 0
}

# check_plain <encrypted file> <passphrase>: decrypts with the restore's command to a tar whose
# members are the fixed list and match their SHA256SUMS.
check_plain() {
  local x=$BATS_TEST_TMPDIR/plain
  rm -rf "$x" && mkdir -p "$x"
  bk_decrypt "$1" "$2" "$x.tar" || { echo "does not decrypt"; return 1; }
  /usr/bin/tar -xf "$x.tar" -C "$x" || return 1
  [ "$(/usr/bin/tar -tf "$x.tar" | tr '\n' ' ')" = "backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak tls.tar.gz SHA256SUMS " ] \
    || { /usr/bin/tar -tf "$x.tar"; return 1; }
  (cd "$x" && /usr/bin/sha256sum -c --quiet SHA256SUMS)
}

@test "encrypt: chosen on the terminal, the file is .tar.enc with Salted__ and an 8-byte salt and decrypts to the members" {
  typed_twice "$BK_PASS"
  interactive "$BATS_TEST_TMPDIR/out" "${TALK[@]}" || { pty_screen "$BATS_TEST_TMPDIR/out"; return 1; }
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out")
  bk_one_enc || return 1
  [ "$(ls -A "$ROOT/backups")" = "$(printf '%s\n' "${BK_FILE##*/}" "${BK_FILE##*/}.sha256")" ] || { ls -lA "$ROOT/backups"; return 1; }
  [ "$(stat -c %a "$BK_FILE")" = 600 ] && [ "$(stat -c %a "$BK_FILE.sha256")" = 600 ] || return 1
  (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "${BK_FILE##*/}.sha256") || return 1
  # openssl's salted format with an 8-byte salt: "Salted__", 8 bytes, then whole 16-byte blocks.
  [ "$(head -c 8 "$BK_FILE")" = Salted__ ] || return 1
  [ $(($(stat -c %s "$BK_FILE") % 16)) -eq 0 ] || { stat -c %s "$BK_FILE"; return 1; }
  check_plain "$BK_FILE" "$BK_PASS" || return 1
  # The command for builds without -saltlen (their salt is 8 bytes) opens it too.
  printf '%s\n' "$BK_PASS" | /usr/bin/openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 -pass stdin \
    -in "$BK_FILE" | cmp - "$BATS_TEST_TMPDIR/plain.tar" || return 1
  [ "$(jq -r '."encryption.enabled" + " " + ."encryption.scheme"' "$BATS_TEST_TMPDIR/plain/backup-manifest.json")" = "true cx-enc-1" ] || return 1
  [ "$(jq -r '."last_backup.encrypted" + " " + ."last_backup.file"' "$ROOT/state.json")" = "true backups/${BK_FILE##*/}" ] || return 1
  # The screen says encrypted, the scheme and what a lost passphrase means.
  [[ $RUN_OUT == *"[ OK ] Backup done ("*", encrypted)
  /opt/custodexa/backups/${BK_FILE##*/}
  Checksum file ${BK_FILE##*/}.sha256 (same folder)"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  [WARN] A restore needs the same passphrase. If it is lost the backup
         cannot be restored; keep the passphrase apart from the file."* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  Encryption: AES-256-CBC, key derived from the passphrase with
  PBKDF2-SHA256, 600,000 rounds"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"[ OK ] 7/7  Build the single file, encrypt it and read it back"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"This file is not encrypted"* ]] || { echo "$RUN_OUT"; return 1; }
  # Nothing of it on the screen, in the log, state.json or any file left.
  no_secret_in "$BK_PASS" "$BATS_TEST_TMPDIR/out" "$ROOT/logs" "$ROOT/state.json" "$ROOT/backups" \
    "$BATS_TEST_TMPDIR/plain" "$DB/run.argv" "$DB/run.env" || return 1
  # status says it is encrypted.
  [[ $(bk_status) == *"/opt/custodexa/backups/${BK_FILE##*/}    "*" (encrypted)"* ]] || { bk_status; return 1; }
}

@test "encrypt: two different entries are asked again with the tries left; three rounds cancel, nothing stopped, exit 3" {
  interactive "$BATS_TEST_TMPDIR/out" "for the default: " "" "for the default: " 2 \
    "secret:Passphrase        > " test-passphrase-a1 "secret:Type it again     > " test-passphrase-b2 \
    "secret:Passphrase        > " test-passphrase-a1 "secret:Type it again     > " test-passphrase-b2 \
    "secret:Passphrase        > " test-passphrase-a1 "secret:Type it again     > " test-passphrase-b2 && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out")
  [ "$rc" = 3 ] && [ "$PTY_FED" = 8 ] || { echo "exit $rc, typed $PTY_FED"; echo "$RUN_OUT"; return 1; }
  diff <(sed -n '/^  Passphrase: 12 to 256/,$p' <<<"$RUN_OUT" | sed 's/ *$//') - <<'EOF' || { echo "$RUN_OUT"; return 1; }
  Passphrase: 12 to 256 characters; letters, digits, spaces and symbols
  from a US keyboard only. Spaces count as part of the passphrase.
  Passphrase        >
  Type it again     >
  [WARN] The two entries differ; type it again (2 more tries).
  Passphrase        >
  Type it again     >
  [WARN] The two entries differ; type it again (1 more try).
  Passphrase        >
  Type it again     >
[FAIL] No passphrase was set after three tries; the backup is cancelled.
       Nothing was changed.
EOF
  no_stop || return 1
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = cancelled ] || return 1
  no_secret_in test-passphrase "$BATS_TEST_TMPDIR/out" "$ROOT/logs" "$ROOT/state.json"
}

@test "encrypt: --yes on a terminal asks nothing, does not encrypt and says how to" {
  pty_talk "$BATS_TEST_TMPDIR/out" "bash $ROOT/custodexa.sh backup --lang en --no-color --yes" && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out")
  [ "$rc" = 0 ] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"[ ?? ]"* && $RUN_OUT != *"Passphrase"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  Encryption: none (add --passphrase-file <file> to encrypt)"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"Start the backup? [y/N] y"* ]] || { echo "$RUN_OUT"; return 1; }
  bk_one && [ "$(bk_mf encryption.enabled)" = false ] && [ ! -e "$DB/run.argv" ]
}

@test "passphrase file: mode 0644 is refused before any stop with the chmod 600 command" {
  chmod 644 "$PASSFILE"
  backup_run en --yes --passphrase-file "$PASSFILE"
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed "s#$BATS_TEST_TMPDIR#/root#g") - <<'EOF' || { echo "$output"; return 1; }
[FAIL] Other accounts can read or write the passphrase file /root/cx-pass
       (mode 0644), or it is owned by someone other than you or root, or it
       has an extra access control list. Nothing was stopped. Fix it and
       run again:
  sudo chown root /root/cx-pass
  sudo chmod 600 /root/cx-pass
EOF
  no_stop || return 1
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = failed ]
}

@test "passphrase file: missing, a link, a folder, 0640, 0604, another owner, an ACL, a bad first line are refused before any stop" {
  local f=$BATS_TEST_TMPDIR/pf
  # case <label> <expected words>: run with the file at $f, refused before any stop with the words.
  refused() {
    fresh
    backup_run en --yes --passphrase-file "$f"
    [ "$status" -eq 3 ] || { echo "$1: exit $status"; echo "$output"; return 1; }
    [[ $output == *"$2"* ]] || { echo "$1: no \"$2\""; echo "$output"; return 1; }
    no_stop || { echo "$1"; return 1; }
    [ ! -e "$DB/run.argv" ] || { echo "$1: a tool ran"; return 1; }
  }
  rm -rf "$f"
  refused missing "Cannot read the passphrase file $f (missing, not a regular" || return 1
  bk_passfile "$BATS_TEST_TMPDIR/target" "$BK_PASS"
  ln -s "$BATS_TEST_TMPDIR/target" "$f"
  refused "symbolic link" "Cannot read the passphrase file $f" || return 1
  rm -f "$f" && mkdir -m 700 "$f"
  refused folder "Cannot read the passphrase file $f" || return 1
  rm -rf "$f"
  for m in 640 604 660 606 620 602; do
    bk_passfile "$f" "$BK_PASS"
    chmod "$m" "$f"
    refused "mode $m" "(mode 0$m)" || return 1
    [[ $output == *"  sudo chmod 600 $f"* && $output != *"setfacl"* ]] || { echo "$output"; return 1; }
  done
  chmod 600 "$f" && chown 4321 "$f"
  refused "another owner" "or it is owned by someone other than you or root" || return 1
  [[ $output == *"  sudo chown root $f"* ]] || { echo "$output"; return 1; }
  chown 0 "$f"
  # An extended ACL with no group bit left in the mode: only the ACL tells.
  setfacl -m u:nobody:r "$f" && chmod 600 "$f"
  [[ $(ls -ld "$f") == -rw-------+* ]] || { ls -ld "$f"; return 1; }
  refused acl "has an extra access control list" || return 1
  [[ $output == *"  sudo setfacl -b $f"* ]] || { echo "$output"; return 1; }
  setfacl -b "$f"
  # The first line: 11 characters, a character outside ASCII, an empty file.
  for line in 'test-pass11' 'test-passphrase-測試' ''; do
    printf '%s\n' "$line" >"$f"
    refused "first line [$line]" "The first line of the passphrase file $f does not fit the" || return 1
  done
  : >"$f"
  refused "empty file" "does not fit the" || return 1
  # The same file with a good first line goes through.
  bk_passfile "$f" "$BK_PASS"
  fresh
  backup_run en --yes --passphrase-file "$f"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one_enc
}

@test "passphrase file: a CRLF line end is left out of the passphrase; later lines are not read" {
  printf '%s\r\nsecond-line-not-used\n' "$BK_PASS" >"$PASSFILE"
  backup_run en --yes --passphrase-file "$PASSFILE"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one_enc || return 1
  check_plain "$BK_FILE" "$BK_PASS" || return 1
  # With the carriage return it does not open.
  if printf '%s\r\n' "$BK_PASS" | /usr/bin/openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 \
    -iter 600000 -pass stdin -in "$BK_FILE" 2>/dev/null | /usr/bin/tar -tf - >/dev/null 2>&1; then
    echo "the carriage return was kept"; return 1
  fi
}

@test "encrypt: no openssl image on the host is refused before any stop, with the load command" {
  host_arch x86_64
  # Not recorded at all, then recorded but not on the host.
  for how in unrecorded absent; do
    fresh
    if [ "$how" = unrecorded ]; then bk_state_fresh; else : >"$DB/images"; fi
    backup_run en --yes --passphrase-file "$PASSFILE"
    [ "$status" -eq 3 ] || { echo "$how: $output"; return 1; }
    diff <(screen_of "$output") - <<'EOF' || { echo "$how"; return 1; }
[FAIL] This host does not have the openssl image used for encryption (it
       is obtained at install or upgrade). Nothing was stopped. Load the
       offline image bundle of this release (1.13.0), or choose no
       encryption. The bundle is named like custodexa-images-1.13.0-amd64.tar
       and is on the same release page as the package:
  sudo /opt/custodexa/custodexa.sh load custodexa-images-1.13.0-amd64.tar --lang en
EOF
    no_stop || return 1
  done
  # Chosen on the terminal: refused right after the choice, before the passphrase is asked.
  fresh
  : >"$DB/images"
  interactive "$BATS_TEST_TMPDIR/out" "for the default: " "" "for the default: " 2 && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out")
  [ "$rc" = 3 ] && [[ $RUN_OUT == *"[FAIL] This host does not have the openssl image"* && $RUN_OUT != *"Passphrase        >"* ]] \
    || { echo "exit $rc"; echo "$RUN_OUT"; return 1; }
  no_stop
}

@test "encrypt: the passphrase is in no log, state, manifest, argv, environment or new file" {
  # Hold the encryption container while it runs and look at every process then.
  : >"$DB/pause.run.enc"
  bash "$ROOT/custodexa.sh" backup --lang en --yes --passphrase-file "$PASSFILE" </dev/null >"$BATS_TEST_TMPDIR/out" 2>&1 &
  local pid=$! p hits=""
  wait_for "$DB/paused.run.enc" || { kill "$pid"; cat "$BATS_TEST_TMPDIR/out"; return 1; }
  for p in /proc/[0-9]*; do
    if tr '\0' '\n' <"$p/cmdline" 2>/dev/null | grep -qF -- "$BK_PASS"; then hits+=" cmdline:${p#/proc/}"; fi
    if tr '\0' '\n' <"$p/environ" 2>/dev/null | grep -qF -- "$BK_PASS"; then hits+=" environ:${p#/proc/}"; fi
  done
  ps -eo pid,args >"$BATS_TEST_TMPDIR/ps"
  # The script's own processes were there to look at.
  grep -q 'custodexa.sh backup' "$BATS_TEST_TMPDIR/ps" || { cat "$BATS_TEST_TMPDIR/ps"; return 1; }
  : >"$DB/go.run.enc"
  wait "$pid" || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
  [ -z "$hits" ] || { echo "the passphrase is in:$hits"; return 1; }
  no_secret_in "$BK_PASS" "$BATS_TEST_TMPDIR/ps" "$BATS_TEST_TMPDIR/out" || return 1
  # The tool containers got it on stdin only: not in their arguments, environment or mounts.
  [ "$(grep -c . "$DB/run.argv")" -eq 2 ] || { cat "$DB/run.argv"; return 1; }
  no_secret_in "$BK_PASS" "$DB/run.argv" "$DB/run.env" "$DB/run.mounts" "$ROOT/logs" "$ROOT/state.json" \
    "$ROOT/backups" "$ROOT/.env" || return 1
  grep -q -- '-pass stdin' "$DB/run.argv" || return 1
  # The members and the manifest inside the file hold no trace of it either.
  bk_one_enc && check_plain "$BK_FILE" "$BK_PASS" || return 1
  no_secret_in "$BK_PASS" "$BATS_TEST_TMPDIR/plain" || return 1
  # The only files that ever held it are the passphrase file and the test's own copies.
  [ "$(grep -rlF -- "$BK_PASS" "$ROOT" | wc -l)" -eq 0 ]
}

@test "encrypt: interrupted while the encryption container runs: it is removed, the pipe gone, no file" {
  : >"$DB/pause.run.enc"
  printf '%s\n' custodexa-backup-tool-20260930-101502-enc >"$DB/tools"
  bash "$ROOT/custodexa.sh" backup --lang en --yes --passphrase-file "$PASSFILE" </dev/null >"$BATS_TEST_TMPDIR/out" 2>&1 &
  local pid=$!
  wait_for "$DB/paused.run.enc" || { kill "$pid"; return 1; }
  kill -TERM "$pid"
  wait "$pid" && rc=0 || rc=$?
  : >"$DB/go.run.enc"
  [ "$rc" = 1 ] || { echo "exit $rc"; cat "$BATS_TEST_TMPDIR/out"; return 1; }
  grep -qx 'rm rm -f custodexa-backup-tool-20260930-101502-enc' "$DB/events" || { cat "$DB/events"; return 1; }
  [ -z "$(find "$ROOT/backups" -type p)" ] || { find "$ROOT/backups" -type p; return 1; }
  [ -z "$(compgen -G "$ROOT/backups/custodexa-backup-*")" ] || { ls -lA "$ROOT/backups"; return 1; }
  grep -q 'The backup was interrupted at step 7 and no backup file was made.' "$BATS_TEST_TMPDIR/out" \
    || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
}

@test "encrypt: the read-back takes the decrypted tar from the pipe in pieces of any size" {
  : >"$DB/run.odd"
  backup_run en --yes --passphrase-file "$PASSFILE"
  [ "$status" -eq 0 ] || { echo "$output"; cat "$ROOT"/logs/backup-*.log; return 1; }
  bk_one_enc && check_plain "$BK_FILE" "$BK_PASS"
}

@test "encrypt: the encryption container failing is a failed step 7: no file, the record as it was" {
  printf '%s\n' 125 >"$DB/run.rc"
  backup_run en --yes --passphrase-file "$PASSFILE"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 7/7  Build the single file, encrypt it and read it back"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The backup did not finish and no backup file was made."* ]] || { echo "$output"; return 1; }
  [ -z "$(compgen -G "$ROOT/backups/custodexa-backup-*")" ] && [ -z "$(bk_pointer)" ] || return 1
  [ -z "$(find "$ROOT/backups" -type p)" ]
}

@test "known answer: the stored vector decrypts to the recorded plaintext; wrong passphrase, -iter, -md or a cut block do not" {
  local vec=$VEC_DIR/cx-enc-1-vector.tar.enc pass want got cut=$BATS_TEST_TMPDIR/cut.enc
  pass=$(sed -n 's/^passphrase=//p' "$VEC_DIR/cx-enc-1-vector.txt")
  want=$(sed -n 's/^plaintext_sha256=//p' "$VEC_DIR/cx-enc-1-vector.txt")
  [[ $want =~ ^[0-9a-f]{64}$ ]] && [ -n "$pass" ] || return 1
  # dec <passphrase> <iter> <md> <file>: the SHA-256 of what openssl gives (empty when it fails).
  dec() {
    local out
    out=$(printf '%s\n' "$1" | /usr/bin/openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md "$3" -iter "$2" \
      -pass stdin -in "$4" 2>/dev/null | /usr/bin/sha256sum) || true
    printf '%s' "${out%% *}"
  }
  got=$(dec "$pass" 600000 sha256 "$vec")
  [ "$got" = "$want" ] || { echo "the vector gives $got"; return 1; }
  printf '%s\n' "$pass" | /usr/bin/openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 \
    -pass stdin -in "$vec" | /usr/bin/tar -tf - | grep -qx vector.txt || return 1
  [ "$(dec "${pass}x" 600000 sha256 "$vec")" != "$want" ] || { echo "a wrong passphrase opens it"; return 1; }
  [ "$(dec "$pass" 599999 sha256 "$vec")" != "$want" ] || { echo "another -iter opens it"; return 1; }
  [ "$(dec "$pass" 600000 sha512 "$vec")" != "$want" ] || { echo "another -md opens it"; return 1; }
  head -c $(($(stat -c %s "$vec") - 16)) "$vec" >"$cut"
  [ "$(dec "$pass" 600000 sha256 "$cut")" != "$want" ] || { echo "a cut file opens it"; return 1; }
}

@test "passphrase: spaces before it and backslashes are kept: the same string decrypts, without the spaces it does not" {
  local p='  test\pass phrase\0n\ '
  typed_twice "$p"
  interactive "$BATS_TEST_TMPDIR/out" "${TALK[@]}" || { pty_screen "$BATS_TEST_TMPDIR/out"; return 1; }
  bk_one_enc || return 1
  check_plain "$BK_FILE" "$p" || return 1
  if bk_decrypt "$BK_FILE" "${p#  }" "$BATS_TEST_TMPDIR/stripped.tar" 2>/dev/null \
    && /usr/bin/tar -tf "$BATS_TEST_TMPDIR/stripped.tar" >/dev/null 2>&1; then
    echo "the passphrase without its leading spaces opens it"; return 1
  fi
  no_secret_in 'test\pass phrase' "$BATS_TEST_TMPDIR/out" "$ROOT/logs" "$ROOT/state.json"
}

@test "passphrase: 11 and 257 characters and a character outside ASCII are asked again; 12 and 256 are taken" {
  local p11 p12 p256 p257
  p11=$(printf 'k%.0s' $(seq 1 11)) p12=$(printf 'k%.0s' $(seq 1 12))
  p256=$(printf 'k%.0s' $(seq 1 256)) p257=$(printf 'k%.0s' $(seq 1 257))
  interactive "$BATS_TEST_TMPDIR/out" "for the default: " "" "for the default: " 2 \
    "secret:Passphrase        > " "$p11" "secret:Passphrase        > " "$p257" \
    "secret:Passphrase        > " "$p256" "secret:Type it again     > " "$p256" "Start the backup? [y/N] " n \
    && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out" | sed 's/ *$//')
  [ "$rc" = 3 ] && [ "$PTY_FED" = 7 ] || { echo "exit $rc, typed $PTY_FED"; echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  [WARN] The passphrase needs at least 12 characters; type it again (2 more tries).
  Passphrase        >
  [WARN] The passphrase can have at most 256 characters; type it again (1 more try).
  Passphrase        >
  Type it again     >
  [ OK ] Both entries match"* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  Encryption: with a passphrase (AES-256)"* ]] || { echo "$RUN_OUT"; return 1; }
  no_secret_in "$p11" "$BATS_TEST_TMPDIR/out" || return 1
  # Outside ASCII, then 12 characters, taken, and the file opens with them.
  fresh
  interactive "$BATS_TEST_TMPDIR/out" "for the default: " "" "for the default: " 2 \
    "secret:Passphrase        > " 'test-密碼-passphrase' "secret:Passphrase        > " "$p12" \
    "secret:Type it again     > " "$p12" "Start the backup? [y/N] " y && rc=0 || rc=$?
  RUN_OUT=$(pty_screen "$BATS_TEST_TMPDIR/out")
  [ "$rc" = 0 ] || { echo "exit $rc"; echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT == *"  [WARN] The passphrase has characters that are not accepted (for example
         non-English letters or full-width symbols); type it again (2 more tries)."* ]] || { echo "$RUN_OUT"; return 1; }
  [[ $RUN_OUT != *"密碼"* ]] || { echo "$RUN_OUT"; return 1; }
  bk_one_enc && check_plain "$BK_FILE" "$p12"
}
