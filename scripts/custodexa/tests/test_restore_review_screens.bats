#!/usr/bin/env bats
load helper
load pty_host
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  mkdir -p "$ROOT"
}

review_snapshot() {
  local name=$1 want=$2 l expected actual rc errors=0
  for l in en zh-TW ja; do
    actual=$BATS_TEST_TMPDIR/$name.$l.txt
    case $name in
      host-values)
        rc=0
        pty_talk "$actual" "bash '$TESTS_DIR/restore_review_screen.sh' '$SRC' '$ROOT' '$l' '$name'" \
          '> ' '' '> ' '' '> ' '' '> ' '' || rc=$?
        [ "$PTY_FED" = 4 ] || { cat "$actual"; return 1; }
        output=$(tr -d '\r' <"$actual"); status=$rc ;;
      passphrase|revert)
        # Echo is disabled before input is consumed. The marker removes only script's
        # initial input echo, not anything emitted by the production screen functions.
        local answer=screen-passphrase
        [ "$name" != revert ] || answer=1.16.0
        run bash -c 'printf "%s\n" "$2" | script -qec "$1" /dev/null' _ \
          "stty -echo; printf '\036'; bash '$TESTS_DIR/restore_review_screen.sh' '$SRC' '$ROOT' '$l' '$name'" "$answer"
        output=${output//$'\r'/}; output=${output#*$'\036'} ;;
      *) run bash "$TESTS_DIR/restore_review_screen.sh" "$SRC" "$ROOT" "$l" "$name" </dev/null ;;
    esac
    rc=$status
    output=${output//"$ROOT/transfer"/\/srv\/transfer}
    output=${output//"$ROOT"/\/opt\/custodexa}
    printf '%s\n' "$output" >"$actual"
    expected=$TESTS_DIR/snapshots/restore-$name.$l.txt
    case $name in progress-same|progress-new)
      # The runner also prints the separately reviewed unseal instructions. Compare both
      # complete screens, including whitespace, without changing either approved fixture.
      cat "$expected" "$TESTS_DIR/snapshots/restore-unseal-wait.$l.txt" >"$BATS_TEST_TMPDIR/progress-expected.$l"
      expected=$BATS_TEST_TMPDIR/progress-expected.$l ;;
    esac
    if [ "$rc" != "$want" ]; then echo "$name $l: exit $rc, expected $want"; errors=1; fi
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(base64 -w0 <"$actual")" >&3
      errors=1
    else diff -u "$expected" "$actual" || errors=1; fi
  done
  [ "$errors" = 0 ]
}

@test "restore reviewed screen: missing checksum without a terminal" { review_snapshot checksum-missing 1; }
@test "restore reviewed screen: hidden passphrase prompt" { review_snapshot passphrase 0; }
@test "restore reviewed screen: reading and checking the file" { review_snapshot read-progress 0; }
@test "restore reviewed screen: an old backup folder" { review_snapshot old-folder 1; }
@test "restore reviewed screen: corrupt member checksum" { review_snapshot corrupt-file 1; }
@test "restore reviewed screen: no master key fingerprint" { review_snapshot fingerprint-missing 1; }
@test "restore reviewed screen: settings key mismatch" { review_snapshot settings-key-mismatch 1; }
@test "restore reviewed screen: release manifest mismatch" { review_snapshot release-mismatch 1; }
@test "restore reviewed screen: engine older than the data" { review_snapshot engine-too-old 1; }
@test "restore reviewed screen: unsupported master key mode" { review_snapshot unsupported-key 1; }
@test "restore reviewed screen: host value questions" { review_snapshot host-values 0; }
@test "restore reviewed screen: insufficient space" { review_snapshot space-short 1; }
@test "restore reviewed screen: same host progress" { review_snapshot progress-same 4; }
@test "restore reviewed screen: new host progress" { review_snapshot progress-new 4; }
@test "restore reviewed screen: waiting for unseal" { review_snapshot unseal-wait 0; }
@test "restore reviewed screen: still sealed" { review_snapshot unseal-still 4; }
@test "restore reviewed screen: unsealed and checked" { review_snapshot unseal-done 0; }
@test "restore reviewed screen: same host import failure" { review_snapshot failure-same 1; }
@test "restore reviewed screen: new host import failure" { review_snapshot failure-new 1; }
@test "restore reviewed screen: interrupted restore" { review_snapshot interrupted 0; }
@test "restore reviewed screen: readiness timeout" { review_snapshot ready-timeout 1; }
@test "restore reviewed screen: runtime master key mismatch" { review_snapshot runtime-key-mismatch 1; }
@test "restore reviewed screen: restore help sections" { review_snapshot help 0; }
@test "restore reviewed screen: go back with the safety backup" { review_snapshot revert 0; }
@test "restore reviewed screen: unknown migration" { review_snapshot unknown-migration 1; }

# The focused progress snapshots above isolate the orchestration from the stage I/O.
# These two checks also execute every production stage with the existing fake host, so
# a missing progress line cannot be attributed to a replaced stage in that fixture.
full_progress() {
  local flow=$1 total=10 i errors=0
  rs_engine_host || return 1
  if [ "$flow" = new ]; then
    total=8
    rs_new_host
    rm -rf "$ROOT/data/postgres" "$ROOT/data/audit" "$ROOT/tls"
    run bash "$ROOT/custodexa.sh" restore "$RS_E_FILE" --new-host --yes --lang en </dev/null
  else rs_engine_run; fi
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$output"; return 1; }
  for ((i=1; i<=total; i++)); do
    if ! grep -Eq "^\[( OK |WARN)\] +$i/$total  " <<<"$output"; then
      echo "Completed $flow-host restore is missing progress step $i/$total"
      errors=1
    fi
  done
  [ "$errors" = 0 ] || { echo "$output"; return 1; }
  local steps
  steps=$(printf '%s\n' "$output" | sed -nE 's/^\[( OK |WARN)\] +([0-9]+)\/[0-9]+  .*/\2/p')
  [ "$steps" = "$(seq 1 "$total")" ] || { echo "$output"; return 1; }
}
@test "restore progress: complete same host pipeline emits every reviewed step" { full_progress same; }
@test "restore progress: complete new host pipeline emits every reviewed step" { full_progress new; }
