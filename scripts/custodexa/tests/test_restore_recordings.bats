#!/usr/bin/env bats
# Threat: a restore onto a new host from a backup without the recordings says nothing, or names the
# wrong recordings, so the ones an auditor asks for are never copied over from the source host; or
# a path in the database leads the list to a file outside the recordings folder.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

REC=/var/lib/custodexa/recordings
LANGS="zh-TW en ja"

setup() {
  rs_host ui
  rs_new_host
  LIST_DIR=$ROOT/restore/20261012-093015
  # rec <lang> <action> [arguments]: the recordings functions on this host, as the finished
  # restore runs them. missing: the list and its counts, then the new-host part of the screen;
  # section <flow> <with> [files]: that part of the screen alone.
  HARNESS=$BATS_TEST_TMPDIR/rec.sh
  cat >"$HARNESS" <<'SH'
. "$1/lib/common.sh"
CX_LANG_FLAG=$3
cx_load_libs "$1"
CX_ROOT=$2 CX_DIR=$2/current
. "$1/lib/backup.sh"
. "$1/lib/restore_recordings.sh"
case $4 in
  missing)
    mkdir -p "$5"
    cx_rs_recordings_missing "$5" || { echo "cannot read"; exit 1; }
    printf 'total=%s missing=%s offsite=%s file=%s\n' "$CX_RS_REC_TOTAL" "$CX_RS_REC_MISSING" \
      "$CX_RS_REC_OFFSITE" "$CX_RS_REC_FILE"
    cx_rs_rec_section new false /data/custodexa ;;
  section) cx_rs_rec_section "$5" "$6" /data/custodexa "${7:-0}" ;;
esac
SH
}
rec() { run bash "$HARNESS" "$SRC" "$ROOT" "$@"; }
# screen: the output after the counts line, with the deployment root as on the reviewed screens.
screen() { printf '%s\n' "$output" | sed 1d | sed "s#$ROOT#/opt/custodexa#g"; }
# matches <name> <lang> <text>: the text equals snapshots/restore-recordings-<name>.<lang>.txt.
matches() {
  local expected=$TESTS_DIR/snapshots/restore-recordings-$1.$2.txt
  if [ ! -f "$expected" ]; then
    printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$3" | base64 -w0)" >&3
    return 1
  fi
  diff <(printf '%s\n' "$3") "$expected"
}

@test "recordings: three recorded, one on this host: the list holds exactly the other two, as paths inside the folder" {
  printf '%s\n' "$REC/2026-10-01/session-1.cast" "$REC/session-2.guac" "$REC/2026-10-02/session-3.cast" >"$DB/recordings"
  printf 'guac\n' >"$ROOT/data/recordings/session-2.guac"
  rec en missing "$LIST_DIR"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "${lines[0]}" = "total=3 missing=2 offsite=0 file=$LIST_DIR/missing-recordings.txt" ] || { echo "$output"; return 1; }
  printf '%s\n' 2026-10-01/session-1.cast 2026-10-02/session-3.cast | diff "$LIST_DIR/missing-recordings.txt" - || return 1
  [[ $output == *"[WARN] The recordings were not restored from the backup: 2 of the"* ]] || { echo "$output"; return 1; }
  grep -qx 'psql recordings' "$DB/events"
  for l in zh-TW ja; do
    rec "$l" missing "$LIST_DIR"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    case $l in
      zh-TW) [[ $output == *"系統記錄的錄影中有 2 段的檔案不在這台"* ]] ;;
      ja) [[ $output == *"うち 2 件のファイルがこのホストにありません"* ]] ;;
    esac || { echo "$output"; return 1; }
  done
}

@test "recordings: all on this host: the screen says so and the list is empty" {
  printf '%s\n' "$REC/2026-10-01/session-1.cast" "$REC/session-2.guac" >"$DB/recordings"
  mkdir -p "$ROOT/data/recordings/2026-10-01"
  : >"$ROOT/data/recordings/2026-10-01/session-1.cast"
  : >"$ROOT/data/recordings/session-2.guac"
  local l want
  for l in $LANGS; do
    rec "$l" missing "$LIST_DIR"
    [ "$status" -eq 0 ] && [ "${lines[0]}" = "total=2 missing=0 offsite=0 file=$LIST_DIR/missing-recordings.txt" ] || { echo "$output"; return 1; }
    [ -f "$LIST_DIR/missing-recordings.txt" ] && [ ! -s "$LIST_DIR/missing-recordings.txt" ]
    case $l in
      en) want='  [ OK ] Recordings: every recording the system knows about has its file
         on this host' ;;
      zh-TW) want='  [ OK ] 錄影：系統記錄的錄影檔都在這台' ;;
      ja) want='  [ OK ] 録画：システムに記録された録画のファイルはすべてこのホストにあります' ;;
    esac
    [ "$(screen)" = "$want" ] || { echo "$output"; return 1; }
  done
  # A recording whose file is gone counts once it is gone.
  rm "$ROOT/data/recordings/session-2.guac"
  rec en missing "$LIST_DIR"
  [ "${lines[0]}" = "total=2 missing=1 offsite=0 file=$LIST_DIR/missing-recordings.txt" ] || { echo "$output"; return 1; }
  printf 'session-2.guac\n' | diff "$LIST_DIR/missing-recordings.txt" -
}

@test "recordings: the missing ones, word for word as reviewed, and the offsite sentence when offsite storage is in use" {
  local i l
  for ((i = 1; i <= 1204; i++)); do printf '%s/2026-10-01/session-%s.cast\n' "$REC" "$i"; done >"$DB/recordings"
  for l in $LANGS; do
    rec "$l" missing "$LIST_DIR"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    matches missing "$l" "$(screen)" || return 1
  done
  [ "$(wc -l <"$LIST_DIR/missing-recordings.txt")" -eq 1204 ]
  printf '2\n' >"$DB/offsite"
  for l in $LANGS; do
    rec "$l" missing "$LIST_DIR"
    [ "$status" -eq 0 ] && [[ ${lines[0]} == *" offsite=1 "* ]] || { echo "$output"; return 1; }
    want=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg rs_rec_offsite' _ "$SRC")
    # The sentence is the last line of the warning, under its text.
    [ "$(screen)" = "$(cat "$TESTS_DIR/snapshots/restore-recordings-missing.$l.txt")"$'\n'"         ${want//$'\n'/$'\n'         }" ] \
      || { echo "$output"; return 1; }
  done
}

@test "recordings: the same host and a backup with recordings, word for word as reviewed" {
  local l
  for l in $LANGS; do
    rec "$l" section same false
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    matches same "$l" "$output" || return 1
    rec "$l" section new true 8412
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    matches put-back "$l" "$output" || return 1
    rec "$l" section same true 8412
    matches put-back "$l" "$output" || return 1
  done
  # No database read for either.
  if grep -q 'psql recordings' "$DB/events" 2>/dev/null; then cat "$DB/events"; return 1; fi
}

@test "recordings: a path outside the recordings folder is listed as the database has it and never looked up here" {
  mkdir -p "$ROOT/etc"
  printf 'x\n' >"$ROOT/etc/passwd"
  : >"$ROOT/data/recordings/ok.cast"
  # ../../etc/passwd from the recordings folder (DATA_PATH/recordings) is $ROOT/etc/passwd, which
  # exists: looking it up would count it as present.
  printf '%s\n' "$REC/ok.cast" "$REC/../../etc/passwd" "/srv/old/session-9.cast" "$REC/" >"$DB/recordings"
  [ -f "$ROOT/data/recordings/../../etc/passwd" ]
  rec en missing "$LIST_DIR"
  [ "$status" -eq 0 ] && [ "${lines[0]}" = "total=4 missing=3 offsite=0 file=$LIST_DIR/missing-recordings.txt" ] || { echo "$output"; return 1; }
  printf '%s\n' "$REC/../../etc/passwd" /srv/old/session-9.cast "$REC/" | diff "$LIST_DIR/missing-recordings.txt" -
}

@test "recordings: the database cannot be read: no list, and the caller is told" {
  printf '%s\n' "$REC/a.cast" >"$DB/recordings"
  printf '1\n' >"$DB/recordings.rc"
  rec en missing "$LIST_DIR"
  [ "$status" -eq 1 ] && [ "$output" = "cannot read" ] || { echo "$output"; return 1; }
  [ ! -e "$LIST_DIR/missing-recordings.txt" ] && [ ! -e "$LIST_DIR/missing-recordings.txt.tmp" ]
}
