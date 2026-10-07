#!/usr/bin/env bats
# Threat (A): a language missing a message, or the help drifting away from what the script does.
# People run this script under pressure and in three languages; a missing key prints an id, an
# option the help does not mention is one nobody finds, and an over-long line wraps unreadably.

load helper

LANGS="zh-TW en ja"

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  printf '1.13.0\n' >"$ROOT/releases/1.13.0/VERSION"
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
}

keys() { grep -oE '^MSG_[a-z0-9_]+=' "$SRC/lang/$1.sh" | sort; }

@test "the three languages define the same message keys, each once" {
  keys en >"$BATS_TEST_TMPDIR/en"
  [ -s "$BATS_TEST_TMPDIR/en" ]
  for l in zh-TW ja; do
    keys "$l" | diff "$BATS_TEST_TMPDIR/en" - || { echo "key set of $l differs from en"; return 1; }
  done
  for l in $LANGS; do
    d=$(keys "$l" | uniq -d)
    [ -z "$d" ] || { echo "$l defines twice: $d"; return 1; }
  done
}

# placeholders <lang>: "<key> <number of %s>" per message.
placeholders() {
  bash -c '. "$1"; for v in $(compgen -v MSG_); do n=${!v//%%/}; n=${n//[^%]/}; printf "%s %s\n" "$v" "${#n}"; done' _ "$SRC/lang/$1.sh" | sort
}

@test "every message takes the same number of arguments in each language" {
  placeholders en >"$BATS_TEST_TMPDIR/en"
  for l in zh-TW ja; do
    placeholders "$l" | diff "$BATS_TEST_TMPDIR/en" - || { echo "argument count differs in $l"; return 1; }
  done
}

@test "no emoji, pictographs or circled numbers anywhere in the script, libraries or messages" {
  run env LC_ALL=C.UTF-8 grep -nP '[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{2460}-\x{24FF}\x{3200}-\x{32FF}\x{FE0F}\x{200D}]' \
    "$SRC/custodexa.sh" "$SRC"/lib/*.sh "$SRC"/lang/*.sh
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
}

@test "every message line fits: 73 columns (80 for help), counting wide characters as two" {
  for l in $LANGS; do
    run env LC_ALL=C.UTF-8 bash -c '
      . "$1"
      for v in $(compgen -v MSG_); do
        max=73; [[ $v == MSG_help_* || $v == MSG_text_* ]] && max=80
        while IFS= read -r line; do
          w=$(printf "%s" "$line" | wc -L)
          [ "$w" -le "$max" ] || echo "$v is $w wide: $line"
        done <<<"${!v}"
      done' _ "$SRC/lang/$l.sh"
    [ -z "$output" ] || { echo "[$l]"; echo "$output"; return 1; }
  done
}

@test "--help matches the reviewed screen text in each language" {
  local errs=0
  for l in $LANGS; do
    run "$ROOT/custodexa.sh" --help --lang "$l"
    [ "$status" -eq 0 ]
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/help.$l.txt" || {
      printf '# SNAPSHOT help.%s.txt %s\n' "$l" "$(printf '%s\n' "$output" | base64 -w0)" >&3
      errs=1
    }
  done
  [ "$errs" = 0 ]
}

@test "the system language picks the help language; unsupported ones fall back to English" {
  # help_in <expected language> <env assignments...> [-- script arguments]
  help_in() {
    local want=$1
    shift
    env "$@" "$ROOT/custodexa.sh" --help 2>/dev/null | diff - "$TESTS_DIR/snapshots/help.$want.txt" \
      || { echo "expected $want for: $*"; return 1; }
  }
  help_in zh-TW LANG=zh_TW.UTF-8
  help_in zh-TW LANG=zh_Hant_TW.UTF-8
  help_in en LANG=zh_CN.UTF-8
  help_in en LANG=zh_HK.UTF-8
  help_in ja LANG=zh_TW.UTF-8 LC_ALL=ja_JP.UTF-8
  help_in zh-TW LANG=ja_JP.UTF-8 LC_MESSAGES=zh_TW.UTF-8
  help_in en LANG=C
  help_in en LANG=POSIX
  env LC_ALL=ja_JP.UTF-8 "$ROOT/custodexa.sh" --help --lang en 2>/dev/null | diff - "$TESTS_DIR/snapshots/help.en.txt"
}

# The options the parser accepts, and the ones the full help lists.
parser_options() { sed -n '/^cx_parse_args()/,/^}/p' "$SRC/custodexa.sh" | grep -oE -- '--[a-z][a-z-]+' | sort -u; }
help_options() { "$ROOT/custodexa.sh" --help --lang en | grep -oE -- '--[a-z][a-z-]+' | sort -u; }

@test "every option the parser accepts is in the help, and every option in the help is accepted" {
  diff <(parser_options) <(help_options)
  for o in $(help_options); do
    run "$ROOT/custodexa.sh" --lang en "$o" x status
    [[ $output != *"Unknown option"* ]] || { echo "help lists $o, the parser refuses it"; return 1; }
  done
}

@test "every command has a help block, and the help names exactly the commands the script knows" {
  known=$(sed -n 's/^readonly CX_COMMANDS="\(.*\)"$/\1/p' "$SRC/custodexa.sh")
  [ -n "$known" ]
  listed=$("$ROOT/custodexa.sh" --help --lang en | sed -n '/^Commands$/,/^$/p' | awk '/^  [a-z]/ {print $1}' | sort -u)
  [ "$(printf '%s\n' $known | sort -u)" = "$listed" ]
  for c in $known; do grep -q "^MSG_help_cmd_$c=" "$SRC/lang/en.sh"; done
}

@test "<command> --help shows that command and only the options it accepts" {
  run "$ROOT/custodexa.sh" status --help --lang en
  [ "$status" -eq 0 ]
  [[ $output == *"  status "* && $output != *"  install "* && $output != *"--yes"* ]]
  [[ $output == *"--lang"* && $output == *"CUSTODEXA_HOME"* ]]
  run "$ROOT/custodexa.sh" upgrade --help --lang en
  [[ $output == *"--backup-ref"* && $output == *"--backup-time"* && $output == *"--backup-restore"* ]]
  [[ $output == *"--images"* && $output != *"--confirm-data-loss"* && $output != *"  rollback "* ]]
  run "$ROOT/custodexa.sh" backup --help --lang en
  [[ $output == *"  backup "* && $output == *"--yes"* && $output != *"--backup-ref"* && $output != *"--images"* ]]
  [[ $output == *"--with-recordings"* && $output == *"--passphrase-file <file>"* && $output == *"To create a passphrase file"* ]]
  run "$ROOT/custodexa.sh" rollback --help --lang en
  [ "$status" -eq 0 ] && [[ $output == *"rollback --resume"* && $output == *"rollback --revert"* ]] || { echo "$output"; return 1; }
  [[ $output == *"--yes"* && $output != *"--images"* && $output != *"--backup-ref"* ]]
  # The backup's options are its own: load, and every other command, does not list them.
  for c in load install upgrade status start stop; do
    run "$ROOT/custodexa.sh" "$c" --help --lang en
    [[ $output != *"--with-recordings"* && $output != *"--passphrase-file"* && $output != *"passphrase file"* ]] || { echo "$c: $output"; return 1; }
  done
  for l in $LANGS; do
    run "$ROOT/custodexa.sh" start --help --lang "$l"
    [ "$status" -eq 0 ] && [[ $output == *"  start "* && $output != *"  stop "* && $output != *"--yes"* && $output != *"--images"* ]] || return 1
    run "$ROOT/custodexa.sh" stop --help --lang "$l"
    [ "$status" -eq 0 ] && [[ $output == *"  stop "* && $output != *"  start "* && $output == *"--yes"* && $output != *"--images"* ]] || return 1
  done
}

@test "marks are the same ASCII in every language; no color without a terminal or with NO_COLOR" {
  for l in $LANGS; do
    out=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; for m in OK WARN FAIL SKIP RUN ASK; do cx_mark $m; done' _ "$SRC")
    [ "$out" = '[ OK ][WARN][FAIL][SKIP][ .. ][ ?? ]' ]
  done
  prog='. "'"$SRC"'/lib/common.sh"; cx_load_libs "'"$SRC"'"; cx_line OK done; cx_cmd "sudo /opt/custodexa/custodexa.sh status"'
  # A terminal: the mark is colored, the command line to copy is not.
  script -qec "bash -c '$prog'" /dev/null >"$BATS_TEST_TMPDIR/tty"
  grep -q $'\033\\[32m\\[ OK \\]\033\\[0m done' "$BATS_TEST_TMPDIR/tty"
  grep 'sudo /opt' "$BATS_TEST_TMPDIR/tty" | tr -d '\r' | grep -qx '    sudo /opt/custodexa/custodexa.sh status'
  NO_COLOR=1 script -qec "bash -c '$prog'" /dev/null >"$BATS_TEST_TMPDIR/nocolor"
  # A bare `! cmd` never fails a bats test (errexit ignores it), so each negation returns 1 itself.
  if grep -q $'\033' "$BATS_TEST_TMPDIR/nocolor"; then echo "color despite NO_COLOR"; return 1; fi
  run bash -c "$prog"
  [[ $output != *$'\033'* ]]
}

@test "a message with several lines keeps its later lines indented under the text" {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en cx_load_libs "$1"; cx_line FAIL "$(cx_msg lock_busy 42)"' _ "$SRC"
  [ "${lines[0]}" = "[FAIL] Another custodexa.sh is running on this deployment (PID 42)." ]
  [ "${lines[1]}" = "       Wait for it to finish." ]
}

# ---- main menu: custodexa.sh without a command, on a terminal ----
# Threat: automation that runs the script without a command starts waiting for a keypress, or a
# menu choice runs a different command than the one it names.

# fake_commands: every cmd_<name> of the deployment only records how it was called; the check the
# menu asks for the version to upgrade to (cx_up_query_core) answers 1.14.0.
fake_commands() {
  local c
  export CX_CALLS=$BATS_TEST_TMPDIR/calls
  : >"$CX_CALLS"
  export CX_QUERIES=$BATS_TEST_TMPDIR/queries
  : >"$CX_QUERIES"
  for c in install status start stop backup load; do
    printf 'cmd_%s() { printf "%%s\\n" "%s $*" >>"$CX_CALLS"; }\n' "$c" "$c" >"$ROOT/releases/1.13.0/lib/cmd_$c.sh"
  done
  for c in start stop; do
    printf 'cmd_%s() { printf "%%s\\n" "%s" >>"$CX_CALLS"; }\n' "$c" "$c" >"$ROOT/releases/1.13.0/lib/cmd_$c.sh"
  done
  printf '%s\n' 'cmd_install() { printf "install --images-from %s\n" "$CX_IMAGES_FROM" >>"$CX_CALLS"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_install.sh"
  printf '%s\n' 'cmd_upgrade() { printf "upgrade %s --images-from %s\n" "$*" "$CX_IMAGES_FROM" >>"$CX_CALLS"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_upgrade.sh"
  printf '%s\n' 'cx_up_query_core() { printf "query\n" >>"$CX_QUERIES"; CX_Q_TARGET=1.14.0; }' >"$ROOT/releases/1.13.0/lib/upgrade_query.sh"
  printf '%s\n' 'cmd_restore() { printf "restore %s same=%s new=%s\n" "$*" "$CX_RS_SAME" "$CX_RS_NEW" >>"$CX_CALLS"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_restore.sh"
}
package_state() { printf '{\n  "format": "2",\n  "current.version": "1.13.2"\n}\n' >"$ROOT/state.json"; }
# menu_run <lang> <typed lines> [folder to start in]: on a terminal (stdin and stdout).
menu_run() {
  run script -qec "cd ${3:-$BATS_TEST_TMPDIR} && bash $ROOT/custodexa.sh --lang $1" /dev/null <<<"$2"
}
# menu_screen: the output as seen, without the echo of the typed input.
menu_screen() {
  printf '%s\n' "$output" | tr -d '\r' | sed -E '/^[0-9]+$/d; s/(：|: )[0-9]+$/\1/' | sed "s#$ROOT#/opt/custodexa#g"
}

# The reviewed screens show a new host whose script is 1.16.2, and an installed 1.16.0 run by its
# own 1.16.0 script; the version the script reports comes from the VERSION file it ships with.
@test "menu: not installed and installed each list their actions, word for word as reviewed" {
  fake_commands
  printf '1.16.2\n' >"$ROOT/releases/1.13.0/VERSION"
  for l in $LANGS; do
    menu_run "$l" 0
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(menu_screen) "$TESTS_DIR/snapshots/menu-none.$l.txt" || { echo "not installed: $l"; return 1; }
  done
  printf '1.16.0\n' >"$ROOT/releases/1.13.0/VERSION"
  printf '{\n  "format": "2",\n  "current.version": "1.16.0"\n}\n' >"$ROOT/state.json"
  for l in $LANGS; do
    menu_run "$l" 0
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(menu_screen) "$TESTS_DIR/snapshots/menu-package.$l.txt" || { echo "installed: $l"; return 1; }
  done
  # Japanese has the same entries (the key set test keeps the texts in step).
  menu_run ja 0
  [ "$status" -eq 0 ] && [[ $output == *"[5] 単一ファイルにバックアップ（他のホストへ移せる。サービスを停止する）"* ]] || { echo "$output"; return 1; }
  [ ! -s "$CX_CALLS" ]
}

@test "menu: only on a terminal (stdin and stdout) of a package deployment; otherwise the help and exit 2 as before" {
  fake_commands
  # No terminal at all (automation): the help, exit 2, nothing run.
  run bash "$ROOT/custodexa.sh" --lang en </dev/null
  [ "$status" -eq 2 ] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/help.en.txt" || return 1
  # stdin a terminal, stdout a file.
  run script -qec "bash $ROOT/custodexa.sh --lang en >$BATS_TEST_TMPDIR/out" /dev/null <<<"0"
  [ "$status" -eq 2 ] || { echo "exit $status"; return 1; }
  diff "$BATS_TEST_TMPDIR/out" "$TESTS_DIR/snapshots/help.en.txt" || return 1
  # stdout a terminal, stdin not.
  run script -qec "bash $ROOT/custodexa.sh --lang en </dev/null" /dev/null
  [ "$status" -eq 2 ] && [[ $output == *"Usage: custodexa.sh <command> [options]"* && $output != *"Choose ["* ]] || { echo "$output"; return 1; }
  # Both a terminal: the menu, not the help.
  menu_run en 0
  [ "$status" -eq 0 ] && [[ $output == *"Choose [0-4]: "* && $output != *"Usage:"* ]] || { echo "$output"; return 1; }
  # A git clone deployment, on a terminal: refuse before displaying the menu.
  local old=$BATS_TEST_TMPDIR/old
  mkdir -p "$old/.git"
  echo 1.12.4 >"$old/VERSION"
  : >"$old/docker-compose.yml"
  export CUSTODEXA_HOME=$old
  menu_run en 0
  [ "$status" -eq 3 ] && [[ $output == *"older git clone deployment"* && $output != *"Choose ["* ]] || { echo "$output"; return 1; }
  [ ! -s "$CX_CALLS" ]
}

@test "menu: each choice runs the command it names, with the answers as its arguments" {
  fake_commands
  package_state
  local dir=$BATS_TEST_TMPDIR/here
  mkdir -p "$dir"
  : >"$dir/custodexa-images-1.13.0-amd64.tar"
  : >"$dir/custodexa-images-1.13.2-amd64.tar"
  : >"$dir/custodexa-1.13.2.tar.gz"
  # status; backup; upgrade to a named version; load the second bundle listed; upgrade to the
  # latest (the query, then the version it names); upgrade from the package listed; load from a
  # typed relative path; a choice not listed; Enter in a question goes back; quit.
  menu_run en $'1\n2\n3\n5\n4\n2\n1.13.2\n2\n7\n2\n4\n1\n1\n4\n3\n1\n\n7\n3\nsub/x.tar\n9\n4\n\n0' "$dir"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff "$CX_CALLS" - <<C || { echo "$output"; return 1; }
status 
start
stop
backup 
upgrade 1.13.2 --images-from source
load $dir/custodexa-images-1.13.2-amd64.tar
upgrade 1.14.0 --images-from auto
upgrade $dir/custodexa-1.13.2.tar.gz --images-from auto
load $dir/sub/x.tar
C
  [[ $output == *"[WARN]"*" No such choice; type one of the numbers in brackets."* ]] || { echo "$output"; return 1; }
  [[ $output == *$'Load an offline image bundle. Bundles in the current directory '"$dir"$':\r\n  [1] custodexa-images-1.13.0-amd64.tar\r\n  [2] custodexa-images-1.13.2-amd64.tar\r\n  [3] Enter another path'* ]] || { echo "$output"; return 1; }
  # Not installed: install; load with nothing in the folder asks for the path; help; quit.
  rm -f "$ROOT/state.json"
  : >"$CX_CALLS"
  menu_run zh-TW $'1\n\n3\n/media/usb/b.tar\n4\n0'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf 'install --images-from auto\nload /media/usb/b.tar\n' | diff "$CX_CALLS" - || return 1
  [[ $output == *"（檔名像 custodexa-images-1.13.0-amd64.tar）。"* && $output == *"用法：custodexa.sh <子命令> [選項]"* ]] || { echo "$output"; return 1; }
}

@test "menu passes --lang to commands and restarted menus only when the user supplied it" {
  package_state
  cat >"$ROOT/releases/1.13.0/lib/cmd_status.sh" <<'STATUS'
cmd_status() {
  printf 'child-lang=%s\n' "$CX_LANG"
  cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
}

STATUS
  run env LANG=zh_TW.UTF-8 script -qec "bash $ROOT/custodexa.sh" /dev/null <<<$'1\n1\n0'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  local clean
  clean=$(printf '%s\n' "$output" | tr -d '\r')
  [ "$(grep -o 'child-lang=zh-TW' <<<"$clean" | wc -l)" -eq 2 ] || { echo "$clean"; return 1; }
  [ "$(grep -c "custodexa.sh status$" <<<"$clean")" -eq 2 ] || { echo "$clean"; return 1; }
  [[ $clean != *"custodexa.sh status --lang"* ]] || { echo "$clean"; return 1; }

  run env LANG=zh_TW.UTF-8 script -qec "bash $ROOT/custodexa.sh --lang ja" /dev/null <<<$'1\n0'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  clean=$(printf '%s\n' "$output" | tr -d '\r')
  [[ $clean == *"child-lang=ja"* && $clean == *"custodexa.sh status --lang ja"* ]] \
    || { echo "$clean"; return 1; }
}

@test "menu latest queries once and image source EOF starts no command" {
  fake_commands
  package_state
  menu_run en $'4\n1\n2\n0'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(wc -l <"$CX_QUERIES")" -eq 1 ]
  grep -qxF 'upgrade 1.14.0 --images-from source' "$CX_CALLS"
  : >"$CX_CALLS"
  run bash -c 'CX_LANG_FLAG=en; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/menu.sh"; CX_ROOT=$2
    cx_menu_pick_images 1.14.0' _ "$SRC" "$ROOT" </dev/null
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ ! -s "$CX_CALLS" ]
}

@test "menu install passes auto, source and Enter defaults" {
  fake_commands
  for answer in 1 2 ''; do
    : >"$CX_CALLS"
    menu_run en $'1\n'"$answer"$'\n0'
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    if [ "$answer" = 2 ]; then
      grep -qxF 'install --images-from source' "$CX_CALLS"
    else
      grep -qxF 'install --images-from auto' "$CX_CALLS"
    fi
  done
}

# Threat: the restore item runs restore on a file other than the one chosen, as a relative path
# that the restore would read from another folder, or with a confirmation of its own in front of
# the restore's.
# backup_file <folder> <name> <bytes>: a backup file of that size (sparse: only its size is read).
backup_file() { mkdir -p "$1" && truncate -s "$3" "$1/$2"; }
# picker_screen: the file picker as seen, from its first line to its question.
picker_screen() {
  menu_screen | sed "s#$BATS_TEST_TMPDIR/root#/root#g" \
    | awk '/^(Restore from a backup file\.|從備份檔還原。|バックアップファイルから復元します。)/ { on = 1 }
      on { print } on && /\[1-[0-9]+\]/ { exit }'
}
# after_picker: the first line with text after the picker'"'"'s question (the menu again, when the
# restore asked nothing itself).
after_picker() {
  menu_screen | awk 'on && NF { print; exit } /\[1-[0-9]+\]/ { on = 1 }'
}

@test "menu: the restore item lists the backup files, word for word as reviewed, and runs restore on the absolute path chosen" {
  fake_commands
  local here=$BATS_TEST_TMPDIR/root bk l
  backup_file "$ROOT/backups" custodexa-backup-1.16.0-20261005-101502.tar 18683107738
  backup_file "$ROOT/backups" custodexa-backup-1.16.0-20261004-221003.tar.enc 18575733555
  # Side files and other names are not offered.
  backup_file "$ROOT/backups" custodexa-backup-1.16.0-20261005-101502.tar.sha256 64
  backup_file "$ROOT/backups" custodexa-images-1.16.0-amd64.tar 10
  mkdir -p "$here"
  bk=$(cd -P "$ROOT/backups" && pwd)
  printf '1.16.0\n' >"$ROOT/releases/1.13.0/VERSION"
  printf '{\n  "format": "2",\n  "current.version": "1.16.0"\n}\n' >"$ROOT/state.json"
  for l in $LANGS; do
    : >"$CX_CALLS"
    menu_run "$l" $'6\n1\n0' "$here"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(picker_screen) "$TESTS_DIR/snapshots/menu-restore-pick.$l.txt" || { echo "picker: $l"; return 1; }
    printf 'restore %s same=1 new=0\n' "$bk/custodexa-backup-1.16.0-20261005-101502.tar" | diff "$CX_CALLS" - || return 1
    # Nothing between the choice and the menu again: the restore's own questions are all there is.
    [[ $(after_picker) == "$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg menu_title 1.16.0 /opt/custodexa' _ "$SRC")" ]] \
      || { echo "after the picker: $(after_picker)"; return 1; }
  done
  # The encrypted one, chosen by its number; Enter at the picker goes back without a restore.
  : >"$CX_CALLS"
  menu_run en $'6\n2\n6\n\n0' "$here"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf 'restore %s same=1 new=0\n' "$bk/custodexa-backup-1.16.0-20261004-221003.tar.enc" | diff "$CX_CALLS" - || return 1
}

# - **WHEN** 維運在尚未安裝的部署根選「從備份檔還原到這台新主機」並選 `backups/` 列出的備份檔
# - **THEN** 選單以該檔的絕對路徑執行 `restore`，問答與確認都由子命令進行，結束後回到主選單
@test "menu: a new host restores a file listed from backups/ or the current folder, or a path typed, as an absolute path" {
  fake_commands
  local here=$BATS_TEST_TMPDIR/root bk
  backup_file "$ROOT/backups" custodexa-backup-1.16.0-20261005-101502.tar 2048
  backup_file "$BATS_TEST_TMPDIR/root" custodexa-backup-1.16.0-20261006-080000.tar.enc 4096
  bk=$(cd -P "$ROOT/backups" && pwd)
  # Newest first, from both folders; [2] is the one in backups/.
  menu_run en $'2\n2\n0' "$here"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf 'restore %s same=0 new=1\n' "$bk/custodexa-backup-1.16.0-20261005-101502.tar" | diff "$CX_CALLS" - || return 1
  [[ $(picker_screen) == *"[1] custodexa-backup-1.16.0-20261006-080000.tar.enc    4.0 KB  2026-10-06 08:00 (encrypted)"* ]] || { picker_screen; return 1; }
  [[ $(after_picker) == "Custodexa management script "* ]] || { after_picker; return 1; }
  # The folder the menu was started in is backups/: each file once.
  : >"$CX_CALLS"
  menu_run en $'2\n0' "$ROOT/backups"
  [ "$(picker_screen | grep -c 'custodexa-backup-')" -eq 1 ] || { picker_screen; return 1; }
  # Nothing found: only "Enter another path"; a relative path is taken from the current folder.
  rm -f "$ROOT/backups/"* "$here/"*
  : >"$CX_CALLS"
  menu_run zh-TW $'2\n1\nsub/b.tar\n0' "$here"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf 'restore %s same=0 new=1\n' "$here/sub/b.tar" | diff "$CX_CALLS" - || return 1
  [[ $(picker_screen) == "從備份檔還原。在 /opt/custodexa/backups/ 與目前目錄 /root 沒有找到備份檔。"$'\n\n'"  [1] 輸入其他路徑"$'\n\n'"請選擇 [1-1]，直接按 Enter 回到主選單："* ]] \
    || { picker_screen; return 1; }
  [[ $output == *"備份檔路徑，直接按 Enter 回到主選單 > "* ]] || { echo "$output"; return 1; }
  # Enter at the path question goes back; nothing is run.
  : >"$CX_CALLS"
  menu_run en $'2\n1\n\n0' "$here"
  [ "$status" -eq 0 ] && [ ! -s "$CX_CALLS" ] || { echo "$output"; return 1; }
}

# Threat: the screens come up in English (sudo often resets the system language) and the reader
# never learns that --lang switches them. Every help, the menu's included, ends with the switch.
@test "every help and the menu's help show how to choose the language, in each language" {
  # has_switch <label>: the output names --lang for each language and the sudo alternative.
  has_switch() {
    [[ $output == *"custodexa.sh --lang zh-TW "*"繁體中文"* && $output == *"custodexa.sh --lang ja "*"日本語"* ]] \
      && [[ $output == *"custodexa.sh --lang en "* && $output == *"sudo env LANG="*"custodexa.sh"* ]] \
      || { echo "no language switch in: $1"; echo "$output"; return 1; }
  }
  for l in $LANGS; do
    run "$ROOT/custodexa.sh" --help --lang "$l"
    has_switch "--help $l"
    for c in install upgrade status start stop backup load; do
      run "$ROOT/custodexa.sh" "$c" --help --lang "$l"
      has_switch "$c --help $l"
    done
  done
  # The English help names the other two languages in their own script too.
  run "$ROOT/custodexa.sh" --help --lang en
  [[ $output == *"Traditional Chinese"* && $output == *"Japanese"* ]] || { echo "$output"; return 1; }
  # The menu's Help: [4] when not installed, [8] when installed.
  fake_commands
  menu_run en $'4\n0'
  has_switch "menu help, not installed"
  package_state
  for l in $LANGS; do
    menu_run "$l" $'8\n0'
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    has_switch "menu help $l"
  done
  [ ! -s "$CX_CALLS" ]
}

# ---- the backup's own options ----
# Threat: an option meant for the backup accepted by another command, which then does something
# without it; or a passphrase file made in a way that leaves the passphrase in the shell history.

@test "flags: --with-recordings and --passphrase-file are usage errors outside backup, nothing done" {
  package_state
  cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before"
  use_fake_docker
  : >"$BATS_TEST_TMPDIR/b.tar"
  # nothing_done <label>: exit 2 with the reason, no docker call, no log, no lock, state.json as it was.
  nothing_done() {
    [ "$status" -eq 2 ] || { echo "$1: exit $status"; echo "$output"; return 1; }
    [[ $output == *"is only for backup"* ]] || { echo "$1: $output"; return 1; }
    [ ! -s "$FAKE_DOCKER_LOG" ] || { echo "$1: docker was called"; cat "$FAKE_DOCKER_LOG"; return 1; }
    [ ! -e "$ROOT/logs" ] && [ ! -e "$ROOT/.custodexa.lock" ] || { echo "$1: something was started"; return 1; }
    cmp -s "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before" || { echo "$1: state.json changed"; return 1; }
  }
  run "$ROOT/custodexa.sh" load "$BATS_TEST_TMPDIR/b.tar" --with-recordings --lang en </dev/null
  nothing_done "load --with-recordings" || return 1
  [[ $output == *'Option --with-recordings is only for backup.'* ]] || { echo "$output"; return 1; }
  run "$ROOT/custodexa.sh" upgrade --passphrase-file x --lang en </dev/null
  nothing_done "upgrade --passphrase-file" || return 1
  [[ $output == *'Option --passphrase-file is only for backup.'* ]] || { echo "$output"; return 1; }
  for c in install status start stop "upgrade 1.13.2"; do
    # shellcheck disable=SC2086 # the command and its argument
    run "$ROOT/custodexa.sh" $c --with-recordings --yes --lang en </dev/null
    nothing_done "$c --with-recordings" || return 1
    # shellcheck disable=SC2086
    run "$ROOT/custodexa.sh" $c --passphrase-file "$BATS_TEST_TMPDIR/pf" --yes --lang en </dev/null
    nothing_done "$c --passphrase-file" || return 1
  done
  # The same in the other languages.
  run "$ROOT/custodexa.sh" load "$BATS_TEST_TMPDIR/b.tar" --with-recordings --lang zh-TW </dev/null
  [ "$status" -eq 2 ] && [[ $output == *"選項 --with-recordings 只適用於 backup。"* ]] || { echo "$output"; return 1; }
  run "$ROOT/custodexa.sh" load "$BATS_TEST_TMPDIR/b.tar" --with-recordings --lang ja </dev/null
  [ "$status" -eq 2 ] && [[ $output == *"オプション --with-recordings は backup 専用です。"* ]] || { echo "$output"; return 1; }
  # --passphrase-file needs its file.
  for tail in "" "--yes"; do
    # shellcheck disable=SC2086
    run "$ROOT/custodexa.sh" backup --lang en --passphrase-file $tail </dev/null
    [ "$status" -eq 2 ] && [[ $output == *"Option --passphrase-file needs a value."* ]] || { echo "[$tail] $output"; return 1; }
  done
  [ ! -s "$FAKE_DOCKER_LOG" ] && [ ! -e "$ROOT/logs" ]
}

@test "help: the two commands for a passphrase file make a 0600 file of root holding exactly the line typed" {
  load pty_host
  local f=$BATS_TEST_TMPDIR/cx-pass p=' test\pass phrase 0003 ' made=$BATS_TEST_TMPDIR/make.sh
  run "$ROOT/custodexa.sh" backup --help --lang en
  [ "$status" -eq 0 ] || return 1
  # The two lines as shown, run as root here (without sudo), into a test path.
  printf '%s\n' "$output" | sed -n '/To create a passphrase file/{n;p;n;p}' | sed 's/^    sudo //' \
    | sed "s#/root/cx-pass#$f#g" >"$made"
  [ "$(wc -l <"$made")" -eq 2 ] && grep -q '^install -m 600 -o root /dev/null ' "$made" || { cat "$made"; return 1; }
  pty_talk "$BATS_TEST_TMPDIR/out" "bash $made" "secret:" "$p" || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
  [ "$PTY_FED" = 1 ] || return 1
  [ "$(stat -c '%a %U' "$f")" = "600 root" ] || { stat -c '%a %U' "$f"; return 1; }
  cmp "$f" <(printf '%s\n' "$p") || { od -c "$f"; return 1; }
  # Typed without echo: the screen does not show it.
  if grep -qF 'pass phrase' "$BATS_TEST_TMPDIR/out"; then cat "$BATS_TEST_TMPDIR/out"; return 1; fi
}

# The keys this release adds or rewrites for the backup. Each renders every argument it is given in
# each language, so a placeholder lost or swapped in one language shows here.
BACKUP_KEYS="usage_backup_only run_backup_unfinished run_backup_unfinished_nodir run_backup_upgrade
  help_cmd_backup help_opt_with_recordings help_opt_passphrase_file help_passphrase_file_make menu_backup
  status_backup_encrypted pb_step_audit pb_step_start pb_step_verify pb_step_pack pb_done pb_sidecar
  pb_summary pb_db_bundled pb_mode_env pb_mode_ui pb_mode_kms pb_mode_hsm pb_kek_in pb_kek_out pb_kek_kms
  pb_warn_kek_fp pb_warn_fps pb_warn_rec pb_warn_plain pb_warn_plain_kek pb_svc_back pb_svc_ui pb_svc_kms
  pb_svc_timeout pb_failed pb_valid pb_after_both pb_after_state pb_after_partial pb_sig_valid pb_sig_both
  pb_sig_partial pb_sig_timeout pb_version_mismatch pb_tool_version pb_kek_material pb_kek_none
  pb_kek_env_empty pb_kek_unknown pb_ts_taken pb_need pb_no_space pb_no_space_hint pb_no_space_ls
  pb_sig_failed pb_sig_again pb_sizes pb_rec_q pb_rec_no pb_rec_yes pb_rec_short pb_rec_keep pb_choose
  pb_enc_q pb_enc_why pb_enc_why_env pb_enc_no pb_enc_yes pb_pass_rules pb_pass_prompt pb_pass_again
  pb_pass_match pb_tries_n pb_tries_1 pb_pass_differ pb_pass_short pb_pass_chars pb_pass_long
  pb_pass_cancel pb_rec_line_no pb_rec_line_yes pb_rec_line_hint pb_enc_line_no pb_enc_line_yes
  pb_enc_line_hint pb_enc_line_file pb_pause pb_warn_seal_ui pb_warn_seal_kms pb_warn_seal_hsm pb_dur_m
  pb_dur_m1 pb_dur_h pb_dur_h1 pb_dur_more_m pb_dur_more_m1 pb_dur_more_h pb_step_pack_enc pb_done_enc
  pb_warn_pass pb_warn_enc_host pb_enc_scheme pb_no_openssl pb_pf_read pb_pf_perm pb_pf_line pb_kek_in_nofp pb_kek_out_nofp
  pb_kek_kms_nofp pb_item_tpl pb_tpl_missing pb_tpl_chars br_opt1_detail_notls br_times_notls"
# The keys of a backup of an external database and of the upgrade's backup file (added or rewritten
# with them).
EXTERNAL_KEYS="up_will_2_ref up_will_2_own pb_summary_ext pb_ext_tool pb_ext_conn pb_ext_mode_system
  pb_ext_verify_none_none pb_ext_verify_none_file pb_ext_verify_ca_system pb_ext_verify_ca_file
  pb_ext_verify_full_system pb_ext_verify_full_file pb_ext_standby pb_pause_ext pb_step_stop_ext
  pb_ext_and pb_ext_no_tool pb_ext_unreachable pb_ext_unreachable_hint pb_ext_no_image
  pb_ext_unsupported pb_ext_dep_ts pb_ext_dep_owner pb_ext_dep_ext pb_ext_dep_ca pb_ext_dep_cert
  pb_ext_dep_keypath pb_ext_dep_key pb_ext_dep_key_rec pb_ext_dep_sysca pb_ext_roles up_bk_db up_bk_files
  up_bk_file up_bk_unrecorded st_gone_unchecked up_no_space_hint up_ext_major_sep up_ext_own_version
  up_ext_own_image up_ext_own_connect up_ext_own_unsupported up_ext_ni_version up_ext_ni_image
  up_ext_ni_connect up_ext_ni_unsupported up_ext_ni_order up_ext_ni_1 up_ext_ni_2 up_ext_ni_3
  up_ext_ni_3_notls up_ext_ni_4 up_ext_ni_flags"

@test "messages: each backup and restore key renders every argument it is given, x1 y2 ..., in each language" {
  local l k n i out want samples=xyzwvuts
  local -a args=()
  for l in $LANGS; do
    for k in $BACKUP_KEYS $EXTERNAL_KEYS $(sed -nE "s/^MSG_((rs_|menu_restore|menu_rs_|menu_ask_restore)[A-Za-z0-9_]*)=.*/\1/p" "$SRC/lang/en.sh"); do
      grep -q "^MSG_$k=" "$SRC/lang/$l.sh" || { echo "$l: no $k"; return 1; }
      # The placeholders: every %s, not counting a literal %%.
      n=$(bash -c '. "$1"; v=MSG_$2; t=${!v//%%/}; t=${t//[^%]/}; printf "%s" "${#t}"' _ "$SRC/lang/$l.sh" "$k")
      args=()
      # A different sample value per argument: x1, y2, z3, w4, ...
      for ((i = 0; i < n; i++)); do args+=("${samples:i:1}$((i + 1))"); done
      out=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; shift; cx_msg "$@"' _ "$SRC" "$k" "${args[@]+"${args[@]}"}")
      [ -n "$out" ] && [ "$out" != "$k" ] || { echo "$l $k: rendered as [$out]"; return 1; }
      for want in "${args[@]+"${args[@]}"}"; do
        [[ $out == *"$want"* ]] || { echo "$l $k: $want missing in: $out"; return 1; }
      done
      # A placeholder the count missed would print as is (a %% in the text prints as % on purpose).
      grep -q '%%' <<<"$(bash -c '. "$1"; v=MSG_$2; printf "%s" "${!v}"' _ "$SRC/lang/$l.sh" "$k")" \
        || [[ $out != *"%s"* ]] || { echo "$l $k: a placeholder left: $out"; return 1; }
    done
  done
}
