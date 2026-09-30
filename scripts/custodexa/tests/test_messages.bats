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
  bash -c '. "$1"; for v in $(compgen -v MSG_); do n=${!v//[^%]/}; printf "%s %s\n" "$v" "${#n}"; done' _ "$SRC/lang/$1.sh" | sort
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
  for l in $LANGS; do
    run "$ROOT/custodexa.sh" --help --lang "$l"
    [ "$status" -eq 0 ]
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/help.$l.txt" || { echo "help differs: $l"; return 1; }
  done
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
  for c in install status backup load; do
    printf 'cmd_%s() { printf "%%s\\n" "%s $*" >>"$CX_CALLS"; }\n' "$c" "$c" >"$ROOT/releases/1.13.0/lib/cmd_$c.sh"
  done
  printf '%s\n' 'cmd_install() { printf "install --images-from %s\n" "$CX_IMAGES_FROM" >>"$CX_CALLS"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_install.sh"
  printf '%s\n' 'cmd_upgrade() { printf "upgrade %s --images-from %s\n" "$*" "$CX_IMAGES_FROM" >>"$CX_CALLS"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_upgrade.sh"
  printf '%s\n' 'cx_up_query_core() { printf "query\n" >>"$CX_QUERIES"; CX_Q_TARGET=1.14.0; }' >"$ROOT/releases/1.13.0/lib/upgrade_query.sh"
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

@test "menu: not installed and installed each list their actions, word for word as reviewed (zh-TW, en)" {
  fake_commands
  for l in zh-TW en; do
    menu_run "$l" 0
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(menu_screen) "$TESTS_DIR/snapshots/menu-none.$l.txt" || { echo "not installed: $l"; return 1; }
  done
  package_state
  for l in zh-TW en; do
    menu_run "$l" 0
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(menu_screen) "$TESTS_DIR/snapshots/menu-package.$l.txt" || { echo "installed: $l"; return 1; }
  done
  # Japanese has the same entries (the key set test keeps the texts in step).
  menu_run ja 0
  [ "$status" -eq 0 ] && [[ $output == *"[3] バックアップ（サービスを十数分停止する）"* ]] || { echo "$output"; return 1; }
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
  [ "$status" -eq 0 ] && [[ $output == *"Choose [0-3]: "* && $output != *"Usage:"* ]] || { echo "$output"; return 1; }
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
  menu_run en $'1\n3\n2\n2\n1.13.2\n2\n4\n2\n2\n1\n1\n2\n3\n1\n\n4\n3\nsub/x.tar\n9\n2\n\n0' "$dir"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff "$CX_CALLS" - <<C || { echo "$output"; return 1; }
status 
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
  menu_run zh-TW $'1\n\n2\n/media/usb/b.tar\n3\n0'
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
  menu_run en $'2\n1\n2\n0'
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
    for c in install upgrade status backup load; do
      run "$ROOT/custodexa.sh" "$c" --help --lang "$l"
      has_switch "$c --help $l"
    done
  done
  # The English help names the other two languages in their own script too.
  run "$ROOT/custodexa.sh" --help --lang en
  [[ $output == *"Traditional Chinese"* && $output == *"Japanese"* ]] || { echo "$output"; return 1; }
  # The menu's Help: [3] when not installed, [5] when installed.
  fake_commands
  menu_run en $'3\n0'
  has_switch "menu help, not installed"
  package_state
  for l in $LANGS; do
    menu_run "$l" $'5\n0'
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    has_switch "menu help $l"
  done
  [ ! -s "$CX_CALLS" ]
}
