# shellcheck shell=bash
# Constants here are read by the other libraries once sourced.
# shellcheck disable=SC2034
# Common pieces of custodexa.sh: exit codes, output marks, deployment root, platform checks.
# Sourced by custodexa.sh and by the tests; defines functions only.

# Exit codes. 4 and 5 are reserved for status warnings and a damaged state file.
readonly CX_EXIT_OK=0 CX_EXIT_FAILED=1 CX_EXIT_USAGE=2 CX_EXIT_REFUSED=3 CX_EXIT_WARN=4 CX_EXIT_STATE=5

readonly CX_PROJECT=custodexa
# The recordings folder: guacd writes as uid 1000, the backend reads as group 0 (install sets it,
# status checks it).
readonly CX_RECORDINGS_MODE="1000:0 2770"
readonly CX_OVERLAY_NAMES="external-ingress external-database"

# cx_load_libs <script dir>: source the other libraries next to this one.
cx_load_libs() {
  local dir=$1 f
  for f in i18n compose state run log help manifest env preflight verify images trust; do
    # shellcheck source=/dev/null
    . "$dir/lib/$f.sh"
  done
  cx_i18n_init "$dir"
  cx_color_init
}

# ---------- output ----------
# Marks are ASCII and identical in every language; color is only ever put on the mark.
# Decided once, when the libraries load: inside $(...) stdout is a pipe, so asking there is too late.
CX_COLOR=0
cx_color_init() {
  CX_COLOR=0
  if [ -z "${NO_COLOR:-}" ] && [ "${CX_NO_COLOR:-0}" != 1 ] && [ -t 1 ]; then
    CX_COLOR=1
  fi
}
cx_color_on() { [ "$CX_COLOR" = 1 ]; }

cx_mark() { # <OK|WARN|FAIL|SKIP|RUN|ASK>
  local tag color
  case $1 in
    OK) tag='[ OK ]' color='32' ;;
    WARN) tag='[WARN]' color='33' ;;
    FAIL) tag='[FAIL]' color='31' ;;
    SKIP) tag='[SKIP]' color='90' ;;
    RUN) tag='[ .. ]' color='36' ;;
    ASK) tag='[ ?? ]' color='1' ;;
    *) tag="[$1]" color='' ;;
  esac
  if [ -n "$color" ] && cx_color_on; then
    printf '\033[%sm%s\033[0m' "$color" "$tag"
  else
    printf '%s' "$tag"
  fi
}

# cx_line <mark> <text...>: one status line, "[ OK ] text".
# A message with several lines keeps its later lines under the text, 7 columns in.
cx_line() {
  local m=$1 text
  shift
  text=$*
  printf '%s %s\n' "$(cx_mark "$m")" "${text//$'\n'/$'\n'       }"
}

# Suffix for a printed status command: preserve --lang only when the caller supplied it.
cx_status_lang_arg() {
  if [ -n "${CX_LANG_FLAG:-}" ]; then
    printf ' --lang %q' "$CX_LANG_FLAG"
  fi
  return 0
}

# cx_width <text>: display columns of one line. Characters outside ASCII in the messages are CJK
# (two columns, three bytes in UTF-8); counted from the bytes, so the host locale does not matter.
cx_width() {
  local LC_ALL=C s=$1 lead
  lead=${s//[$'\x80'-$'\xbf']/}
  printf '%s' $((${#lead} + (${#s} - ${#lead}) / 2))
}

# cx_with_duration <text> <columns before its first line> <duration>: the text with the duration
# starting at column 61 of its last line, or two spaces after a longer line. Later lines of the
# text already carry their indent.
readonly CX_DURATION_COLUMN=61
cx_with_duration() {
  local text=$1 off=$2 dur=$3 w pad
  if [[ $text == *$'\n'* ]]; then
    w=$(cx_width "${text##*$'\n'}")
  else
    w=$((off + $(cx_width "$text")))
  fi
  pad=$((CX_DURATION_COLUMN - 1 - w))
  [ "$pad" -ge 2 ] || pad=2
  printf '%s%*s%s' "$text" "$pad" '' "$dur"
}

# cx_step_line <mark> <n>/<total> <text> [duration]: "[ OK ] 3/7  text ... 48s". Later lines of the
# text sit under the text (12 columns).
cx_step_line() {
  local mark=$1 pos=$2 text=${3//$'\n'/$'\n'            }
  [ -z "${4:-}" ] || text=$(cx_with_duration "$text" 12 "$4")
  printf '%s %s  %s\n' "$(cx_mark "$mark")" "$pos" "$text"
}

# cx_line_timed <mark> <text> <duration>: a status line without a step number, with its duration.
cx_line_timed() {
  local text=${2//$'\n'/$'\n'       }
  printf '%s %s\n' "$(cx_mark "$1")" "$(cx_with_duration "$text" 7 "$3")"
}

# cx_now: seconds since the epoch, for the durations shown on steps.
cx_now() { date +%s; }

# cx_seal_state <body of /api/v1/seal/status>: print the seal state, the top-level "state". The body
# also holds objects with a "state" of their own (instance_guard, which sorts first), so objects
# nested inside it are dropped before the key is read. Fails when there is none.
cx_seal_state() {
  local top=$1
  while [[ $top =~ ^(.*)\"[A-Za-z0-9_]+\":\ ?\{[^{}]*\}(.*)$ ]]; do
    top=${BASH_REMATCH[1]}${BASH_REMATCH[2]}
  done
  [[ $top =~ \"state\":\ ?\"([^\"]*)\" ]] || return 1
  printf '%s' "${BASH_REMATCH[1]}"
}

# Width of a sentence put together at run time, so it lines up with the reviewed screens.
readonly CX_WRAP=60
# cx_wrap <width> <text>: break a sentence put together at run time (a list of items, a reason
# filled in) between words so no line is wider than width. Text without spaces stays one line.
cx_wrap() {
  local width=$1 word line="" out="" sep=""
  local -a words=()
  read -ra words <<<"${2//$'\n'/ }"
  for word in "${words[@]}"; do
    if [ -n "$line" ] && [ $(($(cx_width "$line") + 1 + $(cx_width "$word"))) -gt "$width" ]; then
      out+=$sep$line
      sep=$'\n'
      line=$word
    else
      line+=${line:+ }$word
    fi
  done
  printf '%s' "$out$sep$line"
}

# cx_duration <seconds>: "48s", "1m 05s" in the user's language.
cx_duration() {
  local s=$1
  if [ "$s" -lt 60 ]; then
    cx_msg dur_s "$s"
  else
    cx_msg dur_ms $((s / 60)) $((s % 60))
  fi
}

# cx_sub <mark> <text>: a check under a step, 7 columns in: "       [ OK ] text".
cx_sub() {
  local m=$1 text=$2
  printf '       %s %s\n' "$(cx_mark "$m")" "${text//$'\n'/$'\n'              }"
}

# cx_cmd <command>: a command for people to copy: own line, 4-space indent, never colored.
cx_cmd() { printf '    %s\n' "$*"; }

# cx_die <exit code> <message key> [args...]: print a FAIL line and leave.
cx_die() {
  local code=$1
  shift
  cx_line FAIL "$(cx_msg "$@")" >&2
  exit "$code"
}

# ---------- platform and paths ----------
cx_check_platform() {
  local os
  os=$(uname -s 2>/dev/null)
  [ "$os" = Linux ] && return 0
  cx_line FAIL "$(cx_msg platform_not_linux "${os:-unknown}")" >&2
  return 1
}

# The deployment root is written into .env, state.json and recovery records without escaping,
# so only a small character set is allowed.
cx_check_root_path() {
  local p=$1
  local LC_ALL=C
  [[ $p =~ ^/[A-Za-z0-9._/-]*$ ]]
}

cx_is_root() {
  [ -f "$1/state.json" ] || [ -d "$1/releases" ] || { [ "${CX_ROOT_LEGACY_OK:-0}" = 1 ] && cx_is_legacy_root "$1"; }
}

# cx_is_legacy_root <dir>: a deployment from a git clone of the source, from before the package
# layout (the first upgrade converts it). Only the commands in CX_LEGACY_ROOT_COMMANDS accept it as
# the root (CX_ROOT_LEGACY_OK, set by custodexa.sh): the ones that change nothing, and upgrade, which
# writes nothing there before its conversion preview is answered (a file written there would change
# how it is detected).
cx_is_legacy_root() {
  [ -e "$1/.git" ] && [ -f "$1/VERSION" ] && [ -f "$1/docker-compose.yml" ]
}

# cx_resolve_root <path the script was started as>: print the deployment root.
# CUSTODEXA_HOME wins. Otherwise follow symlinks to the real script; its folder is the root when
# it holds state.json or releases/, or the script sits in <root>/releases/<version>/ (the layout of
# the package, and where an upgrade hands over to the new version's script). No other parent is
# searched: guessing a folder further up is how a script ends up acting on the wrong tree.
cx_resolve_root() {
  local real dir up
  if [ -n "${CUSTODEXA_HOME:-}" ]; then
    dir=$(readlink -f -- "$CUSTODEXA_HOME" 2>/dev/null) || dir=""
    if [ -n "$dir" ] && cx_is_root "$dir"; then
      printf '%s\n' "$dir"
      return 0
    fi
    cx_msg root_home_invalid "$CUSTODEXA_HOME" >&2
    printf '\n' >&2
    return 1
  fi
  real=$(readlink -f -- "$1" 2>/dev/null) || real=""
  dir=${real%/*}
  if [ -n "$real" ] && cx_is_root "$dir"; then
    printf '%s\n' "$dir"
    return 0
  fi
  up=${dir%/*}
  if [ -n "$real" ] && [ "${up##*/}" = releases ] && cx_is_root "${up%/*}"; then
    printf '%s\n' "${up%/*}"
    return 0
  fi
  cx_msg root_not_found "${real:-$1}" >&2
  printf '\n' >&2
  return 1
}
