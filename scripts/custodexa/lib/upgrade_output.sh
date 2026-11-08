# shellcheck shell=bash
# Output pieces of upgrade: the 13 numbered steps and numbers with thousands separators.
#   "[ OK ]  4/13  text                                         9s"
# The step number is right-aligned to "13/13", so every text starts at column 15 and later lines
# of a text sit under it (14 columns in). A duration starts at column 61 (lib/common.sh).

# Sourced by more than one command library: a second load must not touch the readonly settings.
[ -z "${CX_LIB_LOADED_upgrade_output:-}" ] || return 0
CX_LIB_LOADED_upgrade_output=1
readonly CX_UP_STEPS=13

# cx_up_step_line <mark> <n> <text> [duration]
cx_up_step_line() {
  local text=${3//$'\n'/$'\n'              }
  [ -z "${4:-}" ] || text=$(cx_with_duration "$text" 14 "$4")
  printf '%s %5s  %s\n' "$(cx_mark "$1")" "$2/$CX_UP_STEPS" "$text"
}

# cx_up_num <integer>: 1204551 -> 1,204,551.
cx_up_num() {
  local n=$1 out=""
  while [ "${#n}" -gt 3 ]; do
    out=",${n: -3}$out"
    n=${n:0:${#n}-3}
  done
  printf '%s%s' "$n" "$out"
}

# cx_up_par <text>: a paragraph 2 columns in.
cx_up_par() { printf '%s\n' "$1" | sed 's/^/  /'; }

# cx_up_preview_head: the top of the preview.
cx_up_preview_head() {
  printf '%s\n\n' "$(cx_msg up_title)"
  printf '%s\n' "$(cx_msg up_row_installed "$CX_UP_CURRENT")" "$(cx_msg up_row_target "$CX_UP_TARGET")" \
    "$(cx_msg up_row_root "$CX_ROOT")"
}
