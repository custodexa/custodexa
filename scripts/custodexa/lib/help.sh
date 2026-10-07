# shellcheck shell=bash
# --help. The full help lists every command and option; `<command> --help` prints the same
# blocks limited to that command and the options it accepts. Every help ends with how to choose
# the language. The blocks live in lang/<lang>.sh.

# Options each command accepts, in the order of the full help. Kept next to the parser's list
# so the test suite can check both against each other.
readonly CX_HELP_OPTIONS="yes resume revert with_recordings passphrase_file backup_ref backup_time backup_restore images images_from lang no_color version help"
cx_help_options_for() {
  case $1 in
    install) printf '%s' "yes images images_from lang no_color version help" ;;
    upgrade) printf '%s' "yes backup_ref backup_time backup_restore images images_from lang no_color version help" ;;
    rollback) printf '%s' "yes resume revert lang no_color help" ;;
    status) printf '%s' "lang no_color version help" ;;
    start) printf '%s' "lang no_color help" ;;
    stop) printf '%s' "yes lang no_color help" ;;
    backup) printf '%s' "yes with_recordings passphrase_file lang no_color version help" ;;
    load) printf '%s' "yes lang no_color version help" ;;
    # The rest of what restore takes is in its own block (help_restore_options).
    restore) printf '%s' "yes lang no_color version help" ;;
    *) printf '%s' "$CX_HELP_OPTIONS" ;;
  esac
}

# cx_help_print [command]: an unknown or empty command prints the full help.
cx_help_print() {
  local cmd=${1:-} c o cmds opts
  case " $CX_COMMANDS " in
    *" $cmd "*) cmds=$cmd ;;
    *) cmd="" cmds=$CX_COMMANDS ;;
  esac
  opts=$(cx_help_options_for "$cmd")
  printf '%s\n\n%s\n\n%s\n' "$(cx_msg help_title "$(cx_script_version)")" \
    "$(cx_msg help_usage)" "$(cx_msg help_commands)"
  for c in $cmds; do
    printf '%s\n' "$(cx_msg "help_cmd_$c")"
  done
  printf '\n%s\n' "$(cx_msg help_options)"
  for o in $opts; do
    printf '%s\n' "$(cx_msg "help_opt_$o")"
  done
  [[ " $cmds " != *" restore "* ]] || printf '\n%s\n' "$(cx_msg help_restore_options)"
  # How to make a passphrase file without the passphrase reaching the shell history.
  [[ " $opts " != *" passphrase_file "* && " $cmds " != *" restore "* ]] ||
    printf '\n%s\n' "$(cx_msg help_passphrase_file_make)"
  printf '\n%s\n' "$(cx_msg help_footer)"
  # Last, so it stays on screen: under sudo the system language is often reset to English.
  printf '\n%s\n' "$(cx_msg help_language)"
}
