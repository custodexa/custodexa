#!/usr/bin/env bash
# custodexa.sh: install and operate a Custodexa package deployment on a Linux host.
#
#   custodexa.sh <command> [options]        custodexa.sh --help for the full list
#
# The deployment folder is the folder this script belongs to (symlinks are followed), or
# CUSTODEXA_HOME. Every change of state is logged under <deployment folder>/logs/.
# The option variables below are read by the command libraries this file sources.
# shellcheck disable=SC2034
# Tracing would print secrets read from .env; switch it off even under `bash -x`.
set +o xtrace
set -euo pipefail

CX_SELF=$(readlink -f -- "${BASH_SOURCE[0]}")
CX_DIR=${CX_SELF%/*}
# shellcheck source=lib/common.sh
. "$CX_DIR/lib/common.sh"

# Commands the script knows. The ones without lib/cmd_<name>.sh in this build say so and stop.
readonly CX_COMMANDS="install upgrade status backup load"
# Recognize an older tree so every command can refuse it before writing anything.
CX_ROOT_LEGACY_OK=1

CX_COMMAND=""
CX_ARGS=()
CX_YES=0
CX_HELP=0
CX_IMAGES=""
CX_IMAGES_FROM=auto
CX_IMAGES_FROM_GIVEN=0
CX_BACKUP_REF=""
CX_BACKUP_TIME=""
CX_BACKUP_RESTORE=""
CX_LANG_FLAG=""
CX_NO_COLOR=0
CX_SHOW_VERSION=0
CX_USAGE_ERROR=""
CX_FLAGS_TEXT="" # the options as given, for the BEGIN line of the log

cx_parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      --lang | --images | --images-from | --backup-ref | --backup-time | --backup-restore) CX_FLAGS_TEXT+=" $1 ${2:-}" ;;
      -*) CX_FLAGS_TEXT+=" $1" ;;
    esac
    case $1 in
      --yes) CX_YES=1 ;;
      --no-color) CX_NO_COLOR=1 ;;
      -h | --help) CX_HELP=1 ;;
      --version) CX_SHOW_VERSION=1 ;;
      --lang | --images | --images-from | --backup-ref | --backup-time | --backup-restore)
        if [ $# -lt 2 ] || [ -z "$2" ] || [[ $2 == -* ]]; then
          CX_USAGE_ERROR="usage_missing_value $1"
          return 0
        fi
        case $1 in
          --lang) CX_LANG_FLAG=$2 ;;
          --images) CX_IMAGES=$2 ;;
          --images-from) CX_IMAGES_FROM=$2; CX_IMAGES_FROM_GIVEN=1 ;;
          --backup-ref) CX_BACKUP_REF=$2 ;;
          --backup-time) CX_BACKUP_TIME=$2 ;;
          --backup-restore) CX_BACKUP_RESTORE=$2 ;;
        esac
        shift
        ;;
      -*)
        CX_USAGE_ERROR="usage_unknown_option $1"
        return 0
        ;;
      *)
        if [ -z "$CX_COMMAND" ]; then
          CX_COMMAND=$1
        else
          CX_ARGS+=("$1")
        fi
        ;;
    esac
    shift
  done
}

cx_script_version() {
  if [ -f "$CX_DIR/VERSION" ]; then
    tr -d '[:space:]' <"$CX_DIR/VERSION"
  else
    printf 'dev'
  fi
}

cx_legacy_refuse() {
  local line first=1 body=0
  while IFS= read -r line; do
    if [ "$first" = 1 ]; then
      cx_line FAIL "$line" >&2
      first=0
    elif [ -z "$line" ]; then
      printf '\n' >&2
      body=1
    elif [ "$body" = 0 ]; then
      printf '       %s\n' "$line" >&2
    else
      printf '%s\n' "$line" >&2
    fi
  done <<<"$(cx_msg legacy_refused)"
  exit "$CX_EXIT_REFUSED"
}

cx_refuse_legacy_root() {
  if cx_is_legacy_root "$CX_ROOT" && [ ! -f "$CX_ROOT/state.json" ]; then
    cx_legacy_refuse
  fi
  if [ -f "$CX_ROOT/state.json" ]; then
    cx_state_load "$CX_ROOT/state.json"
    [ "$(cx_state_get current.kind)" != legacy-git-clone ] || cx_legacy_refuse
  fi
}

# A legacy checkout keeps this entry point under <root>/scripts/custodexa/ rather than at
# the deployment root. Detect that exact layout before help, menu or a command can exit through
# root resolution with a generic error. An explicit CUSTODEXA_HOME still takes precedence.
cx_refuse_direct_legacy_script() {
  local old_root
  [ -z "${CUSTODEXA_HOME:-}" ] || return 0
  [[ $CX_DIR == */scripts/custodexa ]] || return 0
  old_root=${CX_DIR%/scripts/custodexa}
  if cx_is_legacy_root "$old_root"; then
    CX_ROOT=$old_root
    cx_refuse_legacy_root
  fi
}

cx_main() {
  cx_parse_args "$@"
  cx_load_libs "$CX_DIR"
  cx_refuse_direct_legacy_script
  if [ -n "$CX_USAGE_ERROR" ]; then
    # shellcheck disable=SC2086
    cx_line FAIL "$(cx_msg $CX_USAGE_ERROR)" >&2
    exit "$CX_EXIT_USAGE"
  fi
  if [ "$CX_IMAGES_FROM_GIVEN" = 1 ]; then
    if [[ $CX_IMAGES_FROM != auto && $CX_IMAGES_FROM != source ]]; then
      cx_die "$CX_EXIT_USAGE" usage_images_from_value "$CX_IMAGES_FROM"
    fi
    if [[ $CX_COMMAND != install && $CX_COMMAND != upgrade ]] ||
      { [ "$CX_COMMAND" = upgrade ] && [ "${#CX_ARGS[@]}" -eq 0 ] && [ "$CX_HELP" = 0 ]; }; then
      cx_die "$CX_EXIT_USAGE" usage_images_from_command
    fi
  fi
  if [ "$CX_IMAGES_FROM" = source ] && [ -n "$CX_IMAGES" ]; then
    cx_die "$CX_EXIT_USAGE" usage_images_from_conflict
  fi
  if [ "$CX_SHOW_VERSION" = 1 ]; then
    cx_script_version
    printf '\n'
    exit "$CX_EXIT_OK"
  fi
  if [ "$CX_HELP" = 1 ] || [ -z "$CX_COMMAND" ]; then
    # No command on a terminal (stdin and stdout) of a package deployment: the menu, which never
    # returns. Anywhere else, automation included, the help and exit code 2 as always.
    if [ "$CX_HELP" = 0 ] && [ -t 0 ] && [ -t 1 ]; then
      if CX_ROOT=$(cx_resolve_root "$0" 2>/dev/null) && cx_is_legacy_root "$CX_ROOT" && [ ! -f "$CX_ROOT/state.json" ]; then
        cx_legacy_refuse
      fi
      if [ -n "${CX_ROOT:-}" ] && cx_is_root "$CX_ROOT"; then cx_refuse_legacy_root; fi
      # shellcheck source=lib/menu.sh
      . "$CX_DIR/lib/menu.sh"
      if cx_menu_applies "$0"; then cx_menu; fi
    fi
    cx_help "$CX_COMMAND"
    [ "$CX_HELP" = 1 ] && exit "$CX_EXIT_OK"
    exit "$CX_EXIT_USAGE"
  fi
  case " $CX_COMMANDS " in
    *" $CX_COMMAND "*) ;;
    *)
      cx_line FAIL "$(cx_msg usage_unknown_command "$CX_COMMAND")" >&2
      exit "$CX_EXIT_USAGE"
      ;;
  esac

  cx_check_platform || exit "$CX_EXIT_FAILED"
  CX_ROOT=$(cx_resolve_root "$0") || exit "$CX_EXIT_FAILED"
  if ! cx_check_root_path "$CX_ROOT"; then
    cx_line FAIL "$(cx_msg root_path_chars "$CX_ROOT")" >&2
    exit "$CX_EXIT_FAILED"
  fi
  export CX_ROOT
  cx_refuse_legacy_root

  if [ ! -f "$CX_DIR/lib/cmd_$CX_COMMAND.sh" ]; then
    cx_line FAIL "$(cx_msg command_not_in_build "$CX_COMMAND")" >&2
    exit "$CX_EXIT_USAGE"
  fi
  # shellcheck source=/dev/null
  . "$CX_DIR/lib/cmd_$CX_COMMAND.sh"
  "cmd_$CX_COMMAND" "${CX_ARGS[@]+"${CX_ARGS[@]}"}"
}

# cx_help [command]: the full help, or one command's section (lib/help.sh).
cx_help() { cx_help_print "${1:-}"; }

cx_main "$@"
