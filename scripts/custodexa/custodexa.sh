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
readonly CX_READ_ONLY_COMMANDS="status"
# upgrade also takes a git clone deployment as the root: it converts it, after its own preview.
readonly CX_LEGACY_ROOT_COMMANDS="$CX_READ_ONLY_COMMANDS upgrade"
CX_ROOT_LEGACY_OK=0

CX_COMMAND=""
CX_ARGS=()
CX_YES=0
CX_HELP=0
CX_IMAGES=""
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
      --lang | --images | --backup-ref | --backup-time | --backup-restore) CX_FLAGS_TEXT+=" $1 ${2:-}" ;;
      -*) CX_FLAGS_TEXT+=" $1" ;;
    esac
    case $1 in
      --yes) CX_YES=1 ;;
      --no-color) CX_NO_COLOR=1 ;;
      -h | --help) CX_HELP=1 ;;
      --version) CX_SHOW_VERSION=1 ;;
      --lang | --images | --backup-ref | --backup-time | --backup-restore)
        if [ $# -lt 2 ] || [ -z "$2" ]; then
          CX_USAGE_ERROR="usage_missing_value $1"
          return 0
        fi
        case $1 in
          --lang) CX_LANG_FLAG=$2 ;;
          --images) CX_IMAGES=$2 ;;
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

cx_main() {
  cx_parse_args "$@"
  cx_load_libs "$CX_DIR"
  if [ -n "$CX_USAGE_ERROR" ]; then
    # shellcheck disable=SC2086
    cx_line FAIL "$(cx_msg $CX_USAGE_ERROR)" >&2
    exit "$CX_EXIT_USAGE"
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
  # A git clone deployment is a root only for the commands that read and change nothing, and for
  # upgrade, which converts it (nothing is written before the conversion preview is answered).
  case " $CX_LEGACY_ROOT_COMMANDS " in *" $CX_COMMAND "*) CX_ROOT_LEGACY_OK=1 ;; esac
  CX_ROOT=$(cx_resolve_root "$0") || exit "$CX_EXIT_FAILED"
  if ! cx_check_root_path "$CX_ROOT"; then
    cx_line FAIL "$(cx_msg root_path_chars "$CX_ROOT")" >&2
    exit "$CX_EXIT_FAILED"
  fi
  export CX_ROOT

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
