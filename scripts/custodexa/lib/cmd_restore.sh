# shellcheck shell=bash
# CX_RS_FLOW is read by the steps that follow the entry.
# shellcheck disable=SC2034,SC2030,SC2031 # recovery isolates the safety input in a subshell
# restore: put a portable backup file back on this host. The kind of restore follows from this
# host, never from the file: an installed host (state.json has current.version) has its data
# replaced (same host); a host not installed yet gets the backup's version installed first (new
# host). Without a terminal the kind must be named (--same-host or --new-host) and agree with the
# host. Everything up to the first change to the deployment is checked before any service stops.

# cx_rs_installed: this host has an installed deployment.
cx_rs_installed() { [ -n "$(cx_state_get current.version)" ]; }

# cx_rs_options <file>: the options agree with the action (a file, --resume, --revert or
# --abandon). A misuse ends the run as a usage error before anything is read.
cx_rs_options() {
  local file=$1 o allowed
  case $CX_RS_ACTION in
    "") [ -n "$file" ] || cx_die "$CX_EXIT_USAGE" rs_no_file
        return 0 ;;
    resume) allowed=" --resume " ;;
    *) allowed=" --$CX_RS_ACTION " ;;
  esac
  [ -z "$file" ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$file"
  for o in $CX_RS_GIVEN; do
    [[ $allowed == *" $o "* ]] || cx_die "$CX_EXIT_USAGE" rs_option_with "$o" "--$CX_RS_ACTION"
  done
  # Only a run carried on may be given a passphrase file or your own backup instead of the safety
  # backup; going back or giving up takes neither.
  if [ "$CX_RS_ACTION" != resume ]; then
    [ -z "$CX_PASSPHRASE_FILE" ] || cx_die "$CX_EXIT_USAGE" rs_option_with --passphrase-file "--$CX_RS_ACTION"
    [ -z "$CX_BACKUP_REF$CX_BACKUP_TIME$CX_BACKUP_RESTORE" ] || cx_die "$CX_EXIT_USAGE" rs_option_with --backup-ref "--$CX_RS_ACTION"
  fi
  if [ -n "$CX_IMAGES" ] || [ "$CX_IMAGES_FROM_GIVEN" = 1 ]; then
    cx_die "$CX_EXIT_USAGE" rs_option_with --images "--$CX_RS_ACTION"
  fi
}

# cx_rs_flow: CX_RS_FLOW, same or new, from this host; the flag given has to agree, and without
# a terminal one has to be given. A mismatch or a missing flag is a usage error (exit 2).
CX_RS_FLOW=""
cx_rs_flow() {
  local installed=0
  ! cx_rs_installed || installed=1
  [ "$CX_RS_SAME$CX_RS_NEW" != 11 ] || cx_die "$CX_EXIT_USAGE" rs_flow_both
  if [ "$installed" = 1 ]; then
    CX_RS_FLOW=same
    [ "$CX_RS_NEW" = 0 ] || cx_die "$CX_EXIT_USAGE" rs_flow_wrong_new
    [ "$CX_RS_SAME" = 1 ] || [ -t 0 ] || cx_die "$CX_EXIT_USAGE" rs_flow_needed_same
  else
    CX_RS_FLOW=new
    [ "$CX_RS_SAME" = 0 ] || cx_die "$CX_EXIT_USAGE" rs_flow_wrong_same
    [ "$CX_RS_NEW" = 1 ] || [ -t 0 ] || cx_die "$CX_EXIT_USAGE" rs_flow_needed_new
  fi
}

# shellcheck source=lib/restore_read.sh
. "${BASH_SOURCE[0]%/*}/restore_read.sh"

# shellcheck source=lib/restore_checks.sh
. "${BASH_SOURCE[0]%/*}/restore_checks.sh"

# shellcheck source=lib/restore_release.sh
. "${BASH_SOURCE[0]%/*}/restore_release.sh"

# shellcheck source=lib/restore_env.sh
. "${BASH_SOURCE[0]%/*}/restore_env.sh"

# shellcheck source=lib/restore_external.sh
. "${BASH_SOURCE[0]%/*}/restore_external.sh"

# shellcheck source=lib/restore_external_import.sh
. "${BASH_SOURCE[0]%/*}/restore_external_import.sh"

# shellcheck source=lib/restore_external_safety.sh
. "${BASH_SOURCE[0]%/*}/restore_external_safety.sh"
# shellcheck source=lib/restore_external_screens.sh
. "${BASH_SOURCE[0]%/*}/restore_external_screens.sh"

# shellcheck source=lib/restore_space.sh
. "${BASH_SOURCE[0]%/*}/restore_space.sh"

# shellcheck source=lib/restore_preview.sh
. "${BASH_SOURCE[0]%/*}/restore_preview.sh"

# shellcheck source=lib/restore_state.sh
. "${BASH_SOURCE[0]%/*}/restore_state.sh"

# shellcheck source=lib/restore_safety.sh
. "${BASH_SOURCE[0]%/*}/restore_safety.sh"

# shellcheck source=lib/restore_journal.sh
. "${BASH_SOURCE[0]%/*}/restore_journal.sh"

# shellcheck source=lib/restore_import.sh
. "${BASH_SOURCE[0]%/*}/restore_import.sh"

# shellcheck source=lib/restore_output.sh
. "${BASH_SOURCE[0]%/*}/restore_output.sh"

# shellcheck source=lib/restore_db_check.sh
. "${BASH_SOURCE[0]%/*}/restore_db_check.sh"

# shellcheck source=lib/restore_files.sh
. "${BASH_SOURCE[0]%/*}/restore_files.sh"

# shellcheck source=lib/restore_start.sh
. "${BASH_SOURCE[0]%/*}/restore_start.sh"

# shellcheck source=lib/restore_resume.sh
. "${BASH_SOURCE[0]%/*}/restore_resume.sh"

# shellcheck source=lib/restore_engine.sh
. "${BASH_SOURCE[0]%/*}/restore_engine.sh"

# shellcheck source=lib/restore_recovery.sh
. "${BASH_SOURCE[0]%/*}/restore_recovery.sh"

# shellcheck source=lib/restore_exit.sh
. "${BASH_SOURCE[0]%/*}/restore_exit.sh"

# shellcheck source=lib/restore_finish.sh
. "${BASH_SOURCE[0]%/*}/restore_finish.sh"

# shellcheck source=lib/restore_abandon.sh
. "${BASH_SOURCE[0]%/*}/restore_abandon.sh"

cmd_restore() {
  local file=${1:-}
  [ "$#" -le 1 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$2"
  cx_rs_options "$file"
  if [ -n "$CX_RS_ACTION" ]; then cx_rs_continue
  else cx_rs_new "$file"; fi
}
