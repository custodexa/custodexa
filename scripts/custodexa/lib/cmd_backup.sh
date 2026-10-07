# shellcheck shell=bash
# CX_OVERLAYS is read by lib/compose.sh.
# shellcheck disable=SC2034
# custodexa.sh backup: a stopped backup of this deployment into one portable file (lib/portable.sh).
#   checks -> preview (the recordings and encryption choices, lib/backup_ask.sh; pause, sealing,
#   size and free space) -> confirm -> 7 steps -> the file
# A version that cannot be told, a master key setting the backend would refuse, a passphrase file
# that cannot be used, a missing encryption image, an external database the script cannot back up
# (lib/dbext.sh), or not enough space stops the run before any service is stopped.
# shellcheck source=lib/backup.sh
. "${BASH_SOURCE[0]%/*}/backup.sh"
# shellcheck source=lib/health.sh
. "${BASH_SOURCE[0]%/*}/health.sh"
# shellcheck source=lib/portable.sh
. "${BASH_SOURCE[0]%/*}/portable.sh"
# shellcheck source=lib/backup_ask.sh
. "${BASH_SOURCE[0]%/*}/backup_ask.sh"
# shellcheck source=lib/backup_external.sh
. "${BASH_SOURCE[0]%/*}/backup_external.sh"

CX_PB_ASKED_REC=0 CX_PB_ASKED_ENC=0 CX_PB_PICK="" CX_PB_TYPED=""

# cmd_backup_ind <mark> <text>: a status line 2 columns in, later lines under the text.
cmd_backup_ind() { printf '  %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'         }"; }
# cmd_backup_par <text>: a paragraph 2 columns in.
cmd_backup_par() { printf '%s\n' "$1" | sed 's/^/  /'; }
# cmd_backup_cmd <command>: a command under a paragraph, 2 columns in.
cmd_backup_cmd() { printf '  %s\n' "$1"; }

# cmd_backup_step <OK|WARN|FAIL> <n> <total> <step id> <start>: the step line; a few steps show no
# time.
cmd_backup_step() {
  local dur="" key=bk_step_$4
  if [ "$1" != FAIL ] && [ "$4" != conf ]; then
    dur=$(cx_duration $(($(cx_now) - $5)))
  fi
  case $4 in
    stop) ! cx_db_external || key=pb_step_stop_ext ;;
    files) [ "$CX_PB_WITH_REC" = 1 ] || key=pb_step_audit ;;
    start | verify | pack) key=pb_step_$4 ;;
  esac
  [ "$4$CX_PB_ENC" != pack1 ] || key=pb_step_pack_enc
  cx_step_line "$1" "$2/$3" "$(cx_msg "$key")" "$dur"
  cx_step "$2" "$3" "$4"
}

# cmd_backup_contents: "Contains: database, ..., certificates tls/", wrapped like the screen. A
# deployment without tls/ has no certificates to name; a proxy template .env names is named.
cmd_backup_contents() {
  local sep items env=bk_item_env
  sep=$(cx_msg bk_item_sep)
  [ "$CX_PB_KEK" = env ] && env=bk_item_env_kek
  items=$(cx_msg bk_item_db)
  [ "$CX_PB_WITH_REC" != 1 ] || items+="$sep$(cx_msg bk_item_rec)"
  items+="$sep$(cx_msg bk_item_audit)$sep$(cx_msg "$env")"
  [ "$CX_PB_TLS" != 1 ] || items+="$sep$(cx_msg bk_item_tls)"
  [ -z "$CX_PB_TPL" ] || items+="$sep$(cx_msg pb_item_tpl "$CX_PB_TPL")"
  cmd_backup_par "$(cx_wrap 70 "$(cx_msg bk_contents "$items")")"
}

cmd_backup_unseal_url() {
  local url
  url=$(cx_bk_env PUBLIC_BASE_URL)
  printf '%s/unseal' "${url%/}"
}

cmd_backup_cmd_of() { printf 'sudo %s/custodexa.sh %s%s' "$CX_ROOT" "$1" "$(cx_status_lang_arg)"; }

# cmd_backup_mode: the master key mode in words.
cmd_backup_mode() {
  local p
  case $CX_PB_KEK in
    kms)
      p=$(cx_pb_trim "$(cx_bk_env KEK_KMS_PROVIDER)")
      cx_msg pb_mode_kms "${p:-?}"
      ;;
    *) cx_msg "pb_mode_$CX_PB_KEK" ;;
  esac
}

# cmd_backup_key: where the master key comes from on a restore, and the fingerprint warnings. A
# fingerprint that could not be read is not shown at all; the warning below says why.
cmd_backup_key() {
  local p
  local nofp=""
  local -a fp=("$CX_PB_FP")
  if [ "$CX_PB_FP_STATUS" != ok ] || [ -z "$CX_PB_FP" ]; then
    fp=()
    nofp=_nofp
  fi
  case $CX_PB_KEK in
    env) cmd_backup_par "$(cx_msg "pb_kek_in$nofp" "${fp[@]+"${fp[@]}"}")" ;;
    kms)
      p=$(cx_pb_trim "$(cx_bk_env KEK_KMS_PROVIDER)")
      cmd_backup_par "$(cx_msg "pb_kek_kms$nofp" "${p:-?}" "${fp[@]+"${fp[@]}"}")"
      ;;
    *) cmd_backup_par "$(cx_msg "pb_kek_out$nofp" "${fp[@]+"${fp[@]}"}")" ;;
  esac
  if [ "$CX_PB_FP_STATUS" != ok ]; then
    cmd_backup_ind WARN "$(cx_msg pb_warn_kek_fp)"
  elif [ "$CX_SNAP_USABLE" != true ]; then
    cmd_backup_ind WARN "$(cx_msg pb_warn_fps)"
  fi
}

# cmd_backup_service: how the services came back (step 5): back, waiting to be unsealed, or not
# ready in time with the commands to look and to start again.
cmd_backup_service() {
  if [ "$CX_PB_HEALTH" != ready ]; then
    cmd_backup_ind WARN "$(cx_msg pb_svc_timeout "$(cx_ready_seconds)")"
    cx_cmd "$(cmd_backup_cmd_of status)"
    cx_cmd "$(cmd_backup_cmd_of start)"
    return 0
  fi
  case $CX_PB_KEK in
    env) cmd_backup_ind OK "$(cx_msg pb_svc_back)" ;;
    ui) cmd_backup_ind WARN "$(cx_msg pb_svc_ui "$(cmd_backup_unseal_url)")" ;;
    *) cmd_backup_ind WARN "$(cx_msg pb_svc_kms "$(cmd_backup_unseal_url)")" ;;
  esac
}

# cmd_backup_file_lines: the backup file and its checksum file.
cmd_backup_file_lines() {
  cmd_backup_par "$CX_PB_FINAL"
  cmd_backup_par "$(cx_msg pb_sidecar "$CX_PB_NAME.sha256")"
}

cmd_backup_done() {
  local done=pb_done
  [ "$CX_PB_ENC" != 1 ] || done=pb_done_enc
  printf '\n'
  cx_line OK "$(cx_msg "$done" "$(cx_size_human "$CX_PB_SIZE")")"
  cmd_backup_file_lines
  cmd_backup_contents
  cmd_backup_summary
  cmd_backup_key
  [ "$CX_PB_ENC" != 1 ] || cmd_backup_ind WARN "$(cx_msg pb_warn_pass)"
  [ "$CX_PB_WITH_REC" = 1 ] || cmd_backup_ind WARN "$(cx_msg pb_warn_rec "$CX_BK_DATA/recordings/")"
  if [ "$CX_PB_ENC" = 1 ]; then
    cmd_backup_ind WARN "$(cx_msg pb_warn_enc_host)"
  elif [ "$CX_PB_KEK" = env ]; then
    cmd_backup_ind WARN "$(cx_msg pb_warn_plain_kek)"
  else
    cmd_backup_ind WARN "$(cx_msg pb_warn_plain)"
  fi
  cmd_backup_ext_roles
  cmd_backup_service
  [ "$CX_PB_ENC" != 1 ] || cmd_backup_par "$(cx_msg pb_enc_scheme)"
  cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}

# cmd_backup_failed: a step failed before the commit. While the services may still be stopped the
# command to start them; once they started, how they came back.
cmd_backup_failed() {
  printf '\n'
  cx_line FAIL "$(cx_msg pb_failed "$CX_BK_DIR/")"
  if [ "$CX_PB_SVC" = started ]; then
    cmd_backup_service
  else
    printf '%s\n' "$(cx_msg bk_start_again)"
    cmd_backup_cmd "$(cmd_backup_cmd_of start)"
  fi
  cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}

# cmd_backup_after <state failed 0|1> <cleanup failed 0|1>: the file is committed, what did not
# finish after it.
cmd_backup_after() {
  local key=pb_after_both
  [ "$2" = 1 ] || key=pb_after_state
  [ "$1" = 1 ] || key=pb_after_partial
  printf '\n'
  cx_line WARN "$(cx_msg pb_valid)"
  cmd_backup_file_lines
  cx_line FAIL "$(cx_msg "$key" "$CX_BK_DIR/")"
  cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
}

# cmd_backup_timeout_cmds: the backend was not ready in time: the commands to look and to start.
cmd_backup_timeout_cmds() {
  cmd_backup_ind WARN "$(cx_msg pb_sig_timeout "$(cx_ready_seconds)")"
  cx_cmd "$(cmd_backup_cmd_of status)"
  cx_cmd "$(cmd_backup_cmd_of start)"
}

# cmd_backup_on_signal: the command running now and what it started are stopped, this run's tool
# containers and named pipes removed; the rest of the temporary folder stays (0700). Then the
# screen for where the run stood (cx_pb_commit_state). The state stays in_progress before the
# commit: the next start, stop and backup say so, and an upgrade waits for a finished backup.
cmd_backup_on_signal() {
  local st
  trap - INT TERM HUP
  cx_pb_interrupt_cleanup
  # Interrupted before the temporary folder existed: nothing was stopped or written.
  if [ -z "$CX_BK_DIR" ]; then
    cx_finish cancelled || true
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)" >&"${CX_SIGNAL_FD:-2}"
    exit "$CX_EXIT_FAILED"
  fi
  st=$(cx_pb_commit_state)
  [ "$st" != pre-commit ] || cmd_backup_interrupted
  cx_log END "result=interrupted step=$CX_RUN_STEP commit=$st"
  {
    printf '\n'
    cx_line WARN "$(cx_msg pb_sig_valid)"
    cmd_backup_file_lines
    if [ "$st" = committed ]; then
      cx_line FAIL "$(cx_msg pb_sig_both "$CX_BK_DIR/")"
    elif [ -d "$CX_BK_DIR" ]; then
      cx_line FAIL "$(cx_msg pb_sig_partial "$CX_BK_DIR/")"
    fi
    [ "$CX_PB_HEALTH" != timeout ] || cmd_backup_timeout_cmds
    cmd_backup_par "$(cx_msg bk_log "$CX_LOG_FILE")"
  } >&"${CX_SIGNAL_FD:-2}"
  exit "$CX_EXIT_FAILED"
}

# cmd_backup_interrupted: interrupted before the commit: no backup file. While the services may
# still be stopped the command to start them; once started but not ready in time, the commands to
# look and to start; then the command to back up again.
cmd_backup_interrupted() {
  # The step it stopped in, for the next run; the run stays in progress.
  cx_state_set last_backup.step "$CX_BK_STEP_NOW"
  cx_state_save "$CX_ROOT/state.json" 2>/dev/null || true
  cx_log END "result=interrupted step=$CX_BK_STEP_NOW commit=pre-commit"
  {
    printf '\n'
    cx_line FAIL "$(cx_msg pb_sig_failed "$CX_BK_STEP_NOW" "$CX_BK_DIR/")"
    case $CX_PB_HEALTH in
      ready) ;;
      timeout) cmd_backup_timeout_cmds ;;
      *)
        printf '%s\n' "$(cx_msg bk_start_again)"
        cmd_backup_cmd "$(cmd_backup_cmd_of start)"
        ;;
    esac
    printf '%s\n' "$(cx_msg pb_sig_again)"
    cmd_backup_cmd "$(cmd_backup_cmd_of backup)"
  } >&"${CX_SIGNAL_FD:-2}"
  exit "$CX_EXIT_FAILED"
}

# cmd_backup_refuse <message...>: a FAIL before anything was stopped; the run is recorded failed.
cmd_backup_refuse() {
  cx_line FAIL "$(cx_msg "$@")"
  cx_finish failed
  exit "$CX_EXIT_REFUSED"
}

# cmd_backup_checks: the version of the data and the master key mode, before the preview.
cmd_backup_checks() {
  local rc=0
  cx_pb_versions || rc=$?
  case $rc in
    0) ;;
    2)
      cx_line FAIL "$(cx_msg pb_version_mismatch "${CX_PB_VERSION:-?}" "${CX_PB_MF_VERSION:-?}")"
      cmd_backup_cmd "$(cmd_backup_cmd_of status)"
      cx_finish failed
      exit "$CX_EXIT_REFUSED"
      ;;
    3) cmd_backup_refuse pb_tool_version "$CX_PB_TOOL_MF" "$CX_PB_TOOL_VERSION" "$CX_PB_SCRIPT_VERSION" ;;
    *) cx_finish failed; exit "$CX_EXIT_REFUSED" ;;
  esac
  cx_pb_kek_mode
  case $CX_PB_KEK_REFUSE in
    "") ;;
    material) cmd_backup_refuse pb_kek_material "$CX_PB_KEK_SHOWN" ;;
    *) cmd_backup_refuse "pb_kek_$CX_PB_KEK_REFUSE" ;;
  esac
  rc=0
  cx_pb_parts || rc=$?
  case $rc in
    0) ;;
    2) cmd_backup_refuse pb_tpl_chars "$CX_PB_TPL" ;;
    *) cmd_backup_refuse pb_tpl_missing "$CX_PB_TPL_FILE" ;;
  esac
}

# cmd_backup_no_space: the space check failed; nothing was stopped.
cmd_backup_no_space() {
  cx_line FAIL "$(cx_msg pb_no_space "$(cx_size_human "$CX_BK_NEED")" "$CX_ROOT/backups" "$(cx_size_human "$CX_BK_FREE")")"
  cmd_backup_par "$(cx_msg pb_no_space_hint)"
  cmd_backup_par "$(cx_msg pb_no_space_ls "ls -l $CX_ROOT/backups/")"
  cx_finish failed
  exit "$CX_EXIT_FAILED"
}

# cmd_backup_choices: what goes into the file and whether it is encrypted, as chosen; a choice
# made by default without a question says which option changes it.
cmd_backup_choices() {
  local rec=pb_rec_line_hint enc=pb_enc_line_hint
  if [ "$CX_PB_WITH_REC" = 1 ]; then
    rec=pb_rec_line_yes
  elif [ "$CX_PB_ASKED_REC" = 1 ]; then
    rec=pb_rec_line_no
  fi
  cmd_backup_par "$(cx_msg "$rec")"
  if [ -n "${CX_PASSPHRASE_FILE:-}" ]; then
    cmd_backup_par "$(cx_msg pb_enc_line_file "$CX_PB_PF_PATH")"
    return 0
  fi
  if [ "$CX_PB_ENC" = 1 ]; then
    enc=pb_enc_line_yes
  elif [ "$CX_PB_ASKED_ENC" = 1 ]; then
    enc=pb_enc_line_no
  fi
  cmd_backup_par "$(cx_msg "$enc")"
}

# cmd_backup_space_check: the space for the choice made, recorded in the log; not enough stops here.
cmd_backup_space_check() {
  cx_pb_space "$CX_PB_WITH_REC"
  cx_log PREVIEW "need=$CX_BK_NEED file=$CX_PB_FILE_EST free=$CX_BK_FREE recordings=$CX_PB_WITH_REC kek_provider=$CX_PB_KEK encryption=$CX_PB_ENC"
  [ "$CX_BK_NEED" -le "$CX_BK_FREE" ] || cmd_backup_no_space
}

# cmd_backup_sizes: the sizes and the free space, wrapped between words but never inside a size.
cmd_backup_sizes() {
  local nb=$'\x01' text
  text=$(cx_msg pb_sizes "$(cx_size_human "$CX_BK_SIZE_DB")" "$(cx_size_human "$CX_BK_SIZE_AUDIT")" \
    "$(cx_size_human "$CX_BK_SIZE_REC")" "$(cx_size_human "$CX_BK_FREE")")
  # A size is a number and its unit: join them for the wrap, then part them again.
  text=$(sed -E "s/([0-9.]+) ([KMG]B)/\1${nb}\2/g" <<<"$text")
  text=$(cx_wrap 70 "$text")
  cmd_backup_par "${text//$nb/ }"
}

# cmd_backup_preview: the version, the sizes, the questions (on a terminal without --yes), then the
# choices, the pause, sealing and the space, and the confirmation. The space is reckoned for what
# goes into the file, so it is checked once the recordings are chosen.
cmd_backup_preview() {
  local m
  if ! cx_bk_estimate; then
    if cx_db_external; then
      CX_DBX_FAIL=connect
      cmd_backup_ext_refuse
    fi
    cx_line FAIL "$(cx_msg bk_db_unreachable)"
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  CX_PB_WITH_REC=${CX_WITH_RECORDINGS:-0}
  printf '%s\n\n' "$(cx_msg bk_title)"
  cmd_backup_summary
  cmd_backup_ext_preview
  cmd_backup_sizes
  cmd_backup_ext_standby
  if cmd_backup_interactive; then
    if [ "$CX_PB_WITH_REC" != 1 ]; then
      CX_PB_ASKED_REC=1
      cmd_backup_ask_rec
      cmd_backup_space_check
    fi
    if [ -z "${CX_PASSPHRASE_FILE:-}" ]; then
      CX_PB_ASKED_ENC=1
      cmd_backup_ask_enc
    fi
    [ "$CX_PB_ASKED_REC$CX_PB_ASKED_ENC" = 00 ] || printf '\n'
  fi
  cx_pb_space "$CX_PB_WITH_REC"
  m=$(cx_pb_minutes)
  cmd_backup_choices
  if cx_db_external; then
    cmd_backup_par "$(cx_msg pb_pause_ext "$(cx_pb_dur "$m")" "$(cx_pb_dur "$m" more)")"
  else
    cmd_backup_par "$(cx_msg pb_pause "$(cx_pb_dur "$m")" "$(cx_pb_dur "$m" more)")"
  fi
  case $CX_PB_KEK in
    ui | kms | hsm) cmd_backup_ind WARN "$(cx_msg "pb_warn_seal_$CX_PB_KEK")" ;;
  esac
  cmd_backup_par "$(cx_msg pb_need "$(cx_size_human "$CX_BK_NEED")" "$(cx_size_human "$CX_PB_FILE_EST")" "$(cx_size_human "$CX_BK_FREE")")"
  printf '\n'
  cmd_backup_space_check
  if ! cx_confirm bk_confirm; then
    printf '%s\n' "$(cx_msg pre_nothing_changed)"
    cx_finish cancelled
    exit "$CX_EXIT_REFUSED"
  fi
  # --yes answered the question: show it answered, as on the terminal.
  [ "${CX_YES:-0}" != 1 ] || printf '%s y\n' "$(cx_msg bk_confirm)"
  printf '\n'
}

# cmd_backup_open: the timestamp and the temporary folder, before anything is stopped.
cmd_backup_open() {
  local rc=0
  cx_pb_open portable || rc=$?
  [ "$rc" != 0 ] || return 0
  if [ "$rc" = 2 ]; then
    cx_line FAIL "$(cx_msg pb_ts_taken "$CX_ROOT/backups" "$CX_BK_TS")"
  else
    cx_line FAIL "$(cx_msg bk_dir_failed "$CX_ROOT/backups")"
  fi
  cx_finish failed
  exit "$CX_EXIT_FAILED"
}

cmd_backup() {
  local state_failed=0 cleanup_failed=0
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_state_load "$CX_ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  cx_begin backup
  trap 'cmd_backup_on_signal' INT TERM HUP
  cmd_backup_checks
  cmd_backup_pass_file
  cmd_backup_external
  cmd_backup_preview
  cmd_backup_open
  if ! cx_bk_take portable cmd_backup_step; then
    CX_PB_PASS=""
    cmd_backup_failed
    cx_finish failed
    exit "$CX_EXIT_FAILED"
  fi
  # The passphrase is not needed past the read-back.
  CX_PB_PASS=""
  cx_pb_record || state_failed=1
  cx_pb_cleanup || cleanup_failed=1
  if [ "$state_failed$cleanup_failed" != 00 ]; then
    cx_log FAIL "after the commit: state=$state_failed cleanup=$cleanup_failed"
    cmd_backup_after "$state_failed" "$cleanup_failed"
    cx_finish failed || true
    exit "$CX_EXIT_FAILED"
  fi
  cx_finish succeeded || true
  cmd_backup_done
}
