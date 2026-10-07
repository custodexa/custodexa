# shellcheck shell=bash
# CX_UP_PRE_* are read by the upgrade steps that follow the preview; CX_BK_* come from
# lib/backup.sh.
# shellcheck disable=SC2034,SC2153
# The checks of upgrade that come before its preview, and the preview itself. Nothing here
# writes a file or stops a service: a refusal exits 3 (1 for too little space) with nothing changed.
#   an earlier run left unfinished   refused; its recovery command is printed
#   the backend                      running: its version is noted; not running: the preview says
#                                    the audit queue cannot be checked and the services stop directly
#   master key mode                  a preview row, and what is needed after the upgrade
#   the installed version's images   their IDs are noted for a rollback; missing ones are a warning
#   an external database             the target's PostgreSQL clients obtained and checked first, then
#                                    the server probed (lib/dbext.sh). When the script cannot back
#                                    it up: on a terminal the preview says why and step 7 takes the
#                                    operator's own backup only; without one (or with --yes) the run
#                                    is refused with the steps to an own backup. --backup-ref needs
#                                    neither the clients nor the probe.
#   the backup file                  when the script may back up: the data's version and the master
#                                    key mode it records, and the proxy template it takes
#                                    (lib/portable.sh), as the backup command checks them
#   space                            the backup file, its largest member and 1 GB, plus the new
#                                    images, against the free space where backups go; too little
#                                    stops the run here
#   report exports                   kept in <data>/exports on the host
# The seal state and the audit queue are read by the drain gate (lib/drain_gate.sh), after the
# preview is answered.
# Needs lib/backup.sh (sourced by lib/upgrade_query.sh) loaded first.
# shellcheck source=lib/backup_ref.sh
. "${BASH_SOURCE[0]%/*}/backup_ref.sh"
# shellcheck source=lib/portable.sh
. "${BASH_SOURCE[0]%/*}/portable.sh"

CX_UP_PRE_BACKEND=""     # running | stopped <time> | absent
CX_UP_PRE_HEALTH_VER=""  # the version /health reported, when it answered
CX_UP_PRE_ACTIVE=""      # connections in progress, "" when not known
CX_UP_PRE_PENDING=""     # structure changes this upgrade applies, "" when not known
CX_UP_PRE_OLD_IDS=""     # "<name>=<image ID> ..." of the installed version
CX_UP_PRE_OLD_MISSING=0  # an image of the installed version is not on this host
CX_UP_PRE_EXTERNAL_DB=0
CX_UP_OWN_ONLY=0 # the script cannot back up the external database this time (CX_DBX_FAIL says why)

# cx_up_pre_unfinished: an earlier state-changing run that never finished. An upgrade interrupted
# while the old version still ran unchanged (up to the drain gate, step 4), or one whose services
# were started again by hand after the stop (steps 5 to 7: nothing was switched yet), starts over
# with a warning; CX_UP_RERUN=1 then. Any other unfinished run is refused with the recovery
# commands of the step it stopped at; an unfinished backup with the commands to start the services
# and to back up again.
CX_UP_RERUN=0
cx_up_pre_unfinished() {
  local key prefix step
  CX_UP_RERUN=0
  for key in "${CX_STATE_KEYS[@]+"${CX_STATE_KEYS[@]}"}"; do
    [[ $key == *.result ]] || continue
    prefix=${key%.result}
    step=${CX_STATE[$prefix.step]:-?}
    # An upgrade that failed after the backup changed the deployment: the same as interrupted,
    # until a restore that finished settled it (lib/run.sh).
    if [ "$key" = last_upgrade.result ] && [ "${CX_STATE[$key]}" = failed ] && [[ $step =~ ^[0-9]+$ ]] \
      && [ "$step" -ge 8 ] && [ "${CX_STATE[last_upgrade.settled_by]:-}" != restore ]; then
      cx_line FAIL "$(cx_msg up_failed_at "$step")"
      cx_up_recovery_hint "$prefix" "$step"
      printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
      return "$CX_EXIT_REFUSED"
    fi
    [ "${CX_STATE[$key]}" = in_progress ] || continue
    # An interrupted backup: below, with a backup that was interrupted earlier.
    [ "$prefix" != last_backup ] || continue
    if [ "$prefix" = last_upgrade ] && cx_up_rerun_ok "$step"; then
      cx_line WARN "$(cx_msg run_interrupted upgrade "$step")"
      if [ "$step" -le 4 ]; then
        cx_up_par "$(cx_msg up_rerun_safe)"
      else
        cx_up_par "$(cx_msg up_rerun_resumed)"
      fi
      printf '\n'
      CX_UP_RERUN=1
      continue
    fi
    if [ "$prefix" = last_upgrade ]; then
      cx_line FAIL "$(cx_msg run_interrupted upgrade "$step")"
    else
      cx_line FAIL "$(cx_msg run_interrupted "$prefix" "$step")"
      printf '%s\n' "$(cx_msg run_recover_first)"
    fi
    cx_up_recovery_hint "$prefix" "$step"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_REFUSED"
  done
  # A backup that never finished: the upgrade waits until one does (lib/run.sh).
  ! cx_run_backup_refuse || return "$CX_EXIT_REFUSED"
}

# cx_up_rerun_ok <step>: an interrupted upgrade may start over: the old version ran unchanged when
# it stopped (steps 0 to 4), or it was stopped but not yet switched and runs again now (5 to 7).
cx_up_rerun_ok() {
  [[ $1 =~ ^[0-9]+$ ]] || return 1
  [ "$1" -le 4 ] && return 0
  [ "$1" -le 7 ] && [ "$(cx_br_backend)" = running ]
}

# cx_up_recovery_hint <state prefix> <step>: what to do after an interrupted run. For an upgrade,
# the commands of the step it stopped at (stopped and unchanged,
# switched to the new version); other commands: status and the log.
cx_up_recovery_hint() {
  local step=$2
  if [ "$1" != last_upgrade ] || ! [[ $step =~ ^[0-9]+$ ]]; then
    [ "$1" != last_upgrade ] || printf '%s\n' "$(cx_msg run_recover_first)"
    cx_recovery_hint "$(cx_run_command_of "$1")"
    return 0
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  if [ "$step" -le 8 ]; then
    cx_up_par "$(cx_msg up_hint_stopped)"
    cx_up_resume_cmd
    cx_up_par "$(cx_msg up_hint_again)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
  else
    cx_up_par "$(cx_msg up_hint_switched)"
    cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
    if [ -n "$(cx_state_get last_upgrade.backup)" ]; then
      cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_upgrade.backup)")"
    elif [ -n "$(cx_state_get last_backup.file)" ]; then
      cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_backup.file)")"
    elif [ -n "$(cx_state_get last_backup.dir)" ]; then
      cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_backup.dir)/")"
    fi
    if cx_rb_hint_ok; then
      cx_rb_hint
    else
      cx_up_par "$(cx_msg up_restore_guide "$(cx_state_get previous.version)")"
    fi
  fi
}

# cx_up_pre_backend: the backend container's state and, when it runs, the version it reports.
cx_up_pre_backend() {
  local health
  CX_UP_PRE_BACKEND=$(cx_br_backend)
  CX_UP_PRE_HEALTH_VER=""
  [ "$CX_UP_PRE_BACKEND" = running ] || return 0
  health=$(docker exec custodexa-backend wget -qO- http://localhost:8080/health 2>/dev/null) || return 0
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && CX_UP_PRE_HEALTH_VER=${BASH_REMATCH[1]}
  return 0
}

# cx_up_pre_old_images: the image IDs of the installed version (a rollback starts them again).
cx_up_pre_old_images() {
  local line name ref id
  local -a refs=()
  CX_UP_PRE_OLD_IDS="" CX_UP_PRE_OLD_MISSING=0
  if [ -f "$CX_ROOT/current/images.env" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      [[ $line =~ ^CUSTODEXA_IMAGE_([A-Z0-9_]+)=(.+)$ ]] || continue
      name=${BASH_REMATCH[1],,}
      refs+=("$name=${BASH_REMATCH[2]}")
    done <"$CX_ROOT/current/images.env"
  fi
  [ ${#refs[@]} -gt 0 ] || { CX_UP_PRE_OLD_MISSING=1; return 0; }
  for line in "${refs[@]}"; do
    name=${line%%=*} ref=${line#*=}
    if id=$(cx_img_id "$ref") && [ -n "$id" ]; then
      CX_UP_PRE_OLD_IDS+="${CX_UP_PRE_OLD_IDS:+ }$name=$id"
    else
      CX_UP_PRE_OLD_MISSING=1
    fi
  done
}

# cx_up_pre_space: the backup file (with the recordings), its largest member and 1 GB (cx_pb_space)
# plus the new images, against the free space where backups go. The images may live on another
# disk; counting them here only ever asks for more. An external database the script cannot reach
# this time has nothing to estimate.
cx_up_pre_space() {
  local images
  cx_db_ready || return 0
  if ! cx_bk_estimate; then
    cx_line FAIL "$(cx_msg bk_db_unreachable)"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
  cx_pb_space 1
  images=$(cx_mf_needed_bytes "$(cx_arch 2>/dev/null || printf amd64)")
  cx_log CHECK "space need=$CX_BK_NEED images=$images free=$CX_BK_FREE"
  if [ $((CX_BK_NEED + images)) -gt "$CX_BK_FREE" ]; then
    # The screen of the backup command; the recordings are always in the upgrade's file, so its
    # hint names no recordings to leave out.
    cx_line FAIL "$(cx_msg pb_no_space "$(cx_size_human $((CX_BK_NEED + images)))" "$CX_ROOT/backups" "$(cx_size_human "$CX_BK_FREE")")"
    cx_up_par "$(cx_msg up_no_space_hint)"
    cx_up_par "$(cx_msg pb_no_space_ls "ls -l $CX_ROOT/backups/")"
    return "$CX_EXIT_FAILED"
  fi
}

# cx_up_pre_counts: connections in progress and the structure changes to apply; either may stay
# unknown (the preview then says so).
cx_up_pre_counts() {
  local n
  CX_UP_PRE_ACTIVE="" CX_UP_PRE_PENDING=""
  cx_db_ready || return 0
  n=$(cx_snap_sql "SELECT count(*) FROM sessions WHERE status = 'active' AND deleted_at IS NULL" 2>/dev/null) || n=""
  [[ $n =~ ^[0-9]+$ ]] && CX_UP_PRE_ACTIVE=$n
  n=$(cx_q_pending 2>/dev/null) || n=""
  [[ $n =~ ^[0-9]+$ ]] && CX_UP_PRE_PENDING=$n
  return 0
}

# cx_up_interactive: the run can ask (a terminal, no --yes), as step 7 does.
cx_up_interactive() { [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; }

# cx_up_pre_ext: an external database, when the script may back it up: the target's clients
# obtained and checked (their lines go to the log; step 2 shows every image), then the server
# probed with them. 0 = the script can back it up, or only the operator's own backup is possible
# on a terminal (CX_UP_OWN_ONLY=1); otherwise the refusal's exit code.
cx_up_pre_ext() {
  local out n
  local -a clients=()
  cx_img_needed "$CX_OVERLAYS"
  for n in "${CX_TOOL_NAMES[@]+"${CX_TOOL_NAMES[@]}"}"; do
    [[ $n != pgclient[0-9]* ]] || clients+=("$n")
  done
  out=$(mktemp) || return "$CX_EXIT_FAILED"
  if [ "${#clients[@]}" -gt 0 ] && cx_images_resolve "$CX_OVERLAYS" "${clients[@]}" >"$out" 2>&1; then
    cx_dbx_prepare resolved
  else
    CX_DBX_FAIL=image CX_DBX_MISSING_MAJOR=""
  fi
  while IFS= read -r n || [ -n "$n" ]; do cx_log OUT "$n"; done <"$out"
  rm -f "$out"
  [ -n "$CX_DBX_FAIL" ] || return 0
  cx_log CHECK "external database: the script cannot back it up this time: $CX_DBX_FAIL${CX_DBX_MISSING_MAJOR:+ missing=pgclient$CX_DBX_MISSING_MAJOR}"
  # No client is used from here on: step 6 and the checks after the start know it by this.
  CX_DB_EXT_ID="" CX_DB_EXT_MAJOR=""
  if cx_up_interactive; then
    CX_UP_OWN_ONLY=1
    return 0
  fi
  cx_up_ext_refused
  return "$CX_EXIT_REFUSED"
}

# cx_up_ext_why <own|ni>: why the script cannot back up the external database, in the wording of
# the interactive warning (own) or of the refusal (ni); an unsupported setting lists its items.
cx_up_ext_why() {
  local f=$1 port
  port=$(cx_bk_env EXTERNAL_DB_PORT)
  case $CX_DBX_FAIL in
    version) cx_msg "up_ext_${f}_version" "$CX_DBX_SERVER" ;;
    connect) cx_msg "up_ext_${f}_connect" "$(cx_bk_env EXTERNAL_DB_HOST):${port:-5432}" ;;
    unsupported) cx_msg "up_ext_${f}_unsupported" ;;
    *) cx_msg "up_ext_${f}_image" "$(cx_up_ext_majors)" ;;
  esac
}

# cx_up_ext_majors: the client majors the target release carries, as "16/17/18" in the language.
cx_up_ext_majors() {
  local n out="" sep
  sep=$(cx_msg up_ext_major_sep)
  for n in "${CX_MF_IMAGES[@]}"; do
    [[ $n =~ ^pgclient([0-9]+)$ ]] && out+="${out:+$sep}${BASH_REMATCH[1]}"
  done
  printf '%s' "${out:-?}"
}

# cx_up_ext_items <indent>: the unsupported settings, one "- <text>" line each.
cx_up_ext_items() {
  local item key text pad=$1
  local -a args=()
  [ "$CX_DBX_FAIL" = unsupported ] || return 0
  for item in "${CX_DBX_ITEMS[@]}"; do
    key=${item%% *}
    args=()
    [ "$key" = "$item" ] || IFS=$'\t' read -r -a args <<<"${item#* }"
    text=$(cx_msg "$key" "${args[@]+"${args[@]}"}")
    printf '%s- %s\n' "$pad" "${text//$'\n'/$'\n'"$pad"  }"
  done
}

# cx_up_ext_own_only: the preview line of an upgrade whose step 7 can only take the operator's own
# backup.
cx_up_ext_own_only() {
  printf '\n'
  cx_br_ind WARN "$(cx_up_ext_why own)"
  cx_up_ext_items '           '
}

# cx_up_ext_refused: non-interactive, and the script cannot back up the external database: nothing
# was changed; the steps to an own backup the next run accepts. The reason goes to a log of its own,
# named on the screen (state.json is not touched).
cx_up_ext_refused() {
  local stop flags target=$CX_UP_TARGET self=${CX_SELF:-} given=${CX_FLAGS_TEXT:-}
  if cx_log_open upgrade; then
    cx_log BEGIN "upgrade lang=${CX_LANG:-en} script=${self#"$CX_ROOT"/} flags=\"${given# }\""
    cx_log END "result=refused step=1"
  fi
  cx_line FAIL "$(cx_up_ext_why ni)"
  if [ "$CX_DBX_FAIL" = unsupported ]; then
    cx_up_ext_items '         '
    printf '%s\n' "$(cx_up_par "$(cx_msg up_ext_ni_order)")"
  fi
  stop="sudo $CX_ROOT/custodexa.sh"
  printf '%s\n' "$(cx_up_par "$(cx_msg up_ext_ni_1)")"
  printf '       %s\n' "$stop stop --yes"
  printf '%s\n' "$(cx_up_par "$(cx_msg up_ext_ni_2)")"
  printf '       %s\n' "$stop status"
  printf '%s\n' "$(cx_up_par "$(cx_msg "up_ext_ni_3$(cx_br_notls)")")"
  printf '%s\n' "$(cx_up_par "$(cx_msg up_ext_ni_4)")"
  printf '       %s\n' "$stop upgrade $target --yes \\"
  flags=$(cx_msg up_ext_ni_flags)
  printf '         %s\n' "${flags//$'\n'/$'\n'         }"
  [ -z "$CX_LOG_FILE" ] || printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
}

# cx_up_pre_portable: what the backup file records and takes, checked as the backup command does
# before anything stops: the data's version (state.json against current/MANIFEST.json), the master
# key mode, and the proxy template TLS_NGINX_TEMPLATE names. Returns the refusal's exit code.
cx_up_pre_portable() {
  local rc=0
  cx_pb_versions || rc=$?
  case $rc in
    0) ;;
    2) cx_line FAIL "$(cx_msg pb_version_mismatch "${CX_PB_VERSION:-?}" "${CX_PB_MF_VERSION:-?}")"; return "$CX_EXIT_REFUSED" ;;
    3) cx_line FAIL "$(cx_msg pb_tool_version "$CX_PB_TOOL_MF" "$CX_PB_TOOL_VERSION" "$CX_PB_SCRIPT_VERSION")"; return "$CX_EXIT_REFUSED" ;;
    *) return "$CX_EXIT_REFUSED" ;;
  esac
  cx_pb_kek_mode
  case $CX_PB_KEK_REFUSE in
    "") ;;
    material) cx_line FAIL "$(cx_msg pb_kek_material "$CX_PB_KEK_SHOWN")"; return "$CX_EXIT_REFUSED" ;;
    *) cx_line FAIL "$(cx_msg "pb_kek_$CX_PB_KEK_REFUSE")"; return "$CX_EXIT_REFUSED" ;;
  esac
  rc=0
  cx_pb_parts || rc=$?
  case $rc in
    0) ;;
    2) cx_line FAIL "$(cx_msg pb_tpl_chars "$CX_PB_TPL")"; return "$CX_EXIT_REFUSED" ;;
    *) cx_line FAIL "$(cx_msg pb_tpl_missing "$CX_PB_TPL_FILE")"; return "$CX_EXIT_REFUSED" ;;
  esac
}

# cx_up_preflight: every check before the preview. Returns the exit code of a refusal. The run's
# log opens at step 3; what these checks log is kept until then (or until a refusal opens one).
cx_up_preflight() {
  local rc=0
  cx_secrets_from_env "$CX_ROOT/.env"
  cx_log_hold
  cx_up_preflight_checks || rc=$?
  cx_log_hold_end
  return "$rc"
}

cx_up_preflight_checks() {
  local rc=0
  # cx_up_pre_unfinished runs first of all, in cx_up_run.
  CX_OVERLAYS=$(cx_state_get current.overlays)
  case " $CX_OVERLAYS " in *" external-database "*) CX_UP_PRE_EXTERNAL_DB=1 ;; esac
  cx_bk_vars
  cx_up_pre_backend
  CX_UP_OWN_ONLY=0
  if cx_br_flags_given; then
    # The operator's own backup given on the command line: only when the services already stopped
    # before this run; checked now, so a refusal changes nothing. No client, no probe.
    cx_br_noninteractive || return "$?"
  else
    if [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ]; then
      cx_up_pre_ext || return "$?"
    fi
    if [ "$CX_UP_OWN_ONLY" = 0 ]; then
      cx_up_pre_portable || return "$?"
    fi
  fi
  cx_up_pre_old_images
  cx_up_pre_space || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  cx_up_pre_counts
}

# cx_up_preview_body: the rest of the preview after the rows at the top.
cx_up_preview_body() {
  local m low high
  case $CX_BK_KEK in
    ui | env | kms | hsm) printf '%s\n' "$(cx_msg up_row_kek "$(cx_msg "up_kek_$CX_BK_KEK")")" ;;
  esac
  printf '\n%s\n' "$(cx_msg up_will)"
  printf '%s\n' "$(cx_msg up_will_1)"
  if ! cx_db_ready; then
    # An external database without a client: the backup given with --backup-ref, or only an own
    # backup possible this time (the reason closes the preview).
    if cx_br_flags_given; then
      printf '%s\n' "$(cx_msg up_will_2_ref)"
    else
      printf '%s\n' "$(cx_msg up_will_2_own)"
    fi
    m=1
  else
    printf '%s\n' "$(cx_msg up_will_2 "$(cx_size_human "$CX_BK_NEED")" "$(cx_size_human "$CX_BK_FREE")")"
    m=$(cx_bk_minutes)
  fi
  printf '%s\n%s\n' "$(cx_msg up_will_3 "$CX_UP_TARGET")" "$(cx_msg up_will_4)"
  # The backup (taking the data, then packing and reading back the file), then switching,
  # starting and checking (a few minutes); up to twice that.
  low=$((m + 3)) high=$(((m + 3) * 2))
  printf '\n%s\n' "$(cx_msg up_know)"
  if [ -n "$CX_UP_PRE_ACTIVE" ]; then
    printf '%s\n' "$(cx_msg up_know_pause "$low" "$high" "$CX_UP_PRE_ACTIVE")"
  else
    printf '%s\n' "$(cx_msg up_know_pause_unknown "$low" "$high")"
  fi
  [ "$CX_UP_PRE_BACKEND" = running ] || printf '%s\n' "$(cx_msg up_know_backend_down)"
  case $CX_UP_PRE_PENDING in
    "") ! cx_db_ready || printf '%s\n' "$(cx_msg up_know_mig_unknown)" ;;
    0) printf '%s\n' "$(cx_msg up_know_mig_none)" ;;
    1) printf '%s\n' "$(cx_msg up_know_mig_one)" ;;
    *) printf '%s\n' "$(cx_msg up_know_mig_many "$CX_UP_PRE_PENDING")" ;;
  esac
  case $CX_BK_KEK in
    ui) printf '%s\n' "$(cx_msg up_know_ui)" ;;
    kms) printf '%s\n' "$(cx_msg up_know_kms)" ;;
  esac
  [ "$CX_TRUST_SIG $CX_TRUST_PROV" != "ok ok" ] || printf '%s\n' "$(cx_msg up_know_verified)"
  [ "$CX_UP_PRE_OLD_MISSING" = 0 ] || printf '%s\n' "$(cx_msg up_know_old_images)"
  printf '%s\n' "$(cx_msg up_know_tmux)"
  [ "$CX_UP_OWN_ONLY" != 1 ] || cx_up_ext_own_only
}
