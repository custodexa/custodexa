# shellcheck shell=bash
# CX_UP_PRE_* are read by the upgrade steps that follow the preview.
# shellcheck disable=SC2034
# The checks of upgrade that come before its preview, and the preview itself. Nothing here
# writes a file or stops a service: a refusal exits 3 (1 for too little space) with nothing changed.
#   an earlier run left unfinished   refused; its recovery command is printed
#   the development compose file     refused (a git clone deployment run from docker-compose.dev.yml)
#   the backend                      running: its version is noted; not running: the preview says
#                                    the audit queue cannot be checked and the services stop directly
#   master key mode                  a preview row, and what is needed after the upgrade
#   the installed version's images   their IDs are noted for a rollback; missing ones are a warning
#   space                            the backup estimate plus the new images, against the free space
#                                    where backups go; too little stops the run here
#   report exports                   not said: from 1.13.0 on they are kept in <data>/exports on the
#                                    host (a first conversion copies them there, lib/convert.sh)
# The seal state and the audit queue are read by the drain gate (lib/drain_gate.sh), after the
# preview is answered.
# Needs lib/backup.sh (sourced by lib/upgrade_query.sh) loaded first.
# shellcheck source=lib/backup_ref.sh
. "${BASH_SOURCE[0]%/*}/backup_ref.sh"

CX_UP_PRE_BACKEND=""     # running | stopped <time> | absent
CX_UP_PRE_HEALTH_VER=""  # the version /health reported, when it answered
CX_UP_PRE_ACTIVE=""      # connections in progress, "" when not known
CX_UP_PRE_PENDING=""     # structure changes this upgrade applies, "" when not known
CX_UP_PRE_OLD_IDS=""     # "<name>=<image ID> ..." of the installed version
CX_UP_PRE_OLD_MISSING=0  # an image of the installed version is not on this host
CX_UP_PRE_EXTERNAL_DB=0

# cx_up_pre_unfinished: an earlier state-changing run that never finished. An upgrade interrupted
# while the old version still ran unchanged (up to the drain gate, step 4), or one whose services
# were started again by hand after the stop (steps 5 to 7: nothing was switched yet), starts over
# with a warning; CX_UP_RERUN=1 then. Any other unfinished run is refused with the recovery
# commands of the step it stopped at.
CX_UP_RERUN=0
cx_up_pre_unfinished() {
  local key prefix step
  CX_UP_RERUN=0
  for key in "${CX_STATE_KEYS[@]+"${CX_STATE_KEYS[@]}"}"; do
    [[ $key == *.result ]] || continue
    prefix=${key%.result}
    step=${CX_STATE[$prefix.step]:-?}
    # An upgrade that failed from the conversion on changed the deployment: the same as interrupted.
    if [ "$key" = last_upgrade.result ] && [ "${CX_STATE[$key]}" = failed ] && [[ $step =~ ^[0-9]+$ ]] \
      && [ "$step" -ge 8 ]; then
      cx_line FAIL "$(cx_msg up_failed_at "$step")"
      cx_up_recovery_hint "$prefix" "$step"
      printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
      return "$CX_EXIT_REFUSED"
    fi
    [ "${CX_STATE[$key]}" = in_progress ] || continue
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
# conversion under way, switched to the new version); other commands: status and the log.
cx_up_recovery_hint() {
  local step=$2
  if [ "$1" != last_upgrade ] || ! [[ $step =~ ^[0-9]+$ ]]; then
    [ "$1" != last_upgrade ] || printf '%s\n' "$(cx_msg run_recover_first)"
    cx_recovery_hint "$(cx_run_command_of "$1")"
    return 0
  fi
  CX_OVERLAYS=$(cx_state_get current.overlays)
  if [ "$step" -eq 8 ] && [ "$(cx_state_get current.kind)" = legacy-git-clone ]; then
    cx_cv_hint "$(cx_state_get conversion.from)" "$CX_ROOT/$(cx_state_get conversion.env_backup)" \
      "$(cx_state_get conversion.old_project)" "$(cx_state_get conversion.old_files)"
  elif [ "$step" -le 8 ]; then
    cx_up_par "$(cx_msg up_hint_stopped)"
    cx_up_resume_cmd
    cx_up_par "$(cx_msg up_hint_again)"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $CX_UP_TARGET"
  else
    cx_up_par "$(cx_msg up_hint_switched)"
    cx_cmd "sudo docker compose $(cx_up_compose_hint) logs --tail 50 backend"
    [ -z "$(cx_state_get last_backup.dir)" ] \
      || cx_up_par "$(cx_msg up_hint_backup "$CX_ROOT/$(cx_state_get last_backup.dir)/")"
    cx_up_par "$(cx_msg up_restore_guide "$(cx_state_get previous.version)")"
  fi
}

# cx_up_pre_form: a git clone deployment started from the development compose file is not a
# deployment form and is not upgraded.
cx_up_pre_form() {
  local cf
  [ "$CX_UP_KIND" = convert ] || return 0
  cf=$(cx_env_get "$CX_ROOT/.env" COMPOSE_FILE)
  case $cf in
    *docker-compose.dev.yml*)
      cx_line FAIL "$(cx_msg up_dev_form "$cf")"
      printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
      return "$CX_EXIT_REFUSED"
      ;;
  esac
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
  if [ "$CX_UP_KIND" = convert ]; then
    refs=(backend=custodexa/backend:latest frontend=custodexa/frontend:latest guacd=custodexa/guacd:latest)
  elif [ -f "$CX_ROOT/current/images.env" ]; then
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

# cx_up_pre_space: the backup estimate (lib/backup.sh) plus the new images against the free space
# where backups go. The images may live on another disk; counting them here only ever asks for more.
cx_up_pre_space() {
  local images
  [ "$CX_UP_PRE_EXTERNAL_DB" = 0 ] || return 0
  if ! cx_bk_estimate; then
    cx_line FAIL "$(cx_msg bk_db_unreachable)"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
  images=$(cx_mf_needed_bytes "$(cx_arch 2>/dev/null || printf amd64)")
  if [ $((CX_BK_NEED + images)) -gt "$CX_BK_FREE" ]; then
    cx_line FAIL "$(cx_msg bk_no_space "$(cx_bk_gb $((CX_BK_NEED + images)))" "$CX_ROOT/backups" "$(cx_bk_gb "$CX_BK_FREE")")"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
}

# cx_up_pre_counts: connections in progress and the structure changes to apply; either may stay
# unknown (the preview then says so).
cx_up_pre_counts() {
  local n
  CX_UP_PRE_ACTIVE="" CX_UP_PRE_PENDING=""
  [ "$CX_UP_PRE_EXTERNAL_DB" = 0 ] || return 0
  n=$(cx_snap_sql "SELECT count(*) FROM sessions WHERE status = 'active' AND deleted_at IS NULL" 2>/dev/null) || n=""
  [[ $n =~ ^[0-9]+$ ]] && CX_UP_PRE_ACTIVE=$n
  n=$(cx_q_pending 2>/dev/null) || n=""
  [[ $n =~ ^[0-9]+$ ]] && CX_UP_PRE_PENDING=$n
  return 0
}

# cx_up_preflight: every check before the preview. Returns the exit code of a refusal.
cx_up_preflight() {
  local rc=0
  # cx_up_pre_unfinished runs first of all, in cx_up_run.
  cx_up_pre_form || return "$?"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  # A git clone deployment: a clean work tree first, then the overlays its COMPOSE_FILE names.
  if [ "$CX_UP_KIND" = convert ]; then
    cx_cv_check || return "$?"
    cx_cv_plan
    CX_OVERLAYS=$CX_CV_OVERLAYS
  fi
  case " $CX_OVERLAYS " in *" external-database "*) CX_UP_PRE_EXTERNAL_DB=1 ;; esac
  cx_bk_vars
  # A git clone deployment is stopped and backed up under its own project and compose files.
  if [ "$CX_UP_KIND" = convert ] && ! cx_up_legacy_compose; then
    cx_line FAIL "$(cx_msg up_legacy_compose_unknown "$CX_ROOT")"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
  cx_up_pre_backend
  # The operator's own backup given on the command line: only when the services already stopped
  # before this run; checked now, so a refusal changes nothing.
  if cx_br_flags_given; then
    cx_br_noninteractive || return "$?"
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
  if [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ]; then
    printf '%s\n' "$(cx_msg up_will_2_external)"
    m=1
  else
    printf '%s\n' "$(cx_msg up_will_2 "$(cx_bk_gb "$CX_BK_NEED")" "$(cx_bk_gb "$CX_BK_FREE")")"
    m=$(cx_bk_minutes)
  fi
  printf '%s\n%s\n' "$(cx_msg up_will_3 "$CX_UP_TARGET")" "$(cx_msg up_will_4)"
  # The backup, then switching, starting and checking (a few minutes); up to twice that.
  low=$((m + 3)) high=$(((m + 3) * 2))
  printf '\n%s\n' "$(cx_msg up_know)"
  if [ -n "$CX_UP_PRE_ACTIVE" ]; then
    printf '%s\n' "$(cx_msg up_know_pause "$low" "$high" "$CX_UP_PRE_ACTIVE")"
  else
    printf '%s\n' "$(cx_msg up_know_pause_unknown "$low" "$high")"
  fi
  [ "$CX_UP_PRE_BACKEND" = running ] || printf '%s\n' "$(cx_msg up_know_backend_down)"
  case $CX_UP_PRE_PENDING in
    "") [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ] || printf '%s\n' "$(cx_msg up_know_mig_unknown)" ;;
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
}
