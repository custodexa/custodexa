# shellcheck shell=bash
# custodexa.sh status: what this deployment is and how it is doing, changing nothing. No lock, no
# log file, nothing written; Docker is only asked (daemon info, container state, and /health and
# the seal status from inside the backend container). Sections, as reviewed:
#   version, services, images, backup, last upgrade, disk, reminders
# A section without anything to say is left out (images before an install, the last upgrade
# before the first one, reminders when there are none). Any [WARN] or [FAIL] line ends the run
# with exit code 4, so a monitor can act on the code alone.
# The backup and upgrade records (last_backup.*, last_upgrade.*, previous.*) are written by the
# backup and upgrade commands; status reads whatever of them is there.

readonly CX_STATUS_WRAP=56        # text columns of a line under a section (65 with its indent)
readonly CX_STATUS_BACKUP_DAYS=30 # an older latest backup is a warning
readonly CX_STATUS_MIN_FREE=5     # GB free on the deployment's file system, as install requires
readonly CX_STATUS_SERVICES="postgres guacd backend frontend tls-init tls-proxy"
readonly CX_STATUS_BACKEND=custodexa-backend
CX_STATUS_WARNED=0

# cmd_status_text <text>: each line of a message wrapped to CX_STATUS_WRAP columns.
cmd_status_text() {
  local line out="" sep=""
  while IFS= read -r line; do
    out+=$sep$(cx_wrap "$CX_STATUS_WRAP" "$line")
    sep=$'\n'
  done <<<"$1"
  printf '%s' "$out"
}

# cmd_status_line <mark> <text> [keep]: one line under a section, 2 columns in; later lines of
# the text under the text. With keep, the text is one line as given (the images line).
cmd_status_line() {
  local text=$2
  case $1 in OK | SKIP) ;; *) CX_STATUS_WARNED=1 ;; esac
  if [ -n "${3:-}" ]; then
    text=${text//$'\n'/ }
  else
    text=$(cmd_status_text "$text")
  fi
  cx_line "$1" "$text" | sed 's/^/  /'
}
cmd_status_under() { printf '         %s\n' "$1"; } # a line under the text of the line above
cmd_status_section() { printf '%s\n' "$(cx_msg "status_sec_$1")"; }

# cmd_status_pad <text> <columns>: the text and spaces up to that many columns (at least two).
cmd_status_pad() {
  local pad=$(($2 - $(cx_width "$1")))
  [ "$pad" -ge 2 ] || pad=2
  printf '%s%*s' "$1" "$pad" ''
}
cmd_status_row() { # <label id> <version> <text>
  printf '  %s%s%s\n' "$(cmd_status_pad "$(cx_msg "$1")" 11)" "$(cmd_status_pad "$2" 10)" "$3"
}

# Times in state.json are written as 2026-09-30T02:17:55+0800; they are shown as written.
cmd_status_day() { printf '%s' "${1:0:10}"; }
cmd_status_minute() { printf '%s %s' "${1:0:10}" "${1:11:5}"; }
cmd_status_days_ago() { # <recorded time>: whole days until now, empty when unreadable
  local t
  t=$(date -d "$1" +%s 2>/dev/null) || return 0
  printf '%s' $(((CX_STATUS_NOW - t) / 86400))
}
cmd_status_gb() { # <bytes>: "16.9 GB", "175 GB"
  awk -v b="${1:-0}" 'BEGIN { g = b / 1073741824; if (g >= 100) printf "%.0f GB", g; else printf "%.1f GB", g }'
}
cmd_status_du() { # <folder>: bytes used, 0 when absent; a part that cannot be read is left out
  local out
  [ -d "$1" ] || { printf '0'; return 0; }
  out=$(du -sb -- "$1" 2>/dev/null) || true
  printf '%s' "${out%%[[:space:]]*}"
}

cmd_status_env() { # <key>: the value in .env, empty when missing or unreadable
  [ -r "$CX_ROOT/.env" ] || return 0
  cx_env_get "$CX_ROOT/.env" "$1"
}
cmd_status_data_path() {
  local d
  d=$(cmd_status_env DATA_PATH)
  case $d in
    "") d=$CX_ROOT/data ;;
    /*) ;;
    *) d=$CX_ROOT/${d#./} ;;
  esac
  printf '%s' "${d%/}"
}

# ---------- version ----------
CX_STATUS_KIND="" # package | none
CX_STATUS_VERSION=""
cmd_status_version() {
  local st ver since kind prev
  cmd_status_section version
  ver=$(cx_state_get current.version)
  if [ -z "$ver" ]; then
    CX_STATUS_KIND=none
    st=$(cx_state_get install.result)
    if [ -z "$st" ]; then
      cmd_status_line WARN "$(cx_msg status_not_installed)"
    else
      cmd_status_line WARN "$(cx_msg status_install_unfinished "$(cx_state_get install.step)")"
    fi
    cx_cmd "sudo $CX_ROOT/custodexa.sh install"
    return 0
  fi
  CX_STATUS_KIND=package
  CX_STATUS_VERSION=$ver
  since=$(cmd_status_day "$(cx_state_get current.since)")
  kind=$(cx_msg status_kind_installed "$since")
  if [ "$(cx_state_get last_upgrade.result)" = succeeded ] && [ "$(cx_state_get last_upgrade.to)" = "$ver" ]; then
    kind=$(cx_msg status_kind_upgraded "$since")
  fi
  cmd_status_row status_label_current "$ver" "$kind"
  prev=$(cx_state_get previous.version)
  if [ -n "$prev" ] && [ -d "$CX_ROOT/releases/$prev" ]; then
    cmd_status_row status_label_previous "$prev" "$(cx_msg status_previous_kept)"
  fi
}

# ---------- services ----------
cmd_status_containers() { # the containers this deployment should have
  local n
  if [ "$CX_STATUS_KIND" = package ] && [ -n "$(cx_state_get current.image_ids)" ]; then
    for n in $(cx_state_get current.image_ids); do cx_img_container "${n%%=*}"; printf '\n'; done
  else
    for n in $CX_STATUS_SERVICES; do printf 'custodexa-%s\n' "$n"; done
  fi
}

CX_STATUS_BACKEND_UP=0
cmd_status_services() {
  local err c st total=0 oneshot=0 known=0
  local -a down=()
  cmd_status_section services
  if ! err=$(docker info 2>&1 >/dev/null); then
    if [[ $err == *"permission denied"* ]]; then
      cmd_status_line FAIL "$(cx_msg pre_docker_perm)"
      printf '%s\n' "$(cx_msg text_pre_docker_perm)"
    else
      cmd_status_line FAIL "$(cx_msg pre_docker_down "$(printf '%s' "$err" | tail -n1)")"
    fi
    return 0
  fi
  while IFS= read -r c; do
    st=$(docker container inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$c" 2>/dev/null) || st=""
    if [ -z "$st" ] && [ "$CX_STATUS_KIND" != package ]; then
      continue # not part of this deployment's form
    fi
    total=$((total + 1))
    [ -z "$st" ] || known=$((known + 1))
    if [ "$c" = custodexa-tls-init ]; then
      oneshot=1
      [ "$st" = "exited 0" ] || [ "${st%% *}" = running ] || down+=("$c")
    elif [ "${st%% *}" = running ]; then
      [ "$c" != "$CX_STATUS_BACKEND" ] || CX_STATUS_BACKEND_UP=1
    else
      down+=("$c")
    fi
  done < <(cmd_status_containers)
  if [ "$known" -eq 0 ]; then
    cmd_status_line FAIL "$(cx_msg status_services_none)"
  elif [ "${#down[@]}" -gt 0 ]; then
    cmd_status_line FAIL "$(cx_msg status_services_down "${#down[@]}" "$total" "${down[*]}")"
  elif [ "$oneshot" = 1 ]; then
    cmd_status_line OK "$(cx_msg status_services_ok_oneshot "$total")"
  else
    cmd_status_line OK "$(cx_msg status_services_ok "$total")"
  fi
  if [ "$known" -eq 0 ] || [ "${#down[@]}" -gt 0 ]; then
    printf '%s\n' "$(cx_msg status_services_hint)"
    cx_cmd "cd $CX_ROOT && sudo docker compose ps -a"
  fi
  [ "$CX_STATUS_BACKEND_UP" = 1 ] || return 0
  cmd_status_backend
}

cmd_status_ask_backend() { # <path>
  docker exec "$CX_STATUS_BACKEND" wget -qO- "http://localhost:8080$1" 2>/dev/null
}
cmd_status_backend() {
  local health v seal state url
  if ! health=$(cmd_status_ask_backend /health); then
    cmd_status_line FAIL "$(cx_msg status_health_bad)"
    cx_cmd "cd $CX_ROOT && sudo docker compose logs backend"
    return 0
  fi
  v=""
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && v=${BASH_REMATCH[1]}
  if [ -n "$CX_STATUS_VERSION" ] && [ "$v" != "$CX_STATUS_VERSION" ]; then
    cmd_status_line WARN "$(cx_msg status_health_version "${v:-?}" "$CX_STATUS_VERSION")"
  else
    cmd_status_line OK "$(cx_msg status_health_ok "${v:-?}")"
  fi
  if ! seal=$(cmd_status_ask_backend /api/v1/seal/status) || ! state=$(cx_seal_state "$seal"); then
    cmd_status_line SKIP "$(cx_msg status_seal_unknown)"
    return 0
  fi
  url=$(cmd_status_env PUBLIC_BASE_URL)
  url=${url%/}/unseal
  if [ "$state" = unsealed ]; then
    cmd_status_line OK "$(cx_msg status_unsealed)"
  elif [[ $seal =~ \"initialization_required\":\ ?true ]]; then
    cmd_status_line WARN "$(cx_msg status_seal_init "$url")"
  else
    cmd_status_line WARN "$(cx_msg status_sealed "$url")"
  fi
}

# ---------- images ----------
cmd_status_images() {
  local ver src="" kv sig prov mark
  [ "$CX_STATUS_KIND" = package ] || return 0
  ver=$(cx_state_get current.verification)
  [ -n "$ver" ] || return 0
  for kv in $(cx_state_get current.image_source); do
    [ "${kv%%=*}" = backend ] && src=${kv#*=}
  done
  case $src in
    local) src=$(cx_msg status_src_local) ;;
    offline) src=$(cx_msg status_src_offline) ;;
    build) src=$(cx_msg status_src_build) ;;
    *) src=$(cx_img_label "$src/") ;;
  esac
  sig=${ver#*signature=} sig=${sig%% *}
  prov=${ver#*provenance=} prov=${prov%% *}
  cmd_status_section images
  # cx_trust_summary describes the recorded verification result.
  # shellcheck disable=SC2034
  CX_TRUST_SIG=$sig CX_TRUST_PROV=$prov
  mark=WARN
  [ "$sig" != ok ] || [ "$prov" != ok ] || mark=OK
  cmd_status_line "$mark" "$(cx_msg status_images "$src" "$(cx_trust_summary)")" keep
}

# ---------- backup ----------
cmd_status_backup() {
  local taken kind id days what when mark=OK size
  cmd_status_section backup
  taken=$(cx_state_get last_backup.taken_at)
  if [ -z "$taken" ]; then
    cmd_status_line WARN "$(cx_msg status_backup_none)"
    return 0
  fi
  kind=$(cx_state_get last_backup.kind)
  id=$(cx_state_get last_backup.id)
  if [ "$kind" = external ]; then
    what=$(cx_msg status_backup_external)
  elif [ -n "$id" ] && [ "$id" = "$(cx_state_get last_upgrade.backup_id)" ]; then
    what=$(cx_msg status_backup_upgrade)
  else
    what=$(cx_msg status_backup_script)
  fi
  days=$(cmd_status_days_ago "$taken")
  case $days in
    "") when="" ;;
    0) when=$(cx_msg status_days_0) ;;
    1) when=$(cx_msg status_days_1) ;;
    *) when=$(cx_msg status_days_n "$days") ;;
  esac
  [ -z "$days" ] || [ "$days" -le "$CX_STATUS_BACKUP_DAYS" ] || mark=WARN
  cmd_status_line "$mark" "$(cx_msg status_backup "$(cmd_status_minute "$taken")" "$what" "${when:-?}")"
  if [ "$kind" = external ]; then
    cmd_status_under "$(cx_state_get last_backup.external_ref)"
  else
    size=$(cx_state_get last_backup.size_bytes)
    cmd_status_under "$CX_ROOT/$(cx_state_get last_backup.dir)/${size:+    $(cmd_status_gb "$size")}"
  fi
}

# ---------- last upgrade ----------
cmd_status_upgrade() {
  local res from to log pkg
  res=$(cx_state_get last_upgrade.result)
  [ -n "$res" ] || return 0
  from=$(cx_state_get last_upgrade.from) to=$(cx_state_get last_upgrade.to)
  cmd_status_section upgrade
  case $res in
    succeeded)
      cmd_status_line OK "$(cx_msg status_upgrade_ok "$from" "$to" "$(cmd_status_minute "$(cx_state_get last_upgrade.finished_at)")")"
      ;;
    failed)
      cmd_status_line FAIL "$(cx_msg status_upgrade_failed "$from" "$to" "$(cx_state_get last_upgrade.step)" \
        "$(cmd_status_minute "$(cx_state_get last_upgrade.finished_at)")")"
      ;;
    *) cmd_status_line WARN "$(cx_msg status_upgrade_unfinished "$from" "$to" "$(cx_state_get last_upgrade.step)")" ;;
  esac
  pkg=$(cx_state_get last_upgrade.package_verification)
  case $pkg in
    *signature=mismatch*) cmd_status_line WARN "$(cx_msg status_pkg_sig_mismatch)" ;;
    *signature=skip-*) cmd_status_line WARN "$(cx_msg status_pkg_sig_unverified)" ;;
  esac
  [ "$res" != succeeded ] || return 0
  log=$(cx_state_get last_upgrade.log)
  [ -z "$log" ] || cmd_status_under "$CX_ROOT/$log"
}

# ---------- disk ----------
cmd_status_disk() {
  local data free mark=OK
  data=$(cmd_status_data_path)
  free=$(cx_free_bytes "$CX_ROOT")
  [ "${free:-0}" -ge $((CX_STATUS_MIN_FREE * CX_GIB)) ] || mark=WARN
  cmd_status_section disk
  cmd_status_line "$mark" "$(cx_msg status_disk "$(cmd_status_gb "$(cmd_status_du "$data")")" \
    "$(cmd_status_gb "$(cmd_status_du "$CX_ROOT/backups")")" "$(cmd_status_gb "${free:-0}")")"
}

# ---------- reminders ----------
cmd_status_reminders() {
  local out rec mode
  out=$(
    if [ -e "$CX_ROOT/.env" ] && [ ! -r "$CX_ROOT/.env" ]; then
      cmd_status_line SKIP "$(cx_msg status_env_unreadable)"
    elif [ -n "$(cmd_status_env ADMIN_INITIAL_PASSWORD)" ]; then
      cmd_status_line WARN "$(cx_msg status_remind_password)"
    fi
    if [ "$CX_STATUS_KIND" != none ]; then
      rec=$(cmd_status_data_path)/recordings
      mode=$(stat -c '%u:%g %a' -- "$rec" 2>/dev/null) || mode="?"
      if [ "$mode" != "$CX_RECORDINGS_MODE" ]; then
        cmd_status_line WARN "$(cx_msg status_remind_recordings "$rec" "$mode" "$CX_RECORDINGS_MODE")"
        cx_cmd "sudo chown 1000:0 $rec && sudo chmod 2770 $rec"
      fi
    fi
    if [ "$(cx_state_get load.result)" = in_progress ]; then
      cmd_status_line WARN "$(cx_msg status_load_unfinished "$(cx_state_get load.step)")"
      cx_recovery_hint load
    fi
  )
  [ -n "$out" ] || return 0
  [[ $out != *'[WARN]'* ]] || CX_STATUS_WARNED=1
  cmd_status_section reminders
  printf '%s\n' "$out"
}

cmd_status() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_state_load "$CX_ROOT/state.json"
  CX_STATUS_NOW=$(cx_now)
  printf '%s\n\n' "$(cx_msg status_title "$CX_ROOT" "$(date -d "@$CX_STATUS_NOW" '+%Y-%m-%d %H:%M')")"
  cmd_status_version
  cmd_status_services
  cmd_status_images
  cmd_status_backup
  cmd_status_upgrade
  cmd_status_disk
  cmd_status_reminders
  [ "$CX_STATUS_WARNED" = 0 ] || exit "$CX_EXIT_WARN"
}
