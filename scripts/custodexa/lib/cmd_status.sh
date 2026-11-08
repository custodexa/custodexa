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
# The deployment form section prints its messages line by line as written (each template line is
# at most 73 columns, the message rule); a line only breaks when a value put into it makes it wider
# than an 80-column terminal holds after the 9 columns of indent and mark.
readonly CX_STATUS_FORM_MAX=71
readonly CX_STATUS_BACKUP_DAYS=30 # an older latest backup is a warning
readonly CX_STATUS_MIN_FREE=5     # GB free on the deployment's file system, as install requires
readonly CX_STATUS_SERVICES="postgres guacd backend frontend tls-init tls-proxy" # container names
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
# cmd_status_form_line <mark> <text>: a line of the deployment form section. Each line of the text
# stays as written while it fits CX_STATUS_FORM_MAX; a wider one that ends in a .env line
# ("…：KEY=value", "…: KEY=value") breaks after that colon, so the .env line stands whole on the
# next line; any other wider line breaks between words.
cmd_status_form_line() {
  local line out="" sep="" re='^(.*)(：|: )([A-Z_]+=.*)$'
  case $1 in OK | SKIP) ;; *) CX_STATUS_WARNED=1 ;; esac
  while IFS= read -r line; do
    if [ "$(cx_width "$line")" -gt "$CX_STATUS_FORM_MAX" ]; then
      if [[ $line =~ $re ]]; then
        line=${BASH_REMATCH[1]}${BASH_REMATCH[2]% }$'\n'${BASH_REMATCH[3]}
      else
        line=$(cx_wrap "$CX_STATUS_FORM_MAX" "$line")
      fi
    fi
    out+=$sep$line
    sep=$'\n'
  done <<<"$2"
  cx_line "$1" "$out" | sed 's/^/  /'
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

# ---------- deployment form ----------
# The form the deployment runs in, then whatever in .env says otherwise. Read only: the entries that
# change the deployment refuse (lib/form_guard.sh); status only says which of them would.
cmd_status_form_text() { # the one line: database; web entry
  local env=$CX_ROOT/.env db web host port hp sw="" line
  sw=$(cx_state_get current.overlays)
  if [[ " $sw " == *" external-database "* ]]; then
    host=$(cx_state_get current.external_db_host)
    port=$(cx_state_get current.external_db_port)
    [ -n "$host" ] || host=$(cx_form_db_host "$env")
    [ -n "$port" ] || port=$(cx_form_trim "$(cx_env_get "$env" EXTERNAL_DB_PORT)")
    db=$(cx_msg status_form_db_external "$host:${port:-5432}")
  else
    db=$(cx_msg status_form_db_builtin)
  fi
  if [[ " $sw " == *" external-ingress "* ]]; then
    hp=$(cx_form_trim "$(cx_env_get "$env" HTTP_PORT)")
    web=$(cx_msg status_form_web_own "${hp:-80}")
  else
    hp=$(cx_form_trim "$(cx_env_get "$env" TLS_HTTPS_PORT)")
    port=$(cx_form_trim "$(cx_env_get "$env" TLS_HTTP_PORT)")
    web=$(cx_msg status_form_web_builtin "${hp:-443}" "${port:-80}")
  fi
  line=$(cx_msg status_form_join "$db" "$web")
  if [ "$(cx_width "$line")" -gt "$CX_STATUS_WRAP" ]; then
    line=$(cx_msg status_form_join "$db" $'\n'"$web")
    line=${line//" "$'\n'/$'\n'}
  fi
  printf '%s' "$line"
}

# cmd_status_form_warn: print the WARN lines for what .env says against what runs (none when they
# agree). Returns 1 when something was printed.
cmd_status_form_warn() {
  local env=$CX_ROOT/.env words host sw tls s_db=0 s_ing=0 i_db=0 i_ing=0 rec port
  [ -r "$env" ] || return 0
  sw=$(cx_state_get current.overlays)
  [[ " $sw " != *" external-database "* ]] || s_db=1
  [[ " $sw " != *" external-ingress "* ]] || s_ing=1
  tls=$(cx_form_tls_mode "$env")
  if ! words=$(cx_form_derive "$env"); then
    cmd_status_form_line WARN "$(cx_msg status_form_bad_tls "$tls")"
    return 1
  fi
  host=$(cx_form_db_host "$env")
  if [ -n "$host" ] && ! cx_form_check_host "$host"; then
    cmd_status_form_line WARN "$(cx_msg status_form_bad_host "$host")"
    return 1
  fi
  [[ " $words " != *" external-database "* ]] || i_db=1
  [[ " $words " != *" external-ingress "* ]] || i_ing=1
  if [ "$s_db" = 0 ] && [ "$i_db" = 1 ]; then
    cmd_status_form_line WARN "$(cx_msg status_form_db_added "$host")"
    return 1
  fi
  if [ "$s_db" = 1 ] && [ "$i_db" = 0 ]; then
    rec=$(cx_state_get current.external_db_host)
    if [ -n "$rec" ]; then
      port=$(cx_state_get current.external_db_port)
      cmd_status_form_line WARN "$(cx_msg status_form_db_emptied "$rec:${port:-5432}" "$rec")"
    else
      rec=$(cx_msg fm_e3_placeholder)
      cmd_status_form_line WARN "$(cx_msg status_form_db_emptied "$rec" "$rec")"
    fi
    return 1
  fi
  if [ "$s_ing" != "$i_ing" ]; then
    # The old notation of an external ingress on an older layout is the upgrade's to convert.
    if [ "$s_ing" = 1 ] && { [ "$(cx_form_layout "$CX_ROOT/current")" = overlays ] || cx_fg_pending; }; then
      return 0
    fi
    [ -n "$tls" ] || tls=selfsigned
    if [ "$s_ing" = 1 ]; then
      cmd_status_form_line WARN "$(cx_msg status_form_tls_changed "$tls" "$(cx_msg fm_e4_now_own)" external)"
    else
      rec=$(cx_state_get current.tls_mode)
      [ -n "$rec" ] && [ "$rec" != external ] || rec=selfsigned
      cmd_status_form_line WARN "$(cx_msg status_form_tls_changed "$tls" "$(cx_msg fm_e4_now_builtin)" "$rec")"
    fi
    return 1
  fi
}

cmd_status_form() {
  [ "$CX_STATUS_KIND" = package ] || return 0
  cmd_status_section form
  cmd_status_form_line OK "$(cmd_status_form_text)"
  cmd_status_form_warn || true
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

# cmd_status_backup_source <kind> <id>: where the latest backup came from, by what state.json
# records. An own backup is only ever recorded by an upgrade. The upgrade saves the id of its
# backup with the backup's record (last_upgrade.backup_id); without it (state.json of an earlier
# release) the path the upgrade recorded as its backup is compared with the latest backup's (its
# file, else its folder). Anything else is not known: never guessed as a backup run.
cmd_status_backup_source() {
  local kind=$1 id=$2 bid path mine
  if [ "$kind" = external ]; then
    cx_msg status_backup_external
    return
  fi
  bid=$(cx_state_get last_upgrade.backup_id)
  if [ -n "$bid" ]; then
    if [ "$id" = "$bid" ]; then cx_msg status_backup_upgrade; else cx_msg status_backup_script; fi
    return
  fi
  if [ -z "$(cx_state_get last_upgrade.result)" ]; then
    cx_msg status_backup_script
    return
  fi
  path=$(cx_state_get last_upgrade.backup)
  mine=$(cx_state_get last_backup.file)
  [ -n "$mine" ] || mine=$(cx_state_get last_backup.dir)
  if [ -n "$path" ] && [ "$path" = "$mine" ]; then
    cx_msg status_backup_upgrade
  else
    cx_msg status_backup_unrecorded
  fi
}

cmd_status_backup() {
  local taken kind id days what when mark=OK size file line
  cmd_status_section backup
  taken=$(cx_state_get last_backup.taken_at)
  if [ -z "$taken" ]; then
    cmd_status_line WARN "$(cx_msg status_backup_none)"
    return 0
  fi
  kind=$(cx_state_get last_backup.kind)
  id=$(cx_state_get last_backup.id)
  what=$(cmd_status_backup_source "$kind" "$id")
  days=$(cmd_status_days_ago "$taken")
  case $days in
    "") when="" ;;
    0) when=$(cx_msg status_days_0) ;;
    1) when=$(cx_msg status_days_1) ;;
    *) when=$(cx_msg status_days_n "$days") ;;
  esac
  [ -z "$days" ] || [ "$days" -le "$CX_STATUS_BACKUP_DAYS" ] || mark=WARN
  cmd_status_line "$mark" "$(cx_msg status_backup "$(cmd_status_minute "$taken")" "$what" "${when:-?}")"
  size=$(cx_state_get last_backup.size_bytes)
  file=$(cx_state_get last_backup.file)
  if [ "$kind" = external ]; then
    cmd_status_under "$(cx_state_get last_backup.external_ref)"
  elif [ -n "$file" ]; then
    line="$CX_ROOT/$file${size:+    $(cx_size_human "$size")}"
    [ "$(cx_state_get last_backup.encrypted)" != true ] || line=$(cx_msg status_backup_encrypted "$line")
    cmd_status_under "$line"
  else
    cmd_status_under "$CX_ROOT/$(cx_state_get last_backup.dir)/${size:+    $(cx_size_human "$size")}"
  fi
}

# ---------- last upgrade ----------
cmd_status_upgrade() {
  local res from to log pkg at line mark="" settled=""
  res=$(cx_state_get last_upgrade.result)
  [ -n "$res" ] || return 0
  from=$(cx_state_get last_upgrade.from) to=$(cx_state_get last_upgrade.to)
  cmd_status_section upgrade
  case $res in
    rolled_back)
      # The version gone back to is given before and after the time: each language uses the one
      # that suits its word order (%.0s skips the other).
      cmd_status_line OK "$(cx_msg status_upgrade_rolled_back "$from" "$to" "$from" \
        "$(cmd_status_minute "$(cx_state_get last_upgrade.rolled_back_at)")" "$from")"
      ;;
    succeeded)
      cmd_status_line OK "$(cx_msg status_upgrade_ok "$from" "$to" "$(cmd_status_minute "$(cx_state_get last_upgrade.finished_at)")")"
      ;;
    failed)
      at=$(cx_state_get last_upgrade.finished_at)
      [ -n "$at" ] || at=$(cx_state_get last_upgrade.handed_at)
      pkg=status_upgrade_failed
      [ "$(cx_state_get last_upgrade.handed_to)" != restore ] || pkg=status_upgrade_failed_handed
      # A restore that finished settled it (lib/run.sh): the failure is shown as it was, no longer
      # as a fault, with the restore that dealt with it under the log path.
      mark=FAIL
      [ "$(cx_state_get last_upgrade.settled_by)" != restore ] || mark=OK settled=$(cx_state_get last_upgrade.settled_at)
      cmd_status_line "$mark" "$(cx_msg "$pkg" "$from" "$to" "$(cx_state_get last_upgrade.step)" \
        "$(cmd_status_minute "$at")")"
      ;;
    *) cmd_status_line WARN "$(cx_msg status_upgrade_unfinished "$from" "$to" "$(cx_state_get last_upgrade.step)")" ;;
  esac
  # The log path right under the line that ends with its label.
  log=$(cx_state_get last_upgrade.log)
  [ "$res" = succeeded ] || [ -z "$log" ] || cmd_status_under "$CX_ROOT/$log"
  if [ "$mark" = OK ]; then
    while IFS= read -r line; do
      cmd_status_under "$line"
    done <<<"$(cmd_status_text "$(cx_msg status_upgrade_settled "$(cmd_status_minute "$settled")")")"
  fi
  case $(cx_state_get last_rollback.result) in
    in_progress)
      if [ "$(cx_state_get last_rollback.direction)" = revert ]; then
        cmd_status_line WARN "$(cx_msg status_rollback_reverting "$(cx_state_get last_rollback.target)" \
          "$(cx_state_get last_rollback.step)")"
      else
        cmd_status_line WARN "$(cx_msg status_rollback_unfinished "$(cx_state_get last_rollback.from)" \
          "$(cx_state_get last_rollback.to)" "$(cx_state_get last_rollback.step)")"
      fi
      cx_recovery_hint rollback
      ;;
    reverted) cmd_status_line OK "$(cx_msg status_rollback_reverted "$(cx_state_get last_rollback.from)")" ;;
    refused)
      pkg=status_rollback_refused
      [ "$(cx_state_get last_rollback.refusal_reason)" != unreadable ] || pkg=status_rollback_unreadable
      cmd_status_line WARN "$(cx_msg "$pkg" "$(cx_state_get last_rollback.from)" "$(cx_state_get current.version)")"
      ;;
  esac
  pkg=$(cx_state_get last_upgrade.package_verification)
  case $pkg in
    *signature=mismatch*) cmd_status_line WARN "$(cx_msg status_pkg_sig_mismatch)" ;;
    *signature=skip-*) cmd_status_line WARN "$(cx_msg status_pkg_sig_unverified)" ;;
  esac
}

# ---------- disk ----------
cmd_status_disk() {
  local data free mark=OK
  data=$(cmd_status_data_path)
  free=$(cx_free_bytes "$CX_ROOT")
  [ "${free:-0}" -ge $((CX_STATUS_MIN_FREE * CX_GIB)) ] || mark=WARN
  cmd_status_section disk
  cmd_status_line "$mark" "$(cx_msg status_disk "$(cx_size_human "$(cmd_status_du "$data")")" \
    "$(cx_size_human "$(cmd_status_du "$CX_ROOT/backups")")" "$(cx_size_human "${free:-0}")")"
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

# ---------- database ----------
# The bundled database's major, where its data is, whether data checksums are on, and the old folders
# kept next to it (rolled-back ones are listed like any other, with no WARN). An unfinished removal
# is the one thing here that warns. Read only: the checksums are asked of the running container.
cmd_status_database() {
  local ov host port data d major size sums n p kind bytes w
  [ "$CX_STATUS_KIND" = package ] || return 0
  ov=$(cx_state_get current.overlays)
  if [[ " $ov " == *" external-database "* ]]; then
    host=$(cx_state_get current.external_db_host)
    port=$(cx_state_get current.external_db_port)
    [ -n "$host" ] || host=$(cx_form_db_host "$CX_ROOT/.env")
    cmd_status_section db
    cmd_status_line OK "$(cx_msg status_db_external "$host:${port:-5432}")" keep
    return 0
  fi
  cx_dbo_current || return 0
  data=$(cx_dbo_data_path)
  d=$data/$CX_DBO_DIR${CX_DBO_PGDATA:+/$CX_DBO_PGDATA}
  major=$(cx_pgm_dir_major "$data" "$CX_DBO_DIR" "$CX_DBO_PGDATA") || major=""
  cx_dbo_list "$data"
  # A release from before the bundled database had a version of its own says nothing here.
  if [ -z "$major" ] && [ "${#CX_DBO_ROWS[@]}" -eq 0 ] && ! grep -q '"bundled_db"' "$CX_ROOT/current/MANIFEST.json" 2>/dev/null; then
    return 0
  fi
  cmd_status_section db
  if [ -z "$major" ]; then
    cmd_status_line WARN "$(cx_msg status_db_no_version "$d")" keep
  else
    size=$(cx_size_human "$(cx_dbo_du "$data/$CX_DBO_DIR")")
    cmd_status_line OK "$(cx_msg status_db_main "$major" "$data/$CX_DBO_DIR" "$size")" keep
    sums=$(timeout 10 docker exec custodexa-postgres psql -U "$(cmd_status_env DB_USER)" -d "$(cmd_status_env DB_NAME)" \
      -AtX -c 'SHOW data_checksums' 2>/dev/null | head -n 1) || sums=""
    case $sums in
      on) cmd_status_under "$(cx_msg status_db_checksums_on)" ;;
      off) cmd_status_under "$(cx_msg status_db_checksums_off)" ;;
    esac
  fi
  n=0
  for p in "${CX_DBO_ROWS[@]}"; do [[ $p == removing\|* ]] || n=$((n + 1)); done
  if [ "$n" -gt 0 ]; then
    w=$(cx_dbo_size_width)
    printf '  %s\n' "$(cx_msg status_db_old_head "$n")"
    for p in "${CX_DBO_ROWS[@]}"; do
      [[ $p != removing\|* ]] || continue
      IFS='|' read -r kind p major bytes <<<"$p"
      printf '         %s\n             PostgreSQL %s    %s    %s\n' "$p" "$(cx_dbo_major_text "$major")" \
        "$(cx_dbo_size_text "$bytes" "$w")" "$(cx_dbo_kind_text "$kind")"
    done
  fi
  for p in "${CX_DBO_ROWS[@]}"; do
    [[ $p == removing\|* ]] || continue
    IFS='|' read -r _ p _ bytes <<<"$p"
    CX_STATUS_WARNED=1
    cx_line WARN "$(cx_msg status_db_removing "$p" "$(cx_size_human "$bytes")" "$CX_ROOT")" | sed 's/^/  /'
  done
}

# shellcheck source=lib/restore_status.sh
. "${BASH_SOURCE[0]%/*}/restore_status.sh"

cmd_status() {
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_state_load "$CX_ROOT/state.json"
  CX_STATUS_NOW=$(cx_now)
  printf '%s\n\n' "$(cx_msg status_title "$CX_ROOT" "$(date -d "@$CX_STATUS_NOW" '+%Y-%m-%d %H:%M')")"
  cmd_status_version
  cmd_status_form
  cmd_status_database
  cmd_status_services
  cmd_status_images
  cmd_status_backup
  cmd_status_upgrade
  cmd_status_restore
  cmd_status_disk
  cmd_status_reminders
  [ "$CX_STATUS_WARNED" = 0 ] || exit "$CX_EXIT_WARN"
}
