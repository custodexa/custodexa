# shellcheck shell=bash
# CX_CV_* are read by the upgrade steps and the tests.
# shellcheck disable=SC2034
# The first conversion of a git clone deployment into the package layout. It is meant for a
# deployment made from an unchanged clone of the public tree, and runs once:
#   before the preview  the work tree must be clean: `git status --porcelain` lists nothing apart
#                       from what this script writes itself (backups/, the lock, .incoming-*);
#                       otherwise the upgrade is refused with what git lists
#   step 8              (drained, stopped and backed up by then)
#                       .env copied into the backup folder; the report exports the old backend keeps
#                       inside its container copied into <data>/exports; the old containers removed
#                       with the old project and files; .git and every top-level entry git tracks moved into
#                       releases/<old version>/; .env rewritten (absolute host paths, the new
#                       COMPOSE_FILE and COMPOSE_PROJECT_NAME); the new release copied into
#                       releases/<new version>/; state.json written
# .env, tls/, the data folder, backups/ and logs/ stay where they are. A failure stops with the
# commands that put the clone back and start the old version; nothing is undone on its own.

readonly CX_CV_KEEP=".env tls data backups logs releases current custodexa.sh state.json state.json.prev .custodexa.lock"
readonly CX_CV_EXPORTS=/var/lib/custodexa/exports # EXPORT_ARTIFACT_PATH in the backend container

# The .env rewrites; new "#" = commented out. RAW is the commented-out line a key without a setting
# line gets written on (cx_env_set uncomments the first one), else empty.
CX_CV_KEYS=() CX_CV_LINES=() CX_CV_OLD=() CX_CV_NEW=() CX_CV_RAW=()
CX_CV_OVERLAYS="" CX_CV_DROPPED="" CX_CV_ENV_BAK="" CX_CV_REWRITES="" CX_CV_STAGE=0

# Read-only: no optional index refresh, and a clone owned by another account is still read.
cx_cv_git() { git --no-optional-locks -c safe.directory="$CX_ROOT" -C "$CX_ROOT" "$@"; }

# cx_cv_dirty: what git lists as changed or untracked, less what this script writes itself.
cx_cv_dirty() {
  local out line
  out=$(cx_cv_git status --porcelain 2>/dev/null) || return 2
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case ${line:3} in
      backups/ | backups/* | .custodexa.lock | .incoming-*) continue ;;
    esac
    printf '%s\n' "$line"
  done <<<"$out"
}

# cx_cv_check: before the preview. A refusal changes nothing.
cx_cv_check() {
  local list rc=0
  if ! command -v git >/dev/null 2>&1; then
    cx_line FAIL "$(cx_msg cv_no_git "$CX_ROOT")"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
  list=$(cx_cv_dirty) || rc=$?
  if [ "$rc" -ne 0 ]; then
    cx_line FAIL "$(cx_msg cv_git_failed "$CX_ROOT")"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return "$CX_EXIT_FAILED"
  fi
  [ -n "$list" ] || return 0
  cx_line FAIL "$(cx_msg cv_dirty "$CX_ROOT")"
  printf '%s\n' "$list" | sed 's/^/    /'
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
  return "$CX_EXIT_REFUSED"
}

# cx_cv_abs <value>: a host path from .env made absolute against the root.
cx_cv_abs() {
  case $1 in
    /*) printf '%s' "$1" ;;
    *) readlink -m -- "$CX_ROOT/${1#./}" ;;
  esac
}

cx_cv_add() { # <key> <old value> <new value>
  local n raw=""
  n=$(grep -n "^$1=" "$CX_ROOT/.env" 2>/dev/null | tail -n 1 | cut -d: -f1)
  if [ -z "$n" ]; then
    raw=$(grep -En "^# *$1=" "$CX_ROOT/.env" 2>/dev/null | head -n 1)
    n=${raw%%:*} raw=${raw#*:}
  fi
  CX_CV_KEYS+=("$1") CX_CV_OLD+=("$2") CX_CV_NEW+=("$3") CX_CV_LINES+=("$n") CX_CV_RAW+=("$raw")
}

# cx_cv_plan: the .env rewrites. Only the keys compose puts into host paths (DATA_PATH,
# TLS_NGINX_TEMPLATE), plus COMPOSE_FILE (the old files mapped onto the release's) and
# COMPOSE_PROJECT_NAME. A template that is a product file is commented out (the release has its own).
cx_cv_plan() {
  local env=$CX_ROOT/.env v p cf f new=current/compose.yml ing=0 ext=0
  local -a list=()
  CX_CV_KEYS=() CX_CV_LINES=() CX_CV_OLD=() CX_CV_NEW=() CX_CV_RAW=() CX_CV_OVERLAYS="" CX_CV_DROPPED=""
  v=$(cx_env_get "$env" DATA_PATH)
  case $v in /*) ;; *) cx_cv_add DATA_PATH "$v" "$(cx_cv_abs "${v:-./data}")" ;; esac
  v=$(cx_env_get "$env" TLS_NGINX_TEMPLATE)
  if [ -n "$v" ]; then
    p=$(cx_cv_abs "$v")
    if [[ $p == "$CX_ROOT"/* ]] && cx_cv_git ls-files --error-unmatch -- "${p#"$CX_ROOT"/}" >/dev/null 2>&1; then
      cx_cv_add TLS_NGINX_TEMPLATE "$v" "#"
    elif [ "$p" != "$v" ]; then
      cx_cv_add TLS_NGINX_TEMPLATE "$v" "$p"
    fi
  fi
  cf=$(cx_env_get "$env" COMPOSE_FILE)
  IFS=: read -ra list <<<"${cf:-docker-compose.yml}"
  for f in "${list[@]}"; do
    case ${f##*/} in
      "" | docker-compose.yml) ;;
      docker-compose.external-ingress.yml) ing=1 ;;
      docker-compose.external-database.yml) ext=1 ;;
      *) CX_CV_DROPPED+="${CX_CV_DROPPED:+ }$f" ;;
    esac
  done
  if [ "$ing" = 1 ]; then new+=:current/compose.external-ingress.yml CX_CV_OVERLAYS=external-ingress; fi
  if [ "$ext" = 1 ]; then
    new+=:current/compose.external-database.yml
    CX_CV_OVERLAYS+="${CX_CV_OVERLAYS:+ }external-database"
  fi
  [ "$cf" = "$new" ] || cx_cv_add COMPOSE_FILE "$cf" "$new"
  v=$(cx_env_get "$env" COMPOSE_PROJECT_NAME)
  [ "$v" = "$CX_PROJECT" ] || cx_cv_add COMPOSE_PROJECT_NAME "$v" "$CX_PROJECT"
}

# ---------- the preview ----------

cx_cv_preview() {
  local i label added="" n=0 low high m
  printf '\n%s\n' "$(cx_msg cv_will)"
  printf '%s\n' "$(cx_msg cv_will_1)" "$(cx_msg cv_will_2 "${CX_UP_OLD_FILES%% *}")"
  if [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ]; then
    printf '%s\n' "$(cx_msg cv_will_3_external)"
    m=1
  else
    printf '%s\n' "$(cx_msg cv_will_3 "$(cx_bk_gb "$CX_BK_NEED")" "$(cx_bk_gb "$CX_BK_FREE")")"
    m=$(cx_bk_minutes)
  fi
  printf '%s\n' "$(cx_msg cv_will_4)" "$(cx_msg cv_will_5 "$CX_UP_TARGET")"
  printf '\n%s\n' "$(cx_msg cv_dir)"
  printf '%s\n' "$(cx_msg cv_stays)" "$(cx_msg cv_moves "$CX_UP_CURRENT")" "$(cx_msg cv_copies)"
  label=$(cx_msg cv_env_label)
  for i in "${!CX_CV_KEYS[@]}"; do
    if [ -z "${CX_CV_LINES[i]}" ]; then
      added+="${added:+$(cx_msg cv_env_sep)}${CX_CV_KEYS[i]}"
      n=$((n + 1))
      continue
    fi
    if [ -n "${CX_CV_RAW[i]}" ]; then
      printf '%s%s\n' "$label" "$(cx_msg cv_env_row_raw "${CX_CV_LINES[i]}" "${CX_CV_RAW[i]}")"
    else
      printf '%s%s\n' "$label" "$(cx_msg cv_env_row "${CX_CV_LINES[i]}" "${CX_CV_KEYS[i]}" "${CX_CV_OLD[i]}")"
    fi
    if [ "${CX_CV_NEW[i]}" = "#" ]; then
      printf '%s\n' "$(cx_msg cv_env_to_comment)"
    else
      printf '%s\n' "$(cx_msg cv_env_to "${CX_CV_KEYS[i]}" "${CX_CV_NEW[i]}")"
    fi
    label=$(cx_msg cv_env_indent)
  done
  if [ "$n" -gt 0 ]; then
    case $n in
      1 | 2) printf '%s%s\n' "$label" "$(cx_msg "cv_env_add_$n" "$added")" ;;
      *) printf '%s%s\n' "$label" "$(cx_msg cv_env_add_n "$n" "$added")" ;;
    esac
    label=$(cx_msg cv_env_indent)
  fi
  printf '%s%s\n' "$label" "$(cx_msg cv_env_saved)"
  for i in $CX_CV_DROPPED; do cx_up_par "$(cx_line WARN "$(cx_msg cv_compose_dropped "$i")")"; done
  low=$((m + 3)) high=$(((m + 3) * 2))
  printf '\n%s\n' "$(cx_msg up_know)"
  printf '%s\n' "$(cx_msg cv_know_pause "$low" "$high")"
  case $CX_UP_PRE_PENDING in
    0) ;;
    "") [ "$CX_UP_PRE_EXTERNAL_DB" = 1 ] || printf '%s\n' "$(cx_msg up_know_mig_unknown)" ;;
    *) printf '%s\n' "$(cx_msg cv_know_mig "$CX_UP_CURRENT")" ;;
  esac
  printf '%s\n' "$(cx_msg cv_know_manage "$CX_ROOT" "$CX_ROOT")"
}

# ---------- step 8 ----------

# cx_cv_exports: the report and evidence exports the old backend keeps inside its container (its
# compose file mounts no folder for them) are copied into <data>/exports, where the new version
# mounts that folder, before `down` removes the container: the upgrade guide's manual copy, on the
# old project and files. The folder keeps the backend's modes (0700, the files as they were).
# Nothing to copy when that folder is already mounted from the host, missing or empty; any other
# failure stops step 8 before anything is removed.
cx_cv_exports() {
  local dest=${CX_BK_DATA%/}/exports made=0 out count
  if docker inspect --format '{{range .Mounts}}{{println .Destination}}{{end}}' custodexa-backend 2>/dev/null \
    | grep -qx "$CX_CV_EXPORTS"; then
    cx_log EXPORTS "already on the host: nothing to copy"
    return 0
  fi
  if [ ! -d "$dest" ]; then
    (umask 077 && mkdir -p -- "$dest") || return 1
    made=1
  fi
  if ! out=$(cx_up_compose cp "backend:$CX_CV_EXPORTS/." "$dest/" 2>&1); then
    cx_log OUT "$out"
    [ "$made" = 0 ] || rmdir -- "$dest" 2>/dev/null
    case $out in *"Could not find the file"*) ;; *) return 1 ;; esac
    cx_log EXPORTS "no export folder in the old container: nothing to copy"
    return 0
  fi
  count=$(find "$dest" -type f | wc -l)
  if [ "$count" -eq 0 ] && [ "$made" = 1 ]; then
    rmdir -- "$dest"
    cx_log EXPORTS "the export folder in the old container is empty: nothing to copy"
    return 0
  fi
  chmod 0700 "$dest" || return 1
  cx_log EXPORTS "copied $count files to $dest"
}

# cx_cv_tops: the top-level entries to move, .git first. Read before .git moves.
cx_cv_tops() {
  local t
  printf '.git\n'
  cx_cv_git ls-files -z | tr '\0' '\n' | cut -d/ -f1 | sort -u | while IFS= read -r t; do
    [ -n "$t" ] || continue
    case " $CX_CV_KEEP " in *" $t "*) continue ;; esac
    case $t in .incoming-*) continue ;; esac
    # Never the data folder, wherever DATA_PATH points.
    case ${CX_BK_DATA%/}/ in "$CX_ROOT/$t"/*) continue ;; esac
    [ -e "$CX_ROOT/$t" ] || [ -L "$CX_ROOT/$t" ] || continue
    printf '%s\n' "$t"
  done
}

# cx_cv_env_apply: the planned rewrites, each logged with its line, old and new value.
cx_cv_env_apply() {
  local env=$CX_ROOT/.env i k n tmp new
  CX_CV_REWRITES=""
  for i in "${!CX_CV_KEYS[@]}"; do
    k=${CX_CV_KEYS[i]} new=${CX_CV_NEW[i]}
    if [ "$new" = "#" ]; then
      n=${CX_CV_LINES[i]}
      tmp=$(umask 077 && mktemp "$env.tmp-XXXXXX") || return 1
      awk -v n="$n" 'NR == n {print "# " $0; next} {print}' "$env" >"$tmp" && mv -f -- "$tmp" "$env" || return 1
    else
      cx_env_set "$env" "$k" "$new" || return 1
      n=$(grep -n "^$k=" "$env" | tail -n 1 | cut -d: -f1)
    fi
    cx_log ENV "rewrite $k line $n: \"${CX_CV_OLD[i]}\" -> \"$new\""
    CX_CV_REWRITES+="${CX_CV_REWRITES:+;}$k:$n:${CX_CV_OLD[i]}>$new"
  done
  chmod 600 "$env"
}

# cx_cv_state_init: state.json for the converted deployment: what ran before (the clone, its
# project and files, its image IDs), the backup of step 7 and this upgrade, in progress at step 8.
cx_cv_state_init() {
  local rw=$CX_CV_REWRITES
  cx_state_valid_value "$rw" || rw="see ${CX_LOG_FILE#"$CX_ROOT"/}"
  cx_state_reset
  cx_state_set home "$CX_ROOT"
  cx_state_set compose_project "$CX_PROJECT"
  cx_state_set current.version "$CX_UP_CURRENT"
  cx_state_set current.kind legacy-git-clone
  cx_state_set current.release_dir "releases/$CX_UP_CURRENT"
  cx_state_set current.overlays "$CX_CV_OVERLAYS"
  cx_state_set current.image_ids "$CX_UP_PRE_OLD_IDS"
  cx_state_set conversion.from "$CX_UP_CURRENT"
  cx_state_set conversion.at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set conversion.old_project "$CX_UP_OLD_PROJECT"
  cx_state_set conversion.old_files "$CX_UP_OLD_FILES"
  cx_state_set conversion.env_backup "${CX_CV_ENV_BAK#"$CX_ROOT"/}"
  cx_state_set conversion.env_rewrites "$rw"
  cx_state_set last_upgrade.log "${CX_LOG_FILE#"$CX_ROOT"/}"
  cx_state_set last_upgrade.result in_progress
  cx_state_set last_upgrade.step 8
  cx_state_set last_upgrade.started_at "$CX_UP_STARTED"
  cx_state_set last_upgrade.from "$CX_UP_CURRENT"
  cx_state_set last_upgrade.to "$CX_UP_TARGET"
  if [ "$CX_UP_BACKUP_KIND" = external ]; then
    cx_br_record "${CX_UP_BACKUP_DIR##*/}" || return 1
  else
    cx_bk_record || return 1
  fi
  cx_state_save "$CX_ROOT/state.json" && [ -f "$CX_ROOT/state.json" ]
}

# cx_cv_run <n>: step 8 on a git clone deployment.
cx_cv_run() {
  local n=$1 t0 rel part t
  local -a tops=()
  t0=$(cx_now)
  CX_CV_STAGE=0
  trap 'cx_cv_signal '"$n" INT TERM HUP
  CX_CV_ENV_BAK=$CX_UP_BACKUP_DIR/env-before-convert.bak
  (umask 077 && cp -p -- "$CX_ROOT/.env" "$CX_CV_ENV_BAK") \
    || { cx_cv_failed "$n" "$(cx_msg cv_why_env_copy "$CX_CV_ENV_BAK")"; return 1; }
  CX_CV_STAGE=1
  cx_cv_exports || { cx_cv_failed "$n" "$(cx_msg cv_why_exports)"; return 1; }
  cx_log_run cx_up_compose down >/dev/null 2>&1 || { cx_cv_failed "$n" "$(cx_msg cv_why_down)"; return 1; }
  mapfile -t tops < <(cx_cv_tops)
  cx_log CONVERT "move to releases/$CX_UP_CURRENT: ${tops[*]}"
  CX_CV_STAGE=2
  rel=$CX_ROOT/releases/$CX_UP_CURRENT
  (umask 022 && mkdir -p -- "$rel") || { cx_cv_failed "$n" "$(cx_msg cv_why_move releases/)"; return 1; }
  for t in "${tops[@]}"; do
    cx_log_run mv -- "$CX_ROOT/$t" "$rel/$t" >/dev/null 2>&1 || { cx_cv_failed "$n" "$(cx_msg cv_why_move "$t")"; return 1; }
  done
  cx_cv_env_apply || { cx_cv_failed "$n" "$(cx_msg cv_why_env)"; return 1; }
  part=$CX_ROOT/releases/.$CX_UP_TARGET.partial
  if ! cp -a -- "$CX_DIR" "$part" || ! mv -T -- "$part" "$CX_ROOT/releases/$CX_UP_TARGET"; then
    cx_cv_failed "$n" "$(cx_msg cv_why_copy "$CX_UP_TARGET")"
    return 1
  fi
  cx_cv_state_init || { cx_cv_failed "$n" "$(cx_msg cv_why_state)"; return 1; }
  # From here on it is a package deployment: the release's compose files, this project.
  CX_UP_KIND=package CX_OVERLAYS=$CX_CV_OVERLAYS CX_UP_OLD_HINT=""
  trap 'cx_on_signal' INT TERM HUP
  cx_up_step_line OK "$n" "$(cx_msg cv_step)" "$(cx_duration $(($(cx_now) - t0)))"
}

cx_cv_signal() {
  trap - INT TERM HUP
  cx_log END "result=interrupted step=$1"
  cx_cv_failed "$1" "$(cx_msg cv_why_signal)" >&"${CX_SIGNAL_FD:-2}"
  exit "$CX_EXIT_FAILED"
}

# ---------- a failure, and what to type ----------

cx_cv_failed() { # <n> <reason>
  cx_log FAIL "convert: $2"
  cx_up_step_line FAIL "$1" "$(cx_msg cv_step)"
  printf '\n'
  cx_line FAIL "$(cx_msg cv_fail "$2")"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg up_state_title)")"
  cx_up_bullet "$(cx_msg cv_stopped)"
  cx_up_bullet_backup
  if [ "$CX_CV_STAGE" -lt 2 ]; then
    cx_up_bullet "$(cx_msg cv_dir_same)"
    printf '\n%s\n' "$(cx_up_par "$(cx_msg cv_start_old)")"
  else
    cx_up_bullet "$(cx_msg cv_dir_part)"
    printf '\n'
    cx_cv_revert "$CX_UP_CURRENT" "$CX_CV_ENV_BAK"
    printf '\n%s\n' "$(cx_up_par "$(cx_msg cv_start_old_after)")"
  fi
  cx_cv_up_cmd "$CX_UP_OLD_PROJECT" "$CX_UP_OLD_FILES"
  [ "$CX_BK_KEK" != ui ] || cx_up_par "$(cx_msg cv_unseal)"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg bk_log "$CX_LOG_FILE")")"
}

# cx_cv_revert <old version> <.env copy>: the commands that put the clone back, in order.
cx_cv_revert() {
  local r=$CX_ROOT
  cx_up_par "$(cx_msg cv_revert_title)"
  cx_cmd "sudo find $r/releases/$1 -mindepth 1 -maxdepth 1 \\"
  cx_cmd "  -exec mv -n -t $r {} +"
  cx_cmd "sudo rmdir $r/releases/$1"
  cx_cmd "sudo rm -rf $r/releases $r/state.json \\"
  cx_cmd "  $r/state.json.prev"
  cx_cmd "sudo cp $2 \\"
  cx_cmd "  $r/.env"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg cv_revert_check)")"
  cx_cmd "sudo git -c safe.directory=$r -C $r \\"
  cx_cmd "  status --porcelain"
}

# cx_cv_up_cmd <project> <files>: start the old version with its own project and files.
cx_cv_up_cmd() {
  local f files=""
  for f in $2; do files+="${files:+ }-f $f"; done
  cx_cmd "sudo docker compose -p $1 --project-directory $CX_ROOT \\"
  cx_cmd "  $files up -d"
}

# cx_cv_hint <old version> <.env copy> <project> <files>: the next run after a conversion that
# stopped halfway (from state.json, or found on disk when state.json was not written yet).
cx_cv_hint() {
  cx_up_par "$(cx_msg cv_hint)"
  printf '\n'
  cx_cv_revert "$1" "$2"
  printf '\n%s\n' "$(cx_up_par "$(cx_msg cv_start_old_after)")"
  cx_cv_up_cmd "$3" "$4"
  [ "$(cx_env_get "$CX_ROOT/.env" KEK_PROVIDER)" != ui ] || cx_up_par "$(cx_msg cv_unseal)"
}

# cx_cv_interrupted: no state.json, but a releases/<v>/.git: a conversion stopped halfway. Prints
# the commands and returns 0; returns 1 when there is none.
cx_cv_interrupted() {
  local d old="" bak log line
  for d in "$CX_ROOT"/releases/*/.git; do
    [ -e "$d" ] && old=${d%/.git} && old=${old##*/} && break
  done
  [ -n "$old" ] || return 1
  # shellcheck disable=SC2012 # the names are the script's own timestamps
  bak=$(ls -1t "$CX_ROOT"/backups/*/env-before-convert.bak 2>/dev/null | head -n 1)
  # shellcheck disable=SC2012
  log=$(ls -1t "$CX_ROOT"/logs/upgrade-*.log 2>/dev/null | head -n 1)
  line=$(sed -n 's/^[^ ]* CONVERT project=\([^ ]*\) files=\(.*\)$/\1 \2/p' "${log:-/dev/null}" 2>/dev/null | tail -n 1)
  cx_line FAIL "$(cx_msg cv_interrupted)"
  cx_cv_hint "$old" "${bak:-$CX_ROOT/backups/<ts>/env-before-convert.bak}" "${line%% *}" "${line#* }"
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
}
