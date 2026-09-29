# shellcheck shell=bash
# Host checks for install, run before anything is written. Every check runs and its result is kept;
# nothing is printed while checking. On success the step is one line; on a failure the step lists
# the checks under it, says that nothing was changed, and explains the next move for each failure.

# Lowest Docker Compose accepted. Confirmed on a Linux host with that version before a release.
readonly CX_COMPOSE_MIN=2.0.0
readonly CX_GIB=1073741824
readonly CX_ROOT_FREE_MIN=$((5 * CX_GIB))  # logs, backups staging and settings next to the data
readonly CX_DOCKER_FREE_EXTRA=$((2 * CX_GIB))

declare -ga CX_PRE_MARK=() CX_PRE_TEXT=() CX_PRE_HINT=()
CX_PRE_EXIT=0

cx_pre_add() { # <mark> <text> [hint function and arguments, one string]
  CX_PRE_MARK+=("$1")
  CX_PRE_TEXT+=("$2")
  CX_PRE_HINT+=("${3:-}")
  if [ "$1" = FAIL ] && [ "$CX_PRE_EXIT" -eq 0 ]; then CX_PRE_EXIT=$CX_EXIT_FAILED; fi
}

# cx_version_ge <a> <b>: a >= b for dotted numbers.
cx_version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

cx_arch() {
  case $(uname -m) in
    x86_64 | amd64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) return 1 ;;
  esac
}

# cx_port_holder <port>: who listens on the port ("" when nobody); returns 1 when no tool can tell.
cx_port_holder() {
  local port=$1 out="" name pid holders
  if command -v ss >/dev/null 2>&1; then
    out=$(ss -ltnHp "sport = :$port" 2>/dev/null)
    [ -n "$out" ] || return 0
    local -a who=()
    while read -r name pid; do
      who+=("$(cx_msg pre_holder "$name" "$pid")")
    done < <(printf '%s\n' "$out" | sed -n 's/.*users:(("\([^"]*\)",pid=\([0-9]*\).*/\1 \2/p' | sort -u)
    if [ "${#who[@]}" -eq 0 ]; then
      cx_msg pre_holder_unnamed
      return 0
    fi
    out=$(cx_join "$(cx_msg pre_list_sep)" "${who[@]}")
  elif command -v lsof >/dev/null 2>&1; then
    out=$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $2}' | sort -u |
      while read -r name pid; do cx_msg pre_holder "$name" "$pid"; printf '\n'; done | paste -sd, -)
  else
    return 1
  fi
  # docker-proxy alone does not say whose port it is; name the container too.
  if [[ $out == *docker-proxy* ]]; then
    holders=$(docker ps --filter "publish=$port" --format '{{.Names}}' 2>/dev/null | paste -sd, -)
    [ -z "$holders" ] || out=$(cx_msg pre_holder_container "$out" "$holders")
  fi
  printf '%s' "$out"
}

cx_join() { # <separator> <item>...
  local sep=$1 out=$2
  shift 2
  for x in "$@"; do out+=$sep$x; done
  printf '%s' "$out"
}

# cx_free_bytes <dir>: free bytes on the file system of dir (the nearest existing parent).
cx_free_bytes() {
  local d=$1
  while [ ! -e "$d" ] && [ "$d" != / ]; do d=${d%/*}; d=${d:-/}; done
  df -Pk "$d" 2>/dev/null | awk 'NR==2 {print $4 * 1024}'
}
cx_mount_of() {
  local d=$1
  while [ ! -e "$d" ] && [ "$d" != / ]; do d=${d%/*}; d=${d:-/}; done
  df -Pk "$d" 2>/dev/null | awk 'NR==2 {print $6}'
}
cx_gb_down() { printf '%s' $(($1 / CX_GIB)); }
cx_gb_up() { printf '%s' $((($1 + CX_GIB - 1) / CX_GIB)); }

# cx_preflight <root> <manifest loaded: yes>: fill CX_PRE_* and CX_PRE_EXIT.
cx_preflight() {
  local root=$1 info rc ver dockerdir compose arch
  CX_PRE_MARK=() CX_PRE_TEXT=() CX_PRE_HINT=() CX_PRE_EXIT=0

  # Docker and Compose.
  info=$(docker info --format '{{.ServerVersion}} {{.DockerRootDir}}' 2>/dev/null) && rc=0 || rc=$?
  if [ "$rc" -ne 0 ]; then
    info=$(docker info --format '{{.ServerVersion}}' 2>&1 >/dev/null || true)
    if [[ $info == *"ermission denied"* ]]; then
      cx_pre_add FAIL "$(cx_msg pre_docker_perm)" cx_pre_hint_docker_perm
    else
      cx_pre_add FAIL "$(cx_msg pre_docker_down "$(printf '%s' "$info" | tail -n1 | cut -c1-60)")"
    fi
    dockerdir=""
  else
    ver=${info%% *}
    dockerdir=${info#* }
    compose=$(cx_compose_version) || compose=""
    compose=${compose#v}
    if [ -z "$compose" ]; then
      cx_pre_add FAIL "$(cx_msg pre_compose_missing "$CX_COMPOSE_MIN")"
    elif ! cx_version_ge "$compose" "$CX_COMPOSE_MIN"; then
      cx_pre_add FAIL "$(cx_msg pre_compose_old "$ver" "v$compose" "$CX_COMPOSE_MIN")"
    else
      cx_pre_add OK "$(cx_msg pre_docker_ok "$ver" "v$compose")"
    fi
  fi

  if arch=$(cx_arch); then
    cx_pre_add OK "$(cx_msg pre_arch_ok "$arch")"
  else
    cx_pre_add FAIL "$(cx_msg pre_arch_bad "$(uname -m)")"
  fi

  cx_preflight_ports "$root"

  if [ -n "$dockerdir" ] && [ -n "$arch" ]; then
    cx_preflight_disk "$root" "$dockerdir" "$(cx_mf_needed_bytes "$arch")"
  fi

  command -v openssl >/dev/null 2>&1 || cx_pre_add FAIL "$(cx_msg pre_openssl_missing)"
  local before=$CX_PRE_EXIT
  CX_PRE_EXIT=0
  cx_preflight_existing "$root" "$([ -n "$dockerdir" ] && echo yes)"
  # Refusing to install over a deployment is a rule, not a host problem: exit code 3.
  if [ "$CX_PRE_EXIT" -ne 0 ]; then CX_PRE_EXIT=$CX_EXIT_REFUSED; else CX_PRE_EXIT=$before; fi
  if [ ! -w "$root" ]; then
    cx_pre_add FAIL "$(cx_msg pre_not_writable "$root")" cx_pre_hint_sudo
  fi
}

# Public ports: the https and http ports of the built-in proxy, or HTTP_PORT behind your own ingress.
cx_preflight_ports() {
  local root=$1 env=$1/.env cf p who busy=0 checked=""
  local -a ports=()
  cf=$(cx_env_get "$env" COMPOSE_FILE)
  if [[ $cf == *external-ingress* ]]; then
    p=$(cx_env_get "$env" HTTP_PORT)
    ports=("${p:-80}")
  else
    p=$(cx_env_get "$env" TLS_HTTPS_PORT)
    ports=("${p:-443}")
    p=$(cx_env_get "$env" TLS_HTTP_PORT)
    ports+=("${p:-80}")
  fi
  for p in "${ports[@]}"; do
    if ! who=$(cx_port_holder "$p"); then
      cx_pre_add WARN "$(cx_msg pre_ports_unchecked "$(cx_join "$(cx_msg pre_list_sep)" "${ports[@]}")")"
      return 0
    fi
    if [ -n "$who" ] && cx_port_ours "$root" "$p"; then
      who=""
    fi
    if [ -n "$who" ]; then
      cx_pre_add FAIL "$(cx_msg pre_port_busy "$p" "$who")" "cx_pre_hint_port $p"
      busy=1
      printf -v "CX_PRE_WHO_$p" '%s' "$who"
    else
      checked+=${checked:+$(cx_msg pre_list_sep)}$p
    fi
  done
  [ "$busy" = 1 ] || cx_pre_add OK "$(cx_msg pre_ports_ok "$checked")"
}

# cx_port_ours <root> <port>: the port is published by this deployment's own services, left running
# by an install of this folder that did not finish. Running install again is expected then.
cx_port_ours() {
  local root=$1 p=$2
  [ -n "$(cx_state_get install.result)" ] || return 1
  [ -n "$(docker ps --filter "publish=$p" --filter "label=com.docker.compose.project=$CX_PROJECT" \
    --filter "label=com.docker.compose.project.working_dir=$root" --format '{{.Names}}' 2>/dev/null)" ]
}

# Disk: the Docker data folder takes the images; the deployment folder takes logs and settings.
# One file system holding both needs the sum.
cx_preflight_disk() {
  local root=$1 dockerdir=$2 need=$(($3 + CX_DOCKER_FREE_EXTRA)) free rfree
  free=$(cx_free_bytes "$dockerdir")
  if [ -z "$free" ]; then
    cx_pre_add WARN "$(cx_msg pre_disk_unknown "$dockerdir")"
  elif [ "$(cx_mount_of "$dockerdir")" = "$(cx_mount_of "$root")" ]; then
    need=$((need + CX_ROOT_FREE_MIN))
    if [ "$free" -ge "$need" ]; then
      cx_pre_add OK "$(cx_msg pre_disk "$(cx_gb_down "$free")" "$(cx_gb_up "$need")")"
    else
      cx_pre_add FAIL "$(cx_msg pre_disk "$(cx_gb_down "$free")" "$(cx_gb_up "$need")")"
    fi
    return 0
  elif [ "$free" -ge "$need" ]; then
    cx_pre_add OK "$(cx_msg pre_disk "$(cx_gb_down "$free")" "$(cx_gb_up "$need")")"
  else
    cx_pre_add FAIL "$(cx_msg pre_disk "$(cx_gb_down "$free")" "$(cx_gb_up "$need")")"
  fi
  rfree=$(cx_free_bytes "$root")
  if [ -n "$rfree" ] && [ "$rfree" -lt "$CX_ROOT_FREE_MIN" ]; then
    cx_pre_add FAIL "$(cx_msg pre_disk_root "$(cx_gb_down "$rfree")" "$(cx_gb_up "$CX_ROOT_FREE_MIN")")"
  fi
}

# An existing deployment is never installed over: a finished install in state.json, a
# custodexa-backend container that this unfinished install did not start, or a git clone.
cx_preflight_existing() {
  local root=$1 docker_ok=$2 labels
  if [ -n "$(cx_state_get current.version)" ]; then
    cx_pre_add FAIL "$(cx_msg pre_existing_state "$(cx_state_get current.version)")" cx_pre_hint_existing
  fi
  if [ -e "$root/.git" ]; then
    cx_pre_add FAIL "$(cx_msg pre_existing_git)" cx_pre_hint_existing
  fi
  [ "$docker_ok" = yes ] || return 0
  if labels=$(docker container inspect --format '{{json .Config.Labels}}' custodexa-backend 2>/dev/null); then
    if [[ $labels != *"\"com.docker.compose.project.working_dir\":\"$root\""* ]] ||
      [ "$(cx_state_get install.result)" = "" ]; then
      cx_pre_add FAIL "$(cx_msg pre_existing_container)" cx_pre_hint_existing
    fi
  fi
}

# cx_preflight_report <root>: the step line, and on failure the checks and what to do.
cx_preflight_report() {
  local root=$1 i h
  if [ "$CX_PRE_EXIT" -eq 0 ]; then
    return 0
  fi
  cx_step_line FAIL 1/7 "$(cx_msg step_preflight)"
  for i in "${!CX_PRE_MARK[@]}"; do
    cx_sub "${CX_PRE_MARK[i]}" "${CX_PRE_TEXT[i]}"
  done
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
  local seen=" "
  for h in "${CX_PRE_HINT[@]}"; do
    [ -n "$h" ] || continue
    [[ $seen == *" ${h// /_} "* ]] && continue
    seen+="${h// /_} "
    printf '\n'
    # shellcheck disable=SC2086 # the hint is a function name and its arguments
    $h
  done
}

cx_pre_hint_port() {
  local p=$1 var="CX_PRE_WHO_$1" ip
  printf '%s\n' "$(cx_msg text_pre_port "$p" "${!var:-?}")"
  cx_cmd "sudo $CX_ROOT/custodexa.sh install"
  if [[ $(cx_env_get "$CX_ROOT/.env" COMPOSE_FILE) == *external-ingress* ]]; then
    printf '%s\n' "$(cx_msg text_pre_port_change_ingress "$CX_ROOT")"
    return 0
  fi
  ip=$(cx_env_primary_ipv4)
  printf '%s\n' "$(cx_msg text_pre_port_change "$CX_ROOT" "${ip:-$(cx_env_host_fqdn)}")"
}
cx_pre_hint_docker_perm() { printf '%s\n' "$(cx_msg text_pre_docker_perm)"; }
cx_pre_hint_sudo() {
  printf '%s\n' "$(cx_msg text_pre_sudo)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh install"
}
cx_pre_hint_existing() {
  printf '%s\n' "$(cx_msg text_pre_existing)"
  cx_cmd "sudo $CX_ROOT/custodexa.sh status"
  cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade"
}
