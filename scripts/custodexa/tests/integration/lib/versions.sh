# shellcheck shell=bash
# A built-in deployment that goes between the versions built from the working tree (scenarios
# with "needs: package local-versions"), for the scenarios of going back to the version before.
#   lv_install <version>             unpack that package, master key mode env, install from its bundle
#   lv_cx <label> <arguments...>     custodexa.sh <arguments> --lang en; LV_OUT, LV_RC; the screen is
#                                    printed under the label. LV_INJECT (below) applies to it.
#   lv_upgrade <version> [expected exit]   upgrade --images <its bundle> --yes
#   lv_bg <label> <arguments...>     the same in the background: LV_PID, output in $IT_WORK/<label>.out
#   lv_signal_at_up <label>          with LV_INJECT=hold-up: wait until the run reaches its `compose
#                                    up`, send SIGTERM to the script only (as `kill <pid>` does), let the
#                                    up go on, wait for the end; LV_RC, LV_OUT
#   lv_st <key>                      a key of state.json
#   lv_version                       the version the backend reports on /health ("" when it does not)
#   lv_ids_running                   "<service>=<image ID>" of the running containers, as current.image_ids
#   lv_ps                            the running containers: name, image ID, start time (for "unchanged")
#   lv_tools_left                    tool containers left behind (none expected)
#   lv_api <method> <path> [json]    the deployment's API as the administrator (signed in on first use)
#   lv_sql <sql>                     psql -At in the database container, as DB_USER
#   lv_files_sha                     sha256 of .env, every file under tls/ and the fixed recording
# LV_INJECT, test only, read by a docker wrapper first on the script's PATH (the script and the
# images are unchanged):
#   recordings-fail   the container that prepares the recordings folder fails (upgrade step 9)
#   health-fail       the readiness question to the backend (compose exec ... wget /health) fails
#   hold-up           `compose up` waits until $IT_WORK/lv-hold is removed ($IT_WORK/lv-up-reached
#                     tells it got there), then runs
#   pause-after-up    after `compose up`, the backend container is paused (the version started
#                     does not become ready; with CX_READY_TRIES the wait is short)
#   hold-after-up     `compose up -d` of every service runs, then waits until $IT_WORK/lv-hold is
#                     removed ($IT_WORK/lv-up-reached tells it got there) before it returns
#   restore-place-fail  once: the restore's stop before it places the files fails
#   restore-check-fail  once: the restore's check of the imported database reads 999999 users
#   hold-import       the restore's pg_restore gets the first 4 KiB of the dump, the rest 8 seconds
#                     later ($IT_WORK/lv-import-reached tells it started)
#   hold-swap         (a sync wrapper) the restore moved the old database folder aside, not yet the
#                     audit folder: wait until $IT_WORK/lv-hold is removed ($IT_WORK/lv-swap-reached)

readonly LV_ROOT=/opt/custodexa
readonly LV_REAL_DOCKER=/usr/local/bin/docker
readonly LV_WAIT=1200 # tenths of a second
readonly LV_RECORDING=data/recordings/it-fixed-recording.cast
LV_OUT="" LV_RC=0 LV_PID="" LV_TOKEN="" LV_INJECT="" LV_READY_TRIES=""

lv_st() { jq -r --arg k "$1" '.[$k] // ""' "$LV_ROOT/state.json"; }

lv_shim() {
  mkdir -p "$IT_WORK/lvshim"
  cat >"$IT_WORK/lvshim/docker" <<EOF
#!/usr/bin/env bash
real=$LV_REAL_DOCKER
args=" \$* "
case " \${LV_INJECT:-} " in
  *" recordings-fail "*)
    if [ "\${1:-}" = run ] && [[ \$args == *"/recordings:/r "* ]]; then
      echo "injected: the recordings folder could not be prepared" >&2
      exit 1
    fi
    ;;
esac
if [ "\${1:-}" = compose ] && [[ \$args == *" exec -T backend wget "* ]]; then
  case " \${LV_INJECT:-} " in *" health-fail "*) exit 1 ;; esac
fi
phase() { jq -r '."last_restore.phase" // ""' "$LV_ROOT/state.json" 2>/dev/null; }
if [ "\${1:-}" = compose ] && [ ! -e "$IT_WORK/lv-injected" ]; then
  case " \${LV_INJECT:-} " in
    *" restore-place-fail "*)
      if [[ \$args == *" stop "* ]] && [ "\$(phase)" = db_checked ]; then
        touch "$IT_WORK/lv-injected"
        echo "injected: the services could not be stopped before the files are placed" >&2
        exit 1
      fi
      ;;
    *" restore-check-fail "*)
      if [[ \$args == *"SELECT count(*) FROM users"* ]] && [ "\$(phase)" = imported ]; then
        touch "$IT_WORK/lv-injected"
        echo 999999
        exit 0
      fi
      ;;
  esac
fi
if [ "\${1:-}" = compose ] && [[ \$args == *" exec -T postgres pg_restore --single-transaction "* ]]; then
  case " \${LV_INJECT:-} " in
    *" hold-import "*)
      # The first block of the dump now, the rest after a pause: pg_restore runs meanwhile.
      touch "$IT_WORK/lv-import-reached"
      { dd bs=4096 count=1 iflag=fullblock status=none; sleep 8; cat; } | "\$real" "\$@"
      exit "\${PIPESTATUS[1]}"
      ;;
  esac
fi
if [ "\${1:-}" = compose ] && [[ \$args == *" up -d "* ]]; then
  case " \${LV_INJECT:-} " in
    *" hold-up "*)
      touch "$IT_WORK/lv-up-reached"
      while [ -e "$IT_WORK/lv-hold" ]; do sleep 0.2; done
      ;;
    *" hold-after-up "*)
      # The start of every service (not the database alone) runs, then waits before it returns.
      if [[ \$args != *" up -d postgres "* ]]; then
        "\$real" "\$@"
        rc=\$?
        touch "$IT_WORK/lv-up-reached"
        while [ -e "$IT_WORK/lv-hold" ]; do sleep 0.2; done
        exit \$rc
      fi
      ;;
    *" pause-after-up "*)
      "\$real" "\$@"
      rc=\$?
      "\$real" pause custodexa-backend >/dev/null
      exit \$rc
      ;;
  esac
fi
exec "\$real" "\$@"
EOF
  chmod +x "$IT_WORK/lvshim/docker"
  # hold-swap: the restore moved the old database folder aside and has not moved the audit folder
  # yet (the sync after the first rename); wait there until $IT_WORK/lv-hold is removed.
  cat >"$IT_WORK/lvshim/sync" <<EOF
#!/usr/bin/env bash
case " \${LV_INJECT:-} " in
  *" hold-swap "*)
    if [ ! -e "$IT_WORK/lv-swap-reached" ] && [ -d "$LV_ROOT/data/audit" ] && [ ! -e "$LV_ROOT/data/postgres" ] &&
      compgen -G "$LV_ROOT/data/postgres.before-restore-*" >/dev/null; then
      touch "$IT_WORK/lv-swap-reached"
      while [ -e "$IT_WORK/lv-hold" ]; do sleep 0.2; done
    fi
    ;;
esac
exec "\$(PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin command -v sync)" "\$@"
EOF
  chmod +x "$IT_WORK/lvshim/sync"
}

lv_cx() {
  local label=$1
  shift
  lv_shim
  LV_OUT=$(LV_INJECT=${LV_INJECT:-} CX_READY_TRIES=${LV_READY_TRIES:-} PATH=$IT_WORK/lvshim:$PATH \
    "$LV_ROOT/custodexa.sh" "$@" --lang en 2>&1) && LV_RC=0 || LV_RC=$?
  printf '%s\n' "$LV_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$LV_RC"
}

lv_install() {
  local v=$1
  it_step "built-in form, master key mode env: install $v"
  it_unpack /opt "$v"
  ex_preset "$LV_ROOT" KEK_PROVIDER=env
  lv_cx install install --images "$(it_bundle_file "$v")"
  it_same "install $v exits 0" 0 "$LV_RC"
  it_same "the backend reports $v" "$v" "$(lv_version)"
  LV_TOKEN=""
}

lv_upgrade() {
  local v=$1 want=${2:-0} was
  was=$(lv_st current.version)
  lv_cx upgrade upgrade "$(it_package_file "$v")" --images "$(it_bundle_file "$v")" --yes
  it_same "upgrade $was -> $v exits $want" "$want" "$LV_RC"
}

lv_bg() {
  local label=$1
  shift
  lv_shim
  rm -f "$IT_WORK/lv-up-reached"
  LV_INJECT=${LV_INJECT:-} CX_READY_TRIES=${LV_READY_TRIES:-} PATH=$IT_WORK/lvshim:$PATH \
    "$LV_ROOT/custodexa.sh" "$@" --lang en >"$IT_WORK/$label.out" 2>&1 &
  LV_PID=$!
}

# lv_until <what> <command...>: poll every tenth of a second, at most LV_WAIT times.
lv_until() {
  local what=$1 i
  shift
  for ((i = 0; i < LV_WAIT; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  printf 'not ok - %s never happened\n' "$what"
  return 1
}

lv_signal_at_up() {
  local label=$1
  lv_until "$label: the run reaches compose up" test -e "$IT_WORK/lv-up-reached"
  it_say "   $label: at compose up (step $(lv_st last_rollback.step) of the rollback record); SIGTERM to the script"
  kill -TERM "$LV_PID"
  sleep 1
  rm -f "$IT_WORK/lv-hold"
  LV_RC=0
  wait "$LV_PID" || LV_RC=$?
  LV_OUT=$(cat "$IT_WORK/$label.out")
  printf '%s\n' "$LV_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$LV_RC"
}

lv_backend_ip() {
  docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' custodexa-backend 2>/dev/null | awk '{print $1}'
}

lv_version() {
  local ip
  ip=$(lv_backend_ip) || return 0
  [ -n "$ip" ] || return 0
  curl -fsS --max-time 5 "http://$ip:8080/health" 2>/dev/null | jq -r '.version // empty' 2>/dev/null || true
}

lv_ids_running() {
  local pair name c
  for pair in $(lv_st current.image_ids); do
    name=${pair%%=*}
    case $name in # the container of each image, as the script names it
      openssl) c=custodexa-tls-init ;;
      nginx) c=custodexa-tls-proxy ;;
      *) c=custodexa-$name ;;
    esac
    printf '%s=%s ' "$name" "$(docker inspect --format '{{.Image}}' "$c" 2>/dev/null)"
  done | sed 's/ $//'
}

lv_ps() { docker ps --no-trunc --format '{{.Names}} {{.Image}} {{.ID}} {{.Status}}' | sed 's/ (healthy)//; s/ (health: starting)//' | awk '{print $1, $2, $3}' | sort; }
lv_images() { docker images --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort; }
lv_tools_left() { docker ps -a --format '{{.Names}}' | grep -E -- '-tool-' || true; }

lv_env_get() { sed -n "s/^$1=//p" "$LV_ROOT/.env" | tail -n1; }

lv_sql() {
  docker exec -i custodexa-postgres psql -X -v ON_ERROR_STOP=1 -At -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "$1"
}

# lv_login: a session for the administrator; the first sign-in changes the initial password.
lv_login() {
  local ip r pw new=$IT_WORK/lv-admin-password
  ip=$(lv_backend_ip)
  if [ -s "$new" ]; then
    pw=$(cat "$new")
  else
    pw=$(lv_env_get ADMIN_INITIAL_PASSWORD)
  fi
  r=$(curl -sS --max-time 10 -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$pw" '{username: "admin", password: $p}')" "http://$ip:8080/api/v1/auth/login")
  if [ "$(jq -r '.password_change_required // false' <<<"$r")" = true ]; then
    printf 'It-%s-9q' "$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" >"$new"
    r=$(curl -sS --max-time 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $(jq -r .change_token <<<"$r")" \
      -d "$(jq -cn --arg o "$pw" --arg n "$(cat "$new")" '{old_password: $o, new_password: $n}')" \
      "http://$ip:8080/api/v1/auth/change-password")
  fi
  LV_TOKEN=$(jq -r '.token // empty' <<<"$r")
  [ -n "$LV_TOKEN" ] || { printf 'not ok - administrator sign-in: %s\n' "$(head -c 300 <<<"$r")"; return 1; }
}

lv_api() {
  local method=$1 path=$2 body=${3:-} ip
  [ -n "$LV_TOKEN" ] || lv_login
  ip=$(lv_backend_ip)
  if [ -n "$body" ]; then
    curl -fsS --max-time 15 -X "$method" -H "Authorization: Bearer $LV_TOKEN" -H 'Content-Type: application/json' \
      -d "$body" "http://$ip:8080/api/v1$path"
  else
    curl -fsS --max-time 15 -X "$method" -H "Authorization: Bearer $LV_TOKEN" "http://$ip:8080/api/v1$path"
  fi
}

lv_files_sha() {
  (cd "$LV_ROOT" && find .env tls "$LV_RECORDING" -type f -print0 | sort -z | xargs -0 sha256sum)
}

# lv_wait_version <version>: the backend answers /health with this version (it may still start).
lv_is_version() { [ "$(lv_version)" = "$1" ]; }
lv_wait_version() {
  lv_until "the backend reports $1" lv_is_version "$1" || true
  it_same "the backend reports $1" "$1" "$(lv_version)"
}
