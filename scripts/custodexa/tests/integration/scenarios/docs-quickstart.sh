# shellcheck shell=bash
# about: the docker compose commands of the three QUICKSTART guides (English, zh-TW, ja) for a source deployment, each taken as written (the line must be in all three guides) and run on a deployment that quickstart.sh brought up: ps, the health check, logs (also with -f), tls-init, recreating tls-init and tls-proxy, up -d tls-proxy, exec postgres, restart, down and down -v with the data erased; then the external database form and the own-ingress form with ps and down. Commands of the development stack (hot reload, go test, rebuild) are not run here.
# needs: package
# images: pg16 openssl-3.5.4

readonly DQ_PORT=15519
readonly DQ_DIR=/it/dq
readonly DQ_EN=/src/docs/QUICKSTART.md
DQ_DOCS=("$DQ_EN" /src/docs/zh-TW/QUICKSTART.md /src/docs/ja/QUICKSTART.md)
DQ_OUT=""
DQ_RC=0

# dq_in_doc <file> <command>: a line of the guide that is this command, alone or followed by a comment,
# or the command written in backticks in a sentence.
dq_in_doc() {
  awk -v c="$2" '
    { l = $0; sub(/^[ \t]+/, "", l)
      if (l == c) f = 1
      else if (index(l, c " ") == 1) { r = substr(l, length(c) + 1); sub(/^ +/, "", r); if (r ~ /^#/) f = 1 } }
    END { exit !f }' "$1" || grep -qF -- "\`$2\`" "$1"
}

dq_in_all() {
  local f
  for f in "${DQ_DOCS[@]}"; do
    dq_in_doc "$f" "$1" || {
      echo "not in ${f#/src/docs/}: $1"
      return 1
    }
  done
}

# dq_cmd <command> [follow|stdin]: the command, from the guides as written, in the deployment folder,
# through the docker wrapper that skips only the image build. follow: a command that never ends
# (logs -f) is stopped after 8 seconds. stdin: an interactive psql gets \dt and \q.
dq_cmd() {
  local cmd=$1 mode=${2:-}
  it_check "the line is in all three guides: $cmd" dq_in_all "$cmd" || return 1
  DQ_RC=0
  case $mode in
    follow) DQ_OUT=$(cd "$DQ_DIR" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG eval "timeout 8 $cmd" 2>&1) || DQ_RC=$? ;;
    stdin) DQ_OUT=$(cd "$DQ_DIR" && printf '\\dt\n\\q\n' | PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG bash -c "$cmd" 2>&1) || DQ_RC=$? ;;
    *) DQ_OUT=$(cd "$DQ_DIR" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG bash -c "$cmd" 2>&1) || DQ_RC=$? ;;
  esac
  printf '%s\n' "$DQ_OUT" | sed 's/^/   > /' | tail -n 14
  if [ "$mode" = follow ]; then
    [ "$DQ_RC" = 124 ] || [ "$DQ_RC" = 0 ] || {
      printf 'not ok - ran: %s (exit %s)\n' "$cmd" "$DQ_RC"
      return 1
    }
  elif [ "$DQ_RC" != 0 ]; then
    printf 'not ok - ran: %s (exit %s)\n' "$cmd" "$DQ_RC"
    return 1
  fi
  printf 'ok - ran as written: %s (exit %s)\n' "$cmd" "$DQ_RC"
}

dq_healthy() {
  local i
  for ((i = 0; i < 90; i++)); do
    (cd "$DQ_DIR" && docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1) && return 0
    sleep 2
  done
  (cd "$DQ_DIR" && docker compose logs backend 2>&1 | tail -n 30) >&2
  it_die "the backend did not become healthy"
}

scenario() {
  local up_pid blk
  qs_images
  ex_pg_start pg16 16 "$DQ_PORT"

  it_step "step 3: the preparation, then the foreground start (docker compose up), as the guide gives them"
  qs_tree "$DQ_DIR"
  qs_env "$DQ_DIR" KEK_PROVIDER=env TLS_MODE=selfsigned
  dq_cmd "bash scripts/quickstart.sh"
  it_same "the preparation started nothing" "" "$(cd "$DQ_DIR" && docker compose ps -q)"
  (cd "$DQ_DIR" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG exec docker compose up >"$IT_WORK/dq-up.out" 2>&1) &
  up_pid=$!
  it_check "the line is in all three guides: docker compose up" dq_in_all "docker compose up"
  dq_healthy
  it_check "the foreground run printed the logs of the services" grep -q 'custodexa-backend' "$IT_WORK/dq-up.out"
  kill -INT "$up_pid"
  wait "$up_pid" || true
  it_same "stopping it (Ctrl-C) leaves no running container" "" "$(cd "$DQ_DIR" && docker compose ps -q)"
  dq_cmd "bash scripts/quickstart.sh --up"
  dq_healthy

  it_step "the recordings directory block of step 3"
  blk=$(awk '/^docker run --rm --network none -v "\$PWD\/data\/recordings:\/r"/ { print; getline; print; exit }' "$DQ_EN")
  it_check "the block is in the English guide" test -n "$blk"
  it_check "and in the other two" bash -c 'for f in "$@"; do grep -qF -- "docker run --rm --network none -v \"\$PWD/data/recordings:/r\" --entrypoint /bin/sh alpine/openssl:3.5.4 -c" "$f" || exit 1; done' _ "${DQ_DOCS[1]}" "${DQ_DOCS[2]}"
  (cd "$DQ_DIR" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG bash -c "$blk")
  it_same "the directory is owned by 1000:0 with mode 2770" "1000:0 2770" "$(stat -c '%u:%g %a' "$DQ_DIR/data/recordings")"

  it_step "step 4 and the deployment verification (production form: bundled database, built-in proxy)"
  dq_cmd "docker compose ps"
  for blk in backend frontend guacd tls-proxy postgres; do
    it_check "docker compose ps lists $blk" grep -q "custodexa-$blk" <<<"$DQ_OUT"
  done
  it_check "tls-init is not listed (it has exited; ps shows running containers)" bash -c '! grep -q "tls-init" <<<"$1"' _ "$DQ_OUT"
  dq_cmd "docker compose exec backend wget -qO- http://localhost:8080/health"
  it_check "the health check answered with a status" grep -q '"status"' <<<"$DQ_OUT"
  dq_cmd "docker compose logs backend | tail -30"
  it_check "the startup log has output" test -n "$DQ_OUT"
  dq_cmd 'docker compose logs backend | grep "refresh cookie"'
  it_check "the log prints the refresh cookie line" grep -q 'refresh cookie' <<<"$DQ_OUT"
  dq_cmd "docker compose logs -f" follow
  dq_cmd "docker compose logs -f backend" follow
  dq_cmd "docker compose logs -f frontend" follow
  dq_cmd "docker compose logs tls-init"
  it_check "tls-init has output of its run" test -n "$DQ_OUT"

  it_step "TLS: the certificate step again, and the proxy"
  dq_cmd "docker compose up -d --force-recreate tls-init tls-proxy"
  it_check "tls-proxy runs again" bash -c 'docker ps --format "{{.Names}}" | grep -qx custodexa-tls-proxy'
  dq_cmd "docker compose logs tls-init"
  it_check "tls-init reports on the certificate in tls/" test -n "$DQ_OUT"
  dq_cmd "docker compose up -d tls-proxy"
  dq_cmd "docker compose ps -a"
  it_check "tls-proxy is Up" bash -c 'grep custodexa-tls-proxy <<<"$1" | grep -q "Up"' _ "$DQ_OUT"
  it_check "tls-init is listed as exited(0)" bash -c 'grep custodexa-tls-init <<<"$1" | grep -Eq "Exited \(0\)"' _ "$DQ_OUT"

  it_step "common commands that apply to the production form"
  dq_cmd "docker compose restart backend"
  dq_healthy
  dq_cmd "docker compose exec postgres psql -U postgres -d custodexa" stdin
  it_check "psql listed the tables" grep -q 'users' <<<"$DQ_OUT"
  dq_cmd "docker compose down"
  it_same "down removed every container" "" "$(docker ps -aq --filter name=custodexa-)"
  it_check "the data stayed" test -d "$DQ_DIR/data/audit"
  dq_cmd "bash scripts/quickstart.sh --up"
  dq_healthy
  dq_cmd "docker compose down -v"
  it_check "down -v left the bind-mounted data" test -d "$DQ_DIR/data/audit"
  dq_cmd "docker compose down && rm -rf ./data/*"
  it_same "the data folder is empty" "" "$(ls -A "$DQ_DIR/data")"

  it_step "section 7: the external database form (docker compose ps shows no postgres)"
  qs_down
  qs_tree "$DQ_DIR"
  ex_db_create pg16 dq_ext
  qs_env "$DQ_DIR" KEK_PROVIDER=env TLS_MODE=selfsigned "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$DQ_PORT" \
    DB_NAME=dq_ext "DB_USER=$EX_USER" "DB_PASSWORD=$EX_PASS"
  dq_cmd "bash scripts/quickstart.sh --up"
  dq_healthy
  dq_cmd "docker compose ps"
  for blk in backend frontend guacd tls-proxy; do
    it_check "docker compose ps lists $blk" grep -q "custodexa-$blk" <<<"$DQ_OUT"
  done
  it_check "and no postgres" bash -c '! grep -q "custodexa-postgres" <<<"$1"' _ "$DQ_OUT"
  dq_cmd "docker compose down"

  it_step "TLS_MODE=external: docker compose ps and down cover the same services"
  qs_down
  qs_env "$DQ_DIR" TLS_MODE=external
  dq_cmd "bash scripts/quickstart.sh --up"
  dq_healthy
  dq_cmd "docker compose ps"
  it_check "the frontend is listed and there is no tls-proxy" bash -c 'grep -q custodexa-frontend <<<"$1" && ! grep -q tls-proxy <<<"$1"' _ "$DQ_OUT"
  dq_cmd "docker compose down"
  it_same "down removed every container" "" "$(docker ps -aq --filter name=custodexa-)"

  it_step "clean up"
  qs_down
  it_pg_stop pg16
}
