# shellcheck shell=bash
# about: a source deployment (the working tree's docker-compose.yml and scripts/quickstart.sh) comes up in each of the four forms with quickstart.sh --up (bundled or external database, built-in proxy or your own ingress), the database it uses is the one the form says, the development form with an external setting is refused before docker is called, and the root compose file answers a bare docker compose, COMPOSE_FILE and -f as the spec says
# needs: package
# images: pg16 openssl-3.5.4

readonly QF_PORT=15516
readonly QF_DIR=/it/qs

# qf_up <label> <external db 0|1> <TLS_MODE> <expected profiles> <expected URL regex>
qf_up() {
  local label=$1 ext=$2 tls=$3 want=$4 url=$5 where=bundled db=custodexa names
  it_step "$label"
  qs_down
  qs_tree "$QF_DIR"
  qs_env "$QF_DIR" KEK_PROVIDER=env "TLS_MODE=$tls" HTTP_PORT=8080
  if [ "$ext" = 1 ]; then
    where=pg16 db=qf_$RANDOM
    ex_db_create pg16 "$db"
    qs_env "$QF_DIR" "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$QF_PORT" "DB_NAME=$db" \
      "DB_USER=$EX_USER" "DB_PASSWORD=$EX_PASS"
  fi
  : >"$QS_LOG"
  qs_run "$QF_DIR" --up
  it_same "quickstart.sh --up exits 0" 0 "$QS_RC"
  it_same "the managed block says" "$want" "$(qs_profiles "$QF_DIR")"
  it_check "the login URL" grep -Eq "URL: +$url" <<<"$QS_OUT"
  names=$(docker ps --format '{{.Names}}' | grep '^custodexa-' | sort | tr '\n' ' ')
  it_step "$label: what runs"
  it_say "   $names"
  if [ "$ext" = 1 ]; then
    it_check "no postgres container" bash -c '! docker ps -a --format "{{.Names}}" | grep -qx custodexa-postgres'
    it_same "the backend connects to the external server" "$(ex_addr)" "$(qs_backend_env DB_HOST)"
    it_same "and to its port" "$QF_PORT" "$(qs_backend_env DB_PORT)"
  else
    it_check "the bundled postgres runs" bash -c 'docker ps --format "{{.Names}}" | grep -qx custodexa-postgres'
    it_same "the backend connects to the service postgres" postgres "$(qs_backend_env DB_HOST)"
  fi
  qs_wait_db "$where" "$db"
  # The backend runs its migrations and creates the first administrator: rows only it can have written.
  it_same "the backend wrote to that database (an account exists there)" 1 \
    "$([ "$(qs_sql "$where" "$db" "SELECT count(*) FROM users")" -ge 1 ] && echo 1 || echo 0)"
  if [ "$tls" = external ]; then
    it_check "your own ingress: no proxy container" bash -c '! docker ps --format "{{.Names}}" | grep -qx custodexa-tls-proxy'
    it_check "the frontend publishes the HTTP port" bash -c 'docker port custodexa-frontend 80 | grep -q ":8080$"'
  else
    it_check "the built-in proxy runs" bash -c 'docker ps --format "{{.Names}}" | grep -qx custodexa-tls-proxy'
    it_same "the frontend publishes nothing (docker port prints nothing)" "" "$(docker port custodexa-frontend)"
  fi
}

# qf_services <label> <expected services> <command...>: docker compose config --services
qf_services() {
  local label=$1 want=$2 got
  shift 2
  got=$(cd "$QF_DIR" && env -u COMPOSE_FILE -u COMPOSE_PROFILES "$@" 2>/dev/null | sort | tr '\n' ' ')
  it_same "$label" "$want" "$got"
}

scenario() {
  local prod dev
  qs_images
  ex_pg_start pg16 16 "$QF_PORT"

  qf_up "bundled database, built-in proxy" 0 selfsigned bundled-db,builtin-tls 'https://'
  qf_up "external database, built-in proxy" 1 selfsigned builtin-tls 'https://'
  qf_up "bundled database, your own ingress" 0 external bundled-db,own-ingress 'http://localhost:8080/'
  qf_up "external database, your own ingress" 1 external own-ingress 'http://localhost:8080/'
  qs_down

  it_step "the development form with an external setting is refused before docker is called"
  qs_tree "$QF_DIR"
  qs_env "$QF_DIR" KEK_PROVIDER=env COMPOSE_FILE=docker-compose.dev.yml "EXTERNAL_DB_HOST=$(ex_addr)"
  : >"$QS_LOG"
  qs_run "$QF_DIR" --up
  it_check "non-zero exit and the reason" bash -c '[ "$1" -ne 0 ] && grep -q "cannot be used with" <<<"$2"' _ "$QS_RC" "$QS_OUT"
  it_same "no docker call at all" 0 "$(wc -l <"$QS_LOG" | tr -d ' ')"

  it_step "the root compose file: a bare docker compose, COMPOSE_FILE, and -f"
  qs_tree "$QF_DIR"
  qs_env "$QF_DIR" KEK_PROVIDER=env VAULT_DEV_ROOT_TOKEN_ID=it-token
  # the template as copied, then prepared by quickstart.sh (no --up): the production form
  qs_run "$QF_DIR"
  it_same "the preparation exits 0" 0 "$QS_RC"
  prod="backend frontend guacd postgres tls-init tls-proxy "
  dev=$(cd "$QF_DIR" && env -u COMPOSE_FILE -u COMPOSE_PROFILES docker compose -f docker-compose.dev.yml config --services | sort | tr '\n' ' ')
  it_check "the development services include the test targets and no proxy" \
    bash -c '[[ " $1 " == *" ssh-test "* && " $1 " != *" tls-proxy "* ]]' _ "$dev"
  qf_services "template .env, bare docker compose: the production services" "$prod" docker compose config --services
  qs_env "$QF_DIR" COMPOSE_FILE=docker-compose.dev.yml
  qf_services "COMPOSE_FILE=docker-compose.dev.yml in .env: the development services" "$dev" \
    env -u COMPOSE_FILE docker compose config --services
  qf_services "the same .env with an explicit -f docker-compose.yml: the production services" "$prod" \
    docker compose -f docker-compose.yml config --services
  qs_down
}
