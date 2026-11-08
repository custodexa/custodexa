# shellcheck shell=bash
# about: source deployments made with the 1.22 compose files (a base file and the two overlay files) in the four old combinations, each running and each after docker compose down, with one sentinel row written, go through quickstart.sh --up twice: the first run keeps the form and the database, the second leaves .env byte for byte the same
# needs: package
# images: pg16 openssl-3.5.4

readonly QM_PORT=15517
readonly QM_DIR=/it/qs
QM_RUNS=0

# qm_healthy: the backend of the running stack answers /health (the way quickstart.sh waits).
qm_healthy() {
  local i
  for ((i = 0; i < 90; i++)); do
    (cd "$QM_DIR" && docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1) && return 0
    sleep 2
  done
  docker logs custodexa-backend 2>&1 | tail -n 20 >&2
  it_die "the backend did not become healthy"
}

# qm_case <label> <old COMPOSE_FILE or -> <external db 0|1> <running|stopped> <profiles> <TLS_MODE after>
qm_case() {
  local label=$1 cf=$2 ext=$3 state=$4 want=$5 tls=$6 where=bundled db=custodexa first second pg
  it_step "$label, $state"
  qs_down
  qs_tree "$QM_DIR" legacy
  qs_env "$QM_DIR" KEK_PROVIDER=env TLS_MODE=selfsigned HTTP_PORT=8080
  if [ "$ext" = 1 ]; then
    where=pg16 db=qm_$RANDOM
    ex_db_create pg16 "$db"
    qs_env "$QM_DIR" "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$QM_PORT" "DB_NAME=$db" \
      "DB_USER=$EX_USER" "DB_PASSWORD=$EX_PASS"
  fi
  # the secrets, then the .env as 1.22 left it: no managed block, the old COMPOSE_FILE
  qs_run "$QM_DIR"
  it_same "the preparation exits 0" 0 "$QS_RC"
  sed -i '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d' "$QM_DIR/.env"
  [ "$cf" = - ] || qs_env "$QM_DIR" "COMPOSE_FILE=$cf"
  # the old stack, started with its own files
  (cd "$QM_DIR" && docker compose up -d >/dev/null 2>&1)
  qm_healthy
  qs_wait_db "$where" "$db"
  qs_sentinel "$where" "$db" "sentinel-$QM_RUNS"
  QM_RUNS=$((QM_RUNS + 1))
  it_same "before: the sentinel is in the database" "sentinel-$((QM_RUNS - 1))" "$(qs_sentinel_get "$where" "$db")"
  if [ "$state" = stopped ]; then
    (cd "$QM_DIR" && docker compose down >/dev/null 2>&1)
    it_same "stopped: no container is left" "" "$(docker ps -aq --filter label=com.docker.compose.project)"
  fi

  # updating the clone: the base compose file is this tree's, the two overlay files are gone
  qs_pull_new_compose "$QM_DIR"
  : >"$QS_LOG"
  qs_run "$QM_DIR" --up
  first=$(sha256sum "$QM_DIR/.env" | cut -d' ' -f1)
  it_same "first run exits 0" 0 "$QS_RC"
  it_same "the form is the old combination's" "$want" "$(qs_profiles "$QM_DIR")"
  it_same "TLS_MODE after the first run" "$tls" "$(sed -n 's/^TLS_MODE=//p' "$QM_DIR/.env" | tail -n 1)"
  it_check "COMPOSE_FILE is gone" bash -c '! grep -q "^COMPOSE_FILE=" "$1/.env"' _ "$QM_DIR"
  qs_wait_db "$where" "$db"
  it_same "the same sentinel is read from the database the backend uses" "sentinel-$((QM_RUNS - 1))" "$(qs_sentinel_get "$where" "$db")"
  if [ "$ext" = 1 ]; then
    it_same "the backend connects to the external server" "$(ex_addr)" "$(qs_backend_env DB_HOST)"
    it_check "no postgres container was created" bash -c '! docker ps -a --format "{{.Names}}" | grep -qx custodexa-postgres'
  else
    it_same "the backend connects to the service postgres" postgres "$(qs_backend_env DB_HOST)"
    it_check "the bundled postgres runs" bash -c 'docker ps --format "{{.Names}}" | grep -qx custodexa-postgres'
  fi

  qs_run "$QM_DIR" --up
  second=$(sha256sum "$QM_DIR/.env" | cut -d' ' -f1)
  it_same "second run exits 0" 0 "$QS_RC"
  it_same ".env is byte for byte the same after the second run" "$first" "$second"
  it_same "the form is the same" "$want" "$(qs_profiles "$QM_DIR")"
  it_check "the second run lists no change" bash -c '! grep -Eq "^ +(removed|changed|added|updated) " <<<"$1"' _ "$QS_OUT"
  pg=$(qs_sentinel_get "$where" "$db")
  it_same "the sentinel is still there" "sentinel-$((QM_RUNS - 1))" "$pg"
}

scenario() {
  local c s
  qs_images
  ex_pg_start pg16 16 "$QM_PORT"
  for s in running stopped; do
    c="docker-compose.yml:docker-compose.external-database.yml"
    qm_case "no COMPOSE_FILE" - 0 "$s" bundled-db,builtin-tls selfsigned
    qm_case "external database" "$c" 1 "$s" builtin-tls selfsigned
    qm_case "external ingress" "docker-compose.yml:docker-compose.external-ingress.yml" 0 "$s" bundled-db,own-ingress external
    qm_case "both" "docker-compose.yml:docker-compose.external-ingress.yml:docker-compose.external-database.yml" 1 "$s" own-ingress external
  done
  qs_down
}
