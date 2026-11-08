# shellcheck shell=bash
# about: the command blocks of docs/ops/standby-takeover.md (2.1 the .env of an external database, 2.2 the copy to the standby and its preparation, 3 stopping the first host and starting the second, 5 the checks), taken from the guide at run time and run as written on two source deployment folders with the same secrets and one external PostgreSQL server: host a is installed and written to, its containers are removed, host b starts from the copied files and reads what a wrote
# needs: package
# images: pg16 openssl-3.5.4

readonly DX_DOC=/src/docs/ops/standby-takeover.md
readonly DX_PORT=15518
readonly DX_A=/it/a DX_B=/it/b

# dx_block <lang> <first heading> <next heading> <n>: the n-th (from 1) code block of that language
# between two headings of the guide, as written, without the indent of a list item.
dx_block() {
  awk -v lang="$1" -v a="$2" -v b="$3" -v n="$4" '
    index($0, a) == 1 { on = 1; next }
    on && index($0, b) == 1 { exit }
    on && $0 ~ ("^ *```" lang "$") { k++; if (k == n) { inb = 1; match($0, /^ */); ind = RLENGTH; next } }
    inb && $0 ~ /^ *```$/ { exit }
    inb { print substr($0, ind + 1) }
  ' "$DX_DOC"
}

# dx_count <lang> <first heading> <next heading>: how many blocks of that language there are.
dx_count() {
  awk -v lang="$1" -v a="$2" -v b="$3" '
    index($0, a) == 1 { on = 1; next }
    on && index($0, b) == 1 { exit }
    on && $0 ~ ("^ *```" lang "$") { k++ }
    END { print k + 0 }' "$DX_DOC"
}

# dx_run <dir> <file>: a block, in the deployment folder, through the docker wrapper that skips the
# image build; DX_OUT, DX_RC. (No errexit: the guide's lines run one after another as typed.)
dx_run() {
  DX_RC=0
  DX_OUT=$(cd "$1" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG bash "$2" 2>&1) || DX_RC=$?
  printf '%s\n' "$DX_OUT" | sed 's/^/   > /' | tail -n 40
}

# dx_healthy <dir>
dx_healthy() {
  local i
  for ((i = 0; i < 90; i++)); do
    (cd "$1" && docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1) && return 0
    sleep 2
  done
  (cd "$1" && docker compose logs backend 2>&1 | tail -n 30) >&2
  it_die "the backend of $1 did not become healthy"
}

# dx_rsync_shim: the dind host has no rsync. The guide's block uses "rsync -a --relative <paths> <dest>";
# this stands in for exactly that (cp -a --parents), and refuses any other form.
dx_rsync_shim() {
  mkdir -p "$IT_WORK/shim"
  cat >"$IT_WORK/shim/rsync" <<'SHIM'
#!/usr/bin/env bash
[ "${1:-}" = -a ] && [ "${2:-}" = --relative ] || { echo "rsync shim: only -a --relative" >&2; exit 2; }
shift 2
dest=${*: -1}
set -- "${@:1:$#-1}"
mkdir -p "$dest"
cp -a --parents "$@" "$dest"
SHIM
  chmod +x "$IT_WORK/shim/rsync"
}

scenario() {
  local env_block blk users_a audit_a cert_a prof_a prof_b kv k sent
  local -a kvs=()
  env_block=$IT_WORK/dx-env.txt
  qs_images
  dx_rsync_shim

  it_step "the guide's blocks are there: 2.1 one env block, 2.2 two bash blocks, 3 two, 5 one"
  it_same "2.1 env blocks" 1 "$(dx_count env '### 2.1' '### 2.2')"
  it_same "2.2 bash blocks" 2 "$(dx_count bash '### 2.2' '### 2.3')"
  it_same "3 bash blocks" 2 "$(dx_count bash '## 3.' '## 4.')"
  it_same "5 bash blocks" 1 "$(dx_count bash '## 5.' '## 6.')"

  it_step "the database server, and host a: the guide's .env block (2.1), as changed from the guide"
  ex_pg_start pg16 16 "$DX_PORT"
  ex_db_create pg16
  qs_tree "$DX_A"
  qs_env "$DX_A" KEK_PROVIDER=env TLS_MODE=selfsigned
  dx_block env '### 2.1' '### 2.2' 1 >"$env_block"
  it_say "   the block:"
  sed 's/^/     | /' "$env_block"
  it_check "the block has no COMPOSE_FILE line" bash -c '! grep -q "^COMPOSE_FILE=" "$1"' _ "$env_block"
  # Changed from the guide, and only these: the values the guide leaves for you to fill in
  # (host, password), the port of this test's server, and DB_SSLMODE (this server has no TLS).
  while IFS= read -r kv; do
    k=${kv%%=*}
    case $k in
      EXTERNAL_DB_HOST) kv="EXTERNAL_DB_HOST=$(ex_addr)" ;;
      EXTERNAL_DB_PORT) kv="EXTERNAL_DB_PORT=$DX_PORT" ;;
      DB_PASSWORD) kv="DB_PASSWORD=$EX_PASS" ;;
      DB_SSLMODE) kv="DB_SSLMODE=disable" ;;
    esac
    kvs+=("$kv")
  done < <(grep -E '^[A-Z_]+=' "$env_block")
  it_say "   keys set from it: $(printf '%s ' "${kvs[@]%%=*}")"
  qs_env "$DX_A" "${kvs[@]}"
  it_same "the guide sets the host, port, name, user, password and sslmode" \
    "DB_NAME DB_PASSWORD DB_SSLMODE DB_USER EXTERNAL_DB_HOST EXTERNAL_DB_PORT" \
    "$(printf '%s\n' "${kvs[@]%%=*}" | sort | paste -sd' ')"

  it_step "host a: quickstart.sh --up, then the first rows"
  qs_run "$DX_A" --up
  it_same "quickstart.sh --up exits 0" 0 "$QS_RC"
  prof_a=$(qs_profiles "$DX_A")
  it_same "the shape host a derived" builtin-tls "$prof_a"
  dx_healthy "$DX_A"
  it_check "no postgres container: the database is the external server" \
    bash -c '! docker ps -a --format "{{.Names}}" | grep -qx custodexa-postgres'
  it_same "the backend of host a connects to the server" "$(ex_addr)" "$(qs_backend_env DB_HOST)"
  qs_sentinel pg16 custodexa "written-on-a"
  users_a=$(qs_sql pg16 custodexa "SELECT count(*) FROM users")
  audit_a=$(qs_sql pg16 custodexa "SELECT count(*) FROM audit_logs")
  cert_a=$(sha256sum "$DX_A/tls/fullchain.pem" | cut -d' ' -f1)
  it_say "   users $users_a, audit_logs $audit_a, fullchain.pem $cert_a"
  it_check "host a has an account to carry over" test "$users_a" -ge 1

  it_step "2.2 step 2: the copy to the standby (block 1, run on host a), as changed from the guide"
  blk=$IT_WORK/dx-copy.sh
  dx_block bash '### 2.2' '### 2.3' 1 >"$blk"
  it_check "the block copies to standby:/opt/custodexa/" grep -q 'standby:/opt/custodexa/' "$blk"
  # Changed from the guide: "standby:/opt/custodexa/" is host b's folder here, and rsync is the shim.
  sed -i "s|standby:/opt/custodexa/|$DX_B/|" "$blk"
  mkdir -p "$DX_B"
  (cd "$DX_A" && PATH=$IT_WORK/shim:$PATH bash "$blk")
  it_same "the same .env" "$(sha256sum <"$DX_A/.env" | cut -d' ' -f1)" "$(sha256sum <"$DX_B/.env" | cut -d' ' -f1)"
  it_same "the same tls/fullchain.pem (the certificate host a made)" "$cert_a" "$(sha256sum "$DX_B/tls/fullchain.pem" | cut -d' ' -f1)"
  it_check "the compose file and scripts/quickstart.sh arrived" test -f "$DX_B/docker-compose.yml" -a -f "$DX_B/scripts/quickstart.sh"
  it_check "no other compose file was needed" bash -c '! ls "$1"/docker-compose.*.yml 2>/dev/null | grep -v dev.yml' _ "$DX_B"

  it_step "2.2 step 2: the preparation on host b (block 2, nothing is started)"
  blk=$IT_WORK/dx-prepare.sh
  dx_block bash '### 2.2' '### 2.3' 2 >"$blk"
  dx_run "$DX_B" "$blk"
  it_same "the preparation exits 0" 0 "$DX_RC"
  prof_b=$(qs_profiles "$DX_B")
  it_same "host b reports the same COMPOSE_PROFILES as host a" "$prof_a" "$prof_b"
  it_check "its output says so" grep -q "COMPOSE_PROFILES.*$prof_a" <<<"$DX_OUT"
  it_same "the preparation changed nothing in .env" "$(sha256sum <"$DX_A/.env" | cut -d' ' -f1)" "$(sha256sum <"$DX_B/.env" | cut -d' ' -f1)"
  it_same "nothing was started on host b" "" "$(cd "$DX_B" && docker compose ps -q)"

  it_step "3 step 3: stop the primary (block 1, run on host a)"
  blk=$IT_WORK/dx-stop.sh
  dx_block bash '## 3.' '## 4.' 1 >"$blk"
  dx_run "$DX_A" "$blk"
  it_same "the block exits 0 (docker compose ps)" 0 "$DX_RC"
  it_same "docker compose ps shows nothing" "" "$(cd "$DX_A" && docker compose ps -q)"
  it_same "no container of the stack is left on the machine" "" "$(docker ps -aq --filter name=custodexa-)"
  it_check "the data folder of host a is untouched (the audit folder is there)" test -d "$DX_A/data/audit"

  it_step "3 step 4: start the standby (block 2, run on host b)"
  blk=$IT_WORK/dx-start.sh
  dx_block bash '## 3.' '## 4.' 2 >"$blk"
  dx_run "$DX_B" "$blk"
  it_check "the block started containers on host b" test -n "$(cd "$DX_B" && docker compose ps -q)"
  dx_healthy "$DX_B"
  it_check "the log shows the normal startup" bash -c 'cd "$1" && docker compose logs backend | grep -Eq "資料庫連線成功|Listening|監聽"' _ "$DX_B"
  it_check "the [InstanceGuard] line says the lock is held (taken by this instance)" bash -c 'cd "$1" && docker compose logs backend | grep -q "InstanceGuard.*狀態=held"' _ "$DX_B"
  it_check "and there is no CRITICAL line about another session holding it" bash -c 'cd "$1" && ! docker compose logs backend | grep -q "CRITICAL"' _ "$DX_B"

  it_step "5: the checks on the standby (the guide's block, with <address> as localhost)"
  blk=$IT_WORK/dx-verify.sh
  dx_block bash '## 5.' '## 6.' 1 >"$blk"
  it_check "the block names <address>" grep -q '<address>' "$blk"
  sed -i 's|<address>|localhost|' "$blk"
  dx_run "$DX_B" "$blk"
  it_same "the block exits 0" 0 "$DX_RC"
  for k in backend frontend guacd tls-proxy; do
    it_check "docker compose ps lists $k" grep -q "custodexa-$k" <<<"$DX_OUT"
  done
  it_check "and no postgres" bash -c '! grep -q "custodexa-postgres" <<<"$1"' _ "$DX_OUT"
  it_check "the health check answered" grep -qi 'ok\|healthy\|status' <<<"$DX_OUT"
  it_same "seal/status reports instance_guard.state held" held \
    "$(sed -n 's/.*"instance_guard"[^{]*{[^}]*"state":"\([a-z]*\)".*/\1/p' <<<"$DX_OUT" | head -n 1)"

  it_step "the standby reads what the primary wrote"
  qs_wait_db pg16 custodexa
  it_same "the sentinel row of host a" "written-on-a" "$(qs_sentinel_get pg16 custodexa)"
  it_same "the accounts of host a are all there" "$users_a" "$(qs_sql pg16 custodexa "SELECT count(*) FROM users")"
  sent=$(qs_sql pg16 custodexa "SELECT count(*) FROM audit_logs")
  it_check "the audit rows of host a are still there (and the standby added its own)" test "$sent" -ge "$audit_a"
  it_same "the backend of host b connects to the same server" "$(ex_addr)" "$(qs_backend_env DB_HOST)"
  it_same "host b serves the certificate host a made (tls-init kept it)" "$cert_a" "$(sha256sum "$DX_B/tls/fullchain.pem" | cut -d' ' -f1)"
  it_check "host b's containers belong to host b's folder" \
    bash -c '[ "$(docker inspect -f "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}" custodexa-backend)" = "$1" ]' _ "$DX_B"

  it_step "clean up"
  qs_down
  it_pg_stop pg16
}
