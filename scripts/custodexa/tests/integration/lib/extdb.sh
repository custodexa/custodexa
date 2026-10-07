# shellcheck shell=bash
# Deployments on an external PostgreSQL server, for the scenarios of the external database form.
#
# The servers run on the host network of the integration host, each on its own port, and are
# addressed by the host's address on the default bridge (ex_addr). The deployment's backend reaches
# that address from its compose network, and the script's client container (host network) from the
# host itself: the same server, the same address, the same certificate check for both. A server on
# the it-pg network would not do: a compose network cannot reach another bridge network.
#
#   ex_addr                                  the servers' address (EXTERNAL_DB_HOST)
#   ex_pg_start <name> <16|17|18> <port> [plain|tls-only|client-cert]
#       tls-only and client-cert: a certificate for ex_addr signed by the test CA (/it/pki/test);
#       plain connections are refused; client-cert also requires a client certificate (CN = user)
#   ex_db_create <server> [database]         the login DB_USER and its own new database, created
#                                            the default way (public keeps owner pg_database_owner)
#   ex_db_sql <server> <database> <sql>      SQL as DB_USER over the server's local socket
#   ex_preset <root> KEY=VALUE...            .env from the release template with these keys set
#                                            (each replaces the template's line, as an operator
#                                            edits it), before install
#   ex_install <root> <now|from> <port> [KEY=VALUE...]
#       unpack the package (or the older one), .env for the external database form (COMPOSE_FILE
#       is EX_CF when set; master key mode env, so the services come up unsealed and the key
#       fingerprints can be taken) plus these values, install from the offline bundle
#   ex_upgrade <root> <online|offline> [from]
#       upgrade to the package's release (with "from": to the older package, from the oldest);
#       offline with --images (no image from a registry), online without, the images pulled from
#       their registries (the scenario's host needs '# network: bridge'). Checks the upgrade's own
#       backup file; EX_X, EX_MF of it
#   ex_env <root> KEY=VALUE...               set keys in .env (KEY= for an empty value); -KEY removes
#   ex_backup <root> [sysca file]            backup --yes; EX_FILE, EX_OUT, EX_X (members), EX_MF
#   ex_refused <what> <pattern> <root> [sysca file]
#       backup refuses before any service stops: exit 3, the pattern, the services still running
#   ex_teardown <root>                       the deployment's containers, networks, volumes, folder
#
# The sysca file: a test-only read-only mount of that file over the system CA file of the
# PostgreSQL client containers the script starts (/etc/ssl/certs/ca-certificates.crt), through a
# docker wrapper first on the script's PATH; the release images and the script are unchanged.

readonly EX_USER=custodexa
readonly EX_DB=custodexa
readonly EX_PASS='it-test:only-db-user' # a ":" exercises the pgpass escaping
EX_ADDR=""
EX_N=0

ex_addr() {
  [ -n "$EX_ADDR" ] || EX_ADDR=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
  [ -n "$EX_ADDR" ] || it_die "no address on the default bridge"
  printf '%s' "$EX_ADDR"
}

ex_pg_start() {
  local name=$1 major=$2 port=$3 mode=${4:-plain} dir=$IT_WORK/pg/$1 addr i
  local -a mounts=() cmd=()
  addr=$(ex_addr)
  rm -rf "$dir"
  mkdir -p "$dir"
  if [ "$mode" != plain ]; then
    it_pki_cert test "$name" server "IP:$addr,DNS:localhost,IP:127.0.0.1"
    cp "$IT_PKI/test/ca.crt" "$dir/ca.crt"
    cp "$IT_PKI/test/$name.crt" "$dir/server.crt"
    cp "$IT_PKI/test/$name.key" "$dir/server.key"
    {
      printf 'local all all trust\nhostnossl all all all reject\n'
      if [ "$mode" = client-cert ]; then
        printf 'hostssl all all all scram-sha-256 clientcert=verify-full\n'
      else
        printf 'hostssl all all all scram-sha-256\n'
      fi
    } >"$dir/pg_hba.conf"
    chown -R "$IT_PG_UID:$IT_PG_UID" "$dir"
    chmod 600 "$dir/server.key"
    mounts=(-v "$dir:/etc/it-pg:ro")
    cmd=(-c ssl=on -c ssl_cert_file=/etc/it-pg/server.crt -c ssl_key_file=/etc/it-pg/server.key
      -c ssl_ca_file=/etc/it-pg/ca.crt -c hba_file=/etc/it-pg/pg_hba.conf)
  fi
  # PGPORT: the server's port, and the default of every psql run in the container.
  docker run -d --name "it-pg-$name" --network host -e PGPORT="$port" -e POSTGRES_PASSWORD="$IT_PG_PASSWORD" \
    ${mounts[@]+"${mounts[@]}"} "$(it_image "pg$major")" postgres ${cmd[@]+"${cmd[@]}"} >/dev/null
  for ((i = 0; i < IT_PG_READY_TRIES; i++)); do
    docker exec "it-pg-$name" pg_isready -q -h 127.0.0.1 -U postgres && return 0
    sleep 1
  done
  docker logs "it-pg-$name" 2>&1 | tail -n 20 >&2
  it_die "server $name (PostgreSQL $major) did not become ready"
}

ex_db_create() {
  local s=$1 db=${2:-$EX_DB}
  it_pg_sql "$s" postgres "DO \$\$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$EX_USER')
    THEN CREATE ROLE $EX_USER LOGIN PASSWORD '$EX_PASS'; END IF; END\$\$"
  it_pg_sql "$s" postgres "CREATE DATABASE \"$db\" OWNER $EX_USER"
}

ex_db_sql() {
  docker exec -i "it-pg-$1" psql -X -q -At -v ON_ERROR_STOP=1 -U "$EX_USER" -d "$2" -c "$3"
}

ex_install() {
  local root=$1 which=$2 port=$3 b cf=${EX_CF:-current/compose.yml:current/compose.external-database.yml}
  shift 3
  if [ "$which" = from ]; then
    it_unpack "${root%/*}" from
    b=$(it_bundle_file from)
  else
    it_unpack "${root%/*}"
    b=$(it_bundle_file)
  fi
  ex_preset "$root" "COMPOSE_FILE=$cf" "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$port" \
    "DB_NAME=$EX_DB" "DB_USER=$EX_USER" "DB_PASSWORD=$EX_PASS" KEK_PROVIDER=env "$@"
  it_cx "$root" install --images "$b"
}

# The template's own lines are replaced, not followed by a second line of the same key: a value
# left on an earlier line (DB_PASSWORD=postgres) is still read as a secret of the file.
ex_preset() {
  local root=$1
  shift
  [ -f "$root/.env" ] || install -m 600 "$root/current/.env.example" "$root/.env"
  ex_env "$root" "$@"
}

ex_env() {
  local root=$1 kv k
  shift
  for kv in "$@"; do
    k=${kv#-}
    k=${k%%=*}
    sed -i "/^[[:space:]]*$k=/d" "$root/.env"
    [ "${kv#-}" != "$kv" ] || printf '%s\n' "$kv" >>"$root/.env"
  done
}

# ex_shim: the docker wrapper. With IT_SYSCA set it adds the mount to each `docker run` of a
# PostgreSQL client tool (psql, pg_dump, pg_restore) and of the script's system CA file probe.
ex_shim() {
  mkdir -p "$IT_WORK/shim"
  cat >"$IT_WORK/shim/docker" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = run ] && [ -n "${IT_SYSCA:-}" ]; then
  prev=""
  for a in "$@"; do
    if [ "$prev" = --entrypoint ]; then
      case $a in psql | pg_dump | pg_restore | test)
        shift
        exec /usr/local/bin/docker run -v "$IT_SYSCA:/etc/ssl/certs/ca-certificates.crt:ro" "$@" ;;
      esac
    fi
    prev=$a
  done
fi
exec /usr/local/bin/docker "$@"
EOF
  chmod +x "$IT_WORK/shim/docker"
}

# ex_cx <sysca file|""> <root> <arguments>: custodexa.sh, through the wrapper when a file is given.
ex_cx() {
  local ca=$1
  shift
  if [ -z "$ca" ]; then
    it_cx "$@"
  else
    ex_shim
    IT_SYSCA=$ca PATH=$IT_WORK/shim:$PATH it_cx "$@"
  fi
}

ex_backup() {
  local root=$1 ca=${2:-} rc
  EX_N=$((EX_N + 1))
  touch "$IT_WORK/mark"
  sleep 1
  EX_OUT=$(ex_cx "$ca" "$root" backup --lang en --yes 2>&1) && rc=0 || rc=$?
  printf '%s\n' "$EX_OUT" | sed 's/^/   > /'
  it_same "backup exits 0" 0 "$rc"
  EX_FILE=$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark" | head -n1)
  it_check "one new backup file, its checksum file matches" \
    bash -c 'cd "${1%/*}" && sha256sum -c --quiet "${1##*/}.sha256"' _ "$EX_FILE"
  EX_X=$IT_WORK/x$EX_N
  rm -rf "$EX_X"
  mkdir -p "$EX_X"
  tar -xf "$EX_FILE" -C "$EX_X"
  it_check "the members match SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$EX_X"
  EX_MF=$EX_X/backup-manifest.json
  it_same "the manifest says db.location=external" external "$(ex_mf db.location)"
  it_same "no client container is left" "" "$(docker ps -aq --filter name=custodexa-backup-tool)"
  it_same "no pgpass file is left" "" "$(find "$root/backups" -name '.pgpass' -o -name '.db-client-*' | head -n1)"
}

ex_mf() { jq -r --arg k "$1" '.[$k] // ""' "$EX_MF"; }

# ex_running: the IDs of the running containers of the deployment.
ex_running() { docker ps -q --filter label=com.docker.compose.project | sort | tr '\n' ' '; }

ex_refused() {
  local what=$1 pattern=$2 root=$3 ca=${4:-} out rc before
  before=$(ex_running)
  out=$(ex_cx "$ca" "$root" backup --lang en --yes 2>&1) && rc=0 || rc=$?
  if [ "$rc" -ne 3 ] || ! grep -Eq -- "$pattern" <<<"$(tr '\n' ' ' <<<"$out" | tr -s ' ')"; then
    printf 'not ok - %s (exit %s, wanted 3 and: %s)\n' "$what" "$rc" "$pattern"
    printf '%s\n' "$out" | tail -n 30 | sed 's/^/   | /'
    return 1
  fi
  printf 'ok - %s (exit 3)\n' "$what"
  printf '%s\n' "$out" | grep -E 'not|Cannot|Owner|Custom|Extension|CA file|private key' | head -n 4 | sed 's/^/   > /' || true
  it_same "  ... before any service stopped (the same containers run, none restarted)" "$before" "$(ex_running)"
  it_same "  ... no backup file, no temporary folder" "" \
    "$(find "$root/backups" -maxdepth 1 \( -name '.partial-*' -o -name 'custodexa-backup-*.tar' \) -newer "$IT_WORK/mark")"
}

ex_teardown() {
  local ids
  ids=$(docker ps -aq --filter label=com.docker.compose.project)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  ids=$(docker ps -aq --filter name=custodexa-)
  # shellcheck disable=SC2086
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  docker network prune -f >/dev/null
  docker volume prune -af >/dev/null
  rm -rf "$1"
}

# ex_status <root> <version>: status passes (warnings only) and reports the backend at that version.
ex_status() {
  local out rc
  out=$(it_cx "$1" status --lang en) && rc=0 || rc=$?
  printf '%s\n' "$out" | sed 's/^/   > /'
  it_check "status exits 0 or 4 (warnings only), got $rc" test "$rc" = 0 -o "$rc" = 4
  it_same "status reports no failure" 0 "$(grep -c '\[FAIL\]' <<<"$out" || true)"
  it_check "status reports the backend healthy at $2" grep -qF "[ OK ] Backend healthy, version $2" <<<"$out"
  # shellcheck disable=SC2034 # read by the scenarios
  EX_STATUS=$out
}

ex_st() { jq -r --arg k "$2" '.[$k] // ""' "$1/state.json"; }

ex_upgrade() {
  local root=$1 how=$2 which=${3:-} to pkg bundle rc log f was
  pkg=$(it_package_file "$which")
  bundle=$(it_bundle_file "$which")
  to=$(jq -r .version "${pkg%/*}/MANIFEST.json")
  was=$(ex_st "$root" current.version)
  cp "$root/state.json" "$IT_WORK/state.before.json"
  EX_N=$((EX_N + 1))
  touch "$IT_WORK/mark"
  sleep 1
  if [ "$how" = online ]; then
    EX_OUT=$(it_cx "$root" upgrade "$pkg" --yes --lang en 2>&1) && rc=0 || rc=$?
  else
    EX_OUT=$(it_cx "$root" upgrade "$pkg" --images "$bundle" --yes --lang en 2>&1) && rc=0 || rc=$?
  fi
  printf '%s\n' "$EX_OUT" | sed 's/^/   > /'
  it_same "upgrade $was -> $to ($how) exits 0" 0 "$rc"
  log=$(find "$root/logs" -name 'upgrade-*.log' -newer "$IT_WORK/mark" | sort | tail -n 1)
  if [ "$how" = online ]; then
    it_check "the PostgreSQL clients of $to came from a registry" \
      bash -c '[ "$(grep -cE "IMAGE pgclient1[678] source=[a-z0-9-]+\.[a-z0-9.-]+ .* OK$" "$1")" = 3 ]' _ "$log"
  else
    it_same "no image came from a registry or was built" "" "$(grep -E 'IMAGE .* source=([a-z0-9-]+\.[a-z0-9.-]+|build) .* OK$' "$log")"
  fi
  it_same "upgrade recorded as succeeded" succeeded "$(ex_st "$root" last_upgrade.result)"
  it_same "current version is $to" "$to" "$(ex_st "$root" current.version)"
  f=$(ex_st "$root" last_upgrade.backup)
  it_check "last_upgrade.backup ($f) is a backup file named after $was" \
    grep -qE "^backups/custodexa-backup-${was//./\\.}-[0-9]{8}-[0-9]{6}\.tar$" <<<"$f"
  it_same "it is also the last backup" "$f" "$(ex_st "$root" last_backup.file)"
  it_check "its checksum file matches" bash -c 'cd "${1%/*}" && sha256sum -c --quiet "${1##*/}.sha256"' _ "$root/$f"
  it_same "no upgrade backup folder is made" "" "$(find "$root/backups" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -newer "$IT_WORK/mark")"
  EX_X=$IT_WORK/x$EX_N
  rm -rf "$EX_X"
  mkdir -p "$EX_X"
  tar -xf "$root/$f" -C "$EX_X"
  EX_MF=$EX_X/backup-manifest.json
  it_check "the members match SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$EX_X"
  it_same "trigger, contents.state, product.version" "upgrade true $was" \
    "$(ex_mf trigger) $(ex_mf contents.state) $(ex_mf product.version)"
  it_same "the state.json member is the state before the upgrade (current.version)" "$was" \
    "$(jq -r '."current.version"' "$EX_X/state.json")"
  it_check "the log names the snapshot before (${log##*/} .before.txt)" grep -qE "SNAPSHOT file=logs/upgrade-[0-9-]+\.before\.txt" "$log"
  it_check "the snapshot before equals the member snapshot.txt" cmp "${log%.log}.before.txt" "$EX_X/snapshot.txt"
  it_check "step 12 took the snapshot after (.after.txt) and it is usable" grep -qx 'usable=true' "${log%.log}.after.txt"
  it_same "users before = after the upgrade" "$(grep '^count\.users=' "${log%.log}.before.txt")" \
    "$(grep '^count\.users=' "${log%.log}.after.txt")"
}
