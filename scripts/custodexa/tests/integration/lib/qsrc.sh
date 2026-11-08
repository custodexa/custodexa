# shellcheck shell=bash
# A source deployment (git clone plus scripts/quickstart.sh) on the integration host.
#
# The host has no network, so the images are loaded, not built: the package's offline bundle gives
# the backend, frontend, guacd and nginx images of the release the run is built on, retagged to the
# names docker-compose.yml wants; PostgreSQL and openssl come from the scenario's `# images:` line.
# A docker wrapper first on PATH skips `docker compose build` (and nothing else); every call goes to
# $QS_LOG.
#
#   qs_images                        load the bundle, tag the images the way docker-compose.yml names them
#   qs_tree <dir> [legacy]           the files quickstart.sh needs, from the working tree; with "legacy"
#                                    the compose files of 1.22 (a base file and two overlay files)
#   qs_env <dir> KEY=VALUE...        .env from the template (once) with these keys set; -KEY removes
#   qs_run <dir> [args]              quickstart.sh from the tree, through the wrapper; QS_OUT, QS_RC
#   qs_profiles <dir>                COMPOSE_PROFILES in the managed block
#   qs_down <dir>                    remove every container of the compose project and its network
#   qs_sentinel <where> <db> <value> write one row where: bundled, or the name of an external server
#   qs_sentinel_get <where> <db>

QS_LOG=$IT_WORK/qs-docker-calls.log
QS_BIN=$IT_WORK/qs-bin

qs_images() {
  local f ref repo
  f=$(it_bundle_file)
  docker load -i "$f" >/dev/null
  while read -r ref; do
    repo=${ref%%:*}
    case $repo in
      */backend) docker tag "$ref" custodexa/backend:latest ;;
      */frontend) docker tag "$ref" custodexa/frontend:latest ;;
      nginx) docker tag "$ref" nginx:stable-alpine ;;
      guacamole/guacd) docker tag "$ref" guacamole/guacd:1.6.0 ;;
    esac
  done < <(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>')
  it_check "the images docker-compose.yml names are all here" bash -c '
    for i in custodexa/backend:latest custodexa/frontend:latest nginx:stable-alpine postgres:16.15-alpine3.24 \
      alpine/openssl:3.5.4; do docker image inspect "$i" >/dev/null || { echo "missing $i"; exit 1; }; done'
  mkdir -p "$QS_BIN"
  cat >"$QS_BIN/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${QS_LOG:?}"
if [ "${1:-}" = compose ]; then
  for a in "$@"; do
    [ "$a" != build ] || { echo "(build skipped: the images are loaded)"; exit 0; }
  done
fi
exec /usr/local/bin/docker "$@"
EOF
  chmod +x "$QS_BIN/docker"
}

qs_tree() {
  local d=$1 f
  rm -rf "$d"
  mkdir -p "$d/scripts/custodexa" "$d/docker"
  cp /src/.env.example /src/VERSION "$d/"
  cp /src/scripts/quickstart.sh "$d/scripts/"
  cp -R /src/scripts/custodexa/lib "$d/scripts/custodexa/"
  cp -R /src/docker/reverse-proxy "$d/docker/"
  if [ "${2:-}" = legacy ]; then
    f=/src/scripts/custodexa/tests/integration/fixtures/compose-1.22
    cp "$f/base.yml" "$d/docker-compose.yml"
    cp "$f/database.yml" "$d/docker-compose.external-database.yml"
    cp "$f/ingress.yml" "$d/docker-compose.external-ingress.yml"
    cp /src/docker-compose.dev.yml "$d/"
  else
    cp /src/docker-compose.yml /src/docker-compose.dev.yml "$d/"
  fi
  qs_guacd_by_tag "$d"
}

# qs_guacd_by_tag <dir>: the one change to a compose file here. The guacd reference carries a digest,
# which a loaded image cannot satisfy (compose would try to pull it); the loaded image has the tag.
qs_guacd_by_tag() {
  sed -i 's|image: guacamole/guacd:1.6.0@sha256:[0-9a-f]*|image: guacamole/guacd:1.6.0|' "$1/docker-compose.yml"
}

# qs_pull_new_compose <dir>: what updating a 1.22 clone to this tree does to the compose files: the
# base file is the new one and the two overlay files are gone.
qs_pull_new_compose() {
  cp /src/docker-compose.yml "$1/docker-compose.yml"
  rm -f "$1/docker-compose.external-database.yml" "$1/docker-compose.external-ingress.yml"
  qs_guacd_by_tag "$1"
}

qs_env() {
  local d=$1 kv k
  shift
  [ -f "$d/.env" ] || install -m 600 "$d/.env.example" "$d/.env"
  for kv in "$@"; do
    k=${kv#-}
    k=${k%%=*}
    sed -i "/^[[:space:]]*$k=/d" "$d/.env"
    [ "${kv#-}" != "$kv" ] || printf '%s\n' "$kv" >>"$d/.env"
  done
}

qs_run() {
  local d=$1
  shift
  QS_RC=0
  QS_OUT=$(cd "$d" && PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG bash scripts/quickstart.sh "$@" 2>&1) || QS_RC=$?
  printf '%s\n' "$QS_OUT" | sed 's/^/   > /' | tail -n 40
}

qs_profiles() { awk -F= '/^COMPOSE_PROFILES=/ { print $2 }' "$1/.env" | tail -n 1; }

qs_down() {
  local ids
  ids=$(docker ps -aq --filter label=com.docker.compose.project)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  ids=$(docker ps -aq --filter name=custodexa-)
  # shellcheck disable=SC2086
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  docker network ls -q --filter label=com.docker.compose.project | xargs -r docker network rm >/dev/null 2>&1 || true
}

# qs_sql <where> <db> <sql>: bundled = the deployment's postgres container, else an external server.
qs_sql() {
  if [ "$1" = bundled ]; then
    docker exec -i custodexa-postgres psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d "$2" -c "$3"
  else
    ex_db_sql "$1" "$2" "$3"
  fi
}

qs_sentinel() {
  qs_sql "$1" "$2" "CREATE TABLE IF NOT EXISTS it_sentinel (v text); INSERT INTO it_sentinel VALUES ('$3')"
}
qs_sentinel_get() { qs_sql "$1" "$2" "SELECT string_agg(v, ',') FROM it_sentinel"; }

# qs_backend_env <name>: one variable of the backend container.
qs_backend_env() {
  docker inspect custodexa-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n "s/^$1=//p"
}

# qs_wait_db <where> <db>: the database answers (a restarted container needs a moment).
qs_wait_db() {
  local i
  for ((i = 0; i < 60; i++)); do
    qs_sql "$1" "$2" "SELECT 1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  it_die "database $1/$2 does not answer"
}
