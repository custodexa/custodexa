# shellcheck shell=bash
# The form of a deployment through the move from a published release to the working tree's
# version (scenarios form-upgrade, form-upgrade-old, form-old-backup). A deployment of one of the
# four forms is installed from the published package exactly as an operator of that release
# does (the notation of that release: COMPOSE_FILE overlays for 1.22 and before), then goes on.
#   fu_install <form>      form: builtin | extdb | ingress | both. Needs the published package at
#                          /published; extdb and both start PostgreSQL 17 first (fu_server)
#   fu_sentinel <n>        a record (an asset named it-sentinel-<n>) written through the API
#   fu_sentinels           how many sentinel records the database holds, and their names
#   fu_identity            the database's system_identifier, name and server_version_num, as the
#                          superuser asks the server itself (an external form only)
#   fu_names               the names of the running containers, sorted
#   fu_label               the compose service label of custodexa-frontend
#   fu_port                what `docker port custodexa-frontend` prints, one line
#   fu_no_overlay_lines    nothing outside the managed block of .env names COMPOSE_FILE or COMPOSE_PROFILES
#   fu_block               the managed block of .env
# FU_PORT is where the external server listens; FU_OLD is the published version.

readonly FU_PORT=15417 FU_SERVER=fu17
FU_FORM="" FU_OLD=""

fu_ext() { [ "$FU_FORM" = extdb ] || [ "$FU_FORM" = both ]; }
fu_ing() { [ "$FU_FORM" = ingress ] || [ "$FU_FORM" = both ]; }

fu_install() {
  local bundle
  FU_FORM=$1
  it_step "$FU_FORM: the published package and offline bundle"
  it_check "$FU_FORM: the published files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  bundle=$(find /published -maxdepth 1 -name 'custodexa-images-*.tar')
  mkdir -p /opt
  tar -xzf "$(find /published -maxdepth 1 -name 'custodexa-[0-9]*.tar.gz' | head -n1)" -C /opt
  FU_OLD=$(cat "$LV_ROOT/current/VERSION")
  local -a kv=(KEK_PROVIDER=env)
  local cf=current/compose.yml
  if fu_ext; then
    ex_pg_start "$FU_SERVER" 17 "$FU_PORT"
    ex_db_create "$FU_SERVER"
    # The published release has the old layout (1.22 and before): the external database is a COMPOSE_FILE overlay.
    cf+=:current/compose.external-database.yml
    kv+=("EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$FU_PORT" "DB_NAME=$EX_DB" "DB_USER=$EX_USER" "DB_PASSWORD=$EX_PASS")
  fi
  if fu_ing; then
    # Notation of the old layout (1.22 and before): the ingress overlay comes right after the base file.
    cf=current/compose.yml:current/compose.external-ingress.yml${cf#current/compose.yml}
  fi
  [ "$cf" = current/compose.yml ] || kv+=("COMPOSE_FILE=$cf")
  ex_preset "$LV_ROOT" "${kv[@]}"
  it_step "$FU_FORM: install $FU_OLD --images ${bundle##*/}"
  lv_cx install install --images "$bundle"
  it_same "$FU_FORM: install $FU_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$FU_OLD"
  LV_TOKEN=""
}

fu_sentinel() {
  lv_api POST /assets "$(jq -cn --arg n "it-sentinel-$1" '{name: $n, protocol: "ssh", host: "192.0.2.30", port: 22, description: "form test sentinel"}')" >/dev/null
}

fu_sql() {
  if fu_ext; then ex_db_sql "$FU_SERVER" "$EX_DB" "$1"; else lv_sql "$1"; fi
}
fu_sentinels() { fu_sql "SELECT count(*)||' '||coalesce(string_agg(name, ',' ORDER BY name), '') FROM assets WHERE name LIKE 'it-sentinel-%'"; }
fu_identity() {
  it_pg_sql "$FU_SERVER" postgres "SELECT (SELECT system_identifier FROM pg_control_system())||' '||current_database()||' '||current_setting('server_version_num')"
}
fu_names() { docker ps --format '{{.Names}}' | sort | paste -sd' '; }
fu_label() { docker inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' custodexa-frontend 2>/dev/null; }
fu_port() { docker port custodexa-frontend 2>/dev/null | paste -sd' '; }
fu_block() { sed -n '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/p' "$LV_ROOT/.env"; }
fu_outside() { sed '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d' "$LV_ROOT/.env"; }
fu_no_overlay_lines() { [ -z "$(fu_outside | grep -E '^[[:space:]]*COMPOSE_(FILE|PROFILES)=' || true)" ]; }
