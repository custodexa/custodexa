#!/usr/bin/env bats
# Threat (A): the two ways to deploy ending up with different settings, a value the operator set
# being overwritten, or a secret echoed where it should not be. lib/env.sh copies the rules of
# scripts/quickstart.sh; this file runs both on the same template and compares the results.

load helper

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  cp /src/.env.example "$ROOT/current/.env.example"
  # quickstart.sh works on <tree>/.env next to <tree>/scripts/quickstart.sh.
  QS=$BATS_TEST_TMPDIR/qs
  mkdir -p "$QS/scripts"
  cp /src/scripts/quickstart.sh "$QS/scripts/"
  cp /src/.env.example "$QS/.env.example"
  # The same host for both: name, default route and addresses.
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  printf '#!/bin/sh\necho ops-host.example.internal\n' >"$FAKES/hostname"
  cat >"$FAKES/ip" <<'IP'
#!/bin/sh
case "$*" in
  *route*) echo "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.12 uid 0" ;;
  *addr*) printf '2: eth0    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\n3: docker0    inet 172.17.0.1/16 scope global docker0\n4: eth1    inet 10.20.5.20/24 scope global eth1\n' ;;
esac
IP
  chmod +x "$FAKES/hostname" "$FAKES/ip"
  export PATH="$FAKES:$PATH"
  load_lib
}

keys() { grep -oE '^[A-Z_][A-Z0-9_]*=' "$1" | sort; }
val() { cx_env_get "$1" "$2"; }
# Keys only the package deployment writes: its compose files and project name.
readonly PKG_ONLY='COMPOSE_FILE= COMPOSE_PROJECT_NAME='

run_quickstart() { (cd / && bash "$QS/scripts/quickstart.sh" >"$BATS_TEST_TMPDIR/qs.out" 2>&1); }

@test "same template: the same keys, the same non-secret values, secrets of the same shape" {
  for mode in ui env; do
    rm -f "$ROOT/.env" "$QS/.env"
    if [ "$mode" = env ]; then
      cp "$ROOT/current/.env.example" "$ROOT/.env"
      cx_env_set "$ROOT/.env" KEK_PROVIDER env
      cp "$ROOT/.env" "$QS/.env"
    fi
    run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
    cx_env_generate "$ROOT"
    local only
    only=$(comm -3 <(keys "$ROOT/.env") <(keys "$QS/.env") | tr -d '\t' | paste -sd' ' -)
    [ "$only" = "$PKG_ONLY" ] || { echo "[$mode] keys differ: $only"; return 1; }
    local k
    for k in $(keys "$QS/.env" | tr -d =); do
      case $k in JWT_SECRET | ENCRYPTION_KEY | ADMIN_INITIAL_PASSWORD | DB_PASSWORD | DATA_PATH) continue ;; esac
      [ "$(val "$ROOT/.env" "$k")" = "$(val "$QS/.env" "$k")" ] ||
        { echo "[$mode] $k: '$(val "$ROOT/.env" "$k")' vs quickstart '$(val "$QS/.env" "$k")'"; return 1; }
    done
    # Generated secrets: same length and alphabet as quickstart's, and not the template value.
    local a b
    for k in JWT_SECRET ENCRYPTION_KEY ADMIN_INITIAL_PASSWORD DB_PASSWORD; do
      a=$(val "$ROOT/.env" "$k") b=$(val "$QS/.env" "$k")
      [ "${#a}" -eq "${#b}" ] || { echo "[$mode] $k: ${#a} characters vs quickstart ${#b}"; return 1; }
      case $k in
        ADMIN_INITIAL_PASSWORD | DB_PASSWORD) [[ $a =~ ^[A-Za-z0-9]+$ ]] || { echo "[$mode] $k alphabet"; return 1; } ;;
        ENCRYPTION_KEY) [ -z "$a" ] || [[ $a =~ ^[0-9a-f]{64}$ ]] || { echo "[$mode] $k not hex"; return 1; } ;;
      esac
      [ -z "$a" ] || [ "$a" != "$b" ] || { echo "[$mode] $k identical to quickstart's: not generated"; return 1; }
    done
    [ "$(val "$ROOT/.env" JWT_SECRET)" != change-me-in-production-dev-secret ]
    [ "$mode" != ui ] || [ -z "$(val "$ROOT/.env" ENCRYPTION_KEY)" ]
    [ "$mode" != env ] || [ -n "$(val "$ROOT/.env" ENCRYPTION_KEY)" ]
  done
  # What the package adds: absolute data folder, this release's compose file, the fixed project.
  [ "$(val "$ROOT/.env" DATA_PATH)" = "$ROOT/data" ]
  [ "$(val "$ROOT/.env" COMPOSE_FILE)" = current/compose.yml ]
  [ "$(val "$ROOT/.env" COMPOSE_PROJECT_NAME)" = custodexa ]
  [ "$(stat -c %a "$ROOT/.env")" = 600 ]
}

@test "values already set are left exactly as they are" {
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  local -A set=(
    [JWT_SECRET]=operator-chosen-jwt-secret-value
    [DB_PASSWORD]=operator-db-password-1
    [ADMIN_INITIAL_PASSWORD]=operator-admin-pass-2
    [DATA_PATH]=/srv/custodexa-data
    [TLS_DOMAIN]=audit.example.org
    [TLS_IP_SAN]=10.9.9.9
    [PUBLIC_BASE_URL]=https://audit.example.org
    [TRUSTED_PROXIES]=10.1.0.0/16
  )
  local k
  for k in "${!set[@]}"; do cx_env_set "$ROOT/.env" "$k" "${set[$k]}"; done
  cx_env_generate "$ROOT"
  for k in "${!set[@]}"; do
    [ "$(val "$ROOT/.env" "$k")" = "${set[$k]}" ] || { echo "$k was changed"; return 1; }
  done
  [ -z "$CX_ENV_ADMIN_PASSWORD" ]
  [[ " $CX_ENV_GENERATED " != *" jwt "* && " $CX_ENV_GENERATED " != *" db "* ]] || return 1
  # A database folder already initialized keeps its password even if it is still the template one.
  cx_env_set "$ROOT/.env" DB_PASSWORD postgres
  mkdir -p /srv/custodexa-data/postgres && touch /srv/custodexa-data/postgres/PG_VERSION
  cx_env_generate "$ROOT"
  rm -rf /srv/custodexa-data
  [ "$(val "$ROOT/.env" DB_PASSWORD)" = postgres ]
}

@test "running twice leaves .env byte for byte the same" {
  cx_env_generate "$ROOT"
  cp "$ROOT/.env" "$BATS_TEST_TMPDIR/first"
  cx_env_generate "$ROOT"
  cmp "$ROOT/.env" "$BATS_TEST_TMPDIR/first"
  [ -z "$CX_ENV_GENERATED" ]
}

@test "only the password generated in this run is handed back; nothing is printed" {
  run cx_env_generate "$ROOT"
  [ "$status" -eq 0 ] && [ -z "$output" ] || return 1
  cx_env_generate "$ROOT" # second run: nothing new
  [ -z "$CX_ENV_ADMIN_PASSWORD" ]
  rm "$ROOT/.env"
  cx_env_generate "$ROOT" >"$BATS_TEST_TMPDIR/out" 2>&1
  [ -n "$CX_ENV_ADMIN_PASSWORD" ] && [ "$CX_ENV_ADMIN_PASSWORD" = "$(val "$ROOT/.env" ADMIN_INITIAL_PASSWORD)" ] || return 1
  [ ! -s "$BATS_TEST_TMPDIR/out" ]
}

@test "settings that cannot be honored stop with one line and generate nothing after it" {
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  cx_env_set "$ROOT/.env" COMPOSE_PROJECT_NAME other
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *"COMPOSE_PROJECT_NAME=other"* ]] || return 1
  [ "$(val "$ROOT/.env" JWT_SECRET)" = change-me-in-production-dev-secret ]
  cx_env_set "$ROOT/.env" COMPOSE_PROJECT_NAME custodexa
  cx_env_set "$ROOT/.env" COMPOSE_FILE docker-compose.yml
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *"COMPOSE_FILE=docker-compose.yml"* ]] || return 1
  cx_env_set "$ROOT/.env" COMPOSE_FILE current/compose.yml:current/compose.external-database.yml
  cx_env_set "$ROOT/.env" EXTERNAL_DB_HOST db.example.org
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *EXTERNAL_DB_HOST* ]] || return 1
  [ "$(val "$ROOT/.env" DB_PASSWORD)" = postgres ]
  cx_env_set "$ROOT/.env" EXTERNAL_DB_HOST ""
  cx_env_set "$ROOT/.env" KEK_PROVIDER vault
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *"KEK_PROVIDER=vault"* ]] || return 1
}

# A key written twice: docker compose uses the last line, so every reader here must too, and a value
# the script writes must land on that line (otherwise compose runs with a value nobody looked at).
@test "a key written twice: the last line is read and written, as compose reads it" {
  local f=$BATS_TEST_TMPDIR/dup.env
  printf '%s\n' 'DATA_PATH=./data' '# DATA_PATH=/commented' 'X=1' '  DATA_PATH="/srv/custodexa/data"' >"$f"
  [ "$(val "$f" DATA_PATH)" = /srv/custodexa/data ] || { echo "read: $(val "$f" DATA_PATH)"; return 1; }
  printf '%s\n' 'KEK_PROVIDER=env' 'KEK_PROVIDER=ui' >"$f"
  [ "$(val "$f" KEK_PROVIDER)" = ui ] || return 1
  cx_env_set "$f" KEK_PROVIDER kms
  [ "$(val "$f" KEK_PROVIDER)" = kms ] || { cat "$f"; return 1; }
  [ "$(head -n 1 "$f")" = KEK_PROVIDER=env ]
}
