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
  # ... and the libraries it takes its rules from (the deployment form: lib/form.sh and friends).
  mkdir -p "$QS/scripts/custodexa"
  cp -R "$SRC/lib" "$QS/scripts/custodexa/"
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
# Keys only the package deployment writes: its compose file and project name. The profiles of the
# managed block are written by both (a release of the profiles layout, see the first test).
readonly PKG_ONLY='COMPOSE_FILE= COMPOSE_PROJECT_NAME='

run_quickstart() { (cd / && bash "$QS/scripts/quickstart.sh" >"$BATS_TEST_TMPDIR/qs.out" 2>&1); }

@test "same template: the same keys, the same non-secret values, secrets of the same shape" {
  printf '{\n  "format": 1,\n  "compose_layout": "profiles"\n}\n' >"$ROOT/current/MANIFEST.json"
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
  # Notation of the old layout (1.22 and before): the external database written as an overlay.
  cx_env_set "$ROOT/.env" COMPOSE_FILE current/compose.yml:current/compose.external-database.yml
  cx_env_set "$ROOT/.env" EXTERNAL_DB_HOST db.example.org
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *EXTERNAL_DB_HOST* ]] || return 1
  [ "$(val "$ROOT/.env" DB_PASSWORD)" = postgres ]
  cx_env_set "$ROOT/.env" EXTERNAL_DB_HOST ""
  cx_env_set "$ROOT/.env" COMPOSE_FILE current/compose.yml
  cx_env_set "$ROOT/.env" KEK_PROVIDER vault
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *"KEK_PROVIDER=vault"* ]] || return 1
}

@test "the form comes from EXTERNAL_DB_HOST and TLS_MODE: only the address gives an external database, the block follows the release layout" {
  printf '{\n  "format": 1,\n  "compose_layout": "profiles"\n}\n' >"$ROOT/current/MANIFEST.json"
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  cx_env_set "$ROOT/.env" EXTERNAL_DB_HOST db.example.internal
  cx_env_set "$ROOT/.env" DB_PASSWORD secret-of-the-external-database
  cx_env_generate "$ROOT" >/dev/null
  [ "$CX_ENV_OVERLAYS" = external-database ]
  grep -qx 'COMPOSE_PROFILES=own-ingress' "$ROOT/.env" && return 1
  grep -qx 'COMPOSE_PROFILES=builtin-tls' "$ROOT/.env"
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$ROOT/.env"
  [ "$(grep -c '^COMPOSE_FILE=' "$ROOT/.env")" -eq 1 ]
  cx_env_set "$ROOT/.env" TLS_MODE external
  cx_env_generate "$ROOT" >/dev/null
  [ "$CX_ENV_OVERLAYS" = "external-ingress external-database" ]
  grep -qx 'COMPOSE_PROFILES=own-ingress' "$ROOT/.env"
  [ "$(grep -c '^COMPOSE_PROFILES=' "$ROOT/.env")" -eq 1 ]
}

@test "an old COMPOSE_FILE that agrees with the two keys is replaced by the block and reported; one that does not is refused" {
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  # Notation of the old layout (1.22 and before): the ingress written as an overlay.
  cx_env_set "$ROOT/.env" COMPOSE_FILE current/compose.yml:current/compose.external-ingress.yml
  cx_env_set "$ROOT/.env" TLS_MODE external
  cx_env_generate "$ROOT" >/dev/null
  [ "$CX_ENV_OVERLAYS" = external-ingress ]
  [[ $CX_FORM_MOVED == *'compose.external-ingress.yml'* ]]
  [ "$(grep -c '^COMPOSE_FILE=' "$ROOT/.env")" -eq 1 ]
  # the older layout keeps the old notation inside the block
  grep -qx 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml' "$ROOT/.env"
  cx_env_set "$ROOT/.env" TLS_MODE selfsigned
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *'TLS_MODE'* ]]
}

@test "an unknown TLS_MODE stops with the valid values" {
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  cx_env_set "$ROOT/.env" TLS_MODE letsencrypt
  run cx_env_generate "$ROOT"
  [ "$status" -eq 1 ] && [[ $output == *letsencrypt* && $output == *external* ]]
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

# Development stack: the compose file refuses to start without the test Vault's initialization token.
dev_form() { sed -i 's/^# *COMPOSE_FILE=docker-compose.dev.yml$/COMPOSE_FILE=docker-compose.dev.yml/' "$QS/.env"; }
plain_form() { sed -i 's/^COMPOSE_FILE=docker-compose.dev.yml$/# COMPOSE_FILE=docker-compose.dev.yml/' "$QS/.env"; }
qs_val() { awk -F= '/^VAULT_DEV_ROOT_TOKEN_ID=/ {sub(/^[^=]*=/, ""); print; exit}' "$QS/.env"; }

@test "Vault dev token: generated in the dev form only, never printed, kept on re-run and on switching back" {
  cp "$QS/.env.example" "$QS/.env"
  dev_form
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  local t
  t=$(qs_val)
  [[ $t =~ ^[A-Za-z0-9]{32}$ ]] || { echo "token: '$t'"; return 1; }
  ! grep -qF "$t" "$BATS_TEST_TMPDIR/qs.out"
  # (b) second run: unchanged
  run_quickstart
  [ "$(qs_val)" = "$t" ]
  # (c) a value the operator chose is kept as is
  sed -i 's/^VAULT_DEV_ROOT_TOKEN_ID=.*/VAULT_DEV_ROOT_TOKEN_ID=operator-vault-token/' "$QS/.env"
  run_quickstart
  [ "$(qs_val)" = operator-vault-token ]
  # (e) back to the production form: the line stays byte for byte, and the key is not mentioned
  plain_form
  run_quickstart
  grep -qx 'VAULT_DEV_ROOT_TOKEN_ID=operator-vault-token' "$QS/.env"
  ! grep -q VAULT_DEV_ROOT_TOKEN_ID "$BATS_TEST_TMPDIR/qs.out"
  # (d) a fresh .env in the production form gets no active line for the key
  rm -f "$QS/.env"
  run_quickstart
  ! grep -q '^VAULT_DEV_ROOT_TOKEN_ID=' "$QS/.env"
}

# The three single-file mount paths of the dev stack, relative to the source tree.
placeholder_paths() {
  PH_FILES=(backend/config/testdata/.env.example backend/cmd/server/testdata/release/VERSION backend/cmd/server/testdata/release/CHANGELOG.md)
}
# Fake docker for the --up runs: `compose up` fails unless the three mount points already exist.
placeholder_hook() {
  use_fake_docker
  cat >"$FAKE_DOCKER_REPLAY/hook" <<HOOK
#!/usr/bin/env bash
case " \$* " in
  *" compose "*" up "*)
    for f in ${PH_FILES[*]}; do [ -e "$QS/\$f" ] || { echo "missing mount point \$f" >&2; exit 1; }; done
    exit 0 ;;
  *" exec "*" wget "*) exit 0 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}
run_quickstart_up() { (cd / && bash "$QS/scripts/quickstart.sh" --up >"$BATS_TEST_TMPDIR/qs.out" 2>&1); }

@test "placeholder files for single-file mounts exist before compose up, and an existing one is untouched" {
  placeholder_paths
  placeholder_hook
  cp "$QS/.env.example" "$QS/.env"
  dev_form
  local f
  for f in "${PH_FILES[@]}"; do [ ! -e "$QS/$f" ] || return 1; done
  mkdir -p "$QS/$(dirname "${PH_FILES[1]}")"
  printf 'keep me\n' >"$QS/${PH_FILES[1]}"
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  grep -q 'compose up' "$FAKE_DOCKER_LOG"
  for f in "${PH_FILES[@]}"; do [ -e "$QS/$f" ] || { echo "missing $f"; return 1; }; done
  [ "$(cat "$QS/${PH_FILES[1]}")" = "keep me" ]
}

@test "placeholder files are not created without --up, nor in the production form with --up (not created)" {
  placeholder_paths
  placeholder_hook
  local f
  # Dev form, no --up.
  cp "$QS/.env.example" "$QS/.env"
  dev_form
  for f in "${PH_FILES[@]}"; do [ ! -e "$QS/$f" ] || return 1; done
  [ ! -e "$QS/backend/cmd/server/testdata/release" ]
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  for f in "${PH_FILES[@]}"; do [ ! -e "$QS/$f" ] || { echo "created without --up: $f"; return 1; }; done
  [ ! -e "$QS/backend/cmd/server/testdata/release" ]
  # Production form, with --up: the script must really reach `compose up`.
  rm -f "$QS/.env"
  : >"$FAKE_DOCKER_LOG"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$FAKE_DOCKER_REPLAY/hook"
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  grep -q 'compose up' "$FAKE_DOCKER_LOG"
  for f in "${PH_FILES[@]}"; do [ ! -e "$QS/$f" ] || { echo "created in production form: $f"; return 1; }; done
  [ ! -e "$QS/backend/cmd/server/testdata/release" ]
}

# The health wait is longer in the dev form (first start compiles the backend in the container).
health_timeout_in_message() {
  use_fake_docker
  mkdir -p "$BATS_TEST_TMPDIR/nosleep"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$BATS_TEST_TMPDIR/nosleep/sleep"
  chmod +x "$BATS_TEST_TMPDIR/nosleep/sleep"
  # Every call succeeds except the health probe.
  printf '#!/usr/bin/env bash\ncase " $* " in *" wget "*) exit 1 ;; esac\nexit 0\n' >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  run env PATH="$BATS_TEST_TMPDIR/nosleep:$PATH" bash -c "cd / && bash '$QS/scripts/quickstart.sh' --up"
  [ "$status" -eq 1 ]
}

@test "health wait: 1800 seconds in the dev form with a progress line, 120 seconds in the production form" {
  cp "$QS/.env.example" "$QS/.env"
  dev_form
  health_timeout_in_message
  [[ $output == *"did not report healthy within 1800s"* ]] || { echo "$output" | tail -n 5; return 1; }
  [[ $output == *"10 to 15 minutes"* ]]
  [[ $output == *"still waiting... 60s elapsed"* ]]
  plain_form
  health_timeout_in_message
  [[ $output == *"did not report healthy within 120s"* ]] || { echo "$output" | tail -n 5; return 1; }
  [[ $output != *"10 to 15 minutes"* ]]
}

# ---------------------------------------------------------------------------------------------
# The deployment form of a source deployment (scripts/quickstart.sh): derived from .env, kept in the
# managed block, translated from the old COMPOSE_FILE notation, refused where it would start a
# database with no data. The refusals must come before any docker call and leave .env as it was.
# ---------------------------------------------------------------------------------------------
readonly BLOCK_BEGIN='# >>> managed by custodexa.sh: derived from EXTERNAL_DB_HOST and TLS_MODE; do not edit'
readonly BLOCK_END='# <<< managed by custodexa.sh'
readonly EXTDB=db.example.internal

profiles_of() { awk -F= '/^COMPOSE_PROFILES=/ { print $2 }' "$1" | tail -n 1; }
sha_of() { sha256sum "$1" | cut -d' ' -f1; }
strip_block() { sed -i "/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d" "$1"; }
out_has() { grep -qF -- "$1" "$BATS_TEST_TMPDIR/qs.out" || { echo "output lacks: $1"; cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }; }
out_lacks() { if grep -qF -- "$1" "$BATS_TEST_TMPDIR/qs.out"; then echo "output has: $1"; return 1; fi; }
docker_untouched() { [ ! -s "$FAKE_DOCKER_LOG" ] || { echo "docker was called:"; cat "$FAKE_DOCKER_LOG"; return 1; }; }

# qs_env [KEY=VALUE...]: a complete production .env as 1.22 left it (every secret and address
# filled in, no managed block), then these keys. A key that is not there yet is appended.
qs_env() {
  local kv
  cp "$QS/.env.example" "$QS/.env"
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  strip_block "$QS/.env"
  for kv in "$@"; do cx_env_set "$QS/.env" "${kv%%=*}" "${kv#*=}"; done
}

# qs_refused <pattern...>: --up fails, every pattern is in the output, no docker call, .env unchanged.
qs_refused() {
  local before pat
  before=$(sha_of "$QS/.env")
  use_fake_docker
  if run_quickstart_up; then echo "quickstart.sh succeeded"; cat "$BATS_TEST_TMPDIR/qs.out"; return 1; fi
  for pat in "$@"; do out_has "$pat" || return 1; done
  docker_untouched || return 1
  [ "$(sha_of "$QS/.env")" = "$before" ] || { echo ".env changed"; return 1; }
}

# The package's own derivation on the same .env: the same profiles in the same block.
profiles_in_package() {
  printf '{\n  "format": 1,\n  "compose_layout": "profiles"\n}\n' >"$ROOT/current/MANIFEST.json"
  cp "$QS/.env" "$ROOT/.env"
  cx_env_generate "$ROOT" >/dev/null || return 1
  profiles_of "$ROOT/.env"
}

# The lines of .env outside the managed block that differ between two files, '<' before, '>' after.
env_delta() {
  diff <(sed '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d' "$1") \
    <(sed '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d' "$2") | grep '^[<>]' || true
}

# form_case <EXTERNAL_DB_HOST> <TLS_MODE> <profiles>
form_case() {
  local h
  qs_env "EXTERNAL_DB_HOST=$1" "TLS_MODE=$2"
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(profiles_of "$QS/.env")" = "$3" ] || { echo "[$1 $2] profiles: $(profiles_of "$QS/.env")"; return 1; }
  [ "$(grep -c '^COMPOSE_PROFILES=' "$QS/.env")" -eq 1 ] || return 1
  [ "$(grep -cxF "$BLOCK_BEGIN" "$QS/.env")" -eq 1 ] || return 1
  [ "$(tail -n 1 "$QS/.env")" = "$BLOCK_END" ] || return 1
  if grep -q '^COMPOSE_FILE=' "$QS/.env"; then echo "COMPOSE_FILE was written"; return 1; fi
  [ "$(profiles_in_package)" = "$3" ] || { echo "[$1 $2] the package derives $(profiles_in_package)"; return 1; }
  h=$(sha_of "$QS/.env")
  run_quickstart || return 1
  [ "$(sha_of "$QS/.env")" = "$h" ] || { echo "[$1 $2] the second run changed .env"; return 1; }
}

@test "form (source): bundled database, built-in HTTPS gives bundled-db,builtin-tls, as the package derives it" {
  form_case "" selfsigned bundled-db,builtin-tls
}
@test "form (source): external database, built-in HTTPS gives builtin-tls, as the package derives it" {
  form_case "$EXTDB" selfsigned builtin-tls
}
@test "form (source): bundled database, your own reverse proxy gives bundled-db,own-ingress, as the package derives it" {
  form_case "" external bundled-db,own-ingress
}
@test "form (source): external database, your own reverse proxy gives own-ingress, as the package derives it" {
  form_case "$EXTDB" external own-ingress
}

@test "form (source): the report names the form and the line it wrote" {
  qs_env "EXTERNAL_DB_HOST=$EXTDB" TLS_MODE=selfsigned
  run_quickstart || return 1
  out_has "deployment form          external database at $EXTDB:5432; built-in HTTPS (ports 443 and 80)" || return 1
  out_has "from EXTERNAL_DB_HOST ($EXTDB), TLS_MODE (selfsigned)" || return 1
  out_has "COMPOSE_PROFILES=builtin-tls" || return 1
  qs_env TLS_MODE=external HTTP_PORT=8080
  run_quickstart || return 1
  out_has "bundled database; your reverse proxy (port 8080)" || return 1
}

# translated <old COMPOSE_FILE> <db: 1 when EXTERNAL_DB_HOST is filled in> <profiles>
translated() {
  local cf=$1 delta
  if [ "$2" = 1 ]; then qs_env "COMPOSE_FILE=$cf" "EXTERNAL_DB_HOST=$EXTDB"; else qs_env "COMPOSE_FILE=$cf"; fi
  cp "$QS/.env" "$BATS_TEST_TMPDIR/before"
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(profiles_of "$QS/.env")" = "$3" ] || { echo "[$cf] profiles: $(profiles_of "$QS/.env")"; return 1; }
  out_has "removed  COMPOSE_FILE=$cf" || return 1
  out_has "COMPOSE_PROFILES=$3" || return 1
  if grep -q '^COMPOSE_FILE=' "$QS/.env"; then echo "COMPOSE_FILE is still there"; return 1; fi
  delta=$(env_delta "$BATS_TEST_TMPDIR/before" "$QS/.env")
  if [[ $cf == *external-ingress* ]]; then
    out_has "changed  TLS_MODE=selfsigned -> external" || return 1
    [ "$(grep -c '^TLS_MODE=external$' "$QS/.env")" -eq 1 ] || return 1
    [ "$delta" = "$(printf '%s\n' "< COMPOSE_FILE=$cf" "< TLS_MODE=selfsigned" "> TLS_MODE=external")" ] || { echo "delta: $delta"; return 1; }
  else
    out_lacks "changed  TLS_MODE" || return 1
    [ "$delta" = "< COMPOSE_FILE=$cf" ] || { echo "delta: $delta"; return 1; }
  fi
}

@test "form (source): an old COMPOSE_FILE for the external database is translated: only that line goes, the change is reported" {
  translated docker-compose.yml:docker-compose.external-database.yml 1 builtin-tls
}
@test "form (source): an old COMPOSE_FILE for the external ingress is translated: that line goes, TLS_MODE becomes external, both reported" {
  translated docker-compose.yml:docker-compose.external-ingress.yml 0 bundled-db,own-ingress
}
@test "form (source): an old COMPOSE_FILE for both is translated: that line goes, TLS_MODE becomes external" {
  translated docker-compose.yml:docker-compose.external-ingress.yml:docker-compose.external-database.yml 1 own-ingress
}

@test "form (source): after the translation a second run changes nothing and lists no change" {
  local h
  qs_env "COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml"
  run_quickstart || return 1
  h=$(sha_of "$QS/.env")
  run_quickstart || return 1
  [ "$(sha_of "$QS/.env")" = "$h" ] || { echo ".env changed on the second run"; return 1; }
  [ "$(profiles_of "$QS/.env")" = bundled-db,own-ingress ] || return 1
  if grep -Eq '^ +(removed|changed|added|updated) ' "$BATS_TEST_TMPDIR/qs.out"; then
    echo "the second run lists a change"
    cat "$BATS_TEST_TMPDIR/qs.out"
    return 1
  fi
}

@test "form (source): a translation that cannot write its temporary file stops with .env byte for byte the same; the rerun gives the translation" {
  qs_env "COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml"
  cp "$QS/.env" "$BATS_TEST_TMPDIR/before"
  # A directory that takes no new files: mktemp for a file next to .env fails.
  mkdir -p "$BATS_TEST_TMPDIR/nomk"
  printf '#!/bin/sh\ncase "$*" in *.env.tmp-*) exit 1 ;; esac\nexec /usr/bin/mktemp "$@"\n' >"$BATS_TEST_TMPDIR/nomk/mktemp"
  chmod +x "$BATS_TEST_TMPDIR/nomk/mktemp"
  if (cd / && PATH="$BATS_TEST_TMPDIR/nomk:$PATH" bash "$QS/scripts/quickstart.sh" >"$BATS_TEST_TMPDIR/qs.out" 2>&1); then
    echo "quickstart.sh succeeded"
    return 1
  fi
  cmp "$QS/.env" "$BATS_TEST_TMPDIR/before" || { echo ".env changed"; return 1; }
  [ -z "$(ls "$QS"/.env.tmp-* 2>/dev/null)" ] || { echo "a temporary file was left"; return 1; }
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(profiles_of "$QS/.env")" = bundled-db,own-ingress ] || return 1
  grep -q '^TLS_MODE=external$' "$QS/.env" || return 1
  [ "$(env_delta "$BATS_TEST_TMPDIR/before" "$QS/.env")" = "$(printf '%s\n' "< COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml" "< TLS_MODE=selfsigned" "> TLS_MODE=external")" ] || return 1
}

@test "form (source): the development form with an external address is refused before any docker call" {
  qs_env COMPOSE_FILE=docker-compose.dev.yml "EXTERNAL_DB_HOST=$EXTDB"
  qs_refused "EXTERNAL_DB_HOST=$EXTDB cannot be used with" "COMPOSE_FILE=docker-compose.dev.yml (the development stack)" \
    "comment out the" || return 1
}

@test "form (source): the development form with TLS_MODE=external is refused before any docker call" {
  qs_env COMPOSE_FILE=docker-compose.dev.yml TLS_MODE=external
  qs_refused "TLS_MODE=external cannot be used with" "an external database or TLS_MODE=external is not applied" || return 1
}

@test "form (source): the development form without those settings runs and writes no managed block" {
  qs_env COMPOSE_FILE=docker-compose.dev.yml
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  if grep -qxF "$BLOCK_BEGIN" "$QS/.env"; then echo "the development form wrote the block"; return 1; fi
  out_lacks "deployment form" || return 1
}

@test "form (source): an address that cannot name a database server is refused before any docker call" {
  qs_env EXTERNAL_DB_HOST=localhost
  qs_refused "EXTERNAL_DB_HOST=localhost cannot be used. Nothing was changed." "inside a container, localhost is the backend container itself" || return 1
  qs_env EXTERNAL_DB_HOST=postgres
  qs_refused "EXTERNAL_DB_HOST=postgres cannot be used" "service name of Custodexa itself" || return 1
  qs_env "EXTERNAL_DB_HOST=postgres://$EXTDB:6432"
  qs_refused "takes a host name or IP only" || return 1
}

@test "form (source): a port without an address, and a TLS_MODE that is none of the three, are refused before any docker call" {
  qs_env EXTERNAL_DB_PORT=6432
  qs_refused "EXTERNAL_DB_PORT=6432 is set but EXTERNAL_DB_HOST is empty." || return 1
  qs_env TLS_MODE=letsencrypt
  qs_refused "TLS_MODE=letsencrypt in .env is not a valid value" || return 1
}

@test "form (source): the last start was external (managed block) and the address is empty: refused before any docker call" {
  qs_env "EXTERNAL_DB_HOST=$EXTDB"
  run_quickstart || return 1
  [ "$(profiles_of "$QS/.env")" = builtin-tls ] || return 1
  cx_env_set "$QS/.env" EXTERNAL_DB_HOST ""
  qs_refused "EXTERNAL_DB_HOST is empty, but this deployment last started with an" \
    "COMPOSE_PROFILES=builtin-tls, no bundled-db" "Switching to an external database" "does not record the address" || return 1
}

@test "form (source): the last start was external (old COMPOSE_FILE) and the address is empty: refused before any docker call" {
  qs_env "COMPOSE_FILE=docker-compose.yml:docker-compose.external-database.yml"
  qs_refused "last started   with an external database (COMPOSE_FILE in .env lists" "docker-compose.external-database.yml" || return 1
}

@test "form (source): bundled data is there and an external address is filled in: refused with the data folder named" {
  qs_env
  mkdir -p "$QS/data/postgres"
  printf '16\n' >"$QS/data/postgres/PG_VERSION"
  cx_env_set "$QS/.env" EXTERNAL_DB_HOST "$EXTDB"
  qs_refused "EXTERNAL_DB_HOST=$EXTDB cannot be used: this deployment" "already has bundled database data" \
    "data in use    ./data/postgres    PostgreSQL 16" 'follow "Switching to an external' "keep using the bundled database" || return 1
}

@test "form (source): once the bundled data is moved away the same external address goes through" {
  qs_env
  mkdir -p "$QS/data/postgres"
  printf '16\n' >"$QS/data/postgres/PG_VERSION"
  cx_env_set "$QS/.env" EXTERNAL_DB_HOST "$EXTDB"
  mv "$QS/data/postgres" "$QS/data/postgres.before-external"
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(profiles_of "$QS/.env")" = builtin-tls ] || return 1
}

@test "form (source): a postgres container of this project with an empty data folder also counts as data" {
  local before
  qs_env "EXTERNAL_DB_HOST=$EXTDB"
  use_fake_docker
  printf '#!/usr/bin/env bash\ncase " $* " in *" ps -a "*) echo custodexa-postgres; exit 0 ;; esac\nexit 99\n' >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  before=$(sha_of "$QS/.env")
  if run_quickstart_up; then echo "succeeded"; return 1; fi
  out_has "data in use    container custodexa-postgres" || return 1
  if grep -q ' compose ' "$FAKE_DOCKER_LOG"; then echo "docker compose was called"; return 1; fi
  [ "$(sha_of "$QS/.env")" = "$before" ] || return 1
}

@test "form (source): the login URL of your own reverse proxy is http://localhost:<HTTP_PORT>/ without a CA link" {
  qs_env TLS_MODE=external HTTP_PORT=8080
  use_fake_docker
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "URL:      http://localhost:8080/" || return 1
  out_lacks "custodexa-ca.crt" || return 1
  grep -q 'compose up' "$FAKE_DOCKER_LOG" || return 1
}

@test "form (source): the login URL of the built-in HTTPS form is the https address with the CA link" {
  qs_env
  use_fake_docker
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "URL:      https://" || return 1
  out_has "custodexa-ca.crt" || return 1
}

@test "form (source): every docker compose call of --up carries the derived profiles in its environment" {
  qs_env "EXTERNAL_DB_HOST=$EXTDB"
  use_fake_docker
  printf '#!/usr/bin/env bash\ncase " $* " in *" compose "*) echo "PROFILES=$COMPOSE_PROFILES" >>"$FAKE_DOCKER_LOG" ;; esac\nexit 99\n' >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  grep -q '^PROFILES=builtin-tls$' "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  [ "$(grep -c '^PROFILES=' "$FAKE_DOCKER_LOG")" -ge 3 ] || { cat "$FAKE_DOCKER_LOG"; return 1; }
  if grep -q '^PROFILES=$' "$FAKE_DOCKER_LOG"; then echo "a compose call without profiles"; return 1; fi
}

@test "form (source): a public port held by another program stops the run before docker compose up, naming the program" {
  qs_env
  use_fake_docker
  mkdir -p "$BATS_TEST_TMPDIR/busy"
  printf '#!/bin/sh\ncase "$*" in *"sport = :443"*) echo "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\\"nginx\\",pid=77,fd=6))" ;; esac\n' >"$BATS_TEST_TMPDIR/busy/ss"
  chmod +x "$BATS_TEST_TMPDIR/busy/ss"
  if (cd / && PATH="$BATS_TEST_TMPDIR/busy:$PATH" bash "$QS/scripts/quickstart.sh" --up >"$BATS_TEST_TMPDIR/qs.out" 2>&1); then
    echo "quickstart.sh succeeded"
    return 1
  fi
  out_has "port 443 (https) is already in use by nginx (pid 77)" || return 1
  if grep -q 'compose up' "$FAKE_DOCKER_LOG"; then echo "compose up was called"; return 1; fi
}

@test "form (source): the ui master key mode ends with the initialization guidance, the URL and the admin account, and no key material" {
  qs_env KEK_PROVIDER=ui
  use_fake_docker
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "Initialize & login (in-memory master key mode)" || return 1
  out_has "URL:      https://" || return 1
  out_has "Account:  admin" || return 1
  out_has "SAVE IT SOMEWHERE SAFE" || return 1
  out_lacks "ENCRYPTION_KEY=" || return 1
}

@test "form (source): the development form's login URL is http://localhost:3000" {
  qs_env COMPOSE_FILE=docker-compose.dev.yml
  use_fake_docker
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "URL:      http://localhost:3000" || return 1
  out_lacks "custodexa-ca.crt" || return 1
}

@test "form (source): a host with no global IPv4 address leaves TLS_IP_SAN empty and the run goes on" {
  mkdir -p "$BATS_TEST_TMPDIR/noip"
  printf '#!/bin/sh\nexit 0\n' >"$BATS_TEST_TMPDIR/noip/ip"
  chmod +x "$BATS_TEST_TMPDIR/noip/ip"
  cp "$QS/.env.example" "$QS/.env"
  if ! (cd / && PATH="$BATS_TEST_TMPDIR/noip:$PATH" bash "$QS/scripts/quickstart.sh" >"$BATS_TEST_TMPDIR/qs.out" 2>&1); then
    cat "$BATS_TEST_TMPDIR/qs.out"
    return 1
  fi
  out_has "left empty (no non-loopback IPv4 address found)" || return 1
  [ "$(profiles_of "$QS/.env")" = bundled-db,builtin-tls ] || return 1
}

@test "form (source): a frontend container left by the other web service is replaced before compose up, one that fits is left alone" {
  local rm_line up_line
  qs_env TLS_MODE=external
  use_fake_docker
  printf '#!/usr/bin/env bash\ncase " $* " in *" inspect "*) echo frontend; exit 0 ;; esac\nexit 99\n' >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  run_quickstart_up || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "replaced (it ran as service frontend; this form runs frontend-published)" || return 1
  rm_line=$(grep -n 'rm -f custodexa-frontend' "$FAKE_DOCKER_LOG" | head -n 1 | cut -d: -f1)
  up_line=$(grep -n 'compose up' "$FAKE_DOCKER_LOG" | head -n 1 | cut -d: -f1)
  [ -n "$rm_line" ] && [ "$rm_line" -lt "$up_line" ] || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # the same container in the form it belongs to: nothing is removed
  qs_env TLS_MODE=selfsigned
  : >"$FAKE_DOCKER_LOG"
  run_quickstart_up || return 1
  if grep -q 'rm -f custodexa-frontend' "$FAKE_DOCKER_LOG"; then echo "the fitting container was removed"; return 1; fi
}

# Data an older release left in data/postgres is not read by the PostgreSQL 18 image, which would
# initialize an empty database in data/postgresql next to it.
old_data_hash() { (cd "$QS/data/postgres" && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1); }
old_data_seed() {
  mkdir -p "$QS/data/postgres/base"
  printf '16\n' >"$QS/data/postgres/PG_VERSION"
  printf 'rows\n' >"$QS/data/postgres/base/1"
}

@test "form (source): old data in data/postgres and nothing in data/postgresql: refused before any docker call, screen as approved, old folder untouched" {
  local before hash
  qs_env
  old_data_seed
  cx_env_set "$QS/.env" DB_PASSWORD postgres
  before=$(sha_of "$QS/.env")
  hash=$(old_data_hash)
  use_fake_docker
  if run_quickstart_up; then echo "quickstart.sh succeeded"; return 1; fi
  docker_untouched || return 1
  [ "$(sha_of "$QS/.env")" = "$before" ] || { echo ".env changed"; return 1; }
  [ "$(old_data_hash)" = "$hash" ] || { echo "old data changed"; return 1; }
  [ ! -e "$QS/data/postgresql" ] || [ -z "$(ls -A "$QS/data/postgresql")" ] || return 1
  # the whole screen, the size normalized: the text of the approved screen, word for word
  sed -E '1{/^$/d}; s/\(([0-9.]+ )?[KMGT]?i?B\)/(<size>)/' "$BATS_TEST_TMPDIR/qs.out" >"$BATS_TEST_TMPDIR/qs.norm"
  diff -u "$TESTS_DIR/snapshots/quickstart-old-data.en.txt" "$BATS_TEST_TMPDIR/qs.norm" || return 1
}

@test "form (source): old data in data/postgres, data/postgresql is empty but exists: refused the same way" {
  qs_env
  old_data_seed
  mkdir -p "$QS/data/postgresql"
  qs_refused "./data/postgres holds PostgreSQL 16 data" "./data/postgresql, which is empty" \
    'Follow "Moving a source deployment to' "docs/QUICKSTART.md" || return 1
}

@test "form (source): data in both folders: goes on, DB_PASSWORD is not changed, the output says the old folder is still there" {
  qs_env
  old_data_seed
  mkdir -p "$QS/data/postgresql/18/docker"
  printf '18\n' >"$QS/data/postgresql/18/docker/PG_VERSION"
  cx_env_set "$QS/.env" DB_PASSWORD postgres
  use_fake_docker
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(val "$QS/.env" DB_PASSWORD)" = postgres ] || return 1
  out_has "./data/postgresql is already initialized" || return 1
  out_has "./data/postgres is not used any more and was left in place" || return 1
}

@test "form (source): data in both folders and a complete .env (second run): the output still says the old folder is still there" {
  qs_env
  old_data_seed
  mkdir -p "$QS/data/postgresql/18/docker"
  printf '18\n' >"$QS/data/postgresql/18/docker/PG_VERSION"
  use_fake_docker
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_has "./data/postgresql is already initialized" || return 1
  out_has "./data/postgres is not used any more and was left in place" || return 1
}

@test "form (source): an external database is not checked for old data folders" {
  qs_env "EXTERNAL_DB_HOST=$EXTDB"
  # the old folder is there, the address is filled in: the data-in-use refusal applies (it names the
  # external address), not the old-major-data one, and nothing about PostgreSQL 18 is said
  old_data_seed
  use_fake_docker
  if run_quickstart_up; then echo "succeeded"; return 1; fi
  out_has "EXTERNAL_DB_HOST=$EXTDB cannot be used" || return 1
  out_lacks "This version runs" || return 1
  # without the old folder the same external form goes through with no old-data complaint
  mv "$QS/data/postgres" "$QS/data/postgres.moved"
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  out_lacks "This version runs" || return 1
}

@test "form (source): data only in data/postgresql: DB_PASSWORD stays whatever it is" {
  qs_env
  mkdir -p "$QS/data/postgresql/18/docker"
  printf '18\n' >"$QS/data/postgresql/18/docker/PG_VERSION"
  cx_env_set "$QS/.env" DB_PASSWORD postgres
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(val "$QS/.env" DB_PASSWORD)" = postgres ] || return 1
  out_has "./data/postgresql is already initialized" || return 1
  out_lacks "not used any more" || return 1
}

@test "form (source): an external database keeps the password you set, no local data folder involved" {
  qs_env "EXTERNAL_DB_HOST=$EXTDB" DB_PASSWORD=the-password-of-that-server
  run_quickstart || { cat "$BATS_TEST_TMPDIR/qs.out"; return 1; }
  [ "$(val "$QS/.env" DB_PASSWORD)" = the-password-of-that-server ] || return 1
  out_has "left as is (EXTERNAL_DB_HOST is set; the password belongs to that server)" || return 1
}

@test "form (source): an external database without its password stops the run and leaves .env alone" {
  local before
  qs_env "EXTERNAL_DB_HOST=$EXTDB" DB_PASSWORD=postgres
  before=$(sha_of "$QS/.env")
  if run_quickstart; then echo "succeeded"; return 1; fi
  out_has "DB_PASSWORD is empty or still the template value" || return 1
  [ "$(sha_of "$QS/.env")" = "$before" ] || return 1
}
