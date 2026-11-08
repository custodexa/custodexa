#!/usr/bin/env bats
# The deployment form comes from two keys of .env and from nothing else. A derivation that read the
# environment, trusted a value that points back at this stack or at the backend container itself, or
# named the wrong services for a release would start another stack than the one .env describes.
# Also here: the managed block of .env (the only lines the script writes there).

load helper

setup() {
  load_lib
  E=$BATS_TEST_TMPDIR/env
}

derive() { printf '%s\n' "$@" >"$E"; cx_form_derive "$E"; }
# form_is <form> <.env lines...>: the derivation succeeds and gives that form (an empty form is the
# built-in one, so the exit code is checked as well as the words).
form_is() {
  local got
  got=$(derive "${@:2}") || { echo "derive failed: ${*:2}"; return 1; }
  [ "$got" = "$1" ] || { echo "${*:2}: '$got', not '$1'"; return 1; }
}

@test "derive: no EXTERNAL_DB_HOST and no TLS_MODE is the built-in form" {
  form_is "" 'DB_USER=postgres'
}

@test "derive: EXTERNAL_DB_HOST with a value (blanks around it ignored) is the external database" {
  form_is external-database 'EXTERNAL_DB_HOST=db.example.internal'
  form_is external-database 'EXTERNAL_DB_HOST=  db.example.internal  '
  form_is external-database "EXTERNAL_DB_HOST='db.example.internal'"
}

@test "derive: an empty or blank EXTERNAL_DB_HOST is the built-in database" {
  form_is "" 'EXTERNAL_DB_HOST='
  form_is "" 'EXTERNAL_DB_HOST=   '
}

@test "derive: TLS_MODE selfsigned, provided and empty are the built-in proxy" {
  form_is "" 'TLS_MODE=selfsigned'
  form_is "" 'TLS_MODE=provided'
  form_is "" 'TLS_MODE='
}

@test "derive: TLS_MODE=external is your own ingress; both together keep the recorded word order" {
  form_is external-ingress 'TLS_MODE=external'
  form_is "external-ingress external-database" 'TLS_MODE=external' 'EXTERNAL_DB_HOST=db.example.internal'
}

@test "derive: any other TLS_MODE is refused and the value is kept" {
  printf 'TLS_MODE=letsencrypt\n' >"$E"
  run cx_form_derive "$E"
  [ "$status" -ne 0 ]
  cx_form_derive "$E" || true
  [ "$CX_FORM_BAD" = letsencrypt ]
}

@test "derive: the shell environment is not read" {
  printf 'DB_USER=postgres\n' >"$E"
  local got
  got=$(EXTERNAL_DB_HOST=db.other.internal TLS_MODE=external cx_form_derive "$E") || return 1
  [ "$got" = "" ]
}

@test "host check: names of this stack are refused as service" {
  local v
  for v in postgres custodexa-postgres backend frontend guacd tls-proxy custodexa-backend POSTGRES; do
    run cx_form_check_host "$v"
    [ "$status" -ne 0 ] || { echo "$v passed"; return 1; }
    cx_form_check_host "$v" || true
    [ "$CX_FORM_REASON" = service ] || { echo "$v: $CX_FORM_REASON"; return 1; }
  done
}

@test "host check: loopback and wildcard addresses are refused as loopback" {
  local v
  for v in localhost LOCALHOST 127.0.0.1 127.1.2.3 ::1 0.0.0.0 ::; do
    cx_form_check_host "$v" && { echo "$v passed"; return 1; }
    [ "$CX_FORM_REASON" = loopback ] || { echo "$v: $CX_FORM_REASON"; return 1; }
  done
}

@test "host check: a port, a scheme, blanks or quotes are refused as syntax" {
  local v
  for v in db.example.internal:6432 postgres://db.example.internal postgresql://db:5432/x "db example" 'db"x' "db'x" 10.0.0.40:5432; do
    cx_form_check_host "$v" && { echo "$v passed"; return 1; }
    [ "$CX_FORM_REASON" = syntax ] || { echo "$v: $CX_FORM_REASON"; return 1; }
  done
}

@test "host check: host names, IPv4 and IPv6 addresses and the host's own address pass" {
  local v
  for v in db.example.internal db01 10.0.0.40 172.16.0.5 fd00::5 host.docker.internal; do
    cx_form_check_host "$v" || { echo "$v refused: $CX_FORM_REASON"; return 1; }
  done
}

@test "profiles: the four forms" {
  [ "$(cx_form_profiles "")" = bundled-db,builtin-tls ]
  [ "$(cx_form_profiles "external-database")" = builtin-tls ]
  [ "$(cx_form_profiles "external-ingress")" = bundled-db,own-ingress ]
  [ "$(cx_form_profiles "external-ingress external-database")" = own-ingress ]
}

@test "services: the layout of the release picks the web service (eight combinations)" {
  [ "$(cx_form_services overlays "")" = frontend ]
  [ "$(cx_form_services overlays "external-database")" = frontend ]
  [ "$(cx_form_services overlays "external-ingress")" = frontend ]
  [ "$(cx_form_services overlays "external-ingress external-database")" = frontend ]
  [ "$(cx_form_services profiles "")" = frontend ]
  [ "$(cx_form_services profiles "external-database")" = frontend ]
  [ "$(cx_form_services profiles "external-ingress")" = frontend-published ]
  [ "$(cx_form_services profiles "external-ingress external-database")" = frontend-published ]
}

@test "layout: a MANIFEST with compose_layout profiles, in either JSON spacing; anything else is overlays" {
  local d=$BATS_TEST_TMPDIR/rel
  mkdir -p "$d"
  [ "$(cx_form_layout "$d")" = overlays ]
  printf '{"version":"1.22.0"}' >"$d/MANIFEST.json"
  [ "$(cx_form_layout "$d")" = overlays ]
  printf '{"compose_layout": "profiles"}' >"$d/MANIFEST.json"
  [ "$(cx_form_layout "$d")" = profiles ]
  printf '{"compose_layout":"profiles"}' >"$d/MANIFEST.json"
  [ "$(cx_form_layout "$d")" = profiles ]
}

# ---- the managed block ----
env_file() {
  printf '%s\n' '# a comment' 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db.example.internal' 'TLS_MODE=selfsigned' '' 'PORT=1' >"$E"
  chmod 600 "$E"
}
other_lines_hash() { grep -vE '^(COMPOSE_FILE|COMPOSE_PROFILES)=|managed by custodexa.sh' "$E" | sha256sum; }

@test "managed block: profiles layout writes the fixed COMPOSE_FILE and the profiles; the rest is unchanged" {
  env_file
  local before
  before=$(other_lines_hash)
  cx_env_sync_managed "$E" profiles "external-database"
  [ "$(other_lines_hash)" = "$before" ]
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$E"
  grep -qx 'COMPOSE_PROFILES=builtin-tls' "$E"
  tail -n 1 "$E" | grep -q '^# <<< managed by custodexa.sh'
  [ "$(stat -c %a "$E")" = 600 ]
}

@test "managed block: overlays layout writes one of the four old COMPOSE_FILE values and no profiles" {
  env_file
  # The four COMPOSE_FILE values of the old layout (1.22 and before).
  cx_env_sync_managed "$E" overlays "external-ingress external-database"
  grep -qx 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml:current/compose.external-database.yml' "$E"
  ! grep -q '^COMPOSE_PROFILES=' "$E" || return 1
  cx_env_sync_managed "$E" overlays "external-database"
  grep -qx 'COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml' "$E"
  # Value of the old layout (1.22 and before) for an external ingress.
  cx_env_sync_managed "$E" overlays "external-ingress"
  grep -qx 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml' "$E"
  cx_env_sync_managed "$E" overlays ""
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$E"
}

@test "managed block: a second run changes nothing" {
  env_file
  cx_env_sync_managed "$E" profiles ""
  local once
  once=$(sha256sum <"$E")
  cx_env_sync_managed "$E" profiles ""
  [ "$(sha256sum <"$E")" = "$once" ]
}

@test "managed block: COMPOSE_FILE and COMPOSE_PROFILES outside the block move into it and are reported" {
  env_file
  # A COMPOSE_FILE line of the old layout (1.22 and before) left outside the block.
  printf '%s\n' 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml' 'COMPOSE_PROFILES=x' >>"$E"
  local before
  before=$(other_lines_hash)
  cx_env_sync_managed "$E" profiles "external-database"
  [ "$(other_lines_hash)" = "$before" ]
  [ "$(grep -c '^COMPOSE_FILE=' "$E")" -eq 1 ]
  [ "$(grep -c '^COMPOSE_PROFILES=' "$E")" -eq 1 ]
  # The moved line is reported as written, in the notation of the old layout (1.22 and before).
  [[ $CX_FORM_MOVED == *COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml* ]]
}

@test "managed block: the layout of the release switches the block, other lines stay byte for byte" {
  env_file
  cx_env_sync_managed "$E" profiles "external-database"
  local before
  before=$(other_lines_hash)
  cx_env_sync_managed "$E" overlays "external-database"
  [ "$(other_lines_hash)" = "$before" ]
  ! grep -q '^COMPOSE_PROFILES=' "$E" || return 1
}
