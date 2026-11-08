#!/usr/bin/env bats
# One compose file serves every form of a release with the profiles layout: the form is passed as
# COMPOSE_PROFILES. A release without that layout keeps its overlay files. A call that names the
# wrong web service, leaves the caller's form keys in the environment, or removes a running web
# container would act on another stack than the one the form describes.

load helper

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  load_lib
  use_fake_docker
  CX_ROOT=$ROOT
  cd "$BATS_TEST_TMPDIR"
}

profiles_layout() {
  printf '{"compose_layout": "profiles"}\n' >"$ROOT/current/MANIFEST.json"
  cp "$SRC/../../packaging/compose.yml" "$ROOT/current/compose.yml"
}

# env_hook: the fake docker records the call and the form-related environment it was started with.
env_hook() {
  ENVLOG=$BATS_TEST_TMPDIR/env.log
  : >"$ENVLOG"
  {
    printf '#!/bin/bash\n{ echo "ARGS $*"; echo "PROFILES=${COMPOSE_PROFILES-unset}"; echo "CF=${COMPOSE_FILE-unset}"\n'
    printf 'echo "DBH=${EXTERNAL_DB_HOST-unset}"; echo "TLS=${TLS_MODE-unset}"; } >>%s\nexit 99\n' "$ENVLOG"
  } >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

@test "profiles layout: one -f and COMPOSE_PROFILES for each of the four forms" {
  profiles_layout
  env_hook
  local forms=("" "external-database" "external-ingress" "external-ingress external-database")
  local want=(bundled-db,builtin-tls builtin-tls bundled-db,own-ingress own-ingress)
  local i
  for i in 0 1 2 3; do
    : >"$ENVLOG"
    CX_OVERLAYS="${forms[i]}" cx_compose up -d
    [ "$(grep -c '^ARGS compose' "$ENVLOG")" -eq 1 ] || { cat "$ENVLOG"; return 1; }
    grep -qF "ARGS compose -p custodexa --project-directory $ROOT -f $ROOT/current/compose.yml up -d" "$ENVLOG"
    grep -qx "PROFILES=${want[i]}" "$ENVLOG" || { echo "form '${forms[i]}'"; cat "$ENVLOG"; return 1; }
  done
}

@test "overlays layout: the base file and the overlays of the form, no profiles, for each of the four forms" {
  env_hook
  local forms=("" "external-database" "external-ingress" "external-ingress external-database")
  # The overlay files of the old layout (1.22 and before), one -f list per form.
  local files=("" " -f $ROOT/current/compose.external-database.yml" " -f $ROOT/current/compose.external-ingress.yml" \
    " -f $ROOT/current/compose.external-ingress.yml -f $ROOT/current/compose.external-database.yml")
  local i
  for i in 0 1 2 3; do
    : >"$ENVLOG"
    CX_OVERLAYS="${forms[i]}" cx_compose ps
    grep -qF -- "-f $ROOT/current/compose.yml${files[i]} ps" "$ENVLOG" || { echo "form '${forms[i]}'"; cat "$ENVLOG"; return 1; }
    grep -qx "PROFILES=unset" "$ENVLOG"
  done
}

@test "the web service name follows the layout and the form (eight combinations)" {
  local layout form want
  for layout in overlays profiles; do
    for form in "" external-database external-ingress "external-ingress external-database"; do
      want=frontend
      if [ "$layout" = profiles ] && [[ " $form " == *" external-ingress "* ]]; then want=frontend-published; fi
      [ "$(cx_form_services "$layout" "$form")" = "$want" ] || { echo "$layout '$form'"; return 1; }
    done
  done
}

@test "lib/ names no web service literally in a stop, start, up or remove" {
  run bash -c "grep -rnE '\\b(stop|start|up|rm)\\b.*\\bfrontend\\b' '$SRC/lib/' | grep -vE ':[0-9]+:[[:space:]]*#' | grep -v 'cx_form_services' | grep -v 'lib/compose.sh:'"
  [ -z "$output" ] || { echo "$output"; return 1; }
  # The container name of the hand-over is a compose.sh matter; elsewhere it names containers to check.
  run bash -c "grep -rln 'rm custodexa-frontend' '$SRC/lib/' | grep -v 'lib/compose.sh\$'"
  [ -z "$output" ] || { echo "$output"; return 1; }
}

# frontend_hook <running: true|false> <service label>: the fake docker answers `docker inspect`.
frontend_hook() {
  printf '#!/bin/bash\n[ "$1" = inspect ] && { echo "%s %s"; exit 0; }\nexit 99\n' "$1" "$2" >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

@test "hand-over: a stopped custodexa-frontend of the other service is removed before up" {
  profiles_layout
  frontend_hook false frontend
  CX_OVERLAYS="external-ingress" cx_compose up -d
  local rmn upn
  rmn=$(grep -n $'ARGS\trm custodexa-frontend' "$FAKE_DOCKER_LOG" | cut -d: -f1)
  upn=$(grep -n $'ARGS\tcompose .* up -d' "$FAKE_DOCKER_LOG" | cut -d: -f1)
  [ -n "$rmn" ] && [ -n "$upn" ] && [ "$rmn" -lt "$upn" ] || { cat "$FAKE_DOCKER_LOG"; return 1; }
}

@test "hand-over: a container of the wanted service is left alone" {
  profiles_layout
  frontend_hook false frontend-published
  CX_OVERLAYS="external-ingress" cx_compose up -d
  ! grep -q $'ARGS\trm ' "$FAKE_DOCKER_LOG" || return 1
}

@test "hand-over: a running container of the other service is not removed and the step fails" {
  profiles_layout
  frontend_hook true frontend
  CX_OVERLAYS="external-ingress" run cx_compose up -d
  [ "$status" -ne 0 ]
  ! grep -q $'ARGS\trm ' "$FAKE_DOCKER_LOG" || return 1
  ! grep -q $'ARGS\tcompose .* up' "$FAKE_DOCKER_LOG" || return 1
}

@test "controlled environment: form keys and COMPOSE_FILE of the caller never reach compose" {
  profiles_layout
  env_hook
  EXTERNAL_DB_HOST=db.other.internal TLS_MODE=external COMPOSE_FILE=x.yml CX_OVERLAYS="" cx_compose up -d
  grep -qx "DBH=unset" "$ENVLOG" || { cat "$ENVLOG"; return 1; }
  grep -qx "TLS=unset" "$ENVLOG"
  grep -qx "CF=unset" "$ENVLOG"
}
