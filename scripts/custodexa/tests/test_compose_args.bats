#!/usr/bin/env bats
# Threat (A): compose picking files on its own or the project name drifting. Without -p,
# --project-directory and -f, compose derives the project from the current directory and reads
# whatever docker-compose.yml it finds there, so the script would act on another stack.

load helper

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  load_lib
  use_fake_docker
  CX_ROOT=$ROOT
  cd "$BATS_TEST_TMPDIR"   # a directory holding no compose file of ours
}

@test "every call carries -p custodexa, --project-directory <root> and -f <root>/current/compose.yml" {
  CX_OVERLAYS="" cx_compose ps
  grep -qF $'ARGS\tcompose -p custodexa --project-directory '"$ROOT"' -f '"$ROOT"'/current/compose.yml ps' "$FAKE_DOCKER_LOG"
}

@test "overlays are added with -f in the recorded order" {
  CX_OVERLAYS="external-ingress external-database" cx_compose up -d
  grep -qF -- "-f $ROOT/current/compose.yml -f $ROOT/current/compose.external-ingress.yml -f $ROOT/current/compose.external-database.yml up -d" "$FAKE_DOCKER_LOG"
}

@test "an unknown overlay name is refused, compose is not called" {
  CX_OVERLAYS="../../etc/evil" run cx_compose ps
  [ "$status" -ne 0 ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "images.env of the current release is exported to compose" {
  printf 'CUSTODEXA_IMAGE_BACKEND=custodexa-local/backend:1.13.0\n' >"$ROOT/current/images.env"
  CX_OVERLAYS="" cx_compose up -d
  grep -qF 'IMG_BACKEND=custodexa-local/backend:1.13.0' "$FAKE_DOCKER_LOG"
}

@test "a malformed images.env line stops before compose runs" {
  printf 'CUSTODEXA_IMAGE_BACKEND=$(touch /tmp/pwned)\n' >"$ROOT/current/images.env"
  CX_OVERLAYS="" run cx_compose up -d
  [ "$status" -ne 0 ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "exception entry: old project name, old directory and old files are all passed" {
  cx_compose_explicit terminal-audit /srv/old /srv/old/docker-compose.yml /srv/old/docker-compose.external-ingress.yml -- stop backend
  grep -qF $'ARGS\tcompose -p terminal-audit --project-directory /srv/old -f /srv/old/docker-compose.yml -f /srv/old/docker-compose.external-ingress.yml stop backend' "$FAKE_DOCKER_LOG"
}

@test "exception entry refuses a missing project name, directory or file list" {
  run cx_compose_explicit "" /srv/old /srv/old/docker-compose.yml -- stop
  [ "$status" -ne 0 ]
  run cx_compose_explicit old "" /srv/old/docker-compose.yml -- stop
  [ "$status" -ne 0 ]
  run cx_compose_explicit old /srv/old -- stop
  [ "$status" -ne 0 ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "no code path calls docker compose except through lib/compose.sh" {
  # Messages may show commands for people to type; code may not. Comments are skipped.
  run bash -c "grep -nE '(^|[^#]*[;&|(]|^[[:space:]]*)docker[[:space:]]+compose|docker-compose[[:space:]]' '$SRC/custodexa.sh' '$SRC'/lib/*.sh | grep -v '^$SRC/lib/compose.sh:' | grep -vE ':[0-9]+:[[:space:]]*#'"
  [ -z "$output" ] || { echo "$output"; return 1; }
}

# ---- the package compose files: what must survive a container rebuild is mounted ----
PKG=${CX_TEST_REPO:-/src}/packaging
# service_block <file> <service>: the lines of one service, up to the next service or top-level key.
service_block() {
  awk -v s="  $2:" '$0 == s { on = 1; next } on && /^  [a-z][a-z0-9_-]*:/ { exit } on && /^[a-z]/ { exit } on' "$1"
}

@test "export artifacts: backend mounts DATA_PATH/exports where EXPORT_ARTIFACT_PATH points, in every form" {
  local b env mount
  b=$(service_block "$PKG/compose.yml" backend)
  [ -n "$b" ] || { echo "no backend service in compose.yml"; return 1; }
  env=$(sed -n 's/^      EXPORT_ARTIFACT_PATH: *//p' <<<"$b")
  mount=$(sed -n 's/^      - \${DATA_PATH:-\.\/data}\/exports:\([^: ]*\).*/\1/p' <<<"$b")
  [ -n "$env" ] || { echo "backend sets no EXPORT_ARTIFACT_PATH"; return 1; }
  [ -n "$mount" ] || { echo "backend does not mount DATA_PATH/exports"; return 1; }
  [ "$env" = "$mount" ] || { echo "EXPORT_ARTIFACT_PATH=$env but the mount is at $mount"; return 1; }
  [ "$env" = /var/lib/custodexa/exports ] || return 1
  # Only backend holds the artifacts (they include decrypted evidence).
  [ "$(grep -c '/exports:' "$PKG/compose.yml")" -eq 1 ] || return 1
  # The overlays add to compose.yml; none may drop the mount or move the path of backend.
  for f in "$PKG"/compose.external-*.yml; do
    b=$(service_block "$f" backend)
    if grep -Eq '^    volumes: *!(override|reset)|EXPORT_ARTIFACT_PATH' <<<"$b"; then
      echo "${f##*/} replaces the volumes or the export path of backend"
      return 1
    fi
  done
}
