#!/usr/bin/env bats
# The fixture of the conversion tests (tests/pgconvert_host.bash) itself: PG_VERSION of 16, 18 and
# none, a MANIFEST with and without bundled_db, a df that answers per place or fails, and the
# injections that wait on a phase in state.json. A fixture that cannot do what the later tests ask
# of it would turn their failures into noise.

load helper
load install_host
load backup_host
load upgrade_host
load pgconvert_host

setup() {
  backup_host ui
}

@test "PG_VERSION: 16 in the old layout, 18 under 18/docker, none for missing" {
  pgc_version 16
  [ "$(cat "$ROOT/data/postgres/PG_VERSION")" = 16 ] || return 1
  pgc_version 18 postgresql 18/docker
  [ "$(cat "$ROOT/data/postgresql/18/docker/PG_VERSION")" = 18 ] || return 1
  pgc_version missing postgresql 18/docker
  [ -d "$ROOT/data/postgresql/18/docker" ] || return 1
  [ ! -e "$ROOT/data/postgresql/18/docker/PG_VERSION" ] || return 1
}

@test "MANIFEST: with bundled_db the major, folder and PGDATA; without it none and a 16 tag" {
  pgc_manifest "$ROOT/releases/1.13.0" with
  [ "$(jq -c .bundled_db "$ROOT/releases/1.13.0/MANIFEST.json")" = '{"major":18,"data_dir":"postgresql","pgdata":"18/docker"}' ] || return 1
  [ "$(jq -r .images.postgres.tag "$ROOT/releases/1.13.0/MANIFEST.json")" = 18.6-alpine3.24 ] || return 1
  pgc_manifest "$ROOT/releases/1.13.0" without
  [ "$(jq -r '.bundled_db // "none"' "$ROOT/releases/1.13.0/MANIFEST.json")" = none ] || return 1
  [ "$(jq -r .images.postgres.tag "$ROOT/releases/1.13.0/MANIFEST.json")" = 16.15-alpine3.24 ] || return 1
}

@test "df: the four write places can sit on different file systems, and one can be unreadable" {
  host_free / 900000
  pgc_free backups 111
  pgc_free docker 222
  pgc_free data 333
  pgc_free pg 444
  [ "$(df -Pk "$ROOT/backups" | awk 'NR==2{print $4}')" = 111 ] || return 1
  [ "$(df -Pk /var/lib/docker | awk 'NR==2{print $4}')" = 222 ] || return 1
  [ "$(df -Pk "$ROOT/data" | awk 'NR==2{print $4}')" = 333 ] || return 1
  [ "$(df -Pk "$ROOT/data/postgresql" | awk 'NR==2{print $4}')" = 444 ] || return 1
  pgc_free docker none
  run df -Pk /var/lib/docker
  [ "$status" -ne 0 ] || return 1
  [ "$(df -Pk "$ROOT/backups" | awk 'NR==2{print $4}')" = 111 ] || return 1
}

@test "phase injection: a fail makes a docker call fail only while that phase is recorded" {
  : >"$FAKE_DOCKER_LOG"
  fake sleep ':'
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/db-hook" 2>/dev/null || true
  printf '#!/bin/bash\nexit 0\n' >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  pgc_phase_inject fail restore
  jq '."last_upgrade.db_convert.phase" = "dump"' "$ROOT/state.json" >"$ROOT/s.new" && mv "$ROOT/s.new" "$ROOT/state.json"
  run docker ps
  [ "$status" -eq 0 ] || { echo "dump: $status $output"; return 1; }
  jq '."last_upgrade.db_convert.phase" = "restore"' "$ROOT/state.json" >"$ROOT/s.new" && mv "$ROOT/s.new" "$ROOT/state.json"
  run docker ps
  [ "$status" -eq 1 ] || { echo "restore: $status $output"; return 1; }
  [ "$(pgc_state last_upgrade.db_convert.phase)" = restore ] || return 1
}
