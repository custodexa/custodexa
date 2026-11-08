#!/usr/bin/env bats
# The bundled database of the package compose (packaging/compose.yml) from 1.23 on: PostgreSQL 18.6
# on alpine, the same pin as the pgclient18 tool image of the release build, the data folder mounted
# one level up (/var/lib/postgresql, the image's own VOLUME), no PGDATA. The same facts are read by
# `docker compose config` in the release evidence; a bats runner has no
# daemon, so this file reads the file.

setup() {
  REPO=$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)
  COMPOSE=$REPO/packaging/compose.yml
  BUILD=$REPO/scripts/release/build-package.sh
  # The postgres service block: from "  postgres:" to the next service at the same indent.
  awk '/^  postgres:/{f=1; print; next} f && /^  [a-z]/{exit} f{print}' "$COMPOSE" >"$BATS_TEST_TMPDIR/postgres.block"
}

@test "the postgres image is 18.6 on alpine3.24 and pinned by digest" {
  grep -qE 'image: \$\{CUSTODEXA_IMAGE_POSTGRES:-postgres:18\.6-alpine3\.24@sha256:[0-9a-f]{64}\}' "$BATS_TEST_TMPDIR/postgres.block" \
    || { cat "$BATS_TEST_TMPDIR/postgres.block"; return 1; }
}

@test "the digest is the one of the pgclient18 pin in the release build" {
  want=$(sed -n 's/^pgclient18 postgres:18\.6-alpine3\.24@//p' "$BUILD")
  [ -n "$want" ] || return 1
  grep -qF "postgres:18.6-alpine3.24@$want" "$BATS_TEST_TMPDIR/postgres.block" || return 1
}

@test "the data folder is mounted at /var/lib/postgresql, from DATA_PATH/postgresql" {
  grep -qF -- '- ${DATA_PATH:-./data}/postgresql:/var/lib/postgresql' "$BATS_TEST_TMPDIR/postgres.block" || return 1
  ! grep -qE '/var/lib/postgresql/data' "$BATS_TEST_TMPDIR/postgres.block" || return 1
}

@test "no PGDATA is set anywhere in the compose file (comments may name it)" {
  grep -v '^[[:space:]]*#' "$COMPOSE" >"$BATS_TEST_TMPDIR/compose.active"
  [ -s "$BATS_TEST_TMPDIR/compose.active" ] || return 1
  ! grep -q 'PGDATA' "$BATS_TEST_TMPDIR/compose.active" || return 1
}

@test "the pin comment no longer says a new major needs pg_upgrade" {
  ! grep -q 'pg_upgrade' "$COMPOSE" || return 1
}
