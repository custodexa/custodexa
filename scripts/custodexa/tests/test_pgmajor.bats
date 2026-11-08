#!/usr/bin/env bats
# lib/pgmajor.sh: which PostgreSQL major a release's bundled database is, where its data lives, and
# what the data folder on disk really holds. A mismatch between what is on disk and what the server
# says stops the caller; the library never guesses. Return codes: 0 agree, 2 no PG_VERSION, 3 the
# server says another major.

load helper

setup() {
  load_lib
  # shellcheck source=scripts/custodexa/lib/pgmajor.sh
  . "$SRC/lib/pgmajor.sh"
  D=$BATS_TEST_TMPDIR/data
  mkdir -p "$D"
}

# manifest <json file content from jq>: load a MANIFEST.json written the way build-package writes it.
manifest() {
  jq -n "$1" >"$BATS_TEST_TMPDIR/MANIFEST.json"
  cx_manifest_load "$BATS_TEST_TMPDIR/MANIFEST.json"
}

new_manifest='{format: 1, version: "1.23.0", images: {postgres: {ref: "docker.io/library/postgres", tag: "18.6-alpine3.24"}},
  bundled_db: {major: 18, data_dir: "postgresql", pgdata: "18/docker"}}'
old_manifest='{format: 1, version: "1.22.0", images: {postgres: {ref: "docker.io/library/postgres", tag: "16.15-alpine3.24"}}}'

@test "a release with bundled_db: its fields are the answer" {
  manifest "$new_manifest"
  cx_pgm_release_db || return 1
  [ "$CX_PGM_MAJOR $CX_PGM_DATA_DIR $CX_PGM_PGDATA" = "18 postgresql 18/docker" ] || return 1
}

@test "an older release without bundled_db: 16 in data/postgres, read from the image tag" {
  manifest "$old_manifest"
  cx_pgm_release_db || return 1
  [ "$CX_PGM_MAJOR $CX_PGM_DATA_DIR [$CX_PGM_PGDATA]" = "16 postgres []" ] || { echo "$CX_PGM_MAJOR $CX_PGM_DATA_DIR [$CX_PGM_PGDATA]"; return 1; }
}

@test "a release with neither bundled_db nor a postgres tag it can read is refused" {
  manifest '{format: 1, version: "1.0.0", images: {postgres: {tag: "latest"}}}'
  run cx_pgm_release_db
  [ "$status" -ne 0 ] || return 1
}

@test "the data folder says 16: the major read from PG_VERSION" {
  mkdir -p "$D/postgres"
  printf '16\n' >"$D/postgres/PG_VERSION"
  run cx_pgm_dir_major "$D" postgres ""
  [ "$status" -eq 0 ] && [ "$output" = 16 ] || { echo "$status $output"; return 1; }
}

@test "the data folder says 18, under the pgdata of the release" {
  mkdir -p "$D/postgresql/18/docker"
  printf '18\n' >"$D/postgresql/18/docker/PG_VERSION"
  run cx_pgm_dir_major "$D" postgresql 18/docker
  [ "$status" -eq 0 ] && [ "$output" = 18 ] || { echo "$status $output"; return 1; }
}

@test "no PG_VERSION: refused with 2 and nothing printed" {
  mkdir -p "$D/postgresql/18/docker"
  run cx_pgm_dir_major "$D" postgresql 18/docker
  [ "$status" -eq 2 ] && [ -z "$output" ] || { echo "$status $output"; return 1; }
}

@test "a PG_VERSION that is not a number is refused with 2" {
  mkdir -p "$D/postgres"
  printf 'sixteen\n' >"$D/postgres/PG_VERSION"
  run cx_pgm_dir_major "$D" postgres ""
  [ "$status" -eq 2 ] || { echo "$status $output"; return 1; }
}

@test "server_version_num to major: 160015 is 16 and 180006 is 18" {
  [ "$(cx_pgm_server_major 160015)" = 16 ] || return 1
  [ "$(cx_pgm_server_major 180006)" = 18 ] || return 1
  run cx_pgm_server_major abc
  [ "$status" -ne 0 ] || return 1
}

@test "the check: disk 16 and server 160015 agree" {
  mkdir -p "$D/postgres"
  printf '16\n' >"$D/postgres/PG_VERSION"
  cx_pgm_check "$D" postgres "" 160015 || return 1
  [ "$CX_PGM_FOUND" = 16 ] || return 1
}

@test "the check: no server number given, the disk alone decides" {
  mkdir -p "$D/postgresql/18/docker"
  printf '18\n' >"$D/postgresql/18/docker/PG_VERSION"
  cx_pgm_check "$D" postgresql 18/docker || return 1
  [ "$CX_PGM_FOUND" = 18 ] || return 1
}

@test "the check: disk 16 but the server says 18 stops with 3" {
  mkdir -p "$D/postgres"
  printf '16\n' >"$D/postgres/PG_VERSION"
  run cx_pgm_check "$D" postgres "" 180006
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
}

@test "the check: a missing PG_VERSION stops with 2 even when the server answers" {
  mkdir -p "$D/postgres"
  run cx_pgm_check "$D" postgres "" 160015
  [ "$status" -eq 2 ] || { echo "$status $output"; return 1; }
}
