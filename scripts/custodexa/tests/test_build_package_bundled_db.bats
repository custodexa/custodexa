#!/usr/bin/env bats
# The bundled database of a release: its MANIFEST names the major version and where the data lives
# (bundled_db), the image is the same pin as the PostgreSQL 18 client, a non-alpine image stops the
# build, and rollback_compatible never lists a version whose bundled major differs.

load helper

V=1.23.0
BACKEND=sha256:$(printf 'b%.0s' {1..64})
FRONTEND=sha256:$(printf 'f%.0s' {1..64})

setup() {
  use_fake_docker
  R=$BATS_TEST_TMPDIR/repo
  mkdir -p "$R/scripts/release"
  cp "$SRC/../release/build-package.sh" "$SRC/../release/migrations-json.sh" "$R/scripts/release/"
  ln -s "$SRC" "$R/scripts/custodexa"
  ln -s "$SRC/../../packaging" "$R/packaging"
  S=$BATS_TEST_TMPDIR/public
  mkdir -p "$S/docker/reverse-proxy" "$S/backend/internal/database" "$S/scripts/release"
  printf 'DB_USER=postgres\n' >"$S/.env.example"
  printf '#!/bin/sh\n' >"$S/docker/reverse-proxy/tls-init.sh"
  printf 'server {}\n' >"$S/docker/reverse-proxy/nginx-tls.conf.template"
  printf '%s\n' 'package database' 'const BaselineVersion = "20260816_schema_baseline"' \
    'var migrations = []Migration{' '	{Version: "20260816_schema_baseline"},' '}' \
    'const LdapSeedMarkerVersion = "20260804_ldap_env_seeded"' \
    'const OffsiteSeedMarkerVersion = "20260825_offsite_env_seeded"' \
    'const CredentialSecretsMarkerVersion = "20260906_credential_secrets_converted"' \
    'const ApproverScopeKeyMarkerVersion = "20261030_approver_scope_management_key"' \
    'var runtimeMarkerVersions = []string{' '	LdapSeedMarkerVersion,' '	OffsiteSeedMarkerVersion,' \
    '	CredentialSecretsMarkerVersion,' '	ApproverScopeKeyMarkerVersion,' '}' \
    >"$S/backend/internal/database/migrations.go"
  jq -n --arg v "$V" --arg b "$BACKEND" --arg f "$FRONTEND" '{version: $v, images: {
      backend: {digest: $b, ghcr: ("ghcr.io/custodexa/backend@" + $b)},
      frontend: {digest: $f, ghcr: ("ghcr.io/custodexa/frontend@" + $f)}}}' >"$BATS_TEST_TMPDIR/digests.json"
  jq -n --arg c "sha256:$(printf 'c%.0s' {1..64})" '{
      manifests: [{platform: {os: "linux", architecture: "amd64"}, digest: $c},
                  {platform: {os: "linux", architecture: "arm64"}, digest: $c}],
      config: {digest: $c, size: 10}, layers: [{size: 100}]}' \
    >"$FAKE_DOCKER_REPLAY/buildx_imagetools_inspect_--raw.out"
  OUT=$BATS_TEST_TMPDIR/out
  mkdir -p "$BATS_TEST_TMPDIR/rehearsals"
}

build() {
  rm -rf "$OUT"
  run bash "$R/scripts/release/build-package.sh" --digests "$BATS_TEST_TMPDIR/digests.json" --source "$S" \
    --out "$OUT" --released-at 2026-11-06T10:00:00+08:00 "$@"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  rm -rf "$BATS_TEST_TMPDIR/unpacked"
  mkdir -p "$BATS_TEST_TMPDIR/unpacked"
  tar -xzf "$OUT/custodexa-$V.tar.gz" -C "$BATS_TEST_TMPDIR/unpacked"
  REL=$BATS_TEST_TMPDIR/unpacked/custodexa/releases/$V
}

# build_fails <pattern> [options]: the build stops, prints the pattern, and leaves no MANIFEST.json.
build_fails() {
  local pattern=$1
  shift
  rm -rf "$OUT"
  run bash "$R/scripts/release/build-package.sh" --digests "$BATS_TEST_TMPDIR/digests.json" --source "$S" \
    --out "$OUT" --released-at 2026-11-06T10:00:00+08:00 "$@"
  [ "$status" -ne 0 ] || { echo "the build passed"; return 1; }
  [ ! -e "$OUT/MANIFEST.json" ] || { echo "a MANIFEST.json was left"; return 1; }
  grep -Eq -- "$pattern" <<<"$output" || { echo "no '$pattern' in: $output"; return 1; }
}

@test "bundled_db names major 18, the data folder and the PGDATA of the image, in both MANIFESTs" {
  build
  want='{"major":18,"data_dir":"postgresql","pgdata":"18/docker"}'
  [ "$(jq -c .bundled_db "$REL/MANIFEST.json")" = "$want" ] || return 1
  [ "$(jq -c .bundled_db "$OUT/MANIFEST.json")" = "$want" ] || return 1
}

@test "the bundled database image is PostgreSQL 18.6 on alpine, the same pin as pgclient18" {
  build
  [ "$(jq -r '.images.postgres.tag' "$REL/MANIFEST.json")" = 18.6-alpine3.24 ] || return 1
  [ "$(jq -r '.images.postgres.index_digest' "$REL/MANIFEST.json")" = \
    "$(jq -r '.images.pgclient18.index_digest' "$REL/MANIFEST.json")" ] || return 1
}

@test "the other MANIFEST fields keep their order, bundled_db is the last one" {
  build
  [ "$(jq -c 'keys_unsorted' "$REL/MANIFEST.json")" = \
    '["format","version","min_source_version","released_at","migrations","runtime_markers","images","rollback_compatible","source","notes","compose_layout","bundled_db"]' ] || return 1
  [ "$(jq -r '.images | keys | length' "$REL/MANIFEST.json")" = 9 ] || return 1
}

@test "a bundled database image that is not alpine stops the build and leaves no MANIFEST" {
  rm -f "$R/packaging"
  cp -R "$SRC/../../packaging" "$R/packaging"
  sed -i.bak -E 's#(postgres:[0-9.]+)-alpine[0-9.]*(@sha256)#\1\2#' "$R/packaging/compose.yml"
  grep -qE 'postgres:[0-9.]+@sha256' "$R/packaging/compose.yml" || { echo "fixture edit did not apply"; return 1; }
  build_fails 'alpine'
}

@test "rollback-compatible naming a version with another bundled major stops the build" {
  build_fails 'bundled database.*1\.22\.0|1\.22\.0.*bundled database' \
    --rollback-compatible 1.22.0 --rehearsals-dir "$BATS_TEST_TMPDIR/rehearsals"
}
