#!/usr/bin/env bats
# The package carries one compose file, and its MANIFEST says so (compose_layout: "profiles"). The
# management script reads that field to tell a release that is one file with profiles from an older
# one that is a base file plus overlays; a package that still shipped the overlay files, or a
# MANIFEST without the field, would make a new script drive a new release the old way. The other
# MANIFEST fields stay as they were.

load helper

V=1.23.0
BACKEND=sha256:$(printf 'b%.0s' {1..64})
FRONTEND=sha256:$(printf 'f%.0s' {1..64})

setup() {
  use_fake_docker
  # The build script in a repository layout of its own; the script tree and the compose file are
  # the ones under test.
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

@test "the release folder holds compose.yml and no overlay file" {
  build
  [ -f "$REL/compose.yml" ]
  [ "$(find "$REL" -maxdepth 1 -name 'compose*.yml' | wc -l)" -eq 1 ] || { ls "$REL"; return 1; }
  # Not a fixture: the two overlay files of the old layout (1.22 and before) must be gone from the release.
  [ ! -e "$REL/compose.external-database.yml" ]
  [ ! -e "$REL/compose.external-ingress.yml" ]
}

@test "the MANIFEST names the layout, in the package and beside it" {
  build
  [ "$(jq -r .compose_layout "$REL/MANIFEST.json")" = profiles ]
  [ "$(jq -r .compose_layout "$OUT/MANIFEST.json")" = profiles ]
  cmp "$OUT/MANIFEST.json" "$REL/MANIFEST.json"
}

@test "the other MANIFEST fields are the ones a release always had" {
  build
  [ "$(jq -c 'del(.compose_layout, .bundled_db) | keys_unsorted' "$REL/MANIFEST.json")" = \
    '["format","version","min_source_version","released_at","migrations","runtime_markers","images","rollback_compatible","source","notes"]' ]
  [ "$(jq -r .version "$REL/MANIFEST.json")" = "$V" ]
  [ "$(jq -r '.images | keys | length' "$REL/MANIFEST.json")" = 9 ]
}

@test "the compose file in the package is filled in and still has the two web services" {
  build
  ! grep -qE '@@[A-Z_]+@@' "$REL/compose.yml" || return 1
  grep -q "^  frontend:" "$REL/compose.yml"
  grep -q "^  frontend-published:" "$REL/compose.yml"
  grep -q "ghcr.io/custodexa/frontend:$V@$FRONTEND" "$REL/compose.yml"
}
