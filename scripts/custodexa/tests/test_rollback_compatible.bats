#!/usr/bin/env bats
# A release that lists an earlier version in rollback_compatible lets a deployment whose database
# that release changed go straight back to the earlier version, with no restore. The rehearsal
# record is the only thing that stands behind such a line. A build that accepts a record holding
# only "PASS", one missing a step or a field, one written for other versions, or one that tested
# other images (the same version number rebuilt) would ship that promise without proof; each case
# below expects the build to stop, name the file and the field, and leave no MANIFEST.json.

load helper

V=1.16.2
BACKEND=sha256:$(printf 'b%.0s' {1..64})
FRONTEND=sha256:$(printf 'f%.0s' {1..64})

setup() {
  use_fake_docker
  # The build script and its reader in a repository layout of their own; the script tree and the
  # compose files are the ones under test. The rehearsal records are in a folder of their own,
  # named with --rehearsals-dir.
  R=$BATS_TEST_TMPDIR/repo
  mkdir -p "$R/scripts/release" "$BATS_TEST_TMPDIR/rehearsals"
  cp "$SRC/../release/build-package.sh" "$SRC/../release/migrations-json.sh" "$R/scripts/release/"
  ln -s "$SRC" "$R/scripts/custodexa"
  ln -s "$SRC/../../packaging" "$R/packaging"
  REC=$BATS_TEST_TMPDIR/rehearsals
  # A public tree with what the package copies from it.
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
    'var runtimeMarkerVersions = []string{' '	LdapSeedMarkerVersion,' '	OffsiteSeedMarkerVersion,' \
    '	CredentialSecretsMarkerVersion,' '}' \
    >"$S/backend/internal/database/migrations.go"
  jq -n --arg v "$V" --arg b "$BACKEND" --arg f "$FRONTEND" '{version: $v, images: {
      backend: {digest: $b, ghcr: ("ghcr.io/custodexa/backend@" + $b)},
      frontend: {digest: $f, ghcr: ("ghcr.io/custodexa/frontend@" + $f)}}}' >"$BATS_TEST_TMPDIR/digests.json"
  # Every image index and manifest the build reads from a registry: two platforms, one config.
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
    --out "$OUT" --released-at 2026-11-02T10:00:00+08:00 "$@"
}

# record <from> [edits...]: the rehearsal record of $V from <from>, complete and for these images,
# then each edit: first=<line> | drop=<key> | set=<key>=<value> | dup=<key> | only-first.
record() {
  local from=$1 f=$REC/$V-from-$1.txt e k
  shift
  printf '%s\n' PASS "date: 2026-11-02" "operator: release-operator" "from: $from" "to: $V" \
    "to_backend_digest: $BACKEND" "to_frontend_digest: $FRONTEND" \
    "step1_upgrade: PASS sudo /opt/custodexa/custodexa.sh upgrade $V --yes" \
    "step2_write: PASS users, assets, a recorded connection, a policy change" \
    "step3_rollback: PASS sudo /opt/custodexa/custodexa.sh rollback --yes" \
    "step4_old_readwrite: PASS the same reads and writes on $from, no error in the logs" >"$f"
  for e in "$@"; do
    case $e in
      first=*) sed -i "1s/.*/${e#first=}/" "$f" ;;
      drop=*) sed -i "/^${e#drop=}:/d" "$f" ;;
      set=*) k=${e#set=}; sed -i "s|^${k%%=*}:.*|${k%%=*}: ${k#*=}|" "$f" ;;
      dup=*) k=$(grep "^${e#dup=}:" "$f"); printf '%s\n' "$k" >>"$f" ;;
      only-first) printf 'PASS\n' >"$f" ;;
    esac
  done
}

# refused <field text> <flag value>: the build stops, names the text, and writes no MANIFEST.json.
refused() {
  build --rollback-compatible "$2" --rehearsals-dir "$REC"
  [ "$status" -ne 0 ] || { echo "accepted: $1"; return 1; }
  [ ! -e "$OUT/MANIFEST.json" ] || { echo "MANIFEST.json written: $1"; return 1; }
  [[ $output == *"$1"* ]] || { echo "message lacks '$1': $output"; return 1; }
}

@test "rollback_compatible: without the flag the list is empty, as before" {
  build
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -c .rollback_compatible "$OUT/MANIFEST.json")" = '[]' ]
}

@test "rollback_compatible: records are read only from --rehearsals-dir, never from beside the script" {
  # A folder of records alone lists nothing.
  record 1.16.1
  build --rehearsals-dir "$REC"
  [ "$status" -eq 0 ] && [ "$(jq -c .rollback_compatible "$OUT/MANIFEST.json")" = '[]' ] || { echo "$output"; return 1; }
  # A version listed without the folder stops the build, even with a record beside the script.
  mkdir -p "$R/scripts/release/rollback-rehearsals"
  cp "$REC/$V-from-1.16.1.txt" "$R/scripts/release/rollback-rehearsals/"
  build --rollback-compatible 1.16.1
  [ "$status" -ne 0 ] && [ ! -e "$OUT/MANIFEST.json" ] && [[ $output == *"--rollback-compatible needs --rehearsals-dir"* ]] \
    || { echo "$status $output"; return 1; }
  build --rollback-compatible 1.16.1 --rehearsals-dir "$BATS_TEST_TMPDIR/none"
  [ "$status" -ne 0 ] && [ ! -e "$OUT/MANIFEST.json" ] && [[ $output == *"--rehearsals-dir: no such folder"* ]] \
    || { echo "$status $output"; return 1; }
}

@test "rollback_compatible: a complete record for exactly these images lists the version" {
  record 1.16.1
  build --rollback-compatible 1.16.1 --rehearsals-dir "$REC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -c .rollback_compatible "$OUT/MANIFEST.json")" = '["1.16.1"]' ] || return 1
  # The MANIFEST inside the package is the same file.
  /usr/bin/tar -xzOf "$OUT/custodexa-$V.tar.gz" "custodexa/releases/$V/MANIFEST.json" | cmp - "$OUT/MANIFEST.json"
}

@test "rollback_compatible: a version that is malformed or not older than this release is refused" {
  refused "not a version: 1.16" 1.16
  refused "not a version: v1.16.1" v1.16.1
  refused "1.16.2 is not older than 1.16.2" 1.16.2
  refused "1.17.0 is not older than 1.16.2" 1.17.0
}

@test "rollback_compatible: no record, or a record that is only PASS or does not start with it, is refused" {
  refused "no rehearsal record $REC/$V-from-1.16.1.txt" 1.16.1
  record 1.16.1 only-first
  refused "$V-from-1.16.1.txt: field date is missing" 1.16.1
  record 1.16.1 first=FAIL
  refused "$V-from-1.16.1.txt: the first line is not PASS" 1.16.1
}

@test "rollback_compatible: a missing or empty field is refused, naming it" {
  local k
  for k in date operator from to to_backend_digest to_frontend_digest; do
    record 1.16.1 "drop=$k"
    refused "field $k is missing" 1.16.1 || return 1
  done
  record 1.16.1 "set=operator="
  refused "field operator is missing or empty" 1.16.1
}

@test "rollback_compatible: every one of the four steps must be there and start with PASS" {
  local k
  for k in step1_upgrade step2_write step3_rollback step4_old_readwrite; do
    record 1.16.1 "drop=$k"
    refused "field $k is missing" 1.16.1 || return 1
    record 1.16.1 "set=$k=FAIL the old version did not start"
    refused "field $k does not start with PASS" 1.16.1 || return 1
    record 1.16.1 "set=$k=PASSED"
    refused "field $k does not start with PASS" 1.16.1 || return 1
  done
}

@test "rollback_compatible: a record for other versions, of other images, or with a field twice is refused" {
  record 1.16.1 "set=from=1.16.0"
  refused "field from is 1.16.0, the build lists 1.16.1" 1.16.1
  record 1.16.1 "set=to=1.16.3"
  refused "field to is 1.16.3, this build is 1.16.2" 1.16.1
  # The same version number rebuilt: the record tested other images.
  record 1.16.1 "set=to_backend_digest=sha256:$(printf 'a%.0s' {1..64})"
  refused "field to_backend_digest is not the backend image of this build" 1.16.1
  record 1.16.1 "set=to_frontend_digest=sha256:$(printf 'a%.0s' {1..64})"
  refused "field to_frontend_digest is not the frontend image of this build" 1.16.1
  record 1.16.1 dup=operator
  refused "field operator appears twice" 1.16.1
  record 1.16.1 "set=date=2 Nov 2026"
  refused "field date is not YYYY-MM-DD" 1.16.1
  # One good and one bad version: the whole build stops.
  record 1.16.1
  record 1.16.0 drop=step3_rollback
  refused "$V-from-1.16.0.txt: field step3_rollback is missing" 1.16.1,1.16.0
}
