#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_fixtures; }
setup() { RS_FIX=$BATS_FILE_TMPDIR/fixtures; rs_host ui; rs_preflight_only; backup_strict; }

protected_tree() {
  (cd "$ROOT" && find . \( -path ./logs -o -path ./restore -o -name .custodexa.lock \) -prune -o -printf '%y %p %l\n' | LC_ALL=C sort)
  (cd "$ROOT" && find . \( -path ./logs -o -path ./restore -o -name .custodexa.lock \) -prune -o \
    -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
  readlink "$ROOT/current"
  readlink "$ROOT/custodexa.sh"
}
read_backup() {
  run bash "$ROOT/custodexa.sh" restore "$1" --same-host --yes --confirm-data-loss --lang en "${@:2}" </dev/null
}
refused() {
  [ "$status" -eq 3 ] || { echo "$status: $output"; return 1; }
  [ "$before" = "$(protected_tree)" ] || return 1
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events" || return 1
  [ -z "$(find "$ROOT/restore" -mindepth 1 -print -quit 2>/dev/null)" ] || return 1
  [[ $output != *'command not found'* && $output != *'syntax error'* && $output != *'No such file'* ]] || return 1
}
tampered() {
  local f
  f=$(rs_tamper "$1") || return 1
  before=$(protected_tree)
  read_backup "$f"
  refused || return 1
  [[ $output == *"$2"* ]] || { echo "$output"; return 1; }
}

@test "restore read: sidecar refuses before stopping or changing the deployment" {
  tampered sidecar "checksum file does not match"
}

@test "restore read: member-hash refuses before stopping or changing the deployment" {
  tampered member-hash "checksum of db.dump differs"
}

@test "restore read: member-extra refuses before stopping or changing the deployment" {
  tampered member-extra "extra, missing or repeated"
}

@test "restore read: member-missing refuses before stopping or changing the deployment" {
  tampered member-missing "extra, missing or repeated"
}

@test "restore read: member-dup refuses before stopping or changing the deployment" {
  tampered member-dup "extra, missing or repeated"
}

@test "restore read: member-link refuses before stopping or changing the deployment" {
  tampered member-link "directory, a link"
}

@test "restore read: member-dir refuses before stopping or changing the deployment" {
  tampered member-dir "directory, a link"
}

@test "restore read: member-path refuses before stopping or changing the deployment" {
  tampered member-path "directory, a link"
}

@test "restore read: manifest-bad refuses before stopping or changing the deployment" {
  tampered manifest-bad "field is missing or invalid"
}

@test "restore read: release-mf refuses before stopping or changing the deployment" {
  tampered release-mf "release manifest hash or version differs"
}

@test "restore read: migrations refuses before stopping or changing the deployment" {
  tampered migrations "migration hash or count differs"
}

@test "restore read: kek-fp refuses before stopping or changing the deployment" {
  tampered kek-fp "master key fingerprint differs"
}

@test "restore read: inner-path refuses before stopping or changing the deployment" {
  tampered inner-path "inner archive"
}

@test "restore read: inner-link refuses before stopping or changing the deployment" {
  tampered inner-link "inner archive"
}

@test "restore read: tls-missing refuses before stopping or changing the deployment" {
  tampered tls-missing "field is missing or invalid"
}

@test "restore read: tpl-flag refuses before stopping or changing the deployment" {
  tampered tpl-flag "field is missing or invalid"
}

@test "restore read: tpl-source refuses before stopping or changing the deployment" {
  tampered tpl-source "field is missing or invalid"
}

@test "restore read: state-version refuses before stopping or changing the deployment" {
  tampered state-version "state.json differs"
}

@test "restore read: enc-as-tar refuses before stopping or changing the deployment" {
  tampered enc-as-tar "file header do not agree"
}

@test "restore read: tar-as-enc refuses before stopping or changing the deployment" {
  tampered tar-as-enc "file header do not agree"
}

@test "restore read: enc-cut refuses before stopping or changing the deployment" {
  tampered enc-cut "truncated or has an invalid length"
}

@test "restore read: the producer's tls, no-tls and both template path forms pass the reader" {
  local name
  before=$(protected_tree)
  for name in plain notls tplabs tplrel; do
    read_backup "$(rs_fix "$name")"
    [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$name: $output"; return 1; }
    refused || return 1
  done
}

@test "restore read: without a sidecar explicit consent still cannot bypass member hashes" {
  local f
  f=$(rs_tamper member-hash)
  rm "$f.sha256"
  before=$(protected_tree)
  read_backup "$f"
  refused || return 1
  [[ $output == *'--no-checksum-file'* ]] || return 1
  read_backup "$f" --no-checksum-file
  refused || return 1
  [[ $output == *'checksum of db.dump differs'* ]] || { echo "$output"; return 1; }
}

@test "restore read: encryption uses stdin and keeps the passphrase out of every caller's argv and environment" {
  local pf=$BATS_TEST_TMPDIR/pass
  bk_passfile "$pf" "$RS_PASS"
  before=$(protected_tree)
  read_backup "$(rs_fix enc)" --passphrase-file "$pf"
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  refused || return 1
  [ -s "$DB/proc.seen" ]
  ! grep -Fq -- "$RS_PASS" "$DB/proc.seen" "$FAKE_DOCKER_LOG" "$ROOT"/logs/restore-*.log || return 1
  chmod 644 "$pf"
  read_backup "$(rs_fix enc)" --passphrase-file "$pf"
  refused || return 1
  [[ $output == *'chmod 600'* ]] || { echo "$output"; return 1; }
}

@test "restore read: three wrong interactive passphrases cancel without stopping services" {
  before=$(protected_tree)
  # Input arrives after the silent read has disabled echo.
  run bash -c '{ sleep .4; printf "wrong-passphrase-1\n"; sleep 1; printf "wrong-passphrase-2\n"; sleep 1; printf "wrong-passphrase-3\n"; } | script -qec "$1" /dev/null' _ \
    "bash '$ROOT/custodexa.sh' restore '$(rs_fix enc)' --same-host --lang en --no-color"
  output=${output//$'\r'/}
  refused || return 1
  [[ $output == *'Three tries did not decrypt it'* ]] || { echo "$output"; return 1; }
}

@test "restore read: an old directory or archive without a manifest is explained before any changes" {
  mkdir "$DB/old"
  printf 'old\n' >"$DB/old/env.bak"
  /usr/bin/tar --format=gnu -cf "$DB/old.tar" -C "$DB/old" env.bak
  before=$(protected_tree)
  read_backup "$DB/old"
  refused || return 1
  [[ $output == *'backup folder from before'* ]] || return 1
  read_backup "$DB/old.tar" --no-checksum-file
  refused || return 1
  [[ $output == *'This file has no backup manifest.'* ]] || { echo "$output"; return 1; }
}

# An offline bundle loaded on the containerd image store leaves each image under an ID of its own,
# which neither the release's index digest nor its config digest finds; install, upgrade and load
# record that ID. The host below holds the openssl and database images only under such IDs.
@test "restore read: openssl and the database image of an offline bundle on containerd are found by the IDs this host recorded, never by digest alone" {
  local pf=$BATS_TEST_TMPDIR/pass ossl=sha256:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    pg=sha256:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
  bk_passfile "$pf" "$RS_PASS"
  printf 'containerd\n' >"$DB/store"
  printf '%s\n' "$ossl" "$pg" >"$DB/images"
  # Recorded by install or upgrade for this release.
  bk_state_set current.image_ids "openssl=$ossl postgres=$pg"
  before=$(protected_tree)
  read_backup "$(rs_fix enc)" --passphrase-file "$pf"
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  refused || return 1
  grep -F -- "--entrypoint openssl $ossl enc -d" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # Recorded by load of this release's bundle only (as on a new host). The read and its checks are
  # called directly: the safety backup of the full command needs the current images recorded.
  bk_state_set current.image_ids ""
  bk_state_set load.version "$RS_VERSION"
  bk_state_set load.image_ids "openssl=$ossl postgres=$pg"
  : >"$FAKE_DOCKER_LOG"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -F -- "--entrypoint openssl $ossl enc -d" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # Not recorded for this release: the database image is not taken by any other ID, and the screen
  # says which image is missing and what to load (not that the file is damaged).
  bk_state_set load.image_ids "openssl=$ossl"
  : >"$DB/events"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *"The database tool image of release $RS_VERSION is not on this host."* ]] || { echo "$output"; return 1; }
  [[ $output == *"load that release's offline"* && $output != *'could not be read to check its grants'* ]] || { echo "$output"; return 1; }
  [[ $output != *'incomplete or has been changed'* ]] || { echo "$output"; return 1; }
  ! grep -q '^pg_restore' "$DB/events" || return 1
  # Recorded for another release: the engine's openssl is not taken either.
  bk_state_set load.version 1.15.9
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *'openssl tool image of release'* ]] || { echo "$output"; return 1; }
}
# After an upgrade the release a backup of the upgrade names is the previous one: its images were
# recorded by install under previous.* (the upgrade moves current.* there), which a restore of that
# backup on this host must find as well, and only for that release.
@test "restore read: the database image of the release before an upgrade is found by the ID recorded under previous.*" {
  local pf=$BATS_TEST_TMPDIR/pass ossl=sha256:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    pg=sha256:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
  bk_passfile "$pf" "$RS_PASS"
  printf 'containerd\n' >"$DB/store"
  printf '%s\n' "$ossl" "$pg" >"$DB/images"
  bk_state_set current.version 1.16.9
  bk_state_set current.image_ids ""
  bk_state_set load.version "$RS_VERSION"
  bk_state_set load.image_ids "openssl=$ossl"
  bk_state_set previous.version "$RS_VERSION"
  bk_state_set previous.image_ids "postgres=$pg"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # Recorded under previous.* for another release: not taken.
  bk_state_set previous.version 1.15.9
  : >"$DB/events"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *"The database tool image of release $RS_VERSION is not on this host."* ]] || { echo "$output"; return 1; }
  ! grep -q '^pg_restore' "$DB/events" || return 1
}


# The engine and the data can be of different releases on a host that has neither installed: the
# engine's openssl decrypts and the data release's database image reads the grants, while `load`
# keeps the IDs of the last bundle it loaded only. An ID recorded for another release is taken when
# that release's manifest names the same index digest for the image (the same image), and only then.
@test "restore read: an image ID recorded for another release is taken only when that release's manifest names the same index digest" {
  local pf=$BATS_TEST_TMPDIR/pass ossl=sha256:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
    pg=sha256:0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c other=1.15.9 od pd
  bk_passfile "$pf" "$RS_PASS"
  printf 'containerd\n' >"$DB/store"
  printf '%s\n' "$ossl" "$pg" >"$DB/images"
  od=$(jq -r .images.openssl.index_digest "$ROOT/current/MANIFEST.json")
  pd=$(jq -r .images.postgres.index_digest "$ROOT/current/MANIFEST.json")
  [[ $od == sha256:* && $pd == sha256:* ]] || return 1
  bk_state_set current.image_ids ""
  bk_state_set load.version "$other"
  bk_state_set load.image_ids "openssl=$ossl postgres=$pg"
  # That release's package is unpacked here and its manifest names the same index digests.
  mkdir -p "$ROOT/releases/$other"
  jq --arg v "$other" '.version = $v' "$ROOT/current/MANIFEST.json" >"$ROOT/releases/$other/MANIFEST.json"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -F -- "--entrypoint openssl $ossl enc -d" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # Another database image in that release: its ID is not taken for this release's.
  jq --arg d "sha256:$(printf '%064d' 7)" '.images.postgres.index_digest = $d' "$ROOT/current/MANIFEST.json" |
    jq --arg v "$other" '.version = $v' >"$ROOT/releases/$other/MANIFEST.json"
  : >"$DB/events"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *"The database tool image of release $RS_VERSION is not on this host."* ]] || { echo "$output"; return 1; }
  ! grep -q '^pg_restore' "$DB/events" || return 1
  # Another openssl image in that release: decryption does not start.
  jq --arg d "sha256:$(printf '%064d' 8)" '.images.openssl.index_digest = $d' "$ROOT/current/MANIFEST.json" |
    jq --arg v "$other" '.version = $v' >"$ROOT/releases/$other/MANIFEST.json"
  : >"$FAKE_DOCKER_LOG"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *'openssl tool image of release'* ]] || { echo "$output"; return 1; }
  ! grep -qF -- "--entrypoint openssl" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # A manifest in that folder that is not that release's does not count.
  jq '.version = "1.15.8"' "$ROOT/current/MANIFEST.json" >"$ROOT/releases/$other/MANIFEST.json"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *'openssl tool image of release'* ]] || { echo "$output"; return 1; }
  # Without the package: the index digests load recorded from the manifest it checked the bundle against.
  rm -rf "$ROOT/releases/$other"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *'openssl tool image of release'* ]] || { echo "$output"; return 1; }
  bk_state_set load.index_digests "openssl=$od postgres=$pd"
  : >"$FAKE_DOCKER_LOG"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -F -- "--entrypoint openssl $ossl enc -d" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { cat "$FAKE_DOCKER_LOG"; return 1; }
  bk_state_set load.index_digests "openssl=$od postgres=sha256:$(printf '%064d' 7)"
  read_checks "$(rs_fix enc)" "$pf"
  [ "$status" -ne 0 ] && [[ $output == *"The database tool image of release $RS_VERSION is not on this host."* ]] || { echo "$output"; return 1; }
  # Recorded by install for another current release, whose package is here with the same digests.
  bk_state_set load.version ""
  bk_state_set load.image_ids ""
  bk_state_set load.index_digests ""
  mkdir -p "$ROOT/releases/$other"
  jq --arg v "$other" '.version = $v' "$ROOT/current/MANIFEST.json" >"$ROOT/releases/$other/MANIFEST.json"
  bk_state_set current.version "$other"
  bk_state_set current.image_ids "openssl=$ossl postgres=$pg"
  : >"$FAKE_DOCKER_LOG"
  read_checks "$(rs_fix enc)" "$pf"
  grep -F -- "--entrypoint openssl $ossl enc -d" "$FAKE_DOCKER_LOG" >/dev/null || { echo "$output"; cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -F -- "--entrypoint pg_restore $pg -l" "$FAKE_DOCKER_LOG" >/dev/null || { echo "$output"; cat "$FAKE_DOCKER_LOG"; return 1; }
}

read_checks() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"
    . "$1/lib/cmd_restore.sh"
    CX_ROOT=$2 CX_DIR=$2/current CX_RS_ACTION="" CX_COMMAND=restore CX_PASSPHRASE_FILE=$4
    cx_rs_read_setup && cx_rs_open "$3" && cx_rs_checks' _ "$SRC" "$ROOT" "$1" "$2"
}
