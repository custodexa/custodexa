#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host
setup() {
  rs_engine_host
  cp -a "$ROOT/current/." "$ROOT/releases/1.16.2"
  printf '1.16.2\n' >"$ROOT/releases/1.16.2/VERSION"
  jq '.version="1.16.2"' "$ROOT/current/MANIFEST.json" >"$ROOT/releases/1.16.2/MANIFEST.json"
  ENGINE=$ROOT/releases/1.16.2/custodexa.sh
  fake bash 'if [ "${2:-}" = upgrade ]; then printf "upgrade %s\n" "${3:-}" >>"$DB/events"; exit 0; fi; exec /bin/bash "$@"'
}
latest() {
  jq --arg v "$1" --arg min "${2:-1.16.0}" '.version=$v | .min_source_version=$min | .released_at="2026-10-12T00:00:00Z"' \
    "$ROOT/current/MANIFEST.json" >"$DB/curl/MANIFEST.json"
  (cd "$DB/curl" && sha256sum MANIFEST.json >SHA256SUMS)
}
finish_tty() {
  run bash -c 'printf "%s\n" "$2" | script -qec "$1" /dev/null' _ \
    "bash '$ENGINE' restore '$RS_E_FILE' --${FINISH_FLOW:-same}-host --yes --confirm-data-loss --lang en" "$1"
  output=${output//$'\r'/}
}
@test "restore finish: a latest version above the engine is handed to ordinary upgrade when accepted" {
  latest 1.17.0
  finish_tty y
  [ "$status" = 0 ] && [[ $output == *'Upgrade to 1.17.0 now?'* ]] || { echo "$output"; return 1; }
  grep -qx 'upgrade 1.17.0' "$DB/events"
}
@test "restore finish: equal engine and data still ask about a newer release, default no prints its command" {
  ENGINE=$ROOT/custodexa.sh
  latest 1.16.3
  finish_tty ''
  [ "$status" = 0 ] && [[ $output == *'Upgrade to 1.16.3 now?'* && $output == *'To upgrade later:'* && $output == *' upgrade 1.16.3'* ]] || { echo "$output"; return 1; }
  ! grep -q '^upgrade ' "$DB/events"
}
@test "restore finish: query failure names the installed engine without calling it latest" {
  touch "$DB/curl.offline"
  finish_tty N
  [ "$status" = 0 ] && [[ $output == *'latest version could not be confirmed'* && $output == *'1.16.2 is already on this host'* && $output == *'releases/1.16.2/custodexa.sh upgrade 1.16.2'* && $output != *'latest version is 1.16.2'* && $output != *'Upgrade to 1.16.2 now?'* ]] || { echo "$output"; return 1; }
}
@test "restore finish: no direct upgrade gives no prompt, and an up-to-date restore needs no upgrade" {
  latest 1.17.0 1.16.3
  finish_tty N
  [ "$status" = 0 ] && [[ $output != *'Upgrade to 1.17.0 now?'* && $output == *'custodexa.sh upgrade'* ]] || { echo "$output"; return 1; }
}
@test "restore finish: the current latest version is reported without asking" {
  latest 1.16.0
  finish_tty N
  [ "$status" = 0 ] && [[ $output == *'1.16.0 is the latest version'* && $output != *'Upgrade to 1.16.0 now?'* ]] || { echo "$output"; return 1; }
}
@test "restore finish: explicit no prints the command and does not upgrade" {
  rs_new_host
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit" "$ROOT/tls"
  FINISH_FLOW=new
  latest 1.17.0
  finish_tty N
  [ "$status" = 0 ] && [[ $output == *'To upgrade later:'* && $output == *'upgrade 1.17.0'* ]] || { echo "$output"; return 1; }
  ! grep -q '^upgrade ' "$DB/events"
}
@test "restore finish: noninteractive has no downloads, keeps previous state and removes payload plaintext" {
  local old staging recordings
  recordings=$(find "$ROOT/data/recordings" -printf '%p %s %T@\n' | sort)
  old=$(jq -r '."current.image_ids"' "$ROOT/state.json")
  run bash "$ENGINE" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  [ "$status" = 0 ] && [[ $output == *'upgrade 1.16.2'* && $output == *'To look up the latest version and upgrade later:'* ]] || { echo "$output"; return 1; }
  ! grep -Eq '^(curl|upgrade) ' "$DB/events" || return 1
  [ "$recordings" = "$(find "$ROOT/data/recordings" -printf '%p %s %T@\n' | sort)" ] && [[ $output == *'recordings were not restored from the backup'* ]] || return 1
  [ "$(jq -r '."previous.image_ids"' "$ROOT/state.json")" = "$old" ] || return 1
  staging=$(jq -r '."last_restore.staging"' "$ROOT/state.json")
  [ -d "$staging" ] && [ -z "$(find "$staging" -type f \( -name db.dump -o -name env.bak -o -name '*.tar.gz' \))" ] || return 1
  [ -f "$staging/missing-recordings.txt" ] && [ -f "$staging/state-before.json" ] && [ -f "$staging/env-before-restore" ] || return 1
  # No upgrade on record: nothing of one is written.
  [ -z "$(jq -r '[to_entries[] | select(.key | startswith("last_upgrade."))] | length | select(. > 0)' "$ROOT/state.json")" ]
}
# The built-in database behind an external ingress: openssl is that form's tool image (backup
# encryption), loaded from an offline bundle on the containerd store, so this host knows it only
# by the deployment's record. Once the restore placed its files, the record still names it.
@test "restore finish: behind an external ingress the finished restore keeps the openssl tool image on record" {
  local ossl=sha256:7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e
  printf 'containerd\n' >"$DB/store"
  # The host has openssl under the bundle's ID only, not under the release's index digest.
  grep -vxF "$BK_OPENSSL_ID" "$DB/images" >"$BATS_TEST_TMPDIR/images" || true
  printf '%s\n' "$ossl" >>"$BATS_TEST_TMPDIR/images"
  cp "$BATS_TEST_TMPDIR/images" "$DB/images"
  bk_state_set current.tool_image_ids "openssl=$ossl"
  rs_engine_run
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$status $output"; return 1; }
  [ "$(jq -r '."current.tool_image_ids" // ""' "$ROOT/state.json")" = "openssl=$ossl" ] ||
    { jq -r '."current.tool_image_ids" // "(none)"' "$ROOT/state.json"; return 1; }
}
# A finished restore settles an upgrade that failed after the switch; its other keys stay.
@test "restore finish: a finished restore settles a failed upgrade and keeps the rest of its record" {
  local before
  bk_state_set last_upgrade.from 1.16.0
  bk_state_set last_upgrade.to 1.16.2
  bk_state_set last_upgrade.result failed
  bk_state_set last_upgrade.step 11
  bk_state_set last_upgrade.backup backups/custodexa-backup-1.16.0-20260930-101502.tar
  before=$(jq -S 'with_entries(select(.key | startswith("last_upgrade.")))' "$ROOT/state.json")
  run bash "$ENGINE" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_upgrade.settled_by"' "$ROOT/state.json")" = restore ] &&
    [[ $(jq -r '."last_upgrade.settled_at"' "$ROOT/state.json") == 20??-??-??T??:??:??* ]] || { cat "$ROOT/state.json"; return 1; }
  diff <(jq -S 'with_entries(select(.key | startswith("last_upgrade.")) | select(.key != "last_upgrade.settled_by" and
    .key != "last_upgrade.settled_at"))' "$ROOT/state.json") <(printf '%s\n' "$before") || return 1
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = succeeded ]
}
# Derived from the real producer file: upgrade changes trigger and adds its required state.
upgrade_input() {
  local w=$BATS_TEST_TMPDIR/upgrade-input
  rs_unpack "$RS_E_FILE" "$w"
  cp "$ROOT/state.json" "$w/state.json"
  sed -i '/^SHA256SUMS$/i state.json' "$w/.order"
  (cd "$w" && rs_mf_set trigger upgrade && rs_mf_set contents.state true &&
    rs_mf_set contents.members "$(tr '\n' ' ' <.order | sed 's/ $//')") || return 1
  RS_E_FILE=$BATS_TEST_TMPDIR/upgrade.tar
  rs_pack "$w" "$RS_E_FILE" sums
}
@test "restore finish: pre-upgrade backup never queries or asks, with or without a terminal" {
  upgrade_input
  # The normal producer of this input can be an upgrade interrupted after switching releases.
  bk_state_set last_upgrade.result in_progress
  bk_state_set last_upgrade.step 9
  finish_tty N
  [ "$status" = 0 ] && [[ $output == *'Back on the version from before the upgrade (1.16.0)'* && $output != *'Looking up the latest'* && $output != *'Upgrade to '* ]] || { echo "$output"; return 1; }
  ! grep -q '^curl ' "$DB/events" || return 1
  run bash "$ENGINE" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  [ "$status" = 0 ] && [[ $output == *'Back on the version from before the upgrade (1.16.0)'* && $output != *'Looking up the latest'* && $output != *'Upgrade to '* ]] || { echo "$output"; return 1; }
  ! grep -q '^curl ' "$DB/events" || return 1
  # The interrupted upgrade was handed over, then settled by the finished restore.
  [ "$(jq -r '."last_upgrade.handed_to" + " " + ."last_upgrade.settled_by"' "$ROOT/state.json")" = 'restore restore' ]
}

@test "restore finish: waiting for unseal never queries until the resumed runtime check completes" {
  bk_env_set KEK_PROVIDER ui
  bk_env_set ENCRYPTION_KEY ''
  bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/ui.log" 2>&1 || { cat "$BATS_TEST_TMPDIR/ui.log"; return 1; }
  RS_E_FILE=$(find "$ROOT/backups" -name '*.tar')
  cp "$RS_E_FILE" "$RS_E_FILE.sha256" "$BATS_TEST_TMPDIR/source/"
  RS_E_FILE=$BATS_TEST_TMPDIR/source/${RS_E_FILE##*/}
  rm -f "$ROOT"/backups/*
  rs_new_host
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit" "$ROOT/tls"
  FINISH_FLOW=new
  echo sealed >"$DB/seal"
  latest 1.17.0
  : >"$DB/events"
  finish_tty N
  [ "$status" = 4 ] && [[ $output != *'Upgrade to '* ]] || { echo "$output"; return 1; }
  ! grep -q '^curl ' "$DB/events" || return 1
  echo unsealed >"$DB/seal"
  run env NO_COLOR=1 bash -c 'printf "N\n" | script -qec "$1" /dev/null' _ "bash '$ENGINE' restore --resume --lang en"
  [ "$status" = 0 ] && [[ $output == *'Upgrade to 1.17.0 now?'* ]] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | grep -c '^\[ OK \] Restore done')" = 1 ] || { echo "$output"; return 1; }
}
