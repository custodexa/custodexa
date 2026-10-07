#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() {
  rs_fixtures || return 1
  rs_make "$RS_FIX/env-valid" env 'BK_KEK=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ; bk_dotenv env
    awk '\''$1 == "fill5a" {print $3}'\'' /src/backend/pkg/crypto/testdata/kek-fingerprint-vectors.txt >"$DB/kek"' || return 1
  rs_derive env-valid env-hex 'sed -i "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$(printf ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ | od -An -v -tx1 | tr -d " \\n")/" env.bak' || return 1
  rs_derive env-valid env-base64 'sed -i "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$(printf ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ | base64 -w0)/" env.bak' || return 1
}
setup() { RS_FIX=$BATS_FILE_TMPDIR/fixtures; rs_host ui; rs_preflight_only; backup_strict; }
restore_file() { run bash "$ROOT/custodexa.sh" restore "$(rs_fix "$1")" --same-host --yes --confirm-data-loss --lang "${2:-en}" </dev/null; }
no_stop() { ! grep -Eq '^(stop|start|up|curl)( |$)' "$DB/events"; }
reached_end() { [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }; no_stop; }

@test "restore checks: old data is refused first, with or without a fingerprint, in all three languages" {
  local n l f expected errs=0
  for l in en zh-TW ja; do
    for n in oldupgrade oldnofp; do
      f=$(rs_fix "$n")
      restore_file "$n" "$l"
      [ "$status" -eq 3 ] || { echo "$output"; return 1; }
      no_stop || return 1
      [ "$(find "$ROOT/releases" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ] || return 1
      output=$(printf '%s\n' "$output" | sed -n '/^\[FAIL\]/,$p' | sed "s#$f#/srv/transfer/backup.tar#g")
      expected=$TESTS_DIR/snapshots/restore-data-too-old.$l.txt
      if [ ! -f "$expected" ]; then
        printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
        errs=1
      else
        diff <(printf '%s\n' "$output") "$expected" || errs=1
      fi
    done
  done
  [ "$errs" = 0 ]
}

@test "restore checks: data at the minimum and an equal engine pass; a newer data version refuses" {
  restore_file plain
  reached_end || return 1
  rs_derive plain newer 'jq '\''.version="1.16.2"'\'' release-MANIFEST.json > mf.new
    mv mf.new release-MANIFEST.json
    rs_mf_set product.version 1.16.2
    rs_mf_set product.manifest_sha256 "$(sha256sum release-MANIFEST.json | cut -d " " -f1)"' || return 1
  restore_file newer
  [ "$status" -eq 3 ] && [[ $output == *'management script is 1.16.0'* && $output == *'newer 1.16.2'* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore checks: a unique fingerprint passes; missing and non-unique fingerprints refuse" {
  local n
  restore_file plain
  reached_end || return 1
  for n in missing not-unique; do
    rs_derive plain "$n" 'sed -i "s/^fp.kek=.*/fp.kek=/" snapshot.txt
      rs_mf_set kek.fingerprint ""; rs_mf_set kek.fingerprint_status '"$n" || return 1
    restore_file "$n"
    [ "$status" -eq 3 ] && [[ $output == *'This backup has no master key fingerprint'* ]] || { echo "$output"; return 1; }
    no_stop || return 1
  done
}

@test "restore checks: ui and kms pass; hsm refuses before stopping" {
  local n
  for n in plain kms; do restore_file "$n"; reached_end || return 1; done
  rs_derive plain hsm 'rs_mf_set kek.provider hsm' || return 1
  restore_file hsm
  [ "$status" -eq 3 ] && [[ $output == *'no working'*'HSM implementation'* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore checks: the three key forms agree with the backup; a different key refuses" {
  local n
  for n in env-valid env-hex env-base64; do restore_file "$n"; reached_end || return 1; done
  rs_derive env-valid wrong-key 'sed -i "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY/" env.bak' || return 1
  restore_file wrong-key
  [ "$status" -eq 3 ] && [[ $output == *'master key in the settings file does not belong'* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore checks: fingerprints use the same locked known-answer vector file as the backend" {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"
    . "$1/lib/restore_read.sh"; . "$1/lib/restore_checks.sh"; CX_RS_DIR=$2
    while read -r label encoded expected; do
      case $label in ""|\#*) continue ;; esac
      cx_rs_key_fingerprint "$encoded" && [ "$CX_RS_KEY_FP" = "$expected" ] || exit 1
      hex=$(printf "%s" "$encoded" | base64 -d | od -An -v -tx1 | tr -d " \n")
      cx_rs_key_fingerprint "$hex" && [ "$CX_RS_KEY_FP" = "$expected" ] || exit 1
    done </src/backend/pkg/crypto/testdata/kek-fingerprint-vectors.txt' _ "$SRC" "$BATS_TEST_TMPDIR"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "restore checks: token key matches the snapshot, mismatch refuses, and an absent fingerprint is not checked" {
  restore_file plain
  reached_end || return 1
  [[ $output == *'[ OK ] The sign-in token key fingerprint'* ]] || return 1
  restore_file nojwt
  reached_end || return 1
  [[ $output == *'[ -- ] Sign-in token key'* && $output != *'[ OK ] The sign-in token key fingerprint'* ]] || return 1
  rs_derive plain jwt-different 'sed -i "s/^JWT_SECRET=.*/JWT_SECRET=different-test-value-for-token/" env.bak' || return 1
  restore_file jwt-different
  [ "$status" -eq 3 ] && [[ $output == *'key fingerprint in the settings file differs'* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore checks: required secrets come from the file; missing or template values refuse without generating keys" {
  local n
  restore_file plain
  reached_end || return 1
  for n in absent template; do
    rs_derive plain "db-$n" 'sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD='"$([ "$n" = template ] && echo changeme)"'/" env.bak' || return 1
    restore_file "db-$n"
    [ "$status" -eq 3 ] && [[ $output == *'required key'* && $output == *'DB_PASSWORD'* ]] || { echo "$output"; return 1; }
    no_stop || return 1
  done
}

@test "restore checks: grants of a bundled database to additional roles refuse before stopping" {
  printf '%s\n' report_reader >"$DB/grants.restore"
  restore_file plain
  [ "$status" -eq 3 ] && [[ $output == *'other roles: report_reader'* && $output == *'by hand'* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "restore checks: grants can be read when the offline postgres image is known only by its config digest" {
  local config=sha256:2222222222222222222222222222222222222222222222222222222222222222 file
  (unset FAKE_DOCKER_REPLAY; rs_make "$RS_FIX/config-image" ui 'jq '\''.images.postgres.platforms = {amd64: {config_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"}}'\'' "$ROOT/releases/1.13.0/MANIFEST.json" >"$ROOT/mf.new"
    mv "$ROOT/mf.new" "$ROOT/releases/1.13.0/MANIFEST.json"') || return 1
  file=$(rs_fix config-image)
  host_arch x86_64
  printf '%s\n' "$config" >"$DB/images"
  echo PUBLIC >"$DB/grants.restore"
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"
    . "$1/lib/cmd_restore.sh"
    CX_ROOT=$2 CX_DIR=$2/current CX_RS_ACTION="" CX_COMMAND=restore
    cx_rs_read_setup && cx_rs_open "$3" && cx_rs_grants' _ "$SRC" "$ROOT" "$file"
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  grep -qx 'pg_restore list' "$DB/events" && grep -qx 'pg_restore acl' "$DB/events" || { cat "$DB/events" "$FAKE_DOCKER_LOG"; return 1; }
  grep -F "pg_restore $config -l" "$FAKE_DOCKER_LOG"
}
