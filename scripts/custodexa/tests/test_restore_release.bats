#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { export RS_FIX=$BATS_FILE_TMPDIR/fixtures; rs_make "$RS_FIX/plain" ui :; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_host ui
  rs_preflight_only
  backup_strict
  # The engine is newer than the backup; only the engine is installed here initially.
  mv "$ROOT/releases/1.16.0" "$ROOT/releases/1.16.2"
  printf '1.16.2\n' >"$ROOT/releases/1.16.2/VERSION"
  jq '.version="1.16.2"' "$ROOT/releases/1.16.2/MANIFEST.json" >"$ROOT/releases/1.16.2/mf.new"
  mv "$ROOT/releases/1.16.2/mf.new" "$ROOT/releases/1.16.2/MANIFEST.json"
  /usr/bin/ln -sfn releases/1.16.2 "$ROOT/current"
  bk_state_set current.version 1.16.2
  original=$(release_tree)
}
release_tree() {
  (cd "$ROOT" && find releases -type f -print0 | sort -z | xargs -0 sha256sum)
  readlink "$ROOT/current"
  sha256sum "$ROOT/state.json" "$ROOT/.env"
}
unchanged() {
  [ "$original" = "$(release_tree)" ] || return 1
  [ -z "$(find "$ROOT/releases" -name '.incoming-*' -print -quit)" ] || return 1
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events"
}
restore_file() { run bash "$ROOT/custodexa.sh" restore "$(rs_fix plain)" --same-host --yes --confirm-data-loss --lang en "$@" </dev/null; }
make_package() {
  local out=$BATS_TEST_TMPDIR/package rel=$BATS_TEST_TMPDIR/package/custodexa/releases/1.16.0
  rs_unpack "$(rs_fix plain)" "$BATS_TEST_TMPDIR/unpacked"
  package_release "$rel" 1.16.0 1.16.0
  cp "$BATS_TEST_TMPDIR/unpacked/release-MANIFEST.json" "$rel/MANIFEST.json"
  PACKAGE_DIR=$out PACKAGE_RELEASE=$rel
  pack_package
}
pack_package() {
  tar -czf "$DB/curl/custodexa-1.16.0.tar.gz" -C "$PACKAGE_DIR" custodexa
  (cd "$DB/curl" && sha256sum custodexa-1.16.0.tar.gz >SHA256SUMS)
}

# - **WHEN** 備份清單的版本是沒有發行附檔的版本，且未帶 `--package`
# - **THEN** 腳本拒絕並說明只能用同一版還原、可用 `--package` 指定手上的安裝包，部署沒有任何變更
@test "restore release: missing release files refuse with the same-version and package guidance" {
  restore_file
  [ "$status" -eq 3 ] && [[ $output == *'1.16.0 has no release files'* && $output == *'--package'* && $output == *'will not install a different one'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore release: a connection failure gives offline guidance and removes incoming files" {
  touch "$DB/curl.offline"
  restore_file
  [ "$status" -eq 3 ] && [[ $output == *'could not be downloaded'* && $output == *'--package'* && $output == *'--images'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore release: package checksum mismatch refuses before changing the deployment" {
  make_package
  printf 'changed' >>"$DB/curl/custodexa-1.16.0.tar.gz"
  restore_file --package "$DB/curl/custodexa-1.16.0.tar.gz"
  [ "$status" -eq 3 ] && [[ $output == *'checksum'* && $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}

# - **WHEN** `--package` 指定的安裝包校驗和正確，但其中的 `MANIFEST.json` 與備份內的 `release-MANIFEST.json` 不同
# - **THEN** 腳本拒絕，部署沒有任何變更
@test "restore release: a package manifest different from the backup refuses" {
  make_package
  jq '.released_at="different"' "$PACKAGE_RELEASE/MANIFEST.json" >"$PACKAGE_RELEASE/mf.new"
  mv "$PACKAGE_RELEASE/mf.new" "$PACKAGE_RELEASE/MANIFEST.json"
  pack_package
  restore_file --package "$DB/curl/custodexa-1.16.0.tar.gz"
  [ "$status" -eq 3 ] && [[ $output == *'release manifest'*'differs from the one'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore release: package layout and VERSION must name the data version" {
  make_package
  printf '1.16.1\n' >"$PACKAGE_RELEASE/VERSION"
  pack_package
  restore_file --package "$DB/curl/custodexa-1.16.0.tar.gz"
  [ "$status" -eq 3 ] && [[ $output == *'1.16.0'* && $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore release: a checked local older release passes without switching current or applying upgrade direction rules" {
  make_package
  cp -a "$PACKAGE_RELEASE" "$ROOT/releases/1.16.0"
  original=$(release_tree)
  restore_file
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore release: downloaded and offline packages prepare without placing the release" {
  make_package
  restore_file
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged || return 1
  restore_file --package "$DB/curl/custodexa-1.16.0.tar.gz"
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}
