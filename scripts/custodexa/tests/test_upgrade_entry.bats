#!/usr/bin/env bats
# Threat (A): a call that should only check changes something. On a package deployment the bare
# call only checks, and says whether the release manifest was verified; a
# checksum mismatch gives no answer about upgrading. A version or a package is verified before the
# target version's script takes over.

load helper
load install_host
load backup_host
load upgrade_host

@test "package deployment, bare upgrade: only checks, nothing changed" {
  backup_host ui
  fake_github
  printf '%s\n' 20260816_schema_baseline 20260901_add_x >"$DB/migrations"
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  for l in zh-TW en; do
    upgrade_run "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(screen_of "$output") "$TESTS_DIR/snapshots/s05.$l.txt" || return 1
  done
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT") || return 1
  ! grep -q ' stop \| down \| up ' "$FAKE_DOCKER_LOG"
}

@test "menu query returns the verified target without CLI-only command or second fetch" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  run bash -c 'CX_LANG_FLAG=en; . "$1/lib/common.sh"; cx_load_libs "$1"
    CX_ROOT=$2; cx_state_load "$CX_ROOT/state.json"
    . "$1/lib/version_rules.sh"; . "$1/lib/upgrade_query.sh"
    cx_up_query_core menu || exit 1
    printf "target=%s\n" "$CX_Q_TARGET"' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"target=1.13.2"* && $output != *"To upgrade, run:"* && $output != *"This only checked"* ]] || { echo "$output"; return 1; }
  [ "$(wc -l <"$REL/requests")" -eq 3 ]
}

@test "query shows download and signature progress before slow tools return" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  local out=$BATS_TEST_TMPDIR/query-progress pid
  mv "$FAKES/curl" "$FAKES/curl-real"
  printf '#!/bin/bash\n/bin/sleep 2\nexec %q "$@"\n' "$FAKES/curl-real" >"$FAKES/curl"
  chmod +x "$FAKES/curl"
  bash "$ROOT/custodexa.sh" upgrade --lang en >"$out" 2>&1 &
  pid=$!
  /bin/sleep 0.2
  grep -q 'Downloading MANIFEST.json' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
  mv "$FAKES/curl-real" "$FAKES/curl"
  printf '#!/bin/bash\n/bin/sleep 2\nexec %q "$@"\n' "$TESTS_DIR/fakes/cosign" >"$FAKES/cosign"
  chmod +x "$FAKES/cosign"
  bash "$ROOT/custodexa.sh" upgrade --lang en >"$out" 2>&1 &
  pid=$!
  /bin/sleep 0.2
  grep -q 'Verifying the release manifest signature' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
}

@test "optional signature bundle download has an immediate result for present and absent files" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  upgrade_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *$'[ .. ] Downloading SHA256SUMS.sigstore.json for the latest release…\n[ OK ] Downloaded SHA256SUMS.sigstore.json'* ]] || {
    echo "present bundle has no immediate OK result: $output"
    return 1
  }
  rm "$REL/v1.13.2/SHA256SUMS.sigstore.json"
  upgrade_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *$'[ .. ] Downloading SHA256SUMS.sigstore.json for the latest release…\n[WARN] Signature bundle is unavailable; publisher unverified'* ]] || {
    echo "absent bundle has no immediate WARN result: $output"
    return 1
  }
}

@test "package download progress is visible before slow curl returns" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  local out=$BATS_TEST_TMPDIR/package-progress dir=$BATS_TEST_TMPDIR/package-download pid
  mkdir -p "$dir"
  mv "$FAKES/curl" "$FAKES/curl-real"
  printf '#!/bin/bash\n/bin/sleep 2\nexec %q "$@"\n' "$FAKES/curl-real" >"$FAKES/curl"
  chmod +x "$FAKES/curl"
  bash -c 'CX_LANG_FLAG=en; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/cmd_upgrade.sh"; cx_up_download 1.13.2 "$2"' _ "$SRC" "$dir" >"$out" 2>&1 &
  pid=$!
  /bin/sleep 0.2
  grep -q 'Downloading custodexa-1.13.2.tar.gz' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
  [ -f "$dir/custodexa-1.13.2.tar.gz" ]
}

@test "upgrade rejected before confirmation does not create a lock; a leftover flock file is reusable" {
  backup_host ui
  upgrade_run en 1.13.0
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [ ! -e "$ROOT/.custodexa.lock" ] || return 1
  printf '%s\n' 99999 >"$ROOT/.custodexa.lock"
  upgrade_run en 1.13.0
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  exec 8>>"$ROOT/.custodexa.lock"
  flock -n 8 || return 1
  exec 8>&-
}

@test "upgrade handoff preserves whether --lang was explicitly supplied" {
  backup_host ui
  run bash -c 'CX_LANG_FLAG="" LANG=ja_JP.UTF-8; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/cmd_upgrade.sh"; cx_up_handoff_args; [ ${#CX_UP_ARGS[@]} -eq 0 ]' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  run bash -c 'CX_LANG_FLAG=zh-TW; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/cmd_upgrade.sh"; cx_up_handoff_args
    [ ${#CX_UP_ARGS[@]} -eq 2 ] && [ "${CX_UP_ARGS[0]}" = --lang ] && [ "${CX_UP_ARGS[1]}" = zh-TW ]' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  run bash -c 'CX_LANG_FLAG=ja; CX_IMAGES_FROM=source; CX_IMAGES_FROM_GIVEN=1
    . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/cmd_upgrade.sh"
    cx_up_handoff_args
    [ "${CX_UP_ARGS[*]}" = "--lang ja --images-from source" ]' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  run bash -c 'CX_LANG_FLAG=""; CX_IMAGES_FROM=auto; CX_IMAGES_FROM_GIVEN=1
    . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/cmd_upgrade.sh"
    cx_up_handoff_args
    [ "${CX_UP_ARGS[*]}" = "--images-from auto" ]' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "package deployment, the check: unverified said so, a checksum mismatch gives no answer, offline" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule
  no_cosign
  upgrade_run zh-TW
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  [WARN] 發行清單只驗了校驗和，沒有驗發行者簽章（這台主機沒有' || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '         cosign），以下結果未經來源驗證' || return 1
  [[ $output != *"已驗證"* ]] || return 1
  # The manifest does not match SHA256SUMS: FAIL and no eligibility at all.
  printf ' ' >>"$REL/v1.13.2/MANIFEST.json"
  upgrade_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The release manifest checksum does not match SHA256SUMS"* ]] || { echo "$output"; return 1; }
  [[ $output != *"Direct upgrade"* && $output != *"structure change"* && $output != *"To upgrade, run"* ]] || { echo "$output"; return 1; }
  touch "$REL/offline"
  upgrade_run zh-TW
  [ "$status" -eq 1 ] && [[ $output == *"連不到 GitHub；離線升級請指定安裝包路徑"* ]] || { echo "$output"; return 1; }
}

@test "query answers with WARN when the publisher signature mismatches" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x
  sed -i 's#refs/tags/v1.13.2#refs/tags/v9.9.9#' "$REL/v1.13.2/SHA256SUMS.sigstore.json"
  upgrade_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"Latest      1.13.2"* && $output == *"[WARN]"* && $output == *"signature mismatch, publisher unverified"* ]] || { echo "$output"; return 1; }
}

@test "query and package preview warn when the signature file is absent" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x
  rm "$REL/v1.13.2/SHA256SUMS.sigstore.json"
  upgrade_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"Latest      1.13.2"* && $output == *"[WARN]"* && $output == *"signature file is absent; publisher unverified"* ]] || { echo "$output"; return 1; }
  upgrade_run en 1.13.2
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] custodexa-1.13.2.tar.gz: no signature file; publisher unverified"* && $output == *"upgrade preview"* ]] || { echo "$output"; return 1; }
}

@test "package checksum mismatch still fails with a redownload instruction" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  printf 'tampered\n' >>"$REL/v1.13.2/custodexa-1.13.2.tar.gz"
  upgrade_run en 1.13.2
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL]"* && $output == *"incomplete or damaged; download it again"* ]] || { echo "$output"; return 1; }
}

@test "package deployment, a version: verified, put in releases/, that version's script takes over" {
  backup_host ui
  fake_github
  publish 1.13.2 1.12.4
  upgrade_run en 1.13.2
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  Upgrade to         1.13.2' || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  Installed          1.13.0' || return 1
  [ -f "$ROOT/releases/1.13.2/custodexa.sh" ] || return 1
  [ -z "$(ls -A "$ROOT/releases" | grep incoming)" ] || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.13.0 ] || return 1
  # Run from releases/1.13.2 while current is 1.13.0: its own version is the target, no check.
  rm -f "$REL/requests"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang zh-TW </dev/null
  [ "$status" -eq 3 ] && printf '%s\n' "$output" | grep -qxF '  升級到       1.13.2' || { echo "$output"; return 1; }
  [ ! -e "$REL/requests" ]
}

@test "an unpacked package with no deployment here says where the running one is" {
  backup_host ui
  local pkg=$BATS_TEST_TMPDIR/package
  package_release "$pkg/releases/1.13.0" 1.13.0
  ln -s releases/1.13.0 "$pkg/current"
  ln -s current/custodexa.sh "$pkg/custodexa.sh"
  docker_says inspect_--format "$ROOT"
  run bash "$pkg/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"There is no deployment here: $pkg"* ]] || { echo "$output"; return 1; }
  [[ $output == *"CUSTODEXA_HOME=$ROOT sudo -E $pkg/releases/1.13.0/custodexa.sh upgrade"* ]] || { echo "$output"; return 1; }
}

# ---- the upgrade itself: the 13 steps, and where each failure leaves the services ----

# fresh <kek>: a new package deployment with 1.13.2 in releases/ (the earlier one is removed).
fresh() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host "${1:-ui}" || return 1
  clock 0 3 0 41 0 4 0 11
}

s10_of() { screen_of "$output" | sed -n '/^\(升級\|Upgrade\) 1.13.0/,/ 7\/13 /p' | sed '$d'; }
from_line() { screen_of "$output" | sed -n "/^$(printf '%s' "$1" | sed 's/[][\/.*]/\\&/g')/,\$p"; }
st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }
events_in_order() { # <event>... : each event appears, in this order
  local e n=0 at
  for e in "$@"; do
    at=$(grep -nx -m1 "$e" "$DB/events" | cut -d: -f1)
    [ -n "$at" ] && [ "$at" -gt "$n" ] || { echo "event $e missing or out of order"; cat "$DB/events"; return 1; }
    n=$at
  done
}

@test "the whole upgrade: the steps and the closing screen word for word, 1.13.2 current and recorded, backup before the switch" {
  for l in zh-TW en; do
    fresh ui
    full_run "$l"
    [ "$status" -eq 0 ] || { echo "$l: $status"; echo "$output"; return 1; }
    diff <(s10_of) "$TESTS_DIR/snapshots/s10.$l.txt" || { echo "$output"; return 1; }
    diff <(from_line "$(sed -n 1p "$TESTS_DIR/snapshots/s11.$l.txt")") "$TESTS_DIR/snapshots/s11.$l.txt" \
      || { echo "$output"; return 1; }
  done
  [ "$(readlink "$ROOT/current")" = releases/1.13.2 ] || return 1
  [ "$(st current.version)" = 1.13.2 ] && [ "$(st previous.version)" = 1.13.0 ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(st last_upgrade.result)" = succeeded ] && [ "$(st last_upgrade.step)" = 13 ] || return 1
  # Step 7 makes one backup file of the version it came from (rewritten from the backup folder of
  # earlier releases: the upgrade's backup is now the portable file).
  local f=backups/custodexa-backup-1.13.0-20260930-101502.tar
  [ "$(st last_upgrade.backup)" = "$f" ] && [ "$(st last_backup.file)" = "$f" ] && [ "$(st last_backup.kind)" = script ] || return 1
  [ -n "$(st previous.image_ids)" ] && [[ $(st current.image_ids) == *backend=sha256:* ]] || { cat "$ROOT/state.json"; return 1; }
  [ -s "$ROOT/$f" ] && (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "${f#backups/}.sha256") || return 1
  ! compgen -G "$ROOT/backups/.partial-*" >/dev/null || return 1
  events_in_order "stop backend guacd frontend" pg_dump pg_restore "tar pack ${f#backups/}" up || return 1
  ! grep -qx stop-all "$DB/events"
}

@test "upgrade records a handed-over package signature mismatch in state and log" {
  fresh ui
  export CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=mismatch'
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(st last_upgrade.package_verification)" = 'checksum=ok signature=mismatch' ] || { echo "$(st last_upgrade.package_verification)"; return 1; }
  grep -q 'VERIFY package checksum=ok signature=mismatch' "$ROOT"/logs/upgrade-*.log
}

@test "a failure before the switch: the services as the upgrade guide says, never started on the new version" {
  # 4: the queue cannot be read: nothing stopped, nothing changed.
  fresh ui
  touch "$UP/metrics.rc"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL]  4/13"* ]] || { echo "$output"; return 1; }
  ! grep -q '^stop\|^pg_dump\|^up' "$DB/events" || return 1
  [ "$(st last_upgrade.result)" = failed ] && [ "$(st last_upgrade.step)" = 4 ] || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.13.0 ] || return 1
  # 5: the stop fails: how to start the old version again; no backup, no switch.
  fresh ui
  printf '1\n' >"$DB/stop.rc"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL]  5/13"* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
  ! grep -q '^pg_dump\|^up' "$DB/events" || return 1
  # 7: the backup fails: what it took stays in its temporary folder and there is no backup file
  # (rewritten: the folder of earlier releases marked itself INCOMPLETE; the portable file is only
  # ever put in place whole), the old version's start command, unseal again (ui).
  fresh ui
  printf '1\n' >"$DB/pg_dump.rc"
  full_run zh-TW
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"        [FAIL] 資料庫"* ]] || { echo "$output"; return 1; }
  [ -d "$ROOT/backups/.partial-20260930-101502" ] && ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || return 1
  printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
  [[ $output == *"主金鑰模式是網頁輸入，服務恢復後要再解封一次。"* ]] || { echo "$output"; return 1; }
  ! grep -qx up "$DB/events" || return 1
  [ "$(st last_upgrade.step)" = 7 ] && [ "$(readlink "$ROOT/current")" = releases/1.13.0 ]
}

@test "a failure after the switch: the not-ready screen word for word; the next upgrade refuses with the backup and the restore guide, never runs again" {
  fresh ui
  touch "$UP/health.rc"
  full_run zh-TW
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(from_line '[FAIL] 升級停在第 11/13 步') "$TESTS_DIR/snapshots/s12c.zh-TW.txt" || { echo "$output"; return 1; }
  fresh ui
  touch "$UP/health.rc"
  full_run en
  diff <(from_line '[FAIL] The upgrade stopped at step 11/13') "$TESTS_DIR/snapshots/s12c.en.txt" || { echo "$output"; return 1; }
  # 10: the start fails: the same commands.
  fresh ui
  touch "$UP/up.rc"
  full_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The upgrade stopped at step 10/13: the new version did not start"* ]] \
    || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  To go back to 1.13.0, restore the backup above by hand as described' || { echo "$output"; return 1; }
  [ "$(st last_upgrade.result)" = failed ] && [ "$(st last_upgrade.step)" = 10 ] || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.13.2 ] || return 1
  # Running it again would back up a database the new version may have changed: refused.
  : >"$DB/events"
  rm "$UP/up.rc"
  full_run en 1.13.2
  [ "$status" -eq 3 ] && [[ $output == "[FAIL] The last upgrade stopped at step 10."* ]] || { echo "$output"; return 1; }
  # The backup file of the upgrade (rewritten from the folder).
  printf '%s\n' "$output" | grep -qxF "  Pre-upgrade backup: $ROOT/backups/custodexa-backup-1.13.0-20260930-101502.tar" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  To go back to 1.13.0, restore the backup above by hand as described' || { echo "$output"; return 1; }
  [[ $output != *"custodexa.sh rollback"* ]] || { echo "$output"; return 1; }
  ! grep -q '^stop\|^pg_dump\|^up' "$DB/events"
}

@test "the version the check suggests, alone (the main menu upgrades to it): newest, a required step first, none" {
  backup_host ui
  fake_github
  q() {
    run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en cx_load_libs "$1"; . "$1/lib/version_rules.sh"
      . "$1/lib/upgrade_query.sh"; CX_ROOT=$2; cx_state_load "$2/state.json"; cx_q_latest' _ "$SRC" "$ROOT"
  }
  publish 1.13.0 1.12.4
  q
  [ "$status" -ne 0 ] && [ -z "$output" ] || { echo "up to date: $status $output"; return 1; }
  publish 1.13.2 1.12.4
  q
  [ "$status" -eq 0 ] && [ "$output" = 1.13.2 ] || { echo "newest: $status $output"; return 1; }
  # Too far ahead: the minimum source version first, as the check prints it.
  publish 1.14.0 1.13.2
  q
  [ "$status" -eq 0 ] && [ "$output" = 1.13.2 ] || { echo "step first: $status $output"; return 1; }
  printf ' ' >>"$REL/v1.14.0/MANIFEST.json"
  q
  [ "$status" -ne 0 ] && [ -z "$output" ] || { echo "checksum: $status $output"; return 1; }
  touch "$REL/offline"
  q
  [ "$status" -ne 0 ] && [ -z "$output" ] || { echo "offline: $status $output"; return 1; }
}

# Rewritten with the portable file: state.json as the upgrade found it is a
# member of the upgrade's backup file now, not a file in a backup folder.
@test "the upgrade keeps the state.json it started from in its backup file (0600), for going back by hand" {
  fresh ui
  cp -p "$ROOT/state.json" "$BATS_TEST_TMPDIR/state-before"
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  BK_FILE=$ROOT/$(st last_upgrade.backup)
  [ -f "$BK_FILE" ] || { cat "$ROOT/state.json"; return 1; }
  cmp "$BATS_TEST_TMPDIR/state-before" <(bk_member state.json) || return 1
  [ "$(/usr/bin/tar -tvf "$BK_FILE" state.json | cut -c1-10)" = -rw------- ] || return 1
  # Part of the backup's checksums, like every other member of it.
  bk_member SHA256SUMS | grep -q ' state.json$' || { bk_member SHA256SUMS; return 1; }
  [ "$(bk_mf contents.state)" = true ] && [ "$(bk_mf trigger)" = upgrade ] || return 1
  ! cmp -s "$ROOT/state.json" <(bk_member state.json)
}

# Rewritten (the upgrade's backup was a folder beside the portable files of the backup command):
# the upgrade's backup is a file of its own, and it becomes the last backup on record.
@test "the upgrade's backup after an encrypted manual backup: its own file, the last backup on record, status shows it" {
  fresh ui
  # A manual backup first, recorded the way an encrypted one is (its file named .tar.enc).
  run bash "$ROOT/custodexa.sh" backup --lang en --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  local f
  f=$(st last_backup.file)
  [ -n "$f" ] && [ -f "$ROOT/$f" ] || { cat "$ROOT/state.json"; return 1; }
  mv "$ROOT/$f" "$ROOT/$f.enc"
  jq --arg f "$f.enc" '."last_backup.file" = $f | ."last_backup.encrypted" = "true"' "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" \
    && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  clock 0 3 0 41 0 4 0 11
  : >"$DB/events"
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(s10_of) "$TESTS_DIR/snapshots/s10.en.txt" || { echo "$output"; return 1; }
  # The manual backup took this second: the upgrade's file has the next one, the earlier file stays.
  local u=backups/custodexa-backup-1.13.0-20260930-101503.tar
  [ -f "$ROOT/$u" ] && [ -f "$ROOT/$f.enc" ] || { ls -lA "$ROOT/backups"; return 1; }
  [ "$(st last_upgrade.backup)" = "$u" ] && [ "$(st last_backup.file)" = "$u" ] && [ "$(st last_backup.encrypted)" = false ] \
    || { cat "$ROOT/state.json"; return 1; }
  [ "$(jq -r 'has("last_backup.dir") or has("last_backup.external_ref") or has("last_backup.partial")' "$ROOT/state.json")" = false ] \
    || { cat "$ROOT/state.json"; return 1; }
  ! grep -q '^start backend' "$DB/events" || { cat "$DB/events"; return 1; }
  run bk_status
  [[ $output == *"Latest $(date -d "$(st last_backup.taken_at)" '+%Y-%m-%d %H:%M') ("* ]] || { echo "$output"; return 1; }
  [[ $output == *"/opt/custodexa/$u"* ]] || { echo "$output"; return 1; }
  [[ $output != *".tar.enc"* && $output != *"encrypted"* ]] || { echo "$output"; return 1; }
}
