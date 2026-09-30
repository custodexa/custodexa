#!/usr/bin/env bats
# Threat (A): the first conversion cannot be entered (a git clone deployment falls into the
# check-only branch, so it can never be converted by the script), or a call that should only check
# changes something. On a clone, a bare `upgrade`, a version and a package all lead to the conversion
# preview and nothing is written before it is answered; `--yes` alone is refused. On a package
# deployment the bare call only checks, and says whether the release manifest was verified; a
# checksum mismatch gives no answer about upgrading. A version or a package is verified before the
# target version's script takes over.

load helper
load install_host
load backup_host
load upgrade_host

s08_head() { # <lang> <installed> <target> <root>
  case $1 in
    zh-TW) printf '%s\n' 'Custodexa 升級預覽（還沒有做任何變更）' '' "  目前版本     $2（git clone 部署，$4）" \
      "  升級到       $3" '  這台主機還是 git clone 部署。這是第一次用管理腳本升級，會先把' \
      '  部署目錄整理成新的結構，再完成升級。' ;;
    en) printf '%s\n' 'Custodexa upgrade preview (nothing has been changed yet)' '' \
      "  Installed    $2 (git clone deployment, $4)" "  Upgrade to   $3" \
      '  This host still runs a git clone deployment. This is the first' \
      '  upgrade with the management script, so the deployment folder is' \
      '  reorganized first and the upgrade is then completed.' ;;
  esac
}

@test "clone, bare upgrade: the conversion preview for this script's version, never the check" {
  legacy_host
  fake_github
  tree_of "$LROOT" >"$BATS_TEST_TMPDIR/before"
  for l in zh-TW en; do
    legacy_run "$l"
    # No terminal and no --yes: the preview is shown, the question cannot be asked, exit 3.
    [ "$status" -eq 3 ] || { echo "$l: status $status"; echo "$output"; return 1; }
    diff <(printf '%s\n' "$output" | head -n 7 | grep -v '^$' ) <(s08_head "$l" 1.12.4 1.13.0 "$LROOT" | grep -v '^$') \
      || { echo "$output"; return 1; }
  done
  [ ! -e "$REL/requests" ] || { echo "downloaded:"; cat "$REL/requests"; return 1; }
  ! grep -q ' stop \| down ' "$FAKE_DOCKER_LOG" || return 1
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$LROOT")
}

@test "clone, bare upgrade --yes: refused (exit 3), nothing written" {
  legacy_host
  tree_of "$LROOT" >"$BATS_TEST_TMPDIR/before"
  legacy_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"加上 --yes 時請寫明要升級到的版本或安裝包路徑"* ]] || { echo "$output"; return 1; }
  [[ $output == *"sudo $PKG/releases/1.13.0/custodexa.sh upgrade 1.13.0 --yes"* ]] || { echo "$output"; return 1; }
  [[ $output != *"升級預覽"* ]] || return 1
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$LROOT")
}

@test "clone, this script's version or another one: both reach the conversion preview" {
  legacy_host
  fake_github
  legacy_run en 1.13.0
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output" | head -n 7 | grep -v '^$') <(s08_head en 1.12.4 1.13.0 "$LROOT" | grep -v '^$') || return 1
  [ ! -e "$REL/requests" ] || return 1
  # Another version: downloaded and verified by this script, then that version's script takes over
  # and shows the conversion preview in the language asked for.
  publish 1.13.2 1.12.4
  legacy_run en 1.13.2
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] custodexa-1.13.2.tar.gz: checksum and publisher signature verified"* ]] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output" | sed -n '2,$p' | head -n 7 | grep -v '^$') <(s08_head en 1.12.4 1.13.2 "$LROOT" | grep -v '^$') \
    || { echo "$output"; return 1; }
  grep -qx 'https://github.com/custodexa/custodexa/releases/download/v1.13.2/custodexa-1.13.2.tar.gz' "$REL/requests" || return 1
  # A package given by path: the same.
  legacy_run zh-TW "$REL/v1.13.2/custodexa-1.13.2.tar.gz"
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"  升級到       1.13.2"* && $output == *"git clone 部署，$LROOT"* ]] || { echo "$output"; return 1; }
}

@test "clone, a package with bad checksum stops; mismatched signature warns and previews" {
  legacy_host
  fake_github
  publish 1.13.2 1.12.4
  printf 'tampered\n' >>"$REL/v1.13.2/custodexa-1.13.2.tar.gz"
  legacy_run en 1.13.2
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"The checksum of custodexa-1.13.2.tar.gz does not match SHA256SUMS"* ]] || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || return 1
  [ -z "$(ls -A "$LROOT" | grep incoming)" ] || { ls -A "$LROOT"; return 1; }
  # Signed by someone else: warn, then reach the normal preview confirmation.
  publish 1.13.2 1.12.4
  sed -i 's#refs/tags/v1.13.2#refs/tags/v9.9.9#' "$REL/v1.13.2/SHA256SUMS.sigstore.json"
  legacy_run en 1.13.2
  [ "$status" -eq 3 ] && [[ $output == *"[WARN] custodexa-1.13.2.tar.gz: signature mismatch, publisher unverified"* && $output == *"upgrade preview"* ]] || { echo "$output"; return 1; }
}

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
  legacy_host
  fake_github
  publish 1.13.2 1.12.4
  printf 'tampered\n' >>"$REL/v1.13.2/custodexa-1.13.2.tar.gz"
  legacy_run en 1.13.2
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
  legacy_host
  docker_says inspect_--format "$LROOT"
  run bash "$PKG/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"There is no deployment here: $PKG"* ]] || { echo "$output"; return 1; }
  [[ $output == *"CUSTODEXA_HOME=$LROOT sudo -E $PKG/releases/1.13.0/custodexa.sh upgrade"* ]] || { echo "$output"; return 1; }
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
  [ "$(st last_upgrade.backup)" = backups/20260930-101502 ] && [ "$(st last_backup.kind)" = script ] || return 1
  [ -n "$(st previous.image_ids)" ] && [[ $(st current.image_ids) == *backend=sha256:* ]] || { cat "$ROOT/state.json"; return 1; }
  [ -s "$ROOT/backups/20260930-101502/SHA256SUMS" ] && [ ! -e "$ROOT/backups/20260930-101502/INCOMPLETE" ] || return 1
  events_in_order "stop backend guacd frontend" pg_dump pg_restore up || return 1
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
  # 7: the backup fails: INCOMPLETE stays, the old version's start command, unseal again (ui).
  fresh ui
  printf '1\n' >"$DB/pg_dump.rc"
  full_run zh-TW
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"        [FAIL] 資料庫"* ]] || { echo "$output"; return 1; }
  [ -e "$ROOT/backups/20260930-101502/INCOMPLETE" ] || return 1
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
  printf '%s\n' "$output" | grep -qxF "  Pre-upgrade backup: $ROOT/backups/20260930-101502/" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  To go back to 1.13.0, restore the backup above by hand as described' || { echo "$output"; return 1; }
  [[ $output != *"custodexa.sh rollback"* ]] || { echo "$output"; return 1; }
  ! grep -q '^stop\|^pg_dump\|^up' "$DB/events"
}

@test "a git clone deployment: stopped, backed up and its containers removed on its own project and root compose file, no state.json before the conversion" {
  legacy_host
  fake_github
  export ROOT=$LROOT
  mkdir -p "$LROOT/data/recordings" "$LROOT/data/audit"
  upgrade_stack 1.13.0
  docker_says inspect_--format 'custodexa_old'
  run env CUSTODEXA_HOME="$LROOT" bash "$PKG/custodexa.sh" upgrade 1.13.0 --yes --lang en </dev/null
  [ "$status" -eq 0 ] && [[ $output == *"[ OK ]  8/13"* ]] || { echo "$output"; return 1; }
  old="-p custodexa_old --project-directory $LROOT -f $LROOT/docker-compose.yml"
  grep -qF "compose $old stop backend guacd frontend" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -qF "compose $old exec -T postgres pg_dump" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  grep -qF "compose $old down" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  # Until the old containers are gone, never the release's compose file.
  sed -n "1,/compose $old down/p" "$FAKE_DOCKER_LOG" | grep -q 'current/compose.yml' && { cat "$FAKE_DOCKER_LOG"; return 1; }
  # state.json is written by the conversion: nothing before it ran while one existed.
  ! grep -q ' stop \| down\|pg_dump' "$UP/with_state" 2>/dev/null || { echo "state.json written before the conversion"; cat "$UP/with_state"; return 1; }
  ls "$LROOT"/backups/*/SHA256SUMS >/dev/null && grep -qx up "$DB/events"
}

@test "first conversion records handed-over package signature mismatch in log and state" {
  legacy_host
  export ROOT=$LROOT CX_UP_PACKAGE_VERIFICATION='checksum=ok signature=mismatch'
  mkdir -p "$LROOT/data/recordings" "$LROOT/data/audit"
  upgrade_stack 1.13.0
  docker_says inspect_--format 'custodexa_old'
  run env CUSTODEXA_HOME="$LROOT" bash "$PKG/custodexa.sh" upgrade 1.13.0 --yes --lang en </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_upgrade.package_verification" // ""' "$LROOT/state.json")" = 'checksum=ok signature=mismatch' ] || { cat "$LROOT/state.json"; return 1; }
  grep -q 'VERIFY package checksum=ok signature=mismatch' "$LROOT"/logs/upgrade-*.log
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

@test "the upgrade keeps the state.json it started from in its backup folder (0600), for going back by hand" {
  fresh ui
  cp -p "$ROOT/state.json" "$BATS_TEST_TMPDIR/state-before"
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk=$ROOT/$(st last_upgrade.backup)
  cmp "$BATS_TEST_TMPDIR/state-before" "$bk/state.json" || { diff "$BATS_TEST_TMPDIR/state-before" "$bk/state.json"; return 1; }
  [ "$(stat -c %a "$bk/state.json")" = 600 ] || return 1
  # Part of the backup's checksums, like every other file in it.
  grep -q ' state.json$' "$bk/SHA256SUMS" || { cat "$bk/SHA256SUMS"; return 1; }
  ! cmp -s "$ROOT/state.json" "$bk/state.json"
}
