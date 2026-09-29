#!/usr/bin/env bats
# Threat (A): the version rules bypassed. An upgrade to an older version (that is a restore, and
# the older code meets a newer database), to the same version, or from a version older than the
# target's min_source_version (its migrations assume an intermediate version) must be refused,
# with nothing changed. Versions compare as numbers, not as text: 1.10.0 is newer than 1.9.0.
# The other checks before the preview refuse the same way: an unfinished earlier run, the
# development compose file, too little space. None of them may change anything.

load helper
load install_host
load backup_host
load upgrade_host

setup() {
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/version_rules.sh"
  export CX_ROOT=/opt/custodexa
}

cmp_is() { # <a> <b> <expected -1|0|1>
  local got
  got=$(cx_vr_cmp "$1" "$2") || { echo "cx_vr_cmp $1 $2 failed"; return 1; }
  [ "$got" = "$3" ] || { echo "cx_vr_cmp $1 $2 = $got, expected $3"; return 1; }
}

@test "versions compare as numbers, pre-releases before their release" {
  cmp_is 1.10.0 1.9.0 1 || return 1
  cmp_is 1.9.9 1.10.0 -1 || return 1
  cmp_is 1.13.10 1.13.2 1 || return 1
  cmp_is 2.0.0 1.99.99 1 || return 1
  cmp_is 1.13.0 1.13.0 0 || return 1
  cmp_is 1.13.0-rc.1 1.13.0 -1 || return 1
  cmp_is 1.13.0 1.13.0-rc.1 1 || return 1
  cmp_is 1.13.0-rc.2 1.13.0-rc.10 -1 || return 1
  cmp_is 1.13.0-rc.1 1.13.0-rc.1.1 -1 || return 1
  cmp_is 1.13.0-alpha 1.13.0-beta -1 || return 1
  cmp_is 1.13.0-1 1.13.0-alpha -1 || return 1
  cmp_is 1.12.4 1.13.0-rc.1 -1 || return 1
  cmp_is 12345678901234567890.0.0 9.0.0 1 || return 1
  for bad in 1.13 v1.13.0 1.13.0. 01.13.0 1.13.x ''; do
    run cx_vr_cmp "$bad" 1.13.0
    [ "$status" -eq 2 ] || { echo "accepted '$bad'"; return 1; }
  done
}

@test "downgrade refused, pointed at restoring the backup by hand, word for word (zh-TW, en), exit 3" {
  for l in zh-TW en; do
    run bash -c 'CX_LANG_FLAG=$1; . "$2/lib/common.sh"; cx_load_libs "$2"; . "$2/lib/version_rules.sh"
      CX_ROOT=/opt/custodexa cx_vr_check 1.13.0 1.12.4 1.12.4' _ "$l" "$SRC"
    [ "$status" -eq 3 ] || { echo "$l: status $status"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s06-older.$l.txt" || return 1
  done
}

@test "below min_source_version refused with the intermediate version, word for word, exit 3" {
  for l in zh-TW en; do
    run bash -c 'CX_LANG_FLAG=$1; . "$2/lib/common.sh"; cx_load_libs "$2"; . "$2/lib/version_rules.sh"
      CX_ROOT=/opt/custodexa cx_vr_check 1.12.9 1.14.0 1.13.0' _ "$l" "$SRC"
    [ "$status" -eq 3 ] || { echo "$l: status $status"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s06-skip.$l.txt" || return 1
  done
}

@test "each rule case by case: same version, pre-releases, the boundary of min_source_version" {
  refused() { run cx_vr_check "$@"; [ "$status" -eq 3 ] || { echo "allowed: $*"; return 1; }; }
  allowed() { run cx_vr_check "$@"; [ "$status" -eq 0 ] || { echo "refused: $*"; echo "$output"; return 1; }; }
  refused 1.13.0 1.13.0 1.12.4 || return 1
  [[ $output == *"[FAIL] 1.13.0 is already installed"* && $output == *"custodexa.sh status"* ]] || return 1
  refused 1.13.0 1.13.0-rc.3 1.12.4 || return 1   # a pre-release of the installed version is older
  refused 1.13.10 1.13.9 || return 1              # numbers, not text
  refused 1.12.3 1.13.0 1.12.4 || return 1        # one below the minimum
  refused 1.12.4-rc.1 1.13.0 1.12.4 || return 1   # a pre-release of the minimum is below it
  allowed 1.12.4 1.13.0 1.12.4 || return 1        # exactly the minimum
  allowed 1.12.9 1.13.0 1.12.4 || return 1
  allowed 1.13.0-rc.3 1.13.0 1.12.4 || return 1   # release over its pre-release
  allowed 1.13.9 1.13.10 || return 1              # numbers, not text
  allowed 1.13.0 1.14.0 || return 1               # no minimum given
  run cx_vr_check 1.13.0 latest 1.12.4
  [ "$status" -eq 2 ]
}

# ---------- through the upgrade command ----------

# up_host: a 1.13.0 package deployment, services running, the installed images present, a 17.4 GB
# database, and 1.13.2 published with one new migration.
up_host() {
  backup_host ui
  fake_github
  printf '%s\n' 18683107737 >"$DB/size"
  printf '%s\n' CUSTODEXA_IMAGE_BACKEND=ghcr.io/custodexa/backend:1.13.0 \
    CUSTODEXA_IMAGE_FRONTEND=ghcr.io/custodexa/frontend:1.13.0 >"$ROOT/current/images.env"
  docker_says image_inspect 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
  docker_says container_inspect 'true 0001-01-01T00:00:00Z'
  docker_says exec_custodexa-backend '{"status":"ok","version":"1.13.0"}'
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule
}

# preview_of <lang>: the preview, from its title to the line before the question.
preview_of() {
  case $1 in
    en) screen_of "$output" | sed -n '/^Custodexa upgrade preview/,/^    the upgrade$/p' ;;
    zh-TW) screen_of "$output" | sed -n '/^Custodexa 升級預覽/,/升級中斷的風險$/p' ;;
  esac
}

@test "the preview word for word, and nothing written or stopped before it is answered" {
  up_host
  upgrade_run en 1.13.2 # puts the verified 1.13.2 release in releases/, then hands over
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  : >"$FAKE_DOCKER_LOG"
  for l in zh-TW en; do
    run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang "$l" </dev/null
    [ "$status" -eq 3 ] || { echo "$l: $status"; echo "$output"; return 1; }
    diff <(preview_of "$l") "$TESTS_DIR/snapshots/s07.$l.txt" || { echo "$output"; return 1; }
  done
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT") || return 1
  ! grep -q ' stop \| down \| up ' "$FAKE_DOCKER_LOG" || return 1
  # The other forms of the preview: images missing, backend not running, nothing to apply.
  rm "$FAKE_DOCKER_REPLAY/image_inspect.out"
  docker_says container_inspect 'false 2026-09-30T02:00:00Z'
  printf '%s\n' 20260816_schema_baseline 20260901_add_x 20261010_report_schedule >"$DB/migrations"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  printf '%s\n' "$output" | grep -qxF '  - Some images of the installed version are not on this host; a' || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  - The backend is not running, so the audit queue cannot be checked;' || return 1
  printf '%s\n' "$output" | grep -qxF '  - This version does not change the database structure' || return 1
}

@test "refused through the upgrade command, nothing changed: older, same, below the minimum" {
  up_host
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  publish 1.12.9 1.12.4
  upgrade_run en 1.12.9
  [ "$status" -eq 3 ] && [[ $output == *"Cannot upgrade to 1.12.9: it is older than the installed 1.13.0"* ]] || { echo "$output"; return 1; }
  upgrade_run en 1.13.0
  [ "$status" -eq 3 ] && [[ $output == *"1.13.0 is already installed"* ]] || { echo "$output"; return 1; }
  # A package whose MANIFEST needs a newer source version: refused before it is put in releases/.
  publish 1.14.0 1.13.1
  upgrade_run en "$REL/v1.14.0/custodexa-1.14.0.tar.gz"
  [ "$status" -eq 3 ] && [[ $output == *"sudo $ROOT/custodexa.sh upgrade 1.13.1"* ]] || { echo "$output"; return 1; }
  # Nothing was downloaded for the refused versions.
  ! grep -q 'v1.12.9\|v1.13.0/' "$REL/requests" 2>/dev/null || { cat "$REL/requests"; return 1; }
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT") || return 1
  ! grep -q ' stop \| down \| up ' "$FAKE_DOCKER_LOG"
}

@test "an unfinished earlier run: refused with how to recover, exit 3, nothing changed" {
  up_host
  upgrade_run en 1.13.2 # puts the verified 1.13.2 release in place
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  printf '{\n  "format": "2",\n  "current.version": "1.13.0",\n  "current.overlays": "",\n  "last_backup.result": "in_progress",\n  "last_backup.step": "3"\n}\n' \
    >"$ROOT/state.json"
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The last last_backup run was interrupted at step 3."* ]] || { echo "$output"; return 1; }
  [[ $output == *"sudo $ROOT/custodexa.sh status"* ]] || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || { echo "$output"; return 1; }
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT")
}

# interrupted_at <step> [backend inspect answer]: last_upgrade left in progress at that step.
interrupted_at() {
  printf '{\n  "format": "2",\n  "compose_project": "custodexa",\n  "current.version": "1.13.0",\n  "current.overlays": "",\n  "previous.version": "1.12.4",\n  "last_backup.dir": "backups/20260930-021504",\n  "last_upgrade.log": "logs/upgrade-20260930-021504.log",\n  "last_upgrade.result": "in_progress",\n  "last_upgrade.step": "%s"\n}\n' "$1" \
    >"$ROOT/state.json"
  docker_says container_inspect "${2:-true 0001-01-01T00:00:00Z}"
  tree_of "$ROOT" >"$BATS_TEST_TMPDIR/before"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] || { echo "step $1: $status"; echo "$output"; return 1; }
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$ROOT") || return 1
}

@test "an interrupted upgrade: starts over while nothing was switched and it runs, else that step's commands" {
  up_host
  upgrade_run en 1.13.2 # puts the verified 1.13.2 release in place
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  # Up to the drain gate the old version ran unchanged: a warning, then the preview again.
  interrupted_at 4 || return 1
  [[ $output == "[WARN] The last upgrade run was interrupted at step 4."* ]] || { echo "$output"; return 1; }
  [[ $output == *"nothing was changed. Starting over."* ]] || { echo "$output"; return 1; }
  [[ $output == *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # Whether or not the backend runs now: the upgrade had not stopped anything yet.
  interrupted_at 4 'false 2026-09-30T02:15:30Z' || return 1
  [[ $output == "[WARN] The last upgrade run was interrupted at step 4."* ]] || { echo "$output"; return 1; }
  [[ $output == *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # Stopped, not switched, and started again by hand: the same.
  interrupted_at 6 || return 1
  [[ $output == "[WARN] The last upgrade run was interrupted at step 6."* ]] || { echo "$output"; return 1; }
  [[ $output == *"Starting over, with a new backup."* ]] || { echo "$output"; return 1; }
  [[ $output == *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # Stopped and still stopped: how to start the old version, then the upgrade again. No preview.
  interrupted_at 6 'false 2026-09-30T02:15:30Z' || return 1
  [[ $output == "[FAIL] The last upgrade run was interrupted at step 6."* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "    sudo docker compose -p custodexa --project-directory $ROOT -f $ROOT/current/compose.yml \\" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "    sudo $ROOT/custodexa.sh upgrade 1.13.2" || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # Step 8 of a package deployment reorganizes nothing: the same as stopped and not switched.
  interrupted_at 8 'false 2026-09-30T02:15:30Z' || return 1
  printf '%s\n' "$output" | grep -qxF '      start backend guacd frontend' || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # During a conversion that already wrote state.json: the commands that put the clone back.
  printf '{\n  "format": "2",\n  "current.version": "1.12.4",\n  "current.kind": "legacy-git-clone",\n  "conversion.from": "1.12.4",\n  "conversion.old_project": "custodexa",\n  "conversion.old_files": "%s/docker-compose.yml",\n  "conversion.env_backup": "backups/20260930-021504/env-before-convert.bak",\n  "last_upgrade.result": "in_progress",\n  "last_upgrade.step": "8"\n}\n' "$ROOT" >"$ROOT/state.json"
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == "[FAIL] The last upgrade run was interrupted at step 8."* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "    sudo rmdir $ROOT/releases/1.12.4" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "    sudo cp $ROOT/backups/20260930-021504/env-before-convert.bak \\" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "      -f $ROOT/docker-compose.yml up -d" || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || { echo "$output"; return 1; }
  # Switched to the new version, running or not: the log, the backup and how to restore it by
  # hand; never over again.
  interrupted_at 10 || return 1
  [[ $output == "[FAIL] The last upgrade run was interrupted at step 10."* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "    sudo docker compose -p custodexa -f $ROOT/current/compose.yml logs --tail 50 backend" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "  Pre-upgrade backup: $ROOT/backups/20260930-021504/" || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  To go back to 1.12.4, restore the backup above by hand as described' || { echo "$output"; return 1; }
  [[ $output != *"custodexa.sh rollback"* ]] || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || { echo "$output"; return 1; }
  ! grep -q ' stop \| down \| up \| start ' "$FAKE_DOCKER_LOG"
}

@test "the development compose file on a git clone: refused, exit 3, nothing changed" {
  legacy_host
  printf '%s\n' COMPOSE_FILE=docker-compose.dev.yml >>"$LROOT/.env"
  tree_of "$LROOT" >"$BATS_TEST_TMPDIR/before"
  legacy_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] This deployment uses the development compose file (COMPOSE_FILE=docker-compose.dev.yml)."* ]] \
    || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || return 1
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$LROOT")
}

@test "too little space for the backup and the new images: FAIL before the preview, nothing stopped" {
  up_host
  host_free / 18874368 # 18 GB in KiB, under the 18.4 GB estimate
  upgrade_run zh-TW 1.13.2
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 備份空間不足：預估需要 18.4 GB，$ROOT/backups 只剩 18.0 GB。"* ]] || { echo "$output"; return 1; }
  [[ $output != *"升級預覽"* ]] || return 1
  [ ! -e "$ROOT/backups" ] || return 1
  ! grep -q ' stop \| down \| up ' "$FAKE_DOCKER_LOG"
}
