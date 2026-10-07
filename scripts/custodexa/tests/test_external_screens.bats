#!/usr/bin/env bats
# The screens of a backup of an external database and of the upgrade's backup, word for word in
# zh-TW and en (ja for the two refusals that list what the server runs or has): a screen that says
# something the run did not do, or drops a line an operator acts on, shows here as a difference
# from the reviewed text. Each screen's file is in tests/snapshots; the list below is all of them.

load helper
load install_host
load backup_host
load upgrade_host
load pty_host

# The snapshot files these screens are compared with, and nothing else under these names.
SCREENS=(
  backup-external-preview backup-external-preview-ca backup-external-progress backup-external-no-tool
  backup-external-unreachable backup-external-no-image backup-external-unsupported
  backup-external-unsupported-tls backup-external-roles
  upgrade-external-own-only upgrade-external-ref-preview upgrade-external-refused
  upgrade-external-step6 upgrade-backup-steps upgrade-no-space
)
# The screens also checked in Japanese.
JA_SCREENS=" backup-external-no-tool backup-external-unsupported "

# screen_is <name> <lang> <text>: the text is the snapshot, word for word; on a difference the
# text is printed in full (between === lines) with the diff, and SCREEN_BAD is set.
SCREEN_BAD=0
screen_is() {
  local f=$TESTS_DIR/snapshots/$1.$2.txt
  if ! diff "$f" <(printf '%s\n' "$3") >/dev/null 2>&1; then
    printf '=== %s.%s\n%s\n=== end\n' "$1" "$2" "$3"
    diff "$f" <(printf '%s\n' "$3") || true
    SCREEN_BAD=1
  fi
}

langs_of() { if [[ $JA_SCREENS == *" $1 "* ]]; then echo zh-TW en ja; else echo zh-TW en; fi; }

# ---------- the backup command on an external database ----------

backup_ext_host() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  backup_host ui
  backup_strict
  fake sleep ':'
  host_arch x86_64
  clock
  printf '%s\n' 18683107737 >"$DB/size"
  bk_external
}

refused_screen() { screen_of "$output" | sed -n '/^\[FAIL\]/,$p'; }
# preview_of: the preview, from its title to its first blank line after the warning about a standby.
preview_of() {
  screen_of "$output" | awk '/^(備份預覽|Backup preview|バックアップのプレビュー)/ { f = 1 } f && w && /^$/ { exit } f { print } /\[WARN\]/ { w = 1 }'
}

@test "the snapshot files of these screens are exactly the list" {
  local -a want=() have=()
  local n l
  for n in "${SCREENS[@]}"; do
    for l in $(langs_of "$n"); do want+=("$n.$l.txt"); done
  done
  mapfile -t have < <(cd "$TESTS_DIR/snapshots" && ls backup-external-*.txt upgrade-*.txt 2>/dev/null)
  diff <(printf '%s\n' "${want[@]}" | sort) <(printf '%s\n' "${have[@]}" | sort)
}

@test "screens (backup, external): the preview, with the system's authorities and with a CA file" {
  local l
  for l in zh-TW en; do
    backup_ext_host
    backup_run "$l"
    screen_is backup-external-preview "$l" "$(preview_of)"
    backup_ext_host
    bk_env_set DB_SSLMODE require
    printf -- '-----BEGIN CERTIFICATE-----\nMIIBtest-ca\n-----END CERTIFICATE-----\n' >"$ROOT/data/audit/db-ca.pem"
    bk_env_set PGSSLROOTCERT /var/log/custodexa/audit/db-ca.pem
    backup_run "$l"
    screen_is backup-external-preview-ca "$l" "$(preview_of)"
  done
  [ "$SCREEN_BAD" = 0 ]
}

@test "screens (backup, external): the steps, the first one leaving the external database alone" {
  local l
  for l in zh-TW en; do
    backup_ext_host
    backup_run "$l" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen_is backup-external-progress "$l" "$(screen_of "$output" | sed -n '/ 1\/7 /,/ 7\/7 /p')"
  done
  [ "$SCREEN_BAD" = 0 ]
}

@test "screens (backup, external): the refusals before any stop (no client of the major, unreachable, no client image, unsupported settings)" {
  local l
  for l in zh-TW en ja; do
    backup_ext_host
    bk_server 15.8
    backup_run "$l" --yes
    screen_is backup-external-no-tool "$l" "$(refused_screen)"
    backup_ext_host
    printf '%s|3\n' "$(bk_hex fast_ssd)" >"$DB/tablespaces"
    printf '%s|12\n' "$(bk_hex report_owner)" >"$DB/owners"
    printf 'pg_trgm 1.6\n' >"$DB/extensions"
    bk_env_set DB_SSLMODE verify-ca
    printf '%s\n' "${BK_PGC_ID[17]}" >"$DB/sysca.absent"
    backup_run "$l" --yes
    screen_is backup-external-unsupported "$l" "$(refused_screen)"
  done
  for l in zh-TW en; do
    backup_ext_host
    printf '2\n' >"$DB/connect.rc"
    backup_run "$l" --yes
    screen_is backup-external-unreachable "$l" "$(refused_screen)"
    backup_ext_host
    grep -vxF "${BK_PGC_ID[18]}" "$DB/images" >"$DB/images.new" && mv "$DB/images.new" "$DB/images"
    backup_run "$l" --yes
    screen_is backup-external-no-image "$l" "$(refused_screen)"
    # The TLS settings the client cannot follow are refused before the server is asked anything,
    # so they are listed on their own.
    backup_ext_host
    bk_env_set PGSSLROOTCERT /etc/ssl/db-ca.pem
    mkdir -p "$ROOT/data/audit/keys"
    printf 'key\n' >"$ROOT/data/audit/keys/client.key"
    bk_env_set PGSSLKEY /var/log/custodexa/audit/keys/client.key
    backup_run "$l" --yes
    screen_is backup-external-unsupported-tls "$l" "$(refused_screen)"
  done
  [ "$SCREEN_BAD" = 0 ]
}

@test "screens (backup, external): privileges granted to other roles, on the closing screen" {
  local l
  for l in zh-TW en; do
    backup_ext_host
    printf '%s\n' "$(bk_hex 'report reader')" "$(bk_hex monitor)" >"$DB/grants"
    backup_run "$l" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen_is backup-external-roles "$l" "$(screen_of "$output" | awk '/\[WARN\] (The external database grants|外接資料庫裡有權限授予)/ { f = 1; print; next } f && !/^         / { exit } f { print }')"
  done
  [ "$SCREEN_BAD" = 0 ]
}

# ---------- the upgrade ----------

# plan_of: the preview from what will happen to its last line before the question.
plan_of() { awk '/^(會做的事|What will happen|実行内容)/ { f = 1 } /^(開始升級嗎|Start the upgrade|アップグレードを開始|\[FAIL\])/ { exit } f { print }'; }

@test "screens (upgrade, external): the preview when only an own backup is possible, and with --backup-ref" {
  local l s
  for l in zh-TW en; do
    fresh_ext online 15.8
    PTY_LANG=$l pty_up "$BATS_TEST_TMPDIR/screen" -- "[y/N] " n || true
    s=$(pty_screen "$BATS_TEST_TMPDIR/screen" | plan_of)
    screen_is upgrade-external-own-only "$l" "$s"
    fresh_ext online 17.6
    printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
    run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang "$l" --backup-ref vm-snap-0217 \
      --backup-time '2026-09-30 02:17' --backup-restore /doc </dev/null
    screen_is upgrade-external-ref-preview "$l" "$(screen_of "$output" | plan_of)"
  done
  [ "$SCREEN_BAD" = 0 ]
}

@test "screens (upgrade, external): the refusal without a terminal, and step 6 without a client" {
  local l
  for l in zh-TW en; do
    fresh_ext online 15.8
    full_run "$l"
    screen_is upgrade-external-refused "$l" "$(refused_screen)"
    fresh_ext online 17.6
    printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
    full_run "$l" --backup-ref vm-snap-0217 --backup-time '2026-09-30 02:17' --backup-restore /doc
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen_is upgrade-external-step6 "$l" "$(screen_of "$output" | sed -n '/ 6\/13 /,/ 7\/13 /p' | sed '$d')"
  done
  [ "$SCREEN_BAD" = 0 ]
}

@test "screens (upgrade): the lines of step 7, and too little space for the backup file" {
  local l
  for l in zh-TW en; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    upgraded_host ui
    clock 0 3 0 41 0 4 0 11
    full_run "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    screen_is upgrade-backup-steps "$l" "$(screen_of "$output" | sed -n '/ 7\/13 /,/ 8\/13 /p' | sed '$d')"
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    upgraded_host ui
    host_free / 18874368
    full_run "$l"
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    screen_is upgrade-no-space "$l" "$(refused_screen)"
  done
  [ "$SCREEN_BAD" = 0 ]
}
