#!/usr/bin/env bats
# Screen snapshots of db-upgrade, the clean-up confirmation and the status database section (task 3.11):
# P11-P15. The deployment is the one of test_db_upgrade.bats.

load helper
load install_host
load backup_host
load upgrade_host
load pgconvert_host

setup() {
  backup_host ui
  jq '.["current.kind"] = "package"' "$ROOT/state.json" >"$ROOT/state.new" && /usr/bin/mv "$ROOT/state.new" "$ROOT/state.json"
  pgc_manifest "$ROOT/releases/1.13.0" with 18
  pgc_version 18 postgresql 18/docker
  bk_server 18.6
  D=$ROOT/data
  printf 'x\n' >"$D/postgresql/18/docker/file"
  size_of "$D/postgresql/18/docker/file" 18.2
}

# dbu <arguments>: the command with no terminal.
dbu() { run bash "$ROOT/custodexa.sh" db-upgrade "$@" --lang en </dev/null; }

# old_dir <name> <major>: an old data folder with something in it.
# The third argument is its size in GiB (a sparse file: the screens print the apparent size).
old_dir() {
  mkdir -p "$D/$1"
  printf '%s\n' "$2" >"$D/$1/PG_VERSION"
  printf 'data\n' >"$D/$1/file"
  if [ -n "${3:-}" ]; then truncate -s "$(awk -v g="$3" 'BEGIN { printf "%.0f", g * 1073741824 }')" "$D/$1/file"; fi
}
# size_of <path> <GiB>: the apparent size of a file.
size_of() { truncate -s "$(awk -v g="$2" 'BEGIN { printf "%.0f", g * 1073741824 }')" "$1"; }

# upgraded: the state of a 1.23 deployment that was upgraded from 1.22 and started.
upgraded() {
  mkdir -p "$ROOT/backups"
  printf 'backup\n' >"$ROOT/backups/custodexa-backup-1.22.0-20261120-021700.tar"
  size_of "$ROOT/backups/custodexa-backup-1.22.0-20261120-021700.tar" 18.1
  bk_state_set last_upgrade.to 1.23.0
  bk_state_set previous.version 1.22.0
  bk_state_set last_upgrade.result succeeded
  bk_state_set last_upgrade.step 13
  bk_state_set last_upgrade.new_started_at 2026-11-20T02:30:00+0800
  bk_state_set last_upgrade.backup backups/custodexa-backup-1.22.0-20261120-021700.tar
  bk_state_set last_upgrade.backup_kind script
}

# menu_lines <external|builtin> <typed lines>: the main menu on a terminal as seen.
menu_lines() {
  if [ "$1" = external ]; then bk_state_set current.overlays external-database; fi
  run script -qec "cd $BATS_TEST_TMPDIR && bash $ROOT/custodexa.sh --lang en" /dev/null <<<"$2"
  printf '%s\n' "$output" | tr -d '\r' | sed -E '/^[0-9]+$/d'
}

# each <name> <body>: the body runs per language after a reset of the deployment folder.
each() {
  local l rc=0
  for l in en zh-TW ja; do
    LNG=$l
    "$2"
    pg_emit "$1" "$l" || rc=1
    pg_reset
  done
  return $rc
}
db() { run bash "$ROOT/custodexa.sh" db-upgrade "$@" --lang "$LNG" </dev/null; }
tt() { local a=$1; shift; run script -qec "$*" /dev/null <<<"$a"; output=$(printf '%s' "$output" | tr -d '\r'); }

p11b() { db; }
# p11a: the main menu, the database upgrade entry, Enter at the question; what the entry printed.
p11a() {
  local first last
  pg_lang "$LNG"
  run script -qec "cd $BATS_TEST_TMPDIR && bash $ROOT/custodexa.sh --lang $LNG" /dev/null <<<$'8\n\n0'
  first=$MSG_dbu_title last=${MSG_menu_choose_remove%%\%s*}
  # the title follows the menu's question on the same line
  output=$(printf '%s\n' "$output" | tr -d '\r' | awk -v f="$first" -v l="$last" '
    !on && length($0) >= length(f) && substr($0, length($0) - length(f) + 1) == f { on = 1; print f; next }
    on { print } on && index($0, l) == 1 { exit }')
}
p13a() {
  tt "16" "bash $ROOT/custodexa.sh db-upgrade --remove-old --lang $LNG"
  # the pty echoes the typed answer first; a terminal shows it after the prompt
  output=$(printf '%s\n' "$output" | sed '1d' | sed 's/^> $/> 16\n/')
}
p13b() { /usr/bin/rm -f "$ROOT"/backups/custodexa-backup-1.22.0-*.tar; db --remove-old --yes; }
p13c() { db --remove-old; }
p14a() { bk_state_set last_upgrade.result in_progress; bk_state_set last_upgrade.step 11; bk_state_set last_upgrade.new_started_at ""; db --remove-old --yes; }
p14b() { hook_before 'case " $* " in *" wget "*) exit 1 ;; esac'; db --remove-old --yes; }
# p15 <external|removing|sums>: the database section of status, as printed (the title line to the next).
p15() {
  hook_before 'case " $* " in *" exec custodexa-postgres psql "*) echo on; exit 0 ;; esac'
  pg_lang "$LNG"
  run bash "$ROOT/custodexa.sh" status --lang "$LNG" </dev/null
  output=$(printf '%s\n' "$output" | awk -v t="$MSG_status_sec_db" '$0 == t { on = 1; print; next } on && /^[^ ]/ { exit } on { print }')
}
p15a() { p15; }
p15b() { bk_state_set current.overlays external-database; bk_state_set current.external_db_host db01.example.internal; p15; }
p12() { bk_state_set current.overlays external-database; bk_state_set current.external_db_host db01.example.internal; db; }

@test "P11 up to date" {
  upgraded
  old_dir postgres 16 17.4
  old_dir postgresql.failed-convert-20261119-231004 18 3.2
  pg_keep
  each P11a p11a
  find "$D/postgresql.failed-convert-20261119-231004" -delete
  pg_keep
  each P11b p11b
  find "$D/postgres" -delete
  pg_keep
  each P11c p11b
}
@test "P12 external" {
  upgraded
  pg_keep
  each P12 p12
}
@test "P13 removal" {
  upgraded
  old_dir postgres 16 17.4
  pg_keep
  each P13a p13a
  each P13b p13b
  each P13c p13c
}
@test "P14 refusals" {
  upgraded
  old_dir postgres 16 17.4
  pg_keep
  each P14a p14a
  each P14b p14b
}
@test "P15 status" {
  upgraded
  old_dir postgres 16 17.4
  old_dir postgresql.rolled-back-20261123-101502 18 18.0
  pg_keep
  each P15a p15a
  each P15b p15b
  find "$D/postgres" "$D/postgresql.rolled-back-20261123-101502" -delete
  old_dir postgres.removing-20261201-102011 16 9.1
  pg_keep
  each P15c p15a
}
