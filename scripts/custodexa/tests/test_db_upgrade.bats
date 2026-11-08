#!/usr/bin/env bats
# lib/cmd_db_upgrade.sh, lib/db_old.sh, the menu entry and the status database section.
# Each test works on backup_host's deployment, made a bundled PostgreSQL 18 one, with the fake docker.

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
}

# dbu <arguments>: the command with no terminal.
dbu() { run bash "$ROOT/custodexa.sh" db-upgrade "$@" --lang en </dev/null; }

# old_dir <name> <major>: an old data folder with something in it.
old_dir() { mkdir -p "$D/$1"; printf '%s\n' "$2" >"$D/$1/PG_VERSION"; printf 'data\n' >"$D/$1/file"; }

# upgraded: the state of a 1.23 deployment that was upgraded from 1.22 and started.
upgraded() {
  mkdir -p "$ROOT/backups"
  printf 'backup\n' >"$ROOT/backups/custodexa-backup-1.22.0-20261120-021700.tar"
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

@test "[pg18] 已是最新" {
  old_dir postgres 16
  dbu
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"PostgreSQL 18, data in $D/postgresql"* ]] || { echo "$output"; return 1; }
  [[ $output == *"no upgrade needed"* && $output == *"$D/postgres"* && $output == *"only queries"* ]] || { echo "$output"; return 1; }
  ! grep -qE ' (stop|up|start|rm|kill) ' "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  [ -d "$D/postgres" ] || return 1
}

@test "the kept folders of every kind are listed with version and size, and without any the screen says nothing changed" {
  find "$D/postgres" -delete
  dbu
  [ "$status" -eq 0 ] && [[ $output == *"Nothing was changed."* && $output != *"kept"* ]] || { echo "$output"; return 1; }
  old_dir postgres 16
  old_dir postgresql.before-convert-20261120-021800 16
  old_dir postgresql.rolled-back-20261123-101502 18
  old_dir postgres.before-restore-20261125-093015 16
  old_dir postgresql.failed-convert-20261119-231004 18
  old_dir postgresql.partial-convert-20261119-231005 18
  mkdir -p "$D/audit.before-restore-1"
  dbu
  for n in postgres postgresql.before-convert-20261120-021800 postgresql.rolled-back-20261123-101502 \
    postgres.before-restore-20261125-093015 postgresql.failed-convert-20261119-231004 postgresql.partial-convert-20261119-231005; do
    [[ $output == *"$D/$n"$'\n'* ]] || { echo "not listed: $n"; echo "$output"; return 1; }
  done
  [[ $output != *"audit.before-restore"* ]] || return 1
}

@test "[pg18] 外接資料庫部署" {
  bk_state_set current.overlays external-database
  bk_state_set current.external_db_host db.example.internal
  dbu
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"external database db.example.internal:5432"* && $output == *"yours to manage"* ]] || { echo "$output"; return 1; }
  ! grep -q . "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
}

@test "[pg18] 清除舊目錄" {
  upgraded
  old_dir postgres 16
  dbu --remove-old --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"cannot be undone"* && $output == *"rollback can no longer go back to 1.22.0"* \
    && $output == *"$ROOT/backups/custodexa-backup-1.22.0-20261120-021700.tar"* && $output == *"Removed $D/postgres"* ]] || { echo "$output"; return 1; }
  [ ! -e "$D/postgres" ] && [ -z "$(ls -d "$D"/postgres.removing-* 2>/dev/null)" ] || return 1
  [ -d "$D/postgresql/18/docker" ] || return 1
  [ "$(pgc_state db_remove.dirs)" = postgres ] || return 1
  [ "$(pgc_state dir_op.id)" = removing ] && [ "$(pgc_state dir_op.phase)" = done ] || return 1
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [[ $output != *"$D/postgres"$'\n'* ]] || { echo "$output"; return 1; }
}

@test "removal asks for the version of what goes, and any other answer removes nothing" {
  upgraded
  old_dir postgres 16
  run script -qec "bash $ROOT/custodexa.sh db-upgrade --remove-old --lang en" /dev/null <<<"17"
  [ "$status" -eq 3 ] && [[ $output == *"type the PostgreSQL version being removed (16)"* && $output == *"Cancelled"* ]] || { echo "$output"; return 1; }
  [ -d "$D/postgres" ] || return 1
  run script -qec "bash $ROOT/custodexa.sh db-upgrade --remove-old --lang en" /dev/null <<<"16"
  [ "$status" -eq 0 ] && [ ! -e "$D/postgres" ] || { echo "$output"; return 1; }
}

@test "without a terminal and without --yes nothing is removed" {
  upgraded
  old_dir postgres 16
  dbu --remove-old
  [ "$status" -eq 3 ] && [[ $output == *"--yes is needed"* ]] || { echo "$output"; return 1; }
  [ -d "$D/postgres" ]
}

@test "the confirmation warns when the pre-upgrade backup is gone" {
  upgraded
  old_dir postgres 16
  /usr/bin/rm -f "$ROOT"/backups/custodexa-backup-1.22.0-*.tar
  dbu --remove-old --yes
  [ "$status" -eq 0 ] && [[ $output == *"was not found"* && $output == *"no way back to 1.22.0"* ]] || { echo "$output"; return 1; }
}

@test "[pg18] 新版尚未啟動時要清除" {
  upgraded
  bk_state_set last_upgrade.result in_progress
  bk_state_set last_upgrade.step 9
  bk_state_set last_upgrade.new_started_at ""
  old_dir postgres 16
  dbu --remove-old --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"did not finish (stopped at step 9/13)"* && $output == *"has not been started yet"* && $output == *"is the only data that can go back to 1.22.0"* ]] || { echo "$output"; return 1; }
  [ -d "$D/postgres" ] || return 1
}

@test "each of the conditions refuses the removal of the previous folder by itself" {
  upgraded
  old_dir postgres 16
  echo 1 >"$DB/server_version_num.rc"
  dbu --remove-old --yes
  [ "$status" -ne 0 ] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
  /usr/bin/rm -f "$DB/server_version_num.rc"
  bk_state_set last_rollback.result in_progress
  dbu --remove-old --yes
  [ "$status" -eq 3 ] && [[ $output == *"not finished"* ]] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
  bk_state_set last_rollback.result ""
  hook_before 'case " $* " in *" wget "*) exit 1 ;; esac'
  dbu --remove-old --yes
  [ "$status" -eq 3 ] && [[ $output == *"does not answer"* ]] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
}

@test "[pg18] 失敗產物不受升級成功前提限制" {
  upgraded
  bk_state_set last_upgrade.result failed
  bk_state_set last_upgrade.db_convert.result failed
  old_dir postgres 16
  old_dir postgresql.partial-convert-20261119-231005 18
  dbu --remove-old --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ ! -e "$D/postgresql.partial-convert-20261119-231005" ] || return 1
  [ -d "$D/postgres" ] || return 1
  [[ $output == *"cannot be removed now"* && $output == *"did not finish"* && $output == *"$D/postgres"* ]] || { echo "$output"; return 1; }
  [ "$(pgc_state db_remove.dirs)" = postgresql.partial-convert-20261119-231005 ] || return 1
}

@test "a failed-conversion leftover goes only while no other upgrade is unfinished" {
  upgraded
  bk_state_set last_upgrade.result in_progress
  bk_state_set last_upgrade.step 8
  old_dir postgresql.failed-convert-20261119-231004 18
  dbu --remove-old --yes
  [ "$status" -eq 3 ] && [ -d "$D/postgresql.failed-convert-20261119-231004" ] || { echo "$output"; return 1; }
}

@test "a folder that a running container mounts is not removed" {
  upgraded
  old_dir postgres 16
  hook_before 'case " $* " in *" ps -q"*) echo abc; exit 0 ;; *" inspect -f "*) echo "'"$D"'/postgres"; exit 0 ;; esac'
  dbu --remove-old --yes
  [ "$status" -eq 3 ] && [[ $output == *"is used by a running container"* ]] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
}

@test "a folder whose removal was started is finished by the next removal" {
  upgraded
  old_dir postgres.removing-20261201-102011 16
  dbu --remove-old --yes
  [ "$status" -eq 0 ] && [ ! -e "$D/postgres.removing-20261201-102011" ] || { echo "$output"; return 1; }
}

@test "a rename that was cut short is settled before the removal goes on" {
  upgraded
  old_dir postgres 16
  bk_state_set dir_op.id removing
  bk_state_set dir_op.from "$D/postgres"
  bk_state_set dir_op.to "$D/postgres.removing-20261201-102011"
  bk_state_set dir_op.phase intent
  dbu --remove-old --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ ! -e "$D/postgres" ] && [ ! -e "$D/postgres.removing-20261201-102011" ] || return 1
}

@test "a path that is not an old folder is refused and nothing is removed" {
  upgraded
  old_dir postgres 16
  dbu --remove-old --yes "$D/postgresql"
  [ "$status" -eq 3 ] && [ -d "$D/postgresql" ] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
}

@test "one folder can be named and the others stay" {
  upgraded
  old_dir postgres 16
  old_dir postgresql.rolled-back-20261123-101502 18
  dbu --remove-old --yes "$D/postgresql.rolled-back-20261123-101502"
  [ "$status" -eq 0 ] && [ ! -e "$D/postgresql.rolled-back-20261123-101502" ] && [ -d "$D/postgres" ] || { echo "$output"; return 1; }
}

@test "the data is newer than the program: refused, nothing stopped" {
  pgc_version 19 postgresql 18/docker
  bk_server 19.0
  dbu
  [ "$status" -eq 3 ] && [[ $output == *"newer than the PostgreSQL 18"* ]] || { echo "$output"; return 1; }
  ! grep -qE ' (stop|up|start) ' "$FAKE_DOCKER_LOG"
}

@test "the data folder and the running server disagree: stops" {
  bk_server 16.15
  dbu
  [ "$status" -eq 1 ] && [[ $output == *"data folder is PostgreSQL 18 but the running server is PostgreSQL 16"* ]] || { echo "$output"; return 1; }
}

@test "older data: the conversion module of the upgrade runs for the release that is running" {
  pgc_version 16 postgresql 18/docker
  bk_server 16.15
  printf '%s\n' 'cx_up_run() { echo "up_run target=$CX_UP_TARGET same=$CX_DBU_SAME from=$CX_PGC_DISK_FROM"; }' \
    >"$ROOT/releases/1.13.0/lib/cmd_upgrade.sh"
  dbu
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"data is PostgreSQL 16 and this release bundles PostgreSQL 18"* && $output == *"up_run target=1.13.0 same=1 from=16"* ]] || { echo "$output"; return 1; }
  dbu --remove-old --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
}

@test "the plan takes the major of the folder when db-upgrade says so" {
  load_lib
  . "$SRC/lib/pgconvert.sh"
  CX_ROOT=$ROOT
  CX_OVERLAYS=""
  cx_manifest_load "$ROOT/releases/1.13.0/MANIFEST.json"
  CX_PGC_DISK_FROM=16
  cx_pgc_plan
  [ "$CX_PGC_ACTIVE" = 1 ] && [ "$CX_PGC_FROM" = 16 ] && [ "$CX_PGC_TO" = 18 ] && [ "$CX_PGC_OLD_DIR" = postgresql ] || { echo "$CX_PGC_ACTIVE $CX_PGC_FROM $CX_PGC_TO $CX_PGC_OLD_DIR"; return 1; }
  [ -z "$CX_PGC_OLD_PGDATA" ] || return 1
}

@test "options of db-upgrade belong to it alone" {
  run bash "$ROOT/custodexa.sh" status --remove-old --lang en </dev/null
  [ "$status" -eq 2 ] && [[ $output == *"only for db-upgrade"* ]] || { echo "$output"; return 1; }
  dbu --yes
  [ "$status" -eq 2 ] || { echo "$output"; return 1; }
  dbu "$D/postgres"
  [ "$status" -eq 2 ] || { echo "$output"; return 1; }
}

@test "[pg18] 指回後保留的 18 目錄列在狀態中" {
  old_dir postgresql.rolled-back-20261123-101502 18
  old_dir postgres 16
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  section=$(printf '%s\n' "$output" | sed -n '/^Database$/,/^[A-Z][a-z]/p')
  [[ $section == *"PostgreSQL 18 (bundled), data in $D/postgresql"* ]] || { echo "$output"; return 1; }
  [[ $section == *"$D/postgresql.rolled-back-20261123-101502"* && $section == *"$D/postgres"$'\n'* ]] || { echo "$output"; return 1; }
  [[ $section != *"[WARN]"* ]] || { echo "$section"; return 1; }
}

@test "status says an unfinished removal" {
  old_dir postgres.removing-20261201-102011 16
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [[ $output == *"did not finish"* && $output == *"postgres.removing-20261201-102011 is still there"* ]] || { echo "$output"; return 1; }
}

@test "status of an external database says whose it is" {
  bk_state_set current.overlays external-database
  bk_state_set current.external_db_host db.example.internal
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [[ $output == *"External database db.example.internal:5432 (managed by you)"* ]] || { echo "$output"; return 1; }
}

@test "[pg18] 外接資料庫部署的選單" {
  menu_lines external 0 >|"$BATS_TEST_TMPDIR/ext.txt"
  grep -q '^  \[8\] Help' "$BATS_TEST_TMPDIR/ext.txt" && grep -q 'Choose \[0-8\]' "$BATS_TEST_TMPDIR/ext.txt" || { cat "$BATS_TEST_TMPDIR/ext.txt"; return 1; }
  ! grep -qi 'database upgrade' "$BATS_TEST_TMPDIR/ext.txt"
}

@test "[pg18] 加入資料庫升級後既有編號不變" {
  menu_lines external 0 >|"$BATS_TEST_TMPDIR/ext.txt"
  bk_state_set current.overlays ""
  menu_lines builtin 0 >|"$BATS_TEST_TMPDIR/bi.txt"
  for n in 1 2 3 4 5 6 7 0; do
    [ "$(grep "^  \[$n\] " "$BATS_TEST_TMPDIR/ext.txt")" = "$(grep "^  \[$n\] " "$BATS_TEST_TMPDIR/bi.txt")" ] || { echo "item $n differs"; return 1; }
  done
  grep -q '^  \[8\] Database upgrade (now PostgreSQL 18; remove old database folders)' "$BATS_TEST_TMPDIR/bi.txt" || { cat "$BATS_TEST_TMPDIR/bi.txt"; return 1; }
  grep -q '^  \[9\] Help' "$BATS_TEST_TMPDIR/bi.txt" && grep -q 'Choose \[0-9\]' "$BATS_TEST_TMPDIR/bi.txt" || return 1
}

@test "the menu label follows what the data is" {
  bk_state_set current.overlays ""
  pgc_version missing postgresql 18/docker
  menu_lines builtin 0 | grep -q '^  \[8\] Database upgrade$' || return 1
  pgc_version 16 postgresql 18/docker
  menu_lines builtin 0 | grep -q 'can upgrade to PostgreSQL 18' || return 1
}

@test "choosing 5 in the builtin menu runs backup and 8 shows the old folders" {
  bk_state_set current.overlays ""
  printf '%s\n' 'cmd_backup() { echo backup >>"'"$BATS_TEST_TMPDIR"'/calls"; }' >|"$ROOT/releases/1.13.0/lib/cmd_backup.sh"
  : >|"$BATS_TEST_TMPDIR/calls"
  menu_lines builtin $'5\n0' >/dev/null
  [ "$(cat "$BATS_TEST_TMPDIR/calls")" = backup ] || return 1
  upgraded
  old_dir postgres 16
  menu_lines builtin $'8\n1\n16\n0' >|"$BATS_TEST_TMPDIR/m.txt"
  grep -q "$D/postgres" "$BATS_TEST_TMPDIR/m.txt" && grep -q 'Removed' "$BATS_TEST_TMPDIR/m.txt" || { cat "$BATS_TEST_TMPDIR/m.txt"; return 1; }
  [ ! -e "$D/postgres" ] || return 1
}

@test "the builtin menu is word for word the reviewed screen in each language, the external one has no database entry" {
  printf '1.16.0\n' >|"$ROOT/releases/1.13.0/VERSION"
  bk_state_set current.version 1.16.0
  bk_state_set current.overlays ""
  for l in en zh-TW ja; do
    run script -qec "cd $BATS_TEST_TMPDIR && bash $ROOT/custodexa.sh --lang $l" /dev/null <<<"0"
    printf '%s\n' "$output" | tr -d '\r' | sed -E '/^[0-9]+$/d; s/(：|: )[0-9]+$/\1/' | sed "s#$ROOT#/opt/custodexa#g" >|"$BATS_TEST_TMPDIR/screen"
    diff "$BATS_TEST_TMPDIR/screen" "$TESTS_DIR/snapshots/menu-package-db.$l.txt" || { echo "builtin menu: $l"; return 1; }
  done
}
