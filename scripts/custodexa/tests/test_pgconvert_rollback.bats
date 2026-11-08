#!/usr/bin/env bats
# Going back, and returning, across the bundled database's major version (lib/rollback_pg.sh): the
# judgment on the kept folder, the preview and warning, the rename of the new major's folder after
# the database stops, `rollback --revert`, and the start guard of both entries. The deployment is a
# real upgrade (rollback_host); the database conversion is on record the way step 8 leaves it: the
# old release names the 16 layout, the new one names 18, db_convert.result is done, and the two data
# folders hold their PG_VERSION. An external database never takes this path.

load helper
load install_host
load backup_host
load upgrade_host
load rollback_host
load pgconvert_host

setup() { host_workdir; }

# crossed [outcome] [mode]: a deployment 1.16.1 -> 1.16.2 whose database went from 16 to 18.
crossed() {
  rb_cached "${1:-ready}" "${2:-ui}" 1.16.1 1.16.2
  OLD=1.16.1 NEW=1.16.2
  pgc_manifest "$ROOT/releases/$OLD" without 16
  pgc_manifest "$ROOT/releases/$NEW" with 18
  jq '. + {"last_upgrade.db_convert.result": "done"}' "$ROOT/state.json" >"$ROOT/state.new"
  mv "$ROOT/state.new" "$ROOT/state.json"
  pgc_version 16 postgres
  pgc_version 18 postgresql 18/docker
  printf '%s\n' 160015 >"$DB/server_version_num"
  # The renames of a data folder, in the order they happen among the other events.
  cp "$FAKES/mv" "$FAKES/mv.inner"
  fake mv 'a=("$@"); [ "${a[0]}" != -- ] || a=("${a[@]:1}")
if [[ ${a[0]} == */data/postgres* ]]; then printf "rename %s %s\n" "${a[0]##*/}" "${a[1]##*/}" >>"$DB/events"; fi
exec "$(dirname "$0")/mv.inner" "$@"'
  : >"$DB/events"
  : >"$DB/db-calls"
}

flat() { printf '%s' "$output" | tr -d '\r' | tr '\n' ' ' | tr -s ' '; }
aside() { ls -d "$ROOT"/data/postgresql.rolled-back-* 2>/dev/null | head -n 1; }
# tty <answer> <command...>: the command with a terminal, the answer typed ahead.
tty() {
  local answer=$1
  shift
  run script -qec "$*" /dev/null <<<"$answer"
  output=$(printf '%s' "$output" | tr -d '\r')
}
# unchanged: the deployment is as the upgrade left it, nothing renamed, no rollback on record.
unchanged() {
  [ "$(readlink "$ROOT/current")" = "releases/$NEW" ] || return 1
  [ "$(rb_state last_rollback.result)" = "" ] || return 1
  [ -d "$ROOT/data/postgresql/18/docker" ] && [ -z "$(aside)" ] || return 1
  ! grep -q '^rename ' "$DB/events"
}
# order <earlier pattern> <later pattern>: the first line of each in the events log, in that order.
order() {
  local a b
  a=$(grep -n -m1 -E "$1" "$DB/events" | cut -d: -f1)
  b=$(grep -n -m1 -E "$2" "$DB/events" | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] || { echo "events: $1 ($a) before $2 ($b)"; cat "$DB/events"; return 1; }
}
RESTORE_LINE='custodexa.sh restore '

@test "[pg18] 跨大版本新版從未啟動時指回" {
  crossed switch-linked
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  flat | grep -q "the new version never started, so the data did not change" || { echo "$output"; return 1; }
  flat | grep -q "So no data is lost and no restore is needed" || return 1
  [[ $output != *"WARN"* ]] || return 1
  [ "$(readlink "$ROOT/current")" = "releases/$OLD" ]
  # the old folder was not touched; the new major's folder is kept under its new name
  [ "$(head -n 1 "$ROOT/data/postgres/PG_VERSION")" = 16 ]
  [ ! -e "$ROOT/data/postgresql" ]
  [ -f "$(aside)/18/docker/PG_VERSION" ]
  [ "$(rb_state last_upgrade.result)" = rolled_back ]
  [ "$(rb_state last_rollback.db_aside)" = "$(aside)" ]
  # the migrations of the new database were never read
  ! grep -q schema_migrations "$DB/db-calls" || { cat "$DB/db-calls"; return 1; }
}

@test "[pg18] 資料庫轉換後新版已啟動" {
  crossed ready
  # A migration the database gained since the upgrade refuses a same-major rollback; here it is no matter.
  printf '%s\n' 20269999_after_upgrade >>"$DB/migrations"
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  flat | grep -q "has already started (since 2026-11-05 09:30)" || { echo "$output"; return 1; }
  flat | grep -q "audit records - connection records - recording index" || return 1
  flat | grep -q "setting and account changes" || return 1
  [[ $output == *"$ROOT/data/postgresql.rolled-back-"* ]] || return 1
  [[ $output == *"sudo $ROOT/custodexa.sh restore $ROOT/backups/custodexa-backup-"* ]] || { echo "$output"; return 1; }
  flat | grep -q "again; the kept PostgreSQL 18 data is not merged back" || return 1
  [[ $output != *"nothing needs restoring"* && $output != *"no restore is needed"* ]] || return 1
  [ "$(readlink "$ROOT/current")" = "releases/$OLD" ]
  [ -f "$(aside)/18/docker/PG_VERSION" ] && [ ! -e "$ROOT/data/postgresql" ]
  [ "$(rb_state last_rollback.result)" = succeeded ]
  ! grep -q schema_migrations "$DB/db-calls" || { cat "$DB/db-calls"; return 1; }
  # the rename comes after the database stops and before the old version starts
  order 'stop .*postgres' '^rename postgresql postgresql.rolled-back-'
  order '^rename postgresql postgresql.rolled-back-' '^up releases/'
  [[ $output == *"Back on $OLD"* ]]
  flat | grep -q "run upgrade as usual; it converts the database again" || return 1
}

@test "[pg18] 跨大版本指回非互動未帶 --yes" {
  crossed ready
  rb_run en
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  flat | grep -q "has already started" || return 1
  flat | grep -q "gives up the data written after the upgrade. This run is non-interactive" || { echo "$output"; return 1; }
  [[ $output == *"custodexa.sh rollback --yes"* ]]
  unchanged
}

@test "[pg18] 跨大版本指回的警告直接按 Enter" {
  crossed ready
  tty "" "bash $ROOT/custodexa.sh rollback --lang en"
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  flat | grep -q "give up the data written after the upgrade? \[y/N\]" || { echo "$output"; return 1; }
  [[ $output == *"Nothing was changed."* ]]
  unchanged
  tty "n" "bash $ROOT/custodexa.sh rollback --lang en"
  [ "$status" -eq 3 ]
  unchanged
  # y goes ahead
  tty "y" "bash $ROOT/custodexa.sh rollback --lang en"
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [ -f "$(aside)/18/docker/PG_VERSION" ]
}

@test "[pg18] 轉換後舊資料目錄已清除" {
  crossed ready
  rm -rf "$ROOT/data/postgres"
  rb_run en --yes
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  flat | grep -q "Cannot go straight back to $OLD: the PostgreSQL 16 data kept at the upgrade is no longer there" || { echo "$output"; return 1; }
  flat | grep -q "Nothing was changed; the services are still running" || return 1
  [[ $output == *"$RESTORE_LINE$ROOT/backups/custodexa-backup-"* ]] || return 1
  [[ $output == *"data written afterwards is lost"* || $(flat) == *"data written afterwards is lost"* ]] || return 1
  unchanged
  # the folder of another major is no better
  pgc_version 18 postgres
  rb_run en --yes
  [ "$status" -eq 3 ]
  flat | grep -q "is not PostgreSQL 16 data" || { echo "$output"; return 1; }
  flat | grep -q "recorded in this folder is 18" || return 1
  unchanged
}

@test "[pg18] 資料庫轉換後換版前失敗" {
  # The last check, with the application services already stopped: the folder is gone by then.
  crossed ready
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/hook.x"
  # shellcheck disable=SC2016 # expanded by the hook
  printf '#!/bin/bash\ncase " $* " in *" compose "*" stop "*) case " $* " in *" postgres "*) ;; *) rm -f "%s/data/postgres/PG_VERSION" ;; esac ;; esac\nexec "$FAKE_DOCKER_REPLAY/hook.x" "$@"\n' "$ROOT" >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  flat | grep -q "the PostgreSQL 16 data kept at the upgrade is no longer there" || { echo "$output"; return 1; }
  flat | grep -q "Nothing was changed; the services remain stopped" || { echo "$output"; return 1; }
  [ "$(rb_state last_rollback.result)" = refused ]
  [ "$(readlink "$ROOT/current")" = "releases/$NEW" ]
  [ -d "$ROOT/data/postgresql/18/docker" ] && [ -z "$(aside)" ]
  ! grep -q '^rename ' "$DB/events"
  [[ $output == *"custodexa.sh start"* ]]
}

@test "[pg18] 跨大版本指回的執行" {
  crossed ready
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(rb_state current.version)" = "$OLD" ] && [ "$(rb_state previous.version)" = "$NEW" ]
  # the database the old version found is the kept 16 folder, with its content
  [ "$(head -n 1 "$ROOT/data/postgres/PG_VERSION")" = 16 ]
  # the rename is on record before it is done, with the destination fixed at the start
  [ "$(rb_state dir_op.id)" = rolled-back ] && [ "$(rb_state dir_op.phase)" = done ]
  [ "$(rb_state dir_op.to)" = "$(rb_state last_rollback.db_aside)" ]
  [ "$(rb_state dir_op.from)" = "$ROOT/data/postgresql" ]
  [ "$(rb_state last_rollback.db_old_path)" = "$ROOT/data/postgres" ]
  # the old version starts only after the check of its folder; one rename, nothing else moved
  [ "$(grep -c '^rename ' "$DB/events")" -eq 1 ]
}

@test "[pg18] 跨大版本指回後撤回" {
  crossed ready
  touch "$DB/rb.up"
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [ "$(rb_state last_rollback.step)" = 3 ] && [ "$(rb_state last_rollback.result)" = in_progress ]
  [ -z "$(ls -d "$ROOT/data/postgresql" 2>/dev/null)" ] && [ -n "$(aside)" ]
  rm -f "$DB/rb.up"
  printf '%s\n' 180006 >"$DB/server_version_num"
  : >"$DB/events"
  rb_run en --revert --yes
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [ "$(rb_state current.version)" = "$NEW" ] && [ "$(readlink "$ROOT/current")" = "releases/$NEW" ]
  [ -f "$ROOT/data/postgresql/18/docker/PG_VERSION" ] && [ -z "$(aside)" ]
  # the kept 16 folder was not renamed, moved or deleted
  [ "$(head -n 1 "$ROOT/data/postgres/PG_VERSION")" = 16 ]
  # the rename back comes before the new version starts
  order '^rename postgresql.rolled-back-.* postgresql$' '^up releases/'
  [ "$(grep -c '^rename ' "$DB/events")" -eq 1 ]
  [ "$(rb_state dir_op.id)" = revert ] && [ "$(rb_state dir_op.phase)" = done ]
  flat | grep -q "Returned to $NEW" || { echo "$output"; return 1; }
  flat | grep -q "Check: the backend reports $NEW and the database is PostgreSQL 18" || return 1
  flat | grep -q "written to PostgreSQL 16 while going back is still in $ROOT/data/postgres; it was not deleted" || { echo "$output"; return 1; }
}

@test "[pg18] 撤回跨大版本指回時未確認" {
  crossed ready
  touch "$DB/rb.up"
  rb_run en --yes
  [ "$status" -eq 1 ]
  rm -f "$DB/rb.up"
  before=$(jq -S '{d: ."last_rollback.direction", s: ."last_rollback.step", r: ."last_rollback.result"}' "$ROOT/state.json")
  : >"$DB/events"
  # without a terminal and without --yes
  rb_run en --revert
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  flat | grep -q "has run on PostgreSQL 16 for a while" || { echo "$output"; return 1; }
  flat | grep -q "recording index" || return 1
  flat | grep -q "This data stays in the old data folder; it is not deleted and not merged back: $ROOT/data/postgres" || { echo "$output"; return 1; }
  flat | grep -q "Returning gives up the data written to PostgreSQL 16" || return 1
  [[ $output == *"sudo $ROOT/releases/$NEW/custodexa.sh rollback --revert --yes"* ]] || { echo "$output"; return 1; }
  [ "$before" = "$(jq -S '{d: ."last_rollback.direction", s: ."last_rollback.step", r: ."last_rollback.result"}' "$ROOT/state.json")" ]
  [ "$(rb_state last_rollback.direction)" = rollback ]
  ! grep -q '^rename ' "$DB/events"
  [ -n "$(aside)" ] && [ ! -e "$ROOT/data/postgresql" ]
  # Enter is no
  tty "" "bash $ROOT/custodexa.sh rollback --revert --lang en"
  [ "$status" -eq 3 ]
  flat | grep -q "while going back? \[y/N\]" || { echo "$output"; return 1; }
  [ "$(rb_state last_rollback.direction)" = rollback ]
  ! grep -q '^rename ' "$DB/events"
}

@test "[pg18] 指回尚未啟動上一版時撤回" {
  crossed ready
  rb_interrupt cx_rb_switch after
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [ "$(rb_state last_rollback.step)" = 2 ]
  printf '%s\n' 180006 >"$DB/server_version_num"
  : >"$DB/events"
  # no warning, and the ordinary confirmation: without --yes it stops on that
  rb_run en --revert
  [ "$status" -eq 3 ]
  [[ $output != *"has run on PostgreSQL"* && $output != *"WARN"* ]] || { echo "$output"; return 1; }
  flat | grep -q "stopped before $OLD started" || { echo "$output"; return 1; }
  flat | grep -q "never started on PostgreSQL 16" || return 1
  rb_run en --revert --yes
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [ -f "$ROOT/data/postgresql/18/docker/PG_VERSION" ] && [ -z "$(aside)" ]
  order '^rename postgresql.rolled-back-.* postgresql$' '^up releases/'
}

@test "[pg18] 外接資料庫部署的指回與撤回不動本機資料目錄" {
  local m ids=""
  rb_cached ready ui 1.16.1 1.16.2
  OLD=1.16.1 NEW=1.16.2
  bk_state_set current.overlays external-database
  for m in 16 17 18; do ids+="${ids:+ }pgclient$m=${BK_PGC_ID[$m]}"; done
  bk_state_set current.tool_image_ids "$ids"
  printf '%s\n' "${BK_PGC_ID[16]}" "${BK_PGC_ID[17]}" "${BK_PGC_ID[18]}" >>"$DB/images"
  bk_env_set DB_USER custodexa_app
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  bk_env_set EXTERNAL_DB_PORT 5432
  bk_env_set DB_SSLMODE verify-full
  bk_server 17.6
  # the two releases name different majors and the conversion step is on record: still not across
  pgc_manifest "$ROOT/releases/$OLD" without 16
  pgc_manifest "$ROOT/releases/$NEW" with 18
  jq '. + {"last_upgrade.db_convert.result": "done"}' "$ROOT/state.json" >"$ROOT/state.new"
  mv "$ROOT/state.new" "$ROOT/state.json"
  pgc_version 16 postgres
  cp "$FAKES/mv" "$FAKES/mv.inner"
  fake mv 'a=("$@"); [ "${a[0]}" != -- ] || a=("${a[@]:1}")
if [[ ${a[0]} == */data/* ]]; then printf "rename %s %s\n" "${a[0]##*/}" "${a[1]##*/}" >>"$DB/events"; fi
exec "$(dirname "$0")/mv.inner" "$@"'
  : >"$DB/events"
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$status $output"; return 1; }
  [ "$(rb_state last_rollback.db_crossed)" = 0 ]
  [[ $output != *"written after the"* && $output != *"rolled-back"* && $output != *"kept at the upgrade"* ]] || { echo "$output"; return 1; }
  rb_run en --revert --yes
  [ "$status" -eq 3 ] || [ "$status" -eq 0 ]
  ! grep -q '^rename ' "$DB/events" || { cat "$DB/events"; return 1; }
  [ -d "$ROOT/data/postgres" ]
}

@test "[pg18] 跨大版本不能指回時的說明" {
  # the kept folder gone, and the new version never started: the same explanation and the restore
  crossed switch-linked
  rm -rf "$ROOT/data/postgres"
  rb_run en --yes
  [ "$status" -eq 3 ] || { echo "$status $output"; return 1; }
  flat | grep -q "no longer there" || return 1
  [[ $output == *"$RESTORE_LINE"* ]]
  [ -z "$(aside)" ] && [ "$(readlink "$ROOT/current")" = "releases/$NEW" ]
}

# ---- the start guard of the two entries (the rename log and the version file) ----

@test "[pg18] 指回的啟動步在目錄缺版本檔時拒絕" {
  crossed ready
  # The old folder loses its version file after the last check, while the database is stopping.
  cp "$FAKES/mv" "$FAKES/mv.step"
  fake mv 'a=("$@"); [ "${a[0]}" != -- ] || a=("${a[@]:1}")
"$(dirname "$0")/mv.step" "$@" || exit $?
if [[ ${a[0]} == */data/postgresql && ${a[1]} == *rolled-back-* ]]; then rm -f "'"$ROOT"'/data/postgres/PG_VERSION"; fi'
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  flat | grep -q "has no PG_VERSION" || flat | grep -qi "version file\|PG_VERSION" || { echo "$output"; return 1; }
  ! grep -q '^up ' "$DB/events" || { cat "$DB/events"; return 1; }
  [ "$(rb_state last_rollback.result)" = in_progress ]
}

@test "[pg18] 撤回的啟動步在目錄缺版本檔時拒絕" {
  crossed ready
  touch "$DB/rb.up"
  rb_run en --yes
  [ "$status" -eq 1 ]
  rm -f "$DB/rb.up"
  cp "$FAKES/mv" "$FAKES/mv.step"
  fake mv 'a=("$@"); [ "${a[0]}" != -- ] || a=("${a[@]:1}")
"$(dirname "$0")/mv.step" "$@" || exit $?
if [[ ${a[0]} == */data/postgresql.rolled-back-* ]]; then rm -f "${a[1]}/18/docker/PG_VERSION"; fi'
  : >"$DB/events"
  rb_run en --revert --yes
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  flat | grep -qi "PG_VERSION" || { echo "$output"; return 1; }
  ! grep -q '^up ' "$DB/events" || { cat "$DB/events"; return 1; }
}

@test "[pg18] 改名意圖兩端都在時指回續跑停下" {
  crossed ready
  rb_interrupt cx_rb_switch before
  rb_run en --yes
  [ "$status" -eq 1 ]
  # an intent of the rename on record with both ends present: nothing starts, both paths shown
  jq --arg f "$ROOT/data/postgresql" --arg t "$ROOT/data/postgresql.rolled-back-x" \
    '. + {"dir_op.id": "rolled-back", "dir_op.from": $f, "dir_op.to": $t, "dir_op.phase": "intent"}' \
    "$ROOT/state.json" >"$ROOT/state.new"
  mv "$ROOT/state.new" "$ROOT/state.json"
  mkdir -p "$ROOT/data/postgresql.rolled-back-x"
  : >"$DB/events"
  rb_run en --resume
  [ "$status" -eq 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *"$ROOT/data/postgresql.rolled-back-x"* ]]
  ! grep -q '^up ' "$DB/events"
}
