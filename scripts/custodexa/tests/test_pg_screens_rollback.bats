#!/usr/bin/env bats
# Screen snapshots of going back and returning across the database major (task 3.11): P08, P09, P19,
# P22, P23. The deployment is the one of test_pgconvert_rollback.bats; each language is a fresh one.

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
  bk_state_set last_upgrade.app_stop.at 2026-11-20T02:33:00+0800
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

# ttyecho <answer> <command...>: tty, with the typed answer where a terminal shows it: the pty
# echoes it as the first line of the output, and it belongs at the end of the question.
ttyecho() {
  local answer=$1
  tty "$@"
  output=$(printf '%s\n' "$output" | sed '1d' | sed -E "s/(\[y\/N\]) ?/\1 $answer\n/")
}
# env_change: the .env block of the deployment is the layout of the new release, so going back
# changes it (the line about .env shows).
env_change() {
  jq '. + {compose_layout: "profiles"}' "$ROOT/releases/$NEW/MANIFEST.json" >"$ROOT/m.new"
  mv "$ROOT/m.new" "$ROOT/releases/$NEW/MANIFEST.json"
  bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_env_sync_managed "$2/.env" profiles ""' _ "$SRC" "$ROOT"
}

# shot <name> <body>: a fresh deployment per language; the body arranges it, runs the command and
# leaves what it printed in $output.
shot() {
  local l rc=0
  for l in en zh-TW ja; do
    crossed "${CROSS:-ready}"
    LNG=$l
    "$2"
    pg_emit "$1" "$l" || rc=1
  done
  return $rc
}

p08c() { env_change; rb_run "$LNG"; }
p08ab() { env_change; ttyecho "" "bash $ROOT/custodexa.sh rollback --lang $LNG"; }
p08d() {
  env_change
  bk_state_set last_upgrade.backup backups/20261120-021502
  bk_state_set last_upgrade.backup_kind external
  ttyecho "" "bash $ROOT/custodexa.sh rollback --lang $LNG"
}
p09() { env_change; ttyecho y "bash $ROOT/custodexa.sh rollback --lang $LNG"; }
p19a() { rm -rf "$ROOT/data/postgres"; rb_run "$LNG" --yes; }
p19c() {
  rm -rf "$ROOT/data/postgres"
  bk_state_set db_remove.at 2026-12-01T10:20:11+0800
  bk_state_set db_remove.dirs postgres
  rb_run "$LNG" --yes
  # the time the clean-up recorded is on the screen (pg_emit normalises it away)
  [[ $output == *"2026-12-01 10:20"* ]]
}
p19b() { pgc_version 18 postgres; rb_run "$LNG" --yes; }
# revert_ready: a rollback whose check after the start of the old version failed (the record
# says it started; the server answers as the new major, which the old version does not accept).
revert_ready() {
  printf '%s\n' 180006 >"$DB/server_version_num"
  rb_run "$LNG" --yes
  [ "$status" -eq 1 ]
}
p22d() { revert_ready; rb_run "$LNG" --revert; }
p22a() { revert_ready; ttyecho "" "bash $ROOT/custodexa.sh rollback --revert --lang $LNG"; }
p22b() { revert_ready; ttyecho y "bash $ROOT/custodexa.sh rollback --revert --lang $LNG"; }
p22e() {
  rb_interrupt cx_rb_switch after
  rb_run "$LNG" --yes
  printf '%s\n' 180006 >"$DB/server_version_num"
  ttyecho "" "bash $ROOT/custodexa.sh rollback --revert --lang $LNG"
}
# The screens of P23 are the start check every entry that starts the bundled database runs
# (cx_dirop_start_guard); each entry is tried in test_pgconvert_dirop.bats and test_pgconvert_rollback.bats.
p23_guard() { cx_dirop_start_guard "$ROOT/current/"; }
p23_intent() {
  jq --arg f "$ROOT/data/postgresql" --arg t "$ROOT/data/postgresql.rolled-back-20261123-101502" \
    '. + {"dir_op.id": "rolled-back", "dir_op.from": $f, "dir_op.to": $t, "dir_op.phase": "intent",
      "last_upgrade.backup": "backups/custodexa-backup-1.16.1-20261120-021502.tar"}' \
    "$ROOT/state.json" >"$ROOT/state.new"
  mv "$ROOT/state.new" "$ROOT/state.json"
}
p23_run() {
  [ -n "${P23_LOADED:-}" ] || { load_lib; P23_LOADED=1; }
  CX_ROOT=$ROOT CX_BK_DATA=$ROOT/data
  cx_state_load "$ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_dirop_du() { case $1 in *rolled-back*) printf %s $((174 * CX_GIB / 10)) ;; *) printf %s $((179 * CX_GIB / 10)) ;; esac; }
  pg_lang "$LNG"
  output=$(p23_guard 2>&1) || true
}
p23a() {
  p23_intent
  mkdir -p "$ROOT/data/postgresql.rolled-back-20261123-101502/18/docker"
  printf '18\n' >"$ROOT/data/postgresql.rolled-back-20261123-101502/18/docker/PG_VERSION"
  p23_run
}
p23b() {
  p23_intent
  rm -rf "$ROOT/data/postgresql" "$ROOT/data/postgresql.rolled-back-20261123-101502"
  p23_run
}
p23c() {
  rm -f "$ROOT/data/postgresql/18/docker/PG_VERSION"
  jq '. + {"last_upgrade.backup": "backups/custodexa-backup-1.16.1-20261120-021502.tar"}' "$ROOT/state.json" >"$ROOT/state.new"
  mv "$ROOT/state.new" "$ROOT/state.json"
  p23_run
}

@test "P08 warning when going back after the new version started" {
  shot P08c p08c
  shot P08ab p08ab
  shot P08d p08d
}
@test "P09 going back, the new version never started" {
  CROSS=switch-linked shot P09 p09
}
@test "P19 the old folder is gone" {
  shot P19a p19a
  shot P19b p19b
  shot P19c p19c
}
@test "P22 returning" {
  shot P22d p22d
  shot P22a p22a
  shot P22b p22b
  shot P22e p22e
}
@test "P23 a rename of unknown state" {
  shot P23a p23a
  shot P23b p23b
  shot P23c p23c
}
