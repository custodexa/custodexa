#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host
setup() {
  rs_engine_host
  # A valid producer input, with a template and ui mode, for both file placement and exit.
  bk_env_set KEK_PROVIDER ui
  bk_env_set ENCRYPTION_KEY ''
  printf 'backup template\n' >"$ROOT/nginx.template"
  bk_env_set TLS_NGINX_TEMPLATE "$ROOT/nginx.template"
  bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/producer-ui.log" 2>&1 || { cat "$BATS_TEST_TMPDIR/producer-ui.log"; return 1; }
  RS_E_FILE=$(find "$ROOT/backups" -name '*.tar')
  cp "$RS_E_FILE" "$RS_E_FILE.sha256" "$BATS_TEST_TMPDIR/source/"
  RS_E_FILE=$BATS_TEST_TMPDIR/source/${RS_E_FILE##*/}
  rm -f "$ROOT"/backups/*
  cp -a "$ROOT/current/." "$ROOT/releases/1.16.2"
  printf '1.16.2\n' >"$ROOT/releases/1.16.2/VERSION"
  jq '.version="1.16.2"' "$ROOT/current/MANIFEST.json" >"$ROOT/releases/1.16.2/MANIFEST.json"
  /usr/bin/ln -sfn releases/1.16.2 "$ROOT/current"
  rs_new_host
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit" "$ROOT/tls"
  printf 'existing template\n' >"$ROOT/nginx.template"
  cp "$ROOT/.env" "$BATS_TEST_TMPDIR/failed-env"
  ENGINE=$ROOT/releases/1.16.2/custodexa.sh
  : >"$DB/events"
  : >"$FAKE_DOCKER_LOG"
  echo sealed >"$DB/seal"
  cat >>"$ROOT/releases/1.16.2/lib/cmd_restore.sh" <<'SH'
eval "$(declare -f cx_rs_journal_apply | sed '1s/cx_rs_journal_apply/rs_a_apply/')"
cx_rs_journal_apply() {
  if [ "$CX_RS_ACTION" = abandon ] && [ "$CX_RS_J_KIND" = move ]; then
    # Record both event order and actual state at every destructive exit operation.
    printf 'rename\n' >>"$DB/events"
    for f in "$DB"/ctr/*; do [ "$(cat "$f")" != running ] || return 97; done
  fi
  rs_a_apply || return 1
  if [ "${RS_A_INTERRUPT:-0}" = 1 ] && [ "$CX_RS_ACTION" = abandon ] && [ "$CX_RS_J_KIND" = move ] && [ ! -e "$DB/abandon-cut" ]; then
    touch "$DB/abandon-cut"; kill -TERM "$$"; return 1
  fi
}
SH
}
new_run() { run bash "$ENGINE" restore "$RS_E_FILE" --new-host --yes --lang en </dev/null; }
abandon() { run bash "$ENGINE" restore --abandon --yes --lang en </dev/null; }
recordings() { find "$ROOT/data/recordings" -printf '%p %s %T@\n' | sort; }
settled() {
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(rs_engine_result)" = abandoned ] && [ "$(jq -r '."current.version" // ""' "$ROOT/state.json")" = '' ] || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.16.2 ] || return 1
  [ -n "$(find "$ROOT/data" -maxdepth 1 -name 'postgres.abandoned-*')" ] || return 1
  [ -n "$(find "$ROOT" -maxdepth 1 -name '.env.abandoned-*')" ] || return 1
  cmp "$BATS_TEST_TMPDIR/failed-env" "$ROOT/.env" || return 1
  [ "$(cat "$ROOT/nginx.template")" = 'existing template' ] || return 1
  [ "$rec" = "$(recordings)" ] || return 1
  [ "$(head -n 1 "$DB/events")" = stop ]
}
@test "restore new host: database or audit files refuse, existing recordings do not" {
  local part
  for part in postgres audit; do
    mkdir -p "$ROOT/data/$part"; echo data >"$ROOT/data/$part/file"
    new_run
    [ "$status" = 3 ] && [[ $output == *"$ROOT/data/$part"* ]] || { echo "$output"; return 1; }
    ! grep -qx stop "$DB/events" || return 1
    rm -rf "$ROOT/data/$part"
  done
  new_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  [[ $output == *'not needed'* ]] || { echo "$output"; return 1; }
  ! grep -qx pg_dump "$DB/events" && [ -z "$(find "$ROOT/backups" -name '*.tar')" ] || return 1
  # Every compose call uses the data release, even before current is changed.
  ! grep 'ARGS.*compose -p' "$FAKE_DOCKER_LOG" | grep -vF -- "-f $ROOT/releases/1.16.0/compose.yml" || return 1
  [[ $output == *"$ENGINE restore --resume"* ]]
}
@test "restore new host: abandon after started stops before every rename and restores the prior template" {
  export RS_E_CUT=started
  new_run
  [ "$status" = 1 ] || { echo "$output"; return 1; }
  unset RS_E_CUT
  rec=$(recordings); : >"$DB/events"
  abandon
  settled
}
@test "restore new host: abandon while awaiting unseal stops before every rename and leaves recordings" {
  new_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  [[ $output == *'renamed and kept'* ]] || { echo "$output"; return 1; }
  local kept
  kept=$(find "$ROOT" -maxdepth 1 -name 'nginx.template.before-restore-*')
  [ "$(cat "$kept")" = 'existing template' ] && [ "$(cat "$ROOT/nginx.template")" = 'backup template' ] || return 1
  rec=$(recordings); : >"$DB/events"
  abandon
  settled
}
@test "restore new host: abandon after a mismatched key is stopped before renaming" {
  new_run
  [ "$status" = 4 ] || return 1
  echo unsealed >"$DB/seal"; echo 1111111111111111 >"$DB/kek"
  run bash "$ENGINE" restore --resume --lang en
  [ "$status" = 1 ] && [[ $output == *'master key does not match'* ]] || { echo "$output"; return 1; }
  rec=$(recordings); : >"$DB/events"
  abandon
  settled
}
@test "restore new host: stop failure does not rename anything" {
  new_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  echo 1 >"$DB/stop.rc"; : >"$DB/events"
  abandon
  [ "$status" = 1 ] && [[ $output == *'Nothing has been renamed'* && $output == *'restore --abandon'* ]] || { echo "$output"; return 1; }
  ! grep -qx rename "$DB/events"
}
@test "restore new host: interrupted abandon resumes its recorded rename and completes" {
  new_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  rec=$(recordings)
  export RS_A_INTERRUPT=1
  abandon
  [ "$status" = 1 ] && [ -e "$DB/abandon-cut" ] || { echo "$output"; return 1; }
  unset RS_A_INTERRUPT
  : >"$DB/events"
  abandon
  settled
}
@test "restore new host: completion writes the missing recordings list and does not make a safety backup" {
  printf '%s\n' /var/lib/custodexa/recordings/2026/a.cast /var/lib/custodexa/recordings/2026/b.cast /var/lib/custodexa/recordings/2026/c.cast >"$DB/recordings"
  new_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  ! grep -q '^curl ' "$DB/events" || return 1
  echo unsealed >"$DB/seal"
  run bash "$ENGINE" restore --resume --lang en </dev/null
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] && [[ $output == *'backup: 2 of the'* && $output == *'missing-recordings.txt'* ]] || { echo "$output"; return 1; }
  local staging
  staging=$(jq -r '."last_restore.staging"' "$ROOT/state.json")
  diff <(printf '%s\n' 2026/b.cast 2026/c.cast) "$staging/missing-recordings.txt" || return 1
  ! grep -qx pg_dump "$DB/events"
}
