#!/usr/bin/env bats
# The upgrade to a release with the profiles layout converts .env: the old COMPOSE_FILE
# lines leave, the managed block comes in, and an external ingress written as an overlay becomes
# TLS_MODE=external. Step 9 does it in three parts (state record, links, .env); every test that stops
# the run between them starts the deployment again from its own `custodexa.sh` link, as an operator
# would, and asserts what the script now behind that link may and may not do.
#   a  state.json records last_upgrade.env_rewrite=pending and the sha256 of .env
#   b  the links current and custodexa.sh
#   c  .env is rewritten whole (one rename), then the record becomes done

load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

setup() { host_workdir; }

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }
envsha() { sha256sum "$ROOT/.env" | cut -d' ' -f1; }
statesha() { sha256sum "$ROOT/state.json" | cut -d' ' -f1; }
LEGACY_INGRESS=current/compose.yml:current/compose.external-ingress.yml

# conv_fetched: 1.16.1 installed (the overlays layout), 1.16.2 fetched (the profiles layout).
conv_fetched() {
  RB_NEW=1.16.2
  UP_LAYOUT=profiles
  rb_fetched ui 1.16.1
}

# conv_host <ingress|builtin>: the deployment as a 1.22 install left .env and state.json: the form
# in COMPOSE_FILE, TLS_MODE as the template has it.
conv_host() {
  RB_NEW=1.16.2
  UP_LAYOUT=profiles
  host_cache "conv-fetched" conv_fetched || return 1
  bk_env_set TLS_MODE selfsigned
  case $1 in
    ingress)
      bk_state_set current.overlays external-ingress
      bk_env_set COMPOSE_FILE "$LEGACY_INGRESS"
      # The web service of a deployment behind its own ingress has the other name in the new layout.
      hook_before 'case " $* " in *" compose "*" ps "*"--format"*)
  printf "backend running \nguacd running \nfrontend-published running \npostgres running healthy\n"; exit 0 ;;
esac' ;;
    *) bk_env_set COMPOSE_FILE current/compose.yml ;;
  esac
  BEFORE_ENV=$(envsha)
  BEFORE_OTHERS=$(grep -vE '^(COMPOSE_FILE|COMPOSE_PROFILES|TLS_MODE)=' "$ROOT/.env")
  : >"$DB/events"
  : >"$FAKE_DOCKER_LOG"
}

# conv_hook <lib file> <function> <code before> [code after]: wrap a function of the release that
# runs the upgrade; the code runs in the function, a `return 1` or a kill there stops the run.
conv_hook() {
  local f=$ROOT/releases/1.16.2/lib/$1.sh
  printf '\neval "$(declare -f %s | sed '\''1s/%s/%s_orig/'\'')"\n%s() { %s; %s_orig "$@" || return $?; %s; }\n' \
    "$2" "$2" "$2" "$2" "${3:-:}" "$2" "${4:-:}" >>"$f"
}
conv_events() {
  conv_hook upgrade_steps cx_up_link : 'printf "link %s\n" "${1##*/}" >>"$DB/conv.events"'
  conv_hook upgrade_convert cx_up_env_rewrite : 'printf "env\n" >>"$DB/conv.events"'
}

# conv_up [options]: the upgrade by the release 1.16.2 itself, as the old script hands it over.
conv_up() {
  clock 0 3 0 41 0 4 0 11
  run bash "$ROOT/releases/1.16.2/custodexa.sh" upgrade --lang "${CONV_LANG:-en}" --yes "$@" </dev/null
  # The daemon fake wraps mv once; a second call would wrap its own wrapper without end.
  [ -e "$DB/live" ] || { rb_live_daemon; : >"$DB/live"; }
  : >"$DB/events"
}
# conv_stop <point>: the run ends at that point of step 9 (the daemon answers like upgrade_stack's).
conv_stop() {
  case $1 in
    1) conv_hook upgrade_steps cx_up_record_switch : 'kill -TERM $$' ;;
    2) conv_hook upgrade_convert cx_up_env_rewrite 'kill -TERM $$' ;;
    3) conv_hook upgrade_convert cx_up_conv_build 'case ${2:-} in "$ROOT"/.env.tmp-*) return 1 ;; esac' ;;
    4) conv_hook upgrade_convert cx_up_env_done 'kill -TERM $$' ;;
  esac
  conv_up
  [ "$status" -eq 1 ] || { echo "point $1: $status"; echo "$output"; return 1; }
}
cur_link() { readlink "$ROOT/current"; }

# ---------- the preview ----------

# conv_preview <lang> <overlays> <env lines...>: the section of the preview, on a folder of its own.
conv_preview() {
  local l=$1 ov=$2 w=$BATS_TEST_TMPDIR/pv
  shift 2
  rm -rf "$w"
  mkdir -p "$w/releases/9.9.9"
  printf '{"compose_layout": "profiles"}\n' >"$w/releases/9.9.9/MANIFEST.json"
  printf '%s\n' "$@" >"$w/.env"
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=$3; cx_load_libs "$1"; . "$1/lib/upgrade_convert.sh"
    CX_ROOT=$2; CX_UP_TARGET=9.9.9; CX_OVERLAYS=$4; cx_up_conv_preview' _ "$SRC" "$w" "$l" "$ov"
}

@test "preview of the .env change for the four old COMPOSE_FILE forms, word for word in three languages" {
  local l
  for l in zh-TW en ja; do
    conv_preview "$l" "" 'DATA_PATH=./data' 'COMPOSE_FILE=current/compose.yml' 'TLS_MODE=selfsigned'
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/convert-builtin.$l.txt" || { echo "builtin $l"; return 1; }
    # The other three COMPOSE_FILE values of the old layout (1.22 and before).
    conv_preview "$l" "external-database" 'DATA_PATH=./data' 'EXTERNAL_DB_HOST=db.example.internal' \
      'COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml' 'TLS_MODE=selfsigned'
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/convert-extdb.$l.txt" || { echo "extdb $l"; return 1; }
    conv_preview "$l" "external-ingress" 'DATA_PATH=./data' "COMPOSE_FILE=$LEGACY_INGRESS" 'TLS_MODE=selfsigned'
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/convert-ingress.$l.txt" || { echo "ingress $l"; return 1; }
    # Both overlays of the old layout (1.22 and before).
    conv_preview "$l" "external-ingress external-database" 'EXTERNAL_DB_HOST=db.example.internal' \
      "COMPOSE_FILE=$LEGACY_INGRESS:current/compose.external-database.yml" 'TLS_MODE=selfsigned'
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/convert-both.$l.txt" || { echo "both $l"; return 1; }
  done
  # Nothing to change: no section at all.
  conv_preview en "" 'DATA_PATH=./data' '# >>> managed by custodexa.sh: derived from EXTERNAL_DB_HOST and TLS_MODE; do not edit' \
    'COMPOSE_FILE=current/compose.yml' 'COMPOSE_PROFILES=bundled-db,builtin-tls' '# <<< managed by custodexa.sh'
  [ "$status" -eq 0 ] && [ -z "$output" ] || { echo "$output"; return 1; }
}

@test "the upgrade preview shows the .env section after the notes; nothing is written before the answer" {
  conv_host ingress
  local state0
  state0=$(statesha)
  CONV_LANG=zh-TW
  run bash "$ROOT/releases/1.16.2/custodexa.sh" upgrade --lang zh-TW </dev/null
  [[ $output == *'需要知道的事'*'.env 將調整（第 9 步換版時改寫；其他設定一行都不動）'*'TLS_MODE=selfsigned  →  TLS_MODE=external'* ]] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$BEFORE_ENV" ] && [ "$(statesha)" = "$state0" ] || return 1
  [ "$(cur_link)" = releases/1.16.1 ]
  ! grep -q ' stop \| up ' "$FAKE_DOCKER_LOG" || return 1
}

# ---------- refusals before anything stops ----------

@test "an address added to a built-in deployment with data: the upgrade refuses at step 1 (E2), nothing touched" {
  conv_host builtin
  mkdir -p "$ROOT/data/postgres" && printf '16\n' >"$ROOT/data/postgres/PG_VERSION"
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  local before state0
  before=$(envsha) state0=$(statesha)
  : >"$FAKE_DOCKER_LOG"
  CONV_LANG=zh-TW conv_up
  [ "$status" -eq 3 ] && [[ $output == *'從來沒有生效'* && $output == *'EXTERNAL_DB_HOST=db.example.internal'* ]] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$before" ] && [ "$(statesha)" = "$state0" ] && [ "$(cur_link)" = releases/1.16.1 ] || return 1
  ! grep -q ' stop \| up \| rm ' "$FAKE_DOCKER_LOG" || return 1
  [[ $output != *host.docker.internal* ]]
}

@test "COMPOSE_FILE lists the external database and the address is empty: the screen of a configuration that could not start" {
  conv_host builtin
  bk_state_set current.overlays external-database
  bk_state_set current.external_db_host db01.example.internal
  bk_state_set current.external_db_port 5432
  # A deployment of the old layout (1.22 and before) whose COMPOSE_FILE lists the external database overlay.
  bk_env_set COMPOSE_FILE current/compose.yml:current/compose.external-database.yml
  bk_env_set EXTERNAL_DB_HOST -
  local before state0 l
  before=$(envsha) state0=$(statesha)
  : >"$FAKE_DOCKER_LOG"
  for l in zh-TW en ja; do
    CONV_LANG=$l conv_up
    [ "$status" -eq 3 ] && [[ $output == *'EXTERNAL_DB_HOST=db01.example.internal'* && $output == *'db01.example.internal:5432'* ]] || { echo "$l: $output"; return 1; }
    # The screen quotes the overlay of the old layout (1.22 and before) as the operator wrote it.
    [[ $output == *'compose.external-database.yml'* && $output == *'custodexa.sh upgrade'* && $output != *host.docker.internal* ]] || { echo "$output"; return 1; }
  done
  [ "$(envsha)" = "$before" ] && [ "$(statesha)" = "$state0" ] || return 1
  ! grep -q ' stop \| up ' "$FAKE_DOCKER_LOG" || return 1
}

# ---------- the whole upgrade ----------

@test "the whole upgrade: block, TLS_MODE and the record; the .env rename comes after the links; other lines unchanged" {
  conv_host ingress
  conv_events
  conv_up
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$DB/conv.events")" = $'link current\nlink custodexa.sh\nenv' ] || { cat "$DB/conv.events"; return 1; }
  [ "$(st last_upgrade.env_rewrite)" = done ] && [ "$(st last_upgrade.env_rewrite_from)" = "$BEFORE_ENV" ] || return 1
  [ "$(st last_upgrade.env_rewrite_keys)" = "COMPOSE_FILE TLS_MODE" ] || { st last_upgrade.env_rewrite_keys; return 1; }
  grep -qx 'TLS_MODE=external' "$ROOT/.env"
  grep -qx 'COMPOSE_PROFILES=bundled-db,own-ingress' "$ROOT/.env"
  [ "$(grep -c '^COMPOSE_FILE=' "$ROOT/.env")" = 1 ] && grep -qx 'COMPOSE_FILE=current/compose.yml' "$ROOT/.env" || return 1
  [ "$(stat -c %a "$ROOT/.env")" = 600 ]
  # Every line outside the block and the two rewritten keys is the same, byte for byte.
  [ "$(grep -vE '^(COMPOSE_FILE|COMPOSE_PROFILES|TLS_MODE)=|^# (>>>|<<<) managed' "$ROOT/.env")" = "$BEFORE_OTHERS" ]
}

@test "a deployment whose form was never in COMPOSE_FILE: the block is added, TLS_MODE is not touched" {
  conv_host builtin
  conv_up
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -qx 'TLS_MODE=selfsigned' "$ROOT/.env"
  grep -qx 'COMPOSE_PROFILES=bundled-db,builtin-tls' "$ROOT/.env"
  [ "$(st last_upgrade.env_rewrite)" = done ] && [ "$(st last_upgrade.env_rewrite_keys)" = COMPOSE_FILE ] || return 1
}

@test "a failure after the switch and the interruption notes name the plain container logs command, never docker compose" {
  conv_host ingress
  touch "$DB/rb.health" "$UP/health.rc"
  conv_up
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '    sudo docker logs --tail 50 custodexa-backend' || { echo "$output"; return 1; }
  [[ $output != *'docker compose'* ]]
  [ -z "$(grep -rn 'cx_up_compose_''hint' "$SRC")" ]
}

# ---------- step 9 stopped between its parts ----------

@test "point 1, state saved and links not switched: status from the link runs the old script, shows the interrupted upgrade, .env is as before" {
  conv_host ingress
  conv_stop 1
  [ "$(readlink -f "$ROOT/custodexa.sh")" = "$ROOT/releases/1.16.1/custodexa.sh" ]
  [ "$(cur_link)" = releases/1.16.1 ] && [ "$(envsha)" = "$BEFORE_ENV" ] || return 1
  [ "$(st last_upgrade.env_rewrite)" = pending ] && [ "$(st last_upgrade.env_rewrite_from)" = "$BEFORE_ENV" ] || return 1
  grep -qx "COMPOSE_FILE=$LEGACY_INGRESS" "$ROOT/.env"
  # The operator starts again from the link: status of the old script shows the interrupted upgrade
  # and writes nothing.
  local state1
  state1=$(statesha)
  : >"$FAKE_DOCKER_LOG"
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  printf '%s\n' "$output" | grep -qxF '  [WARN] 1.16.1 -> 1.16.2 did not finish; it stopped at step 9.' || { echo "$output"; return 1; }
  [ "$(envsha)" = "$BEFORE_ENV" ] && [ "$(statesha)" = "$state1" ] || { echo "status wrote a file"; return 1; }
  grep -qx 'TLS_MODE=selfsigned' "$ROOT/.env" && ! grep -q 'managed by custodexa' "$ROOT/.env" || return 1
  ! grep -q ' stop \| up \| rm ' "$FAKE_DOCKER_LOG" || return 1
}

@test "point 2, links switched and .env not rewritten: rollback is not refused and .env ends as before the upgrade" {
  conv_host ingress
  conv_stop 2
  [ "$(cur_link)" = releases/1.16.2 ] && [ "$(readlink -f "$ROOT/custodexa.sh")" = "$ROOT/releases/1.16.2/custodexa.sh" ] || return 1
  [ "$(envsha)" = "$BEFORE_ENV" ]
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cur_link)" = releases/1.16.1 ] && [ "$(envsha)" = "$BEFORE_ENV" ] || return 1
  grep -q 'COMPOSE_FILE=' "$ROOT/.env" && ! grep -q 'managed by custodexa' "$ROOT/.env" || return 1
}

@test "point 2 with .env edited by hand: rollback refuses with exit code 3 and the hashes stay" {
  conv_host ingress
  conv_stop 2
  bk_env_set TLS_MODE provided
  local env1 state1
  env1=$(envsha) state1=$(statesha)
  : >"$FAKE_DOCKER_LOG"
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *'TLS_MODE=external'* ]] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$env1" ] && [ "$(statesha)" = "$state1" ] || return 1
  ! grep -q ' stop \| up ' "$FAKE_DOCKER_LOG" || return 1
}

@test "point 3, the temporary file cannot be written: the upgrade fails, the record stays pending, rollback works as at point 2" {
  conv_host ingress
  conv_stop 3
  [[ $output == *'step 9/13'* && $output == *'stays as it was before the upgrade'* ]] || { echo "$output"; return 1; }
  [ "$(st last_upgrade.env_rewrite)" = pending ] && [ "$(envsha)" = "$BEFORE_ENV" ] || return 1
  [ -z "$(ls "$ROOT"/.env.tmp-* 2>/dev/null)" ]
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cur_link)" = releases/1.16.1 ] && [ "$(envsha)" = "$BEFORE_ENV" ] || return 1
}

@test "point 4, renamed and the record not saved: rollback is not refused and changes only the block" {
  conv_host ingress
  conv_stop 4
  [ "$(st last_upgrade.env_rewrite)" = pending ] && [ "$(envsha)" != "$BEFORE_ENV" ] || return 1
  grep -qx 'TLS_MODE=external' "$ROOT/.env"
  local others
  others=$(grep -vE '^(COMPOSE_FILE|COMPOSE_PROFILES)=|^# (>>>|<<<) managed' "$ROOT/.env")
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cur_link)" = releases/1.16.1 ]
  grep -qx "COMPOSE_FILE=$LEGACY_INGRESS" "$ROOT/.env"
  ! grep -q '^COMPOSE_PROFILES=' "$ROOT/.env" || return 1
  [ "$(grep -vE '^(COMPOSE_FILE|COMPOSE_PROFILES)=|^# (>>>|<<<) managed' "$ROOT/.env")" = "$others" ]
}

@test "after the rollback of point 2, upgrading again lists TLS_MODE changing to external" {
  conv_host ingress
  conv_stop 2
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  run bash "$ROOT/releases/1.16.2/custodexa.sh" upgrade --lang en </dev/null
  [[ $output == *'TLS_MODE=selfsigned  ->  TLS_MODE=external'* ]] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$BEFORE_ENV" ]
}

# ---------- reverting an unfinished conversion ----------

@test "an unfinished conversion: rollback --revert is refused with exit code 3 and only --resume and the restore guide are offered" {
  conv_host ingress
  conv_stop 2
  touch "$DB/rb.health"
  rb_run en --yes
  [ "$status" -eq 1 ] && [[ $output == *'rollback --resume'* && $output != *'--revert'* && $output == *'docs/ops/backup-and-restore.md'* ]] || { echo "$output"; return 1; }
  local id0 step0 env1 state1 l
  id0=$(rb_identity) step0=$(st last_rollback.step) env1=$(envsha) state1=$(statesha)
  for l in zh-TW en ja; do
    : >"$DB/events"
    : >"$FAKE_DOCKER_LOG"
    run bash "$ROOT/custodexa.sh" rollback --revert --yes --lang "$l" </dev/null
    [ "$status" -eq 3 ] || { echo "$l: $status $output"; return 1; }
    [[ $output == *'rollback --resume'* && $output == *'docs/ops/backup-and-restore.md'* && $output != *'--revert'* ]] || { echo "$output"; return 1; }
    ! grep -qE '^(stop|up)' "$DB/events" && ! grep -q ' stop \| up ' "$FAKE_DOCKER_LOG" || return 1
    [ "$(rb_identity)" = "$id0" ] && [ "$(st last_rollback.step)" = "$step0" ] && [ "$(st last_rollback.direction)" = rollback ] || return 1
    [ "$(envsha)" = "$env1" ] && [ "$(statesha)" = "$state1" ] || return 1
  done
  rm "$DB/rb.health"
  rb_run en --resume --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$BEFORE_ENV" ] && [ "$(cur_link)" = releases/1.16.1 ] || return 1
}

@test "a finished conversion: rollback --revert goes back to the upgraded version as before" {
  conv_host ingress
  conv_up
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  touch "$DB/rb.health"
  rb_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *'rollback --revert'* ]] || { echo "$output"; return 1; }
}

# ---------- upgrade does not sync the block at step 1 ----------

# conv_profiles_source: the deployment already runs a release with the profiles layout (1.23.0 going
# to 1.23.x), with a COMPOSE_FILE line outside the block.
conv_profiles_source() {
  conv_host builtin
  jq '.compose_layout = "profiles"' "$ROOT/releases/1.16.1/MANIFEST.json" >"$ROOT/m.new" && mv "$ROOT/m.new" "$ROOT/releases/1.16.1/MANIFEST.json"
  BEFORE_ENV=$(envsha)
}

@test "a profiles deployment with a COMPOSE_FILE line outside the block: a stop before step 9 leaves .env alone" {
  conv_profiles_source
  conv_hook upgrade_steps cx_up_record_switch 'kill -TERM $$'
  conv_up
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ "$(envsha)" = "$BEFORE_ENV" ] && [ "$(cur_link)" = releases/1.16.1 ] || return 1
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$ROOT/.env"
  ! grep -q 'managed by custodexa' "$ROOT/.env" || return 1
}

@test "a profiles deployment with a COMPOSE_FILE line outside the block: the line moves into the block only after the links switched" {
  conv_profiles_source
  conv_events
  conv_up
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$DB/conv.events")" = $'link current\nlink custodexa.sh\nenv' ] || { cat "$DB/conv.events"; return 1; }
  [ "$(grep -c '^COMPOSE_FILE=' "$ROOT/.env")" = 1 ]
  awk '/^# >>> managed/{b=1} b&&/^COMPOSE_FILE=current\/compose.yml$/{ok=1} /^# <<< managed/{b=0} END{exit !ok}' "$ROOT/.env"
}
