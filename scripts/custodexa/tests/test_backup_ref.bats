#!/usr/bin/env bats
# Threat (A): a backup that is not what it claims. The stopped backup must stop the services before
# it copies anything, stop before stopping anything when the space is short, mark a failed backup
# as unusable, keep secrets out of the log, and keep the backup folder private. A backup of the
# operator's own (--backup-ref) must be taken after the services stopped; one taken earlier misses
# the last writes and is refused.

load helper
load install_host
load backup_host

setup() {
  backup_host ui
  # database 17.4 GB; recordings, audit and tls/ are a few KB (real du): the estimate is 18.4 GB.
  printf '%s\n' 18683107737 >"$DB/size"
  printf '%s\n' 19434628710 >"$DB/du.$(printf '%s' "$ROOT/backups/20260930-101502" | tr / -)"
  # stop 11s, database 1m 40s, files 8m 02s, settings (no time), start 9s, check 38s
  clock 0 11 0 100 0 482 0 0 9 0 38
}

@test "backup: the screen and the order of the steps match the reviewed text (three languages)" {
  for l in zh-TW en ja; do
    rm -rf "$ROOT/backups" "$ROOT/logs"
    : >"$DB/events"
    clock 0 11 0 100 0 482 0 0 9 0 38
    backup_run "$l" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(screen_of "$output") "$TESTS_DIR/snapshots/s17.$l.txt" || { echo "screen differs: $l"; return 1; }
  done
  # The order of the stopped-backup procedure: stop, dump, files, settings, start, then check.
  grep -v '^psql' "$DB/events" >"$BATS_TEST_TMPDIR/order"
  diff "$BATS_TEST_TMPDIR/order" - <<'EOF'
stop backend guacd frontend
pg_dump
tar -czf custodexa-files-20260930-101502.tar.gz
tar -czf custodexa-tls-20260930-101502.tar.gz
start backend guacd frontend
pg_restore
tar -tzf custodexa-files-20260930-101502.tar.gz
tar -tzf custodexa-tls-20260930-101502.tar.gz
EOF
}

@test "backup: the folder holds the named files, verified by SHA256SUMS, and no INCOMPLETE" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  d=$ROOT/backups/20260930-101502
  for f in custodexa-db-20260930-101502.dump custodexa-files-20260930-101502.tar.gz \
    custodexa-env-20260930-101502.bak custodexa-tls-20260930-101502.tar.gz snapshot.txt SHA256SUMS; do
    [ -s "$d/$f" ] || { echo "missing $f"; return 1; }
  done
  [ ! -e "$d/INCOMPLETE" ] || return 1
  (cd "$d" && sha256sum -c --quiet SHA256SUMS) || return 1
  [ "$(wc -l <"$d/SHA256SUMS")" -eq 5 ] || return 1
  # recordings and audit are in; exports (decrypted evidence plaintext) is not.
  tar -tzf "$d/custodexa-files-20260930-101502.tar.gz" >"$BATS_TEST_TMPDIR/list"
  grep -q '^recordings/2026/a.cast$' "$BATS_TEST_TMPDIR/list" || return 1
  grep -q '^audit/fallback.log$' "$BATS_TEST_TMPDIR/list" || return 1
  if grep -q exports "$BATS_TEST_TMPDIR/list"; then echo "exports was backed up"; return 1; fi
  cmp "$ROOT/.env" "$d/custodexa-env-20260930-101502.bak" || return 1
  # status reads these keys.
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.id)" = 20260930-101502 ] || return 1
  [ "$(cx_state_get last_backup.kind)" = script ] || return 1
  [ "$(cx_state_get last_backup.dir)" = backups/20260930-101502 ] || return 1
  [ "$(cx_state_get last_backup.size_bytes)" = 19434628710 ] || return 1
  [ "$(cx_state_get last_backup.snapshot_usable)" = true ] || return 1
  [ "$(cx_state_get last_backup.result)" = succeeded ]
}

@test "backup: backups/ and the backup folder are 0700, the .env copy 0600" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(stat -c %a "$ROOT/backups")" = 700 ] || return 1
  [ "$(stat -c %a "$ROOT/backups/20260930-101502")" = 700 ] || return 1
  [ "$(stat -c %a "$ROOT/backups/20260930-101502/custodexa-env-20260930-101502.bak")" = 600 ]
}

@test "backup: no .env secret value on the screen, in the log, in state.json or in snapshot.txt" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  for v in "$BK_JWT" "$BK_KEK" "$BK_DBPW"; do
    [[ $output != *"$v"* ]] || { echo "secret on screen"; return 1; }
    if grep -rqF -- "$v" "$ROOT/logs" "$ROOT/state.json" "$ROOT/backups/20260930-101502/snapshot.txt"; then
      echo "secret written: ${v:0:4}..."
      return 1
    fi
  done
}

@test "backup: not enough space stops before any service is stopped" {
  host_free / 1048576 # 1 GB
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] Not enough space for the backup: about 18.4 GB needed,"* ]] || { echo "$output"; return 1; }
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  if grep -q ' stop ' "$FAKE_DOCKER_LOG"; then echo "a stop call was made"; return 1; fi
  [ ! -d "$ROOT/backups/20260930-101502" ] || return 1
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = failed ] || return 1
  [ -z "$(cx_state_get last_backup.id)" ]
}

@test "backup: a failed step leaves INCOMPLETE, says how to start the services, records no backup" {
  printf '1\n' >"$DB/pg_dump.rc"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ -e "$ROOT/backups/20260930-101502/INCOMPLETE" ] || return 1
  [[ $output == *"[FAIL] 2/6  Database"* ]] || { echo "$output"; return 1; }
  [[ $output == *"the INCOMPLETE file there marks this backup as unusable."* ]] || return 1
  [[ $output == *"    cd $ROOT && sudo docker compose start backend guacd frontend"* ]] || return 1
  if grep -q '^start' "$DB/events"; then echo "started despite the failure"; return 1; fi
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = failed ] || return 1
  [ -z "$(cx_state_get last_backup.id)" ]
}

@test "backup: a backup that cannot be read back is failed and keeps INCOMPLETE" {
  printf '1\n' >"$DB/pg_restore.rc"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 6/6  Check the backup can be read"* ]] || { echo "$output"; return 1; }
  [ -e "$ROOT/backups/20260930-101502/INCOMPLETE" ] || return 1
  [ ! -e "$ROOT/backups/20260930-101502/SHA256SUMS" ]
}

@test "backup: without a terminal and without --yes nothing is stopped (exit 3)" {
  backup_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ ! -d "$ROOT/backups/20260930-101502" ] || return 1
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = cancelled ]
}

@test "backup: an external database is not backed up by the script (exit 3, nothing stopped)" {
  sed -i 's/"current.overlays": ""/"current.overlays": "external-database"/' "$ROOT/state.json"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"external database"* ]] || return 1
  [ ! -s "$DB/events" ]
}

@test "backup: KEK_PROVIDER=env says the .env copy holds the master key and gives no seal warning" {
  sed -i 's/^KEK_PROVIDER=ui$/KEK_PROVIDER=env/' "$ROOT/.env"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  screen_of "$output" | sed -n '/Backup done/,$p' >"$BATS_TEST_TMPDIR/done"
  diff "$BATS_TEST_TMPDIR/done" - <<'EOF'
[ OK ] Backup done: /opt/custodexa/backups/20260930-101502/ (18.1 GB)
  Contains: database, recordings, audit files, settings file .env
  (includes the master key), certificates tls/
  [WARN] This backup holds sensitive data and sits on the same host
         as .env. Encrypt it, store it elsewhere, and keep it apart
         from the master key material.
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
  [[ $output != *"sealed"* ]]
}

@test "backup within an upgrade: no stop or start of its own (the upgrade stopped them), no record (4 steps)" {
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/backup.sh"
  export CX_ROOT=$ROOT
  cx_log_open upgrade
  cx_state_load "$ROOT/state.json"
  cx_bk_vars
  cx_bk_open
  seen=""
  cb() { seen+="$1 $2/$3 $4;"; }
  cx_bk_take upgrade cb
  [ "$seen" = "OK 1/4 db;OK 2/4 files;OK 3/4 conf;OK 4/4 verify;" ] || { echo "$seen"; return 1; }
  if grep -q '^start\|^stop' "$DB/events"; then echo "stopped or started within an upgrade"; return 1; fi
  if grep -q 'last_backup' "$ROOT/state.json"; then echo "recorded by the backup, not the upgrade"; return 1; fi
  [ ! -e "$ROOT/backups/20260930-101502/INCOMPLETE" ]
}

# ---- the operator's own backup ----

# own_setup: the backend stopped at 02:16:13 UTC; the library loaded as the upgrade loads it.
own_setup() {
  export TZ=UTC
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/backup_ref.sh"
  export CX_ROOT=$ROOT
  docker_says container_inspect 'false 2026-09-30T02:16:13.123456789Z'
  cx_br_set_stop 2026-09-30T02:16:13.123456789Z
}

# with_answers <lang> <answer>...: the terminal as the operator saw it: each answer typed after its
# question (the tests have no terminal to echo the input).
with_answers() {
  local out=$output l=$1 p a
  shift
  local -a qs=(br_choose br_ask_ref br_ask_time br_ask_restore br_ask_yes)
  for a in "$@"; do
    p=$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg "$2"' _ "$SRC" "${qs[0]}")
    qs=("${qs[@]:1}")
    [ "$p" = "$(CX_LANG_FLAG=$l bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; cx_msg br_choose' _ "$SRC")" ] || p=${p//$'\n'/$'\n'  }
    out=${out/"$p"/"$p$a"$'\n'}
  done
  printf '%s\n' "${out%$'\n'}" | sed "s#$ROOT#/opt/custodexa#g"
}

own_interactive() { # <lang> <answers as lines>: choose, then the questions
  run bash -c 'CX_LANG_FLAG="" LANG=$1; . "$2/lib/common.sh"; cx_load_libs "$2"; . "$2/lib/backup_ref.sh"
    cx_br_set_stop 2026-09-30T02:16:13Z
    cx_br_choose "18.4 GB" 12 0 && [ "$CX_BR_CHOICE" = 2 ] && cx_br_interactive 02:16:02 0' _ "$1" "$SRC" <<<"$2"
}

@test "own backup, interactive: the reviewed screen word for word (zh-TW, en)" {
  own_setup
  own_interactive zh-TW $'2\nvm-snap-custodexa-20260930-0218\n2026-09-30 02:18\n虛擬化平台操作手冊 第 4 章\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(with_answers zh-TW 2 vm-snap-custodexa-20260930-0218 '2026-09-30 02:18' '虛擬化平台操作手冊 第 4 章' yes) \
    "$TESTS_DIR/snapshots/s09.zh-TW.txt" || return 1
  own_interactive en $'2\nvm-snap-custodexa-20260930-0218\n2026-09-30 02:18\nVirtualization platform manual, chapter 4\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(with_answers en 2 vm-snap-custodexa-20260930-0218 '2026-09-30 02:18' 'Virtualization platform manual, chapter 4' yes) \
    "$TESTS_DIR/snapshots/s09.en.txt"
}

@test "own backup, interactive: a snapshot started before the stop is refused, word for word" {
  own_setup
  for l in zh-TW en; do
    own_interactive "$l" $'2\nvm-snap-1\n2026-09-30 02:10'
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output" | sed -n '/^\[FAIL\]/,$p' | sed "s#$ROOT#/opt/custodexa#g") \
      "$TESTS_DIR/snapshots/s09-early.$l.txt" || { echo "differs: $l"; return 1; }
  done
}

@test "own backup: earlier the same day, the same minute as the stop, or a day before: all refused" {
  own_setup
  # Full answers follow, so only the time check can refuse.
  for t in '2026-09-30 00:05' '2026-09-30 02:16' '2026-09-29 23:59'; do
    own_interactive en $'2\nsnap\n'"$t"$'\n/doc\nyes'
    [ "$status" -eq 1 ] || { echo "accepted $t"; return 1; }
    [[ $output == *"The snapshot time ${t#* } is before the stop time 02:16:13"* ]] || { echo "$output"; return 1; }
  done
  own_interactive en $'2\nsnap\n2026-09-30 02:17\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "own backup: a malformed time is asked again; no yes, no name or no procedure is refused" {
  own_setup
  own_interactive en $'2\nsnap\n30/09 02:18\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"Enter the time as YYYY-MM-DD HH:MM"* ]] || return 1
  own_interactive en $'2\nsnap\n2026-09-30 02:18\n/doc\ny'
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"The snapshot was not confirmed"* && $output == *"up -d"* ]] || return 1
  own_interactive en $'2\n\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 1 ] || return 1
  own_interactive en $'2\nsnap\n2026-09-30 02:18\n\nyes'
  [ "$status" -eq 1 ]
}

@test "own backup: empty or EOF answers print refusal and commands to resume the old service" {
  own_setup
  local answers
  for answers in $'2\nsnap\n' $'2\nsnap' $'2\n' $'2\nsnap\n2026-09-30 02:18\n'; do
    own_interactive en "$answers"
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    [[ $output == *"[FAIL] The snapshot was not confirmed"* ]] || { echo "$output"; return 1; }
    [[ $output == *"current/compose.yml up -d"* && $output == *"custodexa.sh status"* ]] \
      || { echo "$output"; return 1; }
  done
}

@test "own backup: EOF at the backup choice prints refusal and commands to resume" {
  own_setup
  run bash -c 'LANG=en; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_ROOT=$2 CX_UP_KIND=package; cx_br_choose "18.4 GB" 12 0' _ "$SRC" "$ROOT" </dev/null
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The snapshot was not confirmed"* ]] || { echo "$output"; return 1; }
  [[ $output == *"current/compose.yml up -d"* && $output == *"custodexa.sh status"* ]]
}

@test "recovery status commands carry only an explicitly requested language" {
  own_setup
  for kind in package convert; do
    run bash -c 'CX_LANG_FLAG=zh-TW; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
      CX_ROOT=$2 CX_DIR=/tmp/custodexa-1.13.0/custodexa CX_UP_KIND=$3
      CX_UP_OLD_PROJECT=custodexa_old CX_UP_OLD_FILES=$2/docker-compose.yml; cx_br_resume' _ "$SRC" "$ROOT" "$kind"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [[ $output == *"custodexa.sh status --lang zh-TW"* ]] || { echo "$output"; return 1; }
  done
  run bash -c 'CX_LANG_FLAG=""; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_ROOT=$2 CX_UP_KIND=package; cx_br_resume' _ "$SRC" "$ROOT"
  [[ $output == *"custodexa.sh status"* && $output != *"custodexa.sh status --lang"* ]]
}

@test "stopped upgrade recovery starts the old services and checks status in the chosen language" {
  own_setup
  run bash -c 'CX_LANG_FLAG=ja; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/upgrade_output.sh"; . "$1/lib/stop_check.sh"
    CX_ROOT=$2 CX_UP_KIND=package CX_BK_SERVICES="backend guacd frontend"; cx_up_resume_cmd' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"start backend guacd frontend"* && $output == *"custodexa.sh status --lang ja"* ]]
}

@test "stopped conversion recovery checks status through the package script" {
  own_setup
  run bash -c 'CX_LANG_FLAG=zh-TW; . "$1/lib/common.sh"; cx_load_libs "$1"
    . "$1/lib/upgrade_output.sh"; . "$1/lib/stop_check.sh"
    CX_ROOT=$2 CX_DIR=/tmp/custodexa-1.13.0/custodexa CX_UP_KIND=convert
    CX_UP_OLD_HINT="-p custodexa_old --project-directory $2 -f $2/docker-compose.yml"
    CX_BK_SERVICES="backend guacd frontend"; cx_up_resume_cmd' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"sudo env CUSTODEXA_HOME=$ROOT /tmp/custodexa-1.13.0/custodexa/custodexa.sh status --lang zh-TW"* ]]
}

# own_flags <expected status> [--backup-ref x] ...: cx_br_noninteractive with those options.
own_flags() {
  local want=$1
  shift
  run bash -c 'CX_LANG_FLAG=en; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_BACKUP_REF=$2 CX_BACKUP_TIME=$3 CX_BACKUP_RESTORE=$4; cx_br_noninteractive' _ "$SRC" "$@"
  [ "$status" -eq "$want" ] || { echo "want $want got $status for: $*"; echo "$output"; return 1; }
}

@test "own backup, --backup-ref: the two companion options are required" {
  own_setup
  own_flags 2 snap '' '' || return 1
  own_flags 2 snap '2026-09-30 02:18' '' || return 1
  own_flags 2 snap '' /doc || return 1
  own_flags 2 '' '2026-09-30 02:18' /doc || return 1
  own_flags 2 snap '2026-09-30T02:18' /doc || return 1
  [[ $output == *"YYYY-MM-DD HH:MM"* ]]
}

@test "own backup, --backup-ref: refused while the services run (exit 3), nothing recorded" {
  own_setup
  docker_says container_inspect 'true 0001-01-01T00:00:00Z'
  cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before"
  own_flags 3 snap '2026-09-30 02:18' /doc || return 1
  [[ $output == *"Your own backup has to be taken after the services stop."* ]] || return 1
  cmp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before"
}

@test "own backup, --backup-ref after the operator stopped the services: time, drain, acceptance" {
  own_setup
  own_flags 1 snap '2026-09-30 02:10' /doc || return 1
  [[ $output == *"The snapshot time 02:10 is before the stop time 02:16:13"* ]] || return 1
  own_flags 1 snap '2026-09-30 01:59' /doc || return 1
  docker_says logs '稽核佇列排空逾時：3 列未確認落地（已降級寫檔 3 列、worker 持有中未回報 0 列、確定遺失 0 列）'
  own_flags 1 snap '2026-09-30 02:18' /doc || return 1
  [[ $output == *"did not drain"* ]] || return 1
  rm -f "$FAKE_DOCKER_REPLAY/logs.out"
  own_flags 0 vm-snap-custodexa-20260930-0218 '2026-09-30 02:18' /doc || return 1
  [ "$output" = "[WARN] Using your backup vm-snap-custodexa-20260930-0218 (02:18, after the stop at 02:16:13);
       the script makes none." ] || { echo "$output"; return 1; }
  docker_says container_inspect 'garbage'
  own_flags 1 snap '2026-09-30 02:18' /doc
}

@test "own backup: recorded in state.json for status, the answers kept as given in a private file" {
  own_setup
  cx_state_load "$ROOT/state.json"
  CX_BR_REF=vm-snap-1 CX_BR_TIME='2026-09-30 02:18' CX_BR_RESTORE='虛擬化平台操作手冊 第 4 章'
  CX_BR_EPOCH=$(date -d '2026-09-30 02:18' +%s)
  cx_br_record 20260930-021613
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.kind)" = external ] || return 1
  [ "$(cx_state_get last_backup.id)" = 20260930-021613 ] || return 1
  [ "$(cx_state_get last_backup.external_ref)" = vm-snap-1 ] || return 1
  [ "$(cx_state_get last_backup.external_restore)" = "see backups/20260930-021613/external.txt" ] || return 1
  [ "$(cx_state_get last_backup.external_time)" = 2026-09-30T02:18:00+0000 ] || return 1
  [ "$(cx_state_get last_backup.stopped_at)" = 2026-09-30T02:16:13+0000 ] || return 1
  [ "$(cx_state_get last_backup.taken_at)" = 2026-09-30T02:18:00+0000 ] || return 1
  grep -qx 'restore=虛擬化平台操作手冊 第 4 章' "$ROOT/backups/20260930-021613/external.txt" || return 1
  [ "$(stat -c %a "$ROOT/backups/20260930-021613")" = 700 ] || return 1
  [ "$(stat -c %a "$ROOT/backups/20260930-021613/external.txt")" = 600 ]
}

@test "own backup, external database: no choice offered, and the database is on the list" {
  own_setup
  run bash -c 'CX_LANG_FLAG=en; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    cx_br_set_stop 2026-09-30T02:16:13Z
    cx_br_choose "18.4 GB" 12 1 && [ "$CX_BR_CHOICE" = 2 ] && cx_br_interactive 02:16:02 1' _ "$SRC" \
    <<<$'snap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output != *"Choose [1/2]"* ]] || return 1
  [[ $output == *"    Database         a full backup of the external database taken
                     after 02:16:13"* ]]
}

# resume_of <kind> [old project] [old files]: cx_br_resume as the upgrade calls it.
resume_of() {
  run bash -c 'CX_LANG_FLAG="" LANG=en; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_ROOT=$2 CX_UP_KIND=$3 CX_UP_OLD_PROJECT=${4:-} CX_UP_OLD_FILES=${5:-} CX_DIR=/tmp/custodexa-1.13.0/custodexa
    cx_br_resume' _ "$SRC" "$ROOT" "$@"
}

# The command lines of the output, as typed without sudo.
typed_cmds() { printf '%s\n' "$output" | grep '^    ' | sed 's/^    //; s/^sudo //'; }

@test "own backup refused, package deployment: the cancel command starts current/compose.yml with the release's image references" {
  mkdir -p "$ROOT/current"
  printf '%s\n' CUSTODEXA_IMAGE_BACKEND=ghcr.io/custodexa/backend:1.13.0 \
    CUSTODEXA_IMAGE_FRONTEND=ghcr.io/custodexa/frontend:1.13.0 >"$ROOT/current/images.env"
  resume_of package
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | sed "s#$ROOT#/opt/custodexa#g" | sed -n '/^  To cancel/,$p')" = "$(sed -n '/^  To cancel/,$p' "$TESTS_DIR/snapshots/s09-early.en.txt")" ] \
    || { echo "$output"; return 1; }
  : >"$FAKE_DOCKER_LOG"
  (eval "$(typed_cmds | head -n 3)") || { typed_cmds; return 1; }
  grep -qxF "$(printf 'ARGS\tcompose -p custodexa --project-directory %s -f %s/current/compose.yml up -d\tIMG_BACKEND=ghcr.io/custodexa/backend:1.13.0' "$ROOT" "$ROOT")" \
    "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
}

@test "own backup refused during the first conversion: the cancel command starts the old project with its root compose file" {
  resume_of convert custodexa_old "$ROOT/docker-compose.yml"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output" | sed -n '/^  To cancel/,$p') - <<EXPECTED || { echo "$output"; return 1; }
  To cancel the upgrade, start all the services again and confirm:
    sudo docker compose -p custodexa_old --project-directory $ROOT \\
      -f $ROOT/docker-compose.yml up -d
    sudo env CUSTODEXA_HOME=$ROOT /tmp/custodexa-1.13.0/custodexa/custodexa.sh status
EXPECTED
  : >"$FAKE_DOCKER_LOG"
  (eval "$(typed_cmds | head -n 2)") || { typed_cmds; return 1; }
  grep -qF "$(printf 'ARGS\tcompose -p custodexa_old --project-directory %s -f %s/docker-compose.yml up -d' "$ROOT" "$ROOT")" \
    "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  ! grep -q current/ "$FAKE_DOCKER_LOG"
}
