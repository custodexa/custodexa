#!/usr/bin/env bats
# lib/pgconvert.sh: the checks before the preview, the preview section and step 8.
# The unit tests run the module's functions on backup_host's deployment with the fake docker; the
# whole-upgrade scenarios (interruptions, the old data read back by the old version) are the
# integration scenario pg18-convert and keep their skeletons here until that scenario covers them.

load helper
load install_host
load backup_host
load upgrade_host
load pgconvert_host

setup() {
  backup_host ui
  load_lib
  for f in service_controls upgrade_query upgrade_preflight stop_check upgrade_steps rollback_check; do
    # shellcheck source=/dev/null
    . "$SRC/lib/$f.sh"
  done
  CX_ROOT=$ROOT
  CX_LANG=en
  CX_LOG_FILE=$BATS_TEST_TMPDIR/log
  : >"$CX_LOG_FILE"
  cx_state_load "$ROOT/state.json"
  CX_OVERLAYS=$(cx_state_get current.overlays)
  cx_bk_vars
  CX_UP_TARGET=1.23.0 CX_UP_CURRENT=1.13.0
  CX_UP_BACKUP=backups/x.tar CX_UP_BACKUP_KIND=script CX_UP_BACKUP_DIR=$ROOT/backups
  CX_READY_TRIES=3
  declare -gA CX_IMG_REF=([postgres]=docker.io/library/postgres@sha256:aaaa)
  mkdir -p "$ROOT/releases/1.23.0" "$ROOT/backups"
  jq '.version = "1.23.0" | .images.postgres.tag = "18.6-alpine3.24"
    | .bundled_db = {major: 18, data_dir: "postgresql", pgdata: "18/docker"}
    | .images |= with_entries(.value.platforms = {amd64: {config_digest: "sha256:c", size: 1000000000}})' \
    "$ROOT/releases/1.13.0/MANIFEST.json" >"$ROOT/releases/1.23.0/MANIFEST.json"
  cx_manifest_load "$ROOT/releases/1.23.0/MANIFEST.json"
  host_arch x86_64
  host_free / 900000000
  printf '/var/lib/docker\n' >"$FAKE_DOCKER_REPLAY/info_--format_{{.DockerRootDir}}.out"
  pgc_free docker 900000000
  CX_BK_NEED=0
  cx_wait_backend_health() { return 0; }
  fake sleep ':'
}

# new_side: the temporary container's psql answers, and the files `run -d` leaves.
new_side() {
  cp "$DB/encoding" "$DB/new.facts"
  printf 'on\n' >"$DB/new.checksums"
  hook_before 'case " $* " in
  *" ps -q postgres"*) echo pgid; exit 0 ;;
  *" inspect -f"*) echo custodexa_default; exit 0 ;;
  *" run --rm "*"--entrypoint pg_dump "*) printf "%s" "${PGPASSWORD:-}" >"'"$DB"'/dump-pw"; exit "$(cat "'"$DB"'/pg_dump.rc" 2>/dev/null || echo 0)" ;;
  *" run -d "*) printf "%s" "${POSTGRES_PASSWORD:-}" >"'"$DB"'/init-pw"; mkdir -p "'"$ROOT"'/data/postgresql/18/docker"; echo 18 >"'"$ROOT"'/data/postgresql/18/docker/PG_VERSION"; exit 0 ;;
  *" start "*) jq -r ".\"last_upgrade.db_convert.recovery\" // \"\"" "'"$ROOT"'/state.json" >>"'"$DB"'/rec-at-start"; exit 0 ;;
  *" exec custodexa-pgconvert psql "*"SHOW data_checksums"*) cat "'"$DB"'/new.checksums"; exit 0 ;;
  *" exec custodexa-pgconvert psql "*) cat "'"$DB"'/new.facts"; exit 0 ;;
  *" exec custodexa-pgconvert pg_restore "*) [ -e "'"$DB"'/restore.fail" ] && { echo "pg_restore: error: could not execute query: foreign key fk_session_asset" >&2; exit 1; }; exit 0 ;;
esac'
}

@test "[pg18] 1.22 內建部署升到 1.23" {
  # the whole upgrade, with the old data read back by the old version, is the integration scenario
  pgx_pending lib/pgconvert.sh 2.3-integration
}

# ---------- the progress line of the long phases ----------

# slow_dump <seconds>: the export takes that long (a real sleep; the suite's fake sleep returns at once).
slow_dump() {
  fake sleep 'exec /bin/sleep "$@"'
  hook_before 'case " $* " in *" --entrypoint pg_dump "*) /bin/sleep '"$1"' ;; esac'
}

@test "[pg18] 第 8 步長階段每隔一段時間印一行已過時間與預估剩餘" {
  new_side
  slow_dump 3
  cx_pgc_plan
  CX_PGC_DBSIZE=2147483648 CX_PGC_MINUTES=3 CX_PGC_TICK=1
  run cx_pgc_run 8
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  n=$(grep -cE '^        [0-9]+s elapsed, about 3 to [0-9]+ more minutes$' <<<"$output")
  [ "$n" -ge 1 ] || { echo "$output"; return 1; }
  # the line comes while the export runs: before its own finished line
  tick=$(grep -n 'elapsed, about' <<<"$output" | head -n 1 | cut -d: -f1)
  done_line=$(grep -n '1/5' <<<"$output" | head -n 1 | cut -d: -f1)
  [ "$tick" -lt "$done_line" ] || { echo "$output"; return 1; }
}

@test "[pg18] 第 8 步資料大小未知時進度行只印已過時間" {
  new_side
  slow_dump 3
  cx_pgc_plan
  CX_PGC_DBSIZE=0 CX_PGC_MINUTES=0 CX_PGC_TICK=1
  run cx_pgc_run 8
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -qE '^        [0-9]+s elapsed$' <<<"$output" || { echo "$output"; return 1; }
}

@test "[pg18] 第 8 步各階段都比間隔短時不印進度行" {
  new_side
  cx_pgc_plan
  CX_PGC_DBSIZE=2147483648 CX_PGC_MINUTES=3 CX_PGC_TICK=60
  run cx_pgc_run 8
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output != *elapsed* ]] || { echo "$output"; return 1; }
}

@test "[pg18] 進度行超過預估範圍時改說還需要一些時間" {
  CX_PGC_DBSIZE=1 CX_PGC_MINUTES=1 CX_PGC_T0=$(($(cx_now) - 200))
  run cx_pgc_tick_line
  [[ $output == *"past the estimate"* ]] || { echo "$output"; return 1; }
  CX_PGC_T0=$(($(cx_now) - 50))
  run cx_pgc_tick_line
  [[ $output == *"50s elapsed, about 1 to 2 more minutes"* ]] || { echo "$output"; return 1; }
}

# ---------- the wrap-up of a failed phase (task 3.6) ----------

# rm_log: every rm the script runs is written down (and still runs).
rm_log() {
  fake rm 'printf "%s\n" "$*" >>"'"$BATS_TEST_TMPDIR"'/rm.log"; exec /usr/bin/rm "$@"'
  : >"$BATS_TEST_TMPDIR/rm.log"
}

# phase_breaks <phase>: only that phase's own command fails (the services' start still works, so
# the wrap-up can be watched).
phase_breaks() {
  case $1 in
    prepare) echo 1 >"$DB/encoding.rc" ;;
    dump) echo 1 >"$DB/pg_dump.rc" ;;
    init) hook_before 'case " $* " in *" run -d "*) exit 1 ;; esac' ;;
    restore) : >"$DB/restore.fail" ;;
    verify) printf 'off\n' >"$DB/new.checksums" ;;
    analyze) hook_before 'case " $* " in *" vacuumdb "*) exit 1 ;; esac' ;;
    done) hook_before 'case " $* " in *" stop -t 120 custodexa-pgconvert"*) exit 1 ;; esac' ;;
  esac
}

# phase_fail_case <phase>: the wrap-up in the order of the design, whichever phase failed.
phase_fail_case() {
  new_side
  rm_log
  phase_breaks "$1"
  cx_pgc_plan
  run cx_pgc_run 8
  [ "$status" -ne 0 ] || return 1
  [ "$(pgc_state last_upgrade.db_convert.phase)" = "$1" ] || { echo "phase: $(pgc_state last_upgrade.db_convert.phase)"; echo "$output"; return 1; }
  [ "$(pgc_state last_upgrade.db_convert.result)" = failed ] || return 1
  # the way back is on record before the old services start
  [ "$(cat "$DB/rec-at-start")" = restart_old ] || return 1
  [ "$(pgc_state last_upgrade.db_convert.reuse)" = invalid ] || return 1
  # the temporary container went, the scratch space went, the version did not change
  grep -q 'rm -f custodexa-pgconvert' "$FAKE_DOCKER_LOG" || return 1
  [ -z "$(ls -A "$ROOT/data/.pg-convert" 2>/dev/null)" ] || return 1
  [ "$(pgc_state current.version)" = 1.13.0 ] || return 1
  # the old data folder is never written, renamed or removed
  [ "$(cat "$ROOT/data/postgres/PG_VERSION")" = 16 ] || return 1
  ! grep -q "$ROOT/data/postgres\( \|$\)" "$BATS_TEST_TMPDIR/rm.log" || return 1
  [[ $output == *"works as before"* || $output == *"started again and works"* || $output == *"started again"* ]] || { echo "$output"; return 1; }
}

@test "[pg18] 第 8 步 prepare 失敗的收尾" { phase_fail_case prepare; }
@test "[pg18] 第 8 步 dump 失敗的收尾" { phase_fail_case dump; }
@test "[pg18] 第 8 步 init 失敗的收尾" { phase_fail_case init; }
@test "[pg18] 第 8 步 restore 失敗的收尾" { phase_fail_case restore; }
@test "[pg18] 第 8 步 verify 失敗的收尾" { phase_fail_case verify; }
@test "[pg18] 第 8 步 analyze 失敗的收尾" { phase_fail_case analyze; }
@test "[pg18] 第 8 步 done 失敗的收尾" { phase_fail_case done; }

@test "[pg18] 失敗收尾：恢復方向存不下來時不重新啟動舊版" {
  new_side
  : >"$DB/restore.fail"
  cx_state_save_orig() { :; }
  eval "$(declare -f cx_state_save | sed '1s/.*/cx_state_save_real ()/')"
  cx_state_save() {
    [ "$(cx_state_get last_upgrade.db_convert.recovery)" != restart_old ] || return 1
    cx_state_save_real "$@"
  }
  cx_pgc_plan
  run cx_pgc_run 8
  [ "$status" -ne 0 ] || return 1
  # nothing started, the screen says the old version is down and what to run
  [ ! -e "$DB/rec-at-start" ] || return 1
  ! grep -q ' start ' "$FAKE_DOCKER_LOG" || return 1
  [[ $output == *"did not start again"* && $output == *"does not handle this on its own"* ]] || { echo "$output"; return 1; }
  [[ $output == *"custodexa.sh start"* ]] || return 1
  [ "$(pgc_state current.version)" = 1.13.0 ] || return 1
}

# ---------- a run cut short in step 8 (task 3.6) ----------

# world <running|stopped> [started-at]: the application containers as the daemon reports them. The
# stop of step 5 was at 02:20:00; each container has an ID recorded then.
world() {
  PGR=$BATS_TEST_TMPDIR/pgr
  mkdir -p "$PGR"
  local st=${1:-stopped} started=${2:-2026-09-30T02:00:00.000000000Z} svc
  printf '%s\n' "$st" >"$PGR/backend"
  for svc in backend guacd frontend; do
    printf '%s%062d|%s|%s\n' "$(case $svc in backend) echo b0 ;; guacd) echo c0 ;; *) echo f0 ;; esac)" 7 "$started" "$([ "$st" = running ] && echo true || echo false)" >"$PGR/c.$svc"
  done
  hook_before 'case " $* " in
  *" container inspect "*custodexa-backend*)
    if [ "$(cat "'"$PGR"'/backend")" = running ]; then echo "true 0001-01-01T00:00:00Z"; else echo "false 2026-09-30T02:20:00.5Z"; fi; exit 0 ;;
  *" ps -aq "*) cat "'"$PGR"'/c.${*: -1}" 2>/dev/null | cut -d"|" -f1; exit 0 ;;
esac
if [ "$1" = inspect ] && [[ $* == *Running* ]]; then f="'"$PGR"'/by.${*: -1}"; [ -e "$f" ] || exit 1; cat "$f"; exit 0; fi'
  for svc in backend guacd frontend; do
    cp "$PGR/c.$svc" "$PGR/by.$(cut -d'|' -f1 "$PGR/c.$svc")"
  done
}

# interrupted <phase> [recovery]: state.json of an upgrade cut short in step 8 with the proof recorded.
interrupted() {
  local ph=${1:-restore} rec=${2:-} ids="" svc
  for svc in backend guacd frontend; do ids+="${ids:+ }$svc=$(cut -d'|' -f1 "$PGR/c.$svc")"; done
  cx_state_set last_upgrade.result in_progress
  cx_state_set last_upgrade.step 8
  cx_state_set last_upgrade.from 1.13.0
  cx_state_set last_upgrade.to 1.23.0
  cx_state_set last_upgrade.backup backups/custodexa-backup-1.13.0-20260930-021500.tar
  cx_state_set last_upgrade.backup_kind script
  cx_state_set last_upgrade.snapshot backups/x.before.txt
  cx_state_set last_upgrade.app_stop.at 2026-09-30T02:20:00+0000
  cx_state_set last_upgrade.app_stop.ids "$ids"
  cx_state_set last_upgrade.db_convert.phase "$ph"
  cx_state_set last_upgrade.db_convert.old_path "$ROOT/data/postgres"
  cx_state_set last_upgrade.db_convert.new_path "$ROOT/data/postgresql"
  [ -z "$rec" ] || cx_state_set last_upgrade.db_convert.recovery "$rec"
  cx_state_save "$ROOT/state.json"
  mkdir -p "$ROOT/data/postgresql/18/docker"
  printf '18\n' >"$ROOT/data/postgresql/18/docker/PG_VERSION"
  cx_snap_take "$ROOT/backups/x.before.txt" "$(cx_bk_env JWT_SECRET)"
  printf '0\n' >"$DB/connections"
}

@test "[pg18] 第 5 步記下停機時間與各應用容器 ID" {
  world stopped
  cx_up_services() { printf 'backend guacd frontend'; }
  cx_pgr_record_stop
  [ "$(pgc_state last_upgrade.app_stop.ids | wc -w)" -eq 3 ] || return 1
  [[ $(pgc_state last_upgrade.app_stop.ids) == "backend=b0"* ]] || return 1
  [[ $(pgc_state last_upgrade.app_stop.at) =~ ^20[0-9-]+T[0-9:]+[+-][0-9]{4}$ ]] || return 1
  # an ID that cannot be read leaves no record, so nothing can be proven from it later
  rm "$PGR/c.guacd"
  cx_pgr_record_stop
  [ -z "$(pgc_state last_upgrade.app_stop.at)" ] && [ -z "$(pgc_state last_upgrade.app_stop.ids)" ] || return 1
}

@test "[pg18] 轉換中斷後重跑" {
  world stopped
  interrupted restore
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
  [ "$CX_UP_RERUN" = 1 ] && [ "$CX_UP_RESUME" = resume ] || return 1
  grep -q 'It is confirmed that the application services' "$BATS_TEST_TMPDIR/out" || return 1
  grep -q 'custodexa-backup-1.13.0-20260930-021500.tar' "$BATS_TEST_TMPDIR/out" || return 1
  grep -q 'moved first' "$BATS_TEST_TMPDIR/out" || return 1
  # the half-converted folder is aside, never deleted; the old data is untouched
  [ ! -e "$ROOT/data/postgresql" ] || return 1
  [ -n "$(ls -d "$ROOT"/data/postgresql.partial-convert-* 2>/dev/null)" ] || return 1
  [ "$(cat "$ROOT/data/postgres/PG_VERSION")" = 16 ] || return 1
  # the next run takes the backup as it is on record and does not forget the stop
  cx_pgr_resume_load || return 1
  [ "$CX_UP_BACKUP" = backups/custodexa-backup-1.13.0-20260930-021500.tar ] || return 1
  [ "$CX_UP_SNAP" = "$ROOT/backups/x.before.txt" ] || return 1
  [ -n "$(pgc_state last_upgrade.app_stop.ids)" ] || return 1
}

@test "[pg18] 轉換中斷後應用曾被手動啟動" {
  world running
  interrupted restore
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RERUN" = 1 ] && [ "$CX_UP_RESUME" = fresh ] || return 1
  grep -q 'the services are running\|The services are running' "$BATS_TEST_TMPDIR/out" || return 1
  grep -q 'the whole upgrade runs again' "$BATS_TEST_TMPDIR/out" || return 1
  [ -n "$(ls -d "$ROOT"/data/postgresql.partial-convert-* 2>/dev/null)" ] || return 1
  # a fresh run keeps nothing of the earlier stop or backup
  cx_pgr_forget
  [ -z "$(cx_state_get last_upgrade.app_stop.ids)" ] && [ -z "$(cx_state_get last_upgrade.db_convert.phase)" ] || return 1
}

@test "[pg18] 轉換中斷後應用曾啟動但只更新既有列" {
  # the counts and migrations are the same as in the snapshot, the container started after the stop
  world stopped 2026-09-30T02:30:00.000000000Z
  interrupted restore
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RESUME" = fresh ] || return 1
  [ "$CX_PGR_WHY" = started ] || return 1
  grep -q 'cannot be confirmed' "$BATS_TEST_TMPDIR/out" || return 1
  grep -q 'is not used again' "$BATS_TEST_TMPDIR/out" || return 1
}

@test "[pg18] 轉換中斷後應用容器被移除重建" {
  world stopped
  interrupted restore
  # recreated containers have other IDs: the recorded ones cannot be inspected any more
  for svc in backend guacd frontend; do rm "$PGR/by.$(cut -d'|' -f1 "$PGR/c.$svc")"; done
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RESUME" = fresh ] && [ "$CX_PGR_WHY" = gone ] || return 1
  # and one that exists under the recorded ID but is another container is no proof either
  world stopped
  interrupted restore
  printf 'b0aa|2026-09-30T02:00:00Z|false\n' >"$PGR/by.b0$(printf '%062d' 7)"
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RESUME" = fresh ] || return 1
}

@test "[pg18] 轉換中斷後停機紀錄缺失或 docker inspect 失敗" {
  world stopped
  interrupted restore
  cx_state_unset last_upgrade.app_stop.at
  cx_state_unset last_upgrade.app_stop.ids
  cx_state_save "$ROOT/state.json"
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RESUME" = fresh ] && [ "$CX_PGR_WHY" = no_record ] || return 1
  # a container that is running now cannot be unbroken
  world stopped
  interrupted restore
  sed -i 's/|false$/|true/' "$PGR"/by.*
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RESUME" = fresh ] && [ "$CX_PGR_WHY" = running ] || return 1
}

@test "[pg18] 失敗收尾重新啟動舊版後、記為失敗前中斷" {
  # cut short after the way back was recorded: the services are down, the half folder is there
  world stopped
  interrupted verify restart_old
  new_side
  cx_up_pre_unfinished >"$BATS_TEST_TMPDIR/out" || return 1
  [ "$CX_UP_RERUN" = 1 ] && [ "$CX_UP_RESUME" = fresh ] || return 1
  grep -q 'Data written after that is not in the last backup' "$BATS_TEST_TMPDIR/out" || return 1
  # the wrap-up that was cut short is finished: the folder is kept as failed-convert, the old
  # services start
  [ -n "$(ls -d "$ROOT"/data/postgresql.failed-convert-* 2>/dev/null)" ] && [ ! -e "$ROOT/data/postgresql" ] || return 1
  grep -q ' start ' "$FAKE_DOCKER_LOG" || return 1
  grep -q 'rm -f custodexa-pgconvert' "$FAKE_DOCKER_LOG" || return 1
}

@test "[pg18] 改名上次沒有做完且無法判斷時中斷的升級不繼續" {
  world stopped
  interrupted restore
  cx_state_set dir_op.id failed-convert
  cx_state_set dir_op.from "$ROOT/data/gone-a"
  cx_state_set dir_op.to "$ROOT/data/gone-b"
  cx_state_set dir_op.phase intent
  cx_state_save "$ROOT/state.json"
  run cx_up_pre_unfinished
  [ "$status" -eq 3 ] || return 1
  [[ $output == *"could not be told"* || $output == *"cannot tell"* || $output == *"rename"* ]] || { echo "$output"; return 1; }
  ! grep -q ' start ' "$FAKE_DOCKER_LOG" || return 1
}

@test "[pg18] 其他指令遇到中斷在第 8 步的升級" {
  world stopped
  interrupted restore
  local cmd
  # start and stop refuse through the pending check; the others through cx_begin
  run cx_svc_pending
  [ "$status" -ne 0 ] || return 1
  for cmd in "" backup; do
    if [ -n "$cmd" ]; then
      run cx_begin "$cmd"
      [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    fi
    [[ $output == *'interrupted at step 8, "convert the database"'* ]] || { echo "$output"; return 1; }
    [[ $output == *"Nothing was changed"* ]] || return 1
    [[ $output == *"upgrade 1.23.0"* && $output == *"partial-convert-<time>"* && $output == *"custodexa.sh status"* ]] || return 1
  done
  [ "$(pgc_state last_upgrade.result)" = in_progress ] || return 1
}

@test "[pg18] 以舊的自備備份重跑失敗後的升級" {
  # after a failed conversion the old services run again: an own backup given on the command line
  # needs the services stopped, and is checked against the stop of THIS run
  world running
  CX_BACKUP_REF=old CX_BACKUP_TIME="2026-09-30 02:10" CX_BACKUP_RESTORE=x
  run cx_br_noninteractive
  [ "$status" -eq 3 ] || return 1
  # stopped by hand later than that backup: refused as taken before the stop
  world stopped
  run cx_br_noninteractive
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
}

@test "[pg18] 失敗後重跑從第 1 步全新開始" {
  # a conversion that failed is recorded: the next upgrade is allowed, any other step 8 failure is not
  cx_state_set last_upgrade.result failed
  cx_state_set last_upgrade.step 8
  cx_state_set last_upgrade.db_convert.result failed
  cx_state_set last_upgrade.backup_id 20260930-021500
  cx_state_set last_upgrade.app_stop.ids "backend=aaaaaaaaaaaa"
  cx_state_save "$ROOT/state.json"
  cx_up_pre_unfinished || return 1
  [ "$CX_UP_RESUME" = none ] || return 1
  # starting it forgets the old run's backup and stop; the new run records its own
  CX_UP_RESUME=none
  cx_pgr_forget
  [ -z "$(cx_state_get last_upgrade.app_stop.ids)" ] || return 1
  cx_state_unset last_upgrade.db_convert.result
  cx_state_save "$ROOT/state.json"
  run cx_up_pre_unfinished
  [ "$status" -eq 3 ] || return 1
  cx_state_set last_upgrade.db_convert.result failed
  cx_state_set last_upgrade.step 9
  cx_state_save "$ROOT/state.json"
  run cx_up_pre_unfinished
  [ "$status" -eq 3 ] || return 1
}


# ---------- the preview and the checks before it (task 3.4) ----------

# preview_ready: the variables the body of the preview reads.
preview_ready() {
  CX_UP_PRE_BACKEND=running CX_UP_PRE_ACTIVE=2 CX_UP_PRE_PENDING=0 CX_UP_PRE_OLD_MISSING=0
  CX_UP_PRE_EXTERNAL_DB=0 CX_UP_OWN_ONLY=0 CX_TRUST_SIG=ok CX_TRUST_PROV=ok CX_BK_NEED=1000 CX_BK_FREE=2000
  CX_BACKUP_REF=""
  cx_up_conv_preview() { :; }
  cx_bk_minutes() { printf 5; }
  cx_br_flags_given() { return 1; }
}

@test "[pg18] 預覽的會做的事把資料庫轉換排第 3 項" {
  preview_ready
  cx_pgc_plan
  cx_pgc_space || return 1
  run cx_up_preview_body
  [[ $output == *$'  1. Wait until all audit records'* ]] || return 1
  line() { printf '%s\n' "$output" | grep -n "$1" | head -n 1 | cut -d: -f1; }
  l2=$(line '^  2\. Full backup'); l3=$(line '^  3\. Convert the database from PostgreSQL 16 to 18')
  l4=$(line '^  4\. Switch to 1.23.0'); l5=$(line '^  5\. Check the version')
  lc=$(line '^Database conversion: PostgreSQL 16 -> 18')
  [ -n "$l2" ] && [ -n "$l3" ] && [ -n "$l4" ] && [ -n "$l5" ] && [ -n "$lc" ] || { echo "$output"; return 1; }
  [ "$l2" -lt "$l3" ] && [ "$l3" -lt "$l4" ] && [ "$l4" -lt "$l5" ] && [ "$l5" -lt "$lc" ] || { echo "$output"; return 1; }
  [[ $output != *"  3. Switch to"* ]] || return 1
  # the downtime counts the conversion
  [[ $output == *"minutes of downtime"* ]] || return 1
  # no conversion: the list is the one of before
  CX_PGC_ACTIVE=0
  run cx_up_preview_body
  [[ $output == *"  3. Switch to 1.23.0 and start it"* && $output == *"  4. Check the version"* ]] || return 1
  [[ $output != *"Convert the database from"* && $output != *"  5. "* ]] || return 1
}

@test "[pg18] 授權掃描涵蓋物件、欄位、預設權限與資料庫層級" {
  local sql
  sql=$(cx_pgc_scan_sql)
  # the sources pg_restore -l lists as ACL entries
  for want in relacl attacl nspacl proacl typacl defaclacl lomacl srvacl datacl; do
    [[ $sql == *"aclexplode($want)"* || $sql == *"aclexplode(a.$want)"* ]] || { echo "missing $want"; return 1; }
  done
  # the criterion of the restore: the application account, PUBLIC and pg_ roles are not findings
  [[ $sql == *"x.g <> 0"* && $sql == *"NOT LIKE 'pg\\_%'"* && $sql == *"rolname <> '$CX_BK_DBUSER'"* ]] || return 1
  # the system schemas are not part of a dump
  [[ $sql == *"NOT IN ('pg_catalog', 'information_schema')"* ]] || return 1
  # a finding of any source is refused
  printf '%s\n' 'role|report_reader' >"$DB/grants"
  cx_pgc_plan
  run cx_pgc_precheck
  [ "$status" -eq 3 ] && [[ $output == *"report_reader"* ]] || return 1
}

@test "[pg18] 失敗產物被執行中容器掛載時不提供清除" {
  cx_pgc_plan
  mkdir -p "$ROOT/data/postgresql.failed-convert-1" "$ROOT/data/postgresql.partial-convert-2"
  hook_before 'case " $* " in
  *" ps -q"*) echo cid1; exit 0 ;;
  *" inspect -f "*cid1*) printf "%s\n" "'"$ROOT"'/data/postgresql.failed-convert-1/18/docker" "/etc/localtime"; exit 0 ;;
esac'
  cx_pgc_artifacts
  [ "${#CX_PGC_ART[@]}" -eq 1 ] || return 1
  [[ ${CX_PGC_ART[0]} == "$ROOT/data/postgresql.partial-convert-2|"* ]] || return 1
  # and the removal itself refuses it
  ! cx_pgc_art_clear "$ROOT/data/postgresql.failed-convert-1" || return 1
  [ -d "$ROOT/data/postgresql.failed-convert-1" ] || return 1
}

# before_mark: the state of the deployment a refusal is compared with (after the test set its host up).
before_mark() { BEFORE_STATE=$(sha256sum <"$ROOT/state.json") BEFORE_TREE=$(tree_of "$ROOT/data"); }

# nothing_changed: a refusal before the stop changed nothing: no docker call that stops, starts,
# removes, creates or restarts anything, no rename, the state file and the data folders as they were.
nothing_changed() {
  local line
  while IFS= read -r line; do
    line=${line%% psql *}
    if [[ $line =~ [[:space:]](stop|start|restart|kill|rm|down|create|rename|pause|unpause|run|up|cp|build|pull)([[:space:]]|$) ]]; then
      echo "a changing call: $line"
      return 1
    fi
  done <"$FAKE_DOCKER_LOG"
  [ "$(sha256sum <"$ROOT/state.json")" = "$BEFORE_STATE" ] || { echo "state.json changed"; return 1; }
  [ "$(tree_of "$ROOT/data")" = "$BEFORE_TREE" ] || { echo "the data folders changed"; return 1; }
  [ ! -e "$ROOT/data/.pg-convert" ] || return 1
}

@test "[pg18] 預覽列出轉換" {
  cx_pgc_plan
  [ "$CX_PGC_ACTIVE" = 1 ] && [ "$CX_PGC_FROM" = 16 ] && [ "$CX_PGC_TO" = 18 ] || return 1
  cx_pgc_space || return 1
  run cx_pgc_preview
  [[ $output == *"Database conversion: PostgreSQL 16 -> 18"* ]] || return 1
  [[ $output == *"kept as it is in $ROOT/data/postgres,"* ]] || return 1
  [[ $output == *"New data"*"$ROOT/data/postgresql"* ]] || return 1
  [[ $output == *"needs"* && $output == *"minutes"* ]] || return 1
  [[ $output == *"works as before"* && $output == *"rollback"* && $output == *"restore"* ]] || return 1
}

@test "[pg18] 外接資料庫部署升級" {
  CX_OVERLAYS="external-database"
  cx_pgc_plan
  [ "$CX_PGC_ACTIVE" = 0 ] || return 1
  cx_pgc_precheck || return 1
  cx_pgc_space || return 1
  [ -z "$(cx_pgc_preview)" ] || return 1
  run cx_pgc_run 8
  [ "$status" -eq 0 ] && [[ $output == *"[SKIP]"* ]] || return 1
}

@test "[pg18] 已是目標大版本" {
  pgc_manifest "$ROOT/releases/1.13.0" with 18
  cx_pgc_plan
  [ "$CX_PGC_ACTIVE" = 0 ] || return 1
  run cx_pgc_run 8
  [[ $output == *"[SKIP]"* ]] || return 1
  [ ! -s "$FAKE_DOCKER_LOG" ] || ! grep -q 'pg_dump' "$FAKE_DOCKER_LOG" || return 1
}

@test "[pg18] 資料庫有額外擴充" {
  printf '%s\n' 'ext|pgcrypto' 'ts|archive_ts' 'role|report_reader' >"$DB/grants"
  cx_pgc_plan
  before_mark
  run cx_pgc_precheck
  [ "$status" -eq 3 ] || return 1
  [[ $output == *"pgcrypto"* && $output == *"archive_ts"* && $output == *"report_reader"* ]] || return 1
  [[ $output == *"No service was stopped"* ]] || return 1
  nothing_changed || return 1
  : >"$DB/grants"
  cx_pgc_precheck || return 1
}

@test "[pg18] 新資料目錄另掛小磁碟" {
  pgc_free pg 100
  cx_pgc_plan
  before_mark
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"$ROOT/data/postgresql"* && $output == *"short"* && $output == *"new database"* ]] || return 1
  [[ $output == *"nothing was changed"* ]] || return 1
  nothing_changed || return 1
}

@test "[pg18] 映像儲存區空間不足" {
  pgc_free docker 100
  cx_pgc_plan
  before_mark
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"/var/lib/docker"* && $output == *"new images"* && $output == *"short"* ]] || return 1
  nothing_changed || return 1
}

@test "[pg18] 映像儲存區位置取不到" {
  cx_pgc_plan
  rm -f "$FAKE_DOCKER_REPLAY/info_--format_{{.DockerRootDir}}.out"
  before_mark
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"Cannot tell whether the space is enough"* && $output == *"Docker image storage"* ]] || return 1
  printf '/var/lib/docker\n' >"$FAKE_DOCKER_REPLAY/info_--format_{{.DockerRootDir}}.out"
  pgc_free docker none
  run cx_pgc_space
  [ "$status" -eq 1 ] && [[ $output == *"Docker image storage"* ]] || return 1
  nothing_changed || return 1
}

@test "[pg18] 空間不足" {
  # the four places on one file system are one row; on several, one row each
  cx_pgc_plan
  host_free / 1000
  pgc_free docker 900000000
  CX_BK_NEED=$((3 * CX_GIB))
  before_mark
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [ "$(printf '%s\n' "$output" | grep -c '^ *needs')" -eq 2 ] || { echo "$output"; return 1; }
  [[ $output == *"the backup and the new database are both here"* ]] || { echo "$output"; return 1; }
  nothing_changed || return 1
}

@test "[pg18] 帶自備備份升級時仍計入資料庫轉換空間" {
  CX_BACKUP_REF=x
  cx_pgc_plan
  CX_BK_NEED=$((300 * CX_GIB))
  pgc_free pg 100
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"new database"* && $output != *"backup ("* ]] || return 1
}

@test "[pg18] 新叢集空間為資料庫大小加 2 GiB（實測 1.3 GB 資料時 WAL 約 1.1 GiB，1 GiB 不夠）" {
  CX_BACKUP_REF=x
  cx_pgc_plan
  pgc_free pg 100
  cx_pgc_space >"$BATS_TEST_TMPDIR/out" 2>&1 || true
  local m
  m=$(cx_mount_of "$ROOT/data/postgresql")
  [ "${CX_PGC_DBSIZE:-0}" -gt 0 ] || return 1
  # the new cluster's file system: the size plus the margin
  [ "${CX_PGC_NEED[$m]}" -eq $((CX_PGC_DBSIZE + 2 * CX_GIB)) ] || { echo "need=${CX_PGC_NEED[$m]} size=$CX_PGC_DBSIZE"; return 1; }
  [ "$CX_PGC_NEW_MARGIN" -ge $((2 * CX_GIB)) ] || return 1
}

@test "[pg18] 失敗產物佔滿空間後清除再重跑" {
  cx_pgc_plan
  mkdir -p "$ROOT/data/postgresql.failed-convert-1/18/docker"
  printf 'x\n' >"$ROOT/data/postgresql.failed-convert-1/18/docker/PG_VERSION"
  pgc_free pg 100
  cx_up_interactive() { return 0; }
  eval "$(declare -f cx_pgc_art_clear | sed '1s/.*/cx_pgc_art_clear_orig ()/')"
  cx_pgc_art_clear() { cx_pgc_art_clear_orig "$@" && pgc_free pg 900000000; }
  cx_pgc_space <<<y >"$BATS_TEST_TMPDIR/out" || return 1
  [ ! -e "$ROOT/data/postgresql.failed-convert-1" ] || return 1
  [ -e "$ROOT/data/postgres/PG_VERSION" ] || return 1
  grep -q 'Removed' "$BATS_TEST_TMPDIR/out" || return 1
  [ "$(jq -r '."dir_op.id"' "$ROOT/state.json")" = removing ] || return 1
}

@test "[pg18] 非互動不清除失敗產物" {
  cx_pgc_plan
  mkdir -p "$ROOT/data/postgresql.failed-convert-1" "$ROOT/data/postgresql.partial-convert-2"
  pgc_free pg 100
  cx_up_interactive() { return 1; }
  run cx_pgc_space
  [ "$status" -eq 1 ] || return 1
  [[ $output == *"postgresql.failed-convert-1"* && $output == *"postgresql.partial-convert-2"* ]] || return 1
  [[ $output == *"same upgrade command"* ]] || return 1
  [ -d "$ROOT/data/postgresql.failed-convert-1" ] && [ -d "$ROOT/data/postgresql.partial-convert-2" ] || return 1
}

@test "[pg18] 第 8 步完成時新舊資料等價" {
  new_side
  cx_pgc_plan
  cx_pgc_dbsize
  run cx_pgc_run 8
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(pgc_state last_upgrade.db_convert.result)" = done ] && [ "$(pgc_state last_upgrade.db_convert.phase)" = done ] || return 1
  [ "$(pgc_state last_upgrade.db_convert.checksums)" = on ] || return 1
  # the phases, in order, with the new cluster's parameters from the old database
  grep -n 'pg_dump\|--network none.*custodexa-pgconvert\|POSTGRES_INITDB_ARGS\|pg_restore --single-transaction --exit-on-error\|vacuumdb --all --analyze-in-stages' "$FAKE_DOCKER_LOG" | cut -d: -f1 | sort -nc || return 1
  grep -q 'POSTGRES_INITDB_ARGS=--encoding=UTF8 --lc-collate=en_US.utf8 --lc-ctype=en_US.utf8' "$FAKE_DOCKER_LOG" || return 1
  grep -q -- '--network none' "$FAKE_DOCKER_LOG" || return 1
  # nothing names the old data folder, and no password is in a command or the log
  ! grep -q "$ROOT/data/postgres[: ]" "$FAKE_DOCKER_LOG" || return 1
  ! grep -q "$BK_DBPW" "$FAKE_DOCKER_LOG" "$CX_LOG_FILE" || return 1
  # the password reaches pg_dump and the new cluster by environment, read from the .env key DB_PASSWORD
  [ "$(cat "$DB/dump-pw")" = "$BK_DBPW" ] && [ "$(cat "$DB/init-pw")" = "$BK_DBPW" ] || return 1
  [ -z "$(ls -A "$ROOT/data/.pg-convert")" ] || return 1
  [ "$(cat "$ROOT/data/postgres/PG_VERSION")" = 16 ] || return 1
}

@test "[pg18] 新叢集未開啟 data checksums" {
  new_side
  printf 'off\n' >"$DB/new.checksums"
  cx_pgc_plan
  cx_pgc_run 8 >"$BATS_TEST_TMPDIR/out" 2>&1 && return 1
  [ "$(pgc_state last_upgrade.db_convert.result)" = failed ] || return 1
  [ "$(pgc_state last_upgrade.db_convert.phase)" = verify ] || return 1
  grep -q 'data_checksums is off' "$CX_LOG_FILE" || return 1
  # the way back was on record before the old services started, and the new folder is kept
  [ "$(cat "$DB/rec-at-start")" = restart_old ] || return 1
  [ -d "$ROOT/data/postgresql.failed-convert-$CX_PGC_TS" ] && [ ! -e "$ROOT/data/postgresql" ] || return 1
  [ "$(pgc_state last_upgrade.db_convert.reuse)" = invalid ] || return 1
  [ "$(cat "$ROOT/data/postgres/PG_VERSION")" = 16 ] || return 1
}

@test "[pg18] 匯入失敗" {
  new_side
  : >"$DB/restore.fail"
  cx_pgc_plan
  cx_pgc_run 8 >"$BATS_TEST_TMPDIR/out" 2>&1 && return 1
  [ "$(pgc_state last_upgrade.db_convert.phase)" = restore ] && [ "$(pgc_state last_upgrade.db_convert.result)" = failed ] || return 1
  grep -q 'foreign key fk_session_asset' "$BATS_TEST_TMPDIR/out" || return 1
  grep -q 'failed at "import"' "$BATS_TEST_TMPDIR/out" || return 1
  [ "$(pgc_state current.version)" = 1.13.0 ] || return 1
  [ -d "$ROOT/data/postgresql.failed-convert-$CX_PGC_TS" ] || return 1
}
