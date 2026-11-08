#!/usr/bin/env bats
# Screen snapshots of the database conversion on the upgrade side (task 3.11): P01-P07, P18, P21.
# Each screen is printed by the real function on backup_host's deployment with the fake docker,
# in three languages, and compared with the reviewed text.

load helper
load install_host
load backup_host
load upgrade_host
load pgconvert_host

setup() {
  backup_host ui
  load_lib
  for f in service_controls upgrade_query upgrade_convert upgrade_preflight upgrade_output health stop_check upgrade_steps rollback_check rollback_output; do
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
  CX_UP_BACKUP=backups/custodexa-backup-1.13.0-20261120-021502.tar CX_UP_BACKUP_KIND=script CX_UP_BACKUP_DIR=$ROOT/backups
  CX_READY_TRIES=3
  declare -gA CX_IMG_REF=([postgres]=docker.io/library/postgres@sha256:aaaa)
  mkdir -p "$ROOT/releases/1.23.0" "$ROOT/backups"
  jq '.version = "1.23.0" | .images.postgres.tag = "18.6-alpine3.24"
    | .bundled_db = {major: 18, data_dir: "postgresql", pgdata: "18/docker"}
    | .compose_layout = "profiles"
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
  *" --entrypoint pg_dump "*) [ -e "'"$DB"'/dump.fail" ] && exit 1 ;;
  *" run -d "*) mkdir -p "'"$ROOT"'/data/postgresql/18/docker"; echo 18 >"'"$ROOT"'/data/postgresql/18/docker/PG_VERSION"; exit 0 ;;
  *" start "*) jq -r ".\"last_upgrade.db_convert.recovery\" // \"\"" "'"$ROOT"'/state.json" >>"'"$DB"'/rec-at-start"; exit 0 ;;
  *" exec custodexa-pgconvert psql "*"SHOW data_checksums"*) cat "'"$DB"'/new.checksums"; exit 0 ;;
  *" exec custodexa-pgconvert psql "*) cat "'"$DB"'/new.facts"; exit 0 ;;
  *" exec custodexa-pgconvert pg_restore "*) [ -e "'"$DB"'/restore.fail" ] && { echo "pg_restore: error: could not execute query: foreign key fk_session_asset" >&2; exit 1; }; exit 0 ;;
esac'
}

preview_ready() {
  CX_UP_PRE_BACKEND=running CX_UP_PRE_ACTIVE=2 CX_UP_PRE_PENDING=0 CX_UP_PRE_OLD_MISSING=0
  CX_UP_PRE_EXTERNAL_DB=0 CX_UP_OWN_ONLY=0 CX_TRUST_SIG=ok CX_TRUST_PROV=ok CX_BK_NEED=1000 CX_BK_FREE=2000
  CX_BACKUP_REF=""
  cx_bk_minutes() { printf 5; }
  cx_br_flags_given() { return 1; }
}

# The mounts as the canvas names them: the deployment on /opt, the Docker image storage on /var,
# the data folder on /data when a test puts it on a file system of its own.
screen_mounts() {
  host_free / 900000000
  host_free "$ROOT" 221249536 /opt
  host_free /var/lib/docker 62914560 /var
}

p01() {
  cx_pgc_plan
  cx_pgc_space || return $?
  cx_up_preview_head
  cx_up_preview_body
  printf '\n%s\n' "$(cx_msg up_confirm)"
}

@test "P01 preview" {
  preview_ready
  CX_BK_NEED=$((7 * CX_GIB / 2)) CX_BK_FREE=$((211 * CX_GIB))
  screen_mounts
  printf 'COMPOSE_FILE=current/compose.yml\n' >>"$ROOT/.env"
  pg_shot P01 p01
}

@test "P02 space refusals" {
  # A: the backup, the images and the new database on three file systems
  screen_mounts
  host_free "$ROOT/data" 1048576 /data
  cx_pgc_plan
  CX_BK_NEED=$((7 * CX_GIB / 2))
  pg_shot P02a cx_pgc_space
  # B: backup and new database on one file system
  screen_mounts
  host_free "$ROOT" 4928307 /opt
  host_free "$ROOT/data" 4928307 /opt
  pg_shot P02b cx_pgc_space
  # C: only the image storage is short
  screen_mounts
  host_free "$ROOT/data" 900000000 /data
  host_free /var/lib/docker 2202009 /var
  pg_shot P02c cx_pgc_space
  # D: the image storage cannot be placed
  screen_mounts
  rm -f "$FAKE_DOCKER_REPLAY/info_--format_{{.DockerRootDir}}.out"
  pg_shot P02d cx_pgc_space
}

@test "P02 e: leftovers of a failed conversion, not asked" {
  cx_pgc_plan
  mkdir -p "$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker" "$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker"
  printf '18\n' >"$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker/PG_VERSION"
  printf '18\n' >"$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker/PG_VERSION"
  screen_mounts
  host_free "$ROOT/data" 1048576 /data
  cx_bk_du() { case $1 in *failed-convert*) printf %s $((32 * CX_GIB / 10)) ;; *) printf %s $((131 * CX_GIB / 10)) ;; esac; }
  cx_pgc_art_offer() { return 1; }
  pg_shot P02e cx_pgc_space
}

@test "P03 data the conversion cannot carry" {
  printf '%s\n' 'ext|pg_stat_statements' 'ext|pgcrypto' 'ts|archive_ts' 'role|report_reader' >"$DB/grants"
  cx_pgc_plan
  pg_shot P03 cx_pgc_precheck
}

@test "P04 progress of step 8" {
  new_side
  cx_pgc_plan
  cx_pgc_dbsize
  pg_shot P04b cx_pgc_run 8
  CX_OVERLAYS="external-database"
  cx_pgc_plan
  pg_shot P04c cx_pgc_run 8
}

@test "P05 step 8 fails" {
  new_side
  : >"$DB/restore.fail"
  cx_pgc_plan
  pg_shot P05a cx_pgc_run 8
}

@test "P05 b: the old version did not start again" {
  new_side
  : >"$DB/dump.fail"
  cx_state_save_orig() { :; }
  eval "$(declare -f cx_state_save | sed '1s/.*/cx_state_save_real ()/')"
  cx_state_save() {
    [ "$(cx_state_get last_upgrade.db_convert.recovery)" != restart_old ] || return 1
    cx_state_save_real "$@"
  }
  cx_pgc_plan
  pg_shot P05b cx_pgc_run 8
}

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

@test "P06 interrupted conversion" {
  # A: the services are stopped and the proof holds
  world stopped
  interrupted restore
  pg_shot P06a cx_up_pre_unfinished
  # B: the backend is running
  world running
  interrupted restore
  pg_shot P06b cx_up_pre_unfinished
  # B2: stopped but the proof cannot be made
  world stopped 2026-09-30T02:30:00.000000000Z
  interrupted restore
  pg_shot P06b2 cx_up_pre_unfinished
}

@test "P06 c: other commands" {
  world stopped
  interrupted restore
  pg_shot P06c cx_begin backup
}

@test "P06 d: the wrap-up after a failure was cut short" {
  world stopped
  interrupted restore restart_old
  pg_shot P06d cx_up_pre_unfinished
}

@test "P07 the closing screen: database row and section" {
  declare -gA CX_IMG_REF=([postgres]=docker.io/library/postgres@sha256:aaaa)
  cx_pgc_plan
  cx_state_set last_upgrade.db_convert.result "done"
  cx_state_set last_upgrade.from 1.13.0
  mkdir -p "$ROOT/data/postgres" "$ROOT/data/postgresql/18/docker"
  printf '18\n' >"$ROOT/data/postgresql/18/docker/PG_VERSION"
  printf '180006\n' >"$DB/server_version_num"
  cx_bk_du() { printf %s $((174 * CX_GIB / 10)); }
  printf 'PUBLIC_BASE_URL=https://10.0.0.12\n' >>"$ROOT/.env"
  CX_DIR=$ROOT/releases/1.23.0 CX_UP_PRE_EXTERNAL_DB=0
  CX_BK_KEK=ui CX_IR_SKIPPED=0 CX_IR_REMOVED=0 CX_IR_FAILED=()
  CX_UP_BACKUP=backups/custodexa-backup-1.13.0-20261120-021502.tar CX_UP_BACKUP_KIND=script
  cx_rb_hint_ok() { return 0; }
  p07() {
    CX_PC_ROWS=() CX_PC_FAIL=0
    cx_pc_row OK pc_version 1.23.0
    cx_pc_row OK pc_same_data 42 18,305 1,204,551 1,204,540 11
    cx_pc_dbmajor
    cx_pc_row OK pc_keys_same
    cx_pc_row OK pc_lock_held
    cx_up_done
  }
  pg_shot P07 p07
}

@test "P18 after the switch" {
  declare -gA CX_IMG_REF=([postgres]=docker.io/library/postgres@sha256:aaaa)
  cx_pgc_plan
  cx_state_set last_upgrade.db_convert.result "done"
  cx_state_set last_upgrade.from 1.13.0
  cx_state_set last_upgrade.new_started_at 2026-11-20T02:40:00+0800
  mkdir -p "$ROOT/data/postgres"
  CX_UP_BACKUP=backups/custodexa-backup-1.22.0-20261120-021502.tar
  CX_LOG_FILE=$ROOT/logs/upgrade-20261120-021502.log
  pg_shot P18a cx_up_fail_switched up_fail_ready 180
  rm -rf "$ROOT/data/postgres"
  pg_shot P18b cx_up_fail_switched up_fail_ready 180
}

# p21a: the question on a terminal; the typed answer is shown where a terminal shows it, at the end
# of the question (the answer is read from the here-string, which echoes nothing).
p21a() {
  cx_up_interactive() { return 0; }
  { cx_pgc_space <<<"${P21_ANSWER-n}"; } | sed -E "s/(\[y\/N\]) ?/\1 ${P21_ANSWER:-}\n/"
}
p21_enough() { pgc_free pg 100; p21a; }
p21_ni() { cx_up_interactive() { return 1; }; cx_pgc_space; }
@test "P21 leftovers of a failed conversion" {
  cx_pgc_plan
  mkdir -p "$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker" "$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker"
  printf '18\n' >"$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker/PG_VERSION"
  printf '18\n' >"$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker/PG_VERSION"
  pgc_free pg 100
  P21_ANSWER= pg_shot P21c p21a
  pg_shot P21d p21_ni
  pgc_free pg 100
  # removing them is not enough: the real removal runs, so the refusal no longer lists them
  P21_ANSWER=y pg_shot P21b p21a
  [ ! -e "$ROOT/data/postgresql.failed-convert-20261120-023318" ]
  mkdir -p "$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker" "$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker"
  printf '18\n' >"$ROOT/data/postgresql.failed-convert-20261120-023318/18/docker/PG_VERSION"
  printf '18\n' >"$ROOT/data/postgresql.partial-convert-20261120-031044/18/docker/PG_VERSION"
  # removing them is enough: the space is counted again
  cx_pgc_art_clear() { pgc_free pg 900000000; }
  P21_ANSWER=y pg_shot P21e p21_enough
}
