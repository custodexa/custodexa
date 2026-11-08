# shellcheck shell=bash
# about: a published release (PostgreSQL 16, real data incl. a table over 1 GB) upgraded by script to the working tree (PostgreSQL 18.6): at the end of step 8 and before step 10 every table, every sequence and schema_migrations are equal on both sides, data_checksums is on, the old data folder is untouched (PG_VERSION 16, no mv/rm/mount of it in the script log or the docker calls); a failing restore leaves the old version running and a retry backs up again and carries a row written meanwhile; a kill during the failure wrap-up, a kill during the restore (apps never started / started and a row added / started and a row updated) and a lack of room each end as the design says
# needs: package local-versions published
# images:
# Run with: CX_IT_PUBLISHED_VERSION=1.17.9 CX_IT_LOCAL_VERSIONS=1.23.90 (the working tree's version, above the source).
# CX_IT_PG_BULK_ROWS sets the rows of the big table (default 1100000 rows of 1 KiB, about 1.1 GB).

# The source is the published release the run mounts (CX_IT_PUBLISHED_VERSION, default 1.15.2); use
# 1.17.9, the oldest source the upgrade accepts: the script of a release before 1.17 cannot place the
# same release folder again after a failed upgrade, so a retry from it is refused whatever the target.
readonly PC_OLD=${CX_IT_PUBLISHED_VERSION:-1.15.2} PC_NEW=${CX_IT_LOCAL_VERSIONS:-1.23.90}
readonly PC_BULK_ROWS=${CX_IT_PG_BULK_ROWS:-1100000}

pc_flat() { tr '\n' ' ' <<<"$LV_OUT" | tr -s ' '; }

# pc_install: the published release installed from its own package and offline bundle, then a user
# and an asset through its API and the big table.
pc_install() {
  local bundle
  it_step "install the published $PC_OLD (PostgreSQL 16)"
  it_check "the published files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  bundle=$(find /published -maxdepth 1 -name "custodexa-images-$PC_OLD-*.tar")
  mkdir -p /opt
  tar -xzf "/published/custodexa-$PC_OLD.tar.gz" -C /opt
  ex_preset "$LV_ROOT" KEK_PROVIDER=env
  lv_cx install install --images "$bundle"
  it_same "install $PC_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$PC_OLD"
  it_same "the data folder is PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  LV_TOKEN=""
}

pc_seed() {
  local tag=${1:-seed}
  it_step "$tag: users, an asset, audit rows (the API writes them) and a table over 1 GB"
  lv_api POST /users "$(jq -cn --arg u "it-before-$tag" '{username: $u, password: "It-user-pass-0001",
    email: ($u + "@example.test"), full_name: "Upgrade test user"}')" >/dev/null
  lv_api POST /assets "$(jq -cn --arg n "it-before-$tag" '{name: $n, protocol: "ssh", host: "192.0.2.20", port: 22,
    description: "upgrade test asset", tags: "it,upgrade"}')" >/dev/null
  lv_sql "CREATE TABLE it_bulk AS SELECT g AS id, repeat(md5(g::text), 32) AS pad FROM generate_series(1, $PC_BULK_ROWS) g" >/dev/null
  lv_sql "ALTER TABLE it_bulk ADD PRIMARY KEY (id)" >/dev/null
  lv_sql "CREATE SEQUENCE it_seq" >/dev/null
  lv_sql "SELECT setval('it_seq', 4242)" >/dev/null
  it_check "it_bulk is over 1 GB (or the rows were set lower on purpose)" \
    test "$(lv_sql "SELECT pg_total_relation_size('it_bulk') > 1000000000 OR $PC_BULK_ROWS < 1100000")" = t
}

# pc_hash <sql runner...>: one line per public table "<table> <count> <md5 of all rows>", then every
# sequence's last value. The runner is a command that takes the SQL as its last argument.
pc_hash() {
  local t
  while read -r t; do
    [ -n "$t" ] || continue
    printf '%s %s\n' "$t" "$("$@" "SELECT count(*) || ' ' || coalesce(md5(string_agg(x::text, '' ORDER BY x::text)), '-') FROM \"$t\" x" </dev/null)"
  done < <("$@" "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")
  "$@" "SELECT string_agg(sequencename || '=' || coalesce(last_value::text, 'null'), ',' ORDER BY sequencename) FROM pg_sequences"
}

pc_old_sql() { lv_sql "$1"; }

# pc_new_start / pc_new_sql / pc_new_stop: the new cluster (step 8's result) read by a server of the
# target's own image on that folder, with no network, while the upgrade waits before step 10.
pc_new_start() {
  local ref
  ref=$(jq -r '"\(.images.postgres.ref):\(.images.postgres.tag)"' "/it-run/pkg-$PC_NEW/MANIFEST.json")
  docker run -d --name it-pgconvert-read --network none -v "$LV_ROOT/data/postgresql:/var/lib/postgresql" "$ref" >/dev/null
  lv_until "the new cluster answers" docker exec it-pgconvert-read pg_isready -q
}
pc_new_sql() {
  docker exec -i it-pgconvert-read psql -X -v ON_ERROR_STOP=1 -At -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "$1"
}
pc_new_stop() { docker rm -f it-pgconvert-read >/dev/null; }

# pc_upgrade_bg <label>: the upgrade in the background with the given LV_INJECT.
pc_upgrade_bg() {
  : >"$IT_WORK/docker-calls.log"
  lv_bg "$1" upgrade "$(it_package_file "$PC_NEW")" --images "$(it_bundle_file "$PC_NEW")" --yes
}

# pc_wait_end <label>: the background run ends; LV_RC, LV_OUT.
pc_wait_end() {
  LV_RC=0
  wait "$LV_PID" || LV_RC=$?
  LV_OUT=$(cat "$IT_WORK/$1.out")
  printf '%s\n' "$LV_OUT" | sed "s/^/   $1> /"
  printf '   %s> (exit %s)\n' "$1" "$LV_RC"
}

# pc_kill <label>: SIGKILL to the script and to the docker shim it was waiting in, as a crash does.
pc_kill() {
  kill -KILL "$LV_PID" 2>/dev/null || true
  pkill -KILL -f "$IT_WORK/lvshim/docker" 2>/dev/null || true
  wait "$LV_PID" 2>/dev/null || true
  rm -f "$IT_WORK/lv-hold"
  it_say "   $1: the script was killed with SIGKILL"
}

# pc_kill_stray: SIGKILL any custodexa.sh run left in the background, with the shim it waits in.
pc_kill_stray() {
  pkill -KILL -f "$LV_ROOT/custodexa.sh" 2>/dev/null || true
  pkill -KILL -f "$IT_WORK/lvshim/docker" 2>/dev/null || true
  sleep 1
}

pc_fresh() {
  pc_kill_stray
  for p in postgresql .pg-convert; do umount "$LV_ROOT/data/$p" 2>/dev/null || true; done
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK"/lv-* "$IT_WORK/df-small"
  mkdir -p "$IT_WORK"
  pc_install
  pc_seed "$1"
}

# 1. success path: stop at the end of step 8 (the hold is before step 10's compose up).
pc_success() {
  local old new calls log
  pc_fresh success
  it_step "success: upgrade held before step 10, both sides compared"
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-up pc_upgrade_bg up1
  lv_until "the upgrade reaches step 10" test -e "$IT_WORK/lv-up-reached"
  it_same "step 8 recorded as done" "done" "$(lv_st last_upgrade.db_convert.result)"
  old=$(pc_hash pc_old_sql)
  pc_new_start
  new=$(pc_hash pc_new_sql)
  it_check "every table has rows to compare" test "$(grep -c . <<<"$old")" -gt 5
  it_same "every table (count and md5 of all rows), every sequence: new equals old" "$old" "$new"
  it_same "schema_migrations: the same set" "$(pc_old_sql 'SELECT string_agg(version, $$,$$ ORDER BY version) FROM schema_migrations')" \
    "$(pc_new_sql 'SELECT string_agg(version, $$,$$ ORDER BY version) FROM schema_migrations')"
  it_same "the new cluster has data_checksums on" on "$(pc_new_sql 'SHOW data_checksums')"
  it_same "the new cluster is PostgreSQL 18" 18 "$(pc_new_sql 'SHOW server_version_num' | cut -c1-2)"
  it_same "encoding and collation as the old database" "$(pc_old_sql "SELECT pg_encoding_to_char(encoding)||datcollate||datctype FROM pg_database WHERE datname = current_database()")" \
    "$(pc_new_sql "SELECT pg_encoding_to_char(encoding)||datcollate||datctype FROM pg_database WHERE datname = current_database()")"
  pc_new_stop
  rm -f "$IT_WORK/lv-hold"
  pc_wait_end up1
  it_same "the upgrade exits 0" 0 "$LV_RC"
  lv_wait_version "$PC_NEW"
  it_same "SHOW data_checksums after the upgrade" on "$(lv_sql 'SHOW data_checksums')"
  it_same "the old data folder is still PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  log=$(find "$LV_ROOT/logs" -name 'upgrade-*.log' | sort | tail -n 1)
  calls=$IT_WORK/docker-calls.log
  it_same "the script log has no mv, rm or write on the old data folder" "" \
    "$(grep -E '(mv|rm|chmod|chown)[^|]*data/postgres([^a-z]|$)' "$log" || true)"
  it_same "no docker call mounts the old data folder" "" "$(grep -E 'data/postgres:|data/postgres ' "$calls" | grep -v 'data/postgresql' || true)"
}

# 2. failure injection at restore, then a retry that backs up again and carries a row written meanwhile.
pc_failure() {
  local b1 b2
  pc_fresh failure
  it_step "failure: the restore fails"
  LV_INJECT=convert-restore-fail pc_upgrade_bg f1
  pc_wait_end f1
  it_check "the upgrade fails (exit $LV_RC)" test "$LV_RC" -ne 0
  it_same "current.version is still $PC_OLD" "$PC_OLD" "$(lv_st current.version)"
  it_same "the upgrade is recorded as failed" failed "$(lv_st last_upgrade.result)"
  it_same "the step of the failure is 8" 8 "$(lv_st last_upgrade.step)"
  it_same "the old version is healthy" "$PC_OLD" "$(lv_version)"
  it_check "the new folder was kept under a failed-convert name" compgen -G "$LV_ROOT/data/postgresql.failed-convert-*"
  it_check "data/postgresql is gone" test ! -e "$LV_ROOT/data/postgresql"
  b1=$(lv_st last_upgrade.backup)
  LV_TOKEN=""
  lv_api POST /users "$(jq -cn '{username: "it-after-failure", password: "It-user-pass-0002", email: "it-after-failure@example.test", full_name: "x"}')" >/dev/null
  it_step "failure: the retry backs up again and the new row reaches PostgreSQL 18"
  LV_INJECT="" pc_upgrade_bg f2
  pc_wait_end f2
  it_same "the retry exits 0" 0 "$LV_RC"
  b2=$(lv_st last_upgrade.backup)
  it_check "a new backup was made ($b1 -> $b2)" test "$b1" != "$b2"
  lv_wait_version "$PC_NEW"
  it_same "PostgreSQL 18 holds the row written after the failure" 1 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-after-failure'")"
}

# 3. kill during the failure wrap-up (after recovery=restart_old, old services up, before "failed").
pc_wrapup_kill() {
  local b1 b2
  pc_fresh wrapup
  it_step "wrap-up: SIGKILL after the old services were restarted"
  touch "$IT_WORK/lv-hold"
  LV_INJECT="convert-restore-fail hold-recovery" pc_upgrade_bg w1
  lv_until "the wrap-up restarted the old services" test -e "$IT_WORK/lv-recovery-reached"
  it_same "recovery=restart_old is recorded before the restart" restart_old "$(lv_st last_upgrade.db_convert.recovery)"
  b1=$(lv_st last_upgrade.backup)
  pc_kill w1
  lv_wait_version "$PC_OLD"
  LV_TOKEN=""
  lv_api POST /users "$(jq -cn '{username: "it-after-wrapup", password: "It-user-pass-0003", email: "it-after-wrapup@example.test", full_name: "x"}')" >/dev/null
  LV_INJECT="" pc_upgrade_bg w2
  pc_wait_end w2
  it_same "the rerun exits 0" 0 "$LV_RC"
  b2=$(lv_st last_upgrade.backup)
  it_check "the old backup was not reused ($b1 -> $b2)" test "$b1" != "$b2"
  lv_wait_version "$PC_NEW"
  it_same "PostgreSQL 18 holds the row" 1 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-after-wrapup'")"
}

# 4. kill during the restore; variants for what happened to the application meanwhile.
pc_interrupt() {
  local variant=$1 b1 b2 want
  pc_fresh "int-$variant"
  it_step "interrupt ($variant): SIGKILL during the restore"
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-convert-restore pc_upgrade_bg i1
  lv_until "the restore started" test -e "$IT_WORK/lv-convert-reached"
  b1=$(lv_st last_upgrade.backup)
  pc_kill i1
  it_same "the old data folder is still PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  case $variant in
    never)
      want=same ;;
    row)
      docker start custodexa-backend >/dev/null
      lv_wait_version "$PC_OLD"
      LV_TOKEN=""
      lv_api POST /users "$(jq -cn '{username: "it-mid-interrupt", password: "It-user-pass-0004", email: "it-mid@example.test", full_name: "x"}')" >/dev/null
      docker stop custodexa-backend >/dev/null
      want=new ;;
    update)
      docker start custodexa-backend >/dev/null
      lv_wait_version "$PC_OLD"
      docker stop custodexa-backend >/dev/null
      lv_sql "UPDATE users SET full_name = 'Renamed by the test' WHERE username = 'it-before-int-update'" >/dev/null
      want=new ;;
  esac
  LV_INJECT="" pc_upgrade_bg i2
  pc_wait_end i2
  it_same "the rerun exits 0" 0 "$LV_RC"
  b2=$(lv_st last_upgrade.backup)
  if [ "$want" = same ]; then
    it_same "the application never started: the backup of the first run is used" "$b1" "$b2"
  else
    it_check "the application ran: a new backup ($b1 -> $b2)" test "$b1" != "$b2"
  fi
  it_same "the old data folder was neither renamed nor removed" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  lv_wait_version "$PC_NEW"
  case $variant in
    row) it_same "PostgreSQL 18 holds the row" 1 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-mid-interrupt'")" ;;
    update) it_same "PostgreSQL 18 holds the updated name" "Renamed by the test" "$(lv_sql "SELECT full_name FROM users WHERE username = 'it-before-int-update'")" ;;
  esac
}

# 5. no room: small file systems for the new cluster and for the dump.
pc_space() {
  local place ps0
  pc_fresh space
  for place in postgresql .pg-convert; do
    it_step "space: a 8 MiB tmpfs at data/$place"
    mkdir -p "$LV_ROOT/data/$place"
    mount -t tmpfs -o size=8m tmpfs "$LV_ROOT/data/$place"
    ps0=$(lv_ps)
    LV_INJECT="" pc_upgrade_bg s1
    pc_wait_end s1
    it_same "the upgrade is refused before anything stops (exit 1, as every space refusal)" 1 "$LV_RC"
    it_check "the screen names the file system (data/$place)" grep -q "data/$place" <<<"$LV_OUT"
    it_same "no service was stopped" "$ps0" "$(lv_ps)"
    it_same "current.version is $PC_OLD" "$PC_OLD" "$(lv_st current.version)"
    umount "$LV_ROOT/data/$place"
    rmdir "$LV_ROOT/data/$place" 2>/dev/null || true
  done
}

# pc_pty_yes <label>: the upgrade on a terminal, every [y/N] answered y and the backup choice answered 1
# (the script makes the backup), as an operator does.
pc_pty_yes() {
  local label=$1 pid fd seen=0 seen1=0 n i rc=0
  rm -f "$IT_WORK/$label.in"
  mkfifo "$IT_WORK/$label.in"
  : >"$IT_WORK/$label.out"
  script -qfec "env PATH=$IT_WORK/lvshim:$PATH $LV_ROOT/custodexa.sh upgrade $(it_package_file "$PC_NEW") --images $(it_bundle_file "$PC_NEW") --lang en" /dev/null \
    <"$IT_WORK/$label.in" >"$IT_WORK/$label.out" 2>&1 &
  pid=$!
  exec {fd}>"$IT_WORK/$label.in"
  for ((i = 0; i < 36000; i++)); do
    n=$(tr -d '\r' <"$IT_WORK/$label.out" | grep -c '\[y/N\]' || true)
    if [ "$n" -gt "$seen" ]; then
      printf 'y\n' >&"$fd"
      seen=$n
    fi
    # the backup question of step 7 (a terminal run asks which backup): the script's own
    n=$(tr -d '\r' <"$IT_WORK/$label.out" | grep -c 'Choose \[1/2\]' || true)
    if [ "$n" -gt "$seen1" ]; then
      printf '1\n' >&"$fd"
      seen1=$n
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  wait "$pid" || rc=$?
  exec {fd}>&-
  LV_RC=$rc
  LV_OUT=$(tr -d '\r' <"$IT_WORK/$label.out")
  printf '%s\n' "$LV_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$LV_RC"
}

# 6. leftovers of a failed conversion fill the room; an interactive rerun may clear them, --yes may not.
pc_leftovers() {
  pc_fresh leftovers
  it_step "leftovers: the first conversion fails at restore and its folder is kept"
  LV_INJECT=convert-restore-fail pc_upgrade_bg l1
  pc_wait_end l1
  it_check "the first upgrade fails" test "$LV_RC" -ne 0
  it_check "a failed-convert folder is kept" compgen -G "$LV_ROOT/data/postgresql.failed-convert-*"
  touch "$IT_WORK/df-small"
  it_step "leftovers: --yes does not clear them, and the room is short"
  LV_INJECT="" pc_upgrade_bg l2
  pc_wait_end l2
  it_same "the --yes rerun is refused for room (exit 1)" 1 "$LV_RC"
  it_check "the failed-convert folder is still there" compgen -G "$LV_ROOT/data/postgresql.failed-convert-*"
  it_check "the screen lists the folder" grep -q 'postgresql.failed-convert-' <<<"$LV_OUT"
  it_step "leftovers: the interactive rerun answers y to the clearing question"
  LV_INJECT="" pc_pty_yes l3
  it_same "the interactive rerun exits 0" 0 "$LV_RC"
  # shellcheck disable=SC2016
  it_check "the failed-convert folder is gone" bash -c '! compgen -G "$1/data/postgresql.failed-convert-*"' _ "$LV_ROOT"
  lv_wait_version "$PC_NEW"
}

# pc_section <label> <function> [argument]: one section in a subshell of its own with errexit on, so
# a section that fails does not hide the others. A red run needs this: every section
# has to be seen failing on its own against the current script. A section that fails prints
# "section not ok - <label>"; the scenario ends non-zero when any did.
pc_failed=""
pc_section() {
  local label=$1 fn=$2 rc=0 p
  shift 2
  case " ${CX_IT_PG_SECTIONS:-all} " in *" all "* | *" $fn "*) ;; *) return 0 ;; esac
  it_step "section: $label"
  ( set -e; "$fn" "$@" ) &
  wait $! || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'section not ok - %s (%s, exit %s)\n' "$label" "$fn" "$rc"
    pc_failed="$pc_failed [$label]"
  else
    printf 'section ok - %s\n' "$label"
  fi
  # a section that stopped halfway can leave a tmpfs, a held docker shim or a background run
  # behind; kill the run first, or releasing the hold lets it carry on into the next section
  pc_kill_stray
  for p in postgresql .pg-convert; do umount "$LV_ROOT/data/$p" 2>/dev/null || true; done
  rm -f "$IT_WORK/lv-hold"
}

# 7. time and space of the conversion at one data size (calibration). Not part of "all": name it,
#    CX_IT_PG_SECTIONS=pc_timing CX_IT_PG_BULK_ROWS=<rows of 1 KiB>. Prints TIMING lines: the size, the
#    seconds of each phase (from the upgrade log), the preview's estimate, and the peak of every file
#    system sampled once a second (du of the data folders, df of / and of the image store).
pc_du_start() {
  rm -f "$IT_WORK/du.log"
  (
    while :; do
      printf '%s' "$(date +%s)"
      for d in postgres postgresql .pg-convert; do
        printf ' %s=%s' "$d" "$(du -sk "$LV_ROOT/data/$d" 2>/dev/null | cut -f1 || true)"
      done
      printf ' backups=%s' "$(du -sk "$LV_ROOT/backups" 2>/dev/null | cut -f1 || true)"
      printf ' rootused=%s dockerused=%s\n' "$(df -k --output=used / | tail -n 1 | tr -d ' ')" \
        "$(df -k --output=used /var/lib/docker | tail -n 1 | tr -d ' ')"
      sleep 1
    done
  ) >"$IT_WORK/du.log" 2>/dev/null &
  PC_DU_PID=$!
}

pc_du_stop() {
  kill "$PC_DU_PID" 2>/dev/null || true
  wait "$PC_DU_PID" 2>/dev/null || true
}

# pc_ts <log> <pattern>: epoch seconds of the first log line that matches.
pc_ts() {
  local t
  t=$(grep -m1 -- "$2" "$1" | cut -d' ' -f1)
  if [ -z "$t" ]; then
    echo "pc_ts: no log line matches: $2" >&2
    echo 0
    return 0
  fi
  date -d "$t" +%s
}

pc_timing() {
  local log size t0 t1 t2 t3 t5 t6 t9 est
  pc_fresh timing
  size=$(lv_sql 'SELECT pg_database_size(current_database())')
  it_say "TIMING rows=$PC_BULK_ROWS database_bytes=$size"
  pc_du_start
  pc_upgrade_bg tm1
  pc_wait_end tm1
  pc_du_stop
  it_same "the upgrade exits 0" 0 "$LV_RC"
  est=$(grep -m1 'Time      about' <<<"$LV_OUT" | sed 's/^ *//')
  it_say "TIMING estimate: $est"
  grep -A1 -E '^ *(Space) ' <<<"$LV_OUT" | sed 's/^ */TIMING preview: /'
  log=$(find "$LV_ROOT/logs" -name 'upgrade-*.log' | sort | tail -n 1)
  it_say "TIMING step 8 of the log (commands and times):"
  sed -n '/STEP  8\/13/,/STEP  9\/13/p' "$log" | cut -c1-200 | sed 's/^/   TIMING log> /'
  t0=$(pc_ts "$log" 'STEP  8/13') t1=$(pc_ts "$log" 'entrypoint pg_dump') t2=$(pc_ts "$log" 'docker run -d --name custodexa-pgconvert')
  t3=$(pc_ts "$log" 'pg_restore --single-transaction')
  t5=$(pc_ts "$log" 'vacuumdb') t6=$(pc_ts "$log" 'docker stop -t 120 custodexa-pgconvert') t9=$(pc_ts "$log" 'STEP  9/13')
  it_say "TIMING seconds: prepare=$((t1 - t0)) dump=$((t2 - t1)) init=$((t3 - t2)) restore_and_verify=$((t5 - t3)) analyze=$((t6 - t5)) done=$((t9 - t6)) step8_total=$((t9 - t0))"
  it_say "TIMING bytes_per_second_restore_and_verify=$((size / (t5 - t3 > 0 ? t5 - t3 : 1))) bytes_per_second_step8=$((size / (t9 - t0 > 0 ? t9 - t0 : 1)))"
  awk '{
      for (i = 2; i <= NF; i++) { split($i, kv, "="); v[kv[1]] = kv[2] + 0 }
      if (NR == 1) { b0 = v["backups"]; r0 = v["rootused"]; d0 = v["dockerused"]; o = v["postgres"] }
      if (v["postgresql"] > pn) pn = v["postgresql"]
      if (v[".pg-convert"] > pd) pd = v[".pg-convert"]
      add = v["postgresql"] + v[".pg-convert"] + v["backups"] - b0
      if (add > pa) pa = add
      if (v["rootused"] - r0 > pr) pr = v["rootused"] - r0
      if (v["dockerused"] - d0 > pk) pk = v["dockerused"] - d0
      if (v["backups"] - b0 > pb) pb = v["backups"] - b0
    } END { printf "TIMING peak_KiB: old_data=%d new_data=%d dump_scratch=%d backup_added=%d sum_of_the_three=%d root_fs_growth=%d image_store_growth=%d samples=%d\n", o, pn, pd, pb, pa, pr, pk, NR }' "$IT_WORK/du.log"
}

# CX_IT_PG_SECTIONS="pc_success pc_space" runs only those functions (default: all of them).
scenario() {
  pc_section "success path" pc_success
  pc_section "failure injection at restore" pc_failure
  pc_section "failure wrap-up interrupted" pc_wrapup_kill
  pc_section "interrupt at restore" pc_interrupt never
  pc_section "interrupt, app started, row written" pc_interrupt row
  pc_section "interrupt, app started, display name updated" pc_interrupt update
  pc_section "no room" pc_space
  pc_section "failure leftovers" pc_leftovers
  case " ${CX_IT_PG_SECTIONS:-} " in *" pc_timing "*) pc_section "time and space" pc_timing ;; esac
  ex_teardown "$LV_ROOT" || true
  [ -z "$pc_failed" ] || it_die "sections not ok:$pc_failed"
}
