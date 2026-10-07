# shellcheck shell=bash
# about: an external database deployment on PostgreSQL 16, 17 and 18 each restores its backup on its own host and on a new host, into the same database, with the pinned clients' default output: on its own host, its backend connected, the restore stops the services itself; a body.sql maker that fails opens no transaction; held after the database check the target digest is the source's at the backup, and --revert (the safety backup) brings back the rows, data, sequences and grants from before; the finished restore has the backup's snapshot and master key. A new host is refused while the original host is connected, and once it is gone the same holds, its --revert putting the safety export back to the digest of before. On 17, a connection held open is listed before the stop and stops the restore after it (step 2), and --revert starts the services again
# needs: package local-versions
# images: pg16 pg17 pg18

XD_A=/opt/custodexa XD_B=/opt/b/custodexa XD_B_DATA=/opt/b/data XD_FILE=""
XR_SERVER=""
XD_MAJORS=${XD_MAJORS:-16 17 18}

# The deployment's database facts of lib/restore.sh (ri_*), read on the external server.
lv_sql() { ex_db_sql "$XR_SERVER" "$EX_DB" "$1"; }

xd_log() {
  local log
  log=$(ex_st "$1" last_restore.log)
  [[ $log == /* ]] || log=$1/$log
  printf '%s' "$log"
}
xd_flat() { tr '\n' ' ' <<<"$XR_OUT" | tr -s ' '; }
xd_phase() { printf '%s %s' "$(ex_st "$1" last_restore.result)" "$(ex_st "$1" last_restore.phase)"; }
xd_no_tx() {
  it_same "$1: no import container was started (no transaction opened)" "" "$(grep -- '-import ' "$IT_WORK/xr-docker.log" || true)"
}

# xd_same <label> [args]: a restore on host A of its own backup.
xd_same() {
  local label=$1
  shift
  xr_cx "$label" "$XD_A" restore "$XD_FILE" --same-host --yes --confirm-data-loss "$@"
}
xd_new() {
  local label=$1
  shift
  xr_cx "$label" "$XD_B" restore "$XD_FILE" --new-host --yes --confirm-data-loss --data-path "$XD_B_DATA" "$@"
}

# xd_held <label> <root> <source digest> <source lines>: held after the database check.
xd_held() {
  it_same "$1: exit 1 at the file placement" 1 "$XR_RC"
  it_check "$1: the injection happened" test -s "$IT_WORK/xr-injected"
  it_same "$1: in progress, database checked" "in_progress db_checked" "$(xd_phase "$2")"
  it_same "$1: the target digest equals the source's at the backup (the script's own query)" "$3" "$(xr_digest "$XR_SERVER")"
  it_same "$1: and so every line of it" "$(cat "$4")" "$(xr_lines "$XR_SERVER")"
}

xd_holder() {
  local i
  docker run -d --name it-xd-holder --network host -e PGPASSWORD="$EX_PASS" -e PGAPPNAME=it-holder \
    --entrypoint psql "$(it_image pg17)" -h "$(ex_addr)" -p "$1" -U "$EX_USER" -d "$EX_DB" -c 'SELECT pg_sleep(900)' >/dev/null
  for ((i = 0; i < 30; i++)); do
    [ "$(it_pg_sql "$XR_SERVER" postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'it-holder'")" = 1 ] && return 0
    sleep 1
  done
  it_die "the held connection did not show"
}
xd_holder_end() {
  local i
  docker rm -f it-xd-holder >/dev/null
  it_pg_sql "$XR_SERVER" postgres "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = 'it-holder'" >/dev/null
  for ((i = 0; i < 30; i++)); do
    [ "$(it_pg_sql "$XR_SERVER" postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'it-holder'")" = 0 ] && return 0
    sleep 1
  done
  it_die "the held connection did not end"
}

# xd_same_held: on its own host, a psql connection held open is listed before the stop and stops
# the restore after it (step 2, after the stop); --revert starts the services again.
xd_same_held() {
  local port=$1 log
  it_step "same host, a psql connection held open: listed before the stop, the restore stops after it"
  xd_holder "$port"
  ri_mark
  ri_facts "$IT_WORK/facts.held"
  xd_same held
  it_same "held: exit 1" 1 "$XR_RC"
  it_check "held: stopped at step 2, after the services stopped" grep -qF '2/10' <<<"$XR_OUT"
  it_check "held: it names the held connection" grep -qF 'application it-holder' <<<"$(xd_flat)"
  log=$(xd_log "$XD_A")
  it_check "held: listed before the stop (${log##*/})" grep -qE 'external database other connections=[1-9]' "$log"
  it_check "held: no import record (nothing was emptied)" test ! -e "$(xr_rs_dir "$XD_A")/external-import"
  xd_no_tx held
  xd_holder_end
  xr_cx held-revert "$XD_A" restore --revert --yes
  it_same "held-revert: exit 0" 0 "$XR_RC"
  it_same "held-revert: recorded reverted" reverted "$(ex_st "$XD_A" last_restore.result)"
  lv_wait_version "$XR_V"
  ri_same_facts "held-revert: version, rows, data, sequences and grants are those before" "$IT_WORK/facts.held"
}

xd_major() {
  local m=$1 port=$((15450 + $1)) src t0 safety log
  XR_SERVER=xd$m
  it_step "PostgreSQL $m: server $XR_SERVER on $(ex_addr):$port"
  ex_pg_start "$XR_SERVER" "$m" "$port"
  ex_db_create "$XR_SERVER"

  it_step "host A: install $XR_V on $XR_SERVER, data through the API"
  rm -f "$IT_WORK/lv-admin-password"
  # shellcheck disable=SC2034 # read by lv_api
  LV_TOKEN=""
  xr_install "$XD_A" "$port"
  ri_data "in-backup-$m"

  it_step "host A stopped: the source digest by the script's own query, then the backup (which starts it again)"
  xr_cx stop "$XD_A" stop --yes
  it_same "host A stops" 0 "$XR_RC"
  xr_lines "$XR_SERVER" >"$IT_WORK/source$m.lines"
  src=$(xr_digest "$XR_SERVER")
  it_same "the digest is the hash of its lines" "$src" "$(printf '%s' "$(cat "$IT_WORK/source$m.lines")" | sha256sum | cut -c1-64)"
  ri_backup "backup$m"
  XD_FILE=$RI_FILE
  it_same "the backup: external, PostgreSQL $m, its client" "external $m pgclient$m" \
    "$(jq -r '[."db.location", ."db.server_major", ."tool.dump_image"] | join(" ")' "$IT_WORK/backup$m.manifest")"
  lv_wait_version "$XR_V"
  ri_data "after-backup-$m"

  [ "$m" != 17 ] || xd_same_held "$port"

  it_step "same host, its backend connected: the body.sql maker fails; no transaction"
  ri_mark
  ri_facts "$IT_WORK/facts.before$m"
  XR_INJECT=body-prefix xd_same same-body
  it_same "same-body: exit 1" 1 "$XR_RC"
  it_same "same-body: in progress at the import" "in_progress swapped" "$(xd_phase "$XD_A")"
  log=$(xd_log "$XD_A")
  it_check "same-body: the services were stopped by the restore after it listed the backend (${log##*/})" \
    grep -qE 'external database other connections=[1-9]' "$log"
  it_check "same-body: making body.sql failed" grep -qF 'external import: making body.sql failed' "$log"
  xd_no_tx same-body
  ri_same_facts "same-body: version, rows, data, sequences and grants unchanged" "$IT_WORK/facts.before$m"
  it_step "same host: --resume, held after the database check"
  XR_INJECT=place-fail xr_cx same-held "$XD_A" restore --resume
  xd_held same-held "$XD_A" "$src" "$IT_WORK/source$m.lines"
  it_same "same-held: the safety backup is the deployment's own" script "$(ex_st "$XD_A" last_restore.safety)"
  xr_cx same-revert "$XD_A" restore --revert --yes
  it_same "same-revert: exit 0" 0 "$XR_RC"
  it_same "same-revert: recorded reverted" reverted "$(ex_st "$XD_A" last_restore.result)"
  lv_wait_version "$XR_V"
  ri_same_facts "same-revert: version, rows, data, sequences and grants are those before" "$IT_WORK/facts.before$m"
  it_same "same-revert: the user written after the backup is back" 1 "$(ri_has "after-backup-$m")"

  it_step "same host, its backend connected: the restore stops the services itself and finishes"
  ri_mark
  xd_same same
  it_same "same: exit 0" 0 "$XR_RC"
  it_same "same: recorded succeeded" succeeded "$(ex_st "$XD_A" last_restore.result)"
  lv_wait_version "$XR_V"
  xr_snap_same "same: the snapshot (rows, migrations, keys) equals the backup's" "$XR_SERVER" "$XD_A" "$IT_WORK/backup$m.snapshot"
  it_same "same: the active master key is the backup's" "$(jq -r '."kek.fingerprint"' "$IT_WORK/backup$m.manifest")" "$(ri_kek_id)"
  it_same "same: the user written after the backup is gone" 0 "$(ri_has "after-backup-$m")"

  it_step "host B: $XR_V unpacked, its bundle loaded; the original host still connected: refused"
  xr_new_host "$XD_B"
  xd_new new-refused
  it_same "new-refused: exit 3" 3 "$XR_RC"
  it_check "new-refused: another connection from the original host" grep -Eq 'other connections? (is|are) using custodexa \(from [0-9.]+' <<<"$(xd_flat)"
  it_check "new-refused: nothing has been changed" grep -qF 'Nothing has been changed.' <<<"$(xd_flat)"

  it_step "the original host is gone: host B's body.sql maker fails; no transaction"
  ri_data "on-a-$m"
  xr_gone "$XR_SERVER"
  t0=$(xr_digest "$XR_SERVER")
  XR_INJECT=body-prefix xd_new new-body
  it_same "new-body: exit 1" 1 "$XR_RC"
  it_same "new-body: in progress at the import" "in_progress swapped" "$(xd_phase "$XD_B")"
  it_check "new-body: making body.sql failed" grep -qF 'external import: making body.sql failed' "$(xd_log "$XD_B")"
  xd_no_tx new-body
  it_same "new-body: the target digest is the one before" "$t0" "$(xr_digest "$XR_SERVER")"
  it_step "host B: --resume, held after the database check"
  XR_INJECT=place-fail xr_cx new-held "$XD_B" restore --resume
  xd_held new-held "$XD_B" "$src" "$IT_WORK/source$m.lines"
  it_same "new-held: exported first, with the digest of before" "db-dump $t0" \
    "$(ex_st "$XD_B" last_restore.safety) $(ex_st "$XD_B" last_restore.safety_digest)"
  safety=$(ex_st "$XD_B" last_restore.safety_file)
  it_same "new-held: safety-db.dump has its recorded SHA-256" "$(ex_st "$XD_B" last_restore.safety_sha256)" "$(sha256sum "$safety" | cut -c1-64)"
  xr_cx new-revert "$XD_B" restore --revert --yes
  it_same "new-revert: exit 0" 0 "$XR_RC"
  it_same "new-revert: recorded reverted" reverted "$(ex_st "$XD_B" last_restore.result)"
  it_same "new-revert: the target digest is the one at the export" "$t0" "$(xr_digest "$XR_SERVER")"
  it_check "new-revert: safety-db.dump removed" test ! -e "$safety"
  it_same "new-revert: host B is not installed" "" "$(ex_st "$XD_B" current.version)"

  it_step "host B: the restore finishes"
  xr_mark "$XR_SERVER"
  xd_new new
  it_same "new: exit 0" 0 "$XR_RC"
  it_same "new: recorded succeeded" succeeded "$(ex_st "$XD_B" last_restore.result)"
  lv_wait_version "$XR_V"
  xr_snap_same "new: the snapshot (rows, migrations, keys) equals the backup's" "$XR_SERVER" "$XD_B" "$IT_WORK/backup$m.snapshot"
  it_same "new: the active master key is the backup's" "$(jq -r '."kek.fingerprint"' "$IT_WORK/backup$m.manifest")" "$(ri_kek_id)"
  it_same "new: written before the backup there, after it not" "1 0 0" \
    "$(ri_has "in-backup-$m") $(ri_has "after-backup-$m") $(ri_has "on-a-$m")"

  it_same "no client container is left" "" "$(docker ps -aq --filter name=custodexa-restore-tool)"
  it_same "no pgpass file is left" "" "$(find "$XD_A" "$XD_B" -name '.pgpass' 2>/dev/null | head -n1)"
  ex_teardown "$XD_B"
  rm -rf /opt/b "$XD_A"
  it_pg_stop "$XR_SERVER"
}

scenario() {
  local m
  for m in $XD_MAJORS; do xd_major "$m"; done
}
