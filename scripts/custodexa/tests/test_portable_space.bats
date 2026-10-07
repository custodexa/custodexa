#!/usr/bin/env bats
# Threat (A): a backup that runs out of space with the services stopped. While tar builds the single
# file, the largest member is still in the temporary folder: the file, that member again and 1 GB
# spare must fit before anything is stopped. An estimate that leaves out the largest member, the
# spare or the recordings chosen lets the backup stop the services and then fail half way.

load helper
load install_host
load backup_host

GIB=1073741824

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  clock
}

# sizes <database> <audit> <tls> <recordings>: what the database and du report, in bytes.
sizes() {
  printf '%s\n' "$1" >"$DB/size"
  printf '%s\n' "$2" >"$DB/du.$(printf '%s' "$ROOT/data/audit" | tr / -)"
  printf '%s\n' "$3" >"$DB/du.$(printf '%s' "$ROOT/tls" | tr / -)"
  printf '%s\n' "$4" >"$DB/du.$(printf '%s' "$ROOT/data/recordings" | tr / -)"
}

# free_bytes <bytes>: the free space where backups go (df reports whole KiB).
free_bytes() {
  [ $(($1 % 1024)) -eq 0 ] || { echo "free_bytes: $1 is not whole KiB"; return 1; }
  host_free / $(($1 / 1024))
}

# no_stop: nothing was stopped and nothing was made under backups/.
no_stop() {
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; cat "$DB/events"; return 1; fi
  [ ! -e "$ROOT/backups" ] || { ls -lA "$ROOT/backups"; return 1; }
}

@test "space: short by one byte is refused before any stop with the amounts and what to do" {
  # 8 GiB database, a 1-byte audit folder, an empty tls/: the file is 8 GiB + 1 byte and needs
  # 17 GiB + 1 byte; one byte less is free.
  sizes $((8 * GIB)) 1 0 4096
  free_bytes $((17 * GIB)) || return 1
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF' || { echo "$output"; return 1; }
[FAIL] Not enough space for the backup: 17.0 GB needed (including room to
       build the file and 1 GB spare), /opt/custodexa/backups has 17.0 GB
       free. Nothing was stopped.
  You can move older backup files elsewhere and delete them here, or (if
  you chose to include the recordings) run it again without them.
  The backup files now: ls -l /opt/custodexa/backups/
EOF
  no_stop || return 1
  grep -q "PREVIEW need=$((17 * GIB + 1)) file=$((8 * GIB + 1)) free=$((17 * GIB)) recordings=0" "$ROOT"/logs/backup-*.log \
    || { grep PREVIEW "$ROOT"/logs/backup-*.log; return 1; }
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = failed ]
  # The same in zh-TW.
  rm -rf "$ROOT/logs"
  : >"$DB/events"
  backup_run zh-TW --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF' || { echo "$output"; return 1; }
[FAIL] 備份空間不足：需要 17.0 GB（含組裝時的暫存與 1 GB 餘裕），
       /opt/custodexa/backups 只剩 17.0 GB。沒有停止任何服務。
  可以：把舊的備份檔搬到別處後刪除，或（若選了放入錄影）
  改成不放錄影再執行一次。
  目前的備份檔：ls -l /opt/custodexa/backups/
EOF
  no_stop
}

@test "space: exactly the space needed is enough; the preview shows the need and the file" {
  # 8 GiB database, nothing else: the file is 8 GiB and needs 17 GiB, all of it free.
  sizes $((8 * GIB)) 0 0 4096
  free_bytes $((17 * GIB)) || return 1
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"  Needs 17.0 GB (a file of about 8.0 GB, room to build it and 1 GB
  spare); 17.0 GB free where backups go"* ]] || { echo "$output"; return 1; }
  # The pause is that of the 8 GB taken, not of the space needed: 8 GiB at 25 MB/s is 6 minutes.
  [[ $output == *"pause for about
  6 minutes"* ]] || { echo "$output"; return 1; }
  grep -q '^stop' "$DB/events" && bk_one
}

@test "space: an estimate without the largest member would pass, and it is refused" {
  # The file and 1 GB spare (9 GiB) fit in 12 GiB; the database again (another 8 GiB) does not.
  sizes $((8 * GIB)) 0 0 4096
  free_bytes $((12 * GIB)) || return 1
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] Not enough space for the backup: 17.0 GB needed (including room to"* ]] || { echo "$output"; return 1; }
  no_stop || return 1
  # Without the 1 GB spare it would pass too: 16 GiB + 1 byte without it, 16 GiB + 1 KiB free.
  : >"$DB/events"
  sizes $((8 * GIB)) 1 0 4096
  free_bytes $((16 * GIB + 1024)) || return 1
  backup_run en --yes
  [ "$status" -eq 1 ] && [[ $output == *"17.0 GB needed"* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "space: with and without the recordings, the largest member is the one in the file" {
  bk_libs || return 1
  # Recordings 20 GiB, database 8 GiB, audit 1 GiB, tls/ 4 KiB.
  CX_BK_SIZE_DB=$((8 * GIB)) CX_BK_SIZE_AUDIT=$GIB CX_BK_SIZE_TLS=4096 CX_BK_SIZE_REC=$((20 * GIB))
  cx_pb_space 0
  [ "$CX_PB_FILE_EST" -eq $((9 * GIB + 4096)) ] || { echo "file without: $CX_PB_FILE_EST"; return 1; }
  [ "$CX_BK_NEED" -eq $((9 * GIB + 4096 + 8 * GIB + GIB)) ] || { echo "need without: $CX_BK_NEED"; return 1; }
  cx_pb_space 1
  [ "$CX_PB_FILE_EST" -eq $((29 * GIB + 4096)) ] || { echo "file with: $CX_PB_FILE_EST"; return 1; }
  [ "$CX_BK_NEED" -eq $((29 * GIB + 4096 + 20 * GIB + GIB)) ] || { echo "need with: $CX_BK_NEED"; return 1; }
  # The audit folder can be the largest member.
  CX_BK_SIZE_AUDIT=$((10 * GIB)) CX_BK_SIZE_REC=0
  cx_pb_space 1
  [ "$CX_BK_NEED" -eq $((18 * GIB + 4096 + 10 * GIB + GIB)) ] || { echo "audit largest: $CX_BK_NEED"; return 1; }
}

@test "space: the check uses the recordings choice; a free space that fits without them is short with them" {
  # The check of the preview with the recordings put in, on the same numbers: 8 GiB database,
  # 20 GiB recordings; 20 GiB free is enough without them (17 GiB), short with them (49 GiB).
  sizes $((8 * GIB)) 0 0 $((20 * GIB))
  free_bytes $((20 * GIB)) || return 1
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "without: $output"; return 1; }
  rm -rf "$ROOT/backups" "$ROOT/logs"
  : >"$DB/events"
  bk_state_fresh
  backup_run en --yes --with-recordings
  [ "$status" -eq 1 ] || { echo "with: $output"; return 1; }
  [[ $output == *"[FAIL] Not enough space for the backup: 49.0 GB needed (including room to"* ]] || { echo "$output"; return 1; }
  no_stop
}
