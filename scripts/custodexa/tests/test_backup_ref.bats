#!/usr/bin/env bats
# Threat (A): a backup that is not what it claims. The stopped backup must stop the services before
# it copies anything, stop before stopping anything when the space is short, leave no backup file
# when it failed, keep secrets out of the log, and keep the backup private. A backup of the
# operator's own (--backup-ref) must be taken after the services stopped; one taken earlier misses
# the last writes and is refused.

load helper
load install_host
load backup_host

BK_FILE_NAME=custodexa-backup-1.13.0-20260930-101502.tar

setup() {
  backup_host ui
  # database 17.4 GB; recordings, audit and tls/ are a few KB (real du): a file of 17.4 GB, which
  # needs 35.8 GB (the database again while tar adds it, and 1 GB).
  printf '%s\n' 18683107737 >"$DB/size"
  printf '%s\n' 18690000000 >"$DB/du.$(printf '%s' "$ROOT/backups/$BK_FILE_NAME" | tr / -)"
  # stop 11s, database 1m 40s, audit 2s, settings (no time), start 41s, check 38s, file 3m 12s
  clock 0 11 0 100 0 2 0 0 41 0 38 0 192
}

@test "backup: the screen and the order of the steps match the reviewed text (three languages)" {
  for l in zh-TW en ja; do
    rm -rf "$ROOT/backups" "$ROOT/logs"
    : >"$DB/events"
    clock 0 11 0 100 0 2 0 0 41 0 38 0 192
    backup_run "$l" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(screen_of "$output") "$TESTS_DIR/snapshots/s17.$l.txt" || { echo "screen differs: $l"; return 1; }
  done
  # The order of the stopped-backup procedure: stop, dump, files, settings, start, check, then the
  # single file built and read back once, its checksum file put in place before it.
  grep -v '^psql' "$DB/events" >"$BATS_TEST_TMPDIR/order"
  diff "$BATS_TEST_TMPDIR/order" - <<'EOF'
stop backend guacd frontend
pg_dump
pg_dump_version
tar -czf audit.tar.gz
tar -czf tls.tar.gz
start backend guacd frontend
health
pg_restore
tar -tzf audit.tar.gz
tar -tzf tls.tar.gz
tar pack custodexa-backup-1.13.0-20260930-101502.tar
tar readback
ln custodexa-backup-1.13.0-20260930-101502.tar.sha256
ln custodexa-backup-1.13.0-20260930-101502.tar
EOF
}

@test "backup: the file holds the named members, verified by SHA256SUMS; state.json points at it" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  local f=$ROOT/backups/$BK_FILE_NAME d=$BATS_TEST_TMPDIR/x
  mkdir -p "$d"
  /usr/bin/tar -xf "$f" -C "$d" || return 1
  for m in backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump \
    audit.tar.gz env.bak tls.tar.gz SHA256SUMS; do
    [ -s "$d/$m" ] || { echo "missing $m"; return 1; }
  done
  (cd "$d" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || return 1
  [ "$(wc -l <"$d/SHA256SUMS")" -eq 8 ] || return 1
  # audit is in; recordings are left out unless asked for; exports (decrypted evidence plaintext)
  # never.
  /usr/bin/tar -tzf "$d/audit.tar.gz" >"$BATS_TEST_TMPDIR/list"
  grep -q '^audit/fallback.log$' "$BATS_TEST_TMPDIR/list" || return 1
  [ ! -e "$d/recordings.tar.gz" ] || return 1
  if grep -q exports "$BATS_TEST_TMPDIR/list"; then echo "exports was backed up"; return 1; fi
  cmp "$ROOT/.env" "$d/env.bak" || return 1
  # status reads these keys.
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.id)" = 20260930-101502 ] || return 1
  [ "$(cx_state_get last_backup.kind)" = script ] || return 1
  [ "$(cx_state_get last_backup.file)" = "backups/$BK_FILE_NAME" ] || return 1
  [ "$(cx_state_get last_backup.encrypted)" = false ] && [ -z "$(cx_state_get last_backup.dir)" ] || return 1
  [ "$(cx_state_get last_backup.size_bytes)" = 18690000000 ] || return 1
  [ "$(cx_state_get last_backup.snapshot_usable)" = true ] || return 1
  [ "$(cx_state_get last_backup.result)" = succeeded ]
}

@test "backup: backups/ is 0700; the file, its checksum file and the .env copy in it are 0600" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(stat -c %a "$ROOT/backups")" = 700 ] || return 1
  [ "$(stat -c %a "$ROOT/backups/$BK_FILE_NAME")" = 600 ] || return 1
  [ "$(stat -c %a "$ROOT/backups/$BK_FILE_NAME.sha256")" = 600 ] || return 1
  /usr/bin/tar -tvf "$ROOT/backups/$BK_FILE_NAME" env.bak | grep -q '^-rw------- '
}

@test "backup: no .env secret on the screen, in the log, in state.json, in the manifest or in snapshot.txt" {
  bk_dotenv env
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  local d=$BATS_TEST_TMPDIR/x
  mkdir -p "$d"
  /usr/bin/tar -xf "$ROOT/backups/$BK_FILE_NAME" -C "$d" snapshot.txt backup-manifest.json || return 1
  for v in "$BK_JWT" "$BK_KEK" "$BK_DBPW"; do
    [[ $output != *"$v"* ]] || { echo "secret on screen"; return 1; }
    if grep -rqF -- "$v" "$ROOT/logs" "$ROOT/state.json" "$d/snapshot.txt" "$d/backup-manifest.json"; then
      echo "secret written: ${v:0:4}..."
      return 1
    fi
  done
}

@test "backup: not enough space stops before any service is stopped" {
  host_free / 1048576 # 1 GB
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF' || { echo "$output"; return 1; }
[FAIL] Not enough space for the backup: 35.8 GB needed (including room to
       build the file and 1 GB spare), /opt/custodexa/backups has 1.0 GB
       free. Nothing was stopped.
  You can move older backup files elsewhere and delete them here, or (if
  you chose to include the recordings) run it again without them.
  The backup files now: ls -l /opt/custodexa/backups/
EOF
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  if grep -q ' stop ' "$FAKE_DOCKER_LOG"; then echo "a stop call was made"; return 1; fi
  [ ! -e "$ROOT/backups" ] || return 1
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = failed ] || return 1
  [ -z "$(cx_state_get last_backup.id)" ]
}

@test "backup: a failed step keeps what it took, makes no file, says how to start the services, records no backup" {
  printf '1\n' >"$DB/pg_dump.rc"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [ -d "$ROOT/backups/.partial-20260930-101502" ] || return 1
  [ ! -e "$ROOT/backups/$BK_FILE_NAME" ] || return 1
  [[ $output == *"[FAIL] 2/7  Database"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The backup did not finish and no backup file was made."* ]] || return 1
  [[ $output == *$'\n'"  sudo $ROOT/custodexa.sh start --lang en"* ]] || return 1
  if grep -q '^start' "$DB/events"; then echo "started despite the failure"; return 1; fi
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = failed ] || return 1
  [ -z "$(cx_state_get last_backup.id)" ]
}

@test "backup: a backup that cannot be read is failed and makes no file" {
  printf '1\n' >"$DB/pg_restore.rc"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 6/7  Check each part can be read"* ]] || { echo "$output"; return 1; }
  [ -d "$ROOT/backups/.partial-20260930-101502" ] || return 1
  [ ! -e "$ROOT/backups/.partial-20260930-101502/SHA256SUMS" ] || return 1
  [ ! -e "$ROOT/backups/$BK_FILE_NAME" ] && [ ! -e "$ROOT/backups/$BK_FILE_NAME.sha256" ]
}

@test "backup: without a terminal and without --yes nothing is stopped (exit 3)" {
  backup_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ ! -e "$ROOT/backups" ] || return 1
  load_lib
  cx_state_load "$ROOT/state.json"
  [ "$(cx_state_get last_backup.result)" = cancelled ]
}

# This case asserted that the script never backs up an external database. It now does, with a
# PostgreSQL client of the release; a deployment that has no client recorded is refused before
# anything stops (test_portable_backup_external.bats holds the rest).
@test "backup: an external database without its client images is refused before any service is stopped (exit 3)" {
  sed -i 's/"current.overlays": ""/"current.overlays": "external-database"/' "$ROOT/state.json"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] This host does not have the export tool images for the external"* ]] || { echo "$output"; return 1; }
  [ ! -s "$DB/events" ] && [ ! -e "$ROOT/backups" ]
}

@test "backup: KEK_PROVIDER=env says the .env copy holds the master key and gives no seal warning" {
  bk_dotenv env
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  screen_of "$output" | sed -n '/Backup done/,$p' >"$BATS_TEST_TMPDIR/done"
  diff "$BATS_TEST_TMPDIR/done" - <<'EOF'
[ OK ] Backup done (17.4 GB)
  /opt/custodexa/backups/custodexa-backup-1.13.0-20260930-101502.tar
  Checksum file custodexa-backup-1.13.0-20260930-101502.tar.sha256 (same folder)
  Contains: database, audit files, settings file .env (includes the
  master key), certificates tls/
  Version 1.13.0; bundled database; master key: in the settings file
  The master key is in the .env inside the backup file (fingerprint
  5a5a5a5a5a5a5a5a) and comes back with a restore.
  [WARN] The recordings are not in the backup file. They are in
         /opt/custodexa/data/recordings/; keep them some other way, or
         back up again and choose to include them.
  [WARN] This file is not encrypted and holds the master key and other
         sensitive data (database password, sign-in token secret,
         certificate private keys). Whoever has it can decrypt every stored
         credential. Store it elsewhere with limited access; a backup can
         also be encrypted with a passphrase.
  [ OK ] The services are back.
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
  [[ $output != *"sealed"* ]]
}

# up_take: the backup steps of upgrade step 7 on this deployment, at library level (the services
# are taken as stopped by the upgrade): the portable file with state.json and the snapshot in it.
# SEEN gets "<mark> <n>/<total> <step>;" per step.
up_take() {
  bk_libs || return 1
  CX_DIR=$ROOT/current
  cx_log_open upgrade
  cx_state_load "$ROOT/state.json"
  CX_OVERLAYS=""
  cx_pb_versions && cx_pb_kek_mode && cx_pb_parts && cx_bk_estimate || return 1
  CX_PB_TRIGGER=upgrade CX_PB_STATE=1 CX_PB_WITH_REC=1 CX_PB_ENC=0
  CX_PB_CREATED_AT=$(date '+%Y-%m-%dT%H:%M:%S%z')
  cx_pb_open || return 1
  (umask 077 && cp "$ROOT/state.json" "$CX_BK_DIR/state.json") || return 1
  cx_snap_take "$CX_BK_DIR/snapshot.txt" "$BK_JWT" || return 1
  SEEN=""
  cb() { SEEN+="$1 $2/$3 $4;"; }
  cx_bk_take upgrade cb
}

# Rewritten with the portable file: within an upgrade the backup was a folder of
# four steps; it is the same portable file as the backup command's now, without its stop and start.
@test "backup within an upgrade: no stop or start of its own (the upgrade stopped them), no record (5 steps, one file)" {
  up_take || { echo "$SEEN"; return 1; }
  [ "$SEEN" = "OK 1/5 db;OK 2/5 files;OK 3/5 conf;OK 4/5 verify;OK 5/5 pack;" ] || { echo "$SEEN"; return 1; }
  if grep -q '^start\|^stop' "$DB/events"; then echo "stopped or started within an upgrade"; return 1; fi
  if grep -q '"last_backup.file"' "$ROOT/state.json"; then echo "recorded by the backup, not the upgrade"; return 1; fi
  BK_FILE=$CX_PB_FINAL
  [ -f "$BK_FILE" ] && (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "$CX_PB_NAME.sha256") || return 1
  [ "$(bk_mf trigger)" = upgrade ] && [ "$(bk_mf contents.state)" = true ] && [ "$(bk_mf contents.recordings)" = true ] \
    && [ "$(bk_mf encryption.enabled)" = false ] || return 1
  cmp "$ROOT/state.json" <(bk_member state.json)
}

@test "backup within an upgrade: tls/ is packed when the deployment has one; without one (own ingress) the file is complete without it" {
  local has
  for has in 1 0; do
    rm -rf "$ROOT/backups"
    [ "$has" = 1 ] || rm -rf "$ROOT/tls"
    : >"$DB/events"
    up_take || { echo "[$has] $SEEN"; return 1; }
    [ "$SEEN" = "OK 1/5 db;OK 2/5 files;OK 3/5 conf;OK 4/5 verify;OK 5/5 pack;" ] || { echo "[$has] $SEEN"; return 1; }
    BK_FILE=$CX_PB_FINAL
    if [ "$has" = 1 ]; then
      /usr/bin/tar -tf "$BK_FILE" | grep -qx tls.tar.gz && [ "$(bk_mf contents.tls)" = true ] || return 1
      grep -qx 'tar -tzf tls.tar.gz' "$DB/events" || { cat "$DB/events"; return 1; }
    else
      ! /usr/bin/tar -tf "$BK_FILE" | grep -q tls || return 1
      [ "$(bk_mf contents.tls)" = false ] || return 1
      grep -q 'CHECK tls=absent' "$CX_LOG_FILE" || { cat "$CX_LOG_FILE"; return 1; }
    fi
  done
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

@test "own backup, interactive: a deployment without tls/ (own ingress) gets no certificates folder on the list" {
  own_setup
  rm -rf "$ROOT/tls"
  own_interactive en $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(printf '%s\n' "$output" | sed -n '/^  The snapshot must include$/,/^$/p' | sed "s#$ROOT#/opt/custodexa#g") - <<'EOF' || return 1
  The snapshot must include
    Data folder      /opt/custodexa/data (database, recordings,
                     audit files)
    Settings file    /opt/custodexa/.env

EOF
  # A tls/ that is a link still counts, as tar would take it.
  ln -s /nonexistent "$ROOT/tls"
  own_interactive en $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"    Certificates     $ROOT/tls/"* ]] || { echo "$output"; return 1; }
}

# own_head: the screen from the choice to the list heading, the root shown as /opt/custodexa and
# the space after the unanswered prompt dropped.
own_head() {
  printf '%s\n' "$output" | sed -n '1,/^  \(The snapshot must include\|快照必須包含\|スナップショットに含めるもの\)$/p' \
    | sed -e "s#$ROOT#/opt/custodexa#g" -e 's/ *$//'
}

@test "own backup, interactive: without tls/ (own ingress) the choice and the paragraph name no certificates, word for word; with tls/ they do" {
  own_setup
  rm -rf "$ROOT/tls"
  own_interactive en $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(own_head) - <<'EOF' || return 1
[ ?? ] Backup before the upgrade

  [1] Let the script make a full backup (recommended)
      Database, recordings, audit files, settings.
      About 18.4 GB, roughly 12 minutes
  [2] Use my own backup
      For example a virtual machine or storage snapshot

Choose [1/2]:
[WARN] You chose to use your own backup

  All audit records were confirmed written at 02:16:02 and the
  services stopped at 02:16:13. Take the snapshot now. It must start
  after the services stop, and cover the data folder and .env in
  the same restorable backup.

  The snapshot must include
EOF
  own_interactive zh-TW $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(own_head) - <<'EOF' || return 1
[ ?? ] 升級前備份

  [1] 由腳本做完整備份（建議）
      資料庫、錄影、稽核檔、設定檔。預估 18.4 GB，約 12 分鐘
  [2] 我要用自己的備份
      例如虛擬機快照、儲存設備快照

請選擇 [1/2]：
[WARN] 你選擇使用自己的備份

  稽核紀錄在 02:16:02 確認全部寫入，服務在 02:16:13 停止。
  請現在做快照。快照須在停機後開始，並確認資料目錄和 .env 都包含在
  同一次可還原的備份中。

  快照必須包含
EOF
  own_interactive ja $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(own_head) - <<'EOF' || return 1
[ ?? ] アップグレード前のバックアップ

  [1] スクリプトで完全バックアップを取る（推奨）
      データベース、録画、監査ファイル、設定ファイル。
      推定 18.4 GB、約 12 分
  [2] 自分のバックアップを使う
      例：仮想マシンのスナップショット、ストレージのスナップショット

選択してください [1/2]：
[WARN] 自分のバックアップを使うことを選びました

  監査記録は 02:16:02 にすべて書き込み済みを確認し、
  サービスは 02:16:13 に停止しました。
  いまスナップショットを取ってください。停止後に開始し、データフォルダーと
  .env が同じ復元可能なバックアップに含まれることを確認してください。

  スナップショットに含めるもの
EOF
  # No word for certificates anywhere on these screens.
  local l word
  for l in zh-TW en ja; do
    case $l in zh-TW) word=憑證 ;; en) word=ertificate ;; ja) word=証明書 ;; esac
    own_interactive "$l" $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
    [[ $output != *"$word"* ]] || { echo "$l, no tls/: $output"; return 1; }
  done
  # With tls/ (a link counts too) every language names them in the choice and in the paragraph.
  ln -s /nonexistent "$ROOT/tls"
  for l in zh-TW en ja; do
    case $l in zh-TW) word=憑證 ;; en) word=ertificate ;; ja) word=証明書 ;; esac
    own_interactive "$l" $'2\nsnap\n2026-09-30 02:18\n/doc\nyes'
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    own_head | sed -n '/\[1\]/,/\[2\]/p' | grep -q "$word" || { echo "$l, choice: $output"; return 1; }
    own_head | sed -n '/^\[WARN\]/,$p' | sed '$d' | grep -q "$word" || { echo "$l, paragraph: $output"; return 1; }
  done
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
  run bash -c 'CX_LANG_FLAG=zh-TW; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_ROOT=$2; cx_br_resume' _ "$SRC" "$ROOT"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"custodexa.sh status --lang zh-TW"* ]] || { echo "$output"; return 1; }
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

own_flags() { # <expected status> <ref> <time> <restore>
  local want=$1
  shift
  run env CX_BACKUP_REF="$1" CX_BACKUP_TIME="$2" CX_BACKUP_RESTORE="$3" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"
    . "$1/lib/backup_ref.sh"; CX_ROOT=$2; cx_br_noninteractive' _ "$SRC" "$ROOT"
  [ "$status" -eq "$want" ] || { echo "$output"; return 1; }
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

# resume_of: cx_br_resume as the upgrade calls it.
resume_of() {
  run bash -c 'CX_LANG_FLAG="" LANG=en; . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/backup_ref.sh"
    CX_ROOT=$2; cx_br_resume' _ "$SRC" "$ROOT"
}

# The command lines of the output, as typed without sudo.
typed_cmds() { printf '%s\n' "$output" | grep '^    ' | sed 's/^    //; s/^sudo //'; }

@test "own backup refused, package deployment: the cancel command starts current/compose.yml with the release's image references" {
  mkdir -p "$ROOT/current"
  printf '%s\n' CUSTODEXA_IMAGE_BACKEND=ghcr.io/custodexa/backend:1.13.0 \
    CUSTODEXA_IMAGE_FRONTEND=ghcr.io/custodexa/frontend:1.13.0 >"$ROOT/current/images.env"
  resume_of
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(printf '%s\n' "$output" | sed "s#$ROOT#/opt/custodexa#g" | sed -n '/^  To cancel/,$p')" = "$(sed -n '/^  To cancel/,$p' "$TESTS_DIR/snapshots/s09-early.en.txt")" ] \
    || { echo "$output"; return 1; }
  : >"$FAKE_DOCKER_LOG"
  (eval "$(typed_cmds | head -n 3)") || { typed_cmds; return 1; }
  grep -qxF "$(printf 'ARGS\tcompose -p custodexa --project-directory %s -f %s/current/compose.yml up -d\tIMG_BACKEND=ghcr.io/custodexa/backend:1.13.0' "$ROOT" "$ROOT")" \
    "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
}
