#!/usr/bin/env bats
# Threat (A): a backup of an external database that is not what it claims, or that leaks how to
# reach the database. The export runs in a PostgreSQL client container of the release, chosen to
# match the server; a client of another major version, a password on a command line, in an
# environment or a log, a client that checks the server's certificate more or less than the
# backend does, a dependency the dump leaves out, or a stop before a refusal would each make the
# file lie to the restore or harm the deployment. Each must show here as a failed assertion.

load helper
load install_host
load backup_host
load upgrade_host

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  host_arch x86_64
  clock
  printf '%s\n' 18683107737 >"$DB/size"
  bk_external
}

# The CA file and client certificate as the backend container sees them (under its audit and
# exports mounts), and where they are on this host.
CA_CTR=/var/log/custodexa/audit/db-ca.pem
KEY_CTR=/var/lib/custodexa/exports/client.key
CERT_CTR=/var/lib/custodexa/exports/client.crt

# ca_file: the CA file the backend reads through PGSSLROOTCERT, on this host.
ca_file() { printf -- '-----BEGIN CERTIFICATE-----\nMIIBtest-ca\n-----END CERTIFICATE-----\n' >"$ROOT/data/audit/db-ca.pem"; }

# again: forget the last run (its files, its records), the clock back at the start.
again() {
  rm -rf "$ROOT/backups" "$ROOT/logs"
  local f
  for f in events db-calls db-runs run.argv run.env run.mounts run.names run.tmpfs pgpass.seen \
    pgpass.content db-env; do
    : >"$DB/$f"
  done
  : >"$FAKE_DOCKER_LOG"
  clock
}

# extract_all: every member of BK_FILE into $BATS_TEST_TMPDIR/x (X).
extract_all() {
  X=$BATS_TEST_TMPDIR/x
  rm -rf "$X"
  mkdir -p "$X"
  /usr/bin/tar -xf "$BK_FILE" -C "$X"
}

# no_stop: no service was stopped and nothing was made under backups/.
no_stop() {
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  if [ -e "$ROOT/backups" ] && [ -n "$(ls -A "$ROOT/backups")" ]; then ls -lA "$ROOT/backups"; return 1; fi
}

# ok_run <lang>: a backup with --yes that finished; BK_FILE is its file.
ok_run() {
  backup_run "$1" --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one
}

# dump_argv: the arguments of the last export container (`docker run ... pg_dump -Fc -d <conninfo>`).
dump_argv() { grep -- '--entrypoint pg_dump ' "$DB/run.argv" | grep -- ' -Fc ' | tail -n 1; }

# conn <name>: that setting of the export's connection string ("" when it is not there).
conn() { dump_argv | sed -n "s/.* $1='\([^']*\)'.*/\1/p"; }

# conn_line: the preview's connection line, its lines joined by one space (none before a full-width
# aside, which starts a line of its own).
conn_line() {
  printf '%s\n' "$output" | sed -n '/^  \(Connection\|連線\)/,/^  \(Database\|資料庫\) /p' | sed '$d' \
    | sed 's/^ *//' | paste -sd ' ' - | sed 's/ （/（/g'
}

# refused_screen: the screen from the [FAIL] line on, the deployment folder as /opt/custodexa.
refused_screen() { screen_of "$output" | sed -n '/^\[FAIL\]/,$p'; }

# ---------- the seven steps ----------

# An external database used to be refused here; it now goes through the same seven steps as a
# bundled one, with the export in a client container and the services stopped meanwhile.
@test "external: the seven steps in order, every member and its hash, db.location=external (with and without an external ingress)" {
  for form in database ingress; do
    again
    if [ "$form" = ingress ]; then
      bk_state_set current.overlays "external-ingress external-database"
      rm -rf "$ROOT/tls"
    fi
    ok_run en || return 1
    local -a order=('stop backend guacd frontend' pg_dump 'tar -czf audit.tar.gz')
    [ "$form" = ingress ] || order+=('tar -czf tls.tar.gz')
    order+=('start backend guacd frontend' health pg_restore "tar pack ${BK_FILE##*/}")
    diff <(grep -E '^(stop|start|health|pg_dump$|pg_restore|tar -czf|tar pack)' "$DB/events") \
      <(printf '%s\n' "${order[@]}") || { echo "$form"; cat "$DB/events"; return 1; }
    extract_all
    (cd "$X" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || return 1
    local want="backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak"
    [ "$form" = ingress ] || want+=" tls.tar.gz"
    want+=" SHA256SUMS"
    [ "$(/usr/bin/tar -tf "$BK_FILE" | paste -sd ' ' -)" = "$want" ] || { /usr/bin/tar -tf "$BK_FILE"; return 1; }
    [ "$(bk_mf contents.members)" = "$want" ] || return 1
    [ "$(bk_mf db.location)" = external ] && [ "$(bk_mf db.server_version)" = 17.6 ] || return 1
    [ "$(bk_mf deploy.overlays)" = "$(jq -r '."current.overlays"' "$ROOT/state.json")" ] || return 1
    [ "$(bk_pointer)" = "backups/${BK_FILE##*/}" ] || return 1
    if grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG"; then echo "a call in a bundled service"; return 1; fi
  done
}

# ---------- the one way into the database ----------

@test "database client (external): every kind of database call runs in the chosen client, the snapshot after an upgrade too; none in a bundled service" {
  ok_run en || return 1
  # The probe asks the server with the client of the highest major (18); from the choice on, every
  # call is the client of the server's major (17): queries, the export, its listing, the version.
  [ "$(head -n 1 "$DB/db-runs")" = "sql ${BK_PGC_ID[18]} psql server_version_num" ] || { cat "$DB/db-runs"; return 1; }
  sed -n '/ psql datdba$/,$p' "$DB/db-runs" | sed 1d >"$BATS_TEST_TMPDIR/chosen"
  [ -s "$BATS_TEST_TMPDIR/chosen" ] || { cat "$DB/db-runs"; return 1; }
  if grep -v "^[a-z-]* ${BK_PGC_ID[17]} " "$BATS_TEST_TMPDIR/chosen"; then echo "a call outside the chosen client"; return 1; fi
  for want in 'sql psql size' 'sql psql count.users' 'sql psql kek' 'sql psql encoding' 'dump pg_dump' \
    'restore-list pg_restore' 'dump-version pg_dump_version'; do
    grep -qx "${want%% *} ${BK_PGC_ID[17]} ${want#* }" "$BATS_TEST_TMPDIR/chosen" || { echo "missing: $want"; cat "$DB/db-runs"; return 1; }
  done
  # Every database call was a client container: as many docker runs of a client as calls.
  [ "$(wc -l <"$DB/db-runs")" -eq "$(wc -l <"$DB/db-calls")" ] || return 1
  if grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG"; then echo "a call in a bundled service"; return 1; fi
  # Step 12 of an upgrade on this deployment: the snapshot after is taken by the chosen client.
  : >"$DB/db-runs"
  : >"$FAKE_DOCKER_LOG"
  bk_libs || return 1
  # shellcheck disable=SC1091
  . "$SRC/lib/upgrade_steps.sh"
  cx_state_load "$ROOT/state.json"
  CX_OVERLAYS=external-database
  cx_dbx_prepare >/dev/null
  [ -z "$CX_DBX_FAIL" ] && [ "$CX_DB_EXT_ID" = "${BK_PGC_ID[17]}" ] || { echo "prepare: $CX_DBX_FAIL"; return 1; }
  : >"$DB/db-runs"
  CX_UP_PRE_EXTERNAL_DB=1 CX_UP_SNAP="" CX_UP_TARGET=1.13.2 CX_UP_HEALTH_VER=1.13.2
  CX_LOG_FILE=$BATS_TEST_TMPDIR/upgrade-20260930-101502.log
  cx_up_post_checks 12 >/dev/null 2>&1 || true
  [ -f "$BATS_TEST_TMPDIR/upgrade-20260930-101502.after.txt" ] || { echo "no snapshot after"; return 1; }
  [ "$(cx_snap_get "$BATS_TEST_TMPDIR/upgrade-20260930-101502.after.txt" count.users)" = 5 ] || return 1
  grep -qx "sql ${BK_PGC_ID[17]} psql count.users" "$DB/db-runs" || { cat "$DB/db-runs"; return 1; }
  if grep -v "^sql ${BK_PGC_ID[17]} " "$DB/db-runs"; then echo "a call outside the chosen client"; return 1; fi
  if grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG"; then echo "a call in a bundled service"; return 1; fi
}

@test "database client (external): no client chosen yet, no snapshot after an upgrade and no call at all" {
  bk_libs || return 1
  # shellcheck disable=SC1091
  . "$SRC/lib/upgrade_steps.sh"
  CX_OVERLAYS=external-database CX_DB_EXT_ID=""
  CX_UP_PRE_EXTERNAL_DB=1 CX_UP_SNAP="" CX_UP_TARGET=1.13.2 CX_UP_HEALTH_VER=1.13.2
  CX_LOG_FILE=$BATS_TEST_TMPDIR/upgrade-20260930-101502.log
  cx_up_post_checks 12 >/dev/null 2>&1 || true
  [ ! -e "$BATS_TEST_TMPDIR/upgrade-20260930-101502.after.txt" ] || return 1
  [ ! -s "$DB/db-runs" ] && ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG"
}

# ---------- the client and the server ----------

@test "external: a server of 16, 17 or 18 is exported by the client of its own major; the probe always runs on 18" {
  for v in 16.4 17.6 18.1; do
    again
    bk_server "$v"
    printf 'pg_dump (PostgreSQL) %s\n' "${v%%.*}.2" >"$DB/pg_dump_version"
    ok_run en || return 1
    local m=${v%%.*}
    [ "$(head -n 1 "$DB/db-runs")" = "sql ${BK_PGC_ID[18]} psql server_version_num" ] || { cat "$DB/db-runs"; return 1; }
    grep -qx "dump ${BK_PGC_ID[$m]} pg_dump" "$DB/db-runs" || { echo "$v"; cat "$DB/db-runs"; return 1; }
    grep -qx "restore-list ${BK_PGC_ID[$m]} pg_restore" "$DB/db-runs" || return 1
    grep -qx "dump-version ${BK_PGC_ID[$m]} pg_dump_version" "$DB/db-runs" || return 1
    [ "$(grep -c ' pg_dump$' "$DB/db-runs")" -eq 1 ] || return 1
    [ "$(bk_mf tool.dump_image)" = "pgclient$m" ] && [ "$(bk_mf db.server_major)" = "$m" ] || return 1
    [ "$(bk_mf db.server_version)" = "$v" ] && [ "$(bk_mf db.dump_tool_version)" = "$m.2" ] || return 1
    [[ $output == *"Export tool: PostgreSQL $m client (shipped with this release, verified)"* ]] || { echo "$output"; return 1; }
  done
}

@test "external: PostgreSQL 15 or 19 has no client of its major: refused before any stop, word for word (zh-TW, en)" {
  bk_server 15.8
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] The external database runs PostgreSQL 15.8; this release carries
       export tools for 16, 17 and 18, and the script only uses the tool
       of the server's own major version. Nothing was stopped. Use your
       own database backup procedure; an upgrade can take your own backup
       instead (--backup-ref).
EOF
  no_stop || return 1
  again
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 外接資料庫是 PostgreSQL 15.8，這個版本只帶 16、17、18 的匯出工具，
       腳本只用與伺服器主版本相同的工具。沒有停止任何服務。
       請用你們自己的資料庫備份程序；升級時可改用自備備份（--backup-ref）。
EOF
  no_stop || return 1
  # The probe asked; no export was tried with an older or newer client.
  ! grep -q ' pg_dump$' "$DB/db-runs" || return 1
  again
  bk_server 19.1
  backup_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *"[FAIL] The external database runs PostgreSQL 19.1; this release carries"* ]] \
    || { echo "$output"; return 1; }
  no_stop
}

@test "external: a client image not on this host: refused before any stop, word for word (zh-TW, en)" {
  # The probe's client (18) missing; then the one of the server's major (17).
  grep -vxF "${BK_PGC_ID[18]}" "$DB/images" >"$DB/images.new" && mv "$DB/images.new" "$DB/images"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] This host does not have the export tool images for the external
       database (PostgreSQL 16/17/18 clients, obtained at install or
       upgrade). Nothing was stopped. Load the offline image bundle of this
       release (1.13.0):
  sudo /opt/custodexa/custodexa.sh load custodexa-images-1.13.0-amd64.tar
EOF
  no_stop || return 1
  [ ! -s "$DB/db-runs" ] || { echo "a client ran"; return 1; }
  again
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 這台主機沒有外接資料庫用的匯出工具映像（PostgreSQL 16／17／18 客戶端，
       應在安裝或升級時取得）。沒有停止任何服務。請載入這個版本（1.13.0）的
       離線映像包：
  sudo /opt/custodexa/custodexa.sh load custodexa-images-1.13.0-amd64.tar
EOF
  no_stop || return 1
  again
  printf '%s\n' "${BK_PGC_ID[16]}" "${BK_PGC_ID[18]}" >"$DB/images"
  backup_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *"[FAIL] This host does not have the export tool images for the external"* ]] \
    || { echo "$output"; return 1; }
  no_stop || return 1
  grep -q 'missing=pgclient17' "$ROOT/logs/backup-20260930-101502.log"
}

@test "external: the server cannot be reached or refuses the sign-in: refused before any stop, word for word (zh-TW, en), the reason in the log" {
  printf '2\n' >"$DB/connect.rc"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] Cannot reach the external database db.example.internal:5432 (with
       DB_USER, DB_NAME and DB_SSLMODE from .env). The reason is in the
       log file. Nothing was stopped.
  Check in this order:
    1. This host can reach that address and port (name lookup, firewall)
    2. The backend can reach the database now:
       sudo /opt/custodexa/custodexa.sh status --lang en
    3. DB_SSLMODE matches the server's TLS setup
    4. The password of DB_USER was not changed on the database side
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
  no_stop || return 1
  grep -q 'Connection refused' "$ROOT/logs/backup-20260930-101502.log" || return 1
  again
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 連不上外接資料庫 db.example.internal:5432（使用 .env 的 DB_USER、
       DB_NAME、DB_SSLMODE）。原因記在紀錄檔。沒有停止任何服務。
  可依序檢查：
    1. 這台主機能否連到該位址與連接埠（名稱解析、防火牆）
    2. 後端目前能否連上資料庫：sudo /opt/custodexa/custodexa.sh status --lang zh-TW
    3. DB_SSLMODE 與伺服器的 TLS 設定是否相符
    4. DB_USER 的密碼是否在資料庫端被改過
  紀錄檔 /opt/custodexa/logs/backup-20260930-101502.log
EOF
  no_stop
}

# The password of these tests: every character the pgpass format escapes, a space and a #.
PW='p:w\x y#z-secret-0004'

# no_password: the password is in no docker argument, no client's -e, no docker client's
# environment, not on the screen and not in the log.
no_password() {
  local f
  for f in "$FAKE_DOCKER_LOG" "$DB/run.argv" "$DB/run.env" "$DB/db-env" "$ROOT"/logs/*.log; do
    if grep -qF -- 'z-secret-0004' "$f"; then echo "password in ${f##*/}"; return 1; fi
  done
  [[ $output != *z-secret-0004* ]]
}

# no_pgpass: no pgpass file and no private folder for one is left under backups/.
no_pgpass() {
  [ -z "$(find "$ROOT/backups" \( -name .pgpass -o -name '.db-client-*' \) 2>/dev/null)" ] \
    || { find "$ROOT/backups" -ls; return 1; }
}

@test "external: a password with : \\ space #: a pgpass file 0600 escaped as the format wants, gone afterwards; never an argument, an environment or in the log" {
  bk_env_set DB_PASSWORD "$PW"
  ok_run en || return 1
  # Every connecting client got the file, private, with : and \ escaped.
  [ -s "$DB/pgpass.seen" ] || return 1
  if grep -v '^600 ' "$DB/pgpass.seen"; then echo "not 0600"; return 1; fi
  [ "$(sort -u "$DB/pgpass.content")" = '*:*:*:*:p\:w\\x y#z-secret-0004' ] || { cat "$DB/pgpass.content"; return 1; }
  [ "$(grep -c '' "$DB/pgpass.seen")" -eq "$(grep -c '^\(sql\|dump\) ' "$DB/db-runs")" ] || return 1
  # The probe's file in a private folder of its own; the export's in the temporary folder.
  grep -q " $ROOT/backups/.db-client-[0-9]*/.pgpass$" "$DB/pgpass.seen" || { cat "$DB/pgpass.seen"; return 1; }
  grep -q " $ROOT/backups/.partial-20260930-101502/.pgpass$" "$DB/pgpass.seen" || { cat "$DB/pgpass.seen"; return 1; }
  # The client's environment: the pgpass file and the empty home, nothing else.
  [ "$(sort -u "$DB/run.env")" = "$(printf '%s\n' HOME=/cx/home PGPASSFILE=/cx/pgpass)" ] || { sort -u "$DB/run.env"; return 1; }
  no_password || return 1
  no_pgpass || return 1
  # Nor in the backup file's members other than the copy of .env.
  extract_all
  for f in "$X"/*; do
    [ "${f##*/}" = env.bak ] && continue
    if grep -qF 'z-secret-0004' "$f"; then echo "password in ${f##*/}"; return 1; fi
  done
}

@test "external: interrupted (SIGTERM to the script, or to its whole process group) in the probe or in the export: no pgpass file is left" {
  bk_env_set DB_PASSWORD "$PW"
  local OUT=$BATS_TEST_TMPDIR/out point how rc
  for how in script group; do
    for point in db.psql db.pg_dump; do
      again
      : >"$DB/pause.$point"
      if [ "$how" = group ]; then
        # A process group of its own, signalled as a whole (a closed terminal, a service manager):
        # the client and its shell end at once and only the script's handler is left to clean up.
        setsid bash "$ROOT/custodexa.sh" backup --lang en --yes </dev/null >"$OUT" 2>&1 &
        BK_PID=$!
      else
        backup_bg "$OUT"
      fi
      wait_for "$DB/paused.$point" || { kill -9 "$BK_PID"; cat "$OUT"; return 1; }
      # The client holds its pgpass file now.
      [ -n "$(find "$ROOT/backups" -name .pgpass)" ] || { echo "$how $point: no pgpass while it runs"; return 1; }
      if [ "$how" = group ]; then
        kill -TERM -- "-$BK_PID"
      else
        kill -TERM "$BK_PID"
      fi
      # Signalled alone, the script handles the signal once the query of the preview it waits for
      # returns; the export is a background job its handler stops at once.
      : >"$DB/go.$point"
      rc=0
      wait "$BK_PID" || rc=$?
      [ "$rc" -ne 0 ] || { echo "$how $point: finished"; cat "$OUT"; return 1; }
      no_pgpass || { echo "$how $point"; cat "$OUT"; return 1; }
      output=$(cat "$OUT")
      no_password || return 1
      rm -f "$DB/go.$point" "$DB/paused.$point"
    done
  done
}

@test "external: every refusal is before any stop and leaves no pgpass file" {
  local c
  for c in version image connect unsupported; do
    again
    db_default
    bk_external
    case $c in
      version) bk_server 15.8 ;;
      image) : >"$DB/images" ;;
      connect) printf '2\n' >"$DB/connect.rc" ;;
      unsupported) printf 'pg_trgm 1.6\n' >"$DB/extensions" ;;
    esac
    backup_run en --yes
    [ "$status" -eq 3 ] || { echo "$c: $status"; echo "$output"; return 1; }
    no_stop || { echo "$c"; return 1; }
    no_pgpass || { echo "$c"; return 1; }
    rm -f "$DB/connect.rc" "$DB/extensions"
  done
}

# ---------- TLS ----------

# tls_case <DB_SSLMODE | - | ""> <PGSSLROOTCERT | - | system | file>: .env set that way; "-" leaves the
# key out, file names the CA file under the audit mount.
tls_case() {
  if [ "$1" = - ]; then bk_env_set DB_SSLMODE -; else bk_env_set DB_SSLMODE "$1"; fi
  case $2 in
    -) bk_env_set PGSSLROOTCERT - ;;
    file) ca_file; bk_env_set PGSSLROOTCERT "$CA_CTR" ;;
    *) bk_env_set PGSSLROOTCERT "$2" ;;
  esac
}

# tls_check <sslmode> <sslrootcert | -> <trust> <verify> <connection line>: what the export was
# given, what the manifest says, what the preview said, and db-ca.pem exactly when the trust is a
# file.
tls_check() {
  local root
  root=$(conn sslrootcert)
  [ "$(conn sslmode)" = "$1" ] || { echo "sslmode $(conn sslmode), not $1"; return 1; }
  if [ "$2" = - ]; then
    [ -z "$root" ] && [[ $(dump_argv) != *sslrootcert* ]] || { echo "sslrootcert $root"; return 1; }
  else
    [ "$root" = "$2" ] || { echo "sslrootcert $root, not $2"; return 1; }
  fi
  [ "$(bk_mf db.tls_trust)" = "$3" ] && [ "$(bk_mf db.tls_verify)" = "$4" ] \
    || { echo "manifest $(bk_mf db.tls_trust)/$(bk_mf db.tls_verify), not $3/$4"; return 1; }
  [ "$(conn_line)" = "$5" ] || { echo "line: $(conn_line)"; echo "want: $5"; return 1; }
  if [ "$3" = file ]; then
    [ "$(bk_mf contents.db_ca)" = true ] && /usr/bin/tar -tf "$BK_FILE" | grep -qx db-ca.pem || return 1
    cmp <(bk_member db-ca.pem) "$ROOT/data/audit/db-ca.pem" || return 1
  else
    [ "$(bk_mf contents.db_ca)" = false ] && ! /usr/bin/tar -tf "$BK_FILE" | grep -qx db-ca.pem || return 1
  fi
  # No PGSSLROOTCERT goes into a client: its environment holds the pgpass file and the home only.
  ! grep -q '^PGSSLROOTCERT' "$DB/run.env" || return 1
  # The sslmode given is the effective mode the backend uses (unset or empty is disable; system
  # makes it verify-full).
  local eff
  eff=$(sed -n 's/^DB_SSLMODE=//p' "$ROOT/.env")
  eff=${eff:-disable}
  [ "$(sed -n 's/^PGSSLROOTCERT=//p' "$ROOT/.env")" != system ] || eff=verify-full
  [ "$(conn sslmode)" = "$eff" ] || { echo "sslmode $(conn sslmode) is not the effective $eff"; return 1; }
}

NONE='server certificate not checked'
NONE_FILE='server certificate not checked (the CA file still goes into the backup file)'
CA_SYS="server certificate checked against the system's trusted certificate authorities, host name not checked"
CA_FILE='server certificate checked against the CA file, host name not checked (the CA goes into the backup file)'
FULL_SYS="server checked against the system's trusted certificate authorities"
FULL_FILE='server checked against the CA file (the CA goes into the backup file)'
BY_SYSTEM='verify-full (set by PGSSLROOTCERT=system, as in the backend)'

@test "TLS: each row of the table: the client's sslmode and sslrootcert, the manifest's trust and verification, the preview's connection line" {
  local -a rows=(
    "disable|-|disable|-|none|none|Connection: disable, $NONE"
    "allow|-|allow|-|none|none|Connection: allow, $NONE"
    "prefer|-|prefer|-|none|none|Connection: prefer, $NONE"
    "require|-|require|-|none|none|Connection: require, $NONE"
    "verify-full|-|verify-full|system|system|full|Connection: verify-full, $FULL_SYS"
    "verify-ca|-|verify-ca|/etc/ssl/certs/ca-certificates.crt|system|ca|Connection: verify-ca, $CA_SYS"
    "require|system|verify-full|system|system|full|Connection: $BY_SYSTEM, $FULL_SYS"
    "verify-full|system|verify-full|system|system|full|Connection: verify-full, $FULL_SYS"
    "disable|file|disable|-|file|none|Connection: disable, $NONE_FILE"
    "allow|file|allow|-|file|none|Connection: allow, $NONE_FILE"
    "prefer|file|prefer|-|file|none|Connection: prefer, $NONE_FILE"
    "require|file|require|/cx/tls/root.crt|file|ca|Connection: require, $CA_FILE"
    "verify-ca|file|verify-ca|/cx/tls/root.crt|file|ca|Connection: verify-ca, $CA_FILE"
    "verify-full|file|verify-full|/cx/tls/root.crt|file|full|Connection: verify-full, $FULL_FILE"
  )
  local r mode root
  for r in "${rows[@]}"; do
    IFS='|' read -r mode root a b c d e <<<"$r"
    again
    rm -f "$ROOT/data/audit/db-ca.pem"
    tls_case "$mode" "$root"
    ok_run en || { echo "$r"; return 1; }
    tls_check "$a" "$b" "$c" "$d" "$e" || { echo "row: $r"; return 1; }
    [ "$(bk_mf db.sslmode)" = "$mode" ] || return 1
    # The CA file is mounted, read-only, exactly when the client is given it.
    if [ "$b" = /cx/tls/root.crt ]; then
      grep -qx "$ROOT/data/audit/db-ca.pem:/cx/tls/root.crt:ro" "$DB/run.mounts" || { cat "$DB/run.mounts"; return 1; }
    else
      ! grep -q ':/cx/tls/root.crt' "$DB/run.mounts" || { echo "row: $r"; cat "$DB/run.mounts"; return 1; }
    fi
  done
  # The preview in zh-TW: require with a CA file, as the design shows it.
  again
  tls_case require file
  ok_run zh-TW || return 1
  # (wrapped at a space like every line put together at run time; joined again here)
  [ "$(conn_line)" = '連線：require，以 CA 檔驗證伺服器憑證，不核對主機名稱（CA 會放進備份檔）' ] || { echo "$output"; return 1; }
}

@test "TLS: DB_SSLMODE unset or empty, with PGSSLROOTCERT unset, a file or system: the effective mode, db.sslmode kept as it is (empty)" {
  local s r
  for s in - ""; do
    for r in - file system; do
      again
      rm -f "$ROOT/data/audit/db-ca.pem"
      tls_case "$s" "$r"
      ok_run en || { echo "DB_SSLMODE=$s PGSSLROOTCERT=$r"; return 1; }
      case $r in
        -) tls_check disable - none none "Connection: disable, $NONE" ;;
        file) tls_check disable - file none "Connection: disable, $NONE_FILE" ;;
        system) tls_check verify-full system system full "Connection: $BY_SYSTEM, $FULL_SYS" ;;
      esac || { echo "DB_SSLMODE=$s PGSSLROOTCERT=$r"; return 1; }
      [ "$(bk_mf db.sslmode)" = "" ] || { echo "db.sslmode $(bk_mf db.sslmode)"; return 1; }
    done
  done
}

@test "TLS: allow and prefer with a CA file: no sslrootcert, no PGSSLROOTCERT for the client, HOME an empty tmpfs; db-ca.pem still goes in" {
  local m
  for m in allow prefer; do
    again
    tls_case "$m" file
    ok_run en || return 1
    tls_check "$m" - file none "Connection: $m, $NONE_FILE" || return 1
    # Every client: HOME on an empty tmpfs of its own, no root certificate mounted.
    [ "$(sort -u "$DB/run.tmpfs")" = /cx/home ] || { cat "$DB/run.tmpfs"; return 1; }
    [ "$(grep -c -- '--tmpfs /cx/home' "$DB/run.argv")" -eq "$(grep -c '' "$DB/run.argv")" ] || return 1
    grep -qx HOME=/cx/home "$DB/run.env" || return 1
    ! grep -q 'root.crt' "$DB/run.mounts" || return 1
    [ "$(bk_mf db.sslmode)" = "$m" ] || return 1
  done
}

@test "TLS: verify-ca without a CA file, and a client image without the system CA file: refused before any stop" {
  tls_case verify-ca -
  # The client of the server's major (17) has none.
  printf '%s\n' "${BK_PGC_ID[17]}" >"$DB/sysca.absent"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] The external database has settings this backup does not support; on
       a new database server they could not be rebuilt as they are:
         - DB_SSLMODE=verify-ca, but the export tool has no system CA file to
           check the server the same way
       Nothing was stopped. Use your own database backup procedure, or
       change the items above first.
EOF
  no_stop || return 1
  ! grep -q ' pg_dump$' "$DB/db-runs" || return 1
  # The probe's client (18) has none: refused before it asks the server anything.
  again
  printf '%s\n' "${BK_PGC_ID[18]}" >"$DB/sysca.absent"
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 外接資料庫有這個備份不支援的設定，換到新的資料庫伺服器時無法照原樣重建：
         - DB_SSLMODE=verify-ca 但匯出工具裡沒有系統 CA 檔，無法以相同方式驗證伺服器
       沒有停止任何服務。請用你們自己的資料庫備份程序，或先調整上面各項。
EOF
  no_stop || return 1
  [ ! -s "$DB/db-runs" ] || { cat "$DB/db-runs"; return 1; }
  # Both have it: the backup goes on, checking the server with that file.
  again
  : >"$DB/sysca.absent"
  ok_run en || return 1
  grep -qx "sysca ${BK_PGC_ID[17]}" "$DB/events" || return 1
  [ "$(conn sslrootcert)" = /etc/ssl/certs/ca-certificates.crt ]
}

@test "TLS: PGSSLROOTCERT under the audit mount: db-ca.pem is that file byte for byte, contents.db_ca=true" {
  tls_case verify-full file
  printf 'second line, no newline at the end' >>"$ROOT/data/audit/db-ca.pem"
  ok_run en || return 1
  cmp <(bk_member db-ca.pem) "$ROOT/data/audit/db-ca.pem" || return 1
  [ "$(bk_mf contents.db_ca)" = true ] && [ "$(bk_mf db.tls_trust)" = file ] || return 1
  [[ " $(bk_mf contents.members) " == *" db-ca.pem SHA256SUMS "* ]] || return 1
  /usr/bin/tar -tvf "$BK_FILE" | grep -q '^-rw------- .* db-ca.pem$' || return 1
  extract_all
  grep -q ' db-ca.pem$' "$X/SHA256SUMS"
}

@test "TLS: a CA, a client certificate or key path the script cannot find, a key in a folder the backup packs: refused before any stop" {
  tls_case verify-full -
  bk_env_set PGSSLROOTCERT /etc/ssl/db-ca.pem
  mkdir -p "$ROOT/data/audit/keys"
  printf 'key\n' >"$ROOT/data/audit/keys/client.key"
  bk_env_set PGSSLKEY /var/log/custodexa/audit/keys/client.key
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] The external database has settings this backup does not support; on
       a new database server they could not be rebuilt as they are:
         - CA file PGSSLROOTCERT=/etc/ssl/db-ca.pem is not where the script
           can find it
         - Client private key PGSSLKEY is inside the audit folder, which is
           packed into the backup
       Nothing was stopped. Use your own database backup procedure, or
       change the items above first.
EOF
  no_stop || return 1
  [ ! -s "$DB/db-runs" ] || return 1
  again
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 外接資料庫有這個備份不支援的設定，換到新的資料庫伺服器時無法照原樣重建：
         - CA 檔 PGSSLROOTCERT=/etc/ssl/db-ca.pem 不在腳本找得到的位置
         - 用戶端私鑰 PGSSLKEY 放在會被打包的稽核目錄下
       沒有停止任何服務。請用你們自己的資料庫備份程序，或先調整上面各項。
EOF
  no_stop || return 1
  # Each one alone: a key under the recordings, a key or a certificate outside the mounts, a CA
  # path with a .. part.
  local -a cases=(
    "PGSSLKEY|/var/lib/custodexa/recordings/client.key|Client private key PGSSLKEY is inside the recordings folder"
    "PGSSLKEY|/etc/ssl/private/client.key|Client private key PGSSLKEY=/etc/ssl/private/client.key is not where the script"
    "PGSSLCERT|/etc/ssl/client.crt|Client certificate PGSSLCERT=/etc/ssl/client.crt is not where the"
    "PGSSLROOTCERT|/var/log/custodexa/audit/../db-ca.pem|CA file PGSSLROOTCERT=/var/log/custodexa/audit/../db-ca.pem is not"
  )
  local c k v want
  for c in "${cases[@]}"; do
    IFS='|' read -r k v want <<<"$c"
    again
    bk_env_set PGSSLROOTCERT -
    bk_env_set PGSSLKEY -
    bk_env_set PGSSLCERT -
    bk_env_set "$k" "$v"
    backup_run en --yes
    [ "$status" -eq 3 ] && [[ $output == *"  - $want"* ]] || { echo "$c"; echo "$output"; return 1; }
    no_stop || return 1
  done
}

@test "TLS: a client certificate: certificate and key mounted read-only for the client, the key in no member, db.tls_client_cert=true" {
  tls_case verify-full -
  printf 'CLIENT-CERT-0005\n' >"$ROOT/data/exports/client.crt"
  printf 'CLIENT-PRIVATE-KEY-0006\n' >"$ROOT/data/exports/client.key"
  bk_env_set PGSSLCERT "$CERT_CTR"
  bk_env_set PGSSLKEY "$KEY_CTR"
  ok_run en || return 1
  [ "$(bk_mf db.tls_client_cert)" = true ] || return 1
  [ "$(conn sslcert)" = /cx/tls/client.crt ] || [[ $(dump_argv) == *" sslcert=/cx/tls/client.crt"* ]] || { dump_argv; return 1; }
  [[ $(dump_argv) == *" sslkey=/cx/tls/client.key"* ]] || { dump_argv; return 1; }
  grep -qx "$ROOT/data/exports/client.key:/cx/tls/client.key:ro" "$DB/run.mounts" || { cat "$DB/run.mounts"; return 1; }
  grep -qx "$ROOT/data/exports/client.crt:/cx/tls/client.crt:ro" "$DB/run.mounts" || return 1
  # The key is in no member, nor inside the packed archives.
  extract_all
  local f
  for f in "$X"/*; do
    case $f in
      *.tar.gz) /usr/bin/tar -xzOf "$f" ;;
      *) cat "$f" ;;
    esac | grep -qF CLIENT-PRIVATE-KEY-0006 && { echo "the key is in ${f##*/}"; return 1; }
  done
  # Without one: false.
  again
  bk_env_set PGSSLCERT -
  bk_env_set PGSSLKEY -
  ok_run en || return 1
  [ "$(bk_mf db.tls_client_cert)" = false ]
}

# ---------- what the dump leaves out ----------

@test "dependencies: a tablespace, another owner, an extension: refused before any stop, each on its own line (zh-TW, en)" {
  printf '%s|3\n' "$(bk_hex fast_ssd)" >"$DB/tablespaces"
  printf '%s|12\n' "$(bk_hex report_owner)" >"$DB/owners"
  printf 'pg_trgm 1.6\n' >"$DB/extensions"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] The external database has settings this backup does not support; on
       a new database server they could not be rebuilt as they are:
         - Custom tablespace: fast_ssd (3 objects)
         - Owners other than custodexa_app: report_owner (12 objects)
         - Extension: pg_trgm 1.6
       Nothing was stopped. Use your own database backup procedure, or
       change the items above first.
EOF
  no_stop || return 1
  again
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(refused_screen) - <<'EOF' || return 1
[FAIL] 外接資料庫有這個備份不支援的設定，換到新的資料庫伺服器時無法照原樣重建：
         - 自訂表空間：fast_ssd（3 個物件）
         - 擁有者不只 custodexa_app：另有 report_owner（12 個物件）
         - 擴充套件：pg_trgm 1.6
       沒有停止任何服務。請用你們自己的資料庫備份程序，或先調整上面各項。
EOF
  no_stop || return 1
  # Each one alone is enough; a name that needs quoting is shown quoted.
  local f
  for f in tablespaces owners extensions; do
    again
    : >"$DB/tablespaces"
    : >"$DB/owners"
    : >"$DB/extensions"
    case $f in
      tablespaces) printf '%s|1\n' "$(bk_hex 'Fast SSD')" >"$DB/tablespaces"; want='  - Custom tablespace: "Fast SSD" (1 objects)' ;;
      owners) printf '%s|2\n' "$(bk_hex 'report owner')" >"$DB/owners"; want='  - Owners other than custodexa_app: "report owner" (2 objects)' ;;
      extensions) printf 'postgis 3.4.2\n' >"$DB/extensions"; want='  - Extension: postgis 3.4.2' ;;
    esac
    backup_run en --yes
    [ "$status" -eq 3 ] && [[ $output == *"$want"* ]] || { echo "$f"; echo "$output"; return 1; }
    no_stop || return 1
  done
}

@test "dependencies: public owned by pg_database_owner and the tables by DB_USER passes; a table of report_owner in public is refused" {
  # The fake answers the owners query as a server would: nothing when public belongs to
  # pg_database_owner and every object to DB_USER, because the query leaves exactly that out.
  : >"$DB/owners"
  ok_run en || return 1
  local q
  q=$(grep -- '--entrypoint psql ' "$DB/run.argv" | grep relowner | tail -n 1)
  [[ $q == *"NOT (n.nspname = 'public' AND n.nspowner = 'pg_database_owner'::regrole)"* ]] || { echo "$q"; return 1; }
  # Only the schema itself is excused: the objects in public are counted with every other.
  [[ $q == *"SELECT c.relowner FROM pg_class c"* && $q != *"c.relnamespace <> 'public'"* ]] || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = "" ] || return 1
  # public grants to pg_database_owner by default: never listed, whatever the server answers.
  again
  printf '%s\n' "$(bk_hex pg_database_owner)" >"$DB/grants"
  ok_run en || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = "" ] || return 1
  [[ $output != *"grants privileges to other roles"* ]] || return 1
  again
  : >"$DB/grants"
  printf '%s|1\n' "$(bk_hex report_owner)" >"$DB/owners"
  backup_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *"  - Owners other than custodexa_app: report_owner (1 objects)"* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "grants to other roles: the backup completes, the roles hex-encoded in the manifest, the closing screen warns (zh-TW, en); pg_ roles never listed" {
  printf '%s\n' "$(bk_hex 'report reader')" "$(bk_hex monitor)" "$(bk_hex pg_monitor)" "$(bk_hex monitor)" >"$DB/grants"
  ok_run en || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = "$(bk_hex monitor) $(bk_hex 'report reader')" ] || { bk_mf db.extra_grant_roles_hex; return 1; }
  diff <(printf '%s\n' "$output" | sed -n '/\[WARN\] The external database grants/,+2p') - <<'EOF' || { echo "$output"; return 1; }
  [WARN] The external database grants privileges to other roles:
         monitor, "report reader". On a new database server those roles have
         to exist first, or the restored privileges will differ.
EOF
  # Decoded, the manifest gives the roles back.
  bk_libs || return 1
  local h names=""
  for h in $(bk_mf db.extra_grant_roles_hex); do names+="$(cx_dbx_unhex "$h")|"; done
  [ "$names" = 'monitor|report reader|' ] || { echo "$names"; return 1; }
  again
  ok_run zh-TW || return 1
  diff <(printf '%s\n' "$output" | sed -n '/\[WARN\] 外接資料庫裡有權限/,+1p') - <<'EOF' || { echo "$output"; return 1; }
  [WARN] 外接資料庫裡有權限授予其他角色：monitor、"report reader"。
         換到新的資料庫伺服器時，這些角色要先建立，否則還原後的權限會不同。
EOF
  # A role named report_reader, as the scenario has it: shown as it is.
  again
  printf '%s\n' "$(bk_hex report_reader)" >"$DB/grants"
  ok_run en || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = "$(bk_hex report_reader)" ] || return 1
  [[ $output == *"[WARN] The external database grants privileges to other roles:
         report_reader. On a new database server those roles have"* ]] || { echo "$output"; return 1; }
}

# ---------- the manifest ----------

@test "manifest (external): every reserved key with its value; the export tool is the client of the script's release, its digest from tool-MANIFEST.json" {
  tls_case require file
  bk_env_set EXTERNAL_DB_PORT 6432
  printf '%s\n' "$(bk_hex monitor)" >"$DB/grants"
  release_next
  bk_manifest_clients "$ROOT/releases/1.13.2/MANIFEST.json"
  # The script's release pins another 17 than the installed one.
  jq '.images.pgclient17.index_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"' \
    "$ROOT/releases/1.13.2/MANIFEST.json" >"$BATS_TEST_TMPDIR/m" && cp "$BATS_TEST_TMPDIR/m" "$ROOT/releases/1.13.2/MANIFEST.json"
  run bash "$BK_SCRIPT" backup --lang en --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  extract_all
  [ "$(bk_mf db.location)" = external ] || return 1
  [ "$(bk_mf db.external_host)" = db.example.internal ] && [ "$(bk_mf db.external_port)" = 6432 ] || return 1
  [ "$(bk_mf db.sslmode)" = require ] && [ "$(bk_mf db.tls_trust)" = file ] && [ "$(bk_mf db.tls_verify)" = ca ] || return 1
  [ "$(bk_mf db.tls_client_cert)" = false ] && [ "$(bk_mf contents.db_ca)" = true ] || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = 6d6f6e69746f72 ] || return 1
  [ "$(bk_mf db.user)" = custodexa_app ] || return 1
  [ "$(bk_mf tool.dump_manifest)" = tool ] && [ "$(bk_mf tool.dump_image)" = pgclient17 ] || return 1
  [ "$(bk_mf tool.dump_image_digest)" = "$(jq -r .images.pgclient17.index_digest "$X/tool-MANIFEST.json")" ] || return 1
  [ "$(bk_mf tool.dump_image_digest)" = sha256:2222222222222222222222222222222222222222222222222222222222222222 ] || return 1
  cmp "$X/tool-MANIFEST.json" "$ROOT/releases/1.13.2/MANIFEST.json" || return 1
  [[ $(dump_argv) == *" port='6432' "* ]] || { dump_argv; return 1; }
  # It reads back and passes the check, with the same keys as a bundled file.
  bk_libs || return 1
  local -A m=()
  local -a k=()
  cx_flat_parse "$X/backup-manifest.json" m k || { echo "line $CX_FLAT_BAD"; return 1; }
  cx_pb_manifest_check m || { echo "bad: $CX_PB_BAD_KEY"; return 1; }
  diff <(bk_member backup-manifest.json | jq -r 'keys[]') <(jq -r 'keys[]' "$TESTS_DIR/fixtures/manifest-bundled-reference.json")
}

@test "role names: report reader, 報表, a\"b, a\\b, and x y against x + y: each list decodes to its set, the two lists differ, unique in byte order" {
  bk_libs || return 1
  # list <names...>: the manifest value for these roles.
  list() {
    local -a h=()
    local n
    for n in "$@"; do h+=("$(cx_dbx_hex "$n")"); done
    cx_dbx_hex_list "${h[@]}"
  }
  # names <value>: the decoded names, one per line, in the value's order.
  names() {
    local h
    for h in $1; do printf '%s\n' "$(cx_dbx_unhex "$h")"; done
  }
  local a b
  a=$(list 'report reader' '報表' 'a"b' 'a\b' 'x y' 'report reader')
  diff <(names "$a" | LC_ALL=C sort) <(printf '%s\n' 'report reader' '報表' 'a"b' 'a\b' 'x y' | LC_ALL=C sort) || return 1
  # Unique, in byte order of the names (the hex strings sort the same way).
  [ "$(printf '%s\n' $a | wc -l)" -eq 5 ] || { echo "$a"; return 1; }
  [ "$(printf '%s\n' $a | LC_ALL=C sort -c && echo sorted)" = sorted ] || return 1
  [[ $a =~ ^([0-9a-f]{2})+( ([0-9a-f]{2})+)*$ ]] || return 1
  [ "$(cx_dbx_hex '報表')" = "$(bk_hex '報表')" ] && [ "$(cx_dbx_hex 'a\b')" = 615c62 ] || return 1
  b=$(list x y)
  [ "$(list 'x y')" != "$b" ] && [ "$b" = '78 79' ] && [ "$(list 'x y')" = 782079 ] || return 1
  diff <(names "$b") <(printf '%s\n' x y) || return 1
  # As the closing screen shows them.
  [ "$(cx_dbx_show_name "$(cx_dbx_hex 'a"b')")" = '"a""b"' ] || return 1
  [ "$(cx_dbx_show_name "$(cx_dbx_hex 'report reader')")" = '"report reader"' ] || return 1
  [ "$(cx_dbx_show_name "$(cx_dbx_hex '報表')")" = '"報表"' ] || return 1
  [ "$(cx_dbx_show_name "$(cx_dbx_hex report_reader)")" = report_reader ] || return 1
  [ "$(cx_dbx_show_name "$(cx_dbx_hex "$(printf 'a\tb')")")" = '"a\x09b"' ] || return 1
  # Two databases: one grants to "report reader" and 報表, the other to report and reader.
  printf '%s\n' "$(bk_hex 'report reader')" "$(bk_hex '報表')" >"$DB/grants"
  ok_run en || return 1
  a=$(bk_mf db.extra_grant_roles_hex)
  again
  printf '%s\n' "$(bk_hex report)" "$(bk_hex reader)" >"$DB/grants"
  ok_run en || return 1
  b=$(bk_mf db.extra_grant_roles_hex)
  [ "$a" != "$b" ] || return 1
  diff <(names "$a") <(printf '%s\n' 'report reader' '報表') || return 1
  diff <(names "$b") <(printf '%s\n' reader report)
}

@test "role names: report and reader are written 726561646572 7265706f7274, word for word" {
  printf '%s\n' "$(bk_hex report)" "$(bk_hex reader)" >"$DB/grants"
  ok_run en || return 1
  [ "$(bk_mf db.extra_grant_roles_hex)" = '726561646572 7265706f7274' ] || { bk_mf db.extra_grant_roles_hex; return 1; }
  [ "$(bk_hex 'report reader')" = 7265706f727420726561646572 ]
}

@test "manifest check: the bundled reference manifest reads as valid; an external one without any of its reserved keys is refused" {
  ok_run en || return 1
  extract_all
  bk_libs || return 1
  local -A m=()
  local -a k=()
  cx_flat_parse "$TESTS_DIR/fixtures/manifest-bundled-reference.json" m k || { echo "line $CX_FLAT_BAD"; return 1; }
  cx_pb_manifest_check m || { echo "reference: $CX_PB_BAD_KEY"; return 1; }
  # A bundled file of a writer that left the reserved keys out reads them as empty or false.
  local key
  for key in db.external_host db.external_port db.sslmode db.tls_trust db.tls_verify db.tls_client_cert \
    db.extra_grant_roles_hex contents.db_ca; do
    jq --arg k "$key" 'del(.[$k])' "$TESTS_DIR/fixtures/manifest-bundled-reference.json" >"$BATS_TEST_TMPDIR/b.json"
    m=() k=()
    cx_flat_parse "$BATS_TEST_TMPDIR/b.json" m k || return 1
    cx_pb_manifest_check m || { echo "bundled without $key: $CX_PB_BAD_KEY"; return 1; }
  done
  # The external file as made passes; without any one reserved key it does not.
  m=() k=()
  cx_flat_parse "$X/backup-manifest.json" m k && cx_pb_manifest_check m || { echo "as made: $CX_PB_BAD_KEY"; return 1; }
  for key in db.external_host db.external_port db.sslmode db.tls_trust db.tls_verify db.tls_client_cert \
    db.extra_grant_roles_hex contents.db_ca; do
    jq --arg k "$key" 'del(.[$k])' "$X/backup-manifest.json" >"$BATS_TEST_TMPDIR/e.json"
    m=() k=()
    cx_flat_parse "$BATS_TEST_TMPDIR/e.json" m k || return 1
    ! cx_pb_manifest_check m || { echo "external without $key was accepted"; return 1; }
    [ "$CX_PB_BAD_KEY" = "$key" ] || { echo "without $key: $CX_PB_BAD_KEY"; return 1; }
  done
  # The cross checks: a pair not in the table, the CA flag against the trust, the tool, the roles.
  bad() { # <key> <value>: the external manifest with that value is refused
    jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$X/backup-manifest.json" >"$BATS_TEST_TMPDIR/e.json"
    m=() k=()
    cx_flat_parse "$BATS_TEST_TMPDIR/e.json" m k || return 1
    ! cx_pb_manifest_check m || { echo "$1=$2 was accepted"; return 1; }
  }
  bad db.tls_verify none || return 1
  bad contents.db_ca true || return 1
  bad db.external_host "" || return 1
  bad tool.dump_manifest release || return 1
  bad tool.dump_image pgclient16 || return 1
  bad db.extra_grant_roles_hex '7265706f7274 726561646572' || return 1
  bad db.extra_grant_roles_hex 'report' || return 1
  bad db.extra_grant_roles_hex '726561646572 726561646572'
}
