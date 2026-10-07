# shellcheck shell=bash
# about: the restore procedure of the operations guide for a deployment with an external database (docs/ops/backup-and-restore.md 5.2, then 5 with step 5 replaced by the two blocks of 5.3), taken from the guide at run time and run as written on a real backup file of a PostgreSQL 17 deployment (verify-full with a CA file, roles named with a space and in Chinese) onto another PostgreSQL 17 server; pg_restore exits 0 with the password typed at its prompt, the loaded database equals snapshot.txt and the backend starts on the new server
# needs: package
# images: pg17 openssl-3.5.4

readonly DX_DOC=/src/docs/ops/backup-and-restore.md
readonly DX_SRC_PORT=15617 DX_TGT_PORT=15717
readonly DX_AUD_CTR=/var/log/custodexa/audit/it-tls

# dx_block <first heading> <next heading> <n>: the n-th (from 1) bash code block between two
# headings of the guide, as written.
dx_block() {
  awk -v a="$1" -v b="$2" -v n="$3" '
    index($0, a) == 1 { on = 1; next }
    on && index($0, b) == 1 { exit }
    on && /^```bash$/ { k++; if (k == n) { inb = 1; next } }
    inb && /^```$/ { exit }
    inb { print }
  ' "$DX_DOC"
}

# dx_guide: the blocks of the restore as the guide has them for an unencrypted file of an external
# database: 5.2 (the first block, the C block for a .tar, the last block), then section 5, then the
# two blocks of 5.3 (5.3 replaces section 5 step 5; dx_script puts them in its place).
dx_guide() {
  dx_block '### 5.2' '## 6.' 1
  dx_block '### 5.2' '## 6.' 2
  dx_block '### 5.2' '## 6.' 4
  dx_block '## 5. Restore procedure' '### 5.1' 1
  dx_block '### 5.3' '## 6.' 1
  dx_block '### 5.3' '## 6.' 2
}

# dx_script <file> <stamp> <hook>: the commands an operator types for this restore, in one shell.
# Changed from the guide, and only these:
#   "sudo -s" is left out (this runs as root already); FILE= and STAMP= get the actual values (the
#   guide says to fill them in); section 5 step 0's two assignments are skipped (the guide says
#   to); right after section 5 step 2, EXTERNAL_DB_PORT is set to the new server's (the guide's
#   "Another server" of 5.3; host, sslmode and CA file stay); section 5 step 5 is replaced by the
#   two blocks of 5.3 (as 5.3 says), with an echo line before and after the first so its output can
#   be read back; and before section 5 step 6 the hook takes the snapshot of the loaded database.
dx_script() {
  local file=$1 stamp=$2 hook=$3 load=$IT_WORK/dx-load.sh
  {
    printf '# [not in the guide] where the output of 5.3 block 1 begins\necho "== 5.3 block 1"\n'
    dx_block '### 5.3' '## 6.' 1
    printf '# [not in the guide] where it ends\necho "== 5.3 block 1 end"\n'
    dx_block '### 5.3' '## 6.' 2
    printf '# [not in the guide] the snapshot of the loaded database, before the other services start\n'
    printf 'bash %s\n' "$hook"
  } >"$load"
  {
    dx_block '### 5.2' '## 6.' 1
    dx_block '### 5.2' '## 6.' 2
    dx_block '### 5.2' '## 6.' 4
    dx_block '## 5. Restore procedure' '### 5.1' 1
  } | sed -e '/^sudo -s$/d' -e "s|^FILE=[^ ]*|FILE=$file|" -e "s|^STAMP=YYYYMMDD-HHMMSS|STAMP=$stamp|" \
    -e '/^STAMP=YYYYMMDD-HHMM$/d' -e '/^BACKUP_DIR=\.$/d' \
    -e '/^cp "${BACKUP_DIR:?}\/custodexa-env-${STAMP}.bak" "$ENV_FILE"$/a\
# [not in the guide] 5.3 "Another server": the database goes to the server on port '"$DX_TGT_PORT"'\
sed -i "s/^EXTERNAL_DB_PORT=.*/EXTERNAL_DB_PORT='"$DX_TGT_PORT"'/" "$ENV_FILE"' |
    awk -v ins="$load" '
      /^# 5\. Start postgres only/ { skip = 1; while ((getline l < ins) > 0) print l; next }
      /^# 6\. Start the remaining services/ { skip = 0 }
      !skip { print }
    '
}

# dx_hook: a script, run from the deployment folder, that takes the script's snapshot of the
# database pg_restore loaded on the new server, into $IT_WORK/dx-restored.txt.
dx_hook() {
  local f=$IT_WORK/dx-hook.sh
  {
    printf '. /src/scripts/custodexa/tests/integration/lib/snap.sh\n'
    # shellcheck disable=SC2016 # expanded by the hook
    printf 'v() { sed -n "s/^[[:space:]]*$1=//p" .env | tail -n 1; }\n'
    # shellcheck disable=SC2016
    printf 'it_snap_take %q "$(v JWT_SECRET)" docker exec -i it-pg-tgt17 psql -U "$(v DB_USER)" -d "$(v DB_NAME)" -AtX -v ON_ERROR_STOP=1 -c\n' \
      "$IT_WORK/dx-restored.txt"
  } >"$f"
  printf '%s' "$f"
}

# dx_pty <out file> <script> <password>: the script on a terminal (script(1)), as an operator runs
# it; the password is typed once pg_restore's "Password:" prompt is on the screen (15 minutes at
# most). The input stays open until the script ends. Returns the script's exit code.
dx_pty() {
  local out=$1 cmd=$2 pw=$3 fifo=$IT_WORK/dx-pty.in fd pid rc=0 i
  rm -f "$fifo"
  mkfifo "$fifo"
  : >"$out"
  script -qec "bash $cmd" /dev/null <"$fifo" >"$out" 2>&1 &
  pid=$!
  exec {fd}>"$fifo"
  DX_TYPED=0
  for ((i = 0; i < 9000; i++)); do
    if tr -d '\r' <"$out" | grep -q 'Password: *$'; then
      printf '%s\n' "$pw" >&"$fd"
      DX_TYPED=1
      break
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  wait "$pid" || rc=$?
  exec {fd}>&-
  rm -f "$fifo"
  return "$rc"
}

scenario() {
  local root=/opt/custodexa aud file stamp hook out rc bdir v
  aud=$root/data/audit/it-tls
  v=$(jq -r .version /it-run/pkg/MANIFEST.json)

  it_step "servers on $(ex_addr): src17 and tgt17, PostgreSQL 17, TLS only, certificates from the test CA"
  ex_pg_start src17 17 "$DX_SRC_PORT" tls-only
  ex_pg_start tgt17 17 "$DX_TGT_PORT" tls-only
  ex_db_create src17

  it_step "install $v: external database src17, verify-full with a CA file under the audit folder"
  it_unpack /opt
  mkdir -p "$aud"
  cp "$IT_PKI/test/ca.crt" "$aud/ca.crt"
  ex_preset "$root" "COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml" \
    "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$DX_SRC_PORT" "DB_NAME=$EX_DB" "DB_USER=$EX_USER" \
    "DB_PASSWORD=$EX_PASS" DB_SSLMODE=verify-full "PGSSLROOTCERT=$DX_AUD_CTR/ca.crt" KEK_PROVIDER=env
  it_cx "$root" install --images "$(it_bundle_file)" >/dev/null
  it_pg_sql src17 postgres 'CREATE ROLE "report reader"'
  it_pg_sql src17 postgres 'CREATE ROLE "報表"'
  ex_db_sql src17 "$EX_DB" 'GRANT SELECT ON public.schema_migrations TO "report reader", "報表"'

  it_step "backup --yes"
  ex_backup "$root"
  file=$EX_FILE
  stamp=$(sed -E 's/^custodexa-backup-[0-9.]+-([0-9]{8}-[0-9]{6})\.tar$/\1/' <<<"${file##*/}")
  it_same "the manifest has the CA file and checks the server as the backend does" "true file full" \
    "$(ex_mf contents.db_ca) $(ex_mf db.tls_trust) $(ex_mf db.tls_verify)"

  it_step "the server's administrator prepares tgt17 (5.3): the roles of the manifest, $EX_USER and an empty database"
  it_pg_sql tgt17 postgres 'CREATE ROLE "report reader"'
  it_pg_sql tgt17 postgres 'CREATE ROLE "報表"'
  ex_db_create tgt17
  it_same "the new database has the encoding, collation and character type of the manifest" \
    "$(ex_mf db.encoding)|$(ex_mf db.collate)|$(ex_mf db.ctype)" \
    "$(it_pg_sql tgt17 postgres "SELECT pg_encoding_to_char(encoding) || '|' || datcollate || '|' || datctype FROM pg_database WHERE datname = '$EX_DB'")"
  it_same "the new database is empty" 0 "$(ex_db_sql tgt17 "$EX_DB" "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"

  it_step "the guide's procedure, on a terminal ($IT_WORK/dx.sh), as changed from the guide:"
  hook=$(dx_hook)
  dx_script "$file" "$stamp" "$hook" >"$IT_WORK/dx.sh"
  diff <(dx_guide) "$IT_WORK/dx.sh" | sed 's/^/     | /' || true
  dx_pty "$IT_WORK/dx.out" "$IT_WORK/dx.sh" "$EX_PASS" && rc=0 || rc=$?
  out=$(tr -d '\r' <"$IT_WORK/dx.out")
  it_say "   their output (exit $rc, of the last command):"
  printf '%s\n' "$out" | sed 's/^/     > /'
  bdir=$root/backups/restore-$stamp

  it_check "5.2 ends with '5.2: ready'" grep -qx '5.2: ready' <<<"$out"
  it_same "the password was typed at pg_restore's prompt" 1 "$DX_TYPED"
  it_check "5.3 block 1 printed db.location external, the server's major and the client image" \
    bash -c 'grep -q "\"db.location\": \"external\"" <<<"$1" && grep -q "\"db.server_major\": \"17\"" <<<"$1" && grep -q "\"tool.dump_image\": \"pgclient17\"" <<<"$1"' _ "$out"
  it_same "5.3 block 1 decoded the roles as the server names them" "report reader|報表" \
    "$(awk '$0 == "== 5.3 block 1 end" { f = 0 } f && !/^ *"/ { print } $0 == "== 5.3 block 1" { f = 1 }' <<<"$out" | sort | paste -sd'|')"
  it_check "5.3 block 2 found the 17 client recorded in state.json" grep -qE '^PostgreSQL 17 client: sha256:[0-9a-f]{64}$' <<<"$out"
  it_check "5.3 block 2 connects to the new server with the CA file of the backup, verify-full" \
    grep -qx "host=$(ex_addr) port=$DX_TGT_PORT dbname=$EX_DB user=$EX_USER sslmode=verify-full sslrootcert=/backup/db-ca.pem" <<<"$out"
  it_check "pg_restore exit code: 0" grep -qx 'pg_restore exit code: 0' <<<"$out"
  it_check "no command printed an error" \
    bash -c '! grep -Eiq "error|no such|not found|cannot|denied|failed|refused" <<<"$1"' _ "$out"
  it_same "the password is not on the screen" 0 "$(grep -cF "$EX_PASS" <<<"$out" || true)"

  it_step "the database loaded on tgt17, against snapshot.txt"
  it_snap_same "row counts, schema_migrations and the four fingerprints equal snapshot.txt" \
    "$bdir/snapshot.txt" "$IT_WORK/dx-restored.txt"
  it_same "fp.kek equals the manifest's kek.fingerprint" \
    "$(jq -r '."kek.fingerprint"' "$bdir/backup-manifest.json")" "$(sed -n 's/^fp\.kek=//p' "$IT_WORK/dx-restored.txt")"
  it_check "the grants to the two roles came back" \
    bash -c '[ "$(docker exec it-pg-tgt17 psql -X -At -U postgres -d "$1" -c "SELECT count(*) FROM information_schema.role_table_grants WHERE table_name = '"'"'schema_migrations'"'"' AND grantee IN ('"'"'report reader'"'"', '"'"'報表'"'"')")" = 2 ]' _ "$EX_DB"

  it_step "section 6: the services run on the new server"
  for ((rc = 0; rc < 90; rc++)); do
    docker exec custodexa-backend wget -qO- http://localhost:8080/health >/dev/null 2>&1 && break
    sleep 2
  done
  it_check "the backend health check answers" docker exec custodexa-backend wget -qO- http://localhost:8080/health
  it_check "the backend holds a connection to tgt17 as $EX_USER" \
    bash -c '[ "$(docker exec it-pg-tgt17 psql -X -At -U postgres -d postgres -c "SELECT count(*) FROM pg_stat_activity WHERE usename = '"'"'$1'"'"' AND datname = '"'"'$1'"'"'")" -ge 1 ]' _ "$EX_USER"
  it_same "no connection of $EX_USER is left on src17 (stopped at section 5 step 1)" 0 \
    "$(it_pg_sql src17 postgres "SELECT count(*) FROM pg_stat_activity WHERE usename = '$EX_USER'")"
  ex_status "$root" "$v"

  it_step "clean up"
  ex_teardown "$root"
  it_pg_stop src17
  it_pg_stop tgt17
}
