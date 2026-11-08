# shellcheck shell=bash
# shellcheck disable=SC2154 # variables set by the guides' own blocks
# about: the command blocks of the Upgrade SOP section "When the database holds extra settings" taken from the guide at run time and run as written on a package deployment of a published release (PostgreSQL 16) that holds an extension, a tablespace with objects in it and roles with privileges of every kind: what the script's preflight names, what the guide's list queries show, what the guide's removal statements do, the preflight after them; then the six steps of the QUICKSTART section "Moving a source deployment to PostgreSQL 18" taken from the guide and run as written on a source deployment whose data is a real PostgreSQL 16 folder
# needs: package local-versions published
# images: pg16 pg18 openssl-3.5.4
# Run with the published release and one local version: CX_IT_PUBLISHED_VERSION=1.22.0 CX_IT_LOCAL_VERSIONS=1.23.90
# CX_IT_PG_SECTIONS="pd_extras pd_quickstart" runs only those sections.

# shellcheck source=scripts/custodexa/tests/integration/lib/pgx.sh
. "$IT_DIR/lib/pgx.sh"

readonly PD_SOP=/src/docs/ops/upgrade-sop.md
readonly PD_QS=/src/docs/QUICKSTART.md
readonly PD_BAR=/src/docs/ops/backup-and-restore.md
PD_OUTF=/it/pd-out.txt
PD_RC=0
PD_N=0

# pd_block <file> <heading line start> <n>: the n-th bash block under that heading, up to the next heading.
pd_block() {
  awk -v h="$2" -v n="$3" '
    /^```/ {
      if (fence) { fence = 0; if (inb) exit; next }
      fence = 1
      if (on && $0 == "```bash") { k++; if (k == n) inb = 1 }
      next
    }
    fence { if (inb) print; next }
    index($0, h) == 1 { on = 1; next }
    on && /^#+ / { exit }
  ' "$1"
}

# pd_run <file>: the lines in the current shell, as an operator types them (no errexit); PD_RC, output kept.
pd_run() {
  DM_RC=0
  PD_RC=0
  # shellcheck disable=SC1090
  . "$1" >"$PD_OUTF" 2>&1 || PD_RC=$?
  sed 's/^/   > /' "$PD_OUTF" | tail -n 40
}

# pd_sop <n> [sed expression]: block n of the "extra settings" section, as written except the one
# substitution the guide asks for and "sudo " (not needed as root).
pd_sop() {
  local f=$IT_WORK/pd-sop-$1-$((++PD_N)).sh
  pd_block "$PD_SOP" '##### When the database holds extra settings' "$1" | sed -e 's/^sudo //' ${2:+-e "$2"} >"$f"
  pd_run "$f"
}

# pd_sop_names: the names a list query printed (psql's aligned output: the rows between the rule and the count).
pd_sop_names() { awk '/^-+$/ { on = 1; next } /^\([0-9]+ rows?\)$/ { on = 0 } on && NF { print $1 }' "$PD_OUTF" | sort -u | paste -sd' '; }

# pd_refused <label>: the upgrade is refused at step 1 and the screen names what it cannot convert.
pd_refused() {
  : >"$IT_WORK/docker-calls.log"
  lv_cx "$1" upgrade "$(it_package_file "$PX_NEW")" --images "$(it_bundle_file "$PX_NEW")" --yes
}

pd_names_on_screen() { grep -oE 'it_[a-z_]+' <<<"$LV_OUT" | sort -u | paste -sd' '; }

pd_extras() {
  local r0 n
  px_fresh extras
  r0=$(px_fp lv_sql)
  it_say "   R0: $r0"
  it_step "the settings the script cannot convert: an extension, a tablespace with objects, roles with each kind of privilege"
  docker exec custodexa-postgres sh -c 'mkdir -p /var/lib/postgresql/ts1 && chown postgres /var/lib/postgresql/ts1'
  lv_sql "CREATE EXTENSION pg_trgm" >/dev/null
  lv_sql "CREATE TABLESPACE it_ts LOCATION '/var/lib/postgresql/ts1'" >/dev/null
  lv_sql "CREATE TABLE it_in_ts (id int PRIMARY KEY, v text) TABLESPACE it_ts" >/dev/null
  lv_sql "CREATE INDEX it_marker_note ON it_marker (note) TABLESPACE it_ts" >/dev/null
  lv_sql "CREATE MATERIALIZED VIEW it_mv TABLESPACE it_ts AS SELECT * FROM it_marker" >/dev/null
  for n in tbl col def db sch seq fn own; do lv_sql "CREATE ROLE it_r_$n NOLOGIN" >/dev/null; done
  lv_sql "GRANT SELECT ON users TO it_r_tbl" >/dev/null
  lv_sql "GRANT SELECT (username) ON users TO it_r_col" >/dev/null
  lv_sql "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO it_r_def" >/dev/null
  lv_sql "GRANT CONNECT ON DATABASE $(lv_env_get DB_NAME) TO it_r_db" >/dev/null
  lv_sql "GRANT USAGE ON SCHEMA public TO it_r_sch" >/dev/null
  lv_sql "GRANT USAGE ON SEQUENCE it_seq TO it_r_seq" >/dev/null
  lv_sql "CREATE FUNCTION it_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'" >/dev/null
  lv_sql "REVOKE EXECUTE ON FUNCTION it_fn() FROM PUBLIC; GRANT EXECUTE ON FUNCTION it_fn() TO it_r_fn" >/dev/null
  lv_sql "CREATE TABLE it_owned (id int)" >/dev/null
  lv_sql "ALTER TABLE it_owned OWNER TO it_r_own" >/dev/null
  it_same "the application account is a superuser (so DROP EXTENSION, REASSIGN OWNED and DROP OWNED are allowed to it)" t \
    "$(lv_sql "SELECT rolsuper FROM pg_roles WHERE rolname = '$(lv_env_get DB_USER)'")"

  it_step "the preflight of upgrade names them (step 1, nothing stops)"
  pd_refused refused1
  it_same "the upgrade is refused (exit 3)" 3 "$LV_RC"
  it_same "nothing stopped: the old version runs" "$PX_OLD" "$(lv_version)"
  it_say "   names on the screen: $(pd_names_on_screen) / pg_trgm"
  it_same "the screen names the extension and the tablespace" "it_ts pg_trgm" \
    "$(grep -oE 'it_ts|pg_trgm' <<<"$LV_OUT" | sort -u | paste -sd' ')"
  printf '%s\n' "$LV_OUT" >|"$IT_WORK/pd-refused1.txt"

  it_step "the guide: section 2.3 variables, then every block as written, from the deployment folder"
  cd "$LV_ROOT"
  pd_block "$PD_BAR" '### 2.3 How the shell commands' 1 | sed 's/^sudo //' >"$IT_WORK/pd-env.sh"
  pd_run "$IT_WORK/pd-env.sh"
  it_check "DB_USER and DB_NAME were read from .env" bash -c 'grep -q "^DB_USER=." "$1" && grep -q "^DB_NAME=." "$1"' _ "$PD_OUTF"
  it_step "the guide: the list of extensions, as written"
  pd_sop 2
  it_say "   exit $PD_RC"
  PD_AS_WRITTEN_RC=$PD_RC
  printf 'as written, list of extensions: exit %s\n' "$PD_RC" >|"$IT_WORK/pd-asis.txt"
  cat "$PD_OUTF" >>"$IT_WORK/pd-asis.txt"
  it_step "the same block without -f docker-compose.yml (the .env of a package deployment names its compose files)"
  pd_sop 2 's/ -f docker-compose.yml//'
  it_same "the list of extensions: exit 0" 0 "$PD_RC"
  it_check "it lists pg_trgm" grep -q pg_trgm "$PD_OUTF"
  PD_FIX='s/ -f docker-compose.yml//'

  it_step "the guide: remove the extension"
  pd_sop 3 "$PD_FIX;s/<extension name>/pg_trgm/"
  it_same "DROP EXTENSION: exit 0" 0 "$PD_RC"
  pd_sop 2 "$PD_FIX"
  it_same "the list of extensions is empty after the removal" 1 "$(grep -c '(0 rows)' "$PD_OUTF")"

  it_step "the guide: list the tablespace and what is in it"
  pd_sop 4 "$PD_FIX"
  it_same "exit 0" 0 "$PD_RC"
  it_check "the tablespace and its objects are listed" bash -c 'grep -q it_ts "$1" && grep -q it_in_ts "$1" && grep -q it_mv "$1" && grep -q it_marker_note "$1"' _ "$PD_OUTF"
  it_step "the guide: move everything to the default tablespace and drop it"
  pd_sop 5 "$PD_FIX;s/<tablespace name>/it_ts/g"
  it_same "the four statements in one psql call: exit 0" 0 "$PD_RC"
  pd_sop 4 "$PD_FIX"
  it_same "both lists are empty after the move" 2 "$(grep -c '(0 rows)' "$PD_OUTF")"
  it_same "the tablespace is gone" 0 "$(lv_sql "SELECT count(*) FROM pg_tablespace WHERE spcname = 'it_ts'")"

  it_step "the guide: the roles its query lists"
  pd_sop 6 "$PD_FIX"
  it_same "exit 0" 0 "$PD_RC"
  PD_DOC_ROLES=$(pd_sop_names)
  it_say "   the guide's query lists: $PD_DOC_ROLES"
  printf 'roles the guide query lists: %s\n' "$PD_DOC_ROLES" >|"$IT_WORK/pd-roles.txt"
  it_step "what the preflight names now (the extension and the tablespace are gone)"
  pd_refused refused2
  it_say "   exit $LV_RC; names: $(pd_names_on_screen)"
  printf 'roles the preflight names: %s\n' "$(pd_names_on_screen)" >>"$IT_WORK/pd-roles.txt"
  it_same "the preflight refuses on the roles (exit 3)" 3 "$LV_RC"
  cp "$IT_WORK/pd-roles.txt" "$IT_WORK/pd-roles-before.txt"

  it_step "the guide: REASSIGN OWNED, DROP OWNED, DROP ROLE for each role the guide's query lists"
  for n in $PD_DOC_ROLES; do
    pd_sop 7 "$PD_FIX;s/<role name>/$n/g"
    it_say "   $n: exit $PD_RC"
  done
  pd_sop 6 "$PD_FIX"
  it_say "   after the guide's removals the guide's query lists: $(pd_sop_names) ($(grep -c '(0 rows)' "$PD_OUTF") empty)"
  printf 'guide query after removal: %s\n' "$(pd_sop_names)" >>"$IT_WORK/pd-roles.txt"
  it_step "the preflight again"
  pd_refused refused3
  it_say "   exit $LV_RC; names: $(pd_names_on_screen)"
  printf 'roles the preflight names after the guide removals: exit %s: %s\n' "$LV_RC" "$(pd_names_on_screen)" >>"$IT_WORK/pd-roles.txt"
  sed 's/^/   roles> /' "$IT_WORK/pd-roles.txt"
  cd /
  it_same "the guide's role query lists nothing after the removals" "" "$(pd_sop_names)"
  it_same "the same command now goes through (exit 0): the preflight no longer names a role" 0 "$LV_RC"
  it_step "the upgrade that command ran"
  lv_wait_version "$PX_NEW"
  LV_TOKEN=""
  it_same "PostgreSQL 18 runs" 18 "$(lv_sql 'SHOW server_version_num' | cut -c1-2)"
  it_same "it_marker, users, assets, sequence are those of R0 plus the settings removed (it_marker and the others equal)" "$r0" "$(px_fp lv_sql)"
  cp "$IT_WORK/pd-refused1.txt" /dev/null
  it_say "   $(cat "$IT_WORK/pd-asis.txt" | head -n 6 | tr '\n' ' ')"
}

# a few behaviours of psql the guide relies on
pd_psql() {
  px_fresh psql
  it_step "psql with several -c: one fails, do the others run, what is the exit status"
  docker exec -i custodexa-postgres psql -X -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" \
    -c "SELECT 1/0" -c "SELECT 'second ran'" -c "SELECT 'third ran'" >|"$IT_WORK/pd-multi.txt" 2>&1 && PD_RC=0 || PD_RC=$?
  sed 's/^/   > /' "$IT_WORK/pd-multi.txt"
  it_say "   exit status with a failing first -c: $PD_RC"
  docker exec -i custodexa-postgres psql -X -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" \
    -c "SELECT 'first ran'" -c "SELECT 1/0" >|"$IT_WORK/pd-multi2.txt" 2>&1 && PD_RC=0 || PD_RC=$?
  sed 's/^/   > /' "$IT_WORK/pd-multi2.txt"
  it_say "   exit status with a failing last -c: $PD_RC"
  it_step "psql -v ON_ERROR_STOP=1 with several -c: does the second run after the first failed"
  docker exec -i custodexa-postgres psql -X -v ON_ERROR_STOP=1 -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" \
    -c "SELECT 1/0" -c "SELECT 'second ran'" >|"$IT_WORK/pd-multi3.txt" 2>&1 && PD_RC=0 || PD_RC=$?
  sed 's/^/   > /' "$IT_WORK/pd-multi3.txt"
  it_say "   exit status with ON_ERROR_STOP and a failing first -c: $PD_RC"
  it_step "DROP OWNED after a failed REASSIGN OWNED (same psql call, no ON_ERROR_STOP): does it drop what the role owns"
  lv_sql "CREATE ROLE it_r_y NOLOGIN; CREATE TABLE it_y (id int); ALTER TABLE it_y OWNER TO it_r_y; INSERT INTO it_y VALUES (1)" >/dev/null
  docker exec -i custodexa-postgres psql -X -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" \
    -c "REASSIGN OWNED BY it_r_nosuchrole TO CURRENT_USER" -c "DROP OWNED BY it_r_y" 2>&1 | sed 's/^/   > /' || true
  it_say "   it_y still there after DROP OWNED: $(lv_sql "SELECT count(*) FROM pg_tables WHERE tablename = 'it_y'")"
  it_step "DROP ROLE of a role that still owns an object: refused, nothing cascades"
  lv_sql "CREATE ROLE it_r_x NOLOGIN; CREATE TABLE it_x (id int); ALTER TABLE it_x OWNER TO it_r_x" >/dev/null
  docker exec -i custodexa-postgres psql -X -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "DROP ROLE it_r_x" 2>&1 | sed 's/^/   > /' || true
  it_same "the table is still there" 1 "$(lv_sql "SELECT count(*) FROM pg_tables WHERE tablename = 'it_x'")"
}

# which privileges each of the guide's role query and the script's preflight sees
pd_acl() {
  px_fresh acl
  lv_sql "CREATE ROLE it_a_def NOLOGIN; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO it_a_def" >/dev/null
  lv_sql "CREATE DOMAIN it_dom AS int; CREATE ROLE it_a_typ NOLOGIN; GRANT USAGE ON TYPE it_dom TO it_a_typ" >/dev/null
  lv_sql "CREATE ROLE it_a_col NOLOGIN; GRANT SELECT (username) ON users TO it_a_col" >/dev/null
  lv_sql "CREATE ROLE it_a_ns NOLOGIN; GRANT USAGE ON SCHEMA public TO it_a_ns" >/dev/null
  cd "$LV_ROOT"
  pd_block "$PD_BAR" '### 2.3 How the shell commands' 1 | sed 's/^sudo //' >"$IT_WORK/pd-env.sh"
  pd_run "$IT_WORK/pd-env.sh"
  pd_sop 6
  it_say "   the guide's query lists: [$(pd_sop_names)]"
  PD_DOC=$(pd_sop_names)
  cd /
  pd_refused acl
  it_say "   the preflight names: [$(pd_names_on_screen)]"
  printf 'acl-only roles (default privileges it_a_def, type it_a_typ, column it_a_col, schema it_a_ns): the guide query lists [%s]; the preflight names [%s]\n' "$PD_DOC" "$(pd_names_on_screen)" >|"$IT_WORK/pd-acl.txt"
  sed 's/^/   acl> /' "$IT_WORK/pd-acl.txt"
}

# pd_qsblock <n>: block n of the QUICKSTART section as written, in the current shell, in the tree.
pd_qsblock() {
  local f=$IT_WORK/pd-qs-$1-$((++PD_N)).sh
  pd_block "$PD_QS" '### 8. Moving a source deployment to PostgreSQL 18' "$1" >"$f"
  cd "$PD_TREE"
  pd_run "$f"
}

PD_TREE=/it/qs8

# the six steps of the QUICKSTART section, on a source deployment whose data is a real PostgreSQL 16 folder
pd_quickstart() {
  local i before after
  qs_down
  rm -rf "$PD_TREE"
  qs_images
  it_step "the 1.22 form of the source tree, started, one table of our own, then stopped: data/postgres is PostgreSQL 16"
  qs_tree "$PD_TREE" legacy
  qs_env "$PD_TREE" KEK_PROVIDER=env TLS_MODE=selfsigned HTTP_PORT=8080
  qs_run "$PD_TREE"
  it_same "the preparation exits 0" 0 "$QS_RC"
  sed -i '/^# >>> managed by custodexa.sh/,/^# <<< managed by custodexa.sh/d' "$PD_TREE/.env"
  (cd "$PD_TREE" && QS_LOG=$QS_LOG PATH=$QS_BIN:$PATH docker compose up -d >"$IT_WORK/pd-up.txt" 2>&1) || { tail -n 20 "$IT_WORK/pd-up.txt"; it_die "the 1.22 form did not come up"; }
  for ((i = 0; i < 90; i++)); do
    (cd "$PD_TREE" && docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1) && break
    sleep 2
  done
  qs_wait_db bundled "$(sed -n 's/^DB_NAME=//p' "$PD_TREE/.env" | tail -n1)"
  qs_sql bundled "$(sed -n 's/^DB_NAME=//p' "$PD_TREE/.env" | tail -n1)" "CREATE TABLE it_marker AS SELECT g AS id, md5(g::text) AS note FROM generate_series(1, 700) g; CREATE SEQUENCE it_seq; SELECT setval('it_seq', 4242)" >/dev/null
  (cd "$PD_TREE" && docker compose down >"$IT_WORK/pd-down.txt" 2>&1) || { tail -n 20 "$IT_WORK/pd-down.txt"; it_die "down failed"; }
  it_same "the old folder is PostgreSQL 16" 16 "$(cat "$PD_TREE/data/postgres/PG_VERSION")"
  it_step "the working tree's compose file: quickstart.sh stops before it starts anything"
  qs_pull_new_compose "$PD_TREE"
  sed -i 's|image: postgres:18.6-alpine3.24@sha256:[0-9a-f]*|image: postgres:18.6-alpine3.24|' "$PD_TREE/docker-compose.yml"
  : >"$QS_LOG"
  qs_run "$PD_TREE" --up
  it_check "quickstart.sh --up stops (exit $QS_RC)" test "$QS_RC" -ne 0
  it_check "the message points to the guide section" grep -q "Moving a source deployment to PostgreSQL 18" <<<"$(tr '\n' ' ' <<<"$QS_OUT" | tr -s ' ')"

  it_step "the six steps, as written"
  export PATH="$QS_BIN:$PATH" QS_LOG
  pd_qsblock 1
  it_same "step 1 prints the old folder's version file (16)" 16 "$(tail -n1 "$PD_OUTF" | tr -d ' ')"
  pd_qsblock 2
  it_check "step 2: the temporary PostgreSQL 16 answers and the notes were written" bash -c 'test -s "$1/data/pg16-encoding.txt" && test -s "$1/data/pg16-counts.txt"' _ "$PD_TREE"
  cp "$PD_TREE/data/pg16-counts.txt" "$IT_WORK/pd-counts.before"
  it_say "   tables counted: $(grep -c . "$IT_WORK/pd-counts.before"); encoding: $(cat "$PD_TREE/data/pg16-encoding.txt")"
  pd_qsblock 3
  it_check "step 3: the export exists" test -s "$PD_TREE/data/pg16-export.dump"
  it_check "step 3: the temporary container is gone" bash -c '! docker ps -a --format "{{.Names}}" | grep -qx custodexa-pg16-export'
  pd_qsblock 4
  it_check "step 4: encoding and collation equal, checksums on" bash -c 'grep -q "encoding and collation equal" "$1" && tail -n1 "$1" | grep -qx on' _ "$PD_OUTF"
  pd_qsblock 5
  it_check "step 5: loaded and the three comparisons equal" bash -c 'grep -q "^loaded" "$1" && grep -q "row counts equal" "$1" && grep -q "migrations equal" "$1" && grep -q "sequences equal" "$1"' _ "$PD_OUTF"
  cp "$PD_TREE/data/pg16-migrations.txt" "$IT_WORK/pd-migrations.before"
  cp "$PD_TREE/data/pg16-sequences.txt" "$IT_WORK/pd-sequences.before"
  pd_qsblock 6
  it_same "step 6: quickstart.sh --up exits 0" 0 "$PD_RC"
  it_check "step 6: the export and the notes are gone" bash -c '! ls "$1"/data/pg16-* >/dev/null 2>&1' _ "$PD_TREE"
  for ((i = 0; i < 90; i++)); do
    (cd "$PD_TREE" && docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1) && break
    sleep 2
  done
  it_same "the data is on PostgreSQL 18" 18 "$(qs_sql bundled "$(sed -n 's/^DB_NAME=//p' "$PD_TREE/.env" | tail -n1)" 'SHOW server_version_num' | cut -c1-2)"
  before=$(cat "$IT_WORK/pd-counts.before")
  after=$(qs_sql bundled "$(sed -n 's/^DB_NAME=//p' "$PD_TREE/.env" | tail -n1)" "$COUNT_Q")
  it_same "the row counts of every table but audit_logs equal those of the PostgreSQL 16 folder (the backend writes audit records when it starts)" \
    "$(grep -v '^audit_logs ' <<<"$before")" "$(grep -v '^audit_logs ' <<<"$after")"
  it_check "audit_logs has at least the rows it had" test "$(sed -n 's/^audit_logs //p' <<<"$after")" -ge "$(sed -n 's/^audit_logs //p' <<<"$before")"
  it_check "the old folder is still there and still PostgreSQL 16" test "$(cat "$PD_TREE/data/postgres/PG_VERSION")" = 16
  # Step 6 of the guide says the script "tells you the old folder is still there".
  it_check "step 6: the --up output says the old folder was left in place" grep -q 'data/postgres is not used any more and was left in place' "$PD_OUTF"
  cd /
  qs_down
}

scenario() {
  px_section "extra settings of the upgrade SOP" pd_extras
  px_section "psql behaviours the guide relies on" pd_psql
  px_section "privileges the guide's query and the preflight each see" pd_acl
  px_section "QUICKSTART: moving a source deployment to PostgreSQL 18" pd_quickstart
  ex_teardown "$LV_ROOT" || true
  [ -z "$px_failed" ] || it_die "sections not ok:$px_failed"
}
