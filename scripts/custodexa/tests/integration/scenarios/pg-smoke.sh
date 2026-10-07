# shellcheck shell=bash
# about: the external database servers the backup is checked against: PostgreSQL 16, 17, 18 as a deployment creates them, a client-certificate server, one with another owner's table and a tablespace, one with grants to roles named with a space and in Chinese; the client images carry a system CA file
# images: pg16 pg17 pg18 openssl-3.5.4

# The deployment's database login (DB_USER): owns its database and the product tables, not a
# superuser. The database is created the default way; nothing changes the owner of public.
readonly PS_USER=custodexa
readonly PS_PASS=it-test-only-db-user
readonly PS_DB=custodexa
readonly PS_TABLE=assets
readonly PS_CA=/pki/test/ca.crt
readonly PS_SPACE_DIR=/var/lib/postgresql/it-report-space

# ps_psql <major> <server> <sql> [conninfo options]: psql as DB_USER from a client of that major.
ps_psql() {
  it_pg_client "$1" -e PGPASSWORD="$PS_PASS" -- \
    psql -X -q -At -v ON_ERROR_STOP=1 "host=$2 user=$PS_USER dbname=$PS_DB ${4:-}" -c "$3"
}

# ps_product <server> <major> [conninfo options]: the login, its database, a product table it creates.
ps_product() {
  it_pg_sql "$1" postgres "CREATE ROLE $PS_USER LOGIN PASSWORD '$PS_PASS'"
  it_pg_sql "$1" postgres "CREATE DATABASE $PS_DB OWNER $PS_USER"
  it_check "DB_USER creates a product table in public" \
    ps_psql "$2" "$1" "CREATE TABLE public.$PS_TABLE (id bigint PRIMARY KEY, name text NOT NULL); INSERT INTO public.$PS_TABLE VALUES (1, 'host-1')" "${3:-}"
  it_same "the product tables are DB_USER's" "$PS_USER" \
    "$(it_pg_sql "$1" "$PS_DB" "SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'public'")"
}

# ps_server <major>: a server as a deployment's external database is created.
ps_server() {
  local m=$1 s=pg$1 ip
  it_step "PostgreSQL $m"
  it_pg_start "$s" "$m"
  it_same "server $s runs major $m" "$m" "$(it_pg_sql "$s" postgres 'SHOW server_version_num' | cut -c1-2)"
  ps_product "$s" "$m"
  it_same "psql as DB_USER connects" "$PS_USER" "$(ps_psql "$m" "$s" 'SELECT current_user')"
  # \dn+ prints the ACL over more lines; the first holds name|owner.
  it_same "\\dn+ public: owner pg_database_owner" "public|pg_database_owner" \
    "$(ps_psql "$m" "$s" '\dn+ public' | head -n1 | cut -d'|' -f1,2)"
  # The backup's client runs on the host network: the server's address on it-pg, not its alias.
  ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$IT_PG_NET\").IPAddress}}" "it-pg-$s")
  it_same "a client on the host network reaches it at $ip" 1 "$(docker run --rm --pull never --network host \
    -e PGPASSWORD="$PS_PASS" "$(it_image "pg$m")" psql -X -At -h "$ip" -U "$PS_USER" -d "$PS_DB" -c 'SELECT 1')"
}

ps_client_cert() {
  local o="sslmode=verify-full sslrootcert=$PS_CA"
  it_step "client-certificate server (PostgreSQL 18, self-signed test CA)"
  it_pg_start cert18 18 --client-cert
  it_pki_cert test "$PS_USER" client
  o="$o sslcert=/pki/test/$PS_USER.crt sslkey=/pki/test/$PS_USER.key"
  ps_product cert18 18 "$o"
  it_same "psql as DB_USER connects with its client certificate over TLS" t \
    "$(ps_psql 18 cert18 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()' "$o")"
  it_expect_fail "without the client certificate it is refused" 'requires a valid client certificate' \
    ps_psql 18 cert18 'SELECT 1' "sslmode=verify-full sslrootcert=$PS_CA"
}

ps_report_owner() {
  it_step "a table of another owner and a tablespace (PostgreSQL 16)"
  it_pg_start report16 16
  ps_product report16 16
  docker exec -u postgres it-pg-report16 mkdir -p "$PS_SPACE_DIR"
  it_pg_sql report16 postgres "CREATE ROLE report_owner"
  it_pg_sql report16 postgres "CREATE TABLESPACE report_space LOCATION '$PS_SPACE_DIR'"
  it_pg_sql report16 "$PS_DB" "CREATE TABLE public.report_totals (day date PRIMARY KEY, sessions int) TABLESPACE report_space"
  it_pg_sql report16 "$PS_DB" "ALTER TABLE public.report_totals OWNER TO report_owner"
  it_same "public.report_totals: owner report_owner, tablespace report_space" "report_owner|report_space" \
    "$(it_pg_sql report16 "$PS_DB" "SELECT tableowner || '|' || tablespace FROM pg_tables WHERE tablename = 'report_totals'")"
  it_same "psql as DB_USER connects" "$PS_USER" "$(ps_psql 16 report16 'SELECT current_user')"
}

ps_grants() {
  local r
  it_step "grants to roles named with a space and in Chinese (PostgreSQL 17)"
  it_pg_start grants17 17
  ps_product grants17 17
  it_pg_sql grants17 postgres 'CREATE ROLE "report reader"'
  it_pg_sql grants17 postgres 'CREATE ROLE "報表"'
  ps_psql 17 grants17 "GRANT SELECT ON public.$PS_TABLE TO \"report reader\", \"報表\""
  for r in 'report reader' '報表'; do
    it_same "\"$r\" may read public.$PS_TABLE" t \
      "$(it_pg_sql grants17 "$PS_DB" "SELECT has_table_privilege(\$q\$$r\$q\$, 'public.$PS_TABLE', 'SELECT')")"
  done
  it_same "psql as DB_USER connects" "$PS_USER" "$(ps_psql 17 grants17 'SELECT current_user')"
}

# The PostgreSQL clients of the release are these images (run.sh holds images.txt to the pins).
ps_client_ca() {
  local m
  it_step "system CA file of the client images"
  for m in 16 17 18; do
    it_check "PostgreSQL $m client image has /etc/ssl/certs/ca-certificates.crt" \
      docker run --rm --pull never --network none --entrypoint ls "$(it_image "pg$m")" /etc/ssl/certs/ca-certificates.crt
  done
}

scenario() {
  local m
  for m in 16 17 18; do ps_server "$m"; done
  ps_client_cert
  ps_report_owner
  ps_grants
  ps_client_ca
}
