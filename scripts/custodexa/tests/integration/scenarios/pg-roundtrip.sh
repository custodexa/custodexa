# shellcheck shell=bash
# about: PostgreSQL 16, 17 and 18 servers start; pg_dump of each restores into a new empty database; TLS-only and client-certificate servers refuse what they should
# images: pg16 pg17 pg18 openssl-3.5.4

readonly RT_OWNER=it_owner
readonly RT_OWNER_PASS=it-test-only-owner
readonly RT_ROWS=1000
readonly RT_DIGEST="SELECT count(*) || ' ' || md5(string_agg(id || ':' || name, ',' ORDER BY id)) FROM items"

# rt_seed <server>: a database owned by an ordinary role, with a table it filled.
rt_seed() {
  it_pg_sql "$1" postgres "CREATE ROLE $RT_OWNER LOGIN PASSWORD '$RT_OWNER_PASS'"
  it_pg_sql "$1" postgres "CREATE DATABASE it_src OWNER $RT_OWNER"
  it_pg_client "${1#pg}" -e PGPASSWORD="$RT_OWNER_PASS" -- psql -X -q -v ON_ERROR_STOP=1 -h "$1" -U "$RT_OWNER" -d it_src \
    -c "CREATE TABLE items (id int PRIMARY KEY, name text NOT NULL)" \
    -c "INSERT INTO items SELECT g, md5(g::text) FROM generate_series(1, $RT_ROWS) g"
}

# rt_roundtrip <major>: dump with that major's pg_dump as the owner, restore into a new empty
# database with pg_restore as the same role, compare the rows.
rt_roundtrip() {
  local m=$1 s=pg$1 src dst
  it_step "PostgreSQL $m"
  it_pg_start "$s" "$m"
  it_check "server $s runs major $m" test "$(it_pg_sql "$s" postgres 'SHOW server_version_num' | cut -c1-2)" = "$m"
  it_check "published on 127.0.0.1 ($(it_pg_port "$s")) and nowhere else" \
    test "$(docker port "it-pg-$s" | grep -vc ' -> 127\.0\.0\.1:')" = 0
  rt_seed "$s"
  it_check "pg_dump $m (custom format)" it_pg_client "$m" -e PGPASSWORD="$RT_OWNER_PASS" -- \
    pg_dump -h "$s" -U "$RT_OWNER" -d it_src -Fc -f "/work/$s.dump"
  it_pg_sql "$s" postgres "CREATE DATABASE it_dst OWNER $RT_OWNER"
  it_same "the new database is empty" 0 "$(it_pg_sql "$s" it_dst "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
  it_check "pg_restore $m into it" it_pg_client "$m" -e PGPASSWORD="$RT_OWNER_PASS" -- \
    pg_restore --exit-on-error -h "$s" -U "$RT_OWNER" -d it_dst "/work/$s.dump"
  src=$(it_pg_sql "$s" it_src "$RT_DIGEST")
  dst=$(it_pg_sql "$s" it_dst "$RT_DIGEST")
  it_same "restored rows equal the source ($src)" "$src" "$dst"
  it_check "source has $RT_ROWS rows" test "${src%% *}" = "$RT_ROWS"
}

rt_tls() {
  local ca=/pki/test/ca.crt
  it_step "TLS-only server"
  it_pg_start tls17 17 --tls-only
  it_expect_fail "a plain connection is refused" 'no encryption' \
    it_pg_client 17 -e PGPASSWORD="$IT_PG_PASSWORD" -- psql -X -At "host=tls17 user=postgres sslmode=disable" -c 'SELECT 1'
  it_same "verify-full with the test CA connects over TLS" t "$(it_pg_client 17 -e PGPASSWORD="$IT_PG_PASSWORD" -- \
    psql -X -At "host=tls17 user=postgres sslmode=verify-full sslrootcert=$ca" -c 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()')"

  it_step "client-certificate server"
  it_pg_start cert17 17 --client-cert
  it_pki_cert test postgres client
  it_expect_fail "TLS without a client certificate is refused" 'requires a valid client certificate' \
    it_pg_client 17 -e PGPASSWORD="$IT_PG_PASSWORD" -- psql -X -At "host=cert17 user=postgres sslmode=verify-full sslrootcert=$ca" -c 'SELECT 1'
  it_same "the client certificate is accepted" 1 "$(it_pg_client 17 -e PGPASSWORD="$IT_PG_PASSWORD" -- \
    psql -X -At "host=cert17 user=postgres sslmode=verify-full sslrootcert=$ca sslcert=/pki/test/postgres.crt sslkey=/pki/test/postgres.key" -c 'SELECT 1')"
}

scenario() {
  local m
  for m in 16 17 18; do rt_roundtrip "$m"; done
  rt_tls
}
