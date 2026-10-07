# shellcheck shell=bash
# about: a backup of an external database deployment on PostgreSQL 16, 17 and 18 each: the export runs with the client of the server's major, and pg_restore of that major, run as DB_USER (not a superuser), loads it into a new empty database on a fresh server of the same major; row counts, schema_migrations and the key fingerprints equal its snapshot.txt
# needs: package
# images: pg16 pg17 pg18

re_major() {
  local m=$1 root=/opt/custodexa src=src$1 tgt=tgt$1 jwt
  it_step "PostgreSQL $m: install with the external database $src, backup"
  ex_pg_start "$src" "$m" "154$m"
  ex_db_create "$src"
  ex_install "$root" now "154$m"
  ex_backup "$root"
  it_same "the server's major is recorded" "$m" "$(ex_mf db.server_major)"
  it_same "the export ran with pgclient$m" "pgclient$m" "$(ex_mf tool.dump_image)"
  it_same "the dump was written by pg_dump $m" "$m" "$(ex_mf db.dump_tool_version | grep -oE '[0-9]+' | head -n1)"
  it_same "the snapshot is usable" true "$(sed -n 's/^usable=//p' "$EX_X/snapshot.txt")"
  it_same "kek.fingerprint is fp.kek of snapshot.txt" "$(sed -n 's/^fp\.kek=//p' "$EX_X/snapshot.txt")" "$(ex_mf kek.fingerprint)"
  it_say "   snapshot: $(grep -c '^migration=' "$EX_X/snapshot.txt") migrations, $(grep '^count\.' "$EX_X/snapshot.txt" | tr '\n' ' ')"

  it_step "PostgreSQL $m: a fresh server $tgt, $EX_USER owns a new empty database and is not a superuser"
  ex_pg_start "$tgt" "$m" "155$m"
  ex_db_create "$tgt"
  it_same "$EX_USER is not a superuser" f "$(it_pg_sql "$tgt" postgres "SELECT rolsuper FROM pg_roles WHERE rolname = '$EX_USER'")"
  it_same "the database is empty" 0 "$(ex_db_sql "$tgt" "$EX_DB" "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
  it_check "pg_restore $m --exit-on-error as $EX_USER over the network ends 0" \
    docker run --rm -i --pull never --network host -e PGPASSWORD="$EX_PASS" --entrypoint pg_restore "$(it_image "pg$m")" \
    -h "$(ex_addr)" -p "155$m" -U "$EX_USER" -d "$EX_DB" --exit-on-error <"$EX_X/db.dump"
  jwt=$(sed -n 's/^[[:space:]]*JWT_SECRET=//p' "$EX_X/env.bak" | tail -n 1)
  re_sql() { docker exec -i "it-pg-$RE_TGT" psql -U "$EX_USER" -d "$EX_DB" -AtX -v ON_ERROR_STOP=1 -c "$1"; }
  RE_TGT=$tgt
  it_snap_take "$IT_WORK/restored$m.txt" "$jwt" re_sql
  it_snap_same "row counts, schema_migrations and the four fingerprints equal snapshot.txt" "$EX_X/snapshot.txt" "$IT_WORK/restored$m.txt"
  ex_teardown "$root"
  it_pg_stop "$src"
  it_pg_stop "$tgt"
}

scenario() {
  local m
  for m in 16 17 18; do re_major "$m"; done
}
