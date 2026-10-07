# shellcheck shell=bash
# about: a real backup of a built-in PostgreSQL 16 deployment restores, with pg_restore run as DB_USER (not a superuser), into a new empty database on another server; row counts, schema_migrations and the key fingerprints equal its snapshot.txt
# needs: package
# images: pg16

readonly RS_USER=cxapp                      # a DB_USER other than the template's postgres
readonly RS_PASS='it-test-only app password' # of that role on the target server

# rs_psql_target <sql>: SQL as DB_USER on the target server, the way the snapshot reads it.
rs_psql_target() {
  docker exec -i it-pg-target psql -U "$RS_USER" -d "$RS_DB" -AtX -v ON_ERROR_STOP=1 -c "$1"
}

scenario() {
  local root=/opt/custodexa x=$IT_WORK/x f mf major jwt
  it_step "built-in form, master key mode env, DB_USER=$RS_USER: install --images $(it_bundle_file)"
  it_unpack /opt
  it_env_preset "$root" KEK_PROVIDER=env "DB_USER=$RS_USER"
  it_cx "$root" install --images "$(it_bundle_file)"

  it_step "backup --yes"
  it_cx "$root" backup --lang en --yes
  f=$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*.tar')
  it_check "one backup file, and its checksum file matches" \
    bash -c 'cd "$1" && sha256sum -c --quiet "$2.sha256"' _ "$root/backups" "${f##*/}"
  mkdir -p "$x"
  tar -xf "$f" -C "$x"
  it_check "the members match SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$x"
  mf=$x/backup-manifest.json
  it_same "the manifest names DB_USER" "$RS_USER" "$(jq -r '."db.user"' "$mf")"
  RS_DB=$(jq -r '."db.name"' "$mf")
  major=$(jq -r '."db.dump_tool_version"' "$mf" | grep -oE '[0-9]+' | head -n1)
  it_same "the dump was written by pg_dump 16" 16 "$major"
  it_same "the snapshot is usable" true "$(sed -n 's/^usable=//p' "$x/snapshot.txt")"
  it_say "   snapshot: $(grep -c '^migration=' "$x/snapshot.txt") migrations, $(grep '^count\.' "$x/snapshot.txt" | tr '\n' ' ')"
  it_say "   $(grep '^fp\.kek=' "$x/snapshot.txt"); manifest kek.fingerprint=$(jq -r '."kek.fingerprint"' "$mf")"
  it_same "kek.fingerprint is fp.kek of snapshot.txt" "$(sed -n 's/^fp\.kek=//p' "$x/snapshot.txt")" "$(jq -r '."kek.fingerprint"' "$mf")"

  it_step "a new PostgreSQL 16 server; $RS_USER is a login role that owns the new empty database, not a superuser"
  it_pg_start target 16
  it_pg_sql target postgres "CREATE ROLE $RS_USER LOGIN PASSWORD '$RS_PASS'"
  it_pg_sql target postgres "CREATE DATABASE \"$RS_DB\" OWNER $RS_USER"
  it_same "$RS_USER is not a superuser" f "$(it_pg_sql target postgres "SELECT rolsuper FROM pg_roles WHERE rolname = '$RS_USER'")"
  it_same "the database is empty" 0 "$(rs_psql_target "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"

  it_step "pg_restore as $RS_USER over the network"
  mkdir -p "$IT_WORK/work"
  cp "$x/db.dump" "$IT_WORK/work/db.dump"
  it_check "pg_restore --exit-on-error as $RS_USER ends 0" \
    it_pg_client 16 -e "PGPASSWORD=$RS_PASS" -- pg_restore -h target -U "$RS_USER" -d "$RS_DB" --exit-on-error /work/db.dump

  it_step "the restored database against snapshot.txt"
  jwt=$(sed -n 's/^[[:space:]]*JWT_SECRET=//p' "$x/env.bak" | tail -n 1)
  it_snap_take "$IT_WORK/restored.txt" "$jwt" rs_psql_target
  it_snap_same "row counts, schema_migrations and the four fingerprints equal snapshot.txt" "$x/snapshot.txt" "$IT_WORK/restored.txt"
  it_check "users, sessions and audit_logs were counted" grep -q '^count\.audit_logs=[0-9]' "$IT_WORK/restored.txt"
}
