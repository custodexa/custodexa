# shellcheck shell=bash
# about: an external database deployment on PostgreSQL 17 upgrades from the older release to the package's, online (no --images: the PostgreSQL clients and the release's images pulled from their registries) and offline (--images, nothing from a registry): the upgrade's backup is one portable file of the external database exported with the 17 client, the snapshot before equals its snapshot.txt and the check after the start passes
# needs: package upgrade
# network: bridge
# images: pg17

ue_run() {
  local how=$1 db=$2 root=/opt/custodexa
  it_step "$how: install the older release on the external database $db, then upgrade"
  ex_db_create pg17 "$db"
  ex_install "$root" from 15417 "DB_NAME=$db"
  ex_upgrade "$root" "$how"
  it_same "db.location, tool.dump_image, db.server_major" "external pgclient17 17" \
    "$(ex_mf db.location) $(ex_mf tool.dump_image) $(ex_mf db.server_major)"
  it_check "the dump lists (pg_restore --list with the 17 client)" \
    docker run --rm -i --pull never --network none --entrypoint pg_restore "$(it_image pg17)" --list <"$EX_X/db.dump"
  ex_status "$root" "$(ex_st "$root" current.version)"
  ex_teardown "$root"
}

scenario() {
  ex_pg_start pg17 17 15417
  ue_run online custodexa_online
  ue_run offline custodexa_offline
}
