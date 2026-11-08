# shellcheck shell=bash
# about: a published release (PostgreSQL 16) upgraded by script to the working tree (PostgreSQL 18), the new version writes data, then the pre-upgrade backup (data of the old release, PostgreSQL 16) restored on this host: the preview names the old version and PostgreSQL 16, the deployment ends on the old release with the data of the backup (the data written on the new version is gone), both data folders (postgres and postgresql) are kept under before-restore names and only the folder the old release uses exists, and upgrading again converts again and leaves the kept folders as they were
# needs: package local-versions published
# images:
# Run with the published release and one local version: CX_IT_PUBLISHED_VERSION=1.22.0 CX_IT_LOCAL_VERSIONS=1.23.90

# shellcheck source=scripts/custodexa/tests/integration/lib/pgx.sh
. "$IT_DIR/lib/pgx.sh"

pq_flat() { tr '\n' ' ' <<<"$LV_OUT" | tr -s ' '; }

pq_restore_other_major() {
  local r0 backup kept_a kept_b
  px_fresh restore
  r0=$(px_fp lv_sql)
  it_say "   R0: $r0"
  px_upgrade
  lv_wait_version "$PX_NEW"
  LV_TOKEN=""
  lv_api POST /users "$(jq -cn '{username: "it-on-new", password: "It-user-pass-0002", email: "it-on-new@example.test", full_name: "x"}')" >/dev/null
  lv_sql "INSERT INTO it_marker VALUES (9001, 'written on the new version')" >/dev/null
  backup=$LV_ROOT/$(lv_st last_upgrade.backup)
  it_check "the upgrade's backup is a file" test -f "$backup"
  it_same "its manifest: product.version, db.server_major" "$PX_OLD 16" \
    "$(tar -xOf "$backup" backup-manifest.json | jq -r '."product.version" + " " + (."db.server_major" | tostring)')"
  it_check "both data folders are here: postgres (16) and postgresql (18)" \
    bash -c 'test "$(cat "$1/data/postgres/PG_VERSION")" = 16 && test "$(cat "$1/data/postgresql/18/docker/PG_VERSION")" = 18' _ "$LV_ROOT"

  it_step "restore of the pre-upgrade backup on this host (now $PX_NEW, PostgreSQL 18)"
  lv_cx restore restore "$backup" --same-host --yes --confirm-data-loss
  it_same "restore exits 0" 0 "$LV_RC"
  it_check "the preview names the old version and PostgreSQL 16" bash -c 'grep -q "$2" <<<"$1" && grep -q "PostgreSQL 16" <<<"$1"' _ "$LV_OUT" "$PX_OLD"
  lv_wait_version "$PX_OLD"
  it_same "current.version, the current link" "$PX_OLD releases/$PX_OLD" "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  it_same "the data folder in use is PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  it_check "data/postgresql does not exist" test ! -e "$LV_ROOT/data/postgresql"
  kept_a=$(compgen -G "$LV_ROOT/data/postgres.before-restore-*" | head -n1)
  kept_b=$(compgen -G "$LV_ROOT/data/postgresql.before-restore-*" | head -n1)
  it_check "postgres.before-restore-* is kept ($kept_a)" test -d "$kept_a"
  it_check "postgresql.before-restore-* is kept ($kept_b)" test -d "$kept_b"
  it_same "the kept postgres folder is PostgreSQL 16" 16 "$(cat "$kept_a/PG_VERSION")"
  it_same "the kept postgresql folder is PostgreSQL 18" 18 "$(cat "$kept_b/18/docker/PG_VERSION")"
  LV_TOKEN=""
  it_same "the data equals R0 (the backup was made when the upgrade began)" "$r0" "$(px_fp lv_sql)"
  it_same "the user written on the new version is not here" 0 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-on-new'")"
  px_read_start "$kept_b" 18
  it_same "the kept PostgreSQL 18 folder holds what the new version wrote" "1 1" \
    "$(px_read_sql "SELECT (SELECT count(*) FROM users WHERE username = 'it-on-new') || ' ' || (SELECT count(*) FROM it_marker WHERE id = 9001)")"
  px_read_stop

  it_step "upgrade again: it converts again, the kept folders are as they were"
  px_upgrade
  lv_wait_version "$PX_NEW"
  it_same "PostgreSQL 18 runs" 18 "$(lv_sql 'SHOW server_version_num' | cut -c1-2)"
  it_same "the data equals R0" "$r0" "$(px_fp lv_sql)"
  it_check "both kept folders are still there under the same names" test -d "$kept_a" -a -d "$kept_b"
}

scenario() {
  px_section "restore of a PostgreSQL 16 backup on the PostgreSQL 18 host" pq_restore_other_major
  ex_teardown "$LV_ROOT" || true
  [ -z "$px_failed" ] || it_die "sections not ok:$px_failed"
}
