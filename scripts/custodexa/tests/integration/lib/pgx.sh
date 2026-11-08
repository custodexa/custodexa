# shellcheck shell=bash
# Shared by the scenarios that go between the bundled database's majors (pg18-rollback,
# pg18-restore): a published release (PostgreSQL 16) installed from its own package and offline
# bundle, upgraded to the version built from the working tree (PostgreSQL 18).
#   PX_OLD, PX_NEW           the published release and the first local version of this run
#   px_install_old           install PX_OLD, check its data folder is PostgreSQL 16
#   px_seed <tag>            a user and an asset (through the API), rows in it_marker, a sequence
#   px_fp <sql runner>       one line over the data a rollback or a restore must give back
#   px_upgrade [rc]          upgrade to PX_NEW (--yes); LV_INJECT applies
#   px_read_start <folder> <major> / px_read_sql <sql> / px_read_stop
#                            a server of that major on a data folder, no network, to read it
#   px_section <label> <fn>  one section in a subshell of its own (CX_IT_PG_SECTIONS selects)
#   px_fresh <tag>           a clean host state: the old release installed and seeded
#   px_shim_mv               an mv wrapper: LV_INJECT=hold-rename waits after the rename of a
#                            folder named postgresql.rolled-back-* until $IT_WORK/lv-hold is removed

PX_OLD=$(find /published -maxdepth 1 -name 'custodexa-[0-9]*.tar.gz' | sed -E 's#.*/custodexa-(.*)\.tar\.gz#\1#' | head -n1)
PX_NEW=$(cut -d' ' -f1 /it-run/local-versions 2>/dev/null || true)
readonly PX_OLD PX_NEW

px_install_old() {
  local bundle
  it_step "install the published $PX_OLD (PostgreSQL 16)"
  it_check "the published files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  bundle=$(find /published -maxdepth 1 -name "custodexa-images-$PX_OLD-*.tar")
  mkdir -p /opt
  tar -xzf "/published/custodexa-$PX_OLD.tar.gz" -C /opt
  ex_preset "$LV_ROOT" KEK_PROVIDER=env
  lv_cx install install --images "$bundle"
  it_same "install $PX_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$PX_OLD"
  it_same "the data folder is PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  LV_TOKEN=""
}

px_seed() {
  local tag=$1
  it_step "$tag: a user, an asset (the API writes them), it_marker rows and a sequence"
  lv_api POST /users "$(jq -cn --arg u "it-before-$tag" '{username: $u, password: "It-user-pass-0001",
    email: ($u + "@example.test"), full_name: "Upgrade test user"}')" >/dev/null
  lv_api POST /assets "$(jq -cn --arg n "it-before-$tag" '{name: $n, protocol: "ssh", host: "192.0.2.20", port: 22,
    description: "upgrade test asset", tags: "it,upgrade"}')" >/dev/null
  lv_sql "CREATE TABLE it_marker AS SELECT g AS id, 'r0-' || g AS note FROM generate_series(1, 500) g" >/dev/null
  lv_sql "CREATE SEQUENCE it_seq" >/dev/null
  lv_sql "SELECT setval('it_seq', 4242)" >/dev/null
}

# px_fp <runner...>: the runner takes the SQL as its last argument. The same data reads the same
# line on PostgreSQL 16 and 18, and a line that differs shows data that is not the same.
px_fp() {
  "$@" "SELECT concat_ws(' ',
    (SELECT count(*) || ':' || md5(string_agg(m::text, ',' ORDER BY m::text)) FROM it_marker m),
    (SELECT count(*) || ':' || md5(string_agg(username, ',' ORDER BY username)) FROM users),
    (SELECT count(*) || ':' || md5(string_agg(name, ',' ORDER BY name)) FROM assets),
    (SELECT count(*) || ':' || md5(string_agg(version, ',' ORDER BY version)) FROM schema_migrations),
    (SELECT last_value::text FROM it_seq))"
}

px_upgrade() {
  : >"$IT_WORK/docker-calls.log"
  lv_cx up upgrade "$(it_package_file "$PX_NEW")" --images "$(it_bundle_file "$PX_NEW")" --yes
  it_same "upgrade exits ${1:-0}" "${1:-0}" "$LV_RC"
}

px_read_start() {
  local folder=$1 major=$2 man ref target
  if [ "$major" = 18 ]; then
    man=/it-run/pkg-$PX_NEW/MANIFEST.json target=/var/lib/postgresql
  else
    man=$(find /published -maxdepth 1 -name MANIFEST.json | head -n1)
    [ -n "$man" ] || man=$LV_ROOT/releases/$PX_OLD/MANIFEST.json
    target=/var/lib/postgresql/data
  fi
  ref=$(jq -r '"\(.images.postgres.ref):\(.images.postgres.tag)"' "$man")
  docker rm -f it-px-read >/dev/null 2>&1 || true
  docker run -d --name it-px-read --network none -v "$folder:$target" "$ref" >/dev/null
  lv_until "the server on $folder answers" docker exec it-px-read pg_isready -q
}
px_read_sql() {
  docker exec -i it-px-read psql -X -v ON_ERROR_STOP=1 -At -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "$1"
}
px_read_stop() { docker rm -f it-px-read >/dev/null 2>&1 || true; }

px_kill_stray() {
  pkill -KILL -f "$LV_ROOT/custodexa.sh" 2>/dev/null || true
  pkill -KILL -f "$IT_WORK/lvshim/" 2>/dev/null || true
  sleep 1
}

px_fresh() {
  px_kill_stray
  px_read_stop
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK"/lv-* "$IT_WORK/df-small"
  mkdir -p "$IT_WORK"
  px_install_old
  px_seed "$1"
}

px_shim_mv() {
  mkdir -p "$IT_WORK/lvshim"
  cat >"$IT_WORK/lvshim/mv" <<SHIM
#!/usr/bin/env bash
real=\$(PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin command -v mv)
"\$real" "\$@"
rc=\$?
case " \${LV_INJECT:-} " in
  *" hold-rename "*)
    if [[ "\$*" == *"postgresql.rolled-back-"* ]]; then
      touch "$IT_WORK/lv-rename-reached"
      while [ -e "$IT_WORK/lv-hold" ]; do sleep 0.2; done
    fi
    ;;
esac
exit \$rc
SHIM
  chmod +x "$IT_WORK/lvshim/mv"
}

px_failed=""
px_section() {
  local label=$1 fn=$2 rc=0
  shift 2
  case " ${CX_IT_PG_SECTIONS:-all} " in *" all "* | *" $fn "*) ;; *) return 0 ;; esac
  it_step "section: $label"
  ( set -e; "$fn" "$@" ) &
  wait $! || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'section not ok - %s (%s, exit %s)\n' "$label" "$fn" "$rc"
    px_failed="$px_failed [$label]"
  else
    printf 'section ok - %s\n' "$label"
  fi
  px_kill_stray
  px_read_stop
  rm -f "$IT_WORK/lv-hold"
}
