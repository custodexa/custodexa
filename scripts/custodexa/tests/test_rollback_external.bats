#!/usr/bin/env bats
# `rollback` on a deployment that uses an external database. No client is chosen unless the command
# chooses one (the recorded client images, as every other command that talks to that database
# does), and without one the migrations cannot be read, which the judgment must refuse. So this
# file pins three things: the same migrations go back; the permission model boundary still
# refuses; and a client that cannot be chosen still refuses as unreadable.

load helper
load install_host
load backup_host
load upgrade_host
load rollback_host

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

# ext_host: the upgraded 1.16.1 -> 1.16.2 host, recorded as one on an external database whose
# three PostgreSQL clients this host holds.
ext_host() {
  local m ids=""
  rb_cached ready ui "${1:-1.16.1}" "${2:-1.16.2}"
  bk_state_set current.overlays external-database
  for m in 16 17 18; do ids+="${ids:+ }pgclient$m=${BK_PGC_ID[$m]}"; done
  bk_state_set current.tool_image_ids "$ids"
  printf '%s\n' "${BK_PGC_ID[16]}" "${BK_PGC_ID[17]}" "${BK_PGC_ID[18]}" >>"$DB/images"
  bk_env_set DB_USER custodexa_app
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  bk_env_set EXTERNAL_DB_PORT 5432
  bk_env_set DB_SSLMODE verify-full
  bk_server 17.6
  : >"$DB/events"
  : >"$DB/db-calls"
}

# decide_ext <function...>: as the command sets things up, the judgment functions on $ROOT.
decide_ext() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/backup.sh"
    . "$1/lib/rollback_check.sh"; CX_ROOT=$2; cx_bk_vars; cx_state_load "$2/state.json"
    CX_OVERLAYS=$(cx_state_get current.overlays); shift 2
    rc=0; for f in "$@"; do "$f" || { rc=$?; break; }; done
    printf "basis=%s reason=%s added=%s client=%s\n" "$CX_RB_BASIS" "$CX_RB_REASON" \
      "${CX_RB_ADDED[*]+"${CX_RB_ADDED[*]}"}" "${CX_DB_EXT_ID:+chosen}"
    exit "$rc"' _ "$SRC" "$ROOT" "$@"
}

setup() {
  host_workdir
}

@test "rollback external: the same migrations judge as unchanged, the migrations are read by a recorded client" {
  ext_host
  decide_ext cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=same_migrations "*"client=chosen"* ]] || { echo "$output"; return 1; }
  grep -q '^sql psql migrations' "$DB/db-calls" || { cat "$DB/db-calls"; return 1; }
}

@test "rollback external: the command goes back on the same migrations, the migrations read from the external database" {
  ext_host
  rb_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; cat "$DB/events"; return 1; }
  [ "$(st last_rollback.basis)" = same_migrations ]
  [ "$(st current.version)" = 1.16.1 ]
  [ "$(readlink "$ROOT/current")" = releases/1.16.1 ]
  grep -q 'psql migrations' "$DB/events"
  # The external database is not stopped; the bundled one's stop never ran.
  ! grep -q '^stop postgres' "$DB/events"
}

@test "rollback external: a migration the new version added still refuses, across the permission model too" {
  ext_host 1.17.9 1.18.0
  local mig=20261016_authz_permission_model
  printf '%s\n' "$mig" >>"$DB/migrations"
  jq -e '(.rollback_compatible // []) | index("1.17.9") | not' "$ROOT/releases/1.18.0/MANIFEST.json" >/dev/null
  decide_ext cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=changed added=$mig "* ]] || { echo "$output"; return 1; }
  # Listing the version before as compatible does not open the way across the model.
  jq '.rollback_compatible = ["1.17.9"] | .migrations = ((.migrations // []) + ["'"$mig"'"])' \
    "$ROOT/releases/1.18.0/MANIFEST.json" >"$BATS_TEST_TMPDIR/m"
  cp "$BATS_TEST_TMPDIR/m" "$ROOT/releases/1.18.0/MANIFEST.json"
  decide_ext cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=changed added=$mig "* ]] || { echo "$output"; return 1; }
  cp "$ROOT/state.json" "$DB/before"
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *"custodexa.sh restore "* ]] || { echo "$output"; return 1; }
  cmp "$ROOT/state.json" "$DB/before"
  [ "$(readlink "$ROOT/current")" = releases/1.18.0 ]
  ! grep -Eq '^(stop|up|start)' "$DB/events"
}

@test "rollback external: no client that can be chosen is unreadable, and refuses" {
  ext_host
  # The recorded clients are gone from this host.
  : >"$DB/images"
  decide_ext cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=unreadable "* ]] || { echo "$output"; return 1; }
  ! grep -q 'migrations' "$DB/db-calls"
  # No client recorded at all.
  ext_host
  bk_state_set current.tool_image_ids ""
  decide_ext cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"reason=unreadable "* ]] || { echo "$output"; return 1; }
  # The command refuses the same way and changes nothing.
  cp "$ROOT/state.json" "$DB/before"
  rb_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  cmp "$ROOT/state.json" "$DB/before"
  [ "$(readlink "$ROOT/current")" = releases/1.16.2 ]
  ! grep -Eq '^(stop|up|start)' "$DB/events"
}
