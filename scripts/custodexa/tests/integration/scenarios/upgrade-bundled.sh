# shellcheck shell=bash
# about: a built-in deployment upgrades from the older release to the package's: the upgrade's backup is one portable file (no folder), the snapshot before equals its snapshot.txt, the state.json member is the state before, and the check after the start passes
# needs: package upgrade
# images:

scenario() {
  local root=/opt/custodexa
  it_step "built-in form, master key mode env: install $(jq -r .version /it-run/pkg-from/MANIFEST.json)"
  it_unpack /opt from
  ex_preset "$root" KEK_PROVIDER=env
  it_cx "$root" install --images "$(it_bundle_file from)"
  ex_upgrade "$root" offline
  it_same "the upgrade's backup is of the built-in database" bundled "$(ex_mf db.location)"
  it_check "the dump lists" bash -c 'docker exec -i custodexa-postgres pg_restore --list <"$1" >/dev/null' _ "$EX_X/db.dump"
  ex_status "$root" "$(ex_st "$root" current.version)"
  ex_teardown "$root"
}
