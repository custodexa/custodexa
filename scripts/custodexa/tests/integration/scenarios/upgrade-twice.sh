# shellcheck shell=bash
# about: a built-in deployment upgrades twice in a row (the release before the older one, the older one, the package's); each upgrade's backup file holds the state.json of before that upgrade: its current.* is the version then running, previous.* the one before
# needs: package upgrade twice
# images:

scenario() {
  local root=/opt/custodexa v0 v1 v2
  v0=$(jq -r .version /it-run/pkg-from2/MANIFEST.json)
  v1=$(jq -r .version /it-run/pkg-from/MANIFEST.json)
  v2=$(jq -r .version /it-run/pkg/MANIFEST.json)
  it_step "built-in form, master key mode env: install $v0"
  it_unpack /opt from2
  ex_preset "$root" KEK_PROVIDER=env
  it_cx "$root" install --images "$(it_bundle_file from2)"
  it_step "first upgrade $v0 -> $v1"
  ex_upgrade "$root" offline from
  it_same "its state.json member: current.version / previous.version" "$v0 " \
    "$(jq -r '."current.version" + " " + (."previous.version" // "")' "$EX_X/state.json")"
  it_step "second upgrade $v1 -> $v2"
  ex_upgrade "$root" offline
  it_same "its state.json member: current.version / previous.version" "$v1 $v0" \
    "$(jq -r '."current.version" + " " + (."previous.version" // "")' "$EX_X/state.json")"
  it_same "its state.json member: current.* is the state before the second upgrade" \
    "$(jq -cS 'with_entries(select(.key | startswith("current.")))' "$IT_WORK/state.before.json")" \
    "$(jq -cS 'with_entries(select(.key | startswith("current.")))' "$EX_X/state.json")"
  ex_status "$root" "$v2"
  ex_teardown "$root"
}
