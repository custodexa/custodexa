# shellcheck shell=bash
# about: the package built from the working tree installs (built-in database, offline bundle) and status reports it
# needs: package
# images:

scenario() {
  local root=/opt/custodexa version out rc
  it_step "unpack the package"
  it_unpack /opt
  version=$(jq -r .version "$root/current/MANIFEST.json")
  it_check "the package carries the working tree's management scripts" \
    diff -r /src/scripts/custodexa/lib "$root/current/lib"
  it_check "the package carries the working tree's compose overlays" \
    diff /src/packaging/compose.external-ingress.yml "$root/current/compose.external-ingress.yml"

  it_step "install --images $(it_bundle_file)"
  it_cx "$root" install --images "$(it_bundle_file)"
  it_same "install recorded as succeeded" succeeded "$(jq -r '."install.result"' "$root/state.json")"
  it_same "current version is the package's" "$version" "$(jq -r '."current.version"' "$root/state.json")"
  it_same "built-in deployment (no overlay)" "" "$(jq -r '."current.overlays"' "$root/state.json")"

  # status exits 4 when it shows a warning; a fresh install in browser-entered master key mode
  # always has some (master key not set up, no backup, publisher not verified offline).
  it_step "status"
  out=$(it_cx "$root" status) && rc=0 || rc=$?
  printf '%s\n' "$out"
  it_check "status exits 0 or 4 (warnings only), got $rc" test "$rc" = 0 -o "$rc" = 4
  it_check "status reports no failure" test "$(grep -c '\[FAIL\]' <<<"$out")" = 0
  it_check "status reports the backend healthy at $version" grep -qF "[ OK ] Backend healthy, version $version" <<<"$out"
  it_check "status sees the services started" grep -q '\[ OK \] .* service processes started' <<<"$out"
}
