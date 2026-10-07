# shellcheck shell=bash
# about: the builder makes 1.16.90, 1.16.91 and 1.16.92 from the working tree (images, install package, offline bundle each): each MANIFEST names its version and the images built for it, 1.16.92 has exactly one migration more (it_rollback_probe), 1.16.91 the same ones as 1.16.90, and the working tree is unchanged by the build
# needs: package local-versions
# images:

lv_mf() { jq -r "$2" "/it-run/pkg-$1/MANIFEST.json"; }

scenario() {
  local v a b
  it_same "the versions built" "1.16.90 1.16.91 1.16.92" "$(cat /it-run/local-versions)"
  for v in 1.16.90 1.16.91 1.16.92; do
    it_step "$v"
    it_check "$v: the package matches its SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "/it-run/pkg-$v"
    it_same "$v: MANIFEST.json version" "$v" "$(lv_mf "$v" .version)"
    it_same "$v: the MANIFEST inside the package is the one beside it" "$(sha256sum <"/it-run/pkg-$v/MANIFEST.json")" \
      "$(tar -xzOf "/it-run/pkg-$v/custodexa-$v.tar.gz" "custodexa/releases/$v/MANIFEST.json" | sha256sum)"
    it_same "$v: VERSION in the package" "$v" "$(tar -xzOf "/it-run/pkg-$v/custodexa-$v.tar.gz" "custodexa/releases/$v/VERSION")"
    it_same "$v: own images are the ones built for $v" \
      "ghcr.io/custodexa-it/backend:$v ghcr.io/custodexa-it/frontend:$v" \
      "$(lv_mf "$v" '"\(.images.backend.ref):\(.images.backend.tag) \(.images.frontend.ref):\(.images.frontend.tag)"')"
    it_check "$v: the offline bundle matches its SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "/bundle-$v"
    it_check "$v: the offline bundle is named for $v" test -f "$(it_bundle_file "$v")"
    it_same "$v: rollback_compatible is empty" "[]" "$(lv_mf "$v" '.rollback_compatible | tostring')"
  done
  a=$(lv_mf 1.16.90 '.migrations[]')
  it_same "1.16.91 has the migrations of 1.16.90" "$a" \
    "$(lv_mf 1.16.91 '.migrations[]')"
  b=$(lv_mf 1.16.92 '.migrations[]')
  it_same "1.16.92 has one migration more than 1.16.90: it_rollback_probe" "it_rollback_probe" \
    "$(comm -13 <(sort <<<"$a") <(sort <<<"$b"))"
  it_same "and none fewer" "" "$(comm -23 <(sort <<<"$a") <(sort <<<"$b"))"
  it_check "the backend images of 1.16.90 and 1.16.91 differ (the version is built in)" \
    test "$(lv_mf 1.16.90 .images.backend.platforms.arm64.config_digest)" != "$(lv_mf 1.16.91 .images.backend.platforms.arm64.config_digest)"
  it_check "the working tree's git status was recorded before the build" test -f /it-run/worktree-status.before
  it_same "the working tree's git status is the same after the build" \
    "$(cat /it-run/worktree-status.before)" "$(cat /it-run/worktree-status.after)"
}
