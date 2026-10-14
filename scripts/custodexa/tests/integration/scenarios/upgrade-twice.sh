# shellcheck shell=bash
# about: a built-in deployment upgrades twice in a row (the release before the older one, the older one, the package's); each upgrade's backup file holds the state.json of before that upgrade: its current.* is the version then running, previous.* the one before; after the second upgrade the backend and frontend images of the first version are gone, those of the other two and every upstream image still there
# needs: package upgrade twice
# images:

# tw_id <state file> <key> <name>: the image ID the state file records for <name> under <key>.
tw_id() { jq -r --arg k "$2" '.[$k] // ""' "$1" | tr ' ' '\n' | sed -n "s/^$3=//p"; }

# tw_upstream: the IDs of every image on this host with no backend or frontend reference, sorted.
tw_upstream() {
  local id refs
  for id in $(docker image ls -a -q --no-trunc | sort -u); do
    refs=$(docker image inspect --format '{{range .RepoTags}}{{.}} {{end}}{{range .RepoDigests}}{{.}} {{end}}' "$id")
    [[ " $refs" =~ /(backend|frontend)[:@] ]] || printf '%s\n' "$id"
  done | sort
}

tw_has() { docker image inspect "$1" >/dev/null 2>&1; }

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
  local up_before n st0 id
  up_before=$(tw_upstream)
  cp "$root/state.json" "$IT_WORK/state.first.json"
  ex_upgrade "$root" offline
  it_same "its state.json member: current.version / previous.version" "$v1 $v0" \
    "$(jq -r '."current.version" + " " + (."previous.version" // "")' "$EX_X/state.json")"
  it_same "its state.json member: current.* is the state before the second upgrade" \
    "$(jq -cS 'with_entries(select(.key | startswith("current.")))' "$IT_WORK/state.before.json")" \
    "$(jq -cS 'with_entries(select(.key | startswith("current.")))' "$EX_X/state.json")"
  it_step "images after the second upgrade"
  it_check "the closing screen counts the old images removed" grep -qE 'Removed [0-9]+ old backend and frontend image' <<<"$EX_OUT"
  st0=$IT_WORK/state.first.json
  for n in backend frontend; do
    id=$(tw_id "$st0" previous.image_ids "$n")
    it_check "$n of $v0 ($id) recorded before the second upgrade" test -n "$id"
    it_check "$n of $v0 is gone" bash -c '! docker image inspect "$1" >/dev/null 2>&1' _ "$id"
    id=$(tw_id "$root/state.json" previous.image_ids "$n")
    it_check "$n of $v1 (previous, $id) is here" tw_has "$id"
    id=$(tw_id "$root/state.json" current.image_ids "$n")
    it_check "$n of $v2 (current, $id) is here" tw_has "$id"
  done
  it_same "the upstream images are the same as before the second upgrade" "$up_before" "$(tw_upstream)"
  it_check "the upgrade log records the removals" grep -q 'IMAGE old images removed=[1-9]' "$(find "$root/logs" -name 'upgrade-*.log' -newer "$IT_WORK/mark" | sort | tail -n 1)"
  ex_status "$root" "$v2"
  ex_teardown "$root"
}
