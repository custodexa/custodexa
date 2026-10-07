# shellcheck shell=bash
# about: the published 1.15.2 (its own package and offline bundle) upgraded offline by script to 1.16.90 of the working tree, in the built-in form (host builtin) and the external ingress form (host ingress): the upgrade exits 0, the backend reports 1.16.90, the current link and state.json name it, the upgrade's portable backup file of 1.15.2 is there and reads, a user and an asset written on 1.15.2 read the same, status passes; rollback is refused before anything stops (1.15.2 is older than 1.16.0) and names the backup file
# hosts: builtin ingress
# needs: package local-versions published
# images:

readonly UP_OLD=1.15.2 UP_NEW=1.16.90
readonly UP_INGRESS=current/compose.yml:current/compose.external-ingress.yml

# up_flat: the screen of the last lv_cx on one line, spaces squeezed.
up_flat() { tr '\n' ' ' <<<"$LV_OUT" | tr -s ' '; }

# up_install <form>: the published package unpacked as an operator does, master key mode env (and
# the external ingress overlay for form ingress), installed from the published offline bundle.
up_install() {
  local form=$1 bundle
  it_step "$form: the published $UP_OLD package and offline bundle"
  it_check "$form: the published files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  bundle=$(find /published -maxdepth 1 -name "custodexa-images-$UP_OLD-*.tar")
  mkdir -p /opt
  tar -xzf "/published/custodexa-$UP_OLD.tar.gz" -C /opt
  it_same "$form: the published package is $UP_OLD" "$UP_OLD" "$(cat "$LV_ROOT/current/VERSION")"
  if [ "$form" = ingress ]; then
    ex_preset "$LV_ROOT" KEK_PROVIDER=env "COMPOSE_FILE=$UP_INGRESS"
  else
    ex_preset "$LV_ROOT" KEK_PROVIDER=env
  fi
  it_step "$form: install $UP_OLD --images ${bundle##*/}"
  lv_cx install install --images "$bundle"
  it_same "$form: install $UP_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$UP_OLD"
  if [ "$form" = ingress ]; then
    it_same "$form: the external ingress overlay is recorded" external-ingress "$(lv_st current.overlays)"
    it_check "$form: no tls/ folder (the ingress terminates TLS)" test ! -e "$LV_ROOT/tls"
  else
    it_same "$form: no overlay is recorded" "" "$(lv_st current.overlays)"
    it_check "$form: the built-in proxy has its tls/ folder" test -d "$LV_ROOT/tls"
  fi
}

# up_data_json: the user and the asset written by up_data, read through the API of the version
# running now, as the fields both versions return.
up_data_json() {
  local uid aid
  read -r uid aid <"$IT_WORK/up-data.ids"
  {
    lv_api GET "/users/$uid" | jq -c '(.data // .) | {user: {id, username, email, full_name}}'
    lv_api GET "/assets/$aid" | jq -c '(.data // .) | {asset: {id, name, protocol, host, port, description}}'
  } | jq -scS add
}

# up_rows: users, assets and the rows of the two written by up_data, from the database itself.
up_rows() {
  lv_sql "SELECT (SELECT count(*) FROM users)||' users, '||(SELECT count(*) FROM assets)||' assets; '||
    (SELECT username FROM users WHERE username = 'it-before-upgrade')||' '||
    (SELECT host||':'||port FROM assets WHERE name = 'it-before-upgrade')"
}

# up_data <form>: a user and an asset written through the API of $UP_OLD.
up_data() {
  local form=$1 r uid aid
  it_step "$form: a user and an asset written on $UP_OLD"
  r=$(lv_api POST /users "$(jq -cn '{username: "it-before-upgrade", password: "It-user-pass-0001",
    email: "it-before-upgrade@example.test", full_name: "Upgrade test user"}')")
  uid=$(jq -er '.data.id // .id' <<<"$r")
  r=$(lv_api POST /assets "$(jq -cn '{name: "it-before-upgrade", protocol: "ssh", host: "192.0.2.20",
    port: 22, description: "upgrade test asset", tags: "it,upgrade"}')")
  aid=$(jq -er '.data.id // .id' <<<"$r")
  printf '%s %s\n' "$uid" "$aid" >"$IT_WORK/up-data.ids"
  up_data_json >"$IT_WORK/up-data.json"
  up_rows >"$IT_WORK/up-rows.txt"
  it_say "   on $(lv_version): $(cat "$IT_WORK/up-rows.txt")"
  it_check "$form: the API returns the user and the asset just written" \
    test "$(jq -r '.user.username + " " + .asset.host' "$IT_WORK/up-data.json")" = "it-before-upgrade 192.0.2.20"
}

# up_upgrade <form>: upgrade --images to $UP_NEW with its package, offline; what the record, the
# link and the backend say after it, and the portable backup file it took before the switch.
up_upgrade() {
  local form=$1 f log x tls_want
  it_step "$form: upgrade $UP_OLD -> $UP_NEW offline (the $UP_OLD script hands the upgrade to the $UP_NEW script)"
  touch "$IT_WORK/mark"
  sleep 1
  lv_upgrade "$UP_NEW"
  UP_UPGRADE_OUT=$LV_OUT
  lv_wait_version "$UP_NEW"
  it_same "$form: last_upgrade.result, from, to" "succeeded $UP_OLD $UP_NEW" \
    "$(lv_st last_upgrade.result) $(lv_st last_upgrade.from) $(lv_st last_upgrade.to)"
  it_same "$form: current.version, previous.version" "$UP_NEW $UP_OLD" "$(lv_st current.version) $(lv_st previous.version)"
  it_same "$form: the current link points at releases/$UP_NEW" "releases/$UP_NEW" "$(readlink "$LV_ROOT/current")"
  it_same "$form: the running script is the $UP_NEW one" "$UP_NEW" "$(cat "$LV_ROOT/current/VERSION")"
  it_same "$form: the running images are the ones recorded for $UP_NEW" "$(lv_st current.image_ids)" "$(lv_ids_running)"
  log=$(find "$LV_ROOT/logs" -name 'upgrade-*.log' -newer "$IT_WORK/mark" | sort | tail -n 1)
  it_same "$form: no image came from a registry or was built" "" \
    "$(grep -E 'IMAGE .* source=([a-z0-9-]+\.[a-z0-9.-]+|build) .* OK$' "$log" || true)"
  it_check "$form: the upgrade's screen offers no rollback command (the version before is older than 1.16.0)" \
    bash -c '! grep -q "custodexa.sh rollback" <<<"$1"' _ "$UP_UPGRADE_OUT"

  it_step "$form: the portable backup the upgrade took before the switch"
  f=$(lv_st last_upgrade.backup)
  UP_BACKUP=$f
  it_check "$form: last_upgrade.backup ($f) is a backup file of $UP_OLD" \
    grep -qE "^backups/custodexa-backup-${UP_OLD//./\\.}-[0-9]{8}-[0-9]{6}\.tar$" <<<"$f"
  it_same "$form: last_upgrade.backup_kind" script "$(lv_st last_upgrade.backup_kind)"
  it_check "$form: the file and its .sha256 are there, 0600" \
    test "$(stat -c %a "$LV_ROOT/$f") $(stat -c %a "$LV_ROOT/$f.sha256")" = "600 600"
  it_check "$form: its checksum file matches" bash -c 'cd "${1%/*}" && sha256sum -c --quiet "${1##*/}.sha256"' _ "$LV_ROOT/$f"
  it_same "$form: no upgrade backup folder is made" "" \
    "$(find "$LV_ROOT/backups" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -newer "$IT_WORK/mark")"
  x=$IT_WORK/upgrade-backup
  rm -rf "$x"
  mkdir -p "$x"
  tar -xf "$LV_ROOT/$f" -C "$x"
  it_check "$form: the members match its SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$x"
  tls_want=true
  [ "$form" = builtin ] || tls_want=false
  it_same "$form: manifest trigger, product.version, db.location, contents.state, contents.tls" \
    "upgrade $UP_OLD bundled true $tls_want" \
    "$(jq -r '[.trigger, ."product.version", ."db.location", (."contents.state"|tostring), (."contents.tls"|tostring)] | join(" ")' "$x/backup-manifest.json")"
  it_same "$form: the state.json member is the state before (current.version)" "$UP_OLD" \
    "$(jq -r '."current.version"' "$x/state.json")"
  it_check "$form: the snapshot before the upgrade equals the member snapshot.txt" cmp "${log%.log}.before.txt" "$x/snapshot.txt"
  it_check "$form: the dump lists with pg_restore" \
    bash -c 'docker exec -i custodexa-postgres pg_restore --list <"$1" >/dev/null' _ "$x/db.dump"
  it_check "$form: the dump holds the user written on $UP_OLD" \
    bash -c 'docker exec -i custodexa-postgres pg_restore --data-only --table=users -f - <"$1" | grep -q it-before-upgrade' _ "$x/db.dump"
  if [ "$form" = ingress ]; then
    it_same "$form: the external ingress overlay is kept" external-ingress "$(lv_st current.overlays)"
    it_check "$form: still no tls/ folder" test ! -e "$LV_ROOT/tls"
    it_check "$form: no certificate initializer or built-in proxy container" \
      bash -c '! docker container inspect custodexa-tls-init >/dev/null 2>&1 && ! docker container inspect custodexa-tls-proxy >/dev/null 2>&1'
  fi
}

# up_after <form> <service count> <front url> <front status>: the data written on $UP_OLD, status,
# the frontend as the deployment guide's check reaches it.
up_after() {
  local form=$1 n=$2 url=$3 code=$4 out
  it_step "$form: the data written on $UP_OLD, through $UP_NEW"
  # shellcheck disable=SC2034 # read by lv_api: sign in again on the version now running
  LV_TOKEN=""
  it_same "$form: users, assets and the two rows, from the database" "$(cat "$IT_WORK/up-rows.txt")" "$(up_rows)"
  it_same "$form: the user and the asset read the same through the API" "$(cat "$IT_WORK/up-data.json")" "$(up_data_json)"

  it_step "$form: status"
  lv_cx status status
  it_check "$form: status exits 0 or 4 (warnings only), got $LV_RC" test "$LV_RC" = 0 -o "$LV_RC" = 4
  it_same "$form: status reports no failure" 0 "$(grep -c '\[FAIL\]' <<<"$LV_OUT" || true)"
  it_check "$form: status reports the backend healthy at $UP_NEW" grep -qF "[ OK ] Backend healthy, version $UP_NEW" <<<"$LV_OUT"
  it_check "$form: status counts $n service processes" grep -q "\[ OK \] $n service processes started" <<<"$LV_OUT"
  out=$(curl -skI --max-time 10 "$url" 2>&1 | sed -n 1p) || true
  it_say "   curl -skI $url : $out"
  it_check "$form: $url answers $code" grep -q "^HTTP/[0-9.]* $code" <<<"$out"
}

# up_host_state: what a refused rollback must leave as it was.
up_host_state() {
  (
    cd "$LV_ROOT" || exit 1
    sha256sum .env state.json
    readlink current
    ls -1A releases
  )
}

# up_rollback <form>: rollback after the upgrade, without a terminal and without --yes. Going back
# to a version older than 1.16.0 is refused before anything stops (the design's premise row 5, no
# database read), whatever the migrations; the screen names the backup file to restore by hand.
up_rollback() {
  local form=$1 ps0 st0 now before added
  it_step "$form: rollback to $UP_OLD"
  now=$(lv_sql "SELECT version FROM schema_migrations ORDER BY version" | LC_ALL=C sort -u)
  before=$(sed -n 's/^migration=//p' "$IT_WORK/upgrade-backup/snapshot.txt" | LC_ALL=C sort -u)
  added=$(LC_ALL=C comm -23 <(printf '%s\n' "$now") <(printf '%s\n' "$before") | paste -sd ' ')
  it_say "   migrations: $(grep -c . <<<"$before") before the upgrade, $(grep -c . <<<"$now") now; added by $UP_NEW: ${added:-none}"
  ps0=$(lv_ps)
  st0=$(up_host_state)
  lv_cx rollback rollback </dev/null
  it_same "$form: rollback exits 3" 3 "$LV_RC"
  it_check "$form: the screen says it cannot go straight back to $UP_OLD, only to 1.16.0 or later, nothing changed" \
    grep -qF "Cannot go straight back to $UP_OLD: the script can only go back to 1.16.0 or later. Nothing was changed." <<<"$(up_flat)"
  it_check "$form: the screen gives the hand restore of the guide" grep -qF 'section 5 "Restore procedure"' <<<"$(up_flat)"
  it_check "$form: the screen names the upgrade's backup file" grep -qF "$LV_ROOT/$UP_BACKUP" <<<"$LV_OUT"
  it_check "$form: no preview and no confirmation were reached" \
    bash -c '! grep -qE "\[y/N\]|--yes" <<<"$1"' _ "$LV_OUT"
  it_same "$form: the same containers run" "$ps0" "$(lv_ps)"
  it_same "$form: .env, state.json, the current link and releases/ are unchanged" "$st0" "$(up_host_state)"
  it_same "$form: no rollback record" "" "$(lv_st last_rollback.result)"
  it_same "$form: the backend still reports $UP_NEW" "$UP_NEW" "$(lv_version)"
}

scenario_builtin() {
  up_install builtin
  up_data builtin
  up_upgrade builtin
  up_after builtin 6 https://localhost/ 200
  up_rollback builtin
}

scenario_ingress() {
  up_install ingress
  up_data ingress
  up_upgrade ingress
  up_after ingress 4 http://localhost/ 200
  up_rollback ingress
}
