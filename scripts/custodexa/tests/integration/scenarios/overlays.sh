# shellcheck shell=bash
# about: the built-in form and the external ingress form each go through install, backup, status, upgrade (older release to the package's), status and backup again; openssl is a service image in the first and a recorded tool image in the second; backups/ holds what the deployment guide says; tls/ is backed up where there is one, and its absence behind an own ingress is no failure; the frontend answers as the guide's post-restore check says
# needs: package upgrade
# images:

# overlays_status <root> <service count> <version>: status passes (warnings only), counts the
# services, reports the backend at that version.
overlays_status() {
  local root=$1 n=$2 out rc
  out=$(it_cx "$root" status --lang en) && rc=0 || rc=$?
  printf '%s\n' "$out"
  it_check "status exits 0 or 4 (warnings only), got $rc" test "$rc" = 0 -o "$rc" = 4
  it_check "status reports no failure" test "$(grep -c '\[FAIL\]' <<<"$out")" = 0
  it_check "status counts $n service processes" grep -q "\[ OK \] $n service processes started" <<<"$out"
  it_check "status reports the backend healthy at $3" grep -qF "[ OK ] Backend healthy, version $3" <<<"$out"
  STATUS_OUT=$out
}

# overlays_teardown <root>: remove the deployment (containers, networks, volumes, folder).
overlays_teardown() {
  local ids
  ids=$(docker ps -aq)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  docker network prune -f >/dev/null
  docker volume prune -af >/dev/null
  rm -rf "$1"
}

# overlays_backup <root> <version>: backup --yes writes one file and its checksum file where the
# deployment guide says (backups/custodexa-backup-<version>-<YYYYMMDD-HHMMSS>.tar, 0600, in a 0700
# backups/), state.json points at it, the temporary folder is gone. OV_FILE is its name.
overlays_backup() {
  local root=$1 v=$2 f
  it_cx "$root" backup --lang en --yes
  f=$(find "$root/backups" -maxdepth 1 -name "custodexa-backup-$v-*.tar" -newer "$IT_WORK/mark")
  OV_FILE=${f##*/}
  it_check "backups/$OV_FILE is named custodexa-backup-<version>-<YYYYMMDD-HHMMSS>.tar" \
    grep -qE "^custodexa-backup-${v//./\\.}-[0-9]{8}-[0-9]{6}\.tar$" <<<"$OV_FILE"
  it_same "backups/ is 0700" 700 "$(stat -c %a "$root/backups")"
  it_same "the file and its .sha256 are 0600" "600 600" "$(stat -c %a "$f") $(stat -c %a "$f.sha256")"
  it_check "the .sha256 names the file without a path and matches" \
    bash -c 'cd "$1" && [ "$(cut -d" " -f3 "$2.sha256")" = "$2" ] && sha256sum -c --quiet "$2.sha256"' _ "$root/backups" "$OV_FILE"
  it_same "no temporary folder is left" "" "$(find "$root/backups" -maxdepth 1 -name '.partial-*')"
  it_same "state.json points at it" "backups/$OV_FILE" "$(st last_backup.file)"
  it_same "the backup says the version" "$v" \
    "$(tar -xOf "$f" backup-manifest.json | jq -r '."product.version"')"
}

# overlays_tls <root> <true|false>: the last backup file holds tls.tar.gz exactly when the
# deployment has tls/, and its manifest says the same (contents.tls).
overlays_tls() {
  local f=$1/backups/$OV_FILE want=$2
  it_same "tls/ in the deployment: $want" "$want" "$([ -e "$1/tls" ] && echo true || echo false)"
  it_same "the manifest says contents.tls=$want" "$want" "$(tar -xOf "$f" backup-manifest.json | jq -r '."contents.tls"')"
  it_same "tls.tar.gz is a member: $want" "$want" "$(tar -tf "$f" | grep -qx tls.tar.gz && echo true || echo false)"
}

# overlays_front <url> <status>: the first line of curl -skI answers that status (section 6 item 4).
overlays_front() {
  local out
  out=$(curl -skI "$1" 2>&1 | sed -n 1p) || true
  it_say "   curl -skI $1 : $out"
  it_check "$1 answers $2" grep -q "^HTTP/[0-9.]* $2" <<<"$out"
}

# overlays_upgrade <root>: upgrade from the older release to the package's, with the package's
# offline bundle; the backup it takes is a folder backups/<YYYYMMDD-HHMMSS>/ (0700, complete).
overlays_upgrade() {
  local root=$1 to=$2 d
  touch "$IT_WORK/mark"
  sleep 1
  it_cx "$root" upgrade "$(it_package_file)" --images "$(it_bundle_file)" --yes --lang en
  it_same "upgrade recorded as succeeded" succeeded "$(st last_upgrade.result)"
  it_same "current version is $to" "$to" "$(st current.version)"
  d=$(find "$root/backups" -mindepth 1 -maxdepth 1 -type d -newer "$IT_WORK/mark" ! -name '.*')
  it_check "the upgrade's backup is a folder backups/<YYYYMMDD-HHMMSS>/" grep -qE '/backups/[0-9]{8}-[0-9]{6}$' <<<"$d"
  it_same "that folder is 0700" 700 "$(stat -c %a "$d")"
  it_check "that folder is complete: no INCOMPLETE, SHA256SUMS matches, snapshot.txt and state.json in it" \
    bash -c 'cd "$1" && [ ! -e INCOMPLETE ] && sha256sum -c --quiet SHA256SUMS && [ -s snapshot.txt ] && [ -s state.json ]' _ "$d"
  it_check "the earlier backup file is untouched" \
    bash -c 'cd "$1" && sha256sum -c --quiet "$2.sha256"' _ "$root/backups" "$OV_FILE"
  it_say "   backups/: $(cd "$root/backups" && find . -mindepth 1 -maxdepth 1 ! -name '.*' | sort | tr '\n' ' ')"
  if [ -e "$root/tls" ]; then
    it_check "the folder holds the tls archive" bash -c 'compgen -G "$1/custodexa-tls-*.tar.gz" >/dev/null' _ "$d"
  else
    it_check "no tls/: the folder has no tls archive, and the upgrade's log says why" \
      bash -c '! compgen -G "$1/custodexa-tls-*.tar.gz" >/dev/null && grep -q "CHECK tls=absent" "$(ls -t "$2"/logs/upgrade-*.log | head -n 1)"' _ "$d" "$root"
  fi
}

scenario() {
  local root=/opt/custodexa id want from to
  st() { jq -r --arg k "$1" '.[$k] // ""' "$root/state.json"; }
  from=$(jq -r .version /it-run/pkg-from/MANIFEST.json)
  to=$(jq -r .version /it-run/pkg/MANIFEST.json)

  it_step "built-in form: install $from --images $(it_bundle_file from)"
  it_unpack /opt from
  it_cx "$root" install --images "$(it_bundle_file from)"
  it_same "install recorded as succeeded" succeeded "$(st install.result)"
  it_same "no overlay" "" "$(st current.overlays)"
  it_check "openssl is a service image (tls-init)" grep -q ' openssl=sha256:' <<<" $(st current.image_ids)"
  it_same "no tool image recorded" "" "$(st current.tool_image_ids)"
  it_step "built-in form: the frontend through the built-in proxy (section 6 item 4)"
  overlays_front https://localhost/ 200
  overlays_front http://localhost/ 301
  it_step "built-in form: backup"
  touch "$IT_WORK/mark"
  overlays_backup "$root" "$from"
  overlays_tls "$root" true
  it_step "built-in form: status"
  overlays_status "$root" 6 "$from"
  it_check "status names the certificate initializer as run once" grep -q 'tls-init runs once' <<<"$STATUS_OUT"
  it_check "status shows the backup file" grep -qF "$OV_FILE" <<<"$STATUS_OUT"
  it_step "built-in form: upgrade $from -> $to"
  overlays_upgrade "$root" "$to"
  it_check "openssl is still a service image" grep -q ' openssl=sha256:' <<<" $(st current.image_ids)"
  it_step "built-in form: status, backup after the upgrade"
  overlays_status "$root" 6 "$to"
  touch "$IT_WORK/mark"
  overlays_backup "$root" "$to"
  overlays_tls "$root" true
  overlays_teardown "$root"

  it_step "external ingress form: install $from --images $(it_bundle_file from)"
  it_unpack /opt from
  it_env_preset "$root" "COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml"
  it_cx "$root" install --images "$(it_bundle_file from)"
  it_same "install recorded as succeeded" succeeded "$(st install.result)"
  it_same "the external ingress overlay" external-ingress "$(st current.overlays)"
  id=$(st current.tool_image_ids)
  it_check "openssl recorded as a tool image" grep -qE '^openssl=sha256:[0-9a-f]{64}$' <<<"$id"
  want=$(docker image inspect --format '{{.Id}}' "$(jq -r '.images.openssl.ref + ":" + .images.openssl.tag' "$root/current/MANIFEST.json")")
  it_same "the recorded tool image is the openssl image on this host" "openssl=$want" "$id"
  it_check "openssl and nginx are not service images" bash -c '! grep -qE " (openssl|nginx)=" <<<" $1"' _ "$(st current.image_ids)"
  it_check "compose is not given the tool image" bash -c '! grep -q "^CUSTODEXA_IMAGE_OPENSSL=" "$1"' _ "$root/current/images.env"
  it_check "no certificate initializer container" bash -c '! docker container inspect custodexa-tls-init >/dev/null 2>&1'
  it_step "external ingress form: the frontend on plain http for the ingress (section 6 item 4)"
  overlays_front http://localhost/ 200
  it_step "external ingress form: backup (the deployment has no tls/)"
  touch "$IT_WORK/mark"
  overlays_backup "$root" "$from"
  overlays_tls "$root" false
  it_step "external ingress form: status"
  overlays_status "$root" 4 "$from"
  it_check "status lists no tool container" bash -c '! grep -q "tls-init" <<<"$1"' _ "$STATUS_OUT"
  it_check "status shows the backup file" grep -qF "$OV_FILE" <<<"$STATUS_OUT"
  it_step "external ingress form: upgrade $from -> $to"
  overlays_upgrade "$root" "$to"
  it_same "the external ingress overlay is kept" external-ingress "$(st current.overlays)"
  it_check "openssl still recorded as a tool image" grep -qE '^openssl=sha256:[0-9a-f]{64}$' <<<"$(st current.tool_image_ids)"
  it_check "no certificate initializer container" bash -c '! docker container inspect custodexa-tls-init >/dev/null 2>&1'
  it_step "external ingress form: status, backup after the upgrade"
  overlays_status "$root" 4 "$to"
  touch "$IT_WORK/mark"
  overlays_backup "$root" "$to"
  overlays_tls "$root" false
  overlays_teardown "$root"
}
