#!/usr/bin/env bats
# Threat (A): a tool image taken unchecked, or checked as a service that never runs. The backup
# encrypts with the release's openssl image; the external ingress form does not run the certificate
# initializer that image belongs to. There it must still be obtained and checked against the
# release manifest and its ID recorded, while the check after the start, the compose image list
# and status leave it out. The built-in form keeps openssl a service image, as before.

load helper
load release_fixture
load install_host
load backup_host
load upgrade_host

INGRESS=current/compose.yml:current/compose.external-ingress.yml

st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

# ---------- install and status ----------

# install_form <none|ingress>: a fresh install of that form, without a terminal.
install_form() {
  ROOT=/opt/custodexa
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  host_base
  host_full
  fresh_host
  : >"$SIM/images"
  if [ "$1" = ingress ]; then
    cp "$ROOT/current/.env.example" "$ROOT/.env"
    printf 'COMPOSE_FILE=%s\n' "$INGRESS" >>"$ROOT/.env"
  fi
  clock 0 2 0 48 0 9 0 21
  : >"$FAKE_DOCKER_LOG"
  install_run en --yes
}

@test "tool images: the external ingress form obtains and checks openssl, does not inspect a container for it, status lists no tool" {
  install_form ingress
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(st current.overlays)" = external-ingress ] || { cat "$ROOT/state.json"; return 1; }
  # Obtained by its digest and checked: the ID is the release's config digest.
  grep -q $'^ARGS\tpull -q --platform linux/amd64 docker.io/alpine/openssl@'"${IDX[openssl]}" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  [ "$(st current.tool_image_ids)" = "openssl=${CFG[openssl]}" ] || { cat "$ROOT/state.json"; return 1; }
  [[ " $(st current.image_ids) " != *" openssl="* && " $(st current.image_ids) " != *" nginx="* ]] || return 1
  [[ " $(st current.image_ids) " == *" backend=${CFG[backend]} "* ]] || return 1
  # Neither compose nor the check after the start sees it.
  ! grep -q '^CUSTODEXA_IMAGE_OPENSSL=' "$ROOT/current/images.env" || return 1
  ! grep -q '^openssl=' "$ROOT/current/image-ids.env" || return 1
  ! grep -q 'custodexa-tls-init' "$FAKE_DOCKER_LOG" || { grep tls-init "$FAKE_DOCKER_LOG"; return 1; }
  [[ $output == *"[ OK ] 5/7  "* ]] || { echo "$output"; return 1; }
  [[ $output == *"openssl 3.5.4"* ]] || { echo "$output"; return 1; }
  # status: the four service containers, no tool among them, no failure.
  : >"$FAKE_DOCKER_LOG"
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [ "$status" -eq 0 ] || [ "$status" -eq 4 ] || { echo "$status: $output"; return 1; }
  [[ $output == *"[ OK ] 4 service processes started"* ]] || { echo "$output"; return 1; }
  [[ $output != *"[FAIL]"* && $output != *"tls-init"* ]] || { echo "$output"; return 1; }
  ! grep -q 'tls-init' "$FAKE_DOCKER_LOG"
}

@test "tool images: openssl whose content is not the release's stops the external ingress install at step 3" {
  ROOT=/opt/custodexa
  install_form ingress
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # Again, with the registry giving other content for openssl's digest.
  fresh_host
  : >"$SIM/images"
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  printf 'COMPOSE_FILE=%s\n' "$INGRESS" >>"$ROOT/.env"
  sed -i "s#^docker.io/alpine/openssl@${IDX[openssl]} .*#docker.io/alpine/openssl@${IDX[openssl]} sha256:0bad000000000000000000000000000000000000000000000000000000000000#" "$SIM/registry"
  install_run en --yes
  [ "$status" -ne 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 3/7  "* ]] || { echo "$output"; return 1; }
  [[ $output == *"openssl@sha256:42c7...8278"* ]] || { echo "$output"; return 1; }
  [ -z "$(st current.tool_image_ids)" ]
}

@test "tool images: the built-in form keeps openssl a service image, checked as tls-init after the start" {
  install_form none
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -z "$(st current.overlays)" ] || return 1
  [[ " $(st current.image_ids) " == *" openssl=${CFG[openssl]} "* ]] || { cat "$ROOT/state.json"; return 1; }
  [ "$(jq -r 'has("current.tool_image_ids")' "$ROOT/state.json")" = false ] || return 1
  grep -q '^CUSTODEXA_IMAGE_OPENSSL=' "$ROOT/current/images.env" || return 1
  grep -q $'^ARGS\tinspect --format {{.Image}} custodexa-tls-init' "$FAKE_DOCKER_LOG" || { grep inspect "$FAKE_DOCKER_LOG"; return 1; }
  run bash "$ROOT/custodexa.sh" status --lang en </dev/null
  [ "$status" -eq 0 ] || [ "$status" -eq 4 ] || { echo "$status: $output"; return 1; }
  [[ $output == *"[ OK ] 6 service processes started (tls-init runs once and has"* ]] || { echo "$output"; return 1; }
  [[ $output != *"[FAIL]"* ]]
}

# ---------- upgrade ----------

# upgrade_form <none|ingress>: the 1.13.0 deployment of that form upgraded to 1.13.2, whose release
# names openssl and nginx too.
upgrade_form() {
  UP_IMG_NAMES="backend frontend postgres guacd openssl nginx"
  UP_IMG_REF[openssl]=docker.io/alpine/openssl
  UP_IMG_REF[nginx]=docker.io/library/nginx
  upgraded_host ui || return 1
  if [ "$1" = ingress ]; then
    jq '."current.overlays" = "external-ingress" | ."current.tool_image_ids" = "openssl=sha256:1111"' \
      "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
    printf 'COMPOSE_FILE=%s\n' "$INGRESS" >>"$ROOT/.env"
  else
    # The containers of the built-in proxy run the images just obtained.
    up_digest cfg-openssl >"$UP/image.tls-init"
    up_digest cfg-nginx >"$UP/image.tls-proxy"
  fi
  clock 0 3 0 41 0 4 0 11
  : >"$FAKE_DOCKER_LOG"
  full_run en
}

@test "tool images: upgrading the external ingress form obtains openssl as a tool and records it; no container check for it" {
  upgrade_form ingress
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(st current.version)" = 1.13.2 ] || return 1
  [ "$(st current.tool_image_ids)" = "openssl=$(up_digest cfg-openssl)" ] || { cat "$ROOT/state.json"; return 1; }
  [ "$(st previous.tool_image_ids)" = "openssl=sha256:1111" ] || { cat "$ROOT/state.json"; return 1; }
  [[ " $(st current.image_ids) " != *" openssl="* && " $(st current.image_ids) " != *" nginx="* ]] || return 1
  # Checked: its digest was looked up on this host.
  grep -q "image inspect --format {{.Id}} docker.io/alpine/openssl@$(up_digest idx-openssl)" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  ! grep -q 'inspect --format {{.Image}} custodexa-tls-init' "$FAKE_DOCKER_LOG" || return 1
  ! grep -q '^CUSTODEXA_IMAGE_OPENSSL=' "$ROOT/releases/1.13.2/images.env" || return 1
  ! grep -q '^openssl=' "$ROOT/releases/1.13.2/image-ids.env"
}

@test "tool images: upgrading the built-in form keeps openssl a service image, checked as tls-init" {
  upgrade_form none
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ " $(st current.image_ids) " == *" openssl=$(up_digest cfg-openssl) "* ]] || { cat "$ROOT/state.json"; return 1; }
  [ "$(jq -r 'has("current.tool_image_ids") or has("previous.tool_image_ids")' "$ROOT/state.json")" = false ] || return 1
  grep -q 'inspect --format {{.Image}} custodexa-tls-init' "$FAKE_DOCKER_LOG" || { grep inspect "$FAKE_DOCKER_LOG"; return 1; }
  grep -q '^CUSTODEXA_IMAGE_OPENSSL=' "$ROOT/releases/1.13.2/images.env"
}

# ---------- an external database: the PostgreSQL clients ----------
# The three clients that export an external database are tool images of that form only: obtained
# and checked at install and upgrade, recorded, never run as a service, never on the status list.

EXTDB=current/compose.yml:current/compose.external-database.yml
EXTBOTH=current/compose.yml:current/compose.external-ingress.yml:current/compose.external-database.yml

# with_clients: the release names the three PostgreSQL clients too.
with_clients() {
  local m
  NAMES="$NAMES pgclient16 pgclient17 pgclient18"
  for m in 16 17 18; do
    REF[pgclient$m]=docker.io/library/postgres-client-$m
    TAG[pgclient$m]=$m-alpine3.24
    IDX[pgclient$m]=sha256:$(printf 'idx-pgclient%s' "$m" | sha256sum | cut -c1-64)
  done
}

# install_ext <database|both>: a fresh install on an external database, without or with the
# external ingress too.
install_ext() {
  ROOT=/opt/custodexa
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  with_clients
  host_base
  host_full
  fresh_host
  : >"$SIM/images"
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  if [ "$1" = both ]; then
    printf 'COMPOSE_FILE=%s\n' "$EXTBOTH" >>"$ROOT/.env"
  else
    printf 'COMPOSE_FILE=%s\n' "$EXTDB" >>"$ROOT/.env"
    # The containers of the built-in proxy run the images just obtained.
    up_digest cfg-openssl >"$UP/image.tls-init"
    up_digest cfg-nginx >"$UP/image.tls-proxy"
  fi
  printf '%s\n' EXTERNAL_DB_HOST=db.example.internal DB_PASSWORD=external-db-password-0007 >>"$ROOT/.env"
  clock 0 2 0 48 0 9 0 21
  : >"$FAKE_DOCKER_LOG"
  install_run en --yes
}

# clients_checked: each client was obtained by its digest and recorded as a tool image, never as a
# service image, never handed to compose, never looked for as a container.
clients_checked() {
  local m
  for m in 16 17 18; do
    grep -q $'^ARGS\tpull -q --platform linux/amd64 docker.io/library/postgres-client-'"$m@${IDX[pgclient$m]}" "$FAKE_DOCKER_LOG" \
      || { echo "pgclient$m not pulled by digest"; return 1; }
    [[ " $(st current.tool_image_ids) " == *" pgclient$m=${CFG[pgclient$m]} "* ]] || { cat "$ROOT/state.json"; return 1; }
    [[ " $(st current.image_ids) " != *" pgclient$m="* ]] || return 1
    ! grep -q "^CUSTODEXA_IMAGE_PGCLIENT$m=" "$ROOT/current/images.env" || return 1
    ! grep -q "^pgclient$m=" "$ROOT/current/image-ids.env" || return 1
  done
  ! grep -q 'custodexa-pgclient\|custodexa-postgres' "$FAKE_DOCKER_LOG" || { grep 'custodexa-p' "$FAKE_DOCKER_LOG"; return 1; }
  # The bundled database is not this form's: neither pulled nor recorded.
  [[ " $(st current.image_ids) " != *" postgres="* ]] || return 1
  ! grep -q $'^ARGS\tpull .*docker.io/library/postgres@' "$FAKE_DOCKER_LOG"
}

@test "tool images: an external database, and an external database behind an external ingress: the three clients obtained and checked, no container check, not on status" {
  local form
  for form in database both; do
    install_ext "$form"
    [ "$status" -eq 0 ] || { echo "$form"; echo "$output"; return 1; }
    case $form in
      database) [ "$(st current.overlays)" = external-database ] ;;
      both) [ "$(st current.overlays)" = "external-ingress external-database" ] ;;
    esac || { cat "$ROOT/state.json"; return 1; }
    clients_checked || { echo "$form"; return 1; }
    # The check after the start passed without them.
    [[ $output == *"[ OK ] 5/7  "* ]] || { echo "$output"; return 1; }
    if [ "$form" = both ]; then
      [[ " $(st current.tool_image_ids) " == *" openssl=${CFG[openssl]} "* ]] || { cat "$ROOT/state.json"; return 1; }
    fi
    : >"$FAKE_DOCKER_LOG"
    run bash "$ROOT/custodexa.sh" status --lang en </dev/null
    [ "$status" -eq 0 ] || [ "$status" -eq 4 ] || { echo "$status: $output"; return 1; }
    [[ $output != *"[FAIL]"* && $output != *pgclient* && $output != *"postgres-client"* ]] || { echo "$output"; return 1; }
    ! grep -q 'pgclient\|postgres-client' "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  done
}

@test "tool images: the built-in database form obtains no PostgreSQL client" {
  ROOT=/opt/custodexa
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  with_clients
  host_base
  host_full
  fresh_host
  : >"$SIM/images"
  clock 0 2 0 48 0 9 0 21
  : >"$FAKE_DOCKER_LOG"
  install_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  ! grep -q 'postgres-client' "$FAKE_DOCKER_LOG" || return 1
  [[ " $(st current.tool_image_ids) $(st current.image_ids) " != *pgclient* ]] || { cat "$ROOT/state.json"; return 1; }
  [[ " $(st current.image_ids) " == *" postgres=${CFG[postgres]} "* ]]
}

# upgrade_ext <database|both>: the 1.13.0 deployment on an external database (behind an external
# ingress too with both) upgraded to 1.13.2, whose release names the three clients; the services
# were stopped by the operator and the upgrade takes the operator's own backup.
upgrade_ext() {
  local m ov=external-database ids=""
  UP_IMG_NAMES="backend frontend postgres guacd openssl nginx pgclient16 pgclient17 pgclient18"
  UP_IMG_REF[openssl]=docker.io/alpine/openssl
  UP_IMG_REF[nginx]=docker.io/library/nginx
  for m in 16 17 18; do
    UP_IMG_REF[pgclient$m]=docker.io/library/postgres-client-$m
    ids+="${ids:+ }pgclient$m=sha256:$m$m$m$m"
  done
  upgraded_host ui || return 1
  if [ "$1" = both ]; then
    ov="external-ingress external-database"
    ids="openssl=sha256:1111 $ids"
    printf 'COMPOSE_FILE=%s\n' "$EXTBOTH" >>"$ROOT/.env"
  else
    printf 'COMPOSE_FILE=%s\n' "$EXTDB" >>"$ROOT/.env"
    # The containers of the built-in proxy run the images just obtained.
    up_digest cfg-openssl >"$UP/image.tls-init"
    up_digest cfg-nginx >"$UP/image.tls-proxy"
  fi
  jq --arg o "$ov" --arg i "$ids" '."current.overlays" = $o | ."current.tool_image_ids" = $i' \
    "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  bk_env_set DB_USER custodexa_app
  # Stopped by the operator before the upgrade, who took a backup of their own after that.
  printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
  clock 0 3 0 41 0 4 0 11
  : >"$FAKE_DOCKER_LOG"
  TZ=UTC full_run en --backup-ref vm-snap-0218 --backup-time '2026-09-30 02:18' --backup-restore /doc
}

# The whole upgrade with the operator's own backup (no client is chosen for it): step 2 obtains
# and checks the clients, step 9 records them as tools, the check after the start passes without a
# container of theirs, and status does not list them.
@test "tool images: upgrading an external database (and one behind an external ingress) obtains and checks the three clients as tools, never hands them to compose" {
  local form m
  for form in database both; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    upgrade_ext "$form"
    [ "$status" -eq 0 ] || { echo "$form"; echo "$output"; return 1; }
    [[ $output == *"[ OK ]  2/13  "* && $output == *"[ OK ] 12/13  "* && $output == *"[ OK ] 13/13  "* ]] \
      || { echo "$form"; echo "$output"; return 1; }
    for m in 16 17 18; do
      grep -q "image inspect --format {{.Id}} docker.io/library/postgres-client-$m@$(up_digest "idx-pgclient$m")" "$FAKE_DOCKER_LOG" \
        || { cat "$FAKE_DOCKER_LOG"; return 1; }
      [[ $output == *"pgclient$m 1.13.2"* ]] || { echo "$output"; return 1; }
      ! grep -q "^CUSTODEXA_IMAGE_PGCLIENT$m=" "$ROOT/releases/1.13.2/images.env" || return 1
      ! grep -q "^pgclient$m=" "$ROOT/releases/1.13.2/image-ids.env" || return 1
    done
    grep -q '^CUSTODEXA_IMAGE_BACKEND=' "$ROOT/releases/1.13.2/images.env" || return 1
    # The bundled database is not this form's: neither looked up nor handed to compose.
    ! grep -q '^CUSTODEXA_IMAGE_POSTGRES=' "$ROOT/releases/1.13.2/images.env" || return 1
    ! grep -q "image inspect --format {{.Id}} docker.io/library/postgres@" "$FAKE_DOCKER_LOG" || return 1
    ! grep -q 'inspect --format {{.Image}} custodexa-pgclient\|inspect --format {{.Image}} custodexa-postgres' "$FAKE_DOCKER_LOG" || return 1
    # Recorded as the new version's tools, the old ones kept as the previous version's.
    for m in 16 17 18; do
      [[ " $(st current.tool_image_ids) " == *" pgclient$m=$(up_digest "cfg-pgclient$m") "* ]] || { cat "$ROOT/state.json"; return 1; }
      [[ " $(st current.image_ids) " != *" pgclient$m="* ]] || { cat "$ROOT/state.json"; return 1; }
      [[ " $(st previous.tool_image_ids) " == *" pgclient$m=sha256:$m$m$m$m "* ]] || { cat "$ROOT/state.json"; return 1; }
    done
    : >"$FAKE_DOCKER_LOG"
    run bash "$ROOT/custodexa.sh" status --lang en </dev/null
    [[ $output != *pgclient* && $output != *"postgres-client"* ]] || { echo "$output"; return 1; }
    ! grep -q 'pgclient\|postgres-client' "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  done
}
