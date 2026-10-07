# Hosts for the upgrade tests. Needs helper.bash, install_host.bash and backup_host.bash loaded.
#   package_release <dir> <version> [min_source_version] [migrations...]
#       a release tree as the package holds it: the script, VERSION and a MANIFEST.json
#   publish <version> [min] [migrations...]
#       that release as GitHub serves it ($REL/v<ver>/: package, SHA256SUMS, signature bundle,
#       MANIFEST.json); `latest` points at the last one published
#   fake curl: serves $REL; $REL/offline makes every download fail

UP_IDENTITY_PREFIX="https://github.com/custodexa/custodexa/.github/workflows/release-images.yml@refs/tags/v"

package_release() {
  local dir=$1 ver=$2 min=${3:-1.12.4} mig
  shift 3 2>/dev/null || shift $#
  mkdir -p "$dir"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$dir/"
  printf '%s\n' "$ver" >"$dir/VERSION"
  mig=$(printf '%s\n' "$@" | jq -R . | jq -s 'map(select(. != ""))')
  jq -n --arg v "$ver" --arg m "$min" --argjson mig "$mig" --argjson img "$(up_images_json "$ver")" \
    '{format: 1, version: $v, min_source_version: $m, released_at: "2026-10-20T20:00:00+08:00",
      images: $img, migrations: $mig, rollback_compatible: []}' >"$dir/MANIFEST.json"
  [ -z "${FAKE_DOCKER_REPLAY:-}" ] || up_images_here
}

# The images every published release names: two own (signed, with provenance) and two upstream.
# Their digests are made up; up_images_here puts them on the fake host, so step 2 of upgrade finds
# them there and the signature and provenance checks (tests/fakes) pass.
UP_IMG_NAMES="backend frontend postgres guacd"
declare -gA UP_IMG_REF=([backend]=ghcr.io/custodexa/backend [frontend]=ghcr.io/custodexa/frontend
  [postgres]=docker.io/library/postgres [guacd]=docker.io/guacamole/guacd)
up_digest() { printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | cut -c1-64)"; }
up_images_json() {
  local n e img='{}'
  for n in $UP_IMG_NAMES; do
    e=$(jq -n --arg r "${UP_IMG_REF[$n]}" --arg t "$1" --arg d "$(up_digest "idx-$n")" --arg c "$(up_digest "cfg-$n")" \
      '{ref: $r, tag: $t, index_digest: $d, platforms: {amd64: {config_digest: $c, size: 1000},
        arm64: {config_digest: $c, size: 1000}}}')
    case $n in postgres | guacd) e=$(jq '. + {upstream: true}' <<<"$e") ;; esac
    img=$(jq --arg n "$n" --argjson e "$e" '.[$n] = $e' <<<"$img")
  done
  printf '%s' "$img"
}
up_images_here() {
  local n key
  for n in $UP_IMG_NAMES; do
    key=$(printf 'image_inspect_--format_{{.Id}}_%s' "$(printf '%s@%s' "${UP_IMG_REF[$n]}" "$(up_digest "idx-$n")" | tr '/ :@' '----')")
    up_digest "cfg-$n" >"$FAKE_DOCKER_REPLAY/$key.out"
  done
}

publish() {
  local ver=$1 d=$REL/v$1 b=$BATS_TEST_TMPDIR/build-$1
  shift
  package_release "$b/custodexa/releases/$ver" "$ver" "$@"
  mkdir -p "$d"
  tar -C "$b" -czf "$d/custodexa-$ver.tar.gz" custodexa
  cp "$b/custodexa/releases/$ver/MANIFEST.json" "$d/MANIFEST.json"
  (cd "$d" && sha256sum "custodexa-$ver.tar.gz" MANIFEST.json >SHA256SUMS)
  sign_release "$ver"
  ln -sfn "v$ver" "$REL/latest"
}

# sign_release <version>: the fake cosign bundle over the current SHA256SUMS.
sign_release() {
  local d=$REL/v$1
  printf 'identity %s%s\nsha256 %s\n' "$UP_IDENTITY_PREFIX" "$1" "$(sha256sum "$d/SHA256SUMS" | cut -d' ' -f1)" \
    >"$d/SHA256SUMS.sigstore.json"
}

fake_github() {
  export REL=$BATS_TEST_TMPDIR/github
  mkdir -p "$REL"
  # The single-quoted program is written to the fake curl executable for later expansion.
  # shellcheck disable=SC2016
  fake curl 'out="" url="" proto=0 redir=0
while [ $# -gt 0 ]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    --proto) [ "$2" = "=https" ] || exit 98; proto=1; shift 2 ;;
    --proto-redir) [ "$2" = "=https" ] || exit 98; redir=1; shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
case $url in https://github.com/custodexa/custodexa/releases/*)
  [ "$proto" -eq 1 ] && [ "$redir" -eq 1 ] || exit 98 ;;
esac
printf "%s\n" "$url" >>'"$REL"'/requests
[ -e '"$REL"'/offline ] && { echo "curl: (6) Could not resolve host: github.com" >&2; exit 6; }
case $url in https://127.0.0.1*|http://127.0.0.1*) [ -e '"$REL"'/entry.rc ] && exit 7; printf 200; exit 0 ;; esac
p=${url#https://github.com/custodexa/custodexa/releases/}
case $p in latest/download/*) f='"$REL"'/latest/${p#latest/download/} ;; download/*) f='"$REL"'/${p#download/} ;; *) exit 22 ;; esac
[ -f "$f" ] || exit 22
cp "$f" "$out"'
}

# no_cosign: this host has no cosign (the fakes folder holds one).
no_cosign() {
  local bin=$BATS_TEST_TMPDIR/bin-nocosign
  mkdir -p "$bin"
  ln -sf "$TESTS_DIR/fakes/docker" "$bin/docker"
  export PATH="$FAKES:$bin:${PATH//$TESTS_DIR\/fakes:/}"
}

# tree_of <dir>: every path with its type, mode and content checksum, to show nothing changed.
tree_of() {
  (cd "$1" && find . -printf '%y %m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 -r sha256sum)
}

# upgrade_run <lang> [arguments...]: the deployment's own script.
upgrade_run() {
  local l=$1
  shift
  run bash "$ROOT/custodexa.sh" upgrade --lang "$l" "$@" </dev/null
}

# upgrade_stack <target version>: the whole upgrade on backup_host's deployment. The daemon answers
# from $UP (and the database from $DB, tests/backup_host.bash):
#   $UP/running        State.Running and FinishedAt of the backend ("" = no container)
#   $UP/logs           the backend log (drain timeout, baseline migration, instance lock lines)
#   $UP/health         what /health answers after the start; $UP/health.rc makes it fail
#   $UP/metrics.rc     the queue metric and the seal state cannot be read
#   $UP/after.<name>   what psql answers for <name> once the new version started
#   $UP/up.rc          `up` fails     $UP/data_path   .env DATA_PATH becomes this on `up`
#   $UP/down.rc        `down` fails   $UP/with_state  every call made while state.json existed
#   $UP/exports/       what the backend container holds in its export folder (absent = none)
#   $UP/exports.rc     copying that folder out fails for another reason
#   $UP/image.<name>   the image ID the container of <name> runs (else the one recorded)
# $DB/events gets "up", "down", "cp-exports" and "stop-all" besides the backup's events.
upgrade_stack() {
  export UP=$BATS_TEST_TMPDIR/up ROOT
  mkdir -p "$UP"
  printf 'true 0001-01-01T00:00:00Z\n' >"$UP/running"
  printf '%s\n' '2026/09/30 02:20:05 [InstanceGuard] 單實例鎖狀態=held' >"$UP/logs"
  printf '{"status":"ok","version":"%s"}\n' "$1" >"$UP/health"
  fake sleep ':'
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/db-hook"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
all=" $* "
ev() { printf '%s\n' "$1" >>"$DB/events"; }
# Record commands issued while state.json existed.
[ -e "$ROOT/state.json" ] && printf '%s\n' "$*" >>"$UP/with_state"
case $1 in
  exec)
    [ "$2" = custodexa-backend ] || exit 99
    case ${*: -1} in
      /metrics)
        [ -e "$UP/metrics.rc" ] && exit 1
        printf '  HTTP/1.1 200 OK\n' >&2; printf 'custodexa_audit_queue_depth 0\n' ;;
      /api/v1/seal/status) exit 1 ;;
      *health) printf '{"status":"ok","version":"1.13.0"}\n' ;;
      *) exit 1 ;;
    esac
    exit 0 ;;
  container)
    [ -s "$UP/running" ] || exit 1
    case $* in *StartedAt*) echo 2026-09-30T02:20:00.000000000Z ;; *) cat "$UP/running" ;; esac
    exit 0 ;;
  logs) cat "$UP/logs"; exit 0 ;;
  # An image the database fake knows ($DB/images: the PostgreSQL clients this host holds).
  image) exec "$FAKE_DOCKER_REPLAY/db-hook" "$@" ;;
  inspect)
    case $* in
      *'{{.Image}}'*)
        n=${*: -1}; n=${n#custodexa-}
        if [ -e "$UP/image.$n" ]; then cat "$UP/image.$n"; else sed -n "s/^$n=//p" "$ROOT/current/image-ids.env"; fi
        exit 0 ;;
    esac
    exit 99 ;;
  run)
    # A PostgreSQL client container (an external database) is the database fake's.
    case " $* " in
      *" --entrypoint psql "* | *" --entrypoint pg_dump "* | *" --entrypoint pg_restore "* | *" --entrypoint test "*)
        exec "$FAKE_DOCKER_REPLAY/db-hook" "$@" ;;
    esac
    echo '1000:0 2770'; exit 0 ;;
  compose)
    case $all in
      *" up -d "*)
        ev up
        [ -e "$UP/up.rc" ] && exit 1
        [ -e "$UP/data_path" ] && sed -i "s#^DATA_PATH=.*#DATA_PATH=$(cat "$UP/data_path")#" "$ROOT/.env"
        exit 0 ;;
      *" down "*) ev down; [ -e "$UP/down.rc" ] && exit 1; exit 0 ;;
      *" cp backend:/var/lib/custodexa/exports/. "*)
        # The export folder of the backend container: $UP/exports (absent = no such folder).
        ev cp-exports
        [ -e "$UP/exports.rc" ] && { echo "Error response from daemon: no space left on device" >&2; exit 1; }
        [ -d "$UP/exports" ] || { echo "Error response from daemon: Could not find the file /var/lib/custodexa/exports/. in container 2eb2d0435ae8" >&2; exit 1; }
        cp -a "$UP/exports/." "${*: -1}"; exit 0 ;;
      *" ps "*) printf '%s\n' 'backend running ' 'guacd running ' 'frontend running ' 'postgres running healthy'; exit 0 ;;
      *" exec -T backend wget "*) [ -e "$UP/health.rc" ] && exit 1; cat "$UP/health"; exit 0 ;;
      *" psql "*pg_stat_activity*) printf '%s psql pg_stat_activity\n' "${CX_DB_ACTION:-none}" >>"$DB/db-calls"; echo 0; exit 0 ;;
      *" psql "*)
        sql=${*: -1} f=""
        case $sql in
          *"FROM users"*) f=count.users ;;
          *"FROM sessions WHERE status = 'active'"*) f=count.active ;;
          *"FROM sessions"*) f=count.sessions ;;
          *"FROM audit_logs"*) f=count.audit_logs ;;
          *schema_migrations*) f=migrations ;;
          *data_keys*) f=kek ;;
          *export_signing_keys*) f=export ;;
          *checkpoint_signing_keys*) f=checkpoint ;;
        esac
        if [ -n "$f" ] && grep -qx up "$DB/events" && [ -e "$UP/after.$f" ]; then
          printf '%s psql %s after\n' "${CX_DB_ACTION:-none}" "$f" >>"$DB/db-calls"
          cat "$UP/after.$f"
          exit 0
        fi ;;
    esac
    [ "${*: -1}" = stop ] && { ev stop-all; exit 0; }
    exec "$FAKE_DOCKER_REPLAY/db-hook" "$@" ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# upgraded_host: backup_host with 1.13.2 published and put in releases/, the numbers of the
# reviewed screens in the database, and the daemon of upgrade_stack.
upgraded_host() {
  backup_host "${1:-ui}"
  fake_github
  printf '%s\n' 18683107737 >"$DB/size"
  printf '%s\n' CUSTODEXA_IMAGE_BACKEND=ghcr.io/custodexa/backend:1.13.0 \
    CUSTODEXA_IMAGE_FRONTEND=ghcr.io/custodexa/frontend:1.13.0 >"$ROOT/current/images.env"
  docker_says image_inspect 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
  publish 1.13.2 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule
  printf '%s\n' 42 >"$DB/count.users"
  printf '%s\n' 18305 >"$DB/count.sessions"
  printf '%s\n' 1204540 >"$DB/count.audit_logs"
  upgrade_stack 1.13.2
  mkdir -p "$UP"
  printf '%s\n' 1204551 >"$UP/after.count.audit_logs"
  printf '%s\n' 20260816_schema_baseline 20260901_add_x 20261010_report_schedule >"$UP/after.migrations"
  # The old script fetches and verifies 1.13.2, then hands over; without --yes it stops at the preview.
  bash "$ROOT/custodexa.sh" upgrade 1.13.2 --lang en </dev/null >/dev/null 2>&1 || true
  [ -d "$ROOT/releases/1.13.2" ]
}

# full_run <lang> [options...]: the 1.13.2 script upgrades with --yes.
full_run() {
  local l=$1
  shift
  run bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang "$l" --yes "$@" </dev/null
}

# upgraded_external_host [mode]: upgraded_host as a deployment on an external database from a release
# that shipped no PostgreSQL client: no PostgreSQL image on this host and no tool image recorded;
# the target release (1.13.2) names the three clients, which this host does not have yet.
upgraded_external_host() {
  local n r key
  UP_IMG_NAMES="backend frontend postgres guacd pgclient16 pgclient17 pgclient18"
  for n in 16 17 18; do UP_IMG_REF[pgclient$n]=docker.io/library/postgres-client-$n; done
  upgraded_host "${1:-ui}" || return 1
  jq '."current.overlays" = "external-database" | del(."current.tool_image_ids")' "$ROOT/state.json" >"$ROOT/state.json.new"
  /usr/bin/mv "$ROOT/state.json.new" "$ROOT/state.json"
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  bk_env_set EXTERNAL_DB_PORT 5432
  bk_env_set DB_USER custodexa_app
  bk_env_set DB_SSLMODE verify-full
  # The host holds no PostgreSQL image: neither the bundled one nor any client, by digest or by tag.
  for n in postgres pgclient16 pgclient17 pgclient18; do
    for r in "${UP_IMG_REF[$n]}@$(up_digest "idx-$n")" "${UP_IMG_REF[$n]}:1.13.0" "${UP_IMG_REF[$n]}:1.13.2"; do
      key=image_inspect_--format_{{.Id}}_$(printf '%s' "$r" | tr '/ :@' '----')
      rm -f "$FAKE_DOCKER_REPLAY/$key.out"
      printf '1\n' >"$FAKE_DOCKER_REPLAY/$key.rc"
    done
  done
}

# upgraded_twice_host [mode]: upgraded_host upgraded to 1.13.2 (1.13.0 is then the previous
# version), with 1.16.0 published and fetched: the next upgrade is the second one in a row.
upgraded_twice_host() {
  upgraded_host "${1:-ui}" || return 1
  clock 0 3 0 41 0 4 0 11
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  publish 1.16.0 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule
  bash "$ROOT/custodexa.sh" upgrade 1.16.0 --lang en </dev/null >/dev/null 2>&1 || true
  [ -d "$ROOT/releases/1.16.0" ]
}

# ---------- an upgrade that obtains the PostgreSQL clients (an external database) ----------

# hook_before <code>: shell code that sees every docker call before the daemon of upgrade_stack
# answers it (it may answer itself with exit).
hook_before() {
  local n=0
  while [ -e "$FAKE_DOCKER_REPLAY/hook.$n" ]; do n=$((n + 1)); done
  mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/hook.$n"
  # shellcheck disable=SC2016 # expanded by the hook
  { printf '#!/bin/bash\n%s\n' "$1"; printf 'exec "$FAKE_DOCKER_REPLAY/hook.%s" "$@"\n' "$n"; } >"$FAKE_DOCKER_REPLAY/hook"
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# stop_flips: the backend container reports itself stopped after the services stop, and running
# again after `up -d`, as the daemon does (the own backup reads the stop time from it).
stop_flips() {
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'case " $* " in
  *" compose "*" stop "*) printf "false 2026-09-30T02:16:13.123456789Z\n" >"$UP/running" ;;
  *" compose "*" up -d "*) printf "true 0001-01-01T00:00:00Z\n" >"$UP/running" ;;
esac'
}

# pgc_id <major>: the ID the client of the target release (1.13.2, upgrade_host) has once obtained.
pgc_id() { printf 'sha256:%s' "$(printf 'cfg-pgclient%s' "$1" | sha256sum | cut -c1-64)"; }

# clients_online: the registry serves the three clients: a pull by digest makes the image answer by
# that digest, and the host knows its ID ("pull pgclientNN" in the events).
clients_online() {
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'if [ "$1" = pull ]; then
  r=${*: -1}
  case $r in
    docker.io/library/postgres-client-*@sha256:*)
      n=${r#docker.io/library/postgres-client-}; n=${n%%@*}
      printf "pull pgclient%s\n" "$n" >>"$DB/events"
      key=image_inspect_--format_{{.Id}}_$(printf "%s" "$r" | tr "/ :@" "----")
      id=sha256:$(printf "cfg-pgclient%s" "$n" | sha256sum | cut -c1-64)
      rm -f "$FAKE_DOCKER_REPLAY/$key.rc"
      printf "%s\n" "$id" >"$FAKE_DOCKER_REPLAY/$key.out"
      printf "%s\n" "$id" >>"$DB/images"
      exit 0 ;;
  esac
fi'
}

# clients_bundle: the offline image bundle of 1.13.2 next to the deployment, holding the three
# clients only (laid out as `docker save` writes it; each config blob hashes to the digest the
# release names). `docker load` of it makes the clients answer by their tag ("load" in the events).
clients_bundle() {
  local d=$BATS_TEST_TMPDIR/bundle n cfg m md idx='[]' man='[]' arch
  case $(uname -m) in x86_64 | amd64) arch=amd64 ;; *) arch=arm64 ;; esac
  rm -rf "$d"
  mkdir -p "$d/blobs/sha256"
  for n in 16 17 18; do
    printf 'cfg-pgclient%s' "$n" >"$d/c"
    cfg=$(sha256sum "$d/c" | cut -c1-64)
    mv "$d/c" "$d/blobs/sha256/$cfg"
    m=$(jq -cn --arg c "sha256:$cfg" '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json",
      config: {mediaType: "application/vnd.oci.image.config.v1+json", digest: $c, size: 14}, layers: []}')
    printf '%s' "$m" >"$d/m"
    md=$(sha256sum "$d/m" | cut -c1-64)
    mv "$d/m" "$d/blobs/sha256/$md"
    idx=$(jq -c --arg d "sha256:$md" --arg name "docker.io/library/postgres-client-$n:1.13.2" \
      '. + [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: 300,
             annotations: {"io.containerd.image.name": $name, "org.opencontainers.image.ref.name": "1.13.2"}}]' <<<"$idx")
    man=$(jq -c --arg c "blobs/sha256/$cfg" --arg t "postgres-client-$n:1.13.2" \
      '. + [{Config: $c, RepoTags: [$t], Layers: []}]' <<<"$man")
  done
  jq -c '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: .}' <<<"$idx" >"$d/index.json"
  printf '%s' "$man" >"$d/manifest.json"
  echo '{"imageLayoutVersion": "1.0.0"}' >"$d/oci-layout"
  (cd "$d" && /usr/bin/tar -cf "$ROOT/custodexa-images-1.13.2-$arch.tar" index.json manifest.json oci-layout blobs)
  (cd "$ROOT" && sha256sum "custodexa-images-1.13.2-$arch.tar" >SHA256SUMS)
  # shellcheck disable=SC2016 # expanded by the hook
  hook_before 'if [ "$1" = load ]; then
  printf "load\n" >>"$DB/events"
  for n in 16 17 18; do
    key=image_inspect_--format_{{.Id}}_docker.io-library-postgres-client-$n-1.13.2
    id=sha256:$(printf "cfg-pgclient%s" "$n" | sha256sum | cut -c1-64)
    rm -f "$FAKE_DOCKER_REPLAY/$key.rc"
    printf "%s\n" "$id" >"$FAKE_DOCKER_REPLAY/$key.out"
    printf "%s\n" "$id" >>"$DB/images"
  done
  exit 0
fi'
}

# fresh_ext [online|offline|none] [server version]: upgraded_external_host (no PostgreSQL image on
# this host) with the clients served by a registry (default), by an offline bundle, or not at all;
# the server runs 17.6 unless given.
fresh_ext() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_external_host ui || return 1
  case ${1:-online} in
    online) clients_online ;;
    offline) clients_bundle ;;
  esac
  stop_flips
  bk_server "${2:-17.6}"
  clock 0 3 0 41 0 4 0 11
  : >"$DB/events"
  : >"$DB/db-runs"
  : >"$FAKE_DOCKER_LOG"
  export TZ=UTC
}

# pty_up <out file> [options] [-- <prompt> <answer>...]: the 1.13.2 script upgrades on a terminal
# (tests/pty_host.bash), in English unless PTY_LANG names another language.
pty_up() {
  local out=$1 opts=""
  shift
  while [ $# -gt 0 ] && [ "$1" != -- ]; do
    opts+=" $1"
    shift
  done
  [ $# -eq 0 ] || shift
  pty_talk "$out" "bash $ROOT/releases/1.13.2/custodexa.sh upgrade --lang ${PTY_LANG:-en} --no-color$opts" "$@"
}

