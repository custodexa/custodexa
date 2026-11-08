# shellcheck shell=bash
# about: the package built from the working tree installs (built-in database, offline bundle) and status reports it; docker compose ps and logs typed in the deployment folder without -f reach the deployment and follow a switched current link
# needs: package
# images:

scenario() {
  local root=/opt/custodexa version out rc
  it_step "unpack the package"
  it_unpack /opt
  version=$(jq -r .version "$root/current/MANIFEST.json")
  it_check "the package carries the working tree's management scripts" \
    diff -r /src/scripts/custodexa/lib "$root/current/lib"
  # compose.external-*.yml are the overlay files of the old layout (1.22 and before); the package must not hold them.
  it_check "the package carries the working tree's single compose file (same lines, placeholders filled) and no overlay" \
    bash -c '[ "$(wc -l <"$2/packaging/compose.yml")" = "$(wc -l <"$1/current/compose.yml")" ] &&
      ! grep -q "@@[A-Z_]*@@" "$1/current/compose.yml" && [ -z "$(ls "$1"/current/compose.external-*.yml 2>/dev/null)" ]' _ "$root" /src

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

  # An operator types compose commands in the deployment folder without -f: the managed block of
  # .env names current/compose.yml and the profiles, so they reach this deployment, and a switched
  # current link is followed without touching .env.
  it_step "docker compose ps and logs typed in the deployment folder, no -f"
  local want got env_sha
  it_same "the managed block names the single compose file" "COMPOSE_FILE=current/compose.yml" \
    "$(grep '^COMPOSE_FILE=' "$root/.env")"
  it_same "the managed block names the profiles of the form" "COMPOSE_PROFILES=bundled-db,builtin-tls" \
    "$(grep '^COMPOSE_PROFILES=' "$root/.env")"
  want=$(docker ps -a --filter label=com.docker.compose.project=custodexa --format '{{.Names}}' | sort | paste -sd' ')
  got=$(cd "$root" && env -u COMPOSE_FILE -u COMPOSE_PROFILES -u COMPOSE_PROJECT_NAME \
    docker compose ps -a --format '{{.Name}}' | sort | paste -sd' ')
  it_check "the deployment has containers ($want)" test -n "$want"
  it_same "docker compose ps lists the containers of the deployment" "$want" "$got"
  # shellcheck disable=SC2016 # expanded by the inner shell
  it_check "docker compose logs backend answers" \
    bash -c 'cd "$1" && env -u COMPOSE_FILE -u COMPOSE_PROFILES docker compose logs --tail 5 backend | grep -q .' _ "$root"
  env_sha=$(sha256sum "$root/.env")
  cp -a "$root/releases/$version" "$root/releases/it-probe"
  sed -i 's|ghcr.io/custodexa/backend:|ghcr.io/custodexa/backend-it-probe:|' "$root/releases/it-probe/compose.yml"
  ln -sfn releases/it-probe "$root/current"
  # shellcheck disable=SC2016 # expanded by the inner shell
  # config loads env_file (.env) relative to the project directory, which compose takes from the
  # first file of COMPOSE_FILE (current/) unless told; ps and logs above do not load it.
  it_check "after current is switched, COMPOSE_FILE of .env reads the new definition" bash -c 'set -o pipefail
    cd "$1" && img=$(env -u COMPOSE_FILE -u COMPOSE_PROFILES -u CUSTODEXA_IMAGE_BACKEND \
      docker compose --project-directory . config --format json | jq -r ".services.backend.image") || exit 1
    echo "backend image: $img"; [ "${img%%:*}" = ghcr.io/custodexa/backend-it-probe ]' _ "$root"
  ln -sfn "releases/$version" "$root/current"
  rm -rf "$root/releases/it-probe"
  it_same ".env was not touched for the switch" "$env_sha" "$(sha256sum "$root/.env")"
}
