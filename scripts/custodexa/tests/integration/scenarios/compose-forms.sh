# shellcheck shell=bash
# about: the package's single compose.yml, filled in the way build-package.sh fills it, resolved by the real compose for each deployment form (bundled or external database, built-in proxy or your own ingress): the services, the backend's DB_HOST and DB_PORT and its start condition on postgres, which frontend service is enabled and what it publishes, and that both frontend services share an image and a container name; no service is started
# needs:
# images:

# The compose files under test: the package's template and the source deployment's own compose file.
# Same structure, same forms, same assertions (the source file has no placeholders to fill).
CF_FILES=(/src/packaging/compose.yml /src/docker-compose.yml)

# cf_fill <template> <destination>: the placeholders build-package.sh fills (version and digests).
cf_fill() {
  sed -e 's|@@VERSION@@|9.9.9|g' \
    -e "s|@@BACKEND_DIGEST@@|$(printf 'b%.0s' {1..64})|g" \
    -e "s|@@FRONTEND_DIGEST@@|$(printf 'f%.0s' {1..64})|g" "$1" >"$2"
  ! grep -qE '@@[A-Z_]+@@' "$2"
}

# cf_config <profiles> <EXTERNAL_DB_HOST> <TLS_MODE> <HTTP_PORT>: the resolved model as JSON, from
# the deployment root CF_ROOT. The shell carries nothing of these keys: .env is the one source.
cf_config() {
  {
    printf 'DB_PASSWORD=it-password\n'
    printf 'EXTERNAL_DB_HOST=%s\n' "$2"
    printf 'TLS_MODE=%s\n' "$3"
    printf 'HTTP_PORT=%s\n' "$4"
  } >"$CF_ROOT/.env"
  env -u EXTERNAL_DB_HOST -u EXTERNAL_DB_PORT -u TLS_MODE -u HTTP_PORT -u COMPOSE_FILE \
    COMPOSE_PROFILES="$1" \
    docker compose -p custodexa --project-directory "$CF_ROOT" -f "$CF_COMPOSE" config --format json
}

# cf_form <what> <profiles> <db host> <tls mode> <http port> <services> <DB_HOST> <depends required>
# <frontend service> <frontend ports>: one form checked in full.
cf_form() {
  local what=$1 profiles=$2 dbhost=$3 tls=$4 port=$5 want_services=$6 want_host=$7 want_req=$8 front=$9
  local want_ports=${10} json
  it_step "$what (COMPOSE_PROFILES=$profiles)"
  json=$(cf_config "$profiles" "$dbhost" "$tls" "$port")
  it_same "services" "$want_services" "$(jq -r '.services | keys | join(" ")' <<<"$json")"
  it_same "backend DB_HOST" "$want_host" "$(jq -r '.services.backend.environment.DB_HOST' <<<"$json")"
  it_same "backend DB_PORT" "5432" "$(jq -r '.services.backend.environment.DB_PORT' <<<"$json")"
  it_same "backend depends_on postgres required" "$want_req" \
    "$(jq -r '.services.backend.depends_on.postgres | if has("required") then .required else "absent" end' <<<"$json")"
  it_same "the enabled web service" "$front" "$(jq -r '.services | keys[] | select(startswith("frontend"))' <<<"$json")"
  it_same "its published ports" "$want_ports" \
    "$(jq -r --arg f "$front" '[.services[$f].ports[]? | "\(.published):\(.target)"] | join(",")' <<<"$json")"
  it_same "the backend publishes no host port" "" "$(jq -r '[.services.backend.ports[]?] | join(",")' <<<"$json")"
}

scenario() {
  CF_ROOT=/it/cf-root
  CF_COMPOSE=$CF_ROOT/compose.yml
  local f

  for f in "${CF_FILES[@]}"; do
    it_step "$f"
    mkdir -p "$CF_ROOT"
    it_check "the placeholders are all filled" cf_fill "$f" "$CF_COMPOSE"

    cf_form "bundled database, built-in proxy" bundled-db,builtin-tls "" selfsigned 80 \
      "backend frontend guacd postgres tls-init tls-proxy" postgres false frontend ""
    cf_form "external database, built-in proxy" builtin-tls db.example.internal selfsigned 80 \
      "backend frontend guacd tls-init tls-proxy" db.example.internal false frontend ""
    cf_form "bundled database, your own ingress" bundled-db,own-ingress "" external 8080 \
      "backend frontend-published guacd postgres" postgres false frontend-published "8080:80"
    cf_form "external database, your own ingress" own-ingress db.example.internal external 8080 \
      "backend frontend-published guacd" db.example.internal false frontend-published "8080:80"

    it_step "the two web services are one definition"
    local a b
    a=$(cf_config builtin-tls "" selfsigned 8080 | jq -c '.services.frontend | {image, container_name, networks, build, depends_on, restart}')
    b=$(cf_config own-ingress "" external 8080 | jq -c '.services["frontend-published"] | {image, container_name, networks, build, depends_on, restart}')
    it_same "image, container_name, networks, build, depends_on and restart are equal" "$a" "$b"
    it_same "container_name" "custodexa-frontend" "$(jq -r .container_name <<<"$a")"
    it_same "frontend (built-in proxy) publishes nothing" "null" \
      "$(cf_config builtin-tls "" selfsigned 8080 | jq -c '.services.frontend.ports')"
    # Compose itself refuses the two together (one container name): the profiles that exclude each
    # other are also what keeps the two from ever being enabled by mistake.
    it_expect_fail "both web services enabled together are refused" "container name .* already in use" \
      cf_config builtin-tls,own-ingress "" selfsigned 8080
  done
}
