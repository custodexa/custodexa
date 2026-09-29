# shellcheck shell=bash
# The CX_ENV_* results are read by the install command.
# shellcheck disable=SC2034
# The deployment's .env: created from the release's .env.example, then filled key by key with the
# same rules as scripts/quickstart.sh (the source deployment path), so both paths produce the same
# settings. A value that is already set is never changed; generated secrets are never logged.
# On top of those rules: an absolute DATA_PATH, and COMPOSE_FILE / COMPOSE_PROJECT_NAME so that
# `docker compose` typed in the deployment folder acts on the current release and this project.

CX_ENV_GENERATED=""     # names generated in this run: jwt kek admin db
CX_ENV_ADMIN_PASSWORD="" # only when generated in this run; shown once on the terminal
CX_ENV_KEK=""
CX_ENV_URL=""
CX_ENV_OVERLAYS=""

readonly CX_ENV_TEMPLATE_JWT=change-me-in-production-dev-secret
readonly CX_ENV_TEMPLATE_ADMIN=change-me-admin-initial-password-in-env

# cx_env_get <file> <key>: the value the way docker compose reads .env: the last uncommented line for
# the key wins, one pair of surrounding quotes is removed. Parsed, never sourced. Every reader of .env
# in this script goes through here, so all of them see the value compose uses.
cx_env_get() {
  local v
  [ -f "$1" ] || return 0
  v=$(sed -n "s/^[[:space:]]*$2=//p" "$1" | tail -n 1)
  v=${v%$'\r'}
  if [[ $v =~ ^\"(.*)\"$ || $v =~ ^\'(.*)\'$ ]]; then
    v=${BASH_REMATCH[1]}
  fi
  printf '%s' "$v"
}

# cx_env_set <file> <key> <value>: replace the uncommented line in place (the last one, the line
# cx_env_get reads), else uncomment the first commented one, else append. The file keeps mode 600.
cx_env_set() {
  local file=$1 key=$2 val=$3 tmp n
  tmp=$(umask 077 && mktemp "$file.tmp-XXXXXX")
  if grep -q "^${key}=" "$file"; then
    n=$(grep -n "^${key}=" "$file" | tail -n 1 | cut -d: -f1)
    awk -v n="$n" -v k="$key" -v v="$val" 'NR == n {print k"="v; next} {print}' "$file" >"$tmp"
  elif grep -Eq "^# *${key}=" "$file"; then
    awk -v k="$key" -v v="$val" 'BEGIN{d=0} !d && $0 ~ "^# *"k"=" {print k"="v; d=1; next} {print}' "$file" >"$tmp"
  else
    cat "$file" >"$tmp"
    printf '%s=%s\n' "$key" "$val" >>"$tmp"
  fi
  mv -f "$tmp" "$file"
}

# cx_env_random <n>: n characters from [A-Za-z0-9]. Reads a fixed amount so no pipe breaks early.
cx_env_random() {
  local out=""
  while [ "${#out}" -lt "$1" ]; do
    out+=$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')
  done
  printf '%s' "${out:0:$1}"
}

# A password of 20 characters holding both letters and digits.
cx_env_password() {
  local p
  while :; do
    p=$(cx_env_random 20)
    [[ $p == *[A-Za-z]* && $p == *[0-9]* ]] && break
  done
  printf '%s' "$p"
}

cx_env_host_fqdn() {
  local h
  h=$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)
  case $h in
    "" | localhost | localhost.* | *[!A-Za-z0-9.-]*) printf 'custodexa.local' ;;
    *) printf '%s' "$h" ;;
  esac
}

# The address on the interface of the default route, then the other global IPv4 addresses without
# loopback and virtual interfaces (docker, bridges, tunnels): the addresses people type.
cx_env_primary_ipv4() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}' | head -n1
}
cx_env_host_ipv4s() {
  local rest=""
  if command -v ip >/dev/null 2>&1; then
    rest=$(ip -4 -o addr show scope global 2>/dev/null |
      awk '$2 !~ /^(docker|br-|veth|virbr|vmnet|tun|tap|bridge)/ {split($4, a, "/"); print a[1]}')
  else
    rest=$(hostname -I 2>/dev/null | tr ' ' '\n' || true)
  fi
  { cx_env_primary_ipv4; printf '\n%s\n' "$rest"; } |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | awk '!seen[$0]++' | paste -sd, - | tr -d '\n'
}

cx_env_generated() { CX_ENV_GENERATED="${CX_ENV_GENERATED:+$CX_ENV_GENERATED }$1"; }

# cx_env_generate <root>: create or complete <root>/.env. Prints nothing; a rule that cannot be met
# prints one FAIL line and returns 1 (nothing generated after that point).
cx_env_generate() {
  local root=$1 f=$1/.env v prov data cf ov
  CX_ENV_GENERATED="" CX_ENV_ADMIN_PASSWORD="" CX_ENV_OVERLAYS=""
  if [ ! -f "$f" ]; then
    (umask 077 && cp "$root/current/.env.example" "$f") || return 1
  fi
  chmod 600 "$f"

  # Deployment form and project first: the rules below depend on the form.
  cf=$(cx_env_get "$f" COMPOSE_FILE)
  if [ -z "$cf" ]; then
    cf=current/compose.yml
    cx_env_set "$f" COMPOSE_FILE "$cf"
  fi
  case $cf in
    current/compose.yml | current/compose.yml:current/compose.external-ingress.yml | \
      current/compose.yml:current/compose.external-database.yml | \
      current/compose.yml:current/compose.external-ingress.yml:current/compose.external-database.yml) ;;
    *)
      cx_line FAIL "$(cx_msg env_compose_file_bad "$cf")"
      return 1
      ;;
  esac
  for ov in $CX_OVERLAY_NAMES; do
    [[ $cf == *"compose.$ov.yml"* ]] && CX_ENV_OVERLAYS="${CX_ENV_OVERLAYS:+$CX_ENV_OVERLAYS }$ov"
  done
  v=$(cx_env_get "$f" COMPOSE_PROJECT_NAME)
  if [ -z "$v" ]; then
    cx_env_set "$f" COMPOSE_PROJECT_NAME "$CX_PROJECT"
  elif [ "$v" != "$CX_PROJECT" ]; then
    cx_line FAIL "$(cx_msg env_project_bad "$v" "$CX_PROJECT")"
    return 1
  fi
  data=$(cx_env_get "$f" DATA_PATH)
  if [ -z "$data" ] || [ "$data" = ./data ]; then
    data=$root/data
    cx_env_set "$f" DATA_PATH "$data"
  fi

  v=$(cx_env_get "$f" JWT_SECRET)
  if [ -z "$v" ] || [ "$v" = "$CX_ENV_TEMPLATE_JWT" ]; then
    cx_env_set "$f" JWT_SECRET "$(openssl rand -base64 32)"
    cx_env_generated jwt
  fi

  prov=$(cx_env_get "$f" KEK_PROVIDER)
  CX_ENV_KEK=${prov:-env}
  case $prov in
    "" | env)
      if [ -z "$(cx_env_get "$f" ENCRYPTION_KEY)" ]; then
        cx_env_set "$f" ENCRYPTION_KEY "$(openssl rand -hex 32)"
        cx_env_generated kek
      fi
      ;;
    ui | kms | hsm) ;;
    *)
      cx_line FAIL "$(cx_msg env_kek_bad "$prov")"
      return 1
      ;;
  esac

  v=$(cx_env_get "$f" ADMIN_INITIAL_PASSWORD)
  if [ -z "$v" ] || [ "$v" = "$CX_ENV_TEMPLATE_ADMIN" ]; then
    CX_ENV_ADMIN_PASSWORD=$(cx_env_password)
    cx_env_set "$f" ADMIN_INITIAL_PASSWORD "$CX_ENV_ADMIN_PASSWORD"
    cx_env_generated admin
  fi

  # The database password is never changed once the database exists; an external database has
  # its own password, which only the operator knows.
  v=$(cx_env_get "$f" DB_PASSWORD)
  if [ -d "$data/postgres" ] && [ -n "$(ls -A "$data/postgres" 2>/dev/null)" ]; then
    :
  elif [ -n "$(cx_env_get "$f" EXTERNAL_DB_HOST)" ]; then
    if [ -z "$v" ] || [ "$v" = postgres ]; then
      cx_line FAIL "$(cx_msg env_db_external "$f")"
      return 1
    fi
  elif [ -z "$v" ] || [ "$v" = postgres ]; then
    cx_env_set "$f" DB_PASSWORD "$(cx_env_random 32)"
    cx_env_generated db
  fi

  local host ips port suffix=""
  host=$(cx_env_get "$f" TLS_DOMAIN)
  if [ -z "$host" ]; then
    host=$(cx_env_host_fqdn)
    cx_env_set "$f" TLS_DOMAIN "$host"
  fi
  ips=$(cx_env_get "$f" TLS_IP_SAN)
  if [ -z "$ips" ]; then
    ips=$(cx_env_host_ipv4s)
    [ -z "$ips" ] || cx_env_set "$f" TLS_IP_SAN "$ips"
  fi
  port=$(cx_env_get "$f" TLS_HTTPS_PORT)
  [ "${port:-443}" = 443 ] || suffix=":$port"
  CX_ENV_URL=$(cx_env_get "$f" PUBLIC_BASE_URL)
  if [ -z "$CX_ENV_URL" ]; then
    if [ -n "$ips" ]; then CX_ENV_URL="https://${ips%%,*}$suffix"; else CX_ENV_URL="https://$host$suffix"; fi
    cx_env_set "$f" PUBLIC_BASE_URL "$CX_ENV_URL"
  fi

  # Only the built-in proxy form is filled in: behind your own ingress, its address belongs here.
  if [ -z "$(cx_env_get "$f" TRUSTED_PROXIES)" ] && [[ " $CX_ENV_OVERLAYS " != *" external-ingress "* ]]; then
    v=$(cx_env_get "$f" DOCKER_SUBNET)
    cx_env_set "$f" TRUSTED_PROXIES "${v:-172.28.100.0/24}"
  fi
  chmod 600 "$f"
}
