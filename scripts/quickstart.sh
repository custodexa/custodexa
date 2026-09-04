#!/usr/bin/env bash
# Quickstart: verify the required secrets in .env, generate any missing ones with a
# CSPRNG, then (optionally) start the stack and print the login info.
#
#   bash scripts/quickstart.sh        # prepare .env (created from the template if absent)
#   bash scripts/quickstart.sh --up   # prepare, then docker compose up -d and wait for health
#
# Principles:
#   - Idempotent: values you have already set are never touched; re-running is safe.
#   - Generated values are exactly equivalent to hand-filled ones — no product behavior
#     changes, and the first login still forces a password change.
#   - An explicit KEK_PROVIDER of ui / kms / hsm is respected: no local key is generated.
#   - DB_PASSWORD is never changed once the postgres data directory has been initialized
#     (changing it afterwards would lock the backend out of the existing database).
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=.env
TEMPLATE=.env.example
HEALTH_TIMEOUT=120

say()  { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fail "openssl is required to generate secrets (preinstalled on macOS/Linux; on Windows run this inside WSL)"

RUN_UP=0
[ "${1:-}" = "--up" ] && RUN_UP=1
TOTAL=1; [ "${RUN_UP}" = 1 ] && TOTAL=4

# ---------- step 1: secrets ----------
say ""
say "[1/${TOTAL}] Checking required secrets in ${ENV_FILE}"

if [ ! -f "${ENV_FILE}" ]; then
  [ -f "${TEMPLATE}" ] || fail "${TEMPLATE} not found (run this from the project root)"
  cp "${TEMPLATE}" "${ENV_FILE}"
  say "  created ${ENV_FILE} from template"
fi

# Read the current value of a key (first uncommented line wins).
current() {
  awk -v k="$1" 'index($0, k"=")==1 { sub("^"k"=",""); print; exit }' "${ENV_FILE}"
}

# Idempotent write: replace the uncommented line in place, else uncomment the first
# commented one, else append. Values always live on their own line with no inline
# comment (env_file does not strip inline comments; they would corrupt the value).
set_kv() {
  local key="$1" val="$2" tmp
  tmp=$(mktemp)
  if grep -q "^${key}=" "${ENV_FILE}"; then
    awk -v k="${key}" -v v="${val}" 'BEGIN{d=0} !d && index($0,k"=")==1 {print k"="v; d=1; next} {print}' "${ENV_FILE}" >"${tmp}"
  elif grep -Eq "^# *${key}=" "${ENV_FILE}"; then
    awk -v k="${key}" -v v="${val}" 'BEGIN{d=0} !d && $0 ~ "^# *"k"=" {print k"="v; d=1; next} {print}' "${ENV_FILE}" >"${tmp}"
  else
    cat "${ENV_FILE}" >"${tmp}"
    printf '%s=%s\n' "${key}" "${val}" >>"${tmp}"
  fi
  mv "${tmp}" "${ENV_FILE}"
}

gen_alnum() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }

# Password: 20 alphanumeric chars, guaranteed to contain both letters and digits.
gen_password() {
  local p
  while :; do
    p=$(gen_alnum 20)
    case ${p} in *[A-Za-z]*) ;; *) continue ;; esac
    case ${p} in *[0-9]*)    ;; *) continue ;; esac
    printf '%s' "${p}"
    return
  done
}

GENERATED_ADMIN=""
report() { printf '  %-24s %s\n' "$1" "$2"; }

# ---------- JWT_SECRET ----------
v=$(current JWT_SECRET)
if [ -z "${v}" ] || [ "${v}" = "change-me-in-production-dev-secret" ]; then
  set_kv JWT_SECRET "$(openssl rand -base64 32)"
  report JWT_SECRET "generated"
else
  report JWT_SECRET "already set, left as is"
fi

# ---------- KEK / ENCRYPTION_KEY ----------
prov=$(current KEK_PROVIDER)
case "${prov}" in
  ""|env)
    v=$(current ENCRYPTION_KEY)
    if [ -z "${v}" ]; then
      set_kv ENCRYPTION_KEY "$(openssl rand -hex 32)"
      report ENCRYPTION_KEY "generated (env mode: the key lives in ${ENV_FILE} — protect this file)"
    else
      report ENCRYPTION_KEY "already set, left as is"
    fi
    ;;
  ui)
    report ENCRYPTION_KEY "skipped (KEK_PROVIDER=ui: the key is supplied on the unseal page and never touches disk)"
    ;;
  kms|hsm)
    report ENCRYPTION_KEY "skipped (KEK_PROVIDER=${prov}: delegated mode, local key material must stay unset)"
    ;;
  *)
    fail "KEK_PROVIDER=${prov} is not one of env/ui/kms/hsm — fix ${ENV_FILE} first"
    ;;
esac

# ---------- ADMIN_INITIAL_PASSWORD ----------
v=$(current ADMIN_INITIAL_PASSWORD)
if [ -z "${v}" ] || [ "${v}" = "change-me-admin-initial-password-in-env" ]; then
  GENERATED_ADMIN=$(gen_password)
  set_kv ADMIN_INITIAL_PASSWORD "${GENERATED_ADMIN}"
  report ADMIN_INITIAL_PASSWORD "generated (shown in the login info below)"
else
  report ADMIN_INITIAL_PASSWORD "already set, left as is (existing secrets are never echoed)"
fi

# ---------- DB_PASSWORD ----------
data_path=$(current DATA_PATH); data_path=${data_path:-./data}
v=$(current DB_PASSWORD)
if [ -d "${data_path}/postgres" ] && [ -n "$(ls -A "${data_path}/postgres" 2>/dev/null)" ]; then
  report DB_PASSWORD "left as is (${data_path}/postgres is already initialized; changing it would lock the backend out)"
elif [ -z "${v}" ] || [ "${v}" = "postgres" ]; then
  set_kv DB_PASSWORD "$(gen_alnum 32)"
  report DB_PASSWORD "generated"
else
  report DB_PASSWORD "already set, left as is"
fi

# ---------- TLS: host name, certificate addresses, public URL ----------
# The production stack terminates TLS itself, so a fresh .env needs a host name to put in the
# certificate and a base URL that matches it. Anything already filled in is left alone.
host_fqdn() {
  local h
  h=$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)
  case "${h}" in
    ""|localhost|localhost.*) printf 'custodexa.local' ;;
    *[!A-Za-z0-9.-]*)         printf 'custodexa.local' ;;
    *)                        printf '%s' "${h}" ;;
  esac
}

primary_ipv4() {
  # The address on the interface that carries the default route: what people on the
  # network reach this host by. Linux via ip route; macOS via route + ipconfig.
  local ip ifc
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}' | head -n1)
  if [ -z "${ip}" ] && command -v route >/dev/null 2>&1; then
    ifc=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    [ -n "${ifc}" ] && ip=$(ipconfig getifaddr "${ifc}" 2>/dev/null || true)
  fi
  printf '%s' "${ip}"
}

host_ipv4s() {
  # Every IPv4 address of this host that a client might use, comma separated, the
  # primary one first. Loopback and the usual virtual interfaces (docker bridges,
  # VM host bridges, tunnels) are left out: a certificate is for the addresses users
  # type, and those are the physical ones.
  local primary rest
  primary=$(primary_ipv4)
  if command -v ip >/dev/null 2>&1; then
    rest=$(ip -4 -o addr show scope global 2>/dev/null \
      | awk '$2 !~ /^(docker|br-|veth|virbr|vmnet|utun|tun|tap|bridge|awdl|llw)/ {split($4, a, "/"); print a[1]}')
  elif command -v ifconfig >/dev/null 2>&1; then
    rest=$(ifconfig 2>/dev/null | awk '
      /^[a-z]/ { ifc = $1; sub(":", "", ifc) }
      /^\t*inet / && ifc !~ /^(docker|br-|veth|virbr|vmnet|utun|tun|tap|bridge|awdl|llw|lo)/ { print $2 }')
  else
    rest=$(hostname -I 2>/dev/null | tr ' ' '\n' || true)
  fi
  { printf '%s\n' "${primary}"; printf '%s\n' "${rest}"; } \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -v '^127\.' \
    | awk '!seen[$0]++' \
    | paste -sd, - | tr -d '\n'
}

v=$(current TLS_DOMAIN)
if [ -z "${v}" ]; then
  v=$(host_fqdn)
  set_kv TLS_DOMAIN "${v}"
  report TLS_DOMAIN "set to ${v}"
else
  report TLS_DOMAIN "already set, left as is"
fi
TLS_HOST="${v}"

v=$(current TLS_IP_SAN)
if [ -z "${v}" ]; then
  v=$(host_ipv4s)
  if [ -n "${v}" ]; then
    set_kv TLS_IP_SAN "${v}"
    report TLS_IP_SAN "set to ${v}"
  else
    report TLS_IP_SAN "left empty (no non-loopback IPv4 address found)"
  fi
else
  report TLS_IP_SAN "already set, left as is"
fi
FIRST_IP=${v%%,*}

https_port=$(current TLS_HTTPS_PORT); https_port=${https_port:-443}
http_port=$(current TLS_HTTP_PORT); http_port=${http_port:-80}
PORT_SUFFIX=""
[ "${https_port}" = "443" ] || PORT_SUFFIX=":${https_port}"

v=$(current PUBLIC_BASE_URL)
if [ -z "${v}" ]; then
  if [ -n "${FIRST_IP}" ]; then
    v="https://${FIRST_IP}${PORT_SUFFIX}"
  else
    v="https://${TLS_HOST}${PORT_SUFFIX}"
  fi
  set_kv PUBLIC_BASE_URL "${v}"
  report PUBLIC_BASE_URL "set to ${v}"
  say "  (host name and addresses above were read from this machine's network settings;"
  say "   if people will reach the site by another name or address, edit TLS_DOMAIN,"
  say "   TLS_IP_SAN and PUBLIC_BASE_URL in ${ENV_FILE} before the first start)"
else
  report PUBLIC_BASE_URL "already set, left as is"
fi
PUBLIC_URL="${v}"

# ---------- TRUSTED_PROXIES ----------
# Which addresses may speak for a client. The stack ships with its own proxy in front of the
# frontend, so every request reaches the backend from inside the Docker network; without this key
# the source of each request is read as the proxy's own address, and both the audit trail and the
# login rate limit lose the ability to tell one client from another.
#
# Only the built-in form is filled in automatically. Run your own ingress and its address is the
# one that belongs here, which is a decision about your network rather than about this stack.
compose_file=$(current COMPOSE_FILE)
v=$(current TRUSTED_PROXIES)
if [ -n "${v}" ]; then
  report TRUSTED_PROXIES "already set, left as is"
else
  case "${compose_file}" in
    docker-compose.dev.yml|*external-ingress*)
      report TRUSTED_PROXIES "left empty (this form has no built-in proxy; set it to your ingress address)"
      ;;
    *)
      subnet=$(current DOCKER_SUBNET); subnet=${subnet:-172.28.100.0/24}
      set_kv TRUSTED_PROXIES "${subnet}"
      report TRUSTED_PROXIES "set to ${subnet} (the built-in proxy speaks for the clients behind it)"
      ;;
  esac
fi

chmod 600 "${ENV_FILE}" 2>/dev/null || true

# ---------- login target ----------
CA_URL=""
case "${compose_file}" in
  docker-compose.dev.yml)
    APP_URL="http://localhost:3000"
    ;;
  *external-ingress*)
    APP_URL="http://localhost:${http_port}/"
    ;;
  *)
    APP_URL="${PUBLIC_URL}/"
    [ "$(current TLS_MODE)" = "provided" ] || CA_URL="${PUBLIC_URL}/custodexa-ca.crt"
    ;;
esac

print_login_info() {
  say ""
  say "=========================================="
  if [ "${prov}" = "ui" ]; then
    say " Initialize & login (in-memory master key mode)"
  else
    say " Login info"
  fi
  say "   URL:      ${APP_URL}"
  say "   Account:  admin"
  if [ -n "${GENERATED_ADMIN}" ]; then
    say "   Password: ${GENERATED_ADMIN}"
    say ""
    say " The password is also stored as ADMIN_INITIAL_PASSWORD in ${ENV_FILE}."
  else
    say "   Password: the existing ADMIN_INITIAL_PASSWORD value in ${ENV_FILE}"
  fi
  if [ "${prov}" = "ui" ]; then
    say ""
    say " First visit: the browser will take you to the master-key initialization"
    say " page. The master key is generated locally in your browser and is never"
    say " written to disk — SAVE IT SOMEWHERE SAFE; every restart stays sealed"
    say " until someone enters it on the unseal page."
    say " Authorize the initialization with the admin credentials above, then log in"
    say " (the first login still forces a password change)."
  else
    say " The first login forces a password change; after that, remove or rotate"
    say " ADMIN_INITIAL_PASSWORD in ${ENV_FILE}."
  fi
  if [ -n "${CA_URL}" ]; then
    say ""
    say " This deployment serves https with a certificate it generated itself."
    say " Download the certificate authority from ${CA_URL} and install it on the"
    say " machines that connect (group policy, MDM, or by hand); browsers then show"
    say " the site as trusted. To use a certificate from your own CA instead, see"
    say " the TLS section of docs/QUICKSTART.md."
    say ""
  fi
  say "=========================================="
}

# ---------- public ports ----------
# Naming whatever already holds a port is worth more than letting docker fail with
# "address already in use": the fix is a different pair of ports here, and knowing which
# program is in the way is what tells you whether that is the right fix.
#
# port_listener prints what listens on $1 (empty when the port is free) and returns 1 when
# neither tool is available, which is the difference between "nothing is listening" and
# "nobody looked".
port_listener() {
  local port="$1" out=""
  if command -v ss >/dev/null 2>&1; then
    out=$(ss -ltnHp "sport = :${port}" 2>/dev/null \
      | sed -n 's/.*users:((\"\([^\"]*\)\",pid=\([0-9]*\).*/\1 (pid \2)/p' | sort -u | paste -sd, -)
    if [ -z "${out}" ] && [ -n "$(ss -ltnH "sport = :${port}" 2>/dev/null)" ]; then
      out="an unnamed process (run as root to see which)"
    fi
  elif command -v lsof >/dev/null 2>&1; then
    out=$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null \
      | awk 'NR>1 {printf "%s (pid %s)\n", $1, $2}' | sort -u | paste -sd, -)
  else
    return 1
  fi
  printf '%s' "${out}"
}

PORTS_UNCHECKED=0
require_port_free() {
  local port="$1" label="$2" who
  if ! who=$(port_listener "${port}"); then
    PORTS_UNCHECKED=1
    return 0
  fi
  [ -z "${who}" ] && return 0
  say ""
  say "ERROR: port ${port} (${label}) is already in use by ${who}." >&2
  say "Set TLS_HTTPS_PORT and TLS_HTTP_PORT in ${ENV_FILE} to ports nothing else holds (8443 and" >&2
  say "8088 are a common choice) and run this again; whenever the https port is not 443, the" >&2
  say "address people type carries it, as in https://host:8443" >&2
  exit 1
}

# ---------- start & wait (--up) ----------
if [ "${RUN_UP}" = 1 ]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for --up"
  case "${compose_file}" in
    docker-compose.dev.yml) ;;
    *external-ingress*) require_port_free "${http_port}" "http, published by the frontend" ;;
    *)
      require_port_free "${https_port}" "https"
      require_port_free "${http_port}" "http, redirected to https"
      ;;
  esac
  if [ "${PORTS_UNCHECKED}" = 1 ]; then
    say ""
    say "  (neither ss nor lsof is installed, so the public ports were not checked; docker will"
    say "   report the port itself if something already holds it)"
  fi
  say ""
  say "[2/${TOTAL}] Building images (first run may take 5-10 minutes)"
  docker compose build
  say ""
  say "[3/${TOTAL}] Starting containers"
  docker compose up -d
  say ""
  say "[4/${TOTAL}] Waiting for the backend to become healthy (up to ${HEALTH_TIMEOUT}s)"
  waited=0
  until docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1; do
    waited=$((waited + 3))
    if [ "${waited}" -ge "${HEALTH_TIMEOUT}" ]; then
      say ""
      say "The backend did not report healthy within ${HEALTH_TIMEOUT}s."
      say "Inspect the logs: docker compose logs backend"
      say "(a refused start always states which variable was rejected and why)"
      exit 1
    fi
    sleep 3
    printf '.'
  done
  say ""
  say "Backend is healthy."
  print_login_info
else
  say ""
  say "Preparation complete. Next:"
  say "    docker compose up -d     # first run builds the images (5-10 minutes)"
  print_login_info
fi
