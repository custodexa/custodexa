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

chmod 600 "${ENV_FILE}" 2>/dev/null || true

# ---------- login target ----------
compose_file=$(current COMPOSE_FILE)
if [ "${compose_file}" = "docker-compose.dev.yml" ]; then
  APP_URL="http://localhost:3000"
else
  APP_URL="http://localhost/"
fi

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
  say "=========================================="
}

# ---------- start & wait (--up) ----------
if [ "${RUN_UP}" = 1 ]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for --up"
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
