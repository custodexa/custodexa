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
#   - DB_PASSWORD is never changed once a postgres data directory (postgres or postgresql) has been initialized
#     (changing it afterwards would lock the backend out of the existing database).
#   - The deployment form (bundled or external database, built-in HTTPS or your own reverse proxy)
#     comes from EXTERNAL_DB_HOST and TLS_MODE in .env. The script derives the compose profiles
#     from them, keeps them in a managed block at the end of .env and passes them to docker
#     compose; COMPOSE_FILE=docker-compose.dev.yml selects the development stack instead.
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=.env
TEMPLATE=.env.example
HEALTH_TIMEOUT=120
DEV_HEALTH_TIMEOUT=1800

say()  { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fail "openssl is required to generate secrets (preinstalled on macOS/Linux; on Windows run this inside WSL)"

RUN_UP=0
[ "${1:-}" = "--up" ] && RUN_UP=1
TOTAL=1; [ "${RUN_UP}" = 1 ] && TOTAL=4

# ---------- deployment form ----------
# The rules that turn .env into a deployment form live in scripts/custodexa/lib (form.sh derives it
# from EXTERNAL_DB_HOST and TLS_MODE and checks the address; form_guard.sh finds the data folders):
# the files the installed management script uses, so both ways to deploy decide alike.
LIB_DIR=scripts/custodexa/lib
for lib_file in common env form form_guard; do
  [ -f "${LIB_DIR}/${lib_file}.sh" ] || fail "${LIB_DIR}/${lib_file}.sh not found (run this from a complete checkout)"
  # shellcheck source=/dev/null
  . "${LIB_DIR}/${lib_file}.sh"
done
CX_ROOT=${PWD}

# refuse <text>: print it to stderr and stop. Nothing was written.
refuse() { printf '%s\n' "$*" >&2; exit 1; }

DEV=0 LEGACY_DB=0 LEGACY_ING=0 COMPOSE_FILE_RAW="" TLS_FLIP=0 TLS_WAS=""
classify_compose_file() {
  COMPOSE_FILE_RAW=$(cx_form_trim "$(cx_env_get "${ENV_FILE}" COMPOSE_FILE)")
  DEV=0 LEGACY_DB=0 LEGACY_ING=0
  [ "${COMPOSE_FILE_RAW}" != "docker-compose.dev.yml" ] || DEV=1
  [[ ${COMPOSE_FILE_RAW} != *docker-compose.external-database.yml* ]] || LEGACY_DB=1
  [[ ${COMPOSE_FILE_RAW} != *docker-compose.external-ingress.yml* ]] || LEGACY_ING=1
}

# Refusals that need nothing but .env: they come before anything is printed or written.
refuse_unusable_settings() {
  local host tls port what
  classify_compose_file
  host=$(cx_form_db_host "${ENV_FILE}")
  tls=$(cx_form_tls_mode "${ENV_FILE}")
  if [ "${DEV}" = 1 ]; then
    if [ -n "${host}" ] || [ "${tls}" = external ]; then
      what="EXTERNAL_DB_HOST=${host}"
      [ -n "${host}" ] || what="TLS_MODE=external"
      refuse "ERROR: ${what} cannot be used with
COMPOSE_FILE=docker-compose.dev.yml (the development stack). Nothing was changed.
The development stack always uses the database and entry point defined in
docker-compose.dev.yml; an external database or TLS_MODE=external is not applied.
  - to keep developing: empty EXTERNAL_DB_HOST (and undo any TLS_MODE change)
  - to run the production form with an external database: comment out the
    COMPOSE_FILE line and run this again"
    fi
    return 0
  fi
  if ! cx_form_derive "${ENV_FILE}" >/dev/null; then
    refuse "ERROR: TLS_MODE=${tls} in .env is not a valid value. Nothing was changed.
  Valid values: selfsigned, provided, external (empty means selfsigned)."
  fi
  if [ -n "${host}" ] && ! cx_form_check_host "${host}"; then
    case ${CX_FORM_REASON} in
      service)
        refuse "ERROR: EXTERNAL_DB_HOST=${host} cannot be used. Nothing was changed.
  why            ${host} is a service name of Custodexa itself; it would connect
                 back to the bundled database, not to a database server of your own
  what to put    the host name or IP of your database server, for example
                 db01.example.internal or 10.0.0.40
To use the bundled database, leave EXTERNAL_DB_HOST empty or remove the line." ;;
      loopback)
        refuse "ERROR: EXTERNAL_DB_HOST=${host} cannot be used. Nothing was changed.
  why            inside a container, ${host} is the backend container itself,
                 not this host
  what to put    the database server's host name or IP; if the database runs on
                 this host, this host's network address (for example 10.0.0.12)
To use the bundled database, leave EXTERNAL_DB_HOST empty or remove the line." ;;
      *)
        refuse "ERROR: EXTERNAL_DB_HOST=${host} cannot be used. Nothing was changed.
  why            this line takes a host name or IP only: no scheme, port,
                 account or blanks
  what to put    EXTERNAL_DB_HOST=db01.example.internal
                 EXTERNAL_DB_PORT=5432   (own line, default 5432)
                 account and password go in DB_USER and DB_PASSWORD
To use the bundled database, leave EXTERNAL_DB_HOST empty or remove the line." ;;
    esac
  fi
  port=$(cx_form_trim "$(cx_env_get "${ENV_FILE}" EXTERNAL_DB_PORT)")
  if [ -z "${host}" ] && [ -n "${port}" ] && [ "${port}" != 5432 ]; then
    refuse "ERROR: EXTERNAL_DB_PORT=${port} is set but EXTERNAL_DB_HOST is empty.
Nothing was changed.
  - for an external database: add EXTERNAL_DB_HOST (host name or IP)
  - for the bundled database: remove the EXTERNAL_DB_PORT line"
  fi
}
[ ! -f "${ENV_FILE}" ] || refuse_unusable_settings

# The managed block at the end of .env holds the profiles this script derived last time.
block_profiles() {
  awk -v b="${CX_FORM_MARK_BEGIN}" -v e="${CX_FORM_MARK_END}" '
    $0 == b { inb = 1; next }
    inb && $0 == e { exit }
    inb && index($0, "COMPOSE_PROFILES=") == 1 { sub("^COMPOSE_PROFILES=", ""); print; exit }' "${ENV_FILE}"
}

# rel_path <path>: a path under the project folder written the way .env writes it (./data/...).
rel_path() { case $1 in "${PWD}"/*) printf './%s' "${1#"${PWD}"/}" ;; *) printf '%s' "$1" ;; esac; }

# db_password_line: what the secrets step reports for DB_PASSWORD, printed before a refusal so the
# screen reads like the run it interrupted. Nothing is written.
db_password_line() {
  local first v
  first=$(cx_fg_data_dirs | head -n1)
  v=$(cx_env_get "${ENV_FILE}" DB_PASSWORD)
  if [ -n "${first}" ]; then
    report DB_PASSWORD "left as is ($(rel_path "${first}") holds data; changing it would lock the backend out)"
  elif [ -n "${v}" ] && [ "${v}" != "postgres" ]; then
    report DB_PASSWORD "already set, left as is"
  fi
}

# Refusals that need the state of this folder: what the last run started, and where the data is.
refuse_form_mismatch() {
  local host last_ext=0 bp was dirs d ver size container=""
  host=$(cx_form_db_host "${ENV_FILE}")
  bp=$(block_profiles)
  if [ "${LEGACY_DB}" = 1 ] || { [ -n "${bp}" ] && [[ ",${bp}," != *,bundled-db,* ]]; }; then last_ext=1; fi
  if [ -z "${host}" ] && [ "${last_ext}" = 1 ]; then
    if [ "${LEGACY_DB}" = 1 ]; then
      was="with an external database (COMPOSE_FILE in .env lists
                 docker-compose.external-database.yml)"
    else
      was="with an external database (the managed block at the end of
                 .env has COMPOSE_PROFILES=${bp}, no bundled-db)"
    fi
    db_password_line
    refuse "
ERROR: EXTERNAL_DB_HOST is empty, but this deployment last started with an
external database. Nothing was changed and nothing was started.
  last started   ${was}
  why            with the line empty, this script would start a bundled
                 database that has no data. It would look like a fresh
                 install: your users, assets and audit records are not in it.
  - to keep using the external database: put EXTERNAL_DB_HOST back to its
    original value (this script does not record the address)
  - to go back to the bundled database on purpose: follow the rollback steps
    in the \"Switching to an external database\" section of
    docs/ops/backup-and-restore.md"
  fi
  if [ -n "${host}" ] && [ "${last_ext}" = 0 ]; then
    dirs=$(cx_fg_data_dirs)
    if [ -z "${dirs}" ] && command -v docker >/dev/null 2>&1; then
      container=$(docker ps -a --filter "name=^custodexa-postgres$" --format '{{.Names}}' 2>/dev/null || true)
    fi
    if [ -n "${dirs}" ] || [ -n "${container}" ]; then
      db_password_line
      printf '\nERROR: EXTERNAL_DB_HOST=%s cannot be used: this deployment\nalready has bundled database data. Nothing was changed and nothing was started.\n' "${host}" >&2
      if [ -n "${dirs}" ]; then
        while IFS= read -r d; do
          [ -n "${d}" ] || continue
          ver=""
          [ ! -f "${d}/PG_VERSION" ] || ver="PostgreSQL $(tr -d '[:space:]' <"${d}/PG_VERSION")"
          size=$(cx_size_human "$(du -sk "${d}" 2>/dev/null | cut -f1 | awk '{print $1 * 1024}')")
          printf '  data in use    %s    %s    %s\n' "$(rel_path "${d}")" "${ver}" "${size}" >&2
        done <<<"${dirs}"
      else
        printf '  data in use    container %s\n' "${container}" >&2
      fi
      refuse "  why            the bundled database is the one holding your data. Pointing
                 at an external database does not move it; the system would
                 start against a different database that has none of it.
  - to keep using the bundled database: empty EXTERNAL_DB_HOST (or remove the
    line), then run this again
  - to move the data to an external database: follow \"Switching to an external
    database\" in docs/ops/backup-and-restore.md, then run this again"
    fi
  fi
  refuse_old_major_data "${host}"
}

# refuse_old_major_data <external host>: the bundled database keeps its data in data/postgresql
# since PostgreSQL 18. Data left in data/postgres by an older release is not read by the new image,
# which would initialize an empty database next to it, so stop before anything starts. Nothing
# converts it here: the manual steps are in docs/QUICKSTART.md.
refuse_old_major_data() {
  local root old ver size
  [ -z "$1" ] || return 0
  root=$(cx_fg_data_root)
  old=${root}/postgres
  [ -d "${old}" ] && [ -n "$(ls -A "${old}" 2>/dev/null)" ] || return 0
  [ ! -d "${root}/postgresql" ] || [ -z "$(ls -A "${root}/postgresql" 2>/dev/null)" ] || return 0
  ver="PostgreSQL"
  [ ! -f "${old}/PG_VERSION" ] || ver="PostgreSQL $(tr -d '[:space:]' <"${old}/PG_VERSION")"
  size=$(cx_size_human "$(du -sk "${old}" 2>/dev/null | cut -f1 | awk '{print $1 * 1024}')")
  db_password_line
  refuse "
ERROR: $(rel_path "${old}") holds ${ver} data (${size}). This version runs
PostgreSQL 18 from $(rel_path "${root}/postgresql"), which is empty, so it would start with
no data. Nothing was started and $(rel_path "${old}") was not touched.
This script does not convert the data. Follow \"Moving a source deployment to
PostgreSQL 18\" in docs/QUICKSTART.md, then run this again."
}

# commit_form <profiles>: the one write of the form. The new .env is built in full next to the old
# one and takes its place in a single rename, so a failure before the rename leaves the old file
# as it was. Outside the managed block only two edits are allowed: the COMPOSE_FILE line that lists
# an old overlay file goes, and TLS_MODE becomes external when that line listed the ingress.
FORM_BLOCK="" # "", added or updated
commit_form() {
  local tmp t2 old_block=0
  FORM_BLOCK=""
  if grep -qxF "${CX_FORM_MARK_BEGIN}" "${ENV_FILE}"; then old_block=1; fi
  tmp=$(umask 077 && mktemp "${ENV_FILE}.tmp-XXXXXX") || return 1
  cat "${ENV_FILE}" >"${tmp}" || { rm -f "${tmp}"; return 1; }
  if [ "${TLS_FLIP}" = 1 ]; then
    cx_env_set "${tmp}" TLS_MODE external || { rm -f "${tmp}" "${tmp}".tmp-*; return 1; }
  fi
  t2=$(umask 077 && mktemp "${ENV_FILE}.tmp-XXXXXX") || { rm -f "${tmp}"; return 1; }
  awk -v b="${CX_FORM_MARK_BEGIN}" -v e="${CX_FORM_MARK_END}" -v legacy="${LEGACY_DB}${LEGACY_ING}" '
    $0 == b { skip = 1; next }
    skip { if ($0 == e) skip = 0; next }
    legacy != "00" && /^[[:space:]]*COMPOSE_FILE=.*docker-compose\.external-(database|ingress)\.yml/ { next }
    { print }' "${tmp}" >"${t2}" || { rm -f "${tmp}" "${t2}"; return 1; }
  printf '%s\nCOMPOSE_PROFILES=%s\n%s\n' "${CX_FORM_MARK_BEGIN}" "$1" "${CX_FORM_MARK_END}" >>"${t2}" || { rm -f "${tmp}" "${t2}"; return 1; }
  rm -f "${tmp}"
  if cmp -s "${t2}" "${ENV_FILE}"; then
    rm -f "${t2}"
    return 0
  fi
  if ! { chmod 600 "${t2}" && mv -f "${t2}" "${ENV_FILE}"; }; then
    rm -f "${t2}"
    return 1
  fi
  FORM_BLOCK=added
  if [ "${old_block}" = 1 ]; then FORM_BLOCK=updated; fi
}

PROFILES="" FORM_WORDS="" TRANSLATION=""
# settle_form: derive the form, write the managed block (and translate an old COMPOSE_FILE) once.
settle_form() {
  local host tls
  [ "${DEV}" = 0 ] || return 0
  host=$(cx_form_db_host "${ENV_FILE}")
  tls=$(cx_form_tls_mode "${ENV_FILE}")
  TLS_WAS=${tls}
  TLS_FLIP=0
  if [ "${LEGACY_ING}" = 1 ] && [ "${tls}" != external ]; then TLS_FLIP=1; fi
  FORM_WORDS=""
  if [ "${tls}" = external ] || [ "${LEGACY_ING}" = 1 ]; then FORM_WORDS=external-ingress; fi
  [ -z "${host}" ] || FORM_WORDS="${FORM_WORDS:+${FORM_WORDS} }external-database"
  PROFILES=$(cx_form_profiles "${FORM_WORDS}")
  commit_form "${PROFILES}" ||
    fail "could not write ${ENV_FILE}: a temporary file next to it could not be created or renamed; ${ENV_FILE} was not changed"
  if [ "${LEGACY_DB}" = 1 ] || [ "${LEGACY_ING}" = 1 ]; then
    TRANSLATION="  COMPOSE_FILE             old setting translated, each change below:
                           removed  COMPOSE_FILE=${COMPOSE_FILE_RAW}"
    if [ "${TLS_FLIP}" = 1 ]; then
      TRANSLATION="${TRANSLATION}
                           changed  TLS_MODE=${TLS_WAS:-selfsigned} -> external"
    fi
    TRANSLATION="${TRANSLATION}
                           ${FORM_BLOCK:-added}    managed block at the end of .env:
                                    COMPOSE_PROFILES=${PROFILES}"
  fi
}

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

# ---------- deployment form: refusals, then the one write ----------
# Everything that can refuse runs before the first secret is written, so a refusal leaves .env as
# it was.
classify_compose_file
if [ "${DEV}" = 0 ]; then
  refuse_form_mismatch
  if [ -n "$(cx_form_db_host "${ENV_FILE}")" ] && [ -z "$(cx_fg_data_dirs)" ]; then
    v=$(cx_env_get "${ENV_FILE}" DB_PASSWORD)
    if [ -z "${v}" ] || [ "${v}" = "postgres" ]; then
      fail "DB_PASSWORD is empty or still the template value while EXTERNAL_DB_HOST=$(cx_form_db_host "${ENV_FILE}") is set: put the password of the database account on that server into ${ENV_FILE} and run this again (nothing was generated)"
    fi
  fi
fi
settle_form

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
external_db=$(current EXTERNAL_DB_HOST)
db_data_dir=""
for d in postgresql postgres; do
  if [ -d "${data_path}/${d}" ] && [ -n "$(ls -A "${data_path}/${d}" 2>/dev/null)" ]; then db_data_dir=${data_path}/${d}; break; fi
done
if [ -n "${db_data_dir}" ]; then
  report DB_PASSWORD "left as is (${db_data_dir} is already initialized; changing it would lock the backend out)"
  if [ -z "${external_db}" ] && [ "${db_data_dir}" = "${data_path}/postgresql" ] && [ -d "${data_path}/postgres" ] && [ -n "$(ls -A "${data_path}/postgres" 2>/dev/null)" ]; then
    say "  ${data_path}/postgres is not used any more and was left in place; remove it yourself once you no longer need it."
  fi
elif [ -n "${external_db}" ]; then
  # An external database decides its own password; a value generated here would never match it
  # (an empty or template value was refused above, before anything was written).
  report DB_PASSWORD "left as is (EXTERNAL_DB_HOST is set; the password belongs to that server)"
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
  # A host with no global IPv4 address makes the grep in host_ipv4s find nothing, which pipefail
  # turns into a failure: that is the "left empty" case below, not an error.
  v=$(host_ipv4s || true)
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
OWN_INGRESS=0
[[ " ${FORM_WORDS} " != *" external-ingress "* ]] || OWN_INGRESS=1
v=$(current TRUSTED_PROXIES)
if [ -n "${v}" ]; then
  report TRUSTED_PROXIES "already set, left as is"
elif [ "${DEV}" = 1 ] || [ "${OWN_INGRESS}" = 1 ]; then
  report TRUSTED_PROXIES "left empty (this form has no built-in proxy; set it to your ingress address)"
else
  subnet=$(current DOCKER_SUBNET); subnet=${subnet:-172.28.100.0/24}
  set_kv TRUSTED_PROXIES "${subnet}"
  report TRUSTED_PROXIES "set to ${subnet} (the built-in proxy speaks for the clients behind it)"
fi

# ---------- VAULT_DEV_ROOT_TOKEN_ID (development stack only) ----------
# The development compose file refuses to start unless the test Vault's initialization token is
# set, and it checks that even when another service is the one being started. The value is a
# throwaway for the bundled test target, so it is generated here but never printed. Other forms
# neither need it nor get it written; a value already present there is left alone.
if [ "${DEV}" = 1 ]; then
  if [ -z "$(current VAULT_DEV_ROOT_TOKEN_ID)" ]; then
    set_kv VAULT_DEV_ROOT_TOKEN_ID "$(gen_alnum 32)"
    report VAULT_DEV_ROOT_TOKEN_ID "generated (development stack only)"
  else
    report VAULT_DEV_ROOT_TOKEN_ID "already set, left as is"
  fi
fi

chmod 600 "${ENV_FILE}" 2>/dev/null || true

# ---------- deployment form report ----------
own_port=$(cx_form_trim "$(current HTTP_PORT)"); own_port=${own_port:-80}
if [ "${DEV}" = 0 ]; then
  tls_now=$(cx_form_tls_mode "${ENV_FILE}"); tls_now=${tls_now:-selfsigned}
  db_now=$(cx_form_db_host "${ENV_FILE}")
  if [ -n "${db_now}" ]; then
    db_port_now=$(cx_form_trim "$(current EXTERNAL_DB_PORT)")
    form_db="external database at ${db_now}:${db_port_now:-5432}"
  else
    form_db="bundled database"
  fi
  if [ "${OWN_INGRESS}" = 1 ]; then
    form_web="your reverse proxy (port ${own_port})"
  else
    form_web="built-in HTTPS (ports ${https_port} and ${http_port})"
  fi
  if [ -n "${TRANSLATION}" ]; then
    say "${TRANSLATION}"
    report "deployment form" "${form_db}; ${form_web}"
    say "                           now decided by EXTERNAL_DB_HOST and TLS_MODE only"
  else
    report "deployment form" "${form_db}; ${form_web}"
    say "                           from EXTERNAL_DB_HOST (${db_now:-empty}), TLS_MODE (${tls_now})"
    if [ -n "${FORM_BLOCK}" ]; then
      report COMPOSE_PROFILES "written to the managed block at the end of ${ENV_FILE}:"
      say "                           COMPOSE_PROFILES=${PROFILES}"
    else
      report COMPOSE_PROFILES "${PROFILES} (in the managed block, left as is)"
    fi
  fi
fi

# ---------- login target ----------
CA_URL=""
if [ "${DEV}" = 1 ]; then
  APP_URL="http://localhost:3000"
elif [ "${OWN_INGRESS}" = 1 ]; then
  APP_URL="http://localhost:${own_port}/"
else
  APP_URL="${PUBLIC_URL}/"
  [ "$(current TLS_MODE)" = "provided" ] || CA_URL="${PUBLIC_URL}/custodexa-ca.crt"
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

# ---------- recordings directory ----------
# guacd writes graphical recordings into ${DATA_PATH}/recordings as uid 1000 with no
# capabilities; the backend renames, plays back and expires them as uid 0 without the
# capabilities that bypass file permissions. So the directory is owner 1000 (guacd), group 0
# (the backend), mode 2770. The setgid bit makes each new file inherit group 0, which is how
# the backend reads a file guacd created with mode 0640.
#
# A throwaway container does the work as root, so the result is the same whether a docker
# group member or sudo runs this script. It uses the image of the tls-init service in
# docker-compose.yml; the built-in HTTPS form pulls that image anyway, while with your own
# reverse proxy tls-init does not run and this is one extra image to pull. Safe to repeat:
# files guacd left in group 1000 move to group 0, and the directory change takes effect on a
# running stack without restarting it.
RECORDINGS_PREP_IMAGE=alpine/openssl:3.5.4
prepare_recordings_dir() {
  local dir
  case "${data_path}" in
    /*) dir="${data_path}/recordings" ;;
    *)  dir="${PWD}/${data_path#./}/recordings" ;;
  esac
  docker run --rm --network none -v "${dir}:/r" --entrypoint /bin/sh "${RECORDINGS_PREP_IMAGE}" -c \
    'chown 1000:0 /r && chmod 2770 /r && find /r -mindepth 1 -maxdepth 1 -type f -group 1000 -exec chgrp 0 {} + && stat -c "%u:%g %a" /r'
}

# published_by_this_stack succeeds when this stack's container for service $1 is running and
# publishes its container port $2 on host port $3. Re-running the script on a deployment that is
# up finds the stack's own proxy on the public ports; that is not a conflict. The answer comes
# from the container (docker-compose.yml fixes the container names), not from the listener's
# process name: every published container port shows up as docker-proxy, whichever project it
# belongs to. The container, not the compose service: a deployment started by the 1.22 files
# publishes the port from the same frontend container that is the service frontend-published now.
published_by_this_stack() {
  local service="$1" target="$2" port="$3" bound
  bound=$(docker port "custodexa-${service}" "${target}" 2>/dev/null) || return 1
  printf '%s\n' "${bound}" | grep -q ":${port}\$"
}

PORTS_UNCHECKED=0
require_port_free() {
  local port="$1" label="$2" service="$3" target="$4" who holders
  if ! who=$(port_listener "${port}"); then
    PORTS_UNCHECKED=1
    return 0
  fi
  [ -z "${who}" ] && return 0
  if published_by_this_stack "${service}" "${target}" "${port}"; then
    report "port ${port}" "held by this stack's own ${service} service, left as is"
    return 0
  fi
  # docker-proxy on its own does not say whose port it is; name the container as well.
  case "${who}" in
    *docker-proxy*)
      holders=$(docker ps --filter "publish=${port}" --format '{{.Names}}' 2>/dev/null | paste -sd, -)
      [ -n "${holders}" ] && who="${who}, publishing it for container ${holders}"
      ;;
  esac
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
  # The profiles derived above reach every docker compose call below through the environment
  # (the managed block of .env says the same; the environment wins if the two ever differ).
  if [ "${DEV}" = 0 ]; then export COMPOSE_PROFILES="${PROFILES}"; fi
  if [ "${DEV}" = 1 ]; then
    :
  elif [ "${OWN_INGRESS}" = 1 ]; then
    require_port_free "${own_port}" "http, published by the frontend" frontend 80
  else
    require_port_free "${https_port}" "https" tls-proxy 443
    require_port_free "${http_port}" "http, redirected to https" tls-proxy 80
  fi
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
  if [ "${DEV}" = 0 ]; then
    perms=$(prepare_recordings_dir) || fail "could not prepare ${data_path}/recordings (the docker error is shown above)"
    report "recordings directory" "${data_path}/recordings is ${perms} (uid:gid mode)"
  fi
  if [ "${DEV}" = 1 ]; then
    # The development stack mounts single files under the backend source directory. When the
    # host-side path is missing, Docker has to create it while setting up the mount, which can
    # fail on the first start. Create the paths first; an existing file is left untouched.
    mkdir -p backend/config/testdata backend/cmd/server/testdata/release
    for placeholder in backend/config/testdata/.env.example \
      backend/cmd/server/testdata/release/VERSION \
      backend/cmd/server/testdata/release/CHANGELOG.md; do
      [ -e "${placeholder}" ] || : >"${placeholder}"
    done
  fi
  if [ "${DEV}" = 0 ]; then
    # Both frontend services share one container name. A deployment started with the 1.22 files
    # (or in the other web form) holds that name under the other service, and compose would stop at
    # the name conflict. The frontend keeps no data, so the old container is replaced.
    want_front=frontend
    [ "${OWN_INGRESS}" = 0 ] || want_front=frontend-published
    have_front=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' custodexa-frontend 2>/dev/null || true)
    if [ -n "${have_front}" ] && [ "${have_front}" != "${want_front}" ]; then
      docker rm -f custodexa-frontend >/dev/null
      report "frontend container" "replaced (it ran as service ${have_front}; this form runs ${want_front})"
    fi
  fi
  docker compose up -d
  say ""
  health_timeout=${HEALTH_TIMEOUT}
  if [ "${DEV}" = 1 ]; then
    # The first start of the development stack downloads Go modules and compiles the backend
    # inside the container (about 13-14 minutes measured), so it needs a much longer wait.
    health_timeout=${DEV_HEALTH_TIMEOUT}
  fi
  say "[4/${TOTAL}] Waiting for the backend to become healthy (up to ${health_timeout}s)"
  if [ "${DEV}" = 1 ]; then
    say "The first start of the development stack downloads modules and compiles the backend inside the container,"
    say "which can take 10 to 15 minutes. Later starts are much faster."
  fi
  waited=0
  until docker compose exec -T backend wget -qO- http://localhost:8080/health >/dev/null 2>&1; do
    waited=$((waited + 3))
    if [ "${waited}" -ge "${health_timeout}" ]; then
      say ""
      say "The backend did not report healthy within ${health_timeout}s."
      say "Inspect the logs: docker compose logs backend"
      say "(a refused start always states which variable was rejected and why)"
      exit 1
    fi
    sleep 3
    if [ $((waited % 60)) -eq 0 ]; then
      say "  still waiting... ${waited}s elapsed"
    fi
  done
  say ""
  say "Backend is healthy."
  print_login_info
else
  say ""
  say "Preparation complete. Next:"
  if [ "${DEV}" = 1 ]; then
    say "    docker compose up -d     # first run builds the images (5-10 minutes)"
  else
    say "    bash scripts/quickstart.sh --up   # builds the images (5-10 minutes), prepares the"
    say "                                      # recordings directory and starts the services"
  fi
  print_login_info
fi
