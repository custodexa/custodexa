# shellcheck shell=bash
# Run log: logs/<command>-<YYYYmmdd-HHMMSS>.log, one event per line,
#   2026-09-30T02:15:04+08:00 BEGIN install lang=zh-TW script=releases/1.13.0/custodexa.sh flags=""
# English machine fields, the user's language only inside messages, so support can grep.
#
# .env values never reach the log or state.json. The code writes .env keys by name only; as a
# safety net every .env value is replaced by <KEY> before a line is written, and cx_state_set
# refuses a value that contains one. Masking is the default: only the keys listed below, which hold
# paths, ports, host names, modes and switches, stay readable. A key that is not listed, including
# one added to .env later, is treated as a secret; forgetting a key costs readability, never a leak.

CX_LOG_FILE=""
declare -gA CX_SECRETS=()

# .env keys whose values are not secrets and may appear in the log and in state.json. Reviewed one by
# one; add a key here only when its value can never be a password, key, token or credential.
readonly CX_ENV_SHOWN="DATA_PATH COMPOSE_FILE COMPOSE_PROJECT_NAME
  TLS_HTTPS_PORT TLS_HTTP_PORT HTTP_PORT EXTERNAL_DB_PORT
  TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL TRUSTED_PROXIES DOCKER_SUBNET EXTERNAL_DB_HOST
  TLS_MODE KEK_PROVIDER DB_NAME DB_USER DB_SSLMODE
  FEATURE_AUDIT_LOG_ENABLED FEATURE_ASYNC_AUDIT_ENABLED FEATURE_AUDIT_FALLBACK_TO_FILE
  FEATURE_ANOMALY_DETECTION_ENABLED FEATURE_ALERTING_ENABLED AUTH_REFRESH_COOKIE_SECURE
  LDAP_ENABLED LDAP_SKIP_TLS_VERIFY SSH_IDLE_TIMEOUT_MINUTES SSH_MAX_SESSION_MINUTES
  RECORDING_RETENTION_DAYS"

# cx_env_value_shown <key>: true only for the keys listed above.
cx_env_value_shown() {
  local k
  for k in $CX_ENV_SHOWN; do
    [ "$k" = "$1" ] && return 0
  done
  return 1
}

# cx_secret_add <key> <value>: a secret created during the run (before .env holds it).
# Values shorter than 4 characters are not masked: they cannot be meaningful secrets and would
# garble every line that happens to contain them.
cx_secret_add() {
  [ "${#2}" -ge 4 ] || return 0
  CX_SECRETS[$2]=$1
}

# cx_secrets_from_env <file>: collect the values to mask from an .env file: every value except those
# of the keys listed in CX_ENV_SHOWN. Parsed, never sourced.
cx_secrets_from_env() {
  local line key val
  [ -f "$1" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line#export }
    [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
    val=${val%$'\r'}
    if [[ $val =~ ^\"(.*)\"$ || $val =~ ^\'(.*)\'$ ]]; then
      val=${BASH_REMATCH[1]}
    fi
    cx_env_value_shown "$key" || cx_secret_add "$key" "$val"
  done <"$1"
  return 0
}

# cx_mask <text>: the text with every known secret replaced by <KEY>.
cx_mask() {
  local text=$1 v
  for v in "${!CX_SECRETS[@]}"; do
    text=${text//"$v"/"<${CX_SECRETS[$v]}>"}
  done
  printf '%s' "$text"
}

# cx_has_secret <text>: true when the text contains a known secret of 8 characters or more
# (shorter ones could match inside a digest by chance).
cx_has_secret() {
  local v
  for v in "${!CX_SECRETS[@]}"; do
    [ "${#v}" -ge 8 ] && [[ $1 == *"$v"* ]] && return 0
  done
  return 1
}

cx_log_now() { date '+%Y-%m-%dT%H:%M:%S%:z'; }

# cx_log_open <command>: start this run's log file; prints nothing. The folder is private (0700).
cx_log_open() {
  local dir="$CX_ROOT/logs"
  (umask 077 && mkdir -p "$dir") || return 1
  CX_LOG_FILE="$dir/$1-$(date '+%Y%m%d-%H%M%S').log"
  (umask 077 && : >>"$CX_LOG_FILE")
}

# cx_log <EVENT> <text...>: append one line; a no-op until cx_log_open.
cx_log() {
  [ -n "$CX_LOG_FILE" ] || return 0
  local ev=$1 text
  shift
  text=$(cx_mask "$*")
  printf '%s %-5s %s\n' "$(cx_log_now)" "$ev" "${text//$'\n'/ }" >>"$CX_LOG_FILE"
}

# cx_log_run <command...>: log the command (CMD) and each output line (OUT, stderr included),
# pass the output through, and return the command's exit status.
cx_log_run() {
  local line
  local -a ps=(1)
  cx_log CMD "$*"
  {
    "$@" 2>&1 | while IFS= read -r line || [ -n "$line" ]; do
      printf '%s\n' "$line"
      cx_log OUT "$line"
    done
    ps=("${PIPESTATUS[@]}")
  } || true
  return "${ps[0]}"
}
