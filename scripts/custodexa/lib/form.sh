# shellcheck shell=bash
# CX_FORM_* results are read by the callers.
# shellcheck disable=SC2034
# The deployment form of a package deployment, derived from two keys of .env:
#   EXTERNAL_DB_HOST has a value   -> external-database (your own PostgreSQL server)
#   TLS_MODE=external              -> external-ingress  (your own reverse proxy carries HTTPS)
# The words are the ones state.json and backup manifests have always recorded (CX_OVERLAY_NAMES),
# in that order. The form becomes compose profiles (lib/compose.sh) for a release whose MANIFEST
# says compose_layout "profiles"; older releases are a base file plus overlay files.

readonly CX_FORM_WEB_BUILTIN=frontend CX_FORM_WEB_OWN=frontend-published
CX_FORM_BAD=""    # the TLS_MODE value cx_form_derive refused
CX_FORM_REASON="" # why cx_form_check_host refused a value: service | loopback | syntax

cx_form_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# cx_form_db_host <env file>: EXTERNAL_DB_HOST without surrounding blanks.
cx_form_db_host() { cx_form_trim "$(cx_env_get "$1" EXTERNAL_DB_HOST)"; }
cx_form_tls_mode() { cx_form_trim "$(cx_env_get "$1" TLS_MODE)"; }

# cx_form_derive <env file>: print the form words. A TLS_MODE that is none of the three is refused
# (return 1, the value in CX_FORM_BAD). Reads the file only, never the environment.
cx_form_derive() {
  local f=$1 words=""
  CX_FORM_BAD=""
  case $(cx_form_tls_mode "$f") in
    "" | selfsigned | provided) ;;
    external) words=external-ingress ;;
    *)
      CX_FORM_BAD=$(cx_form_tls_mode "$f")
      return 1
      ;;
  esac
  [ -z "$(cx_form_db_host "$f")" ] || words+=${words:+ }external-database
  printf '%s' "$words"
}

# cx_form_check_host <value>: return 0 when it can name your own database server. Otherwise return
# 1 with CX_FORM_REASON: service (a name of this stack), loopback (the backend container itself),
# syntax (a port, a scheme, blanks or quotes in it).
cx_form_check_host() {
  local v=$1 l
  CX_FORM_REASON=""
  l=$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]') # not ${v,,}: scripts/quickstart.sh also runs on bash 3.2
  if [[ $v == *://* || $v =~ [[:space:]\"\'] ]] || [[ $v =~ ^[^:]+:[^:]*$ ]]; then
    CX_FORM_REASON=syntax
  elif [[ $l == localhost || $l =~ ^127\.[0-9]+\.[0-9]+\.[0-9]+$ || $l == ::1 || $l == 0.0.0.0 || $l == :: ]]; then
    CX_FORM_REASON=loopback
  else
    case $l in
      postgres | backend | frontend | frontend-published | guacd | tls-proxy | tls-init | custodexa-*) CX_FORM_REASON=service ;;
    esac
  fi
  [ -z "$CX_FORM_REASON" ]
}

# cx_form_profiles <form words>: the compose profiles of a form, comma separated.
cx_form_profiles() {
  local p=bundled-db
  [[ " $1 " != *" external-database "* ]] || p=""
  if [[ " $1 " == *" external-ingress "* ]]; then p+=${p:+,}own-ingress; else p+=${p:+,}builtin-tls; fi
  printf '%s' "$p"
}

# cx_form_layout <release dir>: profiles when its MANIFEST says so, overlays for every older one.
cx_form_layout() {
  if [ -f "$1/MANIFEST.json" ] && grep -Eq '"compose_layout": *"profiles"' "$1/MANIFEST.json"; then
    printf profiles
  else
    printf overlays
  fi
}

# cx_form_services <layout> <form words>: the name of the web service. Only a release with the
# profiles layout has a second one, for your own ingress.
cx_form_services() {
  if [ "$1" = profiles ] && [[ " $2 " == *" external-ingress "* ]]; then
    printf '%s' "$CX_FORM_WEB_OWN"
  else
    printf '%s' "$CX_FORM_WEB_BUILTIN"
  fi
}

# cx_form_app_services <layout> <form words>: the application services a backup stops and starts.
cx_form_app_services() { printf 'backend guacd %s' "$(cx_form_services "$1" "$2")"; }

# ---------- the managed block of .env ----------
readonly CX_FORM_MARK_BEGIN='# >>> managed by custodexa.sh: derived from EXTERNAL_DB_HOST and TLS_MODE; do not edit'
readonly CX_FORM_MARK_END='# <<< managed by custodexa.sh'
CX_FORM_MOVED="" # COMPOSE_FILE / COMPOSE_PROFILES lines moved into the block by cx_env_sync_managed

# cx_form_compose_file <layout> <form words>: the COMPOSE_FILE value of the block.
cx_form_compose_file() {
  local v=current/compose.yml ov
  if [ "$1" = overlays ]; then
    for ov in $CX_OVERLAY_NAMES; do
      [[ " $2 " != *" $ov "* ]] || v+=":current/compose.$ov.yml"
    done
  fi
  printf '%s' "$v"
}

# cx_form_managed_text <layout> <form words>: the block, with its markers.
cx_form_managed_text() {
  printf '%s\nCOMPOSE_FILE=%s\n' "$CX_FORM_MARK_BEGIN" "$(cx_form_compose_file "$1" "$2")"
  [ "$1" != profiles ] || printf 'COMPOSE_PROFILES=%s\n' "$(cx_form_profiles "$2")"
  printf '%s\n' "$CX_FORM_MARK_END"
}

# cx_form_managed_rewrite <env file> <layout> <form words>: print the file as it would be with the
# block in place: every line outside the block and outside COMPOSE_FILE / COMPOSE_PROFILES is
# unchanged; those lines (and an old block) are dropped and the block is appended.
cx_form_managed_rewrite() {
  awk -v b="$CX_FORM_MARK_BEGIN" -v e="$CX_FORM_MARK_END" '
    $0 == b { skip = 1; next }
    skip { if ($0 == e) skip = 0; next }
    /^[[:space:]]*COMPOSE_(FILE|PROFILES)=/ { next }
    { print }' "$1"
  cx_form_managed_text "$2" "$3"
}

# cx_form_managed_moved <env file>: COMPOSE_FILE / COMPOSE_PROFILES lines outside the block.
cx_form_managed_moved() {
  awk -v b="$CX_FORM_MARK_BEGIN" -v e="$CX_FORM_MARK_END" '
    $0 == b { skip = 1; next }
    skip { if ($0 == e) skip = 0; next }
    /^[[:space:]]*COMPOSE_(FILE|PROFILES)=/ { print }' "$1"
}

# cx_env_sync_managed <env file> <layout> <form words>: put the block in place, atomically, mode
# 600. Nothing is written when the file already has exactly that content. The lines moved into the
# block are in CX_FORM_MOVED.
cx_env_sync_managed() {
  local f=$1 tmp
  CX_FORM_MOVED=$(cx_form_managed_moved "$f")
  tmp=$(umask 077 && mktemp "$f.tmp-XXXXXX") || return 1
  if ! cx_form_managed_rewrite "$f" "$2" "$3" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if cmp -s "$tmp" "$f"; then
    rm -f "$tmp"
    return 0
  fi
  chmod 600 "$tmp" && mv -f "$tmp" "$f"
}
