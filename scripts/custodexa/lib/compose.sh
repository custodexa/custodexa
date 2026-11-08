# shellcheck shell=bash
# The only place that runs `docker compose`. Every call names the project, the project
# directory and each compose file explicitly, so compose never picks a file or a project name from
# the current directory. The test suite fails if any other file calls docker compose.

# cx_images_env_export <file>: export CUSTODEXA_IMAGE_<NAME>=<reference> lines. The file is parsed,
# not sourced: a line that is not exactly that shape stops the run.
cx_images_env_export() {
  local file=$1 line n=0 bad=0
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ -z "$line" ] && continue
    if [[ $line =~ ^(CUSTODEXA_IMAGE_[A-Z0-9_]+)=([A-Za-z0-9._/:@-]+)$ ]]; then
      export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
    else
      bad=$n
      break
    fi
  done <"$file"
  if [ "$bad" -ne 0 ]; then
    cx_line FAIL "$(cx_msg images_env_bad_line "$file" "$bad")" >&2
    return 1
  fi
}

# cx_compose_version: the Compose version (for the host checks; no project involved).
cx_compose_version() { docker compose version --short 2>/dev/null; }

# cx_compose_setup <release dir>: the arguments of a call on that release. CX_CMP_ARGS is
# the -f list, CX_CMP_PROFILES the profiles of a release with the profiles layout (empty for an
# older release, which has overlay files instead), CX_CMP_LAYOUT the layout. An unknown form word
# is refused here, before compose is called.
cx_compose_setup() {
  local release=$1 ov
  CX_CMP_LAYOUT=$(cx_form_layout "$release")
  CX_CMP_ARGS=(-f "$release/compose.yml")
  CX_CMP_PROFILES=""
  for ov in ${CX_OVERLAYS:-}; do
    case " $CX_OVERLAY_NAMES " in
      *" $ov "*) ;;
      *)
        cx_line FAIL "$(cx_msg overlay_unknown "$ov")" >&2
        return 1
        ;;
    esac
    [ "$CX_CMP_LAYOUT" != overlays ] || CX_CMP_ARGS+=(-f "$release/compose.$ov.yml")
  done
  if [ "$CX_CMP_LAYOUT" = profiles ]; then
    CX_CMP_PROFILES=$(cx_form_profiles "${CX_OVERLAYS:-}")
  fi
}

# cx_compose_files: print the -f arguments for the current release, one per line.
cx_compose_files() {
  cx_compose_files_for "$CX_ROOT/current"
}

cx_compose_files_for() {
  cx_compose_setup "$1" || return 1
  printf '%s\n' "${CX_CMP_ARGS[@]}"
}

# cx_compose_env_names <compose file>...: the variables the files interpolate (${NAME...}).
cx_compose_env_names() {
  # shellcheck disable=SC2016 # a literal ${ in the pattern
  grep -ho '\${[A-Za-z_][A-Za-z0-9_]*' "$@" 2>/dev/null | sed 's/^..//' | sort -u
}

# cx_compose_handoff <layout> <form words>: before `up`, a stopped custodexa-frontend left by a
# release whose web service has another name is removed, or compose would refuse the new service
# with the same container name. A running one is never removed.
cx_compose_handoff() {
  local info running label want
  want=$(cx_form_services "$1" "$2")
  info=$(docker inspect --format '{{.State.Running}} {{index .Config.Labels "com.docker.compose.service"}}' custodexa-frontend 2>/dev/null) || return 0
  [ -n "$info" ] || return 0
  running=${info%% *}
  label=${info#* }
  [ "$label" != "$want" ] || return 0
  if [ "$running" = true ]; then
    cx_line FAIL "$(cx_msg compose_frontend_running)" >&2
    return 1
  fi
  cx_log CMD "docker rm custodexa-frontend (service $label, wanted $want)"
  docker rm custodexa-frontend >/dev/null
}

# cx_compose_run <release dir> <images.env> <build source or ""> <env file> <compose arguments...>:
# one call, in a controlled environment: the variables the compose files interpolate and
# COMPOSE_FILE are removed first, so compose reads them from the deployment's .env only (the file
# the form was derived from); then the script's own values are set.
cx_compose_run() {
  local release=$1 images=$2 build=$3
  shift 3
  cx_compose_setup "$release" || return 1
  local -a env_args=()
  # Only a call on a named release (it has a build source) may take another env file.
  [ -z "$build" ] || [ -z "${CX_COMPOSE_ENV:-}" ] || env_args=(--env-file "$CX_COMPOSE_ENV")
  (
    local -a names=()
    mapfile -t names < <(cx_compose_env_names "$release"/compose*.yml)
    unset COMPOSE_FILE COMPOSE_PROFILES "${names[@]}"
    [ -z "$CX_CMP_PROFILES" ] || export COMPOSE_PROFILES=$CX_CMP_PROFILES
    cx_images_env_export "$images" || exit 1
    [ -z "$build" ] || export CUSTODEXA_BUILD_SOURCE=$build
    if [ "${1:-}" = up ]; then
      cx_compose_handoff "$CX_CMP_LAYOUT" "${CX_OVERLAYS:-}" || exit 1
    fi
    cx_log CMD "docker compose -p $CX_PROJECT --project-directory $CX_ROOT ${CX_CMP_ARGS[*]} ${CX_CMP_PROFILES:+[profiles $CX_CMP_PROFILES] }$*"
    docker compose -p "$CX_PROJECT" --project-directory "$CX_ROOT" ${env_args[@]+"${env_args[@]}"} "${CX_CMP_ARGS[@]}" "$@"
  )
}

# cx_compose <compose arguments...>: run compose on this deployment.
cx_compose() {
  [ -n "${CX_ROOT:-}" ] || { cx_line FAIL "cx_compose: CX_ROOT unset" >&2; return 1; }
  cx_compose_run "$CX_ROOT/current" "$CX_ROOT/current/images.env" "" "$@"
}

# cx_compose_release <release dir> <compose arguments...>: build from a verified target release.
# CUSTODEXA_BUILD_SOURCE overrides the compose build context so an upgrade never reads current/source.
cx_compose_release() {
  local release=$1
  shift
  if [ -z "${CX_ROOT:-}" ] || [ ! -f "$release/compose.yml" ]; then
    cx_line FAIL "cx_compose_release: release compose unavailable" >&2
    return 1
  fi
  cx_compose_run "$release" "$release/images.env" "$release/source" "$@"
}
