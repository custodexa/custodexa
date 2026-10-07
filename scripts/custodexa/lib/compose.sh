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

# cx_compose_files: print the -f arguments for the current release and overlays, one per line.
cx_compose_files() {
  local ov
  printf '%s\n' "-f" "$CX_ROOT/current/compose.yml"
  for ov in ${CX_OVERLAYS:-}; do
    case " $CX_OVERLAY_NAMES " in
      *" $ov "*) printf '%s\n' "-f" "$CX_ROOT/current/compose.$ov.yml" ;;
      *)
        cx_line FAIL "$(cx_msg overlay_unknown "$ov")" >&2
        return 1
        ;;
    esac
  done
}

# cx_compose <compose arguments...>: run compose on this deployment.
cx_compose() {
  local files
  [ -n "${CX_ROOT:-}" ] || { cx_line FAIL "cx_compose: CX_ROOT unset" >&2; return 1; }
  files=$(cx_compose_files) || return 1
  local -a f
  mapfile -t f <<<"$files"
  (
    cx_images_env_export "$CX_ROOT/current/images.env" || exit 1
    cx_log CMD "docker compose -p $CX_PROJECT --project-directory $CX_ROOT ${f[*]} $*"
    docker compose -p "$CX_PROJECT" --project-directory "$CX_ROOT" "${f[@]}" "$@"
  )
}

# cx_compose_release <release dir> <compose arguments...>: build from a verified target release.
# CUSTODEXA_BUILD_SOURCE overrides the compose build context so an upgrade never reads current/source.
cx_compose_release() {
  local release=$1 files
  shift
  if [ -z "${CX_ROOT:-}" ] || [ ! -f "$release/compose.yml" ]; then
    cx_line FAIL "cx_compose_release: release compose unavailable" >&2
    return 1
  fi
  files=$(cx_compose_files_for "$release") || return 1
  local -a f
  mapfile -t f <<<"$files"
  (
    cx_images_env_export "$release/images.env" || exit 1
    export CUSTODEXA_BUILD_SOURCE="$release/source"
    cx_log CMD "docker compose -p $CX_PROJECT --project-directory $CX_ROOT ${f[*]} $*"
    local -a env_args=()
    [ -z "${CX_COMPOSE_ENV:-}" ] || env_args=(--env-file "$CX_COMPOSE_ENV")
    docker compose -p "$CX_PROJECT" --project-directory "$CX_ROOT" "${env_args[@]}" "${f[@]}" "$@"
  )
}

cx_compose_files_for() {
  local release=$1 ov
  printf '%s\n' '-f' "$release/compose.yml"
  for ov in ${CX_OVERLAYS:-}; do
    case " $CX_OVERLAY_NAMES " in
      *" $ov "*) printf '%s\n' '-f' "$release/compose.$ov.yml" ;;
      *) cx_line FAIL "$(cx_msg overlay_unknown "$ov")" >&2; return 1 ;;
    esac
  done
}
