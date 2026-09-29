# shellcheck shell=bash
# CX_OVERLAYS is read by lib/compose.sh.
# shellcheck disable=SC2034
# custodexa.sh install: the first install of a package deployment, in seven steps:
#   1 check this host (nothing is written before these checks pass)
#   2 create or complete .env (lib/env.sh)
#   3 get the images and check them (lib/images.sh, lib/trust.sh)
#   4 prepare the recordings folder (owner 1000, group 0, mode 2770)
#   5 start the services, then compare each running container's image ID with the one recorded
#   6 wait until the backend reports healthy with this release's version
#   7 record the deployment in state.json and print how to finish the setup in the browser
# A failure stops the run and keeps what was done: running install again repeats every step, and
# each step leaves alone what is already in place (.env values, images present, running services).

readonly CX_INSTALL_STEPS=7
readonly CX_HEALTH_TRIES=60 CX_HEALTH_WAIT=3 # up to 180 seconds
readonly CX_RULE='=========================================================='

cmd_install_elapsed() { cx_duration $(($(cx_now) - $1)); }

# cmd_install_note <text>: lines under a step, 7 columns in, no mark.
cmd_install_note() { printf '%s\n' "$1" | sed 's/^/       /'; }

# cmd_install_stop <step> <step message id> [file with the lines to show under the step]:
# the FAIL step line, what went wrong, how to go on; the run is recorded as failed.
cmd_install_stop() {
  local n=$1 id=$2 detail=${3:-}
  cx_step_line FAIL "$n/$CX_INSTALL_STEPS" "$(cx_msg "$id")"
  if [ -n "$detail" ]; then
    cat "$detail"
    rm -f "$detail"
  fi
  printf '\n%s\n' "$(cx_msg install_stopped "$n")"
  cx_cmd "sudo $CX_ROOT/custodexa.sh install"
  printf '%s\n' "$(cx_msg install_log "$CX_LOG_FILE")"
  cx_finish failed
  exit "$CX_EXIT_FAILED"
}

# The generated values, in words: "Sign-in signing key, database password and initial admin
# password generated", wrapped like the other lines under the step.
cmd_install_generated() {
  local k i out
  local -a items=()
  for k in jwt kek db admin; do
    [[ " $CX_ENV_GENERATED " == *" $k "* ]] && items+=("$(cx_msg "env_item_$k")")
  done
  if [ "${#items[@]}" -eq 0 ]; then
    cx_msg env_generated_none
    return 0
  fi
  out=${items[0]}
  for ((i = 1; i < ${#items[@]}; i++)); do
    if [ "$i" -eq $((${#items[@]} - 1)) ]; then
      out+=$(cx_msg env_item_last)${items[i]}
    else
      out+=$(cx_msg env_item_sep)${items[i]}
    fi
  done
  out=$(cx_msg env_generated "$out")
  cx_wrap "$CX_WRAP" "${out^}"
}

# Step 4. The folder is prepared by a throw-away container running as root, so the result is the
# same whether sudo or a docker group member runs the script: guacd writes recordings as uid 1000,
# the backend reads them as group 0, and the setgid bit gives new files group 0. The image is the
# one tls-init runs (already obtained), or guacd's when this deployment has no built-in proxy.
cmd_install_recordings() {
  local dir img out
  dir=$(cx_env_get "$CX_ROOT/.env" DATA_PATH)/recordings
  img=${CX_IMG_REF[openssl]:-${CX_IMG_REF[guacd]:-}}
  mkdir -p "$dir" || return 1
  # shellcheck disable=SC2016 # the script runs inside the container
  out=$(cx_log_run docker run --rm --pull never --network none --user 0:0 -v "$dir:/r" \
    --entrypoint /bin/sh "$img" -c \
    'chown 1000:0 /r && chmod 2770 /r && find /r -mindepth 1 -maxdepth 1 -type f -group 1000 -exec chgrp 0 {} + && stat -c "%u:%g %a" /r') || {
    cx_sub FAIL "$(cx_msg install_recordings_failed "$dir")"
    return 1
  }
  out=$(printf '%s\n' "$out" | tail -n1)
  if [ "$out" != "$CX_RECORDINGS_MODE" ]; then
    cx_sub FAIL "$(cx_msg install_recordings_mode "$dir" "$out" "$CX_RECORDINGS_MODE")"
    return 1
  fi
}

# Step 6: /health inside the backend container, every 3 seconds for up to 180 seconds; the
# version it reports must be this release's.
CX_INSTALL_HEALTH_VERSION=""
cmd_install_wait_ready() {
  local tries=0 health
  while :; do
    if health=$(cx_compose exec -T backend wget -qO- http://localhost:8080/health 2>/dev/null); then
      break
    fi
    tries=$((tries + 1))
    if [ "$tries" -ge "$CX_HEALTH_TRIES" ]; then
      cx_sub FAIL "$(cx_msg install_not_ready $((CX_HEALTH_TRIES * CX_HEALTH_WAIT)))"
      printf '%s\n' "$(cx_msg install_not_ready_hint)"
      cx_cmd "cd $CX_ROOT && sudo docker compose logs backend"
      return 1
    fi
    sleep "$CX_HEALTH_WAIT"
  done
  CX_INSTALL_HEALTH_VERSION=""
  [[ $health =~ \"version\":\ ?\"([^\"]*)\" ]] && CX_INSTALL_HEALTH_VERSION=${BASH_REMATCH[1]}
  cx_log CHECK "health version=${CX_INSTALL_HEALTH_VERSION:-none}"
  if [ "$CX_INSTALL_HEALTH_VERSION" != "$(cx_mf version)" ]; then
    cx_sub FAIL "$(cx_msg install_version_bad "${CX_INSTALL_HEALTH_VERSION:-?}" "$(cx_mf version)")"
    return 1
  fi
}

# Step 7: what this deployment is, for status, upgrade and rollback.
cmd_install_record() {
  local ver n src=""
  ver=$(cx_mf version)
  for n in "${CX_IMG_NAMES[@]}"; do src+="${src:+ }$n=${CX_IMG_SRC[$n]:-?}"; done
  cx_state_set home "$CX_ROOT"
  cx_state_set compose_project "$CX_PROJECT"
  cx_state_set current.version "$ver"
  cx_state_set current.kind package
  cx_state_set current.since "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  cx_state_set current.release_dir "releases/$ver"
  cx_state_set current.overlays "$CX_ENV_OVERLAYS"
  cx_state_set current.images_env "releases/$ver/images.env"
  cx_state_set current.image_ids "$(cx_images_ids_text)"
  cx_state_set current.image_source "$src"
  cx_state_set current.verification "$(cx_trust_state)"
}

# The closing block: where to go, the account, and the first steps for this master key mode.
cmd_install_guide() {
  local url=${CX_ENV_URL%/}/ env=$CX_ROOT/.env n=0 p
  local -a points=()
  case $CX_ENV_KEK in
    ui) points=(done_ui_1 done_ui_2) ;;
    kms | hsm) points=(done_kms_1 done_login) ;;
    *) points=(done_login) ;;
  esac
  if [[ " $CX_ENV_OVERLAYS " != *" external-ingress "* ]] && [ "$(cx_env_get "$env" TLS_MODE)" != provided ]; then
    points+=(done_cert)
  fi
  printf '\n%s\n' "$CX_RULE"
  if [ "$CX_ENV_KEK" = env ]; then
    printf ' %s\n\n' "$(cx_msg done_title_login)"
  else
    printf ' %s\n\n' "$(cx_msg done_title_setup)"
  fi
  printf '   %s\n' "$(cx_msg done_address "$url")" "$(cx_msg done_account)"
  if [ -n "$CX_ENV_ADMIN_PASSWORD" ]; then
    printf '   %s\n' "$(cx_msg done_password "$CX_ENV_ADMIN_PASSWORD")" "$(cx_msg done_password_where "$env")"
  else
    printf '   %s\n' "$(cx_msg done_password_kept "$env")"
  fi
  printf '\n'
  for p in "${points[@]}"; do
    n=$((n + 1))
    if [ "$p" = done_cert ]; then
      printf ' %s. %s\n' "$n" "$(cx_msg "$p" "${url}custodexa-ca.crt" | sed '2,$s/^/    /')"
    else
      printf ' %s. %s\n' "$n" "$(cx_msg "$p" | sed '2,$s/^/    /')"
    fi
  done
  printf '\n %s\n' "$(cx_msg done_status "sudo $CX_ROOT/custodexa.sh status")"
  printf ' %s\n' "$(cx_msg done_log "$CX_LOG_FILE")"
  printf '%s\n' "$CX_RULE"
}

cmd_install() {
  local root=$CX_ROOT t0 i tmp
  [ $# -eq 0 ] || cx_die "$CX_EXIT_USAGE" usage_extra_args "$1"
  cx_manifest_load "$root/current/MANIFEST.json" || exit "$CX_EXIT_FAILED"
  cx_state_load "$root/state.json"
  printf '%s\n\n' "$(cx_msg install_title "$(cx_mf version)" "$root")"

  # 1: the host. A failure here has written nothing: no log, no lock, no state.
  t0=$(cx_now)
  cx_preflight "$root"
  if [ "$CX_PRE_EXIT" -ne 0 ]; then
    cx_preflight_report "$root"
    exit "$CX_PRE_EXIT"
  fi
  cx_begin install
  cx_step 1 "$CX_INSTALL_STEPS" preflight
  for i in "${!CX_PRE_MARK[@]}"; do cx_log CHECK "${CX_PRE_MARK[i]} ${CX_PRE_TEXT[i]}"; done
  cx_step_line OK "1/$CX_INSTALL_STEPS" "$(cx_msg step_preflight)" "$(cmd_install_elapsed "$t0")"

  # 2: .env. Values already set are kept; new secrets are masked in the log from here on.
  cx_step 2 "$CX_INSTALL_STEPS" env
  tmp=$(mktemp)
  if ! cx_env_generate "$root" >"$tmp" 2>&1; then
    sed -i 's/^/       /' "$tmp"
    cmd_install_stop 2 step_env "$tmp"
  fi
  rm -f "$tmp"
  CX_OVERLAYS=$CX_ENV_OVERLAYS
  # Rebuilt, not added to: a template placeholder replaced in this step (DB_PASSWORD=postgres) is no
  # longer a secret, and kept it would match the image name "postgres" in the state at step 7.
  CX_SECRETS=()
  cx_secrets_from_env "$root/.env"
  cx_log ENV "generated=\"$CX_ENV_GENERATED\" kek_provider=$CX_ENV_KEK overlays=\"$CX_ENV_OVERLAYS\""
  [ -z "$CX_ENV_ADMIN_PASSWORD" ] || cx_log ENV "ADMIN_INITIAL_PASSWORD $(cx_msg log_initial_password)"
  cx_step_line OK "2/$CX_INSTALL_STEPS" "$(cx_msg step_env)"
  cmd_install_note "$(cmd_install_generated)"
  cmd_install_note "$(cx_msg "env_kek_$CX_ENV_KEK")"
  cmd_install_note "$(cx_msg env_url "$CX_ENV_URL")"

  # 3: images, then who published them.
  cx_step 3 "$CX_INSTALL_STEPS" images
  t0=$(cx_now)
  cx_step_line RUN "3/$CX_INSTALL_STEPS" "$(cx_msg step_images)"
  cx_images_resolve "$CX_ENV_OVERLAYS" || cmd_install_stop 3 step_images
  cx_images_write_env "$root/current/images.env"
  cx_images_write_ids "$root/current/image-ids.env"
  cx_trust_check
  if cx_trust_failed; then
    cmd_install_stop 3 step_images
  fi
  if ! cx_trust_screen; then
    printf '\n%s\n' "$(cx_msg install_declined)"
    cx_cmd "sudo $root/custodexa.sh install"
    cx_log VERIFY "declined at the confirmation"
    cx_finish cancelled
    exit "$CX_EXIT_REFUSED"
  fi
  cx_step_line OK "3/$CX_INSTALL_STEPS" \
    "$(cx_msg step_images_done "${#CX_IMG_NAMES[@]}" "$(cx_trust_summary)")" "$(cmd_install_elapsed "$t0")"

  # 4: recordings folder.
  cx_step 4 "$CX_INSTALL_STEPS" recordings
  tmp=$(mktemp)
  cmd_install_recordings >"$tmp" 2>&1 || cmd_install_stop 4 step_recordings "$tmp"
  rm -f "$tmp"
  cx_step_line OK "4/$CX_INSTALL_STEPS" "$(cx_msg step_recordings)"

  # 5: start, then the running containers must run exactly the images checked in step 3.
  cx_step 5 "$CX_INSTALL_STEPS" start
  t0=$(cx_now)
  tmp=$(mktemp)
  if ! cx_log_run cx_compose up -d --remove-orphans >/dev/null 2>&1; then
    cx_sub FAIL "$(cx_msg install_up_failed)" >"$tmp"
    cmd_install_stop 5 step_start "$tmp"
  fi
  cx_images_verify_running >"$tmp" 2>&1 || cmd_install_stop 5 step_start "$tmp"
  rm -f "$tmp"
  cx_step_line OK "5/$CX_INSTALL_STEPS" "$(cx_msg step_start)" "$(cmd_install_elapsed "$t0")"

  # 6: ready, with this release's version.
  cx_step 6 "$CX_INSTALL_STEPS" ready
  t0=$(cx_now)
  tmp=$(mktemp)
  cmd_install_wait_ready >"$tmp" 2>&1 || cmd_install_stop 6 step_ready_wait "$tmp"
  rm -f "$tmp"
  cx_step_line OK "6/$CX_INSTALL_STEPS" "$(cx_msg step_ready "$CX_INSTALL_HEALTH_VERSION")" "$(cmd_install_elapsed "$t0")"

  # 7: record and hand over.
  cx_step 7 "$CX_INSTALL_STEPS" "done"
  cmd_install_record
  cx_finish succeeded
  cx_step_line OK "7/$CX_INSTALL_STEPS" "$(cx_msg step_done)"
  cmd_install_guide
}
