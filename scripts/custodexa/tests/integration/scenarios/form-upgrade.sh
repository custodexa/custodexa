# shellcheck shell=bash
# about: a deployment installed from the published release in each form (host builtin: built-in database and proxy, extdb: external database, ingress: external ingress, both: external database and ingress) is upgraded to the working tree's version offline: the containers by name are the same, the front end's published port and compose service are what the form says, a record written before is readable after and again after the way back, .env keeps no COMPOSE_FILE outside the managed block; the external forms keep the server's identity and create no built-in data; the two ingress forms go on to rollback with an injected failure after the old version started, then rollback --revert, then a complete rollback (host e2: the built-in deployment with an address added to .env is refused at step 1 before any service stops)
# hosts: builtin extdb ingress both e2
# free-hosts: yes
# needs: package local-versions published
# images: pg17
#
# Run with CX_IT_LOCAL_VERSIONS=1.23.90 CX_IT_PUBLISHED_VERSION=1.22.0.

readonly FUP_NEW=${CX_IT_LOCAL_VERSIONS:-1.23.90}

# fup_up <form>: the whole of one form.
fup_up() {
  local form=$1 names ident want_label want_port
  fu_install "$form"
  fu_sentinel 1
  it_same "$form: one sentinel before the upgrade" "1 it-sentinel-1" "$(fu_sentinels)"
  names=$(fu_names)
  ident=""
  ! fu_ext || ident=$(fu_identity)
  it_say "   before: $names ${ident:+| $ident}"
  it_step "$form: upgrade $FU_OLD -> $FUP_NEW"
  lv_upgrade "$FUP_NEW"
  lv_wait_version "$FUP_NEW"
  LV_TOKEN=""
  it_same "$form: the running containers by name are the same" "$names" "$(fu_names)"
  want_label=frontend
  want_port=""
  if fu_ing; then
    want_label=frontend-published
    want_port=$(lv_env_get HTTP_PORT)
    want_port=${want_port:-80} # HTTP_PORT unset in .env: the compose default
  fi
  it_same "$form: custodexa-frontend is the compose service ${want_label}" "$want_label" "$(fu_label)"
  if [ -z "$want_port" ]; then
    it_same "$form: docker port custodexa-frontend prints nothing" "" "$(fu_port)"
  else
    it_check "$form: docker port custodexa-frontend publishes ${want_port:-80}" grep -q ":${want_port:-80}\b" <<<"$(fu_port)"
  fi
  it_check "$form: no COMPOSE_FILE or COMPOSE_PROFILES outside the managed block" fu_no_overlay_lines
  if fu_ing; then it_same "$form: TLS_MODE is external after the upgrade" external "$(lv_env_get TLS_MODE)"; fi
  it_same "$form: the sentinel is readable after the upgrade" "1 it-sentinel-1" "$(fu_sentinels)"
  fu_sentinel 2
  it_same "$form: a second record is written" "2 it-sentinel-1,it-sentinel-2" "$(fu_sentinels)"
  if fu_ext; then
    it_same "$form: the server's identity (system_identifier, database, version) is the same" "$ident" "$(fu_identity)"
    it_check "$form: no built-in database container and no built-in data folder" \
      bash -c '! docker container inspect custodexa-postgres >/dev/null 2>&1 && [ ! -e "$1/data/postgres" ] && [ ! -e "$1/data/postgresql" ]' _ "$LV_ROOT"
  else
    it_same "$form: backend DB_HOST is postgres" postgres "$(docker exec custodexa-backend printenv DB_HOST)"
  fi
  lv_cx status status
  it_same "$form: status reports no failure" 0 "$(grep -c '\[FAIL\]' <<<"$LV_OUT" || true)"
  it_check "$form: status shows the form" grep -q 'Deployment form' <<<"$LV_OUT"
}

# fup_back <form>: the way back to the published release.
fup_back() {
  local form=$1 ps_names
  if fu_ing; then
    it_step "$form: rollback fails after the old version started (injected), then --revert"
    LV_INJECT=health-fail LV_READY_TRIES=2 lv_cx rollback rollback --yes
    it_check "$form: the injected rollback did not succeed (exit $LV_RC)" test "$LV_RC" != 0
    it_same "$form: the record is a rollback that is not finished" "in_progress rollback" \
      "$(lv_st last_rollback.result) $(lv_st last_rollback.direction)"
    it_same "$form: custodexa-frontend is the compose service of the old layout" frontend "$(fu_label)"
    # After the way back, custodexa.sh is the old release'"'"'s script, which knows nothing of the layout
    # of the release it would return to: the revert runs from that release'"'"'s own folder.
    LV_SCRIPT="$LV_ROOT/releases/$FUP_NEW/custodexa.sh" lv_cx revert rollback --revert --yes
    it_same "$form: rollback --revert exits 0" 0 "$LV_RC"
    lv_wait_version "$FUP_NEW"
    it_same "$form: after --revert custodexa-frontend is frontend-published" frontend-published "$(fu_label)"
    LV_TOKEN=""
  fi
  it_step "$form: rollback to $FU_OLD"
  lv_cx rollback rollback --yes
  it_same "$form: rollback exits 0" 0 "$LV_RC"
  lv_wait_version "$FU_OLD"
  LV_TOKEN=""
  ps_names=$(fu_names)
  it_check "$form: the managed block is the overlay notation of $FU_OLD" \
    grep -q '^COMPOSE_FILE=current/compose.yml' <<<"$(fu_block)"
  it_check "$form: the block has no COMPOSE_PROFILES" bash -c '! grep -q COMPOSE_PROFILES <<<"$1"' _ "$(fu_block)"
  it_check "$form: docker compose ps (typed in the deployment folder) lists the running containers" \
    bash -c 'cd "$1" && docker compose ps --format "{{.Name}}" | sort | paste -sd" " | grep -q custodexa-backend' _ "$LV_ROOT"
  it_same "$form: the sentinels are readable after the way back" "2 it-sentinel-1,it-sentinel-2" "$(fu_sentinels)"
  fu_sentinel 3
  it_same "$form: a record is written after the way back" "3 it-sentinel-1,it-sentinel-2,it-sentinel-3" "$(fu_sentinels)"
  it_same "$form: the containers by name after the way back" "$ps_names" "$(fu_names)"
}

scenario_builtin() { fup_up builtin; }

scenario_extdb() {
  fup_up extdb
  fup_back extdb
}

scenario_ingress() {
  fup_up ingress
  fup_back ingress
}

scenario_both() {
  fup_up both
  fup_back both
}

# E2: the built-in deployment, an address added to .env afterwards. The upgrade is refused at
# step 1: exit 3, no service stops, .env and state.json as they were.
scenario_e2() {
  local ps0 st0
  fu_install builtin
  fu_sentinel 1
  printf 'EXTERNAL_DB_HOST=db.example.internal\n' >>"$LV_ROOT/.env"
  ps0=$(lv_ps)
  st0=$(cd "$LV_ROOT" && sha256sum .env state.json)
  lv_upgrade "$FUP_NEW" 3
  it_check "e2: the screen says the data is in the built-in database" grep -qi 'built-in' <<<"$LV_OUT"
  it_same "e2: the same containers run" "$ps0" "$(lv_ps)"
  it_same "e2: .env and state.json are unchanged" "$st0" "$(cd "$LV_ROOT" && sha256sum .env state.json)"
  it_same "e2: the old version still answers" "$FU_OLD" "$(lv_version)"
  it_same "e2: the sentinel is still there" "1 it-sentinel-1" "$(fu_sentinels)"
}
