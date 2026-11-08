# shellcheck shell=bash
# about: the compatibility end point of form-upgrade: a published 1.17.x release with an external database and an external ingress upgraded offline to the working tree's version, with the same sentinel and server-identity evidence as form-upgrade
# needs: package local-versions published
# images: pg17
#
# Run with CX_IT_LOCAL_VERSIONS=1.23.90 CX_IT_PUBLISHED_VERSION=1.17.9.

readonly FUP_NEW=${CX_IT_LOCAL_VERSIONS:-1.23.90}

scenario() {
  local names ident
  fu_install both
  it_check "the published release is a 1.17 one ($FU_OLD)" bash -c '[[ $1 == 1.17.* ]]' _ "$FU_OLD"
  fu_sentinel 1
  it_same "one sentinel before the upgrade" "1 it-sentinel-1" "$(fu_sentinels)"
  names=$(fu_names)
  ident=$(fu_identity)
  it_say "   before: $names | $ident"
  lv_upgrade "$FUP_NEW"
  lv_wait_version "$FUP_NEW"
  LV_TOKEN=""
  it_same "the running containers by name are the same" "$names" "$(fu_names)"
  it_same "custodexa-frontend is the compose service frontend-published" frontend-published "$(fu_label)"
  it_check "docker port custodexa-frontend publishes the HTTP port" grep -q ":$(lv_env_get HTTP_PORT | grep . || echo 80)\b" <<<"$(fu_port)"
  it_check "no COMPOSE_FILE or COMPOSE_PROFILES outside the managed block" fu_no_overlay_lines
  it_same "TLS_MODE is external after the upgrade" external "$(lv_env_get TLS_MODE)"
  it_same "the sentinel is readable after the upgrade" "1 it-sentinel-1" "$(fu_sentinels)"
  fu_sentinel 2
  it_same "a second record is written" "2 it-sentinel-1,it-sentinel-2" "$(fu_sentinels)"
  it_same "the server's identity is the same" "$ident" "$(fu_identity)"
  it_check "no built-in database container and no built-in data folder" \
    bash -c '! docker container inspect custodexa-postgres >/dev/null 2>&1 && [ ! -e "$1/data/postgres" ] && [ ! -e "$1/data/postgresql" ]' _ "$LV_ROOT"
}
