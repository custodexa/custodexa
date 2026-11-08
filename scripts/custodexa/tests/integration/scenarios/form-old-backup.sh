# shellcheck shell=bash
# about: a backup taken on a published 1.22.x deployment with an external ingress (host a) is restored on a new host (host b) with the working tree's script; start, backup and upgrade to the working tree's version then run in that order from the restored deployment, each exits 0, a record written before the backup reads after the upgrade, and TLS_MODE is external
# hosts: a b
# needs: package local-versions published
# images:
#
# Run with CX_IT_LOCAL_VERSIONS=1.23.90 CX_IT_PUBLISHED_VERSION=1.22.0.

readonly FOB_NEW=${CX_IT_LOCAL_VERSIONS:-1.23.90} FOB_T=/transfer

scenario_a() {
  local file
  fu_install ingress
  fu_sentinel 1
  it_step "backup on the published release"
  lv_cx backup backup --yes
  it_same "backup on $FU_OLD exits 0" 0 "$LV_RC"
  file=$(lv_st last_backup.file)
  it_check "the backup file is there ($file)" test -f "$LV_ROOT/$file"
  mkdir -p "$FOB_T/backup"
  cp "$LV_ROOT/$file" "$LV_ROOT/$file.sha256" "$FOB_T/backup/"
  cat "$LV_ROOT/current/VERSION" >"$FOB_T/version"
}

scenario_b() {
  local old file
  old=$(cat "$FOB_T/version")
  file=$(find "$FOB_T/backup" -name 'custodexa-backup-*.tar' | head -n1)
  it_step "b: the working tree's package ($FOB_NEW) unpacked, the published $old backup restored as a new host"
  ex_teardown "$LV_ROOT"
  # A new host has no images: the published release's own script loads its offline bundle (the restore
  # reads the backup with that release's database tool image and finds it from what load recorded in
  # state.json), then the working tree's package takes over the script and the current link and does
  # the restore.
  mkdir -p /opt
  tar -xzf "$(find /published -maxdepth 1 -name 'custodexa-[0-9]*.tar.gz' | head -n1)" -C /opt
  lv_cx load load "$(find /published -maxdepth 1 -name 'custodexa-images-*.tar' | head -n1)"
  it_same "load of the published $old offline bundle exits 0" 0 "$LV_RC"
  rm -rf "$LV_ROOT/current" "$LV_ROOT/custodexa.sh"
  it_unpack /opt "$FOB_NEW"
  ri_doc restore restore "$file" --new-host --yes \
    --package "$(find /published -maxdepth 1 -name 'custodexa-[0-9]*.tar.gz' | head -n1)" \
    --images "$(find /published -maxdepth 1 -name 'custodexa-images-*.tar' | head -n1)"
  it_same "restore of the $old backup with the $FOB_NEW script exits 0" 0 "$LV_RC"
  lv_wait_version "$old"
  LV_TOKEN=""
  FU_FORM=ingress
  it_step "b: start, backup, upgrade $FOB_NEW from the restored deployment"
  lv_cx start start
  it_same "start exits 0" 0 "$LV_RC"
  lv_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  lv_upgrade "$FOB_NEW"
  lv_wait_version "$FOB_NEW"
  LV_TOKEN=""
  it_same "the sentinel written before the backup reads after the upgrade" "1 it-sentinel-1" "$(fu_sentinels)"
  it_same "TLS_MODE is external" external "$(lv_env_get TLS_MODE)"
  it_same "custodexa-frontend is the compose service frontend-published" frontend-published "$(fu_label)"
  it_check "no COMPOSE_FILE or COMPOSE_PROFILES outside the managed block" fu_no_overlay_lines
}
