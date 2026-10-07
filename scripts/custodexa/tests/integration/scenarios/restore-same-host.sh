# shellcheck shell=bash
# about: a built-in deployment (master key mode env) restores its own backup on the same host: the row counts and migrations equal the backup's snapshot, data written after the backup is gone, the three folders kept from before are there, the recordings folder is unchanged, the backend holds the master key the backup names, the deployment's own proxy template changed after the backup is the backup's again and the running proxy loads it; --revert after the end is refused and the safety backup restores what was there before; a restore whose file placement fails after the database check goes back with --revert to the same version, rows, data, sequences and grants, every service running
# needs: package local-versions
# images:

readonly SH_V=1.16.90 SH_TPL=./custom/proxy.conf.template
readonly SH_TPL_BACKUP="the deployment's own template, as backed up" SH_TPL_AFTER="the template changed after the backup"

# sh_restore <label> <file> [expected exit]: the command backup-and-restore.md §5 gives for a host
# without a terminal: --same-host --yes --confirm-data-loss.
sh_restore() {
  ri_doc "$1" restore "$2" --same-host --yes --confirm-data-loss
  it_same "$1: restore exits ${3:-0}" "${3:-0}" "$LV_RC"
}

scenario() {
  local fp ts safety tpl_sha
  lv_install "$SH_V"
  install -m 640 /dev/null "$LV_ROOT/$LV_RECORDING"
  head -c 262144 /dev/urandom >"$LV_ROOT/$LV_RECORDING"
  chown 1000:0 "$LV_ROOT/$LV_RECORDING"
  ri_data in-backup

  it_step "the deployment's own proxy template: TLS_NGINX_TEMPLATE=$SH_TPL, a copy of the shipped one"
  ri_template "$SH_TPL" "$SH_TPL_BACKUP"
  ri_apply template
  it_same "the running proxy loaded it (nginx -T)" yes "$(ri_nginx_has "$SH_TPL_BACKUP")"
  tpl_sha=$(ri_sha "$LV_ROOT/$SH_TPL")

  it_step "backup, then more data and a changed template"
  ri_backup backup
  fp=$(jq -r '."kek.fingerprint"' "$IT_WORK/backup.manifest")
  it_check "the backup names a master key fingerprint" test -n "$fp"
  it_same "the backup holds the template and the path .env gave" "true $SH_TPL" \
    "$(jq -r '."contents.nginx_template" + " " + ."source.tls_nginx_template"' "$IT_WORK/backup.manifest")"
  it_same "the template in the backup is the deployment's (sha256)" "$tpl_sha" \
    "$(tar -xOf "$RI_FILE" nginx-tls.conf.template | sha256sum | cut -c1-64)"
  ri_data after-backup
  ri_template "$SH_TPL" "$SH_TPL_AFTER"
  ri_apply template-after
  it_same "the running proxy loaded the changed template" "yes no" \
    "$(ri_nginx_has "$SH_TPL_AFTER") $(ri_nginx_has "$SH_TPL_BACKUP")"
  ri_mark
  ri_facts "$IT_WORK/facts.before"
  ri_rec_sha >"$IT_WORK/rec.before"
  sed 's/^/   before: /' "$IT_WORK/facts.before"

  it_step "restore of that backup on this host"
  sh_restore restore "$RI_FILE"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$SH_V"
  ri_snap_same "the snapshot of the database now equals the backup's snapshot.txt" backup
  it_same "the user written before the backup is there" 1 "$(ri_has in-backup)"
  it_same "the user written after the backup is not" 0 "$(ri_has after-backup)"
  ts=$(lv_st last_restore.stamp)
  it_check "the database, audit and tls folders from before are kept" \
    test -d "$LV_ROOT/data/postgres.before-restore-$ts" -a -d "$LV_ROOT/data/audit.before-restore-$ts" -a -d "$LV_ROOT/tls.before-restore-$ts"
  it_same "the recordings folder is unchanged" "$(cat "$IT_WORK/rec.before")" "$(ri_rec_sha)"
  it_same "the backend holds the master key of the backup (seal/status kek_id)" "$fp" "$(ri_kek_id)"
  ri_running_same "after the restore"
  it_same "the proxy template is back at $SH_TPL, the backup's (sha256)" "$tpl_sha" "$(ri_sha "$LV_ROOT/$SH_TPL")"
  it_check "the template from before is kept as ${SH_TPL##*/}.before-restore-$ts" \
    grep -qxF "# $SH_TPL_AFTER" "$LV_ROOT/$SH_TPL.before-restore-$ts"
  it_same "the running proxy loaded the restored template, not the one from before (nginx -T)" "yes no" \
    "$(ri_nginx_has "$SH_TPL_BACKUP") $(ri_nginx_has "$SH_TPL_AFTER")"

  it_step "--revert after the end is refused; the safety backup brings back what was there before"
  ri_doc revert restore --revert --yes
  it_same "restore --revert exits 3" 3 "$LV_RC"
  it_check "because the restore finished" grep -q 'only handles' <<<"$LV_OUT"
  safety=$(lv_st last_restore.safety_file)
  [[ $safety == /* ]] || safety=$LV_ROOT/$safety
  it_check "the safety backup file is there ($safety)" test -f "$safety"
  sh_restore safety "$safety"
  lv_wait_version "$SH_V"
  ri_same_facts "version, rows, data, sequences and grants are those before the first restore" "$IT_WORK/facts.before"
  it_same "the user written after the backup is back" 1 "$(ri_has after-backup)"

  it_step "a restore whose file placement fails after the database check, then --revert"
  ri_mark
  ri_facts "$IT_WORK/facts.before2"
  rm -f "$IT_WORK/lv-injected"
  LV_INJECT=restore-place-fail ri_doc place-fail restore "$RI_FILE" --same-host --yes --confirm-data-loss
  it_same "the restore fails: exit 1" 1 "$LV_RC"
  it_check "the failure was the injected one" test -e "$IT_WORK/lv-injected"
  it_same "last_restore.result, phase" "in_progress db_checked" "$(lv_st last_restore.result) $(lv_st last_restore.phase)"
  it_check "the screen gives --revert" grep -q 'custodexa.sh restore --revert' <<<"$LV_OUT"
  ri_doc revert-placed restore --revert --yes
  it_same "restore --revert exits 0" 0 "$LV_RC"
  it_same "last_restore.result" reverted "$(lv_st last_restore.result)"
  lv_wait_version "$SH_V"
  ri_same_facts "version, rows, data, sequences and grants are those before this restore" "$IT_WORK/facts.before2"
  ri_running_same "after --revert"
  it_same "the recordings folder is unchanged" "$(cat "$IT_WORK/rec.before")" "$(ri_rec_sha)"
}
