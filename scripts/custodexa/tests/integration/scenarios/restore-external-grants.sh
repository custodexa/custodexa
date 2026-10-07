# shellcheck shell=bash
# about: a backup that grants rights to a role the PostgreSQL 17 server no longer has: without --accept-grant-loss and without a terminal the restore is refused and nothing changes; a grant statement naming that role and another one at once cannot be split, so the import opens no transaction; carrying on with the grants skipped leaves only the missing role's grants out (the table's ACL compared entry by entry) and skipped-grants.txt lists them
# needs: package local-versions
# images: pg17

readonly XG_PORT=15461
XG_A=/opt/custodexa XG_FILE=""
XR_SERVER=xg17

# xg_acl: the ACL of public.it_g, one entry per line, sorted.
xg_acl() {
  it_pg_sql xg17 "$EX_DB" "SELECT a FROM unnest((SELECT relacl FROM pg_class WHERE oid = 'public.it_g'::regclass)::text[]) a ORDER BY 1"
}
xg_run() {
  local label=$1
  shift
  xr_cx "$label" "$XG_A" restore "$XG_FILE" --same-host --yes --confirm-data-loss "$@"
}
xg_log() {
  local log
  log=$(ex_st "$XG_A" last_restore.log)
  [[ $log == /* ]] || log=$XG_A/$log
  printf '%s' "$log"
}

scenario() {
  local acl0 t1 list
  it_step "server xg17 (PostgreSQL 17) on $(ex_addr):$XG_PORT, roles \"report reader\" and it_auditor"
  ex_pg_start xg17 17 "$XG_PORT"
  ex_db_create xg17
  it_pg_sql xg17 postgres 'CREATE ROLE "report reader"; CREATE ROLE it_auditor'

  it_step "host A: install $XR_V on xg17; a table of DB_USER granted to both roles"
  xr_install "$XG_A" "$XG_PORT"
  ex_db_sql xg17 "$EX_DB" "CREATE TABLE public.it_g (id int PRIMARY KEY); INSERT INTO public.it_g VALUES (1), (2);
    GRANT SELECT ON public.it_g TO \"report reader\"; GRANT SELECT, INSERT ON public.it_g TO it_auditor"
  acl0=$(xg_acl)
  printf '%s\n' "$acl0" | sed 's/^/   acl> /'
  it_check "the table grants to \"report reader\"" grep -qF '"report reader"=r/' <<<"$acl0"
  it_check "the table grants to it_auditor" grep -q '^it_auditor=ar/' <<<"$acl0"

  it_step "the backup, then the role \"report reader\" is dropped from the server"
  ex_backup "$XG_A"
  mkdir -p "$IT_WORK/f"
  cp -p "$EX_FILE" "$EX_FILE.sha256" "$IT_WORK/f/"
  XG_FILE=$IT_WORK/f/${EX_FILE##*/}
  it_pg_sql xg17 "$EX_DB" 'DROP OWNED BY "report reader"'
  it_pg_sql xg17 postgres 'DROP ROLE "report reader"'
  it_same "the role is gone" 0 "$(it_pg_sql xg17 postgres "SELECT count(*) FROM pg_roles WHERE rolname = 'report reader'")"
  # The backend writes rows of its own while it runs: stopped, the digest holds still.
  xr_cx stop "$XG_A" stop --yes
  it_same "host A stops" 0 "$XR_RC"
  xr_quiet xg17
  t1=$(xr_digest xg17)

  it_step "without a terminal and without --accept-grant-loss: refused, nothing changed"
  xg_run no-flag
  it_same "no-flag: exit 3" 3 "$XR_RC"
  it_check "no-flag: it names the missing role" grep -qF 'report reader' <<<"$XR_OUT"
  it_check "no-flag: nothing has been changed" grep -qF 'Nothing has been changed.' <<<"$XR_OUT"
  it_same "no-flag: no restore was started" "" "$(ex_st "$XG_A" last_restore.result)"
  it_same "no-flag: the target digest is unchanged" "$t1" "$(xr_digest xg17)"

  it_step "a grant statement naming the missing role and another one at once: no transaction"
  XR_INJECT=grants-filter xg_run unsure --accept-grant-loss
  it_same "unsure: exit 1" 1 "$XR_RC"
  it_check "unsure: the injection happened" test -s "$IT_WORK/xr-injected"
  it_same "unsure: in progress at the import" "in_progress swapped" \
    "$(ex_st "$XG_A" last_restore.result) $(ex_st "$XG_A" last_restore.phase)"
  it_check "unsure: the log says the grants cannot be told apart" \
    grep -qF 'external import: the grants to the missing roles cannot be told apart' "$(xg_log)"
  it_same "unsure: no import container was started" "" "$(grep -- '-import ' "$IT_WORK/xr-docker.log" || true)"
  xr_quiet xg17
  it_same "unsure: the target digest is unchanged" "$t1" "$(xr_digest xg17)"

  it_step "carrying on: the grants to the missing role are skipped, the others restored"
  xr_cx resume "$XG_A" restore --resume
  it_same "resume: exit 0" 0 "$XR_RC"
  it_same "resume: recorded succeeded" succeeded "$(ex_st "$XG_A" last_restore.result)"
  it_same "the ACL is the backup's without the missing role's entry" \
    "$(grep -vF '"report reader"=' <<<"$acl0")" "$(xg_acl)"
  list=$(find "$XG_A/restore" -name skipped-grants.txt | head -n1)
  it_check "skipped-grants.txt is kept" test -s "$list"
  sed 's/^/   skipped> /' "$list"
  it_check "skipped-grants.txt lists the grant to \"report reader\"" grep -qF 'TO "report reader"' "$list"
  it_check "skipped-grants.txt lists nothing of it_auditor" bash -c '! grep -q it_auditor "$1"' _ "$list"
  it_check "the end screen counts the skipped grants" grep -qF 'grant statements for roles the server lacks were not' <<<"$(tr '\n' ' ' <<<"$XR_OUT" | tr -s ' ')"

  it_same "no client container is left" "" "$(docker ps -aq --filter name=custodexa-restore-tool)"
  ex_teardown "$XG_A"
  rm -rf "$XG_A"
  it_pg_stop xg17
}
