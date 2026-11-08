# shellcheck shell=bash
# about: a published release (PostgreSQL 16) upgraded by script to the working tree (PostgreSQL 18) and taken back with rollback: after a failure at step 9 (the new version never started) the old version reads the data as it was before the upgrade; after a successful upgrade and writes on the new version the non-interactive rollback needs --yes, prints the data-loss warning, ends on the old version and the data of the upgrade, and keeps the PostgreSQL 18 folder with the data written meanwhile; the upgrade again converts again; with the old folder removed rollback is refused and the screen's restore of the pre-upgrade backup gives back the data of the upgrade; a go-back whose old version never passes its check, with a write to PostgreSQL 16 meanwhile, is undone with --revert (warning, back on 18, the write stays in the old folder); a kill after the rename of the PostgreSQL 18 folder and before it is recorded is finished by --resume with no empty database
# needs: package local-versions published
# images:
# Run with the published release and one local version: CX_IT_PUBLISHED_VERSION=1.22.0 CX_IT_LOCAL_VERSIONS=1.23.90
# CX_IT_PG_SECTIONS="pr_step9 pr_after_start pr_revert pr_kill" runs only those sections.

# shellcheck source=scripts/custodexa/tests/integration/lib/pgx.sh
. "$IT_DIR/lib/pgx.sh"

# pr_flat: the screen of the last command on one line.
pr_flat() { tr '\n' ' ' <<<"$LV_OUT" | tr -s ' '; }

pr_said() {
  local flat t
  flat=$(pr_flat)
  for t in "$@"; do
    it_check "the screen says \"$t\"" grep -qF -- "$t" <<<"$flat"
  done
}

pr_not_said() {
  local flat t
  flat=$(pr_flat)
  for t in "$@"; do
    it_check "the screen does not say \"$t\"" bash -c '! grep -qF -- "$1" <<<"$2"' _ "$t" "$flat"
  done
}

# pr_old_back <label> <R0>: the deployment runs the old release on PostgreSQL 16 with the data of R0.
pr_old_back() {
  lv_wait_version "$PX_OLD"
  it_same "$1: current.version, the current link" "$PX_OLD releases/$PX_OLD" "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "$1: the data folder is PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  LV_TOKEN=""
  it_same "$1: the data equals R0 (it_marker, users, assets, schema_migrations, sequence)" "$2" "$(px_fp lv_sql)"
}

# pr_aside: the folder the PostgreSQL 18 data was renamed to.
pr_aside() { compgen -G "$LV_ROOT/data/postgresql.rolled-back-*" | head -n1; }

# pr_audit_count <runner>: audit records that name the user written while going back is unfinished.
pr_audit_count() { "$1" "SELECT count(*) FROM audit_logs a WHERE a::text LIKE '%it-on-16%'"; }
pr_has_audit() { [ "$(pr_audit_count lv_sql)" -gt 0 ]; }

# 1. the upgrade fails at step 9, the new version never started: rollback gives the old data back.
pr_step9() {
  local r0 aside
  px_fresh step9
  r0=$(px_fp lv_sql)
  it_say "   R0: $r0"
  it_step "step 9 fails (the recordings folder cannot be prepared)"
  LV_INJECT=recordings-fail px_upgrade 1
  it_same "the upgrade stopped at step 9" "failed 9" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.step)"
  it_same "step 8 was done" done "$(lv_st last_upgrade.db_convert.result)"
  it_step "rollback --yes"
  lv_cx rollback rollback --yes
  it_same "rollback exits 0" 0 "$LV_RC"
  pr_said "the new version never started" "So no data is lost and no restore is needed."
  pr_not_said "has already started"
  pr_old_back step9 "$r0"
  aside=$(pr_aside)
  it_check "the PostgreSQL 18 folder is kept under a rolled-back name ($aside)" test -n "$aside"
  it_same "the kept folder is PostgreSQL 18" 18 "$(cat "$aside/18/docker/PG_VERSION")"
  it_check "data/postgresql is gone" test ! -e "$LV_ROOT/data/postgresql"
}

# 2. an upgrade that ended, writes on the new version, then rollback; the upgrade again; remove old; restore.
pr_after_start() {
  local r0 aside backup cmd
  px_fresh after
  r0=$(px_fp lv_sql)
  it_say "   R0: $r0"
  px_upgrade
  lv_wait_version "$PX_NEW"
  it_same "PostgreSQL 18 runs" 18 "$(lv_sql 'SHOW server_version_num' | cut -c1-2)"
  LV_TOKEN=""
  lv_api POST /users "$(jq -cn '{username: "it-on-new", password: "It-user-pass-0002", email: "it-on-new@example.test", full_name: "x"}')" >/dev/null
  lv_sql "INSERT INTO it_marker VALUES (9001, 'written on the new version')" >/dev/null
  it_same "the data differs from R0 now" 1 "$([ "$(px_fp lv_sql)" != "$r0" ] && echo 1 || echo 0)"

  it_step "rollback without --yes and without a terminal is refused"
  lv_cx noyes rollback
  it_same "exit 3" 3 "$LV_RC"
  pr_said "it only runs with --yes" "Nothing was changed."
  it_same "still on $PX_NEW" "$PX_NEW" "$(lv_version)"

  it_step "rollback --yes: the warning is printed, the old data comes back"
  lv_cx rollback rollback --yes
  it_same "rollback exits 0" 0 "$LV_RC"
  pr_said "has already started" "Data written after the upgrade will not be in the database" "audit records" \
    "The current PostgreSQL 18 data is not deleted; it is renamed and kept at:" "The other way is to restore the backup taken before the upgrade"
  pr_old_back rollback "$r0"
  it_same "the user written on the new version is not here" 0 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-on-new'")"
  aside=$(pr_aside)
  it_check "the PostgreSQL 18 folder is kept ($aside)" test -n "$aside"
  px_read_start "$aside" 18
  it_same "the kept folder still holds the user and the marker row written on the new version" "1 1" \
    "$(px_read_sql "SELECT (SELECT count(*) FROM users WHERE username = 'it-on-new') || ' ' || (SELECT count(*) FROM it_marker WHERE id = 9001)")"
  px_read_stop

  it_step "upgrade again: it converts again, the kept folder is not merged"
  px_upgrade
  lv_wait_version "$PX_NEW"
  it_same "the kept folder is still there, unchanged name" "$aside" "$(pr_aside)"
  it_same "PostgreSQL 18 runs again" 18 "$(lv_sql 'SHOW server_version_num' | cut -c1-2)"
  it_same "the data of the second conversion equals R0 (no write of the first stay)" "$r0" "$(px_fp lv_sql)"
  lv_cx status status
  pr_said "rolled-back"

  it_step "db-upgrade --remove-old removes the old PostgreSQL 16 folder"
  lv_cx remove db-upgrade --remove-old --yes
  it_same "remove exits 0" 0 "$LV_RC"
  it_check "data/postgres is gone" test ! -e "$LV_ROOT/data/postgres"
  backup=$(lv_st last_upgrade.backup)
  it_step "rollback is refused and the screen gives restore"
  lv_cx refused rollback --yes
  it_same "exit 3" 3 "$LV_RC"
  pr_said "is no longer there" "restore"
  it_same "still on $PX_NEW" "$PX_NEW" "$(lv_version)"
  cmd=$(grep -E "custodexa\.sh .*restore" <<<"$LV_OUT" | tail -n1 | sed -E 's/^ *(sudo +)?//; s/ --lang [a-zA-Z-]+//; s#^[^ ]*/custodexa\.sh +##')
  it_check "the screen gives a restore command ($cmd)" test -n "$cmd"
  it_check "the command names the pre-upgrade backup ($backup)" grep -qF -- "${backup##*/}" <<<"$cmd"
  it_step "restore as the screen says (plus the confirmations a run without a terminal needs)"
  # shellcheck disable=SC2086
  lv_cx restore $cmd --same-host --yes --confirm-data-loss
  it_same "restore exits 0" 0 "$LV_RC"
  pr_old_back restore "$r0"
  it_check "the PostgreSQL 18 data is kept under a before-restore name" compgen -G "$LV_ROOT/data/postgresql.before-restore-*"
}

# 3. a go-back whose old version never passes its check; a write to PostgreSQL 16 meanwhile; --revert.
pr_revert() {
  local r18
  px_fresh revert
  px_upgrade
  lv_wait_version "$PX_NEW"
  LV_TOKEN=""
  lv_api POST /users "$(jq -cn '{username: "it-on-new", password: "It-user-pass-0002", email: "it-on-new@example.test", full_name: "x"}')" >/dev/null
  r18=$(px_fp lv_sql)
  it_step "rollback; the old backend is paused after the start, so the check never passes"
  LV_INJECT=pause-after-up LV_READY_TRIES=2 lv_cx rb rollback --yes
  it_same "exit 1" 1 "$LV_RC"
  it_same "last_rollback.result, step" "in_progress 4" "$(lv_st last_rollback.result) $(lv_st last_rollback.step)"
  it_same "PostgreSQL 16 is the data in use" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  docker unpause custodexa-backend >/dev/null
  lv_wait_version "$PX_OLD"
  LV_TOKEN=""
  it_step "a write to PostgreSQL 16 (a user, so audit events too) while going back is unfinished"
  lv_api POST /users "$(jq -cn '{username: "it-on-16", password: "It-user-pass-0003", email: "it-on-16@example.test", full_name: "x"}')" >/dev/null
  it_same "the user is in PostgreSQL 16" 1 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-on-16'")"
  lv_until "an audit record naming the user is in PostgreSQL 16" pr_has_audit
  it_same "an audit record names the user in PostgreSQL 16" 1 "$([ "$(pr_audit_count lv_sql)" -gt 0 ] && echo 1 || echo 0)"
  it_step "rollback --revert --yes"
  # the screen says to run the script of the version going back to, not the root link (which points at the older one)
  LV_SCRIPT=$LV_ROOT/releases/$PX_NEW/custodexa.sh lv_cx revert rollback --revert --yes
  it_same "revert exits 0" 0 "$LV_RC"
  pr_said "has run on PostgreSQL 16 for a while" "will not be in the database after returning" "This data stays in the old data folder" "Returned to"
  lv_wait_version "$PX_NEW"
  it_same "last_rollback.result" reverted "$(lv_st last_rollback.result)"
  it_same "PostgreSQL 18 runs" 18 "$(lv_sql 'SHOW server_version_num' | cut -c1-2)"
  LV_TOKEN=""
  it_same "the record written to PostgreSQL 16 is not in PostgreSQL 18" 0 "$(lv_sql "SELECT count(*) FROM users WHERE username = 'it-on-16'")"
  it_same "no audit record names it in PostgreSQL 18" 0 "$(pr_audit_count lv_sql)"
  it_same "the data in PostgreSQL 18 is that before going back" "$r18" "$(px_fp lv_sql)"
  it_same "the old folder is still PostgreSQL 16" 16 "$(cat "$LV_ROOT/data/postgres/PG_VERSION")"
  px_read_start "$LV_ROOT/data/postgres" 16
  it_same "the old folder holds the write (user, audit records)" "1 yes" \
    "$(px_read_sql "SELECT (SELECT count(*) FROM users WHERE username = 'it-on-16') || ' ' || CASE WHEN $(printf '(SELECT count(*) FROM audit_logs a WHERE a::text LIKE %s) > 0' "'%it-on-16%'") THEN 'yes' ELSE 'no' END")"
  px_read_stop
}

# 4. SIGKILL after the rename of the PostgreSQL 18 folder, before it is recorded: --resume.
pr_kill() {
  local r0 intent
  px_fresh kill
  r0=$(px_fp lv_sql)
  px_upgrade
  lv_wait_version "$PX_NEW"
  px_shim_mv
  it_step "rollback killed (SIGKILL) right after the rename of data/postgresql"
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-rename lv_bg k1 rollback --yes
  lv_until "the rename was made" test -e "$IT_WORK/lv-rename-reached"
  it_check "the folder is renamed" bash -c '! test -e "$1/data/postgresql" && compgen -G "$1/data/postgresql.rolled-back-*"' _ "$LV_ROOT"
  intent=$(lv_st dir_op.phase)
  it_same "the rename is recorded as an intent only (dir_op.phase)" intent "$intent"
  # the script re-runs itself from the release folder: kill every process of it, as a crash does
  pkill -KILL -f "$LV_ROOT/.*custodexa.sh" 2>/dev/null || true
  kill -KILL "$LV_PID" 2>/dev/null || true
  pkill -KILL -f "$IT_WORK/lvshim/mv" 2>/dev/null || true
  wait "$LV_PID" 2>/dev/null || true
  rm -f "$IT_WORK/lv-hold"
  it_say "   k1: the script was killed with SIGKILL"
  sleep 1
  for p in /proc/[0-9]*; do
    if ls -l "$p/fd" 2>/dev/null | grep -q custodexa.lock; then it_say "   lock holder: ${p#/proc/} $(tr '\0' ' ' <"$p/cmdline")"; fi
  done
  it_step "status and rollback --resume"
  lv_cx resume rollback --resume --yes
  it_same "rollback --resume exits 0" 0 "$LV_RC"
  pr_old_back resume "$r0"
  it_check "no new PostgreSQL 18 cluster was created: data/postgresql is absent" test ! -e "$LV_ROOT/data/postgresql"
  it_same "the kept folder is PostgreSQL 18" 18 "$(cat "$(pr_aside)/18/docker/PG_VERSION")"
  it_same "last_rollback.result" succeeded "$(lv_st last_rollback.result)"
}

scenario() {
  px_section "step 9 fails, rollback" pr_step9
  px_section "after the upgrade ended: rollback, upgrade again, remove old, restore" pr_after_start
  px_section "unfinished go-back, revert" pr_revert
  px_section "kill after the rename, resume" pr_kill
  ex_teardown "$LV_ROOT" || true
  [ -z "$px_failed" ] || it_die "sections not ok:$px_failed"
}
