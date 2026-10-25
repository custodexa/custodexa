#!/usr/bin/env bats
# The permission model in backup, restore and downgrade.
#
# The backend does the permission work in a one-shot command (docker compose run, no HTTP):
# `permission-meta` for the snapshot, `permission-restore` for the original-state check, the
# reference and last-administrator checks and the restore transaction (a new restore generation).
# Here the command is a fake docker answer; its real behaviour is proven by the Go test
# TestPermissionRestoreGeneration and by a drill on a real database with tickets.
# What this file proves is the script side: the order of the stages, what each answer of the
# command does to the restore, and that nothing of the new model is asked of a legacy data set.
#
# The second test, "permission downgrade boundary", is the other direction: no list in a
# release and no rehearsal record gives a way back across the permission model; the way back is the
# backup taken before the upgrade. It builds its own host (see setup) and shares nothing with the rest.

load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
load restore_engine_host
load restore_ext_flow_host
load rollback_host

readonly AUTHZ_MIG=20261017_permission_state_attestation
readonly MODEL_MIG=20261016_authz_permission_model
readonly AUTHZ_DIGEST=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

setup() {
  if [[ $BATS_TEST_DESCRIPTION == "permission downgrade boundary" ]]; then
    host_workdir
    host_cache judge-base judge_base
    return
  fi
  rs_import_host
  printf 'count.users=5\ncount.sessions=42\ncount.audit_logs=1234\n' >"$RS_I_STAGE/pass2/snapshot.txt"
  sed 's/^/migration=/' "$DB/migrations" >>"$RS_I_STAGE/pass2/snapshot.txt"
  cat >>"$ROOT/releases/1.16.1/lib/cmd_restore.sh" <<'HARNESS'
cmd_restore() {
  cx_rs_options "${1:-}"
  cx_lock
  cx_log_open restore || return 1
  CX_RS_FILE=$1 CX_RS_FLOW=same CX_RS_VERSION=1.16.1 CX_RS_ENGINE=1.16.1
  CX_RS_DIR=$RS_I_STAGE CX_RS_TS=import-test CX_RS_CHECKSUM=matched CX_RS_DATA=$CX_ROOT/data
  CX_RS_MAP=([db.migrations_count]=$(grep -c '^migration=' "$RS_I_STAGE/pass2/snapshot.txt") [kek.fingerprint]=5a5a5a5a5a5a5a5a)
  CX_RS_MAP[db.migrations_sha256]=$(cx_snap_migrations "$CX_RS_DIR/pass2/snapshot.txt" | LC_ALL=C sort | sha256sum | cut -c1-64)
  if [ "${PERM_HARNESS:-}" = snapshot ]; then cx_rs_authz_snapshot "$CX_RS_DIR/pass2/snapshot.txt"; return; fi
  cx_rs_record && cx_rs_phase imported && cx_rs_step 7 || return 1
  cx_state_set last_restore.covering 1
  cx_state_set last_restore.safety script
  cx_state_set last_restore.safety_file backups/safety.tar
  cx_rs_db_check
}
HARNESS
  printf 'running\n' >"$DB/ctr/postgres"
  # The one-shot command of the backend: its answers and the calls it got are files of $DB.
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/perm-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' run --rm --no-deps -T backend ./custodexa '*)
    all="$*"
    sub=${all#* ./custodexa }
    printf '%s\n' "$sub" >>"$DB/authz.calls"
    case $sub in
      permission-meta*) cat "$DB/authz.meta" 2>/dev/null; exit "$(cat "$DB/authz.meta.rc" 2>/dev/null || echo 0)" ;;
      permission-restore*) cat "$DB/authz.restore.out" 2>/dev/null; exit "$(cat "$DB/authz.restore.rc" 2>/dev/null || echo 0)" ;;
    esac
    exit 64 ;;
  *' psql '*'DO $$ BEGIN'*)
    # The statement that revokes the old sessions (an older version's data set).
    printf 'CALL\n%s\n' "$*" >>"$DB/legacy.sql"
    exit "$(cat "$DB/legacy.rc" 2>/dev/null || echo 0)" ;;
esac
exec "$FAKE_DOCKER_REPLAY/perm-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  : >"$DB/authz.calls"
  cp "$DB/migrations" "$DB/migrations.base"
  cp "$RS_I_STAGE/pass2/snapshot.txt" "$RS_I_STAGE/snapshot.base"
  cp "$ROOT/state.json" "$ROOT/state.base"
}

# reset_case: the imported state again, for the next row of a table.
reset_case() {
  cp "$DB/migrations.base" "$DB/migrations"
  cp "$RS_I_STAGE/snapshot.base" "$RS_I_STAGE/pass2/snapshot.txt"
  cp "$ROOT/state.base" "$ROOT/state.json"
  local f
  for f in "$DB"/ctr/*; do printf 'stopped\n' >"$f"; done
  printf 'running\n' >"$DB/ctr/postgres"
  : >"$DB/events"
  : >"$DB/authz.calls"
  rm -f "$DB"/authz.restore.* "$DB"/authz.meta* "$DB"/legacy.*
}

# authz_snapshot [refs]: the permission summary a new-model backup carries (refs defaults to ok).
authz_snapshot() {
  {
    printf 'migration=%s\n' "$AUTHZ_MIG"
    printf 'authz.model=1\nauthz.snapshot=1\nauthz.catalog=%s\nauthz.digest=%s\nauthz.version=7\nauthz.refs=%s\n' \
      "$AUTHZ_DIGEST" "$AUTHZ_DIGEST" "${1:-ok}"
    local s
    for s in roles user_roles group_roles binding_nodes nodes role_maps group_maps members groups principals; do
      printf 'authz.count.%s=1\n' "$s"
    done
  } >>"$RS_I_STAGE/pass2/snapshot.txt"
  printf '%s\n' "$AUTHZ_MIG" >>"$DB/migrations"
}
# ---- Whole-flow rows (internal and external database): cancel before the overwrite, and revert after.
# The one-shot command is a stand-in that behaves like the backend's transaction (a new generation for
# every operation ID and input digest it has not committed yet). The dump is told apart per call, as a
# real pg_dump of different data is, so the safety backup's input digest differs from the file's.

# perm_flow_before: runs on the source deployment before its backup (RS_E_BEFORE, RS_X_BEFORE).
perm_flow_before() {
  printf '%s\n' "$AUTHZ_MIG" >>"$DB/migrations"
  jq --arg m "$AUTHZ_MIG" '.migrations += [$m]' "$ROOT/current/MANIFEST.json" >"$BATS_TEST_TMPDIR/mf.new"
  cp "$BATS_TEST_TMPDIR/mf.new" "$ROOT/current/MANIFEST.json"
  : >"$DB/authz.calls"
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/perm-flow-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
all=" $* "
case $all in
  *' run --rm --no-deps -T backend ./custodexa '*)
    sub=${all#* ./custodexa }; sub=${sub% }
    case $sub in
      permission-meta*)
        printf 'authz.model=1\nauthz.snapshot=1\nauthz.catalog=%s\nauthz.digest=%s\nauthz.version=7\nauthz.refs=ok\n' "$PERM_DIGEST" "$PERM_DIGEST"
        for s in roles user_roles group_roles binding_nodes nodes role_maps group_maps members groups principals; do printf 'authz.count.%s=1\n' "$s"; done
        exit 0 ;;
      permission-restore*)
        printf '%s\n' "$sub" >>"$DB/authz.calls"
        op=$(sed -n 's/.*--op-id \([^ ]*\).*/\1/p' <<<"$sub"); dg=$(sed -n 's/.*--input-digest \([^ ]*\).*/\1/p' <<<"$sub")
        if [ "$(cat "$DB/authz.last" 2>/dev/null)" = "$op $dg" ]; then fresh=false
        else
          fresh=true; printf '%s %s\n' "$op" "$dg" >"$DB/authz.last"
          printf '%s\n' "$(( $(cat "$DB/authz.gen" 2>/dev/null || echo 0) + 1 ))" >"$DB/authz.gen"
        fi
        printf 'restore.generation_fp=%032d\nrestore.fresh=%s\n' "$(cat "$DB/authz.gen")" "$fresh"
        exit 0 ;;
    esac
    exit 64 ;;
  *' pg_dump --version'*) ;;
  *' pg_dump '*)
    "$FAKE_DOCKER_REPLAY/perm-flow-base" "$@"; rc=$?
    n=$(( $(cat "$DB/dumpseq" 2>/dev/null || echo 0) + 1 )); printf '%s\n' "$n" >"$DB/dumpseq"
    printf 'dump number %s\n' "$n"; exit "$rc" ;;
esac
exec "$FAKE_DOCKER_REPLAY/perm-flow-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  export PERM_DIGEST=$AUTHZ_DIGEST
  # One cut point at a phase boundary, as the engine host's: the run stops there with status 1.
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'HARNESS'
eval "$(declare -f cx_rs_phase | sed '1s/cx_rs_phase/rs_p_phase/')"
cx_rs_phase() {
  rs_p_phase "$@" || return 1
  [ "${RS_P_CUT:-}" = "$1" ] || return 0
  [ ! -e "$DB/cut-hit" ] || return 0
  echo "$1" >"$DB/cut-hit"
  return 1
}
HARNESS
}
perm_gen() { cat "$DB/authz.gen" 2>/dev/null || echo 0; }
# perm_digests: the input digests of the restore command's calls, in order.
perm_digests() { sed -n 's/.*--input-digest \([^ ]*\).*/\1/p' "$DB/authz.calls"; }
perm_result() { jq -r '."last_restore.result"' "$ROOT/state.json"; }
perm_fresh_dirs() {
  unset FAKE_DOCKER_REPLAY
  rm -rf "$BATS_TEST_TMPDIR/opt" "$BATS_TEST_TMPDIR/db" "$BATS_TEST_TMPDIR/host" "$BATS_TEST_TMPDIR/replay" "$BATS_TEST_TMPDIR/source" "$BATS_TEST_TMPDIR/ui"
}

# perm_flow <internal|external> <cut phase>: the restore of a new-model backup, stopped at the phase.
perm_flow_start() {
  local kind=$1 cut=$2
  perm_fresh_dirs
  if [ "$kind" = internal ]; then
    RS_E_BEFORE=perm_flow_before rs_engine_host || return 1
    unset RS_E_BEFORE
    export RS_P_CUT=$cut
    run bash "$ROOT/custodexa.sh" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  else
    RS_X_BEFORE=perm_flow_before rs_ext_flow_host || return 1
    unset RS_X_BEFORE
    printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
    : >"$DB/activity.after-stop"
    export RS_P_CUT=$cut
    run bash "$ROOT/custodexa.sh" restore "$RS_X_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  fi
  unset RS_P_CUT
  [ "$status" = 1 ] && [ "$(cat "$DB/cut-hit")" = "$cut" ] || { echo "start $kind $cut: $status $output"; return 1; }
}
phase() { jq -r '."last_restore.phase"' "$ROOT/state.json"; }
backend_calls() { grep -c "^$1" "$DB/authz.calls" || true; }

# legacy_flow_start <internal|external> <cut phase|"">: a backup of an older version (no permission
# model) restored by scripts that know the model (their manifest lists its migration, added after the
# backup was taken). The revoking statement is a recorded stand-in; every other answer is the host's.
legacy_flow_start() {
  local kind=$1 cut=$2 mf
  perm_fresh_dirs
  if [ "$kind" = internal ]; then rs_engine_host || return 1; else rs_ext_flow_host || return 1; fi
  LEGACY_OLD_JWT=$(sed -n 's/^JWT_SECRET=//p' "$ROOT/.env")
  # The scripts are those of a newer package (1.16.1, which lists the model's migration); the
  # backup and the package it names are 1.16.0.
  LEGACY_ENG=$ROOT/releases/1.16.1
  cp -a "$ROOT/releases/1.16.0" "$LEGACY_ENG"
  printf '1.16.1\n' >"$LEGACY_ENG/VERSION"
  mf=$BATS_TEST_TMPDIR/mf.legacy
  jq --arg m "$AUTHZ_MIG" '.version = "1.16.1" | .migrations += [$m]' "$LEGACY_ENG/MANIFEST.json" >"$mf" && cp "$mf" "$LEGACY_ENG/MANIFEST.json"
  : >"$DB/authz.calls"
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/legacy-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' psql '*'DO $$ BEGIN'*)
    printf 'CALL\n%s\n' "$*" >>"$DB/legacy.sql"
    exit "$(cat "$DB/legacy.rc" 2>/dev/null || echo 0)" ;;
  *' run --rm --no-deps -T backend ./custodexa '*) printf '%s\n' "$*" >>"$DB/authz.calls"; exit 64 ;;
esac
exec "$FAKE_DOCKER_REPLAY/legacy-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  cat >>"$LEGACY_ENG/lib/cmd_restore.sh" <<'HARNESS'
eval "$(declare -f cx_rs_phase | sed '1s/cx_rs_phase/rs_p_phase/')"
cx_rs_phase() {
  rs_p_phase "$@" || return 1
  [ "${RS_P_CUT:-}" = "$1" ] || return 0
  [ ! -e "$DB/cut-hit" ] || return 0
  echo "$1" >"$DB/cut-hit"
  return 1
}
HARNESS
  [ -z "${LEGACY_RC:-}" ] || echo "$LEGACY_RC" >"$DB/legacy.rc"
  export RS_P_CUT=$cut
  if [ "$kind" = internal ]; then
    run bash "$LEGACY_ENG/custodexa.sh" restore "$RS_E_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  else
    printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
    : >"$DB/activity.after-stop"
    run bash "$LEGACY_ENG/custodexa.sh" restore "$RS_X_FILE" --same-host --yes --confirm-data-loss --lang en </dev/null
  fi
  unset RS_P_CUT
}
env_jwt() { sed -n 's/^JWT_SECRET=//p' "$ROOT/.env"; }
legacy_calls() { grep -c '^CALL$' "$DB/legacy.sql" 2>/dev/null || true; }
legacy_record() { jq -r '."last_restore.legacy_return" // ""' "$ROOT/state.json"; }

# One row per answer of the restore command:
#   name | setup | exit code | stdout | phase after | expected text ("" when none)
@test "permission restore lifecycle" {
  local row name want_phase want_text rc out calls dumpsum
  dumpsum=$(sha256sum "$RS_I_STAGE/pass2/db.dump" | cut -d' ' -f1)
  while IFS='|' read -r name rc out want_phase want_text; do
    # Each row starts from the same imported state.
    reset_case
    case $name in
      legacy) ;;
      *) authz_snapshot ;;
    esac
    printf '%s\n' "$rc" >"$DB/authz.restore.rc"
    printf '%b' "$out" >"$DB/authz.restore.out"
    rs_import_run
    echo "row $name: status=$status phase=$(phase)"
    [ "$(phase)" = "$want_phase" ] || { echo "$output"; cat "$DB/authz.calls"; grep -a "custodexa" "${FAKE_DOCKER_LOG:-/dev/null}" | tail -3; return 1; }
    [[ -z $want_text || $output == *"$want_text"* ]] || { echo "$output"; return 1; }
    # The backend is never started in this stage, whatever the answer.
    ! grep -Eq '^(start|up)( |$)' "$DB/events" || return 1
    [ "$(cat "$DB/ctr/backend")" = stopped ] || return 1
    calls=$(backend_calls permission-restore)
    case $name in
      legacy) [ "$calls" = 0 ] || return 1 ;;
      *)
        [ "$calls" = 1 ] || return 1
        grep -qx "permission-restore --op-id import-test --input-digest $dumpsum --expect-digest $AUTHZ_DIGEST" "$DB/authz.calls" || return 1 ;;
    esac
  done <<'ROWS'
legacy|0||db_checked|
committed|0|restore.generation_fp=0123456789abcdef0123456789abcdef\nrestore.fresh=true\n|db_checked|
resumed after the commit|0|restore.generation_fp=0123456789abcdef0123456789abcdef\nrestore.fresh=false\n|db_checked|
references do not hold|3|finding=dangling_user_role_role:1:99\nfinding=no_local_super_admin:0\n|imported|permission references do not hold (dangling_user_role_role,no_local_super_admin)
state differs from the backup|5|mismatch.expected=0123456789abcdef\nmismatch.actual=fedcba9876543210\n|imported|(imported fedcba987654, backup 0123456789ab)
another restore is unfinished|4|error=op-conflict\n|imported|another unfinished permission restore
command fails|1||imported|the imported data could not be read
ROWS

  # The original checks come first: a changed migration set stops the restore before the command.
  reset_case
  authz_snapshot
  printf '20261103_session_tags\n' >>"$DB/migrations"
  rs_import_run
  [ "$status" = 1 ] && [ "$(phase)" = imported ] || { echo "$output"; return 1; }
  [ "$(backend_calls permission-restore)" = 0 ] || return 1
  [[ $output == *'migrations after the import differ'* ]] || { echo "$output"; return 1; }

  # An incomplete or malformed summary is no restore source; so is one whose references do not hold.
  reset_case
  authz_snapshot
  sed -i '/^authz.count.nodes=/d' "$RS_I_STAGE/pass2/snapshot.txt"
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en
  [ "$status" = 1 ] && [[ $output == *'permission summary in the snapshot is incomplete'* ]] || { echo "$output"; return 1; }
  reset_case
  authz_snapshot
  sed -i 's/^authz.snapshot=1$/authz.snapshot=2/' "$RS_I_STAGE/pass2/snapshot.txt"
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en
  [ "$status" = 1 ] && [[ $output == *'has a model or snapshot version'* ]] || { echo "$output"; return 1; }
  # The file is whole, so the screen must not call it damaged or send the reader to copy it again.
  [[ $output == *'backup file is whole'* && $output == *'Use the release that made'* ]] || { echo "$output"; return 1; }
  [[ $output != *'incomplete or has been changed'* && $output != *'copy this file again'* ]] || { echo "$output"; return 1; }
  reset_case
  authz_snapshot 'findings:2'
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en
  [ "$status" = 1 ] && [[ $output == *'snapshot reports permission findings'* ]] || { echo "$output"; return 1; }
  [[ $output == *'backup file is whole'* && $output == *'Use an earlier backup'* && $output == *'take a new backup'* ]] || { echo "$output"; return 1; }
  [[ $output != *'incomplete or has been changed'* && $output != *'copy this file again'* ]] || { echo "$output"; return 1; }
  # The same screen in the other two languages: the whole-file heading, not the damaged-file one.
  reset_case
  authz_snapshot 'findings:2'
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang zh-TW
  [ "$status" = 1 ] && [[ $output == *'備份檔本身完整'* && $output == *'重新複製檔案不會改變結果'* && $output != *'不完整或被改動過'* ]] || { echo "$output"; return 1; }
  reset_case
  authz_snapshot 'findings:2'
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang ja
  [ "$status" = 1 ] && [[ $output == *'バックアップファイル自体は完全です'* && $output == *'結果は変わりません'* && $output != *'不完全か変更されている'* ]] || { echo "$output"; return 1; }
  reset_case
  PERM_HARNESS=snapshot run bash "$RS_I_ENGINE" restore "$RS_I_STAGE/pass2/db.dump" --same-host --yes --lang en
  [ "$status" = 0 ] || { echo "$output"; return 1; }

  # Going back to an older version: the engine knows the permission model, the data
  # set does not. Rows: the secret of the settings was not replaced / it was and the revoke runs once
  # / the revoke fails. The sessions are revoked after the original checks and before the services.
  local mf=$ROOT/releases/1.16.1/MANIFEST.json
  cp "$mf" "$BATS_TEST_TMPDIR/mf.engine"
  jq --arg m "$AUTHZ_MIG" '.migrations += [$m]' "$BATS_TEST_TMPDIR/mf.engine" >"$mf"
  reset_case
  cp "$RS_I_STAGE/env.merged" "$RS_I_STAGE/pass2/env.bak"
  rs_import_run
  [ "$status" = 1 ] && [ "$(phase)" = imported ] && [[ $output == *'sign-in secret in the settings to restore was not replaced'* ]] || { echo "$output"; return 1; }
  [ ! -s "$DB/legacy.sql" ] && [ "$(legacy_record)" = "" ] || return 1
  reset_case
  sed -i 's/^JWT_SECRET=.*/JWT_SECRET=replaced-secret-value-for-legacy-0002/' "$RS_I_STAGE/env.merged"
  echo 1 >"$DB/legacy.rc"
  rs_import_run
  [ "$status" = 1 ] && [ "$(phase)" = imported ] && [[ $output == *'could not all be revoked'* ]] || { echo "$output"; return 1; }
  [ "$(legacy_record)" = "" ] || return 1
  reset_case
  sed -i 's/^JWT_SECRET=.*/JWT_SECRET=replaced-secret-value-for-legacy-0002/' "$RS_I_STAGE/env.merged"
  rs_import_run
  [ "$status" = 0 ] && [ "$(phase)" = db_checked ] || { echo "$output"; return 1; }
  [ "$(legacy_calls)" = 1 ] && [ "$(backend_calls permission-restore)" = 0 ] || return 1
  grep -q "refresh_tokens" "$DB/legacy.sql" && grep -q "agent_tokens" "$DB/legacy.sql" &&
    grep -q "source = 'ticket'" "$DB/legacy.sql" || return 1
  [[ $(legacy_record) =~ ^secret=[0-9a-f]{16}\ revoked=refresh,agent,ticket$ ]] || { legacy_record; return 1; }
  [[ $output == *'the sign-in secret is replaced'* ]] || return 1
  ! grep -rq 'replaced-secret-value-for-legacy-0002' "$ROOT/state.json" "$ROOT/logs" 2>/dev/null || return 1
  [[ $output != *replaced-secret-value-for-legacy-0002* ]] || return 1
  cp "$BATS_TEST_TMPDIR/mf.engine" "$mf"

  # Whole flow, internal then external database: nothing is asked of the command before the data is
  # overwritten, and the revert after it is another restore with its own generation.
  local kind
  for kind in internal external; do
    # Cancelled before the overwrite: the original services start again; no generation, no call.
    perm_flow_start "$kind" stopped || return 1
    run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
    echo "cancel $kind: status=$status result=$(perm_result) calls=$(backend_calls permission-restore) generation=$(perm_gen)" >&3
    [ "$status" = 0 ] || { echo "$output"; return 1; }
    [ "$(backend_calls permission-restore)" = 0 ] && [ "$(perm_gen)" = 0 ] || { cat "$DB/authz.calls"; return 1; }
    [ "$(cat "$DB/ctr/backend")" = running ] || return 1

    # Reverted after the overwrite: the restore checked once (generation 1); the revert imports the
    # safety backup, which is another input, so it commits another restore (generation 2).
    perm_flow_start "$kind" placed || return 1
    [ "$(backend_calls permission-restore)" = 1 ] && [ "$(perm_gen)" = 1 ] || { cat "$DB/authz.calls"; return 1; }
    run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
    echo "revert $kind: status=$status result=$(perm_result) calls=$(backend_calls permission-restore) generation=$(perm_gen)" >&3
    [ "$status" = 0 ] && [ "$(perm_result)" = reverted ] || { echo "$output"; return 1; }
    [ "$(backend_calls permission-restore)" = 2 ] && [ "$(perm_gen)" = 2 ] || { cat "$DB/authz.calls"; return 1; }
    [ "$(perm_digests | sort -u | wc -l)" = 2 ] || { cat "$DB/authz.calls"; return 1; }
    [ "$(cat "$DB/ctr/backend")" != running ] || true
  done
  # Whole flow back to an older version, internal database (the external client stands behind the same
  # two functions; its host fixture cannot take a newer engine package, see the progress file). After the files are placed
  # the sign-in secret differs from the one the backup held and the revoke ran once, never asking the
  # backend command for a restore generation; the secret is in no log, state or screen. A resume
  # replaces and revokes nothing again. A revoke that fails stops the restore with the one new
  # secret already in the settings, and the resume that follows finishes without replacing it.
  local new
  for kind in internal; do
    legacy_flow_start "$kind" placed
    [ "$status" = 1 ] && [ "$(cat "$DB/cut-hit")" = placed ] || { echo "legacy $kind: $status $output"; return 1; }
    new=$(env_jwt)
    [ -n "$new" ] && [ "$new" != "$LEGACY_OLD_JWT" ] || return 1
    [ "$(legacy_calls)" = 1 ] && [ "$(backend_calls permission-restore)" = 0 ] || return 1
    [[ $(legacy_record) =~ ^secret=[0-9a-f]{16}\ revoked=refresh,agent,ticket$ ]] || { legacy_record; return 1; }
    ! grep -rqF -- "$new" "$ROOT/state.json" "$ROOT/logs" 2>/dev/null && [[ $output != *"$new"* ]] || return 1
    run bash "$LEGACY_ENG/custodexa.sh" restore --resume --yes --lang en </dev/null
    echo "legacy resume $kind: status=$status result=$(perm_result)" >&3
    [ "$status" = 0 ] && [ "$(env_jwt)" = "$new" ] && [ "$(legacy_calls)" = 1 ] || { echo "$output"; return 1; }

    LEGACY_RC=1 legacy_flow_start "$kind" ""
    [ "$status" = 1 ] && [ "$(phase)" = imported ] && [[ $output == *'could not all be revoked'* ]] || { echo "legacy fail $kind: $status $output"; return 1; }
    new=$(env_jwt)
    [ -n "$new" ] && [ "$new" != "$LEGACY_OLD_JWT" ] && [ "$(legacy_record)" = "" ] || return 1
    rm -f "$DB/legacy.rc"
    run bash "$LEGACY_ENG/custodexa.sh" restore --resume --yes --lang en </dev/null
    echo "legacy fail-resume $kind: status=$status result=$(perm_result)" >&3
    [ "$status" = 0 ] && [ "$(env_jwt)" = "$new" ] && [ "$(legacy_calls)" = 2 ] || { echo "$output"; return 1; }
  done
}

# ---- The downgrade boundary. The deployment is the one an upgrade by the script left (the
# rollback host of test_rollback_judge.bats); the migration under test is the one the code registers.
st() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }
judge_base() {
  backup_host ui
  : >"$DB/events"
  : >"$DB/db-calls"
}
# switched <from> <to> <result> <step>: captured from a real upgrade, including its records and snapshot.
switched() {
  local outcome=ready
  case $4 in 7) outcome=backup ;; 9) outcome=switch-linked ;; 10) outcome=start ;; esac
  rb_cached "$outcome" ui "$1" "$2"
}
# decide <function...>: run the decision functions on $ROOT; prints the variables they set.
decide() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/backup.sh"
    . "$1/lib/rollback_check.sh"; CX_ROOT=$2; cx_bk_vars; cx_state_load "$2/state.json"; shift 2
    rc=0; for f in "$@"; do "$f" || { rc=$?; break; }; done
    printf "basis=%s reason=%s added=%s\n" "$CX_RB_BASIS" "$CX_RB_REASON" "${CX_RB_ADDED[*]+"${CX_RB_ADDED[*]}"}"
    exit "$rc"' _ "$SRC" "$ROOT" "$@"
}
# lists <to> <version> [model]: the release <to> lists <version> as one it can go straight back to, and
# (third argument) also carries the permission model migration in its MANIFEST, as a wrongly built one would.
lists() {
  local mf=$ROOT/releases/$1/MANIFEST.json
  jq --arg v "$2" '.rollback_compatible = [$v]' "$mf" >"$BATS_TEST_TMPDIR/m"
  if [ "${3:-}" = model ]; then
    jq --arg m "$MODEL_MIG" '.migrations += [$m] | .migrations |= unique' "$BATS_TEST_TMPDIR/m" >"$BATS_TEST_TMPDIR/m2"
    cp "$BATS_TEST_TMPDIR/m2" "$BATS_TEST_TMPDIR/m"
  fi
  cp "$BATS_TEST_TMPDIR/m" "$mf"
}

@test "permission downgrade boundary" {
  local mig=$MODEL_MIG
  grep -q "Version: \"$mig\"" "$SRC/../../backend/internal/database/migrations.go" || { echo "migration $mig not registered"; return 1; }

  # 1. The new model is applied and the release lists the version before: still refused. The listing
  #    cannot buy a way back across the model, with the database readable (the migration is named) ...
  switched 1.17.9 1.18.0 succeeded 13
  printf '%s\n' "$mig" >>"$DB/migrations"
  lists 1.18.0 1.17.9
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"basis= reason=changed added=$mig"* ]] || { echo "$output"; return 1; }
  #    ... and with the database unreadable (nothing to tell the model is there but the two manifests,
  #    of which the release's lists the migration).
  lists 1.18.0 1.17.9 model
  printf '1\n' >"$DB/migrations.rc"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"basis= reason=unreadable "* ]] || { echo "$output"; return 1; }
  rm -f "$DB/migrations.rc"
  #    The decision stops nothing: only reads were made.
  ! grep -Eq '^(stop|up|start)' "$DB/events" || { cat "$DB/events"; return 1; }
  #    An old release that cannot be read cannot show it has the model either: refused, not allowed.
  mv "$ROOT/releases/1.17.9/MANIFEST.json" "$BATS_TEST_TMPDIR/old.manifest"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 1 ] && [[ $output == *"basis= "* ]] || { echo "$output"; return 1; }
  mv "$BATS_TEST_TMPDIR/old.manifest" "$ROOT/releases/1.17.9/MANIFEST.json"

  # 2. The same through the command: refused, nothing changed, nothing started, and the guidance
  #    names the restore command and a backup taken before the upgrade; it never restores by itself.
  : >"$DB/events"
  cp "$ROOT/state.json" "$DB/before"
  rb_run en --yes
  [ "$status" -eq 3 ] && [[ $output == *"$mig"* ]] && [[ $output == *"custodexa.sh restore "* ]] || { echo "$output"; return 1; }
  cmp "$ROOT/state.json" "$DB/before"
  [ "$(readlink "$ROOT/current")" = releases/1.18.0 ]
  ! grep -Eq '^(stop|up|start|restore)' "$DB/events" || { cat "$DB/events"; return 1; }
  local snap
  snap=$(st last_upgrade.backup_file)
  [ -z "$snap" ] || [ -e "$ROOT/$snap" ] || { echo "guidance names a backup that is not there: $snap"; return 1; }

  # 3. The last check is the same rule. A preview that passed (the database was as before the
  #    upgrade), then the model arrives before the old version starts: the stop happened, the old
  #    version does not start, the record says refused.
  switched 1.17.9 1.18.0 succeeded 13
  lists 1.18.0 1.17.9
  rb_interrupt cx_rb_stop_apps after
  rb_run en --yes
  [ "$status" -eq 1 ]
  printf '%s\n' "$mig" >>"$DB/migrations"
  : >"$DB/events"
  rb_run en --resume
  [ "$status" -eq 1 ] && [ "$(st last_rollback.result)" = refused ] || { echo "$output"; return 1; }
  ! grep -Eq '^up|^stop postgres' "$DB/events" || { cat "$DB/events"; return 1; }
  [ "$(readlink "$ROOT/current")" = releases/1.18.0 ]

  # 4. The rules that stay: a new version that never started leaves the database as it was (no
  #    database call at all), and a release that lists the version before without the model between
  #    them is honoured as before.
  switched 1.17.9 1.18.0 failed 9
  : >"$DB/db-calls"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=not_started "* ]] && [ ! -s "$DB/db-calls" ] || { echo "$output"; return 1; }
  switched 1.16.1 1.16.2 succeeded 13
  printf '%s\n' 20261101_session_tag_index >>"$DB/migrations"
  jq '.rollback_compatible = ["1.16.1"]' "$ROOT/releases/1.16.2/MANIFEST.json" >"$BATS_TEST_TMPDIR/m"
  cp "$BATS_TEST_TMPDIR/m" "$ROOT/releases/1.16.2/MANIFEST.json"
  decide cx_rb_premise cx_rb_judge
  [ "$status" -eq 0 ] && [[ $output == *"basis=compatible "* ]] || { echo "$output"; return 1; }

  # 5. The data side: a backup of the new model into a release that does not know the model migration
  #    is refused by the original checks before anything stops; so is a summary with a model or
  #    snapshot version the scripts do not know, and one with a key missing.
  #    (the other two rows are in test_restore_migrations.bats, a snapshot migration the release does
  #    not list, and in the lifecycle test above, the incomplete summary. Here: the versions.)
  local m
  for m in "authz.model=2" "authz.snapshot=2" "authz.model=legacy"; do
    run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/backup.sh"
      text=$(printf "%s\n" "authz.model=1" "authz.snapshot=1" "authz.catalog=0123456789abcdef" "authz.digest=0123456789abcdef" \
        "authz.version=7" "authz.refs=ok" "authz.count.roles=1" "authz.count.user_roles=1" "authz.count.group_roles=1" \
        "authz.count.binding_nodes=1" "authz.count.nodes=1" "authz.count.role_maps=1" "authz.count.group_maps=1" \
        "authz.count.members=1" "authz.count.groups=1" "authz.count.principals=1")
      cx_snap_authz_valid "$text" && cx_snap_authz_known "$text" || exit 90   # the summary as written is read
      text=$(printf "%s\n" "$text" | sed "s/^${2%%=*}=.*/$2/")
      if cx_snap_authz_valid "$text" && cx_snap_authz_known "$text"; then echo accepted; exit 0; fi
      echo refused' _ "$SRC" "$m"
    [ "$status" -eq 0 ] && [ "$output" = refused ] || { echo "$m: status=$status $output"; return 1; }
  done

  # 6. Building: a release that carries the model migration cannot list an earlier version, record or
  #    not. The build stops and writes no MANIFEST.json; a release that does not carry it lists as before.
  build_boundary_fixture
  build_boundary --rollback-compatible 1.16.1 --rehearsals-dir "$REC"
  [ "$status" -ne 0 ] && [ ! -e "$OUT/MANIFEST.json" ] && [[ $output == *"--rollback-compatible 1.16.1: this release carries the data model migration $mig"* ]] \
    || { echo "$status $output"; return 1; }
  build_boundary
  [ "$status" -eq 0 ] && [ "$(jq -c .rollback_compatible "$OUT/MANIFEST.json")" = '[]' ] || { echo "$output"; return 1; }
  sed -i "/$mig/d" "$S/backend/internal/database/migrations.go"
  build_boundary --rollback-compatible 1.16.1 --rehearsals-dir "$REC"
  [ "$status" -eq 0 ] && [ "$(jq -c .rollback_compatible "$OUT/MANIFEST.json")" = '["1.16.1"]' ] || { echo "$output"; return 1; }
}

# build_boundary_fixture: the build script in a repository layout of its own and a public tree whose
# migrations include the model migration; one complete rehearsal record for 1.16.1 (the record is
# what lets a list through today, so the refusal must come from the boundary and not from it).
build_boundary_fixture() {
  local V=1.16.2 B F
  B=sha256:$(printf 'b%.0s' {1..64}) F=sha256:$(printf 'f%.0s' {1..64})
  R=$BATS_TEST_TMPDIR/bnd-repo S=$BATS_TEST_TMPDIR/bnd-public REC=$BATS_TEST_TMPDIR/bnd-rehearsals OUT=$BATS_TEST_TMPDIR/bnd-out
  mkdir -p "$R/scripts/release" "$REC" "$S/docker/reverse-proxy" "$S/backend/internal/database" "$S/scripts/release"
  cp "$SRC/../release/build-package.sh" "$SRC/../release/migrations-json.sh" "$R/scripts/release/"
  ln -s "$SRC" "$R/scripts/custodexa"
  ln -s "$SRC/../../packaging" "$R/packaging"
  printf 'DB_USER=postgres\n' >"$S/.env.example"
  printf '#!/bin/sh\n' >"$S/docker/reverse-proxy/tls-init.sh"
  printf 'server {}\n' >"$S/docker/reverse-proxy/nginx-tls.conf.template"
  printf '%s\n' 'package database' 'const BaselineVersion = "20260816_schema_baseline"' \
    'var migrations = []Migration{' '	{Version: "20260816_schema_baseline"},' "	{Version: \"$MODEL_MIG\"}," '}' \
    'const LdapSeedMarkerVersion = "20260804_ldap_env_seeded"' \
    'const OffsiteSeedMarkerVersion = "20260825_offsite_env_seeded"' \
    'const CredentialSecretsMarkerVersion = "20260906_credential_secrets_converted"' \
    'const ApproverScopeKeyMarkerVersion = "20261030_approver_scope_management_key"' \
    'var runtimeMarkerVersions = []string{' '	LdapSeedMarkerVersion,' '	OffsiteSeedMarkerVersion,' \
    '	CredentialSecretsMarkerVersion,' '	ApproverScopeKeyMarkerVersion,' '}' \
    >"$S/backend/internal/database/migrations.go"
  jq -n --arg v "$V" --arg b "$B" --arg f "$F" '{version: $v, images: {
      backend: {digest: $b, ghcr: ("ghcr.io/custodexa/backend@" + $b)},
      frontend: {digest: $f, ghcr: ("ghcr.io/custodexa/frontend@" + $f)}}}' >"$BATS_TEST_TMPDIR/bnd-digests.json"
  jq -n --arg c "sha256:$(printf 'c%.0s' {1..64})" '{
      manifests: [{platform: {os: "linux", architecture: "amd64"}, digest: $c},
                  {platform: {os: "linux", architecture: "arm64"}, digest: $c}],
      config: {digest: $c, size: 10}, layers: [{size: 100}]}' \
    >"$FAKE_DOCKER_REPLAY/buildx_imagetools_inspect_--raw.out"
  printf '%s\n' PASS "date: 2026-11-02" "operator: release-operator" "from: 1.16.1" "to: $V" \
    "to_backend_digest: $B" "to_frontend_digest: $F" \
    "step1_upgrade: PASS sudo /opt/custodexa/custodexa.sh upgrade $V --yes" \
    "step2_write: PASS users, assets, a recorded connection, a policy change" \
    "step3_rollback: PASS sudo /opt/custodexa/custodexa.sh rollback --yes" \
    "step4_old_readwrite: PASS the same reads and writes on 1.16.1, no error in the logs" >"$REC/$V-from-1.16.1.txt"
}
build_boundary() {
  rm -rf "$OUT"
  run bash "$R/scripts/release/build-package.sh" --digests "$BATS_TEST_TMPDIR/bnd-digests.json" --source "$S" \
    --out "$OUT" --released-at 2026-11-02T10:00:00+08:00 "$@"
}
