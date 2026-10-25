# shellcheck shell=bash
# CX_DB_RELEASE and CX_OVERLAYS are read by the shared database client.
# shellcheck disable=SC2034
# Check the imported data before any backend process can write to it.
cx_rs_db_check_fail() {
  local step=7 total=10 text
  [ "$CX_RS_FLOW" != new ] || { step=$((4 + $(cx_rs_ext_shift))); total=$(cx_rs_steps_total); }
  text=$(cx_msg "rs_db_check_$1" "${@:2}")
  cx_line FAIL " $step/$total  $text"
  cx_rs_failure
}
# The permission model checks, after the migrations, counts and master key matched:
# the backend compares the imported permission state with the backup's digest (original state,
# before anything is changed), checks the references and the last local administrator, and only
# then commits the restore transaction (a new restore generation). One backend call does all of it,
# so nothing is written when any check refuses. A resume after the commit is told apart by the
# operation ID and the dump's digest: the same transaction is never committed twice.
# A legacy set (no permission model) has nothing to do here.
cx_rs_perm_restore() {
  local snap=$CX_RS_DIR/pass2/snapshot.txt out rc=0 sum findings codes line
  case $(cx_snap_get "$snap" authz.model) in '' | legacy) return 0 ;; esac
  sum=$(sha256sum -- "$CX_RS_DIR/pass2/db.dump") || { cx_rs_db_check_fail read; return 1; }
  out=$(cx_snap_backend permission-restore --op-id "$CX_RS_TS" --input-digest "${sum%% *}" \
    --expect-digest "$(cx_snap_get "$snap" authz.digest)") || rc=$?
  case $rc in
    0) cx_log CHECK "permission restore $(printf '%s' "$out" | tr '\n' ' ')" ;;
    3)
      findings=$(printf '%s\n' "$out" | sed -n 's/^finding=//p')
      codes=$(printf '%s\n' "$findings" | cut -d: -f1 | LC_ALL=C sort -u | head -n 3 | paste -sd ',')
      while IFS= read -r line; do cx_log CHECK "permission restore refused: $line"; done <<<"$findings"
      cx_rs_db_check_fail authz_refs "$(printf '%s' "$codes")"
      return 1 ;;
    4) cx_rs_db_check_fail authz_conflict; return 1 ;;
    5)
      cx_rs_db_check_fail authz "$(printf '%s\n' "$out" | sed -n 's/^mismatch.actual=//p' | cut -c1-12)" \
        "$(printf '%s\n' "$out" | sed -n 's/^mismatch.expected=//p' | cut -c1-12)"
      return 1 ;;
    *) cx_rs_db_check_fail read; return 1 ;;
  esac
}
# Going back to a version without the permission model: such a version knows no restore
# generation, so the backup's sessions would come back alive. This is the case when the data set
# has no permission model while the scripts doing the restore know it (their manifest lists the
# migration). A restore among versions that have no model keeps the backup's settings as they are.
# Two things close the gap. The sign-in secret of the settings to restore was replaced when they
# were merged (cx_rs_legacy_rotate, before anything is placed: the journal compares the placed file
# by its digest), and here, after the original checks, one transaction revokes every refresh token,
# agent token and temporary grant (ticket and break-glass) of the imported data. Nothing is
# printed of the secret; only its fingerprint goes into the restore record. The checks stop the
# restore when either part is missing.
cx_rs_legacy() {
  [ -f "$CX_RS_DIR/pass2/snapshot.txt" ] && [ -f "$CX_DIR/MANIFEST.json" ] || return 1
  case $(cx_snap_get "$CX_RS_DIR/pass2/snapshot.txt" authz.model) in '' | legacy) ;; *) return 1 ;; esac
  grep -qF "\"$CX_SNAP_AUTHZ_MIGRATION\"" "$CX_DIR/MANIFEST.json"
}
cx_rs_legacy_return() {
  local old new
  cx_rs_legacy || return 0
  old=$(cx_env_get "$CX_RS_DIR/pass2/env.bak" JWT_SECRET)
  new=$(cx_env_get "$CX_RS_DIR/env.merged" JWT_SECRET)
  if [ -z "$new" ] || [ "$new" = "$old" ]; then cx_rs_db_check_fail legacy_secret; return 1; fi
  cx_db sql "DO \$\$ BEGIN
 IF to_regclass('public.refresh_tokens') IS NOT NULL THEN
  UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'restore' WHERE revoked_at IS NULL;
  IF EXISTS (SELECT 1 FROM refresh_tokens WHERE revoked_at IS NULL) THEN RAISE EXCEPTION 'refresh tokens'; END IF;
 END IF;
 IF to_regclass('public.agent_tokens') IS NOT NULL THEN
  UPDATE agent_tokens SET revoked_at = now(), revoke_note = 'restore' WHERE revoked_at IS NULL;
  IF EXISTS (SELECT 1 FROM agent_tokens WHERE revoked_at IS NULL) THEN RAISE EXCEPTION 'agent tokens'; END IF;
 END IF;
 IF to_regclass('public.asset_authorizations') IS NOT NULL THEN
  UPDATE asset_authorizations SET date_expired = now()
   WHERE source = 'ticket' AND deleted_at IS NULL AND (date_expired IS NULL OR date_expired > now());
  IF EXISTS (SELECT 1 FROM asset_authorizations WHERE source = 'ticket' AND deleted_at IS NULL
   AND (date_expired IS NULL OR date_expired > now())) THEN RAISE EXCEPTION 'temporary grants'; END IF;
 END IF;
END \$\$" >/dev/null || { cx_rs_db_check_fail legacy_revoke; return 1; }
  if ! cx_state_set last_restore.legacy_return "secret=$(cx_snap_fp "$new") revoked=refresh,agent,ticket" || ! cx_rs_save; then
    cx_rs_db_check_fail legacy_revoke; return 1
  fi
  cx_line OK "$(cx_msg rs_legacy_return_ok)"
}
cx_rs_db_check() {
  local CX_DB_RELEASE=$CX_ROOT/releases/$CX_RS_VERSION
  local rows digest count table expected got extra missing detail
  [ "$(cx_rs_phase_value)" = imported ] || return 1
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  # The import ran in a job of its own: the database account is read here too (a new host, or a
  # run that carries on after the import, sets it nowhere else).
  cx_bk_vars
  # An external database: the client and connection chosen here too (a run that starts after
  # the checks, such as going back with the safety backup, chose none yet).
  if cx_rs_ext && ! cx_rs_ext_with cx_rs_ext_ready; then cx_rs_db_check_fail read; return 1; fi
  rows=$(cx_db sql 'SELECT version FROM schema_migrations ORDER BY version') || { cx_rs_db_check_fail read; return 1; }
  rows=$(printf '%s\n' "$rows" | LC_ALL=C sort)
  count=$(printf '%s\n' "$rows" | grep -c .) || true
  digest=$(printf '%s\n' "$rows" | sha256sum)
  if [ "$count" != "$(cx_rs_get db.migrations_count)" ] || [ "${digest%% *}" != "$(cx_rs_get db.migrations_sha256)" ]; then
    extra=$(comm -13 <(cx_snap_migrations "$CX_RS_DIR/pass2/snapshot.txt" | LC_ALL=C sort) <(printf '%s\n' "$rows"))
    missing=$(comm -23 <(cx_snap_migrations "$CX_RS_DIR/pass2/snapshot.txt" | LC_ALL=C sort) <(printf '%s\n' "$rows"))
    detail=""
    if [ -n "$extra" ]; then
      detail=$(cx_msg rs_db_extra "$(printf '%s\n' "$extra" | wc -l)" "$(printf '%s\n' "$extra" | paste -sd ',')")
    fi
    if [ -n "$missing" ]; then
      detail+="${detail:+; }$(cx_msg rs_db_missing "$(printf '%s\n' "$missing" | wc -l)" "$(printf '%s\n' "$missing" | paste -sd ',')")"
    fi
    cx_rs_db_check_fail migrations "$detail"; return 1
  fi
  for table in users sessions audit_logs; do
    expected=$(cx_snap_get "$CX_RS_DIR/pass2/snapshot.txt" "count.$table")
    got=$(cx_db sql "SELECT count(*) FROM $table") || { cx_rs_db_check_fail read; return 1; }
    if ! [[ $got =~ ^[0-9]+$ ]] || [ "$got" != "$expected" ]; then
      cx_rs_db_check_fail counts "$table" "$got" "$expected"; return 1
    fi
  done
  got=$(cx_db sql "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1") || { cx_rs_db_check_fail read; return 1; }
  if [ -z "$got" ] || [[ $got == *$'\n'* ]] || [ "$got" != "$(cx_rs_get kek.fingerprint)" ]; then
    cx_rs_db_check_fail kek "$got" "$(cx_rs_get kek.fingerprint)"; return 1
  fi
  cx_rs_perm_restore || return 1
  cx_rs_legacy_return || return 1
  cx_rs_phase db_checked
}
