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
  cx_rs_phase db_checked
}
