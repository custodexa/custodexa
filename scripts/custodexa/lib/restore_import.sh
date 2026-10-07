# shellcheck shell=bash
# Only the data release's postgres service runs during import. A failed attempt is retained
# under a numbered name before a fresh empty cluster is started on the next attempt.
# shellcheck disable=SC2034,SC2015
cx_rs_import_mark() {
  (umask 077; printf '%s %s\n' "$1" "$2" >"$CX_RS_DIR/import-attempt.tmp") &&
    sync -f "$CX_RS_DIR/import-attempt.tmp" && mv -- "$CX_RS_DIR/import-attempt.tmp" "$CX_RS_DIR/import-attempt" &&
    sync -f "$CX_RS_DIR"
}
cx_rs_import_fail() {
  local line detail="" key=rs_import_error
  if [ "$1" != failed ]; then cx_line FAIL "$(cx_msg "rs_import_$1")"; return 1; fi
  cx_rs_progress_end import FAIL
  if [ -f "$CX_RS_DIR/import.err" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      cx_log OUT "$line"
      if [ -z "$detail" ] && [[ $line == *ERROR:* ]]; then
        detail=$(cx_mask "ERROR:${line#*ERROR:}")
      fi
    done <"$CX_RS_DIR/import.err"
  fi
  [ -z "$detail" ] || key=rs_import_error_detail
  printf '       %s\n' "$(cx_msg "$key")"
  [ -z "$detail" ] || printf '       %s\n' "$detail"
  return 1
}
cx_rs_db_import() {
  local attempt=1 stage=running extra active row expected tries=0 max line
  local CX_DB_RELEASE=$CX_ROOT/releases/$CX_RS_VERSION
  case $(cx_rs_phase_value) in
    imported|db_checked|placed|started|awaiting_unseal|done) return 0 ;;
    swapped) ;; *) return 1 ;;
  esac
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  cx_bk_vars
  if cx_db_external; then cx_rs_ext_import; return; fi
  cx_rs_recovery_route resume || return 1
  if [ -f "$CX_RS_DIR/import-attempt" ]; then
    read -r attempt stage extra <"$CX_RS_DIR/import-attempt" || return 1
    [[ $attempt =~ ^[1-9][0-9]*$ && -z $extra ]] || return 1
    case $stage in
      running) attempt=$((attempt + 1)); cx_rs_import_mark "$attempt" reset || return 1 ;;
      reset) ;; *) return 1 ;;
    esac
    cx_rs_services all-stopped || return 1
    cx_compose_release "$CX_DB_RELEASE" stop postgres >/dev/null 2>&1 || return 1
    active=$(cx_compose_release "$CX_DB_RELEASE" ps --status running --services) || return 1
    ! grep -qx postgres <<<"$active" || return 1
    cx_rs_journal "postgres-partial-$attempt" move "$CX_RS_DATA/postgres" \
      "$CX_RS_DATA/postgres.partial-restore-$CX_RS_TS-$((attempt - 1))" &&
      cx_rs_journal "postgres-empty-$attempt" mkdir "$CX_RS_DATA/postgres" 0700 || return 1
  fi
  cx_rs_import_mark "$attempt" running && cx_rs_services app-stopped || return 1
  cx_compose_release "$CX_DB_RELEASE" up -d postgres >/dev/null 2>&1 || { cx_rs_import_fail start; return 1; }
  max=$(cx_ready_tries)
  until cx_db ready >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt "$max" ] || { cx_rs_import_fail ready; return 1; }
    sleep "$CX_UP_READY_WAIT"
  done
  row=$(cx_db sql 'SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = current_database()') || {
    cx_rs_import_fail encoding; return 1;
  }
  expected="$(cx_rs_get db.encoding)|$(cx_rs_get db.collate)|$(cx_rs_get db.ctype)"
  [ "$row" = "$expected" ] || { cx_rs_import_fail encoding; return 1; }
  cx_db restore <"$CX_RS_DIR/pass2/db.dump" 2>"$CX_RS_DIR/import.err" || { cx_rs_import_fail failed; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    cx_log OUT "$line"
    printf '%s\n' "$(cx_mask "$line")" >&2
  done <"$CX_RS_DIR/import.err"
  cx_rs_phase imported
}
