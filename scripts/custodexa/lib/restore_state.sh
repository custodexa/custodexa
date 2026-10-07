# shellcheck shell=bash
# Durable restore records and recovery context. The entry connects these only once all
# execution stages exist; preview and confirmation alone never start a durable restore.
# shellcheck disable=SC2034,SC2153
CX_RS_PHASE=""
cx_rs_save() { cx_state_save "$CX_ROOT/state.json"; }
cx_rs_record() {
  local key digest handed=0
  cx_run_switched_only restore && handed=1
  digest=$(sha256sum -- "$CX_RS_FILE") || return 1
  digest=${digest%% *}
  cx_rs_preserve_before || return 1
  # The caller already owns the deployment lock and has opened the restore log.
  for key in "${CX_STATE_KEYS[@]}"; do [[ $key != last_restore.* ]] || cx_state_unset "$key"; done
  cx_state_set last_restore.result in_progress || return 1
  cx_state_set last_restore.phase checked || return 1
  cx_state_set last_restore.flow "$CX_RS_FLOW-host" || return 1
  cx_state_set last_restore.purpose restore || return 1
  cx_state_set last_restore.file "$CX_RS_FILE" || return 1
  cx_state_set last_restore.file_sha256 "$digest" || return 1
  cx_state_set last_restore.checksum "$CX_RS_CHECKSUM" || return 1
  cx_state_set last_restore.product_version "$CX_RS_VERSION" || return 1
  if [ "$CX_RS_ENGINE" = "$CX_RS_VERSION" ] &&
    [ "$(readlink -f -- "$CX_ROOT/custodexa.sh")" = "$(readlink -f -- "$CX_DIR/custodexa.sh")" ]; then
    key=$CX_ROOT/custodexa.sh
  else key=$CX_ROOT/releases/$CX_RS_ENGINE/custodexa.sh; fi
  cx_state_set last_restore.engine "$key" || return 1
  cx_state_set last_restore.stamp "$CX_RS_TS" || return 1
  cx_state_set last_restore.staging "$CX_RS_DIR" || return 1
  cx_state_set last_restore.prev_version "$(cx_state_get current.version)" || return 1
  cx_state_set last_restore.kek_provider "$(cx_rs_get kek.provider)" || return 1
  cx_state_set last_restore.kek_fingerprint "$(cx_rs_get kek.fingerprint)" || return 1
  for key in safety safety_file safety_ref safety_time safety_restore stopped_at covering db_covering exit kek_mismatch kek_evidence; do
    cx_state_set "last_restore.$key" '' || return 1
  done
  cx_state_set last_restore.services running || return 1
  [ "$CX_RS_FLOW" != new ] || cx_state_set last_restore.services all-stopped || return 1
  cx_state_set last_restore.log "${CX_LOG_FILE#"$CX_ROOT"/}" || return 1
  cx_state_set last_restore.step 0 || return 1
  cx_state_set last_restore.started_at "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
  if [ "$handed" = 1 ]; then
    cx_run_upgrade_handed
    cx_log PREVIOUS "upgrade result=interrupted step=$(cx_state_get last_upgrade.step) handed_to=restore"
  fi
  cx_rs_save || return 1
  CX_RUN_CMD=restore CX_RUN_STEP=0 CX_RS_PHASE=checked
}
# Only a completed stage advances phase. The step is the visible work in progress; callers
# record it before doing that work. A failed save stops the caller before the next operation.
cx_rs_step() {
  cx_state_set last_restore.step "$1" && cx_rs_save || return 1
  CX_RUN_STEP=$1
}
cx_rs_phase_value() {
  if [ -n "${CX_RS_PHASE_FILE:-}" ]; then cat "$CX_RS_PHASE_FILE"
  else cx_state_get last_restore.phase; fi
}
cx_rs_phase() {
  case $1 in checked|prepared|safety|stopped|swapped|imported|db_checked|placed|started|awaiting_unseal|done) ;; *) return 1 ;; esac
  if [ -n "${CX_RS_PHASE_FILE:-}" ]; then
    (umask 077; printf '%s\n' "$1" >"$CX_RS_PHASE_FILE.tmp") && sync -f "$CX_RS_PHASE_FILE.tmp" &&
      mv -- "$CX_RS_PHASE_FILE.tmp" "$CX_RS_PHASE_FILE" && sync -f "${CX_RS_PHASE_FILE%/*}" && cx_rs_save || return 1
  else cx_state_set last_restore.phase "$1" && cx_rs_save || return 1; fi
  CX_RS_PHASE=$1
}
cx_rs_services() {
  case $1 in running|app-stopped|all-stopped|starting|up) ;; *) return 1 ;; esac
  cx_state_set last_restore.services "$1" || return 1
  cx_rs_save
}
# Called only after the application stop has been confirmed, never for its intent.
cx_rs_apps_stopped() {
  [ -n "$(cx_state_get last_restore.stopped_at)" ] ||
    cx_state_set last_restore.stopped_at "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
  cx_rs_services app-stopped
}
cx_rs_leaving() {
  case $1 in reverting|abandoning) ;; *) return 1 ;; esac
  cx_state_set last_restore.exit "$1" && cx_rs_save
}
cx_rs_settle() {
  case $1 in succeeded|reverted|abandoned) ;; *) return 1 ;; esac
  cx_state_set last_restore.result "$1" || return 1
  cx_state_set last_restore.finished_at "$(date '+%Y-%m-%dT%H:%M:%S%z')" || return 1
  cx_state_unset last_restore.exit
  cx_state_unset last_restore.covering
  cx_rs_save
}
# Restore identity from state rather than accepting replacement input on --resume. Staging
# integrity and journal reconciliation are performed by the execution stages before any work.
cx_rs_recover_context() {
  [ "$(cx_state_get last_restore.result)" = in_progress ] || return 1
  cx_run_restore_guard restore "${CX_RS_ACTION:-resume}" || return 1
  CX_RS_PHASE=$(cx_state_get last_restore.phase) CX_RUN_STEP=$(cx_state_get last_restore.step)
  CX_RS_FLOW=$(cx_state_get last_restore.flow); CX_RS_FLOW=${CX_RS_FLOW%-host}
  CX_RS_FILE=$(cx_state_get last_restore.file) CX_RS_DIR=$(cx_state_get last_restore.staging)
  CX_RS_TS=$(cx_state_get last_restore.stamp) CX_RS_VERSION=$(cx_state_get last_restore.product_version)
  CX_RS_ENGINE=$(cat "$CX_DIR/VERSION") CX_RS_CHECKSUM=$(cx_state_get last_restore.checksum)
  CX_RUN_CMD=restore
}
