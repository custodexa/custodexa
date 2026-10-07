#!/usr/bin/env bash
# Rendering fixtures: production screen functions, with deterministic storage and service I/O.
# Message, indentation, duration and recovery formatters are never replaced.
# The progress cases isolate engine orchestration; stage behavior has its own tests.
. "$1/lib/common.sh"
CX_LANG_FLAG=$3 CX_NO_COLOR=1
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_LANG_FLAG="" CX_ROOT=$2 CX_DIR=$2/current CX_SELF=$2/custodexa.sh
CX_RS_TS=20261012-093015 CX_RS_DIR=$2/restore/20261012-093015
CX_RS_DATA=$2/data CX_RS_VERSION=1.16.0 CX_RS_ENGINE=1.16.2 CX_RS_FLOW=same
CX_LOG_FILE=$2/logs/restore-20261012-093015.log
CX_RS_FILE=custodexa-backup-1.16.0-20261005-101502.tar.enc
mkdir -p "$CX_RS_DIR/pass2" "$CX_ROOT/logs" "$CX_RS_DATA" "$CX_DIR"
printf '1.16.2\n' >"$CX_DIR/VERSION"
printf 'PUBLIC_BASE_URL=https://10.0.0.31\n' >"$CX_ROOT/.env"
CX_RS_MAP=([product.version]=1.16.0 [created_at]=2026-10-05T10:15:02Z
  [kek.provider]=ui [kek.fingerprint_status]=ok [kek.fingerprint]=5a5a5a5a5a5a5a5a
  [contents.recordings]=false [contents.tls]=true [source.data_path]=/data/custodexa)
cx_state_set last_restore.result in_progress
cx_state_set last_restore.flow same-host
cx_state_set last_restore.phase awaiting_unseal
cx_state_set last_restore.step 6
cx_state_set last_restore.engine "$CX_ROOT/custodexa.sh"
cx_state_set last_restore.covering 1
cx_state_set last_restore.safety script
cx_state_set last_restore.safety_file "backups/custodexa-backup-1.16.0-$CX_RS_TS.tar"
cx_state_set last_restore.stamp "$CX_RS_TS"
cx_state_set last_restore.prev_version 1.16.0
cx_state_set last_restore.stopped_at 2026-10-12T09:31:00Z
CX_RUN_STEP=6
cx_rs_save
# These adapters are storage/service observations, not presentation functions.
cx_compose_release() {
  case " $* " in
    *'/api/v1/seal/status '*) printf '%s\n' "$SCREEN_SEAL" ;;
    *' ps --status running --services '*) return 0 ;;
    *) return 99 ;;
  esac
}
case $4 in
  checksum-missing) (cd "$CX_ROOT"; cx_rs_sidecar); exit $? ;;
  passphrase)
    CX_RS_ENC=1
    CX_RS_FILE=$CX_RS_DIR/input.tar.enc
    truncate -s 32 "$CX_RS_FILE"
    cx_rs_openssl_image() { :; }
    cx_rs_pass() { :; }
    cx_rs_first_pass; exit $? ;;
  read-progress)
    CX_RS_FILE=$CX_ROOT/transfer/custodexa-backup-1.16.0-20261005-101502.tar.enc
    mkdir -p "${CX_RS_FILE%/*}"
    printf Salted__ >"$CX_RS_FILE"
    (cd "${CX_RS_FILE%/*}"; sha256sum "${CX_RS_FILE##*/}" >"$CX_RS_FILE.sha256")
    printf 'JWT_SECRET=screen-token\nDB_PASSWORD=screen-password\n' >"$CX_RS_DIR/pass2/env.bak"
    printf 'fp.jwt=%s\n' "$(cx_snap_fp screen-token)" >"$CX_RS_DIR/pass2/snapshot.txt"
    (cd "$CX_RS_DIR/pass2"; sha256sum env.bak snapshot.txt >SHA256SUMS)
    seq 11 >"$CX_RS_DIR/list1"; : >"$CX_RS_DIR/sums1"
    cx_rs_first_pass() { :; }
    cx_rs_member_check() { :; }
    cx_rs_cross() { :; }
    cx_rs_inner() { :; }
    cx_rs_pass() { cp "$CX_RS_DIR/list1" "$CX_RS_DIR/list2"; cp "$CX_RS_DIR/sums1" "$CX_RS_DIR/sums2"; }
    cx_rs_grants() { :; }
    printf '0\n182\n182\n349\n' >"$CX_RS_DIR/times"
    cx_now() { head -n1 "$CX_RS_DIR/times"; sed -i 1d "$CX_RS_DIR/times"; }
    cx_rs_open "$CX_RS_FILE" && cx_rs_checks; exit $? ;;
  old-folder)
    CX_RS_FILE=$CX_ROOT/backups/20260930-021504
    mkdir -p "$CX_RS_FILE"
    cx_rs_old_file; exit $? ;;
  corrupt-file) cx_rs_bad hash db.dump; exit $? ;;
  fingerprint-missing) CX_RS_MAP[kek.fingerprint_status]=missing; cx_rs_checks; exit $? ;;
  settings-key-mismatch)
    CX_RS_MAP[kek.provider]=env
    cx_rs_key_fingerprint() { CX_RS_KEY_FP=1f2e3d4c5b6a7980; }
    cx_rs_checks; exit $? ;;
  release-mismatch) cx_rs_release_bad rs_release_manifest 1.16.0; exit $? ;;
  engine-too-old) CX_RS_ENGINE=1.16.0 CX_RS_VERSION=1.16.2; cx_rs_checks; exit $? ;;
  unsupported-key) CX_RS_MAP[kek.provider]=hsm; cx_rs_checks; exit $? ;;
  host-values)
    CX_RS_FLOW=new
    CX_RS_MAP[deploy.tls_mode]=selfsigned CX_RS_MAP[deploy.overlays]=""
    printf 'COMPOSE_PROJECT_NAME=custodexa\nCOMPOSE_FILE=current/compose.yml\nDATA_PATH=/data/custodexa\nTLS_DOMAIN=bastion-a.example.internal\nTLS_IP_SAN=10.0.0.12\nPUBLIC_BASE_URL=https://10.0.0.12\n' >"$CX_RS_DIR/pass2/env.bak"
    cx_env_host_fqdn() { printf bastion-b.example.internal; }
    cx_env_host_ipv4s() { printf 10.0.0.31; }
    cx_rs_env_merge; exit $? ;;
  space-short)
    CX_RS_BYTES=$((20 * CX_GIB))
    CX_RS_MAP[size.db_bytes]=$((18 * CX_GIB)) CX_RS_MAP[size.audit_bytes]=0
    cx_mount_of() { case $1 in */data) printf /data ;; *) printf /opt ;; esac; }
    cx_free_bytes() { case $1 in */data) echo $((300 * CX_GIB)) ;; *) echo $((40 * CX_GIB)) ;; esac; }
    cx_bk_vars() { :; }
    cx_bk_estimate() { :; }
    cx_pb_space() { CX_BK_NEED=$((34 * CX_GIB)); }
    cx_bk_minutes() { echo 12; }
    cx_manifest_load() { :; }
    cx_img_needed() { CX_IMG_NAMES=(); }
    cx_rs_space; exit $? ;;
  progress-same|progress-new)
    [ "$4" != progress-new ] || CX_RS_FLOW=new
    CX_RS_REISSUE=1 CX_RS_MAP[db.migrations_count]=57
    cx_state_set last_restore.engine "$CX_ROOT/releases/1.16.2/custodexa.sh"
    # Each value is an observation at a stage boundary, shared across waited jobs.
    if [ "$CX_RS_FLOW" = same ]; then
      printf '%s\n' 0 41 41 41 52 52 764 764 954 954 958 958 2016 2016 2022 2022 2022 2066 2066 >"$CX_RS_DIR/times"
    else
      printf '%s\n' 0 125 125 125 1183 1183 1189 1189 1194 1194 1232 1232 1253 1253 >"$CX_RS_DIR/times"
    fi
    cx_now() { head -n1 "$CX_RS_DIR/times"; sed -i 1d "$CX_RS_DIR/times"; }
    CX_RS_RELEASE=$CX_DIR
    cx_state_set last_restore.phase checked
    cx_rs_release_place() { :; }
    cx_rs_images() { :; }
    printf '%s\n' 5a5a5a5a5a5a5a5a >"$CX_RS_DIR/safety-fingerprint"
    cx_pb_versions() { :; }
    cx_pb_kek_mode() { :; }
    cx_pb_parts() { :; }
    cx_pb_open() { CX_PB_FINAL=$CX_ROOT/backups/custodexa-backup-1.16.0-$CX_RS_TS.tar; }
    cx_bk_take() { "$2" OK 1 6 stop 0 && "$2" OK 6 6 pack 0; }
    cx_rs_safety_still_stopped() { :; }
    cx_rs_safety_verify() { :; }
    cx_pb_cleanup() { :; }
    cx_bk_vars() { :; }
    cx_db() { echo 0; }
    cx_rs_stop_all() { :; }
    cx_rs_swapped() { cx_rs_phase swapped; }
    cx_rs_db_import() { cx_rs_phase imported; }
    cx_rs_db_check() { cx_rs_phase db_checked; }
    cx_rs_images_load() { :; }
    cx_rs_files_place() { cx_rs_phase placed; }
    cx_rs_health() { CX_UP_HEALTH_VER=1.16.0; }
    cx_rs_all_running() { :; }
    cx_rs_compose_quiet() { :; }
    cx_images_verify_running() { :; }
    SCREEN_SEAL='{"state":"sealed"}'
    cx_rs_run; exit $? ;;
  unseal-wait)
    cx_state_set last_restore.engine "$CX_ROOT/releases/1.16.2/custodexa.sh"
    cx_rs_unseal_screen; exit $? ;;
  unseal-still|unseal-done|runtime-key-mismatch)
    SCREEN_SEAL='{"state":"sealed"}'
    if [ "$4" = unseal-done ]; then
      SCREEN_SEAL='{"state":"unsealed","kek_id":"5a5a5a5a5a5a5a5a"}'
      CX_RS_WAS_AWAITING=1
    elif [ "$4" = runtime-key-mismatch ]; then
      SCREEN_SEAL='{"state":"unsealed","kek_id":"0c0c0c0c0c0c0c0c"}'
      cx_rs_stop_all() { :; }
    fi
    [ "$4" != unseal-still ] || cx_state_set last_restore.engine "$CX_ROOT/releases/1.16.2/custodexa.sh"
    cx_rs_kek_verify
    rc=$?
    if [ "$4" = unseal-done ] && [ "$rc" = 0 ]; then
      CX_RS_FLOW=new CX_RS_MAP[trigger]=upgrade
      CX_RS_HOST_SOURCE[PUBLIC_BASE_URL]=https://10.0.0.11
      CX_RS_REC_MISSING=1204 CX_RS_REC_FILE=$CX_RS_DIR/missing-recordings.txt
      cx_rs_finish_screen
      cx_rs_upgrade_offer
    fi
    exit "$rc" ;;
  failure-same|failure-new|interrupted)
    mkdir -p "$CX_RS_DATA/postgres.before-restore-$CX_RS_TS" "$CX_RS_DATA/audit.before-restore-$CX_RS_TS" "$CX_ROOT/tls.before-restore-$CX_RS_TS"
    if [ "$4" = failure-new ]; then
      CX_RS_FLOW=new CX_RUN_STEP=3
      cx_state_set last_restore.flow new-host
      cx_state_set last_restore.engine "$CX_ROOT/releases/1.16.2/custodexa.sh"
    fi
    if [ "$4" = interrupted ]; then
      cx_rs_save
      cx_pb_stop_jobs() { :; }
      cx_rs_tools_rm() { :; }
      cx_db_pgpass_rm() { :; }
      cx_rs_interrupted
    else
      printf '%s\n' 0 252 >"$CX_RS_DIR/times"
      cx_now() { head -n1 "$CX_RS_DIR/times"; sed -i 1d "$CX_RS_DIR/times"; }
      cx_rs_progress_begin import
      if [ "$4" = failure-same ]; then
        printf '%s\n' 'pg_restore: error: could not execute query: ERROR:  could not extend file "base/16384/24576": No space left on device' >"$CX_RS_DIR/import.err"
      else : >"$CX_RS_DIR/import.err"; fi
      cx_rs_import_fail failed || true
      cx_rs_failure
    fi
    exit $? ;;
  ready-timeout)
    cx_state_set last_restore.phase started
    cx_rs_images_load() { CX_IMG_NAMES=(); }
    cx_rs_all_running() { :; }
    cx_images_verify_running() { :; }
    cx_rs_health() { return 1; }
    cx_ready_seconds() { echo 180; }
    cx_rs_start; exit $? ;;
  help)
    # The full --help is tested separately; these are its unchanged restore sections.
    printf '%s\n\n%s\n' "$(cx_msg help_cmd_restore)" "$(cx_msg help_restore_options)" ;;
  revert)
    mkdir -p "$CX_ROOT/backups" "$CX_RS_DATA/postgres" "$CX_RS_DATA/audit" "$CX_ROOT/tls"
    safety=$CX_ROOT/backups/custodexa-backup-1.16.0-$CX_RS_TS.tar
    truncate -s "$((18 * CX_BK_RATE * 60))" "$safety"
    cx_state_set last_restore.safety_file "$safety"
    cx_rs_revert_screen && cx_rs_exit_confirm safety; exit $? ;;
  unknown-migration)
    cx_manifest_load() { CX_MF=(); }
    printf '{"migrations":[]}' >"$CX_RS_DIR/pass2/release-MANIFEST.json"
    printf '{"runtime_markers":[]}' >"$CX_DIR/MANIFEST.json"
    printf 'migration=20261103_session_tags\n' >"$CX_RS_DIR/pass2/snapshot.txt"
    cx_rs_migrations; exit $? ;;
  *) exit 99 ;;
esac
