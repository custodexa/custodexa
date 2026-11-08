#!/usr/bin/env bats
# Screen snapshots of the restore preview across the database major (task 3.11): P16 (the database
# row, same major and other major) and P17 (the whole preview of a restore that changes the major).
# The harness is the one of test_restore_preview.bats; the deployment runs a release with PostgreSQL
# 18 and the backup is of a release with 16.

load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load pgconvert_host

setup_file() {
  export RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_make "$RS_FIX/plain" ui : || return 1
}
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_host ui
  rs_preflight_only
  backup_strict
  host_ip 10.0.0.31
  W=$BATS_TEST_TMPDIR/preview
  rs_unpack "$(rs_fix plain)" "$W/pass2"
  PREVIEW=$BATS_TEST_TMPDIR/preview.sh
  cat >"$PREVIEW" <<'SH'
#!/bin/bash
. "$1/lib/common.sh"
CX_LANG_FLAG=$4
export NO_COLOR=1
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_FLOW=same CX_RS_TS=20261125-093015
cx_state_load "$CX_ROOT/state.json"
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
CX_RS_MAP[created_at]=2026-11-20T02:17:02Z
CX_RS_MAP[source.hostname]=bastion-a.example.internal
CX_RS_MAP[kek.fingerprint]=5a5a5a5a5a5a5a5a
CX_RS_MAP[db.location]=bundled CX_RS_MAP[db.server_major]=$6
CX_RS_MAP[size.db_bytes]=18683107738 CX_RS_MAP[size.audit_bytes]=12582912 CX_RS_MAP[size.recordings_bytes]=227633266688
CX_RS_DATA=$2/data CX_RS_VERSION=$5 CX_RS_ENGINE=$5 CX_RS_ENC=0
CX_RS_FILE=$2/backups/custodexa-backup-$5-20261120-021502.tar
CX_RS_PACKAGE_CHECK=ok CX_RS_PACKAGE_NAME=custodexa-$5.tar.gz CX_RS_SIGNATURE=skip-no-cosign
CX_IMAGES=/srv/transfer/custodexa-images-$5-x86_64.tar CX_IMG_NAMES=(a b c d e f g h i)
CX_RS_HOST_VALUES=([DATA_PATH]=$2/data [TLS_DOMAIN]=bastion-a.example.internal [TLS_IP_SAN]=10.0.0.30 [PUBLIC_BASE_URL]=https://10.0.0.30)
for k in DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL; do CX_RS_HOST_SOURCE[$k]=${CX_RS_HOST_VALUES[$k]}; done
CX_RS_SPACE_MOUNTS=(/opt) CX_RS_SPACE_NEED[/opt]=$((56 * CX_GIB)) CX_RS_SPACE_FREE[/opt]=$((211 * CX_GIB))
CX_RS_SAFETY_MIN=12 CX_RS_IMPORT_MIN=18
stty -echo
printf '\036'
cx_rs_preview
cx_rs_confirm || exit 3
SH
  chmod +x "$PREVIEW"
}

# crossed_host <backup version>: the deployment is on a release with 18, the backup's release has 16.
crossed_host() {
  local cur=$RS_VERSION
  pgc_manifest "$ROOT/releases/$cur" with 18
  mkdir -p "$ROOT/releases/$1"
  cp "$ROOT/releases/$cur/MANIFEST.json" "$ROOT/releases/$1/MANIFEST.json"
  pgc_manifest "$ROOT/releases/$1" without 16
  pgc_version 18 postgresql 18/docker
  pgc_version 16 postgres
}

# shot <name> <backup version> <backup major> <answer>
shot() {
  local l rc=0 out
  fake hostname 'echo bastion-a.example.internal'
  printf '128402\n' >"$DB/count.audit_logs"
  printf '9311\n' >"$DB/count.sessions"
  for l in en zh-TW ja; do
    run bash -c 'printf "%s\n" "$2" | script -qec "$1" /dev/null' _ \
      "bash '$PREVIEW' '$SRC' '$ROOT' '$W' '$l' '$2' '$3'" "$4"
    output=${output//$'\r'/}; output=${output#*$'\036'}
    output=${output#$'\n'}
    pg_emit "$1" "$l" || rc=1
  done
  return $rc
}

@test "P16 the database row: same major" {
  crossed_host 1.16.1
  pgc_manifest "$ROOT/releases/1.16.1" with 18
  shot P16a 1.16.1 18 1.16.1
}
@test "P17 restore across the major" {
  crossed_host 1.16.1
  shot P17 1.16.1 16 1.16.1
}
