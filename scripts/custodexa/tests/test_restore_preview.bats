#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() {
  export RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_make "$RS_FIX/plain" ui : || return 1
  rs_make "$RS_FIX/tplrel" ui 'mkdir -p "$ROOT/conf"; printf "server {}\n" >"$ROOT/conf/nginx-tls.conf.template"
    bk_env_set TLS_NGINX_TEMPLATE ./conf/nginx-tls.conf.template'
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
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_FLOW=same CX_RS_TS=20261012-093015
cx_state_load "$CX_ROOT/state.json"
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
CX_RS_MAP[created_at]=2026-10-05T10:15:02Z
CX_RS_MAP[source.hostname]=bastion-a.example.internal
CX_RS_MAP[kek.fingerprint]=5a5a5a5a5a5a5a5a
CX_RS_MAP[size.db_bytes]=18683107738 CX_RS_MAP[size.audit_bytes]=12582912 CX_RS_MAP[size.recordings_bytes]=227633266688
CX_RS_DATA=/opt/custodexa/data CX_RS_VERSION=1.16.0 CX_RS_ENGINE=1.16.2 CX_RS_ENC=0
CX_RS_FILE=/opt/custodexa/backups/custodexa-backup-1.16.0-20261005-101502.tar
CX_RS_PACKAGE_CHECK=ok CX_RS_PACKAGE_NAME=custodexa-1.16.0.tar.gz CX_RS_SIGNATURE=skip-no-cosign
CX_IMAGES=/srv/transfer/custodexa-images-1.16.0-x86_64.tar CX_IMG_NAMES=(a b c d e f g h i)
CX_RS_HOST_VALUES=([DATA_PATH]=/opt/custodexa/data [TLS_DOMAIN]=bastion-a.example.internal [TLS_IP_SAN]=10.0.0.30 [PUBLIC_BASE_URL]=https://10.0.0.30)
for k in DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL; do CX_RS_HOST_SOURCE[$k]=${CX_RS_HOST_VALUES[$k]}; done
CX_RS_SPACE_MOUNTS=(/opt) CX_RS_SPACE_NEED[/opt]=$((56 * CX_GIB)) CX_RS_SPACE_FREE[/opt]=$((211 * CX_GIB))
CX_RS_SAFETY_MIN=12 CX_RS_IMPORT_MIN=18
# Render documented paths while all input and read-only SQL still belong to the fake host.
CX_ROOT=/opt/custodexa
case $5 in
  new)
    CX_RS_FLOW=new CX_RS_ENC=1 CX_RS_REISSUE=1
    CX_RS_FILE=/srv/transfer/custodexa-backup-1.16.0-20261005-101502.tar.enc
    CX_RS_HOST_VALUES[TLS_DOMAIN]=bastion-b.example.internal CX_RS_HOST_VALUES[TLS_IP_SAN]=10.0.0.31 CX_RS_HOST_VALUES[PUBLIC_BASE_URL]=https://10.0.0.31
    CX_RS_SPACE_NEED[/opt]=$((41 * CX_GIB)) CX_RS_SPACE_FREE[/opt]=$((180 * CX_GIB)) ;;
  other) CX_RS_MAP[source.hostname]=bastion-c.example.internal ;;
esac
stty -echo
printf '\036'
cx_rs_preview
cx_rs_confirm || exit 3
SH
  chmod +x "$PREVIEW"
}
unchanged() {
  [ "$before" = "$(sha256sum "$ROOT/state.json" "$ROOT/.env")" ] || return 1
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events"
}
preview_snapshot() {
  local variant=$1 l expected errs=0 answer=1.16.0
  fake hostname 'echo bastion-a.example.internal'
  printf '128402\n' >"$DB/count.audit_logs"
  printf '9311\n' >"$DB/count.sessions"
  sed -i 's/^count.audit_logs=.*/count.audit_logs=124590/; s/^count.sessions=.*/count.sessions=9254/' "$W/pass2/snapshot.txt"
  [ "$variant" != unknown ] || printf '1\n' >"$DB/count.audit_logs.rc"
  [ "$variant" != new ] || answer=y
  for l in en zh-TW ja; do
    run bash -c 'printf "%s\n" "$2" | script -qec "$1" /dev/null' _ \
      "bash '$PREVIEW' '$SRC' '$ROOT' '$W' '$l' '$variant'" "$answer"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    output=${output//$'\r'/}; output=${output#*$'\036'}
    # The leading blank separates this screen from preceding validation messages.
    output=${output#$'\n'}
    expected=$TESTS_DIR/snapshots/restore-preview-$variant.$l.txt
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
      errs=1
    else
      diff <(printf '%s\n' "$output") "$expected" || errs=1
    fi
  done
  [ "$errs" = 0 ]
}

@test "restore preview: new host in all three languages" { preview_snapshot new; }
@test "restore preview: same host in all three languages" { preview_snapshot same; }
@test "restore preview: another host's backup in all three languages" { preview_snapshot other; }
@test "restore preview: unreadable counts in all three languages" { preview_snapshot unknown; }

@test "restore confirmation: a wrong version at the terminal cancels with exit 3 before stopping" {
  before=$(sha256sum "$ROOT/state.json" "$ROOT/.env")
  run bash -c 'printf "\n1.16.9\n" | script -qec "$1" /dev/null' _ \
    "bash '$ROOT/custodexa.sh' restore '$(rs_fix plain)' --lang en"
  [ "$status" -eq 3 ] && [[ $output == *'To confirm, type the version after the restore, 1.16.0:'* && $output == *'restore was cancelled'* && $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}

@test "restore confirmation: without a terminal --yes alone refuses; both flags reach the execution boundary" {
  before=$(sha256sum "$ROOT/state.json" "$ROOT/.env")
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix plain)" --same-host --yes --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'requires both'* && $output == *'--confirm-data-loss'* && $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged || return 1
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix plain)" --same-host --yes --confirm-data-loss --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  unchanged
}

# - **WHEN** 在已安裝主機還原一份 `source.hostname` 是另一台主機的備份
# - **THEN** 走同機流程，預覽以警告寫明備份來自哪台主機、這台的資料會被取代，且不列筆數比較
@test "restore preview: an installed host taking another host's backup shows only current counts" {
  rs_derive plain other 'rs_mf_set source.hostname bastion-c.example.internal' || return 1
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix other)" --same-host --yes --confirm-data-loss --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* && $output == *'bastion-c.example.internal'* && $output == *'it will replace this host'* ]] || { echo "$output"; return 1; }
  local counts=${output#*Replaced}
  counts=${counts%%Safety backup*}
  [[ $counts == *'1,234 audit records and 42 connection records here'* && $counts != *'in the backup'* && $counts != *'difference'* ]] || { echo "$counts"; return 1; }
}

# - **WHEN** 同機還原時，目前資料庫的稽核紀錄筆數少於備份裡的筆數
# - **THEN** 預覽列出兩邊的筆數並註明只是參考，畫面不出現負數，也不把筆數差稱為遺失
@test "restore preview: smaller current counts are not presented as negative or lost counts" {
  printf '2\n' >"$DB/count.audit_logs"
  printf '1\n' >"$DB/count.sessions"
  local l counts
  for l in en zh-TW ja; do
    run bash "$ROOT/custodexa.sh" restore "$(rs_fix plain)" --same-host --yes --confirm-data-loss --lang "$l" </dev/null
    [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    case $l in
      en) counts=${output#*Replaced}; counts=${counts%%Safety backup*}; [[ $counts == *'not a count of what is'*'lost'* && $counts == *'1,234 and 42'* ]] ;;
      zh-TW) counts=${output#*會取代     }; counts=${counts%%安全備份*}; [[ $counts == *'不是會遺失的筆數'* && $counts == *'1,234 筆、42 筆'* ]] ;;
      ja) counts=${output#*置換対象}; counts=${counts%%事前の保存*}; [[ $counts == *'失われる件数ではありません'* && $counts == *'1,234'*'42'* ]] ;;
    esac || { echo "$output"; return 1; }
    ! printf '%s\n' "$counts" | grep -Eq -- '-[0-9]|lost [0-9]|遺失 [0-9]|[0-9][0-9,]* 件を失' || return 1
  done
}

@test "restore preview: a new host without value flags lists its suggestions and the template's kept name" {
  rs_new_host
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit"
  mkdir -p "$ROOT/conf"
  printf 'existing template\n' >"$ROOT/conf/nginx-tls.conf.template"
  before=$(sha256sum "$ROOT/state.json" "$ROOT/.env")
  run bash "$ROOT/custodexa.sh" restore "$(rs_fix tplrel)" --new-host --yes --lang en </dev/null
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  [[ $output == *"DATA_PATH        $ROOT/data"* && $output == *'TLS_DOMAIN       ops-host.example.internal'* && $output == *'TLS_IP_SAN       10.0.0.31'* && $output == *'PUBLIC_BASE_URL  https://10.0.0.31'* ]] || { echo "$output"; return 1; }
  [[ $output == *'the file already there is renamed and kept as'* && $output == *"$ROOT/conf/nginx-tls.conf.template.before-restore-"* ]] || { echo "$output"; return 1; }
  unchanged
}
