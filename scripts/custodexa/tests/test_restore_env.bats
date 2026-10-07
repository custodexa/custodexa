#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_fixtures; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_host ui
  backup_strict
  host_ip 10.0.0.31
  W=$BATS_TEST_TMPDIR/merge
  MERGE=$BATS_TEST_TMPDIR/merge.sh
  cat >"$MERGE" <<'SH'
#!/bin/bash
. "$1/lib/common.sh"
CX_LANG_FLAG=en
cx_load_libs "$1"
. "$1/lib/cmd_restore.sh"
CX_DIR=$2/current CX_ROOT=$2 CX_RS_DIR=$3 CX_RS_FLOW=$4 CX_RS_TS=20261012-093015
cx_flat_parse "$CX_RS_DIR/pass2/backup-manifest.json" CX_RS_MAP CX_RS_KEYS || exit 3
cx_rs_env_merge || exit 3
printf 'template=%s\nchanged=%s\nkept=%s\n' "$CX_RS_TEMPLATE" "$CX_RS_TEMPLATE_CHANGED" "$CX_RS_TEMPLATE_KEEP"
SH
  prepare plain
}
prepare() { rm -rf "$W"; rs_unpack "$(rs_fix "$1")" "$W/pass2"; }
merge() { run bash "$MERGE" "$SRC" "$ROOT" "$W" "$1" </dev/null; }
merge_tty() {
  local answer=$1 flow=${2:-new}
  run bash -c 'printf "%s" "$2" | script -qec "$1" /dev/null' _ \
    "bash '$MERGE' '$SRC' '$ROOT' '$W' '$flow'" "$answer"
  output=${output//$'\r'/}
}
only_host_keys_differ() {
  diff <(grep -vE '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL)=' "$W/pass2/env.bak") \
    <(grep -vE '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL)=' "$W/env.merged")
}

@test "restore host values: same host keeps its four values and all other backup bytes" {
  merge same
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  only_host_keys_differ || return 1
  diff <(grep -E '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL)=' "$ROOT/.env") \
    <(grep -E '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL)=' "$W/env.merged")
}

@test "restore host values: Enter takes this host's suggestions and keeps the backup secrets" {
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit"
  merge_tty $'\n\n\n\n'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  only_host_keys_differ || return 1
  grep -Fx "DATA_PATH=$ROOT/data" "$W/env.merged"
  grep -Fx 'TLS_DOMAIN=ops-host.example.internal' "$W/env.merged"
  grep -Fx 'TLS_IP_SAN=10.0.0.31' "$W/env.merged"
  grep -Fx 'PUBLIC_BASE_URL=https://10.0.0.31' "$W/env.merged"
}

@test "restore host values: a dash keeps each source value without rewriting the backup" {
  sed -i "s#^DATA_PATH=.*#DATA_PATH=$BATS_TEST_TMPDIR/source-data#" "$W/pass2/env.bak"
  merge_tty $'-\n-\n-\n-\n'
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff "$W/pass2/env.bak" "$W/env.merged"
}

@test "restore host values: relative or nonempty data paths are asked again" {
  merge_tty "relative
$ROOT/data
$BATS_TEST_TMPDIR/empty-data



"
  [ "$status" -eq 0 ] && [[ $output == *'must be an absolute path'* && $output == *'must have no database or audit data'* ]] || { echo "$output"; return 1; }
  grep -Fx "DATA_PATH=$BATS_TEST_TMPDIR/empty-data" "$W/env.merged"
  only_host_keys_differ
}

@test "restore host values: without a terminal flags override suggestions; absent flags use suggestions" {
  export CX_RS_GIVEN=' --data-path' CX_RS_DATA_PATH=$BATS_TEST_TMPDIR/chosen-data
  merge new
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  only_host_keys_differ || return 1
  grep -Fx "DATA_PATH=$BATS_TEST_TMPDIR/chosen-data" "$W/env.merged"
  grep -Fx 'TLS_IP_SAN=10.0.0.31' "$W/env.merged"
}

@test "restore host values: external ingress asks neither certificate question" {
  prepare notls
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit"
  merge_tty $'\n\n'
  [ "$status" -eq 0 ] && [[ $output != *'Certificate host name'* && $output != *'Certificate IP'* ]] || { echo "$output"; return 1; }
  only_host_keys_differ
}

@test "restore template: a relative source path is resolved from the deployment root even from another directory" {
  prepare tplrel
  mkdir -p "$ROOT/conf"
  cd /
  merge same
  [ "$status" -eq 0 ] && [[ $output == *"template=$ROOT/conf/nginx-tls.conf.template"* ]] || { echo "$output"; return 1; }
  only_host_keys_differ
}

@test "restore template: an unavailable source prompts for a new path, changing only the permitted keys" {
  prepare tplabs
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit"
  merge_tty "



$ROOT/custom.conf.template
"
  [ "$status" -eq 0 ] && [[ $output == *'Custom nginx template'* ]] || { echo "$output"; return 1; }
  diff <(grep -vE '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL|TLS_NGINX_TEMPLATE)=' "$W/pass2/env.bak") \
    <(grep -vE '^(DATA_PATH|TLS_DOMAIN|TLS_IP_SAN|PUBLIC_BASE_URL|TLS_NGINX_TEMPLATE)=' "$W/env.merged") || return 1
  grep -Fx "TLS_NGINX_TEMPLATE=$ROOT/custom.conf.template" "$W/env.merged"
}

# - **WHEN** 原路徑不可用，非互動執行未帶 `--nginx-template`
# - **THEN** 腳本在停機前拒絕並說明旗標，沒有任何變更
@test "restore template: an unavailable source without the noninteractive flag refuses before stopping" {
  prepare tplabs
  export CX_RS_GIVEN=' --data-path' CX_RS_DATA_PATH=$BATS_TEST_TMPDIR/empty-data
  merge new
  [ "$status" -eq 3 ] && [[ $output == *'--nginx-template'* ]] || { echo "$output"; return 1; }
  ! grep -Eq '^(stop|start|up)( |$)' "$DB/events"
}

@test "restore template: an available original path is not asked for and a different existing file is kept for the preview" {
  prepare tplrel
  mkdir -p "$ROOT/conf"
  printf 'existing\n' >"$ROOT/conf/nginx-tls.conf.template"
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit"
  merge_tty $'\n\n\n\n'
  [ "$status" -eq 0 ] && [[ $output != *'Custom nginx template'* && $output == *"kept=$ROOT/conf/nginx-tls.conf.template.before-restore-20261012-093015"* ]] || { echo "$output"; return 1; }
  only_host_keys_differ
}
