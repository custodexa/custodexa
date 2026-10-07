#!/usr/bin/env bats
# A whole new-host restore on a terminal, from `restore <file>` to completion, on the engine host
# (the parser, reader, journal, placement, startup and finish are real). The assertions read what
# the deployment has afterwards: the written .env, tls/ and the template, not the work folder.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host
setup() {
  rs_engine_host
  # tls-init keeps the restored certificate authority and writes only the missing server leaf;
  # its container runs the release's openssl image (the other services run the postgres one).
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/flow-base"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
case " $* " in
  *' inspect --format {{.Image}} custodexa-tls-init ')
    echo 'verify tls-init' >>"$DB/events"
    jq -r '.images.openssl.index_digest' "$ROOT/current/MANIFEST.json"
    exit 0 ;;
  *' run --rm --no-deps --name custodexa-restore-tool-'*' tls-init '*)
    printf 'new leaf\n' >"$ROOT/tls/fullchain.pem"
    printf 'new leaf key\n' >"$ROOT/tls/privkey.pem"
    echo 'issue leaf' >>"$DB/events"
    exit 0 ;;
esac
exec "$FAKE_DOCKER_REPLAY/flow-base" "$@"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}
# tls_form: the deployment terminates TLS itself (no external ingress), with its own tls/.
tls_form() {
  bk_env_set COMPOSE_FILE current/compose.yml
  bk_state_set current.overlays ''
  printf 'ca\n' >"$ROOT/tls/ca.crt"
  printf 'old leaf\n' >"$ROOT/tls/fullchain.pem"
  printf 'old leaf key\n' >"$ROOT/tls/privkey.pem"
}
# produce: a backup of the deployment as it is now; its env.bak is kept for comparison. Then the
# deployment folder becomes a new host: nothing installed or running, no data, another address.
produce() {
  bash "$ROOT/custodexa.sh" backup --yes --lang en >"$BATS_TEST_TMPDIR/flow-producer.log" 2>&1 || {
    cat "$BATS_TEST_TMPDIR/flow-producer.log"; return 1;
  }
  RS_E_FILE=$(find "$ROOT/backups" -name '*.tar')
  mkdir -p "$BATS_TEST_TMPDIR/flow"
  cp "$RS_E_FILE" "$RS_E_FILE.sha256" "$BATS_TEST_TMPDIR/flow/"
  RS_E_FILE=$BATS_TEST_TMPDIR/flow/${RS_E_FILE##*/}
  rm -f "$ROOT"/backups/*
  /usr/bin/tar -xOf "$RS_E_FILE" env.bak >"$BATS_TEST_TMPDIR/env.bak"
  rs_new_host
  rm -rf "$ROOT/data/postgres" "$ROOT/data/audit" "$ROOT/tls"
  host_ip 10.0.0.31
  : >"$DB/events"
}
# tty_restore <answers>: the restore of RS_E_FILE on a terminal, given these keystrokes.
tty_restore() {
  run bash -c 'printf "%s" "$2" | script -qec "$1" /dev/null' _ \
    "bash '$ROOT/custodexa.sh' restore '$RS_E_FILE' --new-host --lang en" "$1"
  output=${output//$'\r'/}
}
completed() {
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$status $output"; return 1; }
}
# other_keys_same <key>...: every line of the written .env except these keys equals env.bak.
other_keys_same() {
  local re
  re="^($(IFS='|'; echo "$*"))="
  diff <(grep -vE "$re" "$BATS_TEST_TMPDIR/env.bak" | sort) <(grep -vE "$re" "$ROOT/.env" | sort)
}

# - **WHEN** 在新主機互動還原一份不含自訂 nginx 範本（或範本放回原路徑）的備份，四個主機值都直接按 Enter
# - **THEN** 寫入的設定檔四個主機值是這台的建議值，其餘鍵（含 `JWT_SECRET`、`DB_PASSWORD`、`ENCRYPTION_KEY`）與 `env.bak` 逐字相同
@test "restore acceptance: 他機主機值" {
  tls_form
  produce
  ! /usr/bin/tar -tf "$RS_E_FILE" | grep -qx nginx-tls.conf.template || return 1
  tty_restore $'\n\n\n\ny\n\n\n'
  completed || return 1
  [[ $output == *'Certificate host name'* && $output == *'Certificate IP'* ]] || { echo "$output"; return 1; }
  grep -Fx "DATA_PATH=$ROOT/data" "$ROOT/.env"
  grep -Fx 'TLS_DOMAIN=ops-host.example.internal' "$ROOT/.env"
  grep -Fx 'TLS_IP_SAN=10.0.0.31' "$ROOT/.env"
  grep -Fx 'PUBLIC_BASE_URL=https://10.0.0.31' "$ROOT/.env"
  other_keys_same DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL || return 1
  # The secrets are named on their own: they must be present, not just equally absent.
  local key
  for key in JWT_SECRET DB_PASSWORD ENCRYPTION_KEY; do
    grep -q "^$key=." "$BATS_TEST_TMPDIR/env.bak" || return 1
    [ "$(grep "^$key=" "$ROOT/.env")" = "$(grep "^$key=" "$BATS_TEST_TMPDIR/env.bak")" ] || return 1
  done
}

# - **WHEN** 還原一份外部入口形態、清單記錄沒有憑證成員的備份
# - **THEN** 還原完成，`tls/` 沒有被建立或改動，畫面不提重簽
@test "restore acceptance: 外部入口形態沒有憑證目錄" {
  rm -rf "$ROOT/tls"
  produce
  [ "$(/usr/bin/tar -xOf "$RS_E_FILE" backup-manifest.json | jq -r '."contents.tls"')" = false ] || return 1
  [ "$(/usr/bin/tar -xOf "$RS_E_FILE" backup-manifest.json | jq -r '."deploy.overlays"')" = external-ingress ] || return 1
  tty_restore $'\n\ny\n\n\n'
  completed || return 1
  [ ! -e "$ROOT/tls" ] && [ ! -L "$ROOT/tls" ] || return 1
  [ -z "$(find "$ROOT" -maxdepth 1 -name 'tls*')" ] || return 1
  [[ $output != *'Certificate host name'* && $output != *'server certificate'* ]] || { echo "$output"; return 1; }
  ! grep -qx 'issue leaf' "$DB/events"
}

# - **WHEN** 備份的範本原路徑是 `/etc/custodexa/nginx-tls.conf.template`，新主機沒有 `/etc/custodexa/`，互動時輸入 `/opt/custodexa/nginx/custom.conf.template`
# - **THEN** 範本放在新路徑、內容與備份成員相同，設定檔的 `TLS_NGINX_TEMPLATE` 指向新路徑，其餘鍵與 `env.bak` 相同
@test "restore acceptance: 他機原路徑不可用" {
  local source_dir=$BATS_TEST_TMPDIR/source-etc/custodexa chosen=$ROOT/nginx/custom.conf.template
  tls_form
  mkdir -p "$source_dir" "$ROOT/nginx"
  printf 'server { listen 443 ssl; } # custom\n' >"$source_dir/nginx-tls.conf.template"
  bk_env_set TLS_NGINX_TEMPLATE "$source_dir/nginx-tls.conf.template"
  produce
  /usr/bin/tar -xOf "$RS_E_FILE" nginx-tls.conf.template >"$BATS_TEST_TMPDIR/member"
  # The source host's folder is not on this host.
  rm -rf "$BATS_TEST_TMPDIR/source-etc"
  tty_restore $'\n\n\n\n'"$chosen"$'\ny\n\n\n'
  completed || return 1
  [[ $output == *'Custom nginx template'* ]] || { echo "$output"; return 1; }
  cmp "$chosen" "$BATS_TEST_TMPDIR/member" || return 1
  [ ! -e "$source_dir" ] || return 1
  grep -Fx "TLS_NGINX_TEMPLATE=$chosen" "$ROOT/.env" || return 1
  grep -Fx "TLS_NGINX_TEMPLATE=$source_dir/nginx-tls.conf.template" "$BATS_TEST_TMPDIR/env.bak" || return 1
  other_keys_same DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL TLS_NGINX_TEMPLATE
}
