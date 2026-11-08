#!/usr/bin/env bats
# The deployment form .env describes must be the deployment that exists. An entry that went on with
# an address that never took effect, an emptied address, or a switched web entry would start another
# stack than the one holding the data. Every refusal here leaves .env, state.json and the services as
# they were: exit code 3, no docker call, the lines outside the managed block in place.

load helper

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  use_fake_docker
  ENV=$ROOT/.env
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
}

# deploy <layout> <overlays> [extra state lines]: a package deployment of that form. profiles
# means the release's MANIFEST says compose_layout profiles; overlays is the older layout.
deploy() {
  local layout=$1 ov=$2 l
  shift 2
  if [ "$layout" = profiles ]; then
    printf '{\n  "format": 1,\n  "compose_layout": "profiles"\n}\n' >"$ROOT/current/MANIFEST.json"
  fi
  {
    printf '{\n  "format": "2",\n  "current.version": "1.23.0",\n  "current.kind": "package",\n'
    printf '  "current.overlays": "%s"' "$ov"
    for l in "$@"; do printf ',\n  %s' "$l"; done
    printf '\n}\n'
  } >"$ROOT/state.json"
}
env_is() { printf '%s\n' "$@" >"$ENV"; chmod 600 "$ENV"; }
sha() { if [ -e "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else echo absent; fi; }
# guard <command>: cx_form_guard of that entry, in a shell of its own; run's output holds both streams.
guard() {
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=${LANG_ARG:-zh-TW}; cx_load_libs "$1"
    CX_ROOT=$2; CX_FLAGS_TEXT=""; CX_ARGS=(${GUARD_ARGS:-}); cx_state_load "$2/state.json"; cx_form_guard "$3"' \
    _ "$SRC" "$ROOT" "$1"
}
start_run() { run bash "$ROOT/custodexa.sh" "$@" --lang "${LANG_ARG:-zh-TW}" </dev/null; }
snap() { ENV_SHA=$(sha "$ENV"); STATE_SHA=$(sha "$ROOT/state.json"); }
refused_untouched() { # the refusal changed nothing
  [ "$status" -eq 3 ] || { echo "status $status"; echo "$output"; return 1; }
  [ "$(sha "$ENV")" = "$ENV_SHA" ] && [ "$(sha "$ROOT/state.json")" = "$STATE_SHA" ] || { echo "files changed"; return 1; }
  [ ! -s "$FAKE_DOCKER_LOG" ] || { echo "docker was called:"; cat "$FAKE_DOCKER_LOG"; return 1; }
}
no_docker_host() { [[ $output != *host.docker.internal* ]] || { echo "$output"; return 1; }; }
has_data() { mkdir -p "$ROOT/data/postgres" && printf '16\n' >"$ROOT/data/postgres/PG_VERSION"; }

@test "a built-in deployment with data and an address added: start refuses, the address never took effect" {
  deploy profiles ""
  has_data
  env_is 'DATA_PATH='"$ROOT/data" 'EXTERNAL_DB_HOST=db.example.internal' 'TLS_MODE=selfsigned'
  snap
  start_run start
  refused_untouched
  [[ $output == *'從來沒有生效'* && $output == *'EXTERNAL_DB_HOST=db.example.internal'* ]]
  [[ $output == *'刪除或留空'* && $output == *'備份與還原'* ]]
  [[ $output == *"$ROOT/data/postgres"* ]]
  no_docker_host
}

@test "an external deployment with the address emptied: refused before any service stops, the recorded address is printed" {
  deploy profiles "external-database" '"current.external_db_host": "db01.example.internal"' '"current.external_db_port": "5432"'
  env_is 'EXTERNAL_DB_HOST=' 'TLS_MODE=selfsigned'
  snap
  GUARD_ARGS=1.23.0 guard upgrade
  refused_untouched
  [[ $output == *'db01.example.internal:5432'* && $output == *'EXTERNAL_DB_HOST=db01.example.internal'* ]]
  [[ $output == *'upgrade 1.23.0'* ]]
  no_docker_host
}

@test "an external deployment with no recorded address: the screen says so and shows a placeholder" {
  deploy overlays "external-database"
  env_is 'EXTERNAL_DB_HOST=' 'TLS_MODE=selfsigned'
  snap
  guard start
  refused_untouched
  [[ $output == *'部署紀錄沒有記下位址'* && $output == *'<外接資料庫的主機名或 IP>'* ]]
}

@test "the address points back at this stack, at the container itself, or carries a port: refused, never advising host.docker.internal" {
  deploy profiles ""
  env_is 'EXTERNAL_DB_HOST=postgres'
  snap
  guard start
  refused_untouched
  [[ $output == *'Custodexa 自己的服務名稱'* && $output == *'留空或刪除'* ]]
  no_docker_host
  env_is 'EXTERNAL_DB_HOST=127.0.0.1'
  snap
  guard start
  refused_untouched
  [[ $output == *'後端容器自己'* && $output == *'這台主機的網路位址'* ]]
  no_docker_host
  env_is 'EXTERNAL_DB_HOST=db.example.internal:6432'
  snap
  guard start
  refused_untouched
  [[ $output == *'EXTERNAL_DB_PORT=6432'* && $output == *'EXTERNAL_DB_HOST=db.example.internal'* ]]
  no_docker_host
  env_is 'EXTERNAL_DB_HOST=postgres://u:p@db.example.internal/x'
  snap
  guard start
  refused_untouched
  [[ $output == *'EXTERNAL_DB_HOST=db.example.internal'* ]]
  no_docker_host
  snap
  LANG_ARG=en guard start
  refused_untouched
  [[ $output == *'cannot be used'* ]]
  no_docker_host
  snap
  LANG_ARG=ja guard start
  refused_untouched
  [[ $output == *'使えません'* ]]
  no_docker_host
}

@test "only EXTERNAL_DB_PORT filled in: start refuses; 5432 counts as not filled in" {
  deploy profiles ""
  env_is 'EXTERNAL_DB_HOST=' 'EXTERNAL_DB_PORT=6432'
  snap
  start_run start
  refused_untouched
  [[ $output == *'EXTERNAL_DB_PORT=6432'* && $output == *'補上 EXTERNAL_DB_HOST'* ]]
  env_is 'EXTERNAL_DB_HOST=' 'EXTERNAL_DB_PORT=5432'
  guard start
  [ "$status" -eq 0 ]
}

@test "an unknown TLS_MODE is refused and the valid values are listed" {
  deploy profiles ""
  env_is 'TLS_MODE=letsencrypt'
  snap
  guard start
  refused_untouched
  [[ $output == *'letsencrypt'* && $output == *'selfsigned、provided、external'* ]]
}

@test "a new install with an address on a folder that holds built-in data: refused with the folder and its size" {
  has_data
  head -c 4096 /dev/zero >"$ROOT/data/postgres/f"
  env_is 'DATA_PATH='"$ROOT/data" 'EXTERNAL_DB_HOST=db.example.internal'
  snap
  guard install
  refused_untouched
  [[ $output == *"$ROOT/data/postgres"* && $output == *'PostgreSQL 16'* && $output == *'外接安裝不會使用'* ]]
  [[ $output == *'custodexa.sh install'* ]]
  [ ! -e "$ROOT/state.json" ] && [ ! -e "$ROOT/logs" ] || return 1
}

@test "a new install with an address and no data folder passes; a built-in install on old data passes too" {
  env_is 'DATA_PATH='"$ROOT/data" 'EXTERNAL_DB_HOST=db.example.internal'
  guard install
  [ "$status" -eq 0 ]
  has_data
  env_is 'DATA_PATH='"$ROOT/data" 'EXTERNAL_DB_HOST='
  guard install
  [ "$status" -eq 0 ]
}

@test "install: a COMPOSE_FILE listing an external database without an address, or an ingress without TLS_MODE=external, is refused" {
  # Notation of the old layout (1.22 and before) in a new install's .env.
  env_is 'COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml'
  snap
  guard install
  refused_untouched
  [[ $output == *'EXTERNAL_DB_HOST 是空的'* ]]
  # Notation of the old layout (1.22 and before): an ingress overlay without TLS_MODE=external.
  env_is 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml' 'TLS_MODE=selfsigned'
  snap
  guard install
  refused_untouched
  [[ $output == *'TLS_MODE=external'* ]]
  # Notation of the old layout (1.22 and before) agreeing with TLS_MODE.
  env_is 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml' 'TLS_MODE=external'
  guard install
  [ "$status" -eq 0 ]
}

@test "a refusal does not write the managed block: the COMPOSE_FILE line outside it stays where it was" {
  deploy profiles ""
  has_data
  env_is 'DATA_PATH='"$ROOT/data" 'COMPOSE_FILE=current/compose.yml' 'EXTERNAL_DB_HOST=db.example.internal'
  snap
  start_run start
  refused_untouched
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$ENV"
  ! grep -q 'managed by custodexa.sh' "$ENV" || return 1
}

@test "a 1.23 external-ingress deployment whose TLS_MODE was changed: start refuses, TLS_MODE stays as typed, the original is printed" {
  deploy profiles "external-ingress"
  env_is 'TLS_MODE=selfsigned' 'HTTP_PORT=8080'
  snap
  start_run start
  refused_untouched
  grep -qx 'TLS_MODE=selfsigned' "$ENV"
  [[ $output == *'TLS_MODE=external'* && $output == *'8080'* && $output == *'目前沒有提供這個流程'* ]]
}

@test "the other way: built-in at install, TLS_MODE=external now: refused, the recorded TLS_MODE is printed" {
  deploy profiles "" '"current.tls_mode": "provided"'
  env_is 'TLS_MODE=external'
  snap
  start_run start
  refused_untouched
  [[ $output == *'TLS_MODE=provided'* ]]
}

@test "the old notation of an external ingress: let through on an overlays layout, refused on a profiles layout" {
  deploy overlays "external-ingress"
  # The ingress in the notation of the old layout (1.22 and before).
  env_is 'TLS_MODE=selfsigned' 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml'
  snap
  GUARD_ARGS=1.23.0 guard upgrade
  [ "$status" -eq 0 ]
  [ "$(sha "$ENV")" = "$ENV_SHA" ]
  guard start
  [ "$status" -eq 0 ]
  [ "$(sha "$ENV")" = "$ENV_SHA" ] || { echo ".env written by an accepted old notation"; return 1; }
  deploy profiles "external-ingress"
  snap
  start_run start
  refused_untouched
  grep -qx 'TLS_MODE=selfsigned' "$ENV"
}

@test "an unfinished conversion record counts as the old notation only while .env is what it was before" {
  deploy profiles "external-ingress"
  # The ingress in the notation of the old layout (1.22 and before), as before the unfinished conversion.
  env_is 'TLS_MODE=selfsigned' 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml'
  local from
  from=$(sha "$ENV")
  deploy profiles "external-ingress" '"last_upgrade.env_rewrite": "pending"' "\"last_upgrade.env_rewrite_from\": \"$from\""
  snap
  guard rollback
  [ "$status" -eq 0 ]
  [ "$(sha "$ENV")" = "$ENV_SHA" ] || { echo ".env written"; return 1; }
  printf 'TLS_MODE=provided\n' >>"$ENV"
  snap
  guard rollback
  refused_untouched
  [[ $output == *'TLS_MODE=external'* ]]
}

@test "a consistent deployment passes and gets the managed block; a second run changes nothing" {
  deploy profiles "external-ingress external-database" '"current.external_db_host": "db.example.internal"'
  env_is 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db.example.internal' 'TLS_MODE=external'
  guard start
  [ "$status" -eq 0 ]
  grep -qx 'COMPOSE_PROFILES=own-ingress' "$ENV"
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$ENV"
  local once
  once=$(sha "$ENV")
  guard backup
  [ "$status" -eq 0 ] && [ "$(sha "$ENV")" = "$once" ] || return 1
}

@test "upgrade step 1 passes without writing .env" {
  deploy profiles ""
  env_is 'DB_USER=postgres'
  snap
  GUARD_ARGS=1.23.1 guard upgrade
  [ "$status" -eq 0 ]
  [ "$(sha "$ENV")" = "$ENV_SHA" ]
}

@test "backup and rollback refuse the same way before changing anything" {
  deploy profiles ""
  has_data
  env_is 'DATA_PATH='"$ROOT/data" 'EXTERNAL_DB_HOST=db.example.internal'
  snap
  start_run backup
  refused_untouched
  [[ $output == *'從來沒有生效'* ]]
  start_run rollback
  refused_untouched
  [[ $output == *'從來沒有生效'* ]]
}

@test "status never refuses and never writes: same exit code and the same .env with a form that start refuses" {
  deploy profiles ""
  env_is 'DB_USER=postgres' 'TLS_MODE=selfsigned'
  start_run status
  local rc_ok=$status
  has_data
  env_is 'DATA_PATH='"$ROOT/data" 'COMPOSE_FILE=current/compose.yml' 'EXTERNAL_DB_HOST=db.example.internal'
  snap
  start_run status
  [ "$status" -eq "$rc_ok" ] || { echo "$status vs $rc_ok"; echo "$output"; return 1; }
  [ "$(sha "$ENV")" = "$ENV_SHA" ] && [ "$(sha "$ROOT/state.json")" = "$STATE_SHA" ] || return 1
}

# Status shows the form, and says which line disagrees with it. Read only, in each language.
status_form() { # the lines of the form section of the last status run, up to the services title
  # The database section, when shown between them, has its own tests and is left out here.
  sed -n '/^\(部署型態\|Deployment form\|配置形態\)$/,/^\(服務\|Services\|サービス\)$/p' <<<"$output" |
    sed '/^\(資料庫\|Database\|データベース\)$/,/^[^ ]/{/^\(資料庫\|Database\|データベース\)$/d;/^ /d;}'
}

@test "status shows the form of a built-in deployment on one line, nothing else when .env agrees" {
  deploy profiles ""
  env_is 'DB_USER=postgres' 'TLS_MODE=selfsigned'
  snap
  start_run status
  [[ $output == *'部署型態'* ]]
  [[ $(status_form) == *'[ OK ] 資料庫 內建；網頁入口 內建 HTTPS（對外埠 443、80）'* ]] || { echo "$output"; return 1; }
  [[ $(status_form) != *'[WARN]'* ]]
  [ "$(sha "$ENV")" = "$ENV_SHA" ] && [ "$(sha "$ROOT/state.json")" = "$STATE_SHA" ] || return 1
}

@test "status shows an external database and your own reverse proxy with the port" {
  deploy profiles "external-ingress external-database" '"current.external_db_host": "db01.example.internal"' '"current.external_db_port": "5432"'
  env_is 'EXTERNAL_DB_HOST=db01.example.internal' 'TLS_MODE=external' 'HTTP_PORT=8080'
  LANG_ARG=en start_run status
  [[ $(status_form) == *'Database: external db01.example.internal:5432;'* ]] || { echo "$output"; return 1; }
  [[ $(status_form) == *'Web entry: your reverse proxy (web service on port 8080)'* ]]
  [[ $(status_form) != *'[WARN]'* ]]
}

@test "status warns when .env gives an address the built-in deployment never used, in three languages" {
  deploy profiles ""
  env_is 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db01.example.internal' 'TLS_MODE=selfsigned'
  snap
  start_run status
  [[ $(status_form) == *'[WARN] .env 和目前的部署不一致：'* && $(status_form) == *'EXTERNAL_DB_HOST=db01.example.internal'* ]] || { echo "$output"; return 1; }
  [[ $(status_form) == *'系統仍在用內建資料庫，這一行沒有生效。'* && $(status_form) == *'繼續用內建資料庫：刪除這一行。'* ]]
  [ "$status" -eq 4 ]
  [ "$(sha "$ENV")" = "$ENV_SHA" ] && [ "$(sha "$ROOT/state.json")" = "$STATE_SHA" ] || return 1
  LANG_ARG=en start_run status
  [[ $(status_form) == *'[WARN] .env does not match the deployment:'* && $(status_form) == *'EXTERNAL_DB_HOST=db01.example.internal'* ]] || { echo "$output"; return 1; }
  [[ $(status_form) == *'To keep the built-in database: delete this line.'* ]]
  LANG_ARG=ja start_run status
  [[ $(status_form) == *'[WARN] .env が現在の配置と一致しません:'* && $(status_form) == *'EXTERNAL_DB_HOST=db01.example.internal'* ]] || { echo "$output"; return 1; }
}

@test "status warns for an emptied address, a switched web entry and an unusable value; the old notation of an ingress is left to the upgrade" {
  deploy profiles "external-database" '"current.external_db_host": "db01.example.internal"' '"current.external_db_port": "5432"'
  env_is 'EXTERNAL_DB_HOST=' 'TLS_MODE=selfsigned'
  start_run status
  [[ $(status_form) == *'EXTERNAL_DB_HOST 是空的'* && $(status_form) == *'系統仍在用外接資料庫 db01.example.internal'* ]] || { echo "$output"; return 1; }
  deploy profiles "external-ingress"
  env_is 'TLS_MODE=selfsigned'
  start_run status
  [[ $(status_form) == *'TLS_MODE=selfsigned'* && $(status_form) == *'改回安裝時的值：TLS_MODE=external'* ]] || { echo "$output"; return 1; }
  deploy profiles ""
  env_is 'EXTERNAL_DB_HOST=localhost' 'TLS_MODE=selfsigned'
  start_run status
  [[ $(status_form) == *'EXTERNAL_DB_HOST=localhost 不能用'* ]] || { echo "$output"; return 1; }
  rm -f "$ROOT/current/MANIFEST.json"
  deploy overlays "external-ingress"
  env_is 'TLS_MODE=selfsigned'
  start_run status
  [[ $(status_form) != *'[WARN]'* ]] || { echo "$output"; return 1; }
}

# form_is <expected lines...>: the form section of the last status run, word for word.
form_is() {
  diff <(status_form) <(printf '%s\n' "$@") || { echo "$output"; return 1; }
}
LONG_HOST=a-very-long-database-hostname.corp.example.internal

@test "status form section word for word: the address stays on the first line while it fits and moves under it when it does not" {
  deploy profiles ""
  env_is 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db01.example.internal' 'TLS_MODE=selfsigned'
  start_run status
  form_is '部署型態' \
    '  [ OK ] 資料庫 內建；網頁入口 內建 HTTPS（對外埠 443、80）' \
    '  [WARN] .env 和目前的部署不一致：EXTERNAL_DB_HOST=db01.example.internal' \
    '         系統仍在用內建資料庫，這一行沒有生效。' \
    '         下一次啟動、升級、備份、還原或回到上一版會被擋下。' \
    '         繼續用內建資料庫：刪除這一行。' \
    '         要搬到外接資料庫：照「備份與還原」的「換到外接資料庫」程序。' \
    '服務'
  env_is 'DB_USER=postgres' "EXTERNAL_DB_HOST=$LONG_HOST" 'TLS_MODE=selfsigned'
  start_run status
  form_is '部署型態' \
    '  [ OK ] 資料庫 內建；網頁入口 內建 HTTPS（對外埠 443、80）' \
    '  [WARN] .env 和目前的部署不一致：' \
    "         EXTERNAL_DB_HOST=$LONG_HOST" \
    '         系統仍在用內建資料庫，這一行沒有生效。' \
    '         下一次啟動、升級、備份、還原或回到上一版會被擋下。' \
    '         繼續用內建資料庫：刪除這一行。' \
    '         要搬到外接資料庫：照「備份與還原」的「換到外接資料庫」程序。' \
    '服務'
  env_is 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db1.local' 'TLS_MODE=selfsigned'
  LANG_ARG=en start_run status
  form_is 'Deployment form' \
    '  [ OK ] Database: built-in;' \
    '         Web entry: built-in HTTPS (ports 443, 80)' \
    '  [WARN] .env does not match the deployment: EXTERNAL_DB_HOST=db1.local' \
    '         The system still uses the built-in database; this line has no effect.' \
    '         The next start, upgrade, backup, restore or rollback will stop.' \
    '         To keep the built-in database: delete this line.' \
    '         To move to an external database: follow "Switching to an external' \
    '         database" in "backup and restore".' \
    'Services'
  env_is 'DB_USER=postgres' "EXTERNAL_DB_HOST=$LONG_HOST" 'TLS_MODE=selfsigned'
  LANG_ARG=en start_run status
  [ "$(status_form | sed -n '4,5p')" = "  [WARN] .env does not match the deployment:
         EXTERNAL_DB_HOST=$LONG_HOST" ] || { echo "$output"; return 1; }
  env_is 'DB_USER=postgres' 'EXTERNAL_DB_HOST=db01.example.internal' 'TLS_MODE=selfsigned'
  LANG_ARG=ja start_run status
  [ "$(status_form | sed -n '4p')" = '  [WARN] .env が現在の配置と一致しません: EXTERNAL_DB_HOST=db01.example.internal' ] || { echo "$output"; return 1; }
  env_is 'DB_USER=postgres' "EXTERNAL_DB_HOST=$LONG_HOST" 'TLS_MODE=selfsigned'
  LANG_ARG=ja start_run status
  [ "$(status_form | sed -n '4,5p')" = "  [WARN] .env が現在の配置と一致しません:
         EXTERNAL_DB_HOST=$LONG_HOST" ] || { echo "$output"; return 1; }
}

@test "status form section word for word: the recorded address with its port, the .env line moving under its label only when it is too wide" {
  deploy profiles "external-database" '"current.external_db_host": "db01.example.internal"' '"current.external_db_port": "5432"'
  env_is 'EXTERNAL_DB_HOST=' 'TLS_MODE=selfsigned'
  start_run status
  form_is '部署型態' \
    '  [ OK ] 資料庫 外接 db01.example.internal:5432；' \
    '         網頁入口 內建 HTTPS（對外埠 443、80）' \
    '  [WARN] .env 和目前的部署不一致：EXTERNAL_DB_HOST 是空的' \
    '         系統仍在用外接資料庫 db01.example.internal:5432。' \
    '         下一次啟動、升級、備份、還原或回到上一版會被擋下。' \
    '         把這一行填回原值：EXTERNAL_DB_HOST=db01.example.internal' \
    '服務'
  deploy profiles "external-database" "\"current.external_db_host\": \"$LONG_HOST\"" '"current.external_db_port": "5432"'
  start_run status
  [ "$(status_form | sed -n '8,9p')" = "         把這一行填回原值：
         EXTERNAL_DB_HOST=$LONG_HOST" ] || { echo "$output"; return 1; }
  deploy profiles "external-ingress"
  env_is 'TLS_MODE=selfsigned' 'HTTP_PORT=8080'
  start_run status
  form_is '部署型態' \
    '  [ OK ] 資料庫 內建；網頁入口 你的反向代理（網頁服務在埠 8080）' \
    '  [WARN] .env 和目前的部署不一致：TLS_MODE=selfsigned' \
    '         系統仍在用安裝時的入口，不是「你的反向代理」。' \
    '         下一次啟動、升級、備份、還原或回到上一版會被擋下。' \
    '         改回安裝時的值：TLS_MODE=external' \
    '服務'
  LANG_ARG=en start_run status
  [ "$(status_form | sed -n '5,6p')" = '         The system still uses the entry chosen at install,
         not "your reverse proxy".' ] || { echo "$output"; return 1; }
  LANG_ARG=ja start_run status
  [ "$(status_form | sed -n '5,6p')" = '         システムは「お客様のリバースプロキシ」ではなく、
         インストール時の入口を使っています。' ] || { echo "$output"; return 1; }
}
