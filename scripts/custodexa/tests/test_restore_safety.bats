#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_safety_host

setup() { rs_safety_host; }

@test "restore safety: a produced file passes the full reader, key and migration checks without a start" {
  rs_safety_run
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = safety ] || return 1
  local file
  file=$(jq -r '."last_restore.safety_file"' "$ROOT/state.json")
  [ -f "$file" ] || return 1
  run bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/cmd_restore.sh"
    CX_ROOT=$2 CX_DIR=$2/current CX_RS_ENGINE=1.16.0 CX_RS_DIR=$3 CX_RS_TS=verify
    mkdir -m700 "$CX_RS_DIR"; cx_rs_open --verify-only "$4" && cx_rs_checks && cx_rs_migrations' _ "$SRC" "$ROOT" "$BATS_TEST_TMPDIR/verify" "$file"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  rs_safety_no_cover
}

# - **WHEN** 同機還原時，目前資料庫的主金鑰識別不只一個
# - **THEN** 腳本在停止服務前說明腳本的安全備份將無法自動還原，互動時只提供自備備份，非互動未帶自備備份選項即拒絕，服務沒有停止
@test "restore acceptance: 目前資料會產生無法自動還原的安全備份" {
  local kind reason brief
  for kind in duplicate hsm images old; do
    rm -rf "$ROOT" "$DB" "$FAKE_DOCKER_REPLAY"
    rs_safety_host
    brief=""
    case $kind in
      duplicate) printf '%s\n' 5a5a5a5a5a5a5a5a 6b6b6b6b6b6b6b6b >"$DB/kek"; reason='2 were'; brief='a single master key ID cannot be read' ;;
      hsm) bk_env_set KEK_PROVIDER hsm; reason='mode is hsm' ;;
      images) : >"$DB/images"; reason='missing locally' ;;
      old)
        cp -a "$ROOT/releases/1.16.0" "$ROOT/releases/1.15.2"
        printf '1.15.2\n' >"$ROOT/releases/1.15.2/VERSION"
        /usr/bin/ln -sfn releases/1.15.2 "$ROOT/current"
        bk_state_set current.version 1.15.2
        reason='older than 1.16.0' ;;
    esac
    run bash "$ROOT/releases/1.16.0/custodexa.sh" restore "$BATS_TEST_TMPDIR/source.tar" --same-host --yes --lang en </dev/null
    [ "$status" -eq 3 ] && [[ $output == *'could not be restored'* && $output == *"${brief:-$reason}"* ]] || { echo "$output"; return 1; }
    ! grep -q '^stop ' "$DB/events" || return 1
    : >"$DB/only-preflight"
    run bash -c 'printf "2\n" | script -qec "$1" /dev/null' _ "bash '$ROOT/releases/1.16.0/custodexa.sh' restore '$BATS_TEST_TMPDIR/source.tar' --same-host --lang en"
    [ "$status" -eq 0 ] && [[ $output == *'[2]'* && $output != *'[1]'* && $output == *"$reason"* ]] || { echo "$output"; return 1; }
    ! grep -q '^stop ' "$DB/events" || return 1
  done
}

@test "restore safety: a producer-legal non-unique fingerprint race is whole but cannot be restored" {
  : >"$DB/race"
  rs_safety_run
  rs_safety_failed || return 1
  [[ $output == *'whole, but this script cannot restore'* && $output == *'no master key fingerprint'* ]] || { echo "$output"; return 1; }
  local file
  file=$(find "$ROOT/backups" -name '*.tar' -maxdepth 1)
  [ -f "$file" ] || return 1
  [ "$(/usr/bin/tar -xOf "$file" backup-manifest.json | jq -r '."kek.fingerprint_status"')" = not-unique ]
}

@test "restore safety: readback failure preserves the deployment and prints both recovery commands" {
  printf '1\n' >"$DB/tar.readback.rc"
  rs_safety_run
  rs_safety_failed || return 1
  [[ $output == *'did not check out when read back'* ]] || { echo "$output"; return 1; }
}

# - **WHEN** 同機還原時安全備份因空間不足失敗
# - **THEN** 腳本停下，資料沒有任何變更，畫面印出接續與回去兩條指令，回去的說明寫明只是重新啟動原服務
@test "restore acceptance: 安全備份失敗" {
  fake tar 'case " $* " in *" -czf "*) echo "No space left on device" >&2; exit 1 ;; esac; exec /usr/bin/tar "$@"'
  rs_safety_run
  rs_safety_failed || return 1
  [[ $output == *'No space left on device'* ]] || { echo "$output"; return 1; }
}

# - **WHEN** 安全備份因空間不足失敗後，執行畫面印出的接續指令並帶上自備備份的識別、時間與還原程序，時間晚於這次還原停止服務的時間
# - **THEN** 腳本登記自備備份並往下進行，不重新停機、不重做腳本安全備份
@test "restore acceptance: 安全備份失敗後改用自備備份接續" {
  fake tar 'case " $* " in *" -czf "*) echo "No space left on device" >&2; exit 1 ;; esac; exec /usr/bin/tar "$@"'
  rs_safety_run
  rs_safety_failed || return 1
  local cmd time
  cmd=$(printf '%s\n' "$output" | sed -n 's/^    sudo \(.*--backup-ref.*\)$/\1/p')
  [ -n "$cmd" ] || { echo "$output"; return 1; }
  time=$(date -d "$(jq -r '."last_restore.stopped_at"' "$ROOT/state.json") + 1 hour" '+%Y-%m-%d %H:%M')
  cmd=${cmd//<id>/storage-snapshot}; cmd=${cmd//<time>/\"$time\"}; cmd=${cmd//<procedure>/\"restore storage snapshot\"}
  cp "$DB/events" "$BATS_TEST_TMPDIR/events-before"
  run bash -c "$cmd"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.safety"' "$ROOT/state.json")" = own ] || return 1
  [ "$(jq -r '."last_restore.safety_ref"' "$ROOT/state.json")" = storage-snapshot ] || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = safety ] || return 1
  ! diff "$BATS_TEST_TMPDIR/events-before" "$DB/events" | grep -E '^\+[^+].*(stop|pg_dump|tar pack)' || return 1
  rs_safety_no_cover
}

# - **WHEN** 選擇自備備份，輸入的時間早於這次停止服務的時間
# - **THEN** 腳本拒絕這份自備備份，不進入覆蓋步驟
@test "restore acceptance: 自備備份時間早於停機" {
  printf '1\n' >"$DB/tar.readback.rc"
  rs_safety_run
  rs_safety_failed || return 1
  run bash "$ROOT/custodexa.sh" restore --resume --backup-ref mine --backup-time '2020-01-01 00:00' --backup-restore procedure --lang en
  [ "$status" -eq 1 ] && [[ $output == *'is before the stop time'* ]] || { echo "$output"; return 1; }
  rs_safety_no_cover
}

@test "restore safety: a service restarted after the stop refuses an own backup even when stopped again" {
  printf '1\n' >"$DB/tar.readback.rc"
  rs_safety_run
  rs_safety_failed || return 1
  printf '2099-01-01T00:00:00Z\n' >"$DB/started.guacd"
  run bash "$ROOT/custodexa.sh" restore --resume --backup-ref mine --backup-time '2099-01-02 00:00' --backup-restore procedure --lang en
  [ "$status" -eq 1 ] && [[ $output == *'have been started since the recorded stop'* && $output == *'restore --revert'* ]] || { echo "$output"; return 1; }
  rs_safety_no_cover
}

@test "restore safety: own-backup options after swapping are a usage error" {
  printf '1\n' >"$DB/tar.readback.rc"
  rs_safety_run
  rs_safety_failed || return 1
  bk_state_set last_restore.phase swapped
  bk_state_set last_restore.covering 1
  run bash "$ROOT/custodexa.sh" restore --resume --backup-ref mine --backup-time '2099-01-02 00:00' --backup-restore procedure --lang en
  [ "$status" -eq 2 ] && [[ $output == *'only accepted'* ]] || { echo "$output"; return 1; }
  rs_safety_no_cover
}

@test "restore safety: terminal resume asks again and registers an own backup using the recorded stop" {
  printf '1\n' >"$DB/tar.readback.rc"
  rs_safety_run
  rs_safety_failed || return 1
  local time
  time=$(date -d "$(jq -r '."last_restore.stopped_at"' "$ROOT/state.json") + 1 hour" '+%Y-%m-%d %H:%M')
  cp "$DB/events" "$BATS_TEST_TMPDIR/events-before"
  run bash -c 'printf "2\nmine\n%s\nrestore snapshot\nyes\n" "$2" | script -qec "$1" /dev/null' _ "bash '$ROOT/custodexa.sh' restore --resume --lang en" "$time"
  [ "$status" -eq 0 ] && [[ $output == *'The last safety backup did not finish'* && $output != *'have not been stopped'* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.safety"' "$ROOT/state.json")" = own ] || return 1
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = safety ] || return 1
  ! diff "$BATS_TEST_TMPDIR/events-before" "$DB/events" | grep -E '^\+[^+].*(stop|pg_dump|tar pack)' || return 1
  rs_safety_no_cover
}
