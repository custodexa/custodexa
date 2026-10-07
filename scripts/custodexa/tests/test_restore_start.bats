#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
load restore_start_host
setup() { rs_start_host; }
# - **WHEN** `ui` 模式的還原啟動服務後仍是封存
# - **THEN** 指令以結束碼 4 結束，狀態為待解封核對，畫面印出解封網址、指紋與 `restore --resume`
@test "restore acceptance: ui 模式待解封" {
  rs_start_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  [ "$(rs_start_phase)" = awaiting_unseal ] || return 1
  [[ $output == *'/unseal'* && $output == *'5a5a5a5a5a5a5a5a'* && $output == *'restore --resume'* ]]
}
# - **WHEN** 待解封核對時執行 `restore --resume`，系統尚未解封
# - **THEN** 腳本說明仍在封存、沒有變更任何東西，以結束碼 4 結束
@test "restore acceptance: 接續時仍封存" {
  rs_start_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/before"
  rs_start_resume
  [ "$status" = 4 ] && [[ $output == *'still sealed'* && $output == *'Nothing was changed.'* ]] || { echo "$output"; return 1; }
  cmp "$ROOT/state.json" "$BATS_TEST_TMPDIR/before"
}
@test "restore startup: an unsealed matching runtime ID completes the key checkpoint" {
  echo unsealed >"$DB/seal"
  rs_start_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ "$(rs_start_phase)" = done ] || return 1
  [[ $output == *'Master key: the ID read after unseal, 5a5a5a5a5a5a5a5a, matches'* ]]
}
# - **WHEN** 接續時讀到的執行期 KEK 識別與備份記錄不同
# - **THEN** 腳本停止服務、還原不算完成，畫面印出兩個識別與接續、回去兩條指令
@test "restore acceptance: 解封後識別不符" {
  rs_start_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  echo unsealed >"$DB/seal"
  echo 0c0c0c0c0c0c0c0c >"$DB/kek"
  rs_start_resume
  [ "$status" = 1 ] && [ "$(rs_start_phase)" = placed ] || { echo "$output"; return 1; }
  [[ $output == *'0c0c0c0c0c0c0c0c'* && $output == *'5a5a5a5a5a5a5a5a'* && $output == *'restore --resume'* && $output == *'restore --revert'* ]] || return 1
  grep -q '^stop ' "$DB/events" || return 1
  local f
  for f in "$DB"/ctr/*; do [ "$(cat "$f")" = stopped ] || return 1; done
}
@test "restore startup: an unreadable seal status does not advance" {
  echo unreadable >"$DB/seal"
  rs_start_run
  [ "$status" = 1 ] && [ "$(rs_start_phase)" = started ] || { echo "$output"; return 1; }
  [[ $output == *'could not be read'* && $output == *'status'* ]]
}
# - **WHEN** 待解封核對時執行 `restore --resume`，封存狀態為已解封但回應沒有執行期 KEK 識別
# - **THEN** 腳本不當作已核對，還原不算完成，說明讀不到識別
@test "restore acceptance: 已解封但讀不到執行期識別" {
  rs_start_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  echo unsealed-noid >"$DB/seal"
  rs_start_resume
  [ "$status" = 1 ] && [[ $output == *'runtime master key ID could not be read'* ]] || { echo "$output"; return 1; }
  [ "$(rs_start_phase)" = awaiting_unseal ] || return 1
  [ "$(jq -r '."last_restore.result"' "$ROOT/state.json")" = in_progress ] || return 1
  [ -z "$(jq -r '."last_restore.kek_evidence" // ""' "$ROOT/state.json")" ]
}
@test "restore startup: a health timeout keeps running containers and resumes at readiness" {
  echo 1 >"$DB/health.rc"
  rs_start_run
  [ "$status" = 1 ] && [ "$(rs_start_phase)" = started ] || { echo "$output"; return 1; }
  [[ $output == *'not ready within'* && $output == *'services are started'* ]] || return 1
  local f
  for f in "$DB"/ctr/*; do [ "$(cat "$f")" = running ] || return 1; done
  : >"$DB/events"
  rm "$DB/health.rc"
  rs_start_resume
  [ "$status" = 4 ] && [ "$(rs_start_phase)" = awaiting_unseal ] || { echo "$output"; return 1; }
  ! grep -Eq 'pg_restore|psql|^stop ' "$DB/events"
}
# - **WHEN** `ui` 模式核對不符、服務已停止之後執行 `restore --resume`
# - **THEN** 腳本重新啟動服務並等待就緒，以結束碼 4 停在待解封核對，由正確材料解封後再接續才完成
@test "restore acceptance: 識別不符之後接續" {
  echo unsealed >"$DB/seal"
  echo 0c0c0c0c0c0c0c0c >"$DB/kek"
  rs_start_run
  [ "$status" = 1 ] && [ "$(rs_start_phase)" = placed ] || { echo "$output"; return 1; }
  touch "$DB/reseal-on-up"
  : >"$DB/events"
  rs_start_resume
  [ "$status" = 4 ] && [ "$(rs_start_phase)" = awaiting_unseal ] || { echo "$output"; return 1; }
  run awk '/^up$/{u=NR} /^verify /{v=NR} /^health$/{h=NR} END{exit !(u && v>u && h>v)}' "$DB/events"
  [ "$status" = 0 ] || return 1
  echo 5a5a5a5a5a5a5a5a >"$DB/kek"
  echo unsealed >"$DB/seal"
  rs_start_resume
  [ "$status" = 0 ] && [ "$(rs_start_phase)" = done ]
}
@test "restore startup: env mismatch then wrong settings refuses without starting" {
  export RS_START_PROVIDER=env RS_START_FP=22a48051594c1949
  bk_env_set ENCRYPTION_KEY AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  echo unsealed >"$DB/seal"
  rs_start_run
  [ "$status" = 1 ] && [ "$(rs_start_phase)" = placed ] || { echo "$output"; return 1; }
  bk_env_set ENCRYPTION_KEY BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
  : >"$DB/events"
  rs_start_resume
  [ "$status" = 1 ] && [[ $output == *'master key in the settings file'* ]] || { echo "$output"; return 1; }
  ! grep -q '^up$' "$DB/events"
}
@test "restore startup: awaiting unseal refuses upgrade" {
  rs_start_run
  [ "$status" = 4 ] || { echo "$output"; return 1; }
  run bash "$RS_I_ENGINE" upgrade --yes --lang en
  [ "$status" = 3 ] && [[ $output == *'cannot be'* && $output == *'upgraded'* ]]
}
