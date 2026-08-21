#!/bin/bash
# 指令審計 E2E 測試（command-audit tasks 3.2）：
#   DB 種子指令資料（兩個 session、不同 user）
#   -> 單會話 API 順序驗證 -> 跨會話 keyword 搜尋 -> user_id 過濾
#   -> 分頁 total -> 無權限用戶 403 -> 清理
# 真鍵流由瀏覽器 E2E（tasks 3.1）驗證；本腳本以 DB 種子驗 API 形狀/權限/分頁
# 可重複執行；需 docker compose 全套服務運行中
# 無權限用戶做法：建立不在 RBAC 矩陣（admin/user/auditor）內的臨時角色，
# RequirePermission 對未知角色一律拒絕，得到 403

set -u

API_BASE="http://localhost:8080/api/v1"
MARKER="cmdaudit"                      # 所有測試產物統一前綴，清理用
RESTRICTED_ROLE="${MARKER}_restricted" # 不在 RBAC 矩陣內 -> 任何權限檢查皆 403
USER2_NAME="${MARKER}_user2"
NOPERM_NAME="${MARKER}_noperm"
PASS_COUNT=0
FAIL_COUNT=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT+1)); }
test_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

psql_exec() {
    docker compose exec -T postgres psql -U postgres -d custodexa -t -A -c "$1" 2>/dev/null | tr -d '[:space:]'
}

cleanup() {
    echo -e "\n${YELLOW}清理測試數據...${NC}"
    # 種子指令/會話/用戶/角色皆為測試產物，硬刪除確保下一輪從乾淨狀態起跑
    docker compose exec -T postgres psql -U postgres -d custodexa -c "
        DELETE FROM session_commands WHERE session_id IN (SELECT id FROM sessions WHERE session_id LIKE '${MARKER}-%');
        DELETE FROM sessions WHERE session_id LIKE '${MARKER}-%';
        DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username LIKE '${MARKER}_%');
        DELETE FROM users WHERE username LIKE '${MARKER}_%';
        DELETE FROM roles WHERE name = '$RESTRICTED_ROLE';
    " > /dev/null 2>&1 || true
    echo -e "${GREEN}清理完成${NC}"
}
trap cleanup EXIT

# 防殘留：先清掉前次失敗執行留下的資料
cleanup

# 1. 管理員登入
info "管理員登入"
ADMIN_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | jq -r '.token')
if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
    test_pass "管理員登入成功"
else
    test_fail "管理員登入失敗"; exit 1
fi
ADMIN_ID=$(psql_exec "SELECT id FROM users WHERE username = 'admin' AND deleted_at IS NULL;")

# 2. 建立第二位用戶（跨會話搜尋需不同 user 的資料）
info "建立測試用戶 $USER2_NAME"
USER2_RESP=$(curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER2_NAME\",\"password\":\"test123456\",\"email\":\"$USER2_NAME@test.local\",\"roles\":[\"user\"]}")
USER2_ID=$(psql_exec "SELECT id FROM users WHERE username = '$USER2_NAME' AND deleted_at IS NULL;")
if [ -n "$USER2_ID" ]; then
    test_pass "測試用戶已建立 (id=$USER2_ID)"
else
    test_fail "建立測試用戶失敗: $USER2_RESP"; exit 1
fi

# 3. 種子資料：兩個會話 + 指令記錄（直接 INSERT，模擬 recorder 入庫結果）
info "種子兩個會話與指令資料"
docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO sessions (session_id, status, protocol, user_id, client_ip, start_time, created_at, updated_at)
    VALUES ('${MARKER}-sess-a', 'closed', 'ssh', $ADMIN_ID, '127.0.0.1', NOW() - INTERVAL '10 minutes', NOW(), NOW()),
           ('${MARKER}-sess-b', 'closed', 'ssh', $USER2_ID, '127.0.0.1', NOW() - INTERVAL '5 minutes', NOW(), NOW());
" > /dev/null 2>&1
SID_A=$(psql_exec "SELECT id FROM sessions WHERE session_id = '${MARKER}-sess-a';")
SID_B=$(psql_exec "SELECT id FROM sessions WHERE session_id = '${MARKER}-sess-b';")
if [ -n "$SID_A" ] && [ -n "$SID_B" ]; then
    test_pass "種子會話已建立 (A=$SID_A, B=$SID_B)"
else
    test_fail "種子會話建立失敗"; exit 1
fi

docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at) VALUES
        ($SID_A, $ADMIN_ID, NULL, 'ls -la',            1, NOW() - INTERVAL '9 minutes'),
        ($SID_A, $ADMIN_ID, NULL, 'rm -rf /tmp/x',     2, NOW() - INTERVAL '8 minutes'),
        ($SID_A, $ADMIN_ID, NULL, 'echo cmdaudit done', 3, NOW() - INTERVAL '7 minutes'),
        ($SID_B, $USER2_ID, NULL, 'whoami',            1, NOW() - INTERVAL '4 minutes'),
        ($SID_B, $USER2_ID, NULL, 'rm old.log',        2, NOW() - INTERVAL '3 minutes');
" > /dev/null 2>&1
SEED_COUNT=$(psql_exec "SELECT COUNT(*) FROM session_commands WHERE session_id IN ($SID_A, $SID_B);")
if [ "$SEED_COUNT" = "5" ]; then
    test_pass "種子指令已寫入 (5 筆)"
else
    test_fail "種子指令寫入異常 (count=$SEED_COUNT)"; exit 1
fi

# 4. 單會話指令流：順序與內容
info "GET /sessions/$SID_A/commands"
SESS_RESP=$(curl -s "$API_BASE/sessions/$SID_A/commands" -H "Authorization: Bearer $ADMIN_TOKEN")
SESS_TOTAL=$(echo "$SESS_RESP" | jq -r '.total')
SEQ_ORDER=$(echo "$SESS_RESP" | jq -r '[.data[].seq] | join(",")')
FIRST_CMD=$(echo "$SESS_RESP" | jq -r '.data[0].command')
if [ "$SESS_TOTAL" = "3" ] && [ "$SEQ_ORDER" = "1,2,3" ] && [ "$FIRST_CMD" = "ls -la" ]; then
    test_pass "單會話指令按 seq 順序返回 (total=3, seq=1,2,3)"
else
    test_fail "單會話指令異常 (total=$SESS_TOTAL, seq=$SEQ_ORDER, first=$FIRST_CMD)"
fi

# 5. 跨會話 keyword 搜尋：兩個 session 的 'rm' 都要命中
info "GET /commands?keyword=rm"
KW_RESP=$(curl -s "$API_BASE/commands?keyword=rm" -H "Authorization: Bearer $ADMIN_TOKEN")
# 限定在種子會話內計數，避免環境中其他真實指令記錄干擾可重複性
KW_HITS=$(echo "$KW_RESP" | jq -r --argjson a "$SID_A" --argjson b "$SID_B" \
    '[.data[] | select(.session_id == $a or .session_id == $b)] | length')
KW_SESSIONS=$(echo "$KW_RESP" | jq -r --argjson a "$SID_A" --argjson b "$SID_B" \
    '[.data[] | select(.session_id == $a or .session_id == $b) | .session_id] | unique | length')
if [ "$KW_HITS" = "2" ] && [ "$KW_SESSIONS" = "2" ]; then
    test_pass "keyword=rm 跨會話命中 2 筆、橫跨 2 個會話"
else
    test_fail "keyword 搜尋異常 (hits=$KW_HITS, sessions=$KW_SESSIONS): $(echo "$KW_RESP" | jq -c '.total')"
fi

# 6. user_id 過濾
info "GET /commands?user_id=$USER2_ID"
UID_RESP=$(curl -s "$API_BASE/commands?user_id=$USER2_ID" -H "Authorization: Bearer $ADMIN_TOKEN")
UID_TOTAL=$(echo "$UID_RESP" | jq -r '.total')
UID_USERS=$(echo "$UID_RESP" | jq -r '[.data[].user_id] | unique | join(",")')
if [ "$UID_TOTAL" = "2" ] && [ "$UID_USERS" = "$USER2_ID" ]; then
    test_pass "user_id 過濾正確 (total=2)"
else
    test_fail "user_id 過濾異常 (total=$UID_TOTAL, users=$UID_USERS)"
fi

# 7. 分頁：page_size=1 時 total 不變、data 僅 1 筆、第二頁內容不同
info "分頁驗證 (user_id=$USER2_ID, page_size=1)"
PG1_RESP=$(curl -s "$API_BASE/commands?user_id=$USER2_ID&page=1&page_size=1" -H "Authorization: Bearer $ADMIN_TOKEN")
PG2_RESP=$(curl -s "$API_BASE/commands?user_id=$USER2_ID&page=2&page_size=1" -H "Authorization: Bearer $ADMIN_TOKEN")
PG1_TOTAL=$(echo "$PG1_RESP" | jq -r '.total')
PG1_LEN=$(echo "$PG1_RESP" | jq -r '.data | length')
PG1_CMD=$(echo "$PG1_RESP" | jq -r '.data[0].command')
PG2_CMD=$(echo "$PG2_RESP" | jq -r '.data[0].command')
PG2_PAGE=$(echo "$PG2_RESP" | jq -r '.page')
if [ "$PG1_TOTAL" = "2" ] && [ "$PG1_LEN" = "1" ] && [ "$PG2_PAGE" = "2" ] && [ "$PG1_CMD" != "$PG2_CMD" ]; then
    test_pass "分頁正確 (total=2, page1='$PG1_CMD', page2='$PG2_CMD')"
else
    test_fail "分頁異常 (total=$PG1_TOTAL, len=$PG1_LEN, p1='$PG1_CMD', p2='$PG2_CMD')"
fi

# 8. 時間範圍過濾：只取最近 6 分鐘 -> 僅 session B 的 2 筆
info "時間範圍過濾"
START_TS=$(date -u -v-6M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '6 minutes ago' +"%Y-%m-%dT%H:%M:%SZ")
TIME_RESP=$(curl -s "$API_BASE/commands?user_id=$USER2_ID&start_time=$START_TS" -H "Authorization: Bearer $ADMIN_TOKEN")
TIME_TOTAL=$(echo "$TIME_RESP" | jq -r '.total')
if [ "$TIME_TOTAL" = "2" ]; then
    test_pass "start_time 過濾正確 (total=2)"
else
    test_fail "start_time 過濾異常 (total=$TIME_TOTAL)"
fi

# 9. 無權限用戶 403：建立矩陣外角色並指派，跨會話與單會話 API 皆應拒絕
# 變數後緊接全形字元時 macOS bash 3.2 解析會出錯，統一用 ${} 包裹
info "建立無權限用戶 ${NOPERM_NAME} (角色 ${RESTRICTED_ROLE})"
docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO roles (name, description, created_at, updated_at)
    VALUES ('$RESTRICTED_ROLE', 'command-audit E2E 臨時角色（無任何權限）', NOW(), NOW());
" > /dev/null 2>&1
curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NOPERM_NAME\",\"password\":\"test123456\",\"email\":\"$NOPERM_NAME@test.local\",\"roles\":[\"$RESTRICTED_ROLE\"]}" > /dev/null

NOPERM_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NOPERM_NAME\",\"password\":\"test123456\"}" | jq -r '.token')
if [ -n "$NOPERM_TOKEN" ] && [ "$NOPERM_TOKEN" != "null" ]; then
    test_pass "無權限用戶登入成功"
else
    test_fail "無權限用戶登入失敗"; exit 1
fi

CMD_403=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/commands?keyword=rm" -H "Authorization: Bearer $NOPERM_TOKEN")
SESS_403=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/sessions/$SID_A/commands" -H "Authorization: Bearer $NOPERM_TOKEN")
if [ "$CMD_403" = "403" ]; then
    test_pass "無權限用戶查 GET /commands 被拒 (403)"
else
    test_fail "無權限用戶查 GET /commands 未被拒 (HTTP $CMD_403)"
fi
if [ "$SESS_403" = "403" ]; then
    test_pass "無權限用戶查 GET /sessions/:id/commands 被拒 (403)"
else
    test_fail "無權限用戶查單會話指令未被拒 (HTTP $SESS_403)"
fi

# 10. 未認證請求 401
NOAUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/commands")
if [ "$NOAUTH_STATUS" = "401" ]; then
    test_pass "未認證請求被拒 (401)"
else
    test_fail "未認證請求未被拒 (HTTP $NOAUTH_STATUS)"
fi

echo ""
echo -e "${GREEN}通過: $PASS_COUNT${NC}"
echo -e "${RED}失敗: $FAIL_COUNT${NC}"
[ "$FAIL_COUNT" -eq 0 ] && echo -e "${GREEN}所有測試通過${NC}" || { echo -e "${RED}部分測試失敗${NC}"; exit 1; }
