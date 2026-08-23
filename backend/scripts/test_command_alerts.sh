#!/bin/bash
# 危險指令告警 E2E 測試：
#   規則 CRUD（無效 regex 400 / 非法 severity 400 / 建立 / 更新 / 刪除）
#   -> 權限（非 admin 改規則 403、無權限查告警 403、未認證 401）
#   -> 告警查詢（severity / user_id / 時間範圍過濾、分頁、rule_name 冗餘欄位）
#
# 測試邊界說明：告警比對掛在 proxy.CommandRecorder 的 writeLoop 入庫路徑，
# 直接 INSERT session_commands 不會經過該路徑、不會觸發比對；
# 故本腳本的告警資料以 SQL 種子 INSERT command_alerts 驗證「查詢面」，
# 「真實觸發鏈路」（瀏覽器 SSH 輸入危險指令 -> recorder -> matcher -> 告警入庫）
# 由瀏覽器實機 E2E 驗證。
# 可重複執行；需 docker compose 全套服務運行中

set -u

API_BASE="http://localhost:8080/api/v1"
MARKER="cmdalert"                      # 所有測試產物統一前綴，清理用
RESTRICTED_ROLE="${MARKER}_restricted" # 不在 RBAC 矩陣內 -> 任何權限檢查皆 403
USER2_NAME="${MARKER}_user2"
NOPERM_NAME="${MARKER}_noperm"
RULE_NAME="${MARKER}_rule"
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
    # 種子告警/規則/會話/用戶/角色皆為測試產物，硬刪除確保下一輪從乾淨狀態起跑
    docker compose exec -T postgres psql -U postgres -d custodexa -c "
        DELETE FROM command_alerts WHERE rule_name LIKE '${MARKER}_%';
        DELETE FROM alert_rules WHERE name LIKE '${MARKER}_%';
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

# 2. 種子規則存在性：migration v7.9 應帶入 8 條預設規則
SEED_RULES=$(curl -s "$API_BASE/alert-rules" -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.total')
if [ "$SEED_RULES" -ge 8 ] 2>/dev/null; then
    test_pass "種子規則存在 (total=$SEED_RULES >= 8)"
else
    test_fail "種子規則數異常 (total=$SEED_RULES)"
fi

# 3. 無效 regex 規則被拒（400 且錯誤訊息含原因）
info "POST /alert-rules（無效 regex）"
BAD_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/alert-rules" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${RULE_NAME}_bad\",\"pattern\":\"rm -rf (\",\"severity\":\"high\"}")
BAD_CODE=$(echo "$BAD_RESP" | tail -1)
BAD_ERR=$(echo "$BAD_RESP" | head -1 | jq -r '.error')
if [ "$BAD_CODE" = "400" ] && echo "$BAD_ERR" | grep -q "regex"; then
    test_pass "無效 regex 被拒 (400: $BAD_ERR)"
else
    test_fail "無效 regex 未被正確拒絕 (HTTP $BAD_CODE: $BAD_ERR)"
fi

# 4. 非法 severity 被拒
SEV_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/alert-rules" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${RULE_NAME}_sev\",\"pattern\":\"x\",\"severity\":\"critical\"}")
if [ "$SEV_CODE" = "400" ]; then
    test_pass "非法 severity 被拒 (400)"
else
    test_fail "非法 severity 未被拒 (HTTP $SEV_CODE)"
fi

# 5. 建立合法測試規則
info "POST /alert-rules（合法規則）"
CREATE_RESP=$(curl -s -X POST "$API_BASE/alert-rules" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$RULE_NAME\",\"pattern\":\"${MARKER}_dangerous\",\"severity\":\"high\"}")
RULE_ID=$(echo "$CREATE_RESP" | jq -r '.id')
if [ -n "$RULE_ID" ] && [ "$RULE_ID" != "null" ]; then
    test_pass "測試規則已建立 (id=$RULE_ID)"
else
    test_fail "建立測試規則失敗: $CREATE_RESP"; exit 1
fi

# 6. 更新規則（改 severity 與停用）
UPDATE_RESP=$(curl -s -w "\n%{http_code}" -X PUT "$API_BASE/alert-rules/$RULE_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$RULE_NAME\",\"pattern\":\"${MARKER}_dangerous\",\"severity\":\"medium\",\"enabled\":false}")
UPDATE_CODE=$(echo "$UPDATE_RESP" | tail -1)
DB_SEV=$(psql_exec "SELECT severity FROM alert_rules WHERE id = $RULE_ID;")
DB_ENABLED=$(psql_exec "SELECT enabled FROM alert_rules WHERE id = $RULE_ID;")
if [ "$UPDATE_CODE" = "200" ] && [ "$DB_SEV" = "medium" ] && [ "$DB_ENABLED" = "f" ]; then
    test_pass "規則更新生效 (severity=medium, enabled=false)"
else
    test_fail "規則更新異常 (HTTP $UPDATE_CODE, severity=$DB_SEV, enabled=$DB_ENABLED)"
fi

# 7. 更新不存在的規則 404
NF_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API_BASE/alert-rules/999999" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"x\",\"pattern\":\"x\",\"severity\":\"low\"}")
if [ "$NF_CODE" = "404" ]; then
    test_pass "更新不存在規則回 404"
else
    test_fail "更新不存在規則未回 404 (HTTP $NF_CODE)"
fi

# 8. 建立測試用戶（告警過濾維度 + 權限測試用）
info "建立測試用戶"
curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER2_NAME\",\"password\":\"test123456\",\"email\":\"$USER2_NAME@test.local\",\"roles\":[\"user\"]}" > /dev/null
USER2_ID=$(psql_exec "SELECT id FROM users WHERE username = '$USER2_NAME' AND deleted_at IS NULL;")

docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO roles (name, description, created_at, updated_at)
    VALUES ('$RESTRICTED_ROLE', 'command-alerts E2E 臨時角色（無任何權限）', NOW(), NOW());
" > /dev/null 2>&1
curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NOPERM_NAME\",\"password\":\"test123456\",\"email\":\"$NOPERM_NAME@test.local\",\"roles\":[\"$RESTRICTED_ROLE\"]}" > /dev/null
if [ -n "$USER2_ID" ]; then
    test_pass "測試用戶已建立 (user2=$USER2_ID)"
else
    test_fail "建立測試用戶失敗"; exit 1
fi

# 9. 權限：非 admin（user 角色）操作規則 CRUD 應 403
USER2_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER2_NAME\",\"password\":\"test123456\"}" | jq -r '.token')
RULE_403=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/alert-rules" \
    -H "Authorization: Bearer $USER2_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"x","pattern":"x","severity":"low"}')
RULE_LIST_403=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/alert-rules" -H "Authorization: Bearer $USER2_TOKEN")
if [ "$RULE_403" = "403" ] && [ "$RULE_LIST_403" = "403" ]; then
    test_pass "非 admin 操作規則被拒 (POST/GET 皆 403)"
else
    test_fail "非 admin 操作規則未被拒 (POST=$RULE_403, GET=$RULE_LIST_403)"
fi

# 10. 種子告警資料：種子會話 + 直接 INSERT command_alerts（見檔頭邊界說明）
info "種子會話與告警資料"
docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO sessions (session_id, status, protocol, user_id, client_ip, start_time, created_at, updated_at)
    VALUES ('${MARKER}-sess-a', 'closed', 'ssh', $ADMIN_ID, '127.0.0.1', NOW() - INTERVAL '10 minutes', NOW(), NOW()),
           ('${MARKER}-sess-b', 'closed', 'ssh', $USER2_ID, '127.0.0.1', NOW() - INTERVAL '5 minutes', NOW(), NOW());
" > /dev/null 2>&1
SID_A=$(psql_exec "SELECT id FROM sessions WHERE session_id = '${MARKER}-sess-a';")
SID_B=$(psql_exec "SELECT id FROM sessions WHERE session_id = '${MARKER}-sess-b';")

docker compose exec -T postgres psql -U postgres -d custodexa -c "
    INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id, asset_id, command, severity, triggered_at) VALUES
        ($RULE_ID, '${RULE_NAME}', $SID_A, $ADMIN_ID, NULL, 'rm -rf /data',        'high',   NOW() - INTERVAL '9 minutes'),
        ($RULE_ID, '${RULE_NAME}', $SID_A, $ADMIN_ID, NULL, 'chmod 777 /etc',      'medium', NOW() - INTERVAL '8 minutes'),
        ($RULE_ID, '${RULE_NAME}', $SID_B, $USER2_ID, NULL, 'mkfs.ext4 /dev/sdb1', 'high',   NOW() - INTERVAL '4 minutes');
" > /dev/null 2>&1
SEED_ALERTS=$(psql_exec "SELECT COUNT(*) FROM command_alerts WHERE rule_name = '${RULE_NAME}';")
if [ "$SEED_ALERTS" = "3" ]; then
    test_pass "種子告警已寫入 (3 筆)"
else
    test_fail "種子告警寫入異常 (count=$SEED_ALERTS)"; exit 1
fi

# 11. 告警查詢：severity 過濾 + rule_name 冗餘欄位存在
info "GET /command-alerts?severity=high"
HIGH_RESP=$(curl -s "$API_BASE/command-alerts?severity=high&page_size=100" -H "Authorization: Bearer $ADMIN_TOKEN")
HIGH_HITS=$(echo "$HIGH_RESP" | jq -r --arg rn "$RULE_NAME" '[.data[] | select(.rule_name == $rn)] | length')
HIGH_SEVS=$(echo "$HIGH_RESP" | jq -r --arg rn "$RULE_NAME" '[.data[] | select(.rule_name == $rn) | .severity] | unique | join(",")')
if [ "$HIGH_HITS" = "2" ] && [ "$HIGH_SEVS" = "high" ]; then
    test_pass "severity=high 過濾正確且 data 含 rule_name 欄位 (hits=2)"
else
    test_fail "severity 過濾異常 (hits=$HIGH_HITS, sevs=$HIGH_SEVS)"
fi

# 12. 非法 severity 查詢 400
SEVQ_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/command-alerts?severity=bogus" -H "Authorization: Bearer $ADMIN_TOKEN")
if [ "$SEVQ_CODE" = "400" ]; then
    test_pass "非法 severity 查詢被拒 (400)"
else
    test_fail "非法 severity 查詢未被拒 (HTTP $SEVQ_CODE)"
fi

# 13. user_id 過濾
UID_RESP=$(curl -s "$API_BASE/command-alerts?user_id=$USER2_ID" -H "Authorization: Bearer $ADMIN_TOKEN")
UID_TOTAL=$(echo "$UID_RESP" | jq -r '.total')
UID_CMD=$(echo "$UID_RESP" | jq -r '.data[0].command')
if [ "$UID_TOTAL" = "1" ] && [ "$UID_CMD" = "mkfs.ext4 /dev/sdb1" ]; then
    test_pass "user_id 過濾正確 (total=1)"
else
    test_fail "user_id 過濾異常 (total=$UID_TOTAL, cmd=$UID_CMD)"
fi

# 14. 時間範圍過濾：最近 6 分鐘 -> 僅 session B 那筆
START_TS=$(date -u -v-6M +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '6 minutes ago' +"%Y-%m-%dT%H:%M:%SZ")
TIME_RESP=$(curl -s "$API_BASE/command-alerts?start_time=$START_TS&page_size=100" -H "Authorization: Bearer $ADMIN_TOKEN")
TIME_HITS=$(echo "$TIME_RESP" | jq -r --arg rn "$RULE_NAME" '[.data[] | select(.rule_name == $rn)] | length')
if [ "$TIME_HITS" = "1" ]; then
    test_pass "start_time 過濾正確 (hits=1)"
else
    test_fail "start_time 過濾異常 (hits=$TIME_HITS)"
fi

# 15. 分頁：限定 user_id=ADMIN_ID（2 筆種子）驗 total 不變、newest-first
PG1_RESP=$(curl -s "$API_BASE/command-alerts?user_id=$ADMIN_ID&page=1&page_size=1" -H "Authorization: Bearer $ADMIN_TOKEN")
PG2_RESP=$(curl -s "$API_BASE/command-alerts?user_id=$ADMIN_ID&page=2&page_size=1" -H "Authorization: Bearer $ADMIN_TOKEN")
PG1_TOTAL=$(echo "$PG1_RESP" | jq -r '.total')
PG1_LEN=$(echo "$PG1_RESP" | jq -r '.data | length')
PG1_CMD=$(echo "$PG1_RESP" | jq -r '.data[0].command')
PG2_CMD=$(echo "$PG2_RESP" | jq -r '.data[0].command')
PG2_PAGE=$(echo "$PG2_RESP" | jq -r '.page')
# triggered_at 倒序：第一頁應是較新的 chmod 777，第二頁是較舊的 rm -rf
if [ "$PG1_TOTAL" = "2" ] && [ "$PG1_LEN" = "1" ] && [ "$PG2_PAGE" = "2" ] && \
   [ "$PG1_CMD" = "chmod 777 /etc" ] && [ "$PG2_CMD" = "rm -rf /data" ]; then
    test_pass "分頁與 newest-first 排序正確 (p1='$PG1_CMD', p2='$PG2_CMD')"
else
    test_fail "分頁異常 (total=$PG1_TOTAL, len=$PG1_LEN, p1='$PG1_CMD', p2='$PG2_CMD')"
fi

# 16. 權限：無權限角色查告警 403、未認證 401（audit:view 與指令審計同模式）
NOPERM_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$NOPERM_NAME\",\"password\":\"test123456\"}" | jq -r '.token')
ALERT_403=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/command-alerts" -H "Authorization: Bearer $NOPERM_TOKEN")
ALERT_401=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/command-alerts")
if [ "$ALERT_403" = "403" ]; then
    test_pass "無權限用戶查告警被拒 (403)"
else
    test_fail "無權限用戶查告警未被拒 (HTTP $ALERT_403)"
fi
if [ "$ALERT_401" = "401" ]; then
    test_pass "未認證請求被拒 (401)"
else
    test_fail "未認證請求未被拒 (HTTP $ALERT_401)"
fi

# 17. 刪除規則：API 成功且 DB 消失；歷史告警因 rule_name 快照仍可查
DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API_BASE/alert-rules/$RULE_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
RULE_LEFT=$(psql_exec "SELECT COUNT(*) FROM alert_rules WHERE id = $RULE_ID;")
ALERT_LEFT=$(psql_exec "SELECT COUNT(*) FROM command_alerts WHERE rule_name = '${RULE_NAME}';")
if [ "$DEL_CODE" = "200" ] && [ "$RULE_LEFT" = "0" ] && [ "$ALERT_LEFT" = "3" ]; then
    test_pass "規則刪除成功，歷史告警保留 (snapshot 冗餘)"
else
    test_fail "規則刪除異常 (HTTP $DEL_CODE, rule_left=$RULE_LEFT, alert_left=$ALERT_LEFT)"
fi

echo ""
echo -e "${GREEN}通過: $PASS_COUNT${NC}"
echo -e "${RED}失敗: $FAIL_COUNT${NC}"
[ "$FAIL_COUNT" -eq 0 ] && echo -e "${GREEN}所有測試通過${NC}" || { echo -e "${RED}部分測試失敗${NC}"; exit 1; }
