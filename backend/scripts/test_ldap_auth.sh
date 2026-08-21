#!/bin/bash
# LDAP 認證 E2E 測試：首登供應影子用戶（DB 驗證 is_ldap=true + user 角色）
#                   -> 二登不重複建 -> 錯密拒絕 -> 本地 admin 不受影響
#                   -> 改密被拒 -> 審計 source=ldap -> 清理
# 可重複執行；需 docker compose 全套服務（含 ldap-test）運行中
# 測試帳號 testldap/ldappass123 由 bitnami/openldap 以環境變數預置

set -u

API_BASE="http://localhost:8080/api/v1"
LDAP_USER="testldap"
LDAP_PASS="ldappass123"
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
    # 影子用戶為測試產物，刪除後下一輪可重新驗證「首登供應」
    docker compose exec -T postgres psql -U postgres -d custodexa -c \
        "DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username = '$LDAP_USER'); DELETE FROM users WHERE username = '$LDAP_USER';" > /dev/null 2>&1 || true
    echo -e "${GREEN}清理完成${NC}"
}
trap cleanup EXIT

# 防殘留：先清掉前次失敗執行留下的影子用戶，確保本輪從「查無用戶」起跑
cleanup

# 0. 確認 ldap-test 服務可用
info "確認 ldap-test 服務狀態"
if docker compose ps ldap-test 2>/dev/null | grep -q "Up"; then
    test_pass "ldap-test 服務運行中"
else
    test_fail "ldap-test 服務未運行（請先 docker compose up -d ldap-test）"; exit 1
fi

# 1. 本地 admin 登入不受影響（LDAP 啟用下本地路徑零變化）
info "本地 admin 登入"
ADMIN_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | jq -r '.token')
if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
    test_pass "本地 admin 登入成功（LDAP 啟用不影響本地路徑）"
else
    test_fail "本地 admin 登入失敗"; exit 1
fi

# 2. LDAP 用戶首次登入：自動供應影子用戶並核發 token
info "LDAP 用戶首次登入 ($LDAP_USER)"
LOGIN1_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$LDAP_USER\",\"password\":\"$LDAP_PASS\"}")
LDAP_TOKEN=$(echo "$LOGIN1_RESP" | jq -r '.token')
if [ -n "$LDAP_TOKEN" ] && [ "$LDAP_TOKEN" != "null" ]; then
    test_pass "LDAP 用戶首次登入成功"
else
    test_fail "LDAP 用戶首次登入失敗: $LOGIN1_RESP"; exit 1
fi

# 3. token 可正常使用
ME_NAME=$(curl -s "$API_BASE/auth/me" -H "Authorization: Bearer $LDAP_TOKEN" | jq -r '.username')
if [ "$ME_NAME" = "$LDAP_USER" ]; then
    test_pass "LDAP 用戶 token 可存取 /auth/me"
else
    test_fail "LDAP 用戶 token 無法使用 (username: $ME_NAME)"
fi

# 4. DB 驗證：影子用戶 is_ldap=true
IS_LDAP=$(psql_exec "SELECT is_ldap FROM users WHERE username = '$LDAP_USER' AND deleted_at IS NULL;")
if [ "$IS_LDAP" = "t" ]; then
    test_pass "DB 驗證影子用戶 is_ldap=true"
else
    test_fail "DB 影子用戶 is_ldap 異常 (got: '$IS_LDAP')"
fi

# 5. DB 驗證：預設 user 角色
ROLE_NAME=$(psql_exec "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id JOIN users u ON u.id = ur.user_id WHERE u.username = '$LDAP_USER';")
if [ "$ROLE_NAME" = "user" ]; then
    test_pass "DB 驗證影子用戶角色為 user"
else
    test_fail "DB 影子用戶角色異常 (got: '$ROLE_NAME')"
fi

USER_COUNT_1=$(psql_exec "SELECT COUNT(*) FROM users WHERE username = '$LDAP_USER' AND deleted_at IS NULL;")
SHADOW_ID=$(psql_exec "SELECT id FROM users WHERE username = '$LDAP_USER' AND deleted_at IS NULL;")

# 6. 二次登入：複用影子用戶，不重複建立
LOGIN2_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$LDAP_USER\",\"password\":\"$LDAP_PASS\"}")
LDAP_TOKEN2=$(echo "$LOGIN2_RESP" | jq -r '.token')
USER_COUNT_2=$(psql_exec "SELECT COUNT(*) FROM users WHERE username = '$LDAP_USER' AND deleted_at IS NULL;")
if [ -n "$LDAP_TOKEN2" ] && [ "$LDAP_TOKEN2" != "null" ] && [ "$USER_COUNT_1" = "1" ] && [ "$USER_COUNT_2" = "1" ]; then
    test_pass "二次登入成功且未重複建立影子用戶 (count=$USER_COUNT_2)"
else
    test_fail "二次登入異常 (count1=$USER_COUNT_1, count2=$USER_COUNT_2): $LOGIN2_RESP"
fi

# 7. 錯誤密碼被拒（與本地失敗相同形狀：401）
WRONG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$LDAP_USER\",\"password\":\"wrongpassword\"}")
if [ "$WRONG_STATUS" = "401" ]; then
    test_pass "LDAP 錯誤密碼被拒 (401)"
else
    test_fail "LDAP 錯誤密碼未被拒 (HTTP $WRONG_STATUS)"
fi

# 8. 改密路徑拒絕 LDAP 用戶（密碼真身在目錄端）
CHPW_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API_BASE/users/$SHADOW_ID/password" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"password":"newpassword123"}')
if [ "$CHPW_STATUS" = "400" ]; then
    test_pass "LDAP 用戶改密被拒 (400)"
else
    test_fail "LDAP 用戶改密未被拒 (HTTP $CHPW_STATUS)"
fi

# wait_audit_count 輪詢等待審計筆數達標：審計為異步批次寫入，
# 固定 sleep 會因 flush 時點不同而閃失敗，輪詢才能穩定可重複
wait_audit_count() {
    local sql="$1" expect="$2" count=""
    for _ in $(seq 1 10); do
        count=$(psql_exec "$sql")
        if [ -n "$count" ] && [ "$count" -ge "$expect" ] 2>/dev/null; then
            echo "$count"; return 0
        fi
        sleep 1
    done
    echo "${count:-0}"; return 1
}

# 9. 審計日誌標註認證來源（異步寫入，輪詢等待 flush）
AUDIT_LDAP_COUNT=$(wait_audit_count "SELECT COUNT(*) FROM audit_logs WHERE username = '$LDAP_USER' AND action = 'login' AND status = 'success' AND error_msg LIKE '%source=ldap%' AND created_at > NOW() - INTERVAL '2 minutes';" 2)
if [ "$AUDIT_LDAP_COUNT" -ge 2 ] 2>/dev/null; then
    test_pass "登入審計已標註 source=ldap ($AUDIT_LDAP_COUNT 筆)"
else
    test_fail "審計日誌未找到 source=ldap 標註 (count: '$AUDIT_LDAP_COUNT')"
fi

# 10. 失敗登入也有審計（暴力破解偵測訊號）
AUDIT_FAIL_COUNT=$(wait_audit_count "SELECT COUNT(*) FROM audit_logs WHERE username = '$LDAP_USER' AND action = 'login' AND status = 'failure' AND created_at > NOW() - INTERVAL '2 minutes';" 1)
if [ "$AUDIT_FAIL_COUNT" -ge 1 ] 2>/dev/null; then
    test_pass "LDAP 登入失敗已記入審計 ($AUDIT_FAIL_COUNT 筆)"
else
    test_fail "審計日誌未找到 LDAP 失敗登入記錄"
fi

echo ""
echo -e "${GREEN}通過: $PASS_COUNT${NC}"
echo -e "${RED}失敗: $FAIL_COUNT${NC}"
[ "$FAIL_COUNT" -eq 0 ] && echo -e "${GREEN}所有測試通過${NC}" || { echo -e "${RED}部分測試失敗${NC}"; exit 1; }
