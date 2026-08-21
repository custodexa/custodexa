#!/bin/bash
# MFA TOTP E2E 測試：setup -> enable（錯碼先拒）-> 兩階段登入 -> pending token 受限
#                  -> 錯碼拒絕 -> self disable -> admin 救援 -> 清理
# 可重複執行；需 docker compose 全套服務運行中
# 驗證碼由容器內 Go 工具產生（scripts/totp_code.go），與後端共用時鐘

set -u

API_BASE="http://localhost:8080/api/v1"
TS=$(date +%s)
MFA_USER="mfa_test_$TS"
MFA_PASS="mfatest123456"
PASS_COUNT=0
FAIL_COUNT=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

test_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT+1)); }
test_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

TEST_USER_ID=""

cleanup() {
    echo -e "\n${YELLOW}清理測試數據...${NC}"
    if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
        docker compose exec -T postgres psql -U postgres -d custodexa -c \
            "DELETE FROM user_roles WHERE user_id = $TEST_USER_ID; DELETE FROM users WHERE id = $TEST_USER_ID;" > /dev/null 2>&1 || true
    fi
    # 防殘留：清掉歷次失敗執行留下的測試用戶
    docker compose exec -T postgres psql -U postgres -d custodexa -c \
        "DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username LIKE 'mfa_test_%'); DELETE FROM users WHERE username LIKE 'mfa_test_%';" > /dev/null 2>&1 || true
    echo -e "${GREEN}清理完成${NC}"
}
trap cleanup EXIT

# 產生當前時間窗的 TOTP 驗證碼（容器內執行，與後端共用時鐘）
gen_code() {
    docker compose exec -T backend go run scripts/totp_code.go "$1" 2>/dev/null
}

# 0. 管理員登入
info "管理員登入"
ADMIN_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | jq -r '.token')
if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
    test_fail "管理員登入失敗"; exit 1
fi
test_pass "管理員登入成功"

# 1. 建立測試用戶
info "建立測試用戶 $MFA_USER"
CREATE_RESP=$(curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MFA_USER\",\"password\":\"$MFA_PASS\",\"email\":\"$MFA_USER@example.com\",\"roles\":[\"user\"]}")
TEST_USER_ID=$(echo "$CREATE_RESP" | jq -r '.data.id')
if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
    test_pass "測試用戶建立成功 (ID: $TEST_USER_ID)"
else
    test_fail "測試用戶建立失敗: $CREATE_RESP"; exit 1
fi

# 2. 未啟用 MFA 時一階段登入（行為不變）
LOGIN_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MFA_USER\",\"password\":\"$MFA_PASS\"}")
USER_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.token')
MFA_FLAG=$(echo "$LOGIN_RESP" | jq -r '.mfa_required // false')
if [ -n "$USER_TOKEN" ] && [ "$USER_TOKEN" != "null" ] && [ "$MFA_FLAG" = "false" ]; then
    test_pass "非 MFA 用戶一階段登入正常"
else
    test_fail "非 MFA 用戶登入異常: $LOGIN_RESP"; exit 1
fi

# 3. MFA setup
SETUP_RESP=$(curl -s "$API_BASE/auth/mfa/setup" -H "Authorization: Bearer $USER_TOKEN")
SECRET=$(echo "$SETUP_RESP" | jq -r '.secret')
OTPAUTH_URL=$(echo "$SETUP_RESP" | jq -r '.otpauth_url')
if [ -n "$SECRET" ] && [ "$SECRET" != "null" ] && echo "$OTPAUTH_URL" | grep -q "^otpauth://totp/"; then
    test_pass "MFA setup 成功（取得 secret + otpauth URL）"
else
    test_fail "MFA setup 失敗: $SETUP_RESP"; exit 1
fi

# 4. 錯誤驗證碼啟用被拒
WRONG_CODE="000000"
ENABLE_FAIL=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/enable" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$WRONG_CODE\"}")
if [ "$ENABLE_FAIL" = "400" ]; then
    test_pass "錯誤驗證碼啟用被拒 (400)"
else
    test_fail "錯誤驗證碼啟用未被拒 (HTTP $ENABLE_FAIL)"
fi

# 5. 正確驗證碼啟用成功
CODE=$(gen_code "$SECRET")
ENABLE_OK=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/enable" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$CODE\"}")
if [ "$ENABLE_OK" = "200" ]; then
    test_pass "正確驗證碼啟用成功"
else
    test_fail "MFA 啟用失敗 (HTTP $ENABLE_OK)"; exit 1
fi

# 6. 兩階段登入：第一階段回 mfa_required + pending_token，不含正式 token
LOGIN2_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MFA_USER\",\"password\":\"$MFA_PASS\"}")
MFA_REQUIRED=$(echo "$LOGIN2_RESP" | jq -r '.mfa_required // false')
PENDING_TOKEN=$(echo "$LOGIN2_RESP" | jq -r '.pending_token')
PHASE1_TOKEN=$(echo "$LOGIN2_RESP" | jq -r '.token // empty')
if [ "$MFA_REQUIRED" = "true" ] && [ -n "$PENDING_TOKEN" ] && [ "$PENDING_TOKEN" != "null" ] && [ -z "$PHASE1_TOKEN" ]; then
    test_pass "MFA 用戶登入回 mfa_required + pending_token（無正式 token）"
else
    test_fail "兩階段登入第一階段回應異常: $LOGIN2_RESP"; exit 1
fi

# 7. pending token 不得存取一般 API
PENDING_BLOCK=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/assets" \
    -H "Authorization: Bearer $PENDING_TOKEN")
if [ "$PENDING_BLOCK" = "401" ]; then
    test_pass "pending token 存取 /assets 被拒 (401)"
else
    test_fail "pending token 未被拒 (HTTP $PENDING_BLOCK)"
fi

# 8. 第二階段錯誤驗證碼被拒
VERIFY_FAIL=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/verify" \
    -H "Content-Type: application/json" \
    -d "{\"pending_token\":\"$PENDING_TOKEN\",\"code\":\"$WRONG_CODE\"}")
if [ "$VERIFY_FAIL" = "401" ]; then
    test_pass "第二階段錯誤驗證碼被拒 (401)"
else
    test_fail "第二階段錯誤驗證碼未被拒 (HTTP $VERIFY_FAIL)"
fi

# 9. 第二階段正確驗證碼換取正式 JWT
CODE=$(gen_code "$SECRET")
VERIFY_RESP=$(curl -s -X POST "$API_BASE/auth/mfa/verify" \
    -H "Content-Type: application/json" \
    -d "{\"pending_token\":\"$PENDING_TOKEN\",\"code\":\"$CODE\"}")
FULL_TOKEN=$(echo "$VERIFY_RESP" | jq -r '.token')
if [ -n "$FULL_TOKEN" ] && [ "$FULL_TOKEN" != "null" ]; then
    test_pass "第二階段驗證成功，取得正式 token"
else
    test_fail "第二階段驗證失敗: $VERIFY_RESP"; exit 1
fi

# 10. 正式 token 可正常使用
ME_NAME=$(curl -s "$API_BASE/auth/me" -H "Authorization: Bearer $FULL_TOKEN" | jq -r '.username')
if [ "$ME_NAME" = "$MFA_USER" ]; then
    test_pass "正式 token 可存取 /auth/me"
else
    test_fail "正式 token 無法使用 (username: $ME_NAME)"
fi

# 11. 錯誤密碼自行停用被拒
DISABLE_FAIL=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/disable" \
    -H "Authorization: Bearer $FULL_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"password":"wrongpassword"}')
if [ "$DISABLE_FAIL" = "401" ]; then
    test_pass "錯誤密碼停用 MFA 被拒 (401)"
else
    test_fail "錯誤密碼停用未被拒 (HTTP $DISABLE_FAIL)"
fi

# 12. 正確密碼自行停用成功
DISABLE_OK=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/disable" \
    -H "Authorization: Bearer $FULL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$MFA_PASS\"}")
if [ "$DISABLE_OK" = "200" ]; then
    test_pass "正確密碼自行停用 MFA 成功"
else
    test_fail "自行停用 MFA 失敗 (HTTP $DISABLE_OK)"
fi

# 13. 停用後恢復一階段登入
LOGIN3_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MFA_USER\",\"password\":\"$MFA_PASS\"}")
TOKEN3=$(echo "$LOGIN3_RESP" | jq -r '.token')
MFA_FLAG3=$(echo "$LOGIN3_RESP" | jq -r '.mfa_required // false')
if [ -n "$TOKEN3" ] && [ "$TOKEN3" != "null" ] && [ "$MFA_FLAG3" = "false" ]; then
    test_pass "停用後恢復一階段登入"
else
    test_fail "停用後登入異常: $LOGIN3_RESP"
fi

# 14. admin 救援路徑：重新啟用 MFA 後由管理員停用
info "重新啟用 MFA 以測試 admin 救援"
SETUP2_RESP=$(curl -s "$API_BASE/auth/mfa/setup" -H "Authorization: Bearer $TOKEN3")
SECRET2=$(echo "$SETUP2_RESP" | jq -r '.secret')
CODE2=$(gen_code "$SECRET2")
ENABLE2_OK=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/auth/mfa/enable" \
    -H "Authorization: Bearer $TOKEN3" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$CODE2\"}")
if [ "$ENABLE2_OK" = "200" ]; then
    test_pass "重新啟用 MFA 成功"
else
    test_fail "重新啟用 MFA 失敗 (HTTP $ENABLE2_OK)"
fi

# 14a. 非 admin 不得呼叫救援端點
RESCUE_FORBIDDEN=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/users/$TEST_USER_ID/mfa/disable" \
    -H "Authorization: Bearer $TOKEN3")
if [ "$RESCUE_FORBIDDEN" = "403" ]; then
    test_pass "非 admin 呼叫救援端點被拒 (403)"
else
    test_fail "非 admin 救援未被拒 (HTTP $RESCUE_FORBIDDEN)"
fi

# 14b. admin 停用目標用戶 MFA
RESCUE_OK=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/users/$TEST_USER_ID/mfa/disable" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
if [ "$RESCUE_OK" = "200" ]; then
    test_pass "admin 救援停用 MFA 成功"
else
    test_fail "admin 救援失敗 (HTTP $RESCUE_OK)"
fi

# 15. 救援後用戶恢復一階段登入
LOGIN4_RESP=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$MFA_USER\",\"password\":\"$MFA_PASS\"}")
TOKEN4=$(echo "$LOGIN4_RESP" | jq -r '.token')
if [ -n "$TOKEN4" ] && [ "$TOKEN4" != "null" ]; then
    test_pass "救援後恢復一階段登入"
else
    test_fail "救援後登入異常: $LOGIN4_RESP"
fi

# 16. 審計事件落庫（異步寫入，等待 flush）
sleep 3
AUDIT_COUNT=$(docker compose exec -T postgres psql -U postgres -d custodexa -t -A -c \
    "SELECT COUNT(*) FROM audit_logs WHERE username = '$MFA_USER' AND path LIKE '%mfa%';" 2>/dev/null | tr -d '[:space:]')
if [ -n "$AUDIT_COUNT" ] && [ "$AUDIT_COUNT" -gt 0 ] 2>/dev/null; then
    test_pass "MFA 事件已記入審計日誌 ($AUDIT_COUNT 筆)"
else
    test_fail "審計日誌未找到 MFA 事件"
fi

echo ""
echo -e "${GREEN}通過: $PASS_COUNT${NC}"
echo -e "${RED}失敗: $FAIL_COUNT${NC}"
[ "$FAIL_COUNT" -eq 0 ] && echo -e "${GREEN}所有測試通過${NC}" || { echo -e "${RED}部分測試失敗${NC}"; exit 1; }
