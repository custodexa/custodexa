#!/bin/bash
set -e

# 用戶管理 E2E 測試：用戶管理完整流程測試
# 測試場景：創建用戶 → 分配角色 → 修改用戶 → 禁用用戶 → 啟用用戶 → 刪除用戶

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 測試計數
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# 測試數據 ID（用於清理）
TEST_USER_ID=""
TEST_USER2_ID=""

# API 基礎 URL
API_BASE="http://localhost:8080/api/v1"

# 輔助函數
function test_start() {
    echo -e "\n${YELLOW}[TEST]${NC} $1"
    TESTS_RUN=$((TESTS_RUN + 1))
}

function test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

function test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

function info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 清理函數
function cleanup() {
    echo -e "\n${YELLOW}清理測試數據...${NC}"

    # 刪除測試用戶（通過 API）
    if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
        info "刪除測試用戶 ID: $TEST_USER_ID"
        curl -s -X DELETE "$API_BASE/users/$TEST_USER_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" > /dev/null 2>&1 || true
    fi

    if [ -n "$TEST_USER2_ID" ] && [ "$TEST_USER2_ID" != "null" ]; then
        info "刪除測試用戶 ID: $TEST_USER2_ID"
        curl -s -X DELETE "$API_BASE/users/$TEST_USER2_ID" \
            -H "Authorization: Bearer $ADMIN_TOKEN" > /dev/null 2>&1 || true
    fi

    echo -e "${GREEN}清理完成${NC}"
}

trap cleanup EXIT

# ============================================================================
# 主測試流程
# ============================================================================

echo "=========================================="
echo "=== 用戶管理 E2E 測試: 用戶管理完整流程 ==="
echo "=========================================="

# -------------------------
# 階段 0: 管理員登入
# -------------------------
info "階段 0: 管理員登入"

ADMIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}')

ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | jq -r '.token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo -e "${RED}管理員登入失敗${NC}"
    echo "Response: $ADMIN_RESPONSE"
    exit 1
fi

info "管理員登入成功"

# -------------------------
# 階段 1: 獲取角色列表
# -------------------------
test_start "獲取角色列表"

ROLES_RESPONSE=$(curl -s "$API_BASE/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

ROLES_COUNT=$(echo "$ROLES_RESPONSE" | jq -r '.total')

if [ "$ROLES_COUNT" -ge 3 ]; then
    ROLE_NAMES=$(echo "$ROLES_RESPONSE" | jq -r '.data[].name' | tr '\n' ', ')
    test_pass "角色列表獲取成功 (共 $ROLES_COUNT 個): $ROLE_NAMES"
else
    test_fail "角色列表數量不正確 (應 >= 3，實際: $ROLES_COUNT)"
fi

# -------------------------
# 階段 2: 創建用戶（含角色分配）
# -------------------------
test_start "創建用戶 testuser_usermgmt（分配 user 角色）"

CREATE_RESPONSE=$(curl -s -X POST "$API_BASE/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "testuser_usermgmt",
        "password": "test123456",
        "email": "testuser_usermgmt@example.com",
        "full_name": "Test User Mgmt",
        "roles": ["user"]
    }')

TEST_USER_ID=$(echo "$CREATE_RESPONSE" | jq -r '.data.id')

if [ "$TEST_USER_ID" != "null" ] && [ -n "$TEST_USER_ID" ]; then
    # 驗證角色是否正確分配
    USER_ROLES=$(echo "$CREATE_RESPONSE" | jq -r '.data.roles[].name' | tr '\n' ', ')
    if [[ "$USER_ROLES" == *"user"* ]]; then
        test_pass "用戶創建成功 (ID: $TEST_USER_ID, 角色: $USER_ROLES)"
    else
        test_fail "用戶創建成功但角色分配失敗 (期望: user, 實際: $USER_ROLES)"
    fi
else
    test_fail "創建用戶失敗"
    echo "Response: $CREATE_RESPONSE"
fi

# -------------------------
# 階段 3: 獲取用戶詳情
# -------------------------
test_start "獲取用戶詳情"

USER_DETAIL=$(curl -s "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

USERNAME=$(echo "$USER_DETAIL" | jq -r '.data.username')
EMAIL=$(echo "$USER_DETAIL" | jq -r '.data.email')

if [ "$USERNAME" = "testuser_usermgmt" ] && [ "$EMAIL" = "testuser_usermgmt@example.com" ]; then
    test_pass "用戶詳情獲取成功"
else
    test_fail "用戶詳情不正確 (username: $USERNAME, email: $EMAIL)"
fi

# -------------------------
# 階段 4: 更新用戶基本資訊
# -------------------------
test_start "更新用戶郵箱和全名"

UPDATE_RESPONSE=$(curl -s -X PUT "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "updated_usermgmt@example.com",
        "full_name": "Updated Name"
    }')

UPDATED_EMAIL=$(echo "$UPDATE_RESPONSE" | jq -r '.data.email')
UPDATED_NAME=$(echo "$UPDATE_RESPONSE" | jq -r '.data.full_name')

if [ "$UPDATED_EMAIL" = "updated_usermgmt@example.com" ] && [ "$UPDATED_NAME" = "Updated Name" ]; then
    test_pass "用戶資訊更新成功"
else
    test_fail "用戶資訊更新失敗 (email: $UPDATED_EMAIL, full_name: $UPDATED_NAME)"
fi

# -------------------------
# 階段 5: 分配角色（改為 auditor）
# -------------------------
test_start "分配角色（改為 auditor）"

ASSIGN_RESPONSE=$(curl -s -X PUT "$API_BASE/users/$TEST_USER_ID/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"roles": ["auditor"]}')

# 重新獲取用戶詳情確認角色變更
USER_DETAIL=$(curl -s "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

NEW_ROLES=$(echo "$USER_DETAIL" | jq -r '.data.roles[].name' | tr '\n' ', ')

if [[ "$NEW_ROLES" == *"auditor"* ]]; then
    test_pass "角色分配成功 (新角色: $NEW_ROLES)"
else
    test_fail "角色分配失敗 (期望: auditor, 實際: $NEW_ROLES)"
fi

# -------------------------
# 階段 6: 分配多個角色
# -------------------------
test_start "分配多個角色（user + auditor）"

curl -s -X PUT "$API_BASE/users/$TEST_USER_ID/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"roles": ["user", "auditor"]}' > /dev/null

USER_DETAIL=$(curl -s "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

MULTI_ROLES=$(echo "$USER_DETAIL" | jq -r '.data.roles[].name' | sort | tr '\n' ', ')

if [[ "$MULTI_ROLES" == *"user"* ]] && [[ "$MULTI_ROLES" == *"auditor"* ]]; then
    test_pass "多角色分配成功 ($MULTI_ROLES)"
else
    test_fail "多角色分配失敗 (實際: $MULTI_ROLES)"
fi

# -------------------------
# 階段 7: 修改密碼
# -------------------------
test_start "修改用戶密碼"

PASSWORD_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -X PUT "$API_BASE/users/$TEST_USER_ID/password" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"password": "newpassword123"}')

HTTP_CODE=$(echo "$PASSWORD_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

if [ "$HTTP_CODE" = "200" ]; then
    test_pass "密碼修改成功"
else
    test_fail "密碼修改失敗 (HTTP $HTTP_CODE)"
fi

# -------------------------
# 階段 8: 測試新密碼登入
# -------------------------
test_start "使用新密碼登入"

LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser_usermgmt","password":"newpassword123"}')

USER_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

if [ "$USER_TOKEN" != "null" ] && [ -n "$USER_TOKEN" ]; then
    test_pass "新密碼登入成功"
else
    test_fail "新密碼登入失敗"
fi

# -------------------------
# 階段 9: 禁用用戶
# -------------------------
test_start "禁用用戶"

curl -s -X PUT "$API_BASE/users/$TEST_USER_ID/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"active": false}' > /dev/null

USER_DETAIL=$(curl -s "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

IS_ACTIVE=$(echo "$USER_DETAIL" | jq -r '.data.active')

if [ "$IS_ACTIVE" = "false" ]; then
    test_pass "用戶已禁用"
else
    test_fail "用戶禁用失敗 (active: $IS_ACTIVE)"
fi

# -------------------------
# 階段 10: 驗證禁用用戶無法登入
# -------------------------
test_start "驗證禁用用戶無法登入"

DISABLED_LOGIN=$(curl -s -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser_usermgmt","password":"newpassword123"}')

DISABLED_TOKEN=$(echo "$DISABLED_LOGIN" | jq -r '.token')

if [ "$DISABLED_TOKEN" = "null" ] || [ -z "$DISABLED_TOKEN" ]; then
    test_pass "禁用用戶無法登入（符合預期）"
else
    test_fail "禁用用戶仍可登入（不符合預期）"
fi

# -------------------------
# 階段 11: 重新啟用用戶
# -------------------------
test_start "重新啟用用戶"

curl -s -X PUT "$API_BASE/users/$TEST_USER_ID/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"active": true}' > /dev/null

USER_DETAIL=$(curl -s "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

IS_ACTIVE=$(echo "$USER_DETAIL" | jq -r '.data.active')

if [ "$IS_ACTIVE" = "true" ]; then
    test_pass "用戶已重新啟用"
else
    test_fail "用戶啟用失敗 (active: $IS_ACTIVE)"
fi

# -------------------------
# 階段 12: 用戶列表查詢（搜尋功能）
# -------------------------
test_start "搜尋用戶（按用戶名）"

SEARCH_RESPONSE=$(curl -s "$API_BASE/users?search=testuser_usermgmt" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

SEARCH_COUNT=$(echo "$SEARCH_RESPONSE" | jq -r '.total')

if [ "$SEARCH_COUNT" = "1" ]; then
    test_pass "用戶搜尋成功 (找到 1 個用戶)"
else
    test_fail "用戶搜尋失敗 (期望: 1, 實際: $SEARCH_COUNT)"
fi

# -------------------------
# 階段 13: 用戶列表查詢（狀態篩選）
# -------------------------
test_start "篩選啟用的用戶"

ACTIVE_RESPONSE=$(curl -s "$API_BASE/users?active=true" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

ACTIVE_COUNT=$(echo "$ACTIVE_RESPONSE" | jq -r '.total')

if [ "$ACTIVE_COUNT" -gt 0 ]; then
    test_pass "啟用用戶篩選成功 (找到 $ACTIVE_COUNT 個用戶)"
else
    test_fail "啟用用戶篩選失敗"
fi

# -------------------------
# 階段 14: 刪除用戶
# -------------------------
test_start "刪除測試用戶"

DELETE_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -X DELETE "$API_BASE/users/$TEST_USER_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

HTTP_CODE=$(echo "$DELETE_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

if [ "$HTTP_CODE" = "200" ]; then
    test_pass "用戶刪除成功"
    TEST_USER_ID="" # 已刪除，清理時不需要再刪
else
    test_fail "用戶刪除失敗 (HTTP $HTTP_CODE)"
fi

# -------------------------
# 階段 15: 驗證已刪除用戶不在列表中
# -------------------------
test_start "驗證已刪除用戶不在列表中"

SEARCH_DELETED=$(curl -s "$API_BASE/users?search=testuser_usermgmt" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

DELETED_COUNT=$(echo "$SEARCH_DELETED" | jq -r '.total')

if [ "$DELETED_COUNT" = "0" ]; then
    test_pass "已刪除用戶不在列表中（軟刪除生效）"
else
    test_fail "已刪除用戶仍在列表中 (count: $DELETED_COUNT)"
fi

# -------------------------
# 階段 16: 測試最後管理員保護機制
# -------------------------
test_start "測試最後管理員保護（嘗試禁用 admin）"

# 先獲取 admin 用戶的 ID
ADMIN_USER=$(curl -s "$API_BASE/users?search=admin" \
    -H "Authorization: Bearer $ADMIN_TOKEN")

ADMIN_USER_ID=$(echo "$ADMIN_USER" | jq -r '.data[0].id')

if [ -n "$ADMIN_USER_ID" ] && [ "$ADMIN_USER_ID" != "null" ]; then
    # 嘗試禁用 admin（如果只有一個 admin，應該失敗）
    DISABLE_ADMIN=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -X PUT "$API_BASE/users/$ADMIN_USER_ID/status" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"active": false}')

    HTTP_CODE=$(echo "$DISABLE_ADMIN" | grep "HTTP_CODE:" | cut -d: -f2)

    if [ "$HTTP_CODE" = "400" ]; then
        ERROR_MSG=$(echo "$DISABLE_ADMIN" | sed '/HTTP_CODE:/d' | jq -r '.error')
        if [[ "$ERROR_MSG" == *"最後"* ]] || [[ "$ERROR_MSG" == *"管理員"* ]]; then
            test_pass "最後管理員保護機制生效 (返回 400 並提示)"
        else
            test_fail "返回 400 但錯誤訊息不正確: $ERROR_MSG"
        fi
    else
        test_fail "最後管理員保護失敗（應返回 400，實際: ${HTTP_CODE}）"
    fi
else
    info "跳過最後管理員保護測試（無法獲取 admin ID）"
fi

# -------------------------
# 測試總結
# -------------------------
echo ""
echo "=========================================="
echo "=== 測試總結 ==="
echo "=========================================="
echo "執行: $TESTS_RUN"
echo -e "${GREEN}通過: $TESTS_PASSED${NC}"
echo -e "${RED}失敗: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}所有測試通過${NC}"
    exit 0
else
    echo -e "${RED}部分測試失敗${NC}"
    exit 1
fi
