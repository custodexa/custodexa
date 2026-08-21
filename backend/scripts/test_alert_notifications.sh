#!/bin/bash
# 告警通知通道 E2E：CRUD / 權限 / URL 驗證 / 測試發送。可重複執行
set -u
API_BASE="http://localhost:8080/api/v1"
PASS=0; FAIL=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
ng() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

CH_ID=""
cleanup() {
  echo -e "${YELLOW}清理...${NC}"
  docker compose exec -T postgres psql -U postgres -d custodexa -c \
    "DELETE FROM notification_channels WHERE name LIKE 'e2e-hook%';" > /dev/null 2>&1 || true
}
trap cleanup EXIT

ADMIN_TOKEN=$(curl -s -X POST "$API_BASE/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] && ok "管理員登入" || { ng "登入失敗"; exit 1; }

cleanup

# 1. 無效 URL 拒絕
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/notification-channels" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"e2e-hook-bad","url":"ftp://x"}')
[ "$CODE" = "400" ] && ok "無效 URL scheme 拒絕 (400)" || ng "無效 URL 未拒絕 ($CODE)"

# 2. 建立通道
RESP=$(curl -s -X POST "$API_BASE/notification-channels" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"e2e-hook","url":"http://backend:8080/health","secret":"e2e-secret","enabled":true}')
CH_ID=$(echo "$RESP" | jq -r '.id')
[ -n "$CH_ID" ] && [ "$CH_ID" != "null" ] && ok "通道建立 (ID: $CH_ID)" || ng "建立失敗: $RESP"

# 3. 回應不洩漏 secret
echo "$RESP" | grep -q "e2e-secret" && ng "回應洩漏 secret" || ok "回應遮罩 secret"

# 4. 測試發送
TEST=$(curl -s -X POST "$API_BASE/notification-channels/$CH_ID/test" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$(echo "$TEST" | jq -r '.success')" = "true" ] && ok "測試發送成功" || ng "測試發送失敗: $TEST"

# 5. 更新（停用）
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API_BASE/notification-channels/$CH_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"e2e-hook","url":"http://backend:8080/health","enabled":false}')
[ "$CODE" = "200" ] && ok "通道更新" || ng "更新失敗 ($CODE)"

# 6. 非 admin 403
TS=$(date +%s)
curl -s -X POST "$API_BASE/users" -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"username\":\"e2e_notif_$TS\",\"password\":\"test123456\",\"email\":\"e2e_notif_$TS@example.com\",\"roles\":[\"user\"]}" > /dev/null
UTOKEN=$(curl -s -X POST "$API_BASE/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\":\"e2e_notif_$TS\",\"password\":\"test123456\"}" | jq -r '.token')
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/notification-channels" -H "Authorization: Bearer $UTOKEN")
[ "$CODE" = "403" ] && ok "非 admin 被拒 (403)" || ng "權限未阻擋 ($CODE)"
docker compose exec -T postgres psql -U postgres -d custodexa -c \
  "DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username='e2e_notif_$TS'); DELETE FROM users WHERE username='e2e_notif_$TS';" > /dev/null 2>&1

# 7. 刪除
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$API_BASE/notification-channels/$CH_ID" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$CODE" = "200" ] && ok "通道刪除" || ng "刪除失敗 ($CODE)"

echo ""; echo -e "${GREEN}通過: $PASS${NC}"; echo -e "${RED}失敗: $FAIL${NC}"
[ "$FAIL" -eq 0 ] || exit 1
