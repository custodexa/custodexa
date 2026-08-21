#!/bin/bash
# e2e_smoke.sh — 連線體驗主線一鍵煙測（路線圖 P0 E2E 腳本化）
#
# 覆蓋：SSH xterm 直連（WS 級）、指令審計、asciicast 錄製回放、工作區 API 面與
# 統一錯誤封套（api-error-responses spec 回歸）、指令阻斷、資料庫協議、K8s、
# SFTP 保真、多帳號切換、OIDC SSO 全鏈路（場景 12，idp-oidc-integration），
# 以及 RDP／VNC 圖形協議走 guacd 的建線／落庫／錄影／審計（場景 16-17）。
# 依賴：docker compose 全棧運行、curl、python3。失敗即非零退出。
#
# 靶機/組態未就緒的場景一律 **skip 而非 fail**（k3s、dex 皆然）——正式版 compose
# 不含這些靶機，把「沒裝」判成回歸只會訓練人忽略紅字。
set -u

BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
# ADMIN_PASS **刻意無預設值**：admin 密碼於首登強制改密後就只有操作者持有，
# 任何寫死的字面值都會週期性失效（2026-08-04、2026-08-16 各失效一次）。
# **也不自 .env 的 ADMIN_INITIAL_PASSWORD 回退**，理由不是「風險高」而是那條路徑
# 恆不可用：該值仍是現行密碼的唯一情況＝admin 從未改密（`must_change_password`
# 為真），而該狀態下 `/auth/login` 只回 `change_token` 不回 `token`
# （backend/internal/modules/identity/auth_service.go 強制改密分支），
# 本腳本要的正式 token 拿不到——「值還有效」與「跑得動」互斥。
ADMIN_PASS="${ADMIN_PASS:-}"
# SSH_ASSET_ID 未設時於登入後自動查詢（見 resolve_ssh_asset_id）；
# 設了就以其為準（要指定特定資產時用）。
SSH_ASSET_ID="${SSH_ASSET_ID:-}"
# 自動查詢的判準：連向哪台 SSH 靶機。dev compose 的常設靶機是 ssh-test
SSH_ASSET_HOST="${SSH_ASSET_HOST:-ssh-test}"

PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

psql_q() {
  docker compose exec -T postgres psql -U postgres -d custodexa -tAc "$1" 2>/dev/null
}

if [ -z "$ADMIN_PASS" ]; then
  cat >&2 <<'EOF'
FAIL: 未提供 ADMIN_PASS（本腳本不內建 admin 密碼，也不自 .env 取值）。

  ADMIN_PASS='<現行 admin 密碼>' bash scripts/e2e_smoke.sh

- 這裡要的是**現行**密碼，不是 .env 的 ADMIN_INITIAL_PASSWORD：後者是初始密碼，
  admin 首登強制改密後即退役；而它仍有效時（admin 從未改密）登入只會回
  change_token，本腳本需要的正式 token 拿不到，故無自動回退可用。
- 忘記現行密碼時，比照 docs/QUICKSTART.md 的「初始管理員離線 remediation」
  以 DB 直改雜湊重設（本產品不提供線上救援 API）。
- 帳號非 admin 時另帶 ADMIN_USER=<帳號>。
EOF
  exit 1
fi

# resolve_ssh_asset_id 自 API 查出主線 SSH 靶機的資產 ID。
# **不寫死預設值**：資產 ID 隨清庫重建漂移，寫死會讓整批場景以「連錯資產」的形式
# 假紅（2026-08-09 首跑 31/4，僅改 ID 即 35/0）。判準取 host 而非 name／id：
# 靶機主機名是 compose 定義的、比資產名穩定
resolve_ssh_asset_id() {
  curl -s "$BASE_URL/api/v1/assets?protocol=ssh&active=true&page=1&page_size=200" \
    -H "Authorization: Bearer $TOKEN" \
  | python3 -c "
import json,sys
host=sys.argv[1]
try:
    rows=json.load(sys.stdin).get('data') or []
except Exception:
    rows=[]
# 取 id 最小者：列表本身是 created_at DESC，命中多筆時最新的多半是前次跑剩下的
# 臨時資產（e2e 自建的 e2e-oidc-* 等），常設靶機資產才是想要的那筆
m=sorted((r for r in rows if r.get('host')==host), key=lambda r: r.get('id') or 0)
print(m[0]['id'] if m else '')
" "$SSH_ASSET_HOST"
}

echo "=== Custodexa E2E 煙測 ($(date '+%F %T')) ==="

# --- 0. 服務健檢 ---
echo "[0] 服務健檢"
if ! curl -sf "$BASE_URL/health" > /dev/null; then
  echo "  FAIL: 後端未運行（$BASE_URL/health）；請先 docker compose up -d"
  exit 1
fi
ok "後端 health"
if ! docker compose ps ssh-test 2>/dev/null | grep -q "Up"; then
  echo "  FAIL: ssh-test 容器未運行"
  exit 1
fi
ok "ssh-test 容器"

# --- 1. 登入與錯誤封套抽查 ---
echo "[1] 登入與統一錯誤封套"
LOGIN_BODY=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" -H "Content-Type: application/json" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
TOKEN=$(echo "$LOGIN_BODY" | python3 -c "
import json,sys
try:
    print(json.load(sys.stdin).get('token',''))
except Exception:
    print('')
")
if [ -z "$TOKEN" ]; then
  bad "登入失敗，無法取得 token（帳號 ${ADMIN_USER}）"
  if echo "$LOGIN_BODY" | grep -q '"password_change_required"'; then
    echo "  原因: 該帳號處於強制改密狀態，登入只回 change_token。請先完成改密，再以新密碼帶 ADMIN_PASS 重跑。"
  else
    echo "  原因: ADMIN_PASS 不是現行密碼（首登改密後 .env 的 ADMIN_INITIAL_PASSWORD 已退役）。"
    echo "        重設程序見 docs/QUICKSTART.md「初始管理員離線 remediation」。"
  fi
  echo "結果: PASS=$PASS FAIL=$((FAIL))"; exit 1
fi
ok "admin 登入"

# SSH 靶機資產 ID：未由環境指定就當場查（見檔頭 resolve_ssh_asset_id 的理由）
if [ -z "$SSH_ASSET_ID" ]; then
  SSH_ASSET_ID=$(resolve_ssh_asset_id)
  if [ -z "$SSH_ASSET_ID" ]; then
    bad "查不到 host=$SSH_ASSET_HOST 的啟用中 SSH 資產"
    echo "  處置: 先建一個指向該靶機的 SSH 資產（ssh-test 的埠須為 2222，帳密見 docs/dev/testing.md），"
    echo "        或以 SSH_ASSET_ID=<id> 指定既有資產重跑。"
    echo "結果: PASS=$PASS FAIL=$((FAIL))"; exit 1
  fi
  # 用 INFO 而非 ok()：這是前置解析不是被測行為，計入 PASS 會讓歷次 PASS/FAIL 數字不可比
  echo "  INFO: SSH 靶機資產自動解析 host=$SSH_ASSET_HOST → id=$SSH_ASSET_ID"
else
  echo "  INFO: 使用指定的 SSH_ASSET_ID=$SSH_ASSET_ID"
fi

# 401 無 token：機器碼＋文案封套（backend-i18n-unification 後契約），
# 精確 key 集合——多出欄位（debug/stack 等洩漏面）也算 FAIL
BODY=$(curl -s "$BASE_URL/api/v1/assets")
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert set(d.keys())=={'code','error'} and d['code'].startswith('AUTH_') and d['error'], d" && ok "401 錯誤封套 {code,error}" || bad "401 錯誤封套格式異常: $BODY"

# 400 壞參數：無效資產 ID
BODY=$(curl -s "$BASE_URL/api/v1/assets/not-a-number" -H "Authorization: Bearer $TOKEN")
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert set(d.keys())=={'code','error','params'} and d['code'].startswith('VALIDATION_') and d['error'], d" && ok "400 錯誤封套 {code,error,params}" || bad "400 錯誤封套格式異常: $BODY"

# 401 錯誤密碼：訊息可讀且不洩內部
BODY=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong-pass"}')
echo "$BODY" | grep -q '"error":"使用者名稱或密碼錯誤"' && ok "登入失敗訊息" || bad "登入失敗訊息異常: $BODY"

# --- 2. SSH xterm 直連（WS 級）+ marker 指令 ---
echo "[2] SSH WS 直連煙測"
MARKER="e2e-smoke-$(date +%s)"
SMOKE_OUT=$(docker compose exec -T backend go run scripts/sshws_smoke.go \
  -token "$TOKEN" -asset "$SSH_ASSET_ID" -extra "echo $MARKER" 2>&1)
if echo "$SMOKE_OUT" | grep -q "PASS all"; then
  ok "sshws_smoke（echo/resize/extra）"
else
  bad "sshws_smoke 失敗"
  echo "$SMOKE_OUT" | tail -5
fi

# --- 3. 指令審計斷言（非同步寫入，帶重試） ---
echo "[3] 指令審計"
AUDIT_HIT=""
for i in 1 2 3 4 5; do
  AUDIT_HIT=$(psql_q "SELECT count(*) FROM session_commands WHERE command LIKE '%$MARKER%'")
  [ "${AUDIT_HIT:-0}" -ge 1 ] 2>/dev/null && break
  sleep 1
done
if [ "${AUDIT_HIT:-0}" -ge 1 ] 2>/dev/null; then
  ok "session_commands 含 marker（$AUDIT_HIT 筆）"
else
  bad "審計未記錄 marker 指令: $MARKER"
fi

# --- 4. asciicast 錄製與回放 API ---
echo "[4] 錄製回放"
SESSION_ID=$(psql_q "SELECT id FROM sessions WHERE asset_id=$SSH_ASSET_ID ORDER BY id DESC LIMIT 1")
if [ -z "$SESSION_ID" ]; then
  bad "查無 session 記錄"
else
  META_CODE=""
  for i in 1 2 3 4 5; do
    META_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "$BASE_URL/api/v1/sessions/$SESSION_ID/recording" -H "Authorization: Bearer $TOKEN")
    [ "$META_CODE" = "200" ] && break
    sleep 1
  done
  [ "$META_CODE" = "200" ] && ok "錄製 metadata API (session $SESSION_ID)" || bad "錄製 metadata HTTP $META_CODE"

  HEAD_LINE=$(curl -s "$BASE_URL/api/v1/sessions/$SESSION_ID/recording/download" \
    -H "Authorization: Bearer $TOKEN" | head -c 200)
  echo "$HEAD_LINE" | grep -q '"version"' && ok "asciicast 內容（version 標頭）" || bad "錄製內容非 asciicast: ${HEAD_LINE:0:80}"
fi

# --- 5. 工作區 API 面 ---
echo "[5] 工作區 API 面"
BODY=$(curl -s "$BASE_URL/api/v1/assets?page=1&page_size=5" -H "Authorization: Bearer $TOKEN")
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert isinstance(d.get('data'), list) and 'total' in d, list(d.keys())" && ok "資產列表分頁封套" || bad "資產列表封套異常"

BODY=$(curl -s "$BASE_URL/api/v1/sessions?page=1&page_size=5" -H "Authorization: Bearer $TOKEN")
echo "$BODY" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert isinstance(d.get('data'), list), list(d.keys())" && ok "session 列表" || bad "session 列表封套異常"

# --- 6. 指令阻斷（command-blocking） ---
echo "[6] 指令阻斷"
BLOCK_MARK="blockme-$(date +%s)"
RULE_ID=$(curl -s -X POST "$BASE_URL/api/v1/alert-rules" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"e2e-block\",\"pattern\":\"touch /tmp/$BLOCK_MARK\",\"severity\":\"high\",\"action\":\"block\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
if [ -z "$RULE_ID" ]; then
  bad "block 規則建立失敗"
else
  docker compose exec -T backend go run scripts/sshws_smoke.go \
    -token "$TOKEN" -asset "$SSH_ASSET_ID" -extra "touch /tmp/$BLOCK_MARK" > /dev/null 2>&1
  if docker compose exec -T ssh-test sh -c "test -e /tmp/$BLOCK_MARK"; then
    bad "阻斷失效：檔案在目標主機被建立"
    docker compose exec -T ssh-test rm -f "/tmp/$BLOCK_MARK"
  else
    ok "block 指令未達目標主機"
  fi
  BLOCKED=$(psql_q "SELECT count(*) FROM command_alerts WHERE rule_name LIKE 'e2e-block%' AND command LIKE '%$BLOCK_MARK%'")
  [ "${BLOCKED:-0}" -ge 1 ] 2>/dev/null && ok "阻斷事件入告警庫" || bad "阻斷事件未入庫"
  curl -s -X DELETE "$BASE_URL/api/v1/alert-rules/$RULE_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
  psql_q "DELETE FROM command_alerts WHERE rule_name LIKE 'e2e-block%'" > /dev/null
fi

# --- 7. 資料庫協議（database-protocol：psql 代理＋審計沿用） ---
echo "[7] 資料庫協議"
DB_MARKER="dbsmoke-$(date +%s)"
# $$ 必須雙引號包裹：macOS bash 3.2 在 $( ) 內把裸 '$$' 後接單引號誤讀為
# ANSI-C 引用 $'…'，$$ 展開成空 → 名稱撞殘留資產回 409（實測重現，勿改回）
DB_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"e2e-pg-'"$$"'","protocol":"postgres","host":"postgres","port":5432,"username":"postgres","password":"postgres"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
if [ -z "$DB_ASSET_ID" ]; then
  bad "postgres 測試資產建立失敗"
else
  DB_OUT=$(docker compose exec -T backend go run scripts/dbws_smoke.go \
    -token "$TOKEN" -asset "$DB_ASSET_ID" -extra "select '$DB_MARKER';" 2>&1)
  if echo "$DB_OUT" | grep -q "PASS all"; then
    ok "dbws_smoke（prompt/select/resize）"
  else
    bad "dbws_smoke 失敗"
    echo "$DB_OUT" | tail -3
  fi
  DB_AUDIT=""
  for i in 1 2 3 4 5; do
    DB_AUDIT=$(psql_q "SELECT count(*) FROM session_commands WHERE command LIKE '%$DB_MARKER%'")
    [ "${DB_AUDIT:-0}" -ge 1 ] 2>/dev/null && break
    sleep 1
  done
  [ "${DB_AUDIT:-0}" -ge 1 ] 2>/dev/null && ok "SQL 指令入審計庫" || bad "SQL 指令未入審計庫"

  # 撥測（db-protocol-connection-test 5.3）：DB 協議曾被撥測分派的 else 分支送進
  # guacd（沒有 mysql/postgres/redis client library）而永不返回，前端 10 秒後誤報
  # 「網路錯誤」。這裡驗三件事：可達回 success、有界時間內返回、不可達的失敗
  # 分類不是 protocol_unsupported（後者代表分派又掉回未登記狀態）。
  DB_TEST_START=$(date +%s)
  DB_TEST=$(curl -s -X POST "$BASE_URL/api/v1/assets/$DB_ASSET_ID/test-connection" \
    -H "Authorization: Bearer $TOKEN" --max-time 40)
  DB_TEST_ELAPSED=$(( $(date +%s) - DB_TEST_START ))
  echo "$DB_TEST" | grep -q '"success":true' \
    && ok "postgres 撥測可達（${DB_TEST_ELAPSED}s）" \
    || bad "postgres 撥測未回 success=true: $DB_TEST"
  [ "$DB_TEST_ELAPSED" -le 10 ] \
    && ok "postgres 撥測 10 秒內返回" \
    || bad "postgres 撥測耗時 ${DB_TEST_ELAPSED}s（>10s，疑似又落入無逾時中介）"
  curl -s -X DELETE "$BASE_URL/api/v1/assets/$DB_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
fi

# mysql 靶機撥測（dev compose 專屬；缺靶機一律 skip 而非 fail）
if docker compose ps mysql-test 2>/dev/null | grep -q "Up"; then
  MY_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-mysql-'"$$"'","protocol":"mysql","host":"mysql-test","port":3306,"username":"root","password":"testpass123"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$MY_ASSET_ID" ]; then
    bad "mysql 測試資產建立失敗"
  else
    MY_TEST=$(curl -s -X POST "$BASE_URL/api/v1/assets/$MY_ASSET_ID/test-connection" \
      -H "Authorization: Bearer $TOKEN" --max-time 40)
    echo "$MY_TEST" | grep -q '"success":true' \
      && ok "mysql 撥測可達" || bad "mysql 撥測未回 success=true: $MY_TEST"
    curl -s -X DELETE "$BASE_URL/api/v1/assets/$MY_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
  fi
else
  echo "  (mysql-test 未運行，跳過 mysql 撥測)"
fi

# mssql 靶機（mssql-web-cli 5.2；dev compose 專屬，缺靶機一律 skip 而非 fail）。
# 這條與 postgres 場景的差別在於**批次終止符**：mssql 的一筆指令由 `GO` 結算，
# 故 -extra 送的是「SQL 一行 ↵ GO」；若審計切分沒帶協議感知，marker 永遠不會入庫。
if docker compose ps mssql-test 2>/dev/null | grep -q "Up"; then
  MS_MARKER="mssqlsmoke-$(date +%s)"
  MS_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"e2e-mssql-'"$$"'","protocol":"mssql","host":"mssql-test","port":1433,"username":"sa","password":"Testpass123!"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$MS_ASSET_ID" ]; then
    bad "mssql 測試資產建立失敗"
  else
    # -prompt/-probe/-want 皆須改寫：sqlcmd 的提示符是 `1>`，且無 GO 不執行。
    MS_OUT=$(docker compose exec -T backend go run scripts/dbws_smoke.go \
      -token "$TOKEN" -asset "$MS_ASSET_ID" -prompt "1>" \
      -probe $'SELECT 40+2 AS smoke\rGO' -want "42" \
      -extra $'SELECT \''"$MS_MARKER"$'\'\rGO' 2>&1)
    if echo "$MS_OUT" | grep -q "PASS all"; then
      ok "dbws_smoke mssql（prompt/select/resize）"
    else
      bad "dbws_smoke mssql 失敗"
      echo "$MS_OUT" | tail -3
    fi
    MS_AUDIT=""
    for i in 1 2 3 4 5; do
      MS_AUDIT=$(psql_q "SELECT count(*) FROM session_commands WHERE command LIKE '%$MS_MARKER%'")
      [ "${MS_AUDIT:-0}" -ge 1 ] 2>/dev/null && break
      sleep 1
    done
    [ "${MS_AUDIT:-0}" -ge 1 ] 2>/dev/null && ok "mssql 指令入審計庫（GO 結算）" || bad "mssql 指令未入審計庫"

    MS_TEST_START=$(date +%s)
    MS_TEST=$(curl -s -X POST "$BASE_URL/api/v1/assets/$MS_ASSET_ID/test-connection" \
      -H "Authorization: Bearer $TOKEN" --max-time 40)
    MS_TEST_ELAPSED=$(( $(date +%s) - MS_TEST_START ))
    echo "$MS_TEST" | grep -q '"success":true' \
      && ok "mssql 撥測可達（${MS_TEST_ELAPSED}s）" \
      || bad "mssql 撥測未回 success=true: $MS_TEST"
    [ "$MS_TEST_ELAPSED" -le 10 ] \
      && ok "mssql 撥測 10 秒內返回" \
      || bad "mssql 撥測耗時 ${MS_TEST_ELAPSED}s（>10s，疑似落入無逾時中介）"
    curl -s -X DELETE "$BASE_URL/api/v1/assets/$MS_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
  fi
else
  echo "  (mssql-test 未運行，跳過 mssql 場景)"
fi

# 不可達埠的負向案例：必須是「連線被拒/逾時」，不得是 protocol_unsupported。
# protocol_unsupported 出現在此＝撥測對照表漏登記該協議（本 change 修的缺陷復發）。
DEAD_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"e2e-redis-dead-'"$$"'","protocol":"redis","host":"postgres","port":6399,"password":"x"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
if [ -z "$DEAD_ASSET_ID" ]; then
  bad "不可達測試資產建立失敗"
else
  DEAD_START=$(date +%s)
  DEAD_TEST=$(curl -s -X POST "$BASE_URL/api/v1/assets/$DEAD_ASSET_ID/test-connection" \
    -H "Authorization: Bearer $TOKEN" --max-time 40)
  DEAD_ELAPSED=$(( $(date +%s) - DEAD_START ))
  echo "$DEAD_TEST" | grep -q '"success":false' \
    && ok "不可達埠撥測回 success=false（${DEAD_ELAPSED}s）" \
    || bad "不可達埠撥測未回 success=false: $DEAD_TEST"
  echo "$DEAD_TEST" | grep -q '"error_code":"protocol_unsupported"' \
    && bad "不可達埠撥測回 protocol_unsupported（撥測對照表漏登記 redis）" \
    || ok "不可達埠失敗分類非 protocol_unsupported"
  curl -s -X DELETE "$BASE_URL/api/v1/assets/$DEAD_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
fi

# --- 8. K8s 協議優雅失敗（k8s-exec：無叢集環境的回歸保險） ---
# kubectl 連不上叢集時：錯誤須印在使用者終端（PTY 輸出）、會話正常 closed、後端無 panic
echo "[8] K8s 連線時選 pod（live，需 k3s-test + demo bootstrap）"
K8S_TOKEN=$(docker compose exec -T k3s-test kubectl -n demo create token operator --duration=1h 2>/dev/null)
if [ -z "$K8S_TOKEN" ]; then
  echo "  (k3s-test 不可用或 demo 未 bootstrap，跳過 k8s live 場景)"
else
  K8S_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-k8s-$$\",\"protocol\":\"k8s\",\"host\":\"k3s-test\",\"port\":6443,\"password\":\"$K8S_TOKEN\",\"k8s_namespace\":\"demo\",\"k8s_insecure_skip_tls\":true}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$K8S_ASSET_ID" ]; then
    bad "k8s 測試資產建立失敗"
  else
    # list-pods 斷言（連線時選 pod 的清單）
    curl -s "$BASE_URL/api/v1/assets/$K8S_ASSET_ID/k8s/pods" -H "Authorization: Bearer $TOKEN" \
      | grep -q '"multi"' && ok "list-pods 列出 demo pod" || bad "list-pods 未見預期 pod"
    # kubectl cp 上傳 sha256 往返保真 + 審計
    CP_FILE=$(mktemp); echo "k8s-cp-e2e-$$-$(date +%s)" > "$CP_FILE"
    CP_SHA=$(sha256sum "$CP_FILE" | awk '{print $1}'); CP_NAME=$(basename "$CP_FILE")
    curl -s -X POST "$BASE_URL/api/v1/assets/$K8S_ASSET_ID/k8s/upload" -H "Authorization: Bearer $TOKEN" \
      -F "pod=multi" -F "container=app" -F "dest_path=/tmp" -F "file=@$CP_FILE" > /dev/null
    CP_BACK=$(docker compose exec -T k3s-test kubectl -n demo exec multi -c app -- sha256sum "/tmp/$CP_NAME" 2>/dev/null | awk '{print $1}')
    [ -n "$CP_SHA" ] && [ "$CP_SHA" = "$CP_BACK" ] && ok "kubectl cp 上傳 sha256 往返保真" || bad "cp 往返 sha256 不符: $CP_SHA vs $CP_BACK"
    rm -f "$CP_FILE"
    AUD=$(psql_q "SELECT count(*) FROM audit_logs WHERE action='file_upload' AND request_body LIKE '%\"direction\":\"upload\"%'")
    [ "${AUD:-0}" -ge 1 ] && ok "kubectl cp 上傳入審計（檔名/大小/方向）" || bad "cp 上傳未入審計"
    curl -s -X DELETE "$BASE_URL/api/v1/assets/$K8S_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
  fi
fi

# --- 9. 閒置斷線（session-timeout；耗時 ~90s，預設跳過） ---
# 啟用方式：後端設 SSH_IDLE_TIMEOUT_MINUTES=1 並 force-recreate，再以
# IDLE_TIMEOUT_SMOKE=1 執行本腳本。驗證：伺服器注入斷線通知＋end_reason 入庫。
if [ "${IDLE_TIMEOUT_SMOKE:-0}" = "1" ]; then
  echo "[9] 閒置斷線（等待 ~75s）"
  IDLE_OUT=$(docker compose exec -T backend go run scripts/sshws_smoke.go \
    -token "$TOKEN" -asset "$SSH_ASSET_ID" -idle-wait 120 2>&1)
  if echo "$IDLE_OUT" | grep -q "PASS idle-timeout"; then
    ok "閒置斷線通知"
  else
    bad "閒置斷線未觸發"
    echo "$IDLE_OUT" | tail -3
  fi
  IDLE_REASON=""
  for i in 1 2 3 4 5; do
    IDLE_REASON=$(psql_q "SELECT end_reason FROM sessions WHERE asset_id=$SSH_ASSET_ID ORDER BY id DESC LIMIT 1")
    [ "$IDLE_REASON" = "idle_timeout" ] && break
    sleep 1
  done
  [ "$IDLE_REASON" = "idle_timeout" ] && ok "end_reason=idle_timeout 入庫" || bad "end_reason 異常: $IDLE_REASON"
else
  echo "[9] 閒置斷線（IDLE_TIMEOUT_SMOKE 未設，跳過）"
fi

# --- 10. SSH 檔案上傳保真（terminal-native-parity：SFTP sha256 往返）---
echo "[10] SSH 檔案上傳保真"
UP_FILE=$(mktemp)
printf '原生級驗證\nnative-parity\t特殊!@#%%\n第三行中文\n' > "$UP_FILE"
UP_SRC_SHA=$(shasum -a 256 "$UP_FILE" 2>/dev/null | awk '{print $1}')
[ -z "$UP_SRC_SHA" ] && UP_SRC_SHA=$(sha256sum "$UP_FILE" 2>/dev/null | awk '{print $1}')
curl -s -o /dev/null -X POST "$BASE_URL/api/v1/assets/$SSH_ASSET_ID/files/upload" \
  -H "Authorization: Bearer $TOKEN" -F "path=/config" -F "file=@$UP_FILE;filename=np-e2e-upload.txt"
UP_REMOTE_SHA=$(docker compose exec -T ssh-test sh -c 'sha256sum /config/np-e2e-upload.txt 2>/dev/null | cut -d" " -f1')
if [ -n "$UP_REMOTE_SHA" ] && [ "$UP_SRC_SHA" = "$UP_REMOTE_SHA" ]; then
  ok "SFTP 上傳 sha256 往返保真（含中文/Tab/特殊字元）"
else
  bad "SFTP 上傳保真失敗（src=$UP_SRC_SHA remote=${UP_REMOTE_SHA}）"
fi
docker compose exec -T ssh-test sh -c 'rm -f /config/np-e2e-upload.txt' 2>/dev/null
rm -f "$UP_FILE"

# --- 11. 多帳號帳號切換（asset-accounts：connect token 綁帳號、會話身分切換）---
# 靶機 ssh-multi-test（rootful sshd）常設於 dev compose；root 與 testuser 皆可密碼登入。
echo "[11] 多帳號帳號切換"
MA_ASSET_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"e2e-multiacct-'"$$"'","protocol":"ssh","host":"ssh-multi-test","port":22,"username":"testuser","password":"testpass123"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
if [ -z "$MA_ASSET_ID" ]; then
  bad "多帳號測試資產建立失敗"
else
  MA_ROOT_ID=$(curl -s -X POST "$BASE_URL/api/v1/assets/$MA_ASSET_ID/accounts" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"username":"root","password":"rootpass123","privileged":true,"note":"e2e"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$MA_ROOT_ID" ]; then
    bad "root 帳號建立失敗"
  else
    MA_OUT=$(docker compose exec -T backend go run scripts/sshws_smoke.go \
      -token "$TOKEN" -asset "$MA_ASSET_ID" -extra "echo uid=\$(id -u)" -extra-expect "uid=1000" 2>&1)
    echo "$MA_OUT" | grep -q "PASS all" && ok "預設帳號建線（testuser，uid=1000）" \
      || { bad "預設帳號建線失敗"; echo "$MA_OUT" | tail -3; }
    MA_OUT=$(docker compose exec -T backend go run scripts/sshws_smoke.go \
      -token "$TOKEN" -asset "$MA_ASSET_ID" -account "$MA_ROOT_ID" \
      -extra "echo uid=\$(id -u)" -extra-expect "uid=0" 2>&1)
    echo "$MA_OUT" | grep -q "PASS all" && ok "指定帳號建線（root，uid=0）" \
      || { bad "指定帳號建線失敗"; echo "$MA_OUT" | tail -3; }
  fi
  curl -s -X DELETE "$BASE_URL/api/v1/assets/$MA_ASSET_ID" -H "Authorization: Bearer $TOKEN" > /dev/null
fi

# --- 12. OIDC SSO 全鏈路（idp-oidc-integration 4.10：dex 靶機三情境）---
#
# 三情境：成功登入→exchange→建 SSH 連線／准入拒絕／同名衝突。全程走真實 HTTP
# （begin 302 → dex 授權頁 → dex 密碼登入 → callback → exchange → connect token → WS）。
#
# **前置不成立一律 skip 而非 fail**：dex 是 dev compose 專屬靶機，正式版 compose
# 不含它，未跑 dex 的環境不該被本場景判為回歸。skip 訊息須指出缺什麼、怎麼補。
#
# 需要的 .env 值（缺任一即 skip，並由下方訊息指名）：
#   PUBLIC_BASE_URL=http://localhost:3000
#   OIDC_DEDICATED_ISSUERS=http://dex.localhost:5556/dex
#   OIDC_ALLOWED_INTERNAL_HOSTS=dex.localhost
# 改 .env 後須 `docker compose up -d backend`（env_file 變更要 recreate 才生效）。
echo "[12] OIDC SSO 全鏈路（dex 靶機）"

DEX_BASE="${DEX_BASE:-http://dex.localhost:5556}"
DEX_ISSUER="$DEX_BASE/dex"
DEX_CLIENT_ID="${DEX_CLIENT_ID:-custodexa-dev}"
DEX_CLIENT_SECRET="${DEX_CLIENT_SECRET:-custodexa-dev-secret}"
# 三個 dex 靜態使用者，對應三情境（明文密碼見 docker/dex/config.yaml，dev 專用）
DEX_OK_LOGIN="oidcuser@dex.localhost";      DEX_OK_PASS="oidcpass123"
DEX_DENY_LOGIN="outsider@outside.example";  DEX_DENY_PASS="deniedpass123"
DEX_CONFLICT_LOGIN="admin@dex.localhost";   DEX_CONFLICT_PASS="conflictpass123"

oidc_skip() { echo "  (跳過 OIDC 場景：$1)"; }

sha256_hex() { python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$1"; }

# oidc_sso_flow <dex 帳號> <dex 密碼>
# 走完 begin → dex 授權 → dex 密碼登入 → callback，結果放進三個全域變數：
#   OIDC_FRAGMENT  callback 導回登入頁的 fragment（sso_ticket=... 或 sso_error=...）
#   OIDC_SECRET    本次流程的 browser secret（exchange 時要送）
#   OIDC_ERR       回傳非零時的診斷字串
# 回傳非零＝流程在抵達 callback 前就斷了（環境問題，呼叫端據此報 FAIL 並印診斷）。
# **診斷走全域變數而非 stdout**：呼叫端若以 $(...) 收訊息，函式即在子 shell 執行，
# OIDC_FRAGMENT 就傳不回來（整個場景會靜默失去斷言對象）。
#
# **callback 刻意改打 $BASE_URL 而非 redirect_uri 上的 PUBLIC_BASE_URL**：後者是
# Vite dev server（只做反向代理），把它算進 e2e 鏈路等於讓前端熱重載的抖動變成
# 認證測試的假紅。dex 對 redirect_uri 的比對發生在授權與 token 兌換兩處，兩處用的
# 都是後端組出的字串，與本腳本從哪個埠發出 callback 請求無關。
oidc_sso_flow() {
  local login="$1" password="$2"
  local cj auth_url page action cb_url cb_query location
  OIDC_FRAGMENT=""; OIDC_SECRET=""; OIDC_ERR=""
  OIDC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cj=$(mktemp)

  auth_url=$(curl -s -o /dev/null -D - -c "$cj" -b "$cj" \
    "$BASE_URL/api/v1/auth/oidc/$OIDC_PROVIDER_ID/begin?binding=$(sha256_hex "$OIDC_SECRET")" \
    | tr -d '\r' | awk '/^[Ll]ocation:/{print $2}')
  if [ -z "$auth_url" ]; then rm -f "$cj"; OIDC_ERR="begin 未回 302"; return 1; fi

  page=$(curl -s -L -c "$cj" -b "$cj" "$auth_url")
  action=$(echo "$page" | grep -oE 'action="[^"]*"' | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
  if [ -z "$action" ]; then rm -f "$cj"; OIDC_ERR="dex 登入表單解析失敗"; return 1; fi

  # 不追蹤重導向：要的是 dex 發出的 code/state，callback 由下一步自行發起
  cb_url=$(curl -s -o /dev/null -D - -c "$cj" -b "$cj" \
    --data-urlencode "login=$login" --data-urlencode "password=$password" \
    "$DEX_BASE$action" | tr -d '\r' | awk '/^[Ll]ocation:/{print $2}' | tail -1)
  rm -f "$cj"
  case "$cb_url" in
    *code=*) ;;
    *) OIDC_ERR="dex 未發出授權碼（帳號密碼錯誤或 client 設定不符）: ${cb_url:-<空>}"; return 1 ;;
  esac
  cb_query="${cb_url#*\?}"

  location=$(curl -s -o /dev/null -D - "$BASE_URL/api/v1/auth/oidc/callback?$cb_query" \
    | tr -d '\r' | awk '/^[Ll]ocation:/{print $2}')
  if [ -z "$location" ]; then OIDC_ERR="callback 未回 302"; return 1; fi
  OIDC_FRAGMENT="${location#*#}"
  return 0
}

# 依身分域鍵清掉外部身分與影子帳號。
# **不是收尾清潔，是防假綠**：准入拒絕與同名衝突兩情境的正確行為是「不建身分」，
# 若上一輪因缺陷建過一筆，下一輪的 callback 會走「既有身分回訪」而直接成功，
# 測試從此恆綠。故兩情境開跑前一律先清。
# 只清 claim_email 命中的**外部身分**與**該身分所屬的影子帳號**；本地 admin 不在
# 此列（衝突情境若真被接管，被接管的是本地 admin，其身分列會被清掉但帳號保留）。
oidc_purge_identity() {
  local email="$1"
  psql_q "DELETE FROM user_roles WHERE user_id IN (
            SELECT user_id FROM user_external_identities WHERE claim_email='$email')" > /dev/null
  psql_q "DELETE FROM asset_authorizations WHERE user_id IN (
            SELECT user_id FROM user_external_identities WHERE claim_email='$email')" > /dev/null
  psql_q "DELETE FROM users WHERE email='$email' AND id IN (
            SELECT user_id FROM user_external_identities WHERE claim_email='$email')" > /dev/null
  psql_q "DELETE FROM user_external_identities WHERE claim_email='$email'" > /dev/null
}

oidc_scenarios() {
  # --- 前置 1：dex 可達且 issuer 字串與預期逐字相符 ---
  local disco iss
  # -sf：非 2xx 不留 body，否則 dex 的 404 文字會被當成「有回應」而讓
  # issuer 比對拿到空字串，skip 訊息指向錯誤方向
  disco=$(curl -sf -m 5 "$DEX_ISSUER/.well-known/openid-configuration" 2>/dev/null)
  if [ -z "$disco" ]; then
    oidc_skip "dex 靶機不可達（${DEX_ISSUER}）；dev compose 起 dex 後重跑"
    return 0
  fi
  iss=$(echo "$disco" | python3 -c "import json,sys; print(json.load(sys.stdin).get('issuer',''))" 2>/dev/null)
  if [ "$iss" != "$DEX_ISSUER" ]; then
    oidc_skip "dex discovery issuer 為 '$iss'，與預期 '$DEX_ISSUER' 不符（改過 config.yaml 或埠映射？）"
    return 0
  fi

  # --- 前置 2：provider 設定（沿用既有同身分域者，否則建立）---
  #
  # 身分域鍵是 (issuer, client_id)，同鍵重複建立會被 409 擋下，故先查再決定 PUT/POST。
  # **更新時一併送 client_secret**：留空是「沿用既有」，但既有值是什麼本腳本無從得知，
  # 猜錯會表現成 callback 階段的 code 兌換失敗——那個錯誤看起來像 SSO 壞了。
  # 代價是每跑一次即算一次密鑰輪替（推進 auth_epoch、撤銷該 provider 的既有存取）；
  # dev 環境可接受，且本場景隨後就重新登入。
  local rules payload existing resp code
  rules='{"email_domain":["dex.localhost"],"email_verified":true}'
  existing=$(curl -s "$BASE_URL/api/v1/oidc-providers" -H "Authorization: Bearer $TOKEN" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin).get('data') or []
print(next((str(p['id']) for p in d
            if p.get('issuer')=='$DEX_ISSUER' and p.get('client_id')=='$DEX_CLIENT_ID'), ''))" 2>/dev/null)
  payload=$(python3 -c "
import json
print(json.dumps({'name':'e2e-dex-sso','issuer':'$DEX_ISSUER','client_id':'$DEX_CLIENT_ID',
                  'client_secret':'$DEX_CLIENT_SECRET','scopes':'openid profile email',
                  'admission_mode':'jit_with_rules','admission_rules':'''$rules''','enabled':True}))")
  if [ -n "$existing" ]; then
    resp=$(curl -s -X PUT "$BASE_URL/api/v1/oidc-providers/$existing" -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" -d "$payload")
  else
    resp=$(curl -s -X POST "$BASE_URL/api/v1/oidc-providers" -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" -d "$payload")
  fi
  if [ -z "$resp" ]; then
    bad "OIDC provider 設定請求無回應（後端重啟中或不可達）"
    return 0
  fi
  code=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('code',''))" 2>/dev/null)
  case "$code" in
    VALIDATION_OIDC_ISSUER)
      oidc_skip "後端拒收 http issuer：.env 需 OIDC_ALLOWED_INTERNAL_HOSTS=dex.localhost（改後 docker compose up -d backend）"
      return 0 ;;
    VALIDATION_OIDC_ADMISSION_RULES)
      oidc_skip "dex issuer 被判為共用身分域：.env 需 OIDC_DEDICATED_ISSUERS=${DEX_ISSUER}（改後 docker compose up -d backend）"
      return 0 ;;
    "") ;;
    *)
      bad "OIDC provider 設定失敗（${code}）: $(echo "$resp" | head -c 200)"
      return 0 ;;
  esac
  OIDC_PROVIDER_ID=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  if [ -z "$OIDC_PROVIDER_ID" ]; then
    bad "OIDC provider 回應無 id: $(echo "$resp" | head -c 200)"
    return 0
  fi
  if ! echo "$resp" | grep -q '"config_complete":true'; then
    oidc_skip "provider 設定不完整（多半是 .env 缺 PUBLIC_BASE_URL=http://localhost:3000；改後 docker compose up -d backend）"
    return 0
  fi
  ok "dex provider 就緒（id=${OIDC_PROVIDER_ID}，issuer_kind=dedicated）"

  # ---- 情境 A：成功登入 → exchange → 建 SSH 連線 ----
  local ex sso_token claims asset_id ssh_out uid
  if ! oidc_sso_flow "$DEX_OK_LOGIN" "$DEX_OK_PASS"; then
    bad "SSO 流程未走到 callback：$OIDC_ERR"
  elif ! echo "$OIDC_FRAGMENT" | grep -q '^sso_ticket='; then
    bad "登入成功情境未取得交棒憑證: $OIDC_FRAGMENT"
  else
    ok "dex 登入 → callback 交棒憑證（fragment）"
    # 兩個值都是十六進位（ticket 由後端簽發、secret 由本腳本產生），直接內插不需
    # JSON 轉義；刻意不套巢狀 python 產生 body——巢狀引號一旦沒閉好，字面的 {..}
    # 會落入 brace expansion 而被拆成兩個字，錯誤訊息還長得像 python 語法錯
    ex=$(curl -s -X POST "$BASE_URL/api/v1/auth/oidc/exchange" -H "Content-Type: application/json" \
      -d "{\"ticket\":\"${OIDC_FRAGMENT#sso_ticket=}\",\"browser_secret\":\"$OIDC_SECRET\"}")
    sso_token=$(echo "$ex" | python3 -c "
import json,sys; print(json.load(sys.stdin).get('login',{}).get('token',''))" 2>/dev/null)
    if [ -z "$sso_token" ]; then
      bad "exchange 未回正式會話: $(echo "$ex" | head -c 200)"
    else
      claims=$(echo "$sso_token" | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip(); p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print(c.get('user_id'), c.get('username'), c.get('auth_method'), c.get('provider_id'))")
      uid=$(echo "$claims" | awk '{print $1}')
      if [ "$(echo "$claims" | awk '{print $3" "$4}')" = "oidc $OIDC_PROVIDER_ID" ]; then
        ok "exchange 換得正式會話（${claims}）"
      else
        bad "會話認證脈絡不符（期望 auth_method=oidc provider_id=${OIDC_PROVIDER_ID}）: $claims"
      fi
      # 專用資產，且顯式 access_policy=open。
      # 兩件事都是必要的：(1) 不借用既有資產，避免其政策/授權狀態影響判讀；
      # (2) 全域預設政策鍵目前是 reason，SSO 使用者是一般 user 角色**不吃 admin 豁免**，
      #     不顯式開放就會停在 RULE_ACCESS_REASON_REQUIRED，測到的是政策閘而非 SSO 鏈路。
      asset_id=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"name":"e2e-oidc-'"$$-$(date +%s)"'","protocol":"ssh","host":"ssh-test","port":2222,"username":"testuser","password":"testpass123","access_policy":"open"}' \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
      if [ -z "$asset_id" ]; then
        bad "OIDC 場景測試資產建立失敗"
      else
        curl -s -o /dev/null -X POST "$BASE_URL/api/v1/authorizations" -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"user_id\":$uid,\"asset_id\":$asset_id,\"permission\":\"connect\"}"
        # -token 收的是 SSO 換得的正式會話：連 connect token 都由該會話簽出，
        # 驗的是「外部身分的會話在協議連線鏈路上與本地帳號等效」
        ssh_out=$(docker compose exec -T backend go run scripts/sshws_smoke.go \
          -token "$sso_token" -asset "$asset_id" \
          -extra "echo oidc-sso-e2e" -extra-expect "oidc-sso-e2e" 2>&1)
        if echo "$ssh_out" | grep -q "PASS all"; then
          ok "以 SSO 會話簽 connect token 並建立 SSH 連線"
        else
          bad "SSO 會話建立 SSH 連線失敗"
          echo "$ssh_out" | tail -5
        fi
        curl -s -o /dev/null -X DELETE "$BASE_URL/api/v1/assets/$asset_id" -H "Authorization: Bearer $TOKEN"
      fi
    fi
  fi

  # ---- 情境 B：准入拒絕（email 網域不符規則）----
  local leftover
  oidc_purge_identity "$DEX_DENY_LOGIN"
  if ! oidc_sso_flow "$DEX_DENY_LOGIN" "$DEX_DENY_PASS"; then
    bad "准入拒絕情境未走到 callback：$OIDC_ERR"
  else
    if [ "$OIDC_FRAGMENT" = "sso_error=oidc_admission_denied" ]; then
      ok "准入不符者於 callback 被拒（${OIDC_FRAGMENT}）"
    else
      bad "准入拒絕情境的 fragment 非預期: $OIDC_FRAGMENT"
    fi
    echo "$OIDC_FRAGMENT" | grep -q 'sso_ticket=' && bad "准入被拒卻仍簽出交棒憑證" \
      || ok "准入被拒未簽交棒憑證"
    leftover=$(psql_q "SELECT count(*) FROM users u
      WHERE u.email='$DEX_DENY_LOGIN'
         OR EXISTS (SELECT 1 FROM user_external_identities i
                    WHERE i.user_id=u.id AND i.claim_email='$DEX_DENY_LOGIN')")
    [ "${leftover:-1}" = "0" ] && ok "准入被拒未建立帳號或外部身分" \
      || bad "准入被拒卻留下帳號/身分（$leftover 筆）"
  fi

  # ---- 情境 C：同名衝突（映射所得 username 撞既有本地帳號 admin）----
  oidc_purge_identity "$DEX_CONFLICT_LOGIN"
  if ! oidc_sso_flow "$DEX_CONFLICT_LOGIN" "$DEX_CONFLICT_PASS"; then
    bad "同名衝突情境未走到 callback：$OIDC_ERR"
  else
    if [ "$OIDC_FRAGMENT" = "sso_error=oidc_username_conflict" ]; then
      ok "同名者於 callback 被拒（${OIDC_FRAGMENT}）"
    else
      bad "同名衝突情境的 fragment 非預期: $OIDC_FRAGMENT"
    fi
    echo "$OIDC_FRAGMENT" | grep -q 'sso_ticket=' && bad "同名衝突卻仍簽出交棒憑證" \
      || ok "同名衝突未簽交棒憑證"
    # 不接管：本地 admin 不得被掛上這個外部身分
    leftover=$(psql_q "SELECT count(*) FROM user_external_identities
      WHERE claim_email='$DEX_CONFLICT_LOGIN' OR user_id=(
        SELECT id FROM users WHERE username='$ADMIN_USER' AND deleted_at IS NULL)")
    [ "${leftover:-1}" = "0" ] && ok "本地 admin 未被外部身分接管" \
      || bad "同名衝突卻建立了外部身分（$leftover 筆）"
  fi
}

oidc_scenarios

# --- 13. LDAP 目錄設定與登入（ldap-settings-migration 5.3）---
#
# 一條線走完：API upsert（含啟用）→ 連線測試 → LDAP 使用者登入 → 影子帳號斷言 → 清理。
#
# **顯式設定、不依賴 seed**：dev `.env` 出廠 `LDAP_ENABLED=false`，且 seed marker 的語義是
# 「已完成評估」（評估過就不再看 env），fresh 與既有環境都不會自動生出設定列——場景自己
# upsert 才有確定起點。
#
# **前置不成立一律 skip 而非 fail**（同場景 12）：ldap-test 是 dev compose 專屬靶機，
# 正式版 compose 不含它；LDAP 通道政策為 strict 時，明文目標依設計即拒存/拒測。
echo "[13] LDAP 目錄設定與登入（ldap-test 靶機）"

# 下列值對齊 docker-compose.dev.yml 的 ldap-test 服務（亦即 .env.example 的 LDAP 段）
LDAP_URL_E2E="${LDAP_URL_E2E:-ldap://ldap-test:1389}"
LDAP_BIND_DN_E2E="${LDAP_BIND_DN_E2E:-cn=admin,dc=example,dc=org}"
LDAP_BIND_PASS_E2E="${LDAP_BIND_PASS_E2E:-adminpass}"
LDAP_BASE_DN_E2E="${LDAP_BASE_DN_E2E:-ou=users,dc=example,dc=org}"
# 靶機初始化的唯一目錄使用者（compose 的 LDAP_USERS/LDAP_PASSWORDS）
LDAP_LOGIN_USER="${LDAP_LOGIN_USER:-testldap}"
LDAP_LOGIN_PASS="${LDAP_LOGIN_PASS:-ldappass123}"

ldap_skip() { echo "  (跳過 LDAP 場景：$1)"; }

# 影子帳號清除（**best-effort**）：只刪 provisioning_origin='ldap' 的列，本地同名帳號不在此列。
# 目的是讓「首次登入即供應」成為本輪實際發生的事；曾建過連線的舊影子帳號會被 sessions 外鍵
# 擋住（那是稽核資料，不為了讓測試好看而刪），此時退回欄位斷言並印註記。
ldap_purge_shadow() {
  psql_q "DELETE FROM user_roles WHERE user_id IN (
            SELECT id FROM users WHERE username='$LDAP_LOGIN_USER' AND provisioning_origin='ldap')" > /dev/null
  psql_q "DELETE FROM users WHERE username='$LDAP_LOGIN_USER' AND provisioning_origin='ldap'" > /dev/null
}

ldap_scenario() {
  local existing resp code payload test_payload test_resp matched login_resp token claims shadow left

  if ! docker compose ps ldap-test 2>/dev/null | grep -q "Up"; then
    ldap_skip "ldap-test 靶機未運行（dev compose 專屬）；起 ldap-test 後重跑"
    return 0
  fi

  # 既有設定若指向別處就不碰：本場景會 upsert 覆寫，而 bind 密碼不可回讀、覆寫後無法還原
  existing=$(curl -s "$BASE_URL/api/v1/ldap-directory" -H "Authorization: Bearer $TOKEN" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('url','') if d.get('configured') else '')" 2>/dev/null)
  if [ -n "$existing" ] && [ "$existing" != "$LDAP_URL_E2E" ]; then
    ldap_skip "已存在指向 $existing 的 LDAP 設定；覆寫會使既存 bind 密碼不可回復，故不動它"
    return 0
  fi

  # ---- (1) API upsert：顯式設定並啟用 ----
  # risk_acknowledged=true：ldap:// 為明文通道，warn 檔位下缺確認即 400（strict 檔位仍拒）
  payload="{\"name\":\"e2e-ldap\",\"url\":\"$LDAP_URL_E2E\",\"bind_dn\":\"$LDAP_BIND_DN_E2E\",\
\"bind_password\":\"$LDAP_BIND_PASS_E2E\",\"base_dn\":\"$LDAP_BASE_DN_E2E\",\"user_filter\":\"(uid=%s)\",\
\"attr_email\":\"mail\",\"attr_fullname\":\"cn\",\"skip_tls_verify\":false,\"enabled\":true,\
\"risk_acknowledged\":true}"
  resp=$(curl -s -X PUT "$BASE_URL/api/v1/ldap-directory" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" -d "$payload")
  if [ -z "$resp" ]; then
    bad "LDAP 設定 PUT 無回應（後端重啟中或不可達）"
    return 0
  fi
  code=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('code',''))" 2>/dev/null)
  case "$code" in
    VALIDATION_TRANSMISSION_STRICT_REJECT)
      ldap_skip "LDAP 通道政策為 strict，明文 ldap:// 目標依設計拒存；改 warn/off 後重跑"
      return 0 ;;
    "") ;;
    *)
      bad "LDAP 設定存檔失敗（${code}）: $(echo "$resp" | head -c 200)"
      return 0 ;;
  esac
  echo "$resp" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d.get('configured') is True and d.get('enabled') is True, d
assert d.get('has_bind_password') is True, d
assert 'bind_password' not in d, list(d.keys())
assert d.get('url')=='$LDAP_URL_E2E', d.get('url')" \
    && ok "LDAP 設定 upsert 並啟用（回應不含密碼、has_bind_password=true）" \
    || { bad "LDAP 設定回應形狀異常: $(echo "$resp" | head -c 200)"; return 0; }

  # ---- (2) 連線測試：三階段成功且回報比對筆數 ----
  test_payload="{\"url\":\"$LDAP_URL_E2E\",\"bind_dn\":\"$LDAP_BIND_DN_E2E\",\
\"bind_password\":\"$LDAP_BIND_PASS_E2E\",\"base_dn\":\"$LDAP_BASE_DN_E2E\",\"user_filter\":\"(uid=%s)\",\
\"attr_email\":\"mail\",\"attr_fullname\":\"cn\",\"skip_tls_verify\":false,\"enabled\":true,\
\"risk_acknowledged\":true}"
  test_resp=$(curl -s -X POST "$BASE_URL/api/v1/ldap-directory/test" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" -d "$test_payload")
  # 階梯已執行即 HTTP 200（含失敗），故斷言對象是 body 的 stages/failed_stage 而非狀態碼
  matched=$(echo "$test_resp" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d.get('success') is True and not d.get('failed_stage'), d
assert [(s.get('stage'), s.get('ok')) for s in d.get('stages',[])] == [('dial',True),('bind',True),('search',True)], d.get('stages')
c=d.get('matched_count')
assert isinstance(c,int) and c>=1, d
print(c)" 2>/dev/null)
  [ -n "$matched" ] && ok "連線測試 dial/bind/search 三階段成功（matched_count=${matched}）" \
    || bad "連線測試未通過: $(echo "$test_resp" | head -c 200)"

  # ---- (3) LDAP 使用者登入 ----
  ldap_purge_shadow
  if [ "$(psql_q "SELECT count(*) FROM users WHERE username='$LDAP_LOGIN_USER' AND provisioning_origin='ldap'")" != "0" ]; then
    echo "  (註：既有影子帳號有 sessions 外鍵殘留而無法清除，本輪不代表「首次登入即供應」；欄位斷言仍有效)"
  fi
  login_resp=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$LDAP_LOGIN_USER\",\"password\":\"$LDAP_LOGIN_PASS\"}")
  token=$(echo "$login_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
  if [ -z "$token" ]; then
    bad "LDAP 使用者登入失敗: $(echo "$login_resp" | head -c 200)"
  else
    ok "LDAP 使用者登入（${LDAP_LOGIN_USER}）"
    claims=$(echo "$token" | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip(); p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print(c.get('auth_method'), c.get('username'))")
    [ "$claims" = "ldap $LDAP_LOGIN_USER" ] && ok "會話認證脈絡 auth_method=ldap" \
      || bad "會話認證脈絡不符（期望 'ldap $LDAP_LOGIN_USER'）: $claims"

    # ---- (4) 影子帳號已供應 ----
    # last_login_at 的時間窗使斷言指向**本次**登入，不會被殘留舊帳號蒙混過關
    shadow=$(psql_q "SELECT is_ldap::text || ' ' || provisioning_origin || ' ' ||
                            (last_login_at > now() - interval '5 minutes')::text
                     FROM users WHERE username='$LDAP_LOGIN_USER' AND deleted_at IS NULL")
    [ "$shadow" = "true ldap true" ] && ok "影子帳號已供應（is_ldap=true、provisioning_origin=ldap、本次登入更新）" \
      || bad "影子帳號欄位不符（期望 'true ldap true'）: ${shadow:-<查無帳號>}"
  fi

  # ---- (5) 清理 ----
  curl -s -o /dev/null -X DELETE "$BASE_URL/api/v1/ldap-directory" -H "Authorization: Bearer $TOKEN"
  left=$(curl -s "$BASE_URL/api/v1/ldap-directory" -H "Authorization: Bearer $TOKEN" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('configured'))" 2>/dev/null)
  [ "$left" = "False" ] && ok "設定已軟刪（GET 回 configured=false）" \
    || bad "設定未清除（configured=${left}），下次執行起點不確定"
  ldap_purge_shadow
}

ldap_scenario

# --- 14. 審計檢查點鏈（audit-checkpoint-chain 10.4）---
#
# 覆蓋兩層驗證與「抽一列即現形」的核心承諾。**竄改以 psql 直寫製造**：
# 那正是本機制的威脅模型（對手可直寫 DB），經 API 造不出來也不該造得出來。
# 抽列前先把整列存進暫存表，驗完原樣寫回——含 integrity_hmac 與 id，
# 否則還原本身會變成第二次竄改。
checkpoint_scenario() {
  echo "[14] 審計檢查點鏈（結構層／內容層／竄改現形）"

  local body code seq id_from id_to victim status

  # ---- (1) 公鑰端點：離線驗章的對外承諾 ----
  body=$(curl -s "$BASE_URL/api/v1/audit-checkpoints/public-key" -H "Authorization: Bearer $TOKEN")
  echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
assert d['algorithm']=='Ed25519' and d['public_key'] and d['fingerprint'] and d['version']>=1, d
" 2>/dev/null && ok "公鑰端點回 Ed25519 公鑰與指紋" \
    || bad "公鑰端點回應異常: $(echo "$body" | head -c 200)"

  # ---- (2) 結構層全鏈驗證：預設不帶範圍即驗全鏈 ----
  body=$(curl -s "$BASE_URL/api/v1/audit-checkpoints/verify" -H "Authorization: Bearer $TOKEN")
  status=$(echo "$body" | python3 -c "
import json,sys
print(json.load(sys.stdin)['data']['chain'].get('status',''))" 2>/dev/null)
  if [ "$status" = "passed" ]; then
    ok "結構層全鏈驗證通過（簽章＋鏈接＋seq 連續）"
  else
    bad "結構層驗證未通過（status=${status}）: $(echo "$body" | head -c 300)"
  fi

  # ---- (3) 內容層必須帶範圍：不帶即拒，且不得啟動全歷史掃描 ----
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    "$BASE_URL/api/v1/audit-checkpoints/verify?content=true" -H "Authorization: Bearer $TOKEN")
  [ "$code" = "400" ] && ok "內容層拒絕無範圍請求（400）" \
    || bad "內容層無範圍請求回 ${code}（應 400，否則等於允許全歷史掃描）"

  # ---- (4) 取一個至少三列、未清除的區間；沒有就 skip 後續竄改子場景 ----
  #
  # **下限 row_count >= 3 是斷言正確性的前提，不是效能調校**：抽走單列區間的唯一一列
  # 等於抽空整個區間，驗證器依定義回 purged_invalid（checkpoint_verify.go 的
  # remain == 0 分支），與「抽一列」是兩件不同的事。dev 環境常出現單列／空區間，
  # 不設下限則 (5) 會確定性假紅（2026-08-16 seq=49 即 row_count=1）。
  # 規範來源 openspec/specs/audit-checkpoint-chain/spec.md 的
  # Scenario「抽走中段列被偵測」同樣以「抽中段列」為語義，此處對齊之。
  seq=$(psql_q "SELECT seq FROM audit_checkpoints
                WHERE row_count >= 3 AND purged_at IS NULL ORDER BY seq DESC LIMIT 1")
  if [ -z "$seq" ]; then
    echo "  SKIP: 本次未驗竄改現形 —— 鏈上無 row_count>=3 的未清除檢查點區間"
    echo "  SKIP: （單列／空區間抽列等於抽空區間，測不出「抽一列即現形」；此項不計入 PASS）"
    return 0
  fi
  id_from=$(psql_q "SELECT id_from FROM audit_checkpoints WHERE seq = $seq")
  id_to=$(psql_q "SELECT id_to FROM audit_checkpoints WHERE seq = $seq")

  body=$(curl -s "$BASE_URL/api/v1/audit-checkpoints/verify?content=true&seq_from=$seq&seq_to=$seq" \
    -H "Authorization: Bearer $TOKEN")
  status=$(echo "$body" | python3 -c "
import json,sys
c=json.load(sys.stdin)['data'].get('content') or {}
print(c['intervals'][0]['status'] if c.get('intervals') else '')" 2>/dev/null)
  [ "$status" = "passed" ] && ok "內容層範圍驗證通過（seq=${seq}，區間 [$id_from,$id_to]）" \
    || bad "內容層驗證 seq=$seq 未通過（status=${status}）: $(echo "$body" | head -c 300)"

  # ---- (5) 抽走區間**中段**的一列 → 內容層必須現形 ----
  #
  # 取中段而非首列：首／末列被抽走時區間邊界仍在，但若該區間只剩一列就會整段消失；
  # 中段列保證抽完 remain > 0，讓「抽一列」與「抽空區間」在狀態上分得開。
  victim=$(psql_q "SELECT id FROM audit_logs WHERE id >= $id_from AND id <= $id_to ORDER BY id
                   OFFSET (SELECT count(*)/2 FROM audit_logs WHERE id >= $id_from AND id <= $id_to)
                   LIMIT 1")
  if [ -z "$victim" ]; then
    echo "  SKIP: 本次未驗竄改現形 —— 區間 [$id_from,$id_to] 內查無列（可能剛被清除）；此項不計入 PASS"
    return 0
  fi
  psql_q "DROP TABLE IF EXISTS e2e_checkpoint_victim" >/dev/null
  psql_q "CREATE TABLE e2e_checkpoint_victim AS SELECT * FROM audit_logs WHERE id = $victim" >/dev/null
  psql_q "DELETE FROM audit_logs WHERE id = $victim" >/dev/null

  body=$(curl -s "$BASE_URL/api/v1/audit-checkpoints/verify?content=true&seq_from=$seq&seq_to=$seq" \
    -H "Authorization: Bearer $TOKEN")
  status=$(echo "$body" | python3 -c "
import json,sys
c=json.load(sys.stdin)['data'].get('content') or {}
print(c['intervals'][0]['status'] if c.get('intervals') else '')" 2>/dev/null)
  case "$status" in
    count_mismatch|hash_mismatch)
      ok "抽走中段列 id=$victim 後內容層轉為 ${status}（竄改現形）" ;;
    *)
      # purged_invalid 不收進可接受集合：它代表「整個區間被抹掉」，
      # 抽一列卻回這個狀態＝區間比宣稱的還小，本身就是要抓的異常。
      bad "抽列後狀態 = ${status}（應為 count_mismatch／hash_mismatch；驗不出即機制失效）" ;;
  esac

  # ---- (6) 原樣寫回並複驗：還原後必須回到 passed ----
  psql_q "INSERT INTO audit_logs SELECT * FROM e2e_checkpoint_victim" >/dev/null
  psql_q "DROP TABLE IF EXISTS e2e_checkpoint_victim" >/dev/null
  body=$(curl -s "$BASE_URL/api/v1/audit-checkpoints/verify?content=true&seq_from=$seq&seq_to=$seq" \
    -H "Authorization: Bearer $TOKEN")
  status=$(echo "$body" | python3 -c "
import json,sys
c=json.load(sys.stdin)['data'].get('content') or {}
print(c['intervals'][0]['status'] if c.get('intervals') else '')" 2>/dev/null)
  [ "$status" = "passed" ] && ok "還原該列後內容層回到 passed（驗證器不是恆紅）" \
    || bad "還原後狀態 = ${status}（資料已還原卻仍告警，或還原未成功）"
}

checkpoint_scenario

# --- 15. 稽核工作台：以人樞紐查當日並自告警跳入（auditor-workbench 10.3）---
# 這條守的是「聚合誠實」：counts 不受 limit 影響、游標分頁不重不漏、
# 六類 coverage 全有狀態（空白區間永遠帶標記）、未知型別不靜默忽略。
# 任何一條鬆掉，工作台都會回一份看起來完整、實際少一整類的時間軸。
echo ""
echo "[15] 稽核工作台時間軸"
workbench_scenario() {
  local body code subj_user subj_asset uid day_from day_to

  # ---- (1) 主體目錄兩型皆可查，且只回最小欄位 ----
  for kind in user asset; do
    body=$(curl -s -w "\n%{http_code}" "$BASE_URL/api/v1/audit/subjects?type=$kind&limit=5" \
      -H "Authorization: Bearer $TOKEN")
    code=$(echo "$body" | tail -1)
    [ "$code" = "200" ] && ok "主體目錄 type=$kind 回 200" \
      || { bad "主體目錄 type=$kind 回 ${code}（資產型曾因 SELECT 不存在的欄位而 500）"; return; }
  done
  body=$(curl -s "$BASE_URL/api/v1/audit/subjects?type=user&limit=5" -H "Authorization: Bearer $TOKEN")
  echo "$body" | python3 -c "
import json,sys
rows=json.load(sys.stdin)['data']
allowed={'id','name','display_name','active','deleted'}
extra=set().union(*[set(r) for r in rows]) - allowed if rows else set()
sys.exit(1 if extra else 0)" \
    && ok "主體目錄只回最小欄位（不外洩 email／角色／外部身分）" \
    || bad "主體目錄回了白名單外的欄位——本端點存在的理由就是不交出這些"

  # ---- (2) 取一位有會話的使用者與其當日窗 ----
  uid=$(psql_q "SELECT user_id FROM sessions WHERE start_time IS NOT NULL ORDER BY start_time DESC LIMIT 1" | tr -d ' ')
  if [ -z "$uid" ]; then
    echo "  SKIP: 無任何會話，工作台場景略過"
    return
  fi
  day_from=$(psql_q "SELECT to_char(date_trunc('day', max(start_time)), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM sessions" | tr -d ' ')
  day_to=$(psql_q "SELECT to_char(date_trunc('day', max(start_time)) + interval '1 day', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM sessions" | tr -d ' ')

  body=$(curl -s "$BASE_URL/api/v1/audit/timeline?subject=user&subject_id=$uid&from=$day_from&to=$day_to&limit=5" \
    -H "Authorization: Bearer $TOKEN")
  echo "$body" | python3 -c "
import json,sys
d=json.load(sys.stdin)
need={'alert','audit_log','clipboard','command','file_transfer','session'}
cov={c['type']: c['state'] for c in d['coverage']}
if set(cov) != need:
    print('coverage 類別缺漏:', need - set(cov)); sys.exit(1)
if any(v not in ('present','purged','not_retained') for v in cov.values()):
    print('coverage 出現未知狀態:', cov); sys.exit(1)
if cov['clipboard'] != 'not_retained':
    print('剪貼簿無保留政策，coverage 應為 not_retained，實得', cov['clipboard']); sys.exit(1)
if set(d['counts']) != need:
    print('counts 類別缺漏:', need - set(d['counts'])); sys.exit(1)
if len(d['events']) > 5:
    print('limit 未生效'); sys.exit(1)
if d['truncated'] and sum(d['counts'].values()) <= len(d['events']):
    print('truncated=true 但 counts 未回真實總數'); sys.exit(1)
" && ok "六類 coverage 齊備且狀態合法、counts 不受 limit 影響" \
    || bad "工作台聚合誠實性斷言失敗（空白區間無標記會被讀成紀錄被刪）"

  # ---- (3) 未知型別回 400 而非靜默忽略 ----
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/v1/audit/timeline?subject=user&subject_id=$uid&from=$day_from&to=$day_to&types=bogus" \
    -H "Authorization: Bearer $TOKEN")
  [ "$code" = "400" ] && ok "未知 types 回 400（不靜默忽略整類資料）" \
    || bad "未知 types 回 ${code}（應為 400）"

  # ---- (4) 游標分頁不重不漏（與單次大 limit 逐筆比對）----
  BASE_URL="$BASE_URL" TOKEN="$TOKEN" UID_="$uid" FROM_="$day_from" TO_="$day_to" python3 -c "
import json,os,subprocess,urllib.parse,sys
base,tok=os.environ['BASE_URL'],os.environ['TOKEN']
common={'subject':'user','subject_id':os.environ['UID_'],'from':os.environ['FROM_'],'to':os.environ['TO_']}
def get(**kw):
    url=base+'/api/v1/audit/timeline?'+urllib.parse.urlencode(dict(common,**kw))
    return json.loads(subprocess.run(['curl','-s',url,'-H','Authorization: Bearer '+tok],
                                     capture_output=True,text=True).stdout)
paged,cur,n=[],None,0
while n < 50:
    kw={'limit':20}
    if cur: kw['cursor']=cur
    d=get(**kw); n+=1
    paged += [e['id'] for e in d['events']]
    cur=d.get('next_cursor')
    if not cur: break
one=[e['id'] for e in get(limit=500)['events']]
if len(paged)!=len(set(paged)): print('分頁重複列'); sys.exit(1)
if paged[:len(one)]!=one: print('分頁與單次取回不一致（k-way merge 或游標錯位）'); sys.exit(1)
" && ok "游標分頁與單次取回逐筆一致（不重不漏）" \
    || bad "游標分頁與單次取回不一致——六來源合併漏列"

  # ---- (5) 自告警跳入：以 triggered_at ±30 分鐘為窗，該告警必須在窗內查得到 ----
  local aid ats
  aid=$(psql_q "SELECT id FROM command_alerts ORDER BY triggered_at DESC LIMIT 1" | tr -d ' ')
  if [ -z "$aid" ]; then
    echo "  SKIP: 無告警資料，跳入場景略過"
    return
  fi
  ats=$(psql_q "SELECT user_id || '|' || to_char(triggered_at - interval '30 min', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') || '|' || to_char(triggered_at + interval '30 min', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM command_alerts WHERE id=$aid" | tr -d ' ')
  body=$(curl -s "$BASE_URL/api/v1/audit/timeline?subject=user&subject_id=${ats%%|*}&from=$(echo "$ats" | cut -d'|' -f2)&to=$(echo "$ats" | cut -d'|' -f3)&types=alert&limit=500" \
    -H "Authorization: Bearer $TOKEN")
  echo "$body" | AID="$aid" python3 -c "
import json,os,sys
d=json.load(sys.stdin)
want='alert:'+os.environ['AID']
sys.exit(0 if any(e['id']==want for e in d['events']) else 1)" \
    && ok "自告警 ±30 分鐘窗跳入，該告警在時間軸內查得到（深連結有效）" \
    || bad "告警 id=$aid 不在自己的 ±30 分鐘窗內——深連結會跳到查無此事件的畫面"
}

workbench_scenario

# --- 16/17. 圖形協議端到端（RDP／VNC：guacd 路徑的建線、落庫、錄影、審計）---
#
# **為什麼要獨立一條路徑**：SSH 早已退出 guacd（指令審計與 asciicast 錄製走
# internal/sshproxy），圖形協議則是「後端先與 guacd 完成握手 → 成功才升級
# WebSocket → Tunnel 純轉發」。前面 15 個場景一條都沒踩過這條路徑。
#
# 斷言層級刻意高於「TCP 可達」：`last_test_status=reachable` 只證明埠通，
# 撥測不建線。此處要求收到 guacd 的 **sync 幀**——那代表協議協商完成、畫面串流
# 已經開始，且 error 幀會被驅動判為失敗（VNC 認證失敗即以 in-band error 現形）。
#
# 錄影斷言是 observability-lite 錄影路徑正規化（`internal/proxy/handler.go`
# 更名段改走 recorder.GraphicsRecordingPath）在圖形協議上的唯一端到端驗證：
# 路徑不做逐字比對常數，改驗其**性質**——結尾為 `session-<id>.guac`、
# 全路徑不含 `//`。雙斜線正是該正規化要防的回歸（保留期清理刪得掉檔案、
# 清不掉 DB 欄位），而寫死根目錄字面值只會讓場景綁死一組 RECORDING_PATH。
#
# 這是冒煙不是功能矩陣：剪貼簿、檔案傳輸、解析度協商一律不在此。
#
# 靶機或 guacd 未就緒時顯性 SKIP 且不計入 PASS（同場景 8／14 的慣例）。
graphics_scenario() {
  local idx="$1" label="$2" proto="$3" svc="$4" host="$5" port="$6" user="$7" pass="$8"
  local asset_id sid out proto_db status_db rec_path rec_size disk_size code aud i
  local slack_def slack_k rec_delta

  echo ""
  echo "[$idx] $label 圖形協議端到端（guacd 路徑）"

  if ! docker compose ps guacd 2>/dev/null | grep -q "Up"; then
    echo "  SKIP: guacd 服務未運行——圖形協議的代理路徑不存在，無從驗起（此項不計入 PASS）"
    return 0
  fi
  if ! docker compose ps "$svc" 2>/dev/null | grep -q "Up"; then
    echo "  SKIP: $svc 靶機未運行（正式版 compose 不含測試靶機；此項不計入 PASS）"
    echo "  處置: docker compose up -d $svc 後重跑"
    return 0
  fi

  asset_id=$(curl -s -X POST "$BASE_URL/api/v1/assets" -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"e2e-$proto-$$\",\"protocol\":\"$proto\",\"host\":\"$host\",\"port\":$port,\"username\":\"$user\",\"password\":\"$pass\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
  if [ -z "$asset_id" ]; then
    bad "$label 測試資產建立失敗"
    return 0
  fi

  # 建線：WS 升級＋子協議協商＋sync 幀。-hold 讓 guacd 累積畫格（錄影非空的前提）
  out=$(docker compose exec -T backend go run scripts/guacws_smoke.go \
    -token "$TOKEN" -asset "$asset_id" -hold 5 2>&1)
  if echo "$out" | grep -q "PASS all"; then
    ok "$label WS 建線並收到 guacd sync 幀（非僅 TCP 可達）"
  else
    bad "$label WS 建線失敗（後續落庫／錄影／審計斷言失去前提，一併未驗）"
    echo "$out" | tail -4
    curl -s -X DELETE "$BASE_URL/api/v1/assets/$asset_id" -H "Authorization: Bearer $TOKEN" > /dev/null
    return 0
  fi

  # 會話落庫：協議欄位須為本協議，且連線結束後狀態收斂為 closed
  sid=$(psql_q "SELECT id FROM sessions WHERE asset_id=$asset_id ORDER BY id DESC LIMIT 1")
  if [ -z "$sid" ]; then
    bad "$label 查無 session 記錄（asset_id=${asset_id}）"
    curl -s -X DELETE "$BASE_URL/api/v1/assets/$asset_id" -H "Authorization: Bearer $TOKEN" > /dev/null
    return 0
  fi
  proto_db=$(psql_q "SELECT protocol FROM sessions WHERE id=$sid")
  status_db=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    status_db=$(psql_q "SELECT status FROM sessions WHERE id=$sid")
    [ "$status_db" = "closed" ] && break
    sleep 1
  done
  if [ "$proto_db" = "$proto" ] && [ "$status_db" = "closed" ]; then
    ok "$label 會話落庫（session ${sid}，protocol=${proto_db}，status=closed）"
  else
    bad "$label 會話欄位異常（protocol=${proto_db} 應為 ${proto}；status=${status_db} 應為 closed）"
  fi

  # 錄影落檔：更名段在隧道收線後才跑，帶重試
  rec_path=""
  for i in 1 2 3 4 5 6 7 8 9 10; do
    rec_path=$(psql_q "SELECT coalesce(recording_path,'') FROM sessions WHERE id=$sid")
    [ -n "$rec_path" ] && break
    sleep 1
  done
  case "$rec_path" in
    "")
      bad "$label 錄影未落檔：sessions.recording_path 為空（guacd 未寫檔或更名失敗）" ;;
    *//*)
      bad "$label 錄影路徑含雙斜線（${rec_path}）——正規化回歸，保留期清理將刪得掉檔案卻清不掉 DB 欄位" ;;
    */session-$sid.guac)
      ok "$label 錄影路徑正規化正確（${rec_path}）" ;;
    *)
      bad "$label 錄影路徑不符 session-$sid.guac 慣例: $rec_path" ;;
  esac

  if [ -n "$rec_path" ]; then
    rec_size=$(psql_q "SELECT coalesce(recording_size,0) FROM sessions WHERE id=$sid")
    disk_size=$(docker compose exec -T backend sh -c "wc -c < '$rec_path' 2>/dev/null" | tr -d ' \r')
    # 錄影大小：雙側界斷言 `db > 0` 且 `0 <= disk - db <= K`，**不是嚴格相等**。
    #
    # 圖形錄影（.guac）的 fd 由 guacd 持有，後端在隧道返回後 os.Stat 取大小，而 guacd
    # 之後還會寫收尾尾段（釋放顯示層的 dispose 指令）；協議層無收尾完成訊號、guacd 也
    # 不會先關與後端之間的 TCP，故後端沒有可用的同步點——差額無法消除，只能界定。
    # 方向恆為少記（db <= disk），反向偏差表示檔案被截斷／被取代／量測對象錯了。
    # 上界 K 取自後端的單一定義點（防止兩邊各寫一個數字而悄悄漂開）。
    #
    # **本上界的前提是靶機畫面靜態**：本場景的 guacws_smoke 只做建線與 sync 幀計數，
    # 不產生畫面活動，故 guacd 的 8192 B 輸出緩衝在畫格邊界已清空，收尾殘量就只有
    # 那幾則 dispose。**K 不是普遍上界**——若日後把場景改成跑動畫，收線可能落在畫格
    # 中途，殘量可達一個畫格的量級（遠大於 K），屆時應改場景設計，不是調大 K。
    # 差額超過 K 一律視為待查缺陷（見 change graphics-teardown-sync design D5）。
    slack_def="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backend/internal/recorder/graphics_teardown_slack.go"
    slack_k=$(grep -oE 'GraphicsTeardownSlackBytes = [0-9]+' "$slack_def" 2>/dev/null | grep -oE '[0-9]+$')
    if [ -z "$slack_k" ]; then
      # 取不到就是紅，**不回退內建預設**：回退會讓「守衛失效」偽裝成「守衛通過」
      bad "$label 錄影大小上界 K 取不到（定義點 ${slack_def} 缺 GraphicsTeardownSlackBytes）——斷言無從進行"
    else
      rec_delta=$(( ${disk_size:-0} - ${rec_size:-0} ))
      if [ "${disk_size:-0}" -gt 0 ] 2>/dev/null && [ "${rec_size:-0}" -gt 0 ] 2>/dev/null \
         && [ "$rec_delta" -ge 0 ] && [ "$rec_delta" -le "$slack_k" ]; then
        ok "$label 錄影檔存在且非空（磁碟 ${disk_size} / DB ${rec_size} bytes，差額 ${rec_delta} ≤ K=${slack_k}）"
      else
        bad "$label 錄影大小異常（磁碟 ${disk_size:-無檔} bytes / DB ${rec_size} bytes / 差額 ${rec_delta} / K=${slack_k}）"
      fi
    fi

    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "$BASE_URL/api/v1/sessions/$sid/recording" -H "Authorization: Bearer $TOKEN")
    [ "$code" = "200" ] && ok "$label 錄影 metadata API 回 200（可回放）" \
      || bad "$label 錄影 metadata API 回 ${code}"
  fi

  # 審計：連線行為須進審計庫，且帶得出協議（無此列即等於該次連線沒有稽核歸屬）
  aud=""
  for i in 1 2 3 4 5; do
    aud=$(psql_q "SELECT count(*) FROM audit_logs WHERE action='create' AND resource='session'
                  AND resource_id=$sid AND details LIKE '%\"protocol\":\"$proto\"%'")
    [ "${aud:-0}" -ge 1 ] 2>/dev/null && break
    sleep 1
  done
  [ "${aud:-0}" -ge 1 ] 2>/dev/null && ok "$label 連線入審計庫（resource=session/${sid}，protocol=${proto}）" \
    || bad "$label 連線未入審計庫（session $sid 無 create/session 稽核列）"

  curl -s -X DELETE "$BASE_URL/api/v1/assets/$asset_id" -H "Authorization: Bearer $TOKEN" > /dev/null
}

# 靶機帳密取自 docker-compose.dev.yml 的 rdp-test／vnc-test 環境變數（僅 dev 靶機）。
# VNC 無 username 概念（handler 於 fillDefaults 直接 delete），故留空。
graphics_scenario 16 RDP rdp rdp-test rdp-test 3389 testuser testpass123
graphics_scenario 17 VNC vnc vnc-test vnc-test 5901 "" vncpass123

echo ""
echo "=== 結果: PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ] || exit 1
