# Custodexa - API 規格文件

> 資料來源：`backend/cmd/server/main.go`（組裝根）, `backend/cmd/server/stage1.go`／`stage2.go`（兩段啟動）, `backend/internal/api/*.go`,
> `backend/internal/sshproxy/handler.go`, `backend/internal/proxy/handler.go`,
> `backend/internal/modules/*`（asset／identity／authz／policy／audit／session／keyvault 七模組）, `backend/internal/model/*.go`,
> `backend/internal/middleware/permission.go`, `backend/config/config.go`
> 相關文件：資料模型見 [DB_SCHEMA.md](DB_SCHEMA.md)；各能力行為規格見 `openspec/specs/`；動到路由時須同步本文件（見 [CONTRIBUTING.md](../CONTRIBUTING.md)）。

---

## 總覽

| 模組 | 端點數 | 基礎路徑 | 說明 |
|------|--------|----------|------|
| 系統 | 3 | `/health`, `/api/v1/ping` | 健康檢查（GET/POST）與 ping |
| 單實例守衛 | 1 | `/api/v1/instance-guard` | 守衛全貌快照（admin；每次呼叫留一筆讀取審計，介面不輪詢；粗狀態另隨 `/api/v1/seal/status` 出） |
| 認證 / MFA | 12 | `/api/v1/auth`, `/api/v1/users` | 登入（本地/LDAP）、MFA 兩階段、強制註冊、自助改密、會話刷新、管理員救援 |
| OIDC 登入 | 4 | `/api/v1/auth/methods`, `/api/v1/auth/oidc` | 登入方法清單（公開）、SSO 發起／IdP 回呼／交棒憑證兌換 |
| OIDC provider | 4 | `/api/v1/oidc-providers` | 身分提供者 CRUD（admin；secret write-only，身分域建後不可變） |
| LDAP 目錄 | 4 | `/api/v1/ldap-directory` | 目錄設定 singleton 資源＋連線測試（admin；bind 密碼 write-only，設定自 env 遷入 DB） |
| 安全政策 | 2 | `/api/v1/security-policies` | PCI 安全政策查詢/批次更新（admin） |
| 金鑰管理 | 4 | `/api/v1/keys` | 金鑰清冊/DEK 輪替/KEK 重包/退役材料清理（admin） |
| 資產 | 17 | `/api/v1/assets` | CRUD、連線測試、K8s pod 列表與檔案進出、標籤清單與治理、資產帳號 CRUD＋設預設 |
| Host Key | 2 | `/api/v1/assets/:id/host-key` | TOFU host key 檢視/重置 |
| 檔案管理（SFTP） | 5 | `/api/v1/assets/:id/files` | SSH 資產檔案列表/上下傳/建目錄/刪除 |
| 資產節點 | 6 | `/api/v1/asset-groups` | 節點樹 CRUD＋樹導覽＋搬移 |
| Session | 5 | `/api/v1/sessions` | 列表/詳情/活動/統計/終止（`session:view`＝admin/auditor） |
| 自助連線 | 2 | `/api/v1/my/connections`（列表＋`:id/terminate` 自助終止） | 一般 user 自己的連線精簡紀錄與自助終止（僅需登入） |
| 指令審計 | 2 | `/api/v1/sessions`, `/api/v1/commands` | 單會話指令流、跨會話搜尋 |
| 剪貼簿審計 | 2 | `/api/v1/sessions/:id/clipboard-events` | RDP/VNC 剪貼簿留存事實列表＋單筆內容解密調閱（逐筆留痕） |
| 會話分享 | 3 | `/api/v1/sessions` | 建立/撤銷分享、分享觀看（WS） |
| 監看 / 會話指標 | 2 | `/api/v1/sessions`, `/api/v1/ssh` | 即時監看（WS）、目標主機指標 |
| 連線 | 3 | `/api/v1/connect`, `/api/v1/ssh`, `/api/v1/connect-tokens` | 圖形/文字終端 WS、一次性連線 token（傳輸政策閘：strict 400／warn 428） |
| 傳輸同意 | 1 | `/api/v1/transmission-consents` | 傳輸風險同意立據（warn 檔連線前） |
| 通道清冊 | 2 | `/api/v1/transmission-inventory` | 全通道加密狀態清冊＋匯出快照（admin，PCI Req 4） |
| 錄影 | 7 | `/api/v1/sessions`, `/api/v1/recordings` | 元數據/下載/串流/rtoken/刪除/統計 |
| 離機儲存 | 11 | `/api/v1/offsite-storage` | 設定（讀/寫/世代切換確認/停止離機/歷史世代/撤銷憑證）＋狀態、失敗清單、測試連線、批次與單筆重試（全數 admin；憑證 write-only） |
| 用戶 | 12 | `/api/v1/users` | CRUD + 角色/狀態/密碼 + 解鎖/閒置停用豁免 + 本地管理員計數 + 允許來源網段判定 |
| 角色 | 1 | `/api/v1/roles` | 角色列表 |
| 使用者群組 | 6 | `/api/v1/user-groups` | 群組 CRUD＋成員維護（授權主體，admin） |
| 授權 | 7 | `/api/v1/authorizations` | 資產/節點授權（主體 user/群組二擇一）＋多主體批量＋有效權限雙視角＋帳號範圍更新 |
| 連線申請 | 15 | `/api/v1/access-requests` | 三段存取政策申請核准流＋破窗/撤銷/補審：申請/破窗/撤回/我的單＋審核/撤銷/補審端點 |
| 審核範圍 | 3 | `/api/v1/approver-scopes` | approver 審核範圍維護（admin，客體四維恰一：資產/節點/申請人/使用者群組） |
| 審計日誌 | 3 | `/api/v1/audit-logs` | 日誌查詢（依功能開關註冊） |
| 稽核工作台 | 2 | `/api/v1/audit/timeline`, `/api/v1/audit/subjects` | 六類審計資料的聚合時間軸＋樞紐候選（人／資產／來源位址；`audit:view`，唯讀） |
| 稽核匯出 | 4 | `/api/v1/audit-export` | 事件報告同步匯出＋證據包非同步 job（發起/清單/下載）（PCI 10.5.1） |
| 存取複審 | 4 | `/api/v1/access-reviews` | 存取矩陣/複審歷史/單筆快照/簽核（PCI 7.2.4；全端點無條件守門） |
| 告警規則 | 4 | `/api/v1/alert-rules` | 危險指令規則 CRUD |
| 告警查詢 / 審閱 | 2 | `/api/v1/command-alerts` | 告警記錄查詢 + 審閱處置（PCI 10.4.1） |
| 通知通道 | 5 | `/api/v1/notification-channels` | webhook 通道 CRUD + 測試 |
| 命令片段 | 4 | `/api/v1/snippets` | user-scoped 片段 CRUD |
| 改密 | 9 | `/api/v1/change-secret-plans`、`/api/v1/change-secret-candidates` | 計劃 CRUD、手動觸發、執行記錄；未驗證憑證清單／重試／清除 |
| 營運指標 | 1 | `/metrics` | Prometheus 曝光格式（刻意不在 `/api` 之下，故預設不被 edge 代理） |

**總計**: 164 端點（含 4 個 WebSocket 端點）。此數為上表各模組的人工加總，口徑是
「語義端點」；下方索引則是 gin 實際註冊的路由條目數，同一路徑的不同方法各計一條，
故兩者不相等屬正常。**以索引為準**。

### 端點索引（機器生成，勿手改）

下表由 `registerRoutes` 的實際註冊結果生成，並由 `TestAPIIndex` 守衛雙向相等：
索引缺少任一實際路由會失敗，索引含有不存在的路由亦會失敗。

`註冊條件` 為枚舉：`always` 表無條件註冊，其餘值為控制該路由是否註冊的環境變數名。
路徑採 gin 形式（`:id` 為路徑參數）。新增條件註冊機制時須同步擴充枚舉值域。

重新生成（**不可手改本區塊**）：

```bash
docker compose run --rm --no-deps -v ./docs:/app/cmd/server/testdata/docs-rw backend \
  go test ./cmd/server -run '^TestAPIIndex$' -update
```

一般測試容器只有唯讀的 `docs/` 掛載，故守衛無法竄改其驗證對象——重新生成須用上述
額外加掛可寫點的一次性容器。

<!-- BEGIN API-INDEX -->
| 方法 | 路徑 | 註冊條件 |
|---|---|---|
| POST | `/api/v1/access-requests` | always |
| POST | `/api/v1/access-requests/:id/approve` | always |
| POST | `/api/v1/access-requests/:id/cancel` | always |
| POST | `/api/v1/access-requests/:id/reject` | always |
| POST | `/api/v1/access-requests/:id/review` | always |
| POST | `/api/v1/access-requests/:id/revoke` | always |
| POST | `/api/v1/access-requests/break-glass` | always |
| GET | `/api/v1/access-requests/history` | always |
| GET | `/api/v1/access-requests/mine` | always |
| GET | `/api/v1/access-requests/mine/tickets` | always |
| GET | `/api/v1/access-requests/pending` | always |
| GET | `/api/v1/access-requests/pending/count` | always |
| GET | `/api/v1/access-requests/reviews/pending` | always |
| GET | `/api/v1/access-requests/tickets` | always |
| GET | `/api/v1/access-reviews` | always |
| POST | `/api/v1/access-reviews` | always |
| GET | `/api/v1/access-reviews/:id` | always |
| GET | `/api/v1/access-reviews/matrix` | always |
| GET | `/api/v1/alert-rules` | always |
| POST | `/api/v1/alert-rules` | always |
| DELETE | `/api/v1/alert-rules/:id` | always |
| PUT | `/api/v1/alert-rules/:id` | always |
| GET | `/api/v1/approver-scopes` | always |
| POST | `/api/v1/approver-scopes` | always |
| DELETE | `/api/v1/approver-scopes/:id` | always |
| GET | `/api/v1/asset-groups` | always |
| POST | `/api/v1/asset-groups` | always |
| DELETE | `/api/v1/asset-groups/:id` | always |
| PUT | `/api/v1/asset-groups/:id` | always |
| PUT | `/api/v1/asset-groups/:id/move` | always |
| GET | `/api/v1/asset-groups/tree` | always |
| GET | `/api/v1/assets` | always |
| POST | `/api/v1/assets` | always |
| DELETE | `/api/v1/assets/:id` | always |
| GET | `/api/v1/assets/:id` | always |
| PUT | `/api/v1/assets/:id` | always |
| GET | `/api/v1/assets/:id/accounts` | always |
| POST | `/api/v1/assets/:id/accounts` | always |
| DELETE | `/api/v1/assets/:id/accounts/:accountId` | always |
| PUT | `/api/v1/assets/:id/accounts/:accountId` | always |
| POST | `/api/v1/assets/:id/accounts/:accountId/set-default` | always |
| DELETE | `/api/v1/assets/:id/files` | always |
| GET | `/api/v1/assets/:id/files` | always |
| GET | `/api/v1/assets/:id/files/download` | always |
| POST | `/api/v1/assets/:id/files/mkdir` | always |
| POST | `/api/v1/assets/:id/files/upload` | always |
| DELETE | `/api/v1/assets/:id/host-key` | always |
| GET | `/api/v1/assets/:id/host-key` | always |
| GET | `/api/v1/assets/:id/k8s/download` | always |
| GET | `/api/v1/assets/:id/k8s/pods` | always |
| POST | `/api/v1/assets/:id/k8s/upload` | always |
| POST | `/api/v1/assets/:id/test-connection` | always |
| GET | `/api/v1/assets/:id/transfer-capabilities` | always |
| GET | `/api/v1/assets/tags` | always |
| POST | `/api/v1/assets/tags/delete` | always |
| POST | `/api/v1/assets/tags/rename` | always |
| GET | `/api/v1/audit-checkpoints` | always |
| GET | `/api/v1/audit-checkpoints/public-key` | always |
| GET | `/api/v1/audit-checkpoints/verify` | always |
| GET | `/api/v1/audit-export` | always |
| GET | `/api/v1/audit-export/jobs` | always |
| POST | `/api/v1/audit-export/jobs` | always |
| GET | `/api/v1/audit-export/jobs/:id/download` | always |
| GET | `/api/v1/audit-export/public-key` | always |
| GET | `/api/v1/audit-failures` | always |
| GET | `/api/v1/audit-integrity/verify` | always |
| GET | `/api/v1/audit-logs` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit-logs/:id` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit-logs/resource/:resource/:id` | FEATURE_AUDIT_LOG_ENABLED |
| GET | `/api/v1/audit/subjects` | always |
| GET | `/api/v1/audit/timeline` | always |
| POST | `/api/v1/auth/change-password` | always |
| POST | `/api/v1/auth/login` | always |
| POST | `/api/v1/auth/logout` | always |
| GET | `/api/v1/auth/me` | always |
| PATCH | `/api/v1/auth/me` | always |
| GET | `/api/v1/auth/methods` | always |
| POST | `/api/v1/auth/mfa/disable` | always |
| POST | `/api/v1/auth/mfa/enable` | always |
| POST | `/api/v1/auth/mfa/enroll/confirm` | always |
| POST | `/api/v1/auth/mfa/enroll/setup` | always |
| POST | `/api/v1/auth/mfa/setup` | always |
| POST | `/api/v1/auth/mfa/verify` | always |
| GET | `/api/v1/auth/oidc/:id/begin` | always |
| GET | `/api/v1/auth/oidc/callback` | always |
| POST | `/api/v1/auth/oidc/exchange` | always |
| POST | `/api/v1/auth/refresh` | always |
| GET | `/api/v1/authorizations` | always |
| POST | `/api/v1/authorizations` | always |
| DELETE | `/api/v1/authorizations/:id` | always |
| PUT | `/api/v1/authorizations/:id/accounts` | always |
| POST | `/api/v1/authorizations/batch` | always |
| GET | `/api/v1/authorizations/effective-assets` | always |
| GET | `/api/v1/authorizations/effective-users` | always |
| GET | `/api/v1/change-secret-candidates` | always |
| DELETE | `/api/v1/change-secret-candidates/:id` | always |
| POST | `/api/v1/change-secret-candidates/:id/retry` | always |
| GET | `/api/v1/change-secret-plans` | always |
| POST | `/api/v1/change-secret-plans` | always |
| DELETE | `/api/v1/change-secret-plans/:id` | always |
| PUT | `/api/v1/change-secret-plans/:id` | always |
| GET | `/api/v1/change-secret-plans/:id/records` | always |
| POST | `/api/v1/change-secret-plans/:id/run` | always |
| GET | `/api/v1/command-alerts` | always |
| POST | `/api/v1/command-alerts/:id/review` | always |
| GET | `/api/v1/commands` | always |
| GET | `/api/v1/connect` | always |
| POST | `/api/v1/connect-tokens` | always |
| GET | `/api/v1/daily-reviews` | always |
| POST | `/api/v1/daily-reviews` | always |
| GET | `/api/v1/daily-reviews/status` | always |
| GET | `/api/v1/instance-guard` | always |
| GET | `/api/v1/keys` | always |
| DELETE | `/api/v1/keys/retired-material` | always |
| DELETE | `/api/v1/keys/rewrap` | always |
| POST | `/api/v1/keys/rewrap` | always |
| POST | `/api/v1/keys/rotate` | always |
| DELETE | `/api/v1/ldap-directory` | always |
| GET | `/api/v1/ldap-directory` | always |
| PUT | `/api/v1/ldap-directory` | always |
| POST | `/api/v1/ldap-directory/test` | always |
| GET | `/api/v1/my/connections` | always |
| POST | `/api/v1/my/connections/:id/terminate` | always |
| GET | `/api/v1/notification-channels` | always |
| POST | `/api/v1/notification-channels` | always |
| DELETE | `/api/v1/notification-channels/:id` | always |
| PUT | `/api/v1/notification-channels/:id` | always |
| POST | `/api/v1/notification-channels/:id/test` | always |
| GET | `/api/v1/offsite-storage/failures` | always |
| POST | `/api/v1/offsite-storage/objects/:id/retry` | always |
| GET | `/api/v1/offsite-storage/profiles` | always |
| POST | `/api/v1/offsite-storage/profiles/:id/revoke-credentials` | always |
| POST | `/api/v1/offsite-storage/retry-failed` | always |
| GET | `/api/v1/offsite-storage/settings` | always |
| PUT | `/api/v1/offsite-storage/settings` | always |
| POST | `/api/v1/offsite-storage/settings/confirm` | always |
| POST | `/api/v1/offsite-storage/settings/disable` | always |
| GET | `/api/v1/offsite-storage/status` | always |
| POST | `/api/v1/offsite-storage/test` | always |
| GET | `/api/v1/oidc-providers` | always |
| POST | `/api/v1/oidc-providers` | always |
| DELETE | `/api/v1/oidc-providers/:id` | always |
| PUT | `/api/v1/oidc-providers/:id` | always |
| GET | `/api/v1/ping` | always |
| GET | `/api/v1/recordings/stats` | always |
| GET | `/api/v1/recordings/stream` | always |
| GET | `/api/v1/roles` | always |
| GET | `/api/v1/seal/status` | always |
| POST | `/api/v1/seal/unseal` | always |
| GET | `/api/v1/security-policies` | always |
| PUT | `/api/v1/security-policies` | always |
| GET | `/api/v1/sessions` | always |
| GET | `/api/v1/sessions/:id` | always |
| GET | `/api/v1/sessions/:id/clipboard-events` | always |
| GET | `/api/v1/sessions/:id/clipboard-events/:eventID/content` | always |
| GET | `/api/v1/sessions/:id/commands` | always |
| GET | `/api/v1/sessions/:id/monitor` | always |
| DELETE | `/api/v1/sessions/:id/recording` | always |
| GET | `/api/v1/sessions/:id/recording` | always |
| GET | `/api/v1/sessions/:id/recording/download` | always |
| GET | `/api/v1/sessions/:id/recording/stream` | always |
| POST | `/api/v1/sessions/:id/recording/token` | always |
| DELETE | `/api/v1/sessions/:id/share` | always |
| POST | `/api/v1/sessions/:id/share` | always |
| POST | `/api/v1/sessions/:id/terminate` | always |
| GET | `/api/v1/sessions/active` | always |
| GET | `/api/v1/sessions/share/:code/ws` | always |
| GET | `/api/v1/sessions/statistics` | always |
| GET | `/api/v1/snippets` | always |
| POST | `/api/v1/snippets` | always |
| DELETE | `/api/v1/snippets/:id` | always |
| PUT | `/api/v1/snippets/:id` | always |
| GET | `/api/v1/ssh` | always |
| GET | `/api/v1/ssh/sessions/:id/stats` | always |
| GET | `/api/v1/syslog-settings` | always |
| PUT | `/api/v1/syslog-settings` | always |
| POST | `/api/v1/syslog-settings/test` | always |
| POST | `/api/v1/transmission-consents` | always |
| GET | `/api/v1/transmission-inventory` | always |
| POST | `/api/v1/transmission-inventory/export` | always |
| GET | `/api/v1/user-groups` | always |
| POST | `/api/v1/user-groups` | always |
| DELETE | `/api/v1/user-groups/:id` | always |
| PUT | `/api/v1/user-groups/:id` | always |
| GET | `/api/v1/user-groups/:id/authorization-count` | always |
| PUT | `/api/v1/user-groups/:id/members` | always |
| GET | `/api/v1/users` | always |
| POST | `/api/v1/users` | always |
| DELETE | `/api/v1/users/:id` | always |
| GET | `/api/v1/users/:id` | always |
| PUT | `/api/v1/users/:id` | always |
| GET | `/api/v1/users/:id/external-identities` | always |
| POST | `/api/v1/users/:id/external-identities` | always |
| DELETE | `/api/v1/users/:id/external-identities/:identityId` | always |
| POST | `/api/v1/users/:id/external-identities/:identityId/unbind-and-disable` | always |
| POST | `/api/v1/users/:id/external-only` | always |
| PUT | `/api/v1/users/:id/inactivity-exempt` | always |
| POST | `/api/v1/users/:id/mfa/disable` | always |
| PUT | `/api/v1/users/:id/password` | always |
| PUT | `/api/v1/users/:id/roles` | always |
| POST | `/api/v1/users/:id/roles/:role` | always |
| PUT | `/api/v1/users/:id/status` | always |
| POST | `/api/v1/users/:id/unlock` | always |
| GET | `/api/v1/users/local-admin-count` | always |
| POST | `/api/v1/users/source-policy/check` | always |
| GET | `/health` | always |
| POST | `/health` | always |
| GET | `/healthz` | always |
| GET | `/metrics` | always |
<!-- END API-INDEX -->

---

## 認證機制

### JWT Token

- **Header**: `Authorization: Bearer <token>`
- **WebSocket**: 資產連線端點（`/ssh`、`/connect`）僅收一次性 `connect_token`（query-JWT
  直連已收口：繞過簽發閘＝繞過傳輸政策）；監看/分享等
  輔助 WS 端點仍以 `?token=<jwt>` 認證
- **有效期**: 15 分鐘（access token 固定短效；它是撤銷後殘餘存活上限，
  不進政策頁、不隨閒置政策放寬。會話續命走 `POST /auth/refresh` 輪替，不再發 24h 長效 token）
- **Claims**: `user_id`, `username`, `email`, `role`, `scope`（空值＝正式 session token；
  `mfa_pending`＝MFA 過渡 token；`mfa_enrollment`＝MFA 強制註冊過渡 token；`password_change`＝強制改密過渡 token）

### 短時效 token（取代 URL 中的長效 JWT）

| Token | 簽發端點 | TTL | 特性 |
|-------|---------|-----|------|
| `connect_token` | `POST /api/v1/connect-tokens` | 60 秒 | 一次性（Resolve 即焚），綁定 user+asset+account（`account_id` 選填，0＝預設帳號），簽發時已完成授權與帳號客體綁定檢查 |
| `rtoken`（錄影） | `POST /api/v1/sessions/:id/recording/token` | 120 秒 | TTL 內可重用（HTTP Range 多次 fetch），僅授權讀取指定 session 錄影 |
| `pending_token`（MFA） | `POST /api/v1/auth/login`（第一階段） | 5 分鐘 | scope `mfa_pending`；僅可用於 `POST /auth/mfa/verify` |
| `enrollment_token`（MFA 強制註冊） | `POST /api/v1/auth/login` | 15 分鐘 | scope `mfa_enrollment`；僅可用於 `POST /auth/mfa/enroll/setup`、`/confirm` |
| `change_token`（強制改密） | `POST /api/v1/auth/login`（或 MFA/註冊完成後） | 15 分鐘 | scope `password_change`；僅可用於 `POST /auth/change-password` |

**refresh_token（Web 會話刷新憑證）**：不透明 256-bit 隨機字串（非 JWT），
DB 僅存 SHA-256。**瀏覽器端的唯一載體是 `HttpOnly` cookie `custodexa_refresh`**——
回應 body 一律不含此憑證明文，前端讀不到也就無法寫入 localStorage。cookie 屬性：
`HttpOnly`、`SameSite=Strict`、`Path=/api/v1/auth/`（同時涵蓋刷新與登出）、
效期對齊憑證絕對壽命（輪替時取剩餘壽命，不因輪替延長）、`Secure` 由安全政策
`refresh_cookie_secure` 決定（發放時現讀，管理端調整即生效不需重啟；初值於首次啟動
自部署組態播種，詳見下方「政策鍵值域」）。
刷新時輪替（舊憑證即刻作廢），已輪替憑證再被提交視為洩漏訊號 → 撤銷該使用者全部
refresh（家族撤銷，RFC 9700）。壽命受安全政策控制：sliding 閒置窗（`web_idle_minutes`）
＋絕對壽命（`web_max_session_hours`）。詳見 `POST /auth/refresh`。

### 權限層級（RBAC）

| 角色 | 說明 | 權限 |
|------|------|------|
| `admin` | 管理員 | 全部權限 |
| `user` | 一般用戶 | `asset:view`（連線受資產授權限制；自己的連線紀錄走 `GET /my/connections`。session/audit/alert 檢視收斂為稽核職能，不授予） |
| `auditor` | 審計員 | `asset:view`, `session:view`, `audit:view`, `alert:view`, `alert:manage` |

多角色帳號的有效角色（JWT `role`）優先序為 `admin > auditor > user`（與前端路由守衛一致）。

細粒度權限檢查（`RequirePermission`）**無條件掛載**——權限檢查沒有開關，於所有模式生效；
關閉時對應端點僅需登入。標註「admin only」的端點使用 `RequireRole("admin")`，不受此開關影響。
**例外**：session 敏感讀取端點——列表 `GET /sessions`、詳情 `GET /sessions/:id`、活動 `/sessions/active`、統計 `/sessions/statistics`、per-session 指令 `GET /sessions/:id/commands`——無條件要求 `session:view`，不受此開關影響（安全敏感讀取無 debug 旁路；`POST /sessions/:id/terminate` 等寫入維持開關行為）。

---

## 統一回應格式

- **列表（分頁）**: `{"data": [...], "total": N, "page": 1, "page_size": 20}`
- **列表（不分頁）**: `{"data": [...], "total": N}`
- **錯誤封套**: `{"error": "使用者可讀繁中訊息", "code": "MACHINE_CODE", "params": {...}}`（內部錯誤細節僅留伺服器日誌，不外洩）
- **操作成功**: 直接回傳資源 JSON 或動作結果欄（如 `{"success": true, "status_code": 200}`）；**不帶 `message` 文案欄**——成功文案由前端 `$t` 自有

### 錯誤封套與 i18n

使用者可見的 HTTP 錯誤**一律**採機器可讀 code + 前端查譯，無例外軌：

- **`error`**（必）：繁中訊息，由該 code 的 `ZhFallback`（以 `params` 插值後）渲染，作為 wire fallback；後端不再有獨立的錯誤文字字面量。
- **`code`**（必）：穩定機器識別字，grammar `^[A-Z][A-Z0-9_]{0,63}$`，分域 `AUTH_*`/`VALIDATION_*`/`NOTFOUND_*`/`CONFLICT_*`/`INTERNAL_*`/`RULE_<DOMAIN>_*`。前端以 code 查 `apiError.*` 三語譯文顯示；一經發布不得改義或重用。**grammar 無例外**：全部錯誤碼皆符合上述分域與大寫格式，不存在小寫或未分域的例外碼。
- **`params`**（可選）：插值受控值（語義 ID 如 `{"resource":"asset"}`、數值，或宣告為 opaque 的自由字串），前端經 enum 查譯後插值；opaque 值原樣傳遞不翻譯且經淨化（限長、去換行/ANSI/控制字元）。參數不合契約時整組丟棄（不外洩），僅記伺服端日誌。
- **前端降級**：`code` 有當前語言譯文 → 顯示譯文；否則顯示 `error`；再否則通用語（三層降級，永不空白/裸 key）。
- **非文字 metadata（Meta 平鋪）**：`required_permission`、`kind`、`risks`、`reason`、`policy`、`channel`、`level` 等結構化欄與 `error`/`code`/`params` **平鋪同層**共存——它們是前端控制流分支依據（如 connect 流程依 `reason` 決定彈框）而非文案，故不碼化、不進偵測鍵；保留欄名與值域不變。Meta 不得覆寫 `error`/`code`/`params` 三個保留欄（衝突時丟棄並記 log）。
- 範例：`{"error":"無效的資產 ID","code":"VALIDATION_INVALID_ID","params":{"resource":"asset"}}` → en 顯 "Invalid Asset ID"、ja 顯「無効なアセット ID です」。
- 外部/CLI client 只需自行以 `code` 查譯；繁中 `error` 非多語 API。

**單一出口，無例外軌**：

- 後端 HTTP 錯誤的唯一合法出口為 `apierror.Respond` / `apierror.RespondInternal` / `apierror.Write`
  （帶 `code` 的結構化寫出）。**不存在不帶 `code` 的錯誤回應路徑**，WS 與串流出口亦然。
- 錯誤碼 registry 與三語譯文為雙向完備：每個碼都有三語譯文，每則譯文都對應一個在用的碼。

**HTTP 狀態碼**:
| 狀態碼 | 說明 |
|--------|------|
| 400 | 請求格式/參數錯誤 |
| 401 | 未認證或 token 無效 |
| 403 | 權限不足 |
| 404 | 資源不存在 |
| 409 | 資源衝突（名稱重複、授權重複） |
| 202 | 已受理（異步批次，如改密觸發） |
| 502 | 上游/遠端失敗（SSH/K8s/DB 連線、webhook 投遞、SFTP 操作） |
| 500 | 伺服器內部錯誤 |

---

## 系統端點

### 健康檢查

```
GET /health
POST /health
```

POST 與 GET 同義（供告警通知 E2E 作為無認證、冪等的 webhook 測試收端）。

**回應** (200):
```json
{
  "status": "ok",
  "service": "custodexa-backend",
  "version": "1.0.1",
  "database": "connected",
  "oidc_dedicated_issuers_digest": "e3b0c44298fc"
}
```

`version` 直接輸出 `main.go` 的 `Version` 變數，該變數**由建置時注入**：正式版映像於
`docker/backend/Dockerfile` 以 `-ldflags -X main.Version=...` 帶入，值取自專案根 `VERSION` 檔
（單一事實源，與 `CHANGELOG.md` 的一致性由 `TestVersionFileMatchesChangelog` 釘住）。
未注入的建置（`go run`、`go test`）顯示 `dev`，開發容器顯示 `dev`。上例的值即當前發布版。
依安全政策只揭露版號，不揭露 commit hash 或建置時間。
`oidc_dedicated_issuers_digest` 為 `OIDC_DEDICATED_ISSUERS` 部署宣告的內容指紋
（正規化後 sha256 前 12 hex）：多副本部署時外部監控比對各副本
此值即可偵測設定分歧；輸出指紋而非原文，不洩漏宣告內容。未設宣告時為空集合的固定指紋。

### API Ping

```
GET /api/v1/ping
```

**回應** (200): `{"status": "ok"}`（原 `{"message": "pong"}`，移除 `message` 文案欄）

### 封印狀態與解封（`KEK_PROVIDER=ui` 為主要場景）

兩段啟動下，段 1 只開放健康檢查與下列兩條路徑；**其餘全部路由於封印期一律回
503＋`SEAL_SERVICE_SEALED`**（不是 500、不是 401——狀態必須可被外部監控正確辨識），
未匹配的路徑亦同（封印期不對外透露路由是否存在）。A／C 模式恆為 `unsealed`，
兩條路徑照常註冊：狀態查詢是有效的運維面，解封端點則一律回 409 且不重跑任何初始化。

```
GET  /api/v1/seal/status
POST /api/v1/seal/unseal
```

兩者**皆不要求 JWT**。要求 JWT 會在「管理員已啟用 MFA」時死鎖——TOTP secret 是
信封加密欄，封印期解不開，管理員無法登入來解封。一般解封的授權由「知道 KEK」
承擔（能解開現行代表列即最強授權證明）；**空金鑰表的初始化解封沒有這個證明，
故另行要求初始管理員憑證**。

**`GET /seal/status` 回應** (200)：

| 欄位 | 說明 |
|---|---|
| `state` | `sealed` / `unsealing` / `unsealed` / `sealed-faulted` |
| `generation` | 世代號（每次取得解封持有權 +1） |
| `fault_code` | 僅 `sealed-faulted` 時出現，為失敗機器碼 |
| `cooldown_until` | 全域冷卻到期時間（RFC3339）；冷卻期滿自動恢復，**不需重啟行程** |
| `cleanup_pending` / `cleanup_generation` / `cleanup_reason` / `cleanup_started_at` | 前代持有者待收束狀態 |
| `journal_faulted` | 封印期留痕 I/O 故障（fail-close 拒收新嘗試，修復後自動恢復） |
| `timeout_total` | 段 2 逾時次數（逾時另計，不入材料失敗計數） |
| `timeout_retry_hint_code` | 發生過逾時時出現，值為 `SEAL_STAGE2_TIMEOUT`：**初始化可能已完成，請以第一次輸入的材料重試，切勿改用新材料** |
| `initialization_required` | 金鑰表為空（走初始化解封路徑）；判定失敗時回 500 而非以 `false` 頂替 |
| `trusted_proxy` / `source_restricted` / `bind_addr` | 可信代理、來源網段限制與獨立監聽位址的組態現況 |
| `instance_guard` | 單實例守衛的粗狀態 `{state, since, reason, peers}`：`state` 為 `held`／`overridden`／`lost`（關閉中短暫為 `stopping`／`released`）、`since` 狀態起始時間（RFC3339）、`reason` 為 `""`／`ack_startup`／`contention`／`db_unreachable`／`permanent`／`unknown`、`peers` 偵測到的其他守衛版實例連線數。**不含識別資訊**（無持鎖者指紋、確認碼、主機名、pid）；供管理介面橫幅每 60 秒輪詢，本端點不寫審計列。全貌走 `GET /api/v1/instance-guard`（下段） |

**`POST /seal/unseal` 請求體**：

```json
{
  "kek": "<32 字元 KEK 材料>",
  "kek_confirm": "<僅初始化解封：paste-back 二次輸入>",
  "confirm_saved": true,
  "username": "<僅初始化解封：初始管理員帳號>",
  "password": "<僅初始化解封：初始管理員密碼>"
}
```

- **一般解封**（金鑰表非空）只需 `kek`，**不驗格式**（既有部署的 KEK 可能早於格式規則），
  唯一判準是「以該材料解包現行代表列全數成功」。
- **初始化解封**（金鑰表為空）另要求 paste-back 二次輸入、保存確認、初始管理員憑證，
  並過完整格式驗證（長度 32、字元集、非出廠預設值）。`confirm_saved` 為 UX 意圖聲明、
  **不具授權力**；伺服端唯一信任的機械不變式是 `kek_confirm` 的逐字比對。
  憑證驗證走段 1 簡化路徑，**不套用安全政策的帳號鎖定**（該服務於段 2 才建構），
  其防爆破由下列退避／冷卻承擔；且**不豁免 `must_change_password`**。

**回應**：成功 200 `{"state":"unsealed","generation":N}`。失敗一律走機器碼信封，
且**失敗回應的內容不可區分**（格式錯、材料錯、paste-back 不符、憑證錯皆為
`SEAL_MATERIAL_INVALID`）；timing 差異不在承諾範圍內。

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `SEAL_MATERIAL_INVALID` | 400 | 材料類失敗（唯一出口，計入退避） |
| `SEAL_ABORTED` | 400 | 驗證前即中止，未取得任何判定（不計入退避） |
| `SEAL_UNSEAL_IN_PROGRESS` | 409 | 已有解封在飛（single-flight） |
| `SEAL_CLEANUP_PENDING` | 409 | 前代持有者待收束 |
| `SEAL_ALREADY_UNSEALED` | 409 | 已解封，且不重跑初始化 |
| `SEAL_SOURCE_NOT_ALLOWED` | 403 | 來源不在 `SEAL_UNSEAL_ALLOWED_CIDRS` 內 |
| `SEAL_BACKOFF_ACTIVE` / `SEAL_COOLDOWN_ACTIVE` | 429 | per-來源退避／全域冷卻期內 |
| `SEAL_INIT_FAILED` | 500 | 材料正確但段 2 初始化失敗（狀態轉 `sealed-faulted`，**行程續存、可重試**） |
| `SEAL_PUBLISH_UNCONFIRMED` | 500 | 段 2 完成但服務從未發佈（不鎖死，重試產生新世代） |
| `SEAL_STAGE2_TIMEOUT` | 504 | 段 2 逾時（不計入材料失敗計數） |
| `SEAL_JOURNAL_IO_FAILURE` | 503 | 封印期留痕寫入故障，fail-close 拒收新嘗試 |

**抗鎖死**：無任何需重啟行程才能解除的鎖定態。退避成長有封頂、冷卻有明確到期時間，
冷卻期間抵達的嘗試被直接拒絕且**不計入失敗、不延長冷卻**。未設定 `TRUSTED_PROXIES`
時 per-IP 退避**保守降級為全域退避**——無可信代理鏈約定時限速鍵可被轉送標頭污染，
寧可影響可用性也不提供可繞過的假防線。部署方 SHOULD 另以 `SEAL_UNSEAL_BIND_ADDR`
／`SEAL_UNSEAL_ALLOWED_CIDRS` 把解封端點收進管理網段：未認證端點上，任何速率手段
都無法保證管理員可用性。

**遺失語義**：B 模式的 KEK 遺失＝全部信封密文永久不可解，**產品不提供任何 recovery**。

### 單實例守衛快照（管理者限定）

```
GET /api/v1/instance-guard
```

**認證**: JWT ＋ `admin` 角色（`RequireRole("admin")`）；未登入 401、非 admin 403。

單實例守衛在段 1 以 postgres session 級 advisory lock 保證「第二個應用實例不會在操作者不知情下運作」：
第二實例啟動即被攔下並印出持鎖者指紋與確認碼，以 `INSTANCE_GUARD_ACK` 確認後可啟動但留審計事件；
執行期失鎖只告知不退出。守衛防的是不知情，不是不發生——確認後的並存不由守衛阻擋。營運面判讀見
`docs/ops/upgrade-sop.md` §2.6b／§3.4。

本端點回守衛的**完整快照**，含持鎖者指紋與本實例識別。管理介面只在橫幅出現時取一次
（與管理者手動重新整理），**不輪詢**；粗狀態的輪詢走 `GET /api/v1/seal/status` 的 `instance_guard` 欄
（不含識別資訊、不寫審計列）。**本端點每次呼叫經審計中介層留一筆讀取列**（資源 `instance_guard`）：
「哪個管理者何時看了衝突細節」本身是留痕。唯讀、無副作用。

**回應** (200):
```json
{
  "state": "overridden",
  "since": "2026-08-25T10:05:58Z",
  "reason": "ack_startup",
  "instance": {"hostname": "bb34e4ff1892", "pid": 1, "started_at": "2026-08-25T10:05:50Z"},
  "db_session_pid": 8744,
  "holder": {
    "application_name": "custodexa-instance-guard",
    "pid": 8510,
    "backend_start": "2026-08-25T10:04:22.2442Z",
    "code": "55bd875b8d97",
    "fingerprint_source": "pg_stat_activity"
  },
  "ack": "55bd875b8d97",
  "lost_total": 0,
  "peers": 0
}
```

| 欄位 | 說明 |
|---|---|
| `state` | `held`（持鎖）／`overridden`（以確認碼啟動、尚未取得鎖）／`lost`（執行期失鎖，每週期重取中）；關閉中短暫為 `stopping`／`released` |
| `since` | 目前狀態的起始時間（RFC3339） |
| `reason` | 進入目前狀態的原因：`""`（held）／`ack_startup`／`contention`／`db_unreachable`／`permanent`／`unknown` |
| `instance` | 本實例識別：`hostname`（容器主機名）、`pid`（應用行程 id）、`started_at`（守衛**開始**取鎖的時刻；實際持鎖時刻是 `since`，兩者可差數秒） |
| `db_session_pid` | 本實例釘選連線在 postgres 內的 `pg_backend_pid()` |
| `holder` | 持鎖者指紋（`overridden` 與 `lost{contention}` 時有值，否則 `null`）：`application_name`／`pid`（postgres 工作階段 id）／`backend_start`；`code` 為三欄正規化字串 sha256 前 12 碼＝確認碼；`fingerprint_source` 為 `pg_stat_activity`，查不到持鎖者細節時為 `unavailable`（此時 `code` 為降級碼，不綁定特定工作階段） |
| `ack` | 本行程環境中的 `INSTANCE_GUARD_ACK` 值（去除前後空白），未設時為空字串。只有 `state=overridden` 代表它被用上；`state=held` 時它是留在環境裡的惰性值（啟動日誌會提示移除） |
| `lost_total` | 本行程累計失鎖次數 |
| `peers` | 偵測到的其他守衛版實例連線數（同一資料庫、同 `application_name`，每個驗證週期更新） |

回應**不含**連線字串、密碼、主機位址、資料庫名、任何工作階段的 `client_addr`。守衛狀態是**行程本地的**：
多個實例並存時，每個實例回的是自己的快照。

---

## 認證 API

### 登入

```
POST /api/v1/auth/login
```

**請求**:
```json
{"username": "admin", "password": "admin123"}
```

登入為固定順序的 gate chain（登入狀態機）：
**來源限流 → 鎖定檢查 → 密碼/LDAP 驗證 → 帳號啟用檢查 → 允許來源網段判定 →
MFA 分流（驗證或強制註冊）→ 強制改密 → 發正式 token**。
（網段判定在 MFA 分岔**之前**：該分岔會發出正式會話或受限票證（enrollment／password_change），
清單外的來源連受限票證也不該拿到。）
回應依所處階段為多形態（互斥，僅其一）：

**來源限流**：本端點有 per-IP 速率上限，超出回
`429` ＋ `AUTH_LOGIN_RATE_LIMITED`。**回應不含剩餘額度、重試秒數或 `Retry-After`**
——那些數值會讓攻擊者把流量精確調到門檻之下持續消耗。限流與既有的帳號級鎖定
是兩層不同的防護：帳號鎖定擋對單一帳號的暴力破解，來源限流擋換帳號輪流試的
密碼噴灑（每個帳號各試少數次，永遠碰不到帳號門檻）。被擋下的請求以聚合形式入
審計（每個「來源×時間窗」一筆帶計數），不逐筆寫入。

**帳號啟用檢查在密碼驗證之後**：帳號不存在、密碼錯誤、帳號存在但已停用且密碼
錯誤——三者回應**完全相同**（`401` ＋ `AUTH_INVALID_CREDENTIALS`），使未認證者
無法藉回應差異枚舉帳號是否存在。憑證正確而帳號已停用者才回 `403` ＋
`AUTH_USER_INACTIVE`（此時請求者已證明持有該帳號憑證，告知不構成洩漏）。

**允許來源網段判定也在憑證驗證之後**，且位於「發正式會話／發受限票證」的分岔之前，
故一次涵蓋正式會話、強制註冊票證與強制改密票證三條出口。不落使用者
`allowed_cidrs` 者回 `403` ＋ `AUTH_SOURCE_NOT_ALLOWED`。三點須注意：
- **MFA 第一階段（`mfa_required`）不判**：提前判會讓「密碼對但來源錯」在 pending 訊號
  之外多一個分岔，持有密碼但無第二因素者因此得以探知來源政策。判定移到多因素完成那一點。
- **回應不含來源位址值，也不含清單內容**——只說「此來源不允許」。位址與命中的清單快照
  只進審計（登入審計列的 `error_msg`／`details`）。
- 此類拒絕**不計入**失敗登入次數（憑證是對的），但仍受來源限流覆蓋；審計 status 為 `denied`。

**回應** (200，全數通過，發正式會話):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "full_name": "Administrator",
    "active": true,
    "roles": ["admin"],
    "totp_enabled": false
  }
}
```

（Web 會話刷新憑證隨此回應以 `Set-Cookie: custodexa_refresh=...` 下發，不在 body 內。）

**回應** (200，MFA 用戶第一階段，需輸入 TOTP):
```json
{"mfa_required": true, "pending_token": "..."}
```

**回應** (200，受 MFA 強制但尚未註冊 TOTP，導向強制註冊):
```json
{"mfa_enrollment_required": true, "enrollment_token": "..."}
```

**回應** (200，認證全過但須先改密，PCI 8.3.5/2.2.2):
```json
{"password_change_required": true, "change_token": "...", "policy_hint": "密碼至少 12 字元，且須同時包含字母與數字",
 "password_change_reason": "policy_noncompliant", "reason_code": "RULE_USER_PASSWORD_TOO_SHORT", "reason_params": {"min": 12}}
```
（`policy_hint` 為改密表單提示文案，依現行密碼政策動態產生；政策頁 API 為 admin-only，
未登入的改密表單靠此欄取得規則。`password_change_reason` 為觸發原因：
`must_change`＝首登/管理員重設、`policy_noncompliant`＝登入時偵測現行密碼不符政策（附
`reason_code`/`reason_params` 供 i18n 插值，值域同 apierror 碼）、`password_expired`＝密碼逾
`password_max_age_days` 政策（NULL 改密時間戳視為已過期）。合規偵測同時落審計動作
`pw_noncompliant`（僅違規類別，無密碼材料）。MFA 用戶的偵測發生在第一階段，第二階段以
`must_change` 呈現）

**錯誤**: 401 認證失敗、403 帳號已停用（`AUTH_USER_INACTIVE`）或來源不在允許網段
（`AUTH_SOURCE_NOT_ALLOWED`）、423 帳號已鎖定（連續失敗達門檻，PCI 8.3.4；
訊息明示鎖定但不透露剩餘時間/次數）、500 內部錯誤（訊息泛化為「登入失敗」）。

登入失敗與成功均直接寫入審計日誌（登入前無用戶 context，全局中間件會跳過）；MFA/註冊/改密等
中繼階段亦以對應標註（`mfa_pending`/`mfa_enrollment_required`/`password_change_required`）留痕。
密碼失敗與 TOTP 失敗共用同一鎖定計數。

**LDAP 認證**（`LDAP_ENABLED=true` 時）:
- 同一登入端點與請求格式，無需前端改動
- 分流規則：本地（非 `is_ldap`）用戶走本地密碼驗證；`is_ldap` 用戶或本地查無的帳號走
  LDAP search-then-bind 驗證
- 首次 LDAP 登入成功自動建立影子用戶（`is_ldap=true`、預設 `user` 角色、無可用本地密碼）
- LDAP 用戶若啟用 MFA，照常走兩階段登入
- LDAP 用戶不可使用 `PUT /users/:id/password` 改密（回 400，密碼由目錄服務管理）
- 登入審計於 `error_msg` 欄位標註 `source=ldap`；本地登入維持既有輸出
- 環境變數：`LDAP_ENABLED` / `LDAP_URL` / `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` /
  `LDAP_BASE_DN` / `LDAP_USER_FILTER`（預設 `(uid=%s)`）/ `LDAP_ATTR_EMAIL`（預設 `mail`）/
  `LDAP_ATTR_FULLNAME`（預設 `cn`）/ `LDAP_SKIP_TLS_VERIFY`（僅測試環境）

### 登出

```
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

**請求**：無 body 欄位。Web 會話刷新憑證由瀏覽器以 `custodexa_refresh` cookie 自動附帶
（cookie 的 `Path` 涵蓋本端點）。

**回應** (200): `{"username": "admin"}`（`message` 文案欄已移除）。
回應一律帶清除性 `Set-Cookie`（即時到期），無論撤銷成敗。

access token 無狀態，登出由客戶端刪除、殘餘存活 ≤15 分；cookie 帶有憑證時後端一併撤銷
（reason=`logout`）。若提交的是已輪替憑證＝分叉/洩漏訊號，觸發家族撤銷並記高價值審計事件。
cookie 缺失不阻擋登出。登出事件由審計中間件記錄。

### 當前用戶

```
GET /api/v1/auth/me
Authorization: Bearer <token>
```

**回應** (200): `UserInfo`（同登入回應的 `user` 欄位，含 `totp_enabled`、`is_ldap`）。
含後端 resolve 的 `display_name`（`local_display_name || full_name || username`，單一事實源）
與自助顯示名原始值 `local_display_name`（可為 `null`＝未自訂）。

另含 `source_ip`（**可選欄，`omitempty`**）：**本人這次請求的來源位址**，
**僅供顯示**（允許來源網段表單的「你目前的來源」），**不參與任何判定**——
「這個清單會不會把我鎖在外面」一律問判定端點（見「用戶 API」的允許來源網段段），
前端自行以 CIDR 函式庫比對必與強制點分歧。取不到時整欄不出現；
登入回應共用同一個型別但不填此欄，故既有登入回應的欄位集逐字不變。

另含身分三分的兩欄：`external_credential`（憑證由外部提供者管理，
前端的自助改密與密碼到期提示一律依此欄泛化——**不可續用 `is_ldap`**，OIDC 影子帳號的
`is_ldap` 為 `false`）與 `provisioning_origin`（`local`／`ldap`／`oidc`，建立後不可變）。
兩者分離是刻意的：混合帳號（OIDC 供應但保有本地密碼）兩者不同值。

### 自助更新個人資料

```
PATCH /api/v1/auth/me
Authorization: Bearer <token>
```

自助更新個人資料。目前**僅放行 `local_display_name`**（自助顯示名）；正式身分
（`full_name`／`email`／`username`）維持唯讀（PAM 治理，未來由 IdP 權威同步）。
target 使用者一律取自 token claims，**不接受 path/body 指定他人**；端點重查帳號 active，
拒絕已停用/刪除帳號。

**請求**:
```json
{"local_display_name": "小王"}
```

- 空字串／`null`／全空白：trim 後寫回 `NULL`（清除顯示名，回退 `full_name`/`username`）。
- 驗證：長度上限 100（rune 計），拒控制字元/換行；違反回 `400`（`VALIDATION_DISPLAY_NAME`）。
- 其他欄位（`full_name`/`email`/`role`/`active`/`username`/`is_ldap`）一律忽略（僅 `local_display_name` 可寫）。
- **作用域收窄（安全紅線）**：`display_name` 僅用於裝飾/自我檢視場景（登入問候、側欄、Profile）；
  審計 actor、授權 subject、審核方、admin 使用者列表、session owner、會話監看一律 `username`。

**回應** (200): canonical `UserInfo`（含 resolve 後的 `display_name`）。
審計歸類為 `resource=user, resource_id=當前使用者ID`。

### 會話刷新（refresh）

```
POST /api/v1/auth/refresh
```

以 Web 會話刷新憑證換發新 access token 並輪替 refresh（公開端點：access 可能已過期）。

**請求**：無 body 欄位。憑證**僅**自 `custodexa_refresh` cookie 讀取，
不接受 request body 傳遞，亦無 body fallback。

**回應** (200): `{"token": "<新 access token>"}`；輪替後的新憑證以 `Set-Cookie` 下發，
`Max-Age` 取該憑證的剩餘絕對壽命。

- **rotation**：成功即輪替，舊 refresh 立刻作廢；新憑證由瀏覽器自動取代 cookie 內的舊值
- **reuse detection**：提交已輪替憑證 → 撤銷該使用者全部 refresh（家族撤銷，RFC 9700），記高價值審計
- **壽命**：sliding 閒置窗（`web_idle_minutes` 政策）＋絕對壽命（`web_max_session_hours` 政策，
  以登入時刻起算、rotation 不重置）
- **允許來源網段**：刷新亦判來源。判定在交易內、世代複查之後、撤舊之前，不落清單者
  **零寫入**（不撤舊、不插新、不動 `last_used_at`），該憑證隨後自允許來源刷新照常成功，
  也不觸發家族撤銷。對外回應與其他刷新失敗**逐字相同**（401 `AUTH_SESSION_EXPIRED`），
  不新增訊號；成因只進審計。前端沿既有「續期失敗導回登入頁」流，登入頁再以
  `AUTH_SOURCE_NOT_ALLOWED` 給出可行動的說明。**收緊清單後的殘窗＝access token 壽命**（15 分）
- **錯誤**：一律 401 同文案「會話已失效，請重新登入」（不洩漏憑證狀態，讓攻擊者無法區分猜錯與已失效）。
  **cookie 缺失走同一則失敗回應**（不是 400）——「未提供」與「無效／已撤銷」在回應上不可區分；
  失敗事件直記審計

### 自助改密（change-password）

```
POST /api/v1/auth/change-password
Authorization: Bearer <token>
```

修改自己的密碼。接受兩種 token：**正式 session token**（自願改密）或
**`password_change` scoped token**（強制改密流程）；其餘 scope 一律拒。userID 一律取自 token claims，
不接受路徑參數（防改他人密碼）。

**請求**:
```json
{"old_password": "目前密碼", "new_password": "新密碼"}
```

**回應** (200)：成功後直接換發正式會話（不重走登入），格式同登入成功回應
（`{token, user}`，新的 Web 會話刷新憑證以 `Set-Cookie` 下發）。

**錯誤**:
- 400 政策違規（長度/組成/歷史重用，回可讀訊息）或目前密碼不符或 LDAP 用戶（密碼由目錄服務管理）
- 401 未提供/無效 token，或 token scope 不可用於改密
- 404 用戶不存在
- 503 改密服務未啟用（`userService` 未注入時）

改密成功會撤銷該使用者全部 refresh 會話（reason=`password_change`，8.3.5 語義延伸）。
自助改密不經 AuthMiddleware，事件由 handler 直記審計（標註 `self_change_password`）。

### 多因素認證（MFA / TOTP）

啟用 MFA 的用戶登入為兩階段：`POST /auth/login` 驗證帳密通過後回傳
`{"mfa_required": true, "pending_token": "..."}`（pending token 有效 5 分鐘、
scope 限定 `mfa_pending`），再以 TOTP 驗證碼換取正式 JWT。

| 方法 | 路徑 | 說明 | 認證 |
|---|---|---|---|
| POST | `/auth/mfa/verify` | body: `{pending_token, code}` → `{token, user}`＋`Set-Cookie` 下發刷新憑證（若仍須改密則回 `password_change_required`） | 公開 |
| POST | `/auth/mfa/setup` | 產生 secret 與 otpauth URL：`{secret, otpauth_url}`（發行者 "Custodexa"；重做即覆蓋舊 secret）。POST 而非 GET：有寫入副作用（覆蓋 pending secret、重設 enabled） | JWT |
| POST | `/auth/mfa/enable` | body: `{code}`，驗證通過後啟用 | JWT |
| POST | `/auth/mfa/disable` | body: `{password}`，驗密後停用 | JWT |
| POST | `/auth/mfa/enroll/setup` | 強制註冊：以 `enrollment_token`（Bearer）產生 TOTP 設定 → `{secret, otpauth_url}`。已註冊者持 token 重放回 409（防改綁） | 公開（自帶 enrollment token） |
| POST | `/auth/mfa/enroll/confirm` | 強制註冊：body `{code}` ＋ `enrollment_token`（Bearer）完成綁定，直接換發正式會話；若仍須改密則回 `password_change_required`。綁定碼暴力達門檻回 423 | 公開（自帶 enrollment token） |
| POST | `/users/:id/mfa/disable` | 管理員救援停用（審計記入 admin 身分＋目標用戶 ID） | JWT + admin |

啟用 MFA 的用戶登入為兩階段：`POST /auth/login` 驗證帳密通過後回
`{"mfa_required": true, "pending_token": "..."}`（pending token 5 分鐘、scope `mfa_pending`），
再以 TOTP 驗證碼換取正式 JWT。受 MFA 強制但尚未註冊者則走 `enroll/setup`→`enroll/confirm` 流程。
TOTP 防重放（PCI 8.5.1）：驗證僅接受 step 大於最後消耗值，以 CAS 原子推進擋同碼跨 skew 窗重放。
所有 MFA 事件（驗證成功/失敗、啟用/停用、強制註冊、管理員救援）均直接記入審計日誌。

---

## OIDC 單一登入 API

多個 OIDC 身分提供者可並存，各自為獨立的 OAuth client；provider 設定存於資料庫，
部署層只決定三項環境變數（`PUBLIC_BASE_URL`／`OIDC_DEDICATED_ISSUERS`／`OIDC_ALLOWED_INTERNAL_HOSTS`，
見 [QUICKSTART.md](QUICKSTART.md) 與 `.env.example`）。

### 登入方法清單

```
GET /api/v1/auth/methods
```

未認證可讀（登入頁需在登入前取得 SSO 按鈕清單）。

**回應** (200):
```json
{"local": true, "oidc": [{"id": 1, "name": "公司 Entra ID"}, {"id": 2, "name": "Okta"}]}
```

只回識別與顯示所需欄位——**不含 issuer／client_id 等設定值**。
**停用者與設定不完整者皆不列出**（否則按鈕看得到、按下去必失敗）；
未設 `PUBLIC_BASE_URL` 時 `oidc` 恆為空陣列（fail-close）。
清單讀取失敗**不阻斷登入頁**：回 `{"local": true, "oidc": []}`，前端降級為只顯示本地表單。

### SSO 三段流程

```
GET  /api/v1/auth/oidc/:id/begin?binding=<sha256>&next=<相對路徑>
GET  /api/v1/auth/oidc/callback?state=...&code=...
POST /api/v1/auth/oidc/exchange
```

三者皆為**公開端點**（使用者尚未登入即需發起）。流程：

1. **begin**：前端產生隨機 browser secret 存 `sessionStorage`，只把其 SHA-256 以 `binding`
   查詢參數送出（**明文不離開瀏覽器**）。後端建立流程狀態（state／nonce／PKCE verifier／
   binding hash／redirect_next／簽發當下的 provider 世代）後 **302** 導向 IdP 的授權端點。
   `binding` 缺漏回 400。`next` 經白名單化：只接受同源相對路徑，scheme-relative（`//evil`）、
   絕對 URL、反斜線與多重編碼一律退回 `/`（防開放重導向）。
   redirect_uri 固定為 `${PUBLIC_BASE_URL}/api/v1/auth/oidc/callback`（不從請求 Host 推導）。

2. **callback**：IdP 導回。後端以 state **原子消費**流程狀態（僅在未過期時取用並失效），
   交換 code、完整驗證 id_token（簽章演算法白名單／`iss`／`aud`／`azp`／`exp`／`iat`／`nbf`／
   ±60 秒 clock skew／`nonce`／`sub` 非空與長度），求值准入規則，完成身分對應與（必要時）供應，
   最後產生一次性**交棒憑證**並以 **302 + URL fragment** 交給 SPA：

   ```
   302 Location: ${PUBLIC_BASE_URL}/login#sso_ticket=<ticket>
   Referrer-Policy: no-referrer
   Cache-Control: no-store
   ```

   用 fragment 而非 query：query 會完整送到反向代理與其 access log，fragment 不送伺服器。
   失敗一律導回 `${PUBLIC_BASE_URL}/login#sso_error=<slug>`，slug 值域為
   `oidc_provider_error`（IdP 端回報錯誤）／`oidc_flow_invalid`（state/code 缺漏、流程狀態
   無效或過期、驗證失敗——**成因刻意收斂，不洩漏 IdP 內部狀態**）／`oidc_admission_denied`／
   `oidc_username_conflict`／`oidc_provider_unavailable`。前端據 slug 顯示可行動訊息。

3. **exchange**：SPA 讀出 fragment 後立即 `history.replaceState` 抹除，再兌換正式登入回應。

   **請求**:
   ```json
   {"ticket": "<自 fragment 取得>", "browser_secret": "<sessionStorage 的明文>"}
   ```

   **回應** (200)：
   ```json
   {"login": { "...與 POST /auth/login 完全同形（含 mfa_required／mfa_enrollment_required／password_change_required 分支）..." },
    "redirect_next": "/assets"}
   ```

   `redirect_next` 取自 begin 階段**已驗證**的值，**不於兌換階段重新採信前端提交值**。
   兌換為原子消費並比對 provider 與使用者兩個世代。

   發出正式會話時，Web 會話刷新憑證以 `Set-Cookie: custodexa_refresh=...` 下發，
   **巢狀的 `login` 物件內不含憑證明文**；尚待多因素驗證／強制註冊／強制改密的分支
   不下發該 cookie。

**瀏覽器綁定（login CSRF 防護）**：DB 保存 state 只證明「伺服器簽發且未用過」，不證明 callback
發生在發起的瀏覽器。攻擊者可自行發起流程、以自己的 IdP 帳號完成授權但攔住 callback，
再把該 URL 交給受害者——state/nonce/PKCE 全部有效，受害者會被登入攻擊者帳號，其後操作與審計
全歸屬錯誤。故 `browser_secret` 明文必須在 exchange 時提出。**綁定不符時 ticket 不被消耗**
但累計失敗次數，達 3 次作廢——「消耗」與「請回到原分頁重試」互斥，故前 2 次可於原分頁重試。

**錯誤**（exchange／begin，統一錯誤封套）: 400 `AUTH_OIDC_PROVIDER_UNAVAILABLE`（provider 不存在／
停用／設定不完整）、400 `VALIDATION_OIDC_*`（binding 或 ticket 缺漏）、403 `AUTH_OIDC_ADMISSION_DENIED`、
409 `AUTH_OIDC_USERNAME_CONFLICT`、401 `AUTH_OIDC_FLOW_INVALID`（ticket／流程狀態無效、過期或已消費）、
403 帳號已停用、423 帳號已鎖定。

**與既有 gate chain 的關係**：exchange 走與本地登入相同的 `finishLogin`，故 MFA 與強制改密分支
一併適用；但**密碼類 gate 對外部帳號短路**（外部帳號無本地密碼可改）。
外部帳號無法使用本地密碼路徑（自助改密、admin 重設、本地登入）——一律回
`AUTH_EXTERNAL_USER_PASSWORD`。

### OIDC provider 管理（admin only）

```
GET    /api/v1/oidc-providers
POST   /api/v1/oidc-providers
PUT    /api/v1/oidc-providers/:id
DELETE /api/v1/oidc-providers/:id
```

**請求**（POST／PUT 同形）:
```json
{
  "name": "公司 Entra ID",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "…",
  "client_secret": "…",
  "scopes": "openid profile email",
  "admission_mode": "jit_with_rules",
  "admission_rules": "{…JSON…}",
  "force_shared": null,
  "enabled": true
}
```

**回應**（列表為 `{"data": [...]}`；單筆 201／200）:
```json
{
  "id": 1, "name": "公司 Entra ID",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "…", "scopes": "openid profile email",
  "admission_mode": "jit_with_rules", "admission_rules": "{…}",
  "enabled": true, "has_secret": true,
  "issuer_kind": "dedicated", "issuer_kind_source": "deploy_declared",
  "config_complete": true, "identity_count": 12
}
```

**回應語義**:
- **回應永不含 client_secret 的任何形式**；`has_secret` 僅告知「是否已設定」，供 UI 顯示
  「留空沿用」提示。PUT 時 `client_secret` 留空＝沿用既有值。
- `issuer_kind`（`shared`／`dedicated`）為 **effective 判定結果，現算不持久化**，優先序：
  內建共用清單 > `force_shared`（admin 收緊意圖）> 部署層 `OIDC_DEDICATED_ISSUERS` > 未知（一律 `shared`，fail-close）。
- `issuer_kind_source`（`builtin_list`／`admin_forced`／`deploy_declared`／`unknown_default`）
  使「部署宣告打錯字而未生效」可被立即看出，而非表現為「規則設定莫名被拒」。
  多副本部署時該欄反映**本副本**的判定。
- `identity_count`（列表端點）為已綁定此 provider 的外部身分數。兩處管理決策需要具體
  數字而非語義提示：切換為 `prebound_only` 時「既有 N 個身分沿用、新使用者不再自動供應」，
  以及刪除被拒時「請先解綁 N 個身分」——只說「有既有身分」無從判斷影響面。
- `config_complete=false`＋`incomplete_hint`：設定不完整（如未設 `PUBLIC_BASE_URL`），
  該 provider 不會出現在 `/auth/methods`。

**約束與錯誤**:
- `issuer` 與 `client_id` 組成身分域，**建後不可變**（PUT 送出不同值回 400
  `VALIDATION_OIDC_IMMUTABLE_FIELD`）。Entra 的 `sub` 為 per-application pairwise，
  換 client_id 後同一人會拿到不同 subject，此約束為硬需求。
- `(issuer, client_id)` 唯一（排除軟刪列）；重複回 409 `CONFLICT_OIDC_IDENTITY_DOMAIN`。
- 有外部身分關聯者**不可刪除**，回 409 `CONFLICT_OIDC_PROVIDER_IN_USE`（僅能停用）。
- `scopes` 走允許清單，未知 scope 回 400；`admission_rules` 鍵封閉，未知鍵／共用身分域
  未帶組織歸屬規則／消費者租戶值入清單一律回 400 `VALIDATION_OIDC_ADMISSION_RULES`。
- issuer 格式與 scheme 不合（release 拒 http）回 400 `VALIDATION_OIDC_ISSUER`。
- 404 `NOTFOUND_OIDC_PROVIDER`；`:id` 非正整數回 400 `VALIDATION_OIDC_PROVIDER_ID`。

**停用／刪除／secret 輪替的失效語義**（安全紅線）：三者皆先推進該 provider 的 `auth_epoch`，
再撤銷 refresh、拒絕既簽 access、終斷該 provider 建立的協議連線、收線其監看與分享訂閱。
`auth_epoch` **重新啟用不回退**，故「停用後短時間重新啟用」不會復活攻擊者手上的既簽憑證。
secret 輪替一併走全套——僅推進世代不足夠，既有連線建立後不再使用憑證，世代對其無效。
**IdP 端的停權不在此列**：見 QUICKSTART.md「OIDC／SSO 部署注意」。

### LDAP 目錄設定（admin only）

```
GET    /api/v1/ldap-directory
PUT    /api/v1/ldap-directory
DELETE /api/v1/ldap-directory
POST   /api/v1/ldap-directory/test
```

**singleton 資源**：無集合式建立端點、無資源 id。`PUT` 為 upsert（無列即建、有列即改），
`DELETE` 為軟刪。「至多一條有效設定」由資料庫層保證（`CHECK (singleton = 1)` ＋
partial unique index），不依賴服務層計數；並發寫入以交易範圍互斥鎖線性化，
取不到鎖回可重試機器碼而非 500。

**請求**（PUT）:
```json
{
  "name": "公司目錄",
  "url": "ldaps://dir.example.com:636",
  "bind_dn": "cn=svc-bind,dc=example,dc=com",
  "bind_password": "…",
  "clear_bind_password": false,
  "base_dn": "ou=users,dc=example,dc=com",
  "user_filter": "(&(objectClass=user)(sAMAccountName=%s))",
  "attr_email": "mail",
  "attr_fullname": "displayName",
  "skip_tls_verify": false,
  "enabled": true,
  "risk_acknowledged": false
}
```

**回應**（GET／PUT）:
```json
{
  "configured": true, "name": "公司目錄",
  "url": "ldaps://dir.example.com:636",
  "bind_dn": "cn=svc-bind,dc=example,dc=com",
  "has_bind_password": true,
  "base_dn": "ou=users,dc=example,dc=com",
  "user_filter": "(&(objectClass=user)(sAMAccountName=%s))",
  "attr_email": "mail", "attr_fullname": "displayName",
  "skip_tls_verify": false, "enabled": true
}
```

未設定時回 `{"configured": false}`。**bind 密碼永不回讀**，僅以 `has_bind_password` 表達有無。

**密碼編輯語義**（與通知通道 secret 同族）: 空值＝沿用既存；`clear_bind_password: true`＝顯式清除
（同事務抹除密文，軟刪 tombstone 不留可解密內容）；兩者同時給＝400。
**URL 的 canonical origin 改變且既存有密碼時**，必須同時提供新密碼或顯式清除，否則 400——
否則「改指向 ＋ 留空沿用」會把既存憑證送往新位址。既存無密碼（草稿）時改 URL 不受此限。

**URL 文法**：僅接受 `ldap[s]://host[:port]`，拒絕 userinfo／path／query／fragment／空 host／
超界 port（`ldap://user:secret@host/...` 形態會使憑證流入 UI、錯誤訊息與審計的目標欄位）。
比較、出站檢查與撥號共用同一份解析結果。

**`user_filter` 兩層驗證**（存檔即驗，非僅測試時）: 語法層要求 `%s` 恰一次、無其他格式化動詞、
括號配對、可解析為 RFC 4515；結構層要求 `%s` 所在等式斷言為**每條可滿足路徑的必要條件**
（其祖先不得為 OR／NOT）。`(|(uid=%s)(uid=svc-admin))` 語法合法但被結構層拒絕——
OR 的另一分支可在不含登入帳號時命中，配合「唯一命中即 bind」會使搜尋結果與登入身分脫鉤。

**存檔閘**（沿既有三通道共用契約）: 僅「儲存後為啟用且含傳輸風險」須過閘。strict 檔位拒存、
warn 檔位缺 `risk_acknowledged` 拒存（400，碼與 syslog／通知通道相同）；`enabled=false` 不受限。

**連線測試** `POST /ldap-directory/test`：測**表單當下未儲存的值**（先測後存）。
階梯為 撥號 → bind → 搜尋，`err == nil` 即階梯已執行（HTTP 200，失敗資訊在 body 的
`stages[]`／`failed_stage`／`code`）；`err != nil` 代表測試未執行（驗證/閘 400、限流 429）。

```json
{
  "success": true, "target": "ldaps://dir.example.com:636",
  "stages": [{"stage": "dial", "ok": true}, {"stage": "bind", "ok": true}, {"stage": "search", "ok": true}],
  "matched_count": 42, "matched_at_least": false,
  "attr_sample": {"sampled": true, "email_present": true, "fullname_present": true},
  "reused_stored_password": false
}
```

搜尋以未轉義 `*` 展開 `%s`（**全系統唯一不經 `EscapeFilter` 的例外**，登入路徑不受影響），
`SizeLimit` 1000（達上限時 `matched_at_least: true`，UI 顯示「至少 N 筆」）。

**錯誤揭露的收斂**：撥號失敗一律回單一 `connect_failed`，**不細分** DNS／逾時／拒絕／TLS——
階梯本身已是 open/closed 訊號，再細分等於提供內網埠掃描解析度。失敗回應附 `diagnostic_id`
（不透明關聯碼，同值出現於回應、審計與伺服端 operational log 三處），粗分類原因**只**寫入
operational log，需主機營運權限才能對照。出站政策拒絕另立 `egress_blocked`——該判定發生在
本地（IP 分類），封包從未送出，不揭露目標主機狀態。

**測試路徑亦受傳輸政策約束**且**不受請求的 `enabled` 限縮**：測試當下就會撥號送出 bind 密碼，
若比照存檔閘只在啟用時生效，關掉開關即可在 strict 下明文外送憑證。空密碼在本機即擋
（不對目錄發出 bind），確保「改 URL／勾清除」兩種情形下憑證不離開本機。

**出站位址政策**（登入與測試兩路徑皆過）: 拒絕 loopback／link-local（含雲端 metadata）／
未指定／multicast；**私有網段預設放行**（目錄常態位置為內網）。判定發生於名稱解析之後、
實際連線之前並套用於每個候選位址，故 DNS rebinding 無窗口；不改寫 host 為 IP，
`ldaps://` 的憑證主機名驗證不受影響。loopback 例外見 `LDAP_ALLOWED_LOOPBACK_ENDPOINTS`。

**設定來源與降版**：`.env` 的 `LDAP_*` 九鍵僅供首次啟動 seed，之後以本 API 為唯一事實源；
降版至舊版本前須將現行設定回填 `.env`，見 QUICKSTART.md。

---

## 資產 API

> 需要登入；並掛細粒度權限（見各端點）。

**支援協議**（`protocol` 欄位）: `ssh` / `rdp` / `vnc` / `mysql` / `postgres` / `redis` / `mssql` / `k8s`

### 列表

```
GET /api/v1/assets
```

**權限**: `asset:view`

**可視範圍**: 非 admin/auditor 一律由伺服端收斂為該使用者的授權資產集合——個人授權與所屬使用者群組授權的聯集（各自含直授與資產分組授權，四路徑）、僅計入時效窗內授權，`authorized_only` 參數被忽略；admin/auditor 見全量且參數仍可自查。授權分支的每筆 Asset 額外帶 `permission` 欄位（該資產最高授權等級 `view`/`connect` 兩階取高，已移除 `manage`）；管理角色回應不帶該欄。approver 的審核範圍另構成第三個可視來源（範圍內資產可見、不可連）。

**連線入口三態**: 非 admin/auditor 的授權分支每筆 Asset 由伺服端統一標註 `access_state`（`connectable`＝可直接連線／`reason_required`＝填理由即連／`approval_required`＝需核准／`pending`＝已有在途申請，另帶 `pending_request_id`），持有效臨時授權時帶 `ticket_date_expired`；破窗可用時另帶 `break_glass_available`（伺服端事實源，omitempty）。前端按鈕狀態零推導，一律以此欄為準；點擊後仍以連線簽發點的政策閘回應為最終裁決（按鈕過時會被 403 自癒）。

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `search` | string | 名稱/主機搜尋 |
| `protocol` | string | 協議過濾 |
| `active` | bool | 啟用狀態 |
| `authorized_only` | bool | 僅顯示已授權資產（僅 admin/auditor 有效；非特權角色恆強制授權範圍） |
| `node_id` | int | 節點過濾（僅列掛該節點的資產；兩分支皆生效） |
| `include_subtree` | bool | 含子樹（預設 true；顯式 `false` 僅直掛） |
| `ungrouped` | bool | 僅列未掛載任何節點的資產 |
| `tags` | string | 標籤篩選（逗號分隔多值 AND；整詞比對、大小寫不敏感、`%`/`_`/`\` 跳脫不作萬用字元；空 token 丟棄、超 20 個 400；**僅 admin/auditor**——非特權角色帶此參數 400，不靜默忽略） |
| `page` | int | 頁碼（從 1 開始，預設 1） |
| `page_size` | int | 每頁數量（預設 20） |

**回應** (200): `{"data": [Asset], "total": N, "page": 1, "page_size": 20}`（兩分支同格式，篩選與分頁在授權分支同樣生效）

### 標籤清單與治理

```
GET  /api/v1/assets/tags          標籤清單（admin/auditor；一般使用者 403——全表彙整會洩漏未授權資產的標籤詞彙）
POST /api/v1/assets/tags/rename   全面改名/合併（僅 admin；auditor 403）
POST /api/v1/assets/tags/delete   全面刪除（僅 admin；auditor 403）
```

**清單回應** (200): `{"data": [{"name": "生產", "count": 2}]}`——全表動態彙整（無獨立 tag 表）、canonical 去重（NFC＋大小寫折疊，保首見書寫形）、升冪排序、附使用資產數；供資產頁篩選下拉、表單自動完成與治理介面共用。

**改名請求**: `{"from": "DbA標籤", "to": "DBA"}` → `{"affected": N}`。to 與既有標籤 canonical 相等即為合併（歸一至既有書寫形、逐資產去重）；套用至所有含 from 的資產、單一交易、逐資產留操作者審計。to 驗證：非空、不含逗號、≤64 字元（違規 400）。

**刪除請求**: `{"name": "廢棄"}` → `{"affected": N}`——自所有資產移除該標籤，其餘標籤不動。

**標籤儲存正規化**：Create/Update 時伺服端正規化（trim/去空/canonical 去重保序/歸一至既有書寫形）；文法上限：單項 ≤64 字元、每資產 ≤20 項、序列化總長 ≤500（違規 400）。存量資料由 migration `20260722_normalize_asset_tags` 一次性清洗（冪等、不動 updated_at）。

**Asset 主要欄位**（密文欄位 `password_enc`/`private_key_enc`/`sftp_password_enc` 永不輸出）:
```json
{
  "id": 1,
  "name": "Production Server",
  "protocol": "ssh",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "has_password": true,
  "has_private_key": false,
  "description": "",
  "tags": "production,linux",
  "active": true,
  "node_ids": [1, 4],
  "node_paths": ["prod", "prod / kafka"],
  "access_policy": "approval",
  "created_by": 1,
  "last_test_status": "reachable",
  "last_test_at": "2026-06-30T00:00:00Z",
  "last_test_latency_ms": 12,
  "db_name": "",
  "db_tls_mode": "",
  "k8s_namespace": "",
  "k8s_insecure_skip_tls": false,
  "sftp_enabled": false,
  "sftp_port": 22,
  "sftp_username": "",
  "has_sftp_password": false,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

### 創建

```
POST /api/v1/assets
```

**權限**: `asset:create`

**請求**（`CreateAssetRequest`）:
```json
{
  "name": "Production Server",
  "protocol": "ssh",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "password": "secret123",
  "private_key": "",
  "description": "Main production server",
  "tags": "production,linux",
  "node_ids": [1, 4],
  "access_policy": "",
  "rdp_security": "",
  "rdp_verify_cert": false,
  "db_name": "",
  "db_tls_mode": "",
  "db_ca_cert": "",
  "k8s_namespace": "",
  "k8s_pod": "",
  "k8s_container": "",
  "k8s_ca_cert": "",
  "k8s_insecure_skip_tls": false,
  "sftp_enabled": false,
  "sftp_port": 22,
  "sftp_username": "",
  "sftp_password": ""
}
```

**協議別驗證**:
- `username` 必填於 ssh/rdp/mysql/postgres/mssql；vnc/redis/k8s 僅密碼（K8s 為 Bearer Token，走 `password` 欄加密儲存）
- mssql 的 `host` **不得含逗號**（`-S host,port` 的分隔語義），違反回 `VALIDATION_ASSET_MSSQL_HOST_COMMA`
- `protocol=k8s` 時 `k8s_namespace` 必填（連線時選 pod；`k8s_pod`/`k8s_container` 為相容舊資料的選填）
- `db_name` 僅 mysql/postgres/redis/mssql 有意義（空＝連預設庫）；`db_tls_mode`: `''`/`disable`/`require`/`verify-ca`/`verify-full`
- `db_ca_cert` 對 mysql/postgres/redis 為 **CA bundle**；對 **mssql 為伺服器憑證釘選**（sqlcmd `-J`），語義不同，UI 另有說明文字
- `sftp_*` 僅 vnc 有意義（SFTP 側車檔案傳輸，選配）：`sftp_enabled=true` 時 `sftp_username` 必填、`sftp_port` 預設 22；`sftp_password` 後端 AES-256-GCM 加密存放，回應僅 `has_sftp_password` 布林；Update 時 `sftp_password` 空字串＝沿用既有
- `access_policy`: `open`（不需申請）/ `reason`（填理由即連）/ `approval`（需核准）；非法值 400。Create 空字串或省略＝NULL（繼承全域預設鍵 `access_policy_default`）；Update 為指標欄位——省略＝不動、空字串＝清除覆寫回 NULL（非沿用既有）；變更經 asset hooks 入審計
- `node_ids`: 掛載節點 id 集（多歸屬；節點須存在否則 400）。Create 空/省略＝未分組；Update 省略（null）＝不動、空陣列＝清空全部掛載；成員變更以 `node_ids` 舊→新入審計。回應恆帶 `node_ids`＋`node_paths`（全路徑顯示）

**回應** (201): Asset JSON。**錯誤**: 400 協議無效、409 名稱重複。

### 詳情 / 更新 / 刪除

```
GET    /api/v1/assets/:id     （asset:view＋逐資產可視守門）
PUT    /api/v1/assets/:id     （asset:update；UpdateAssetRequest 全欄位選填，密碼空字串不更新）
DELETE /api/v1/assets/:id     （asset:delete；軟刪除）
```

刪除回應 (200): `{}`（`message` 文案欄已移除；下同）

**逐資產可視守門**: `GET /assets/:id`、`GET /assets/:id/k8s/pods`、`GET /assets/:id/host-key` 統一掛 `RequireAssetVisible` 中介層——非 admin/auditor 須對該資產有 view（或更高）授權，未授權回 404「資產不存在」（不洩漏存在性）；守門無條件生效。

### 資產帳號

一資產多系統帳號，各自持有信封加密憑證；未指定帳號的連線與系統路徑（改密 runner、k8s、
SFTP 獨立入口）一律走**預設帳號**。適用 ssh/rdp/vnc/mysql/postgres/redis/mssql；k8s 固定單一預設帳號。

```
GET    /api/v1/assets/:id/accounts                         （asset:view＋逐資產可視守門）
POST   /api/v1/assets/:id/accounts                         （asset:update）
PUT    /api/v1/assets/:id/accounts/:accountId              （asset:update）
DELETE /api/v1/assets/:id/accounts/:accountId              （asset:update；204 No Content）
POST   /api/v1/assets/:id/accounts/:accountId/set-default  （asset:update）
```

**回應 DTO**（`AssetAccountDTO`，列表為 `{"data":[...],"total":N}`、建立回 201、更新與 set-default 回 200）:
```json
{
  "id": 3, "asset_id": 1, "username": "app",
  "is_default": false, "privileged": false, "auth_method": "sql", "note": "",
  "has_password": true, "has_private_key": false,
  "created_at": "2026-08-02T00:00:00Z", "updated_at": "2026-08-02T00:00:00Z"
}
```
**憑證絕不出站**：`password_enc`/`private_key_enc` 於 model 標 `json:"-"`，DTO 只降為
`has_password`/`has_private_key` 布林。列表排序 `is_default DESC, username ASC, id ASC`。

**列表的帳號範圍過濾**: 依請求者有效授權帳號集合逐筆過濾——範圍外的帳號**直接不出現**
（不回 403，不成為帳號探測器）；admin 全量，auditor 於非 connect 權限時全量。

**建立請求**（全欄位選填）:
```json
{"username": "app", "password": "...", "private_key": "", "is_default": false, "privileged": false, "auth_method": "sql", "note": "", "copy_from_account_id": 0}
```
- `copy_from_account_id`＝**從其他資產帳號複製建號**：密文**原樣搬移**（不解密重加密），
  `username` 僅在請求未帶時沿用來源，顯式帶 `password`/`private_key` 則覆蓋複製值。
  跨資產複製需操作者對來源資產有 view 權；來源不存在與無權限**共用同一碼**（不洩漏存在性）。
- 資產的第一個帳號強制成為預設（`is_default` 傳 false 亦然）。
- `auth_method`: 認證類型，值域 `sql`｜`domain`，未帶＝`sql`。**1.0 只接受 `sql`**——
  帶 `domain` 明確回 `VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED`（**不靜默降級**），
  值域外回 `VALIDATION_ACCOUNT_AUTH_METHOD`。非 mssql 協議的帳號留在預設值且不參與連線組裝。

**更新請求**（欄位皆為指標，未帶＝不動）: `username`/`password`/`private_key`/`privileged`/`auth_method`/`note`；
密碼與私鑰**空字串＝沿用既有**。**無 `is_default` 欄位**——切換預設帳號只能走 set-default 端點。

**default 語義**: 「至多一個」由 partial unique index 強制，「有帳號必有 default」由服務層
交易維護。刪除預設帳號時若資產尚有其他帳號 → 400 `RULE_ACCOUNT_DEFAULT_REQUIRED`；
資產僅剩該帳號時允許刪除（零帳號資產合法，同步清空資產顯示欄）。set-default 對已是預設者為
no-op（不寫審計），否則在同一交易內先清舊預設再設新預設。

**錯誤碼**（apierror 機器碼，前端查譯）:
`VALIDATION_INVALID_ACCOUNT_ID`(400)、`VALIDATION_ACCOUNT_USERNAME_INVALID`(400，含冒號或控制字元)、
`VALIDATION_ACCOUNT_USERNAME_RESERVED`(400，`@` 前綴為授權別名保留命名空間)、
`VALIDATION_ACCOUNT_USERNAME_TOO_LONG`(400)、`VALIDATION_ACCOUNT_NOTE_TOO_LONG`(400)、
`CONFLICT_ACCOUNT_USERNAME`(409，同資產同名)、`CONFLICT_ACCOUNT_DEFAULT`(409，併發撞 partial unique index)、
`RULE_ACCOUNT_DEFAULT_REQUIRED`(400)、`NOTFOUND_ASSET`(404)、`NOTFOUND_ASSET_ACCOUNT`(404)、
`NOTFOUND_ASSET_ACCOUNT_SOURCE`(404，複製來源不存在或無權)、`INTERNAL_ASSET_ACCOUNT_*`(500)。

**審計**: 建立/更新/刪除/切換預設各記一筆專屬審計，Details **只記被變更的欄位名稱**，
絕不含密文或明文憑證。

### 連線測試

```
POST /api/v1/assets/:id/test-connection
```

**權限**: `asset:test`
**請求**（選填）: `{"timeout": 10}`（秒，預設 10）

**回應** (200，`ConnectionTestResult`；結果同時落庫至 `last_test_*` 欄位):
```json
{
  "success": true,
  "message": "",
  "latency_ms": 150,
  "error_code": "",
  "protocol": "ssh",
  "tested_at": "2026-07-01T10:00:00Z"
}
```

失敗時另帶 `code`（apierror 機器碼，前端查譯），`message` 降為過渡 fallback＝該碼的
zh-TW 文案（不再回填 guacd／驅動的原始訊息，原文只落伺服端日誌）；成功時 `message` 為空。
`error_code` 為既有粗分類機器欄（徽章用），語義不變。

### K8s Pod 列表（連線時選 pod）

```
GET /api/v1/assets/:id/k8s/pods
```

**權限**: `asset:view`

**回應** (200): `{"pods": [PodInfo]}`
```json
{
  "pods": [{
    "name": "web-abc123",
    "phase": "Running",
    "ready": "2/2",
    "restarts": 0,
    "started_at": "2026-06-30T00:00:00Z",
    "node": "node-1",
    "containers": [{"name": "app", "image": "nginx:1.25", "ready": true}],
    "default_container": "app"
  }]
}
```

**錯誤**: 502 + `{"error": "...", "kind": "unreachable|tls|unauthorized|forbidden|notfound|unknown"}`
（K8s 連線錯誤分類為六類人話）。

### K8s 容器檔案進出（kubectl cp）

```
POST /api/v1/assets/:id/k8s/upload      （asset:update；multipart: pod, container, dest_path, file）
GET  /api/v1/assets/:id/k8s/download    （asset:update；query: pod, container, path）
```

- 上傳回應 (200): `{"path": "/tmp/xxx", "size": 1024}`；下載回應為檔案附件
- 檔案進出視為寫級操作，需 `asset:update` 而非僅讀
- 每次操作直接落審計日誌（resource=file，含方向/pod/container/路徑/大小）
- 下載對「容器內不存在的來源」回 404（以本地是否產出檔案判斷）；目錄回 400

---

## Host Key API（TOFU）

SSH 首連記錄 host key，之後指紋不符即拒線（SSH 終端、SFTP、SSH 直連測試共用）。

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/assets/:id/host-key` | 檢視指紋記錄：`{id, asset_id, algorithm, fingerprint, created_at, updated_at}`（`fingerprint` 為 `SHA256:xxx`，公鑰本體不外露）；無記錄回 404「尚無 host key 記錄」 | 登入＋逐資產可視守門（非 admin/auditor 未授權回 404「資產不存在」，無條件生效） |
| DELETE | `/assets/:id/host-key` | 重置（主機重灌場景），下次連線重新記錄 | admin |

---

## 檔案管理 API（SFTP，SSH 資產）

> 資產收口：client 只送 `asset_id` 與路徑，憑證由後端解析。
> 權限沿用連線授權（`connect` 權限，能連線即能傳檔）；全操作審計（含 size 與 SHA-256 摘要）。
> 存取政策閘同套生效：reason/approval 段位無時窗內臨時授權時常設
> connect 亦被擋（admin 豁免；auditor 與一般 user 同攔）——檔案資料面不得繞過政策閘。
> 未授權（無 connect）與政策攔截統一回 404「資產不存在」（不洩漏存在性；申請入口在資產列表，
> 檔案端點僅擋不引導）。
> 遠端路徑必須為絕對路徑且不得包含 `..`（否則 400）；遠端操作失敗回 502。
> 五個端點均接受選填 query `session_id`：自某會話的檔案分頁進入時
> 沿用該會話的資產帳號連線；省略＝檔案管理獨立入口，走預設帳號。非本人或非該資產的
> `session_id` 一律 404 `NOTFOUND_SESSION`（fail-close，不退回預設帳號）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/assets/:id/files?path=/abs/dir` | 目錄列表 → `{"path": "...", "entries": [{name, size, mode, mod_time, is_dir}]}` |
| GET | `/assets/:id/files/download?path=/abs/file` | 串流下載（attachment） |
| POST | `/assets/:id/files/upload` | multipart: `path`（目錄）+ `file` → `{"path": "...", "size": N}` |
| POST | `/assets/:id/files/mkdir` | body: `{"path": "/abs/dir"}` → `{"path": "..."}` |
| DELETE | `/assets/:id/files?path=/abs/target` | 刪除檔案或空目錄 → `{"path": "..."}` |

---

## 資產節點 API（分組升級節點樹）

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/asset-groups` | 節點平面列表 → `{data: [{id,name,description,parent_id,path,assets}], total}`（assets＝直掛成員；非 admin/auditor 收斂：每節點僅含該使用者授權的資產，保留「有授權資產的節點＋祖先鏈」——祖先空殼僅結構不洩漏資產） | 登入 |
| GET | `/asset-groups/tree` | 樹導覽（惰性）：`?parent_id=` 空＝根層 → `{data: [{id,name,description,parent_id,path,asset_count,subtree_asset_count,has_children}]}`；非 admin/auditor 依可視節點鏈收斂（授權資產掛載節點＋全部祖先，無關子樹不洩漏） | 登入 |
| POST | `/asset-groups` | 建立節點，body: `{name, description, parent_id}`（parent_id 空＝根節點；深度上限 10、同層同名 409） → 201 | admin |
| PUT | `/asset-groups/:id` | 更新名稱/描述（位置不動；同層同名 409） | admin |
| PUT | `/asset-groups/:id/move` | 搬移，body: `{parent_id}`（null＝搬到根層）；環路（搬到自身/子孫）400、搬移後子樹深度超限 400、目標層同名 409 | admin |
| DELETE | `/asset-groups/:id` | 刪除（僅「無子節點且無直掛資產」的空節點可刪，否則 400；掛該節點的授權與 approver 審核範圍連動軟刪＋審計） | admin |

> 授權客體 `asset_group_id` 語義＝「節點＋全部後代節點的資產」（含子樹，隨掛隨涵蓋）；
> 政策不掛節點。

**錯誤**: 409 同層名稱重複、404 不存在、400 深度超限/環路/非空節點。

---

## Session API

> 需要登入；權限 `session:view`（收斂為 admin/auditor）；終止為 `session:terminate`＝admin。
> 一般 user 檢視自己的連線紀錄請改用 [自助連線 API](#自助連線-api-my-connections)（`GET /my/connections`）。
> session:view 讀取端點（列表/詳情/活動/統計/per-session 指令）無條件守門。

### 列表

```
GET /api/v1/sessions
```

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `user_id` | uint | 用戶 ID |
| `asset_id` | uint | 資產 ID |
| `protocol` | string | ssh/rdp/vnc/mysql/postgres/redis/mssql/k8s |
| `status` | string | active/disconnected/closed |
| `start_time` | RFC3339 | 開始時間（起） |
| `end_time` | RFC3339 | 開始時間（迄） |
| `page`, `page_size` | int | 分頁（預設 1 / 20） |

**回應** (200): `{"data": [Session], "total": N, "page": 1, "page_size": 20}`

**Session 主要欄位**:
```json
{
  "id": 1,
  "session_id": "sess_1735700000000000000_1",
  "status": "closed",
  "protocol": "ssh",
  "user_id": 1,
  "user": {"id": 1, "username": "admin"},
  "asset_id": 1,
  "asset": {"id": 1, "name": "Server1"},
  "client_ip": "192.168.1.10",
  "start_time": "2026-07-01T10:00:00Z",
  "end_time": "2026-07-01T10:30:00Z",
  "duration": 1800,
  "end_reason": "normal",
  "recording_path": "...",
  "recording_size": 102400,
  "has_recording": true,
  "recording_error": "",
  "offsite_object_id": 42,
  "offsite_status": "uploaded",
  "k8s_namespace": "", "k8s_pod": "", "k8s_pod_uid": "",
  "k8s_container": "", "k8s_image": "", "k8s_node": ""
}
```

`end_reason`: `normal` / `idle_timeout` / `max_duration` / `admin_terminate` / `user_terminate`
（自助終止）/ `backend_restart` / `orphaned`（啟動清掃孤兒）/ `revoked`（授權撤銷）。
K8s 會話帶不可變 pod 快照（uid/image/node 於連線當下釘住）。

**離機儲存兩欄**（`offsite_object_id`／`offsite_status`）:
- `offsite_object_id`：保管帳冊列的識別；本會話的錄影尚未（或不會）進入離機佇列時**該鍵不出現**（`omitempty`）。
- `offsite_status`：**恆出現**（未進佇列時為空字串）。值域＝帳冊七態
  `pending`／`uploading`／`uploaded`／`failed`／`integrity_mismatch`／`foreign`／`local_purged`，
  另加回填掃描的兩個分類 `skipped_missing`（本機檔讀不到）／`skipped_expired`（已逾錄影保留期）
  ——後兩者**不建帳冊列**，故沒有對應的 `offsite_object_id`。
- 兩欄皆為**顯示用快取**（權威在帳冊），供列表與詳情頁免 join；離機功能從未設定的部署，
  存量與新建會話的 `offsite_status` 恆為空字串。逐態的語義見 [DB_SCHEMA.md](DB_SCHEMA.md) 第 45 節。

### 詳情 / 活動 / 統計 / 終止

```
GET  /api/v1/sessions/:id            → Session
GET  /api/v1/sessions/active         → [Session]（純陣列，無封套）
GET  /api/v1/sessions/statistics     → {"active_sessions": 5, "today_sessions": 50, "total_sessions": 1000}
POST /api/v1/sessions/:id/terminate  → {}
```

終止需 admin（403 否則）；已關閉的 session 回 400。

---

## 自助連線 API（my-connections）

> 僅需登入（任何已認證帳號，不需 `session:view`）。owner 一律取自 JWT，回傳呼叫者**自己**的連線精簡紀錄。
> owner 條件由服務層先行固定（取自 JWT），client 無法以查詢參數覆蓋擁有者範圍。

```
GET  /api/v1/my/connections
POST /api/v1/my/connections/:id/terminate
```

**Query 參數**（列表）:
| 參數 | 類型 | 說明 |
|------|------|------|
| `page`, `page_size` | int | 分頁（預設 1 / 20；`page_size` 上限 100，逾者夾為 100） |

任何 client 傳入的 `user_id`（query/body/header/path）皆被忽略，回應永遠僅限呼叫者自己的 session。
穩定排序 `start_time DESC, id DESC`。

**回應** (200): `{"data": [MyConnectionDTO], "total": N, "page": 1, "page_size": 20}`

**MyConnectionDTO**（獨立精簡投影，結構性不含指令/錄影/client IP/目標主機/K8s 快照/憑證）:
```json
{
  "id": 10,
  "asset_name": "Server1",
  "protocol": "ssh",
  "connected_at": "2026-07-01T10:00:00Z",
  "duration_seconds": 1800,
  "status": "active"
}
```

- `id`：session 識別碼，供自助終止指定目標（owner-scoped，對他人 id 一律 404）。
- `connected_at`：session 的 `StartTime`（連線起始，非 GORM 建列時間）。
- `status`：機器值 `active` / `ended`（`disconnected` 與 `closed` 皆歸 `ended`；前端顯示為「進行中/已結束」）。
- `duration_seconds`：`ended` 用持久化 `Duration`；`active` 為 `floor(now - StartTime)`，時鐘異常負值夾為 0。

### 自助終止

```
POST /api/v1/my/connections/:id/terminate
```

owner-scoped 終止呼叫者**自己**的 active 連線（實際斷開 WebSocket，`end_reason=user_terminate`）。owner 一律取自 JWT，`WHERE id=? AND user_id=?` 雙條件取回。owner 檢查即授權，**其安全語義不依賴任何 RBAC 權限判定**。

| 情境 | 回應 |
|---|---|
| 自己的 active 連線 | 200 `{}` |
| 他人的或不存在的 id | 404 `{"error":"連線不存在"}`（無可區分，不洩漏存在性） |
| 自己的非 active 連線 | 400 `{"error":"連線已結束"}` |

> admin/auditor 的全域強制終止仍走 `POST /sessions/:id/terminate`（admin only，`end_reason=admin_terminate`），與自助端點分離。

---

## 指令審計 API

指令由 SSH 按鍵流重組（Backspace 修正、keypad/Unicode keysym 映射）；
資料庫 CLI（mysql/postgres）以多行語句累積為單一 SQL；K8s logs 唯讀模態不產生指令。

| 方法 | 路徑 | 說明 | 權限 |
|---|---|---|---|
| GET | `/sessions/:id/commands` | 單會話指令流（seq 升冪，全量）→ `{data, total}` | `session:view` |
| GET | `/commands` | 跨會話搜尋 → `{data, total, page, page_size, degraded_total}` | `audit:view` |

**`/commands` Query 參數**: `keyword`（ILIKE 子字串）、`user_id`、`asset_id`、
`start_time`/`end_time`（RFC3339）、`page`/`page_size`、
`degraded`（`true`＝只要降級列／`false`＝只要有文字的列／未帶＝不過濾；無法解析時不套用）。

**`degraded_total`**：本次查詢的**時間窗／人／資產範圍內**，
指令文字無法可信重組的輪數。**刻意不套用 `keyword` 與 `degraded` 兩個條件**——
降級列的 `command` 恆為空字串，`command ILIKE '%rm -rf%'` 永遠不會命中它們；
本欄若跟著 keyword 走，稽核員搜 `rm -rf` 得到 0 筆時它也是 0，
於是「這個區間有 N 輪根本沒有文字可搜」仍然無從得知——而那正是本欄存在的理由
（前端據此常駐誠實橫幅）。

**SessionCommand 欄位**（搜尋結果另附 `username`、`asset_name`）:
```json
{
  "id": 1, "session_id": 10, "user_id": 1, "asset_id": 2,
  "command": "rm -rf /tmp/x", "seq": 3,
  "executed_at": "2026-07-01T10:00:05Z",
  "degraded": false, "degrade_reason": "",
  "k8s_pod": "", "k8s_container": "",
  "username": "admin", "asset_name": "Server1"
}
```

---

## 告警 API

### 告警規則（admin only）

指令入庫時與啟用規則比對，命中即依 `action` 告警或阻斷；規則 CUD 後快取即時重載。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/alert-rules` | 規則列表 → `{data, total}` |
| POST | `/alert-rules` | 新增 → 201；regex 以 `regexp.Compile` 驗證，無效回 400 附原因 |
| PUT | `/alert-rules/:id` | 更新 |
| DELETE | `/alert-rules/:id` | 刪除 |

**請求**（`AlertRuleRequest`）:
```json
{
  "name": "刪除根目錄",
  "pattern": "rm\\s+-rf\\s+/",
  "severity": "high",
  "action": "block",
  "enabled": true
}
```

- `severity`: `high`/`medium`/`low`；`action`: `alert`（預設）/`block`（阻斷）；`enabled` 未傳預設啟用
- `protocols`（逗號分隔協議，空＝全協議，用於 shell/SQL 規則分流）：Create/Update 皆可傳，
  會驗證值域並寫入，非法值回 400（`ErrInvalidProtocols`）；migration/seed 亦會設定

### 告警查詢

```
GET /api/v1/command-alerts
```

**權限**: `audit:view`
**Query 參數**: `severity`（非法值直接 400）、`user_id`、`asset_id`、`start_time`/`end_time`、
`unreviewed`（`=true` 僅列未審閱＝`reviewed_at IS NULL`，供每日審閱走查，PCI 10.4.1）、`page`/`page_size`。

**回應** (200): `{data, total, page, page_size}`；data 項為 CommandAlert + `username`/`asset_name`，
`rule_name`/`severity` 為觸發當下快照（規則後續改名/刪除不影響歷史）。
data 項另含審閱處置欄位 `reviewed_by`/`reviewed_at`/`disposition`（`pending`/`benign`/`escalated`）/`note`，
以及**可選** `client_ip`（該告警所屬會話的來源位址；查不到所屬會話時整欄不出現）。

**`kind` 三類**：`rule`（規則比對／阻斷）／`audit_degraded`（指令審計降級）／
`new_source_ip`（**該帳號首次自某來源位址建線**）。後兩類的 `rule_id` 為 `null`、`command` 為空字串，
機器碼落 `reason_code`（`audit_degraded_span`／`new_source_ip_session`）。
`new_source_ip` 為 `severity=medium`；它記錄的是「這個帳號以前沒從這個位址連過」，
**不表示該次連線被阻擋**——是否放行由允許來源網段（見「用戶 API」）決定，兩者互不影響。

### 告警審閱處置（PCI 10.4.1）

```
POST /api/v1/command-alerts/:id/review
```

**權限**: `alert:manage`（auditor/admin 有；user 無）

標記告警已審閱並記處置分類與備註；動作入審計（`resource=command_alert`、`action=update`，
`error_msg=alert_disposition_<disposition>`）。冪等：重覆審閱同一告警視為更新處置（可修正誤判），
`reviewed_at` 刷新為最新。

**請求**:
```json
{"disposition": "benign", "note": "誤報，屬例行維運"}
```
（`disposition` 必填，僅接受 `benign`＝誤報/無害 或 `escalated`＝升級處理；`note` 選填）

**回應** (200): `{"success": true}`

**錯誤**: 400 無效告警 ID 或 `disposition` 非 `benign`/`escalated`、404 告警不存在、500 內部錯誤。

---

## 通知通道 API（admin only）

告警產生時異步推送 JSON payload 至所有啟用通道；設定 secret 時以
HMAC-SHA256 簽名（`X-OT-Signature` header）。失敗重試 3 次（1s/2s/4s）後放棄並記 log。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/notification-channels` | 列表 → `{data, total}`（`secret` 不隨 JSON 輸出） |
| POST | `/notification-channels` | 新增 → 201；URL 僅允許 http/https，非法回 400 |
| PUT | `/notification-channels/:id` | 更新 |
| DELETE | `/notification-channels/:id` | 刪除 |
| POST | `/notification-channels/:id/test` | 同步測試發送 |

**請求**: `{"name": "...", "type": "webhook", "url": "https://...", "secret": "", "enabled": true, "language": "zh-TW"}`
（`type` 為 `webhook`／`slack`，未傳預設 webhook；`enabled` 未傳預設啟用；
Update 另可傳 `clear_secret: true` 顯式清除簽名密鑰，Create 忽略此欄）

**`language`（per-channel 語系）**: 三值 `zh-TW`／`en-US`／`ja-JP`，
Create 未傳預設 `zh-TW`；Update **省略＝保留舊值**，顯式傳空字串或白名單外值一律拒
（400＋`VALIDATION_CHANNEL_LANGUAGE`）。僅影響 Slack 通道的伺服端組字語言
（webhook 通道可設但目前無作用，UI 已註明）；列表與詳情回應皆帶此欄。

**測試回應**:
- 送達對端 (200): `{"success": true, "status_code": 200}`（對端 2xx 才算 success）
- 連線層失敗 (502): `{"error": ..., "code": "INTERNAL_CHANNEL_TEST_CONN_FAILED"}`；
  逾時為 `INTERNAL_CHANNEL_TEST_TIMEOUT`（原始錯誤僅留伺服器日誌，URL 可能含 secret 不回傳原文）

**推送 payload 形狀（散文零入 payload）**

webhook 通道分兩型。**指令告警**（`event` 為 `command_alert`；測試發送同形狀但 `event` 為 `test`）：

```json
{
  "event": "command_alert",
  "alert": {"id": 12, "command": "rm -rf /", "severity": "high",
            "rule_name": "危險刪除", "blocked": true, "triggered_at": "..."},
  "session": {"id": 34, "user_id": 2, "asset_id": 9, "client_ip": "198.51.100.7"}
}
```

- `session.client_ip`（可選）：該會話的來源位址；查不到所屬會話時整欄不出現（純加法，既有欄位集不變）。

- `blocked`（布林）：規則是否為阻斷型，觸發當下快照。原以 `rule_name` 後綴「（已阻斷）」承載散文，**已移除**——`rule_name` 自此為純淨的規則名稱快照。
- 測試發送（`POST /notification-channels/:id/test`）的 `rule_name` 固定為機器識別字 `"test"`，不再夾帶中文「測試發送」字樣。

**系統訊息**（審計失效／恢復／進行中、每日審閱逾期、存取申請與破窗事件等）：

```json
{"event": "audit_failure",
 "params": {"mechanism": "syslog_forward", "cause_code": "syslog_connect_failed",
            "started_at": "2026-08-01T10:00:00+08:00"},
 "sent_at": "2026-08-01T10:00:00+08:00"}
```

- `event`：具名機器識別字（`access_request.created`／`access_request.approved`／
  `access_request.approval_progress`／`access_request.rejected`／`break_glass_used`／
  `ticket_revoked`／`break_glass_review_overdue`／`audit_failure`／`audit_failure_resolved`／
  `audit_failure_ongoing`／`daily_review_overdue`／`test`）。
- `params`：結構化參數，每個 event 由 `EventSpec` 宣告值層契約（`enum`／`int`／`opaque` 三 kind）；
  opaque 值原樣傳遞不翻譯，經淨化（限長 128 rune、去換行/ANSI/控制字元，超限可見截斷）。
  去識別紅線不變：事由全文與底層錯誤原文（forensic detail）**不入出站 payload**。
- `degraded`（可選布林）：event 未註冊或 params 不合契約時降級投遞並附此旗標——
  合規告警不因目錄問題靜默消失。
- 舊形狀 `{event, title, text}`（散文 title/text）**已移除**（BREAKING，dev 階段不設相容期）。

**Slack 通道**：送 `{"text": "<mrkdwn>"}`，系統文案（測試通知標題內文、等級與「已阻斷」標示）
一律由伺服端翻譯目錄 `internal/notifycat` 依**該通道的 `language` 欄**渲染；使用者資料
（規則名、指令）原樣呈現只做 Slack `&<>` 跳脫。目錄無鍵時走 generic 降級渲染，仍投遞。

**遮罩**: `secret` 與 `url` 信封加密落庫；回應 `url` 遮罩為
`scheme://host/****末4碼`，全文不外洩。更新時空 `url`／空 `secret` 皆＝沿用既有值
（前端無從回填遮罩值）。

**傳輸政策閘**: 存檔（POST/PUT）受 `transport_notify_level` 政策約束——
`warn` 檔且 URL 為 http 時須帶 `"risk_acknowledged": true`（未帶回 400＋
`{code: "VALIDATION_TRANSMISSION_ACK_REQUIRED", risks}`，確認聲明入審計）；`strict` 檔拒存 http
（400＋`{code: "VALIDATION_TRANSMISSION_STRICT_REJECT", risks}`）；`off`（預設）行為不變。
（`ack_required`／`strict_reject` 等小寫碼已收斂為 registry 碼，
`risks` 仍以 Meta 平鋪保留供前端確認框列示。）
列表回應每列附 `transmission_deviation`（存量不安全通道誠實標偏離，不自動停用）。

---

## 傳輸安全 API（PCI Req 4）

六通道傳輸強制階梯（off/warn/strict）掛安全政策鍵（`transport_{rdp,vnc,db,ldap,syslog,notify}_level`＋
`transport_consent_ttl_days`），判定核心收口於 `TransmissionPolicyService`（閘門、徽章、清冊共用同一規則）。

### 連線同意（warn 檔連線類通道）

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/connect-tokens` | 簽發前經停用硬擋：資產 `active=false`→**403＋`{reason: "asset_disabled"}`**（授權檢查之後、政策閘之前；admin 不豁免——停用是資產態非權限態，須先重新啟用留審計）；再經傳輸閘：strict 命中→400＋`{channel, level, risks}`；warn 無有效同意→428＋`{channel, level, risks}`（與 strict 同一 body 形狀）；off/無風險→照常簽發。SFTP 檔案端點同收口（停用資產 403 `asset_disabled`）；token 兌換點（`/ssh`、`/connect`）建線前重查 active——簽發後停用者殘窗內同 403。停用硬擋後另經**錄影前置檢查**（偵測/告警恆做；政策鍵 `recording_failclose_enabled` 開啟且錄影目錄不可寫→**403＋`{reason: "recording_unavailable"}`**，admin 唯一例外放行＋審計豁免標記 `recording_exemption`） |
| POST | `/transmission-consents` | 傳輸風險同意立據（authenticate＋checkPermission 同簽發邊界） |

**同意請求**: `{"asset_id": 9, "risk_keys": ["vnc_unencrypted"]}`（`risk_keys`＝使用者看到的風險項 key 集合）
- 成功 (200): `{"consented_at": "..."}`；同意入審計（誰／何時／資產／風險項）；per user×asset 冪等更新
- 風險已變 (409): `{"error": "風險項已變更，請重新確認"}`（TOCTOU 守衛：立據集合與當下不符）
- strict 檔／無風險 (400): 不受理立據（strict 不吃同意、off 無需同意）

**同意有效性**: 效期動態判定（`consented_at`＋`transport_consent_ttl_days`，政策改動立即全域生效；0=永不過期）；
資產傳輸屬性變更→風險項集合雜湊（`risk_fingerprint`）不符→同意自然失效，無需監聽資產寫路徑。

### 通道加密清冊（admin only）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/transmission-inventory` | 全通道加密狀態彙整（讀取入審計，資源分類 transmission） |
| POST | `/transmission-inventory/export` | 匯出 JSON 快照（含 `generated_at`＋`generated_by`，匯出入審計） |

清冊讀時彙整不落表：資產類 SQL group by 聚合（不逐列）＋部署層設定狀態（LDAP scheme/SkipTLSVerify、
nginx 標「部署方管理」）＋各通道政策等級＋「若切 strict 將被拒資產數／將拒絕 LDAP 登入」預檢。

**通道欄位 i18n**：每個 channel 除繁中 fallback `note`／`strict_preflight`／`detail`（`(未設定)` 等）外，另附機器碼供前端查譯——`note_code`＋`note_params`（查 `transportNote.<code>`，如 `syslog_protocol` 帶 `{protocol}`）、`preflight_code`＋`preflight_params`（查 `transportPreflight.<code>`，`rdp/vnc/db_reject` 帶整數 `{n}` 走 count plural）、`detail_codes`（完整 machine-keyed 明細，技術複合鍵原樣＋`(未設定)`→`unset`，新前端整份取代 `detail`）、`display_params`（供清冊 risk label 查譯，如 syslog `{protocol}`）；風險項 `risks` 沿既有 `{key,label}`，前端以 `key` 查 `riskLabel.<key>`。所有碼欄位 additive omitempty、向後相容；審計僅記 event 碼、不含中文。

---

## 金鑰管理 API（admin only）

信封加密金鑰清冊與換鑰精靈；系統永不自動輪換，所有換鑰為管理員手動操作。
路徑段 `keys` 由審計 middleware 歸類為 `key_management` 資源、讀取入審計。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/keys` | 金鑰清冊：DB 側金鑰版本鏈（DataKey，不含金鑰材料）＋env 側四鑰一致顯示指紋（KEK／JWT_SECRET 為 secret 摘要指紋，匯出簽章鑰與檢查點簽章鑰為 Ed25519 公鑰指紋，並附公鑰供複製/下載）＋KEK 退役史（from→to）＋切換待收斂提示＋遷移與重包狀態＋超齡提醒 |
| POST | `/keys/rotate` | 輪替金鑰。`{"purpose": "data"}` 生成新 DEK 並批次重加密（上限 `KEY_ROTATION_MAX_PER_RUN`）；現行版本仍有殘值時以現版續跑（回應 `resumed: true`，不鑄新版本），殘值歸零才鑄新版；`{"purpose": "audit_integrity"}` 僅新章換鑰、歷史不重算。KEK 重包待切換期間回 409（`rewrap_pending`，切換完成後恢復） |
| POST | `/keys/rewrap` | KEK 重包：以**呼叫端指定的目標 KEK** 重包全部金鑰、新舊雙包裹並存。請求體為 discriminated union——本地目標 `{mode:"local", new_kek, new_kek_confirm, confirm_saved}`、委託目標 `{mode:"kms"\|"hsm", key_ref}`；混合欄位一律 400 拒絕。**伺服端不生成、不回傳、不落庫、不落日誌任何 KEK 明文**（明文流向反轉）。遷移未完成回 409；委託目標的連通性預檢失敗回 502 `INTERNAL_KEY_REWRAP_TARGET_UNAVAILABLE`；該模式未交付回 501 `VALIDATION_KEY_REWRAP_TARGET_UNSUPPORTED` |
| DELETE | `/keys/rewrap` | 放棄尚未切換的 KEK 重包：**軟退役**新 KEK 的未切換包裹列（`kek_retired_reason=abandoned`，材料保留至顯式清理）、清除待切換狀態，回應 `{"deleted": n}`（鍵名保留 wire 相容，值＝軟退役筆數）。無待切換重包時回 409；另一金鑰操作進行中回 409 `CONFLICT_KEY_OP_BUSY` |
| DELETE | `/keys/retired-material` | 清理退役金鑰材料：**系統唯一的材料銷毀點**。前置全收斂閘（有待切換 pending 或退役 backlog 即回 409 `CONFLICT_KEY_CLEANUP_NOT_CONVERGED`）＋逐 slot 自證（現行 KEK 須有可解包的 live 材料列）＋退役 DEK 版本引用掃描（仍被存量密文或審計列引用者拒清並逐項回報）。回應 `{"purged": [{purpose, version, kek_id}], "skipped": [{purpose, version, kek_id, refs, reason}]}`；指紋與退役軌跡永久保留，清理後留佔位列使版本鏈不斷號。清理明細顯式留痕審計 |

**清冊回應**（節錄）: `{"keys": [{purpose, version, status, kek_id, age_days, over_cryptoperiod, material_purged, ...}], "env_keys": [{name, name_code, fingerprint, public_key, managed_by, note, note_code}], "kek_id": "...", "rewrap_pending": false, "kek_history": [{from_kek_id, to_kek_id, retired_at, rows, material_rows}], "finalize_pending": 0, "retire_backlog": 0, "converge_state_error": false, "migration_pending": 0, "rotation_pending": 0, "reminder_days": 0}`
——`rotation_pending`＝現行 data DEK 版本尚未覆蓋的值數（partial 續跑提示）；`migration_pending`＝尚待信封化的 legacy 值數。兩者均以 Go 層嚴格信封判定計數。`env_keys` 四鑰（KEK、`JWT_SECRET`、匯出簽章鑰、檢查點簽章鑰）皆顯示 `fingerprint`，兩筆 Ed25519 另附 `public_key`（base64，供複製/下載，私鑰不外洩）；檢查點簽章鑰另帶 `version`。`kek_history`＝KEK 退役史（每筆 `from_kek_id`→`to_kek_id` 指紋＋退役時間＋退役列數 `rows`，不選取 wrapped_key）；`finalize_pending`／`retire_backlog`＝KEK 切換收尾待收斂筆數（>0 表 best-effort 收尾未竟、需重啟收斂）；`converge_state_error=true` 表上述兩數讀取失敗、數字不可信（UI 顯示未知態並保守禁用清理，不得以 0 呈現為健康）。`material_purged`（每筆金鑰）／`material_rows`（每筆退役史）為材料存量衍生欄位——SQL 端比較運算式產出，不取 `wrapped_key` 本值。

**重包回應**（**恰三鍵，任何分支皆不含明文欄**）: `{"target_mode": "local|kms|hsm", "new_kek_id": "...", "rewrapped_keys": 3}`
——`target_mode` 為 union 判別子；`new_kek_id` 本地目標＝材料指紋、委託目標＝外部識別（KMS 正規 key ARN／HSM `token:label`），皆為非機密。
本地目標：材料由管理員自行提供並保存，重包後存入 `ENCRYPTION_KEY` 後重啟；**遺失即資料永久不可解，系統不提供任何救回途徑**。
委託目標（kms）：重包後 clone 列的 `wrapped_key` 為 `wk:2:kms:` 格式，管理員移除本地 KEK 材料鍵並設 `KEK_PROVIDER=kms` 後重啟。
兩者共通：新 KEK 開機驗證成功才**軟退役**舊包裹列並完成切換（材料保留至顯式清理），未切換前以舊 KEK 照常運作（不鎖死）。回應帶 `Cache-Control: no-store`＋`Pragma: no-cache`。

---

## 剪貼簿審計 API

> **內容以信封加密落庫**：列表僅回**事實投影**（不含內容），
> 內容須經下方單筆調閱端點解密取得，且**逐筆入審計**（伺服器端留痕為交付前置，fail-close）。
> 兩端點皆掛 `audit:view`。

### 列表（事實投影）

```
GET /api/v1/sessions/:id/clipboard-events
```

**權限**: `audit:view`（此端點恆掛權限檢查）

**回應** (200): `{"data": [ClipboardEventFact], "total": N}`
```json
{"id": 1, "session_id": 10, "direction": "send", "content_length": 402, "content_status": "available", "created_at": "..."}
```

- 列表為**顯式 DTO**（`clipboardEventFact`），**不含內容**：識別、方向、內容長度、內容狀態、時間。
- `direction`: `send`（入遠端）/ `recv`（回拷）。
- `content_length`: 明文**位元組**數（與 64KB 截斷上限同單位）。
- `content_status`: `available`（內容可調閱）/ `failed`（內容留存失敗的缺口紀錄）；
  呈現端據此區分「可調閱」與「缺口」，**不以密文為空或長度為零推斷**。
- 列表本身入頁面級審計（`audit_details.result_count`＝本次取走幾筆）。

### 單筆內容調閱（解密＋逐筆留痕）

```
GET /api/v1/sessions/:id/clipboard-events/:eventID/content
```

**權限**: `audit:view`

**回應** (200): `{"data": {...}}`
```json
{"id": 1, "session_id": 10, "direction": "send", "content_length": 402, "content_status": "available", "created_at": "...", "content": "..."}
```

- 伺服器端解密該筆並回全文；**每次調閱逐筆入審計**（操作者、會話、事件識別、時間；
  `resource=clipboard_event`、`action=read`）。留痕成功是回傳內容的前置條件（**fail-close**）：
  審計寫入不可用時拒絕該次調閱、回收斂錯誤、不交付明文，該失敗沿既有審計失敗告警鏈揭露。
- 缺口紀錄（`content_status=failed`）回 200＋事實，但 **`content` 鍵缺席**（不以空字串冒充內容）。
- 以單一受權查詢同時約束事件識別與所屬會話：事件不存在、識別非法、或**不屬路徑中會話**
  三種情形一律收斂為同一 **404 `NOTFOUND_CLIPBOARD_EVENT`**，不洩存在性細節、不產生歸屬錯誤的審計。

**錯誤**: 404 `NOTFOUND_CLIPBOARD_EVENT`（收斂拒絕）；500 `INTERNAL_CLIPBOARD_QUERY`
（解密失敗／審計不可用等，原因只進伺服器 log 與告警鏈，對外不展開）。

---

## 錄影 API

**錄製格式**: SSH/DB CLI/K8s exec 為 asciinema v2（`.cast`）；RDP/VNC 為 Guacamole 原生（`.guac`）。
舊 `.typescript` 檔案於首次串流時自動轉換為 `.cast`。

### 錄影元數據

```
GET /api/v1/sessions/:id/recording
```

**權限**: `audit:view`

**回應** (200，`RecordingMetadata`):
```json
{
  "session_id": 1,
  "file_path": "/var/lib/custodexa/recordings/session-1.cast",
  "file_size": 102400,
  "duration": 1800,
  "created_at": "2026-07-01T10:00:00Z",
  "protocol": "ssh",
  "username": "admin",
  "asset_name": "Server1"
}
```

### 下載 / 串流

```
GET /api/v1/sessions/:id/recording/download   （audit:view；attachment）
GET /api/v1/sessions/:id/recording/stream     （audit:view；支援 HTTP Range）
```

- 串流 Content-Type：`.cast` 為 `application/x-asciicast`、`.guac` 為 `application/octet-stream`
- 下載一律標 `application/x-asciicast`（含 `.guac`，為現行程式碼行為）

### 來源判定與離機退路

下載、串流與 rtoken 串流三條路徑在交付位元組之前都會先做**來源判定**：本機副本可讀且大小不小於
帳冊記載者，直接由本機交付（現況行為）；本機檔缺席、開不了或被截斷，而帳冊記載該錄影已離機時，
才改由物件儲存取回。**下載走整檔路徑**，故順帶比對整檔雜湊——大小相同而內容已被改動的本機檔，
在此也會退到離機來源。

取回一律**先落暫存、驗過才交付**（含 Range 播放）：暫存檔的 SHA-256 與大小須與帳冊相符，
不符即刪除暫存、拒絕交付並把該帳冊列標為完整性不符。收口不變——仍走既有的 rtoken 或 JWT 授權，
**不簽發任何指向物件儲存的直連網址**。代價是首次播放的等待與暫存磁碟佔用（容器本地，有存活期與總量上限）。

**離機取回失敗回 409 ＋機器碼**（零位元組交付，並留審計）:

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `CONFLICT_OFFSITE_INTEGRITY_MISMATCH` | 409 | 取回內容的雜湊或大小與帳冊不符，已拒絕交付 |
| `CONFLICT_OFFSITE_PROFILE_MISSING` | 409 | 帳冊列指向的設定世代不存在（多半是部分還原）；fail-close，不改用現行設定猜 |
| `CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING` | 409 | 該世代的憑證已撤銷或缺席；**不回退預設憑證鏈** |
| `CONFLICT_OFFSITE_CREDENTIALS_UNAVAILABLE` | 409 | 憑證解密失敗（金鑰事故）。**不併吞為「功能未設定」** |

**審計的 `source` 與 `fallback_reason`**：離機取回成功時，該次交付的審計列 `details` 會多帶
`"source": "offsite"` 與 `"fallback_reason"`（值域 `local_missing`／`local_unreadable`／
`local_truncated`／`local_divergent`），記「這一次交付的位元組來自哪裡、為何不是本機」。
**只在離機來源時標記**——本機來源的審計列與離機功能上線前逐位元組相同，
「未設定＝行為完全不變」在審計面沒有例外。

> **`source` 不出現在錄影元數據回應內。** `GET /sessions/:id/recording` 的回應形狀未因離機功能改變
> （欄位如上一節），它描述的是這個會話的錄影本身，而非某一次交付的來源。會話層的離機狀態
> 請讀 Session 回應的 `offsite_status`（見 [Session API](#session-api)）。

### 錄影 token 串流（播放器建議路徑）

```
POST /api/v1/sessions/:id/recording/token     （audit:view）→ {"token": "<rtoken>"}
GET  /api/v1/recordings/stream?rtoken=<token>  （無需 JWT；token 即授權）
```

rtoken 不透明、120 秒 TTL 內可重用、僅授權讀取簽發時綁定的 session 錄影；
取代「把長效 JWT 放進播放 URL query」（避免 JWT 進 access log）。
無效或逾時回 401。

### 刪除 / 統計

```
DELETE /api/v1/sessions/:id/recording   （admin；session:terminate 權限 + handler 內 admin 檢查）
GET    /api/v1/recordings/stats         （audit:view）
```

**stats 回應** (200): `{"total_size": 10737418240, "count": 100, "oldest_date": "...", "newest_date": "..."}`

`total_size` 取自錄影目錄的實際檔案大小加總（`filepath.Walk`），非 `sessions.recording_size`
欄位之和。**系統不設任何阻擋性儲存上限**：沒有任何建線或錄影路徑會因儲存量而被拒絕，
磁碟容量本身由部署方的基礎設施監控承擔。

---

## 離機儲存 API

> 把錄影與證據包的副本上傳到物件儲存，並在本機副本不可用時由該處取回。
> **全部端點限 admin**（認證中介層＋角色檢查，無細分權限）。
> 儲存桶本身的建立、版本化、保留與生命週期規則歸部署方，產品只上傳、記帳、取回時驗證，
> 並在測試連線與狀態端點**中性揭露**儲存桶的現況（建議參數見 `docs/ops/`）。

```
GET    /api/v1/offsite-storage/settings                        讀取現行設定
PUT    /api/v1/offsite-storage/settings                        寫入設定（可能回「需確認」）
POST   /api/v1/offsite-storage/settings/confirm                確認世代切換
POST   /api/v1/offsite-storage/settings/disable                停止離機（退役現行世代）
GET    /api/v1/offsite-storage/profiles                        歷史世代清單
POST   /api/v1/offsite-storage/profiles/:id/revoke-credentials 撤銷某世代的憑證
GET    /api/v1/offsite-storage/status                          總覽（設定＋佇列＋治理揭露）
GET    /api/v1/offsite-storage/failures                        失敗清單（分頁）
POST   /api/v1/offsite-storage/test                            測試連線（以表單當下值，未儲存）
POST   /api/v1/offsite-storage/retry-failed                    批次重試全部失敗件
POST   /api/v1/offsite-storage/objects/:id/retry               單筆重試
```

### 設定的 write-only 語義

**回應永不含憑證**。讀取投影（`ProfileView`，`GET /settings`、`PUT /settings`、
`/settings/confirm`、`/settings/disable`、`GET /profiles` 共用）固定 17 欄：

| 欄位 | 說明 |
|---|---|
| `configured` | 設定表是否有任何世代（`false`＝從未設定） |
| `disabled` | 有歷史世代但無現行世代（＝已停止離機） |
| `generation_id` | 世代識別（**不可重用**，識別一律用它） |
| `profile_fingerprint` | 設定指紋；**可重複**，只作切換判準與顯示，不是識別 |
| `provider` | `s3`／`gcs` |
| `endpoint_origin` | 端點的**正規化 origin**。path、query 與 fragment 一律不回顯 |
| `bucket`／`prefix`／`region`／`path_style` | 連線參數 |
| `credential_mode` | `stored`／`default_chain`／`revoked` |
| `has_credentials` | 是否存有本世代自己的憑證（布林，**不是遮罩值**） |
| `credentials_cleared_at` | 憑證撤銷時刻（`revoked` 時非空） |
| `created_at`／`activated_at`／`retired_at` | 世代的時刻軌跡；`retired_at` 為空即現行世代 |
| `object_count` | 該世代的帳冊存量（清單端點填入） |

**寫入請求**（`PUT /settings`、`/settings/confirm` 與 `/test` 共用形狀）：
`provider`、`endpoint`、`bucket`、`prefix`、`region`、`path_style`，
憑證欄依 provider 為 `access_key_id`＋`secret_access_key`（s3）或 `service_account_json`（gcs），
另有 `clear_credentials` 布林旗標。憑證欄的三種意圖：

- **填值**＝設定新憑證；
- **`clear_credentials: true`**＝改走雲端 SDK 的預設憑證鏈；
- **兩者皆無＝沿用既存憑證**，但**僅在落點未變時成立**——provider、端點或 bucket 任一改變時，
  沿用既存憑證會被拒（`RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE`，409）。換落點必須重新輸入憑證，
  這條規則恰與世代切換對齊：憑證不會跟著設定被送到另一個地方去。

未設定時 `GET /settings` 回 **200 `configured:false`**，不是 404——「還沒設定」是本資源的正常狀態。

### 世代切換的確認流程

`PUT /settings` 算出的新指紋與現行世代不同、且帳冊已有存量物件時，**不逕行儲存**，
改回 **200** ＋確認要求：

```json
{
  "needs_confirmation": true,
  "object_count": 128,
  "expected_current_generation_id": 3,
  "settings_digest": "<sha256>"
}
```

前端據此顯示確認對話框（物件數、舊世代去向），並把後兩個值**原樣攜回** `POST /settings/confirm`。
確認在鎖內依序做：以 `expected_current_generation_id` 對現行世代做 CAS（0＝預期目前無現行世代）→
重算請求體摘要與 `settings_digest` 比對 → **以與 `PUT /settings` 完全相同的驗證核心重驗全部輸入**
→ 重數存量 → 才寫入。同一交易內完成「舊世代退役、新世代建立並啟用、舊世代的帳冊列轉為只讀、審計」。

CAS 或摘要不符時回 409（`CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION`／
`CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH`），訊息只說「設定已被其他操作變更，請重新讀取後再試」，
**不回顯現行設定的任何細節**。兩名管理員並發確認時先到者成立，任何交錯都不會留下兩個現行世代。

不需確認時（指紋相同，或帳冊零存量）直接回 `ProfileView` ＋ `"needs_confirmation": false`。

**`POST /settings/disable`（停止離機）** 退役現行世代而**不建新列**，該世代的帳冊列一併轉為只讀，
回 `ProfileView`（此時 `configured:true`、`disabled:true`）。**憑證不隨停用撤銷**——歷史取回還要用。
無現行世代時回 409 `CONFLICT_OFFSITE_NO_CURRENT_GENERATION`。

**`POST /profiles/:id/revoke-credentials`** 在單一交易內清除該世代的密文、置為 `revoked`、
記錄撤銷時刻並使該世代的用戶端快取立即失效，回 **204**。撤銷後該世代的物件取回一律以
`CONFLICT_OFFSITE_FOREIGN_CREDENTIALS_MISSING` 失敗，**不會回退到雲端預設憑證鏈**。
世代不存在或識別非法收斂同一個 404（`NOTFOUND_OFFSITE_GENERATION`）；已撤銷者回 409。

### 測試連線

`POST /offsite-storage/test` 收**表單當下值**（尚未儲存）執行實測。憑證沿用的三條件與寫入相同
（未帶憑證＋落點未變＋未帶 clear 旗標；**先證同落點才解密**）。**兩種失敗語義嚴格分立**：

- **測試未能執行**（請求格式錯、限流、內部錯）→ 4xx／5xx ＋機器碼，回應無 `stages`。
- **測試已執行但其中有失敗** → **200** ＋逐步結果陣列。

```json
{
  "passed": false,
  "stages": [
    {"step": "probe_bucket", "outcome": "ok",   "code": "", "detail": "..."},
    {"step": "versioning",   "outcome": "ok",   "code": "", "detail": "..."},
    {"step": "retention",    "outcome": "warn", "code": "offsite.test_governance_unknown", "detail": "..."},
    {"step": "write",        "outcome": "ok",   "code": "", "detail": ""},
    {"step": "read",         "outcome": "ok",   "code": "", "detail": ""},
    {"step": "delete",       "outcome": "warn", "code": "offsite.test_delete_denied", "detail": "..."}
  ]
}
```

- `step`：`probe_bucket`／`versioning`／`retention`／`write`／`read`／`delete`。
  前三步是**只讀的資訊性揭露**（儲存桶可達性、版本化與保留設定的現況）——
  **只回報現況、不判好壞**，開不開是部署方的決定；讀不到（權限不足）記 `warn`「無法確認，不影響上傳」。
  後三步是寫入、讀回比對、刪除自己的探測物。
- `outcome`：`ok`／`warn`／`fail`。
- `code`：`offsite.test_*` 機器碼（`test_bucket_unreachable`／`test_governance_unknown`／
  `test_write_failed`／`test_read_failed`／`test_read_mismatch`／`test_delete_denied`），成功步為空字串。
  **刪除被拒收斂單一 `warn`、不細分原因**：儲存桶保留設定擋下與憑證缺刪除權限都只是 `warn`，
  而產品的正式路徑對遠端零刪除，不依賴刪除能力；該探測物由部署方的生命週期規則或人工清除，不計入產品追蹤。
- 回應**不含端點 origin 以外的任何連線資訊**，整體結果入審計。
- **限流**：逐操作者權杖桶（穩態每分鐘 5 次）＋全域在途上限；超出回 **429 `RULE_OFFSITE_TEST_RATE_LIMITED`**，
  且**不揭露命中哪一道界線、不回 `Retry-After`**。端點是管理員輸入的任意主機，此處防的是把服務當成對外探測器。

### 狀態、失敗清單與重試

**`GET /status`**：`ProfileView` 的全部欄位，另加

- `credential_state`：`unconfigured`（無現行世代）／`ok`／`failed`（讀取或解密失敗）。
  **`failed` 不得被讀成「功能未設定」**——那是金鑰事故，上傳與取回會停在失敗態。
- `counts`：帳冊各狀態的計數；`total_objects`：帳冊總列數（管理介面的空狀態判準）。
- `oldest_pending_age_seconds`：各狀態最老待處理件的年齡（秒）。
- `governance`（**僅探測成功時出現**）：`versioning`（`enabled`／`disabled`／`unknown`）、
  `retention`（`none`／`bucket_policy`／`per_object`／`unknown`）與 `retention_detail`（現況描述，無判斷語）。
  探測失敗**不使本端點失敗**——遠端出事時管理員更需要看得到佇列。

**`GET /failures`**：`page`／`size`（預設 1／20），回
`{"data": [...], "total": N, "page": P, "page_size": S}`。每列：`object_id`、`kind`、`owner_id`、
`origin`、`provider`、`bucket`、`attempts`、`error_code`、`generation_id`、`updated_at`；
擁有者模組能描述時另有 `label`、`ended_at`、`retention_deadline`、`days_to_deadline`。
**排序在頁內成立**：距保留到期近者在前、無到期日者殿後——到期日不在帳冊裡，跨頁的全域排序需要
把全部失敗列取出並逐列點查詢。每一頁都看得見「距到期天數」，到期在即的件不會因為排在第二頁而被漏看。

**`POST /retry-failed`** 與 **`POST /objects/:id/retry`** 都回 `{"retried": n}`（重新排入佇列的件數）。
單筆重試在識別非法、帳冊列不存在或該列不可重試時，**一律收斂 404 `NOTFOUND_OFFSITE_OBJECT`**
——三者的差異只對探測者有意義（帳冊列的存在性），對管理員則是同一個修正動作。

### 機器碼

設定與操作面（狀態碼由拒因決定，未列於下者為 400）:

| 機器碼 | 狀態碼 | 情境 |
|---|---|---|
| `VALIDATION_OFFSITE_PROVIDER_INVALID` | 400 | provider 不在值域內 |
| `VALIDATION_OFFSITE_BUCKET_REQUIRED` | 400 | 未填儲存桶 |
| `VALIDATION_OFFSITE_ENDPOINT_INVALID` | 400 | 端點格式不合法 |
| `VALIDATION_OFFSITE_ENDPOINT_HAS_SECRETS` | 400 | 端點帶了帳密、query 或 fragment（端點淨化拒收） |
| `VALIDATION_OFFSITE_REGION_OR_ENDPOINT_REQUIRED` | 400 | region 與端點皆空 |
| `VALIDATION_OFFSITE_CREDENTIAL_HALF_SET` | 400 | 憑證只填了一半 |
| `VALIDATION_OFFSITE_CREDENTIAL_CONFLICT` | 400 | 同時帶新憑證與清除旗標，或帶了與 provider 不相稱的憑證欄 |
| `RULE_OFFSITE_CREDENTIAL_REUSE_ON_MOVE` | 409 | 落點已變更卻要沿用既存憑證 |
| `CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION` | 409 | 確認所依據的現行世代已被其他操作變更 |
| `CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH` | 409 | 確認攜回的設定摘要與請求體不符 |
| `CONFLICT_OFFSITE_NO_CURRENT_GENERATION` | 409 | 該操作需要現行世代，但目前沒有 |
| `CONFLICT_OFFSITE_CREDENTIALS_ALREADY_REVOKED` | 409 | 該世代憑證已撤銷 |
| `CONFLICT_OFFSITE_PROFILE_BUSY` | 409 | 另一項設定變更正在進行（可重試，非內部錯誤） |
| `NOTFOUND_OFFSITE_GENERATION` | 404 | 世代不存在或識別非法 |
| `NOTFOUND_OFFSITE_OBJECT` | 404 | 帳冊列不存在、識別非法，或該列不可重試 |
| `RULE_OFFSITE_TEST_RATE_LIMITED` | 429 | 測試連線超出資源上限 |
| `INTERNAL_OFFSITE_CREDENTIAL_ENCRYPT` | 500 | 憑證加密失敗 |
| `INTERNAL_OFFSITE_CREDENTIAL_DECRYPT` | 500 | 憑證解密失敗 |
| `INTERNAL_OFFSITE_STATUS` / `INTERNAL_OFFSITE_SETTINGS_SAVE` / `INTERNAL_OFFSITE_TEST` / `INTERNAL_OFFSITE_RETRY` | 500 | 各端點的內部錯誤出口 |

取回面的四個 409 見〈來源判定與離機退路〉。全部機器碼三語齊備（介面依碼查譯）。

---

## 用戶 API

> 整組 admin only（`RequireRole("admin")`）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/users` | 列表 → `{data, total}`；query: `search`（用戶名/郵箱）、`active`、`page`、`page_size` |
| POST | `/users` | 創建 → 201 `{data: User}` |
| GET | `/users/:id` | 詳情 → `{data: User}` |
| PUT | `/users/:id` | 更新基本資訊（不含密碼/角色） |
| DELETE | `/users/:id` | 軟刪除；不能刪除最後一個管理員（400） |
| PUT | `/users/:id/roles` | body: `{"roles": ["admin", "auditor"]}`（替換現有角色） |
| POST | `/users/:id/roles/:role` | 冪等追加單一角色（不觸碰其他角色，重複追加 no-op）→ `{}`；未知角色 400。一站式代配（審核範圍表單）用此端點避免整包替換的 lost-update |
| PUT | `/users/:id/status` | body: `{"active": false}`；不能停用最後一個管理員（400） |
| PUT | `/users/:id/password` | body: `{"password": "..."}`；長度/組成/歷史重用由密碼政策 validator 統一判定（單一事實源；預設最小長度 12、須含字母與數字、禁重用近 N 筆），違規回 400 附可讀原因；LDAP 用戶回 400 |
| POST | `/users/:id/unlock` | 管理員手動解鎖帳號（PCI 8.3.4）：清零 `failed_login_attempts` 與 `locked_until` → `{}`；顯式審計 action=`unlock` |
| PUT | `/users/:id/inactivity-exempt` | 設定閒置停用豁免（PCI 8.2.6）：body `{"exempt": true}` → `{}`；豁免旗標變更顯式審計（`inactivity_exempt_granted`/`revoked`） |
| POST | `/users/source-policy/check` | 允許來源網段草稿的判定 → `{data 見下}`；**純判定、不寫任何狀態**（見下段） |
| GET | `/users/local-admin-count` | 現存本地管理員數 → `{"count": n}`；唯讀、不入快取。計數直接來自 `service.CountLocalAdmins`，與「不得自一以上降為零」不變式的判定同一定義（啟用、具 admin 角色、密碼非空、憑證未外部化）。管理端據此條件式警示：`0` 表示遇 KEK 重啟時無人能解封 |

**創建請求**（`CreateUserRequest`）:
```json
{
  "username": "newuser",
  "password": "password123",
  "email": "newuser@example.com",
  "full_name": "New User",
  "roles": ["user"]
}
```
（`username` 3-50 字元、`email` 需合法、用戶名重複回 400；`password` 除 binding 下限外，
另過密碼政策 validator——預設最小長度 12、須含字母與數字，違規回 400 附可讀原因）

建立的帳號一律標記 `must_change_password`：使用者以此處設定的初始密碼首次登入時，
`POST /auth/login` 回 `password_change_required` 與 `change_token`（原因 `must_change`），
完成改密後才換發正式會話。此標記不受 `force_change_on_reset` 政策影響。

**更新請求**（`UpdateUserRequest`）: `{"email": "...", "full_name": "...", "allowed_cidrs": ["10.0.0.0/8"]}`
（`allowed_cidrs` 的 presence 三態見下段——**送 `[]` 會清空既有限制**）

**User 欄位**: `id, username, email, full_name, active, is_ldap, totp_enabled, roles[], created_at, updated_at`，
另含下列可見欄位 `locked_until`、`must_change_password`、`password_changed_at`、
`last_login_at`、`inactivity_exempt`（`password`、`totp_secret_enc`、`failed_login_attempts`、
`totp_last_step` 永不輸出），以及允許來源網段三欄 `allowed_cidrs`、`allowed_cidrs_status`、
`allowed_cidrs_families`（見下段）。

注意：登入/`/auth/me` 回應用的是精簡 `UserInfo`（`id/username/email/full_name/local_display_name/
display_name/active/roles/totp_enabled/is_ldap/external_credential/provisioning_origin/is_approver`），
不含上述欄位；完整欄位僅見於 `/users` 管理端點。

**帳號來源**：`/users` 列表另回 `auth_provider_names`
（該帳號已綁定的 OIDC provider 實例名陣列，依名稱排序；非持久化欄位，查詢時組出）。
多 provider 並存下管理者要看的是實例名（「Azure AD」）而非籠統的 `oidc`，且綁多個時
全部列出——只顯示第一個會讓人誤判解綁的影響面。

列表查詢參數另支援 `provisioning_origin`（值域 `local`／`ldap`／`oidc`，**未知值回 400
`VALIDATION_USER_ORIGIN_FILTER`** 而非靜默忽略）與 `auth_provider_id`（依 provider 實例篩選）。
兩者皆為伺服端篩選：列表是分頁的，在前端篩當頁會讓使用者看到「第 2 頁明明有 oidc 帳號，
篩選後卻說沒有」。依 provider 篩選以子查詢實作，綁多個身分的帳號不會重複出現。

### 允許來源網段（`allowed_cidrs`）

限制某個帳號**可以從哪些來源位址使用系統**。清單為空＝不限來源。
它限制的是可用來源，**不是**帳號憑證的強度，也不取代密碼政策、鎖定或多因素。

**回應三欄**（Create／Update／Get／List 皆有）：

```jsonc
{
  "allowed_cidrs": ["10.0.0.0/8", "198.51.100.0/24"],  // 已正規化、去重、排序
  "allowed_cidrs_status": "restricted",                 // 見下表
  "allowed_cidrs_families": ["v4"]                      // 僅 effectively_unrestricted 時出現
}
```

| `allowed_cidrs_status` | 語義 |
|---|---|
| `unrestricted` | 清單為空＝不限來源 |
| `effectively_unrestricted` | 清單非空但含全域前綴（`0.0.0.0/0` 或 `::/0`），**實際等同不限**；`allowed_cidrs_families` 指出被全放行的是哪一族（`v4`／`v6`／兩者） |
| `restricted` | 其他 |

**本欄由伺服端算出，前端不得自行推導**——「清單非空即已限定」在含全域前綴時會把實際放行呈現為受限。

> **命名注意**：`User` 物件上的欄位是 **`allowed_cidrs_families`**；
> 下方判定端點回覆裡的同一份資料則叫 **`families`**。兩者**不同名**，串接時勿互換。

**`PUT /users/:id` 的 presence 三態**（最容易做錯的一點）——**缺欄＝保留、`null`＝保留、`[]`＝清空**：

| 送出的 body | 後端行為 | 欄位級審計 diff |
|---|---|---|
| **省略** `allowed_cidrs` 欄 | 保留現值 | 無該欄 |
| `"allowed_cidrs": null` | 保留現值（**與省略同**） | 無該欄 |
| `"allowed_cidrs": []` | **清除為不限來源** | 記前後清單 |
| `"allowed_cidrs": [...]` | 整體取代 | 記前後清單 |

把整份表單物件送出的客戶端請注意：**未編輯清單時要送 `null` 或省略該欄，不可送 `[]`**
——後者會把既有限制清空。

驗證失敗**整體拒絕**（不靜默丟棄任何一項）：
- `VALIDATION_SOURCE_PREFIX_INVALID`（400）：含無法解析為位址或 CIDR 的項目
- `VALIDATION_SOURCE_PREFIX_LIMIT`（400）：去重後超過 32 項

**判定端點**（前端不自行判落入）：

```
POST /api/v1/users/source-policy/check
```

**權限**: admin only。**純判定**：不寫任何狀態、不儲存草稿。
判定權單一化是刻意的——IPv6 縮寫、IPv4-mapped 位址對 IPv4 前綴、遮罩正規化
（`10.1.2.3/8` → `10.0.0.0/8`）這些行為在兩套實作之間必然分歧，分歧的後果是
介面說「你還進得來」而下一次登入被擋在門外。本端點與登入、刷新、簽發、兌換各判定點
共用同一份判定實作。

**請求**:
```jsonc
{
  "allowed_cidrs": ["10.0.0.0/8"],   // 草稿清單（尚未儲存）
  "address": "203.0.113.9"           // 省略＝以本請求的來源判定（自鎖預警走這條）
}
```

**回應** (200):
```jsonc
{
  "valid": true,                      // 清單整體是否合法
  "items": [                          // 逐項結果，順序同請求
    {"input": "10.1.2.3/8", "normalized": "10.0.0.0/8"},
    {"input": "bad", "error_code": "invalid"}        // 或 "too_many"
  ],
  "normalized": ["10.0.0.0/8"],       // 去重排序後（清單合法時）
  "status": "restricted",             // 同上表的 allowed_cidrs_status 三值
  "families": ["v4"],                 // 僅 status 為 effectively_unrestricted 時出現
  "source": {
    "address": "203.0.113.9",         // 不可解析時為顯式 null（不是空字串）
    "reason": "provided"              // "request"（取自本請求）｜"provided"（呼叫端指定）｜"unresolvable"
  },
  "allowed": false                    // 該來源在此清單下是否放行
}
```

`allowed` 的判準與各強制點**同源**且 fail-close：清單不合法、或清單非空而來源不可解析
皆為 `false`；清單為空為 `true`。自鎖警告直接消費本欄。

**審計語義為讀取**（`action=read`、`resource=user`）。POST 的動詞推導預設會把它記成「建立使用者」
——那是假事件，故中介層依路徑訂正為讀取。該列的 `details` **記形狀不記內容**，六個鍵：

| 鍵 | 值 | 答的問題 |
|---|---|---|
| `check` | `source_policy` | 這一列是哪一種試算 |
| `cidr_count` | 草稿項數 | 送了幾條進來 |
| `valid` | `true`／`false` | 草稿本身合不合法 |
| `address_source` | `request`／`provided`／`unresolvable` | 試算的是他自己的來源還是指定的位址 |
| `allowed` | `true`／`false` | 試算結果 |
| `status` | 涵蓋狀態（**僅 `valid=true` 時才寫**） | 這份草稿等不等於不限 |

**草稿清單與被試算的位址一律不進 `details`**：那是一份從未儲存的草稿，寫進去等於把試算輸入
永久封存在受檢查點鏈保護、刪不掉的紀錄裡，卻換不到任何課責。
草稿本體另由 `request_body` 承擔：`allowed_cidrs` 自 2026-08-26 起登記為審計放行的實質欄位
（清單變更是安全開關，不放行就與改名寫出同一列），而遮罩以鍵名為單位、分不出端點，
故本端點的草稿清單也會原樣入庫；被試算的 `address` 不在白名單內，入庫即為 `***MASKED***`。

**自鎖與復原**：後端**不阻擋**把自己鎖在外面的儲存（管理者可能刻意設定尚未切換過去的網段），
介面只就近顯示 warning。真的鎖住時的復原途徑見
`docs/ops/deployment-topology-limits.md` 的「允許來源網段對部署的影響」段。

---

## 角色 API

```
GET /api/v1/roles
```

**權限**: admin only

**回應** (200): `{"data": [{"id": 1, "name": "admin", "description": "..."}], "total": 3}`
（預定義角色：`admin` / `user` / `auditor`）

---

## 安全政策 API（admin only）

PCI-DSS 合規政策的 key-value 設定。政策值以字串儲存，型別語義與 PCI 建議值由
服務層常數表定義；無對應列時以出廠預設生效。變更於單一交易內批次落庫（中途失敗全回滾），
每項變更寫入審計日誌（`resource=security_policy`，`old→new`，PCI 10.2.2）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/security-policies` | 取全部政策項（現值＋兩基準建議值＋各自符合性）→ `{data: [PolicyView], deviation_count: N, epayment_deviation_count: M}` |
| PUT | `/security-policies` | 批次更新，body `{"policies": {"key": "value", ...}}`（僅送有變更的鍵）；成功回同 GET 格式 |

**PolicyView 欄位**（每項政策）:
```json
{
  "key": "lockout_max_attempts",
  "type": "int",
  "default": "10",
  "pci_value": "10",
  "epayment_value": "5",
  "direction": "max",
  "requirement": "8.3.4",
  "epayment_requirement": "4-7(五)",
  "label": "登入失敗鎖定次數上限",
  "unit": "次",
  "unit_key": "count",
  "value": "10",
  "compliant": true,
  "epayment_compliant": false,
  "strictest_value": "5",
  "updated_by": "admin",
  "updated_at": "2026-07-03T00:00:00Z"
}
```
（`compliant` 為 null 表示該項無 PCI 建議值、不評估；`deviation_count` 為與 PCI 偏離的項數）

**雙基準標示**：PCI-DSS 與電子支付機構資通安全基準為
**平行兩軌**，各自有建議值（`pci_value`／`epayment_value`）、條號（`requirement`／
`epayment_requirement`）與符合性（`compliant`／`epayment_compliant`）。兩者 SHALL NOT
互相覆寫，偏離數亦不合計——同一項可能符合其一而偏離另一（如登入鎖定次數現值 8：
符合 PCI 的 ≤10，偏離電支的 ≤5）。`epayment_compliant` 為 null 表示該項無電支建議值。

`strictest_value` 是**兩基準取嚴後**的建議值，供「套用電支基準」使用。**不可改用
`epayment_value` 直接套用**：兩基準在部分項目上方向相反（密碼最小長度 PCI 要求 ≥12、
電支只要求 ≥6），無條件覆寫會把已符合 PCI 的設定改差，使「套用合規基準」這個動作
反而降低系統安全性。出廠預設值不因新增基準而改變（合規為一鍵之遙，非強制）。

`label`／`unit` 為繁中顯示 fallback；前端 i18n 以穩定 `key` 查 `policyLabel.<key>`、以語義 `unit_key`（值域 `count`／`minutes`／`chars`／`records`／`hours`／`days`／`persons`）查 `policyUnit.<unit_key>`——切語言顯示對應譯文，漏譯降級回 `label`／`unit`。

**政策鍵值域**（型別/出廠預設/PCI 建議值見 [DB_SCHEMA.md](DB_SCHEMA.md) security_policies 一節）:
`lockout_max_attempts`、`lockout_duration_minutes`、`password_min_length`、`password_require_alnum`、
`password_history_count`、`force_change_on_reset`、`mfa_required`（enum: off/admin_only/all）、
`web_idle_minutes`、`web_max_session_hours`、
`refresh_cookie_secure`（bool，預設 true——refresh cookie 是否標記 `Secure`（僅在 https 連線下由瀏覽器保存與回送）。
發放 cookie 時現讀，改值即生效不需重啟；初值於首次啟動自部署組態播種
（`AUTH_REFRESH_COOKIE_SECURE` 顯式值 → `PUBLIC_BASE_URL` 的 scheme；兩者皆缺則不寫政策列、出廠預設生效），
播種後本鍵以政策為準、改 env 不再介入。**無 PCI／電支建議值**：正確取值由部署對外協定決定
（https 部署開啟、刻意明文部署關閉），不是合規基準線，故不入「套用建議值」也不計偏離）、
`session_idle_minutes`、`session_max_minutes`、
`inactive_disable_days`；日誌保留與審閱（PCI Req 10）:
`retention_audit_log_days`、`retention_session_command_days`、`retention_alert_days`（預設 0=永久，PCI 365）、
`retention_recording_days`（預設 90，初始值由 `RECORDING_RETENTION_DAYS` env 播種）、
`retention_checkpoint_days`（檢查點鏈保留，預設 0＝永久、上界 3650、無 PCI 建議值——
其合規語義是**跨鍵**關係，見下方跨鍵約束）、
`daily_review_enabled`、`failure_alert_enabled`（bool，預設 false，PCI true）；存取政策（PCI 7.2）:
`access_policy_default`（enum: open/reason/approval，預設 open，PCI approval——資產未個別設定政策時的全域段位）、
`access_request_max_duration_minutes`（預設 1440）、`access_request_pending_timeout_hours`（預設 72）、
`access_request_min_approvals`（int，預設 1、區間 1–10——最少核准人數，內控強化選項非 PCI 要求，無 PCI 建議值）；
破窗與撤銷（PCI 7.2）: `break_glass_enabled`（bool，預設 false——破窗 opt-in）、
`break_glass_duration_minutes`（預設 60）、`break_glass_review_timeout_hours`（預設 24）、
`access_revoke_disconnect`（bool，預設 false——撤銷預設只擋新連線不硬斷）；
金鑰管理（PCI Req 3）: `key_cryptoperiod_reminder_days`（int，預設 0＝不提醒，
PCI 建議 365——金鑰超齡提醒天數，反映於金鑰清冊的 `reminder_days`）。

另有兩組政策鍵於他處詳述而不重複列於此：錄影 fail-close（`recording_failclose_enabled`，見連線簽發段）
與傳輸風險（7 個 `transport_*`，見傳輸安全段）。

**保留政策的跨鍵約束**：`retention_checkpoint_days` SHALL NOT
低於四個資料保留鍵中最長者，**0 視為無限大**（任一資料鍵為 0＝永久時，檢查點鍵僅允許 0）。
批次只要觸及這五個鍵中任一個，就以**批次套用後的終值**對四組關係全部驗一遍
（結果不因鍵在請求中的先後順序而異）；違反即整批拒絕，回
`VALIDATION_POLICY_RETENTION_CROSS_KEY` 並以 `params.key` 指出觸發的資料保留鍵。
出廠五鍵為 `0/0/0/90/0`，`RetentionCovers(0, 任意)` 恆真，故出廠狀態下的任何保留鍵
編輯都不會被誤擋。理由：檢查點是「這段資料沒被動過」的證明，證明活得比資料短
等於在資料還在的期間先把證明丟掉。約束於 retention 執行期亦成立——政策若經 SQL
直改而違規，鏈修剪保守跳過並記告警（不刪比資料更早的檢查點）。

**錯誤**: 400 未知鍵（`ErrPolicyUnknownKey`）或值不合法（型別/範圍，`ErrPolicyInvalidValue`）、
跨鍵約束違反（`VALIDATION_POLICY_RETENTION_CROSS_KEY`）、
未提供任何政策項；500 寫入失敗。

---

## 日誌合規 API（PCI Req 10）

### syslog 轉發設定（admin only，10.3.3）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/syslog-settings` | 設定與狀態 → `{data: {setting: {enabled, host, port, protocol, tls_ca, updated_by, updated_at}, dropped: N}}`（dropped=累計丟棄筆數，只增不歸零） |
| PUT | `/syslog-settings` | 更新設定；`protocol` 為 `udp`/`tcp`/`tcp+tls`；`tls_ca` 為 PEM（空=系統信任庫）；啟用時 host 必填；變更入審計（`resource=syslog_setting`，不含 CA 內容僅記 `tls_ca_set`） |
| POST | `/syslog-settings/test` | 以請求 body 的表單值（未儲存也可測）同步發送測試訊息。**成敗由狀態碼表達**：送達成功 `200 {data:{success:true}}`；送達失敗 `502 {error, code:"INTERNAL_SYSLOG_TEST_FAILED"}`（泛化訊息，連線拒絕／逾時／TLS 驗證失敗等具體原因僅記伺服端 log）；傳輸政策閘未確認 `400 {error, code:"VALIDATION_TRANSMISSION_ACK_REQUIRED", risks}` |

轉發語義：audit_logs 與 command_alerts 於 DB 寫入成功後 tee，RFC5424（TCP 用 octet-counting framing），
MSG 為 JSON 含 PCI 10.2.2 六要素；有界緩衝（4096）滿即丟並計數，斷線指數退避重連，
任何轉發故障不阻塞審計寫入。

### 每日審閱簽核（10.4.1；查詢 `audit:view`、簽核 `alert:manage`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/daily-reviews/status` | 今日狀態 → `{data: {enabled, signed?, snapshot?: {date, login_failures, unreviewed_alerts, high_risk_ops}, review?}}`（功能關閉時僅 `{enabled: false}`） |
| POST | `/daily-reviews` | 簽核今日審閱，body `{"note": "..."}`；快照於簽核時刻固化；每日至多一筆，衝突回 409 含既有簽核者；400 功能未啟用；簽核入審計（`resource=daily_review`） |
| GET | `/daily-reviews` | 簽核歷史（`page`/`page_size`）→ `{data: {items: [{review_date, reviewer_name, snapshot_json, note, created_at}], total}}` |

高危操作計數白名單：任何資源的 delete、`security_policy`/`syslog_setting`/`audit_export` 的寫入、
`user` 的 create/update。逾期提醒：政策啟用且昨日未簽核，每日 09:00 經通知通道發送。

### 審計失效事件（10.7.2/10.7.3；`audit:view`）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-failures` | 失效事件列表（`page`/`page_size`）→ `{data: {items: [{mechanism, started_at, ended_at, cause, cause_code, cause_params, details}], total}}`；`ended_at` null=進行中 |

機制：`audit_write`（審計批量寫庫失敗降級 fallback 檔）、`syslog_forward`（斷線/緩衝溢出）、
`recording_probe`/`recording_text`/`recording_graphics`（錄影三路）、`session_record`、`kek_retirement`。
事件記錄恆開；通知（失效/恢復，經通知通道）受政策 `failure_alert_enabled` 控制，進行中節流。

**cause 機器碼化**：

- `cause_code`（權威表述）：機器碼，值域見 `backend/internal/model/audit_failure.go` 的 `Cause*` 常數
  （如 `recording_start_failed`／`audit_write_fallback_file`／`syslog_connect_failed`／
  `kek_retirement_backlog`），前端按碼查譯顯示；三語短語另由 `internal/notifycat` 的 cause 詞庫渲染。
- `cause_params`：**物件**形態輸出（DB 存 JSON 字串，API 解碼後回物件，解不開即空物件不讓整份列表失敗）。
  含 `detail` 鍵時為 forensic 明細（底層錯誤原文），**僅落庫與 UI，不進出站 webhook payload**（去識別紅線）。
- `cause`（散文）：降為顯示 fallback（zh-TW 短語＋forensic detail），保留以免未改查譯的既有讀取點白屏。
- 同源一致：`sessions.recording_error` 自此存**同一組 cause code**（不再存散文），前端 tooltip 亦按碼查譯。

### 審計完整性（10.3.4；**admin 或 auditor**）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-integrity/verify?from=YYYY-MM-DD&to=YYYY-MM-DD` | 範圍掃描重算逐列 HMAC → `{data: {checked, passed, mismatched, mismatched_ids(上限 100), legacy}}`；`legacy`=功能上線前無 HMAC 的歷史列（不算不符）；預設近 7 天 |
| GET | `/audit-export/public-key` | 匯出簽章公鑰（`audit:view`）→ `{data: {algorithm: "Ed25519", public_key: base64}}` |

匯出 ZIP 內新增 `manifest.sig`（Ed25519 簽 `manifest.json` 檔案位元組的 base64），
以公鑰可離線驗證 manifest 未被竄改。能力邊界：逐列 HMAC 可偵測改內容，
**整列連 HMAC 刪除由檢查點鏈偵測**（見下節；本端點自身不涵蓋序列完整性）。

`/audit-integrity/verify` 由 `RequireRole(admin)` 放寬為
`RequireAnyRole(admin, auditor)`：auditor 若只能證序列完整卻不能自行驗內容真偽，
「被監督者代為出具監督證明」的角色錯配只解了一半。

### 審計檢查點鏈（**admin 或 auditor**，唯讀）

檢查點鏈對 `audit_logs` 的 **id 閉區間 `[id_from, id_to]`** 逐段蓋章：每小時或每 10000 筆先到先觸發，
記下 `id_hi = MAX(id)` 並延遲 grace（預設 30 秒）後掃描區間，算出
`(id, key_version, integrity_hmac)` 三元組的串流 SHA-256，與前一檢查點的雜湊鏈接後
以 Ed25519 簽章落庫。空區間照蓋（`row_count=0`），故 `seq` 恆為嚴格連續。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/audit-checkpoints?page=&page_size=` | 檢查點列表（seq 倒序）→ `{data: {items: [...], total}}`；每筆含 `seq`／`id_from`／`id_to`／`row_count`／`agg_hash`／`agg_scheme`／`prev_checkpoint_hash`／`sealed_at`／`signing_key_version`／`signature`／`anchor_status`／`purged_at` |
| GET | `/audit-checkpoints/verify` | **結構層**（預設全鏈）→ `{data: {chain: {total, latest_seq, oldest_seq, passed, failed, status, failures, unsealed_rows, unsealed_from_id, anchor_disabled}}}` |
| GET | `/audit-checkpoints/verify?content=true&seq_from=&seq_to=` | 加驗**內容層**（亦支援 `from=`／`to=` 日期映射）→ 另回 `content.intervals[]`，逐區間帶 `status` 與 `remain_rows` |
| GET | `/audit-checkpoints/public-key` | 鏈簽章公鑰 → `{data: {algorithm: "Ed25519", public_key, fingerprint, version}}`，供離線驗章 |

**兩層驗證的分工**：結構層純讀檢查點表（驗簽章、驗 prev hash 鏈接、驗 seq 連續），
10 年鏈約 8.8 萬列仍是秒級，故常開；內容層要重掃 `audit_logs` 重算聚合，
**必須帶範圍**，不帶回 `400 VALIDATION_CHECKPOINT_RANGE_REQUIRED`（範圍格式錯誤
回 `VALIDATION_CHECKPOINT_RANGE_FORMAT`）——不設此閘則一個無參數請求就會啟動
全歷史掃描。日期範圍映射不到任何檢查點時回空結果，不退化成全鏈。

逐區間狀態（九態，前端逐態有獨立文案與視覺分級）：

| 狀態 | 語義 |
|---|---|
| `passed` | 列數與聚合雜湊皆相符 |
| `purged_legal` | 區間已依保留政策整段清除，tombstone 簽章驗過（**非錯誤**） |
| `purged_invalid` | 列已不存在卻無有效 tombstone＝竄改 |
| `count_mismatch` | 殘留列數少於封章主張 |
| `hash_mismatch` | 列數相符但聚合不符（含多出的列其列級 HMAC 無效） |
| `extra_rows_valid_hmac` | 多出列且列級 HMAC 皆有效（遲到交易或持蓋章鑰者插列，需人工研判） |
| `signature_invalid` | 檢查點自身簽章驗不過 |
| `chain_broken` | `prev_checkpoint_hash` 與前一點重算值不符 |
| `seq_gap` | seq 斷洞，且無修剪記錄可解釋 |

**寫入面刻意不存在**：本組端點無任何 POST/PUT/DELETE——「可以被系統改的檢查點」
在稽核面前一文不值。到期修剪只由 retention 排程依 `retention_checkpoint_days` 執行。

誠實邊界（R0-R6 全文見 `openspec/specs/audit-checkpoint-chain/spec.md`，驗證頁亦逐條呈現）：
鏈證明「**DB 內的序列未被動**」，不證明「所有事件都進了 DB」（降級寫檔與滿載丟棄的
列不在 DB 也無 HMAC）；持簽章私鑰者可偽造整鏈，對抗手段是 syslog 離機錨定，
未啟用轉發時 `anchor_disabled=true` 且驗證頁顯示不可關閉的降級橫幅。

---

## 使用者群組 API（admin only）

> 使用者群組是**授權主體**的分組（與 RBAC 角色相互獨立，不影響端點權限）；
> 群組授權對全體成員生效，成員加入/移出即時反映（下次權限判定生效，無快取）。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/user-groups` | 群組列表（含成員）→ `{data, total}` |
| POST | `/user-groups` | 建立 → 201；名稱重複 409 |
| PUT | `/user-groups/:id` | 更新名稱/描述 |
| DELETE | `/user-groups/:id` | 刪除 → `{message, revoked_authorizations}`；同交易軟刪成員關係＋掛該群組的全部授權並寫審計（含連動撤銷筆數） |
| PUT | `/user-groups/:id/members` | 成員全量替換（穿梭框語義），body `{"user_ids": [...]}`；成員不存在 400 |
| GET | `/user-groups/:id/authorization-count` | 群組授權筆數 → `{authorization_count}`（刪除確認 UI「將連動撤銷 N 筆授權」） |

---

## 授權 API

> 整組 admin only。權限解析為四路徑聯集取最高（個人直授/個人組授/群組直授/群組組授），
> 無 deny、無「個人優先」；僅計入時效窗內授權（`date_start`/`date_expired`，空值＝永久；
> 建立 API 不接受手填時效，傳入即忽略——時效唯一來源為後續核准流）。

### 創建授權

```
POST /api/v1/authorizations
```

**請求**（主體 `user_id` 與 `user_group_id` 二擇一、客體 `asset_id` 與 `asset_group_id` 二擇一，違反回 400）:
```json
{"user_id": 2, "asset_id": 1, "permission": "connect"}
```
群組主體: `{"user_group_id": 1, "asset_id": 1, "permission": "connect"}`；
節點客體（含子樹）: `{"user_id": 2, "asset_group_id": 1, "permission": "view"}`

**Permission 類型**: `view`（查看）/ `connect`（連線，含 view）——兩階制。
`manage` 已移除：建立/批量 API binding 拒收（400）；歷史軟刪列不動，
活躍 manage 已由 migration 收斂為 connect（碰撞安全）。

**source 欄位**: `manual`（管理員手動授權，預設）/ `ticket`（申請核准流產生的臨時授權，帶
`date_start`/`date_expired` 時效窗）。臨時授權不佔用手動授權的去重空間（partial 唯一索引
排除 `source='ticket'`），撤銷語義相同。

**accounts 欄位（帳號範圍）**: 建立與批量授權的請求皆可帶
`"accounts": ["app", "deploy"]`——**省略（null）＝`@ALL`**（客體範圍內資產的全部帳號，
與多帳號引入前行為一致）；顯式送 `[]` 拒收（要撤銷請刪授權列）。批量授權展開出的每一筆
共用同一帳號範圍。回應恆帶 `accounts` 且恆非空（空值顯化為 `["@ALL"]`）。

**回應** (200，注意非 201):
```json
{
  "id": 1,
  "user_id": 2,
  "username": "user1",
  "asset_id": 1,
  "asset_name": "Server1",
  "permission": "connect",
  "granted_by": 1,
  "created_at": "2026-07-01T00:00:00Z"
}
```
（群組主體回 `user_group_id`/`user_group_name`；節點客體回 `asset_group_id`/`asset_group_name`，涵蓋＝節點＋子樹資產）

**錯誤**: 409 授權已存在（撤銷後重授同組合不受歷史記錄阻擋）、404 用戶/群組/資產不存在。

### 批量授權

```
POST /api/v1/authorizations/batch
```

**請求**（主體集×客體集×單一等級，伺服端於單一交易展開為多筆單主體單客體記錄）:
```json
{"user_ids": [2, 3], "user_group_ids": [1], "asset_ids": [1, 2, 3], "asset_group_ids": [], "permission": "connect"}
```

**回應** (200): `{"created": 8, "skipped": 1}`——已存在的組合原子跳過不報錯（`ON CONFLICT DO NOTHING`，並發安全）。

**錯誤**: 400 主體集或客體集為空／展開筆數超過上限 10000（不部分寫入）、404 任一引用不存在（整批拒絕）。
審計記一筆批量事件。

### 列表 / 刪除

```
GET    /api/v1/authorizations                （零篩選＝全量分頁；user_id、user_group_id、asset_id、node_id 至多一個，多於一個 400）
GET    /api/v1/authorizations?validity=expired&source=ticket  （伺服端篩選，COUNT 與分頁前生效）
DELETE /api/v1/authorizations/:id            → {}
```

列表回應: `{"data": [...], "total": N, "page": 1, "page_size": 20}`
（`page_size` 逾 100 或小於 1 一律**重設為 20**，非夾為 100；`/my/connections` 才是夾為 100）。
篩選參數：`validity` = `active`/`scheduled`/`expired`（三態時窗，白名單否則 400）、
`source` = `manual`/`ticket`。

`node_id` 篩選＝**涵蓋盤點語義**：回傳授權有效範圍與該節點子樹有交集的記錄，
三分支聯集——(1) 節點客體位於目標之祖先鏈/自身/後代（掛祖先因子樹涵蓋、掛後代落在範圍內）；
(2) 節點客體之子樹內存在同時掛載於目標子樹的資產（多歸屬橋接）；(3) 資產客體掛載於目標子樹內。
每筆授權僅出現一次；與 `validity`/`source` AND 疊加、COUNT 與分頁前生效。

列表項目主體與客體皆可辨識：user 主體帶 `user_id`/`username`、群組主體帶 `user_group_id`/`user_group_name`；
直接授權帶 `asset_id`/`asset_name`/`asset_protocol`、節點授權帶 `asset_group_id`/`asset_group_name`（全路徑）。
每列另含 `source`、`date_start`/`date_expired`（有值才出）、`validity_state`（`scheduled`/`active`/`expired`，
伺服端計算與解析引擎同語義）；`source='ticket'` 列附 `request_id`（反查申請單，無單省略）與
`revocable`（有單且時窗內＝true，前端按鈕零推導）。引用已軟刪實體的列帶 `subject_deleted`/`target_deleted` 標示。

DELETE 對 `source='ticket'` 且有關聯申請單的授權回 **409**（撤銷唯一路徑＝`POST /access-requests/:id/revoke`，
資格/附註/`access_revoke_disconnect` 斷線聯動見連線申請 API）；反查無單的孤兒 ticket 放行刪除並記審計。

### 帳號範圍更新

```
PUT /api/v1/authorizations/:id/accounts
```

**權限**: admin only，且於 handler 內**即時查 DB 有效角色重判**（不看 JWT 角色快照）；
非 admin 回 403 `AUTH_ROLE_REQUIRED`。

**請求**: `{"accounts": ["app"]}` 或 `{"accounts": ["@ALL"]}`
- 欄位為指標型別：**省略或 null → 400 `VALIDATION_ACCOUNT_SCOPE_REQUIRED`**（此端點不把
  未帶當 @ALL——收緊範圍是安全動作，必須顯式表態）。
- 顯式 `[]`、超過 200 項、項目全空白、含冒號／控制字元／`@` 前綴、單項逾 100 字元
  → 400 `VALIDATION_ACCOUNT_SCOPE_INVALID`。
- `source='ticket'` 的授權列 → 409 `CONFLICT_TICKET_ACCOUNT_SCOPE_IMMUTABLE`
  （臨時授權的帳號範圍源自申請單，不得事後改）。
- 授權不存在 → 404 `NOTFOUND_AUTHORIZATION`；id 非法 → 400 `VALIDATION_INVALID_AUTHORIZATION_ID`。

**回應** (200): 該授權列的完整序列化（同列表項目形狀，含更新後的 `accounts`）。

**語義**: 有效帳號集合＝使用者全部命中授權列（含群組授權與 ticket 臨時授權）帳號範圍之**聯集**
（`@ALL` 展開為資產全帳號，聯集取寬）；admin 全量。強制點收斂三處——connect token **簽發**、
**兌換複查**、工作區**帳號選擇器過濾**；系統路徑（改密計劃、k8s、SFTP 側車）走預設帳號、不經此判定。
帳號範圍收緊於**兌換點 DB 現查**即時生效（已簽發 token 不因效期未到而放行）。

**申請單傳遞**: `POST /api/v1/access-requests` 的 `accounts` 於核准時原樣落入 ticket 授權列；
核准人**不得上調**（同既有「時長/起始只可下修」語義）。

### 有效權限雙視角（admin only）

```
GET /api/v1/authorizations/effective-assets?user_id=153   主體視角：該使用者實際可及的資產＋溯因
GET /api/v1/authorizations/effective-users?asset_id=1     客體視角：實際可及該資產的使用者＋溯因
```

subject 顯式參數解析（不自 request context 推導），來源六種聯集與執行期判定一致：
授權記錄四路徑（`direct_user`/`user_group`/`asset_node`/`user_group_asset_node`，帶 `authorization_id`＋時窗）、
`approver_scope`（審核範圍隱含 view，`authorization_id` 空）、`role_override`（admin/auditor 角色隱含——
主體視角回 `role_override` 欄位供 UI 摘要橫幅；客體視角回 `role_override_note` 說明，不逐人列舉）。
每資產/使用者帶最高 `permission` 與 `paths` 溯因列表（`via_group_name`/`via_node_path` 等）。
404＝主體/資產不存在。

---

## 連線申請 API

三段存取政策（`open`/`reason`/`approval`，分組欄位→全域鍵）在連線 token 簽發點與 SFTP 檔案端點
設閘：非 open 段位僅時窗內臨時授權（`source='ticket'`）放行，常設 connect 被政策蓋過；admin 豁免
（審計帶 `policy_exemption='admin'` 標記），auditor 不豁免。簽發點政策攔截回 403＋機器可辨 body
（`code: reason_required|approval_required`、`max_duration_minutes`、在途單帶 `pending_request_id`），
前端據此分流（填理由框／導向申請）。

**狀態機**（全轉移 CAS，終態不可再轉移）: `pending` → `approved` / `rejected` / `cancelled`（申請人撤回）
/ `expired`（待審逾時，scheduler 每 5 分鐘掃描＋讀取惰性過濾雙保險）。

### 申請人端點（登入即可）

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/access-requests` | 提出申請，body `{asset_id, reason(≤1000 必填), duration_minutes(≥1，≤政策上限), date_start?(預約起始)}` → 201；reason 段位自動核准（決定者 system、回應即帶 `approved`）；open 段位拒建單（400） |
| POST | `/access-requests/break-glass` | 破窗緊急連線，body `{asset_id, reason(≤1000 必填)}` → 201；時長固定政策鍵（client 傳入即忽略）；即時核准＋建 ticket 授權＋標記待補審 |
| GET | `/access-requests/mine` | 我的申請（全狀態；破窗單帶 `kind='break_glass'`、撤銷單帶 `revoked_at`/`revoke_note`）→ `{data, total}` |
| GET | `/access-requests/mine/tickets` | 我的有效限時連線（時窗內 ticket 授權，帶 `request_id` 回鏈）→ `{data, total}` |
| POST | `/access-requests/:id/cancel` | 撤回自己的 pending 單（他人單 403、非 pending 409） |

**錯誤**: 409 同資產已有在途單（帶在途單資訊；若在途單實已逾時，伺服端就地作廢後重試建單）、
400 時長超過 `access_request_max_duration_minutes`／open 段位、404 資產不可視（非授權資產不洩漏存在性）。

**破窗錯誤**: 403 `break_glass_disabled`（政策開關關閉，機器可辨 code）／
無破窗資格（需時窗內常設 connect，票證不算）／admin 與 auditor 不受理；409 同資產已有有效破窗票證
（帶單號＋到期時間）；400 事由缺漏／open 段位。破窗每次入審計獨立標記（`break_glass:true`），
事件 `break_glass_used` 廣播全體範圍命中的有效審核者（範圍無人時單維持待補審並持續逾期告警，
**不由 admin 兜底**——見下節；不阻斷破窗本身）。

### 審核端點（**有效審核者**：approver 角色 OR 屬任一審核方群組；即時查 DB roles 不看 JWT）

> **`admin` 角色本身不構成審核資格**，僅具 admin 者對本節端點一律 403。
> 理由＝職責分離：管理員自行指派權限又自行核准特權存取不可接受。
> 因此審核者須顯式以 `PUT /api/v1/users/{id}/roles` 指派 `approver` 角色，或納入審核方群組
> ——指派即時生效、無 token 殘窗。
> **脫困路徑保證**：角色指派與 `/approver-scopes` 皆為 admin only、**不經審核端點守衛**，
> 故即使系統中有效審核者為零，admin 仍能重建可審池，系統不會死鎖。
> **撤銷端點例外**：`POST /:id/revoke` 屬遏制動作非審核，**未收斂**（仍為 admin OR 有效審核者，
> 細緻資格見下方「撤銷資格」）——一併收斂會造成 admin 無法撤銷已核出的票證＝安全倒退。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/access-requests/pending` | 待審列表（僅審核範圍內＋排除本人單）→ `{data, total}` |
| GET | `/access-requests/pending/count` | 待審＋待補審計數（同範圍語義，導航 badge 輪詢用）→ `{count, review_count}` |
| GET | `/access-requests/history` | 歷史（一律依審核範圍過濾；分頁）→ `{data, total, page, page_size}` |
| GET | `/access-requests/tickets` | 有效限時連線（審核視角，帶 `request_id` 回鏈供撤銷）→ `{data, total}` |
| GET | `/access-requests/reviews/pending` | 待補審破窗單（範圍過濾＋排除本人單）→ `{data, total}` |
| POST | `/access-requests/:id/approve` | 核准（quorum 逐票）；body 可空（照申請值），或 `{duration_minutes?(僅可下修), date_start?(僅可推遲), note?}`；核准數達 `access_request_min_approvals` 門檻的那一票才同交易建 ticket 授權並回填 `authorization_id`，未達門檻回 pending 單＋進度；同人重複核准 409 |
| POST | `/access-requests/:id/reject` | 拒絕，body `{note}` 必填；任一具資格者即拒（既有核准記錄留存供審計） |
| POST | `/access-requests/:id/revoke` | 提前撤銷限時連線，body `{note}` 必填；軟刪票證＋單附註（不動狀態機終態）；政策開啟時同步斷線。**守衛為 `RequireRevokeEligibility`（admin OR 有效審核者），與上列審核端點分離** |
| POST | `/access-requests/:id/review` | 破窗事後補審，body `{disposition(confirmed\|violation), note?}`；破窗人自審 403、CAS 防重複 |

**裁決資格**（雙側聯集）: 資產側範圍命中（直配資產 OR 經節點含子樹）**OR**
申請人側範圍命中（申請人本人 OR 其所屬使用者群組）；**admin 身分不再兜底**，範圍未命中即
無人可裁，解法為 admin 補建審核範圍或指派 approver。**禁自核硬擋**（申請人＝操作者一律 403，
兼具 admin 身分者也不例外）。**錯誤**: 400 上調時長/提前起始、403 範圍外或自核、409 非 pending 或已逾時
（CAS 帶 `pending_expires_at > now` 守衛——逾期單核准落敗）、409 同人重複核准。

**最少核准人數**（政策鍵 `access_request_min_approvals`，預設 1、區間 1–10）: 每筆核准逐票記錄於
`access_request_approvals`（同單同人唯一）；兼具 admin 身分的有效審核者一票計入但不單票繞過門檻
（雙人完整性）。可審池不足門檻時 **SHALL NOT 由 admin 以 admin 身分補位**，須擴充可審池。申請單回應帶
`approvals`（逐票：誰/何時/note）與 `approvals_received`/`approvals_required` 進度欄；未達門檻的核准
回 200＋pending 單。政策值於每次核准時讀取。自動核准（reason 段）與破窗不受門檻約束。

**撤銷資格**: 一般核准單＝admin OR 原核准人；自動核准單與破窗單（無真人核准人）
＝admin OR 範圍命中 approver。**撤銷錯誤**: 403 非資格、409 無有效票證可撤（已到期或已撤，語義分離）、
400 事由缺漏。`access_revoke_disconnect=true` 時撤銷同步收線該 user×asset 的 active 會話
（`end_reason='revoked'`，收線失敗不回滾撤銷）。**補審錯誤**: 403 破窗人自審／範圍外、
409 已補審、400 處置值非法／非破窗單。逾期未補審（`break_glass_review_timeout_hours`）發
`break_glass_review_overdue` 升級告警。**逾期後週期重發**——以該單最近一次告警時刻節流，
仍待補審就每 24 小時再升級一次，直到有人補審為止（補審後即離開待補審視圖，不再命中）。

### 審核範圍 API（admin only）

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/approver-scopes?approver_id=` | 範圍列表 → `{data, total}` |
| POST | `/approver-scopes` | 建立，body 審核方恰一 `{approver_id XOR approver_group_id}` × 客體恰一 `{asset_id XOR asset_group_id XOR subject_user_id XOR subject_group_id}` → 201；個人審核方須具 approver 角色、群組審核方零代配（群組即資格）；重複組合 409 |
| DELETE | `/approver-scopes/:id` | 移除（範圍內申請即刻不可見/不可裁） |

approver 為可疊加角色（不進 JWT 三階 primaryRole 判定）。**審核資格＝具 approver 角色 OR 屬任一審核方
群組**（群組即資格：入組即可審、離組即失效；守衛 `RequireApproverRole` 與 `/auth/me` 的
`is_approver` 欄**共用同一述詞**、即時判定，兩者對 admin 結論一致，皆不放行）。**資產側**範圍（asset/asset_group）隱含範圍內資產 `view`（可視第三來源，
可見不可連；個人與群組成員同語義）；**申請人側**範圍（subject_user/subject_group）僅影響待審路由，
不隱含任何資產可視。前端管理入口：`/approver-scopes` 雙視角總覽頁（預設按資產/節點含可審人數與涵蓋
缺口警示；按審核人員矩陣，身分與權限組，admin only）＋使用者管理列內對話框（共用同一表單組件；
一站式新增——個人未具角色明示代配、群組零代配）。申請/核准/拒絕/撤回/逾時全動作入審計（`resource=access_request`）；事件廣播至
告警通道（payload 最小化：單號/資產名/事件/連結，無事由全文；通道未配置不阻斷）。

---

## 審計日誌 API

> 僅在 `FEATURE_AUDIT_LOG_ENABLED=true` 時註冊（程式碼預設 true，見 `config/config.go:173`）。
> 權限 `audit:view`。

### 列表

```
GET /api/v1/audit-logs
```

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `user_id` | uint | 操作者 ID |
| `action` | string | create/read/update/delete/execute/login/logout/unlock/file_list/file_upload/file_download/file_mkdir/file_delete/recording_failed/approve/reject/cancel/expire/revoke/review |
| `resource` | string | asset/session/recording/user/user_group/auth/file/security_policy/command_alert/audit_export/access_review/retention/daily_review/syslog_setting/audit_log/command/key_management/transmission/access_request/approver_scope/change_secret_plan/authorization/audit_timeline/clipboard_event/audit_checkpoint/audit_failure/audit_integrity/alert_rule/notify_channel/oidc_provider/ldap_directory/asset_group/snippet/role/unclassified（共 35，權威來源為 `backend/internal/model/audit_log.go` 的 `Resource*` 常數；前後端值域由雙向守衛釘住） |
| `status` | string | success/failure/denied |
| `client_ip` | string | 客戶端 IP |
| `start_time`, `end_time` | RFC3339 | 時間範圍 |
| `page`, `page_size` | int | 分頁 |
| `sort_by` | string | 排序欄位（預設 created_at） |
| `sort_order` | string | asc/desc（預設 desc） |

**回應** (200): `{"data": [AuditLog], "total": N, "page": 1, "page_size": 20}`

**AuditLog 欄位**: `id, action, resource, resource_id, status, user_id, username, method, path,
client_ip, status_code, duration_ms, request_body, error_msg, details, request_id, created_at`

### 詳情 / 資源歷史

```
GET /api/v1/audit-logs/:id                        → AuditLog（不存在回 404）
GET /api/v1/audit-logs/resource/:resource/:id     → {"resource": "asset", "resource_id": 1, "total": N, "logs": [...]}
```

`:resource` 僅接受 `asset`/`session`/`user`（其餘 400）。
`recording` **不是合法樞紐型別**：該分類的
`resource_id` 已改為**連線 id**，留在白名單會讓 `/audit-logs/resource/recording/7` 讀起來像
「第 7 號錄影」而實際是「第 7 場連線」。錄影調閱事件改由連線樞紐帶出（見下）。

連線樞紐（`:resource=session`）的回應**涵蓋該連線的取證讀取列**：取走剪貼簿明文
（`resource=clipboard_event`）、調閱錄影本體（`resource=recording`）與查詢指令原文
（`resource=command`）皆已獨立分類，三者的 `resource_id` 均為連線 id，樞紐查詢對同 id 空間的
子資源展開後合併，並依 `created_at` 重排為單一時間軸；`resource` 欄仍回樞紐型別本身。
跨會話端點（`/commands`、`/recordings/stats`）的列 `resource_id` 為空，不匹配任何樞紐
識別字，故不會被展開撈入。

`unclassified` 是分類器的**兜底哨兵**（同一 change 起），不對應任何實體：帶身分卻未被分類器
辨識的路由會寫出該分類的列。它使漏分類可以 `resource=unclassified` 單查詢計數，且不再污染
`asset_id`——訂正前兜底落 `asset`，帶路徑識別字的未分類端點會把別的實體 id 寫進 `asset_id`。

---

## 稽核調查工作台 API

> 權限 `audit:view`（**無條件強制**，不隨任何部署組態進退）。兩支端點皆**唯讀**：
> 工作台不提供任何狀態變更端點——稽核工具一旦能改東西，它產出的證據就要先自證沒被自己改過。
> 兩支的讀取本身入審計（`resource=audit_timeline`、`action=read`）。

### 時間軸

```
GET /api/v1/audit/timeline
```

把六類審計資料（`alert`／`audit_log`／`clipboard`／`command`／`file_transfer`／`session`）
聚合到一條時間軸上，依所選**樞紐**取出與該主體相關的列。

**Query 參數**:
| 參數 | 類型 | 說明 |
|------|------|------|
| `subject` | string | 樞紐種類：`user`／`asset`／`ip`（必填；未知值 400） |
| `subject_id` | uint | 人／資產樞紐的主體 id。**`subject=ip` 時本參數被忽略**（不構成錯誤） |
| `subject_ip` | string | **位址樞紐的主體鍵**（`subject=ip` 時必填）。不是合法位址時回 400 `VALIDATION_SOURCE_ADDRESS`；保留字 `unknown` **不被接受**（樞紐需要一個具體位址） |
| `client_ip` | string | 人／資產樞紐下的來源位址篩選。保留字 **`unknown`**＝只看未知來源列（位址欄為空，或所屬會話缺失）；其餘須為合法位址，否則 400 `VALIDATION_SOURCE_ADDRESS`。**位址樞紐下再帶本參數為 400**（樞紐已經是位址，再篩一次沒有語義） |
| `from`, `to` | RFC3339 | 時間範圍 |
| `types` | string | 逗號分隔的類別子集；空＝全部。**未知值回 400**，不靜默忽略——靜默忽略會回一份看起來完整、實際少了一整類的時間軸 |
| `cursor` | string | 分頁游標（由前一頁的 `next_cursor` 取得） |
| `limit` | int | 每頁筆數（預設 200、上限 500） |

**回應** (200): `{"events": [...], "spans": [...], "coverage": [...], "counts": {...}, "next_cursor": "...", "truncated": false}`

**事件欄（`events[]`）**：`id`、`ts`、`type`、`summary_code`、`params`、`counterpart`、`refs`、`severity`，
另有來源位址三欄：

- **`client_ip`**：`string | null`。**三樞紐皆帶，刻意不設 `omitempty`**——無位址時輸出**顯式 `null`**
  而不是缺欄。「每筆事件皆帶來源位址」是條文；省略欄位會讓呼叫端無法區分「未帶」與「未知」，
  筆數口徑也就無從定義。
- **`client_ip_reason`**：只在 `client_ip` 為 `null` 時出現，三值閉集合：
  `system`（系統發起的操作日誌列，無請求來源）／`unresolvable`（有請求脈絡但位址欄為空，
  寫入當下來源無法解析）／`session_missing`（指令或告警列經 `session_id` 找不到所屬會話列
  ——三表皆刻意無外鍵）。
- **`actor`**：`{kind:"user", id, name}`，**只在位址樞紐下出現**，未認證列為缺欄。
  位址軸上多帳號的事件會混在同一軸（NAT 共用出口），每列必須同時標「誰 · 哪台」——
  `counterpart` 在位址樞紐下裝資產，人由本欄承載。

**跨度欄（`spans[]`，僅會話類有跨度）** 同樣帶 `client_ip`（`string | null`、不設 `omitempty`）
與 `client_ip_reason`，語義同上。

### 樞紐候選

```
GET /api/v1/audit/subjects?type=<user|asset|ip>&q=<prefix>&limit=<n>
```

供工作台的樞紐選擇器做前綴查詢。**`type=ip` 的回應與 `user`／`asset` 是不同形狀**：

```jsonc
// type=user / type=asset
{"data": [{"id": 7, "name": "alice", "display_name": "Alice", "active": true, "deleted": false}], "total": 1}

// type=ip —— 位址沒有整數 id，也沒有啟停與軟刪語義
{"data": [{"ip": "198.51.100.7", "last_seen_at": "2026-08-26T10:00:00+08:00"}], "total": 1}
```

`type=ip` 的候選自帳號來源位址基準表導出，**只含成功登入或建線過的位址**，依最近見到時間降序。
只出現在拒絕列的位址不會進候選——但時間軸接受任一合法位址，呼叫端直接輸入即可查詢。

**讀取留痕**：本端點與時間軸同樣入審計（`resource=audit_timeline`、`action=read`）。

---

## 稽核證據匯出 API（PCI 10.5.1）

> 權限 `audit:view`（**無條件強制**，不隨任何部署組態進退）。匯出動作本身入審計
>（`resource=audit_export`、`action=read`，記匯出者、範圍與各部分筆數/截斷標記）。
>
> **兩種包，包型由 `pack` 決定**：
> - **事件報告**（`pack=event_report`）：六來源的**事件事實**，**不含**剪貼簿內容、傳輸檔案本體與錄影檔。
>   報告的職能是陳述發生了什麼；證物本體屬取證動作，於介面上逐筆個別取得並各自留痕。
>   走**同步**匯出（本端點 `GET /audit-export`），既有呼叫端行為不變。
> - **證據包**（`pack=evidence_bundle`）：含操作審計、指令、**剪貼簿內容全文**、關聯會話錄影**本體**，
>   以及告警／檔案傳輸的事件事實。體積不可控，改為**非同步**交付——**不由本端點回傳**，改經下方
>   `POST /audit-export/jobs` 發起、由申請者本人限時下載。
>
> **`pack` 缺席時沿既有推斷**（帶 `subject` 或 `types`＝事件報告，否則證據包）：不帶 `pack` 的既有
> 呼叫端行為逐位不變。證據包自此也吃樞紐（`subject`）後，`subject` 不再單獨分辨得出包型，故以 `pack` 明示為正解。

```
GET /api/v1/audit-export
```

**同步匯出，僅事件報告。** 證據包模式一律以 **400 `RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY`** 拒絕
（**不轉為 job 發起**——安全方法 GET 不得產生建立副作用，否則快取／預取／重試會誤觸發起；
拒絕在設定任何串流標頭之前，回應零 bundle 位元組）。

**權限**: `audit:view`
**Produce**: `application/zip`（`Content-Disposition: attachment; filename="audit-evidence-<時間戳>.zip"`）

**Query 參數**（至少須指定一個範圍條件，全無條件回 400，避免匯出整庫；
任一參數解析失敗回 400 `VALIDATION_INVALID_QUERY_PARAM` 並帶 `field`，**不靜默忽略**）:
| 參數 | 類型 | 說明 |
|------|------|------|
| `pack` | `event_report`｜`evidence_bundle` | 包型明示（缺席沿舊推斷；未知值→400 `field=pack`）。本同步端點僅受理 `event_report` |
| `session_id` | uint | 指定單一會話；**事件報告模式不接受**（證據包模式接受） |
| `user_id` | uint | 使用者 ID；`subject=user` 時即樞紐 id（必填） |
| `asset_id` | uint | 資產 ID；`subject=asset` 時即樞紐 id（必填） |
| `start_time` | RFC3339 | 起始時間；事件報告模式必填 |
| `end_time` | RFC3339 | 結束時間；事件報告模式必填，且須晚於 `start_time` |
| `subject` | `user`｜`asset` | 樞紐宣告。事件報告模式**必填**；證據包模式**選填**（帶了即比照校驗其 id） |
| `types` | csv | 類別篩選，值域同時間軸：`session`／`command`／`audit_log`／`file_transfer`／`clipboard`／`alert`。空＝六類全收；未知值回 400。**事件報告**模式缺 `subject` 而單獨帶 `types` 回 400；**證據包**模式選 `alert`／`file_transfer` 時須同時帶樞紐與正向時間窗（否則 400 `field=subject`／`range`） |

**ZIP 內容（事件報告模式，本端點同步產出）**: 逐類別各一個 CSV，第一欄一律為紀錄編號
`record_ref`（格式 `<類別>:<編號>`，與時間軸事件 id 同源，可回系統查對原始紀錄）。
- `sessions.csv` — 含 `recording_state`（`available`／`purged`／`none`）與 `recording_error`；**不含錄影本體**
- `commands.csv` — 含 `command_seq`、`command`
- `audit_logs.csv`／`file_transfers.csv` — 同表互斥切分（後者為 `resource=file`）
- `clipboard_events.csv` — 含 `direction` 與 `content_length`；**不含內容**
- `alerts.csv` — 含規則、風險等級、是否阻斷、審閱處置
- `manifest.json`（＋ `manifest.sig`）

**ZIP 內容（證據包模式，經 job 產出）**：**未被選取的類別段整段不入包**（其 `counts`／`truncated`
鍵一併缺席——寫個 0 會讓「沒選」與「選了但範圍內沒有」看起來是同一回事）。`types` 缺席＝六類全收。
- `audit_logs.json` — 操作日誌（`asset_id` 篩選已套用，manifest 標明該關聯的歷史起始邊界）〔類別 `audit_log`〕
- `commands.csv` — 指令流〔類別 `command`〕
- `clipboard_contents.json` — 剪貼簿**解密全文**，逐筆含 `record_ref`／`id`／`session_id`／`occurred_at`／`direction`／`content_status`／`content_length`／`content`（缺口列 `content_status=failed`、`content` 鍵缺席）〔類別 `clipboard`〕
- `recordings/session-<id>.<ext>` — 有錄影的會話本體（`.cast`/`.guac`；逐檔跳過缺失，不阻斷整包）〔類別 `session`〕
- `alerts.csv`／`file_transfers.csv` — 無本體之類別以**事件事實**列入（重用事件報告的寫入器）〔類別 `alert`／`file_transfer`〕
- `manifest.json`（＋ `manifest.sig`）

**manifest.json 欄位**:
| 欄位 | 說明 |
|---|---|
| `mode` | `evidence_bundle`｜`event_report`（置於最前，讀者須先知道拿到的是哪一種包） |
| `exported_by`／`exported_by_id`／`exported_at` | 保管鏈（`exported_at`＝實際打包執行時刻） |
| `job_requested_at` | 證據包專屬：job 發起時刻。與 `exported_at` 併為**雙時戳**，使收包方能判斷內容對應的資料時點 |
| `filter` | 原始查詢條件字串化 |
| `scope` | 事件報告專屬：樞紐、樞紐 id 與名稱、時間區間、類別 |
| `selected_types` | 證據包專屬：本包實際收錄的類別清單（缺席＝展開為全部六類） |
| `files[]` | 各檔 `name`／`size`／`sha256` |
| `counts` | 本包**收錄**筆數（逐類別；未選類別鍵缺席） |
| `totals` | 範圍內**真實**筆數（逐類別，不受上限影響）。與 `counts` 不等即代表截斷 |
| `truncated` | 逐類別截斷旗標 |
| `clipboard` | 證據包剪貼簿段三數：`events`（事件總數）／`content_available`（內容可用）／`content_failed`（留存失敗） |
| `coverage[]` | 逐類別保留覆蓋三態（`present`／`purged`／`not_retained`）＋保留天數、清除截止與最近清除時刻、`archive_unit_range`（封存單位編號區間）、`note_code`＋`note_params` |
| `signed`／`signed_reason` | 是否已簽章；未簽時給機器碼原因（**不靜默省略**） |
| `disclosures[]` | 這個包能證明什麼、不能證明什麼（`code`＋選用 `params`；`export.proves.*` 全數排在 `export.limit.*` 之前）。證據包含明文剪貼簿內容時，**明載本包含明文內容**（僅 `content_available>0` 時寫入——全缺口包不宣告，宣告即假警報） |
| `note_codes` | 各段的範圍說明機器碼（如資產關聯的歷史邊界） |

**manifest 內零散文**：`coverage[].note_code`、`disclosures[].code`、`note_codes`
一律只給機器碼與參數，不含任何自然語言句子（後端零散文出站，三語才可能齊備）。
對應文字由 i18n 依碼提供；**目前的已知缺口**：離線開包的讀者只會看到碼，
需要可讀說明時請在系統介面上檢視同一組碼的說明。

**上限**（超過即截斷並於 manifest 標明，不靜默截斷）:
證據包＝操作日誌 50000、指令 50000、錄影 100 檔；事件報告＝**每一類別各自** 50000 列
（刻意不共用總上限，否則「哪一類被截斷」不可辨識）。

**完整性判準**: `manifest.json` 是最後寫入的檔案。**包內若無 `manifest.json`，
即代表匯出中途失敗、此包不完整，不得作為證據**——事件報告一旦開始串流 body 即無法改狀態碼，
故串流中途失敗只記伺服器日誌並留一筆失敗審計（HTTP 狀態已為 200）；證據包則由 job worker
於背景寫檔，失敗落 job `failed` 態並清除半成品。

**離線驗簽**: 取公鑰 `GET /api/v1/audit-export/public-key`（base64 Ed25519），
以該公鑰對 ZIP 內 `manifest.json` 的**位元組**驗證 `manifest.sig`（base64 簽章）；
通過即證明清單與其中每個檔案的 SHA-256 自匯出後未被更動。
`tools/checkpoint-verify/` 是封存鏈的獨立驗證工具，**不涵蓋匯出包**（已知缺口，明載不粉飾）。

**錯誤**: 400 未指定任何篩選條件（`VALIDATION_AUDIT_EXPORT_FILTER_REQUIRED`）；
400 參數不合法（`VALIDATION_INVALID_QUERY_PARAM`，`params.field` 指出是哪一個）；
400 對同步端點請求證據包（`RULE_AUDIT_EXPORT_BUNDLE_ASYNC_ONLY`）。

### 證據包非同步 job 端點

> 證據包體積不可控，改為非同步：發起後進入打包排程，產物落於系統指定暫存位置
>（`EXPORT_ARTIFACT_PATH`，預設 `/var/lib/custodexa/exports`），由申請者本人限時下載。
> 三端點同屬 `/audit-export` 路由群、同掛 `audit:view`；下載另綁**申請者本人**。
> 產物保留 **24h**（逾期自動清除並轉 `expired`）；job 終態紀錄另有 30 天保存期，兩者分別計。

```
POST /api/v1/audit-export/jobs                發起打包（僅證據包）
GET  /api/v1/audit-export/jobs                申請者本人的 job 清單（分頁）
GET  /api/v1/audit-export/jobs/:id/download   下載產物（綁申請者本人）
```

**POST `/audit-export/jobs`**（發起）：篩選參數與同步端點同一套解析。僅受理證據包——
帶 `subject` 或 `types`（即被推斷為事件報告）者回 **400 `RULE_EXPORT_JOB_BUNDLE_ONLY`**。
- **回應** (202): `{"data": ExportJob, "deduplicated": <bool>}`。命中 `pending`／`running` 去重時回既有 job（`deduplicated=true`，冪等，非錯誤）。
- **額度**: 每申請者進行中（`pending`＋`running`）上限 3、全域 10；上限檢查與 job 建立為原子。超額回 **409 `CONFLICT_EXPORT_JOB_LIMIT`**。
- 發起（成功與被拒）皆入審計，含完整篩選快照。

**GET `/audit-export/jobs`**（清單）：`page`（預設 1）／`page_size`（預設 20），id 降冪穩定排序。
**僅列申請者本人**的 job（與下載授權同判準）。回應 `{"data": [ExportJob], "total": N, "page": P, "page_size": S}`。

**GET `/audit-export/jobs/:id/download`**（下載）：認證＋`audit:view` 由路由群承擔，本端點另加**申請者本人**。
- 成功回產物 ZIP（`attachment; filename="audit-evidence-job-<id>.zip"`），下載入審計（誰、何時、哪個包＋SHA-256）。
- **非申請者**（含其他具 `audit:view` 帳號）、job 不存在、識別非法：一律收斂 **403 `AUTH_EXPORT_JOB_REQUESTER_ONLY`**
  （分成 404/403 會讓具權限的探測者以狀態碼枚舉 job 存在性；真實原因只進審計）。
- 申請者本人但**不可下載態**（`pending`／`running`／`failed`／`expired`、或產物已清）：**410 `RULE_EXPORT_ARTIFACT_UNAVAILABLE`**。

**離機退路**（本機產物不可讀時）：上述可下載性判定**先於**任何取回動作——逾期的 job 即使遠端副本仍在，
一樣回 410。通過判定後，本機產物檔缺席或大小與紀錄不符，而該 job 有離機帳冊列時，改由物件儲存取回，
**驗過 SHA-256 與大小才交付**；驗證不符或該世代不可用時回 **409 ＋離機機器碼**（四碼同錄影側，
見〈來源判定與離機退路〉），零位元組交付並留審計。帳冊記載「從未上傳」而本機產物仍在者，
照常交付本機那一份（既有行為不變）。

**產品不代刪遠端**：產物到期（24h）只清本機產物檔並轉 `expired`，job 列的 30 天保存期到期只清 job 列
——**兩者都不對物件儲存發出刪除**。已離機的證據包副本何時消失，取決於部署方在儲存桶上設定的
生命週期規則；產品不偵測、不同步這兩個期限。

**ExportJob 回應投影**（顯式 DTO；`artifact_path`／`filter_json` 為伺服器內部，不出站）:
| 欄位 | 說明 |
|---|---|
| `id` | job 識別 |
| `status` | `pending`／`running`／`done`／`failed`／`expired` |
| `requested_at` | 發起時刻 |
| `artifact_size` | 產物位元組大小 |
| `filter` | 篩選條件的顯示投影（`DisplayMap`；id 字串化，不含名稱） |
| `artifact_sha256` | 產物 SHA-256（done 後出現） |
| `error_summary` | 失敗摘要機器碼（`export_job.pack_failed`／`export_job.requester_revoked`；`failed` 時出現） |
| `packaged_at` | 實際打包完成時刻（done 後出現） |
| `expires_at` | 產物過期時刻（done 後出現） |
| `offsite_status` | 產物副本的離機狀態；**恆輸出**（未進佇列時為空字串），值域同 Session 的同名欄 |
| `offsite_sha256` | 已離機副本的 SHA-256（僅 `uploaded` 態出現）。**與 `artifact_sha256` 不同源**：前者取自保管帳冊（上傳當下量得），後者是打包完成時記的產物雜湊 |

> 投影**刻意不輸出帳冊識別碼**：那對申請者無用——重試離機上傳是管理員在離機儲存頁的動作。

打包 worker 對申請者於**領件與每次重試時**重驗主體狀態與 `audit:view` 權限——已停用／刪除／失權者
job 取消（落 `failed`＋`error_summary=export_job.requester_revoked`）並清除已產出的產物；worker 異常
不終止服務行程，重試上限 3，服務重啟時遺留的進行中 job 可恢復或重排。

---

## 存取複審 API（PCI 7.2.4）

> 週期性存取複審 v1：矩陣檢視與複審歷史限 `audit:view`；提交簽核限 admin（管理層確認語意）。
> 一筆簽核＝複審者＋時間＋範圍＋結論＋複審當下的存取矩陣 JSON 快照（append-only 不可變證據）。

### 存取矩陣

```
GET /api/v1/access-reviews/matrix
```

**權限**: `audit:view`

當下完整存取矩陣（所有授權展開，join 用戶/資產/群組名稱）。

**回應** (200): `{"data": [AccessMatrixEntry], "total": N}`
```json
{
  "authorization_id": 1,
  "user_id": 2,
  "username": "user1",
  "asset_id": 1,
  "asset_name": "Server1",
  "permission": "connect",
  "granted_by": 1,
  "granted_at": "2026-07-01T00:00:00Z"
}
```
主體 `user_*` 與 `user_group_*`（`user_group_id`/`user_group_name`）二擇一、
客體 `asset_*` 與 `asset_group_*`（`asset_group_id`/`group_name`）二擇一，
未使用側省略（omitempty）。

### 複審歷史

```
GET /api/v1/access-reviews
```

**權限**: `audit:view`

近 50 筆複審簽核（`reviewed_at` 倒序）＋距上次複審天數（供存取複審頁逾期提示）。

**回應** (200): `{"data": [AccessReviewView], "last_review_days_ago": N, "review_period_days": 180, "overdue": false}`
- `last_review_days_ago`: 整數天數；`-1` 表示從未複審
- `review_period_days`/`overdue`: 建議週期（v1 固定 180）與逾期判定，伺服端單源回傳，前端不硬編碼
  （週期政策鍵化登 backlog）
- `AccessReviewView` 為 AccessReview 欄位（不含大型 `matrix_snapshot`）＋ `days_ago`

### 單筆複審檢視

```
GET /api/v1/access-reviews/:id
```

**權限**: `audit:view`

單筆簽核完整內容：中繼資料＋`matrix`（快照 `json.Unmarshal` 後的 `[AccessMatrixEntry]` 型別化陣列）。
快照損壞回明確 500（不回空內容）；不存在 404。路由註冊 `/matrix` 先於 `/:id`。

> 複審四端點（matrix/list/:id/POST）權限一律**無條件**強制（讀取 `audit:view`、簽核 admin），
> 無條件強制（比照 session 敏感讀取端點先例）。
> UI 入口為審計區「存取複審」獨立頁（admin＋auditor；自資產授權頁遷出）。

### 提交複審簽核

```
POST /api/v1/access-reviews
```

**權限**: admin only（`RequireRole("admin")`，管理層確認語意）

快照當下存取矩陣並記一筆簽核；動作入審計（`resource=access_review`、`action=create`）。

**請求**（`note` 選填）:
```json
{"note": "本季存取權複審完成，無異常授權"}
```

**回應** (201): `AccessReview` JSON（不含 `matrix_snapshot`，避免回應肥大）
```json
{
  "id": 1,
  "reviewed_by": 1,
  "reviewer_name": "admin",
  "reviewed_at": "2026-07-03T00:00:00Z",
  "scope": "全部使用者存取權（user × asset/group × permission）",
  "note": "本季存取權複審完成，無異常授權",
  "authorization_count": 12,
  "created_at": "2026-07-03T00:00:00Z"
}
```

簽核為不可變證據：ORM 層 `BeforeUpdate`/`BeforeDelete` 拒絕修改與刪除（縱深防禦），無更新/刪除路由。

---

## 命令片段 API

> user-scoped：查詢一律帶 user_id 條件，他人資源視為不存在（404）。內容僅注入終端輸入，不直接執行。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/snippets` | 當前用戶全部片段 → `{data, total}` |
| POST | `/snippets` | body: `{"name": "...", "content": "..."}` → 201 |
| PUT | `/snippets/:id` | 更新 |
| DELETE | `/snippets/:id` | 刪除 → `{}` |

`name` 上限 128、`content` 上限 4096 字元（超出 400）。

---

## 改密 API（admin only）

輪換 SSH 資產憑證：**帳號級**密碼改密與 SSH 金鑰輪替。執行記錄與任何回應皆不含秘密材料。

| 方法 | 路徑 | 說明 |
|---|---|---|
| GET | `/change-secret-plans` | 計劃列表 → `{data, total}` |
| POST | `/change-secret-plans` | 建立 → 201 |
| PUT | `/change-secret-plans/:id` | 更新（CUD 後排程器即時重載） |
| DELETE | `/change-secret-plans/:id` | 刪除 |
| POST | `/change-secret-plans/:id/run` | 手動觸發（異步）→ 202 `{}` |
| GET | `/change-secret-plans/:id/records?limit=100` | 執行記錄 → `{data, total}` |
| GET | `/change-secret-candidates` | 未驗證憑證清單 → `{data, total}`（**不含任何秘密材料**） |
| POST | `/change-secret-candidates/:id/retry` | 立即重試一次 → `{promoted: bool}` |
| DELETE | `/change-secret-candidates/:id` | 清除候選（破壞性，見下）→ 200 `{}` |

**請求**（`ChangeSecretPlanRequest`）:
```json
{
  "name": "每月輪換", "asset_ids": [1, 3], "accounts": ["@ALL"],
  "secret_type": "password", "key_strategy": "append_replace",
  "password_length": 16, "password_include_symbol": true,
  "password_exclude_ambiguous": true,
  "cron": "0 3 1 * *", "enabled": true
}
```

- `accounts`：帳號範圍。`["@ALL"]`（預設）＝該資產全部帳號；否則為帳號 username 明列集合。
  空值一律讀成 `@ALL`。
- `secret_type`：`password`（chpasswd）或 `ssh_key`（authorized_keys 輪替）；其他值回 400
  `VALIDATION_PLAN_BAD_SECRET_TYPE`。
- `key_strategy`（僅 `ssh_key`）：`append_replace`（預設，加新 → 驗新 → 刪舊，零鎖死）或
  `exclusive`（清空重寫，高風險）；其他值回 400 `VALIDATION_PLAN_BAD_KEY_STRATEGY`。
- 密碼策略：長度 12–64（預設 16，越界回 400 `VALIDATION_PLAN_BAD_PASSWORD_LENGTH`）、是否含符號、
  是否排除易混淆字元。**shell 敏感字元與控制字元為系統級硬排除，無任何設定可放寬**。
- `cron` 空值＝僅手動觸發；非法 cron 回 400；名稱重複 409。

**執行記錄欄位**: `{id, plan_id, asset_id, account_id, account_username, secret_type, status, error, executed_at}`；
`status`:

| 值 | 語義 |
|---|---|
| `success` | 已驗證並提交為帳號憑證 |
| `failed` | 遠端**確定未變更**（指令非零退出／登入失敗）；帳號憑證原樣，無殘留候選 |
| `unverified` | 遠端狀態**不可知**或驗證未通過；帳號憑證維持舊值，候選保留待系統重試 |
| `skipped` | 非 SSH 資產、無可用憑證、或該帳號已有未驗證候選 |

**未驗證憑證（候選）**：新秘密於動遠端**之前**即加密落庫，驗證成功才提交為帳號憑證並立即刪除候選。
候選內容**不出現於任何 API 回應、UI、日誌或審計欄位**，只供系統重試登入。清單欄位為
`{id, asset_id, account_id, account_username, plan_id, secret_type, applied, abandoned, attempt_count,
last_attempt_at, next_attempt_at, last_error, created_at}`。

系統以指數退避重試（上限 1 小時、總期限 24 小時），逾期標 `abandoned` 並告警；**已放棄的候選不會被
系統自動刪除**——它是那把可能已在遠端生效的秘密的唯一副本。`DELETE` 為 admin 的顯式逃生口，
會產生審計記錄；清除後若遠端確實已改密，只能以主機 console 等帶外途徑重設救回。

---

## 營運指標端點（Prometheus）

```
GET /metrics
```

**路徑刻意不在 `/api` 之下**。正式版 edge（`docker/frontend/nginx.conf`）只代理 `location /api`
與 `/ws`，`/metrics` 不在其中——故本端點在**預設部署下自外部打不到**，這道安全性由拓撲保證，
而非由「有沒有記得掛上認證中介層」這種每次改路由都可能失手的人為保證。


**認證**: 由 `METRICS_TOKEN` 環境變數決定

| `METRICS_TOKEN` | 行為 |
|---|---|
| 未設（預設） | 免認證曝光；安全性由「edge 不代理」承擔 |
| 已設 | 強制 `Authorization: Bearer <token>`，常數時間比對。不符回 **401**，且回應體不含任何指標名稱或值；401 不區分「未帶 token」與「token 錯誤」 |

**要對外暴露就必須同時設 token**：跨機採集需要在反向代理上另開 `/metrics` 通道，
該動作與設定 `METRICS_TOKEN` 是同一件事的兩半——不存在「只開洞、不設 token」的正當中間狀態，
否則等於把端點清單、各功能使用量與錯誤率公開。

**回應** (200): Prometheus 文字曝光格式，`Content-Type: text/plain; version=0.0.4; charset=utf-8`，
含 `# HELP`／`# TYPE` 標頭，標準採集端可直接解析。

**指標盤**（`custodexa_` 前綴，單位入名，累計量以 `_total` 結尾）:

| 指標 | 型別 | 標籤 |
|---|---|---|
| `custodexa_active_sessions` | gauge | `protocol` |
| `custodexa_active_connections` | gauge | — |
| `custodexa_recording_storage_bytes` | gauge | — |
| `custodexa_command_alerts_pending` | gauge | `severity`（未審閱數，非累計產生數） |
| `custodexa_audit_queue_depth` | gauge | — |
| `custodexa_audit_dropped_total` | counter | `reason`（`fallback_file` 降級寫檔／`discarded` 永久遺失） |
| `custodexa_seal_state` | gauge | `state`（列舉形態：目前所處的態為 1、其餘為 0） |
| `custodexa_instance_guard_held` | gauge | —（單實例鎖是否由本實例持有：1 持有、0 未持有） |
| `custodexa_instance_guard_lost_total` | counter | —（本行程偵測到失鎖的累計次數） |
| `custodexa_instance_guard_overridden` | gauge | —（本實例以 `INSTANCE_GUARD_ACK` 啟動且尚未取得鎖：1 是、0 否） |
| `custodexa_instance_guard_peers` | gauge | —（偵測到的其他守衛版實例連線數；同一資料庫、同 `application_name`） |
| `custodexa_http_requests_total` | counter | `method`, `path`, `status` |
| `custodexa_http_request_duration_seconds` | histogram | `method`, `path` |
| `go_*` / `process_*` | — | Go runtime 標準 collector |

`path` 標籤一律取**路由模板**（`/api/v1/assets/:id`）而非實際 URL；未匹配任何路由的請求
歸入單一固定值 `<unmatched>`，使序列數不隨資料量或掃描次數成長。

**高成本指標讀的是快取值**：活躍會話（查資料庫）與錄影儲存量（遍歷檔案系統）由背景任務
定期刷新（預設 30 秒）後供讀取，不於每次採集時同步查詢；其值因此最多落後一個刷新週期。

**封印期（尚未解封）可採集，但只有縮減盤**：僅曝光 `custodexa_seal_state`、四條 `custodexa_instance_guard_*`
序列與 Go runtime 指標，使監控能區分「系統封印中待解封」與「系統當機」——兩者的處置完全不同。
守衛序列自段 1 起就存在（守衛在 migration 之前取鎖），封印期即可看到 `overridden`／`held`。封印期尚未建構的服務
（會話、錄影、審計佇列、HTTP 統計），其指標**缺席而非為 0**：0 值會讓採集端把「服務不存在」
讀成「服務正常且計數為零」，而缺值在 PromQL 中可由 `absent()` 明確偵測。守衛序列同理：
資料源未注入時四條序列缺席而非為 0。

**守衛序列的判讀**：`held 1／overridden 0／peers 0` 是正常態；`held 0` 配 `overridden 1` 表示本實例以確認碼啟動、
尚未取得鎖；`held 0` 配 `overridden 0` 表示執行期失鎖（`lost_total` 同步加 1）；`peers > 0` 表示持鎖實例看到了
其他守衛版實例的連線。四條序列都是**行程本地**的：兩個實例並存時各報各的，不做跨副本聚合。
守衛失鎖不影響 `/health`。營運面判讀見 `docs/ops/upgrade-sop.md` §3.4。

**多副本下各報各的**：行程內 gauge（活躍連線、佇列深度）不做跨副本聚合，與現行單實例部署
不變式一致。

---

## WebSocket 連線

### 圖形協議連線（RDP/VNC，經 guacd）

```
GET /api/v1/connect?connect_token=<token>&width=<px>&height=<px>
Upgrade: websocket（子協議 guacamole）
```

**認證**: 僅收一次性 `connect_token`（授權與傳輸政策閘於簽發時完成；缺省或無效回 401）。
本端點**僅接受一次性 `connect_token`**：不接受以 query 參數攜帶 JWT 或 `asset_id` 直連——
那會繞過簽發閘，連同其上的授權檢查與傳輸政策一併落空。
兌換時重載狀態（殘窗收斂）：使用者停用 403／鎖定 423；資產停用 403＋`{reason: "asset_disabled"}`；
**兌換當下的來源不在該帳號的允許來源網段** 403＋`{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`
——token 簽發後、兌換前被停用或來源改變者同擋，不因 token 尚在效期放行。

**連線收口**:
- 只收 token + asset_id；目標主機與憑證由後端從資產庫解密注入 guacd 握手，
  前端與 URL 全程不出現 hostname/username/password（帶 `hostname`/`password` 參數直接 400）
- SSH 已退出此路徑：`protocol=ssh` 資產回 400，請改用 `GET /api/v1/ssh`
- RDP 啟用磁碟重導（Shared drive，每連線獨立路徑）；RDP/VNC 皆啟用 Guacamole 原生錄製（`.guac`）
- RDP/VNC 剪貼簿內容旁路留存

### 文字終端連線（SSH / 資料庫 CLI / K8s exec）

```
GET /api/v1/ssh?connect_token=<token>&cols=<n>&rows=<n>[&k8s_mode=][&k8s_pod=][&k8s_container=]
Upgrade: websocket
```

**Query 參數**:
| 參數 | 必填 | 說明 |
|------|------|------|
| `connect_token` | 是 | 一次性連線 token（唯一入口；缺省 401。舊 `?token=<jwt>`+`asset_id` 直連已移除） |
| `cols`, `rows` | 是 | 初始終端尺寸（1-1000 / 1-500，超界 400） |
| `k8s_pod` | k8s 必填 | 連線目標 pod（namespace 取自資產，server-trusted） |
| `k8s_container` | 否 | 容器名（缺省用 default annotation 或第一個容器） |
| `k8s_mode` | 否 | 空＝互動 shell；`logs`＝kubectl logs -f 唯讀；`oneshot` 目前一律拒絕（400，v1.1 再開放） |

**行為**:
- 憑證後端解密注入（SSH）；mysql/postgres/redis/mssql 以本地 CLI 子程序 + PTY 代理；k8s 走 kubectl exec/logs
- SSH 握手/CLI 啟動在 WS 升級前完成；失敗時對 WS 升級請求改為升級後送 `{"type":"error", "code", "data"}` 再關閉
  （瀏覽器讀不到握手失敗的 HTTP body），非 WS 請求維持一般 HTTP 錯誤（502 為主）。
  SSH 撥號失敗帶 `RULE_SSH_*` code（`HOST_KEY_CHANGED`／`AUTH_FAILED`／`DIAL_TIMEOUT`／`UNREACHABLE`，
  入 apierror registry 受三語完備性守衛）；k8s/database 啟動失敗僅帶 `data` zh 文案
- 兌換時重載狀態（殘窗收斂）：使用者停用/鎖定即擋；資產停用回 403＋`{reason: "asset_disabled"}`（簽發後停用者同擋）；
  來源不在允許來源網段回 403＋`{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`（**兌換當下現讀清單，不信簽發時的判定**）
- 全模態 asciinema 錄製；指令審計與阻斷（K8s logs 唯讀模態除外）；接入即時監看 room
- 閒置/最大時長自動斷線：由安全政策 `session_idle_minutes`（出廠預設 **60**）與 `session_max_minutes`（0＝不限）決定。
  `SSH_IDLE_TIMEOUT_MINUTES`／`SSH_MAX_SESSION_MINUTES` 僅於首次啟動播種政策列；生產路徑一律走政策，
  env 值不再生效（handler 內的 30 分鐘僅為政策未注入時的 fallback，正常部署不可達）

**WS 訊息協議**（JSON envelope，雙向）:
```json
{"type": "data|resize|ping|pong|connected|error", "data": "...", "code": "..."}
```
`resize` 的 data 為 `{"cols": N, "rows": N}` JSON 字串；`code` 僅 `error` 訊息使用（機器可讀錯誤碼，可缺省）。

### 一次性連線 token 簽發

```
POST /api/v1/connect-tokens
Authorization: Bearer <token>
```

**請求**: `{"asset_id": 1, "account_id": 3}`（`account_id` 選填，省略／0＝該資產的預設帳號）
**回應** (200): `{"connect_token": "<hex>", "expires_in": 60}`

簽發時完成資產存在性與連線授權檢查（資產不存在 404、無授權 403）；
token 綁定 user+asset+account，Resolve 即焚。guacd 與原生 SSH 兩路徑共用同一 token 管理器。

**允許來源網段**：簽發端也判來源，位置在角色現查之後、請求綁定之前——只依主體判定，
不需要資產，也就不對「來源不對」的請求洩漏資產是否存在或有無授權。
不落清單回 **403 ＋ `{code: "AUTH_SOURCE_NOT_ALLOWED", reason: "source_not_allowed"}`**。
兩條兌換入口（`/connect`、`/ssh`）**各自現讀清單再判一次，不信簽發時的結論**：
只擋簽發側時，自允許網段簽票、換個位址兌換即成立。
`reason` 值刻意不與 `asset_disabled`／`recording_unavailable`／`approval_required`／`reason_required`
重疊，前端據此顯示「目前來源不在允許範圍」而**不彈申請框**。
**回應不回顯位址，也不回顯清單**；位址與命中的清單快照只進拒絕留痕。
清單讀不到或字串損壞時**走同一組回應值**，對外不分岔——分岔等於告訴呼叫端
「這個帳號的政策壞了」，那是探測面；成因（`read_error`／`parse_error`）只進審計。

`account_id` 為**憑證選擇器、非授權快照**：簽發點於授權檢查之後、
政策閘之前以 `(account_id, asset_id, deleted_at IS NULL)` DB 現查客體綁定，不屬該資產或
已刪除→**404 `NOTFOUND_ASSET_ACCOUNT`**（不區分「不存在」與「屬於他資產」，避免成為帳號探測器）；
K8s 資產固定單一預設帳號，帶 `account_id`→**400 `RULE_ACCOUNT_K8S_DEFAULT_ONLY`**。
兌換點（`/ssh`、`/connect`）以同一條件重查後才取憑證：帳號於簽發後被刪除者兌換即拒
（404 `NOTFOUND_ASSET_ACCOUNT`），**絕不靜默退回預設帳號**。連線成功的 session 記錄
`account_id` 與連線當下的 `account_username` 雙快照，帳號日後改名／刪除不改寫歷史。

### 會話即時監看（admin/auditor）

```
GET /api/v1/sessions/:id/monitor?token=<jwt>
Upgrade: websocket
```

- 僅 admin/auditor（403 否則）；僅進行中的文字終端會話可監看（400 否則）
- 唯讀：觀察者輸入一律忽略；斷線不影響被監看會話
- 會話剛結束的競態：回 `{"type": "error", "data": "會話已結束"}` 後關閉

### 會話分享

| 方法 | 路徑 | 說明 |
|---|---|---|
| POST | `/sessions/:id/share` | 會話本人建立分享碼（JWT）；body: `{"ttl_minutes": 10}`（1-60，預設 10；再建立即覆蓋舊碼）→ `{"code": "...", "share_path": "/share/<code>", "expires_at": "..."}` |
| DELETE | `/sessions/:id/share` | 撤銷分享（JWT；無有效分享回 404） |
| GET | `/sessions/share/:code/ws?token=<jwt>` | 任何已登入用戶持有效碼加入唯讀觀看（WS）；加入由全局審計中間件記錄 |

會話結束時分享自動撤銷。

### 會話即時指標

```
GET /api/v1/ssh/sessions/:id/stats
Authorization: Bearer <token>
```

**授權**: 會話本人或 admin/auditor；非活躍會話回 404（`會話不在線上`）。
僅 SSH 會話支援（DB CLI/K8s 無 SSH channel）；目標主機需支援 `/proc`（否則 502）。

**回應** (200，`SessionStats`；counters 為原始值，CPU%/網速由前端兩次輪詢差分):
```json
{
  "hostname": "server1",
  "uptime_sec": 12345.67,
  "load1": 0.5, "load5": 0.4, "load15": 0.3,
  "mem_total_kb": 8000000, "mem_avail_kb": 4000000,
  "cpu_busy": 12345, "cpu_total": 67890,
  "net_rx_bytes": 1024, "net_tx_bytes": 2048
}
```

---

## 功能開關

以下功能可透過環境變數控制（`backend/config/config.go`）：

| 功能 | 環境變數 | 程式碼預設 | 說明 |
|------|----------|--------|------|
| 審計日誌 | `FEATURE_AUDIT_LOG_ENABLED` | true | API 操作記錄；關閉時 `/audit-logs` 端點不註冊 |
| 異步寫入 | `FEATURE_ASYNC_AUDIT_ENABLED` | true | 異步日誌寫入 |
| 檔案降級 | `FEATURE_AUDIT_FALLBACK_TO_FILE` | true | 寫庫失敗時寫入檔案 |
| 異常偵測 | `FEATURE_ANOMALY_DETECTION_ENABLED` | false | 連線異常偵測 |
| 告警系統 | `FEATURE_ALERTING_ENABLED` | false | 告警通知 |

**其他環境變數**:

| 環境變數 | 預設 | 說明 |
|----------|------|------|
| `RECORDING_PATH` | `/var/lib/custodexa/recordings` | 錄影儲存目錄 |
| `SSH_IDLE_TIMEOUT_MINUTES` | 60 | **僅首次啟動播種政策 `session_idle_minutes`**；之後以政策為準（0＝停用） |
| `SSH_MAX_SESSION_MINUTES` | 0（不限） | 文字終端最大會話時長（同上，播種 `session_max_minutes`） |
| `RECORDING_RETENTION_DAYS` | 未設＝不播種 | 僅首次啟動播種政策 `retention_recording_days`（政策自身出廠值 90） |
| `AUDIT_LOG_PATH` | `logs/audit_fallback`（相對路徑） | 審計寫庫失敗時的降級檔案目錄；compose/生產以掛載卷指定絕對路徑 |
| `KEY_ROTATION_MAX_PER_RUN` | 100000 | 單次 DEK 輪替的重加密上限 |
| `RETENTION_MAX_PER_RUN` | 100000 | 單次保留期清理的刪除上限 |
| `K8S_LIST_TIMEOUT_SECONDS` | 10 | K8s pod 列表逾時（秒） |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗號分隔允許來源；release 模式未設＝僅允許同源 |
| `ADMIN_INITIAL_PASSWORD` | 無預設 | **全新空 DB 必須設定合格值**（>=12 bytes、非預設/placeholder、無前後空白、無換行或控制字元；**中間空白允許**），未設或不合格即 `log.Fatal` 拒絕啟動（不因 dev/release 放寬）；既有 DB 不需要此值，僅在仍留著**合格**值時記警告提醒移除（不合格值於既有 DB 靜默忽略） |
| `LDAP_*` | 見認證 API 一節 | LDAP 認證設定 |
