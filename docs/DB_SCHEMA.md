# Custodexa - 資料庫規格文件

> **最後更新**：2026-09-01（新增 `offsite_profiles`／`offsite_objects` 兩表與兩張擁有表的離機指標欄）

> 資料來源：`backend/internal/database/baseline_schema_{identity,asset,authz,audit,platform}.go`
> **加上其後的增量 migration**（`migration_audit_export_jobs.go`、`migration_evidence_offsite.go`、`migration_source_ip_forensics.go`）——
> 兩段串接即 `migrations.go` 的 `schemaDDLStatements()`，那才是 schema 的**唯一事實源**、
> `backend/internal/database/baseline_seed.go`（內建告警規則種子）、`backend/internal/model/*.go`（欄位語義與 JSON 形狀）、
> `backend/internal/database/database.go` 的 `schemaParityModels`（`schemaDDLStatements()` 必須對得上的 model 清單，**只被驗證、不被執行**）。
> **索引與約束以 `schemaDDLStatements()` 的 DDL 為準**：schema 的唯一事實源是 baseline（`20260816_schema_baseline`）
> **加其後全部增量 migration** 的 DDL 串接；只看 baseline 會讓增量建的表與增量加的欄整張脫離射程
> （parity 守衛因此也解析同一串接，見 `schema_parity_test.go`）。
> 開機不跑 `AutoMigrate`，且 baseline 與各增量的 DDL **一律無條件**（產品程式碼中唯一的 `IF NOT EXISTS`
> 是 `schema_migrations` 自身的 bootstrap 建表）。在非空 schema 上跑 baseline 會立刻失敗，不會靜默 no-op，
> 因此不存在「宣告與現實分岔」的空間。
>
> **逐表欄位表的第 4 欄是 JSON 序列化名，不是資料庫欄名。** 兩者多數相同，但 GORM 的
> `NamingStrategy` 對連續大寫縮寫的斷詞與直覺不同（`DBCACert` → `dbca_cert`，**不是** `db_ca_cert`
> ——`DB` 與 `CA` 都不在 GORM 的 initialism 清單內），且 model 可另給 `json:` 別名。
> **只有兩個持久化欄位的 JSON 名與資料庫欄名不一致**，皆已於該列就地標註：
> `assets.dbca_cert`（JSON `db_ca_cert`）與 `audit_logs.duration`（JSON `duration_ms`）。
> 其餘不一致全部落在 DTO／請求結構，不對應任何資料表。
> **寫 SQL 時一律以 baseline 的 `CREATE TABLE` 為準，不要拿本欄或 API 文件的欄名去查表。**
>
> 相關文件：API 參考見 [API_SPEC.md](API_SPEC.md)；各能力行為規格見 `openspec/specs/`；動到 model 或 baseline 時須同步本文件（見 [CONTRIBUTING.md](../CONTRIBUTING.md)）。

---

## 總覽

**全部應用資料表由單一 baseline 建立**，故「建表來源」欄不再區分 AutoMigrate 與逐條 migration。
該欄只標註 baseline 於建表當下一併建立、且**承載資料層不變式**的 CHECK 與 partial unique index
——那些是「拿掉不會有任何測試變紅、但會讓不合法的列寫得進去」的東西。

| 模型 | 表名 | 建表來源 | 說明 |
|------|------|----------|------|
| User | `users` | baseline（`idx_users_username`／`idx_users_email` 兩條 partial unique）＋增量 `20260826_source_ip_forensics` 加 `allowed_cidrs` 欄 | 系統用戶（含 LDAP 標記、MFA/TOTP、帳號鎖定/強制改密/閒置停用豁免、允許來源網段） |
| Role | `roles` | baseline | 角色定義 |
| - | `user_roles` | baseline | 用戶-角色關聯表（M2M，由 baseline 顯式建表） |
| UserGroup | `user_groups` | baseline | 使用者群組（授權主體分組，與 RBAC 角色正交） |
| - | `user_group_members` | baseline | 用戶-群組關聯表（一人可屬多群；同上，現由 baseline 顯式建表） |
| Asset | `assets` | baseline（`idx_assets_name` partial unique） | 遠端資產（SSH/RDP/VNC/DB CLI/K8s） |
| AssetAccount | `asset_accounts` | baseline（`idx_asset_accounts_default`＝一資產至多一預設、`idx_asset_accounts_username`＝軟刪列不佔名，兩條 partial unique） | 資產系統帳號（一資產多帳號、各自信封加密憑證、至多一 default） |
| AssetGroup | `asset_groups` | baseline（`idx_asset_groups_sibling_name` 同層唯一，partial unique 表達式索引） | 資產節點樹（parent_id 自參照、同層唯一） |
| AssetNode | `asset_nodes` | baseline | 資產×節點成員（多歸屬 M2M） |
| Session | `sessions` | baseline | 連線會話（含 K8s 快照、斷線原因、帳號快照） |
| AssetAuthorization | `asset_authorizations` | baseline（CHECK `chk_auth_target`＋`chk_authz_subject_xor`；四條 partial unique） | 資產授權（主體 user XOR user_group、客體 asset XOR asset_group、時效窗、source 來源標記） |
| AccessRequest | `access_requests` | baseline（`idx_access_request_pending_dedup` partial unique） | 連線申請單（三段存取政策核准流，CAS 狀態機） |
| ApproverScope | `approver_scopes` | baseline（CHECK `chk_approver_scope_actor`＋`chk_approver_scope_target`；八條 partial unique） | approver 審核範圍（資產/節點/申請人/使用者群組四維恰一） |
| AccessRequestApproval | `access_request_approvals` | baseline | 申請單核准逐票記錄（quorum，同單同人唯一） |
| AuditLog | `audit_logs` | baseline | 審計日誌（不可變） |
| SessionCommand | `session_commands` | baseline | 文字終端指令審計記錄 |
| AlertRule | `alert_rules` | baseline（CHECK action／severity；`uniq_alert_rules_name` 唯一索引＝種子 `ON CONFLICT` 的衝突目標）＋`baseline_seed.go` 種入 12 條內建規則 | 危險指令告警/阻斷規則 |
| CommandAlert | `command_alerts` | baseline（CHECK severity／kind／kind↔rule_id；**刻意無 FK**——rule_id/session_id 為觸發快照冗餘，規則改名或刪除不得破壞歷史告警） | 危險指令告警記錄（含審閱處置欄位） |
| NotificationChannel | `notification_channels` | baseline（CHECK type／language） | 告警 webhook 通知通道 |
| ClipboardEvent | `clipboard_events` | baseline | RDP/VNC 剪貼簿內容留存（內容信封加密，`content_enc` 登記於 `envelopeMigrationTargets`；另存 `content_length`／`content_status`） |
| AssetHostKey | `asset_host_keys` | baseline | SSH host key TOFU 記錄 |
| Snippet | `snippets` | baseline | 使用者命令片段 |
| ChangeSecretPlan | `change_secret_plans` | baseline | 改密計劃 |
| ChangeSecretRecord | `change_secret_records` | baseline | 改密執行記錄 |
| ChangeSecretCandidate | `change_secret_candidates` | baseline | 未驗證候選憑證（一帳號至多一筆，`account_id` 唯一）。`password_enc`／`private_key_enc` 登記於 `envelopeMigrationTargets` |
| SecurityPolicy | `security_policies` | baseline | PCI 安全政策 key-value |
| PasswordHistory | `password_histories` | baseline | 密碼歷史，防重用（PCI 8.3.7） |
| RefreshToken | `refresh_tokens` | baseline | Web 會話 refresh 憑證（PCI 8.2.8） |
| AccessReview | `access_reviews` | baseline | 週期性存取複審簽核（不可變，PCI 7.2.4） |
| DailyReviewLog | `daily_review_logs` | baseline | 每日審閱簽核（PCI 10.4.1） |
| AuditFailureEvent | `audit_failure_events` | baseline（`idx_failure_events_single_open`＝一機制至多一未結案失敗區間，partial unique） | 審計機制失效事件（PCI 10.7.2/10.7.3） |
| SyslogSetting | `syslog_settings` | baseline | syslog 轉發設定（PCI 10.3.3） |
| ExportSigningKey | `export_signing_keys` | baseline | 匯出簽章金鑰（PCI 10.3.4） |
| IntegrityBaseline | `integrity_baselines` | baseline | 完整性啟用基準（PCI 10.3.4） |
| AuditCheckpoint | `audit_checkpoints` | baseline | 審計檢查點鏈（id 區間聚合＋鏈接＋Ed25519 簽章，偵測「列被刪」） |
| CheckpointSigningKey | `checkpoint_signing_keys` | baseline | 檢查點鏈簽章鑰（Ed25519，自始帶版本欄；`private_key_enc` 登記於 `envelopeMigrationTargets`） |
| AuditCheckpointTrim | `audit_checkpoint_trims` | baseline | 檢查點鏈修剪記錄（殘鏈的新起點錨定，不可變；刻意獨立於 audit_logs——留痕會過期，錨定不會） |
| AuditChainVerifyState | `audit_chain_verify_states` | baseline | 檢查點鏈兩層自動驗證的營運狀態（單列，ID 恆為 1；兩層各記最近執行時點、滾動重驗位置、未結案失敗區間集合）。**營運狀態非證明**：不在鏈的覆蓋範圍內，具 DB 寫入權者可改 |
| AuditRetentionWatermark | `audit_retention_watermarks` | baseline（`class` 唯一索引；**無 `deleted_at`**——本表永不刪除） | 保留期清除水位（每類別一列，永久保留；稽核工作台的 `present`／`purged` 三態來源） |
| AuditExportJob | `audit_export_jobs` | **migration（增量 `20260824_audit_export_jobs`，非 baseline）** | 證據包非同步匯出 job 追蹤（純狀態表，非證據；申請者本人綁定、部分唯一索引去重） |
| UserSourceIP | `user_source_ips` | **migration（增量 `20260826_source_ip_forensics`，非 baseline）** | 帳號×來源位址的「已見」基準（新來源位址告警的判定依據，**非證據**、不受保留政策清除；複合主鍵，刻意無 FK） |
| OffsiteProfile | `offsite_profiles` | **migration（增量 `20260825_evidence_offsite`，非 baseline）**（CHECK `offsite_profiles_singleton_check`＋`offsite_profiles_credential_mode_check`；`idx_offsite_profiles_current` partial unique＝現行世代至多一列） | 離機儲存的設定世代目錄（每列一個世代，連線參數＋憑證模式）；`credentials_enc` 登記於 `envelopeMigrationTargets` |
| OffsiteObject | `offsite_objects` | **migration（增量 `20260825_evidence_offsite`，非 baseline）**（`uniq_offsite_objects_owner_generation` 唯一索引＋兩條 partial index） | 離機保管帳冊（每個上傳目標一列，遠端物件的身分與狀態機；**帳冊即佇列**） |
| DataKey | `data_keys` | baseline（`idx_data_keys_purpose_version_kek`＝同 slot 至多一列帶材料，partial unique） | 信封加密金鑰表（KEK 包裹的 DEK/HMAC 鑰）；`kek_id`／`kek_retired_by` 為 `varchar(255)` 以容納外部金鑰引用（KMS ARN） |
| TransmissionConsent | `transmission_consents` | baseline | 傳輸風險同意記錄（per user×asset） |
| OIDCProvider | `oidc_providers` | baseline（`idx_oidc_providers_identity_domain` partial unique） | OIDC 身分提供者設定（多實例並存）；`client_secret_enc` 登記於 `envelopeMigrationTargets` |
| UserExternalIdentity | `user_external_identities` | baseline（`idx_user_external_identities_domain` partial unique） | 使用者的外部身分關聯，鍵為 `(issuer, client_id, subject)` |
| OIDCFlowState | `oidc_flow_states` | baseline（`expires_at` 索引） | OIDC 登入流程的伺服端狀態（state/nonce/PKCE/瀏覽器綁定，一次性消費） |
| OIDCLoginTicket | `oidc_login_tickets` | baseline（`expires_at` 索引） | callback → SPA 的一次性交棒憑證（僅存雜湊） |
| LDAPDirectory | `ldap_directories` | baseline（CHECK `singleton = 1` ＋ `idx_ldap_directories_singleton` partial unique） | LDAP 目錄設定（設定面自 env 遷入 DB）；`bind_password_enc` 登記於 `envelopeMigrationTargets` |
| SchemaMigration | `schema_migrations` | **`RunMigrations` 的 bootstrap DDL**（見下） | migration 版本追蹤（框架內部） |

應用資料表共 **48 張**（46 張 baseline 建的表，扣掉關聯表 `user_roles`／`user_group_members`＝44，
再加 **4 張由 baseline 之後的增量 migration 建的表**：`audit_export_jobs`、`offsite_profiles`、
`offsite_objects` 與 `user_source_ips`）；連同 `schema_migrations` 共 51 張。
baseline 的 DDL 總數為 **188 條**（46 建表 ＋ 26 外鍵 ＋ 116 索引），
另有 **162 條索引**（116 條顯式 `CREATE INDEX` ＋ 46 條主鍵）與 **10 條 CHECK**——**上述三個數字皆只計 baseline，
不含三條增量 migration**：`20260824_audit_export_jobs` 另建 1 表 ＋ 3 索引（含 1 條部分唯一索引）；
`20260825_evidence_offsite` 另建 2 表 ＋ 7 索引（含 5 條部分索引，其一為部分唯一索引）
＋ 4 欄（`sessions` 與 `audit_export_jobs` 各兩欄）＋ 2 條具名 CHECK；
`20260826_source_ip_forensics` 另建 1 表 ＋ 2 索引 ＋ 1 欄（`users.allowed_cidrs`），並重建
`command_alerts_kind_check`（CHECK 條數不變，值域擴充）。三者皆見「Migration 版本一覽」。

**`schema_migrations` 是唯一不由 baseline 建立的表**，也是產品程式碼中唯一的 `IF NOT EXISTS`：
它有雞生蛋問題——必須先於「讀取已套用版本集合」而存在，故不能由 baseline 建立
（baseline 該不該執行，正是靠讀它來判定）。其欄位形狀為 `varchar(50) NOT NULL` / `timestamptz NOT NULL` / PK on version。
DDL 見 `backend/internal/database/migrations.go` 的 `schemaMigrationsBootstrapDDL`。

**開機不跑 `AutoMigrate`**。啟動順序
（`backend/cmd/server/stage1.go`）：`InitDatabase()` → `RunMigrations()` → `SeedDatabase()`。
`RunMigrations` 只做四件事：建 `schema_migrations` → 讀已套用集合 → **fail-close 判定**（見下）
→ 套用未執行的 migration（現況只有 baseline 一條）。

守衛：
- `backend/cmd/server/schema_source_guard_test.go` 的 `TestNoAutoMigrateInProductionCode`
  ——AST 掃描產品程式碼，**零 `AutoMigrate`、無例外清單**。
- `backend/internal/database/schema_parity_test.go`（第 1 層，離線、不需資料庫、不可被 skip）
  ——`schemaParityModels` 的 **40 個 model** 與 schema DDL 逐欄位名雙向比對；比對的 DDL 來源
  自 `20260824_audit_export_jobs` 起擴為 **baseline ＋ 全部增量**（`schemaDDLStatements()`），
  故增量建的 `audit_export_jobs` 同受此守衛，不因不在 baseline 而脫離 parity 檢查。
- `backend/internal/database/baseline_parity_pg_test.go`、`index_declaration_parity_test.go`
  （第 2 層，PG-gated）——型別／可空／預設／索引／約束層級的 parity，以及具名結構不變式的
  `pg_get_indexdef` 逐字比對。

**fail-close（既有資料庫拒絕啟動）**：`schema_migrations` 內若出現本版程式碼不認識的版本、
且 baseline 尚未套用，`RunMigrations` 會**在任何寫入之前**拒絕啟動
（`migrations.go:157`，錯誤文案在 `legacySchemaError`，`:108`）。
判定會先扣掉 `runtimeMarkerVersions`（`:66`）——那些是模組借用本表做的執行期冪等標記
（現況唯一成員為 LDAP env seed 的 `20260804_ldap_env_seeded`），不是 migration。
**本版不提供既有資料庫的就地升級路徑**；維運面的處置見
[docs/ops/upgrade-sop.md](./ops/upgrade-sop.md)。

---

## ER 關係圖

```mermaid
erDiagram
    users ||--o{ user_roles : has
    roles ||--o{ user_roles : has
    users ||--o{ user_group_members : member_of
    user_groups ||--o{ user_group_members : has
    user_groups ||--o{ asset_authorizations : granted_to
    users ||--o{ sessions : creates
    users ||--o{ asset_authorizations : granted_to
    users ||--o{ audit_logs : performs
    users ||--o{ snippets : owns
    users ||--o{ refresh_tokens : issues
    users ||--o{ password_histories : keeps
    users ||--o{ access_reviews : signs_off
    sessions ||--o{ session_commands : captures
    sessions ||--o{ command_alerts : triggers
    sessions ||--o{ clipboard_events : captures
    alert_rules ||--o{ command_alerts : matched_by

    assets ||--o{ sessions : connects
    assets ||--o{ asset_accounts : owns
    assets ||--o{ asset_nodes : mounted
    asset_groups ||--o{ asset_nodes : contains
    asset_groups |o--o{ asset_groups : parent_of
    assets ||--o{ asset_authorizations : authorized
    assets ||--o| asset_host_keys : pinned
    assets ||--o{ change_secret_records : rotated

    asset_groups ||--o{ asset_authorizations : authorized
    change_secret_plans ||--o{ change_secret_records : executes

    users ||--o{ access_requests : requests
    assets ||--o{ access_requests : requested
    access_requests |o--o| asset_authorizations : issues_ticket
    users ||--o{ approver_scopes : reviews
    assets ||--o{ approver_scopes : scoped
    asset_groups ||--o{ approver_scopes : scoped

    users ||--o{ user_external_identities : linked_to
    oidc_providers ||--o{ user_external_identities : configures

    users ||--o{ user_source_ips : seen_from

    users {
        uint id PK
        string username UK
        string email UK_nullable
        string password
        string full_name
        string local_display_name
        bool active
        bool is_ldap
        string provisioning_origin
        bool external_credential
        int credential_epoch
        string totp_secret_enc
        bool totp_enabled
        uint64 totp_last_step
        int failed_login_attempts
        time locked_until
        bool must_change_password
        time password_changed_at
        time last_login_at
        bool inactivity_exempt
        string allowed_cidrs
    }

    user_source_ips {
        uint user_id PK
        string client_ip PK
        time first_seen_at
        time last_seen_at
        time first_session_at
        uint first_session_id
    }

    roles {
        uint id PK
        string name UK
        string description
    }

    assets {
        uint id PK
        string name
        string protocol
        string host
        int port
        string username
        string password_enc
        uint created_by FK
        string access_policy
        string db_name
        string db_tls_mode
        string k8s_namespace
    }

    asset_accounts {
        uint id PK
        uint asset_id FK
        string username
        string password_enc
        string private_key_enc
        bool is_default
        bool privileged
        string auth_method
        string note
    }

    asset_groups {
        uint id PK
        string name
        string description
        uint parent_id FK
    }

    asset_nodes {
        uint id PK
        uint asset_id FK
        uint node_id FK
    }

    sessions {
        uint id PK
        string session_id UK
        string status
        string protocol
        uint user_id FK
        uint asset_id FK
        string end_reason
        string recording_path
        uint account_id
        string account_username
        uint auth_provider_id
        int auth_epoch
        string k8s_pod
        string k8s_pod_uid
    }

    asset_authorizations {
        uint id PK
        uint user_id FK
        uint user_group_id FK
        uint asset_id FK
        uint asset_group_id FK
        string permission
        time date_start
        time date_expired
        string source
        string accounts
        uint granted_by FK
    }

    user_groups {
        uint id PK
        string name UK
        string description
    }

    access_requests {
        uint id PK
        uint requester_id FK
        uint asset_id FK
        string reason
        string status
        uint approver_id FK
        uint authorization_id FK
        time pending_expires_at
    }

    approver_scopes {
        uint id PK
        uint approver_id FK
        uint asset_id FK
        uint asset_group_id FK
        uint subject_user_id FK
        uint subject_group_id FK
        uint granted_by FK
    }

    access_request_approvals {
        uint id PK
        uint request_id FK
        uint approver_id FK
        string note
    }

    audit_logs {
        uint id PK
        string action
        string resource
        uint resource_id
        string status
        uint user_id FK
        string username
        string idempotency_uuid UK
    }

    session_commands {
        uint id PK
        uint session_id FK
        uint user_id FK
        uint asset_id FK
        string command
        int seq
        time executed_at
        string k8s_pod
        bool degraded
        string degrade_reason
    }

    alert_rules {
        uint id PK
        string name
        string pattern
        string severity
        string action
        string protocols
        bool enabled
    }

    command_alerts {
        uint id PK
        uint rule_id FK
        string rule_name
        string kind
        string reason_code
        uint session_id FK
        uint user_id FK
        uint asset_id FK
        string command
        string severity
        time triggered_at
        uint reviewed_by
        time reviewed_at
        string disposition
        string note
    }

    notification_channels {
        uint id PK
        string name
        string type
        string url
        string secret
        bool enabled
    }

    clipboard_events {
        uint id PK
        uint session_id FK
        string direction
        string content_enc
        int content_length
        string content_status
    }

    asset_host_keys {
        uint id PK
        uint asset_id UK
        string algorithm
        string fingerprint
        string public_key
    }

    snippets {
        uint id PK
        uint user_id FK
        string name
        string content
    }

    change_secret_plans {
        uint id PK
        string name UK
        string asset_ids
        string cron
        bool enabled
    }

    change_secret_records {
        uint id PK
        uint plan_id FK
        uint asset_id FK
        string status
        string error
        time executed_at
    }

    refresh_tokens {
        uint id PK
        uint user_id FK
        string token_hash UK
        time session_started_at
        time expires_at
        time last_used_at
        string auth_method
        uint provider_id
        int auth_epoch
        int cred_epoch
        time revoked_at
        string revoked_reason
    }

    oidc_providers {
        uint id PK
        string name
        string issuer UK
        string client_id UK
        string client_secret_enc
        string scopes
        string admission_mode
        string admission_rules
        bool force_shared
        int auth_epoch
        bool enabled
    }

    user_external_identities {
        uint id PK
        uint user_id FK
        uint provider_id FK
        string issuer UK
        string client_id UK
        string subject UK
        string claim_username
        string claim_email
        time last_login_at
    }

    ldap_directories {
        uint id PK
        int singleton UK
        string name
        string url
        string bind_dn
        string bind_password_enc
        string base_dn
        string user_filter
        string attr_email
        string attr_fullname
        bool skip_tls_verify
        bool enabled
    }

    security_policies {
        string key PK
        string value
        string updated_by
        time updated_at
    }

    password_histories {
        uint id PK
        uint user_id FK
        string password_hash
        time created_at
    }

    access_reviews {
        uint id PK
        uint reviewed_by FK
        string reviewer_name
        time reviewed_at
        string scope
        string note
        int authorization_count
        string matrix_snapshot
    }
```

---

## 模型詳細定義

### 1. User（用戶）

**表名**: `users`
**檔案**: `backend/internal/model/user.go`
**建表方式**: baseline（`baseline_schema_identity.go`）＋增量 migration `20260826_source_ip_forensics`
（`ALTER TABLE users ADD COLUMN allowed_cidrs text NOT NULL DEFAULT ''`，見下欄位表末列與「Migration 版本一覽」）。
兩條 partial unique index 承載帳號名的資料層不變式：
`idx_users_username`＝`(username) WHERE deleted_at IS NULL`、`idx_users_email`＝`(email) WHERE email IS NOT NULL AND deleted_at IS NULL`
——謂詞 GORM tag 表達不了，只能由顯式 DDL 承載

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Username` | string | `uniqueIndex;not null;size:50` | `username` | 登入帳號 |
| `Email` | string | `uniqueIndex;size:100` | `email` | 電子郵件 |
| `Password` | string | `not null` | `-` | bcrypt 雜湊密碼 |
| `FullName` | string | `size:100` | `full_name` | 顯示名稱 |
| `Active` | bool | `default:true` | `active` | 啟用狀態 |
| `IsLDAP` | bool | `default:false` | `is_ldap` | 是否 LDAP 用戶 |
| `ProvisioningOrigin` | string | `size:16;not null;default:'local'` | `provisioning_origin` | 供應來源（`local`／`ldap`／`oidc`）：建立時寫入後不可變，僅供顯示、審計與統計，**不參與授權判定**。 |
| `ExternalCredential` | bool | `default:false` | `external_credential` | 憑證由外部提供者管理，禁止一切本地密碼路徑。語義刻意是「外部化＝true」而非「有本地密碼＝true」——GORM 對帶 `default` tag 的欄位遇零值交由 DB 填 default，`default:true` 的 bool 顯式寫 false 會被覆寫（真 postgres 實測），反轉後外部帳號寫非零值故必寫入。同 migration |
| `CredentialEpoch` | int | `not null;default:0` | `-` | **使用者級**憑證世代（單調遞增）。解除外部身分綁定／帳號停用刪除／改為僅外部登入／改密時推進，使該使用者既有憑證全數失效；**自動鎖定刻意不推進**（鎖定可由未認證第三方觸發，推進將使其成為遠端斷線武器）。換發路徑一律簽發當下現查，不得繼承來源憑證。同 migration |
| `TOTPSecretEnc` | string | `size:512` | `-` | TOTP secret（AES 加密，永不輸出 JSON）。migration `v7.7` 補欄 |
| `TOTPEnabled` | bool | `default:false` | `totp_enabled` | 是否啟用 MFA/TOTP |
| `TOTPLastStep` | *uint64 | - | `-` | 最後成功消耗的 TOTP time-step 索引（⌊unix/30⌋）；驗證僅接受 step > 此值並以 CAS 原子推進，防同碼重放（PCI 8.5.1）。 |
| `FailedLoginAttempts` | int | `default:0` | `-` | 連續登入失敗計數（密碼與 TOTP 失敗共用）；達 `lockout_max_attempts` 觸發鎖定（PCI 8.3.4）。 |
| `LockedUntil` | *time.Time | - | `locked_until,omitempty` | 鎖定到期時間；到期放行時計數一併歸零。 |
| `MustChangePassword` | bool | `default:false` | `must_change_password` | 強制改密旗標；seed admin 預設 true，admin 重設後依政策 `force_change_on_reset` 設 true（PCI 8.3.5/2.2.2）。 |
| `PasswordChangedAt` | *time.Time | - | `password_changed_at,omitempty` | 最後改密時間。 |
| `LastLoginAt` | *time.Time | - | `last_login_at,omitempty` | 最後成功登入時間；閒置停用判定（8.2.6）據此。 |
| `InactivityExempt` | bool | `default:false` | `inactivity_exempt` | 閒置帳號自動停用豁免（per-user 永久旗標）；seed admin 預設豁免，避免唯一管理員久未登入被自動停用鎖死（PCI 8.2.6）。 |
| `AllowedCIDRs` | string | `column:allowed_cidrs;type:text;not null;default:''` | `-`（不出 JSON） | **允許來源網段清單的儲存形式**：逗號分隔、已正規化的前綴字串（沿 `alert_rules.protocols` 的逗號分隔慣例；前綴本身不含逗號，不需結構化格式）。**空字串＝不限制來源**。只由 service 層經 `internal/sourceip` 單一實作驗證後寫入。欄名以 `column:` 顯式釘死——GORM 的 snake_case 會把 `CIDRs` 拆成 `c_id_rs`。DB 側為 `text NOT NULL DEFAULT ''`，由增量 migration `20260826_source_ip_forensics` 加欄 |
| `AllowedCIDRList` | []string | `-`（非持久化） | `allowed_cidrs` | 清單的 API 形狀（字串陣列），由 service 層自 `AllowedCIDRs` 拆出。**衍生欄、不入庫**；未經 service 裝飾的 `User` 值此欄為 nil（序列化為 `null`） |
| `AllowedCIDRsStatus` | string | `-`（非持久化） | `allowed_cidrs_status,omitempty` | 有效涵蓋狀態：`unrestricted`（清單空）／`effectively_unrestricted`（清單非空但含全域前綴，實際等於不限）／`restricted`。由伺服端單一實作依**實際放行的範圍**計算，介面不自行推算。**衍生欄、不入庫** |
| `AllowedCIDRFamilies` | []string | `-`（非持久化） | `allowed_cidrs_families,omitempty` | 狀態為 `effectively_unrestricted` 時被全放行的位址家族（`v4`／`v6`），供介面指出「含全域前綴的是哪一族」。**衍生欄、不入庫**。注意判定端點 `POST /api/v1/users/source-policy/check` 的回應把同一份資料放在 `families` 鍵（非 `allowed_cidrs_families`），兩處不同名，見 [API_SPEC.md](API_SPEC.md) |

**認證來源常數**（登入審計標註用，同時作為 `users.provisioning_origin` 的值域）:
```go
const (
    AuthSourceLocal = "local" // 本地帳密認證
    AuthSourceLDAP  = "ldap"  // LDAP 目錄認證
    AuthSourceOIDC = "oidc" // OIDC 身分提供者認證
)
```

**身分三分與 `IsExternal()`**：單一欄位無法同時承擔「帳號怎麼來的」、
「能不能用本地密碼」、「本次怎麼登入的」三種判定——admin 把外部身分綁到既有本地帳號後即自相矛盾。
故拆為：供應來源（`provisioning_origin`，不可變）、憑證外部化（`external_credential`）、
本次登入方式（執行期值，隨流程傳遞**不落庫**）。
`model.User.IsExternal()` 取三訊號（`external_credential`／`is_ldap`／`provisioning_origin != local`）的**聯集**
（fail-secure：單欄漂移不會打開本地密碼路徑）；所有密碼類判定（自助改密、admin 重設、
本地登入分派、封印解封的初始管理員驗證）一律經此方法，不得直讀單一欄位。
過渡期不變式：`(is_ldap=true) ⟺ (provisioning_origin='ldap')`、`origin != local ⟹ external_credential`。

**索引（實際 DB 狀態）**:
- migration `v7.6` 將 `username`/`email` 唯一索引改為 **partial unique index**（`WHERE deleted_at IS NULL`），
  避免軟刪除列永久佔用帳號名稱。model tag 仍為一般 `uniqueIndex`，實際約束以 migration 為準。
- `email` 唯一索引為 partial：`WHERE email IS NOT NULL AND deleted_at IS NULL`
  （僅約束非 NULL 值）。`email` 欄改以 **NULL 表達「未知」**（非空字串，model 型別 `*string`），
  既有 `''` 一次性正規化為 NULL；多個無 email 帳號（如 LDAP 衝突影子帳號）可並存。
- `allowed_cidrs` **無索引**：判定一律以主鍵讀單列（每個判定點現讀該欄、不快取、不進 JWT），
  沒有以清單內容為條件的查詢。唯一會掃該欄全表的是失效恢復謂詞
  （`identity/source_policy_gate.go` 的 `EvaluateSourcePolicyHealth`），
  呼叫時機限於啟動、清單成功寫入後、以及判定點成功讀取且目前失效中時。

**欄位備註**:
- `local_display_name`（nullable，`*string`，無唯一約束）：使用者自助顯示名。
  初始 NULL、不由 username/full_name/IdP 初始化、trim 後空字串寫回 NULL。顯示名 resolver
  `local_display_name || full_name || username`（`model.User.DisplayName()`）；僅裝飾/自我檢視場景使用，
  身分敏感場景一律 `username`（安全紅線）。

**關聯**:
- `Roles []Role` - 多對多（透過 `user_roles` 表）
- `Groups []UserGroup` - 多對多（透過 `user_group_members` 表，授權主體分組）

---

### 2. Role（角色）

**表名**: `roles`
**檔案**: `backend/internal/model/role.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `idx_roles_name` 唯一索引
（**非** partial：本表雖有 `deleted_at`，軟刪除的角色名仍佔用該名稱）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Name` | string | `uniqueIndex;not null;size:50` | `name` | 角色名稱 |
| `Description` | string | `size:200` | `description` | 角色描述 |

**預設角色常數**:
```go
const (
    RoleAdmin    = "admin"    // 管理員
    RoleUser     = "user"     // 一般用戶
    RoleAuditor  = "auditor"  // 審計員
    RoleApprover = "approver" // 審核人（可疊加角色；seed 補種）
)
```
`approver` 為可疊加角色：不進 JWT 的三階 `primaryRoleOf` 判定（admin>auditor>user 不變），
審核端點以 DB roles 即時判定（撤角色即時生效）；審核範圍見 ApproverScope。

**關聯**:
- `Users []User` - 多對多（透過 `user_roles` 表）

---

### 2b. user_roles（用戶×角色關聯表）

**表名**: `user_roles`
**檔案**: **無 model 檔**——僅由 `model.User.Roles` 與 `model.Role.Users` 的
`gorm:"many2many:user_roles;"` tag 隱含（`user.go:111`、`role.go:20`）
**建表方式**: baseline（`baseline_schema_identity.go`），複合主鍵 `(role_id, user_id)`，
兩條外鍵 `fk_user_roles_role`→`roles(id)`、`fk_user_roles_user`→`users(id)`；無其他索引
**維護陷阱（沒有守衛會提醒你）**: 本表沒有 model 結構，故**不在 `schemaParityModels` 的射程內**
——`schema_parity_test.go`（第 1 層）與 `index_declaration_parity_test.go`（第 2 層）都不會檢查它。
壓縮前它由 GORM many2many 自動建立；`AutoMigrate` 移除後，**改 model 既不會動到本表、也不會有任何測試變紅**。
要改關聯表的形狀，唯一途徑是直接改 `baseline_schema_identity.go`。

| 欄位（baseline） | 類型 | 說明 |
|------------------|------|------|
| `role_id` | bigint NOT NULL | 角色；複合主鍵之一 |
| `user_id` | bigint NOT NULL | 使用者；複合主鍵之一 |

無 `created_at`／`deleted_at`：關聯為硬刪（增刪列即掛/摘）。

---

### 3. Asset（資產）

**表名**: `assets`
**檔案**: `backend/internal/model/asset.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_assets_name`＝`UNIQUE (name) WHERE deleted_at IS NULL`
（partial unique，軟刪列不佔名；model tag 僅為一般 `index`，實際約束以 baseline 為準）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Name` | string | `not null;size:100;index` | `name` | 資產名稱 |
| `Protocol` | ProtocolType | `not null;size:10;index` | `protocol` | 協議類型 |
| `Host` | string | `not null;size:255` | `host` | 主機位址 |
| `Port` | int | `not null` | `port` | 埠號 |
| `Description` | string | `size:500` | `description` | 描述 |
| `Active` | bool | `default:true;index` | `active` | 啟用狀態 |
| `CreatedBy` | uint | `not null;index` | `created_by` | 創建者 ID |
| `Username` | string | `size:100` | `username` | 連線帳號 |
| `PasswordEnc` | string | `type:text` | `-` | AES-256-GCM 加密密碼（K8s 資產以此欄存 Token） |
| `PrivateKeyEnc` | string | `type:text` | `-` | 加密的 SSH 私鑰 |
| `HasPassword` | bool | - | `has_password` | 是否有密碼 |
| `HasPrivateKey` | bool | - | `has_private_key` | 是否有私鑰 |
| `AccessPolicy` | *string | `type:varchar(20)` | `access_policy,omitempty` | 存取政策段位 `open`/`reason`/`approval`；NULL＝繼承全域預設鍵 `access_policy_default`（政策掛資產本身，不掛節點） |
| `NodeIDs` | []uint | `-`（非 DB 欄） | `node_ids,omitempty` | 掛載節點 id 集（多歸屬；成員在 `asset_nodes` 表，service 層組裝——**assets 上沒有單欄外鍵**） |
| `NodePaths` | []string | `-`（非 DB 欄） | `node_paths,omitempty` | 掛載節點全路徑顯示（如 `prod / kafka`） |
| `Tags` | string | `size:500` | `tags` | 逗號分隔標籤 |
| `LastTestStatus` | string | `size:20;default:''` | `last_test_status` | 最近手動連測結果（''=未測）。 |
| `LastTestAt` | *time.Time | - | `last_test_at` | 最近連測時間 |
| `LastTestLatencyMS` | int64 | `default:0` | `last_test_latency_ms` | 最近連測延遲（毫秒） |
| `DBName` | string | `size:128` | `db_name` | DB CLI 目標資料庫（僅 mysql/postgres/redis；空＝連預設庫）。 |
| `DBTLSMode` | string | `size:20` | `db_tls_mode` | DB TLS 模式：''＝client 預設 / `disable` / `require` / `verify-ca` / `verify-full`（Postgres=PGSSLMODE verify-full、Redis 等同 verify-ca）。 |
| `DBCACert` | string | `type:text` | `db_ca_cert` | verify-ca/verify-full 用 CA（PEM，選填）。**DB 欄名是 `dbca_cert`，不是 `db_ca_cert`**——GORM 的 `NamingStrategy` 把 `DBCACert` 斷成 `dbca`＋`cert`（`DB`／`CA` 都不在 GORM 的 initialism 清單內），而 `db_ca_cert` 只是 JSON 別名。壓縮前 `assets` 上另有一個真的叫 `db_ca_cert` 的**死欄**（無任何 model 欄對應、零讀寫），已隨本次壓縮自 baseline 移除 |
| `RDPSecurity` | string | `size:10` | `rdp_security` | RDP 安全模式：''＝沿現狀 any / `nla` / `tls`。baseline |
| `RDPVerifyCert` | bool | `default:false` | `rdp_verify_cert` | RDP 驗證伺服器憑證（預設 false＝ignore-cert，與現狀一致）。baseline |
| `K8sNamespace` | string | `size:63` | `k8s_namespace` | K8s 目標 namespace（protocol=k8s 必填）。 |
| `K8sPod` | string | `size:253` | `k8s_pod` | 保留相容舊 fixed-pod 資料；新設計連線時選 pod，不再強制必填 |
| `K8sContainer` | string | `size:63` | `k8s_container` | 同上，保留相容 |
| `K8sCACert` | string | `type:text` | `k8s_ca_cert` | API server CA（PEM，選填）。 |
| `K8sInsecureSkipTLS` | bool | `default:false` | `k8s_insecure_skip_tls` | 顯式略過 control plane TLS 驗證（預設 false） |
| `SftpEnabled` | bool | `default:false` | `sftp_enabled` | VNC SFTP 側車檔案傳輸開關。 |
| `SftpPort` | int | `default:22` | `sftp_port` | SFTP 埠（僅 protocol=vnc 使用） |
| `SftpUsername` | string | `size:100` | `sftp_username` | 目標主機 SSH 帳號（與 VNC 密碼分離） |
| `SftpPasswordEnc` | string | `type:text` | `sftp_password_enc` | SFTP 密碼（AES-256-GCM 加密；API 不回明文） |
| `HasSftpPassword` | bool | `default:false` | `has_sftp_password` | 是否已設 SFTP 密碼 |

**協議類型常數**:
```go
type ProtocolType string
const (
    ProtocolSSH ProtocolType = "ssh"
    ProtocolRDP ProtocolType = "rdp"
    ProtocolVNC ProtocolType = "vnc"
    // 資料庫協議：本地 CLI 子程序代理，文字流走 sshproxy bridge
    ProtocolMySQL    ProtocolType = "mysql"
    ProtocolPostgres ProtocolType = "postgres"
    ProtocolRedis    ProtocolType = "redis"
    // K8s 容器 exec：kubectl exec 本地 PTY，同走 bridge
    ProtocolK8s ProtocolType = "k8s"
)
```

**協議判別方法**:
- `IsDatabase()` - mysql / postgres / redis
- `IsTextTerminal()` - ssh + 資料庫 CLI + k8s（走 sshproxy bridge，指令審計/錄製/監看/阻斷全沿用）

**索引（實際 DB 狀態）**:
- migration `v7.6` 將 `idx_assets_name` 改建為 **partial unique index**（`name` 唯一，`WHERE deleted_at IS NULL`）；
  model tag 僅為一般 `index`，實際約束以 v7.6 為準。

**關聯**:
- 節點掛載走 `asset_nodes` M2M（多歸屬）；無 belongs-to 關聯

**GORM Hooks** (定義於 `asset_audit.go`):
- `AfterCreate` / `AfterUpdate` / `AfterDelete` - 自動記錄審計日誌

---

### 3b. AssetAccount（資產帳號）

**表名**: `asset_accounts`
**檔案**: `backend/internal/model/asset_account.go`（審計結構 `asset_account_audit.go`）
**建表方式**: baseline（`baseline_schema_asset.go`）。兩條 partial unique index 承載本表的資料層不變式：
`idx_asset_accounts_default`（一資產至多一預設帳號）與 `idx_asset_accounts_username`（同資產內帳號名唯一、軟刪列不佔名）；
兩者以 `pg_get_indexdef` 逐字比對釘在 `baselineStructuralAssertions`

一資產多系統帳號。適用 ssh/rdp/vnc/mysql/postgres/redis/mssql；
**k8s 固定單一預設帳號**（token 即身分，連線帶非預設 `account_id` 於連線側回 400）。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除（密文留存供退役 DEK 引用掃描） |
| `AssetID` | uint | `not null;index` | `asset_id` | 所屬資產（嚴格 per-asset，不跨資產共用——同一組帳密用在不同資產上就是不同列） |
| `Username` | string | `size:100` | `username` | 系統帳號名。空字串合法（無身分僅憑證的資產）；`@` 前綴為保留字（授權別名 `@ALL` 命名空間），冒號與 C0/C1 控制字元拒收 |
| `PasswordEnc` | string | `type:text` | `-` | 信封加密密碼，**絕不出站**（JSON `-`、審計 Details 只記欄位名） |
| `PrivateKeyEnc` | string | `type:text` | `-` | 信封加密 SSH 私鑰，同上 |
| `IsDefault` | bool | `default:false;index` | `is_default` | 預設帳號：系統路徑（改密 runner、k8s、SFTP 獨立入口）與未指定 `account_id` 的連線一律走此帳號 |
| `Privileged` | bool | `default:false` | `privileged` | 特權帳號標記（如 root/sa）。**純標示欄**，供 UI 與審計辨識，不改變授權判定 |
| `AuthMethod` | string | `size:20;default:sql` | `auth_method` | 認證類型。值域 `sql`｜`domain`；**1.0 只接受 `sql`**，`domain` 由驗證層明確拒絕（`VALIDATION_ACCOUNT_AUTH_METHOD_UNSUPPORTED`，不靜默降級）。刻意放帳號而非資產：同一台 MSSQL 可同時掛 SQL login 與域帳號，放資產上兩者無法並存。非 mssql 協議的帳號一律留在預設 `sql` 且不參與連線組裝。 |
| `Note` | string | `size:255` | `note` | 備註 |

**索引與 default 語義**:
- Partial unique index `idx_asset_accounts_default` - `(asset_id) WHERE is_default AND deleted_at IS NULL`
  ——DB 層只保證「**至多一個** default」。
- Partial unique index `idx_asset_accounts_username` - `(asset_id, username) WHERE deleted_at IS NULL`
  ——同資產同名歧義防護（授權綁 username 字串，重名會使授權指向不唯一）。
- 「**有帳號必有 default**」不在 DB 層，由服務層交易維護：建立首個帳號強制 `IsDefault=true`；
  刪除 default 時若資產尚有其他帳號則拒絕（`RULE_ACCOUNT_DEFAULT_REQUIRED`）；
  set-default 於同一交易內先清舊 default 再設新 default（不讓 partial unique index 中途看到兩筆）。
- **零帳號資產合法**（原本即無憑證的資產；刪除唯一帳號時同步清空 `assets` 的顯示欄）。

**安全紅線**: `password_enc`／`private_key_enc` 必須與 model **同版**登記於
`service.envelopeMigrationTargets`——該清單同時驅動 DEK 輪替重加密、legacy pending 判定與
退役 DEK 銷毀前的引用掃描；漏登會使銷毀前掃描看不見本表密文而誤判零引用、銷毀仍在用的金鑰材料。
AST 守衛 `envelope_targets_guard_test.go` 強制此約束。

**與 `assets` 內嵌憑證的關係（單向切換）**: 服務層把資產上的內嵌憑證**原樣複製**為
一筆 IsDefault 帳號（信封密文自帶 DEK 版本前綴、無 AAD 列綁定，跨表可解）。此後讀寫一律走
本表，`assets.username/password_enc/private_key_enc/has_*` 降為**顯示鏡射欄**（服務層以
`UpdateColumns` 同步 default 帳號，不動 `assets.updated_at`），保留一個版本後移除。
`PUT /assets/:id` 的憑證欄位透明轉寫 default 帳號（舊前端／腳本不壞）。
**回滾邊界**：`RollbackAssetAccounts` 為資料保全會拒滾（存在非遷移形態帳號或已顯式刪除帳號時），
緊急回退需人工反向同步。

**審計**: 不掛 GORM hook（hook 拿不到 diff），由 service 顯式呼叫
`RecordAssetAccountAudit`；操作類型 `create`/`update`/`delete`/`set_default`，
Details **只記被變更的欄位名稱**，永不含密文或明文憑證（審計庫讀取面遠比憑證欄寬）。

**會話快照**: `sessions.account_id` + `sessions.account_username` 雙快照，
寫入後永不隨帳號改名／刪除更新——只存 FK 不足以保證不可否認性。

---

### 4. AssetGroup（資產節點）

**表名**: `asset_groups`
**檔案**: `backend/internal/model/asset.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_asset_groups_sibling_name`＝
`UNIQUE (COALESCE(parent_id, 0), name) WHERE deleted_at IS NULL`——**表達式** partial unique，
GORM tag 既表達不了 `COALESCE` 也表達不了謂詞；拿掉它同層即可出現重名節點

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Name` | string | `not null;size:100` | `name` | 節點名稱（同層唯一，見下） |
| `Description` | string | `size:500` | `description` | 描述 |
| `ParentID` | *uint | `index` | `parent_id,omitempty` | 父節點（自參照；NULL＝根節點） |

> 資產分組為**節點樹**：parent_id 自參照、
> 深度上限 10（service 層驗證）、環路檢查、僅空節點可刪（連動軟刪節點授權與 approver 範圍）。
> 名稱唯一自全域改**同層唯一**：`idx_asset_groups_sibling_name`＝
> `UNIQUE (COALESCE(parent_id, 0), name) WHERE deleted_at IS NULL`（表達式索引，根層彼此也互斥）。
> 政策不掛節點（鐵則）。

---

### 4b. AssetNode（資產×節點成員）

**表名**: `asset_nodes`
**檔案**: `backend/internal/model/asset.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `(asset_id, node_id)` 唯一索引

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 掛載時間 |
| `AssetID` | uint | `not null;index` | `asset_id` | 資產 |
| `NodeID` | uint | `not null;index` | `node_id` | 節點（asset_groups.id） |

**索引**: `idx_asset_nodes_asset_node`＝`UNIQUE (asset_id, node_id)`（ON CONFLICT 冪等依據）。
**語義**: 多歸屬 M2M（一資產可掛多節點；零掛載＝未分組）；硬刪（掛/摘即增刪列，變更審計在 service 層記 `node_ids` 舊→新）。授權解析的子樹展開：授權節點 N 涵蓋資產 A ⟺ N ∈ A 的掛載節點或其任一祖先（遞迴 CTE，無快取即時查詢）。

---

### 5. Session（連線會話）

**表名**: `sessions`
**檔案**: `backend/internal/model/session.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `idx_sessions_session_id` 唯一索引；
**baseline 的 audit 域僅有的兩條外鍵都在本表**（`fk_sessions_user`→`users(id)`、`fk_sessions_asset`→`assets(id)`）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `SessionID` | string | `uniqueIndex;not null;size:100` | `session_id` | 唯一會話 ID |
| `Status` | SessionStatus | `not null;size:20` | `status` | 會話狀態 |
| `Protocol` | ProtocolType | `not null;size:10` | `protocol` | 協議類型 |
| `UserID` | uint | `not null` | `user_id` | 用戶 ID |
| `AssetID` | *uint | - | `asset_id` | 資產 ID（可選，手動連線可為 NULL；migration `v6.1` 改 nullable） |
| `ClientIP` | string | `size:50` | `client_ip` | 客戶端 IP |
| `StartTime` | time.Time | - | `start_time` | 開始時間 |
| `EndTime` | *time.Time | - | `end_time` | 結束時間 |
| `Duration` | int | - | `duration` | 持續時間（秒） |
| `EndReason` | string | `size:20;default:normal` | `end_reason` | 斷線原因（session-reconciliation）。 |
| `RecordingPath` | string | `size:500` | `recording_path` | 錄製檔案路徑 |
| `RecordingSize` | int64 | - | `recording_size` | 錄製檔案大小（bytes）：**錄影落地確認當下的量測值，不是檔案最終大小**。文字錄影（`.cast`）的 fd 由後端自持，錄製器 `Stop()` 返回即完成 flush 與 close，故為精確值；圖形錄影（`.guac`）的 fd 由 guacd 持有，其收尾尾段（釋放顯示層時送出的 dispose 指令）寫入於後端量測之後，而協議層不提供收尾完成訊號、guacd 亦不會先行關閉與後端之間的連線，後端不存在可用的同步點——故圖形路徑的本欄**恆小於或等於**磁碟實際大小（方向恆為少記），差額限於收尾尾段、不隨會話長度或錄影檔大小成長（上界推導見 `backend/internal/recorder/graphics_teardown_slack.go`）。**不得作為錄影完整性、稽核對帳或配額判定的依據**：儲存量統計走磁碟實測（`GetRecordingStats` 的 `filepath.Walk`），不讀本欄；同一份錄影另有即時量測的 `RecordingMetadata.file_size`（每次呼叫當下 `os.Stat`），兩者不同源、不保證相等 |
| `HasRecording` | bool | `default:false` | `has_recording` | 是否有錄製 |
| `RecordingError` | string | `type:text` | `recording_error` | 錄影失敗原因：非空＝錄影缺失或不完整（只記首因），前端據此顯「無錄影」標示。** 起語義改為存 cause 機器碼**（與 `audit_failure_events.cause_code` 同一組 `model.Cause*` 常數）而非中文散文，前端 tooltip 按碼查譯；schema 未變（仍為 text，無 migration），dev 階段不轉存量——既有列殘留散文，新列一律存碼 |
| `RecordingStartedAt` | *time.Time | - | `recording_started_at` | 錄影的時間原點：回放的 elapsed=0 對應的絕對時刻。**不等於 `start_time`**——文字終端的錄製器在會話建檔之後才啟動（認證＋PTY 就緒，差為正），圖形的 guacd 握手則在建檔之前完成（差為負）。缺這一欄，`/sessions/:id?t=` 深連結只能拿 `start_time` 當原點，文字終端偏早、圖形偏晚而**跳過目標事件**。NULL＝無錄影或存量會話，前端據此退回未校正值並在畫面明示。baseline 建欄（nullable；全新安裝無歷史列可回填） |
| `OffsiteObjectID` | *uint | - | `offsite_object_id` | 離機保管帳冊列的指標（→ `offsite_objects.id`，邏輯外鍵，不建 FK 約束）。NULL＝本會話的錄影尚未（或不會）進入離機佇列。由增量 migration `20260825_evidence_offsite` 加欄 |
| `OffsiteStatus` | string | `size:20;not null;default:''` | `offsite_status` | 帳冊 `state` 的**顯示用快取**，值域＝帳冊七態 ∪ 回填掃描的兩個分類（`skipped_missing`／`skipped_expired`，兩者**不建帳冊列**）∪ 空字串。**所有決策邏輯只讀帳冊**，本欄只供列表與詳情頁免 join；與帳冊短暫不一致不影響正確性。同一條 migration 加欄 |
| `AccountID` | uint | `index` | `account_id` | 帳號雙快照：連線所用的 `asset_accounts.id`；0＝未帶帳號（歷史會話／零帳號路徑）。 |
| `AccountUsername` | string | `size:100` | `account_username` | 帳號雙快照：**連線當下**的帳號 username。只存 FK 不足以保證不可否認性——帳號改名／刪除會洗掉「當時用哪個帳號連的」；寫入後永不隨帳號變動更新（沿 K8s 六欄不可變快照先例） |
| `K8sNamespace` | string | `size:63` | `k8s_namespace` | K8s 快照：namespace。 |
| `K8sPod` | string | `size:253` | `k8s_pod` | K8s 快照：pod 名稱 |
| `K8sPodUID` | string | `size:40` | `k8s_pod_uid` | K8s 快照：pod UID（pod 短命且名稱可複用，釘 UID 才有不可否認性） |
| `K8sContainer` | string | `size:63` | `k8s_container` | K8s 快照：container |
| `K8sImage` | string | `size:255` | `k8s_image` | K8s 快照：image |
| `K8sNode` | string | `size:253` | `k8s_node` | K8s 快照：node |

**認證溯源欄位**（`auth_provider_id`、`auth_epoch`；
含索引 `idx_sessions_auth_provider_id`）:
- `auth_provider_id`（BIGINT，nullable）：建立本連線的憑證由哪個 `oidc_providers.id` 認證；NULL／0＝本地或 LDAP。
- `auth_epoch`（BIGINT NOT NULL DEFAULT 0）：兌換當下的 provider 世代快照。
- 兩欄**僅為溯源快照，不作授權判定**——授權一律於兌換點現查 DB 的 `enabled` 與世代。
  provider 停用／刪除時據 `auth_provider_id` 找出須終斷的協議連線；
  **禁止以「查外部身分表反推 provider」代替**（混合帳號會被誤標，導致停用時誤殺本地會話）。

**會話狀態常數**:
```go
type SessionStatus string
const (
    SessionStatusActive       SessionStatus = "active"       // 活動中
    SessionStatusDisconnected SessionStatus = "disconnected" // 已斷線
    SessionStatusClosed       SessionStatus = "closed"       // 已關閉
)
```

**斷線原因值**（`end_reason`）: `normal` / `idle_timeout` / `max_duration`/ `admin_terminate`（管理員強制終止＋帳號停用收線）/ `user_terminate`（一般 user 自助終止自己的連線）/ `backend_restart`（啟動清掃殘留 active）/ `orphaned`（週期偵測無活連線的孤兒 session）/ `revoked`（臨時授權提前撤銷＋`access_revoke_disconnect` 開啟時的收線）／`block_clear_failed`（指令阻斷後清遠端行緩衝失敗，fail-close 主動收線）。**欄型為 varchar 且無 CHECK**——新增原因值不需改 schema

**索引列表**（以 `pg_indexes.indexdef` 實測為準）:
- `idx_sessions_session_id` - UNIQUE `(session_id)`
- `idx_sessions_account_id` - `(account_id)`
- `idx_sessions_auth_provider_id` - `(auth_provider_id)`
- `idx_sessions_deleted_at` - `(deleted_at)`
- `idx_sessions_user_start` - `(user_id, start_time)`，稽核工作台人樞紐的會話類 keyset 查詢
- `idx_sessions_asset_start` - `(asset_id, start_time)`，同上的資產樞紐側
- `idx_sessions_client_ip_start` - `(client_ip, start_time)`，稽核工作台**位址樞紐**的會話查詢與三表 join
  皆以 `sessions.client_ip` 為鍵，時間窗 keyset 需第二鍵。**由增量 migration `20260826_source_ip_forensics`
  建立**（DDL 逐字：`CREATE INDEX idx_sessions_client_ip_start ON sessions USING btree (client_ip, start_time)`），
  非 baseline
- `idx_sessions_offsite_backfill` - **部分索引** `(id) WHERE ((offsite_object_id IS NULL) AND has_recording)`
  ——離機回填掃描的取件面（有錄影而尚未建帳冊列者）。由增量 migration `20260825_evidence_offsite` 建立，非 baseline
- `idx_sessions_offsite_retention` - **部分索引** `(end_time) WHERE (offsite_object_id IS NOT NULL)`
  ——保留清理段以會話結束時刻掃出已有帳冊物件的列。同一條 migration，非 baseline

> 上述兩條部分索引**只存在於 migration DDL**，不在 model 的 GORM tag 上：其 `WHERE` 涉及
> `has_recording` 與本欄的 `IS NOT NULL`，tag 表達得出但會使 `Session` model 承載離機子系統的查詢面知識
> （沿 `audit_export_jobs` 部分索引只留 DDL 的既有取捨）。

**關聯**:
- `User *User` - 屬於（透過 `UserID`）
- `Asset *Asset` - 屬於（透過 `AssetID`，可選）

---

### 6. AssetAuthorization（資產授權）

**表名**: `asset_authorizations`
**檔案**: `backend/internal/model/asset_authorization.go`
**建表方式**: baseline（`baseline_schema_authz.go`）。兩條 inline CHECK 承載主客體互斥不變式——
`chk_auth_target`（客體 asset XOR asset_group）與 `chk_authz_subject_xor`（主體 user XOR user_group）；
四條複合唯一索引皆為 partial（`WHERE deleted_at IS NULL AND source <> 'ticket'`），使撤銷後重授不撞唯一衝突、
且臨時授權與常設授權可並存

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primaryKey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除（撤銷＝軟刪） |
| `UserID` | *uint | `uniqueIndex:idx_*`（nullable，migration 20260717 放寬） | `user_id,omitempty` | 被授權用戶（主體之一） |
| `UserGroupID` | *uint | `uniqueIndex:idx_*` | `user_group_id,omitempty` | 被授權使用者群組（主體之一） |
| `AssetID` | *uint | `uniqueIndex:idx_*;index:idx_asset` | `asset_id,omitempty` | 資產 ID（客體之一） |
| `AssetGroupID` | *uint | `uniqueIndex:idx_*` | `asset_group_id,omitempty` | 資產分組 ID（客體之一） |
| `Permission` | PermissionType | `type:varchar(20);not null;uniqueIndex:idx_*` | `permission` | 權限類型 |
| `DateStart` | *time.Time | - | `date_start,omitempty` | 時效窗起（空＝不設限；來源限核准流，管理 API 不接受手填） |
| `DateExpired` | *time.Time | - | `date_expired,omitempty` | 時效窗迄（空＝永久；到期語義＝解析不命中，記錄留存供審計） |
| `Source` | string | `type:varchar(20)` | `source` | 授權來源 `manual`（預設，BeforeCreate 空值回填）/ `ticket`（核准流臨時授權，帶時效窗） |
| `Accounts` | AccountScope（`[]string`） | `type:text`（DB 端 NOT NULL DEFAULT `["@ALL"]`） | `accounts,omitempty` | 帳號範圍：`["@ALL"]`＝客體範圍內資產全部帳號（行為與多帳號前一致），或具名 username 清單（語義＝範圍內資產上的同名帳號）。**不參與唯一索引**——帳號範圍是授權列屬性、非去重維度（收緊範圍＝改既有列，不是新增列）。 |
| `GrantedBy` | uint | `not null` | `granted_by` | 授權者 ID（ticket 列＝核准人；自動核准因 FK 記申請人＋申請單 auto_approved 標記辨識） |

**權限類型常數**（兩階制，移除 manage）:
```go
type PermissionType string
const (
    PermissionView    PermissionType = "view"    // 查看資產資訊
    PermissionConnect PermissionType = "connect" // 連線到資產（含 view）
    // Deprecated: manage 已移除——API binding 拒收，僅歷史軟刪列殘留此值
    PermissionManage  PermissionType = "manage"
)
```
**約束與索引**（baseline 建出的形狀）:
- CHECK 約束 `chk_authz_subject_xor` - UserID 與 UserGroupID 恰好一個非 NULL（主體 XOR）
- CHECK 約束 `chk_auth_target` - AssetID 與 AssetGroupID 恰好一個非 NULL（客體 XOR）
- 四條複合唯一索引對應主體×客體四種組合，**全部 partial**（`WHERE deleted_at IS NULL AND source <> 'ticket'`）：排除軟刪列，
  否則「撤銷後重新授權」會撞唯一衝突；排除 `ticket` 列，讓臨時授權可與常設授權同組合並存、
  不佔手動授權的去重空間：
  - `idx_user_asset_permission` - (user_id, asset_id, permission)
  - `idx_user_group_permission` - (user_id, asset_group_id, permission)
  - `idx_ugroup_asset_permission` - (user_group_id, asset_id, permission)
  - `idx_ugroup_agroup_permission` - (user_group_id, asset_group_id, permission)
- Partial index `idx_user_asset` - (user_id, asset_id) WHERE asset_id IS NOT NULL（v7.5）
- Partial index `idx_user_group` - (user_id, asset_group_id) WHERE asset_group_id IS NOT NULL（v7.5）

**關聯**:
- `User User` / `UserGroup *UserGroup` - 屬於（主體，二擇一）
- `Asset *Asset` / `AssetGroup *AssetGroup` - 屬於（客體，二擇一）
- `GrantedByUser User` - 屬於（授權者）

**GORM Hooks 與方法**:
- `BeforeCreate` - 驗證主體恰一（UserID XOR UserGroupID）與客體恰一（AssetID XOR AssetGroupID）；主要約束由 DB CHECK 保證
- `ActiveWithin(now)` - 判定指定時刻是否在時效窗內（空值＝不設限）

**權限解析語義**（`repository/asset_authorization_repository.go` 唯一入口）：主體條件為 `user_id = ?` OR `user_group_id IN (成員群組子查詢)`，客體含直授與資產分組，四路徑聯集取最高等級；僅計入時效窗內授權（時刻參數由呼叫端注入，非 DB NOW()，求跨 SQLite 可攜）；無 deny、無「個人優先」覆蓋語義。

---

### 7. AuditLog（審計日誌）

**表名**: `audit_logs`
**檔案**: `backend/internal/model/audit_log.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `idx_audit_idempotency`＝`UNIQUE (idempotency_uuid)`
（冪等寫入的衝突目標）與 8 條查詢索引；本表不建任何外鍵

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | `index:idx_audit_created_at` | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `-` | 更新時間（隱藏） |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Action` | AuditAction | `type:varchar(20);not null;index:idx_*` | `action` | 操作類型 |
| `Resource` | AuditResource | `type:varchar(20);not null;index:idx_*` | `resource` | 資源類型 |
| `ResourceID` | *uint | `index:idx_audit_resource` | `resource_id` | 資源 ID |
| `Status` | AuditStatus | `type:varchar(20);not null;index:idx_*` | `status` | 操作狀態 |
| `AssetID` | *uint | `index:idx_audit_asset_created,priority:1` | `asset_id,omitempty` | 資產主體鍵。稽核工作台的資產樞紐**只認本欄**，SHALL NOT 以 `(resource, resource_id)` 冒充——`(resource, resource_id)` 對改密計畫、授權列等實體會記成 `resource=asset` 而 `resource_id` 是計畫 id／授權列 id，據此反查會把別的實體的事件掛到這台資產上（假事件比遺漏更糟）。主體在**寫入期**釘在來源列上，與 sessions／session_commands／command_alerts 既有的 `user_id`＋`asset_id` 冗餘慣例一致。指標型可為 NULL：非資產類動作留空，**不得以 0 冒充「無資產」**。納入 HMAC 蓋章 payload 但走 `omitempty`——nil 時位元組與加欄前相同，既有已蓋章列零誤判。寫入端由 `cmd/server/audit_points_asset_pivot_guard_test.go` 逐產生點登記守衛 |
| `UserID` | uint | `not null;index:idx_audit_user_created,priority:1` | `user_id` | 操作者 ID。與 `CreatedAt` 的 priority 2 合成複合索引 `(user_id, created_at)` |
| `Username` | string | `type:varchar(100);not null` | `username` | 操作者名稱（反正規化） |
| `Method` | string | `type:varchar(10)` | `method` | HTTP 方法 |
| `Path` | string | `type:varchar(500)` | `path` | 請求路徑。**入庫前受長度收口**（見表後「字串欄位長度收口」）——`:id` 型路由可吸收任意長度，未收口時一個零憑證的超長路徑請求即可使整批 INSERT 回滾並沖掉同批的真實記錄 |
| `ClientIP` | string | `type:varchar(50);index:idx_*` | `client_ip` | 客戶端 IP（支援 IPv6） |
| `StatusCode` | int | - | `status_code` | HTTP 狀態碼 |
| `Duration` | int | - | `duration_ms` | 響應時間（毫秒）。**DB 欄名是 `duration`**——`duration_ms` 只是 JSON 別名 |
| `RequestBody` | string | `type:text` | `request_body` | 請求內容（脫敏） |
| `ErrorMsg` | string | `type:text` | `error_msg` | 錯誤訊息 |
| `Details` | string | `type:text` | `details` | 變更詳情（JSON） |
| `RequestID` | string | `type:varchar(100);index:idx_*` | `request_id` | 追蹤 ID |
| `IntegrityHMAC` | string | `type:varchar(64)` | `-` | 逐列完整性驗證碼（PCI 10.3.4；HMAC-SHA256 hex）。由 `AuditLog.BeforeCreate` 註冊 hook 蓋章，覆蓋**全部入庫路徑**（middleware 批次、asset GORM hook、file_tap、k8s cp）——**「入庫」二字是刻意的（誠實邊界 R2）**：檔案降級（`AuditLogService.writeToFile`）與佇列滿載丟棄的事件不進 DB、不經本 hook，既無 HMAC 也無 key_version，故 SHALL NOT 表述為「覆蓋全部寫入路徑」；基準前歷史列為空，基準後仍空即判不符（以列 id 對比 IntegrityBaseline.max_log_id 判定） |
| `KeyVersion` | int | migration default 0 | `-` | 蓋章鑰版本。0＝legacy 派生鑰快照（凍結為 audit_integrity DataKey v0，JWT_SECRET 輪替不影響歷史驗章），>=1 為系統生成的版本化鑰。驗證按列 KeyVersion 取對應鑰 |
| `IdempotencyUUID` | *string | `type:varchar(64);uniqueIndex:idx_audit_idempotency` | `-` | 封印期留痕回灌的冪等鍵。B 模式封印期的解封嘗試先寫入定長環狀 journal，解封後回灌審計；回灌為 **at-least-once**，故以本欄的唯一索引保證重複回灌不產生重複列。**一般審計列為 NULL**（唯一索引對 NULL 不生效）。合成的聚合列另以 `(journal_uuid, 起始 seq, 結束 seq)` 導出確定性 ID 填入本欄——聚合列無個別事件 uuid，若不給確定性鍵，checkpoint 未落盤而重跑時同一區間會重複入審計 |
| `IdempotencyUUID` | *string | `type:varchar(64);uniqueIndex:idx_audit_idempotency` | `-` | 回灌冪等鍵。封印期 journal 的 at-least-once 回灌以此去重：個別事件列用 journal 的確定性事件 ID，合成聚合列用 `(journal_uuid, 起始 seq, 結束 seq)` 導出的確定性 ID。**可為 NULL 且必須是指標**——一般審計列不帶此鍵，若用空字串則唯一索引會讓第二筆一般審計列直接寫入失敗；多個 NULL 在 Postgres 與 SQLite 的唯一索引下皆允許並存 |

**字串欄位長度收口**（`backend/internal/model/audit_log_bounds.go`）：
`AuditLog.BeforeCreate` 在**蓋章之前**把字串欄位收進各自 gorm 標籤宣告的上界內（上界由標籤
**反射導出**，不寫對照表——手寫表與 schema 雙向漂移都不會有測試轉紅），以字元（rune）而非
位元組計。被截斷的值保留**逐字為真的前綴**並附 `…[trunc len=N sha256=…]` 標記。
**順序不可對調**：HMAC 涵蓋這些欄位，先蓋後截即存值與章不符，鏈驗證會把正常寫入報成竄改。
**誠實邊界**：該標記寫在使用者可控的欄位本身，攻擊者可構造長度恰好等於上界、尾端自帶合法
形態標記的請求，故 `len=`／指紋只是線索而非防偽保證（規格明載，見 `openspec/specs/audit-coverage/`）；
完整原值另存於 access log（無長度上界、會輪替、不受鏈保護，屬補充證據）。
**本項不改 schema、無 migration**——收口的是寫入值，不是欄位宣告。

**操作類型常數**:
```go
type AuditAction string
const (
    ActionCreate  AuditAction = "create"
    ActionRead    AuditAction = "read"
    ActionUpdate  AuditAction = "update"
    ActionDelete  AuditAction = "delete"
    ActionExecute AuditAction = "execute"
    ActionLogin   AuditAction = "login"
    ActionLogout  AuditAction = "logout"

    // SFTP 檔案操作
    ActionFileList     AuditAction = "file_list"
    ActionFileUpload   AuditAction = "file_upload"
    ActionFileDownload AuditAction = "file_download"
    ActionFileMkdir    AuditAction = "file_mkdir"
    ActionFileDelete   AuditAction = "file_delete"
)
```

**資源類型常數**:
```go
type AuditResource string
const (
    ResourceAsset     AuditResource = "asset"
    ResourceSession   AuditResource = "session"
    ResourceRecording AuditResource = "recording"
    ResourceUser      AuditResource = "user"
    ResourceAuth      AuditResource = "auth"
    ResourceFile      AuditResource = "file"
    ResourceSecurityPolicy AuditResource = "security_policy" // 安全政策變更（PCI 10.2.2）
    //：告警審閱處置 / 稽核證據匯出 / 週期性存取複審
    ResourceCommandAlert AuditResource = "command_alert" // PCI 10.4.1
    ResourceAuditExport  AuditResource = "audit_export"  // PCI 10.5.1
    ResourceAccessReview AuditResource = "access_review" // PCI 7.2.4
)
```

**狀態常數**:
```go
type AuditStatus string
const (
    StatusSuccess AuditStatus = "success"
    StatusFailure AuditStatus = "failure"
    StatusDenied  AuditStatus = "denied"
)
```

**索引列表**（以 `pg_indexes.indexdef` 實測為準，非照抄宣告）:
- `idx_audit_created_at` - `(created_at)`
- `idx_audit_action_status` - `(action, status)`
- `idx_audit_resource` - `(resource, resource_id)`
- `idx_audit_user_created` - `(user_id, created_at)`，人樞紐的 keyset 查詢
- `idx_audit_asset_created` - `(asset_id, created_at)`，資產樞紐的 keyset 查詢

> 上列兩條的權威定義在 `baseline_schema_audit.go`；gorm tag 只是文件。
> 兩者的欄序等價由 `backend/internal/database/index_declaration_parity_test.go`
> （tag 宣告 vs `pg_index` 目錄實際欄序逐條比對）把關——**複合索引的欄序寫錯不會有任何症狀**，
> 查詢照樣回正確結果，只是走不到索引，故必須由守衛而非人眼確認。
- `idx_audit_client_ip` - `(client_ip)`
- `idx_audit_request_id` - `(request_id)`
- `idx_audit_idempotency` - UNIQUE `(idempotency_uuid)`
- `idx_audit_logs_deleted_at` - `(deleted_at)`

**GORM Hooks**:
- `BeforeCreate` - 確保 CreatedAt 設置（HMAC 涵蓋時戳，必須在此定值）＋經註冊 hook 蓋完整性 HMAC
- `AfterCreate` - 經註冊 hook tee 入 syslog 離機轉發（PCI 10.3.3，覆蓋全部**入庫**路徑；未入庫的降級事件同樣不轉發）
- `BeforeUpdate` - **禁止更新**（審計日誌不可變）
- `BeforeDelete` - **禁止 ORM 刪除**（含 Unscoped 硬刪；唯一刪除路徑為保留政策原生 SQL）

---

### 8. SessionCommand（文字終端指令審計記錄）

**表名**: `session_commands`
**檔案**: `backend/internal/model/session_command.go`
**建表方式**: baseline（`baseline_schema_audit.go`）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `SessionID` | uint | `not null` | `session_id` | 所屬會話 ID |
| `UserID` | uint | `not null` | `user_id` | 用戶 ID（冗餘，跨會話搜尋免 JOIN） |
| `AssetID` | *uint | - | `asset_id` | 資產 ID（冗餘，手動連線可為 NULL）。阻斷路徑同樣填此欄；無資產時寫 NULL，不得以 0 代表無值 |
| `Command` | string | `type:text;not null` | `command` | 重組出的指令行。**`Degraded=true` 時恆為空字串**，由 CHECK 約束釘死（見下方約束段）——降級列不得回填任何自螢幕內容推測的文字 |
| `Seq` | int | `not null` | `seq` | 會話內執行順序（從 1 開始） |
| `ExecutedAt` | time.Time | `type:timestamptz;not null` | `executed_at` | 執行（Enter）時間 |
| `K8sPod` | string | `size:253` | `k8s_pod` | K8s 冗餘欄：當次選定 pod（跨會話搜尋免 JOIN sessions） |
| `K8sContainer` | string | `size:63` | `k8s_container` | K8s 冗餘欄：當次 container |
| `Degraded` | bool | `not null;default:false` | `degraded` | **該輪沒有可信的指令文字**。全螢幕重繪、alt-screen 標記區間、無回顯輸入等情形下，重組結果不可信，此時記一筆降級列而非靜默丟棄——後者可被主動觸發成「零紀錄」。為 true 時 `Command` 必為空 |
| `DegradeReason` | string | `size:32` | `degrade_reason` | 降級原因機器碼。**兩個值域刻意不合併**：`Degraded=true` 時取 `Degrade*` 常數（無可信文字）；`Degraded=false` 且本欄非空時取 `Qualify*` 常數（**文字已入庫但可能不等於實際執行的指令**）。合併會使「`Degraded=false` ⇒ 文字可信」變成假話。值域見 `model/session_command.go` |

**約束**:
- `session_commands_degraded_no_text` - `CHECK ((NOT degraded) OR (command = ''))`。
  把「降級列不得含推測的指令文字」從約定升格為 **DB 層不變式**——
   spec 的「降級紀錄 SHALL NOT 包含推測的指令文字」機器可見化。

**索引列表**（以 `pg_indexes.indexdef` 實測為準）:
- `idx_session_commands_session_seq` - `(session_id, seq)`，單會話指令流取序
- `idx_session_commands_user_id` - `(user_id)`，跨會話搜尋常用維度
- `idx_session_commands_user_executed` - `(user_id, executed_at)`，稽核工作台人樞紐的指令類 keyset 查詢
- `idx_session_commands_asset_executed` - `(asset_id, executed_at)`，同上的資產樞紐側

**設計說明**:
- 由 proxy tunnel tap client→guacd 的 Guacamole `key` instruction 重組而來；涵蓋所有文字終端協議（SSH、DB CLI、K8s exec，即 `IsTextTerminal()`）
- 指令行為「重組自按鍵流」的盡力結果（可列印字元 + Enter 落行 + Backspace 修正），錄影回放仍是完整事實來源
- 無 FK 約束：寫入位於會話資料路徑（異步批次），避免外鍵檢查與級聯刪除影響會話可用性
- 不可變記錄：僅由 recorder 寫入，無更新/刪除 API
- **降級列與指令列共用 `Seq` 計數器**（`CommandStore` 單一發號來源），故兩者在
  `(session_id, seq)` 序上正確交錯——「第 3 輪降級、第 4 輪是真指令」即 seq 3 與 4，
  稽核視圖不需任何合併邏輯。分表會使 spec 主句「每一輪輸入 SHALL 產生一筆對應的
  審計記錄」由一次 count 變成一個 join
- **佇列滿載丟列時 `seq` 留下斷號，斷號本身即證據**（`s.seq++` 在 select 之前），
  由 `command_degrade_record_test.go` 的守衛釘住

---

### 9. AlertRule（危險指令告警/阻斷規則）

**表名**: `alert_rules`
**檔案**: `backend/internal/model/alert_rule.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `action`／`severity` 兩條 CHECK 與
`uniq_alert_rules_name` 唯一索引。**12 條內建規則的最終狀態**由 `baseline_seed.go` 的 `seedBuiltinAlertRules` 種入
（`ON CONFLICT (name) DO NOTHING`，衝突目標即該唯一索引）：ssh,k8s × 8、mysql,postgres,mssql × 3、redis × 1。
壓縮前這 12 條是三個 migration 疊加的結果（v7.9 八條 → `20260620` 回填 protocols 並增四條 →
`20260813` 把三條 SQL 規則擴含 mssql）；**schema 等價比對看不到種子資料**，故 protocols 分佈本身即為驗收項

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Name` | string | `size:100;not null` | `name` | 規則名稱 |
| `Pattern` | string | `type:text;not null` | `pattern` | 比對 regex（API 入庫前以 `regexp.Compile` 驗證） |
| `Severity` | string | `size:10;not null` | `severity` | 告警等級，CHECK 約束限定 `high`/`medium`/`low` |
| `Action` | string | `size:10;not null;default:alert` | `action` | `alert`=告警 / `block`=阻斷，CHECK 約束 |
| `Protocols` | string | `size:64;not null;default:''` | `protocols` | 逗號分隔適用協議（如 `ssh,k8s`、`mysql,postgres`）；空＝全協議。shell 與 SQL 規則語法不通用，依會話協議分流避免誤報 |
| `Enabled` | bool | `not null;default:true` | `enabled` | 停用規則不參與比對 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
- 規則全量預編譯快取於 `service.AlertMatcher` 單例（RWMutex 保護），規則 CUD 後同進程 Reload
- 種子規則：8 條 shell 規則（rm -rf、mkfs、dd of=/dev、chmod 777、chown -R root、shutdown/poweroff/reboot、iptables -F、curl/wget 管道執行，protocols 回填為 `ssh,k8s`）
  ＋ 4 條 DB 規則（DROP TABLE/DATABASE、TRUNCATE、GRANT ALL 限 `mysql,postgres`；FLUSHALL/FLUSHDB 限 `redis`）
- Go regexp 為 RE2 線性時間實作，無災難性回溯風險

---

### 10. CommandAlert（危險指令告警記錄）

**表名**: `command_alerts`
**檔案**: `backend/internal/model/command_alert.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `severity`／`kind`／`kind↔rule_id` 三條 CHECK。
`command_alerts_kind_check` 的值域由增量 migration `20260826_source_ip_forensics` 重建擴充
（`DROP CONSTRAINT` → `ADD CONSTRAINT ... CHECK (kind IN ('rule','audit_degraded','new_source_ip'))`，**約束名不變**）。
**刻意不設外鍵**：`rule_id`／`session_id` 是觸發當下的快照冗餘，規則改名或刪除不得破壞歷史告警

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `RuleID` | *uint | - | `rule_id,omitempty` | 命中規則 ID。**指標型且 DB 為 nullable**：`kind='audit_degraded'` 的告警沒有規則可指，值型會把「無規則」寫成 0 |
| `RuleName` | string | `size:100;not null` | `rule_name` | 規則名稱快照（冗餘，免 JOIN）。**降級類填機器碼**（該類無規則名可快照，同 `alert_notifier` 的 `testRuleName` 慣例） |
| `Kind` | string | `size:20;not null` | `kind` | 告警來源類別，現行值域三值：`rule`（規則比對／阻斷）／`audit_degraded`（指令審計降級）／`new_source_ip`（帳號首次自某來源位址建線）。CHECK 限定值域（`command_alerts_kind_check`，由 `20260826_source_ip_forensics` 重建擴充），另有 CHECK 釘住 `(kind='rule') = (rule_id IS NOT NULL)`——故後兩類的 `rule_id` 必為 NULL。**存在的理由是規格不變式不該掛在可 CRUD 的資料列上**——降級訊號若借一條內建規則承載，管理員停用該規則即可靜默關掉它；新來源位址告警同理 |
| `ReasonCode` | string | `size:64;not null` | `reason_code` | 非規則類告警的機器碼（現行值域兩值：`audit_degraded_span`／`new_source_ip_session`，見 `model/command_alert.go` 的 `AlertReason*` 常數）；規則類為空字串 |
| `SessionID` | uint | `not null` | `session_id` | 所屬會話 ID |
| `UserID` | uint | `not null` | `user_id` | 用戶 ID（冗餘） |
| `AssetID` | *uint | - | `asset_id` | 資產 ID（冗餘，手動連線可為 NULL） |
| `Command` | string | `type:text;not null` | `command` | 觸發告警的指令原文 |
| `Severity` | string | `size:10;not null` | `severity` | 告警等級快照，CHECK 約束限定 `high`/`medium`/`low` |
| `Blocked` | bool | `not null;default:false` | `blocked` | 觸發當下規則是否為阻斷型。 |
| `TriggeredAt` | time.Time | `type:timestamptz;not null` | `triggered_at` | 觸發時間（取指令執行時間） |
| `ReviewedBy` | *uint | - | `reviewed_by,omitempty` | 審閱者 ID（NULL＝未審閱）。 |
| `ReviewedAt` | *time.Time | - | `reviewed_at,omitempty` | 審閱時間；`reviewed_at IS NULL` 即「未審閱」（`unreviewed` 篩選與部分索引據此） |
| `Disposition` | string | `size:20;not null` | `disposition` | 處置分類：`pending`（預設/未審閱）/`benign`（誤報無害）/`escalated`（升級處理），DB 層 `DEFAULT 'pending'` |
| `Note` | string | `type:text;not null` | `note` | 審閱備註（DB 層 `DEFAULT ''`） |

**索引列表**（以 `pg_indexes.indexdef` 實測為準）:
- `idx_command_alerts_triggered_at` - `(triggered_at DESC)`，告警列表預設按時間倒序
- `idx_command_alerts_severity` - `(severity)`，常用過濾維度
- `idx_command_alerts_unreviewed` - `(triggered_at DESC) WHERE reviewed_at IS NULL`，部分索引加速每日未審閱走查
- `idx_command_alerts_user_triggered` - `(user_id, triggered_at)`，稽核工作台人樞紐的告警類 keyset 查詢
- `idx_command_alerts_asset_triggered` - `(asset_id, triggered_at)`，同上的資產樞紐側

**設計說明**:
- **四條寫入路徑、單一落地面**（第三條是下一則的降級告警，第四條是再下一則的新來源位址告警）：比對路徑（`proxy.CommandRecorder` writeLoop 在指令批次 flush 成功後比對）與阻斷路徑（`sshproxy` 的 `commandBlocker`，指令送往目標前攔下）皆經 `internal/modules/audit/alert_sink.go` 的落地面寫入，該處同時做「入庫 → 通知推送 → syslog 離機轉發」。**修復前阻斷路徑直寫本表且不做 syslog tee**，導致「實際被阻斷的危險指令」這一類最高價值證據只存在本機一份。兩路徑的錯誤處置皆為「僅 log、不影響指令入庫與會話」（無可回滾的業務交易）
- **第三條寫入路徑：指令審計降級的專用發射器**。由 `sshproxy` 的 `CommandStore` 在指令批次 flush 成功後、規則比對之後呼叫，落地經同一個 `AlertSink`（故通知與 syslog tee 自動接上）。
  **不走規則表**是刻意的：規則是可 CRUD 停用／刪除的營運物件，把規格要求的安全訊號掛上去等於交出「管理員一鍵靜默」的開關；且內建規則數有硬斷言，還得為它填一個永不匹配的 pattern＝在機器欄裡寫謊。
  該類的 `kind='audit_degraded'`、`rule_id IS NULL`、`command=''`（降級的定義就是沒有可信的指令文字）、`severity='medium'`。
  **以 span 為單位，一段連續降級只發一筆**：真 vim 一次編輯產生數十筆降級列，逐列告警＝告警疲勞。
  **刻意沒有「超過門檻升級為 high」的第二筆**——正常的全螢幕程式（vim／nano）與偽標記攻擊，其 span 在時長與輪數上不可分（攻擊側只要令對端停止回顯，就與真 vim 同形），填一個看起來能分的門檻是編造判準
- **第四條寫入路徑：新來源位址告警**（`kind='new_source_ip'`、`reason_code='new_source_ip_session'`、
  `rule_id IS NULL`、`command=''`、`severity='medium'`）。由 `internal/modules/audit/source_ip_baseline.go`
  的 `ObserveSession` 在**同一個交易內**寫入（`RecordAlertInTx`）：基準表 `user_source_ips` 的
  `first_session_id` 條件更新決出單一勝者，只有勝者那一筆交易寫告警列——並發同址首連線因此恰好一筆。
  推送與 syslog tee 在**提交之後**才做（`PublishCommitted`），入庫失敗即不發幽靈告警。
  同樣不走規則表，理由與降級告警同：規則可被停用即可靜默關掉安全訊號。
- **降級列不進規則比對**：`session_commands.degraded` 為真的列在 `MatchAndStore` 迴圈首即跳過。內建規則不會命中空字串，但使用者可自建 `.*` 規則，屆時每筆降級列都會生出一筆 `command=''` 的告警——那是把「這一輪無法還原」呈現成「使用者執行了一條空指令」，即另一種捏造
- 批次告警為單次 INSERT（`RecordAlerts`），不得拆成 N 次
- `rule_name`/`severity`/`blocked` 為觸發當下快照：規則之後改名、改級、改 action 或刪除不影響歷史告警可讀性
- `blocked` 取代原先寫入 `rule_name` 的「（已阻斷）」後綴散文：阻斷事實改以布林欄結構化承載，`rule_name` 自此為純淨規則名；出站 webhook payload 帶 `blocked`，Slack 由伺服端翻譯目錄依通道語系渲染標示
- 無 FK 約束：與 `session_commands` 同取向，寫入位於會話資料路徑旁，避免外鍵檢查影響可用性
- 審閱處置（PCI 10.4.1）：**兩條寫入路徑皆**顯式設 `disposition=pending`（阻斷路徑漏設此欄時 DB 收到空字串，審閱清單的「未審閱」篩選就會漏掉阻斷告警）；
  審閱冪等，重覆審閱同一告警更新處置並刷新 `reviewed_at`。struct 不用 gorm `default` tag（避免 GORM Create 對零值欄位改走 RETURNING 讀回，破壞既有 sqlmock 期望），NOT NULL DEFAULT 由 baseline 的建表語句設

---

### 11. NotificationChannel（告警通知通道）

**表名**: `notification_channels`
**檔案**: `backend/internal/model/notification_channel.go`
**建表方式**: baseline（`baseline_schema_platform.go`），含 `type`（`webhook`／`slack`）與
`language`（三語）兩條 CHECK

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Name` | string | `size:100;not null` | `name` | 通道名稱 |
| `Type` | string | `size:20;not null;default:webhook` | `type` | 通道類型，CHECK 約束限 `webhook`/`slack`（預留 email/SMS 擴充） |
| `URL` | string | `type:text;not null` | `url` | webhook 端點，僅允許 http/https |
| `Secret` | string | `type:text` | `-` | HMAC-SHA256 簽名密鑰（`X-OT-Signature`），空字串=不簽名 |
| `Enabled` | bool | `not null;default:true` | `enabled` | 啟用狀態 |
| `Language` | string | `size:8;not null;default:zh-TW` | `language` | per-channel 語系，CHECK 約束限 `zh-TW`/`en-US`/`ja-JP`。 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
- secret 存明文：通道整組 admin only 且需原文計算 HMAC 簽名無法雜湊；與資產憑證不同（憑證有 AES 加密），首版信任 DB 邊界（其後 改為 `url`/`secret` 信封加密落庫）
- `language` 語義：Create 未給＝預設 `zh-TW`；Update **省略＝保留舊值**，顯式空字串或白名單外值一律拒（API 層 `VALIDATION_CHANNEL_LANGUAGE`＋DB CHECK 雙層，同 `type` 欄慣例）。只影響 Slack 通道的伺服端組字語言（`internal/notifycat` 渲染），webhook 型可設但目前無作用

---

### 12. ClipboardEvent（剪貼簿審計）

**表名**: `clipboard_events`
**檔案**: `backend/internal/model/clipboard_event.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `idx_clipboard_events_session_id`；
無 `deleted_at` 欄、無外鍵

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `SessionID` | uint | `index;not null` | `session_id` | 所屬會話 ID |
| `Direction` | string | `size:8;not null` | `direction` | `send`=入遠端 / `recv`=回拷 |
| `ContentEnc` | string | `type:text` | `-` | 剪貼簿內容的**信封加密密文**（`enc:a1` 格式；AAD 綁 `clipboard_events\|content_enc`，登記於 `envelopeMigrationTargets` 與 `cipher_refs.go`）。**明文欄已移除**；`json:"-"` 不外露，內容僅經單筆調閱端點（逐筆留痕）與證據包（匯出留痕）解密取得。缺口紀錄（`content_status=failed`）此欄恆為空字串 |
| `ContentLength` | int | `not null` | `content_length` | 明文**位元組**長度（與 64KB tap 截斷上限同單位）；長度是事實非機密，供列表與匯出陳述使用 |
| `ContentStatus` | string | `size:16;not null` | `content_status` | 內容狀態：`available`＝已加密落庫可解密調閱／`failed`＝加密失敗的缺口紀錄（事實齊、內容缺）。**明確欄位，不以密文為空或長度為零推斷** |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |

**設計說明**:
- RDP/VNC 剪貼簿內容留存，無軟刪除、無更新路徑。
- **內容以信封加密落庫**：明文 `content` 欄移除，改存
  `content_enc`（密文）＋`content_length`（事實）＋`content_status`（可調閱／缺口）。加密失敗時
  不以明文落庫、不中斷會話、亦不整筆丟棄，改留缺口紀錄（`content_status=failed`、內容欄空），
  使「此類永不清除、空白即無事件」的誠實宣稱不被靜默缺口打破。
- 既有資料庫的 `content`→`content_enc` 轉換（加欄→逐筆加密回填→刪 `content`）需要 codec，
  走 **post-unseal 佇列**（非增量 versioned migration），以「`content` 欄是否存在」判冪等，
  整段包在單一交易內，回填失敗即 rollback、不刪欄（fail-close）。

---

### 13. AssetHostKey（SSH Host Key 記錄）

**表名**: `asset_host_keys`
**檔案**: `backend/internal/model/host_key.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_asset_host_keys_asset_id`＝`UNIQUE (asset_id)`
——TOFU 的「一資產至多一筆已信任指紋」即由這條唯一索引承載

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `AssetID` | uint | `uniqueIndex;not null` | `asset_id` | 資產 ID（每資產一筆） |
| `Algorithm` | string | `size:64;not null` | `algorithm` | 金鑰演算法 |
| `Fingerprint` | string | `size:128;not null` | `fingerprint` | `SHA256:xxx` 格式指紋 |
| `PublicKey` | string | `type:text;not null` | `-` | base64 公鑰本體（不外露） |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
- TOFU：首連記錄，之後指紋不符即拒線

---

### 14. Snippet（命令片段）

**表名**: `snippets`
**檔案**: `backend/internal/model/snippet.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_snippets_user_id`；
無 `deleted_at` 欄、無唯一索引（同一使用者可有同名片段）、無外鍵

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `UserID` | uint | `index;not null` | `user_id` | 擁有者（user-scoped） |
| `Name` | string | `size:128;not null` | `name` | 片段名稱 |
| `Content` | string | `size:4096;not null` | `content` | 片段內容 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
-：內容僅作為文字注入終端輸入，不直接執行

---

### 15. ChangeSecretPlan（改密計劃）

**表名**: `change_secret_plans`
**檔案**: `backend/internal/model/change_secret.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_change_secret_plans_name`＝`UNIQUE (name)`
（**非** partial：本表無 `deleted_at`，計劃為硬刪）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Name` | string | `size:128;not null;uniqueIndex` | `name` | 計劃名稱 |
| `AssetIDs` | string | `type:text;not null` | `asset_ids` | 目標資產集合，JSON 陣列字串（如 `"[1,3]"`） |
| `Accounts` | string | `type:text` | `accounts` | 帳號範圍，JSON 字串陣列；`["@ALL"]`＝該資產全部帳號，否則為 username 明列集合。空值一律讀成 `@ALL`（回歸安全方向） |
| `Cron` | string | `size:64` | `cron` | 排程（空值＝僅手動觸發） |
| `Enabled` | bool | `default:true` | `enabled` | 啟用狀態 |
| `SecretType` | string | `size:16;default:password` | `secret_type` | 秘密類型（`password`／`ssh_key`） |
| `KeyStrategy` | string | `size:16;default:append_replace` | `key_strategy` | SSH 金鑰輪替策略（`append_replace`／`exclusive`）；僅 `SecretType=ssh_key` 時有意義 |
| `PasswordLength` | int | `default:16` | `password_length` | 產生密碼長度（邊界 12–64） |
| `PasswordIncludeSymbol` | bool | `default:true` | `password_include_symbol` | 是否含符號 |
| `PasswordExcludeAmbiguous` | bool | `default:true` | `password_exclude_ambiguous` | 是否排除易混淆字元 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
- 密碼策略為 **per-plan**，不進全域安全政策鍵——那域管的是平台使用者密碼。
  大小寫與數字恆為必要字類、shell 敏感字元與控制字元為系統級硬排除，皆不開放設定。

---

### 16. ChangeSecretRecord（改密執行記錄）

**表名**: `change_secret_records`
**檔案**: `backend/internal/model/change_secret.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `plan_id`／`asset_id`／`account_id` 三條一般索引；
無唯一索引、無外鍵、無 `deleted_at`（`account_username` 與 `account_id` 並存，記錄執行當下的帳號名）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `PlanID` | uint | `index;not null` | `plan_id` | 所屬計劃 ID |
| `AssetID` | uint | `index;not null` | `asset_id` | 目標資產 ID |
| `AccountID` | uint | `index` | `account_id` | 執行時釘住的帳號；`0`＝尚未解析到帳號即失敗（如資產無帳號） |
| `AccountUsername` | string | `size:100` | `account_username` | 執行當下的帳號名快照 |
| `SecretType` | string | `size:16` | `secret_type` | 秘密類型（`password`／`ssh_key`） |
| `Status` | string | `size:16;not null` | `status` | 執行狀態 |
| `Error` | string | `size:512` | `error` | 錯誤訊息 |
| `ExecutedAt` | time.Time | - | `executed_at` | 執行時間 |

**狀態常數**:
```go
const (
    ChangeSecretSuccess = "success"
    // 遠端確定未變更（指令跑完但非零退出）：帳號憑證原樣、候選已清
    ChangeSecretFailed = "failed"
    // 遠端狀態不可知（連線中斷／逾時／驗證失敗）：帳號憑證維持舊值、
    // 候選保留待系統重試
    ChangeSecretUnverified = "unverified"
    ChangeSecretSkipped    = "skipped"
)
```

**設計說明**:
- 不存任何密碼
- `AccountID` ＋ `AccountUsername` 雙快照沿 session 的不可否認性慣例——帳號可能隨後
  改名或刪除，只留 ID 則事後回答不了「當時改的是哪個帳號」

---

### 16b. ChangeSecretCandidate（未驗證候選憑證）

**表名**: `change_secret_candidates`
**檔案**: `backend/internal/model/change_secret.go`
**建表方式**: baseline（`baseline_schema_asset.go`），含 `idx_change_secret_candidates_account_id`＝`UNIQUE (account_id)`
——「一帳號至多一筆未驗證候選」即由這條唯一索引承載（**非** partial：本表無 `deleted_at`）；
另有 `asset_id`／`abandoned`／`next_attempt_at` 三條一般索引（重試排程掃描依賴之）；無外鍵

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `AccountID` | uint | `uniqueIndex;not null` | `account_id` | 所屬資產帳號；唯一——同一帳號不疊加第二個未知狀態 |
| `AssetID` | uint | `index;not null` | `asset_id` | 目標資產 |
| `PlanID` | uint | - | `plan_id` | 來源改密計劃（0＝手動觸發） |
| `AccountUsername` | string | `size:100` | `account_username` | 執行當下的帳號名快照 |
| `SecretType` | string | `size:16;not null` | `secret_type` | 秘密類型（`password`／SSH 金鑰） |
| `PasswordEnc` | string | `type:text` | `-` | 候選密碼（信封加密），**絕不出站** |
| `PrivateKeyEnc` | string | `type:text` | `-` | 候選 SSH 私鑰（信封加密），同上 |
| `PublicKey` | string | `type:text` | `public_key` | 新公鑰的 authorized_keys 行（公鑰非機密，明文保存供刪舊／還原比對） |
| `PreviousPublicKey` | string | `type:text` | `previous_public_key` | 本系統先前推送的公鑰行；空值＝無舊行可刪 |
| `Applied` | bool | `default:false` | `applied` | 遠端變更指令已回報成功；false＝遠端狀態不可知（下達中被中斷） |
| `Abandoned` | bool | `default:false;index` | `abandoned` | 超過重試期限：停止重試並告警。**列不自動刪除** |
| `AttemptCount` | int | `default:0` | `attempt_count` | 重試次數 |
| `LastAttemptAt` | time.Time | - | `last_attempt_at` | 最後嘗試時間 |
| `NextAttemptAt` | time.Time | `index` | `next_attempt_at` | 下次嘗試時間（排程掃描鍵） |
| `LastError` | string | `size:512` | `last_error` | 最後錯誤 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**設計說明**:
- 秘密於**動遠端之前**落庫：後端在「已下達改密、尚未驗證」的窗口被砍時，
  候選若只在記憶體即永久遺失，帳號直接鎖死。
- 候選列的存在**即代表**該帳號憑證處於「未驗證」狀態，不另設會與之漂移的狀態欄位。
- **安全紅線**: `password_enc`／`private_key_enc` 須登記於 `envelopeMigrationTargets`
  （AST 守衛 `envelope_targets_guard_test.go` 強制），漏登會使退役 DEK 銷毀前的引用掃描誤判零引用。

---

### 17. SecurityPolicy（安全政策 key-value）

**表名**: `security_policies`
**檔案**: `backend/internal/model/security_policy.go`
**建表方式**: baseline（`baseline_schema_identity.go`）。無列時以常數表出廠預設生效，故 seed 不需預先物化政策列

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `Key` | string | `primaryKey;size:64` | `key` | 政策鍵（值域見下） |
| `Value` | string | `size:128;not null` | `value` | 政策值（一律字串存放，型別語義由服務層常數表定義） |
| `UpdatedBy` | string | `size:100` | `updated_by` | 最後修改者 |
| `UpdatedAt` | time.Time | - | `updated_at` | 最後修改時間 |

**政策鍵值域與 PCI 建議值**（常數表 `service.policyDefs`，PCI 建議值以官方《PCI DSS v4.0.1》June 2024 定稿；
出廠預設多為易用取向，PCI 值供「一鍵套用」符合性評估）:

| Key | 型別 | 出廠預設 | PCI 建議 | 方向 | PCI 條號 | 說明 |
|-----|------|--------|--------|------|--------|------|
| `lockout_max_attempts` | int | `10` | `10` | max | 8.3.4 | 登入失敗鎖定次數上限（0=停用；上界 1000） |
| `lockout_duration_minutes` | int | `30` | `30` | min | 8.3.4 | 鎖定時長（上界 10080＝7 天，防 int64 溢位） |
| `password_min_length` | int | `12` | `12` | min | 8.3.6 | 密碼最小長度（上界 128） |
| `password_require_alnum` | bool | `true` | `true` | - | 8.3.6 | 密碼須含字母與數字 |
| `password_history_count` | int | `4` | `4` | min | 8.3.7 | 禁止重用最近密碼筆數（0=停用；**上界 24**） |
| `force_change_on_reset` | bool | `true` | `true` | - | 8.3.5 | 管理員重設後強制改密 |
| `mfa_required` | enum | `off` | `all` | 序位 | 8.4.2 | 多因子強制範圍（弱→強：`off`/`admin_only`/`all`） |
| `web_idle_minutes` | int | `60` | `15` | max | 8.2.8 | Web 會話閒置逾時（0=停用；上界 10080） |
| `web_max_session_hours` | int | `12` | （無） | - | - | Web 會話最長時數（0=不限；上界 8760；PCI 未規定不評估符合性） |
| `session_idle_minutes` | int | `60` | `15` | max | 8.2.8 | 協議會話閒置逾時（0=停用；上界 10080；以 `SSH_IDLE_TIMEOUT_MINUTES` 初始化） |
| `session_max_minutes` | int | `0` | （無） | - | - | 協議會話最長時長（0=不限；上界 525600；以 `SSH_MAX_SESSION_MINUTES` 初始化） |
| `inactive_disable_days` | int | `0` | `90` | max | 8.2.6 | 閒置帳號自動停用天數（0=關閉；上界 3650） |
| `retention_audit_log_days` | int | `0` | `365` | min | 10.5.1 | 操作日誌保留天數（0=永久保留＝未定義保留政策，判不符；上界 3650） |
| `retention_session_command_days` | int | `0` | `365` | min | 10.5.1 | 指令流保留天數（同上） |
| `retention_alert_days` | int | `0` | `365` | min | 10.5.1 | 告警記錄保留天數（同上） |
| `retention_recording_days` | int | `90` | `365` | min | 10.5.1 | 會話錄影保留天數（初始值由 `RECORDING_RETENTION_DAYS` 播種） |
| `daily_review_enabled` | bool | `false` | `true` | - | 10.4.1 | 每日審閱簽核 |
| `failure_alert_enabled` | bool | `false` | `true` | - | 10.7.2 | 審計失效告警通知（失效事件記錄恆開，此鍵僅控通知） |
| `key_cryptoperiod_reminder_days` | int | `0` | `365` | max | 3.7.4 | 金鑰輪替提醒天數（0=不提醒；純提醒不觸發動作） |
| `transport_rdp_level` | enum | `off` | `warn` | 序位 | 4.2.1 | RDP 傳輸強制等級（弱→強：`off`/`warn`/`strict`） |
| `transport_vnc_level` | enum | `off` | `warn` | 序位 | 4.2.1 | VNC 傳輸強制等級（同上） |
| `transport_db_level` | enum | `off` | `warn` | 序位 | 4.2.1 | 資料庫傳輸強制等級（同上） |
| `transport_ldap_level` | enum | `off` | `warn` | 序位 | 4.2.1 | LDAP 傳輸強制等級（登入時 runtime 閘；strict 拒 LDAP 登入本地帳號不受影響） |
| `transport_syslog_level` | enum | `off` | `warn` | 序位 | 4.2.1 | syslog 傳輸強制等級（同上） |
| `transport_notify_level` | enum | `off` | `warn` | 序位 | 4.2.1 | 通知傳輸強制等級（同上） |
| `transport_consent_ttl_days` | int | `90` | （無） | - | - | 傳輸風險同意效期（0=永不過期；上界 3650；PCI 未規定不評估符合性） |
| `access_policy_default` | enum | `open` | `approval` | 序位 | 7.2 | 全域預設存取政策段位（弱→強：`open`/`reason`/`approval`；資產未個別設定時生效） |
| `access_request_max_duration_minutes` | int | `1440` | `1440` | max | 7.2 | 申請時長上限（上界 525600＝1 年） |
| `access_request_pending_timeout_hours` | int | `72` | `72` | max | 7.2 | 申請待審超時時限（上界 8760＝1 年） |
| `break_glass_enabled` | bool | `false` | `false` | - | 7.2 | 破窗緊急連線開關（opt-in，關閉期緊急通道＝admin 豁免） |
| `break_glass_duration_minutes` | int | `60` | `60` | max | 7.2 | 破窗票證固定時窗（上界 1440＝1 天；不開放破窗人自填） |
| `break_glass_review_timeout_hours` | int | `24` | `24` | max | 7.2 | 破窗補審逾期時限（上界 720＝30 天；逾期升級告警） |
| `access_revoke_disconnect` | bool | `false` | `true` | - | 7.2 | 撤銷即斷線（出廠關＝只擋新連線；建議開，與到期語義一致的預設取捨） |

**設計說明**:
- 服務層 typed accessor（Get/GetInt/GetBool）＋ 30 秒 TTL 快取（「更新即失效」不等 TTL）
- `SeedFromEnv` 以既有環境變數初始化（僅在 DB 尚無該鍵列時），升級相容
- 常數表打錯字（enum PCIValue 非成員、int 預設不可解析等）在啟動時 panic（常數表自檢），寧可不上線也不靜默誤判符合性

---

### 18. PasswordHistory（密碼歷史）

**表名**: `password_histories`
**檔案**: `backend/internal/model/security_policy.go`
**建表方式**: baseline（`baseline_schema_identity.go`）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `UserID` | uint | `not null;index` | `user_id` | 所屬用戶 |
| `PasswordHash` | string | `not null` | `-` | bcrypt 雜湊（永不輸出） |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |

**設計說明**:
- 每次設定密碼（建立帳號/seed/自助改密/admin 重設）都寫入一筆；改密時**逐筆以該筆當初的演算法**比對近 N 筆（`password_history_count`）拒絕重用（PCI 8.3.7）。
  **歷史列不可重新雜湊**（write-once）：轉換需要明文而系統沒有明文，且偷偷升級比中的那筆會使「撞到第幾筆」成為可觀察側信道。
  **上界 24 的理由**：每多一筆歷史就多一次密碼雜湊比對，直接決定改密請求的成本——實測設 100 時單次改密約 8 秒（登入的 103 倍），而改密端點對外暴露
- 初始密碼也入表，否則首次強制改密可設回原密碼
- 歷史裁剪保底 4 筆：政策調低（含 0=關閉）時仍保留 PCI 建議筆數，避免日後調回時歷史已被清空

---

### 19. RefreshToken（Web 會話刷新憑證）

**表名**: `refresh_tokens`
**檔案**: `backend/internal/model/refresh_token.go`
**建表方式**: baseline（`baseline_schema_identity.go`；PCI 8.2.8）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `UserID` | uint | `not null;index` | `user_id` | 所屬用戶 |
| `TokenHash` | string | `size:64;uniqueIndex;not null` | `-` | 憑證明文的 SHA-256 hex（明文僅發放當下回傳，DB 只存雜湊） |
| `SessionStartedAt` | time.Time | `not null` | `session_started_at` | 絕對壽命錨點（登入時刻）；rotation 沿用不重置 |
| `ExpiresAt` | time.Time | `not null` | `expires_at` | 絕對壽命（登入時刻 + `web_max_session_hours`；0=不限時為遠期哨兵 10 年） |
| `LastUsedAt` | time.Time | `not null` | `last_used_at` | sliding 閒置錨點（發放與每次刷新時間，8.2.8 閒置判定基準） |
| `AuthMethod` | string | `size:32` | `-` | 認證脈絡：本會話以何種方式建立。零值＝本地／LDAP 登入 |
| `ProviderID` | uint | `index` | `-` | 認證脈絡：由哪個 `oidc_providers.id` 認證；0＝不受任何 provider 停用影響。同 migration |
| `AuthEpoch` | int | `not null;default:0` | `-` | 認證脈絡：簽發當下的 provider 世代（`oidc_providers.auth_epoch` 快照），刷新時比對現行值。同 migration |
| `CredEpoch` | int | `not null;default:0` | `-` | 認證脈絡：簽發當下的使用者世代（`users.credential_epoch` 快照）。同 migration |
| `RevokedAt` | *time.Time | `index` | `revoked_at,omitempty` | 撤銷時間 |
| `RevokedReason` | string | `size:32` | `revoked_reason,omitempty` | 撤銷原因（見下），供審計與 reuse detection 判別 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |

**撤銷原因常數**:
```go
const (
    RefreshRevokeRotated        = "rotated"          // 正常輪替：舊憑證作廢、鏈上有新憑證
    RefreshRevokeLogout         = "logout"           // 使用者登出
    RefreshRevokePasswordChange = "password_change"  // 改密撤銷全部會話（8.3.5 語義延伸）
    RefreshRevokeDisabled       = "disabled"         // 帳號停用（admin）撤銷全部
    RefreshRevokeLocked         = "locked"           // 帳號自動鎖定撤銷全部（不砍協議會話）
    RefreshRevokeReuseDetected  = "reuse_detected"   // 已輪替憑證被重放 → 家族撤銷（RFC 9700）
    RefreshRevokeIdleTimeout    = "idle_timeout"     // 閒置逾政策窗口（8.2.8）
    RefreshRevokeExpired        = "expired"          // 逾絕對壽命
    RefreshRevokeProviderDisabled = "provider_disabled" // provider 停用／刪除／密鑰輪替
    RefreshRevokeCredentialEpoch  = "credential_epoch"  // 使用者憑證世代推進（解綁外部身分／改為僅外部登入等）
)
```

**設計說明**:
- 刷新時輪替（舊列標 `rotated`、發新列）；已輪替列再被提交＝憑證洩漏訊號，撤銷該使用者全部 refresh（家族撤銷，RFC 9700）
- **rotation 必須顯式沿用四個認證脈絡欄位**：現行 rotation 只複製五個欄位，
  不顯式沿用則 access token 輪替一次（分鐘級）後撤銷目標即失聯，provider 停用時「正在使用中的會話一個都撤不到」；
  對應測試須**先輪替再停用**，否則恆綠而無效
- 明文為密碼學隨機 256 bit（64 字元 hex），DB 只存 SHA-256：DB 洩漏不等於憑證洩漏
- 與短效 access token（15 分固定）搭配：access 無狀態、快過期，長期會話續命全靠此表的 rotation

---

### 20. AccessReview（週期性存取複審簽核）

**表名**: `access_reviews`
**檔案**: `backend/internal/model/access_review.go`
**建表方式**: baseline（`baseline_schema_authz.go`，PCI 7.2.4）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `ReviewedBy` | uint | `not null` | `reviewed_by` | 複審者用戶 ID |
| `ReviewerName` | string | `size:50` | `reviewer_name` | 複審者名稱（反正規化快照） |
| `ReviewedAt` | time.Time | `not null` | `reviewed_at` | 複審時間 |
| `Scope` | string | `size:200;not null` | `scope` | 複審範圍描述（v1 為全庫：`全部使用者存取權（user × asset/group × permission）`） |
| `Note` | string | `type:text;not null` | `note` | 複審結論備註（管理層確認語意） |
| `AuthorizationCount` | int | `not null` | `authorization_count` | 複審當下的授權筆數（快速摘要） |
| `MatrixSnapshot` | string | `type:text;not null` | `-` | 複審當下完整存取矩陣的 JSON 快照（不可變證據，永不輸出 JSON；可另行匯出/檢視） |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |

**設計說明**:
- append-only 不可變證據：ORM 層 `BeforeUpdate`/`BeforeDelete` 一律回 `ErrAccessReviewImmutable`（縱深防禦，比照 AuditLog），即使誤加 update 路徑也不會靜默竄改快照
- v1 補償控制：一筆簽核＝複審者＋時間＋範圍＋結論＋矩陣快照；完整逐列 campaign（保留/撤銷決策）列 v1.1
- 回應與列表不帶大型 `MatrixSnapshot`（避免回應肥大），快照僅供證據匯出/檢視取用

---

### 21. DailyReviewLog（每日審閱簽核）

**表名**: `daily_review_logs`
**檔案**: `backend/internal/model/daily_review.go`
**建表方式**: baseline（`baseline_schema_audit.go`，PCI 10.4.1/10.4.1.1）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `ReviewDate` | string | `type:varchar(10);not null;uniqueIndex` | `review_date` | 審閱日（YYYY-MM-DD；每日至多一筆） |
| `ReviewerID` | uint | `not null` | `reviewer_id` | 簽核者 ID |
| `ReviewerName` | string | `type:varchar(100);not null` | `reviewer_name` | 簽核者名稱（反正規化） |
| `SnapshotJSON` | string | `type:text;not null` | `snapshot_json` | 簽核當下事件計數快照（登入失敗/未審閱告警/高危操作） |
| `Note` | string | `type:text` | `note` | 備註（選填） |
| `CreatedAt` | time.Time | - | `created_at` | 簽核時間 |

---

### 22. AuditFailureEvent（審計機制失效事件）

**表名**: `audit_failure_events`
**檔案**: `backend/internal/model/audit_failure.go`
**建表方式**: baseline（`baseline_schema_audit.go`，PCI 10.7.2/10.7.3；記錄恆開）。
`idx_failure_events_single_open` partial unique 承載「一機制至多一個未結案失敗區間」，
以 `pg_get_indexdef` 逐字比對釘在 `baselineStructuralAssertions`

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Mechanism` | string | `type:varchar(30);not null;index:idx_failure_mechanism_open` | `mechanism` | 機制（`audit_write`/`syslog_forward`/`recording_probe`/`recording_text`/`recording_graphics`/`session_record`/`kek_retirement`/`source_policy`） |
| `StartedAt` | time.Time | `not null` | `started_at` | 失效開始 |
| `EndedAt` | *time.Time | `index:idx_failure_mechanism_open` | `ended_at` | 恢復時間（null=進行中；同機制進行中去重，另有 partial 唯一索引 `idx_failure_events_single_open` 強制） |
| `Cause` | string | `type:text;not null` | `cause` | 失效原因散文（10.7.3）。**本欄為顯示 fallback**（zh-TW 短語＋forensic detail），權威表述改為 `CauseCode`；保留以免未改查譯的既有讀取點白屏 |
| `CauseCode` | string | `size:64;not null;default:''` | `cause_code` | 失效原因機器碼＝權威表述，值域見 `model/audit_failure.go` 的 `Cause*` 常數；三語短語由 `internal/notifycat` cause 詞庫渲染。 |
| `CauseParams` | string | `type:text;not null;default:''` | `cause_params` | `CauseCode` 的參數（JSON 字串；API 輸出時解碼為物件）。含 `detail` 鍵時為 forensic 明細（底層 err 原文），**不進出站 payload**。 |
| `Details` | string | `type:text` | `details` | 詳情（forensic 原文，定性不翻譯） |

**設計說明**:
- 新增 cause code 常數＝同時補三語詞庫鍵，否則 `TestCauseEnumMatchesModel`／`TestLexiconCompleteness` 轉紅；碼值即 DB 與前端契約，改值等同 migration
- dev 階段不轉存量：既有列 `cause_code`/`cause_params` 為空字串，前端沿 `cause` 散文顯示

---

### 23. SyslogSetting（syslog 轉發設定）

**表名**: `syslog_settings`
**檔案**: `backend/internal/model/syslog_setting.go`
**建表方式**: baseline（`baseline_schema_platform.go`，PCI 10.3.3；單列表 ID=1）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 恆為 1 |
| `Enabled` | bool | `not null;default:false` | `enabled` | 轉發開關 |
| `Host` | string | `type:varchar(255);not null;default:''` | `host` | 目的地主機 |
| `Port` | int | `not null;default:514` | `port` | 目的地埠 |
| `Protocol` | string | `type:varchar(10);not null;default:'udp'` | `protocol` | `udp`/`tcp`/`tcp+tls` |
| `TLSCA` | string | `type:text;not null;default:''` | `tls_ca` | 驗證伺服器憑證的 CA（PEM；空=系統信任庫） |
| `UpdatedBy` | string | `type:varchar(100)` | `updated_by` | 最後修改者 |
| `UpdatedAt` | time.Time | - | `updated_at` | 最後修改時間 |

---

### 24. ExportSigningKey（匯出簽章金鑰）

**表名**: `export_signing_keys`
**檔案**: `backend/internal/model/signing_key.go`
**建表方式**: baseline（`baseline_schema_platform.go`，PCI 10.3.4；單列表 ID=1，首啟自動生成）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 恆為 1 |
| `PrivateKeyEnc` | string | `type:text;not null` | `-` | Ed25519 私鑰（AES 加密，同 `ENCRYPTION_KEY`；金鑰變更後既有簽章鑰不可解=啟動報錯不靜默重生） |
| `PublicKey` | string | `type:varchar(64);not null` | `public_key` | 公鑰（base64，供下載端點） |
| `CreatedAt` | time.Time | - | `created_at` | 生成時間 |

---

### 25. IntegrityBaseline（完整性啟用基準）

**表名**: `integrity_baselines`
**檔案**: `backend/internal/model/integrity_baseline.go`
**建表方式**: baseline（`baseline_schema_audit.go`，PCI 10.3.4；單列表 ID=1，首啟寫入當下時間與最大列 id）
**Migration**: `20260715_integrity_baseline_max_log_id`（既有基準以 created_at 邊界一次性回填 max_log_id）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 恆為 1 |
| `BaselineAt` | time.Time | `not null` | `baseline_at` | 完整性功能啟用時間（顯示與記載用） |
| `MaxLogID` | uint | DB 端 default 0 | `max_log_id` | 基準建立當下 audit_logs 最大 id。驗證端點對「基準後（id > max_log_id）仍空 HMAC」的列判不符（堵竄改＋清空 HMAC、回填時間插列規避），基準前（id <= max_log_id）空 HMAC 列歸 Legacy。以不可回填的自增 id 判定，非 created_at——created_at 可被插入端指定，判別力不足 |

---

### 26. DataKey（信封加密金鑰表）

**表名**: `data_keys`
**檔案**: `backend/internal/model/data_key.go`
**建表方式**: baseline（`baseline_schema_platform.go`，PCI Req 3 自我要求框架）。
`idx_data_keys_purpose_version_kek` partial unique（`WHERE kek_retired_at IS NULL`）承載「同 slot 至多一列帶材料」，
使退役列得以保留指紋史而不佔活動唯一鍵；以 `pg_get_indexdef` 逐字比對釘在 `baselineStructuralAssertions`

每列一把被 KEK（`ENCRYPTION_KEY`）包裹的金鑰材料。每 purpose 同時僅一把 active；retired 鑰永久保留供舊資料解密與歷史驗章，不得刪除。KEK 重包過渡期同一 (purpose, version) 允許新舊 kek_id 各一列並存；新 KEK 開機驗證成功後的切換收尾為軟刪除退役——舊 kek_id 包裹列不硬刪，改標 `kek_retired_at`＋`kek_retired_by`（replacement KEK 指紋）＋`kek_retired_reason=switched`。

**材料保留至顯式清理**：退役（含放棄重包的 `reason=abandoned`）**不清空** `wrapped_key`，使最後手段回退在資料層始終可行；材料銷毀的唯一發生點是管理員顯式呼叫 `DELETE /api/v1/keys/retired-material`（全收斂閘＋逐 slot 自證＋退役 DEK 版本引用掃描三道閘）。清理後該列成「已清理佔位」（`wrapped_key=''`、`status=retired`），列本身與 kek_id 指紋、退役軌跡永久保留，使版本鏈不斷號、載入時跳過解包。金鑰明文不落庫。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Purpose` | string | `type:varchar(32);not null;uniqueIndex(1)` | `purpose` | 用途：`data`（資產憑證/通知 secret 等落庫資料）、`audit_integrity`（審計 HMAC 蓋章鑰） |
| `Version` | int | `not null;uniqueIndex(2)` | `version` | 版本；audit_integrity 的 0 為 legacy 派生鑰快照 |
| `WrappedKey` | string | `type:text;not null` | `-` | KEK 包裹後金鑰材料（base64），不經 API 回傳 |
| `KEKID` | string | `type:varchar(32);not null;uniqueIndex(3)` | `kek_id` | 包裹所用 KEK 指紋（SHA-256 前 8 bytes hex）；開機一致性檢查與重包識別 |
| `Status` | string | `type:varchar(16);not null` | `status` | `active` / `retired` |
| `CreatedAt` | time.Time | - | `created_at` | 生成時間 |
| `RetiredAt` | *time.Time | - | `retired_at` | DEK 退役時間（nullable；與 KEK 切換正交，屬 DEK Status 維度） |
| `KEKPending` | bool | `not null;default:false` | `kek_pending` | KEK 待切換 pending 標記：RewrapKEK 以新 KEK 重包的過渡列；切換完成（現行 KEK 指向此 clone）後轉 false 成為現行。與 DEK Status 正交 |
| `KEKRetiredAt` | *time.Time | `index` | `kek_retired_at` | KEK 軟退役時間（nullable，index）：非 NULL 表此列 KEK 已退役、不參與現行金鑰解析；**材料保留至顯式清理**，清理後 `wrapped_key` 才為空 |
| `KEKRetiredBy` | string | `type:varchar(32);not null;default:''` | `kek_retired_by` | 退役時記錄的 replacement KEK 指紋（切換到的新 KEK）；供 KEK 退役史正確呈現 from→to（多次 A→B→C 切換不誤配） |
| `KEKRetiredReason` | string | `type:varchar(16);not null;default:''` | `kek_retired_reason` | 退役原因：`switched`＝切換收尾退役（曾在役，有 replacement）／`abandoned`＝放棄重包退役（從未在役，`kek_retired_by` 為空）。載入時的定向錯誤指引依此分流 |

**合法欄位形狀五種**（載入開頭驗證，非法形狀 fail-close）：
1. **live**：`kek_pending=false`、`kek_retired_at=NULL`、`kek_retired_by=''`、有 `wrapped_key`
2. **pending**：`kek_pending=true`、`kek_retired_at=NULL`、`kek_retired_by=''`、有 `wrapped_key`
3. **retired-switched**：`kek_pending=false`、`kek_retired_at!=NULL`、`kek_retired_by!=''`、`reason=switched`；`wrapped_key` 保留或已清理皆合法
4. **retired-abandoned**：`kek_pending=false`、`kek_retired_at!=NULL`、`kek_retired_by=''`（無 replacement）、`reason=abandoned`；材料同上
5. **purged-placeholder**：顯式清理後的退役 DEK 版本現行列——`wrapped_key=''` 且 `status=retired`，載入時跳過解包、版本鏈不斷號

**唯一索引**：`idx_data_keys_purpose_version_kek (purpose, version, kek_id) WHERE kek_retired_at IS NULL`——partial：退役列自軟刪除後永久保留指紋史，不得佔用活動唯一鍵。

---

### 27. TransmissionConsent（傳輸風險同意記錄）

**表名**: `transmission_consents`
**檔案**: `backend/internal/model/transmission_consent.go`
**建表方式**: baseline（`baseline_schema_audit.go`）

per user×asset 一列（唯一索引冪等更新）。不存 `expires_at`——效期以 `consented_at`＋政策 `transport_consent_ttl_days`
讀時動態判定（政策改動立即全域生效）；失效另靠 `risk_fingerprint` 比對（資產傳輸屬性變更即不符，同意自然作廢）。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `UserID` | uint | `not null;uniqueIndex(user_asset)` | `user_id` | 同意者 |
| `AssetID` | uint | `not null;uniqueIndex(user_asset);index` | `asset_id` | 資產 |
| `RiskFingerprint` | string | `size:64;not null` | `risk_fingerprint` | 同意當下風險項集合的確定性雜湊（sha256 hex，僅雜湊 key） |
| `RiskItems` | string | `type:text;not null` | `risk_items` | 同意當下的風險項清單（JSON，含 key＋label） |
| `ConsentedAt` | time.Time | `not null` | `consented_at` | 最近一次同意時間（重複同意冪等刷新） |

---

### 28. SchemaMigration（migration 版本追蹤）

**表名**: `schema_migrations`
**檔案**: `backend/internal/database/migrations.go`
**建表方式**: **不由 baseline 建立**——`RunMigrations` 的 bootstrap DDL
（`migrations.go` 的 `schemaMigrationsBootstrapDDL`），也是產品程式碼中唯一的 `CREATE TABLE IF NOT EXISTS`。
雞生蛋：baseline 該不該執行正是靠讀本表判定，故它必須先於 baseline 存在。**全庫唯一的例外，其餘 46 張表一律走 baseline**

| 欄位 | 類型 | GORM Tags | 說明 |
|------|------|-----------|------|
| `Version` | string | `primaryKey;size:50` | migration 版本字串 |
| `AppliedAt` | time.Time | `not null` | 執行時間 |

---

### 29. UserGroup（使用者群組）

**表名**: `user_groups`（成員關聯表 `user_group_members` 由 baseline 顯式建表，見 `backend/internal/database/baseline_schema_identity.go`；程式碼中零 `AutoMigrate`——改 model 不會自動建表或加欄）
**檔案**: `backend/internal/model/user_group.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `idx_user_groups_name` 唯一索引
（**非** partial：本表雖有 `deleted_at`，軟刪除的群組名仍佔用該名稱）；
成員關聯表 `user_group_members` 另見 29b

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Name` | string | `uniqueIndex;not null;size:100` | `name` | 群組名稱（唯一） |
| `Description` | string | `size:500` | `description` | 描述 |

**關聯**:
- `Users []User` - 多對多（透過 `user_group_members` 表，一人可屬多群）

**語義**：授權主體的分組維度，與 RBAC 的 Role 正交——Role 管職能（端點權限）、UserGroup 管授權分組（資產可及範圍），不可混用。刪除群組時 service 層於同一交易內軟刪成員關係＋掛該群組的全部授權記錄，審計日誌記連動撤銷筆數（`resource=user_group`）。

---

### 29b. user_group_members（用戶×群組關聯表）

**表名**: `user_group_members`
**檔案**: **無 model 檔**——僅由 `model.User.Groups` 與 `model.UserGroup.Users` 的
`gorm:"many2many:user_group_members;"` tag 隱含（`user.go:113`、`user_group.go:22`）
**建表方式**: baseline（`baseline_schema_identity.go`），複合主鍵 `(user_group_id, user_id)`，
兩條外鍵 `fk_user_group_members_user`→`users(id)`、`fk_user_group_members_user_group`→`user_groups(id)`；無其他索引
**維護陷阱（沒有守衛會提醒你）**: 同 [2b](#2b-user_roles用戶角色關聯表)——本表無 model 結構，
**不在 `schemaParityModels` 的射程內**，兩層 parity 守衛都不檢查它；改 model 不會動到它，也不會有測試變紅。
要改形狀只能直接改 `baseline_schema_identity.go`。

| 欄位（baseline） | 類型 | 說明 |
|------------------|------|------|
| `user_group_id` | bigint NOT NULL | 群組；複合主鍵之一 |
| `user_id` | bigint NOT NULL | 使用者；複合主鍵之一 |

無 `created_at`／`deleted_at`：關聯為硬刪——刪群組與刪使用者皆以
`DELETE FROM user_group_members`（`modules/identity/user_group_service.go:125`、`user_service.go:557`）
在同一交易內清成員列。

---

### 30. AccessRequest（連線申請單）

**表名**: `access_requests`
**檔案**: `backend/internal/model/access_request.go`
**建表方式**: baseline（`baseline_schema_authz.go`），含 `idx_access_request_pending_dedup` partial unique
（謂詞含 status 條件，GORM tag 表達不了，故只能由顯式 DDL 承載）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primaryKey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `RequesterID` | uint | `not null;index` | `requester_id` | 申請人 |
| `AssetID` | uint | `not null;index` | `asset_id` | 申請資產（單資產申請） |
| `Reason` | string | `varchar(1000);not null` | `reason` | 連線事由（必填） |
| `RequestedDurationMinutes` | int | `not null` | `requested_duration_minutes` | 申請時長（≤政策上限，service 層驗證） |
| `RequestedDateStart` | *time.Time | - | `requested_date_start,omitempty` | 預約起始（空＝立即） |
| `Accounts` | AccountScope（`[]string`） | `type:text`（DB 端 NOT NULL DEFAULT `["@ALL"]`） | `accounts,omitempty` | 申請的帳號範圍：核准時原樣傳遞給 ticket 授權列；核准人**不得上調**（同既有「時長/起始只可下修」語義，上調等於授出未經申請的帳號）。 |
| `Status` | AccessRequestStatus | `varchar(20);not null;index` | `status` | 狀態機（見下） |
| `ApproverID` | *uint | - | `approver_id,omitempty` | 核准人（自動核准為 NULL＋auto_approved 標記） |
| `DecidedAt` | *time.Time | - | `decided_at,omitempty` | 裁決時間 |
| `DecisionNote` | string | `varchar(1000)` | `decision_note,omitempty` | 裁決備註（拒絕必填） |
| `ApprovedDurationMinutes` | *int | - | `approved_duration_minutes,omitempty` | 核定時長（僅可下修） |
| `ApprovedDateStart` | *time.Time | - | `approved_date_start,omitempty` | 核定起始（僅可推遲） |
| `AutoApproved` | bool | - | `auto_approved` | reason 段自動核准標記（決定者記 system） |
| `AuthorizationID` | *uint | - | `authorization_id,omitempty` | 核准後回填的臨時授權 FK（授權與申請單各自獨立主鍵，不共用 id） |
| `PendingExpiresAt` | time.Time | `not null;index` | `pending_expires_at` | 待審超時時限（建單時以政策鍵計算；scheduler＋讀取惰性過濾雙保險） |
| `Kind` | string | `type:varchar(20)` | `kind` | 單類別 `normal`／`break_glass`（BeforeCreate 空值兜底為 `normal`） |
| `ReviewStatus` | string | `type:varchar(20);index` | `review_status,omitempty` | 破窗補審狀態（空＝非破窗單；`pending_review`→`reviewed`，CAS 防重複補審） |
| `ReviewedBy` | *uint | - | `reviewed_by,omitempty` | 補審人 |
| `ReviewedAt` | *time.Time | - | `reviewed_at,omitempty` | 補審時間 |
| `ReviewDisposition` | string | `type:varchar(20)` | `review_disposition,omitempty` | 補審處置 `confirmed`／`violation`（沿 command_alerts 詞彙） |
| `ReviewNote` | string | `type:varchar(1000)` | `review_note,omitempty` | 補審備註 |
| `ReviewOverdueNotifiedAt` | *time.Time | - | `-` | 逾期升級告警的最近發送時刻（nil＝從未告警）。**記時間戳而非布林**：布林＝每單至多一次，告警響一次後永久靜默，無法承擔「零有效審核者」情境下破窗單的可見性保底（一封通知被漏看，該單即永久沉沒）；記時間戳後由固定 24h 間隔節流**週期重發**，直到有人補審 |
| `RevokedAt` | *time.Time | - | `revoked_at,omitempty` | 提前撤銷時間（附註非狀態轉移，approved 終態不變） |
| `RevokedBy` | *uint | - | `revoked_by,omitempty` | 撤銷人 |
| `RevokeNote` | string | `type:varchar(1000)` | `revoke_note,omitempty` | 撤銷事由 |

**狀態機常數**（全轉移 CAS `WHERE status='pending'`，終態不可復活；核准 CAS 另帶 `pending_expires_at > now` 守衛）:
`pending` / `approved` / `rejected` / `cancelled` / `expired`。提前撤銷 SHALL NOT 新增終態——票證軟刪＋單附註 `revoked_*`（保 CAS 不變式）。

**索引**: pending 去重 partial 唯一索引 `(requester_id, asset_id) WHERE status='pending' AND deleted_at IS NULL AND kind='normal'`（原生 SQL；謂詞含 `kind='normal'` 讓破窗單交易內短暫 pending 不撞一般在途單，20260719 加）；破窗待補審 partial 索引 `(review_status) WHERE review_status='pending_review' AND deleted_at IS NULL`。

**關聯**: `Requester User` / `Asset *Asset` / `Approver *User` / `Authorization *AssetAuthorization`

---

### 31. ApproverScope（審核範圍）

**表名**: `approver_scopes`
**檔案**: `backend/internal/model/approver_scope.go`
**建表方式**: baseline（`baseline_schema_authz.go`）。兩條 inline CHECK 為本表的核心不變式——
`chk_approver_scope_target`（範圍客體四維恰一）與 `chk_approver_scope_actor`（審核方恰一）；
另有八條 partial 唯一索引（審核方 user／group 兩側 × 四個維度）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primaryKey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除（移除範圍＝軟刪） |
| `ApproverID` | *uint | `uniqueIndex:idx_approver_scope_*（partial）` | `approver_id,omitempty` | 審核方個人（與群組恰一；須具 approver 角色，service 層驗證） |
| `ApproverGroupID` | *uint | `uniqueIndex:idx_approver_scope_g_*（partial）` | `approver_group_id,omitempty` | 審核方群組（群組即資格：成員自動具審核資格） |
| `AssetID` | *uint | `uniqueIndex:idx_approver_scope_asset` | `asset_id,omitempty` | 客體資產（四維恰一） |
| `AssetGroupID` | *uint | `uniqueIndex:idx_approver_scope_agroup` | `asset_group_id,omitempty` | 客體節點（含子樹，四維恰一） |
| `SubjectUserID` | *uint | `uniqueIndex:idx_approver_scope_suser` | `subject_user_id,omitempty` | 申請人側：使用者（四維恰一） |
| `SubjectGroupID` | *uint | `uniqueIndex:idx_approver_scope_sgroup` | `subject_group_id,omitempty` | 申請人側：使用者群組（四維恰一，成員異動即時反映） |
| `GrantedBy` | uint | `not null` | `granted_by` | 分配者（admin only，入審計） |

**語義**：條目＝審核方（個人 XOR 群組）×客體（四維恰一）。資產側與授權客體同構（範圍命中＝直配資產
OR 經節點含子樹）；申請人側＝申請人本人 OR 所屬群組（OR 資格擴充，非收斂路由）。裁決資格＝〔資產側 OR
申請人側命中〕且操作者為審核方（本人或群組成員）OR admin；審核資格閘＝具 approver 角色 OR 屬任一審核方
群組（即時查）。資產側隱含範圍內資產 `view` 可視（個人與群組成員同語義）；申請人側不隱含任何資產可視。
不隱含連線權、不進複審矩陣。八條 partial 唯一索引（`WHERE deleted_at IS NULL`，個人側/群組側各四）
防同審核方×同客體重複配置。
範圍命中 SQL 集中於 `repository/asset_authorization_repository.go` 家族區（單筆祖先方向／列表後代方向，
等價性測試釘住），禁止另寫等價 SQL。

---

### 32. AccessRequestApproval（申請單核准記錄）

**表名**: `access_request_approvals`
**檔案**: `backend/internal/model/access_request_approval.go`
**建表方式**: baseline（`baseline_schema_authz.go`），`(request_id, approver_id)` 唯一

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primaryKey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 投票時間 |
| `RequestID` | uint | `not null;uniqueIndex:idx_request_approval_once;index` | `request_id` | 申請單 |
| `ApproverID` | uint | `not null;uniqueIndex:idx_request_approval_once` | `approver_id` | 核准人（同單同人唯一——重複核准由索引硬擋，含 admin） |
| `Note` | string | `type:varchar(1000)` | `note,omitempty` | 核准附註 |

**語義**：quorum 逐票資料軌（`access_request_min_approvals` 政策）。核准數達門檻的那一票才觸發申請單
CAS 轉 approved（`AccessRequest.ApproverID`＝補齊門檻的最終核准人）；記錄不可變（無軟刪無更新），
拒絕/撤回/逾時終態下已存在的票留存供審計。

---

### 33. OIDCProvider（OIDC 身分提供者設定）

**表名**: `oidc_providers`
**檔案**: `backend/internal/model/oidc_provider.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `idx_oidc_providers_identity_domain`
＝`(issuer, client_id) WHERE deleted_at IS NULL`（partial 為必要——身分域建後不可變，但軟刪後須允許同 tuple 重建）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` / `UpdatedAt` | time.Time | - | `created_at` / `updated_at` | 時間戳 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Name` | string | `size:100;not null` | `name` | 管理端與登入頁顯示名（使用者看到的按鈕文字） |
| `Issuer` | string | `size:500;not null` | `issuer` | OIDC 簽發者 URL；endpoint 由執行期 discovery 解析，**不落庫** |
| `ClientID` | string | `size:255;not null` | `client_id` | 用戶端識別；與 `Issuer` 同為身分域組成，**建後不可變**（服務層強制） |
| `ClientSecretEnc` | string | `type:text` | `-` | 用戶端密鑰（信封加密）。**write-only**：任何讀取回應皆不含此欄 |
| `Scopes` | string | `size:255;not null;default:'openid profile email'` | `scopes` | 授權請求 scope（空白分隔）；服務層強制注入 `openid`，附加項限允許清單，未知 scope 於設定時即拒絕 |
| `AdmissionMode` | AdmissionMode | `size:32;not null;default:'prebound_only'` | `admission_mode` | 准入模式（見下）；出廠 `prebound_only`（不自動供應，fail-close） |
| `AdmissionRules` | string | `type:text` | `admission_rules` | 准入規則集（JSON）。規則鍵封閉、未知鍵於 CRUD 即拒絕；跨規則 AND、清單內 OR；claim 缺失／型別不符一律不匹配 |
| `ForceShared` | *bool | `column:force_shared` | `force_shared,omitempty` | 管理者的收緊意圖（三值：nil＝未表態、true＝強制視為共用身分域）。**刻意用 `*bool` 且不加 `default` tag**——帶 default tag 的 bool 欄位顯式寫 false 會被 DB default 覆寫，三值語義必須用指標表達 |
| `AuthEpoch` | int | `not null;default:0` | `auth_epoch` | **provider 級**憑證世代（單調遞增）。停用與 secret 輪替時推進，**重新啟用不回退**（使「停用後短時間重新啟用」不會復活攻擊者手上的既簽憑證） |
| `Enabled` | bool | `not null;default:false` | `enabled` | 啟用狀態；停用即觸發全面失效流程（推進世代 → 撤 refresh → 拒既簽 access → 終斷協議連線與唯讀訂閱） |

**准入模式常數**:
```go
type AdmissionMode string
const (
    AdmissionPreboundOnly AdmissionMode = "prebound_only"  // 僅允許已綁定外部身分者登入；不自動供應（出廠預設）
    AdmissionJITWithRules AdmissionMode = "jit_with_rules" // 允許自動供應，但每次認證都須通過 admission_rules
)
```

**索引**:
- `idx_oidc_providers_identity_domain`：`(issuer, client_id) WHERE deleted_at IS NULL`。
  partial 是必要的——身分域欄位建後不可變，但 provider 軟刪後應允許以同一 tuple 重建，全表唯一會使該路徑不可達。

**設計說明**:
- **身分域不可變**：外部身分以 `(issuer, client_id, subject)` 為鍵，變更任一即等同換身分域。
  Entra 的 `sub` 為 per-application pairwise（官方明載），換 `client_id` 後同一人會拿到不同 subject，
  故此約束是硬需求而非潔癖。
- **生命週期為原地治理**：secret 輪替、停用／重新啟用、改顯示名皆原地更新；有外部身分關聯者不可刪除（服務層回 409），僅能停用。
- **effective issuer kind 不持久化**，每次以固定優先序現算：
  內建共用清單 > `force_shared` > 部署層 `OIDC_DEDICATED_ISSUERS` > 未知（一律視為共用，fail-close）。
- **安全紅線**：`client_secret_enc` 必須登記於 `service.envelopeMigrationTargets`——
  該清單同時驅動 DEK 輪替重加密與退役金鑰銷毀前的引用掃描，漏登會使銷毀前掃描看不見本表密文而誤判零引用
  （AST 守衛 `envelope_targets_guard_test.go` 強制）。
- **授權關鍵欄位一律現查 DB**（`enabled`／`auth_epoch`／`admission_*`／issuer kind），
  不得讀程序快取——可快取者僅限 discovery/JWKS/verifier。

---

### 34. UserExternalIdentity（使用者外部身分關聯）

**表名**: `user_external_identities`
**檔案**: `backend/internal/model/user_external_identity.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `idx_user_external_identities_domain`
＝`(issuer, client_id, subject) WHERE deleted_at IS NULL`（鍵非 `provider_id`——provider 列的生命週期不應決定使用者能否登入）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` / `UpdatedAt` | time.Time | - | `created_at` / `updated_at` | 時間戳 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `UserID` | uint | `not null;index` | `user_id` | 所屬使用者 |
| `ProviderID` | uint | `index` | `provider_id` | **當前設定載體，非身分域鍵**；provider 軟刪後以同 tuple 重建時，身分仍可經三元組查回，此欄於下次登入修正指向 |
| `Issuer` | string | `size:500;not null` | `issuer` | 身分域三元組之一 |
| `ClientID` | string | `size:255;not null` | `client_id` | 身分域三元組之一 |
| `Subject` | string | `size:255;not null` | `subject` | IdP 的 `sub`。非空、長度上限、**原值大小寫敏感比對、不做任何正規化**——空 subject 會使第一個異常 token 吸附該 provider 後續全部異常 token |
| `ClaimUsername` | string | `size:255` | `claim_username` | IdP 自報 `preferred_username` 的**快照**（回訪更新） |
| `ClaimEmail` | string | `size:255` | `claim_email` | IdP 自報 email 的快照；**僅保存已驗證的 email**，未驗證則留空 |
| `LastLoginAt` | *time.Time | - | `last_login_at,omitempty` | 最近一次經此身分登入的時間 |

**索引**:
- `idx_user_external_identities_domain`：`(issuer, client_id, subject) WHERE deleted_at IS NULL`。

**設計說明**:
- **身分域鍵為 `(issuer, client_id, subject)` 而非 `provider_id`**——身分歸屬於「issuer＋client_id」這個外部事實，
  不是我方 provider 列的識別碼。以代理鍵當身分域會使 admin 誤刪重建 provider 後全體使用者被鎖出
  （新 `provider_id` 使既有身分全數未命中，繼而撞名被拒）。登入查找一律以三元組為準。
- **claim 快照與 `users` 本體刻意分離**：本體是授權主體識別（授權綁定、審計歸屬皆依它），回訪不得改寫；
  快照則是 IdP 現況的觀測值。快照內容**完全由外部控制**（低權使用者可把自己的 `preferred_username` 設為 `admin`），
  故 UI 顯示時必須標示為「身分提供者自報值」並與本地使用者名稱分欄，不得混排。

---

### 35. OIDCFlowState（登入流程狀態）

**表名**: `oidc_flow_states`
**檔案**: `backend/internal/model/oidc_flow.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `expires_at` 索引（清理排程與容量上限判定依賴之）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `State` | string | `primarykey;size:64` | `-` | 隨機值，同時為主鍵 |
| `Nonce` | string | `size:64;not null` | `-` | id_token 的 nonce 比對值 |
| `PKCEVerifier` | string | `size:128;not null` | `-` | PKCE code_verifier |
| `ProviderID` | uint | `not null;index` | `provider_id` | 發起的 provider |
| `AuthEpoch` | int | `not null;default:0` | `-` | 簽發當下的 provider 世代；callback 比對現行值，涵蓋「begin 之後、callback 之前 provider 被停用（並可能已重新啟用）」的窗口 |
| `BindingHash` | string | `size:64;not null` | `-` | 發起端瀏覽器 secret 的 SHA-256 |
| `RedirectNext` | string | `size:255` | `-` | 登入後導向目標；限同源相對路徑且須符合既有路由白名單，於 begin 時即驗證 |
| `ExpiresAt` | time.Time | `not null;index` | `-` | 到期時間 |
| `CreatedAt` | time.Time | - | `-` | 建立時間 |

**設計說明**:
- 本系統無 server-side session（純 JWT），故 state/nonce/PKCE verifier 落庫。
- **一次性消費**：callback 以 state 查表並於單一原子操作中「僅在未過期時取用並失效」——
  過期記錄即使清理排程尚未執行亦須拒絕（排程延遲不得擴大有效窗口）。
- **`BindingHash` 是瀏覽器綁定**：DB 保存 state 只證明「伺服器簽發且未用過」，不證明 callback 發生在發起的瀏覽器。
  攻擊者可自行發起流程、以自己的 IdP 帳號完成授權但攔住 callback，再把該 URL 交給受害者——
  state/nonce/PKCE 全部有效，受害者會被登入攻擊者帳號（login CSRF），其後操作與審計全歸屬錯誤。
  故發起端產生 secret 存 sessionStorage，begin 只送其雜湊，兌換時須提出原文。
- **刻意不帶使用者憑證世代**：begin 階段尚未認證、不知使用者是誰；使用者世代自 callback 簽發的 login ticket 起才進入憑證鏈。
- 全表容量上限與 per-IP 限流：防未認證洪水佔滿（本地登入路徑不受影響，為刻意取捨）。

---

### 36. OIDCLoginTicket（callback → SPA 交棒憑證）

**表名**: `oidc_login_tickets`
**檔案**: `backend/internal/model/oidc_flow.go`
**建表方式**: baseline（`baseline_schema_identity.go`），含 `expires_at` 索引（清理排程與容量上限判定依賴之）

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `TokenHash` | string | `primarykey;size:64` | `-` | 交棒憑證的 SHA-256，同時為主鍵（**明文不落庫、不進日誌**） |
| `UserID` | uint | `not null;index` | `-` | 已完成身分對應的使用者 |
| `ProviderID` | uint | `not null;index` | `-` | 認證來源 provider |
| `AuthEpoch` | int | `not null;default:0` | `-` | 簽發當下的 provider 世代 |
| `CredEpoch` | int | `not null;default:0` | `-` | 簽發當下的使用者世代；與 `AuthEpoch` 兌換時**並列比對**，兩者缺一即留下該類憑證的復活窗口 |
| `AuthMethod` | string | `size:32;not null` | `-` | 本次認證方式，隨會話全鏈傳遞（決定密碼類 gate 是否適用、審計標註） |
| `FlowBindingHash` | string | `size:64;not null` | `-` | 自 flow state 承接的瀏覽器綁定雜湊 |
| `RedirectNext` | string | `size:255` | `-` | 已驗證的登入後導向目標；兌換成功後回傳給 SPA，**不得於兌換階段重新採信前端提交值** |
| `BindingFailures` | int | `not null;default:0` | `-` | 綁定不符的累計次數；以單一條件式 UPDATE 原子遞增，達三次即作廢，與成功兌換互斥 |
| `ExpiresAt` | time.Time | `not null;index` | `-` | 到期時間 |
| `CreatedAt` | time.Time | - | `-` | 建立時間 |

**設計說明**:
- callback 是瀏覽器對後端的 GET，無法直接回傳 JSON 形式的登入回應；而把 token 放進 URL query
  會落入瀏覽器歷史與反向代理日誌。故 callback 完成全部驗證後產生本憑證，以 **URL fragment** 交給 SPA
  （fragment 不送伺服器），SPA 讀取後立即以 `history.replaceState` 抹除，再經 exchange 端點
  換取與一般登入完全同形的回應（含 MFA 分支）。
- **綁定不符時不消耗但累計失敗次數**，達三次作廢——「消耗」與「請回到原分頁重試」互斥
  （ticket 已被落錯的分頁消耗掉就救不回來）。

---

### 36b. LDAPDirectory（LDAP 目錄設定）

**表名**: `ldap_directories`
**檔案**: `backend/internal/model/ldap_directory.go`
**建表方式**: baseline（`baseline_schema_identity.go`）。單列不變式由**兩者並用**承載：
inline `CONSTRAINT ldap_directories_singleton_check CHECK (singleton = 1)` 鎖死值域，
＋ `idx_ldap_directories_singleton`＝`UNIQUE (singleton) WHERE deleted_at IS NULL`（partial，軟刪列不佔位、刪除後可重建）。
**CHECK 不可省**：單靠唯一索引只禁止相同值重複，`singleton=1` 與 `singleton=2` 仍可並存。
兩者皆為具名斷言——索引釘在 `baseline_parity_pg_test.go` 的 `baselineStructuralAssertions`（`pg_get_indexdef` 逐字比對），
CHECK 釘在同檔的 `baselineCheckConstraints`

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |
| `DeletedAt` | gorm.DeletedAt | `index` | `-` | 軟刪除 |
| `Singleton` | int | `not null;default:1` | `-` | 單列守衛欄；恆為 1，由 CHECK 與 partial unique index 保證。不對外暴露——它是 schema 層的不變式載體，非業務欄位 |
| `Name` | string | `size:100;not null;default:''` | `name` | 管理端顯示名 |
| `URL` | string | `size:500;not null;default:''` | `url` | 目錄伺服器位址；僅接受 origin 形狀 `ldap[s]://host[:port]` |
| `BindDN` | string | `size:500;not null;default:''` | `bind_dn` | service bind 帳號 DN |
| `BindPasswordEnc` | string | `type:text;not null;default:''` | `-` | service bind 密碼（信封加密）。**write-only**：讀取回應改回 `has_bind_password` 布林旗標 |
| `BaseDN` | string | `size:500;not null;default:''` | `base_dn` | 使用者搜尋起點 |
| `UserFilter` | string | `size:500;not null;default:''` | `user_filter` | 使用者搜尋 filter；`%s` 佔位恰一次且不得位於 OR／NOT 之下 |
| `AttrEmail` | string | `size:100;not null;default:''` | `attr_email` | 電子郵件屬性名 |
| `AttrFullName` | string | `column:attr_fullname;size:100;not null;default:''` | `attr_fullname` | 顯示名屬性名。**DB 欄名刻意為 `attr_fullname`**（與 env 鍵 `LDAP_ATTR_FULLNAME` 同形），非 GORM 預設的 `attr_full_name` |
| `SkipTLSVerify` | bool | `not null;default:false` | `skip_tls_verify` | 跳過 TLS 憑證驗證；傳輸安全框架視為一級風險項（`RiskLDAPSkipVerify`） |
| `Enabled` | bool | `not null;default:false` | `enabled` | 啟用狀態；停用即等同「LDAP 未設定」語義（登入路徑不撥號） |

**設計說明**:
- **帶 id 的資料列而非單列固定表**：未來多目錄只需解除單列限制＋補身分歸屬，不需 schema 重做。
- **安全紅線**: `bind_password_enc` 須登記於 `envelopeMigrationTargets` 與 `cipher_refs.go`
  （AST 守衛 `envelope_targets_guard_test.go` 強制）。
- env→DB 的一次性 seed 需要 codec（段 2 才存在），故走 post-unseal 佇列；
  其執行期冪等標記 `20260804_ldap_env_seeded` 借用 `schema_migrations` 表存放，
  由 `runtimeMarkerVersions` 自 fail-close 判定中扣除（`migrations.go:66`）。

---

## Migration 版本一覽

**現行 migration 有四條**（`backend/internal/database/migrations.go` 的 `migrations` 陣列，依序執行）：

| 版本 | 內容 | Down |
|---|---|---|
| `20260816_schema_baseline` | 建立整個 schema（46 張表、26 條外鍵、116 條索引，共 188 條無條件 DDL）＋種入 12 條內建告警規則。呼叫端把它與 `schema_migrations` 的版本記錄包在單一交易內，PostgreSQL 的 DDL 可交易，故全成或全不成，不會留下半套 schema | **一律回拒絕錯誤**（`refuseBaselineRollback`）。baseline 建的是整個 schema，「回滾」它等於刪掉全部使用者、資產、授權與審計證據——一個看起來像回滾入口、實際是資料庫毀滅按鈕的東西比沒有入口更危險。退路是還原備份 |
| `20260824_audit_export_jobs` | 建 `audit_export_jobs` 表（1 建表 ＋ 3 索引，含 1 條部分唯一索引；見第 42 節）。**baseline 之後的首條增量 migration**——純新表、無加密欄、無回填，在全新庫（baseline → 本條）與既有庫（僅本條）上收斂同形。DDL 沿 baseline 紀律：無條件、無 `IF NOT EXISTS` | `DROP TABLE audit_export_jobs`（`rollbackAuditExportJobs`）。純狀態表，證據不在其中，可棄可逆 |
| `20260825_evidence_offsite` | 離機儲存：建 `offsite_profiles` 設定世代表（含信封加密憑證欄與兩條具名 CHECK；見第 44 節）與 `offsite_objects` 保管帳冊（見第 45 節），建 5 條索引，並對 `sessions` 與 `audit_export_jobs` 各加 `offsite_object_id`／`offsite_status` 兩欄、對 `sessions` 建 2 條部分索引。**兩張表同一條 migration**：帳冊的 `storage_generation_id` 是指向世代表的邏輯外鍵，分兩條會產生「帳冊已存在而世代表尚未存在」的中間形狀，該形狀下的世代連續性健檢無法判讀。**加密欄無資料回填**——`credentials_enc` 由管理介面寫入，或由 post-unseal 佇列的 env seed 寫入（見下），故 migration 本身不需要 codec。DDL 沿 baseline 紀律：無條件、無 `IF NOT EXISTS` | `rollbackEvidenceOffsite`：反序 DROP 兩條 `sessions` 索引 → 四個加欄 → `DROP TABLE offsite_objects` → `DROP TABLE offsite_profiles`。**回退是資料追蹤不可逆**：drop 帳冊即失去「哪個錄影的遠端副本在哪個 bucket、哪個 key、上傳當下的 SHA-256 是多少」，drop 世代表更失去「哪個物件要用哪組憑證取回」的對應；**遠端物件不隨回退消失**（產品從不刪遠端），故回退後那些物件成為孤兒。回退前須 `pg_dump --data-only -t offsite_objects` 匯出清冊與備份集同保管，重新升級時先還原清冊即零重傳（程序見 `docs/ops/upgrade-sop.md` §4） |
| `20260826_source_ip_forensics` | 來源位址追查：`ALTER TABLE users ADD COLUMN allowed_cidrs text NOT NULL DEFAULT ''`、建 `user_source_ips` 表（見第 43 節）、建 `idx_sessions_client_ip_start` 與 `idx_user_source_ips_ip_seen` 兩索引、重建 `command_alerts_kind_check` 使 `kind` 值域含 `new_source_ip`，最後**冷啟動回填**（自 `sessions` 全史與 `audit_logs` 登入成功列合併，使部署當下已見的位址不觸發告警）。**Up 為純加法**：不刪不改任何既有資料列 | `rollbackSourceIPForensics`：反序 DROP 兩索引 → `DELETE FROM command_alerts WHERE kind = 'new_source_ip'` → 還原舊 CHECK → `DROP TABLE user_source_ips` → `DROP COLUMN allowed_cidrs`。**銷毀資料、開發庫限定**：丟掉整份已見位址基準與每位使用者的來源限定，再次 Up 後清單為空（來源限制靜默消失）、基準為空（全部位址重新判為新）。**生產回退＝部署回舊版映像並還原升級前備份**（見 `docs/ops/upgrade-sop.md` §4） |

執行序仍由 `migrations` 陣列的順序決定；日後新增增量 migration 時照舊。

> **升級注意**：`20260824_audit_export_jobs`、`20260825_evidence_offsite` 與 `20260826_source_ip_forensics`
> 於既有部署升級時自動套用（段 1，無 codec 依賴；最後一條含冷啟動回填，其耗時隨 `sessions` 與 `audit_logs` 的存量成長，
> 升級程序見 `docs/ops/upgrade-sop.md`）；離機儲存**設定面**的 env→DB seed 需要 codec，另走 post-unseal 佇列（見下）；
> 剪貼簿 `content`→`content_enc` 轉換則走 **post-unseal 佇列**（段 2，需 codec，見下）。

**post-unseal 資料 migration**：需要 codec（信封加解密）的資料遷移不得在段 1 執行，
改登記於 post-unseal 佇列、由段 2 於 `InitKeyManager` 成功後執行。此類含兩項：
剪貼簿 `content`→`content_enc` 的加密回填（加欄→逐筆加密→刪 `content`，以「`content` 欄是否存在」判冪等，
整段單一交易、回填失敗即 rollback 不刪欄；見第 12 節），以及
LDAP 的 env→DB seed（標記 `20260804_ldap_env_seeded`）——後者標記語義為
**「已完成評估」而非「已建立資料」**——實際 seed、env 未啟用、資料表非空三種終局皆寫入標記，
僅基礎設施失敗不寫（留待下次啟動重試）。此語義使「資料列被硬刪後 env 仍為啟用」
不會靜默重建一個外部認證來源。

---

## 輔助結構

### AssetChange / AssetChangeDetails

用於記錄資產變更詳情（寫入 audit_logs.details）：

```go
type AssetChange struct {
    Field string      `json:"field"` // 變更欄位
    Old   interface{} `json:"old"`   // 舊值
    New   interface{} `json:"new"`   // 新值
}

type AssetChangeDetails struct {
    Changes []AssetChange `json:"changes"`
}
```

### AccountScope（帳號範圍）

`asset_authorizations.accounts` 與 `access_requests.accounts` 的欄位型別
（`backend/internal/model/asset_authorization.go`）：

```go
type AccountScope []string
const AccountScopeAll = "@ALL" // 全部帳號（別名，`@` 前綴為保留命名空間）
```

- **DB 序列化**（`Value()`）：一律 JSON 字串陣列；**nil／空一律寫成 `["@ALL"]`**
  ——庫內不存在語義待解讀的 NULL（稽核直讀該欄即可區分「全帳號」與具名範圍）。
- **讀取**（`Scan()`）：容忍 NULL／空字串／`"null"`（→ 視為 `@ALL`，回歸安全方向）；
  **非法 JSON 一律報錯**，不默默視為 `@ALL`。
- **正規化**（`NormalizeAccountScope`）：TrimSpace、去空項、去重、排序；
  含 `@ALL` 即塌縮為 `["@ALL"]`。上限 200 項、單項 ≤100 字元。
- 判定：`IsAll()`（len==0 亦為真）、`Contains(username)`（`@ALL` 恆真）。

---

## 安全特性

1. **密碼儲存**: 使用 bcrypt 雜湊
2. **憑證加密**: 使用 AES-256-GCM 加密資產密碼、SSH 私鑰與 TOTP secret（共用同一把金鑰）
3. **軟刪除**: 核心模型（users/roles/assets/asset_groups/sessions/asset_authorizations）支援軟刪除，保留審計軌跡；audit_logs 另有 ORM 層 `BeforeUpdate`/`BeforeDelete` 雙守衛（含 Unscoped 硬刪），唯一刪除路徑為保留政策的原生 SQL 清除（清除入審計）；審計附屬表（session_commands、command_alerts、clipboard_events 等）為不可變記錄，僅保留政策可清除。
   **audit_logs 的清除語義**：清除單位不是「逐列過期即刪」，而是**已封檢查點區間整段清除**——
   區間須已封章、`row_count > 0`、`max_created_at < cutoff`，且交易內再確認無未過期列；刪除與 tombstone 簽章
   （`purged_at`／`purge_signature`／`purge_signing_key_version`／`purge_policy_days`）同一交易提交。
   代價是**有界過度保留**（區間內只要有一列未過期，整段暫留，部署後首輪清除會看到少量已過期列仍在，屬預期行為）；
   反向偏差（提早刪）不會發生。實刪列數少於檢查點所簽 `row_count` 時整段回滾——照清會把一起竊取洗成「合法清除」。
   genesis 之前的列（`id < genesis id_from`）不受任何檢查點覆蓋，續走逐列路徑並以 id 上界封死，兩條路徑不重疊。
   原生 SQL 刪除入口為精確清冊（`cmd/server/audit_raw_delete_sites_guard_test.go`），新增未登記的入口即測試轉紅。
4. **審計不可變**: 審計日誌禁止更新（BeforeUpdate 拒絕）；存取複審簽核（access_reviews）為 append-only 證據，`BeforeUpdate`/`BeforeDelete` 一律拒絕（PCI 7.2.4）
5. **敏感欄位隱藏**: 密碼、私鑰、TOTP secret、host key 公鑰本體、webhook secret、refresh token_hash、password_histories 雜湊、failed_login_attempts、totp_last_step 等欄位 JSON 標籤為 `-`
6. **審計表無 FK**: session_commands / command_alerts 刻意不加外鍵，寫入位於會話資料路徑上，避免外鍵檢查與級聯刪除影響會話可用性與審計資料保留
7. **認證強化（/ PCI-DSS v4.0.1）**: refresh 憑證只存 SHA-256（明文僅發放當下回傳，rotation + reuse detection）；密碼歷史防重用（8.3.7）；帳號鎖定（密碼/TOTP 失敗共用計數，8.3.4）；TOTP 防重放（totp_last_step CAS 推進，8.5.1）；access token 固定 15 分短效，撤銷殘窗有上限
8. **雙層憑證世代**: provider 級 `oidc_providers.auth_epoch` 與使用者級 `users.credential_epoch` 各自單調遞增、**永不回退**；所有簽發出去的憑證（access／refresh／scoped／login ticket／connect grant／sessions 溯源）記錄簽發當下的兩個世代，全部驗證點**現查 DB** 並列比對（不得讀程序快取，否則多副本下停用形同虛設）。provider 停用／刪除／secret 輪替推進前者，解綁外部身分／帳號停用刪除／改為僅外部登入／改密推進後者。OIDC 一次性憑證（`oidc_flow_states`／`oidc_login_tickets`）皆為原子消費、僅存雜湊或隨機值，且帶到期索引供清理排程掃描

---

### 37. AuditCheckpoint（審計檢查點鏈）

**表名**: `audit_checkpoints`
**檔案**: `backend/internal/model/audit_checkpoint.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `seq` 唯一索引與 `(id_from, id_to)` 複合索引

列級 HMAC 偵測得了「列被改」、偵測不了「列被刪」。檢查點以 audit_logs 的 **id 閉區間 `[id_from, id_to]`** 為覆蓋單位，
把區間內每列的 `(id, key_version, integrity_hmac)` 依 id 升冪聚合成一個雜湊，鏈接前一檢查點並以 Ed25519 簽章，
使「少了列」成為可偵測事件。**區間主軸是 id 不是 created_at**：封印期回灌列的 `created_at` 是過去事件時刻而 id 是新取號，
時間區間必然被後來長出的列打破。空區間（`row_count=0`、`id_from = id_to + 1`）照樣蓋章並簽名。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Seq` | uint | `not null;uniqueIndex` | `seq` | 鏈序號，自 1（genesis）起嚴格連續；UNIQUE 是並發封章下不產生分叉鏈的最後防線 |
| `IDFrom` | uint | `not null;index(1)` | `id_from` | 覆蓋區間下界（含），= 前一檢查點 `id_to + 1` |
| `IDTo` | uint | `not null;index(2)` | `id_to` | 覆蓋區間上界（含），= 封章觸發時觀測到的 `MAX(id)` |
| `RowCount` | int64 | `not null` | `row_count` | 區間內實際列數（軟刪列計入） |
| `AggHash` | string | `type:varchar(64);not null` | `agg_hash` | 區間聚合雜湊（hex SHA-256） |
| `AggScheme` | string | `type:varchar(32);not null` | `agg_scheme` | 聚合演算法版本標識；編碼演進以新值表示，舊檢查點續以原 scheme 重算 |
| `PrevCheckpointHash` | string | `type:varchar(64);not null` | `prev_checkpoint_hash` | 前一檢查點「被簽章欄位＋signature」序列化的 SHA-256；genesis 錨定 `integrity_baselines` 的 `max_log_id` 與 `baseline_at` |
| `MinCreatedAt` | *time.Time | 無 | `min_created_at` | 區間內列的時間下界（空區間 NULL）。**僅供人讀與時間查詢的近似映射，不參與完整性判定** |
| `MaxCreatedAt` | *time.Time | 無 | `max_created_at` | 同上（時間上界）；同時是 retention「整區間過期才清」的判準 |
| `SealedAt` | time.Time | `not null` | `sealed_at` | 封章時刻（本機時鐘；完整性語義不依賴時鐘單調） |
| `SigningKeyVersion` | int | `not null` | `signing_key_version` | 簽章所用的 `checkpoint_signing_keys.version`；驗證依此取鑰，版本不存在計為 `signature_invalid` |
| `Signature` | string | `type:varchar(128);not null` | `signature` | Ed25519 簽章（base64） |
| `AnchorStatus` | string | `type:varchar(16);not null` | `anchor_status` | `enqueued`／`dropped`／`disabled`。封章後才發生，**不在簽章涵蓋內**；為本地盡力記錄，證明力最終取決於 syslog 收集端留存 |
| `PurgedAt` | *time.Time | 無 | `purged_at` | 合法清除（retention）的時刻；NULL 表未清除 |
| `PurgeSignature` | *string | `type:varchar(128)` | `purge_signature` | 清除 tombstone 簽章（簽 `(seq, purged_at, row_count, policy_days)`）；列不存在且無有效 tombstone 即為竄改告警 |
| `PurgeSigningKeyVersion` | *int | 無 | `purge_signing_key_version` | tombstone 所用簽章鑰版本（無此欄則簽章鑰輪替後 tombstone 不可驗） |
| `PurgePolicyDays` | *int | 無 | `purge_policy_days` | 清除當下的 `retention_audit_log_days` 值；tombstone 驗證以**本欄**重算而非現行政策值——不存則 admin 一改保留天數，全部歷史 tombstone 會同時驗不過而發出大規模假告警。本欄自身在 tombstone 簽章涵蓋內，直改仍驗不過 |
| `CreatedAt` | time.Time | - | `created_at` | 落庫時間 |

**ORM 守衛**：`BeforeDelete` 全拒；`BeforeUpdate` **僅**放行 `anchor_status`／`purged_at`／`purge_signature`／
`purge_signing_key_version`／`purge_policy_days` 五欄（皆為封章之後才發生、且不在檢查點簽章涵蓋內的狀態欄）
且只認 map 形式的 `Updates`（結構體形式一律拒絕，否則全欄位更新會從 `Save` 路徑溜過白名單）。
守衛由 `internal/model/audit_checkpoint_guard_test.go` 雙向釘住（拿掉守衛要紅、放寬白名單也要紅）。

---

### 38. CheckpointSigningKey（檢查點鏈簽章鑰）

**表名**: `checkpoint_signing_keys`
**檔案**: `backend/internal/model/checkpoint_signing_key.go`
**建表方式**: baseline（`baseline_schema_platform.go`），含 `version` 唯一索引；首啟由 `CheckpointSigningService` 生成 v1

形態沿匯出簽章鑰的專表＋ColumnCodec AAD 包裹，但**自始帶 `version` 與 `active` 語義**（匯出鑰無版本欄是既有缺陷）。
不納入 DataKey purpose 的版本鏈／輪替／清理機制（那套機器為對稱包裹材料而設）；防刪保障＝無任何刪除或匯出私鑰的 API ＋ ORM 守衛。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Version` | int | `not null;uniqueIndex` | `version` | 鑰版本（自 1 起）；檢查點記錄其簽章版本，驗證依此取鑰 |
| `Active` | bool | `not null;default:false` | `active` | 現行簽章鑰標記（本階段恆僅 v1 為 true）；無 active 版本即 fail-close 拒絕啟動 |
| `PublicKey` | string | `type:varchar(64);not null` | `public_key` | base64 Ed25519 公鑰（非機密，供離線驗章與清冊指紋） |
| `PrivateKeyEnc` | string | `type:text;not null` | `-` | 經 ColumnCodec 以 `RefCheckpointSigningPrivateKey` 綁定 AAD 包裹的私鑰密文；登記於 `envelopeMigrationTargets`（漏登會使退役 DEK 誤判零引用而銷毀，全部歷史檢查點從此不可驗） |
| `CreatedAt` | time.Time | - | `created_at` | 生成時間 |

**ORM 守衛**：`BeforeUpdate`／`BeforeDelete` 全拒。刪除任一曾用於簽章的版本＝以該版本簽的歷史檢查點永久不可驗，
屬單向不可逆的證據損毀。日後新增輪替時須刻意修改守衛（放行 `active` 翻轉），而非現在先留縫。

---

### 39. AuditCheckpointTrim（檢查點鏈修剪記錄）

**表名**: `audit_checkpoint_trims`
**檔案**: `backend/internal/model/audit_checkpoint_trim.go`
**建表方式**: baseline（`baseline_schema_audit.go`；步驟 5），`last_trimmed_seq` 唯一

檢查點自身到期（`retention_checkpoint_days`）時自鏈頭（最舊 seq）起整段修剪，每次修剪寫一筆本表記錄。
**落點刻意是獨立表而非 audit_log 型別**：修剪記錄必須活得比它所記錄的檢查點久，寫成 audit_log 列則它自己
會落入某個檢查點區間並在保留期到期時被 retention 清掉——鏈頭錨定隨之消失，殘鏈自此永遠無法與被修剪段接續。
修剪動作**另外**寫一筆 audit_log 留痕（人可讀的操作記錄）：留痕會過期，錨定不會。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `FromSeq` | uint | `not null` | `from_seq` | 本次修剪的 seq 閉區間下界（＝修剪前的鏈頭） |
| `LastTrimmedSeq` | uint | `not null;uniqueIndex` | `last_trimmed_seq` | 上界；UNIQUE 使同一段不會被記錄兩次 |
| `TrimmedCount` | int64 | `not null` | `trimmed_count` | 實際刪除的檢查點列數 |
| `LastTrimmedLinkHash` | string | `type:varchar(64);not null` | `last_trimmed_link_hash` | 被修剪的最後一個檢查點的鏈接雜湊＝殘鏈新鏈頭的 `prev_checkpoint_hash`；驗證端據此區分「合法修剪」與「有人挖掉鏈頭」（後者回 `seq_gap`） |
| `GenesisIDFrom` | uint | `not null` | `genesis_id_from` | 修剪前鏈上最小的 `id_from`。修剪使 `MIN(id_from)` 上移，不保存則 pre-genesis 逐列清除路徑的 id 上界會隨每次修剪自動放寬，吃到曾被區間覆蓋的 id 段 |
| `PolicyDays` | int | `not null` | `policy_days` | 觸發本次修剪的 `retention_checkpoint_days` 值 |
| `TrimmedAt` | time.Time | `not null` | `trimmed_at` | 修剪時刻 |
| `SigningKeyVersion` | int | `not null` | `signing_key_version` | 簽章鑰版本 |
| `Signature` | string | `type:varchar(128);not null` | `signature` | Ed25519 簽章（涵蓋上列全部欄位） |
| `CreatedAt` | time.Time | - | `created_at` | 落庫時間 |

**ORM 守衛**：`BeforeUpdate`／`BeforeDelete` 全拒（與 `audit_checkpoints` 同級）。
**執行期保守閘**：政策若經 SQL 直改而違反跨鍵約束（檢查點保留期短於資料保留期），
retention **跳過**鏈修剪並記告警；`TrimChain` 另有「仍覆蓋現存列的檢查點絕不修剪」的內層約束（兩者為縱深）。

---

### 40. AuditRetentionWatermark（保留期清除水位）

**表名**: `audit_retention_watermarks`
**檔案**: `backend/internal/model/audit_retention_watermark.go`
**建表方式**: baseline（`baseline_schema_audit.go`），含 `class` 唯一索引。
**無 `deleted_at` 欄**——本表永不刪除，軟刪欄只會讓「被藏起來的列」與「不存在的列」在冷啟動語義上不可區分

稽核工作台的保留三態（`present`／`purged`／`not_retained`）來源。
**為何另立一張表**：現行清除留痕本身是一筆 `audit_logs` 列，下一輪 retention 會把它一併清掉——
拿它當「此區間已依保留政策清除」的來源，會在最需要它的時候（區間夠舊）消失，工作台於是把
「已合法清除」誤呈為「空白」，即自己製造竄改誤報。故水位落在一張**永不清除**的表，
每類別恆定一列，體積不隨資料量成長。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `Class` | RetentionClass | `type:varchar(32);not null;uniqueIndex:idx_retention_watermark_class` | `class` | 資料類別，每類別至多一列：`audit_log`／`session_command`／`command_alert`／`recording`／`clipboard_event`（末者現況不在任何 retention 目標內，恆無列＝工作台回 `not_retained`） |
| `PurgedThroughAt` | time.Time | `not null` | `purged_through_at` | 已清除資料的時間上界，**單調前進**（只可 `GREATEST` 更新）。保留天數自 90 調為 365 時若倒退，早先已清掉的區間會被重新宣稱為 present |
| `LastPurgeAt` | time.Time | `not null` | `last_purge_at` | 最近一次清除執行時刻（UI 的「最後清除於 T」） |
| `PolicyDays` | int | - | `policy_days` | 該次清除所用的保留天數；0＝永久保留（永久時不更新水位） |
| `Partial` | bool | `not null;default:false` | `partial` | 上次執行是否因單輪上限而僅部分完成；為真時 UI 另標「清除進行中」 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**索引**（實測）: `idx_retention_watermark_class`＝UNIQUE `(class)`。

**ORM 守衛**：`BeforeDelete` **全拒**（`ErrRetentionWatermarkImmutable`）。水位一旦消失，該類別回退為冷啟動語義（`present`），
已清除區間立刻被誤呈為「完整且無紀錄」。原生 SQL 繞得過本 hook，故 retention 側另有守衛測試釘住「清除迴圈不含本表」。

**誠實邊界**（須與 UI 文案一致）：`purged_through_at` 的語義是「早於此刻者**不完整**」，不是「早於此刻者全部已刪」
（分批清除、部分完成、區間化過度保留都會殘留）；本表**無簽章**，具 DB 權限者可改，是可用性標記而非防篡改證明——
工作台不得據本表作出任何完整性宣稱（audit_logs 類另有簽章化 tombstone `audit_checkpoints.purged_at/purge_signature`）。

---

### 41. AuditChainVerifyState（鏈自動驗證的營運狀態）

**表名**: `audit_chain_verify_states`
**檔案**: `backend/internal/model/audit_chain_verify_state.go`
**建表方式**: baseline（`baseline_schema_audit.go`）

檢查點鏈兩層自動驗證（近期層＋全鏈層）的執行狀態，**單列表**（ID 恆為 `AuditChainVerifyStateID`＝1，
併發 tick 只會更新同一列而非長出第二份狀態）。成功輪次的歷史沒有證據價值，異常的歷史已由
`audit_failure_events` 永久承載且帶起訖區間，故不做每輪一列。

**為何要持久化**：排程器若靜默停擺（或從未啟動），不會有任何告警發出——沒跑就沒有異常可報，
這是所有 watchdog 的共同盲點。兩層各自的最近執行時點是唯一能讓人（與稽核）看出「它其實沒在運作」的訊號。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵，恆為 1（單列語義以主鍵釘死） |
| `RecentLastRunAt` | *time.Time | - | `recent_last_run_at` | 近期層最近執行時點；nil＝從未執行 |
| `RecentLastStatus` | string | `size:16;not null;default:''` | `recent_last_status` | `passed`／`failed`／`error`（`error`＝本輪無法完成，狀態為未知而非「無異常」） |
| `RecentLastDurationMs` | int64 | `not null;default:0` | `recent_last_duration_ms` | 近期層最近一輪耗時 |
| `RecentWindowDaysEffective` | int | `not null;default:0` | `recent_window_days_effective` | 近期層本次**實際生效**的窗口天數（政策值經審計紀錄保留天數 clamp 後）。記生效值而非設定值：承諾驗證保留期以外的範圍是空頭支票 |
| `RecentLastSeq` | uint | `not null;default:0` | `recent_last_seq` | 上次觀測到的鏈尾檢查點序號；前進即代表期間有新封存（觀測式觸發的狀態載體） |
| `FullLastRunAt` | *time.Time | - | `full_last_run_at` | 全鏈層最近執行時點；nil＝從未執行 |
| `FullLastStatus` | string | `size:16;not null;default:''` | `full_last_status` | 同 `RecentLastStatus` 的值域 |
| `FullLastDurationMs` | int64 | `not null;default:0` | `full_last_duration_ms` | 全鏈層最近一輪耗時 |
| `StructureFailedCount` | int | `not null;default:0` | `structure_failed_count` | 最近一次結構層全鏈驗證的失敗點數（兩層共用同一支驗證） |
| `ContentVerifiedIntervals` | int | `not null;default:0` | `content_verified_intervals` | 最近一輪實際驗過的內容層區間數 |
| `ContentCursorSeq` | uint | `not null;default:0` | `content_cursor_seq` | 內容層滾動位置（下一輪自此檢查點序號起推進；推至鏈尾即回捲至修剪點之後） |
| `LastFullCycleAt` | *time.Time | - | `last_full_cycle_at` | 最近一次繞完全歷史一輪的時點 |
| `OpenFailedSeqs` | string | `type:text;not null;default:''` | `open_failed_seqs` | **未結案的失敗區間集合**（JSON 物件，序號→狀態；兩層共用同一份）。假恢復修法的核心：每輪必重驗且不受列預算限制，失效事件僅在本集合清空時才准結案 |
| `LastFingerprint` | string | `size:32;not null;default:''` | `last_fingerprint` | 由「最嚴重狀態＋結構層失敗點數＋`OpenFailedSeqs`」計算的指紋，**不得由本輪驗過的區間結果計算**（會逐輪抖動而變相每輪重發通知） |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**索引**: 僅主鍵（單列表）。

**誠實邊界（須與 UI 文案一致）**：本表**不在檢查點鏈的覆蓋範圍內**（鏈只覆蓋 `audit_logs`），
可由資料庫直寫改成「最近驗過且通過」。此風險已落在既有邊界 R0（同時掌握金鑰與資料庫者）之內，不新增風險面；
但檢查點驗證頁 SHALL 明示該區塊為**營運狀態顯示而非完整性證明**——真正的證據是 `audit_failure_events`、
離機備份留存的副本，以及外部查核方以公鑰自行驗章。
對外揭露（`GET /audit-checkpoints/verify` 的既有回應，**不新增路由**）**只帶計數不帶序號清單**，
與告警出站同一條去識別紅線。

---

### 42. AuditExportJob（證據包非同步匯出 job）

**表名**: `audit_export_jobs`
**檔案**: `backend/internal/model/audit_export_job.go`
**建表方式**: **增量 migration `20260824_audit_export_jobs`（非 baseline）**——純新表、無加密欄、
無資料回填，增量 DDL 在全新資料庫（baseline → 本條）與既有資料庫（僅本條）上收斂到同一形狀，
不需要剪貼簿轉換那種「baseline 終態＋post-unseal 回填」雙軌。DDL 沿 baseline 紀律：無條件、無 `IF NOT EXISTS`。

證據包（`evidence_bundle`）匯出改為**非同步**後的 job 追蹤表。**只有證據包走 job；事件報告維持同步匯出**。
本表是**純狀態表、非證據**：job 列是申請者的追蹤憑據，證據義務落在 `audit_logs`（發起與下載均留痕）
與產物檔本身；drop 本表僅失去追蹤面，不觸及任何證據（故 Down 為可逆 `DROP TABLE`）。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey` | `id` | 主鍵 |
| `RequesterID` | uint | `not null;index:idx_audit_export_jobs_requester_status,priority:1` | `-` | 申請者（下載授權與清單範圍的判準；回應層另走 DisplayMap 投影） |
| `RequesterName` | string | `size:50;not null` | `-` | 申請者名稱（發起當下快照，供 manifest `exported_by` 與審計列） |
| `FilterJSON` | string | `type:text;not null` | `-` | 完整篩選條件快照（`ExportFilter` 的 JSON 序列化；供 worker 重建篩選，不出站） |
| `FilterHash` | string | `size:64;not null` | `-` | 篩選正規化 SHA-256；`pending`／`running` 去重鍵 |
| `Status` | string | `size:16;not null;index:idx_audit_export_jobs_requester_status,priority:2;index:idx_audit_export_jobs_status` | `status` | 狀態五態：`pending`／`running`／`done`／`failed`／`expired`（**無獨立「取消」態**——失權取消落 `failed` 並以 `ErrorSummary` 標因） |
| `Attempts` | int | `not null` | `-` | 打包嘗試次數（含首次）；達上限（3）即轉 `failed` |
| `ArtifactPath` | string | `size:500;not null` | `-` | 產物檔伺服器內部路徑（不出站；過期清除後清空） |
| `ArtifactSHA256` | string | `size:64;not null` | `artifact_sha256` | 產物 SHA-256（過期後仍保留供紀錄比對） |
| `ArtifactSize` | int64 | `not null` | `artifact_size` | 產物位元組大小 |
| `ErrorSummary` | string | `size:64;not null` | `error_summary` | 失敗摘要機器碼（`export_job.pack_failed`／`export_job.requester_revoked`）；成功恆空 |
| `RequestedAt` | time.Time | `not null` | `requested_at` | 發起時刻 |
| `PackagedAt` | *time.Time | - | `packaged_at` | 實際打包完成時刻（與 `RequestedAt` 一併寫入 manifest 的雙時戳） |
| `ExpiresAt` | *time.Time | - | `expires_at` | 產物過期時刻（`done` 時＝`PackagedAt`＋保留期）；逾期由 worker 清檔並轉 `expired` |
| `OffsiteObjectID` | *uint | - | `-` | 離機保管帳冊列的指標（→ `offsite_objects.id`，邏輯外鍵，不建 FK 約束）。NULL＝本 job 的產物尚未（或不會）進入離機佇列。由增量 migration `20260825_evidence_offsite` 加欄 |
| `OffsiteStatus` | string | `size:20;not null;default:''` | `-` | 帳冊 `state` 的顯示用快取，語義與 `sessions` 的同名欄逐字相同；下載中心的離機狀態行讀本欄。回應層另以 `offsite_status` 投影（本 model 本身不帶 json tag）。同一條 migration 加欄 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `UpdatedAt` | time.Time | - | `updated_at` | 更新時間 |

**索引**（DDL 於 `backend/internal/database/migration_audit_export_jobs.go`）:
- `idx_audit_export_jobs_requester_status`＝`(requester_id, status)`——下載中心清單與每申請者進行中計數的查詢面。
- `idx_audit_export_jobs_status`＝`(status)`——worker 領件（`pending` 最舊優先）與過期清掃的查詢面。
- `uniq_audit_export_jobs_active_filter`＝**部分唯一索引** `(requester_id, filter_hash) WHERE status IN ('pending','running')`
  ——`pending`／`running` 去重的資料庫層防線（admission 交易是第一道，本索引擋住繞過服務層的寫入路徑）；
  `failed`／`done` 不在 `WHERE` 內，故不阻擋重新發起、也不使舊包被復用。

**設計說明**:
- **產物與 job 列的保留期分別計**：產物檔 24h 後由 worker 清除並轉 `expired`；job 列（含終態）
  另有紀錄保存期（30 天）後清理，兩者不同源。
- 欄位刻意不帶 `gorm default` tag：所有欄位由程式碼顯式賦值（避免 GORM 對零值交由 DB 填值）。
- **產物暫存目錄不落資料庫**（`EXPORT_ARTIFACT_PATH`，預設 `/var/lib/custodexa/exports`）：
  屬暫存、限時清除，非備份對象（見 `docs/ops/backup-and-restore.md`）。
- **離機兩欄不另建索引**：`20260825_evidence_offsite` 只對 `sessions` 建了兩條部分索引
  （回填與保留清理的掃描面），本表沒有等價的掃描查詢——下載中心清單以既有的
  `idx_audit_export_jobs_requester_status` 取件後直讀快取欄，離機側的查詢面則落在
  `offsite_objects` 自己的四條索引上。
- **產物到期只清本機側，不動遠端物件**（產物檔 24h、job 列 30 天，兩者不同源，見上）：產品對遠端不發刪除，
  遠端副本的到期清理歸部署方的 bucket lifecycle（見第 45 節與 `docs/ops/backup-and-restore.md`）。

---

### 43. UserSourceIP（帳號來源位址基準）

**表名**: `user_source_ips`
**檔案**: `backend/internal/model/user_source_ip.go`
**建表方式**: **增量 migration `20260826_source_ip_forensics`（非 baseline）**——建表、兩條索引、
`users.allowed_cidrs` 加欄、`command_alerts_kind_check` 值域擴充與**冷啟動回填**同屬這一條。
DDL 沿 baseline 紀律：無條件、無 `IF NOT EXISTS`，在已套用的庫上重跑必須大聲失敗。

帳號 × 來源位址的「**已見**」基準。它是新來源位址告警的**判定依據，不是日誌、也不是防篡改證據**
（證據是 `command_alerts` 的告警列與 `audit_logs` 的審計列）；故**不在任何保留政策的清除目標內**
——清掉它會讓舊位址回來時再被判為新，告警就成了噪音。表大小上界＝使用者數 × 相異位址數，
每列只更新時間、不追加，無無界增長來源。
**刻意無外鍵**（與 `command_alerts` 同取向）：軟刪使用者的列保留（帳號可能重新啟用），
硬刪使用者的殘列惰性無害。

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `UserID` | uint | `primaryKey;autoIncrement:false` | `user_id` | 帳號 ID。DB 側 `bigint NOT NULL`，與 `ClientIP` 合為複合主鍵 `user_source_ips_pkey`（**本表無 `id` 代理鍵**） |
| `ClientIP` | string | `primaryKey;size:50;index:idx_user_source_ips_ip_seen,priority:1` | `client_ip` | 來源位址（正規化後的字串）。DB 側 `character varying(50) NOT NULL` |
| `FirstSeenAt` | time.Time | `not null` | `first_seen_at` | 首次見到（登入或建線皆算）。DB 側 `timestamp with time zone NOT NULL` |
| `LastSeenAt` | time.Time | `not null;index:idx_user_source_ips_ip_seen,priority:2` | `last_seen_at` | 最近見到。位址候選查詢依此降序，故與 `ClientIP` 同在覆蓋索引內。DB 側 `timestamp with time zone NOT NULL` |
| `FirstSessionAt` | *time.Time | -（nullable） | `first_session_at,omitempty` | 首次自此位址**建線**的時刻；NULL＝從未建線（只登入過）。DB 側 `timestamp with time zone`（可空、無預設） |
| `FirstSessionID` | *uint | -（nullable） | `first_session_id,omitempty` | 取得首次建線資格的會話 id；NULL＝尚無勝者。DB 側 `bigint`（可空、無預設）。**同時是並發首連線的單勝者判定鍵**：條件更新只讓第一個提交者寫入，回傳值等於自己 session id 者才發告警 |

**索引**（DDL 於 `backend/internal/database/migration_source_ip_forensics.go`）:
- `user_source_ips_pkey`＝**複合主鍵** `(user_id, client_ip)`，由建表語句的
  `CONSTRAINT user_source_ips_pkey PRIMARY KEY (user_id, client_ip)` 承載；也是回填與觀察 upsert 的
  `ON CONFLICT` 目標。
- `idx_user_source_ips_ip_seen`＝`(client_ip varchar_pattern_ops, last_seen_at)`
  ——位址候選查詢是「前綴 `LIKE` ＋ 依 `MAX(last_seen_at)` 降序」的覆蓋索引。
  首欄**必須**以 `varchar_pattern_ops` 建立：非 C collation 下 `LIKE 'p%'` 不走一般 btree。
  DDL 逐字：`CREATE INDEX idx_user_source_ips_ip_seen ON user_source_ips USING btree (client_ip varchar_pattern_ops, last_seen_at)`。

**設計說明**:
- **登入不佔建線**：`FirstSeenAt` 與 `FirstSessionAt`／`FirstSessionID` 分開追蹤——登入只把位址納入基準，
  首次建線才設後兩欄並取得告警資格。「先登入再建線」的典型流程因此仍會在建線時響一次，
  登入不得抹掉「新」這件事。
- **冷啟動回填**（migration Up 的最後兩句，不在 `schemaDDLStatements()` 內——回填不是 schema）：
  自 `sessions` 全史（每組 `(user_id, client_ip)` 取最早會話為首次建線，`first_session_id` 一併填）
  與 `audit_logs` 的登入成功列（只補 `first_seen_at`／`last_seen_at`）合併，
  使部署當下**已見的位址不觸發告警**。軟刪列不計、空位址或 NULL 位址跳過；
  全新庫兩表皆空、回填零列。
- **Down 銷毀資料**：`DROP TABLE user_source_ips` 丟掉整份基準，再次 Up 後全部位址重新判為新。
  詳見「Migration 版本一覽」與 `docs/ops/upgrade-sop.md` §4。

---

### 44. OffsiteProfile（離機儲存設定世代）

**表名**: `offsite_profiles`
**檔案**: `backend/internal/model/offsite_profile.go`
**建表方式**: **增量 migration `20260825_evidence_offsite`（非 baseline）**，與 `offsite_objects` 同一條。
單列不變式沿 `ldap_directories` 的既有形態，由**三者並用**承載：
inline `CONSTRAINT offsite_profiles_singleton_check CHECK ((singleton = 1))` 鎖死值域，
＋ `idx_offsite_profiles_current`＝`UNIQUE (singleton) WHERE retired_at IS NULL`（partial）。
**CHECK 不可省**：單靠唯一索引只禁止相同值重複，`singleton=2` 仍可與 `singleton=1` 並存而使「至多一列」失效。
另有 inline `CONSTRAINT offsite_profiles_credential_mode_check`，把 `credential_mode='stored'` 與
「密文非空」釘成等價（見下）。兩條 CHECK 與該索引皆為具名斷言，登記於
`baseline_parity_pg_test.go` 的 `baselineCheckConstraints` 與 `baselineStructuralAssertions`（`pg_get_indexdef` 逐字比對）。

**建表 DDL（逐字，`backend/internal/database/migration_evidence_offsite.go`）**:

```sql
CREATE TABLE offsite_profiles (
	generation_id bigserial,
	profile_fingerprint character varying(16) NOT NULL,
	singleton integer DEFAULT 1 NOT NULL,
	provider character varying(8) NOT NULL,
	endpoint text DEFAULT ''::text NOT NULL,
	bucket character varying(255) NOT NULL,
	prefix character varying(255) DEFAULT ''::character varying NOT NULL,
	region character varying(64) DEFAULT ''::character varying NOT NULL,
	path_style boolean DEFAULT false NOT NULL,
	credential_mode character varying(16) NOT NULL,
	credentials_enc text DEFAULT ''::text NOT NULL,
	credential_revision bigint DEFAULT 0 NOT NULL,
	created_at timestamp with time zone,
	activated_at timestamp with time zone,
	retired_at timestamp with time zone,
	credentials_cleared_at timestamp with time zone,
	CONSTRAINT offsite_profiles_singleton_check CHECK ((singleton = 1)),
	CONSTRAINT offsite_profiles_credential_mode_check CHECK ((((credential_mode)::text = 'stored'::text) = (credentials_enc <> ''::text))),
	CONSTRAINT offsite_profiles_pkey PRIMARY KEY (generation_id)
)
```

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `GenerationID` | uint | `column:generation_id;primarykey` | `generation_id` | **世代識別，不可重用**（`bigserial`，序列不回頭）。帳冊的 `storage_generation_id` 以它為邏輯外鍵 |
| `ProfileFingerprint` | string | `size:16;not null` | `profile_fingerprint` | 儲存設定指紋（16 位十六進位；成分＝provider＋完整正規化 endpoint＋bucket＋prefix＋region）。**可重複**——它是連線參數的函數，「A→B→切回 A」會算出與第一世代相同的值。只作世代切換的觸發判準與顯示 |
| `Singleton` | int32 | `not null;default:1` | `-` | 現行世代唯一性的常數載體；恆為 1，由 CHECK 與 partial unique index 保證。不對外暴露——schema 層的不變式載體，非業務欄位。型別取 `int32` 使 GORM 於 PostgreSQL 映射為 `integer`，與 DDL 逐欄一致 |
| `Provider` | string | `size:8;not null` | `provider` | driver 選擇；值域同 `internal/offsite` 的 `ProviderS3`／`ProviderGCS` |
| `Endpoint` | string | `type:text;not null;default:''` | `-` | 連線端點，**完整正規化含 path**。userinfo／query／fragment 於寫入時即被拒（端點淨化），故本欄不含機密；**顯示面只印 origin**，path 不回顯、不入日誌 |
| `Bucket` | string | `size:255;not null` | `bucket` | 儲存桶名 |
| `Prefix` | string | `size:255;not null;default:''` | `prefix` | 物件 key 前綴 |
| `Region` | string | `size:64;not null;default:''` | `region` | 區域 |
| `PathStyle` | bool | `not null;default:false` | `path_style` | S3 path-style 定址 |
| `CredentialMode` | string | `size:16;not null` | `credential_mode` | 三值：`stored`（用本世代自己的憑證，密文非空）／`default_chain`（部署方**刻意**選 SDK 預設憑證鏈，密文必空）／`revoked`（曾有憑證、已由管理員撤銷，密文必空且 `credentials_cleared_at` 非空）。三值分立是為了消除「空密文」的歧義——若空密文同時代表「用預設鏈」與「已撤銷」，撤銷後仍可能靜默改走預設鏈繼續取回。`revoked` 一律不回退預設鏈 |
| `CredentialsEnc` | string | `type:text;not null;default:''` | `-` | 該世代的憑證（信封加密；明文為依 provider 的 JSON）。**write-only**：任何讀取投影、API 回應與審計皆不含本欄與其遮罩值 |
| `CredentialRevision` | int64 | `not null;default:0` | `-` | 每次憑證變更或撤銷 +1；per-generation client 快取的失效依據。跨程序與重啟的正確性不靠行程內事件——取用 client 前核對快取內記載的版號與該列現值，不等即丟棄重建 |
| `CreatedAt` | time.Time | - | `created_at` | 建立時間 |
| `ActivatedAt` | time.Time | - | `activated_at` | 成為現行世代的時刻 |
| `RetiredAt` | *time.Time | - | `retired_at`（omitempty） | 退役時刻；**NULL＝現行世代** |
| `CredentialsClearedAt` | *time.Time | - | `credentials_cleared_at`（omitempty） | 憑證撤銷時刻（`credential_mode='revoked'` 時非空） |

**索引**（DDL 於 `backend/internal/database/migration_evidence_offsite.go`）:
- `idx_offsite_profiles_current`＝**部分唯一索引**
  `CREATE UNIQUE INDEX idx_offsite_profiles_current ON offsite_profiles USING btree (singleton) WHERE (retired_at IS NULL)`
  ——現行世代至多一列。CHECK 把索引鍵釘成常數，故「未退役者至多一列」是**全域**保證。

**設計說明**:
- **現行世代是「至多一列（0 或 1）」而不是「恰一列」**。零現行世代是合法終局態——管理介面的
  「停止離機」把現行列填上 `retired_at` 而**不建新列**。零列因此有兩種語義，由帳冊區分：
  `offsite_profiles` 完全零列＝**從未設定**（「未設定＝行為完全不變」的機械保證只綁這一格）；
  有歷史世代而零現行世代＝**停用態**——不建上傳 worker、上傳佇列指標缺席，但取回子系統照常組裝、
  歷史物件仍可取回。
- **主鍵取 `generation_id` 而非指紋**：指紋是連線參數的函數，`s3 → gcs → 切回原 s3 參數`
  會算出與已退役列相同的值；以指紋為主鍵則第三個世代必然撞主鍵，改成「重啟舊列」
  又會把兩個時間世代及其**各自不同的憑證**合併成一列。取 `bigserial` 是沿本 repo 慣例
  （baseline 每張表皆 `id bigserial`，無 ULID／UUID 主鍵先例）；序列不回頭即天然滿足「不可重用」。
- **安全紅線**：`credentials_enc` 須登記於 `cipher_refs.go`（`RefOffsiteCredentials`）與
  `envelopeMigrationTargets`（AST 守衛 `envelope_targets_guard_test.go` 強制）。該清單同時驅動
  DEK 輪替重加密與退役 DEK 銷毀前的引用掃描——漏登會誤判零引用而銷毀仍在用的金鑰材料，
  屆時該世代憑證永久不可解、其遠端物件永不可取回。
- **env→DB 的一次性 seed 需要 codec**（段 2 才存在），故走 post-unseal 佇列；其執行期冪等標記
  `20260825_offsite_env_seeded` 借用 `schema_migrations` 表存放，由 `runtimeMarkerVersions`
  自 fail-close 判定中扣除（`migrations.go`）。標記語義為**「已完成評估」而非「已建立資料」**，
  且**隨資料庫備份一起還原**——「標記在而本表零列」是真實可達的部署狀態，其終局為「未設定」，
  只能經管理介面重新設定（見 `docs/ops/backup-and-restore.md` §4.4）。

**不得作出的宣稱**（本節與引用本節的文件一律避免）:
1. **世代表記的是連線參數，不是可用性**——bucket 被刪除、憑證在儲存端失效、網路不可達，取回一樣失敗；
   本表只保證失敗訊息能指出「哪個世代、哪個 provider、缺什麼」，不宣稱歷史物件必然取得回。
2. **指紋不是識別**——`profile_fingerprint` 可重複，任何「以指紋指認某個世代」的說法都是錯的；
   識別一律用 `generation_id`。

---

### 45. OffsiteObject（離機保管帳冊）

**表名**: `offsite_objects`
**檔案**: `backend/internal/model/offsite_object.go`
**建表方式**: **增量 migration `20260825_evidence_offsite`（非 baseline）**，與 `offsite_profiles` 同一條。
DDL 沿 baseline 紀律：無條件、無 `IF NOT EXISTS`。

每個上傳目標一列，是遠端物件的**身分與狀態機**所在，同時**即是佇列**
（`state='pending'` 的部分索引就是取件查詢面）。**表所有權歸 `internal/offsite`**：
其他模組不得直接以 GORM 或 SQL 碰本表，只能經該包的帳冊方法取物件（資料邊界閘門盯著）。
`kind`／`origin`／`state` 的值域走應用層常數、**不加 CHECK**（加 CHECK 會動 baseline 具名 CHECK 的總量斷言，
而這三欄只由本包寫入）。

**建表 DDL（逐字，`backend/internal/database/migration_evidence_offsite.go`）**:

```sql
CREATE TABLE offsite_objects (
	id bigserial,
	kind character varying(16) NOT NULL,
	owner_id bigint NOT NULL,
	origin character varying(8) NOT NULL,
	provider character varying(8) NOT NULL,
	storage_generation_id bigint NOT NULL,
	bucket character varying(255) NOT NULL,
	object_key character varying(1024) NOT NULL,
	version_id character varying(255) NOT NULL,
	sha256 character varying(64) NOT NULL,
	size bigint NOT NULL,
	state character varying(20) NOT NULL,
	attempts bigint NOT NULL,
	lease_expiries bigint NOT NULL,
	next_attempt_at timestamp with time zone,
	lease_until timestamp with time zone,
	uploaded_at timestamp with time zone,
	error_code character varying(64) NOT NULL,
	created_at timestamp with time zone,
	updated_at timestamp with time zone,
	CONSTRAINT offsite_objects_pkey PRIMARY KEY (id)
)
```

| 欄位 | 類型 | GORM Tags | JSON | 說明 |
|------|------|-----------|------|------|
| `ID` | uint | `primarykey;index:idx_offsite_objects_due,priority:3,where:state = 'pending'` | `-` | 主鍵 |
| `Kind` | string | `size:16;not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:1` | `-` | 上傳目標種類：`recording`（擁有者＝`sessions.id`）／`export`（擁有者＝`audit_export_jobs.id`） |
| `OwnerID` | uint | `not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:2` | `-` | 擁有者列的主鍵（依 `kind` 解讀；邏輯外鍵，不建 FK 約束） |
| `Origin` | string | `size:8;not null;index:idx_offsite_objects_due,priority:1,where:state = 'pending'` | `-` | 排入來源：`live`（會話結束／打包完成當下即排入）／`backfill`（回填掃描排入）。雙佇列配額的判準 |
| `Provider` | string | `size:8;not null` | `-` | 上傳當時的 provider；**冗餘的明文身分欄**（對帳與管理介面顯示直讀，免 join） |
| `StorageGenerationID` | uint | `not null;uniqueIndex:uniq_offsite_objects_owner_generation,priority:3` | `-` | 上傳當時的設定世代（→ `offsite_profiles.generation_id` 的邏輯外鍵，不建 FK 約束）。**取回一律以本欄取世代、用該世代自己的憑證與 driver**；對不到世代列時 fail-close 拒絕，不退回「用現行設定猜」 |
| `Bucket` | string | `size:255;not null` | `-` | 上傳當時的 bucket（設定世代變更後仍可指認） |
| `ObjectKey` | string | `size:1024;not null` | `-` | 物件 key |
| `VersionID` | string | `size:255;not null` | `-` | 儲存端回的版本識別；**參考性記錄**——有帶就記，任何路徑不依賴；非版本化的儲存桶為空字串 |
| `SHA256` | string | `column:sha256;size:64;not null` | `-` | **上傳當下**讀到的位元組的整檔 SHA-256。取回時以本值核對，不符即拒絕交付 |
| `Size` | int64 | `not null` | `-` | 上傳當下讀到的位元組數 |
| `State` | string | `size:20;not null;index:idx_offsite_objects_state` | `-` | 狀態機，七態（見下） |
| `Attempts` | int | `not null` | `-` | 上傳嘗試次數；達上限（5）即轉 `failed` |
| `LeaseExpiries` | int | `not null` | `-` | 租約到期回收次數；≥2 即卡死判準（不等到 `attempts` 上限） |
| `NextAttemptAt` | *time.Time | `index:idx_offsite_objects_due,priority:2,where:state = 'pending'` | `-` | 退避時點（退避表 1m／5m／15m／1h／6h） |
| `LeaseUntil` | *time.Time | `index:idx_offsite_objects_lease,where:state = 'uploading'` | `-` | 上傳中的租約；到期回收回 `pending` |
| `UploadedAt` | *time.Time | - | `-` | 上傳成功時刻（本機快取清除的計時起點） |
| `ErrorCode` | string | `size:64;not null` | `-` | 機器碼（`offsite.*`）。原始錯誤只進伺服器日誌——儲存端的錯誤字串可能夾帶端點、路徑甚至簽章材料 |
| `CreatedAt` | time.Time | - | `-` | 建立時間 |
| `UpdatedAt` | time.Time | - | `-` | 更新時間 |

**狀態機**（值域常數在 `backend/internal/offsite/state.go`，該檔是唯一事實源）:

```
pending → uploading → uploaded → local_purged
         ↘ failed（達重試上限）
           integrity_mismatch（取回驗證不符）
           foreign（設定世代已退役；只讀）
```

| `state` | 語義 |
|---|---|
| `pending` | 待上傳（本態＋`next_attempt_at` 就是取件查詢面） |
| `uploading` | 上傳中，持有租約 |
| `uploaded` | 已上傳並記帳（`sha256`／`size`／`uploaded_at`） |
| `failed` | 重試達上限；`error_code` 保留，可經管理介面手動重試 |
| `integrity_mismatch` | 取回時 SHA-256 或大小不符，已拒絕交付 |
| `foreign` | 所屬設定世代已退役（世代切換或停止離機）：**只讀**。不再上傳、不做本機快取清除（其遠端可達性已不由現行設定保證，本機副本可能是唯一可讀副本）；取回仍以該世代自己的憑證進行 |
| `local_purged` | 本機副本已因保留政策到期而清除；**遠端物件未被刪除** |

> 擁有表的 `offsite_status` 快取欄另含兩個**非帳冊態**的回填掃描分類——
> `skipped_missing`（`recording_path` 非空但本機檔讀不到）與 `skipped_expired`（已逾錄影保留期）
> ——這兩者**不建帳冊列**，故不出現在上表。快取欄的完整值域＝上表七態 ∪ 這兩者 ∪ 空字串。

**索引**（DDL 於 `backend/internal/database/migration_evidence_offsite.go`，四條）:
- `uniq_offsite_objects_owner_generation`＝**唯一索引** `(kind, owner_id, storage_generation_id)`
  ——同一擁有者在同一設定世代只追蹤一個物件，重傳更新同列；世代含在鍵內，故新世代可有新物件而舊世代的列不被覆蓋。
  排入帳冊時的冪等衝突目標。**不得以可重複的指紋取代世代識別**——「A→B→A」的第一與第三世代指紋相同，
  以它作鍵會把兩個世代的物件混為一談而在取回時拿到另一個世代的憑證。
- `idx_offsite_objects_due`＝**部分索引** `(origin, next_attempt_at, id) WHERE (state = 'pending')`——雙佇列取件。
- `idx_offsite_objects_lease`＝**部分索引** `(lease_until) WHERE (state = 'uploading')`——租約回收。
- `idx_offsite_objects_state`＝`(state)`——各態計數與失敗清單。

**設計說明**:
- **擁有表只留指標與快取**：`sessions`／`audit_export_jobs` 各加 `offsite_object_id` 與 `offsite_status`
  （見第 5、42 節）。所有決策邏輯只讀本表，快取只供列表與詳情頁免 join。
- 欄位刻意不帶 `gorm default` tag（沿 `AuditExportJob` 的既有取捨）：所有欄位由程式碼顯式賦值。

**不得作出的宣稱**（本節與引用本節的文件一律避免）:
1. **`sha256` 不是錄製當下的完整性證明**——它是**上傳當下**讀到的位元組的雜湊。本機檔在錄製到上傳
   之間的任何改動無從偵測（與審計檢查點鏈、會話錄影大小欄同一揭露）。
2. **不得宣稱遠端物件等於磁碟最終內容**——上傳後的複驗只能偵測「上傳期間變了」；圖形錄影的收尾尾段
   寫在量測之後，其長尾差額不在射程內。
3. **儲存端的分段校驗值與本欄的整檔 SHA-256 不可比**——大檔走分段上傳時，儲存端計算的是分段雜湊的
   組合值（用於驗證傳輸完整性），與整檔雜湊在數學上不同一個東西。對帳一律用本欄，不要拿儲存端的
   校驗欄位去比。
4. **只追蹤 key 的目前內容**——重傳即覆寫同 key。版本歷史的有無、累積與清理全由部署方的儲存桶
   versioning 與 lifecycle 設定承擔（`version_id` 只是參考性記錄），產品不列舉、不清理、不依賴。
   同 key 被外力覆寫時，產品的防護**只到拒絕交付**（雜湊不符即 `integrity_mismatch`）；能否救回原內容
   取決於部署方的 versioning 與保留設定。
5. **帳冊是現況，審計事件才是軌跡**——本表每列只保存目前狀態（狀態機是覆寫式的）；
   「什麼時候上傳的、什麼時候判定不符、什麼時候本機到期」的時序在保管鏈審計事件裡。
   反過來說，帳冊狀態是權威，審計列受審計佇列同樣的滿載降級與丟棄計數約束。

---

## 已知 model 與 baseline 差異（維護注意）

> 以下是 model 與 baseline 之間仍然成立的差異。

1. **GORM tag 只是文件，不再建立任何東西**。全部 46 張表由 baseline 的 `CREATE TABLE` 建出，
   `AutoMigrate` 已自產品程式碼移除（AST 守衛 `TestNoAutoMigrateInProductionCode` 釘住零命中）。
   **改 model 的欄位必須同步改 `baseline_schema_*.go`**——沒有任何東西會依 tag 補欄，
   缺欄的症狀要到執行期第一次查詢才以 `column does not exist` 出現在生產。
   守衛：`schema_parity_test.go`（離線第 1 層，欄位名雙向比對，不可被 skip）。
2. **partial unique index 在 model tag 上表達不出來**。`users.username`／`users.email`／
   `assets.name`／`asset_accounts` 兩條／`data_keys` 一條／`audit_failure_events` 一條等，
   實際約束皆為 partial（多數是 `WHERE deleted_at IS NULL`），而 model tag 只能寫
   `uniqueIndex` 或 `index`。**權威定義在 DDL（baseline 或增量 migration）**；8 條核心不變式（6 條 baseline＋2 條來自離機儲存增量 migration）另以
   `pg_get_indexdef` 逐字比對釘在 `baseline_parity_pg_test.go` 的 `baselineStructuralAssertions`。
3. **CHECK 約束同樣只由建表語句承載**（15 條：13 條 baseline＋2 條來自離機儲存增量 migration）。GORM 不產出 inline CHECK，故
   `chk_auth_target`／`chk_authz_subject_xor`／`chk_approver_scope_*`／`singleton = 1`／
   三個枚舉 CHECK 全部由建表語句承載。放寬任何一條，不合法的列就寫得進去而無錯誤。
4. **種子資料不在 schema 比對的射程內**。12 條內建告警規則由 `baseline_seed.go` 寫入；
   `pg_dump --schema-only` 的等價比對**完全看不到它們**，故其內容（尤其 `protocols` 分佈）
   須另行驗證，見 `assertBuiltinAlertRules`。

---

## 規劃中（尚未實作）

目前無。
