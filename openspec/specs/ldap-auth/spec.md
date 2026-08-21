# ldap-auth

## Purpose

LDAP/AD 目錄服務的使用者認證與帳號同步：目錄設定以資料庫為事實源、由 admin 於身分管理 UI 維護（含連線測試與出站位址政策），登入時以單次解析快照完成傳輸風險判定與撥號。
## Requirements
### Requirement: LDAP authentication with shadow provisioning
When LDAP is enabled, a user not found locally (or flagged is_ldap) SHALL be authenticated against the directory via search-then-bind. On first successful login the system SHALL auto-create a shadow user (is_ldap=true, default user role, no local password usable).

#### Scenario: First LDAP login provisions shadow user
- **WHEN** a directory user logs in with correct credentials for the first time
- **THEN** authentication succeeds, a shadow user exists with is_ldap=true and the user role, and the audit log records source=ldap

#### Scenario: Wrong LDAP password rejected
- **WHEN** a directory user submits a wrong password
- **THEN** login fails with the same error shape as local failures and is audit-logged

### Requirement: Local authentication unaffected
Local (non-LDAP) users SHALL authenticate exactly as before regardless of LDAP being enabled or the directory being unreachable.

#### Scenario: Directory down
- **WHEN** the LDAP server is unreachable and a local user logs in
- **THEN** local login succeeds normally

### Requirement: LDAP users cannot use local password paths
LDAP users SHALL NOT be able to set or use a local password; password change endpoints reject is_ldap users.

#### Scenario: Password change rejected
- **WHEN** a password change is attempted for an is_ldap user
- **THEN** the request is rejected with a clear error

### Requirement: MFA compatibility
An is_ldap user with TOTP enabled SHALL go through the same two-phase login after successful directory authentication.

#### Scenario: LDAP + MFA
- **WHEN** an MFA-enabled LDAP user passes directory authentication
- **THEN** the response is mfa_required with a pending token, and TOTP verification issues the session JWT

### Requirement: LDAP directory settings stored in DB with admin management
LDAP 目錄設定 SHALL 儲存於資料庫 `ldap_directories` 表（帶 id 資料列），由 admin 於身分管理 UI 以 singleton 資源維護（GET／PUT upsert／DELETE，無集合式建立端點）。「至多一條 live 列」SHALL 由資料庫層保證且不依賴服務層計數——`CHECK (singleton = 1)` 與 partial unique index（`WHERE deleted_at IS NULL`）**兩者皆必要**（單靠 unique index 無法阻止不同 singleton 值並存）。資料表 SHALL 由 schema baseline 以無條件 DDL 建立，其 `CHECK (singleton = 1)` SHALL 與建表於同一段 DDL 產出；系統 SHALL NOT 存在任何可先行建出本表的 schema 自動遷移路徑——自動遷移不產出 CHECK 約束，其建出的表會使後續建表語句被略過而導致約束在生產缺席（此為已發生過的事故形態，非假想）。守衛測試 SHALL 斷言 baseline 產出的本表帶該 CHECK 約束，且產品程式碼不含任何 schema 自動遷移呼叫。seed 與所有寫入路徑 SHALL 共用交易範圍互斥（沿既有跨實例鎖機制但使用本功能專屬的鎖鍵，不與金鑰管理路徑共用鍵），一切判定（密碼沿用、端點比較、marker、表空）SHALL 於鎖內重讀；取不到鎖與 unique violation SHALL 轉為機器碼而非 500。bind 密碼 SHALL 信封加密儲存並登記於 envelope 遷移目標清單；任何讀取回應 SHALL 不含密碼明文，SHALL 回 `has_bind_password` 布林旗標。

`url` SHALL 僅接受 origin 形狀 `ldap[s]://host[:port]`——拒絕 userinfo、path、query、fragment、空 host 與超界 port，並設長度上限；比較、出站檢查與撥號 SHALL 共用同一份解析結果（避免 parser 差異使檢查對象與撥號對象不同）。更新時空密碼 SHALL 沿用既存值，但**既存列有密碼且 URL 的 canonical origin 改變**時 SHALL 拒絕空密碼沿用（須同時提供新密碼或顯式清除）；既存列無密碼時改 URL SHALL 正常存檔。同時提供非空密碼與 `clear_bind_password: true` SHALL 拒絕（400）。清除密碼與刪除設定 SHALL 於同一事務將 `bind_password_enc` 抹除，軟刪 tombstone 不保留可解密密文。設定的建立、更新、刪除與被拒絕的嘗試 SHALL 入審計（不記密碼）；**URL 變更 SHALL 記為高權重審計事件，含舊值與新值的 canonical origin 及 host 是否變更**，使「目錄何時被改指向」事後可查。

#### Scenario: 建立與讀取不洩漏密碼
- **WHEN** admin 以 PUT 建立 LDAP 目錄設定（含 bind 密碼）後讀取設定
- **THEN** 回應含全部設定欄位與 `has_bind_password: true`，不含密碼明文；資料庫中密碼為信封加密密文

#### Scenario: 空密碼沿用、顯式清除
- **WHEN** admin 更新設定（url 未變）時密碼欄留空
- **THEN** 既存密碼保持不變；僅當請求帶 `clear_bind_password: true` 時密碼被清空、`bind_password_enc` 被抹除且 `has_bind_password` 轉 false

#### Scenario: URL 變更時空密碼不得沿用
- **WHEN** 既存設定有 bind 密碼，admin PUT 將 url 改為另一位址且密碼欄留空、未帶清除旗標
- **THEN** 請求被拒（400 機器碼），既存設定與密碼不變——既存憑證不會被沿用到新位址

#### Scenario: 無既存密碼時改 URL 正常存檔
- **WHEN** 既存為無 bind 密碼的草稿，admin PUT 修正打錯的 url 且密碼欄留空
- **THEN** 存檔成功（無憑證可被沿用，不套重供規則）

#### Scenario: URL 變更入高權重審計
- **WHEN** admin 將既存設定的 url 由 A 改為 B（host 不同）
- **THEN** 審計出現 URL 變更事件，含舊值與新值的 canonical origin 與 host 變更標記

#### Scenario: 非法 URL 形狀被拒
- **WHEN** admin PUT `url=ldap://user:secret@dir.example/ou=x?scope`
- **THEN** 請求被拒（400 機器碼），憑證未進入儲存、審計或錯誤訊息

#### Scenario: DB 層拒絕第二條 live 列
- **WHEN** 以直接 SQL 對已有 live 列的資料表插入 `singleton=2` 的第二列
- **THEN** 資料庫拒絕該插入（CHECK 約束），服務層計數未參與判定

#### Scenario: 刪除後可重建且 tombstone 無密文
- **WHEN** admin 刪除設定（軟刪）後再以 PUT 建立新設定
- **THEN** 新設定建立成功（軟刪列不佔 singleton 約束）；軟刪列的 `bind_password_enc` 為空

### Requirement: Server-side validation for enabled directory settings
服務層 SHALL 對目錄設定做條件式驗證（前端必填驗證僅為 UX 提前提示，非權威）：`enabled=false`（草稿）僅驗有值欄位格式；`enabled=true` SHALL 要求 `url`（scheme 僅 ldap:// 或 ldaps://）、`bind_dn`、`base_dn`、`user_filter`、`attr_email`、`attr_fullname` 齊全且 `has_bind_password` 為真。`user_filter` SHALL 於存檔即驗證兩層——(1) 語法：`%s` 佔位恰出現一次、無其他格式化動詞、括號配對、可解析為 RFC 4515 filter；(2) 結構：placeholder 所在的等式斷言 SHALL 是每條可滿足路徑的必要條件，即 `%s` 節點的任一祖先 SHALL NOT 為 OR（`|`）或 NOT（`!`）——否則不含登入帳號的分支亦可命中而使搜尋結果與登入身分脫鉤。不合法即拒絕（400 機器碼），驗證不得僅存在於連線測試路徑。

#### Scenario: 啟用態缺欄位被拒
- **WHEN** admin PUT `enabled=true` 但 `base_dn` 為空
- **THEN** 請求被拒（400 機器碼指明缺欄），設定未寫入

#### Scenario: 壞 filter 存檔即拒
- **WHEN** admin PUT `user_filter=(objectClass=person)`（無 `%s` 佔位）
- **THEN** 存檔被拒（400 機器碼），不論 enabled 狀態；連線測試未被執行過亦然

#### Scenario: OR 繞過型 filter 被拒
- **WHEN** admin PUT `user_filter=(|(uid=%s)(uid=svc-admin))`（語法三規則皆通過）
- **THEN** 存檔被拒（400 機器碼）——placeholder 位於 OR 之下，非每條命中路徑的必要條件

#### Scenario: 合法 AD 複合 filter 通過
- **WHEN** admin PUT `user_filter=(&(objectClass=user)(sAMAccountName=%s))`
- **THEN** 存檔成功——AND 組合下 placeholder 為必要條件

#### Scenario: 草稿可不完整
- **WHEN** admin PUT `enabled=false` 且僅填 `url`
- **THEN** 存檔成功（草稿語義），讀取回 `enabled=false`

### Requirement: LDAP outbound address policy
LDAP 撥號（登入認證與連線測試兩路徑）SHALL 通過出站位址政策：位址落於 loopback、link-local（含雲端 metadata 位址）、unspecified 或 multicast SHALL 拒絕撥號；私有網段 SHALL 預設放行（目錄服務常態位置為內網，與 OIDC 的公網 IdP 前提相反）；loopback 例外 SHALL 僅經 `LDAP_ALLOWED_LOOPBACK_ENDPOINTS` 以 `host:port` 精確比對放行（不支援萬用字元），SHALL NOT 提供關閉檢查的開關。

**檢查對象 SHALL 即撥號對象**：判定 SHALL 發生於名稱解析之後、實際連線之前，並套用於每一個候選位址（多 A／AAAA 回應全數涵蓋）——「連線前先查一次 DNS 再撥號」的形態 SHALL NOT 採用，因檢查與連線之間的 DNS 變動即構成繞過；亦 SHALL NOT 以改寫 host 為 IP 的方式達成，該做法會破壞 ldaps 的憑證主機名驗證。

#### Scenario: 測試端點拒絕 loopback 目標
- **WHEN** admin 對連線測試送 `url=ldap://127.0.0.1:5432`
- **THEN** 撥號階段被拒（出站政策機器碼），未發生實際連線；事件入審計

#### Scenario: 登入路徑同樣受政策約束
- **WHEN** 既存啟用設定的 url 主機名解析至 loopback 位址，LDAP 使用者登入
- **THEN** 撥號被拒、登入失敗（憑證錯誤語義），內部事件可辨識為出站政策拒絕

#### Scenario: 解析後改變的位址仍被攔截
- **WHEN** 目標主機名於名稱解析回應中包含一個公網位址與一個 metadata 位址
- **THEN** 連往 metadata 位址的嘗試被拒；實際建立的連線只可能是通過檢查的位址

#### Scenario: ldaps 憑證驗證不因政策而弱化
- **WHEN** 設定為 `ldaps://` 的目錄通過出站政策並完成撥號
- **THEN** TLS 憑證仍以 URL 的主機名驗證（未因位址檢查而改以 IP 驗證或跳過驗證）

#### Scenario: 私網目錄正常放行
- **WHEN** 目錄設定 url 指向私有網段位址（如 docker 網路內的目錄服務），LDAP 使用者登入
- **THEN** 撥號正常進行，登入行為不受出站政策影響

### Requirement: LDAP connection test against unsaved form values
系統 SHALL 提供 LDAP 連線測試端點（admin-only），以請求中的表單當下值執行分階段測試：出站政策＋撥號 → service bind → 以 `user_filter` 對 `base_dn` 搜尋（`%s` 以未轉義萬用字元展開——此為唯一不經 EscapeFilter 的例外，登入路徑不受影響；SizeLimit 上限 1000）→ 回報比對到的使用者數（達上限時標示「至少 N 筆」）與屬性映射抽樣。bind 之後各階段失敗 SHALL 回專屬機器碼；撥號失敗 SHALL 僅回單一「無法連線」碼、不細分失敗原因（降低內網探測 oracle 精度）。失敗回應 SHALL 附 `diagnostic_id`——一個不透明的關聯識別碼，其值 SHALL 於回應、審計事件與伺服端 operational log 三者一致；失敗的粗分類原因（DNS／逾時／拒絕／TLS）SHALL 僅寫入 operational log，SHALL NOT 出現於 API 回應或 admin 可見的審計欄位。測試請求密碼為空時，SHALL 僅在請求 URL 與既存列的 canonical origin 相等、既存列有密碼、且請求未帶 `clear_bind_password` 時代入既存密碼，否則以空密碼測試。測試路徑 SHALL 受傳輸政策約束（與存檔閘同一判定語義與請求欄名）：strict 檔位下含傳輸風險的測試 SHALL 拒絕執行；warn 檔位下 SHALL 於缺確認旗標時拒絕、帶確認旗標時放行並留痕——不得成為「strict 政策下仍以明文送出 bind 密碼」的旁路。此判定 SHALL NOT 受請求的 `enabled` 值限縮（測試當下即撥號送出憑證，與存檔閘「停用者不撥號」的前提不同）。端點 SHALL 設 per-actor 與 per-target 速率限制、全域併發上限與欄位長度上限，逾時 SHALL 主動關閉連線。測試成功與失敗 SHALL 皆入審計（actor、canonical 目標、失敗階段、diagnostic id、是否沿用既存密碼；不記密碼與 socket 細節）。

#### Scenario: 成功測試回報比對筆數
- **WHEN** admin 以正確的未儲存表單值執行連線測試
- **THEN** 回應逐階段成功並含比對到的使用者數（matched_count）

#### Scenario: 分階段錯誤定位（bind 之後）
- **WHEN** admin 以錯誤的 bind 密碼執行連線測試
- **THEN** 回應指出失敗於 service bind 階段（專屬機器碼），撥號階段標示成功

#### Scenario: 改 URL 後留空密碼不代入既存憑證
- **WHEN** 既存設定有 bind 密碼，admin 在測試請求中將 url 改為另一台伺服器並留空密碼
- **THEN** 撥號層可觀察到既存密碼未被送出（測試以空密碼執行）——斷言對象為送出內容本身，不依賴遠端回應（部分目錄將空密碼視為匿名 bind 而回成功）

#### Scenario: 勾選清除密碼後測試不沿用
- **WHEN** admin 勾選 `clear_bind_password` 但尚未存檔即執行連線測試，URL 未變
- **THEN** 測試以空密碼執行，不沿用即將被清除的既存密碼

#### Scenario: strict 檔位拒絕不安全測試
- **WHEN** LDAP 通道政策為 strict，admin 對 `ldap://`（明文）目標執行連線測試
- **THEN** 測試被拒（傳輸閘機器碼），bind 密碼未送出

#### Scenario: 關閉啟用開關不能繞過測試閘
- **WHEN** LDAP 通道政策為 strict，admin 將表單 `enabled` 設為 false 後對 `ldap://` 目標執行連線測試
- **THEN** 測試仍被拒——測試閘不因 `enabled=false` 而放行

#### Scenario: 測試失敗入審計
- **WHEN** admin 執行連線測試且 bind 失敗
- **THEN** 審計出現測試事件（含失敗階段、目標與 diagnostic id，無密碼）

### Requirement: One-time env seed via post-unseal migration
seed（讀 env→信封加密→插列）SHALL 登記於 post-unseal migration 佇列執行（加密所需 codec 於段 2 才可用；封印模式段 1 無金鑰材料），SHALL NOT 於段 1 versioned migration 執行——段 1 僅建表。seed SHALL 自帶執行 marker，marker 語義為**「已完成評估」而非「已建立資料」**：實際 seed、因 env 未啟用而跳過、因表非空而跳過三種終局結果 SHALL 皆寫入 marker；僅基礎設施失敗（DB 錯誤、加密失敗）SHALL NOT 寫入，留待下次啟動重試。判定順序 SHALL 為：資料表不存在則直接無作用返回（不記失敗、不寫 marker）→ `LDAP_ENABLED` 未啟用則寫 marker 返回 → marker 已寫則返回 → 表非空（含軟刪列）則寫 marker 返回 → 執行 seed 並於同事務寫 marker。marker 寫入 SHALL 為冪等（重複寫入不得因主鍵衝突而失敗）——判定順序使 env 未啟用的分支先於 marker 檢查，非冪等寫入會在第二次啟動時撞重複鍵。env 解析語義 SHALL 與既有 config 讀取完全同源（布林接受 `1`／`true` 等 `ParseBool` 形式、空值取預設），不得改用字串相等判定。seed SHALL 沿用與現行 config 相同的預設值（`user_filter` 預設 `(uid=%s)`、`attr_email` 預設 `mail`、`attr_fullname` 預設 `cn`），使最小 env 集合 seed 出可用設定。seed 事件（含來源標記與傳輸風險項）SHALL 入審計；seed 失敗 SHALL 記錄且 marker 不寫（下次啟動重試），SHALL NOT 靜默吞沒。seed 為遷移例外不經存檔閘；登入當下的傳輸閘仍為最終權威。marker 已寫或表非空時 env SHALL 不參與任何執行期判定。

#### Scenario: 既有部署無感升級
- **WHEN** 既有部署（env `LDAP_ENABLED=true` 且設定齊全）升級至本版本並完成啟動（含解封）
- **THEN** env 值入庫為一列啟用設定，LDAP 使用者登入行為與升級前一致

#### Scenario: 全新部署不誤 seed
- **WHEN** 全新部署以出廠範本（`LDAP_ENABLED=false`、`LDAP_URL` 有 dev 靶機值）啟動
- **THEN** 不 seed，`ldap_directories` 維持空表，身分管理頁顯示未設定

#### Scenario: 顯式刪除後硬刪列亦不回灌
- **WHEN** admin 刪除設定後，維運將軟刪列自資料庫硬刪，服務重啟且 env 仍為 `LDAP_ENABLED=true`
- **THEN** 因 marker 已寫，不重新 seed，LDAP 維持未設定狀態

#### Scenario: UI 自行建立的設定被硬刪後亦不回灌
- **WHEN** 部署首啟時 env 未啟用（marker 於該次寫入），admin 事後以 UI 建立設定、該列日後被硬刪，服務重啟且 env 為 `LDAP_ENABLED=true`
- **THEN** 不 seed——marker 記錄的是「評估已完成」，不因資料列由 UI 而非 seed 建立而失效

#### Scenario: 布林 env 的非 true 字面值仍被正確識別
- **WHEN** 既有部署 `.env` 設 `LDAP_ENABLED=1` 且設定齊全，升級後啟動
- **THEN** seed 判定為已啟用並正常入庫，LDAP 登入行為與升級前一致

#### Scenario: 最小 env 集合 seed 出可用設定
- **WHEN** env 僅設 `LDAP_ENABLED/LDAP_URL/LDAP_BIND_DN/LDAP_BIND_PASSWORD/LDAP_BASE_DN` 五鍵時 seed 執行
- **THEN** seed 出的列 `user_filter=(uid=%s)`、`attr_email=mail`、`attr_fullname=cn`，LDAP 登入可用

### Requirement: Runtime settings resolution as single per-login snapshot
LDAP 認證路徑 SHALL 於每次登入嘗試單次解析現行設定（一次 DB 讀取＋解密），傳輸風險判定與實際撥號 SHALL 共用同一次解析結果——閘檢查的參數即撥號使用的參數，設定並發變更不產生「檢查新值、撥號舊值」窗口。設定變更 SHALL 即時生效（無需重啟）。

解析結果 SHALL 區分三態：無啟用列（功能未啟用，登入流程與 LDAP 未啟用語義一致）；有效；解析失敗（DB 錯誤、密文解密失敗）SHALL fail-close 拒絕該次登入，對外收斂為憑證錯誤、對內記可辨識的 log 與審計事件，SHALL NOT 偽裝為「未啟用」。**傳輸清冊等非撥號消費端的設定視圖 SHALL 同樣區分三態**——故障 SHALL 以明確狀態碼呈現，SHALL NOT 顯示為「未啟用」（否則金鑰事故時清冊與設定頁互相矛盾並指向錯誤排錯方向）。供非撥號消費端使用的設定視圖 SHALL NOT 包含 bind 密碼明文（風險判定僅需啟用狀態、URL 與憑證驗證旗標）。

多於一條 live 列時（資料庫層約束缺席的環境）解析 SHALL 有確定性行為（取 id 最小者），不得行為未定。

#### Scenario: 設定變更即時生效
- **WHEN** admin 於 UI 修正 base DN 後（不重啟服務）LDAP 使用者登入
- **THEN** 登入以新 base DN 對目錄搜尋並成功

#### Scenario: 停用即時生效
- **WHEN** admin 於 UI 將設定停用後 LDAP 使用者嘗試登入
- **THEN** 登入失敗（憑證錯誤語義），本地帳號登入不受影響

#### Scenario: 閘與撥號同一 snapshot
- **WHEN** strict 檔位下，某次 LDAP 登入進行中 admin 將 url 由 ldaps:// 改為 ldap://
- **THEN** 該次登入的風險判定與撥號使用同一份解析當下的設定（要嘛都是舊值、要嘛都是新值），不存在「閘按安全設定放行、撥號用不安全設定送出密碼」的交錯

#### Scenario: 解密失敗 fail-close 且可辨識
- **WHEN** `bind_password_enc` 因金鑰事故無法解密，LDAP 使用者登入
- **THEN** 登入被拒（對外憑證錯誤語義）；內部 log 與審計事件可辨識為解析失敗而非帳密錯誤；本地帳號登入不受影響

#### Scenario: 故障態在清冊不顯示為未啟用
- **WHEN** 設定讀取或解密失敗時 admin 開啟傳輸安全頁
- **THEN** LDAP 列顯示「設定讀取失敗」狀態（機器碼），非「未啟用」——與設定頁顯示的「已啟用」不矛盾

