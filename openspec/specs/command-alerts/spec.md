# command-alerts

## Purpose

互動指令比對告警規則並記錄告警事件，供稽核查詢與通知派送。
## Requirements
### Requirement: Alert rule management
Admins SHALL manage alert rules (name, regex pattern, severity high/medium/low, enabled). Invalid regex MUST be rejected at save time. Default seed rules for common destructive commands SHALL ship with the migration.

#### Scenario: Invalid regex rejected
- **WHEN** an admin saves a rule with pattern "rm -rf ("
- **THEN** the API rejects it with a clear error

### Requirement: Command alert generation
Each captured command SHALL be matched against enabled rules; a match creates an alert linking rule, session, user, asset and the command text. Matching MUST NOT disrupt the session or command persistence.

#### Scenario: Dangerous command alerts
- **WHEN** a user executes "rm -rf /data" in an SSH session with the seed rules enabled
- **THEN** a high severity alert exists referencing that command and session

### Requirement: Alert retrieval and UI
Alerts SHALL be queryable (severity, user, asset, time range, pagination) under audit view permission, listed in an Alerts page with severity tags and session links; the dashboard SHALL show an alert count card.

#### Scenario: Alert list
- **WHEN** an auditor opens the Alerts page
- **THEN** alerts render newest-first with severity tags and links to session detail

### Requirement: 告警規則協議分流
告警規則 SHALL 具備適用協議（`protocols`，逗號分隔；空＝全協議）；告警比對 SHALL 僅以與當前會話協議相符的規則進行。shell 指令危險規則 SHALL 限定文字終端協議（ssh,k8s），SHALL NOT 套用於資料庫會話，以免 SQL 字面值（如 `SELECT 'rm -rf / test';`）誤觸 shell 規則。規則管理 API 與 UI SHALL 可設定 `protocols`，值 SHALL 限於具指令審計的文字終端協議集合（ssh/k8s/mysql/postgres/redis/**mssql**），未知值 SHALL 被拒絕。

#### Scenario: SQL 字面值不誤報 shell 規則
- **WHEN** 使用者在 mysql/postgres/mssql 會話執行 `SELECT 'rm -rf / test';`
- **THEN** 不觸發 shell 的「遞迴強制刪除」告警

#### Scenario: shell 規則對 ssh/k8s 仍有效
- **WHEN** 使用者在 ssh 或 k8s 會話執行 `rm -rf /tmp/x`
- **THEN** 仍觸發「遞迴強制刪除」告警

#### Scenario: 管理入口設定協議
- **WHEN** 以 API 或 UI 建立/更新規則並指定 `protocols` 為 `mysql,postgres`
- **THEN** 規則入庫且比對僅套用於該協議之會話；提交未知協議值（如 `rdp` 或 `foo`）被拒回 400

#### Scenario: mssql 為合法協議值
- **WHEN** 以 API 建立規則並指定 `protocols` 為 `mssql`
- **THEN** 規則入庫且僅套用於 mssql 會話

### Requirement: SQL 與 Redis 危險指令規則
系統 SHALL 內建協議限定的 DB 危險指令告警規則：SQL（DROP TABLE/DATABASE/SCHEMA、TRUNCATE、GRANT ALL）限 mysql,postgres,**mssql**；Redis（FLUSHALL/FLUSHDB）限 redis。

內建 SQL 規則的 `protocols` SHALL 於 schema baseline 中即為含 `mssql` 的終態值，SHALL NOT 依賴任何事後回填步驟——內建規則的內容由單一 baseline 定義，不存在「先種舊值、再以後續 migration 補上」的中間態。baseline 的種子內容 SHALL 為歷次演進疊加後的最終狀態；**漏帶最後一次協議擴充是本規則最不易察覺的失敗形態**：schema 層的等價比對看不到資料列，MSSQL 會話會完全不受 SQL 危險規則保護而使用者無從察覺，故種子內容 SHALL 另以資料層比對驗收。

#### Scenario: SQL DROP 觸發告警
- **WHEN** 使用者在 mysql 會話執行 `DROP TABLE x;`（含拆行送出）
- **THEN** 觸發「SQL 刪除資料表或資料庫」高嚴重度告警

#### Scenario: mssql 會話的 SQL 規則生效
- **WHEN** 使用者在 mssql 會話執行 `DROP TABLE x` 後送出 `GO`
- **THEN** 觸發同一則「SQL 刪除資料表或資料庫」告警

#### Scenario: 全新安裝的內建 SQL 規則出廠即含 mssql
- **WHEN** 全新安裝完成初始化後查詢內建 SQL 危險規則
- **THEN** 其 `protocols` 為 `mysql,postgres,mssql`，建立 mssql 會話即受該規則保護，不需任何額外步驟

### Requirement: 帳號新來源位址告警

系統 SHALL 維護每個帳號的已見來源位址基準（帳號 × 位址：首次見到、最近見到、首次建線時刻與取得首次建線資格的會話），並於帳號**首次自某位址建立協議會話**時產生一筆告警。判定 SHALL 以基準中該（帳號, 位址）尚無首次建線時刻為準；同一（帳號, 位址）之後再建線 SHALL NOT 重複告警。

**狀態與證據不可分離**：基準自「未見」轉為「已見（已建線）」與告警列的寫入 SHALL 在同一資料庫交易內完成；交易任一步失敗 SHALL 整筆回滾（基準不轉態、無告警列），使下一次自同位址建線仍能取得資格並產生告警，SHALL NOT 出現「基準已標已見而告警永不補發」的狀態。通知推送 SHALL 於交易提交之後才進行（沿既有落地面「入庫成功才推送」的順序）。同一（帳號, 位址）的並發首次建線 SHALL 只有一個會話取得首次資格（以條件更新與回傳值判定單一勝者），恰產生一筆告警，其餘會話 SHALL NOT 告警亦 SHALL NOT 吞掉勝者的告警。

告警 SHALL 走既有告警框架：來源類別為 `new_source_ip`（不掛任何告警規則，管理員 SHALL NOT 能以停用規則的方式關閉此訊號）、`rule_id` 為空、`rule_name` 與 `reason_code` 為機器碼、指令文字為空（本類無指令可指，SHALL NOT 填入推測文字）、綁該場會話與其使用者、資產，嚴重度為 medium。告警 SHALL 僅經唯一告警落地面寫入，並沿既有通知推送與審閱處置流程（可審閱、可標處置）。資料庫層對來源類別的值域約束 SHALL 同步擴充。

該位址 SHALL 由所屬會話承載（告警列不另存位址）；告警列表、通知 payload 與稽核調查時間軸呈現此類告警時 SHALL 帶出該會話的來源位址，通知 payload 的既有欄位 SHALL NOT 改動、新增欄位為可選。告警列表中此類告警的位址 SHALL 為深連結：一鍵以該位址為樞紐進入稽核調查工作台，時間窗為告警觸發當日、類別為全部，SHALL NOT 要求稽核員手動複製位址與重設條件。

**登入完成點的處理與邊界**：帳號自基準中不存在的位址完成 web 登入時，系統 SHALL 寫入一筆審計紀錄（動作 `new_source_ip`，含來源位址）並將該位址納入基準，兩者 SHALL 在同一交易內完成（失敗整筆回滾、下次登入再補），但 SHALL NOT 產生告警、SHALL NOT 推送通知——只登入而未建線的新位址不進告警頁；此邊界 SHALL 於規格與介面說明載明。基準的首次建線時刻 SHALL 獨立於登入而追蹤，使「先登入再建線」的典型流程仍於建線時觸發告警且只觸發一次。

**基準的生命週期**：基準 SHALL NOT 納入任何日誌保留政策的清除目標——清除會使舊位址回來時再被判為新。系統首次部署本能力時 SHALL 自既有會話歷史與登入成功紀錄回填基準，使部署當下已見的位址不觸發告警。基準 SHALL 表述為判定依據而非防篡改證據。本能力的資料庫變更以增量 migration 交付，其 Down 只還原結構、會刪除基準與此類告警列、僅供開發庫；生產回退唯一手段為還原升級前備份；Down 後再升級，基準為空、全部位址重新判為新。此邊界 SHALL 於營運文件載明，SHALL NOT 表述為可逆。

判定或基準寫入失敗 SHALL NOT 阻斷會話建立；失敗 SHALL 記錄於伺服端日誌。來源位址為空（來源無法解析而清單為空放行者）的會話 SHALL NOT 進入基準、SHALL NOT 告警，該會話於時間軸呈現為未知來源；此邊界 SHALL 載明。

同一裝置的 IPv6 臨時位址輪替會被視為不同位址（系統不做前綴聚合）；部署未宣告可信代理鏈時所有來源皆為代理位址。此兩點 SHALL 於文件載明。

#### Scenario: 首次自新位址建線觸發告警

- **WHEN** 使用者 X 首次自位址 203.0.113.5 建立 SSH 會話
- **THEN** 產生一筆來源類別為 `new_source_ip` 的 medium 告警，綁該會話、使用者與資產，告警推送至已啟用的通知通道，並出現於告警列表與稽核調查時間軸

#### Scenario: 同位址再現不重響

- **WHEN** 同一使用者其後自 203.0.113.5 再建立任何協議的會話
- **THEN** 不產生新的告警（實跑兩輪，第二輪告警數不變）

#### Scenario: 只登入不建線只留審計標記

- **WHEN** 使用者 X 自從未見過的位址完成 web 登入但未建立任何會話
- **THEN** audit_logs 新增一筆動作為 `new_source_ip`、含該位址的紀錄，告警表無新列、通知通道無推送

#### Scenario: 先登入再建線只響一次

- **WHEN** 使用者 X 自新位址登入後建立會話
- **THEN** 登入時留審計標記，建線時產生一筆告警；同一位址不因登入與建線各響一次

#### Scenario: 部署回填後既有位址不響

- **WHEN** 升級部署本能力後，使用者自其歷史會話曾使用過的位址建線
- **THEN** 不產生告警；自歷史中不存在的位址建線才產生

#### Scenario: 告警不可經規則停用

- **WHEN** 管理員停用或刪除全部告警規則
- **THEN** 新來源位址告警仍照常產生

#### Scenario: 列表與通知帶出位址

- **WHEN** 稽核員於告警列表檢視一筆新來源位址告警，或通知通道收到該告警
- **THEN** 皆可見該會話的來源位址；webhook payload 既有欄位不變

#### Scenario: 基準不受保留清除

- **WHEN** 日誌保留政策清除早於保留水位的操作日誌與指令紀錄
- **THEN** 已見位址基準不受影響，清除前已見的位址再現時仍不觸發告警

#### Scenario: 基準轉態與告警列不可分離

- **WHEN** 使用者 X 首次自新位址建線，而告警列寫入在交易內被注入失敗
- **THEN** 基準中該（帳號, 位址）仍無首次建線時刻、告警表無新列、通知通道無推送；同一使用者再自該位址建線時恰產生一筆告警

#### Scenario: 並發首連線只響一次

- **WHEN** 使用者 X 自同一新位址同時建立多場會話（各自的基準觀察並發執行）
- **THEN** 恰產生一筆告警，且該告警所綁的會話等於基準所記的首次建線會話；其餘會話不告警

#### Scenario: 告警位址一鍵進入位址樞紐

- **WHEN** 稽核員於告警列表點選一筆新來源位址告警的位址
- **THEN** 進入稽核調查工作台，樞紐為該位址、時間窗為告警觸發當日、類別為全部，無須再輸入

