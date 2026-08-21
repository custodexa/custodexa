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

