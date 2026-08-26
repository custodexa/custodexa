# 審計產生點 manifest

> **這份表是什麼**：`backend/` 全樹每一個「會產生一筆 `audit_logs` 資料列」的程式碼位置，
> 逐點登記它的交易歸屬、審計寫入失敗時的處置，以及目標 sink 變體。
> 表內數字的量測基準日為 2026-08-09，其後隨程式碼變動逐列維護。
>
> **怎麼用**：想知道某一筆審計列從哪寫出、寫失敗會不會連帶回滾業務操作，
> 用 §2 總表的 `file:line` 反查；新增或搬動審計寫入點時，照 §4 的維護紀律補列或更新。
>
> **它不是平行維護的文件**：表內每一列都由守衛測試雙向釘住——
> `backend/cmd/server/audit_points_manifest_guard_test.go`（雙向完備性）與
> `backend/cmd/server/audit_points_tx_attribution_guard_test.go`（交易歸屬的機器驗證，見 §1.4）。
> 現實中多一個未登記的產生點、或表內某列在現實中已不存在，測試即紅。
>
> 表內每一列都經人工開檔複核：實際讀過該行與其外圍函式，確認寫入形態、是否吃呼叫方 `tx`、
> 以及呼叫方對審計寫入失敗的處置（回滾或只記 log）。

## 1. 範圍與判準

### 1.1 「審計產生點」的定義

**產生一筆 `audit_logs` 資料列的程式碼位置。** 機械判準（守衛測試的現實側掃描規則，AST 精確比對而非字串 grep）：

1. `model.AuditLog{...}` 複合字面量（在 `internal/model` 包內為 `AuditLog{...}`），**且至少帶一個欄位**——
   空字面量 `&model.AuditLog{}` 是 GORM 的型別標記（`Model()`／`AutoMigrate`），不產生列。
2. `audit.AuditLogEntry{...}` 複合字面量（在 `internal/modules/audit` 包內為 `AuditLogEntry{...}`），同樣要求至少一欄位。
3. 呼叫 `model.RecordAssetChange` ／ `model.RecordAssetNodeChange` ／ `model.RecordAssetAccountChange`
   ——這三個 exported 函式**不是 GORM hook**，由 service 層顯式呼叫並吃呼叫方的 `tx`，是編譯器與型別引數守衛都看不見的寫入面。
4. `port.AuditEvent{...}` ／ `gatewayapi.AuditEvent{...}` 複合字面量（**收口後的形態**），同樣要求至少一欄位。
   兩個型別名指向同一個型別（`port.AuditEvent` 是別名），寫法依該檔 import 而定，兩者都認。

掃描範圍＝`backend/` module 全樹的**非測試** `.go` 檔（現況 300+ 檔），排除 `vendor`／`testdata`／`.git` 等。

### 1.2 明載的範圍缺口（不在本表、亦不在守衛斷言內）

| 缺口 | 內容 | 為何排除 |
|---|---|---|
| 非 INSERT 的 `audit_logs` 存取 | `retention_service.go:43-52` 保留期硬刪（原生 SQL，`BeforeDelete` 守衛唯一放行路徑）；`migrations.go:673-694,711` 的 DDL／回填 | 不產生列，且無 sink 分派問題。列此以免誤以為守衛涵蓋全部 `audit_logs` 存取 |
| 非 DB 落地的降級路徑 | `audit_log_service.go:150/161/194→252` `writeToFile`（JSONL）、`:153` 直接丟棄 | 是 AsyncSink 實作的內部策略，不是獨立產生點 |
| 唯讀存取 | `key_manager_cleanup.go:231`、`daily_review_service.go:76/89`、`audit_integrity_service.go:55/198`、`audit_log_service.go:298` | 讀，非寫 |
| 其他審計性資料表 | `command_alerts`／`session_commands`／`clipboard_events`／`audit_failure_events`／`daily_review_logs`／`integrity_baselines` | 不寫 `audit_logs`；`command_alerts` 的收口由 `AlertSink` 另案處理 |

### 1.3 欄位語義

- **呼叫方交易內**：`是`＝該寫入使用呼叫方傳入的 `tx *gorm.DB`（或位於呼叫方 `Transaction` 閉包內），業務操作回滾時審計列一併回滾；`否`＝使用 `s.db`／`repository.DB` 全域連線，與呼叫方交易無關；`自開交易`＝自己開一個交易。
- **fail-close?**：呼叫方對審計寫入失敗的處置。`是`＝回 error 使業務操作回滾；`否`＝只記 log／無回傳值。
  **這一欄是本 manifest 存在的理由**——fail-close 的點若被分派成 AsyncSink，回滾語義會靜默退化為 fail-open，
  而且**測試會更綠**（原本會失敗的路徑變成永遠成功），編譯器與既有測試皆零保護。
- **目標變體**：`TxSink`（audit 模組 internal port，`WriteInTx(tx *gorm.DB, ev AuditEvent) error`，同步回 error、參與呼叫方交易）／`AsyncSink`（`pkg/gatewayapi`，fire-and-forget，at-most-once）／`維持 hook`（GORM hook 直寫不改）／`不進 sink`（audit 模組內部落地入口，本身就是 sink 的實作側）。
- **落地階段**：該點的 sink 收口由哪一個工程階段（`W1`…`W10`）承擔。TxSink 點**必須**有值——
  沒有階段認領的收口點會靜默停在舊形態，`TestTxSinkPointsAllHaveLandingWave` 檢查此欄（見 §3.2）。
- **分派規則（硬性）**：**凡「呼叫方交易內＝是」者一律 `TxSink`**，不論該呼叫方目前是否 fail-close——
  因為只要寫入吃的是 `tx`，它就需要 `*gorm.DB` 參數，AsyncSink 的簽名表達不了。fail-close 與否只影響呼叫方
  對回傳 error 的處置，不影響變體選擇。

### 1.4 「呼叫方交易內」欄的機器驗證

**修補前的缺口**：本欄原為純人工註記，兩個守衛皆不與現實比對——雙向完備性只驗 `file:line` 與種類，
變體不變式只在本欄＝`是` 時才斷言。實測把 AP-51 一列**同時**翻成 `否｜否｜AsyncSink`，
兩個守衛雙雙 PASS，fail-close 就此靜默退化為 fail-open。

**修補**：`TestAuditPointTxAttributionMatchesCode`（`backend/cmd/server/audit_points_tx_attribution_guard_test.go`
＋判定器 `audit_points_tx_dataflow_test.go`／`audit_points_tx_resolve_test.go`）以**資料流（def-use）**判定每個產生點的交易歸屬，與本欄
**雙向**比對——機器判為交易內而本欄標 `否` 會紅，機器判為非交易內而本欄標 `是` 也會紅。

**判定原則＝保守格序（不是涵蓋率）**。第一版判定是「任一層包覆函式帶 `*gorm.DB` 參數 ⇒ `TxBound`」，
只證明句柄**可見**、不證明寫入**用了它**；反方向更危險——tx 若存於 struct 欄位、context、
`Begin()` 後被閉包捕獲等非參數形態，一律會被判成 `NotTxBound`，manifest 同步翻成「否＋AsyncSink」即可全綠。
**誤判不對稱**：誤判 `TxBound` ⇒ 多一次同步寫入；誤判 `NotTxBound` ⇒ fail-close 退化為 fail-open
且測試更綠。故 `NotTxBound` 改為**只在正面可證時才給**，其餘一律 `Indeterminate`。

**判定流程（以單一寫入 call 為中心）**：

1. 找**落地寫入**：`model.AuditLog` 字面量追它的 carrier（字面量本身或它初始化的區域變數）在最內層
   作用域的使用點，**恰好一個 GORM 寫入呼叫**才算找到；被 `return`／送進 channel／包進其他字面量／
   有多個候選一律 `Indeterminate`。`RecordCall` 取呼叫第一引數。`AuditLogEntry` 走型別層規則。
2. **一跳（hop ≤ 1）**：carrier 若恰好交給同包的一個函式／方法，追進去對應參數再判一次（AP-58／59 即此形態）。
   跨包、介面派發、可變參數 ⇒ `unresolved-callee`。
3. 走該寫入 call 的 **receiver 鏈**到根運算式。

| 機器判定 | 可證的來源 | 理由類別 | 對應本欄 |
|---|---|---|---|
| `TxBound` | receiver 根＝某層包覆函式的 `*gorm.DB` 參數（含 `Transaction` 閉包參數） | `tx-param` | `是` |
| `Detached` | **該次寫入 call 自身**的 receiver 鏈帶 `Session(&gorm.Session{NewDB: true})` | `detached-session` | `否`（AP-23／24／25） |
| `NotTxBound` | receiver 根＝跨包／本包的包級句柄（`repository.DB`） | `root-handle` | `否` |
| `NotTxBound` | receiver 根＝struct 欄位（`s.db`），**且全域 tx 逃逸不變式成立** | `struct-field` | `否` |
| `NotTxBound` | `AuditLogEntry` 型別層：型別不帶 DB 句柄，且無任何落地面同時吃 entry 與 `*gorm.DB` | `entry-type-level` | `否` |
| `Indeterminate` | 以上皆證不到（逸出作用域／多落地候選／找不到寫入／轉手不可解／來源不可追／`Begin()` 自開交易／tx 逃逸／entry 落地面不安全） | `escapes-scope`／`multi-consumer`／`no-write`／`unresolved-callee`／`unresolved-root`／`self-begin`／`tx-escape`／`entry-landing-unsafe` | 須列入機器不可判定清單，**且不得標 AsyncSink** |

**三條硬不變式**（守衛失守的判準）：

- **I1 雙向比對**：機器判 `TxBound` 而本欄標「否」→ 紅；反之亦然。
- **I2 `Indeterminate` 不得標 `AsyncSink`**（本次修補的核心指標）。機器證不出「不在交易內」的列若被
  fire-and-forget 化，就是把未知當成安全。**機器不可判定允許清單不豁免這一條**——豁免只證明有人看過，
  不足以支撐把未知寫入丟進 at-most-once 通道。保守出路是走 `TxSink`（最壞只多一次同步寫入）。
- **I3 豁免不得濫發**：`isMU ⇒ 機器 verdict == Indeterminate`（判得出來的列不得進豁免）；豁免須綁定
  **檔／最內層函式／機器給出的理由類別**三段指紋，任一不符即紅；條數受 `maxTxMachineUndeterminable = 3`
  節制，要新增豁免必須在 PR diff 裡把這個數字調高。

**tx 逃逸不變式（把盲區 B1 從「靜默」變成「機器可見」）**：`struct-field` 這個來源之所以算「可證非交易內」，
前提是沒有人把交易句柄塞進 struct 欄位／包級變數／`context`。守衛掃全模組驗這個前提（含「傳給一個會把
`*gorm.DB` 參數存起來的函式」這條轉手路徑）；一旦命中，**所有 `struct-field` 與 `entry-type-level` 結論
同時降為 `Indeterminate`**，經 I2 整批轉紅。現況逃逸 **0 筆**。

**量測當時（2026-08-09）的機器判定結果**：`TxBound` **19**（與當時本表的 19 列 `是` 逐點吻合）／
`Detached` **3**／`NotTxBound` **35**／`Indeterminate` **3**；**57 列**進入雙向比對（60 − 3 豁免）；
tx 逃逸 0 筆。此組數字隨產生點增減而變動，現值以守衛執行輸出為準。

**明載的殘餘邊界（不假裝涵蓋）**：

| 邊界 | 內容 | 處置 |
|---|---|---|
| B1 | tx 存於 struct 欄位／context／`Begin()` 捕獲等非參數形態 | **已由 tx 逃逸不變式機器化**：命中即整批降 `Indeterminate` 並經 I2 轉紅。判定器另有合成原始碼自檢 `TestTxVerdictLatticeIsConservative`，逐形態斷言「不得被判成 `NotTxBound`」 |
| B2 | `TxBound` 只證明這次寫入吃了某個 `*gorm.DB` 參數，不證明**每一條呼叫路徑**都在交易內 | AP-50 即路徑二分，以守衛內 `auditPointTxHumanQualified` 登記＋本表括號註記＋人工複核標記為權威（守衛另斷言該清單只能用在機器實判 `TxBound` 的列） |
| B3 | 同函式混有「附著」與「脫離」兩種寫入 | **已消解**：`Detached` 改以該次寫入 call 自身的 receiver 鏈判定，不再看「作用域內某處出現過 `NewDB` 字面量」，故不存在互相覆蓋 |
| B4 | 一跳以上的間接（A→B→C 才落地）、介面派發的落地、反射／生成碼／原生 SQL 寫入 | 前兩者落 `Indeterminate` 並受 I2 節制；後者連產生點掃描都看不見，其正解是執行期的 fault-injection backstop（測試位置見 §4 的落地階段表），不是更多 AST |

**機器不可判定列（3 列）**：AP-43（`multi-consumer`）、AP-56／AP-57（`escapes-scope`）。三列的目標變體皆為
`不進 sink`，滿足 I2。本表交易欄以 `（機器不可判定）` 標記，末欄附 `[人工複核 YYYY-MM-DD]`；守衛以
`auditPointTxMachineUndeterminable` 三段指紋雙向釘住——**只改本表標記而不改守衛程式碼，守衛會紅**。
（AP-58／AP-59 原列為不可判定，一跳判定上線後已可正面證明為 `struct-field`，2026-08-09 移出豁免。）

---

## 2. 產生點總表（77 點）

> ID 依「檔路徑升冪、行號升冪」編號，**編號一經指派不得變動**——它是本表對外的引用把手。
> `種類` 欄對應 §1.1 的判準：`AuditLog`／`AuditLogEntry`／`AuditEvent`／`RecordCall`。
>
> `file:line` 是給人讀的定位，會隨上游程式碼增減而漂移；守衛比對的就是這一欄，
> 故漂移時逐列重新量測即可，**不得以放寬守衛判準的方式讓它轉綠**。備註欄內的次要行號
> 參照不受守衛比對，更新主欄時要一併核對。

| ID | 產生點 file:line | 種類 | 呼叫方交易內 | fail-close? | 目標變體 | 落地階段 | 對應測試 | 判定證據／備註 |
|---|---|---|---|---|---|---|---|---|
| AP-01 | `cmd/server/sealwire.go:392` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `cmd/server/seal_integration_test.go:182` | `writeSealAudit`（`:367`）走 `auditService.Log`，`Log` 無回傳值。行號因 single-instance-guard 於 `newWiredSealHandler` 加入守衛探針注入（`:165`）而下移 2 行，程式碼未變 |
| AP-02 | `cmd/server/stage2.go:1038` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `logKEKSwitchAudit`（`:1005`），KEK 切換補記；行號因 workbench-clipboard-and-layout B2 於上方新增匯出服務組裝與打包 worker 而下移，程式碼未變；single-instance-guard 於 `mark("auditService")` 後注入守衛事件 sink（`:438`）再下移 4 行，程式碼未變 |
| AP-03 | `internal/api/access_review_handler.go:103` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `Create`（`:83`）內事後審計 |
| AP-04 | `internal/api/asset_handler.go:747` | AuditEvent | 否 | 否 | AsyncSink | W4（4.6 等價檢查項） | 待補 | `auditK8sFile`（`:737`）`repository.DB.Create`，**error 完全未檢查**。現況**不受** `AuditLogEnabled` 管制 → 改走 AsyncSink 時須繞過該分支，行為零變更 |
| AP-05 | `internal/api/audit_export_handler.go:326` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `auditExport`（`:322`）；行號因 workbench-clipboard-and-layout B2 於上方加入同步 bundle 拒絕與 jobs 路由而下移，程式碼未變 |
| AP-06 | `internal/api/auth_handler.go:365` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/auth_audit_source_and_provider_test.go` | `auditPasswordNoncompliant`（`:160`）。**行號因 audit-coverage-closure 於檔頭新增 `trustProxy` 欄位與 `auditSourceIP` 而下移**，產生點未變；`ClientIP` 改由 `h.auditSourceIP(c)` 取（不採信轉送標頭） |
| AP-07 | `internal/api/auth_handler.go:384` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/auth_audit_source_and_provider_test.go` | `auditLogin`（`:181`）。同 AP-06：行號因同一次檔頭改動下移，`ClientIP` 改取連線對端 |
| AP-08 | `internal/api/auth_handler.go:507` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/refresh_rotation_audit_test.go` | `auditRefreshEvent`（`:291`）——刷新事件的**單一寫入點**。原僅承接失敗（`auditRefresh` 現為其薄包覆），audit-coverage-closure 起同時承接成功輪替（`Refresh` 的 `:256` 呼叫，`status=success`／`errMsg=refresh_rotated`）。兩者共用同一字面量是刻意的：分成兩份就會有兩處各自演化的欄位集，而「成功列少填來源位址」不會讓任何測試轉紅 |
| AP-09 | `internal/api/auth_handler.go:740` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `auditPasswordChange`（`:488`）。**行號因 audit-coverage-closure 先於上方新增 refresh 成功留痕、再於檔頭新增 `auditSourceIP` 而兩度下移**，產生點與程式碼皆未變 |
| AP-10 | `internal/api/auth_mfa_handler.go:388` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/auth_audit_source_and_provider_test.go` | 產生點自 `auditAuthEventWithResource` 下沉為 `auditAuthEventFull`（`:310`，落地在 `:328` `Log(entry)`），前者變成薄包覆——**本檔審計列仍只有這一個字面量**，audit-coverage-closure 2.9 只是替它加上 `Details` 參數（MFA 完成路徑的 provider 標註）。與 AP-06 相同：`ClientIP` 改取連線對端 |
| AP-11 | `internal/api/command_alert_handler.go:134` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `Review`（`:100`） |
| AP-12 | `internal/api/key_management_handler.go:473` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/key_rewrap_audit_regression_test.go:60` | `CleanupRetired`（`:442`） |
| AP-13 | `internal/api/security_policy_handler.go:124` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `auditPolicyChange`（`:113`） |
| AP-14 | `internal/api/sftp_handler.go:405` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `audit`（`:402`），SFTP 成功路徑留痕 |
| AP-15 | `internal/api/syslog_setting_handler.go:151` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `Update`（`:111`） |
| AP-16 | `internal/api/syslog_setting_handler.go:177` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | 同上函式第二處 |
| AP-17 | `internal/api/syslog_setting_handler.go:229` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `Test`（`:187`） |
| AP-18 | `internal/api/transmission_inventory_handler.go:37` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `audit`（`:28`） |
| AP-19 | `internal/api/user_handler.go:472` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `Unlock`（`:426`） |
| AP-20 | `internal/api/user_handler.go:520` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | handler `SetInactivityExempt`（`:466`） |
| AP-21 | `internal/middleware/audit_log.go:226` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/api/key_rewrap_audit_regression_test.go:60` | HTTP 中介層批次（全部帶認證的請求），落地 `:245` `auditService.Log(entry)`。**產生點與程式碼皆未變，行號因同函式上方的查詢摘要分支反覆擴寫而下移**：audit-coverage-closure 於檔頭補入中介層選項與 `:52` 起的匿名拒絕分支，再淨增 46 行（前次 `:179`／落地 `:199`）；a76b7a8 於 `:118` 起淨增 26 行（query 值改走 `MaskCredentialQuery`＋剪貼簿補記 `session_id`；原 `:148`／落地 `:168`），audit-resource-classification-closure 再淨增 5 行（會話內取證的範圍鍵取材自剪貼簿單支 `if` 改為涵蓋 recording／command 的 `switch`；前次 `:174`／落地 `:194`）。更早一次登記寫成 `:161`／`:181` 只算進了剪貼簿分支、漏算遮蔽段，已一併訂正。歷次皆僅重新錨定，產生點未增減 |
| AP-22 | `internal/modules/asset/asset_audit_events.go:68` | AuditEvent | 是 | 是 | TxSink | W6（6.2） | `internal/modules/asset/asset_account_service_test.go:327` | `RecordAssetAccountChange(tx …)`（`:78`）函式體，`:105` `tx.Create` 回 error。T-2 的落地側，收口時下沉為 audit 模組內部 |
| AP-23 | `internal/model/asset_audit.go:140` | AuditLog | **否** | 是 | **維持 hook** | W4（4.5） | 待補 | `(*Asset).AfterCreate`（`:133`）。`:149` `tx.Session(&gorm.Session{NewDB:true}).Create` ——**獨立 session、脫離呼叫方交易**。刻意不改走 sink（改走需 `internal/model` 持包級全域 sink＝再造一個可漏接的 nil no-op 全域旗標，見 `model/audit_log.go:164-183`） |
| AP-24 | `internal/model/asset_audit.go:170` | AuditLog | **否** | 是 | **維持 hook** | W4（4.5） | 待補 | `(*Asset).AfterUpdate`（`:159`），同 AP-23 |
| AP-25 | `internal/model/asset_audit.go:189` | AuditLog | **否** | 是 | **維持 hook** | W4（4.5） | 待補 | `(*Asset).AfterDelete`（`:186`），同 AP-23 |
| AP-26 | `internal/modules/asset/asset_audit_events.go:108` | AuditEvent | 是 | 是 | TxSink | W6（6.2） | 待補 | `RecordAssetChange(tx …)`（`:197`）函式體，`:227` `tx.Create` 回 error |
| AP-27 | `internal/modules/asset/asset_audit_events.go:136` | AuditEvent | 是 | 是 | TxSink | W6（6.2） | 待補 | `RecordAssetNodeChange(tx …)`（`:232`）函式體，`:253` `tx.Create` 回 error |
| AP-28 | `internal/proxy/file_tap.go:272` | AuditEvent | 否 | 否 | AsyncSink | W4（4.6 等價檢查項） | `internal/proxy/file_tap_test.go:60` | `(*FileTap).submit`（`:226`）於 `go func`（`:233`）內 `sink.Submit`，失敗只記 log。**data-transfer-control 期 1 起為成功／被拒共用的單一投遞實作**（`status` 由呼叫方傳入），刻意不分家以杜絕兩條路徑漂移——故 tunnel 攔截的 denied 留痕不另立產生點。現況**不受** `AuditLogEnabled` 管制（走 AsyncSink 的 Submit 面繞過該分支） |
| AP-29 | `internal/modules/authz/access_request_service.go:850` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `logAudit`（`:845`，隨 authz 搬包） |
| AP-30 | `internal/modules/asset/asset_account_service.go:508` | RecordCall | 是 | **是** | TxSink | W6（6.1） | `internal/modules/asset/asset_account_service_test.go:327` | `Create` 的 `repository.DB.Transaction`（`:445`）閉包內，`return model.RecordAssetAccountChange(tx …)` ——error 直接成為交易回傳值 |
| AP-31 | `internal/modules/asset/asset_account_service.go:648` | RecordCall | 是 | **是** | TxSink | W6（6.1） | `internal/modules/asset/asset_account_service_test.go:327` | `Update` 的交易（`:536`）內，`return` 形態 |
| AP-32 | `internal/modules/asset/asset_account_service.go:715` | RecordCall | 是 | **是** | TxSink | W6（6.1） | `internal/modules/asset/asset_account_service_test.go:327` | `Delete` 的交易（`:647`）內，`return` 形態 |
| AP-33 | `internal/modules/asset/asset_account_service.go:766` | RecordCall | 是 | **是** | TxSink | W6（6.1） | `internal/modules/asset/asset_account_service_test.go:327` | `SetDefault` 的交易（`:705`）內，`return` 形態 |
| AP-34 | `internal/modules/asset/asset_account_service.go:879` | RecordCall | 是 | **是** | TxSink | W6（6.1） | 待補 | `syncDefaultAccountFromAsset(tx *gorm.DB …)`（`:816`）內，`return` 形態；唯一呼叫方 `asset_service.go:896`（在 `:932` 交易內） |
| AP-35 | `internal/modules/asset/asset_account_service.go:920` | RecordCall | 是 | **是** | TxSink | W6（6.1） | 待補 | 同 AP-34 函式的更新分支 |
| AP-36 | `internal/modules/asset/asset_group_service.go:348` | AuditEvent | 是 | **是** | **TxSink** | W4（4.4） | `internal/modules/asset/asset_group_service_test.go:214` | `nodeAudit(tx *gorm.DB …)`（`:344`），註解 `:345-347` 自陳「AssetID 刻意留空——主體是節點不是資產」，`:357` 失敗回 `審計留痕失敗` error。呼叫方三處：`:389`（Create）／`:428`（Update）／`:490`（Move），皆在交易閉包內以 `return nodeAudit(...)` 形態 |
| AP-37 | `internal/modules/asset/asset_group_service.go:561` | AuditEvent | 是 | **是** | **TxSink** | W4（4.4） | `internal/modules/asset/asset_group_service_test.go:214` | `Delete`（`:513`）的交易（`:518`）內；先經 `RevokeByAssetGroup`（介面宣告 `:64`）級聯撤銷 `AssetAuthorization`／`ApproverScope`，`:571` 失敗回 error → 整筆回滾（授權撤銷不可無痕） |
| AP-38 | `internal/modules/asset/asset_service.go:454` | RecordCall | 是 | **是** | TxSink | W6（6.1） | 待補 | `Create` 的交易（`:385`）內，`:414` `return fmt.Errorf("記錄預設帳號建立審計失敗: %w", err)` |
| AP-39 | `internal/modules/asset/asset_service.go:471` | RecordCall | 是 | 否 | TxSink | W6（6.1） | 待補 | 同一交易內，但 `:425` **只 `log.Printf` 不回 error** ——寫入吃 `tx`（故變體為 TxSink），呼叫方為 fail-open。收口時**保持現況 fail-open**，不得順手改成 fail-close（那是行為變更） |
| AP-40 | `internal/modules/asset/asset_service.go:631` | RecordCall | 是 | **是** | TxSink | W6（6.1） | 待補 | `UpdatePassword`（`:548`）的交易（`:556`）內，`return` 形態 |
| AP-41 | `internal/modules/asset/asset_service.go:1045` | RecordCall | 是 | 否 | TxSink | W6（6.1） | 待補 | `Update` 的交易（`:967`）內，`:999` 只記 log。同 AP-39 的 fail-open 保持 |
| AP-42 | `internal/modules/asset/asset_service.go:1053` | RecordCall | 是 | 否 | TxSink | W6（6.1） | 待補 | 同上，`:986-987` 註解自陳「不中斷事務，只記錄錯誤」 |
| AP-43 | `internal/modules/audit/audit_log_service.go:177` | AuditLog | 否（機器不可判定） | 否 | **不進 sink** | W4 | `internal/api/key_rewrap_audit_regression_test.go:60` | `(*AuditLogService).Log`（`:123`）的 entry→row 轉換，即 AsyncSink 的實作本體（`:134` `AuditLogEnabled=false` 靜默 return、`:175` 滿載丟棄）。它是 sink 的實作側，不再經 sink。**列在 `Log` 內建構、落地在 `writeToDatabase`／`logChan` 消費端，作用域分析對交易歸屬無資訊** [人工複核 2026-08-09] |
| AP-44 | `internal/modules/identity/auth_service.go:744` | AuditLog | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | `internal/modules/identity/auth_service_ldap_resolution_test.go:271` | `auditLDAPResolveFailure`（`:654`），`:668` `repository.DB.Create` 失敗只記 log。**2026-08-19 上移 1 行**：`password-hasher-interface` 移除本檔的 bcrypt import 致全檔位移，產生點未變，僅重新錨定。**產生點與程式碼皆未變，行號因 audit-coverage-closure 於 `LoginResponse` 增列 `AuthProviderID`／`AuthProviderName`（供 handler 標註 provider）而下移 5 行**，僅重新錨定 |
| AP-45 | `internal/modules/identity/auth_service.go:767` | AuditLog | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | `internal/modules/identity/auth_service_transmission_test.go:51` | `auditLDAPTransport`（`:674`），`:699` 同上。**行號下移 5 行的成因同 AP-44**，僅重新錨定。**2026-08-19 再上移 1 行**：`password-hasher-interface` 移除本檔的 `golang.org/x/crypto/bcrypt` import（改經 `pkg/crypto` 的 Hasher／Verifier），import 區塊少一行故全檔位移；產生點與程式碼皆未變。本點的 `status=denied`（`ldap_strict_reject`）自 audit-coverage-closure 起計入每日覆核的登入失敗數——計數口徑以 `action=login` 收斂，故 `resource=transmission` 不再使它被排除 |
| AP-46 | `internal/modules/audit/daily_review_service.go:162` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | `internal/modules/audit/daily_review_service_test.go:76` | `Sign`（`:124`）**交易（`:141`）提交之後**才 `s.audit.Log`（`:156-158` 先檢查 err）——不在交易內。**產生點與程式碼皆未變，行號因 audit-coverage-closure 兩度改寫 `Snapshot` 的登入失敗計數口徑（涵蓋 `failure` 與 `denied`、再排除例行 token 到期）而共下移 20 行**，僅重新錨定 |
| AP-47 | `internal/modules/identity/external_identity_service.go:521` | AuditLogEntry | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | 待補 | `(*UserService).writeIdentityAudit`（`:513`） |
| AP-48 | `internal/modules/identity/external_login_attempt_audit.go:195` | AuditLog | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | `internal/modules/identity/external_login_attempt_audit_test.go:60` | `writeExternalLoginAttemptAudits`（`:173`），`:203` `repository.DB.Create` 失敗只記 log |
| AP-49 | `internal/modules/identity/inactivity_service.go:79` | AuditLogEntry | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | 待補 | `auditDisable`（`:72`） |
| AP-50 | `internal/modules/identity/ldap_directory_service.go:719` | AuditEvent | **是（部分呼叫路徑）** | **是（部分呼叫路徑）** | **TxSink** | W4（4.4 擴充） | `internal/modules/identity/ldap_directory_service_test.go:100,607,642` | **先前盤點完全漏列的 fail-close 點**。`ldapDirectoryAuditLog(db *gorm.DB …)`（`:754`）單一寫入點、**六條呼叫路徑語義二分**：<br>**交易內 fail-close**——`auditSave`（`:777`→`:780`）自 `upsertLocked:644` 收 `tx`、`auditURLChange`（`:801`→`:817`）自 `:650`、`auditDelete`（`:830`→`:832`）自 `Delete:679`；三者皆位於 `WithLDAPDirectoryLock`（`:462`／`:659`，內部即 `db.Transaction`）閉包內，error 直接回滾整筆設定變更（`:642-643` 註解自陳「審計與寫列同事務」）。<br>**交易外 fail-open**——`auditRejection`（`:857`）、`ldap_directory_probe.go:676`／`:703`，傳 `s.db` 且失敗只記 log。<br>→ 變體必須是 TxSink（需 `*gorm.DB` 參數並回 error）；fail-open 呼叫方沿用「傳根 DB、忽略 error」的現況處置。**機器只判得出 TxBound（作用域拿得到呼叫方 `*gorm.DB`），六條路徑的二分屬人工權威** [人工複核 2026-08-09] |
| AP-51 | `internal/modules/identity/ldap_seed_migration.go:335` | AuditEvent | **是** | **是** | **TxSink** | W4（4.4 擴充） | `internal/modules/identity/ldap_seed_migration_test.go:226` | **先前盤點漏列的第二個 fail-close 點**。`ldapSeedAudit(auditTx port.TxSink, db *gorm.DB …)`（`:320`）`:342` 失敗回 error；唯一呼叫點 `:191` 位於 `WithLDAPDirectoryLock`（`:178`）交易閉包內，`:200` 註解自陳「列、審計與標記同進退，標記未寫，下次啟動重試」。**行號於 migration-baseline-compression（`a67a64e`）隨同檔改動整體下移，歸檔時逐條重新量測** |
| AP-52 | `internal/modules/audit/notification_channel_service.go:114` | AuditLog | 否 | 否 | AsyncSink | W4 | `internal/modules/audit/notification_channel_gate_test.go:60` | `auditAcknowledgment`（`:97`），`:116` `s.db.Create`（根 DB，非 tx）失敗只記 log；唯一呼叫點 `:90` 亦不在交易內 |
| AP-53 | `internal/modules/identity/oidc_login_service.go:926` | AuditLogEntry | 否 | 否 | AsyncSink | W4／檔案隨 W8 搬 identity | `internal/api/oidc_abuse_guard_test.go`（聚合列的筆數上界）＋`internal/api/oidc_login_audit_test.go`（欄位與狀態語義） | `writeAuditFrom`（`:920`），經 `auditLogger` 窄介面（`retention_service.go:37`）。**audit-coverage-closure 起只承接聚合列**（`LogAggregatedFailure`）：逐請求的流程留痕（flow error／准入拒絕／撞名／JIT 建帳號）已改由 service 交回審計意向、handler 落地（AP-72），因為 service 拿不到 `*gin.Context`，其寫出的列 `client_ip`／`path`／`method`／`status_code` 四欄必然全空。**聚合列的來源位址取自聚合鍵而非結清當下的請求**——結清由後續任一請求觸發，拿它的脈絡蓋上去是錯的歸屬；路徑／方法／狀態碼同理留空（一個時間窗涵蓋多個請求，無單一值可填）。`resource` 亦由 `user` 改為 `auth`。行號因同檔新增審計意向型別與 trail 而下移；**2026-08-19 再上移 1 行**：`password-hasher-interface` 移除本檔 bcrypt import 致全檔位移，產生點未變 |
| AP-54 | `internal/modules/session/recording_failure_report.go:43` | AuditLog | 否 | 否 | AsyncSink | W4 | `internal/modules/session/recording_failure_report_test.go:63` | `ReportSessionRecordingFailure`（`:21`），`:51` `repository.DB.Create` 失敗只記 log |
| AP-55 | `internal/modules/audit/retention_service.go:478` | AuditLogEntry | 否 | 否 | AsyncSink | W4 | 待補 | `logPurge`（`:469`），保留期清除留痕 |
| AP-56 | `internal/modules/audit/seal_replay_sink.go:206` | AuditLog | 自開交易（機器不可判定） | 是 | **不進 sink** | W4 | `internal/modules/audit/seal_replay_sink_test.go:93` | `sealEventRow`（`:183`）建列 → `SubmitSealReplayRows`（`:148`，**`AuditLogService` 自身的方法**）於 `:158` 自開交易、`:160-163` 逐列 `Clauses(OnConflict{idempotency_uuid, DoNothing}).Create`。既是 audit 模組內部落地入口，不再繞經 sink；`:141-147` 註解自陳三點刻意設計（尊重 `AuditLogEnabled`、逐列非批次、失敗上報）。**列由 `sealEventRow` 回傳後才落地，作用域分析對交易歸屬無資訊** [人工複核 2026-08-09] |
| AP-57 | `internal/modules/audit/seal_replay_sink.go:290` | AuditLog | 自開交易（機器不可判定） | 是 | **不進 sink** | W4 | `internal/modules/audit/seal_replay_sink_test.go:93` | `sealAggregateRow`（`:244`）建列，落地同 AP-56。**同 AP-56 的機器盲區** [人工複核 2026-08-09] |
| AP-58 | `internal/modules/policy/transmission_consent_service.go:167` | AuditLog | 否 | 否 | AsyncSink | W4 | `internal/modules/policy/transmission_consent_service_test.go:36` | `auditConsent`（`:166`）→ `writeAudit`（`:219`）`s.db.Create`，註解自陳「失敗記 log 不阻斷主流程」；呼叫點 `:152` 不在交易內。**機器一跳追到唯一落地點（`struct-field` 來源），2026-08-09 起不再是盲區** [人工複核 2026-08-09] |
| AP-59 | `internal/modules/policy/transmission_consent_service.go:184` | AuditLog | 否 | 否 | AsyncSink | W4 | `internal/modules/policy/transmission_consent_service_test.go:36` | `auditGateDenied`（`:183`），同上；呼叫點 `:73`。**同 AP-58，機器一跳可證** [人工複核 2026-08-09] |
| AP-60 | `internal/modules/identity/user_group_service.go:136` | AuditEvent | 是 | **是** | **TxSink** | W4（4.4） | `internal/modules/identity/user_group_service_test.go:160` | `Delete`（`:92`）的交易（`:94`）內；`:104/:114` 先級聯刪 `AssetAuthorization`／`ApproverScope`，`:128` 註解自陳「審計留痕與刪除同交易：留痕失敗即回滾（授權變更不可無痕）」，`:140` `tx.Create` 失敗回 error |
| AP-61 | `internal/modules/audit/tx_sink.go:56` | AuditLog | 自開交易（機器不可判定） | 是 | **不進 sink** | W4（4.3） | `internal/modules/audit/sink_test.go` | **收口時新增：TxSink 的落地本體**。`auditRowOf`（`:55`）把 `port.AuditEvent` 組成列後回傳，`WriteInTx`（`:49`）以呼叫方傳入的 `tx.Create` 落地——19 個 TxSink 點的**唯一**實際寫入位置。它是 sink 的實作側，不再繞經 sink（同 AP-43 的類別）。**機器判 `escapes-scope`**：列由 `auditRowOf` 回傳後才落地，該作用域的資料流對交易歸屬無資訊；實際交易歸屬由呼叫端的 tx 決定，故欄位標「自開交易」不適用而以機器不可判定標記 [人工複核 2026-08-10] |
| AP-62 | `internal/modules/audit/async_sink.go:47` | AuditLogEntry | 否 | 否 | **不進 sink** | W4（4.2） | `internal/modules/audit/sink_test.go` | **收口時新增：AsyncSink.Submit 的轉換本體**。`entryOf`（`:46`）把 `gatewayapi.AuditEvent` 轉成 `AuditLogEntry` 後交給 `logAt`——即 AP-43 那條路徑的入口。它是 sink 的實作側，不再繞經 sink。機器以型別層規則判 `entry-type-level`（AuditLogEntry 不帶 DB 句柄且無落地面同時吃 entry 與 `*gorm.DB`） |
| AP-63 | `internal/modules/asset/asset_service.go:683` | RecordCall | 是 | 是 | TxSink | W6（6.1） | `internal/modules/asset/change_secret_reliability_test.go` | **change-secret-ssh-deepening 新增，自始為收口後形態**（`port.WriteInTx`，非待收口的舊形態）。`UpdatePrivateKey` 的交易內，比照 `UpdatePassword`（AP-40 同型）：金鑰輪替提交私鑰時於同一交易寫帳號變更審計，只記欄位名 `private_key` 不記材料。**fail-close**：審計寫入失敗即整筆交易回滾，憑證不落地 |
| AP-64 | `internal/modules/asset/change_secret_candidate_service.go:282` | RecordCall | 是 | 是 | TxSink | W6（6.1） | `internal/modules/asset/change_secret_reliability_test.go` | **change-secret-ssh-deepening 新增，自始為收口後形態**。`DiscardByAdmin` 的交易內：admin 顯式清除未驗證候選憑證是破壞性操作（候選為那把可能已在遠端生效的秘密的唯一副本），刪列與審計同交易。**fail-close**：審計失敗即不刪列 |
| AP-65 | `internal/api/asset_handler.go:774` | AuditEvent | 否 | 否 | AsyncSink | — | 待補 | **data-transfer-control 期 1 新增，自始為收口後形態**。`auditK8sFileDenied`（`:767`）：kubectl cp 被資料傳輸閘擋下時的 `status=denied` 留痕，與成功路徑 AP-04 對稱。**漏登記的後果**：拒絕留痕是「誰在什麼時候試圖搬走什麼」的唯一證據，未登記者在下一次 sink 收口時沒有任何東西擋著它被漏接或誤分派——而它一旦靜默失效，稽核看到的會是「沒有人嘗試過」，與「嘗試過但被擋下」在資料上無從分辨。fail-open 沿成功路徑（`_ =` 丟棄 error），刻意與 AP-04 一致 |
| AP-66 | `internal/api/sftp_handler.go:386` | AuditLogEntry | 否 | 否 | AsyncSink | — | 待補 | **data-transfer-control 期 1 新增**。`auditDenied`（`:383`）：SFTP 上傳／下載／刪除／建目錄被全域政策擋下時的 `status=denied` 留痕，與成功路徑 AP-14 共用 `auditService.Log`。**漏登記的後果**：同 AP-65——被擋的傳輸企圖若不入審計，全域政策就只剩「擋住了」而無「擋住了誰」；且此點與 AP-14 同函式群，漏登記時 AP-14 的登記會讓讀者誤以為該檔的傳輸留痕已完備 |
| AP-67 | `internal/proxy/handler.go:385` | AuditEvent | 否 | 否 | AsyncSink | — | 待補 | **data-transfer-control 期 1 新增**。連線建立時把「這次連線當時允許哪五種傳輸能力」快照入審計；政策可在連線後被改，只查政策現值答不出「那次連線當時允許什麼」。**產生點與程式碼皆未變，行號因 workbench-exits-and-export 在上方插入 `recordingStartedAt` 擷取而下移**（原 `:334`／守衛 `:333`；audit-coverage-closure 於上方新增兌換拒絕留痕下移至 `:362`；workbench-clipboard-and-layout 於上方新增 ClipboardEncrypt 欄位註解，再下移至 `:369`），僅重新錨定；`AssetID` 仍未填，缺口狀態不變（見 `audit_points_asset_pivot_guard_test.go` 的 AP-67 列與 `maxAssetPivotGaps`）。`:342` 以 `h.dataTransfer != nil && h.AuditSink != nil` 雙重守衛，失敗只記 log 不回壓連線（與 FileTap 同處置，刻意 fail-open）。**漏登記的後果**：這是事後回答「當時的有效能力」的唯一來源，未登記者在收口時被漏接後，能力快照消失卻不會有任何測試轉紅——傳輸爭議將無從還原當時的政策狀態 |
| AP-68 | `internal/api/recording_handler.go:239` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/api/recording_stream_audit_guard_test.go` | **audit-resource-classification-closure 新增**。`auditRecordingRetrieval`（`:217`）：以錄影 token 取走錄影本體時自寫 `resource=recording, resource_id=<連線 id>, action=read`，`details` 記 `session_id` 與 `via=rtoken`。**這是全系統唯一「取走證物卻不經審計中介層」的入口**——`GET /recordings/stream` 註冊於未套 AuthMiddleware 的 v1 群組（播放器只持短時效不透明 token，不把長效 JWT 放進 URL query），而 `AuditLogMiddleware` 無 userID／username 即整筆跳過（`internal/middleware/audit_log.go:52-56`），修法前 `audit_logs` **零列**（實測 2026-08-13：完整取流 200＋Range 206 後總數不變、`path like '%recordings/stream%'` 計數 0）。身分取自 grant 的簽發時快照（`recordingGrant.Username`）。**一次取證＝一個 grant**：HTTP Range 分塊由 `MarkRetrievalAudited` 去重，避免審計量正比於傳輸分塊、並保住 `Resolve` 熱路徑「不碰 DB」的前提。`AssetID` 不填（主體是連線非資產，見 pivot 守衛的 AP-68 列）。**漏登記的後果**：錄影含完整終端畫面與憑證輸入，取走它不留痕時稽核鏈對該動作全盲，且與「沒有人取過」在資料上無從分辨 |
| AP-69 | `internal/proxy/connect_gates.go:331` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/proxy/connect_deny_audit_test.go`＋`internal/sshproxy/ssh_redeem_deny_audit_test.go` | **audit-coverage-closure 新增**。`AuditConnectDenied`（`:290`）：`GET /api/v1/connect`（圖形）與 `GET /api/v1/ssh`（文字）**兩條兌換入口共用的唯一寫入點**（`/ssh` 側於 audit-coverage-closure 後續併入；圖形側另有薄包裝 `ConnectionHandler.auditConnectDenied` 只負責釘 `via`）。兌換拒絕自寫 `resource=session, action=create`，`details` 記 `asset_id`／`reason`／`via`（`connect`／`ssh`）。修法前拒絕純 HTTP 回應、`audit_logs` **零列**（實測 2026-08-13），使「反覆兌換偽造票證」的探測與「沒有人試過」無從分辨；中介層在此路徑亦幫不上忙——兌換失敗時 `userID` 從未寫進 gin context，`AuditLogMiddleware` 整筆跳過。**單一出口**：閘序拒絕一律經各側的 outcome 出口（圖形 `writeOutcome`／文字 `writeRedeemOutcome`），票證類拒絕經各自 handler 的兩個呼叫點，故新增一道閘不需要記得補審計。**兩側共用同一個 `AuditLogEntry` 字面量**是刻意的：各寫一份就會各自演化欄位集，而「某一側少填來源位址」不會讓任何測試轉紅。`status` 依 HTTP 機械分流（401＝憑證不成立→`failure`，其餘＝授權拒絕→`denied`）；拒絕原因分 `ticket_missing`／`ticket_invalid`／`ticket_expired`／閘的 apierror 碼，**對外回應仍一律收斂為同一則「token 無效」**（不給票證存在性探測面）。**`/ssh` 側併入前**：缺票／無效票各回 401 即返、閘序拒絕純 HTTP，`audit_logs` 零列（實測 2026-08-14），且該路由在覆蓋守衛中列為 `exemptHandlerSelfAuth`，無任何守衛看得見。**漏登記的後果**：這是連線兌換面唯一的拒絕證據，靜默失效後稽核只會看到成功的連線 |
| AP-70 | `internal/sshproxy/handler.go:1181` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/sshproxy/observer_join_audit_test.go` | **audit-coverage-closure 新增（優先序最前）**。`auditObserverJoin`（`:1152`）：`/sessions/:id/monitor` 與 `/sessions/share/:code/ws` 的唯讀觀看加入自寫 `resource=session, resource_id=<連線 id>, action=read`，`AssetID` 填實，`details` 記 `session_id`／`via`（`monitor`／`share`）／`target_user_id`；無效分享碼的拒絕同點寫 `status=denied`。兩條路由不掛 AuthMiddleware（WebSocket 只能以 query token 認證），`authenticate` 的 `?token=` 分支不寫 `userID`，故 `AuditLogMiddleware` 恆整筆跳過——修法前 `audit_logs` **零列**（實測 2026-08-13）。**這是 PAM 最敏感的一列**：管理員可即時旁觀他人終端，無痕即無從課責。`AssetID` 填實而非比照 AP-68 留白——監看的稽核問題本身就是「誰看了這台機器上的操作」，缺資產鍵時資產樞紐與「沒有人看過」不可分辨。**漏登記的後果**：旁觀行為靜默消失，且與從未發生無從分辨 |
| AP-71 | `internal/middleware/anonymous_rejection_audit.go:432` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/middleware/anonymous_rejection_audit_test.go` | **audit-coverage-closure 新增**。`(anonRejectionAuditor).writeRow`（`:424`）：認證中介層 abort 的請求在此寫匿名失敗列（`user_id=0`／`username` 空／`resource=auth`／`status=failure`，來源位址與方法／路徑／狀態碼填實，`details.reason` 帶 apierror 機器碼）。**逐筆與聚合兩種列共用這一個字面量**是刻意的：分成兩份就會有兩處各自演化的欄位集，而「聚合列少填來源位址」不會讓任何測試轉紅。修法前 171 條掛認證中介層的路由其拒絕路徑`audit_logs` **零列**（實測 2026-08-13），「誰在敲門、敲了幾次」在稽核上答不出來。寫入受 per-key／全域令牌桶與時間窗聚合節制（未認證即可寫庫＝無界寫入載體）。`AssetID` 不填（主體是來源位址與被拒的請求，與任何資產無關） |
| AP-72 | `internal/api/oidc_handler.go:405` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/api/oidc_login_audit_test.go` | **audit-coverage-closure 新增**。`writeOIDCAudit`（`:400`）：OIDC 登入流程的**唯一**落地點——成功交換（`resource=auth`／`action=login`／`status=success`，`details` 帶 `provider_id`／`provider_name`／`auth_method`，`error_msg` 以 `annotateAuthSource` 附註 `source=oidc`）、MFA 待驗證階段（`stage=mfa_pending`，正式會話成功列仍由 AP-10 寫，兩者不重複）、JIT 首登建帳號（`resource=user`／`action=create`／`resource_id=<新帳號 id>`）、以及 callback 各階段失敗（`status` 依性質分流：憑證不成立＝`failure`、准入或撞名＝`denied`）。修法前 OIDC 成功登入 **零審計列**（實測 2026-08-13 兩輪 `max(audit_logs.id)` 22920→22920、22925→22925，同時 `users.last_login_at` 確實更新——登入真的發生了，只是無痕），失敗列則四欄全空。**單一字面量承接全部事件**是刻意的：拆成多份就會有多處各自演化的欄位集，而「某一種列少填來源位址」不會讓任何測試轉紅。事件本身由 service 以 `identity.OIDCAuditEvent` 交回（`CallbackResult.AuditEvents` 與 `OIDCLoginError.Events`），handler 只補請求脈絡——HTTP 關注點不進 service 層（design Non-Goals）。**漏登記的後果**：登入是 PAM 最核心的稽核項，此點靜默失效後「誰用哪個 IdP 進來過」與「沒有人登入過」在資料上無從分辨 |
| AP-73 | `internal/api/auth_handler.go:186` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/api/login_rate_limit_test.go` | **security-backlog-settlement 塊 3 新增**。`loginAbuseSink.LogAggregatedFailure`（`:92`）：本地登入端點來源限流的**聚合**審計出口。與 AP-72 的 OIDC 側同形——公開端點的失敗不逐筆落審計，否則偵測訊號本身即成 DoS 載體（攻擊者持續送登入請求＝持續寫 DB）。由 guard 以（事件, 來源 IP, 時間窗）聚合，窗結束時落一筆帶計數與首末時間的列。`ClientIP` 取**聚合鍵**而非觸發結清那一次請求的來源——本列描述的是一個已結束的時間窗，拿結清請求的脈絡蓋上去是錯的歸屬；路徑／方法／狀態碼同理留空。`status` 為 `denied`（政策拒絕，與 RBAC 403 同語義），非 `failure`——被擋下的請求根本沒走到密碼比對。**漏登記的後果**：密碼噴灑是登入面最常見的攻擊形態，此點失效後「有沒有人在大規模試帳號」無從回答
| AP-74 | `internal/modules/session/clipboard_content_service.go:119` | AuditEvent | 是 | 是 | TxSink | W4（4.4） | `internal/modules/session/clipboard_content_service_test.go` | **workbench-clipboard-and-layout B1 新增，自始為收口後形態**（`port.WriteInTx`）。`ClipboardContentService.ReadContent` 的逐筆調閱留痕：單筆剪貼簿內容解密交付前，於 `db.Transaction` 閉包內同步寫審計列（操作者、會話、`details.event_id` 事件識別、`content_status`）——語義＝「伺服器端已解密並交付回應」。**fail-close**：留痕成功是交付明文的前置條件，審計寫入失敗即拒絕該次調閱（收斂錯誤），並經 AuditFailureService（`audit_write`／`audit_write_sync_refused`）走告警鏈。此處刻意**不沿** timeline 讀取審計的不阻斷慣例——那是查列表，這是解密機密，層級不同 |
| AP-75 | `internal/api/audit_export_job_handler.go:171` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/api/audit_export_job_handler_test.go` | **workbench-clipboard-and-layout B2 新增，自始為收口後形態**。`auditJob`（`:164`）：證據包非同步匯出 job 的 handler 側**唯一**審計出口——發起成功（含完整篩選條件快照與 job id）、發起被額度拒絕（denied）、下載成功（SHA-256＋大小）、下載拒絕（非申請者／不可下載態，真實原因只在本列）全部共用這一個字面量。**單一字面量是刻意的**（沿 AP-69/AP-71 紀律）：拆成多份就會有多處各自演化的欄位集。對外回應一律收斂（404/410 不洩存在性），存在性細節只進本列。**漏登記的後果**：下載綁申請者本人的裁決只剩「擋住了」而無「誰持誰的連結來過」——越權嘗試與從未發生無從分辨 |
| AP-76 | `internal/modules/audit/audit_export_job_worker.go:352` | AuditLogEntry | 否 | 否 | AsyncSink | — | `internal/modules/audit/audit_export_job_worker_test.go` | **workbench-clipboard-and-layout B2 新增**。`auditRevokedCancel`（`:337`）：worker 領件／重試時重驗申請者主體失效（停用、刪除、失去 audit:view）的取消留痕——spec 明文「取消可於審計查得」的唯一落點。行為者是系統（user_id=0/username=system，沿 AP-71 匿名列慣例），申請者與 job 識別入 details。**漏登記的後果**：失權取消是「排隊中的匯出為何消失」的唯一解釋，靜默失效後申請者的 job 轉 failed 卻查無原因，且「系統守住了失權邊界」這件事在稽核上不存在 |
| AP-77 | `cmd/server/stage2.go:1071` | AuditEvent | 否 | 否 | AsyncSink | —（single-instance-guard） | `cmd/server/instance_guard_wiring_test.go`（`TestInstanceGuardAuditSinkWritesSystemRows`／`TestInstanceGuardEventDetails`）＋`internal/database/instance_guard_test.go`（事件格） | **single-instance-guard 新增**。`instanceGuardAuditSink`（`:1047`）：守衛三事件（overridden／lost／regained）的系統列（user_id 0／system、action=execute、resource=instance_guard），經 `auditService.Submit`（AsyncSink，`OccurredAt`＝事件當下——段 1 緩衝的事件於段 2 補寫時時間戳不以入列時刻頂替）。status：regained→success、lost／overridden→failure（反映互斥是否成立，稽核者篩 failure 即撈到失守時刻）。details 由 `instanceGuardEventDetails` 組（instance 三元組、db_session_pid、持鎖者指紋、ack＋`actor: operator via env`、unheld_for_ms），無憑證、無 DSN、無 client_addr。**漏登記的後果**：ack 啟動與失鎖是「守衛防的是不知情，不是不發生」唯一的事後證據；靜默失效後兩實例並存只剩行程日誌 |
| AP-78 | `internal/modules/audit/source_ip_baseline.go:184` | AuditEvent | 是 | 是 | TxSink | W4（4.4） | `internal/modules/audit/source_ip_baseline_test.go`（`TestSourceIPBaselineLoginMarksButDoesNotClaimSession`／`TestSourceIPBaselineAuditWriteFailureRollsBackLoginMark`） | **source-ip-forensics 新增，自始為收口後形態**。`ObserveLogin`（`:156`）於基準 upsert 的**同一交易**內寫「帳號自新來源位址登入」標記（`action=new_source_ip`、`resource=auth`、帶 `client_ip`）：`port.WriteInTx` 回 error，失敗即整筆回滾——基準列不建、標記不寫，下次登入補寫。**不得改走 AsyncSink**：非同步是 at-most-once，基準已轉態而標記可丟，該位址從此永遠不算新、標記卻永遠不存在。呼叫端為五個正式會話發放點（`internal/api/auth_source_ip_observe.go`），失敗只記 log 不阻登入 |

---

## 3. 分派計數

| 目標變體 | 條數 | ID |
|---|---|---|
| **TxSink** | **22** | AP-22、AP-26、AP-27（`RecordAsset*Change` 的落地本體 3）；AP-30…AP-35、AP-38…AP-42（asset 模組的交易內呼叫點 11）；AP-36、AP-37、AP-60（資產群組與使用者群組的交易內 fail-close 3）；AP-50、AP-51（LDAP 目錄設定與播種遷移的交易內 fail-close 2）；AP-63、AP-64（憑證輪替與候選清除的交易內 fail-close 2）；AP-74（剪貼簿單筆調閱的逐筆留痕 fail-close 1） |
| **AsyncSink** | **47** | AP-01…AP-21、AP-28、AP-29、AP-44…AP-49、AP-52…AP-55、AP-58、AP-59、AP-65…AP-73、AP-75、AP-76、AP-77 |
| **維持 hook** | **3** | AP-23、AP-24、AP-25 |
| **不進 sink** | **5** | AP-43（AsyncSink 實作本體）、AP-56、AP-57（封印回灌專用入口）、AP-61（TxSink 的落地本體）、AP-62（`Submit` 的轉換本體） |
| 合計 | **77** | |

**交易內（吃呼叫方 `tx`）合計 22 點，全部標 `TxSink`，零例外。** 其中呼叫方 fail-close 者 19 點、
刻意 fail-open 者 3 點（AP-39／AP-41／AP-42，收口時保持現況不得改判）。

### 3.1 收口後的產生點形態變化

sink 收口把「建構審計列」與「落地」分了家：收口後的產生點不再建構
`model.AuditLog`，而是建構 `port.AuditEvent`／`gatewayapi.AuditEvent` 交給 sink。
**§1.1 的機械判準因此有第 4 條**（`AuditEvent` 複合字面量）——判準不隨收口延伸的話，
已收口的點會整批從掃描面上消失，而 sink 內部那唯一一個 `model.AuditLog` 字面量
會讓「產生點總數」看起來只是少了幾個，也就是收口即失明。

| 收口的點 | 收口前種類 | 收口後種類 | 落地路徑 |
|---|---|---|---|
| 五個交易內 fail-close 點（AP-36／37／50／51／60） | AuditLog | **AuditEvent** | `port.WriteInTx(sink, tx, ev)` → `TxSink.WriteInTx` → AP-61 |
| 兩個繞過 `AuditLogEnabled` 的直寫點（AP-04／AP-28） | AuditLog | **AuditEvent** | `sink.Submit(ctx, ev)` → `DirectSink`（繞過 `AuditLogEnabled`，行為零變更） |

sink 的實作側另佔兩列（變體「不進 sink」，同 AP-43 的類別）：**AP-61**（`tx_sink.go` 的
`auditRowOf`，全部 TxSink 點的唯一實際寫入位置）、**AP-62**（`async_sink.go` 的 `entryOf`）。
收口不改變 TxSink 點的數量——五個收口點的機器判定自 `tx-param` 轉為 `sink-tx-arg`，皆仍為 `TxBound`。

### 3.2 落地階段的覆蓋完整性

22 個 TxSink 點**逐點皆有指定階段，無未指定者**：

| 落地階段 | 點數 | ID |
|---|---|---|
| W4（4.4） | 5 | AP-36、AP-37、AP-60、AP-74、AP-78 |
| W4（4.4 擴充） | 2 | AP-50、AP-51 |
| W6（6.1） | 13 | AP-30…AP-35、AP-38…AP-42、AP-63、AP-64 |
| W6（6.2） | 3 | AP-22、AP-26、AP-27 |

這件事由 `TestTxSinkPointsAllHaveLandingWave`（`cmd/server/audit_points_manifest_guard_test.go`）
守著：任一 TxSink 列的落地階段欄留空或非 `W<n>` 形態即紅，不再依賴「有人記得去數」。

---

## 4. 落地階段與後續責任

「落地階段」欄的值對應下表。各階段涵蓋的範圍不只本表，這裡只記與審計產生點相關的部分。

| 階段 | 對本表的動作 |
|---|---|
| W1 | 建表；雙向守衛（`backend/cmd/server/audit_points_manifest_guard_test.go`）；`TxSink` 介面定義 |
| W4 | **已完成（2026-08-10）**：全表 `file:line` 覆核並同步（15 檔搬入 `internal/modules/audit`、收口造成的位移逐列更新）；`TxSink` 落地器（AP-61）；**五點收口**（AP-36／AP-37／AP-60 ＋ AP-50／AP-51，皆經 `port.WriteInTx`）；AP-23…AP-25 維持 hook 並加防復辟守衛（`TestT3HooksStayDetachedDirectWrites`／`TestModelPackageHasNoSinkImport`）；AP-04／AP-28 改走 `DirectSink`（繞過 `AuditLogEnabled`，行為零變更）；`Submit`（AP-62）；執行期 fault-injection backstop（`internal/modules/identity/audit_failclose_backstop_test.go` 5 格＋`internal/modules/asset/audit_failclose_backstop_test.go` 12 格＋`internal/modules/audit/seal_replay_sink_test.go` 1 格） |
| W5 | 不涉本表（`command_alerts` 的 `AlertSink` 另案） |
| W6 | AP-30…AP-35／AP-38…AP-42 收口；AP-22／AP-26／AP-27 下沉，並加 `model.Record*Change` 識別字禁令守衛 |
| W8 | AP-44／AP-45／AP-47／AP-48／AP-49／AP-53 隨檔搬入 identity（變體不變） |

**維護紀律**：新增任何審計寫入點 SHALL 同步在本表登記（含「呼叫方交易內」「目標變體」與「落地階段」三欄），
否則 `TestAuditPointManifestIsBidirectionallyComplete` 的反向斷言會失敗。行號位移時逐條更新，
**不得以放寬守衛判準的方式讓它轉綠**。

---

## 5. 資產主體鍵（`audit_logs.asset_id`）的第二維登記

`audit_logs` 自 migration `20260812_auditor_workbench` 起新增 `asset_id`，稽核工作台的**資產樞紐**
採納入原則：一個資產的時間軸＝「所有 `asset_id` 非空的列」，而非一份列舉動作的清單。
代價全部落在寫入端——**產生點沒填 `asset_id`，該事件就從資產樞紐上整個消失**，而編譯器（`*uint` 不填即
合法 nil）、既有測試（列照寫、行為照樣正確）與稽核端（看到的是「這台機器上沒發生過這件事」）三者皆零保護。

### 5.1 登記放在哪裡，以及為什麼不加第十欄

第二維登記表為 **Go 常數** `assetPivotRegistry`（`backend/cmd/server/audit_points_asset_pivot_guard_test.go`），
以本表的**穩定 AP ID 為鍵**，四值閉集合：`填 AssetID`／`委由 helper`／`非資產類`／`已知缺口`。

不在本表加第十欄的理由：本表是 sink 收口的凍結物，其欄位語義（交易歸屬、變體、落地階段）自成一組；
資產主體鍵是正交的關切，混入同一張表會讓兩組語義互相牽動（任一方調整都要動 73 列）。
以 AP ID 跨表關聯即可，且守衛對兩表做**雙向完備性**比對：本表新增一列而登記表未跟上 → 紅；
登記表有孤兒列（本表已無該 AP）→ 紅。

### 5.2 守衛涵蓋的三個面（`audit_points_asset_pivot_guard_test.go`）

| 測試 | 釘住的事 |
|---|---|
| `TestAssetPivotRegistryCoversEveryAuditPoint` | 每個產生點都必須有明示分類；分類詞彙閉集合；理由不得為空；`填`／`委由` 有條數下限（整批翻成「非資產類」是最省事的消紅手法）；缺口受 `maxAssetPivotGaps` 上限節制 |
| `TestAssetPivotRegistryMatchesCode` | 登記 × AST 實況雙向比對：`填` 的字面量必須有 `AssetID` 欄（**移除任一既有賦值即紅**）、`非資產類`／`已知缺口` 不得有、`委由 helper` 必須追得到 helper 內登記為 `填` 的產生點（委派鏈斷掉即紅）；另比對「包覆函式作用域內是否握有資產識別字」的指紋 |
| `TestAssetSubjectInjectionSitesAreRegistered` | 中介層覆寫側：路徑上沒有資產 id 的端點（授權建立、候選處置、資產建立）靠 handler 呼叫 `setAuditAssetID*` 補主體。以「包覆函式標籤 → 呼叫次數」雙向釘住——刪掉任一注入即紅，新增未登記的注入亦紅 |

現況分佈：`填 AssetID` 18／`委由 helper` 13／`非資產類` 40／`已知缺口` 2（共 73 列）。

### 5.3 兩個已載明的缺口（`maxAssetPivotGaps = 2`）

| ID | 缺口 | 後果 |
|---|---|---|
| `AP-66` | SFTP 被全域政策擋下的 `denied` 留痕未填 `asset_id`，與**同檔成功路徑 AP-14 不對稱** | 資產樞紐的檔案傳輸類只讀 `asset_id`，故「有人試圖從這台機器搬走東西但被擋下」在資產樞紐上完全不可見，與「沒有人試過」無從分辨 |
| `AP-67` | 連線建立的傳輸能力快照（`resource=session`）未填 `asset_id` | 該列是事後回答「那次連線當時允許什麼」的唯一來源，未填則不出現在資產樞紐的「對資產做的事」 |

兩者皆為一行修法（`AssetID: &aid` ／ `AssetID: &assetIDUint`），但兩個檔案屬另一條工作線的職權，
本表不越權改；登記為缺口使其**機器可見且不得擴大**——要新增第三個缺口就必須在同一份 diff 裡
把 `maxAssetPivotGaps` 調高，缺口從此是需要簽字的動作。缺口被補上時守衛同樣轉紅（逼登記改為 `填 AssetID`），
故它不會被默默關掉、也不會被默默擴大。

### 5.4 明載的邊界

守衛驗的是**欄位有沒有被賦值**，不驗**賦的值對不對**（填錯機器 AST 看不出來——那是
`internal/api/asset_subject_audit.go` 的「只在單一資產時才填」語義與人工複核的職權）。
「新增一個作用於資產的產生點卻整個忘了填」無法由 AST 從語義上判定，守衛給的是兩道機械壓力：
(a) 新產生點必然缺登記 → 紅，作者被迫做出分類決定；(b) 判為「非資產類」但包覆函式握有資產識別字時，
必須在登記中顯式承認並寫下理由——「有資產在手卻不填」從此是白紙黑字的決定。
