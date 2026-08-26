# lifecycle manifest｜包級全域・init・注入時序・啟停・reset／zeroize

> **這份表是什麼**：`backend/` 全樹每一個具時序語義的符號與步驟——包級全域、`init()`、
> 組裝根的注入／註冊、啟動步驟、釋放與收尾——逐項登記它屬於哪一類、歸哪個模組，
> 以及**順序反了會發生什麼**。
>
> **怎麼用**：要搬動、刪除或新增上述任一類符號之前，先在這裡查它有沒有順序約束；
> 讀某段組裝碼卻看不出「為什麼是這個順序」時，以錨點鍵反查該列的理由欄。重生與維護見 §0.4。
>
> 守衛：`backend/cmd/server/lifecycle_manifest_guard_test.go`（雙向完備性、有序序列比對、
> 摺疊類別下限、ID 唯一性）。掃描基準為 2026-08-13 的工作樹
> （`packages.Load("./...")`，43 包／350 個非測試 `.go` 檔）。
> **本檔每一列都由該守衛的反向斷言釘住**：程式碼裡多一個未登記的包級全域／`init()`／
> 組裝根注入點／單例 `Init`/`Reset`/`Zeroize`，測試即紅。本檔不是平行維護的文件。

---

## 0. 口徑、分工與使用方式

### 0.1 為什麼要有這份 manifest

Phase B 要把 223 檔的扁平 `internal/service` 拆成 7 個 Go package。**拆包會改變
「包級變數初始化 → `init()` → 組裝根的注入／註冊 → 啟動步驟 → 停止／reset／zeroize」
這條時序鏈**，而系統已存在多個順序敏感點（sink 必須先注入才有人寫審計、
`model.SetAuditCreateHooks` 的蓋章 hook、release singleton、金鑰 zeroize、封印狀態機）。

**現有的 build／test／路由 golden 全部證明不了啟停等價**——既有測試各自建構自己的
DB 與服務，不走真實啟動路徑；`stage2ServiceInventory` 只驗「有沒有建」不驗「先後」。
順序在搬遷中被改掉的症狀是隱性的：某段窗口的審計未蓋章、關閉時金鑰未清零、
注入失敗未回滾。故先把現實凍結成本檔，再以守衛雙向釘住。

### 0.2 與 `manifest-audit-points.md` 的分工（互補不重複）

| | 審計產生點 manifest | 本檔（lifecycle manifest） |
|---|---|---|
| 登記對象 | 審計列的**寫入點** | 具**時序語義**的符號與步驟 |
| 欄位重點 | 是否在呼叫方交易內／目標 sink 變體 | 何時被註冊、相對誰必須先／後、釋放時的反序位置 |
| 交集項舉例 | `model.SetAuditCreateHooks` ＝「蓋章與 syslog tee 的掛載點」 | 同一符號 ＝「必須早於任何會寫審計列的步驟；釋放時必須先解 hook 再解單例」 |

兩份互為補集：審計 manifest 回答「這一筆列從哪寫出、回滾語義是什麼」，本檔回答
「這個 hook 在哪一刻生效、被誰擋在前面、釋放時排第幾」。同一符號在兩檔各佔一列不算重複。

### 0.3 欄位與錨點鍵

每列欄位＝**ID**／**錨點鍵**／**項目**／**file:line**／**類別**／**所屬模組**／**落地階段**／**順序敏感理由**。

- **錨點鍵**是守衛比對用的機器鍵，格式固定：

  | 前綴 | 形態 | 比對方式 |
  |---|---|---|
  | `var:<相對 module 根的檔>:<名>` | 包級全域 | 多重集合雙向 |
  | `init:<檔>:init` | `init()` 函式 | 多重集合雙向 |
  | `hook:<檔>:<接收者>.<被呼叫者>` | 組裝根的注入／註冊呼叫點（`Set`／`Init`／`Register`／`Reset`／`With`／`Use`／`Attach`／`Bind` 前綴，或 `*ForRelease` 後綴） | 多重集合雙向（同檔同名可多列，語義不同） |
  | `inject:<檔>:<變數>.<欄位>` | 組裝根的**裸欄位注入**（`handler.Field = service`，不經呼叫） | 多重集合雙向＋筆數下限 |
  | `singleton:<檔>[:<型別>].<名>` | `Init*`／`Reset*`／`*ForRelease` 函式宣告 | 多重集合雙向 |
  | `class:<類別名>` | 同質摺疊類別 | 筆數下限 |
  | `step:<名>` | 段 2 啟動步驟 | **有序**（列序＝執行序） |
  | `release:<檔>:<名>` | `ResourceBag` 釋放登記 | **有序**（列序＝登記序＝LIFO 反序釋放） |
  | `shutdown:<名>` | 行程收尾步驟 | **有序** |

- **ID** 全域唯一，由 `TestLifecycleManifestIDsAreUnique` 釘住。ID 是本檔對外的引用把手
  （散文交叉引用與討論都以它指認某一列），撞號會讓所有引用二義化。新增列一律取
  未使用的新號；同一批工作的多列不得共用一個號。
- **file:line** 是給人讀的定位入口，**不受守衛對帳，可能過期**。錨點鍵擋得住「符號消失或改名」，
  擋不住「這一列指向的位置早已不是它描述的東西」——曾有一次重生查出 299 個可比對錨點中
  187 個指錯行，最遠的（G-17／18／19）差了 56 行。故照行號讀碼之前先確認該處確實是本列描述的符號，
  對不上就以 §0.4 的傾印重生行號。`class:*`（摺疊類別無單一位置）與由迴圈追加的啟動步驟
  （無屬於自己的字面量 `mark()`，錨點指向迴圈那一處共用呼叫點並標「（迴圈）」）本來就沒有可比對的行號。
  檔案搬包時錨點鍵必須同步更新，否則守衛當場轉紅。
- **順序敏感理由**必須寫「若順序反了會發生什麼」。判為無序者一律寫明「無序」＋為何無序。

### 0.4 重生與維護

```
# 傾印現實側全部項目（維護工具，不承擔守衛責任）
docker compose exec -T -e LIFECYCLE_DUMP=1 backend \
  go test ./cmd/server -run '^TestLifecycleScanDump$' -v -count=1

# 跑守衛
docker compose exec -T backend go test ./cmd/server -run 'Lifecycle'
```

本檔由 `docker-compose.dev.yml` 的 `./openspec:/app/testdata/openspec:ro` 唯讀掛入容器；
**單一來源、不留副本**。掛載新增後需 `docker compose up -d --force-recreate backend` 才生效。

### 0.5 現況總數（守衛下限的基準）

> 「現況筆數」是最近一次以 `TestLifecycleScanDump` 實測的結果，會隨程式碼增減而變動；
> 「守衛下限」是守衛檔內的常數。兩欄不連動——把現況追平現實，不表示下限可以跟著調高。

| 類別 | 現況筆數 | 守衛下限 |
|---|---|---|
| 個別登記的包級全域（`var:`） | 161 | 110 |
| `init()`（`init:`） | 5 | —（雙向等值） |
| 組裝根注入／註冊呼叫點（`hook:`） | 72 | 35 |
| 組裝根裸欄位注入（`inject:`） | 15（納管判準見 §4.4／§4.5） | 8 |
| 單例式 `Init`／`Reset`／`Zeroize` 宣告（`singleton:`） | 16 | —（雙向等值） |
| 段 2 啟動步驟（`step:`） | 41（34 字面量＋7 迴圈） | 25（字面量） |
| 釋放登記（`release:`） | 15 | —（有序等值） |
| 行程收尾步驟（`shutdown:`） | 3 | —（有序等值） |
| 摺疊類別（`class:`） | 3 類／831 筆（sentinel 285／apierror-code 533／blank 13） | 各類分別設限（200／480／4） |
| 載入包數 | 43 | 24 |
| 掃描檔數 | 350 | 250 |

---

## 1. 摺疊類別（`class:*`）

逐條登記無助於時序判讀、但**整批消失即代表掃描範圍縮水**的同質全域，以類別登記並帶筆數下限。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| CL-1 | class:sentinel | 200（現況 257 筆） | 全樹 `var X = errors.New(...)`／`fmt.Errorf(...)` | 包級全域／不可變哨兵 | 全模組 | W2–W9 隨檔 | 無序——值於包變數初始化期定值後不再改寫，比對一律走 `errors.Is`／指標相等，任何包初始化順序皆等價。設下限而非逐條登記：整類消失＝掃描範圍失真。 |
| CL-2 | class:apierror-code | 480（現況 514 筆） | `internal/apierror/codes*.go` 的 `var Code* = register(...)` | 包級全域／registry 填充 | 不搬（橫切 i18n） | —（不動） | **有序但由 Go 保證**：同包內 `register()` 於包變數初始化期執行，重複註冊即 panic（`apierror.go:83`），故順序錯不可能靜默通過。逐條登記 514 列會淹沒真正的時序項；下限保護「整批被移出視野」。 |
| CL-3 | class:blank | 4 | `internal/modules/audit/seal_replay_sink.go:49`、`internal/sealjournal/journal.go:21`、`internal/modules/audit/audit_failure_service.go:40`（`AuditFailureReporter`）、`internal/modules/audit/notification_channel_service.go:52`（`ChannelInventoryProvider`） | 包級全域／編譯期介面斷言 | audit／不搬 | W4／— | 無序——`var _ T = ...` 只在編譯期成立，無執行期狀態。仍納下限：斷言被刪除時（介面契約鬆綁）要看得見。**後兩筆為拆 4.10／4.11 環的產物**：介面由消費方（keyvault／policy）宣告，斷言刻意寫在**實作側**（audit）——寫在宣告側會把剛拆掉的出向邊加回來。 |

---

## 2. 包級全域（`var:`，161 筆）

### 2.1 組裝根（`cmd/server`，5 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-1 | var:cmd/server/main.go:Version | Version | cmd/server/main.go:30 | 包級全域／建置期常量 | assembly（不搬） | —（不動） | 無序——ldflags 於連結期定值，執行期只讀不寫。 |
| G-2 | var:cmd/server/main.go:BuildTime | BuildTime | cmd/server/main.go:31 | 包級全域／建置期常量 | assembly（不搬） | —（不動） | 無序——同 G-1。 |
| G-3 | var:cmd/server/main.go:oidcIssuerDeclarationDigest | oidcIssuerDeclarationDigest | cmd/server/main.go:44 | 包級全域／啟動期單寫 | assembly（不搬） | —（不動） | **必須於段 1 開放監聽之前寫入**（`stage1.go:68`）。`/health` 在封印期即開放探測；若延到段 2 才填，B 模式解封前的探測會回「空宣告」指紋，監控在最需要比對各副本設定的窗口內讀到假一致。 |
| G-4 | var:cmd/server/sealgate.go:sealGateWhitelist | sealGateWhitelist | cmd/server/sealgate.go:23 | 包級全域／不可變查表 | assembly（不搬） | —（不動） | 無序（包變數初始化期定值後不改寫），但**內容即封印期的安全邊界**：三項白名單以外一律 503。拆包不得使此表被複製成兩份——兩份會讓「白名單」與「實際放行」分歧且無編譯錯誤。 |
| G-5 | var:cmd/server/stage2.go:stage2ServiceInventory | stage2ServiceInventory | cmd/server/stage2.go:57 | 包級全域／可執行契約 | assembly（不搬） | —（不動） | **列序即段 2 啟動序**，且與 `appGraph.ServiceNames()` 逐項比對（`stage2.go:123`）。重排此表等同於宣告一個與現實不同的啟動序；本檔 §6 的 `step:` 序列與它逐位對齊，三方任一漂移即紅。 |

### 2.2 單例實例與其保護鎖（audit／keyvault，11 筆）

> 這一組是**段 2 可重跑**（B 模式每次解封重建整張圖）與模組化的正面衝突點：
> 單例假設「一個行程只建構一次」。不清單例，舊持有者的物件會在封印期間仍被
> GORM 直寫路徑取用；清錯順序則會 panic 或讓 in-flight 寫入落空。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-6 | var:internal/modules/audit/alert_matcher.go:alertMatcherMu | alertMatcherMu | internal/modules/audit/alert_matcher.go:41 | 包級全域／singleton 鎖 | audit | W4 | 與 G-7 是同一份狀態的鎖與值，**必須同包**。拆散後兩側各自持有一把鎖 ⇒ 互斥失效，且無編譯錯誤。 |
| G-7 | var:internal/modules/audit/alert_matcher.go:alertMatcherInstance | alertMatcherInstance | internal/modules/audit/alert_matcher.go:42 | 包級全域／singleton | audit | W4 | `InitAlertMatcher` 寫、`ResetAlertMatcherSingleton` 清（釋放時）。若釋放時不清，B 模式下一代的告警比對會打到已丟棄的舊物件（持有舊 DB handle 與舊規則快取）。 |
| G-8 | var:internal/modules/audit/alert_notifier.go:alertNotifierMu | alertNotifierMu | internal/modules/audit/alert_notifier.go:212 | 包級全域／singleton 鎖 | audit | W4 | 同 G-6。 |
| G-9 | var:internal/modules/audit/alert_notifier.go:alertNotifierInstance | alertNotifierInstance | internal/modules/audit/alert_notifier.go:213 | 包級全域／singleton | audit | W4 | 釋放序是契約（`stage2_release.go:52` 註解）：**先解單例 → 再歸零通道明文 → 最後關佇列**。順序反了，in-flight 的 `Enqueue` 會對已關閉的 channel `send` 而 panic；且通道 URL／secret 是解密後的 KEK 衍生材料，每代殘留一份。 |
| G-10 | var:internal/modules/audit/stage2_release.go:alertNotifierStopMu | alertNotifierStopMu | internal/modules/audit/stage2_release.go:40 | 包級全域／收束序列化鎖 | audit | W4 | 使同一物件的收束序列化——兩條路徑可能同時抵達（段 2 重試的 bag 釋放與行程收尾）。拆包後若與 `StopAlertNotifierForRelease` 分屬不同包即失去保護，形態是重複 `close(channel)` panic。 |
| G-11 | var:internal/modules/audit/audit_failure_service.go:auditFailureMu | auditFailureMu | internal/modules/audit/audit_failure_service.go:50 | 包級全域／singleton 鎖 | audit | W4 | 同 G-6。 |
| G-12 | var:internal/modules/audit/audit_failure_service.go:auditFailureInstance | auditFailureInstance | internal/modules/audit/audit_failure_service.go:51 | 包級全域／singleton | audit | W4 | `InitAuditFailure` 必須早於 `syslogForwarder.SetFailureReporter`（`stage2.go:200` → `:215`）——reporter 閉包捕獲本單例，反序即捕獲 nil，syslog 失效將不產生任何失效事件（PCI 10.7 的機制失效偵測靜默消失）。 |
| G-13 | var:internal/modules/audit/audit_integrity_service.go:auditIntegrityMu | auditIntegrityMu | internal/modules/audit/audit_integrity_service.go:45 | 包級全域／singleton 鎖 | audit | W4 | 同 G-6。 |
| G-14 | var:internal/modules/audit/audit_integrity_service.go:auditIntegrityInstance | auditIntegrityInstance | internal/modules/audit/audit_integrity_service.go:46 | 包級全域／singleton | audit | W4 | 釋放時**必須先 `model.SetAuditCreateHooks(nil, nil)` 再 `ResetAuditIntegritySingleton`**（`stage2_release.go:32` 明文）。反序期間 GORM 直寫路徑仍會呼叫已釋放物件的 `StampOne`。 |
| G-15 | var:internal/modules/audit/syslog_forwarder.go:syslogForwarderMu | syslogForwarderMu | internal/modules/audit/syslog_forwarder.go:83 | 包級全域／singleton 鎖 | audit | W4 | 同 G-6。 |
| G-16 | var:internal/modules/audit/syslog_forwarder.go:syslogForwarderInstance | syslogForwarderInstance | internal/modules/audit/syslog_forwarder.go:84 | 包級全域／singleton | audit | W4 | `SetFailureReporter` **必須先於 `Start()`**（`stage2.go:215` → `:222`，同檔註解自陳）：run loop 啟動後再無鎖寫 `onFailure` 是 data race。 |

### 2.3 全域 hook 承載體（`internal/model`，4 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-17 | var:internal/model/audit_log.go:auditCreateHookMu | auditCreateHookMu | internal/model/audit_log.go:273 | 包級全域／hook 鎖 | 不搬（橫切 model） | —（不動） | 保護 G-18／G-19 的讀寫；`getAuditCreateHooks` 每次 GORM 建立都取讀鎖。與被保護值必須同包。　**G-17／G-18／G-19 三列的行號因 audit-coverage-closure 於本檔新增 `AuditReasonTokenExpired` 常數（審計側原因碼，不對外）而各下移 16 行**，變數本身與註冊順序皆未變。 |
| G-18 | var:internal/model/audit_log.go:auditStampHook | auditStampHook | internal/model/audit_log.go:274 | 包級全域／hook 承載體 | 不搬（橫切 model） | —（不動） | **註冊晚於任何會寫審計列的步驟＝該窗口寫出的列 `IntegrityHMAC` 為空**，驗章端會把它當成上線前的歷史列而不計入竄改判定（既有守衛 `post_unseal_guard_test.go:182` 即釘此序）。sink 雙變體落地時 `stage2.go:239` 的註冊位置 SHALL NOT 後移。 |
| G-19 | var:internal/model/audit_log.go:auditPublishHook | auditPublishHook | internal/model/audit_log.go:275 | 包級全域／hook 承載體 | 不搬（橫切 model） | —（不動） | 同 G-18；未註冊窗口寫出的列**不進 syslog tee**（PCI 10.3.3 離機轉發出現空洞），而該空洞在任何測試中都不可見。 |
| G-127 | var:internal/model/audit_checkpoint.go:checkpointUpdatableColumns | checkpointUpdatableColumns | internal/model/audit_checkpoint.go:110 | 包級全域／`BeforeUpdate` 欄位白名單 | 不搬（橫切 model） | —（不動，audit-checkpoint-chain 新增） | 無序，但**內容即安全邊界**：`AuditCheckpoint.BeforeUpdate` 只放行本表列出的四個封章後狀態欄。多列一個被簽章欄位（`agg_hash`／`signature`／`id_to` 等）＝檢查點鏈可被系統自己改寫，鏈的證明力歸零且無任何編譯錯誤。守衛：`TestCheckpointUpdatableColumnsWhitelistIsExact` 逐字釘住四個成員。 |
| G-131 | var:internal/model/audit_log.go:AuditHubSubResources | AuditHubSubResources | internal/model/audit_log.go:161 | 包級全域／樞紐查詢的子資源涵蓋表 | 不搬（橫切 model） | —（不動，clipboard-read-provenance 新增） | 無序（無 init／注入，字面量在載入期即定值），但**內容即查詢正確性邊界**，故與 G-127 同型逐項登記。連線樞紐 `GET /audit-logs/resource/session/:id` 以本表把 `ResourceSession` 展開成含 `ResourceClipboardEvent`／`ResourceRecording`／`ResourceCommand` 的集合（後兩者為 audit-resource-classification-closure 追加，同一次改動把 `recording` 移出樞紐型別白名單——其 `:id` 語義已漂移為連線 id）；**入列的唯一判準是 resource_id 落在同一 id 空間**（clipboard_event 的 resource_id 是連線 id，非事件列 id）。誤增一個 id 空間不同的分類（例如 `ResourceChangeSecretPlan` 的 resource_id 是計畫 id）＝以連線 id 去撈別的實體的事件，樞紐上憑空出現不屬於這場連線的審計列——**假事件比遺漏更糟且無編譯錯誤**；反之整表被清空則取證動作從樞紐消失，稽核看到的是「這場連線沒人取走過剪貼簿」。拆包時若被搬離 `internal/model`，讀取端（`audit_log_service`／handler）與定義端就不再是同一份事實。 |

### 2.4 全域 DB handle 與 schema baseline（`internal/database`，改名前為 `internal/repository`，24 筆）

> **migration-baseline-compression（2026-08-16）改寫本節**：49 條增量 migration 與開機
> `AutoMigrate` 一併退場，schema 的唯一事實源改為單一 baseline 的 DDL 清單。
> 原 G-22（`assetAccountIndexes`）與 G-22b（`auditPivotIndexDDL`）隨其所屬 migration 消失，
> G-22a 的 `autoMigrateModels` 更名為 `schemaParityModels` 並自「執行路徑」轉為「驗證路徑」。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-20 | var:internal/database/database.go:DB | DB | internal/database/database.go:16 | 包級全域／全域資源 handle | infra（**已改名** `internal/database`；授權資料存取層另內化入 authz） | W7 | **段 1 `InitDatabase` 賦值，段 2 的建構子直接吃它**（`stage2.go` 多處，全樹上百處讀取）。任何在 `InitDatabase` 之前建構的服務會捕獲 nil handle——症狀是首次查詢才 panic，而非啟動即失敗。 |
| G-21 | var:internal/database/migrations.go:migrations | migrations | internal/database/migrations.go:38 | 包級全域／有序登記表 | infra | W7 | **slice 順序即 migration 執行序**（`RunMigrations` 依序跑）。壓縮後只有 baseline 一條，但**成員資格具時序語義**：本清單同時是 fail-close 的 `codeDeclaredVersions` 來源，任何未列於此、也未列於 `runtimeMarkerVersions` 的已套用版本都會使啟動被拒。日後新增增量 migration 時，順序照舊即執行序。 |
| G-22a | var:internal/database/database.go:schemaParityModels | schemaParityModels | internal/database/database.go:75 | 包級全域／不可變查表 | infra | W7（migration-baseline-compression 更名） | **本清單不再被執行，只被驗證**：AutoMigrate 移除後它自「要建哪些表」轉為「baseline 必須與哪些 model 對得上」的比對來源。無序，但**成員資格具時序無關卻同等致命的語義**：漏一個 model＝該 model 與 baseline 的欄位漂移不再被任何守衛檢查，而缺欄的症狀要到執行期第一次查詢才以 `column does not exist` 出現在生產。守衛：`schema_parity_test.go`（離線第 1 層，不可被 skip）與 `baseline_parity_pg_test.go`（PG 第 2 層）。 |
| G-22c | var:internal/database/baseline.go:baselineGroups | baselineGroups | internal/database/baseline.go:35 | 包級全域／有序登記表 | infra | migration-baseline-compression | **本表決定 baseline 的 DDL 執行序**：`baselineSchemaStatements` 依「全部建表 → 全部外鍵 → 全部索引」三段跨域串接。域的先後不影響結果（外鍵與索引皆後置），但**漏掉一個域＝整批表不會被建立**，而 baseline 的 DDL 是無條件的，缺表的症狀是啟動後第一次查詢即失敗。`applyBaseline` 的語句數下界（150）是這一類失真的煞車。 |
| G-22d | var:internal/database/baseline_schema_identity.go:baselineIdentityTables | baselineIdentityTables | internal/database/baseline_schema_identity.go:14 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 身分域建表 DDL。組內無序（外鍵後置故不受參照關係限制），但**內容即 schema 事實源**：改一欄而未同步 model 即被第 1／2 層 parity 守衛打紅；整批消失則由 G-22c 的語句數下界攔截。 |
| G-22e | var:internal/database/baseline_schema_identity.go:baselineIdentityForeignKeys | baselineIdentityForeignKeys | internal/database/baseline_schema_identity.go:179 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 身分域外鍵。**必須晚於全部建表**（由 G-22c 的三段串接保證）；若被提前，`ALTER TABLE ... REFERENCES` 會撞上尚未存在的被參照表而使整個 baseline 交易回滾。 |
| G-22f | var:internal/database/baseline_schema_identity.go:baselineIdentityIndexes | baselineIdentityIndexes | internal/database/baseline_schema_identity.go:188 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 身分域索引，含 `idx_users_username`／`idx_users_email`／`idx_ldap_directories_singleton` 三條 partial unique。**partial 條件被拿掉不會改變索引數量**，卻會讓軟刪列佔住使用者名而永遠無法重建同名帳號；具名比對在 `baselineStructuralAssertions`。 |
| G-22g | var:internal/database/baseline_schema_asset.go:baselineAssetTables | baselineAssetTables | internal/database/baseline_schema_asset.go:14 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 資產域建表 DDL；理由同 G-22d。 |
| G-22h | var:internal/database/baseline_schema_asset.go:baselineAssetForeignKeys | baselineAssetForeignKeys | internal/database/baseline_schema_asset.go:158 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 資產域外鍵（現況空集合，保留以維持五域同構）；理由同 G-22e。 |
| G-22i | var:internal/database/baseline_schema_asset.go:baselineAssetIndexes | baselineAssetIndexes | internal/database/baseline_schema_asset.go:161 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 資產域索引，含 `idx_asset_accounts_default`（一資產至多一預設帳號）與 `idx_asset_accounts_username`（軟刪列不佔名）兩條 partial unique——兩者是 asset-multi-account 的資料層不變式承載，缺席時重複列可寫入而無任何錯誤。 |
| G-22j | var:internal/database/baseline_schema_authz.go:baselineAuthzTables | baselineAuthzTables | internal/database/baseline_schema_authz.go:14 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 授權域建表 DDL，含 `chk_auth_target`／`chk_authz_subject_xor`／`chk_approver_scope_*` 四條 CHECK：授權主客體的互斥不變式即由這些 inline CHECK 承載，放寬後越權授權列可直接寫進 DB。 |
| G-22k | var:internal/database/baseline_schema_authz.go:baselineAuthzForeignKeys | baselineAuthzForeignKeys | internal/database/baseline_schema_authz.go:105 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 授權域外鍵（本域 19 條，全樹最多）；理由同 G-22e。 |
| G-22l | var:internal/database/baseline_schema_authz.go:baselineAuthzIndexes | baselineAuthzIndexes | internal/database/baseline_schema_authz.go:128 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 授權域索引；理由同 G-22f。 |
| G-22m | var:internal/database/baseline_schema_audit.go:baselineAuditTables | baselineAuditTables | internal/database/baseline_schema_audit.go:14 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 會話與審計域建表 DDL，含 `audit_logs`／`audit_checkpoints`／`command_alerts`／`alert_rules`。**本檔同時是 `command_alert_write_guard_test.go` 的 `baselineSchemaFiles` 成員**：漏列該清單會使本檔的建表 SQL 被判為繞過告警落地面的原生寫入（大聲失敗，非靜默放行）。 |
| G-22n | var:internal/database/baseline_schema_audit.go:baselineAuditForeignKeys | baselineAuditForeignKeys | internal/database/baseline_schema_audit.go:233 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 審計域外鍵；理由同 G-22e。**刻意只有 sessions 兩條**：`command_alerts` 的 rule_id/session_id 不設 FK（觸發快照冗餘，規則改名或刪除不得破壞歷史告警）。 |
| G-22o | var:internal/database/baseline_schema_audit.go:baselineAuditIndexes | baselineAuditIndexes | internal/database/baseline_schema_audit.go:239 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 審計域索引，含 `idx_failure_events_single_open`（一機制至多一未結案失敗區間，PCI 10.7）與本 change 新增的 `uniq_alert_rules_name`（種子冪等的 `ON CONFLICT` 衝突目標）。後者缺席時 `seedBuiltinAlertRules` 會直接報錯而非靜默重複，屬 fail-fast。 |
| G-22p | var:internal/database/baseline_schema_platform.go:baselinePlatformTables | baselinePlatformTables | internal/database/baseline_schema_platform.go:14 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 平台域建表 DDL（金鑰信封、簽章鑰、外送通道），含 `notification_channels` 的 type／language 兩條 CHECK。 |
| G-22q | var:internal/database/baseline_schema_platform.go:baselinePlatformForeignKeys | baselinePlatformForeignKeys | internal/database/baseline_schema_platform.go:74 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 平台域外鍵（現況空集合，保留以維持五域同構）；理由同 G-22e。 |
| G-22r | var:internal/database/baseline_schema_platform.go:baselinePlatformIndexes | baselinePlatformIndexes | internal/database/baseline_schema_platform.go:77 | 包級全域／不可變 DDL 清單 | infra | migration-baseline-compression | 平台域索引，含 `idx_data_keys_purpose_version_kek`（partial unique，重包狀態機「同 slot 至多一列帶材料」的 DB 層承載，同時是 AAD 完備性的依賴）。 |
| G-22s | var:internal/database/baseline_seed.go:builtinAlertRules | builtinAlertRules | internal/database/baseline_seed.go:31 | 包級全域／不可變查表 | infra | migration-baseline-compression | 12 條內建危險指令規則的**最終狀態**（壓縮前是三個 migration 疊加的結果）。無序，但**內容即安全涵蓋面**：漏掉第三段（`mysql,postgres` → `mysql,postgres,mssql`）＝MSSQL 會話的危險 SQL 無規則覆蓋，而 schema 等價比對（`pg_dump --schema-only`）完全看不到種子資料。守衛：`assertBuiltinAlertRules` 逐條比對 name／pattern／severity／protocols 與三組分佈計數。 |
| G-22t | var:internal/database/migrations.go:runtimeMarkerVersions | runtimeMarkerVersions | internal/database/migrations.go:66 | 包級全域／具名豁免清單 | infra | migration-baseline-compression | 由執行期寫入 `schema_migrations` 但**不是** migration 的版本值（現況唯一成員：LDAP env seed 的冪等標記）。無序，但**漏登記一個 marker 的後果是每一個跑過該模組初始化的全新安裝在第二次啟動時被自己的 fail-close 擋住**——第一次啟動完全正常（marker 尚未寫入），故顯現時機是「昨天還好好的，今天起不來」，且錯誤訊息會誤指資料庫是壓縮前的舊庫。守衛：`TestRuntimeMarkerVersionsCoverAllWriters` 雙面掃描（`*MarkerVersion` 常數＋對 `schema_migrations` 的原生 INSERT 檔）。 |
| G-143 | var:internal/database/instance_guard.go:instanceGuard | instanceGuard | internal/database/instance_guard.go:497 | 包級全域／singleton（`atomic.Pointer[InstanceGuard]`） | infra | single-instance-guard | 單實例守衛的生產實例。**段 1 `AcquireInstanceLock` 於 `InitDatabase` 之後、`RunMigrations` 之前賦值**——那是「DB 已可用、尚未發生任何寫入」的唯一窗口，晚於 migration 即失去「未確認不寫入」的保證。讀者：指標 collector（H-66）、seal status 探針（H-68／H-69）、管理者端點、段 2 事件 sink 注入（H-67）皆經 `InstanceGuardSnapshot`／`SetInstanceGuardEventSink` 現讀。釋放：`database.Close()` **先** `releaseInstanceLock()`（Stop：stopping→取消 watchdog→join→釋放釘選連線→released）**再** `sqlDB.Close()`——釘選連線不在池的管理下，反序則 watchdog 可能把池關閉誤計為失鎖。 |
| G-144 | var:internal/database/instance_guard.go:instanceGuardProcessMu | instanceGuardProcessMu | internal/database/instance_guard.go:502 | 包級全域／行程層級 try 互斥（sqlite 分支） | infra | single-instance-guard | sqlite（僅單元測試）以此提供「第二次取鎖被攔、ack 路徑可測」的同語義（沿 `kekProcessMu`／`ldapDirectoryProcessMu`），不宣稱跨行程互斥；同時承載持鎖者的 Acquire 時間供固定形式指紋。**必須是包級而非 per-instance**：單行程多守衛實例的互斥測試依賴它共用。 |
| G-146 | var:internal/modules/identity/source_policy_gate.go:sourcePolicyDegraded | sourcePolicyDegraded | internal/modules/identity/source_policy_gate.go:46 | 包級全域／行程內失效旗標（atomic.Bool） | identity | —（source-ip-forensics 4.6） | 無序，但**它只決定「要不要付出掃描成本」，不決定放行與否**——判定一律由 `sourceip.Evaluate` 以當次讀到的字串作成。把它改成判定依據（例如「失效中就一律拒絕」）會讓一列損壞資料把全部帳號鎖在門外；把恢復謂詞改成無條件每次掃描，登入尖峰會變成每秒數十次 users 全表掃描。行程級是刻意的：多副本各自持有一份，各自依自己讀到的事實升降級。 |
| G-147 | var:internal/api/source_policy_gate.go:errSourcePolicyGateUnwired | errSourcePolicyGateUnwired | internal/api/source_policy_gate.go:103 | 包級全域／不可變 sentinel | 不搬（接入層） | —（source-ip-forensics 4.2） | 無序。存在理由：讀取面未接線與 DB 讀取失敗**必須收斂到同一條處置**（拒絕＋政策不可讀留痕）——兩者對判定點而言是同一件事：判定所需的事實取不到。改成回 nil error 或布林旗標即等於「未注入＝放行」，而一條漏接的組裝路徑就能讓整套來源限定靜默關掉。 |
| G-145 | var:internal/database/instance_guard_backend_pg.go:pgGuardTryLockSQL | pgGuardTryLockSQL | internal/database/instance_guard_backend_pg.go:43 | 包級全域／不可變 SQL 字面量 | infra | single-instance-guard | 無序——`var` 而非 `const` 僅為測試可替換（沿 G-47 `pgSessionLockAcquireSQL` 形態）：pg-gated 格 `TestInstanceGuardPGTryLockResponseFailureLeavesNoLock` 以「多回一欄使 Scan 失敗」覆寫，驗 spec「取鎖回應失敗不留殘鎖」（鎖已在 DB 端授予、回應在客戶端失敗 → 連線丟棄不歸池）；產品路徑不改寫。 |

### 2.5 `init()` 期填充的 registry 與其對表（policy／audit／橫切，14 筆）

> 這一組是**拆包後最容易靜默失效**的類別：`init()` 隨檔走，但它讀寫的對表若被分到
> 另一個包，Go 只保證「同包內變數初始化早於同包 `init()`」與「被 import 的包先完成初始化」；
> 一旦對表與 `init()` 分屬互不 import 的兩包，初始化順序**未定義**。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-23 | var:internal/modules/policy/security_policy_service.go:policyDefs | policyDefs | internal/modules/policy/security_policy_service.go:241 | 包級全域／init 期被改寫 | policy | W3 | 被同檔 `init()`（I-3）就地改寫 `UnitKey` 欄位。**與 G-24 必須同包**：`init()` 讀不到對表即 panic（fail-fast，尚屬可見）；但若 `policyDefs` 被別包在 `init()` 之前讀取，讀到的是 `UnitKey` 未填的半成品，政策頁單位顯示為空且無任何錯誤。 |
| G-24 | var:internal/modules/policy/security_policy_service.go:unitKeyByZh | unitKeyByZh | internal/modules/policy/security_policy_service.go:657 | 包級全域／不可變對表 | policy | W3 | G-23 的衍生來源。本身不可變，但**必須早於 I-3 完成初始化**——同包由 Go 保證，跨包則不保證。 |
| G-25 | var:internal/modules/policy/transmission_policy_service.go:riskDefs | riskDefs | internal/modules/policy/transmission_policy_service.go:102 | 包級全域／init 期填充的 registry | policy | W3 | 由同檔 `init()`（I-4）以 `registerRisk` 填充，重複註冊即 panic。**唯一事實源**：`newRisk`（後續要匯出供 identity 消費）只從此表建構風險項。若消費者的包初始化早於本表填充，`newRisk` 會查無 key 而回退——風險徽章靜默消失。 |
| G-26 | var:internal/modules/policy/transmission_policy_service.go:channelPolicyKeys | channelPolicyKeys | internal/modules/policy/transmission_policy_service.go:153 | 包級全域／不可變對表 | policy | W3 | 無序——六通道到政策鍵的固定對照，初始化期定值後只讀。 |
| G-27 | var:internal/modules/policy/transmission_policy_service.go:displayPlaceholderRe | displayPlaceholderRe | internal/modules/policy/transmission_policy_service.go:46 | 包級全域／不可變 regexp | policy | W3 | 無序——`regexp.MustCompile` 於包初始化期完成，失敗即 panic；被 `validateTemplateParams` 用於 I-3／I-4 的驗證。**須早於同包 `init()`**，Go 於同包保證。 |
| G-28 | var:internal/modules/policy/transmission_inventory_service.go:inventoryDefs | inventoryDefs | internal/modules/policy/transmission_inventory_service.go:141 | 包級全域／init 期填充的 registry | policy | W3 | 同 G-25 形態（`registerInventory`／I-5）。**注意跨模組耦合**：本檔是 §3.1 的 4.11 policy↔audit 環所在（`transmission_inventory_service.go:19,24` 持 `NotificationChannelService`），**已反轉**為 policy 自宣告的 `ChannelInventoryProvider` 窄介面（audit 側 `NotificationChannelService` 實作、`stage2.go` 注入），本 registry 的填充自此與 audit 的初始化完全脫鉤；反轉前若逕行搬檔，會產生「policy 包初始化需要 audit 包已初始化」的隱性順序。 |
| G-29 | var:internal/notifycat/render.go:catalog | catalog | internal/notifycat/render.go:28 | 包級全域／init 期填充 | 不搬（橫切 i18n） | —（不動） | 由 I-1 自 `embed.FS` 載入三語模板，缺檔／解析失敗即 panic（建置期錯誤不可能在執行期修復）。**必須早於任何出站通知渲染**；由 Go 的 import 初始化順序保證，前提是 `catalog` 與 I-1 同包。 |
| G-30 | var:internal/notifycat/render.go:localeFS | localeFS | internal/notifycat/render.go:13 | 包級全域／embed 資產 | 不搬（橫切 i18n） | —（不動） | `//go:embed` 於編譯期綁定；I-1 的輸入。無執行期寫入，但**與 I-1 同包是 embed 的語法要求**。 |
| G-31 | var:internal/notifycat/render.go:SupportedLangs | SupportedLangs | internal/notifycat/render.go:19 | 包級全域／不可變清單 | 不搬（橫切 i18n） | —（不動） | I-1／I-2 的迭代來源，且為三語完備性守衛的枚舉基準。無序，但**必須早於兩個 `init()`**（同包保證）。 |
| G-32 | var:internal/notifycat/lexicon.go:lexiconCat | lexiconCat | internal/notifycat/lexicon.go:87 | 包級全域／init 期填充 | 不搬（橫切 i18n） | —（不動） | 同 G-29，由 I-2 填充。 |
| G-33 | var:internal/notifycat/lexicon.go:lexiconFS | lexiconFS | internal/notifycat/lexicon.go:84 | 包級全域／embed 資產 | 不搬（橫切 i18n） | —（不動） | 同 G-30。 |
| G-34 | var:internal/notifycat/lexicon.go:causeEnum | causeEnum | internal/notifycat/lexicon.go:58 | 包級全域／不可變枚舉 | 不搬（橫切 i18n） | —（不動） | 無序——與 `model.Cause*` 常數對照的枚舉清單，供詞庫完備性守衛比對。 |
| G-35 | var:internal/notifycat/notifycat.go:mechanismEnum | mechanismEnum | internal/notifycat/notifycat.go:72 | 包級全域／不可變枚舉 | 不搬（橫切 i18n） | —（不動） | 同 G-34。 |
| G-36 | var:internal/notifycat/notifycat.go:registry | registry | internal/notifycat/notifycat.go:134 | 包級全域／不可變 registry | 不搬（橫切 i18n） | —（不動） | 事件規格表，於變數初始化期以複合字面量定值（非 `init()` 填充），故無跨檔順序需求。無序。 |

### 2.6 apierror registry 與其對表（橫切，9 筆；另 514 碼見 CL-2）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-37 | var:internal/apierror/apierror.go:registry | registry | internal/apierror/apierror.go:79 | 包級全域／registry | 不搬（橫切 i18n） | —（不動） | **必須早於全部 514 個 `register()` 呼叫**。Go 的變數初始化依賴分析保證此序（`register` 讀 `registry`），故無法被拆包破壞——但若 registry 與 codes 檔被分到兩包，`register` 變成跨包呼叫、初始化順序改由 import 圖決定，重複碼的 panic 保護仍在但「碼表不完整」不會被偵測。**i18n 必須維持橫切且不得弱化，故本包不參與拆分。** |
| G-38 | var:internal/apierror/apierror.go:CodeGrammar | CodeGrammar | internal/apierror/apierror.go:29 | 包級全域／不可變 regexp | 不搬（橫切 i18n） | —（不動） | `register()` 用它驗碼文法。**必須早於任何 `register()`**；同包由初始化依賴分析保證。 |
| G-39 | var:internal/apierror/apierror.go:placeholderRe | placeholderRe | internal/apierror/apierror.go:32 | 包級全域／不可變 regexp | 不搬（橫切 i18n） | —（不動） | 同 G-38（驗 `ZhFallback` 的 placeholder 與 `Params` 一致）。 |
| G-40 | var:internal/apierror/apierror.go:reservedEnvelopeKeys | reservedEnvelopeKeys | internal/apierror/apierror.go:35 | 包級全域／不可變查表 | 不搬（橫切 i18n） | —（不動） | 無序——封套保留字（`error`／`code`／`params`）不得被 `Meta` 覆蓋，執行期只讀。 |
| G-41 | var:internal/apierror/codes.go:resourceZhLabels | resourceZhLabels | internal/apierror/codes.go:12 | 包級全域／不可變標籤表 | 不搬（橫切 i18n） | —（不動） | 無序——`ParamEnum` 的 zh 標籤來源，供 `Descriptor` 引用。 |
| G-42 | var:internal/apierror/codes.go:roleZhLabels | roleZhLabels | internal/apierror/codes.go:25 | 包級全域／不可變標籤表 | 不搬（橫切 i18n） | —（不動） | 同 G-41。 |
| G-43 | var:internal/apierror/codes_audit.go:policyKeyZhLabels | policyKeyZhLabels | internal/apierror/codes_audit.go:76 | 包級全域／衍生標籤表 | 不搬（橫切 i18n） | —（不動） | 由 `identityLabels(...)` 於初始化期衍生；**必須早於引用它的 `register()`**，同包由依賴分析保證。跨包則無保證。 |
| G-44 | var:internal/apierror/codes_authz.go:grantEntityZhLabels | grantEntityZhLabels | internal/apierror/codes_authz.go:11 | 包級全域／不可變標籤表 | 不搬（橫切 i18n） | —（不動） | 同 G-41。 |
| G-45 | var:internal/apierror/codes_authz.go:queryFieldZhLabels | queryFieldZhLabels | internal/apierror/codes_authz.go:22 | 包級全域／不可變標籤表 | 不搬（橫切 i18n） | —（不動） | 同 G-41。 |
| G-45a | var:internal/apierror/codes_session_sftp.go:transferActionZhLabels | transferActionZhLabels | internal/apierror/codes_session_sftp.go:111 | 包級全域／不可變允許清單 | 不搬（橫切 i18n） | —（data-transfer-control 期 1 新增） | 無序（`identityLabels` 於初始化期建表），但**內容即 wire 上的動作值域**：綁 `ParamEnum` 後任意字串進不了封套。**漏登記的後果**不在時序而在拆包——若本表與 `register()` 被分到兩包，初始化序改由 import 圖決定，「碼表不完整」不會被偵測。值域須與 `internal/modules/policy` 的 `TransferAction*` 常數一致，由 `TestTransferActionLabelsMatchPolicy` 雙向釘住。 |
| G-45b | var:internal/apierror/codes_session_sftp.go:transferDenyReasonZhLabels | transferDenyReasonZhLabels | internal/apierror/codes_session_sftp.go:122 | 包級全域／不可變允許清單 | 不搬（橫切 i18n） | —（data-transfer-control 期 1 新增） | 同 G-45a。期 1 只有 `global_policy` 一種來源；期 2 的 per-authorization 放寬會新增 `no_matching_grant`。**成員數有關**：漏一個來源＝該類拒絕退化成無法辨識的錯誤碼，稽核分不出「被全域政策擋下」與「無匹配放寬」。 |

### 2.7 程序級鎖與 pre-write hook（identity／asset／keyvault，13 筆）

> 兩種都在拆包時**靜默失效**：鎖被複製成兩把（互斥消失），hook 變成跨包不可見（守衛注入不進去）。
> 兩者都不會產生編譯錯誤。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-46 | var:internal/modules/keyvault/key_manager_lock.go:kekProcessMu | kekProcessMu | internal/modules/keyvault/key_manager_lock.go:59 | 包級全域／程序級互斥 | keyvault | W2 | KEK 操作的程序內互斥（DB advisory lock 之外的第一道）。**同一把鎖的全部持有者必須同包**；拆散後兩側各取到不同實例，KEK 輪替與退役可並行進入臨界區。 |
| G-47 | var:internal/modules/keyvault/key_manager_lock.go:pgSessionLockAcquireSQL | pgSessionLockAcquireSQL | internal/modules/keyvault/key_manager_lock.go:101 | 包級全域／不可變 SQL 字面量 | keyvault | W2 | 無序——`var` 而非 `const` 僅為測試可替換；產品路徑不改寫。 |
| G-48 | var:internal/modules/identity/ldap_directory_lock.go:ldapDirectoryProcessMu | ldapDirectoryProcessMu | internal/modules/identity/ldap_directory_lock.go:44 | 包級全域／程序級互斥 | identity | W8 | 同 G-46 形態（LDAP 目錄設定的單列寫入序列化）。 |
| G-49 | var:internal/modules/identity/ldap_directory_lock.go:ldapDirectoryPreWriteHook | ldapDirectoryPreWriteHook | internal/modules/identity/ldap_directory_lock.go:51 | 包級全域／測試注入 hook | identity | W8 | 生產恆 nil，僅測試在臨界區內注入以驗證競態。**拆包後測試若與被測碼分屬不同包即注入不進去**——形態是「競態守衛測試永遠走不到分支而恆綠」。搬檔時測試檔的 package 宣告 SHALL 同步。 |
| G-50 | var:internal/modules/identity/local_admin_invariant.go:localAdminProcessMu | localAdminProcessMu | internal/modules/identity/local_admin_invariant.go:43 | 包級全域／程序級互斥 | identity | W8 | 同 G-46（「最後一個本地 admin」不變式的並發保護）。鎖失效的後果是不變式可被兩個並發請求同時繞過＝系統可被鎖死在無管理員狀態。 |
| G-51 | var:internal/modules/identity/local_admin_invariant.go:localAdminPreWriteHook | localAdminPreWriteHook | internal/modules/identity/local_admin_invariant.go:51 | 包級全域／測試注入 hook | identity | W8 | 同 G-49。 |
| G-52 | var:internal/modules/identity/local_admin_invariant.go:ErrLastLocalAdmin | ErrLastLocalAdmin | internal/modules/identity/local_admin_invariant.go:77 | 包級全域／哨兵值（非 errors.New） | identity | W8 | 無序——`*LastLocalAdminError` 實例，供 `errors.Is` 比對。**不屬 CL-1 摺疊類別**（初值不是 `errors.New`），故逐條登記：它同時承載 apierror 機器碼，搬包後仍須維持同一個實例被全樹比對。 |
| G-53 | var:internal/modules/identity/external_identity_service.go:ErrLastLoginPath | ErrLastLoginPath | internal/modules/identity/external_identity_service.go:62 | 包級全域／哨兵值（非 errors.New） | identity | W8 | 同 G-52。 |
| G-54 | var:internal/modules/identity/oidc_provider_lock.go:oidcProviderMu | oidcProviderMu | internal/modules/identity/oidc_provider_lock.go:49 | 包級全域／per-key 互斥（sync.Map） | identity | W8 | 同 G-46；per-provider 鎖表。§5.3 已裁決 `oidcProviderPreWriteHook`／`oidcSiteSessionCreate`／`oidcSiteMonitorJoin` 三個私有符號由 session 跨模組使用，須改 identity 匯出包裝——**包裝時鎖仍須留在 identity 側**，否則 session 會持有第二把鎖。 |
| G-54b | var:internal/modules/identity/oidc_provider_lock.go:oidcProviderRowLockSQL | oidcProviderRowLockSQL | internal/modules/identity/oidc_provider_lock.go:45 | 包級全域／不可變 SQL 字面量 | identity | W8 | 無序——`SELECT id FROM oidc_providers WHERE id = ? FOR UPDATE`，`var` 而非 `const` 僅為測試可替換；產品路徑不改寫。與 G-54 的程序級鎖是**兩層互斥**（行程內＋DB 行鎖），拆包只影響前者。 |
| G-55 | var:internal/modules/identity/oidc_provider_lock.go:oidcProviderPreWriteHook | oidcProviderPreWriteHook | internal/modules/identity/oidc_provider_lock.go:83 | 包級全域／測試注入 hook | identity | W8 | 同 G-49；另為 §5.3／§5.6 明列的跨模組私有符號之一（`session_provider_termination.go` 消費），後續要改為匯出包裝。 |
| G-56 | var:internal/modules/identity/oidc_login_service.go:oidcTicketBindingFailureHook | oidcTicketBindingFailureHook | internal/modules/identity/oidc_login_service.go:70 | 包級全域／測試注入 hook | identity | W8 | 同 G-49（OIDC 票證綁定失敗路徑的注入點）。 |
| G-57 | var:internal/modules/identity/user_credential_lock.go:userCredentialMu | userCredentialMu | internal/modules/identity/user_credential_lock.go:38 | 包級全域／per-key 互斥（sync.Map） | identity | W8 | 同 G-46。**與 `verifyCredentialGenerationTx` 同一條臨界區**——§5.3 裁決該函式須對外匯出供 session 在 identity 鎖交易內呼叫；鎖若被複製，「世代閘在鎖內驗證」的不變式即失效（`auth_context_touchpoints_guard_test.go` 正是釘住此跨檔呼叫的守衛）。 |
| G-58 | var:internal/modules/identity/user_credential_lock.go:userCredentialPreWriteHook | userCredentialPreWriteHook | internal/modules/identity/user_credential_lock.go:56 | 包級全域／測試注入 hook | identity | W8 | 同 G-49。 |

### 2.8 解封後遷移佇列（keyvault，4 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-59 | var:internal/modules/keyvault/post_unseal_migration.go:postUnsealMu | postUnsealMu | internal/modules/keyvault/post_unseal_migration.go:43 | 包級全域／佇列鎖 | keyvault | W1（登記上移）／W2（搬檔） | 保護 G-60／G-61；與被保護值必須同包。 |
| G-60 | var:internal/modules/keyvault/post_unseal_migration.go:postUnsealQueue | postUnsealQueue | internal/modules/keyvault/post_unseal_migration.go:44 | 包級全域／有序佇列 | keyvault | W1（已上移）／W2（搬檔） | **組裝根的 `RegisterPostUnsealBuiltin` 必須早於 `RunPostUnsealMigrations`**（`stage2.go:258` → `:259`，H-13），且兩者都必須晚於審計蓋章 hook（G-18／G-19；`post_unseal_guard_test.go` 釘此序）。反序的後果：佇列為空＝遷移靜默不執行（不報錯），或遷移寫出的審計列無 HMAC。**登記上移已完成**（4.9 環拆解）：佇列順序自此＝組裝根的登記順序，不再由 keyvault 內部寫死。 |
| G-60b | var:internal/modules/keyvault/post_unseal_migration.go:postUnsealBuiltins | postUnsealBuiltins | internal/modules/keyvault/post_unseal_migration.go:56 | 包級全域／登記器清單 | keyvault | W1（1.10 新增）／W2（搬檔） | **拆 4.9 環的產物**：各模組的「內建遷移登記器」由組裝根注入本清單，keyvault 因此不再認識 identity 的 `registerLDAPSeedMigration`。與 G-60 分開保存是契約：`ResetPostUnsealQueueForTest` 清佇列但**不清本清單**，重播即回到生產狀態（此契約不因拆環而失效）。若把它與佇列一起清空，凡用 Reset 的測試都會看到空佇列而讓佇列成員的負向斷言假綠；若改以 `init()` 填充，則回到已否決的「檔名字典序決定順序」。 |
| G-61 | var:internal/modules/keyvault/post_unseal_migration.go:postUnsealRuns | postUnsealRuns | internal/modules/keyvault/post_unseal_migration.go:62 | 包級全域／執行計數 | keyvault | W1／W2 | 冪等計數（重複登記為 no-op 的依據）。B 模式每次解封重跑段 2，計數不清＝可觀測的重跑次數；清錯時機會讓冪等判定失準。 |

### 2.9 keyvault 的登記表與 AAD 綁定（keyvault，18 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-62 | var:internal/modules/keyvault/cipher_refs.go:RefAssetsSftpPassword | RefAssetsSftpPassword | internal/modules/keyvault/cipher_refs.go:17 | 包級全域／AAD 綁定登記 | keyvault | W2 | 無序（不可變 `crypto.CipherRef`），但**必須與 G-73 `allCipherRefs` 同包**：後者是 AAD 完備性守衛的唯一資料來源，登記表被拆散時守衛只看到子集，「某欄位未綁 AAD」不再被偵測。 |
| G-63 | var:internal/modules/keyvault/cipher_refs.go:RefAssetsPassword | RefAssetsPassword | internal/modules/keyvault/cipher_refs.go:21 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-64 | var:internal/modules/keyvault/cipher_refs.go:RefAssetsPrivateKey | RefAssetsPrivateKey | internal/modules/keyvault/cipher_refs.go:22 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-65 | var:internal/modules/keyvault/cipher_refs.go:RefAccountPassword | RefAccountPassword | internal/modules/keyvault/cipher_refs.go:25 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-66 | var:internal/modules/keyvault/cipher_refs.go:RefAccountPrivateKey | RefAccountPrivateKey | internal/modules/keyvault/cipher_refs.go:26 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-66a | var:internal/modules/keyvault/cipher_refs.go:RefChangeSecretCandidatePassword | RefChangeSecretCandidatePassword | internal/modules/keyvault/cipher_refs.go:31 | 包級全域／AAD 綁定登記 | keyvault | —（change-secret-ssh-deepening 新增） | 同 G-65：改密未驗證候選憑證的密碼欄 AAD 身分，與 asset_accounts 的 ref 刻意分立（不同信任面）。 |
| G-66b | var:internal/modules/keyvault/cipher_refs.go:RefChangeSecretCandidatePrivateKey | RefChangeSecretCandidatePrivateKey | internal/modules/keyvault/cipher_refs.go:32 | 包級全域／AAD 綁定登記 | keyvault | —（change-secret-ssh-deepening 新增） | 同上，候選私鑰欄。 |
| G-67 | var:internal/modules/keyvault/cipher_refs.go:RefUserTOTPSecret | RefUserTOTPSecret | internal/modules/keyvault/cipher_refs.go:35 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62（跨模組：identity 的 MFA secret 由 keyvault 的 ref 描述）。 |
| G-68 | var:internal/modules/keyvault/cipher_refs.go:RefExportSigningPrivateKey | RefExportSigningPrivateKey | internal/modules/keyvault/cipher_refs.go:38 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-69 | var:internal/modules/keyvault/cipher_refs.go:RefChannelSecret | RefChannelSecret | internal/modules/keyvault/cipher_refs.go:45 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62；為 §3.1 的 4.10 audit→keyvault 反向邊之一（`notification_channel_service.go:166,253` 消費）。該方向**保留為合法單向**，搬檔後不得反轉。 |
| G-70 | var:internal/modules/keyvault/cipher_refs.go:RefChannelURL | RefChannelURL | internal/modules/keyvault/cipher_refs.go:46 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-69。 |
| G-71 | var:internal/modules/keyvault/cipher_refs.go:RefOIDCClientSecret | RefOIDCClientSecret | internal/modules/keyvault/cipher_refs.go:49 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62。 |
| G-72 | var:internal/modules/keyvault/cipher_refs.go:RefLDAPBindPassword | RefLDAPBindPassword | internal/modules/keyvault/cipher_refs.go:52 | 包級全域／AAD 綁定登記 | keyvault | W2 | 同 G-62；**§3.1 的 4.9 keyvault↔identity 環的一條邊**（`ldap_seed_migration.go:125` 消費）。拆環後方向為 identity→keyvault ✔。 |
| G-73 | var:internal/modules/keyvault/cipher_refs.go:allCipherRefs | allCipherRefs | internal/modules/keyvault/cipher_refs.go:56 | 包級全域／完備性守衛資料來源 | keyvault | W2 | **必須列齊 G-62…G-72 全部 11 個 ref**；此表是 AAD 完備性與 KEK 重寫守衛的枚舉基準。少列一項＝該欄位不受守衛涵蓋且無任何編譯錯誤。此類登記表本身即守衛的資料來源，須加雙向完備性。 |
| G-128 | var:internal/modules/keyvault/cipher_refs.go:RefCheckpointSigningPrivateKey | RefCheckpointSigningPrivateKey | internal/modules/keyvault/cipher_refs.go:42 | 包級全域／AAD 綁定登記 | keyvault | —（audit-checkpoint-chain 新增） | 同 G-62。另：本 ref 對應的 `checkpoint_signing_keys.private_key_enc` **必須同時登記於 G-74 `envelopeMigrationTargets`**——漏登會使退役 DEK 誤判零引用而被銷毀，該私鑰即永久不可解，以它簽的全部歷史檢查點從此不可驗。 |
| G-142 | var:internal/modules/keyvault/cipher_refs.go:RefClipboardContent | RefClipboardContent | internal/modules/keyvault/cipher_refs.go:58 | 包級全域／AAD 綁定登記 | keyvault | —（workbench-clipboard-and-layout 新增） | 同 G-62（跨模組：session 的剪貼簿留存內容由 keyvault 的 ref 描述）。對應的 `clipboard_events.content_enc` **必須同時登記於 G-74 `envelopeMigrationTargets`**——漏登會使退役 DEK 誤判零引用而被銷毀，剪貼簿審計證據整批永久不可解。 |
| G-74 | var:internal/modules/keyvault/envelope_migration_service.go:envelopeMigrationTargets | envelopeMigrationTargets | internal/modules/keyvault/envelope_migration_service.go:43 | 包級全域／動態表名登記表 | keyvault | W2 | **守衛的資料來源**（動態表名登記表）。同時是「keyvault 對 7 張他模組表 UPDATE」這條既知缺口的來源（`:225`）——須以具名寫入例外白名單登記並附理由，且**與交易級聯刪除類分開登記、不共用解法**。 |
| G-75 | var:internal/modules/keyvault/key_manager_cleanup.go:purgeClasses | purgeClasses | internal/modules/keyvault/key_manager_cleanup.go:222 | 包級全域／不可變分類表 | keyvault | W2 | 無序——金鑰清理的分類對照，執行期只讀。 |
| G-76 | var:internal/modules/keyvault/key_manager_cleanup.go:unregisteredPurgeClass | unregisteredPurgeClass | internal/modules/keyvault/key_manager_cleanup.go:265 | 包級全域／fallback 分類 | keyvault | W2 | 無序——未登記類別的 fail-visible 兜底值。 |
| G-77 | var:internal/modules/audit/seal_replay_sink.go:sealAggregateNamespace | sealAggregateNamespace | internal/modules/audit/seal_replay_sink.go:63 | 包級全域／UUID 命名空間 | audit | W4 | 無序，但**值不可變**：封印期 journal 回灌的去重鍵由此命名空間衍生。搬包時若被重新產生（例如誤改為 `uuid.New()`），既有部署的回灌會全部視為新事件而重複寫入審計。 |
| G-78 | var:internal/modules/audit/seal_replay_sink.go:sealEventNamespace | sealEventNamespace | internal/modules/audit/seal_replay_sink.go:64 | 包級全域／UUID 命名空間 | audit | W4 | 同 G-77。 |

### 2.10 其餘服務層全域（asset／audit／identity／policy／session，13 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-79 | var:internal/modules/asset/asset_group_service.go:treeStructMu | treeStructMu | internal/modules/asset/asset_group_service.go:21 | 包級全域／程序級互斥 | asset | W6 | 資產節點樹結構變更的序列化鎖。同 G-46 的拆散風險；失效後果是並發移動節點可造成環狀父子關係。 |
| G-80 | var:internal/modules/asset/asset_tags.go:likeTagReplacer | likeTagReplacer | internal/modules/asset/asset_tags.go:85 | 包級全域／不可變 replacer | asset | W6 | 無序——LIKE 萬用字元跳脫；`strings.NewReplacer` 於初始化期建構後只讀。 |
| G-81 | var:internal/modules/asset/change_secret_plan_service.go:cronParser | cronParser | internal/modules/asset/change_secret_plan_service.go:50 | 包級全域／不可變 parser | asset | W6 | 無序——cron 運算式解析器，無狀態。 |
| G-81a | var:internal/modules/asset/asset_service.go:assetProtocols | assetProtocols | internal/modules/asset/asset_service.go:1272 | 包級全域／不可變協議清單 | asset | db-protocol-connection-test | 無序——可建立資產的協議全集，初始化後只讀（`validateProtocol` 查它）。**與 G-81b、以及 `CreateAssetRequest.Protocol` 的 gin `binding:"oneof=…"` 標籤三者互為完備**（mssql-web-cli 起為三份事實源，不再是兩份）：G-81a↔G-81b 由 `connection_probe_test.go` 的 `TestConnectionProbeTableComplete` 釘住，G-81a↔binding 標籤由 `TestCreateAssetProtocolBindingMatchesTable` 釘住。**binding 那份曾漏過**：`mssql` 只加了本表與 probe 表而未加 binding，`POST /api/v1/assets` 對該協議一律回 `VALIDATION_BAD_REQUEST` 而前兩份的守衛全綠——服務層完備不代表接入層放得進來。 |
| G-81b | var:internal/modules/asset/connection_probe.go:connectionProbes | connectionProbes | internal/modules/asset/connection_probe.go:76 | 包級全域／不可變分派對照表 | asset | db-protocol-connection-test | 無序——協議→撥測 probe 的對照表，初始化後只讀。失效後果不在順序而在**完備性**：漏登記一個協議，該協議的撥測會落入 `protocol_unsupported`（舊實作是落入 guacd 而永不返回）。故守衛是完備性而非時序，見 G-81a。 |
| G-82 | var:internal/modules/audit/alert_notifier.go:defaultNotifyBackoff | defaultNotifyBackoff | internal/modules/audit/alert_notifier.go:39 | 包級全域／不可變退避表 | audit | W4 | 無序——推送重試的固定退避階梯。 |
| G-83 | var:internal/modules/audit/alert_rule_service.go:commandAuditedProtocols | commandAuditedProtocols | internal/modules/audit/alert_rule_service.go:34 | 包級全域／不可變查表 | audit | W4 | 無序——哪些協議做指令稽核的固定對照。 |
| G-84 | var:internal/modules/audit/retention_service.go:retentionTargets | retentionTargets | internal/modules/audit/retention_service.go:73 | 包級全域／有序目標表 | audit | W4 | 表列順序即保留期清理的執行順序；**跨表外鍵相依時重排會造成刪除失敗**（子表未清先清父表）。後續要把 `NewRetentionService` 的 `recording` 參數改 `RecordingReader` 窄介面（§3.6 的 C↔E 環第二實例），該改動不得順手改動本表順序。 |
| G-132 | var:internal/modules/policy/cross_key_retention.go:dataRetentionKeys | dataRetentionKeys | internal/modules/policy/cross_key_retention.go:25 | 包級全域／不可變鍵清單 | policy | —（audit-checkpoint-chain 第 7 組新增） | 受檢查點保留跨鍵約束涵蓋的四個資料保留鍵。**順序無關，但成員數有關**：漏列一個鍵＝該類資料可設定成比檢查點鏈更長的保留期，鏈到期被修剪後那些資料的完整性再也無法證明。設定期（UpdateBatch）與執行期（retention 跳過修剪）共用本清單。 |
| G-84b | var:internal/modules/audit/async_sink.go:errDirectSinkNoDB | errDirectSinkNoDB | internal/modules/audit/async_sink.go:109 | 包級全域／不可變哨兵錯誤 | audit | W4（4.6） | 無序——`DirectSink` 未注入 DB 句柄時的哨兵。**值不可為 nil**：C-plain 兩點（AP-04／AP-28）現況對審計寫入失敗只記 log 不阻斷，若此哨兵被改成 nil，「未接線」會與「寫成功」不可分辨。 |
| G-84c | var:internal/modules/audit/timeline_service.go:allTimelineTypes | allTimelineTypes | internal/modules/audit/timeline_service.go:35 | 包級全域／有序類別全集 | audit | —（auditor-workbench 新增） | **順序即字典序，與 `keysetWhere` 的比較同源**——重排即游標比較與資料排序脫鉤，時間軸分頁會漏事件或重複發事件（且兩者都不會讓任何既有測試轉紅）。同時是「六類審計資料」的單一事實源：**漏列一類＝工作台永遠看不到該類事件**，症狀與「那段期間沒發生事」不可分辨。 |
| G-84d | var:internal/modules/audit/timeline_service.go:directIPPredicate | directIPPredicate | internal/modules/audit/timeline_service.go:413 | 包級全域／不可變查詢述詞 | audit | —（source-ip-forensics 新增） | 無序（包變數初始化期定值後不改寫），但**內容即位址樞紐與位址篩選的 WHERE 形狀**：自帶 `client_ip` 欄的兩張表（sessions／audit_logs）用它。三個述詞常數必須維持同一組語義——fetch／count／spans 三處共用同一份，拆成各自的字面量即回到「events 有、counts 沒有」的三處漂移。 |
| G-84e | var:internal/modules/audit/timeline_service.go:joinedIPPredicate | joinedIPPredicate | internal/modules/audit/timeline_service.go:420 | 包級全域／不可變查詢述詞 | audit | —（source-ip-forensics 新增） | 同 G-84d：經 LEFT JOIN sessions 取位址的兩張表（session_commands／command_alerts）。**LEFT 而非 INNER 是語義的一部分**——會話列缺失的指令／告警列仍要在人／資產樞紐以未知來源呈現，改成 INNER 會把整列藏掉。 |
| G-84f | var:internal/modules/audit/timeline_service.go:clipboardIPPredicate | clipboardIPPredicate | internal/modules/audit/timeline_service.go:426 | 包級全域／不可變查詢述詞 | audit | —（source-ip-forensics 新增） | 同 G-84d：剪貼簿沿既有 INNER JOIN（本表無主體欄，會話缺失的列任何樞紐皆不可達，已列為誠實邊界）。 |
| G-84g | var:internal/modules/audit/timeline_subjects.go:seenAtLayouts | seenAtLayouts | internal/modules/audit/timeline_subjects.go:47 | 包級全域／不可變時刻格式表 | audit | —（source-ip-forensics 新增） | 無序。存在理由：`MAX(last_seen_at)` 是運算式，欄位宣告型別在聚合後即遺失——PostgreSQL 回 time.Time、sqlite 回字串。本表是後者的解析形式清單；**移除或縮減它會讓 sqlite 路徑的候選時刻靜默變成零值**（候選仍回得出位址，但「最近見到」全成 0001-01-01，排序看起來仍正常）。 |
| G-85 | var:internal/modules/identity/auth_epoch_gate.go:epochGateWarnOnce | epochGateWarnOnce | internal/modules/identity/auth_epoch_gate.go:160 | 包級全域／一次性告警 | identity | W8 | 無序（僅去重 log 噪音）。但後續要把 `auth_epoch_gate.go` 的包級函式改方法，**改動不得把 `sync.Once` 併入實例**——那會讓每個實例各印一次，且在 B 模式重建段 2 時重複刷屏。 |
| G-86 | var:internal/modules/identity/auth_service.go:lockoutWarnOnce | lockoutWarnOnce | internal/modules/identity/auth_service.go:532 | 包級全域／一次性告警 | identity | W8 | 無序，同 G-85。**行號因 audit-coverage-closure 於 `LoginResponse` 增列 `AuthProviderID`／`AuthProviderName` 而下移 5 行**，變數本身未變。 |
| G-87 | var:internal/modules/identity/auth_refresh_service.go:refreshPostRotateHook | refreshPostRotateHook | internal/modules/identity/auth_refresh_service.go:76 | 包級全域／測試注入 hook | identity | W8 | 同 G-49（refresh token 輪替後的注入點，用於驗證撤銷競態）。 |
| G-88 | var:internal/modules/identity/ldap_directory_probe.go:ldapProbeCurrentRuntime | ldapProbeCurrentRuntime | internal/modules/identity/ldap_directory_probe.go:215 | 包級全域／程序級單例 | identity | W8 | 承載全域 in-flight 上限的限流器。**程序級是刻意的**（同檔註解自陳）；拆包造成兩份實例＝限流上限翻倍，LDAP 伺服器可被本服務打爆。唯一改寫者是 `_test.go`，故與 G-49 同樣有「跨包注入不進去」風險。 |
| G-89 | var:internal/modules/identity/ldap_directory_probe.go:ldapProbeStageTimeout | ldapProbeStageTimeout | internal/modules/identity/ldap_directory_probe.go:72 | 包級全域／可置換逾時 | identity | W8 | 無序；`var` 而非 `const` 僅為測試縮短逾時。 |
| G-90 | var:internal/modules/identity/ldap_settings_validation.go:ldapAttrNamePattern | ldapAttrNamePattern | internal/modules/identity/ldap_settings_validation.go:317 | 包級全域／不可變 regexp | identity | W8 | 無序——`MustCompile` 於初始化期完成，失敗即 panic。 |
| G-91 | var:internal/modules/identity/ldap_url.go:ldapHostPattern | ldapHostPattern | internal/modules/identity/ldap_url.go:136 | 包級全域／不可變 regexp | identity | W8 | 同 G-90。 |

### 2.11 identity／keyvault 其餘查表（3 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-92 | var:internal/modules/identity/oidc_admission.go:builtinSharedIssuers | builtinSharedIssuers | internal/modules/identity/oidc_admission.go:193 | 包級全域／不可變安全清單 | identity | W8 | 無序，但**內容即安全邊界**（共用 issuer 需專用 issuer 宣告才放行）。拆包不得使此表被複製成兩份。 |
| G-93 | var:internal/modules/identity/oidc_discovery.go:oidcSignatureAlgs | oidcSignatureAlgs | internal/modules/identity/oidc_discovery.go:29 | 包級全域／不可變允許清單 | identity | W8 | 無序；§7.7 提醒本檔搬家後須同步改 `pkg/crypto/kms/endpoint_gate_test.go:46` 的 `endpointWriteAllowlist` map 鍵。 |
| G-94 | var:internal/modules/identity/oidc_provider_service.go:oidcAllowedExtraScopes | oidcAllowedExtraScopes | internal/modules/identity/oidc_provider_service.go:44 | 包級全域／不可變允許清單 | identity | W8 | 同 G-92。 |
| G-95 | var:internal/modules/identity/user_service.go:emailValidator | emailValidator | internal/modules/identity/user_service.go:23 | 包級全域／不可變 validator | identity | W8 | 無序——`validator.New()` 無狀態。**注意本檔目前有並行改動**（`role-change-revocation`），搬檔階段以當時工作樹為準。 |

### 2.12 接入層與橫切包（不參與拆分，40 筆）

> 這些包不在 7 模組劃分內，但**組裝根對它們注入**（handler 反向後綁定、middleware 單例），
> 故其全域仍屬啟停時序的一部分，一併納管以維持反向斷言的完整涵蓋。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| G-137 | var:internal/observability/metrics.go:sealStateDesc | sealStateDesc | internal/observability/metrics.go:134 | 包級全域／不可變 Desc | 不搬（橫切 observability） | —（observability-lite 新增） | 無序——`prometheus.NewDesc` 於包初始化定值，執行期只讀。**取代已刪除的 G-96／G-97**（`internal/middleware/metrics.go` 的 collector 與其 sync.Once，隨行程內延遲統計整組退場：該實作與新的 Prometheus middleware 落在同一個全域位置，留著即每個請求統計兩次）。 |
| G-98 | var:internal/middleware/audit_log.go:auditSensitiveResources | auditSensitiveResources | internal/middleware/audit_log.go:422 | 包級全域／不可變遮罩表 | 不搬（橫切 middleware） | —（不動） | 無序，但**內容即遮罩邊界**：漏列一項＝該資源的敏感欄位進審計明文。 |
| G-133 | var:internal/middleware/accesslog.go:sensitiveQueryFragments | sensitiveQueryFragments | internal/middleware/accesslog.go:59 | 包級全域／不可變語彙片段表 | 不搬（橫切 middleware） | —（不動，access log 憑證遮蔽新增） | 無序（初始化期定值後只讀），但**內容即兩個遮蔽面的共同邊界**：`IsCredentialQueryKey` 逐項 `Contains` 比對本表，而 access log（`IsSensitiveQueryKey`）與審計 details（`MaskCredentialQuery`）都經它。**漏一個命名＝該憑證在兩個面同時逐字留存**——access log 會被轉存帶走，audit_logs 受檢查點鏈保護寫進去刪不掉，等於永久封存。誤增只損失除錯資訊，故刻意偏保守（唯一的例外紀律是不收單獨的 `key`，會誤殺 `sort_key`／`risk_keys`）。與前端 `frontend/src/api/redact.js` 的 `SENSITIVE_FRAGMENTS` 刻意同語彙；**拆包時不得複製成兩份**——兩份會讓「一端遮了、另一端沒遮」的分歧無編譯錯誤（同 G-4 論述）。 |
| G-134 | var:internal/middleware/accesslog.go:sensitiveQueryExactKeys | sensitiveQueryExactKeys | internal/middleware/accesslog.go:78 | 包級全域／不可變完整比對表 | 不搬（橫切 middleware） | —（不動，access log 憑證遮蔽新增） | 無序，但**成員資格與比對方式互為前提**：`code`／`state`／`binding` 太短，移進 G-133 當片段比對會誤殺 `status_code`／`estate`，故只做完整比對——**兩表不得合併，也不得把本表的成員複製進片段表**。漏 `state` ＝ OIDC CSRF nonce 進 log，漏 `code` ＝授權碼進 log（該碼可兌換 token）。 |
| G-135 | var:internal/middleware/accesslog.go:piiQueryExactKeys | piiQueryExactKeys | internal/middleware/accesslog.go:94 | 包級全域／不可變個資參數表 | 不搬（橫切 middleware） | —（不動，access log 憑證遮蔽新增） | 無序，但**這一表刻意只作用於 access log 面**：`IsSensitiveQueryKey` 讀它、`IsCredentialQueryKey` 不讀。把成員併進憑證那兩表（看似「更保守」）會讓審計 details 的查詢摘要失去「對象」這一維，而 PCI 10.2.1.3 要的正是「誰以什麼條件查了誰」——摘要就答不出它存在的理由。反向漏列則是管理員以 email 搜尋時整串個資落進 access log 並被收集系統帶走（違反全域紀律「log 不得含個資」）。 |
| G-136 | var:internal/middleware/accesslog.go:queryKeySeparators | queryKeySeparators | internal/middleware/accesslog.go:102 | 包級全域／不可變 Replacer | 不搬（橫切 middleware） | —（不動，access log 憑證遮蔽新增） | 無序，但**與上列三表是內容耦合的一組，必須同包**：三表的成員一律寫成「去分隔符、全小寫」形式，正因為比對前先過本 Replacer（故 `connect_token`／`connectToken`／`CONNECT-TOKEN` 同命中）。分家後有人改了正規化規則或表的寫法，比對會**永遠不命中且無編譯錯誤**——遮蔽函式照跑、輸出全是明文。以包級全域而非每次呼叫重建，是因為 access log 在每個請求的熱路徑上（每請求每參數重建一次 Replacer）。 |
| G-99 | var:internal/api/recording_token.go:recordingIssueGateWarnOnce | recordingIssueGateWarnOnce | internal/api/recording_token.go:133 | 包級全域／一次性告警 | 不搬（接入層） | —（不動） | 無序（僅去重 log）。 |
| G-100 | var:internal/api/seal_handler.go:sealErrorStatus | sealErrorStatus | internal/api/seal_handler.go:316 | 包級全域／不可變對照表 | 不搬（接入層） | —（不動） | 無序——封印機器碼到 HTTP 狀態的固定對照；由 `seal_codes_test.go` 釘住與 `internal/seal` 常數的雙射。 |
| G-101 | var:internal/api/key_rewrap_payload.go:rewrapVariantKeys | rewrapVariantKeys | internal/api/key_rewrap_payload.go:108 | 包級全域／不可變查表 | 不搬（接入層） | —（不動） | 無序。 |
| G-102 | var:internal/api/key_rewrap_payload.go:rewrapKnownFields | rewrapKnownFields | internal/api/key_rewrap_payload.go:115 | 包級全域／不可變查表 | 不搬（接入層） | —（不動） | 無序，但為未知欄位 fail-close 的判準來源。 |
| G-103 | var:internal/api/ldap_directory_handler.go:ldapURLReasonCodes | ldapURLReasonCodes | internal/api/ldap_directory_handler.go:129 | 包級全域／不可變碼對照 | 不搬（接入層） | —（不動） | 無序；i18n 機器碼對照，由 apierror 完備性守衛涵蓋。 |
| G-104 | var:internal/api/ldap_directory_handler.go:ldapFilterReasonCodes | ldapFilterReasonCodes | internal/api/ldap_directory_handler.go:143 | 包級全域／不可變碼對照 | 不搬（接入層） | —（不動） | 同 G-103。 |
| G-105 | var:internal/api/ldap_directory_handler.go:ldapFieldReasonCodes | ldapFieldReasonCodes | internal/api/ldap_directory_handler.go:156 | 包級全域／不可變碼對照 | 不搬（接入層） | —（不動） | 同 G-103。 |
| G-106 | var:internal/api/oidc_redirect_allowlist.go:frontendRouteSegments | frontendRouteSegments | internal/api/oidc_redirect_allowlist.go:15 | 包級全域／不可變允許清單 | 不搬（接入層） | —（不動） | 無序，但**內容即開放重導向的邊界**；由前端 router 掛載守衛雙向核對。 |
| G-107 | var:internal/proxy/handler.go:upgrader | upgrader | internal/proxy/handler.go:31 | 包級全域／不可變 WS 設定 | 不搬（接入層） | —（不動） | 無序——`websocket.Upgrader` 設定於初始化期定值。 |
| G-108 | var:internal/proxy/tunnel.go:clientInputOpcodes | clientInputOpcodes | internal/proxy/tunnel.go:43 | 包級全域／不可變查表 | 不搬（接入層） | —（不動） | 無序，但為 guacd 通道輸入過濾的判準。 |
| G-108b | var:internal/proxy/file_tap.go:fileTapForward | fileTapForward | internal/proxy/file_tap.go:42 | 包級全域／不可變 verdict 哨兵 | 不搬（接入層） | —（data-transfer-control 期 1 新增） | 無序（初始化期定值後只讀），但**值即放行語義**：`FileTapVerdict` 的零值刻意是「不轉發」，新增分支忘了設 `Forward` 的失敗方向因此是擋住而非放行。**本哨兵是唯一一個 `Forward: true` 的來源**——它若被誤改成零值，guac 通道全數檔案指令被靜默擋下；若被改成可變並於執行期覆寫，資料傳輸閘的放行判定就多出一個不受政策管的旁路。 |
| G-109 | var:internal/sshproxy/handler.go:upgrader | upgrader | internal/sshproxy/handler.go:37 | 包級全域／不可變 WS 設定 | 不搬（接入層） | —（不動） | 同 G-107。 |
| G-110 | var:internal/sshproxy/monitor.go:monitorWriteTimeout | monitorWriteTimeout | internal/sshproxy/monitor.go:29 | 包級全域／可置換逾時 | 不搬（接入層） | —（不動） | 無序；`var` 而非 `const` 僅為測試以極短逾時驗證慢速觀察者被移除。 |
| G-111 | var:internal/sshproxy/command_parser.go:altScreenEnterMarks | altScreenEnterMarks | internal/sshproxy/command_parser.go:23 | 包級全域／不可變位元組樣式 | 不搬（接入層） | —（不動） | 無序。 |
| G-112 | var:internal/sshproxy/command_parser.go:altScreenExitMarks | altScreenExitMarks | internal/sshproxy/command_parser.go:29 | 包級全域／不可變位元組樣式 | 不搬（接入層） | —（不動） | 無序。 |
| G-113 | var:internal/k8sproxy/conn.go:distrolessHint | distrolessHint | internal/k8sproxy/conn.go:130 | 包級全域／不可變提示字串 | 不搬（接入層） | —（不動） | 無序。 |
| G-114 | var:internal/seal/journal.go:validOutcomes | validOutcomes | internal/seal/journal.go:66 | 包級全域／不可變值域 | 不搬（封印骨架） | —（不動） | 無序，但為 journal 結果碼的**封閉值域**：與 `cells` 表（G-116）的 `Outcome` 欄互為約束，兩者被拆散時不合法碼可靜默寫入 journal。 |
| G-115 | var:internal/seal/journal.go:validRejectedKinds | validRejectedKinds | internal/seal/journal.go:75 | 包級全域／不可變值域 | 不搬（封印骨架） | —（不動） | 同 G-114。 |
| G-116 | var:internal/seal/transitions.go:cells | cells | internal/seal/transitions.go:100 | 包級全域／有序狀態機遷移表 | 不搬（封印骨架） | —（不動） | **12 格遷移表，順序即表列順序、且是狀態機的唯一判準來源**（`Resolve` 依序比對 `match`）。重排會改變命中格（`TestCellsPairwiseExclusive` 以窮舉笛卡兒積驗證兩兩互斥，故重排若造成重疊會被抓到；但互斥前提下重排仍改變 `Resolve` 的遍歷成本與可讀對照）。B 模式的解封／逾時／收束全部由此表決定。 |
| G-117 | var:internal/sealjournal/fileio.go:syncDirFn | syncDirFn | internal/sealjournal/fileio.go:33 | 包級全域／測試可置換入口 | 不搬（封印骨架） | —（不動） | 同 G-49 形態。**語義關鍵**：首次建立 journal 後未同步目錄項時，崩潰後檔案可能不存在，下次啟動從零起算而抹除單調計數器。測試以置換此入口斷言「首次建立確有同步」——跨包後注入不進去即守衛失效。 |
| G-118 | var:internal/sealjournal/format.go:castagnoli | castagnoli | internal/sealjournal/format.go:81 | 包級全域／不可變 CRC 表 | 不搬（封印骨架） | —（不動） | 無序，但**值不可變**：CRC 多項式改變＝既有 journal 全部驗章失敗。 |
| G-119 | var:internal/sealjournal/replay.go:nsEvent | nsEvent | internal/sealjournal/replay.go:13 | 包級全域／UUID 命名空間 | 不搬（封印骨架） | —（不動） | 同 G-77（回灌去重鍵的來源，值不可變）。 |
| G-120 | var:internal/sealjournal/replay.go:nsAggregate | nsAggregate | internal/sealjournal/replay.go:14 | 包級全域／UUID 命名空間 | 不搬（封印骨架） | —（不動） | 同 G-119。 |
| G-121 | var:pkg/crypto/kms/arn.go:canonicalKeyARN | canonicalKeyARN | pkg/crypto/kms/arn.go:53 | 包級全域／不可變 regexp | 不搬（crypto） | —（不動） | 無序。 |
| G-122 | var:pkg/crypto/kms/client.go:endpointOverrideEnvKeys | endpointOverrideEnvKeys | pkg/crypto/kms/client.go:61 | 包級全域／不可變 env 鍵清單 | 不搬（crypto） | —（不動） | 無序，但為 endpoint 覆寫閘的判準；`endpoint_gate_test.go` 釘住其寫入允許清單。 |
| G-123 | var:pkg/crypto/kms/retry.go:describeTotalBudget | describeTotalBudget | pkg/crypto/kms/retry.go:37 | 包級全域／可置換預算 | 不搬（crypto） | —（不動） | 無序；`TestRetryBudgetConstantsAreProductionValues` 釘住產品值（SHALL < 10s），產品路徑永不改寫。 |
| G-124 | var:pkg/crypto/kms/retry.go:describeBaseBackoff | describeBaseBackoff | pkg/crypto/kms/retry.go:39 | 包級全域／可置換退避 | 不搬（crypto） | —（不動） | 同 G-123。 |
| G-125 | var:pkg/crypto/kms/retry.go:retryableCodes | retryableCodes | pkg/crypto/kms/retry.go:59 | 包級全域／不可變查表 | 不搬（crypto） | —（不動） | 無序。 |
| G-126 | var:pkg/crypto/kms/retry.go:transientSyscallErrs | transientSyscallErrs | pkg/crypto/kms/retry.go:100 | 包級全域／不可變錯誤清單 | 不搬（crypto） | —（不動） | 無序。 |

> **編號說明**：G-* 為人讀用的穩定 ID，守衛只比對錨點鍵；上表最後一列不是登記列（錨點鍵欄非受管前綴，守衛自動忽略）。

---
| G-129 | var:internal/k8sproxy/client.go:policyMu | policyMu | internal/k8sproxy/client.go:93 | 包級全域／保護鎖 | 不搬（接入層 k8sproxy） | —（不動） | 與 G-130 是同一份狀態的鎖與值，**必須同包**（同 G-6／G-7 的形態）。`listTimeout()` 本身即包級函式、三個呼叫點都不持有服務實例，故政策來源只能掛在包級；讀寫跨 goroutine（組裝根注入 vs. 連線期列表），拆散後兩側各持一把鎖即互斥失效且無編譯錯誤。 |
| G-130 | var:internal/k8sproxy/client.go:policySrc | policySrc | internal/k8sproxy/client.go:94 | 包級全域／政策來源 | 不搬（接入層 k8sproxy） | policy-numeric-lower-bounds | 叢集列表逾時的執行期事實源（`k8s_list_timeout_seconds`；env 僅為初值）。**nil＝退回 env→預設**，故漏注入不報錯而是靜默沿用啟動時的 env 值——管理員在政策頁為慢叢集調高逾時將完全不生效，且頁面顯示的值與實際行為不一致。 |
| G-138 | var:config/kek.go:KEKGenerateCommands | KEKGenerateCommands | config/kek.go:73 | 包級全域／不可變文件化指令集合 | 不搬（config） | —（kek-encoding-and-unseal-entry 新增） | 無序（字面量於載入期定值後只讀），但**內容即「文件叫人做的事」與「系統會不會接受」之間的唯一事實源**：列 3b 錯誤訊息、`.env.example`（env 漂移守衛比對）、解封頁與換鑰精靈的指令參考、以及實跑守衛全部讀它。取代已刪除的 `const:KEKGenerateCommand`（單一指令改為每形態一條的集合）。**拆包時不得複製成兩份**——兩份會讓範本列一組、介面列另一組而無編譯錯誤，而該不一致正是本次缺陷的形狀（operator 照著看到的指令做卻被拒）。集合被清空則錯誤訊息與介面同時失去自救線索，操作者只能自行發明指令。 |
| G-139 | var:pkg/crypto/kek_material.go:kekBase64Encodings | kekBase64Encodings | pkg/crypto/kek_material.go:76 | 包級全域／不可變編碼變體表 | 不搬（crypto） | —（kek-encoding-and-unseal-entry 新增） | 無序（載入期定值後只讀），但**成員與順序都具語義**：四個變體（Std／RawStd／URL／RawURL，皆 Strict）逐一嘗試，第一個解出 32 位元組者勝出。四者互斥（padding 長度不同、兩套字母表的非英數字元互斥），故順序不改變任何輸入的結果——但**刪掉任一成員即是把一種正確的金鑰寫法變成不可用**（例如移除 RawStd 會拒絕 43 字元無 padding 的 base64），而移除 `.Strict()` 會讓同一把金鑰有多份非規範編碼都解得開。此表是「輸入編碼」與「金鑰」分層的落點，**不得與 KEKAlphabet（原字元形態的字元集政策）合併**——後者只約束原字元形態。 |
| G-140 | var:pkg/crypto/password_hasher.go:defaultHasher | defaultHasher | pkg/crypto/password_hasher.go:168 | 包級全域／不可變單例（產線密碼雜湊實作） | 不搬（crypto） | —（password-hasher-interface） | **無序但不可有第二份**。以 `NewBcryptHasher(BcryptDefaultCost)` 在包初始化時建構，常數參數故不依賴任何其他初始化，順序上無前置需求。**若被改成各處自建或允許執行期置換會發生什麼**：「當前演算法／參數」會散成多份，`Verifier.NeedsRehash` 的判定依呼叫端而異——同一個雜湊在登入路徑判定要升級、在改密路徑判定不用，漸進遷移於是變成不確定行為，且可能反覆重雜湊。故 `DefaultPasswordHasher()`／`DefaultPasswordVerifier()` 是唯一取得入口，產品碼不得自行 `NewBcryptHasher`（`internal/guards/passwordhash` 守衛禁止直接 import 演算法庫，但自建 Hasher 不在其射程，此處以單一入口的慣例承擔）。 |
| G-141 | var:internal/modules/audit/audit_log_service.go:auditSortableColumns | auditSortableColumns | internal/modules/audit/audit_log_service.go:407 | 包級全域／不可變白名單（審計日誌排序欄位收斂表） | audit | —（CodeQL go/sql-injection 修復新增） | 無序（載入期定值後只讀），但**成員即安全邊界**：這是 `List` 對使用者可控 `sort_by` 的唯一收斂依據——ORDER BY 的識別字位置無法參數化，只能列舉，不在表內者一律落回 `created_at`。**增刪的後果不對稱**：漏列一個合法欄位只是該欄排序被靜默降級（使用者點了沒反應、無錯誤）；而把表清空、或改成黑名單／正則放行形態，等於把 SQL 注入原樣打開——`fmt.Sprintf` 拼出的子句會逐字進 SQL（GORM 對 string 型 `.Order()` 以 Raw 寫入，不參數化）。故拆包時此表不得離開 `List` 的可視範圍，亦不得由呼叫端覆寫。守衛見 `internal/modules/audit/audit_log_sort_injection_test.go`。 |

## 3. `init()` 函式（`init:`，5 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| I-1 | init:internal/notifycat/render.go:init | 載入三語通知模板 → `catalog` | internal/notifycat/render.go:30 | init() | 不搬（橫切 i18n） | —（不動） | 讀 `localeFS`（G-30）填 `catalog`（G-29），缺檔／解析失敗即 panic。**必須早於任何出站通知渲染**；同包由 Go 保證，`catalog` 與本 `init()` 分包則順序未定義（渲染會讀到空 map，通知變成空標題空內文而不報錯）。 |
| I-2 | init:internal/notifycat/lexicon.go:init | 載入三語詞庫 → `lexiconCat` | internal/notifycat/lexicon.go:89 | init() | 不搬（橫切 i18n） | —（不動） | 同 I-1（`Phrase()` 未命中時回吐機器碼本身，故初始化未完成的症狀是「使用者看到機器碼」而非錯誤）。 |
| I-3 | init:internal/modules/policy/security_policy_service.go:init | 依 `Unit` 衍生 `UnitKey` ＋ `validatePolicyDefs` | internal/modules/policy/security_policy_service.go:672 | init() | policy | W3 | 就地改寫 `policyDefs`（G-23）並驗證不變式，違規即 panic（fail-fast）。**搬檔時本 `init()` 必須與 `policyDefs`／`unitKeyByZh` 同包**；分包後若別包在初始化完成前讀 `policyDefs`，取得的是 `UnitKey` 空白的半成品，政策 API 回傳缺 `unit_key` 而前端顯示無單位——無錯誤、無測試失敗。 |
| I-4 | init:internal/modules/policy/transmission_policy_service.go:init | `registerRisk` × 8 → `riskDefs` | internal/modules/policy/transmission_policy_service.go:115 | init() | policy | W3 | 填充 `riskDefs`（G-25），重複註冊或 template↔params 不符即 panic。**`newRisk` 是唯一 sanctioned 建構子且只從此表取**；後續要匯出 `newRisk` 供 identity 消費，屆時 identity 包的初始化必須晚於 policy 包（由 import 方向 identity→policy ✔ 保證）——**方向若被反轉即出現初始化競態**。 |
| I-5 | init:internal/modules/policy/transmission_inventory_service.go:init | `registerInventory` × 13 → `inventoryDefs` | internal/modules/policy/transmission_inventory_service.go:157 | init() | policy | W3 | 同 I-4 形態。**本檔是 §3.1 的 4.11 policy↔audit 真環所在**；`ChannelInventoryProvider` 反轉未完成即搬檔，會把「policy 包初始化依賴 audit 包」這條隱性順序固化進 import 圖。 |

---

## 4. 組裝根注入／註冊呼叫點（`hook:` 72 筆＋`inject:` 15 筆）

> 依注入發生的位置分節（段 1、段 2 主序、封印接線、裸欄位注入）。**列序即程式碼中的出現序**（同一檔內）。

### 4.1 段 1（`cmd/server/stage1.go`，2 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| H-1 | hook:cmd/server/stage1.go:database.InitDatabase | `database.InitDatabase(cfg)` | cmd/server/stage1.go:156 | 啟動步驟／全域資源初始化 | infra（**已改名** `internal/database`） | W7 | **賦值 G-20 全域 handle 的唯一位置**，且必須晚於全部 DB-independent 的組態與金鑰驗證（`stage1.go:86-145`）——那條界線的目的是「任何金鑰設定錯誤在任何持久化（含 seed 初始 admin）之前即 fail-close，不留半初始化的 DB」。提前連 DB 會讓 fail-close 路徑留下寫入。 |
| H-66 | hook:cmd/server/stage1.go:s.metrics.SetInstanceGuardSource | `s.metrics.SetInstanceGuardSource(instanceGuardMetricsSource)` | cmd/server/stage1.go:263 | setter 後綁定（現讀資料源） | assembly ← observability／database | single-instance-guard | 四條守衛序列（held／lost_total／overridden／peers）的現讀來源。**必須在段 1、指標實例建構之後、任何監聽開放之前**：守衛自段 1 起存在，封印期就要能採集。漏注入的症狀是四序列**缺席**（collector 對 nil 資料源刻意不曝光、非 0），「守衛不存在」與「未持鎖」在採集端可分辨，但失守自此無指標可告警。 |

### 4.2 段 2 主序（`cmd/server/stage2.go`，55 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| H-2 | hook:cmd/server/stage2.go:keyvault.InitKeyManager | `keyvault.InitKeyManager(repository.DB, kek)` | cmd/server/stage2.go:178 | singleton／啟動步驟 | keyvault | W2 | **段 2 第一步**。其後每一個吃 `crypto.ColumnCodec` 的服務（LDAP 目錄、通知通道、匯出簽章、OIDC provider、告警推送）都依賴它已就緒；提前任何一個即取得 nil codec，症狀是首次解密才失敗。 |
| H-3 | hook:cmd/server/stage2.go:keyManager.ZeroizeForRelease | bag 內 `keyManager.ZeroizeForRelease()` | cmd/server/stage2.go:185 | zeroize（釋放） | keyvault | W2 | 登記於 bag 第 2 位 ⇒ **LIFO 下倒數第 2 個執行**（`sealJournalReplay` 之後）。這是遷移表格 5b「清除已解封的 KEK」的落點：晚於它的任何釋放項若仍需解密（例如推送器歸零通道明文），就會打到已歸零的金鑰。現況序列正確——`alertNotifier`（release 9）在 `keyManager`（release 2）之後登記、故先釋放。 |
| H-4 | hook:cmd/server/stage2.go:ldapDirectoryService.SetTransmissionPolicy | `ldapDirectoryService.SetTransmissionPolicy(transmissionPolicy)` | cmd/server/stage2.go:240 | setter 後綁定 | identity ← policy | W3／W8 | **打環序**：先建目錄服務 → 以其 `RiskViewProvider()` 建傳輸政策 → 回頭注入。三步任一提前都會取得 nil。後續 §3.5 要把 6 個 LDAP 符號遷入 policy，遷後方向為 identity→policy ✔；**遷移中途的中間態會同時存在兩個方向**，故該項搬檔（3.7）須與 3.2 同一批完成。 |
| H-5 | hook:cmd/server/stage2.go:audit.InitAuditFailure | `service.InitAuditFailure(repository.DB, policyService)` | cmd/server/stage2.go:246 | singleton／啟動步驟 | audit | W4 | 必須早於 H-7（`SetFailureReporter` 的閉包捕獲本單例）。且緊接的 `ReconcileOnStartup()` 回填重啟遺留的進行中事件——**不回填即成永久懸掛的失效事件**。 |
| H-6 | hook:cmd/server/stage2.go:audit.ResetAuditFailureSingleton | bag 內 `service.ResetAuditFailureSingleton()` | cmd/server/stage2.go:249 | reset（釋放） | audit | W4 | 釋放時解單例；晚於它釋放的項目若仍呼叫 `Report()`，會建立新單例而洩漏一份服務圖。 |
| H-7 | hook:cmd/server/stage2.go:audit.InitSyslogForwarder | `service.InitSyslogForwarder(repository.DB)` | cmd/server/stage2.go:260 | singleton／啟動步驟 | audit | W4 | 必須早於 H-8 與 `Start()`。 |
| H-8 | hook:cmd/server/stage2.go:syslogForwarder.SetFailureReporter | `syslogForwarder.SetFailureReporter(...)` | cmd/server/stage2.go:261 | setter 後綁定 | audit | W4 | **必須先於 `Start()`（`:222`）**：run loop 啟動後再無鎖寫 `onFailure` 是 data race（同檔註解自陳）。反序的症狀是 `-race` 下偶發紅、生產下 syslog 失效不產生失效事件。 |
| H-9 | hook:cmd/server/stage2.go:audit.InitAuditIntegrityVersioned | `service.InitAuditIntegrityVersioned(repository.DB, keyManager)` | cmd/server/stage2.go:278 | singleton／啟動步驟 | audit（依賴 keyvault） | W4 | **§3.1 的 4.10 audit→keyvault 反向邊**（蓋章需 `km`），該方向保留為合法單向。必須早於 H-10；且整體必須早於任何寫審計列的步驟。 |
| H-10 | hook:cmd/server/stage2.go:model.SetAuditCreateHooks | `model.SetAuditCreateHooks(auditIntegrity.StampOne, syslogForwarder.EnqueueAuditLog)` | cmd/server/stage2.go:285 | hook 註冊 | audit → model | W4 | **全案最危險的三個順序敏感點之一**。註冊之前寫出的任何審計列 `IntegrityHMAC` 為空且不進 syslog tee，而驗章端會把空章列當成上線前的歷史列（不計入竄改判定）。既有守衛 `post_unseal_guard_test.go:182` 只釘「同檔且先於遷移呼叫」，**不釘「先於全部審計寫入」**——搬檔時本行 SHALL NOT 後移，且 4.13 明列「hook 註冊順序未動」為該階段驗收項。 |
| H-11 | hook:cmd/server/stage2.go:model.SetAuditCreateHooks | bag 內 `model.SetAuditCreateHooks(nil, nil)` | cmd/server/stage2.go:288 | hook 解除（釋放） | audit → model | W4 | 與 H-10 同鍵但語義相反，故各佔一列（守衛以多重集合比對，少一列即紅）。**必須早於同一個 bag 項內的 `ResetAuditIntegritySingleton`（H-12）**：反序期間 GORM 直寫路徑仍呼叫已釋放物件的 `StampOne`。 |
| H-12 | hook:cmd/server/stage2.go:audit.ResetAuditIntegritySingleton | bag 內 `service.ResetAuditIntegritySingleton()` | cmd/server/stage2.go:289 | reset（釋放） | audit | W4 | 見 H-11。 |
| H-55 | hook:cmd/server/stage2.go:checkpointService.SetPolicySource | `checkpointService.SetPolicySource(policyService)` | cmd/server/stage2.go:650 | setter 後綁定 | audit ← policy | —（audit-chain-scheduled-verification 新增；原誤用已被 `retentionService.UseCheckpointIntervals` 佔用的 H-51，2026-08-13 由登記表單一寫者改編為 H-55） | 封章門檻的執行期事實源（env 僅為初值）。**必須在封章排程啟動之前注入**：漏注入不會報錯，而是靜默沿用 env 初值——管理員在安全政策頁調短封存週期以縮小未封窗口（誠實邊界 R5）將完全不生效，且頁面顯示的值與實際行為不一致。注入本身無副作用、可重入。 |
| H-13 | hook:cmd/server/stage2.go:keyvault.RegisterPostUnsealBuiltin | `keyvault.RegisterPostUnsealBuiltin(service.PostUnsealMigrationLDAPSeed, service.RegisterLDAPSeedMigration)` | cmd/server/stage2.go:307 | 套件層註冊 | assembly（已自 keyvault 上移） | W1（1.10，已完成） | **必須早於下一行的 `RunPostUnsealMigrations`（`:259`），且兩者都必須晚於 H-10**。登記動作已上移組裝根以拆 4.9 keyvault↔identity 環：identity 匯出自己的 `RegisterLDAPSeedMigration`，由本呼叫注入 keyvault 的登記器清單（G-60b）。**日後每加一個內建遷移即多一行登記，全部 SHALL 落在 `Run` 之前**，否則佇列在執行時只有一半——`post_unseal_guard_test.go` 的 `TestAssemblyRegistersPostUnsealBuiltins` 對本檔逐條斷言（含具名清單，防止某一行被刪後包內測試仍綠）。 |
| H-13b | hook:cmd/server/stage2.go:identity.RegisterLDAPSeedMigration | 登記器閉包內 `service.RegisterLDAPSeedMigration(auditTxSink)` | cmd/server/stage2.go:308 | 套件層註冊（閉包內） | identity ← audit | W4（4.4／AP-51） | **收口時新增**：登記器自無參數改為收 `port.TxSink`（seed 的插列＋審計＋marker 同事務，審計改經 TxSink 後需要落地面），故組裝根改以閉包呼叫。**捕獲的 `auditTxSink` 必須在此之前建立並通過 `requireAuditTxSink` 自檢**（`stage2.go:186` 一帶）——捕獲 nil 的後果是 seed 審計寫入回 `port.ErrTxSinkMissing`，整筆 seed 回滾、marker 未寫、下次啟動重試（fail-close，非靜默）。H-13 的「登記須早於 `RunPostUnsealMigrations`」不變。 |
| H-64 | hook:cmd/server/stage2.go:keyvault.RegisterPostUnsealBuiltin | `keyvault.RegisterPostUnsealBuiltin(session.PostUnsealMigrationClipboardContent, session.RegisterClipboardContentMigration)` | cmd/server/stage2.go:334 | 套件層註冊 | assembly ← session | —（workbench-clipboard-and-layout 1.2 新增） | 與 H-13 同鍵（守衛以多重集合比對，第二個登記呼叫即第二列）。剪貼簿明文欄→信封加密欄轉換需要 codec，故走 post-unseal 佇列；**必須早於同檔 `RunPostUnsealMigrations`**（TestAssemblyRegistersPostUnsealBuiltins 具名斷言），晚於它即佇列執行時缺此項——既有帶明文欄的資料庫將停留在舊形狀，model 查詢以 column does not exist 大聲失敗（fail-visible，非靜默）。 |
| H-14 | hook:cmd/server/stage2.go:authService.SetSecurityPolicies | `authService.SetSecurityPolicies(policyService)` | cmd/server/stage2.go:326 | setter 後綁定 | identity ← policy | W8 | 未注入時鎖定與密碼 validator 讀不到政策值，會退回硬編碼預設——**登入鎖定政策靜默失效**（PCI 8.3.4）。方向 identity→policy ✔。 |
| H-14b | hook:cmd/server/stage2.go:authService.SetEpochGateDB | `authService.SetEpochGateDB(database.DB)` | cmd/server/stage2.go:336 | setter 後綁定 | identity | W8（獨立驗收補接） | 憑證世代閘的資料來源。**注入的即回退分支會取到的同一個 `database.DB`**，故行為零變更；顯式注入的價值在於「組裝路徑漏接」不再被 identity 內部的全域回退默默補上（B-32 登記的風險）。**必須晚於 `database.InitDatabase`（stage1）、早於任何簽發或驗證路徑**——段 2 期間尚未開放監聽，故落在此處即滿足。行為面由 `TestAssemblyInjectsEpochGateDB` 釘住（拔掉全域仍能判定）。 |
| H-15 | hook:cmd/server/stage2.go:authService.SetLDAPResolver | `authService.SetLDAPResolver(service.NewLDAPLoginResolver(ldapDirectoryService))` | cmd/server/stage2.go:344 | setter 後綁定 | identity | W8 | **恆注入、無 `cfg.LDAP.Enabled` 分支**（設定遷入 DB 後由執行期查詢表達）。漏注入＝LDAP 登入全數失敗且與「未啟用」不可分辨。 |
| H-16 | hook:cmd/server/stage2.go:authService.SetTransmissionPolicy | `authService.SetTransmissionPolicy(transmissionPolicy)` | cmd/server/stage2.go:347 | setter 後綁定 | identity ← policy | W8 | LDAP 登入傳輸閘（warn 留痕／strict 拒絕）。漏注入＝strict 政策不生效，明文目錄連線被放行。 |
| H-17 | hook:cmd/server/stage2.go:assetService.SetTransmissionPolicy | `assetService.SetTransmissionPolicy(transmissionPolicy)` | cmd/server/stage2.go:355 | setter 後綁定 | asset ← policy | W6 | 資產列表傳輸風險徽章。漏注入＝徽章消失（可觀察，風險較低）。 |
| H-18 | hook:cmd/server/stage2.go:userService.SetSecurityPolicies | `userService.SetSecurityPolicies(policyService)` | cmd/server/stage2.go:426 | setter 後綁定 | identity ← policy | W8 | 密碼合規判定的政策來源。**後續要把 `checkPasswordCompliance` 拆入 policy 並匯出為 `policy.CheckCompliance`**（屆時改消費端），拆檔期間本注入不得斷——斷了即密碼政策不生效而改密全部放行。 |
| H-19 | hook:cmd/server/stage2.go:userService.SetSessionTerminator | `userService.SetSessionTerminator(sessionService)` | cmd/server/stage2.go:427 | setter 後綁定 | identity ← session（介面反轉） | W8／W9 | 停用帳號即時撤權收線。**必須晚於 `sessionService` 建構（step 12）**。漏注入＝停用帳號後進行中協議會話不斷線，即「撤權有延遲窗口」——安全紅線。矩陣 identity→session 為 ✗（介面反轉），故此處注入的是窄介面。 |
| H-20 | hook:cmd/server/stage2.go:userService.SetAuditSink | `userService.SetAuditSink(auditService)` | cmd/server/stage2.go:429 | setter 後綁定 | identity ← audit | W8 | 外部身分管理四操作的審計出口。**漏注入＝該四操作零審計留痕**且無任何錯誤，是「某段窗口審計未蓋章」的同型風險。sink 雙變體落地後本注入改吃 `AsyncSink`，4.7 要求 nil sink 啟動即 fail-close。 |
| H-21 | hook:cmd/server/stage2.go:audit.InitAlertMatcher | `service.InitAlertMatcher(repository.DB)` | cmd/server/stage2.go:443 | singleton／啟動步驟 | audit | W4 | 啟動即載入規則快取供 recorder 路徑比對；載入失敗不致命（無快取＝不告警）。**注意 `alert_matcher.go:203,205` 的寬鬆跳過**——4.7 明訂 nil sink 自檢不得沿用此寬鬆形態。 |
| H-22 | hook:cmd/server/stage2.go:audit.ResetAlertMatcherSingleton | bag 內 `service.ResetAlertMatcherSingleton()` | cmd/server/stage2.go:448 | reset（釋放） | audit | W4 | 同 H-6 形態。 |
| H-23 | hook:cmd/server/stage2.go:audit.InitAlertNotifier | `service.InitAlertNotifier(repository.DB, keyManager)` | cmd/server/stage2.go:458 | singleton／啟動步驟 | audit（依賴 keyvault） | W4 | 建單例並起推送 worker；**worker 啟動後即持有解密後的通道 URL／secret**（KEK 衍生材料）。必須晚於 H-2。 |
| H-24 | hook:cmd/server/stage2.go:audit.StopAlertNotifierForRelease | bag 內 `service.StopAlertNotifierForRelease(alertNotifier)` | cmd/server/stage2.go:466 | reset＋zeroize（釋放） | audit | W4 | **三步順序是契約**（解單例 → 歸零通道明文 → 關佇列），且**呼叫端 SHALL 先停排程器**——`changeSecret`／`accessRequest` 兩個排程器登記於本項之後，LIFO 下必然先停；它們是唯二持有本物件直接參考（不經單例）的路徑。此順序若被打破，in-flight `Enqueue` 會對已關閉佇列 `send` 而 panic。**搬檔不得改動 bag 登記位置。** |
| H-25 | hook:cmd/server/stage2.go:notificationChannelService.SetTransmissionPolicy | `notificationChannelService.SetTransmissionPolicy(transmissionPolicy)` | cmd/server/stage2.go:483 | setter 後綁定 | audit ← policy | W4 | 通知通道設定的傳輸政策閘。漏注入＝http 明文通道可被存檔。方向 audit→policy ✔（保留）。 |
| H-26 | hook:cmd/server/stage2.go:exportSigning.ZeroizeForRelease | bag 內 `exportSigning.ZeroizeForRelease()` | cmd/server/stage2.go:511 | zeroize（釋放） | keyvault | W2 | 解密後常駐記憶體的 Ed25519 私鑰，與 KEK 同級。登記於 bag 第 10 位 ⇒ 早於 `keyManager`（第 2 位）釋放，**順序正確**（先歸零衍生材料、再歸零根材料）。反序不會 panic，但會留下「根已清、衍生仍在」的窗口。 |
| H-26b | hook:cmd/server/stage2.go:checkpointSigning.ZeroizeForRelease | bag 內 `checkpointSigning.ZeroizeForRelease()` | cmd/server/stage2.go:526 | zeroize（釋放） | keyvault | —（audit-checkpoint-chain 新增） | 同 H-26，但歸零的是**多版本**私鑰表：檢查點簽章鑰自始帶版本欄，記憶體同時持有歷史版本（供輪替後重驗歷史檢查點），只清 active 版本會把同樣能偽造歷史區間的舊版材料留在記憶體。登記於 bag 第 11 位 ⇒ 仍早於 `keyManager`（第 2 位）釋放。 |
| H-27 | hook:cmd/server/stage2.go:assetService.SetHostKeyService | `assetService.SetHostKeyService(hostKeyService)` | cmd/server/stage2.go:546 | setter 後綁定 | asset | W6 | SSH 直連測試共用 TOFU。漏注入＝直連測試跳過 host key 驗證（中間人風險）。 |
| H-28 | hook:cmd/server/stage2.go:userService.SetSubscriptionTerminator | `userService.SetSubscriptionTerminator(sshHandler.Monitor)` | cmd/server/stage2.go:553 | 反向後綁定（service ← 連線層） | identity ← 接入層 | W8 | **跨層方向由下往上**，且必須晚於 `sshHandler` 建構。監看與分享觀看不建 `sessions` 列，`SessionTerminator`（H-19）完全掃不到它們——漏注入＝解綁外部身分後唯讀訂閱仍存活，屬撤權不完整。 |
| H-29 | hook:cmd/server/stage2.go:oidcProviderService.SetSessionTerminator | `oidcProviderService.SetSessionTerminator(sessionService)` | cmd/server/stage2.go:558 | setter 後綁定 | identity ← session | W8／W9 | provider 停用／刪除／密鑰輪替推進 `auth_epoch` 後主動收線已建立的協議連線。**世代閘只能拒絕「下一次出示憑證」，長連線建立後不再出示憑證**——漏注入＝已建立的連線永不斷。 |
| H-30 | hook:cmd/server/stage2.go:oidcProviderService.SetSubscriptionTerminator | `oidcProviderService.SetSubscriptionTerminator(sshHandler.Monitor)` | cmd/server/stage2.go:559 | 反向後綁定 | identity ← 接入層 | W8 | 同 H-28（provider 級）。 |
| H-31 | hook:cmd/server/stage2.go:accessRequestService.SetSessionService | `accessRequestService.SetSessionService(sessionService)` | cmd/server/stage2.go:620 | setter 後綁定 | authz ← session | W7／W9 | break-glass 撤銷即斷線政策。漏注入＝撤銷票證後會話續存，破窗遏制失效。 |
| H-32 | hook:cmd/server/stage2.go:authHandler.SetUserService | `authHandler.SetUserService(s.userService)` | cmd/server/stage2.go:915 | handler ← service 後綁定 | 接入層 ← identity | W8 | 於 `buildRouteDeps` 內（自陳「純建構＋依賴注入，無 I/O 副作用」）。**`routeDeps` 契約明文要求全部成員於 `registerRoutes` 之前完成注入**（`main.go:369`）——漏注入＝該端點 nil deref panic（可見，風險較低）。 |
| H-32b | hook:cmd/server/stage2.go:authHandler.SetRefreshCookieWriter | `authHandler.SetRefreshCookieWriter(refreshCookies)` | cmd/server/stage2.go:1017 | handler ← 部署期常數 後綁定 | 接入層 ← config | —（refresh-token-httponly-cookie 新增） | 於 `buildRouteDeps` 內，與 H-32 同批。注入的是**三個 handler 共用的同一個 writer**（`Secure` 旗標於啟動時自 `cfg.Security.RefreshCookie` 推導定值，不逐請求重算）。**漏注入不會 panic 也不會有測試轉紅**——建構函式已備妥同源的 fail-safe 預設（`defaultRefreshCookieWriter`，自同一組 env 推導），故漏接的後果只是「三個 handler 各持一份等值實例」而非行為改變。此注入無 I/O 副作用、可重入，順序上只需早於 `registerRoutes`。 |
| H-32c | hook:cmd/server/stage2.go:oidcHandler.SetRefreshCookieWriter | `oidcHandler.SetRefreshCookieWriter(refreshCookies)` | cmd/server/stage2.go:1021 | handler ← 部署期常數 後綁定 | 接入層 ← config | —（refresh-token-httponly-cookie 新增） | 同 H-32b，對象為 OIDC handler。**必須晚於 `api.NewOIDCHandler`**（本 change 把該建構自 `routeDeps` 字面量內提到前面，正是為了取得可注入的變數）——順序反了是編譯錯誤，不會靜默。 |
| H-33 | hook:cmd/server/stage2.go:syslogSettingHandler.SetTransmissionPolicy | `syslogSettingHandler.SetTransmissionPolicy(s.transmissionPolicy)` | cmd/server/stage2.go:922 | handler ← service 後綁定 | 接入層 ← policy | W3 | 同 H-32；漏注入＝syslog 設定頁的傳輸政策閘不生效。 |
| H-34 | hook:cmd/server/stage2.go:commandAlertHandler.SetAuditService | `commandAlertHandler.SetAuditService(s.auditService)` | cmd/server/stage2.go:948 | handler ← service 後綁定 | 接入層 ← audit | W4 | 審閱處置留痕。漏注入＝處置動作零審計。 |
| H-35 | hook:cmd/server/stage2.go:keyManagementHandler.SetAuditService | `keyManagementHandler.SetAuditService(s.auditService)` | cmd/server/stage2.go:968 | handler ← service 後綁定 | 接入層 ← audit | W4 | 清理退役資料的顯式留痕。漏注入＝金鑰清理零審計（PCI 3.6 金鑰管理留痕缺口）。 |
| H-36 | hook:cmd/server/stage2.go:keyManagementHandler.SetDelegatedProviderFactory | `keyManagementHandler.SetDelegatedProviderFactory(buildDelegatedRewrapProvider)` | cmd/server/stage2.go:971 | handler ← 工廠函式後綁定 | 接入層 ← keyvault | W2 | 委託式 rewrap 的 provider 工廠。漏注入＝委託模式重寫端點不可用。 |
| H-36b | hook:cmd/server/stage2.go:keyManagementHandler.SetCheckpointSigning | `keyManagementHandler.SetCheckpointSigning(s.checkpointSigning)` | cmd/server/stage2.go:973 | handler ← service 後綁定 | 接入層 ← keyvault | —（audit-checkpoint-chain 3.4／第 8 組） | 檢查點簽章鑰的金鑰清冊項（公鑰指紋＋版本）。漏注入＝清冊上看不到這把鑰，稽核者無從得知系統持有一把可簽鏈的私鑰——清冊的價值正是「沒有藏起來的鑰」。僅影響顯示，不影響封章。 |
| H-37 | hook:cmd/server/stage2.go:userHandler.SetAuditService | `userHandler.SetAuditService(s.auditService)` | cmd/server/stage2.go:980 | handler ← service 後綁定 | 接入層 ← audit | W4 | 同 H-34。 |
| H-38 | hook:cmd/server/stage2.go:s.userService.SetRecordingTokenRevoker | `s.userService.SetRecordingTokenRevoker(recordingHandler.TokenManager())` | cmd/server/stage2.go:990 | 反向後綁定（service ← handler） | identity ← 接入層 | W8 | **必須晚於 `recordingHandler` 建構**（同函式內）。漏注入＝改密／停用後既發的錄影 token 仍可播放。 |
| H-39 | hook:cmd/server/stage2.go:s.oidcProviderService.SetRecordingTokenRevoker | `s.oidcProviderService.SetRecordingTokenRevoker(recordingHandler.TokenManager())` | cmd/server/stage2.go:993 | 反向後綁定 | identity ← 接入層 | W8 | 同 H-38（provider 級）。 |
| H-40 | hook:cmd/server/stage2.go:auditExportService.SetSigning | `auditExportService.SetSigning(exportSigning)` | cmd/server/stage2.go:699 | setter 後綁定 | audit ← keyvault | W4 | 匯出簽章金鑰注入。漏注入＝審計匯出無簽章（PCI 10.5 完整性證明缺口）。§4.5／§3.6 的 `RecordingReader` 介面反轉改的是同一個建構子的另一個參數，**兩處不得互相波及**。**呼叫點已自 buildRouteDeps 上移 runStage2**（workbench-clipboard-and-layout B2：匯出服務改與打包 worker 共用單一實例），同檔故錨點鍵不變。 |
| H-65 | hook:cmd/server/stage2.go:auditExportService.SetClipboardCodec | `auditExportService.SetClipboardCodec(keyManager)` | cmd/server/stage2.go:700 | setter 後綁定 | audit ← keyvault | —（workbench-clipboard-and-layout B2 新增） | 證據包剪貼簿內容解密器注入。**漏注入不是靜默降級**：bundle 匯出遇到 content_status=available 的事件即整包失敗（fail-close——宣稱帶內容的包靜默缺內容等於對收包方說謊），事件報告與零剪貼簿事件的 bundle 不受影響。必須晚於 keyManager（H-10 一帶）建構、早於 worker 啟動與路由開放——段 2 內的現行位置即滿足。 |
| H-41 | hook:cmd/server/stage2.go:assetHandler.SetAccessStateAnnotator | `assetHandler.SetAccessStateAnnotator(s.accessPolicyService)` | cmd/server/stage2.go:1023 | handler ← service 後綁定 | 接入層 ← policy | W3 | **後續要把 `AnnotateConnectStates` 就地重歸 authz 側**（§4.8 環拆解）——搬遷後此處注入的型別會變，注入點本身必須保留，否則資產列表的存取狀態標註消失。 |
| H-56 | hook:cmd/server/stage2.go:auditCheckpointHandler.SetAutoVerifyStatus | `auditCheckpointHandler.SetAutoVerifyStatus(s.chainVerifyStatus)` | cmd/server/stage2.go:945 | handler ← service 後綁定 | 接入層 ← audit | —（audit-chain-scheduled-verification 5.1 新增） | 兩層自動驗證的營運狀態揭露（掛既有結構層報告，**不新增路由**）。**必須早於 `registerRoutes` 交出 handler**（`routeDeps` 契約要求註冊前完成注入）。**漏注入不會報錯**：驗證頁的鏈健康總覽照常顯示，只是自動驗證那一區塊永遠顯示「取不到狀態」——而該區塊正是稽核唯一能看出「排程其實沒在跑」的地方（排程靜默停擺時不會有任何告警，沒跑就沒有異常可報）。注入的實例 SHALL 與排程器執行的是同一個 `ChainVerifyService`：另建一份會讓頁面顯示一個從未跑過的物件的狀態，把停擺蓋成「剛啟動」。注入本身唯讀、無副作用、可重入。 |
| H-41b | hook:cmd/server/stage2.go:assetHandler.SetDataTransfer | `assetHandler.SetDataTransfer(s.dataTransferService)` | cmd/server/stage2.go:932 | handler ← service 後綁定 | 接入層 ← policy | data-transfer-control 期 1（4.3） | K8s 檔案進出（`kubectl cp`）的資料傳輸閘。**必須早於 `registerRoutes` 交出 handler**（`routeDeps` 契約要求註冊前完成注入）。**漏注入＝K8s 端點的上傳／下載完全不受全域傳輸政策管制**，且症狀與「政策設為允許」不可分辨——安全紅線，同 H-42 的類別。 |
| H-41c | hook:cmd/server/stage2.go:connHandler.SetDataTransfer | `connHandler.SetDataTransfer(dataTransferService)` | cmd/server/stage2.go:614 | handler ← service 後綁定 | 接入層 ← policy | data-transfer-control 期 1 | guacd 圖形協議側的資料傳輸閘：連線參數的 `disable-copy`／`disable-paste`／`disable-*load`、tunnel 的 `file_tap` 逐次攔截、會話能力快照三者共用此一實例。**原為裸欄位賦值 `connHandler.DataTransfer = …`，因而落在本登記表的辨識範圍外**——把該行換成 `_ = dataTransferService` 時三處同時靜默失效而 `./cmd/server`／`./internal/proxy` 全綠（驗收實證）。已改為 setter 並不匯出欄位，使其與 H-41b／H-42b 同構且未登記即紅。 |
| H-42 | hook:cmd/server/stage2.go:sftpHandler.SetAccessPolicy | `sftpHandler.SetAccessPolicy(s.accessPolicyService)` | cmd/server/stage2.go:1027 | handler ← service 後綁定 | 接入層 ← policy | W3 | 檔案資料面同套存取政策閘。**漏注入＝SFTP 路徑繞過存取政策**——安全紅線，且閘序統一時本注入是「兌換點政策重查」的一環。 |
| H-42b | hook:cmd/server/stage2.go:sftpHandler.SetDataTransfer | `sftpHandler.SetDataTransfer(s.dataTransferService)` | cmd/server/stage2.go:1028 | handler ← service 後綁定 | 接入層 ← policy | data-transfer-control 期 1（4.1） | SFTP 上傳／下載／刪除／建目錄的資料傳輸閘。同 H-41b：**漏注入＝SFTP 資料面繞過全域傳輸政策**，且被放行的傳輸不會產生 `status=denied` 留痕（AP-66），事後查不出政策曾經失效。與 H-42 的存取政策閘是兩道獨立的閘，缺任一道都不會讓另一道轉紅。 |
| H-42c | hook:cmd/server/stage2.go:retentionService.SetWatermarks | `retentionService.SetWatermarks(audit.NewRetentionWatermarkService(database.DB))` | cmd/server/stage2.go:723 | setter 後綁定 | audit（自注入） | auditor-workbench | 保留期清除水位：每輪 `PurgeAll` 後前進 `audit_retention_watermarks`。**必須早於 `retentionScheduler.Start`**（同函式內下一行即建排程器）。**漏注入＝`recordWatermark` 因 `s.watermarks == nil` 永遠早退**，工作台把真的被清除過的區間回成 `present`＋空白，亦即把「已依政策清除」講成「本來就沒發生」——招牌能力反向失效，且方向與誤報要防的相反。原以 `WithWatermarks` 流暢式命名，落在 Set／Init／Register／Reset 的辨識前綴外，自建立起零呼叫點而無任何測試轉紅。（本列原誤置於 §4.3 封印接線表，2026-08-12 歸位段 2 主序。） |
| H-51 | hook:cmd/server/stage2.go:retentionService.UseCheckpointIntervals | `retentionService.UseCheckpointIntervals(checkpointPurger)` | cmd/server/stage2.go:719 | 策略切換注入（流暢式命名） | audit | audit-checkpoint-chain（6.7） | `audit_logs` 清除由「逐列刪」切換為「已封區間整段刪＋簽章 tombstone」的**唯一切換點**（回滾即拿掉這一行）。**必須早於 `retentionScheduler.Start`**（下方 5 行即建排程器並啟動），晚了即首輪清除仍走舊路徑。**漏注入不產生任何錯誤**：清除照常進行、只是不再產出 tombstone，事後無從區分「依政策清除」與「被抹除」，檢查點鏈在該區間出現無法解釋的缺口。**`Use*` 前綴原落在 Set／Init／Register／Reset 判準外**，自建立起零守衛（2026-08-12 擴充 `isHookCallee` 後納入）。 |
| H-52 | hook:cmd/server/stage2.go:asset.NewAssetAccountService().WithAuthorization | `asset.NewAssetAccountService(...).WithAuthorization(s.authorizationService)` | cmd/server/stage2.go:936 | 建構鏈上的注入（流暢式） | asset ← authz | asset-multi-account（階段 2） | 資產帳號服務的跨資產可見性判定來源，**建構與注入在同一運算式內**，故沒有第二個機會補注入。**漏注入＝`asset_account_service.go:401` 的 `s.authz != nil` 短路成 false，複製來源帳號的可見性檢查整段跳過**——只管得到自己那台的管理員可以把任意資產的帳號複製過來，即越權讀取憑證來源（設計時已明列的攻擊面），且被放行的請求與「來源本就可見」不可分辨。同 H-51，`With*` 前綴原在判準外。 |
| H-53 | hook:cmd/server/stage2.go:keyManager.SetPolicySource | `keyManager.SetPolicySource(policyService)` | cmd/server/stage2.go:209 | setter 後綁定 | keyvault ← policy | policy-numeric-lower-bounds | 單次換鑰重加密上限的執行期事實源（`key_rotation_max_per_run`；env 僅為初值）。**漏注入不會報錯**：`s.policies == nil` 時退回 env→預設，換鑰照跑，但管理員在政策頁調整的上限完全不生效，且政策層的下界（`Min`＝500）失去作用——env 可設成 1 而使換鑰永遠跑不完，金鑰清冊上仍顯示可輪替。注入本身無副作用、可重入。 |
| H-54 | hook:cmd/server/stage2.go:k8sproxy.SetPolicySource | `k8sproxy.SetPolicySource(policyService)` | cmd/server/stage2.go:210 | 包級 setter 後綁定 | 接入層 ← policy | policy-numeric-lower-bounds | 叢集列表逾時的執行期事實源（`k8s_list_timeout_seconds`）。**注入對象是包級變數而非實例**（見 G-129／G-130），故全行程只有這一個注入點、漏了就整個 k8sproxy 都吃不到政策。漏注入不報錯，形態同 H-53：退回 env→預設，政策頁的調整不生效。 |

| H-59 | hook:cmd/server/stage2.go:s1.metrics.RegisterStage2 | `s1.metrics.RegisterStage2()` | cmd/server/stage2.go:812 | 分階段註冊（指標曝光面） | assembly ← observability | observability-lite | 把段 2 服務的指標註冊進 registry。**必須晚於段 2 服務就緒、且不得提前到段 1**：段 1 註冊完整路由樹（佔位 handler），此時若曝光 HTTP 指標，其 `path` 標籤即端點清單全集——等於在未解封狀態下洩漏整份路由表。**漏呼叫不報錯**：封印期縮減盤照常曝光，只是解封後所有營運指標永久缺席，監控看起來「有在採集」而實際上什麼都沒有。以 `sync.Once` 保證冪等——B 模式每次解封都會走到，重複 `MustRegister` 會 panic 並終止行程。 |
| H-60 | hook:cmd/server/stage2.go:s1.metrics.SetConnectionSource | `s1.metrics.SetConnectionSource(...)` | cmd/server/stage2.go:815 | setter 後綁定（現讀資料源） | assembly ← observability／proxy | observability-lite | 活躍連線數的現讀來源（`registry.Count()`，O(1) 故不走背景刷新）。**必須晚於 ST-3 連線註冊表建立**。漏注入不報錯：GaugeFunc 回 0，而「零連線」與「沒接線」在採集端不可分辨——是比缺值更糟的假訊號。 |
| H-61 | hook:cmd/server/stage2.go:s1.metrics.SetAuditQueueSource | `s1.metrics.SetAuditQueueSource(...)` | cmd/server/stage2.go:816 | setter 後綁定（現讀資料源） | assembly ← observability／audit | observability-lite | 審計非同步佇列深度的現讀來源（`len(logChan)`）。漏注入的症狀同 H-60：恆 0，使「佇列將滿」這個丟棄前兆完全不可見。 |
| H-62 | hook:cmd/server/stage2.go:auditService.SetDropObserver | `auditService.SetDropObserver(...)` | cmd/server/stage2.go:819 | setter 後綁定（觀測掛勾） | assembly ← audit／observability | observability-lite | 審計佇列滿載時的丟棄計數掛勾。**漏注入的代價最高且完全無聲**：該路徑不記 `audit_failure_events`（`audit-failure-alerting` 的涵蓋範圍明文限定為「fallback 檔案觸發時」），原本唯一的痕跡是 `log.Printf`。漏了這一行，「審計曾經永久掉過資料」就退回成不可查詢、不可告警、容器重啟即失的狀態。語義映射（降級寫檔 vs 直接丟棄）落在此處，使 audit 模組不因監控而新增依賴。 |
| H-67 | hook:cmd/server/stage2.go:database.SetInstanceGuardEventSink | `database.SetInstanceGuardEventSink(instanceGuardAuditSink(auditService))` | cmd/server/stage2.go:438 | setter 後綁定（事件 sink） | assembly ← database／audit | single-instance-guard | 守衛三事件（overridden／lost／regained）落 `audit_logs` 的唯一通道（產生點 AP-77）。**必須晚於 `auditService` 建構**（緊接 `mark("auditService")`）；段 1 緩衝的事件（含 ack 啟動的 overridden）於注入當下依序補寫，B 模式在解封後才寫。漏注入＝三事件永遠只在行程日誌，「哪個實例何時失守、誰確認了衝突」在稽核上不存在，且緩衝（上限 16）溢出丟最舊。 |
| H-63 | hook:cmd/server/main.go:s1.metrics.SetSealStateSource | `s1.metrics.SetSealStateSource(...)` | cmd/server/main.go:179 | setter 後綁定（現讀資料源） | assembly ← observability／seal | observability-lite | 封印狀態指標的來源。**刻意接在 B 模式與 A／C 模式分支之後的匯流點**：兩條路徑到該處都已產生 `machine`，一處接線即涵蓋全模式——分頭接線只要漏一邊，該模式的封印指標就靜默缺席。未注入時 collector **不曝光任何序列**（不輸出猜測值）：監控據此判斷要不要派人解封，猜錯的代價是實際封印中卻無人知曉。 |

### 4.3 封印接線（`cmd/server/main.go`／`sealwire.go`，10 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| H-43 | hook:cmd/server/main.go:sealHandler.SetSourceControls | `sealHandler.SetSourceControls(...)`（A／C 模式） | cmd/server/main.go:135 | setter 後綁定 | assembly（不搬） | —（不動） | **必須在開放監聽之前**：來源網段組態在任何模式下都要解析，否則設了 `SEAL_UNSEAL_ALLOWED_CIDRS` 的部署以為來源受限、實際完全沒生效。 |
| H-44 | hook:cmd/server/main.go:deps.keyManagement.SetSealStateProbe | `deps.keyManagement.SetSealStateProbe(...)`（A／C 模式） | cmd/server/main.go:156 | setter 後綁定 | assembly（不搬） | —（不動） | **必須早於 `registerRoutes`（`:157`）**——`routeDeps` 契約要求全部成員於註冊前完成注入。漏注入＝金鑰清冊的封印狀態欄缺失，前端須寫兩套判斷。 |
| H-45 | hook:cmd/server/sealwire.go:w.main.SetUnsealRelocated | `w.main.SetUnsealRelocated(true)` | cmd/server/sealwire.go:150 | setter 後綁定 | assembly（不搬） | —（不動） | 解封端點另行繫結時，主監聽的 handler 硬拒解封。**必須早於開放監聽**：晚了即出現「兩個監聽面都可解封」的窗口，網段隔離形同虛設。 |
| H-46 | hook:cmd/server/sealwire.go:h.SetSourceControls | `h.SetSourceControls(...)` | cmd/server/sealwire.go:163 | setter 後綁定 | assembly（不搬） | —（不動） | 同 H-43（B 模式，兩個監聽面各一個實例但共用狀態機／journal／限速）。 |
| H-47 | hook:cmd/server/sealwire.go:h.SetInitRequiredProbe | `h.SetInitRequiredProbe(...)` | cmd/server/sealwire.go:164 | setter 後綁定 | assembly ← keyvault | —（不動） | 探測 `CountDataKeys == 0` 以分流初始化解封／一般解封。漏注入＝初始化路徑判定失效，已有金鑰的部署可能被當成首啟而接受任意材料。 |
| H-48 | hook:cmd/server/sealwire.go:h.SetAdmitter | `h.SetAdmitter(...)` | cmd/server/sealwire.go:168 | setter 後綁定 | assembly ← sealjournal | —（不動） | journal admission ticket。**封印期留痕不受任何 feature flag 控制、建立失敗即不得開放監聽**（`stage1.go:230`）——漏注入＝未認證端點的嘗試零留痕。 |
| H-49 | hook:cmd/server/sealwire.go:h.SetOnUnsealed | `h.SetOnUnsealed(...)` | cmd/server/sealwire.go:175 | setter 後綁定 | assembly（不搬） | —（不動） | 解封成功後的換手回呼（`publishStage2`）。**回呼內只做一次原子指標交換，不做任何可能失敗的建構**——engine 已於 publish 之前建好（`runStage2Graph`）。若把建構移進回呼，失敗即停在「狀態已解封、router 仍是段 1」的不可重試死鎖。 |
| H-50 | hook:cmd/server/sealwire.go:deps.keyManagement.SetSealStateProbe | `deps.keyManagement.SetSealStateProbe(...)`（B 模式解封後） | cmd/server/sealwire.go:352 | setter 後綁定 | assembly（不搬） | —（不動） | 同 H-44（B 模式路徑）。與 H-44 同名不同檔，各佔一列。 |
| H-57 | hook:cmd/server/stage2.go:assetService.SetSessionTerminator | `assetService.SetSessionTerminator(sessionService)` | cmd/server/stage2.go:374 | setter 後綁定 | asset ← session（介面反轉） | —（security-backlog-settlement 塊 1） | 停用資產即收線。**必須晚於 `sessionService` 建構**。漏注入＝資產停用後，已建立的連線活到自然斷線（殘窗以小時計），管理員在介面上看到已停用、操作者其實還在裡面打字。與 H-19（帳號停用收線）是同一語義的兩個主體（人／機器）。矩陣 asset→session 為 ✗，故注入的是窄介面 `SessionTerminator`。 |
| H-58 | hook:cmd/server/stage2.go:assetService.SetAuthorizationRevoker | `assetService.SetAuthorizationRevoker(authorizationService)` | cmd/server/stage2.go:361 | setter 後綁定 | asset ← authz（tx-taking 窄 port，交易級聯刪除） | —（security-backlog-settlement 塊 2） | 刪除資產即撤銷其授權與審核範圍。**必須晚於 `authorizationService` 建構**。漏注入＝`AssetService.Delete` fail-close 拒絕刪除（刻意：靜默略過會留下幽靈授權——權限查詢不 join `assets`，已刪資產的授權仍會命中）。tx-taking 白名單見 `internal/guards/txtaking/tx_taking_whitelist_test.go`。 |
| H-68 | hook:cmd/server/main.go:sealHandler.SetInstanceGuardProbe | `sealHandler.SetInstanceGuardProbe(instanceGuardStatusProbe)`（A／C 模式） | cmd/server/main.go:154 | setter 後綁定（現讀探針） | assembly ← api／database | single-instance-guard | `/seal/status` 的 `instance_guard` 粗狀態欄（state／since／reason／peers，不含識別資訊），即管理介面橫幅的輪詢出口。與 H-69 同名不同檔，各佔一列——**兩種模式各自接線，漏任一側不會讓另一側轉紅**，症狀是該模式下欄位省略、橫幅永不出現。`TestInstanceGuardBModeSealStatusCarriesGuardField` 只涵蓋 sealwire 側；本列（A／C）由手測承接。 |
| H-69 | hook:cmd/server/sealwire.go:h.SetInstanceGuardProbe | `h.SetInstanceGuardProbe(instanceGuardStatusProbe)`（B 模式，主／管理監聽的 handler 共用同一函式） | cmd/server/sealwire.go:165 | setter 後綁定（現讀探針） | assembly ← api／database | single-instance-guard | 同 H-68（B 模式路徑，`newWiredSealHandler` 對兩個監聽面的 handler 皆生效）。 |
| H-70 | hook:cmd/server/stage2.go:authHandler.SetSourceIPBaseline | `authHandler.SetSourceIPBaseline(s.sourceIPBaseline)` | cmd/server/stage2.go:1159 | setter 後綁定 | api ← audit | —（source-ip-forensics 3.2） | 帳號 × 來源位址「已見」基準的注入（本地認證流）。消費端 `internal/api/auth_source_ip_observe.go` 為 `baseline == nil` 即 return——**漏注入＝五個正式會話發放點全部不觀察，且完全無錯誤訊號**：基準表永遠是空的，於是每一次建線都判為新位址、告警不停響；或反過來說，「這個帳號從沒從這裡登入過」這件事永遠答不出來。**必須與 J-14／J-15 取到同一份服務**（同一個 `sourceIPBaseline` 變數）——登入點與建線點寫的是同一張表的同一組鍵，服務分裂即判定分裂。 |
| H-71 | hook:cmd/server/stage2.go:oidcHandler.SetSourceIPBaseline | `oidcHandler.SetSourceIPBaseline(s.sourceIPBaseline)` | cmd/server/stage2.go:1160 | setter 後綁定 | api ← audit | —（source-ip-forensics 3.2） | 同 H-70 的 OIDC 交換流。**兩者缺任一側，另一側都不會轉紅**——症狀是「本地登入進得了基準、OIDC 登入進不了」，而該帳號自 OIDC 進來的位址從此永遠不算已見。 |
| H-72 | hook:cmd/server/stage2.go:authHandler.SetSourcePolicyReader | `authHandler.SetSourcePolicyReader(s.authService)` | cmd/server/stage2.go:1165 | setter 後綁定 | api ← identity | —（source-ip-forensics 4.2） | 允許來源網段的現讀面注入（本地認證流）。**與 H-70 的方向相反**：那是旁路功能，漏注入即靜默不觀察；本列是**強制點**，漏注入即 fail-close——判定點讀不到清單一律拒絕，症狀是所有人登不進去。方向刻意如此：一條漏接的組裝路徑不得讓整套來源限定靜默關掉。三個 handler（H-72／H-73／H-74）必須取到同一份服務，否則會出現「登入判、管理端點不判」這種只有一半生效的狀態。 |
| H-73 | hook:cmd/server/stage2.go:oidcHandler.SetSourcePolicyReader | `oidcHandler.SetSourcePolicyReader(s.authService)` | cmd/server/stage2.go:1166 | setter 後綁定 | api ← identity | —（source-ip-forensics 4.2） | 同 H-72 的 OIDC 交換流（交換點的判定）。 |
| H-74 | hook:cmd/server/stage2.go:userHandler.SetSourcePolicyReader | `userHandler.SetSourcePolicyReader(s.authService)` | cmd/server/stage2.go:1239 | setter 後綁定 | api ← identity | —（source-ip-forensics 4.2） | 同 H-72 的使用者管理流（管理者對他人認證因子的三個端點：改密、解鎖、MFA 重設，依**操作者本人**的清單判定）。 |

### 4.4 段 2 裸欄位注入（`inject:`，`cmd/server/stage2.go`，11 筆）

> **為什麼另立一節**：這 11 筆不經任何函式呼叫（`handler.Field = service`），
> 守衛原本只走 `*ast.CallExpr`，**整類在射程外**——拆掉其中任何一行，`./cmd/server`
> 全綠（`sshHandler.AccessPolicy` 為實證案例）。2026-08-12 擴充
> `scanAssemblyFieldInjections` 後納入，判準見該函式檔頭（`=` ／ 匯出欄位 ／
> base 為同函式內 `New*` 建出的區域變數，三條合取）。
>
> 這一節的注入面全部落在**兩個連線入口**（`connHandler`＝guacd 圖形協議、
> `sshHandler`＝原生 SSH／SFTP），亦即全系統離真實流量最近的一層；**其中 8 筆的
> 消費端在 nil 時走「早退＝放行」或「跳過＝不留痕」**，故漏注入的症狀與「政策本來
> 就設為允許」在外部完全不可分辨。標記 **[紅線]** 者即此類。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| J-1 | inject:cmd/server/stage2.go:connHandler.Registry | `connHandler.Registry = registry` | cmd/server/stage2.go:415 | 裸欄位注入（連線層 ← 註冊表） | 接入層 ← session | W9 | 圖形連線的活躍連線註冊表：`Register`／`Close`／`Unregister` 三點使用（`internal/proxy/handler.go:395,401,490`），是強制下線與關機收線（`connectionRegistry.CloseAll`）唯一掃得到這些 tunnel 的途徑。**必須早於任何連線建立**。漏注入＝建線時 nil deref panic（可見）；真正的風險形態是被改成「有就註冊」的寬容分支，那會讓圖形會話不受強制下線與關機收線管轄。 |
| J-2 | inject:cmd/server/stage2.go:connHandler.TimeoutPolicy | `connHandler.TimeoutPolicy = sessionTimeoutPolicy` | cmd/server/stage2.go:417 | 裸欄位注入（連線層 ← policy） | 接入層 ← policy | W3 | RDP/VNC 的閒置／最大時長改讀安全政策（與 SSH／k8s／DB 同一政策鍵）。消費端 `internal/proxy/handler.go:411` 有 nil 退路（TIMEOUT-3：退回安全預設而非零逾時），故**漏注入不致無限期連線**，但政策頁上調降的逾時值靜默不生效——使用者以為已收緊，實際仍是預設值。非紅線（有安全退路），但屬「設定與行為不一致」類缺陷。 |
| J-3 | inject:cmd/server/stage2.go:connHandler.AuditSink | `connHandler.AuditSink = auditDirectSink` | cmd/server/stage2.go:420 | 裸欄位注入（連線層 ← audit） | 接入層 ← audit | W4（AP-28） | **[紅線]** 圖形連線的檔案上傳／下載審計投遞面：每條連線的 `FileTap` 由此取得（`handler.go:374`），連線層的傳輸事件亦由此送出（`handler.go:333` 的 `h.AuditSink != nil` 條件）。**漏注入＝條件短路，圖形協議的檔案進出零審計列**，且沒有任何錯誤或降級訊號——事後查稽核只看到「這段期間沒有檔案傳輸」，與真的沒傳輸不可分辨。刻意用 `auditDirectSink` 而非 `auditService`（本點不受 `AuditLogEnabled` 管制），故不得以「政策關了」解釋缺列。 |
| J-4 | inject:cmd/server/stage2.go:sshHandler.TimeoutPolicy | `sshHandler.TimeoutPolicy = sessionTimeoutPolicy` | cmd/server/stage2.go:533 | 裸欄位注入（連線層 ← policy） | 接入層 ← policy | W3 | 同 J-2 的 SSH 側。兩者共用同一個 `sessionTimeoutPolicy` 閉包是契約——**分開建兩份即兩條協議路徑的逾時可能來自不同政策快照**，出現「同一政策、兩種行為」。非紅線（同有安全退路）。 |
| J-5 | inject:cmd/server/stage2.go:sshHandler.RecordingFailClose | `sshHandler.RecordingFailClose = func() bool { ... }` | cmd/server/stage2.go:535 | 裸欄位注入（連線層 ← policy，閉包） | 接入層 ← policy | recording-failure-handling | **[紅線]** 錄影失敗時是否拒絕建線。消費端為 `internal/sshproxy/connect_gates.go:193` 的 `h.RecordingFailClose != nil && h.RecordingFailClose()`——**nil 即整條 fail-close 判定短路成 false，錄影建立失敗的會話照常放行**，亦即產生「無錄影的特權會話」，而該政策的全部價值就是不允許它存在。以閉包而非取值注入是為了「政策改動對新簽發即時生效」，改成取值即凍結成啟動當下的快照。 |
| J-6 | inject:cmd/server/stage2.go:sshHandler.AlertSink | `sshHandler.AlertSink = alertSink` | cmd/server/stage2.go:540 | 裸欄位注入（連線層 ← audit） | 接入層 ← audit | W5 | **[紅線]** 危險指令阻斷的告警落地面：每條會話的 `commandBlocker` 由此取得（`sshproxy/handler.go:451`）。`newCommandBlocker` 刻意在 `alerts == nil` 時**仍建立 blocker**（同檔 `:35` 註解：不因告警接線缺失而關掉阻斷），故**漏注入的症狀是「阻斷照樣發生、但零筆 `command_alerts`、零通知」**——被擋下的危險指令事後查不出曾經發生，稽核與事件調查失去唯一來源。上游 `requireAlertSink`（`stage2.go:418`）只驗 sink 建得出來，不驗它被接上這裡。 |
| J-7 | inject:cmd/server/stage2.go:connHandler.ConnectTokens | `connHandler.ConnectTokens = sshHandler.ConnectTokens` | cmd/server/stage2.go:542 | 裸欄位注入（跨入口共用單一 token manager） | 接入層 | connect-token-guacd | **[紅線]** SSH 與圖形兩條路徑 SHALL 共用**同一個** connect token manager（簽發端點掛在 `sshHandler`、兌換發生在兩側）。**必須晚於 `sshHandler` 建構**。漏注入＝圖形側兌換點取到 nil（`proxy/handler.go:135` 直接呼叫，握手期 panic）；而「補一個新的 manager」這種順手的修法更危險——一次性兌換與撤銷的簿記會分裂成兩本，SSH 側已撤銷／已用掉的 token 在圖形側仍然有效。 |
| J-8 | inject:cmd/server/stage2.go:sshHandler.HostKeys | `sshHandler.HostKeys = hostKeyService` | cmd/server/stage2.go:545 | 裸欄位注入（連線層 ← asset） | 接入層 ← asset | W6 | **[紅線]** TOFU host key 驗證服務（SSH 與 SFTP 共用）。消費端 `sshproxy/handler.go:273` 無 nil 分支（`h.HostKeys.Callback(assetID)`），故漏注入在握手期 nil deref——**但這道注入的真正語義是「host key 比對有人做」**：一旦此處被換成寬鬆或空的 callback，目標主機換鑰即不再被察覺，中間人可在不觸發任何告警的情況下接管連線。與下一行 `assetService.SetHostKeyService`（H-27）是同一實例的兩個消費面，缺任一面另一面都不會轉紅。 |
| J-9 | inject:cmd/server/stage2.go:sshHandler.TransmissionConsent | `sshHandler.TransmissionConsent = transmissionConsent` | cmd/server/stage2.go:601 | 裸欄位注入（連線層 ← policy） | 接入層 ← policy | transmission-security-policy | **[紅線]** 傳輸安全閘：strict＝400 拒絕、warn＝428 要求同意、off＝零影響。消費端 `sshproxy/connect_gates.go:243` 與 `handler.go:1126` 都是 **`== nil` 即 `return nil`（＝放行）**——漏注入＝strict 政策靜默失效、明文風險連線直接建立，且不再彈同意對話框，等於「使用者從未被告知風險、也從未同意」卻留下連線成功的紀錄。後端強制閘，繞前端直呼 API 同受此閘，故這是唯一的攔截點。 |
| J-10 | inject:cmd/server/stage2.go:sshHandler.AccessPolicy | `sshHandler.AccessPolicy = accessPolicyService` | cmd/server/stage2.go:611 | 裸欄位注入（連線層 ← policy） | 接入層 ← policy | access-policy-approval | **[紅線／本次缺口的實證案例]** 存取政策閘（授權檢查之後、傳輸閘之前）：非 open 段位蓋過常設 connect，僅時窗內核准流的臨時授權放行。**兩個消費點（`connect_gates.go:212` 建線閘、`:375` 兌換點重查）都是 `== nil` 即 `return nil`＝放行**。獨立複驗者把本行換成 `_ = accessPolicyService` 後 `./cmd/server` **全綠**——即「SSH 路徑的存取政策整段失效」不會被任何測試察覺，且對外表現與「政策設為 open」完全相同。**無條件注入、不掛功能開關**，任何條件化都等於製造一個關掉紅線的開關。 |
| J-11 | inject:cmd/server/stage2.go:connHandler.AccessPolicy | `connHandler.AccessPolicy = accessPolicyService` | cmd/server/stage2.go:612 | 裸欄位注入（連線層 ← policy） | 接入層 ← policy | access-policy-approval | **[紅線]** 同 J-10 的圖形協議側（兌換點政策重查，與 SSH 對稱；消費端 `proxy/connect_gates.go:137` 同樣 nil 即放行）。**兩側必須注入同一實例**：分岔的那一側就是越權面（同 H-41c 對 `dataTransferService` 的論述）。缺任一側不會讓另一側轉紅，故兩列各自登記。 |

### 4.5 段 1 engine 組態的裸欄位注入（`inject:`，`cmd/server/main.go`，2 筆）

> **為什麼 2026-08-13 才入列**：`newEngine` 原本以 `gin.Default()` 建 engine，`r` 因此
> 不是「同函式內由 `New*` 建構子建出的區域變數」，兩行落在 `scanAssemblyFieldInjections`
> 判準第 3 條之外（該函式檔頭至今仍以 `r.RedirectTrailingSlash = false` 為「組態結構賦值」
> 的舉例）。access log 憑證遮蔽把它換成自家的 `middleware.NewEngineWithAccessLog()` 後，
> 第 3 條**自然成立**，兩行隨即納管。**這是判準涵蓋面擴大而非放寬**：它們確實是組裝根
> 對自建元件的欄位設定，且承載封印期的安全語義（下表），本來就該在管內。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| J-12 | inject:cmd/server/main.go:r.RedirectTrailingSlash | `r.RedirectTrailingSlash = false`（僅 `stageOne`） | cmd/server/main.go:325 | 裸欄位注入（engine 組態／封印期安全邊界） | assembly（不搬） | —（不動，access log 憑證遮蔽期納管） | **[紅線]** 封印期的路由存在性 oracle 關閉點。gin 的自動 redirect **發生在中間件鏈之前**：路由樹查無此路徑時直接回 301/307，不進任何 handler／middleware，故封印閘（G-4 的 `sealGateWhitelist`）根本攔不到——這兩行是唯一的關法。**必須在 engine 建出後、開放監聽之前設定**；漏設＝`/api/v1/assets/` 回 301 代表該路由真的存在、不存在的路徑回 503，正是封印閘刻意要抹平的區別，而外部表現只是「多了一次導向」，任何既有測試都不會紅。僅在 `stageOne` 為真時關閉：段 2 解封後回復 gin 預設，既有相容行為不變。 |
| J-13 | inject:cmd/server/main.go:r.RedirectFixedPath | `r.RedirectFixedPath = false`（僅 `stageOne`） | cmd/server/main.go:326 | 裸欄位注入（engine 組態／封印期安全邊界） | assembly（不搬） | —（不動，access log 憑證遮蔽期納管） | **[紅線]** 同 J-12 的另一半：`RedirectFixedPath` 涵蓋大小寫與 `..`／`//` 清理後的路徑修正導向，其洩漏面與尾斜線相同且更寬（一次探測可試多種變形）。**兩行必須成對存在**——只關一行等於把 oracle 從「尾斜線」搬到「路徑變形」，緩解看似做了而實際仍在；故兩者各佔一列，缺任一行另一行都不會轉紅。 |
| J-14 | inject:cmd/server/stage2.go:sshHandler.SourceIPBaseline | `sshHandler.SourceIPBaseline = sourceIPBaseline` | cmd/server/stage2.go:592 | 裸欄位注入（連線層 ← audit） | 接入層 ← audit | —（source-ip-forensics 3.1） | 文字終端建線點的新來源位址觀察。消費端 `internal/sshproxy/source_ip_observe.go` 為 `== nil` 即 return——**漏注入＝自新位址建線零告警、零基準列，且沒有任何錯誤或降級訊號**，事後查告警頁只看到「這段期間沒有新位址」，與真的沒有新位址不可分辨。**必須晚於 `alertSink` 與 `auditTxSink` 建構**（基準服務以兩者為建構參數）。 |
| J-15 | inject:cmd/server/stage2.go:connHandler.SourceIPBaseline | `connHandler.SourceIPBaseline = sourceIPBaseline` | cmd/server/stage2.go:593 | 裸欄位注入（連線層 ← audit） | 接入層 ← audit | —（source-ip-forensics 3.1） | 同 J-14 的圖形協議側。**兩側共用同一份服務是契約**：分開建兩份不會編譯失敗，但「同帳號同位址只響一次」會退化成「每種協議各響一次」。缺任一側另一側都不轉紅，症狀是「SSH 會響、RDP 不響」。 |

---

## 5. 單例式 `Init`／`Reset`／`Zeroize` 函式宣告（`singleton:`，16 筆）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| S-1 | singleton:internal/database/database.go:InitDatabase | `InitDatabase(cfg)` | internal/database/database.go:19 | singleton 建立 | infra（**已改名** `internal/database`） | W7 | 賦值 G-20；見 H-1。改名時本函式的呼叫點只有段 1 與兩個 `cmd/test_*` 工具，須一併改。 |
| S-2 | singleton:internal/modules/keyvault/key_manager_service.go:InitKeyManager | `InitKeyManager(db, kek)` | internal/modules/keyvault/key_manager_service.go:76 | singleton 建立 | keyvault | W2 | 見 H-2。**DB-dependent 的金鑰表比對落在此處而非段 1**是刻意的（組態段須 DB-independent）；搬包不得改變此分界。 |
| S-3 | singleton:internal/modules/audit/audit_failure_service.go:InitAuditFailure | `InitAuditFailure(db, policy)` | internal/modules/audit/audit_failure_service.go:55 | singleton 建立 | audit ← policy | W4 | 見 H-5。方向 audit→policy ✔（保留）。 |
| S-4 | singleton:internal/modules/audit/syslog_forwarder.go:InitSyslogForwarder | `InitSyslogForwarder(db)` | internal/modules/audit/syslog_forwarder.go:88 | singleton 建立 | audit | W4 | 見 H-7／H-8。 |
| S-5 | singleton:internal/modules/audit/audit_integrity_service.go:InitAuditIntegrityVersioned | `InitAuditIntegrityVersioned(db, km)` | internal/modules/audit/audit_integrity_service.go:82 | singleton 建立 | audit ← keyvault | W4 | 見 H-9。內部呼叫 `registerAuditIntegrity(svc)` 寫 G-14。 |
| S-6 | singleton:internal/modules/audit/alert_matcher.go:InitAlertMatcher | `InitAlertMatcher(db)` | internal/modules/audit/alert_matcher.go:55 | singleton 建立 | audit | W4 | 見 H-21。 |
| S-7 | singleton:internal/modules/audit/alert_notifier.go:InitAlertNotifier | `InitAlertNotifier(db, codec)` | internal/modules/audit/alert_notifier.go:229 | singleton 建立＋worker 啟動 | audit ← keyvault | W4 | 見 H-23。**建立即啟動 worker**，故它同時是「具外部副作用的步驟」（`stage2.go:372` 前有 `CheckCancelStep`）。 |
| S-8 | singleton:internal/modules/audit/stage2_release.go:ResetAuditFailureSingleton | `ResetAuditFailureSingleton()` | internal/modules/audit/stage2_release.go:27 | reset | audit | W4（§5.1 拆檔後留 audit） | 見 H-6。 |
| S-9 | singleton:internal/modules/audit/stage2_release.go:ResetAuditIntegritySingleton | `ResetAuditIntegritySingleton()` | internal/modules/audit/stage2_release.go:36 | reset | audit | W4 | **函式註解即契約**：「呼叫端 SHALL 於此之前先 `model.SetAuditCreateHooks(nil, nil)`」。見 H-11／H-12。 |
| S-10 | singleton:internal/modules/audit/stage2_release.go:StopAlertNotifierForRelease | `StopAlertNotifierForRelease(n)` | internal/modules/audit/stage2_release.go:56 | reset＋zeroize | audit | W4 | 見 H-24；三步順序與「呼叫端 SHALL 先停排程器」的 LIFO 前提都寫在函式註解內。 |
| S-11 | singleton:internal/modules/audit/stage2_release.go:ResetAlertMatcherSingleton | `ResetAlertMatcherSingleton()` | internal/modules/audit/stage2_release.go:90 | reset | audit | W4 | 見 H-22。 |
| S-12 | singleton:internal/modules/keyvault/release.go:KeyManagerService.ZeroizeForRelease | `(*KeyManagerService) ZeroizeForRelease()` | internal/modules/keyvault/release.go:28 | zeroize | **keyvault**（§5.1 改判：型別方法跟型別走） | W2（2.1 拆檔） | **逐位元組覆寫而非只丟參考**——切片內容可能仍被 `ciphers` 快取引用。後續要把本方法與 S-13 自 `stage2_release.go` 拆出歸 keyvault（Go 要求型別方法與型別同包）；**拆檔不得改變 bag 內的呼叫位置**（H-3）。 |
| S-13 | singleton:internal/modules/keyvault/release.go:ExportSigningService.ZeroizeForRelease | `(*ExportSigningService) ZeroizeForRelease()` | internal/modules/keyvault/release.go:50 | zeroize | **keyvault**（§5.1 改判） | W2（2.1 拆檔） | 同 S-12（Ed25519 私鑰）；見 H-26 的釋放序說明。 |
| S-16 | singleton:internal/modules/keyvault/release.go:CheckpointSigningService.ZeroizeForRelease | `(*CheckpointSigningService) ZeroizeForRelease()` | internal/modules/keyvault/release.go:68 | zeroize | keyvault | —（audit-checkpoint-chain 新增） | 同 S-13，但**逐版本**覆寫（`keys` 為 version→私鑰的表）並把 `activeVersion` 歸 0；見 H-26b。 |
| S-14 | singleton:internal/modules/keyvault/post_unseal_migration.go:ResetPostUnsealQueueForTest | `ResetPostUnsealQueueForTest()` | internal/modules/keyvault/post_unseal_migration.go:159 | reset（測試專用） | keyvault | W2 | 測試重置佇列（G-60）。**跨包後測試取用不到即失效**；`post_unseal_guard_test.go:113` 依賴它做 `t.Cleanup`，該守衛本身是解封後遷移佇列的負向成員斷言。 |
| S-15 | singleton:internal/modules/keyvault/post_unseal_migration.go:ResetPostUnsealRunCountsForTest | `ResetPostUnsealRunCountsForTest()` | internal/modules/keyvault/post_unseal_migration.go:77 | reset（測試專用） | keyvault | W2 | 同 S-14（重置 G-61）。 |

---

## 6. 段 2 啟動步驟（`step:`，42 項；列序＝執行序）

> 守衛以兩條斷言釘住：① 本節列序逐位等於 `stage2ServiceInventory`（`stage2.go:48`）；
> ② 程式碼中 34 個字面量 `mark("…")` 的出現序是本節列序的**有序子序列**（告警 sink 收口新增 `alertSink`、audit-checkpoint-chain 新增 `checkpointSigning`）（其餘 8 項由排程器迴圈 `mark(s.name)` 產生，audit-chain-scheduled-verification 新增 `chainVerifyScheduler`、workbench-clipboard-and-layout B2 新增 `auditExportJobWorker`）。
> `stage2ServiceInventory` 另由既有守衛與 `appGraph.ServiceNames()` 逐項比對，故三方對齊。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| ST-1 | step:keyManager | `InitKeyManager` | cmd/server/stage2.go:188 | 啟動步驟 | keyvault | W2 | **必須第一**：其後全部吃 `ColumnCodec` 的服務都依賴它。 |
| ST-2 | step:policyService | `NewSecurityPolicyService` ＋ 3 次 `SeedFromEnv` | cmd/server/stage2.go:211 | 啟動步驟 | policy | W3 | 必須早於全部讀政策者（auth／asset／audit／retention）。`SeedFromEnv` 為升級相容：既有部署的 env 值沿用，**播種晚於任何政策讀取即讀到零值**（逾時 0＝永不逾時）。 |
| ST-2b | step:auditTxSink | `audit.NewTxSink()` ＋ `requireAuditTxSink` 自檢 | cmd/server/stage2.go:228 | 啟動步驟（fail-close 自檢） | audit | W4（4.3／4.7） | **必須早於 ST-3 與 ST-8**：交易內審計落地面的第一個消費者是 `ldapDirectoryService`（ST-3），而 `postUnsealMigrations`（ST-8）的 LDAP seed 在段 2 期間就會寫審計。自檢晚於任一者即等於沒檢查。sink 未注入時 `return fail(...)`＝**啟動不成立**（比照 `InitAuditIntegrityVersioned`），SHALL NOT 沿用 `alert_matcher.go` 的寬鬆跳過——後者適用的是下游 tee，漏掉只損失附加價值。 |
| ST-3 | step:ldapDirectoryService | `NewLDAPDirectoryService(db, keyManager, auditTxSink)` | cmd/server/stage2.go:231 | 啟動步驟 | identity ← keyvault | W8 | **落點必須在 keyManager 之後**（同檔註解自陳）——bind 密碼走信封加密，codec 未就緒即無法解密。 |
| ST-4 | step:transmissionPolicy | `NewTransmissionPolicyService(policyService, ldapDirectoryService.RiskViewProvider())` ＋ 回注 | cmd/server/stage2.go:241 | 啟動步驟 | policy | W3 | **打環三步序**：見 H-4。 |
| ST-5 | step:auditFailureService | `InitAuditFailure` ＋ `ReconcileOnStartup` | cmd/server/stage2.go:252 | 啟動步驟 | audit | W4 | 見 H-5；回填必須在啟動時做，否則重啟遺留的進行中事件永久懸掛。 |
| ST-6 | step:syslogForwarder | `InitSyslogForwarder` ＋ `SetFailureReporter` ＋ `Start` | cmd/server/stage2.go:273 | 啟動步驟 | audit | W4 | reporter 先於 Start（H-8）；本步驟前有 `CheckCancelStep`（具外部副作用）。 |
| ST-7 | step:auditIntegrity | `InitAuditIntegrityVersioned` ＋ `SetAuditCreateHooks` | cmd/server/stage2.go:292 | 啟動步驟 | audit ← keyvault | W4 | **蓋章 hook 於此掛上**（H-10）：本步驟之前寫出的任何審計列無 HMAC、不進 tee。 |
| ST-8 | step:postUnsealMigrations | `RegisterBuiltinPostUnsealMigrations` ＋ `RunPostUnsealMigrations` | cmd/server/stage2.go:311 | 啟動步驟 | keyvault | W1／W2 | **必須緊接在 ST-7 之後**（遷移會寫審計列）；本步驟前有 `CheckCancelStep`。 |
| ST-9 | step:authService | `NewAuthServiceWithMFA` ＋ 3 個 setter | cmd/server/stage2.go:348 | 啟動步驟 | identity | W8 | 見 H-14／H-15／H-16。MFA TOTP secret 解密需 keyManager，故必須晚於 ST-1。 |
| ST-10 | step:assetService | `NewAssetService(keyManager, …)` ＋ `SetTransmissionPolicy` | cmd/server/stage2.go:356 | 啟動步驟 | asset ← keyvault | W6 | 憑證加解密走信封 key manager，必須晚於 ST-1。 |
| ST-11 | step:connectionRegistry | `proxy.NewConnectionRegistry()` | cmd/server/stage2.go:368 | 啟動步驟 | 接入層 | —（不動） | 必須早於 ST-12（SessionService 注入 registry）與 ST-13。釋放時 `CloseAll` 是實際收線的主力。 |
| ST-12 | step:sessionService | `NewSessionService(registry)` | cmd/server/stage2.go:372 | 啟動步驟 | session | W9 | 必須晚於 ST-11；且必須早於 H-19／H-29／H-31 三個 terminator 注入。 |
| ST-13 | step:reconciliationService | `NewSessionReconciliationService` ＋ `ReconcileStartup` | cmd/server/stage2.go:383 | 啟動步驟 | session | W9 | **啟動清掃必須在受理新連線之前**：重啟後不可能有存活連線，殘留 active 於此一次收斂（`backend_restart`）。晚於開服＝新連線與殘留混在一起無法區分。失敗不擋開服。 |
| ST-14 | step:recordingService | `NewRecordingService(recordingBasePath)` | cmd/server/stage2.go:391 | 啟動步驟 | session | W9 | 必須早於 ST-30（retentionScheduler 消費）與 sshHandler。§3.6／§4.5 的 `RecordingReader` 介面反轉（10.1／4.8）改的是消費側，不改本步位置。 |
| ST-15 | step:auditService | `NewAuditLogService(&cfg.Features)` | cmd/server/stage2.go:403 | 啟動步驟 | audit | W4 | **必須早於全部 `SetAuditSink`／`SetAuditService` 注入**（H-20／H-34／H-35／H-37）。緊接的 `logKEKSwitchAudit` 是本步之後第一筆審計寫入，故 ST-7 必須更早。 |
| ST-16 | step:dailyReviewService | `NewDailyReviewService(db, policyService, auditService)` | cmd/server/stage2.go:411 | 啟動步驟 | audit ← policy | W4 | 必須晚於 ST-2 與 ST-15。 |
| ST-17 | step:connHandler | `proxy.NewConnectionHandler(...)` ＋ `Registry`／`TimeoutPolicy` | cmd/server/stage2.go:421 | 啟動步驟 | 接入層 | —（不動） | 必須晚於 ST-10／ST-11／ST-12。`ConnectTokens` 於 ST-25 才接上（兩路徑共用同一 token manager）——**閘序統一後的兌換側入口之一**。 |
| ST-18 | step:userService | `NewUserService(db)` ＋ 3 個 setter | cmd/server/stage2.go:430 | 啟動步驟 | identity | W8 | 見 H-18／H-19／H-20。 |
| ST-18b | step:alertSink | `audit.NewAlertRecorder(db)` ＋ `requireAlertSink` 自檢 | cmd/server/stage2.go:439 | 啟動步驟（fail-close 自檢） | audit | W5（5.1／5.4） | **必須早於 ST-19 與 ST-25**：指令告警落地面僅有的兩個消費者是 `alertMatcher`（ST-19，比對路徑）與 `sshHandler`（ST-25，阻斷路徑的 `commandBlocker` 由它取得）。自檢晚於任一者，等於讓「未注入」在第一次告警時才以 log 現形。sink 未注入時 `return fail(...)`＝**啟動不成立**（比照 ST-2b），SHALL NOT 降 no-op；降了之後，一整類安全證據會在沒有任何東西變紅的情況下停止離機。 |
| ST-19 | step:alertMatcher | `InitAlertMatcher` ＋ `LoadRules` | cmd/server/stage2.go:451 | 啟動步驟 | audit | W4 | 載入失敗不致命（無快取＝不告警）——**這正是 4.7 要求 nil sink 自檢不得沿用的寬鬆形態**。 |
| ST-20 | step:alertNotifier | `InitAlertNotifier` ＋ `LoadChannels` | cmd/server/stage2.go:469 | 啟動步驟 | audit ← keyvault | W4 | 本步驟前有 `CheckCancelStep`（起 worker＝外部副作用）。 |
| ST-21 | step:kekRetirementMonitor | `NewKEKRetirementMonitor(keyManager, auditFailureService)` ＋ `ReportOnStartup` | cmd/server/stage2.go:474 | 啟動步驟 | keyvault ← `AuditFailureReporter`（audit 實作） | W2 | **§3.1 的 4.10 keyvault→audit 邊已反轉**：`KEKRetirementMonitor.af` 與 `ReportAADResidueOnStartup` 的參數型別皆改為 keyvault 自宣告的 `AuditFailureReporter` 窄介面（audit 側 `var _ AuditFailureReporter = (*AuditFailureService)(nil)` 實作），注入點仍在本步驟，注入序不變。**`ReportAADResidueOnStartup` 是該環的第二實例**（先前盤點未列，由 1.13 參照圖守衛掃出）。緊接的 `ReportAADResidueOnStartup` 仍必須置於告警服務就緒之後（否則通知必被丟棄，同檔註解自陳）。**注入的實作 SHALL 非 nil**：介面化後型別化的 nil 指標不等於 nil，函式內既有的 `af == nil` 早退擋不住它。 |
| ST-22 | step:notificationChannelService | `NewNotificationChannelService(db, keyManager)` ＋ `SetTransmissionPolicy` | cmd/server/stage2.go:484 | 啟動步驟 | audit ← keyvault／policy | W4 | codec 為建構參數：secret/url 一律以 `ColumnCodec` 寫 `enc:a1`，故必須晚於 ST-1。 |
| ST-23 | step:oidcServices | `OIDCEgressPolicy` ＋ provider／discovery／login 三服務 | cmd/server/stage2.go:501 | 啟動步驟 | identity | W8 | egress 政策依 `cfg.Server.Mode` 分流（release 一律無例外）。三個服務於同一步內建構，**`oidcLoginService` 吃 `authService`／`auditService`**，故必須晚於 ST-9／ST-15。 |
| ST-24 | step:exportSigning | `NewExportSigningService(db, keyManager)` | cmd/server/stage2.go:514 | 啟動步驟 | keyvault | W2 | 首啟自動生成 Ed25519 金鑰，私鑰經信封加密落 DB；必須晚於 ST-1。釋放需 zeroize（H-26）。 |
| ST-24b | step:checkpointSigning | `NewCheckpointSigningService(db, keyManager)` | cmd/server/stage2.go:529 | 啟動步驟 | keyvault | —（audit-checkpoint-chain 新增） | 首啟自動生成 Ed25519 v1（active），私鑰經 `ColumnCodec` 以 `RefCheckpointSigningPrivateKey` 綁定 AAD 落 DB；必須晚於 ST-1。**載入失敗一律 fail-close**——帶病啟動會產出一批永遠驗不了的檢查點。必須早於 ST-34b（封章排程器是唯一消費者）。釋放需 zeroize（H-26b）。 |
| ST-25 | step:sshHandler | `sshproxy.NewHandler(...)` ＋ `TimeoutPolicy`／`RecordingFailClose`／`ConnectTokens`／`HostKeys` | cmd/server/stage2.go:560 | 啟動步驟 | 接入層 | —（不動；W10 契約收斂） | **`connHandler.ConnectTokens = sshHandler.ConnectTokens`（`:441`）使兩路徑共用同一 token manager**——簽發側 10 道／SSH 兌換 11 道／guacd 兌換 9 道閘序即架在此共用之上。**已知釋放缺口**：`MonitorHub`／`ShareManager`／`ConnectTokenManager` 與 `statsClients` 持有的活躍 `*ssh.Client` 皆無全量關閉入口（`stage2.go:446-448` 自陳，tasks 2.1a）。 |
| ST-26 | step:hostKeyService | `NewHostKeyService(db)` | cmd/server/stage2.go:561 | 啟動步驟 | asset | W6 | 於 ST-25 內建構但單獨 `mark`；SSH 與 SFTP 共用 TOFU。 |
| ST-27 | step:changeSecretScheduler | plan／runner／scheduler ＋ `Start` | cmd/server/stage2.go:582 | 啟動步驟 | asset | W6 | 本步驟前有 `CheckCancelStep`。**排程器持有 `alertNotifier` 的直接參考（不經單例）**，故其 bag 登記必須晚於 alertNotifier（現況如此，LIFO 下先停排程器再停推送器）。**已知缺口**：`Stop` 不等 in-flight（tasks 2.1a）。 |
| ST-27b | step:changeSecretRetryScheduler | `NewChangeSecretRetryRunner` ＋ `NewChangeSecretRetryScheduler` ＋ `Start` | cmd/server/stage2.go:597 | 啟動步驟 | asset | —（change-secret-ssh-deepening 新增） | 未驗證候選憑證的重試排程。與 ST-27 分立：改密是使用者定義的 cron，重試是系統自身的可靠性機制，兩者節奏與失效語義不同。本步驟前有 `CheckCancelStep`；同樣持有 `alertNotifier` 直接參考，bag 登記晚於 alertNotifier（LIFO 下先停排程器再停推送器）。`cron.SkipIfStillRunning` 防重入。 |
| ST-28 | step:accessRequestScheduler | consent／accessPolicy／accessRequest ＋ scheduler `Start` | cmd/server/stage2.go:632 | 啟動步驟 | authz ← policy | W7 | 同 ST-27 的排程器約束。本步內建構的 `accessPolicyService` 同時注入 `sshHandler.AccessPolicy`／`connHandler.AccessPolicy`（兌換點政策重查）——**兩階段閘序契約的關鍵注入點**。 |
| ST-29 | step:apiHandlers | `buildRouteDeps(cfg, routeServices{...})` | cmd/server/stage2.go:697 | 啟動步驟 | 接入層 | —（不動） | **自陳「純建構＋依賴注入，無 I/O 副作用」**；H-32…H-42 全部落在此步內。`routeDeps` 契約：全部成員 SHALL 於 `registerRoutes` 之前完成建構與注入（`main.go:369`）。 |
| ST-30 | step:retentionScheduler | `NewRetentionService` ＋ `NewRetentionScheduler` ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | audit ← policy／session | W4 | 五個排程器由同一迴圈啟動，**各自於啟動前 `CheckCancelStep`**（每一個都是具外部副作用的步驟）。後續要把 `recording` 參數改 `RecordingReader` 窄介面（§3.6），建構子 2→3。 |
| ST-31 | step:reviewReminderScheduler | `NewDailyReviewReminderScheduler(dailyReviewService)` ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | audit | W4 | 同 ST-30；依賴 ST-16。 |
| ST-32 | step:inactivityScheduler | `NewInactivityService` ＋ scheduler ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | identity ← policy／audit | W8 | 同 ST-30；依賴 ST-2／ST-18／ST-15。 |
| ST-33 | step:kekRetirementScheduler | `NewKEKRetirementScheduler(kekRetirementMonitor)` ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | keyvault | W2 | 同 ST-30；依賴 ST-21。 |
| ST-34 | step:reconcileScheduler | `NewSessionReconciliationScheduler(reconciliationService)` ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | session | W9 | 同 ST-30；依賴 ST-13。 |
| ST-34b | step:checkpointScheduler | `NewCheckpointService` ＋ `NewCheckpointScheduler` ＋ `Start`（含 genesis 建立） | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | audit ← keyvault | —（audit-checkpoint-chain 新增） | 同 ST-30 的迴圈約束。依賴 ST-24b（簽章鑰）、ST-6（syslogForwarder 為錨定出口）、ST-5（失效上報）。`Start` 內含 genesis 建立，失敗即啟動失敗——沒有 genesis 的排程器每輪 Tick 都會失敗，是「活著但什麼都沒保護」的靜默狀態。**封章為旁路批次工作**：本排程器停擺不影響審計寫入，只讓鏈尾未封窗口（誠實邊界 R5）變長。 |
| ST-34c | step:chainVerifyScheduler | `NewChainVerifyService` ＋ `NewChainVerifyPolicyTuning` ＋ `NewChainVerifyScheduler` ＋ `Start` | cmd/server/stage2.go:776（迴圈） | 啟動步驟 | audit ← policy／keyvault | —（audit-chain-scheduled-verification 新增） | 同 ST-30 的迴圈約束。**必須晚於 ST-34b**：驗證的對象是封章產出的鏈，且兩者共用同一組 `checkpointVerifier`／`checkpointService` 實例——另建一份即等於拿另一套聚合算法驗封章的產物。依賴 ST-24b（簽章鑰，供依賴自檢）、ST-5（失效上報出口）、政策服務（三顆旋鈕現讀、不快取）。**與 ST-34b 相反，`Start` 不做任何前置建立**：鏈為空是驗證要回報的結論而非啟動失敗，在此建立或修補鏈上物件會讓驗證者同時成為被驗者的作者。**漏登記不產生任何錯誤**：鏈仍在、驗證頁的人工按鈕仍在，只是竄改再也不會有人被通知——證據存在卻無人知曉的靜默狀態，正是本 change 要消滅的形態。 |
| ST-34d | step:auditExportJobWorker | `NewAuditExportJobWorker` ＋ `Start` | cmd/server/stage2.go:838（迴圈） | 啟動步驟 | audit ← identity/authz（申請者重驗閉包） | —（workbench-clipboard-and-layout B2 新增） | 同 ST-30 的迴圈約束。**必須晚於 ST-33（apiHandlers）所依賴的匯出服務組裝**——worker 與 handler 共用同一個 `auditExportService` 實例（H-40/H-65 注入完成後才可啟動，否則打包出未簽章或缺剪貼簿內容的包）。`Start` 內含產物目錄建立（0700）與懸置 job 恢復（running→pending），恢復必須先於首輪領件。停止走資源袋（釋放序見 §7 摺疊註記）：**必須在 DB 關閉前停**，否則收尾週期對已關的 DB 寫狀態。**漏登記不產生任何錯誤**：job 永遠停在 pending、無人打包，發起端點照常受理——申請者看到的是永不完成的排隊，與「打包很慢」不可分辨。 |
| ST-35 | step:metricsRefresher | `observability.StartRefresher(...)` | cmd/server/stage2.go:826 | 啟動步驟 | assembly ← observability | observability-lite（**取代 perfMonitor**） | **段 2 最後一步**，本步驟前有 `CheckCancelStep`；沿用原 `perfMonitor` 的位置與形態（可停止的背景任務），使啟停順序的變動面最小。刷新的是**查詢成本不對稱**的指標（活躍會話走 DB、錄影儲存量走檔案系統遍歷、未審閱告警走 DB 聚合）——**不可改為採集當下同步查詢**：採集間隔由外部 Prometheus 決定（可低至 15s），同步查詢等於讓外部設定直接放大本系統的 DB 與磁碟負載。停止函式以 `sync.Once` 保證冪等（B 模式每次解封建立新任務）。**前身 perfMonitor 連同 `internal/middleware/metrics.go` 整組退場**：其行程內延遲統計與新的 Prometheus middleware 落在同一個全域位置，留著即每個請求統計兩次；其「效能退化偵測」只 `log.Printf`（無人消費、容器重啟即失），正解是採集端對 histogram 設 alerting rule。 |

---

## 7. 釋放登記序（`release:`，15 筆；列序＝登記序，**執行為 LIFO 反序**）

> `seal.ResourceBag` 以**反序**釋放（`internal/seal/cancel.go:60` 起）：後建者通常依賴先建者
> （排程器依賴服務、服務依賴 codec），先關依賴者才不會讓仍在跑的 worker 打到已釋放的物件。
> 單項失敗或 panic 不中斷後續（`errors.Join` 聚合）；`Release` 冪等。
> **本節列序即登記序**；下表最後一列最先被釋放。

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| R-1 | release:cmd/server/sealwire.go:sealJournalReplay | 等待封印期 journal 回灌結束 | cmd/server/sealwire.go:435 | 停止步驟（等待點） | assembly ← sealjournal／audit | —（不動） | **刻意最後登記 ⇒ LIFO 下最先被等待**：稍後才收的審計服務（R-7）此時仍在，回灌中的列不會落空。**且先登記等待點、再起 goroutine**——反序會留下「已在跑但還沒有人等得到」的窗口（實測形態是測試偶發「TempDir RemoveAll: directory not empty」）。註：本項於 `publishStage2` 內登記，故在 B 模式解封路徑上其登記時點晚於 R-2…R-13 全部。 |
| R-2 | release:cmd/server/stage2.go:keyManager | `keyManager.ZeroizeForRelease()` | cmd/server/stage2.go:184 | zeroize | keyvault | W2 | **第 2 個登記 ⇒ 倒數第 2 個執行**。全部 KEK 衍生材料的持有者都排在它之後登記（故先釋放），此序不可反轉：先歸零根材料會讓仍在收束的推送器無法解密其持有的通道明文（雖然它是覆寫記憶體而非需要解密，但 `ciphers` 快取被清空後任何殘留解密路徑即失敗）。 |
| R-3 | release:cmd/server/stage2.go:auditFailureService | `ResetAuditFailureSingleton()` | cmd/server/stage2.go:248 | reset | audit | W4 | 晚於它釋放的項目若仍呼叫 `Report()` 會重建單例而洩漏一份圖。 |
| R-4 | release:cmd/server/stage2.go:syslogForwarder | `syslogForwarder.Stop()` | cmd/server/stage2.go:269 | 停止步驟 | audit | W4 | **必須晚於 R-5 執行**（＝早於 R-5 登記）：R-5 解除 `auditPublishHook` 之後才停轉發器，否則已解 hook 但轉發器仍在跑的窗口內，佇列中的列無人消費。現況登記序 R-4 → R-5 ⇒ 執行序 R-5 → R-4，**正確**。 |
| R-5 | release:cmd/server/stage2.go:auditIntegrity | `SetAuditCreateHooks(nil, nil)` ＋ `ResetAuditIntegritySingleton()` | cmd/server/stage2.go:287 | hook 解除＋reset | audit | W4 | **同一個閉包內兩步的順序是契約**（先解 hook、後解單例）；見 H-11／H-12／S-9。 |
| R-6 | release:cmd/server/stage2.go:connectionRegistry | `registry.CloseAll()` | cmd/server/stage2.go:364 | 停止步驟 | 接入層 | —（不動） | 實際收線的主力（ST-25 的三個持有者無全量關閉入口）。必須晚於全部會寫審計的路徑釋放？**否**——現況登記於第 6 位，執行序在 R-7…R-13 之後，即**連線先於審計服務關閉**，這是正確方向：仍在處理中的連線可能還會產生審計列。 |
| R-7 | release:cmd/server/stage2.go:auditService | `auditService.Shutdown(ctx)` | cmd/server/stage2.go:402 | 停止步驟（flush） | audit | W4 | **審計 worker pool 的 flush 點**。執行序上晚於 R-8…R-13（排程器、推送器、簽章）而早於 R-6（連線）——即「先停產生者、再 flush 審計、最後收連線」的相反：現況是連線最後關。**此處為已知的排序張力**：`main.go:212` 以「關 HTTP server → 再收束段 2 資源」的更外層順序保證請求已停，故 bag 內的相對序不影響 HTTP 路徑的審計；但**協議連線（WS）不經 HTTP Shutdown**，理論上存在「auditService 已 flush、連線仍在寫審計」的窗口（見 §10 風險 3）。 |
| R-8 | release:cmd/server/stage2.go:alertMatcher | `ResetAlertMatcherSingleton()` | cmd/server/stage2.go:447 | reset | audit | W4 | 同 R-3 形態。 |
| R-9 | release:cmd/server/stage2.go:alertNotifier | `StopAlertNotifierForRelease(alertNotifier)` | cmd/server/stage2.go:465 | reset＋zeroize＋停止 | audit | W4 | **必須晚於 R-11／R-12 執行**（＝早於它們登記）：兩個排程器是唯二持有本物件直接參考的路徑，未先停即 in-flight `Enqueue` 對已關閉佇列 `send` 而 panic。現況登記序 R-9 → R-11 → R-12 ⇒ 執行序 R-12 → R-11 → R-9，**正確**（函式註解明文依賴此 LIFO 前提）。 |
| R-10 | release:cmd/server/stage2.go:exportSigning | `exportSigning.ZeroizeForRelease()` | cmd/server/stage2.go:510 | zeroize | keyvault | W2 | 執行序早於 R-2（keyManager），即先歸零衍生材料、再歸零根材料。 |
| R-10b | release:cmd/server/stage2.go:checkpointSigning | `checkpointSigning.ZeroizeForRelease()` | cmd/server/stage2.go:525 | zeroize | keyvault | —（audit-checkpoint-chain 新增） | 同 R-10：執行序早於 R-2（keyManager），先歸零衍生材料再歸零根材料。與 R-10 的相對序無約束（兩把鑰互不依賴）。 |
| R-11 | release:cmd/server/stage2.go:changeSecretScheduler | `changeSecretScheduler.Stop()` | cmd/server/stage2.go:578 | 停止步驟 | asset | W6 | 見 R-9。**已知缺口**：`Stop` 不等 in-flight（tasks 2.1a）。 |
| R-11b | release:cmd/server/stage2.go:changeSecretRetryScheduler | `changeSecretRetryScheduler.Stop()` | cmd/server/stage2.go:593 | 停止步驟 | asset | —（change-secret-ssh-deepening 新增） | 見 R-9：登記晚於 R-9（alertNotifier）⇒ 執行早於它。**已知缺口同 R-11**：`Stop` 不等 in-flight。 |
| R-12 | release:cmd/server/stage2.go:accessRequestScheduler | `accessRequestScheduler.Stop()` | cmd/server/stage2.go:628 | 停止步驟 | authz | W7 | 見 R-9。 |
| R-13 | release:cmd/server/stage2.go:metricsRefresher | `stopRefresher()` | cmd/server/stage2.go:874 | 停止步驟 | assembly | observability-lite（**取代 perfMonitor**） | 最後登記的 stage2 項 ⇒ 最先執行（R-1 除外，其登記更晚）。以 `sync.Once` 保證 `close(stop)` 冪等。**先停刷新再收服務**：反序會讓刷新任務在 DB 連線池已關後仍發查詢，產出一串無意義的錯誤日誌淹掉真正的關機失敗訊息。 |

---

## 8. 行程收尾步驟（`shutdown:`，3 筆；列序＝執行序）

| ID | 錨點鍵 | 項目 | file:line | 類別 | 所屬模組 | 落地階段 | 順序敏感理由 |
|---|---|---|---|---|---|---|---|
| SD-1 | shutdown:解封端點獨立監聽 | `sealSrv.Shutdown` | cmd/server/main.go:218 | 停止步驟 | assembly（不搬） | —（不動） | 僅 B 模式且設 `SEAL_UNSEAL_BIND_ADDR` 時存在。先關隔離監聽再關主監聽。 |
| SD-2 | shutdown:主監聽 | `srv.Shutdown` | cmd/server/main.go:221 | 停止步驟 | assembly（不搬） | —（不動） | **順序不可倒**（`main.go:212` 明文）：仍在處理中的請求可能還會產生審計列，故 HTTP 必須先關、再收束段 2 資源。 |
| SD-3 | shutdown:段 2 資源 | `shutdown(ctx)` → `graph.Release(ctx)`／B 模式另含 `machine.WaitCleanup()` ＋ `journal.Close()` | cmd/server/main.go:222 | 停止步驟 | assembly（不搬） | —（不動） | 觸發 §7 的 LIFO 釋放。**單步失敗不中斷後續**（跳過剩下的收束會讓資源永久洩漏），但失敗不得被吞掉——回傳非零碼供 supervisor／CI 觀察（`runShutdown`，`main.go:284`）。B 模式的 `journal.Close()` 必須最後：封印期留痕在服務圖收束期間仍可能寫入。整個收尾有 **5 秒逾時**（`main.go:209`）。 |

---

## 9. reset 與 zeroize 序（封印狀態機／金鑰清零／journal）

### 9.1 段 2 可重跑是全部 reset 需求的來源

B 模式每次解封都重建一次完整服務圖（`seal.Machine` 的 `Stage2` 回呼）。現況的套件級單例、
全域 hook 與常駐明文材料**都假設「一個行程只建構一次」**（`stage2_release.go:10-18` 自陳）。
故：

1. **不清單例** → 舊持有者的物件在封印期間仍被 GORM 直寫路徑呼叫（G-7／G-9／G-12／G-14／G-16）。
2. **不歸零材料** → 被丟棄的服務圖仍握著 KEK 衍生明文（S-12／S-13）。

兩者都是封印設計要擋的「兩份服務圖同時持有資源」的實際形態。

### 9.2 zeroize 的三個層次與相對序

| 層次 | 位置 | 相對序要求 |
|---|---|---|
| 請求載荷 | `api.SealUnsealPayload.Zeroize`（`internal/api/seal_payload.go:297`）、`rewrapPayload.Zeroize`（`key_rewrap_payload.go:97`） | `defer` 於解碼後立即登記（`sealwire.go:269`、`key_management_handler.go:283`）——**材料離開臨界區之前**。 |
| 衍生材料 | `ExportSigningService.ZeroizeForRelease`（S-13，release 第 10 位登記）／`StopAlertNotifierForRelease` 內的通道明文置空（S-10，第 9 位） | **必須早於根材料執行**（LIFO 下＝晚於根材料登記）。現況正確。 |
| 根材料 | `KeyManagerService.ZeroizeForRelease`（S-12，release 第 2 位登記 ⇒ 倒數第 2 執行） | 逐位元組覆寫 `keys`／清空 `ciphers`／`active`／`kek`。**只丟參考不夠**——切片內容可能仍被 `ciphers` 快取引用。 |

**誠實邊界**：`string` 不可覆寫，通道 URL／secret 的「歸零」實際是「不再持有參考」
（`stage2_release.go:70` 與 `api.SealUnsealPayload.Zeroize` 同一條界線）。本檔如實記載，
不宣稱記憶體已被抹除。

### 9.3 封印狀態機的 reset 語義

- 全域狀態由單一 `atomic.Pointer[sealNode]` 承載，**所有轉態一律 CAS(observed, new)**；
  CAS 失敗即代表本次結果已被較新世代取代，一律丟棄（`internal/seal/state.go:1-11`）。
  本套件**不得**出現 `if cur.generation == mine { Store(new) }` 的兩步形式。
- `cleanupToken`（`state.go`）使「不放行兩份服務圖」成為 CAS 的**結構性前置**（格 2 的
  前置條件為 `cleanup == nil`），而非散文承諾。
- 12 格遷移表（G-116）是唯一判準來源；`TestCellsPairwiseExclusive` 以窮舉笛卡兒積驗證兩兩互斥。
- 四態：`sealed` → `unsealing` → `unsealed`／`sealed-faulted`。段 2 失敗**不殺行程**
  （回機器碼＋轉 sealed-faulted、可重試）；但 `publishStage2` 發現「已發佈的圖不具 router」時
  **刻意 `log.Fatalf`**——此刻狀態已 unsealed 且無出邊，不換手＝恆 503 且無法重試，
  fail-close 結束行程反而是唯一可恢復的處置（`sealwire.go:229-236`）。

### 9.4 journal 的 reset／關閉序

1. 段 1 開監聽前建立（`stage1.go:231`）：**建立失敗即不得開放監聽**，不受任何 feature flag 控制。
2. 解封成功後回灌（`startSealJournalReplay`，登記為 release R-1 ⇒ 最先被等待）。
3. 行程收尾：`machine.WaitCleanup()` → `journal.Close()`（`main.go:117-120`），**在服務圖 Release 之後**。

---

## 10. 已知缺口與風險（如實記載，不宣稱已覆蓋）

| # | 缺口 | 證據 | 影響 | 處置 |
|---|---|---|---|---|
| 1 | `sshHandler` 的 `MonitorHub`／`ShareManager`／`ConnectTokenManager` 與 `statsClients` 持有的活躍 `*ssh.Client` **無全量關閉入口**，故 ST-25 未登記任何 releaser | `cmd/server/stage2.go:462-448` 自陳 | B 模式每次解封殘留一份；行程收尾靠行程結束兜底 | 全量關閉入口另案處理，不在本表登記範圍；**不登記空 releaser**（空 releaser 會讓 bag 看起來完整而製造假安全感） |
| 2 | `changeSecretScheduler.Stop()` **不等 in-flight**；各 `Stop()` 的冪等性未統一 | `internal/modules/audit/stage2_release.go:19-20` 自陳 | 收束逾時後仍可能有改密作業在跑 | 同上，另案處理 |
| 3 | `auditService.Shutdown`（R-7）執行序早於 `connectionRegistry.CloseAll`（R-6） | §7 R-6／R-7 | HTTP 路徑由 `main.go:212` 的外層順序保證；**協議連線（WS）不經 HTTP Shutdown**，理論上存在「審計已 flush、連線仍在寫」的窗口 | 只登記、不改動（改動屬行為變更）。「完整啟動 → 注入失敗回滾 → 反向關閉」的整合測試（`cmd/server/lifecycle_startup_shutdown_test.go`）SHALL 涵蓋此序，若實測有列遺失即升為缺陷 |
| 4 | 本 manifest 的守衛**只驗結構與順序，不驗執行期真的按此序跑** | 守衛設計 | 例如 `mark()` 被刪除但服務仍建構，守衛看不到 | 由 `stage2ServiceInventory` ⇄ `appGraph.ServiceNames()` 的既有比對，加上 `cmd/server/lifecycle_startup_shutdown_test.go` 的啟停整合測試共同承擔 |
| 5 | 跨包 `init()` 順序**在 Go 中由 import 圖決定**，本守衛無法斷言 | Go 語言語義 | I-3／I-4／I-5 拆包後若消費者包與定義包無 import 關係，順序未定義 | 依賴矩陣（§3.2）本身即約束，policy 的依賴矩陣須維持全 ✗ |
| 6 | 本檔以 `file:line` 為人讀定位，行號會漂移 | — | 誤導風險 | 守衛只比對錨點鍵；每次搬遷收尾時 SHALL 以 `LIFECYCLE_DUMP=1` 重生行號（見 §0.4） |

### 10.1 最危險的三個順序敏感點

1. **H-10 `model.SetAuditCreateHooks` 的註冊時點**（ST-7）。之前寫出的審計列 HMAC 為空且不進
   syslog tee，而驗章端會把空章列當成上線前的歷史列——**失敗形態是「更安靜」而非更吵**。
   既有守衛只釘「同檔、先於遷移呼叫」，不釘「先於全部審計寫入」。
2. **R-9 `StopAlertNotifierForRelease` 依賴 LIFO 的隱含前提**。「呼叫端 SHALL 先停排程器」
   這件事**沒有任何程式碼強制**，它成立僅因為兩個排程器碰巧登記在推送器之後。
   任何一次搬遷移動 bag 的登記位置都會靜默破壞它，症狀是收束時 panic（尚可見）或
   in-flight 告警遺失（不可見）。
3. **R-2 `keyManager.ZeroizeForRelease` 相對其他釋放項的位置**。它是「封印」在記憶體層面
   唯一的實體動作；若被移到更晚登記（＝更早執行），被丟棄的服務圖在其餘收束期間仍持有可用
   codec，「封印」退化為路由層的假象——而這條路徑上沒有任何測試會變紅。
