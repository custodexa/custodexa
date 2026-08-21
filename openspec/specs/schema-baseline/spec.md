# schema-baseline Specification

## Purpose
資料庫 schema 的事實源與其守衛：schema 由單一 baseline migration 完整定義（零啟動時自動遷移）、
model 宣告與 baseline 的兩層一致性守衛、對不認識的既有 schema 版本 fail-close 拒絕啟動、
內建種子資料以終態冪等寫入，以及 baseline 不提供回滾入口的明確設計。
## Requirements
### Requirement: schema 的單一事實源

資料庫 schema SHALL 由單一 baseline migration 完整定義，包含全部資料表、欄位、索引、
CHECK 約束與內建種子資料。系統 SHALL NOT 於啟動時執行任何 schema 自動遷移
（GORM `AutoMigrate` 或等效機制）——**兩個並存的 schema 來源會使先執行者的產物令後執行者的
`CREATE ... IF NOT EXISTS` 靜默略過，其差異在啟動日誌與測試中皆不可見**。追蹤表
（`schema_migrations`）自身的建立為唯一例外，SHALL 以原生 DDL 完成，SHALL NOT 借道自動遷移。

baseline 的 DDL SHALL 為無條件形式，SHALL NOT 使用 `IF NOT EXISTS` 之類的存在性守衛：
baseline 於非空 schema 上執行時必須立即失敗，SHALL NOT 產出「執行成功但未建立任何物件」
的結果——後者會使等價驗證與 schema 比對全部假綠。

baseline 的執行 SHALL 為原子的：其 DDL 與 `schema_migrations` 的版本列 SHALL 於同一交易內
完成，中途失敗 SHALL NOT 留下半套 schema。

#### Scenario: 空資料庫初始化

- **WHEN** 系統對一個空的資料庫 schema 啟動
- **THEN** baseline 執行後 schema 含全部資料表、索引與約束，`schema_migrations` 僅有 baseline 一列，
  且啟動過程未執行任何 schema 自動遷移

#### Scenario: baseline 於非空 schema 執行即失敗

- **WHEN** baseline 於一個已含同名資料表的 schema 上執行
- **THEN** 執行失敗並回可辨識錯誤，SHALL NOT 靜默略過既有物件而回報成功

#### Scenario: 產品程式碼不含自動遷移呼叫

- **WHEN** 掃描產品程式碼（排除測試檔）中的 schema 自動遷移呼叫
- **THEN** 命中數為零，且該掃描不設任何例外條目

### Requirement: model 宣告與 baseline 的一致性守衛

移除 schema 自動遷移後，「model 改了而 baseline 未改」SHALL 由守衛測試攔截，
SHALL NOT 僅依賴人工複查或執行期錯誤。守衛 SHALL 分兩層，且**兩層皆為必要**：

- **離線層**：不依賴資料庫，以 model 的 schema 解析結果與 baseline 的 DDL 文字雙向比對欄位集合。
  此層 SHALL 在任何開發環境下皆實際執行，SHALL NOT 因缺少資料庫連線而被跳過。
- **資料庫層**：於乾淨 schema 上執行 baseline 後，比對欄位型別、可空性、索引與 CHECK 約束。
  此層 MAY 依賴真實 PostgreSQL 而受環境旗標控制，但 CI SHALL 使其跳過即失敗。

兩層 SHALL 各自具備防假綠下界（解析結果少於預期規模時 SHALL 直接失敗），使解析器故障
表現為失敗而非「零違規」。model 清單 SHALL 保留為守衛的比對來源，SHALL NOT 因不再被執行而刪除。

系統 SHALL NOT 宣稱單元測試全綠即代表 baseline 正確：單元測試於記憶體資料庫上以自動遷移建表，
驗證的是 model 形狀而非 baseline 形狀，兩者僅於本 requirement 的守衛處相遇。

#### Scenario: model 新增欄位而 baseline 未同步

- **WHEN** 於任一 model 新增欄位但未於 baseline 加入對應欄
- **THEN** 離線層守衛失敗並指出該欄位名，且該失敗在未配置資料庫連線的環境中同樣發生

#### Scenario: baseline 遺漏索引

- **WHEN** 自 baseline 移除一條已宣告的索引
- **THEN** 資料庫層守衛失敗並指出該索引名

#### Scenario: 解析器故障不得表現為通過

- **WHEN** 守衛的解析結果少於預期規模（model 數或資料表數低於下界）
- **THEN** 測試直接失敗，SHALL NOT 以空集合上的恆真斷言回報通過

### Requirement: 不認識的既有 schema 版本 fail-close

系統啟動時 SHALL 於執行任何 migration 之前，比對 `schema_migrations` 已套用集合與程式碼所知版本。
已套用集合含程式碼不認識的版本、**且** baseline 版本不在該集合中時，系統 SHALL 拒絕啟動，
SHALL NOT 執行任何 migration、SHALL NOT 產生任何資料庫寫入。

執行期寫入的 marker 版本（非 schema 變更、由功能模組借用追蹤表記錄「已完成評估」者）
SHALL 以具名清單登記為已知版本。**未登記即會使每一個執行過該功能的正常安裝在下次啟動時被自己的
fail-close 擋住**，故該清單 SHALL 有守衛測試：新增執行期 marker 而未登記 SHALL 使測試失敗。

拒絕啟動的訊息 SHALL 具名列出未知版本與其筆數、SHALL 說明本版本以單一 baseline 為 schema 事實源
且不提供既有資料庫的就地升級路徑、SHALL 給出具體的處置動作。訊息 SHALL 明確澄清這不是資料庫損毀，
並 SHALL 警告不得以手動刪除 `schema_migrations` 列的方式繞過。訊息 SHALL NOT 含連線字串、
密碼或主機位址。

#### Scenario: 舊版本鏈的資料庫拒絕啟動

- **WHEN** 資料庫的 `schema_migrations` 含壓縮前的版本列，且 baseline 版本不在其中
- **THEN** 系統拒絕啟動並輸出具名指引；資料表數、索引數與內建告警規則列數於啟動前後完全相同

#### Scenario: 執行期 marker 不觸發 fail-close

- **WHEN** 全新安裝跑完 baseline，功能模組寫入其執行期 marker 版本，系統再次啟動
- **THEN** 系統正常啟動並開始服務，marker 版本不被判為未知版本

#### Scenario: 空資料庫不受影響

- **WHEN** 系統對空資料庫啟動（已套用集合為空）
- **THEN** 不觸發 fail-close，baseline 正常執行

### Requirement: 內建種子資料的冪等寫入

baseline 內建的種子資料 SHALL 以其**最終狀態**寫入（跨多次歷史演進疊加後的結果），
SHALL NOT 只寫入首次引入時的形態。種子寫入 SHALL 為冪等：重複執行 SHALL NOT 產生重複列、
SHALL NOT 回報錯誤。

冪等 SHALL 由資料庫層的唯一性約束承擔（種子的自然鍵上建唯一索引）加寫入時的衝突略過語義，
SHALL NOT 僅依賴「migration 只會跑一次」的執行假設——該假設在追蹤表被外部修改時不成立，
而重複的內建告警規則會使每次命中產生兩份告警與兩份審閱項，且**不報錯**。

為種子自然鍵新增唯一性約束時，該欄位的管理入口（建立與更新）SHALL 將唯一性衝突映射為
登記的機器碼與 4xx 回應，SHALL NOT 讓資料庫層錯誤冒為 5xx。

#### Scenario: 種子重複執行不增列

- **WHEN** 於已含內建種子的 schema 上再次執行種子寫入
- **THEN** 列數不變且不回報錯誤

#### Scenario: 種子為疊加後的終態

- **WHEN** 全新安裝完成後查詢內建告警規則
- **THEN** 其協議欄位為歷次演進疊加後的最終值（含最後一次擴充所併入的協議），
  SHALL NOT 停留在任一中間狀態

#### Scenario: 名稱衝突回機器碼而非 5xx

- **WHEN** 管理者建立或更名告警規則，使其名稱與既有規則相同
- **THEN** 回 409 與登記機器碼（三語齊備），SHALL NOT 回 500

### Requirement: baseline 無回滾入口

系統 SHALL NOT 提供 baseline 的回滾實作：其回滾方向 SHALL 回明確的拒絕錯誤並指出退路為還原備份，
SHALL NOT 實作為「丟棄全部資料表」——後者是外觀像回滾入口、實質是資料庫毀滅操作的東西。

部署與升級文件 SHALL 維持「本版不提供 migration 回滾、唯一退路是還原備份」的既有結論，
SHALL NOT 因 migration 數量減少而暗示回滾變得可行。

#### Scenario: 回滾 baseline 被拒絕

- **WHEN** 對 baseline 版本呼叫回滾
- **THEN** 回非 nil 錯誤並說明退路為還原備份；資料表數不變、無任何物件被刪除

