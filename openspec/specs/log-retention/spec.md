# log-retention Specification

## Purpose
規範審計資料的保留與到期清除：保留政策、以檢查點區間為單位的分批清除、清除動作入審計與 tombstone 驗證語義、有界過度保留為已知代價，以及永久保留水位的誠實語義。
## Requirements
### Requirement: 審計資料保留政策

系統 SHALL 對 audit_logs、session_commands、command_alerts、錄影檔四類審計資料提供各自獨立的保留天數政策（0 = 永久保留，PCI 建議值 365）；政策值 SHALL 可於安全政策頁設定並即時生效，無需重啟。

自 `audit-checkpoint-chain` 起，**audit_logs 的清除粒度改為檢查點區間**：保留天數的語義為「該區間內最新一列的 created_at 早於 cutoff 時，整個區間才可清除」（詳見「audit_logs 以檢查點區間為清除單位」）。其餘三類維持逐列／逐檔行為不變。此差異 SHALL 於安全政策頁的保留鍵說明與 release note 明載——部署後首輪 retention 會出現「已過期但所屬區間未全數過期的列暫時留存」，此為預期行為而非缺陷。

系統 SHALL 另提供檢查點自身的保留天數政策鍵 `retention_checkpoint_days`（見 `security-policy`；**出廠 0＝永久**），其值 SHALL 受跨鍵約束（不得低於四類資料保留鍵中最長者，0 視為無限大）。出廠值為 0 使出廠狀態自洽——`RetentionCovers(0, 任意)` 恆真，任一資料保留鍵的出廠值（含永久）皆被涵蓋。

#### Scenario: 預設不清除
- **WHEN** 全新部署未調整任何保留政策
- **THEN** audit_logs、session_commands、command_alerts 三鍵為 0，retention scheduler 不刪除該三類資料（錄影檔沿既有出廠值 90 天，見 `security-policy`），行為與導入前一致

#### Scenario: 設定後到期清除
- **WHEN** 管理員將 audit_logs 保留天數設為 365，且存在建立時間早於 365 天的 audit_logs 列，其所屬檢查點區間內全部列皆早於 cutoff
- **THEN** 下次 retention 排程執行時該區間整段被清除並寫入 purge tombstone，未過期區間不受影響

#### Scenario: 區間未全數過期則暫留
- **WHEN** 某檢查點區間內既有早於 cutoff 的列、也有晚於 cutoff 的列
- **THEN** 該區間整段暫不清除（有界過度保留），下次區間內最新列亦過期時才清；系統 SHALL NOT 部分刪除該區間

### Requirement: 到期分批清除

retention scheduler SHALL 每日執行一次，對每類過期資料分批刪除（固定批量＋單次執行筆數上限）；單次執行未刪完 SHALL 於次日繼續，且不阻塞線上請求。

audit_logs 的清除 SHALL 以「已封檢查點區間」為最小不可分割單位：單次執行 SHALL 逐個可清區間處理，每個區間的刪除與其 tombstone 寫入 SHALL 為一體（見「purge tombstone」），單次執行的區間數 SHALL 受既有單次上限（總筆數）約束；達上限時 SHALL 於區間邊界停止，SHALL NOT 在區間中途停止而留下半清區間。「部分完成」的判定與留痕語義維持既有行為。

#### Scenario: 大量積壓分批處理
- **WHEN** 首次啟用保留政策時過期列數超過單次執行上限
- **THEN** 本次僅刪除至上限即停止，清除記錄標明「部分完成」，剩餘量於後續排程繼續刪除

#### Scenario: 上限落在區間中途
- **WHEN** audit_logs 清除進行中，單次上限的剩餘額度小於下一個可清區間的列數
- **THEN** 本次不處理該區間（整段留待次輪），清除記錄標明部分完成；DB 中 MUST NOT 出現任何被部分刪除的檢查點區間

#### Scenario: 錄影檔與 DB 列一致清除
- **WHEN** 錄影保留政策到期觸發清除
- **THEN** 過期錄影檔案自磁碟移除，行為與既有 recording cleanup 一致

### Requirement: 清除動作入審計

每次 retention 清除執行後，系統 SHALL 寫入一筆 audit_log，內容包含資料類型、清除時間範圍、實際刪除筆數與是否部分完成；清除本身失敗 SHALL 記錄錯誤且不得靜默。audit_logs 類的清除留痕 SHALL 另載明本次清除的檢查點 seq 清單（或其區間），使「哪些區間被合法清除」在鏈上可查。

該留痕列本身寫入 audit_logs，因而落在後續檢查點區間內受鏈二次見證；其亦 SHALL 經 syslog 轉發（沿既有機制）。

#### Scenario: 清除留痕
- **WHEN** retention scheduler 刪除了 1200 筆過期 session_commands
- **THEN** audit_logs 出現一筆 action 為 retention purge 的記錄，載明 session_commands、時間範圍與 1200 筆

#### Scenario: 區間清除留痕含 seq
- **WHEN** retention 清除了 audit_logs 的三個檢查點區間
- **THEN** 留痕記錄載明該三個 seq 與其 id 區間、合計刪除筆數；該留痕列於後續封章時被納入新檢查點

### Requirement: audit_logs 以檢查點區間為清除單位

audit_logs 的 retention 清除 SHALL 以已封檢查點的 id 區間為單位。區間可清條件 SHALL 為全部成立：該檢查點已封章且簽章有效、`row_count > 0`、且其 `max_created_at < cutoff`（cutoff 沿現行 audit_logs 保留天數計算）。任一條件不成立 SHALL NOT 清除該區間。

清除執行 SHALL 刪除 `[id_from, id_to]` 內的全部列，SHALL NOT 依 `created_at` 逐列篩選刪除——區間內即使存在個別更早過期的列，其清除時機一律由整區間決定。

系統 SHALL NOT 因本改造新增任何繞過 model 刪除守衛的第二條刪除入口：區間清除與既有 genesis 前逐列清除 SHALL 共用同一收口的原生 SQL 路徑家族（見 `audit-integrity` 之審計表刪改守衛）。

`row_count = 0` 的空區間 SHALL NOT 進入清除路徑（其無列可刪），其生命週期由檢查點自身的保留政策決定。

#### Scenario: 只清整段過期的區間

- **WHEN** 區間 A 的 `max_created_at` 早於 cutoff、區間 B 的 `max_created_at` 晚於 cutoff
- **THEN** A 整段被清除、B 完全不動；清除後對兩區間執行內容層驗證分別得 `purged_legal` 與 `passed`

#### Scenario: 未封章區間不清除

- **WHEN** 最新尾段的列已早於 cutoff 但尚未被任何檢查點覆蓋
- **THEN** 該些列不被清除（等待封章後才具備可清資格）

#### Scenario: 無第二刪除入口

- **WHEN** 稽核後端全部 audit_logs 的 DELETE 語句
- **THEN** 僅存在 retention 收口路徑（區間清除與 genesis 前逐列清除），守衛測試在新增任何其他刪除語句時轉紅

### Requirement: purge tombstone 與其驗證語義

區間清除成功後系統 SHALL 於該檢查點記錄寫入 `purged_at` 與 `purge_signature`：以檢查點簽章私鑰對固定 canonical 編碼的 `(seq, purged_at, row_count, policy_days)` 簽章，並 SHALL 記錄該簽章所用的簽章鑰版本（使簽章鑰輪替後 tombstone 仍可驗）。

**區間列的刪除與其 tombstone 寫入 SHALL 為單一交易**：系統 SHALL NOT 產生「列已被刪除但無有效 tombstone 已提交」的持久狀態。刪除中途失敗、行程中斷或 tombstone 簽章失敗 SHALL 使整個區間的刪除回滾，該區間留待下輪重試，且失敗 SHALL 記錄不靜默。

驗證語義 SHALL 為：區間列不存在且 `purge_signature` 驗過 → `purged_legal`（內容不可重算，`row_count` 與 `agg_hash` 主張仍保留於已簽章的檢查點）；區間列不存在或短少且無有效 tombstone → `purged_invalid`（竄改告警）。攻擊者無簽章私鑰即無法偽造 tombstone；持私鑰者屬誠實邊界 R0。

已寫入 `purged_at` 的檢查點 SHALL NOT 再被清除路徑重複處理，且其被簽章欄位 SHALL 維持不可變（見 `audit-checkpoint-chain` 的不可變守衛）。

#### Scenario: 合法清除不觸發告警

- **WHEN** retention 合法清除某區間後，稽核員對該區間執行內容層驗證
- **THEN** 回報 `purged_legal` 並附 `purged_at` 與驗過的 tombstone，SHALL NOT 回報任何竄改狀態

#### Scenario: 刪除成功但 tombstone 失敗必回滾

- **WHEN** 區間列已刪除但 tombstone 簽章或寫入失敗（含簽章鑰暫時不可用）
- **THEN** 該交易整體回滾（列仍在），錯誤入留痕；後續驗證回報 `passed` 而非 `purged_invalid`——系統 MUST NOT 因自身清除流程而製造假的竄改告警

#### Scenario: 清除中途中斷不留半清區間

- **WHEN** 區間清除交易進行中行程被中止
- **THEN** 重啟後該區間的列完整存在或完整不存在且帶有效 tombstone，兩者之一；MUST NOT 出現列數短少而無 tombstone 的狀態

#### Scenario: 偽造 tombstone 不成立

- **WHEN** 攻擊者以 DB 直寫刪除某未過期區間的列，並自行填入 `purged_at` 與任意 `purge_signature`
- **THEN** 驗證回報 `purged_invalid`（簽章驗不過）

### Requirement: genesis 之前的列維持逐列清除

檢查點 genesis 之前的 audit_logs 列（`id < genesis id_from`）不受任何檢查點覆蓋，其 retention 清除 SHALL 維持現行逐列過期刪除路徑直到清空；該路徑 SHALL 以 id 上界明確界定（`id < genesis id_from`），SHALL NOT 因 cutoff 而誤觸已被檢查點覆蓋的列。

驗證端 SHALL NOT 對 genesis 之前的區段作序列完整性主張——該段列的缺失既不可證為合法清除、也不可證為竄改，SHALL 誠實呈現為「檢查點覆蓋範圍之外」。

#### Scenario: pre-genesis 殘量走舊路徑

- **WHEN** 部署存在 genesis 之前的過期歷史列
- **THEN** 該些列由逐列路徑清除，其刪除不寫任何 tombstone、不影響任何檢查點狀態

#### Scenario: 逐列路徑不越界

- **WHEN** cutoff 涵蓋的時間範圍同時包含 genesis 前的列與已被檢查點覆蓋的列
- **THEN** 逐列路徑僅刪除 `id < genesis id_from` 的列；已被覆蓋的列一律只能由區間路徑處理

#### Scenario: 覆蓋外範圍誠實呈現

- **WHEN** 使用者查詢的時間範圍早於 genesis
- **THEN** 驗證結果標示該段為「檢查點覆蓋範圍之外」，不宣稱通過亦不報竄改

### Requirement: 有界過度保留為已知代價

以區間為清除單位 SHALL 導致有界的過度保留：區間內只要有一列未過期，整區間暫不清除。此代價 SHALL 明載於 spec、安全政策頁保留鍵說明與 release note。

一般區間的 `created_at` 跨度約等於其封章跨度（至多 1 小時＋grace），過度保留量有界；含封印期回灌列的區間，回灌列的實際保留期 SHALL 被理解為「自回灌時刻起算」而非「自事件時刻起算」。

反向偏差（早於保留期刪除）SHALL NOT 發生：任何情形下系統 SHALL NOT 因區間化而刪除任何尚未過期的列。

#### Scenario: 過度保留有界且可解釋

- **WHEN** 管理員發現部分已過期列仍在 DB 中
- **THEN** 該些列必屬於「所屬區間尚有未過期列」的情形，管理介面或文件可據此解釋，且其保留延長不超過一個區間跨度

#### Scenario: 不提早刪除

- **WHEN** 任一區間內存在尚未過期的列
- **THEN** 該區間不被清除，未過期列一律保留

### Requirement: 檢查點自身的保留與鏈修剪

檢查點記錄 SHALL 依 `retention_checkpoint_days` 政策鍵保留（**出廠 0 = 永久**，上界 3650 天）。到期清除 SHALL 自鏈頭（最舊 seq）起整段修剪，SHALL NOT 自中段挖除（中段挖除必造成無法解釋的 seq 斷洞）。

每次修剪 SHALL 產生一筆以檢查點簽章私鑰簽章的**修剪記錄**，內容至少含：被修剪的最後一個 seq 與其檢查點雜湊、修剪時間、政策天數、所用簽章鑰版本；該記錄 SHALL 持久保存且不隨被修剪的檢查點消失。修剪後的殘餘鏈 SHALL 仍可驗證：驗證端 SHALL 以修剪記錄作為新的鏈起點錨定，SHALL NOT 因鏈頭 seq 不為 1 而回報 `seq_gap` 或 `chain_broken`。

修剪動作 SHALL 入審計留痕（沿清除動作入審計機制）。無有效修剪記錄的鏈頭斷檔 SHALL 回報為異常而非合法修剪。

#### Scenario: 修剪後殘鏈仍可驗

- **WHEN** 最舊的 100 個檢查點依政策被修剪，稽核員對殘餘鏈執行結構層驗證
- **THEN** 驗證通過；鏈起點以修剪記錄錨定，不回報 seq 斷洞

#### Scenario: 無修剪記錄的斷檔判為異常

- **WHEN** 攻擊者直接刪除最舊的若干檢查點列而未留下有效修剪記錄
- **THEN** 結構層驗證回報異常（鏈頭無法錨定），不被當作合法修剪

#### Scenario: 不自中段修剪

- **WHEN** 到期修剪執行
- **THEN** 僅自最舊 seq 起連續修剪，任何中段檢查點 MUST NOT 被清除

### Requirement: 永久保留水位

系統 SHALL 對每一受保留政策管理的資料類別（audit_logs、session_commands、command_alerts、錄影）維持一筆**永久保留水位**記錄，內容至少含：資料類別、已清除資料的時間上界、最近清除執行時刻、該次清除所用的保留天數、上次執行是否部分完成。

水位的時間上界 SHALL 單調前進（只取較新值），SHALL NOT 因保留天數被調大而倒退——倒退會使已被清除的區間重新顯示為「資料仍在」。

水位記錄 SHALL NOT 被任何保留政策清除（永久保留）。其體積為每類別一列，恆定。

系統 SHALL NOT 以「清除動作入審計」所寫的 audit_log 留痕作為清除事實的唯一來源：該留痕列本身位於 audit_logs 內並受其保留政策清除，會在最需要它的時點消失。

保留天數為 0（永久）時 SHALL NOT 更新水位。

水位的生產端 SHALL 由實際執行清除的 retention 服務接線；水位測試 SHALL 至少有一條走真實清除流程的路徑，SHALL NOT 全數以直接呼叫水位服務代替——僅測水位服務會使「服務存在但無人呼叫」的斷線保持全綠。

#### Scenario: 清除後水位前進

- **WHEN** retention 清除了截至 2026-01-31 的 session_commands
- **THEN** 該類別水位的時間上界更新為該清除批次涵蓋的最新時間，並記錄執行時刻與保留天數

#### Scenario: 政策調大不使水位倒退

- **WHEN** 管理員將保留天數自 90 調為 365
- **THEN** 既有水位維持不變，系統 SHALL NOT 宣稱先前已清除的區間資料仍在

#### Scenario: 從未清除即為完整

- **WHEN** 某類別自部署以來從未執行過清除
- **THEN** 該類別無水位記錄，查詢端 SHALL 將其視為完整（present），SHALL NOT 視為狀態未知

#### Scenario: 水位不被清除

- **WHEN** 任何保留政策到期執行
- **THEN** 水位記錄不被刪除

#### Scenario: 真實清除流程推進水位

- **WHEN** 保留政策到期並經 retention 服務實際執行一次清除
- **THEN** 對應類別的水位前進，查詢端據此對該區間回報 `purged`

### Requirement: 保留水位的誠實語義

保留水位的語義 SHALL 為「早於該時間上界的該類資料**不完整**」，SHALL NOT 被表述為「早於該時間者已全部刪除」——分批清除、單次上限造成的部分完成、以及 audit_logs 的區間化過度保留，皆會使水位之前仍有殘留資料存在。

上次清除為部分完成時，查詢端 SHALL 能據此標示清除仍在進行中。

水位記錄無簽章保護，SHALL 明載為**可用性標記而非防篡改證明**；具資料庫寫入權限者可竄改。audit_logs 類另有簽章化的清除證明（檢查點 tombstone），其餘類別沒有。

錄影類的清除狀態以水位作**時間近似**：單檔清除失敗時個別會話會被誤標為已清除；誤標方向 SHALL 選在此側，SHALL NOT 反向（把已清除的標成可回放只會給出無解釋的回放失敗）。

#### Scenario: 殘留資料不與水位矛盾

- **WHEN** 水位之前仍有尚未被清完的殘留列被查出
- **THEN** 系統呈現為「該區間已依保留政策清除（清除進行中）」，SHALL NOT 因殘留存在而回報矛盾或錯誤
