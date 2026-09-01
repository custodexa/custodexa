# single-instance-guard Specification

## Purpose
TBD - created by archiving change single-instance-guard. Update Purpose after archive.
## Requirements
### Requirement: 啟動期單實例互斥

系統 SHALL 於啟動序列中、資料庫連線建立之後且任何資料庫寫入（含 schema migration）之前，
以 postgres session 級 advisory lock 取得單實例互斥。該鎖 SHALL 由一條**專用的釘選連線**持有
（自連線池取出後終生不歸池），SHALL NOT 在池化連線上取鎖——池會回收閒置連線而使鎖靜默釋放，
或使持鎖連線被其他呼叫者取用而永久洩漏。鎖鍵 SHALL 登記於既有的跨實例鎖 keyspace 單一登記處，
並 SHALL 有撞號守衛測試。

取鎖 SHALL 採非阻塞（try）語義並配合**有界重試**（總等待上限約 10 秒）以吸收前一實例工作階段的
收尾延遲。重試耗盡仍未取得時，系統 SHALL 依「確認啟動與留痕」requirement 判定操作者是否已提供
與本次持鎖者指紋相符的確認；**未提供或不相符即 SHALL NOT 啟動服務**：不開放任何監聽、不執行 migration、
不產生任何資料庫寫入，並印出「攔下訊息」requirement 規定的警告。系統 SHALL NOT 以阻塞式等待取代攔下——
操作者看到的必須是明確的警告與救援指令，不是停在「啟動中」。

取鎖回應失敗（連線中斷、回應解析失敗）時，該連線 SHALL 被丟棄而非歸池（鎖可能已在資料庫端授予）。

#### Scenario: 第二實例未經確認即被攔在任何寫入之前
- **WHEN** 一個實例已持有單實例鎖，另一個實例未設定確認值即對同一資料庫啟動
- **THEN** 第二實例於重試上限內停止啟動、未開放監聽、未執行 migration；資料庫的資料表數、索引數與
  `schema_migrations` 列數於其啟動前後完全相同；啟動日誌含警告與救援指令

#### Scenario: 前一實例退出後新實例無需確認即可起
- **WHEN** 持鎖實例以任何方式退出（優雅關閉、收束逾時 `os.Exit`、`log.Fatalf`、SIGKILL），隨後啟動新實例且未設定確認值
- **THEN** 新實例於重試上限內取得鎖並正常啟動，不印攔下警告

#### Scenario: 毫秒級的工作階段收尾競態被吸收
- **WHEN** 新實例的取鎖發生在前一實例行程已退出、但資料庫尚未處理完其連線 EOF 的窗口內
- **THEN** 新實例於重試中取得鎖，不產生攔下警告

#### Scenario: 取鎖回應失敗不留殘鎖
- **WHEN** `pg_try_advisory_lock` 已於資料庫端授予，但回應在客戶端失敗
- **THEN** 該連線被丟棄（不歸池），資料庫隨連線結束釋放該鎖，`pg_locks` 無殘留

### Requirement: 攔下訊息的內容、持鎖者指紋與救援指令

攔下訊息 SHALL 含「本版不支援多實例」字樣，SHALL 陳述現況（單實例鎖由另一個資料庫工作階段持有——
SHALL NOT 寫成「另一個實例持鎖」，殘留工作階段時該說法不成立）、簡述風險（多實例同時執行會造成金鑰快取、
匯出、錄影與封印期留痕的資料問題），並 SHALL 澄清這不是資料庫損毀且**本次啟動未由本實例執行 migration
或任何資料寫入**（SHALL NOT 宣稱「資料庫未被寫入」——持鎖的工作階段可能正在寫）。

訊息 SHALL 含**持鎖者指紋**：由持鎖工作階段的 `application_name`、backend pid 與 `backend_start`
組成的可讀形式，以及該三欄正規化字串之 sha256 十六進位前 12 碼作為**確認碼**。指紋 SHALL 由本實例在
釘選連線上以鎖鍵連接 `pg_locks` 與 `pg_stat_activity` 查得；NULL 欄以固定占位符代入正規化字串。
指紋查詢本身失敗時，系統 SHALL 以標示「持鎖者細節不可得」的降級指紋產生確認碼，SHALL NOT 因此讓操作者無路可走。

訊息 SHALL 給出**兩條救援指令**：(a) 若確認另一實例仍在執行，先停止它再重啟本實例（無需任何設定）；
(b) 若確認無其他實例在執行，設定確認環境變數為上列確認碼後重啟，並 SHALL 明說此啟動會寫入審計事件、
在管理介面顯示橫幅，且確認後兩實例並存造成的資料問題由確認者承擔。訊息 SHALL 說明確認碼綁定上列指紋，
持鎖者變更後失效。

訊息 SHALL NOT 含連線字串、密碼、主機位址、資料庫名，亦 SHALL NOT 含持鎖工作階段的 `client_addr`。

訊息為啟動日誌（操作者面），不經 API 交付、不進入使用者介面。

#### Scenario: 訊息含必要要素
- **WHEN** 第二實例未經確認被攔下
- **THEN** 啟動日誌含「本版不支援多實例」、「另一個資料庫工作階段持有」、持鎖者指紋的可讀形式與 12 碼確認碼、
  風險說明、兩條救援指令（停止另一實例；或以確認碼重啟）、「非資料庫損毀」與「本實例未執行 migration 或寫入」的澄清，
  以及「確認碼綁定指紋、持鎖者變更後失效」的說明

#### Scenario: 訊息不含連線細節
- **WHEN** 檢視攔下訊息全文
- **THEN** 不含連線字串、密碼、主機位址、資料庫名，亦不含持鎖工作階段的 `client_addr`

#### Scenario: 指紋查詢不可用時仍有救援路徑
- **WHEN** 鎖由他人持有，且持鎖者查詢因權限或錯誤而失敗
- **THEN** 訊息明說持鎖者細節不可得，仍給出降級確認碼與兩條救援指令；以該碼重啟可依「確認啟動與留痕」啟動，
  審計事件標示指紋來源為不可得

### Requirement: 確認啟動與留痕

系統 SHALL 提供環境變數 `INSTANCE_GUARD_ACK` 作為操作者對**本次偵測到的衝突**的確認。其值 SHALL 與本次
啟動查得的持鎖者確認碼精確比對：相符即 SHALL 允許啟動（狀態為「已確認、未持鎖」），保留釘選連線並於
背景每週期嘗試取鎖，取得後轉為持鎖狀態；不相符 SHALL 視同未設定（攔下，並於訊息加註「持鎖者已變更，
請以新確認碼重新確認」）；設定但本次未偵測到衝突時 SHALL 正常啟動、不使用該值，並以資訊日誌建議移除。

**每一次**以確認啟動，系統 SHALL：(1) 寫入一筆 `audit_logs` 系統事件（事件名 `overridden`），details 含確認碼、
持鎖者指紋（`application_name`、pid、`backend_start`、確認碼、指紋來源）、本實例識別（主機名、行程 id、
啟動時間）、本實例的資料庫工作階段 id，以及確認者標示 `operator via env`（環境變數無法識別自然人，
SHALL NOT 假造身分）；(2) 使營運指標 `custodexa_instance_guard_overridden` 為 1、`custodexa_instance_guard_held` 為 0；
(3) 使管理介面常駐橫幅顯示（見對應 requirement）。三者於鎖由本實例取得時解除，並寫入一筆 `regained` 事件。

確認後系統 SHALL NOT 再做任何攔阻：migration、服務與背景工作照常執行。

確認值 SHALL NOT 出現在環境變數範本中——它是對一次衝突的確認，不是部署設定；殘留於環境中的舊值因不再相符而惰性。

#### Scenario: 帶相符確認啟動並留痕
- **WHEN** 一個實例已持有單實例鎖，另一個實例以 `INSTANCE_GUARD_ACK` 等於本次持鎖者確認碼啟動
- **THEN** 第二實例正常執行 migration 並開放監聽；`audit_logs` 新增一筆 `resource=instance_guard`、事件 `overridden` 的系統列，
  details 含確認碼、持鎖者指紋、本實例主機名／行程 id／啟動時間與 `operator via env`；`/metrics` 含
  `custodexa_instance_guard_overridden 1` 與 `custodexa_instance_guard_held 0`；啟動日誌含 CRITICAL 等級的確認啟動警告

#### Scenario: 確認碼不符視同未帶
- **WHEN** 操作者以先前衝突的確認碼啟動，而當前持鎖者已是另一個工作階段
- **THEN** 系統攔下，訊息含新的持鎖者指紋與確認碼，並加註持鎖者已變更；不寫入 `overridden` 事件

#### Scenario: 無衝突時確認值不被使用
- **WHEN** 環境中設有 `INSTANCE_GUARD_ACK`，且本次取鎖成功
- **THEN** 系統正常啟動、狀態為持鎖、不寫入 `overridden` 事件、指標 `custodexa_instance_guard_overridden` 為 0，
  日誌含「已設定但未使用、建議移除」的資訊行

#### Scenario: 確認啟動後鎖釋放即轉為持鎖並留痕
- **WHEN** 以確認啟動的實例運作中，原持鎖工作階段結束
- **THEN** 該實例於一個 watchdog 週期內取得鎖：狀態轉為持鎖、`custodexa_instance_guard_held` 為 1、
  `custodexa_instance_guard_overridden` 為 0、橫幅消失；`audit_logs` 新增一筆 `regained` 事件，
  details 含未持鎖時長

#### Scenario: 確認啟動的實例不執行任何自動終止
- **WHEN** 以確認啟動的實例偵測到鎖仍由他人持有
- **THEN** 它不對任何資料庫工作階段執行終止，只重試取鎖

### Requirement: 執行期持鎖狀態的持續驗證與失鎖告知

系統 SHALL 以背景任務週期性（週期 ≤ 30 秒）在釘選連線上驗證該鎖仍由本工作階段持有；
驗證 SHALL 直接查詢資料庫的鎖狀態（`pg_locks` 中本工作階段是否持有該鍵），SHALL NOT 以連線存活探測（ping）
代替。驗證結果 SHALL 三分：持有、未持有、未知（查詢錯誤）。

守衛 SHALL 是明確的狀態機：`acquiring → held | overridden`、`held → lost`、`lost | overridden → held`，
另有 `stopping → released` 供關閉使用。一旦驗證結果為未持有或未知，系統 SHALL 進入 `lost`、丟棄舊連線、
遞增失鎖計數、以 CRITICAL 等級記錄失鎖與其原因、寫入 `lost` 稽核事件、使指標與橫幅反映未持鎖，
**然後繼續服務**：SHALL NOT 拒絕任何請求、SHALL NOT 暫停背景工作、SHALL NOT 退出行程。
`lost` 與 `overridden` 期間系統 SHALL 於每個週期嘗試重新取鎖，SHALL NOT 設定重試上限；重取成功即回到 `held`、
寫入 `regained` 事件並解除告知。

重取失敗的原因 SHALL 由純函式分類並有逐類測試，分類只決定**告知方式**，不決定是否退出：
1. **他人持鎖**（取鎖回 false）→ CRITICAL 日誌含持鎖者指紋；事件與橫幅標示原因為 `contention` 並含持鎖者指紋。
2. **資料庫不可達**（網路層錯誤、查詢逾時、SQLSTATE 連線類與伺服器關閉類）→ 日誌節流；事件原因 `db_unreachable`（經非同步稽核落地，寫不進資料庫時落檔案）。
3. **永久性錯誤**（權限不足、認證失敗、語法或物件錯誤、資料庫不存在）或**無法歸類**→ CRITICAL 日誌不節流；事件原因 `permanent` 或 `unknown`。未知 SHALL 歸永久類。

背景任務的 panic SHALL 被攔截並記錄，SHALL NOT 終止行程、SHALL NOT 改變守衛狀態；其停止 SHALL 冪等並於關閉資料庫連線時執行。

系統 SHALL NOT 自動終止其他資料庫工作階段以奪回鎖——守衛無法區分殘留工作階段與另一主機上存活的實例。

#### Scenario: 失鎖即告知且繼續服務
- **WHEN** 持鎖實例運作中，其持鎖工作階段被終止，且背景任務於下一週期偵測到未持有
- **THEN** 日誌出現 CRITICAL 失鎖行；`audit_logs` 新增 `lost` 事件；`custodexa_instance_guard_held` 為 0、失鎖計數加一；
  同時對任一業務端點的請求仍回正常回應（非 503）、既有 WebSocket 會話未被切斷、排程器照常執行

#### Scenario: 重取成功即解除告知
- **WHEN** 進入 `lost` 的實例重取鎖成功（例如 postgres 重啟後）
- **THEN** 守衛回到 `held`，`custodexa_instance_guard_held` 經歷 1 → 0 → 1，失鎖計數為 1；`audit_logs` 新增 `regained` 事件；橫幅消失

#### Scenario: 失鎖期間被他實例取得仍繼續服務並指認持鎖者
- **WHEN** 持鎖實例失鎖，且重取前另一實例已取得該鎖
- **THEN** 原實例維持 `lost`、每週期重試、繼續服務；日誌與 `lost` 事件的原因為 `contention` 且含新持鎖者的指紋；行程未退出

#### Scenario: 資料庫不可達持續重試且無上限
- **WHEN** 持鎖實例失鎖且資料庫持續不可達
- **THEN** 行程維持 `lost`、每週期重試、日誌節流、指標為未持鎖；資料庫恢復後（不論多久）重取成功回到 `held`；期間行程未退出

#### Scenario: 永久性或未知錯誤告知並持續重取
- **WHEN** 重取時資料庫回覆權限不足（SQLSTATE 42501）或一個無法歸類的錯誤
- **THEN** 日誌以 CRITICAL 記錄原因 `permanent` 或 `unknown`，事件與橫幅同標示；行程未退出，下一週期照常重試

#### Scenario: 背景任務 panic 不殺行程
- **WHEN** 驗證任務內發生 panic
- **THEN** panic 被記錄，行程與服務繼續，守衛狀態不變，下一週期照常驗證

### Requirement: 守衛事件的稽核留痕

守衛的三個事件——確認啟動（`overridden`）、失鎖（`lost`）、取得或重取成功（`regained`）——SHALL 各寫入一筆 `audit_logs`，
以系統主體記錄（`user_id` 0、`username` system），資源為 `instance_guard`，details SHALL 含事件名、原因、
本實例識別（主機名、行程 id、守衛啟動時間）、本實例的資料庫工作階段 id；`overridden` 與原因為他人持鎖的 `lost`
SHALL 另含持鎖者指紋（`application_name`、pid、`backend_start`、確認碼、指紋來源）；`overridden` SHALL 含確認碼與
確認者標示；`regained` SHALL 含未持鎖時長。details SHALL NOT 含連線字串、憑證或任何工作階段的 `client_addr`。

審計服務建立之前發生的事件（含確認啟動）SHALL 由守衛以有界緩衝暫存，於審計服務建立後依序寫入；
超出緩衝上限的最舊事件丟棄並記錄。文件 SHALL 揭露：事件經非同步稽核落地（at-most-once、失敗落檔案），
以及緩衝上限。

#### Scenario: 三個事件可由稽核查得
- **WHEN** 一個實例以確認啟動、其後取得鎖、再失鎖並重取成功
- **THEN** `audit_logs` 中可查得該實例（同一主機名、行程 id、啟動時間）的 `overridden`、`regained`、`lost`、`regained` 四列，
  且可依 details 還原每段未持鎖的起訖

#### Scenario: 事件不含憑證與連線字串
- **WHEN** 檢視任一守衛事件的 details
- **THEN** 含本實例識別與持鎖者指紋三元組，不含連線字串、密碼或 `client_addr`

#### Scenario: 審計服務建立前的事件於建立後補寫
- **WHEN** `KEK_PROVIDER=ui` 模式下實例以確認啟動並停在封印期，其後管理員解封
- **THEN** 解封完成後 `audit_logs` 出現該次啟動的 `overridden` 事件，時間戳為啟動當下（驗法：手測；不做自動化整合格——需兩個行程級實例，離線 flush 格與 sink 時間戳格各覆蓋半段）

### Requirement: 管理介面常駐橫幅與守衛狀態出口

系統 SHALL 在既有的封印狀態查詢回應中提供守衛的粗狀態（狀態列舉、起始時間、原因、對等守衛連線數），
SHALL NOT 在該處提供持鎖者指紋、確認碼或本實例的主機名／行程 id；該查詢不寫審計列，供介面輪詢。
系統 SHALL 另提供管理者限定的唯讀端點回傳守衛完整快照（含持鎖者指紋、確認碼、本實例識別）；
該端點 SHALL 經審計中間件留痕，介面 SHALL NOT 對其輪詢。

管理介面 SHALL 於守衛狀態非持鎖、或偵測到其他守衛版實例連線時，對**所有登入使用者**顯示常駐橫幅，
SHALL NOT 提供關閉或隱藏橫幅的操作；橫幅 SHALL 於狀態回到持鎖且無對等連線時自動消失。
一般使用者看到的內容 SHALL 為狀態說明（以確認啟動／失鎖／偵測到其他實例）與「管理者已被告知」；
管理者 SHALL 額外看到持鎖者指紋的可讀形式與確認碼、狀態起始時間、本實例識別與處置說明。
橫幅文案 SHALL 三語齊備。

守衛 SHALL 於每個驗證週期計數同一資料庫中其他守衛版實例的連線（以守衛連線的 `application_name` 辨識），
曝光為指標與狀態欄位；文件 SHALL 揭露此偵測依賴 `application_name` 且無守衛的舊版實例不可見。

#### Scenario: 非持鎖狀態的橫幅對所有登入者可見
- **WHEN** 實例處於 `overridden` 或 `lost`，任一角色的使用者登入管理介面
- **THEN** 頁面頂部顯示橫幅，內容含狀態說明；橫幅沒有關閉鈕

#### Scenario: 管理者看到完整指紋
- **WHEN** 實例處於 `overridden`，管理者登入
- **THEN** 橫幅顯示持鎖者的 `application_name`、pid、`backend_start` 與確認碼、狀態起始時間、本實例主機名與行程 id；
  該資訊由一次管理者限定端點呼叫取得，`audit_logs` 有對應的讀取列

#### Scenario: 橫幅輪詢不產生審計列
- **WHEN** 使用者停留在管理介面 10 分鐘
- **THEN** `audit_logs` 未因橫幅的狀態輪詢新增任何列

#### Scenario: 狀態回到持鎖即消失
- **WHEN** 橫幅顯示中，鎖由本實例取得且無對等連線
- **THEN** 下一次輪詢後橫幅消失，無需重新整理或登出

#### Scenario: 持鎖實例偵測到對等守衛連線亦顯示橫幅
- **WHEN** 實例 A 持鎖，實例 B 以確認啟動連上同一資料庫
- **THEN** A 的 `/metrics` 含 `custodexa_instance_guard_peers 1`，A 的管理介面顯示「偵測到其他實例」橫幅；B 停止後一個週期內 A 的橫幅消失

### Requirement: 鎖的釋放時機

正常關閉時系統 SHALL 於關閉資料庫連線池之前釋放單實例鎖（關閉釘選連線）。任何非正常退出路徑
（收束逾時 `os.Exit`、`log.Fatalf`、panic、SIGKILL、主機當機）SHALL 由資料庫隨工作階段結束釋放該鎖，
系統 SHALL NOT 依賴應用程式碼在這些路徑上執行釋放。

關閉 SHALL 依固定順序：先將守衛標記為停止中（此後背景任務的任何驗證結果一律丟棄）、取消並等待背景任務結束（join）、再釋放釘選連線，最後才關閉連線池。
背景任務 SHALL NOT 在關閉期間把取消誤計為失鎖、SHALL NOT 在釋放後重新取鎖。

文件 SHALL 揭露唯一的殘鎖情境：持鎖主機當機或網路分割造成 TCP 半開時，鎖會停留至資料庫的 TCP keepalive
回收該工作階段為止；其處置 SHALL 是「確認無其他實例後以確認碼啟動」，SHALL NOT 要求操作者對資料庫執行
終止工作階段等寫入性操作。

#### Scenario: 優雅關閉釋放鎖
- **WHEN** 持鎖實例收到 SIGTERM 並完成優雅關閉
- **THEN** 釘選連線於連線池關閉前被關閉，`pg_locks` 無該鍵殘留

#### Scenario: 關閉期間的驗證結果不被誤判
- **WHEN** 關閉序開始時背景任務正有一輪驗證在途，且該輪回覆「未持有」
- **THEN** 該結果被丟棄：失鎖計數維持 0、未寫入 `lost` 事件、未重取；關閉完成後 `pg_locks` 無該鍵殘留

#### Scenario: 殘鎖情境的救援不碰資料庫
- **WHEN** 操作者在確認無其他實例運作下仍被攔下
- **THEN** 營運文件的處置為以訊息中的確認碼設定 `INSTANCE_GUARD_ACK` 後重啟，並說明橫幅會持續到資料庫回收殘留工作階段、
  本實例取得鎖為止；文件未要求執行 `pg_terminate_backend`

### Requirement: 守衛保證的誠實邊界

守衛的保證 SHALL 表述為「第二實例不會在操作者不知情下運作」：文件、訊息與介面文案 SHALL NOT 主張守衛能防止
多實例並存造成的資料問題，SHALL 明說確認後的並存及其資料後果由確認者承擔，守衛提供的是攔下、告知與事後可證的留痕。

跨行程的單實例保證 SHALL 僅在 postgres 上成立（唯一正式部署目標）。sqlite（僅供單元測試）SHALL 以行程層級共用的
try 互斥提供同語義（第二次取鎖被攔、訊息與確認路徑可測），SHALL NOT 宣稱跨行程互斥；白名單外的未知 dialect SHALL fail-close
拒絕啟動，SHALL NOT 靜默退化為行程內鎖。

跨行程保證 SHALL 僅在**守衛版之間**成立：不含守衛的舊版本不持鎖，故首次自無守衛版升級至本版、或自本版回滾至無守衛版時，
新舊實例並存不會被攔下。文件 SHALL 在升級程序中要求並說明如何確認舊實例已停（行程管理器無該服務在跑、資料庫中應用帳號的連線數為零）後才起新版，
並 SHALL 說明「新版取得鎖」不能作為「舊版已停」的證據。

文件 SHALL 揭露：守衛依賴 postgres 的工作階段級鎖語義，應用 SHALL 直連 postgres 或經 session pooling 模式的連線池；
transaction pooling 模式的連線池會使鎖在工作階段間漂移，守衛將持續偵測失鎖並告知——該拓撲不受支援。

#### Scenario: 文件不主張防止資料問題
- **WHEN** 冷讀部署形態限制與升級程序中關於守衛的段落
- **THEN** 段落陳述「攔下並要求確認」「確認後有審計證據」「守衛防的是不知情，不是不發生」，不含「防止資料損毀」「保證單實例」等主張

#### Scenario: 確認後的並存不由守衛阻擋
- **WHEN** 實例 B 以確認啟動，實例 A 仍在運作
- **THEN** 兩者皆正常服務與寫入；守衛在 A 與 B 各自的日誌、指標、橫幅上可見，`audit_logs` 有 B 的 `overridden` 事件；守衛未阻擋任一方的任何操作

#### Scenario: sqlite 下第二次取鎖被攔且確認路徑可驗
- **WHEN** 測試環境以 sqlite 於同一行程內第二次呼叫取鎖
- **THEN** 回傳攔下錯誤，其訊息含「本版不支援多實例」與固定形式的指紋；以相符確認碼再呼叫則成功並產生 `overridden` 事件；釋放後可再次取得

#### Scenario: 首次升級到守衛版的檢核
- **WHEN** 操作者自無守衛版升級到本版
- **THEN** 升級程序要求先確認舊實例已停且應用帳號連線數為零，並說明守衛在此窗口不提供保護

#### Scenario: 未知 dialect fail-close
- **WHEN** 資料庫 dialect 不在白名單
- **THEN** 取鎖回錯、系統拒絕啟動，不執行任何行程內替代

### Requirement: 守衛狀態可觀測且健康檢查形狀不變

系統 SHALL 於營運指標曝光 `custodexa_instance_guard_held`（gauge：1 持有、0 未持有）、
`custodexa_instance_guard_lost_total`（counter：偵測到失鎖的累計次數）、`custodexa_instance_guard_overridden`
（gauge：1 表示本實例以確認啟動且尚未取得鎖）與 `custodexa_instance_guard_peers`（gauge：偵測到的其他守衛版實例連線數）。
四指標 SHALL 自段 1 起註冊，封印期即可採集。

`/health` 的回應形狀 SHALL NOT 因本守衛改變。

#### Scenario: 指標自啟動起可採集
- **WHEN** 系統啟動完成段 1（含封印期），採集端請求 `/metrics`
- **THEN** 回應含 `custodexa_instance_guard_held 1`、`custodexa_instance_guard_lost_total 0`、`custodexa_instance_guard_overridden 0` 與 `custodexa_instance_guard_peers 0`

#### Scenario: 健康檢查不變
- **WHEN** 請求 `/health`
- **THEN** 回應欄位集合與守衛引入前完全相同

### Requirement: 守衛不得由組態停用；確認值不是開關

系統 SHALL NOT 提供任何停用單實例守衛的環境變數、功能旗標或政策鍵。`INSTANCE_GUARD_ACK` SHALL NOT 具備停用效果：
它只對與當前持鎖者指紋相符的一次衝突生效，持鎖者變更即失效，且每次生效皆留審計事件。環境變數範本 SHALL NOT 含該鍵。

#### Scenario: 無停用途徑
- **WHEN** 檢視環境變數範本、功能旗標清單與安全政策鍵
- **THEN** 不存在任何與單實例守衛相關的停用選項，範本亦不含 `INSTANCE_GUARD_ACK`

#### Scenario: 確認值不能常設關掉守衛
- **WHEN** 操作者把一次衝突的確認碼長期留在環境中，其後發生持鎖者不同的新衝突
- **THEN** 新衝突仍被攔下並要求新的確認碼；舊值未使任何啟動繞過攔下

