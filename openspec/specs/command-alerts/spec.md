# command-alerts

## Purpose

互動指令比對告警規則並記錄告警事件，供稽核查詢與通知派送。
## Requirements
### Requirement: Alert rule management

Admins SHALL manage alert rules (name, regex pattern, severity high/medium/low, enabled). Invalid regex MUST be rejected at save time. Default seed rules for common destructive commands SHALL ship with the migration.

告警規則 SHALL 另具備**適用主體型別**（`subject_kind`：全體／人類／自動化主體，預設全體），
使同一套機制可對兩類操作者分別設定而不需複製規則集。管理 API 與 UI SHALL 可設定該值，
未知值 SHALL 被拒回 400。既有規則 SHALL 以「全體」為值，其比對行為 SHALL 與本欄引入前逐則相同。

#### Scenario: Invalid regex rejected
- **WHEN** an admin saves a rule with pattern "rm -rf ("
- **THEN** the API rejects it with a clear error

#### Scenario: 適用主體可設定且拒未知值

- **WHEN** 管理員以 API 建立規則並指定適用主體為自動化主體
- **THEN** 規則入庫且僅對自動化主體比對；提交未知值時回 400

#### Scenario: 既有規則行為不變

- **WHEN** 升級後檢視引入本欄之前建立的規則
- **THEN** 其適用主體為全體，對人類與自動化主體的比對結果與升級前相同

### Requirement: Command alert generation

Each captured command SHALL be matched against enabled rules; a match creates an alert linking rule, session, user, asset and the command text. Matching MUST NOT disrupt the session or command persistence.

比對 SHALL 僅以適用於**當前會話行為主體型別**的規則進行；主體型別 SHALL 取自認證層解析出的主體事實
（會話建立時的快照），SHALL NOT 取自任何請求可宣告的欄位（如客戶端自述或來源位址）。
主體型別不可判定時 SHALL 以最嚴的一側處理（比對全體適用的規則），SHALL NOT 略過比對。

#### Scenario: Dangerous command alerts
- **WHEN** a user executes "rm -rf /data" in an SSH session with the seed rules enabled
- **THEN** a high severity alert exists referencing that command and session

#### Scenario: 主體型別決定規則集

- **WHEN** 同一則只對自動化主體啟用的規則，分別在自動化主體會話與人類會話上命中同一段指令文字
- **THEN** 只有自動化主體的會話產生告警與阻斷，人類會話不受影響

#### Scenario: 主體型別不取自請求宣告

- **WHEN** 請求以標頭或參數宣告自身為人類主體，而其憑證解析出的主體為自動化主體
- **THEN** 比對仍以憑證解析出的主體型別進行

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

### Requirement: 告警規則的比對方向

告警規則 SHALL 具備**比對方向**（`direction`：`input`＝使用者送出的指令、`output`＝目標回傳的內容），
預設為 `input`。規則管理 API 與 UI SHALL 可設定該值，未知值 SHALL 被拒回 400，三語文案齊備。

比對器 SHALL 依方向分割規則集：指令比對與指令阻斷 SHALL 只取 `input` 方向的規則，
輸出偵測 SHALL 只取 `output` 方向的規則。既有規則 SHALL 以 `input` 為值，
其比對與阻斷行為 SHALL 與本欄引入前逐則相同。

輸出面規則的動作 SHALL 限於告警：`direction = output` 且動作為阻斷的組合 SHALL 於儲存時被拒回 400。
理由 SHALL 載明於介面說明——位元組送達使用者之後無從收回，把阻斷掛在輸出面是宣稱一個系統不具備的能力。

輸出面規則 SHALL 僅套用於具備解析後文字流的協議（文字終端與資料庫主控台）；
畫面型協議 SHALL NOT 進入輸出偵測，其「未涵蓋」SHALL 於規格與介面說明載明，
SHALL NOT 以「已啟用」的形態呈現而使部署者誤以為該協議受保護。

#### Scenario: 方向可設定且拒未知值

- **WHEN** 管理員以 API 建立規則並指定方向為輸出面
- **THEN** 規則入庫且僅參與輸出偵測；提交未知方向值時回 400

#### Scenario: 輸出面不得設為阻斷

- **WHEN** 管理員建立或更新一條方向為輸出面、動作為阻斷的規則
- **THEN** 請求被拒回 400 並指出輸出面不支援阻斷；資料庫無該列亦未被更新

#### Scenario: 既有規則行為不變

- **WHEN** 升級後於任一既有協議會話執行既有規則涵蓋的危險指令
- **THEN** 告警與阻斷結果與升級前逐則相同，且該規則的方向為輸入面

#### Scenario: 輸入面比對不套用輸出面規則

- **WHEN** 使用者送出的指令文字恰好符合某條輸出面規則的樣式
- **THEN** 不因該輸出面規則產生告警（輸入面比對只取輸入面規則）

### Requirement: 輸出面敏感資料偵測

系統 SHALL 對具備解析後文字流的會話，於輸出旁路掃描目標回傳的內容，並以**會話啟動時的輸出面規則快照**比對；規則的新增、停用與修改於新會話生效，進行中的會話沿用啟動時的規則集。
偵測 SHALL NOT 阻斷、延遲或改變送往使用者終端的內容，SHALL NOT 影響錄影與指令紀錄的寫入；
偵測本身失敗 SHALL NOT 中斷會話，失敗 SHALL 記錄於伺服端日誌。

系統 SHALL 內建兩條輸出面出廠規則：

- **信用卡號**：連續 13 至 19 位數字（允許其間的常見分隔符），且 SHALL 通過 Luhn 校驗才算命中。
  未通過 Luhn 的數字串 SHALL NOT 命中——單靠長度比對會使時間戳、單號、雜湊值全數誤報，
  而持續誤報的訊號等同沒有訊號。
- **私鑰標頭**：`-----BEGIN` 與 `PRIVATE KEY-----` 構成的標頭行一族（含 RSA、EC、OPENSSH 等變體）。

出廠規則的內容 SHALL 於 schema baseline 中即為終態值，SHALL NOT 依賴事後回填；
其內容 SHALL 以資料層比對驗收（schema 層的等價比對看不到資料列）。

偵測 SHALL 跨輸出幀續接：目標回傳的內容以任意大小分段抵達，一個卡號被切在兩個相鄰分段之間時
SHALL 仍然命中。續接所保留的尾段 SHALL 有固定上界，SHALL NOT 隨會話時長增長。

**射程邊界 SHALL 載明於規格、介面說明與營運文件**：

- 偵測只看**解析後的文字流**。加密、壓縮、以 Base64 或其他編碼承載的內容 SHALL NOT 被視為已掃描；
  以編碼繞過偵測是**可行的**，系統 SHALL NOT 表述為能防止資料外流。
- 偵測是**啟發式**。命中表示該段輸出**可能含有**該類資料；告警文案、通知內容與稽核呈現
  SHALL 使用「可能含」的表述，SHALL NOT 斷言「含有」。
- 未命中**不表示不存在**。「零告警」SHALL NOT 被表述為「該會話未輸出敏感資料」。

無啟用中的輸出面規則時，偵測器 SHALL 整段跳過，使未使用本能力的部署不承擔任何輸出熱路徑成本。

#### Scenario: 卡號輸出觸發告警

- **WHEN** 使用者於文字終端會話讀出一個通過 Luhn 校驗的十六位數字串
- **THEN** 產生一筆該規則的告警，綁該會話、使用者與資產，並推送至已啟用的通知通道

#### Scenario: 私鑰標頭輸出觸發告警

- **WHEN** 會話輸出中出現私鑰標頭行
- **THEN** 產生該規則的告警；標頭的多種變體皆命中

#### Scenario: 非卡號數字串不誤報

- **WHEN** 會話輸出中出現時間戳、單號、雜湊值、版本號、位址等未通過 Luhn 校驗的數字串
- **THEN** 不產生卡號規則的告警

#### Scenario: 卡號跨輸出分段仍命中

- **WHEN** 一個有效卡號被切在兩個相鄰輸出分段之間（於任一切點）
- **THEN** 仍產生一筆告警，且不因切點不同而漏報或重複

#### Scenario: 編碼內容不在射程

- **WHEN** 會話輸出中的卡號以 Base64 承載
- **THEN** 不命中；此為已載明的射程邊界，SHALL NOT 被記為缺陷

#### Scenario: 未啟用輸出面規則時不掃描

- **WHEN** 會話啟動時全部輸出面規則皆停用
- **THEN** 該會話的輸出旁路不執行任何掃描，會話輸出路徑與本能力引入前等價

### Requirement: 輸出面告警的紀錄形態

輸出面命中所產生的告警 SHALL 經與既有比對路徑相同的告警寫入介面落地，並照常推送通知與納入既有轉發鏈，
SHALL NOT 另闢寫入路徑。

**告警紀錄 SHALL NOT 存入命中的原文。** 指令文字欄 SHALL 為空（本類沒有指令可指，
SHALL NOT 填入推測文字或截取的輸出片段）；可出站的內容 SHALL 限於規則、會話、使用者、資產、
命中次數與時刻。原文留在錄影與既有紀錄，由具權限者依既有流程調閱——
把偵測到的敏感片段複製進告警表，會使偵測機制自己成為第二個外流點，且該表的可讀範圍比錄影寬。

同一規則於同一會話的連續命中 SHALL 於一個時間窗內彙總為一筆告警並累計次數，
SHALL NOT 逐次產生告警——讀取一個私鑰檔會在數十行內連續命中，逐行開單會把告警頁淹沒而使真訊號沉底。

#### Scenario: 告警不含命中原文

- **WHEN** 會話輸出中出現卡號並產生告警
- **THEN** 該告警紀錄的指令文字欄為空，且其任何欄位皆不含該卡號或其片段

#### Scenario: 連續命中彙總為一筆

- **WHEN** 使用者於同一會話讀出一個含數十行私鑰內容的檔案
- **THEN** 該規則於該會話產生一筆告警並記錄命中次數，而非數十筆

#### Scenario: 輸出面告警走既有落地面與轉發

- **WHEN** syslog 轉發已啟用且輸出面規則命中
- **THEN** 該告警寫入資料庫後被轉發至 syslog 目的地，與比對路徑產生的告警同軌

### Requirement: 敏感資料遮罩原語與其計數

系統 SHALL 提供遮罩原語：輸入一段文字與一組輸出面規則，輸出「已遮罩文字」與「遮罩次數」。
遮罩 SHALL 以固定的佔位文字取代命中片段，SHALL NOT 保留可還原原值的任何部分
（末四碼一類的部分保留 SHALL NOT 作為預設行為）。

呼叫遮罩原語的回傳路徑 SHALL 記錄該次呼叫的遮罩次數於其自身的紀錄欄位，
使「這次回傳被遮掉幾處」成為事後可查的事實；遮罩次數為 0 與未遮罩 SHALL 可區分。

**遮罩 SHALL NOT 套用於錄影、指令紀錄與任何證據面。** 證據保留原文，遮罩只作用於回傳給呼叫端的內容；
兩者並存，系統 SHALL NOT 以遮罩為理由刪改任一邊。此邊界 SHALL 載明於營運文件。

#### Scenario: 遮罩取代命中片段並回報次數

- **WHEN** 以含兩處卡號與一處私鑰標頭的文字呼叫遮罩原語
- **THEN** 回傳文字中三處皆為佔位文字、原值不可還原，遮罩次數為 3

#### Scenario: 未命中時原文與次數皆不變

- **WHEN** 以不含任何敏感資料的文字呼叫遮罩原語
- **THEN** 回傳文字與輸入逐位元組相同，遮罩次數為 0

#### Scenario: 證據面不受遮罩影響

- **WHEN** 一段含卡號的輸出經遮罩後回傳給呼叫端
- **THEN** 同一場會話的錄影與指令紀錄仍為未遮罩的原文

### Requirement: 自動化主體專屬的種子規則

系統 SHALL 內建僅對自動化主體啟用（適用主體＝agent）且動作為阻斷的種子規則兩類：

- **橫向移動**：自會話內再向其他主機發起連線或執行的指令族（含 `ssh`、`scp`、`sftp`、`nc`、`socat`，
  以及 Windows 上的遠端執行指令族）。
- **敏感路徑讀取**：私鑰與帳號憑證檔案路徑（含 `.ssh/` 目錄、`authorized_keys`、`id_rsa`、`/etc/shadow`）。

兩類種子規則 SHALL 於 schema baseline 中即為終態值，SHALL NOT 依賴事後回填。
人類會話 SHALL NOT 因此受影響，除非管理員自行把該規則的適用主體改為全體。

**邊界 SHALL 明載**：規則以指令文字比對，只擋得住列舉得出的形態；
寫檔、以其他工具達成同一目的一類無法以規則窮舉，其控制手段是任務信封與報告對照，
系統 SHALL NOT 表述為「自動化主體的操作面已受完整控制」。

#### Scenario: 自動化主體的橫向移動被擋

- **WHEN** 自動化主體於已授權的會話內執行向其他主機的連線指令
- **THEN** 該指令被阻斷並產生高嚴重度告警，目標主機無任何副作用

#### Scenario: 敏感路徑讀取被擋

- **WHEN** 自動化主體於會話內讀取私鑰或帳號憑證檔案路徑
- **THEN** 該指令被阻斷並產生告警

#### Scenario: 人類會話不受種子規則影響

- **WHEN** 人類使用者於會話內執行同樣的連線指令
- **THEN** 該指令不因這兩則種子規則被阻斷（既有的全體適用規則仍照常生效）

### Requirement: 範圍外引用的熔斷

系統 SHALL 記錄自動化主體對可視範圍外資產識別字的引用事件（主體、token、目標識別字、端點、時刻），
並於設定的時間窗內達設定次數時**跳閘**：停用該次使用的 token、於主體上標記未處置熔斷事件、
產生告警並通知負責人、寫入審計。門檻與時間窗 SHALL 為政策鍵（`agent_probe_trip_count`、
`agent_probe_window_seconds`），SHALL 具備預設值且可由管理員調整。

**計數判準 SHALL 只計「對該主體從未可視」的識別字。** 曾可視而後被撤權者、資產已下線或不存在者
SHALL 分別記錄但 SHALL NOT 計入門檻。三類 SHALL 以事件列上的**分類欄**記錄，其值域 SHALL 為固定的三值
（從未可視／撤權後／已下線），SHALL NOT 以自由文字或事後推導表達——三類的對外回應相同（不洩漏存在性），內部 SHALL 分開記，
使「探測」與「權限變動後的滯後引用」在紀錄上可區分。同一識別字於同一時間窗內 SHALL 只計一次。
累計 SHALL 於資料庫原子進行，SHALL NOT 依賴單一行程的記憶體狀態。

系統 SHALL 以 `agent_visibility_exposures(user_id, asset_id, first_seen_at, last_seen_at)` 記錄識別字告知事實，鍵為 `(user_id, asset_id)`。僅 agent 主體 SHALL 寫入：清單完成過濾與分頁後對實際回傳的資產 id 逐筆 upsert，任務項核准（含自動核准）於同一交易對執行主體與核准資產 id upsert。人類 SHALL NOT 寫入。寫入失敗 SHALL 不回傳該頁或提交該次核准。

分類 SHALL 依次判定：不存在或軟刪為 `retired`；存在且有 exposure 為 `revoked`；存在且無 exposure 為 `never_visible`。單純停用、但尚未軟刪的資產仍按 exposure 分類。此證據 SHALL NOT 被描述為群組歷史或完整授權歷史。

**升級前無紀錄的邊界**：資料 SHALL 自本 change 上線起累積，SHALL NOT 回推升級前群組／會話。升級前已獲知而無 exposure 的識別字，在升級後被拒時可能記為 `never_visible`。此風險 SHALL NOT 被描述為只限升級後首個時間窗：升級前已獲知而其後未重新列舉或核准的識別字，直到取得 exposure 之前被拒都會記為 `never_visible`。營運文件 SHALL 明載此點與「管理員可解除」，且解除須填原因、不自動恢復停用 token。

通知 SHALL 沿既有 webhook／Slack 通道推送並帶 `owner_id`；此為負責人路由資訊，SHALL NOT 宣稱已有個人收件匣或保證負責人已收件。

熔斷事件 SHALL 掛在**主體**上而停用作用於 **token**：主體上存在未處置事件時 SHALL NOT 為其核發新 token，
使重新核發無法洗掉未處置的事件。跳閘當下該 token 已換出的連線憑證與既有會話 SHALL 一併失效
（沿用既有的即時終止路徑）。

解除 SHALL 僅限負責人或管理員，SHALL 必填原因並入審計；解除 SHALL NOT 自動重啟已停用的 token
（須重新核發）。人類主體 SHALL NOT 適用本機制。

**本機制為 fail-safe**：主體被外部內容誘導而引用範圍外識別字因此被停，是預期結果而非誤判。
此語義 SHALL 於介面文案載明，使處置者不把跳閘一律讀成主體有惡意。

#### Scenario: 連續範圍外引用觸發跳閘

- **WHEN** 自動化主體於時間窗內引用達門檻數量的、對其從未可視的資產識別字
- **THEN** 該 token 被停用、主體標記未處置事件、負責人收到告警、審計留有熔斷紀錄，且各次引用的回應皆為 404

#### Scenario: 撤權後的舊識別字不計入門檻

- **WHEN** 自動化主體引用曾經可視、其後被撤權的資產識別字達門檻數量
- **THEN** 不跳閘；該些引用以獨立類別記錄，回應仍為 404

#### Scenario: 未處置事件期間不得核發新 token

- **WHEN** 主體上存在未處置的熔斷事件而管理員嘗試為其核發新 token
- **THEN** 請求被拒並回傳對應的規則錯誤碼

#### Scenario: 解除須填原因且不自動復權

- **WHEN** 負責人解除熔斷並填入原因
- **THEN** 主體的未處置標記清除、審計留有解除紀錄與原因；已停用的 token 仍為停用，須重新核發

#### Scenario: 人類不適用熔斷

- **WHEN** 人類使用者連續引用可視範圍外的資產識別字
- **THEN** 回應為 404，不產生熔斷事件、不停用任何憑證

### Requirement: 熔斷事件唯讀查詢
系統 SHALL 在 AuthMiddleware 後提供 GET /users/:id/agent-breaker/events，僅 admin／auditor 或該 agent 負責人能讀取，agent token SHALL 回 403，並沿審計資源讀取機制留痕。

#### Scenario: 有界事件序列與他人主體隔離
- **WHEN** 合格讀者查一個 agent 的事件
- **THEN** 依時間與 id 降序回時間、目標 id、端點、class、token id，offset／limit 分頁且上限 100，附主體目前 breaker_pending_at
- **AND** 非 owner 的一般 human、agent token 回 403；未登入回 401；空結果回 data=[] 與 total=0
- **AND** 目前未處置旗標不冒充每個事件的解除歷史，不回推 exposures 升級前歷史
