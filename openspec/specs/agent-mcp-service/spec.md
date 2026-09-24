# agent-mcp-service Specification

## Purpose

把平台既有的資產申請、連線授權、終端與查詢主控台能力，以一組語義固定的工具面提供給自動化執行者（AI agent）使用：工具呼叫的身分只來自 agent token、連線一律沿既有閘序建立、每次呼叫各自留痕，並在回傳形狀上把「不知道結果」與「知道結果」分開表達。

## Requirements

### Requirement: MCP 傳輸面與認證

系統 SHALL 於後端行程內提供 MCP 服務端點 `POST /api/v1/mcp`，採 streamable HTTP 傳輸。呼叫方 SHALL 以 `Authorization: Bearer` 攜帶 agent token 認證；系統 SHALL NOT 於本端點接受 JWT、cookie 或任何人類登入憑證，亦 SHALL NOT 實作 OAuth 授權流程。

工具呼叫的主體 SHALL 只由 token 決定：請求本體所帶的任何使用者、主體或角色欄位 SHALL 被忽略，SHALL NOT 用於任何授權判定。

只支援 stdio 傳輸的宿主 SHALL 經獨立發行的 `custodexa-mcp` 轉接頭接入（發行面見 `mcp-client-distribution`）。轉接頭 SHALL 為薄客戶端：它 SHALL 把工具呼叫原樣送至同一個 HTTP 端點，SHALL NOT 自行實作任何授權判定、連線建立或審計寫入。經轉接頭與直連 HTTP 兩種途徑取得的工具名稱、參數與回傳 SHALL 完全一致。服務端 SHALL NOT 依賴轉接頭的存在：所有授權、連線、審計與遮罩語義 SHALL 在直連 HTTP 時即完整成立。

#### Scenario: 以人類 JWT 呼叫被拒

- **WHEN** 呼叫方以有效的人類登入 JWT 作 bearer 呼叫 `/api/v1/mcp`
- **THEN** 請求被拒（機器可辨的認證錯誤碼），不執行任何工具，且不建立任何工作階段

#### Scenario: 請求本體宣稱的身分不生效

- **WHEN** 呼叫方以 agent token 認證，但在工具參數中額外夾帶其他主體識別
- **THEN** 授權與可視性判定一律以 token 對應的主體為準，夾帶的識別被忽略

#### Scenario: 兩種傳輸的工具面一致

- **WHEN** 分別經直連 streamable HTTP 與 `custodexa-mcp` 轉接頭列出工具
- **THEN** 兩者回傳的工具名稱、參數結構與回傳欄位完全相同

#### Scenario: 直連即具備完整語義

- **WHEN** 宿主不經轉接頭、以 agent token 直連 `/api/v1/mcp` 完成一次申請、建線、執行與收尾
- **THEN** 帳本、錄影、遮罩與審計的產出與經轉接頭時相同

### Requirement: v1 工具面為封閉集合

系統於 v1 SHALL 提供且僅提供下列十項工具：`list_assets`、`request_access`、`check_request`、`open_session`、`run_command`、`send_keys`、`query`、`read_screen`、`close_session`、`close_task`。

每一項工具的說明文字 SHALL 寫給不認識本系統的執行者閱讀：SHALL 說明該工具做什麼、參數從哪裡取得、回傳每個狀態值的意義，以及失敗時該採取什麼動作。`list_assets` 的說明 SHALL 寫明其回傳的可連狀態表達的是「此刻能不能連」，不是「需不需要申請」。

資產識別 SHALL 只來自 `list_assets` 的回傳。對主體從未可視的資產識別提出的任何工具呼叫 SHALL 以「不存在」的形式回應，SHALL NOT 洩漏該識別是否存在。

`send_keys` SHALL 只接受 `ctrl-c`、`ctrl-d`、`enter` 三個鍵名，其他值 SHALL 被拒且不送出任何位元組。

下列參數 SHALL 為顯式參數，SHALL NOT 由系統隱式推導：`open_session` SHALL 收任務識別（申請單 id）——
主體同時持有多張有效申請單時，系統 SHALL NOT 代為挑選，因為任務識別是整條審計鏈的錨，挑錯不會報錯只會讓證據掛到錯的任務上；
`request_access` SHALL 逐資產收帳號範圍，由自動化主體執行的項 SHALL NOT 以全部帳號提出；
`query` SHALL 收逾時秒數，省略時採預設值，超出後端既有上限者 SHALL 以該上限為準。

#### Scenario: 工具面沒有影像協議與免工作階段執行

- **WHEN** 列出 v1 工具
- **THEN** 清單恰為上述十項；不存在圖形協議工具，也不存在「不開工作階段直接執行一條指令」的工具

#### Scenario: 未經列表取得的資產識別

- **WHEN** 執行者對一個從未出現在自己 `list_assets` 回傳中的資產識別呼叫 `open_session`
- **THEN** 回應為「不存在」，與該識別實際存在與否無關

#### Scenario: 不在允許清單的按鍵被拒

- **WHEN** 執行者以 `ctrl-z` 呼叫 `send_keys`
- **THEN** 呼叫被拒，工作階段未收到任何位元組

#### Scenario: 同時持多張有效單時不代為挑選

- **WHEN** 執行者同時持有兩張有效申請單，呼叫 `open_session` 而未指定任務識別
- **THEN** 呼叫被拒並指出必須指定任務識別，系統 SHALL NOT 自行選用其中一張

### Requirement: 連線建立沿用既有閘序

`open_session` SHALL 在後端行程內簽發並立即兌換一次性連線 token，且 SHALL 沿用與瀏覽器終端、資料庫查詢主控台完全相同的簽發閘序與兌換閘序，包含角色現查、連線授權重查、存取政策重查、來源位址判定、帳號客體綁定與工作階段記錄 fail-close。系統 SHALL NOT 為本通道另立一套判定。

簽發 SHALL 攜帶呼叫方顯式指定的任務識別，由簽發與兌換兩點對該任務項逐項比對（資產、帳號範圍、時窗）；未指定任務識別的 `open_session` SHALL 被拒。

判定所用的來源位址 SHALL 為 MCP 請求本身觀察到的呼叫端位址，SHALL NOT 因建線在行程內完成而退化為迴路位址。

任一閘拒絕時，`open_session` SHALL 以與人類路徑相同的機器可辨錯誤碼回應，且該次拒絕 SHALL 沿既有的兌換拒絕留痕路徑寫入審計。

`open_session` 建立的工作階段 SHALL 與人類建立者具有相同的錄影與指令審計掛載；錄影或指令審計無法掛載時 SHALL 與人類路徑採相同的 fail-close 處置。

#### Scenario: 授權於呼叫前被撤銷

- **WHEN** 執行者對一個授權已被撤銷的資產呼叫 `open_session`
- **THEN** 呼叫被拒，未建立工作階段，且審計留有一筆拒絕紀錄

#### Scenario: 來源位址閘對 agent 生效

- **WHEN** 主體的允許來源網段清單非空，執行者自清單外的位址呼叫 `open_session`
- **THEN** 呼叫被拒，拒絕依據為來源位址，且判定所用位址為呼叫端位址而非迴路位址

#### Scenario: 工作階段留痕與人類路徑同形

- **WHEN** 執行者成功呼叫 `open_session` 並送出指令後關閉
- **THEN** 該工作階段有錄影檔，指令審計筆數與同樣操作的人類工作階段一致

### Requirement: 指令執行的六個狀態與逾時誠實邊界

`run_command` SHALL 以下列六個互斥狀態之一回應：`completed`、`timed_out`、`needs_input`、`blocked`、`unknown`、`running`。

`completed` SHALL 只表示系統在逾時前於輸出中觀察到提示符再次出現。它 SHALL NOT 被表述為「指令已結束」或「指令執行成功」；工具不提供 exit_code 等結束保證，執行者須以輸出及獨立狀態證據判讀。工具說明 SHALL 寫明這條邊界。

`timed_out` SHALL 表示在指定秒數內未觀察到提示符，該次指令的**結果為未知**：指令可能仍在執行、可能已完成、可能已失敗。回傳 SHALL NOT 以任何欄位暗示指令已結束。工具說明 SHALL 寫明「逾時後不得盲目重送同一指令」，並指出可用的確認手段。

`blocked` SHALL 表示送出的內容命中阻斷規則，回傳 SHALL 攜帶該規則的機器可辨碼。

送出的指令 SHALL 以歸位字元結尾。

`run_command` SHALL 接受選填的**冪等鍵**：同一工作階段內、同一鍵於 60 秒內再次送達時，系統 SHALL 回傳前一次的結果並
SHALL NOT 對工作階段送出任何位元組。這是工具層唯一能真正防止重送的手段——說明文字只約束願意讀它的執行者，
而逾時後重送是自動化最容易做的事。未帶冪等鍵時系統無從辨識兩次呼叫是否為同一意圖，重送即真的重送；
工具說明 SHALL 寫明這條邊界，SHALL NOT 使執行者以為系統預設會去重。

**狀態判定的邊界 SHALL 寫進工具說明**：提示符可被目標端偽造（提示字串是可設定的），背景程序的輸出可與本次指令的輸出交錯。
故 `completed` 與殘餘標示皆為啟發式判定，SHALL NOT 被表述為對「指令已結束」或「這段輸出屬於哪一次呼叫」的保證。

#### Scenario: 逾時不宣稱結果

- **WHEN** 執行者以 5 秒逾時送出一條需要 30 秒的指令
- **THEN** 狀態為 `timed_out`，回傳不含任何表示指令已完成或已失敗的欄位

#### Scenario: 看到提示符不等於成功

- **WHEN** 執行者送出一條會以非零離開碼結束的指令，且提示符在逾時前出現
- **THEN** 狀態為 `completed`，而輸出中保留該指令自身的錯誤訊息供執行者判讀

#### Scenario: 命中阻斷規則

- **WHEN** 執行者送出一條命中阻斷規則的指令
- **THEN** 狀態為 `blocked` 並附規則的機器可辨碼，工作階段未中斷

#### Scenario: 同一冪等鍵不重送

- **WHEN** 執行者以同一個冪等鍵於 60 秒內兩次呼叫 `run_command`
- **THEN** 第二次回傳前一次的結果，且該工作階段未收到任何位元組

### Requirement: 逾時殘餘輸出不得污染下一次呼叫

當某次 `run_command` 以 `timed_out` 結束後，該指令稍後產生的輸出 SHALL NOT 被當作下一次 `run_command` 的結果回傳而不加標示。

下一次 `run_command` 的回傳 SHALL 攜帶 `stale_output` 標記，指出本次回傳的輸出區段中含有前一次未收斂的內容；系統 SHALL 在該標記中指出殘餘來自哪一次呼叫。工作階段一旦重新觀察到提示符且無未收斂的前次指令，後續回傳 SHALL NOT 再帶該標記。

#### Scenario: 逾時後的下一次呼叫被標示

- **WHEN** 一次 `run_command` 逾時，執行者隨後送出另一條指令，而前一條的輸出此時才抵達
- **THEN** 該次回傳帶有 `stale_output` 標記並指出殘餘來源，執行者可辨識輸出不全屬本次指令

#### Scenario: 收斂後標記消失

- **WHEN** 前一次逾時的指令已結束、提示符已重新出現，執行者再送出一條指令
- **THEN** 該次回傳不帶 `stale_output` 標記

### Requirement: 等待輸入的工作階段必須可復位

當 `run_command` 逾時且輸出的末尾呈現等待互動輸入的形態（例如密碼提示）時，系統 SHALL 以 `needs_input` 狀態回應，SHALL NOT 以 `timed_out` 含糊帶過。

`needs_input` 的回傳 SHALL 說明工作階段目前停在等待輸入，並 SHALL 指出可用的復位手段（以按鍵工具送出中斷鍵）。

**系統 SHALL NOT 自動送出中斷鍵或任何其他位元組**：復位是一個會改變目標主機上執行中動作的決定，該決定屬於執行者；
自動送鍵也會在指令審計裡留下沒有任何人下過的輸入。回傳 `needs_input` 的該次呼叫 SHALL NOT 對工作階段寫入任何位元組。
系統 SHALL 使工作階段在執行者採取復位動作後回到可接受下一條指令的狀態；復位完成 SHALL 於回傳中明確表示。

系統 SHALL NOT 提供任何把密碼或其他機密作為工具參數送入互動提示的路徑。

#### Scenario: 互動提示被辨識

- **WHEN** 執行者送出一條會停在密碼提示的指令
- **THEN** 狀態為 `needs_input`，回傳說明工作階段停在等待輸入並指出復位手段，且系統未對該工作階段送出任何位元組

#### Scenario: 復位後工作階段可用

- **WHEN** 執行者對停在 `needs_input` 的工作階段採取復位動作，隨後送出一條普通指令
- **THEN** 回傳明確表示工作階段已復位，且該普通指令取得屬於自己的輸出

#### Scenario: 機密不得經工具參數送入

- **WHEN** 檢視工具面
- **THEN** 不存在任何接受密碼或機密作為參數的工具或參數欄位

### Requirement: 等待核准期間可被判斷

`check_request` SHALL 回傳申請單的建立時間、目前狀態、已取得的核准數、所需的核准數，以及該單的失效時間。工具說明 SHALL 據此給出等待策略：在什麼情況下繼續等、在什麼情況下改做別的事、在什麼情況下判定不會被核准。

`request_access` SHALL 僅在「該資產已有本主體的**有效核准任務項**」時回傳表示已可連線的狀態，且該回傳 SHALL 攜帶那一項所屬的任務識別，
使執行者得以據之建立連線。除此之外 SHALL 一律建立申請單——包含 `open` 段位的資產：`open` 段位 SHALL NOT 成為免單的例外，
無單時 SHALL 照常建項並由後端即時自動核准。理由是建立連線必帶任務識別；若對 `open` 段位資產回「已可連線」而不建單，
執行者就沒有任何可用的任務識別，形成無出口的斷路。

`request_access` SHALL 逐資產帶帳號範圍。由自動化主體執行的項 SHALL NOT 以「全部帳號」提出；未指定帳號範圍時後端 SHALL 拒絕，工具 SHALL 如實回傳該拒絕並於說明中寫明必須指定，SHALL NOT 代為填入任何預設範圍。

#### Scenario: 等待中的單回傳足以判斷的資訊

- **WHEN** 執行者對一張仍在等待核准的申請單呼叫 `check_request`
- **THEN** 回傳含建立時間、已取得核准數、所需核准數與失效時間

#### Scenario: 已有有效核准項時不重複建單

- **WHEN** 執行者對一個已有本主體有效核准任務項的資產呼叫 `request_access`
- **THEN** 回傳表示已可連線並帶該項所屬的任務識別，系統中未新增任何申請單

#### Scenario: open 段位資產無單時照建

- **WHEN** 執行者對一個 `open` 段位、但本主體尚無任何有效任務項的資產呼叫 `request_access`
- **THEN** 系統建立申請項並即時自動核准，回傳帶該任務識別；SHALL NOT 以「已可連線」回應而不建單

### Requirement: 每次工具呼叫留痕

系統 SHALL 為每一次工具呼叫寫入恰一筆工具呼叫帳本列，含主體、所用 token、任務、工作階段（若有）、工具名、參數、判定結果、
遮罩後回傳文字的摘要與節錄、遮罩計數與耗時。

**寫入順序 SHALL 為「先記錄、後轉送」**：系統 SHALL 於把指令轉送至目標或建立連線之前寫入該列並標記為待定，結果返回後 SHALL 更新同一列
（判定、結果狀態、回傳摘要與節錄、耗時），SHALL NOT 於結果返回後才首次寫入。行程於兩者之間中止時該列 SHALL 停留在待定狀態，
使稽核面看得到「已記錄，是否送出與結果皆未知」；系統 SHALL NOT 補寫其結果，亦 SHALL NOT 刪除該列。

被拒絕的呼叫 SHALL 同樣留痕，並記錄拒絕的機器可辨原因。帳本寫入失敗 SHALL NOT 被靜默吞掉。

**參數留存規則**：帳本 SHALL 逐字保存執行者送入的參數原文（`run_command` 的指令、`query` 的 SQL、`send_keys` 的按鍵、`close_task` 的報告、各工具的任務／資產／帳號識別與理由），SHALL NOT 以整欄遮罩取代；被拒絕與被阻斷的呼叫尤其 SHALL 留下原文，因為那是稽核者判讀異常的唯一依據。唯二例外：(1) 能力句柄與任何憑證（現況為 `session_handle`）SHALL 以不可逆指紋取代，SHALL NOT 逐字保存；(2) 參數命中輸出面敏感資料規則（卡號、私鑰等）的片段 SHALL 在帳本的可讀欄以固定標記取代，而原文 SHALL 另以靜態加密留存，僅經「敏感內容調閱」路徑取得（見 agent-channel-ui 與 command-alerts 對應 requirement）。本規則前寫入的列 SHALL 於呈現面標示「未留存參數」，SHALL NOT 顯示為遮罩標記以免與機敏遮罩混淆。

#### Scenario: 被拒的呼叫同樣留痕

- **WHEN** 一次 `open_session` 因授權不足被拒
- **THEN** 帳本新增恰一筆列，判定為拒絕並記錄原因碼

#### Scenario: 轉送前先留痕

- **WHEN** 執行者送出一條指令，系統尚未將其轉送至目標
- **THEN** 帳本已有該次呼叫的一列且判定為待定；結果返回後更新的是同一列

#### Scenario: 帳本不含票證

- **WHEN** 檢視任一次 `open_session` 的帳本列
- **THEN** 參數欄不含連線票證、密碼或其他憑證的原文

#### Scenario: 無法歸屬任務的呼叫於入口拒絕並由請求審計留痕

- **WHEN** 非三個前置工具的呼叫缺 request_id、request_id 不存在或非本主體執行、或句柄不存在／非本 MCP 連線與 token
- **THEN** 系統在工具帳本之前拒絕，不新增 agent_tool_calls、不填假任務或改工具名稱；同次 MCP HTTP 審計列記錄 agent 主體、工具名、拒絕原因碼與時間，open_session 另沿 AP-69 via=mcp 留建線拒絕
- **AND** 可合法歸屬任務的呼叫仍須先 pending，完成或拒絕後更新同列；三個前置工具可空任務的清單不變

#### Scenario: 被阻斷的指令原文可讀

- **WHEN** `run_command` 送入 `ssh 10.0.0.9` 並命中阻斷規則
- **THEN** 帳本該列判定為拒絕、原因碼為阻斷，參數欄可讀到 `ssh 10.0.0.9` 原文

#### Scenario: 句柄以指紋留存

- **WHEN** 任一帶 `session_handle` 的呼叫寫入帳本
- **THEN** 參數欄的 `session_handle` 為固定長度指紋，無法還原句柄本身，但同一句柄在各列的指紋一致可供關聯

#### Scenario: 命中機敏規則的參數分級留存

- **WHEN** `run_command` 的指令含一組通過 Luhn 檢核的卡號
- **THEN** 帳本可讀欄的該段為固定標記、遮罩計數為 1，且該列另存有加密原文；列表與詳情預設不呈現原文

### Requirement: 輸出面遮罩只作用於回傳給執行者的內容

系統 SHALL 在回傳給執行者之前，對 `run_command` 的輸出、`read_screen` 的行、`query` 的結果列與 `close_task` 的報告本文套用輸出面敏感資料規則，並以固定標記取代命中的內容，同時記錄本次呼叫的遮罩計數。

錄影與指令審計 SHALL 保留未遮罩的原文：遮罩是給執行者看的那一份，SHALL NOT 改變作為證據的那一份。

`run_command` 的指令被阻斷規則攔下時，該工作階段的錄影 SHALL 同時留下阻斷標記與被攔下的指令原文——執行者送入的整行從未抵達目標、不會被回顯，若錄影只有標記，稽核者無從得知被擋的是什麼。

#### Scenario: 執行者看到遮罩、錄影保留原文

- **WHEN** 目標主機輸出一段命中輸出面規則的內容
- **THEN** 執行者取得的文字中該段已被取代，帳本記錄遮罩計數，而該工作階段的錄影中該段為原文

#### Scenario: 阻斷的指令進錄影

- **WHEN** 執行者以 `run_command` 送入命中阻斷規則的指令
- **THEN** 錄影回放在阻斷標記的同一處可讀到該指令原文，執行者收到的回傳只有阻斷機器碼與規則名

### Requirement: 螢幕讀取在本版本的邊界

`read_screen` 於本版本 SHALL 以行緩衝實作：回傳該工作階段累積輸出去除控制序列後的最後 N 行。

其工具說明 SHALL 明確寫出：它不是虛擬螢幕；當目標端執行畫面清除、游標定位或全螢幕程式時，回傳內容與真實終端畫面不一致。系統 SHALL NOT 以任何措辭把它表述為終端畫面的快照。

#### Scenario: 說明寫明非虛擬螢幕

- **WHEN** 執行者讀取 `read_screen` 的工具說明
- **THEN** 說明中含「非虛擬螢幕」與全螢幕程式下不一致的邊界陳述

#### Scenario: 全螢幕程式後的回傳不被宣稱為畫面

- **WHEN** 工作階段執行過會重繪整個畫面的程式後呼叫 `read_screen`
- **THEN** 回傳為累積輸出的末尾若干行，系統未宣稱其等同當前終端畫面

### Requirement: 工作階段生命週期由服務負責收束

工作階段句柄 SHALL 只在發給它的 MCP 連線的存續期內有效，SHALL NOT 可被另一個 token 或另一個主體引用。

當 token 被撤銷或停用、主體或其負責人被停用、或授權來源單被撤銷時，該 token 建立的工作階段 SHALL 沿既有的即時終止路徑關閉；其後對該句柄的任何工具呼叫 SHALL 以明確的已終止狀態回應，SHALL NOT 回傳看似正常的空輸出。

執行者未呼叫 `close_session` 而 MCP 連線中斷時，系統 SHALL 關閉其建立的工作階段並結算錄影與指令審計，SHALL NOT 留下上游連線續存而無人收束的工作階段。

#### Scenario: 撤銷 token 後句柄不可用

- **WHEN** 執行者的 token 於工作階段進行中被撤銷，隨後以同一句柄呼叫 `run_command`
- **THEN** 回應為明確的已終止狀態，且該工作階段的上游連線已關閉

#### Scenario: 連線中斷不留孤兒工作階段

- **WHEN** 執行者在未呼叫 `close_session` 的情況下中斷 MCP 連線
- **THEN** 其建立的工作階段被關閉、錄影結算完成，資料庫中無仍標示為進行中的殘留列

#### Scenario: 期限對存量會話及進行中指令的效力

- **WHEN** token 到期、會話綁定的任務項到期、或任務持久化 closed_at（含 close_task 及全部項到期／撤銷）
- **THEN** 三種情形皆終止既有工作階段，進行中的 run_command 同時被打斷、不等待該指令完成，工具回 terminated 而非空輸出或 completed；僅終止本系統的連線，不保證遠端背景程序停止
- **AND** 服務每 250ms 檢查在存會話的 token 與任務信封；此為偵測取樣間隔，不保證資料庫故障／排程延遲下的完成時限。撤銷事件沿既有 registry 即時收線；已失效 token 的新 HTTP 請求仍回既有 AUTH_AGENT_TOKEN_INVALID，不為表達句柄狀態繞過認證

#### Scenario: 無持續 HTTP 請求時中斷由有界閒置租期偵測

- **WHEN** POST streamable HTTP 客戶端在沒有進行中請求時消失（含程序退出），未先 close_session
- **THEN** 因無持續 socket 可立即判斷，服務於 SDK 的五分鐘閒置租期屆滿後關閉該 MCP session 的工作階段並結算錄影／指令審計，不主張 TCP 關閉等於 MCP session 已即時結束
- **AND** 進行中的終端工具 HTTP 請求被取消時立即關閉其工作階段；不新增 GET／DELETE 路由或改 agent 允許清單

### Requirement: 任務收束與報告

`close_task` SHALL 接受任務識別與報告本文，並將報告存為該任務的一個版本。任務在關閉時無報告 SHALL 為可被觀察的狀態，SHALL NOT 以空白報告冒充已交付。

**`close_task` SHALL NOT 為任務關閉的唯一途徑**：任務亦於其全部任務項到期或被撤銷時關閉，關閉時刻由後端持久化，
關閉 SHALL 終止該任務名下其餘進行中的工作階段。工具說明 SHALL 寫明這一點，SHALL NOT 使執行者以為「沒呼叫 `close_task` 就仍然開著」；
工作階段因任務關閉而被收束後，其後對該句柄的呼叫 SHALL 回明確的已終止狀態。缺報告 SHALL 以關閉時刻判定。

`close_task` SHALL NOT 具備關閉他人任務或修改既有報告版本的能力。對同一任務再次呼叫 SHALL 為提交新版本，並 SHALL 受審計面的修訂資格與修訂時窗約束（限原提交主體、限任務關閉後的固定時窗內）；逾窗或非原提交者的呼叫 SHALL 由後端拒絕，工具 SHALL 如實回傳該拒絕，SHALL NOT 自行重試或改以其他路徑寫入。

#### Scenario: 報告落檔為任務的版本

- **WHEN** 執行者對自己的任務呼叫 `close_task` 並附報告本文
- **THEN** 該任務新增一個報告版本，內容為遮罩後的報告本文

#### Scenario: 無報告的任務可被辨識

- **WHEN** 任務關閉而未提交任何報告
- **THEN** 該任務在報告面呈現為缺報告，而非呈現為一份空報告

#### Scenario: 任務項全數到期即關閉

- **WHEN** 執行者未呼叫 `close_task`，而該任務的全部任務項皆已到期
- **THEN** 任務被關閉並記錄關閉時刻，其名下仍進行中的工作階段被終止，其後對該句柄的呼叫回已終止狀態

### Requirement: 對外文件說明接入方式與開放邊界

主產品對外文件 SHALL 於說明文件首頁提供 agent 接入一節，並 SHALL 於快速入門提供接上第一個宿主的最短路徑。該節 SHALL 依序說明：

1. MCP 服務端即本產品後端的 `POST /api/v1/mcp` 端點，隨產品部署即存在，無另外需要部署的服務端。
2. 兩種接法：支援 streamable HTTP 的宿主以 agent token 直連；只支援 stdio 的宿主安裝 `custodexa-mcp` 轉接頭，並指向其公開 repo。
3. 開放邊界：agent 主體的自助建立出廠為關閉；agent token 必須設定到期時刻，明文只在建立時顯示一次；agent 只能連線經 `request_access` 申請並核准的資產；每一次工具呼叫寫入帳本；回傳給 agent 的內容經遮罩，而錄影保留原始畫面。

對外文件 SHALL NOT 指示使用者從主產品原始碼或服務端容器映像取得轉接頭。

#### Scenario: 讀者分得清服務端與轉接頭

- **WHEN** 讀者閱讀說明文件首頁的 agent 接入一節
- **THEN** 可得知服務端已在產品內、何種宿主需要轉接頭、轉接頭從哪裡取得

#### Scenario: 開放邊界明列

- **WHEN** 讀者評估是否開放 agent 通道
- **THEN** 該節列出自助建立預設關閉、token 必設到期、只能連經核准的資產、呼叫留帳本與遮罩語義

#### Scenario: 不再指向已移除的取得方式

- **WHEN** 檢索主產品全部對外文件中提及轉接頭的段落
- **THEN** 無任何段落指示自主產品原始碼建置或自服務端映像執行轉接頭
