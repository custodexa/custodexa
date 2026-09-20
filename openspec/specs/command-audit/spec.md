# command-audit

## Purpose

終端輸出經虛擬螢幕重組還原使用者實際執行的指令，全程留存供稽核。
## Requirements
### Requirement: SSH command capture

For SSH sessions the system SHALL reconstruct executed command lines by feeding the server output stream into a virtual terminal screen and extracting the current line when the user submits it with Enter. **Enter SHALL be recognized as either carriage return (`\r`) or line feed (`\n`)**, matching how the target host's line discipline treats both bytes; a `\r\n` pair SHALL count as one submission followed by one empty submission, and empty submissions SHALL NOT produce records. Every rule that counts submissions (replay-queue round counting, queue settlement at close) SHALL use the same Enter definition. This reconstruction MUST correctly reflect backspace editing, tab completion, and history recall (arrow keys), since the captured text comes from the rendered screen rather than raw keystrokes. Captured commands SHALL be persisted with session, user, asset, sequence and timestamp. When the rendered screen shows evidence of full-screen redraw, the system SHALL stop reconstructing command text from screen content for that round.

**偵測 SHALL NOT 僅依賴輸出流中的 alternate-screen 標記。** 那些位元組由被稽核主機送出，
而輸出流的內容使用者可以影響——全螢幕程式送出的與其他來源送出的無從分辨。
僅依賴該標記時，該判定即成為單點失效：一旦被誤導，其後整段會話的指令審計靜音。

**偵測 SHALL 在重組後的 render 緩衝上進行，SHALL NOT 逐幀比對。**
逐幀比對可被輸出流的分段方式規避，而分段並非全然不受使用者影響；
規避的後果是全螢幕重繪落入正常解析路徑而**產生捏造的指令紀錄**。

**拒絕發出 SHALL 同時滿足兩個條件**：(a) 該輪已被全螢幕重繪汙染，
且 (b) 重組文字沒有有效的原點或提示符錨點。
**僅缺原點者 SHALL 仍然發出**——多候選補全的重繪會重印提示符，
該路徑是下方 Scenario「重繪自帶 prompt 的情形不受原點種入影響」所要求的合法行為。 Capture failures MUST NOT disrupt the session.

**指令文字的欄位原點 SHALL 含 prompt。** 重組時餵進虛擬螢幕的是「自使用者按第一個鍵起累積的回顯」，
其中不含 prompt；但 shell 與 readline 送出的欄位算術（游標右移、行清除、行內插入刪除）
是**相對於含 prompt 的整行**。系統 SHALL 在進入輸入狀態時，把當下螢幕的**游標所在列原文與游標顯示欄**
種入輸入期的虛擬螢幕作為原點，並在結算時還原。原點 SHALL 取自螢幕的游標欄，
SHALL NOT 以去除前後空白後的 prompt 文字長度代替——去空白會使原點少一欄，
而尾端輸出恰為換行時游標本就在新的一列、原點應為空。

#### Scenario: Command captured
- **WHEN** a user types `ls -la` and presses Enter in an SSH session
- **THEN** a command record `ls -la` is stored for that session

#### Scenario: 以換行符結尾的指令同樣被記錄
- **WHEN** 客戶端以 `uptime\n`（而非 `uptime\r`）送出指令且對端正常回顯
- **THEN** 該會話存在一筆 `uptime` 指令紀錄，與 `\r` 結尾者形態相同

#### Scenario: CRLF 不產生重複或空白紀錄
- **WHEN** 客戶端以 `uptime\r\n` 送出指令
- **THEN** 該會話恰有一筆 `uptime` 指令紀錄，沒有多出的空白紀錄

#### Scenario: 同幀多條以換行分隔的指令各自記錄
- **WHEN** 客戶端在同一幀送出 `echo a\necho b\n`
- **THEN** 該會話依序存在 `echo a` 與 `echo b` 兩筆紀錄

#### Scenario: Backspace correction
- **WHEN** a user types `lss`, presses backspace, then types `s` and Enter
- **THEN** the stored command is `ls`

#### Scenario: Tab completion captured
- **WHEN** a user types `ls /et` then Tab (server completes to `/etc/`) then Enter
- **THEN** the stored command is `ls /etc/`

#### Scenario: History recall captured
- **WHEN** a user presses Up arrow (server replays `cat /etc/hosts`) then Enter
- **THEN** the stored command is `cat /etc/hosts`

#### Scenario: Alternate screen suppressed
- **WHEN** a user runs `vim` (server sends `\x1b[?1049h`) and types inside it
- **THEN** no command records are created for keystrokes until `\x1b[?1049l` is received

#### Scenario: 整行清除後改打的指令不被拼接
- **WHEN** 使用者輸入 `abc`、按 Ctrl-U 清行、改打 `ls` 後 Enter
- **THEN** 該會話的指令紀錄為 `ls`，不含 `abc`

#### Scenario: 補全後清行改打的語句不被拼接
- **WHEN** 使用者輸入 `ls /et`、按 Tab 補全、按 Ctrl-U 清行、改打 `pwd` 後 Enter
- **THEN** 該會話的指令紀錄為 `pwd`

#### Scenario: 重繪自帶 prompt 的情形不受原點種入影響
- **WHEN** 多候選補全使 shell 重印提示符與輸入
- **THEN** 結算文字仍為使用者送出的指令，不含提示符

#### Scenario: 偽造的 alternate-screen 標記不使會話靜音
- **WHEN** 輸出流中出現非全螢幕程式送出的 alternate-screen 標記，其後使用者照常在 shell 執行指令
- **THEN** 後續每一輪輸入仍各自產生審計記錄（完整指令文字或降級紀錄），不存在整段靜音

#### Scenario: 不進入 alternate screen 的全螢幕程式不產生假指令
- **WHEN** 使用者執行不切換 alternate screen 的全螢幕程式並在其中按鍵
- **THEN** 該時段不產生以螢幕內容捏造的指令紀錄

#### Scenario: 標記被切在幀邊界上仍不產生假指令
- **WHEN** alternate-screen 標記位元組跨越兩個輸出幀
- **THEN** 判定結果與單幀送達時相同

### Requirement: Command retrieval APIs
The system SHALL provide two command retrieval endpoints with distinct permission gates: the per-session command list (`GET /sessions/:id/commands`) SHALL require `session:view`, and the cross-session search (`GET /commands`; keyword substring, user, asset, time range, pagination) SHALL require `audit:view`. Both `session:view` and `audit:view` are held only by admin/auditor. A regular user SHALL NOT retrieve the commands of any session through either endpoint — neither their own nor others' — because command content may contain secrets typed at the terminal.

#### Scenario: Keyword search
- **WHEN** an auditor searches commands with keyword "rm"
- **THEN** all captured commands containing "rm" are returned with their session context

#### Scenario: Regular user denied per-session commands
- **WHEN** a user-role account calls `GET /sessions/:id/commands` for any session id
- **THEN** the API returns 403 and no command content is disclosed

#### Scenario: Regular user denied cross-session search
- **WHEN** a user-role account calls `GET /commands`
- **THEN** the API returns 403 (audit:view required) and no command content is disclosed

### Requirement: Command audit UI
SessionDetail SHALL show the session's command list; a Commands page under the audit group SHALL offer cross-session search with links to session detail.

#### Scenario: Session detail commands
- **WHEN** an SSH session with captured commands is opened in session detail
- **THEN** the command list renders in execution order with timestamps

### Requirement: DB CLI 多行 SQL 語句累積
對 mysql/postgres 會話，指令審計 SHALL 把跨續行（continuation prompt）的單一邏輯 SQL 語句累積為**一筆** session_command，遇語句結束符（尾端 `;`、`\g`/`\G`、或開頭 `\` 元命令）才結算；redis 與 ssh SHALL 維持逐行記錄。累積後的記錄 SHALL 含完整語句（含換行），使審計可搜尋且告警比對看得到完整語句。

#### Scenario: 跨行 SQL 存為單筆
- **WHEN** 使用者在 psql 跨三行輸入 `SELECT`⏎`1 AS`⏎`x;`
- **THEN** session_commands 記錄一筆完整語句 `SELECT\n1 AS\nx;`，而非三筆

#### Scenario: 元命令不誤併
- **WHEN** 使用者輸入 psql 元命令 `\dt` 後再輸入 `SELECT 1;`
- **THEN** 兩者各為獨立一筆 session_command

### Requirement: 已送出的輸入不得因結算時序而遺失
使用者送出的每一輪輸入 SHALL 產生一筆對應的審計記錄。**指令文字無法可信重組時
（見「重繪期間的降級 SHALL 可搜尋且可告警」），該記錄 SHALL 為明確標記的降級紀錄，
SHALL NOT 為零紀錄**。前一輪尚在等待回顯結算期間抵達的輸入 MUST 排入佇列並於結算完成後重放，SHALL NOT 丟棄。

此需求與既有的「重組結果 SHALL NOT 含使用者未送出的內容」互為兩面，兩者 MUST 同時成立：前者防捏造、本條防漏記。修補漏記 SHALL NOT 以放寬捏造約束為代價。

**本條的失效是安全缺陷而非可靠性缺陷**：送出時機與封包切分由使用者端控制，故遺失可被主動觸發。使用者確實有權執行該指令——被繞過的是留痕，不是執行權。

#### Scenario: 同一封包內的多條指令
- **WHEN** 單一輸入封包含多條以 Enter 分隔的指令（如 `echo A\recho B\r`）
- **THEN** 每一條各產生一筆審計記錄，數量與實際在遠端執行的條數一致

#### Scenario: 前一條回顯未返回即送出下一條
- **WHEN** 前一輪的回顯尚未返回，使用者已送出下一輪輸入
- **THEN** 後送的輸入排隊等待前一輪結算，結算後重放並產生自己的審計記錄

#### Scenario: 結算順序與送出順序一致
- **WHEN** 多輪輸入在結算期間連續抵達
- **THEN** 審計記錄的順序與送出順序相同

### Requirement: 重放佇列的容量上界機器可見
重放佇列 SHALL 有明確的容量上界，且該上界 MUST 以程式可檢的形式表達（常數、斷言或測試），SHALL NOT 僅以註解聲明。佇列達到上界時的行為 MUST 為明確定義的終態，並 SHALL 產生可觀測的訊號。

理由：對端若永不回顯，結算永不完成，佇列將無限增長。這是本需求引入的新失敗面——**不得以「實務上不會發生」為由略過**，因為對端正是不受信的納管主機。

#### Scenario: 佇列達到上界
- **WHEN** 結算長時間未完成且抵達的輸入達到佇列上界
- **THEN** 行為符合明確定義的終態，且該事件可被觀測（非靜默丟棄）

### Requirement: 重繪期間的降級 SHALL 可搜尋且可告警

當某一輪輸入因全螢幕重繪而無法可信重組指令文字時，系統 SHALL 產生一筆降級紀錄。
該紀錄 MUST 可歸因到會話與時段、MUST 可被稽核搜尋、
且 **MUST 本身即為可告警的訊號**——SHALL NOT 僅為一筆可搜尋而不可告警的列。

降級紀錄 **SHALL NOT 包含推測的指令文字**。無法還原即記為無法還原，
不得以任何形式猜測其內容——捏造比漏記更嚴重（見「SSH command capture」的論證）。

**理由**：本產品判斷審計缺陷的兩條判準是「稽核事後查得到嗎」與「該響的告警會響嗎」。
一筆只可搜尋、不可告警的降級列在攻擊案上接近無用——攻擊者可令所有輪次降級，
把「零紀錄」換成「無用紀錄」，實質未改善。

**本版本的邊界（誠實記載，SHALL 不被理解為更強的保證）**：
指令文字的還原依賴被稽核主機的終端輸出流，而該流的內容使用者可以寫入。
因此對一個**刻意規避的攻擊者**，本機制的保證是
**「不靜默漏記、不捏造、降級可告警」**，
**SHALL NOT** 被理解為「攻擊者仍無法規避指令文字審計」。
取得後者需要在被稽核主機上取得核心層事實（如自 `execve` 取指令），
牴觸本產品無 agent 的形態，屬 1.x 以後的射程。
此邊界為**本版本的選擇**，非技術上不可達成。

**指令文字審計是索引，連線錄影是事實來源。** 兩者不一致時 SHALL 以錄影為準。
重組自終端輸出流的指令文字，在部分程式形態下可能不正確（見下段）；
而錄影保存的是該時段的原始輸出，**足以還原當時實際發生的事**。
稽核流程 MUST 據此設計：對任何指令紀錄的爭議，以該時段錄影為裁決依據。
本產品 SHALL NOT 宣稱文字索引在所有終端程式形態下皆正確——
終端程式與分頁器的形態無窮，逐一枚舉不會收斂。

**未觸發判準的重繪捏造 SHALL 被視為本版本的已知邊界。** 不送 alternate-screen 標記、
以純相對定位（`\r`／`ESC[K`）逐列重繪、且每輪結算時為單列的程式
（如 BusyBox 的預設 `more`、以 Enter 捲動的 `less -X`），其重繪內容可能被誤記為指令，
而該紀錄 **不帶降級標記**（`degraded=false`）。此類程式為一般使用者的常見工具，
非攻擊者專屬。**此類誤記的內容若命中告警規則，SHALL 被理解為可能對使用者未曾執行的
指令發出告警**——本機制不保證告警一定對應真實執行的指令。此邊界 MUST 於誠實邊界揭露，
不得使讀者以為所有告警都對應真實操作。

**降級標記 SHALL NOT 被理解為「未標記即可信」。** 判定螢幕是否遭全螢幕重繪的判準
是**充分條件而非必要條件**——存在不觸發判準卻仍可能產生錯誤重組的形態，
且不排除有尚未被發現者。稽核者看到一段**沒有**降級紀錄的指令歷史時，
SHALL NOT 據此推論該段內容必然可信。此限制 MUST 於使用者可見的介面上揭露，
不得僅記載於本規格——未揭露時，降級機制會**提高**稽核對未標記紀錄的信任度，
在該面向上是負向的。

**降級同時是日常事件與異常訊號，本版本不宣稱已將兩者分離。**
正常使用全螢幕程式（vim、nano、tmux、top 等）本就會產生降級紀錄，
故「出現降級」本身不是異常。告警判準因此必須看樣態而非單筆；
而樣態判準可被刻意壓低至與正常使用不可分。
本版本 SHALL 據實揭露此限制，**SHALL NOT 以未經量測的門檻宣稱兩者已可區分**。

#### Scenario: 全螢幕程式的會話產生降級紀錄而非零紀錄

- **WHEN** 使用者在 vim 中編輯並多次按 Enter
- **THEN** 該會話存在可歸因到該時段的降級紀錄，且其中不含任何指令文字

#### Scenario: 降級紀錄不含推測內容

- **WHEN** 某一輪因全螢幕重繪而無法可信重組
- **THEN** 該輪的紀錄 SHALL NOT 含任何自螢幕內容推測出的文字

#### Scenario: 降級本身可觸發告警

- **WHEN** 一條會話中出現異常的降級樣態（如長時間持續降級而未離開全螢幕狀態）
- **THEN** 該樣態 SHALL 可被告警機制觀測，而非僅存在於可查詢的紀錄中

### Requirement: 有輸入但零指令的會話 SHALL 標示降級並可告警

當一條 SSH 會話結束時，若系統曾收到來自使用者端的實質輸入位元組（非空、非純 Enter），卻自始至終沒有產生任何指令紀錄（包含降級紀錄），系統 SHALL 為該會話補一筆降級紀錄：指令文字恆為空、降級原因為專用機器碼，時間取會話結束時刻。該筆紀錄 SHALL 經既有的降級告警路徑發出告警，SHALL NOT 靜默。

降級紀錄 SHALL NOT 含任何輸入位元組或推測的指令文字。呈現面的文案 SHALL 描述事實（有輸入但無法還原任何指令），SHALL NOT 斷言成因（解析缺口、對端關閉回顯、客戶端形態皆可能）。

此要求是安全網：其目的是讓任何尚未被發現的 Enter 判定或結算缺口，對稽核者呈現為「審計失效」而非「這條會話沒有操作」。

#### Scenario: 有輸入但解析器未結算任何指令
- **WHEN** 一條 SSH 會話收到過非空輸入，結束時指令紀錄為零
- **THEN** 該會話存在恰一筆指令文字為空的降級紀錄，且產生一筆降級告警

#### Scenario: 正常會話不觸發
- **WHEN** 一條 SSH 會話至少產生過一筆指令紀錄或降級紀錄
- **THEN** 會話結束時不補任何額外紀錄

#### Scenario: 只按 Enter 不觸發
- **WHEN** 一條 SSH 會話的輸入只有 Enter（無其他位元組）
- **THEN** 會話結束時不補降級紀錄

#### Scenario: 呈現面不斷言成因
- **WHEN** 稽核者在會話詳情看到該降級紀錄
- **THEN** 文案描述「有輸入但無法還原任何指令」，不含「客戶端」「回顯」等成因用語

### Requirement: 結構化執行來源的指令紀錄與檢索

指令紀錄 SHALL 可承載**結構化執行來源**（資料庫查詢主控台）的列：其語句文字取自請求原文而非螢幕重組，故降級旗標恆為假、降級原因恆為空；此類列 SHALL 另帶事件識別（ULID，唯一）與結果事實欄（目標資料庫、結果狀態、原因碼、回傳列數、影響列數、結果集計數、目標端錯誤碼、耗時、是否截斷）。結果狀態 SHALL 取自資料庫約束釘住的集合（執行中、成功、錯誤、阻斷、已取消、逾時、部分生效、結果未知）。非結構化來源（螢幕重組）的列 SHALL 維持既有欄位語義，其事件識別與結果狀態欄為空值，SHALL NOT 被讀成任何結果事實。

既有檢索端點（單會話清單與跨會話搜尋）SHALL 原樣回傳結構化來源的列與其結果事實欄，權限閘不變；跨會話搜尋 SHALL 以同一關鍵字子字串語義涵蓋兩類來源，並 SHALL 增加結果事實篩選參數：來源（主控台／命令列）、目標資料庫、結果狀態（多選，含阻斷、部分生效、結果未知）、目標端錯誤碼；指令審計頁 SHALL 提供對應篩選控件。證據包的指令紀錄檔 SHALL 增列事件識別與結果事實欄（非結構化列為空），使被阻斷、部分生效或結果未知的主控台語句在包內不被讀成已執行。

「指令文字審計是索引、錄影是事實來源」的規則 SHALL 明載其在結構化來源的對應物：主控台列本身即事實來源，轉錄錄影為其派生（見 `db-query-console`）。

#### Scenario: 主控台語句可經既有端點檢索

- **WHEN** 稽核員以關鍵字搜尋跨會話指令
- **THEN** 命中的主控台語句與 CLI 語句同列回傳，主控台列帶結果事實欄且降級旗標為假

#### Scenario: 以結果事實篩選跨會話搜尋

- **WHEN** 稽核員以來源＝主控台、結果狀態＝部分生效與結果未知、目標資料庫＝`app` 篩選跨會話指令
- **THEN** 只回傳符合三個條件的主控台列，每列帶事件識別與原因碼；命令列來源的列不出現

#### Scenario: 證據包標示阻斷語句

- **WHEN** 匯出含主控台阻斷語句的證據包
- **THEN** 指令紀錄檔中該列的結果狀態為阻斷並帶事件識別，CLI 列的事件識別與結果狀態欄為空
