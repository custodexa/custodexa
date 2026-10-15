# session-workspace

## Purpose

多會話工作區：側欄資產列表（分組樹、名稱辨識、存取狀態引導、重新整理與全量載入）、保活頁籤、連線畫面留白、資料庫查詢主控台分頁，以及斷線標灰與重連。

## Requirements

### Requirement: Multi-session workspace
The system SHALL provide a workspace page with a slim header, a collapsible asset sidebar and a session tab area. Selecting an asset in the sidebar SHALL open a new session tab and activate it. Multiple sessions (including the same asset twice, and mixed protocols) SHALL run concurrently.

#### Scenario: Open multiple sessions
- **WHEN** the user opens two SSH assets and one VNC asset from the sidebar
- **THEN** three tabs exist, each with its own live session

### Requirement: Tab switching preserves sessions
Switching tabs MUST NOT disconnect or reset the underlying sessions; returning to a tab SHALL show the session in its previous state and re-fit terminal dimensions.

#### Scenario: Switch away and back
- **WHEN** the user runs a command in tab A, switches to tab B, then returns to tab A
- **THEN** tab A still shows the command output and accepts input without reconnecting

### Requirement: Closing a tab ends its session
Closing a session tab SHALL cleanly terminate that session (WebSocket closed, recording finalized) without affecting other tabs.

#### Scenario: Close one of several tabs
- **WHEN** the user closes tab B while tab A is active elsewhere
- **THEN** tab B's session ends and tab A remains connected

### Requirement: Workspace entry
The asset list connect action SHALL open the workspace in a new browser tab with the chosen asset auto-opened as the first session tab. The legacy single-session terminal route SHALL remain functional.

#### Scenario: Connect from asset list
- **WHEN** the user clicks connect on an asset
- **THEN** a workspace opens in a new browser tab with that asset's session active, and the asset list stays in the original tab

### Requirement: 頁籤拖曳排序
工作區頁籤 SHALL 支援水平拖曳重排；重排 SHALL 僅變更頁籤順序，不中斷任何會話連線，且當前啟用頁籤維持不變。

#### Scenario: 拖曳重排
- **WHEN** 使用者將頁籤拖曳至新位置放開
- **THEN** 頁籤列依新順序顯示，所有會話（含被拖曳者）連線保持

#### Scenario: 拖曳不誤觸切換
- **WHEN** 使用者點擊頁籤（未達拖曳延遲）
- **THEN** 正常切換頁籤，不觸發排序

### Requirement: 頁籤右鍵選單
頁籤標籤 SHALL 提供右鍵選單：重新連線、複製會話、關閉、關閉其他、關閉左側、關閉右側、關閉全部；操作 SHALL 僅影響目標頁籤集合，其餘會話連線不中斷。

#### Scenario: 重新連線
- **WHEN** 對頁籤選「重新連線」
- **THEN** 該頁籤面板重建並重新撥接，其他頁籤會話不受影響

#### Scenario: 關閉其他
- **WHEN** 對頁籤 B 選「關閉其他」（存在 A/B/C）
- **THEN** 僅 B 保留且為啟用頁籤

#### Scenario: 複製會話
- **WHEN** 對頁籤選「複製會話」
- **THEN** 以同一資產開啟新頁籤並啟用，原頁籤連線保持

### Requirement: 資料庫查詢主控台分頁

工作區側欄的 `mysql`／`postgres`／`mssql` 資產列 SHALL 提供獨立的「主控台」入口，點擊整列 SHALL 維持既有的命令列開籤行為。主控台入口 SHALL 為列尾的圖示鈕（附提示文字說明其開啟查詢主控台），只在該列被滑鼠停留、取得鍵盤焦點或為選中列時出現；未出現時 SHALL NOT 佔用名稱寬度。**入口的顯示判準 SHALL 與同列的命令列連線入口完全相同**，SHALL NOT 為主控台入口另創前端可見性判準、SHALL NOT 另設逐資產的主控台開關；connect 授權的裁決 SHALL 統一發生於連線票簽發點的閘序表——拒絕形狀與命令列連線一致。

側欄資產列 SHALL 消費資產列表既有的存取狀態欄位（`access_state`，與資產頁同一事實源）分化入口呈現（細則見「側欄存取狀態與點擊回饋」）：可連線者維持既有行為；需填理由者 SHALL NOT 被前端擋下，整列點擊與主控台鈕照常發起連線，由既有連線流程就地要求填寫理由（填理由屬連線流程的一步）；需審核者 SHALL 呈鎖定態，點擊 SHALL 說明需先申請並提供前往資產頁申請的途徑（工作區為純連線面，SHALL NOT 內嵌申請流程）；申請審核中者 SHALL 呈停用態並標示審核中。鎖定與停用態（含僅檢視）的整列點擊與主控台鈕 SHALL NOT 發起連線票簽發；欄位缺席（舊回應或未啟用申請流）時 SHALL 回退為既有行為（照常顯示、簽發點裁決）。呈現 SHALL 僅為提示，SHALL NOT 取代簽發點的授權裁決。主控台入口 SHALL 沿用既有帳號選擇流程（多帳號時先選帳號），建立型別為主控台的分頁；同一資產 SHALL 可同時開啟命令列分頁與主控台分頁。

主控台分頁 SHALL 為三區佈局：資料庫樹、語句編輯器、結果表；SHALL 提供資料庫切換、執行（含鍵盤快捷鍵）、執行選取範圍、**執行游標所在語句**（以游標位置切出的文字段送出；切分只決定送出範圍，不解析 SQL）、取消、匯出、樹重新整理；工具列在寬度不足時 SHALL 換行而非被裁切；資料庫樹 SHALL 提供對已載入節點的本地篩選；結果截斷的提示 SHALL 附可操作指引（如何以查詢語法縮小範圍）；空態與零列態 SHALL 走共用空狀態元件並給下一步指引；語句錯誤 SHALL 就近呈現於編輯器下方而非全域提示；結果表 SHALL 分頁且分頁列常駐；結果狀態列 SHALL 顯示狀態、原因碼與可複製的事件識別，部分生效與結果未知 SHALL 以警示呈現；交易處於失敗或不可提交狀態時 SHALL 常駐顯示並指引執行 `ROLLBACK`；MSSQL 分頁 SHALL 首次呈現可關閉的批次終止符說明。

主控台分頁的連線狀態 SHALL 與其他分頁同語義：斷線或錯誤時分頁標灰並可頁內重連；重連 SHALL 以新票建立新的會話、保留編輯器文字、清空結果並明示。斷線時若有進行中的執行單位，分頁 SHALL 顯示該筆結果未知並連到其稽核紀錄，重連後 SHALL 以伺服端回報的終態更新，且使用者送出與該單位位元組相同的文字前 SHALL 先確認。主控台分頁 SHALL NOT 顯示文字終端的工具列項目（分享、片段、檔案管理、系統監控）。

自工作區主動關閉主控台分頁（單一關閉、關閉其他、關閉全部）時，若該分頁存在進行中的執行單位或未提交／失敗狀態的交易，SHALL 先以破壞性確認揭露後果（結果未知或交易未提交、關閉即結束會話、結束後可於會話詳情查看終態），確認後才關閉；無上述狀態時 SHALL 維持既有的直接關閉行為。關閉後各執行單位的終態 SHALL 可於會話詳情以事件識別查得（回填由伺服端完成，不依賴分頁存活）。自會話管理頁自助終止主控台會話 SHALL 走既有的通用確認，不揭露未收束狀態——該頁不持有分頁狀態，伺服端側的揭露屬另一設計；其終態同樣可於會話詳情以事件識別查得。

#### Scenario: 自側欄開啟主控台

- **WHEN** 使用者將滑鼠停在 mysql 資產列上，點擊列尾出現的「主控台」圖示鈕
- **THEN** 開啟一個主控台分頁並啟用，樹載入可見資料庫，命令列分頁不受影響；點擊該列其他區域仍開啟命令列分頁；滑鼠離開且該列未選中時，圖示鈕隱藏、名稱恢復可用全寬

#### Scenario: 無 connect 授權者於簽發點被拒

- **WHEN** 存取狀態欄位缺席的回應中，一位無 connect 授權的使用者於側欄點擊某 mysql 資產的「主控台」入口
- **THEN** 連線票簽發點的閘序拒絕（與點擊整列開命令列的拒絕形狀一致），不建立會話、不解封憑證；持他人簽發的票直接呼叫主控台兌換點時同樣於閘序內被拒

#### Scenario: 側欄依存取狀態分化入口

- **WHEN** 側欄列出四個 mysql 資產：一個可連線、一個需填理由、一個需審核、一個申請審核中
- **THEN** 第一個維持既有的開籤與主控台入口；第二個的整列點擊與主控台鈕照常發起連線並先要求填寫理由；第三個呈鎖定態、點擊出現說明與「前往資產頁申請」、不發起簽發、工作區內不出現申請表單；第四個呈停用態並標示審核中、點擊出現說明、不發起簽發；四者的呈現不影響伺服端授權裁決

#### Scenario: 主控台分頁斷線可重連

- **WHEN** 主控台會話因閒置逾時結束
- **THEN** 分頁標灰並提示斷線、編輯器文字保留；選擇重新連線後以新票建立新會話，結果區清空並明示為新會話

#### Scenario: 斷線中的進行中語句顯示結果未知

- **WHEN** 使用者送出 `UPDATE` 後分頁斷線
- **THEN** 結果區顯示該筆結果未知並提供稽核紀錄連結；重連後若使用者再次送出相同文字，先出現確認提示

#### Scenario: 執行快捷鍵與錯誤就近呈現

- **WHEN** 使用者於編輯器按執行快捷鍵送出一條語法錯誤的語句
- **THEN** 錯誤與目標端訊息呈現於編輯器下方的錯誤面板，未出現全域錯誤提示

#### Scenario: 有未收束狀態時關分頁先確認

- **WHEN** 使用者送出 `UPDATE` 後（結果未回或交易未提交）點擊關閉該主控台分頁
- **THEN** 出現破壞性確認並揭露「結果可於會話詳情查看」；取消則分頁保留；確認後會話結束，稍後於會話詳情以事件識別查得該單位終態

#### Scenario: 執行游標所在語句

- **WHEN** 編輯器內有多條以分號分隔的語句，使用者將游標置於第二條內並點「執行游標語句」
- **THEN** 僅第二條語句的文字被送出執行，結果表呈現其結果

#### Scenario: 樹節點本地篩選

- **WHEN** 資料庫樹某層已載入大量節點，使用者於樹頂篩選框輸入片段
- **THEN** 樹僅顯示名稱含該片段的已載入節點，未發出任何伺服端請求；清空篩選即還原

#### Scenario: 窄寬度下工具列換行

- **WHEN** 主控台分頁的可用寬度小於工具列按鈕的總寬
- **THEN** 工具列換到第二行，所有按鈕可見且可點擊，未被裁切

### Requirement: 側欄資產列表的版面與名稱辨識

工作區側欄 SHALL 可由使用者拖曳調整寬度，範圍 200–480px、預設 280px；調整後的寬度 SHALL 保存在瀏覽器端，重新載入頁面後沿用，讀不到或值域外時 SHALL 回到預設。側欄整個收合的既有行為 SHALL 保留。拖曳把手 SHALL 可用鍵盤調整。

側欄每列 SHALL 以列首的小圖示表示協定類別（終端、桌面、資料庫、容器），hover 與輔助技術標籤 SHALL 提供協定全名；列上 SHALL NOT 再顯示協定文字徽章。資料庫查詢主控台入口在未被觸發顯示時 SHALL NOT 佔用名稱寬度（見「資料庫查詢主控台分頁」）。

資產名稱放不下時 SHALL 依下列規則截斷，使只差尾碼的資產仍可區分：

- 名稱含 `.` 時視為「主機名.網域」：主機名（第一個 `.` 之前）SHALL 完整保留，網域自尾端省略；
- 名稱不含 `.`，或主機名本身放不下時，SHALL 對主機名採保留尾段的中段省略；
- 放得下的名稱 SHALL 原樣顯示。

截斷規則 SHALL 實作為可單獨測試的純函式。hover SHALL 顯示資產全名與主機位址，且提示不得遮住分組樹；名稱 SHALL 維持介面字型。

#### Scenario: 網域式名稱保留主機名尾碼

- **WHEN** 兩台資產名為 `mysql-101-r-01.acme.internal.example` 與 `mysql-101-r-02.acme.internal.example`，名稱欄只放得下約 20 個字元
- **THEN** 兩列分別顯示為 `mysql-101-r-01.acme…` 與 `mysql-101-r-02.acme…`，可互相區分

#### Scenario: 無網域長名稱保留尾段

- **WHEN** 資產名為 `acme-db-prod-audit-primary-01`，名稱欄放不下
- **THEN** 顯示為頭段＋省略號＋尾段（例如 `acme-db-pro…primary-01`），尾碼 `primary-01` 可見

#### Scenario: 主機名本身過長

- **WHEN** 資產名為含網域的名稱，但第一個 `.` 之前的主機名已超過可用寬度
- **THEN** 網域被捨去，主機名以保留尾段的中段省略呈現

#### Scenario: 短名稱不截斷

- **WHEN** 資產名短於可用寬度
- **THEN** 名稱原樣顯示，不出現省略號

#### Scenario: 拖寬側欄並保留寬度

- **WHEN** 使用者把側欄拖到 400px 後重新載入工作區
- **THEN** 側欄以 400px 呈現；拖曳超過 480px 時停在 480px

#### Scenario: 協定以圖示呈現

- **WHEN** 側欄列出 SSH、RDP、MySQL 與 Kubernetes 資產各一台
- **THEN** 每列列首顯示對應類別圖示、hover 顯示協定全名，列上沒有協定文字徽章

### Requirement: 側欄分組樹、搜尋與重新整理

側欄 SHALL 依資產的節點路徑建立可收合的分層樹，每個節點名稱後 SHALL 緊接該節點子樹內的資產數；名稱過長時 SHALL 只截節點名、保留台數。多歸屬資產 SHALL 在其每個歸屬節點下各出現一次；未掛節點的資產 SHALL 歸「未分組」並排在最後。節點展開狀態 SHALL 保存在瀏覽器端；無保存紀錄時 SHALL 預設展開第一層。所有資產皆未分組時 SHALL NOT 顯示樹頭。

搜尋 SHALL 比對資產名稱、主機位址與節點路徑（不分大小寫）；有關鍵字時 SHALL 自動展開含命中的節點並隱藏無命中的節點；清空關鍵字 SHALL 還原使用者保存的展開狀態。

側欄 SHALL 提供重新整理按鈕，重新取得資產列表；載入中 SHALL 顯示進行中狀態。重新整理 SHALL NOT 關閉、重建或中斷任何已開啟的分頁。

側欄 SHALL 取完使用者可見的全部資產（逐頁取到總數為止），SHALL NOT 停在單頁上限而靜默遺漏資產；載入因安全上限中止時 SHALL 明示列表不完整。

#### Scenario: 分層樹與台數

- **WHEN** 使用者可見的資產掛在 `prod / mysql`（3 台）與 `prod / redis`（1 台）
- **THEN** 樹顯示節點 `prod (4)`，其下 `mysql (3)` 與 `redis (1)`，各節點可收合；重新載入後展開狀態沿用

#### Scenario: 搜尋主機位址

- **WHEN** 使用者在搜尋框輸入某台資產的主機位址片段
- **THEN** 該資產所在節點自動展開並顯示該資產，無命中的節點被隱藏；清空搜尋後回到原本的展開狀態

#### Scenario: 超過單頁上限的資產全部列出

- **WHEN** 使用者可見 150 台資產
- **THEN** 側欄列出全部 150 台，節點台數合計與之相符

#### Scenario: 重新整理不影響已開分頁

- **WHEN** 使用者已開兩個連線分頁，管理者新授權一台資產後，使用者按側欄的重新整理
- **THEN** 新資產出現在列表，兩個既有分頁的會話保持連線、內容不變

### Requirement: 側欄存取狀態與點擊回饋

側欄資產列 SHALL 消費資產列表既有的權限欄位（`permission`）與存取狀態欄位（`access_state`，與資產頁同一事實源）呈現入口；前端 SHALL NOT 另創可見性判準。點擊任何資產列 SHALL 有可見回饋，SHALL NOT 出現點了沒反應的列。對非特權角色：

- 僅具檢視權限者 SHALL 於列上標示僅檢視、SHALL NOT 發起連線票簽發，點擊 SHALL 說明無法連線的原因；
- 需填理由者（`reason_required`）SHALL NOT 被前端擋下：點擊照常發起連線，由既有連線流程就地要求填寫理由後連線；列上 SHALL 以提示標示連線時需填理由；
- 需審核者（`approval_required`）SHALL 呈鎖定態，點擊 SHALL NOT 發起簽發，SHALL 說明需先申請並提供「前往資產頁申請」：以新的瀏覽器分頁開啟資產頁並自動開啟該資產的申請表單，工作區已開的連線分頁 SHALL NOT 受影響；工作區 SHALL NOT 內嵌申請表單；
- 申請審核中者（`pending`）點擊 SHALL NOT 發起簽發，SHALL 說明審核中、核准後重新整理即可連線。

資產頁的申請深連結 SHALL 僅在該資產仍需申請時自動開啟申請表單；資產不存在或不可視時 SHALL 沿用既有的不存在呈現（不洩漏存在性）；狀態已變時 SHALL 改提示目前狀態；深連結參數在處理後 SHALL 清除。

欄位缺席（舊回應或未啟用申請流）與特權角色 SHALL 回退為既有行為（照常顯示、簽發點裁決）。呈現 SHALL 僅為提示，SHALL NOT 取代簽發點的授權裁決。

#### Scenario: 僅檢視資產不可連

- **WHEN** 一般使用者對某資產只有檢視授權，並在側欄點擊該列
- **THEN** 列上標示僅檢視；點擊出現說明無法連線的原因，未發起連線票簽發

#### Scenario: 需填理由資產照常連線

- **WHEN** 一般使用者點擊一台政策為需填理由的資產
- **THEN** 出現填寫連線理由的對話框；填寫送出後連線分頁開啟

#### Scenario: 需審核資產導向資產頁申請

- **WHEN** 一般使用者點擊一台政策為需審核的資產，並在說明中選擇「前往資產頁申請」
- **THEN** 新的瀏覽器分頁開啟資產頁並自動開啟該資產的申請表單；工作區內未出現申請表單、未發起連線票簽發，既有連線分頁保持連線

#### Scenario: 資產頁申請深連結遇到已不需申請的資產

- **WHEN** 使用者以帶指定資產的申請深連結開啟資產頁，但該資產此時已在審核中或已可連線
- **THEN** 不開啟申請表單，改提示該資產目前的狀態；深連結參數被清除，重新整理頁面不再觸發

#### Scenario: 審核中資產點擊有說明

- **WHEN** 一般使用者點擊一台申請審核中的資產
- **THEN** 出現說明審核中、核准後重新整理即可連線，未發起連線票簽發

### Requirement: 連線畫面留白與分頁標題

工作區各類連線分頁（文字終端、圖形桌面、資料庫查詢主控台）的畫面 SHALL 與主區四邊保持一致的小段留白，同一畫面 SHALL NOT 疊加兩層留白；畫面邊緣 SHALL NOT 被主區裁切。

分頁標題 SHALL 有最大寬度，超出時單行省略，hover SHALL 顯示完整標題（含手選帳號時的帳號）。分頁列 SHALL 為右側工具列預留空間，分頁 SHALL NOT 被工具列遮蓋。

#### Scenario: 三類分頁留白一致

- **WHEN** 使用者依序開啟 SSH、RDP 與資料庫查詢主控台分頁
- **THEN** 三者畫面與主區四邊的間距相同，畫面右緣與底緣完整可見

#### Scenario: 長分頁標題不被工具列蓋住

- **WHEN** 使用者開啟多個長名稱資產的分頁，使分頁列延伸到右側
- **THEN** 每個分頁標題單行省略、hover 可見全名，最右側分頁未被工具列遮蓋
