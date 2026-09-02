# session-workspace

## Purpose

多會話工作區：側欄資產列表、保活頁籤、斷線標灰與重連。

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

工作區側欄的 `mysql`／`postgres`／`mssql` 資產列 SHALL 提供獨立的「主控台」入口（列內文字鈕），點擊整列 SHALL 維持既有的命令列開籤行為。**入口的顯示判準 SHALL 與同列的命令列連線入口完全相同**，SHALL NOT 為主控台入口另創前端可見性判準、SHALL NOT 另設逐資產的主控台開關；connect 授權的裁決 SHALL 統一發生於連線票簽發點的閘序表——拒絕形狀與命令列連線一致。

側欄資產列 SHALL 消費資產列表既有的存取狀態欄位（`access_state`，與資產頁同一事實源）分化入口呈現：可連線者維持既有行為；需申請或需事由者 SHALL 呈鎖定態並就近指引至資產頁申請（工作區為純連線面，SHALL NOT 內嵌申請流程）；申請審核中者 SHALL 呈停用態並標示審核中。鎖定與停用態的整列點擊與主控台鈕 SHALL NOT 發起連線票簽發；欄位缺席（舊回應或未啟用申請流）時 SHALL 回退為既有行為（照常顯示、簽發點裁決）。呈現 SHALL 僅為提示，SHALL NOT 取代簽發點的授權裁決。主控台入口 SHALL 沿用既有帳號選擇流程（多帳號時先選帳號），建立型別為主控台的分頁；同一資產 SHALL 可同時開啟命令列分頁與主控台分頁。

主控台分頁 SHALL 為三區佈局：資料庫樹、語句編輯器、結果表；SHALL 提供資料庫切換、執行（含鍵盤快捷鍵）、執行選取範圍、**執行游標所在語句**（以游標位置切出的文字段送出；切分只決定送出範圍，不解析 SQL）、取消、匯出、樹重新整理；資料庫樹 SHALL 提供對已載入節點的本地篩選；結果截斷的提示 SHALL 附可操作指引（如何以查詢語法縮小範圍）；空態與零列態 SHALL 走共用空狀態元件並給下一步指引；語句錯誤 SHALL 就近呈現於編輯器下方而非全域提示；結果表 SHALL 分頁且分頁列常駐；結果狀態列 SHALL 顯示狀態、原因碼與可複製的事件識別，部分生效與結果未知 SHALL 以警示呈現；交易處於失敗或不可提交狀態時 SHALL 常駐顯示並指引執行 `ROLLBACK`；MSSQL 分頁 SHALL 首次呈現可關閉的批次終止符說明。

主控台分頁的連線狀態 SHALL 與其他分頁同語義：斷線或錯誤時分頁標灰並可頁內重連；重連 SHALL 以新票建立新的會話、保留編輯器文字、清空結果並明示。斷線時若有進行中的執行單位，分頁 SHALL 顯示該筆結果未知並連到其稽核紀錄，重連後 SHALL 以伺服端回報的終態更新，且使用者送出與該單位位元組相同的文字前 SHALL 先確認。主控台分頁 SHALL NOT 顯示文字終端的工具列項目（分享、片段、檔案管理、系統監控）。

自工作區主動關閉主控台分頁（單一關閉、關閉其他、關閉全部）時，若該分頁存在進行中的執行單位或未提交／失敗狀態的交易，SHALL 先以破壞性確認揭露後果（結果未知或交易未提交、關閉即結束會話、結束後可於會話詳情查看終態），確認後才關閉；無上述狀態時 SHALL 維持既有的直接關閉行為。關閉後各執行單位的終態 SHALL 可於會話詳情以事件識別查得（回填由伺服端完成，不依賴分頁存活）。自會話管理頁自助終止主控台會話 SHALL 走既有的通用確認，不揭露未收束狀態——該頁不持有分頁狀態，伺服端側的揭露屬另一設計；其終態同樣可於會話詳情以事件識別查得。

#### Scenario: 自側欄開啟主控台

- **WHEN** 使用者點擊 mysql 資產列的「主控台」入口
- **THEN** 開啟一個主控台分頁並啟用，樹載入可見資料庫，命令列分頁不受影響；點擊該列其他區域仍開啟命令列分頁

#### Scenario: 無 connect 授權者於簽發點被拒

- **WHEN** 存取狀態欄位缺席的回應中，一位無 connect 授權的使用者於側欄點擊某 mysql 資產的「主控台」入口
- **THEN** 連線票簽發點的閘序拒絕（與點擊整列開命令列的拒絕形狀一致），不建立會話、不解封憑證；持他人簽發的票直接呼叫主控台兌換點時同樣於閘序內被拒

#### Scenario: 側欄依存取狀態分化入口

- **WHEN** 側欄列出三個 mysql 資產：一個可連線、一個需申請存取、一個申請審核中
- **THEN** 第一個維持既有的開籤與主控台入口；第二個呈鎖定態、tooltip 指引至資產頁申請、點擊不發起簽發；第三個呈停用態並標示審核中；三者的呈現不影響伺服端授權裁決

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
