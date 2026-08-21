# session-timeout

## Purpose

會話閒置與最大時長的自動斷線與審計：閒置或超長會話自動收線並記錄斷線原因，滿足堡壘機合規（閒置 re-auth、會話超時）要求。
## Requirements
### Requirement: 閒置自動斷線
當會話閒置時間超過設定上限時，系統 SHALL 以**碼化控制幀**送出斷線原因至終端（機器 `code`＋zh fallback `data`，由前端依當前語言查譯後注入 xterm）、優雅收線、並以 idle_timeout 記錄斷線原因；後端 SHALL NOT 將斷線提示以散文直接寫入終端資料流。閒置上限為 0 時 SHALL 停用此檢查。閒置上限 SHALL 由安全政策管理（PCI 8.2.8 建議 ≤15 分鐘），既有環境變數僅作政策初始預設值。

協議族的「活動」定義不同（刻意的設計權衡）：
- **文字協議（SSH、k8s exec、資料庫 CLI）**：使用者輸入與伺服器下行輸出皆重置閒置計時。此為支援監看類會話（tail -f、top、journalctl -f、k8s logs——人在場盯著日誌流卻無鍵盤輸入）的真實維運需求；伺服器輸出無法區分「人在看」與「離開座位」，故不以純輸入計 idle。代價是閒置控制對持續輸出會話失效，此類長連線 SHALL 由「最大會話時長」絕對封頂治理（見下）。
- **圖形協議（RDP/VNC）**：僅客戶端輸入事件（滑鼠/鍵盤/剪貼簿/檔案傳輸）重置閒置計時；畫面更新 SHALL NOT 視為活動（圖形畫面永遠在動，以輸出計時等於永不逾時）。

#### Scenario: 使用者無互動即閒置斷線
- **WHEN** SSH 會話無伺服器輸出且使用者超過閒置上限未輸入
- **THEN** 終端顯示當前語言的閒置斷線訊息（由碼化幀查譯而來）、會話收線、session.end_reason 記為 idle_timeout

#### Scenario: 監看類會話由最大時長治理而非閒置
- **WHEN** 文字會話持續有伺服器輸出（如 tail -f）但使用者無輸入
- **THEN** 閒置計時被輸出重置而不觸發 idle_timeout；此會話改由最大會話時長封頂中斷（部署須設定 session_max_minutes）

#### Scenario: 圖形會話畫面更新不算活動
- **WHEN** RDP 會話中畫面持續更新（如時鐘）但使用者無滑鼠鍵盤輸入超過上限
- **THEN** 會話以 idle_timeout 收線

### Requirement: 最大會話時長
當會話總時長超過設定上限時，系統 SHALL 以**碼化控制幀**送出中斷原因至終端（機器 `code`＋zh fallback `data`，由前端依當前語言查譯後注入 xterm）、收線、並以 max_duration 記錄斷線原因。此判定以會話建立時刻錨定、與活動狀態無關——持續活躍（含持續伺服器輸出）的會話達上限同樣 SHALL 被中斷，作為閒置控制對監看類長連線失效時的絕對封頂。上限為 0 時 SHALL 停用此檢查。上限 SHALL 由安全政策管理（無 PCI 建議值，標示為部署自訂項），既有環境變數僅作政策初始預設值。安全政策頁 SHALL 在「已設閒置逾時但最大會話時長為 0（無封頂）」時標示風險，引導部署者為監看場景設定封頂。

#### Scenario: 達時長上限斷線
- **WHEN** 會話總時長超過最大上限（無論是否活躍、是否持續輸出）
- **THEN** 終端顯示當前語言的中斷訊息（由碼化幀查譯而來）、會話收線、session.end_reason 記為 max_duration

#### Scenario: 政策頁調整時長上限
- **WHEN** 管理員在安全政策頁修改最大會話時長
- **THEN** 新建會話以新值生效，變更入審計

#### Scenario: 政策頁標示未封頂風險
- **WHEN** 已設定協議會話閒置逾時但最大會話時長為 0
- **THEN** 政策頁顯示風險提示，說明監看類長連線不受閒置逾時治理、建議設定最長時長封頂

### Requirement: 斷線原因審計
會話結束 SHALL 記錄 end_reason（normal/idle_timeout/max_duration/admin_terminate），供連線管理與會話詳情呈現。

#### Scenario: 正常結束
- **WHEN** 使用者主動關閉會話
- **THEN** end_reason 記為 normal

#### Scenario: 稽核可見斷線原因
- **WHEN** 稽核員查看已結束會話
- **THEN** 可見該會話的 end_reason

### Requirement: 管理員終止與圖形逾時原因碼化
會話被管理員終止時，終端提示 SHALL 同樣以碼化控制幀送出（機器 `code`＋zh fallback），由前端查譯顯示，SHALL NOT 以散文直寫終端資料流。

圖形協議（guacd）的逾時中斷 SHALL 以既有機器碼為權威來源：後端 instruction 已攜帶機器碼，前端 `onerror` 處理 SHALL **按碼查譯**顯示當前語言訊息，隨附的中文 msg 降為 fallback，SHALL NOT 直接呈現該中文為主要文案。

上述變更 SHALL NOT 改動斷線原因審計語義：`end_reason`（normal／idle_timeout／max_duration／admin_terminate）的判定與記錄行為不變。

#### Scenario: 管理員終止提示依語言顯示
- **WHEN** 管理員終止一場 en-US 使用者的會話
- **THEN** 終端顯示英文的「連線已被終止」訊息（由碼化幀查譯），會話 end_reason 記為 admin_terminate

#### Scenario: 圖形逾時前端按碼查譯
- **WHEN** ja-JP 使用者的 RDP 會話因逾時被 guacd 中斷
- **THEN** 前端依 instruction 攜帶的機器碼顯示日文逾時說明；碼無譯文時才退回隨附中文 msg

#### Scenario: 斷線原因審計不變
- **WHEN** 上述任一碼化路徑觸發收線
- **THEN** session.end_reason 的值與寫入時機不因提示碼化而改變，稽核檢視不受影響

