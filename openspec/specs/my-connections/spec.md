# my-connections

## Purpose

一般使用者的自助連線紀錄視圖：在 session 檢視收斂為 admin/auditor 職能（最小權限基線）之後，為 user 保留「看自己連了什麼」的合法需求——owner-scoped、資料最小化的精簡自助端點與前端頁，不含指令、錄影等任何監管內容。形態為獨立的 per-user 端點＋server 端 owner 過濾，DTO 為白名單式精簡投影而非 session 本體。
## Requirements
### Requirement: 自助連線紀錄檢視
系統 SHALL 提供一般使用者（任何已認證帳號）一個自助端點，僅回傳呼叫者**自己**的連線 session。服務層 SHALL 先固定 owner 條件（以 JWT user_id 過濾）再套其他允許篩選，SHALL NOT 接受由 client 傳入的 user_id 覆蓋擁有者範圍。回傳內容 SHALL 為獨立精簡 DTO（不得回傳 `model.Session` 本體），僅含：session 識別碼（`id`，供自助終止指定目標）、資產名稱、協議、連線時間（`connected_at`＝session `StartTime`）、時長（`duration_seconds`）、狀態（機器值 `active`/`ended`）。DTO SHALL NOT 含操作指令、錄影、憑證、client IP、目標主機或 K8s 快照等任何欄位（資料面即不可得）。

端點 SHALL 支援分頁 `page`／`page_size`（`page_size` 上限 100）並以穩定排序 `start_time DESC, id DESC` 回傳，SHALL NOT 一次回傳全部歷史。時長語義：狀態 `ended`（含 disconnected 與 closed）SHALL 用持久化 `Duration`；狀態 `active` 的 `duration_seconds` SHALL 為 `floor(now - StartTime)`，且 SHALL 防時鐘異常回負值（負值夾為 0）。

#### Scenario: 只看得到自己的連線
- **WHEN** user 角色帳號呼叫自助連線端點
- **THEN** 僅回傳該帳號自己的 session，不含任何他人的紀錄

#### Scenario: 精簡欄位不洩漏敏感內容
- **WHEN** 自助端點回傳連線紀錄
- **THEN** 每筆僅含 id、資產名、協議、connected_at、duration_seconds、狀態；回應中不存在指令、錄影連結、密碼、client IP、主機位址或 K8s 快照欄位

#### Scenario: 無法以參數操縱越權
- **WHEN** user 角色帳號在自助端點請求附帶 `user_id` 或其他他人識別參數
- **THEN** 參數被忽略，回應仍僅限呼叫者自己的 session

#### Scenario: 分頁與穩定排序
- **WHEN** 使用者有大量歷史連線且以預設或指定 `page_size` 請求
- **THEN** 回應依 `start_time DESC, id DESC` 分頁；`page_size` 超過 100 被夾為 100，不會一次回傳全部

#### Scenario: 進行中與已結束的時長契約
- **WHEN** 使用者有一筆進行中（active）與一筆已結束（closed/disconnected）的 session
- **THEN** active 狀態回機器值 `active` 且 `duration_seconds = floor(now - StartTime)`（不為負）；ended 狀態回機器值 `ended` 且 `duration_seconds` 為持久化 `Duration`（前端將 active/ended 顯示為「進行中/已結束」）

### Requirement: 自助頁前端入口
前端 SHALL 為一般 user 提供「我的連線」頁與導覽入口，僅顯示自助端點的精簡欄位；該入口 SHALL NOT 對 admin/auditor 取代其完整 session 管理頁。前端 SHALL NOT 於此頁提供任何指令檢視或錄影播放入口。

#### Scenario: 一般 user 見自助入口
- **WHEN** user 角色登入
- **THEN** 導覽顯示「我的連線」，點入呈現自己的連線紀錄（資產/協議/時間/時長/狀態），無指令與錄影入口

#### Scenario: admin 沿用完整管理頁
- **WHEN** admin 或 auditor 登入
- **THEN** 沿用完整「連線管理」頁（含指令與錄影），不被自助頁取代

### Requirement: 自助終止進行中連線
系統 SHALL 提供一般使用者（任何已認證帳號）一個自助終止端點，允許呼叫者終止**自己的**進行中（active）session。服務層 SHALL 以 `WHERE id = ? AND user_id = 呼叫者 JWT user_id` 取回目標 session——他人的 session 與不存在的 session SHALL 一律回 404（不洩漏他人 session 的存在性）；狀態非 active 者 SHALL 回 400。終止 SHALL 複用既有終止鏈：更新持久化狀態並實際斷開對應的 WebSocket 連線，`end_reason` SHALL 記為 `user_terminate`。端點 SHALL 僅要求認證（owner 檢查即授權），SHALL NOT 依賴任何 RBAC 權限判定——其安全語義由 owner 檢查單獨承擔，SHALL NOT 隨權限組態變動。終止操作 SHALL 進入操作審計（操作者＝會話擁有者本人）。

#### Scenario: 終止自己的進行中連線
- **WHEN** user 角色帳號對自己的 active session 呼叫自助終止端點
- **THEN** 該 session 的 WebSocket 被實際斷開、狀態收斂為已結束、`end_reason` 記為 `user_terminate`，且審計日誌留有本人終止紀錄

#### Scenario: 無法終止他人的連線
- **WHEN** user 角色帳號以他人的 session id 呼叫自助終止端點
- **THEN** 回應 404，與不存在的 session id 無可區分，目標 session 不受影響

#### Scenario: 已結束的連線不可重複終止
- **WHEN** 使用者對狀態非 active 的自己 session 呼叫自助終止端點
- **THEN** 回應 400，持久化紀錄不變

#### Scenario: 無 RBAC 權限者仍可自助終止
- **WHEN** 不具任何 session 相關 RBAC 權限的一般使用者呼叫自助終止端點終止自己的 session
- **THEN** 終止成功；owner 檢查與 404/400 語義完全不變（授權由 owner 檢查單獨承擔）

### Requirement: 自助頁終止入口
前端「我的連線」頁 SHALL 僅對狀態為進行中（active）的列提供「終止」操作，操作 SHALL 有二次確認，成功後 SHALL 刷新列表使狀態收斂可見。已結束的列 SHALL NOT 顯示終止操作。終止請求因競態失敗（連線已自行結束）時 SHALL 以可讀訊息提示並刷新列表，SHALL NOT 呈現為未處理錯誤。

#### Scenario: active 列可終止、ended 列不可
- **WHEN** 一般 user 開啟「我的連線」頁且同時有進行中與已結束的紀錄
- **THEN** 僅進行中的列顯示「終止」按鈕，已結束的列無此操作

#### Scenario: 二次確認後終止並刷新
- **WHEN** 使用者點擊「終止」並在確認框中確認
- **THEN** 發出終止請求，成功後顯示成功訊息且列表刷新、該列狀態轉為已結束

#### Scenario: 競態下的優雅處理
- **WHEN** 使用者確認終止時該連線恰已自行斷開（後端回 400）
- **THEN** 頁面顯示可讀提示並刷新列表，不出現未處理錯誤

