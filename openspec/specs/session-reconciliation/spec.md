# session-reconciliation

## Purpose

session 持久化狀態與實際連線的一致性收斂：確保 DB 中 status=active 的 session 始終對應一條真實活連線。連線層的閒置/最大時長逾時（session-timeout）只治理「有活連線」的會話，無法收斂後端重啟殘留與純 DB 孤兒列——這些會永久卡 active，使「我的連線」顯示假進行中、自助終止對它們失效。本能力以啟動清掃＋週期孤兒偵測雙機制補齊。單一後端實例前提（多實例部署需重設計）。
## Requirements
### Requirement: 啟動狀態收斂
後端啟動時，系統 SHALL 將持久化狀態為 active 的全部殘留 session 一次收斂為已結束，`end_reason` SHALL 記為 `backend_restart`，並補寫 `end_time` 與時長。此收斂 SHALL 在開始受理新連線前完成（單一後端實例前提：重啟後不可能存在存活連線，無誤殺面）。

#### Scenario: 重啟後殘留 active 被收斂
- **WHEN** 後端在存在 active session 時重啟
- **THEN** 啟動後這些 session 全部轉為已結束、`end_reason=backend_restart`，「我的連線」與 session 管理頁不再顯示為進行中

#### Scenario: 無殘留時啟動不受影響
- **WHEN** 後端啟動時 DB 無 active session
- **THEN** 啟動流程正常完成，無任何 session 被改動

### Requirement: 孤兒會話偵測
系統 SHALL 以週期排程比對持久化狀態與連線註冊表（ConnectionRegistry）：狀態為 active、建立時間已超過寬限期、且註冊表中無對應活連線的 session，SHALL 收斂為已結束且 `end_reason` 記為 `orphaned`。寬限期 SHALL 覆蓋「持久化先寫 active、註冊表後掛載」的建線短窗與正常收線的反向短窗，SHALL NOT 誤殺建線中或收線中的正常會話。每批掃描 SHALL 為有界工作量（keyset 分頁、單批查詢＋記憶體比對），單輪 SHALL 掃至候選集清空（正確性優先），且排程層 SHALL 防重入避免前一輪未竟時疊掃同批資料。

#### Scenario: 純 DB 孤兒列被收斂
- **WHEN** 存在一筆無任何實際連線對應的 active session（如手工植入或異常殘留）且已超過寬限期
- **THEN** 下一輪排程將其收斂為已結束、`end_reason=orphaned`

#### Scenario: 建線中的正常會話不被誤殺
- **WHEN** 一筆 session 已寫入 active 但尚在寬限期內（WebSocket 註冊可能尚未完成）
- **THEN** 排程跳過該筆，不做任何改動

#### Scenario: 活連線不受排程影響
- **WHEN** active session 在註冊表中有對應活連線
- **THEN** 排程不改動該筆，連線持續正常

### Requirement: 連線註冊完整性
任何建立 active session 持久化紀錄的連線路徑，SHALL 在連線建立後將其 WebSocket 註冊至 ConnectionRegistry，並在收線時反註冊。此為孤兒偵測正確性的前提：未註冊的活連線會被誤判為孤兒。新增協議或連線路徑時 SHALL 隨附此註冊。

#### Scenario: 既有兩個建線點皆註冊
- **WHEN** 經 SSH 代理或圖形代理（RDP/VNC）建立連線
- **THEN** session 於註冊表中可查得對應活連線，孤兒偵測不誤判

#### Scenario: 正常收線後反註冊
- **WHEN** 連線正常結束
- **THEN** 註冊表中該 session 的登記被移除，且持久化狀態同步收斂為已結束

### Requirement: 強制收線的協議正確性與執行緒安全
連線註冊表的強制收線 SHALL 為 per-connection 的執行緒安全關閉：關閉通知的寫入 SHALL 與該連線資料橋接的寫入共享同一把寫鎖（禁止對底層 WebSocket 併發寫）；關閉通知 SHALL 按連線協議正確編碼（文字終端走其訊息協議、圖形通道走 Guacamole disconnect 指令），SHALL NOT 向文字終端連線發送 Guacamole 指令。既有 Terminate／帳號停用收線／孤兒收斂路徑的對外語義 SHALL 不變。

#### Scenario: 併發收線不 panic
- **WHEN** 資料橋接持續寫入輸出的同時，管理路徑對同一會話觸發強制收線
- **THEN** 關閉通知與資料寫入串行完成，行程不 panic，會話正常落終態

#### Scenario: 文字終端收到正確協議通知
- **WHEN** SSH 文字會話被強制終止
- **THEN** 前端收到該通道自身協議的斷線通知（非 Guacamole 指令），並正常顯示會話結束

### Requirement: 撤銷收線斷線原因
因臨時授權撤銷（`access_revoke_disconnect=true`）而終止的會話，`end_reason` SHALL 記為 `revoked`，與既有斷線原因（normal/idle_timeout/max_duration/admin_terminate/user_terminate/backend_restart/orphaned）並列可查。

#### Scenario: 撤銷收線落原因
- **WHEN** 政策開啟且票證被撤，進行中會話被終止
- **THEN** 該會話 `end_reason='revoked'`，會話列表與自助連線頁可見此原因

### Requirement: 正常關閉的收線即時性

連線因客戶端送出協議層正常關閉訊號而結束時，系統 SHALL 於該訊號被讀到後立即進入收線路徑：
關閉底層連線、反註冊連線註冊表、將持久化狀態收斂為已結束。

收線的觸發 SHALL NOT 依賴保活探測、閒置逾時或任何週期性計時器——以計時器為觸發者，其滯留
上界等於該計時器週期，而該窗內持久化狀態與連線註冊表**同時**仍顯示會話進行中，使並發統計
系統性高估；並發數字是容量判斷的依據，系統性偏高的數字比沒有數字更難察覺。

此要求 SHALL 對全部代理協議一致成立（文字終端、資料庫 CLI、K8s exec、圖形 RDP/VNC）。
雙向資料泵中任一方向結束時，SHALL 觸發同一個冪等收線函式，使**正常結束與異常結束走同一條
收線路徑**；正常結束回傳「無錯誤」SHALL NOT 因此略過收線。

異常關閉路徑的既有行為 SHALL NOT 因本要求退化：客戶端直接斷線、目標端或協議伺服器故障、
逾時觸發的強制收線、管理端強制收線，其收線時機與對外語義 SHALL 維持不變。半開連線
（無任何訊號抵達）SHALL 仍由保活探測與讀取逾時收斂——本要求限縮的是計時器作為**正常關閉**
的觸發者，不移除其作為**無訊號情境**兜底的職責。

收線提早 SHALL NOT 改變斷線原因的判定：正常關閉仍記為 `normal`，逾時與強制收線仍記其既有原因。

#### Scenario: 圖形會話送出正常關閉訊號後立即收線

- **WHEN** RDP/VNC 客戶端送出 WebSocket 正常關閉訊號（關閉分頁的真實路徑）
- **THEN** 該會話於一秒內反註冊、持久化狀態轉為已結束且 `end_reason='normal'`，
  SHALL NOT 等待下一次保活探測

#### Scenario: 文字會話維持既有零延遲收線

- **WHEN** SSH／資料庫 CLI／K8s exec 會話的客戶端送出正常關閉訊號
- **THEN** 收線行為與本要求導入前逐字相同（既有實作已符合），無新增延遲

#### Scenario: 異常斷線仍立即收線

- **WHEN** 客戶端未送正常關閉訊號而直接斷線，或目標端／協議伺服器故障
- **THEN** 收線於錯誤被偵測到時立即發生，時機與斷線原因與本要求導入前相同

#### Scenario: 無訊號的半開連線仍由保活收斂

- **WHEN** 網路中斷造成半開連線，兩個資料方向皆無訊號抵達
- **THEN** 保活探測失敗或讀取逾時仍會收線，該兜底路徑不因本要求而失效

#### Scenario: 並發統計不含已收線會話

- **WHEN** 圖形會話正常關閉後立即查詢連線註冊表計數
- **THEN** 該會話已不計入；持久化狀態來源的並發統計於下一輪刷新亦不計入，
  其落後上界為指標刷新週期，SHALL NOT 額外疊加保活週期
