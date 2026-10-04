# data-transfer-control

## Purpose

剪貼簿與檔案傳輸的資料進出控管：五個全域安全政策鍵、四類強制點（guacd 連線參數、SFTP HTTP 端點、guac tunnel 指令流、K8s 檔案端點）與其生效時機、被拒動作的審計語義，以及本控管的誠實邊界。

**交付範圍（期別）**：本規格只描述已交付的全域政策鍵層。per-authorization 傳輸放寬（`authorization_transfer_grants` 子表、`全域值 OR 匹配授權放寬` 的解析、接入通道維度的寫入面、授權放寬偏離計數與鑽取）**尚未實作**，其條文不收於本規格；「有效能力」的解析結果因此恆等於全域鍵值。

## Requirements

### Requirement: 資料傳輸控管政策鍵

系統 SHALL 提供五個資料傳輸控管政策鍵（皆為 bool，`true`＝允許、`false`＝禁止），出廠預設一律 `true`（沿安全政策既有易用取向通則）：

- `clipboard_send_enabled`：本機→遠端方向的剪貼簿傳輸（把內容送進受管資產）
- `clipboard_recv_enabled`：遠端→本機方向的剪貼簿傳輸（把內容自受管資產抄出）
- `file_upload_enabled`：檔案寫入受管資產（含建立目錄）
- `file_download_enabled`：檔案自受管資產取出
- `file_delete_enabled`：刪除受管資產上的檔案或空目錄

政策鍵語義 SHALL 一律為「啟用某能力」而非「停用某能力」；`disable-*` 形式的轉換 SHALL 僅發生在強制點內部，SHALL NOT 外露於政策鍵、API 或 UI。五鍵 SHALL 沿既有安全政策機制（讀寫 API、批次原子、非法值拒絕、變更入審計、穩定機器鍵、i18n 三語）。

五鍵 SHALL NOT 帶 PCI 建議值（`PCIValue` 留空）：其法源為電子支付機構相關基準（§16-6、§21-8(七)），非 PCI-DSS 條文。五鍵的**電支基準值一律為 `false`（禁止）**，SHALL 由電支建議值雙軌機制（尚未實作）承接為「一鍵套用基準值」的涵蓋對象。

系統 SHALL NOT 為任何角色提供繞過本組政策鍵的例外路徑：admin 不豁免、破窗票證不放行。admin 需要放寬時 SHALL 經修改政策鍵達成（該修改自帶審計軌跡）。有效能力的解析函式內 SHALL NOT 有任何角色分支。

#### Scenario: 出廠預設不改變既有行為
- **WHEN** 全新安裝後管理員未設定任何資料傳輸政策
- **THEN** 五鍵值皆為 `true`，剪貼簿與檔案傳輸行為與導入本控管前完全一致

#### Scenario: 政策變更入審計
- **WHEN** 管理員將 `file_download_enabled` 由 `true` 改為 `false` 並儲存
- **THEN** 儲存成功且審計記錄變更者、鍵名與舊值→新值

#### Scenario: admin 不豁免
- **WHEN** `file_download_enabled=false` 時 admin 呼叫檔案下載端點
- **THEN** 請求被拒（與一般使用者同語義），SHALL NOT 因角色為 admin 而放行

#### Scenario: 破窗票證不放行
- **WHEN** 使用者持有效破窗票證且 `file_upload_enabled=false` 時嘗試上傳
- **THEN** 上傳被拒；破窗票證僅影響段位存取政策，不影響資料傳輸控管

### Requirement: 剪貼簿控管的強制點與適用範圍

剪貼簿政策 SHALL 於圖形協議（RDP／VNC）的 guacd 連線參數組裝點強制：`clipboard_send_enabled=false` SHALL 送出 `disable-paste=true`、`clipboard_recv_enabled=false` SHALL 送出 `disable-copy=true`；兩參數 SHALL 於 RDP 與 VNC 兩分支皆顯式送出，SHALL NOT 依賴 guacd 預設值。

因該強制為連線參數，政策變更 SHALL NOT 影響進行中的連線；UI SHALL 於該組鍵旁明示「需重新連線才生效」，SHALL NOT 顯示或暗示變更已對進行中會話生效。

**適用範圍的誠實邊界**：剪貼簿政策 SHALL 明載為**僅對圖形協議具強制力**。文字終端（SSH、資料庫 CLI、K8s exec）的複製貼上在瀏覽器內完成，貼上內容進入連線後與逐字鍵盤輸入不可區分，伺服端無強制點；前端隱藏或停用按鈕 SHALL 明載為介面約束而非控制（瀏覽器開發者工具與自製客戶端一律繞得過），SHALL NOT 被描述為「已控管」。基於此，文字終端 SHALL NOT 以「貼上鈕變灰」等呈現暗示已被阻擋——看起來被擋卻擋不住，比不做更具誤導性。UI SHALL 於該組鍵標示適用協議。

被 guacd 擋下的剪貼簿嘗試發生於 guacd 行程內部，本系統無從觀測，故 SHALL NOT 產生審計事件；此限制 SHALL 明載，SHALL NOT 以「無事件即無嘗試」呈現。

#### Scenario: 禁止貼入遠端
- **WHEN** `clipboard_send_enabled=false` 且使用者新建 RDP 連線後嘗試把本機剪貼簿內容貼入遠端桌面
- **THEN** 內容未抵達遠端；連線參數含 `disable-paste=true`

#### Scenario: 禁止自遠端抄出
- **WHEN** `clipboard_recv_enabled=false` 且使用者在遠端桌面複製文字
- **THEN** 本機剪貼簿未取得該文字；連線參數含 `disable-copy=true`

#### Scenario: 進行中會話不受政策變更影響
- **WHEN** 使用者已建立 VNC 連線後管理員把 `clipboard_recv_enabled` 改為 `false`
- **THEN** 該進行中連線的剪貼簿行為不變；政策頁明示需重新連線才生效；使用者重新連線後新政策生效

#### Scenario: 文字終端標示適用範圍
- **WHEN** 管理員檢視資料傳輸管控區塊的剪貼簿兩鍵
- **THEN** 介面明示本組鍵僅對 RDP／VNC 具強制力，並說明文字終端的複製貼上無伺服端強制點

#### Scenario: 文字終端不做假控制
- **WHEN** 使用者於 SSH 終端頁面連線且剪貼簿鍵為 `false`
- **THEN** 終端不呈現「貼上已被停用」的假控制，剪貼簿限制的事實改由存取管控頁的邊界說明承載

### Requirement: 檔案傳輸控管的強制點

檔案傳輸政策 SHALL 於本系統**全部**檔案進出通道強制，逐次判定、即時生效（不需重新連線）：

- SFTP HTTP 檔案端點：上傳與建目錄受 `file_upload_enabled` 管制、下載受 `file_download_enabled` 管制、刪除受 `file_delete_enabled` 管制。列目錄 SHALL NOT 受本組鍵管制（列目錄不是資料傳輸，可見性由連線授權涵蓋）。建目錄的**判定鍵**為 `file_upload_enabled`，但其**審計動作**SHALL 保持 `file_mkdir`（兩者刻意不同源：判定回答「哪條政策擋的」，留痕回答「被擋的是哪個操作」）。
- guacd 圖形通道（RDP 磁碟重導、VNC SFTP 側車）：上傳 SHALL 於 tunnel 指令流層攔截（丟棄 `put` 及其後續 `blob`／`end`），下載方向的客戶端讀取指令（`get`）SHALL 同樣受 `file_download_enabled` 攔截。**tunnel 層攔截為主強制點**；guacd 的 `disable-upload`／`disable-download`／`sftp-disable-upload`／`sftp-disable-download` 參數 SHALL 作為縱深防禦一併送出，SHALL NOT 作為唯一強制點（其支援度隨 guacd 版本變動）。
- K8s 容器檔案進出（`kubectl cp`）：上傳受 `file_upload_enabled`、下載受 `file_download_enabled` 管制。
- 資料庫查詢主控台的結果集匯出端點：受 `file_download_enabled` 管制（結果集自受管資料庫取出即為資料離開系統）。判定鍵與審計動作皆為 `file_download`，審計列以細節欄標示來源為主控台結果與事件識別，SHALL NOT 新增第二套動作或資源分類。被拒、成功與**串流中止**（客戶端斷線、寫入或序列化錯誤：記已送出位元組數、已送出位元組的雜湊與受控原因碼）皆入審計（見「資料傳輸被拒的審計軌跡」）；主控台建立時 SHALL 向前端投影有效能力，使匯出入口的停用態反映伺服端強制點。

能力解析失敗時 SHALL fail-close（視為全禁）：傳輸控制的失敗方向必須是擋住而非放行。此與呈現面相反——能力查詢端點的解析失敗以全禁**呈現**，而非回傳錯誤讓 UI 退回「全部當可用」。

被拒的傳輸 SHALL 回可辨識的機器碼錯誤（註冊於錯誤碼目錄、前端查譯三語），SHALL NOT 回泛化的內部錯誤，SHALL NOT 靜默成功。guacd 通道被拒的**上傳** SHALL 回送客戶端可辨識的串流拒絕回應（`ack` 帶非零狀態碼），SHALL NOT 使客戶端串流無限等待；被拒的**下載** SHALL 為靜默丟棄且不回錯誤 `ack`——`get` 被攔時串流尚未由 guacd 的 `body` 指令建立，客戶端手上沒有可被 `ack` 指涉的 stream index，此不對稱 SHALL 明載，SHALL NOT 描述為「下載被拒也會通知客戶端」。

指令層的資料外帶（於終端內執行 `scp`、`curl`、`base64` 等）SHALL 明載為不在本組鍵範圍內——該面由指令阻斷能力負責。

#### Scenario: SFTP 上傳被拒
- **WHEN** `file_upload_enabled=false` 且使用者呼叫 SFTP 上傳端點
- **THEN** 請求被拒並回註冊的機器碼，遠端檔案系統未被寫入

#### Scenario: 建目錄併入上傳鍵
- **WHEN** `file_upload_enabled=false` 且使用者呼叫建目錄端點
- **THEN** 請求被拒（建目錄屬對遠端檔案系統的寫入），且審計動作為 `file_mkdir` 而非 `file_upload`

#### Scenario: 列目錄不受管制
- **WHEN** 五鍵全為 `false` 且使用者呼叫列目錄端點
- **THEN** 列目錄成功回傳（連線授權已涵蓋可見性）

#### Scenario: 圖形通道上傳被攔
- **WHEN** `file_upload_enabled=false` 且使用者經 RDP 重導磁碟上傳檔案
- **THEN** `put` 指令未轉發至 guacd、遠端未收到檔案，客戶端收到帶非零狀態碼的 `ack`

#### Scenario: 圖形通道下載被攔且無回應
- **WHEN** `file_download_enabled=false` 且客戶端送出 `get`
- **THEN** 指令未轉發至 guacd、無檔案內容回流，且客戶端不會收到錯誤 `ack`（僅無回應）

#### Scenario: 政策變更即時生效於檔案面
- **WHEN** 使用者於檔案管理面板操作期間，管理員把 `file_delete_enabled` 改為 `false`
- **THEN** 政策快取窗口過後該使用者的刪除請求即被拒，不需重新連線

#### Scenario: K8s 容器下載被拒
- **WHEN** `file_download_enabled=false` 且使用者呼叫 K8s 容器檔案下載端點
- **THEN** 請求被拒並回註冊的機器碼

#### Scenario: 主控台結果匯出被拒
- **WHEN** `file_download_enabled=false` 且使用者呼叫資料庫查詢主控台的結果匯出端點
- **THEN** 請求被拒並回註冊的機器碼、無 CSV 內容回流，audit_logs 產生 action=file_download、status=denied 且細節標示為主控台結果的紀錄；admin 同樣被拒

### Requirement: 資料傳輸被拒的審計軌跡

被政策拒絕的傳輸動作 SHALL 入審計，狀態為 `denied`，內容含操作者、資產、動作、目標路徑或檔名，以及拒絕來源（現行唯一來源為全域政策）。SHALL NOT 只在成功路徑留痕——「有沒有人試圖把資料帶出去」必須可由審計回答。

連線建立時 SHALL 於既有會話審計記錄中快照該次連線的五項有效傳輸能力。圖形連線 SHALL 記錄後端建線時採用的有效值；文字會話 SHALL 依「文字會話建立時留存傳輸政策快照」記錄當時政策及非強制邊界，不將剪貼簿政策值描述為伺服端強制能力。此快照供事後查閱，檔案操作仍逐次判定現行政策。

剪貼簿的拒絕 SHALL NOT 有審計（強制在 guacd 內部完成，見剪貼簿要求）；檔案面的拒絕 SHALL 有審計。此不對稱 SHALL 明載。

#### Scenario: 被拒的下載留痕
- **WHEN** `file_download_enabled=false` 時使用者嘗試下載檔案
- **THEN** audit_logs 產生 action=file_download、status=denied 的紀錄，含資產與遠端路徑

#### Scenario: 連線快照有效能力
- **WHEN** 使用者建立 RDP 連線
- **THEN** 該會話的審計紀錄含五項傳輸能力於連線當下的有效值

#### Scenario: 圖形通道被拒上傳留痕
- **WHEN** 圖形通道的 `put` 被 tunnel 層攔下
- **THEN** audit_logs 產生 status=denied 的 file_upload 紀錄

### Requirement: 資料傳輸控管的誠實邊界

下列限制 SHALL 明載於規格與使用者可見說明，SHALL NOT 以「已控管」概括：

1. 剪貼簿政策僅對圖形協議（RDP／VNC）具強制力；文字終端無伺服端強制點，前端按鈕呈現屬介面約束而非控制。
2. 被 guacd 擋下的剪貼簿嘗試無審計事件。
3. 會話分享的觀看者繼承該會話建立當下的連線參數，不另行判定其個人的傳輸能力。
4. K8s 容器檔案端點僅受本組傳輸鍵管制；其連線授權與段位存取政策的覆蓋缺口為已知邊界，不在本能力範圍內修復。
5. 終端內以指令外帶資料（`scp`／`curl`／編碼輸出等）不在本組鍵範圍，屬指令阻斷能力的職責——**關閉下載不等於資料出不去**。
6. 圖形通道被拒的下載為靜默丟棄，客戶端不會收到錯誤回應（僅上傳被拒有 `ack`）。
7. 資料庫查詢主控台的結果表呈現於瀏覽器畫面，可被選取複製或以開發者工具讀取，無伺服端強制點；受本組鍵管制的只有匯出端點。主控台介面 SHALL NOT 以停用複製之類的呈現暗示畫面內容已受控。

呈現面與強制面的失效方向 SHALL 為不對稱：瀏覽器能力查詢失敗時 UI SHALL 保留最近一次已知值並標記呈現可能過期；若從未取得有效能力，SHALL 沿既有可用呈現，不阻斷瀏覽，也不以預設值推論政策變更。伺服端強制點解析失敗仍 SHALL 一律**拒絕**（fail-close）。能力端點依既有契約成功回傳的全禁五鍵 SHALL 與瀏覽器查詢失敗區分，SHALL NOT 被當成失敗而丟棄。前端呈現 SHALL NOT 被視為強制點；繞過前端直呼端點 SHALL 仍被伺服端擋下。

#### Scenario: 誠實邊界可查
- **WHEN** 管理員或稽核人員檢視資料傳輸管控說明
- **THEN** 上述七項限制可被查閱，且無任何文案宣稱剪貼簿控管涵蓋文字終端或主控台畫面複製已受控

#### Scenario: 分享會話沿用原連線能力
- **WHEN** 一位被允許貼入遠端的使用者把 RDP 會話分享給另一位使用者
- **THEN** 觀看者於該會話內的剪貼簿能力等同該會話建立當下的連線參數，此行為已明載

#### Scenario: 繞過前端仍被擋
- **WHEN** 客戶端略過前端呈現為不可用的控件，直接呼叫傳輸端點
- **THEN** 伺服端閘門仍拒絕該請求

### Requirement: 圖形會話連線中告知剪貼簿政策差異

RDP／VNC 用戶端 SHALL 分離本次建線前成功查得的能力基準與連線期間查得的現行政策。剪貼簿送／收控件及自動同步的介面條件 SHALL 沿本次建線基準，SHALL NOT 因後續政策查詢或上傳入口刷新而改變。上傳入口刷新 SHALL 只更新檔案面；檔案操作仍由伺服端逐次判定。因上傳／下載方向在握手時寫入 guacd、放寬須重新連線才生效，圖形連線的上傳／下載呈現 SHALL 為建線基準與現行讀值皆允許時才可用：收緊 SHALL 立即呈現為停用，放寬 SHALL NOT 使建線時停用的控件變為可用。

用戶端 SHALL 於連線成功後立即以既有能力查詢介面檢查，並在連線期間每 30 秒排程檢查；視窗回焦及頁面恢復可見 SHALL 以 5 秒間隔合併節流補查，冷卻中的事件 SHALL 合併為一次尾端檢查，在途觀測 SHALL NOT 重疊。瀏覽器背景節流、政策快取與查詢耗時造成的延遲 SHALL 明示，不得宣稱即時推送。

當成功取得的剪貼簿兩鍵中至少一鍵與已知建線基準不同時，UI SHALL 在連線工具列下方、遠端畫布上方顯示非阻斷且可關閉的提示，說明現行查得的政策與連線前不同、「重新連線後套用」，並引導至既有重連操作。提示 SHALL NOT 斷言該線握手實際採用的精確能力、將變更描述為已對本線生效、搶走遠端輸入焦點或自動斷線／重連；僅檔案鍵變動 SHALL NOT 觸發剪貼簿重連提示。

查詢失敗或能力物件缺漏 SHALL 保留最近一次有效呈現與差異／關閉狀態，不得推論政策變更。若本次建線前未成功取得基準，後續讀值 SHALL NOT 冒充建線基準或據此宣稱政策已變；重新連線時才建立新基準。基準是前端建線前政策讀值，SHALL NOT 被描述為後端握手快照。

提示關閉 SHALL 僅抑制本輪相同的剪貼簿兩鍵組合，政策觀測 SHALL 繼續；另一個不同於基準的組合 SHALL 再提示。成功查得政策回到基準時 SHALL 清除提示及其關閉狀態。斷線、錯誤、卸載或重新建線 SHALL 停止舊觀測，丟棄舊輪晚到回應並重置本輪提示狀態。

#### Scenario: 定期查得剪貼簿政策不同
- **WHEN** RDP 連線的建線前基準已知，連線中成功查得 clipboard_send 或 clipboard_recv 與基準不同
- **THEN** 下一次檢查回應後顯示「重新連線後套用」提示，連線保持，剪貼簿控件與自動同步的介面條件沿原基準，不宣稱該線精確能力

#### Scenario: 回焦檢查與節流
- **WHEN** VNC 連線所在視窗回焦或頁面恢復可見，且使用者短時間反覆切換焦點
- **THEN** 用戶端依 5 秒節流補查，冷卻內的多個事件合併至一次尾端檢查，在途觀測不重疊，成功查得差異時顯示同一提示

#### Scenario: 上傳刷新不改剪貼簿控件
- **WHEN** 圖形連線建立後政策被收緊或放寬，使用者開啟上傳入口並刷新能力
- **THEN** 只有檔案面更新，剪貼簿控件及自動同步仍沿建線基準；後續定期或回焦查詢另行判定是否提示，檔案強制點仍逐次判定

#### Scenario: 只有檔案政策改變
- **WHEN** 成功查得的剪貼簿兩鍵與基準相同，只有檔案三鍵改變
- **THEN** 檔案呈現依建線基準與現行讀值的交集更新（收緊即停用、放寬不提前啟用），UI 不顯示剪貼簿需重新連線的提示

#### Scenario: 查詢失敗不假報差異
- **WHEN** 連線中的能力查詢逾時、失敗或回應缺少有效五鍵
- **THEN** 前值、原提示及其關閉狀態保留，不製造政策差異、不清除已知差異，也不更改本線剪貼簿控件

#### Scenario: 初次基準未知
- **WHEN** 建線前能力查詢失敗，連線後才成功取得現行政策
- **THEN** 用戶端保持基準未知，不以預設值或後到讀值推論建線時政策；不顯示政策已變提示，下次重新連線才重新取得基準

#### Scenario: 關閉提示後持續觀測
- **WHEN** 使用者關閉差異提示，後續檢查仍回相同的剪貼簿兩鍵組合
- **THEN** 提示保持關閉且觀測繼續；另一個不同於基準的組合出現時再次提示，回到基準時清除提示與關閉狀態

#### Scenario: 重新連線與晚到回應
- **WHEN** 使用者以既有入口重新連線，或元件已斷線、錯誤或卸載後舊查詢才返回
- **THEN** 舊排程與監聽已停止，舊回應不寫入新狀態；重新連線依新一輪預查建立基準，不沿用舊提示或關閉狀態

### Requirement: 文字會話建立時留存傳輸政策快照

SSH、所有受支援的資料庫 CLI 與資料庫查詢主控台 SHALL 在成功建立會話記錄後，於既有 create／session／success 審計分類的 details 留存一次五項傳輸政策快照；紀錄 SHALL 可對應操作者、資產、會話與協議，並區分 CLI 與查詢主控台。建線成功的判準 SHALL 沿既有會話建立流程，不以資料庫 CLI 啟動推論遠端登入已驗證。

快照 SHALL 包含 clipboard_send、clipboard_recv、file_upload、file_download、file_delete 五個 bool，以及 `clipboard_enforced=false` 標記，明示文字協議的剪貼簿無伺服端強制點。解析成功 SHALL 以 `transfer_capabilities_resolved=true` 標明；若解析未成功，SHALL 記錄未成功標記與保守零值，不得將其描述為已知政策。後續政策變更 SHALL NOT 覆寫歷史快照；檔案端點仍於操作時重驗政策。此紀錄 SHALL NOT 暗示終端指令、文字複製貼上或主控台結果畫面受到五鍵強制。

建線或會話建立失敗 SHALL NOT 產生成功快照。快照 SHALL 沿既有非同步審計處理，SHALL NOT 新增審計 action／cause、資料表或以現行政策回填歷史連線；此要求不改變會話建立的既有失敗語義。

#### Scenario: SSH 成功建線留五鍵
- **WHEN** SSH 會話成功建立且傳輸政策解析成功
- **THEN** 該會話恰有一筆傳輸快照審計，含當時五鍵、操作者／資產／會話識別、解析成功標記與 clipboard_enforced=false，剪貼簿值不被解釋為文字複製貼上的強制能力

#### Scenario: 資料庫 CLI 與主控台都留存
- **WHEN** 使用者分別建立受支援的資料庫 CLI 與查詢主控台會話
- **THEN** 兩者均有自己的五鍵快照，details 可區分會話型態並標記剪貼簿非強制，主控台原有 file_download 呈現不代替這筆審計

#### Scenario: 歷史值不隨政策覆寫
- **WHEN** 文字會話建立並留存快照後管理員改變傳輸政策，再建立另一個會話
- **THEN** 原快照保持不變，新會話寫當時的新值，檔案操作按現行政策判定，歷史缺少快照的會話不被回填

#### Scenario: 建立失敗不留下成功快照
- **WHEN** 連線流程被拒、連線資源建立失敗或會話記錄無法建立
- **THEN** 不產生宣稱已成功建立該會話的傳輸快照，既有失敗回應與審計保持原語義
