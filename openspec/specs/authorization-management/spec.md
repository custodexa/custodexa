# authorization-management

## Purpose

授權管理頁面的完整行為：全量列表與篩選、有效性三態與來源可辨識、有效權限雙視角與溯因、ticket 授權撤銷收斂與裸刪守門。
## Requirements
### Requirement: 授權列表全量模式與誠實呈現
`GET /api/v1/authorizations` SHALL 支援零篩選的全量列表模式（回傳全部授權，依既有分頁參數分頁）；同時保留 `user_id`/`user_group_id`/`asset_id`/`node_id` 單維篩選，多於一個維度 SHALL 回 400。`node_id` 篩選 SHALL 採涵蓋盤點語義：回傳授權有效範圍與該節點子樹有交集的記錄——(1) 客體為節點且位於目標節點之祖先鏈、自身或後代者；(2) 客體為節點且其子樹內存在同時掛載於目標節點子樹之資產者（多歸屬橋接）；(3) 客體為資產且該資產掛載於目標節點子樹內者。每筆授權記錄於結果中 SHALL 僅出現一次。前端授權頁初載 SHALL 顯示全量列表；列表載入失敗 SHALL 呈現錯誤訊息，SHALL NOT 以空狀態（「尚無授權記錄」）偽裝錯誤。分頁 SHALL 真實生效（頁碼與每頁筆數送達伺服端並反映於回應）；變更篩選條件、快速篩選或每頁筆數 SHALL 重設頁碼至第 1 頁。節點篩選 SHALL 於 COUNT 與分頁前生效，並可與有效性/來源快速篩選疊加。

#### Scenario: 初載全量
- **WHEN** admin 進入授權頁（不帶任何篩選）
- **THEN** 列表顯示全部授權（第一頁）與正確總數，無錯誤

#### Scenario: 換頁真實生效
- **WHEN** 授權總數超過每頁筆數且 admin 切換至第 2 頁
- **THEN** 回應為第 2 頁的不同記錄（非重複第一頁）

#### Scenario: 篩選變更重設頁碼
- **WHEN** admin 位於第 5 頁時套用一個結果僅一頁的篩選
- **THEN** 頁碼重設為 1 並顯示結果，不出現「伺服端正確回空第 5 頁」造成的偽空狀態

#### Scenario: 載入失敗誠實呈現
- **WHEN** 列表請求失敗（如 5xx）
- **THEN** 頁面顯示錯誤提示，不顯示「尚無授權記錄」空狀態

#### Scenario: 多維篩選拒絕
- **WHEN** 請求同時帶 `user_id` 與 `asset_id`（或任兩個維度，含 `node_id`）
- **THEN** 回 400

#### Scenario: 節點涵蓋盤點
- **WHEN** 節點樹為 root→A→B，授權分別掛 root（節點客體）、B（節點客體）、與掛載於 B 之資產 X（資產客體），admin 以節點 A 篩選
- **THEN** 三筆均回傳（root 為祖先涵蓋、B 為後代、X 為子樹內資產客體），且總數與分頁反映篩選後結果

#### Scenario: 多歸屬橋接命中
- **WHEN** 資產 X 同時掛載於節點 A 子樹與節點 C 子樹（A 與 C 無祖先/後代關係），一筆授權以節點 C 為客體，admin 以節點 A 篩選
- **THEN** 該授權出現於結果（其有效範圍涵蓋 A 子樹內的 X），且僅出現一次

#### Scenario: 範圍外排除
- **WHEN** 另有授權掛於與 A 無祖先/後代關係的節點 C（C 子樹內所有資產均僅掛載於 C、無多歸屬），或掛於僅掛載於 C 之資產，admin 以節點 A 篩選
- **THEN** 該筆不出現於結果

#### Scenario: 節點與快速篩選疊加
- **WHEN** admin 以節點 A 篩選並同時套用「已過期」快速篩選
- **THEN** 僅回傳涵蓋 A 範圍且已過期的授權，總數一致

### Requirement: 授權有效性與來源可辨識
授權列表序列化 SHALL 包含 `source`、`date_start`、`date_expired` 與伺服端計算的 `validity_state`（三態：`scheduled` 未達起始／`active` 時窗內／`expired` 已過期，時窗語義與權限解析一致）；`source='ticket'` 的記錄 SHALL 附其申請單 `request_id`（經 `access_requests.authorization_id` 批量反查，無單者省略）與 `revocable`（有關聯申請單且票證於時窗內為 true）。列表 SHALL 支援伺服端篩選參數 `validity`（active/scheduled/expired）與 `source`（manual/ticket），於 COUNT 與分頁前生效；前端快速篩選 SHALL 對應伺服端參數（非僅過濾當頁）。前端 SHALL 以可辨識樣式區分：ticket 記錄帶「臨時」標籤與到期時間、非 active 記錄整列灰化（`scheduled` 標「未生效」、`expired` 標「已到期」，不得混稱）、到期時間依剩餘天數分級著色。引用已刪除實體（資產/節點/使用者/群組）的記錄 SHALL 標示為已失效客體或主體，不得出現雙側空白的不可辨識列。

#### Scenario: 過期臨時授權可辨識
- **WHEN** 一筆 ticket 授權的 `date_expired` 已過
- **THEN** 列表該筆 `validity_state=expired`、`revocable=false`、帶「臨時」標籤與「已到期」標示、整列灰化，與有效常設授權視覺可分

#### Scenario: 未生效不混稱已過期
- **WHEN** 一筆授權 `date_start` 於未來
- **THEN** 該筆 `validity_state=scheduled`、顯示「未生效」，且不出現於 `validity=expired` 的篩選結果

#### Scenario: ticket 反查申請單
- **WHEN** 列表含一筆由申請單核准產生的授權
- **THEN** 該筆回應含 `request_id`；時窗內者 `revocable=true`

#### Scenario: 快速篩選跨頁正確
- **WHEN** 過期記錄分佈於多頁，admin 選「已過期」快速篩選
- **THEN** 伺服端以 `validity=expired` 過濾後回傳全部過期記錄的第一頁與正確總數（不漏報其他頁的過期記錄）

### Requirement: 有效權限主體視角
系統 SHALL 提供 `GET /api/v1/authorizations/effective-assets?user_id=`（admin only）：以顯式 subject 參數解析（SHALL NOT 自 request context 推導 subject 角色），回傳該使用者於時窗內實際可及的資產清單與溯因，來源集合為：`direct_user`、`user_group`、`asset_node`（節點含子樹×直授）、`user_group_asset_node`（節點含子樹×群組）、`approver_scope`（審核範圍隱含 view）、`role_override`（admin 角色隱含全可及【含 connect】；auditor 角色隱含 view 可及【檢視全部資產，connect 需顯式授權】）。授權記錄來源含 `authorization_id` 與時窗；非記錄來源（approver_scope/role_override）`authorization_id` 為空並標示來源。全部來源的聯集 SHALL 與執行期權限判定（資產列表／connect 檢查）對同一使用者的可及集合一致；auditor 的聯集 SHALL 為 view 可及全部資產，加其顯式 connect 授權記錄。

#### Scenario: 一般使用者與執行期一致
- **WHEN** 主體為無特權角色的一般使用者 U，admin 查 U 的主體視角
- **THEN** 回傳集合與 U 實際資產列表／連線判定一致，每筆含溯因

#### Scenario: 群組繼承可見
- **WHEN** 使用者 U 無直授但所屬群組 G 對資產 A 有 connect 授權，admin 查 U 的主體視角
- **THEN** A 出現於清單，溯因含 `user_group` 路徑（經由 G）與該授權 id

#### Scenario: 節點子樹展開可見
- **WHEN** U 經節點 N（含子樹）授權覆蓋資產 A，admin 查 U 的主體視角
- **THEN** A 出現於清單，溯因含節點 N 全路徑

#### Scenario: 過期路徑不計入
- **WHEN** U 對 A 僅有一筆已過期 ticket 授權
- **THEN** A 不出現於 U 的主體視角清單

#### Scenario: 特權主體標示角色隱含
- **WHEN** 主體為 admin 或 auditor 角色的使用者
- **THEN** 回應帶 `role_override` 標示（UI 摘要橫幅：admin 呈現「角色隱含全部資產」、auditor 呈現「角色隱含檢視全部資產」，不逐列展開），同時仍列出其顯式授權記錄；auditor 的 `role_override` 為 view 等級，其 connect 可及僅來自顯式授權記錄

#### Scenario: auditor 主體視角與執行期一致
- **WHEN** auditor 使用者 A 對資產 X 有顯式 connect 授權、對其餘 open 資產無顯式授權，admin 查 A 的主體視角
- **THEN** 全部資產以 `role_override`（view 等級）呈現可檢視；X 另帶顯式 connect 授權溯因；此集合與 A 的執行期判定一致（僅 X 可連線）

#### Scenario: approver 範圍隱含可視
- **WHEN** 主體為 approver 且審核範圍覆蓋資產 A、無任何對 A 的授權記錄
- **THEN** A 以 `approver_scope` 來源出現（view 等級、無 authorization_id），與其實際資產列表一致

### Requirement: 有效權限客體視角
系統 SHALL 提供 `GET /api/v1/authorizations/effective-users?asset_id=`（admin only）：回傳時窗內經授權記錄路徑（含群組主體展開至成員）與 `approver_scope` 實際可及該資產的使用者清單，每人含最高權限等級與溯因路徑列表；回應 SHALL 另帶 `role_override` 標示說明 admin 角色帳號隱含全可及、auditor 角色帳號隱含 view 可及（不逐人列舉）。

#### Scenario: 群組成員展開
- **WHEN** 群組 G（成員 U1、U2）對資產 A 有授權，admin 查 A 的客體視角
- **THEN** U1、U2 均出現，溯因標示經由群組 G

#### Scenario: 祖先節點授權命中
- **WHEN** U 經 A 的祖先節點授權可及 A，admin 查 A 的客體視角
- **THEN** U 出現，溯因含該節點全路徑

#### Scenario: 角色隱含以摘要標示
- **WHEN** admin 查任一資產的客體視角
- **THEN** 回應含 `role_override` 摘要標示（admin 隱含全可及、auditor 隱含 view 可及），使用者清單不逐人列舉特權角色帳號

### Requirement: ticket 授權撤銷收斂
`DELETE /api/v1/authorizations/:id` 對 `source='ticket'` 且存在關聯申請單的授權 SHALL 拒絕並回 409（service 以 exported sentinel error 表達、handler 以 `errors.Is` 映射，不得落入 500）；ticket 來源但反查無申請單的孤兒記錄 SHALL 放行刪除並記審計。前端對 `revocable=true` 的 ticket 記錄 SHALL 以「撤銷」動作取代刪除，呼叫既有申請單撤銷 API（資格判定、票證附註、`access_revoke_disconnect` 斷線聯動全數沿用）；對 `revocable=false` 的 ticket 記錄（已過期/未生效）SHALL NOT 提供撤銷或刪除動作，以唯讀狀態留存為審計證據（到期與撤銷語義分離）。

#### Scenario: 裸刪被擋且狀態碼正確
- **WHEN** admin 對一筆有關聯申請單的 ticket 授權呼叫 DELETE
- **THEN** 回 409（非 500），記錄未被刪除

#### Scenario: 撤銷入口走申請單流
- **WHEN** admin 在授權頁對 `revocable=true` 的 ticket 記錄按「撤銷」並確認
- **THEN** 經申請單撤銷 API 生效：票證軟刪＋申請單附註撤銷資訊；若 `access_revoke_disconnect=true` 同步收線

#### Scenario: 過期票證唯讀留存
- **WHEN** 一筆 ticket 授權已過期（有關聯申請單）
- **THEN** 列表該筆無撤銷與刪除動作、標示「已到期」；DELETE API 呼叫仍回 409；記錄於「已過期」篩選可見（審計留存）

#### Scenario: 孤兒 ticket 可刪
- **WHEN** 一筆 ticket 授權反查無申請單，admin 呼叫 DELETE
- **THEN** 刪除成功並入審計

### Requirement: 授權客體術語與主體標示一致
授權頁 SHALL 以「節點」術語標示節點客體（含全路徑與含子樹提示），SHALL NOT 使用「分組」；主體欄 SHALL 對使用者與群組主體提供對稱的型別標示。

#### Scenario: 節點客體標示
- **WHEN** 列表含一筆節點客體授權
- **THEN** 該筆客體顯示「節點」標籤＋節點全路徑，刪除確認文案同用「節點」

#### Scenario: 主體標示對稱
- **WHEN** 列表同時含使用者主體與群組主體記錄
- **THEN** 兩者各有型別標籤，無一方裸文字

### Requirement: 批量授權資產挑選輔助
批量授權精靈的「逐資產」模式 SHALL 提供伺服端過濾的挑選輔助：關鍵字搜尋、節點過濾（含子樹）與標籤篩選（多值 AND），三者 SHALL 可疊加；過濾條件變更 SHALL 重新向伺服端取列表且 SHALL 保持既有勾選（跨篩選不丟失）；併發回應 SHALL 以最新請求為準（先發出的回應晚到 SHALL NOT 覆蓋較新結果）。結果總數超過單次載入上限時 SHALL 顯示截斷警示與總數，SHALL NOT 靜默截斷。重新開啟精靈 SHALL 清空上次會話的勾選與篩選。標籤選項 SHALL 來自標籤清單端點。

#### Scenario: 按節點收窄
- **WHEN** admin 於逐資產步驟選擇節點「生產環境」（含子樹）
- **THEN** 列表僅顯示該節點子樹內的資產

#### Scenario: 按標籤篩選
- **WHEN** admin 選擇標籤「資料庫」
- **THEN** 列表僅顯示含該標籤（整詞）的資產

#### Scenario: 篩選切換保持勾選
- **WHEN** admin 勾選 2 筆資產後切換節點過濾使該 2 筆不在當前列表，再送出授權
- **THEN** 已勾選的 2 筆仍計入授權對象（勾選未因篩選切換而丟失）

#### Scenario: 截斷誠實呈現
- **WHEN** 篩選結果總數超過單次載入上限（如 1000）
- **THEN** 列表顯示「僅載入前 1000 筆（共 N 筆）」警示，提示以篩選收窄

#### Scenario: 舊回應不覆蓋新結果
- **WHEN** admin 快速連續變更篩選 A→B，A 的回應晚於 B 到達
- **THEN** 畫面顯示 B 的結果（A 的回應被棄用），loading 狀態與最新請求一致

#### Scenario: 重開精靈不殘留勾選
- **WHEN** admin 於精靈勾選資產後關閉精靈，再重新開啟
- **THEN** 勾選與節點/標籤篩選均為空（上次會話不殘留，避免溢授）

### Requirement: 角色權限短路的執行期語義
執行期資產權限判定（`AssetAuthorizationService.CheckPermission`）SHALL 依角色套用最小必要的自動放行：`admin` 角色 SHALL 自動獲得全部權限（含 `connect`）；`auditor` 角色 SHALL 僅自動獲得非連線權限（`view` 類），SHALL NOT 因角色自動獲得 `connect`。auditor 對某資產的 `connect` 判定 SHALL 落正常授權查詢，僅在該使用者對該資產有時窗內顯式 connect 授權時為真。無特權角色使用者 SHALL 不受角色短路影響，一律走授權查詢。此執行期語義 SHALL 與有效權限主體視角回傳的可及集合一致。

#### Scenario: auditor 對 open 資產不得連線
- **WHEN** auditor 使用者對一 `open` 段位、未顯式授予其 connect 的資產發起 connect 判定（如簽發 connect token 或 SFTP）
- **THEN** 判定為拒，端點回 403（職責分離）

#### Scenario: auditor 保留檢視權
- **WHEN** auditor 使用者對任一資產發起 `view` 判定
- **THEN** 判定為准（稽核可檢視全部資產）

#### Scenario: auditor 顯式授權仍可連線
- **WHEN** auditor 使用者對某資產有時窗內顯式 connect 授權
- **THEN** connect 判定為准（顯式授權不因角色收窄而失效）

#### Scenario: admin 全權限不受影響
- **WHEN** admin 使用者發起 connect 判定
- **THEN** 判定為准

#### Scenario: 一般使用者不受影響
- **WHEN** 無特權角色使用者發起 connect 判定
- **THEN** 依其授權查詢結果裁定，與本變更前一致

### Requirement: 授權帳號範圍
授權列 SHALL 支援帳號範圍：預設 `@ALL`（客體範圍內資產的全部帳號），MAY 個別指定
username 清單（語義＝範圍內資產上同名帳號）。有效帳號集合 SHALL 為使用者全部命中
授權列（含群組授權與 ticket 臨時授權）帳號範圍之聯集；admin SHALL 為全量。帳號
授權判定 SHALL 於 connect token 簽發、兌換複查與工作區帳號選擇三處強制；系統路徑
（改密計劃、k8s、SFTP 側車）作用於預設帳號，不經此判定。未指定帳號範圍的授權列
SHALL 由欄位預設值取得 `@ALL`（行為＝全部帳號），SHALL NOT 依賴任何一次性回填步驟。

#### Scenario: 未指定帳號範圍即為全部
- **WHEN** 以未帶帳號範圍的請求建立授權列，使用者據此連線多帳號資產
- **THEN** 該授權列的帳號範圍為 `@ALL`，全部帳號可選

#### Scenario: 個別指定帳號
- **WHEN** 授權列指定 `["app"]`，資產另有 root 帳號
- **THEN** 該使用者的帳號選擇僅列 app；指定 root 的 token 簽發被拒

#### Scenario: 聯集語義
- **WHEN** 使用者個人授權指定 `["app"]`、其群組授權為 `@ALL`
- **THEN** 有效帳號集合為全部帳號（聯集取寬）

#### Scenario: 帳號範圍收緊即時生效
- **WHEN** 使用者取得綁 root 的 connect token 後，授權列帳號範圍改為 `["app"]`
- **THEN** 兌換複查拒絕建線（帳號授權於兌換點 DB 現查）

