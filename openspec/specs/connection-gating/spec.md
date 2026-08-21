# connection-gating

## Purpose

連線憑證收口：前端零接觸明文憑證，後端記憶體解密注入，全協議一致。
## Requirements
### Requirement: Asset-gated connections
All protocol connections (SSH, RDP, VNC) SHALL be initiated with an authentication token and an asset identifier only. The backend MUST resolve connection targets and decrypt credentials in memory; connection endpoints MUST NOT accept hostname, username, or password parameters from the client.

#### Scenario: RDP connects with asset reference only
- **WHEN** the frontend opens the guacd WebSocket for an RDP asset
- **THEN** the request carries only token, asset_id and initial dimensions, and the session is established with backend-resolved credentials

#### Scenario: Legacy credential parameters rejected
- **WHEN** a client calls the connect endpoint without asset_id (or with hostname/username/password parameters only)
- **THEN** the connection is rejected with an error explaining that connections require a registered asset

#### Scenario: Authorization always enforced
- **WHEN** a user without connect permission on the asset opens the connect WebSocket
- **THEN** the connection is rejected before any upstream handshake occurs

### Requirement: No plaintext credential egress
No API response SHALL contain decrypted asset credentials. Credential material decrypted for connection establishment MUST exist only in backend memory for the duration of the handshake.

#### Scenario: connect-info endpoint removed
- **WHEN** a client requests GET /api/v1/assets/{id}/connect-info
- **THEN** the endpoint does not exist (404), and no other endpoint returns plaintext passwords or private keys

### Requirement: No manual bypass path
The system SHALL NOT provide a user-facing path to open proxied connections to arbitrary, unregistered targets with manually supplied credentials. Asset connectivity verification SHALL be performed server-side via the asset test endpoint.

#### Scenario: Manual connection page removed
- **WHEN** a user navigates to the legacy manual test-connection page
- **THEN** the route no longer exists, and asset connectivity can only be verified through the server-side asset test action

### Requirement: 一次性連線 token
系統 SHALL 提供 `POST /api/v1/connect-tokens`：經 JWT 認證與資產連線授權檢查後簽發一次性 token（60 秒有效）；請求 MAY 指定 `account_id`（省略＝預設帳號），簽發 SHALL 驗證該帳號隸屬該資產且在請求者有效授權帳號範圍內；SSH 與 guacd（RDP/VNC）WS 端點 SHALL 接受 `connect_token` 並於使用後即刻失效；過期或已用 token SHALL 被拒絕；前端兩類 WS URL SHALL NOT 攜帶 JWT。

#### Scenario: 正常兩段式連線
- **WHEN** 前端以 JWT 換取 connect token 後開啟 WS（SSH 或 guacd）
- **THEN** 連線建立，且同一 token 再次使用被拒

#### Scenario: 無授權資產
- **WHEN** 使用者對無連線權限的資產請求 token
- **THEN** 回 403，不簽發 token

#### Scenario: 過期 token
- **WHEN** 以超過 60 秒的 token 開啟 WS
- **THEN** 連線被拒（401）

#### Scenario: guacd 路徑持 token 連線
- **WHEN** 前端以 connect token 開啟 /api/v1/connect（RDP/VNC）
- **THEN** 連線建立且 URL 不含 JWT，token 即焚

#### Scenario: 跨資產帳號注入被拒
- **WHEN** 請求 token 時指定隸屬其他資產的 account_id
- **THEN** 簽發被拒（fail-close），不洩漏該帳號存在性

### Requirement: 不安全通道連線前同意閘
connect-token 簽發 SHALL 依傳輸安全政策對 RDP／VNC／DB 連線加閘：該通道為 warn 且申請者對該資產無有效同意記憶時，簽發 SHALL 被拒並回須同意之風險項；該通道為 strict 且資產命中風險判定時，簽發 SHALL 無條件拒絕。off 檔 SHALL 完全不影響簽發。閘檢查 SHALL 位於簽發端點（授權檢查之後），確保所有連線入口（含直呼 API）一致受閘。

#### Scenario: strict 檔簽發無條件拒絕
- **WHEN** DB 通道政策為 strict，使用者對 db_tls_mode=disable 的資產申請 connect-token
- **THEN** 簽發拒絕（不因任何同意而放行），回應含不符項，事件入審計

#### Scenario: off 檔行為不變
- **WHEN** 通道政策為 off，使用者申請任一資產 connect-token
- **THEN** 簽發流程與未套用傳輸安全閘時完全一致，無同意檢查

### Requirement: 簽發閘序
connect-token 簽發 SHALL 依固定順序施行五道檢查：連線授權檢查 → 停用資產硬擋（見「停用資產連線硬擋」）→ 錄影前置檢查（見 session-recording「錄影前置檢查與 fail-close」，政策開啟時生效）→ 存取政策閘（見 access-policy）→ 傳輸安全閘；任一檢查攔截即不簽發、不觸發後續檢查。攔截回應 SHALL 機器可辨：停用硬擋、錄影前置檢查與政策閘同用 403 但 `reason` 值不重疊（`asset_disabled`／`recording_unavailable`／`approval_required`/`reason_required`），傳輸閘沿用 strict 400／warn 428；前端 SHALL 能僅憑狀態碼與 reason 欄位區分該顯示停用、錄影異常、彈申請框、同意框或顯示拒絕。

#### Scenario: 停用攔截不觸發政策閘
- **WHEN** 具授權的使用者對「停用且政策段位為 approval」的資產申請 connect-token
- **THEN** 回應為停用硬擋的 403（asset_disabled），不出現政策閘的 403（approval_required）——停用資產不引導使用者走申請流

#### Scenario: 錄影攔截不觸發政策閘
- **WHEN** fail-close 政策開啟、錄影目錄不可寫，具授權的 user 對 approval 段位資產申請 connect-token
- **THEN** 回應為錄影前置檢查的 403（recording_unavailable），不出現政策閘的 403——錄影儲存異常不引導使用者走申請流

#### Scenario: 政策攔截不觸發傳輸閘
- **WHEN** 使用者對 `approval` 段位且傳輸政策 warn 的資產申請 connect-token（無臨時授權、無傳輸同意）
- **THEN** 回應為政策閘的 403（approval_required），不出現傳輸閘的 428

#### Scenario: 政策放行後傳輸閘照常
- **WHEN** 同一資產上使用者已獲時窗內臨時授權但無傳輸同意
- **THEN** 政策閘放行、傳輸閘回 428 要求同意——兩閘獨立判定

#### Scenario: 閘序不受旁路
- **WHEN** 任何客戶端直呼 `POST /connect-tokens`（不經前端）
- **THEN** 五道檢查依序全部生效，與 UI 路徑無差別

### Requirement: 停用資產連線硬擋
連線 token 簽發點 SHALL 於既有權限與政策檢查外檢查資產啟用狀態：`active=false` 的資產一律拒發（403、機器可辨錯誤碼），涵蓋全部協議（SSH/RDP/VNC/DB/K8s）與 SFTP 檔案端點（同收口）。admin SHALL NOT 豁免——停用是資產狀態而非權限問題，admin 需先重新啟用資產（留審計軌跡）方可建線。拒發 SHALL 不受功能開關旁路。token 兌換點（文字終端與圖形 WS 端點）SHALL 於建線前重查資產啟用狀態：資產於簽發後、兌換前被停用者，兌換 SHALL 被拒（403、同一機器可辨錯誤碼）——與使用者側「消費時重載狀態」對稱，停用即時性殘窗以 token TTL 為上界、不因 token 尚在效期而放行。

#### Scenario: 停用資產拒發連線
- **WHEN** 任一角色（含 admin）對 `active=false` 的資產請求連線 token
- **THEN** 簽發點回 403（機器可辨錯誤碼），不建立連線

#### Scenario: 重新啟用後恢復
- **WHEN** admin 將資產重新啟用後，具授權的使用者再次請求連線
- **THEN** 簽發依既有權限與政策閘正常放行

#### Scenario: SFTP 同收口
- **WHEN** 使用者對 `active=false` 資產的 SFTP 檔案端點發起操作
- **THEN** 同樣被拒（不因端點不同而繞過停用態）

#### Scenario: 簽發後停用，兌換被拒
- **WHEN** 使用者取得連線 token 後、兌換前，admin 將該資產停用
- **THEN** 兌換端點於建線前拒絕（403、機器可辨錯誤碼），token 效期未到不構成放行理由

### Requirement: session 記錄建立 fail-close
連線建立流程於目標連線建立後 SHALL 持久化 session 記錄；session 記錄 INSERT 失敗 SHALL fail-close：關閉已建立的目標連線、拒絕 WebSocket 升級、回 403（機器可辨 `reason: session_unavailable`）；SHALL NOT 在無 session 主鍵下續建連線（杜絕無 registry／錄影／指令審計／監看的無歸責特權連線）。admin SHALL NOT 豁免——session 失敗代表完全無審計歸屬，與錄影失敗（仍保留 session 與指令審計）本質不同，無可歸責審計殘留則無例外。失敗事件 SHALL 經非資料庫降級管道（fallback audit／告警）記錄，SHALL NOT 沉默。文字終端與圖形 WS 兩路徑行為一致。

#### Scenario: session insert 失敗即拒連
- **WHEN** 目標連線已建立但 session 記錄 INSERT 失敗（DB 部分故障：讀正常、寫 sessions 表失敗）
- **THEN** 關閉目標連線、拒絕 WS 升級、回 403 `session_unavailable`，不建立任何無 session 的連線

#### Scenario: admin 不豁免
- **WHEN** 具 admin 角色的使用者遇 session insert 失敗
- **THEN** 同樣被拒（無 admin 例外）

#### Scenario: 失敗不沉默
- **WHEN** session insert 失敗觸發 fail-close
- **THEN** 事件經非 DB 降級管道（fallback audit／告警機制族）記錄，不僅是應用 log

### Requirement: 連線 token 兌換點授權與政策重查
connect token 兌換點（文字終端與圖形 WS 端點）於建線前，除既有 user active 與 asset active 重查外，SHALL 重跑連線授權檢查（`CheckPermission(Connect)`）與存取政策閘（`CheckConnect`），與簽發點對稱；grant 帶 `account_id` 時 SHALL 以 `(account_id, asset_id, 未刪除)` DB 現查客體綁定並重驗帳號授權範圍，失效一律 fail-close。簽發後、兌換前遭撤銷之授權 grant／ticket、收緊之存取政策、或被刪除／移出授權範圍之帳號 SHALL 於兌換即時生效（拒絕建線，403 機器可辨），撤權即時性殘窗 SHALL NOT 因 token 尚在效期而放行。存取政策重查 SHALL 為純判定（不建立 access_request）；admin 政策豁免於兌換點 SHALL NOT 重複記審計標記（簽發點已記）。

#### Scenario: 授權撤銷兌換被拒
- **WHEN** 使用者取得 connect token 後、兌換前，其對該資產的連線授權被撤銷
- **THEN** 兌換端點於建線前拒絕（403 機器可辨），token 效期未到不構成放行理由

#### Scenario: 存取政策收緊兌換被拒
- **WHEN** 資產存取政策於簽發後改為 approval 段位且該使用者無時窗內臨時授權，使用者兌換先前簽發的 token
- **THEN** 兌換被拒（政策閘攔截）

#### Scenario: 授權仍有效正常兌換
- **WHEN** 授權與存取政策自簽發至兌換均未變動
- **THEN** 兌換正常建線（重查不影響有效連線）

#### Scenario: 帳號於簽發後被刪除
- **WHEN** grant 所綁帳號於簽發後、兌換前被刪除
- **THEN** 兌換被拒（fail-close），不以預設帳號靜默替代

### Requirement: connect 角色特權判定以即時有效角色為準

connect token 的**簽發點**與**兩個兌換點**（文字終端與圖形 WS），其角色相關的特權判定——admin 授權短路（`CheckPermission`）、admin 存取政策豁免（`CheckConnect`）、admin 錄影 fail-close 例外——SHALL 以**即時查詢資料庫的有效角色**為準：單次載入該使用者角色並依固定優先序 `admin > auditor > user` 折疊（與 JWT 核發同源，approver 不參與折疊）。系統 SHALL NOT 憑 connect token 或 JWT 攜帶的角色快照授予 admin 特權。角色撤銷（降權）SHALL 於下一次簽發與兌換即時生效——撤權即時性殘窗 SHALL NOT 因 JWT 或 token 尚在效期而放行 admin 特權，杜絕「最高權限主體反較一般 user 享更長撤權殘窗」的特權倒置。connect token 的授權快照 SHALL NOT 持久化角色欄位，使「憑角色快照判定特權」於實作層成為編譯期不可能。本要求界定於**簽發與兌換時點**的即時性；已建立連線的存活期不因事後角色/授權變動而中斷（既有架構，屬 session 存活期撤銷的獨立議題，非本要求範圍）。

#### Scenario: 簽發點降權即擋、不產 token

- **WHEN** 使用者持仍在效期、`role=admin` 的 JWT，但其資料庫有效角色已被降為一般 user，且對目標資產無 connect 授權
- **THEN** `POST /api/v1/connect-tokens` SHALL 回 403（無連線權限），SHALL NOT 簽出 connect token（不依 JWT 角色快照套用 admin 短路/豁免/錄影例外）

#### Scenario: 文字終端兌換點降權即擋

- **WHEN** connect token 於簽發後、兌換前，其持有者資料庫有效角色被降為一般 user（帳號仍 active、對目標資產無 connect 授權）
- **THEN** 文字終端（SSH/DB/K8s）兌換 SHALL 回 403、拒絕建線（不依快照角色放行）

#### Scenario: 圖形 WS 兌換點降權即擋

- **WHEN** 同一降權情境發生於 RDP／VNC 圖形 WS 端點兌換
- **THEN** 圖形路徑兌換 SHALL 回 403、拒絕建線，與文字終端路徑行為一致

#### Scenario: 多角色未降權仍正確視為 admin

- **WHEN** 帳號同時具 admin 與 user 角色且未被降權
- **THEN** 簽發與兌換 SHALL 依折疊優先序正確以 admin 特權放行，判定 SHALL NOT 受角色綁定順序影響

### Requirement: 兌換拒絕留痕

連線票證兌換遭拒時，系統 SHALL 寫入審計列，涵蓋票證缺漏、票證無效、票證過期、閘序拒絕等各類拒絕原因，記錄來源位址與拒絕原因。

此要求 SHALL 涵蓋**全部**兌換入口——圖形協議與文字終端兩條入口皆然。任一入口未留痕，「反覆嘗試兌換偽造票證」的探測只要換一條入口就重新不可見。

拒絕原因的分流 SHALL 只存在於審計。對外回應 SHALL 收斂：票證不存在、已被兌換、已過期三者的回應 SHALL 逐字相同（狀態碼、內容、標頭），否則即開出票證存在性探測面。

`status` SHALL 依 HTTP 狀態機械分流：401（憑證本身不成立）記為認證失敗；其餘（身分成立但不准）記為授權拒絕。逐案判斷 SHALL NOT 採用——遲早會出現兩道語義相同的閘拿到不同狀態值。

拒絕僅回應 HTTP 狀態而不留痕時，「反覆嘗試兌換偽造票證」這類探測行為在稽核上即不可見。

#### Scenario: 偽造票證兌換被拒且留痕

- **WHEN** 以偽造的連線票證嘗試兌換
- **THEN** 兌換被拒且 audit_logs 新增一筆列，含來源位址與拒絕原因

#### Scenario: 協議不符被拒且留痕

- **WHEN** 以有效票證兌換不相符的協議
- **THEN** 兌換被拒且留痕，拒絕原因可與票證無效區分

#### Scenario: 文字終端入口的兌換拒絕同樣留痕

- **WHEN** 對文字終端兌換入口分別以缺票、偽造票、過期票與觸發閘序拒絕的有效票發起請求
- **THEN** 四者各留一筆審計列，含來源位址、路徑、方法與可區分的拒絕原因；閘序拒絕的列並填入目標資產

#### Scenario: 票證狀態不可經回應探測

- **WHEN** 攻擊者分別以偽造票與過期票兌換
- **THEN** 兩次的狀態碼、回應內容與標頭逐字相同，內部拒絕原因 SHALL NOT 出現在回應中

