# auth-session Specification

## Purpose
認證會話治理：短效 access token 搭配資料庫 refresh 憑證輪替與活動刷新、登出／停用／鎖定的撤銷語義、JWT 僅經 Authorization header 接受、會話換發不遺失認證脈絡、OIDC 會話與本地登入同軌治理（含絕對壽命上限）、刷新輪替留痕，以及依實際雜湊成本設定的認證端點併發保護。
## Requirements
### Requirement: 短效會話與活動刷新
Web 會話 SHALL 採固定短效 access token（15 分，撤銷殘窗上限，不隨政策放寬）搭配資料庫儲存的 refresh 憑證。刷新 SHALL 同時滿足：憑證未撤銷、未逾絕對壽命（政策 max session，預設 12 小時）、且距上次活動未逾政策閒置窗口（sliding 閒置判定；出廠預設 60 分，PCI 建議 ≤15 分作標示）；任一不滿足 SHALL 要求重新登入。每次刷新 SHALL 輪替 refresh 憑證（舊憑證即刻作廢，防重放）。前端 SHALL 於活動中透明刷新，使用者操作不中斷。已建立的終端 WebSocket 連線 SHALL NOT 因 access token 到期而中斷（由協議層閒置逾時治理）。

#### Scenario: 活動中透明刷新
- **WHEN** 使用者持續操作且 access token 到期
- **THEN** 前端自動以 refresh 憑證換發新 access token 並重試原請求，操作無感

#### Scenario: 閒置逾時須重登
- **WHEN** 使用者閒置超過政策閒置分鐘數後回到頁面
- **THEN** 刷新被拒，導向重新登入

#### Scenario: 達絕對壽命須重登
- **WHEN** 會話總時長超過 max session 上限（即使持續活動）
- **THEN** 刷新被拒，導向重新登入

#### Scenario: 舊 refresh 憑證重放觸發家族撤銷
- **WHEN** 已被輪替作廢的 refresh 憑證再次用於刷新
- **THEN** 拒絕、事件入審計，並撤銷該使用者全部 refresh 憑證（視同憑證洩漏，RFC 9700）——攻擊者持竊得憑證換得的 session 一併失效

### Requirement: 會話撤銷
登出 SHALL 撤銷當前 refresh 憑證。改密、帳號停用、帳號鎖定 SHALL 撤銷該使用者全部 refresh 憑證。帳號**停用**（管理員動作）SHALL 同步強制終斷該使用者全部進行中的協議會話（SSH/RDP/k8s/DB，沿用 admin_terminate 斷線語義）——即時撤權不得等待閒置逾時。**自動鎖定 SHALL NOT 強制終斷既有會話**（避免未認證攻擊者藉觸發鎖定遠端斷開在線使用者），鎖定僅阻擋新登入與新連線。撤銷後殘餘 access token 的存活 SHALL 以閒置分鐘數為上限。

#### Scenario: 登出即撤銷
- **WHEN** 使用者登出後其 refresh 憑證被用於刷新
- **THEN** 刷新被拒

#### Scenario: 登出提交已輪替憑證觸發家族撤銷
- **WHEN** 登出時提交的 refresh 憑證已被 rotation 作廢（分叉訊號：憑證曾遭竊取並輪替出分叉鏈）
- **THEN** 撤銷該使用者全部 refresh 憑證、事件入審計——不得只做冪等 no-op（否則登出正好移除「重放才觸發」的 reuse detection，攻擊者分叉鏈存活至絕對壽命）；登出本身仍回成功

#### Scenario: 改密撤銷全部會話
- **WHEN** 使用者密碼被修改（自助或 admin 重設）
- **THEN** 該使用者所有既存 refresh 憑證失效，各裝置須重新登入

#### Scenario: 停用即斷進行中會話
- **WHEN** admin 停用某使用者時該使用者有進行中的 SSH 會話
- **THEN** 該會話立即被終斷（不等閒置逾時），refresh 憑證全數失效

#### Scenario: 停用即斷不留連線建立競態窗
- **WHEN** admin 停用恰落在某新連線「會話列已寫入但尚未掛上連線註冊表」的窗口內
- **THEN** 該連線在轉發啟動前 SHALL 重新查核使用者可連線狀態並拒絕——已停用者不得因終斷落在註冊前而逃過即時撤權

#### Scenario: 自動鎖定不斷既有會話
- **WHEN** 某使用者因連續登入失敗被自動鎖定，且其另有進行中的 SSH 會話
- **THEN** 既有會話不被終斷（僅阻擋新登入與新連線），避免鎖定成為遠端斷線武器

### Requirement: JWT 僅經 Authorization header 接受
認證 middleware SHALL 僅從 `Authorization: Bearer` header 接受 JWT，SHALL NOT 接受 URL query 參數傳遞的 JWT——長效權杖入 query 會被 access log 與 proxy 日誌完整記錄。專用短效機制不受影響：錄影播放 rtoken（不透明、120s TTL）與一次性 connect-token 維持既有 query／訊息傳遞方式。

#### Scenario: query 傳遞 JWT 被拒
- **WHEN** client 以 `?token=<有效JWT>` 呼叫掛認證 middleware 的端點且無 Authorization header
- **THEN** 回 401 未提供認證 token

#### Scenario: rtoken 播放不受影響
- **WHEN** 前端以 rtoken 播放文字錄影（`?rtoken=`）
- **THEN** 播放正常（rtoken 走專用驗證路徑，非 JWT middleware fallback）

### Requirement: 會話換發不得遺失認證脈絡
任何換發正式會話的路徑（含登入後段、多因素完成、強制改密完成）SHALL 沿用該次認證的脈絡（認證方式與 provider）。SHALL NOT 因換發而使脈絡歸零——否則經該路徑取得的憑證將對 provider 停用免疫，且與其原始認證方式脫節。

#### Scenario: 改密完成不洗白脈絡
- **WHEN** 一個綁有外部身分的帳號經 OIDC 登入後自願改密，系統換發新會話，其後 admin 停用該 provider
- **THEN** 改密後換發的憑證同樣失效（其認證脈絡仍為該 provider）

### Requirement: OIDC 會話治理一致性
經 OIDC 認證建立的 Web 會話 SHALL 與本地/LDAP 登入走同一套會話發放與撤銷治理：短效 access token＋refresh 憑證輪替、登出/停用/鎖定的撤銷語義一致。系統本身的會話生命週期 SHALL NOT 依賴 IdP 的 token（不儲存 IdP access/refresh token 供會話續命）。

由於身分提供者端的停權不會即時傳導至本系統，**Web 會話** SHALL 受既有絕對壽命上限約束——超過該上限即須重新經身分提供者認證。為使該門檻可驗收，刷新換發的存取憑證其有效期 SHALL NOT 越過絕對壽命期限（剩餘期限短於標準有效期時取較短者）。刷新憑證輪替 SHALL NOT 重置該上限的起算點。認證脈絡（認證方式與 provider）SHALL 於輪替時原樣沿用，以維持 provider 級撤銷的可達性。

**適用範圍的誠實界定**：上述門檻**僅適用於 Web 會話**。既有規範已明訂「已建立的終端 WebSocket 連線 SHALL NOT 因 access token 到期而中斷（由協議層閒置逾時治理）」——協議連線的生命週期與 Web 會話分離，其終止途徑為閒置逾時、管理者顯式終斷、帳號停用，以及本規範新增的 provider 停用與身分解綁。**身分提供者端的停權本身 SHALL NOT 被宣稱能自動終止進行中的協議連線**（本系統無從得知該事件）；需要此保證的部署須改以管理端動作或未來的事件同步機制達成。

#### Scenario: OIDC 會話同軌刷新
- **WHEN** OIDC 登入的使用者 access token 到期且持續活動
- **THEN** 以 refresh 憑證透明換發，行為與本地登入使用者一致

#### Scenario: 停用即撤銷（來源無關）
- **WHEN** admin 停用一個經 OIDC 供應的帳號
- **THEN** 其全部 refresh 憑證撤銷、進行中協議會話終斷、**唯讀訂閱收線**（會話監看與分享觀看）、尚未兌換的能力憑證失效，與本地帳號相同

#### Scenario: 絕對壽命上限即須重新認證
- **WHEN** OIDC 的 Web 會話持續活動達絕對壽命上限
- **THEN** 刷新被拒，使用者須重新經身分提供者認證（此時**帳號已於 IdP 端停用**者無法再取得會話；帳號仍存續而僅組織歸屬變更者，其攔阻取決於 provider 的准入模式）

#### Scenario: 存取憑證不越過絕對期限
- **WHEN** 距絕對壽命期限的剩餘時間短於存取憑證的標準有效期時發生刷新
- **THEN** 換發的存取憑證於絕對期限即到期，不得存活至其標準有效期

#### Scenario: 多次刷新不重置絕對壽命
- **WHEN** OIDC 會話經多次 refresh 憑證輪替
- **THEN** 絕對壽命起算點維持首次登入時刻，輪替 SHALL NOT 延長上限

### Requirement: 刷新憑證輪替留痕

refresh 憑證的成功輪替 SHALL 寫入審計列，記錄使用者、來源位址與輪替時間。

若僅刷新失敗留痕、成功輪替無痕，「憑證遭竊後被持續用於維持存取」這條路徑在稽核上即不可見——成功的輪替正是該情境唯一會留下的訊號。

#### Scenario: 成功輪替留痕

- **WHEN** 前端以有效 refresh 憑證換取新的 access token
- **THEN** audit_logs 新增一筆列，可查明使用者、來源位址與輪替時間

#### Scenario: 稽核可追出異常來源

- **WHEN** 稽核比對某帳號的輪替記錄
- **THEN** 來源位址的變化可被辨識，供判斷憑證是否遭他處使用

### Requirement: 認證端點的併發保護須依實際計算成本
執行密碼雜湊的認證端點 SHALL 受併發上限保護，且各端點的上限 SHALL 依其**單次請求的實際雜湊次數**設定，SHALL NOT 對成本相差數量級的端點套用相同或更寬鬆的上限。

上限的數值 SHALL 由雜湊實作回報的成本推導，SHALL NOT 硬編碼於處理器中——硬編碼的數值在更換演算法後即失去依據，而失效方式是靜默的（數值仍在，但它所根據的成本假設已不成立）。

**成本不對稱的具體形態**：登入每次執行 1 次雜湊；改密每次執行 `2 + N + 1` 次（N 為密碼歷史筆數）。以歷史筆數的組態上界計，兩者相差兩個數量級。僅保護登入而不保護改密，等於把上限掛在便宜的那一端。

#### Scenario: 改密端點的併發上限
- **WHEN** 已認證使用者對改密端點發出超過上限的並行請求
- **THEN** 超額請求被拒或排隊，系統資源不因單一帳號的行為而耗盡

#### Scenario: 上限依成本推導
- **WHEN** 雜湊實作或其參數變更，使單次雜湊的成本改變
- **THEN** 併發上限隨之調整，SHALL NOT 維持依據已失效的舊數值

#### Scenario: 歷史筆數提高時的成本
- **WHEN** 密碼歷史筆數設定為較大值
- **THEN** 改密端點的併發上限相應下修，單一請求的總成本不因組態而失控

