# auth-session Specification

## Purpose
認證會話治理：短效 access token 搭配資料庫 refresh 憑證輪替與活動刷新、登出／停用／鎖定的撤銷語義、JWT 僅經 Authorization header 接受、會話換發不遺失認證脈絡、OIDC 會話與本地登入同軌治理（含絕對壽命上限）、刷新輪替留痕，以及依實際雜湊成本設定的認證端點併發保護。
## Requirements
### Requirement: 短效會話與活動刷新
Web 會話 SHALL 採固定短效 access token（15 分，撤銷殘窗上限，不隨政策放寬）搭配資料庫儲存的 refresh 憑證。刷新 SHALL 同時滿足：憑證未撤銷、未逾絕對壽命（政策 max session，預設 12 小時）、距上次活動未逾政策閒置窗口（sliding 閒置判定；出廠預設 60 分，PCI 建議 ≤15 分作標示）、且請求來源位址落於該使用者的允許來源網段清單內（清單為空即不限；見「登入來源位址限定」）；任一不滿足 SHALL 要求重新登入。刷新的判定順序 SHALL 為：不變更任何狀態的憑證驗證 → 來源判定（含政策不可用的拒絕）→ 於單一交易內輪替；來源判定拒絕時 SHALL NOT 消耗、撤銷或輪替該 refresh 憑證，SHALL NOT 更新其活動時刻，SHALL NOT 觸發重放偵測——持竊得憑證者自清單外來源刷新，不得使合法持有者的憑證失效。來源判定失敗的刷新拒絕 SHALL 沿既有統一認證失敗回應（SHALL NOT 新增可區分的訊號），拒絕入審計含來源位址與判定依據。每次成功刷新 SHALL 輪替 refresh 憑證（舊憑證即刻作廢，防重放）。前端 SHALL 於活動中透明刷新，使用者操作不中斷。已建立的終端 WebSocket 連線 SHALL NOT 因 access token 到期而中斷（由協議層閒置逾時治理）。

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

#### Scenario: 來源變更後刷新被拒
- **WHEN** 清單非空的使用者自清單內位址登入後，其後續刷新請求來自清單外位址
- **THEN** 刷新被拒（統一認證失敗回應，無來源專屬訊號），導向重新登入；拒絕入審計含來源位址；殘窗不超過 access token 壽命

#### Scenario: 清單收緊即時生效於刷新
- **WHEN** 管理員把某使用者的清單收緊為不含其當前位址，該使用者的 access token 到期
- **THEN** 下一次刷新被拒，該使用者須自清單內位址重新登入

#### Scenario: 清單外刷新不消耗憑證
- **WHEN** 攻擊者持竊得的有效 refresh 憑證自清單外位址刷新被拒，隨後合法持有者以同一憑證自清單內位址刷新
- **THEN** 合法持有者的刷新成功並正常輪替；先前的拒絕未撤銷該憑證、未觸發家族撤銷、未更新活動時刻；兩次事件皆入審計且各含其來源位址

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

認證 middleware SHALL 僅從 `Authorization: Bearer` header 接受 JWT，SHALL NOT 接受 URL query 參數傳遞的 JWT——長效權杖入 query 會被 access log 與 proxy 日誌完整記錄。認證 middleware SHALL NOT 自 cookie 接受 JWT——refresh 憑證遷入 cookie 後，系統存在瀏覽器自動附帶的憑證載體，但 access token 的傳輸通道 SHALL 維持唯一（Authorization header）；任何 cookie（含 refresh cookie 本身）對認證 middleware SHALL NOT 構成憑證。

**本規則對 WebSocket 路徑同樣適用，無例外**：不掛認證 middleware 的 WebSocket 端點
SHALL NOT 自 query 參數接受 session JWT，其認證一律以短效一次性票為之——票由掛認證
middleware 的簽發端點發出，只能開一條連線，兌換即失效。專用短效機制不受影響：錄影播放
rtoken（不透明、120s TTL）與一次性連線／觀看票維持既有 query 傳遞方式。

#### Scenario: query 傳遞 JWT 被拒

- **WHEN** client 以 `?token=<有效JWT>` 呼叫掛認證 middleware 的端點且無 Authorization header
- **THEN** 回 401 未提供認證 token

#### Scenario: cookie 傳遞 JWT 被拒

- **WHEN** client 將有效 JWT 置於 cookie（任意名稱）呼叫掛認證 middleware 的端點且無 Authorization header
- **THEN** 回 401 未提供認證 token（middleware 未讀取 cookie，而非讀取後判無效）

#### Scenario: rtoken 播放不受影響

- **WHEN** 前端以 rtoken 播放文字錄影（`?rtoken=`）
- **THEN** 播放正常（rtoken 走專用驗證路徑，非 JWT middleware fallback）

#### Scenario: WebSocket 端點不接受 query 上的 session JWT

- **WHEN** client 以 `?token=<有效JWT>` 呼叫任一 WebSocket 端點（終端、查詢主控台、監看、分享觀看）
- **THEN** 連線被拒，且該次拒絕留痕；建立連線的唯一途徑是先向簽發端點取得一次性票

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

### Requirement: refresh 憑證僅經 httpOnly cookie 傳輸

refresh 憑證在瀏覽器端的唯一載體 SHALL 為 `HttpOnly` cookie：

- 所有發放 refresh 憑證的回應（含登入、多因素完成、多因素註冊確認、強制改密換發、
  OIDC 交換與刷新輪替）SHALL 以 `Set-Cookie` 下發該憑證，屬性 SHALL 為 `HttpOnly`、
  `SameSite=Strict`、Path 收斂於認證端點群前綴，效期 SHALL 對齊該憑證的絕對壽命
  （輪替下發 SHALL 取剩餘壽命，SHALL NOT 因輪替延長）。
- cookie 的 Path SHALL 同時涵蓋刷新與登出端點——僅涵蓋刷新會使登出撤銷靜默退化為
  no-op，連帶分叉偵測的家族撤銷失效。
- `Secure` 旗標 SHALL 由安全政策鍵承載（見 security-policy「瀏覽器會話
  refresh cookie 的 Secure 政策鍵」）：發放時現讀、管理端可調、變更即生效不需
  重啟。其初值 SHALL 於首次啟動自部署組態播種，依序推導：
  `AUTH_REFRESH_COOKIE_SECURE` 顯式設定 → `PUBLIC_BASE_URL` 的 scheme
  （https → 安全、http → 非安全）→ **預設安全**；SHALL NOT 因設定缺席而回落為
  非安全——未設定的部署 SHALL 取得傳輸保護，走明文的部署 SHALL 經顯式關閉
  （播種組態或管理端政策）取得非安全值。政策不可讀或未接線時 SHALL 回落安全方向
  （Secure）。啟動日誌 SHALL 載明生效值與其來源（管理端設定／組態播種／出廠
  預設）；最終值為非安全時 SHALL 說明 refresh 憑證將經明文傳輸與復原方向。
  啟動日誌 SHALL NOT 被視為此組態唯一的可見性來源
  （見「非安全傳輸下的續期降級須可理解」）。
- 回應 body SHALL NOT 含 refresh 憑證明文（含巢狀回應形狀在內的一切序列化路徑）。
- 刷新端點 SHALL 僅自 cookie 讀取 refresh 憑證，SHALL NOT 接受 request body 傳遞，
  SHALL NOT 保留 body fallback；cookie 缺失 SHALL 回統一的認證失敗回應，
  SHALL NOT 洩漏「未提供／無效／已撤銷」的區分訊號。
- 登出 SHALL 自 cookie 讀取憑證執行撤銷（含「提交已輪替憑證觸發家族撤銷」語義原樣
  適用）並於回應清除 cookie；cookie 缺失 SHALL NOT 阻擋登出。
- 前端 SHALL NOT 將 refresh 憑證寫入任何 script 可讀儲存（localStorage／sessionStorage）；
  應用啟動 SHALL 無條件清除 localStorage 中的歷史殘值。

#### Scenario: 登入以 cookie 下發、body 無明文

- **WHEN** 使用者成功登入（任一登入流）
- **THEN** 回應含 `Set-Cookie`（`HttpOnly`、`SameSite=Strict`、Path 為認證端點群前綴），
  且回應 body 不含 refresh 憑證明文

#### Scenario: OIDC 交換的巢狀回應同樣收口

- **WHEN** OIDC 使用者完成 ticket 交換取得正式會話
- **THEN** refresh 憑證以 cookie 下發，巢狀 login 回應物件內不含憑證明文；
  尚待多因素驗證的分支不下發 refresh cookie

#### Scenario: 刷新僅認 cookie

- **WHEN** client 以 request body 攜帶有效 refresh 憑證但不帶 cookie 呼叫刷新端點
- **THEN** 刷新被拒（統一認證失敗回應），body 傳遞路徑不存在

#### Scenario: 登出經 cookie 撤銷並清除

- **WHEN** 使用者帶 refresh cookie 登出，其後同一憑證被用於刷新
- **THEN** 登出回應含清除性 `Set-Cookie`（即時到期），後續刷新被拒——撤銷確實發生而非 no-op

#### Scenario: 顯式關閉後純 HTTP 全循環可用

- **WHEN** 部署對外為純 HTTP，且該政策為非安全——經首次啟動播種
  （`AUTH_REFRESH_COOKIE_SECURE=false` 或 `PUBLIC_BASE_URL` 為 http 位址）
  或管理員於安全政策頁關閉
- **THEN** cookie 不帶 `Secure`，登入—刷新—登出全循環可用，
  啟動日誌載明已關閉與其來源

#### Scenario: 未顯式關閉的純 HTTP 部署降級而非不可用

- **WHEN** 部署對外為純 HTTP，未設定 `AUTH_REFRESH_COOKIE_SECURE` 與
  `PUBLIC_BASE_URL`，且該政策未曾於管理端調整
- **THEN** cookie 帶 `Secure` 而不被瀏覽器保存：登入本身成功、access token 壽命內
  操作正常，壽命到期後續期失敗、使用者須重新登入。系統於此形態 SHALL 維持可用
  （降級），且成因說明 SHALL 依「非安全傳輸下的續期降級須可理解」對使用者呈現

#### Scenario: 政策頁關閉即生效不需重啟

- **WHEN** 處於前一場景降級形態的部署中，管理員於安全政策頁關閉該政策並儲存
- **THEN** 後端不重啟，下一次發放的 refresh cookie 即不帶 `Secure`，
  使用者自下次登入起恢復完整續期循環

#### Scenario: 跨站請求不攜帶 refresh cookie

- **WHEN** 任意第三方站台對刷新或登出端點發起跨站請求
- **THEN** 瀏覽器因 `SameSite=Strict` 不附帶 refresh cookie，請求以無憑證處理

#### Scenario: 啟動清理歷史殘值

- **WHEN** 曾以舊版（localStorage 存放 refresh 憑證）登入的瀏覽器載入新版前端
- **THEN** 應用啟動即移除 localStorage 中的 refresh_token 殘值，不留明文

### Requirement: access token 僅存於頁面記憶體

瀏覽器端的 access token SHALL 只保存於頁面執行期記憶體，由單一前端模組持有：

- 前端 SHALL NOT 將 access token 寫入 localStorage、sessionStorage、IndexedDB、cookie 或任何跨頁面載入
  存續的儲存；應用啟動 SHALL 無條件清除歷史殘值（舊版寫入的 `token` 鍵）。
- 頁面載入（重新載入、新分頁、外部連結進站）時，前端 SHALL 於導覽守衛放行受保護路由**之前**以 refresh
  cookie 換發一次 access token 恢復登入態；同一頁面內的多次觸發 SHALL 共用同一次換發。
  無登入跡象（前端可觀察的「曾登入且未登出」訊號）時 SHALL NOT 呼叫刷新端點。恢復失敗 SHALL 清除登入跡象
  並導向登入頁；「非安全傳輸下的續期降級須可理解」的成因說明 SHALL 對此路徑原樣適用。
- 同一頁面內併發的 access token 失效回應 SHALL 共用一次換發；跨分頁的換發 SHALL 於瀏覽器支援時序列化，
  SHALL NOT 以同一 refresh 憑證併發輪替。
- 跨分頁同步 SHALL 只傳遞事件（登出、登入），SHALL NOT 傳遞任何憑證本體；任一分頁登出後，同瀏覽器的其他
  分頁 SHALL 清除記憶體中的 access token 並導向登入頁。換發終敗 SHALL NOT 廣播（已建立的終端連線不因他分頁
  的會話結束而被整頁導向中斷）。
- 不經 HTTP 攔截器的路徑（監看與分享 WebSocket、圖形錄影取流）SHALL 自同一記憶體持有者取得 access token，
  SHALL NOT 另設儲存；一次性 connect token 與錄影 rtoken 的既有機制不受影響。

#### Scenario: 登入後瀏覽器儲存無憑證

- **WHEN** 使用者經任一登入流取得正式會話
- **THEN** localStorage 與 sessionStorage 皆無 access token；後續 API 請求仍帶 `Authorization: Bearer`

#### Scenario: 重新載入恢復登入態

- **WHEN** 已登入使用者於受保護頁面重新載入
- **THEN** 頁面停留於原路由、不閃現登入頁；恰有一次刷新請求成功並輪替 refresh 憑證；
  記憶體持有新 access token

#### Scenario: 新分頁恢復登入態

- **WHEN** 已登入使用者以新分頁開啟站內受保護路由
- **THEN** 新分頁以 refresh cookie 換發後直接呈現該頁；原分頁不受影響

#### Scenario: 未登入訪客不觸發刷新

- **WHEN** 無登入跡象的瀏覽器開啟登入頁或受保護路由
- **THEN** 前端不呼叫刷新端點（審計中不出現對應的刷新拒絕事件），受保護路由導向登入頁

#### Scenario: 恢復失敗導向登入

- **WHEN** 有登入跡象的分頁重新載入，但 refresh 憑證已到期、已撤銷或未被瀏覽器保存
- **THEN** 導向登入頁、登入跡象被清除；再次重新載入不再呼叫刷新端點

#### Scenario: 一個分頁登出、全部分頁登出

- **WHEN** 使用者於分頁 A 登出
- **THEN** 同瀏覽器的分頁 B 於數秒內清除記憶體憑證並到達登入頁；跨分頁訊號的內容不含任何憑證

#### Scenario: 併發失效共用一次換發

- **WHEN** 同一頁面同時有多個請求收到 access token 失效回應
- **THEN** 只發生一次刷新，各請求以同一枚新 access token 重試成功

#### Scenario: 兩個分頁同時重新載入

- **WHEN** 兩個已登入分頁同時重新載入
- **THEN** 兩次換發序列化完成、皆成功，不觸發家族撤銷

#### Scenario: 監看連線自記憶體取憑證

- **WHEN** 稽核者於新分頁開啟進行中連線的監看頁
- **THEN** 監看 WebSocket 建線成功，其憑證來自恢復後的記憶體持有者，localStorage 中無 access token

#### Scenario: 純 HTTP 降級形態下重新載入即須重登

- **WHEN** 部署對外為純 HTTP 且 refresh cookie 帶 `Secure`（瀏覽器不保存），使用者登入後重新載入
- **THEN** 恢復失敗、導向登入頁，登入頁依既有降級說明呈現成因與處置方向

### Requirement: 非安全傳輸下的續期降級須可理解

會話續期因傳輸組態而失敗時，系統 SHALL 讓兩類讀者各自看得懂成因與處置方向：

- **被登出的使用者**：前端 SHALL 於「頁面經 http 載入、續期失敗、且該分頁未曾有
  成功續期」同時成立時，在登入頁以常駐訊息（而非一次性 toast）說明登入狀態未能
  保存的成因與「轉知管理員」的處置方向；訊息 SHALL 為三語，SHALL NOT 使用內部
  實作詞彙（cookie 屬性名、環境變數名）。偵測 SHALL 僅依前端可觀察的事實
  （頁面協定、續期結果、本分頁續期史），SHALL NOT 要求後端在統一認證失敗回應中
  加入區分訊號。
- **能處置的管理者**：管理端安全設定頁 SHALL 於「頁面經 http 載入且 refresh cookie
  生效值為安全」時顯示建議性提示，並列兩條處置路徑（改以 HTTPS 對外提供、或關閉
  同頁承載的該政策開關）；提示 SHALL 指向該政策鍵所在的同一頁面控制項，措辭
  SHALL 為建議而非警告或強制。系統 SHALL NOT 自動變更該設定——其寫入 SHALL 僅
  發生於管理員於管理介面的顯式儲存與首次啟動播種，SHALL NOT 存在任何自動翻轉
  路徑。
- 生效值 SHALL 作為一般政策項經既有管理端政策讀取 API 提供已認證管理員（供前端
  判定提示條件），SHALL NOT 對未認證請求或非管理角色暴露；其變更 SHALL 經既有
  政策更新流（批次原子、變更入審計），SHALL NOT 另闢寫入通道。

#### Scenario: 登入頁說明在首次續期失敗時出現

- **WHEN** 頁面經 http 載入、該分頁未曾成功續期，access token 到期後續期失敗、
  使用者被導回登入頁
- **THEN** 登入頁顯示常駐說明：登入狀態未能保存、每隔約 access token 壽命須重新
  登入、請轉知系統管理員

#### Scenario: 健康的明文部署不誤報

- **WHEN** 顯式關閉 Secure 的純 HTTP 部署中，使用者經多次成功續期後因閒置逾時
  續期被拒
- **THEN** 前端走一般會話過期處理，不顯示本要求的 http 成因說明

#### Scenario: 管理頁建議與決定權

- **WHEN** 管理員經 http 開啟安全設定頁，且後端 refresh cookie 生效值為安全
- **THEN** 頁面顯示建議性提示與兩條處置路徑，提示指向同頁的該政策開關；
  系統未自動變更任何設定，變更僅在管理員操作該開關並儲存時發生

#### Scenario: HTTPS 下無提示

- **WHEN** 頁面經 https 載入
- **THEN** 登入頁與安全設定頁皆不顯示本要求的提示

#### Scenario: 生效值不對未認證者暴露

- **WHEN** 未認證請求或非管理角色嘗試讀取承載該政策項的管理端資源
- **THEN** 既有認證與角色閘拒絕；該政策項僅隨管理員限定回應提供

### Requirement: 登入來源位址限定

使用者可設定允許來源網段清單（見 user-account-administration「使用者來源網段允許清單」）。清單非空時，系統 SHALL 於**每一個發出正式 web 會話的路徑**判定請求來源位址是否落於清單內：密碼登入完成、多因素驗證完成、OIDC 交換完成、強制註冊完成、改密完成。不在清單內者 SHALL NOT 取得會話。清單為空 SHALL 不限制。

**適用原則**：凡請求建立或變更呼叫者自身的認證狀態——發出正式會話、發出或消費受限票證（多因素強制註冊票證、強制改密票證）、寫入密碼或多因素狀態（自助改密、多因素設定、啟用、停用）——SHALL 於票證或會話驗證之後、狀態寫入之前判定來源；管理者對他人帳號的認證狀態寫入（重設密碼、解鎖、多因素救援停用）SHALL 依操作者本人的清單判定。非認證因子的寫入（顯示名、授權、身分綁定、登出）沿一般請求，不逐請求重判。上述適用集合 SHALL 為閉集合並由守衛釘住：新增認證類端點而未歸入「判定」或「明列不判」任一集合 SHALL 使守衛失敗。

判定 SHALL 發生於憑證驗證**之後**（沿「登入回應不洩漏帳號存在性」：帳號屬性的判定不得先於憑證驗證，否則對未認證者開存在性預言機）。多因素流程的第一階段（密碼通過、尚待第二因素）SHALL NOT 判定，判定放在發出正式會話的完成點；持有密碼但無第二因素者 SHALL NOT 能探知來源政策。強制註冊票證與強制改密票證的**發放**點 SHALL 判定（該時點憑證已完整驗證），其**消費**點 SHALL 再判定一次（票證不攜帶位址）。

來源位址 SHALL 取自系統唯一的來源位址實作（依可信代理宣告決定是否採信轉送標頭），SHALL NOT 另行解析標頭。清單非空而來源無法解析為位址時 SHALL 拒絕（fail-close）。判定 SHALL 於每次現讀該使用者的清單，SHALL NOT 快取於憑證內。

**政策不可用**（讀取使用者清單失敗、或儲存的清單字串無法解析）時，每一個判定點 SHALL 拒絕，SHALL NOT 把錯誤視為空清單放行；拒絕 SHALL 入審計並以專屬原因碼（政策不可讀）與來源拒絕區分；系統 SHALL 同時經既有的審計機制失效通道上報（機制 `source_policy`），使營運端於失效面板與通知通道可見，並於政策恢復可讀後結案。空清單不是不可用。

拒絕 SHALL 入審計（含來源位址與判定依據），對外回應 SHALL 為 403 與專屬機器碼（三語），SHALL NOT 回顯來源位址或清單內容；拒絕 SHALL NOT 計入失敗登入次數（憑證正確），但仍受既有來源限流覆蓋。

本要求界定於會話與票證發放、票證消費與認證狀態寫入時點。已發出的存取憑證在其壽命內對其他請求不逐請求重判（殘窗以存取憑證壽命為上界，由刷新判定收窄，見「短效會話與活動刷新」）。此邊界 SHALL 載明。

#### Scenario: 清單內來源正常登入

- **WHEN** 使用者的允許清單為 `10.0.0.0/8`，自 10.1.2.3 以正確憑證登入
- **THEN** 登入成功，行為與未設清單時一致

#### Scenario: 清單外來源憑證正確仍被拒

- **WHEN** 同一使用者自 203.0.113.5 以正確憑證登入
- **THEN** 回 403 與專屬機器碼，回應不含位址與清單；audit_logs 新增一筆含來源位址與判定依據的拒絕紀錄；失敗登入計數不變

#### Scenario: 清單外來源憑證錯誤不分歧

- **WHEN** 同一使用者自 203.0.113.5 以錯誤憑證登入
- **THEN** 回應與「帳號不存在」及「密碼錯誤」的回應相同，不出現來源相關的專屬碼

#### Scenario: 多因素完成點判定

- **WHEN** 清單非空的使用者密碼通過後，自清單外位址提交多因素驗證碼
- **THEN** 第二階段被拒（403 專屬機器碼），不發出正式會話；第一階段回應本身不因來源而分歧

#### Scenario: OIDC 交換點判定

- **WHEN** 清單非空的使用者經身分提供者認證後，自清單外位址完成票證交換
- **THEN** 交換被拒（403 專屬機器碼），不發出正式會話，拒絕入審計

#### Scenario: 空清單不限制

- **WHEN** 使用者清單為空
- **THEN** 自任何位址登入皆不因來源被拒

#### Scenario: 受限票證自清單外來源消費被拒

- **WHEN** 清單非空的使用者自清單內位址登入取得強制改密票證或強制註冊票證，隨後自清單外位址以該票證呼叫改密、註冊設定或註冊確認端點
- **THEN** 請求被拒（403 專屬機器碼），密碼與多因素狀態皆未變更、不回傳任何 TOTP 秘密、不發出正式會話；拒絕入審計含來源位址

#### Scenario: 受限票證發放點自清單外被拒

- **WHEN** 受強制註冊多因素但尚未註冊的使用者，自清單外位址以正確密碼登入
- **THEN** 不發出註冊票證，回 403 專屬機器碼並入審計；同一使用者若已啟用多因素，第一階段回應不因來源而分歧

#### Scenario: 正式會話下自清單外變更密碼或多因素被拒

- **WHEN** 持有效會話的使用者自清單外位址（會話發放後清單被收緊，存取憑證尚未到期）呼叫自助改密、多因素設定、啟用或停用端點
- **THEN** 請求被拒（403 專屬機器碼），狀態未變更；同一憑證對非認證因子的請求（例如更新顯示名）在殘窗內不受影響，此邊界載明

#### Scenario: 管理者自清單外對他人做認證狀態寫入被拒

- **WHEN** 清單非空的管理者自清單外位址對另一使用者重設密碼、解鎖或停用多因素
- **THEN** 請求被拒（403 專屬機器碼）並入審計，目標使用者的狀態未變更

#### Scenario: 清單字串損壞時拒絕並發出降級訊號

- **WHEN** 某使用者儲存的清單字串被以資料庫直接寫入弄成無法解析的內容，該使用者隨後登入、刷新、申請與兌換連線
- **THEN** 每一個判定點皆拒絕；審計列的原因碼為政策不可讀而非來源不允許；審計機制失效面出現 `source_policy` 事件並經通知通道推送；管理者以合法清單重新儲存後，該事件結案

#### Scenario: 政策讀取失敗不得視為空清單

- **WHEN** 判定點讀取使用者清單時資料庫回錯
- **THEN** 拒絕（對外形狀與該點的來源拒絕相同），不發出會話或票證，失效面上報；不出現「因讀不到清單而放行」的路徑

### Requirement: 自動化主體的長效 bearer token 認證

系統 SHALL 為 `kind=agent` 的主體提供專屬的長效 bearer token，作為該主體存取 API 的唯一憑證。token 明文格式 SHALL 為固定前綴加 32 bytes 的 base64url 隨機值；明文 SHALL 只在建立回應中出現一次，SHALL NOT 可經任何後續查詢再次取得；持久化 SHALL 只保存其 SHA-256 雜湊。每把 token SHALL 帶必填的到期時刻；SHALL NOT 允許建立永不到期的 token。一個 agent 主體 MAY 同時持有多把 token。

認證中介層 SHALL 以明文前綴辨識此類憑證並改走雜湊查表路徑，SHALL NOT 嘗試以 JWT 解析之。通過的條件 SHALL 為下列全部成立，且每一項 SHALL 於該次請求現查資料庫（SHALL NOT 讀行程內快取——多副本部署下快取會使撤銷與停用延遲生效）：token 存在、未逾到期時刻、未撤銷、未停用、該 agent 主體為啟用狀態、其 owner 未失效、**該主體的允許來源網段清單非空時來源位址落在清單內**。來源網段 SHALL 沿用既有的帳號層允許清單欄位與既有判定，SHALL NOT 為自動化主體另立一套清單或另一套比對——同一個欄位在人類登入與本路徑上的語義必須相同，否則管理者設了清單卻不知道它對哪一種主體生效。清單為空時 SHALL 不施加位址限制（與人類語義一致）。連線層依資產政策進行的來源位址判定 SHALL 另行成立，SHALL NOT 因本層已比對而略過。**owner 失效 SHALL 有兩條判定**：owner 帳號為停用狀態，或 owner 的外部身分憑證已失效（既有憑證世代進位）；任一成立即視為失效——只判帳號啟用狀態會讓「外部身分已被解綁的人」持續擔任負責人。通過後 SHALL 於請求脈絡注入主體 id、角色 `user`、主體種類 `agent` 與該 token 的識別值，使下游判定與審計得以區分主體種類。

上述任一條件不成立時，**對外回應 SHALL 使用同一個機器碼**，SHALL NOT 使「token 不存在」「曾有效但已撤銷」「已停用」在對外回應上可區分——可區分即等於開出憑證狀態的探測面。拒絕的真實原因 SHALL 記於審計側，沿既有的拒絕原因分流形態。

人類 JWT 路徑的取值來源、判定順序與既有脈絡欄位 SHALL NOT 改變，並 SHALL 於同一位置標示主體種類為 `human`。agent token SHALL NOT 可用於人類專屬路徑（登入、刷新、改密、MFA 註冊與驗證），SHALL NOT 換發刷新憑證。人類 JWT SHALL NOT 被辨識為 agent 憑證。

**本版本的誠實邊界**：此 token 是長效持有型憑證，持有者即可冒充該主體，被竊期間的冒用 SHALL NOT 被宣稱為已防止。本版本提供的是可撤銷、有到期、每次請求現查狀態、允許來源網段收窄，以及撤銷後既有會話的即時終止；建立協議連線仍須另行換取短效 connect token，該短效憑證維持既有的一次性兌換與兌換點複查語義。被竊後的事後檢視 SHALL 只被表述為**識別所用的憑證**：審計鏈答得出「是哪一把 token 做的」，SHALL NOT 被表述為判明持有人身分——bearer 憑證不攜帶持有者證明。

#### Scenario: 有效 token 通過並標示主體種類

- **WHEN** 以未到期、未撤銷、未停用的 agent token 呼叫一般 API，且該 agent 主體與其 owner 皆為啟用
- **THEN** 請求通過，請求脈絡的主體 id 為該 agent 主體、角色為 `user`、主體種類為 `agent`，且帶該 token 的識別值

#### Scenario: 明文只出現一次

- **WHEN** 建立一把 agent token 後，以任何查詢端點讀取該 token 記錄
- **THEN** 回應含名稱、建立者、到期時刻與狀態，SHALL NOT 含明文或可還原明文的任何值

#### Scenario: 逾期 token 被拒

- **WHEN** 以已逾到期時刻的 agent token 呼叫 API
- **THEN** 回 401，請求不進入任何業務 handler

#### Scenario: 撤銷後下一次請求即被拒

- **WHEN** 一把 agent token 被撤銷後隨即用於下一個 API 請求
- **THEN** 該請求被拒，不因任何快取而在殘窗內通過

#### Scenario: 清單外來源位址被拒

- **WHEN** 某 agent 主體設有允許來源網段清單，而請求自清單外的位址送出
- **THEN** 該請求被拒，對外回應與其他拒絕情形逐位相同；清單為空的主體不受位址限制

#### Scenario: owner 停用即使 token 失效

- **WHEN** agent 主體本身仍為啟用，但其 owner 帳號被停用
- **THEN** 該主體全部 token 的後續請求皆被拒

#### Scenario: owner 外部身分憑證失效同樣使 token 失效

- **WHEN** owner 帳號仍為啟用，但其外部身分憑證失效（憑證世代進位）
- **THEN** 該主體全部 token 的後續請求皆被拒，與 owner 帳號被停用的結果一致

#### Scenario: 拒絕原因對外不可區分

- **WHEN** 分別以不存在的、已撤銷的、已停用的 agent token 呼叫同一個 API
- **THEN** 三次的對外回應本體相同（同一機器碼、同一訊息），無法據以判斷該 token 是否曾經有效；審計側三次各記其真實拒絕原因

#### Scenario: agent token 不得走人類路徑

- **WHEN** 以 agent token 呼叫刷新、改密或 MFA 相關端點
- **THEN** 請求被拒，且 SHALL NOT 簽發任何刷新憑證或會話憑證

#### Scenario: 兩種憑證不互相誤判

- **WHEN** 以人類 JWT 呼叫 API
- **THEN** 走既有 JWT 判定路徑、脈絡欄位與既有一致，主體種類標示為 `human`；SHALL NOT 進入 agent token 的雜湊查表路徑

### Requirement: 自動化主體憑證失效即終止既有會話

下列四種事件 SHALL 即時終止由該憑證建立的全部進行中協議會話，沿用帳號停用既有的即時終止語義，SHALL NOT 等待閒置逾時：撤銷一把 agent token、停用一把 agent token、停用 agent 主體、該 agent 主體的 owner 失效（帳號停用或其外部身分憑證失效，兩者等效）。終止範圍 SHALL 以會話建立時所用的 token 為準（撤銷單一 token 時 SHALL NOT 波及同主體其他 token 建立的會話），主體或 owner 被停用時 SHALL 涵蓋該主體全部 token 的會話。

終止的時效 SHALL 以**目標 3 秒內**表述：逾目標仍未終止的會話 SHALL 另記一筆逾時事件（帶會話識別值與實際耗時），使「說要斷」與「真的斷了」之間的落差被記錄而非被掩蓋。任何實測的毫秒級數字 SHALL NOT 被表述為終止時限——單次量測不是保證，且本要求同時容許個別終止失敗。

每一種事件 SHALL 各留獨立審計事件，並 SHALL 於終止事件中記錄被終止的會話識別值清單——「撤銷了什麼」與「因此斷了哪些連線」須能分別回答。既有的停用即斷、競態複查與自動鎖定不斷線三項語義 SHALL NOT 因本要求改變。個別會話終止失敗 SHALL NOT 使撤銷本身回滾（撤銷已生效是主要目標），失敗 SHALL 留痕供人工跟進。

#### Scenario: 撤銷 token 即斷其會話

- **WHEN** 某 agent token 有進行中的 SSH 會話時該 token 被撤銷
- **THEN** 該會話立即被終止，審計中同時可見撤銷事件與帶被終止會話識別值的終止事件

#### Scenario: 撤銷單把 token 不波及同主體其他 token

- **WHEN** 同一 agent 主體的兩把 token 各有一場進行中會話，其中一把被撤銷
- **THEN** 只有該把 token 建立的會話被終止，另一把的會話繼續

#### Scenario: 停用 owner 即斷該主體全部會話

- **WHEN** 某 agent 主體有多場進行中會話時其 owner 被停用
- **THEN** 該主體全部進行中會話被終止，且其後以任何該主體 token 發起的新連線被拒

#### Scenario: 逾目標時效的終止留痕

- **WHEN** 撤銷後某場會話的終止耗時超過目標時效
- **THEN** 該會話仍被終止，且系統另記一筆逾時事件帶其識別值與實際耗時

#### Scenario: 終止失敗不回滾撤銷

- **WHEN** 撤銷 token 後其中一場會話的終止失敗
- **THEN** 撤銷仍然生效（該 token 後續請求被拒），失敗留痕

### Requirement: 自動化主體的路由範圍限縮

以 agent 憑證認證的請求 SHALL 採預設拒絕：僅明列於允許清單的端點放行，其餘一律回 403 並留痕。允許範圍 SHALL 為下列且僅為下列：可視範圍內資產的唯讀查詢、資產帳號的唯讀查詢、建立存取申請、查詢自己的申請狀態、撤回自己的申請、查詢自身的連線、提交任務報告、自動化執行者的服務介面端點。下列面向 SHALL 一律拒絕，無例外：緊急存取、密碼與憑證變更、政策與授權管理、帳號與群組管理、核准或駁回申請、建立其他自動化主體或為任何主體發放 token。

**一次性連線 token 的申請端點與三類連線端點（終端、圖形協議、資料庫查詢主控台）SHALL NOT 列入允許清單**：自動化主體建立連線 SHALL 只經自動化執行者的服務介面在後端行程內完成。理由是回傳內容的敏感資料遮罩只作用於該服務介面的回傳路徑；若自動化主體能自行取票並直接開啟連線端點，它就取得了一條未經遮罩的原始輸出通道，使該項控制成為可由被控者自行關閉的設定。人類憑證對這些端點的既有行為 SHALL NOT 改變。

允許清單 SHALL 以顯式登記為準，新增端點 SHALL 於未登記時預設被拒——SHALL NOT 採「列出禁止項、其餘放行」的形式，後者使每一條新路由都成為未經判定即開放的面。拒絕 SHALL 使用可辨識的機器碼，且 SHALL NOT 因目標資源是否存在而有不同回應（不得成為存在性探測面）。人類憑證的路由判定 SHALL NOT 受本要求影響。

#### Scenario: agent 憑證打管理端被拒

- **WHEN** 以 agent token 呼叫帳號管理、授權管理或緊急存取端點
- **THEN** 回 403 並帶可辨識機器碼，請求不進入業務邏輯，拒絕留痕

#### Scenario: agent 憑證的允許範圍可用

- **WHEN** 以 agent token 列出自身可視資產、建立申請或查詢自己的申請狀態
- **THEN** 請求正常處理

#### Scenario: 未登記的新端點預設被拒

- **WHEN** 新增一條端點但未登記於 agent 允許清單，以 agent token 呼叫之
- **THEN** 回 403；SHALL NOT 因未列於任何禁止清單而放行

#### Scenario: agent 憑證打連線端點被拒

- **WHEN** 以 agent token 申請一次性連線 token，或直接開啟終端、圖形協議或資料庫查詢主控台的連線端點
- **THEN** 回 403；建立連線 SHALL 只能經自動化執行者的服務介面

#### Scenario: agent 不得為自己或他人發證

- **WHEN** 以 agent token 呼叫建立主體或建立 token 的端點
- **THEN** 回 403，無論目標主體是誰
