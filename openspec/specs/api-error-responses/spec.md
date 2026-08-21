# api-error-responses

## Purpose

HTTP API 錯誤回應的統一封套（`{error, code?, params?}`）、機器碼＋前端查譯的錯誤訊息 i18n（三語完備性守門）、資訊洩漏防護與前端單一 toast 來源。
## Requirements
### Requirement: 統一錯誤封套格式
所有 HTTP API 端點的錯誤回應 SHALL 使用 JSON 封套，其中錯誤**文字**僅由 `error` 欄承載（繁中 legacy fallback），並 SHALL 附加機器可讀的 `code`（以及需要時的插值 `params`）成為 `{"error": <繁中訊息>, "code": <機器碼>, "params": <受控值>}`。`error` 欄 SHALL 必填且為非空字串，作為未在地化錯誤的 fallback。`code` SHALL 為集中登記的穩定識別字並符合 grammar `^[A-Z][A-Z0-9_]{0,63}$`（全大寫）；**系統中無 out-of-system 例外**——原有的小寫 legacy code（`break_glass_disabled`、傳輸閘 `ack_required`/`strict_reject`）已全數改為登記碼（`RULE_BREAK_GLASS_DISABLED`、`VALIDATION_TRANSMISSION_ACK_REQUIRED`/`VALIDATION_TRANSMISSION_STRICT_REJECT`），前端控制流分支同步改值，守衛的 legacy 豁免清單 SHALL 保持為空（新增條目須附書面理由）。`params` 存在時 SHALL 依其 code 登記的 schema 驗證，僅含受控值（數值與語義 ID，如 `resource`、`role`），SHALL NOT 含後端任意字串或已翻譯文字。HTTP status code SHALL 正確反映錯誤類別（4xx 客戶端錯誤、5xx 伺服器錯誤）；**syslog 轉發測試端點的 HTTP 200 `{data:{success:false}}` 例外已解除——該端點送達失敗 SHALL 回 502＋registered `code`，與通知通道測試端點同語義，錯誤封套不再有結果契約型例外**。錯誤**文字** SHALL NOT 由 `detail`、`success`、`message` 等其他欄位承載；但結構化、非文字的 metadata 欄（`code`、`params`、`required_permission`、`kind`、`risks`、`reason`、`policy`）MAY 與 `error` 並存。**使用者可見的 HTTP 錯誤回應 SHALL 全域帶 registered `code`**——凡由 `internal/{api,middleware,sshproxy,proxy,k8sproxy,dbproxy}` 與 `cmd/server` 產生的錯誤回應皆在此範圍內；過渡期未遷移者 SHALL 僅以 grandfather allowlist 列管並以清單歸零為收斂目標。

#### Scenario: 驗證錯誤回應格式
- **WHEN** 客戶端送出格式錯誤的請求（如缺少必填欄位）
- **THEN** 回應為 HTTP 400 且 body 以 `error` 承載可讀訊息並附合法 registered `code`，錯誤文字不出現在 `detail`/`success`/`message` 欄

#### Scenario: 通知通道測試失敗不再回 200
- **WHEN** 管理員測試通知通道且通道不可達
- **THEN** 回應為 HTTP 502 且 body 為 `{"error": <含安全診斷摘要的訊息>, "code": <registered code>}`，而非 HTTP 200 + `{"success": false}`

#### Scenario: syslog 測試失敗不再回 200
- **WHEN** 管理員測試 syslog 轉發設定且目的地不可達（dial/write 失敗）
- **THEN** 回應為 HTTP 502 且 body 帶 registered `code`，而非 HTTP 200 + `{data:{success:false}}`；錯誤封套無結果契約型例外

#### Scenario: 權限不足回應 403 且錯誤文字單一來源
- **WHEN** 使用者存取無權限的資產
- **THEN** 回應為 HTTP 403，錯誤文字僅以 `error`（或其 `code` 查譯）承載，`required_permission` 作為結構化 metadata 並存不承載錯誤文字

#### Scenario: 參數化錯誤帶受控 params
- **WHEN** 後端回傳「無效的資產 ID」類參數化錯誤
- **THEN** body 為 `{"error":"無效的資產 ID","code":"VALIDATION_INVALID_ID","params":{"resource":"asset"}}`，`params` 只含語義 ID 供前端經 enum 查譯後插值，不含後端翻譯文字

#### Scenario: 全域錯誤皆帶 registered code
- **WHEN** 任一 handler、middleware、proxy 或 `cmd/server` 端點回錯
- **THEN** 回應帶符合 grammar 且在後端 registry 登記的 `code`；一項全域守衛測試斷言這些路徑不再回無 `code` 的錯誤，僅 grandfather allowlist 內的過渡條目例外

#### Scenario: legacy 小寫碼不復存在
- **WHEN** 掃描全部錯誤回應路徑與守衛的 legacy 豁免清單
- **THEN** 不存在任何 out-of-system 小寫碼；豁免清單為空，任何小寫碼直寫皆被 sink 守衛判紅

### Requirement: 內部錯誤不洩漏
對於 5xx 等級錯誤，API SHALL 回傳泛化的使用者可讀訊息（如「查詢資產失敗」），SHALL NOT 將內部錯誤原文（資料庫錯誤、SSH 庫錯誤、檔案系統錯誤、驗證庫輸出、K8s/kubectl stderr、容器內路徑、guacd 握手原文、錄製轉檔錯誤、syslog dial/write 錯誤、快照解析與 wrapped DB 錯誤）包含在回應 body 中。完整錯誤上下文（原始錯誤、請求路徑、使用者識別）SHALL 記錄於伺服器端日誌。安全化 writer SHALL 支援指定 HTTP status（500/502），使脫敏不改變既有錯誤類別。

#### Scenario: 資料庫錯誤被泛化
- **WHEN** 資料庫操作失敗（如連線中斷）
- **THEN** 客戶端收到 HTTP 500 + 泛化訊息，伺服器日誌含原始錯誤與請求上下文，回應中不出現 GORM/SQL 錯誤原文

#### Scenario: 連線類錯誤轉為使用者可行動訊息
- **WHEN** SSH/SFTP 對目標資產撥接失敗
- **THEN** 客戶端收到的訊息為分類後的可行動描述（如「目標主機認證失敗」「無法連線目標主機」），不含 ssh 庫原始錯誤字串

#### Scenario: K8s 檔案傳輸錯誤不洩漏容器細節
- **WHEN** K8s pod 檔案上傳/下載（copy to/from pod）失敗
- **THEN** 客戶端收到 HTTP 502 泛化訊息＋code，回應 body 不含 kubectl stderr 或 server-derived 內部路徑，原始錯誤僅記於伺服器日誌（使用者自帶的請求路徑，如下載指定的 srcPath，可比照 REST 慣例原樣回顯，非內部洩漏）

#### Scenario: K8s 連線 unknown 分支不拼原始錯誤
- **WHEN** k8sproxy 連線錯誤落入 unknown 分類
- **THEN** 回傳固定泛化語（不 `"連線 K8s 失敗:"+原始 err`），使其所有消費點（pod 選擇、連線建立）都不外洩原始錯誤

#### Scenario: guacd 握手與錄製轉檔錯誤被泛化
- **WHEN** guacd 握手失敗或錄製格式轉換失敗
- **THEN** 客戶端收到泛化訊息，body 不含握手原文或轉檔器/檔案路徑錯誤，原始錯誤僅記於日誌

#### Scenario: syslog 測試失敗不洩漏
- **WHEN** syslog 轉發設定測試 dial/write 失敗
- **THEN** body 不含 dial/write 原始錯誤字串（泛化訊息＋伺服器日誌記原始錯誤）；回應為 HTTP 502＋registered `code`（原「沿用 `{data:{success:false}}`、status 修正列後續」的過渡狀態已結束）

#### Scenario: 快照解析與查詢錯誤被泛化
- **WHEN** 存取複審詳情查詢或快照解析失敗
- **THEN** 客戶端收到 5xx 泛化訊息，回應不含 wrapped DB 錯誤或解析器原始輸出，原始錯誤僅記於日誌

### Requirement: 前端單一錯誤 toast 來源
前端 HTTP 客戶端 SHALL 由共用純函式 `resolveApiError(data, status)` 解析錯誤文字，並依 `code` 三層降級：`code` 合法（符合 grammar）且前端 `apiError.<code>` 有對應譯文時顯示該三語譯文（`params` 中的語義 ID 先經 enum 查譯再插值）；否則退回後端 `error` 欄（繁中）；再否則顯示通用狀態訊息。全域回應攔截器 SHALL 以此函式產生 toast，直讀 `data.error` 的呼叫端 SHALL 共用同一函式（不覆寫 wire data）。呼叫端 SHALL 能以 `skipErrorToast` 停用全域 toast 自行處理。同一 API 錯誤 SHALL NOT 對使用者顯示多於一次 toast。攔截器 SHALL 依**後端回傳的 code** 分類 401（非 URL 前綴，因雙模端點同一 URL 可回兩類 401）：帶 access-token 失效型 code（`AUTH_TOKEN_INVALID`／`AUTH_TOKEN_MISSING`）的 401 SHALL 觸發透明刷新、於刷新終敗時顯示 session 過期並清憑證導向登入；帶其他業務 code（帳密/驗證碼錯等）的 401 SHALL 走 `resolveApiError` 解析且**不**刷新、**不**清憑證導向。**無 `code` 的 401**（新前端＋尚未 code 化的舊後端錯版相容）SHALL 退回既有 URL 規則——非 `/auth/*` 仍觸發刷新、`/auth/*` 不刷新——以維持與未 code 化後端的相容窗口。

#### Scenario: code 命中顯示在地化譯文
- **WHEN** API 回傳合法 `code` 且該 code 在 `apiError.*` 有當前語言譯文，呼叫端未設 skipErrorToast
- **THEN** 攔截器顯示該 code 的當前語言譯文（en-US 英文、ja-JP 日文，含 `params` 經 enum 查譯後插值），非後端繁中原文

#### Scenario: code 未命中退回後端訊息
- **WHEN** API 回應無 `code`、code 不符 grammar、或 code 在 `apiError.*` 無 key
- **THEN** 顯示後端 `error` 欄（繁中）；`error` 亦缺時顯示通用狀態訊息，永不出現空白、裸 key 路徑或把非字串傳給 Element Plus

#### Scenario: 預設由攔截器顯示恰好一次
- **WHEN** API 回傳 4xx/5xx 且呼叫端未設定 skipErrorToast
- **THEN** 攔截器經 `resolveApiError` 顯示恰好一次 toast，view 層不再重複顯示

#### Scenario: 業務 401（含雙模端點）顯示在地化且不被踢出
- **WHEN** 登入帳密錯、MFA 驗證碼錯、或 `/auth/mfa/disable` 密碼錯回 HTTP 401 且 code 為業務碼（如 `AUTH_INVALID_CREDENTIALS`／`RULE_MFA_INVALID_CODE`）
- **THEN** 顯示該 code 在地化譯文（或 `error` fallback），且不刷新、不清除憑證、不強制導向，使用者留在原流程

#### Scenario: 呼叫端接管錯誤呈現
- **WHEN** 呼叫端以 `skipErrorToast: true` 發送請求且 API 回錯
- **THEN** 攔截器不顯示 toast，由呼叫端以同一 `resolveApiError` 決定呈現方式

#### Scenario: access-token 失效 401 refresh 終敗維持導向登入
- **WHEN** 任一請求回 401 且 code 為 `AUTH_TOKEN_INVALID`／`AUTH_TOKEN_MISSING`（含雙模端點如 `/auth/change-password` 自願改密於 access token 過期）且透明刷新最終失敗
- **THEN** 攔截器清除憑證並導向登入頁（access token 過期的既有行為不變，且不誤傷業務 401）

#### Scenario: 無 code 的 401 退回 URL 規則（錯版相容）
- **WHEN** 尚未 code 化的舊後端對非 `/auth/*` 請求回無 `code` 的 401（access token 過期）
- **THEN** 攔截器仍觸發透明刷新（沿用既有 URL 規則），維持與舊後端的相容窗口；無 code 的 `/auth/*` 401 則不刷新（沿用舊行為）

### Requirement: 後端錯誤碼目錄與三語完備性
後端 SHALL 於不依賴 `internal/api` 與 `internal/middleware` 的中立 package（`internal/apierror`）以具名型別 `ErrCode` 集中登記所有錯誤 code，並維護可列舉的全體 registry。錯誤 code SHALL 採分域命名空間（`AUTH_*`、`VALIDATION_*`、`NOTFOUND_*`、`CONFLICT_*`、`INTERNAL_*`、`RULE_<domain>_*`）並符合 grammar `^[A-Z][A-Z0-9_]{0,63}$`。每個 registry 中的 code SHALL 在前端 `apiError.*` 的三語 locale（zh-TW/en-US/ja-JP）皆有非空對應譯文，且三語 `apiError.*` SHALL NOT 有 registry 以外的孤兒 key（雙向 bijection）。已發布的 code SHALL NOT 被改義或重用；退役 code 的三語譯文 SHALL 保留至少一個相容窗口。完備性測試 SHALL 可在開發版 compose 的 backend 容器內執行（`docker compose exec backend go test`，其中三語 locale 由開發版 compose 唯讀掛載）——正式版 compose 不掛載測試用途路徑，故完備性測試不以正式版容器為執行環境。

#### Scenario: 雙向完備性（docker 內可跑）
- **WHEN** 後端測試套件於開發版 compose 的 backend 容器執行（唯讀掛載三語 locale）
- **THEN** 一項測試斷言 registry 與三語 `apiError.*` key 集合完全相等——每個 code 三語皆有非空 key，且無 registry 以外的 `apiError` key；任一不符則失敗並指出 code 與語言

#### Scenario: AST 掃核心 sink 杜絕漏遷與裸字串發碼
- **WHEN** 後端測試套件執行
- **THEN** 一項以 `go/ast` 掃描的測試斷言指定的核心檔案集（middleware 全量＋auth/mfa/user handler）不含帶 `"error"` 的 map literal（含變數中轉 `body := gin.H{"error":...}`）或 index 賦值 `x["error"]=...`（非錯誤封套者以 file:line allowlist 排除）；`apierror` writer 的 code 實參不得為裸字串 literal 或 `ErrCode(...)` 型別轉換；registry 無重複值、無漏登記。（範圍限制：無 go/types 時無法證明識別字/欄位 refs 解析到已登記常量——該殘留由 runtime 未登記 code 降級與 bijection 完備性兜底）

#### Scenario: legacy 小寫 code 明列例外不誤判
- **WHEN** AST 測試掃到頂層 `"code"` 直寫的既有小寫 code（如 `break_glass_disabled`）
- **THEN** 該點在文件化 legacy allowlist 內即放行，不要求其入 registry 或符合 grammar；未在 allowlist 的新違規 code 則測試紅

#### Scenario: code grammar 前後端一致驗證
- **WHEN** 後端登記一個不符 `^[A-Z][A-Z0-9_]{0,63}$` 的 code，或前端收到不符 grammar 的 code
- **THEN** 後端測試拒絕該常量；前端 `resolveApiError` 對不符 grammar 的 code 直接走 `error` fallback，不送入 vue-i18n path

#### Scenario: 新增 code 受完備性守門
- **WHEN** 開發者新增一個後端 error code 但未補齊三語 `apiError.*` 譯文
- **THEN** 完備性測試失敗並指出缺失的 code 與語言，阻止未在地化的 code 進入主線

#### Scenario: 防繁中複製冒充翻譯
- **WHEN** 某 code 的 en-US/ja-JP 譯文與 zh-TW 完全相同且不在同值 allowlist
- **THEN** heuristic 檢查標記該 code 供人工複審，避免以複製繁中假裝已翻譯

#### Scenario: 完備性守衛的掛載點錯位須可偵測
- **WHEN** 三語 locale 的唯讀掛載點缺失或路徑錯位
- **THEN** 完備性測試失敗並指出讀不到被驗證對象，SHALL NOT 以 skip 或通過收場（讀不到被驗證對象即等於沒有守衛）

### Requirement: HTTP 錯誤單一出口
HTTP 錯誤回應 SHALL 僅由 `apierror` 的三個出口產生：`apierror.Respond`（帶 code 的分類錯誤）、`apierror.RespondInternal`（5xx 泛化）、`apierror.Write`（帶 `Code` 的結構化寫出，供需要附帶機器欄的站點使用）。legacy 出口 `api.RespondError`、`api.RespondInternalError`、`apierror.WriteLegacy` SHALL 自程式碼庫刪除，使雙軌在**編譯期**不可回潮。錯誤原文 SHALL NOT 以 `err.Error()` 直傳回應：呼叫點 SHALL 以 `errors.Is` 就地映射已知 sentinel 為登記 code，未知錯誤 SHALL 一律走 `apierror.RespondInternal` 並將原始錯誤留在伺服器日誌。遷移 SHALL 只更換回應形狀，SHALL NOT 改動 HTTP status 或業務邏輯；唯一許可的例外是**理論不可達的防禦分支**（型別窮舉後不存在的 error 路徑）MAY 改判 `RespondInternal` 5xx，且 SHALL 於呼叫點註解說明不可達論證（實例：syslog 設定閘的 CheckSettingSave 防禦分支）。

#### Scenario: legacy 出口編譯期不存在
- **WHEN** 開發者在新程式碼呼叫 `api.RespondError` 或 `api.RespondInternalError`
- **THEN** 編譯失敗（符號已不存在），無法以既有寫法產生無 code 的錯誤回應

#### Scenario: 已知 sentinel 就地映射
- **WHEN** service 回傳可辨識的 sentinel error（如資源不存在、狀態衝突）
- **THEN** handler 以 `errors.Is` 映射為對應 registered code 經 `apierror.Respond` 回覆，回應不含 `err.Error()` 原文

#### Scenario: 未知錯誤走 RespondInternal
- **WHEN** service 回傳未分類的錯誤（如底層 DB/檔案系統錯誤）
- **THEN** 回應為 5xx 泛化訊息＋registered `INTERNAL_*` code，原始錯誤僅記於伺服器日誌

#### Scenario: gate 決策以 Write 保留機器欄
- **WHEN** 連線閘（proxy/sshproxy handler）因政策決策拒絕連線
- **THEN** 回應經 `apierror.Write` 送出，同時帶 registered `code` 與既有機器欄 `reason`/`policy`（機器常數，非散文），前端據 `reason` 的控制流分支行為不變

### Requirement: 內部錯誤碼沿用 action-scoped 命名
5xx 內部錯誤 SHALL 由 `apierror.RespondInternal` 發出並配置 **action-scoped** 機器碼，沿用 registry 既有 `INTERNAL_<RESOURCE>_<VERB>` 慣例：同一 action 既有碼 SHALL 複用，缺者 SHALL 補登記。SHALL NOT 引入 per-domain 泛碼（會與既有碼形成粒度相反的第二套 taxonomy，使同域錯誤依遷移年代呈現不同粒度）。新碼 SHALL 與其他 code 同受三語完備性守門。

#### Scenario: 同 action 複用既有碼
- **WHEN** 某 handler 的資產查詢內部失敗，而 registry 已有對應 action 的 `INTERNAL_ASSET_LIST`
- **THEN** 該站點複用既有碼，不新增同義碼

#### Scenario: 缺碼補登記且三語完備
- **WHEN** 遷移中出現 registry 未涵蓋的內部失敗 action
- **THEN** 新增一個 action-scoped `INTERNAL_*` 碼並補齊 zh-TW/en-US/ja-JP 譯文，缺一則完備性測試失敗

### Requirement: 全域裸錯誤出口守衛
後端 SHALL 具備常駐的 AST 靜態守衛，掃描 `internal/api`、`internal/middleware`、`internal/sshproxy`、`internal/proxy`、`internal/k8sproxy`、`internal/dbproxy` 與 `cmd/server` 下所有非測試 `.go` 檔，偵測直寫使用者可見文字的裸出口（composite literal、變數中轉、index 賦值），偵測鍵 SHALL 為 `{"error","message"}`（`message` 欄同樣直達使用者）。`reason`、`policy` 等**機器欄 SHALL NOT 納入偵測鍵**——它們是前端控制流分支依據，本就應保留。

過渡 grandfather 清單 SHALL 以 **hash multiset** 記錄（條目＝檔名＋該 sink AST 節點經 `go/printer` 標準化列印後的 hash），使 gofmt 重排與行號漂移不產生假綠；測試語義 SHALL 為「掃描結果集與 allowlist 集合相等」——新 hash 必紅、stale hash 必紅。清單 SHALL 由 `-update` 旗標生成（比照 routes golden 慣例），每次 `-update` 的 diff SHALL 於 commit 中逐條審視（尤其新增條目）。

守衛 SHALL 具備防規避機制：掃描檔數低於 60 即 fail；另設**涵蓋斷言**——`internal/` 與 `cmd/` 下任何 import gin 的非測試套件皆 SHALL 在掃描目錄清單內，清單外出現即紅。已知殘餘風險 SHALL 誠實記載：任意 struct 欄位（如 `Message: "中文"`）與偵測鍵以外的鍵名掃不到，此類盲區 SHALL 明載於一份殘量定性清單，不得以「清單歸零」誤讀為「無裸中文」。

#### Scenario: 新增裸出口即紅
- **WHEN** 開發者在任一受掃描目錄新寫 `c.JSON(400, gin.H{"error": "中文訊息"})`
- **THEN** 守衛測試失敗並指出檔案與運算式，該寫法無法進入主線

#### Scenario: 行號漂移不產生假綠
- **WHEN** 受掃描檔案因無關編輯導致既有 sink 行號位移，或經 gofmt 重排換行
- **THEN** 其 hash 不變，allowlist 仍精確對應該條目，既不誤紅也不放行新違規

#### Scenario: stale 條目必紅
- **WHEN** 某 allowlist 條目對應的 sink 已完成遷移而清單未同步
- **THEN** 集合相等斷言失敗（allowlist 有、掃描結果無），迫使清單同步縮減

#### Scenario: 清單外套件被涵蓋斷言攔截
- **WHEN** 開發者在掃描目錄清單以外的套件新增 import gin 的 handler
- **THEN** 涵蓋斷言失敗並指出該套件未納入掃描清單

#### Scenario: message 欄同受偵測
- **WHEN** 某站點以 `gin.H{"message": "中文訊息"}` 回覆使用者可見文字
- **THEN** 守衛測試失敗；同一檔案內以 `reason`/`policy` 攜帶的機器常數則不被誤判

#### Scenario: 遷移完成後守衛仍常駐
- **WHEN** 全部裸出口已完成遷移、grandfather 過渡清單縮減為空
- **THEN** 守衛測試仍常駐於測試套件（不隨遷移完成而移除），並另附一份已知盲區的殘量定性清單

### Requirement: 成功回應不攜帶 UI 文案
成功（2xx）回應 SHALL NOT 攜帶供 UI 直接顯示的 `message` 文案欄——前端 SHALL 以自有 `$t` 文案呈現成功結果。既有以 `message` 攜帶繁中成功訊息的端點 SHALL 移除該欄；若有前端直顯處，SHALL 同步改為 `$t`。以 `Message` 欄承載結果描述的結構化回應（`ConnectionTestResult.Message`）SHALL 改為機器 `code`＋`params`，由前端查譯呈現。

#### Scenario: 成功回應無 message 文案
- **WHEN** 使用者成功建立或更新一筆資源
- **THEN** 回應 body 不含繁中 `message` 欄，前端以自有 `$t` 顯示成功提示，切換語言時提示文字隨之改變

#### Scenario: 連線測試結果碼化
- **WHEN** 管理員對資產執行連線測試且結果為認證失敗
- **THEN** 回應以機器 `code`（＋必要 `params`）表達結果分類，前端以當前語言顯示對應譯文，而非直顯後端繁中 `Message`

