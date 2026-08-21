# route-registration Specification

## Purpose
規範 HTTP 路由註冊的結構安全：路由註冊單一入口、全域中間件鏈與順序為契約、以靜態守衛防止繞過單一入口，以及路由與中間件鏈的迴歸保護。
## Requirements
### Requirement: 路由註冊單一入口
所有 HTTP 路由註冊 SHALL 收斂於 `cmd/server` 的單一純函式 `registerRoutes`。該函式 SHALL 只執行 gin 的 `Use`／`Group`／HTTP method 註冊與 handler 的 `RegisterRoutes` 呼叫，SHALL NOT 執行任何初始化、I/O、資料庫存取、scheduler 啟停、或可導致行程終止（`log.Fatal*`／`os.Exit`）的呼叫。Production 啟動路徑與測試 SHALL 呼叫同一個 `registerRoutes`，使測試觀察到的路由集合與 production 實際註冊者同源。所有 service 初始化、handler 建構與依賴注入、scheduler lifecycle、`defer` 清理 SHALL 留在 `main()`，且 SHALL 於呼叫 `registerRoutes` 之前完成 handler 的全部依賴注入。

#### Scenario: 測試可取得與 production 同源的路由集合
- **WHEN** 測試以組裝完成的 `routeDeps` 呼叫 `registerRoutes(gin.New(), deps)`
- **THEN** 取得的路由集合與 production 於相同組態下註冊者完全一致，且過程不需連線資料庫、不啟動 scheduler、不啟動 HTTP server

#### Scenario: 註冊函式不含副作用
- **WHEN** 檢視 `registerRoutes` 的實作
- **THEN** 其中不存在初始化、I/O、DB 存取、scheduler 啟停或 fatal 呼叫；此類語句一律位於 `main()`

### Requirement: 全域中間件鏈與順序為契約
全域中間件的完整鏈與順序 SHALL 為 **Logger → Recovery → Metrics → CORS → audit**，且 SHALL 被視為契約而非實作細節。其中 Logger 與 Recovery 由 `gin.Default()` 提供，Metrics、CORS 為顯式掛載，`AuditLogMiddleware` SHALL 依 `FEATURE_AUDIT_LOG_ENABLED` 條件掛載。中間件鏈 SHALL 於註冊當下對路由生效——gin 在註冊時即合併 handler 鏈，其後的 `Use` 不回溯既有路由——故若有路由先於自訂全域中間件註冊，其鏈 SHALL 僅含 Logger → Recovery。變更鏈內容或順序 SHALL 視為行為變更，須經明確的 spec 修訂。

**該條件在 release 模式下 SHALL 恆為真**：審計旗標屬 release 安全底線，於旗標值的決定處被強制為啟用（見 deployment-hardening「release 安全底線不得由 feature flag 關閉」），故 release 模式不存在「全域鏈缺少 audit 段」的可達組態。條件掛載的分支本身 SHALL 保留——非 release 模式仍須能關閉。

`/swagger` 退場後，`registerRoutes` 內 SHALL NOT 再有先於自訂全域中間件註冊的路由；所有路由 SHALL 具備完整的全域鏈。此狀態 SHALL 由鏈比對迴歸保護，新增「早於全域中間件註冊」的路由會使鏈指紋比對失敗。

#### Scenario: 完整全域鏈
- **WHEN** 檢視任一路由
- **THEN** 其中間件鏈前綴為 Logger → Recovery → Metrics → CORS，且在審計啟用時包含 audit

#### Scenario: 註冊順序造成的短鏈可被偵測
- **WHEN** 有人將某條路由移到自訂全域中間件的 `Use` 之前註冊
- **THEN** 該路由的鏈指紋比對失敗——gin 於註冊當下定鏈，其後的 `Use` 不回溯

#### Scenario: 審計中間件對後續路由生效
- **WHEN** `FEATURE_AUDIT_LOG_ENABLED=true` 且客戶端呼叫任一受審計的 API
- **THEN** 該次操作於 `audit_logs` 產生對應記錄

#### Scenario: release 模式的審計段不可被環境變數移除
- **WHEN** `GIN_MODE=release` 且 `FEATURE_AUDIT_LOG_ENABLED=false`
- **THEN** 全域中間件鏈仍含 audit 段，`/audit-logs` 三條路由仍註冊

#### Scenario: 順序變更須經 spec 修訂
- **WHEN** 有人調整全域中間件的相對順序
- **THEN** 對應 spec 須同步修訂；僅改程式碼而未改 spec 的變更視為違反契約

### Requirement: 路由結構守衛
專案 SHALL 具備永久性的靜態守衛，禁止 `cmd/server` 於 `registerRoutes` 以外的位置變更路由。守衛的方法清單 SHALL 以 pinned gin 版本的 `IRoutes` method set 為唯一事實來源，涵蓋 `Use`／`Handle`／`Any`／`GET`／`POST`／`DELETE`／`PATCH`／`PUT`／`OPTIONS`／`HEAD`／`Match`／`StaticFile`／**`StaticFileFS`**／`Static`／`StaticFS`，外加 `Group` 與 handler 的 `RegisterRoutes` 呼叫。

守衛 SHALL 以**型別解析**（`go/types`）判定 receiver 與參數是否為 gin router，SHALL NOT 以識別字名稱推測型別。判定基準為下列二者之一：

1. 該型別或其指標實作 `gin.IRoutes`；
2. 該型別是**介面**（或型別參數，取其 constraint），且**至少宣告一個路由方法**，且 `*gin.Engine` 或 `*gin.RouterGroup` 實作它。

第 2 條為必要條件而非冗餘：窄化介面只需宣告單一方法即可持有 `*gin.Engine`——`type getOnly interface{ GET(string, ...gin.HandlerFunc) gin.IRoutes }` 不實作完整 `IRoutes`，卻能接收 engine 並註冊路由；泛型形態（`func f[T getOnly](r T)`）同理。其判準 SHALL 為「**真實的 gin router 可賦值進該型別**」，SHALL NOT 為「方法簽章與 gin 相同」：具體型別即使簽章完全相同也無法承接 router，不構成繞過管道，僅憑簽章判定會將其誤報。「至少宣告一個路由方法」的限制不可省，否則 `any`／`interface{}` 亦滿足「gin router 可賦值進去」而使全專案的空介面參數誤報。此判定使 `*gin.Engine`／`*gin.RouterGroup`／`gin.IRouter`／型別別名／import alias／自訂包裝型別／窄化介面／泛型 constraint 一律涵蓋。receiver 為非識別字運算式者（struct 欄位、slice／map 元素、函式回傳值）SHALL 同樣被判定。handler 交棒（`RegisterRoutes`）SHALL 以該 selector 的簽章是否收受 gin router 判定，涵蓋 method value、interface method、embedded method 與泛型 receiver 實例化。以名稱推測型別的實作 SHALL 視為缺陷：其名稱集合跨越 lexical scope，對非 gin 的同名方法必然誤報，且會使 self-check 的正向案例因同名宣告而意外通過。

`registerRoutes` 的豁免 SHALL 綁定唯一的頂層宣告**本身**，SHALL NOT 僅比對函式名稱，亦 SHALL NOT 及於其內部的匿名函式。歸屬判定 SHALL 取**最內層**函式節點（`FuncDecl` 或 `FuncLit`）：否則 `registerRoutes` 內 `escaped = func() { r.GET(...) }` 這類逸出的 closure 會共享豁免，於別處執行時憑空多出一條路由而守衛全綠。

豁免 SHALL 僅及於**同步的直接呼叫**：`registerRoutes` 內的路由方法 SHALL 只作為呼叫運算式的函式位置出現（外層括號不影響此判定），SHALL NOT 被提取為 method value 儲存或傳遞，亦 SHALL NOT 以 `go` 陳述呼叫。`lateGET = r.GET` 一旦成立，實際註冊即可逸出至任一沒有 router 參數、也沒有路由 selector 的函式執行；`go r.GET(...)` 則使註冊時機落在函式返回之後，快照與測試皆已看不到。兩者屆時所有防線皆不命中。

`cmd/server` 內任何位置（**含 `registerRoutes` 本身**）SHALL NOT 直接讀寫 gin router 的中間件鏈欄位 `Handlers`。`r.Handlers = append(r.Handlers, mw)` 的效果等同甚至可覆寫 `r.Use(mw)`，卻完全不經過任何方法 selector；先逸出（`hs := r.Handlers`）再修改亦同。掛載全域中間件的正當途徑只有 `Use`。

守衛 SHALL 同時阻擋間接繞過：`cmd/server` 內除 `registerRoutes` 外，SHALL NOT 有任何函式、method 或**匿名函式**接收 gin router 型別參數。

`cmd/server` 下 SHALL NOT 存在帶任何 build constraint 的 production 原始檔。帶約束的檔案對型別檢查可能完全隱形，且 tag 組合可能互斥而無法一次載入；故守衛採**禁止其存在**而非嘗試掃描其內容。約束存在性 SHALL 由**直接解析**判定——檔頭的 `//go:build`／`// +build` 指示，以及 `_GOOS`／`_GOARCH` 檔名後綴；SHALL NOT 以「是否落在當前建置的檔案集合」反推，因為當前為真的約束（於 Linux 上的 `//go:build linux`）依然編入該集合，換平台才消失，本機驗證會全綠。檔頭 SHALL 以 `go/parser` 解析而非逐行字串比對：後者會被 UTF-8 BOM（Go 工具鏈移除、`TrimSpace` 不移除）與區塊註解內的 `package` 字樣騙過，兩者皆足以令約束指示隱形。區塊註解內的 `//go:build` SHALL NOT 視為約束（不符 Go 規則）。檔名後綴清單為硬編且存在版本漂移風險，惟漂移 SHALL NOT 造成繞過——漏列的後綴若當前為真則檔案照常進入型別檢查，為假則落入型別檢查涵蓋率防線。守衛 SHALL 另行斷言每個 production 原始檔都確實進入型別檢查，使前兩道防線的涵蓋率不留死角。掃描範圍排除 `_test.go`。

已知邊界（SHALL 明載，SHALL NOT 以「已有守衛」含混帶過）：

- 跨 package 的**一般函式**交棒（`main()` 呼叫 `otherpkg.Install(r)`）——package-qualified 的函式呼叫既非 method 亦無 selection 可判。此缺口 SHALL 明載為已知限制。
- **反射**動態註冊（`reflect.ValueOf(r).MethodByName("GET").Call(...)`）——靜態 selector 掃描本質上看不到。
- **整體覆寫 router 值**（`*r = *gin.New()`、`r.RouterGroup = gin.New().RouterGroup`）——不含任何路由方法或 `Handlers` selector，可使後續註冊落到另一個 engine 上。

本守衛 SHALL NOT 宣稱涵蓋所有可編譯形態。其威脅模型為**非蓄意的繞過**——維護者為圖方便而在 `registerRoutes` 外註冊路由；SHALL NOT 假設守衛能抵抗蓄意規避者，因為守衛本身是測試檔，具備 commit 權限者刪除它即可。上列邊界依此判準列為不修。

守衛 SHALL 附掃描器 self-check，對每一種方法、每一種間接傳遞形態、每一種非識別字 receiver 形態、以及 build-tagged 檔案各建樣本。self-check SHALL 以 **multiset 相等**比對預期違規（函式＋種類），使漏報與誤報同時可被偵測；SHALL NOT 僅斷言「至少一項違規」——該斷言會讓一道防線的命中掩蓋另一道的失效。self-check SHALL 含負向樣本：非 gin 物件的同名方法、與註冊函式參數同名的非 router 識別字、內層 shadowing，皆不得被判違規。各正向樣本 SHALL 使用互不相同的識別字，避免案例間相互污染。

#### Scenario: 在註冊函式外新增路由被擋
- **WHEN** 有人於 `main()` 或其他 `cmd/server` 函式中加入 `r.GET("/x", h)`
- **THEN** 結構守衛測試失敗並指出違規位置

#### Scenario: 間接繞過被擋
- **WHEN** 有人將 `*gin.Engine` 傳入另一個 helper 函式並於其中註冊路由
- **THEN** 結構守衛因該函式接收 gin router 型別參數而失敗

#### Scenario: 非識別字 receiver 同樣被擋
- **WHEN** 有人以 `holder.router.GET(...)`、`routers[0].GET(...)` 或 `newEngine().GET(...)` 註冊路由
- **THEN** 守衛經型別解析判定 receiver 為 gin router 而失敗

#### Scenario: 非 gin 的同名方法不得誤報
- **WHEN** `cmd/server` 中存在 `cache.Use(...)`、`svc.Group(...)` 等非 gin 物件的同名方法呼叫
- **THEN** 守衛不將其判為路由變更

#### Scenario: 窄化介面／泛型 constraint 被擋
- **WHEN** 有人宣告 `type getOnly interface{ GET(string, ...gin.HandlerFunc) gin.IRoutes }` 並以 `func hidden(r getOnly)` 或 `func hidden[T getOnly](r T)` 接收 engine 後註冊
- **THEN** 守衛因 `*gin.Engine` 實作該介面且該介面宣告了路由方法而失敗——不得因其未實作完整 `IRoutes` 而放行

#### Scenario: 簽章相同的具體型別不得誤報
- **WHEN** `cmd/server` 中存在方法簽章與 gin 完全相同的具體型別（`func (fake) GET(string, ...gin.HandlerFunc) gin.IRoutes`），且某函式僅接收該型別而未碰觸 router
- **THEN** 守衛不將其判為違規——具體型別無法承接 `*gin.Engine`

#### Scenario: 中間件鏈欄位不得直接讀寫
- **WHEN** 有人以 `r.Handlers = append(r.Handlers, mw)` 或先取出 `hs := r.Handlers` 再修改，藉此掛載全域中間件
- **THEN** 守衛失敗——該路徑不經任何方法 selector，僅掃方法者對此無感

#### Scenario: 註冊函式內以 go 陳述延後註冊被擋
- **WHEN** 有人於 `registerRoutes` 內寫 `go r.POST("/async")`
- **THEN** 守衛失敗——註冊時機落在函式返回之後，golden 快照與行為測試皆已錯過

#### Scenario: 註冊函式內取 method value 被擋
- **WHEN** 有人於 `registerRoutes` 內寫 `lateGET = r.GET`，將註冊能力提取後交由他處執行
- **THEN** 守衛因該路由方法未作為直接呼叫出現而失敗

#### Scenario: 註冊函式內逸出的匿名函式被擋
- **WHEN** 有人於 `registerRoutes` 內寫 `escaped = func() { r.GET("/late") }`，將註冊延後至函式外執行
- **THEN** 守衛以最內層函式節點判定歸屬，該匿名函式不共享 registrar 的豁免而失敗

#### Scenario: build constraint 隱藏被擋
- **WHEN** 有人於 `cmd/server` 新增帶 build constraint 的原始檔
- **THEN** 守衛因該檔帶有約束而失敗，**不論該約束於當前平台為真或為假**

#### Scenario: 掃描器自檢
- **WHEN** 執行守衛的 self-check
- **THEN** 內建的各類違規樣本全部被偵測且種類正確，負向樣本全數不被誤報；掃描器若失效，self-check 先行失敗而非靜默放行

### Requirement: 路由與中間件鏈的迴歸保護
路由集合與中間件鏈 SHALL 具備**可重跑**的迴歸保護——baseline 若無任何程式碼消費，即等同不存在。路由 characterization SHALL 以 `Method`＋`Path`＋`Handler` 三元組表示，並涵蓋所有**可達**的部署組態；`release` 模式因強制啟用權限檢查，SHALL NOT 將「release 且權限檢查關閉」列為待驗組態。中間件鏈 SHALL 以 `gin.Context.HandlerNames()` 取得並比對，不得僅比對路由集合即宣稱行為不變。baseline 檔案 SHALL 置於隨 package 存續的位置（如 `testdata/`），SHALL NOT 置於會因 change 歸檔而被搬移的目錄。baseline 載入時 SHALL 驗證其自身完整性（routes 與 chains 鍵集相等、無重複鍵、欄位非空），使刪除 baseline 中某條記錄無法靜默削弱保護。

保護分兩層且職責不同，二者皆為必要：
- **結構層（鏈比對）**：保證「掛了哪些中間件、順序為何」。能偵測中間件被移除或順序變動，但無法偵測「中間件仍在而其邏輯失效」。
- **行為層（HTTP 測試）**：以實際請求驗證中間件確實生效，SHALL 涵蓋受保護端點拒絕未認證請求、公開端點不被誤擋、全域中間件實際作用、條件註冊端點隨旗標存在或消失。

行為層的下列情境**因需真實 JWT 簽發與資料庫而尚未納入現行覆蓋**，SHALL 於後續迭代補足：**低權限帳號的 403**、權限常數是否正確對應（如 `PermAssetView` 被誤換為 `PermAssetDelete`——中間件仍在、鏈指紋相同、未認證仍 401，三層皆無感）、以及審計中間件是否確實落列。此限制 SHALL 明載，不得以「已有測試」含混帶過。

#### Scenario: 路由集合迴歸
- **WHEN** 路由註冊結構被修改
- **THEN** 三元組比對逐條檢出差異，計數相同但內容不同亦會被偵測

#### Scenario: 中間件鏈迴歸
- **WHEN** 某路由的中間件鏈被更動（例如漏掛權限檢查）
- **THEN** 該路由的鏈指紋比對失敗

#### Scenario: 權限退化被偵測
- **WHEN** 權限旗標因錯誤而恆為關閉，導致路由不再掛載權限檢查
- **THEN** 鏈比對偵測到受影響路由的中間件鏈少了權限檢查一段，測試失敗（此情境不需 HTTP 層即可捕捉，因路徑集合不變而鏈必變）

#### Scenario: baseline 位置穩定不隨開發資料搬移
- **WHEN** 產生此 baseline 的開發變更完成、其開發過程資料被歸檔
- **THEN** 迴歸測試仍能讀取 baseline 並通過——baseline 存放於受版控的固定位置，不置於會被歸檔搬移的目錄下

#### Scenario: baseline 被削弱時不得靜默通過
- **WHEN** 有人自 baseline 刪除某條路由的中間件鏈記錄
- **THEN** 載入時的完整性驗證失敗，而非讓該路由悄悄失去鏈保護

#### Scenario: 中間件邏輯失效被偵測
- **WHEN** 認證中間件仍掛載於鏈上但其攔截邏輯失效
- **THEN** HTTP 行為測試中「受保護端點未帶認證」的案例取得非 401 回應，測試失敗

#### Scenario: 不可達組態不列入驗證
- **WHEN** 建立部署組態矩陣
- **THEN** `release` × 權限檢查關閉的組合不列入，因該組態於執行期被強制修正為啟用

