# 開發慣例：架構不變式、安全紅線與程式碼慣例

> 本文記載「改動前必須知道、但看程式碼不會馬上發現」的不變式與慣例。
> 行為規格的權威來源是 `openspec/specs/`；本文是它的導讀與陷阱清單，兩者衝突時以 specs 為準。
> 測試與驗證紀律見 `docs/dev/testing.md`；後端模組邊界與其誠實界定見 `docs/dev/architecture.md`；
> 工作流與提交規範見 `CONTRIBUTING.md`。

## 1. 失敗路徑的兩條對立原則

新增任何失敗處理分支前，先用這兩條定位該 fail-close 還是 best-effort：

- **可用性鐵則：系統絕對不能起不來。** 例如 KEK 切換的收尾不 fail-close——
  這是堡壘機，起不來的代價高於殘留不一致；正解是 best-effort 重試＋明確狀態欄位，
  而不是拒絕啟動。
- **審計鐵則：完全沒有審計軌跡時 fail-close，且 admin 不豁免。** 例如 session 記錄
  INSERT 失敗必須關閉連線＋拒絕升級＋告警（能走到該步代表 DB 讀取正常，屬部分故障）。
  與錄影失敗的差別在「殘留審計程度」：錄影失敗仍留有 session＋指令審計，故可討論例外；
  session 記錄失敗則全無軌跡，無例外。

判斷新失敗路徑時問兩個問題：「失敗後還剩多少審計軌跡」、
「fail-close 會不會讓整台機器不可用」。

## 2. 連線收口（安全紅線）

**前端零接觸明文憑證**：資產憑證只存在後端，前端經一次性 connect token 建線。

- **停用資產必須三位一體硬擋**：token 簽發點、SFTP 入口、所有 token 兌換點都要重查
  資產狀態，缺一即旁路。此設計為定案，不留 backlog、不加 admin 豁免、不得移除。
- **connect token 兌換點必須重跑權限與政策現查**（與簽發點對稱）：否則撤權後的
  殘餘窗口等於 token TTL。
- **admin 特權判定必須查 DB 現值，而非 JWT 快照**：否則被降權的 admin 反而享有
  更長殘窗（特權倒置）。
- **connect token 快照 SHALL NOT 攜帶角色**：`pkg/gatewayapi` 的 `ConnectGrant`
  刻意逐欄複製而不嵌入 `ConnectSubject`，避免 `ClaimedRole` 被帶進 token；
  現況以型別層＋守衛欄位白名單（`gwExactFieldSets`，欄位集合精確相等）雙重約束，
  **是守衛強制而非編譯器強制**——擋的是順手加欄的意外，不是有意繞過。

## 3. WS 入口與 middleware 是兩套認證面

HTTP middleware 之外，各 WebSocket 入口（`/ssh` sshproxy、`/connect` proxy、k8sproxy）
各自有**手動** authenticate。因此：

> 凡新增 scope、gate 或使用者狀態檢查，middleware 與**所有 WS 入口
> ＋connect token 的簽發端與消費端**都要一起補。只改 middleware 會留下完整旁路。

同族事實：

- **auditor 權限是顯式獨立定義**（`backend/internal/modules/authz/route_permissions.go:59-65`
  的 `auditorPermissions`），**不以 `append(userPermissions, …)` 繼承 user**——
  否則從 user 移除 audit/alert view 會連帶架空 auditor。該檔註解已自陳此裁決（`:57-58`）。
- **TOTP 防重放**＝記錄已消耗的 time-step 索引（⌊unix/30⌋）並拒絕 step ≤ last。
  「同窗拒絕」不夠：允許 skew=1 時同時有 3 個有效 step。
- **WS 路由漏掛 AuthMiddleware 不會有任何編譯或測試訊號**——handler 內
  `GetAuthContext(c)` 只會恆回零值。新增 WS 路由時**必須確認 authContext 真的被設進 context**，
  且至少一支測試從真實入口走完（見 `docs/dev/testing.md` 守衛假綠「繞過裝配路徑」形態）。

## 4. 憑證世代與鎖序（OIDC／外部身分）

權威見 `openspec/specs/oidc-auth/spec.md`。動認證相關碼前必知：

- **雙層世代**：provider 層 `auth_epoch` ＋使用者層 `credential_epoch`
  （`backend/internal/model/user.go:70-84`，單調遞增、`json:"-"` 不外露）。
  **自動鎖定刻意不推進世代**——推進會使鎖定成為未認證者可觸發的遠端斷線武器，
  勿當成遺漏「補上」。
- **鎖序固定 system → provider → user**；組合出口為 `WithCapabilityLocks`
  （`backend/internal/modules/identity/oidc_provider_lock.go:118`）。
  鎖內只做 DB 判定與標記；關閉 WS、收線一律在鎖外執行。
- **凡「以既有身分產生新長效能力」皆須鎖內三步**（重查前提 → 讀世代 → 建立）：
  兌換建 session、監看訂閱加入、callback 簽票、exchange、refresh 輪替皆屬之。
  refresh 輪替以 refresh 列**自身**的世代簽發 access，不得改成現查（洗世代缺陷）。
- **角色變更必須推進 `credential_epoch`**：不推進的話，降權前簽出的憑證會活到自然過期。
  已知殘留（現況、誠實記載）：進行中的**唯讀監看訂閱**無時間上界，
  MonitorHub 只在 join 時查一次 role＋世代閘、之後不再重驗；
  錄影播放 rtoken 播放端不查 epoch，殘窗上界＝TTL 120s。
- **簽發／驗證貫穿點的守衛清冊是雙向的**（登記者必須存在＋未登記者不得寫入）；
  新增呼叫點先補清冊。只驗單向（「登記的都還在」）的清冊擋不住**新增一個未登記的
  簽發點**——而那正是這面最容易漏、且漏了不會有任何測試轉紅的方向。

## 5. 錄影與媒體存取的三條獨立路徑

三條路徑各自獨立，勿依註解推斷「媒體走長效 JWT」：

1. **WS 連線**：一次性 connect token，60s TTL、記憶體存放、解析即焚。
2. **圖形錄影（RDP/VNC）**：Bearer header ＋一次抓取完整 Blob，不走 query 參數。
3. **文字錄影（SSH）**：專用短效 rtoken（asciinema-player 只吃 URL、無法加 header），
   不透明隨機值、綁定 (user, session)、TTL 120s 內可重用。

兩種播放器都是「一次抓完整檔 → 前端本地播放」，seek 純本地不重新 fetch——
**rtoken 的 TTL 是取用授權窗口，不是播放時長上限**。

**guacd 對錄影失敗 100% fail-open 且不回傳後端**（上游 `guacamole-server` 原始碼行為：
`recording.c`／`rdp.c`）。因此「會後 stat 檢查」是圖形錄影路徑唯一的後端偵測點，
錄影落地鏈（rename／stat／metadata）的失敗全部要接偵測，勿刪。

**guacd 連線參數真正生效的位置是 `backend/internal/proxy/handler.go`**
（`GuacdHost`／`GuacdPort` 由 `NewConnectionHandler` 收）。改 guacd 行為前先確認呼叫鏈。

## 6. 審計寫入：兩種 sink 與 fail-close 語義

審計列的產生點目前有 **67 個**（AST 全庫掃描判準：產生一筆 `audit_logs` 列的位置），
權威清冊在 `openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md`，
由 `backend/cmd/server/audit_points_manifest_guard_test.go` 雙向守衛。

- **交易內（吃呼叫方 `tx`）＝ 21 點，全部走 `port.TxSink`（同交易 fail-close），零例外**。
  收口形態一律 `port.WriteInTx(sink, tx, ev)`；sink 未注入時回 `port.ErrTxSinkMissing`
  使業務回滾——**「沒接線」也是 fail-close**。
- **非交易內走 `gatewayapi.AsyncSink`（at-most-once，fire-and-forget）**。
- **`model.Asset` 的三個 GORM hook 維持直寫**（`AfterCreate`／`AfterUpdate`／`AfterDelete`，
  `backend/internal/model/asset_audit.go`；以 `tx.Session(&gorm.Session{NewDB: true})`
  脫離呼叫方交易），刻意不改走 sink：改走 sink 需再造一個包級全域的可漏接旗標，
  收益不值該風險。
- **新增審計產生點時必須同步 manifest**，否則守衛紅。交易歸屬欄（是否吃呼叫方 tx）
  由 AST def-use 判定器機器比對，**人工標錯會轉紅**——不要手動「修」成綠的。
- `model.AuditLog` 是 append-only：`(*AuditLog).BeforeUpdate`
  （`backend/internal/model/audit_log.go:387-390`）直接回 `gorm.ErrInvalidValue`，
  ORM 改寫既有審計列不會成功。
- 蓋章與 syslog tee 掛在 `model.SetAuditCreateHooks`
  （`backend/internal/model/audit_log.go:345`，由 `cmd/server` 於啟動第 7 步注入）。
  **此註冊點之前寫出的審計列 HMAC 為空且不進 tee，而驗章端會把空章列當歷史列而不計入
  竄改判定**——失敗形態是「更安靜」而非「更吵」。動 stage2 結構時必須確認註冊時點未後移。

## 7. 啟停順序即契約

`cmd/server` 的啟動步驟、注入點與釋放登記全部登記在
`openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-lifecycle.md`
（機器可讀清冊；受管列數以守衛的 `minLifecycleUniqueIDs` 為準——現況 302、下限釘 260），
並由 `backend/cmd/server/lifecycle_manifest_guard_test.go` 與
`lifecycle_startup_shutdown_test.go` 守住。三個最危險的順序敏感點（失敗形態全部是「安靜」的）：

1. **審計蓋章 hook 的註冊時點**（見上節）。
2. **`StopAlertNotifierForRelease` 依賴 `ResourceBag` LIFO 的隱含前提**：
   「呼叫端先停排程器」無任何程式碼強制，成立僅因兩個排程器碰巧登記在推送器之後。
   移動 bag 登記位置即靜默破壞，症狀是收束 panic（可見）或 in-flight 告警遺失（**不可見**）。
3. **`keyManager.ZeroizeForRelease` 的釋放位置**：它是「封印」在記憶體層面唯一的實體動作。
   登記位置變晚（＝執行變早）時，被丟棄的服務圖在其餘收束期間仍持有可用 codec，
   「封印」退化為路由層的假象，**且這條路徑上沒有任何測試會自動變紅**。

**已知排序張力（現況、誠實記載）**：`auditService.Shutdown` 執行序早於
`connectionRegistry.CloseAll`。HTTP 路徑由 `main.go` 外層順序保證，但**協議連線（WS）
不經 HTTP Shutdown**，理論上存在「審計已 flush、連線仍在寫」的窗口；
現況以 `TestLifecycleKnownUncoveredOrderingTension` 釘住相對序並明記未涵蓋。

## 8. SQL 與資料層陷阱

- **LIKE 整詞比對必須跳脫並明寫 `ESCAPE '\'`**：SQLite 的 LIKE 預設沒有跳脫字元，
  缺了就是「測試綠、生產誤中」（`db_prod` 會誤中 `dbxprod`）。跳脫 `\`、`%`、`_` 三者。
- **欄位改 nullable 時，raw SQL 的 select 與 scan 目標同屬盤查面**：
  raw select 把 nullable 欄掃進非 nullable struct 會導致整頁 500。
  盤查不能只看 GORM model。
- **DB 無外鍵約束時，跨列不變量必須靠鎖＋全交易化**：樹結構變更（節點增刪搬移、
  資產掛載與刪除）一律先取結構鎖，否則並發互搬可建出環、可掛到已刪節點。
- **軟刪除的幽靈成員**會讓空節點永不可刪——涉及成員遷移的 migration
  要排除軟刪組與軟刪資產。
- **GORM `Pluck` 的 dest 必須是 slice**：純量 dest 恆回
  `Scan called without calling Next`；若呼叫端是 fail-close 守門（讀不到即拒），
  就會演成「所有請求被拒」級事故，而單測仍全綠
  （見 `docs/dev/testing.md` 守衛假綠章節形態十）。

## 9. i18n 強制規範

後端使用者可見文字已全面單軌化：**任何新文字不得硬編單語散文**——守衛測試會直接紅，
不是靠自覺。

### HTTP 錯誤：唯一出口是 apierror 三函式

1. `apierror.Respond(c, status, Code, params)`（已知錯誤）、
   `apierror.RespondInternal(c, status, Code, err)`（5xx，細節落 log）、
   `apierror.Write(c, status, ErrorResponse{Code, Meta})`（需附機器欄位如 reason 時）。
   舊的散文回應函式（`api.RespondError`／`RespondInternalError`／`WriteLegacy`）
   **已刪除，編譯期即不可回潮**。
2. 新錯誤碼在 `backend/internal/apierror/codes_<domain>.go` 依 domain 分檔 `register`；
   命名空間 `AUTH_ / VALIDATION_ / NOTFOUND_ / CONFLICT_ / RULE_ / INTERNAL_`
   ＋ `<RESOURCE>_<VERB>`。`err.Error()` 直傳會被守衛擋下；
   已知 sentinel 用 `errors.Is/As` 映射，未知一律 `RespondInternal`。
3. params 有三種 kind：enum（有 `ZhLabels` 允許清單）、int、opaque（自由字串，
   經 `notifycat.SanitizeOpaque` 淨化：128 rune 上限、strip 換行／ANSI／Cf 類控制字元）。
4. 三語 locale（`frontend/src/i18n/locales/*.json`）的 `apiError` 段補鍵；
   zh-TW 與後端 `ZhFallback` 語義一致，由 `TestCodeTranslationsComplete`
   bijection 守衛強制——漏補必紅。
5. 全域 sink 守衛 `TestNoRawErrorSinks` 掃描 handler 層直寫 `{error,message}` 鍵；
   **豁免清單已歸零並保持零**。成功回應不帶 message 文案欄位。

### 出站通知

- 一律走 `NotifyEvent(notifycat 事件常數, params)`；event 必須用匯出常數
  （字面量會被守衛擋）。webhook payload 為 `{event, params, sent_at}` 零散文；
  Slack 類通道由 `notifycat.Render(channel 語言, ...)` 組字（per-channel `language` 欄）。
- 未註冊事件或缺參數時**降級投遞、不得消失**（合規告警不可因格式問題丟失）。
- 審計失敗的 cause 走 `model.Cause*` 機器碼＋params，detail 只落庫不出站；
  `sessions.recording_error` 同碼集。

### WS／終端：送碼、前端查譯

- 錯誤幀 `EncodeErrorMessage(ErrCode, zhFallback)` code 必填；阻斷提示走
  `MsgNotice{Code, Data, Params}`（params 過 `SanitizeOpaque`）。
  **不做伺服端串流渲染、無 lang 參數**（阻斷警告不進錄影是既定行為）。
  串流字面量守衛：sshproxy／proxy 中文字面量僅允許出現在 log 與內部 error。

### vue-i18n 的 `@` 陷阱

vue-i18n 把 `@` 視為 linked message 起手（`@:key`／`@.modifier:key`）。
**訊息內出現裸 `@` 會在 render 期拋 `Invalid linked format` 並中斷整個元件渲染**
——不是顯示錯字，是整頁掛掉，且只在使用者真的觸發該訊息時才炸。

- locale 檔一律寫 `{'@'}`（如「帳號名稱不得以 {'@'} 開頭」）。
- 後端 registry 的 `ZhFallback` 不帶前端模板語法（它是給非前端消費者的 wire fallback）；
  完備性守衛比對前先 `unescapeVueI18nAt` 正規化，**比對語義而非位元組**。
- `i18n.spec.js` 有守衛掃三語全部訊息的裸 `@`。

### 例外（spec 定性）

- 後端 log、啟動期 fail-close 訊息：運維面，不譯。
- 審計欄位的 forensic 原文（如 `audit_logs.error_msg`、`Details`）：保留原文。

## 10. 前端 UI 慣例

### 枚舉顯示鐵則

- 前端枚舉的顯示中繼資料一律走 `frontend/src/constants/` 單一事實源，並附
  「值域硬拷後端（註記後端 file:line）＋完備性單測」。已有多組現成範例可循。
- **勿在元件內手寫 option 陣列或本地 map**——後端新增枚舉值時不會有任何訊號。
  完備性測試要鎖**後端全集**，不是鎖前端目前已映射的值。
- 可指派角色一律走 `/roles` API，不硬編碼。
- 動態枚舉的 i18n 用模板字串 `` $t(`prefix.${var}`) ``，不用字串拼接
  ——否則 key 存在性檢查掃不到。

### Element Plus 實測行為（2.9 實測；「看起來像 bug」的多半是下列已知行為）

- `el-select`：`value=''` 會被當空值而顯示 placeholder；
  解法 `:empty-values="[null, undefined]"`（EP 2.7+）。
- **表格佈局首選「常見可視寬（1280px）內總寬收斂」**；`fixed="right"` 是
  溢寬不可免時的備案——fixed 欄在溢寬時會**蓋住**相鄰資料欄，比「藏在卷軸外」更糟。
  正解＝欄寬收斂＋次要欄移入展開列，讓表格根本不橫捲；真收不下才用 fixed，
  且須以 `getBoundingClientRect` ＋`elementFromPoint` 驗證目標寬度下每欄可見。
- **欄寬不等於內容寬**：`.cell` 預設左右 padding 各 12px，文字被截斷時只調
  `width` 無效，要同時調該欄 padding。（1366 寬螢幕的表格可用寬約 842px。）
- `el-radio-button` 綁 `:value` 而非 `:label`。
- **批量選取的 `reserve-selection` 必須在重置時顯式 `clearSelection()`**：
  EP 內部選擇會跨資料替換保留，重開精靈殘留勾選＝溢授（安全後果，非體驗問題）。
  切換挑選模式時也要清對面模式的殘留。
- `el-tag` 是 inline-block 且不換行，內文過長會**無聲裁掉**
  （text-overflow 對它無效）——多語標籤定稿前要量測最寬語言。
- `el-dropdown` 的包裝元素會破壞相鄰按鈕的 margin（gap 歸零、基線錯位），
  按鈕列混用 dropdown 時要自行補 `margin-left` 與 `vertical-align`。
- **破壞性確認框一律 `autofocus: false`**（否則 Enter 反射直接執行危險操作）。
  本專案已有 `frontend/src/utils/confirm.js:27` 的 `confirmDestructive` 收口，勿繞過。
- `popper-options` 傳入 `preventOverflow` 會**整組取代**內建 modifiers 而破壞 flip
  （選單越出視窗下緣）——要自訂就完整重述所有 modifiers，否則別動。
- 抽屜型功能把內容抽成獨立元件、`el-drawer` 只當殼——單測直接掛內容元件
  （teleport 在測試環境不友善，見 `docs/dev/testing.md`）。

### 篩選與非同步

**伺服端篩選必配 latest-request-wins**：debounce 只降低頻率、不防亂序回應，兩者都要有。

### 同型缺陷換條路徑

修法若綁在「觸發缺陷的那個具體狀態」而非「該不變式應涵蓋的狀態集合」，就必然漏。
UI／互動類修正的驗收要做「**動作 × 狀態**」矩陣掃描（例：`儲存／刪除／測試`
× `loading／loadFailed／正常` 九格逐格實測），不要只驗原路徑。

### 視覺與品牌

- 品牌唯一真相：`docs/DESIGN_SPEC.md`，錨定 `frontend/src/styles/tokens.css` 的 `--ot-*`；
  動品牌 token 須先開 issue 討論。
- 亮底設計的品牌主色直接放暗底會過不了對比度 AA：暗底連結用亮階、品牌原值降為按下態。
  語義色與終端色盤永不隨品牌變動。
- 技術識別字（審計用途的 HKDF info、錄影路徑、module 名、seed email 等）
  **絕不因視覺改版而更名**。

### 頁面結構

每個角色的功能頁單獨切開（原則與實例見 `CONTRIBUTING.md` 設計原則章節）。

## 11. 通用程式碼風格

- **不可變資料優先**；早退出（guard clause）勝過深巢狀。
- **小檔案**：典型 200-400 行，上限 800 行；超過就拆（守衛測試檔亦同）。
- **匯出面是預算**：搬包／重構時不要把「搬包所需」等同「機械大寫化」。
  每新增一個匯出符號都要說得出唯一消費者；優先窄 façade、消費者側宣告的介面、
  或組裝根 adapter（詳見 `docs/dev/testing.md` §11.3 export budget）。
- 產品程式碼須有測試覆蓋關鍵行為（詳見 `docs/dev/testing.md`）。
