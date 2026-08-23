# 測試與驗證指南

> 環境啟動見 `docs/QUICKSTART.md`；架構不變式與 UI 慣例見 `docs/dev/conventions.md`；
> 後端模組邊界與其誠實界定見 `docs/dev/architecture.md`。
> 本文涵蓋：docker 內驗證流程、機器產物重生、Go／前端測試陷阱、守衛測試紀律、
> 突變自檢與故障注入的防呆、flaky 判準與 e2e 煙霧測試。

## 1. 驗證一律在 docker-compose 內

本專案的測試、build、lint 全部在容器內執行；docker 未啟動時不改 code。
開發版 compose（`.env` 設 `COMPOSE_FILE=docker-compose.dev.yml` 後，
日常指令不帶 `-f` 即指向它）含熱重載與全部測試靶機。

```bash
# 後端
docker compose exec -T backend go build ./...
docker compose exec -T backend go vet ./...
docker compose exec -T backend go test ./... -count=1
docker compose exec -T backend gofmt -l .

# 前端
docker compose exec -T frontend npm run test
docker compose exec -T frontend npm run build
docker compose exec -T frontend npm run lint
```

要操作正式版一律顯式 `-f docker-compose.yml`。改了 Dockerfile、`.dockerignore`
或 compose 的 build 區塊後，以 `docker compose -f docker-compose.yml build` 驗證正式版可建置
（image 名已分離：`custodexa/*:latest` 與 `custodexa/*:dev` 互不覆蓋，建置正式版不會覆蓋開發版）。

### 環境坑速查（先照做再排查）

- **改後端多檔後 `docker compose restart backend`**：Air 熱重載在多檔交叉編輯的
  中途破碎狀態會 build 失敗並**悄悄跑舊二進位**。存疑時驗證新碼已編入：
  `docker compose exec -T backend sh -c "strings /app/tmp/main | grep <新函式名>"`。
- **改前端後看不到效果：`docker compose up -d --force-recreate frontend`**。
  macOS bind-mount 的 fsnotify 不可靠，Vite HMR 可能不觸發；
  **勿用 `restart frontend`**（會撞 bind-mount race 導致 `/app/package.json` ENOENT 崩潰）。
  驗證 Vite 真的 serve 新碼：`curl -s localhost:3000/src/components/X.vue | grep <新符號>`。
- **改 `.env` 或 compose 環境變數必須 `up -d --force-recreate`**：
  `restart` 不重載 env（症狀：加了變數仍報未設定）。
- **容器內工具消失（如 `psql: not found`）＝image 過舊**：
  `docker compose build backend` 後再 recreate；`--force-recreate` 用的仍是快取 image。
  若見 `exec: "go": executable file not found`，是容器吃錯 image，force-recreate 即復原。
- **單檔 bind mount 綁 inode**：host 端以 atomic-rename 方式改寫被單檔掛載的檔案後，
  容器內可能讀到「帶部分新內容、缺尾端數行」的中間快照——症狀是「殘檔」而非「舊檔」。
  確診法＝容器內外 `md5sum` ＋行數比對；解法＝force-recreate 該容器，
  **不要去改程式碼找 bug**。
- **改 `vite.config.js` 後必須重啟 frontend**（HMR 不涵蓋它自己）。
- **新增 WebSocket 端點時**，`frontend/vite.config.js` 的 proxy 要加對應 `ws: true` 條目。
- **測試靶機認證失敗（SSH 502）多半是密碼漂移**：靶機容器重建後，DB 內測試資產密碼
  與 compose 設定值對不上。解法：`PUT /api/v1/assets/{id}` 重設密碼。
  注意 `last_test_status=reachable` 只代表 TCP 通，不代表認證通。
- **驗證改密功能勿用共用測試資產**：改密計劃「立即執行」是真輪換，會把靶機帳號
  密碼真的改掉，導致依賴固定密碼的整合測試失敗。測完立即還原：
  `docker compose exec -T ssh-test sh -c "echo 'testuser:testpass123' | chpasswd"`。
- **多帳號功能用 `ssh-multi-test` 靶機**（rootful sshd，root＋testuser 兩帳號可切換）；
  `ssh-test` 是 rootless、**只支援 testuser**，第二帳號建線必失敗
  （channel open error）——這是靶機限制，不是產品 bug。
- **整合測試突然全紅、錯誤是泛用的 `FAILURE`／`permission denied`／寫入失敗時，
  第一步查磁碟**，不要先讀程式碼：`docker compose exec <靶機> df -h /`、`docker system df`。
  磁碟耗盡會偽裝成泛用錯誤——`docker builder prune -af` 清出空間後，
  往往不改任何一行程式碼即自行轉綠。

### 瀏覽器層驗證的邊界

- 自動化瀏覽器與本機共用剪貼簿：測剪貼簿功能前先寫入哨兵值覆蓋，
  測後清理 `clipboard_events`，避免把真實剪貼簿內容（可能含密鑰）留進審計庫。
- a11y snapshot 與自動 click 會**遮蔽「元素滑出可視範圍」的視覺缺陷**
  （snapshot 列得出卷軸外內容、click 會自動捲動）。驗「使用者看不看得到」
  必須用 `getBoundingClientRect` 對照 `window.innerWidth` ＋`elementFromPoint`，或看截圖。
- 以 JS 設定 `input.files` 再 dispatch change **不會**驅動 Vue 的 file input handler
  ——要用正規 file chooser 流程，否則極易誤判成產品 bug。
- 量測幾何用 evaluate script 回傳 `getBoundingClientRect` 數據，比截圖判讀可靠。
- 靜態頁改 CSS 後重載可能吃瀏覽器快取：確診法＝`curl` 比對 server 端；
  解法＝為 stylesheet href 加 cache-bust query 或開全新 page。

## 2. 機器產物重生（動路由必做，守衛會擋）

`docs/API_SPEC.md` 的端點索引與路由 golden baseline 皆由測試生成，
**不可手改**；`TestAPIIndex`（`backend/cmd/server/api_index_test.go:375`）與
`TestRoutesMatchGolden`（`backend/cmd/server/routes_regression_test.go:377`）
是強制守衛，非可選。

```bash
# 端點索引（平時容器的 docs/ 掛載唯讀——守衛不得竄改其驗證對象，
# 故重生須用額外加掛可寫點的一次性容器）
docker compose run --rm --no-deps -v ./docs:/app/cmd/server/testdata/docs-rw backend \
  go test ./cmd/server -run '^TestAPIIndex$' -update

# 路由 golden
docker compose exec backend go test ./cmd/server -run '^TestRoutesMatchGolden$' -update
```

golden 的 diff 須在 commit 中**逐條審視**——它是快照而非不可竄改基準，
盲目 `-update` 等於讓守衛替錯誤背書。`docs/API_SPEC.md` 的散文章節仍為人工維護。

**驗「零 diff」要比 SHA256，不是只看 PASS**：測試 PASS 只代表這次跑的時候一致，
`-update` 會讓 golden 跟著改。正確口徑＝跑完全量測試後**重新雜湊**
`backend/cmd/server/testdata/route-golden/` 下的 4 個 golden 檔
（`dev-auditon`／`dev-auditoff`／`release-auditon`／`release-auditoff`）
與 `docs/API_SPEC.md` 的索引區塊，逐檔與基線比對。

## 3. Go 測試陷阱

- **`type:timestamptz` 欄位在 sqlite 測試 DB 掃不回**：glebarez sqlite 建表後
  scan 回 `time.Time` 失敗——測試改用原生 SQL 建 datetime 等價表。
- **Asset 的 `AfterCreate` 審計 hook 會寫 `audit_logs`**：測試的 AutoMigrate
  必須含 `model.AuditLog`，缺表會回滾 asset 建立（症狀離根因很遠）。
- **GORM `default` tag 觸發 `RETURNING`，破壞 sqlmock 期望**：
  去掉 default tag、寫入端顯式設值。
- **model 加欄後，既有 sqlmock 的 INSERT 期望要補 args**：
  GORM Create 帶全部欄位（含 nil 指標）。
- **sqlite `:memory:` 配連線池＝每條連線是各自獨立的空 DB**：
  被測程式在另一 goroutine 寫入時，池一旦開出第二條連線，寫入就落到沒 migrate 過的
  新 DB——測試讀到 0 筆、log 出現 `no such table`。單獨跑通常綠（併發低只開一條連線）、
  整包跑才紅，**極易被長期誤判為「並行計時敏感 flaky」**。
  修法：`sqlDB, _ := db.DB()` 後 `sqlDB.SetMaxOpenConns(1)`
  （已套用於 `backend/internal/proxy/clipboard_tap_test.go:28`），
  或改 `file::memory:?cache=shared`。**只有非同步寫入的測試會踩到**（同步查詢者不受影響），
  故後端仍有相當數量的 `:memory:` 測試未套用此修法——寫新測試時若被測程式在另一
  goroutine 寫庫，就得自己補上。
- **套件級鎖 ＋ `GOMAXPROCS=1` 會製造「整包恆紅」**：測試以 `defer close(hold)`
  收尾但不等持鎖 goroutine 執行 `defer Unlock()` 時，單核排程下後續每格取鎖皆失敗。
  修法＝加 `released` channel，離場前等 goroutine 確實返回。
  **本專案的驗收口徑是以 `GOMAXPROCS=1 -p 1` 跑全量**（單核序列化最容易逼出這類缺陷），
  故此型缺陷會直接癱瘓整輪驗收，不是偶發。
- **整合測試的 gating 用 `internal/testgate`**（單一入口）：`TEST_PG_DSN`／
  `TEST_KMS_ENDPOINT` 未設時 `t.Skip`；**設 `REQUIRE_INTEGRATION=1` 可讓 skip 轉 fail**。
  本地驗收「由資料庫層保證」類規格時必須顯式跑 gated 測試。

  > **`go test ./...` 全綠不代表跨副本語義驗過。** 有 **27 個測試函式只在真 PostgreSQL 上執行**，
  > 另有 **6 個**只在有 KMS 端點時執行。它們的啟用開關就是上述
  > 兩個環境變數：**沒設就靜默 skip，而 skip 在預設輸出裡看起來與通過無異**。
  >
  > PG-only 的 27 個分佈與驗的東西：
  >
  > - `internal/modules/keyvault` **6**：跨副本 advisory lock 真互斥（1）；session 級鎖與
  >   xact 鎖共 keyspace 互斥、以及 panic／cancel／取鎖回應失敗／高並發四種情境下不洩漏鎖（5）。
  > - `internal/modules/identity` **9**：OIDC「產生新長效能力 vs 解綁」併發矩陣的五種交錯（5）；
  >   provider 列鎖下的兌換／Join／停用先後（3）；兌換洪流對上停用的不變量（1）。
  > - `internal/modules/audit` **8**：保留期區間清除的原子性與會話被砍時的行為、區間效能與
  >   基線比較（4）；保留基線與審計寫入吞吐（2）；檢查點寬限期量測、封印不拖慢寫入（2）。
  > - `internal/database` **4**：宣告索引與實庫對帳、審計樞紐索引的歷史漂移修復（2）；
  >   `kek_id` 欄寬升級路徑（1）；LDAP `CHECK (singleton=1)` ＋ partial unique index 的真實約束（1）。
  >
  > 要真的驗到它們，需備一個 PostgreSQL 靶機並帶 `TEST_PG_DSN=... REQUIRE_INTEGRATION=1` 執行。
  > 這不是理論顧慮——**gated 測試未設環境變數時靜默 skip，在預設輸出裡與通過無異**，
  > 這是本機制最常見的失效方式，`REQUIRE_INTEGRATION=1` 就是為此而存在。**改動任何跨實例互斥、
  > 鎖語義或 schema 約束時，未跑 gated 測試就等於零證據。**
  >
  > 這也代表：**所有「跨實例互斥真的有效」的證據只存在於 PostgreSQL 上**。sqlite 分支的
  > 等價物只被單行程測試覆蓋，沒有、也不可能有跨副本證據。

## 4. 前端測試陷阱（vitest + happy-dom）

### 逐測卸載：偶發逾時的真因多半不是負載

vitest 的偶發 `Test timed out` **極易被誤判為本機並行負載**——因為單獨跑確實綠。
真因通常是：**測試檔掛載元件後從不卸載**，殘留元件在 document 上累積，
單測耗時隨測試序**單調上升**，負載只是把已經很慢的末幾格推過上限。

- **判準**：單獨跑該檔看耗時分佈（末幾格是否明顯比前幾格慢——負載會讓耗時均勻上升，
  不會單調上升）；`grep -c "mount("` 對照 `grep -c "unmount()"`，比例懸殊即中。
- **治法（專案既有慣例）**：`import { enableAutoUnmount } from '@vue/test-utils'`
  ＋ `enableAutoUnmount(afterEach)`。迴圈內需即時卸載者保留顯式
  `wrapper.unmount()`，兩者不衝突。
- **補上自動卸載後全量耗時會明顯下降**（本專案實測快約三成）——
  **耗時大降本身就是診斷正確的反證**；若補完沒變快，真因不在這裡。
- 注意：**同時跑後端與前端全量會自造過載**——要歸因負載，
  必須在無並行下重跑，否則證據不成立。

### happy-dom ＋ Element Plus

- `el-drawer` 的 teleport 跨測試重複 mount 會炸 happy-dom 內部錯誤（`#destroyed`，
  且 `wrapper.vm` 變 null）：stub 成 `{ template: '<div><slot /></div>' }`，
  或依專案慣例把抽屜內容抽成獨立元件、單測直接掛內容元件。
- `el-drawer` 的 `@open` 依賴 transition，測試環境不觸發——
  以 `defineExpose` 的內部方法直接驅動。
- `ElMessageBox` 互動在 happy-dom 不可靠——測邏輯層，不測對話框。
- `el-select`／`el-dialog` 等 teleported popper 內容在測試環境不渲染——
  用具名 stub（`ElSelectStub`／`ElOptionStub`）讓文案落進 DOM；
  `el-table` 要給 MutationObserver 的 no-op stub。
- `el-radio-button` 綁 `:value` 而非 `:label`（綁錯時選取斷言不會如預期）。

### 其他

- 元件在 module 層讀全域物件（如 `window.Guacamole`）時，
  mock 必須用 `vi.hoisted()` 在 import 前注入；`vi.mock` 工廠回傳 class 時
  不可用箭頭函數（不能 new）。
- locale 檔對齊測試要**讀磁碟**，不可 import 物件（會被 `mergeLocaleMessage` 污染）；
  happy-dom 的 `navigator` 預設 en-US，初始語言會漂移，
  在 `beforeEach`／`afterEach` 重設。完備性測試的 id 清單由 exports 導出，勿手抄。
- vitest fake timers 預設不假 `performance.now`——量 RTT 的測試可混用
  fake setInterval ＋真 performance。

## 5. 守衛測試紀律：綠燈不等於守衛在執行

本專案大量使用守衛型測試（golden、完備性、AST 掃描、允許清單、manifest 雙向比對）。
反覆驗證出的鐵則：

> **寫或改守衛，完成前必做「敏感度驗證」——刻意破壞被驗證對象，確認測試轉紅，
> 並保留輸出當證據。宣稱「守衛已就位」而沒有轉紅實測，一律視為未驗收。**

已實際踩過的假綠形態（每一條都真的發生過）：

1. **go test 快取只追蹤 module 內的檔案**：守衛讀 module 外的文件當基準時，
   改文件不會使快取失效——`go test` 回報 `(cached)` 綠而根本沒執行。
   基準檔的掛載點必須在 module 內。敏感度驗證法：暖快取 → 只改被驗證檔案 →
   不加 `-count=1` 重跑 → 必須變紅；看到 `(cached)` 就是踩到。
2. **golden／基準入庫但無消費者**：基準檔存在、任務清單打了勾，但沒有任何測試讀它。
   對每個基準檔反查「誰讀它」，讀不到消費者＝沒有守衛。
3. **完備性測試鎖「現有映射」而非「來源全集」**：後端新增枚舉值時測試照綠。
   斷言對象必須是後端全集（值域硬拷後端並註記 file:line）。
4. **永真斷言與「借樣本」**：問每條斷言「如果產品行為是錯的，這條會紅嗎」；
   借某角色當「非 admin 樣本」時，該角色權限一改，樣本語義就失效。
5. **self-check 只斷言「至少一項違規」**：一道防線的命中會掩蓋另一道失效——
   必須 multiset 相等比對。判型別要用 `go/types`，別以識別字名稱猜。
6. **值域檢查擋不住「缺席」**：新旗標未納入組態矩陣時，受控項在所有 dump 中都不存在
   → 值域檢查連被呼叫的機會都沒有。**只有結構檢查能擋缺席**。
7. **把共享狀態誤判為計時 flaky**：見第 3、4 節。
8. **允許清單「只驗刪除、不驗放寬」**：對豁免條件做突變自檢時，
   多數人只測「拿掉某判準會不會紅」，測不到「把判準的值域撐大」——
   豁免集合加一項、路徑前綴放寬，測試照綠。**兩個方向都要試：刪一項、加一項。**
   修法是字面釘子（直接斷言集合大小與成員）；並實測「豁免範圍內能寫出什麼」，
   讓殘餘風險成為可判斷的事實而非形容詞。
9. **測試繞過生產裝配路徑**：測試直接注入 context 或直接餵內層元件時，
   驗的是內層契約，不是端到端行為——「中介層有沒有真的把值送到這裡」從未被驗證。
   至少一支測試必須從真實入口（HTTP 路由 → middleware → handler）走完。
10. **斷言 helper 把「任何錯誤」當期望結果**：以 `err != nil` 判定「連線已被關閉」，
    讀取逾時也算 err，於是「沒收線」與「已收線」不可區分、整批斷言恆綠。
    網路／IO 類至少區分：對端關閉（期望）、逾時（應紅）、其他錯誤（應紅）。
    **一組互為反面的 helper，其中一個對不代表另一個對。**
11. **fail-close 守門被恆觸發**：「讀取失敗一律拒絕」的守門函式若被 bug 恆觸發
    （如 GORM Pluck 用錯 dest），會變成永久關門而單測全綠——必須有一格
    **以真 DB 驅動的正向放行測試**，否則「誤觸發」與「正常拒絕」不可區分。
12. **窄 `-run` 過濾下的綠不是證據**：突變自檢**必須跑整個 package**——
    守衛可能分散在同 package 的另一支測試，窄過濾會把它濾掉，
    「沒轉紅」就有兩種解釋而你分不出是哪一種。同理，
    `go test ./pkg -run 'X'` 綠不等於 `./pkg` 綠。
13. **gated 測試的 skip 不算驗過**：見第 3 節的 `REQUIRE_INTEGRATION`。
14. **歸零反轉**：「掃到 0 個違規即紅」的 tripwire 在大掃除歸零後語義反轉。
    偵測器健康改由**樣本正向控制**保證（fixture 掃不出必紅），
    不要拿生產碼殘量當偵測器健康指標。
15. **file:line allowlist 的移位假綠**：行號漂移使豁免落到別的 sink 上。
    解法＝`檔名 + AST 節點經 go/printer 正規化後 hash` 的 multiset。
16. **Go 具名字串型別擋不住字面量**：untyped 常數隱式轉換不產生轉換節點，
    `F("literal")`、`"a"+"b"`、本地常數中轉全繞過「掃顯式轉換」——
    要用 `go/types` 的常數摺疊。AST 字串鍵比對也要過 `strconv.Unquote`
    （直接比 `lit.Value == "\"error\""` 會被反引號 raw string 繞過）。
17. **掃描根與 package 位置耦合**：`filepath.Join("..","..")` 或 cwd 相對路徑的掃描根，
    在檔案搬包後會掃空但**照樣綠**。修法統一為「掃描根以 `go.mod` module 身分為錨點
    ＋掃描檔數下限 ＋ `len(pkg.Errors) > 0` 即 `t.Fatal`」。
    這解決的是「找不到檔案」；**「找錯範圍」是另一個問題，見 §11**。
18. **掃描面下限過鬆**：單一總量下限容許數十檔悄悄消失。
    改為**逐頂層目錄釘住現況檔數**（例：`{cmd:8, config:5, internal:263, pkg:22, scripts:7}`）
    ＋「出現未登記的頂層目錄即紅」，任一塊掃描面消失必轉紅。
19. **名稱層啟發式不是證明**：以函式名判別「這是不是 KEK 產生器」擋不住
    import 別名（`import crand "crypto/rand"`）、間接 helper、中性名稱。
    正解是加一條**與名稱無關的來源軸**（每一處直接取用 rand 的函式都須具名登記），
    並把宣稱降級為「名稱層回歸守衛」而非完整證明。
20. **AST 守衛掃 `cmd/` 時要跳過 `testdata`**（測試會在其中建刪臨時目錄，
    與守衛並行即 ENOENT，製造非確定性失敗）；但 `scripts/` 不該跳過
    （維運工具的盲區與被禁行為型態重疊）。
21. **hash／列印失敗路徑要 fail-closed**：退成假 hash 會同長度碰撞靜默放行。

### 5.1 同源 oracle 對照表：哪些守衛是「相關失效」

多道守衛看起來是多道防線，實際常共用一個前提：**先靠同一批掃描器辨識
「什麼算一個事件」，再檢查登記表是否一致**。掃描器看不見的效果，登記表也不會
知道自己缺了一列——一次新增泛型 helper、間接 callback、raw SQL 或新的 GORM
句柄，可能同時讓好幾道守衛靜默失明，而且**不會有任何測試轉紅**。

這與「守衛有 commit 權者可刪」是不同的問題：那條講有人刻意移除，這條講
**沒人動守衛、它們卻一起瞎掉**。

**降險的兩種手段**（不是只有一種）：

- **名稱無關 oracle**：runtime 觀測副作用（GORM callback、計數式 fake、實跑
  組裝後反射檢查）或型別層判定（`go/types`），不看識別字拼法與呼叫形狀。
- **fail-close 掃描**：掃描器遇到判讀不出的形態（非字面表名、非字面 ref、
  非 `fmt.Sprintf` 的 SQL 構造）時**報紅而非略過**。它把「看不見」從靜默
  轉成可見，效果等價於補一條軸。**純名稱層 ＋ 遇不懂就略過**才是危險組合。

下表逐一登記關鍵效果類別的現況。**新增守衛時先問「我這一類落在哪一行」**；
若答案是「純名稱層、且靜默失效屬安全紅線」，那道守衛不足以單獨成立。

| 關鍵效果類別 | 名稱無關 oracle | 證據（`backend/` 起算） |
|---|---|---|
| 審計寫入與 fail-close 回滾 | 有（runtime，射程 asset／identity） | GORM Create callback 注入器 `internal/modules/asset/audit_failclose_backstop_test.go:196`；目標判定看**表名 OR Go 型別**，不看函式名 `:372` |
| 審計列不可刪 | 有（runtime） | `internal/modules/audit/audit_log_guard_test.go:16`（BeforeDelete 副作用，含 Unscoped） |
| 審計寫入點完備登記（manifest） | 部分 | 掃描器認 `model.AuditLog{…}` 複合字面量＋recorder 名 `cmd/server/audit_points_manifest_guard_test.go:407`；GORM 層 backstop 只覆蓋 asset／identity 兩模組 |
| 憑證明文解封 | 有（runtime） | 計數式 `ColumnCodec` 直接觀測 `DecryptFor` 次數 `internal/sshproxy/stage_transition_test.go:239`，附對照組 `:287`；掃描器對**非字面 ref** fail-close `internal/guards/moduleboundary/asset_credential_exit_guard_test.go:190`（具名例外 `:46`＋例外的二次條件 `:206`） |
| 跨模組資料讀寫 ratchet | 有（型別＋fail-close） | 句柄以 `*gorm.DB` **型別**辨識、raw SQL 抽表名、**非字面即報紅** `internal/guards/moduleboundary/module_data_boundary_guard_test.go:815`（判準說明 `:19-22`） |
| 跨模組交易外交（tx-taking） | 有（型別層） | 以簽章是否含 `*gorm.DB` 判定 `internal/guards/txtaking/tx_taking_whitelist_test.go:320`，明言不看識別字拼法 `:337` |
| KEK 材料產生 | 有（來源軸，名稱無關） | 軸 B 要求每一處直接取用 `crypto/rand`／`math/rand` 的函式具名登記 `internal/modules/keyvault/key_rewrap_no_generation_ast_test.go:572`、`:633`；殘餘缺口（自實作 CSPRNG）已於該檔頭自陳 |
| AAD 完備（不得產生無 AAD 密文） | 有（runtime） | 以真 DB 驅動生產哨兵掃描既存密文 `internal/modules/keyvault/aad_residue_bound_test.go:21` |
| 路由註冊與中間件鏈（認證閘） | 有（runtime） | golden 由 `buildRouter` **實跑 gin 引擎**產出，含中間件鏈 `cmd/server/routes_regression_test.go:377` |
| 啟動接線（audit／alert sink） | 有（生產 fail-close＋runtime） | 未注入即段 2 失敗 `cmd/server/audit_sinks.go:38`；未注入時的假綠形態另有一格 `internal/modules/asset/audit_failclose_backstop_test.go:546` |
| 撤銷管道接線 | 有（runtime） | 實跑段 2 後反射檢查介面欄位非 nil `cmd/server/revocation_wiring_runtime_test.go:59`；另有一道語法出現性掃描 `internal/modules/keyvault/revocation_wiring_guard_test.go:102`（單獨不足以證明接上） |
| 認證脈絡觸點 | 無（名稱層，但 fail-close） | 硬編碼符號清單 `internal/guards/authcontext/auth_context_touchpoints_guard_test.go:342`；附「每個符號須解析到 ≥1 宣告」反向斷言 `:601`，故**改名轉紅**而非靜默 |
| 生命週期註冊／釋放 | 無（純名稱層） | 以 `Init*`／`Reset*`／`Start*`／`Stop*` 前綴辨識 `cmd/server/lifecycle_manifest_guard_test.go:324`；服務清單靠人工 `mark()` 登記 |

**未補的兩類與理由**（判準：靜默失效的後果是否屬安全紅線）：

- **認證脈絡觸點**：符號清單雖是名稱層，但反向斷言使**改名／刪除一律轉紅**，
  失效方向是 fail-close。殘餘缺口是「新增一個未登記的觸點」，屬登記表覆蓋面
  問題而非 oracle 盲區。不補。
- **生命週期註冊／釋放**：唯一純名稱層的類別。靜默失效的後果是啟停順序異常
  ——**可觀察、可復原、不屬安全紅線**（憑證外洩／審計缺漏／授權繞過／
  跨模組資料越界）。為它建 runtime oracle 需要把整個服務圖的註冊面重做一遍，
  與收斂原則衝突。**接受此風險**，不補。

**這一類為何非要 runtime oracle 不可**：撤銷管道接線的語法掃描只驗得了
「`stage2.go` 裡六個 `Set*` 呼叫存在」，證不了它們**真的接上了**——`Set*(nil)`、
`Set*(resolve(x))` 這種正常重構引入的中性名稱間接層、或被條件包住而從未執行，
呼叫點形狀完全不變，掃描器一律照綠；後果是停用／解綁／provider 撤銷永久靜默失效
（授權繞過，安全紅線）。故改以「實跑段 2 後反射檢查介面欄位非 nil」把關：
插入一個回 `nil` 的中性名稱 helper 並保留原呼叫點時，語法掃描照綠而該 oracle 轉紅。

**這張表本身就是交付物**：它讓「哪些守衛是相關失效」從隱性變成明寫。
新增關鍵效果類別時 SHALL 同步加一列，並在「無名稱無關 oracle」時寫明
後果與是否接受——不寫等於默認它有覆蓋。

## 6. 突變自檢（mutation self-check）的操作紀律

「刻意改壞 → 確認轉紅 → 還原」是本專案驗收守衛與 fail-close 的核心手段。
以下三條是踩過事故換來的硬規則：

### 6.1 還原只准用事前 `cp` 快照，禁用 `git checkout --`

`git checkout -- <file>`／`git restore <file>`／`git stash` 的語義是
**「還原到 HEAD／索引」，不是「撤銷我剛才那次編輯」**。
在長時間未 commit 的重構工作樹上，這個差距就是全部未提交的工作。

- 突變前先 `cp <file> <版控外的暫存目錄>/<file>.bak`（或整目錄快照），
  還原時 `cp` 回去並以 **SHA256 逐位元組比對自證**。
- 驗收條件寫成「結束時工作樹與動手前逐位元組相同」，而不是「有還原」。
- 同類危險指令：`git clean -fd`、`git reset --hard`、`git stash push -u`
  （會把別人正在編輯的檔案一併收走）。
- **每完成一個可獨立驗證的階段就 commit**，縮小事故半徑。

### 6.2 突變期間工作樹是刻意破壞態，並行的自動化檢查會誤報

- 突變處**留可搜尋標記**（如 `// MUTATION-N：<說明>`），讓同時在動這棵樹的人一眼識別。
- 收到針對「正在驗收中檔案」的自動化告警（安全掃描、CI、他人正在建立的基線）時，
  先 `grep MUTATION` 確認是否為暫時態再判真偽。
  判準：告警建議的修法若與既有修復方向一致，多半是掃到還原狀態。
- **量測行為基線時不要並行跑其他全量測試**：基線會採到破壞態的結果，
  且共用 docker 容器會造成過載，實測數字嚴重失真。
- **e2e 不可退讓**：走真實 SSH／WebSocket 與 90s 級時序，超賣下紅字無法歸因。

### 6.3 突變自檢跑整包，不用 `-run` 縮範圍

理由見上節形態 12。

## 7. 故障注入（fault injection）測試的防呆

「注入失敗、斷言回滾」型測試最危險的假綠**不是斷言寫錯，而是測試根本沒走到注入點**。

實證形態：某 fail-close backstop 測試以 `codec=nil` 呼叫目標函式，
而該函式在**進入交易之前**就早退——故障注入器一次都沒 fire，三條斷言全因早退而「成立」，
**即使把生產碼的 fail-close 完全移除，該格照樣綠**。生產碼是對的，缺陷全在測試。

規則：

1. **每個 fault-injection 測試都要斷言「注入器至少 fire 過一次」**
   （注入器內計數，`t.Cleanup` 檢查 `fired > 0`）。這道防呆獨立於被測邏輯——
   它證明的是「測試真的執行到了注入點」。
2. **`fired > 0` 還不夠，要證明「目標命中」**：一個操作可能寫多筆審計列，
   credit 會被不相干的那筆取得。收緊為三件套：
   - 注入器只對**命中本格身分 spec**（AP 編號＋action／resource／Details 指紋）的寫入注入失敗；
   - 注入器回傳**本格獨有的哨兵 error**，每格 `errors.Is(err, sentinel)`；
   - Cleanup 斷言「命中本格身分的注入次數 > 0」。
3. **每格必須配「無故障對照」**：三條回滾斷言在「查詢條件寫錯」「夾具沒建起業務列」
   「多點共用一格而第一個點先失敗使後續永不可達」時也全成立。
   對照組機械斷言：無故障時業務入口成功、業務列落到預期筆數、且確實抵達本格指定的審計點。
4. **為防呆自己加突變自檢**：把某格改成不觸及被測路徑，該格必須因防呆而紅。
5. **驗收 fault-injection 測試的唯一有效指標是：把生產碼的保護移除後該格會轉紅。**
   只跑「測試通過」不構成證據。
6. **共享狀態才是平行化風險**（不是 Cleanup 被跳過）：每格自建 DB 句柄、
   callback 成對註冊／解除、計數原子且綁定測試身分、**禁用 `t.Parallel`**、`-race` 驗過。
   本專案以原始碼掃描機器化該禁令（含格數下限防自身縮水）。
7. **射程與盲區必須明載**：GORM Create callback 注入器看不見 `db.Exec` 原生 SQL、
   Update callback 路徑、另行 `gorm.Open` 的新句柄、非 GORM 寫入——
   已用三格邊界測試把盲區釘成**可見**而非隱形。措辭一律寫
   「**GORM callback 路徑上的**最終權威」，不得無條件稱「每個 fail-close 點的最終權威」。
8. **同型不可折抵 runtime case**：「這幾點語法同型，一格代表就好」只證明當下的人工比對，
   擋不住日後獨立漂移。每個 fail-close 點都要有自己的格。
9. 同型風險：mock 沒被呼叫、spy 計數為零、`t.Cleanup` 內的斷言因 panic 跳過、
   前置條件早退（nil 參數、feature flag 關閉、權限不足、空集合）。
10. **既有的 fail-close backstop 不會自動涵蓋新加的 fail-close 點**：backstop 的
    注入軸是**特定一種故障**（例如「審計寫入失敗」）。新增一條「協作者回錯誤就整筆
    失敗」的路徑後，把它改成 log-and-continue **不會**讓任何既有格子轉紅——實證：
    把交易級聯撤銷的錯誤處置改成吞掉，委派斷言與審計 backstop 兩格都照樣綠。
    **每新增一個 fail-close 點，就要有一格以該點自己的故障驅動的測試。**
11. **測試替身的「不做事」會打掉別人的對照組**：把一個有副作用的協作者換成純記錄式
    stub，會讓「無故障對照組」的副作用斷言失效（實證：級聯刪除的替身不刪東西，
    對照組的「刪除確實發生」立刻紅）。換替身前先查誰在斷言那個副作用。

## 8. flaky 判準

- **單獨重跑穩定 ＝ 非本次改動引入**——這是初步排除口徑，不是結案。
- **「單獨跑綠、整包跑紅」是共享狀態的訊號，不是計時問題的訊號**：
  先查 sqlite `:memory:` 連線池（第 3 節）與元件不卸載（第 4 節），
  再考慮歸類 flaky。**一個看似合理的解釋（「本機負載」）會讓人停止追查**——
  本專案有兩個長期「flaky」最後都查出確定性真因。
- 判定「既有 flake、非我引入」的完整口徑（四條全過才成立）：
  1. 敗檔單獨跑綠；
  2. 失敗全為 timeout 而非斷言錯誤；
  3. `git stash` 乾淨樹同口徑對照仍敗（**注意：同一棵工作樹上還有別人在動時禁用 stash，
     改用 `git worktree add` 在副本上量**）；
  4. 失敗檔與本次改動交集分析為空。
- 診斷通則：先寫下「我的假設」與「什麼會推翻它」，挑**需要對端參與才會變化**的判準
  （客戶端本地渲染的現象不能當存活證據），並先讀現成的 log。

## 9. e2e 煙霧測試

`scripts/e2e_smoke.sh` 是端到端基準（登入、建線、審計、多帳號、SSO、RDP／VNC 圖形協議等 18 段場景，
腳本輸出以 `[0]`–`[17]` 標號），在開發版 compose 下直接跑：

```bash
ADMIN_PASS='<現行 admin 密碼>' bash scripts/e2e_smoke.sh
```

- **`ADMIN_PASS` 必填，腳本不內建密碼**：未帶即在做任何事之前失敗並印出帶法。
  admin 密碼於首登強制改密後只有操作者持有，硬編碼預設值注定週期性失效
  ——失效時整份煙測全紅，症狀與產品缺陷難以區分。
  **`.env` 的 `ADMIN_INITIAL_PASSWORD` 不能拿來當回退**——不只是「可能過期」，而是該路徑
  恆不可用：它仍是現行密碼的唯一情況＝admin 從未改密（`must_change_password` 為真），
  而該狀態下 `/auth/login` 只回 `change_token` 不回 `token`，腳本要的正式 token 拿不到。
  忘記現行密碼時，照 `docs/QUICKSTART.md` 故障排除的離線重設段以 DB 直改雜湊重設。
- **資產 ID 漂移**（最常見的假紅來源）：腳本會在登入後**自動查**主線 SSH 靶機資產
  ——取 `protocol=ssh`、`active=true`、`host=$SSH_ASSET_HOST`（預設 `ssh-test`）中 id 最小的一筆，
  查不到即中止並提示如何處置，**不會沉默地用一個猜測值跑下去**。
  要指定特定資產時可用 `SSH_ASSET_ID=<id> bash scripts/e2e_smoke.sh` 覆寫（此時不查詢）；
  靶機主機名不同則帶 `SSH_ASSET_HOST=<host>`。
  硬編碼資產 ID 在重建資料庫後會造成大量假紅（改對 ID 即全綠，程式碼一行未動），
  且**這類失敗極易被誤記為「他人 in-flight 改動造成」而繞過**。
- 閒置斷線場景為 opt-in（需把 backend 的 `SSH_IDLE_TIMEOUT_MINUTES` 調到 1 並
  `IDLE_TIMEOUT_SMOKE=1` 跑，全程約 75 秒），驗畢還原設定並 recreate。
- K8s live 與 SSO 場景依賴 dev compose 靶機（dex 等），不可達時自動 skip。
- **e2e 綠不構成「優雅關閉期無審計遺失」的證據**：腳本全程不停止 backend，
  該路徑零執行。要驗需要「WS 連線存活期間觸發優雅關閉」的專用測試。
- 修改煙測腳本後，除了跑通，**還要抽查審計庫裡實際送出的請求體**——
  shell 引用類 bug（如舊版 bash 對 `$$` 的 ANSI-C 誤讀）的症狀離根因極遠，
  審計庫的 `request_body` 是唯一直接證據。

## 10. 覆蓋率與結果導向

- 產品程式碼以 80% 覆蓋率為目標；實驗腳本、文檔、一次性工具不受此限。
- TDD 採**結果導向**：測試必須存在且全綠、覆蓋關鍵行為；先測後寫的順序不強制。
- **不自驗**：安全相關或宣稱「已修好」的改動，須由**未參與該改動的人** review，
  且 review 者自己跑測試／突變自檢並貼輸出。無證據的 PASS 視為未驗收；
  措辭上，驗過的說「已完成並驗證」，沒驗的只能說「已寫入，尚未驗證」。
- **加測試／加守衛的判準有上限**，三條原則：
  1. 守衛擋的是「**正常開發／重構中會意外發生**的錯誤」（漏接一行注入、搬檔後守衛掃空、
     fail-close 被順手改成 log-and-continue），且用**最簡形式**；
     「**要刻意繞才會發生**的路徑」（指標間接賦值、改 import alias、自造同名結構繞過白名單）
     記為 backlog，不修。
  2. **不做通用框架**：單一案例用單一檢查解決，不為「後續可能重複」預先建可擴充登記表
     ——真的重複第三次再抽象。
  3. **審查意見的處置分兩類**：誠實性問題（宣稱強度大於實際）立即改措辭；
     守衛強化建議依上面兩條過濾，不照單全收。修完即收斂，
     第三輪起須警惕「修訂本身在製造新問題」。

## 11. 搬檔／改 package 的三項必查

**任何把檔案搬到另一個 package 的改動都適用。** 這三項的共同點是：
出錯時測試不會轉紅，而是靜默失去守備範圍。

### 11.1 守衛射程隨搬檔改變

以「當前包」定位範圍的守衛（`parsePackageNonTestFiles(t, ".")`、
相對當前包掃描），在檔案搬入新 package 後射程**靜默改變**：
原本守整個來源包，搬完只守新包裡那幾檔，**來源包從此無人看守而測試照樣綠**。

驗法：把違規物（例如一個 KEK 產生器）放進來源包，搬檔前該守衛必須 FAIL、
搬檔後若變成 PASS，就是射程掉了。

- **查法**：逐檔掃隨遷測試檔的 `os.ReadDir`／`filepath.Walk`／`parser.ParseDir`／
  `runtime.Caller`／`filepath.Join("..")`；**反向也要查**——
  留在原處的守衛有沒有因為新 package 出現而掉出射程。
- **修法（都不接受「只改名」或「只加註解」）**：
  - 射程本該涵蓋全模組者 → 改以 `repoRoot`（`go.mod` module 身分錨點）掃全 module
    ＋具名例外清單 ＋例外的二次條件（列進清單不是免死金牌）＋掃描檔數下限。
  - 射程本該跟著程式碼走者 → 保留本包定位，但必須有涵蓋面**下界斷言**
    （指錯包時會先紅）。
- **踩過的坑**：具名下界清單沒跟上搬包（掃描走 `./...` 故涵蓋面未縮，
  但「必須在場」的下界名單漏了新模組）；**指名式定位子必須跟著改**
  ——以包名比對的型別宣告判定（`pf.Pkg == "<舊包名>"`）與以
  `"<舊包名>.<型別>"` 字串指名的型別，包一改名就再也命中不到。
- **改包名的特有形態（比搬檔更隱蔽）**：以**字串字面量**指名 import 路徑或檔案路徑的
  守衛，在包被改名的當下就再也匹配不到目標。若那個字串是**禁令**（「不得出現 X」），
  守衛從此**恆綠**而完全不守任何東西；若是**豁免**（「X 除外」），則轉為誤報。
  兩種都不接受「把字串換成新名字」的修法——下一次改名照壞。修法是換成
  **跟著程式碼走的結構性錨點**：「誰宣告了這個入口函式」、「接收者型別叫什麼」、
  「相依閉包裡有沒有 DB 存取能力」。每一條改寫都要做突變自檢
  （把錨點指向不存在的目標，確認 `t.Fatal` 而非靜默通過）。

### 11.2 零出向必須分層聲明

`go list -deps ./<pkg>` 只證得了 **import 層**零出向。
**資料層**可經共享的 `internal/model` 直接讀寫他模組的表，
`go list -deps` 完全看不見這條通道。

- 宣稱「零出向」時 **SHALL 分別聲明 import 層與資料層**，
  **不得以 `go list -deps` 的結果代表資料層**。
- 資料層須逐處盤點該 package 直接讀寫的**非自有表**，含 `Preload`／`Joins`／
  raw SQL／`db.Table()`／由變數型別決定表名的 `Create(&row)`。
- **判準是 ratchet 方向（只准縮不准增），不是歸零**——現況為基線登記，
  新增未登記的跨模組資料存取即紅。

### 11.3 export budget

**「搬包所需」不等於「匯出改名」。** 機械式大寫化會把原 private 的實作細節
**永久固化成跨包 API**——檔案分開了，耦合面反而擴大且再也收不回。

- 每次搬包三件事：(a) 逐一列出新增匯出符號及其**唯一消費者**；
  (b) 優先窄 façade／消費者側宣告的介面／組裝根 adapter；
  (c) 驗收時列出清單並說明每個匯出為何不可避免，同時列「刻意不匯出」的節流清單。
- **不計入 budget**：既有已是匯出識別字的符號（只是跨了包界）、
  既有匯出符號的簽名加寬。
- 量級供校準：一次搬包新增 12 個匯出，回溯發現 **3 個只被測試消費、1 個零消費者**；
  套上這條紀律後的下一次降為 5 個，且其中 3 個是介面／消費者側形式。
