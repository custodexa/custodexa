# 快速開始指南

> 相關文件：API 參考見 [API_SPEC.md](API_SPEC.md)、資料庫參考見 [DB_SCHEMA.md](DB_SCHEMA.md)、專案總覽見 [zh-TW/README.md](zh-TW/README.md)（英文版在[repo 根目錄](../README.md)）、貢獻與開發流程見 [zh-TW/CONTRIBUTING.md](zh-TW/CONTRIBUTING.md)。

## 前置需求

- Docker 20.10+
- Docker Compose 2.0+
- Git

驗證安裝：
```bash
docker --version
docker compose version
```

## 啟動步驟

部署自用與參與開發走**同一條流程**；預設的 `docker-compose.yml` 即正式版
（nginx 供編譯後前端、backend 為精簡二進位、不含測試靶機）。參與開發者只多一步——
在 `.env` 取消 `COMPOSE_FILE=docker-compose.dev.yml` 的註解，之後所有 `docker compose`
指令自動指向開發版（前端 Vite HMR、後端 Air 熱重載，並帶起各協議的測試靶機），無須每次打 `-f`。

### 1. 取得原始碼

```bash
git clone https://github.com/custodexa/custodexa.git
cd custodexa
```

### 2. 設定環境變數（必需）

> **快速路徑**：`bash scripts/quickstart.sh` 會自動完成本節——檢查 `.env`（沒有就從
> 範本建立）、缺的機密用 CSPRNG 生成；已填的值一律不動，重跑安全。加 `--up` 連啟動
> 一起做：分階段回報進度、等後端健康，最後輸出連線網址與 admin 登入資訊
> （輸出為英文）。Windows 請在 WSL 內執行。
> 想了解各值的語義或手動設定，繼續往下讀。

先複製範本再依環境編輯。

```bash
cp .env.example .env
# 所有全新（空 DB）部署：務必設 ADMIN_INITIAL_PASSWORD（初始 admin 密碼，已無公開預設）
# 正式部署：務必改 JWT_SECRET（release 未改即拒啟動）＋ DB_PASSWORD，並依需求設 DB_SSLMODE / LDAP / DATA_PATH
#   （ENCRYPTION_KEY 僅 KEK_PROVIDER=env 需要；出貨預設 ui＝金鑰不落地，見範本 KEK 段）
# 參與開發：取消 COMPOSE_FILE=docker-compose.dev.yml 的註解，並建議改 KEK_PROVIDER=env＋
#   填 ENCRYPTION_KEY——熱重載每次重編譯即重啟行程，ui 模式會每次要求重新解封
```

> **初始管理員密碼（`ADMIN_INITIAL_PASSWORD`）**：沒有出廠預設密碼。全新（空 DB）部署都要自己設一個
> 合格值——至少 12 字元、前後不帶空白、不能照抄範本的佔位字串，否則服務會拒絕啟動並在日誌說明原因。
> 建議用 `openssl rand -base64 24` 產生（去掉尾端的換行）。
> 這個值只會用一次：首次登入會強制改密，之後請把它從 `.env` 移除或輪替。
> 既有資料庫（非空 DB）不需要此值。

`.env.example` 為**唯一環境變數範本**（dev 與 prod 的 compose 皆以 `env_file` 消費它）。
後端消費變數的完備性由 `backend/config/env_drift_test.go` 守衛——掃描程式碼實際消費的變數，
對照本範本 ＋ compose 提供的拓撲變數，漂移即測試失敗。
拓撲/模式常數（`DB_HOST=postgres`、`GUACD_HOST=guacd`、`GIN_MODE` 等）由 compose 檔提供，不在範本內。

> **注意**：`env_file` 對「空值」的行內 `#` 註解不剝除（`KEY=  # 說明` 的值會變成 `# 說明`），
> 而範本多數旋鈕預設為空值，故 `.env`（與範本）的說明一律置於獨立行、值行不帶行內註解，
> 否則值會含註解導致服務啟動失敗。

**資料存放位置（`DATA_PATH`）**：主體應用資料（審計 / 錄影 / 資料庫）落在單一資料夾根，
由 `DATA_PATH` 決定，預設為專案內 `./data`（開發可直接檢視）。生產部署可覆寫為指定資料夾或磁碟：

```bash
# 生產：將資料集中到指定路徑
DATA_PATH=/opt/custodexa/data
```

> **資料持久化與重置**：資料以 bind mount 落在 `${DATA_PATH}` 目錄，`docker compose down -v`
> **不會**清除（`-v` 僅清 named volume）；如需完全重置資料，停服務後刪除 `DATA_PATH` 指向的目錄
> 內容（預設 `./data`，自訂路徑則改為該路徑；`.env` 內的 `DATA_PATH` 不會自動帶入手動 shell 指令）：
> `rm -rf ./data/*`。`./data/` 已列入 `.gitignore`，不會誤入版控。

### 3. 啟動服務

```bash
# 背景執行（無既存映像時會先自動建置——正式版建置就是部署流程的第一步）
docker compose up -d

# 前台執行（可看到日誌）
docker compose up
```

首次啟動需建置映像與下載依賴，約需 5-10 分鐘。

### 4. 驗證服務

**檢查容器狀態**：
```bash
docker compose ps
# 正式版（預設）：backend, frontend, postgres, guacd
# 開發版（已啟用 COMPOSE_FILE）另有測試靶機：
#   ssh-test, ssh-multi-test, mssql-test, mysql-test, rdp-test, vnc-test, k3s-test
#   （另有 ldap-test / dex / localstack 三個服務供 LDAP、OIDC、S3 相關功能使用）
```

**存取入口（兩版不同）**：

| | 正式版（預設） | 開發版 |
|---|---|---|
| 前端 | http://localhost （nginx，80） | http://localhost:3000 （Vite dev server） |
| 後端 | 不對外開埠（經 nginx 代理 `/api`） | http://localhost:8080 |

**測試後端 API**：
```bash
# 正式版：backend 不對外開埠，且 /health 不在 nginx 代理路徑內，走容器內
docker compose exec backend wget -qO- http://localhost:8080/health
# 開發版：直連
curl http://localhost:8080/health
# {"status":"ok","service":"custodexa-backend"}
```

**封印狀態（出貨預設 `KEK_PROVIDER=ui`）**：全新安裝啟動後系統處於**封印待初始化**態——
`/health` 正常但業務端點尚未開放，首次造訪前端會進入初始化解封頁。查詢狀態：

```bash
curl http://localhost/api/v1/seal/status
```

- 初始帳號: `admin`；初始密碼為你在 `.env` 設定的 `ADMIN_INITIAL_PASSWORD`

> **首次登入須改密**：初始 admin 首次登入後會被導向強制改密頁，設定新密碼
> （依畫面顯示的政策：長度、字母＋數字、不可重用近幾筆）後直接進入系統，不需重新登入。
> 改密後 `ADMIN_INITIAL_PASSWORD` 即退役，請自 `.env` 移除或輪替。

登入之後怎麼建第一筆資產、發起第一條連線，見下方「首次使用」一節。
生產環境的必設項集中在「正式部署補充」；對外 TLS、時間同步、審計完整性邊界與日誌保留
這些部署方責任與行為說明，見「生產環境的部署方責任與行為邊界」；admin 密碼遺失或
啟動被弱憑證掃描擋下時的離線重設，見「故障排除」。

### 5. 查看日誌

```bash
# 所有服務
docker compose logs -f

# 特定服務
docker compose logs -f backend
docker compose logs -f frontend
```

## 首次使用：從登入到第一條連線

以下流程正式版與開發版通用。開發版可以拿內建的測試靶機當連線目標（見「測試連線功能」）；
正式版請換成你自己要納管的主機。

### 1. 初始化解封、登入與改密

開 `http://localhost/`（開發版為 `http://localhost:3000`）。

**出貨預設（`KEK_PROVIDER=ui`）第一次會先進入初始化解封頁**：主金鑰在你的瀏覽器
**本地生成、只存在伺服器記憶體**——頁面會要求你確認已妥善保存（之後每一次行程重啟
都停在封印狀態，需要用它解封）；以 `admin`＋`ADMIN_INITIAL_PASSWORD` 授權初始化。
（env／kms 模式沒有這一步，直接到登入頁。）

接著登入：帳號 `admin`、密碼為 `.env` 的 `ADMIN_INITIAL_PASSWORD`。首次登入會先進
強制改密頁，設定新密碼後直接進入儀表板。

### 2. 建立第一筆資產

「資產管理」→「新增資產」。欄位說明：

| 欄位 | 說明 |
|---|---|
| 名稱、協議、主機、埠號 | 必填。主機填 IP 或主機名（容器化部署要連宿主機上的服務時，可用 `host.docker.internal`） |
| 使用者名稱、密碼、SSH 私鑰 | 連線用憑證，儲存時可留空。實際連線時**私鑰優先、密碼次之**；兩者皆空的資產可以存檔，但發起連線會失敗（「資產未設定可用憑證」） |
| 掛載節點 | 資產在資產樹上的歸屬節點，可多選（一筆資產可同時掛在多個節點下）；留空則列於「未分組」 |
| 連線政策 | 逐資產的連線管控。預設「跟隨全域設定」並回顯目前的全域值，需要對這筆資產特別放寬或收緊時才改 |
| 描述 | 選填，供列表辨識 |

資產列表的「狀態」欄是連通性撥測資訊（新建資產尚未撥測時顯示「-」）；
撥測目前只驗密碼認證，僅設私鑰的資產撥測會失敗，但不代表實際連線不可用——
能不能連，以下一步的「連線」為準。

### 3. 發起連線

在資產列表找到該筆資產，點該列的「**連線**」——會開啟工作區分頁，
網頁終端出現遠端主機的提示符即代表連上了。試跑幾個指令（`whoami`、`ls`），
輸入 `exit` 或關閉分頁即結束會話。

### 4. 回看審計

會話結束後，到「連線管理」可看到這筆歷史會話，點進詳情就有**錄影回放**
（可拖進度、調倍速）與該次會話的**指令記錄**；要跨會話搜尋指令，用「指令審計」頁。
這條「操作必留痕」的鏈路就是本產品的核心，首次部署建議實際走一遍確認錄影可回放。

## 正式部署補充

正式版就是預設 compose（見上方啟動步驟），本節補充 release 特有的必設項與部署驗證。
正式版特性：不對外開放 DB／guacd 埠、`restart: always`、後端走編譯後的二進位（無原始碼掛載、
`GIN_MODE=release`），對外只有 frontend 的 `80`。

### 1. `.env` 的 release 必設項

release 模式對這些值 **fail-close**（不合格即拒絕啟動，非警告）：

| 變數 | 要求 |
|---|---|
| `JWT_SECRET` | 必須改掉出廠預設值（PCI 2.2.2） |
| `ENCRYPTION_KEY` | 僅 `KEK_PROVIDER=env` 需要；出貨預設 `ui`（金鑰不落地）下必須維持註解，有值即組態矛盾拒啟動 |
| `DB_PASSWORD` | 必填——prod compose 未給預設值 |
| `ADMIN_INITIAL_PASSWORD` | 全新空 DB 必填（>=12 bytes、非 placeholder、無前後空白／換行）；既有 DB 不需要 |
| `CORS_ALLOWED_ORIGINS` | 跨來源部署必設；未設時僅允許同源 |
| `DATA_PATH` | 建議指向專用資料夾或磁碟（預設 `./data`） |

### 2. 啟動

```bash
# 無既存映像時 up 會先建置正式版映像（建置就是部署流程的第一步）。
docker compose up -d
```

> 正式版與開發版 image 已分離命名（`custodexa/*:latest` 與 `custodexa/*:dev`），
> 同一台機器可同時保有兩者，建置任一方都不會覆蓋另一方。

### 3. 部署驗證（每次正式部署都應跑過）

```bash
# (1) 全部服務起來且 postgres healthy
docker compose ps

# (2) 後端健康檢查——backend 不對外開埠，且 /health 不在 nginx 代理路徑內，故走容器內
docker compose exec backend wget -qO- http://localhost:8080/health

# (3) 前端可達（nginx 代理 /api 與 /ws 至 backend）
curl -I http://localhost/

# (4) 登入鏈路通（帳號 admin，密碼為 .env 的 ADMIN_INITIAL_PASSWORD）
curl -s -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<ADMIN_INITIAL_PASSWORD>"}'

# (5) 啟動日誌無 fatal（release 的 fail-close 都會出現在這裡）
docker compose logs backend | tail -30
```

> 開發機驗證正式版時，上列指令一律加顯式 `-f docker-compose.yml`（覆蓋 `.env` 的 `COMPOSE_FILE`）。

出貨預設 `ui` 模式下，(4) 在**初始化解封完成前**會被封印閘擋下——先於瀏覽器完成
初始化（見「首次使用」），或以 `curl http://localhost/api/v1/seal/status` 確認狀態。

(4) 於**全新部署**回傳的是 `{"change_token": "...", "password_change_required": true, "policy_hint": {...}}`
而非一般 token——這是首登強制改密流程（PCI 8.3.5），拿到它就代表認證鏈路正常。改密後才換發正式會話。

若任一步失敗，先看 (5) 的日誌——release 的拒絕啟動一律有明確訊息（哪個變數、為什麼不合格）。

> **對外 TLS 仍是部署方職責**：stock 部署只映射 `80`/HTTP。正式對外前須在前面架 TLS-terminating
> 反向代理／ingress（含 WebSocket upgrade 轉發），詳見下方「生產環境的部署方責任與行為邊界」。

### 4. OIDC／SSO 部署注意

provider 本身的設定（issuer／client_id／secret／准入規則）由管理端存入資料庫；
部署層只決定下列三個環境變數，以及一項**必須在啟用 SSO 前就確認的運維前提**。

| 變數 | 說明 |
|---|---|
| `PUBLIC_BASE_URL` | 對外基準網址，用於組出交給 IdP 的 `redirect_uri`（`${PUBLIC_BASE_URL}/api/v1/auth/oidc/callback`）與 callback 導回位址。**不從請求 Host 推導**——反向代理多層轉發下推導必然出錯，而該值會被寫進 `redirect_uri`，錯誤時使用者會被導向錯誤主機。未設定時已啟用的 provider 會被標記「設定不完整」並自登入頁隱藏（fail-close）。正式環境須為 https。 |
| `OIDC_DEDICATED_ISSUERS` | 專屬 issuer 宣告（逗號分隔）。系統對「未知 issuer」一律 fail-close 視為**共用身分域**，並要求其准入規則包含組織歸屬條件（租戶識別或 hosted domain）；但 Okta、自架 IdP 等**不發**這類 claim，若無本宣告，它們的自動供應將無法組態。宣告的語義是「此 issuer 只服務本組織」——該判斷只有部署方能做，故置於部署層而非管理端 API（admin 帳號自身不得放寬安全規則）。內建共用清單（Google、Microsoft 多租戶端點等）優先，不可經此宣告推翻。**變更後須滾動重啟全部副本才算生效**（宣告在啟動時載入；只重啟一個副本會使各副本判定分歧，管理端 provider 詳情顯示的是「本副本」的判定來源）。 |
| `OIDC_ALLOWED_INTERNAL_HOSTS` | 允許出站的內部主機名（逗號分隔）。對 IdP 的出站預設拒絕解析至 loopback／link-local（含雲端 metadata 位址）／私有網段，**內網 IdP 須於此顯式放行**；不提供「關閉位址檢查」的布林開關。非 release 模式下，列於此的主機名同時允許 http（供 dev IdP 靶機使用）。內網 IdP 若用自簽憑證，須把 CA 加進容器的信任存放區——系統**不提供跳過 TLS 驗證的開關**。 |

**必須保留至少一個本地 admin 帳號**（啟用 SSO 前先確認）：

- 系統維持不變式「本地 admin 數量不得自一以上降為零」——把最後一個本地 admin 改為僅外部登入、
  停用、移除 admin 角色或刪除，皆會被拒絕。
- 理由不只是「IdP 掛了就進不去」：**封印解封（`KEK_PROVIDER=ui`）與初始管理員驗證只認本地憑證**，
  該路徑發生在系統尚未完全啟動的階段，不可能經由外部 IdP 完成。全體 admin 都外部化＝
  一旦進入封印狀態即無人能解封。
- 該本地 admin 應設強密碼並啟用 MFA，作為 break-glass 帳號使用。

**IdP 端停權不會自動終斷進行中的協議連線**：

- 使用者於 IdP 端被停權／刪除，本系統**不會**即時得知（OIDC 無反向通知，除非另接
  back-channel logout——本版未實作）。既有的 SSH／RDP／VNC 等協議連線建立後不再使用憑證，
  因此會**繼續存活**，由閒置逾時（`SSH_IDLE_TIMEOUT_MINUTES`）與最大連線時長治理；
  已簽發的 access token 亦會存活至到期（固定 15 分鐘）。IdP 端停權的實際效果是「下次登入被拒」。

**多副本部署的已知邊界**（單實例部署不受影響）：

- 錄影播放存取憑證（recording token）的授權為 **per-process**：token 由哪個後端副本簽發，
  就只有該副本能兌換與撤銷。多副本下若停用帳號／provider 的請求落在其他副本，
  簽發副本上既有的 token 會存活至 TTL 到期——殘窗 **≤120 秒、唯讀能力**（只能取得
  已錄製內容，不能建立新連線）。此邊界屬多副本部署的前置缺口（見
  [部署形態限制](ops/deployment-topology-limits.md)），上 HA 前須以跨副本通知機制一併解決。
- **需要即時切斷者，必須在本系統的管理端操作**：停用該使用者帳號（推進使用者憑證世代）
  或停用整個 provider（推進 provider 世代）。兩者皆會撤銷 refresh、拒絕既簽 access、
  終斷該範圍的協議連線並收線監看／分享訂閱。
- provider 的 **secret 輪替與刪除比照停用**走同一套完整失效流程；`auth_epoch` 只增不減，
  故「停用後短時間重新啟用」不會復活攻擊者手上的既簽憑證。副作用是該 provider 的全體使用者
  被強制重新登入——這是刻意取捨（輪替動機通常是舊 secret 可能已洩漏）。

**可信代理設定的重要性**：SSO 的 callback 與 exchange 端點為公開端點並掛 per-IP 限流；
未設定 `TRUSTED_PROXIES` 時，限速鍵一律採 socket peer IP 並忽略轉送標頭
（無可信代理鏈約定時，標頭可被任意偽造，寧可影響可用性也不提供可繞過的假防線）。
於反向代理後方部署時務必正確設定 `TRUSTED_PROXIES`，否則全部請求會被視為來自代理的同一個 IP。

### 5. LDAP 目錄設定

LDAP 目錄設定（位址／bind 帳密／搜尋參數／屬性映射）由管理端存入資料庫，
於「身分管理 → LDAP 目錄」頁維護；**資料庫是唯一事實源**，
`.env` 的 `LDAP_*` 九個鍵只是**首次啟動的 seed 來源**。

| 情境 | 行為 |
|---|---|
| 首次啟動時 `.env` 已設 `LDAP_ENABLED=true` | 解封後將 env 值一次性寫入資料庫，之後一律以資料庫為準 |
| 首次啟動時未啟用（範本預設 `LDAP_ENABLED=false`） | 不 seed，資料表維持空白；於管理端 UI 建立設定即可 |
| seed 完成後修改 `.env` 的 `LDAP_*` | **不生效**——改設定請走 UI |
| 於 UI 刪除設定後重啟 | 不會被 env 重新灌回（系統記錄「已完成評估」標記，不因資料列消失而重跑） |

出站限制：對目錄的連線一律拒絕解析至 loopback／link-local（含雲端 metadata 位址）／未指定位址／
multicast；**私有網段預設放行**（目錄服務的常態位置即內網，此處與 OIDC 的公網 IdP 前提相反）。
需要以 loopback 位址連線的特殊場景，於 `LDAP_ALLOWED_LOOPBACK_ENDPOINTS` 以 `host:port`
精確列舉放行，不支援萬用字元，亦不提供關閉檢查的開關。

**`.env` 不會被回寫**：seed 之後於管理端所做的任何變更都不會反映到 `.env`——
產品不修改部署方管理的檔案。故 `.env` 內的 `LDAP_*` 值只是首次啟動當下的快照，
不可當作現行設定的參考來源；要看現行值請開管理端頁面。

### 6. 容量與儲存規劃

容量規劃的主軸是**錄影儲存增長**——後端行程本身不會是先飽和的資源（見文末）。
下列數字是開發環境的參考觀測、非承諾值，對你的硬體沒有預測力；能跨環境轉移的是**換算方法**。

#### 錄影儲存增長率（文字與圖形分開，差約兩個數量級，不可平均）

| 協議 | 觀測 | 性質 |
|---|---|---|
| 文字終端 SSH（`.cast`） | 閒置約 30 B/s ≈ 105 KB/會話小時；滿載放大係數約 1.32x | 文字 |
| 圖形 RDP／VNC（`.guac`） | 靜態桌面約 10.4 MB/會話小時起算 | 圖形 |

> 兩筆都是**閒置下界**（量自無輸入的終端／無畫面變化的靜態桌面）。真實操作（捲動輸出、
> 拖曳視窗、切換畫面）會高出數倍到一個數量級——下界只能確認「至少要準備這麼多」，不可當規劃值。

**換算方法（可跨硬體轉移的部分）**

- **文字**：錄影磁碟 ≈ 終端輸出位元組 × 1.32（asciicast 的 JSON 框架與時戳開銷），
  用你自己環境的「每人每日終端輸出量」代入。
- **圖形**：以 10.4 MB/會話小時**起算**，依實際操作強度往上乘；磁碟需求 ≈
  同時圖形會話數 × 平均會話時長 × 增長率 × 保留天數，並保留餘裕。
- 保留期由安全政策頁管理（見下方「生產環境的部署方責任與行為邊界 → 日誌與錄影保留」），
  磁碟需求 ≈ 每日增長量 × 保留天數。

#### 並發容量

**Custodexa 不設並發會話上限，也不會因為會話數而拒絕建線。**實際會先飽和的資源，依應檢查的順序：

1. **guacd 容器（圖形協議）**——每條 RDP/VNC 會話對應一條 guacd 連線，CPU 與記憶體都由它承擔，
   是圖形場景的真正上限，須依你的圖形會話比例單獨壓測。
2. **錄影磁碟的寫入頻寬與容量**——以上表圖形增長率 × 同時圖形會話數估算。
3. **資料庫連線池上限**。
4. **目標主機自身的限制**——例如 sshd 的 `MaxSessions`／`MaxStartups`，與本系統無關但會先擋住你。

後端 Go 行程本身不是瓶頸：每會話約 +16 goroutine、記憶體增量小到量測雜訊底之下
（上界約 148 KB/會話），1 GB 可用記憶體約當數千條文字會話。一句話：
**文字會話的容量幾乎只受磁碟限制；圖形會話的容量由 guacd 決定。**

#### 儲存監控

- 錄影佔用量在產品內可見（具稽核檢視權限者的主控頁「錄影佔用」卡）；採集端可讀
  `custodexa_recording_storage_bytes`（`/metrics`，每 30 秒刷新，其值最多落後一個刷新週期）。
- **系統不設儲存上限**——稽核系統的可用性不應被儲存量挾持，而「照常建線但不錄影」會產生
  無錄影的特權會話，兩者都不可接受。故磁碟總容量與耗盡風險由你的基礎設施監控承擔；
  請對 `custodexa_recording_storage_bytes` 設成長率或容量門檻告警。
- 需要縮減佔用時走**保留期**（系統設定→安全政策），依時間刪除過期錄影。

## 生產環境的部署方責任與行為邊界

正式對外服務前，下列事項屬於**部署方責任**——本產品刻意不代勞，也不假裝有做；
連同兩項行為說明一併集中在此，部署上線前逐項過一遍。

### 對外傳輸加密（TLS）

stock 部署**本身不提供 TLS**——frontend 只映射 `80`/HTTP，
backend 為內網明文、不對外。對外 TLS termination 為**部署方職責**：須於本服務前置一個
TLS-terminating 反向代理／ingress，提供 TLS 1.2+、可信憑證、HTTP→HTTPS redirect、HSTS 與
**WebSocket upgrade 轉發（wss）**；若 LB／ingress 到主機的 hop 跨越不可信網段，該 hop 亦須加密
（re-encrypt）。應用已 TLS-ready——前端依頁面協定自動 `ws`↔`wss`、認證走 Authorization header
（無 Secure cookie 顧慮），故置於 HTTPS edge 後無需改應用。此為部署契約，
非應用強制控制——請據實驗證你的 edge。

**最小可用範例（docker 跑 nginx 反代 + 你的憑證）**：

1. 準備憑證：把憑證鏈與私鑰放到 `./tls/fullchain.pem`、`./tls/privkey.pem`。
   來源用 Let's Encrypt 或企業 CA 皆可；自簽憑證僅供測試（瀏覽器會警告，且 OIDC 等
   外部整合可能拒絕）。
2. 取範例設定，換上你的網域：

   ```bash
   mkdir -p tls
   cp docker/reverse-proxy/nginx-tls.conf.example tls/custodexa.conf
   # 編輯 tls/custodexa.conf：兩處 server_name your.domain.example 換成你的網域
   ```

   範例已含 TLS 1.2+、HTTP→HTTPS redirect、HSTS 與 WebSocket upgrade 轉發；
   upstream 指向 compose 服務名 `frontend:80`，反代加入同一 docker 網路即可解析。
3. 讓出對外埠：把 `docker-compose.yml` 中 frontend 的 `ports:` 兩行註解掉
   （反代經 docker 網路直達 frontend，stock 的 `80:80` 映射不再需要，
   留著會與反代搶 80 埠），然後 `docker compose up -d frontend` 套用。
4. 啟動反代。compose 定義的是具名網路 `custodexa-network`，docker 實際網路名會帶
   專案目錄前綴（例如目錄叫 `custodexa` 時為 `custodexa_custodexa-network`），
   先以 `docker network ls` 確認再帶入。conf 掛載路徑刻意蓋掉 image 內建的
   `default.conf`——內建檔會與你的設定衝突（同名 server_name），或以 welcome 頁
   兜底吃掉不匹配網域的請求：

   ```bash
   docker run -d --name custodexa-tls --restart unless-stopped \
     --network custodexa_custodexa-network \
     -p 80:80 -p 443:443 \
     -v "$PWD/tls/custodexa.conf:/etc/nginx/conf.d/default.conf:ro" \
     -v "$PWD/tls/fullchain.pem:/etc/nginx/certs/fullchain.pem:ro" \
     -v "$PWD/tls/privkey.pem:/etc/nginx/certs/privkey.pem:ro" \
     nginx:stable-alpine
   ```

5. 驗證三件事：

   ```bash
   curl -sI http://your.domain.example/ | head -1    # 應為 301（導向 https）
   curl -sI https://your.domain.example/ | head -1   # 應為 200（自簽測試加 -k）
   # 登入後開一條 SSH 連線，瀏覽器 DevTools 的 Network 應看到 wss:// 串流——
   # 若終端開不起來而頁面正常，多半是 WebSocket upgrade 轉發沒生效
   ```

   有設 OIDC 時，`PUBLIC_BASE_URL` 須同步改為 `https://your.domain.example`（見上節）。

   改用主機安裝的 nginx（不跑容器）時，設定同一份：upstream 改指
   `127.0.0.1:<frontend 對外埠>`，並保留 frontend 的 ports 映射但建議綁 loopback
   （`127.0.0.1:8080:80`）；nginx 低於 1.25.1 不支援 `http2 on;` 指令，
   改寫成 `listen 443 ssl http2;` 即可。其他反代（Caddy、Traefik、雲端 LB）
   滿足同一組契約即可。

### 時間同步（PCI 10.6）

容器時鐘繼承宿主，本產品不內建 NTP client。生產宿主必須啟用時間同步
（chrony / systemd-timesyncd / 雲平台預設 NTP），時間源採 UTC 並指向業界公認的時間伺服器（10.6.2）；
宿主系統時間變更的存取控制與稽核屬 OS 層責任（10.6.3）。
審計日誌時戳的可比性完全依賴宿主時鐘正確。

### 審計完整性的能力邊界（PCI 10.3.4）

audit_logs 逐列 HMAC＋匯出 manifest Ed25519 簽章＋syslog 即時離機轉發三者合為補償控制
——可偵測「既有列被修改」與「基準時間後被竄改並清空 HMAC」（首次啟動記錄啟用基準，
之後所有**入庫**路徑經 `BeforeCreate` 蓋章，基準後仍空 HMAC 即判不符——檔案降級與
佇列滿載丟棄的事件不入庫、不經蓋章，故措辭為「入庫路徑」而非「寫入路徑」）；
「整列連同 HMAC 一併刪除」**由檢查點鏈偵測**（區間聚合＋鏈接＋Ed25519 簽章，
合法清除以簽章 tombstone 與竊取區分），其證明力邊界 R0-R6 見驗證頁與
`openspec/specs/audit-checkpoint-chain/spec.md`。
完整性蓋章鑰為系統生成之版本化鑰（KEK 包裹落庫，自 v1 起），與 `JWT_SECRET` 無派生關係、不需任何環境變數設定。

### 日誌與錄影保留

保留天數由安全政策頁管理，`0 = 永久保留`。`RECORDING_RETENTION_DAYS` 僅在**首次啟動**
（政策表無此列時）播種，之後改 env 重啟不再生效，一律以政策頁為準。
到期清除為每日 02:00 硬刪且不可還原，縮短保留期限時 UI 會先確認。
單次執行刪除上限預設 10 萬筆／表，高流量部署可用 `RETENTION_MAX_PER_RUN` 調高以免每日到期量追不上。

## 常用命令

### 重啟服務
```bash
docker compose restart backend
```

### 重新建置（修改 Dockerfile 或依賴後）
```bash
docker compose up --build
```

### 停止服務
```bash
# 停止服務（應用資料保留於 ${DATA_PATH:-./data}）
docker compose down

# 停止並清除 named volume（go_modules / k3s 等）
# 注意：audit / recordings / postgres 為 bind mount，不受 -v 影響，仍留在 ${DATA_PATH:-./data}
docker compose down -v

# 完全清除應用資料（審計 / 錄影 / 資料庫）：停止後手動刪除 DATA_PATH 目錄內容
# 預設 ./data；若已自訂 DATA_PATH，改刪該實際路徑（.env 的值不會帶入此手動指令）
docker compose down && rm -rf ./data/*
```

## 開發工作流程

> 本節與以下測試段落皆需**開發版**（`.env` 已啟用 `COMPOSE_FILE=docker-compose.dev.yml`）——
> 熱重載、8080/3000 直連埠與測試靶機皆為開發版特性。

### 後端開發
1. 修改 `backend/` 下的程式碼
2. Air 自動重新編譯（熱重載）
3. 查看日誌確認變更生效

### 前端開發
1. 修改 `frontend/` 下的程式碼
2. Vite 自動重新載入（HMR）
3. 瀏覽器自動更新

### 資料庫管理
```bash
# 連線至 PostgreSQL
docker compose exec postgres psql -U postgres -d custodexa

# 常用 SQL 命令
\dt          # 列出所有表
\d users     # 查看 users 表結構
SELECT * FROM users;
\q           # 退出
```

## 故障排除

### 埠號被佔用
```bash
lsof -i :80    # 正式版前端
lsof -i :3000  # 開發版前端
lsof -i :8080  # 開發版後端
# 停止佔用的程序或修改 docker-compose.yml 埠號
```

### 容器無法啟動
```bash
# 查看錯誤訊息
docker compose logs backend

# 重新建置
docker compose up --build
```

### admin 密碼遺失，或啟動被弱憑證掃描擋下（離線重設）

兩種情況走同一條離線重設路徑：

- **唯一 admin 尚未首登且初始密碼遺失**（進不了系統）。
- **啟動被弱憑證掃描擋下**：release 啟動時會掃描所有具 admin 角色的帳號，若任一仍在使用
  公開已知的弱憑證（例如 `admin123`），服務會**拒絕啟動**，要求先重設。

做法是以 DB 直連在**單一交易**內同時更新密碼雜湊、`must_change_password=true`
與寫入 `password_histories`（三者同一交易，避免留下不一致狀態）。
範例（PostgreSQL，`$1`＝新 bcrypt 雜湊、`$2`＝admin 使用者 id）：

```sql
BEGIN;
UPDATE users SET password = $1, must_change_password = true, password_changed_at = now() WHERE id = $2;
INSERT INTO password_histories (user_id, password_hash, created_at) VALUES ($2, $1, now());
COMMIT;
```

bcrypt 雜湊須以**外部工具**產生，例如：

```bash
htpasswd -bnBC 10 "" '你的新密碼' | tr -d ':\n'
```

或任一語言的 bcrypt 函式庫（cost 取 10，與產品預設一致）。

**正式版映像內沒有產生雜湊的工具，也沒有 Go 工具鏈**——請在你自己的機器上產生後貼進 SQL。
（`backend/scripts/generate_hash.go` 帶 `//go:build ignore`，不編入任何二進位，
只能在有 Go 環境的開發機上以 `go run` 執行。）

本產品**不提供**線上救援 API（具 DB 寫入權者本可直接重設，不另開遠端權限面）。

### 清除並重新開始
```bash
docker compose down -v
rm -rf ./data/*          # bind mount 資料 down -v 不清，須手動刪（預設 ./data；自訂 DATA_PATH 改該路徑）
docker image prune -a
docker compose up --build
```

### macOS：改前端後畫面沒更新（HMR 未觸發）
macOS Docker volume 的 fsnotify 不可靠，Vite 可能沒偵測到檔案變更。
不要用 `docker compose restart frontend`（會撞 bind-mount race 導致 ENOENT 崩潰），改用：
```bash
docker compose up -d --force-recreate frontend
```

### 後端改動疑似沒生效（Air 熱重載跑舊二進位）
多檔交叉編輯的中途破碎狀態會讓 Air build 失敗並繼續跑舊二進位。改完後：
```bash
docker compose restart backend
# 驗證運行中的二進位含新符號
docker compose exec -T backend sh -c "strings /app/tmp/main | grep <新函式名>"
```

## 測試連線功能

> 流程與上方「首次使用」相同；本節的測試靶機只存在於**開發版**
> （正式版請把主機換成你自己的目標機）。

### SSH 連線測試

1. 登入系統（帳號 admin；首次以 .env 的 ADMIN_INITIAL_PASSWORD 登入並改密，其後用新密碼）
2. 前往「資產管理」頁面，以「新增資產」建立 SSH 資產（欄位說明見「首次使用」）
3. 在資產列表點該列的「連線」
4. 工作區開啟網頁終端、出現遠端主機的提示符即成功
5. 執行命令測試：`ls`, `pwd`, `whoami`

**測試容器資訊**：
- 主機: ssh-test
- 埠號: 2222
- 帳號: testuser / testpass123

### RDP 連線測試

1. 登入系統（帳號 admin；首次以 .env 的 ADMIN_INITIAL_PASSWORD 登入並改密，其後用新密碼）
2. 前往「資產管理」頁面
3. 創建 RDP 資產
4. 點擊「連線」按鈕
5. 應看到 Xfce 桌面環境

**測試容器資訊**：
- 主機: rdp-test
- 埠號: 3389
- 帳號: testuser / testpass123

### SSO（OIDC）登入測試——dex 靶機（僅開發版）

開發版內建 dex（CNCF 輕量 OIDC provider）作為 IdP 靶機，組態見 `docker/dex/config.yaml`。

**靶機資訊**：
- issuer: `http://dex.localhost:5556/dex`（**後端容器內與瀏覽器共用同一字串**，見下方說明）
- client_id / client_secret: `custodexa-dev` / `custodexa-dev-secret`
- redirect URI: `http://localhost:3000/api/v1/auth/oidc/callback`
- 測試帳號：`oidcuser@dex.localhost` / `oidcpass123`（一般使用者）；
  `conflict@dex.localhost` / `conflictpass123`（`preferred_username` 刻意為 `admin`，測同名衝突拒絕）

**設定步驟**：
1. `.env` 設 `PUBLIC_BASE_URL=http://localhost:3000`、
   `OIDC_ALLOWED_INTERNAL_HOSTS=dex.localhost`（非 release 模式下，列於此的主機名同時允許 http），
   並視需要把 `http://dex.localhost:5556/dex` 加入 `OIDC_DEDICATED_ISSUERS`（否則視為共用身分域，
   准入規則必須帶組織歸屬條件）。改後 `docker compose up -d --force-recreate backend`。
2. 以 admin 登入 → OIDC provider 管理頁建立 provider（issuer / client_id / secret 如上）。
3. 登出後登入頁應出現該 provider 的 SSO 按鈕。

**驗證 discovery（設定 provider 前先做，可省下大量誤判）**：
```bash
# 後端容器內（go-oidc 實際走的路徑）——回應的 issuer 必須與設定值逐字相同
docker compose exec backend wget -qO- http://dex.localhost:5556/dex/.well-known/openid-configuration
# 瀏覽器側（host 端）
curl -s http://dex.localhost:5556/dex/.well-known/openid-configuration
```

> **為什麼 hostname 必須是 `dex.localhost`**：go-oidc 對 discovery 回應的 issuer 做**完整字串比對**，
> 故後端（容器內解析）與瀏覽器（host 端解析）必須用同一個字串。IP 字面值不可行——backend 容器內的
> `127.0.0.1` 指向 backend 自己，而 `extra_hosts` 只能改 hostname 解析、改不了 IP 字面值的 loopback 語義。
> `dex.localhost` 則兩端皆可達：compose 的 network alias 使容器內 DNS 解析至 dex 容器，
> 瀏覽器端依 RFC 6761 解析至 loopback 再經 `127.0.0.1:5556` port mapping 到同一個 dex。
> 改 alias、改埠或改 `docker/dex/config.yaml` 的 issuer，三者必須同步。

> dex 只存在於 `docker-compose.dev.yml`，正式版不含此服務；埠綁 `127.0.0.1` 不暴露到 LAN。

## 測試錄製與回放功能

### SSH 錄製回放

1. 建立 SSH 連線並執行一些命令
2. 斷開連線
3. 前往「連線管理」的歷史會話列表
4. 點該筆會話查看詳情
5. 應看到 asciinema 播放器，可播放終端操作

### RDP 錄製回放

1. 建立 RDP 連線並操作桌面
2. 斷開連線
3. 前往「連線管理」的歷史會話列表
4. 點該筆會話查看詳情
5. 應看到 Guacamole 播放器，可回放圖形操作

## 營運程序

本文件涵蓋的是**把系統跑起來**。實際營運需要的程序另見 `docs/ops/`：

| 文件 | 何時需要 |
|---|---|
| [備份與還原](ops/backup-and-restore.md) | 部署完成後立即建立備份機制；**KEK 材料的保管前提務必在部署前讀過**——某些模式下材料遺失即資料永久不可解 |
| [部署與升級 SOP](ops/upgrade-sop.md) | 每次版本升級前。**本版不提供 migration 回滾**，升級失敗時唯一退路是還原備份，故備份時點須先決定 |
| [部署形態限制](ops/deployment-topology-limits.md) | 規劃架構時。1.0 為單實例部署，多副本與滾動更新皆不支援 |
| [平台自身特權憑證輪替](ops/privileged-credential-rotation.md) | 定期輪替，或人員異動時。含 LDAP bind、通知通道 secret、KEK／DEK 與 env 側鑰 |

## 下一步

- 查看 [zh-TW/README.md](zh-TW/README.md)（繁中）或 [README.md](../README.md)（英文）了解專案架構與文檔地圖
- 開發流程（OpenSpec、commit 規範、驗證慣例）見 [zh-TW/CONTRIBUTING.md](zh-TW/CONTRIBUTING.md)
- 架構不變式與測試紀律見 [dev/conventions.md](dev/conventions.md)、[dev/testing.md](dev/testing.md)

## API 文檔

API 文檔的唯一事實源是 [API_SPEC.md](API_SPEC.md)——本專案不維護由註解生成的第二份
API 產物。

其中的**端點索引**由測試自實際路由註冊生成，並由 `TestAPIIndex` 守衛雙向相等——
索引缺路由或含幽靈條目都會使測試變紅。動到路由後重新生成（在**開發版**下執行；
`.env` 已啟用 `COMPOSE_FILE=docker-compose.dev.yml` 時不需帶 `-f`）：

```bash
docker compose run --rm --no-deps -v ./docs:/app/cmd/server/testdata/docs-rw backend \
  go test ./cmd/server -run '^TestAPIIndex$' -update
```

平時執行測試的容器只有唯讀的 `docs/` 掛載（守衛不得竄改其驗證對象），故重新生成
必須用上述額外加掛可寫點的一次性容器。索引以外的散文章節仍為人工維護。

路由本身另有 golden baseline 保護（`cmd/server/testdata/route-golden`）。刻意變更
路由後同樣需重新生成，且**其 diff 須在 commit 中逐條審視**：

```bash
docker compose exec backend go test ./cmd/server -run '^TestRoutesMatchGolden$' -update
```
