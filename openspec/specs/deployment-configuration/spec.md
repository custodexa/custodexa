# deployment-configuration Specification

## Purpose
規範部署與環境設定的一致性與正確性：環境變數範本的完備性守衛、dev 與正式版 compose 對範本的一致消費、應用資料落點可設定、預設 compose 指令產出正式版部署、測試專用掛載不外溢正式版，以及首次部署指示與實際啟動路徑的一致。
## Requirements
### Requirement: 環境變數範本完備性
系統所有後端**產品碼**消費中的環境變數 SHALL 全數記載於**專案根 `.env.example`（唯一環境變數範本）**或屬明確 allowlist。自動化漂移守衛測試 SHALL 掃描後端產品原始碼（排除 `_test.go`、vendor、testdata，以及 `//go:build ignore` 的獨立開發/smoke 工具 `scripts/`）中傳給已知讀取函式（`os.Getenv`/`os.LookupEnv`、config helper `getEnv`/`getEnvInt`/`getEnvBool`、`SeedFromEnv`）的字面 key 集合，並斷言其為範本記載集合 ∪ allowlist 的子集。allowlist 兩類：系統/測試專用變數（HOME/PATH、`APIERROR_LOCALE_DIR`、`SSH_TEST_HOST`）；以及 **compose 提供的拓撲/模式常數**（`DB_HOST`/`GIN_MODE`/`DB_DRIVER`/`GUACD_HOST` 等，由 compose `environment:` 提供、不入使用者範本）。無法字面掃描的純動態讀取（key 傳入區域閉包而非上述函式，如逾時退路）SHALL 由測試維護的 `knownIndirectKeys` 靜態清單併入核對。新增未記載的產品消費變數 SHALL 使守衛測試失敗。守衛測試在 backend 容器內執行，範本 SHALL 唯讀掛入容器（`/opt/custodexa/.env.example`，掛在 `/app` bind mount 之外以免污染 host）。

#### Scenario: 新增未記載變數觸發失敗
- **WHEN** 後端新增一個 `os.Getenv("NEW_VAR")` 讀取點而未同步加入 `.env.example`
- **THEN** 漂移守衛測試失敗，指出 `NEW_VAR` 未記載

#### Scenario: 全數記載時通過
- **WHEN** 所有消費中的環境變數皆記載於 `.env.example`（或屬 allowlist）
- **THEN** 漂移守衛測試通過

#### Scenario: 純動態 key 以 knownIndirectKeys 核對
- **WHEN** 變數僅經區域閉包動態讀取（如 sshproxy 逾時退路的 `SSH_IDLE/MAX_*_MINUTES`），key 未字面傳入已知讀取函式，字面掃描無法命中
- **THEN** 該 key 由測試的 `knownIndirectKeys` 靜態清單納入完備性核對，仍要求記載於範本

### Requirement: dev 與 prod compose 一致消費範本
開發版（`docker-compose.dev.yml`）與正式版（`docker-compose.yml`）compose SHALL 皆以 `env_file` 消費專案根 `.env`（由唯一範本 `.env.example` 複製）承載的全部使用者可調設定（機密、DB 認證、功能開關、LDAP seed 值、運維上限、`DATA_PATH`），使兩環境操作流程一致：`cp .env.example .env` → 依環境編輯 → up。使用者可調值 SHALL NOT 硬編於 compose `environment:`（否則 `environment:` 優先序會蓋過 env_file 形成「假可調」）。與部署拓撲或映像綁定的值（服務名主機、驅動、模式常數 `GIN_MODE`、容器內固定路徑）SHALL 留在 compose `environment:`。範本 SHALL 可作 `env_file` 直接消費——所有說明置於獨立註解行、值行不帶行內 `#` 註解（`env_file` 對空值的行內註解不剝除，會使值含註解導致啟動失敗；範本多數旋鈕預設為空值故一律禁用行內註解）。

#### Scenario: 運維於範本設值於 dev 與 prod 皆生效
- **WHEN** 運維在 `.env` 設定 `JWT_SECRET`、`FEATURE_ALERTING_ENABLED` 等執行期旋鈕並以開發版或正式版 compose 啟動
- **THEN** 後端容器以該 `.env` 值運行，無需改動 compose 檔；兩環境流程一致（LDAP 9 鍵為 seed 專用例外，語義見「seed 專用環境變數的語義註記」）

#### Scenario: 範本可安全作 env_file 消費
- **WHEN** `cp .env.example .env` 後直接以 compose `env_file` 消費
- **THEN** 各變數值為其宣告值（不含任何行內註解殘留），服務正常啟動

#### Scenario: 拓撲綁定值不入範本
- **WHEN** 檢視使用者面 `.env.example`
- **THEN** 不含 compose 網路服務名（如 `DB_HOST=postgres`、`GUACD_HOST=guacd`）、容器內掛載點（如 `APIERROR_LOCALE_DIR`）與模式常數（`GIN_MODE`），這些留在 compose `environment:`

### Requirement: 應用資料落在可設定的資料夾根
主體應用持久化資料（審計日誌、會話錄影、資料庫）SHALL 儲存於單一運維可設定的資料夾根 `DATA_PATH`，預設為專案內相對路徑 `./data`，透過 bind mount 映入容器；生產部署 SHALL 能將 `DATA_PATH` 覆寫為指定資料夾或磁碟路徑以集中管理。建置快取（go modules、前端 node_modules）與測試專用容器（k3s/ssh/vnc/rdp/mysql-test）不納入此資料夾。

#### Scenario: 預設落於專案內 data 目錄
- **WHEN** 運維未設 `DATA_PATH` 直接啟動 compose
- **THEN** 審計/錄影/資料庫資料落於專案內 `./data/{audit,recordings,postgres}`，可於主機檔案系統直接檢視

#### Scenario: 覆寫資料夾根
- **WHEN** 運維設定 `DATA_PATH=/opt/custodexa/data` 並啟動 compose
- **THEN** 資料落於 `/opt/custodexa/data/{audit,recordings,postgres}`

#### Scenario: 資料於容器重建後留存
- **WHEN** 執行 `docker compose down` 後 `docker compose up`（不刪除 bind mount 目錄）
- **THEN** 先前寫入的審計/錄影/資料庫資料仍在

### Requirement: 預設 compose 指令產出正式版部署

未帶 `-f` 的 `docker compose` 指令 SHALL 作用於正式版定義，該定義 SHALL 位於慣例檔名 `docker-compose.yml`。開發版 SHALL 為具名檔 `docker-compose.dev.yml`，僅在顯式指定或透過 `COMPOSE_FILE` 選用時生效。

`.env.example` SHALL 以註解形式提供 `COMPOSE_FILE=docker-compose.dev.yml` 並說明其用途；該行 SHALL NOT 為生效狀態——若範本帶生效值，複製範本者將取得開發版，與本要求相反。

註：`COMPOSE_FILE` 由 compose CLI 消費而非應用程式讀取；env 漂移守衛為單向（僅斷言程式碼消費的 key 皆記載於範本），故此變數不影響守衛結果，註解狀態的理由純為上述部署語義。

#### Scenario: 複製範本後預設取得正式版
- **WHEN** 於乾淨 clone 執行 `cp .env.example .env`、填入必要值後執行 `docker compose up -d`
- **THEN** 起用的是正式版服務組成（應用與其依賴，不含測試靶機），前端以正式版對外埠提供編譯產物而非開發伺服器

#### Scenario: 開發者啟用 COMPOSE_FILE 後日常指令指向開發版
- **WHEN** 開發者於自己的 `.env` 取消註解 `COMPOSE_FILE=docker-compose.dev.yml`，執行不帶 `-f` 的 `docker compose exec backend ...`
- **THEN** 指令作用於開發版容器，無須顯式 `-f`

#### Scenario: 顯式 -f 覆蓋 COMPOSE_FILE
- **WHEN** 已設 `COMPOSE_FILE` 的開發者執行帶顯式 `-f docker-compose.yml` 的指令
- **THEN** 指令作用於正式版定義，使正式版仍可於開發機驗證

### Requirement: 測試專用掛載不入正式版 compose

守衛測試所需的唯讀掛載點（三語 locale、`.env.example`、`docs/`）SHALL 僅存在於開發版 compose；正式版 compose SHALL NOT 掛載任何測試用途路徑。

遷移這些掛載點時 SHALL 以破壞式方式驗證每一處確實生效：僅修改被驗證對象而不動任何 Go 原始碼，確認對應守衛轉紅。理由：`go test` 的結果快取只追蹤 module 內被開啟的檔案，掛載點錯位時守衛會回報 `(cached)` 通過而根本不執行——「測試通過」不足以證明守衛在執行。

#### Scenario: 正式版 compose 無測試掛載
- **WHEN** 檢視正式版 compose 的 backend `volumes`
- **THEN** 不含三語 locale、`.env.example`、`docs/` 等測試用途掛載

#### Scenario: 守衛於開發版 compose 內確實執行
- **WHEN** 於開發版 compose 內，僅修改 `.env.example`（新增或移除一個變數）而不動任何 Go 檔案後執行對應守衛
- **THEN** 守衛轉紅而非回報 `(cached)` 通過；`docs/` 與三語 locale 的對應守衛以同法各自驗證

### Requirement: seed 專用環境變數的語義註記
僅供首次啟動 seed 的環境變數（LDAP 9 鍵：`LDAP_ENABLED`／`LDAP_URL`／`LDAP_BIND_DN`／`LDAP_BIND_PASSWORD`／`LDAP_BASE_DN`／`LDAP_USER_FILTER`／`LDAP_ATTR_EMAIL`／`LDAP_ATTR_FULLNAME`／`LDAP_SKIP_TLS_VERIFY`）SHALL 於 `.env.example` 註明「僅首次啟動 seed 入資料庫；之後以管理 UI 為準，改本檔不生效」。其執行期消費點 SHALL 自 config 移除（僅 seed 路徑消費），確保「改 env 不生效」與程式碼一致。seed 路徑的消費使該組鍵仍屬漂移守衛的必載集合——自範本移除任一鍵 SHALL 使守衛失敗（註：守衛為單向子集核對「消費 ⊆ 記載」，不保證反向；「範本記載但無人消費」不在其偵測範圍，此為守衛既有語義而非新引入）。

#### Scenario: seed 後修改 env 不影響執行期
- **WHEN** 資料表已有 LDAP 設定列（或 seed marker 已寫），部署方修改 `.env` 的 `LDAP_URL` 並重啟服務
- **THEN** 執行期使用的仍是資料庫中的設定值，env 修改不生效（與範本註記一致）

#### Scenario: 自範本移除仍被消費的 seed 鍵觸發守衛失敗
- **WHEN** `.env.example` 移除 `LDAP_BIND_DN` 而 seed 路徑仍以字面 key 讀取該變數
- **THEN** 漂移守衛測試失敗，指出該鍵未記載

### Requirement: 設定已遷移至資料庫的功能其降版預檢
當某功能的設定事實源已自環境變數遷移至資料庫，降版至讀取環境變數的舊版本 SHALL 有明確的運維預檢程序記載於部署文件：自管理介面取得現行設定值、回填 `.env`（含祕密欄位，若先前已依建議移除）、降版後以該功能執行一次登入或連線驗證。系統 SHALL NOT 自動回寫部署方的環境檔。文件 SHALL 明示「保留原 `.env` 不等於保留最新行為」——環境變數為遷移當下的快照，其後於管理介面所做的變更不會反映其中。

#### Scenario: 降版預檢載於部署文件
- **WHEN** 運維查閱降版程序以自本版本回退
- **THEN** 文件列出 LDAP 設定的回填步驟與降版後驗證方式，並警示 env 為過期快照

#### Scenario: 未回填即降版的後果可預期
- **WHEN** 部署方於遷移後修改過 LDAP 設定並移除 `.env` 中的 bind 密碼，未執行回填即降版
- **THEN** 行為回到 env 快照（設定過期或 LDAP 登入失敗），此結果已於文件明載而非未定義行為

### Requirement: 首次部署指示與實際啟動路徑一致

專案 README 之快速開始 SHALL 逐步對應**預設 compose 指令實際走的那條路徑**，
SHALL NOT 描述任何在該路徑上不成立的步驟、位址或憑證。具體 SHALL 涵蓋：

- **範本複製步驟 SHALL 明列**（`cp .env.example .env`）——正式版 compose 以 `env_file`
  消費專案根 `.env`，缺檔即在啟動第一步失敗。
- **無出廠預設值而必須自行填入之機密鍵 SHALL 逐項列名**——照抄範本無法啟動者
  （KEK 材料、JWT 簽章鑰、初始管理員密碼、資料庫密碼）SHALL 於快速開始即點名，
  SHALL NOT 只寫「依需求調整」。
- **存取位址與登入方式 SHALL 為該指令實際產出的拓撲**——正式版與開發版之發佈埠不同時，
  SHALL 標明何者屬何拓撲；初始管理員憑證 SHALL 描述現行機制（由環境變數設定＋首登強制
  改密），SHALL NOT 保留任何已失效之預設帳密。
- **指令形式 SHALL 為現行 CLI**（`docker compose`）。

`.env.example` 之模式選擇型設定，其**營運後果 SHALL 揭露於選擇點**：凡不同取值會改變
「是否需要人為介入才能恢復服務」或「機密是否落於磁碟」者，該代價 SHALL 與選項並列，
SHALL NOT 僅記載於數十行外之其他段落——讀者在選擇點看不到的代價等同未告知。

#### Scenario: 照快速開始實走全新安裝
- **WHEN** 於全新環境取得專案樹並照 README 快速開始逐步執行
- **THEN** MUST 能啟動至登入畫面，MUST NOT 於任一步因範本缺檔、缺必填機密、
  埠或憑證與實際不符而中斷

#### Scenario: 本機 KEK 兩模式之代價並列於選擇點
- **WHEN** 檢視 `.env.example` 之 `KEK_PROVIDER` 段
- **THEN** `env` 與 `ui` 兩模式之代價 MUST 並列於該段（前者材料以明文存於磁碟、重啟免人
  介入；後者材料永不落地、但每次行程重啟都停在封印狀態須有人再輸入），
  MUST NOT 僅以「不落地」一詞帶過而將重啟後果留在他段

### Requirement: KEK 出貨預設模式
`.env.example` SHALL 出貨 `KEK_PROVIDER=ui`（材料鍵 `ENCRYPTION_KEY` SHALL 維持註解狀態
——ui 模式下材料鍵有值即組態矛盾）。該段 SHALL 於選擇點並列 ui 為預設的營運後果
（每次行程重啟停在封印狀態、須有人於解封頁再輸入）與切換為 `env`／`kms` 的顯式路徑。
開發者指引 SHALL 建議熱重載環境改用 `env`（行程隨每次重編譯重啟，ui 等於每次存檔重新解封），
並 SHALL NOT 宣稱「照抄範本即可啟動」——金鑰類設定無出廠預設值，任一模式皆需一次顯式動作
（跑快速啟動腳本、或自行生成／宣告）。

#### Scenario: 範本出貨值
- **WHEN** 檢視 `.env.example` 的 KEK 段
- **THEN** `KEK_PROVIDER=ui` 為未註解出貨值，`ENCRYPTION_KEY` 為註解狀態，且該段並列
  重啟後果與模式切換路徑

#### Scenario: 全新部署預設體驗經過初始化解封
- **WHEN** 於全新環境照 README 快速開始實走（不更動範本預設）
- **THEN** 系統以 ui 模式啟動至封印待初始化態，首次造訪前端進入初始化解封頁，
  完成初始化後方可登入

#### Scenario: 開發者路徑有指路
- **WHEN** 檢視範本的參與開發指引
- **THEN** 含「熱重載環境建議 `KEK_PROVIDER=env`」與取得材料的方式，無「照抄即可跑」宣稱
