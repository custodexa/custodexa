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

**物件儲存為資料根之外的可選落點**（自 `evidence-offsite-storage` 起）：離機儲存設定完成時（現行設定世代存在），會話錄影與證據包產物於落地後另上傳至部署方指定的物件儲存；該落點 SHALL NOT 取代 `DATA_PATH` 下的三個落點（錄影仍先寫本機、guacd 仍直寫本機目錄），SHALL 於範本與營運文件標示為資料根之外、由部署方承擔存取控管與靜態加密的落點。未設定時 SHALL 完全不影響上述三落點的行為。營運後果（物件儲存內為明文、同 key 覆寫的防護僅及於取回驗證拒付、遠端保留與防刪由部署方的 bucket 設定承擔、非 https 端點）SHALL 於管理介面的設定表單與營運文件揭露。

`OFFSITE_*` 環境變數 SHALL 僅供首次啟動的一次性 seed（其後的變更經管理介面），範本 SHALL 明載此語義。

#### Scenario: 預設落於專案內 data 目錄
- **WHEN** 運維未設 `DATA_PATH` 直接啟動 compose
- **THEN** 審計/錄影/資料庫資料落於專案內 `./data/{audit,recordings,postgres}`，可於主機檔案系統直接檢視

#### Scenario: 覆寫資料夾根
- **WHEN** 運維設定 `DATA_PATH=/opt/custodexa/data` 並啟動 compose
- **THEN** 資料落於 `/opt/custodexa/data/{audit,recordings,postgres}`

#### Scenario: 資料於容器重建後留存
- **WHEN** 執行 `docker compose down` 後 `docker compose up`（不刪除 bind mount 目錄）
- **THEN** 先前寫入的審計/錄影/資料庫資料仍在

#### Scenario: 離機未設定時三落點行為不變
- **WHEN** 運維未設定任何離機儲存設定（設定表零列，亦未以 `OFFSITE_*` 鍵 seed）
- **THEN** 錄影、審計與資料庫仍只落於 `DATA_PATH` 三落點，無任何對外上傳，範本守衛仍通過

#### Scenario: 物件儲存落點於範本被標示為資料根之外且註明僅供初次設定
- **WHEN** 運維檢視 `.env.example` 的離機儲存段
- **THEN** 該段明示物件儲存不在 `DATA_PATH` 之下、備份與存取控管由部署方承擔，於選擇點列出明文與遠端保留歸屬的後果，並註明本段僅供初次設定、其後的變更於管理介面進行

### Requirement: 預設 compose 指令產出正式版部署

未帶 `-f` 的 `docker compose` 指令 SHALL 作用於正式版定義，該定義 SHALL 位於慣例檔名 `docker-compose.yml`。開發版 SHALL 為具名檔 `docker-compose.dev.yml`，僅在顯式指定或透過 `COMPOSE_FILE` 選用時生效。

`.env.example` SHALL 以註解形式提供 `COMPOSE_FILE=docker-compose.dev.yml` 並說明其用途；該行 SHALL NOT 為生效狀態——若範本帶生效值，複製範本者將取得開發版，與本要求相反。原始碼部署正式版的部署形態由「部署形態由 .env 推導」的同一規則決定，SHALL NOT 以 `COMPOSE_FILE` 選擇；正式版的 profiles 由 `scripts/quickstart.sh` 推導並寫入 `.env` 的管理區（只含 `COMPOSE_PROFILES`），文件 SHALL 以 `quickstart.sh` 作為原始碼部署的啟動入口。

**安裝包部署根**（`custodexa.sh` 建立的部署，其根目錄沒有 `docker-compose.yml`）：管理腳本 SHALL 在根目錄 `.env` 的管理區（見「部署形態由 .env 推導」）寫入 `COMPOSE_FILE`（固定為 `current/compose.yml`；`current` 指向沒有單一 compose 的舊版 release 時，依部署形態以 `:` 接上該版的疊加檔，且不寫 `COMPOSE_PROFILES`）與推導出的 `COMPOSE_PROFILES`，`COMPOSE_PROJECT_NAME`（固定值）維持在原位，使維運在根目錄執行、不帶 `-f` 的 `docker compose ps`、`logs`、`exec`、`restart` 作用於現行版本的正式版定義、該部署的服務組成與固定專案。安裝包部署的形態 SHALL 由「部署形態由 .env 推導」決定，SHALL NOT 以客戶填寫的 `COMPOSE_FILE` 選擇。需要重新解析整份定義的指令（`up`、`config`）在根目錄手動執行時須另帶 `--project-directory .`；文件 SHALL 如此標明，SHALL NOT 主張它們不帶該選項即可使用。腳本自身的每次呼叫仍 SHALL 顯式帶 `-p`、`--project-directory` 與 `-f`。`.env.example` 的 `COMPOSE_FILE` 仍 SHALL 為註解狀態——生效值只由腳本寫進部署端 `.env`。

註：`COMPOSE_FILE`、`COMPOSE_PROFILES` 由 compose CLI 消費而非應用程式讀取；env 漂移守衛為單向（僅斷言程式碼消費的 key 皆記載於範本），故這兩個變數不影響守衛結果，註解狀態的理由純為上述部署語義。

#### Scenario: 複製範本後預設取得正式版
- **WHEN** 於乾淨 clone 執行 `cp .env.example .env`、填入必要值後執行 `bash scripts/quickstart.sh --up`
- **THEN** 起用的是正式版服務組成（應用與其依賴，不含測試靶機），前端以正式版對外埠提供編譯產物而非開發伺服器

#### Scenario: 開發者啟用 COMPOSE_FILE 後日常指令指向開發版
- **WHEN** 開發者於自己的 `.env` 取消註解 `COMPOSE_FILE=docker-compose.dev.yml`，執行不帶 `-f` 的 `docker compose exec backend ...`
- **THEN** 指令作用於開發版容器，無須顯式 `-f`

#### Scenario: 顯式 -f 覆蓋 COMPOSE_FILE
- **WHEN** 已設 `COMPOSE_FILE` 的開發者執行帶顯式 `-f docker-compose.yml` 的指令
- **THEN** 指令作用於正式版定義，使正式版仍可於開發機驗證

#### Scenario: 安裝包部署根的手動指令
- **WHEN** 維運在 `custodexa.sh install` 建立的外接資料庫部署根目錄執行不帶 `-f` 的 `docker compose ps` 或 `docker compose logs backend`
- **THEN** 指令作用於 `current/compose.yml`、該部署的 profiles 與固定專案名的容器；升級切換 `current` 後同一指令自動指向新版定義，維運不需修改 `.env`

#### Scenario: 原始碼部署根的手動指令
- **WHEN** 開發者在已跑過 `quickstart.sh` 的原始碼部署根執行不帶 `-f` 的 `docker compose ps`
- **THEN** 指令作用於 `docker-compose.yml` 與管理區 `COMPOSE_PROFILES` 選出的服務組成

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

**委託金鑰保管處的拓撲自本次起併入本要求**，且其降版預檢 SHALL 額外載明兩點，因為它與目錄設定的形態不同：

1. **回填的欄位分兩類**。非秘密拓撲（保管處位址、服務區域、金鑰名稱、角色識別）可自金鑰管理頁讀出後回填；**秘密（存取金鑰對、服務帳號金鑰檔內容、角色密鑰或權杖）自本版起不再存於任何位置**，管理介面讀不出來，SHALL 由部署方自其原始保管處另行取得後填入舊版本的 `.env`。文件 SHALL NOT 表述為「自介面匯出設定即可降版」。
2. **降版後的可用性驗證 SHALL 為一次完整重啟**：舊版本以環境變數的委託設定啟動並成功解開現行金鑰列，才算預檢通過；僅確認設定已填入不構成驗證。

升級方向 SHALL 同樣有明確程序：自舊版本升上本版時，環境變數中的委託拓撲 SHALL 由升級程序一次性讀入資料庫，其中的秘密 SHALL NOT 被寫入資料庫；升級完成後部署方 SHALL 自 `.env` 移除已退場的委託鍵，文件 SHALL 明示未移除者不會生效而非仍然有效。

#### Scenario: 降版預檢載於部署文件
- **WHEN** 運維查閱降版程序以自本版本回退
- **THEN** 文件列出目錄設定的回填步驟與降版後驗證方式，並警示 env 為過期快照

#### Scenario: 未回填即降版的後果可預期
- **WHEN** 部署方於遷移後修改過目錄設定並移除 `.env` 中的 bind 密碼，未執行回填即降版
- **THEN** 行為回到 env 快照（設定過期或目錄登入失敗），此結果已於文件明載而非未定義行為

#### Scenario: 委託秘密無法自介面取回
- **WHEN** 運維依降版程序準備回填委託設定
- **THEN** 文件 MUST 明示秘密須自原始保管處另行取得，MUST NOT 指示自管理介面匯出

#### Scenario: 升級不把秘密寫進資料庫
- **WHEN** 自舊版本升級，且舊 `.env` 內含委託秘密
- **THEN** 升級程序 MUST 只將非秘密拓撲讀入資料庫，秘密 MUST NOT 被持久化；首次啟動後 MUST 於解封頁索取憑證

### Requirement: 首次部署指示與實際啟動路徑一致

專案 README、快速開始與營運程序文件的正式安裝及升級路徑 SHALL 為 Linux 安裝包與 `custodexa.sh`：取得並核對安裝包、解開、執行 `custodexa.sh install`，之後以 `custodexa.sh upgrade` 升級。文件 SHALL 逐步對應腳本實際走的前置檢查、`.env` 產生、映像來源選擇與驗證、啟動、首次引導、升級前備份及失敗時的手動還原界線；SHALL NOT 描述該路徑上不存在的自動轉換或自動回退。文件 SHALL 說明 `--images-from auto|source` 與選單的相同選擇：auto 為預設取得順序；source 建置安裝包內自家原始碼，較慢，所需上游映像與建置依賴仍須取得。

`git clone`、`scripts/quickstart.sh` 與直接 `docker compose` SHALL 僅列為開發者與 macOS／Windows 試用路徑，明載非正式部署入口；此路徑的既有指令仍 SHALL 對應其實際執行的拓撲。舊 git clone 部署的轉入 SHALL 列為人工遷移或在另一個乾淨目錄安裝後手動還原，不得宣稱 `custodexa.sh` 會一次性轉換。三語 README、QUICKSTART 與相關 ops 鏡射 SHALL 保持指令、步驟及恢復邊界對等。

原始碼試用途徑的說明具體 SHALL 涵蓋：

- **範本複製步驟 SHALL 明列**（`cp .env.example .env`），正式版 compose 以 `env_file` 消費專案根 `.env`，缺檔即在啟動第一步失敗。
- **無出廠預設值而必須自行填入之機密鍵 SHALL 逐項列名**，照抄範本無法啟動者（KEK 材料、JWT 簽章鑰、初始管理員密碼、資料庫密碼）SHALL 於快速開始即點名。
- **存取位址與登入方式 SHALL 為該指令實際產出的拓撲**，正式版與開發版之發佈埠不同時 SHALL 標明；初始管理員憑證 SHALL 描述由環境變數設定與首登強制改密的現行機制。
- **指令形式 SHALL 為現行 CLI**（`docker compose`）。

`.env.example` 之模式選擇型設定，其營運後果 SHALL 揭露於選擇點：凡不同取值會改變是否需要人為介入才能恢復服務或機密是否落於磁碟者，該代價 SHALL 與選項並列。

#### Scenario: 照快速開始實走全新安裝
- **WHEN** 開發者取得專案樹並依原始碼試用途徑逐步執行
- **THEN** 文件明確標示非正式部署入口，所列範本、必填機密、位址及憑證與實際啟動拓撲一致

#### Scenario: 本機 KEK 兩模式之代價並列於選擇點
- **WHEN** 檢視 `.env.example` 之 `KEK_PROVIDER` 段
- **THEN** `env` 與 `ui` 兩模式之代價 MUST 並列於該段（前者材料以明文存於磁碟、重啟免人介入；後者材料不由伺服器持久保存、行程重啟後須有人再輸入），MUST NOT 只列其中一面的代價

#### Scenario: 照快速開始以安裝包全新安裝
- **WHEN** 於全新 Linux 主機照快速開始的安裝包路徑取得、核對、解開安裝包並執行 `custodexa.sh install`
- **THEN** MUST 能啟動至首次引導畫面；文件所列每一步、網址與登入方式與腳本實際輸出一致，MUST NOT 要求使用者手動複製範本或手填腳本已產生的機密

#### Scenario: 舊 git clone 部署規劃遷移
- **WHEN** 維運查閱升級與備份還原文件，準備從舊 git clone 部署轉入安裝包形態
- **THEN** 文件指向人工遷移或全新安裝後手動還原的可操作程序，不把一次性腳本轉換列為可用路徑

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

### Requirement: 外接資料庫部署形態

原始碼部署的正式版 compose（根目錄 `docker-compose.yml`）SHALL 為單一檔，SHALL NOT 依賴疊加檔表達部署形態，形態 SHALL 依「部署形態由 .env 推導」的同一規則（鍵、合法值、profiles 名稱與形態詞彙）決定。該檔 SHALL 在單一檔內提供外接資料庫形態：內建 postgres 服務 SHALL 屬 profile `bundled-db`，外接形態不啟用該 profile 時 `config` 輸出不含該服務；backend 對 postgres 的啟動依賴 SHALL 標為非必要（`required: false`），使 postgres 不在堆疊內時 backend 仍照常啟動；backend 的 `DB_HOST` SHALL 取 `.env` 的 `EXTERNAL_DB_HOST`、空白時為 `postgres`，`DB_PORT` SHALL 取 `EXTERNAL_DB_PORT`（預設 5432）。`EXTERNAL_DB_HOST` 有值而內容不可用（見 quickstart-bootstrap「原始碼部署依 .env 推導形態」與 management-script「部署形態的意圖與實況一致才動作」的外接位址檢查）時，SHALL 由腳本在呼叫 compose 前拒絕並指名該鍵，SHALL NOT 以任何預設位址啟動。`DB_NAME`／`DB_USER`／`DB_PASSWORD`／`DB_SSLMODE` 在此形態下 SHALL 沿用既有鍵，描述外部伺服器上的資料庫與帳號。外接資料庫形態 SHALL 可與外部入口形態併用。

`.env.example` SHALL 以註解形式提供 `EXTERNAL_DB_HOST`、`EXTERNAL_DB_PORT` 兩鍵並說明：填了位址即為外接形態、不需要也不應設定 `COMPOSE_FILE`；內建資料庫的資料目錄於此形態不再使用；跨網路連線應設 `DB_SSLMODE=require` 或 `verify-full`；外接形態下快速安裝腳本不產生 `DB_PASSWORD`，仍為空白或範本值時停下要求先填入外部伺服器上該帳號的密碼；已有內建資料庫資料的部署不能靠填這一行改用外接，須照營運文件「換到外接資料庫」一節以備份還原搬遷。`.env.example` SHALL NOT 再提供疊加檔名的 `COMPOSE_FILE` 範例。`DB_HOST` SHALL 維持不入範本（見「拓撲綁定值不入範本」）：外接位址由獨立鍵承載，不在主檔形態下製造填了不生效的鍵。

#### Scenario: 外接形態下堆疊不含 postgres 且後端指向外部伺服器
- **WHEN** `.env` 設 `EXTERNAL_DB_HOST=db.example.internal` 並以推導出的 profiles 執行 `docker compose config`
- **THEN** 輸出的服務集合不含 `postgres`；backend 的 `depends_on` 中 postgres 標為非必要；backend 的 `DB_HOST` 為 `db.example.internal`、`DB_PORT` 為 `5432`

#### Scenario: 外接位址不可用時拒絕啟動
- **WHEN** `.env` 設 `EXTERNAL_DB_HOST=localhost` 或 `EXTERNAL_DB_HOST=postgres` 後執行 `bash scripts/quickstart.sh --up`
- **THEN** 腳本在呼叫 compose 前以非零狀態結束，訊息指名 `EXTERNAL_DB_HOST` 並說明應填外部 PostgreSQL 伺服器位址；沒有服務被啟動

#### Scenario: 與外部入口形態併用
- **WHEN** `.env` 同時設 `EXTERNAL_DB_HOST=db.example.internal` 與 `TLS_MODE=external`
- **THEN** `config` 成功：無 `postgres`、內建代理不啟動、frontend 發布 HTTP 埠、backend 指向外部資料庫

#### Scenario: 範本記載外接資料庫鍵而漂移守衛仍綠
- **WHEN** 檢視 `.env.example` 並執行環境變數守衛測試
- **THEN** 範本含註解狀態的 `EXTERNAL_DB_HOST`、`EXTERNAL_DB_PORT` 與上述說明，不含疊加檔名的 `COMPOSE_FILE` 範例；
  範本不含 `DB_HOST` 行；`TestEnvExampleNoDrift` 等守衛通過

### Requirement: 部署形態由 .env 推導

安裝包的正式版 compose（發行目錄內的 `compose.yml`）SHALL 為單一檔，SHALL NOT 依賴疊加檔表達部署形態。部署形態 SHALL 只由 `.env` 的兩個鍵推導：`EXTERNAL_DB_HOST` 去除前後空白後有值為外接資料庫、空白或沒有此行為內建資料庫；`TLS_MODE` 為 `external` 為外部入口、空白或 `selfsigned`、`provided` 為內建代理，其他值 SHALL 被拒絕並列出合法值。推導結果 SHALL 以 compose profiles 套用：內建資料庫啟用 `bundled-db`，內建代理啟用 `builtin-tls`，外部入口啟用 `own-ingress`。內建代理與外部入口兩種形態的 frontend 服務 SHALL 使用同一映像與同一容器名，任一時間只啟用其一，內建代理形態下 frontend 與 backend SHALL NOT 發布 host port。形態詞彙 SHALL 沿用 `external-database`、`external-ingress`，供狀態檔與備份清單記錄。

管理腳本 SHALL 在每次呼叫 compose 時以環境變數帶入推導出的 `COMPOSE_PROFILES`；compose 插值所用的部署設定（該次所用 compose 檔中插值的每個變數，含 `EXTERNAL_DB_HOST`、`EXTERNAL_DB_PORT`、`TLS_MODE`、`HTTP_PORT`）SHALL 只取自部署根 `.env`，呼叫者 shell 環境中的同名變數與 `COMPOSE_FILE` SHALL NOT 進入 compose，使形態推導、一致性檢查與 compose 實際採用的連線設定為同一份值；並 SHALL 在部署根 `.env` 末尾維護一段以標記包住、註明由腳本維護的管理區，其中為固定值 `COMPOSE_FILE=current/compose.yml` 與 `COMPOSE_PROFILES`，使維運在部署根手動執行的 `docker compose ps`、`logs`、`exec` 與腳本作用於同一組服務。管理區以外的行 SHALL 逐位元組保持不變；管理區外出現的 `COMPOSE_FILE`、`COMPOSE_PROFILES` 行 SHALL 移入管理區並在畫面說明。

#### Scenario: 只填外接位址即生效
- **WHEN** `.env` 設 `EXTERNAL_DB_HOST=db.example.internal`、`TLS_MODE=selfsigned`，以推導出的 profiles 對安裝包的 `compose.yml` 執行 `docker compose config`
- **THEN** 服務集合不含 `postgres`，含 `tls-init`、`tls-proxy` 與 `frontend`；backend 的 `DB_HOST` 為 `db.example.internal`、`DB_PORT` 為 `5432`，`depends_on` 中 postgres 標為非必要

#### Scenario: 預設為內建資料庫與內建代理
- **WHEN** `.env` 的 `EXTERNAL_DB_HOST` 空白、`TLS_MODE=selfsigned`
- **THEN** 推導出的 profiles 為 `bundled-db` 與 `builtin-tls`；`config` 含 `postgres`，backend 的 `DB_HOST` 為 `postgres`；frontend 沒有 host 埠映射

#### Scenario: 外部入口形態
- **WHEN** `.env` 設 `TLS_MODE=external`、`HTTP_PORT=8080`，以推導出的 profiles 對安裝包的 `compose.yml` 執行 `docker compose config`
- **THEN** 不含 `tls-init`、`tls-proxy`；只有一個 frontend 服務啟用，發布 `8080`，容器名與內建代理形態的 frontend 相同；backend 沒有 host 埠映射

#### Scenario: shell 環境變數不覆寫 .env 的連線設定
- **WHEN** 內建資料庫部署的 `.env` 的 `EXTERNAL_DB_HOST` 空白，維運在 shell 中 `export EXTERNAL_DB_HOST=db.other.internal` 後以 `sudo -E` 執行 `start`
- **THEN** 一致性檢查判為內建並放行；compose 收到的環境不含 `EXTERNAL_DB_HOST`，啟動後 backend 容器的 `DB_HOST` 為 `postgres`

#### Scenario: TLS_MODE 為未知值
- **WHEN** `.env` 設 `TLS_MODE=letsencrypt`
- **THEN** 腳本在呼叫 compose 前拒絕，列出 `selfsigned`、`provided`、`external` 三個合法值

