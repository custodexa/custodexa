## Purpose

容器建置契約：全服務單一 build context 基準與 COPY 路徑慣例、context 傳輸範圍排除、開發版與正式版 image 命名分離、建置基底版本對齊、建置驗證在操作流程中的位置。
## Requirements
### Requirement: 單一 build context 基準

所有服務的 compose build 定義 SHALL 以專案根（`.`）為 context，並以 `docker/<service>/Dockerfile` 指定 Dockerfile；Dockerfile 內所有 `COPY` 來源路徑 SHALL 以專案根為基準書寫。SHALL NOT 存在以子目錄為 context 的服務定義，亦 SHALL NOT 出現以 `../` 跳脫 context 的 dockerfile 路徑。

理由：`COPY` 的路徑基準是 context 根而非 Dockerfile 所在位置，兩種 context 慣例並存會使同一行 `COPY` 在不同服務有不同解讀，且無法從 Dockerfile 本身判斷路徑是否可解析。

#### Scenario: 全服務 context 慣例一致
- **WHEN** 檢視正式版與開發版 compose 的所有 `build` 區塊
- **THEN** 每個 `context` 皆為 `.`，每個 `dockerfile` 皆為 `docker/<service>/Dockerfile` 形式且不含 `../`

#### Scenario: COPY 來源皆位於 context 內
- **WHEN** 對兩份 compose 的全部 build 目標執行實際建置（流程位置見「正式版建置驗證列入操作流程」）
- **THEN** 全數建置成功，不出現 `failed to compute cache key: ... not found`——任一來源逸出 context 即於建置期失敗並指出該路徑

### Requirement: context 傳輸範圍排除且不得排除建置來源

專案 SHALL 具備 `.dockerignore`，排除非建置所需的大體積路徑（至少含 `node_modules`、`data/`、`.git`、前端建置產物）。排除清單 SHALL NOT 涵蓋任何 Dockerfile `COPY` 的來源路徑——包含 `docker/` 下測試容器的 entrypoint 與設定資產、`backend/` 與 `frontend/` 原始碼。

#### Scenario: 大體積路徑列於排除清單
- **WHEN** 檢視 `.dockerignore`
- **THEN** `node_modules`、`data/`、`.git`、前端建置產物皆在排除清單內

#### Scenario: 排除清單不破壞任何建置
- **WHEN** `.dockerignore` 就位後對兩份 compose 的全部 build 目標建置
- **THEN** 全數成功——證明無 `COPY` 來源被誤排（尤其 `docker/rdp-test`、`docker/vnc-test` 的 entrypoint 與 supervisord 設定）

### Requirement: 開發版與正式版 image 名稱分離

開發版與正式版 compose SHALL 各自顯式宣告可區分的 `image:` 名稱或 tag，使兩者建置產物可共存於同一主機而互不覆蓋。

理由：兩份 compose 位於同一目錄故共享 compose project name，未顯式宣告時 image 名相同；正式版產物為精簡基底＋二進位、不含語言工具鏈，一旦覆蓋開發版 image 並 recreate 容器，開發容器將失去執行測試的能力。

#### Scenario: 正式版建置後開發版容器仍具工具鏈
- **WHEN** 執行正式版建置後 recreate 開發版 backend 容器
- **THEN** 開發版容器內 Go 工具鏈仍可執行，不出現 `exec: "go": executable file not found`

#### Scenario: 兩版 image 於本機可並存
- **WHEN** 先後建置正式版與開發版後列出 image
- **THEN** 兩者以不同名稱或 tag 並存，各自大小符合其基底（正式版為精簡基底，開發版含工具鏈）

### Requirement: 建置基底映像語言版本不低於模組宣告

Dockerfile 的 Go 基底映像版本 SHALL 不低於 `go.mod` 宣告的 Go 版本，開發版與正式版皆然。SHALL NOT 以 `GOTOOLCHAIN` 自動下載掩蓋版本落差——該機制使版本不一致在開發期無症狀，卻於未設定該變數的建置階段失敗。

SHALL NOT 以 `GOTOOLCHAIN` 自動下載為由容忍落差——移除該機制後，基底低於 `go.mod` 時開發日常建置立即失敗，落差於建置期自然暴露，無須獨立檢查。

#### Scenario: 各 Dockerfile 基底版本符合 go.mod
- **WHEN** 檢視 `docker/backend/Dockerfile` 各 stage 與 `docker/backend/Dockerfile.dev` 的 `FROM` 版本
- **THEN** 皆不低於 `go.mod` 的 `go` 指令宣告版本；且 `Dockerfile.dev` 不含 `GOTOOLCHAIN=auto`

### Requirement: 正式版建置驗證列入操作流程

建置正確性 SHALL 由真實的 `docker compose build` 驗證，並位於操作流程的明確位置；SHALL NOT 以測試層的 `docker build` 呼叫或自製 Dockerfile 解析器替代（解析器對 COPY／glob／stage／context 語義的任何偏差都是新的假綠面；且 backend 容器僅掛 `backend/`，Dockerfile 與 compose 檔在其可見範圍外）。

流程位置有二：

1. **部署者**：全新部署無既存 image，`docker compose up -d` 自動建置正式版全部目標——正式版建置即預設路徑的第一步，每次新部署都是一次完整驗證。
2. **開發者**：專案 SHALL 提供一個顯式以 `-f docker-compose.yml` 執行正式版建置的本地驗證途徑（不受開發者 `.env` 的 `COMPOSE_FILE` 影響），供改動 Dockerfile、`.dockerignore` 或 compose build 區塊後本地驗證；部署文件 SHALL 將其列為部署前步驟。image 名分離保證此操作不覆蓋開發版 image。

#### Scenario: 全新部署自動驗證正式版建置
- **WHEN** 乾淨環境（無既存 image）執行 `docker compose up -d`
- **THEN** 正式版全部 build 目標被實際建置，任一建置失敗即啟動失敗——缺陷於部署流程第一步暴露，不潛伏

#### Scenario: 開發者本地驗證不受 COMPOSE_FILE 影響
- **WHEN** 已在 `.env` 啟用 `COMPOSE_FILE=docker-compose.dev.yml` 的開發者執行正式版建置驗證（顯式 `-f docker-compose.yml`）
- **THEN** 被建置的是正式版目標（顯式 `-f` 覆蓋環境變數），且開發版 image 不被覆蓋

#### Scenario: COPY 來源逸出 context 於建置期即暴露
- **WHEN** 任一 Dockerfile 的 `COPY` 來源被改為其 build context 外的路徑後執行上述任一建置
- **THEN** 建置以 `failed to compute cache key: ... not found` 類錯誤失敗並指出該路徑

### Requirement: 上游來源映像釘定具體版本
**自外部取得、且會進入交付產物的映像** SHALL 指定具體版本 tag，SHALL NOT 使用 `latest` 或僅指定主版本的浮動 tag。射程涵蓋：正式版編排檔所引用的**外部**映像，以及交付映像之 Dockerfile 的每一個 `FROM`（含建置階段）。

**射程的邊界是「來源」不是「出現在哪個檔案」**——本需求管的是「我散布的東西裡包含了上游的哪一版」，故對象是**上游來源**。我方自行建置之產物的標籤（正式版編排檔中帶 `build:` 的那幾個 `image:`）**不在本需求射程內**：其內容版本完全由該 Dockerfile 的 `FROM` 決定，而那些已受本需求約束；標籤本身要不要帶版號屬**版本發佈策略**（SemVer 落地、image 出版本 tag 與 `latest`），是另一項工作。

**釘版不是可重現性的偏好，而是三項義務的技術前提**——未釘版時下列三者在技術上無法成立：

- GPL／LGPL 二進位的「對應源碼取得」義務：無法指名應提供哪一版的源碼。
- 離線安裝包：包內容的版本無法指名。
- 漏洞公告：無版本可指名，使用者無從判斷自身是否受影響。

選定的版本 SHALL 於該版本被指定之處的註解（Dockerfile 或編排檔）記載選擇理由與查證日期
——射程已含編排檔引用的外部映像，而那些映像沒有 Dockerfile 可寫。

**不在射程內：開發用測試靶機**——僅存在於開發版編排檔、不進任何交付產物、不由我方散布的協議靶機（SSH／RDP／VNC／資料庫／目錄服務／物件儲存等）。上列三項義務的觸發條件**皆為「散布」**，靶機一項都不觸發，故本需求不涵蓋它們。**代價要明說**：靶機使用浮動 tag 會使開發環境不可完全重現，上游變更可能表現為測試偶發失敗——那是開發體驗問題，與授權義務、漏洞公告不同量級，處置優先序另計。

#### Scenario: 浮動 tag 進入交付產物的建置定義
- **WHEN** 交付映像的任一 `FROM`、或正式版編排檔引用的任一**外部**映像使用 `latest` 或僅主版本的 tag
- **THEN** 視為建置定義缺陷；該映像的散布無法履行源碼提供義務

#### Scenario: 我方自建產物的標籤
- **WHEN** 正式版編排檔中帶 `build:` 的服務其 `image:` 標籤為 `latest`
- **THEN** 不視為本需求的違反——該標籤指向本地建置產物，其內容版本由已釘版的 `FROM` 決定；標籤是否帶版號屬版本發佈策略，**該規範目前尚不存在**（SemVer 落地是待辦），故此處不得寫成「已由它規範」

#### Scenario: 開發靶機使用浮動 tag
- **WHEN** 僅開發版編排檔使用的測試靶機映像使用浮動 tag
- **THEN** 不視為本需求的違反；但該狀態 SHALL 可被逐一指認，SHALL NOT 以「基底映像已全數釘版」這類概括陳述掩蓋其存在

#### Scenario: 上游無較新基底時的誠實記載
- **WHEN** 某第三方映像的最新可用版本其基底系統已過支援期，且上游未提供替代
- **THEN** 仍釘定該具體版本，並將該狀態與其部署影響記入營運文件，SHALL NOT 以浮動 tag 掩蓋

### Requirement: 語言工具鏈不得停留於已終止支援的版本
**其執行期成分（runtime／標準函式庫）進入交付物的**語言工具鏈版本 SHALL 在上游支援期內。

**判準是「執行期成分」不是「產物」**——這兩者會給出相反的答案，必須寫死：編譯型工具鏈把 runtime 與標準函式庫**鏈進**交付的二進位，其 stdlib 漏洞直接落在使用者的執行環境；而只產出靜態資產的工具鏈，資產雖然進了交付映像，**其 runtime 留在建置階段、不隨產物出貨**。前者落入本 SHALL，後者落入下方的豁免。當某版本已終止支援，且其標準函式庫的已知漏洞修復版僅存在於後續版本時，升級 SHALL NOT 以「影響面小」為由延後。

**執行期成分不進交付物的工具鏈**（例如只負責產出靜態檔，成品由另一個執行階段映像伺服，該工具鏈本身不在交付映像內）不在上述 SHALL 射程內——它無法把 stdlib 漏洞帶進使用者手中的執行環境。但其漏洞面並非為零（建置環境本身是供應鏈的一環），故此類工具鏈一旦 EOL，SHALL 於 Dockerfile 記載該狀態、明示其漏洞面限於建置期，並設定重評的觸發點。

判斷升級目標時 SHALL 考慮下一版的釋出時程：若升級到某版後其支援期即將因下一版釋出而終止，SHALL 直接升至更後的版本，避免短期內重複升級。

#### Scenario: 工具鏈版本已 EOL
- **WHEN** 其執行期成分進入交付物的語言版本已過上游支援期，且存在僅在後續版本修復的標準函式庫漏洞
- **THEN** 升級為必要處置，不因「多數漏洞不可達」而免除

#### Scenario: 僅建置期使用的工具鏈已 EOL
- **WHEN** 某工具鏈已過上游支援期，但其執行期成分不進入任何交付映像（產出的資產進入交付物不影響本判定）
- **THEN** 不觸發前述的強制升級；SHALL 於該 Dockerfile 記載 EOL 事實、明示漏洞面限於建置期，並寫下重評的觸發點，SHALL NOT 以「反正不出貨」為由略去記載

#### Scenario: 升級目標的選擇
- **WHEN** 候選目標版本的支援期將隨下一版釋出而終止，且下一版已進入 release candidate
- **THEN** 選擇更後的版本，使升級後的支援期涵蓋可預見的發佈週期

### Requirement: 映像內依賴安裝鎖定解析版本且不執行套件腳本
Dockerfile 內安裝語言套件管理器依賴的步驟 SHALL 使用鎖定解析版本的命令（npm 為 `npm ci`），SHALL NOT 使用會改寫鎖定檔或自行解析版本的命令（`npm install`）。同一份 Dockerfile 內的多個階段 SHALL 使用一致的安裝方式——階段間解析出不同依賴樹，會使「開發期通過、正式版建置失敗」在無人改動依賴的情況下發生。

安裝步驟 SHALL 抑制第三方套件的生命週期腳本（npm 為 `--ignore-scripts`）。理由是執行時機而非套件品質：安裝腳本於建置階段執行，而建置階段的權限範圍大於執行階段。

**射程限於以套件管理器安裝、且該管理器不自帶內容驗證者**。Go 模組不在此列：`go install <module>@<version>` 由 checksum database 驗證每個模組的內容雜湊，鎖定與完整性由工具鏈承擔，不需要另一份鎖定檔。此處明列邊界，避免本條文被讀成「後端依賴不受管」。

抑制安裝腳本後，依賴若以生命週期腳本取得平台專屬二進位，失敗會出現在建置或執行期而非安裝步驟。故本要求的驗證條件 SHALL 為正式版建置實跑成功，SHALL NOT 以安裝步驟的退出碼為準。

#### Scenario: 安裝命令未鎖定解析版本
- **WHEN** 交付映像或開發版映像的 Dockerfile 以 `npm install` 安裝依賴
- **THEN** 視為建置定義缺陷；該階段解析出的依賴樹與鎖定檔可能不一致

#### Scenario: 同一 Dockerfile 內安裝方式分岔
- **WHEN** 一份 Dockerfile 的兩個階段分別以鎖定與非鎖定命令安裝同一組依賴
- **THEN** 視為建置定義缺陷，即使兩者當下解析結果相同

#### Scenario: 安裝步驟執行第三方生命週期腳本
- **WHEN** 安裝命令未抑制生命週期腳本
- **THEN** 視為建置定義缺陷；第三方程式碼於建置階段執行

#### Scenario: 抑制腳本後的驗證依據
- **WHEN** 為符合本要求而加上腳本抑制旗標
- **THEN** 以正式版建置實跑成功作為通過依據，安裝步驟退出 0 不足以判定通過

