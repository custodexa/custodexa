# deployment-hardening Specification

## Purpose
規範正式版部署的安全加固底線：無內建公開 bootstrap 憑證與首登強制改密、DB-aware 分階段啟動、正式版映像移除固定 shell 入口並使 CLI 子程序降權面可實跑核對、對外 ingress 的 TLS termination 契約，以及這些安全底線不得由 feature flag 關閉。
## Requirements
### Requirement: 無內建公開 bootstrap 憑證，seed 一律需部署方提供合格初始密碼

系統 SHALL NOT 以任何內建、硬編碼或公開的固定密碼建立初始管理員（移除 `admin123`）。任何會執行 seed 的模式（使用者表為空）SHALL 要求部署方經 `.env` 提供 `ADMIN_INITIAL_PASSWORD`。該值為缺失、空字串、等於出貨 placeholder、短於長度下限，或含前後空白／CR-LF／控制字元時，系統 SHALL 拒絕（fail-close，不執行 seed）。密碼的驗證與**雜湊產生** SHALL 使用完全相同的 bytes，SHALL NOT 靜默 `TrimSpace` 後再使用。

#### Scenario: 空 DB 未提供合格初始密碼拒絕 seed
- **WHEN** 使用者表為空、`ADMIN_INITIAL_PASSWORD` 未設／為 placeholder／過短／含前後空白或 CR-LF
- **THEN** 系統 fail-close 拒絕啟動，未建立任何管理員，使用者表維持空白

#### Scenario: 提供合格值才建立初始管理員
- **WHEN** 使用者表為空、提供合格 `ADMIN_INITIAL_PASSWORD`
- **THEN** 系統以與驗證相同的 bytes 建立初始管理員；以公開 `admin123` 登入 SHALL 失敗

#### Scenario: 既有安裝未設初始密碼不被誤擋
- **WHEN** release 模式、使用者表非空、未設 `ADMIN_INITIAL_PASSWORD`
- **THEN** 系統正常啟動並 serving，不因缺該值而 fail-close

#### Scenario: 空 DB 的初始密碼驗證發生在 seed 之前
- **WHEN** 使用者表為空、`ADMIN_INITIAL_PASSWORD` 不合格
- **THEN** 系統在任何使用者／安全資料寫入前即 fail-close，不 serving

### Requirement: DB-aware 分階段啟動序

系統啟動 SHALL 依明確階段執行且任一階段失敗即 SHALL NOT 開始 serving：(1) 驗證無條件必備 secret（JWT／加密金鑰）；(2) 連線 DB 並完成 schema migration，但尚未 serving；(3) 以 user count 判定安裝狀態；(4) 空 DB → 驗證 `ADMIN_INITIAL_PASSWORD` 後才允許 seed；(5) 非空 DB → SHALL NOT 因 `ADMIN_INITIAL_PASSWORD` 缺失／為 placeholder 而阻擋啟動，並 SHALL 執行 legacy 預設憑證掃描（見對應 requirement）。schema migration 於 secret 驗證前寫入不構成缺陷；不可接受的是在驗證前 seed 安全資料或開始服務。

#### Scenario: 既有安裝未設初始密碼不被誤擋
- **WHEN** release 模式、使用者表非空、未設 `ADMIN_INITIAL_PASSWORD`
- **THEN** 系統正常啟動並 serving，不因缺該值而 fail-close

#### Scenario: 空 DB 的初始密碼驗證發生在 seed 之前
- **WHEN** 使用者表為空、`ADMIN_INITIAL_PASSWORD` 不合格
- **THEN** 系統在任何使用者／安全資料寫入前即 fail-close，不 serving

### Requirement: 首登強制改密與初始管理員完成訊號

初始管理員 SHALL 以 `MustChangePassword=true` 建立，且管理員與初始 PasswordHistory SHALL 於同一交易原子建立。首次改密 SHALL 走既有原子路徑，在單一交易內同時更新密碼、`password_changed_at`、清除 `must_change_password` 並寫入 PasswordHistory。`must_change_password` SHALL 作為初始管理員的 pending(true)／completed(false) 訊號，SHALL NOT 被挪用為全域安裝狀態旗標。改密完成後，`ADMIN_INITIAL_PASSWORD` 的舊值 SHALL NOT 再能登入（DB 已存新雜湊）。

#### Scenario: 首登改密後初始密碼失效
- **WHEN** 初始管理員以 `ADMIN_INITIAL_PASSWORD` 首次登入並完成強制改密
- **THEN** 密碼、`password_changed_at`、`must_change_password=false` 與 PasswordHistory 於同一交易更新；此後以原 `ADMIN_INITIAL_PASSWORD` 登入 SHALL 失敗

### Requirement: legacy 既有安裝預設憑證掃描

release 模式下、開始 serving 之前，系統 SHALL 掃描所有可登入且具有效管理權限的帳號，逐一**經雜湊驗證介面**比對是否為已知 vendor 預設 `admin123`；任一命中 SHALL fail-close 要求 remediation。偵測 SHALL NOT 依賴 username、資料列排序、單一管理員假設或 `must_change_password` 篩選。停用帳號 SHALL 在重新啟用前再次接受此檢查。既有管理員即使「合法選用」`admin123` 亦 SHALL 被阻擋（屬公開已知憑證 remediation，非誤傷）。

**此掃描 MUST 涵蓋讀取面支援的全部演算法**：帳號的雜湊可能來自任何一代演算法（漸進遷移期間必然並存），僅比對當前演算法會使舊雜湊的 `admin123` 帳號逃過掃描——**而那正是最可能存在此問題的帳號**（久未登入、故未被遷移）。

#### Scenario: 改名或多 admin 任一使用 admin123 即擋
- **WHEN** release 模式、存在改名後的管理員或多個管理員，其中任一密碼為 `admin123`
- **THEN** 系統 fail-close 拒絕 serving，要求 remediation

#### Scenario: 無 admin123 帳號則正常啟動
- **WHEN** release 模式、所有管理帳號密碼皆非 `admin123`
- **THEN** legacy 掃描通過，系統正常 serving

#### Scenario: 舊演算法雜湊的預設憑證帳號
- **WHEN** 某管理帳號的密碼為 `admin123`，且其雜湊為尚未遷移的舊演算法
- **THEN** 掃描仍 SHALL 命中並 fail-close，SHALL NOT 因演算法不同而漏檢

### Requirement: bootstrap 初始密碼退役

首次 seed 之後，`ADMIN_INITIAL_PASSWORD` SHALL 被視為已退役。非空 DB 啟動時若該變數仍存在且為有效格式，系統 SHALL 發出明確告警，指引部署方移除或輪替（避免 stale credential）。重建空 DB SHALL 要求配置新值，系統 SHALL NOT 靜默沿用歷史 bootstrap secret 作為有效登入憑證。

#### Scenario: 非空 DB 仍留有效初始密碼發告警
- **WHEN** 使用者表非空、`ADMIN_INITIAL_PASSWORD` 仍為有效格式值
- **THEN** 啟動記錄明確告警，指引移除或輪替該值（不 fail-close）

### Requirement: bootstrap 初始密碼不留痕

系統 SHALL NOT 將 `ADMIN_INITIAL_PASSWORD` 明文寫入 log、HTTP API 回應、UI 或審計事件內容。

#### Scenario: 初始密碼不落 log
- **WHEN** 系統以 `ADMIN_INITIAL_PASSWORD` 完成初始管理員建立
- **THEN** 啟動 log 不含該密碼明文

### Requirement: 唯一管理員 lockout 的離線 remediation

系統 SHALL 提供受支援的離線 DB remediation 程序文件，處理「唯一管理員尚未首登、初始密碼遺失」的窄幅 lockout；該程序 SHALL 於單一交易內更新密碼、`must_change_password` 與 PasswordHistory。系統 SHALL NOT 為此新增任何線上救援 API 或應用層後門。

#### Scenario: 唯一 admin 未首登即遺失初始密碼可離線復原
- **WHEN** 唯一管理員尚未首登、`ADMIN_INITIAL_PASSWORD` 遺失、無第二管理員
- **THEN** 依文件化離線 DB remediation 程序，於單一交易重設密碼／`must_change_password`／PasswordHistory 後可恢復接管；無線上救援 API 被新增

### Requirement: stock production edge 移除假 TLS 訊號並於明文時告警

stock production compose SHALL NOT 對外映射一個未實際提供 TLS 服務的埠（移除 `443:443` 假映射）；預設對外 edge 以 HTTP 提供。backend SHALL NOT 發布 host port，僅存在於單主機專用 bridge。release 模式下以明文 HTTP 提供服務時，系統 SHALL 於啟動發出告警，指引於前端部署 TLS-terminating ingress。

stock production compose 的檔名為 `docker-compose.yml`——正式版即專案預設 compose 定義。

#### Scenario: prod compose 無假 TLS 埠映射且 backend 不對外
- **WHEN** 檢視 `docker-compose.yml`（正式版）
- **THEN** frontend 不映射 443（除非同時提供實際 TLS 服務）；backend 無 `ports:` host 映射

#### Scenario: release 明文提供服務時告警
- **WHEN** release 模式、對外以明文 HTTP 提供服務
- **THEN** 啟動 log 出現明文傳輸告警，指引前置 TLS ingress（不 fail-close）

### Requirement: 外部 ingress TLS termination 契約與可用範例

專案 SHALL 提供反向代理 TLS termination 的部署指南與可運作範例反向代理 config（nginx 為必交，Caddy 選配）。契約 SHALL 要求外部 edge 提供 TLS 1.2 以上、可信憑證、HTTP→HTTPS redirect、HSTS，以及 WebSocket `Upgrade`/`Connection` 轉發（使 wss 可達）；並 SHALL 明示 LB／ingress 到主機的 hop 若跨不可信網段須 re-encrypt。文件 SHALL 誠實載明 stock 部署本身不提供 TLS、關閉明文暴露為部署方 edge 職責，SHALL NOT 將傳輸層加密表述為由應用強制的控制。

#### Scenario: 範例反代 config 終結 TLS 並轉發 wss
- **WHEN** 依範例反代 config 於應用前部署
- **THEN** 對外提供 HTTPS（TLS 1.2+、可信憑證、HSTS），HTTP 被 redirect 至 HTTPS，WebSocket 以 wss 成功建立

#### Scenario: 契約明示不可信 hop 須 re-encrypt 且責任歸屬部署方
- **WHEN** 部署指南描述外部 TLS 委外
- **THEN** 指南要求不可信 hop 亦須加密，且明載 stock 部署不自帶 TLS、關閉明文為部署方職責

### Requirement: 應用對外 TLS-ready 不變式

應用 SHALL 在不修改應用程式碼的前提下即可於外部 TLS edge 後正確運作：於 HTTPS 下 SHALL 無 mixed content（前端依 `window.location.protocol` 自動選用 `ws`／`wss`），且認證材料 SHALL NOT 經明文專用通道傳輸。若日後改以 cookie 承載認證材料，該 cookie SHALL 標記 `Secure`／`HttpOnly`／`SameSite` 且應用 SHALL 依可信 proxy scheme 判定協定；此不變式描述性質，而非禁止使用 cookie。

#### Scenario: https 頁面自動使用 wss 無 mixed content
- **WHEN** 前端頁面經外部 TLS edge 以 https 提供
- **THEN** 所有 WebSocket 連線以 `wss://` 建立，無 mixed content 錯誤

#### Scenario: 認證材料不經明文通道
- **WHEN** 檢視認證材料傳遞方式
- **THEN** 認證材料不以明文專用通道傳輸；若採 cookie 則具 `Secure`/`HttpOnly`/`SameSite` 且依可信 proxy scheme 判定

### Requirement: 正式版執行環境不得含 `/bin/sh` 類固定入口

正式版 backend image 的執行階段 SHALL NOT 含 `/bin/sh`、`/bin/ash`、`/bin/bash`。理由是結構性的：資料庫 CLI 的逃逸路徑（psql `\!`、`\copy … TO PROGRAM`、`\e`，mariadb `system`、`pager <程式>`）與其他經 libc `system()`／`popen()` 的間接執行，**一律以硬編碼的 `/bin/sh` 為入口**；移除該入口使整類逃逸失效，且不隨 CLI client 版本演進而漂移。

**誠實邊界（SHALL 明載，不得宣稱「映像內無 shell」）**：`/bin/busybox` 仍存在且 `busybox sh` 可取得 shell——Alpine 的核心工具（`ls`、`cat` 等）皆為其 symlink，移除它會使映像不可用。本要求封閉的是**固定路徑入口**，不是「shell 能力」本身。

殘留風險的封閉條件有二，缺一不可：(1) 利用 `busybox sh` 需**先具備執行任意程式的能力**，而在本產品的威脅模型中 CLI 可用的執行原語只有 `system()`／`popen()`，兩者硬編碼 `/bin/sh`；(2) 即使該入口被還原，CLI 子程序也是以無 capability、無可寫路徑、讀不到任何憑證的降權身分執行（見 `database-protocol` 的「CLI 子程序執行環境降權」），取得 shell 的收益因此趨近於零。

移除 SHALL 位於該 stage 所有 `RUN` 之後（`rm` 之後的 `RUN` 無 shell 可用即失敗）。系統 SHALL NOT 因此需要 shell：容器啟動 SHALL 為 exec 形式的 `CMD`，正式版 compose 的 backend 服務 SHALL NOT 使用 `CMD-SHELL` healthcheck，後端程式碼的子程序 SHALL 以 `exec` 直呼程式（不經 shell）。

開發版 image SHALL 保留 shell（Air 熱重載以 `sh -c` 執行 build，日常驗證亦以 `docker compose exec … sh -c` 進行）。該差異 SHALL 於文件明示；開發版的補償控制是**與環境無關的執行身分降權**（兩版行為一致，故安全驗收可在 dev compose 內完成），正式版無 shell 一項的驗收則由正式版建置驗證流程對 image 實跑斷言。

#### Scenario: busybox 殘留不構成可達路徑

- **WHEN** 稽核者檢視正式版 image，發現 `/bin/busybox` 存在且 `busybox sh` 可啟動 shell
- **THEN** 此為已知且已明載的殘留，非缺陷——利用它需先具備執行任意程式的能力，而 CLI 的執行原語已因 `/bin/sh` 缺席而失效，且取得 shell 者仍受限於降權身分；文件 SHALL NOT 宣稱「映像內無 shell」

#### Scenario: 正式版 image 內無可用 shell
- **WHEN** 對正式版 backend image 執行 `docker run --rm --entrypoint /bin/sh <image> -c true`
- **THEN** 執行失敗（找不到可執行檔），且以 `/bin/ash`、`/bin/bash` 為 entrypoint 同樣失敗

#### Scenario: 移除 shell 不影響正式版啟動
- **WHEN** 以正式版 compose 啟動 backend
- **THEN** 服務正常啟動並可服務請求；資料庫與 k8s 會話仍可建立（CLI 與 kubectl 皆為 exec 直呼）

#### Scenario: 開發版保留 shell 且熱重載可用
- **WHEN** 檢視開發版 image
- **THEN** `/bin/sh` 存在，Air 熱重載與容器內測試指令正常運作

### Requirement: 正式版映像的 CLI 降權面可實跑核對

正式版 backend image SHALL 內建資料庫 CLI 的專用降權身分，且其執行環境的降權性質 SHALL 可在**已建置的 image 上實跑核對**（而非只在開發版容器內以測試驗證）。正式版建置驗證流程 SHALL 斷言：

- 該降權身分存在於 image 內（固定 uid/gid）；
- image 內 SHALL NOT 有任何全域可寫路徑（該身分不屬任何共用群組，`other` 位元即其可寫面）；
- image 內 SHALL NOT 有任何 setuid／setgid 檔（降權身分唯一的原生升權原語）；
- 資料與日誌目錄（錄影、審計）SHALL 為 `0700 root`——錄影是會話全文，可能含使用者在目標機上鍵入的密碼，資料庫 CLI 的身分連目錄都不得進入。

錄影檔 SHALL 以 `0600` 建立、其日期目錄 SHALL 以 `0700` 建立（`os.Create` 的預設 `0644` 會讓同容器內的其他身分讀到會話全文）。日期目錄的權限 SHALL 在每次開檔時顯式收斂，SHALL NOT 只依賴 `MkdirAll` 的 perm 參數——`MkdirAll` 對**既存**目錄不改權限（實測升級當天的日期目錄仍停在 `0755`），只靠它會讓本要求在跨日之前形同虛設。上述檔與目錄權限 SHALL 有守衛測試，且該測試 SHALL 涵蓋「日期目錄已存在且為 `0755`」的情境。

#### Scenario: 正式版 image 缺降權身分即失敗
- **WHEN** 執行正式版建置驗證且 image 內無該降權身分
- **THEN** 驗證失敗並指出缺少的身分

#### Scenario: 正式版 image 出現全域可寫路徑即失敗
- **WHEN** 執行正式版建置驗證且 image 內存在 `other` 可寫的檔案或目錄
- **THEN** 驗證失敗並列出該路徑

#### Scenario: 正式版 image 出現 setuid 檔即失敗
- **WHEN** 執行正式版建置驗證且 image 內存在 setuid 或 setgid 的一般檔
- **THEN** 驗證失敗並列出該路徑

#### Scenario: 錄影目錄權限退化即失敗
- **WHEN** 資料或日誌目錄不是 `0700 root`
- **THEN** 正式版建置驗證失敗

#### Scenario: 既存日期目錄的權限被收斂
- **WHEN** 錄影的日期目錄早已存在且為 `0755`，此時開始一段新錄影
- **THEN** 該目錄被收斂為 `0700`，新錄影檔為 `0600`

### Requirement: 映像內第三方 CLI 二進位的來源與建置約束

正式版 backend 映像內任何**非套件管理器安裝**的第三方 CLI 執行檔（現況：MSSQL 的 `sqlcmd`）SHALL 以下列方式取得，SHALL NOT 以未經固定的下載取得：

1. **優先自建**：於映像的獨立建置階段以固定版本的原始碼建置（Go 工具走 `go install <module>@<釘住的版本>`，`CGO_ENABLED=0`），使其信任面與既有的 `go mod download` 相同（module proxy ＋ checksum database ＋ `go.sum` 驗證）。版本 SHALL 以 `ARG` 明確標示，SHALL NOT 使用 `latest` 或浮動 tag。
2. **若改為使用上游預建二進位**，則 SHALL 於 Dockerfile 內釘住其 **sha256** 並於建置期核對，核對失敗 SHALL 使建置失敗。無 sha256 核對的下載 SHALL NOT 進入映像。
3. 該執行檔的**授權 SHALL 為 OSI 核可**，且授權名稱與來源 SHALL 記於 Dockerfile 註解與開源合規文件。**受 EULA 約束的元件 SHALL NOT 進入公開映像**——需要時 SHALL 改以獨立的自建覆蓋層（`Dockerfile.<元件>`）提供，該覆蓋層 SHALL 以 `ARG` 要求部署方顯式接受條款，SHALL NOT 由專案代為接受（硬編碼 `ACCEPT_EULA=Y`）。缺該可選覆蓋層 SHALL NOT 使正式版建置驗證失敗。
4. 新增建置階段所用的基底映像版本 SHALL 由既有的容器建置守衛涵蓋；若該守衛的比對邏輯無法區分主 builder 與新階段，SHALL 擴充守衛而非放寬它。

該執行檔在映像內 SHALL 滿足既有的降權面條件：非 setuid／setgid、非全域可寫、其所在路徑對資料庫 CLI 降權身分唯讀。此性質 SHALL 由正式版建置驗證流程對已建置 image 實跑核對。

#### Scenario: 未釘版本的第三方二進位即不予採用
- **WHEN** 映像建置以浮動 tag 或未釘 sha256 的下載取得第三方 CLI
- **THEN** 該做法不符本要求，SHALL 改為釘住版本的自建或帶 sha256 核對的下載

#### Scenario: EULA 元件不入公開映像
- **WHEN** 某協議只有受 EULA 約束的 client 可用
- **THEN** 公開映像不內建該元件，改提供需部署方顯式接受條款的自建覆蓋層，且該協議在缺元件時 fail-close

#### Scenario: 自建二進位仍受降權面核對
- **WHEN** 執行正式版建置驗證
- **THEN** 自建的第三方 CLI 執行檔被納入 setuid／全域可寫的掃描，違反即失敗

### Requirement: release 安全底線不得由 feature flag 關閉

release 模式下，屬於安全紅線的 feature flag SHALL 由系統於啟動時強制為啟用，
環境變數把它們設為停用值時 SHALL 被忽略。底線成員 SHALL 至少包含
`FEATURE_AUDIT_LOG_ENABLED`（全操作審計）。

**權限檢查 SHALL NOT 以 feature flag 承載**：安全紅線中「所有模式皆須生效、
任何組態都不應關閉」者，正確處置是不提供該開關，而非提供後於 release 模式強制。
提供可關閉的開關再於單一模式強制，會使開發與測試組態成為「權限缺陷測不出來」
的環境，且每新增一個消費點就多一條需要記得強制的路徑。權限檢查即屬此類，
其開關 SHALL 不存在（見 `security-policy` 的部署安全基線）。

強制 SHALL 發生在**旗標值的決定處**（單一收口點），SHALL NOT 以在各消費點分別
加入模式判斷的方式達成——消費點包含中間件掛載、路由註冊與審計服務內部分支，
逐點守衛會使新增的消費點預設不受保護。

強制 SHALL 先於啟動時的功能開關狀態輸出執行，使日誌顯示的是**生效值**而非環境
變數字面值；被強制的鍵名 SHALL 於啟動日誌具名列出，使部署者能看見自己的停用
設定已被拒絕。

非 release 模式 SHALL NOT 受此強制影響：該處置的目的是保護出貨到生產的部署，
而條件註冊與旗標關閉語義在開發與測試組態中仍須可觸發。此豁免僅適用於**留有
開關的**底線成員；不存在開關者無豁免可言。

#### Scenario: release 模式忽略審計停用設定

- **WHEN** `GIN_MODE=release` 且 `FEATURE_AUDIT_LOG_ENABLED=false`
- **THEN** 系統以審計啟用的狀態啟動：全域審計中間件掛載、`/audit-logs` 路由註冊、
  審計寫入路徑不被旗標短路；啟動日誌具名列出該鍵已被強制

#### Scenario: 權限檢查無開關可關

- **WHEN** 任一模式下，部署者以環境變數嘗試停用權限檢查
- **THEN** 該變數不被辨識，權限檢查照常生效；系統 SHALL NOT 提供任何使其停用的組態途徑

#### Scenario: 啟動日誌不得顯示被強制前的字面值

- **WHEN** release 模式、任一底線旗標於環境變數被設為停用
- **THEN** 功能開關狀態輸出顯示該機制為啟用（生效值），SHALL NOT 顯示環境變數的
  停用字面值

#### Scenario: 非 release 模式維持可關閉

- **WHEN** `GIN_MODE=debug` 且 `FEATURE_AUDIT_LOG_ENABLED=false`
- **THEN** 審計旗標維持停用，條件註冊與旗標關閉語義照常生效（強制 SHALL NOT 擴大
  到全模式）

