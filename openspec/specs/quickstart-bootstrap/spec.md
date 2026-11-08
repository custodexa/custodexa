# quickstart-bootstrap Specification

## Purpose
部署快速啟動腳本（`scripts/quickstart.sh`）的行為契約：`.env` 機密缺項的判定與
CSPRNG 生成、冪等性、KEK 模式尊重、破壞性操作護欄、機密回顯政策，以及 `--up`
的進度回報與登入資訊輸出。腳本是既有部署驗證規則（deployment-hardening／
deployment-configuration）的消費者：生成值必須通過既有 fail-close 驗證，
不修改任何產品行為。
## Requirements

### Requirement: 機密缺項判定與生成
`scripts/quickstart.sh` SHALL 對四項機密逐一檢查：值為空、或等於範本出貨值
（`JWT_SECRET=change-me-in-production-dev-secret`、
`ADMIN_INITIAL_PASSWORD=change-me-admin-initial-password-in-env`、`DB_PASSWORD=postgres`）
即判定為未設定並以 CSPRNG 生成合格值；其餘一律視為使用者已設定、原樣沿用。
生成格式 SHALL 落在既有啟動驗證的接受集內：`ENCRYPTION_KEY` 為 64 十六進位字元
（`openssl rand -hex 32`）、`JWT_SECRET` ≥ 32 bytes、`ADMIN_INITIAL_PASSWORD` 為
≥ 12 字元英數且同時含字母與數字、無前後空白、非 denylist 值。
`.env` 不存在時 SHALL 先自 `.env.example` 建立；範本也不存在時 SHALL 以明確錯誤失敗。
開發版形態（`.env` 的 `COMPOSE_FILE` 為 `docker-compose.dev.yml`）另 SHALL 檢查開發用 Vault 測試靶機的
初始化 token `VAULT_DEV_ROOT_TOKEN_ID`：值為空即以 CSPRNG 生成 32 字元英數值並回報已生成，SHALL NOT 回顯該值；
已有值 SHALL 原樣沿用。非開發版形態 SHALL NOT 新增、生成或改寫這個鍵：原先沒有此鍵（或只有註解行）時維持沒有未註解的行，使兩種部署方式在正式形態產生的鍵集合一致；原先已有未註解的值時（例如由開發版切回正式形態）SHALL 原樣保留，SHALL NOT 刪除或註解掉。

#### Scenario: 全新環境一鍵補齊
- **WHEN** 目錄內無 `.env`，執行 `bash scripts/quickstart.sh`
- **THEN** 自範本建立 `.env`，四項機密全數生成且各自通過對應的啟動驗證格式；以生成的
  `ADMIN_INITIAL_PASSWORD` 對 `/api/v1/auth/login` 登入可取得 `password_change_required`

#### Scenario: 使用者已設定的值不被覆蓋
- **WHEN** `.env` 內 `ADMIN_INITIAL_PASSWORD` 已是非範本值，執行腳本
- **THEN** 該值原樣保留，回報「已設定，未動」

#### Scenario: 開發版補上 Vault 初始化 token
- **WHEN** `.env` 已取消 `COMPOSE_FILE=docker-compose.dev.yml` 註解且 `VAULT_DEV_ROOT_TOKEN_ID` 為空，執行腳本
- **THEN** `.env` 出現未註解的 `VAULT_DEV_ROOT_TOKEN_ID=` 行，值為 32 字元英數；輸出回報已生成但不含該值；
  再執行一次，該值不變

#### Scenario: 正式形態不寫 Vault 初始化 token
- **WHEN** `.env` 未啟用 `COMPOSE_FILE`，且原先沒有未註解的 `VAULT_DEV_ROOT_TOKEN_ID=` 行，執行腳本
- **THEN** `.env` 沒有未註解的 `VAULT_DEV_ROOT_TOKEN_ID=` 行

#### Scenario: 切回正式形態保留既有 Vault 初始化 token
- **WHEN** `.env` 原先在開發版形態下已有 `VAULT_DEV_ROOT_TOKEN_ID` 的值，之後把 `COMPOSE_FILE` 改回註解，再執行腳本
- **THEN** 該行與其值原樣保留，輸出不提及這個鍵

### Requirement: 冪等性
腳本重複執行 SHALL 不改變任何已合格的 `.env` 內容——第二次執行後檔案位元組不變。

#### Scenario: 連跑兩次零改動
- **WHEN** 對同一 `.env` 連續執行腳本兩次
- **THEN** 第二次執行前後 `.env` 內容完全相同，且四項機密均回報「已設定，未動」

### Requirement: KEK 模式尊重
腳本 SHALL 只在 `KEK_PROVIDER` 為空或 `env` 時生成 `ENCRYPTION_KEY`；
`ui` 模式 SHALL 略過（金鑰不落地為該模式的語義）；`kms`／`hsm` SHALL 略過
（本地金鑰鍵有值即組態矛盾）；白名單（env/ui/kms/hsm）以外的值 SHALL 以非零狀態失敗，
不猜測、不修正。

#### Scenario: ui 模式不落地
- **WHEN** `.env` 內 `KEK_PROVIDER=ui`，執行腳本
- **THEN** `.env` 內不出現未註解的 `ENCRYPTION_KEY=` 行，並回報略過理由

### Requirement: 機密回顯與檔案權限
腳本 SHALL 僅回顯**本次生成**的 `ADMIN_INITIAL_PASSWORD`（使用者登入所需）；
既有機密 SHALL NOT 回顯。執行後 `.env` 權限 SHALL 收斂為 600（不支援的檔案系統上失敗不阻斷）。

#### Scenario: 既有機密不進終端
- **WHEN** `.env` 的 `ADMIN_INITIAL_PASSWORD` 已為使用者自設值，執行腳本
- **THEN** 輸出不含該值本身，僅提示沿用既有值

### Requirement: 啟動進度與登入資訊
腳本輸出 SHALL 以英文為預設語言。`--up` 模式 SHALL 分階段回報進度
（機密檢查、映像建置、容器啟動、後端健康等待），健康等待 SHALL 有上限，
逾時 SHALL 輸出排障指引（`docker compose logs backend`）並以非零狀態結束。
流程成功結束時 SHALL 輸出登入資訊區塊：連線 URL（開發形態為 `http://localhost:3000`；
正式形態依推導出的入口形態，內建代理為依 `TLS_DOMAIN` 與 https 對外埠組成的 https 網址、外部入口為 `http://localhost:` 加 `HTTP_PORT`）、帳號 `admin`、
密碼（依「機密回顯與檔案權限」要求：本次生成者顯示、既有者僅指向 `.env`）。
`KEK_PROVIDER=ui` 時（含範本出貨預設）收尾區塊 SHALL 改為初始化解封指引：
說明首次造訪將進入初始化頁、主金鑰於瀏覽器本地生成且必須保存、
以區塊內之 admin 帳密授權初始化，之後方為登入；腳本 SHALL NOT 代為生成、
輸入或顯示任何 KEK 材料。

#### Scenario: 啟動完成即拿到登入資訊
- **WHEN** 全新環境以 `KEK_PROVIDER=env` 執行 `bash scripts/quickstart.sh --up` 且後端於時限內健康
- **THEN** 輸出依序含四階段進度，結尾登入資訊區塊含正式版 URL、`admin` 與本次生成的密碼

#### Scenario: 開發版 URL 判定
- **WHEN** `.env` 已取消 `COMPOSE_FILE=docker-compose.dev.yml` 註解，執行腳本
- **THEN** 登入資訊區塊的 URL 為 `http://localhost:3000`

#### Scenario: 外部入口形態 URL 判定
- **WHEN** `.env` 設 `TLS_MODE=external`、`HTTP_PORT=8080`，執行 `bash scripts/quickstart.sh --up` 且後端健康
- **THEN** 登入資訊區塊的 URL 為 `http://localhost:8080/`，不印 CA 憑證下載網址

#### Scenario: ui 模式收尾為初始化解封指引
- **WHEN** `.env` 為範本出貨預設（`KEK_PROVIDER=ui`），執行 `bash scripts/quickstart.sh --up` 且後端健康
- **THEN** 收尾區塊為初始化解封指引（首次造訪進初始化頁、主金鑰瀏覽器本地生成須保存、
  以 admin 帳密授權），含 URL 與 admin 帳密，且輸出不含任何 KEK 材料

### Requirement: 資料庫密碼護欄
內建資料庫的資料目錄（`${DATA_PATH:-./data}/postgresql/18/docker`，或舊大版本的 `${DATA_PATH:-./data}/postgres`）任一存在且非空時，腳本 SHALL NOT 變更 `DB_PASSWORD`
（即使其值仍為範本出貨值），並 SHALL 說明理由；不提供強制覆寫旗標。
外接資料庫形態（`EXTERNAL_DB_HOST` 有值）下，腳本 SHALL NOT 生成 `DB_PASSWORD`：該密碼由外部伺服器決定，
不是本機可以決定的值。此形態下值已設時 SHALL 維持原值並回報；值為空或仍為範本出貨值時 SHALL 以非零狀態失敗，
訊息 SHALL 指名要填的鍵與原因，不得改用生成值。

#### Scenario: 既有資料庫不被鎖死
- **WHEN** `./data/postgres` 已含初始化後的資料庫檔案且 `DB_PASSWORD=postgres`，執行腳本
- **THEN** `DB_PASSWORD` 維持原值，輸出含「已初始化」護欄說明

#### Scenario: 新大版本資料目錄同樣受保護
- **WHEN** `./data/postgresql/18/docker` 已含初始化後的資料庫檔案且 `DB_PASSWORD=postgres`，執行腳本
- **THEN** `DB_PASSWORD` 維持原值，輸出含「已初始化」護欄說明

#### Scenario: 外接資料庫的自訂密碼不被改
- **WHEN** `.env` 內 `EXTERNAL_DB_HOST` 有值且 `DB_PASSWORD` 為使用者自訂值，本機無 postgres 資料目錄，執行腳本
- **THEN** `DB_PASSWORD` 維持原值，輸出回報維持不變

#### Scenario: 外接資料庫缺密碼時停下
- **WHEN** `.env` 內 `EXTERNAL_DB_HOST` 有值且 `DB_PASSWORD` 為空或仍為範本出貨值，執行腳本
- **THEN** 腳本以非零狀態結束，訊息指名 `DB_PASSWORD` 須填入外部伺服器的密碼；`.env` 未被改寫

### Requirement: 錄影目錄的擁有者與權限
正式版堆疊中，guacd 以 uid 1000 寫入圖形錄影，backend 以 uid 0、經由群組 0 讀取、改名與刪除這些檔案。`--up` 模式 SHALL 在啟動容器之前，把 `${DATA_PATH:-./data}/recordings` 收斂為擁有者 uid 1000、群組 gid 0、
模式 2770（含 setgid，使新檔繼承群組 0），並 SHALL 把該目錄根層群組為 1000 的既有一般檔案改為群組 0。
此步驟 SHALL 以一次性容器、root 身分執行，結果 SHALL 與執行腳本者的身分無關（docker 群組內的一般使用者
與 sudo 結果相同，一般使用者不需要 sudo）。所用映像 SHALL 為正式版 compose 已宣告的上游映像，不新增 compose 以外的映像依賴。
此步驟 SHALL 可重複執行：已收斂時再跑不報錯、不改變目錄與檔案的擁有者、群組與模式；目錄收斂本身
SHALL 對執行中的堆疊立即生效，不需重啟任何服務；映像未變時重跑 `--up` SHALL NOT 重建執行中的容器。步驟失敗 SHALL 以非零狀態結束並指名該目錄。
開發版形態（`COMPOSE_FILE=docker-compose.dev.yml`）SHALL 略過此步驟。
不帶 `--up` 時，收尾指引 SHALL 指出首次啟動前要準備錄影目錄，並指向文件中的指令或 `--up`。

#### Scenario: 一般使用者從零部署
- **WHEN** docker 群組內的一般使用者在全新目錄執行 `bash scripts/quickstart.sh --up`
- **THEN** `${DATA_PATH}/recordings` 為 `1000:0`、模式 `2770`；之後的 RDP／VNC 會話留下 `session-<id>.guac`，
  會話的錄影路徑已寫入，回放串流與下載皆回 200

#### Scenario: 以 sudo 從零部署
- **WHEN** 在全新目錄執行 `sudo bash scripts/quickstart.sh --up`
- **THEN** 錄影目錄的擁有者、群組與模式與一般使用者執行時相同，圖形錄影與回放同樣成功

#### Scenario: 既有部署的錯誤狀態被修正且不需重啟
- **WHEN** 堆疊執行中且映像未變，錄影目錄為 `0:0 0755`，或為 `1000:1000` 且根層有群組 1000 的錄影檔，重跑 `--up`
- **THEN** 目錄收斂為 `1000:0 2770`，群組 1000 的根層檔案改為群組 0；backend 與 guacd 未重啟，
  新的圖形錄影成功，原本讀不到的既有錄影回放轉為 200

#### Scenario: 連跑兩次狀態不變
- **WHEN** 已收斂後再執行 `--up`
- **THEN** 腳本不報錯，錄影目錄與其中檔案的擁有者、群組與模式前後相同

### Requirement: quickstart.sh 的適用範圍

`scripts/quickstart.sh` SHALL 保留其現有環境設定、建置與啟動行為，供開發者及 macOS／Windows 本機試用。對外文件 SHALL 明載此路徑非正式部署入口；正式 Linux 安裝、備份與升級 SHALL 以安裝包的 `custodexa.sh` 及對應營運程序說明。`quickstart.sh` SHALL NOT 被描述成能管理安裝包部署或執行其升級與還原。

#### Scenario: 開發者於 macOS 試用
- **WHEN** 開發者依 QUICKSTART 的試用段落執行 `scripts/quickstart.sh --up`
- **THEN** 文件清楚說明這是本機試用，腳本既有 `.env` 產生與啟動行為仍可使用

#### Scenario: 正式部署尋找升級入口
- **WHEN** 維運從 README 或 QUICKSTART 查詢 Linux 正式部署的升級方式
- **THEN** 文件指向 `custodexa.sh upgrade` 及升級操作程序，不以 `quickstart.sh` 或 git pull 作為正式升級步驟

### Requirement: 開發版單檔掛載占位
開發版堆疊把數個單一檔案以唯讀方式掛進後端原始碼目錄底下；主機端的掛載點不存在時，首次啟動可能失敗。`--up` 模式在開發版形態下 SHALL 於啟動容器之前，確保這些單檔掛載在主機端的掛載點存在：
目錄不存在即建立，檔案不存在即建立空檔；已存在的檔案 SHALL NOT 改變其內容。
不帶 `--up` 執行時 SHALL NOT 建立這些檔案或目錄（該模式不啟動容器）；非開發版形態不論是否帶 `--up` 都 SHALL NOT 建立。

#### Scenario: 開發版從零啟動一次成功
- **WHEN** 開發版形態、主機端沒有任何單檔掛載占位檔，執行 `bash scripts/quickstart.sh --up`
- **THEN** 啟動容器之前，每個單檔掛載的主機端路徑都已存在，腳本不需重跑

#### Scenario: 既有占位檔不被改動
- **WHEN** 開發版形態、占位檔已存在且有內容，執行 `bash scripts/quickstart.sh --up`
- **THEN** 該檔內容前後相同

#### Scenario: 不啟動容器或非開發版形態不建占位檔
- **WHEN** 開發版形態不帶 `--up` 執行腳本，以及正式形態帶 `--up` 執行腳本，執行前主機端都沒有占位檔
- **THEN** 兩次執行後，每個單檔掛載的主機端路徑仍不存在

### Requirement: 開發版首次啟動的健康等待
開發版形態首次啟動時，後端容器要先下載模組並編譯，耗時遠超正式形態。`--up` 模式在開發版形態下 SHALL 將後端健康等待上限設為 1800 秒，並說明首次啟動可能需要 10 到 15 分鐘；等待期間 SHALL 每 60 秒輸出一行已等待時間。正式形態的等待上限維持 120 秒。

#### Scenario: 開發形態首次啟動等待較長並顯示進度
- **WHEN** 開發版形態執行 `bash scripts/quickstart.sh --up`，後端遲遲未回應健康檢查
- **THEN** 腳本印出首次啟動需 10 到 15 分鐘的說明，每 60 秒印一行已等待時間，逾時訊息中的上限為 1800 秒；正式形態同樣情況的逾時上限為 120 秒

### Requirement: 原始碼部署依 .env 推導形態

`scripts/quickstart.sh` SHALL 依 `.env` 的 `COMPOSE_FILE` 區分開發形態與正式形態：值為 `docker-compose.dev.yml` 時為開發形態，SHALL NOT 推導或寫入 `COMPOSE_PROFILES`，且 `EXTERNAL_DB_HOST` 有值或 `TLS_MODE=external` 時 SHALL 拒絕並說明開發形態固定使用開發 compose 內的資料庫與入口；值為空白或 `docker-compose.yml` 時為正式形態，SHALL 依 deployment-configuration「部署形態由 .env 推導」的同一規則推導形態（profiles 套用於根目錄 `docker-compose.yml`），寫入 `.env` 末尾以同一標記包住的管理區（只含 `COMPOSE_PROFILES`，不寫 `COMPOSE_FILE`），並在 `--up` 時以環境變數帶入。值列出舊的疊加檔名時，SHALL 依其內容核對 `EXTERNAL_DB_HOST` 並補上外部入口形態的 `TLS_MODE=external`，移除該行並逐項報告；與 `.env` 其他鍵矛盾時 SHALL 拒絕。

對 `.env` 的寫入 SHALL 在讀完整份檔案並通過本 Requirement 的全部檢查之後，以同目錄暫存檔一次 rename 提交（權限 600）；任何檢查不過或提交前失敗時 `.env` SHALL 逐位元組不變。管理區以外 SHALL 只允許兩種改動：刪除列有舊疊加檔名的 `COMPOSE_FILE` 行，以及舊值列有外部入口疊加檔時把 `TLS_MODE` 改為 `external`；其餘每一行 SHALL 逐位元組不變。已完成翻譯的 `.env` 再執行一次時，推導結果與 `.env` 內容 SHALL 不變。

正式形態 SHALL 套用與管理腳本相同的外接位址檢查，以及下列兩項形態檢查，違反時在任何 `docker compose` 呼叫前以非零狀態結束：內建資料目錄有資料或本專案的 postgres 容器存在時，SHALL NOT 改為外接，畫面 SHALL 指向營運文件「換到外接資料庫」一節；上次形態為外接（管理區的 `COMPOSE_PROFILES` 不含 `bundled-db`，或舊 `COMPOSE_FILE` 列有外接資料庫疊加檔）而 `EXTERNAL_DB_HOST` 空白時，SHALL 拒絕並說明會啟動沒有資料的內建資料庫、應填回原外接位址。

#### Scenario: 原始碼部署只填外接位址
- **WHEN** `.env` 未設 `COMPOSE_FILE`、設 `EXTERNAL_DB_HOST=db.example.internal` 與 `DB_PASSWORD`，本機沒有內建資料目錄，執行 `bash scripts/quickstart.sh --up`
- **THEN** `.env` 管理區的 `COMPOSE_PROFILES` 為 `builtin-tls`；沒有建立 postgres 容器；backend 連 `db.example.internal`

#### Scenario: 開發形態填了外接位址
- **WHEN** `.env` 已取消 `COMPOSE_FILE=docker-compose.dev.yml` 註解，且設了 `EXTERNAL_DB_HOST`，執行腳本
- **THEN** 腳本在任何 `docker compose` 呼叫前以非零狀態結束，說明開發形態使用開發 compose 內的資料庫

#### Scenario: 舊寫法的疊加 COMPOSE_FILE
- **WHEN** `.env` 為 `COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml`、`TLS_MODE=selfsigned`，執行腳本
- **THEN** 腳本移除該行、把 `TLS_MODE` 改為 `external` 並逐項報告，管理區的 `COMPOSE_PROFILES` 為 `bundled-db,own-ingress`

#### Scenario: 外接部署停機後清空了位址
- **WHEN** 以外接形態跑過 `quickstart.sh --up`（管理區為 `COMPOSE_PROFILES=builtin-tls`），之後 `docker compose down` 移除容器、本機沒有內建資料目錄，再把 `EXTERNAL_DB_HOST` 清空並執行 `bash scripts/quickstart.sh --up`
- **THEN** 腳本在任何 `docker compose` 呼叫前以非零狀態結束（fake docker 呼叫紀錄為空），訊息說明上次以外接資料庫啟動、清空會啟動沒有資料的內建資料庫；`.env` 雜湊與執行前相同

#### Scenario: 內建已有資料卻填外接
- **WHEN** 原始碼部署以內建形態運行過、內建資料目錄有資料，`.env` 加上 `EXTERNAL_DB_HOST=db.example.internal` 後執行腳本
- **THEN** 腳本在任何 `docker compose` 呼叫前以非零狀態結束，訊息指出內建資料目錄路徑並指向營運文件「換到外接資料庫」一節；`.env` 雜湊與執行前相同

#### Scenario: 翻譯在提交前失敗
- **WHEN** `.env` 為 `COMPOSE_FILE=docker-compose.yml:docker-compose.external-ingress.yml`、`TLS_MODE=selfsigned`，且 `.env` 所在目錄不可寫入暫存檔，執行腳本
- **THEN** 腳本以非零狀態結束，`.env` 逐位元組不變；目錄恢復可寫後再執行，結果與「舊寫法的疊加 COMPOSE_FILE」相同

#### Scenario: 翻譯完成後再執行一次
- **WHEN** 「舊寫法的疊加 COMPOSE_FILE」完成後立即再執行一次腳本
- **THEN** `.env` 雜湊與第一次執行後相同，管理區的 `COMPOSE_PROFILES` 仍為 `bundled-db,own-ingress`，畫面不列任何改動項目

### Requirement: 原始碼部署的舊大版本資料目錄

正式版 compose 的內建資料庫為 PostgreSQL 18 並掛載 `${DATA_PATH:-./data}/postgresql` 起，正式形態且內建資料庫形態（`EXTERNAL_DB_HOST` 空白）時，`scripts/quickstart.sh` SHALL 在任何 `docker compose` 呼叫之前檢查：舊資料目錄 `${DATA_PATH:-./data}/postgres` 存在且非空、新資料目錄 `${DATA_PATH:-./data}/postgresql/18/docker` 不存在或為空時，SHALL 以非零狀態結束，訊息 SHALL 說明這台機器有舊版資料庫（列出路徑與其版本檔記載的大版本）、新版不會讀取它、腳本不會自動轉換，並指向文件中原始碼部署以匯出再匯入換到新大版本的手動程序；SHALL NOT 修改、改名或刪除舊資料目錄，SHALL NOT 讓新版在空資料庫上啟動。兩個目錄都有資料時 SHALL 照常以新資料目錄啟動，並提示舊目錄仍在、確認不需要後可自行移除。開發形態（`COMPOSE_FILE=docker-compose.dev.yml`）SHALL 略過本檢查。

#### Scenario: 原始碼部署留有 16 的資料
- **WHEN** `./data/postgres` 含 PostgreSQL 16 已初始化的資料、`./data/postgresql` 不存在，`.env` 為內建資料庫形態，執行 `bash scripts/quickstart.sh --up`
- **THEN** 腳本在任何 `docker compose` 呼叫前以非零狀態結束，訊息列出 `./data/postgres` 與大版本 16，並指向手動轉換程序；`./data/postgres` 內容未被改動

#### Scenario: 已手動轉換後重跑
- **WHEN** `./data/postgresql/18/docker` 已有資料、`./data/postgres` 仍在，執行 `bash scripts/quickstart.sh --up`
- **THEN** 服務以新資料目錄啟動，輸出提示舊目錄仍在且可自行移除

#### Scenario: 外接資料庫形態不檢查
- **WHEN** `.env` 設 `EXTERNAL_DB_HOST=db.example.internal`，本機留有 `./data/postgres`，執行腳本
- **THEN** 不因舊資料目錄而停下
