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

#### Scenario: 全新環境一鍵補齊
- **WHEN** 目錄內無 `.env`，執行 `bash scripts/quickstart.sh`
- **THEN** 自範本建立 `.env`，四項機密全數生成且各自通過對應的啟動驗證格式；以生成的
  `ADMIN_INITIAL_PASSWORD` 對 `/api/v1/auth/login` 登入可取得 `password_change_required`

#### Scenario: 使用者已設定的值不被覆蓋
- **WHEN** `.env` 內 `ADMIN_INITIAL_PASSWORD` 已是非範本值，執行腳本
- **THEN** 該值原樣保留，回報「已設定，未動」

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

### Requirement: 資料庫已初始化護欄
`${DATA_PATH:-./data}/postgres` 目錄存在且非空時，腳本 SHALL NOT 變更 `DB_PASSWORD`
（即使其值仍為範本出貨值），並 SHALL 說明理由；不提供強制覆寫旗標。

#### Scenario: 既有資料庫不被鎖死
- **WHEN** `./data/postgres` 已含初始化後的資料庫檔案且 `DB_PASSWORD=postgres`，執行腳本
- **THEN** `DB_PASSWORD` 維持原值，輸出含「已初始化」護欄說明

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
流程成功結束時 SHALL 輸出登入資訊區塊：連線 URL（依 `.env` 的 `COMPOSE_FILE`
判定開發版 `http://localhost:3000` 或正式版 `http://localhost/`）、帳號 `admin`、
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

#### Scenario: ui 模式收尾為初始化解封指引
- **WHEN** `.env` 為範本出貨預設（`KEK_PROVIDER=ui`），執行 `bash scripts/quickstart.sh --up` 且後端健康
- **THEN** 收尾區塊為初始化解封指引（首次造訪進初始化頁、主金鑰瀏覽器本地生成須保存、
  以 admin 帳密授權），含 URL 與 admin 帳密，且輸出不含任何 KEK 材料
