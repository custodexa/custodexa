# Custodexa 後端

Go 實作的堡壘機後端：協議代理、憑證收口、審計與錄製。

本檔只描述 `backend/` 目錄本身。專案總覽見 [根 README](../README.md)；啟動、測試資產與故障排除見
[docs/QUICKSTART.md](../docs/QUICKSTART.md)；API 參考見 [docs/API_SPEC.md](../docs/API_SPEC.md)；
資料表與 migration 見 [docs/DB_SCHEMA.md](../docs/DB_SCHEMA.md)；各能力的行為規格見
[openspec/specs/](../openspec/specs/)。

## 技術棧

- **語言**：Go 1.26+（`go.mod` 宣告 `go 1.26.0` 為下限；容器建置基底釘 `golang:1.26.6-alpine`）
- **Web 框架**：Gin
- **ORM**：GORM
- **資料庫**：PostgreSQL 是唯一的正式目標。程式碼中另有 sqlite 分支，只服務單元測試——
  版本化 migration 一律 PG 語法，`DB_DRIVER=sqlite` 啟動會在遷移階段崩潰，不可用於部署
  （方言相依處以 `internal/database/` 的 migration 與 driver 分支實碼為準）
- **認證**：JWT + bcrypt；另支援 MFA（TOTP）、LDAP、OIDC
- **WebSocket**：gorilla/websocket
- **圖形協議**：Apache Guacamole（guacd），僅 RDP／VNC；SSH／DB CLI／K8s exec 不經 guacd

## 目錄結構

```
backend/
├── cmd/server/          # 組裝根與路由註冊（main.go、stage1/stage2 兩段啟動）＋跨切面守衛測試
├── internal/
│   ├── modules/         # 領域模組（業務邏輯的落點）
│   │   ├── asset/       # 資產、資產帳號、分組、標籤
│   │   ├── identity/    # 使用者、使用者群組、認證來源
│   │   ├── authz/       # 授權關係與權限判定
│   │   ├── policy/      # 安全政策、存取政策、告警規則
│   │   ├── audit/       # 操作與指令審計、稽核鏈
│   │   ├── session/     # 會話生命週期、監看、分享
│   │   └── keyvault/    # 憑證封裝與金鑰管理
│   ├── api/             # HTTP handlers（薄層，業務邏輯落在 modules）
│   ├── middleware/      # 認證、權限、審計中介層
│   ├── connectgate/     # 連線收口閘與一次性 connect token
│   ├── sshproxy/        # SSH 直連代理與文字終端鏈路
│   ├── dbproxy/         # 資料庫 CLI 代理
│   ├── k8sproxy/        # K8s exec 代理
│   ├── localpty/        # 本地 CLI 子程序 PTY（dbproxy／k8sproxy 共用，含提示式憑證注入）
│   ├── proxy/           # Guacamole 代理（RDP／VNC）
│   ├── recorder/        # 會話錄製（asciicast／guac）
│   ├── seal/            # 憑證封裝流程
│   ├── sealjournal/     # 封裝日誌（落盤與 admission）
│   ├── model/           # GORM 資料模型
│   ├── database/        # 連線、AutoMigrate 清單與版本化 migrations
│   ├── guards/          # 架構守衛的被測面（模組邊界、品牌、審計遮罩、閘道 API…）
│   └── …                # apierror、branding、notifycat、observability、scheduler、sourceip 等
├── pkg/                 # 可獨立引用的套件：crypto、guacamole、gatewayapi
├── config/              # 設定載入（環境變數為唯一來源）
├── scripts/             # 補主線煙測未覆蓋面的專題腳本（索引見 scripts/README.md）
└── testdata/            # 測試資產
```

## 開發與驗證

**一律在 docker-compose 內執行**，不在 host 直接 `go run`／`go test`：

```bash
docker compose exec backend go build ./...
docker compose exec backend go test ./...
docker compose exec backend go vet ./...
```

改動多檔後執行 `docker compose restart backend`——Air 熱重載的 build 失敗不會中斷容器，
會安靜地繼續跑舊二進位，看起來像「改了沒生效」。

端到端冒煙由專案根的 `bash scripts/e2e_smoke.sh` 涵蓋；未涵蓋的專題面向見 `scripts/README.md`。
測試紀律與已知陷阱見 [docs/dev/testing.md](../docs/dev/testing.md)；架構不變式（連線收口、
審計 fail-close 語義、啟停順序、SQL 與資料層陷阱）見
[docs/dev/conventions.md](../docs/dev/conventions.md)；模組邊界規則見
[openspec/specs/module-boundaries/](../openspec/specs/module-boundaries/) 與
[docs/dev/architecture.md](../docs/dev/architecture.md)。

## 設定

所有設定經環境變數載入，可用變數與說明見專案根的 `.env.example`。
**不得硬編碼任何密鑰**——`JWT_SECRET`、資料庫密碼與金鑰材料一律於部署時提供，
輪替程序見 [docs/ops/privileged-credential-rotation.md](../docs/ops/privileged-credential-rotation.md)。

## 授權

AGPL-3.0，全文見 [LICENSE](../LICENSE)。
