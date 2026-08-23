# 跨協議完整驗收場景（錄像驗收標準）

> 目的：每協議錄製一段有意義的會話錄像，作為驗收基準。核心驗證貫穿——
> **含中文／特殊符號／emoji 的輸入與檔案內容，能正確還原顯示，且不弄壞終端或錄像回放畫面。**
> 使用方式：本檔是**驗收場景的基準清單**，不是逐步操作手冊。
> 各協議的靶機由 `docker-compose.dev.yml` 提供（Windows RDP 除外，見第 5 節）；
> 資產須自行於系統中建立，本檔不綁定任何特定的資產編號。
>
> 約束：對任何非本專案提供的靶機（如自備的 Windows 主機）全程**非破壞**
> （嚴禁刪除／修改檔案）；資料庫類靶機建議只執行 SELECT。

## 1. SSH（靶機 `ssh-test`）— 終端 + 腳本 + 檔案上傳往返
- [ ] 特殊符號：`echo 'single' "double" $HOME`、`echo "a;b|c&d*e?f(g)h"`
- [ ] 中文+emoji：`echo '中文測試 你好世界 🔒🚀'`（終端正確顯示無亂碼）
- [ ] 多行續行：`echo one \`⏎`two`
- [ ] 迴圈腳本：`for i in 1 2 3; do echo "第 $i 圈 中文"; done`；heredoc 小腳本
- [ ] **SFTP 上傳**（中文檔名、含中文/特殊符號內容）
- [ ] **往返驗證**：`cat` 剛上傳的檔 → 內容正確還原、終端/錄像不錯位
- [ ] SFTP 下載遠端檔

### 1a. SSH 多帳號（靶機 ssh-multi-test，dev compose 常設）

> 靶機為 rootful sshd（`ssh-multi-test:22`，host 埠 2223），root/`rootpass123` 與
> testuser/`testpass123` 皆可密碼登入；既有 ssh-test（rootless）僅支援 testuser，
> 不可用於多帳號驗證。建 SSH 資產指向 `ssh-multi-test:22`（testuser 快速欄位成為
> 預設帳號），再於資產帳號管理加 root（勾 privileged）。自動化基準＝e2e_smoke 場景 11。

- [ ] 工作區點資產 → 帳號選擇器彈出：testuser 預選（default）、root 帶特權標記
- [ ] 分別以兩帳號連入 → `whoami`/`id -u` 確認身分切換（0 vs 1000）
- [ ] 會話列表該筆記錄帳號 username 快照（連線後改名/刪帳號不改寫歷史）
- [ ] 授權範圍：對 testldap 授權該資產並指定帳號 `["testuser"]` → 以 testldap 登入，
      選擇器不出現（單一有效帳號直連 testuser）、root 不可見；改回 `@ALL` 後兩帳號可選

## 2. MySQL（靶機 `mysql-test`，資料庫 `testdb`）
- [ ] 單行：`SELECT 'O''Brien','中文測試',1+1;`
- [ ] 多行（續行 prompt）：跨行 SELECT
- [ ] 危險指令告警（testdb 自建自刪，非破壞）：`CREATE TABLE demo_zz(...);` → `DROP TABLE demo_zz;`

## 3. PostgreSQL（靶機 `postgres`，建議只 SELECT）
- [ ] 單行：`SELECT version();`、`SELECT 'a''b','中文';`
- [ ] 多行（續行）
- [ ] 元命令：`\dt`

### 3a. SQL Server（靶機 mssql-test，dev compose 常設）

> 靶機為 `mcr.microsoft.com/mssql/server:2025-CU8-ubuntu-24.04`，
> 容器內主機名 `mssql-test`、host 埠 1433，帳號 `sa` / 密碼 `Testpass123!`。
> **密碼不沿用專案慣例的 `testpass123`**——SQL Server 的 SA 密碼強度檢查要求大寫／小寫／
> 數字／符號四類取三。建資產：協議選「SQL Server」、埠 1433，**必須填使用者名稱**
> （mssql 不在免使用者名稱清單；無使用者名稱則 sqlcmd 不索取密碼、注入永不觸發）。

- [ ] 提示符為 `1>`（續行 `2>`）；**SQL 不加獨立一行的 `GO` 不會執行**——這是與 MySQL／
      PostgreSQL 手測最大的差異，最容易卡在「打完 `SELECT ...;` 按 Enter 卻沒有結果」
- [ ] 單行：`SELECT 40+2 AS smoke` ⏎ `GO` ⏎ → 回傳結果
- [ ] 多行（續行 `2>`）：跨行 SELECT ＋ `GO`
- [ ] 中文/特殊符號：`SELECT N'中文測試', 'O''Brien'` ⏎ `GO` ⏎
- [ ] 指令審計：一批 `SELECT … ⏎ GO ⏎` 在會話列表的指令記錄中結算為**一筆**
      （內容含 SQL 行與 GO 行，以換行相接），不是每行一筆
- [ ] 認證類型下拉（DB 協議專屬）：`SQL 認證（帳號密碼）` 可選、
      `網域認證（Windows／Kerberos，尚未支援）` 存在但 disabled

安全面（`-X 0` ＋ 環境降權，每項皆須確認**會話存活**、可繼續下指令）：

- [ ] `:!! id` → `ED and !!<command> commands, startup script, and environment variables are disabled`，
      會話存活（後續 `SELECT 1` ⏎ `GO` 仍正常）
- [ ] `:out /tmp/x` → `Sqlcmd: Error: … permission denied`，會話存活（無可寫落點）
- [ ] `:r /etc/passwd` 後 `:list` 可顯示內容——**刻意允許**（`-X` 關不掉 `:R`），
      容器內無有價值內容、無憑證
- [ ] `:connect mssql-test,1433 -U sa` → 再次印出 `Password:` 但**不自動注入**
      （一次性注入窗口已關閉）；下一則輸入被當成密碼吃掉而登入失敗，會話存活回到 `1>`

### 3a-1. 憑證面複驗工具：`backend/scripts/mssql_cred_probe.go`

**唯一能人工複驗憑證面的手段**，正式 QA 工具（`//go:build ignore`，不進建置也不進映像）。
`dbws_smoke.go` 只做斷言、看不到原始會話輸出；本探針**只做取樣、不做斷言**，把 WebSocket 收到的
每一則訊息原樣印出，故能回答「真憑證是否可從子程序側讀到」這種要**眼看**才算數的問題。
這是唯一能人眼複驗憑證面的工具，沒有它就得從頭重寫一支。

> **不得在含真實生產憑證的環境執行。** 它會把原始會話輸出（含 CLI 回顯、`:r` 讀進緩衝的檔案內容、
> 錯誤訊息）整段印到終端與 CI log；若目標資產綁的是真帳號，任何洩漏面都會被原樣落到日誌裡。
> 僅限開發／測試環境與測試資產。輸出貼進任何文件前先去識別。

適用場景：憑證隔離複驗（argv／env／檔案三面）、`-X`／降權擋下逃逸原語後**會話是否存活**、
一次性注入窗口是否真的關閉（第二次 `Password:`）、批次終止符與審計切分的實際行為。
非 mssql 專屬——任何走 web CLI 的 DB 資產都能用（協議差異只在送進去的指令）。

用法（容器內；`-cmds` 以 `;;` 分隔，每條之後收集 `-wait` 秒的輸出）：

```
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<dev 密碼>"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
docker compose exec -T backend go run scripts/mssql_cred_probe.go \
  -token "$TOKEN" -asset <您的資產 id> \
  -cmds ':r /proc/self/environ;;:list;;:r /proc/self/cmdline;;:list;;:!! id;;SELECT 1;;GO'
```

判讀基準（規範來源：`openspec/specs/database-protocol/spec.md`「明文憑證於 CLI 子程序內不得可讀」
與「子程序環境不含 SQLCMD_LANG」）：environ 不得含
`SQLCMDPASSWORD`／`SQLCMD_LANG`／密碼字串，cmdline 不得含 `-P` 或密碼，`:!!`／`:ed` 須被擋下
且會話存活。**探針會自動處理傳輸閘的 428**（自動立據同意後重取 connect token），故不需先手動點 UI。

## 4. k8s exec（靶機 `k3s-test`）
- [ ] 連線時選 pod（multi/app）
- [ ] exec 中文 + 多行指令
- [ ] cp 上傳 → exec `cat` 往返驗證 → 下載
- [ ] logs 模態（唯讀）

## 5. Windows RDP（需自備 Windows 主機；**dev compose 不提供**）— 非破壞
- [ ] 桌面右鍵 → context menu
- [ ] 開檔案總管 → 視窗最小化
- [ ] 剪貼簿貼上到遠端
- [ ] （唯讀）開檔檢視中文內容，不存檔不改
- [ ] 嚴禁刪除/修改任何檔案

## 6. Linux RDP（靶機 `rdp-test`）— 桌面 + 檔案上傳
- [ ] 桌面右鍵 + Ctrl+Alt+Del + 剪貼簿
- [ ] **上傳檔案**（redirected disk）→ 文字編輯器開檔顯示內容（往返驗證）

## 7. VNC（靶機 `vnc-test`）
- [ ] 桌面操作 + 剪貼簿 + Ctrl+Alt+Del

---

## 通過判準（每段共通）
- 中文/特殊符號/emoji 正確顯示，無亂碼（`??`/mojibake）
- 終端不錯位、不殘留控制字元；錄像回放正常、無錯誤層
- 檔案上傳成功且遠端顯示內容與來源一致（往返完整性）
- 審計（session_commands / audit_log）記錄完整、特殊字元無損

---

## 錄像回放控制驗收

> 規格：`openspec/specs/session-recording/`（圖形與文字兩條回放路徑的播放控制條文皆在其中）。

每協議各錄一段會話後，於瀏覽器實際操作播放器，逐項確認：

| 檢查項 | 判準 |
|---|---|
| seek 拖曳／點擊跳轉 | 跳轉後位置**不被彈回** |
| 文字錄像 2x 倍率 | 實測每秒前進兩秒（asciinema 播放器） |
| 圖形錄像變速 | 靜態空檔進度仍平滑；播到底自動暫停（guacamole 播放器） |

文字終端類（SSH／MySQL／PostgreSQL／k8s exec）使用 asciinema 播放器，
圖形類（RDP／VNC）使用 guacamole 播放器，兩者的判準如上表分列。

**已知非回歸（guacamole 本性，列為 non-goal）**：圖形錄像對極少畫面更新的會話幀稀疏（VNC 6 幀/48s 最明顯），從靜態段中間按播放時 guacamole 會「resume 立即渲染下一幀、跳過空檔」→ 快速衝過稀疏幀（進度仍正確跟畫面）。從頭播放則平滑。如需超稀疏錄像亦平順，須走錄製端 heartbeat sync（未做）。
