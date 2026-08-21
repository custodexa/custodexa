# k8s-exec Specification

## Purpose
規範 Kubernetes 容器 exec 連線能力：namespace 資產與連線時選 pod、namespace 級授權與 API server RBAC 邊界、session 不可變 pod 快照、control plane TLS 驗證、四種連線模態的審計語義、容器檔案進出的傳輸控管，以及審計鏈沿用。
## Requirements
### Requirement: namespace 資產與連線時選 pod
K8s 資產 SHALL 綁定 namespace（非固定 pod）；連線時系統 SHALL 列出該 namespace 的活 pod 供使用者選定 pod 與 container，再以 `kubectl exec` 進入。namespace SHALL 取自資產（伺服端可信），SHALL NOT 由客端傳入；選定的 pod/container SHALL 經注入防護驗證（禁 `-` 開頭與控制字元）。

#### Scenario: 連線時選 pod
- **WHEN** 使用者在工作區點擊 K8s 資產
- **THEN** 先呈現該 namespace 的 pod 選擇器，使用者選定 pod（必要時選 container）後進入該容器的互動終端

#### Scenario: pod 名不可越出資產 namespace
- **WHEN** 客端嘗試以其他 namespace 的 pod 或非法 pod 名建線
- **THEN** 後端以資產的 namespace 為準、拒絕非法值，連線不跨出授權的 namespace

### Requirement: namespace 級授權與 API server RBAC 邊界
授權邊界 SHALL 為 namespace（token 的 RBAC 由 kube API server 強制）；ConnectGrant SHALL 維持只授權 user→asset，SHALL NOT 在 grant 內挾帶 pod。系統 MAY 於列 pod 前以 SelfSubjectAccessReview 預檢以提早回報無權。exec 遭 API server 拒絕時 SHALL 以使用者語言回報。

#### Scenario: 無 exec 權
- **WHEN** token 對選定 pod 無 pods/exec 權
- **THEN** 終端顯示繁中可懂的「無權限」訊息，而非裸英文錯誤

### Requirement: Session 不可變 pod 快照
K8s 會話 SHALL 於 Session 落不可變欄位 `k8s_namespace`、`k8s_pod`、`k8s_pod_uid`、`k8s_container`、`k8s_image`、`k8s_node`，取自連線當下後端 `get pod` 的實際值（非前端字串）；session_commands SHALL 冗餘 pod/container；即時監看與錄製 meta SHALL 帶 pod 標識。

#### Scenario: 會話釘住當次 pod
- **WHEN** 使用者經某 K8s 資產進入一個 pod 並執行指令
- **THEN** 該會話記錄釘住當次 pod 名/uid/image/node，列表與回放可顯示「進的是哪個容器」，即使該 pod 之後被同名重建

### Requirement: control plane TLS 驗證
K8s 資產 SHALL 支援選填 CA cert（PEM），連線時 SHALL 以其驗證 API server 憑證；`insecure_skip_tls_verify` SHALL 為 per-asset 顯式開關且預設關閉，開啟時資產列表與連線 SHALL 顯紅色警告並寫入審計。

#### Scenario: 預設驗證 TLS
- **WHEN** 建立 K8s 資產而未開啟 insecure 開關
- **THEN** 連線驗證 API server TLS 憑證；憑證不符時連線失敗並回報 TLS 錯誤

### Requirement: 四連線模態與審計語義
系統 SHALL 支援 interactive-exec、logs（`kubectl logs -f` 唯讀）、kubectl cp（檔案進出）模態；one-shot（單指令）在 argv 側指令審計與阻斷實裝前 SHALL 由後端一律拒絕（避免單指令繞過審計/阻斷）。指令審計與阻斷 SHALL 適用於 interactive-exec；logs SHALL 走相同錄製但跳過指令解析/阻斷並標記 logs 模態，且 SHALL 唯讀（停用終端輸入，不誤導可輸入）。kubectl cp SHALL 以獨立 exec-tar 審計擷取檔名/大小/方向並落 audit_log；傳檔進/出容器 SHALL 需寫級權限（PermAssetUpdate）；下載容器內不存在的檔案 SHALL 回錯誤（不串流空檔偽裝成功）。

#### Scenario: 看容器日誌（唯讀）
- **WHEN** 使用者對 K8s 資產選擇 logs 模態
- **THEN** 唯讀串流容器日誌、會話被錄製、不套用指令阻斷，且終端停用輸入

#### Scenario: 容器檔案進出受審計且需寫權限
- **WHEN** 使用者以 kubectl cp 傳檔進出容器
- **THEN** 需寫級權限，且傳輸的檔名、大小、方向被擷取並寫入 audit_log

#### Scenario: 下載不存在檔不偽裝成功
- **WHEN** 使用者下載容器內不存在的路徑
- **THEN** 回 404 並於前端顯示「容器內找不到該檔案」，不下載空檔

#### Scenario: one-shot 後端拒絕
- **WHEN** 以 API 對 K8s 資產要求 one-shot 模態或夾帶單指令
- **THEN** 後端拒絕該連線（argv 審計/阻斷實裝前不開放）

### Requirement: 原生級選擇器與錯誤可懂
pod 選擇器 SHALL 提供即時清單、pod 狀態色（Running/Pending/CrashLoopBackOff/Terminating）、前端即時篩選、隱藏 Completed job pod，並顯示 Ready/Age/重啟次數/image。多 container 時 SHALL 讀 `default-container` annotation 預選；distroless 無 shell 時 SHALL 攔截並以繁中提示改選 container 或看 logs。列 pod 與連線錯誤 SHALL 分類為：不可達 / TLS 失敗 / token 401 / 無 list RBAC 403 / namespace 404。

#### Scenario: 選定 pod 已消失
- **WHEN** 使用者選定後該 pod 在 exec 前已被重排程消失
- **THEN** exec 失敗時回退選擇器供重選，而非報錯關閉頁籤

#### Scenario: distroless 無 shell
- **WHEN** 使用者選定的容器無任何 shell（distroless/scratch）
- **THEN** 終端顯示繁中「此容器無 shell，請改選其他 container 或看 logs」，而非裸英文 not found

### Requirement: 憑證與會話韌性
臨時 kubeconfig SHALL 為 0600、token 不落 argv、會話結束即刪；系統 SHALL 於啟動期清掃殘留的 `k8sproxy-*` 臨時目錄以覆蓋崩潰路徑；list pods 路徑 SHALL 以 in-memory 設定免落檔。idle 逾時計時 SHALL 同時被伺服器下行資料重置（避免 `tail -f`/等部署等無鍵盤輸入的會話被誤砍）。

#### Scenario: 後端崩潰後不殘留 token
- **WHEN** 後端於 K8s 會話進行中崩潰、重啟
- **THEN** 啟動期清掃刪除殘留的臨時 kubeconfig，token 不滯留磁碟

#### Scenario: 長時間輸出不被誤砍
- **WHEN** 使用者在 exec 會話內 `tail -f` 日誌、長時間無鍵盤輸入但有下行輸出
- **THEN** idle 計時被下行資料重置，會話不被 idle 逾時切斷

### Requirement: 審計鏈沿用
K8s 互動會話 SHALL 走 sshproxy bridge 的 TerminalConn 介面，指令審計、asciicast 錄製、即時監看、指令阻斷 SHALL 自動生效。

#### Scenario: 容器內指令入審計
- **WHEN** 使用者在 K8s interactive-exec 會話執行指令
- **THEN** 指令逐條出現於 session_commands（不漏不亂序）且會話可錄製回放

### Requirement: 容器檔案進出的傳輸控管

K8s 容器檔案進出端點（`kubectl cp` 的上傳與下載）SHALL 受資料傳輸控管管制：上傳需有效 `file_upload_enabled`、下載需有效 `file_download_enabled`（有效值定義見 `data-transfer-control`）。不通過時 SHALL 回註冊的機器碼（與 SFTP 面同碼同語義）、SHALL NOT 執行 `kubectl cp`，並 SHALL 寫入 status=`denied` 的審計紀錄（含 pod／container／路徑）。admin SHALL NOT 豁免。

**已知邊界（SHALL 明載，不在本能力範圍內修復）**：K8s 檔案端點目前僅以資產管理層級的角色權限守門，未經連線授權判定、段位存取政策閘與帳號範圍複查，與 SFTP 檔案面的閘門序列不對稱。本要求只保證資料傳輸鍵在該通道上不說謊，SHALL NOT 被理解為該通道的授權缺口已補齊。

#### Scenario: 容器上傳被禁
- **WHEN** 有效 `file_upload_enabled` 為 false 且使用者呼叫容器檔案上傳端點
- **THEN** 請求被拒並回註冊機器碼，未執行 `kubectl cp`，audit_logs 產生 status=denied 的 file_upload 紀錄

#### Scenario: 容器下載被禁
- **WHEN** 有效 `file_download_enabled` 為 false 且使用者呼叫容器檔案下載端點
- **THEN** 請求被拒並回註冊機器碼，audit_logs 產生 status=denied 的 file_download 紀錄

#### Scenario: 邊界可查
- **WHEN** 稽核人員檢視 K8s 檔案進出的控管說明
- **THEN** 可查得「僅受傳輸鍵管制、未經連線授權與段位政策」的已知邊界說明

### Requirement: 連線 context 可見性
連上 K8s 容器後，系統 SHALL 讓操作者隨時看到當前 namespace / pod / container 與連線模態；分頁 SHALL 以 pod 名標示（同資產多 pod 可區分，重複開同 pod SHALL 加序號）；pod 選擇器標題 SHALL 含 namespace。

#### Scenario: 連上後看得出位置
- **WHEN** 使用者連上某 namespace 的某 pod/container
- **THEN** 工具列顯示該 ns/pod/container 與模態（exec 或 日誌·唯讀），分頁顯示 pod 名

#### Scenario: 同資產多 pod 可區分
- **WHEN** 使用者自同一 K8s 資產開啟兩個不同 pod
- **THEN** 兩分頁分別以各自 pod 名標示，可區分

