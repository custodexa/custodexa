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

### Requirement: 連線 context 可見性
連上 K8s 容器後，系統 SHALL 讓操作者隨時看到當前 namespace / pod / container 與連線模態；分頁 SHALL 以 pod 名標示（同資產多 pod 可區分，重複開同 pod SHALL 加序號）；pod 選擇器標題 SHALL 含 namespace。

#### Scenario: 連上後看得出位置
- **WHEN** 使用者連上某 namespace 的某 pod/container
- **THEN** 工具列顯示該 ns/pod/container 與模態（exec 或 日誌·唯讀），分頁顯示 pod 名

#### Scenario: 同資產多 pod 可區分
- **WHEN** 使用者自同一 K8s 資產開啟兩個不同 pod
- **THEN** 兩分頁分別以各自 pod 名標示，可區分

### Requirement: 四連線模態、審計語義與資料面裁決
系統 SHALL 支援 interactive-exec、logs（`kubectl logs -f` 唯讀）、kubectl cp（檔案進出）模態；one-shot（單指令）在 argv 側指令審計與阻斷實裝前 SHALL 由後端一律拒絕（避免單指令繞過審計/阻斷）。指令審計與阻斷 SHALL 適用於 interactive-exec；logs SHALL 走相同錄製但跳過指令解析/阻斷並標記 logs 模態，且 SHALL 唯讀（停用終端輸入，不誤導可輸入）。kubectl cp SHALL 以獨立 exec-tar 審計擷取檔名/大小/方向並落 audit_log；下載容器內不存在的檔案 SHALL 回錯誤（不串流空檔偽裝成功）。

容器檔案的上傳與下載是資料面操作，SHALL 與連線簽發使用同一組判定，依序檢查：主體仍可連線與來源限定、資產存在且啟用、對該資產的連線授權、K8s 固定預設帳號、存取政策（核准時窗內的臨時授權放行；超級管理者依既有豁免放行並留豁免標記）、傳輸安全。任一不通過 SHALL 回該判定既有的拒絕碼，SHALL NOT 解封憑證或連線目標。資產管理類權限 SHALL NOT 構成檔案進出的放行條件；沒有連線授權者即使持有資產寫入權限亦 SHALL 被拒。K8s 固定作用於單一預設帳號，不受帳號授權範圍約束；檔案進出在帳號範圍上的結論 SHALL 與 K8s 連線簽發相同，SHALL NOT 在資料面單方面加嚴或放寬。錄影前置探測不屬檔案進出的判定（檔案進出不產生錄影會話）。

上傳的本文由客戶端決定送達時間。上傳 SHALL 在讀取本文前裁決一次（被拒的請求不解析本文、不建暫存檔），並 SHALL 在本文接收與暫存完成後、解封憑證與遠端寫入之前，以當下的授權事實再完整裁決一次；在這段期間被撤銷連線授權、資產被停用或核准時窗到期的請求 SHALL 以該判定既有的拒絕碼被拒，SHALL NOT 執行 `kubectl cp`。下載沒有本文，裁決與複製之間沒有客戶端可控的窗口，維持單次裁決。第二次裁決通過後傳輸進行中的撤銷或到期不中斷該次傳輸；exec 與 logs 會話的撤銷依連線會話既有規則處理。

interactive-exec 與 logs SHALL 只經連線簽發與兌換閘序建立；持任何資產管理權限而無連線授權者 SHALL NOT 取得 K8s 連線。

K8s 檔案上傳與下載若因資產沒有可用掛載憑證而於連目標前拒絕，SHALL 回既有 `RULE_ACCOUNT_NONE_USABLE` 與相應 4xx 原因；其他複製失敗 SHALL 保持既有分類。此要求 SHALL NOT 改變檔案權限、傳輸政策或連目標前的拒絕順序。

#### Scenario: 看容器日誌（唯讀）
- **WHEN** 使用者對 K8s 資產選擇 logs 模態
- **THEN** 唯讀串流容器日誌、會話被錄製、不套用指令阻斷，且終端停用輸入

#### Scenario: 容器檔案進出受審計且依連線裁決
- **WHEN** 對某 K8s 資產有連線授權且存取政策通過的使用者以 kubectl cp 傳檔進出容器
- **THEN** 傳輸執行，檔名、大小、方向被擷取並寫入 audit_log

#### Scenario: 本文送達前失效的上傳被拒
- **WHEN** 有連線授權的使用者對 K8s 資產送出上傳請求並通過讀本文前的裁決，之後延遲送出本文，期間其連線授權被撤銷、資產被停用或核准時窗到期
- **THEN** 本文暫存完成後的第二次裁決以對應的既有拒絕碼拒絕該請求，未解封憑證、未執行 `kubectl cp`

#### Scenario: 只有資產管理權限不能傳檔
- **WHEN** 持資產寫入、測試連線等全部資產管理權限，但對該 K8s 資產沒有連線授權的使用者呼叫容器檔案上傳或下載
- **THEN** 請求被拒並回連線授權的既有拒絕碼，未解封憑證、未執行 `kubectl cp`

#### Scenario: 存取政策同樣約束檔案進出
- **WHEN** 資產的有效存取政策為需核准，使用者有常設連線授權但沒有時窗內的核准臨時授權，呼叫容器檔案下載
- **THEN** 請求以存取政策的既有拒絕碼被拒；取得時窗內的核准後同一請求可執行

#### Scenario: 只有資產管理權限不能 exec
- **WHEN** 持全部資產管理權限但沒有連線授權的使用者對 K8s 資產申請連線
- **THEN** 連線簽發被拒，沒有 exec 或 logs 會話建立

#### Scenario: 下載不存在檔不偽裝成功
- **WHEN** 使用者下載容器內不存在的路徑
- **THEN** 回 404 並於前端顯示「容器內找不到該檔案」，不下載空檔

#### Scenario: one-shot 後端拒絕
- **WHEN** 以 API 對 K8s 資產要求 one-shot 模態或夾帶單指令
- **THEN** 後端拒絕該連線（argv 審計/阻斷實裝前不開放）

#### Scenario: 待配憑證資產的容器檔案進出
- **WHEN** 有權使用 K8s 檔案端點者對零可用掛載資產上傳或下載
- **THEN** 連目標前拒絕，回 `RULE_ACCOUNT_NONE_USABLE`，不以 502 檔案傳輸失敗表達

### Requirement: 容器檔案進出的傳輸控管與裁決次序

K8s 容器檔案進出端點（`kubectl cp` 的上傳與下載）SHALL 受資料傳輸控管管制：上傳需有效 `file_upload_enabled`、下載需有效 `file_download_enabled`（有效值定義見 `data-transfer-control`）。不通過時 SHALL 回註冊的機器碼（與 SFTP 面同碼同語義）、SHALL NOT 執行 `kubectl cp`，並 SHALL 寫入 status=`denied` 的審計紀錄（含 pod／container／路徑）。admin SHALL NOT 豁免。

資料傳輸控管 SHALL 在連線裁決通過之後才判定；連線裁決不通過的請求 SHALL 以連線裁決的拒絕碼回應，不進入傳輸控管。兩道判定都通過才執行 `kubectl cp`。

#### Scenario: 容器上傳被禁
- **WHEN** 有效 `file_upload_enabled` 為 false 且使用者呼叫容器檔案上傳端點
- **THEN** 請求被拒並回註冊機器碼，未執行 `kubectl cp`，audit_logs 產生 status=denied 的 file_upload 紀錄

#### Scenario: 容器下載被禁
- **WHEN** 有效 `file_download_enabled` 為 false 且使用者呼叫容器檔案下載端點
- **THEN** 請求被拒並回註冊機器碼，audit_logs 產生 status=denied 的 file_download 紀錄

#### Scenario: 傳輸控管在連線裁決之後
- **WHEN** 有效 `file_upload_enabled` 為 false，且呼叫者對該資產沒有連線授權
- **THEN** 回連線授權的既有拒絕碼，而不是傳輸控管的機器碼；有連線授權的使用者在同一設定下則回傳輸控管的機器碼並留 denied 審計

### Requirement: 管理探測與資料面分離
pods 列表與 K8s 測試連線 SHALL 屬管理探測：沿用其既有的管理權限判定，回應 SHALL 只含可達性、權限預檢結果與 pod 中繼資料（名稱、狀態、容器、映像、就緒與重啟資訊），SHALL NOT 含容器內檔案內容、指令輸出或容器日誌。管理探測的成功 SHALL NOT 產生連線授權、連線票證或任何可供資料面判定引用的狀態。資料面操作（容器檔案進出、exec、logs）SHALL NOT 以任何管理權限或管理探測結果取代連線裁決。

#### Scenario: 列 pod 不代表可進容器
- **WHEN** 持資產檢視與測試連線權限、但沒有連線授權的使用者成功列出某 K8s 資產的 pod
- **THEN** 回應只有 pod 中繼資料；其後對同一資產的檔案進出與連線簽發仍依連線裁決被拒

#### Scenario: 探測不回傳容器內容
- **WHEN** 管理者對 K8s 資產執行測試連線或列 pod
- **THEN** 回應不含任何容器內檔案、指令輸出或日誌內容
