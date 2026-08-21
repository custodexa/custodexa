# access-control-settings

## Purpose

存取管控設定頁（/access-control，admin only）：全域預設段位承載與資產政策覆寫總覽（政策掛資產本身）、資產覆寫可視化表格（含「清除覆寫（跟隨全域，目前：X）」動態回顯）、申請參數與破窗撤銷政策鍵承載、PCI 子集偏離摘要與分域套用；資產編輯表單為政策主要設定入口。
## Requirements
### Requirement: 存取管控設定頁
系統 SHALL 提供 admin 專屬「存取管控」設定頁（`/access-control`，路由守衛沿既有 admin-only 模式），承載存取域全部政策鍵：全域預設段位 `access_policy_default`、申請參數（`access_request_max_duration_minutes`／`access_request_pending_timeout_hours`／`access_request_min_approvals`）、破窗與撤銷（`break_glass_enabled`／`break_glass_duration_minutes`／`break_glass_review_timeout_hours`／`access_revoke_disconnect`）、**資料傳輸管控（`clipboard_send_enabled`／`clipboard_recv_enabled`／`file_upload_enabled`／`file_download_enabled`／`file_delete_enabled`）**。政策鍵編輯 SHALL 沿安全政策既有機制（dirty-keys 儲存列、批次原子、PCI 建議標示、非法值拒絕、變更入審計）。`access_request_min_approvals` SHALL 標示為內控強化選項（雙人覆核慣例）、SHALL NOT 標示或聲稱為 PCI 要求（無 PCI 建議值），其 hint SHALL 明示涵蓋不足風險（門檻高於某資產的可核人數時申請須由 admin 補位或等待逾時）。**資料傳輸五鍵同樣無 PCI 建議值**，SHALL 標示其法源為電子支付機構相關基準、SHALL NOT 標示為 PCI 要求。頁面 SHALL 顯示本頁鍵子集的 PCI 偏離摘要並提供「套用本頁建議值」（**該套用 SHALL NOT 影響無 PCI 建議值的鍵，含資料傳輸五鍵**）。全域預設段位旁 SHALL 明示適用範圍語義（僅適用於未個別設定政策的資產）。

#### Scenario: 頁面承載存取域政策鍵
- **WHEN** admin 開啟存取管控頁
- **THEN** 頁面呈現全域預設段位、申請參數、破窗撤銷與資料傳輸管控共 13 鍵；具 PCI 建議值的鍵帶建議標示，`access_request_min_approvals` 與資料傳輸五鍵標示為無 PCI 建議值；修改後經儲存列送出，批次原子生效且入審計

#### Scenario: 非 admin 被拒
- **WHEN** 非 admin 角色以 URL 直達 `/access-control`
- **THEN** 路由守衛拒絕進入；導覽亦不顯示該項

#### Scenario: 套用本頁建議值僅動本頁鍵
- **WHEN** admin 於存取管控頁點擊「套用本頁建議值」並儲存
- **THEN** 僅本頁具 PCI 建議值的鍵設為建議值（`access_request_min_approvals` 與資料傳輸五鍵不在其列、值不變），其他域頁的政策鍵值不變

#### Scenario: 門檻值驗證
- **WHEN** admin 將 `access_request_min_approvals` 設為 0 或超出上限
- **THEN** 儲存被拒（非法值），有效區間 1–10

### Requirement: 資料傳輸管控區塊

存取管控頁 SHALL 以獨立區塊承載資料傳輸五鍵，區塊 SHALL 明示：剪貼簿兩鍵僅對圖形協議（RDP／VNC）具強制力且**需重新連線才生效**；檔案三鍵（SFTP 檔案管理、圖形通道檔案傳輸、K8s 容器檔案進出）即時生效。

該區塊 SHALL 提供可查閱的控制邊界說明（`data-transfer-control` 的誠實邊界各項），涵蓋：文字終端無伺服端強制點且前端按鈕屬介面約束、剪貼簿拒絕無審計事件、會話分享觀看者繼承原連線參數、K8s 檔案端點的授權缺口、以及「關閉下載不等於資料出不去」（指令外帶屬指令阻斷職責）。該說明 SHALL 可於頁面內展開，SHALL NOT 僅存在於外部文件。

#### Scenario: 區塊明示生效時機差異
- **WHEN** admin 開啟資料傳輸管控區塊
- **THEN** 剪貼簿兩鍵標示「需重新連線才生效」與適用協議，檔案三鍵標示即時生效

#### Scenario: 邊界說明頁內可查
- **WHEN** admin 於資料傳輸管控區塊展開控制邊界說明
- **THEN** 上述各項限制逐條可讀，且無任何文案宣稱剪貼簿控管涵蓋文字終端

### Requirement: 組覆寫可視化表格
存取管控頁 SHALL 以「資產政策覆寫」表格列出**全部已設定政策覆寫的資產**（`access_policy` 非空者）：每列含資產名、協議、政策下拉（三段位＋「清除覆寫（跟隨全域）」）與顯式「清除覆寫」操作鈕（與下拉清除選項等效路徑——清除係移除動作，SHALL 有可直接辨識的入口而非僅藏於下拉）；並 SHALL 提供資產搜尋選擇器以將未覆寫資產加入覆寫。下拉變更 SHALL 列內即時儲存、成功/失敗有明確回饋、失敗回滾顯示值、儲存期間互斥防並發亂序（沿既有覆寫表格語義）；表格區 SHALL 明示「變更即時生效」。全域預設值文案 SHALL 於「清除覆寫」選項動態回顯（跟隨全域設定（目前：X））。無任何覆寫時 SHALL 顯示空狀態說明（全部資產跟隨全域預設）。

#### Scenario: 僅列覆寫資產
- **WHEN** 資產 A 設 `approval`、資產 B 未設政策
- **THEN** 表格僅列 A；B 可經搜尋選擇器加入覆寫

#### Scenario: 列內變更即時生效
- **WHEN** admin 將 A 的政策自 `approval` 改為「清除覆寫」
- **THEN** 變更即時儲存並回饋成功，A 自表格移除、回歸全域預設；變更入審計

#### Scenario: 儲存失敗回滾顯示值
- **WHEN** 列內政策變更因後端錯誤儲存失敗
- **THEN** 顯示失敗回饋且顯示值回滾為變更前的值

### Requirement: 組政策設定入口唯一
資產連線政策的設定入口 SHALL 為：資產編輯表單的「連線政策」欄位（主要入口，選項含「跟隨全域設定（目前：X）」動態文案與三段位）與存取管控頁覆寫表格（總覽入口）；兩者 SHALL 操作同一資產欄位（無獨立資料源）。資產分組管理介面 SHALL NOT 涉及任何政策呈現或設定（分組已卸下政策職責）。

#### Scenario: 資產表單設定政策
- **WHEN** admin 於資產編輯表單將連線政策設為「需審核人核准」並儲存
- **THEN** 該資產 `access_policy=approval`，存取管控頁覆寫表格出現該資產；變更入審計

#### Scenario: 分組管理不涉政策
- **WHEN** admin 開啟資產分組管理介面
- **THEN** 無任何政策標籤或政策設定控件（分組僅組織與授權職能）
