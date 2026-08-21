# access-policy

## Purpose

三段存取政策（`open`／`reason`／`approval`）：資產本身的政策段位與全域預設 fallback（政策掛資產本身、不掛組織結構）、connect-token 簽發點的單點政策閘（全模態一致）、admin 豁免留痕與 auditor 不豁免。
## Requirements
### Requirement: 三段存取政策
資產 SHALL 可設定存取政策段位：`open`（不需申請）／`reason`（填理由即過）／`approval`（強制審核）；未設定 SHALL 走全域預設政策鍵，全域預設出廠 SHALL 為 `open`。政策段位 SHALL 掛於資產本身（`assets.access_policy`，nullable），SHALL NOT 掛於資產分組或節點——資產組織結構（含未來的多歸屬節點樹）SHALL 不影響政策解析。政策設定 SHALL 為 admin only 且變更入審計。

#### Scenario: 資產政策生效
- **WHEN** admin 將資產 A 設為 `approval`，一般使用者對 A 申請 connect-token
- **THEN** 簽發依 `approval` 段位處理（常設 connect 被攔）

#### Scenario: 未設定走全域
- **WHEN** 資產未設政策、全域預設為 `open`
- **THEN** 該資產連線行為與未安裝政策功能時一致

#### Scenario: 全域預設變更即時生效
- **WHEN** 全域預設改為 `reason`，使用者連線未設政策的資產
- **THEN** 依 `reason` 段位處理

#### Scenario: 組織結構不影響政策
- **WHEN** 資產 A 設有 `approval` 且被移入/移出任何分組（或未來的節點）
- **THEN** A 的政策解析結果不變（恆為 `approval`）

### Requirement: 政策閘於簽發點單點強制
connect-token 簽發 SHALL 於連線授權檢查之後檢查資產政策段位：段位非 `open` 時，僅「時窗內、來源為核准流（source=ticket）」的 connect 授權 SHALL 放行；常設 connect SHALL 被攔截（持有者維持可見與可申請）。攔截回應 SHALL 為 403 並含機器可辨欄位（`reason` 為 `reason_required` 或 `approval_required`、政策時長上限、在途申請識別）；SHALL NOT 使用 428（傳輸閘專用）。閘 SHALL 對全模態（SSH/RDP/VNC/DB/k8s）單點生效（含直呼 API），且 SHALL NOT 受功能開關旁路。

#### Scenario: 強制審核攔常設 connect
- **WHEN** 使用者對 `approval` 段位資產持有時窗內常設 connect 授權並申請 connect-token
- **THEN** 簽發被攔（403、reason=approval_required），資產在列表仍可見

#### Scenario: 臨時授權放行
- **WHEN** 同一使用者的申請獲核准（產生時窗內 source=ticket 的 connect 授權）後再申請 connect-token
- **THEN** 簽發放行，時窗內可多次連線

#### Scenario: reason 段同樣攔截常設
- **WHEN** 使用者對 `reason` 段位資產持常設 connect 申請 connect-token 且無有效臨時授權
- **THEN** 簽發被攔（403、reason=reason_required）——與 approval 段的差別僅在申請將被即時自動核准

#### Scenario: 攔截回應機器可辨
- **WHEN** 政策閘攔截且該使用者已有一張 pending 申請
- **THEN** 403 回應含 reason、時長上限與在途申請識別，前端可據此呈現「申請中」而非再送新單

### Requirement: admin 豁免留痕、auditor 不豁免
admin SHALL 豁免政策閘，但每次豁免連線 SHALL 寫入審計日誌並帶獨立豁免標記；auditor SHALL NOT 豁免（與一般 user 同受政策閘）。

#### Scenario: admin 豁免連線留痕
- **WHEN** admin 對 `approval` 段位資產申請 connect-token（無臨時授權）
- **THEN** 簽發放行，審計日誌含該次連線的政策豁免標記

#### Scenario: auditor 不豁免
- **WHEN** auditor 對 `approval` 段位資產申請 connect-token
- **THEN** 與一般 user 同樣被攔（auditor 本就不應連線資產）

### Requirement: break-glass 與政策閘的關係
break-glass SHALL NOT 繞過政策閘：破窗產生的票證即 ticket 來源，連線一律走既有票證放行軌（簽發點三閘序不變、傳輸閘照常獨立判定）。政策閘 SHALL NOT 因 `break_glass_enabled` 開關狀態改變任何攔截語義——開關只控制破窗建單入口，不新增放行路徑。

#### Scenario: 破窗連線走票證軌
- **WHEN** 破窗成功後使用者申請 connect-token
- **THEN** 政策閘以時窗內票證放行（與一般核准票證同一判定路徑），傳輸閘照常獨立生效

#### Scenario: 開關開啟不改變無票證者的攔截
- **WHEN** `break_glass_enabled=true` 但使用者未破窗、無票證，對 approval 段位資產申請 connect-token
- **THEN** 政策閘照常 403（approval_required），開關狀態不影響攔截
