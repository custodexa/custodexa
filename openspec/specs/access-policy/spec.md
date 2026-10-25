# access-policy

## Purpose

三段存取政策（`open`／`reason`／`approval`）：資產本身的政策段位與全域預設 fallback（政策掛資產本身、不掛組織結構）、connect-token 簽發點的單點政策閘（全模態一致）、admin 豁免留痕與 auditor 不豁免。

## Requirements

### Requirement: 三段存取政策
資產 SHALL 可設定存取政策段位：`open`（不需申請）／`reason`（填理由即過）／`approval`（強制審核）；未設定 SHALL 走全域預設政策鍵，全域預設出廠 SHALL 為 `open`。政策段位 SHALL 掛於資產本身（`assets.access_policy`，nullable），SHALL NOT 掛於資產分組或節點——資產組織結構（含未來的多歸屬節點樹）SHALL 不影響政策解析。資產單台覆寫的設定與清除 SHALL 只由持有存取政策權限點的主體執行（超級管理者保留身分照常具備），變更 SHALL 入審計；全域預設鍵的設定權限 SHALL 依安全政策設定的既有規則，SHALL NOT 因持有存取政策權限點而取得。

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

#### Scenario: 持存取政策權限點者不能改全域預設
- **WHEN** 只持存取政策權限點與資產檢視、不具安全政策設定能力的主體送出修改全域預設鍵的請求
- **THEN** 請求被拒絕，全域預設值不變

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

### Requirement: 單台存取政策覆寫為獨立能力
系統 SHALL 在權限目錄提供獨立的存取政策權限點，歸授權規則群組、屬管理類；在節點範圍過濾實作之前 SHALL 只能經全域指派生效。資產管理類的預設組合 SHALL NOT 含此權限點。角色編輯描述 SHALL NOT 為此權限點列出必要依賴（覆寫表格與兩個畫面入口的資料改由單台覆寫清單的唯讀查詢提供，不再讀取資產列表），SHALL NOT 自動補授。

資產更新請求的本文只含 `access_policy` 一個頂層鍵時，主體 SHALL 只需存取政策權限點，SHALL NOT 另需資產編輯能力；本文含其他任何頂層鍵、為空或無法解析時 SHALL 需要資產編輯能力，含其他鍵者另依各欄位既有的額外能力判定。資產更新本文出現 `access_policy` 鍵（含用於清除覆寫的空字串）、資產建立帶非空 `access_policy`、批次匯入任一列帶非空 `access_policy` 時，主體 SHALL 持有存取政策權限點，否則整筆請求拒絕、批次整批拒絕且不寫入任何資料；匯入預檢與正式匯入 SHALL 套用同一判定，皆整批拒絕。主體既無資產編輯能力也無存取政策權限點時，SHALL 在任何資源查詢與輸入驗證之前被拒絕，回應狀態碼、錯誤碼與欄位 SHALL 與以資產編輯能力守衛時相同。

節點範圍過濾已實作，存取政策權限點 SHALL 可經節點範圍指派生效。經節點範圍指派持有時，資產更新中的覆寫設定與清除 SHALL 只對位於該指派管理範圍內的資產生效；資產位於範圍外或不存在時 SHALL 回相同的 404 且不寫入任何欄位（同一請求同時停用資產（active:false）且資產跨出停用能力範圍時除外，該情形依刪除與停用的拒絕優先序先回該拒絕，不在本 Requirement 保證 404），範圍判定 SHALL 與寫入在同一交易內，並 SHALL 在缺能力的拒絕之後、任何欄位驗證之前進行。建立資產帶非空覆寫時，新資產的目的節點 SHALL 至少一個位於存取政策權限點的管理範圍內（與資產的範圍判定同義）；不符者整筆拒絕、不寫入任何資料，拒絕形狀 SHALL 與不持存取政策權限點者帶覆寫時相同。批次匯入任一列帶非空覆寫、而該列的目的節點皆不在存取政策權限點的管理範圍內時，匯入預檢與正式匯入 SHALL 都整批拒絕、不寫入任何資料，拒絕形狀 SHALL 與不持存取政策權限點者的匯入相同，SHALL NOT 改為逐列標示。範圍化持有者造成的降級 SHALL 照單台覆寫降級的規則同交易寫入審計與系統告警。不論經全域或節點範圍指派持有，存取政策權限點 SHALL NOT 使主體取得修改全域預設鍵的能力。只持全域指派者與超級管理者的行為 SHALL 不變。

#### Scenario: 只送覆寫欄位不需資產編輯能力
- **WHEN** 只持存取政策權限點與資產檢視的主體，對資產 A 送出只含 `access_policy: approval` 的更新，之後再送出只含 `access_policy: ""` 的更新
- **THEN** 兩次都成功：A 先設為 `approval`，再清回跟隨全域預設

#### Scenario: 夾帶其他欄位整筆拒絕
- **WHEN** 只持存取政策權限點的主體送出同時含 `access_policy` 與 `name` 的資產更新
- **THEN** 請求被拒絕，資產名稱與政策都不變

#### Scenario: 只持資產編輯能力者不能改覆寫
- **WHEN** 持資產編輯能力、不持存取政策權限點的主體送出含 `access_policy` 的資產更新（無論值為何，含空字串）
- **THEN** 整筆請求被拒絕，該資產任何欄位都不變

#### Scenario: 不帶覆寫欄位的編輯不受影響
- **WHEN** 持資產編輯能力、不持存取政策權限點的主體送出不含 `access_policy` 鍵的資產更新
- **THEN** 依既有規則更新成功，覆寫值不變

#### Scenario: 建立與匯入帶覆寫值
- **WHEN** 不持存取政策權限點的主體建立資產時帶 `access_policy: open`，或匯入的其中一列連線政策欄為 `open`
- **THEN** 建立請求被拒絕；匯入預檢與正式匯入都整批拒絕（與資產欄位級能力同一拒絕形狀）、零列寫入

#### Scenario: 兩種能力皆無者維持原拒絕形狀
- **WHEN** 既無資產編輯能力也無存取政策權限點的主體，對一個不存在的資產 ID 送出只含 `access_policy` 的更新
- **THEN** 回應與以資產編輯能力守衛時的拒絕完全相同，不因資產不存在而改回其他狀態

#### Scenario: 範圍化持有者改範圍內覆寫並告警
- **WHEN** 只經節點範圍指派（範圍為節點 A）持有存取政策權限點與資產檢視的主體，把 A 下資產 X 的覆寫由 `approval` 改為 `reason`
- **THEN** X 的覆寫為 `reason`，同一交易內有資產更新審計與一筆存取政策放寬告警

#### Scenario: 範圍外與不存在同形
- **WHEN** 同一主體對範圍外資產 Y 送出只含 `access_policy` 的更新，再對不存在的資產識別碼送出同樣的更新
- **THEN** 兩次皆回 404，狀態碼、錯誤碼與欄位相同；Y 的覆寫值不變，也不產生告警

#### Scenario: 建立資產的目的節點不在存取政策範圍
- **WHEN** 主體可在節點 A、B 建立資產，但存取政策權限點只涵蓋節點 A，建立一台只放在 B、帶 `access_policy: approval` 的資產
- **THEN** 建立請求被拒絕，拒絕形狀與不持存取政策權限點者帶覆寫時相同，不新增任何資產

#### Scenario: 匯入列的目的節點不在存取政策範圍
- **WHEN** 同一主體匯入三列，其中一列帶 `open` 且只放在 B，其餘兩列不帶覆寫且放在 A 或 B
- **THEN** 匯入預檢與正式匯入都整批拒絕，拒絕形狀與不持存取政策權限點者的匯入相同，零列寫入；該列改放在 A 後整批成功

#### Scenario: 範圍化持有者不能改全域預設
- **WHEN** 只經節點範圍指派持有存取政策權限點的主體送出修改全域預設鍵的請求
- **THEN** 請求被拒絕，全域預設值不變

### Requirement: 有效段位與降級判定單一來源
資產的有效段位 SHALL 為合法的單台覆寫值；未覆寫或覆寫值不合法時 SHALL 為合法的全域預設；兩者皆不合法時 SHALL 為 `open`。段位高低 SHALL 為 `approval` 高於 `reason` 高於 `open`。變更後有效段位低於變更前即為降級，高於為收緊，相同為不變。政策閘、資產列表的段位標註、單台覆寫變更的分類與全域預設變更的分類 SHALL 使用同一份計算。單次單台覆寫變更的前後有效段位 SHALL 以同一個全域預設值計算。

#### Scenario: 覆寫調低
- **WHEN** 資產覆寫由 `approval` 改為 `reason`
- **THEN** 判定為降級

#### Scenario: 清除覆寫回落到較低預設
- **WHEN** 全域預設為 `open`，資產覆寫由 `reason` 清除為跟隨全域
- **THEN** 判定為降級

#### Scenario: 清除覆寫回落到相同或較高預設
- **WHEN** 全域預設為 `approval`，資產覆寫由 `reason` 清除為跟隨全域
- **THEN** 判定為收緊，不是降級

#### Scenario: 新增與預設相同的覆寫
- **WHEN** 全域預設為 `open`，未覆寫的資產新增覆寫 `open`
- **THEN** 有效段位不變，不是降級

#### Scenario: 全域預設調低以同一計算判定
- **WHEN** 以同一份計算比較全域預設由 `approval` 改為 `reason`
- **THEN** 判定為降級

### Requirement: 單台覆寫降級同交易審計並觸發系統告警
單台覆寫變更使資產有效段位降級時，覆寫值、資產變更審計與一筆存取政策放寬系統告警事件（類型 `access_policy_relaxed`） SHALL 在同一交易寫入；任一寫入失敗 SHALL 整筆回滾，覆寫值維持變更前。告警事件 SHALL 帶操作者與目標資產，參數恰為四項：型態 `relax_type`（調低覆寫 `override_lowered` 或清除覆寫 `override_cleared`）、有效段位前後值 `before_level`／`after_level` 與資產名稱 `asset_name`；事件 SHALL NOT 含覆寫前後值，也 SHALL NOT 含秘密。覆寫前後值 SHALL 記在同一交易的資產變更審計，該審計與告警事件 SHALL 帶相同的關聯識別。此告警屬不可刪除、不可停用的系統告警類型，SHALL 不論操作者身分（含超級管理者）一律產生。收緊與有效段位不變的變更 SHALL NOT 產生此告警，只寫一般審計。建立資產時帶入的覆寫值 SHALL NOT 視為降級。此告警 SHALL NOT 阻止降級本身，也 SHALL NOT 阻止降級後依新段位放行的連線。

#### Scenario: 覆寫降級產生審計與告警
- **WHEN** 持存取政策權限點的主體把資產 A 的覆寫由 `approval` 改為 `open`
- **THEN** A 的覆寫為 `open`，同一交易內有一筆含 `access_policy` 前後值的資產更新審計與一筆存取政策放寬告警事件，告警記錄有效段位由 `approval` 降為 `open`、型態為覆寫降級，審計與告警帶相同的關聯識別

#### Scenario: 清除覆寫回落產生告警
- **WHEN** 全域預設為 `open`，主體清除資產 A 的 `approval` 覆寫
- **THEN** 產生存取政策放寬告警，型態為清除回落，有效段位由 `approval` 降為 `open`

#### Scenario: 收緊不告警
- **WHEN** 主體把資產 A 的覆寫由 `open` 改為 `approval`
- **THEN** 只寫資產更新審計，不產生存取政策放寬告警

#### Scenario: 告警寫入失敗整筆回滾
- **WHEN** 覆寫降級時告警事件寫入失敗
- **THEN** 請求回錯誤，A 的覆寫值、資產更新審計都不留下

#### Scenario: 審計寫入失敗整筆回滾
- **WHEN** 覆寫降級時資產變更審計寫入失敗
- **THEN** 請求回錯誤，A 的覆寫值不變且不留下告警事件

#### Scenario: 超級管理者降級同樣告警
- **WHEN** 超級管理者把資產 A 的覆寫由 `approval` 改為 `reason`
- **THEN** 產生存取政策放寬告警

#### Scenario: 建立資產帶低段位覆寫
- **WHEN** 全域預設為 `approval`，主體建立資產並帶覆寫 `open`
- **THEN** 只寫資產建立審計，不產生存取政策放寬告警

### Requirement: 單台覆寫清單依存取政策範圍投影

系統 SHALL 提供單台存取政策覆寫清單的唯讀查詢，供持存取政策權限點者使用：預設列出已設定覆寫的資產，亦 SHALL 可依搜尋條件列出尚未覆寫、可加入覆寫的資產；每筆含資產識別碼、名稱、協議、覆寫值與節點歸屬。經節點範圍指派持有者 SHALL 只見其存取政策範圍內的資產，範圍條件 SHALL 在搜尋、計數與分頁之前套用；節點歸屬 SHALL 只列範圍內節點，範圍外歸屬只以「另有 N 個範圍外節點」計數呈現，SHALL NOT 含範圍外節點的名稱、路徑或識別碼。回應 SHALL 附目前的全域預設段位與檢視者是否為範圍化持有者。範圍、節點歸屬的遮蔽與「是否為範圍化持有者」SHALL 只依存取政策權限點的有效指派判定，SHALL NOT 因資產管理可視、連線授權或其他權限點的節點範圍指派而擴大或改變。不持存取政策權限點者 SHALL 被拒絕。只持全域指派者與超級管理者 SHALL 見全部資產。

#### Scenario: 範圍化持有者只見範圍內資產
- **WHEN** 只經節點範圍指派（範圍為節點 A）持有存取政策權限點的主體查詢覆寫清單，A 內有 3 台已覆寫資產、範圍外另有 5 台
- **THEN** 回應只含 A 內的 3 台，總數為 3

#### Scenario: 連線授權不擴大清單範圍
- **WHEN** 同一主體另經他人授權可連線範圍外的已覆寫資產 Y
- **THEN** 覆寫清單與可加入覆寫的搜尋結果都不含 Y

#### Scenario: 其他權限點的節點範圍不改變判定
- **WHEN** 經全域指派持有存取政策權限點的主體，另經節點範圍指派持有資產檢視能力
- **THEN** 覆寫清單含全部已覆寫資產、節點歸屬完整，且回應標示為非範圍化持有者

#### Scenario: 回應附全域預設
- **WHEN** 全域預設為 `reason`，不具安全政策設定能力的持有者查詢覆寫清單
- **THEN** 回應附全域預設段位 `reason`

#### Scenario: 不持權限點者被拒
- **WHEN** 只持資產檢視能力的主體查詢覆寫清單
- **THEN** 請求被拒絕

#### Scenario: 全域持有者見全部
- **WHEN** 超級管理者查詢覆寫清單
- **THEN** 回應含全部已覆寫資產，節點歸屬完整、不帶範圍外計數
