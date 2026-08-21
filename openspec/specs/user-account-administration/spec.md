# user-account-administration Specification

## Purpose
管理員對使用者帳號的管理語義：email 唯一性衝突以友善訊息呈現、未知 email 以 NULL 表示，使用者更新採欄位級審計差異，帳號標註供應來源並管理外部身分綁定與解綁的失效語義，角色變更即時失效相關憑證。
## Requirements
### Requirement: Admin user email uniqueness conflict is friendly
When an administrator updates a user's `email` via `PUT /api/v1/users/:id` to a value already held by another live account, the system SHALL return `409 Conflict` with a machine-recognizable conflict code, not a generic `500` internal error. Email SHALL be trimmed and case-normalized before the uniqueness comparison.

#### Scenario: Duplicate email rejected with 409
- **WHEN** admin sets a user's email to one already used by another live account
- **THEN** the request fails with `409` and a machine-recognizable conflict (not a `500`)

#### Scenario: Case-insensitive uniqueness
- **WHEN** admin sets an email that differs from an existing one only by case or surrounding whitespace
- **THEN** it is treated as a conflict after trim/case normalization

### Requirement: Field-level audit diff for user updates
Administrative user updates SHALL record a field-level before/after diff in the audit log so that what changed is auditable. `full_name` MUST NOT be masked as `***MASKED***` in the audit body, as it is not a secret.

#### Scenario: Update records before and after
- **WHEN** admin changes a user's `full_name` or `email`
- **THEN** the audit entry records the previous and new values for the changed fields

#### Scenario: full_name not over-masked
- **WHEN** an admin user update touches `full_name`
- **THEN** the audit body shows the actual `full_name` value, not `***MASKED***`

### Requirement: Unknown email represented as NULL
The system SHALL represent an unknown or absent email as NULL rather than an empty string, and SHALL enforce email uniqueness only over non-NULL values. When LDAP provisioning encounters an email conflict, it SHALL store NULL, allowing multiple email-less shadow accounts to coexist.

#### Scenario: LDAP conflict stores NULL not empty string
- **WHEN** LDAP provisioning finds the incoming email already taken
- **THEN** the shadow account's email is stored as NULL, not as an empty string

#### Scenario: Multiple email-less accounts allowed
- **WHEN** more than one account has no email (NULL)
- **THEN** the unique index does not reject them, because uniqueness applies only to non-NULL emails

### Requirement: 供應來源標註與外部身分管理
使用者 SHALL 帶不可變的供應來源標註（local/ldap/oidc），SHALL 於建立時寫入且 SHALL NOT 因後續登入方式改寫。管理端列表 SHALL 呈現來源；OIDC 帳號 SHALL 可辨識至 provider 實例（顯示名），不得壓成籠統單一「oidc」標示。列表 SHALL 提供來源篩選。

使用者的外部身分關聯（provider、subject、最近登入）SHALL 可由 admin 檢視；admin SHALL 可為既有帳號顯式綁定外部身分，並 SHALL 可解除綁定。**解除綁定 SHALL 連帶使該使用者的既有存取失效**——涵蓋刷新憑證、仍有效的存取憑證、進行中協議連線、唯讀訂閱，以及尚未兌換的交棒憑證、待驗證狀態憑證與連線授權憑證。失效粒度為**使用者級**：該使用者經其他身分提供者或本地密碼建立的工作階段亦一併失效，須重新登入。此為刻意的安全取捨——身分級粒度需在每類憑證各多帶一維狀態，漏接風險高於「使用者重新登入一次」的成本；管理介面 SHALL 於確認前明示「該使用者的所有工作階段將被登出」。解除綁定 SHALL 於介面明示後果（已外部化的帳號解除其最後一筆身分將使其無法登入，該操作 SHALL 被拒絕）。

密碼類管理操作（重設密碼、強制改密）SHALL 依帳號憑證是否已外部化而鎖定，並 SHALL 由後端強制。

憑證外部化狀態的轉移 SHALL 明確且受限：非外部化帳號 SHALL 可由 admin 顯式改為僅外部登入（同交易清除密碼雜湊，不留可比對殘值），且該操作 SHALL 要求該帳號至少已有一筆外部身分；該操作 SHALL 一併撤銷以本地密碼建立或啟動的一切存取（含刷新與存取憑證、連線授權憑證、進行中協議連線、監看訂閱，以及**尚在進行中的多因素待驗證狀態**——否則其可於轉換後完成驗證，並因帳號此時已外部化而跳過密碼相關檢查，取得新的正式會話）；已外部化的帳號 SHALL NOT 取得本地密碼。

SHALL NOT 使任何帳號失去全部可用登入途徑。判準為「操作後該帳號是否仍有可用登入途徑」：仍具本地密碼者解除最後一筆外部身分 SHALL 被允許；目錄供應帳號的登入不依賴外部身分記錄故不受此限；憑證已外部化且登入途徑僅剩外部身分者，解除最後一筆 SHALL 被拒絕，並 SHALL 提供原子的「解除綁定並停用帳號」操作作為正當出路。

任何操作（改為僅外部登入、停用、移除 admin 角色、刪除帳號）若將使「啟用中且未外部化的 admin 帳號」數量**自一以上降為零**，SHALL 被拒絕；該數量已為零的既有部署 SHALL NOT 因此被阻擋一切管理操作（此時系統 SHALL 持續警示需新增本地 admin 以保有解封能力）。此判定 SHALL 於序列化範圍內重讀後成立——各操作獨立檢查不足以維持此不變式（兩個並發操作可各自看見對方仍存在而同時成功）。同理，解除外部身分綁定的「仍有可用登入途徑」判定 SHALL 於使用者範圍的序列化範圍內重讀。——系統封印後的解封僅接受本地 admin 憑證，失去最後一個此類帳號將導致無人可解封。

#### Scenario: 列表呈現來源
- **WHEN** admin 檢視使用者列表
- **THEN** 每列可辨識該帳號為 local/ldap/oidc 來源；OIDC 帳號可辨識至 provider 實例（顯示名）

#### Scenario: 外部來源鎖定密碼操作
- **WHEN** admin 開啟一個 OIDC 供應帳號的編輯介面
- **THEN** 密碼重設類操作不可用，並標示密碼由外部身分提供者管理

#### Scenario: admin 綁定外部身分
- **WHEN** admin 為一個既有帳號綁定某 provider 的外部身分
- **THEN** 該使用者此後可經該 provider 登入至此帳號

#### Scenario: 解綁使該使用者既有存取全數失效
- **WHEN** 一個帳號綁有兩個 provider 的身分且各自建立過會話與協議連線，admin 解除其中一個身分的綁定
- **THEN** 該使用者的刷新憑證、既簽存取憑證、協議連線、唯讀訂閱與尚未兌換的能力憑證**全數失效**（含經另一 provider 建立者），須重新登入；管理介面於確認前已明示此後果

#### Scenario: 解綁提示後果
- **WHEN** admin 對一個已外部化帳號的多筆外部身分之一執行解綁
- **THEN** 介面於確認前明示該身分將無法再用於登入

#### Scenario: 來源不因登入改寫
- **WHEN** 一個 local 供應的帳號被綁定外部身分並以該身分登入
- **THEN** 其供應來源標註仍為 local

#### Scenario: 轉換撤銷本地密碼建立的存取
- **WHEN** 使用者以本地密碼取得會話並進入多因素待驗證狀態，admin 隨即將該帳號改為僅外部登入
- **THEN** 其既有會話與連線失效，該待驗證狀態亦失效（SHALL NOT 於轉換後完成驗證並取得正式會話）

#### Scenario: 帳號停用收線監看訂閱
- **WHEN** 一名以本地密碼登入的管理者正監看他人會話，admin 停用該管理者帳號
- **THEN** 其監看訂閱被收線（該訂閱不產生協議會話記錄，亦無外部身分關聯，仍 SHALL 被涵蓋）

#### Scenario: 改為僅外部登入後本地路徑關閉
- **WHEN** admin 對一個已綁外部身分且具本地密碼的帳號執行「改為僅外部登入」
- **THEN** 該帳號此後可經外部身分登入，以任何密碼進行本地登入皆失敗

#### Scenario: 不可製造不可登入的孤兒帳號
- **WHEN** admin 嘗試解除一個憑證已外部化、且登入途徑僅剩該筆外部身分之帳號的最後一筆外部身分
- **THEN** 操作被拒絕並回明確錯誤，並提示可改用「解除綁定並停用帳號」

#### Scenario: 仍有本地密碼者可解綁最後一筆
- **WHEN** admin 對一個仍具本地密碼的帳號解除其最後一筆外部身分
- **THEN** 操作成功，該帳號仍可以本地密碼登入

#### Scenario: 並發操作不得使本地 admin 歸零
- **WHEN** 系統僅有兩個啟用且未外部化的 admin，兩個請求並發分別對兩者執行停用（或改為僅外部登入）
- **THEN** 至多一個成功，系統仍存在至少一個啟用且未外部化的 admin

#### Scenario: 並發解綁不得使登入途徑歸零
- **WHEN** 一個憑證已外部化的帳號有兩筆外部身分，兩個請求並發各解綁其中一筆
- **THEN** 至多一個成功，該帳號仍保有至少一筆外部身分

#### Scenario: 已無本地 admin 時不阻擋管理操作
- **WHEN** 系統已不存在任何啟用且未外部化的 admin，admin 執行其他帳號管理操作
- **THEN** 操作不因該不變式被拒絕，但介面持續警示需新增本地 admin 以保有解封能力

#### Scenario: 不可移除最後一個本地 admin
- **WHEN** admin 嘗試將最後一個啟用且未外部化的 admin 帳號改為僅外部登入（或停用、移除 admin 角色、刪除）
- **THEN** 操作被拒絕並回明確錯誤，帳號狀態不變

### Requirement: 角色變更的憑證失效

管理端**替換**使用者角色集的操作，於「新角色集與現行角色集不同」時 SHALL 於**同一交易**內完成三件事：替換角色、推進該使用者的憑證世代、撤銷其全部刷新憑證。SHALL NOT 停在「角色已變更但世代未推進」的中間態——該中間態使降權在憑證層完全不生效。

現行角色集 SHALL 於序列化範圍（使用者級憑證鎖）內重讀後比對；鎖外預讀 SHALL NOT 視為滿足本要求（兩個並發替換可各自看見舊集合而其一誤判為無變動）。同時需要系統級與使用者級鎖時 SHALL 依既定的 system → user 固定順序取用。

新角色集與現行角色集**相同**時 SHALL NOT 推進世代——管理端重存同一組角色不得使該使用者的既有會話失效。

**純追加角色的冪等端點**（不移除任何既有角色者）SHALL NOT 因此推進世代：其不縮減任何權限，而推進會使當事人於進行中的核准／代配流程被迫重新登入。

本要求的動機是「管理面的權限判定以憑證所攜角色快照為準」這一既有事實：不使既簽憑證失效，被撤除 admin 的帳號在其存取憑證的剩餘壽命內仍以 admin 身分通過管理端判定，據以將自身角色改回——降權可被當事人自行復原。

#### Scenario: 撤除 admin 角色即失效既簽憑證

- **WHEN** admin 將某使用者的角色自 `admin` 替換為 `user`
- **THEN** 該使用者的憑證世代被推進、全部刷新憑證被撤銷；其在此之前簽出的存取憑證於下一次使用時 SHALL 被拒（世代不符），SHALL NOT 得以憑舊快照的 admin 身分再次變更角色

#### Scenario: 保留 admin 的角色變更同樣失效既簽憑證

- **WHEN** admin 將某使用者的角色自 `admin` 替換為 `admin` ＋ `user`（新角色集仍含 admin，不觸發本地 admin 不變式的系統級鎖）
- **THEN** 世代同樣被推進——本要求 SHALL NOT 僅覆蓋「移除 admin」那一條路徑

#### Scenario: 角色集未變動不推進世代

- **WHEN** admin 以與現行完全相同的角色集（順序不同亦視為相同）呼叫角色替換
- **THEN** 憑證世代不變、刷新憑證不被撤銷，該使用者的既有會話不受影響

#### Scenario: 角色變更不終斷進行中的協議會話

- **WHEN** 某使用者角色被變更時其有進行中的協議會話與唯讀訂閱
- **THEN** 該會話與訂閱不因角色變更而被終斷（角色縮減不等同「此帳號不應再有存取」；帳號停用、刪除、解除身分綁定才適用收線語義）
