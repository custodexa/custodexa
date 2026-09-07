# role-assignment-integrity Specification

## Purpose
TBD - created by archiving change role-assignment-integrity. Update Purpose after archive.
## Requirements
### Requirement: 狀態表登記清單

系統 SHALL 以登記清單宣告納入檢查點鏈的狀態表，每一項含表名、正規化快照函式與對應的審計事件過濾條件；封章、驗證與對帳 SHALL 只依登記清單運作，不得對未登記的表做任何比對。本期登記清單 SHALL 只含 `user_roles`；`asset_authorizations`、使用者群組成員、審批範圍等 SHALL 以新增登記項的方式擴充，且守衛 SHALL 要求登記清單中每張表都有快照測試與竄改矩陣列。

#### Scenario: 未登記的表不參與比對

- **WHEN** 直接寫資料庫改動 `asset_authorizations`
- **THEN** 本期的封章、驗證與登入時比對皆不因此回報不符（該表尚未登記），驗證頁的涵蓋範圍只列出 `user_roles`

#### Scenario: 登記一張表即受守衛約束

- **WHEN** 開發者在登記清單新增一張表但未補其快照測試或竄改矩陣列
- **THEN** 守衛測試轉紅並指名缺哪一項

### Requirement: 角色指派快照的正規化

`user_roles` 的快照 SHALL 為全部 `(user_id, role_id)` 對依 user_id、role_id 升冪排序後的固定 canonical 編碼；雜湊 SHALL 為該編碼的長度前綴 SHA-256；快照 SHALL 不含帳號名、電子郵件或任何個資，呈現時再以現行資料換算為帳號名與角色名。

#### Scenario: 同一狀態不同讀取順序得同一雜湊

- **WHEN** 以任意順序讀出同一組角色指派
- **THEN** 快照與雜湊逐位元組相同

#### Scenario: 一筆指派之差即不同雜湊

- **WHEN** 兩組角色指派只差一筆
- **THEN** 雜湊不同，且差集能指出是哪一筆

### Requirement: 角色指派變更同交易留審計列

角色指派的每一條寫入路徑（管理者指派、管理者移除、本地註冊配預設角色、OIDC 首次登入配角色、LDAP 影子帳號建立）SHALL 於同一資料庫交易寫入審計列：資源 `user_role`，動作 `assign` 或 `revoke`，details 含 `user_id`、`role_id` 與來源 `origin`（`api`／`register`／`oidc`／`ldap`／`system`），不含任何秘密。審計列寫入失敗 SHALL 使該次角色變更一併回滾。唯一例外是解封前的初始管理員播種：它發生在完整性基準線之前、沒有蓋章鑰可簽，SHALL NOT 寫審計列（其指派由首個含快照的檢查點作為基準涵蓋），且該路徑 SHALL 只准被播種程序呼叫並由守衛登記。守衛 SHALL 以 AST 確認 `user_roles` 的每個 raw 寫入點都在帶審計的內部函式內。

#### Scenario: 管理者指派角色留痕

- **WHEN** 管理者對某帳號指派 auditor 角色
- **THEN** `user_roles` 多一列，同交易的 `audit_logs` 多一筆資源 `user_role`、動作 `assign`、`origin = api` 的審計列

#### Scenario: OIDC 首登配角色留痕

- **WHEN** 某帳號以 OIDC 首次登入而由系統建號並配角色
- **THEN** 該次角色指派有 `origin = oidc` 的審計列；之後的對帳不將此列判為繞過應用程式的變更

#### Scenario: 審計寫入失敗即回滾

- **WHEN** 指派角色時審計列寫入失敗
- **THEN** `user_roles` 無新列，請求以錯誤結束

### Requirement: 對帳與失效事件

系統 SHALL 提供單一對帳函式：取最近一個含快照**且封章時對帳相符**的檢查點為基準（基準 SHALL 只取簽章載荷涵蓋狀態摘要的檢查點，升級前載荷版本的檢查點即使被補上快照欄亦 SHALL NOT 成為基準；封章時已不符的檢查點 SHALL NOT 成為基準，否則直寫後只需等下一次封章即可讓對帳回相符；升級後首批含快照但尚無對帳結果的檢查點，SHALL 以排在任何不符檢查點之前的最近一個作為涵蓋起點），套用該檢查點之後所有 `user_role` 審計列（assign 加入、revoke 移除）推出預期指派集合，與現況比較，回報預期雜湊、現況雜湊、缺少集合與多出集合。差集非空 SHALL 開一筆審計失效事件（cause `role_state_mismatch`，details 含起算的檢查點序號與差集的 `user_id`／`role_id`），走既有失效通知；同一 `(檢查點序號, 現況雜湊)` SHALL 只開一筆。尚無任何含快照的檢查點時 SHALL 回報「尚未涵蓋」而非不符。對帳 SHALL NOT 更動任何角色指派。

#### Scenario: 直接寫資料庫提權被指出

- **WHEN** 有人以資料庫直寫把某帳號掛上 admin，且該變更沒有對應審計列
- **THEN** 對帳回報現況多出該筆 `(user_id, admin)`，開立 `role_state_mismatch` 事件並發出失效通知，事件指出自哪個檢查點起不符

#### Scenario: 直接寫資料庫移除稽核者被指出

- **WHEN** 有人以資料庫直寫刪除某帳號的 auditor 指派
- **THEN** 對帳回報現況缺少該筆，事件與通知同上

#### Scenario: 合法變更不觸發事件

- **WHEN** 上一檢查點之後所有角色變更皆經 API、註冊或 OIDC 首登發生
- **THEN** 對帳回報相符，不開事件

#### Scenario: 同一不符不重複開單

- **WHEN** 同一筆未經審計的變更在多次登入與驗證中反覆被比對到
- **THEN** 失效事件只有一筆，後續比對回報同一事件

#### Scenario: 封章時不符的檢查點不作基準

- **WHEN** 直寫變更之後系統封了一個檢查點（封章時對帳不符、`role_state_reconciled = false`），其後再執行對帳
- **THEN** 對帳仍回報不符，起算的檢查點序號停在最後一個封章時相符的檢查點

#### Scenario: 升級後首個封章前

- **WHEN** 升級後尚未封過任何含快照的檢查點
- **THEN** 對帳回報「尚未涵蓋」，不開事件，驗證頁標示涵蓋起點待首個封章

### Requirement: 三個比對時機

對帳 SHALL 在以下三處各執行一次：封章時（結果記入該檢查點的 `role_state_reconciled` 並納入簽章）、驗證端點與排程自動驗證時、以及帳號通過身分驗證（密碼、目錄或外部身分）後其有效角色為 admin 或 auditor 且即將簽發權杖時。登入時的比對 SHALL NOT 阻斷登入、SHALL NOT 更動權杖內容；一般使用者登入 SHALL NOT 執行比對。

#### Scenario: 提權者首次登入即被指出

- **WHEN** 某帳號被資料庫直寫掛上 admin 後首次登入
- **THEN** 密碼驗證通過、權杖照常簽發，同時開立 `role_state_mismatch` 事件並發出通知；該次登入的審計列可與事件對得上時間

#### Scenario: 一般使用者登入不比對

- **WHEN** 有效角色為 user 的帳號登入
- **THEN** 不執行對帳，登入路徑無額外查詢

#### Scenario: 封章記錄對帳結果

- **WHEN** 封章時對帳不符
- **THEN** 該檢查點仍照現況封章，`role_state_reconciled = false` 進簽章載荷，事件照開

### Requirement: 驗證頁與端點的呈現

檢查點驗證端點 SHALL 回傳角色指派維度：`covered`（是否已有含快照的檢查點）、`state`（`match`／`mismatch`／`not_covered`）、`since_seq`、`missing`／`extra`（以帳號名與角色名呈現）、最近一筆相關失效事件。驗證頁 SHALL 於涵蓋範圍區顯示「角色指派」一列，不符時以醒目狀態呈現差集並連結失效事件；文案 SHALL 以稽核可讀的語言撰寫，三語齊備。

#### Scenario: 驗證頁指出差異

- **WHEN** 稽核人員開啟驗證頁且對帳不符
- **THEN** 看到「角色指派：自檢查點 #N 起不符」、差集的帳號與角色名，以及失效事件連結；相符時顯示「相符（涵蓋至檢查點 #M）」

