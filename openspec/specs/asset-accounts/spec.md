# asset-accounts Specification

## Purpose

資產多帳號能力：一資產多系統帳號的模型與預設帳號語義、資產建立時於同一交易產生預設帳號的
寫入路徑不變式、加密欄位入冊信封加密盤點清單的安全約束、帳號操作審計、連線時的帳號選擇與
會話帳號快照，以及系統路徑（改密輪替）的憑證寫入不變式與未驗證狀態語義。
## Requirements
### Requirement: 資產多帳號模型
資產 SHALL 支援多個系統帳號（各自憑證加密存放，適用 ssh/rdp/vnc/mysql/postgres/redis/**mssql**；
k8s 固定單一預設帳號）；資產建立時若帶 username 或憑證，SHALL 於同一交易建立其預設帳號，
且憑證密文 SHALL 僅落 `asset_accounts`；每資產 SHALL 至多一個預設帳號（DB 索引強制），
且有帳號時必有預設帳號（服務層交易維護）。

帳號的產生 SHALL 由寫入路徑承擔，SHALL NOT 依賴任何一次性的存量搬移步驟——
schema 由單一 baseline 定義，不存在「先以內嵌欄位建立、再由後續遷移複製為帳號列」的過渡形態。

#### Scenario: 建立資產即產生預設帳號
- **WHEN** admin 建立帶 username 與憑證的資產
- **THEN** 同一交易內出現一筆 IsDefault 帳號、憑證密文只存在於 `asset_accounts`；不帶 username 且不帶憑證的資產零帳號

#### Scenario: 預設帳號不可懸空
- **WHEN** 刪除唯一的預設帳號而資產仍有其他帳號
- **THEN** 操作被拒或自動遞補預設，不出現「有帳號無預設」狀態

#### Scenario: mssql 資產支援多帳號
- **WHEN** 對 mssql 資產建立第二個帳號
- **THEN** 建立成功，連線時可指定使用該帳號，憑證與 username 同取自該帳號

### Requirement: 帳號加密欄位入冊
`asset_accounts` 的加密欄位 SHALL 與 model 同版登記於信封加密盤點清單
（envelopeMigrationTargets），使 DEK 輪替重加密與退役金鑰銷毀前引用掃描涵蓋新表。

#### Scenario: 退役金鑰引用掃描
- **WHEN** 清理退役 DEK 版本前執行引用掃描
- **THEN** asset_accounts 密文被計入引用，仍被引用的金鑰材料不被銷毀

### Requirement: 帳號操作審計
帳號建立、更新、刪除與預設切換 SHALL 產生審計記錄；審計內容 SHALL NOT 含密文或明文憑證。

#### Scenario: 憑證更新留痕
- **WHEN** 管理員更新某帳號密碼
- **THEN** 審計記錄包含操作者、資產、帳號 username 與時間，不含任何憑證內容

### Requirement: 連線選帳號
多帳號資產連線時使用者 SHALL 能自其有效授權帳號中選擇；有效帳號僅一個時 SHALL
直接連線；connect-token SHALL 綁定所選帳號。

#### Scenario: 多帳號選擇
- **WHEN** 對含 root 與 app 兩帳號（均在授權範圍）的資產發起連線
- **THEN** 顯示帳號選擇（預設帳號預選），以所選帳號憑證建線，session 記錄該帳號

#### Scenario: 會話審計雙快照
- **WHEN** 連線建立後帳號被改名或刪除
- **THEN** 該 session 的帳號 ID 與連線當下 username 快照不變

### Requirement: 系統路徑的帳號憑證寫入面

系統路徑（改密輪替）SHALL 能更新帳號的密碼與**私鑰**兩種憑證欄位。兩者 SHALL 走同一組
不變式：以釘住的 AccountID 為目標（SHALL NOT 於寫入時重新解析預設帳號）、於交易內取列鎖、
目標帳號不存在即失敗（SHALL NOT 靜默改到其他帳號），並於同一交易內寫入審計。

審計 SHALL 只記被更動的欄位名稱（`password`／`private_key`），SHALL NOT 記錄任何憑證內容；
系統路徑的操作者 SHALL 記為系統身分。

#### Scenario: 私鑰輪替留痕

- **WHEN** 改密以 SSH 金鑰型別更新某帳號私鑰
- **THEN** 審計記錄含資產、帳號 username 與欄位名 `private_key`，不含任何金鑰材料

#### Scenario: 目標帳號不存在即失敗

- **WHEN** 系統路徑以某 AccountID 寫入憑證，而該帳號在此期間已被刪除
- **THEN** 寫入失敗並回報錯誤，SHALL NOT 退回改寫預設帳號

### Requirement: 帳號憑證的未驗證狀態

帳號憑證處於「未驗證」狀態 SHALL 定義為「該帳號存在未驗證的候選憑證列」
（見 `change-secret`），SHALL NOT 於 `asset_accounts` 另設會與之漂移的狀態欄位。

未驗證狀態下，`asset_accounts` 所存的憑證 SHALL 維持為輪替前的舊憑證——連線與其他讀取路徑
SHALL 繼續使用它，直到候選被驗證成功並提交。

#### Scenario: 未驗證期間連線用舊憑證

- **WHEN** 某帳號的新秘密尚未驗證成功
- **THEN** 連線路徑讀到的仍是舊憑證，SHALL NOT 讀到任何候選秘密

### Requirement: 憑證群組

資產帳號 SHALL 持有可為空的「憑證群組」識別：同群組代表系統已知這些帳號使用同一組憑證。
以「從其他資產帳號複製」建立帳號時，系統 SHALL 於同一交易內使來源帳號與新帳號歸於同一群組（來源無群組時先為其產生群組識別）。
任一帳號經系統改密成功並提交新憑證時，系統 SHALL 使該帳號脫離群組；脫離後群組只剩一個成員時，該成員 SHALL 一併脫離。
管理者手動編輯憑證 SHALL NOT 改變群組（系統無從判定手動輸入的憑證是否仍共用），此邊界 SHALL 於文件明載。

群組識別 SHALL NOT 出現於一般帳號列表以外的任何憑證路徑；報告與帳號列表 SHALL 只以「共用憑證」布林呈現，SHALL NOT 揭露群組識別本身。
本能力引入前已存在的複製建號關係 SHALL NOT 回溯補登，文件 SHALL 明載此邊界。

#### Scenario: 複製建號歸組

- **WHEN** 以帳號甲為來源複製建立帳號乙
- **THEN** 甲與乙的憑證群組相同且非空，兩者於報告皆標示共用憑證

#### Scenario: 改密脫組

- **WHEN** 甲、乙、丙同群組，乙改密成功
- **THEN** 乙群組為空；甲與丙仍同群組

#### Scenario: 剩一人即解散

- **WHEN** 甲、乙同群組，乙改密成功
- **THEN** 甲與乙的群組皆為空，兩者皆不再標示共用憑證

#### Scenario: 手動編輯不動群組

- **WHEN** 管理者手動修改同群組帳號甲的密碼
- **THEN** 甲的群組不變
