# access-request

## Purpose

連線申請與核准流：申請提出/去重/撤回/超時作廢、核准於同一交易產生時窗內臨時授權、`reason` 段位自動核准、approver 可疊加角色與審核範圍（審核方個人 XOR 群組 × 客體四維、群組即資格、自核硬擋、admin 非審核者）、最少核准人數 quorum（逐票記錄、兼具 admin 身分者不單票繞過）、審核範圍矩陣總覽頁、「我的申請」自助頁與審核中心事件通知。
## Requirements
### Requirement: 申請提出與去重
使用者 SHALL 能對政策段位非 `open` 且可視的資產提出連線申請：事由必填、時長必填且 SHALL NOT 超過政策上限、可預約起始時間（空＝立即）。同一申請人對同一資產 SHALL 僅允許一張 pending 在途單，重複申請 SHALL 被拒（409）並回在途單識別。申請動作 SHALL 入審計。

#### Scenario: 提出申請
- **WHEN** 使用者對 `approval` 段位資產提交事由與時長（≤上限）
- **THEN** 建立 pending 申請單，審核範圍命中的 approver 於審核中心可見

#### Scenario: 超過時長上限
- **WHEN** 申請時長超過政策上限
- **THEN** 回 400 並提示上限值，不建單

#### Scenario: 重複申請被擋
- **WHEN** 同人對同資產已有 pending 單再次申請
- **THEN** 回 409 並帶既有單識別，不建新單

#### Scenario: 預約起始時間
- **WHEN** 申請帶未來起始時間（維護窗）且獲核准
- **THEN** 臨時授權 date_start 為預約時刻，未達時刻前連線判定不命中

### Requirement: 核准與臨時授權
審核範圍命中的**有效審核者** SHALL 能核准/拒絕 pending 申請；`admin` 角色本身 SHALL NOT 構成審核資格（見「approver 角色與審核範圍」）。系統 SHALL 支援最少核准人數政策（`access_request_min_approvals`，預設 1）：每筆核准 SHALL 逐筆記錄（同單同人 SHALL NOT 重複核准，含兼具 admin 身分的審核者），核准數達政策門檻的該筆核准才 SHALL 轉 approved 並於同一交易產生臨時授權（申請人×資產×connect、時效窗寫入授權時效欄位、來源標記核准流）並回填申請單關聯；未達門檻時單 SHALL 保持 pending 且回應與通知 SHALL 帶「已核准 n/N」進度。兼具 admin 身分之有效審核者的核准 SHALL 計為一票、SHALL NOT 單票繞過門檻（雙人完整性）；門檻為 1 時行為 SHALL 與單人核准完全一致。最終轉態的核准人 SHALL 可下修時長與推遲起始時間，SHALL NOT 上調超過申請值或政策上限；拒絕 SHALL 為任一具資格者即拒（rejected 終態，事由必填，已存在的部分核准記錄留存供審計）。政策值 SHALL 於每次核准時讀取（調低即時生效於下一票；調高 SHALL NOT 回溯已 approved 單）。填理由自動核准與破窗 SHALL NOT 受門檻約束。時窗內 SHALL 可多次連線；到期 SHALL 以「解析不命中」擋新連線、SHALL NOT 硬斷既有連線；每筆核准/拒絕 SHALL 入審計。

#### Scenario: 核准後可連線
- **WHEN** 門檻 1 且 approver 核准一張 pending 申請
- **THEN** 產生時窗內臨時授權，申請人可於時窗內多次取得 connect-token；申請單狀態為 approved 且關聯授權可查

#### Scenario: 兩人門檻逐票推進
- **WHEN** 門檻 2，第一位 approver 核准
- **THEN** 單保持 pending、記錄該票且回應帶「已核准 1/2」；第二位（不同人）核准後才轉 approved 並產生臨時授權

#### Scenario: 同人重複核准被拒
- **WHEN** 門檻 2，同一 approver 對同單第二次核准
- **THEN** 回明確錯誤（已核准過此單），計票不變

#### Scenario: 無審核資格的 admin 不可核准
- **WHEN** 僅具 `admin` 角色（未被指派 `approver`、不屬任何審核方群組）者對 pending 單執行核准或拒絕
- **THEN** 回 403（需審核資格），單不受影響、不計票

#### Scenario: 兼具 admin 身分者不單票繞過門檻
- **WHEN** 門檻 2，兼具 admin 與有效審核資格者對無任何核准記錄的單執行核准
- **THEN** 單保持 pending（1/2）；其票與其他審核者的票等值，需第二位不同人補齊

#### Scenario: 任一人拒絕即拒
- **WHEN** 門檻 2 且已有一票核准，另一位具資格者拒絕
- **THEN** 單轉 rejected 終態（含決定者與事由）；已存在的核准記錄留存於審計軌跡

#### Scenario: 核准人下修時長
- **WHEN** 申請 8 小時、最終轉態的核准人改為 2 小時
- **THEN** 臨時授權時窗為 2 小時，申請單記錄核准值與原申請值

#### Scenario: 上調被拒
- **WHEN** 核准人嘗試將時長調高於申請值
- **THEN** 回 400，核准不生效

#### Scenario: 到期擋新連線不硬斷
- **WHEN** 臨時授權到期時該使用者仍有進行中連線
- **THEN** 新的 connect-token 申請被政策閘攔截，既有連線不被強制斷開；授權記錄留存可查

#### Scenario: 拒絕留痕
- **WHEN** approver 拒絕申請並填事由
- **THEN** 申請單狀態 rejected、含決定者與事由，申請人於自助視圖可見

#### Scenario: 併發兩票僅一次授權
- **WHEN** 門檻 2 且兩位 approver 同時核准（第 2、3 票並發到達）
- **THEN** 臨時授權僅產生一次；後到者收到明確衝突或冪等回應，SHALL NOT 出現雙授權

### Requirement: 填理由即過自動核准
政策段位 `reason` 之資產，申請 SHALL 走與強制審核相同的表單與資料軌，並 SHALL 被即時自動核准（決定者記 system、帶自動核准標記），當場產生臨時授權；審核中心與申請歷史 SHALL 可辨識自動核准單。

#### Scenario: 填理由即連
- **WHEN** 使用者對 `reason` 段位資產提交事由與時長
- **THEN** 申請即時轉 approved（決定者 system）、臨時授權立即生效，使用者當場可連線

#### Scenario: 自動核准可辨識
- **WHEN** approver 於審核中心檢視歷史
- **THEN** 自動核准單帶明確標記，與人工核准單可區分

### Requirement: 撤回與超時作廢
申請人 SHALL 能撤回自己的 pending 申請（cancelled 終態、入審計）；pending 超過政策時限 SHALL 自動作廢（expired）。全部狀態轉移 SHALL 原子——併發的核准/拒絕/撤回/超時僅一方成立，SHALL NOT 復活終態。

#### Scenario: 申請人撤回
- **WHEN** 申請人對自己的 pending 單執行撤回
- **THEN** 狀態轉 cancelled、入審計；該單不再出現在待審列表

#### Scenario: 超時自動作廢
- **WHEN** pending 單超過政策時限
- **THEN** 狀態轉 expired，申請人可重新申請（去重僅擋 pending）

#### Scenario: 併發決定僅一方成立
- **WHEN** approver 核准與申請人撤回同時發生
- **THEN** 僅先完成者成立，後到方收到明確衝突回應，不產生「已撤回卻有授權」的分裂狀態

### Requirement: approver 角色與審核範圍
`approver` SHALL 為可疊加角色：SHALL NOT 改變既有有效角色判定（admin>auditor>user）與既有端點權限，僅授予審核職能。審核範圍 SHALL 以「審核方 × 客體」分配（admin only 管理且入審計）：審核方＝個人 XOR 使用者群組（審核方群組），客體＝資產 XOR 節點 XOR 申請人 XOR 申請人群組，兩軸全交叉有效。節點範圍 SHALL 以「節點含子樹」語義生效（範圍命中＝申請資產直配或掛於範圍節點及其後代，新資產掛入即時被涵蓋）；申請人側範圍 SHALL 以「申請人本人或其所屬使用者群組成員」語義生效；審核方群組 SHALL 以「操作者屬於該群組」語義生效——以上成員異動皆即時反映（無快取）。

審核資格 SHALL 為：具 `approver` 角色 **OR** 屬於任一審核方群組（群組即資格——入組即可審、離組即失效）；端點守衛與審核中心入口/badge 判定 SHALL 依此即時判定，且 SHALL 為**單一實作來源**——守衛、入口旗標與列表過濾 SHALL 得出一致結論。**`admin` 角色本身 SHALL NOT 構成審核資格**：管理員 SHALL 明確被指派 `approver` 角色或納入審核方群組後方得審核（職責分離——管理員自行指派權限又自行核准特權存取不可接受）。核准資格＝〔資產側範圍命中 OR 申請人側範圍命中〕且操作者為該範圍條目的審核方（個人本人或群組成員）。自核 SHALL 硬性禁止：申請人 SHALL NOT 核准自己的申請——**即使申請人屬於命中的審核方群組亦一律 403**；範圍內唯一可審者即申請人本人時，該單僅其他具資格者可核（不死鎖）。資產/節點範圍 SHALL 隱含範圍內資產的 view 可視（個人與群組成員同語義；SHALL NOT 隱含連線權）；申請人側範圍 SHALL NOT 隱含任何資產可視（僅影響待審路由）。範圍命中判定 SHALL 單一實作來源：單筆資格判定與待審/歷史/有效授權列表過濾 SHALL 得出一致結論（SHALL NOT 出現列表可見但決定被拒的分裂）。

**管理路徑不得死鎖（硬性）**：指派/移除 `approver` 角色（使用者管理）與建立/移除審核範圍（審核範圍管理）SHALL 僅要求 **admin 權限**、SHALL NOT 要求審核資格、SHALL NOT 受審核端點守衛約束；即使系統中有效審核者為零，這兩條路徑 SHALL 仍然可用，使 admin 永遠能重建可審池。指派 SHALL 即時生效（無快取、無 token 殘窗）。無任何審核範圍命中之申請 SHALL 為「無人可核」而非由 admin 兜底放行——此涵蓋缺口 SHALL 於審核範圍總覽頁可視化（可審人數 0 或低於門檻即警告，涵蓋面以下方明載缺口為界），並由 admin 補建範圍解除；申請本身仍受既有 pending 逾時作廢保護。

系統 SHALL 提供 admin 專屬審核範圍總覽頁（`/approver-scopes`，身分與權限組），雙視角：
- **按資產/節點**（預設）：**列舉起點為節點樹與已有直配範圍的資產**——節點樹逐列顯示審核方（個人＋群組）與可審人數（含繼承與群組成員展開、去重），可審人數低於最少核准人數門檻時 SHALL 標示警告；申請人側路由條目不綁資產，SHALL 於同視角獨立區塊列出。
  **明載缺口（未實作）**：本視角**不以資產全集為起點**，故「未隸屬任何節點 ∧ 零直配範圍」的資產不會被列舉，也就不受上述警告涵蓋——而那正是「零有效審核者」最深的一格。管理員目前 SHALL NOT 倚賴本頁作為該類資產的唯一發現途徑。修法（改以資產全集為起點列舉）屬獨立產品工作，**本規格 SHALL NOT 被解讀為該能力已存在**。
- **按審核人員**：個人與群組審核方皆成列 × 四客體欄的矩陣，格內可移除、格內可就地新增（人與類型預選）。

頁面 SHALL 提供一站式新增：審核方選個人（清單排除 admin 與 auditor；未具 approver 角色者標註並於確認後自動先分配角色再建範圍，兩步各自入審計；角色已分配而範圍建立失敗時 SHALL 誠實提示且 SHALL NOT 自動回滾角色）或選群組（零代配）。移除範圍 SHALL NOT 自動移除 approver 角色。總覽頁與使用者管理列內對話框 SHALL 以一致文案明示範圍語義；節點類範圍選項 SHALL 顯示節點全路徑（同名節點可分辨）。

#### Scenario: 範圍外不可核
- **WHEN** approver 對「資產側與申請人側範圍皆未命中」之申請執行核准
- **THEN** 回 403，單不受影響

#### Scenario: 節點範圍含子樹
- **WHEN** approver 的審核範圍配節點 prod，申請資產掛於 prod/kafka
- **THEN** 該 approver 可核此申請；資產自 prod 子樹移除（且無直配）後即不可核

#### Scenario: 使用者群組範圍命中
- **WHEN** approver 的審核範圍配使用者群組 SRE，SRE 成員對任一資產提出申請
- **THEN** 該單出現在此 approver 的待審列表且其可核准/拒絕；該成員退出 SRE 後的新申請即不再命中

#### Scenario: 特定申請人範圍命中
- **WHEN** approver 的審核範圍配使用者 alice
- **THEN** alice 的申請（不論資產）命中該 approver 的資格與待審列表

#### Scenario: 申請人側不隱含可視
- **WHEN** approver 僅有申請人側範圍（無資產側），範圍內成員對資產 A 提出申請
- **THEN** 該單出現在其待審列表（含資產快照資訊）；資產 A SHALL NOT 因此出現在其資產列表

#### Scenario: 自核硬擋
- **WHEN** 同時具 approver 身分的申請人對自己的申請執行核准（含其為範圍內唯一 approver 的情境）
- **THEN** 一律 403；該單仍可由其他具資格且範圍命中者決定

#### Scenario: admin 非審核者
- **WHEN** 僅具 `admin` 角色者開啟審核端點或執行核准/拒絕
- **THEN** 一律回 403（需審核資格）；被指派 `approver` 角色或納入審核方群組後即刻具資格

#### Scenario: 零審核者時 admin 脫困路徑可用
- **WHEN** 系統中有效審核者為零，且操作者僅具 `admin` 角色（無 approver、不屬任何審核方群組）
- **THEN** 其仍可成功指派 `approver` 角色並建立審核範圍（皆回 2xx，皆入審計）；被指派者即刻成為有效審核者並可核准範圍命中的申請

#### Scenario: 範圍隱含可視不含連線
- **WHEN** approver 的資產側審核範圍含資產 A 但其對 A 無任何授權
- **THEN** A 出現在其資產列表（view 語義）；其對 A 申請 connect-token 仍被授權檢查拒絕

#### Scenario: 審核方群組命中即可審
- **WHEN** 節點 prod/db 配了審核方群組 DBA，DBA 成員（不具 approver 角色）登入
- **THEN** 其可見審核中心入口、prod/db 子樹資產的申請出現在其待審列表且可核准；其退出 DBA 群組後即失去資格與入口

#### Scenario: 群組成員不得自審
- **WHEN** DBA 成員對 prod/db 資產提出申請，而 DBA 群組是該節點的審核方
- **THEN** 該成員對自己的申請核准一律 403，待審列表亦不顯示自己的單；其他 DBA 成員可正常核准

#### Scenario: 刪除群組連動清理審核範圍
- **WHEN** admin 刪除一個作為審核方或申請人群組的使用者群組
- **THEN** 掛該群組的審核範圍（approver_group_id 或 subject_group_id）連動軟刪，殘留成員不再具審核資格；不留 approver_group=null 的幽靈範圍

#### Scenario: 刪除使用者連動清理審核範圍與成員關係
- **WHEN** admin 刪除一個作為個人審核方或申請人的使用者
- **THEN** 掛該使用者的審核範圍（approver_id 或 subject_user_id）連動軟刪，其群組成員關係一併清除

#### Scenario: 池不足時以擴充可審池解除
- **WHEN** 門檻 2 且某申請的可審池僅 1 人，該人已投一票
- **THEN** 單保持 pending（1/2）；admin SHALL NOT 以 admin 身分投第二票，SHALL 以指派 approver 角色或補建審核範圍擴充可審池，由第二位有效審核者補齊

#### Scenario: 一站式新增（個人代配角色）
- **WHEN** admin 於總覽頁新增範圍並選擇未具 approver 角色的一般使用者，確認代配提示
- **THEN** 系統先分配 approver 角色再建立範圍（兩步各自入審計）；選擇已具角色者則直接建立；審核方選擇群組時不做任何角色變動

#### Scenario: 涵蓋缺口可視化（限已列舉的節點與直配資產）
- **WHEN** admin 於「按資產/節點」視角檢視，某**已列舉**節點的可審人數（含繼承與群組展開去重）低於最少核准人數門檻
- **THEN** 該列顯示警告標示；可審人數為 0 的節點明確可辨

#### Scenario: 未分組且零範圍的資產不在本頁列舉（已知缺口）
- **WHEN** 某資產既不隸屬任何節點、亦無任何直配審核範圍
- **THEN** 本頁不列出該資產，亦不對它發出涵蓋缺口警告——此為明載的未實作缺口，SHALL NOT 以「已可視化」表述

#### Scenario: 矩陣總覽頁
- **WHEN** admin 開啟 `/approver-scopes`
- **THEN** 預設「按資產/節點」視角，可切「按審核人員」矩陣（個人與群組皆成列、四維可辨識、節點帶全路徑）、可新增與移除範圍，且頁面明示範圍語義說明；非 admin 直達被路由守衛拒絕

#### Scenario: 單筆與列表結論一致
- **WHEN** 任一申請單出現在某具資格者的待審列表
- **THEN** 其對該單執行核准/拒絕不因範圍判定被拒（403 僅來自自核禁止或單已終態）

### Requirement: 我的申請自助頁
系統 SHALL 提供申請人**獨立的**「我的申請」功能頁（與「我的連線」分離——每角色功能頁單獨切開、降低頁面功能耦合）：呈現呼叫者**自己**的申請單（pending 與歷史決定，含狀態、資產、時長、決定者與事由）與有效臨時授權（時窗起迄）；pending 列 SHALL 提供撤回操作（二次確認）。導覽 SHALL 對一般使用者顯示獨立入口。資料 SHALL owner-scoped（以 JWT user_id 過濾，SHALL NOT 接受 client 傳入的使用者參數），SHALL NOT 呈現他人申請。

#### Scenario: 獨立頁與入口
- **WHEN** 一般使用者登入且有一張 pending 單與一筆時窗內臨時授權
- **THEN** 導覽顯示獨立的「我的申請」入口，頁面呈現該申請狀態與臨時授權時窗；「我的連線」頁不含申請內容（兩功能頁不耦合）

#### Scenario: 自助撤回
- **WHEN** 使用者在「我的申請」頁對自己的 pending 單點撤回並確認
- **THEN** 該單轉 cancelled 且列表刷新；已決定的單無撤回操作

#### Scenario: 無法檢視他人申請
- **WHEN** 使用者請求附帶他人識別參數
- **THEN** 參數被忽略，回應仍僅限本人資料

### Requirement: 審核中心與事件通知
系統 SHALL 提供審核中心（**有效審核者**可入——具 `approver` 角色 OR 屬任一審核方群組；`admin` 角色本身 SHALL NOT 構成進入資格）：待審（依審核範圍過濾）、歷史、有效臨時授權三視圖；導航 SHALL 對有效審核者顯示待審計數。進入資格判定 SHALL 與端點守衛同一來源，SHALL NOT 出現「看得到入口卻被端點拒絕」或「端點放行卻無入口」的分裂。申請建立/核准/拒絕事件 SHALL 廣播至既有通知通道，payload SHALL 最小化（單號、資產名、事件類型、連結；SHALL NOT 含事由全文）；送達保證為「盡力外送＋審核中心必見」（通道未配置時不阻斷流程）。管理員對申請流的全域檢視 SHALL 經既有 admin 專屬頁面（審核範圍總覽、授權管理與審計）取得，SHALL NOT 依賴審核中心。

#### Scenario: 待審依範圍過濾
- **WHEN** approver 開啟審核中心待審視圖
- **THEN** 僅見審核範圍命中的 pending 單

#### Scenario: 入口與端點判定一致
- **WHEN** 僅具 `admin` 角色者登入
- **THEN** 導航不顯示審核中心入口，且其直接呼叫審核端點亦回 403（兩者結論一致）

#### Scenario: 待審計數
- **WHEN** approver 登入且範圍內有 pending 單
- **THEN** 導航入口顯示待審計數

#### Scenario: 通知內容最小化
- **WHEN** 申請建立且已配置通知通道
- **THEN** 出站 payload 含單號/資產名/事件類型/連結，不含事由全文

### Requirement: 臨時授權提前撤銷
系統 SHALL 支援對仍有效的臨時授權（ticket 來源）提前撤銷。撤銷資格：一般核准單＝admin OR 該單原核准人；自動核准單與破窗單（無真人核准人）＝admin OR 範圍命中的 approver。撤銷 SHALL 於同一交易內軟刪票證授權（CAS，先到者贏）並在申請單上記錄 revoked_at/revoked_by/revoke_note——申請單狀態機 SHALL NOT 新增終態（approved 維持，附註欄非狀態轉移）。撤銷後權限判定即刻不命中（擋新連線）、資產連線入口的伺服端標註自然回落；撤銷 SHALL 入審計並通知申請人側可見。

#### Scenario: 原核准人撤銷
- **WHEN** 核准人 P 對自己核准且票證仍有效的單發起撤銷（附事由）
- **THEN** 票證即刻失效、單附註撤銷資訊，申請人在「我的申請」看到「已提前撤銷」與事由

#### Scenario: 非原核准人的 approver 不可撤一般單
- **WHEN** 範圍命中但非原核准人的 approver 嘗試撤銷一般核准單
- **THEN** 403 拒絕（一般單資格限 admin＋原核准人）

#### Scenario: 自動核准單放寬資格
- **WHEN** 範圍命中的 approver 對 reason 段位自動核准單（決定者 system）發起撤銷
- **THEN** 撤銷成功

#### Scenario: 撤銷後擋新連線
- **WHEN** 票證被撤後使用者對該資產申請 connect-token
- **THEN** 政策閘攔截（與無票證時行為一致），資產入口回「申請連線」

#### Scenario: 並發撤銷先到者贏
- **WHEN** admin 與原核准人同時對同一票證發起撤銷
- **THEN** 恰一方成功、另一方收到已撤銷回應（409），無雙重審計

#### Scenario: 已到期票證不可撤
- **WHEN** 對票證已自然到期的單發起撤銷
- **THEN** 409 拒絕（無有效票證可撤，到期與撤銷語義分離）

### Requirement: 撤銷斷線聯動
安全政策鍵 `access_revoke_disconnect` 預設 false：撤銷僅擋新連線、不中斷進行中會話（與到期語義一致）。設為 true 時，撤銷 SHALL 於交易提交後終止該使用者×該資產的全部 active 會話（`end_reason='revoked'`，沿既有終止語義含 CAS 競態安全）；個別會話收線失敗 SHALL NOT 回滾撤銷（票證失效為主要目標，殘餘記日誌）。

#### Scenario: 預設不硬斷
- **WHEN** `access_revoke_disconnect=false` 且使用者正以票證連線中，票證被撤
- **THEN** 進行中會話不中斷；斷線後無法再建新連線

#### Scenario: 政策開啟即斷線
- **WHEN** `access_revoke_disconnect=true` 且使用者正以票證連線中，票證被撤
- **THEN** 該使用者對該資產的 active 會話被終止、`end_reason='revoked'`，會話記錄完整落庫

#### Scenario: 收線失敗不回滾
- **WHEN** 政策開啟、撤銷時某會話的連線通道寫入失敗
- **THEN** 撤銷仍生效（票證已軟刪），失敗記日誌供人工跟進

### Requirement: 申請單類別欄
申請單 SHALL 帶 `kind` 欄（`normal`／`break_glass`），未指定時 SHALL 由欄位預設值取得 `normal`，SHALL NOT 依賴任何一次性回填步驟；破窗單 SHALL 與一般單同軌進入歷史查詢與審計，且在歷史與「我的申請」中可辨識為破窗單。待審列表語義不變（破窗單非 pending 不入待審）。

#### Scenario: 歷史可辨識破窗單
- **WHEN** approver 於審核中心歷史頁檢視
- **THEN** 破窗單帶可辨識標記，與一般核准、自動核准區分

#### Scenario: 未指定類別即為一般單
- **WHEN** 以未帶 `kind` 的請求建立申請單並查詢之
- **THEN** `kind='normal'`，其行為與一般申請單完全一致

