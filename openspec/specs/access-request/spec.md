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

頁面 SHALL 提供建立多資產申請的入口。申請單 SHALL 以「單」為列、其項目可展開：列摘要 SHALL 呈現項目數與整單狀態，展開後每項 SHALL 呈現資產、帳號範圍與該項狀態（待審／已核准／已拒絕／已撤銷）。單項被拒或被撤 SHALL NOT 呈現為整單失效。

申請單 SHALL 呈現其任務 id（即申請單 id），且 SHALL 可由已核准的單進入該任務的檢視。

#### Scenario: 獨立頁與入口
- **WHEN** 一般使用者登入且有一張 pending 單與一筆時窗內臨時授權
- **THEN** 導覽顯示獨立的「我的申請」入口，頁面呈現該申請狀態與臨時授權時窗；「我的連線」頁不含申請內容（兩功能頁不耦合）

#### Scenario: 自助撤回
- **WHEN** 使用者在「我的申請」頁對自己的 pending 單點撤回並確認
- **THEN** 該單轉 cancelled 且列表刷新；已決定的單無撤回操作

#### Scenario: 無法檢視他人申請
- **WHEN** 使用者請求附帶他人識別參數
- **THEN** 參數被忽略，回應仍僅限本人資料

#### Scenario: 逐項狀態可展開
- **WHEN** 使用者檢視一張三項中一項被拒的已決定單
- **THEN** 列摘要顯示項目數與整單狀態，展開可見三項各自的資產、帳號範圍與狀態，被拒的一項不使另兩項顯示為失效

### Requirement: 審核中心與事件通知
系統 SHALL 提供審核中心（**有效審核者**可入——具 `approver` 角色 OR 屬任一審核方群組；`admin` 角色本身 SHALL NOT 構成進入資格）：待審（依審核範圍過濾）、歷史、有效臨時授權三視圖；導航 SHALL 對有效審核者顯示待審計數。進入資格判定 SHALL 與端點守衛同一來源，SHALL NOT 出現「看得到入口卻被端點拒絕」或「端點放行卻無入口」的分裂。申請建立/核准/拒絕事件 SHALL 廣播至既有通知通道，payload SHALL 最小化（單號、資產名、事件類型、連結；SHALL NOT 含事由全文）；送達保證為「盡力外送＋審核中心必見」（通道未配置時不阻斷流程）。管理員對申請流的全域檢視 SHALL 經既有 admin 專屬頁面（審核範圍總覽、授權管理與審計）取得，SHALL NOT 依賴審核中心。

待審視圖 SHALL 支援逐項決定：審核者 SHALL 可對單內每項各自核准、拒絕或刪除，並 SHALL 可對核准的項下修**時長、起始與帳號範圍**；
帳號範圍的可選值 SHALL 收斂為該項申請範圍的子集（申請為全部帳號者 SHALL 可收成具體清單，反向 SHALL NOT 可選）。
介面 SHALL NOT 提供上調選項（超出申請範圍的值不可選）。審核範圍未命中的項 SHALL 呈現為不可決定並說明原因，SHALL NOT 隱藏該項。

送出 SHALL 於同一層級完成並在送出前呈現逐項決定摘要（哪幾項核准、哪幾項下修成什麼、哪幾項拒絕或刪除）。送出後部分項失敗時，介面 SHALL 逐項回報結果，SHALL NOT 以單一成功或失敗訊息概括。

送出成功的項 SHALL 以**後端回傳的狀態**寫回該項，改以已決定的樣態呈現，SHALL NOT 續留可再次選擇的決定控件；待審佇列與導航待審計數 SHALL 於同一次操作後一併更新，SHALL NOT 出現同一畫面上兩個互相矛盾的待審數字。

逐項決定的入口 SHALL 可由鍵盤操作（可聚焦、可按下），SHALL NOT 僅能以滑鼠點擊展開。逐項單頭 SHALL 呈現申請人與代表關係（自主執行者明示無代表人）。項目的資產名稱不可讀時 SHALL 明說無法讀取並保留資產識別碼，SHALL NOT 以裸識別碼冒充名稱。

申請人或執行者為 agent 主體的單，待審與歷史視圖 SHALL 標示主體類型與其負責人。

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

#### Scenario: 逐項下修不可上調
- **WHEN** approver 對申請 240 分鐘的一項調整時長
- **THEN** 可選值不超過 240 分鐘；帳號範圍同理只能縮小到申請範圍的子集

#### Scenario: 全部帳號的項可收成具體清單
- **WHEN** approver 對一項申請範圍為全部帳號的項調整帳號範圍
- **THEN** 可選值為該資產上的帳號清單（下修為子集）；選定後 SHALL NOT 能再改回全部帳號

#### Scenario: 範圍外的項可見但不可決定
- **WHEN** 一張兩項的單中只有一項落在該 approver 的審核範圍
- **THEN** 另一項仍呈現於畫面但不可決定，並說明因不在其審核範圍

#### Scenario: 送出前摘要與逐項回報
- **WHEN** approver 對三項分別核准、下修、拒絕後送出，其中一項後端失敗
- **THEN** 送出前呈現三項決定摘要；送出後逐項回報結果，成功的兩項與失敗的一項分別可辨

#### Scenario: 送出後畫面與計數同步

- **WHEN** approver 對一項送出核准且後端回傳該項已核准
- **THEN** 該項改以已核准樣態呈現且不再提供決定控件，待審佇列重新讀取，導航待審計數同步更新

#### Scenario: 展開可由鍵盤操作

- **WHEN** approver 以 Tab 移動到某張待審單的展開入口並按下 Enter
- **THEN** 該單的逐項審核區域展開，不需使用滑鼠

#### Scenario: agent 申請單可辨識
- **WHEN** approver 檢視一張由 agent 主體提出的待審單
- **THEN** 申請人處標示其為 AI agent 並可見其負責人

### Requirement: 臨時授權提前撤銷
系統 SHALL 支援對仍有效的臨時授權（ticket 來源）提前撤銷，撤銷範圍 SHALL 可為整單或單一任務項。撤銷資格：一般核准單＝admin OR 該單原核准人；自動核准單與破窗單（無真人核准人）＝admin OR 範圍命中的 approver。撤銷 SHALL 於同一交易內軟刪該範圍的票證授權（CAS，先到者贏）並在申請單／任務項上記錄 revoked_at/revoked_by/revoke_note——申請單狀態機 SHALL NOT 新增終態（approved 維持，附註欄非狀態轉移）。撤銷後權限判定即刻不命中（擋新連線）、資產連線入口的伺服端標註自然回落；撤銷 SHALL 入審計並通知申請人側可見。

**對既有會話的效力**：由 agent 主體執行的會話（執行主體 `kind='agent'`）SHALL 於撤銷交易提交後**無條件終止**（沿既有終止語義與 CAS 競態安全，`end_reason='revoked'`），SHALL NOT 受 `access_revoke_disconnect` 政策鍵約束；審計事件 SHALL 帶被終止的 session 識別清單。人類執行的會話 SHALL 沿既有 `access_revoke_disconnect` 語義（見「撤銷斷線聯動」）。

**射程邊界（本版本明載）**：終止的射程止於本系統建立並代理的會話。目標主機上已由該會話啟動、且生命週期不依附該會話的背景程序 SHALL NOT 因撤銷而停止，本規格 SHALL NOT 被解讀為具備該能力。

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

#### Scenario: 撤銷即時終止 agent 會話
- **WHEN** 由 agent 主體執行的會話正進行中，其任務項被撤銷（`access_revoke_disconnect` 為預設 false）
- **THEN** 該會話被終止（`end_reason='revoked'`），審計事件帶被終止的 session 識別清單；撤銷後 SHALL NOT 出現該會話仍能執行指令的情形

#### Scenario: 撤銷不追殺主機背景程序
- **WHEN** agent 會話先前於目標主機啟動了脫離該會話的背景程序，其後任務項被撤銷
- **THEN** 會話被終止並留痕；該背景程序不受影響，且系統 SHALL NOT 對外宣稱已終止之

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

### Requirement: 申請單任務項
申請單 SHALL 由一至多個**任務項**組成（`access_request_items`：資產、帳號範圍、逐項狀態 `pending|approved|rejected|revoked`、逐項核准時長與起始、決定者與決定時刻、撤銷時刻與撤銷者、決定當時的政策快照）。單資產申請 SHALL 恰對應一個任務項；`access_requests.asset_id` SHALL 保留為第一項的鏡像欄，既有讀取面與既有請求形狀 SHALL NOT 因此改變。新讀取面 SHALL 以任務項為準。

同一申請人對同一資產 SHALL 僅允許一項 pending 任務項（去重語義由單層擴充至項層，既有單資產行為不變）。此去重 SHALL 由資料庫層的唯一約束保證，任務項 SHALL 為此保留申請人識別的冗餘欄位——併發建單只有資料庫層擋得住，服務層先查後寫擋不住。任務項的資產 SHALL 逐項套用既有可視守門（不可視即「不存在」語義）與既有段位判定，且段位判定 SHALL 看**該項的執行主體種類**（自主模式為申請人、輔助模式為指定的執行者）：`open` 段位資產對人類執行的項 SHALL NOT 建項；對由 agent 執行的項 SHALL 建項並視同 `reason` 段位自動核准，人類為 agent 執行者建立的 open 段位項亦同——判定看執行者而非申請人，否則委派模式在 `open` 段位資產上會無單可用，而自動化執行者建立連線必帶任務識別，形成無出口的斷路。

每個任務項 SHALL 於**被決定的當下**留存政策快照（該資產當時的段位、當時適用的核准門檻、自動核准時的系統依據）。快照 SHALL NOT 於事後回查現行政策改寫——政策可變，而稽核要回答的是「核准當時依的是什麼」。

一項被拒絕、被刪除或被撤銷 SHALL NOT 使整單失效，亦 SHALL NOT 使其餘項退回未授權狀態；整單狀態 SHALL 為各項狀態的彙總（尚有 pending 項即 pending；全部終態即依既有終態語義收斂）。

#### Scenario: 一單多資產逐項核准
- **WHEN** 申請人對資產 A 與 B 提交一張含兩項的申請，核准人核准 A 項、拒絕 B 項
- **THEN** A 項 approved 並產生對應臨時授權，B 項 rejected；整單仍可查得兩項各自的決定者與事由

#### Scenario: 單資產申請仍為一項
- **WHEN** 以既有單資產請求形狀（`asset_id` ＋ `accounts`）建立申請單
- **THEN** 系統建立恰一個任務項，`access_requests.asset_id` 與該項的資產一致，既有回應欄位逐欄不變

#### Scenario: 撤單項不影響其餘項
- **WHEN** 一張含三項且全部 approved 的單，其中一項被撤銷
- **THEN** 該項的臨時授權即刻失效（擋新連線），其餘兩項的授權不受影響，整單狀態仍為 approved

#### Scenario: 決定當時的政策可事後重建

- **WHEN** 一項於 `approval` 段位、門檻為兩個核准時被核准，其後管理員把該資產改為 `open` 段位
- **THEN** 該項的政策快照仍呈現決定當時的段位與門檻，SHALL NOT 被改寫為現行政策

#### Scenario: 項層去重
- **WHEN** 申請人已有一項對資產 A 的 pending 任務項，再提交含資產 A 的新單
- **THEN** 回 409 並帶既有在途單與項的識別，不建重複項

### Requirement: agent 主體申請與執行者
申請人 SHALL 可為 agent 主體（`users.kind='agent'`）。申請單 SHALL 帶 `executor_user_id`（NULL 或指向一個 agent 主體）：

- **自主模式**：`executor_user_id` 為 NULL 且申請人為 agent 主體——授權主體與執行主體同為該 agent。
- **輔助模式**：人類申請人建立申請單並將 `executor_user_id` 指向一個 agent 主體——委派由本系統核發，`on_behalf_of` SHALL 取自申請人，SHALL NOT 由呼叫端自報，亦 SHALL NOT 由 agent 的擁有者推導。

輔助模式的任務項 SHALL 同時受申請人與執行者兩側的可視範圍約束（取交集）；任一側不可視即該項不成立。此交集 SHALL 為**即時交集**：每次判定現查兩側的當前可視範圍，SHALL NOT 以核准當時的快照為準——申請人事後失去可視時，該項 SHALL 即刻不再命中，與撤權的即時性一致。`executor_user_id` SHALL NOT 於單建立後變更——換執行者 SHALL 開新單。agent 主體 SHALL NOT 核准任何申請單（含自己的）。

由 agent 執行的任務項 SHALL 對**任何段位**的資產都存在——`open` 段位不構成免單的例外，系統 SHALL 視同 `reason` 段位即時自動核准（決定者記 system、帶自動核准標記），使每一條 agent 連線都可回溯到一個任務 id。輔助模式下人類為 agent 執行者對 `open` 段位資產建立的項 SHALL 同樣建立並自動核准。


#### Scenario: agent 自主開單
- **WHEN** agent 主體對其可視、`approval` 段位的資產提交申請
- **THEN** 建立 pending 單，`executor_user_id` 為 NULL，審核範圍命中的 approver 於審核中心可見該單並可辨識申請人為 agent

#### Scenario: 人類委派 agent 執行
- **WHEN** 人類申請人建立申請單並指定 `executor_user_id` 為 agent X
- **THEN** 單記錄 `on_behalf_of` 為該申請人；核准後由 agent X 的身分取得的授權綁定該單，且不因該 agent 的擁有者是誰而改變

#### Scenario: 輔助模式取可視交集
- **WHEN** 人類申請人可視資產 A，但被指定的 agent 執行者不可視 A
- **THEN** 該項不成立（回「不存在」語義），不建項、不洩漏存在性

#### Scenario: 核准後申請人失去可視即失效
- **WHEN** 輔助模式的任務項已核准，其後人類申請人失去該資產的可視
- **THEN** 該項的後續判定即刻不命中（擋新連線），系統不以核准當時的快照放行

#### Scenario: agent 對 open 段位資產仍須開單
- **WHEN** agent 主體對 `open` 段位資產請求連線而無任何申請單
- **THEN** 連線被拒；其提交申請後單即時轉 approved（決定者 system）並帶任務 id，連線方可建立

#### Scenario: agent 不得核准
- **WHEN** agent 主體對任一 pending 單執行核准或拒絕
- **THEN** 一律回 403，單不受影響、不計票

### Requirement: 任務關閉的時點與其效力

申請單 SHALL 具備**關閉時刻**並持久化。關閉 SHALL 由下列任一觸發：執行者經 `close_task` 主動關閉該任務，或該單全部任務項皆已到期或被撤銷。關閉時刻 SHALL NOT 由「全部項是否為終態」於查詢時推導——報告的修訂時窗與缺報告的判定都以它為起點，推導值會使同一份報告因時間或政策變動而忽然逾窗。已有關閉時刻者 SHALL NOT 被後續觸發覆寫。

任務關閉 SHALL 終止該任務名下其餘進行中的會話，沿既有的即時終止出口，SHALL NOT 另開第二條終止入口。

任務報告的修訂時窗 SHALL 自關閉時刻起算；**缺報告 SHALL 以關閉時刻判定**——關閉當下無報告列即為缺報告，其後於修訂窗內的提交 SHALL NOT 改寫「關閉時缺報告」這項事實。

#### Scenario: 全部項終態即關閉

- **WHEN** 一張兩項的單，其中一項被撤銷、另一項其後自然到期
- **THEN** 該單記錄關閉時刻，其名下仍進行中的會話被終止

#### Scenario: 缺報告以關閉時判定

- **WHEN** 任務關閉當下無任何報告列，其後執行者於修訂窗內補交一版
- **THEN** 該任務仍記錄「關閉時缺報告」，補交的版本以修訂呈現

#### Scenario: 關閉時刻不被二次覆寫

- **WHEN** 執行者經 `close_task` 關閉任務之後，該單剩餘項才到期
- **THEN** 關閉時刻維持首次寫入的值

### Requirement: 申請帳號範圍的存在性驗證
建立申請單時，每個任務項的帳號範圍內的每個帳號名 SHALL 存在於該項資產的帳號清單中；不存在者 SHALL 回 400 `VALIDATION_ACCOUNT_NOT_ON_ASSET` 且不建單。`@ALL` 範圍 SHALL NOT 觸發此驗證。核准人 SHALL NOT 上調帳號範圍（沿用時長與起始「只可下修」的既有語義）。

由 agent 主體執行的任務項（自主模式的申請人為 agent，或輔助模式指定的執行者為 agent）SHALL 必須指定具體帳號範圍，SHALL NOT 使用全部帳號（`@ALL`）或空範圍；違反 SHALL 回 400 `VALIDATION_AGENT_ACCOUNTS_REQUIRED` 且不建單。理由是任務信封的成立要件即為綁定帳號——未綁帳號的核准書使兌換端的逐項比對沒有比對對象。人類申請人的任務項 SHALL NOT 受此限制，其 `@ALL` 語義不變。

#### Scenario: 範圍寫了不存在的帳號被拒
- **WHEN** 申請人對資產 A 提交帳號範圍 `["testuser"]`，而 A 上沒有 `testuser` 這個帳號
- **THEN** 回 400 `VALIDATION_ACCOUNT_NOT_ON_ASSET`，不建單，核准人不會看到一張寫著不存在帳號的核准書

#### Scenario: 全帳號範圍免驗
- **WHEN** 人類申請人的申請未帶帳號範圍（`@ALL`）
- **THEN** 建單成功，行為與擴充前一致

#### Scenario: agent 的項未指定帳號被拒
- **WHEN** agent 主體提交一項帳號範圍為 `@ALL`（或未帶帳號範圍）的任務項
- **THEN** 回 400 `VALIDATION_AGENT_ACCOUNTS_REQUIRED`，不建單

#### Scenario: 輔助模式的執行者為 agent 時同樣受限
- **WHEN** 人類申請人建立申請單並指定執行者為 agent 主體，但某一項未指定帳號範圍
- **THEN** 回 400 `VALIDATION_AGENT_ACCOUNTS_REQUIRED`，不建單（判定看執行者，不看申請人）

### Requirement: agent 開單速率與在途上限
agent 主體的開單 SHALL 受兩個政策鍵約束：`agent_request_rate_per_hour`（每小時開單上限，預設 30）與 `agent_request_pending_max`（同時 pending 單上限，預設 5）。任一上限被突破 SHALL 回 429 `RULE_AGENT_REQUEST_RATE` 且不建單，並 SHALL 入審計。人類申請人 SHALL NOT 受此兩鍵約束。計數 SHALL 於資料庫原子累計，SHALL NOT 依賴行程記憶體。

#### Scenario: 超過每小時開單上限
- **WHEN** agent 主體於一小時內第 31 次開單（預設值）
- **THEN** 回 429 `RULE_AGENT_REQUEST_RATE`，不建單，審計留一列

#### Scenario: 超過在途上限
- **WHEN** agent 主體已有 5 張 pending 單再提交第 6 張
- **THEN** 回 429 `RULE_AGENT_REQUEST_RATE`；其中一張被決定或作廢後即可再開

#### Scenario: 人類不受上限影響
- **WHEN** 人類申請人於同一小時內開超過 30 張單
- **THEN** 行為與擴充前一致，不因 agent 政策鍵被擋

### Requirement: 多資產申請表單

系統 SHALL 提供一張申請單同時申請多個資產的表單，入口 SHALL 位於「我的申請」頁；資產頁既有的單資產快捷申請入口 SHALL 保留，其送出結果 SHALL 為恰一項的多資產單（兩條路徑寫入同一資料形態）。

表單 SHALL 以逐項的形式呈現：每項含資產、帳號範圍（全部帳號或指定帳號清單）、與該項無關的欄位 SHALL NOT 逐項重複。時長與事由 SHALL 為整單共用欄位。

帳號選擇 SHALL 限於該資產上實際存在的帳號；送出前 SHALL 於前端檢查必填（至少一項、每項有資產、事由非空），送出後後端的帳號存在性拒絕 SHALL 以指向該項的錯誤呈現，SHALL NOT 只給整單層級的泛用錯誤。

執行者為 agent 主體的項，表單 SHALL NOT 提供「全部帳號」選項且帳號範圍 SHALL 為必填——任務信封綁到帳號才成立，讓使用者送出一個必被後端拒絕的值只是把錯誤延後。

自動化主體的開單速率或在途上限被觸發時，申請表單 SHALL 即時呈現已達上限的事實與當前數量與上限值；該提示 SHALL NOT 出現在任務列表（那裡呈現的是任務，不是配額）。

表單 SHALL 於單一層級內完成（新增項、刪除項、選帳號皆不另開疊層對話框）。

申請人為 agent 主體或執行者指定為 agent 主體時，表單與列表 SHALL 標示該主體類型與其負責人。

#### Scenario: 一單多資產

- **WHEN** 使用者在「我的申請」開表單，加入資產 A（指定帳號 ops）與資產 B（全部帳號），填時長與事由後送出
- **THEN** 建立一張含兩項的申請單，列表該單可展開看到兩項各自的資產與帳號範圍

#### Scenario: 單資產快捷路徑同形態

- **WHEN** 使用者自資產頁對資產 A 送出快捷申請
- **THEN** 建立的單含恰一項，其呈現形態與多資產單一致

#### Scenario: 帳號不存在的錯誤指到該項

- **WHEN** 送出的第二項帳號在該資產上不存在
- **THEN** 錯誤呈現在第二項旁，第一項的輸入不被清空

#### Scenario: agent 項不提供全部帳號選項

- **WHEN** 使用者在表單中把某一項的執行者指定為 agent 主體
- **THEN** 該項的帳號選擇不含「全部帳號」，且未選任何帳號時無法送出

#### Scenario: 達開單上限時表單即時告知

- **WHEN** 某 agent 主體本小時的開單數已達上限，使用者在表單中為其建單
- **THEN** 表單即時顯示已達上限與當前數量與上限值；任務列表不呈現此提示

#### Scenario: 表單不疊層

- **WHEN** 使用者在表單內新增項並選擇帳號
- **THEN** 全程於同一層級的表單內完成

### Requirement: 申請讀取與錯誤的增量契約
系統 SHALL 保留既有申請寫入、讀取權限與機器碼，僅新增受控 details 與唯讀投影。原本允許 agent 的 POST /access-requests 與 GET /access-requests/mine SHALL 維持原路由允許清單。

#### Scenario: 配額拒絕具體可辨
- **WHEN** agent 建單超過原有小時或 pending 上限
- **THEN** 429 原碼不變，details 加 used、limit、window_seconds 與 dimension；hour 為 3600 秒，pending 無滾動窗而為 0，不改計數或限額

#### Scenario: 帳號拒絕指出項目
- **WHEN** 第 i 項帳號不存在於資產
- **THEN** 400 原碼不變，details 帶零起算 item_index 與 asset_id，整筆建單仍不提交

#### Scenario: 執行者投影與下修界線
- **WHEN** 在原權限與原主體範圍內讀申請清單
- **THEN** 每單增加 executor 的 id、username、kind、owner_user_id、owner_username；每項增加 decision_bounds 的 max_duration、earliest_start、accounts
- **AND** 界線沿 decisionValues 的原申請上限與 max(now, requested_start)，帳號 @ALL 沿原 sentinel，不是具名帳號；此投影不授予審核權限，提交時仍檢查即時範圍
- **AND** agent 的 mine 忽略 client requester_id，只回自己提出的單；不洩漏其他人的申請
