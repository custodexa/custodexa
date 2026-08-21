# break-glass

## Purpose

破窗緊急連線全流程：政策開關 `break_glass_enabled` 出廠關閉的雙重語義（藏入口＋封 API，不受功能開關旁路）、常設 connect 資格（只解除審核等待不提權，view-only 與無授權者無資格、admin 走既有政策豁免）、強制事由與固定短窗票證（復用申請單資料軌 `kind='break_glass'`、票證語義同核准流）、高亮審計與獨立通知事件、事後補審閉環（禁自審＋逾期升級告警＋審核中心待補審視圖）、申請對話框內次入口的呈現原則（防誤觸）。
## Requirements
### Requirement: 政策開關雙重語義
break-glass 功能 SHALL 由安全政策鍵 `break_glass_enabled` 控制且出廠預設關閉。關閉時系統 SHALL 同時：(1) 破窗 API 一律拒絕（403＋機器可辨 `break_glass_disabled`）；(2) 前端一切破窗入口隱藏（可用性提示由伺服端隨資產列表標註，前端零推導）。兩者 SHALL NOT 受任何功能開關或部署組態旁路。關閉期間的緊急通道語義＝admin 政策豁免（既有機制，不另設旁路）。

#### Scenario: 關閉時 API 拒絕
- **WHEN** `break_glass_enabled=false` 且具資格的使用者直呼破窗 API（不經前端）
- **THEN** 回 403＋`break_glass_disabled`，不建單、不簽發票證

#### Scenario: 關閉時入口隱藏
- **WHEN** `break_glass_enabled=false` 且使用者開啟資產列表與申請對話框
- **THEN** 看不到任何緊急連線入口

#### Scenario: 開啟即生效
- **WHEN** admin 將 `break_glass_enabled` 改為 true
- **THEN** 下次資產列表載入即帶破窗可用性標註，無需重啟

### Requirement: 破窗資格
破窗資格 SHALL 為：對該資產持有時窗內**常設** connect 授權（`source<>'ticket'` 的來源）。票證來源 SHALL NOT 計入資格（破窗不得以先前票證續命）；view-only 與無授權者 SHALL 無資格（破窗只解除審核等待，不提升權限等級）；admin SHALL 不提供破窗入口（其緊急通道為既有政策豁免，避免雙旁路語義混淆）。

#### Scenario: 常設 connect 者可破窗
- **WHEN** 使用者對 approval 段位資產持常設 connect、`break_glass_enabled=true`，發起破窗
- **THEN** 破窗成功、立即可連線

#### Scenario: view-only 無資格
- **WHEN** 使用者對該資產僅有 view 授權，發起破窗
- **THEN** 拒絕（403），提示無破窗資格

#### Scenario: 票證不構成資格
- **WHEN** 使用者對該資產僅有一張已過期的臨時授權票證（無常設 connect），發起破窗
- **THEN** 拒絕（403）

### Requirement: 破窗流程與短窗票證
破窗 SHALL 強制填寫事由（≤1000 字）；時窗 SHALL 固定為政策鍵 `break_glass_duration_minutes`（預設 60）、自破窗當下起算，SHALL NOT 接受申請人自填時長或預約起始（傳入即忽略）。破窗單 SHALL 復用申請單資料軌（`kind='break_glass'`）：建立即完成核准轉移（決定者記 system），同交易簽發 ticket 來源臨時授權並回鏈，票證語義與一般核准票證一致（時窗內多次連線、到期擋新連線不硬斷、可被提前撤銷）。同資產已有有效破窗票證時 SHALL 拒絕重複破窗（409 帶現有票證資訊）；同資產既有在途一般申請 SHALL NOT 阻擋破窗，且破窗 SHALL NOT 影響該在途單的正常裁決。

#### Scenario: 破窗即連
- **WHEN** 具資格使用者填事由破窗
- **THEN** 回應即含已核准單與票證時窗，資產連線入口立即可用，實際連線走既有政策閘票證軌

#### Scenario: 自填時長被忽略
- **WHEN** 破窗請求帶 `duration_minutes=1440`
- **THEN** 票證時窗仍為政策鍵值（預設 60 分鐘）

#### Scenario: 重複破窗擋下
- **WHEN** 使用者對同資產在有效破窗票證存續期間再次破窗
- **THEN** 回 409 並帶現有票證資訊

#### Scenario: 與在途申請並存
- **WHEN** 使用者對資產已有 pending 一般申請，隨後破窗
- **THEN** 破窗成功；原 pending 單保持待審、可照常核准或拒絕

### Requirement: 高亮審計
每次破窗 SHALL 寫入審計日誌並帶獨立事件標記（可與一般核准、admin 豁免區分）；破窗票證的每次連線沿既有連線審計。審計 SHALL 記錄破窗人、資產、事由、票證時窗。

#### Scenario: 破窗入審計
- **WHEN** 使用者破窗成功
- **THEN** 審計日誌出現破窗建單記錄（獨立標記），與 admin 豁免（`policy_exemption='admin'`）及一般核准可區分

### Requirement: 破窗通知
破窗成功 SHALL 即時發出破窗事件（`break_glass_used`）。v1 交付＝廣播至既有 alert-notifications 通道（best-effort 外送）＋審核中心「待補審」視圖為**權威保底可見面**（範圍命中的**有效審核者**於此必見該單，即使外送通道未配置或失敗；`admin` 角色本身 SHALL NOT 構成可見資格——審核中心對僅具 admin 者不開放，其全域檢視經 admin 專屬頁面取得）——收件人層級的定向通知（僅推給範圍命中的有效審核者）屬站內通知系統，列為後續版本工作。事件類型 SHALL 獨立且 SHALL NOT 被告警規則靜默過濾；payload SHALL 最小化（單號/資產名/破窗人/事件/連結，無事由全文）。通知外送失敗 SHALL NOT 阻斷破窗（緊急通道不被通知堵死）。**無任何有效審核者可見該單時**，逾期告警 SHALL 為其可見性保底（見「事後補審閉環」），SHALL NOT 以 admin 兜底可見性替代。

#### Scenario: 破窗事件外送並進待補審視圖
- **WHEN** 使用者對範圍命中的資產破窗成功
- **THEN** `break_glass_used` 事件廣播至已配置的通知通道，且該單即刻出現在範圍命中的有效審核者的審核中心待補審視圖

#### Scenario: 通知失敗不阻斷
- **WHEN** 通知通道全數不可用時使用者破窗
- **THEN** 破窗照常成功，外送失敗記日誌，審核中心待補審視圖仍可見該單（權威保底）

#### Scenario: 僅具 admin 者看不到待補審視圖
- **WHEN** 僅具 `admin` 角色者開啟審核中心待補審視圖
- **THEN** 403（無審核資格）；該單的管理可見性經 admin 專屬頁面（審核範圍總覽、授權管理與審計）取得

#### Scenario: 前端資格閘與後端同一述詞（403 SHALL NOT 呈現為空佇列）
- **WHEN** 僅具 `admin` 角色者登入，或以任何方式（快取過期、直接輸入網址）抵達審核中心
- **THEN** 入口 SHALL NOT 出現於導覽；直接輸入網址 SHALL 不進入該頁；縱使繞過前端閘而載入該頁，頁面 SHALL 明示「不具審核資格」，且 SHALL NOT 把 403 呈現為空列表——把「你看不到」顯示成「沒有東西」會使管理員誤判待審佇列已清空。前端可見性 SHALL 取自後端現算的有效審核資格（`is_approver`），SHALL NOT 另立一份靜態角色述詞

### Requirement: 事後補審閉環
破窗單 SHALL 帶補審狀態（建立即 `pending_review`）；補審資格＝範圍命中的**有效審核者**（具 `approver` 角色 OR 屬任一審核方群組；`admin` 角色本身 SHALL NOT 構成補審資格，須明確被指派 approver 角色或納入審核方群組——與 access-request 的審核資格同一判定來源），破窗人 SHALL NOT 補審自己的破窗單（硬擋，含破窗人兼具 admin 身分之自審）。補審 SHALL 記錄處置（confirmed／violation）與備註，狀態轉移 SHALL 為 CAS（僅 `pending_review` 可補審、補審後不可重複）。超過政策鍵 `break_glass_review_timeout_hours`（預設 24）未補審 SHALL 觸發升級告警事件（`break_glass_review_overdue`）；該告警 SHALL **週期重發**至該單離開 `pending_review` 為止，並 SHALL 以「最近告警時刻」節流（節流間隔與逾期超時窗解耦，實作為固定 24 小時，使超時窗設得很短的部署不被同倍數放大轟炸）——**每單至多一次的一次性告警 SHALL NOT 視為滿足本條**：當可見性保底所依賴的正是這道告警時，只響一次意味著一封通知被漏看該單即永久沉沒。未逾期的破窗單 SHALL NOT 進入告警集合（正常有審核者的部署不因本條產生噪音）；審核中心 SHALL 提供待補審視圖與計數。無有效審核者可補審時，該單 SHALL 維持 `pending_review` 並持續累計逾期告警，SHALL NOT 因無人可審而被自動結案；解除方式 SHALL 為 admin 以管理路徑指派 approver 角色或補建審核範圍（該路徑僅需 admin 權限、永遠可用）。

#### Scenario: 補審完成
- **WHEN** 範圍命中的 approver 對待補審破窗單提交處置 confirmed＋備註
- **THEN** 單記錄補審人/時間/處置，脫離待補審視圖；再次補審回 409

#### Scenario: 破窗人不可自審
- **WHEN** 破窗人本人（同時具 approver 角色且範圍命中）嘗試補審自己的破窗單
- **THEN** 403 拒絕

#### Scenario: 無審核資格的 admin 不可補審
- **WHEN** 僅具 `admin` 角色（未被指派 `approver`、不屬任何審核方群組）者對待補審破窗單提交處置
- **THEN** 403 拒絕；其被指派 approver 角色並具範圍命中後即可補審

#### Scenario: 逾期升級告警
- **WHEN** 破窗單建立超過 24 小時（政策鍵預設）仍未補審
- **THEN** 發出 `break_glass_review_overdue` 事件，單仍留在待補審視圖

#### Scenario: 逾期告警持續重發（可見性保底）
- **WHEN** 同一破窗單逾期後歷經多輪掃描且始終未補審
- **THEN** 每逾一個節流間隔（24 小時）再發一次 `break_glass_review_overdue`；同一節流間隔內重複掃描不重發

#### Scenario: 未逾期單不產生告警噪音
- **WHEN** 破窗單尚未超過 `break_glass_review_timeout_hours`
- **THEN** 掃描不將其納入告警集合，不發任何逾期事件

#### Scenario: 無人可補審不自動結案
- **WHEN** 某破窗單無任何範圍命中的有效審核者
- **THEN** 該單維持 `pending_review` 並持續於待補審視圖與逾期告警中可見；admin 補建審核範圍後即可由該審核者補審

### Requirement: 入口呈現原則
破窗入口 SHALL 呈現於申請對話框內的次要入口（非資產列表主按鈕，防誤觸），且僅在伺服端標註破窗可用（開關開啟＋具資格＋資產處 reason/approval 段位）時出現；入口文案 SHALL 白話明示後果（立即連線、事後補審、全程留痕）。

#### Scenario: 有資格者見次入口
- **WHEN** 開關開啟、具常設 connect 的使用者打開 approval 段位資產的申請對話框
- **THEN** 對話框內出現「緊急連線」次入口與後果說明

#### Scenario: 無資格者不見入口
- **WHEN** 同對話框由僅 view 授權的使用者開啟
- **THEN** 無緊急連線入口

