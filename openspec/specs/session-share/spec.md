# session-share

## Purpose

會話分享碼的建立/撤銷與唯讀加入。
## Requirements
### Requirement: 分享碼建立與撤銷
會話擁有者 SHALL 能對自己的活躍 SSH 會話建立分享碼（TTL 1-60 分鐘，預設 10）；再次建立 SHALL 使舊碼失效；擁有者 SHALL 能撤銷分享；非擁有者建立回 403。

#### Scenario: 建立分享
- **WHEN** 擁有者 POST /sessions/:id/share
- **THEN** 回傳分享碼與過期時間，舊碼（如有）即刻失效

#### Scenario: 非擁有者被拒
- **WHEN** 其他用戶對該會話建立分享
- **THEN** 回 403 統一錯誤封套

### Requirement: 持碼唯讀加入
任何已登入用戶 SHALL 能以有效分享碼加入會話唯讀觀看；過期或已撤銷的碼 SHALL 回 404；加入者輸入 SHALL 被忽略；會話結束 SHALL 自動斷開觀看。

#### Scenario: 有效碼加入
- **WHEN** 登入用戶以有效碼開啟分享頁
- **THEN** 即時看到會話終端輸出，無法輸入

#### Scenario: 過期碼
- **WHEN** 以過期碼加入
- **THEN** 回 404「分享不存在或已過期」

### Requirement: 分享加入留痕

以分享碼加入會話 SHALL 寫入審計列，記錄加入者身分（或匿名加入的來源位址）、所用分享碼對應的會話與資產、加入時間。

留痕 SHALL 由 handler 寫入——分享連線的身分於 handler 內自解析，審計中介層在此路徑整筆跳過。

#### Scenario: 分享加入產生審計列

- **WHEN** 持有效分享碼者加入會話
- **THEN** audit_logs 新增一筆列，可查明加入者、目標會話與加入時間

#### Scenario: 無效分享碼的拒絕留痕

- **WHEN** 以失效或不存在的分享碼嘗試加入而被拒
- **THEN** 拒絕事件留痕，含來源位址與嘗試時間

