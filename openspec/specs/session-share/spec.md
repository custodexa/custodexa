# session-share

## Purpose

會話分享碼的建立/撤銷與唯讀加入。

## Requirements

### Requirement: 分享碼建立與撤銷
會話擁有者 SHALL 能對自己的活躍 SSH 會話建立分享碼（TTL 1-60 分鐘，預設 10）；再次建立 SHALL 使舊碼失效；擁有者 SHALL 能撤銷分享；非擁有者建立或撤銷，以及目標會話不存在，SHALL 回相同的 404 `NOTFOUND_SESSION` 封套。管理或稽核角色 SHALL NOT 豁免會話本人限制；資格判斷 SHALL 先於會話狀態、分享存在性及分享變更。

#### Scenario: 建立分享
- **WHEN** 擁有者 POST /sessions/:id/share
- **THEN** 回傳分享碼與過期時間，舊碼（如有）即刻失效

#### Scenario: 非擁有者被拒
- **WHEN** 其他用戶對該會話建立或撤銷分享
- **THEN** 回 404，本文為 `{"code":"NOTFOUND_SESSION","error":"Session 不存在"}`，與不存在會話的狀態、機器碼、訊息、欄位及相關標頭相同，分享狀態不變

#### Scenario: 兩個方法皆不揭露存在性
- **WHEN** 同一非擁有者分別對不存在會話與他人的會話執行 POST 或 DELETE /sessions/:id/share，後者可能在線、離線、已分享或未分享
- **THEN** 各方法的兩種目標皆回相同 404 `NOTFOUND_SESSION`；本文只有 `code` 與 `error`，內容、快取、驗證與跨來源等相關標頭相同，不建立、替換或撤銷分享；前端使用會話不存在文案，不顯示擁有者資格提示

#### Scenario: 非本人管理與稽核角色
- **WHEN** admin 或 auditor 嘗試管理他人的會話分享
- **THEN** 同樣回 404 `NOTFOUND_SESSION`，角色不擴大分享資格

#### Scenario: 本人撤銷分享
- **WHEN** 會話擁有者 DELETE /sessions/:id/share 且該會話有有效分享
- **THEN** 撤銷成功回 200 與 `{"revoked":true}`，原分享碼失效

#### Scenario: 資格通過後的狀態結果
- **WHEN** 擁有者對非活躍會話建立分享，或對存在但無有效分享的會話撤銷分享
- **THEN** 前者仍回 400 `RULE_SESSION_SHARE_NOT_ACTIVE`，後者仍回 404 `NOTFOUND_SESSION_SHARE`，這些結果不對非擁有者揭露

### Requirement: 持碼唯讀加入
任何已登入用戶 SHALL 能以有效分享碼加入會話唯讀觀看；過期或已撤銷的碼 SHALL 回 404；加入者輸入 SHALL 被忽略；會話結束 SHALL 自動斷開觀看。

#### Scenario: 有效碼加入
- **WHEN** 登入用戶以有效碼開啟分享頁
- **THEN** 即時看到會話終端輸出，無法輸入

#### Scenario: 過期碼
- **WHEN** 以過期碼加入
- **THEN** 回 404「分享不存在或已過期」

### Requirement: 分享加入以一次性觀看票認證

分享觀看的 WebSocket SHALL 只接受一次性觀看票，SHALL NOT 自 query 參數接受登入憑證。
票由掛認證 middleware 的簽發端點發出，任何已登入者皆可取得，且 SHALL 綁定簽票者身分與
該分享碼。分享碼 SHALL NOT 出現在該端點的請求路徑上——請求路徑會逐字進入審計列，
而分享碼是短期憑證。

分享碼的有效性 SHALL 於加入時判定：簽票之後才失效或被撤銷的碼，其加入 SHALL 被拒並維持
既有的留痕與回應語義。缺票、無效票、過期票、重放票，以及用途或客體不符的票，對外 SHALL
收斂為同一則憑證無效回應，審計 SHALL 分得出其成因。

兌換 SHALL 把簽票當下的認證脈絡帶入觀察者訂閱，使分享觀看與即時監看的撤銷治理一致。

#### Scenario: 分享加入須先取票

- **WHEN** 已登入者開啟分享觀看頁
- **THEN** 前端先以該分享碼取得一次性觀看票，WebSocket 網址只帶該票、不含登入憑證

#### Scenario: 簽票後分享被撤銷

- **WHEN** 持票者在分享被撤銷之後才建立連線
- **THEN** 加入被拒並回「分享不存在或已過期」，且拒絕留痕

#### Scenario: 分享碼不落審計表

- **WHEN** 已登入者以分享碼換取觀看票
- **THEN** 該次請求的審計列不含分享碼（路徑、細節、請求本體皆然）

#### Scenario: 票只能開它所綁的分享

- **WHEN** 以為另一個分享碼簽出的票、或以監看票加入某分享
- **THEN** 連線被拒，對外回應與無效票相同，審計註明為用途或客體不符

### Requirement: 分享加入留痕

以分享碼加入會話 SHALL 寫入審計列，記錄加入者身分（或匿名加入的來源位址）、所用分享碼對應的會話與資產、加入時間。

留痕 SHALL 由 handler 寫入——分享連線的身分於 handler 內自解析，審計中介層在此路徑整筆跳過。

#### Scenario: 分享加入產生審計列

- **WHEN** 持有效分享碼者加入會話
- **THEN** audit_logs 新增一筆列，可查明加入者、目標會話與加入時間

#### Scenario: 無效分享碼的拒絕留痕

- **WHEN** 以失效或不存在的分享碼嘗試加入而被拒
- **THEN** 拒絕事件留痕，含來源位址與嘗試時間
