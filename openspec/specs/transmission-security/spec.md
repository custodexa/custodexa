# transmission-security Specification

## Purpose
傳輸層安全政策的分通道治理：六個通道各以 off／warn／strict 三段階梯設定強制程度，連線類通道於連線前要求風險同意並留痕（同意可記憶且有效期），認證類通道設 LDAP 登入傳輸閘，設定類通道於存檔前確認，資產列常駐傳輸風險徽章，並提供通道加密清冊的稽核匯出。出廠預設六通道皆 off，不改變既有連線、登入與存檔行為。
## Requirements
### Requirement: 傳輸強制階梯（per 通道三段）
系統 SHALL 對六個傳輸通道各提供獨立的強制等級政策：`off`（不限制，出廠預設，行為與現狀完全一致）、`warn`（警告留痕）、`strict`（嚴格拒絕）。通道與判定條件：RDP＝guacd 參數未啟憑證驗證（ignore-cert=true 或 security 低於 NLA）、VNC＝協議本身未加密（恆命中）、DB＝資產 `db_tls_mode` 為空或 `disable`、LDAP＝目錄連線非 ldaps 或跳過憑證驗證（SkipTLSVerify）、syslog＝轉發傳輸非 TLS、通知＝通道 URL 為 http。政策變更 SHALL 入審計。

#### Scenario: 出廠預設零影響
- **WHEN** 全新部署未調整任何傳輸政策
- **THEN** 六通道皆為 off，連線、登入與存檔不受傳輸政策影響（無政策攔截、無新增對話框或錯誤）

#### Scenario: strict 檔拒絕並回明確原因
- **WHEN** RDP 通道政策為 strict 且資產連線參數未啟憑證驗證
- **THEN** connect-token 簽發被拒，回應含通道名與不符項（如 ignore-cert），拒絕事件入審計

### Requirement: 連線前風險同意（warn 檔，連線類通道）
RDP／VNC／DB 通道在 warn 檔且該 user×資產無有效同意記憶時，系統 SHALL 在 connect-token 簽發前要求使用者確認風險聲明；同意 SHALL 記錄（使用者、時間、資產、風險項清單）並入審計；拒絕則不簽發 token。同意檢查 SHALL 在後端簽發端點強制執行，前端對話框僅為呈現層——繞過前端直呼 API SHALL 同樣被擋。對話框呈現的風險項說明 SHALL 以風險項 `key` 查譯（`riskLabel.<key>`）依當前 UI 語言顯示；持久化的同意記錄（`risk_items`）與審計 details SHALL 續存既有 `{key, label}` 風險項快照、位元組形狀不變（不新增 params 欄位），不隨 UI 語言改變（同意記憶 fingerprint 亦基於 key 集）。

#### Scenario: 首次連線要求同意並留痕
- **WHEN** VNC 通道為 warn，使用者首次連線某 VNC 資產並在對話框確認「我了解風險並繼續」
- **THEN** 同意記錄落庫並入審計（`risk_items` 為既有 {key,label} 快照），connect-token 正常簽發，連線建立

#### Scenario: 繞過前端直呼簽發 API 被擋
- **WHEN** warn 檔且無有效同意記憶，client 不帶同意憑據直接 POST connect-tokens
- **THEN** 簽發被拒並回須同意之風險項清單

#### Scenario: 對話框風險說明隨語言、記錄快照不變
- **WHEN** UI 語言為 en-US，使用者觸發某 DB 資產的風險同意對話框
- **THEN** 對話框以英文顯示風險項說明（如 "Database connection without TLS"，查 `riskLabel.db_tls_disabled`），確認後落庫的同意記錄與審計 details 仍為改動前的 {key,label} 快照形狀，未新增欄位

### Requirement: 同意記憶與效期
同意記憶 SHALL 以 user×資產為粒度；效期為政策鍵（預設 90 天），期滿後再次連線 SHALL 重新同意。政策由 warn 升為 strict 時既有同意記憶 SHALL 失效（strict 不接受同意）；資產傳輸相關設定變更使**風險項集合改變**時 SHALL 使該資產既有同意失效（失效判定基於風險項集合的 fingerprint，非設定值本身——設定往返回到同一風險集合不重複要求同意）。

#### Scenario: 效期內重連不重複打擾
- **WHEN** 使用者 30 天前已同意某資產風險（效期 90 天），再次連線
- **THEN** 不出現同意對話框，直接簽發連線

#### Scenario: 風險項集合變更使同意失效
- **WHEN** 已同意資產的傳輸屬性變更使風險項集合改變（新增或移除風險項），使用者再連
- **THEN** 需重新同意（fingerprint＝風險項集合雜湊，集合已變即不符，舊同意不沿用）
- 邊界：純設定值往返回到同一風險項集合（如 db_tls_mode disable→require→disable，頭尾同為「未啟用 TLS」單一風險）不重複打擾——該組風險使用者已具名同意過，重問無新資訊、徒增同意疲勞

### Requirement: LDAP 登入傳輸閘（認證類通道）
LDAP 通道在 warn 檔且目錄連線不安全（非 ldaps 或跳過憑證驗證）時，LDAP 登入 SHALL 照常放行但每次登入 SHALL 落一筆傳輸偏離審計事件（使用者、時間、風險項）；不要求登入者同意——登入者無權修復目錄設定，同意語義不成立。strict 檔 SHALL 拒絕不安全通道上的 LDAP 登入並回明確原因（修復指引指向身分管理 UI 的目錄設定頁，非部署層 env）；本地帳號認證 SHALL 不受任何檔位影響。判定 SHALL 基於登入當下的實際撥號參數，與設定存放位置無關。

#### Scenario: warn 檔 LDAP 登入留痕不阻斷
- **WHEN** LDAP 通道為 warn 且目錄設定 url 為 ldap://（明文），LDAP 用戶以正確帳密登入
- **THEN** 登入成功，審計出現傳輸偏離事件（含使用者與「目錄連線未加密」風險項），無同意對話框

#### Scenario: strict 檔拒 LDAP 登入但本地帳號不受影響
- **WHEN** LDAP 通道為 strict 且目錄連線不安全，LDAP 用戶與本地 admin 先後登入
- **THEN** LDAP 登入被拒並回通道不符原因（拒絕入審計，修復指引指向目錄設定頁）；本地 admin 走 bcrypt 路徑正常登入

### Requirement: 管理設定存檔確認（warn 檔，設定類通道）
syslog／通知通道／LDAP 目錄設定在 warn 檔下，存檔含不安全傳輸設定（非 TLS／http；LDAP 為非 ldaps 或跳過憑證驗證且啟用）時，系統 SHALL 要求管理員附確認聲明；確認 SHALL 入審計（管理員、時間、設定摘要、風險項）。strict 檔 SHALL 拒絕存檔並回明確原因。LDAP 目錄設定的存檔閘 SHALL 僅約束「儲存後狀態為啟用且含風險」的存檔；停用狀態的儲存不受閘限制（允許暫存草稿）。存檔閘為提前提示，登入當下的傳輸閘判定仍為最終權威。

#### Scenario: warn 檔存 http 通知通道須確認
- **WHEN** 通知通道政策為 warn，管理員儲存 http URL 的通道並附確認聲明
- **THEN** 存檔成功，確認聲明入審計；未附確認則存檔被拒並提示

#### Scenario: strict 檔拒存不安全的啟用 LDAP 設定
- **WHEN** LDAP 通道政策為 strict，管理員嘗試儲存 url 為 ldap://（明文）且 enabled=true 的目錄設定
- **THEN** 存檔被拒（機器碼指明傳輸風險）；同設定改 enabled=false 儲存則成功

#### Scenario: warn 檔存不安全的啟用 LDAP 設定須確認
- **WHEN** LDAP 通道政策為 warn，管理員儲存 skip_tls_verify=true 且 enabled=true 的設定並附確認旗標
- **THEN** 存檔成功且確認入審計；未附確認旗標則存檔被拒並回須確認的機器碼

### Requirement: 資產傳輸風險徽章（常駐）
資產列表 SHALL 對存在傳輸風險的資產顯示風險徽章（RDP 未驗憑證／VNC 未加密／DB 未啟 TLS），不分政策等級恆顯示；徽章 SHALL 附風險項說明。政策等級只決定攔截行為，不決定可見性。徽章的風險項說明 SHALL 以風險項 `key` 查譯（`riskLabel.<key>`）依當前 UI 語言顯示，切語言即時重繪；資產資料承載的風險項 SHALL 以既有 `{key, label}` 形狀識別（`syslog_non_tls` 等帶 runtime 參數者，其顯示參數如 `{protocol}` 由前端 caller 從自身 context 提供，不加入 wire 風險結構）。

#### Scenario: off 檔仍顯示徽章
- **WHEN** 全通道政策為 off，資產列表含一台 db_tls_mode=disable 的 MySQL 資產
- **THEN** 該資產顯示傳輸風險徽章與「DB 連線未啟用 TLS」說明（依 UI 語言查 `riskLabel.db_tls_disabled`），連線行為不受影響

#### Scenario: 徽章說明隨語言切換即時重繪
- **WHEN** 資產列表已載入且顯示風險徽章，使用者切換 UI 語言至 ja-JP
- **THEN** 徽章的風險項說明即時重繪為日文，無須重新載入列表

### Requirement: 通道加密清冊與稽核匯出
系統 SHALL 提供傳輸安全域頁（admin-only，頁面名稱「傳輸安全」，路由沿用原通道加密清冊路徑不變）：同頁承載 (1) `transport_*` 政策鍵設定區（六通道等級與同意效期，沿安全政策機制與本頁 PCI 子集偏離摘要／套用本頁建議值）與 (2) 通道加密清冊——彙整 SSH／RDP／VNC／DB／LDAP／syslog／通知／nginx 各通道的加密狀態、政策等級與偏離摘要；部署層設定（nginx/HTTPS）SHALL 呈現狀態與偏離提示、標示「部署方管理」，不提供設定開關；LDAP 通道 SHALL 呈現現行 DB 設定的加密狀態與偏離提示、標示於身分管理 UI 維護（附前往設定頁指引），其政策等級與「若切 strict 將拒絕 LDAP 登入」預檢 SHALL 一併呈現。清冊 SHALL 可匯出快照（含產生時間戳與產生者），匯出動作 SHALL 入審計。清冊各通道的說明（`note`）、strict 預檢（`strict_preflight`）與明細未設定標記 SHALL 以穩定機器碼（`note_code`／`preflight_code`／`transportDetail.unset`）＋參數承載，前端依當前 UI 語言查譯顯示（帶數量的預檢採 count-aware plural）；後端保留既有 zh `note`／`strict_preflight` 字串為 fallback 與匯出快照可讀；明細的技術複合鍵（如 `security=nla,verify_cert=true`、DB tls mode）為技術識別字不譯。清冊審計 SHALL 續記 event 碼、不序列化 note/preflight 中文（形狀不變）。

#### Scenario: 政策與清冊同頁呈現
- **WHEN** admin 開啟傳輸安全頁
- **THEN** 頁面同時呈現 transport 政策鍵設定區（含 PCI 子集橫幅）與通道清冊；調整通道等級儲存後，清冊的政策等級欄同步反映新值

#### Scenario: 清冊呈現 LDAP 通道的 UI 管理語義
- **WHEN** admin 開啟傳輸安全頁且 LDAP 以 ldap://（非 ldaps）的啟用設定存於 DB
- **THEN** LDAP 列顯示「未加密」與於身分管理 UI 維護的指引（查譯 `ldap_ui_managed` note 碼）及當前政策等級；若政策非 strict 則附「切 strict 將拒絕 LDAP 登入」預檢提示

#### Scenario: 清冊說明與預檢隨語言查譯
- **WHEN** admin 以 en-US 開啟傳輸安全頁，RDP 通道有 3 台風險資產
- **THEN** 該通道 note 與 strict 預檢以英文顯示（如 "Switching to strict will reject 3 RDP assets"，查 `transportPreflight.rdp_reject` 帶 `{count}` plural），DB 明細的未設定列顯示英文（`transportDetail.unset`），技術複合鍵原樣

#### Scenario: 匯出快照入審計
- **WHEN** admin 匯出通道清冊快照
- **THEN** 產物含全通道狀態、時間戳、產生者；審計出現匯出事件（僅記 event 碼，未含 note/preflight 譯文或中文）

