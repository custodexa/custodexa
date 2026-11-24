# alert-notifications

## Purpose

命令告警經通知通道外送（webhook 通用 JSON+HMAC 簽章、slack mrkdwn）：重試、失敗不影響告警持久化與會話。
## Requirements
### Requirement: Webhook channel management
Principals holding the notification channel management capability (the super administrator, the system security administrator template, or a custom role granted that capability) SHALL manage notification channels (name, type, url, optional secret, enabled) and trigger a test delivery. Principals without that capability, including auditors and identity or asset administrators, SHALL be rejected on every channel endpoint, including listing and test delivery; each rejection SHALL leave one request audit entry with status denied and SHALL NOT write the channel, a service-layer channel audit row, or a system security alert. Channel endpoints SHALL be guarded by that capability, not by a hardcoded role name. Invalid URLs MUST be rejected. Channel type SHALL be one of the types in the channel type registry defined by the notification delivery capability (in this version `webhook`, `slack` and `slack_app`); unknown types SHALL be rejected. The secret SHALL never be returned to clients; on update, an empty secret SHALL preserve the existing value, and clearing the secret SHALL require an explicit `clear_secret` flag. The HMAC signature SHALL apply only to `webhook` channels, whose signing secret is optional. `slack` channels SHALL NOT send a signature and their secret SHALL be forced empty on create/update (has_secret always false). For `slack_app` channels the secret holds the bot token: it SHALL be required on create, SHALL NOT be sent as a signature, and SHALL follow the same storage, masking and preserve-on-empty rules as the signing secret; clearing it SHALL be rejected because the type cannot deliver without it. A `slack_app` channel SHALL also carry a non-secret target conversation identifier, which SHALL be validated for length and characters and SHALL be returned to clients.

When a channel's type changes, the same request SHALL supply the url, otherwise the update SHALL be rejected without changing any field; the secret of the previous type SHALL be cleared and never carried over; if the new type requires a secret (the `slack_app` bot token), the same request SHALL supply it, otherwise the update SHALL be rejected without changing any field; when the new type is `webhook` the signing secret SHALL remain optional. When the url of a `slack_app` channel changes, the same request SHALL supply the bot token, otherwise the update SHALL be rejected without changing any field, so that a stored token is only ever sent to the url it was stored with. These rules SHALL be evaluated against the channel row read under lock inside the update transaction, so that two concurrent updates cannot bypass them. Test delivery SHALL be addressed only by the channel identifier and SHALL use the stored configuration; it SHALL NOT accept a url, secret, target or type from the request. Redirect handling depends on the channel type and applies equally to delivery and test delivery: `slack_app` requests SHALL NOT follow redirects and a redirect response SHALL be reported as a failure; `webhook` and `slack` requests SHALL keep following redirects, but every hop SHALL pass the same notification transmission policy check as the channel url at save time (no downgrade from https to http and no transmission risk beyond that of the stored url), and a hop that fails the check, or too many redirects, SHALL stop delivery without sending that hop and SHALL be reported as a failure. When a redirect is followed, the request to the next hop SHALL NOT carry a header that reveals the previous hop's url.

The stored secret and the channel url SHALL be envelope-encrypted at rest (data DEK). API responses SHALL NOT return the full url: it SHALL be masked preserving scheme, host, and the last 4 characters (e.g. `https://hooks.slack.com/****abcd`). On update, an empty url SHALL preserve the existing value (same semantics as secret). Delivery and test-send SHALL decrypt at send time with behavior unchanged.

#### Scenario: Test delivery
- **WHEN** an admin clicks test send on a channel
- **THEN** a test payload formatted for that channel's type is delivered to the channel URL and the result is reported

#### Scenario: Editing without retyping secret keeps signing intact
- **WHEN** an admin renames a webhook channel (or toggles enabled) without re-entering the secret
- **THEN** the stored secret is unchanged and subsequent pushes remain signed

#### Scenario: Explicit clear
- **WHEN** an admin updates a channel with `clear_secret: true`
- **THEN** the secret is removed and subsequent pushes are unsigned

#### Scenario: Unknown type rejected
- **WHEN** an admin submits a channel with type `teams`
- **THEN** the API rejects it with a clear error

#### Scenario: URL masked in responses
- **WHEN** an admin lists or reads a channel whose url is `https://hooks.slack.com/services/T000/B000/secretpart`
- **THEN** the response url shows scheme and host with the path masked except the last 4 characters, and the full url appears nowhere in the payload

#### Scenario: Editing without retyping url keeps delivery intact
- **WHEN** an admin updates a channel leaving url empty
- **THEN** the stored url is unchanged and subsequent deliveries reach the original endpoint

#### Scenario: Secrets encrypted at rest
- **WHEN** a channel with secret and url is persisted and the DB rows are inspected directly
- **THEN** both values are stored as envelope ciphertext (version-prefixed), not plaintext

#### Scenario: Principal without the channel capability is rejected
- **WHEN** an auditor, an identity administrator, or a principal holding only asset management capabilities lists, creates, updates, deletes, or test-sends a notification channel
- **THEN** every request is rejected; no channel is written, no service-layer channel audit row or system security alert is produced, and the request audit records one entry with status denied for each rejected request

#### Scenario: Slack app channel requires a bot token and a target
- **WHEN** an admin creates a `slack_app` channel without a secret, or without a target conversation identifier
- **THEN** the API rejects it with a clear error and no channel is written

#### Scenario: Bot token is never returned
- **WHEN** an admin lists or reads a `slack_app` channel that has a bot token
- **THEN** the response shows `has_secret: true` and the target identifier, and the token appears nowhere in the payload, the audit row or the channel change alert

#### Scenario: Type change into Slack app needs a new secret
- **WHEN** an admin changes a `webhook` channel that has a signing secret to type `slack_app` without supplying a secret
- **THEN** the update is rejected and the channel keeps its previous type and secret

#### Scenario: Type change out of Slack app clears the token
- **WHEN** an admin changes a `slack_app` channel to type `webhook` without supplying a signing secret
- **THEN** the update succeeds, the bot token is cleared, `has_secret` is false, and subsequent webhook pushes to that channel carry no signature

#### Scenario: Changing a Slack app url requires the token
- **WHEN** an admin changes the url of a `slack_app` channel that has a bot token without supplying the token
- **THEN** the update is rejected, the channel keeps its previous url and token, and no request carrying the token is sent to the new url

#### Scenario: Type change requires the url
- **WHEN** an admin changes a `webhook` channel to type `slack_app`, supplying a bot token and a target but leaving the url empty
- **THEN** the update is rejected, the channel keeps its previous type, url and secret, and the previous webhook receiver receives no request carrying the token

#### Scenario: Test delivery to a Slack app channel does not follow redirects
- **WHEN** an admin test-sends to a `slack_app` channel whose endpoint answers with a redirect
- **THEN** no request is sent to the redirect target and the test reports a failure

#### Scenario: Webhook redirect hops must pass the transmission policy
- **WHEN** an admin test-sends to a `webhook` channel whose https endpoint redirects with a body-preserving redirect, once to another compliant https address and once to an http address
- **THEN** the compliant target receives the test payload and the test succeeds; the http target receives no request and the test reports a failure stating that the redirect target does not meet the transmission policy

### Requirement: Alert push delivery
When a command alert is recorded, the system SHALL write one notification message for it as defined by the notification delivery capability, right after the alert row is written; a failure to write the message SHALL NOT remove the alert row, fail the caller or affect sessions, and SHALL be logged and reported as an audit mechanism failure. In the background the message SHALL be dispatched to every enabled channel whose push threshold admits the alert's severity (see Requirement: 通道推送等級門檻), and the deliveries SHALL be sent, retried with a bounded number of attempts, and made visible as defined by the notification delivery capability. There SHALL NOT be an in-memory queue that can drop a command alert notification when full, and a restart SHALL NOT lose a written notification. `webhook` channels SHALL receive a JSON payload (alert, rule, session context) signed with HMAC-SHA256 in X-OT-Signature when a secret is set. `slack` and `slack_app` channels SHALL receive the same Slack-formatted text (severity, rule, command, and session context) and SHALL NOT include a signature header. Slack `text` content SHALL escape mrkdwn control characters (`&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`) so that command text containing shell redirection/operators renders correctly. Delivery failures MUST NOT affect alert persistence or sessions.

Alerts whose source kind is not a rule (command audit degraded, new source address, sensitive content access) carry a machine identifier in `rule_name` and an intentionally empty command. For these kinds the `slack` text SHALL use a plain-language title for the kind and a plain-language line stating what happened and where to look, both rendered in the channel language; it SHALL NOT show the machine identifier as the title and SHALL NOT render an empty command block. For the command audit degraded kind, the text SHALL state that the input could not be reliably reconstructed as command text and SHALL point the reader to the session recording; when the degrade reason of the rounds that opened the alert can be resolved, the text SHALL add one plain-language line describing the circumstance, and when it cannot be resolved the line SHALL be omitted rather than guessed. The text SHALL NOT characterize the event as an attack or as benign, and the severity SHALL remain as recorded. Rule-kind alerts (including legacy rows without a kind) SHALL keep their existing `slack` rendering apart from the occurrence time and the optional link defined by the notification delivery capability. The `webhook` payload and syslog forwarding SHALL keep every machine field (`kind`, `reason_code`, `rule_name`, `command` and the rest) unchanged in name and value; the plain-language text exists only in the `slack` body. The session's source address (carried in the webhook `session` object and in the new source address text) and the degrade reason SHALL be resolved when the notification is dispatched and stored with it, so that neither disappears because rendering no longer queries the database at delivery time.

Agent probe breaker alerts are recorded as alert rows but SHALL NOT produce a command alert notification; their notification is the agent breaker system event, which carries the agent, owner, token and asset names. System security alerts are recorded with their own source kind and SHALL NOT produce a command alert notification: they SHALL be enqueued by the system security alerts capability in the transaction that records them, so that channel push thresholds never filter them and they are not sent twice. Both share the same delivery worker with command alerts.

#### Scenario: Signed webhook delivery
- **WHEN** an alert triggers and a webhook channel has a secret
- **THEN** the receiver gets the JSON payload with a valid HMAC signature header

#### Scenario: Slack-formatted delivery
- **WHEN** an alert triggers and a `slack` channel is enabled
- **THEN** Slack receives a `{"text": ...}` body rendering severity, rule name, command and session context, with no signature header; for alerts whose kind is not a rule, the plain-language title and explanation take the place of the rule name and command, as described in the requirement text

#### Scenario: Slack command text with shell metacharacters
- **WHEN** an alert for a command containing `>` `<` or `&` is pushed to a `slack` channel
- **THEN** the metacharacters are escaped in the `text` field so Slack renders them literally rather than as link/quote syntax

#### Scenario: Receiver down
- **WHEN** the webhook endpoint is unreachable
- **THEN** the alert is still persisted, the delivery is retried with backoff up to the attempt limit and its attempts and last error are recorded on the delivery, without session impact

#### Scenario: Command audit degraded alert reads in plain language
- **WHEN** a command audit degraded alert is pushed to a `slack` channel whose language is `zh-TW`
- **THEN** the title is a plain-language phrase meaning the command could not be reconstructed, followed by the severity, and the next line tells the reader the input could not be reliably reconstructed and to check the session recording; the text contains neither the machine identifier `audit_degraded_span` nor an empty code block

#### Scenario: Degrade reason is shown only when resolvable
- **WHEN** the rounds that opened a degraded alert were recorded inside a full-screen program
- **THEN** the Slack text adds one plain-language line saying so; and **WHEN** no degrade reason can be resolved for the alert, **THEN** that line is absent and the rest of the message is unchanged

#### Scenario: Other non-rule kinds read in plain language
- **WHEN** a new source address alert or a sensitive content access alert is pushed to a `slack` channel
- **THEN** each shows a plain-language title for its kind and a plain-language explanation line, with no machine identifier as the title and no empty code block; a new source address alert also shows the source address when it is known

#### Scenario: Rule alerts and machine fields unchanged
- **WHEN** a rule-kind alert is pushed to `slack` and any alert is pushed to `webhook` or forwarded to syslog
- **THEN** the rule alert's Slack text keeps the same title line, command block and context line order as before (with the occurrence time format and the optional link defined by the notification delivery capability), and the webhook and syslog payloads carry every existing field with the same name and value as before, including `rule_name: "audit_degraded_span"` for a degraded alert; the webhook payload may additionally carry the optional `notification` object

#### Scenario: System security alert bypasses the push queue
- **WHEN** a system security alert is committed while a `slack` channel and a `webhook` channel are enabled
- **THEN** the alert produces no command alert notification; each channel receives it once through the shared delivery worker regardless of its push threshold, and command alerts created at the same time are delivered through the same worker subject to thresholds

#### Scenario: Written command alert survives a restart
- **WHEN** a command alert is recorded while its only channel is unreachable, and the service restarts before the channel recovers
- **THEN** after the restart the notification is dispatched or continues from its recorded state, and the channel receives the alert once it is reachable, within the attempt limit

#### Scenario: Agent probe breaker is not sent in the command alert shape
- **WHEN** an agent probe breaker trips while a `slack` channel and a `webhook` channel are enabled
- **THEN** each channel receives the agent breaker system event once, and neither receives a command alert shaped message for the breaker alert row

#### Scenario: Session source address survives the move to dispatch
- **WHEN** a new source address alert for a session with a known source address is pushed to a `webhook` channel and a `slack` channel
- **THEN** the webhook payload carries `session.client_ip` with that address as before, and the Slack text shows the address

#### Scenario: Notification write failure keeps the alert
- **WHEN** a command is blocked by a rule and the alert row is written but writing its notification message fails
- **THEN** the command stays blocked, the alert row remains in the alert list, the failure is logged and an audit mechanism failure is reported

### Requirement: 通知通道傳輸政策門
通知通道建立與更新 SHALL 受通知傳輸政策約束：warn 檔下 URL 為 http 時，儲存 SHALL 要求管理員附風險確認聲明，確認入審計；strict 檔下 http URL SHALL 被拒絕存檔並回明確原因。off 檔（預設）行為與現狀一致（http/https 皆可存）。既有 http 通道在政策收緊後 SHALL 不被自動停用，但 SHALL 在通道列表與通道清冊標示偏離。

#### Scenario: strict 檔拒存 http 通道
- **WHEN** 通知傳輸政策為 strict，管理員儲存 URL 為 http:// 的通道
- **THEN** 存檔被拒，回應明確指出「通知傳輸政策要求 https」

#### Scenario: 政策收緊不自動停用存量通道
- **WHEN** 存在既有 http 通道，政策由 off 調為 strict
- **THEN** 既有通道照常投遞但在列表標示偏離；再次編輯存檔時才受 strict 檔拒絕

### Requirement: 通道語系設定
每個通知通道 SHALL 具備語系欄 `language`，值域為 `zh-TW`／`en-US`／`ja-JP`，並以資料庫 CHECK 約束保障。建立通道未指定語系時 SHALL 預設 `zh-TW`；更新時**省略該欄 SHALL 保留既有值**、傳入空值或白名單以外的值 SHALL 以 `VALIDATION_*` 機器碼拒絕（嚴格匹配，不做大小寫或前綴容錯）。語系 SHALL 僅影響會渲染文字的通道型別（`slack`、`slack_app`）的伺服端組字（經 notifycat 渲染）；`webhook` 型通道可設定但無作用（payload 為機器結構、不含文案），UI SHALL 註明此點。指令告警與系統事件 SHALL 依每次送出當下的通道語系渲染，語系變更於下一次送出即生效；系統安全告警 SHALL 依產生當下保存的語系渲染。

#### Scenario: 建立未指定語系採預設
- **WHEN** 管理員建立通道未提供 `language`
- **THEN** 通道以 `zh-TW` 儲存，後續 Slack 訊息以繁中渲染

#### Scenario: 更新省略語系保留原值
- **WHEN** 管理員更新一個語系為 `en-US` 的通道但請求未含 `language` 欄
- **THEN** 既有 `en-US` 保留不變（與 secret／url 的省略即保留語義一致）

#### Scenario: 空值與白名單外值被拒
- **WHEN** 管理員送出 `language: ""` 或 `language: "fr-FR"`
- **THEN** 請求以 4xx＋registered `VALIDATION_*` code 被拒，通道不被寫入無效語系

#### Scenario: Slack 通道以設定語系渲染
- **WHEN** 一個語系為 `en-US` 的 Slack 通道收到系統訊息
- **THEN** Slack 訊息文字為英文，與觸發者的前端介面語言無關（通道語系為唯一決定因素）

#### Scenario: webhook 型語系無作用
- **WHEN** 一個 webhook 通道設定語系為 `ja-JP`
- **THEN** 其 payload 形狀與內容不變（機器欄無文案），UI 標示該設定對 webhook 型不生效

#### Scenario: 語系變更與尚未送達的通知
- **WHEN** 一則系統事件與一則系統安全告警都已排入一個語系為 `zh-TW` 的 Slack 通道且尚未送達，管理員隨後把該通道改為 `en-US`
- **THEN** 系統事件送達時為英文；系統安全告警送達時仍為繁中

### Requirement: 系統訊息 payload 結構化
系統類通知 SHALL 以事件＋參數傳遞，SHALL NOT 由呼叫端組出散文再送出：對外的排入介面 SHALL 只接受事件、參數、需要解析的名稱參照與排入所需的交易，SHALL NOT 接受預組的標題或內文；既有 `NotifyMessage(event, title, text)` SHALL 維持刪除；所有 wrapper（`notify`／`sendNotify`／`NotifyOngoing` 等）簽名 SHALL 不帶散文參數，排入介面改變時 SHALL 以簽章變更使編譯期強制傳播至全部呼叫點（含 access-request、audit-failure、key-manager-degraded、daily-review、AI agent 路徑）。系統類通知 SHALL 經通知投遞層的排入、分派與持久投遞送出，SHALL NOT 以每次起一個背景工作的方式直接投遞；唯一的例外是通知投遞層與審計失效告警能力為稽核機制失效通知訂定的退路。

`webhook` 型通道的系統訊息 payload SHALL 保留 `{event, params, sent_at}` 形狀與既有欄位的名稱、型別與語義，並新增通知投遞層定義的可選 `notification` 物件，**散文零入 payload**；`slack` 與 `slack_app` 型通道的文案 SHALL 由 notifycat 依送出當下的通道語系渲染。params 值 SHALL 依 `EventSpec` 的 kind 建模，opaque 值 SHALL 經共用淨化函式處理；去識別紅線不變（事由全文等敏感長文不入 params）。條件分支型文案（如 audit-failure 的 interval 有無）SHALL 以 optional param＋模板 variant 表達，SHALL NOT 於呼叫端以字串拼接處理。

#### Scenario: webhook 系統訊息無散文
- **WHEN** 一筆存取申請被核准並推送至 webhook 通道
- **THEN** 收端取得 `{event: <事件識別字>, params: {...}, sent_at: <時間>}` 與新增的 `notification` 物件，既有三個欄位的名稱與型別與升級前相同，payload 內無任何中文或英文散文句

#### Scenario: 同一事件雙通道一致
- **WHEN** 同一事件同時推送至 webhook 與 slack 通道
- **THEN** webhook 收到機器結構、Slack 收到由 notifycat 依該通道語系渲染的文案，兩者事實內容一致

#### Scenario: 組字點於編譯期絕跡
- **WHEN** 開發者嘗試沿用舊寫法傳入預組好的標題與內文
- **THEN** 編譯失敗（`NotifyMessage` 與散文參數已不存在），散文無法重新進入通知鏈

#### Scenario: 條件文案以模板 variant 表達
- **WHEN** audit-failure 通知在有／無 interval 兩種情形下送出
- **THEN** 兩種情形由目錄的兩個模板 variant 渲染（optional param 決定），呼叫端不做字串拼接

#### Scenario: 系統事件與業務變更同進退
- **WHEN** 一筆連線申請的核准在同一交易的後續步驟失敗而回滾
- **THEN** 沒有任何核准通知被排入或送出

### Requirement: 事件規格執行期驗證與未註冊事件降級投遞
每個事件 SHALL 有 `EventSpec` 宣告其參數集合與各參數 kind（`enum`／`int`／`opaque`），並於**執行期驗證**：缺漏必填參數、`enum` 值不在允許清單、`int` 值非整數皆 SHALL 被偵測並記錄。

未在目錄註冊的事件 SHALL NOT 導致通知被拒發或消失（合規告警靜默消失是安全回歸），但降級路徑 SHALL 維持出站去識別紀律：已註冊事件降級（參數違規）時 params SHALL 過濾至 `EventSpec` 宣告鍵；**未註冊事件的 params 值 SHALL 全數剝除**（無契約可依，僅 `{event, degraded: true, sent_at}` 與不含參數、標示降級的 `notification` 物件出站），被剔除的鍵名僅記伺服端 log。降級 SHALL 在分派時決定，分派 SHALL NOT 因事件未註冊而失敗。`slack` 與 `slack_app` 分支 SHALL 以目錄內建的 generic 降級模板**依通道語系**組字（獨立 lexicon 鍵，SHALL NOT 依賴 per-event 鍵）。

#### Scenario: enum 值違規被偵測
- **WHEN** 某事件的 `enum` kind 參數收到允許清單以外的值
- **THEN** 執行期驗證記錄違規（並於測試中失敗），不將未受控值當成合法枚舉傳遞

#### Scenario: 未註冊事件 webhook 降級投遞
- **WHEN** 一個尚未在目錄註冊的事件觸發並推送至 webhook 通道
- **THEN** 收端仍收到 `{event, degraded: true, sent_at}`（params 值已全數剝除）與 `degraded` 為真、不含參數的 `notification` 物件，通知不消失，伺服端 log 記錄目錄缺鍵與被剔除的鍵名

#### Scenario: 未註冊事件 Slack 降級渲染
- **WHEN** 同一未註冊事件推送至語系為 `en-US` 的 slack 通道
- **THEN** Slack 收到 generic 降級模板依該通道語系組出的英文訊息（含事件識別字、不含未宣告參數值），而非空訊息或投遞失敗

#### Scenario: 降級不外洩未宣告參數
- **WHEN** 呼叫端誤將 forensic `detail` 之類未宣告鍵放入 params 並因此觸發降級
- **THEN** 該值不出現在 webhook body 與 Slack 文字中，僅於伺服端 log 留鍵名

### Requirement: 測試通知 payload 機器化
通道測試發送 SHALL 不夾帶任何中文散文：`webhook` 分支 SHALL 以機器識別字表達（如 `rule_name: "test"`），payload 內無文案句；`slack` 與 `slack_app` 分支的文案 SHALL 由 notifycat 依該通道語系渲染，第一行 SHALL 表明是測試、不需處理，SHALL NOT 含虛構的指令或使用者與會話編號。測試發送 SHALL 為同步的單次投遞，不經持久投遞、不重試、不出現在投遞紀錄。測試發送的成敗回報 SHALL 沿用既有錯誤封套語義（失敗回錯誤狀態碼＋registered code）；`slack_app` 型失敗時 SHALL 回報平台的錯誤碼，SHALL NOT 回報 token。

測試發送 SHALL 接受可選的形狀參數，值為指令告警、系統安全告警或系統事件三種 webhook 形狀之一；省略時 SHALL 送指令告警形狀，既有欄位與升級前相同。每種形狀的測試 payload SHALL 帶 `notification` 物件且其類別為測試，讓收端可以辨識並略過；形狀參數只對 `webhook` 型有作用。

#### Scenario: 測試 webhook payload 無中文
- **WHEN** 管理員對 webhook 通道點擊測試發送
- **THEN** 收端 payload 全為機器欄與機器識別字，不含「測試發送」等中文文案

#### Scenario: 測試 Slack 文案依通道語系
- **WHEN** 管理員對語系為 `ja-JP` 的 Slack 通道點擊測試發送
- **THEN** Slack 收到由目錄渲染的日文測試訊息

#### Scenario: 測試發送可選形狀
- **WHEN** 管理員對 webhook 通道以系統事件形狀測試發送
- **THEN** 收端收到 `{event, params, sent_at}` 形狀的測試 payload，`notification` 物件的類別為測試；不帶形狀參數時收到的仍是升級前的指令告警形狀加上 `notification` 物件

### Requirement: 阻斷標示不污染規則名稱
指令告警的 `rule_name` SHALL 為純淨的規則名稱，SHALL NOT 以文案後綴（如「（已阻斷）」）承載阻斷語義。阻斷與否 SHALL 由結構化布林欄 `blocked` 表達，並隨 webhook payload 送出（`alert.blocked`）；`slack` 分支的「已阻斷」標示 SHALL 由 notifycat 依通道語系渲染；前端告警列表 SHALL 以既有枚舉 tag 慣例呈現該狀態。至此「散文零入 webhook payload」對全部通知型別與事件成立。

#### Scenario: rule_name 純淨
- **WHEN** 一條阻斷型規則命中並產生告警
- **THEN** 告警記錄與 webhook payload 的 `rule_name` 僅含規則本名，無中文後綴

#### Scenario: blocked 以布林欄表達
- **WHEN** webhook 收端解析告警 payload
- **THEN** 可由 `alert.blocked` 布林值判定是否已阻斷，無需字串比對文案

#### Scenario: 前端以 tag 呈現阻斷
- **WHEN** 使用者以 en-US 介面檢視告警列表
- **THEN** 已阻斷的告警以當前語言的 tag 標示，規則名稱欄顯示純淨規則名

### Requirement: 告警通知的主體可辨識性

告警通知的脈絡資訊 SHALL 使收件人在**不登入系統查表**的前提下判讀「誰、在哪個目標上、何時」。純識別碼（`user 1`／`asset 1`）SHALL NOT 作為主體的唯一表示。

脈絡資訊 SHALL 同時帶主體名稱與識別碼：名稱供判讀、識別碼供追查與唯一對齊。欄位順序 SHALL 為「操作主體 → 目標資產 → 會話 → 時間」——會話識別碼是追查索引而非判讀資訊，SHALL NOT 置於首位。

主體名稱的解析 SHALL 涵蓋**已軟刪的使用者與資產**：離職者與已下架資產仍是調查對象，名稱缺失會使稽核誤判為資料損壞。

實體標籤（會話／使用者／資產）SHALL 依收件通道的語系渲染，SHALL NOT 硬編碼於程式碼。主體名稱本身屬使用者資料，SHALL NOT 進入翻譯目錄，僅施加通道所需的字元跳脫。

**名稱 SHALL 在通知分派當下（排入後由背景處理的那一次）解析一次並隨通知內容保存**，之後的投遞與重送一律使用保存的值；名稱 SHALL NOT 被表述為觸發當下的快照（觸發與分派之間若主體改名，通知顯示分派時的名稱）。通知因目的地離線而延後投遞時，期間主體改名 SHALL NOT 改變已分派通知的內容，同一則通知送到不同通道時名稱相同；識別碼不受影響，故主體的唯一對齊仍成立。此邊界 SHALL 明載，SHALL NOT 僅記於程式碼註解。

名稱解析失敗（查詢錯誤、主體已硬刪、識別碼為零值）時，該欄位 SHALL 退化為僅顯示識別碼，通知 SHALL 照常送出。SHALL NOT 因輔助顯示資訊缺失而使告警靜默或延誤。

`webhook` 型通道的 payload SHALL 以獨立欄位承載主體名稱，SHALL NOT 改動既有欄位的名稱、型別或語義——收端 SHALL 在不修改的前提下繼續運作。

#### Scenario: 脈絡資訊可判讀主體

- **WHEN** 指令告警推送至 slack 型通道
- **THEN** 脈絡行同時含使用者名稱與其識別碼、資產名稱與其識別碼、會話識別碼與觸發時間，且順序為主體、資產、會話、時間

#### Scenario: 軟刪主體仍顯示名稱

- **WHEN** 告警的使用者已離職（軟刪）或資產已下架（軟刪）
- **THEN** 通知仍顯示其名稱，而非退化為僅識別碼

#### Scenario: 名稱缺失不阻斷通知

- **WHEN** 主體名稱無法解析（識別碼為零值、主體已硬刪、或查詢失敗）
- **THEN** 該欄位僅顯示識別碼，通知仍送達收件通道

#### Scenario: 實體標籤隨通道語系

- **WHEN** 同一告警推送至語系設定不同的兩個 slack 通道
- **THEN** 兩則通知的實體標籤各依該通道語系渲染，主體名稱兩則相同且未被翻譯

#### Scenario: webhook 收端不需改動

- **WHEN** 既有 webhook 收端接收帶主體名稱的告警 payload
- **THEN** 既有欄位的名稱、型別與語義不變，新增欄位為可選，收端無需修改即可繼續解析

#### Scenario: 延後投遞不改變已保存的名稱

- **WHEN** 一則指令告警分派後因目的地離線而延後投遞，期間該使用者改名
- **THEN** 通知送達時顯示分派當下的名稱與同一個識別碼，與同一則通知先前送到其他通道的內容相同

### Requirement: 通道推送等級門檻
每個通知通道 SHALL 具備推送門檻欄 `min_severity`，值域為 `low`／`medium`／`high`（依序對應畫面的「全部告警」「中、高等級」「只有高等級」），並以資料庫 CHECK 約束保障。建立通道未指定門檻時 SHALL 預設 `low`；既有通道升級後 SHALL 取得 `low`，推送行為與升級前相同。更新時**省略該欄 SHALL 保留既有值**；傳入空值或白名單以外的值 SHALL 以 `VALIDATION_CHANNEL_MIN_SEVERITY` 機器碼拒絕（嚴格匹配）。不提供「全部不推送」的檔位；要完全不收，停用通道。

門檻 SHALL 只作用於告警推送（命令告警與其他以告警形式推送的事件）：告警等級為 `high`／`medium`／`low` 之一時，等級不低於通道門檻才推送到該通道；等級為空或不在三值內的告警 SHALL 照送。門檻 SHALL 在通知分派時依通道當下的設定判斷，之後的門檻變更 SHALL NOT 影響已建立的待投遞紀錄。系統事件（不論其事件規格宣告的分級為何）與測試發送 SHALL NOT 受門檻影響，照常送到啟用中的通道；系統事件的分級只用於呈現、投遞先後與 webhook 的 `notification` 物件。系統安全告警雖帶分級，SHALL NOT 受門檻影響：不論其分級為何，都 SHALL 經持久投遞送到產生當下每一個啟用中的通道；門檻只過濾一般告警。門檻 SHALL NOT 改變告警的入庫與 syslog 轉發：兩者在排入推送之前即已依既有規則處理，與任何通道的門檻無關。某則告警沒有任何通道收時，系統 MAY 略過僅供推送內容使用的查詢。

門檻實際改變時，系統 SHALL 寫一筆稽核紀錄，記錄操作者、通道識別與改動前後的門檻值；通道設定端點的請求本文稽核 SHALL 原樣記錄 `min_severity` 的值，SHALL NOT 以遮罩值取代。UI SHALL 在設定旁說明：被略過的中、低等級告警仍記在告警頁；啟用中的通道仍會收到系統事件、測試發送與無法判定等級的告警。通道列表 SHALL 另說明系統告警不受推送門檻篩選、一律推送到每一個啟用中的通道。

#### Scenario: 預設全部告警
- **WHEN** 管理員建立通道未提供 `min_severity`，或系統自未有此欄的版本升級
- **THEN** 該通道的門檻為 `low`，high、medium、low 三種等級的告警都推送到該通道

#### Scenario: 只有高等級的通道略過 medium
- **WHEN** 一則 medium 告警排入推送，通道甲門檻為 `high`、通道乙門檻為 `low`，兩者皆啟用
- **THEN** 通道乙收到該告警，通道甲沒有收到

#### Scenario: 只有高等級的通道仍收 high
- **WHEN** 一則 high 告警排入推送，通道門檻為 `high`
- **THEN** 該通道收到該告警

#### Scenario: 中、高等級的通道
- **WHEN** 通道門檻為 `medium`，先後有 low、medium、high 告警各一則排入推送
- **THEN** 該通道收到 medium 與 high 兩則，沒有收到 low

#### Scenario: 無法判定等級的告警照送
- **WHEN** 一則等級為空或不在三值內的告警排入推送，通道門檻為 `high`
- **THEN** 該通道收到該告警

#### Scenario: 系統事件與測試發送不受門檻影響
- **WHEN** 通道門檻為 `high` 且已啟用，系統發出一則系統事件（例如申請核准），管理員對該通道按下測試發送
- **THEN** 該通道收到系統事件與測試訊息

#### Scenario: 被略過的告警仍在告警頁
- **WHEN** 一則 medium 的規則告警被門檻 `high` 的通道略過
- **THEN** 該告警照常入庫並出現在告警列表，syslog 轉發照常進行

#### Scenario: 更新省略門檻保留原值
- **WHEN** 管理員更新一個門檻為 `high` 的通道，請求只含 name、type、enabled（例如切換啟用開關）
- **THEN** 門檻仍為 `high`

#### Scenario: 空值與白名單外值被拒
- **WHEN** 管理員送出 `min_severity: ""` 或 `min_severity: "critical"`
- **THEN** 請求以 4xx＋`VALIDATION_CHANNEL_MIN_SEVERITY` 被拒，通道不被寫入

#### Scenario: 門檻改動留下前後值
- **WHEN** 管理員把通道門檻由 `low` 改為 `high`
- **THEN** 稽核紀錄中有一筆可讀出操作者、通道、改動前 `low` 與改動後 `high`；門檻未改變的更新不產生這筆紀錄

#### Scenario: 系統安全告警不受門檻過濾
- **WHEN** 通道門檻為 `high` 且已啟用，系統先後產生一則分級為 low 與一則分級為 medium 的系統安全告警，同時有一則 medium 的規則告警
- **THEN** 該通道收到兩則系統安全告警，沒有收到那則 medium 規則告警

### Requirement: 通道變更通知新舊目的地與同交易審計

通知通道的建立、修改（含名稱、類型、網址、秘密（簽章密鑰或機器人 token）、目標、語系、推送門檻與啟停）與刪除 SHALL 在單一交易內完成三件事：通道寫入、服務層審計列、一筆通道變更類的系統安全告警。任一步失敗 SHALL 整筆回滾，通道內容、審計與告警皆不留下部分結果。網址、秘密、目標或類型任一變更時，同一交易 SHALL 更新通道的目的地最後變更時間。沒有任何欄位實際變動的重複存檔 SHALL 只寫審計列、SHALL NOT 產生告警。審計列 SHALL 記錄操作者、通道識別、通道名稱、變更型態、變更欄位與遮罩後的前後網址，目標變更時記錄前後目標；傳輸風險確認與推送門檻的前後值 SHALL 併入同一列，SHALL NOT 另以失敗不回滾的方式寫入。審計與告警 SHALL NOT 含簽章密鑰、機器人 token 或完整網址；告警 SHALL 帶通道名稱，使收件人分得出是哪一個通道；告警的 webhook 參數 SHALL 照舊帶遮罩後的前後網址；文字通知在前後網址相同時 SHALL NOT 寫網址那一段。

該告警的投遞目的地 SHALL 為下列三者的聯集，並以相同的類型、網址、秘密與目標去重：其他啟用中的通道、本通道變更前的目的地、本通道變更後的目的地。變更前與變更後的目的地 SHALL 不論本通道當時是否啟用都收到通知，使停用、建立即停用與改址都無法避開舊或新的目的地；網址或秘密無法解開的那一側除外。刪除 SHALL 與保存舊目的地的投遞快照在同一交易完成，通知在提交後自快照送出；重送 SHALL 使用快照，SHALL NOT 以之後的通道設定取代。測試發送不是變更，SHALL NOT 產生此告警。

此機制只讓變更被新舊兩端與審計得知，SHALL NOT 被描述為能阻止具通道管理能力者先改去向再執行其他高危動作；指令告警與系統事件尚未送達的投遞會依通知投遞層的規定使用通道變更後的設定。

#### Scenario: 改網址時新舊兩端都收到
- **WHEN** 持通道管理能力者把啟用中通道的網址由舊址改為新址
- **THEN** 舊址與新址各收到一則通道變更通知，其他啟用通道也收到，且審計列記錄遮罩後的前後網址

#### Scenario: 停用時舊目的地仍收到
- **WHEN** 把一個啟用中的通道停用
- **THEN** 該通道的目的地收到一則通道已停用的通知，之後的一般告警不再送到該通道

#### Scenario: 刪除後仍通知被刪的目的地
- **WHEN** 刪除一個通道
- **THEN** 通道列已不存在，該通道原本的目的地仍收到一則通道已刪除的通知；目的地暫時失敗時重送仍送往原目的地

#### Scenario: 只改名稱不重複送
- **WHEN** 只修改通道名稱或推送門檻
- **THEN** 本通道只收到一則通知，不因前後目的地相同而收到兩則

#### Scenario: 審計或告警寫入失敗即回滾
- **WHEN** 通道修改時審計列或系統安全告警無法寫入
- **THEN** 請求失敗，通道設定、目的地最後變更時間、審計與告警都維持修改前的狀態

#### Scenario: 改目標頻道時新舊頻道都收到
- **WHEN** 持通道管理能力者把一個 `slack_app` 通道的目標由舊頻道改為新頻道，token 不變
- **THEN** 舊頻道與新頻道各收到一則通道變更通知，通知帶通道名稱，審計列記錄前後目標，兩者都不含 token

