# alert-notifications

## Purpose

命令告警經通知通道外送（webhook 通用 JSON+HMAC 簽章、slack mrkdwn）：重試、失敗不影響告警持久化與會話。
## Requirements
### Requirement: Webhook channel management
Admins SHALL manage notification channels (name, type, url, optional secret, enabled) and trigger a test delivery. Invalid URLs MUST be rejected. Channel type SHALL be one of `webhook` or `slack`; unknown types SHALL be rejected. The secret SHALL never be returned to clients; on update, an empty secret SHALL preserve the existing value, and clearing the secret SHALL require an explicit `clear_secret` flag. The secret and HMAC signature SHALL apply only to `webhook` channels; `slack` channels SHALL NOT send a signature and their secret SHALL be forced empty on create/update (has_secret always false).

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

### Requirement: Alert push delivery
When a command alert is created, the system SHALL asynchronously POST a payload to every enabled channel, formatted per channel type, retrying up to 3 times with backoff. `webhook` channels SHALL receive a JSON payload (alert, rule, session context) signed with HMAC-SHA256 in X-OT-Signature when a secret is set. `slack` channels SHALL receive a Slack-compatible message body (`text` field with severity, rule, command, and session context) and SHALL NOT include a signature header. Slack `text` content SHALL escape mrkdwn control characters (`&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`) so that command text containing shell redirection/operators renders correctly. Delivery failures MUST NOT affect alert persistence or sessions.

#### Scenario: Signed webhook delivery
- **WHEN** an alert triggers and a webhook channel has a secret
- **THEN** the receiver gets the JSON payload with a valid HMAC signature header

#### Scenario: Slack-formatted delivery
- **WHEN** an alert triggers and a `slack` channel is enabled
- **THEN** Slack receives a `{"text": ...}` body rendering severity, rule name, command and session context, with no signature header

#### Scenario: Slack command text with shell metacharacters
- **WHEN** an alert for a command containing `>` `<` or `&` is pushed to a `slack` channel
- **THEN** the metacharacters are escaped in the `text` field so Slack renders them literally rather than as link/quote syntax

#### Scenario: Receiver down
- **WHEN** the webhook endpoint is unreachable
- **THEN** the alert is still persisted and retries are logged without session impact

### Requirement: 通知通道傳輸政策門
通知通道建立與更新 SHALL 受通知傳輸政策約束：warn 檔下 URL 為 http 時，儲存 SHALL 要求管理員附風險確認聲明，確認入審計；strict 檔下 http URL SHALL 被拒絕存檔並回明確原因。off 檔（預設）行為與現狀一致（http/https 皆可存）。既有 http 通道在政策收緊後 SHALL 不被自動停用，但 SHALL 在通道列表與通道清冊標示偏離。

#### Scenario: strict 檔拒存 http 通道
- **WHEN** 通知傳輸政策為 strict，管理員儲存 URL 為 http:// 的通道
- **THEN** 存檔被拒，回應明確指出「通知傳輸政策要求 https」

#### Scenario: 政策收緊不自動停用存量通道
- **WHEN** 存在既有 http 通道，政策由 off 調為 strict
- **THEN** 既有通道照常投遞但在列表標示偏離；再次編輯存檔時才受 strict 檔拒絕

### Requirement: 通道語系設定
每個通知通道 SHALL 具備語系欄 `language`，值域為 `zh-TW`／`en-US`／`ja-JP`，並以資料庫 CHECK 約束保障。建立通道未指定語系時 SHALL 預設 `zh-TW`；更新時**省略該欄 SHALL 保留既有值**、傳入空值或白名單以外的值 SHALL 以 `VALIDATION_*` 機器碼拒絕（嚴格匹配，不做大小寫或前綴容錯）。語系 SHALL 僅影響 `slack` 型通道的伺服端組字（經 notifycat 渲染）；`webhook` 型通道可設定但無作用（payload 為機器結構、不含文案），UI SHALL 註明此點。通道快取 SHALL 天然承載此欄，語系變更於快取更新後生效。

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

### Requirement: 系統訊息 payload 結構化
系統類通知 SHALL 以事件＋參數傳遞，SHALL NOT 由呼叫端組出散文再送出：對外介面 SHALL 為 `NotifyEvent(event notifycat.Event, params map[string]string)`，既有 `NotifyMessage(event, title, text)` SHALL 刪除；所有 wrapper（`notify`／`sendNotify`／`NotifyOngoing` 等）簽名 SHALL 同步移除散文參數，使編譯期強制傳播至全部組字點（含 access-request、audit-failure、key-manager-degraded、daily-review 路徑）。

`webhook` 型通道的系統訊息 payload SHALL 為 `{event, params, sent_at}` 形狀，**散文零入 payload**；`slack` 型通道的文案 SHALL 由 notifycat 依通道語系渲染。params 值 SHALL 依 `EventSpec` 的 kind 建模，opaque 值 SHALL 經共用淨化函式處理；去識別紅線不變（事由全文等敏感長文不入 params）。條件分支型文案（如 audit-failure 的 interval 有無）SHALL 以 optional param＋模板 variant 表達，SHALL NOT 於呼叫端以字串拼接處理。

#### Scenario: webhook 系統訊息無散文
- **WHEN** 一筆存取申請被核准並推送至 webhook 通道
- **THEN** 收端取得 `{event: <事件識別字>, params: {...}, sent_at: <時間>}`，payload 內無任何中文或英文散文句

#### Scenario: 同一事件雙通道一致
- **WHEN** 同一事件同時推送至 webhook 與 slack 通道
- **THEN** webhook 收到機器結構、Slack 收到由 notifycat 依該通道語系渲染的文案，兩者事實內容一致

#### Scenario: 組字點於編譯期絕跡
- **WHEN** 開發者嘗試沿用舊寫法傳入預組好的標題與內文
- **THEN** 編譯失敗（`NotifyMessage` 與散文參數已不存在），散文無法重新進入通知鏈

#### Scenario: 條件文案以模板 variant 表達
- **WHEN** audit-failure 通知在有／無 interval 兩種情形下送出
- **THEN** 兩種情形由目錄的兩個模板 variant 渲染（optional param 決定），呼叫端不做字串拼接

### Requirement: 事件規格執行期驗證與未註冊事件降級投遞
每個事件 SHALL 有 `EventSpec` 宣告其參數集合與各參數 kind（`enum`／`int`／`opaque`），並於**執行期驗證**：缺漏必填參數、`enum` 值不在允許清單、`int` 值非整數皆 SHALL 被偵測並記錄。

未在目錄註冊的事件 SHALL NOT 導致通知被拒發或消失（合規告警靜默消失是安全回歸），但降級路徑 SHALL 維持出站去識別紀律：已註冊事件降級（參數違規）時 params SHALL 過濾至 `EventSpec` 宣告鍵；**未註冊事件的 params 值 SHALL 全數剝除**（無契約可依，僅 `{event, degraded: true, sent_at}` 出站），被剔除的鍵名僅記伺服端 log。`slack` 分支 SHALL 以目錄內建的 generic 降級模板**依通道語系**組字（獨立 lexicon 鍵，SHALL NOT 依賴 per-event 鍵）。

#### Scenario: enum 值違規被偵測
- **WHEN** 某事件的 `enum` kind 參數收到允許清單以外的值
- **THEN** 執行期驗證記錄違規（並於測試中失敗），不將未受控值當成合法枚舉傳遞

#### Scenario: 未註冊事件 webhook 降級投遞
- **WHEN** 一個尚未在目錄註冊的事件觸發並推送至 webhook 通道
- **THEN** 收端仍收到 `{event, degraded: true, sent_at}`（params 值已全數剝除），通知不消失，伺服端 log 記錄目錄缺鍵與被剔除的鍵名

#### Scenario: 未註冊事件 Slack 降級渲染
- **WHEN** 同一未註冊事件推送至語系為 `en-US` 的 slack 通道
- **THEN** Slack 收到 generic 降級模板依該通道語系組出的英文訊息（含事件識別字、不含未宣告參數值），而非空訊息或投遞失敗

#### Scenario: 降級不外洩未宣告參數
- **WHEN** 呼叫端誤將 forensic `detail` 之類未宣告鍵放入 params 並因此觸發降級
- **THEN** 該值不出現在 webhook body 與 Slack 文字中，僅於伺服端 log 留鍵名

### Requirement: 測試通知 payload 機器化
通道測試發送 SHALL 不夾帶任何中文散文：`webhook` 分支 SHALL 以機器識別字表達（如 `rule_name: "test"`），payload 內無文案句；`slack` 分支的文案 SHALL 由 notifycat 依該通道語系渲染。測試發送的成敗回報 SHALL 沿用既有錯誤封套語義（失敗回錯誤狀態碼＋registered code）。

#### Scenario: 測試 webhook payload 無中文
- **WHEN** 管理員對 webhook 通道點擊測試發送
- **THEN** 收端 payload 全為機器欄與機器識別字，不含「測試發送」等中文文案

#### Scenario: 測試 Slack 文案依通道語系
- **WHEN** 管理員對語系為 `ja-JP` 的 Slack 通道點擊測試發送
- **THEN** Slack 收到由目錄渲染的日文測試訊息

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

**名稱以解析當下的值呈現，SHALL NOT 被表述為觸發當下的快照**。通知因目的地離線而延後投遞時，期間主體改名會使通知顯示新名稱；識別碼不受影響，故主體的唯一對齊仍成立。此邊界 SHALL 明載，SHALL NOT 僅記於程式碼註解。

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

