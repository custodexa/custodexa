# session-monitor

## Purpose

進行中會話的即時唯讀監看，供稽核員旁路觀察。
## Requirements
### Requirement: Read-only live SSH session monitoring
The system SHALL allow admin and auditor roles to watch an active SSH session's terminal output in real time over a read-only WebSocket. Observer input MUST NOT reach the session. Observer connections and disconnections MUST NOT disrupt the monitored session.

#### Scenario: Auditor watches a live session
- **WHEN** an auditor opens the monitor view for an active SSH session while the session user runs commands
- **THEN** the commands and their output appear in the auditor's read-only terminal in near real time

#### Scenario: Non-privileged role rejected
- **WHEN** a regular user opens the monitor WebSocket for any session
- **THEN** the connection is rejected with a permission error

#### Scenario: Observer cannot inject input
- **WHEN** an observer sends data messages over the monitor WebSocket
- **THEN** the messages are ignored and nothing reaches the session's PTY

### Requirement: Mid-stream join context
An observer joining an in-progress session SHALL receive a tail replay buffer of recent output before live streaming begins, and SHALL receive the session's terminal dimensions.

#### Scenario: Join mid-session
- **WHEN** an auditor starts monitoring after the session has produced output
- **THEN** the observer terminal shows recent prior output followed by the live stream

### Requirement: Session end notification
When the monitored session ends, observers SHALL be notified and the monitor stream SHALL close.

#### Scenario: Session closes during monitoring
- **WHEN** the monitored session disconnects
- **THEN** the observer sees an end-of-session notice and the monitor WebSocket closes

### Requirement: 監看以一次性觀看票認證

即時監看的 WebSocket SHALL 只接受一次性觀看票，SHALL NOT 自 query 參數接受登入憑證。
票由掛認證 middleware 的簽發端點發出，其准入判定（角色、目標會話存在且為進行中的文字
終端）SHALL 於簽發時完成，角色 SHALL 以現時有效角色判定，SHALL NOT 採信憑證所攜帶的
角色快照。

票 SHALL 為短效且單次：兌換成功即失效，SHALL 綁定簽票者身分與目標會話。缺票、無效票、
過期票、重放票，以及用途或客體不符的票，對外 SHALL 收斂為同一則憑證無效回應（不提供
票證存在性的探測面），審計 SHALL 分得出其成因。

兌換 SHALL 把簽票當下的認證脈絡帶入觀察者訂閱，使身分來源停用與憑證世代推進的收線判定
對監看連線同樣有效。

#### Scenario: 監看須先取票

- **WHEN** 稽核者開啟某進行中會話的監看
- **THEN** 前端先向簽發端點取得一次性觀看票，WebSocket 網址只帶該票、不含登入憑證

#### Scenario: 非稽核職能取不到票

- **WHEN** 一般使用者向監看票簽發端點請求票證
- **THEN** 回權限錯誤且不產生任何票證

#### Scenario: 現時角色為準

- **WHEN** 憑證所攜角色為管理員，但該帳號的現時有效角色已被降權
- **THEN** 簽發被拒（角色以現時查得者為準）

#### Scenario: 票不得重放

- **WHEN** 同一張觀看票被使用第二次
- **THEN** 該次連線被拒，且拒絕留痕註明成因

#### Scenario: 票不得換用途或換客體

- **WHEN** 以分享觀看票、終端連線票，或為另一場會話簽出的監看票開啟監看
- **THEN** 連線被拒，對外回應與無效票相同，審計註明為用途或客體不符

### Requirement: 監看加入留痕

即時監看他人會話 SHALL 寫入審計列，記錄監看者身分、被監看的會話與資產、來源位址與加入時間。

留痕 SHALL 由 handler 寫入——監看連線的身分於 handler 內自解析，審計中介層在此路徑取不到身分。

此為特權存取管理的核心稽核項：管理員可即時旁觀他人操作，該行為無痕即無從課責。

#### Scenario: 監看加入產生審計列

- **WHEN** 具權限者加入某進行中會話進行唯讀監看
- **THEN** audit_logs 新增一筆列，可查明誰於何時監看了哪個會話與資產

#### Scenario: 稽核可回答誰看過誰

- **WHEN** 稽核查詢某會話期間是否曾被旁觀
- **THEN** 審計記錄提供全部監看者身分與加入時間

