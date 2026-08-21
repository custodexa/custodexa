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

