# graphics-clipboard

## Purpose

RDP/VNC 圖形會話的雙向剪貼簿傳輸與內容審計。

## Requirements

### Requirement: Bidirectional text clipboard sync
RDP and VNC sessions SHALL synchronize plain-text clipboard content in both directions **subject to the data-transfer clipboard capabilities**: remote copy events SHALL be written to the local browser clipboard only when the effective `clipboard_recv_enabled` capability is true, and local clipboard content SHALL be sent to the remote session when the window regains focus only when the effective `clipboard_send_enabled` capability is true. Enforcement SHALL be performed by guacd via the `disable-copy` / `disable-paste` connection parameters, which SHALL be sent explicitly for both RDP and VNC rather than relying on guacd defaults; the browser-side controls SHALL reflect the capability but SHALL NOT be the enforcement point. Because these are connection parameters, a policy change SHALL NOT affect a session already in progress, and the UI SHALL state that reconnection is required. Clipboard failures (permission denied, unsupported browser) MUST degrade silently without affecting the session.

#### Scenario: Remote copy reaches local clipboard
- **WHEN** the user copies text inside the remote desktop session and the effective `clipboard_recv_enabled` capability is true
- **THEN** the same text becomes available in the local browser clipboard (immediately, or upon next window focus if the page was unfocused)

#### Scenario: Local copy reaches remote session
- **WHEN** the user copies text locally, the effective `clipboard_send_enabled` capability is true, and the user refocuses the session window and pastes inside the remote desktop
- **THEN** the remote paste yields the locally copied text

#### Scenario: Receive disabled blocks remote-to-local
- **WHEN** the effective `clipboard_recv_enabled` capability is false and the user copies text inside the remote desktop
- **THEN** the text does not reach the local clipboard, and the session is otherwise unaffected

#### Scenario: Send disabled blocks local-to-remote
- **WHEN** the effective `clipboard_send_enabled` capability is false and the user attempts to paste into the remote desktop
- **THEN** the content does not reach the remote session, and the paste control is presented as unavailable with a reason

#### Scenario: Policy change requires reconnection
- **WHEN** an administrator disables a clipboard capability while a session is in progress
- **THEN** the in-progress session keeps its original clipboard behaviour and the UI states that reconnection is required

#### Scenario: Permission denied degrades silently
- **WHEN** the browser denies clipboard read permission
- **THEN** the session continues to work normally and remote-to-local sync still functions where allowed

### Requirement: Clean connection interface
Internal debug information (frontend build version, client state, last message) SHALL NOT be visible in production builds; it MAY be shown in development mode.

#### Scenario: Production build hides debug block
- **WHEN** a user opens an RDP/VNC session in a production build
- **THEN** the toolbar shows only connection controls and status, with no debug information block
