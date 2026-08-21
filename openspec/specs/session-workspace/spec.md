# session-workspace

## Purpose

多會話工作區：側欄資產列表、保活頁籤、斷線標灰與重連。

## Requirements

### Requirement: Multi-session workspace
The system SHALL provide a workspace page with a slim header, a collapsible asset sidebar and a session tab area. Selecting an asset in the sidebar SHALL open a new session tab and activate it. Multiple sessions (including the same asset twice, and mixed protocols) SHALL run concurrently.

#### Scenario: Open multiple sessions
- **WHEN** the user opens two SSH assets and one VNC asset from the sidebar
- **THEN** three tabs exist, each with its own live session

### Requirement: Tab switching preserves sessions
Switching tabs MUST NOT disconnect or reset the underlying sessions; returning to a tab SHALL show the session in its previous state and re-fit terminal dimensions.

#### Scenario: Switch away and back
- **WHEN** the user runs a command in tab A, switches to tab B, then returns to tab A
- **THEN** tab A still shows the command output and accepts input without reconnecting

### Requirement: Closing a tab ends its session
Closing a session tab SHALL cleanly terminate that session (WebSocket closed, recording finalized) without affecting other tabs.

#### Scenario: Close one of several tabs
- **WHEN** the user closes tab B while tab A is active elsewhere
- **THEN** tab B's session ends and tab A remains connected

### Requirement: Workspace entry
The asset list connect action SHALL open the workspace in a new browser tab with the chosen asset auto-opened as the first session tab. The legacy single-session terminal route SHALL remain functional.

#### Scenario: Connect from asset list
- **WHEN** the user clicks connect on an asset
- **THEN** a workspace opens in a new browser tab with that asset's session active, and the asset list stays in the original tab

### Requirement: 頁籤拖曳排序
工作區頁籤 SHALL 支援水平拖曳重排；重排 SHALL 僅變更頁籤順序，不中斷任何會話連線，且當前啟用頁籤維持不變。

#### Scenario: 拖曳重排
- **WHEN** 使用者將頁籤拖曳至新位置放開
- **THEN** 頁籤列依新順序顯示，所有會話（含被拖曳者）連線保持

#### Scenario: 拖曳不誤觸切換
- **WHEN** 使用者點擊頁籤（未達拖曳延遲）
- **THEN** 正常切換頁籤，不觸發排序

### Requirement: 頁籤右鍵選單
頁籤標籤 SHALL 提供右鍵選單：重新連線、複製會話、關閉、關閉其他、關閉左側、關閉右側、關閉全部；操作 SHALL 僅影響目標頁籤集合，其餘會話連線不中斷。

#### Scenario: 重新連線
- **WHEN** 對頁籤選「重新連線」
- **THEN** 該頁籤面板重建並重新撥接，其他頁籤會話不受影響

#### Scenario: 關閉其他
- **WHEN** 對頁籤 B 選「關閉其他」（存在 A/B/C）
- **THEN** 僅 B 保留且為啟用頁籤

#### Scenario: 複製會話
- **WHEN** 對頁籤選「複製會話」
- **THEN** 以同一資產開啟新頁籤並啟用，原頁籤連線保持
