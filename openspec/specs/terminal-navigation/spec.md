# terminal-navigation

## Purpose

終端頁面的導覽與返回系統互動。

## Requirements

### Requirement: Tab-model session entry
Opening a session from the asset list SHALL open the multi-session workspace in a new browser tab, leaving the bastion system page intact in the original tab. Users MUST NOT lose the system page by starting a session.

#### Scenario: Connect keeps the system page
- **WHEN** the user clicks connect on an asset in the asset list
- **THEN** the workspace opens in a new browser tab with the session active and the asset list remains in the original tab

### Requirement: Session page header
The terminal page SHALL display a persistent slim header showing the brand (linking back to the system in a new tab), the asset name and protocol, and session tools (file manager for SSH), in every state.

#### Scenario: Direct-URL user returns to system
- **WHEN** a user who entered the terminal page by direct URL clicks the brand in the header
- **THEN** the bastion system opens in a new tab and the session stays alive

#### Scenario: Disconnect screen offers actions
- **WHEN** an SSH session ends
- **THEN** the disconnect screen offers reconnect and a return-to-system action

### Requirement: Accidental close protection
While a session is connected, closing or reloading the tab SHALL trigger a browser confirmation. The guard MUST be released once the session has ended.

#### Scenario: Close confirmation while connected
- **WHEN** the user closes the tab during an active SSH session
- **THEN** the browser asks for confirmation before leaving

### Requirement: Monitor page return
The monitor page SHALL provide a back action returning to the sessions list.

#### Scenario: Return from monitoring
- **WHEN** an auditor clicks back on the monitor page
- **THEN** the app navigates to the sessions list
