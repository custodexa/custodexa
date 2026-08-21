# vnc-protocol

## Purpose

VNC 資產經 guacd 的圖形協議連線與憑證收口：資產管理與連線參數校驗、後端與 guacd 完成握手後升級 WebSocket 的純轉發通道、桌面會話錄影與回放，以及可在專案環境內完整驗證 VNC 連通性的本地驗證環境。前端零接觸明文憑證，連線一律經後端收口。

## Requirements

### Requirement: VNC asset management
The system SHALL allow creating, updating, and listing assets with protocol `vnc`, defaulting the port to 5900, storing the VNC password encrypted like other credentials.

#### Scenario: Create VNC asset
- **WHEN** an admin creates an asset with protocol vnc, host, port and password
- **THEN** the asset is persisted with encrypted credentials and listed with a VNC protocol tag

### Requirement: VNC session via guacd
The connection proxy SHALL establish VNC sessions through guacd using the same WebSocket tunnel as RDP, applying sane defaults (color depth, clipboard enabled) when not specified.

#### Scenario: Connect to VNC asset
- **WHEN** an authorized user opens a terminal session for a VNC asset
- **THEN** the remote desktop renders in the browser and mouse/keyboard input works

#### Scenario: Unauthorized user blocked
- **WHEN** a user without authorization for the VNC asset attempts to connect
- **THEN** the connection is rejected consistently with existing asset authorization rules

### Requirement: VNC session recording and playback
VNC sessions SHALL be recorded using Guacamole native recording (same mechanism as RDP) and be playable from the session detail page.

#### Scenario: Recorded VNC session playback
- **WHEN** a completed VNC session with recording is opened in session detail
- **THEN** the existing Guacamole player replays the desktop session

### Requirement: Local verification environment
The docker-compose stack SHALL include a vnc-test service so VNC connectivity can be verified entirely inside the project environment.

#### Scenario: E2E verification
- **WHEN** the VNC scenario of `scripts/e2e_smoke.sh` runs against the compose stack
- **THEN** it creates a VNC asset, establishes a guacd session that receives a sync frame (not merely TCP reachability), persists the session with the correct protocol and a closed final status, and verifies recording-path normalization and audit — repeatably
