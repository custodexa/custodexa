# workspace-tab-status

## Purpose

工作區頁籤的連線狀態呈現：斷線標灰、頁內重連而不關籤。

## Requirements

### Requirement: Tab session status visibility
Workspace tabs SHALL reflect their session state: disconnected or errored sessions SHALL be visually distinguished (grayed with a disconnected hint) while remaining open and switchable for in-place reconnect.

#### Scenario: Disconnected tab grays out
- **WHEN** a session in a background or active tab ends
- **THEN** its tab shows a grayed label with a disconnected hint, stays open, and the panel offers reconnect
