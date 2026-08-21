# clipboard-audit

## Purpose

RDP/VNC 剪貼簿內容留存與查詢、SFTP 內容摘要。

## Requirements

### Requirement: 剪貼簿內容留存
RDP/VNC 會話的文字剪貼簿傳輸 SHALL 重組並留存（會話/方向/內容/時間，單筆上限 64KB）；留存失敗 SHALL NOT 中斷會話。

#### Scenario: 使用者複製文字進遠端
- **WHEN** 使用者經剪貼簿送文字至遠端桌面
- **THEN** 產生 direction=send 的留存記錄含完整文字

### Requirement: 剪貼簿記錄查詢
系統 SHALL 提供 `GET /api/v1/sessions/:id/clipboard-events`（audit 權限）按時間序回傳該會話剪貼簿記錄。

剪貼簿記錄 SHALL 另可經稽核調查工作台以**人或資產樞紐加時間窗**聯合查詢——現行 per-session 端點無法回答「這個人那天複製了什麼」與「這台機器上那天有哪些剪貼簿傳輸」。剪貼簿事件本身不帶使用者與資產欄位，其主體歸屬 SHALL 經所屬會話解析，且該解析 SHALL 有索引支撐。

工作台的時間軸 SHALL 僅呈現傳輸方向與所屬會話參照，SHALL NOT 納入剪貼簿內容——內容為明文且不在任何保留政策的清除目標內；完整內容仍只經 per-session 端點取得。

剪貼簿類別目前不受任何保留政策管理（永久留存），工作台 SHALL 將其覆蓋狀態標示為「無保留政策」，SHALL NOT 讓稽核員誤以為空白是清除所致。

#### Scenario: 稽核查詢
- **WHEN** auditor 查詢會話剪貼簿記錄
- **THEN** 回傳時間序列表

#### Scenario: 以人樞紐查得剪貼簿
- **WHEN** 稽核員於工作台以某使用者與某時間窗調查
- **THEN** 該窗內經其會話產生的剪貼簿事件出現於時間軸，標示發生於哪個資產，且不含剪貼簿內容

#### Scenario: 無保留政策誠實標示
- **WHEN** 稽核員檢視剪貼簿類別的覆蓋狀態
- **THEN** 標示為無保留政策（永久留存），而非「已清除」或無標記空白

### Requirement: SFTP 內容摘要
SFTP 上傳與下載 SHALL 於審計記錄附 SHA256 與大小。

#### Scenario: 上傳留摘要
- **WHEN** 使用者上傳檔案
- **THEN** 審計記錄含該檔 SHA256
