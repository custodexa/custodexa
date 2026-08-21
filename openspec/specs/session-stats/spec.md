# session-stats

## Purpose

SSH 會話目標主機即時系統指標。

## Requirements

### Requirement: SSH 會話即時指標
系統 SHALL 對活躍 SSH 會話提供目標主機指標查詢（hostname、uptime、loadavg、記憶體、CPU counters、網路 counters）；僅會話本人或 admin SHALL 可查詢；非活躍會話回 404。

#### Scenario: 本人查詢
- **WHEN** 會話擁有者請求該會話 stats
- **THEN** 回傳 200 與指標 JSON

#### Scenario: 他人查詢被拒
- **WHEN** 非擁有者非 admin 請求
- **THEN** 回傳 403 統一錯誤封套

#### Scenario: 非 Linux 目標
- **WHEN** 目標主機無 /proc
- **THEN** 回傳 502「目標主機不支援指標採集」

### Requirement: 工作區監控面板
SSH 會話面板 SHALL 提供監控抽屜：開啟時每 2 秒輪詢並以差分顯示 CPU%/網速；關閉時 SHALL 停止輪詢。

#### Scenario: 開啟面板
- **WHEN** 使用者點「監控」
- **THEN** 抽屜顯示即時指標並持續更新

#### Scenario: 關閉停輪詢
- **WHEN** 抽屜關閉
- **THEN** 不再發出 stats 請求
