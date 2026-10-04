# session-stats

## Purpose

SSH 會話目標主機即時系統指標。

## Requirements

### Requirement: SSH 會話即時指標
系統 SHALL 對活躍 SSH 會話提供目標主機指標查詢（hostname、uptime、loadavg、記憶體、CPU counters、網路 counters）；僅會話本人、admin 或 auditor SHALL 可查詢；通過資格後的非活躍會話回原 404。會話不存在或使用者不具上述資格時 SHALL 回相同的 404 `NOTFOUND_SESSION` 封套，且 SHALL 在查詢在線狀態或採集指標前拒絕。

#### Scenario: 本人查詢
- **WHEN** 會話擁有者請求該會話 stats
- **THEN** 回傳 200 與指標 JSON

#### Scenario: 他人查詢被拒
- **WHEN** 非擁有者且非 admin／auditor 的使用者請求
- **THEN** 回傳 404，本文為 `{"code":"NOTFOUND_SESSION","error":"Session 不存在"}`，與不存在會話的狀態、機器碼、訊息、欄位及相關標頭相同，不揭露是否在線

#### Scenario: 非 Linux 目標
- **WHEN** 目標主機無 /proc
- **THEN** 回傳 502「目標主機不支援指標採集」

#### Scenario: 不存在與未授權會話的完整回應等價
- **WHEN** 同一一般使用者以合法 ID 分別請求不存在會話及他人的在線或離線會話 stats
- **THEN** 皆回相同的 404 `NOTFOUND_SESSION`，本文只有 `code` 與 `error`，相關內容、快取、驗證與跨來源標頭相同，不查採集能力或回傳指標；前端沿用會話不存在文案

#### Scenario: 既有稽核與管理資格
- **WHEN** admin 或 auditor 請求一個存在且可採集的 SSH 會話 stats
- **THEN** 與會話本人一樣回傳 200 與指標 JSON，不因非擁有者而遭 404 拒絕

#### Scenario: 有資格但會話不在線
- **WHEN** 本人、admin 或 auditor 請求一個存在但不在線的會話 stats
- **THEN** 回原 404 `RULE_SESSION_NOT_ONLINE`，此業務結果只在通過資格後呈現

### Requirement: 工作區監控面板
SSH 會話面板 SHALL 提供監控抽屜：開啟時每 2 秒輪詢並以差分顯示 CPU%/網速；關閉時 SHALL 停止輪詢。

#### Scenario: 開啟面板
- **WHEN** 使用者點「監控」
- **THEN** 抽屜顯示即時指標並持續更新

#### Scenario: 關閉停輪詢
- **WHEN** 抽屜關閉
- **THEN** 不再發出 stats 請求
