# terminal-snippets

## Purpose

使用者命令片段的管理與終端注入。

## Requirements

### Requirement: 片段管理（user-scoped）
系統 SHALL 提供使用者範圍的命令片段 CRUD；使用者 SHALL NOT 能讀取或變更他人片段；content 長度 SHALL 限制於 4096 字元內。

#### Scenario: 建立與列表
- **WHEN** 使用者建立片段（name+content）後查詢列表
- **THEN** 僅回傳該使用者的片段

#### Scenario: 越權防護
- **WHEN** 使用者嘗試刪除他人片段 ID
- **THEN** 回應 404，且資料不受影響

### Requirement: 片段注入終端
SSH 會話面板 SHALL 提供片段抽屜（搜尋/列表/使用）；「使用」SHALL 將 content 寫入當前終端輸入而 SHALL NOT 自動執行（不附換行）。

#### Scenario: 使用片段
- **WHEN** 使用者於 SSH 頁籤開啟片段抽屜並點「使用」
- **THEN** content 出現於終端輸入游標處，未送出執行
