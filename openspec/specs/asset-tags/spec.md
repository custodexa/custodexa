# asset-tags

## Purpose
資產標籤作為靜態挑選輔助的完整生命週期：儲存正規化（canonical 鍵＋書寫歸一）、列表顯示、整詞篩選（萬用字元跳脫）、清單端點（含使用數）、輸入輔助（自動完成＋相似確認）與治理（全面改名/合併/刪除）。標籤僅限 admin/auditor 篩選使用，且不是授權客體（動態標籤授權為明確非目標）。
## Requirements
### Requirement: 標籤儲存正規化
資產建立與更新時，系統 SHALL 對 tags 欄位正規化：以逗號切分、逐項 trim、去除空項、以 canonical 鍵（NFC＋大小寫折疊）去除重複（保留首見書寫形）後重新以逗號串接存入；存入的標籤與全庫既有標籤 canonical 相等時 SHALL 歸一為既有書寫形。標籤 SHALL 符合文法上限：單項至多 64 字元、每資產至多 20 項、序列化總長至多 500 字元，違規 SHALL 回 400；標籤內容 SHALL NOT 含半形逗號。該正規化 SHALL 為冪等：對已正規化的值再次儲存，結果與前次相同。正規化 SHALL 由寫入路徑單獨承擔，SHALL NOT 依賴任何一次性的存量資料遷移——schema 由單一 baseline 定義，不存在需要事後補正的既有標籤形態。

#### Scenario: 建立時正規化
- **WHEN** 管理者以「生產, 資料庫,,生產」建立資產
- **THEN** 落庫 tags 為「生產,資料庫」

#### Scenario: 大小寫歸一至既有書寫
- **WHEN** 全庫已有標籤「DBA」，管理者將另一資產標籤存為「Dba」
- **THEN** 該資產落庫標籤為「DBA」（歸一為既有書寫形），標籤清單不出現「Dba」

#### Scenario: 文法上限拒絕
- **WHEN** 管理者送出 21 個標籤、或單一標籤 65 字元、或序列化總長超過 500
- **THEN** 回 400 且不落庫

#### Scenario: 正規化冪等
- **WHEN** 以已正規化的「生產,資料庫」再次更新同一資產
- **THEN** 落庫 tags 仍為「生產,資料庫」，結果與前次相同

### Requirement: 資產列表標籤顯示
資產管理列表 SHALL 顯示標籤欄：以 chips 呈現，最多顯示 2 個，超出部分以「+N」收納並可於 tooltip 檢視全部；無標籤資產 SHALL 顯示「—」。標籤欄對全部角色可見。

#### Scenario: 多標籤收納
- **WHEN** 資產有 4 個標籤
- **THEN** 標籤欄顯示前 2 個 chips 與「+2」，tooltip 可見全部 4 個

#### Scenario: 無標籤
- **WHEN** 資產 tags 為空
- **THEN** 標籤欄顯示「—」

### Requirement: 資產列表按標籤篩選
`GET /api/v1/assets` SHALL 對 admin/auditor 支援 `tags` 查詢參數（逗號分隔多值）：每個標籤以整詞比對（不得以子字串誤中；`%`、`_`、`\` SHALL 經跳脫處理並以 `ESCAPE '\'` 比對，不得被解讀為萬用字元）、大小寫不敏感；多標籤為 AND 語義；空 token SHALL 丟棄、標籤數超過 20 SHALL 回 400。`tags` SHALL 可與 `search`/`protocol`/`node_id`/`include_subtree`/`ungrouped`/`active` 疊加；篩選 SHALL 於 COUNT 與分頁前生效。非 admin/auditor 角色帶 `tags` 參數 SHALL 回 400（不得靜默忽略）。前端標籤篩選下拉 SHALL 僅對 admin/auditor 渲染。

#### Scenario: 整詞比對不誤中
- **WHEN** 存在標籤「生產」與「非生產」的兩筆資產，請求 `tags=生產`
- **THEN** 僅回傳標籤含「生產」整詞者，「非生產」者不出現

#### Scenario: 萬用字元不生效
- **WHEN** 存在標籤「db_prod」與「dbxprod」的兩筆資產，admin 請求 `tags=db_prod`
- **THEN** 僅回傳「db_prod」者，「dbxprod」不出現（底線不作萬用字元）

#### Scenario: 多標籤 AND
- **WHEN** 請求 `tags=生產,資料庫`
- **THEN** 僅回傳同時含兩個標籤的資產

#### Scenario: 與節點過濾疊加
- **WHEN** 請求同時帶 `node_id`（含子樹）與 `tags=生產`
- **THEN** 回傳該節點子樹內且含「生產」標籤的資產，總數與分頁反映疊加後結果

#### Scenario: 非特權角色明確拒絕
- **WHEN** 一般使用者請求 `GET /api/v1/assets?tags=生產`
- **THEN** 回 400

### Requirement: 標籤清單端點
系統 SHALL 提供 `GET /api/v1/assets/tags`：回傳既有標籤清單（canonical 去重、升冪排序）與每標籤使用數（含該標籤的資產數），由全表 tags 動態彙整（不建獨立 tag 表）。端點權限 SHALL 為 admin/auditor；一般使用者 SHALL 被拒（403，不得洩漏未授權資產的標籤詞彙）。

#### Scenario: 彙整去重含使用數
- **WHEN** 兩筆資產分別存「生產,資料庫」與「生產,快取」
- **THEN** 端點回傳「快取(1)、生產(2)、資料庫(1)」（去重、排序、附使用數）

#### Scenario: auditor 可用
- **WHEN** auditor 呼叫標籤清單端點
- **THEN** 回 200 與完整清單

#### Scenario: 一般使用者拒絕
- **WHEN** 一般使用者呼叫標籤清單端點
- **THEN** 回 403

### Requirement: 標籤輸入輔助
資產表單的標籤輸入 SHALL 為多選元件：提供既有標籤自動完成（來源為標籤清單端點、過濾大小寫不敏感）並允許即時建立新標籤；建立的新值與既有標籤 canonical 相等或互為包含時 SHALL 先顯示相似既有標籤並要求確認；含半形逗號的標籤值 SHALL 拒絕建立；送出時 SHALL 序列化回逗號分隔字串。資產頁篩選、授權精靈標籤篩選與表單輸入 SHALL 共用同一標籤清單來源。

#### Scenario: 既有標籤自動完成（大小寫不敏感）
- **WHEN** 管理者於表單標籤欄輸入「dba」
- **THEN** 下拉出現既有標籤「DBA」可直接選取

#### Scenario: 相似標籤確認
- **WHEN** 管理者輸入「DBA專用」而既有清單含「DBA」
- **THEN** 顯示相似既有標籤「DBA」並要求確認後才建立新標籤

#### Scenario: 新標籤即建
- **WHEN** 管理者輸入清單中無相似項的「測試中」並確認
- **THEN** 「測試中」成為該資產標籤並隨儲存落庫

### Requirement: 標籤治理
系統 SHALL 提供 admin 專用的標籤治理功能（資產頁工具列單獨入口）：標籤總覽（含使用數）、全面改名（from→to 套用至所有含 from 的資產；to 與既有標籤 canonical 相等時即為合併，逐資產 canonical 去重）、刪除（自所有資產移除該標籤）。三操作 SHALL 於執行前顯示受影響資產數並二次確認；SHALL 於單一交易內完成；SHALL 逐受影響資產產生帶操作者身分的審計記錄。治理端點權限 SHALL 為 admin（auditor 與一般使用者 403）。

#### Scenario: 全面改名
- **WHEN** admin 將標籤「DbA標籤」改名為「DBA」，3 筆資產含「DbA標籤」
- **THEN** 3 筆資產的「DbA標籤」全部變為「DBA」，標籤清單不再出現「DbA標籤」

#### Scenario: 合併去重
- **WHEN** admin 將「Dba」改名為既有標籤「DBA」，且某資產同時含「Dba」與「DBA」
- **THEN** 該資產僅保留一個「DBA」（無重複項）

#### Scenario: 刪除標籤
- **WHEN** admin 刪除標籤「廢棄」，5 筆資產含該標籤
- **THEN** 5 筆資產的 tags 均移除「廢棄」，其餘標籤不受影響

#### Scenario: 非 admin 拒絕
- **WHEN** auditor 或一般使用者呼叫治理端點
- **THEN** 回 403

