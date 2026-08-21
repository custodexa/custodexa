# host-key-verification

## Purpose

SSH host key 的 TOFU 記錄、變更拒線與管理。
## Requirements
### Requirement: TOFU host key 記錄
SSH 連線（含 SFTP）SHALL 驗證目標主機金鑰：資產首次連線 SHALL 記錄演算法與 SHA256 指紋；既有記錄且指紋相符 SHALL 放行。

#### Scenario: 首連記錄
- **WHEN** 資產首次 SSH 連線成功
- **THEN** 該資產的 host key 指紋被記錄，後續相同金鑰連線放行

### Requirement: 金鑰變更拒線
記錄存在但指紋不符時，連線 SHALL 被拒絕並回覆可讀錯誤（提示可能的中間人攻擊與重置途徑）；SHALL NOT 自動覆蓋舊指紋。拒線原因 SHALL 以機器可讀 code（`RULE_SSH_HOST_KEY_CHANGED`）送達前端終端 UI 並以當前語言顯示；終端錯誤畫面 SHALL 依角色引導重置途徑——admin SHALL 獲得直達該資產編輯框主機金鑰區塊的入口，非 admin SHALL 獲得聯繫管理員的提示。

#### Scenario: 指紋不符
- **WHEN** 目標主機金鑰與記錄不符
- **THEN** 連線拒絕，錯誤訊息含「主機金鑰已變更」

#### Scenario: admin 獲得重置入口引導
- **WHEN** admin 使用者的終端連線因 host key 變更被拒
- **THEN** 終端錯誤畫面顯示當前語言的原因說明與「前往資產設定重置主機金鑰」入口，點擊後到達該資產的編輯框主機金鑰區塊

#### Scenario: 非 admin 獲得聯繫管理員提示
- **WHEN** 非 admin 使用者的終端連線因 host key 變更被拒
- **THEN** 終端錯誤畫面顯示當前語言的原因說明與聯繫管理員重置的提示，不出現重置入口

#### Scenario: 深連結不洩漏未授權資產
- **WHEN** 使用者以資產編輯深連結（`/assets?edit=<id>`）指向其無可視授權的資產
- **THEN** 前端現查該資產得 404 後提示資產不存在並清除參數，不洩漏資產存在性

### Requirement: host key 管理
系統 SHALL 提供 `GET /api/v1/assets/:id/host-key`（檢視指紋）與 `DELETE`（僅 admin，重置後下次連線重新記錄）。GET 對非 admin/auditor 角色 SHALL 要求對該資產有可視授權（view 或更高），未授權 SHALL 回 404「資產不存在」——不得經 host key 端點洩漏未授權資產的存在性或指紋。

#### Scenario: admin 重置
- **WHEN** admin DELETE 資產 host key 後重新連線
- **THEN** 連線成功並記錄新指紋

#### Scenario: 未授權者不可見指紋
- **WHEN** 一般使用者對資產 A 無任何授權並呼叫 `GET /api/v1/assets/A/host-key`
- **THEN** 回 404「資產不存在」，不洩漏 A 是否存在或有無 host key 記錄

#### Scenario: 授權者可見指紋
- **WHEN** 一般使用者對資產 A 有 view（或更高）授權並呼叫 `GET /api/v1/assets/A/host-key`
- **THEN** 有記錄回 200 與演算法/指紋；無記錄回 404「尚無 host key 記錄」

