# command-blocking

## Purpose

危險指令的連線內即時阻斷。
## Requirements
### Requirement: 指令阻斷
規則 action=block 且互動指令命中時，系統 SHALL 不將該行指令送往目標主機，SHALL 向使用者終端注入可讀警告，SHALL 記錄 blocked 事件並照常推送告警。

阻斷所產生的告警 SHALL 經與比對路徑相同的告警寫入介面落地，SHALL NOT 直接寫入告警資料表而繞過該介面——繞過會使阻斷告警不進入外送鏈，導致「被阻斷的危險指令」這類最高價值的證據只存在本機一份。經統一介面後，阻斷告警 SHALL 與比對告警同樣受既有 syslog 轉發規則涵蓋（轉發啟用時，阻斷告警於資料庫寫入成功後 SHALL 被轉發至 syslog 目的地）。

阻斷告警的紀錄內容 SHALL 與比對告警同構：SHALL 帶命中規則名稱、處置欄與所屬資產（資產可為空時 SHALL 以可辨識「無值」的形態儲存，SHALL NOT 以 0 代表無值）；兩條路徑的處置欄語義 SHALL 一致，SHALL NOT 一條留空一條填值。批次產生的告警 SHALL 以批次介面一次寫入，SHALL NOT 被拆成逐筆寫入。告警寫入介面未被注入時系統 SHALL 啟動失敗，SHALL NOT 降級為無操作而靜默丟棄阻斷告警。

改密流程借用告警通道傳遞失敗通知的既有路徑（不入庫、不轉發）SHALL NOT 被併入本介面，以免產生無對應規則的幽靈告警紀錄。

#### Scenario: 阻斷危險指令
- **WHEN** 使用者鍵入命中 block 規則的指令並按 Enter
- **THEN** 指令不在目標執行、終端顯示阻斷警告、審計含 blocked 記錄

#### Scenario: alert 規則不受影響
- **WHEN** 指令命中 action=alert 規則
- **THEN** 行為與現行一致（執行+告警）

#### Scenario: 阻斷告警外送 syslog
- **WHEN** syslog 轉發已啟用，且使用者鍵入命中 block 規則的指令
- **THEN** 該阻斷告警寫入資料庫後被轉發至 syslog 目的地，與比對路徑產生的告警同軌，不再只存本機一份

#### Scenario: 兩條路徑的告警欄位同構
- **WHEN** 分別由阻斷路徑與比對路徑針對同一規則產生告警
- **THEN** 兩筆紀錄皆帶規則名稱、處置欄與資產欄，處置欄語義一致；資產不適用時該欄為可辨識的無值而非 0

#### Scenario: 告警介面未注入即啟動失敗
- **WHEN** 組裝層未注入告警寫入介面
- **THEN** 服務啟動失敗，SHALL NOT 以無操作實作啟動而使阻斷告警靜默消失

### Requirement: 阻斷比對協議分流
指令阻斷（command-blocking）的規則比對 SHALL 依當前會話協議分流，僅以適用該協議的 block 規則進行；阻斷器 SHALL 取得會話協議（由 asset.Protocol 注入）以供比對。此確保 shell block 規則不誤攔 DB 會話、DB block 規則不誤攔 shell 會話。

#### Scenario: DB 會話不套 shell block 規則
- **WHEN** 一條 ssh,k8s 限定的 block 規則存在，且使用者在 mysql 會話送出含相同字面值的 SQL
- **THEN** 該 SQL 不被該 shell 規則阻斷

