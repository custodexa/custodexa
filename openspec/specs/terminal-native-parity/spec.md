# terminal-native-parity Specification

## Purpose
定義 SSH web 終端達到原生終端等效體驗（native parity）的行為基準，涵蓋七個面向：剪貼簿雙向逐字元保真、視窗尺寸適配與 resize 重排（SIGWINCH）、檔案上傳逐位元組保真、中文 IME 組字上屏、特殊鍵與控制序列傳遞、終端顏色（ANSI 16／256／truecolor）渲染保真、斷線後重連與狀態保留語義。凡行為可被自動斷言者（例如上傳後遠端 sha256 相符、文字逐字元相等、特殊鍵碼到達）以自動化測試驗證；不可化約的真實感（選取手感、延遲體感、IME 組字過程、整體配色觀感）屬人工驗證範疇。

## Requirements
### Requirement: SSH 終端剪貼簿雙向保真

SSH web 終端的剪貼簿 SHALL 雙向保真至原生級:終端→本機與本機→終端的內容 MUST 逐字元一致(含中文、Tab、特殊字元),正規化規則為 trailing space / CRLF↔LF / 軟換行 reflow 不計差異。

#### Scenario: 終端→本機 複製保真
- **WHEN** 在 web 終端選取一段含中文與特殊字元的文字並複製,貼到本機編輯器
- **THEN** 貼出內容 SHALL 與遠端來源逐字元相等(經正規化);驗證以注入並讀回 xterm buffer 比對,不走 OS 系統剪貼簿

#### Scenario: 本機→終端 貼上保真
- **WHEN** 將本機一段多行文字貼入 web 終端
- **THEN** 終端收到的內容 SHALL 與來源逐字元相等,且 SHALL 套用 bracketed-paste,避免多行貼上被自動逐行執行

#### Scenario: 選取與複製手感如原生
- **WHEN** 檢視選取/複製互動的操作手感
- **THEN** 是否「選了就有」、是否需額外快捷鍵等手感屬人工驗證範疇

### Requirement: SSH 終端解析度與尺寸適配

SSH web 終端 SHALL 在初次連線與視窗變動時正確適配尺寸:終端 cols/rows MUST 對應可視區域,且 resize 後遠端 SHALL 收到正確的視窗尺寸並正確重排。

#### Scenario: 初次連線尺寸正確
- **WHEN** 初次連上 SSH 並在遠端執行 `stty size`
- **THEN** 回報的 rows/cols SHALL 與前端終端可視區域一致

#### Scenario: 視窗 resize 後正確重排
- **WHEN** 調整瀏覽器視窗/終端容器大小
- **THEN** 遠端 SHALL 收到更新後的尺寸(SIGWINCH),且畫面 SHALL 無錯位、無殘影、無截斷(重排後的視覺完整性屬人工驗證範疇)

### Requirement: SSH 檔案上傳保真

透過 SSH 連線上傳檔案到遠端機器 SHALL 保真:上傳完成後遠端檔案內容 MUST 與來源逐位元組一致。

#### Scenario: 上傳後遠端內容相符
- **WHEN** 經 SFTP 上傳一個檔案到遠端
- **THEN** 遠端檔案的 sha256 SHALL 與本機來源相符,且大小一致

### Requirement: SSH 中文輸入（IME）

SSH web 終端 SHALL 支援中文輸入達原生級:經 IME(注音/拼音)組字後,上屏字元 MUST 正確送達遠端。組字過程本身屬自動化測不準範疇,歸人工驗證。

#### Scenario: 組字上屏後字元正確
- **WHEN** 經 IME 輸入一段中文並上屏
- **THEN** 遠端收到的字元 SHALL 與預期中文逐字元相等(註:此僅驗上屏結果,不等於測到組字過程)

#### Scenario: 組字過程屬人工驗證範疇
- **WHEN** 驗證注音/拼音組字過程(候選窗出現、上屏時機、組字中游標)
- **THEN** 該過程屬人工驗證範疇——自動化輸入注入通常繞過 IME composition,無法涵蓋組字過程本身

### Requirement: SSH 特殊鍵傳遞

SSH web 終端 SHALL 將常用特殊鍵正確傳達遠端達原生級:Ctrl/Alt 組合鍵、方向鍵、Fn 鍵 MUST 送達並產生與原生終端一致的效果;被瀏覽器/OS 攔截的鍵(如 Ctrl+Alt+Del)SHALL 經人工確認其行為或限制。

#### Scenario: 一般特殊鍵到達遠端
- **WHEN** 送出 Ctrl-C、Ctrl-Z、方向鍵、Fn 等特殊鍵
- **THEN** 遠端 SHALL 收到對應控制序列並產生與原生終端一致的效果

#### Scenario: 被攔截鍵的行為確認
- **WHEN** 嘗試 Ctrl+Alt+Del 等被瀏覽器/OS 攔截的鍵
- **THEN** 其行為或限制 SHALL 經人工確認並如實記錄,不得僅憑自動化斷言綠燈即宣稱支援

### Requirement: SSH 終端顏色保真

SSH web 終端 SHALL 正確渲染終端顏色達原生級:ANSI 16 色、256 色、truecolor 的色碼 MUST 渲染為正確色值;顏色觀感保真屬人工範疇。

#### Scenario: 色碼正確渲染
- **WHEN** 遠端輸出 ANSI / 256 色 / truecolor 轉義序列
- **THEN** xterm 渲染出的對應 DOM 樣式色值 SHALL 與色碼一致

#### Scenario: 顏色觀感保真
- **WHEN** 對比 web 終端與原生終端的整體配色觀感
- **THEN** 觀感保真屬人工驗證範疇

### Requirement: SSH 斷線重連

SSH web 終端 SHALL 在連線中斷後正確重連並具明確的狀態保留語義:重連 MUST 恢復可用連線;重連後的狀態保留範圍(session/PTY 內容、游標、scrollback、執行中程式)SHALL 以明確語義定義並驗證。

#### Scenario: 中斷後自動重連
- **WHEN** 連線(WebSocket)中斷後恢復
- **THEN** 系統 SHALL 自動重連並恢復可輸入的終端

#### Scenario: 重連後狀態保留語義
- **WHEN** 重連完成
- **THEN** 狀態保留範圍 SHALL 依錨定語義驗證(明確區分裸 ssh 與 tmux 情境),且畫面/scrollback SHALL 無非預期遺失
