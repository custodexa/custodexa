# ssh-terminal

## Purpose

SSH 資產的原生 xterm.js 終端直連與 PTY 互動：連線收口與憑證後端化、指令阻斷警告以碼化控制幀送達並三軌（錄影／即時監看／審計 tap）留痕、使用者可見文字走機器碼查譯的三語支援、以及終端出口中文字面量的常駐守衛。SSH 已退出 guacd，指令審計與 asciicast 錄製由自有終端代理承擔。
## Requirements
### Requirement: Native SSH text-stream session
The system SHALL establish SSH sessions through a backend-native SSH client (PTY over WebSocket text stream) rendered by xterm.js in the browser. SSH sessions MUST NOT be relayed through guacd.

#### Scenario: Connect to SSH asset
- **WHEN** an authorized user opens a terminal to an SSH asset with stored credentials
- **THEN** an interactive shell renders in xterm.js, typed characters echo immediately, and the terminal fills the available container area

#### Scenario: guacd SSH path retired
- **WHEN** a client requests the legacy guacd connect endpoint with protocol=ssh
- **THEN** the request is rejected with an error directing to the native SSH endpoint

### Requirement: Backend credential injection
The native SSH endpoint SHALL accept only an authentication token and an asset identifier. The backend MUST resolve and decrypt asset credentials in memory and inject them into the SSH connection; plaintext credentials MUST NOT appear in the WebSocket URL, frontend code, or browser-visible payloads.

#### Scenario: Connection without frontend credentials
- **WHEN** the frontend opens the SSH WebSocket with token and asset_id only
- **THEN** the session is established using backend-resolved credentials and no password value is present in the request URL or messages

#### Scenario: Asset without stored credentials
- **WHEN** a user connects to an SSH asset that has no stored credential
- **THEN** the connection is refused with a readable error explaining that managed credentials are required

#### Scenario: Unauthorized user blocked
- **WHEN** a user without connect permission on the asset opens the SSH WebSocket
- **THEN** the connection is rejected before any SSH dial occurs

### Requirement: Terminal size synchronization
The terminal SHALL connect using the actual measured container size and SHALL propagate subsequent size changes to the remote PTY via SSH window-change requests. Hardcoded fallback resolutions MUST NOT be used.

#### Scenario: Initial size from real container
- **WHEN** the terminal view is opened and the container has just finished layout
- **THEN** the connection is initiated only after a non-zero container size is measured and the PTY is created with the fitted cols/rows

#### Scenario: Window resize propagates
- **WHEN** the browser window is resized during an active session
- **THEN** xterm.js refits and the remote PTY dimensions change accordingly (full-screen programs like top re-render at the new size)

### Requirement: Session keepalive and lifecycle
The WebSocket SHALL carry periodic keepalive messages, and session records SHALL be created on connect and closed on disconnect, consistent with existing session management (including registry-based administrative termination).

#### Scenario: Idle session stays alive
- **WHEN** a session is idle for several minutes behind a reverse proxy
- **THEN** keepalive traffic prevents idle disconnection and the session remains usable

#### Scenario: Disconnect updates session
- **WHEN** the user closes the terminal or the SSH connection drops
- **THEN** the session record is marked closed and resources (SSH client, recorder) are released

### Requirement: Asciicast recording and playback
Native SSH sessions SHALL be recorded as asciicast v2 files written by the backend, and session playback SHALL serve these recordings through the existing player. Legacy typescript recordings MUST remain playable.

#### Scenario: New session recorded as asciicast
- **WHEN** a native SSH session ends
- **THEN** a session-{id}.cast file exists, the session recording metadata is updated, and playback renders the terminal output in the player

#### Scenario: Legacy recording still plays
- **WHEN** an auditor plays back a pre-migration typescript recording
- **THEN** the existing conversion path serves it unchanged

### Requirement: 行動快捷鍵列
SSH 終端於行動環境（粗指標裝置或窄視窗）SHALL 顯示快捷鍵列（ESC、Tab、Ctrl+B、Ctrl+C、↑、↓）；點擊 SHALL 將對應控制序列送往終端並保持輸入焦點；桌面環境 SHALL NOT 顯示。

#### Scenario: 行動環境顯示與送鍵
- **WHEN** 行動環境下點擊 Ctrl+C 鍵
- **THEN** 終端收到 \x03 序列且焦點回到終端

#### Scenario: 桌面隱藏
- **WHEN** 桌面寬視窗環境
- **THEN** 快捷鍵列不渲染

### Requirement: WS 撥號失敗原因透傳
`GET /api/v1/ssh` 於 WebSocket 升級前的終端連線建立失敗（SSH 撥號、k8s exec 建立、database CLI 啟動）時，後端 SHALL 嘗試升級 WebSocket 並以 `type:"error"` 訊息送出失敗原因後關閉連線；SSH 撥號失敗 SHALL 依既有分類（host key 變更／認證失敗／逾時／不可達）附機器可讀 `code` 欄（登記於 `internal/apierror` registry，命名空間 `RULE_SSH_*`），`data` 欄 SHALL 為 zh fallback 文案。WebSocket 升級失敗時 SHALL 退回既有 HTTP JSON 錯誤回應。前端 SHALL 以 code 查當前語言譯文顯示（`apiError.*` 三層降級），SHALL NOT 一律顯示籠統的連線失敗文案。

#### Scenario: host key 變更經 WS 送達
- **WHEN** 資產 host key 與記錄不符導致 SSH 撥號被拒，且客戶端為瀏覽器 WebSocket
- **THEN** WS 升級成功並收到 `{type:"error", code:"RULE_SSH_HOST_KEY_CHANGED", data:<zh 文案>}` 後連線關閉；前端錯誤狀態顯示當前語言的「主機金鑰已變更」譯文

#### Scenario: 認證失敗分類送達
- **WHEN** 資產憑證錯誤導致 SSH 撥號認證失敗
- **THEN** 前端收到 `code:"RULE_SSH_AUTH_FAILED"` 並顯示對應譯文，而非籠統 connectFailed

#### Scenario: 非 WS 客戶端維持 HTTP 語義
- **WHEN** 撥號失敗且請求非有效 WebSocket 升級請求
- **THEN** 回應維持既有 HTTP 502 JSON（`{error, ...}`），行為與變更前一致

#### Scenario: 舊前端相容
- **WHEN** 不解析 `code` 欄的舊版前端收到 error 訊息
- **THEN** 其顯示 `data` 欄 zh 文案，無解析錯誤

#### Scenario: 新 code 三語完備
- **WHEN** apierror bijection 完備性測試於開發版 compose backend 容器執行
- **THEN** `RULE_SSH_*` 各 code 於 zh-TW/en-US/ja-JP 的 `apiError.*` 皆有非空譯文，缺一即測試失敗

### Requirement: WebSocket 錯誤幀機器碼必填
終端 WebSocket 的錯誤幀 SHALL 一律攜帶機器可讀 `code`：編碼函式 `EncodeErrorMessage(code, zhFallback)` 的 `code` 參數 SHALL 為必填的 `ErrCode` 型別（非字串），空 code 分支 SHALL 自程式碼刪除，使「送出無碼錯誤幀」在編譯期不可能。`data` 欄 SHALL 保留 zh fallback 文案供舊前端與譯文缺鍵時使用。

既有無碼出口 SHALL 全數補碼並登記於 `internal/apierror` registry，涵蓋（但不限於）：k8s exec 撥號失敗、資料庫 CLI 啟動失敗、「會話已結束」通知、監看房間關閉廣播、認證態拒絕（帳號已停用或鎖定）。監看廣播 SHALL 對全房觀察者送出同一份碼化 bytes，前端各自查譯，SHALL NOT 為此改動 observers 資料結構。

#### Scenario: 會話結束通知帶碼
- **WHEN** 使用者的會話因後端判定已結束而收到通知幀
- **THEN** 幀帶 registered `code`，前端以當前語言顯示；`data` 欄保留 zh fallback

#### Scenario: 認證態拒絕帶碼
- **WHEN** 帳號已停用或鎖定的使用者嘗試建立終端連線
- **THEN** 錯誤幀帶對應 registered `code`，en-US 介面顯示英文說明而非繁中注入文字

#### Scenario: 無碼錯誤幀編譯期不可能
- **WHEN** 開發者嘗試以空 code 呼叫錯誤幀編碼函式
- **THEN** 編譯失敗（型別必填、空 code 分支已刪除）

#### Scenario: 監看廣播單一 bytes 多語呈現
- **WHEN** 監看房間關閉並對全房觀察者廣播
- **THEN** 後端送出同一份碼化 bytes，各觀察者前端依自身語言查譯顯示

### Requirement: 指令阻斷警告以控制幀送達
指令阻斷警告 SHALL 以碼化控制幀送達前端，SHALL NOT 由後端把警告散文直接寫入終端資料流：幀形狀為 `{type: "notice", code: <阻斷碼>, data: <zh fallback>, params: {…}}`；`Message` 結構 SHALL 新增 optional `params` 欄（`omitempty`）。`data` SHALL 保留 zh fallback（比照錯誤幀）——譯文漏鍵時若無 fallback，阻斷將靜默無提示，屬安全 UX 回歸。

**注入安全契約**：後端組幀時 `params` 值 SHALL 一律經共用淨化函式處理（strip ANSI ESC／控制字元；規則名稱等欄位現僅驗必填、可含任意字元）；前端查譯後注入 xterm 前 SHALL 再 escape 一次（縱深防禦）。

**阻斷軌跡入三軌**：阻斷發生時，後端除送出 MsgNotice 幀外 SHALL 另將**標準化阻斷標記**寫入輸出旁路（`outputSinks`），使錄影回放、即時監看與審計 tap 三軌皆留下該事件。標記格式 SHALL 為伺服端固定格式 `[<阻斷碼>] <zh 說明含規則名>`（外覆 CRLF 與紅字 SGR），且 SHALL NOT 隨觀看者語系變動——錄影是不可變稽核物件，內容隨語系改變即失去可比對性；使用者所見文案仍由前端依語系渲染 MsgNotice，兩者並存而非二選一。標記內的規則名 SHALL 經同一淨化函式處理（同上注入安全契約）。此設計確保即時監看端與審計 tap 皆能看到阻斷事件，無「監看端看不到阻斷」的盲區。

**清行失敗即終止會話（fail-close）**：阻斷後送出的中斷鍵（Ctrl+C）用於清除遠端行緩衝；該寫入失敗時後端 SHALL NOT 續跑（若 fail-open 續跑會讓遠端殘留被阻斷指令的前綴，使用者下次按 Enter 即送出殘句，等同阻斷未發生）。後端 SHALL 送出碼化錯誤幀說明原因、終止會話，並將終止原因寫入既有審計軌（`sessions.end_reason`，與逾時／強制終止同欄同機制），SHALL NOT 為此發明新的終止或審計機制。

**已知限制（SHALL 記載，非「漸進安全」）**：部署後未刷新的舊分頁會忽略未知類型的控制幀，使用者將看到指令未送出但無提示；此限制以前後端同版部署為前提，使用者刷新分頁後即恢復正常提示。

#### Scenario: 阻斷警告依前端語言顯示
- **WHEN** 使用者以 en-US 介面輸入被規則阻斷的指令
- **THEN** 終端顯示英文阻斷說明（含規則名稱參數），指令未送達目標主機

#### Scenario: 譯文缺鍵仍有提示
- **WHEN** 阻斷碼在前端無對應譯文
- **THEN** 前端以幀內 `data` 的 zh fallback 顯示提示，阻斷 SHALL NOT 靜默無提示

#### Scenario: 規則名稱含控制序列被淨化
- **WHEN** 某告警規則名稱含 ANSI ESC 或換行字元且該規則阻斷了一條指令
- **THEN** 後端 params 已 strip 控制字元，前端注入 xterm 前再 escape，終端不被注入控制序列

#### Scenario: 錄影／監看／審計三軌含阻斷標記
- **WHEN** 一場含阻斷事件的會話被回放、被即時監看、或被審計 tap 消費
- **THEN** 三軌皆含標準化阻斷標記（帶可 grep 的機器碼前綴與規則名），且該標記為伺服端固定格式，不隨觀看者語系變動

#### Scenario: 清行失敗即終止且原因入審計軌
- **WHEN** 阻斷後的中斷鍵寫入遠端失敗
- **THEN** 使用者收到碼化錯誤幀說明連線已中止、會話立即終止，且終止原因以既有 `end_reason` 欄位落庫供稽核；SHALL NOT 續用可能殘留被阻斷指令前綴的連線

#### Scenario: 舊分頁忽略控制幀（已知限制）
- **WHEN** 部署後未刷新的舊分頁收到新控制幀
- **THEN** 該幀被忽略、無提示（已記載的已知限制），使用者刷新後恢復正常提示

### Requirement: 終端出口中文字面量守衛
`internal/sshproxy` 與 `internal/proxy` 的非測試程式碼 SHALL 受常駐 AST 守衛：中文字面量**僅允許**出現於 log 系呼叫（`log.Printf` 等）、內部 error 建構（`fmt.Errorf`／`errors.New`）與註解；其餘位置出現中文字面量即測試失敗，迫使使用者可見文字走機器碼路徑。過渡條目 SHALL 以與錯誤 sink 守衛相同的 hash allowlist 列管（`-update` 生成、diff 人審），且該 allowlist SHALL 為燒盡制：只減不增、持續收斂至零並維持歸零，守衛常駐測試套件。

守衛盲區 SHALL 誠實記載：此守衛僅偵測中文字面量，使用者可見的**英文**字面量不被攔截；此盲區 SHALL 於本規格與守衛註解中明載，SHALL NOT 以「清單歸零」誤讀為「所有使用者可見文字皆已碼化」。

#### Scenario: 新增中文字面量出口即紅
- **WHEN** 開發者在 `internal/sshproxy` 新寫一段直接寫往 WebSocket 的中文提示字串
- **THEN** 守衛測試失敗並指出位置，迫使改以註冊碼＋前端查譯

#### Scenario: log 與內部 error 豁免
- **WHEN** 同一檔案以 `log.Printf` 記錄中文運維訊息或以 `fmt.Errorf` 建構內部 error
- **THEN** 守衛放行（callee 名稱可區分），不誤傷運維與內部語義

#### Scenario: allowlist 歸零且守衛常駐
- **WHEN** 守衛測試套件執行
- **THEN** 該 allowlist 為空、守衛留在測試套件常駐，英文字面量盲區已於本規格與守衛註解明載

