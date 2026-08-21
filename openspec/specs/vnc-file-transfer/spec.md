# vnc-file-transfer Specification

## Purpose
VNC 資產的檔案傳輸能力。VNC/RFB 協議本身無檔案通道，採 Guacamole 官方路徑：guacd 對資產同一主機另建 SFTP 側車通道並曝露 filesystem 物件，前端與 RDP 磁碟重導共用同一上傳鏈路。連帶補齊 guac 圖形通道（RDP＋VNC）檔案上傳的應用層審計（file_tap）。
## Requirements
### Requirement: VNC SFTP 側車檔案傳輸
VNC 資產 SHALL 可選啟用 SFTP 檔案傳輸（獨立 sftp_port/sftp_username/sftp_password 憑證，AES-256-GCM 加密存放）；啟用時 guacd SHALL 對資產同一主機建立 SFTP 通道並曝露 filesystem 物件；SFTP 目標主機 SHALL 固定為資產 host，不可由前端改指；上傳落地根 SHALL 對到 SSH 帳號家目錄（root→/root，其餘→/home/<username>；自訂路徑列 backlog）。上傳 SHALL 與 RDP 磁碟重導行為對齊；主動下載 UI 對齊 RDP 現況（v1 不提供，列 backlog）。

#### Scenario: 啟用後可上傳
- **WHEN** 對啟用 SFTP 的 VNC 資產連線並上傳檔案
- **THEN** 檔案經 SFTP 落地目標主機帳號家目錄，內容一致

#### Scenario: 未啟用不出現入口
- **WHEN** 對未啟用 SFTP 的 VNC 資產連線
- **THEN** 工具列不顯示檔案傳輸入口，連線行為與現況一致

### Requirement: 憑證收口不變
SFTP 憑證 SHALL 僅於後端解密並注入 guacd 參數；API SHALL 僅回傳 has_sftp_password 布林；SFTP 認證失敗 SHALL 回統一錯誤訊息，不洩漏憑證細節；後端連線參數日誌 SHALL 遮罩憑證欄位（password/sftp-password/private-key），不落明文。

#### Scenario: 前端零接觸
- **WHEN** 讀取資產詳情 API
- **THEN** 回應含 sftp_enabled/sftp_port/sftp_username/has_sftp_password，無任何明文密碼欄位

#### Scenario: 連線參數日誌遮罩
- **WHEN** 後端記錄 guacd 連線參數日誌
- **THEN** password/sftp-password/private-key 以遮罩呈現，無明文憑證

### Requirement: 圖形通道檔案上傳審計
guacd 圖形通道的檔案上傳（RDP 磁碟重導與 VNC SFTP 同一路徑）SHALL 由 file_tap 比照 clipboard_tap 攔截 tunnel 上行的 put/blob/end 指令流，寫入 file_upload 審計紀錄（檔名與大小，`details.via` 分流 `guac-drive`/`guac-sftp`）。此補齊既有落差：file_upload 先前僅涵蓋 SSH REST SFTP 與 k8s cp，guac 通道（含 RDP）無應用層審計，於此一併補齊。審計寫入 SHALL 為非同步且失敗不阻斷傳輸；`put` SHALL 計入用戶端活躍指令，避免上傳中被誤判閒置。

**file_tap SHALL 自「觀察者」升為「強制點」**：收到 `put` 時 SHALL 逐次判定有效 `file_upload_enabled` 能力，不通過時 SHALL 丟棄該 `put` 及其後續 `blob`／`end`、SHALL NOT 轉發至 guacd，並 SHALL 回送客戶端可辨識的串流拒絕回應（`ack` 帶非零狀態碼，使客戶端不致無限等待），同時寫入 status=`denied` 的 file_upload 審計。判定 SHALL 為逐次（政策變更於快取窗口後即生效，不需重新連線），SHALL NOT 快取為連線建立時的一次性布林值。能力查詢 SHALL 以每個 `put` 一次為上限、SHALL NOT 於每個 `blob` 重查。

客戶端主動觸發的下載指令（`get`）SHALL 同樣受有效 `file_download_enabled` 能力管制並於 tunnel 層攔截（即使前端目前未提供下載入口，WebSocket 指令面仍為開放攻擊面）。**下載被拒 SHALL 為靜默丟棄且不回錯誤 `ack`**：`get` 被攔時串流尚未由 guacd 的 `body` 指令建立，客戶端手上沒有可被 `ack` 指涉的 stream index。此與上傳被拒的不對稱 SHALL 明載，SHALL NOT 描述為「下載被拒也會通知客戶端」。

guacd 端的 `disable-upload`／`disable-download`／`sftp-disable-upload`／`sftp-disable-download` 參數 SHALL 依有效能力一併送出作為縱深防禦；tunnel 層攔截 SHALL 為主強制點，系統 SHALL NOT 僅依賴 guacd 參數（其支援度隨 guacd 版本變動）。

#### Scenario: RDP 磁碟上傳留審計
- **WHEN** 透過 RDP 磁碟重導上傳檔案
- **THEN** audit_logs 產生 file_upload 紀錄，含檔名、大小與 `via=guac-drive`

#### Scenario: VNC SFTP 上傳留審計
- **WHEN** 透過 VNC SFTP 上傳檔案
- **THEN** audit_logs 產生 file_upload 紀錄，含檔名、大小與 `via=guac-sftp`

#### Scenario: 上傳被禁時攔於 tunnel
- **WHEN** 有效 `file_upload_enabled` 為 false 且客戶端送出 `put`
- **THEN** `put` 與其後續 `blob`／`end` 皆未轉發至 guacd、遠端未建立檔案，客戶端收到帶非零狀態碼的 `ack`，audit_logs 產生 status=denied 的 file_upload 紀錄

#### Scenario: 下載被禁時靜默丟棄
- **WHEN** 有效 `file_download_enabled` 為 false 且客戶端送出 `get`
- **THEN** 該指令未轉發至 guacd，且客戶端不會收到錯誤 `ack`（僅無回應）；audit_logs 產生 status=denied 的 file_download 紀錄

#### Scenario: 會話中收緊即時生效
- **WHEN** 使用者連線後管理員把 `file_upload_enabled` 改為 false，使用者再次上傳
- **THEN** 該次上傳被攔（不需重新連線）
