# syslog-forwarding Specification

## Purpose
審計事件向外部 syslog 目的地的轉發：以 RFC5424 格式轉發三類事件，轉發走有界緩衝並與審計主鏈隔離（外部目的地不可用不得阻塞或反噬主審計鏈），受 syslog 傳輸政策門治理，測試訊息內容機器化，並明確其證明力邊界——外部 syslog 為補充副本，不取代錨定於檢查點鏈的主審計來源。
## Requirements
### Requirement: syslog 目的地設定

系統 SHALL 提供 Web UI 設定 syslog 轉發:開關、目的地 host/port、協議(UDP/TCP/TCP+TLS)、TLS CA(選填);設定 SHALL 限 admin,變更 SHALL 入審計。UI SHALL 提供「發送測試訊息」按鈕並回報成功或失敗**狀態**(失敗時呈現泛化提示,具體技術原因不對外揭露——見下段)。

測試訊息端點的回應 SHALL 以 HTTP 狀態碼表達成敗:送達成功回 2xx;**送達失敗 SHALL 回錯誤狀態碼(502,對端不可達語義)而非以 2xx 攜帶失敗旗標**,與通知通道測試端點的回應語義一致。失敗回應 SHALL 帶機器可辨錯誤碼(`apierror` 目錄註冊碼),使前端得以三語呈現;失敗原因的具體技術細節(連線拒絕/逾時/TLS 驗證失敗)SHALL 僅記於伺服端 log,對外回應 SHALL 為泛化提示,不洩漏目的地網路拓撲。UI SHALL 於失敗時仍呈現明確的失敗狀態(不得因狀態碼改變而靜默)。

#### Scenario: 測試訊息送達成功

- **WHEN** admin 設定可達目的地後點擊發送測試訊息
- **THEN** 系統向目的地發送一筆可識別的測試事件,回應 HTTP 200,UI 顯示成功狀態

#### Scenario: 測試訊息送達失敗

- **WHEN** admin 對不可達目的地(連線拒絕/逾時/TLS 驗證失敗任一)點擊發送測試訊息
- **THEN** 回應 HTTP 502 且 body 帶註冊於錯誤碼目錄的 `code`;UI 顯示失敗狀態與該碼的當前語言譯文;伺服端 log 記錄具體失敗原因,對外回應不含目的地技術細節

#### Scenario: 預設關閉

- **WHEN** 全新部署未設定 syslog
- **THEN** 轉發功能關閉,無任何對外連線嘗試

### Requirement: RFC5424 事件轉發

啟用後，系統 SHALL 將 audit_logs 與 command_alerts 的新事件於 DB 寫入成功後以 RFC5424 格式轉發（TCP 使用 octet-counting framing；TLS 驗證伺服器憑證），MSG 部分 SHALL 為結構化 JSON 且欄位涵蓋 PCI 10.2.2 六要素（使用者、事件類型、日期時間、成敗、來源、受影響資源）。

自 `audit-checkpoint-chain` 起，系統 SHALL 另轉發第三種事件：**檢查點錨定事件**，於檢查點封章成功並落庫後送出。其 MSG SHALL 為結構化 JSON，欄位至少含 seq、id 區間（`id_from`／`id_to`）、`row_count`、`agg_hash`、`agg_scheme`、`signature`、簽章鑰版本與 `sealed_at`。錨定事件 SHALL 具備可辨識的事件類型標識，使收集端能與一般審計事件區分並長期留存。

錨定事件內容 SHALL 為機器欄位（穩定、語言中立），SHALL NOT 含任何隨語系變動的散文，SHALL NOT 攜帶審計列的內容欄位（僅送出聚合結果與簽章，不外送日誌明細）。

#### Scenario: 審計事件轉發
- **WHEN** syslog 已啟用且一筆操作寫入 audit_logs 成功
- **THEN** 目的地收到一筆 RFC5424 訊息，JSON 內容與該 audit_log 六要素一致

#### Scenario: 檢查點錨定事件轉發
- **WHEN** syslog 已啟用且一個檢查點封章成功落庫
- **THEN** 目的地收到一筆可辨識為檢查點錨定的 RFC5424 訊息，JSON 含 seq、id 區間、`row_count`、`agg_hash`、簽章與簽章鑰版本，且不含任何審計列內容欄位

#### Scenario: TLS 驗證失敗拒送
- **WHEN** 目的地憑證無法通過 CA 驗證
- **THEN** 連線失敗計入失效偵測，事件不以明文降級發送

### Requirement: 緩衝與審計主鏈隔離
轉發 SHALL 經有界緩衝異步處理:目的地斷線時指數退避重連,緩衝滿時丟棄最舊事件並累計 dropped 計數;轉發的任何故障 SHALL NOT 阻塞或拖慢審計 DB 寫入。dropped 計數 SHALL 可查詢且不歸零隱匿。

#### Scenario: 目的地故障不影響審計
- **WHEN** syslog 目的地完全不可達且持續有操作產生審計事件
- **THEN** audit_logs 寫入照常成功,轉發緩衝溢出後 dropped 計數遞增並觸發失效事件記錄

#### Scenario: 恢復後續傳
- **WHEN** 目的地恢復可達
- **THEN** 重連成功,緩衝內未丟棄的事件依序送出,dropped 計數保留歷史值

### Requirement: syslog 傳輸政策門
syslog 轉發設定的建立與更新 SHALL 受 syslog 傳輸政策約束：warn 檔下傳輸為 UDP 或明文 TCP 時，儲存 SHALL 要求管理員附風險確認聲明，確認入審計；strict 檔下非 TLS 傳輸 SHALL 被拒絕存檔並回明確原因。off 檔（預設）行為與現狀一致。既有非 TLS 設定在政策收緊後 SHALL 不中斷轉發，但 SHALL 在設定頁與通道清冊標示偏離。

#### Scenario: warn 檔存 UDP 轉發須確認
- **WHEN** syslog 傳輸政策為 warn，管理員儲存 UDP 轉發設定並附確認聲明
- **THEN** 存檔成功且確認入審計；未附確認則被拒並提示風險項

#### Scenario: 政策收緊不中斷存量轉發
- **WHEN** 既有明文 TCP 轉發運行中，政策調為 strict
- **THEN** 轉發不中斷（審計外送優先於強制），設定頁標示偏離；再次存檔時受 strict 拒絕

### Requirement: 測試訊息內容機器化
「發送測試訊息」送往 syslog 目的地的事件內容 SHALL 為機器常數（穩定、語言中立的英文識別字串），SHALL NOT 硬編中文散文——該訊息是送往外部日誌系統的機器事件，不是 UI 文案，不隨任何語系設定改變。測試訊息 SHALL 維持可識別性（收端能明確辨認其為測試事件），且 SHALL NOT 攜帶目的地技術細節或內部路徑。端點的成敗回報語義不變（送達成功回 2xx；失敗回 502＋registered `code`，具體技術原因僅記於伺服端 log）。

#### Scenario: 測試事件內容為機器常數
- **WHEN** admin 點擊發送測試訊息且目的地可達
- **THEN** 目的地收到內容為固定機器常數的可識別測試事件，其中無中文散文，且不因後端或使用者語系而改變

#### Scenario: 前端狀態文字仍在地化
- **WHEN** admin 以 en-US 介面執行測試並取得結果
- **THEN** UI 的成功／失敗狀態文字由前端以當前語言呈現（失敗時經 registered `code` 查譯），與送往目的地的機器常數互不影響

### Requirement: 審計錯誤原文欄定性為 forensic
審計鏈保留的錯誤原文欄（`audit_logs.error_msg` 與同性質的 detail 欄）SHALL 定性為 **forensic 原文**：其內容為底層錯誤的原始訊息，供事後追查，SHALL NOT 被要求翻譯、SHALL NOT 納入三語完備性守衛的檢查對象，前端 SHALL NOT 將其當作主要顯示文案（僅得作為技術細節輔助呈現）。此定性 SHALL 明確記載，避免日後被誤判為「未清理的裸文字」而錯誤地列入翻譯範圍或被守衛誤紅。

#### Scenario: forensic 欄不入翻譯範圍
- **WHEN** 三語完備性守衛與字面量守衛執行
- **THEN** `error_msg` 類 forensic 欄不被要求有譯文、亦不因保留原文而判定違規

#### Scenario: 追查時原文完整可見
- **WHEN** 稽核員追查一筆轉發或審計寫入失敗
- **THEN** `error_msg` 呈現未經改寫的底層錯誤原文，資訊不因碼化或翻譯而遺失

#### Scenario: 不作為使用者主要文案
- **WHEN** 前端以 en-US 介面呈現一筆失敗紀錄
- **THEN** 主要說明文字來自機器碼查譯，`error_msg` 僅作為技術細節輔助呈現，不是唯一可讀來源

### Requirement: 檢查點錨定的失效語義與證明力邊界

檢查點錨定 SHALL 沿用既有有界緩衝與審計主鏈隔離機制：錨定事件入列失敗或被丟棄 SHALL NOT 阻塞封章、SHALL NOT 阻塞或拖慢審計 DB 寫入。

錨定結果 SHALL 以檢查點的 `anchor_status` 記錄：入列成功記 `enqueued`、緩衝滿被丟棄記 `dropped`、syslog 轉發未啟用記 `disabled`。`dropped` SHALL 經既有審計失效上報機制產生失效事件，SHALL NOT 靜默。失效事件 SHALL 能與一般轉發失效區分其嚴重度來源（錨定失效代表該檢查點失去離機證據）。

證明力邊界 SHALL 明載（誠實邊界 R4）：入列成功不等於送達（UDP 無回執、緩衝滿即丟棄、收集端可能未落盤）；`anchor_status` 為本地盡力記錄，SHALL NOT 被表述為「已離機留存」的證明。完整證明 SHALL 表述為「本地鏈驗證 + 收集端比對」。

未啟用 syslog 的部署 SHALL 於檢查點驗證頁明示降級（誠實邊界 R3），SHALL NOT 以任何方式暗示該部署具備離機錨定能力。

#### Scenario: 錨定丟棄不影響封章

- **WHEN** 轉發緩衝已滿，某檢查點的錨定事件入列被丟棄
- **THEN** 該檢查點仍完成落庫與簽章，`anchor_status = dropped`，並產生失效事件

#### Scenario: 錨定狀態不誇大證明力

- **WHEN** 使用者檢視某 `anchor_status = enqueued` 的檢查點
- **THEN** 介面表述為「已送出（送達須與收集端比對）」，MUST NOT 表述為「已離機留存」或等義措辭

#### Scenario: 未啟用時不暗示具備錨定

- **WHEN** 部署未啟用 syslog 轉發
- **THEN** 全部檢查點的 `anchor_status` 為 `disabled`，驗證頁顯著呈現無離機錨定的降級聲明

