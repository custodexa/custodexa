# audit-failure-alerting Specification

## Purpose
審計機制失效事件的偵測、記錄與告警：以機器碼（`cause_code`＋`cause_params`）記錄失效原因（audit 寫庫失敗、syslog 轉發斷線／緩衝溢出、session 錄影失敗、鏈驗證異常），降級 fallback 檔案的持久化落地，並以可開關的通知通道發送失效與恢復告警，滿足 PCI Req 10 的降級模式審計要求。
## Requirements
### Requirement: 審計機制失效事件記錄
系統 SHALL 偵測並記錄審計機制失效事件至 audit_failure_events 表,涵蓋:audit 寫庫失敗(fallback 檔案觸發時)、syslog 轉發斷線、syslog 緩衝溢出、session 錄影失敗(`recording_*` 機制族——`recording_probe` 簽發前置檢查、`recording_text` 文字路徑啟動/寫入、`recording_graphics` 圖形路徑會後缺檔;三流各自去重與恢復配對,健康探測 SHALL NOT 關閉另一路仍在進行的失效事件)。每筆事件 SHALL 含機制名稱、開始時間、原因與詳情;**原因 SHALL 以機器碼記錄——`cause_code`(可枚舉的穩定識別字)與 `cause_params`(JSON,受控參數)兩欄落庫,SHALL NOT 以散文字串承載原因**;API SHALL 輸出這兩欄,前端 SHALL 以 code 查當前語言譯文顯示。機制恢復時 SHALL 回填結束時間(滿足 PCI 10.7.3 起訖與原因記錄)。事件記錄 SHALL 恆開,不受通知開關影響。

#### Scenario: 寫庫失敗留下失效事件
- **WHEN** audit 異步寫入 DB 失敗並落入 fallback 檔案
- **THEN** audit_failure_events 新增(或延續)一筆 audit-write 機制的失效事件,含開始時間與機器 `cause_code`(＋必要 `cause_params`),原因欄不含散文

#### Scenario: 恢復回填起訖
- **WHEN** 失效中的機制恢復正常運作
- **THEN** 對應失效事件回填結束時間,事件呈現完整起訖區間

#### Scenario: 錄影失敗納入失效事件
- **WHEN** 建線前置錄影檢查失敗或會話錄影被偵測為失敗
- **THEN** audit_failure_events 記錄(或延續)`recording` 機制失效事件,原因以 `cause_code` 表達;同機制進行中失效去重,恢復(下一次探測/寫入成功)回填結束時間

#### Scenario: 稽核頁以當前語言顯示原因
- **WHEN** 稽核員以 en-US 或 ja-JP 介面檢視審計失效事件列表
- **THEN** 原因欄顯示 `cause_code` 對應的當前語言譯文(參數經 `cause_params` 插值),而非後端繁中散文

### Requirement: 失效通知
啟用失效告警時,系統 SHALL 於失效事件開始時經通知通道(webhook/slack)發送告警;同一機制進行中的失效 SHALL 節流不重複發送,恢復時 SHALL 發送恢復通知。此功能 SHALL 可開關,預設關閉。

#### Scenario: 失效即告警
- **WHEN** 失效告警已開啟且綁定通知通道,syslog 轉發進入斷線狀態
- **THEN** 通道收到一次失效告警;斷線持續期間不重複發送;恢復時收到恢復通知

#### Scenario: 關閉時僅記錄
- **WHEN** 失效告警關閉且發生審計寫庫失敗
- **THEN** 失效事件照常記錄於 audit_failure_events,但不發送任何通知

### Requirement: 降級 fallback 檔案持久化落地
audit 寫庫失敗（或 channel 滿載）降級寫入的 fallback 檔案 SHALL 落在由 `AUDIT_LOG_PATH` 環境變數決定的持久化目錄（掛載卷或 bind mount）；`AUDIT_LOG_PATH` 未設定時 SHALL 退回內建相對路徑以保獨立二進位相容。在 compose/生產部署下，fallback 檔案 SHALL NOT 落在容器重建即失的臨時、未掛載路徑（強化 PCI Req 10 降級模式下的審計資料耐久性——原機制僅記失效事件，未保證 fallback 資料本身留存）。

#### Scenario: fallback 落於設定路徑
- **WHEN** `AUDIT_LOG_PATH` 設為掛載的持久化目錄，且 audit 寫庫失敗觸發檔案降級
- **THEN** fallback 審計檔寫入該持久化目錄（而非硬編相對 CWD 的臨時路徑）

#### Scenario: fallback 資料於容器重建後留存
- **WHEN** 降級 fallback 檔案已寫入 `AUDIT_LOG_PATH` 對應的 bind mount 目錄，隨後容器被重建
- **THEN** fallback 審計資料仍存在於主機資料夾，未隨容器銷毀而遺失

#### Scenario: 未設環境變數時相容退回
- **WHEN** `AUDIT_LOG_PATH` 未設定（如獨立二進位、非 compose 環境）
- **THEN** fallback 檔案落於內建預設相對路徑，行為與既有相容

### Requirement: cause 生產者全面碼化與同源一致
**所有** cause 生產者 SHALL 產生機器 `cause_code`＋參數,SHALL NOT 保留任何以散文寫入 cause 的路徑,涵蓋:`AuditFailureService.Report`、錄影失敗回報鏈（`ReportSessionRecordingFailure` 的各類 cause）、`MechanismSessionRecord`（圖形與 SSH 兩側 handler）、`MechanismAuditWrite`（審計寫入服務），以及事件列建立入口 `EnsureEventRow(mechanism, cause, …)` 的簽名——後者 SHALL 同步改為接受 cause code＋參數，使編譯期強制所有呼叫點遷移。cause code 常數 SHALL 集中宣告於 `internal/model`（可枚舉，預期 10-12 種），SHALL NOT 於各生產者就地拼字串。

同一事實 SHALL 在四條路徑上一致：`audit_failure_events.cause_code`、`sessions.recording_error`、`audit_logs` 的對應紀錄與出站通知，皆以同一組 cause code 表達，SHALL NOT 出現「一半機器碼一半散文」的分裂。`sessions.recording_error` SHALL 存機器碼，會話列表與會話詳情的 tooltip SHALL 以 code 查譯顯示。

#### Scenario: 錄影失敗同源四路一致
- **WHEN** 一場會話的錄影寫入失敗並觸發回報
- **THEN** `audit_failure_events.cause_code`、`sessions.recording_error` 與出站通知的 cause 參數為同一個機器碼,四路呈現同一事實

#### Scenario: 會話 tooltip 查譯顯示
- **WHEN** 稽核員以 ja-JP 介面把游標移到某會話的錄影失敗標記
- **THEN** tooltip 顯示該 cause code 的日文譯文,而非後端繁中字串

#### Scenario: 新生產者無法繞過碼化
- **WHEN** 開發者新增一個失效回報站點並嘗試傳入散文原因
- **THEN** 編譯失敗（`Report`／`EnsureEventRow` 只接受 cause code 型別），迫使註冊新的 cause code 常數

### Requirement: forensic 細節通道與出站去識別
cause 碼化後 SHALL 另設 forensic 細節通道，使底層錯誤原文不因碼化而遺失：`Report`／`EnsureEventRow` SHALL 接受一個 opaque `detail` 參數承載底層 `err` 原文，落於 `cause_params.detail` 與 `audit_logs.Details`（forensic 保留，供事後追查）。**出站通知的 params SHALL NOT 攜帶 `detail`**——錯誤原文可含檔案路徑、主機位址等內部資訊，違反出站去識別紅線；出站僅帶 `cause_code` 與受控參數。

`audit_logs.Details`、`AuditFailureEvent.Details`（含補列／回填註記）與 `audit_logs.error_msg` SHALL 定性為 **forensic 原文，不翻譯**：它們是稽核追查素材而非 UI 文案，SHALL NOT 被要求三語化，前端 SHALL NOT 將其當成主要顯示文字。

#### Scenario: detail 落庫供追查
- **WHEN** 錄影寫入因底層 I/O 錯誤失敗
- **THEN** `cause_params.detail` 與 `audit_logs.Details` 保留該錯誤原文,稽核員可據以定位根因

#### Scenario: webhook 不帶 detail
- **WHEN** 同一失效事件推送至 webhook 通道
- **THEN** payload 僅含 `cause_code` 與受控參數,不含 `detail` 原文,無內部路徑或位址外洩

#### Scenario: forensic 欄不列入翻譯範圍
- **WHEN** 三語完備性守衛執行
- **THEN** `Details`／`error_msg` 類 forensic 欄不被要求有譯文,亦不因未翻譯而被判為違規

### Requirement: cause code 完備性守衛
cause code 集合 SHALL 受雙面完備性守衛：後端側 SHALL 以 Go import 直接對照 `internal/model` 的 cause code 常數與 notifycat 的對應鍵（編譯期連結，不需跨目錄 AST 掃描）；前端側 SHALL 沿用既有枚舉守衛模式，斷言三語 locale 對每個 cause code 皆有非空譯文且無孤兒鍵。跨目錄守衛 SHALL 以**開發版 compose** 執行為準——正式版 compose 不掛載測試用途路徑而使該守衛 skip，此為既知限制並 SHALL 記載，SHALL NOT 以正式版的 skip 通過當作守衛已綠。

#### Scenario: 新增 cause code 未補譯文即紅
- **WHEN** 開發者新增一個 cause code 常數但未補三語譯文
- **THEN** 前端枚舉守衛與後端對照守衛失敗並指出缺失的 code 與語言

#### Scenario: 孤兒譯文鍵即紅
- **WHEN** 某 cause code 被退役但三語 locale 仍留有其鍵
- **THEN** 守衛失敗並指出孤兒鍵,迫使集合維持雙向相等

#### Scenario: 跨目錄守衛以開發版 compose 為準
- **WHEN** 於正式版 compose 執行測試,跨目錄守衛因缺掛載而 skip
- **THEN** 該結果 SHALL NOT 視為守衛通過;守衛須在開發版 compose 的容器內實跑並全綠

### Requirement: 鏈驗證異常的機制碼與告警分流

任一層自動鏈驗證（近期層或全鏈層）完成後，結果**不是全數通過**時系統 SHALL 發出告警，SHALL NOT 設任何分級門檻、累積門檻或「連續 N 次才報」的抑制條件。「全數通過」定義為：結構層全部 `passed`，且本輪驗過的內容層區間全部為 `passed` 或 `purged_legal`（依政策合法清除且清除簽章驗過者非異常）。

失效機制碼 SHALL 至少分為三個，SHALL NOT 壓成單一碼：

- **結構層異常**（檢查點自身的簽章、鏈接或 seq 被動）——稽核事件，處置為追查簽章金鑰的可及範圍。
- **內容層異常**（檢查點完好但其覆蓋的審計紀錄被改或缺失）——稽核事件，處置為追查資料庫寫入權的可及範圍。
- **驗證本身失敗**（資料庫不可讀）——運維事件，處置為修復環境；此時機制狀態為**未知**，SHALL NOT 被呈現為「無異常」。

「驗證本身失敗」的成因 SHALL 誠實界定為**資料庫不可讀**（狀態列讀取失敗或檢查點表讀取失敗），且該路徑 SHALL 上報而非只留本地日誌。**「簽章服務不可用」SHALL NOT 被列為其執行期成因**：簽章服務為啟動期 fail-close（金鑰載入或自洽檢查失敗即拒絕啟動），無執行期降級狀態，該情形下排程並不存在。自檢的簽章分支保留為裝配變動時的防線，但 SHALL NOT 被表述為現行部署中會出聲的告警路徑（詳見 `audit-checkpoint-chain` 的「檢查點鏈的兩層自動驗證」）。

結構層與內容層 SHALL NOT 共用同一機制碼，理由有二：其一，失效事件的去重以機制為單位，共用會使結構層異常未結案期間新發生的內容層異常完全靜默，只剩「異常範圍已變化」這類不開立事件、不記錄開始時間的通知作為弱兜底；其二，失效事件的**開始時間是稽核證據**，結構層異常（有人動得了簽章金鑰或檢查點）與內容層異常（有人動得了審計紀錄列）代表兩種不同的攻擊面與不同的持有物，其起訖區間 SHALL NOT 被歸併為同一段，否則首次發現時間即被錯誤合併且無法還原。

**機制碼 SHALL 依攻擊面劃分，SHALL NOT 依驗證層劃分**：近期層與全鏈層是同一組異常狀態的**兩個觀測管道**，而非兩個獨立的告警來源。同一區間可能被兩層先後驗到，若各自開立事件，同一異常會被通報兩次並留下兩個不同的開始時間。因此：異常狀態（結構層失敗點集合與內容層失敗區間集合）SHALL 只有一份、兩層共同維護；開立、結案與重發 SHALL 依合併後的狀態決定，SHALL NOT 依單層單輪的結果決定；發現該異常的層別 SHALL 僅記於失效事件的受控參數欄（不出站），SHALL NOT 影響事件身分。

cause 碼 SHALL 可區分「內容不符或缺失」與「出現額外紀錄且其列級簽章有效」（後者為誠實邊界 R1 所述之待人工確認態，非逕判竄改）。同一機制於一輪內出現多種狀態時，cause SHALL 取較嚴重者。

告警的**去重與重發** SHALL 沿既有失效事件機制，且 SHALL 同時滿足下列三條：

- 進入異常狀態時 SHALL 發出告警，失效事件的開始時間即該異常的**首次發現時間**並永久留存。
- **未結案的失敗區間集合**改變時（受影響範圍擴大或部分轉綠）SHALL 再次發出通知，且 SHALL NOT 為此先行結案再重開——偽造一次不存在的恢復會破壞失效區間的起訖證據。
- **結案 SHALL 以未結案失敗區間集合清空為條件**，SHALL NOT 以「本輪驗過的區間全數通過」為條件（見 `audit-checkpoint-chain` 的「失敗區間 SHALL 被重驗才得結案」）。

**重發判準所依據的指紋 SHALL 由跨輪累積的未結案失敗區間集合計算，SHALL NOT 由本輪驗過的區間結果計算**：兩層與滾動窗每輪驗到的區間本就不同，以本輪結果計算會使指紋逐輪抖動而每輪觸發重發通知，其實際效果即為「每輪重複發送」——正是下一段所禁止者。

系統 SHALL NOT 於每一輪重複發送內容相同的告警：對存量異常每輪重發的實際效果是收件端靜音整個通道，使會出聲的機制變成被靜音的機制。異常在真正恢復之前 SHALL 持續呈現於告警面與驗證頁，SHALL NOT 因「已通知過」而自畫面消失。

**出站 payload SHALL 只帶機器碼與計數**：受影響的檢查點序號清單、紀錄編號區間與任何自由字串 SHALL NOT 進入通知通道，僅落於失效事件的受控參數欄與驗證頁。理由有二：其一為既有去識別紅線（forensic 明細絕不出站）；其二為告警收端可能是第三方服務或任意 webhook，將「哪一段被發現異常」外送等同對已在系統內的攻擊者提供其偵測邊界的情報，而計數已足以驅動「須有人前往查看」這唯一必要的行為。

#### Scenario: 驗出竄改即告警

- **WHEN** 一輪自動驗證發現任一區間為 `count_mismatch`／`hash_mismatch`／`purged_invalid`
- **THEN** 系統以內容層機制碼開立失效事件並發出通知，通知內容含機制碼、cause 碼與失敗區間**數量**，不含任何序號或紀錄編號

#### Scenario: 驗證失敗與竄改不混為一談

- **WHEN** 資料庫暫時不可讀導致驗證無法完成
- **THEN** 系統以「驗證本身失敗」的機制碼上報，SHALL NOT 開立任何竄改機制的事件；驗證頁呈現機制狀態為未知而非通過

#### Scenario: 結構層異常不掩蓋內容層異常

- **WHEN** 結構層異常事件尚未結案，其後某一輪內容層新發現異常
- **THEN** 內容層以其自身機制碼開立獨立失效事件並發出通知，不因結構層事件進行中而被去重掉

#### Scenario: 同一異常不每輪重發

- **WHEN** 同一組異常區間連續多輪被驗出且範圍未變
- **THEN** 僅於首次進入異常時發出告警；失效事件持續存在且顯示首次發現時間，後續輪次不重複發送相同通知

#### Scenario: 異常範圍擴大時再次出聲

- **WHEN** 後續某輪的異常區間集合與上一輪不同
- **THEN** 系統再次發出通知，且原失效事件不被結案、其開始時間不變

#### Scenario: 未重驗的失敗區間不得使事件結案

- **WHEN** 某輪驗出區間 X 異常並開立事件，其後某輪驗的是其他區間且全數通過，而 X 尚未重驗轉綠
- **THEN** 事件 SHALL NOT 被結案、SHALL NOT 發出恢復通知

#### Scenario: 恢復即結案

- **WHEN** 未結案的失敗區間集合全部重驗轉綠且結構層全數通過
- **THEN** 對應失效事件回填結束時間並發出恢復通知

#### Scenario: 兩層驗到同一異常只發一次

- **WHEN** 同一異常區間先後被近期層與全鏈層驗到
- **THEN** 僅存在一個失效事件、一個開始時間，SHALL NOT 因層別不同而重複開立或重複通知
