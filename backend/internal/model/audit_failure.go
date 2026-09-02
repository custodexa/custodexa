package model

import "time"

// 審計機制名稱（PCI 10.7.2 偵測範圍 v1）
const (
	// MechanismAuditWrite audit 異步寫庫失敗（fallback 檔案觸發時上報）
	MechanismAuditWrite = "audit_write"
	// MechanismSyslogForward syslog 轉發斷線或緩衝溢出
	MechanismSyslogForward = "syslog_forward"
	// 錄影失敗機制族：三路各自對稱的
	// 失敗/恢復信號流，避免「健康 probe 誤 Resolve 另一路仍在失敗的事件」。
	// MechanismRecordingProbe 簽發點前置探測（失敗=probe 錯；恢復=probe 成功）
	MechanismRecordingProbe = "recording_probe"
	// MechanismRecordingText 文字路徑錄製（失敗=啟動/寫入/落地錯；恢復=下次啟動成功）
	MechanismRecordingText = "recording_text"
	// MechanismRecordingGraphics 圖形路徑錄製（失敗=會後缺檔/落地錯；恢復=下次會後確認成功）
	MechanismRecordingGraphics = "recording_graphics"
	// MechanismSessionRecord session 記錄建立失敗（fail-close）：連線因無
	// 審計歸屬被拒時上報；DB 寫不進時仍經通知通道告警、不沉默
	MechanismSessionRecord = "session_record"
	// MechanismKEKRetirement KEK 退役收尾未收斂：
	// degraded＝retire backlog>0，服務不降但禁後續換鑰；狀態可由 DB 謂詞導出，
	// 故 ReconcileOnStartup 排除本機制、恢復以謂詞重評估為準
	MechanismKEKRetirement = "kek_retirement"
	// MechanismCheckpointAnchor 檢查點離機錨定失效（audit-checkpoint-chain，
	// Open Question O4 判定：**獨立機制碼，不沿用 syslog_forward**）。
	//
	// 兩者嚴重度來源不同，合併會產生一個具體的錯誤結論：
	//   - `syslog_forward` 是**可回溯**的轉發中斷——期間的審計列仍完整在 DB，
	//     連線恢復後補送或以 DB 對帳即可補回證據；其失效事件的 EndedAt
	//     代表「證據流恢復」。
	//   - 錨定丟棄是**不可回溯**的證據缺口——該檢查點永遠沒有離機見證，
	//     `anchor_status=dropped` 是永久事實。若共用機制碼，syslog 連線一恢復
	//     就會把這個事件結案，讀起來像「錨定缺口已修復」，而它從未修復。
	//
	// 本機制的失效區間語義因此定義為「錨定機制目前不可用」（下一個成功入列的
	// 檢查點即結案），逐檢查點的永久缺口證據落在 audit_checkpoints.anchor_status。
	MechanismCheckpointAnchor = "checkpoint_anchor"
	// 鏈驗證異常的三個機制碼。
	//
	// **按攻擊面分，不按驗證層分**：近期層與全鏈層是同一組異常狀態的兩個觀測
	// 管道，而非兩個獨立的告警來源。同一區間可能被兩層先後驗到，若各自開立事件，
	// 同一異常會被通報兩次並留下兩個不同的 StartedAt。層別只記於 cause_params
	// （DB，不出站），不影響事件身分。
	//
	// MechanismAuditChainStructure 結構層異常：檢查點自身的簽章、鏈接或 seq 被動。
	//
	// **不與內容層共用碼**，理由有二：其一，失效事件的去重是 per-mechanism 的
	// （audit_failure_service.go 的 failing map ＋ DB 未結束事件查詢），共用會使
	// 結構層異常未結案期間新發生的內容層異常完全靜默；其二，失效事件的
	// StartedAt 是稽核證據，結構層異常（有人動得了簽章金鑰或檢查點列）與內容層
	// 異常（有人動得了 audit_logs 的資料列）是兩種不同的持有物與攻擊面，
	// 其起訖區間一旦被歸併為同一段，首次發現時間就再也還原不回來。
	// 處置：追查簽章金鑰與檢查點列的可及範圍
	MechanismAuditChainStructure = "audit_chain_structure"
	// MechanismAuditChainContent 內容層異常：檢查點完好，但其覆蓋的 audit_logs
	// 列被改或缺失。結構層不讀 audit_logs，故此類異常對結構層完全不可見
	// （檢查點一個字都沒動、全鏈驗證 100% 通過）——這正是本機制的招牌威脅。
	// 處置：追查資料庫寫入權的可及範圍
	MechanismAuditChainContent = "audit_chain_content"
	// MechanismAuditChainVerify 驗證本身無法完成（DB 不可讀、簽章服務不可用）。
	//
	// **運維事件，且機制狀態為「未知」而非「無異常」**：簽章服務整體不可用時
	// 全鏈每一點都會判為 signature_invalid，未經依賴自檢即會發出「整條鏈被竄改」
	// 的最高嚴重度告警而真因為環境問題，使真實竄改淹沒於環境噪音。故排程於驗證
	// 之前先自檢，不過即上報本機制並跳過本輪兩層驗證，不產出任何竄改結論
	MechanismAuditChainVerify = "audit_chain_verify"
	// MechanismAADResidue 非終態格式密文殘值：
	// AAD 綁定恆為強制後，啟動掃描發現任何非 `enc:a1` 的登記欄位值即為
	// 「不可能態」——程式缺陷或繞過 API 的資料庫直寫。開列本機制（fail-visible，
	// 不阻塞啟動）。狀態可由現查謂詞導出，收斂後自動結案
	MechanismAADResidue = "aad_residue"
	// MechanismSourcePolicy 來源位址政策不可用：判定點讀不到使用者的允許網段清單，
	// 或儲存的清單字串無法解析。每一個判定點遇此一律**拒絕**而非視為空清單放行；
	// 拒絕是靜默的（對外只看得到「來源不允許」），故經本機制上報使營運端在失效面板
	// 與通知通道看得見「政策壞了」。狀態可由謂詞（全部使用者清單可解析＋最近讀取成功）
	// 重評估，恢復即結案
	MechanismSourcePolicy = "source_policy"
	// MechanismCommandBlocking 指令阻斷比對器不可用（查詢主控台的 fail-close）。
	//
	// **與 audit_write 分開**：規則比對器壞掉與審計寫不進去是兩個不同的持有物
	// ——前者要去看規則載入與比對器本身，後者要去看資料庫。合併會讓兩種故障
	// 共用一個未結案區間，先發生的那個一結案就把另一個也結掉
	MechanismCommandBlocking = "command_blocking"
	// MechanismOffsiteUpload 離機儲存的上傳與取回完整性
	// （evidence-offsite-storage）：上傳重試達上限、租約反覆到期而卡死、
	// 取回時內容雜湊不符。**解除判準是「處於失敗態的件數歸零」而非「任一件成功」**
	// ——後者會把其他仍失敗的證據在通知面誤報為恢復
	MechanismOffsiteUpload = "offsite_upload"
)

// 失效原因機器碼。
//
// 定位：cause 的權威表述。散文（三語短語）由 notifycat 的 cause 詞庫渲染，
// 前端列表亦按碼查譯——同一事實不再一半碼一半散文。
// 底層 err 原文屬 forensic detail，走 cause_params["detail"]，不出站。
//
// 不變式：新增碼＝同時補三語詞庫鍵，否則 notifycat 的
// TestCauseEnumMatchesModel/TestLexiconCompleteness 轉紅。
// 值即 DB 與前端契約，改值等同 migration，不可隨手改。
const (
	// CauseRecordingProbeFailed 簽發點錄影前置探測失敗（sshproxy 簽發閘）
	CauseRecordingProbeFailed = "recording_probe_failed"
	// CauseRecordingStartFailed 文字路徑錄製啟動失敗
	CauseRecordingStartFailed = "recording_start_failed"
	// CauseRecordingFlushFailed recorder autoFlush 落盤失敗（閒置會話的磁碟錯誤）
	CauseRecordingFlushFailed = "recording_flush_failed"
	// CauseRecordingWriteFailed 錄製輸出事件寫入失敗
	CauseRecordingWriteFailed = "recording_write_failed"
	// CauseRecordingResizeWriteFailed 錄製尺寸事件寫入失敗
	CauseRecordingResizeWriteFailed = "recording_resize_write_failed"
	// CauseRecordingStopFailed 停止錄製失敗
	CauseRecordingStopFailed = "recording_stop_failed"
	// CauseRecordingFileStatFailed 錄影檔落地確認（stat）失敗
	CauseRecordingFileStatFailed = "recording_file_stat_failed"
	// CauseRecordingRenameFailed 圖形錄影檔落地重命名失敗
	CauseRecordingRenameFailed = "recording_rename_failed"
	// CauseRecordingMetadataUpdateFailed 錄影 metadata 回寫 session 失敗
	CauseRecordingMetadataUpdateFailed = "recording_metadata_update_failed"
	// CauseRecordingFileMissing 會後錄影檔缺失（guacd 寫入失敗或錄製未啟動）
	CauseRecordingFileMissing = "recording_file_missing"
	// CauseSessionRecordCreateFailed session 記錄建列失敗致連線被拒
	CauseSessionRecordCreateFailed = "session_record_create_failed"
	// CauseAuditWriteFallbackFile 審計批次寫庫失敗、已降級至檔案
	CauseAuditWriteFallbackFile = "audit_write_fallback_file"
	// CauseAuditWriteBatchDropped 審計批次寫庫失敗且檔案降級關閉，批次丟棄
	CauseAuditWriteBatchDropped = "audit_write_batch_dropped"
	// CauseAuditWriteSyncRefused 同步（fail-close）審計寫入失敗，該次操作已拒絕：
	// 逐筆留痕是交付明文的前置條件（剪貼簿單筆調閱），留痕寫不進去即拒絕交付
	// ——證據未損（明文沒出去），但審計機制本身失效，須經告警鏈揭露
	CauseAuditWriteSyncRefused = "audit_write_sync_refused"
	// CauseSyslogConnectFailed syslog 轉發連線失敗
	CauseSyslogConnectFailed = "syslog_connect_failed"
	// CauseSyslogBufferOverflow syslog 轉發緩衝溢出（丟棄計數）
	CauseSyslogBufferOverflow = "syslog_buffer_overflow"
	// CauseCheckpointAnchorDropped 檢查點錨定事件入列被丟棄（緩衝滿）：
	// 該檢查點失去離機見證，且無法補回（audit-checkpoint-chain 誠實邊界 R4）
	CauseCheckpointAnchorDropped = "checkpoint_anchor_dropped"
	// 鏈驗證異常的四個 cause 碼。
	// 同一機制於一輪內出現多種狀態時，cause 取較嚴重者（mismatch > extra_rows）。
	//
	// CauseAuditChainStructureInvalid 結構層任一點為 signature_invalid／
	// chain_broken／seq_gap（鏈為空亦落此碼：空鏈是「機制未啟用或整鏈被抹除」
	// 的結論，不是通過）
	CauseAuditChainStructureInvalid = "audit_chain_structure_invalid"
	// CauseAuditChainContentMismatch 內容層任一區間為 count_mismatch／
	// hash_mismatch／purged_invalid＝已封區間的紀錄被改、被刪，或清除簽章驗不過
	CauseAuditChainContentMismatch = "audit_chain_content_mismatch"
	// CauseAuditChainContentExtraRows 內容層僅出現 extra_rows_valid_hmac
	// ＝區間內多出列且其列級 HMAC 有效（誠實邊界 R1 的待人工確認態，非逕判竄改）
	CauseAuditChainContentExtraRows = "audit_chain_content_extra_rows"
	// CauseAuditChainVerifyFailed 驗證本身無法完成：DB 讀取失敗、簽章服務整體
	// 不可用。此時機制狀態為未知，SHALL NOT 被呈現為「無異常」
	CauseAuditChainVerifyFailed = "audit_chain_verify_failed"
	// CauseKEKRetirementBacklog KEK 退役收尾未收斂
	CauseKEKRetirementBacklog = "kek_retirement_backlog"
	// CauseAADResidueImpossibleState 偵測到非終態格式密文殘值＝依設計不可能之狀態
	// AAD 綁定恆為強制、寫入端在建構上只產
	// `enc:a1`，故殘值只可能來自程式缺陷或繞過 API 的資料庫直寫。取代原先描述
	// 遷移進度／模式狀態的 permissive 與 strict-mismatch 兩值——那兩種狀態隨
	// strict 狀態機一同消滅，其 cause 值不得沿用（語義已不成立）。
	CauseAADResidueImpossibleState = "aad_residue_impossible_state"
	// CauseSourcePolicyUnreadable 判定點讀取使用者的允許網段清單失敗（DB 錯）
	CauseSourcePolicyUnreadable = "source_policy_unreadable"
	// CauseSourcePolicyCorrupt 儲存的允許網段清單字串無法解析：唯一寫入路徑是
	// 驗證後寫入，損壞只可能來自資料庫直寫或程式缺陷
	CauseSourcePolicyCorrupt = "source_policy_corrupt"
	// CauseCommandAuditWriteRefused 同步（fail-close）語句紀錄寫入失敗，該語句
	// 已拒絕執行。與 CauseAuditWriteSyncRefused 分碼是因為兩者的「已拒絕」
	// 指的是不同的東西：那一支是明文未交付，本支是語句未送往目標端
	CauseCommandAuditWriteRefused = "command_audit_write_refused"
	// CauseCommandBlockerUnavailable 指令阻斷比對器不可用，語句已拒絕執行。
	// 規則集為空與比對器壞掉是兩件事：前者比對正常回未命中，後者必須 fail-close
	CauseCommandBlockerUnavailable = "command_blocker_unavailable"
	// CauseOffsiteUploadFailed 離機上傳重試達上限（bucket 不存在、憑證失效、
	// 端點長期不可達等持久性錯誤）。**不自動每日重試**——那只是每天再產一次告警；
	// 修復動作與重試綁在一起，經管理介面「重試失敗項」觸發
	CauseOffsiteUploadFailed = "offsite_upload_failed"
	// CauseOffsiteUploadStalled 同一物件的上傳租約反覆到期（≥2 次）：
	// 行程被砍或傳輸期限被繞過。**不等到重試上限**——租約反覆到期比「上傳失敗」
	// 更早需要人看
	CauseOffsiteUploadStalled = "offsite_upload_stalled"
	// CauseOffsiteIntegrityMismatch 取回離機副本時內容雜湊或大小與上傳當下不符：
	// **零位元組交付**（先驗後送），該物件轉為不可信態
	CauseOffsiteIntegrityMismatch = "offsite_integrity_mismatch"
)

// CauseParamDetail forensic 明細參數鍵：承載底層 err 原文。
// 落 cause_params 與 audit_logs.Details，但**絕不進出站 payload**
// （err 原文可含路徑/位址，去識別紅線）。
const CauseParamDetail = "detail"

// 鏈驗證告警的參數鍵。
//
// **命名不用 Cause* 前綴是刻意的**：notifycat 的 TestCauseEnumMatchesModel 以
// go/types 列舉 model 套件的 `Cause*` 常數當作 cause 碼的比對基準，參數鍵混進去
// 會被當成一個沒有詞庫的原因碼（CauseParamDetail 因此得在守衛裡開一條例外）。
//
// **出站只帶碼與計數**：受影響的檢查點序號清單、紀錄編號區間與任何自由字串
// 一律不出站。理由有二——其一為既有去識別紅線（forensic 明細絕不出站）；
// 其二為告警收端可能是第三方 SaaS 或任意 webhook，把「哪一段被發現異常」外送
// 等同對已在系統內的攻擊者提供其偵測邊界的情報，而計數已足以驅動
// 「須有人前往查看」這唯一必要的行為
const (
	// FailureParamFailedPoints 結構層失敗點數（出站）
	FailureParamFailedPoints = "failed_points"
	// FailureParamFailedIntervals 未結案的內容層失敗區間數（出站）
	FailureParamFailedIntervals = "failed_intervals"
	// FailureParamChainVerifyLayer 發現該異常的驗證層別（recent／full）。
	// 與 CauseParamDetail 同紀律：只落 cause_params 與驗證頁，**不進出站 payload**
	// ——層別是「這次是誰發現的」，不影響事件身分，也不是收件端需要知道的事
	FailureParamChainVerifyLayer = "chain_verify_layer"
)

// AuditFailureEvent 審計機制失效事件（PCI 10.7.2/10.7.3）。
// 記錄恆開、不受通知開關影響；同一機制進行中（EndedAt 為 nil）的事件不重複建列，
// 機制恢復時回填 EndedAt 形成完整起訖區間
type AuditFailureEvent struct {
	ID        uint       `gorm:"primarykey" json:"id"`
	Mechanism string     `gorm:"type:varchar(30);not null;index:idx_failure_mechanism_open" json:"mechanism"`
	StartedAt time.Time  `gorm:"not null" json:"started_at"`
	EndedAt   *time.Time `gorm:"index:idx_failure_mechanism_open" json:"ended_at,omitempty"`
	// Cause 失效原因散文（PCI 10.7.3 要求記錄 cause）。**已降為顯示用 fallback**：
	// 內容＝zh-TW 短語＋forensic detail，權威表述改為 CauseCode。
	// 保留而非清空，是為了讓尚未改查譯的既有讀取點（含既有列）不白屏
	Cause string `gorm:"type:text;not null" json:"cause"`
	// CauseCode 機器碼化的失效原因＝權威表述；
	// 值域見本檔 Cause* 常數，三語短語由 notifycat cause 詞庫渲染
	CauseCode string `gorm:"size:64;not null;default:''" json:"cause_code"`
	// CauseParams CauseCode 的參數（JSON 字串），
	// 含 opaque detail 供 forensic 用途；出站 payload 不帶 detail
	CauseParams string    `gorm:"type:text;not null;default:''" json:"cause_params"`
	Details     string    `gorm:"type:text" json:"details,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AuditFailureEvent) TableName() string {
	return "audit_failure_events"
}
