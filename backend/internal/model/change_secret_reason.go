package model

// 改密結果原因碼。
//
// **安全不變式**：ChangeSecretRecord.Error 與 ChangeSecretCandidate.LastError
// 只允許存放本檔列舉的原因碼，遠端回傳的任何字串（stderr、SSH 交握訊息、
// sftp 狀態文字）一律 SHALL NOT 進入這兩欄與告警通道——那是攻擊者可控輸入，
// 而 record.error 未加密落庫、經 API 反射、並隨告警離開產品邊界。
// 遠端原文只進後端 log（不落庫、不外送）。
//
// 命名沿 apierror 的機器碼慣例（大寫底線、資源前綴），但**不註冊進 apierror
// registry**：那域管的是 HTTP 錯誤回應的出口碼，本組是落庫記錄的原因欄位，
// 兩者生命週期與呈現位置不同。前端文案在 `changeSecretPlans.reason.<CODE>`。
const (
	// --- 資產／帳號解析階段（尚未接觸遠端）---
	ChangeSecretReasonAssetLookupFailed   = "CHANGE_SECRET_ASSET_LOOKUP_FAILED"
	ChangeSecretReasonProtocolUnsupported = "CHANGE_SECRET_PROTOCOL_UNSUPPORTED"
	ChangeSecretReasonAccountLookupFailed = "CHANGE_SECRET_ACCOUNT_LOOKUP_FAILED"
	ChangeSecretReasonNoAccountInScope    = "CHANGE_SECRET_NO_ACCOUNT_IN_SCOPE"
	// ChangeSecretReasonSharedCredentialTargetRequired 目標掛的是共用憑證。
	// 以帳號為目標的計劃不得只改共用憑證的其中一員（其餘成員會失去可用秘密），
	// 也不得自動擴張到未被選取的掛載——要改整組請以憑證為目標。
	// 本碼刻意不帶 CHANGE_SECRET_ 前綴：它描述的是目標種類選錯，不是改密過程的失敗
	ChangeSecretReasonSharedCredentialTargetRequired = "SHARED_CREDENTIAL_TARGET_REQUIRED"
	// ChangeSecretReasonChannelNotConfigured 資產沒有可用的改密通道。
	// 與 PROTOCOL_UNSUPPORTED 分開：後者是「這個協定本系統改不了密」，
	// 前者是「改得了，但這台還沒設定要怎麼連進去」——處置方式不同
	ChangeSecretReasonChannelNotConfigured = "CHANGE_SECRET_CHANNEL_NOT_CONFIGURED"
	// ChangeSecretReasonSecretTypeUnsupported 通道不支援計劃的秘密型別
	//（例：Windows 通道的 SSH 金鑰輪替）
	ChangeSecretReasonSecretTypeUnsupported = "CHANGE_SECRET_SECRET_TYPE_UNSUPPORTED"

	// --- 候選與憑證前置 ---
	ChangeSecretReasonCandidateQueryFailed   = "CHANGE_SECRET_CANDIDATE_QUERY_FAILED"
	ChangeSecretReasonCandidatePending       = "CHANGE_SECRET_CANDIDATE_PENDING"
	ChangeSecretReasonCandidatePersistFailed = "CHANGE_SECRET_CANDIDATE_PERSIST_FAILED"
	ChangeSecretReasonCredentialLoadFailed   = "CHANGE_SECRET_CREDENTIAL_LOAD_FAILED"
	ChangeSecretReasonAccountChanged         = "CHANGE_SECRET_ACCOUNT_CHANGED"
	ChangeSecretReasonNoCredential           = "CHANGE_SECRET_NO_CREDENTIAL"
	ChangeSecretReasonNoPasswordCredential   = "CHANGE_SECRET_NO_PASSWORD_CREDENTIAL"

	// --- 秘密產生 ---
	ChangeSecretReasonPasswordGenerateFailed = "CHANGE_SECRET_PASSWORD_GENERATE_FAILED"
	ChangeSecretReasonKeypairGenerateFailed  = "CHANGE_SECRET_KEYPAIR_GENERATE_FAILED"

	// --- 本地前置驗證（完全未接觸遠端；乾淨失敗，不留候選）---
	ChangeSecretReasonInvalidAccountName = "CHANGE_SECRET_INVALID_ACCOUNT_NAME"
	ChangeSecretReasonInvalidNewSecret   = "CHANGE_SECRET_INVALID_NEW_SECRET"
	// ChangeSecretReasonAccountNameInvalid 帳號名不符 Windows 本機帳號的命名規則
	// （禁用字元、長度上限、首尾空白）。與 INVALID_ACCOUNT_NAME 分開：後者擋的是
	// POSIX 逐行協定的注入字元，本碼依的是 Windows 自己的規則，兩者的允許集合不同
	ChangeSecretReasonAccountNameInvalid = "CHANGE_SECRET_ACCOUNT_NAME_INVALID"
	// ChangeSecretReasonInvalidOldSecret 現行密碼含無法經標準輸入投遞的字元（換行、NUL）。
	// Windows 腳本靠這一行回滾，截斷的舊密碼會把帳號改到一個誰都不知道的值，故本地攔下
	ChangeSecretReasonInvalidOldSecret = "CHANGE_SECRET_INVALID_OLD_SECRET"

	// --- 遠端互動 ---
	ChangeSecretReasonOldCredentialLoginFailed = "CHANGE_SECRET_OLD_CREDENTIAL_LOGIN_FAILED"
	// ChangeSecretReasonHostKeyMismatch 撥號目標出示的主機金鑰與記錄不符（host-key-verification）：
	// 背景作業無人在場，撥號在送出任何憑證或新秘密之前被拒絕；不符本身已另留審計與系統告警。
	// 處理途徑是確認主機後在資產設定採用新指紋或重置主機金鑰，不是去查憑證
	ChangeSecretReasonHostKeyMismatch = "CHANGE_SECRET_HOST_KEY_MISMATCH"
	// ChangeSecretReasonHostKeyCheckFailed 首次派送前綁定目標主機身分失敗（查核或寫入失敗）：
	// 在送出任何憑證或新秘密之前中止，目標未被觸碰；與主機金鑰不符分開，處理途徑是稍後重試或查服務狀態
	ChangeSecretReasonHostKeyCheckFailed = "CHANGE_SECRET_HOST_KEY_CHECK_FAILED"
	// ChangeSecretReasonRemoteRejected 指令跑完但非零退出＝遠端確定未變更
	ChangeSecretReasonRemoteRejected = "CHANGE_SECRET_REMOTE_REJECTED"
	// ChangeSecretReasonRemoteStateUnknown 指令送出後連線中斷／逾時＝遠端狀態不可知
	ChangeSecretReasonRemoteStateUnknown = "CHANGE_SECRET_REMOTE_STATE_UNKNOWN"
	// ChangeSecretReasonRemoteUnreachable 指令送出前就無法建立工作階段（連線被拒或
	// 未回應、撥號逾時、TLS 憑證驗證失敗、目標未提供可用的交握）＝遠端確定未變更
	ChangeSecretReasonRemoteUnreachable = "CHANGE_SECRET_REMOTE_UNREACHABLE"
	ChangeSecretReasonVerifyFailed      = "CHANGE_SECRET_VERIFY_FAILED"
	// ChangeSecretReasonWinRMEncryptionUnavailable 目標無法以訊息層加密交握。
	// 這是拒連而非降級：明文送出的下一個封包就是新密碼
	ChangeSecretReasonWinRMEncryptionUnavailable = "CHANGE_SECRET_WINRM_ENCRYPTION_UNAVAILABLE"
	// ChangeSecretReasonStdinNotDelivered 遠端腳本回報未收到 stdin 的密碼行
	//（退出碼 3）。目標未改密，且不會靜默成功
	ChangeSecretReasonStdinNotDelivered = "CHANGE_SECRET_STDIN_NOT_DELIVERED"
	// ChangeSecretReasonRemoteSelfVerifyFailed 目標設定新密碼後在本機驗證不通過，已當場改回舊密碼
	//（退出碼 4）。遠端確定是舊密碼
	ChangeSecretReasonRemoteSelfVerifyFailed = "CHANGE_SECRET_REMOTE_SELF_VERIFY_FAILED"
	// ChangeSecretReasonRemoteSelfVerifyRollbackFailed 目標驗證新密碼不通過、改回舊密碼也失敗
	//（退出碼 5）。遠端狀態不可知，候選保留
	ChangeSecretReasonRemoteSelfVerifyRollbackFailed = "CHANGE_SECRET_REMOTE_SELF_VERIFY_ROLLBACK_FAILED"
	ChangeSecretReasonPromoteFailed                  = "CHANGE_SECRET_PROMOTE_FAILED"
	ChangeSecretReasonSFTPOpenFailed                 = "CHANGE_SECRET_SFTP_OPEN_FAILED"
	ChangeSecretReasonAuthorizedKeysReadFailed       = "CHANGE_SECRET_AUTHORIZED_KEYS_READ_FAILED"
	ChangeSecretReasonAuthorizedKeysWriteFailed      = "CHANGE_SECRET_AUTHORIZED_KEYS_WRITE_FAILED"
	// ChangeSecretReasonKeyVerifyFailedRestored 新鑰驗證失敗且 authorized_keys 已還原
	ChangeSecretReasonKeyVerifyFailedRestored = "CHANGE_SECRET_KEY_VERIFY_FAILED_RESTORED"
	// ChangeSecretReasonKeyVerifyFailedRestoreFailed 新鑰驗證失敗且還原也失敗（狀態不可知）
	ChangeSecretReasonKeyVerifyFailedRestoreFailed = "CHANGE_SECRET_KEY_VERIFY_FAILED_RESTORE_FAILED"

	// --- 重試執行器 ---
	ChangeSecretReasonRetryPromoted          = "CHANGE_SECRET_RETRY_PROMOTED"
	ChangeSecretReasonRetrySecretUnavailable = "CHANGE_SECRET_RETRY_SECRET_UNAVAILABLE"
	ChangeSecretReasonRetryLoginFailed       = "CHANGE_SECRET_RETRY_LOGIN_FAILED"

	// --- 背景工作授權重驗 ---
	// ChangeSecretReasonAuthzRevoked 發起者當下的權限已不足，工作停止（遠端未被觸碰）
	ChangeSecretReasonAuthzRevoked = "CHANGE_SECRET_AUTHZ_REVOKED"
	// ChangeSecretReasonAuthzContextMissing 工作沒有可指認的發起者（升級前的舊工作或授權脈絡缺失／損毀）
	ChangeSecretReasonAuthzContextMissing = "CHANGE_SECRET_AUTHZ_CONTEXT_MISSING"
	// ChangeSecretReasonAuthzUnavailable 無法判定權限（判定器缺席或讀取失敗），依 fail closed 停止
	ChangeSecretReasonAuthzUnavailable = "CHANGE_SECRET_AUTHZ_UNAVAILABLE"
	// ChangeSecretReasonAuthzTargetChanged 收斂驗證的目標（位址、通道、帳號、掛載或版本）已漂移
	ChangeSecretReasonAuthzTargetChanged = "CHANGE_SECRET_AUTHZ_TARGET_CHANGED"
	// ChangeSecretReasonAuthzConvergenceExpired 失權後的有限收斂驗證已逾期，保留候選待帶外處置
	ChangeSecretReasonAuthzConvergenceExpired = "CHANGE_SECRET_AUTHZ_CONVERGENCE_EXPIRED"
	// ChangeSecretReasonRecoveredCleanupPending 失權後的有限驗證成功並已提交，但 SSH 舊公鑰
	// 尚未清除（失權後不再替原發起者刪舊鑰），需具權者手動清理
	ChangeSecretReasonRecoveredCleanupPending = "CHANGE_SECRET_RECOVERED_CLEANUP_PENDING"
	// ChangeSecretReasonAuthzRestored 工作的授權脈絡建立於還原之前（還原世代不符），背景派送停止：
	// 還原前留下的意圖不得在還原後以過時狀態改動遠端；需具權者重新確認（手動重試或重新授權）
	ChangeSecretReasonAuthzRestored = "CHANGE_SECRET_AUTHZ_RESTORED"
	// ChangeSecretReasonHostIdentityChanged 目標主機的身分與秘密送出當時綁定的不同（或無從核對），
	// 背景作業在撥號前、握手或提交前停止：候選保留，本地不提交，待具權者確認後處置
	// （是否已用新憑證登入過依停止審計的 verification_sent 判斷，不由本原因碼保證）
	ChangeSecretReasonHostIdentityChanged = "CHANGE_SECRET_HOST_IDENTITY_CHANGED"
	// ChangeSecretReasonScopeBoundExceeded 憑證目標計畫的當下掛載有範圍外部分不在該版掛載上界內：
	// 整次停止、遠端零操作，計畫轉待重新確認
	ChangeSecretReasonScopeBoundExceeded = "CHANGE_SECRET_SCOPE_BOUND_EXCEEDED"

	// --- 服務重啟 ---
	// ChangeSecretReasonInterrupted 服務重啟時本台正在改密（成員停在改密中），遠端是否已收下新秘密未知：
	// 啟動時轉為已送出未驗證並保留候選，由逐台補跑以新秘密驗證確認
	ChangeSecretReasonInterrupted = "CHANGE_SECRET_INTERRUPTED"
)

// ChangeSecretReasons 全部合法原因碼；守衛測試以此為封閉集合比對，
// 任何落庫的 error／last_error 若不在集合內即代表有動態字串被拼了進去。
//
// 刻意用函式而非包級 var：包級可變切片會被 lifecycle manifest 守衛要求登記
// 時序語義，而本集合只是常數表、沒有任何初始化順序意義。
func ChangeSecretReasons() []string {
	return []string{
		ChangeSecretReasonAssetLookupFailed,
		ChangeSecretReasonProtocolUnsupported,
		ChangeSecretReasonAccountLookupFailed,
		ChangeSecretReasonNoAccountInScope,
		ChangeSecretReasonSharedCredentialTargetRequired,
		ChangeSecretReasonChannelNotConfigured,
		ChangeSecretReasonSecretTypeUnsupported,
		ChangeSecretReasonCandidateQueryFailed,
		ChangeSecretReasonCandidatePending,
		ChangeSecretReasonCandidatePersistFailed,
		ChangeSecretReasonCredentialLoadFailed,
		ChangeSecretReasonAccountChanged,
		ChangeSecretReasonNoCredential,
		ChangeSecretReasonNoPasswordCredential,
		ChangeSecretReasonPasswordGenerateFailed,
		ChangeSecretReasonKeypairGenerateFailed,
		ChangeSecretReasonInvalidAccountName,
		ChangeSecretReasonInvalidNewSecret,
		ChangeSecretReasonAccountNameInvalid,
		ChangeSecretReasonInvalidOldSecret,
		ChangeSecretReasonOldCredentialLoginFailed,
		ChangeSecretReasonHostKeyMismatch,
		ChangeSecretReasonHostKeyCheckFailed,
		ChangeSecretReasonRemoteRejected,
		ChangeSecretReasonRemoteStateUnknown,
		ChangeSecretReasonRemoteUnreachable,
		ChangeSecretReasonVerifyFailed,
		ChangeSecretReasonWinRMEncryptionUnavailable,
		ChangeSecretReasonStdinNotDelivered,
		ChangeSecretReasonRemoteSelfVerifyFailed,
		ChangeSecretReasonRemoteSelfVerifyRollbackFailed,
		ChangeSecretReasonPromoteFailed,
		ChangeSecretReasonSFTPOpenFailed,
		ChangeSecretReasonAuthorizedKeysReadFailed,
		ChangeSecretReasonAuthorizedKeysWriteFailed,
		ChangeSecretReasonKeyVerifyFailedRestored,
		ChangeSecretReasonKeyVerifyFailedRestoreFailed,
		ChangeSecretReasonRetryPromoted,
		ChangeSecretReasonRetrySecretUnavailable,
		ChangeSecretReasonRetryLoginFailed,
		ChangeSecretReasonAuthzRevoked,
		ChangeSecretReasonAuthzContextMissing,
		ChangeSecretReasonAuthzUnavailable,
		ChangeSecretReasonAuthzTargetChanged,
		ChangeSecretReasonAuthzConvergenceExpired,
		ChangeSecretReasonRecoveredCleanupPending,
		ChangeSecretReasonAuthzRestored,
		ChangeSecretReasonHostIdentityChanged,
		ChangeSecretReasonScopeBoundExceeded,
		ChangeSecretReasonInterrupted,
	}
}

// IsChangeSecretReason 回報字串是否為合法原因碼（空字串＝無訊息，視為合法）
func IsChangeSecretReason(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range ChangeSecretReasons() {
		if r == s {
			return true
		}
	}
	return false
}
