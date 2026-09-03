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
