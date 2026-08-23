package seal

import (
	"errors"
	"fmt"
)

// 封印狀態機的出口機器碼。
//
// 本套件只回傳機器碼常數與 error，不生成任何使用者可見文字——HTTP 狀態碼、
// 三語文案與 apierror registry 的登記由接線層負責。
const (
	// CodeUnsealInProgress 已有持有者在飛（格 3）。對外 409。
	CodeUnsealInProgress = "SEAL_UNSEAL_IN_PROGRESS"
	// CodeCleanupPending 前代持有者尚待收束（格 3）。對外 409，專屬機器碼。
	CodeCleanupPending = "SEAL_CLEANUP_PENDING"
	// CodeAlreadyUnsealed 已解封（格 3）。對外 409，且不重跑初始化。
	CodeAlreadyUnsealed = "SEAL_ALREADY_UNSEALED"

	// CodeCooldownActive 全域冷卻期內抵達。不驗證、不進 CAS、
	// 不計入失敗計數、不刷新到期時間。
	CodeCooldownActive = "SEAL_COOLDOWN_ACTIVE"
	// CodeBackoffActive per-source 退避期內抵達。
	CodeBackoffActive = "SEAL_BACKOFF_ACTIVE"

	// CodeMaterialInvalid 材料驗證失敗（格 4）。對外 400，計入材料失敗計數。
	CodeMaterialInvalid = "SEAL_MATERIAL_INVALID"

	// CodeAborted 解封嘗試被主動中止（格 3b／4b）：請求取消、panic 或
	// PREPARE 寫入逾時。不計入材料失敗計數。
	CodeAborted = "SEAL_ABORTED"
	// CodeJournalIOFailure journal I/O 故障（格 3b 的成因之一，另觸發封印期留痕的 fail-close）。
	CodeJournalIOFailure = "SEAL_JOURNAL_IO_FAILURE"

	// CodeInitFailed 段 2 初始化失敗（格 6，逾時以外的一切失敗，含取消／panic）。
	CodeInitFailed = "SEAL_INIT_FAILED"
	// CodeStage2Timeout 段 2 逾時（格 7，僅逾時）。不計入材料失敗計數，另計逾時次數。
	CodeStage2Timeout = "SEAL_STAGE2_TIMEOUT"

	// CodePublishUnconfirmed 段 2 完成但服務從未發佈（格 5b）：
	// SUCCESS 未 durable，或 SUCCESS 已 durable 而 publish CAS 未成功。
	// 兩種成因同一處置；journal 上表現為「已驗證通過但未確認發佈」，且不鎖死。
	CodePublishUnconfirmed = "SEAL_PUBLISH_UNCONFIRMED"

	// CodeSuperseded 本世代已被較新世代取代，終局副作用經 CAS 丟棄。
	CodeSuperseded = "SEAL_SUPERSEDED"
)

// Error 為封印狀態機的出口錯誤，攜帶機器碼與所屬遷移格。
type Error struct {
	// Code 為機器碼常數（上列 Code* 之一）
	Code string
	// Cell 為產生本錯誤的遷移表格號（"3"、"3b"、"4"…），供測試與稽核對照
	Cell string
	// Generation 為相關世代號；未取得持有權時為觀察到的當代世代號
	Generation uint64
	// Cause 為底層成因（可為 nil）
	Cause error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("seal: %s (cell %s, gen %d): %v", e.Code, e.Cell, e.Generation, e.Cause)
	}
	return fmt.Sprintf("seal: %s (cell %s, gen %d)", e.Code, e.Cell, e.Generation)
}

func (e *Error) Unwrap() error { return e.Cause }

// CodeOf 取出 error 攜帶的機器碼；非本套件錯誤回空字串。
func CodeOf(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// CellOf 取出 error 對應的遷移格號；非本套件錯誤回空字串。
func CellOf(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return se.Cell
	}
	return ""
}

func newError(code, cell string, gen uint64, cause error) *Error {
	return &Error{Code: code, Cell: cell, Generation: gen, Cause: cause}
}
