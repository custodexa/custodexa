package asset

import (
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 主機身分停止時給管理者看的唯讀檢視。
//
// 只含判斷「要不要確認新主機身分」需要的事實：原本綁定的是哪把、現在出示的是哪把、
// 新秘密有沒有送出過認證、還能不能承接。**不含任何秘密、公鑰本體或來源資產**：
// 指紋與演算法是對外可觀測的公開值，確認時帶外核對需要看見它們；其餘一律不進結構。

// HostIdentityOriginalView 工作送出當時綁定的主機身分。
type HostIdentityOriginalView struct {
	Transport   string     `json:"transport"`
	RecordID    uint       `json:"record_id"`
	Algorithm   string     `json:"algorithm"`
	Fingerprint string     `json:"fingerprint"`
	Generation  int64      `json:"generation"`
	Binding     string     `json:"binding"`
	BoundAt     *time.Time `json:"bound_at"`
}

// HostIdentityCurrentView 主機當下的自身記錄。RecordedAt 取自身列的更新時刻
// （採用、重錄與位址補記都會更新它，所以只代表最近更新，不是信任建立時間）。
type HostIdentityCurrentView struct {
	Transport    string    `json:"transport"`
	RecordID     uint      `json:"record_id"`
	Algorithm    string    `json:"algorithm"`
	Fingerprint  string    `json:"fingerprint"`
	Generation   int64     `json:"generation"`
	ResetPending bool      `json:"reset_pending"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// HostIdentityView 一次身分停止的唯讀檢視（重試回應的 host_identity）。
type HostIdentityView struct {
	// Status changed／unbound_legacy／record_missing／reset_pending／transport_changed
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Phase 最近一次停止的階段：precheck／handshake／commit
	Phase string `json:"phase"`
	// VerificationSent 最近一次停止所屬的那次驗證是否已用新秘密送出過認證：true／false／unknown
	VerificationSent string                    `json:"verification_sent"`
	Original         *HostIdentityOriginalView `json:"original"`
	Current          *HostIdentityCurrentView  `json:"current"`
	CandidateApplied bool                      `json:"candidate_applied"`
	Deadline         *time.Time                `json:"deadline"`
	Expired          bool                      `json:"expired"`
	Confirmable      bool                      `json:"confirmable"`
}

// hostIdentityStatusOf 停止細節對映到對外的 status；空字串與查詢不可用（不是身分事件）不產生檢視。
func hostIdentityStatusOf(detail string) string {
	switch detail {
	case "", hostIdentityLookupFailed:
		return ""
	case hostIdentityUnboundLegacy, hostIdentityRecordMissing, hostIdentityResetPending, hostIdentityTransportChanged:
		return detail
	default:
		return "changed"
	}
}

// hostIdentityConfirmable 這種停止能否經人工確認承接：沒有可核對的端點身分，或記錄本身尚待處理的，不能。
func hostIdentityConfirmable(status string) bool {
	switch status {
	case hostIdentityTransportChanged, hostIdentityRecordMissing, hostIdentityResetPending:
		return false
	}
	return true
}

// newHostIdentityView 由一次停止的事實組檢視。尚未綁定（pending）的工作從未送出過秘密，
// 沒有可承接的身分，不給檢視。
func newHostIdentityView(in hostIdentityStopInput, now time.Time) *HostIdentityView {
	status := hostIdentityStatusOf(in.Detail)
	if status == "" || in.Job.Binding == model.HostKeyBindingPending {
		return nil
	}
	v := &HostIdentityView{
		Status: status, Detail: in.Detail, Phase: in.Phase, VerificationSent: in.verificationSent(),
		CandidateApplied: in.CandidateApplied, Deadline: in.Deadline,
		Confirmable: hostIdentityConfirmable(status),
	}
	if in.Deadline != nil {
		v.Expired = now.After(*in.Deadline)
	}
	if in.Job.Binding != model.HostKeyBindingLegacy {
		v.Original = &HostIdentityOriginalView{
			Transport: in.Job.Transport, RecordID: in.Job.RecordID, Algorithm: in.Job.Pin.Algorithm,
			Fingerprint: in.Job.Pin.Fingerprint, Generation: in.Job.Generation,
			Binding: in.Job.Binding, BoundAt: in.Job.BoundAt,
		}
	}
	if c := in.Current; c != nil {
		v.Current = &HostIdentityCurrentView{
			Transport: in.CurrentTransport, RecordID: c.RecordID, Algorithm: c.Algorithm,
			Fingerprint: c.Fingerprint, Generation: c.Generation, ResetPending: c.ResetPending,
			RecordedAt: c.RecordedAt,
		}
	}
	return v
}

// RetryResult 單筆候選重試的結果：是否轉正，以及被主機身分守衛擋下時的唯讀檢視。
type RetryResult struct {
	Promoted     bool
	HostIdentity *HostIdentityView
}

// MemberRunResult 逐台補跑的結果：被主機身分守衛擋下時的唯讀檢視（沒有被擋下為 nil）。
type MemberRunResult struct {
	HostIdentity *HostIdentityView
}
