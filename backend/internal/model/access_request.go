package model

import (
	"time"

	"gorm.io/gorm"
)

// AccessRequestStatus 申請單狀態（access-policy-approval D2）
type AccessRequestStatus string

const (
	AccessRequestPending   AccessRequestStatus = "pending"   // 待審
	AccessRequestApproved  AccessRequestStatus = "approved"  // 已核准（同交易產生臨時授權）
	AccessRequestRejected  AccessRequestStatus = "rejected"  // 已拒絕
	AccessRequestCancelled AccessRequestStatus = "cancelled" // 申請人撤回
	AccessRequestExpired   AccessRequestStatus = "expired"   // pending 超時作廢
)

// 申請單類別（break-glass-revocation D1）：破窗單復用同一資料軌
const (
	AccessRequestKindNormal     = "normal"      // 一般申請（含 reason 段自動核准）
	AccessRequestKindBreakGlass = "break_glass" // 破窗緊急連線（即時核准＋待補審）
)

// 破窗補審狀態（break-glass-revocation D7）：空值＝非破窗單無需補審
const (
	BreakGlassReviewPending  = "pending_review" // 待補審（破窗單建立即寫入）
	BreakGlassReviewReviewed = "reviewed"       // 已補審（CAS 終態，不可重複）
)

// 破窗補審處置（沿 command_alerts 審閱處置詞彙）
const (
	BreakGlassDispositionConfirmed = "confirmed" // 確認正當
	BreakGlassDispositionViolation = "violation" // 判定違規
)

// AccessRequest 連線申請單（access-policy-approval D2）。
// 單資產申請；狀態轉移一律 CAS（WHERE status='pending'），終態不可復活。
// 去重由 partial 唯一索引保證：同申請人×同資產僅一張 pending 在途單
// （(requester_id, asset_id) WHERE status='pending' AND deleted_at IS NULL，
// 於 20260718 migration 以原生 SQL 建立——GORM tag 表達不了 status 條件）
type AccessRequest struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	RequesterID uint   `gorm:"not null;index:idx_access_request_requester" json:"requester_id"`
	AssetID     uint   `gorm:"not null;index:idx_access_request_asset" json:"asset_id"`
	Reason      string `gorm:"type:varchar(1000);not null" json:"reason"`

	// 申請值：時長必填（≤政策上限，service 層驗證）；起始空＝立即
	RequestedDurationMinutes int        `gorm:"not null" json:"requested_duration_minutes"`
	RequestedDateStart       *time.Time `json:"requested_date_start,omitempty"`

	// Accounts 申請的帳號範圍（asset-multi-account D5）：空＝`@ALL`（既有行為）。
	// 核准時原樣傳遞給臨時授權列——申請「以 app 帳號連」核准後不該拿到 root。
	// 核准人**不得上調**此範圍（同時長/起始的既有「只可下修」語義），
	// 上調等於繞過申請內容授出未經申請的帳號
	Accounts AccountScope `gorm:"type:text" json:"accounts,omitempty"`

	Status AccessRequestStatus `gorm:"type:varchar(20);not null;index:idx_access_request_status" json:"status"`

	// 決定欄位：核准人可下修時長/推遲起始（不可上調，service 層驗證）；
	// 自動核准單 approver_id 為 NULL＋auto_approved 標記（決定者記 system）
	ApproverID              *uint      `json:"approver_id,omitempty"`
	DecidedAt               *time.Time `json:"decided_at,omitempty"`
	DecisionNote            string     `gorm:"type:varchar(1000)" json:"decision_note,omitempty"`
	ApprovedDurationMinutes *int       `json:"approved_duration_minutes,omitempty"`
	ApprovedDateStart       *time.Time `json:"approved_date_start,omitempty"`
	AutoApproved            bool       `json:"auto_approved"`

	// 核准後回填的臨時授權 FK：授權不與申請單共用主鍵，FK＋source 欄各自獨立（授權可獨立增刪）
	AuthorizationID *uint `json:"authorization_id,omitempty"`

	// pending 超時時限（建單時以政策鍵計算寫入；scheduler 掃描＋讀取惰性過濾雙保險）
	PendingExpiresAt time.Time `gorm:"not null;index" json:"pending_expires_at"`

	// 單類別（break-glass-revocation D1）：normal / break_glass；migration 回填既有列
	Kind string `gorm:"type:varchar(20)" json:"kind"`

	// 破窗補審（D7，僅 kind=break_glass 有值）：空 ReviewStatus＝非破窗單。
	// 補審轉移 CAS（WHERE review_status='pending_review'），不可重複補審
	ReviewStatus      string     `gorm:"type:varchar(20);index" json:"review_status,omitempty"`
	ReviewedBy        *uint      `json:"reviewed_by,omitempty"`
	ReviewedAt        *time.Time `json:"reviewed_at,omitempty"`
	ReviewDisposition string     `gorm:"type:varchar(20)" json:"review_disposition,omitempty"`
	ReviewNote        string     `gorm:"type:varchar(1000)" json:"review_note,omitempty"`
	// ReviewOverdueNotifiedAt 逾期升級告警的最近發送時刻（W7b 對抗輪修復）。
	// **取代舊的 `review_overdue_notified` 布林**：布林＝每單至多一次，告警響一次
	// 後永久靜默，無法承擔 D-12「admin 不再是有效審核者」所依賴的可見性保底
	//（零有效審核者時，破窗單只會被提醒一次就沉沒）。改記時間戳後由
	// `overdueRenotifyInterval` 節流週期重發；nil＝從未告警
	ReviewOverdueNotifiedAt *time.Time `json:"-"`

	// 提前撤銷附註（D4）：非狀態轉移——approved 終態不變（CAS 不變式），
	// 撤銷事實由票證軟刪＋此三欄記錄
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *uint      `json:"revoked_by,omitempty"`
	RevokeNote string     `gorm:"type:varchar(1000)" json:"revoke_note,omitempty"`

	// 關聯（用於 Preload）
	Requester     User                `gorm:"foreignKey:RequesterID" json:"requester,omitempty"`
	Asset         *Asset              `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	Approver      *User               `gorm:"foreignKey:ApproverID" json:"approver,omitempty"`
	Authorization *AssetAuthorization `gorm:"foreignKey:AuthorizationID" json:"authorization,omitempty"`

	// quorum 逐票軌跡與進度（approval-routing-quorum D-3）：Approvals 為
	// 核准記錄關聯；Received/Required 非持久欄，讀取路徑由 service 回填
	//（Required 僅對 pending 單有意義——終態單凍結於決定當下的軌跡）
	Approvals         []AccessRequestApproval `gorm:"foreignKey:RequestID" json:"approvals,omitempty"`
	ApprovalsReceived int                     `gorm:"-" json:"approvals_received"`
	ApprovalsRequired int                     `gorm:"-" json:"approvals_required"`
}

// TableName 指定表名
func (AccessRequest) TableName() string {
	return "access_requests"
}

// BeforeCreate GORM Hook - 建立前驗證：申請單一律以 pending 起始
// （自動核准於同交易內 CAS 轉 approved，狀態機軌跡完整）；
// 事由與時長為硬性必填（政策上限由 service 層帶政策值驗證）
func (r *AccessRequest) BeforeCreate(tx *gorm.DB) error {
	// kind 空值回填 normal（同 AssetAuthorization.Source 慣例）：GORM 對空字串
	// 欄位照插不吃 DB default，漏填會讓 pending 去重索引（謂詞 kind='normal'）蓋不到
	if r.Kind == "" {
		r.Kind = AccessRequestKindNormal
	}
	if r.RequesterID == 0 || r.AssetID == 0 {
		return gorm.ErrInvalidValue
	}
	if r.Reason == "" {
		return gorm.ErrInvalidValue
	}
	if r.RequestedDurationMinutes < 1 {
		return gorm.ErrInvalidValue
	}
	if r.Status != AccessRequestPending {
		return gorm.ErrInvalidValue
	}
	if r.PendingExpiresAt.IsZero() {
		return gorm.ErrInvalidValue
	}
	return nil
}

// IsTerminal 是否為終態（approved/rejected/cancelled/expired）
func (r *AccessRequest) IsTerminal() bool {
	return r.Status != AccessRequestPending
}
