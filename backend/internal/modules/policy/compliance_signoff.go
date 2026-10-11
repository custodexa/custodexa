package policy

import (
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
)

// 每日審閱條文（PCI DSS 10.4.1）的運作紀錄判定。
//
// 只看開關的話，「開著但天天漏簽」也判符合——稽核要的是每天真的有審。這一類
// 條文改用比較方式 signoff_record：開關要開著，且近 30 天（截至昨日）沒有應簽
// 而未簽的日子。遲簽只計數顯示，不影響結果（補簽有延遲原因留證）。
//
// 運作紀錄由呼叫端備齊（實作在 audit 模組的每日簽核服務，經組裝根以窄介面注入），
// 判定本身仍是純函式、不碰資料庫。

// ComplianceResultInsufficientData 以運作紀錄判定的條文，紀錄期間尚不足以判斷
// 或紀錄取不到。**不併入符合或偏離**：說不知道比冒充符合誠實
const ComplianceResultInsufficientData = "insufficient_data"

// 運作紀錄判定的理由碼
const (
	// ComplianceReasonDailyReviewDisabled 每日審閱簽核未開啟
	ComplianceReasonDailyReviewDisabled = "daily_review_disabled"
	// ComplianceReasonSignoffSourceUnavailable 取不到每日簽核的運作紀錄（未注入或查詢失敗）
	ComplianceReasonSignoffSourceUnavailable = "signoff_source_unavailable"
	// ComplianceReasonSignoffInsufficientData 目前這段連續啟用累計未滿 7 天
	ComplianceReasonSignoffInsufficientData = "signoff_insufficient_data"
	// ComplianceReasonSignoffUnsignedDays 近 30 天有應簽而未簽的日子
	ComplianceReasonSignoffUnsignedDays = "signoff_unsigned_days"
)

// SignoffMinEnabledDays 判定所需的最少連續啟用天數（自啟用起點所屬日至昨日）
const SignoffMinEnabledDays = 7

// 逐日清單的狀態（CSV 與 PDF 的類型欄）。與期間統計的結果不同之處：
// 已簽而尚未到期的日子（例如昨日已準時簽）在這裡仍是準時，只是不計入統計
const (
	SignoffStatusOnTime   = reviewcal.ResultOnTime
	SignoffStatusLate     = reviewcal.ResultLate
	SignoffStatusUnsigned = reviewcal.ResultUnsigned
	SignoffStatusNotDue   = reviewcal.ResultNotDue
)

// SignoffRecord 每日簽核近 30 天的運作紀錄（判定、合規對照頁與報告共用同一份）。
type SignoffRecord struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	AsOf     time.Time `json:"as_of"`
	Timezone string    `json:"timezone"`
	// Required 應簽＝期間內在啟用範圍內且準時期限已過的日子（含推定為啟用者）
	Required int `json:"required"`
	OnTime   int `json:"on_time"`
	Late     int `json:"late"`
	Unsigned int `json:"unsigned"`
	// SignRatePercent （準時＋遲簽）／應簽，無條件捨去；應簽為 0 時為 null
	SignRatePercent *int `json:"sign_rate_percent"`
	// InferredDays 應簽之中啟用狀態由升級遷移推定而來的天數（只用於呈現，不影響結果）
	InferredDays         int        `json:"inferred_days"`
	EnabledSince         *time.Time `json:"enabled_since"`
	EnabledSinceInferred bool       `json:"enabled_since_inferred"`
	EnabledDays          int        `json:"enabled_days"`
	// EarliestUnsigned 計入統計且未簽的最早日期；沒有則空
	EarliestUnsigned string `json:"earliest_unsigned,omitempty"`
	// Days 期間內的逐日清單（只有合規報告要；判定與畫面不帶）
	Days []SignoffDay `json:"-"`
}

// SignoffDay 逐日清單的一列（證據包與合規報告的 daily_reviews.csv 同一套欄位）。
//
// 計數欄為指標：來源已依保留政策清除時為 nil，輸出成空白而不是 0——
// 0 會被讀成「那天沒有事件」。
type SignoffDay struct {
	Date             string
	Timezone         string
	TimezoneInferred bool
	// EnabledBasis recorded，或 presumed_purged／presumed_gap／presumed_tail（已簽列取簽核時固化的值）
	EnabledBasis      string
	WindowStart       time.Time
	WindowEnd         time.Time
	DueAt             time.Time
	Status            string
	CountsTowardStats bool
	SignedAt          *time.Time
	Signer            string
	LateDays          int
	DelayReason       string
	ReviewNote        string
	// Coverage 計數涵蓋該日的方式（full_day／until_signed）
	Coverage           string
	AuditLogSource     string
	CommandAlertSource string
	LoginFailures      *int64
	AlertsTotal        *int64
	AlertsBenign       *int64
	AlertsEscalated    *int64
	HighRiskOps        *int64
	// AlertsAfterSign 簽核後才出現的未審閱告警（未簽列與升級前的 until_signed 列為 nil）
	AlertsAfterSign *int64
	// ReviewID 簽核紀錄編號（未簽為 0）
	ReviewID uint
}

// SignoffRecordSource 運作紀錄的來源（消費者側窄介面；實作在 audit 模組）。
// withDays 為 true 時連同逐日清單（含計數與簽核者）一併備齊。
type SignoffRecordSource interface {
	SignoffRecord(withDays bool) (*SignoffRecord, error)
}

// NewSignoffRecord 由期間統計攤出運作紀錄（逐日清單另由呼叫端補上）。
func NewSignoffRecord(st *reviewcal.Stats) *SignoffRecord {
	return &SignoffRecord{
		From: st.From, To: st.To, AsOf: st.AsOf, Timezone: st.Timezone,
		Required: st.Required, OnTime: st.OnTime, Late: st.Late, Unsigned: st.Unsigned,
		SignRatePercent: st.SignRatePercent, InferredDays: st.InferredDays,
		EnabledSince: st.EnabledSince, EnabledSinceInferred: st.EnabledSinceInferred,
		EnabledDays: st.EnabledDays, EarliestUnsigned: st.EarliestUnsigned(),
	}
}

// summary 不含逐日清單的副本（掛在判定上對外）。
func (r *SignoffRecord) summary() *SignoffRecord {
	out := *r
	out.Days = nil
	return &out
}

// buildSignoffVerdict 運作紀錄判定，依序：
//  1. 開關未開啟 → 偏離（不帶運作紀錄：關閉時不顯示簽核率）
//  2. 取不到運作紀錄 → 資料不足（不退回只看開關而判符合）
//  3. 連續啟用未滿 7 天 → 資料不足
//  4. 近 30 天未簽 0 天 → 符合（遲簽只隨判定顯示）
//  5. 否則 → 偏離
//
// 推定為啟用的日子與其他日子一樣計入應簽，不另成資料不足的理由。
func buildSignoffVerdict(verdict Verdict, value string, rec *SignoffRecord) Verdict {
	if value != "true" {
		verdict.Result = ComplianceResultDeviating
		verdict.Reason = ComplianceReasonDailyReviewDisabled
		return verdict
	}
	if rec == nil {
		verdict.Result = ComplianceResultInsufficientData
		verdict.Reason = ComplianceReasonSignoffSourceUnavailable
		return verdict
	}
	verdict.Signoff = rec.summary()
	switch {
	case rec.EnabledDays < SignoffMinEnabledDays:
		verdict.Result = ComplianceResultInsufficientData
		verdict.Reason = ComplianceReasonSignoffInsufficientData
	case rec.Unsigned == 0:
		verdict.Result = ComplianceResultCompliant
		verdict.Reason = ComplianceReasonMeets
	default:
		verdict.Result = ComplianceResultDeviating
		verdict.Reason = ComplianceReasonSignoffUnsignedDays
	}
	return verdict
}

// usesSignoffRecord 控制清單裡是否有以運作紀錄判定的要求（沒有就不必去取紀錄）。
func usesSignoffRecord(controls []model.PolicyClauseControl) bool {
	for _, c := range controls {
		if c.Comparator == model.PolicyControlComparatorSignoffRecord {
			return true
		}
	}
	return false
}
