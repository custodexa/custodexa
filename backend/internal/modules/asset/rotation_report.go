package asset

import "time"

// 輪替證據報告的資料結構。
//
// **三種輸出（畫面、CSV、PDF）共用這一份結構**：各自查詢即各自有一套隱性假設，
// 而稽核最不能接受的就是同一份報告的三種形式對不上數字。

// 狀態桶（互斥，判定順序見建構函式）。
const (
	// BucketUnverified 帳號有未驗證候選：本系統對遠端憑證的狀態不可知
	BucketUnverified = "unverified"
	// BucketNoPolicy 無適用天數（全域與計劃皆未設定）：無從判定逾期
	BucketNoPolicy = "no_policy"
	// BucketNoRecord 本系統無成功改密記錄。**不代表未曾改密**
	BucketNoRecord = "no_record"
	// BucketOverdue 已超過適用天數
	BucketOverdue = "overdue"
	// BucketDueSoon 於預警窗內到期
	BucketDueSoon = "due_soon"
	// BucketCompliant 其餘
	BucketCompliant = "compliant"
)

// 候選狀態（未驗證候選列的三態）。
const (
	CandidateNone      = "none"
	CandidatePending   = "pending"
	CandidateAbandoned = "abandoned"
)

// 憑證型別。
const (
	CredentialTypePassword = "password"
	CredentialTypeSSHKey   = "ssh_key"
	CredentialTypeNone     = "none"
)

// 天數來源。
const (
	// MaxAgeSourceGlobal 取自全域安全政策鍵
	MaxAgeSourceGlobal = "global"
	// MaxAgeSourcePlanPrefix 取自計劃覆蓋，其後接計劃名
	MaxAgeSourcePlanPrefix = "plan:"
)

// dueSoonWindowDays 到期預警窗（日）。
//
// 固定值而非設定項：它是稽核閱讀慣例的一部分，可設定會讓兩份報告的
// 「30 天內到期」互相不可比。要改的觸發點是機構明確要求。
const dueSoonWindowDays = 30

// 產出上限。超過即截斷並記入 Meta，絕不靜默。
const (
	// ReportRowsCap 帳號列上限
	ReportRowsCap = 20000
	// ReportRecordsCap 區間記錄列上限
	ReportRecordsCap = 50000
)

// ReportScope 報告範圍。
type ReportScope struct {
	// Kind 見 model.RotationScope* 常數：all／node／plan
	Kind string
	// ID node 或 plan 的識別碼；Kind 為 all 時為 0
	ID uint
}

// ReportMeta 報告的自述：這份報告涵蓋什麼、以哪一刻為準。
type ReportMeta struct {
	ScopeKind   string    `json:"scope_kind"`
	ScopeID     uint      `json:"scope_id"`
	ScopeLabel  string    `json:"scope_label"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	AsOf        time.Time `json:"as_of"`
	// GeneratedAt 這份資料集建構完成的時刻（與 AsOf 分離：後者是計算基準，
	// 前者是「這張紙什麼時候印出來的」）
	GeneratedAt time.Time `json:"generated_at"`
	// GlobalMaxAgeDays 全域政策鍵當下的值；0＝未設定
	GlobalMaxAgeDays int `json:"global_max_age_days"`
	// DueSoonWindowDays 預警窗，隨報告出站以便讀者複算
	DueSoonWindowDays int    `json:"due_soon_window_days"`
	Language          string `json:"language"`
	// GeneratedBy 發起者（使用者名或排程名）；由建立工作單的一側填入
	GeneratedBy string `json:"generated_by"`
	// ProductVersion 產出這份報告的版本；由呼叫端填入
	ProductVersion string `json:"product_version,omitempty"`
}

// ReportSummary 摘要數字。合規率為 nil 代表分母為零，輸出「不適用」而非 0%。
type ReportSummary struct {
	TotalAccounts int `json:"total_accounts"`
	Compliant     int `json:"compliant"`
	Overdue       int `json:"overdue"`
	DueWithin30   int `json:"due_within_30"`
	NoRecord      int `json:"no_record"`
	Unverified    int `json:"unverified"`
	NoPolicy      int `json:"no_policy"`

	SharedCredential int `json:"shared_credential"`
	MultiPlan        int `json:"multi_plan"`

	// RateExcludingNoRecord compliant ÷ (X − no_record)，X＝總數 − no_policy − unverified
	RateExcludingNoRecord *float64 `json:"rate_excluding_no_record"`
	// RateCountingNoRecord compliant ÷ X
	RateCountingNoRecord *float64 `json:"rate_counting_no_record"`
}

// AccountRow 一個帳號一列。
type AccountRow struct {
	AccountID    uint   `json:"account_id"`
	AssetID      uint   `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	AssetAddress string `json:"asset_address"`
	Protocol     string `json:"protocol"`
	Username     string `json:"username"`
	// CredentialType 見 CredentialType* 常數（只說型別，不透露任何憑證內容）
	CredentialType   string `json:"credential_type"`
	Privileged       bool   `json:"privileged"`
	SharedCredential bool   `json:"shared_credential"`

	// Plans 涵蓋本帳號的已啟用計劃名稱
	Plans     []string `json:"plans"`
	MultiPlan bool     `json:"multi_plan"`

	// MaxAgeDays 適用天數；0＝未設定
	MaxAgeDays int `json:"max_age_days"`
	// MaxAgeSource 見 MaxAgeSource* 常數；未設定時為空
	MaxAgeSource string `json:"max_age_source"`

	LastSuccessAt *time.Time `json:"last_success_at"`
	// LastRecordStatus 最近一筆改密記錄的狀態（任意狀態）；無記錄時為空
	LastRecordStatus string `json:"last_record_status"`

	// RemainingDaysA 適用天數 − 距最後成功改密的整日數
	RemainingDaysA *int       `json:"remaining_days_a"`
	NextScheduleAt *time.Time `json:"next_schedule_at"`
	// RemainingDaysB 下次排程 − 截止時點的整日數
	RemainingDaysB *int `json:"remaining_days_b"`

	// CandidateState 見 Candidate* 常數
	CandidateState string `json:"candidate_state"`
	Bucket         string `json:"bucket"`
}

// RecordRow 區間內的一筆改密記錄。
type RecordRow struct {
	RecordID   uint      `json:"record_id"`
	ExecutedAt time.Time `json:"executed_at"`
	PlanName   string    `json:"plan_name"`
	AssetName  string    `json:"asset_name"`
	// AccountUsername 執行當下的帳號名快照；帳號已刪除時這是唯一還讀得出的名字
	AccountUsername string `json:"account_username"`
	AccountDeleted  bool   `json:"account_deleted"`
	SecretType      string `json:"secret_type"`
	Status          string `json:"status"`
	// ReasonCode 只有系統列舉的機器碼，不含遠端回傳的任何字串
	ReasonCode string `json:"reason_code"`
}

// ReportTruncation 截斷狀態。上限與是否截斷都出站——讀者必須能分辨
// 「這就是全部」與「這是前 N 筆」。
type ReportTruncation struct {
	RowsCap          int  `json:"rows_cap"`
	RowsTruncated    bool `json:"rows_truncated"`
	RecordsCap       int  `json:"records_cap"`
	RecordsTruncated bool `json:"records_truncated"`
}

// RotationReport 一次建構的完整結果。
type RotationReport struct {
	Meta       ReportMeta       `json:"meta"`
	Summary    ReportSummary    `json:"summary"`
	Rows       []AccountRow     `json:"rows"`
	Records    []RecordRow      `json:"records"`
	Truncation ReportTruncation `json:"truncation"`
}
