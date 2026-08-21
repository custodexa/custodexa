package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// ErrAlreadySigned 當日已有簽核記錄
var ErrAlreadySigned = errors.New("當日已完成簽核")

// AlreadySignedError 當日已簽核，附既有簽核的時刻與簽核者。
//
// 「幾點、由誰簽的」是使用者判斷「不是我漏簽、無須再追」的必需資訊；handler
// 無法從 sentinel 反推，故以具名欄位帶出，轉為 apierror 的 {time}/{signer}
// opaque params。errors.Is(err, ErrAlreadySigned) 續可比對。
type AlreadySignedError struct {
	// SignedAt 既有簽核的時刻（HH:MM，簽核紀錄的建立時間）
	SignedAt string
	// Signer 既有簽核者顯示名（自由字串，出 wire 前經 apierror 淨化）
	Signer string
}

func (e *AlreadySignedError) Error() string {
	return fmt.Sprintf("%s（%s 由 %s 簽核）", ErrAlreadySigned.Error(), e.SignedAt, e.Signer)
}

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *AlreadySignedError) Unwrap() error { return ErrAlreadySigned }

// reviewDateFormat DailyReviewLog.ReviewDate 的日期格式
const reviewDateFormat = "2006-01-02"

// DailyReviewSnapshot 簽核當下的安全事件計數快照（PCI 10.4.1：
// 固化簽核者當時所見，QSA 可比對）
type DailyReviewSnapshot struct {
	Date string `json:"date"`
	// LoginFailures 當日登入失敗數（audit_logs action=login，status 為 failure 或 denied）
	LoginFailures int64 `json:"login_failures"`
	// UnreviewedAlerts 當日觸發且尚未審閱的告警數
	UnreviewedAlerts int64 `json:"unreviewed_alerts"`
	// HighRiskOps 當日高危操作數（design D5 白名單：任何資源的刪除、
	// 安全政策/syslog 設定變更、稽核證據匯出、使用者帳號寫入）
	HighRiskOps int64 `json:"high_risk_ops"`
}

// DailyReviewService 每日審閱簽核（audit-log-compliance，PCI 10.4.1/10.4.1.1）
type DailyReviewService struct {
	db     *gorm.DB
	policy *policy.SecurityPolicyService
	audit  auditLogger
}

// NewDailyReviewService 建立每日審閱服務
func NewDailyReviewService(db *gorm.DB, policy *policy.SecurityPolicyService, audit auditLogger) *DailyReviewService {
	return &DailyReviewService{db: db, policy: policy, audit: audit}
}

// Enabled 每日審閱功能是否啟用（政策 daily_review_enabled）
func (s *DailyReviewService) Enabled() bool {
	return s.policy.GetBool(policy.PolicyDailyReviewEnabled)
}

// Snapshot 計算指定日期（本地時區）的安全事件計數
func (s *DailyReviewService) Snapshot(date time.Time) (*DailyReviewSnapshot, error) {
	dayStart := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	dayEnd := dayStart.AddDate(0, 0, 1)
	snap := &DailyReviewSnapshot{Date: dayStart.Format(reviewDateFormat)}

	// 登入失敗數涵蓋**兩種狀態值**（audit-coverage-closure D3）：認證失敗記
	// `failure`（密碼錯誤、憑證交換失敗），授權拒絕記 `denied`（OIDC 准入規則拒絕、
	// 外部帳號以本地密碼登入、LDAP 傳輸嚴格拒絕）。只數其一會讓外部身分提供者的
	// 登入拒絕全數漏算，PCI 10.4.1 的覆核因而失效。
	//
	// **判準是 `action=login` 而非 `resource=auth`**：資源授權拒絕（RBAC 403）的
	// action 依方法推導（read／create／…），永遠不是 login，故不會被誤計；反之
	// 若以 resource 收斂，`resource=user` 的外部帳號登入嘗試與 `resource=transmission`
	// 的 LDAP 傳輸拒絕會被排除——那正是本 change 要修的漏算，不能一邊修一邊製造
	//
	// **例行的 token 到期不計入**：access token 每 15 分鐘到期一次、前端自動 refresh，
	// 每次都會產生一筆認證中介層的匿名拒絕列。照單全收會讓這個數字被正常流量淹沒，
	// PCI 10.4.1 的覆核價值歸零——修一個缺口不能用另一種方式弄壞同一個數字。
	// 排除的是**審計側**的原因碼（`model.AuditReasonTokenExpired`），對外回應仍與
	// 簽章無效不可區分。無憑證與簽章無效兩者維持計入：那是真正的無效存取嘗試訊號。
	//
	// `COALESCE` 不可省：`NOT LIKE` 遇 NULL 得 NULL，會把所有 details 為 NULL 的列
	// 靜默排除——那正是既有登入失敗列的形狀（handler 自寫的登入失敗不帶 details）
	if err := s.db.Model(&model.AuditLog{}).
		Where("action = ? AND status IN ? AND created_at >= ? AND created_at < ?",
			model.ActionLogin, []model.AuditStatus{model.StatusFailure, model.StatusDenied},
			dayStart, dayEnd).
		Where("COALESCE(details, '') NOT LIKE ?", `%"reason":"`+model.AuditReasonTokenExpired+`"%`).
		Count(&snap.LoginFailures).Error; err != nil {
		return nil, fmt.Errorf("統計登入失敗數: %w", err)
	}

	if err := s.db.Model(&model.CommandAlert{}).
		Where("triggered_at >= ? AND triggered_at < ? AND reviewed_at IS NULL", dayStart, dayEnd).
		Count(&snap.UnreviewedAlerts).Error; err != nil {
		return nil, fmt.Errorf("統計未審閱告警數: %w", err)
	}

	if err := s.db.Model(&model.AuditLog{}).
		Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).
		Where("action = ? OR resource IN ? OR (resource = ? AND action IN ?)",
			model.ActionDelete,
			[]model.AuditResource{model.ResourceSecurityPolicy, model.ResourceSyslogSetting, model.ResourceAuditExport},
			model.ResourceUser,
			[]model.AuditAction{model.ActionCreate, model.ActionUpdate}).
		Count(&snap.HighRiskOps).Error; err != nil {
		return nil, fmt.Errorf("統計高危操作數: %w", err)
	}
	return snap, nil
}

// Sign 簽核指定日期的審閱（每日至多一筆；衝突回 ErrAlreadySigned）。
// 快照於簽核時刻計算並固化入列
func (s *DailyReviewService) Sign(date time.Time, reviewerID uint, reviewerName, note string) (*model.DailyReviewLog, error) {
	snap, err := s.Snapshot(date)
	if err != nil {
		return nil, err
	}
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("快照序列化: %w", err)
	}

	row := &model.DailyReviewLog{
		ReviewDate:   snap.Date,
		ReviewerID:   reviewerID,
		ReviewerName: reviewerName,
		SnapshotJSON: string(snapJSON),
		Note:         note,
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var existing model.DailyReviewLog
		switch findErr := tx.Where("review_date = ?", snap.Date).First(&existing).Error; {
		case findErr == nil:
			return &AlreadySignedError{
				SignedAt: existing.CreatedAt.Format("15:04"),
				Signer:   existing.ReviewerName,
			}
		case errors.Is(findErr, gorm.ErrRecordNotFound):
			// 可簽核
		default:
			return fmt.Errorf("查詢既有簽核: %w", findErr)
		}
		return tx.Create(row).Error
	})
	if err != nil {
		return nil, err
	}

	if s.audit != nil {
		s.audit.Log(&AuditLogEntry{
			UserID: reviewerID, Username: reviewerName,
			Action: model.ActionCreate, Resource: model.ResourceDailyReview,
			ResourceID: &row.ID, Status: model.StatusSuccess,
			Details: string(snapJSON),
		})
	}
	return row, nil
}

// Status 今日簽核狀態（卡片渲染用）：功能開關、今日快照、既有簽核（若有）
func (s *DailyReviewService) Status(now time.Time) (map[string]any, error) {
	enabled := s.Enabled()
	result := map[string]any{"enabled": enabled}
	if !enabled {
		return result, nil
	}
	snap, err := s.Snapshot(now)
	if err != nil {
		return nil, err
	}
	result["snapshot"] = snap

	var existing model.DailyReviewLog
	switch err := s.db.Where("review_date = ?", snap.Date).First(&existing).Error; {
	case err == nil:
		result["signed"] = true
		result["review"] = existing
	case errors.Is(err, gorm.ErrRecordNotFound):
		result["signed"] = false
	default:
		return nil, fmt.Errorf("查詢今日簽核: %w", err)
	}
	return result, nil
}

// List 簽核歷史（新到舊）
func (s *DailyReviewService) List(page, pageSize int) ([]model.DailyReviewLog, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	var total int64
	if err := s.db.Model(&model.DailyReviewLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.DailyReviewLog
	err := s.db.Order("review_date DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).Find(&rows).Error
	return rows, total, err
}

// CheckOverdue 逾期檢查（reminder scheduler 每日呼叫）：功能啟用且昨日無簽核
// 即經通知通道發送提醒；回傳是否發送（供測試斷言）
func (s *DailyReviewService) CheckOverdue(now time.Time) bool {
	if !s.Enabled() {
		return false
	}
	yesterday := now.AddDate(0, 0, -1).Format(reviewDateFormat)
	var count int64
	if err := s.db.Model(&model.DailyReviewLog{}).
		Where("review_date = ?", yesterday).Count(&count).Error; err != nil {
		log.Printf("[DailyReview] 逾期檢查查詢失敗: %v", err)
		return false
	}
	if count > 0 {
		return false
	}
	if notifier := GetAlertNotifier(); notifier != nil {
		notifier.NotifyEvent(notifycat.EventDailyReviewOverdue,
			map[string]string{"date": yesterday})
	}
	log.Printf("[DailyReview] %s 未簽核，已發送逾期提醒", yesterday)
	return true
}
