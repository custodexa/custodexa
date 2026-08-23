package identity

import (
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// InactivityService 閒置帳號自動停用（PCI 8.2.6）：
// 距最後登入逾政策天數的 active 帳號自動停用。復用 UserService.UpdateStatus
// 確保停用語義一致（撤 refresh＋強制收線協議會話＋last-admin 守衛）
type InactivityService struct {
	db           *gorm.DB
	policies     *policy.SecurityPolicyService
	users        *UserService
	auditService *audit.AuditLogService
}

// NewInactivityService 建立閒置停用服務
func NewInactivityService(db *gorm.DB, policies *policy.SecurityPolicyService, users *UserService, audit *audit.AuditLogService) *InactivityService {
	return &InactivityService{db: db, policies: policies, users: users, auditService: audit}
}

// DisableInactive 掃描並停用閒置帳號。回傳實際停用數。
// 政策 inactive_disable_days=0（出廠預設）時停用此檢查、直接返回（易用取向）
func (s *InactivityService) DisableInactive() (int, error) {
	if s.policies == nil {
		return 0, nil
	}
	days := s.policies.GetInt(policy.PolicyInactiveDisableDays)
	if days <= 0 {
		return 0, nil // 0 = 關閉自動停用
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	// 候選：active 且非豁免；last_login_at 為 NULL（從未登入）者以 created_at 起算
	//（否則新建卻未登入的帳號永不觸發）。LDAP 影子用戶同受治理（8.2.6 涵蓋全帳號）
	var candidates []model.User
	if err := s.db.
		Where("active = ? AND inactivity_exempt = ? AND COALESCE(last_login_at, created_at) < ?",
			true, false, cutoff).
		Find(&candidates).Error; err != nil {
		return 0, err
	}

	disabled := 0
	for i := range candidates {
		u := &candidates[i]
		// 復用 UpdateStatus：撤 refresh＋收線＋last-admin 守衛。唯一 active admin
		// 因久未登入被掃到時 UpdateStatus 回 ErrLastAdmin，跳過並記警告（不鎖死系統）
		if err := s.users.UpdateStatus(u.ID, false); err != nil {
			if errors.Is(err, ErrLastAdmin) {
				log.Printf("[Inactivity] 跳過停用最後管理員 (userID=%d, username=%s)：避免鎖死系統，建議設豁免或新增 admin",
					u.ID, u.Username)
				continue
			}
			log.Printf("[Inactivity] 停用閒置帳號失敗 (userID=%d): %v", u.ID, err)
			continue
		}
		s.auditDisable(u, days)
		disabled++
		log.Printf("[Inactivity] 已停用閒置帳號 (userID=%d, username=%s, 逾 %d 天未登入)", u.ID, u.Username, days)
	}
	return disabled, nil
}

// auditDisable 記錄自動停用事件（系統動作，userID 記目標用戶供追溯）
func (s *InactivityService) auditDisable(u *model.User, days int) {
	if s.auditService == nil {
		return
	}
	uid := u.ID
	s.auditService.Log(&audit.AuditLogEntry{
		UserID:     u.ID,
		Username:   u.Username,
		Action:     model.ActionUpdate,
		Resource:   model.ResourceUser,
		ResourceID: &uid,
		Status:     model.StatusSuccess,
		ClientIP:   "system",
		StatusCode: 200,
		ErrorMsg:   "auto_disabled_inactive_account",
	})
}
