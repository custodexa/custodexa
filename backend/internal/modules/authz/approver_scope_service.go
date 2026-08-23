package authz

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	// ErrScopeNotFound 審核範圍不存在
	ErrScopeNotFound = errors.New("審核範圍不存在")
	// ErrScopeExists 同 approver×客體的活躍範圍已存在
	ErrScopeExists = errors.New("審核範圍已存在")
	// ErrScopeTargetInvalid 客體不滿足恰一非空（四維：資產/節點/使用者/使用者群組）
	ErrScopeTargetInvalid = errors.New("審核範圍客體必須恰一（asset_id/asset_group_id/subject_user_id/subject_group_id 四擇一）")
	// ErrScopeActorInvalid 審核方不滿足恰一非空（個人 XOR 群組）
	ErrScopeActorInvalid = errors.New("審核方必須恰一（approver_id/approver_group_id 二擇一）")
	// ErrNotApproverRole 目標使用者不具 approver 角色
	ErrNotApproverRole = errors.New("目標使用者不具 approver 角色")
)

// ApproverScopeService 審核範圍管理（後擴為四維）：
// admin only 分配，approver×（資產 XOR 節點
// XOR 使用者 XOR 使用者群組）。資產側與授權客體同構；申請人側為 OR 資格擴充。
// CRUD 審計由路由中介層記錄（POST/DELETE /approver-scopes → approver_scope）
type ApproverScopeService struct {
	db *gorm.DB
}

// NewApproverScopeService 建立審核範圍服務
func NewApproverScopeService(db *gorm.DB) *ApproverScopeService {
	return &ApproverScopeService{db: db}
}

// ApproverScopeSpec 範圍分配規格（審核方恰一 × 客體恰一）
type ApproverScopeSpec struct {
	ApproverID      *uint
	ApproverGroupID *uint
	AssetID         *uint
	AssetGroupID    *uint
	SubjectUserID   *uint
	SubjectGroupID  *uint
	GrantedBy       uint
}

// List 全部審核範圍（管理視圖）
func (s *ApproverScopeService) List() ([]*model.ApproverScope, error) {
	var scopes []*model.ApproverScope
	err := s.db.Preload("Approver").Preload("ApproverGroup").
		Preload("Asset").Preload("AssetGroup").
		Preload("SubjectUser").Preload("SubjectGroup").
		Order("created_at DESC").Find(&scopes).Error
	if err != nil {
		return nil, fmt.Errorf("查詢審核範圍失敗: %w", err)
	}
	return scopes, nil
}

// Create 分配審核範圍：審核方恰一（個人須具 approver 角色；群組即資格零代配）、
// 客體四維恰一、引用存在、活躍組合去重
func (s *ApproverScopeService) Create(spec ApproverScopeSpec) (*model.ApproverScope, error) {
	actors := 0
	for _, p := range []*uint{spec.ApproverID, spec.ApproverGroupID} {
		if p != nil {
			actors++
		}
	}
	if actors != 1 {
		return nil, ErrScopeActorInvalid
	}
	targets := 0
	for _, p := range []*uint{spec.AssetID, spec.AssetGroupID, spec.SubjectUserID, spec.SubjectGroupID} {
		if p != nil {
			targets++
		}
	}
	if targets != 1 {
		return nil, ErrScopeTargetInvalid
	}

	if spec.ApproverID != nil {
		// 個人審核方須具 approver 角色（範圍掛在審核職能上，掛非 approver 是配置錯誤）
		var roleCount int64
		err := s.db.Table("user_roles").
			Joins("JOIN roles ON user_roles.role_id = roles.id").
			Where("user_roles.user_id = ? AND roles.name = ? AND roles.deleted_at IS NULL",
				*spec.ApproverID, model.RoleApprover).
			Count(&roleCount).Error
		if err != nil {
			return nil, fmt.Errorf("查詢使用者角色失敗: %w", err)
		}
		if roleCount == 0 {
			return nil, ErrNotApproverRole
		}
	}
	if spec.ApproverGroupID != nil {
		// 群組審核方：群組即資格（成員無需 approver 角色），僅驗存在
		if err := s.db.First(&model.UserGroup{}, *spec.ApproverGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者群組不存在: ID=%d", *spec.ApproverGroupID)
			}
			return nil, fmt.Errorf("查詢使用者群組失敗: %w", err)
		}
	}

	if spec.AssetID != nil {
		if err := s.db.First(&model.Asset{}, *spec.AssetID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("資產不存在: ID=%d", *spec.AssetID)
			}
			return nil, fmt.Errorf("查詢資產失敗: %w", err)
		}
	}
	if spec.AssetGroupID != nil {
		if err := s.db.First(&model.AssetGroup{}, *spec.AssetGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("資產分組不存在: ID=%d", *spec.AssetGroupID)
			}
			return nil, fmt.Errorf("查詢資產分組失敗: %w", err)
		}
	}
	if spec.SubjectUserID != nil {
		if err := s.db.First(&model.User{}, *spec.SubjectUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者不存在: ID=%d", *spec.SubjectUserID)
			}
			return nil, fmt.Errorf("查詢使用者失敗: %w", err)
		}
	}
	if spec.SubjectGroupID != nil {
		if err := s.db.First(&model.UserGroup{}, *spec.SubjectGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者群組不存在: ID=%d", *spec.SubjectGroupID)
			}
			return nil, fmt.Errorf("查詢使用者群組失敗: %w", err)
		}
	}

	// 活躍同組合去重（partial 唯一索引同語義，先查後寫給可讀錯誤；索引兜底）
	var count int64
	q := s.db.Model(&model.ApproverScope{})
	if spec.ApproverID != nil {
		q = q.Where("approver_id = ?", *spec.ApproverID)
	} else {
		q = q.Where("approver_group_id = ?", *spec.ApproverGroupID)
	}
	switch {
	case spec.AssetID != nil:
		q = q.Where("asset_id = ?", *spec.AssetID)
	case spec.AssetGroupID != nil:
		q = q.Where("asset_group_id = ?", *spec.AssetGroupID)
	case spec.SubjectUserID != nil:
		q = q.Where("subject_user_id = ?", *spec.SubjectUserID)
	default:
		q = q.Where("subject_group_id = ?", *spec.SubjectGroupID)
	}
	if err := q.Count(&count).Error; err != nil {
		return nil, fmt.Errorf("查詢既有範圍失敗: %w", err)
	}
	if count > 0 {
		return nil, ErrScopeExists
	}

	scope := &model.ApproverScope{
		ApproverID:      spec.ApproverID,
		ApproverGroupID: spec.ApproverGroupID,
		AssetID:         spec.AssetID,
		AssetGroupID:    spec.AssetGroupID,
		SubjectUserID:   spec.SubjectUserID,
		SubjectGroupID:  spec.SubjectGroupID,
		GrantedBy:       spec.GrantedBy,
	}
	if err := s.db.Create(scope).Error; err != nil {
		return nil, fmt.Errorf("建立審核範圍失敗: %w", err)
	}

	var result model.ApproverScope
	if err := s.db.Preload("Approver").Preload("ApproverGroup").
		Preload("Asset").Preload("AssetGroup").
		Preload("SubjectUser").Preload("SubjectGroup").
		First(&result, scope.ID).Error; err != nil {
		return scope, nil
	}
	return &result, nil
}

// Delete 移除審核範圍（軟刪；可視第三來源即刻失效）
func (s *ApproverScopeService) Delete(id uint) error {
	res := s.db.Delete(&model.ApproverScope{}, id)
	if res.Error != nil {
		return fmt.Errorf("刪除審核範圍失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrScopeNotFound
	}
	return nil
}
