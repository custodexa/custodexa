package authz

import (
	"context"
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
// 持審核範圍管理權限點者分配（申請人型另需申請人型管理），approver×（資產 XOR 節點
// XOR 使用者 XOR 使用者群組）。資產側與授權客體同構；申請人側為 OR 資格擴充。
// CRUD 審計由路由中介層記錄（POST/DELETE /approver-scopes → approver_scope）
type ApproverScopeService struct {
	db *gorm.DB
	// writeScope 審核範圍的交易內範圍判定。組裝期必注入（RequireWriteScope 檢查）；
	// 未注入走不判定的內部路徑（程式內部建構與測試用）。
	writeScope   *ApproverScopeWriteScope
	e            *ScopeEvaluator
	minApprovals interface{ GetInt(key string) int }
}

// SetWriteScope 注入審核範圍的範圍判定與判定器（組裝時）；判定器供列表投影與選擇端點使用。
func (s *ApproverScopeService) SetWriteScope(w *ApproverScopeWriteScope, e *ScopeEvaluator) {
	s.writeScope, s.e = w, e
}

// SetPolicies 注入最少核准人數的讀取來源（列表回應帶現值）。
func (s *ApproverScopeService) SetPolicies(p interface{ GetInt(key string) int }) { s.minApprovals = p }

// RequireWriteScope 組裝自檢：範圍判定與判定器皆已注入。
func (s *ApproverScopeService) RequireWriteScope() error {
	if s == nil || s.writeScope == nil || s.e == nil {
		return ErrApproverScopeWriteScopeMissing
	}
	return nil
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
// 客體四維恰一、引用存在、活躍組合去重。
//
// 操作者只認 ctx 帶入的請求脈絡主體（與授權規則建立同一個 trustedOperator）：
// 脈絡無主體即拒，spec.GrantedBy 與主體不符也拒（超管不例外）。granted_by 會被
// 擁有者轉移守衛讀取，記成別人等於替日後的轉移開洞。
func (s *ApproverScopeService) Create(ctx context.Context, spec ApproverScopeSpec) (*model.ApproverScope, error) {
	if _, err := trustedOperator(ctx, spec.GrantedBy); err != nil {
		return nil, err
	}
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

	var created *model.ApproverScope
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 鎖序：拓撲序列化鎖第一個動作 → 同交易重解主體並判定 → 既有驗證 → 寫入
		if s.writeScope != nil {
			if err := LockScopeTopologyTx(tx); err != nil {
				return err
			}
			if err := s.writeScope.DecideCreate(ctx, tx, spec); err != nil {
				return err
			}
		}
		var err error
		created, err = s.createOn(tx, spec)
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// createOn 交易內的既有驗證與寫入（引用存在、審核方資格、不相交、去重）。
func (s *ApproverScopeService) createOn(tx *gorm.DB, spec ApproverScopeSpec) (*model.ApproverScope, error) {
	if spec.ApproverID != nil {
		var principal model.User
		if err := tx.First(&principal, *spec.ApproverID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrNotApproverRole
			}
			return nil, fmt.Errorf("查詢審核主體失敗: %w", err)
		}
		if principal.Kind == model.KindAgent {
			return nil, ErrNotApproverRole
		}
		// 個人審核方須具 approver 角色（範圍掛在審核職能上，掛非 approver 是配置錯誤）
		var roleCount int64
		err := tx.Table("user_roles").
			Joins("JOIN roles ON user_roles.role_id = roles.id").
			Where("user_roles.user_id = ? AND roles.builtin_key = ? AND user_roles.scope_kind = ? AND roles.deleted_at IS NULL",
				*spec.ApproverID, model.BuiltinApprover, model.ScopeKindGlobal).
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
		if err := tx.First(&model.UserGroup{}, *spec.ApproverGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者群組不存在: ID=%d", *spec.ApproverGroupID)
			}
			return nil, fmt.Errorf("查詢使用者群組失敗: %w", err)
		}
	}

	if spec.AssetID != nil {
		if err := tx.First(&model.Asset{}, *spec.AssetID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("資產不存在: ID=%d", *spec.AssetID)
			}
			return nil, fmt.Errorf("查詢資產失敗: %w", err)
		}
	}
	if spec.AssetGroupID != nil {
		if err := tx.First(&model.AssetGroup{}, *spec.AssetGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("資產分組不存在: ID=%d", *spec.AssetGroupID)
			}
			return nil, fmt.Errorf("查詢資產分組失敗: %w", err)
		}
	}
	if spec.SubjectUserID != nil {
		if err := tx.First(&model.User{}, *spec.SubjectUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者不存在: ID=%d", *spec.SubjectUserID)
			}
			return nil, fmt.Errorf("查詢使用者失敗: %w", err)
		}
	}
	if spec.SubjectGroupID != nil {
		if err := tx.First(&model.UserGroup{}, *spec.SubjectGroupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("使用者群組不存在: ID=%d", *spec.SubjectGroupID)
			}
			return nil, fmt.Errorf("查詢使用者群組失敗: %w", err)
		}
	}

	// 申請人型範圍：審核方集合與申請人集合不得相交（資產型／節點型沒有申請人集合，
	// 不判定）。只在建立當下判定，事後成員異動不追溯（self_grant_guard.go）
	if err := (SelfGrantGuard{}).CheckApproverScope(tx, spec); err != nil {
		return nil, err
	}

	// 活躍同組合去重（partial 唯一索引同語義，先查後寫給可讀錯誤；索引兜底）
	var count int64
	q := tx.Model(&model.ApproverScope{})
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
	if err := tx.Create(scope).Error; err != nil {
		return nil, fmt.Errorf("建立審核範圍失敗: %w", err)
	}

	var result model.ApproverScope
	if err := tx.Preload("Approver").Preload("ApproverGroup").
		Preload("Asset").Preload("AssetGroup").
		Preload("SubjectUser").Preload("SubjectGroup").
		First(&result, scope.ID).Error; err != nil {
		return scope, nil
	}
	return &result, nil
}

// Delete 移除審核範圍（軟刪；可視第三來源即刻失效）。
// 已注入範圍判定時：交易內取拓撲鎖 → 判定審核範圍管理鍵（範圍外、不存在同形）→ 讀列 →
// 申請人型列另判申請人型管理鍵（不放行與不存在同形）→ 刪除。
func (s *ApproverScopeService) Delete(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := s.writeScope != nil
		if scoped {
			if err := LockScopeTopologyTx(tx); err != nil {
				return err
			}
			if err := s.writeScope.DecideRow(ctx, tx, id); err != nil {
				return err
			}
		}
		var row model.ApproverScope
		if err := tx.Select("id", "asset_id", "asset_group_id").First(&row, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrScopeNotFound
			}
			return fmt.Errorf("查詢審核範圍失敗: %w", err)
		}
		if scoped && row.AssetID == nil && row.AssetGroupID == nil {
			if err := s.writeScope.DecideApplicantRow(ctx, tx, id); err != nil {
				return err
			}
		}
		res := tx.Delete(&model.ApproverScope{}, id)
		if res.Error != nil {
			return fmt.Errorf("刪除審核範圍失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrScopeNotFound
		}
		return nil
	})
}
