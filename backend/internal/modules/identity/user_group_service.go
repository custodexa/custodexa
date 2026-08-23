package identity

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"log"

	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

var (
	// ErrUserGroupNameExists 群組名稱重複
	ErrUserGroupNameExists = errors.New("使用者群組名稱已存在")
	// ErrUserGroupNotFound 群組不存在
	ErrUserGroupNotFound = errors.New("使用者群組不存在")
	// ErrUserGroupMemberNotFound 成員名單含不存在的使用者
	ErrUserGroupMemberNotFound = errors.New("成員名單含不存在的使用者")
)

// UserGroupService 使用者群組服務：
// 授權主體的分組維度，與 RBAC Role 正交
type UserGroupService struct {
	db *gorm.DB
	// auditTx 交易內審計落地面：刪群組的留痕與級聯撤銷同交易，
	// 留痕失敗即回滾（授權變更不可無痕）。未注入時寫入回 error
	auditTx port.TxSink
	// authzRevoker 刪群組時的 authz 級聯撤銷（tx-taking 窄 port）
	authzRevoker authorizationCascadeRevoker
}

// NewUserGroupService 建立使用者群組服務
func NewUserGroupService(db *gorm.DB, auditTx port.TxSink, authzRevoker authorizationCascadeRevoker) *UserGroupService {
	return &UserGroupService{db: db, auditTx: auditTx, authzRevoker: authzRevoker}
}

// UserGroupRequest 建立/更新請求
type UserGroupRequest struct {
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"max=500"`
}

// List 全部群組（含成員）
func (s *UserGroupService) List() ([]model.UserGroup, error) {
	var groups []model.UserGroup
	if err := s.db.Preload("Users").Order("id").Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

// Create 建立群組
func (s *UserGroupService) Create(req *UserGroupRequest) (*model.UserGroup, error) {
	group := &model.UserGroup{Name: req.Name, Description: req.Description}
	if err := s.db.Create(group).Error; err != nil {
		if dberr.IsUniqueViolation(err) {
			return nil, ErrUserGroupNameExists
		}
		return nil, err
	}
	return group, nil
}

// Update 更新群組
func (s *UserGroupService) Update(id uint, req *UserGroupRequest) (*model.UserGroup, error) {
	var group model.UserGroup
	if err := s.db.First(&group, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserGroupNotFound
		}
		return nil, err
	}
	group.Name = req.Name
	group.Description = req.Description
	if err := s.db.Save(&group).Error; err != nil {
		if dberr.IsUniqueViolation(err) {
			return nil, ErrUserGroupNameExists
		}
		return nil, err
	}
	return &group, nil
}

// AuthorizationCount 掛在群組上的有效授權筆數（刪除確認 UI 用）
func (s *UserGroupService) AuthorizationCount(id uint) (int64, error) {
	var count int64
	if err := s.db.Model(&model.AssetAuthorization{}).
		Where("user_group_id = ?", id).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("查詢群組授權數失敗: %w", err)
	}
	return count, nil
}

// Delete 刪除群組：同交易內移除全部成員關係＋軟刪掛該群組的授權記錄
// （成員立即失權，spec「刪群組即失權」），回傳連動撤銷的授權筆數。
// actorID/actorName/clientIP 供審計留痕（誰刪的、撤了幾筆）
func (s *UserGroupService) Delete(id uint, actorID uint, actorName, clientIP string) (int64, error) {
	var revoked int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var group model.UserGroup
		if err := tx.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserGroupNotFound
			}
			return err
		}

		// 連動軟刪授權與審核範圍：兩張表皆屬 authz，
		// 故經 tx-taking 窄 port 交由擁有者寫入。未注入即 fail-close——
		// 靜默略過會留下惰性授權與可回復審核資格的幽靈範圍
		if s.authzRevoker == nil {
			return fmt.Errorf("authz 級聯撤銷面未注入：刪群組不得在不撤銷授權的情況下完成")
		}
		var rerr error
		revoked, rerr = s.authzRevoker.RevokeByUserGroup(tx, id)
		if rerr != nil {
			return rerr
		}

		// 移除成員關係（join 表無軟刪除，直接清）
		if err := tx.Exec("DELETE FROM user_group_members WHERE user_group_id = ?", id).Error; err != nil {
			return fmt.Errorf("清除群組成員失敗: %w", err)
		}

		if err := tx.Delete(&group).Error; err != nil {
			return fmt.Errorf("刪除群組失敗: %w", err)
		}

		// 審計留痕與刪除同交易：留痕失敗即回滾（授權變更不可無痕）。
		// 審計收口（AP-60）：改經 audit 模組的 TxSink，錯誤包裝詞與回滾語義不變
		groupID := id
		if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action:     string(model.ActionDelete),
			Resource:   string(model.ResourceUserGroup),
			ResourceID: &groupID,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: actorID, Username: actorName},
			Request:    gatewayapi.RequestMeta{ClientIP: clientIP},
			Details:    fmt.Sprintf(`{"group_name":%q,"revoked_authorizations":%d}`, group.Name, revoked),
		}); err != nil {
			return fmt.Errorf("審計留痕失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	log.Printf("[UserGroup] 群組 %d 已刪除，連動撤銷 %d 筆授權（actor=%s）", id, revoked, actorName)
	return revoked, nil
}

// ReplaceMembers 全量替換群組成員（穿梭框語義）；名單含不存在使用者即拒
func (s *UserGroupService) ReplaceMembers(id uint, userIDs []uint) (*model.UserGroup, error) {
	var group model.UserGroup
	if err := s.db.First(&group, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserGroupNotFound
		}
		return nil, err
	}

	var users []model.User
	if len(userIDs) > 0 {
		if err := s.db.Find(&users, userIDs).Error; err != nil {
			return nil, fmt.Errorf("查詢成員失敗: %w", err)
		}
		if len(users) != len(kernel.DedupeUint(userIDs)) {
			return nil, ErrUserGroupMemberNotFound
		}
	}

	if err := s.db.Model(&group).Association("Users").Replace(users); err != nil {
		return nil, fmt.Errorf("更新成員失敗: %w", err)
	}
	group.Users = users
	return &group, nil
}
