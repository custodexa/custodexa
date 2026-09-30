package identity

import (
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	for i := range groups {
		var members []model.UserGroupMember
		if err := s.db.Where("user_group_id=?", groups[i].ID).Order("user_id").Find(&members).Error; err != nil {
			return nil, err
		}
		for _, m := range members {
			groups[i].UserIDs = append(groups[i].UserIDs, m.UserID)
			source := struct {
				UserID uint `json:"user_id"`
				Manual bool `json:"manual"`
				Mapped bool `json:"mapped"`
			}{UserID: m.UserID, Manual: m.Manual}
			if m.Manual {
				groups[i].ManualUserIDs = append(groups[i].ManualUserIDs, m.UserID)
			}
			var n int64
			if err := s.db.Table("user_group_mapping_rule_supports").Where("user_group_id=? AND user_id=?", groups[i].ID, m.UserID).Count(&n).Error; err != nil {
				return nil, err
			}
			if n > 0 {
				groups[i].MappedUserIDs = append(groups[i].MappedUserIDs, m.UserID)
				source.Mapped = true
			}
			groups[i].MemberSources = append(groups[i].MemberSources, source)
		}
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
		var memberIDs []uint
		if err := tx.Table("user_group_members").Where("user_group_id=?", id).Order("user_id").Pluck("user_id", &memberIDs).Error; err != nil {
			return err
		}
		for _, memberID := range memberIDs {
			if err := withUserCredentialLockTx(tx, memberID, func(locked *gorm.DB) error {
				if err := BumpCredentialEpoch(locked, memberID, "user_group_deleted"); err != nil {
					return err
				}
				_, err := RevokeAllRefreshTokens(locked, memberID, model.RefreshRevokeCredentialEpoch)
				return err
			}); err != nil {
				return err
			}
		}
		if err := tx.Exec("DELETE FROM user_group_mapping_rule_supports WHERE user_group_id=?", id).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("user_group_id=?", id).Delete(&model.GroupUserGroupMapping{}).Error; err != nil {
			return err
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
			return fmt.Errorf("稽核留痕失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	log.Printf("[UserGroup] 群組 %d 已刪除，連動撤銷 %d 筆授權（actor=%s）", id, revoked, actorName)
	return revoked, nil
}

// ReplaceMembers preserves the legacy effective-user-list semantics. Existing
// mapped-only users in that list never become manual members on round-trip.
func (s *UserGroupService) ReplaceMembers(id uint, userIDs []uint) (*model.UserGroup, error) {
	return s.ReplaceMembersDetailed(id, nil, &userIDs, 0, "system", "system")
}

// ReplaceMembersDetailed changes only the manual component. Exactly one of
// manualIDs or legacyIDs must be supplied; an explicitly empty slice clears it.
func (s *UserGroupService) ReplaceMembersDetailed(id uint, manualIDs, legacyIDs *[]uint, actorID uint, actorName, clientIP string) (*model.UserGroup, error) {
	if (manualIDs == nil) == (legacyIDs == nil) {
		return nil, fmt.Errorf("請指定 manual_user_ids 或 user_ids 其中之一")
	}
	var group model.UserGroup
	err := s.db.Transaction(func(tx *gorm.DB) error {
		groupQuery := tx
		if tx.Dialector.Name() == "postgres" {
			groupQuery = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := groupQuery.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserGroupNotFound
			}
			return err
		}
		requested := manualIDs
		if requested == nil {
			requested = legacyIDs
		}
		ids := kernel.DedupeUint(*requested)
		var users []model.User
		if len(ids) > 0 {
			if err := tx.Where("id IN ?", ids).Find(&users).Error; err != nil {
				return err
			}
		}
		if len(users) != len(ids) {
			return ErrUserGroupMemberNotFound
		}
		var members []model.UserGroupMember
		if err := tx.Where("user_group_id=?", id).Order("user_id").Find(&members).Error; err != nil {
			return err
		}
		mappedOnly := map[uint]bool{}
		if legacyIDs != nil {
			for _, m := range members {
				if !m.Manual {
					mappedOnly[m.UserID] = true
				}
			}
		}
		want := map[uint]bool{}
		for _, uid := range ids {
			if !mappedOnly[uid] {
				want[uid] = true
			}
		}
		affected := map[uint]bool{}
		for _, m := range members {
			affected[m.UserID] = true
		}
		for uid := range want {
			affected[uid] = true
		}
		ordered := make([]uint, 0, len(affected))
		for uid := range affected {
			ordered = append(ordered, uid)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
		for _, uid := range ordered {
			if err := withUserCredentialLockTx(tx, uid, func(locked *gorm.DB) error {
				var rows []model.UserGroupMember
				if err := locked.Where("user_group_id=? AND user_id=?", id, uid).Find(&rows).Error; err != nil {
					return err
				}
				var supportCount int64
				if err := locked.Table("user_group_mapping_rule_supports").Where("user_group_id=? AND user_id=?", id, uid).Count(&supportCount).Error; err != nil {
					return err
				}
				if want[uid] {
					if len(rows) == 0 {
						return locked.Exec("INSERT INTO user_group_members(user_group_id,user_id,manual) VALUES (?,?,true)", id, uid).Error
					}
					if !rows[0].Manual {
						return locked.Exec("UPDATE user_group_members SET manual=true WHERE user_group_id=? AND user_id=?", id, uid).Error
					}
					return nil
				}
				if len(rows) == 0 || !rows[0].Manual {
					return nil
				}
				if supportCount > 0 {
					return locked.Exec("UPDATE user_group_members SET manual=false WHERE user_group_id=? AND user_id=?", id, uid).Error
				}
				if err := locked.Exec("DELETE FROM user_group_members WHERE user_group_id=? AND user_id=?", id, uid).Error; err != nil {
					return err
				}
				if err := BumpCredentialEpoch(locked, uid, "user_group_member_removed"); err != nil {
					return err
				}
				if _, err := RevokeAllRefreshTokens(locked, uid, model.RefreshRevokeCredentialEpoch); err != nil {
					return err
				}
				payload := fmt.Sprintf(`{"event":"user_group_manual_member_removed","user_group_id":%d,"user_id":%d}`, id, uid)
				if err := port.WriteInTx(s.auditTx, locked, port.AuditEvent{Action: string(model.ActionUpdate), Resource: string(model.ResourceUserGroup), ResourceID: &id, Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: actorID, Username: actorName}, Request: gatewayapi.RequestMeta{ClientIP: clientIP}, Details: payload}); err != nil {
					return err
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return tx.Preload("Users").First(&group, id).Error
	})
	if err != nil {
		return nil, fmt.Errorf("更新成員失敗: %w", err)
	}
	return &group, nil
}
