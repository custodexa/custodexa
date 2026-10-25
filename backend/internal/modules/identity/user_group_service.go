package identity

import (
	"errors"
	"fmt"
	"log"
	"math"
	"sort"

	"github.com/custodexa/backend/internal/kernel"
	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
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
	// guard 共用指派關卡；nil 時用相容目錄的預設關卡
	guard *AssignmentGuard
	// grader 授權變更的分級與留痕；nil 時不分級（僅測試與內部入口，生產組裝自檢拒絕 nil）
	grader *GrantGrader
}

// SetGrantGrader 注入授權變更的分級與留痕。
func (s *UserGroupService) SetGrantGrader(g *GrantGrader) { s.grader = g }

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
	// 建群組改變權限快照的 groups 集合，但此路徑不推進權限版本（空群組不改變任何人的授權）。
	// 外層交易開頭 Begin、結尾 Settle，使事件鏈涵蓋這筆合法寫入。
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		if err := tx.Create(group).Error; err != nil {
			return err
		}
		return authz.SettlePermissionChange(tx)
	})
	if err != nil {
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
	return s.deleteGroup(id, actorID, actorName, clientIP, nil)
}

// DeleteBy 帶操作者的刪除：群組帶保護角色指派限超管，帶其他角色指派須持指派能力。
func (s *UserGroupService) DeleteBy(op Operator, id uint) (int64, error) {
	return s.deleteGroup(id, op.UserID, op.Username, op.ClientIP, &op)
}

func (s *UserGroupService) deleteGroup(id uint, actorID uint, actorName, clientIP string, op *Operator) (int64, error) {
	var revoked int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var group model.UserGroup
		// 鎖序守衛探針（測試期；生產恆為 nil）：取群組列鎖之前
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerGroup, id)
		}
		groupQuery := tx
		if tx.Dialector.Name() == "postgres" {
			groupQuery = tx.Clauses(clause.Locking{Strength: "NO KEY UPDATE"})
		}
		if err := groupQuery.First(&group, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserGroupNotFound
			}
			return err
		}
		var tr *grantTracker
		if op != nil {
			if err := s.assignmentGuard().Check(tx, *op, AssignmentChange{Path: PathGroupDelete, GroupID: id}); err != nil {
				return err
			}
			var gerr error
			if tr, gerr = s.grader.begin(tx, *op, PathGroupDelete, 0, id); gerr != nil {
				return gerr
			}
		}
		// 群組帶的角色指派隨群組移除（同交易）；成員的憑證世代由下方整群推進涵蓋
		curRoles, err := authz.UserGroupRoleIDs(tx, id)
		if err != nil {
			return err
		}
		// 成員預取：在推進權限版本、寫任何權限列之前，依使用者編號升冪取得全部現有成員的
		// 憑證鎖與列鎖；之後逐人迴圈對預取者是重入。預取放在 Begin 之前，附證啟用且有漂移時
		// Begin 會寫事件並持有其保留，使用者鎖不得排在它後面。
		prefetchIDs, prefetched, err := groupPrefetchSet(tx, id, nil)
		if err != nil {
			return err
		}
		if err := lockUsersCredentialUpfrontTx(tx, prefetchIDs); err != nil {
			return err
		}
		if h := loadGroupDeleteLockHooks().afterPrefetch; h != nil {
			h()
		}
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		if len(curRoles) > 0 {
			if err := authz.ReplaceUserGroupRoleRows(tx, id, nil, curRoles); err != nil {
				return err
			}
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
		if h := loadGroupDeleteLockHooks().afterCascadeRevoke; h != nil {
			h()
		}
		var memberIDs []uint
		if err := tx.Table("user_group_members").Where("user_group_id=?", id).Order("user_id").Pluck("user_id", &memberIDs).Error; err != nil {
			return err
		}
		for _, memberID := range memberIDs {
			if !prefetched[memberID] {
				// 預取之後才加入的成員（映射在群組鎖之外仍可加入）：照常補鎖、不跳過其失權處理，
				// 只留一行警告；補鎖可能與另一筆交易互等，結果是恰一方回滾可重試。
				log.Printf("[UserGroup] 警告：群組 %d 刪除時發現預取集合之外的成員 %d，於迴圈內補取使用者鎖", id, memberID)
				// 鎖序守衛的已知例外登記（測試期；生產恆為 nil）：只放行這一位的補取
				if exempt := authz.LockOrderExemptLateJoinerHook(); exempt != nil {
					exempt(tx, authz.LateJoinerGroupDelete, id, memberID)
				}
			}
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
		// 權限版本：群組刪除連同成員、映射規則的清除，與刪除同交易
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		if err := tr.finishGroup(tx, id, group.Name, 0); err != nil {
			return err
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
	authz.NotifyVersionCommittedAfter(s.db, err)
	if err != nil {
		return 0, err
	}
	log.Printf("[UserGroup] 群組 %d 已刪除，連動撤銷 %d 筆授權（actor=%s）", id, revoked, actorName)
	return revoked, nil
}

// groupPrefetchSet 讀出群組現有成員，與 extra 合併去重，回傳要預取的編號與其集合。
// 呼叫端在持有群組列鎖之後、推進權限版本與寫任何權限列之前，以回傳的編號呼叫
// lockUsersCredentialUpfrontTx 取得憑證鎖與列鎖。
// 超出憑證鎖值域的編號不可能對應存在的帳號，不納入預取（呼叫端的存在性檢查會拒絕它們）。
func groupPrefetchSet(tx *gorm.DB, groupID uint, extra []uint) ([]uint, map[uint]bool, error) {
	var memberIDs []uint
	if err := tx.Table("user_group_members").Where("user_group_id=?", groupID).Order("user_id").Pluck("user_id", &memberIDs).Error; err != nil {
		return nil, nil, err
	}
	set := make(map[uint]bool, len(memberIDs)+len(extra))
	all := make([]uint, 0, len(memberIDs)+len(extra))
	for _, uid := range append(memberIDs, extra...) {
		if uid > math.MaxUint32 || set[uid] {
			continue
		}
		set[uid] = true
		all = append(all, uid)
	}
	return all, set, nil
}

// ReplaceMembers preserves the legacy effective-user-list semantics. Existing
// mapped-only users in that list never become manual members on round-trip.
func (s *UserGroupService) ReplaceMembers(id uint, userIDs []uint) (*model.UserGroup, error) {
	return s.ReplaceMembersDetailed(id, nil, &userIDs, 0, "system", "system")
}

// ReplaceMembersDetailed changes only the manual component. Exactly one of
// manualIDs or legacyIDs must be supplied; an explicitly empty slice clears it.
func (s *UserGroupService) ReplaceMembersDetailed(id uint, manualIDs, legacyIDs *[]uint, actorID uint, actorName, clientIP string) (*model.UserGroup, error) {
	return s.replaceMembers(id, manualIDs, legacyIDs, actorID, actorName, clientIP, nil)
}

// ReplaceMembersBy 帶操作者的成員異動：經共用指派關卡；加入同交易寫服務審計。
func (s *UserGroupService) ReplaceMembersBy(op Operator, id uint, manualIDs, legacyIDs *[]uint) (*model.UserGroup, error) {
	return s.replaceMembers(id, manualIDs, legacyIDs, op.UserID, op.Username, op.ClientIP, &op)
}

func (s *UserGroupService) replaceMembers(id uint, manualIDs, legacyIDs *[]uint, actorID uint, actorName, clientIP string, op *Operator) (*model.UserGroup, error) {
	if (manualIDs == nil) == (legacyIDs == nil) {
		return nil, fmt.Errorf("請指定 manual_user_ids 或 user_ids 其中之一")
	}
	var group model.UserGroup
	var addedMembers []uint
	err := s.db.Transaction(func(tx *gorm.DB) error {
		// 鎖序守衛探針（測試期；生產恆為 nil）：取群組列鎖之前
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerGroup, id)
		}
		groupQuery := tx
		if tx.Dialector.Name() == "postgres" {
			groupQuery = tx.Clauses(clause.Locking{Strength: "NO KEY UPDATE"})
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
		// 成員預取：現有成員與請求的使用者合併，在 Begin 之前依編號升冪取得憑證鎖與列鎖；
		// 請求中不存在的編號之後仍在 Begin 之後回 ErrUserGroupMemberNotFound。
		prefetchIDs, prefetched, err := groupPrefetchSet(tx, id, ids)
		if err != nil {
			return err
		}
		if err := lockUsersCredentialUpfrontTx(tx, prefetchIDs); err != nil {
			return err
		}
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		var users []model.User
		if len(ids) > 0 {
			if err := tx.Where("id IN ?", ids).Find(&users).Error; err != nil {
				return err
			}
		}
		if len(users) != len(ids) {
			return ErrUserGroupMemberNotFound
		}
		plan, err := manualMembersAfter(tx, id, ids, legacyIDs != nil)
		if err != nil {
			return err
		}
		members, want := plan.Members, plan.Want
		addedMembers = plan.Added
		var tr *grantTracker
		var addedOthers int
		if op != nil && (plan.ManualRemoved || len(plan.Added) > 0) {
			if err := s.assignmentGuard().Check(tx, *op, AssignmentChange{
				Path: PathGroupMember, GroupID: id, AddedMemberIDs: plan.Added}); err != nil {
				return err
			}
			var gerr error
			if tr, gerr = s.grader.begin(tx, *op, PathGroupMember, 0, id); gerr != nil {
				return gerr
			}
			for _, uid := range plan.Added {
				if uid != op.UserID {
					addedOthers++
				}
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
		// 權限版本：任一成員列被新增、改標記或移除即於迴圈後推進一次（與寫入同交易）
		if h := loadLockOrderHook(); h != nil {
			h("group_members_before_loop", tx)
		}
		membersChanged := false
		for _, uid := range ordered {
			if !prefetched[uid] {
				// 只可能是群組鎖期間由映射加入的非手動列，且不在請求內；現行處理本就不寫入這類列
				continue
			}
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
						membersChanged = true
						if err := locked.Exec("INSERT INTO user_group_members(user_group_id,user_id,manual) VALUES (?,?,true)", id, uid).Error; err != nil {
							return err
						}
						return s.writeMemberAddedAudit(locked, id, uid, actorID, actorName, clientIP)
					}
					if !rows[0].Manual {
						membersChanged = true
						if err := locked.Exec("UPDATE user_group_members SET manual=true WHERE user_group_id=? AND user_id=?", id, uid).Error; err != nil {
							return err
						}
						return s.writeMemberAddedAudit(locked, id, uid, actorID, actorName, clientIP)
					}
					return nil
				}
				if len(rows) == 0 || !rows[0].Manual {
					return nil
				}
				membersChanged = true
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
		if membersChanged {
			if err := authz.AdvanceVersion(tx); err != nil {
				return err
			}
		}
		if err := tr.finishGroup(tx, id, group.Name, addedOthers); err != nil {
			return err
		}
		return tx.Preload("Users").First(&group, id).Error
	})
	authz.NotifyVersionCommittedAfter(s.db, err)
	if err != nil {
		return nil, fmt.Errorf("更新成員失敗: %w", err)
	}
	if len(addedMembers) > 0 {
		// 加入的成員若是 agent，以群組目前帶的角色重查（提交後偵測，不擋寫入）
		if roleIDs, rerr := authz.UserGroupRoleIDs(s.db, id); rerr == nil {
			s.grader.afterAgentRoleWrite(s.db, op, string(model.ResourceUserGroup), id, addedMembers, roleIDs)
		}
	}
	return &group, nil
}

// manualMemberPlan 手動成員輸入的求值結果（寫入與預覽共用）。
type manualMemberPlan struct {
	// Members 群組目前的成員列（依使用者編號）。
	Members []model.UserGroupMember
	// Want 變更後的手動集。舊語義（legacy）下，目前只是映射成員者不會因往返而變成手動。
	Want map[uint]bool
	// Added 加入名單：手動集中目前不是成員、或目前只是映射成員者（升冪）。
	// 沿寫入的定義，不以變更前後有效成員的集合差代替：把已經由映射加入的人改列為手動，
	// 有效成員不變，仍算加入。
	Added []uint
	// ManualRemoved 有手動成員被移出手動集。
	ManualRemoved bool
	// Effective 變更後的有效成員（升冪）：手動集，加上目前非手動者與仍受映射規則支持的被移出者。
	Effective []uint
}

// manualMembersAfter 由群組現值與請求的手動成員集合求變更後成員與加入名單；唯讀。
// ids 須已去重。legacy 為舊的「整組有效成員」輸入語義。
func manualMembersAfter(tx *gorm.DB, groupID uint, ids []uint, legacy bool) (manualMemberPlan, error) {
	plan := manualMemberPlan{Want: map[uint]bool{}}
	if err := tx.Where("user_group_id=?", groupID).Order("user_id").Find(&plan.Members).Error; err != nil {
		return plan, err
	}
	cur := map[uint]model.UserGroupMember{}
	for _, m := range plan.Members {
		cur[m.UserID] = m
	}
	for _, uid := range ids {
		if legacy {
			if m, ok := cur[uid]; ok && !m.Manual {
				continue
			}
		}
		plan.Want[uid] = true
	}
	for uid := range plan.Want {
		if m, ok := cur[uid]; !ok || !m.Manual {
			plan.Added = append(plan.Added, uid)
		}
	}
	sort.Slice(plan.Added, func(i, j int) bool { return plan.Added[i] < plan.Added[j] })
	var supported []uint
	if err := tx.Table("user_group_mapping_rule_supports").Where("user_group_id=?", groupID).Distinct().Pluck("user_id", &supported).Error; err != nil {
		return plan, err
	}
	supportedSet := map[uint]bool{}
	for _, uid := range supported {
		supportedSet[uid] = true
	}
	eff := map[uint]bool{}
	for uid := range plan.Want {
		eff[uid] = true
	}
	for _, m := range plan.Members {
		if plan.Want[m.UserID] {
			continue
		}
		if m.Manual {
			plan.ManualRemoved = true
		}
		if !m.Manual || supportedSet[m.UserID] {
			eff[m.UserID] = true
		}
	}
	plan.Effective = make([]uint, 0, len(eff))
	for uid := range eff {
		plan.Effective = append(plan.Effective, uid)
	}
	sort.Slice(plan.Effective, func(i, j int) bool { return plan.Effective[i] < plan.Effective[j] })
	return plan, nil
}

// PlanManualMembers 群組成員預覽的轉接：手動成員輸入走與 replaceMembers 同一份求值。
func PlanManualMembers(tx *gorm.DB, groupID uint, manualIDs []uint) (authz.GroupMemberPlan, error) {
	plan, err := manualMembersAfter(tx, groupID, kernel.DedupeUint(manualIDs), false)
	if err != nil {
		return authz.GroupMemberPlan{}, err
	}
	return authz.GroupMemberPlan{Effective: plan.Effective, Added: plan.Added}, nil
}

// writeMemberAddedAudit 手動成員加入的同交易服務審計（形狀比照既有移除）。
func (s *UserGroupService) writeMemberAddedAudit(tx *gorm.DB, groupID, userID, actorID uint, actorName, clientIP string) error {
	gid := groupID
	payload := fmt.Sprintf(`{"event":"user_group_manual_member_added","user_group_id":%d,"user_id":%d}`, groupID, userID)
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{Action: string(model.ActionUpdate), Resource: string(model.ResourceUserGroup), ResourceID: &gid, Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: actorID, Username: actorName}, Request: gatewayapi.RequestMeta{ClientIP: clientIP}, Details: payload}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	return nil
}
