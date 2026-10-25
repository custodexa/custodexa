package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 使用者群組的角色指派（讀取與整組替換）。
//
// 同一交易：群組鎖、關卡、全體成員的使用者憑證鎖、寫指派、推進權限版本、有指派被移除時對
// 失去角色的成員推進憑證世代並撤銷 refresh（比照移出群組）、服務審計。任何一步失敗整筆回滾。
// 純增加不推進世代：成員下一個請求即由伺服器解析取得新角色。
//
// **成員的使用者憑證鎖在純新增時同樣要取**：帳號停用、刪除與啟用的「持保護角色者限超管」判定
// 是在目標的使用者憑證鎖內重讀角色再寫狀態；凡會改變某位使用者有效角色集的寫入都必須持該
// 使用者的鎖，否則群組替其新增保護角色可以在那道判定與寫入之間提交，使非超管啟用或停用一個
// 此刻已持保護角色的帳號。取鎖順序固定：群組列鎖 → 成員使用者鎖（依使用者編號升冪）→
// authz_state（推進版本），與刪群組、改成員集的既有順序一致（使用者鎖在前、版本推進在後）。
// 唯一的例外：預取之後才被外部身分對應加入群組的成員，在推進版本之後補取其使用者鎖並先記一行警告；
// 與另一筆持同一使用者鎖的交易互等時，資料庫中止其中一筆並整筆回滾，操作可重試。
//
// 只收全域；審核者內建身分不經群組取得（審核資格留在獨立的審核範圍模型）。

// groupRoleBindingsPreWriteHook 測試用同步點：於「成員使用者鎖已取得、尚未寫入」呼叫。
// 理由同 userCredentialPreWriteHook：與帳號生命週期的交錯只在特定順序下成立，靠時間競賽
// 觸發不穩定；生產路徑此值恆為 nil，改寫者僅限 _test.go。
var groupRoleBindingsPreWriteHook func()

// GroupRoleBindingsRequest 整組替換的請求。ScopeRequested 為請求帶任何範圍或節點欄位。
type GroupRoleBindingsRequest struct {
	RoleIDs        []uint
	ScopeRequested bool
	// RoleNodes 請求的 role_nodes（角色編號 → 範圍值）。鍵不存在即保留現有範圍，新增的角色為全域。
	RoleNodes map[uint]RoleNodesValue
}

// NodeRangeNoEffect 群組目前以節點範圍持有、而範圍不生效的全部角色（Role 為角色編號字串）。
func (s *UserGroupService) NodeRangeNoEffect(groupID uint) ([]NodeRangeNoEffect, error) {
	return groupNodeRangeNoEffect(s.db, groupID)
}

// SetAssignmentGuard 注入共用指派關卡（與使用者服務共用同一個）。
func (s *UserGroupService) SetAssignmentGuard(g *AssignmentGuard) { s.guard = g }

func (s *UserGroupService) assignmentGuard() *AssignmentGuard {
	if s.guard == nil {
		return NewAssignmentGuard(nil)
	}
	return s.guard
}

// RoleBindings 讀取群組目前的角色指派。
func (s *UserGroupService) RoleBindings(groupID uint) ([]authz.GroupRoleBinding, error) {
	var n int64
	if err := s.db.Model(&model.UserGroup{}).Where("id = ?", groupID).Count(&n).Error; err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrUserGroupNotFound
	}
	return authz.UserGroupRoleBindings(s.db, groupID)
}

// ReplaceRoleBindings 整組替換群組的角色指派。
func (s *UserGroupService) ReplaceRoleBindings(op Operator, groupID uint, req GroupRoleBindingsRequest) ([]authz.GroupRoleBinding, error) {
	want := unionIDs(req.RoleIDs, nil)
	for id := range req.RoleNodes {
		if !containsID(want, id) {
			return nil, errRoleNodesKeyNotListed()
		}
	}
	var addedRoles []uint
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var group model.UserGroup
		// 鎖序守衛探針（測試期；生產恆為 nil）：取群組列鎖之前
		if probe := authz.LockOrderProbeHook(); probe != nil {
			probe(tx, authz.LockLayerGroup, groupID)
		}
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = tx.Clauses(clause.Locking{Strength: "NO KEY UPDATE"})
		}
		if err := q.First(&group, groupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserGroupNotFound
			}
			return err
		}
		cur, err := authz.UserGroupRoleIDs(tx, groupID)
		if err != nil {
			return err
		}
		curNodes, err := authz.UserGroupRoleScopes(tx, groupID)
		if err != nil {
			return err
		}
		newScopes := map[uint][]uint{}
		for _, id := range want {
			if v, has := req.RoleNodes[id]; has && !v.Global {
				newScopes[id] = append(make([]uint, 0, len(v.NodeIDs)), v.NodeIDs...)
			}
		}
		if err := s.assignmentGuard().Check(tx, op, AssignmentChange{
			Path: PathGroupRoles, GroupID: groupID, NewRoleIDs: want, ScopeRequested: req.ScopeRequested,
			NodeScopes: newScopes}); err != nil {
			return err
		}
		tr, err := s.grader.begin(tx, op, PathGroupRoles, 0, groupID)
		if err != nil {
			return err
		}
		roles, err := loadRolesByID(tx, want)
		if err != nil {
			return err
		}
		for _, id := range want {
			r, ok := roles[id]
			if !ok {
				return ErrRoleNotFound
			}
			if !roleGroupBindable(r) {
				return ErrRoleNotGroupBindable
			}
		}
		add, remove := subtractIDs(want, cur), subtractIDs(cur, want)
		addedRoles = add
		// 每個保留或新增的角色最終的範圍（nil＝全域）：請求有帶就用請求，沒帶的保留角色維持現狀
		desired := make(map[uint][]uint, len(want))
		inCur := map[uint]bool{}
		for _, id := range cur {
			inCur[id] = true
		}
		var rescope []uint
		for _, id := range want {
			v, has := req.RoleNodes[id]
			switch {
			case has && v.Global:
				desired[id] = nil
			case has:
				desired[id] = newScopes[id]
			case inCur[id]:
				desired[id] = curNodes[id]
			}
			if inCur[id] && (desired[id] != nil) != (len(curNodes[id]) > 0) ||
				inCur[id] && desired[id] != nil && !authz.SameNodeSet(desired[id], curNodes[id]) {
				rescope = append(rescope, id)
			}
		}
		if len(add) == 0 && len(remove) == 0 && len(rescope) == 0 {
			return nil
		}
		// 全體成員的使用者憑證鎖先於任何寫入與版本推進（見檔頭的取鎖順序）：
		// 成員的有效角色集即將改變，與其帳號生命週期的鎖內判定互斥
		var members []uint
		if err := tx.Table("user_group_members").Where("user_group_id = ?", groupID).
			Order("user_id").Pluck("user_id", &members).Error; err != nil {
			return fmt.Errorf("讀取群組成員失敗: %w", err)
		}
		if h := loadLockOrderHook(); h != nil {
			h("group_roles_before_upfront", tx)
		}
		if err := lockUsersCredentialUpfrontTx(tx, members); err != nil {
			return err
		}
		// 拓撲序列化鎖：成員使用者鎖之後、BeginPermissionChange 與任何寫入之前。
		// 本次帶節點範圍，或群組現有節點範圍列可能被改動時才取；取鎖後才驗節點存在
		if len(newScopes) > 0 || len(curNodes) > 0 {
			if err := authz.LockScopeTopologyTx(tx); err != nil {
				return err
			}
		}
		if err := s.assignmentGuard().CheckNodesLive(tx, newScopes); err != nil {
			return err
		}
		if groupRoleBindingsPreWriteHook != nil {
			groupRoleBindingsPreWriteHook()
		}
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		losers, err := authz.MembersLosingRoles(tx, groupID, remove)
		if err != nil {
			return err
		}
		if err := authz.ReplaceUserGroupRoleRows(tx, groupID, add, remove); err != nil {
			return err
		}
		for _, id := range append(append([]uint{}, add...), rescope...) {
			if desired[id] == nil && !containsID(add, id) {
				if err := authz.SetUserGroupRoleScope(tx, groupID, id, nil); err != nil {
					return err
				}
			} else if desired[id] != nil {
				if err := authz.SetUserGroupRoleScope(tx, groupID, id, desired[id]); err != nil {
					return err
				}
			}
		}
		// 範圍縮小：成員在該角色上原本涵蓋的節點，變更後（本群組新範圍加其餘指派）不再涵蓋者，
		// 與失去角色者同樣推進憑證世代。成員一律取自預取集合，不含預取之後才加入的人
		var narrowed []uint
		for _, id := range rescope {
			oldR := authz.RoleRange{Global: len(curNodes[id]) == 0, NodeIDs: curNodes[id]}
			newR := authz.RoleRange{Global: desired[id] == nil, NodeIDs: desired[id]}
			for _, uid := range members {
				others, err := authz.UserOtherRoleRanges(tx, uid, id, groupID, true)
				if err != nil {
					return err
				}
				shrunk, err := s.assignmentGuard().rangeNarrowed(tx, oldR, newR, others)
				if err != nil {
					return err
				}
				if shrunk && !containsID(narrowed, uid) {
					narrowed = append(narrowed, uid)
				}
			}
		}
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		if h := loadLockOrderHook(); h != nil {
			h("group_roles_after_advance", tx)
		}
		prefetched := make(map[uint]bool, len(members))
		for _, uid := range members {
			prefetched[uid] = true
		}
		for _, uid := range append(append([]uint{}, losers...), narrowedOnly(narrowed, losers)...) {
			if !prefetched[uid] {
				// 預取之後才加入的成員（映射在群組鎖之外仍可加入）：照常補鎖、不跳過其失權處理，
				// 只留一行警告；補鎖可能與另一筆交易互等，結果是恰一方回滾可重試。
				log.Printf("[UserGroup] 警告：群組 %d 角色替換時發現預取集合之外的成員 %d，於推進版本之後補取使用者鎖", groupID, uid)
				// 鎖序守衛的已知例外登記（測試期；生產恆為 nil）：只放行這一位的補取
				if exempt := authz.LockOrderExemptLateJoinerHook(); exempt != nil {
					exempt(tx, authz.LateJoinerGroupRoleReplace, groupID, uid)
				}
			}
			if err := withUserCredentialLockTx(tx, uid, func(locked *gorm.DB) error {
				if err := BumpCredentialEpoch(locked, uid, "user_group_role_removed"); err != nil {
					return err
				}
				_, err := RevokeAllRefreshTokens(locked, uid, model.RefreshRevokeCredentialEpoch)
				return err
			}); err != nil {
				return err
			}
		}
		for _, change := range []struct {
			action model.AuditAction
			ids    []uint
		}{{model.ActionAssign, add}, {model.ActionRevoke, remove}} {
			for _, rid := range change.ids {
				if err := s.writeGroupRoleAudit(tx, op, change.action, groupID, rid); err != nil {
					return err
				}
			}
		}
		for _, rid := range rescope {
			if err := s.writeGroupRoleRangeAudit(tx, op, groupID, rid, curNodes[rid], desired[rid]); err != nil {
				return err
			}
		}
		if err := tr.finishGroup(tx, groupID, group.Name, 0); err != nil {
			return err
		}
		return authz.SettlePermissionChange(tx)
	})
	authz.NotifyVersionCommittedAfter(s.db, err)
	if err != nil {
		return nil, err
	}
	if len(addedRoles) > 0 {
		// 群組新增的角色，對其中的 agent 成員提交後重查（不擋寫入）
		var agentMembers []uint
		if qerr := s.db.Table("user_group_members").
			Joins("JOIN users ON users.id = user_group_members.user_id").
			Where("user_group_members.user_group_id = ? AND users.kind = ? AND users.deleted_at IS NULL", groupID, model.KindAgent).
			Pluck("users.id", &agentMembers).Error; qerr == nil {
			s.grader.afterAgentRoleWrite(s.db, &op, string(model.ResourceUserGroup), groupID, agentMembers, addedRoles)
		}
	}
	return authz.UserGroupRoleBindings(s.db, groupID)
}

func (s *UserGroupService) writeGroupRoleAudit(tx *gorm.DB, op Operator, action model.AuditAction, groupID, roleID uint) error {
	return s.writeGroupRoleAuditDetails(tx, op, action, groupID,
		fmt.Sprintf(`{"user_group_id":%d,"role_id":%d,"origin":"api"}`, groupID, roleID))
}

func (s *UserGroupService) writeGroupRoleAuditDetails(tx *gorm.DB, op Operator, action model.AuditAction, groupID uint, details string) error {
	gid := groupID
	if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		Action: string(action), Resource: string(model.ResourceUserGroupRole), ResourceID: &gid,
		Status: string(model.StatusSuccess), Actor: gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
		Request: gatewayapi.RequestMeta{ClientIP: op.ClientIP}, Details: details,
	}); err != nil {
		return fmt.Errorf("稽核留痕失敗: %w", err)
	}
	return nil
}

// writeGroupRoleRangeAudit 只改範圍的群組角色審計列（動作 update）；與角色增減共用同一個審計寫入點。
func (s *UserGroupService) writeGroupRoleRangeAudit(tx *gorm.DB, op Operator, groupID, roleID uint, before, after []uint) error {
	bv, bc := model.RangeAuditValue(before)
	av, ac := model.RangeAuditValue(after)
	details, err := json.Marshal(map[string]any{
		"user_group_id": groupID, "role_id": roleID, "origin": "api",
		"event": model.RoleBindingRangeChangedEvent, "range_before": bv, "range_after": av,
		"range_before_count": bc, "range_after_count": ac,
	})
	if err != nil {
		return fmt.Errorf("序列化稽核詳情失敗: %w", err)
	}
	return s.writeGroupRoleAuditDetails(tx, op, model.ActionUpdate, groupID, string(details))
}

// narrowedOnly narrowed 中不在 losers 內的成員（失去角色者已在失權迴圈內處理）。
func narrowedOnly(narrowed, losers []uint) []uint {
	var out []uint
	for _, u := range narrowed {
		if !containsID(losers, u) {
			out = append(out, u)
		}
	}
	return out
}

func containsID(ids []uint, id uint) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
