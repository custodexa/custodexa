package identity

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
)

// 本套件的測試以真實來源接上 audit（與 cmd/server/stage2.go 的組裝相同），
// 讓走真對帳器的登入測試不必各自注入
func init() {
	audit.SetUserRolesSource(SnapshotUserRolePairs)
}

// TestSnapshotUserRolePairsReadsAssignments 來源讀到的就是 user_roles 的現況：
// 配一筆角色後 pairs 含該對，且快照雜湊隨之改變
func TestSnapshotUserRolePairsReadsAssignments(t *testing.T) {
	db := setupRoleAuditDB(t)
	before, err := audit.SnapshotUserRoles(context.Background(), db)
	if err != nil {
		t.Fatalf("空表快照: %v", err)
	}
	u := seedLoginUser(t, db, "src-user", model.RoleAuditor)
	pairs, err := SnapshotUserRolePairs(context.Background(), db)
	if err != nil {
		t.Fatalf("讀來源: %v", err)
	}
	var role model.Role
	if err := db.Where("name = ?", model.RoleAuditor).First(&role).Error; err != nil {
		t.Fatalf("讀角色: %v", err)
	}
	found := false
	for _, p := range pairs {
		if p.UserID == uint64(u.ID) && p.RoleID == uint64(role.ID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("來源未讀到剛配的指派 (%d,%d)，實得 %v", u.ID, role.ID, pairs)
	}
	after, err := audit.SnapshotUserRoles(context.Background(), db)
	if err != nil {
		t.Fatalf("快照: %v", err)
	}
	if after.Hash == before.Hash {
		t.Fatal("配角色後快照雜湊未變：來源沒有接到快照")
	}
	_ = gorm.ErrRecordNotFound

	// 範圍：節點範圍的指派帶節點集合；種類為全域時殘留的節點列不計入；種類不明不當成全域
	t.Run("reads_scope_and_nodes", func(t *testing.T) {
		must := func(res *gorm.DB) {
			t.Helper()
			if res.Error != nil {
				t.Fatalf("exec: %v", res.Error)
			}
		}
		must(db.Exec("UPDATE user_roles SET scope_kind = 'nodes' WHERE user_id = ? AND role_id = ?", u.ID, role.ID))
		for _, n := range []uint{7, 3} {
			must(db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUser, SubjectID: u.ID, RoleID: role.ID, NodeID: n}))
		}
		// 另一個使用者群組主體的同編號節點列不得混進來
		must(db.Create(&model.RoleBindingNode{SubjectKind: model.BindingSubjectUserGroup, SubjectID: u.ID, RoleID: role.ID, NodeID: 99}))
		rangeOf := func() string {
			t.Helper()
			ps, err := SnapshotUserRolePairs(context.Background(), db)
			if err != nil {
				t.Fatalf("讀來源: %v", err)
			}
			for _, p := range ps {
				if p.UserID == uint64(u.ID) && p.RoleID == uint64(role.ID) {
					return p.Range
				}
			}
			t.Fatalf("來源未讀到指派")
			return ""
		}
		if got := rangeOf(); got != "[3,7]" {
			t.Fatalf("節點範圍 = %q, want [3,7]", got)
		}
		must(db.Exec("UPDATE user_roles SET scope_kind = 'global' WHERE user_id = ? AND role_id = ?", u.ID, role.ID))
		if got := rangeOf(); got != "" {
			t.Fatalf("種類為全域時範圍 = %q, want 空（殘留的節點列不計入）", got)
		}
		must(db.Exec("UPDATE user_roles SET scope_kind = 'weird' WHERE user_id = ? AND role_id = ?", u.ID, role.ID))
		if got := rangeOf(); got != audit.NodeRangeEmpty {
			t.Fatalf("未知種類範圍 = %q, want %q", got, audit.NodeRangeEmpty)
		}
	})
}
