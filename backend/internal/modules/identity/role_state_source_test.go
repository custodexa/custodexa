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
}
