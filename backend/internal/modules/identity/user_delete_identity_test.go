package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 帳號刪除與外部身分綁定：刪除同交易作廢綁定、provider 綁定數只計有效綁定、
// 目錄影子帳號刪除後再登入即重建。

// unscopedIdentities 指定帳號的全部綁定（含已作廢）
func unscopedIdentities(t *testing.T, db *gorm.DB, userID uint) []model.UserExternalIdentity {
	t.Helper()
	var rows []model.UserExternalIdentity
	if err := db.Unscoped().Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀綁定: %v", err)
	}
	return rows
}

// TestDeleteUserRevokesExternalIdentities 刪除帳號時同交易作廢其全部外部身分綁定；
// 刪除被不變式拒絕時綁定不動
func TestDeleteUserRevokesExternalIdentities(t *testing.T) {
	forEachOrphanDialect(t, func(t *testing.T, kind string) {
		env := newOrphanEnv(t, kind, model.AdmissionPreboundOnly)
		second := seedProvider(t, env.db, func(p *model.OIDCProvider) {
			p.Name = "corp-2"
			p.Issuer = "https://idp2.example.com"
			p.ClientID = "cid-2"
		})
		alice := seedOIDCUser(t, env.db, "alice")
		actor := IdentityAdminActor{UserID: 1, Username: "keeper-admin"}
		for _, b := range []struct {
			p       *model.OIDCProvider
			subject string
		}{{env.p, "sub-a"}, {second, "sub-b"}} {
			if _, err := env.users.BindExternalIdentity(alice.ID, b.p.ID, b.subject, actor); err != nil {
				t.Fatalf("綁定 %s: %v", b.subject, err)
			}
		}

		summary, err := env.users.DeleteWithSummary(alice.ID)
		if err != nil {
			t.Fatalf("刪除帳號: %v", err)
		}
		if summary.Username != "alice" || summary.ExternalIdentitiesRevoked != 2 {
			t.Fatalf("摘要 = %+v, want {alice 2}", summary)
		}
		rows := unscopedIdentities(t, env.db, alice.ID)
		if len(rows) != 2 {
			t.Fatalf("綁定列數 = %d, want 2", len(rows))
		}
		for _, r := range rows {
			if !r.DeletedAt.Valid {
				t.Errorf("綁定 %s 應已作廢（deleted_at 非空）", r.Subject)
			}
		}

		// 同一身分域三元組可再綁到新帳號（作廢列不占唯一索引）
		bob := seedOIDCUser(t, env.db, "bob")
		if _, err := env.users.BindExternalIdentity(bob.ID, env.p.ID, "sub-a", actor); err != nil {
			t.Fatalf("作廢後重綁應成功: %v", err)
		}
	})
}

// TestDeleteUserRejectedKeepsExternalIdentities 刪除因「最後一個 admin」被拒時，
// 帳號與其綁定皆維持原狀
func TestDeleteUserRejectedKeepsExternalIdentities(t *testing.T) {
	env := newOrphanEnv(t, "sqlite", model.AdmissionPreboundOnly)
	keeper := env.liveUser(t, "keeper-admin")
	actor := IdentityAdminActor{UserID: keeper.ID, Username: "keeper-admin"}
	for _, sub := range []string{"sub-k1", "sub-k2"} {
		if _, err := env.users.BindExternalIdentity(keeper.ID, env.p.ID, sub, actor); err != nil {
			t.Fatalf("綁定 %s: %v", sub, err)
		}
	}
	if _, err := env.users.DeleteWithSummary(keeper.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("刪除最後一個 admin = %v, want ErrLastAdmin", err)
	}
	for _, r := range unscopedIdentities(t, env.db, keeper.ID) {
		if r.DeletedAt.Valid {
			t.Errorf("刪除被拒時綁定 %s 不應作廢", r.Subject)
		}
	}
}

// providerIdentityCount 清單上指定 provider 的身分數
func providerIdentityCount(t *testing.T, providers *OIDCProviderService, id uint) int64 {
	t.Helper()
	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, dto := range list {
		if dto.ID == id {
			return dto.IdentityCount
		}
	}
	t.Fatalf("清單查無 provider %d", id)
	return -1
}

// TestOIDCProviderDeleteIgnoresDeletedUsersBindings provider 僅剩的綁定屬已刪帳號
// （綁定列未作廢，升級前刪除留下的狀態）：清單身分數為 0 且刪除成功；
// 對照組帳號未刪時身分數為 1 且刪除回衝突
func TestOIDCProviderDeleteIgnoresDeletedUsersBindings(t *testing.T) {
	t.Run("帳號已刪", func(t *testing.T) {
		_, providers, db := setupOIDCEnv(t)
		p := seedProvider(t, db, nil)
		u := seedOIDCUser(t, db, "gone")
		seedIdentity(t, db, u, p, "sub-gone")
		if err := db.Exec("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", u.ID).Error; err != nil {
			t.Fatalf("直寫軟刪帳號: %v", err)
		}
		if n := providerIdentityCount(t, providers, p.ID); n != 0 {
			t.Fatalf("清單身分數 = %d, want 0", n)
		}
		if err := providers.Delete(p.ID); err != nil {
			t.Fatalf("刪除 provider 應成功: %v", err)
		}
	})
	t.Run("帳號在用", func(t *testing.T) {
		_, providers, db := setupOIDCEnv(t)
		p := seedProvider(t, db, nil)
		u := seedOIDCUser(t, db, "alive")
		seedIdentity(t, db, u, p, "sub-alive")
		if n := providerIdentityCount(t, providers, p.ID); n != 1 {
			t.Fatalf("清單身分數 = %d, want 1", n)
		}
		if err := providers.Delete(p.ID); !errors.Is(err, ErrOIDCProviderInUse) {
			t.Fatalf("刪除 provider = %v, want ErrOIDCProviderInUse", err)
		}
	})
}

// TestLDAPShadowUserReprovisionedAfterDelete 目錄影子帳號被刪後，此人再以目錄帳號
// 登入即重建（新帳號編號、同帳號名）。目錄登入不經外部身分綁定，沒有可懸空的列
func TestLDAPShadowUserReprovisionedAfterDelete(t *testing.T) {
	env := setupRegressionEnv(t)
	// 刪除路徑的連動清理表，以及與正式庫同語義的 partial 帳號名／email 索引
	if err := env.db.AutoMigrate(&model.UserGroup{}, &model.UserGroupMember{}, &model.ApproverScope{},
		&model.GroupRoleMapping{}, &model.UserRoleMapping{}, &model.ExternalGroup{},
		&model.GroupUserGroupMapping{}, &model.UserRoleMappingRuleSupport{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS idx_users_username`,
		`CREATE UNIQUE INDEX idx_users_username ON users (username) WHERE deleted_at IS NULL`,
		`DROP INDEX IF EXISTS idx_users_email`,
		`CREATE UNIQUE INDEX idx_users_email ON users (email) WHERE email IS NOT NULL AND deleted_at IS NULL`,
	} {
		if err := env.db.Exec(stmt).Error; err != nil {
			t.Fatalf("partial index: %v", err)
		}
	}
	fake := &fakeLDAPAuthenticator{info: &LDAPUserInfo{
		Username: "dir-carol", Email: "dir-carol@corp.example", FullName: "Dir Carol"}}
	env.auth.SetLDAPResolver(staticLDAPResolver(fake))

	if _, err := env.auth.Login(&LoginRequest{Username: "dir-carol", Password: "dirpass"}); err != nil {
		t.Fatalf("目錄首登應成功: %v", err)
	}
	var first model.User
	if err := env.db.Where("username = ?", "dir-carol").First(&first).Error; err != nil {
		t.Fatalf("影子帳號應已建立: %v", err)
	}
	if err := env.users.Delete(first.ID); err != nil {
		t.Fatalf("刪除影子帳號: %v", err)
	}

	if _, err := env.auth.Login(&LoginRequest{Username: "dir-carol", Password: "dirpass"}); err != nil {
		t.Fatalf("刪除後以目錄帳號再登入應重建帳號: %v", err)
	}
	var second model.User
	if err := env.db.Where("username = ?", "dir-carol").First(&second).Error; err != nil {
		t.Fatalf("重建的影子帳號應存在: %v", err)
	}
	if second.ID == first.ID || !second.IsLDAP {
		t.Fatalf("重建帳號 = (id=%d, is_ldap=%v)，want 新編號（原 %d）且為目錄帳號",
			second.ID, second.IsLDAP, first.ID)
	}
}
