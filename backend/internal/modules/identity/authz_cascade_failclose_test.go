package identity

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// F8 fail-close（modular-architecture W7 7.4）：identity 側的級聯撤銷失敗
// 或撤銷面未注入時，刪群組／刪帳號**必須整筆失敗**。
//
// **為何非有不可**：W7 波內的載重性驗證在 asset 側實測到——把
// 「撤銷回錯誤就 return」改成「記個 log 繼續刪」之後，既有的委派斷言與
// audit backstop **兩格都照樣綠**（backstop 注入的是審計失敗，不是撤銷失敗）。
// identity 側是同一形狀：群組／帳號刪了而授權與審核範圍留著＝幽靈授權
// 與可回復的審核資格（對抗驗證 aaa2018 #1/#2），正是這條級聯存在的理由。

// failingCascadeRevoker 一律回錯誤的 authz 級聯撤銷面替身。
type failingCascadeRevoker struct{ err error }

func (f *failingCascadeRevoker) RevokeByUserGroup(tx *gorm.DB, groupID uint) (int64, error) {
	return 0, f.err
}

func (f *failingCascadeRevoker) RevokeByUser(tx *gorm.DB, userID uint) error { return f.err }

func setupCascadeFailCloseDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{},
		&model.AssetAuthorization{}, &model.ApproverScope{}, &model.AuditLog{},
		&model.RefreshToken{}, &model.UserExternalIdentity{}, &model.Session{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestUserGroupDeleteFailsClosedWhenRevokeFails(t *testing.T) {
	boom := errors.New("撤銷面故障")

	t.Run("撤銷回錯誤即整筆回滾", func(t *testing.T) {
		db := setupCascadeFailCloseDB(t)
		svc := NewUserGroupService(db, audit.NewTxSink(), &failingCascadeRevoker{err: boom})
		g, err := svc.Create(&UserGroupRequest{Name: "G"})
		if err != nil {
			t.Fatalf("前置建立: %v", err)
		}
		if _, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1"); !errors.Is(err, boom) {
			t.Fatalf("撤銷失敗時刪群組應回該錯誤, got %v", err)
		}
		var groups int64
		db.Model(&model.UserGroup{}).Where("id = ?", g.ID).Count(&groups)
		if groups != 1 {
			t.Fatalf("撤銷失敗時群組竟被刪除（剩 %d 筆，應為 1）——幽靈授權即將產生", groups)
		}
	})

	t.Run("撤銷面未注入即拒絕刪除", func(t *testing.T) {
		db := setupCascadeFailCloseDB(t)
		svc := NewUserGroupService(db, audit.NewTxSink(), nil)
		g, err := svc.Create(&UserGroupRequest{Name: "G"})
		if err != nil {
			t.Fatalf("前置建立: %v", err)
		}
		if _, err := svc.Delete(g.ID, 1, "admin", "127.0.0.1"); err == nil {
			t.Fatal("未注入撤銷面時刪群組竟然成功——nil 被當成 no-op，授權將靜默殘留")
		}
		var groups int64
		db.Model(&model.UserGroup{}).Where("id = ?", g.ID).Count(&groups)
		if groups != 1 {
			t.Fatalf("未注入撤銷面時群組竟被刪除（剩 %d 筆，應為 1）", groups)
		}
	})
}

func TestUserDeleteFailsClosedWhenRevokeFails(t *testing.T) {
	boom := errors.New("撤銷面故障")

	mkUser := func(t *testing.T, db *gorm.DB) uint {
		t.Helper()
		u := model.User{Username: "victim", Email: strPtr("v@x"), Active: true}
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return u.ID
	}

	t.Run("撤銷回錯誤即整筆回滾", func(t *testing.T) {
		db := setupCascadeFailCloseDB(t)
		svc := NewUserService(db, &failingCascadeRevoker{err: boom})
		id := mkUser(t, db)
		if err := svc.Delete(id); !errors.Is(err, boom) {
			t.Fatalf("撤銷失敗時刪帳號應回該錯誤, got %v", err)
		}
		var users int64
		db.Model(&model.User{}).Where("id = ?", id).Count(&users)
		if users != 1 {
			t.Fatalf("撤銷失敗時帳號竟被刪除（剩 %d 筆，應為 1）——幽靈審核範圍即將產生", users)
		}
	})

	t.Run("撤銷面未注入即拒絕刪除", func(t *testing.T) {
		db := setupCascadeFailCloseDB(t)
		svc := NewUserService(db, nil)
		id := mkUser(t, db)
		if err := svc.Delete(id); err == nil {
			t.Fatal("未注入撤銷面時刪帳號竟然成功——nil 被當成 no-op，審核範圍將靜默殘留")
		}
		var users int64
		db.Model(&model.User{}).Where("id = ?", id).Count(&users)
		if users != 1 {
			t.Fatalf("未注入撤銷面時帳號竟被刪除（剩 %d 筆，應為 1）", users)
		}
	})
}
