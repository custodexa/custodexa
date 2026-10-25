package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// agent 擁有者轉移的防自我授權：identity 定義、authz 實作的窄 port，
// 在更新交易內、鎖 agent 列之後判定；被拒時擁有者不變、權限版本與主體狀態事件不推進。
//
// 突變自檢：把 authz.SelfGrantGuard.CheckOwnerTransfer 改成一律回 nil，
// 「三案轉移被拒」與「並發至多一成功」轉紅。

type ownerTransferEnv struct {
	db    *gorm.DB
	users *identity.UserService
	authz *authz.AssetAuthorizationService
}

const (
	otUserU     = uint(1) // 曾替 agent 建規則的人
	otUserV     = uint(2) // 另一個授權者
	otUserOwner = uint(3) // 目前擁有者
	otSuper     = uint(4) // 超管
	otAgentX    = uint(5)
	otAsset     = uint(1)
)

func newOwnerTransferEnv(t *testing.T) *ownerTransferEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{},
		&model.AuditLog{}, &model.AuthzState{}, &model.PermissionStateEvent{}, &model.RolePermission{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.UserRole{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatalf("migrate tail: %v", err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	// 權限版本初始列（正式環境由權限模型遷移寫入）
	if err := db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error; err != nil {
		t.Fatal(err)
	}

	admin := model.Role{Name: model.RoleAdmin}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	owner := otUserOwner
	users := []model.User{
		{Username: "u", Active: true, Kind: model.KindHuman},
		{Username: "v", Active: true, Kind: model.KindHuman},
		{Username: "owner", Active: true, Kind: model.KindHuman},
		{Username: "root-admin", Active: true, Kind: model.KindHuman},
		{Username: "agent-x", Active: true, Kind: model.KindAgent, OwnerUserID: &owner},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&model.UserRole{UserID: otSuper, RoleID: admin.ID, ScopeKind: model.ScopeKindGlobal}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Asset{Name: "box", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: otSuper, Active: true}).Error; err != nil {
		t.Fatal(err)
	}
	authzSvc := authz.NewAssetAuthorizationService(db)
	svc := identity.NewUserService(db, authzSvc)
	svc.SetOwnerTransferGuard(authz.SelfGrantGuard{})
	return &ownerTransferEnv{db: db, users: svc, authz: authzSvc}
}

func (e *ownerTransferEnv) transfer(agentID, newOwner uint) error {
	_, _, err := e.users.Update(agentID, &identity.UpdateUserRequest{OwnerUserID: &newOwner})
	return err
}

func (e *ownerTransferEnv) ownerOf(t *testing.T, agentID uint) uint {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, agentID).Error; err != nil {
		t.Fatal(err)
	}
	if u.OwnerUserID == nil {
		return 0
	}
	return *u.OwnerUserID
}

func (e *ownerTransferEnv) rule(t *testing.T, grantedBy uint, expires *time.Time, source string) uint {
	t.Helper()
	agent, asset := otAgentX, otAsset
	row := model.AssetAuthorization{UserID: &agent, AssetID: &asset, Permission: model.PermissionConnect,
		GrantedBy: grantedBy, DateExpired: expires}
	if source != "" {
		row.Source = source
	}
	if err := e.db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	return row.ID
}

func (e *ownerTransferEnv) stateSnapshot(t *testing.T) (int64, int64, int64) {
	t.Helper()
	ver, err := authz.CurrentVersion(e.db)
	if err != nil {
		t.Fatal(err)
	}
	var events, audits int64
	if err := e.db.Model(&model.PermissionStateEvent{}).Count(&events).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceUser).Count(&audits).Error; err != nil {
		t.Fatal(err)
	}
	return ver, events, audits
}

func TestAgentOwnerTransferGuard(t *testing.T) {
	t.Run("U 曾建常設規則、未到期臨時授權、以 X 為申請人的範圍：轉給 U 皆被拒且擁有者不變", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		agent := otAgentX
		cases := []struct {
			name string
			seed func(e *ownerTransferEnv)
		}{
			{"有效常設規則", func(e *ownerTransferEnv) { e.rule(t, otUserU, nil, "") }},
			{"未到期臨時授權", func(e *ownerTransferEnv) { e.rule(t, otUserU, &future, model.AuthorizationSourceTicket) }},
			{"以 X 為申請人的審核範圍", func(e *ownerTransferEnv) {
				uid := otUserU
				if err := e.db.Create(&model.ApproverScope{ApproverID: &uid, SubjectUserID: &agent, GrantedBy: otUserU}).Error; err != nil {
					t.Fatal(err)
				}
			}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				env := newOwnerTransferEnv(t)
				c.seed(env)
				ver0, ev0, au0 := env.stateSnapshot(t)
				err := env.transfer(otAgentX, otUserU)
				if !errors.Is(err, authz.ErrAgentOwnerTransferSelfGrant) {
					t.Fatalf("應回 ErrAgentOwnerTransferSelfGrant，實得 %v", err)
				}
				if got := env.ownerOf(t, otAgentX); got != otUserOwner {
					t.Fatalf("擁有者不得改變: %d", got)
				}
				ver1, ev1, au1 := env.stateSnapshot(t)
				if ver1 != ver0 || ev1 != ev0 || au1 != au0 {
					t.Fatalf("被拒時權限版本與主體狀態事件不得推進: version %d→%d events %d→%d audits %d→%d", ver0, ver1, ev0, ev1, au0, au1)
				}
			})
		}
	})

	t.Run("規則已刪、臨時授權已過期、規則由 V 建立：轉移成功", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		cases := []struct {
			name string
			seed func(e *ownerTransferEnv)
		}{
			{"規則已刪", func(e *ownerTransferEnv) {
				id := e.rule(t, otUserU, nil, "")
				if err := e.db.Delete(&model.AssetAuthorization{}, id).Error; err != nil {
					t.Fatal(err)
				}
			}},
			{"臨時授權已過期", func(e *ownerTransferEnv) { e.rule(t, otUserU, &past, model.AuthorizationSourceTicket) }},
			{"規則由 V 建立", func(e *ownerTransferEnv) { e.rule(t, otUserV, nil, "") }},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				env := newOwnerTransferEnv(t)
				c.seed(env)
				if err := env.transfer(otAgentX, otUserU); err != nil {
					t.Fatalf("應成功: %v", err)
				}
				if got := env.ownerOf(t, otAgentX); got != otUserU {
					t.Fatalf("擁有者應改為 U: %d", got)
				}
			})
		}
	})

	t.Run("新擁有者為超管時成功", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		env.rule(t, otSuper, nil, "")
		if err := env.transfer(otAgentX, otSuper); err != nil {
			t.Fatalf("超管不判定: %v", err)
		}
	})

	t.Run("並發：U 建以 X 為主體的規則與 X 轉給 U 至多一個成功", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		agent, asset := otAgentX, otAsset
		ctx := authz.ContextWithPrincipal(context.Background(), authz.NewPrincipal(otUserU, authz.TokenFacts{}, []authz.Assignment{{
			RoleName: "authz-admin", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
			Permissions: []authz.Permission{authz.PermAuthorizationManage}, Custom: true,
		}}))
		var wg sync.WaitGroup
		var grantErr, transferErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, grantErr = env.authz.Grant(ctx, authz.GrantSpec{UserID: &agent, AssetID: &asset,
				Permission: model.PermissionConnect, GrantedBy: otUserU})
		}()
		go func() {
			defer wg.Done()
			transferErr = env.transfer(otAgentX, otUserU)
		}()
		wg.Wait()
		if grantErr == nil && transferErr == nil {
			t.Fatalf("兩者不得同時成功（規則主體為 X 且 X 的擁有者為 U）")
		}
		if grantErr != nil && !errors.Is(grantErr, authz.ErrSelfSubjectGrant) {
			t.Fatalf("建規則若失敗只能是本人範圍拒絕: %v", grantErr)
		}
		if transferErr != nil && !errors.Is(transferErr, authz.ErrAgentOwnerTransferSelfGrant) {
			t.Fatalf("轉移若失敗只能是防自授拒絕: %v", transferErr)
		}
	})

	t.Run("port 未注入時轉移 fail-close", func(t *testing.T) {
		env := newOwnerTransferEnv(t)
		env.users.SetOwnerTransferGuard(nil)
		if err := env.transfer(otAgentX, otUserV); !errors.Is(err, identity.ErrOwnerTransferGuardMissing) {
			t.Fatalf("未注入應拒絕: %v", err)
		}
		if got := env.ownerOf(t, otAgentX); got != otUserOwner {
			t.Fatalf("擁有者不得改變: %d", got)
		}
	})
}
