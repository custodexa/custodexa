package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 本檔只放 TestPermissionRestoreGeneration 的輔助函式（一次性子命令與兌換入口的子案例用）。

// oneShotDB 建一份帶完整權限模型表的「備份剛匯入」資料庫：四個內建身分、
// 一位直接全域 manual 的本地超管、legacy 世代、version=5。
func oneShotDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{},
		&model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{}, &model.AuthzState{}, &model.AssetGroup{},
		&model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{}, &model.LDAPDirectory{},
		&model.OIDCProvider{}, &model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.AssetAuthorization{}, &model.Asset{}, &model.RolePermission{}))
	for i, bk := range []string{"super_admin", "auditor", "user", "approver"} {
		k := bk
		name := []string{"admin", "auditor", "user", "approver"}[i]
		require.NoError(t, db.Create(&model.Role{Name: name, BuiltinKey: &k}).Error)
	}
	u := &model.User{Username: "root", Password: "hash", Active: true, Kind: "human", ProvisioningOrigin: model.AuthSourceLocal}
	require.NoError(t, db.Create(u).Error)
	require.NoError(t, db.Create(&model.UserRole{UserID: u.ID, RoleID: 1, Source: "manual", ScopeKind: "global"}).Error)
	require.NoError(t, db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 5)").Error)
	return db
}

// oneShot 以子命令入口執行並回傳 (結束碼, stdout)。
func oneShot(db *gorm.DB, args ...string) (int, string) {
	var sb strings.Builder
	code := runOneShotWith(db, args, &sb)
	return code, sb.String()
}

func kvLines(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

// recordingSealer 記錄封章呼叫順序（sealAfterRestore 的測試替身）。
type recordingSealer struct {
	calls *[]string
	fail  bool
}

func (r *recordingSealer) SealNow() (*model.AuditCheckpoint, error) {
	*r.calls = append(*r.calls, "seal")
	if r.fail {
		return nil, errors.New("seal failed")
	}
	return &model.AuditCheckpoint{}, nil
}

func (r *recordingSealer) EnsureGenesis() error {
	*r.calls = append(*r.calls, "genesis")
	return nil
}
