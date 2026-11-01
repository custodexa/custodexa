package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// spyRoleWriter 轉呼叫真服務並記錄次數與最後一次錯誤，證明請求確實通過路由層到達服務。
type spyRoleWriter struct {
	inner *identity.RoleDefinitionService
	calls int
	err   error
}

func (s *spyRoleWriter) Create(ctx context.Context, a uint, in identity.RoleInput) (*identity.RoleDefinition, error) {
	s.calls++
	out, err := s.inner.Create(ctx, a, in)
	s.err = err
	return out, err
}

func (s *spyRoleWriter) Copy(ctx context.Context, a, src uint, name, desc string) (*identity.RoleDefinition, error) {
	s.calls++
	out, err := s.inner.Copy(ctx, a, src, name, desc)
	s.err = err
	return out, err
}

func (s *spyRoleWriter) Update(ctx context.Context, a, id uint, v int64, in identity.RoleInput) (*identity.RoleDefinition, error) {
	s.calls++
	out, err := s.inner.Update(ctx, a, id, v, in)
	s.err = err
	return out, err
}

func (s *spyRoleWriter) Delete(ctx context.Context, a, id uint, v int64) error {
	s.calls++
	err := s.inner.Delete(ctx, a, id, v)
	s.err = err
	return err
}

// 請求以超管身分通過路由層，但在服務交易開始前該帳號的超管指派已被撤銷：
// 服務層在交易內重驗後拒絕，角色內容與定義版本不變（四種寫入各一案）。
func TestRoleDefinitionWritesAfterDemotion(t *testing.T) {
	env := newOwnerTransferEnv(t)
	legacy := legacyPermissionDeniedBody(t)

	var admin model.Role
	require.NoError(t, env.db.Where("name = ?", model.RoleAdmin).First(&admin).Error)
	demoted := model.User{Username: "demoted-admin", Active: true, Kind: model.KindHuman}
	require.NoError(t, env.db.Create(&demoted).Error)
	grant := model.UserRole{UserID: demoted.ID, RoleID: admin.ID, ScopeKind: model.ScopeKindGlobal}
	require.NoError(t, env.db.Create(&grant).Error)
	// 撤銷指派：路由層持有的主體仍是超管，資料庫現況已不是
	require.NoError(t, env.db.Delete(&grant).Error)

	target := model.Role{Name: "demotion-target", DefinitionVersion: 1}
	require.NoError(t, env.db.Create(&target).Error)
	require.NoError(t, env.db.Create(&model.RolePermission{RoleID: target.ID, PermissionKey: "asset:view"}).Error)

	type snapshot struct {
		roles, perms, version int64
		defVersion            int64
	}
	snap := func() snapshot {
		var s snapshot
		require.NoError(t, env.db.Unscoped().Model(&model.Role{}).Count(&s.roles).Error)
		require.NoError(t, env.db.Model(&model.RolePermission{}).Count(&s.perms).Error)
		v, err := authz.CurrentVersion(env.db)
		require.NoError(t, err)
		s.version = v
		var r model.Role
		require.NoError(t, env.db.Unscoped().First(&r, target.ID).Error)
		s.defVersion = r.DefinitionVersion
		return s
	}

	svc := identity.NewRoleDefinitionService(env.db, audit.NewTxSink(), nil, nil)
	targetPath := "/api/v1/role-definitions/" + itoa(target.ID)
	for _, v := range []struct{ name, method, path, body string }{
		{"新增", "POST", "/api/v1/role-definitions", `{"name":"after-demotion","permissions":["asset:view"]}`},
		{"複製", "POST", targetPath + "/copy", `{"name":"after-demotion-copy"}`},
		{"修改", "PUT", targetPath, `{"name":"demotion-target","permissions":["asset:view","asset:update"],"expected_version":1}`},
		{"刪除", "DELETE", targetPath + "?expected_version=1", ""},
	} {
		t.Run(v.name, func(t *testing.T) {
			before := snap()
			spy := &spyRoleWriter{inner: svc}
			pr := markerServe(principalOf(model.BuiltinSuperAdmin, ""), demoted.ID, v.method, v.path, v.body, mountRoles(spy))
			require.Equal(t, 1, spy.calls, "路由層須放行，請求到達服務")
			assert.True(t, errors.Is(spy.err, identity.ErrRoleDefinitionForbidden), "服務層重驗須以哨兵拒絕，實得 %v", spy.err)
			assert.Equal(t, http.StatusForbidden, pr.code)
			assert.Equal(t, legacy, pr.raw)
			assert.Equal(t, before, snap(), "被拒的寫入不改角色內容與定義版本")
		})
	}
}
