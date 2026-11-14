package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleDefinitionWriteWithoutRequestContextDenied 角色定義寫入沒有系統路徑：ctx 既沒有請求憑證種類也沒有
// 請求主體時拒絕且不寫入任何東西（不再以帳號完整身分重驗）。同一帳號以人類工作階段寫入，結果與修改前相同。
func TestRoleDefinitionWriteWithoutRequestContextDenied(t *testing.T) {
	e := newRoleDefEnv(t)
	in := RoleInput{Name: "no-context", Permissions: []string{"asset:view"}}
	roles, perms, ver, audits := e.snapshot(t)

	_, err := e.svc.Create(context.Background(), e.admin, in)
	assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
	_, err = e.svc.Copy(context.Background(), e.admin, e.roles["user"], "no-context-copy", "")
	assert.ErrorIs(t, err, ErrRoleDefinitionForbidden)
	r2, p2, v2, a2 := e.snapshot(t)
	assert.Equal(t, []int64{roles, perms, ver, audits}, []int64{r2, p2, v2, a2}, "被拒時沒有任何寫入")

	d, err := e.svc.Create(asSession(context.Background(), e.admin), e.admin, in)
	require.NoError(t, err, "人類工作階段的超級管理者照常寫入")
	assert.ErrorIs(t, e.svc.Delete(context.Background(), e.admin, d.ID, d.DefinitionVersion), ErrRoleDefinitionForbidden)
	require.NoError(t, e.svc.Delete(asSession(context.Background(), e.admin), e.admin, d.ID, d.DefinitionVersion))
}
