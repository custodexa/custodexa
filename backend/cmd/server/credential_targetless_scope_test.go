package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 不帶目標的憑證管理請求：轉接頭只讓列表（view）與建立（create）認節點範圍來源，並標記呼叫端必須收斂範圍；
// 服務在收斂所需的投影或歸屬判定缺席時拒絕，不退回全域口徑。

// scCtx 以資料庫現況解析主體，組出服務層呼叫用的 context（與請求路徑同形）。
func (e *scEnv) scCtx(uid uint) context.Context {
	e.t.Helper()
	p, err := authz.ResolveUserOnWithCatalogue(e.db, e.cat, uid, authz.TokenFacts{})
	require.NoError(e.t, err)
	ctx := context.WithValue(context.Background(), "userID", uid)     //nolint:staticcheck // 沿用既有審計 context 慣例
	ctx = context.WithValue(ctx, "username", fmt.Sprintf("u%d", uid)) //nolint:staticcheck
	return authz.ContextWithPrincipal(ctx, p)
}

func (e *scEnv) credentialCount() int64 {
	e.t.Helper()
	var n int64
	require.NoError(e.t, e.db.Model(&model.Credential{}).Count(&n).Error)
	return n
}

func TestCredentialTargetlessScopeNarrowing(t *testing.T) {
	env := newSCEnv(t)
	env.node("zz-sc-in", "")
	env.node("zz-sc-out", "")
	scoped := env.user("zz-sc-scoped")
	env.grant(scoped, []string{"zz-sc-in"}, scCredentialPerms...)
	noView := env.user("zz-sc-noview")
	env.grant(noView, []string{"zz-sc-in"}, authz.PermCredentialUpdate)
	global := env.user("zz-sc-global")
	env.grantGlobal(global, env.role(scCredentialPerms...))

	inCred := env.cred("zz-sc-in-cred", env.nodeID("zz-sc-in"))
	outCred := env.cred("zz-sc-out-cred", env.nodeID("zz-sc-out"))
	globalCred := env.cred("zz-sc-global-cred", nil)

	narrowed := []struct {
		op  asset.CredentialOperation
		cap string
	}{{asset.CredOpView, asset.CredCapView}, {asset.CredOpCreate, asset.CredCapCreate}}
	others := []struct {
		op  asset.CredentialOperation
		cap string
	}{
		{asset.CredOpUpdate, asset.CredCapUpdate}, {asset.CredOpSetSecret, asset.CredCapSetSecret},
		{asset.CredOpRotate, asset.CredCapRotate}, {asset.CredOpConvertScope, asset.CredCapConvertScope},
		{asset.CredOpDetach, asset.CredCapDetach}, {asset.CredOpDelete, asset.CredCapDelete},
		{asset.CredOpBind, asset.CredCapBind},
	}
	decide := func(uid uint, op asset.CredentialOperation, capKey string) asset.CredentialManagementDecision {
		t.Helper()
		d, err := env.adapter.AuthorizeCredentialManagement(env.scCtx(uid), nil,
			asset.CredentialManagementActor{UserID: uid}, asset.CredentialManagementRequest{
				Operation: op, Capabilities: []string{capKey},
			})
		require.NoError(t, err)
		return d
	}

	t.Run("轉接頭只讓節點範圍主體以不帶目標的列表與建立過能力關卡並標記須收斂", func(t *testing.T) {
		for _, c := range narrowed {
			d := decide(scoped, c.op, c.cap)
			require.True(t, d.Allowed, "op=%s", c.op)
			require.Empty(t, d.Missing, "op=%s", c.op)
			require.True(t, d.ScopeNarrowingRequired, "op=%s", c.op)
		}
		for _, c := range others {
			d := decide(scoped, c.op, c.cap)
			require.False(t, d.Allowed, "op=%s", c.op)
			require.Equal(t, c.cap, d.Missing, "op=%s", c.op)
			require.False(t, d.ScopeNarrowingRequired, "op=%s", c.op)
		}
	})

	t.Run("節點範圍來源沒有該能力時不帶目標的列表仍被拒", func(t *testing.T) {
		d := decide(noView, asset.CredOpView, asset.CredCapView)
		require.False(t, d.Allowed)
		require.Equal(t, asset.CredCapView, d.Missing)
		require.False(t, d.ScopeNarrowingRequired)
	})

	t.Run("全域主體不帶目標的全部操作照舊放行且不標記", func(t *testing.T) {
		for _, c := range append(append([]struct {
			op  asset.CredentialOperation
			cap string
		}{}, narrowed...), others...) {
			d := decide(global, c.op, c.cap)
			require.True(t, d.Allowed, "op=%s", c.op)
			require.False(t, d.ScopeNarrowingRequired, "op=%s", c.op)
		}
	})

	// 未注入投影來源與歸屬判定的服務（管理授權與正式組裝同形）
	unwired := asset.NewCredentialService(env.assets, env.codec, audit.NewTxSink()).
		WithManagementAuthorizer(env.adapter).WithSystemAlertSink(noopAlertSink{})
	ids := func(list []*asset.CredentialDTO) map[uint]bool {
		out := map[uint]bool{}
		for _, d := range list {
			out[d.ID] = true
		}
		return out
	}

	t.Run("列表：節點範圍主體在投影來源未注入時被拒而非回全量", func(t *testing.T) {
		list, err := unwired.List(env.scCtx(scoped), asset.CredentialFilter{})
		require.Error(t, err)
		require.True(t, errors.Is(err, asset.ErrCredentialAuthzUnavailable), "err=%v", err)
		require.Nil(t, list)
	})

	t.Run("列表：節點範圍主體在投影來源已注入時只回範圍內", func(t *testing.T) {
		list, err := env.creds.List(env.scCtx(scoped), asset.CredentialFilter{})
		require.NoError(t, err)
		require.Equal(t, map[uint]bool{inCred: true}, ids(list))
	})

	t.Run("列表：全域主體在投影來源未注入時行為不變", func(t *testing.T) {
		want, err := env.creds.List(env.scCtx(global), asset.CredentialFilter{})
		require.NoError(t, err)
		got, err := unwired.List(env.scCtx(global), asset.CredentialFilter{})
		require.NoError(t, err)
		// 夾具另有種子憑證：斷言本案三筆皆在、且回傳全部憑證（含範圍外者），不以字面清單排除種子
		for _, id := range []uint{inCred, outCred, globalCred} {
			require.True(t, ids(got)[id], "全域主體須看得到憑證 %d", id)
		}
		require.EqualValues(t, env.credentialCount(), len(ids(got)), "全域主體回全量")
		require.Equal(t, ids(want), ids(got))
	})

	newReq := func(name string, owner *asset.CredentialOwnershipInput) *asset.CreateCredentialRequest {
		return &asset.CreateCredentialRequest{Name: name, Username: "u-" + name,
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-" + name, Ownership: owner}
	}

	t.Run("建立：節點範圍主體在歸屬判定未注入時被拒且憑證表筆數不變", func(t *testing.T) {
		before := env.credentialCount()
		_, err := unwired.Create(env.scCtx(scoped), newReq("zz-sc-new-unwired",
			&asset.CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: env.nodeID("zz-sc-in")}))
		require.Error(t, err)
		require.True(t, errors.Is(err, asset.ErrCredentialAuthzUnavailable), "err=%v", err)
		require.Equal(t, before, env.credentialCount())
	})

	t.Run("建立：節點範圍主體在歸屬判定已注入時未帶歸屬回歸屬無效、帶範圍內節點成功", func(t *testing.T) {
		before := env.credentialCount()
		_, err := env.creds.Create(env.scCtx(scoped), newReq("zz-sc-new-none", nil))
		require.Error(t, err)
		require.True(t, errors.Is(err, asset.ErrCredentialOwnershipInvalid), "err=%v", err)
		require.Equal(t, before, env.credentialCount())

		dto, err := env.creds.Create(env.scCtx(scoped), newReq("zz-sc-new-in",
			&asset.CredentialOwnershipInput{Kind: model.CredentialOwnerNode, NodeID: env.nodeID("zz-sc-in")}))
		require.NoError(t, err)
		var c model.Credential
		require.NoError(t, env.db.First(&c, dto.ID).Error)
		require.NotNil(t, c.OwnerKind)
		require.Equal(t, model.CredentialOwnerNode, *c.OwnerKind)
		require.Equal(t, *env.nodeID("zz-sc-in"), *c.OwnerNodeID)
	})

	t.Run("建立：全域主體在歸屬判定未注入時行為不變", func(t *testing.T) {
		before := env.credentialCount()
		_, err := unwired.Create(env.scCtx(global), newReq("zz-sc-new-global", nil))
		require.Error(t, err)
		require.True(t, errors.Is(err, asset.ErrCredentialOwnershipScopeUnwired), "err=%v", err)
		require.False(t, errors.Is(err, asset.ErrCredentialAuthzUnavailable), "err=%v", err)
		require.Equal(t, before, env.credentialCount())
	})
}
