package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// narrowingAuthorizer 放行一切；不帶目標的請求依 narrowing 標記「只因節點範圍來源放行」。
type narrowingAuthorizer struct{ narrowing bool }

func (a narrowingAuthorizer) AuthorizeCredentialManagement(_ context.Context, _ *gorm.DB,
	_ CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	targetless := len(req.CredentialIDs) == 0 && len(req.AssetIDs) == 0
	return CredentialManagementDecision{Allowed: true, ScopeNarrowingRequired: a.narrowing && targetless}, nil
}

// 資產表單內嵌新秘密（不帶目標的建立）只因節點範圍來源放行時，收斂由資產寫入的範圍判定承擔：
// 該判定未注入即拒絕，不以未收斂的口徑放行。
func TestCreateCredentialCapsScopeNarrowingRequiresWriteScope(t *testing.T) {
	ctx := adminCtx()
	gate := func(narrowing bool) credentialManagementGate {
		return credentialManagementGate{authorizer: narrowingAuthorizer{narrowing: narrowing}}
	}

	t.Run("須收斂且寫入範圍判定未注入：拒絕", func(t *testing.T) {
		err := requireCreateCredentialCaps(gate(true), ctx, nil, nil, 0, true, false, false)
		require.ErrorIs(t, err, ErrAssetWriteScopePortMissing)
	})
	t.Run("須收斂且已注入：放行", func(t *testing.T) {
		require.NoError(t, requireCreateCredentialCaps(gate(true), ctx, nil, nil, 0, true, false, true))
	})
	t.Run("不須收斂（全域來源放行）且未注入：放行", func(t *testing.T) {
		require.NoError(t, requireCreateCredentialCaps(gate(false), ctx, nil, nil, 0, true, false, false))
	})
	t.Run("帶目標資產的內嵌秘密不標記須收斂：未注入仍放行", func(t *testing.T) {
		require.NoError(t, requireCreateCredentialCaps(gate(true), ctx, nil, nil, 42, true, false, false))
	})
	t.Run("只掛既有憑證不新建秘密：不受影響", func(t *testing.T) {
		require.NoError(t, requireCreateCredentialCaps(gate(true), ctx, nil, []uint{7}, 0, false, false, false))
	})
	t.Run("系統呼叫者豁免", func(t *testing.T) {
		require.NoError(t, requireCreateCredentialCaps(gate(true), WithSystemCaller(context.Background()), nil, nil, 0, true, false, false))
	})

	t.Run("資產建立在載入與加密之前即拒絕", func(t *testing.T) {
		setupCredentialDB(t)
		assets, _, _ := newCredentialServices(t)
		assets.WithManagementAuthorizer(narrowingAuthorizer{narrowing: true})
		assets.SetAssetWriteScopePort(nil)
		ctx := WithFieldCapability(adminCtx(), func(string) FieldCapGrant { return FieldCapViaCompat })
		// 協定值域外：若關卡沒有先拒絕，會先得到協定驗證錯誤
		_, err := assets.Create(ctx, &CreateAssetRequest{Name: "narrowing-inline", Protocol: "zz-not-a-protocol",
			Host: "10.42.0.1", Port: 22, Password: "inline-pw", CreatedBy: 1})
		require.ErrorIs(t, err, ErrAssetWriteScopePortMissing)

		assets.WithManagementAuthorizer(narrowingAuthorizer{narrowing: false})
		_, err = assets.Create(ctx, &CreateAssetRequest{Name: "narrowing-inline", Protocol: "zz-not-a-protocol",
			Host: "10.42.0.1", Port: 22, Password: "inline-pw", CreatedBy: 1})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrAssetWriteScopePortMissing, "不須收斂時不由此關卡拒絕")
	})
}
