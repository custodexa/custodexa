package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
)

// tagRefScopeStub 範圍化讀取器替身：view 非 nil 即視為範圍化檢視者，管理可視固定為 mgmt。
type tagRefScopeStub struct {
	view  *authz.AssetScopeView
	mgmt  []uint
	calls int
}

func (s *tagRefScopeStub) View(context.Context) (*authz.AssetScopeView, error) {
	s.calls++
	return s.view, nil
}
func (s *tagRefScopeStub) ManagementVisibleIDs(*authz.AssetScopeView) ([]uint, error) {
	return s.mgmt, nil
}
func (s *tagRefScopeStub) ManagementVisibleAsset(context.Context, uint) (bool, *authz.AssetScopeView, error) {
	return false, nil, nil
}
func (s *tagRefScopeStub) AssetViewScopeDenial(context.Context, uint) (*authz.ErrScopeDenied, error) {
	return nil, nil
}

func tagRefDTO(id uint) *authz.AuthorizedAssetDTO {
	d := &authz.AuthorizedAssetDTO{}
	d.ID = id
	return d
}

func TestAssetTagReferenceSource(t *testing.T) {
	t.Run("no_principal_non_system_rejected", func(t *testing.T) {
		scope := &tagRefScopeStub{view: &authz.AssetScopeView{}}
		ref := NewAssetTagReference(new(MockAssetAuthorizationService), scope)
		ids, scoped, err := ref.VisibleAssetIDsTx(context.Background(), nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, errTagReferenceNoPrincipal))
		assert.False(t, scoped, "沒有主體不得退回全表參照")
		assert.Nil(t, ids)
		assert.Zero(t, scope.calls, "沒有主體不應進入範圍化判定")
	})

	t.Run("non_scoped_principal_full_table", func(t *testing.T) {
		ref := NewAssetTagReference(new(MockAssetAuthorizationService), &tagRefScopeStub{})
		ctx := authz.ContextWithPrincipal(context.Background(), legacyPrincipal(model.RoleAdmin))
		ids, scoped, err := ref.VisibleAssetIDsTx(ctx, nil)
		require.NoError(t, err)
		assert.False(t, scoped)
		assert.Nil(t, ids)
	})

	t.Run("scoped_viewer_union_only", func(t *testing.T) {
		auth := new(MockAssetAuthorizationService)
		auth.On("GetAuthorizedAssets", mock.Anything, mock.Anything, model.PermissionView).
			Return([]*authz.AuthorizedAssetDTO{tagRefDTO(7), tagRefDTO(3)}, nil)
		ref := NewAssetTagReference(auth, &tagRefScopeStub{view: &authz.AssetScopeView{}, mgmt: []uint{3, 5}})
		ctx := authz.ContextWithPrincipal(context.Background(), legacyPrincipal(model.RoleUser))
		ids, scoped, err := ref.VisibleAssetIDsTx(ctx, nil)
		require.NoError(t, err)
		assert.True(t, scoped)
		assert.Equal(t, []uint{3, 5, 7}, ids, "參照集合＝連線可視 ∪ 管理可視，去重升冪")
	})
}
