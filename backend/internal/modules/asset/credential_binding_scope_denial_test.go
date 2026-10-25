package asset

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeScopeDenied struct{ kind string }

func (f fakeScopeDenied) Error() string                 { return "scope denied" }
func (f fakeScopeDenied) ScopeDeniedTargetKind() string { return f.kind }

// 卸載與脫離只把「資產層」的範圍拒絕改成掛載不存在；其餘錯誤原樣回傳。
func TestAssetScopeDenialAsBindingNotFound(t *testing.T) {
	require.ErrorIs(t, assetScopeDenialAsBindingNotFound(fakeScopeDenied{kind: "asset"}), ErrCredentialBindingNotFound)
	require.ErrorIs(t, assetScopeDenialAsBindingNotFound(fmt.Errorf("wrap: %w", fakeScopeDenied{kind: "asset"})),
		ErrCredentialBindingNotFound)

	credDenied := fakeScopeDenied{kind: "credential"}
	require.Equal(t, error(credDenied), assetScopeDenialAsBindingNotFound(credDenied), "憑證層拒絕不改寫")

	for _, e := range []error{ErrCredentialBindForbidden, ErrCredentialAuthzUnavailable, errors.New("db down")} {
		require.Equal(t, e, assetScopeDenialAsBindingNotFound(e), "非範圍拒絕不改寫")
	}
	require.NoError(t, assetScopeDenialAsBindingNotFound(nil))
}
