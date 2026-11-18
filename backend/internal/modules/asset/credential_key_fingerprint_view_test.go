package asset

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 公鑰指紋的檢視判定（服務層）：與憑證讀取同一個能力判定，判定器說不可檢視就不給。

// allowCapFor 解除 denyFor 對指定主體設下的能力拒絕。
func (f *fakeCredentialAuthorizer) allowCapFor(user uint, caps ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range caps {
		delete(f.actorDenied[user], c)
	}
}

func TestViewableCredentialIDsFollowsViewCapability(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()
	const admin = uint(1)

	got := f.accounts.ViewableCredentialIDs(ctx, []uint{7, 9, 7, 0})
	assert.Equal(t, map[uint]bool{7: true, 9: true}, got, "可檢視：去重、略過 0")
	assert.Equal(t, got, f.creds.ViewableCredentialIDs(ctx, []uint{7, 9}), "帳號與憑證服務同一個判定")
	assert.Equal(t, got, f.exec.ViewableCredentialIDs(ctx, []uint{7, 9}), "執行身分服務同一個判定")

	f.auth.denyFor(admin, CredCapView)
	assert.Equal(t, map[uint]bool{7: false, 9: false}, f.accounts.ViewableCredentialIDs(ctx, []uint{7, 9}),
		"有管理能力而沒有檢視能力：一律不可檢視")
	assert.Empty(t, f.accounts.ViewableCredentialIDs(ctx, nil))

	f.auth.allowCapFor(admin, CredCapView)
	f.auth.failFor(admin, errors.New("zz judge unavailable"))
	assert.Equal(t, map[uint]bool{7: false}, f.accounts.ViewableCredentialIDs(ctx, []uint{7}), "判定失敗不給（fail closed）")

	none := NewAssetAccountService(f.assets, f.codec, nil)
	assert.Equal(t, map[uint]bool{7: false}, none.ViewableCredentialIDs(ctx, []uint{7}), "判定器未注入不給")
}

// 堡壘機專用帳號引用共用憑證：落在憑證可見集合內，但主體對該憑證沒有檢視能力時，
// 頂層不帶指紋、也不能匯出公鑰。
func TestExecutorSharedKeyNeedsCredentialViewCapability(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	vis := &fakeExecutorVisibility{visible: map[uint]bool{}}
	f.exec.WithCredentialVisibility(vis)
	ctx := adminCtx()
	const admin = uint(1)

	cred := f.sharedKeyCredential(t, "fp-view-shared", "svc-view")
	a := f.host(t, "fp-view-host", model.ProtocolSSH)
	_, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
		AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
	require.NoError(t, err)
	vis.visible[cred.ID] = true

	// 對照：可見且可檢視時兩者都給（證明下面的不給是檢視判定造成的）
	read, err := f.exec.Get(ctx, a.ID)
	require.NoError(t, err)
	require.NotEmpty(t, read.Fingerprint, "PRECONDITION: 可見且可檢視時帶指紋")
	_, err = f.exec.ExportPublicKey(ctx, a.ID)
	require.NoError(t, err, "PRECONDITION: 可見且可檢視時可匯出")

	f.auth.denyFor(admin, CredCapView)
	read, err = f.exec.Get(ctx, a.ID)
	require.NoError(t, err)
	keys := jsonKeys(t, read)
	assert.False(t, keys["fingerprint"], "沒有檢視能力不帶指紋")
	assert.False(t, keys["has_public_key"], "沒有檢視能力不帶 has_public_key")
	_, err = f.exec.ExportPublicKey(ctx, a.ID)
	assert.True(t, errors.Is(err, ErrAssetExecutorPublicKeyNotFound), "沒有檢視能力不能匯出：%v", err)
}
