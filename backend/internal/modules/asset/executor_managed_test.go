package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 執行身分只能經專用帳號端點處理：既有帳號與掛載端點一律拒絕；
// 同一筆憑證的掛載用途不得混用；預設帳號的解析與清除不碰執行身分。

// outOfScopeAccountWrite 帳號寫入範圍替身：指定資產在範圍外（與資產不存在同形）。
type outOfScopeAccountWrite struct{ out uint }

func (s outOfScopeAccountWrite) AuthorizeAccountWrite(_ context.Context, _ *gorm.DB, assetID, _ uint) error {
	if assetID == s.out {
		return ErrAssetNotFound
	}
	return nil
}

// outOfScopeCredentialAuthorizer 憑證管理判定替身：明確目標含指定資產時回資產種類的範圍拒絕。
type outOfScopeCredentialAuthorizer struct {
	*fakeCredentialAuthorizer
	out uint
}

func (a outOfScopeCredentialAuthorizer) AuthorizeCredentialManagement(ctx context.Context, db *gorm.DB,
	actor CredentialManagementActor, req CredentialManagementRequest) (CredentialManagementDecision, error) {
	for _, id := range req.AssetIDs {
		if id == a.out {
			return CredentialManagementDecision{ScopeDenial: assetOutOfScopeForTest{}}, nil
		}
	}
	return a.fakeCredentialAuthorizer.AuthorizeCredentialManagement(ctx, db, actor, req)
}

func TestExistingAccountEndpointsRejectExecutor(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	setGen := func(a *model.Asset) model.AssetAccount {
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		var m model.AssetAccount
		require.NoError(t, db.First(&m, got.AccountID).Error)
		return m
	}
	in := f.host(t, "managed-in", model.ProtocolSSH)
	out := f.host(t, "managed-out", model.ProtocolSSH)
	execIn, execOut := setGen(in), setGen(out)
	target, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "rebind-target", Username: "svc",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "svc-pw"})
	require.NoError(t, err)

	f.accounts.WithAccountWriteScope(outOfScopeAccountWrite{out: out.ID})
	f.creds.WithManagementAuthorizer(outOfScopeCredentialAuthorizer{fakeCredentialAuthorizer: f.auth, out: out.ID})

	ops := map[string]func(assetID, accountID, credentialID uint) error{
		"update": func(assetID, accountID, _ uint) error {
			note := "x"
			_, err := f.accounts.Update(ctx, assetID, accountID, &UpdateAssetAccountRequest{Note: &note})
			return err
		},
		"delete": func(assetID, accountID, _ uint) error {
			return f.accounts.Delete(ctx, assetID, accountID)
		},
		"set_default": func(assetID, accountID, _ uint) error {
			_, err := f.accounts.SetDefault(ctx, assetID, accountID)
			return err
		},
		"rebind": func(assetID, accountID, _ uint) error {
			_, err := f.creds.Rebind(ctx, assetID, accountID, target.ID)
			return err
		},
		"unbind": func(_, accountID, credentialID uint) error {
			return f.creds.Unbind(ctx, credentialID, accountID)
		},
	}
	unchanged := func(t *testing.T, want model.AssetAccount) {
		t.Helper()
		var got model.AssetAccount
		require.NoError(t, db.First(&got, want.ID).Error)
		assert.Equal(t, model.AccountPurposeExecutor, got.Purpose)
		assert.Equal(t, want.CredentialID, got.CredentialID)
		assert.Equal(t, want.Username, got.Username)
		assert.False(t, got.IsDefault)
		assert.Equal(t, want.Note, got.Note)
	}

	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			before := f.state(t)
			err := op(in.ID, execIn.ID, execIn.CredentialID)
			require.ErrorIs(t, err, ErrAssetAccountExecutorManaged)
			assert.Equal(t, before, f.state(t), "拒絕後掛載與憑證數不變")
			unchanged(t, execIn)

			// 範圍外：執行身分掛載與不存在的帳號同形（判定在範圍之後）
			outErr := op(out.ID, execOut.ID, execOut.CredentialID)
			ghostErr := op(out.ID, 999999, execOut.CredentialID)
			require.Error(t, outErr)
			require.Error(t, ghostErr)
			assert.NotErrorIs(t, outErr, ErrAssetAccountExecutorManaged)
			assert.Equal(t, ghostErr.Error(), outErr.Error(), "範圍外的執行身分與不存在同形")
			assert.Equal(t, before, f.state(t))
			unchanged(t, execOut)
		})
	}

	t.Run("default_resolution_never_selects_executor", func(t *testing.T) {
		only := newBareAsset(t, f.assets, "only-exec", "10.7.9.1")
		require.NoError(t, db.Model(&model.Asset{}).Where("id = ?", only.ID).Update("protocol", model.ProtocolSSH).Error)
		f.accounts.WithAccountWriteScope(allowAllAccountWriteScope{})
		m := setGen(only)
		// 模擬破損態：執行身分列被標成預設，預設解析與清除仍不得選到它
		require.NoError(t, db.Model(&model.AssetAccount{}).Where("id = ?", m.ID).Update("is_default", true).Error)
		got, err := resolveAssetAccount(db, only.ID, 0)
		require.NoError(t, err)
		assert.Nil(t, got, "只有執行身分的資產解析預設帳號＝零登入帳號")
		require.NoError(t, clearDefaultAccounts(db, only.ID, 0))
		var row model.AssetAccount
		require.NoError(t, db.First(&row, m.ID).Error)
		assert.True(t, row.IsDefault, "清除預設只動登入掛載")
	})
}

func TestCredentialPurposeConsistency(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	newShared := func(name, user string) *CredentialDTO {
		c, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: name, Username: user,
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw-" + user})
		require.NoError(t, err)
		return c
	}
	execCred := newShared("exec-shared", "svc-exec")
	holder := f.host(t, "exec-holder", model.ProtocolSSH)
	_, err := f.exec.Set(ctx, holder.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: execCred.ID,
		AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
	require.NoError(t, err)

	p := f.host(t, "purpose-p", model.ProtocolSSH)
	seed, err := f.accounts.List(p.ID)
	require.NoError(t, err)
	require.Len(t, seed, 1)

	type snapshot struct {
		mounts int64
		credOf uint
	}
	snap := func(t *testing.T) snapshot {
		t.Helper()
		var n int64
		require.NoError(t, db.Model(&model.AssetAccount{}).Count(&n).Error)
		var row model.AssetAccount
		require.NoError(t, db.First(&row, seed[0].ID).Error)
		return snapshot{mounts: n, credOf: row.CredentialID}
	}
	rejected := func(t *testing.T, run func() error) {
		t.Helper()
		before := snap(t)
		require.ErrorIs(t, run(), ErrCredentialPurposeMismatch)
		assert.Equal(t, before, snap(t), "拒絕後掛載數與 credential_id 不變")
	}

	t.Run("create_account_shared", func(t *testing.T) {
		rejected(t, func() error {
			_, err := f.accounts.Create(ctx, p.ID, &CreateAssetAccountRequest{CredentialID: execCred.ID})
			return err
		})
	})
	t.Run("create_asset_shared", func(t *testing.T) {
		rejected(t, func() error {
			_, err := f.assets.Create(WithSystemCaller(ctx), &CreateAssetRequest{Name: "purpose-new", Protocol: model.ProtocolSSH,
				Host: "purpose-new.internal", Port: 22, CredentialID: execCred.ID, CreatedBy: 1})
			return err
		})
	})
	t.Run("bind", func(t *testing.T) {
		rejected(t, func() error {
			_, err := f.creds.Bind(ctx, execCred.ID, &BindCredentialRequest{AssetID: p.ID})
			return err
		})
	})
	t.Run("rebind", func(t *testing.T) {
		rejected(t, func() error {
			_, err := f.creds.Rebind(ctx, p.ID, seed[0].ID, execCred.ID)
			return err
		})
	})
	t.Run("batch_same_rebind", func(t *testing.T) {
		var cred model.Credential
		require.NoError(t, db.First(&cred, execCred.ID).Error)
		rejected(t, func() error {
			return db.Transaction(func(tx *gorm.DB) error {
				var account model.AssetAccount
				if err := tx.First(&account, seed[0].ID).Error; err != nil {
					return err
				}
				return rebindBindingToCredential(tx, &account, &cred,
					&model.ChangeSecretCandidate{AccountUsername: account.Username})
			})
		})
	})
	t.Run("executor_shared_with_login_mount", func(t *testing.T) {
		loginCred := newShared("login-shared", "shared-login")
		_, err := f.creds.Bind(ctx, loginCred.ID, &BindCredentialRequest{AssetID: p.ID})
		require.NoError(t, err)
		other := f.host(t, "purpose-q", model.ProtocolSSH)
		rejected(t, func() error {
			_, err := f.exec.Set(ctx, other.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: loginCred.ID,
				AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
			return err
		})
	})
}
