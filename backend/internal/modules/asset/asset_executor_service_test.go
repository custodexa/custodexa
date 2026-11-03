package asset

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/crypto"
)

// 執行身分服務：四種來源的設定、更換與清除，以及各種拒絕都不留下半套狀態。

type allowAllExecutorScope struct{}

func (allowAllExecutorScope) AuthorizeExecutorManage(context.Context, *gorm.DB, uint) error {
	return nil
}

type executorFixture struct {
	db       *gorm.DB
	assets   *AssetService
	accounts *AssetAccountService
	creds    *CredentialService
	exec     *AssetExecutorService
	auth     *fakeCredentialAuthorizer
	codec    crypto.ColumnCodec
}

func newExecutorFixture(t *testing.T, db *gorm.DB) *executorFixture {
	t.Helper()
	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	auth := newAllowAllAuthorizer()
	assets.WithManagementAuthorizer(auth).WithSystemAlertSink(newFakeAlertSink())
	accounts := NewAssetAccountService(assets, codec, audit.NewTxSink()).
		WithManagementAuthorizer(auth).WithSystemAlertSink(newFakeAlertSink()).WithAccountWriteScope(allowAllAccountWriteScope{})
	creds := NewCredentialService(assets, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(auth).WithSystemAlertSink(newFakeAlertSink())
	return &executorFixture{db: db, assets: assets, accounts: accounts, creds: creds,
		exec: NewAssetExecutorService(accounts, allowAllExecutorScope{}), auth: auth, codec: codec}
}

func (f *executorFixture) host(t *testing.T, name string, protocol model.ProtocolType) *model.Asset {
	t.Helper()
	port := 22
	if protocol == model.ProtocolRDP {
		port = 3389
	}
	a, err := f.assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: name, Protocol: protocol, Host: name + ".internal", Port: port,
		Username: "seed", Password: "seed-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	return a
}

// state 掛載與憑證的未刪除列數（拒絕後須與拒絕前相同）。
func (f *executorFixture) state(t *testing.T) [2]int64 {
	t.Helper()
	var mounts, creds int64
	require.NoError(t, f.db.Model(&model.AssetAccount{}).Count(&mounts).Error)
	require.NoError(t, f.db.Model(&model.Credential{}).Count(&creds).Error)
	return [2]int64{mounts, creds}
}

func uptr(v uint) *uint { return &v }
func iptr(v int) *int   { return &v }

// executorTestKey 測試當下產生的私鑰（不落任何檔案）。
func executorTestKey(t *testing.T) string {
	t.Helper()
	private, _, err := GenerateSSHKeyPair("test")
	require.NoError(t, err)
	return private
}

// assertNoKeyMaterial 回應 JSON 不含私鑰與公鑰本體。
func assertNoKeyMaterial(t *testing.T, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "-----BEGIN")
	assert.NotContains(t, string(raw), "ssh-ed25519 ")
}

func TestAssetExecutorServiceSources(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	t.Run("generate", func(t *testing.T) {
		a := f.host(t, "gen-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.True(t, got.Configured)
		assert.Equal(t, model.ChangeSecretTypeSSHKey, got.SecretType)
		assertNoKeyMaterial(t, got)
		var m model.AssetAccount
		require.NoError(t, db.First(&m, got.AccountID).Error)
		assert.Equal(t, model.AccountPurposeExecutor, m.Purpose)
		assert.False(t, m.IsDefault)
		assert.True(t, m.Privileged)
		var v model.CredentialSecretVersion
		require.NoError(t, db.First(&v, *m.EffectiveVersionID).Error)
		assert.Equal(t, model.CredentialVersionReasonGenerated, v.CreatedReason)
		assert.True(t, strings.HasPrefix(v.PublicKey, "ssh-ed25519 "))
		read, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		assertNoKeyMaterial(t, read)
	})

	t.Run("inline", func(t *testing.T) {
		a := f.host(t, "inline-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec", Password: "exec-pw", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, model.ChangeSecretTypePassword, got.SecretType)
		assertNoKeyMaterial(t, got)
	})

	t.Run("shared", func(t *testing.T) {
		a := f.host(t, "shared-1", model.ProtocolSSH)
		cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "exec-shared", Username: "svc-exec",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "svc-pw"})
		require.NoError(t, err)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, "svc-exec", got.Username)
	})

	t.Run("convert", func(t *testing.T) {
		a := f.host(t, "convert-1", model.ProtocolSSH)
		ops, err := f.accounts.Create(WithSystemCaller(ctx), a.ID, &CreateAssetAccountRequest{Username: "ops", Password: "ops-pw"})
		require.NoError(t, err)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceConvert, AccountID: ops.ID, ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		assert.Equal(t, ops.ID, got.AccountID)
		list, err := f.accounts.List(a.ID)
		require.NoError(t, err)
		require.Len(t, list, 1, "轉換後帳號列表不再列出它")
	})

	t.Run("replace_reclaims_old_dedicated_credential", func(t *testing.T) {
		a := f.host(t, "replace-1", model.ProtocolSSH)
		first, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		var old model.AssetAccount
		require.NoError(t, db.First(&old, first.AccountID).Error)
		cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "replace-shared", Username: "svc-replace",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "svc-pw"})
		require.NoError(t, err)
		second, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(first.AccountID)})
		require.NoError(t, err)
		assert.NotEqual(t, first.AccountID, second.AccountID)
		var n int64
		require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", old.CredentialID).Count(&n).Error)
		assert.Zero(t, n, "更換後舊專用憑證不存在")
		replace := findAccountAudit(t, db, a.ID, model.AccountOpExecutorReplace)
		assert.Equal(t, second.AccountID, replace.AccountID)
		assert.Equal(t, cred.ID, replace.CredentialID)
		assert.Equal(t, ExecutorSourceShared, replace.Source)
		assert.Equal(t, 1, replace.HostCount)
		assert.Equal(t, first.AccountID, replace.PreviousAccountID)
		assert.Equal(t, old.CredentialID, replace.PreviousCredentialID)
	})

	t.Run("replace_with_same_shared_credential", func(t *testing.T) {
		a := f.host(t, "replace-same-1", model.ProtocolSSH)
		cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "same-shared", Username: "svc-same",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "svc-pw"})
		require.NoError(t, err)
		first, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		// 舊掛載引用同一筆憑證：台數不加一，重複掛載與同名檢查排除即將移除的舊掛載
		second, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(first.AccountID)})
		require.NoError(t, err)
		assert.Equal(t, "svc-same", second.Username)
	})

	t.Run("username_taken_reported_before_host_count", func(t *testing.T) {
		a := f.host(t, "order-1", model.ProtocolSSH)
		cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "order-shared", Username: "seed",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "svc-pw"})
		require.NoError(t, err)
		_, err = f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: cred.ID,
			ExpectedAccountID: uptr(0)})
		require.ErrorIs(t, err, ErrAssetAccountUsernameExists, "帳號名已佔用先於台數確認回報")
	})

	t.Run("clear", func(t *testing.T) {
		a := f.host(t, "clear-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		require.NoError(t, f.exec.Clear(ctx, a.ID, uptr(got.AccountID)))
		read, err := f.exec.Get(ctx, a.ID)
		require.NoError(t, err)
		assert.False(t, read.Configured)
		assertNoKeyMaterial(t, read)
	})

	// expected_account_id 與 PUT 同語義：缺漏不比對、0＝認定目前沒有、其餘須與當下相符
	t.Run("clear_expected_account_semantics", func(t *testing.T) {
		a := f.host(t, "clear-exp-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		before := f.state(t)
		require.ErrorIs(t, f.exec.Clear(ctx, a.ID, uptr(0)), ErrExecutorStateChanged, "帶 0 但已有專用帳號")
		require.ErrorIs(t, f.exec.Clear(ctx, a.ID, uptr(got.AccountID+1000)), ErrExecutorStateChanged)
		assert.Equal(t, before, f.state(t))
		require.NoError(t, f.exec.Clear(ctx, a.ID, nil), "缺漏＝不比對")
		require.ErrorIs(t, f.exec.Clear(ctx, a.ID, nil), ErrAssetExecutorNotFound)
		require.ErrorIs(t, f.exec.Clear(ctx, a.ID, uptr(0)), ErrAssetExecutorNotFound)
		require.ErrorIs(t, f.exec.Clear(ctx, a.ID, uptr(got.AccountID)), ErrExecutorStateChanged, "認定的專用帳號已不在")
	})
}

func TestAssetExecutorServiceRejections(t *testing.T) {
	db := setupCredentialDB(t)
	f := newExecutorFixture(t, db)
	ctx := adminCtx()

	rejected := func(t *testing.T, want error, run func() error) {
		t.Helper()
		before := f.state(t)
		err := run()
		require.ErrorIs(t, err, want)
		assert.Equal(t, before, f.state(t), "拒絕後掛載與憑證數不變")
	}
	rejectedAny := func(t *testing.T, run func() error) {
		t.Helper()
		before := f.state(t)
		require.Error(t, run())
		assert.Equal(t, before, f.state(t), "拒絕後掛載與憑證數不變")
	}
	gen := func(id uint, user string) error {
		_, err := f.exec.Set(ctx, id, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: user, ExpectedAccountID: uptr(0)})
		return err
	}

	t.Run("protocol_unsupported", func(t *testing.T) {
		a := newBareAsset(t, f.assets, "vnc-1", "10.7.0.1")
		rejected(t, ErrExecutorProtocolUnsupported, func() error { return gen(a.ID, "cx-exec") })
	})
	rdp := f.host(t, "rdp-1", model.ProtocolRDP)
	t.Run("rdp_generate", func(t *testing.T) {
		rejected(t, ErrExecutorSecretTypeUnsupported, func() error { return gen(rdp.ID, "cx-exec") })
	})
	t.Run("rdp_inline_private_key", func(t *testing.T) {
		rejected(t, ErrExecutorSecretTypeUnsupported, func() error {
			_, err := f.exec.Set(ctx, rdp.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec",
				PrivateKey: executorTestKey(t), ExpectedAccountID: uptr(0)})
			return err
		})
	})
	t.Run("rdp_inline_password_ok", func(t *testing.T) {
		_, err := f.exec.Set(ctx, rdp.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec",
			Password: "exec-pw", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
	})

	conv := f.host(t, "conv-1", model.ProtocolSSH)
	seed, err := f.accounts.List(conv.ID)
	require.NoError(t, err)
	convert := func(accountID uint) error {
		_, err := f.exec.Set(ctx, conv.ID, &SetExecutorRequest{Source: ExecutorSourceConvert, AccountID: accountID, ExpectedAccountID: uptr(0)})
		return err
	}
	t.Run("convert_default", func(t *testing.T) {
		rejected(t, ErrAssetAccountDefaultRequired, func() error { return convert(seed[0].ID) })
	})
	t.Run("convert_shared_mount", func(t *testing.T) {
		cred, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "login-shared", Username: "shared-login",
			ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
		require.NoError(t, err)
		b, err := f.creds.Bind(ctx, cred.ID, &BindCredentialRequest{AssetID: conv.ID})
		require.NoError(t, err)
		rejected(t, ErrCredentialPurposeMismatch, func() error { return convert(b.ID) })
	})
	t.Run("convert_pending_candidate", func(t *testing.T) {
		acc, err := f.accounts.Create(WithSystemCaller(ctx), conv.ID, &CreateAssetAccountRequest{Username: "cand", Password: "pw"})
		require.NoError(t, err)
		require.NoError(t, db.Create(&model.ChangeSecretCandidate{AccountID: acc.ID, AssetID: conv.ID, SecretType: model.ChangeSecretTypePassword}).Error)
		rejected(t, ErrExecutorConvertCandidatePending, func() error { return convert(acc.ID) })
	})
	t.Run("convert_rotation_active", func(t *testing.T) {
		acc, err := f.accounts.Create(WithSystemCaller(ctx), conv.ID, &CreateAssetAccountRequest{Username: "rot", Password: "pw"})
		require.NoError(t, err)
		require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", acc.CredentialID).Update("active_rotation_id", 99).Error)
		rejected(t, ErrCredentialRotationActive, func() error { return convert(acc.ID) })
	})
	t.Run("username_taken", func(t *testing.T) {
		rejected(t, ErrAssetAccountUsernameExists, func() error { return gen(conv.ID, "seed") })
	})

	capHost := f.host(t, "caps-1", model.ProtocolSSH)
	shared, err := f.creds.Create(ctx, &CreateCredentialRequest{Name: "caps-shared", Username: "caps-exec",
		ProtocolFamily: model.ProtocolFamilySSH, Password: "pw"})
	require.NoError(t, err)
	capsOps, err := f.accounts.Create(WithSystemCaller(ctx), capHost.ID, &CreateAssetAccountRequest{Username: "caps-ops", Password: "pw"})
	require.NoError(t, err)
	denied := func(t *testing.T, capability string, run func() error) {
		f.auth.mu.Lock()
		f.auth.denied[capability] = true
		f.auth.mu.Unlock()
		defer func() {
			f.auth.mu.Lock()
			delete(f.auth.denied, capability)
			f.auth.mu.Unlock()
		}()
		rejectedAny(t, run)
	}
	t.Run("missing_credential_create", func(t *testing.T) {
		denied(t, CredCapCreate, func() error { return gen(capHost.ID, "cx-exec") })
	})
	t.Run("only_compat_credential_manage", func(t *testing.T) {
		// 只持相容鍵的主體在語義鍵判定下缺 credential:create（判定器回缺能力）
		denied(t, CredCapCreate, func() error {
			_, err := f.exec.Set(ctx, capHost.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: "cx-exec", Password: "pw", ExpectedAccountID: uptr(0)})
			return err
		})
	})
	t.Run("missing_credential_bind", func(t *testing.T) {
		denied(t, CredCapBind, func() error {
			_, err := f.exec.Set(ctx, capHost.ID, &SetExecutorRequest{Source: ExecutorSourceShared, CredentialID: shared.ID,
				AcknowledgedHostCount: iptr(1), ExpectedAccountID: uptr(0)})
			return err
		})
	})
	t.Run("missing_credential_update", func(t *testing.T) {
		denied(t, CredCapUpdate, func() error {
			_, err := f.exec.Set(ctx, capHost.ID, &SetExecutorRequest{Source: ExecutorSourceConvert, AccountID: capsOps.ID, ExpectedAccountID: uptr(0)})
			return err
		})
	})

	t.Run("expected_account_mismatch", func(t *testing.T) {
		a := f.host(t, "expect-1", model.ProtocolSSH)
		require.NoError(t, gen(a.ID, "cx-exec"))
		rejected(t, ErrExecutorStateChanged, func() error { return gen(a.ID, "cx-exec-2") })
	})
	t.Run("clear_rotation_active", func(t *testing.T) {
		a := f.host(t, "clear-rot-1", model.ProtocolSSH)
		got, err := f.exec.Set(ctx, a.ID, &SetExecutorRequest{Source: ExecutorSourceGenerate, Username: "cx-exec", ExpectedAccountID: uptr(0)})
		require.NoError(t, err)
		var m model.AssetAccount
		require.NoError(t, db.First(&m, got.AccountID).Error)
		require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", m.CredentialID).Update("active_rotation_id", 99).Error)
		rejected(t, ErrCredentialRotationActive, func() error { return f.exec.Clear(ctx, a.ID, uptr(got.AccountID)) })
	})
}

// 兩筆設定同時進交易、都認定「目前沒有執行身分」：恰一筆成功，另一筆回狀態已變，不互相覆蓋。
func TestAssetExecutorConcurrentSetPG(t *testing.T) {
	db := openPGTopologyDB(t)
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	f := newExecutorFixture(t, db)
	a := f.host(t, "race-1", model.ProtocolSSH)

	var barrier sync.WaitGroup
	barrier.Add(2)
	f.exec.setTxHook = func() {
		barrier.Done()
		barrier.Wait()
	}
	type outcome struct {
		user string
		dto  *AssetExecutorDTO
		err  error
	}
	results := make(chan outcome, 2)
	for _, user := range []string{"cx-a", "cx-b"} {
		go func(user string) {
			dto, err := f.exec.Set(adminCtx(), a.ID, &SetExecutorRequest{Source: ExecutorSourceInline, Username: user,
				Password: "pw-" + user, ExpectedAccountID: uptr(0)})
			results <- outcome{user, dto, err}
		}(user)
	}
	var winner outcome
	var changed int
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil {
			winner = r
			continue
		}
		require.ErrorIs(t, r.err, ErrExecutorStateChanged)
		changed++
	}
	require.Equal(t, 1, changed, "恰一筆回狀態已變")
	require.NotNil(t, winner.dto, "恰一筆成功")
	f.exec.setTxHook = nil
	got, err := f.exec.Get(adminCtx(), a.ID)
	require.NoError(t, err)
	assert.Equal(t, winner.dto.AccountID, got.AccountID)
	assert.Equal(t, winner.user, got.Username, "最終執行身分為成功那一筆")
	var execs int64
	require.NoError(t, db.Model(&model.AssetAccount{}).Where("asset_id = ? AND purpose = ?", a.ID, model.AccountPurposeExecutor).Count(&execs).Error)
	assert.EqualValues(t, 1, execs)
	t.Logf("EVIDENCE dialect=%s winner=%s", db.Dialector.Name(), winner.user)
}
