package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// credentialAuthzFixture 一組共用憑證掛兩台資產，並提供可逐能力拒絕的判定樁。
type credentialAuthzFixture struct {
	creds  *CredentialService
	auth   *fakeCredentialAuthorizer
	shared *CredentialDTO
	hosts  []*model.Asset
}

func newCredentialAuthzFixture(t *testing.T) *credentialAuthzFixture {
	t.Helper()
	setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	auth := newAllowAllAuthorizer()
	creds = creds.WithManagementAuthorizer(auth)
	shared := newSharedCredential(t, creds, "authz-shared", "ops", "pw")
	var hosts []*model.Asset
	for i, name := range []string{"authz-a", "authz-b"} {
		a := newSSHAsset(t, assets, name, "10.40.0."+string(rune('1'+i)))
		list, err := accounts.List(a.ID)
		require.NoError(t, err)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, err)
		hosts = append(hosts, a)
	}
	auth.reset()
	return &credentialAuthzFixture{creds: creds, auth: auth, shared: shared, hosts: hosts}
}

// 管理授權以語義能力判定，與資產 connect 無關：六類操作各有具權成功與缺權拒絕；
// 判定器缺席、解析錯誤、空主體一律拒絕；零掛載仍要驗；管理成功不新增連線授權。
func TestCredentialManagementAuthorization(t *testing.T) {
	t.Run("六類操作缺權拒絕且不留下任何寫入", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		versionsBefore := credentialVersionIDs(t, database.DB, f.shared.ID)
		newName := "renamed"
		cases := []struct {
			name string
			cap  string
			do   func() error
		}{
			{"中繼資料", CredCapUpdate, func() error {
				_, err := f.creds.Update(adminCtx(), f.shared.ID, &UpdateCredentialRequest{Name: &newName})
				return err
			}},
			{"SetSecret", CredCapSetSecret, func() error {
				_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "new-pw"})
				return err
			}},
			{"範圍轉換", CredCapConvertScope, func() error {
				_, err := f.creds.ConvertScope(adminCtx(), f.shared.ID, &ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
				return err
			}},
			{"刪除", CredCapDelete, func() error { return f.creds.Delete(adminCtx(), f.shared.ID) }},
			{"建立", CredCapCreate, func() error {
				_, err := f.creds.Create(adminCtx(), &CreateCredentialRequest{Name: "x", Username: "u", SecretType: "password", Password: "p"})
				return err
			}},
			{"讀取", CredCapView, func() error { _, err := f.creds.Get(adminCtx(), f.shared.ID); return err }},
			{"掛載", CredCapBind, func() error {
				_, err := f.creds.Bind(adminCtx(), f.shared.ID, &BindCredentialRequest{AssetID: f.hosts[0].ID})
				return err
			}},
		}
		for _, c := range cases {
			f.auth.deny(c.cap)
			err := c.do()
			assert.ErrorIs(t, err, ErrCredentialBindForbidden, "%s 缺 %s 必須拒絕", c.name, c.cap)
			f.auth.allow(c.cap)
		}
		assert.Equal(t, versionsBefore, credentialVersionIDs(t, database.DB, f.shared.ID), "被拒的操作不得追加版本")
		var cred model.Credential
		require.NoError(t, database.DB.First(&cred, f.shared.ID).Error)
		assert.Equal(t, model.CredentialScopeShared, cred.Scope, "被拒的轉換不得改變範圍")
		assert.Equal(t, f.shared.Name, *cred.Name, "被拒的更新不得改名")
	})

	t.Run("具權成功且影響集合涵蓋全部掛載", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "new-pw"})
		require.NoError(t, err)
		assert.ElementsMatch(t, []uint{f.hosts[0].ID, f.hosts[1].ID}, f.auth.askedImpactAssetIDs(),
			"整組宣告的影響集合是全部掛載資產")
		last := f.auth.asked[len(f.auth.asked)-1]
		assert.Equal(t, []string{CredCapSetSecret}, last.Capabilities)
		assert.Equal(t, CredOpSetSecret, last.Operation)
	})

	t.Run("只有管理能力沒有連線授權仍可管理，連線授權不構成管理", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		// 判定樁從不查詢資產連線授權：有管理能力即成功，且不產生任何連線授權列
		_, err := f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "pw2"})
		require.NoError(t, err)
		require.NoError(t, database.DB.AutoMigrate(&model.AssetAuthorization{}))
		var grants int64
		require.NoError(t, database.DB.Model(&model.AssetAuthorization{}).Count(&grants).Error)
		assert.EqualValues(t, 0, grants, "管理成功不新增連線授權")
		// 反向：缺管理能力時，不論主體有無連線授權都拒絕（判定只認能力）
		f.auth.deny(CredCapSetSecret)
		_, err = f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "pw3"})
		assert.ErrorIs(t, err, ErrCredentialBindForbidden)
	})

	t.Run("判定器缺席、解析錯誤、空主體一律拒絕", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		bare := f.creds.WithManagementAuthorizer(nil)
		_, err := bare.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "x"})
		assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "未注入是配置錯誤，不是放行")
		f.creds.WithManagementAuthorizer(f.auth)

		f.auth.err = errors.New("resolver down")
		_, err = f.creds.SetSecret(adminCtx(), f.shared.ID, &SetCredentialSecretRequest{Password: "x"})
		assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "解析失敗 fail closed")
		f.auth.err = nil

		_, err = f.creds.SetSecret(context.Background(), f.shared.ID, &SetCredentialSecretRequest{Password: "x"})
		assert.ErrorIs(t, err, ErrCredentialBindForbidden, "空主體拒絕")
	})

	t.Run("零掛載仍驗憑證本體的能力", func(t *testing.T) {
		setupCredentialDB(t)
		_, _, creds := newCredentialServices(t)
		auth := newAllowAllAuthorizer()
		creds = creds.WithManagementAuthorizer(auth)
		lone := newSharedCredential(t, creds, "lone", "ops", "pw")
		auth.deny(CredCapDelete)
		assert.ErrorIs(t, creds.Delete(adminCtx(), lone.ID), ErrCredentialBindForbidden, "零掛載不能空迴圈放行")
		auth.allow(CredCapDelete)
		require.NoError(t, creds.Delete(adminCtx(), lone.ID))
	})

	t.Run("專用憑證改帳號名另驗帳號編輯能力", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		_, err := f.creds.ConvertScope(adminCtx(), f.shared.ID, &ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
		require.ErrorIs(t, err, ErrCredentialToDedicatedMultiBinding, "兩台共用不可轉專用，改以 Unbind 一台後轉換")
		list, lerr := f.creds.Get(adminCtx(), f.shared.ID)
		require.NoError(t, lerr)
		require.NoError(t, f.creds.Unbind(adminCtx(), f.shared.ID, list.Bindings[1].AccountID))
		_, err = f.creds.ConvertScope(adminCtx(), f.shared.ID, &ConvertCredentialScopeRequest{Scope: model.CredentialScopeDedicated})
		require.NoError(t, err)
		name := "ops2"
		f.auth.deny(CredCapAccountEdit)
		_, err = f.creds.Update(adminCtx(), f.shared.ID, &UpdateCredentialRequest{Username: &name})
		assert.ErrorIs(t, err, ErrCredentialBindForbidden, "有 credential:update 但缺帳號編輯能力")
		f.auth.allow(CredCapAccountEdit)
		_, err = f.creds.Update(adminCtx(), f.shared.ID, &UpdateCredentialRequest{Username: &name})
		require.NoError(t, err)
	})

	t.Run("中繼資料修改不夾帶 SetSecret", func(t *testing.T) {
		f := newCredentialAuthzFixture(t)
		before := credentialVersionIDs(t, database.DB, f.shared.ID)
		f.auth.deny(CredCapSetSecret)
		note := "只改備註"
		_, err := f.creds.Update(adminCtx(), f.shared.ID, &UpdateCredentialRequest{Note: &note})
		require.NoError(t, err, "只有 update 能力即可改中繼資料")
		assert.Equal(t, before, credentialVersionIDs(t, database.DB, f.shared.ID), "中繼資料修改不追加秘密版本")
		for _, r := range f.auth.asked {
			assert.NotContains(t, r.Capabilities, CredCapSetSecret, "中繼資料請求不得要求或夾帶 SetSecret")
		}
	})

	t.Run("資產與帳號表單內嵌宣告秘密與 SetSecret 同一道關卡", func(t *testing.T) {
		setupCredentialDB(t)
		assets, accounts, _ := newCredentialServices(t)
		auth := newAllowAllAuthorizer()
		assets.WithManagementAuthorizer(auth)
		accounts.WithManagementAuthorizer(auth)
		a := newSSHAsset(t, assets, "inline-a", "10.41.0.1")
		list, err := accounts.List(a.ID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		var acc model.AssetAccount
		require.NoError(t, database.DB.First(&acc, list[0].ID).Error)
		before := credentialVersionIDs(t, database.DB, acc.CredentialID)

		auth.deny(CredCapSetSecret)
		pw, note := "declared-pw", "備註"
		_, err = accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw})
		assert.ErrorIs(t, err, ErrCredentialBindForbidden, "帳號表單帶密碼缺 set-secret 拒絕")
		_, err = assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Password: &pw})
		assert.ErrorIs(t, err, ErrCredentialBindForbidden, "資產表單帶密碼缺 set-secret 拒絕")
		assert.Equal(t, before, credentialVersionIDs(t, database.DB, acc.CredentialID), "被拒絕時零寫入")
		_, err = accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Note: &note})
		require.NoError(t, err, "不帶秘密的帳號編輯不需要 set-secret")

		auth.allow(CredCapSetSecret)
		_, err = accounts.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw})
		require.NoError(t, err)
		assert.Len(t, credentialVersionIDs(t, database.DB, acc.CredentialID), len(before)+1)

		bare := NewAssetAccountService(assets, accounts.crypto, accounts.auditTx).WithAccountWriteScope(allowAllAccountWriteScope{})
		pw2 := "declared-pw-2"
		_, err = bare.Update(adminCtx(), a.ID, acc.ID, &UpdateAssetAccountRequest{Password: &pw2})
		assert.ErrorIs(t, err, ErrCredentialAuthzUnavailable, "帳號服務未注入判定器是配置錯誤，不是放行")
	})

	t.Run("批次建立逐項驗複合能力且缺任一整批零寫入", func(t *testing.T) {
		f := setupBatchFixture(t)
		auth := newAllowAllAuthorizer()
		f.batches.WithManagementAuthorizer(auth)
		_, accA := f.addHost(t, "batch-a", "10.42.0.1", "root")
		_, accB := f.addHost(t, "batch-b", "10.42.0.2", "root")
		var batchesBefore, credsBefore int64
		require.NoError(t, f.db.Model(&model.ChangeSecretBatch{}).Count(&batchesBefore).Error)
		require.NoError(t, f.db.Model(&model.Credential{}).Count(&credsBefore).Error)

		for _, missing := range []string{CredCapAccountRotate, CredCapCreate, CredCapBind} {
			auth.deny(missing)
			_, _, err := f.batches.Create(sharedBatchRequest("root", "shared-batch", accA, accB), 1, "admin")
			assert.ErrorIs(t, err, ErrCredentialBindForbidden, "整批同一組缺 %s 拒絕", missing)
			auth.allow(missing)
		}
		var batchesAfter, credsAfter int64
		require.NoError(t, f.db.Model(&model.ChangeSecretBatch{}).Count(&batchesAfter).Error)
		require.NoError(t, f.db.Model(&model.Credential{}).Count(&credsAfter).Error)
		assert.Equal(t, batchesBefore, batchesAfter, "被拒絕不建立批次列")
		assert.Equal(t, credsBefore, credsAfter, "被拒絕不建立共用憑證")

		auth.reset()
		batch, ids, err := f.batches.Create(sharedBatchRequest("root", "shared-batch", accA, accB), 1, "admin")
		require.NoError(t, err)
		assert.Len(t, ids, 2)
		assert.NotZero(t, batch.ID)
		last := auth.asked[len(auth.asked)-1]
		assert.ElementsMatch(t, []string{CredCapAccountRotate, CredCapCreate, CredCapBind}, last.Capabilities)
		assert.ElementsMatch(t, ids, last.AssetIDs, "影響集合是全部選定資產")

		_, _, err = f.batches.Create(batchRequest("root", model.BatchPasswordPerTarget, false, accA), 0, "")
		assert.ErrorIs(t, err, ErrCredentialBindForbidden, "空發起者拒絕")
	})

	t.Run("每台各自隨機遇共用憑證成員須 detach 與 rotate", func(t *testing.T) {
		f := setupBatchFixture(t)
		auth := newAllowAllAuthorizer()
		f.batches.WithManagementAuthorizer(auth)
		_, members := f.sharedOn(t, "perhost-shared", "ops", "pw", "10.43.0.1", "10.43.0.2")
		for _, missing := range []string{CredCapDetach, CredCapRotate} {
			auth.deny(missing)
			_, _, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, members...), 1, "admin")
			assert.ErrorIs(t, err, ErrCredentialBindForbidden, "共用成員缺 %s 拒絕", missing)
			auth.allow(missing)
		}
		_, _, err := f.batches.Create(batchRequest("ops", model.BatchPasswordPerTarget, false, members...), 1, "admin")
		require.NoError(t, err)
		// 全為專用憑證的批次不需要 detach
		_, accC := f.addHost(t, "dedicated-c", "10.43.0.3", "plain")
		auth.deny(CredCapDetach, CredCapRotate)
		_, _, err = f.batches.Create(batchRequest("plain", model.BatchPasswordPerTarget, false, accC), 1, "admin")
		require.NoError(t, err, "專用憑證成員只需 account:rotate")
	})
}
