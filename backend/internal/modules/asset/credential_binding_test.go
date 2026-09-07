package asset

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 掛載與卸載的行為鎖定：唯一性、協定族相容、遠端零寫入、專用憑證的生滅、
// 特權標記逐台獨立、就位版本的歸屬，以及對受影響資產的權限。

// fakePermissionChecker 逐資產放行的權限判定樁。
//
// allow 明列的判定優先；未列者取 defaultAllow。**兩種模式都需要**：驗權本身的
// 測試要逐台明列（漏列一台就該被當成無權），而其餘測試只是為了讓建構期必填的
// 判定器有值，不該為每一台新資產補一行。
type fakePermissionChecker struct {
	allow        map[uint]bool
	defaultAllow bool
	asked        []uint
}

func (f *fakePermissionChecker) CheckPermission(_ context.Context, _ uint, assetID uint,
	_ model.PermissionType) (bool, error) {
	f.asked = append(f.asked, assetID)
	if v, ok := f.allow[assetID]; ok {
		return v, nil
	}
	return f.defaultAllow, nil
}

// denyAsset 明列拒絕一台（allow 為 nil 時就地建表）。
func (f *fakePermissionChecker) denyAsset(assetID uint) {
	if f.allow == nil {
		f.allow = map[uint]bool{}
	}
	f.allow[assetID] = false
}

// 掛載的兩條唯一性：同一憑證不重複掛同一資產、同一資產上同一帳號名只掛一次。
func TestCredentialBindingUniquePerAssetAndUsername(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "uniq-1", "10.3.0.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))

	shared := newSharedCredential(t, creds, "uniq-shared", "ops", "pw")
	_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)

	// 同一憑證掛第二次
	_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	assert.ErrorIs(t, err, ErrCredentialBindingExists)

	// 另一筆憑證但帳號名相同：跨表條件，DB 沒有唯一鍵，靠服務層在資產列鎖內判定
	twin := newSharedCredential(t, creds, "uniq-twin", "ops", "pw2")
	_, err = creds.Bind(adminCtx(), twin.ID, &BindCredentialRequest{AssetID: asset.ID})
	assert.ErrorIs(t, err, ErrAssetAccountUsernameExists)

	count, err := liveAccountCount(db, asset.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "兩次被拒的掛載都不得留下掛載列")
}

// 掛載時資產協定必須屬於憑證的協定族。
func TestCredentialBindRequiresProtocolFamilyMatch(t *testing.T) {
	_ = setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	vncAsset := newBareAsset(t, assets, "vnc-target", "10.3.1.1")
	sshCred := newSharedCredential(t, creds, "ssh-only", "ops", "pw")

	_, err := creds.Bind(adminCtx(), sshCred.ID, &BindCredentialRequest{AssetID: vncAsset.ID})
	assert.ErrorIs(t, err, ErrCredentialProtocolMismatch)

	// 同族者可掛
	vncCred, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "vnc-shared", Username: "ops", Password: "pw",
		ProtocolFamily: model.ProtocolFamilyVNC,
	})
	require.NoError(t, err)
	_, err = creds.Bind(adminCtx(), vncCred.ID, &BindCredentialRequest{AssetID: vncAsset.ID})
	require.NoError(t, err)

	// windows 族涵蓋 RDP 資產：族別由資產協定與改密通道推導，不是逐協定一族
	rdpAsset, err := assets.Create(&CreateAssetRequest{
		Name: "rdp-target", Protocol: model.ProtocolRDP, Host: "10.3.1.2", Port: 3389,
		Username: "seed", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	rdpList, err := accounts.List(rdpAsset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), rdpAsset.ID, rdpList[0].ID))

	winCred, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "win-admin", Username: "Administrator", Password: "pw",
		ProtocolFamily: model.ProtocolFamilyWindows,
	})
	require.NoError(t, err)
	_, err = creds.Bind(adminCtx(), winCred.ID, &BindCredentialRequest{AssetID: rdpAsset.ID})
	require.NoError(t, err, "windows 族必須涵蓋 RDP 資產")
}

// 掛載對目標主機零寫入：不產生密文版本、不改憑證現行版本，且程式路徑上不接遠端。
func TestCredentialBindDoesNotTouchRemote(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "no-remote", "ops", "pw")
	var before model.Credential
	require.NoError(t, db.First(&before, shared.ID).Error)
	versionsBefore := credentialVersionIDs(t, db, shared.ID)

	asset := newSSHAsset(t, assets, "no-remote-host", "10.3.2.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))

	binding, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)

	var after model.Credential
	require.NoError(t, db.First(&after, shared.ID).Error)
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, shared.ID),
		"掛載本身不建立新密文版本")
	require.NotNil(t, before.CurrentVersionID)
	require.NotNil(t, after.CurrentVersionID)
	assert.Equal(t, *before.CurrentVersionID, *after.CurrentVersionID,
		"掛載不改變憑證的現行版本")
	assert.Equal(t, *after.CurrentVersionID, effectiveVersionOf(t, db, binding.ID),
		"新掛載的就位版本即該憑證當下的現行版本")

	assertNoRemoteWriteInFunc(t, "Bind")
}

// 卸載只移除掛載列，不更動遠端密碼：憑證與其密文版本原封不動。
func TestCredentialUnbindDoesNotTouchRemote(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "unbind-shared", "ops", "pw")
	first := newSSHAsset(t, assets, "unbind-a", "10.3.3.1")
	second := newSSHAsset(t, assets, "unbind-b", "10.3.3.2")
	for _, a := range []*model.Asset{first, second} {
		list, lerr := accounts.List(a.ID)
		require.NoError(t, lerr)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		_, berr := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, berr)
	}
	versionsBefore := credentialVersionIDs(t, db, shared.ID)
	bindings := credentialBindings(t, db, shared.ID)
	require.Len(t, bindings, 2)

	// 兩台的就位版本都等於憑證的現行版本：掛載是操作者的宣告，同交易立即生效
	var cred model.Credential
	require.NoError(t, db.First(&cred, shared.ID).Error)
	require.NotNil(t, cred.CurrentVersionID)
	for i := range bindings {
		assert.Equal(t, *cred.CurrentVersionID, effectiveVersionOf(t, db, bindings[i].ID),
			"第 %d 台掛載完即應可連線", i+1)
	}

	require.NoError(t, creds.Unbind(adminCtx(), shared.ID, bindings[1].ID))

	var stillThere model.Credential
	require.NoError(t, db.First(&stillThere, shared.ID).Error, "共用憑證不因卸載而消失")
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, shared.ID),
		"卸載不得動到任何密文版本——遠端上的密碼仍是同一組")
	remaining := credentialBindings(t, db, shared.ID)
	require.Len(t, remaining, 1)
	assert.Equal(t, first.ID, remaining[0].AssetID)

	assertNoRemoteWriteInFunc(t, "Unbind")
}

// 卸載專用憑證的唯一掛載時同交易刪除該憑證（不留零掛載的孤兒）。
func TestCredentialUnbindDedicatedDeletesCredential(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "dedicated-life", "10.3.4.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	credID := credentialIDOf(t, db, list[0].ID)

	require.NoError(t, creds.Unbind(adminCtx(), credID, list[0].ID))

	var visible int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).Count(&visible).Error)
	assert.EqualValues(t, 0, visible, "專用憑證隨其唯一掛載一併消失")

	// 共用憑證則相反：零掛載是合法的待用狀態，不得被卸載順手刪掉
	shared := newSharedCredential(t, creds, "keep-me", "ops", "pw")
	binding, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)
	require.NoError(t, creds.Unbind(adminCtx(), shared.ID, binding.ID))
	var kept int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", shared.ID).Count(&kept).Error)
	assert.EqualValues(t, 1, kept, "零掛載的共用憑證是待用狀態，不得被順手刪掉")
}

// 專用憑證的完整生命週期：隨掛載建立、隨掛載刪除，中途恰有一個掛載。
func TestCredentialDedicatedLifecycleWithBinding(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newBareAsset(t, assets, "lifecycle", "10.3.5.1")
	var zero int64
	require.NoError(t, db.Model(&model.Credential{}).Count(&zero).Error)
	assert.EqualValues(t, 0, zero, "零掛載資產不得留下任何憑證")

	created, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Credential: &InlineCredential{Username: "ops", Password: "pw"},
	})
	require.NoError(t, err)
	credID := credentialIDOf(t, db, created.ID)

	dto, err := creds.Get(adminCtx(), credID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeDedicated, dto.Scope)
	assert.Equal(t, 1, dto.BindingCount, "專用憑證恰有一個掛載")
	require.Len(t, dto.Bindings, 1)
	assert.Equal(t, asset.ID, dto.Bindings[0].AssetID)
	assert.True(t, dto.Bindings[0].UpToDate)
	assert.True(t, dto.HasPassword)

	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, created.ID))
	// 掛載消失就是專用憑證的終點，而掛載消失的入口不只一個：刪帳號與卸載是同一
	// 件事的兩條路徑，任一條不回收，憑證庫就留下一筆沒有顯示名也沒有人能用的列
	_, err = creds.Get(adminCtx(), credID)
	assert.ErrorIs(t, err, ErrCredentialNotFound, "專用憑證隨其唯一掛載一併消失")
	count, err := credentialBindingCount(db, credID)
	require.NoError(t, err)
	assert.EqualValues(t, 0, count)
}

// 刪帳號同交易回收其專用憑證；共用憑證不動；改密進行中則整筆拒絕。
func TestAccountDeleteReclaimsDedicatedCredential(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "reclaim-account", "10.3.13.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	dedicatedID := credentialIDOf(t, db, list[0].ID)

	// 同一台再掛一筆共用憑證，才驗得出「回收只對專用生效」而不是無差別清掃。
	// 掛成預設是為了讓專用那筆變成非預設而刪得掉（「有帳號必有預設」）
	shared := newSharedCredential(t, creds, "reclaim-keep", "ops", "pw")
	sharedBinding, err := creds.Bind(adminCtx(), shared.ID,
		&BindCredentialRequest{AssetID: asset.ID, IsDefault: true})
	require.NoError(t, err)

	// 改密進行中的憑證：刪除整筆拒絕，掛載與憑證都不得動
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", dedicatedID).
		Update("active_rotation_id", 77).Error)
	assert.ErrorIs(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID), ErrCredentialRotationActive)
	count, err := credentialBindingCount(db, dedicatedID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "被拒的刪除不得移除掛載列")
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", dedicatedID).
		Update("active_rotation_id", nil).Error)

	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))

	var dedicatedLeft int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", dedicatedID).
		Count(&dedicatedLeft).Error)
	assert.EqualValues(t, 0, dedicatedLeft, "刪帳號同交易回收其專用憑證")

	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, sharedBinding.ID))
	var sharedLeft int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", shared.ID).
		Count(&sharedLeft).Error)
	assert.EqualValues(t, 1, sharedLeft, "零掛載的共用憑證是待用狀態，不得被順手刪掉")
}

// 刪資產同交易移除其全部掛載，並回收隨之孤兒的專用憑證。
func TestAssetDeleteReclaimsDedicatedCredentials(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)
	assets.SetAuthorizationRevoker(&fakeAuthzRevoker{})

	asset := newSSHAsset(t, assets, "reclaim-asset", "10.3.14.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	dedicatedID := credentialIDOf(t, db, list[0].ID)

	// 共用憑證另外掛在一台不被刪的資產上：驗「回收不越界」
	shared := newSharedCredential(t, creds, "reclaim-shared", "ops", "pw")
	_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)
	survivor := newSSHAsset(t, assets, "reclaim-survivor", "10.3.14.2")
	survivorList, err := accounts.List(survivor.ID)
	require.NoError(t, err)
	survivorCredID := credentialIDOf(t, db, survivorList[0].ID)

	require.NoError(t, assets.Delete(asset.ID))

	remaining, err := credentialBindingCount(db, dedicatedID)
	require.NoError(t, err)
	assert.EqualValues(t, 0, remaining, "資產刪除後不得留下指向它的掛載")
	var dedicatedLeft int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", dedicatedID).
		Count(&dedicatedLeft).Error)
	assert.EqualValues(t, 0, dedicatedLeft, "專用憑證隨其資產一併消失")

	var sharedLeft int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", shared.ID).
		Count(&sharedLeft).Error)
	assert.EqualValues(t, 1, sharedLeft, "共用憑證不因某一台被刪而消失")
	sharedCount, err := credentialBindingCount(db, shared.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 0, sharedCount, "被刪資產上的共用憑證掛載一併移除")

	// 對照組：沒被刪的那台，其掛載與專用憑證原封不動
	survivorCount, err := credentialBindingCount(db, survivorCredID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, survivorCount, "回收不得越界動到其他資產的掛載")
	var survivorLeft int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", survivorCredID).
		Count(&survivorLeft).Error)
	assert.EqualValues(t, 1, survivorLeft)
}

// 並行掛載同帳號名到同一資產：恰一成功。
//
// 「同資產同帳號名只掛一次」失去了 DB 唯一鍵（帳號名的真相在憑證表，跨表條件
// 無法以單一 unique index 表達），序列化改由資產列鎖承擔。這一支就是那個偏離的
// 補償：拿掉鎖內查重，兩個並行掛載會各自讀到「沒有撞名」然後雙雙寫入。
func TestConcurrentBindKeepsUsernameUniquePerAsset(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "race-bind", "10.3.6.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))

	first := newSharedCredential(t, creds, "race-a", "ops", "pw-a")
	second := newSharedCredential(t, creds, "race-b", "ops", "pw-b")

	var wg sync.WaitGroup
	wg.Add(2)
	for _, id := range []uint{first.ID, second.ID} {
		go func(credentialID uint) {
			defer wg.Done()
			_, _ = creds.Bind(adminCtx(), credentialID, &BindCredentialRequest{AssetID: asset.ID})
		}(id)
	}
	wg.Wait()

	var live []model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).Find(&live).Error)
	assert.Len(t, live, 1, "同資產同帳號名的並行掛載必須恰一成功")
	if len(live) == 1 {
		assert.True(t, live[0].IsDefault, "首筆掛載必為預設")
	}
}

// 特權標記逐台獨立：同一共用憑證掛在兩台，一台標特權不影響另一台，憑證本身不持有它。
func TestCredentialPrivilegedIsPerBinding(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "priv-shared", "ops", "pw")
	hostA := newSSHAsset(t, assets, "priv-a", "10.3.7.1")
	hostB := newSSHAsset(t, assets, "priv-b", "10.3.7.2")
	for _, a := range []*model.Asset{hostA, hostB} {
		list, lerr := accounts.List(a.ID)
		require.NoError(t, lerr)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
	}

	privileged, err := creds.Bind(adminCtx(), shared.ID,
		&BindCredentialRequest{AssetID: hostA.ID, Privileged: true})
	require.NoError(t, err)
	plain, err := creds.Bind(adminCtx(), shared.ID,
		&BindCredentialRequest{AssetID: hostB.ID, Privileged: false})
	require.NoError(t, err)

	assert.True(t, privileged.Privileged)
	assert.False(t, plain.Privileged, "同一組秘密在不同主機上的特權性可以不同")

	detail, err := creds.Get(adminCtx(), shared.ID)
	require.NoError(t, err)
	require.Len(t, detail.Bindings, 2)
	byAsset := map[uint]bool{}
	for _, b := range detail.Bindings {
		byAsset[b.AssetID] = b.Privileged
	}
	assert.True(t, byAsset[hostA.ID])
	assert.False(t, byAsset[hostB.ID])

	// 憑證本體不持有特權標記：存進憑證會把一台機器上的分類錯誤擴散到全部成員
	var raw map[string]any
	rows, err := db.Model(&model.Credential{}).Where("id = ?", shared.ID).Rows()
	require.NoError(t, err)
	cols, err := rows.Columns()
	require.NoError(t, rows.Close())
	require.NoError(t, err)
	_ = raw
	for _, c := range cols {
		assert.NotEqual(t, "privileged", c, "credentials 表不得持有特權標記")
	}
}

// 就位版本必屬於該掛載所引用的憑證；改綁時同交易改寫為新憑證的現行版本。
func TestCredentialEffectiveVersionMustBelongToCredential(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "effective-1", "10.3.8.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	binding := &model.AssetAccount{}
	require.NoError(t, db.First(binding, list[0].ID).Error)
	ownVersion := effectiveVersionOf(t, db, binding.ID)
	require.NotZero(t, ownVersion)

	// 另一筆憑證的版本識別
	foreign := newSharedCredential(t, creds, "foreign-cred", "other", "pw")
	var foreignCred model.Credential
	require.NoError(t, db.First(&foreignCred, foreign.ID).Error)
	require.NotNil(t, foreignCred.CurrentVersionID)

	err = setBindingEffectiveVersion(db, binding, *foreignCred.CurrentVersionID)
	assert.ErrorIs(t, err, ErrCredentialVersionNotFound,
		"寫入不屬於本憑證的版本識別必須被拒")
	assert.Equal(t, ownVersion, effectiveVersionOf(t, db, binding.ID),
		"被拒的寫入不得改變就位版本")

	// 改綁：就位版本同交易改為新憑證的現行版本，且必屬於它
	same := newSharedCredential(t, creds, "rebind-target", "seed", "pw2")
	var sameCred model.Credential
	require.NoError(t, db.First(&sameCred, same.ID).Error)
	rebound, err := creds.Rebind(adminCtx(), asset.ID, binding.ID, same.ID)
	require.NoError(t, err)
	assert.Equal(t, same.ID, credentialIDOf(t, db, rebound.ID))
	require.NotNil(t, sameCred.CurrentVersionID)
	assert.Equal(t, *sameCred.CurrentVersionID, effectiveVersionOf(t, db, rebound.ID),
		"改綁後的就位版本必須是新憑證的現行版本")

	// 舊的專用憑證因失去唯一掛載而同交易消失
	var orphan int64
	require.NoError(t, db.Model(&model.Credential{}).
		Where("id = ?", binding.CredentialID).Count(&orphan).Error)
	assert.EqualValues(t, 0, orphan)
}

// 掛載與卸載須驗操作者對受影響資產有權限。
func TestCredentialBindRequiresPermissionOnAffectedAssets(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	allowed := newSSHAsset(t, assets, "perm-allowed", "10.3.9.1")
	denied := newSSHAsset(t, assets, "perm-denied", "10.3.9.2")
	for _, a := range []*model.Asset{allowed, denied} {
		list, lerr := accounts.List(a.ID)
		require.NoError(t, lerr)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
	}
	shared := newSharedCredential(t, creds, "perm-shared", "ops", "pw")

	checker := &fakePermissionChecker{allow: map[uint]bool{allowed.ID: true, denied.ID: false}}
	creds = creds.WithAuthorization(checker)

	_, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: denied.ID})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden)
	count, err := credentialBindingCount(db, shared.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 0, count, "被拒的掛載不得留下掛載列")

	binding, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: allowed.ID})
	require.NoError(t, err)
	assert.Contains(t, checker.asked, allowed.ID, "掛載必須實際問過受影響資產的權限")

	// 卸載同樣要驗：把別人的掛載拿掉一樣是改變那台機器的登入身分
	checker.allow[allowed.ID] = false
	assert.ErrorIs(t, creds.Unbind(adminCtx(), shared.ID, binding.ID), ErrCredentialBindForbidden)
	count, err = credentialBindingCount(db, shared.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "被拒的卸載不得移除掛載列")
}

// 建資產時選共用憑證：同交易產生預設掛載，就位版本為該憑證的現行版本，密文不重複落庫。
func TestAssetCreateWithSharedCredentialBinds(t *testing.T) {
	db := setupCredentialDB(t)
	assets, _, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "asset-create-shared", "ops", "shared-pw")
	versionsBefore := credentialVersionIDs(t, db, shared.ID)
	require.Len(t, versionsBefore, 1)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "created-with-shared", Protocol: model.ProtocolSSH, Host: "10.3.10.1", Port: 22,
		CredentialID: shared.ID, CreatedBy: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, "ops", asset.Username, "資產的顯示身分取自憑證")
	assert.True(t, asset.HasPassword)

	var binding model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&binding).Error)
	assert.True(t, binding.IsDefault)
	assert.Equal(t, shared.ID, binding.CredentialID)

	var cred model.Credential
	require.NoError(t, db.First(&cred, shared.ID).Error)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, *cred.CurrentVersionID, effectiveVersionOf(t, db, binding.ID))
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, shared.ID),
		"選用共用憑證不得讓密文重複落庫")

	// 建完即可連線
	got, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "ops", got.Username)
	assert.Equal(t, "shared-pw", got.Password)

	// 二擇一：同時給共用憑證與直填欄位一律拒絕
	_, err = assets.Create(&CreateAssetRequest{
		Name: "ambiguous", Protocol: model.ProtocolSSH, Host: "10.3.10.2", Port: 22,
		CredentialID: shared.ID, Username: "root", Password: "pw", CreatedBy: 1,
	})
	assert.ErrorIs(t, err, ErrCredentialSourceAmbiguous)
}

// 建資產時用內嵌憑證物件：同交易建專用憑證與其 v1，顯示名為計算值。
func TestAssetCreateWithInlineCredentialCreatesDedicated(t *testing.T) {
	db := setupCredentialDB(t)
	assets, _, creds := newCredentialServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "inline-host", Protocol: model.ProtocolSSH, Host: "10.3.11.1", Port: 22,
		Credential: &InlineCredential{Username: "root", Password: "inline-pw"},
		CreatedBy:  1,
	})
	require.NoError(t, err)
	assert.Equal(t, "root", asset.Username)

	var binding model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).First(&binding).Error)
	require.NotZero(t, binding.CredentialID)
	require.NotNil(t, binding.EffectiveVersionID)

	dto, err := creds.Get(adminCtx(), binding.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeDedicated, dto.Scope)
	assert.Equal(t, "inline-host / root", dto.Name)
	assert.Equal(t, 1, dto.CurrentVersionNo)

	got, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)
	assert.Equal(t, "inline-pw", got.Password)

	// 內嵌物件與頂層簡寫二擇一
	_, err = assets.Create(&CreateAssetRequest{
		Name: "inline-ambiguous", Protocol: model.ProtocolSSH, Host: "10.3.11.2", Port: 22,
		Username:   "root",
		Credential: &InlineCredential{Username: "root", Password: "x"},
		CreatedBy:  1,
	})
	assert.ErrorIs(t, err, ErrCredentialSourceAmbiguous)
}

// 掛載沒有憑證識別時大聲失敗，不就地補一筆。
//
// 存量轉換已保證該欄非空；靜默補一筆會讓一個只可能來自繞過服務層的狀態延續下去，
// 而它下一次出現時仍然沒有人知道它是怎麼來的。
func TestBindingWithoutCredentialFailsLoudly(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, _ := newCredentialServices(t)

	asset := newBareAsset(t, assets, "orphan-binding", "10.3.12.1")
	// 直接以資料層植入殘態（服務層寫不出這種列）
	orphan := model.AssetAccount{AssetID: asset.ID, Username: "ops", IsDefault: true}
	require.NoError(t, db.Create(&orphan).Error)

	pw := "any"
	_, err := accounts.Update(adminCtx(), asset.ID, orphan.ID, &UpdateAssetAccountRequest{Password: &pw})
	assert.ErrorIs(t, err, ErrBindingWithoutCredential)

	var versions int64
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).Count(&versions).Error)
	assert.EqualValues(t, 0, versions, "殘態不得被就地補出一筆憑證與版本")
}

// 硬前提的第二個入口：資產表單的透明轉寫同樣不得就地補憑證。
//
// 兩個入口走同一個判定，但只釘住其中一個等於讓另一條路徑可以在無人察覺下鬆掉——
// 補一筆憑證的那個版本在資料庫狀態上看起來一切正常，而它把一個只可能來自繞過
// 服務層的狀態延續了下去。
func TestSyncDefaultAccountFromAssetRequiresBindingCredential(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, _ := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "sync-orphan", "10.3.15.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	versionsBefore := credentialVersionIDs(t, db, credentialIDOf(t, db, list[0].ID))

	// 直接以資料層抹掉憑證識別（服務層寫不出這種列）
	require.NoError(t, db.Model(&model.AssetAccount{}).Where("id = ?", list[0].ID).
		Update("credential_id", 0).Error)

	// 只改帳號名（不帶秘密）：這條路徑上唯一會回這個哨兵的就是入口的硬前提判定。
	// 帶秘密的請求另有下游判定會擋，拿它當唯一證據等於讓入口的那道判定可以被
	// 拿掉而測試照樣綠
	newName := "renamed"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Username: &newName})
	assert.ErrorIs(t, err, ErrBindingWithoutCredential, "入口的硬前提判定")

	pw := "any"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Password: &pw})
	assert.ErrorIs(t, err, ErrBindingWithoutCredential, "帶秘密的請求同樣大聲失敗")

	var orphanVersions int64
	require.NoError(t, db.Model(&model.CredentialSecretVersion{}).
		Where("id NOT IN ?", versionsBefore).Count(&orphanVersions).Error)
	assert.EqualValues(t, 0, orphanVersions, "殘態不得被就地補出一筆憑證與版本")
	var stillZero model.AssetAccount
	require.NoError(t, db.First(&stillZero, list[0].ID).Error)
	assert.EqualValues(t, 0, stillZero.CredentialID, "被拒的更新不得就地補上憑證識別")
}

// 改密進行中：帳號更新帶新密碼被拒，密文版本與就位版本皆不變。
//
// 這條路徑寫的是操作者宣告的密文，射程是**全部掛載**的就位版本。改密進行中放它過去，
// 那一輪改密會在自己的目標集合底下被換掉腳下的秘密，最後收斂到一個沒有人宣告過的值。
func TestAccountUpdateDeclaredSecretRejectedDuringRotation(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, _ := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "rotation-account-update", "10.3.16.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	credID := credentialIDOf(t, db, list[0].ID)
	versionsBefore := credentialVersionIDs(t, db, credID)
	effectiveBefore := effectiveVersionOf(t, db, list[0].ID)

	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("active_rotation_id", 88).Error)

	pw := "declared-during-rotation"
	_, err = accounts.Update(adminCtx(), asset.ID, list[0].ID,
		&UpdateAssetAccountRequest{Password: &pw})
	assert.ErrorIs(t, err, ErrCredentialRotationActive)
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, credID),
		"被拒的宣告不得留下新密文版本")
	assert.Equal(t, effectiveBefore, effectiveVersionOf(t, db, list[0].ID),
		"被拒的宣告不得改變就位版本")
	var cred model.Credential
	require.NoError(t, db.First(&cred, credID).Error)
	require.NotNil(t, cred.CurrentVersionID)
	assert.Equal(t, versionsBefore[len(versionsBefore)-1], *cred.CurrentVersionID,
		"被拒的宣告不得改變憑證的現行版本")

	// 邊界另一側：改密結束後同一個請求即成立（證明擋下它的就是這道判定）
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("active_rotation_id", nil).Error)
	_, err = accounts.Update(adminCtx(), asset.ID, list[0].ID,
		&UpdateAssetAccountRequest{Password: &pw})
	require.NoError(t, err)
	assert.Len(t, credentialVersionIDs(t, db, credID), len(versionsBefore)+1)
}

// 改密進行中：資產表單帶新密碼的透明轉寫同樣被拒（同一條寫密面的第二個入口）。
func TestAssetUpdateDeclaredSecretRejectedDuringRotation(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, _ := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "rotation-asset-update", "10.3.17.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	credID := credentialIDOf(t, db, list[0].ID)
	versionsBefore := credentialVersionIDs(t, db, credID)
	effectiveBefore := effectiveVersionOf(t, db, list[0].ID)

	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("active_rotation_id", 89).Error)

	pw := "declared-during-rotation"
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Password: &pw})
	assert.ErrorIs(t, err, ErrCredentialRotationActive)
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, credID),
		"被拒的宣告不得留下新密文版本")
	assert.Equal(t, effectiveBefore, effectiveVersionOf(t, db, list[0].ID),
		"被拒的宣告不得改變就位版本")

	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", credID).
		Update("active_rotation_id", nil).Error)
	_, err = assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Password: &pw})
	require.NoError(t, err)
	assert.Len(t, credentialVersionIDs(t, db, credID), len(versionsBefore)+1)
}

// assertNoRemoteWriteInFunc 靜態確認某支方法的函式體不接遠端也不改密文版本。
//
// **為什麼要靜態判**：單元測試裡沒有遠端可觀測，「沒有寫遠端」在資料庫狀態上是
// 看不見的；而掛載與卸載對主機零寫入是規格條文，不是實作細節。以呼叫面判定
// 「這條路徑上有沒有任何一步可能走到遠端或改到秘密」，是這件事唯一可機器檢查的形態。
func assertNoRemoteWriteInFunc(t *testing.T, method string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "credential_binding.go", nil, 0)
	require.NoError(t, err, "讀不到被驗證對象即等於沒有守衛")

	// 會動遠端或動秘密的呼叫面。任一出現在掛載／卸載的函式體內即為違規
	forbidden := map[string]string{
		"rotationExecutorFor":         "選取改密執行器＝準備對遠端下達",
		"runTarget":                   "對單一目標執行改密",
		"UpdatePassword":              "系統路徑寫入面（遠端驗證後才呼叫）",
		"UpdatePrivateKey":            "系統路徑寫入面（遠端驗證後才呼叫）",
		"commitBindingSecret":         "系統路徑寫入面",
		"appendCredentialVersion":     "建立新密文版本＝改變了秘密本身",
		"appendDeclaredSecret":        "建立新密文版本＝改變了秘密本身",
		"setCredentialCurrentVersion": "改變憑證的現行版本",
		"Dial":                        "直接建線",
		"DialTimeout":                 "直接建線",
	}

	var found []string
	seen := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != method {
			continue
		}
		seen = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			if why, bad := forbidden[name]; bad {
				found = append(found, name+"（"+why+"）")
			}
			return true
		})
	}
	require.True(t, seen, "credential_binding.go 找不到方法 %s：守衛已失去被驗證對象", method)
	if len(found) > 0 {
		t.Errorf("%s 的函式體出現會觸及遠端或改動秘密的呼叫：%s。"+
			"掛載與卸載只改掛載列，遠端主機上的密碼不因此改變——"+
			"這條界線一旦鬆動，管理者會把卸載當成把密碼收回來", method, strings.Join(found, "、"))
	}
}
