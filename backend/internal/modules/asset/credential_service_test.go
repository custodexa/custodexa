package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 憑證管理面的行為鎖定：命名唯一性、帳號名可改性、顯示名的計算、範圍轉換與刪除。

// setupCredentialDB 憑證服務的測試裝配。
//
// 與 setupAccountDB 分開的理由：本組測試會走到刪除的引用檢查，那條路徑要查候選表，
// 而帳號服務的裝配不含改密相關的表。共用一份裝配會讓兩組測試的表集合互相牽動。
func setupCredentialDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫，連線池會讓「寫在 A 連線、
	// 讀在 B 連線」偶發查無資料
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AssetAccount{}, &model.Credential{},
		&model.CredentialSecretVersion{}, &model.ChangeSecretCandidate{},
		&model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

// newCredentialServices 三個服務共用同一個 codec 實例（生產組裝的約束）。
func newCredentialServices(t *testing.T) (*AssetService, *AssetAccountService, *CredentialService) {
	t.Helper()
	codec := aesColumnCodec(t, make([]byte, 32))
	assets, err := NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	accounts := NewAssetAccountService(assets, codec, audit.NewTxSink())
	creds := NewCredentialService(assets, codec, audit.NewTxSink())
	return assets, accounts, creds
}

// newSSHAsset 建一台不帶任何憑證來源的 SSH 資產（零掛載）。
func newSSHAsset(t *testing.T, assets *AssetService, name, host string) *model.Asset {
	t.Helper()
	a, err := assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22,
		Username: "seed", Password: "seed-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	return a
}

// newBareAsset 建一台零掛載的資產（VNC 不強制 username）。
func newBareAsset(t *testing.T, assets *AssetService, name, host string) *model.Asset {
	t.Helper()
	a, err := assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolVNC, Host: host, Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)
	return a
}

// newSharedCredential 建一筆 SSH 族的共用憑證。
func newSharedCredential(t *testing.T, creds *CredentialService, name, username, password string) *CredentialDTO {
	t.Helper()
	dto, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: name, Username: username, Password: password,
		ProtocolFamily: model.ProtocolFamilySSH,
	})
	require.NoError(t, err)
	return dto
}

// 共用憑證名稱唯一，但唯一性只涵蓋未軟刪者——軟刪後同名可立即重用。
func TestCredentialSharedNameUniquePartial(t *testing.T) {
	_ = setupCredentialDB(t)
	_, _, creds := newCredentialServices(t)

	first := newSharedCredential(t, creds, "prod-root", "root", "pw-1")

	_, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "prod-root", Username: "root", Password: "pw-2",
		ProtocolFamily: model.ProtocolFamilySSH,
	})
	assert.ErrorIs(t, err, ErrCredentialNameExists, "同名的未軟刪共用憑證必須擋下")

	// 專用憑證的名稱是 NULL，不參與共用名稱的唯一性——兩筆專用不會互撞
	dedicatedA, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "other", Username: "ops", Password: "pw-3",
		ProtocolFamily: model.ProtocolFamilySSH,
	})
	require.NoError(t, err)
	require.NotZero(t, dedicatedA.ID)

	// 軟刪後名稱釋放：同名可立即被新憑證重用
	require.NoError(t, creds.Delete(adminCtx(), first.ID))
	reused, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "prod-root", Username: "root", Password: "pw-4",
		ProtocolFamily: model.ProtocolFamilySSH,
	})
	require.NoError(t, err, "已軟刪的同名憑證不得阻擋名稱重用")
	assert.NotEqual(t, first.ID, reused.ID)
	assert.Equal(t, "prod-root", reused.Name)
}

// 共用憑證的帳號名建立後不可改；專用憑證可改且於其唯一掛載的資產內重驗不撞名。
func TestCredentialUsernameImmutable(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "shared-ops", "ops", "pw")
	newName := "ops2"
	_, err := creds.Update(adminCtx(), shared.ID, &UpdateCredentialRequest{Username: &newName})
	assert.ErrorIs(t, err, ErrCredentialUsernameImmutable)

	var stored model.Credential
	require.NoError(t, db.First(&stored, shared.ID).Error)
	assert.Equal(t, "ops", stored.Username, "被拒的改名不得留下任何痕跡")

	// 掛載後透過帳號服務改名同樣被擋下——那是同一條規則的另一個入口
	asset := newBareAsset(t, assets, "vnc-host", "10.2.0.1")
	sharedVNC, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "vnc-shared", Username: "ops", Password: "pw",
		ProtocolFamily: model.ProtocolFamilyVNC,
	})
	require.NoError(t, err)
	binding, err := creds.Bind(adminCtx(), sharedVNC.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)

	renamed := "ops-renamed"
	_, err = accounts.Update(adminCtx(), asset.ID, binding.ID, &UpdateAssetAccountRequest{Username: &renamed})
	assert.ErrorIs(t, err, ErrCredentialUsernameImmutable,
		"掛載改名是共用憑證改名的側門，必須走同一條規則")

	// 專用憑證：可改，且憑證與掛載列同步
	dedicatedAsset := newSSHAsset(t, assets, "srv-dedicated", "10.2.0.2")
	list, err := accounts.List(dedicatedAsset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	ok := "ops-new"
	updated, err := accounts.Update(adminCtx(), dedicatedAsset.ID, list[0].ID,
		&UpdateAssetAccountRequest{Username: &ok})
	require.NoError(t, err, "專用憑證恰一掛載，改名只需在該資產內重驗")
	assert.Equal(t, "ops-new", updated.Username)

	var boundAccount model.AssetAccount
	require.NoError(t, db.First(&boundAccount, list[0].ID).Error)
	var dedicatedCred model.Credential
	require.NoError(t, db.First(&dedicatedCred, boundAccount.CredentialID).Error)
	assert.Equal(t, "ops-new", dedicatedCred.Username, "帳號名的真相在憑證，必須同步")
}

// 專用憑證的顯示名為「資產名 / 帳號名」計算值，資產改名後隨之改變，且不落庫。
func TestCredentialDedicatedDisplayNameComputed(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "web-01", "10.2.1.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)

	var binding model.AssetAccount
	require.NoError(t, db.First(&binding, list[0].ID).Error)
	require.NotZero(t, binding.CredentialID)

	dto, err := creds.Get(adminCtx(), binding.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeDedicated, dto.Scope)
	assert.Equal(t, "web-01 / seed", dto.Name)

	// 名稱不落庫：欄位本身是 NULL
	var stored model.Credential
	require.NoError(t, db.First(&stored, binding.CredentialID).Error)
	assert.Nil(t, stored.Name, "專用憑證的名稱是 NULL 而非空字串")

	// 資產改名後顯示名隨之改變——落庫的副本會在改名那一刻開始說謊
	require.NoError(t, db.Model(&model.Asset{}).Where("id = ?", asset.ID).
		Update("name", "web-01-renamed").Error)
	dto, err = creds.Get(adminCtx(), binding.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, "web-01-renamed / seed", dto.Name)
}

// 範圍轉換的四條不變式。
func TestCredentialScopeConversionInvariants(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	// 情境 1：專用轉共用必須提供名稱
	asset1 := newSSHAsset(t, assets, "conv-1", "10.2.2.1")
	list, err := accounts.List(asset1.ID)
	require.NoError(t, err)
	dedicatedID := credentialIDOf(t, db, list[0].ID)

	_, err = creds.ConvertScope(adminCtx(), dedicatedID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeShared,
	})
	assert.ErrorIs(t, err, ErrCredentialSharedRequiresName)

	converted, err := creds.ConvertScope(adminCtx(), dedicatedID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeShared, Name: "conv-shared",
	})
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeShared, converted.Scope)
	assert.Equal(t, "conv-shared", converted.Name)

	// 轉換前後的密文版本與就位版本皆不變（不動遠端亦不動秘密）
	versionsBefore := credentialVersionIDs(t, db, dedicatedID)
	effectiveBefore := effectiveVersionOf(t, db, list[0].ID)

	// 情境 2：掛載於多個資產時不可轉專用
	asset2 := newSSHAsset(t, assets, "conv-2", "10.2.2.2")
	// asset2 已有一筆名為 seed 的掛載，先卸掉才不會撞名
	list2, err := accounts.List(asset2.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset2.ID, list2[0].ID))

	_, err = creds.Bind(adminCtx(), dedicatedID, &BindCredentialRequest{AssetID: asset2.ID})
	require.NoError(t, err)

	_, err = creds.ConvertScope(adminCtx(), dedicatedID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	assert.ErrorIs(t, err, ErrCredentialToDedicatedMultiBinding)
	var stillShared model.Credential
	require.NoError(t, db.First(&stillShared, dedicatedID).Error)
	assert.Equal(t, model.CredentialScopeShared, stillShared.Scope, "被拒的轉換不得改變範圍")

	// 情境 3：剩一掛載時可轉專用，同交易清空名稱
	bindings := credentialBindings(t, db, dedicatedID)
	require.Len(t, bindings, 2)
	require.NoError(t, creds.Unbind(adminCtx(), dedicatedID, bindings[1].ID))

	back, err := creds.ConvertScope(adminCtx(), dedicatedID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeDedicated, back.Scope)
	var afterConvert model.Credential
	require.NoError(t, db.First(&afterConvert, dedicatedID).Error)
	assert.Nil(t, afterConvert.Name, "轉專用時同交易清空名稱")
	assert.Equal(t, "conv-1 / seed", back.Name, "顯示名改為計算值")

	// 情境 4：掛載、卸載、被拒的轉換與共用→專用都不動密文版本與就位版本
	// （遠端零操作的可觀測代理）。快照取在專用→共用**之後**，故該方向不在本段射程內
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, dedicatedID),
		"範圍轉換不得產生或改寫任何密文版本")
	assert.Equal(t, effectiveBefore, effectiveVersionOf(t, db, list[0].ID),
		"範圍轉換不得改變任何掛載的就位版本")
}

// 轉專用的判準是「恰剩一個掛載」：零掛載與多掛載都拒絕。
//
// 零掛載這一格是靜默的——判定寫成「不是多掛載就放行」時它會通過，產出一筆
// 沒有顯示名（顯示名由掛載算出）、沒有人能用、也沒有掛載可以把它帶走的憑證，
// 而畫面上看不出任何差別。
func TestCredentialConvertToDedicatedRequiresExactlyOneBinding(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	// 憑證庫新建的共用憑證天生零掛載
	shared := newSharedCredential(t, creds, "zero-binding", "ops", "pw")
	_, err := creds.ConvertScope(adminCtx(), shared.ID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	assert.ErrorIs(t, err, ErrCredentialToDedicatedNoBinding)

	var untouched model.Credential
	require.NoError(t, db.First(&untouched, shared.ID).Error)
	assert.Equal(t, model.CredentialScopeShared, untouched.Scope, "被拒的轉換不得改變範圍")
	require.NotNil(t, untouched.Name)
	assert.Equal(t, "zero-binding", *untouched.Name, "被拒的轉換不得清空名稱")

	// 邊界的另一側：掛上一台之後同一個請求即成立
	asset := newSSHAsset(t, assets, "zero-binding-host", "10.2.6.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))
	_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: asset.ID})
	require.NoError(t, err)

	converted, err := creds.ConvertScope(adminCtx(), shared.ID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	require.NoError(t, err)
	assert.Equal(t, model.CredentialScopeDedicated, converted.Scope)
}

// 影響全部掛載的動作須對**每一台**掛載資產驗權，其中一台無權即整筆拒絕。
//
// 只驗其中一台等於讓操作者拿一台他管得到的機器，決定另外幾台他管不到的機器
// 怎麼登入——改秘密會讓新版本同時就位到每一台，換範圍與刪除同樣是整組的後果。
func TestCredentialWideOperationsRequirePermissionOnAllBoundAssets(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "wide-shared", "ops", "pw")
	hosts := make([]*model.Asset, 0, 3)
	for i, name := range []string{"wide-a", "wide-b", "wide-c"} {
		a := newSSHAsset(t, assets, name, "10.2.7."+string(rune('1'+i)))
		list, lerr := accounts.List(a.ID)
		require.NoError(t, lerr)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		_, berr := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, berr)
		hosts = append(hosts, a)
	}
	require.Len(t, hosts, 3)

	// 第三台無權：前兩台有權不足以放行
	checker := &fakePermissionChecker{allow: map[uint]bool{
		hosts[0].ID: true, hosts[1].ID: true, hosts[2].ID: false,
	}}
	creds = creds.WithAuthorization(checker)
	versionsBefore := credentialVersionIDs(t, db, shared.ID)

	_, err := creds.SetSecret(adminCtx(), shared.ID, &SetCredentialSecretRequest{Password: "new-pw"})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden, "改秘密影響全部掛載")
	assert.Equal(t, versionsBefore, credentialVersionIDs(t, db, shared.ID),
		"被拒的改秘密不得留下新版本")

	_, err = creds.ConvertScope(adminCtx(), shared.ID, &ConvertCredentialScopeRequest{
		Scope: model.CredentialScopeDedicated,
	})
	assert.ErrorIs(t, err, ErrCredentialBindForbidden, "換範圍的後果落在整組上")
	assert.NotErrorIs(t, err, ErrCredentialToDedicatedMultiBinding,
		"權限不足時不得先回規則錯誤——那會透露這組秘密掛了幾台")

	err = creds.Delete(adminCtx(), shared.ID)
	assert.ErrorIs(t, err, ErrCredentialBindForbidden)
	var inUse *CredentialInUseError
	assert.False(t, errors.As(err, &inUse),
		"權限不足時不得回掛載資產名單——那是共用拓撲，正是要擋下的東西")

	var stillThere model.Credential
	require.NoError(t, db.First(&stillThere, shared.ID).Error)
	assert.Equal(t, model.CredentialScopeShared, stillThere.Scope, "被拒的動作不得改變憑證")

	// 補齊第三台的權限後同一個動作即成立，且三台都被問過
	checker.allow[hosts[2].ID] = true
	checker.asked = nil
	_, err = creds.SetSecret(adminCtx(), shared.ID, &SetCredentialSecretRequest{Password: "new-pw"})
	require.NoError(t, err)
	for i := range hosts {
		assert.Contains(t, checker.asked, hosts[i].ID, "每一台掛載資產都必須被問過")
	}
}

// 仍有掛載時拒刪，並回掛載該憑證的資產名單。
func TestCredentialDeleteRejectedWhileBound(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "in-use", "ops", "pw")
	names := []string{"used-a", "used-b", "used-c"}
	for i, name := range names {
		a := newSSHAsset(t, assets, name, "10.2.3."+string(rune('1'+i)))
		list, err := accounts.List(a.ID)
		require.NoError(t, err)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		_, err = creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, err)
	}

	err := creds.Delete(adminCtx(), shared.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCredentialInUse)
	var inUse *CredentialInUseError
	require.ErrorAs(t, err, &inUse)
	assert.ElementsMatch(t, names, inUse.Assets,
		"拒刪必須帶回名單，否則管理者只拿到一句「還有人在用」而無從下手")

	var stillThere model.Credential
	require.NoError(t, db.First(&stillThere, shared.ID).Error)
	count, err := credentialBindingCount(db, shared.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 3, count, "被拒的刪除不得動到任何掛載")
}

// 零掛載可刪，刪除為軟刪並釋放名稱。
func TestCredentialDeleteReleasesNameWhenUnbound(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "releasable", "ops", "pw")
	a := newSSHAsset(t, assets, "rel-1", "10.2.4.1")
	list, err := accounts.List(a.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
	binding, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
	require.NoError(t, err)

	assert.ErrorIs(t, creds.Delete(adminCtx(), shared.ID), ErrCredentialInUse)
	require.NoError(t, creds.Unbind(adminCtx(), shared.ID, binding.ID))
	require.NoError(t, creds.Delete(adminCtx(), shared.ID))

	// 軟刪：列仍在，但一般查詢看不見
	var visible int64
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", shared.ID).Count(&visible).Error)
	assert.EqualValues(t, 0, visible)
	var raw int64
	require.NoError(t, db.Unscoped().Model(&model.Credential{}).
		Where("id = ?", shared.ID).Count(&raw).Error)
	assert.EqualValues(t, 1, raw, "軟刪保留列本體，密文版本的歷史不得憑空消失")

	reused, err := creds.Create(adminCtx(), &CreateCredentialRequest{
		Name: "releasable", Username: "ops", Password: "pw2",
		ProtocolFamily: model.ProtocolFamilySSH,
	})
	require.NoError(t, err, "軟刪後名稱可立即重用")
	assert.NotEqual(t, shared.ID, reused.ID)
}

// 已軟刪的憑證不得再供取密：軟刪對連線路徑失效等於刪除這個動作什麼都沒做。
func TestCredentialDeletedCredentialFailsClosedOnResolve(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, _ := newCredentialServices(t)

	asset := newSSHAsset(t, assets, "resolve-1", "10.2.5.1")
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	accountID := list[0].ID
	credID := credentialIDOf(t, db, accountID)

	// 刪除前連線取得的秘密即建立時直填的那一組
	got, err := assets.GetWithCredentialsForAccount(asset.ID, accountID)
	require.NoError(t, err)
	require.Equal(t, "seed-pw", got.Password)

	// 掛載仍在、憑證被軟刪（走資料層製造殘態：服務層的引用檢查會擋下這種刪除）
	require.NoError(t, db.Delete(&model.Credential{}, credID).Error)

	_, err = assets.GetWithCredentialsForAccount(asset.ID, accountID)
	assert.ErrorIs(t, err, ErrCredentialNotFound,
		"憑證已刪卻仍連得上，正是刪除這個動作要消除的東西")

	_, err = assets.resolver.ResolveForBinding(context.Background(), asset.ID, accountID)
	assert.ErrorIs(t, err, ErrCredentialNotFound)
}

// 對既有憑證直接寫入新密文：全部掛載的就位版本一併改指新版本。
//
// 只改「操作者當時點進去的那一台」會讓其餘各台停在舊版，而畫面上看不出差別——
// 他說的是「這組秘密現在長這樣」，那句話的射程是整組。
func TestCredentialDeclaredSecretUpdatesAllBindings(t *testing.T) {
	db := setupCredentialDB(t)
	assets, accounts, creds := newCredentialServices(t)

	shared := newSharedCredential(t, creds, "three-hosts", "ops", "old-pw")
	accountIDs := make([]uint, 0, 3)
	for i, name := range []string{"multi-a", "multi-b", "multi-c"} {
		a := newSSHAsset(t, assets, name, "10.2.6."+string(rune('1'+i)))
		list, err := accounts.List(a.ID)
		require.NoError(t, err)
		require.NoError(t, accounts.Delete(adminCtx(), a.ID, list[0].ID))
		binding, err := creds.Bind(adminCtx(), shared.ID, &BindCredentialRequest{AssetID: a.ID})
		require.NoError(t, err)
		accountIDs = append(accountIDs, binding.ID)
	}

	before := effectiveVersionOf(t, db, accountIDs[0])
	for _, id := range accountIDs {
		assert.Equal(t, before, effectiveVersionOf(t, db, id), "三台掛載起始就位版本相同")
	}

	updated, err := creds.SetSecret(adminCtx(), shared.ID, &SetCredentialSecretRequest{Password: "new-pw"})
	require.NoError(t, err)
	assert.Equal(t, 2, updated.CurrentVersionNo, "直接寫入產生新版本而非覆寫舊版")

	var reloaded model.Credential
	require.NoError(t, db.First(&reloaded, shared.ID).Error)
	require.NotNil(t, reloaded.CurrentVersionID)
	for i, id := range accountIDs {
		assert.Equal(t, *reloaded.CurrentVersionID, effectiveVersionOf(t, db, id),
			"第 %d 台的就位版本必須一併改指新版本", i+1)
	}

	// 三台實際取到的秘密都是新的（就位指標與取密路徑同一個答案）
	for _, id := range accountIDs {
		var binding model.AssetAccount
		require.NoError(t, db.First(&binding, id).Error)
		got, gerr := assets.GetWithCredentialsForAccount(binding.AssetID, binding.ID)
		require.NoError(t, gerr)
		assert.Equal(t, "new-pw", got.Password)
	}

	// 舊版本列的密文原封不動（版本不可變）
	versions := credentialVersionIDs(t, db, shared.ID)
	require.Len(t, versions, 2)
	var v1 model.CredentialSecretVersion
	require.NoError(t, db.First(&v1, versions[0]).Error)
	assert.NotEmpty(t, v1.PasswordEnc, "舊版本的密文不得被就地覆寫")
	assert.NotEqual(t, *reloaded.CurrentVersionID, v1.ID)
}

// --- 測試輔助 ---

func credentialIDOf(t *testing.T, db *gorm.DB, accountID uint) uint {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	require.NotZero(t, account.CredentialID)
	return account.CredentialID
}

func effectiveVersionOf(t *testing.T, db *gorm.DB, accountID uint) uint {
	t.Helper()
	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	if account.EffectiveVersionID == nil {
		return 0
	}
	return *account.EffectiveVersionID
}

func credentialVersionIDs(t *testing.T, db *gorm.DB, credentialID uint) []uint {
	t.Helper()
	var versions []model.CredentialSecretVersion
	require.NoError(t, db.Where("credential_id = ?", credentialID).
		Order("version_no ASC").Find(&versions).Error)
	out := make([]uint, 0, len(versions))
	for i := range versions {
		out = append(out, versions[i].ID)
	}
	return out
}

func credentialBindings(t *testing.T, db *gorm.DB, credentialID uint) []model.AssetAccount {
	t.Helper()
	var bindings []model.AssetAccount
	require.NoError(t, db.Where("credential_id = ?", credentialID).
		Order("id ASC").Find(&bindings).Error)
	return bindings
}
