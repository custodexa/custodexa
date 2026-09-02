package asset

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證群組的行為鎖定：歸組只發生在複製建號，脫組只發生在系統改密成功提交，
// 手動編輯不動它。群組識別本身不出 API。

// newAssetWithAccount 建一台帶預設帳號的資產，回傳該帳號 id
func newAssetWithAccount(t *testing.T, assets *AssetService, accounts *AssetAccountService,
	name, host, password string) uint {
	t.Helper()
	a, err := assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22,
		Username: "ops", Password: password, CreatedBy: 1,
	})
	require.NoError(t, err)
	list, err := accounts.List(a.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	return list[0].ID
}

// groupOf 直讀帳號的群組值（不經 DTO——DTO 刻意不揭露它）
func groupOf(t *testing.T, db *gorm.DB, accountID uint) string {
	t.Helper()
	var acc model.AssetAccount
	require.NoError(t, db.First(&acc, accountID).Error)
	return acc.CredentialGroup
}

// 複製建號使來源與新帳號歸於同一群組；來源原本無群組時先為其產生一個
func TestCredentialGroupCopyJoins(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	srcAccountID := newAssetWithAccount(t, assets, accounts, "src", "10.1.0.1", "shared-pw")
	require.Empty(t, groupOf(t, db, srcAccountID), "建號當下不該有群組")

	dst, err := assets.Create(&CreateAssetRequest{
		Name: "dst", Protocol: model.ProtocolSSH, Host: "10.1.0.2", Port: 22,
		Username: "root", Password: "rootpw", CreatedBy: 1,
	})
	require.NoError(t, err)

	copied, err := accounts.Create(adminCtx(), dst.ID, &CreateAssetAccountRequest{
		CopyFromAccountID: srcAccountID,
	})
	require.NoError(t, err)

	group := groupOf(t, db, srcAccountID)
	assert.NotEmpty(t, group, "來源應被補上群組")
	assert.Equal(t, group, groupOf(t, db, copied.ID), "新帳號應與來源同群組")
	assert.True(t, copied.SharedCredential, "建號回應即應標示共用憑證")

	// 兩者在列表上都標示共用
	srcList, err := accounts.List(1)
	require.NoError(t, err)
	require.Len(t, srcList, 1)
	assert.True(t, srcList[0].SharedCredential)
}

// 改密成功提交即脫組；同群組的其他成員不受影響
func TestCredentialGroupLeaveOnSuccess(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	aID := newAssetWithAccount(t, assets, accounts, "a", "10.1.1.1", "shared-pw")
	assetB, err := assets.Create(&CreateAssetRequest{
		Name: "b", Protocol: model.ProtocolSSH, Host: "10.1.1.2", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	assetC, err := assets.Create(&CreateAssetRequest{
		Name: "c", Protocol: model.ProtocolSSH, Host: "10.1.1.3", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)

	b, err := accounts.Create(adminCtx(), assetB.ID, &CreateAssetAccountRequest{CopyFromAccountID: aID})
	require.NoError(t, err)
	c, err := accounts.Create(adminCtx(), assetC.ID, &CreateAssetAccountRequest{CopyFromAccountID: b.ID})
	require.NoError(t, err)

	group := groupOf(t, db, aID)
	require.NotEmpty(t, group)
	require.Equal(t, group, groupOf(t, db, b.ID))
	require.Equal(t, group, groupOf(t, db, c.ID))

	require.NoError(t, leaveCredentialGroup(db, b.ID))

	assert.Empty(t, groupOf(t, db, b.ID), "改密成功的帳號應脫離群組")
	assert.Equal(t, group, groupOf(t, db, aID), "其餘成員仍同群組")
	assert.Equal(t, group, groupOf(t, db, c.ID))
}

// 脫離後只剩一個成員時，該成員一併脫離——一個人的「共用」不是共用
func TestCredentialGroupDissolvesLastMember(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	aID := newAssetWithAccount(t, assets, accounts, "a", "10.1.2.1", "shared-pw")
	assetB, err := assets.Create(&CreateAssetRequest{
		Name: "b", Protocol: model.ProtocolSSH, Host: "10.1.2.2", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	b, err := accounts.Create(adminCtx(), assetB.ID, &CreateAssetAccountRequest{CopyFromAccountID: aID})
	require.NoError(t, err)
	require.NotEmpty(t, groupOf(t, db, aID))

	require.NoError(t, leaveCredentialGroup(db, b.ID))

	assert.Empty(t, groupOf(t, db, b.ID))
	assert.Empty(t, groupOf(t, db, aID), "只剩一員的群組應解散")

	list, err := accounts.List(1)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.False(t, list[0].SharedCredential, "解散後不再標示共用憑證")

	// 已無群組者再脫一次為 no-op，不得報錯
	require.NoError(t, leaveCredentialGroup(db, aID))
}

// 管理者手動編輯憑證不動群組：手動輸入的密碼可能仍是共用的，系統無從判定
func TestCredentialGroupManualEditKeeps(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	aID := newAssetWithAccount(t, assets, accounts, "a", "10.1.3.1", "shared-pw")
	assetB, err := assets.Create(&CreateAssetRequest{
		Name: "b", Protocol: model.ProtocolSSH, Host: "10.1.3.2", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	b, err := accounts.Create(adminCtx(), assetB.ID, &CreateAssetAccountRequest{CopyFromAccountID: aID})
	require.NoError(t, err)
	group := groupOf(t, db, aID)
	require.NotEmpty(t, group)

	newPassword := "manually-typed-pw"
	updated, err := accounts.Update(adminCtx(), assetB.ID, b.ID, &UpdateAssetAccountRequest{
		Password: &newPassword,
	})
	require.NoError(t, err)

	assert.Equal(t, group, groupOf(t, db, b.ID), "手動編輯不得改變群組")
	assert.Equal(t, group, groupOf(t, db, aID))
	assert.True(t, updated.SharedCredential, "仍標示共用憑證")
}

// 群組識別不出 API：回應只有布林投影，沒有群組值本身
func TestAssetAccountDTOHidesCredentialGroup(t *testing.T) {
	dto := NewAssetAccountDTO(&model.AssetAccount{
		ID: 7, AssetID: 3, Username: "ops",
		CredentialGroup: "9f1c0f5e-0000-4000-8000-000000000000",
	})
	require.True(t, dto.SharedCredential)

	raw, err := json.Marshal(dto)
	require.NoError(t, err)
	var keys map[string]any
	require.NoError(t, json.Unmarshal(raw, &keys))

	_, present := keys["credential_group"]
	assert.False(t, present, "回應不得含 credential_group 鍵")
	assert.NotContains(t, string(raw), "9f1c0f5e",
		"群組值不得以任何形式出現在回應中")
	assert.Equal(t, true, keys["shared_credential"], "只投影布林")
}

// 兩條提交成功路徑都要接上脫組。
//
// **這一支守的是接線而不是機制**：leaveCredentialGroup 自己有行為測試，但機制
// 存在與每條路徑有沒有接上它是兩個問題——接線被拿掉時上面那些測試全部照樣綠，
// 而報告會持續把已各自改密的帳號標成共用憑證。
func TestCredentialGroupLeaveIsWiredIntoBothCommitPaths(t *testing.T) {
	for _, path := range []string{
		"change_secret_runner.go",
		"change_secret_retry_runner.go",
	} {
		src, err := os.ReadFile(path)
		require.NoError(t, err, "讀不到被驗證對象即等於沒有守衛")
		if !strings.Contains(string(src), "noteCredentialGroupLeft(") {
			t.Errorf("%s 的提交成功路徑未呼叫 noteCredentialGroupLeft："+
				"改密成功卻不脫組，報告會持續把已各自改密的帳號標成共用憑證", path)
		}
	}
}
