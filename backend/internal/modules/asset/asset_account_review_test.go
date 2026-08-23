package asset

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// 資產多帳號階段 2 安全審查所列問題的
// 回歸測試。每個測試對應一條 finding，且都是「舊行為會紅」的真偵測器。

// UpdatePassword 原子性：帳號在驗證後、寫入前被軟刪，必須回錯且不留成功審計。
// 舊寫法（交易外驗證＋不看 RowsAffected）會回 nil，runner 據此記 success——
// 遠端密碼已改、庫內卻沒有新密＝該機器永久鎖死而審計說一切正常。
func TestUpdatePasswordFailsWhenAccountRemovedMidFlight(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "atomic-1", Protocol: model.ProtocolSSH, Host: "10.0.1.1", Port: 22,
		Username: "root", Password: "old", CreatedBy: 1,
	})
	require.NoError(t, err)
	pinned, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)

	// runner 取完憑證、遠端已改密後，管理員刪掉該帳號（資產僅此一帳號，允許刪）
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, pinned.AccountID))

	err = assets.UpdatePassword(asset.ID, pinned.AccountID, pinned.Username, "new-pw")
	assert.ErrorIs(t, err, ErrAssetAccountNotFound, "帳號已消失時必須回錯，不得假成功")

	var passwordAudits int64
	require.NoError(t, db.Model(&model.AuditLog{}).
		Where("details LIKE ?", "%\"fields\":[\"password\"]%").Count(&passwordAudits).Error)
	assert.Zero(t, passwordAudits, "寫入零列時不得留下憑證更新審計")
}

// 上一項的延伸：只釘 AccountID 不夠——帳號在執行期間被改名時，
// 該列已代表另一個系統身分，新密不得寫進去
func TestUpdatePasswordFailsWhenAccountRenamedMidFlight(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "atomic-2", Protocol: model.ProtocolSSH, Host: "10.0.1.2", Port: 22,
		Username: "root", Password: "old", CreatedBy: 1,
	})
	require.NoError(t, err)
	pinned, err := assets.GetWithCredentialsDefault(asset.ID)
	require.NoError(t, err)

	renamed := "someone-else"
	_, err = accounts.Update(adminCtx(), asset.ID, pinned.AccountID,
		&UpdateAssetAccountRequest{Username: &renamed})
	require.NoError(t, err)

	err = assets.UpdatePassword(asset.ID, pinned.AccountID, pinned.Username, "new-pw")
	assert.ErrorIs(t, err, ErrAssetAccountNotFound, "帳號改名後不得把新密寫進已代表他人的列")

	var account model.AssetAccount
	require.NoError(t, db.First(&account, pinned.AccountID).Error)
	plain, err := assets.crypto.DecryptFor(context.Background(), keyvault.RefAccountPassword, account.PasswordEnc)
	require.NoError(t, err)
	assert.Equal(t, "old", plain, "改名的帳號憑證必須維持原值")
}

// 連線入口空憑證 fail-close（服務層側）：零帳號資產的 k8s 兩處、連測與
// SFTP 各自擋住。guacd／終端入口的對應守衛見 internal/proxy、internal/sshproxy。
func TestZeroAccountAssetRejectedByServicePaths(t *testing.T) {
	_ = setupAccountDB(t)
	assets, _ := newAccountServices(t)

	k8s, err := assets.Create(&CreateAssetRequest{
		Name: "k8s-zero", Protocol: model.ProtocolK8s, Host: "10.0.1.3", Port: 6443,
		K8sNamespace: "default", CreatedBy: 1,
	})
	require.NoError(t, err)

	_, err = assets.ListK8sPods(context.Background(), k8s.ID)
	assert.ErrorIs(t, err, ErrAssetNoUsableAccount, "空 token 不得以匿名身分打叢集")
	_, err = assets.k8sTarget(k8s.ID, "pod", "c")
	assert.ErrorIs(t, err, ErrAssetNoUsableAccount)

	vnc, err := assets.Create(&CreateAssetRequest{
		Name: "vnc-zero", Protocol: model.ProtocolVNC, Host: "10.0.1.4", Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)
	res, err := assets.testConnection(context.Background(), vnc.ID, 1)
	require.NoError(t, err)
	assert.False(t, res.Success, "零帳號資產撥測必須判失敗，不得用空密碼試出『成功』")
	assert.Equal(t, "no_usable_account", res.ErrorCode)

	// **搬檔**：原本此處還有一格「SFTP connect 對零帳號資產回同一個哨兵」。
	// SFTPService 屬 session 模組且該斷言要呼叫它的未匯出 connect，跨包取不到；
	// 等值斷言已移到 session 側 `internal/modules/session/sftp_zero_account_test.go` 的
	// `TestSFTPConnectRejectsZeroAccountAsset`，**未放寬**（同一哨兵、同一入口）。
}

// 併發不變式：set-default 與 delete 交錯，
// 「至多一 default」與「有帳號必有 default」都不得被破壞
func TestConcurrentSetDefaultAndDeleteKeepsInvariants(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "race-1", Protocol: model.ProtocolSSH, Host: "10.0.1.5", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	b, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "b", Password: "pw-b",
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = accounts.SetDefault(adminCtx(), asset.ID, b.ID)
	}()
	go func() {
		defer wg.Done()
		_ = accounts.Delete(adminCtx(), asset.ID, b.ID)
	}()
	wg.Wait()

	var live []model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).Find(&live).Error)
	defaults := 0
	for _, a := range live {
		if a.IsDefault {
			defaults++
		}
	}
	assert.LessOrEqual(t, defaults, 1, "至多一個 default")
	if len(live) > 0 {
		assert.Equal(t, 1, defaults, "有帳號必有 default")
		// 連線解析不得落入「有帳號但無預設」的破損態
		creds, err := assets.GetWithCredentialsDefault(asset.ID)
		require.NoError(t, err)
		assert.NotZero(t, creds.AccountID)
	}
}

// 併發建號：兩個 goroutine 同時對零帳號資產建首筆帳號，
// 不得出現「兩筆 default」或「唯一一筆非 default」
func TestConcurrentCreateFirstAccountKeepsSingleDefault(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "race-2", Protocol: model.ProtocolVNC, Host: "10.0.1.6", Port: 5901, CreatedBy: 1,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	for _, name := range []string{"first", "second"} {
		go func(username string) {
			defer wg.Done()
			_, _ = accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
				Username: username, Password: "pw-" + username,
			})
		}(name)
	}
	wg.Wait()

	var live []model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", asset.ID).Find(&live).Error)
	require.NotEmpty(t, live)
	defaults := 0
	for _, a := range live {
		if a.IsDefault {
			defaults++
		}
	}
	assert.Equal(t, 1, defaults, "首筆建號競態後必須恰有一個 default")
}

// 併發更新：改備註的提交不得把剛輪換的密文倒回舊值
// （舊寫法在交易外讀快照、交易內全欄覆寫，後提交者必然倒灌）
func TestConcurrentNoteUpdateDoesNotRollbackRotatedSecret(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "race-3", Protocol: model.ProtocolSSH, Host: "10.0.1.7", Port: 22,
		Username: "root", Password: "old-pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	accountID := list[0].ID

	rotated := "rotated-pw"
	note := "併發備註"
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = accounts.Update(adminCtx(), asset.ID, accountID,
			&UpdateAssetAccountRequest{Password: &rotated})
	}()
	go func() {
		defer wg.Done()
		_, _ = accounts.Update(adminCtx(), asset.ID, accountID,
			&UpdateAssetAccountRequest{Note: &note})
	}()
	wg.Wait()

	var account model.AssetAccount
	require.NoError(t, db.First(&account, accountID).Error)
	plain, err := assets.crypto.DecryptFor(context.Background(), keyvault.RefAccountPassword, account.PasswordEnc)
	require.NoError(t, err)
	assert.Equal(t, rotated, plain, "備註更新不得覆寫已輪換的憑證")
}

// 刪除唯一帳號時 assets.username 鏡射一併清空
func TestDeleteLastAccountClearsAssetIdentityMirror(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "mirror-1", Protocol: model.ProtocolSSH, Host: "10.0.1.8", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	list, err := accounts.List(asset.ID)
	require.NoError(t, err)
	require.NoError(t, accounts.Delete(adminCtx(), asset.ID, list[0].ID))

	var stored model.Asset
	require.NoError(t, db.First(&stored, asset.ID).Error)
	assert.Empty(t, stored.Username, "刪掉唯一帳號後不得殘留已不存在的身分")
	assert.False(t, stored.HasPassword)
}

// 複製建號的來源出處入審計：憑證跨資產複製必須留軌跡
func TestCopyAccountAuditRecordsSource(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	src, err := assets.Create(&CreateAssetRequest{
		Name: "copy-src", Protocol: model.ProtocolSSH, Host: "10.0.1.9", Port: 22,
		Username: "ops", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)
	dst, err := assets.Create(&CreateAssetRequest{
		Name: "copy-dst", Protocol: model.ProtocolSSH, Host: "10.0.1.10", Port: 22,
		Username: "root", Password: "pw2", CreatedBy: 1,
	})
	require.NoError(t, err)
	srcList, err := accounts.List(src.ID)
	require.NoError(t, err)

	copied, err := accounts.Create(adminCtx(), dst.ID, &CreateAssetAccountRequest{
		Username: "copied", CopyFromAccountID: srcList[0].ID,
	})
	require.NoError(t, err)

	var logs []model.AuditLog
	require.NoError(t, db.Where("details LIKE ?", "%copy_from_account_id%").Find(&logs).Error)
	require.Len(t, logs, 1, "複製建號必須留下帶來源的審計")
	assert.Contains(t, logs[0].Details, "\"copy_from_asset_id\":"+strconv.Itoa(int(src.ID)))
	assert.Contains(t, logs[0].Details, "\"copy_from_account_id\":"+strconv.Itoa(int(srcList[0].ID)))
	assert.Contains(t, logs[0].Details, "\"account_id\":"+strconv.Itoa(int(copied.ID)))
}

// 帳號名稱拒全部 C0/C1 控制字元與 DEL：
// tab／ESC 一樣會進 SSH 認證、UI 與審計快照，ESC 還能操縱讀 log 的終端
func TestAccountUsernameRejectsAllControlChars(t *testing.T) {
	_ = setupAccountDB(t)
	assets, accounts := newAccountServices(t)

	asset, err := assets.Create(&CreateAssetRequest{
		Name: "ctl-1", Protocol: model.ProtocolSSH, Host: "10.0.1.11", Port: 22,
		Username: "root", Password: "pw", CreatedBy: 1,
	})
	require.NoError(t, err)

	bad := []string{
		"a\tb",       // C0 tab
		"a\x1b[31mb", // ESC 序列
		"a\x07b",     // BEL
		"a\x7fb",     // DEL
		"ab",        // C1 CSI
		"a\nb",       // 既有：換行
		"a:b",        // 既有：冒號（chpasswd 條目分隔）
	}
	for _, name := range bad {
		_, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: name})
		assert.ErrorIsf(t, err, ErrAssetAccountUsernameInvalid, "應拒絕 %q", name)
	}
}
