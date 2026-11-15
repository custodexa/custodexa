package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 資產更新與帳號端點並發：帳號端點把預設帳號的名稱與秘密旗標鏡射到資產時不推進資產的更新時間。
// 資產更新的檢核與整列寫入必須以鎖內讀到的現況為底，不論更新時間有沒有變；否則以交易外的舊副本判定
// （放過壞值或誤擋合法更新），整列寫入還會把鏡射值蓋回舊值。
//
// 交錯方式：資產更新的交易外讀取（第一次非鎖定的資產查詢）完成之後、交易開始之前，以真實的帳號服務
// 完成一次帳號更新並提交。

type concurrentAccountFixture struct {
	t        *testing.T
	db       *gorm.DB
	assets   *AssetService
	accounts *AssetAccountService
}

func newConcurrentAccountFixture(t *testing.T) *concurrentAccountFixture {
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(&model.AssetAuthorization{}))
	assets, accounts := newAccountServices(t)
	return &concurrentAccountFixture{t: t, db: db, assets: assets, accounts: accounts}
}

func (f *concurrentAccountFixture) create(req *CreateAssetRequest) *model.Asset {
	f.t.Helper()
	req.Host, req.CreatedBy = "198.51.100.41", 1
	a, err := f.assets.Create(WithSystemCaller(context.Background()), req)
	require.NoError(f.t, err)
	return a
}

func (f *concurrentAccountFixture) defaultAccountID(assetID uint) uint {
	f.t.Helper()
	var acc model.AssetAccount
	require.NoError(f.t, f.db.Where("asset_id = ? AND is_default = ?", assetID, true).First(&acc).Error)
	return acc.ID
}

func (f *concurrentAccountFixture) load(id uint) model.Asset {
	f.t.Helper()
	var a model.Asset
	require.NoError(f.t, f.db.First(&a, id).Error)
	return a
}

// interleave 在下一次非鎖定的資產查詢完成後執行 fn 一次（資產更新的交易外讀取）。回傳是否已執行。
func (f *concurrentAccountFixture) interleave(fn func()) *bool {
	f.t.Helper()
	fired := false
	name := "test:account_update_between_read_and_lock"
	require.NoError(f.t, f.db.Callback().Query().After("gorm:query").Register(name, func(db *gorm.DB) {
		if fired || db.Statement.Table != "assets" {
			return
		}
		if _, locking := db.Statement.Clauses["FOR"]; locking {
			return
		}
		fired = true
		fn()
	}))
	f.t.Cleanup(func() { _ = f.db.Callback().Query().Remove(name) })
	return &fired
}

func accountCtx() context.Context {
	return WithFieldCapability(adminCtx(), func(string) FieldCapGrant { return FieldCapViaCompat })
}

func TestUpdateRebasesOnLockedRowWhenAccountMirrorKeepsUpdatedAt(t *testing.T) {
	t.Run("account_adds_password_then_asset_clears_username_is_rejected", func(t *testing.T) {
		f := newConcurrentAccountFixture(t)
		a := f.create(&CreateAssetRequest{Name: "ssh-mirror", Protocol: model.ProtocolSSH, Port: 22, Username: "root"})
		require.False(t, f.load(a.ID).HasPassword, "前提：建立時沒有秘密")
		accID := f.defaultAccountID(a.ID)
		before := f.load(a.ID)

		fired := f.interleave(func() {
			_, err := f.accounts.Update(accountCtx(), a.ID, accID, &UpdateAssetAccountRequest{Password: strp("fixture-only-secret")})
			require.NoError(t, err)
			mid := f.load(a.ID)
			require.True(t, mid.HasPassword, "前提：帳號端點已把秘密旗標鏡射到資產")
			require.True(t, mid.UpdatedAt.Equal(before.UpdatedAt), "前提：鏡射不推進資產的更新時間")
		})

		_, err := f.assets.Update(uvCtx(), a.ID, &UpdateAssetRequest{Username: strp("")})
		require.True(t, *fired, "前提：交易外讀取之後確實插入了帳號更新")
		require.True(t, errors.Is(err, ErrUsernameRequired), "鎖內現況已有秘密，清空帳號名稱應被拒，得 %v", err)

		got := f.load(a.ID)
		assert.True(t, got.HasPassword, "鏡射的秘密旗標不得被蓋回舊值")
		assert.Equal(t, "root", got.Username)
		var acc model.AssetAccount
		require.NoError(t, f.db.First(&acc, accID).Error)
		assert.Equal(t, "root", acc.Username, "預設帳號名稱不得被改成空")
	})

	t.Run("account_renames_then_asset_switches_to_ssh_is_accepted", func(t *testing.T) {
		f := newConcurrentAccountFixture(t)
		a := f.create(&CreateAssetRequest{Name: "vnc-mirror", Protocol: model.ProtocolVNC, Port: 5900, Password: "fixture-only-secret"})
		require.Equal(t, "", f.load(a.ID).Username, "前提：建立時帳號名稱為空")
		accID := f.defaultAccountID(a.ID)
		before := f.load(a.ID)

		fired := f.interleave(func() {
			_, err := f.accounts.Update(accountCtx(), a.ID, accID, &UpdateAssetAccountRequest{Username: strp("alice")})
			require.NoError(t, err)
			mid := f.load(a.ID)
			require.Equal(t, "alice", mid.Username, "前提：帳號端點已把帳號名稱鏡射到資產")
			require.True(t, mid.UpdatedAt.Equal(before.UpdatedAt), "前提：鏡射不推進資產的更新時間")
		})

		resp, err := f.assets.Update(uvCtx(), a.ID, &UpdateAssetRequest{Protocol: protop(model.ProtocolSSH), Port: intp(22)})
		require.True(t, *fired, "前提：交易外讀取之後確實插入了帳號更新")
		require.NoError(t, err, "鎖內現況已有帳號名稱，改為 SSH 應放行")
		assert.Equal(t, "alice", resp.Username, "回應帶鎖內現況的帳號名稱")

		got := f.load(a.ID)
		assert.Equal(t, model.ProtocolSSH, got.Protocol)
		assert.Equal(t, "alice", got.Username, "鏡射的帳號名稱不得被蓋回舊值")
		assert.True(t, got.HasPassword)
	})
}
