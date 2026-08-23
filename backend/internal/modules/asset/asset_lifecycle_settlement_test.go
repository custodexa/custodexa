package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 停用即收線（塊 1）。
//
// 塊 2（刪除即失效授權）的測試在 `internal/modules/authz`——那裡才有權限查詢
// 與其姊妹查詢，且 authz 已 import asset，反向 import 會循環。

// fakeTerminator 記錄收線呼叫，使「不該收線時零呼叫」成為可斷言的事實
// （只斷言「沒有錯誤」會讓漏接與正確行為無法區分）
type fakeTerminator struct {
	calls   []uint
	reasons []string
	nextErr error
	nextN   int
}

func (f *fakeTerminator) TerminateByAsset(assetID uint, reason string) (int, error) {
	f.calls = append(f.calls, assetID)
	f.reasons = append(f.reasons, reason)
	if f.nextErr != nil {
		return 0, f.nextErr
	}
	return f.nextN, nil
}

func setupLifecycleDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAuthorization{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func newLifecycleService(t *testing.T) *AssetService {
	t.Helper()
	key := make([]byte, 32)
	svc, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	return svc
}

func mkLifecycleAsset(t *testing.T, db *gorm.DB, name string, active bool) *model.Asset {
	t.Helper()
	a := &model.Asset{
		Name: name, Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22,
		Username: "root", Active: active,
	}
	require.NoError(t, db.Create(a).Error)
	return a
}

// ── 塊 1：停用即收線 ──────────────────────────────────────────────────────

func TestUpdate_DisableTransitionTerminatesSessions(t *testing.T) {
	db := setupLifecycleDB(t)
	svc := newLifecycleService(t)
	term := &fakeTerminator{nextN: 2}
	svc.SetSessionTerminator(term)

	a := mkLifecycleAsset(t, db, "disable-me", true)

	inactive := false
	_, err := svc.Update(context.Background(), a.ID, &UpdateAssetRequest{Active: &inactive})
	require.NoError(t, err)

	require.Equal(t, []uint{a.ID}, term.calls,
		"active true→false 的躍遷必須觸發該資產的收線")
	require.Equal(t, []string{model.EndReasonAssetDisabled}, term.reasons,
		"收線理由須可與管理員手動終止、授權撤銷收線區分")
}

// 已停用資產的其他編輯不得重複收線：**斷言終止器零呼叫**，
// 而非只斷言沒有錯誤——後者在漏接躍遷判定時照樣通過
func TestUpdate_NonTransitionDoesNotTerminate(t *testing.T) {
	db := setupLifecycleDB(t)
	svc := newLifecycleService(t)
	term := &fakeTerminator{}
	svc.SetSessionTerminator(term)

	a := mkLifecycleAsset(t, db, "already-off", false)

	desc := "只改描述"
	_, err := svc.Update(context.Background(), a.ID, &UpdateAssetRequest{Description: &desc})
	require.NoError(t, err)
	require.Empty(t, term.calls, "對已停用資產的一般編輯不得觸發收線")

	// 反向躍遷（false→true）同樣不收線
	active := true
	_, err = svc.Update(context.Background(), a.ID, &UpdateAssetRequest{Active: &active})
	require.NoError(t, err)
	require.Empty(t, term.calls, "啟用資產不得觸發收線")
}

// 收線失敗不回滾停用：停用的主要目標是阻斷後續存取，收線是縱深
func TestUpdate_TerminateFailureDoesNotBlockDisable(t *testing.T) {
	db := setupLifecycleDB(t)
	svc := newLifecycleService(t)
	svc.SetSessionTerminator(&fakeTerminator{nextErr: errors.New("收線失敗")})

	a := mkLifecycleAsset(t, db, "fail-close", true)

	inactive := false
	got, err := svc.Update(context.Background(), a.ID, &UpdateAssetRequest{Active: &inactive})
	require.NoError(t, err, "收線失敗不得使停用本身失敗")
	require.False(t, got.Active)

	var reloaded model.Asset
	require.NoError(t, db.First(&reloaded, a.ID).Error)
	require.False(t, reloaded.Active, "停用須已落庫")
}

// 未注入終止器時不 panic（測試建構路徑與封印期佔位）
func TestUpdate_NilTerminatorIsSafe(t *testing.T) {
	db := setupLifecycleDB(t)
	svc := newLifecycleService(t)

	a := mkLifecycleAsset(t, db, "no-terminator", true)
	inactive := false
	_, err := svc.Update(context.Background(), a.ID, &UpdateAssetRequest{Active: &inactive})
	require.NoError(t, err)
}

// ── 塊 2 的消費者側：資產刪除的 authz 級聯撤銷 ──────────────────────────────
//
// 撤銷的**行為驗證**（權限查詢是否還命中）在 `internal/modules/authz`——那裡才有
// 權限查詢，且 authz 已 import asset，反向 import 會循環。此處只驗 asset 側的契約：
// 有注入就呼叫、沒注入就 fail-close。

// fakeAuthzRevoker 記錄級聯撤銷呼叫
type fakeAuthzRevoker struct {
	calls   []uint
	nextErr error
}

func (f *fakeAuthzRevoker) RevokeByAsset(tx *gorm.DB, assetID uint) (int64, int64, error) {
	f.calls = append(f.calls, assetID)
	if f.nextErr != nil {
		return 0, 0, f.nextErr
	}
	return 2, 1, nil
}

// 未注入撤銷面時 Delete 必須失敗：靜默略過會留下幽靈授權與懸掛審核範圍，
// 而那正是本塊要消滅的缺陷
func TestDelete_FailsClosedWithoutAuthzRevoker(t *testing.T) {
	db := setupLifecycleDB(t)
	svc := newLifecycleService(t)

	a := mkLifecycleAsset(t, db, "no-revoker", true)
	err := svc.Delete(a.ID)
	require.Error(t, err, "未注入 authz 級聯撤銷面時，刪除不得成功")

	var count int64
	require.NoError(t, db.Model(&model.Asset{}).Where("id = ?", a.ID).Count(&count).Error)
	require.Equal(t, int64(1), count, "刪除失敗時資產須維持存在（交易回滾）")
}
