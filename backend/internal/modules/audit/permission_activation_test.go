package audit_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 首次啟用與起點同交易提交（封章交易合一）。
//
// 啟用事件與它的第一個帶附證檢查點在同一交易提交：封章失敗整筆回滾，資料庫裡不會出現
// 「有啟用事件、沒有檢查點」的狀態，重試仍是起點且自動相符；已啟用環境內讀不到權限狀態時
// 整筆失敗、不留半狀態；未啟用時讀不到權限狀態則封出不帶附證的點，下一輪恢復時仍是起點。

// failSQL 讓 SQL 文字含 needle 的查詢（含 Raw().Scan）在執行前回錯；回傳的函式解除。
func failSQL(t *testing.T, db *gorm.DB, needle string) func() {
	t.Helper()
	name := "test:fail-sql:" + t.Name() + ":" + needle
	fn := func(d *gorm.DB) {
		if strings.Contains(d.Statement.SQL.String(), needle) {
			_ = d.AddError(errors.New("injected read failure"))
		}
	}
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(name, fn))
	require.NoError(t, db.Callback().Row().Before("gorm:row").Register(name, fn))
	off := func() {
		_ = db.Callback().Query().Remove(name)
		_ = db.Callback().Row().Remove(name)
	}
	t.Cleanup(off)
	return off
}

// failCheckpointInsert 讓下一次（之後每一次）INSERT audit_checkpoints 回錯；回傳的函式解除。
func failCheckpointInsert(t *testing.T, db *gorm.DB) func() {
	t.Helper()
	name := "test:fail-checkpoint-insert:" + t.Name()
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(name, func(d *gorm.DB) {
		if d.Statement.Table == "audit_checkpoints" {
			_ = d.AddError(errors.New("injected checkpoint insert failure"))
		}
	}))
	off := func() { _ = db.Callback().Create().Remove(name) }
	t.Cleanup(off)
	return off
}

func permRec(e *permEnv) (*audit.RoleStateReconciler, *fakeFailureSink) {
	fs := &fakeFailureSink{}
	rec := audit.NewRoleStateReconciler(e.db, nil)
	rec.SetStateFailureSink(fs)
	rec.SetPermissionAttestSigner(e.signer)
	return rec, fs
}

func TestPermissionActivationAtomic(t *testing.T) {
	ctx := context.Background()

	t.Run("全新安裝 genesis INSERT 失敗：啟用事件一併回滾，重啟後 genesis 仍是起點且相符", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		off := failCheckpointInsert(t, e.db)
		require.Error(t, e.svc.EnsureGenesis())
		require.Zero(t, e.count(t, "permission_state_events"), "啟用事件與檢查點同交易：檢查點沒落庫，啟用事件也不在")
		require.Zero(t, e.count(t, "audit_checkpoints"))
		off()
		// 失敗期間的合法權限寫入：鏈頭為空時不寫事件
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		require.Zero(t, e.count(t, "permission_state_events"))
		require.NoError(t, e.svc.EnsureGenesis())
		var g model.AuditCheckpoint
		require.NoError(t, e.db.First(&g, "seq = 1").Error)
		require.True(t, isTrue(g.PermOrigin), "重試仍是起點")
		require.Nil(t, g.PermReconciled)
		rec, fs := permRec(e)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State, "重試後自動相符")
		require.Empty(t, fs.permReports())
	})

	t.Run("升級後首個第四版點 INSERT 失敗：重試（期間有合法權限寫入）仍是起點且相符", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		audit.SetPermissionSources(nil, nil)
		audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
		require.NoError(t, e.svc.EnsureGenesis())
		_, err := e.svc.SealNow()
		require.NoError(t, err)
		audit.SetSealSchemeForTest(e.svc, "")
		newPermDBWire(t)
		off := failCheckpointInsert(t, e.db)
		_, err = e.svc.SealNow()
		require.Error(t, err)
		require.Zero(t, e.count(t, "permission_state_events"), "啟用事件一併回滾")
		require.EqualValues(t, 2, e.count(t, "audit_checkpoints"))
		off()
		require.NoError(t, e.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		require.Zero(t, e.count(t, "permission_state_events"), "鏈頭為空時合法寫入不寫事件")
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.Equal(t, model.AggSchemeV4, cp.AggScheme)
		require.True(t, isTrue(cp.PermOrigin), "舊鏈逐點驗章通過、無痕跡、無事件：重試仍是起點")
		rec, fs := permRec(e)
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.Empty(t, fs.permReports())
		next, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(next.PermReconciled), "下一點自起點起算而相符")
	})

	t.Run("已啟用環境內讀取權限狀態失敗：整筆回滾、無 null 點、無半狀態", func(t *testing.T) {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		cps, evs := e.count(t, "audit_checkpoints"), e.count(t, "permission_state_events")
		failSQL(t, e.db, "FROM role_permissions")
		_, err := e.svc.SealNow()
		require.Error(t, err, "有附證卻讀不到權限狀態：本輪不封章")
		require.Equal(t, cps, e.count(t, "audit_checkpoints"))
		require.Equal(t, evs, e.count(t, "permission_state_events"))
	})

	t.Run("尚未啟用時讀取權限狀態失敗：封出不帶附證的第四版點並留痕，恢復後下一輪仍是起點", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		rec, fs := permRec(e)
		e.svc.SetRoleStateReconciler(rec)
		off := failSQL(t, e.db, "FROM role_permissions")
		require.NoError(t, e.svc.EnsureGenesis(), "未啟用時讀取失敗不擋封章")
		off()
		var g model.AuditCheckpoint
		require.NoError(t, e.db.First(&g, "seq = 1").Error)
		require.Equal(t, model.AggSchemeV4, g.AggScheme)
		require.Nil(t, g.PermStateSnapshot)
		require.Nil(t, g.PermOrigin)
		require.Zero(t, e.count(t, "permission_state_events"))
		require.NotEmpty(t, fs.permReports(), "讀取失敗經失效事件通道留痕")
		cp, err := e.svc.SealNow()
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermOrigin), "null 點不是痕跡：下一輪仍是起點")
		require.Equal(t, "match", rec.ReconcilePermission(ctx).State)
		require.Equal(t, 1, fs.permResolved(), "恢復後結案")
	})
}

// checkpointChainStructure 是純函式：參數不含任何資料庫連線（鏈、修剪錨與完整性基準由呼叫端讀入）。
func TestCheckpointChainStructureIsPure(t *testing.T) {
	typ := reflect.TypeOf(audit.CheckpointChainStructureForTest)
	dbType := reflect.TypeOf((*gorm.DB)(nil))
	for i := 0; i < typ.NumIn(); i++ {
		require.NotEqual(t, dbType, typ.In(i), "第 %d 個參數是 *gorm.DB", i)
	}
	require.Equal(t, 4, typ.NumIn())
}

// 量測：升級後第一次封章（含整鏈逐點驗章）的牆鐘，千點與五千點（永久保留不修剪）兩種鏈長。
// 只記錄不設門檻；證據檔記數值（sqlite 單連線，數量級參考）。
func TestPermissionActivationCostMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("量測在 -short 下略過")
	}
	for _, n := range []int{1000, 5000} {
		e := newPermEnv(t)
		seedPerm(t, e.db, false)
		audit.SetPermissionSources(nil, nil)
		audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 1; i < n; i++ {
			_, err := e.svc.SealNow()
			require.NoError(t, err)
		}
		audit.SetSealSchemeForTest(e.svc, "")
		newPermDBWire(t)
		start := time.Now()
		cp, err := e.svc.SealNow()
		elapsed := time.Since(start)
		require.NoError(t, err)
		require.True(t, isTrue(cp.PermOrigin))
		start = time.Now()
		_, err = e.svc.SealNow()
		require.NoError(t, err)
		steady := time.Since(start)
		t.Logf("MEASURE chain=%d 升級後首次封章（整鏈逐點驗章）=%v；啟用後下一次封章=%v", n, elapsed, steady)
	}
}

// isTrue／isFalse 三態布林的斷言輔助：nil 不 panic（一個子測試 panic 會讓整包其餘測試不跑，
// 突變結果因此失真）。
func isTrue(p *bool) bool  { return p != nil && *p }
func isFalse(p *bool) bool { return p != nil && !*p }
