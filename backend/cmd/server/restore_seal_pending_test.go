package main

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/require"
)

// hookSealer 附 SetAfterSealHook 的封章替身：模擬 CheckpointService 的「任一次封章成功後回呼」。
type hookSealer struct {
	recordingSealer
	onSealed func()
}

func (h *hookSealer) SetAfterSealHook(fn func()) { h.onSealed = fn }

func (h *hookSealer) SealNow() (*model.AuditCheckpoint, error) {
	cp, err := h.recordingSealer.SealNow()
	if err == nil && h.onSealed != nil {
		h.onSealed()
	}
	return cp, err
}

type fakeFailures struct{ reports, resolves []string }

func (f *fakeFailures) Report(mechanism, cause string, _ map[string]string) {
	f.reports = append(f.reports, mechanism+"/"+cause)
}
func (f *fakeFailures) ResolveFailure(mechanism string) { f.resolves = append(f.resolves, mechanism) }

type fakeAudit struct{ entries []*audit.AuditLogEntry }

func (f *fakeAudit) Log(e *audit.AuditLogEntry) { f.entries = append(f.entries, e) }

// 還原後待封狀態持久化：事件記成功後、封章成功前重啟，啟動時補封；
// 補封失敗不阻擋開放，改為告警與審計各一筆，下次封章成功時清除。
func TestRestoreSealPendingPersisted(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*hookSealer, *fakeFailures, *fakeAudit, restoreSealer, func() *stage1) {
		db := oneShotDB(t)
		old := database.DB
		database.DB = db
		t.Cleanup(func() { database.DB = old })
		calls := []string{}
		hs := &hookSealer{recordingSealer: recordingSealer{calls: &calls}}
		ff, fa := &fakeFailures{}, &fakeAudit{}
		start := func() *stage1 {
			s1 := &stage1{}
			require.NoError(t, completeRestoreBeforeStage2(ctx, s1))
			return s1
		}
		return hs, ff, fa, restoreSealWrap(hs, ff, fa), start
	}
	status := func() string { return authStateRow(t, database.DB).RestoreStatus }
	next := func() error { return nil }

	t.Run("記成功後封章失敗，重啟啟動時補封成功並清除待封", func(t *testing.T) {
		hs, ff, fa, c, start := setup(t)
		_, _, err := authz.CommitRestoreOnce(database.DB, "op-a", "d")
		require.NoError(t, err)
		hs.fail = true
		require.NoError(t, sealBeforeFirstStart(start(), c, next)(), "封章失敗不阻擋開放")
		require.Equal(t, authz.RestoreStatusSealPending, status(), "待封狀態在資料庫，不只在記憶體")
		require.Len(t, ff.reports, 1)
		require.Len(t, fa.entries, 1)

		// 行程重啟：新的 stage1 從資料庫重設待封旗標。
		hs.fail = false
		hs.onSealed = nil
		s2 := start()
		require.True(t, s2.restoreSealPending, "重啟後仍知道待封")
		require.NoError(t, sealBeforeFirstStart(s2, c, next)())
		require.Equal(t, authz.RestoreStatusDone, status())
		require.Equal(t, []string{model.MechanismRestoreSeal}, ff.resolves)
		require.Len(t, ff.reports, 1)
		require.Len(t, fa.entries, 1)
	})

	t.Run("補封仍失敗：照常開放，每次啟動告警與審計各一筆，之後例行封章成功才清除", func(t *testing.T) {
		hs, ff, fa, c, start := setup(t)
		_, _, err := authz.CommitRestoreOnce(database.DB, "op-b", "d")
		require.NoError(t, err)
		hs.fail = true
		s1 := start()
		opened := false
		require.NoError(t, sealBeforeFirstStart(s1, c, func() error { opened = true; return nil })())
		require.True(t, opened, "封章失敗仍開放（啟動第一個背景工作）")
		require.NoError(t, sealAfterRestore(s1, c, next)(), "檢查點步驟同樣不阻擋，也不重複上報")
		require.Len(t, ff.reports, 1)
		require.Len(t, fa.entries, 1)
		require.Equal(t, model.MechanismRestoreSeal+"/"+model.CauseRestoreSealDeferred, ff.reports[0])
		require.Equal(t, model.ResourceAuditFailure, fa.entries[0].Resource)
		require.Equal(t, model.StatusFailure, fa.entries[0].Status)

		// 再重啟仍失敗：仍開放、狀態仍待封。
		require.NoError(t, sealBeforeFirstStart(start(), c, next)())
		require.Equal(t, authz.RestoreStatusSealPending, status())
		require.Len(t, fa.entries, 2)

		// 例行封章（排程器）成功：回呼清除待封與告警。
		hs.fail = false
		_, err = hs.SealNow()
		require.NoError(t, err)
		require.Equal(t, authz.RestoreStatusDone, status())
		require.Equal(t, []string{model.MechanismRestoreSeal}, ff.resolves)
	})

	t.Run("讀不到待封狀態：不擋啟動，告警與審計各一筆，照待封補封，成功即結案", func(t *testing.T) {
		hs, ff, fa, c, start := setup(t)
		// 讀取失敗只發生在啟動那一刻（之後資料庫恢復）
		require.NoError(t, database.DB.Exec(`ALTER TABLE authz_state RENAME TO authz_state_hidden`).Error)
		s1 := start()
		require.NoError(t, database.DB.Exec(`ALTER TABLE authz_state_hidden RENAME TO authz_state`).Error)
		require.True(t, s1.restoreSealPending, "讀不到就照可能待封處理")
		opened := false
		require.NoError(t, sealBeforeFirstStart(s1, c, func() error { opened = true; return nil })())
		require.True(t, opened, "不阻擋開放")
		require.Equal(t, []string{model.MechanismRestoreSeal + "/" + model.CauseRestoreSealStateUnreadable}, ff.reports)
		require.Len(t, fa.entries, 1)
		require.Equal(t, model.ResourceAuditFailure, fa.entries[0].Resource)
		require.Contains(t, fa.entries[0].Details, model.CauseRestoreSealStateUnreadable)
		require.Contains(t, *hs.calls, "seal", "已嘗試補封")
		require.Equal(t, []string{model.MechanismRestoreSeal}, ff.resolves, "補封成功即結案")
		require.NoError(t, sealAfterRestore(s1, c, next)())
		require.Len(t, ff.reports, 1, "同一次啟動只上報一次")
	})

	t.Run("沒有待封時啟動行為不變", func(t *testing.T) {
		hs, ff, fa, c, start := setup(t)
		s1 := start()
		require.False(t, s1.restoreSealPending)
		require.NoError(t, sealBeforeFirstStart(s1, c, next)())
		require.NoError(t, sealAfterRestore(s1, c, next)())
		require.Empty(t, *hs.calls, "不封章、不確認創世")
		require.Empty(t, ff.reports)
		require.Empty(t, fa.entries)
		require.Empty(t, status())
	})
}
