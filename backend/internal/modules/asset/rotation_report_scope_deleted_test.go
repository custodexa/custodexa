package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRotationReportExcludesSoftDeletedAssets 母體只含掛在**未刪除資產**上的帳號。
//
// 已軟刪除的資產在資產管理頁看不到、連不上，也沒人能去改它的密碼；把它的帳號
// 判成「無記錄」會同時污染例外清單與兩種合規率。雙向斷言：存活資產的帳號必須
// 仍在母體內，否則一個把母體整個清空的實作也會通過。
func TestRotationReportExcludesSoftDeletedAssets(t *testing.T) {
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")

	alive := f.asset(t, "存活主機")
	aliveAcc := f.account(t, alive.ID, "alive-acct")
	f.success(t, aliveAcc, asOf.Add(-10*24*time.Hour))

	gone := f.asset(t, "已刪主機")
	goneAcc := f.account(t, gone.ID, "ghost-acct")
	require.NoError(t, f.db.Delete(gone).Error)

	rep := f.build(t, ReportScope{}, asOf)

	assert.Equal(t, 1, rep.Summary.TotalAccounts, "母體應只含未刪除資產上的帳號")
	require.Len(t, rep.Rows, 1)
	assert.Equal(t, aliveAcc.ID, rep.Rows[0].AccountID, "存活資產的帳號必須留在母體")
	assert.Equal(t, "<not-in-report>", bucketOfAccount(rep, goneAcc.ID),
		"已刪除資產的帳號不得進入母體")

	// 合規率不得被幽靈帳號稀釋：唯一的帳號合規，兩種率都應是 1
	require.NotNil(t, rep.Summary.RateCountingNoRecord)
	require.NotNil(t, rep.Summary.RateExcludingNoRecord)
	assert.InDelta(t, 1.0, *rep.Summary.RateCountingNoRecord, 1e-9)
	assert.InDelta(t, 1.0, *rep.Summary.RateExcludingNoRecord, 1e-9)
	assert.Equal(t, 0, rep.Summary.NoRecord, "幽靈帳號會以無記錄之姿混進來")
}
