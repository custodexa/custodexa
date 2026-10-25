package asset

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 計畫授權脈絡只記下判定器確實放行的能力鍵：建立或修改計畫不因缺能力被擋（撤權由執行時重驗負責），
// 但證據列不得寫下一次沒有發生的確認。
func TestPlanAuthorizationRecordsOnlyConfirmedCapabilities(t *testing.T) {
	t.Run("能力通過：記下所確認的能力鍵", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.40.1", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("確認通過", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.JSONEq(t, `["account:rotate"]`, f.authRow(t, plan.AuthorizationID).Capabilities)
	})

	t.Run("建立時缺目標改密能力：計畫照存，脈絡不記未通過的能力鍵", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.40.2", "ops")
		f.authz.deny(CredCapAccountRotate)
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("確認未過", []uint{a1}, "ops"))
		require.NoError(t, err, "建立不因缺能力被擋")
		row := f.authRow(t, plan.AuthorizationID)
		assert.Equal(t, uint(5), row.ActorID, "發起者照記")
		assert.JSONEq(t, `[]`, row.Capabilities, "未通過的能力鍵不得寫入脈絡")
		assert.NotContains(t, row.Capabilities, CredCapAccountRotate)
	})

	t.Run("修改時缺能力：新版脈絡不記未通過的能力鍵", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.40.3", "ops")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("修改未過", []uint{a1}, "ops"))
		require.NoError(t, err)
		f.authz.deny(CredCapAccountRotate)
		updated, err := f.plans.Update(userCtx(6, "editor"), plan.ID, planRequest("修改未過", []uint{a1}, "ops"))
		require.NoError(t, err)
		row := f.authRow(t, updated.AuthorizationID)
		assert.Equal(t, uint(6), row.ActorID)
		assert.JSONEq(t, `[]`, row.Capabilities, "未通過的能力鍵不得寫入脈絡")
	})

	t.Run("判定失敗：無從確認，不記能力鍵", func(t *testing.T) {
		f := setupBatchFixture(t)
		a1, _ := f.addHost(t, "h1", "10.9.40.4", "ops")
		f.authz.err = errors.New("判定器暫時不可用")
		plan, err := f.plans.Create(userCtx(5, "creator"), planRequest("判定失敗", []uint{a1}, "ops"))
		require.NoError(t, err)
		assert.JSONEq(t, `[]`, f.authRow(t, plan.AuthorizationID).Capabilities)
	})
}
