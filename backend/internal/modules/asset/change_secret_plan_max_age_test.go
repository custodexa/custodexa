package asset

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChangeSecretPlanMaxAgeDaysBounds 計劃層天數覆蓋的值域：0（沿用全域）或 1–3650。
//
// 建立與更新兩條路徑都要擋——只擋一邊等於留一條「先建合法再改成越界」的路。
func TestChangeSecretPlanMaxAgeDaysBounds(t *testing.T) {
	svc := setupPlanDB(t)

	for _, ok := range []int{0, 1, 60, 3650} {
		plan, err := svc.Create(&ChangeSecretPlanRequest{
			Name: "ok-" + strconv.Itoa(ok), AssetIDs: []uint{1}, MaxAgeDays: ok,
		})
		require.NoError(t, err, "覆蓋 %d 天應被接受", ok)
		assert.Equal(t, ok, plan.MaxAgeDays, "值須落庫")
	}

	for _, bad := range []int{-1, 3651, 4000} {
		_, err := svc.Create(&ChangeSecretPlanRequest{
			Name: "bad-" + strconv.Itoa(bad), AssetIDs: []uint{1}, MaxAgeDays: bad,
		})
		if !errors.Is(err, ErrPlanBadMaxAgeDays) {
			t.Errorf("建立覆蓋 %d 天 = %v, want ErrPlanBadMaxAgeDays", bad, err)
		}
	}

	base, err := svc.Create(&ChangeSecretPlanRequest{
		Name: "update-target", AssetIDs: []uint{1}, MaxAgeDays: 90,
	})
	require.NoError(t, err)

	_, err = svc.Update(base.ID, &ChangeSecretPlanRequest{
		Name: "update-target", AssetIDs: []uint{1}, MaxAgeDays: 4000,
	})
	if !errors.Is(err, ErrPlanBadMaxAgeDays) {
		t.Errorf("更新為 4000 天 = %v, want ErrPlanBadMaxAgeDays", err)
	}

	reloaded, err := svc.Get(base.ID)
	require.NoError(t, err)
	assert.Equal(t, 90, reloaded.MaxAgeDays, "被拒的更新不得留下部分寫入")

	updated, err := svc.Update(base.ID, &ChangeSecretPlanRequest{
		Name: "update-target", AssetIDs: []uint{1}, MaxAgeDays: 0,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, updated.MaxAgeDays, "改回 0＝沿用全域")
}

// TestChangeSecretPlanMaxAgeDaysDefaultsToZero 未帶欄位＝沿用全域，
// 不得靜默變成別的值（既有計劃升級後行為與升級前一致）
func TestChangeSecretPlanMaxAgeDaysDefaultsToZero(t *testing.T) {
	svc := setupPlanDB(t)
	plan, err := svc.Create(&ChangeSecretPlanRequest{Name: "no-field", AssetIDs: []uint{1}})
	require.NoError(t, err)
	assert.Equal(t, 0, plan.MaxAgeDays)
}
