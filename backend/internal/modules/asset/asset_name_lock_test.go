package asset

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// TestAssetNameUniqueUnderConcurrentCreateAndImport 擋「兩條路徑同時建同名資產都成功」：
// 單筆建立與一批含同名列的匯入並行，恰一方成功、DB 中該名稱恰一筆。
// 名稱沒有 DB 唯一鍵，靠的是名稱鎖＋交易內再查；兩者任一被拿掉，這裡就會出現兩筆
func TestAssetNameUniqueUnderConcurrentCreateAndImport(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)

	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("race-%02d", i)
		var createErr, importErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = assets.Create(adminCtx(), &CreateAssetRequest{
				Name: name, Protocol: model.ProtocolVNC, Host: "10.3.0.1", Port: 5900, CreatedBy: 1})
		}()
		go func() {
			defer wg.Done()
			_, importErr = assets.ImportAssets(adminCtx(), &ImportBatch{Source: ImportSourceForm, Rows: []ImportRow{
				{Name: fmt.Sprintf("race-other-%02d", i), Protocol: "ssh", Host: "10.3.0.2"},
				{Name: name, Protocol: "rdp", Host: "10.3.0.3"},
			}}, 1, "admin")
		}()
		wg.Wait()

		require.True(t, (createErr == nil) != (importErr == nil),
			"第 %d 輪：恰一方成功（create=%v import=%v）", i, createErr, importErr)
		if createErr != nil {
			require.ErrorIs(t, createErr, ErrAssetNameExists)
		} else {
			var invalid *ImportRowsInvalidError
			var changed *ImportStateChangedError
			require.True(t, errors.As(importErr, &invalid) || errors.As(importErr, &changed),
				"匯入以同名衝突被拒: %v", importErr)
		}
		var n int64
		require.NoError(t, db.Model(&model.Asset{}).Where("name = ?", name).Count(&n).Error)
		require.EqualValues(t, 1, n, "第 %d 輪：DB 中該名稱恰一筆", i)
	}
}
