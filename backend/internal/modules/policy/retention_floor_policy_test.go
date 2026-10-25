package policy

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
)

// newFloorPolicyDB 檔案型 SQLite（避開 :memory: 每條連線各一份資料庫的連線池陷阱）。
func newFloorPolicyDB(t *testing.T) (*SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "floor.db")), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}))
	return NewSecurityPolicyService(db), db
}

// TestRetentionFloorPolicy 擋：四個資料保留鍵接受 1–6 天、0（永久）或上下界合法值被擋、
// 改庫寫入的非法值被當成有效值讀出、播種的非法值落庫。
func TestRetentionFloorPolicy(t *testing.T) {
	floorKeys := []string{
		PolicyRetentionAuditLogDays, PolicyRetentionSessionCommandDays,
		PolicyRetentionAlertDays, PolicyRetentionRecordingDays,
	}

	for _, key := range floorKeys {
		key := key
		t.Run(key+"/1 與 6 被拒且同批另一合法鍵不生效", func(t *testing.T) {
			svc, db := newFloorPolicyDB(t)
			// 明確播種兩鍵的列，零變更以資料庫實值斷言（不讀服務快取）
			require.NoError(t, db.Save(&model.SecurityPolicy{Key: PolicyLockoutMaxAttempts, Value: "10", UpdatedBy: "seed"}).Error)
			require.NoError(t, db.Save(&model.SecurityPolicy{Key: key, Value: "30", UpdatedBy: "seed"}).Error)
			dbValue := func(k string) string {
				var row model.SecurityPolicy
				require.NoError(t, db.Where("key = ?", k).First(&row).Error)
				return row.Value
			}
			for _, bad := range []string{"1", "6"} {
				_, err := svc.UpdateBatchAudited(map[string]string{key: bad, PolicyLockoutMaxAttempts: "5"},
					PolicyActor{ID: 1, Name: "tester"}, floorNoopAuditor)
				var invalid *PolicyInvalidValueError
				require.True(t, errors.As(err, &invalid), "值 %s 應回 PolicyInvalidValueError，實得 %v", bad, err)
				assert.Equal(t, key, invalid.Key)
				assert.Equal(t, "10", dbValue(PolicyLockoutMaxAttempts), "同批的合法鍵不得落庫")
				assert.Equal(t, "30", dbValue(key), "非法保留值不得落庫")
			}
		})
		t.Run(key+"/0、7、3650 可儲存", func(t *testing.T) {
			svc, _ := newFloorPolicyDB(t)
			svc.SetHighRiskAlertRaiser(&relaxAlertRecorder{})
			for _, ok := range []string{"0", "7", "3650"} {
				_, err := svc.UpdateBatchAudited(map[string]string{key: ok}, PolicyActor{ID: 1, Name: "tester"}, floorNoopAuditor)
				require.NoError(t, err, "值 %s 應合法", ok)
				assert.Equal(t, ok, strconv.Itoa(svc.GetInt(key)))
			}
		})
		t.Run(key+"/改庫寫入 3 後讀值退回最後已知合法值，沒有時為出廠預設", func(t *testing.T) {
			def := findDef(key)
			// 沒有最後已知合法值：出廠預設
			svc, db := newFloorPolicyDB(t)
			require.NoError(t, db.Save(&model.SecurityPolicy{Key: key, Value: "3", UpdatedBy: "sql"}).Error)
			assert.Equal(t, def.Default, strconv.Itoa(svc.GetInt(key)))

			// 有最後已知合法值：退回該值
			svc2, db2 := newFloorPolicyDB(t)
			svc2.cacheTTL = 0
			require.NoError(t, db2.Save(&model.SecurityPolicy{Key: key, Value: "30", UpdatedBy: "sql"}).Error)
			require.Equal(t, 30, svc2.GetInt(key))
			require.NoError(t, db2.Save(&model.SecurityPolicy{Key: key, Value: "3", UpdatedBy: "sql"}).Error)
			assert.Equal(t, 30, svc2.GetInt(key))
		})
	}

	t.Run("播種 3 被忽略，錄影保留仍為出廠值", func(t *testing.T) {
		svc, db := newFloorPolicyDB(t)
		t.Setenv("RECORDING_RETENTION_DAYS", "3")
		svc.SeedFromEnv(PolicyRetentionRecordingDays, "RECORDING_RETENTION_DAYS")
		var n int64
		require.NoError(t, db.Model(&model.SecurityPolicy{}).Where("key = ?", PolicyRetentionRecordingDays).Count(&n).Error)
		assert.Zero(t, n, "非法播種值不得落庫")
		assert.Equal(t, 90, svc.GetInt(PolicyRetentionRecordingDays))
	})
}

func floorNoopAuditor(_ *gorm.DB, _ PolicyChange) error { return nil }
