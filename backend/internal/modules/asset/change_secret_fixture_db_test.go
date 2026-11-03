package asset

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 改密測試資料庫的選擇。預設行程內 sqlite；設了 CS_FIXTURE_PG_DSN 時改在該 PostgreSQL 上跑，
// 每個測試各用一個獨立 schema，結束即刪。用於需要實跑資料庫鎖與交易語義的驗收
// （例如共用執行身分的互斥）。環境變數刻意不沿用 TEST_PG_DSN，避免其他測試被動切換。
const envChangeSecretFixturePG = "CS_FIXTURE_PG_DSN"

func openChangeSecretFixtureDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv(envChangeSecretFixturePG)
	if dsn == "" {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		return db
	}
	sum := sha1.Sum([]byte(t.Name()))
	schema := "csfx_" + hex.EncodeToString(sum[:8])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if s, e := db.DB(); e == nil {
			_ = s.Close()
		}
		_ = admin.Exec(drop)
		if s, e := admin.DB(); e == nil {
			_ = s.Close()
		}
	})
	return db
}
