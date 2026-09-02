package scheduler

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 報告排程器的註冊面。
//
// 只驗「哪些排程會被註冊」——觸發的行為（區間、錨點、節流）在排程服務側逐條
// 釘過，在這裡重驗一次只會得到一份與時鐘賽跑的測試。

func newCronTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// `:memory:` 每條連線是各自獨立的空庫，收斂單連線
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.RotationReportSchedule{}, &model.AuditExportJob{}))
	return db
}

func TestRotationReportCronRegistersEnabledOnly(t *testing.T) {
	db := newCronTestDB(t)
	svc := asset.NewRotationReportScheduleService(db, audit.NewAuditExportJobService(db), nil)

	for _, row := range []model.RotationReportSchedule{
		{Name: "啟用", Cron: "0 1 1 * *", Enabled: true, ScopeKind: model.RotationScopeAll,
			RetentionDays: 30, Language: model.NotificationChannelLanguageZhTW},
		{Name: "停用", Cron: "0 2 1 * *", Enabled: false, ScopeKind: model.RotationScopeAll,
			RetentionDays: 30, Language: model.NotificationChannelLanguageZhTW},
	} {
		r := row
		_, err := svc.Create(&r)
		require.NoError(t, err)
	}

	s := NewRotationReportScheduler(svc)
	s.Reload()
	assert.Len(t, s.cron.Entries(), 1, "只有啟用的排程進 cron")

	// Reload 是重建而非累加：CRUD 後重複呼叫不得讓同一個排程被註冊兩次
	s.Reload()
	assert.Len(t, s.cron.Entries(), 1)

	s.Start()
	defer s.Stop()
	assert.Len(t, s.cron.Entries(), 1)
}
