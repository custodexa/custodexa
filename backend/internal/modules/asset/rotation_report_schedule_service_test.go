package asset

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 排程的區間錨點。
//
// 錨點是報告區間唯一的事實源：cron 只說「何時觸發」，說不出「上一次是什麼時候」。
// 以「觸發時刻往回推一個週期」計算，任何一次錯過的觸發都會在區間上留下一段
// 沒有報告涵蓋的空白，而空白在報告上看不出來。故本檔逐條釘住三個寫入點與
// 連續兩期的首尾相接。

type scheduleFixture struct {
	*reportFixture
	svc  *RotationReportScheduleService
	jobs *audit.AuditExportJobService
}

func newScheduleFixture(t *testing.T) *scheduleFixture {
	t.Helper()
	f := newReportFixture(t)
	require.NoError(t, f.db.AutoMigrate(&model.RotationReportSchedule{}, &model.AuditExportJob{}))
	jobs := audit.NewAuditExportJobService(f.db)
	return &scheduleFixture{reportFixture: f, svc: NewRotationReportScheduleService(f.db, jobs, f.builder), jobs: jobs}
}

func (f *scheduleFixture) create(t *testing.T, name string) *model.RotationReportSchedule {
	t.Helper()
	row, err := f.svc.Create(&model.RotationReportSchedule{
		Name: name, Cron: "0 1 1 * *", Enabled: true,
		ScopeKind: model.RotationScopeAll, RetentionDays: 400,
		Language: model.NotificationChannelLanguageZhTW,
	})
	require.NoError(t, err)
	return row
}

// jobFilter 讀回工作單的區間參數。
func jobFilterOf(t *testing.T, job *model.AuditExportJob) *ReportJobFilter {
	t.Helper()
	f, err := ParseReportJobFilter(job.FilterJSON)
	require.NoError(t, err)
	return f
}

func TestRotationScheduleAnchorAdvancesOnRun(t *testing.T) {
	f := newScheduleFixture(t)
	row := f.create(t, "月報")
	created := row.PeriodAnchor
	require.False(t, created.IsZero(), "建立時即須設錨點")

	trigger := time.Now().Add(time.Hour)
	job, err := f.svc.Trigger(row.ID, trigger)
	require.NoError(t, err)
	assert.Equal(t, uint(0), job.RequesterID, "排程產出的發起者記為系統")
	assert.Equal(t, "system", job.RequesterName)
	assert.Equal(t, model.ExportJobKindRotationReport, job.Kind)

	filter := jobFilterOf(t, job)
	assert.WithinDuration(t, created, filter.PeriodStart, time.Second, "區間起點＝原錨點")
	assert.WithinDuration(t, trigger, filter.PeriodEnd, time.Second, "區間迄點＝觸發時刻")
	assert.Equal(t, row.ID, filter.ScheduleID)

	after, err := f.svc.Get(row.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, trigger, after.PeriodAnchor, time.Second,
		"成功建單後錨點推進到本次觸發時刻——立即產出就是提前的一期")

	// 到期時刻以留存天數預定（打包完成時由 worker 自實際完成時刻重算）
	require.NotNil(t, job.ExpiresAt)
	assert.WithinDuration(t, trigger.AddDate(0, 0, 400), *job.ExpiresAt, time.Minute)
}

func TestRotationScheduleAnchorResetOnCronChange(t *testing.T) {
	f := newScheduleFixture(t)
	row := f.create(t, "月報")
	original := row.PeriodAnchor

	// 改 cron 以外的欄位：錨點不動
	same, err := f.svc.Update(row.ID, &model.RotationReportSchedule{
		Name: "月報", Cron: row.Cron, Enabled: true,
		ScopeKind: model.RotationScopeAll, RetentionDays: 30,
		Language: model.NotificationChannelLanguageJaJP,
	})
	require.NoError(t, err)
	assert.WithinDuration(t, original, same.PeriodAnchor, time.Second,
		"僅改留存與語言不得重設區間錨點")

	time.Sleep(2 * time.Millisecond)
	changed, err := f.svc.Update(row.ID, &model.RotationReportSchedule{
		Name: "週報", Cron: "0 1 * * 1", Enabled: true,
		ScopeKind: model.RotationScopeAll, RetentionDays: 30,
		Language: model.NotificationChannelLanguageJaJP,
	})
	require.NoError(t, err)
	assert.True(t, changed.PeriodAnchor.After(original),
		"cron 被改動時錨點重設為修改時刻，實得 %s（原 %s）", changed.PeriodAnchor, original)
}

func TestRotationScheduleConsecutivePeriodsContiguous(t *testing.T) {
	f := newScheduleFixture(t)
	row := f.create(t, "月報")

	first := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	second := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)

	j1, err := f.svc.Trigger(row.ID, first)
	require.NoError(t, err)
	// 第一張讓開，否則第二次觸發會被「同一排程至多一張進行中」擋下
	require.NoError(t, f.db.Model(&model.AuditExportJob{}).Where("id = ?", j1.ID).
		Update("status", model.ExportJobDone).Error)

	j2, err := f.svc.Trigger(row.ID, second)
	require.NoError(t, err)

	f1, f2 := jobFilterOf(t, j1), jobFilterOf(t, j2)
	assert.True(t, f1.PeriodEnd.Equal(f2.PeriodStart),
		"第二期的起點須等於第一期的迄點（無重疊無漏洞）：%s vs %s", f1.PeriodEnd, f2.PeriodStart)
	assert.True(t, f2.PeriodEnd.Equal(second))
	assert.True(t, f1.PeriodStart.Before(f1.PeriodEnd))
}

func TestRotationScheduleOneInflightPerSchedule(t *testing.T) {
	f := newScheduleFixture(t)
	a := f.create(t, "月報-甲")
	b := f.create(t, "月報-乙")

	_, err := f.svc.Trigger(a.ID, time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	_, err = f.svc.Trigger(a.ID, time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC))
	require.ErrorIs(t, err, ErrReportScheduleInflight,
		"同一排程至多一張進行中的工作單")

	after, err := f.svc.Get(a.ID)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC).UTC(), after.PeriodAnchor.UTC(),
		"被擋下的觸發不得推進錨點，否則那一段期間沒有任何報告涵蓋")

	// 另一個排程不受影響
	_, err = f.svc.Trigger(b.ID, time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC))
	require.NoError(t, err)
}

func TestRotationScheduleValidatesFields(t *testing.T) {
	f := newScheduleFixture(t)
	base := func() *model.RotationReportSchedule {
		return &model.RotationReportSchedule{
			Name: "x", Cron: "0 1 1 * *", Enabled: true,
			ScopeKind: model.RotationScopeAll, RetentionDays: 30,
			Language: model.NotificationChannelLanguageZhTW,
		}
	}
	cases := []struct {
		name string
		muta func(*model.RotationReportSchedule)
		want error
	}{
		{"空名稱", func(s *model.RotationReportSchedule) { s.Name = "  " }, ErrReportScheduleNameEmpty},
		{"壞 cron", func(s *model.RotationReportSchedule) { s.Cron = "every minute" }, ErrReportBadCron},
		{"留存為零", func(s *model.RotationReportSchedule) { s.RetentionDays = 0 }, ErrReportBadRetention},
		{"留存越界", func(s *model.RotationReportSchedule) { s.RetentionDays = 3651 }, ErrReportBadRetention},
		{"語言不在閉集", func(s *model.RotationReportSchedule) { s.Language = "de-DE" }, ErrReportBadLanguage},
		{"範圍種類不明", func(s *model.RotationReportSchedule) { s.ScopeKind = "everything" }, ErrReportBadScope},
		{"節點不存在", func(s *model.RotationReportSchedule) {
			s.ScopeKind = model.RotationScopeNode
			s.ScopeID = 9999
		}, ErrReportBadScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.muta(in)
			_, err := f.svc.Create(in)
			require.ErrorIs(t, err, tc.want)
		})
	}

	// 名稱唯一
	f.create(t, "唯一名")
	dup := base()
	dup.Name = "唯一名"
	_, err := f.svc.Create(dup)
	require.ErrorIs(t, err, ErrReportScheduleNameExists)
}

func TestRotationScheduleManualJobKeepsAnchor(t *testing.T) {
	f := newScheduleFixture(t)
	row := f.create(t, "月報")
	before := row.PeriodAnchor

	job, err := f.svc.CreateManualJob(ReportJobFilter{
		ScopeKind:   model.RotationScopeAll,
		PeriodStart: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
		Language:    model.NotificationChannelLanguageZhTW,
	}, "auditor", 8)
	require.NoError(t, err)
	assert.Equal(t, uint(8), job.RequesterID)
	assert.Nil(t, job.ExpiresAt, "手動產出沿既有證據包保留期，不帶預定到期")

	filter := jobFilterOf(t, job)
	assert.Equal(t, uint(0), filter.ScheduleID)
	assert.Equal(t, "auditor", filter.GeneratedBy)

	after, err := f.svc.Get(row.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, before, after.PeriodAnchor, time.Second,
		"手動產出不得影響任何排程的錨點")

	// 區間反向即拒
	_, err = f.svc.CreateManualJob(ReportJobFilter{
		ScopeKind:   model.RotationScopeAll,
		PeriodStart: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Language:    model.NotificationChannelLanguageZhTW,
	}, "auditor", 8)
	require.ErrorIs(t, err, ErrReportBadPeriod)
}
