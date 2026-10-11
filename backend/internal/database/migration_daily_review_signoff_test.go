package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 每日簽核改版的遷移：既有簽核紀錄的回填與啟用歷史的重建。
//
// 同一組情境在 sqlite（資料轉換的語義）與 pg（真 DDL：加欄、回填、收緊 NOT NULL）
// 各跑一次。審計列一律由 model.PolicyChangeAuditMessage 產生——那正是 handler
// 寫政策變更審計時用的同一支（見 api 套件的 TestPolicyChangeAuditFieldsUsesSharedFormat），
// 不手寫產品不會寫出的格式。

func utcAt(date string, hour int) time.Time {
	d, _ := time.Parse(reviewcal.DateFormat, date)
	return d.Add(time.Duration(hour) * time.Hour)
}

type fixtureAuditRow struct {
	at       time.Time
	errorMsg string
	resource model.AuditResource
}

func policyEvent(at time.Time, oldV, newV string) fixtureAuditRow {
	return fixtureAuditRow{at: at, errorMsg: model.PolicyChangeAuditMessage("daily_review_enabled", oldV, newV), resource: model.ResourceSecurityPolicy}
}

type fixtureSigned struct {
	date      string
	createdAt time.Time
}

type signoffScenario struct {
	name       string
	tz         string
	now        time.Time
	baselineAt *time.Time
	watermark  *time.Time
	audit      []fixtureAuditRow
	signed     []fixtureSigned
	// policyValue 為空＝無政策列（出廠 false）
	policyValue     string
	policyUpdatedAt time.Time
	check           func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar)
}

func ptrTime(t time.Time) *time.Time { return &t }

func signoffScenarios() []signoffScenario {
	now := utcAt("2026-10-11", 12)
	return []signoffScenario{
		{
			name: "開關開", tz: "UTC", now: now,
			audit: []fixtureAuditRow{
				policyEvent(utcAt("2026-09-01", 10), "false", "true"),
				policyEvent(utcAt("2026-09-10", 10), "true", "false"),
				policyEvent(utcAt("2026-09-20", 10), "false", "true"),
			},
			policyValue: "true", policyUpdatedAt: utcAt("2026-09-20", 10),
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				expectScope(t, cal, "2026-08-31", false, "", "")
				expectRange(t, cal, "2026-09-01", "2026-09-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
				expectRange(t, cal, "2026-09-11", "2026-09-19", false, "", "")
				expectRange(t, cal, "2026-09-20", "2026-10-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
			},
		},
		{
			name: "審計已部分清除", tz: "UTC", now: now,
			baselineAt: ptrTime(utcAt("2026-09-15", 8)),
			watermark:  ptrTime(utcAt("2026-09-25", 0)),
			audit: []fixtureAuditRow{
				policyEvent(utcAt("2026-10-01", 10), "true", "false"),
				policyEvent(utcAt("2026-10-05", 10), "false", "true"),
			},
			signed:      []fixtureSigned{{date: "2026-09-20", createdAt: utcAt("2026-09-20", 18)}},
			policyValue: "true", policyUpdatedAt: utcAt("2026-10-05", 10),
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				expectScope(t, cal, "2026-09-14", false, "", "")
				for _, d := range dateRange("2026-09-15", "2026-09-24") {
					if d == "2026-09-20" {
						expectScope(t, cal, d, true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationSignRecord)
						continue
					}
					expectScope(t, cal, d, true, model.DailyReviewBasisPresumedPurged, model.PolicyHistorySourceMigrationPresumedPurged)
				}
				expectRange(t, cal, "2026-09-25", "2026-10-01", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
				expectRange(t, cal, "2026-10-02", "2026-10-04", false, "", "")
				expectRange(t, cal, "2026-10-05", "2026-10-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
				var n int64
				db.Model(&model.SecurityPolicyHistory{}).Where("source = ?", model.PolicyHistorySourceMigrationPresumedPurged).Count(&n)
				if n < 1 {
					t.Errorf("歷史沒有 %s 列", model.PolicyHistorySourceMigrationPresumedPurged)
				}
			},
		},
		{
			name: "目前關閉查無審計有舊簽核", tz: "UTC", now: now,
			signed: []fixtureSigned{
				{date: "2026-09-03", createdAt: utcAt("2026-09-03", 9)},
				{date: "2026-09-04", createdAt: utcAt("2026-09-04", 9)},
				{date: "2026-09-10", createdAt: utcAt("2026-09-10", 9)},
			},
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				for _, d := range []string{"2026-09-03", "2026-09-04", "2026-09-10"} {
					expectScope(t, cal, d, true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationSignRecord)
				}
				expectScope(t, cal, "2026-09-02", false, "", "")
				expectRange(t, cal, "2026-09-05", "2026-09-09", false, "", "")
				expectRange(t, cal, "2026-09-11", "2026-10-10", false, "", "")
			},
		},
		{
			name: "尾端缺事件", tz: "UTC", now: now,
			audit: []fixtureAuditRow{
				policyEvent(utcAt("2026-09-01", 10), "false", "true"),
				policyEvent(utcAt("2026-09-10", 10), "true", "false"),
			},
			policyValue: "true", policyUpdatedAt: utcAt("2026-09-20", 10),
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				expectRange(t, cal, "2026-09-01", "2026-09-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
				expectRange(t, cal, "2026-09-11", "2026-09-19", true, model.DailyReviewBasisPresumedTail, model.PolicyHistorySourceMigrationPresumedTail)
				expectRange(t, cal, "2026-09-20", "2026-10-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationPolicyRow)
			},
		},
		{
			name: "相鄰事件銜接不上", tz: "UTC", now: now,
			audit: []fixtureAuditRow{
				policyEvent(utcAt("2026-09-01", 10), "false", "true"),
				policyEvent(utcAt("2026-09-05", 10), "true", "false"),
				policyEvent(utcAt("2026-09-10", 10), "true", "false"),
				policyEvent(utcAt("2026-09-15", 10), "false", "true"),
			},
			policyValue: "true", policyUpdatedAt: utcAt("2026-09-15", 10),
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				expectRange(t, cal, "2026-09-01", "2026-09-05", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
				expectRange(t, cal, "2026-09-06", "2026-09-10", true, model.DailyReviewBasisPresumedGap, model.PolicyHistorySourceMigrationPresumedGap)
				expectRange(t, cal, "2026-09-11", "2026-09-14", false, "", "")
				expectRange(t, cal, "2026-09-15", "2026-10-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
			},
		},
		{
			name: "請求列與重複列不產生事件", tz: "UTC", now: now,
			audit: []fixtureAuditRow{
				// 中介層為同一請求另寫的請求列：無 policy= 標記
				{at: utcAt("2026-09-01", 10), errorMsg: "", resource: model.ResourceSecurityPolicy},
				policyEvent(utcAt("2026-09-01", 10), "false", "true"),
				policyEvent(utcAt("2026-09-01", 10), "false", "true"),
				// 同值儲存不構成變更
				policyEvent(utcAt("2026-09-03", 10), "true", "true"),
			},
			policyValue: "true", policyUpdatedAt: utcAt("2026-09-01", 10),
			check: func(t *testing.T, db *gorm.DB, cal *reviewcal.Calendar) {
				var n int64
				db.Model(&model.SecurityPolicyHistory{}).Where("policy_key = ? AND source = ?",
					"daily_review_enabled", model.PolicyHistorySourceMigrationAuditLog).Count(&n)
				if n != 1 {
					t.Errorf("由審計重建的歷史列 = %d, want 1（請求列、重複列、同值列都不得產生事件）", n)
				}
				expectScope(t, cal, "2026-08-31", false, "", "")
				expectRange(t, cal, "2026-09-01", "2026-10-10", true, model.DailyReviewBasisRecorded, model.PolicyHistorySourceMigrationAuditLog)
			},
		},
	}
}

func dateRange(from, to string) []string {
	var out []string
	for d := from; d <= to; d = reviewcal.AddDays(d, 1) {
		out = append(out, d)
	}
	return out
}

func expectRange(t *testing.T, cal *reviewcal.Calendar, from, to string, inScope bool, basis, source string) {
	t.Helper()
	for _, d := range dateRange(from, to) {
		expectScope(t, cal, d, inScope, basis, source)
	}
}

func expectScope(t *testing.T, cal *reviewcal.Calendar, date string, inScope bool, basis, source string) {
	t.Helper()
	day, ok := cal.Lookup(date)
	if !ok {
		t.Errorf("%s 查無所屬日", date)
		return
	}
	if day.InScope != inScope || day.Basis != basis || day.Source != source {
		t.Errorf("%s: in_scope=%v basis=%q source=%q, want %v %q %q", date, day.InScope, day.Basis, day.Source, inScope, basis, source)
	}
}

// loadCalendarFromDB 以實際寫入的歷史建行事曆（與服務層同一套解析）
func loadCalendarFromDB(t *testing.T, db *gorm.DB, now time.Time) (*reviewcal.Calendar, []model.SecurityPolicyHistory) {
	t.Helper()
	var rows []model.SecurityPolicyHistory
	if err := db.Order("changed_at, id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取歷史: %v", err)
	}
	in := reviewcal.Inputs{CurrentTZ: "UTC"}
	for _, r := range rows {
		ch := reviewcal.Change{At: r.ChangedAt, Old: r.OldValue, New: r.NewValue, Source: r.Source}
		switch r.PolicyKey {
		case "daily_review_enabled":
			in.Enabled = append(in.Enabled, ch)
		case "daily_review_timezone":
			in.TZ = append(in.TZ, ch)
		}
	}
	return reviewcal.Build(in, now), rows
}

func seedSignoffScenario(t *testing.T, db *gorm.DB, sc signoffScenario) {
	t.Helper()
	if sc.baselineAt != nil {
		if err := db.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", BaselineVersion, *sc.baselineAt).Error; err != nil {
			t.Fatalf("baseline 列: %v", err)
		}
	}
	if sc.watermark != nil {
		if err := db.Exec("INSERT INTO audit_retention_watermarks (class, purged_through_at, last_purge_at, policy_days, partial, updated_at) VALUES (?, ?, ?, 365, false, ?)",
			model.RetentionClassAuditLog, *sc.watermark, *sc.watermark, *sc.watermark).Error; err != nil {
			t.Fatalf("水位: %v", err)
		}
	}
	for _, a := range sc.audit {
		if err := db.Exec("INSERT INTO audit_logs (created_at, user_id, username, action, resource, status, error_msg) VALUES (?, 1, 'admin', ?, ?, ?, ?)",
			a.at, model.ActionUpdate, a.resource, model.StatusSuccess, a.errorMsg).Error; err != nil {
			t.Fatalf("審計列: %v", err)
		}
	}
	for _, s := range sc.signed {
		if err := db.Exec("INSERT INTO daily_review_logs (review_date, reviewer_id, reviewer_name, snapshot_json, note, created_at) VALUES (?, 5, 'auditor', ?, 'n', ?)",
			s.date, `{"date":"`+s.date+`","login_failures":1}`, s.createdAt).Error; err != nil {
			t.Fatalf("舊簽核列: %v", err)
		}
	}
	if sc.policyValue != "" {
		if err := db.Exec("INSERT INTO security_policies (key, value, updated_by, updated_at) VALUES ('daily_review_enabled', ?, 'admin', ?)",
			sc.policyValue, sc.policyUpdatedAt).Error; err != nil {
			t.Fatalf("政策列: %v", err)
		}
	}
}

// assertScenarioInvariants 每個情境共通的斷言：舊簽核列全部在範圍內且依據為 recorded；
// 推定為開的未簽日出現在待簽清單並帶對應依據；依鍵重播的末值等於政策現值
func assertScenarioInvariants(t *testing.T, db *gorm.DB, sc signoffScenario, cal *reviewcal.Calendar, rows []model.SecurityPolicyHistory) {
	t.Helper()
	signed := map[string]bool{}
	for _, s := range sc.signed {
		signed[s.date] = true
		day, ok := cal.Lookup(s.date)
		if !ok || !day.InScope || day.Basis != model.DailyReviewBasisRecorded {
			t.Errorf("舊簽核日 %s: in_scope=%v basis=%q, want 在範圍且 recorded", s.date, day.InScope, day.Basis)
		}
		var basis string
		db.Table("daily_review_logs").Select("enabled_basis").Where("review_date = ?", s.date).Scan(&basis)
		if basis != model.DailyReviewBasisRecorded {
			t.Errorf("舊簽核列 %s enabled_basis=%q, want recorded", s.date, basis)
		}
	}
	// 待簽清單＝在範圍、已結束、未簽；推定日必在其中且帶推定依據
	for _, d := range cal.Days() {
		if !d.InScope || !d.Ended(sc.now) || signed[d.Date] {
			continue
		}
		if reviewcal.IsPresumedBasis(d.Basis) && d.Basis != presumedBasisOfSource(d.Source) {
			t.Errorf("待簽日 %s 的依據 %q 與來源 %q 不對應", d.Date, d.Basis, d.Source)
		}
	}
	for key, want := range map[string]string{"daily_review_enabled": orDefault(sc.policyValue, "false"), "daily_review_timezone": sc.tz} {
		last := ""
		has := false
		for _, r := range rows {
			if r.PolicyKey == key {
				last, has = r.NewValue, true
			}
		}
		if key == "daily_review_enabled" && !has {
			last = "false"
		}
		if last != want {
			t.Errorf("%s 重播末值 %q ≠ 政策現值 %q", key, last, want)
		}
	}
	var tzValue string
	db.Table("security_policies").Select("value").Where("key = ?", "daily_review_timezone").Scan(&tzValue)
	if tzValue != sc.tz {
		t.Errorf("時區政策列 = %q, want %q", tzValue, sc.tz)
	}
}

func presumedBasisOfSource(source string) string {
	switch source {
	case model.PolicyHistorySourceMigrationPresumedPurged:
		return model.DailyReviewBasisPresumedPurged
	case model.PolicyHistorySourceMigrationPresumedGap:
		return model.DailyReviewBasisPresumedGap
	case model.PolicyHistorySourceMigrationPresumedTail:
		return model.DailyReviewBasisPresumedTail
	}
	return ""
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// legacyRowBackfill 舊列回填的逐欄斷言（所屬日與快照不動、舊制涵蓋、推定時區）
func assertLegacyBackfill(t *testing.T, db *gorm.DB, tz string, signed []fixtureSigned) {
	t.Helper()
	for _, s := range signed {
		var row model.DailyReviewLog
		if err := db.Where("review_date = ?", s.date).First(&row).Error; err != nil {
			t.Fatalf("讀取回填列 %s: %v", s.date, err)
		}
		wantSnap := `{"date":"` + s.date + `","login_failures":1}`
		loc, _ := time.LoadLocation(tz)
		d, _ := time.Parse(reviewcal.DateFormat, s.date)
		wantDue := time.Date(d.Year(), d.Month(), d.Day()+2, 0, 0, 0, 0, loc)
		wantStart := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, loc)
		switch {
		case row.ReviewDate != s.date || row.SnapshotJSON != wantSnap:
			t.Errorf("%s 所屬日或快照被改動: %q %q", s.date, row.ReviewDate, row.SnapshotJSON)
		case !row.SignedAt.Equal(s.createdAt):
			t.Errorf("%s signed_at=%v, want created_at %v", s.date, row.SignedAt, s.createdAt)
		case row.Timezone != tz || !row.TimezoneInferred:
			t.Errorf("%s timezone=%q inferred=%v, want %q 推定", s.date, row.Timezone, row.TimezoneInferred, tz)
		case row.Coverage != model.DailyReviewCoverageUntilSigned:
			t.Errorf("%s coverage=%q, want until_signed（舊證據不得冒充整日）", s.date, row.Coverage)
		case row.SourceStatus != model.DailyReviewSourceComplete || row.EnabledBasis != model.DailyReviewBasisRecorded:
			t.Errorf("%s source_status=%q enabled_basis=%q", s.date, row.SourceStatus, row.EnabledBasis)
		case row.Late || row.DelayReason != nil:
			t.Errorf("%s late=%v delay_reason=%v, want 準時且無原因", s.date, row.Late, row.DelayReason)
		case !row.DueAt.Equal(wantDue):
			t.Errorf("%s due_at=%v, want %v（所屬日加兩個日曆日的 00:00）", s.date, row.DueAt, wantDue)
		case !row.WindowStart.Equal(wantStart) || !row.WindowEnd.Equal(wantStart.AddDate(0, 0, 1)):
			t.Errorf("%s window=[%v,%v)", s.date, row.WindowStart, row.WindowEnd)
		}
	}
}

// legacyBackfillScenario 2.1 的回填情境：兩筆舊列、非 UTC 的偵測時區
func legacyBackfillScenario() signoffScenario {
	return signoffScenario{
		name: "舊列回填", tz: "Asia/Taipei", now: utcAt("2026-10-11", 4),
		signed: []fixtureSigned{
			{date: "2026-09-28", createdAt: utcAt("2026-09-28", 3)},
			{date: "2026-09-29", createdAt: utcAt("2026-09-29", 9)},
		},
		policyValue: "true", policyUpdatedAt: utcAt("2026-09-01", 0),
		audit: []fixtureAuditRow{policyEvent(utcAt("2026-09-01", 0), "false", "true")},
	}
}

func newSignoffSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}, &model.AuditRetentionWatermark{}, &model.SecurityPolicyHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)",
		// 加欄之後、回填之前的形狀（需回填的欄可空）
		`CREATE TABLE daily_review_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, review_date varchar(10) NOT NULL UNIQUE,
			reviewer_id integer NOT NULL, reviewer_name varchar(100) NOT NULL, snapshot_json text NOT NULL, note text, created_at datetime,
			signed_at datetime, timezone varchar(64), timezone_inferred boolean NOT NULL DEFAULT false, window_start datetime, window_end datetime,
			due_at datetime, late boolean, delay_reason text, coverage varchar(16), source_status varchar(16), enabled_basis varchar(16) NOT NULL DEFAULT 'recorded')`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("建表: %v", err)
		}
	}
	return db
}

// newSignoffPostgres 以真 DDL 建到本 migration 之前，供情境植入舊資料
func newSignoffPostgres(t *testing.T, name string) (*gorm.DB, Migration) {
	t.Helper()
	db := freshSchema(t, testgate.Value(t, testgate.EnvPGDSN), name)
	target := -1
	for i, m := range migrations {
		if m.Version == "20261012_daily_review_signoff" {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("migration 20261012_daily_review_signoff 未登記")
	}
	for _, m := range migrations[:target] {
		if err := m.Up(db); err != nil {
			t.Fatal(m.Version, err)
		}
	}
	if err := db.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		t.Fatal(err)
	}
	return db, migrations[target]
}

// TestMigrationDailyReviewSignoffBackfill 擋：舊紀錄被標成涵蓋整天、或所屬日在回填時
// 被改動（兩者都會讓舊證據冒充新制）；無法證明的日子被靜默略過而不列待簽，或列了
// 卻標成確定啟用；有簽核紀錄的日子因重建而從逐日證據中消失
func TestMigrationDailyReviewSignoffBackfill(t *testing.T) {
	all := append([]signoffScenario{legacyBackfillScenario()}, signoffScenarios()...)

	t.Run("sqlite", func(t *testing.T) {
		for _, sc := range all {
			sc := sc
			t.Run(sc.name, func(t *testing.T) {
				db := newSignoffSQLite(t)
				seedSignoffScenario(t, db, sc)
				if err := backfillDailyReviewSignoff(db, signoffBackfillEnv{Now: sc.now, DetectedTZ: sc.tz}); err != nil {
					t.Fatalf("回填: %v", err)
				}
				runScenarioChecks(t, db, sc)
			})
		}
	})

	t.Run("postgres", func(t *testing.T) {
		for i, sc := range all {
			sc := sc
			t.Run(sc.name, func(t *testing.T) {
				db, target := newSignoffPostgres(t, fmt.Sprintf("daily_review_signoff_%d_%d", i, time.Now().UnixNano()))
				seedSignoffScenario(t, db, sc)
				if err := applyDailyReviewSignoffWith(db, signoffBackfillEnv{Now: sc.now, DetectedTZ: sc.tz}); err != nil {
					t.Fatalf("%s Up: %v", target.Version, err)
				}
				runScenarioChecks(t, db, sc)
				// 收緊後 NOT NULL 生效：缺簽核時刻的列寫不進去
				if db.Exec(`INSERT INTO daily_review_logs (review_date, reviewer_id, reviewer_name, snapshot_json, timezone, window_start, window_end, due_at, late, coverage, source_status)
					VALUES ('2030-01-01', 1, 'x', '{}', 'UTC', now(), now(), now(), false, 'full_day', 'complete')`).Error == nil {
					t.Error("signed_at 未收緊為 NOT NULL")
				}
				// Down 有損但可執行，之後 Up 可再套用
				if err := target.Down(db); err != nil {
					t.Fatalf("Down: %v", err)
				}
			})
		}
	})
}

func runScenarioChecks(t *testing.T, db *gorm.DB, sc signoffScenario) {
	t.Helper()
	assertLegacyBackfill(t, db, sc.tz, sc.signed)
	cal, rows := loadCalendarFromDB(t, db, sc.now)
	if sc.check != nil {
		sc.check(t, db, cal)
	}
	assertScenarioInvariants(t, db, sc, cal, rows)
	t.Logf("%s：歷史 %d 列，行事曆 %d 天", sc.name, len(rows), len(cal.Days()))
}
