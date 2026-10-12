package audit

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/reviewcal"
	"gorm.io/gorm"
)

// 證據包的每日簽核紀錄段（daily_reviews.csv）。
//
// fixture 以真實歷史表＋行事曆＋固定時鐘建構（不注入預先算好的數字）：
// 業務時區 Asia/Taipei，現在 2026-10-11 12:00；時間窗 09-11 00:00 至 10-11 00:00。

const bundleTZ = "Asia/Taipei"

// bundleSign 一筆簽核列（準時於隔天 09:00、遲簽於準時期限後 2 小時）
type bundleSign struct {
	late   bool
	reason string
	note   string
	basis  string
}

// dailyReviewBundleEnv 證據包環境＋真實的每日簽核服務（逐日清單來源）
func dailyReviewBundleEnv(t *testing.T) (*AuditExportService, *gorm.DB, *DailyReviewService) {
	t.Helper()
	svc, db := setupReportEnv(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.SecurityPolicyHistory{}, &model.DailyReviewLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dr := NewDailyReviewService(db, policy.NewSecurityPolicyService(db), nil)
	fixedClock(dr, at(t, bundleTZ, "2026-10-11", 12, 0, 0))
	svc.SetDailyReviewLedger(dr)
	return svc, db, dr
}

// seedBundleSign 寫一筆簽核列（快照帶一組計數，供核對「已簽列取固化值」）
func seedBundleSign(t *testing.T, db *gorm.DB, date string, s bundleSign) {
	t.Helper()
	start, end := reviewcal.DayWindow(date, bundleTZ)
	due := reviewcal.DueAt(date, bundleTZ)
	signedAt := end.Add(9 * time.Hour)
	if s.late {
		signedAt = due.Add(2 * time.Hour)
	}
	basis := s.basis
	if basis == "" {
		basis = model.DailyReviewBasisRecorded
	}
	row := model.DailyReviewLog{ReviewDate: date, ReviewerID: 5, ReviewerName: "auditor01",
		SnapshotJSON: `{"date":"` + date + `","login_failures":2,"login_failures_source":"complete","high_risk_ops":1,"high_risk_ops_source":"complete","unreviewed_alerts":0,"alerts_total":3,"alerts_benign":2,"alerts_escalated":1,"alerts_source":"complete"}`,
		Note:         s.note, SignedAt: signedAt.UTC(), Timezone: bundleTZ,
		WindowStart: start.UTC(), WindowEnd: end.UTC(), DueAt: due.UTC(), Late: s.late,
		Coverage: model.DailyReviewCoverageFullDay, SourceStatus: model.DailyReviewSourceComplete, EnabledBasis: basis}
	if s.late {
		reason := s.reason
		row.DelayReason = &reason
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

// seedSpecScenario spec 的共用情境：09-01 起開啟；10-06 至 10-09 未簽；09-18、09-25、
// 10-02 補簽；其餘到 10-09 準時；10-10 未到期未簽。unsigned 另列要留成未簽的日子
func seedSpecScenario(t *testing.T, db *gorm.DB, unsigned ...string) {
	t.Helper()
	enableFrom(t, db, bundleTZ, at(t, bundleTZ, "2026-09-01", 0, 0, 0))
	skip := map[string]bool{"2026-10-06": true, "2026-10-07": true, "2026-10-08": true, "2026-10-09": true}
	for _, d := range unsigned {
		skip[d] = true
	}
	late := map[string]bundleSign{
		"2026-09-18": {late: true, reason: "=HYPERLINK(\"http://x\")", note: "@SUM(1,1)"},
		"2026-09-25": {late: true, reason: "系統升級停機，隔日補簽"},
		"2026-10-02": {late: true, reason: "連假期間無人值守"},
	}
	for d := "2026-09-11"; d <= "2026-10-09"; d = reviewcal.AddDays(d, 1) {
		if skip[d] {
			continue
		}
		s, ok := late[d]
		if !ok {
			s = bundleSign{}
		}
		seedBundleSign(t, db, d, s)
	}
}

func bundleWindow(t *testing.T) (time.Time, time.Time) {
	return at(t, bundleTZ, "2026-09-11", 0, 0, 0), at(t, bundleTZ, "2026-10-11", 0, 0, 0)
}

// dailyReviewCSV 解析 daily_reviews.csv：表頭索引與資料列（以所屬日索引）
func dailyReviewCSV(t *testing.T, files map[string][]byte) (map[string]int, map[string][]string, int) {
	t.Helper()
	raw, ok := files[policy.DailyReviewsCSVName]
	if !ok {
		t.Fatalf("包內沒有 %s（包內：%v）", policy.DailyReviewsCSVName, fileNames(files))
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF")))).ReadAll()
	if err != nil {
		t.Fatalf("解析 CSV: %v", err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	byDate := map[string][]string{}
	for _, r := range rows[1:] {
		byDate[r[col["review_date"]]] = r
	}
	return col, byDate, len(rows) - 1
}

// TestEvidenceBundleIncludesUnsignedDays 擋：證據只列已簽的日子，未簽的那幾天在證據裡
// 消失；推定為啟用的日子被標成確定啟用；已清除的來源被輸出成 0。
func TestEvidenceBundleIncludesUnsignedDays(t *testing.T) {
	t.Run("未簽與未到期也是一列", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db)
		from, to := bundleWindow(t)
		m, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
		col, byDate, n := dailyReviewCSV(t, files)
		if n != 30 {
			t.Fatalf("CSV %d 列, want 30（09-11 至 10-10）", n)
		}
		count := map[string]int{}
		for _, r := range byDate {
			count[r[col["status"]]]++
		}
		if count["unsigned"] != 4 || count["late"] != 3 || count["not_due"] != 1 || count["on_time"] != 22 {
			t.Errorf("狀態分布 %v, want 未簽 4、補簽 3、未到期 1、準時 22", count)
		}
		for _, d := range []string{"2026-10-06", "2026-10-07", "2026-10-08", "2026-10-09"} {
			if r := byDate[d]; r == nil || r[col["status"]] != "unsigned" || r[col["counts_toward_stats"]] != "true" {
				t.Errorf("%s 列 %v, want 未簽且計入統計", d, r)
			}
		}
		if r := byDate["2026-10-10"]; r[col["status"]] != "not_due" || r[col["counts_toward_stats"]] != "false" {
			t.Errorf("10-10 列 status=%s counts=%s, want not_due／false", r[col["status"]], r[col["counts_toward_stats"]])
		}
		for _, d := range []string{"2026-09-25", "2026-10-02"} {
			if r := byDate[d]; r[col["status"]] != "late" || r[col["delay_reason"]] == "" || r[col["late_days"]] == "" {
				t.Errorf("%s 列 %v, want 補簽且帶延遲原因與晚幾天", d, r)
			}
		}
		// 已簽列取簽核時固化的計數；未簽列為即時計數（此 fixture 皆 0），不是空白
		if r := byDate["2026-09-20"]; r[col["login_failures"]] != "2" || r[col["alerts_total"]] != "3" || r[col["signer"]] != "auditor01" || !strings.HasPrefix(r[col["review_ref"]], "daily_review:") {
			t.Errorf("已簽列未取固化值：%v", r)
		}
		if r := byDate["2026-10-07"]; r[col["login_failures"]] != "0" || r[col["audit_log_source"]] != "complete" {
			t.Errorf("未簽列的即時計數 %v, want 0 且來源完整", r)
		}
		if m.Counts[exportDailyReviewSection] != 30 || m.Totals[exportDailyReviewSection] != 30 || m.Truncated[exportDailyReviewSection] {
			t.Errorf("manifest 收錄 %d 範圍 %d 截斷 %v, want 30／30／false",
				m.Counts[exportDailyReviewSection], m.Totals[exportDailyReviewSection], m.Truncated[exportDailyReviewSection])
		}
		dr := m.DailyReviews
		if dr == nil || dr.Rows != 30 || dr.InRange != 30 || dr.Truncated || !dr.NotFilteredByType ||
			!dr.PivotIndependent || dr.SignoffRetention != DailyReviewSignoffRetention || dr.PresumedRows != 0 {
			t.Errorf("manifest 每日簽核段 %+v", dr)
		}
		if !manifestListsFile(m, policy.DailyReviewsCSVName) {
			t.Error("清單檔沒有記 daily_reviews.csv 的雜湊")
		}
	})

	t.Run("CSV 公式注入轉義：延遲原因與備註", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db)
		from, to := bundleWindow(t)
		_, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
		col, byDate, _ := dailyReviewCSV(t, files)
		r := byDate["2026-09-18"]
		if r[col["delay_reason"]] != "'=HYPERLINK(\"http://x\")" || r[col["note"]] != "'@SUM(1,1)" {
			t.Errorf("延遲原因 %q 備註 %q, want 前置單引號", r[col["delay_reason"]], r[col["note"]])
		}
	})

	t.Run("只選告警類別仍有此檔", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db)
		from, to := bundleWindow(t)
		uid := uint(1)
		_, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to,
			Subject: SubjectUser, UserID: &uid, Types: []TimelineEventType{TimelineTypeAlert}}))
		if _, ok := files["audit_logs.json"]; ok {
			t.Fatal("前提：只選告警時不該有操作日誌段")
		}
		if _, _, n := dailyReviewCSV(t, files); n != 30 {
			t.Errorf("只選告警時 %d 列, want 30", n)
		}
	})

	t.Run("以使用者為樞紐仍有此檔", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db)
		from, to := bundleWindow(t)
		uid := uint(1)
		_, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to,
			Subject: SubjectUser, UserID: &uid}))
		if _, _, n := dailyReviewCSV(t, files); n != 30 {
			t.Errorf("使用者樞紐時 %d 列, want 30", n)
		}
	})

	t.Run("事件報告不收", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db)
		from, to := bundleWindow(t)
		uid := uint(1)
		m, files := exportReport(t, svc, &ExportFilter{StartTime: &from, EndTime: &to, Subject: SubjectUser, UserID: &uid})
		if m.Mode != ExportModeEventReport {
			t.Fatalf("前提：mode=%s", m.Mode)
		}
		if _, ok := files[policy.DailyReviewsCSVName]; ok || m.DailyReviews != nil {
			t.Error("事件報告收了每日簽核段")
		}
	})

	t.Run("來源已清除的日子計數留空", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db, "2026-09-11")
		// 水位在 09-12 00:00：09-11 整日已清除，09-12 起完整
		through := at(t, bundleTZ, "2026-09-12", 0, 0, 0)
		setWatermark(t, db, model.RetentionClassAuditLog, through)
		setWatermark(t, db, model.RetentionClassCommandAlert, through)
		from, to := bundleWindow(t)
		m, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
		col, byDate, _ := dailyReviewCSV(t, files)
		r := byDate["2026-09-11"]
		for _, c := range []string{"login_failures", "alerts_total", "alerts_benign", "alerts_escalated", "high_risk_ops"} {
			if r[col[c]] != "" {
				t.Errorf("已清除的 %s = %q, want 空白（不是 0）", c, r[col[c]])
			}
		}
		if r[col["audit_log_source"]] != model.DailyReviewSourcePurged || r[col["command_alert_source"]] != model.DailyReviewSourcePurged {
			t.Errorf("來源狀態 %s／%s, want purged", r[col["audit_log_source"]], r[col["command_alert_source"]])
		}
		if m.DailyReviews == nil || m.DailyReviews.SourcePurgedRows != 1 {
			t.Errorf("manifest 已清除列數 %+v, want 1", m.DailyReviews)
		}
	})

	t.Run("推定為啟用的日子照實標示", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		// 升級遷移因審計已清除而推定 08-01 起為開；09-14 起有操作日誌證明
		historyRow(t, db, policy.PolicyDailyReviewTimezone, "", bundleTZ, at(t, bundleTZ, "2026-07-01", 0, 0, 0), model.PolicyHistorySourceMigrationUpgrade)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "false", "true", at(t, bundleTZ, "2026-08-01", 0, 0, 0), model.PolicyHistorySourceMigrationPresumedPurged)
		historyRow(t, db, policy.PolicyDailyReviewEnabled, "true", "true", at(t, bundleTZ, "2026-09-14", 0, 0, 0), model.PolicyHistorySourceMigrationAuditLog)
		setPolicyRow(t, db, policy.PolicyDailyReviewTimezone, bundleTZ)
		setPolicyRow(t, db, policy.PolicyDailyReviewEnabled, "true")
		seedBundleSign(t, db, "2026-09-12", bundleSign{late: true, reason: "升級後補簽", basis: model.DailyReviewBasisPresumedPurged})
		from, to := bundleWindow(t)
		m, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
		col, byDate, _ := dailyReviewCSV(t, files)
		want := map[string]string{"2026-09-11": "unsigned", "2026-09-12": "late", "2026-09-13": "unsigned"}
		for d, status := range want {
			r := byDate[d]
			if r[col["status"]] != status || r[col["enabled_basis"]] != model.DailyReviewBasisPresumedPurged {
				t.Errorf("%s status=%s basis=%s, want %s／presumed_purged", d, r[col["status"]], r[col["enabled_basis"]], status)
			}
		}
		if r := byDate["2026-09-14"]; r[col["enabled_basis"]] != model.DailyReviewBasisRecorded {
			t.Errorf("09-14 起有紀錄證明，得 basis=%s", r[col["enabled_basis"]])
		}
		if m.DailyReviews == nil || m.DailyReviews.PresumedRows != 3 {
			t.Errorf("manifest 推定列數 %+v, want 3", m.DailyReviews)
		}
	})

	t.Run("3660 天全收、3661 天截斷且標示", func(t *testing.T) {
		for _, n := range []int{3660, 3661} {
			svc, db, _ := dailyReviewBundleEnv(t)
			first := reviewcal.AddDays("2026-10-10", -(n - 1))
			enableFrom(t, db, bundleTZ, at(t, bundleTZ, first, 0, 0, 0))
			from, to := at(t, bundleTZ, first, 0, 0, 0), at(t, bundleTZ, "2026-10-11", 0, 0, 0)
			m, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
			_, _, rows := dailyReviewCSV(t, files)
			truncated := n > maxExportDailyReviews
			if rows != maxExportDailyReviews || m.Counts[exportDailyReviewSection] != maxExportDailyReviews ||
				m.Totals[exportDailyReviewSection] != int64(n) || m.Truncated[exportDailyReviewSection] != truncated ||
				m.DailyReviews.Truncated != truncated {
				t.Errorf("n=%d：CSV %d 列、收錄 %d、範圍 %d、截斷 %v／%v", n, rows, m.Counts[exportDailyReviewSection],
					m.Totals[exportDailyReviewSection], m.Truncated[exportDailyReviewSection], m.DailyReviews.Truncated)
			}
		}
	})

	t.Run("統計來源回錯誤時匯出失敗", func(t *testing.T) {
		svc, _ := setupReportEnv(t)
		svc.SetDailyReviewLedger(failingDailyReviewLedger{})
		from, to := bundleWindow(t)
		var buf bytes.Buffer
		if _, err := svc.Export(&buf, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}), 9, "auditor1"); err == nil {
			t.Error("來源錯誤卻匯出成功（會產出空白但成功的段落）")
		}
		svc.SetDailyReviewLedger(nil)
		if _, err := svc.Export(&bytes.Buffer{}, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}), 9, "auditor1"); err == nil {
			t.Error("來源未注入卻匯出成功")
		}
	})
}

type failingDailyReviewLedger struct{}

func (failingDailyReviewLedger) DailyReviewLedger(*time.Time, *time.Time, int) ([]policy.SignoffDay, int, bool, error) {
	return nil, 0, false, errors.New("stats query failed")
}

func manifestListsFile(m *ExportManifest, name string) bool {
	for _, f := range m.Files {
		if f.Name == name && len(f.SHA256) == 64 {
			return true
		}
	}
	return false
}

// TestEvidenceBundleDailyReviewsCriteriaColumn 擋：判準調整前後的高危數混在同一份清單裡
// 無從分辨；新欄插在中間打亂下游依欄位位置讀取的既有欄位
func TestEvidenceBundleDailyReviewsCriteriaColumn(t *testing.T) {
	t.Run("兩種口徑在同一份清單可分辨", func(t *testing.T) {
		svc, db, _ := dailyReviewBundleEnv(t)
		seedSpecScenario(t, db) // 已簽列的快照是升級前的形狀（沒有判準版本）
		from, to := bundleWindow(t)
		_, files := exportReport(t, svc, bundleFilter(&ExportFilter{StartTime: &from, EndTime: &to}))
		raw := files[policy.DailyReviewsCSVName]
		rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF")))).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		before := []string{
			"review_date", "timezone", "timezone_inferred", "enabled_basis",
			"window_start", "window_end", "due_at", "status", "counts_toward_stats",
			"signed_at", "signer", "late_days", "delay_reason", "note", "coverage",
			"audit_log_source", "command_alert_source",
			"login_failures", "alerts_total", "alerts_benign", "alerts_escalated",
			"high_risk_ops", "alerts_after_sign", "review_ref",
		}
		header := rows[0]
		if len(header) != len(before)+1 || strings.Join(header[:len(before)], ",") != strings.Join(before, ",") {
			t.Fatalf("表頭前 %d 欄與改動前不同，或沒有在尾端追加一欄: %v", len(before), header)
		}
		if header[len(before)] != "high_risk_criteria" {
			t.Fatalf("尾端欄 = %q, want high_risk_criteria", header[len(before)])
		}
		col, byDate, _ := dailyReviewCSV(t, files)
		if got := byDate["2026-10-01"][col["high_risk_criteria"]]; got != "1" {
			t.Errorf("舊快照的已簽日判準版本 = %q, want 1", got)
		}
		if got := byDate["2026-10-07"][col["high_risk_criteria"]]; got != strconv.Itoa(HighRiskCriteriaVersion) {
			t.Errorf("未簽日判準版本 = %q, want %d", got, HighRiskCriteriaVersion)
		}
	})
}
