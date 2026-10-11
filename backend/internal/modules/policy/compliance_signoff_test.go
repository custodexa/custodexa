package policy

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/reviewcal"
)

// 每日審閱條文（10.4.1）的運作紀錄判定。
//
// fixture 一律以真實行事曆（reviewcal.Build）與固定時鐘建構，期間統計由
// reviewcal.PeriodStats 算出——不直接注入預先算好的應簽／未簽數字，否則測到的
// 只是自己寫進去的數字。共用時鐘：2026-10-11 12:00 +08:00（Asia/Taipei），
// 近 30 天＝09-11 至 10-10，10-10 未到期，應簽至多 29。

const signoffTZ = "Asia/Taipei"

func taipei(t *testing.T, date string, hh int) time.Time {
	t.Helper()
	loc, err := time.LoadLocation(signoffTZ)
	if err != nil {
		t.Fatal(err)
	}
	d, err := time.ParseInLocation(reviewcal.DateFormat, date, loc)
	if err != nil {
		t.Fatal(err)
	}
	return d.Add(time.Duration(hh) * time.Hour)
}

func signoffAsOf(t *testing.T) time.Time { return taipei(t, "2026-10-11", 12) }

// enabledFrom 自 date 00:00 起由管理端開啟（之前為關閉）
func enabledFrom(t *testing.T, date string) []reviewcal.Change {
	return []reviewcal.Change{{At: taipei(t, date, 0), Old: "false", New: "true", Source: model.PolicyHistorySourcePolicyUpdate}}
}

// signoffSign 一個已簽日：準時者於隔天 09:00 簽，遲簽者於準時期限後 2 小時簽
type signoffSign struct {
	late   bool
	signer string
	reason string
}

// signoffCalendar 以業務時區 Taipei 與給定的開關歷史建行事曆
func signoffCalendar(t *testing.T, enabled []reviewcal.Change) *reviewcal.Calendar {
	t.Helper()
	tz := []reviewcal.Change{{At: taipei(t, "2026-07-01", 0), New: signoffTZ,
		Source: model.PolicyHistorySourceMigrationUpgrade}}
	return reviewcal.Build(reviewcal.Inputs{TZ: tz, Enabled: enabled, CurrentTZ: signoffTZ}, signoffAsOf(t))
}

// buildSignoffRecord 由行事曆與已簽日算出近 30 天運作紀錄；withDays 時連同逐日清單
// （狀態、計入與否、簽核者、原因取同一份統計的逐日列）
func buildSignoffRecord(t *testing.T, enabled []reviewcal.Change, signs map[string]signoffSign, withDays bool) *SignoffRecord {
	t.Helper()
	cal := signoffCalendar(t, enabled)
	now := signoffAsOf(t)
	signedAt := map[string]time.Time{}
	signed := map[string]reviewcal.SignedDay{}
	for date, s := range signs {
		day, ok := cal.Lookup(date)
		if !ok {
			t.Fatalf("%s 不在行事曆上", date)
		}
		at := day.End.Add(9 * time.Hour)
		if s.late {
			at = day.DueAt.Add(2 * time.Hour)
		}
		if at.After(now) {
			t.Fatalf("fixture 錯：%s 的簽核時刻 %v 晚於現在", date, at)
		}
		signedAt[date] = at
		signed[date] = reviewcal.SignedDay{DueAt: day.DueAt, Late: s.late, EnabledBasis: day.Basis,
			LateDays: reviewcal.LateDays(date, day.TZ, at)}
	}
	enabledNow := len(enabled) > 0 && enabled[len(enabled)-1].New == "true"
	from, to := cal.Last30()
	st := cal.PeriodStats(from, to, now, signed, enabledNow)
	rec := NewSignoffRecord(st)
	if !withDays {
		return rec
	}
	for _, d := range st.Days {
		day, _ := cal.Lookup(d.Date)
		row := SignoffDay{Date: d.Date, Timezone: day.TZ, EnabledBasis: d.EnabledBasis,
			WindowStart: day.Start, WindowEnd: day.End, DueAt: day.DueAt,
			Status: d.Result, CountsTowardStats: d.CountsTowardStats, Coverage: model.DailyReviewCoverageFullDay,
			AuditLogSource: model.DailyReviewSourceComplete, CommandAlertSource: model.DailyReviewSourceComplete}
		if s, ok := signs[d.Date]; ok {
			at := signedAt[d.Date]
			row.SignedAt, row.Signer, row.DelayReason = &at, s.signer, s.reason
			row.Status = SignoffStatusOnTime
			if s.late {
				row.Status, row.LateDays = SignoffStatusLate, d.LateDays
			}
		}
		rec.Days = append(rec.Days, row)
	}
	return rec
}

// signAll 把 [from, to] 每一天標為準時簽核（except 內的日子跳過）
func signAll(from, to string, except ...string) map[string]signoffSign {
	skip := map[string]bool{}
	for _, d := range except {
		skip[d] = true
	}
	out := map[string]signoffSign{}
	for d := from; d <= to; d = reviewcal.AddDays(d, 1) {
		if !skip[d] {
			out[d] = signoffSign{signer: "auditor01"}
		}
	}
	return out
}

// signoffVerdict 以 PCI 組的 10.4.1 要求（signoff_record）判定一次
func signoffVerdict(t *testing.T, enabledValue string, rec *SignoffRecord) Verdict {
	t.Helper()
	group := testGroup("pci", true)
	clauses := []model.PolicyClause{testClause("pci", "10.4.1", model.PolicyClauseKindSetting, "")}
	controls := []model.PolicyClauseControl{testControl("pci", "10.4.1", PolicyDailyReviewEnabled,
		model.PolicyControlComparatorSignoffRecord, "true", false)}
	defs := []PolicyDef{*findDef(PolicyDailyReviewEnabled)}
	snap := BuildSnapshotWithSignoff(defs, map[string]string{PolicyDailyReviewEnabled: enabledValue}, nil,
		[]model.PolicyGroup{group}, clauses, controls, nil, rec)
	vs := snap.VerdictsForKey(PolicyDailyReviewEnabled)
	if len(vs) != 1 {
		t.Fatalf("判定列數 %d", len(vs))
	}
	return vs[0]
}

// TestSignoffRecordVerdict 擋：開著但天天漏簽仍判符合（本 change 要修的正是這個）；
// 遲簽被算成偏離而違反裁決；來源故障被說成剛開啟；推定日被當成無法判斷而把未簽
// 藏在資料不足後面。
func TestSignoffRecordVerdict(t *testing.T) {
	type want struct {
		result, reason string
		required       int
		unsigned       int
		late           int
		earliest       string
		inferred       int
		enabledDays    int
		noFacts        bool
		rateNil        bool
	}
	presumed := func(t *testing.T) []reviewcal.Change {
		// 升級遷移因審計已清除，推定 08-01 起為開；09-15 起有操作日誌證明
		return []reviewcal.Change{
			{At: taipei(t, "2026-08-01", 0), Old: "false", New: "true", Source: model.PolicyHistorySourceMigrationPresumedPurged},
			{At: taipei(t, "2026-09-15", 0), Old: "true", New: "true", Source: model.PolicyHistorySourceMigrationAuditLog},
		}
	}
	cases := []struct {
		name  string
		value string
		rec   func(t *testing.T) *SignoffRecord
		want  want
	}{
		{"關閉", "false", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signAll("2026-09-11", "2026-10-09"), false)
		}, want{result: ComplianceResultDeviating, reason: ComplianceReasonDailyReviewDisabled, noFacts: true}},
		{"來源不可用", "true", func(t *testing.T) *SignoffRecord { return nil },
			want{result: ComplianceResultInsufficientData, reason: ComplianceReasonSignoffSourceUnavailable, noFacts: true}},
		{"10-08 開啟", "true", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, enabledFrom(t, "2026-10-08"), signAll("2026-10-08", "2026-10-09"), false)
		}, want{result: ComplianceResultInsufficientData, reason: ComplianceReasonSignoffInsufficientData,
			required: 2, enabledDays: 3}},
		{"10-04 開啟恰滿 7 天且全簽", "true", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, enabledFrom(t, "2026-10-04"), signAll("2026-10-04", "2026-10-09"), false)
		}, want{result: ComplianceResultCompliant, reason: ComplianceReasonMeets, required: 6, enabledDays: 7}},
		{"關閉後 10-09 重新開啟", "true", func(t *testing.T) *SignoffRecord {
			hist := append(enabledFrom(t, "2026-09-01"),
				reviewcal.Change{At: taipei(t, "2026-10-05", 0), Old: "true", New: "false", Source: model.PolicyHistorySourcePolicyUpdate},
				reviewcal.Change{At: taipei(t, "2026-10-09", 0), Old: "false", New: "true", Source: model.PolicyHistorySourcePolicyUpdate})
			return buildSignoffRecord(t, hist, signAll("2026-09-11", "2026-10-04"), false)
		}, want{result: ComplianceResultInsufficientData, reason: ComplianceReasonSignoffInsufficientData,
			required: 25, unsigned: 1, earliest: "2026-10-09", enabledDays: 2}},
		{"推定 4 天未簽判偏離", "true", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, presumed(t), signAll("2026-09-15", "2026-10-09"), false)
		}, want{result: ComplianceResultDeviating, reason: ComplianceReasonSignoffUnsignedDays,
			required: 29, unsigned: 4, earliest: "2026-09-11", inferred: 4, enabledDays: 71}},
		{"推定日全部補簽", "true", func(t *testing.T) *SignoffRecord {
			signs := signAll("2026-09-15", "2026-10-09")
			for _, d := range []string{"2026-09-11", "2026-09-12", "2026-09-13", "2026-09-14"} {
				signs[d] = signoffSign{late: true, signer: "auditor01", reason: "升級後補簽"}
			}
			return buildSignoffRecord(t, presumed(t), signs, false)
		}, want{result: ComplianceResultCompliant, reason: ComplianceReasonMeets,
			required: 29, late: 4, inferred: 4, enabledDays: 71}},
		{"29 天全簽含 2 遲簽", "true", func(t *testing.T) *SignoffRecord {
			signs := signAll("2026-09-11", "2026-10-09")
			signs["2026-10-01"] = signoffSign{late: true, signer: "mia", reason: "連假"}
			signs["2026-10-02"] = signoffSign{late: true, signer: "mia", reason: "連假"}
			return buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signs, false)
		}, want{result: ComplianceResultCompliant, reason: ComplianceReasonMeets,
			required: 29, late: 2, enabledDays: 40}},
		{"10-06 至 10-09 未簽", "true", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, enabledFrom(t, "2026-09-01"), signAll("2026-09-11", "2026-10-05"), false)
		}, want{result: ComplianceResultDeviating, reason: ComplianceReasonSignoffUnsignedDays,
			required: 29, unsigned: 4, earliest: "2026-10-06", enabledDays: 40}},
		{"應簽 0 天時簽核率為 null", "true", func(t *testing.T) *SignoffRecord {
			return buildSignoffRecord(t, enabledFrom(t, "2026-10-10"), nil, false)
		}, want{result: ComplianceResultInsufficientData, reason: ComplianceReasonSignoffInsufficientData,
			enabledDays: 1, rateNil: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := signoffVerdict(t, c.value, c.rec(t))
			if v.Result != c.want.result || v.Reason != c.want.reason {
				t.Fatalf("結果 %s／%s, want %s／%s", v.Result, v.Reason, c.want.result, c.want.reason)
			}
			if c.want.noFacts {
				if v.Signoff != nil {
					t.Errorf("此情形不得帶運作紀錄（不顯示簽核率與累計天數），得 %+v", v.Signoff)
				}
				return
			}
			s := v.Signoff
			if s == nil {
				t.Fatal("缺運作紀錄")
			}
			if s.From != "2026-09-11" || s.To != "2026-10-10" || s.Timezone != signoffTZ {
				t.Errorf("期間 %s～%s %s", s.From, s.To, s.Timezone)
			}
			if s.Required != c.want.required || s.Unsigned != c.want.unsigned || s.Late != c.want.late ||
				s.InferredDays != c.want.inferred || s.EnabledDays != c.want.enabledDays {
				t.Errorf("應簽 %d 未簽 %d 遲簽 %d 推定 %d 累計 %d, want %+v",
					s.Required, s.Unsigned, s.Late, s.InferredDays, s.EnabledDays, c.want)
			}
			if s.EarliestUnsigned != c.want.earliest {
				t.Errorf("最早未簽 %q, want %q", s.EarliestUnsigned, c.want.earliest)
			}
			if c.want.rateNil != (s.SignRatePercent == nil) {
				t.Errorf("簽核率 %v, want nil=%v", s.SignRatePercent, c.want.rateNil)
			}
		})
	}

	t.Run("重新開啟後起點重設", func(t *testing.T) {
		hist := append(enabledFrom(t, "2026-09-01"),
			reviewcal.Change{At: taipei(t, "2026-10-05", 0), Old: "true", New: "false", Source: model.PolicyHistorySourcePolicyUpdate},
			reviewcal.Change{At: taipei(t, "2026-10-09", 0), Old: "false", New: "true", Source: model.PolicyHistorySourcePolicyUpdate})
		rec := buildSignoffRecord(t, hist, nil, false)
		if rec.EnabledSince == nil || !rec.EnabledSince.Equal(taipei(t, "2026-10-09", 0)) {
			t.Errorf("enabled_since = %v, want 2026-10-09 00:00 +08:00", rec.EnabledSince)
		}
	})

	t.Run("摘要另計資料不足", func(t *testing.T) {
		group := testGroup("pci", true)
		snap := BuildSnapshotWithSignoff([]PolicyDef{*findDef(PolicyDailyReviewEnabled)},
			map[string]string{PolicyDailyReviewEnabled: "true"}, nil, []model.PolicyGroup{group},
			[]model.PolicyClause{testClause("pci", "10.4.1", model.PolicyClauseKindSetting, "")},
			[]model.PolicyClauseControl{testControl("pci", "10.4.1", PolicyDailyReviewEnabled,
				model.PolicyControlComparatorSignoffRecord, "true", false)}, nil,
			buildSignoffRecord(t, enabledFrom(t, "2026-10-08"), nil, false))
		sum := snap.GroupSummary("pci")
		if sum.InsufficientData != 1 || sum.Compliant != 0 || sum.Deviating != 0 {
			t.Errorf("摘要 %+v, want 資料不足 1、符合與偏離 0", sum)
		}
	})
}
